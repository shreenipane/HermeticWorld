//! Run status determination (§12.3).
//!
//! A pure function from grading inputs to RunStatus with a documented precedence.

use crate::run::RunStatus;

/// Grading inputs for determining run status (§12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GradingInputs {
    /// Excluded by sealcheck before any run (§5.5).
    pub gate_blocked: bool,
    /// Hermetic itself failed (VM crash, WorldServer fault).
    pub infrastructure_failure: bool,
    /// NetVM sent a malformed frame to WorldServer.
    pub netvm_malformed_frame: bool,
    /// R0 normal run verdict passed (FAIL_TO_PASS and PASS_TO_PASS).
    pub r0_passed: bool,
    /// R1 mutant run tripped (a mutant did not fail).
    pub r1_tripped: bool,
    /// R2 equivalence run tripped (result differed from R0).
    pub r2_tripped: bool,
    /// R3 fix removal tripped (FAIL_TO_PASS did not fail when gold was removed).
    pub r3_tripped: bool,
    /// A gateway quota or WorldServer volume cap was hit.
    pub limit_exceeded: bool,
    /// Disagreement between the gate and the retrieval classifier.
    pub gate_classifier_disagreement: bool,
    /// Retrieval classifier gave 'retrieved' label in a sealed world.
    pub retrieved_in_sealed_world: bool,
}

/// Compute the run status from grading inputs (§12.3).
///
/// Precedence order:
/// 1. `gate_blocked`: Pre-run gate finding excluded the task before execution.
/// 2. `infra_error`: Host / VM platform infrastructure failure.
/// 3. `tampered`: Security integrity violation (malformed frame, R1 or R2 tripped).
/// 4. `limit_exceeded`: Gateway quota or WorldServer volume cap exceeded.
/// 5. `review`: Advisory signals (R3 tripped, gate vs classifier disagreement, or retrieved label in sealed world).
/// 6. `unresolved`: R0 normal grading run failed.
/// 7. `resolved`: R0 passed and all integrity/advisory checks clean.
pub fn compute_run_status(inputs: &GradingInputs) -> RunStatus {
    // 1. Gate blocked
    if inputs.gate_blocked {
        return RunStatus::GateBlocked;
    }

    // 2. Infrastructure error
    if inputs.infrastructure_failure {
        return RunStatus::InfraError;
    }

    // 3. Tampering detected (NetVM malformed frame, R1 mutant passed, or R2 equivalence mismatch)
    if inputs.netvm_malformed_frame || inputs.r1_tripped || inputs.r2_tripped {
        return RunStatus::Tampered;
    }

    // 4. Resource limits exceeded
    if inputs.limit_exceeded {
        return RunStatus::LimitExceeded;
    }

    // 5. Review required (R3 tripped, gate vs classifier disagree, or retrieved in sealed world)
    if inputs.r3_tripped || inputs.gate_classifier_disagreement || inputs.retrieved_in_sealed_world
    {
        return RunStatus::Review;
    }

    // 6. Unresolved (R0 failed)
    if !inputs.r0_passed {
        return RunStatus::Unresolved;
    }

    // 7. Resolved
    RunStatus::Resolved
}
