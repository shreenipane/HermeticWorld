use hermetic_attest::{compute_run_status, GradingInputs, RunStatus};

#[test]
fn test_table_driven_all_rows_of_spec_12_3() {
    struct RowTestCase {
        name: &'static str,
        inputs: GradingInputs,
        expected: RunStatus,
    }

    let cases = vec![
        // Row 1: resolved (R0 passes, R1 and R2 clean)
        RowTestCase {
            name: "Row 1: resolved",
            inputs: GradingInputs {
                r0_passed: true,
                ..Default::default()
            },
            expected: RunStatus::Resolved,
        },
        // Row 2: unresolved (R0 fails)
        RowTestCase {
            name: "Row 2: unresolved",
            inputs: GradingInputs {
                r0_passed: false,
                ..Default::default()
            },
            expected: RunStatus::Unresolved,
        },
        // Row 3: tampered (R1 tripped)
        RowTestCase {
            name: "Row 3a: tampered via R1",
            inputs: GradingInputs {
                r0_passed: true,
                r1_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        // Row 3: tampered (R2 tripped)
        RowTestCase {
            name: "Row 3b: tampered via R2",
            inputs: GradingInputs {
                r0_passed: true,
                r2_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        // Row 3: tampered (NetVM malformed frame)
        RowTestCase {
            name: "Row 3c: tampered via NetVM frame",
            inputs: GradingInputs {
                r0_passed: true,
                netvm_malformed_frame: true,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        // Row 4: limit_exceeded (quota or volume cap hit)
        RowTestCase {
            name: "Row 4: limit_exceeded",
            inputs: GradingInputs {
                r0_passed: true,
                limit_exceeded: true,
                ..Default::default()
            },
            expected: RunStatus::LimitExceeded,
        },
        // Row 5: review (R3 tripped)
        RowTestCase {
            name: "Row 5a: review via R3",
            inputs: GradingInputs {
                r0_passed: true,
                r3_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::Review,
        },
        // Row 5: review (gate vs classifier disagreement)
        RowTestCase {
            name: "Row 5b: review via gate-classifier disagreement",
            inputs: GradingInputs {
                r0_passed: true,
                gate_classifier_disagreement: true,
                ..Default::default()
            },
            expected: RunStatus::Review,
        },
        // Row 5: review (retrieved in sealed world)
        RowTestCase {
            name: "Row 5c: review via retrieved in sealed world",
            inputs: GradingInputs {
                r0_passed: true,
                retrieved_in_sealed_world: true,
                ..Default::default()
            },
            expected: RunStatus::Review,
        },
        // Row 6: infra_error (Hermetic infrastructure failure)
        RowTestCase {
            name: "Row 6: infra_error",
            inputs: GradingInputs {
                infrastructure_failure: true,
                ..Default::default()
            },
            expected: RunStatus::InfraError,
        },
        // Row 7: gate_blocked (excluded by sealcheck before run)
        RowTestCase {
            name: "Row 7: gate_blocked",
            inputs: GradingInputs {
                gate_blocked: true,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
    ];

    for c in cases {
        let actual = compute_run_status(&c.inputs);
        assert_eq!(
            actual, c.expected,
            "Failed test case '{}': expected {:?}, got {:?}",
            c.name, c.expected, actual
        );
    }
}

#[test]
fn test_table_driven_all_precedence_conflicts() {
    struct PrecedenceConflictCase {
        name: &'static str,
        inputs: GradingInputs,
        expected: RunStatus,
    }

    let conflict_cases = vec![
        // gate_blocked dominates all others
        PrecedenceConflictCase {
            name: "gate_blocked over infra_error",
            inputs: GradingInputs {
                gate_blocked: true,
                infrastructure_failure: true,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
        PrecedenceConflictCase {
            name: "gate_blocked over tampered",
            inputs: GradingInputs {
                gate_blocked: true,
                netvm_malformed_frame: true,
                r1_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
        PrecedenceConflictCase {
            name: "gate_blocked over limit_exceeded",
            inputs: GradingInputs {
                gate_blocked: true,
                limit_exceeded: true,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
        PrecedenceConflictCase {
            name: "gate_blocked over review",
            inputs: GradingInputs {
                gate_blocked: true,
                r3_tripped: true,
                retrieved_in_sealed_world: true,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
        PrecedenceConflictCase {
            name: "gate_blocked over unresolved",
            inputs: GradingInputs {
                gate_blocked: true,
                r0_passed: false,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
        PrecedenceConflictCase {
            name: "gate_blocked over resolved",
            inputs: GradingInputs {
                gate_blocked: true,
                r0_passed: true,
                ..Default::default()
            },
            expected: RunStatus::GateBlocked,
        },
        // infra_error dominates tampered, limits, review, unresolved, resolved
        PrecedenceConflictCase {
            name: "infra_error over tampered",
            inputs: GradingInputs {
                infrastructure_failure: true,
                netvm_malformed_frame: true,
                r2_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::InfraError,
        },
        PrecedenceConflictCase {
            name: "infra_error over limit_exceeded",
            inputs: GradingInputs {
                infrastructure_failure: true,
                limit_exceeded: true,
                ..Default::default()
            },
            expected: RunStatus::InfraError,
        },
        PrecedenceConflictCase {
            name: "infra_error over review",
            inputs: GradingInputs {
                infrastructure_failure: true,
                r3_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::InfraError,
        },
        PrecedenceConflictCase {
            name: "infra_error over unresolved",
            inputs: GradingInputs {
                infrastructure_failure: true,
                r0_passed: false,
                ..Default::default()
            },
            expected: RunStatus::InfraError,
        },
        PrecedenceConflictCase {
            name: "infra_error over resolved",
            inputs: GradingInputs {
                infrastructure_failure: true,
                r0_passed: true,
                ..Default::default()
            },
            expected: RunStatus::InfraError,
        },
        // tampered dominates limit_exceeded, review, unresolved, resolved
        PrecedenceConflictCase {
            name: "tampered over limit_exceeded",
            inputs: GradingInputs {
                r1_tripped: true,
                limit_exceeded: true,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        PrecedenceConflictCase {
            name: "tampered over review",
            inputs: GradingInputs {
                r2_tripped: true,
                gate_classifier_disagreement: true,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        PrecedenceConflictCase {
            name: "tampered over unresolved",
            inputs: GradingInputs {
                netvm_malformed_frame: true,
                r0_passed: false,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        PrecedenceConflictCase {
            name: "tampered over resolved",
            inputs: GradingInputs {
                r1_tripped: true,
                r0_passed: true,
                ..Default::default()
            },
            expected: RunStatus::Tampered,
        },
        // limit_exceeded dominates review, unresolved, resolved
        PrecedenceConflictCase {
            name: "limit_exceeded over review",
            inputs: GradingInputs {
                limit_exceeded: true,
                r3_tripped: true,
                ..Default::default()
            },
            expected: RunStatus::LimitExceeded,
        },
        PrecedenceConflictCase {
            name: "limit_exceeded over unresolved",
            inputs: GradingInputs {
                limit_exceeded: true,
                r0_passed: false,
                ..Default::default()
            },
            expected: RunStatus::LimitExceeded,
        },
        PrecedenceConflictCase {
            name: "limit_exceeded over resolved",
            inputs: GradingInputs {
                limit_exceeded: true,
                r0_passed: true,
                ..Default::default()
            },
            expected: RunStatus::LimitExceeded,
        },
        // review dominates unresolved and resolved
        PrecedenceConflictCase {
            name: "review over unresolved",
            inputs: GradingInputs {
                r3_tripped: true,
                r0_passed: false,
                ..Default::default()
            },
            expected: RunStatus::Review,
        },
        PrecedenceConflictCase {
            name: "review over resolved",
            inputs: GradingInputs {
                gate_classifier_disagreement: true,
                r0_passed: true,
                ..Default::default()
            },
            expected: RunStatus::Review,
        },
    ];

    for c in conflict_cases {
        let actual = compute_run_status(&c.inputs);
        assert_eq!(
            actual, c.expected,
            "Conflict test '{}' failed: expected {:?}, got {:?}",
            c.name, c.expected, actual
        );
    }
}
