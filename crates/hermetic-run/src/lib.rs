#![forbid(unsafe_code)]

pub mod infra;
pub mod machine;
pub mod verdict;

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

pub use infra::{
    AgentMode, AgentOutcome, CleanupLog, Clock, DeadlineSchedule, ExtractorOutcome, GraderHandle,
    GraderOutcome, GraderPayload, GraderRun, Infra, InfraError, LimitKind, NamedDeadline,
    PreparedWorld, ShutdownKind, Step, VmGuard, VmHandle, VmId, VmKind, WorldSpec,
};
pub use machine::{FailureReason, RunState, StateMachine, TransitionError};
pub use verdict::{
    resolve_status, verdict, verdict_reasons, GraderResults, MutatedTestResult, PairedTestResult,
    R0Result, R1Result, R2Result, R3Result, RunStatus, TestResult, Verdict,
};

/// Outcome recorded for an individual executed step in `RunSummary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Ok,
    Unclean,
    LimitExceeded,
    Tampered,
    Failed,
}

/// Deterministic record of a step's name and outcome (contains no timestamps or host details).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub name: String,
    pub outcome: StepOutcome,
}

impl StepRecord {
    pub fn new(step: Step, outcome: StepOutcome) -> Self {
        Self {
            name: step.as_str().to_string(),
            outcome,
        }
    }
}

/// Configuration for a single Hermetic World evaluation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunConfig {
    pub world: WorldSpec,
    pub agent_mode: AgentMode,
    pub run_r3: bool,
    pub deadlines: DeadlineSchedule,
}

impl RunConfig {
    pub fn new(world: WorldSpec, agent_mode: AgentMode) -> Self {
        Self {
            world,
            agent_mode,
            run_r3: false,
            deadlines: DeadlineSchedule::default(),
        }
    }
}

/// Final deterministic summary of an evaluation run.
/// Contains only step names/outcomes, final status, reasons, and the unclean_shutdown flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    pub steps: Vec<StepRecord>,
    pub status: RunStatus,
    pub reasons: Vec<String>,
    pub unclean_shutdown: bool,
}

impl RunSummary {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

struct RunTracker {
    machine: StateMachine,
    steps: Vec<StepRecord>,
    reasons: Vec<String>,
    unclean_shutdown: bool,
    tamper_detected: bool,
    infra_error: bool,
    limit_exceeded: bool,
}

impl RunTracker {
    fn new() -> Self {
        Self {
            machine: StateMachine::new(),
            steps: Vec::new(),
            reasons: Vec::new(),
            unclean_shutdown: false,
            tamper_detected: false,
            infra_error: false,
            limit_exceeded: false,
        }
    }

    fn record_infra_err(&mut self, step: Step, err: &InfraError) {
        match err {
            InfraError::TamperDetected { detail, .. } => {
                self.tamper_detected = true;
                self.steps
                    .push(StepRecord::new(step, StepOutcome::Tampered));
                self.reasons
                    .push(format!("tampered at step '{}': {}", step, detail));
            }
            other => {
                self.infra_error = true;
                self.steps.push(StepRecord::new(step, StepOutcome::Failed));
                self.reasons
                    .push(format!("infra_error at step '{}': {}", step, other));
            }
        }
        let _ = self.machine.fail(step, err.to_string());
    }

    fn record_transition_err(&mut self, step: Step, err: &TransitionError) {
        self.infra_error = true;
        self.steps.push(StepRecord::new(step, StepOutcome::Failed));
        self.reasons
            .push(format!("infra_error at step '{}': {}", step, err));
        let _ = self.machine.fail(step, err.to_string());
    }

    fn finalize(mut self, grader_results: Option<&GraderResults>) -> RunSummary {
        let status = resolve_status(
            self.tamper_detected,
            self.infra_error,
            self.limit_exceeded,
            grader_results,
        );

        if let Some(results) = grader_results {
            let v_reasons = verdict_reasons(results);
            let v = verdict(results);
            if v == Verdict::Tampered || status == RunStatus::from(v) {
                self.reasons.extend(v_reasons);
            }
        }

        if self.reasons.is_empty() {
            self.reasons.push(format!("status: {}", status.as_str()));
        }

        RunSummary {
            steps: self.steps,
            status,
            reasons: self.reasons,
            unclean_shutdown: self.unclean_shutdown,
        }
    }
}

fn check_deadline<C: Clock>(
    clock: &C,
    step: Step,
    deadline: &NamedDeadline,
) -> Result<(), InfraError> {
    if deadline.is_expired(clock.now_ms()) {
        Err(InfraError::DeadlineExceeded {
            step,
            deadline_name: deadline.name.clone(),
        })
    } else {
        Ok(())
    }
}

fn run_step<I, C, T, F>(
    infra_cell: &RefCell<&mut I>,
    clock: &C,
    deadlines: &DeadlineSchedule,
    step: Step,
    f: F,
) -> Result<T, InfraError>
where
    I: Infra,
    C: Clock,
    F: FnOnce(&mut I, &NamedDeadline) -> Result<T, InfraError>,
{
    let deadline = deadlines.deadline_for(step, clock.now_ms());
    check_deadline(clock, step, &deadline)?;
    let result = {
        let mut infra = infra_cell
            .try_borrow_mut()
            .map_err(|_| InfraError::BackendFailure {
                step,
                detail: "infrastructure backend is mutably borrowed".to_string(),
            })?;
        f(&mut infra, &deadline)
    }?;
    check_deadline(clock, step, &deadline)?;
    Ok(result)
}

/// Executes a complete Hermetic World evaluation run with an explicit `CleanupLog`.
pub fn run_evaluation_with_log<I: Infra, C: Clock>(
    infra: &mut I,
    clock: &C,
    config: &RunConfig,
    cleanup_log: &CleanupLog,
) -> RunSummary {
    let infra_cell = RefCell::new(infra);
    let mut tracker = RunTracker::new();

    // 1. Prepare world
    let prepared_world = match run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::PrepareWorld,
        |inf, dl| inf.prepare_world(&config.world, dl),
    ) {
        Ok(world) => {
            if let Err(err) = tracker.machine.to_prepared() {
                tracker.record_transition_err(Step::PrepareWorld, &err);
                return tracker.finalize(None);
            }
            tracker
                .steps
                .push(StepRecord::new(Step::PrepareWorld, StepOutcome::Ok));
            world
        }
        Err(err) => {
            tracker.record_infra_err(Step::PrepareWorld, &err);
            return tracker.finalize(None);
        }
    };

    // 2. Start NetVM (must be up before AgentVM starts)
    let net_vm = match run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::StartNetVm,
        |inf, dl| inf.start_netvm(&prepared_world, dl),
    ) {
        Ok(handle) => {
            if handle.kind != VmKind::Net {
                let err = InfraError::InvalidVmKind {
                    expected: VmKind::Net,
                    actual: handle.kind,
                };
                tracker.record_infra_err(Step::StartNetVm, &err);
                return tracker.finalize(None);
            }
            if let Err(err) = tracker.machine.to_net_up() {
                tracker.record_transition_err(Step::StartNetVm, &err);
                return tracker.finalize(None);
            }
            tracker
                .steps
                .push(StepRecord::new(Step::StartNetVm, StepOutcome::Ok));
            handle
        }
        Err(err) => {
            tracker.record_infra_err(Step::StartNetVm, &err);
            return tracker.finalize(None);
        }
    };

    let net_cleanup_dl = config
        .deadlines
        .deadline_for(Step::DestroyNetVm, clock.now_ms());
    let mut net_guard = VmGuard::new(&infra_cell, cleanup_log, net_vm, net_cleanup_dl);

    // 3. Start AgentVM, wait for readiness, run agent, shut down agent
    let agent_vm = match run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::StartAgentVm,
        |inf, dl| inf.start_agentvm(&prepared_world, net_guard.handle(), dl),
    ) {
        Ok(handle) => {
            if handle.kind != VmKind::Agent {
                let err = InfraError::InvalidVmKind {
                    expected: VmKind::Agent,
                    actual: handle.kind,
                };
                tracker.record_infra_err(Step::StartAgentVm, &err);
                return tracker.finalize(None);
            }
            if let Err(err) = tracker.machine.to_agent_up() {
                tracker.record_transition_err(Step::StartAgentVm, &err);
                return tracker.finalize(None);
            }
            tracker
                .steps
                .push(StepRecord::new(Step::StartAgentVm, StepOutcome::Ok));
            handle
        }
        Err(err) => {
            tracker.record_infra_err(Step::StartAgentVm, &err);
            return tracker.finalize(None);
        }
    };

    let agent_cleanup_dl = config
        .deadlines
        .deadline_for(Step::DestroyAgentVm, clock.now_ms());
    let mut agent_guard = VmGuard::new(&infra_cell, cleanup_log, agent_vm, agent_cleanup_dl);

    // Wait agent ready
    if let Err(err) = run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::WaitAgentReady,
        |inf, dl| inf.wait_agent_ready(agent_guard.handle(), dl),
    ) {
        tracker.record_infra_err(Step::WaitAgentReady, &err);
        return tracker.finalize(None);
    }
    tracker
        .steps
        .push(StepRecord::new(Step::WaitAgentReady, StepOutcome::Ok));

    // Run agent (Mode H or Mode G)
    match run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::RunAgent,
        |inf, dl| inf.run_agent(agent_guard.handle(), &config.agent_mode, dl),
    ) {
        Ok(AgentOutcome::Completed { .. }) => {
            tracker
                .steps
                .push(StepRecord::new(Step::RunAgent, StepOutcome::Ok));
        }
        Ok(AgentOutcome::LimitExceeded { kind, detail }) => {
            tracker.limit_exceeded = true;
            tracker
                .steps
                .push(StepRecord::new(Step::RunAgent, StepOutcome::LimitExceeded));
            tracker
                .reasons
                .push(format!("limit_exceeded ({}): {}", kind, detail));
        }
        Err(err) => {
            tracker.record_infra_err(Step::RunAgent, &err);
            return tracker.finalize(None);
        }
    }

    // Shutdown agent
    match run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::ShutdownAgent,
        |inf, dl| inf.shutdown_agent(agent_guard.handle(), dl),
    ) {
        Ok(ShutdownKind::Clean) => {
            if let Err(err) = tracker.machine.to_agent_done() {
                tracker.record_transition_err(Step::ShutdownAgent, &err);
                return tracker.finalize(None);
            }
            tracker
                .steps
                .push(StepRecord::new(Step::ShutdownAgent, StepOutcome::Ok));
        }
        Ok(ShutdownKind::Unclean) => {
            tracker.unclean_shutdown = true;
            if let Err(err) = tracker.machine.to_agent_done() {
                tracker.record_transition_err(Step::ShutdownAgent, &err);
                return tracker.finalize(None);
            }
            tracker
                .steps
                .push(StepRecord::new(Step::ShutdownAgent, StepOutcome::Unclean));
        }
        Err(err) => {
            tracker.record_infra_err(Step::ShutdownAgent, &err);
            return tracker.finalize(None);
        }
    }

    // 4. Destroy AgentVM and NetVM BEFORE extraction
    {
        let dl = config
            .deadlines
            .deadline_for(Step::DestroyAgentVm, clock.now_ms());
        if let Err(err) = check_deadline(clock, Step::DestroyAgentVm, &dl) {
            tracker.record_infra_err(Step::DestroyAgentVm, &err);
            return tracker.finalize(None);
        }
        if let Err(err) = agent_guard.destroy_now(&dl) {
            tracker.record_infra_err(Step::DestroyAgentVm, &err);
            return tracker.finalize(None);
        }
        if let Err(err) = check_deadline(clock, Step::DestroyAgentVm, &dl) {
            tracker.record_infra_err(Step::DestroyAgentVm, &err);
            return tracker.finalize(None);
        }
        if let Err(err) = tracker.machine.mark_agent_vm_destroyed() {
            tracker.record_transition_err(Step::DestroyAgentVm, &err);
            return tracker.finalize(None);
        }
        tracker
            .steps
            .push(StepRecord::new(Step::DestroyAgentVm, StepOutcome::Ok));
    }

    {
        let dl = config
            .deadlines
            .deadline_for(Step::DestroyNetVm, clock.now_ms());
        if let Err(err) = check_deadline(clock, Step::DestroyNetVm, &dl) {
            tracker.record_infra_err(Step::DestroyNetVm, &err);
            return tracker.finalize(None);
        }
        if let Err(err) = net_guard.destroy_now(&dl) {
            tracker.record_infra_err(Step::DestroyNetVm, &err);
            return tracker.finalize(None);
        }
        if let Err(err) = check_deadline(clock, Step::DestroyNetVm, &dl) {
            tracker.record_infra_err(Step::DestroyNetVm, &err);
            return tracker.finalize(None);
        }
        if let Err(err) = tracker.machine.mark_net_vm_destroyed() {
            tracker.record_transition_err(Step::DestroyNetVm, &err);
            return tracker.finalize(None);
        }
        tracker
            .steps
            .push(StepRecord::new(Step::DestroyNetVm, StepOutcome::Ok));
    }

    // 5. Run extractor (guaranteed no AgentVM or NetVM exists)
    if let Err(err) = tracker.machine.ensure_ready_for_extraction() {
        tracker.record_transition_err(Step::RunExtractor, &err);
        return tracker.finalize(None);
    }

    let extracted = match run_step(
        &infra_cell,
        clock,
        &config.deadlines,
        Step::RunExtractor,
        |inf, dl| inf.run_extractor(&prepared_world, dl),
    ) {
        Ok(outcome) => {
            if let Err(err) = tracker.machine.to_extracted() {
                tracker.record_transition_err(Step::RunExtractor, &err);
                return tracker.finalize(None);
            }
            if let Some(ref evidence) = outcome.tamper_evidence {
                tracker.tamper_detected = true;
                tracker
                    .steps
                    .push(StepRecord::new(Step::RunExtractor, StepOutcome::Tampered));
                tracker
                    .reasons
                    .push(format!("tampered at extractor: {}", evidence));
            } else {
                tracker
                    .steps
                    .push(StepRecord::new(Step::RunExtractor, StepOutcome::Ok));
            }
            outcome
        }
        Err(err) => {
            tracker.record_infra_err(Step::RunExtractor, &err);
            return tracker.finalize(None);
        }
    };

    // 6. Run graders: R0, R1, R2 started in parallel before any finishes; R3 optional
    let parallel_runs = [GraderRun::R0, GraderRun::R1, GraderRun::R2];
    let mut active_handles: Vec<(GraderRun, GraderHandle, NamedDeadline)> = Vec::with_capacity(3);

    for run in parallel_runs {
        let step = Step::RunGrader(run);
        let dl = config.deadlines.deadline_for(step, clock.now_ms());
        let start_res = check_deadline(clock, step, &dl).and_then(|()| {
            let mut inf = infra_cell
                .try_borrow_mut()
                .map_err(|_| InfraError::BackendFailure {
                    step,
                    detail: "infrastructure backend is mutably borrowed".to_string(),
                })?;
            inf.start_grader(run, &prepared_world, &extracted, &dl)
        });

        match start_res {
            Ok(handle) => {
                active_handles.push((run, handle, dl));
            }
            Err(err) => {
                for (prev_run, prev_handle, prev_dl) in active_handles {
                    if let Ok(mut inf) = infra_cell.try_borrow_mut() {
                        let _ = inf.abort_grader(prev_handle, &prev_dl);
                    }
                    let _ = prev_run;
                }
                tracker.record_infra_err(step, &err);
                return tracker.finalize(None);
            }
        }
    }

    let mut r0_res: Option<R0Result> = None;
    let mut r1_res: Option<R1Result> = None;
    let mut r2_res: Option<R2Result> = None;
    let mut grader_failed = false;

    for (run, handle, dl) in active_handles {
        let step = Step::RunGrader(run);
        let finish_res = {
            let mut inf = match infra_cell.try_borrow_mut() {
                Ok(guard) => guard,
                Err(_) => {
                    tracker.record_infra_err(
                        step,
                        &InfraError::BackendFailure {
                            step,
                            detail: "infrastructure backend is mutably borrowed".to_string(),
                        },
                    );
                    grader_failed = true;
                    continue;
                }
            };
            inf.finish_grader(handle, &dl)
        }
        .and_then(|outcome| {
            check_deadline(clock, step, &dl)?;
            Ok(outcome)
        });

        match finish_res {
            Ok(outcome) => {
                if let Some(ref evidence) = outcome.tamper_evidence {
                    tracker.tamper_detected = true;
                    tracker
                        .steps
                        .push(StepRecord::new(step, StepOutcome::Tampered));
                    tracker
                        .reasons
                        .push(format!("tampered at grader {}: {}", run, evidence));
                } else {
                    tracker.steps.push(StepRecord::new(step, StepOutcome::Ok));
                }

                match (run, outcome.payload) {
                    (GraderRun::R0, GraderPayload::R0(r0)) => r0_res = Some(r0),
                    (GraderRun::R1, GraderPayload::R1(r1)) => r1_res = Some(r1),
                    (GraderRun::R2, GraderPayload::R2(r2)) => r2_res = Some(r2),
                    (expected, GraderPayload::R0(_)) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected,
                                actual: GraderRun::R0,
                            },
                        );
                        grader_failed = true;
                    }
                    (expected, GraderPayload::R1(_)) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected,
                                actual: GraderRun::R1,
                            },
                        );
                        grader_failed = true;
                    }
                    (expected, GraderPayload::R2(_)) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected,
                                actual: GraderRun::R2,
                            },
                        );
                        grader_failed = true;
                    }
                    (expected, GraderPayload::R3(_)) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected,
                                actual: GraderRun::R3,
                            },
                        );
                        grader_failed = true;
                    }
                }
            }
            Err(err) => {
                tracker.record_infra_err(step, &err);
                grader_failed = true;
            }
        }
    }

    if grader_failed {
        return tracker.finalize(None);
    }

    // Optional R3 grader
    let r3_res = if config.run_r3 {
        let step = Step::RunGrader(GraderRun::R3);
        match run_step(&infra_cell, clock, &config.deadlines, step, |inf, dl| {
            inf.run_grader(GraderRun::R3, &prepared_world, &extracted, dl)
        }) {
            Ok(outcome) => {
                if let Some(ref evidence) = outcome.tamper_evidence {
                    tracker.tamper_detected = true;
                    tracker
                        .steps
                        .push(StepRecord::new(step, StepOutcome::Tampered));
                    tracker
                        .reasons
                        .push(format!("tampered at grader R3: {}", evidence));
                } else {
                    tracker.steps.push(StepRecord::new(step, StepOutcome::Ok));
                }
                match outcome.payload {
                    GraderPayload::R3(r3) => Some(r3),
                    GraderPayload::R0(_) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected: GraderRun::R3,
                                actual: GraderRun::R0,
                            },
                        );
                        return tracker.finalize(None);
                    }
                    GraderPayload::R1(_) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected: GraderRun::R3,
                                actual: GraderRun::R1,
                            },
                        );
                        return tracker.finalize(None);
                    }
                    GraderPayload::R2(_) => {
                        tracker.record_infra_err(
                            step,
                            &InfraError::GraderPayloadMismatch {
                                expected: GraderRun::R3,
                                actual: GraderRun::R2,
                            },
                        );
                        return tracker.finalize(None);
                    }
                }
            }
            Err(err) => {
                tracker.record_infra_err(step, &err);
                return tracker.finalize(None);
            }
        }
    } else {
        None
    };

    let (Some(r0), Some(r1), Some(r2)) = (r0_res, r1_res, r2_res) else {
        tracker.infra_error = true;
        return tracker.finalize(None);
    };

    let grader_results = GraderResults {
        r0,
        r1,
        r2,
        r3: r3_res,
    };

    if let Err(err) = tracker.machine.to_graded() {
        tracker.record_transition_err(Step::RunGrader(GraderRun::R2), &err);
        return tracker.finalize(Some(&grader_results));
    }

    if let Err(err) = tracker.machine.to_finished() {
        tracker.record_transition_err(Step::RunGrader(GraderRun::R2), &err);
        return tracker.finalize(Some(&grader_results));
    }

    tracker.finalize(Some(&grader_results))
}

/// Executes a complete Hermetic World evaluation run and returns its deterministic `RunSummary`.
pub fn run_evaluation<I: Infra, C: Clock>(
    infra: &mut I,
    clock: &C,
    config: &RunConfig,
) -> RunSummary {
    let cleanup_log = CleanupLog::new();
    run_evaluation_with_log(infra, clock, config, &cleanup_log)
}
