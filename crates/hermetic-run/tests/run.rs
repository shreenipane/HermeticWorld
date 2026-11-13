#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

use hermetic_run::{
    run_evaluation, run_evaluation_with_log, verdict, AgentMode, AgentOutcome, CleanupLog, Clock,
    ExtractorOutcome, GraderHandle, GraderOutcome, GraderPayload, GraderResults, GraderRun, Infra,
    InfraError, LimitKind, MutatedTestResult, NamedDeadline, PairedTestResult, PreparedWorld,
    R0Result, R1Result, R2Result, R3Result, RunConfig, RunState, RunStatus, ShutdownKind,
    StateMachine, Step, StepOutcome, TestResult, TransitionError, Verdict, VmGuard, VmHandle, VmId,
    VmKind, WorldSpec,
};
use serde_json::Value;

struct FakeClock {
    now: Cell<u64>,
}

impl FakeClock {
    fn new(start_ms: u64) -> Self {
        Self {
            now: Cell::new(start_ms),
        }
    }

    fn advance(&self, delta_ms: u64) {
        self.now.set(self.now.get().saturating_add(delta_ms));
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeEvent {
    StepCalled { step: Step, deadline_name: String },
    VmDestroyed(VmId),
    GraderStarted(GraderRun),
    GraderFinished(GraderRun),
}

struct FakeInfra<'a> {
    clock: &'a FakeClock,
    step_advance_ms: u64,
    events: Vec<FakeEvent>,
    live_vms: BTreeMap<VmId, VmKind>,
    destroyed_vms: Vec<VmId>,
    active_graders: BTreeSet<GraderRun>,
    fail_step: Option<Step>,
    panic_step: Option<Step>,
    agent_outcome: AgentOutcome,
    shutdown_kind: ShutdownKind,
    extractor_tamper: Option<String>,
    grader_tamper: BTreeMap<GraderRun, String>,
    grader_results: GraderResults,
    next_id: usize,
}

impl<'a> FakeInfra<'a> {
    fn new(clock: &'a FakeClock) -> Self {
        Self {
            clock,
            step_advance_ms: 10,
            events: Vec::new(),
            live_vms: BTreeMap::new(),
            destroyed_vms: Vec::new(),
            active_graders: BTreeSet::new(),
            fail_step: None,
            panic_step: None,
            agent_outcome: AgentOutcome::Completed { exit_code: 0 },
            shutdown_kind: ShutdownKind::Clean,
            extractor_tamper: None,
            grader_tamper: BTreeMap::new(),
            grader_results: GraderResults {
                r0: R0Result {
                    tests: vec![
                        TestResult::required("test_alpha", true),
                        TestResult::required("test_beta", true),
                    ],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("mut_alpha", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("test_alpha", true)],
                },
                r3: Some(R3Result {
                    tests: vec![TestResult::required("holdout_gamma", true)],
                }),
            },
            next_id: 0,
        }
    }

    fn alloc_id(&mut self, prefix: &str) -> VmId {
        self.next_id += 1;
        VmId(format!("{}-{}", prefix, self.next_id))
    }

    fn on_step(&mut self, step: Step, deadline: &NamedDeadline) -> Result<(), InfraError> {
        self.events.push(FakeEvent::StepCalled {
            step,
            deadline_name: deadline.name.clone(),
        });
        if self.panic_step == Some(step) {
            panic!("simulated panic at step {}", step);
        }
        self.clock.advance(self.step_advance_ms);
        if self.fail_step == Some(step) {
            return Err(InfraError::BackendFailure {
                step,
                detail: format!("injected failure at {}", step),
            });
        }
        Ok(())
    }
}

impl Infra for FakeInfra<'_> {
    fn prepare_world(
        &mut self,
        world: &WorldSpec,
        deadline: &NamedDeadline,
    ) -> Result<PreparedWorld, InfraError> {
        self.on_step(Step::PrepareWorld, deadline)?;
        Ok(PreparedWorld {
            world_id: world.world_id.clone(),
            image_digest: format!("digest:{}", world.cutoff_seal),
        })
    }

    fn start_netvm(
        &mut self,
        _world: &PreparedWorld,
        deadline: &NamedDeadline,
    ) -> Result<VmHandle, InfraError> {
        self.on_step(Step::StartNetVm, deadline)?;
        let id = self.alloc_id("netvm");
        self.live_vms.insert(id.clone(), VmKind::Net);
        Ok(VmHandle {
            id,
            kind: VmKind::Net,
        })
    }

    fn start_agentvm(
        &mut self,
        _world: &PreparedWorld,
        net_vm: &VmHandle,
        deadline: &NamedDeadline,
    ) -> Result<VmHandle, InfraError> {
        // Ordering rule: NetVM must be up before AgentVM starts.
        assert_eq!(
            self.live_vms.get(&net_vm.id),
            Some(&VmKind::Net),
            "NetVM must be alive before starting AgentVM"
        );
        self.on_step(Step::StartAgentVm, deadline)?;
        let id = self.alloc_id("agentvm");
        self.live_vms.insert(id.clone(), VmKind::Agent);
        Ok(VmHandle {
            id,
            kind: VmKind::Agent,
        })
    }

    fn wait_agent_ready(
        &mut self,
        agent_vm: &VmHandle,
        deadline: &NamedDeadline,
    ) -> Result<(), InfraError> {
        assert_eq!(self.live_vms.get(&agent_vm.id), Some(&VmKind::Agent));
        self.on_step(Step::WaitAgentReady, deadline)
    }

    fn run_agent(
        &mut self,
        agent_vm: &VmHandle,
        _mode: &AgentMode,
        deadline: &NamedDeadline,
    ) -> Result<AgentOutcome, InfraError> {
        assert_eq!(self.live_vms.get(&agent_vm.id), Some(&VmKind::Agent));
        self.on_step(Step::RunAgent, deadline)?;
        Ok(self.agent_outcome.clone())
    }

    fn shutdown_agent(
        &mut self,
        agent_vm: &VmHandle,
        deadline: &NamedDeadline,
    ) -> Result<ShutdownKind, InfraError> {
        assert_eq!(self.live_vms.get(&agent_vm.id), Some(&VmKind::Agent));
        self.on_step(Step::ShutdownAgent, deadline)?;
        Ok(self.shutdown_kind)
    }

    fn destroy_vm(&mut self, vm: &VmHandle, deadline: &NamedDeadline) -> Result<(), InfraError> {
        let step = match vm.kind {
            VmKind::Agent => Step::DestroyAgentVm,
            VmKind::Net => Step::DestroyNetVm,
            _ => Step::DestroyNetVm,
        };
        let res = self.on_step(step, deadline);
        // Remove from live_vms even if destroy reports a post-teardown error so we can track cleanup attempts.
        if self.live_vms.remove(&vm.id).is_some() {
            self.destroyed_vms.push(vm.id.clone());
            self.events.push(FakeEvent::VmDestroyed(vm.id.clone()));
        }
        res
    }

    fn run_extractor(
        &mut self,
        _world: &PreparedWorld,
        deadline: &NamedDeadline,
    ) -> Result<ExtractorOutcome, InfraError> {
        // Ordering rule: AgentVM and NetVM must be destroyed before extraction.
        assert!(
            !self.live_vms.values().any(|k| *k == VmKind::Agent),
            "extractor must never run while AgentVM exists"
        );
        assert!(
            !self.live_vms.values().any(|k| *k == VmKind::Net),
            "extractor must never run while NetVM exists"
        );
        self.on_step(Step::RunExtractor, deadline)?;
        Ok(ExtractorOutcome {
            patch_digest: "sha256:abcdef".to_string(),
            tamper_evidence: self.extractor_tamper.clone(),
        })
    }

    fn start_grader(
        &mut self,
        run_name: GraderRun,
        _world: &PreparedWorld,
        _extracted: &ExtractorOutcome,
        deadline: &NamedDeadline,
    ) -> Result<GraderHandle, InfraError> {
        self.on_step(Step::RunGrader(run_name), deadline)?;
        let id = self.alloc_id(&format!("grader-{}", run_name.as_str().to_lowercase()));
        self.live_vms.insert(id.clone(), VmKind::Grader);
        self.active_graders.insert(run_name);
        self.events.push(FakeEvent::GraderStarted(run_name));
        Ok(GraderHandle {
            run: run_name,
            vm: VmHandle {
                id,
                kind: VmKind::Grader,
            },
        })
    }

    fn finish_grader(
        &mut self,
        handle: GraderHandle,
        _deadline: &NamedDeadline,
    ) -> Result<GraderOutcome, InfraError> {
        assert!(
            self.active_graders.remove(&handle.run),
            "grader {} must be started before finishing",
            handle.run
        );
        if self.live_vms.remove(&handle.vm.id).is_some() {
            self.destroyed_vms.push(handle.vm.id.clone());
            self.events
                .push(FakeEvent::VmDestroyed(handle.vm.id.clone()));
        }
        self.events.push(FakeEvent::GraderFinished(handle.run));

        let payload = match handle.run {
            GraderRun::R0 => GraderPayload::R0(self.grader_results.r0.clone()),
            GraderRun::R1 => GraderPayload::R1(self.grader_results.r1.clone()),
            GraderRun::R2 => GraderPayload::R2(self.grader_results.r2.clone()),
            GraderRun::R3 => GraderPayload::R3(self.grader_results.r3.clone().unwrap_or_default()),
        };

        Ok(GraderOutcome {
            run: handle.run,
            payload,
            tamper_evidence: self.grader_tamper.get(&handle.run).cloned(),
        })
    }
}

fn default_config(mode: AgentMode, run_r3: bool) -> RunConfig {
    let mut cfg = RunConfig::new(
        WorldSpec {
            world_id: "world-2024-01".to_string(),
            cutoff_seal: "cutoff-2024-01-01".to_string(),
        },
        mode,
    );
    cfg.run_r3 = run_r3;
    cfg
}

#[test]
fn happy_path_mode_h_and_mode_g_and_deterministic_json_output() {
    for (mode, run_r3, expected_status) in [
        (
            AgentMode::HarnessDriven {
                commands: vec!["cargo test".to_string()],
            },
            false,
            RunStatus::Resolved,
        ),
        (
            AgentMode::GuestAutonomous {
                entrypoint: "/opt/agent/run".to_string(),
            },
            true,
            RunStatus::Review,
        ),
    ] {
        // Distinctive clock starting point that must NEVER appear in output JSON.
        let clock = FakeClock::new(888_777_666);
        let mut infra = FakeInfra::new(&clock);
        let config = default_config(mode, run_r3);

        let summary = run_evaluation(&mut infra, &clock, &config);

        assert_eq!(summary.status, expected_status);
        assert!(!summary.unclean_shutdown);
        assert!(infra.live_vms.is_empty(), "all VMs must be destroyed");

        // Verify named deadlines were passed to every step.
        assert!(infra.events.iter().any(|ev| matches!(
            ev,
            FakeEvent::StepCalled {
                step: Step::PrepareWorld,
                deadline_name
            } if deadline_name == "prepare_world_deadline"
        )));

        // Verify serialized JSON contains only allowed fields and NO host/clock times.
        let json_str = summary.to_json().expect("serialize summary");
        assert!(!json_str.contains("888777666"));

        let parsed: Value = serde_json::from_str(&json_str).expect("parse summary JSON");
        let obj = parsed.as_object().expect("top-level JSON object");
        let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = ["steps", "status", "reasons", "unclean_shutdown"]
            .into_iter()
            .collect();
        assert_eq!(keys, expected_keys);

        let steps = obj["steps"].as_array().expect("steps array");
        assert!(!steps.is_empty());
        for step_val in steps {
            let step_obj = step_val.as_object().expect("step object");
            let step_keys: BTreeSet<&str> = step_obj.keys().map(String::as_str).collect();
            let expected_step_keys: BTreeSet<&str> = ["name", "outcome"].into_iter().collect();
            assert_eq!(step_keys, expected_step_keys);
            assert_eq!(step_obj["outcome"], "ok");
        }
    }
}

#[test]
fn failure_at_every_step_cleans_up_all_vms_and_reports_infra_error_with_step() {
    let all_steps = [
        Step::PrepareWorld,
        Step::StartNetVm,
        Step::StartAgentVm,
        Step::WaitAgentReady,
        Step::RunAgent,
        Step::ShutdownAgent,
        Step::DestroyAgentVm,
        Step::DestroyNetVm,
        Step::RunExtractor,
        Step::RunGrader(GraderRun::R0),
        Step::RunGrader(GraderRun::R1),
        Step::RunGrader(GraderRun::R2),
        Step::RunGrader(GraderRun::R3),
    ];

    for failing_step in all_steps {
        let clock = FakeClock::new(1_000);
        let mut infra = FakeInfra::new(&clock);
        infra.fail_step = Some(failing_step);

        let config = default_config(
            AgentMode::GuestAutonomous {
                entrypoint: "/bin/agent".to_string(),
            },
            true,
        );

        let summary = run_evaluation(&mut infra, &clock, &config);

        assert_eq!(
            summary.status,
            RunStatus::InfraError,
            "step {:?} failure must produce infra_error",
            failing_step
        );
        assert!(
            infra.live_vms.is_empty(),
            "all started VMs must be cleaned up when {:?} fails",
            failing_step
        );
        assert!(
            summary
                .reasons
                .iter()
                .any(|r| r.contains("infra_error") && r.contains(failing_step.as_str())),
            "reasons {:?} must identify failing step '{}'",
            summary.reasons,
            failing_step.as_str()
        );
        assert!(
            summary
                .steps
                .iter()
                .any(|s| s.name == failing_step.as_str() && s.outcome == StepOutcome::Failed),
            "step list {:?} must record failed outcome for '{}'",
            summary.steps,
            failing_step.as_str()
        );
    }
}

#[test]
fn named_deadline_expiration_fails_with_deadline_name_and_cleans_up_vms() {
    let clock = FakeClock::new(100);
    let mut infra = FakeInfra::new(&clock);
    // Advance clock by 50ms per step, while setting RunAgent deadline budget to 20ms.
    infra.step_advance_ms = 50;

    let mut config = default_config(
        AgentMode::HarnessDriven {
            commands: vec!["make".to_string()],
        },
        false,
    );
    config
        .deadlines
        .set_step(Step::RunAgent, "custom_agent_budget_deadline", 20);

    let summary = run_evaluation(&mut infra, &clock, &config);

    assert_eq!(summary.status, RunStatus::InfraError);
    assert!(infra.live_vms.is_empty());
    assert!(summary
        .reasons
        .iter()
        .any(|r| { r.contains("run_agent") && r.contains("custom_agent_budget_deadline") }));
}

#[test]
fn state_machine_valid_and_invalid_transitions() {
    let mut sm = StateMachine::new();
    assert_eq!(sm.state(), &RunState::Initial);

    // Invalid: skipping Prepared -> NetUp
    assert!(matches!(
        sm.to_net_up(),
        Err(TransitionError::InvalidTransition { .. })
    ));

    // Valid: Initial -> Prepared
    sm.to_prepared().unwrap();
    assert_eq!(sm.state(), &RunState::Prepared);

    // Invalid: skipping NetUp -> AgentUp
    assert!(matches!(
        sm.to_agent_up(),
        Err(TransitionError::InvariantViolation { .. })
    ));

    // Valid: Prepared -> NetUp
    sm.to_net_up().unwrap();
    assert_eq!(sm.state(), &RunState::NetUp);

    // Valid: NetUp -> AgentUp
    sm.to_agent_up().unwrap();
    assert_eq!(sm.state(), &RunState::AgentUp);

    // Invalid: backwards AgentUp -> NetUp
    assert!(matches!(
        sm.transition(RunState::NetUp),
        Err(TransitionError::InvalidTransition { .. })
    ));

    // Valid: AgentUp -> AgentDone
    sm.to_agent_done().unwrap();
    assert_eq!(sm.state(), &RunState::AgentDone);

    // Invalid: extracting while AgentVM and NetVM are still alive
    assert!(matches!(
        sm.to_extracted(),
        Err(TransitionError::InvariantViolation { .. })
    ));

    sm.mark_agent_vm_destroyed().unwrap();
    // Still invalid while NetVM is alive
    assert!(matches!(
        sm.to_extracted(),
        Err(TransitionError::InvariantViolation { .. })
    ));

    sm.mark_net_vm_destroyed().unwrap();
    // Now valid: AgentDone -> Extracted -> Graded -> Finished
    sm.to_extracted().unwrap();
    sm.to_graded().unwrap();
    sm.to_finished().unwrap();
    assert_eq!(sm.state(), &RunState::Finished);

    // Invalid: transitioning out of terminal Finished state
    assert!(matches!(
        sm.fail(Step::RunExtractor, "late failure"),
        Err(TransitionError::InvalidTransition { .. })
    ));

    // Terminal Failed state also rejects further transitions
    let mut failed_sm = StateMachine::new();
    failed_sm.to_prepared().unwrap();
    failed_sm.fail(Step::StartNetVm, "boom").unwrap();
    assert!(matches!(
        failed_sm.to_net_up(),
        Err(TransitionError::InvalidTransition { .. })
    ));
}

#[test]
fn vm_guard_drop_cleans_up_all_vms_even_on_fake_panic() {
    let clock = FakeClock::new(0);
    let mut infra = FakeInfra::new(&clock);
    infra.panic_step = Some(Step::RunAgent);
    let cleanup_log = CleanupLog::new();

    let config = default_config(
        AgentMode::GuestAutonomous {
            entrypoint: "/run".to_string(),
        },
        false,
    );

    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _ = run_evaluation_with_log(&mut infra, &clock, &config, &cleanup_log);
    }));

    assert!(panicked.is_err(), "fake panic should unwind out of run");
    assert!(
        infra.live_vms.is_empty(),
        "VmGuard::drop must destroy both AgentVM and NetVM on panic"
    );

    let recorded = cleanup_log.entries();
    assert_eq!(
        recorded,
        vec![VmId("agentvm-2".to_string()), VmId("netvm-1".to_string())],
        "VmGuard::drop must record cleanup in reverse start order"
    );

    // Also test VmGuard directly in isolation on panic.
    let mut direct_infra = FakeInfra::new(&clock);
    let direct_log = CleanupLog::new();
    let vm = VmHandle::new("direct-vm-99", VmKind::Agent);
    direct_infra.live_vms.insert(vm.id.clone(), VmKind::Agent);

    let direct_panic = catch_unwind(AssertUnwindSafe(|| {
        let cell = std::cell::RefCell::new(&mut direct_infra);
        let _guard = VmGuard::new(
            &cell,
            &direct_log,
            vm.clone(),
            NamedDeadline::new("cleanup_dl", 500),
        );
        panic!("panic while holding VmGuard");
    }));

    assert!(direct_panic.is_err());
    assert_eq!(direct_log.entries(), vec![VmId("direct-vm-99".to_string())]);
    assert!(direct_infra.live_vms.is_empty());
}

#[test]
fn ordering_rules_and_parallel_graders_and_optional_r3() {
    let clock = FakeClock::new(0);
    let mut infra = FakeInfra::new(&clock);
    let config = default_config(
        AgentMode::HarnessDriven {
            commands: vec!["pytest".to_string()],
        },
        false,
    );

    let summary = run_evaluation(&mut infra, &clock, &config);
    assert_eq!(summary.status, RunStatus::Resolved);

    // 1. NetVM starts before AgentVM starts.
    let pos_net_start = infra
        .events
        .iter()
        .position(|e| {
            matches!(
                e,
                FakeEvent::StepCalled {
                    step: Step::StartNetVm,
                    ..
                }
            )
        })
        .unwrap();
    let pos_agent_start = infra
        .events
        .iter()
        .position(|e| {
            matches!(
                e,
                FakeEvent::StepCalled {
                    step: Step::StartAgentVm,
                    ..
                }
            )
        })
        .unwrap();
    assert!(pos_net_start < pos_agent_start);

    // 2. AgentVM and NetVM are destroyed before extractor runs.
    let pos_agent_destroyed = infra
        .events
        .iter()
        .position(|e| e == &FakeEvent::VmDestroyed(VmId("agentvm-2".to_string())))
        .unwrap();
    let pos_net_destroyed = infra
        .events
        .iter()
        .position(|e| e == &FakeEvent::VmDestroyed(VmId("netvm-1".to_string())))
        .unwrap();
    let pos_extractor = infra
        .events
        .iter()
        .position(|e| {
            matches!(
                e,
                FakeEvent::StepCalled {
                    step: Step::RunExtractor,
                    ..
                }
            )
        })
        .unwrap();
    assert!(pos_agent_destroyed < pos_extractor);
    assert!(pos_net_destroyed < pos_extractor);

    // 3. Graders R0, R1, R2 are all started before any finishes.
    let started_positions: Vec<usize> = [GraderRun::R0, GraderRun::R1, GraderRun::R2]
        .iter()
        .map(|r| {
            infra
                .events
                .iter()
                .position(|e| e == &FakeEvent::GraderStarted(*r))
                .unwrap()
        })
        .collect();
    let first_finished_pos = infra
        .events
        .iter()
        .position(|e| matches!(e, FakeEvent::GraderFinished(_)))
        .unwrap();

    for start_pos in started_positions {
        assert!(
            start_pos < first_finished_pos,
            "all of R0, R1, R2 must start before any finishes; events: {:?}",
            infra.events
        );
    }

    // 4. R3 is optional and was not run when run_r3 = false.
    assert!(
        !infra
            .events
            .iter()
            .any(|e| e == &FakeEvent::GraderStarted(GraderRun::R3)),
        "R3 must not run when run_r3 is false"
    );
}

#[test]
fn table_driven_verdict_rules_and_status_precedence_conflicts() {
    struct VerdictCase {
        name: &'static str,
        results: GraderResults,
        expected: Verdict,
    }

    let verdict_cases = [
        VerdictCase {
            name: "resolved when R0 passes required, R1 mutants fail, R2 matches R0, R3 absent",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![
                        TestResult::required("t1", true),
                        TestResult::optional("t_opt", false),
                    ],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", true)],
                },
                r3: None,
            },
            expected: Verdict::Resolved,
        },
        VerdictCase {
            name: "review when R0 passes required and R3 passes all required tests",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", true)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", true)],
                },
                r3: Some(R3Result {
                    tests: vec![
                        TestResult::required("r3_req", true),
                        TestResult::optional("r3_opt", false),
                    ],
                }),
            },
            expected: Verdict::Review,
        },
        VerdictCase {
            name: "resolved when R3 fails a required test",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", true)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", true)],
                },
                r3: Some(R3Result {
                    tests: vec![TestResult::required("r3_req", false)],
                }),
            },
            expected: Verdict::Resolved,
        },
        VerdictCase {
            name: "unresolved when R0 fails any required test",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![
                        TestResult::required("t1", true),
                        TestResult::required("t2", false),
                    ],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", true)],
                },
                r3: None,
            },
            expected: Verdict::Unresolved,
        },
        VerdictCase {
            name: "tampered when R1 has a mutated test not failing",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", true)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", false)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", true)],
                },
                r3: None,
            },
            expected: Verdict::Tampered,
        },
        VerdictCase {
            name: "tampered when R2 differs from R0 on a paired test",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", true)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", false)],
                },
                r3: None,
            },
            expected: Verdict::Tampered,
        },
        VerdictCase {
            name: "conflict: R1 tampered beats R0 unresolved",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", false)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", false)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", false)],
                },
                r3: Some(R3Result {
                    tests: vec![TestResult::required("r3_req", true)],
                }),
            },
            expected: Verdict::Tampered,
        },
        VerdictCase {
            name: "conflict: R2 tampered beats R0 unresolved and R3 review",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", false)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", true)],
                },
                r3: Some(R3Result {
                    tests: vec![TestResult::required("r3_req", true)],
                }),
            },
            expected: Verdict::Tampered,
        },
        VerdictCase {
            name: "conflict: R0 unresolved beats R3 review",
            results: GraderResults {
                r0: R0Result {
                    tests: vec![TestResult::required("t1", false)],
                },
                r1: R1Result {
                    mutated_tests: vec![MutatedTestResult::new("m1", true)],
                },
                r2: R2Result {
                    paired_tests: vec![PairedTestResult::new("t1", false)],
                },
                r3: Some(R3Result {
                    tests: vec![TestResult::required("r3_req", true)],
                }),
            },
            expected: Verdict::Unresolved,
        },
    ];

    for case in verdict_cases {
        assert_eq!(verdict(&case.results), case.expected, "case: {}", case.name);
    }

    // End-to-end precedence table across system signals + grader verdict:
    // tampered > infra_error > limit_exceeded > unresolved > review > resolved
    struct PrecedenceCase {
        name: &'static str,
        extractor_tamper: Option<&'static str>,
        grader_r1_tamper: bool,
        fail_step: Option<Step>,
        agent_outcome: AgentOutcome,
        r0_pass: bool,
        run_r3: bool,
        expected: RunStatus,
    }

    let precedence_cases = [
        PrecedenceCase {
            name: "extractor tamper beats infra_error and limit_exceeded",
            extractor_tamper: Some("modified read-only harness"),
            grader_r1_tamper: false,
            fail_step: Some(Step::RunGrader(GraderRun::R0)),
            agent_outcome: AgentOutcome::LimitExceeded {
                kind: LimitKind::Quota,
                detail: "token quota".to_string(),
            },
            r0_pass: false,
            run_r3: true,
            expected: RunStatus::Tampered,
        },
        PrecedenceCase {
            name: "grader tamper beats limit_exceeded and unresolved",
            extractor_tamper: None,
            grader_r1_tamper: true,
            fail_step: None,
            agent_outcome: AgentOutcome::LimitExceeded {
                kind: LimitKind::VolumeCap,
                detail: "disk cap".to_string(),
            },
            r0_pass: false,
            run_r3: true,
            expected: RunStatus::Tampered,
        },
        PrecedenceCase {
            name: "infra_error beats limit_exceeded",
            extractor_tamper: None,
            grader_r1_tamper: false,
            fail_step: Some(Step::RunExtractor),
            agent_outcome: AgentOutcome::LimitExceeded {
                kind: LimitKind::Quota,
                detail: "step quota".to_string(),
            },
            r0_pass: true,
            run_r3: true,
            expected: RunStatus::InfraError,
        },
        PrecedenceCase {
            name: "limit_exceeded (quota) beats unresolved and review",
            extractor_tamper: None,
            grader_r1_tamper: false,
            fail_step: None,
            agent_outcome: AgentOutcome::LimitExceeded {
                kind: LimitKind::Quota,
                detail: "api quota".to_string(),
            },
            r0_pass: false,
            run_r3: true,
            expected: RunStatus::LimitExceeded,
        },
        PrecedenceCase {
            name: "limit_exceeded (volume cap) beats resolved",
            extractor_tamper: None,
            grader_r1_tamper: false,
            fail_step: None,
            agent_outcome: AgentOutcome::LimitExceeded {
                kind: LimitKind::VolumeCap,
                detail: "10GB cap".to_string(),
            },
            r0_pass: true,
            run_r3: false,
            expected: RunStatus::LimitExceeded,
        },
        PrecedenceCase {
            name: "unresolved beats review",
            extractor_tamper: None,
            grader_r1_tamper: false,
            fail_step: None,
            agent_outcome: AgentOutcome::Completed { exit_code: 1 },
            r0_pass: false,
            run_r3: true,
            expected: RunStatus::Unresolved,
        },
        PrecedenceCase {
            name: "review beats resolved when R3 passes",
            extractor_tamper: None,
            grader_r1_tamper: false,
            fail_step: None,
            agent_outcome: AgentOutcome::Completed { exit_code: 0 },
            r0_pass: true,
            run_r3: true,
            expected: RunStatus::Review,
        },
        PrecedenceCase {
            name: "resolved when all checks pass and R3 is omitted",
            extractor_tamper: None,
            grader_r1_tamper: false,
            fail_step: None,
            agent_outcome: AgentOutcome::Completed { exit_code: 0 },
            r0_pass: true,
            run_r3: false,
            expected: RunStatus::Resolved,
        },
    ];

    for case in precedence_cases {
        let clock = FakeClock::new(0);
        let mut infra = FakeInfra::new(&clock);
        infra.extractor_tamper = case.extractor_tamper.map(str::to_string);
        infra.fail_step = case.fail_step;
        infra.agent_outcome = case.agent_outcome;
        infra.grader_results = GraderResults {
            r0: R0Result {
                tests: vec![TestResult::required("test_alpha", case.r0_pass)],
            },
            r1: R1Result {
                mutated_tests: vec![MutatedTestResult::new("mut_alpha", !case.grader_r1_tamper)],
            },
            r2: R2Result {
                paired_tests: vec![PairedTestResult::new("test_alpha", case.r0_pass)],
            },
            r3: Some(R3Result {
                tests: vec![TestResult::required("holdout_gamma", true)],
            }),
        };

        let config = default_config(
            AgentMode::GuestAutonomous {
                entrypoint: "/agent".to_string(),
            },
            case.run_r3,
        );
        let summary = run_evaluation(&mut infra, &clock, &config);
        assert_eq!(summary.status, case.expected, "case: {}", case.name);
        assert!(infra.live_vms.is_empty());
    }
}

#[test]
fn unclean_shutdown_is_recorded_in_summary_and_step_list() {
    let clock = FakeClock::new(0);
    let mut infra = FakeInfra::new(&clock);
    infra.shutdown_kind = ShutdownKind::Unclean;

    let config = default_config(
        AgentMode::GuestAutonomous {
            entrypoint: "/agent".to_string(),
        },
        false,
    );

    let summary = run_evaluation(&mut infra, &clock, &config);

    assert!(summary.unclean_shutdown);
    assert_eq!(summary.status, RunStatus::Resolved);
    assert!(infra.live_vms.is_empty());

    let shutdown_step = summary
        .steps
        .iter()
        .find(|s| s.name == "shutdown_agent")
        .expect("shutdown_agent step must be recorded");
    assert_eq!(shutdown_step.outcome, StepOutcome::Unclean);

    let json: Value = serde_json::from_str(&summary.to_json().unwrap()).unwrap();
    assert_eq!(json["unclean_shutdown"], Value::Bool(true));
}
