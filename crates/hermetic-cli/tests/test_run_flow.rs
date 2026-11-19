#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde_json::json;

use hermetic_attest::offline_key::{Ed25519Signer, Ed25519Verifier};
use hermetic_attest::verify::{verify_run_attestation, ReplayGuard, RunBinding};
use hermetic_cli::args::{AgentMode, ClockMode, RunRequest};
use hermetic_cli::dispatch::BackendError;
use hermetic_cli::run_flow::{execute_run_flow, FakeClock};
use hermetic_cli::{run_with_args, ExitCode, RealBackend};
use hermetic_run::infra::{
    AgentMode as RunAgentMode, AgentOutcome, ExtractorOutcome, GraderHandle, GraderOutcome,
    GraderPayload, GraderRun, Infra, InfraError, NamedDeadline, PreparedWorld, ShutdownKind, Step,
    VmHandle, VmId, VmKind, WorldSpec,
};
use hermetic_run::verdict::{
    MutatedTestResult, PairedTestResult, R0Result, R1Result, R2Result, R3Result, TestResult,
};

fn generate_test_key() -> (Vec<u8>, Ed25519Signer, Ed25519Verifier) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let signer = Ed25519Signer::from_pkcs8(&pkcs8).unwrap();
    let pk = signer.public_key();
    let verifier = Ed25519Verifier::new(&[&pk]).unwrap();
    (pkcs8, signer, verifier)
}

fn write_canonical_run_dir(dir: &Path) {
    // 1. date_sentinel.json
    let gateway = json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 1000
    });
    fs::write(dir.join("date_sentinel.json"), gateway.to_string()).unwrap();

    // 2. harness_summary.json
    let harness = json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 2000
    });
    fs::write(dir.join("harness_summary.json"), harness.to_string()).unwrap();

    // 3. probe_output.jsonl
    let probe_lines = [
        r#"{"probe":"clock_pairing_hc","result":"unavailable","detail":"hypercall blocked"}"#,
        r#"{"probe":"clocksource_sysfs","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"cpuid","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"cpuinfo","result":"blocked","detail":"filtered"}"#,
        r#"{"probe":"dmesg_dates","result":"blocked","detail":"clear"}"#,
        r#"{"probe":"hpet","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"kernel_canary","result":"blocked","detail":"canary blocked"}"#,
        r#"{"probe":"kvmclock_msr","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"module_load","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"posix_clocks","result":"blocked","detail":"locked"}"#,
        r#"{"probe":"proc_driver_rtc","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"rdtsc","result":"blocked","detail":"trapped"}"#,
        r#"{"probe":"ring0_paths","result":"blocked","detail":"inaccessible"}"#,
        r#"{"probe":"rtc_sysfs_dev","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"vmclock","result":"blocked","detail":"disabled"}"#,
    ]
    .join("\n");
    fs::write(dir.join("probe_output.jsonl"), probe_lines).unwrap();

    // 4. boot_record.json
    let boot = json!({
        "vm_id": "agent-vm-0",
        "boot_path": "sealed_disk"
    });
    fs::write(dir.join("boot_record.json"), boot.to_string()).unwrap();

    // 5. verdict.json
    let verdict = json!({
        "run_status": "resolved",
        "r0_result": "passed",
        "r1_result": "passed",
        "r2_result": "passed",
        "r3_result": "passed",
        "r1_coverage": 1000,
        "unclean_shutdown": false,
        "submitted_work_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    });
    fs::write(dir.join("verdict.json"), verdict.to_string()).unwrap();

    // 6. world_manifest.json
    let manifest = json!({
        "task_id": "fixture-task",
        "task_class": "patch",
        "seal_level": "strict",
        "agent_mode": "H",
        "substrate": "microvm",
        "grader_isolation": "clean",
        "deployment": "single_host",
        "t_world": "2020-01-01T00:00:00Z",
        "t_clock": "2020-01-01T00:00:00Z",
        "base_commit": "abcdef0123456789abcdef0123456789abcdef01",
        "spec_version": "v1.1",
        "world_version": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "sealcheck_version": "v1.0",
        "grader_image_digest": "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "world_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "task_rootfs_digest": "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "netvm_image_digest": "sha256:3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "guest_kernel_digest": "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "vm_config_digest": "sha256:5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "cpu_template_digest": "sha256:6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "firecracker_build_digest": "sha256:7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "agent_volume_digest": "sha256:8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "sealcheck_report_digest": "sha256:9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "substrate_at_t": "full",
        "exemption_list": ["pkg-a", "pkg-b"],
        "world_server_log_head": "sha256:b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "dedupe_index_digest": "sha256:c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "request_count": 42,
        "harness_command_log_head": "sha256:d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    });
    fs::write(dir.join("world_manifest.json"), manifest.to_string()).unwrap();

    // 7. submitted_work.patch
    fs::write(
        dir.join("submitted_work.patch"),
        b"--- a/calc.py\n+++ b/calc.py\n@@ -1 +1 @@\n-return a - b\n+return a + b\n",
    )
    .unwrap();
}

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct MockInfra {
    fail_step: Option<Step>,
    timeout_step: Option<Step>,
    panic_step: Option<Step>,
    live_vms: BTreeMap<VmId, VmKind>,
    destroyed_vms: Vec<VmId>,
    run_dir: PathBuf,
    skip_write_verdict: bool,
    mismatched_verdict_status: Option<String>,
    drop_artifact: Option<&'static str>,
}

impl MockInfra {
    fn new(run_dir: PathBuf) -> Self {
        Self {
            fail_step: None,
            timeout_step: None,
            panic_step: None,
            live_vms: BTreeMap::new(),
            destroyed_vms: Vec::new(),
            run_dir,
            skip_write_verdict: false,
            mismatched_verdict_status: None,
            drop_artifact: None,
        }
    }

    fn check_step(&mut self, step: Step) -> Result<(), InfraError> {
        if Some(step) == self.panic_step {
            panic!("injected panic at step {:?}", step);
        }
        if Some(step) == self.timeout_step {
            return Err(InfraError::DeadlineExceeded {
                step,
                deadline_name: format!("{step}_deadline"),
            });
        }
        if Some(step) == self.fail_step {
            return Err(InfraError::BackendFailure {
                step,
                detail: format!("injected failure at step {:?}", step),
            });
        }
        Ok(())
    }
}

impl Infra for MockInfra {
    fn prepare_world(
        &mut self,
        world: &WorldSpec,
        _deadline: &NamedDeadline,
    ) -> Result<PreparedWorld, InfraError> {
        self.check_step(Step::PrepareWorld)?;
        write_canonical_run_dir(&self.run_dir);
        if self.skip_write_verdict {
            let _ = fs::remove_file(self.run_dir.join("verdict.json"));
        }
        if let Some(name) = self.drop_artifact {
            fs::remove_file(self.run_dir.join(name)).unwrap();
        }
        if let Some(ref st) = self.mismatched_verdict_status {
            let mut verdict: serde_json::Value =
                serde_json::from_slice(&fs::read(self.run_dir.join("verdict.json")).unwrap())
                    .unwrap();
            verdict["run_status"] = serde_json::json!(st);
            fs::write(self.run_dir.join("verdict.json"), verdict.to_string()).unwrap();
        }
        Ok(PreparedWorld {
            world_id: world.world_id.clone(),
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
        })
    }

    fn start_netvm(
        &mut self,
        _world: &PreparedWorld,
        _deadline: &NamedDeadline,
    ) -> Result<VmHandle, InfraError> {
        self.check_step(Step::StartNetVm)?;
        let handle = VmHandle::new("net-vm-0", VmKind::Net);
        self.live_vms.insert(handle.id.clone(), VmKind::Net);
        Ok(handle)
    }

    fn start_agentvm(
        &mut self,
        _world: &PreparedWorld,
        _net_vm: &VmHandle,
        _deadline: &NamedDeadline,
    ) -> Result<VmHandle, InfraError> {
        self.check_step(Step::StartAgentVm)?;
        let handle = VmHandle::new("agent-vm-0", VmKind::Agent);
        self.live_vms.insert(handle.id.clone(), VmKind::Agent);
        Ok(handle)
    }

    fn wait_agent_ready(
        &mut self,
        _agent_vm: &VmHandle,
        _deadline: &NamedDeadline,
    ) -> Result<(), InfraError> {
        self.check_step(Step::WaitAgentReady)
    }

    fn run_agent(
        &mut self,
        _agent_vm: &VmHandle,
        _mode: &RunAgentMode,
        _deadline: &NamedDeadline,
    ) -> Result<AgentOutcome, InfraError> {
        self.check_step(Step::RunAgent)?;
        Ok(AgentOutcome::Completed { exit_code: 0 })
    }

    fn shutdown_agent(
        &mut self,
        _agent_vm: &VmHandle,
        _deadline: &NamedDeadline,
    ) -> Result<ShutdownKind, InfraError> {
        self.check_step(Step::ShutdownAgent)?;
        Ok(ShutdownKind::Clean)
    }

    fn destroy_vm(&mut self, vm: &VmHandle, _deadline: &NamedDeadline) -> Result<(), InfraError> {
        let step = if vm.kind == VmKind::Agent {
            Step::DestroyAgentVm
        } else {
            Step::DestroyNetVm
        };
        let res = self.check_step(step);
        if self.live_vms.remove(&vm.id).is_some() {
            self.destroyed_vms.push(vm.id.clone());
        }
        res
    }

    fn run_extractor(
        &mut self,
        _world: &PreparedWorld,
        _deadline: &NamedDeadline,
    ) -> Result<ExtractorOutcome, InfraError> {
        self.check_step(Step::RunExtractor)?;
        Ok(ExtractorOutcome {
            patch_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            tamper_evidence: None,
        })
    }

    fn start_grader(
        &mut self,
        run_name: GraderRun,
        _world: &PreparedWorld,
        _extracted: &ExtractorOutcome,
        _deadline: &NamedDeadline,
    ) -> Result<GraderHandle, InfraError> {
        self.check_step(Step::RunGrader(run_name))?;
        let handle = GraderHandle {
            run: run_name,
            vm: VmHandle::new(format!("grader-vm-{}", run_name.as_str()), VmKind::Grader),
        };
        self.live_vms.insert(handle.vm.id.clone(), VmKind::Grader);
        Ok(handle)
    }

    fn finish_grader(
        &mut self,
        handle: GraderHandle,
        _deadline: &NamedDeadline,
    ) -> Result<GraderOutcome, InfraError> {
        self.live_vms.remove(&handle.vm.id);
        self.destroyed_vms.push(handle.vm.id.clone());
        let payload = match handle.run {
            GraderRun::R0 => GraderPayload::R0(R0Result {
                tests: vec![TestResult::required("test_1", true)],
            }),
            GraderRun::R1 => GraderPayload::R1(R1Result {
                mutated_tests: vec![MutatedTestResult::new("test_1", true)],
            }),
            GraderRun::R2 => GraderPayload::R2(R2Result {
                paired_tests: vec![PairedTestResult::new("test_1", true)],
            }),
            GraderRun::R3 => GraderPayload::R3(R3Result {
                tests: vec![TestResult::required("test_1", true)],
            }),
            GraderRun::Base => GraderPayload::Base(R0Result {
                tests: vec![TestResult::required("test_1", true)],
            }),
            GraderRun::Gold => GraderPayload::Gold(R0Result {
                tests: vec![TestResult::required("test_1", true)],
            }),
        };
        Ok(GraderOutcome {
            run: handle.run,
            payload,
            tamper_evidence: None,
        })
    }
}

#[test]
fn test_run_flow_happy_path_produces_known_answer_and_signed_record() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());

    let (pkcs8, _signer, verifier) = generate_test_key();
    let key_file = temp.path().join("signing.key");
    fs::write(&key_file, &pkcs8).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();

    let req = RunRequest {
        world: world_dir,
        task: "fixture-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_file))
        .expect("happy path run flow must succeed");

    assert!(outcome.ok);
    assert_eq!(outcome.details.get("status").unwrap(), "resolved");
    assert_eq!(outcome.details.get("unclean_shutdown").unwrap(), false);

    // Verify canonical artifacts exist in run_dir
    assert!(run_dir.join("date_sentinel.json").exists());
    assert!(run_dir.join("harness_summary.json").exists());
    assert!(run_dir.join("probe_output.jsonl").exists());
    assert!(run_dir.join("boot_record.json").exists());
    assert!(run_dir.join("verdict.json").exists());
    assert!(run_dir.join("world_manifest.json").exists());
    assert!(run_dir.join("submitted_work.patch").exists());

    // Verify signed record.json exists and is valid DSSE attestation
    let record_file = run_dir.join("record.json");
    assert!(record_file.exists());
    let record_bytes = fs::read(&record_file).unwrap();
    let record_str = std::str::from_utf8(&record_bytes).unwrap();

    let mut replay_guard = ReplayGuard::new();
    let binding = RunBinding::default();
    let (statement, digest) =
        verify_run_attestation(record_str, &verifier, &binding, &mut replay_guard)
            .expect("record must verify with Ed25519 verifier");
    assert_eq!(statement.predicate.task_id, "fixture-task");
    assert!(!digest.to_string().is_empty());

    // Verify that all started VMs were destroyed
    assert!(infra.live_vms.is_empty(), "all VMs must be destroyed");
    assert!(infra.destroyed_vms.contains(&VmId("net-vm-0".into())));
    assert!(infra.destroyed_vms.contains(&VmId("agent-vm-0".into())));
}

#[test]
fn test_run_flow_each_step_failing() {
    let steps_to_test = [
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
    ];

    for step in steps_to_test {
        let temp = tempfile::tempdir().unwrap();
        let world_dir = temp.path().join("world");
        fs::create_dir_all(&world_dir).unwrap();
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();

        let clock = FakeClock::new(1000);
        let mut infra = MockInfra::new(run_dir.clone());
        infra.fail_step = Some(step);

        let req = RunRequest {
            world: world_dir,
            task: "fail-task".into(),
            agent_mode: AgentMode::H,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: None,
            entrypoint: None,
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };

        let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, None)
            .expect("failure outcome should be returned");

        assert!(
            !outcome.ok,
            "outcome must be problem on failure at step {:?}",
            step
        );
        let status = outcome.details.get("status").unwrap().as_str().unwrap();
        assert_eq!(
            status, "infra_error",
            "expected terminal error status infra_error, got {status} for step {:?}",
            step
        );

        // Verify terminal verdict written to run_dir with matching terminal failure status
        let verdict_bytes = fs::read(run_dir.join("verdict.json")).unwrap();
        let verdict_val: serde_json::Value = serde_json::from_slice(&verdict_bytes).unwrap();
        assert_eq!(
            verdict_val.get("run_status").and_then(|v| v.as_str()),
            Some("infra_error"),
            "verdict run_status must match failure status for step {:?}",
            step
        );
        assert_eq!(
            verdict_val.get("run_status").and_then(|v| v.as_str()),
            Some(status)
        );

        // Verify infra_error.json exists and has expected error kind
        assert!(run_dir.join("infra_error.json").exists());
        let infra_err_bytes = fs::read(run_dir.join("infra_error.json")).unwrap();
        let infra_err_val: serde_json::Value = serde_json::from_slice(&infra_err_bytes).unwrap();
        assert_eq!(
            infra_err_val.get("error_kind").and_then(|v| v.as_str()),
            Some("backend_failure")
        );

        // Zero VMs leaked
        assert!(
            infra.live_vms.is_empty(),
            "VM leak detected when step {:?} failed: {:?}",
            step,
            infra.live_vms
        );
    }
}

#[test]
fn test_run_flow_step_timeout_at_each_step() {
    let steps_to_test = [
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
    ];

    for step in steps_to_test {
        let temp = tempfile::tempdir().unwrap();
        let world_dir = temp.path().join("world");
        fs::create_dir_all(&world_dir).unwrap();
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();

        let clock = FakeClock::new(1000);
        let mut infra = MockInfra::new(run_dir.clone());
        infra.timeout_step = Some(step);

        let req = RunRequest {
            world: world_dir,
            task: "timeout-task".into(),
            agent_mode: AgentMode::H,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: None,
            entrypoint: None,
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };

        let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, None)
            .expect("timeout outcome should be returned");

        assert!(
            !outcome.ok,
            "outcome must be problem on timeout at step {:?}",
            step
        );
        let status = outcome.details.get("status").unwrap().as_str().unwrap();
        assert_eq!(status, "infra_error");

        // Verify infra_error.json exists and has expected error kind
        assert!(run_dir.join("infra_error.json").exists());
        let infra_err_bytes = fs::read(run_dir.join("infra_error.json")).unwrap();
        let infra_err_val: serde_json::Value = serde_json::from_slice(&infra_err_bytes).unwrap();
        assert_eq!(
            infra_err_val.get("error_kind").and_then(|v| v.as_str()),
            Some("deadline_exceeded")
        );

        // Zero VMs leaked
        assert!(
            infra.live_vms.is_empty(),
            "VM leak detected on timeout at step {:?}",
            step
        );
    }
}

#[test]
fn test_run_flow_teardown_always_happens_on_panic() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());
    infra.panic_step = Some(Step::RunAgent);

    let req = RunRequest {
        world: world_dir,
        task: "panic-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = execute_run_flow(&mut infra, &clock, &req, &run_dir, None);
    }));

    assert!(result.is_err(), "panic must be propagated");
    // Verify VmGuard cleaned up VMs on unwind
    assert!(
        infra.live_vms.is_empty(),
        "VmGuard must destroy VMs even on panic unwinding"
    );
}

#[test]
fn test_run_flow_refuses_symlinked_world() {
    let temp = tempfile::tempdir().unwrap();
    let real_world = temp.path().join("real_world");
    fs::create_dir_all(&real_world).unwrap();
    let sym_world = temp.path().join("sym_world");
    symlink(&real_world, &sym_world).unwrap();

    let run_dir = temp.path().join("run");
    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());

    let req = RunRequest {
        world: sym_world,
        task: "sym-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let res = execute_run_flow(&mut infra, &clock, &req, &run_dir, None);
    assert!(matches!(res, Err(BackendError::Data(_))));
}

#[test]
fn test_run_flow_missing_world_returns_io_error() {
    let temp = tempfile::tempdir().unwrap();
    let missing_world = temp.path().join("does_not_exist");
    let run_dir = temp.path().join("run");
    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());

    let req = RunRequest {
        world: missing_world,
        task: "missing-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let res = execute_run_flow(&mut infra, &clock, &req, &run_dir, None);
    assert!(matches!(res, Err(BackendError::Io(_))));
}

#[test]
fn run_with_real_infra_reports_specific_missing_variable() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();

    let orig_fc = std::env::var_os("HERMETIC_FC_BIN");
    let orig_kernel = std::env::var_os("HERMETIC_KERNEL");
    let orig_rootfs = std::env::var_os("HERMETIC_ROOTFS");
    let orig_run_dir = std::env::var_os("HERMETIC_RUN_DIR");

    let req = RunRequest {
        world: world_dir,
        task: "task-test".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    // 1. None set -> RUN_NOT_WIRED
    std::env::remove_var("HERMETIC_FC_BIN");
    std::env::remove_var("HERMETIC_KERNEL");
    std::env::remove_var("HERMETIC_ROOTFS");
    let err = hermetic_cli::run_flow::run_with_real_infra(req.clone()).unwrap_err();
    assert!(
        matches!(err, BackendError::Unavailable(msg) if msg == hermetic_cli::backend::RUN_NOT_WIRED)
    );

    // 2. Missing HERMETIC_FC_BIN
    std::env::set_var("HERMETIC_KERNEL", "kernel");
    std::env::set_var("HERMETIC_ROOTFS", "rootfs");
    let err = hermetic_cli::run_flow::run_with_real_infra(req.clone()).unwrap_err();
    assert!(matches!(
        err,
        BackendError::Unavailable("HERMETIC_FC_BIN must be set")
    ));

    // 3. Missing HERMETIC_KERNEL
    std::env::set_var("HERMETIC_FC_BIN", "fc");
    std::env::remove_var("HERMETIC_KERNEL");
    let err = hermetic_cli::run_flow::run_with_real_infra(req.clone()).unwrap_err();
    assert!(matches!(
        err,
        BackendError::Unavailable("HERMETIC_KERNEL must be set")
    ));

    // 4. Missing HERMETIC_ROOTFS
    std::env::set_var("HERMETIC_KERNEL", "kernel");
    std::env::remove_var("HERMETIC_ROOTFS");
    let err = hermetic_cli::run_flow::run_with_real_infra(req.clone()).unwrap_err();
    assert!(matches!(
        err,
        BackendError::Unavailable("HERMETIC_ROOTFS must be set")
    ));

    // 5. All three set, missing HERMETIC_RUN_DIR
    std::env::set_var("HERMETIC_ROOTFS", "rootfs");
    std::env::remove_var("HERMETIC_RUN_DIR");
    let err = hermetic_cli::run_flow::run_with_real_infra(req).unwrap_err();
    assert!(
        matches!(err, BackendError::Unavailable(msg) if msg.contains("HERMETIC_RUN_DIR must be set"))
    );

    // Restore environment
    if let Some(v) = orig_fc {
        std::env::set_var("HERMETIC_FC_BIN", v);
    } else {
        std::env::remove_var("HERMETIC_FC_BIN");
    }
    if let Some(v) = orig_kernel {
        std::env::set_var("HERMETIC_KERNEL", v);
    } else {
        std::env::remove_var("HERMETIC_KERNEL");
    }
    if let Some(v) = orig_rootfs {
        std::env::set_var("HERMETIC_ROOTFS", v);
    } else {
        std::env::remove_var("HERMETIC_ROOTFS");
    }
    if let Some(v) = orig_run_dir {
        std::env::set_var("HERMETIC_RUN_DIR", v);
    } else {
        std::env::remove_var("HERMETIC_RUN_DIR");
    }
}

#[test]
fn run_flow_requires_run_dir_and_valid_task_segment() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();

    let orig_run_dir = std::env::var_os("HERMETIC_RUN_DIR");
    std::env::remove_var("HERMETIC_RUN_DIR");

    let req = RunRequest {
        world: world_dir.clone(),
        task: "valid-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    // Calling run_with_real_infra without HERMETIC_RUN_DIR fails with Unavailable
    let err = hermetic_cli::run_flow::run_with_real_infra(req).unwrap_err();
    assert!(matches!(err, BackendError::Unavailable(_)));

    // execute_run_flow rejects task that is not a single path segment
    let clock = FakeClock::new(1000);
    let run_dir = temp.path().join("run");
    let mut infra = MockInfra::new(run_dir.clone());

    for bad_task in &["", ".", "..", "../escape", "sub/dir", "a\\b", "/root"] {
        let bad_req = RunRequest {
            world: world_dir.clone(),
            task: bad_task.to_string(),
            agent_mode: AgentMode::H,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: None,
            entrypoint: None,
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };
        let res = execute_run_flow(&mut infra, &clock, &bad_req, &run_dir, None);
        assert!(
            matches!(res, Err(BackendError::Data(_))),
            "task '{bad_task}' must be rejected with BackendError::Data"
        );
    }

    // execute_run_flow rejects run_dir inside req.world
    let inside_world_run = world_dir.join("runs").join("task1");
    let valid_req = RunRequest {
        world: world_dir.clone(),
        task: "valid-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };
    let res = execute_run_flow(&mut infra, &clock, &valid_req, &inside_world_run, None);
    assert!(
        matches!(res, Err(BackendError::Data(_))),
        "run_dir inside world must be rejected"
    );

    if let Some(v) = orig_run_dir {
        std::env::set_var("HERMETIC_RUN_DIR", v);
    } else {
        std::env::remove_var("HERMETIC_RUN_DIR");
    }
}

#[test]
fn test_run_flow_resolved_without_verdict_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());
    infra.skip_write_verdict = true;

    let req = RunRequest {
        world: world_dir,
        task: "no-verdict-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let res = execute_run_flow(&mut infra, &clock, &req, &run_dir, None);
    assert!(
        matches!(res, Err(BackendError::ProblemFound(ref msg)) if msg.contains("missing verdict.json")),
        "resolved run without verdict.json must fail closed: {res:?}"
    );
}

#[test]
fn test_run_flow_verdict_status_mismatch_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());
    infra.mismatched_verdict_status = Some("failed".into());

    let req = RunRequest {
        world: world_dir,
        task: "mismatch-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let res = execute_run_flow(&mut infra, &clock, &req, &run_dir, None);
    assert!(
        matches!(res, Err(BackendError::ProblemFound(ref msg)) if msg.contains("match")),
        "mismatched verdict run_status must be rejected: {res:?}"
    );
}

#[test]
fn test_run_flow_sign_then_verify_roundtrip_cli_paths() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    // Stage world manifest and artifacts in world_dir
    write_canonical_run_dir(&world_dir);

    // Generate throwaway Ed25519 key pair
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let signer = Ed25519Signer::from_pkcs8(&pkcs8).unwrap();
    let pub_bytes = signer.public_key();

    let key_pk8_path = temp.path().join("test_key.pk8");
    fs::write(&key_pk8_path, &pkcs8).unwrap();
    fs::set_permissions(&key_pk8_path, fs::Permissions::from_mode(0o600)).unwrap();

    let key_pub_path = temp.path().join("test_key.pub");
    fs::write(&key_pub_path, pub_bytes).unwrap();
    fs::set_permissions(&key_pub_path, fs::Permissions::from_mode(0o644)).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());

    let req = RunRequest {
        world: world_dir.clone(),
        task: "fixture-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_pk8_path))
        .expect("run flow should succeed");
    assert!(outcome.ok);

    let record_path = run_dir.join("record.json");
    assert!(record_path.exists());

    // 1. Verify via RealBackend and run_with_args
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_with_args(
        [
            OsString::from("verify"),
            OsString::from("--record"),
            record_path.as_os_str().to_os_string(),
            OsString::from("--key"),
            key_pub_path.as_os_str().to_os_string(),
        ],
        &RealBackend,
        &mut out,
        &mut err,
    );
    assert_eq!(
        code,
        ExitCode::SUCCESS,
        "stderr: {}",
        String::from_utf8_lossy(&err)
    );
    let out_str = String::from_utf8(out).unwrap();
    assert!(
        out_str.contains("verify: verified run"),
        "stdout: {out_str}"
    );

    // 2. Verification with wrong key fails
    let wrong_rng = SystemRandom::new();
    let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&wrong_rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let wrong_signer = Ed25519Signer::from_pkcs8(&wrong_pkcs8).unwrap();
    let wrong_pub_path = temp.path().join("wrong_key.pub");
    fs::write(&wrong_pub_path, wrong_signer.public_key()).unwrap();

    let mut out_wrong = Vec::new();
    let mut err_wrong = Vec::new();
    let code_wrong = run_with_args(
        [
            OsString::from("verify"),
            OsString::from("--record"),
            record_path.as_os_str().to_os_string(),
            OsString::from("--key"),
            wrong_pub_path.as_os_str().to_os_string(),
        ],
        &RealBackend,
        &mut out_wrong,
        &mut err_wrong,
    );
    assert_eq!(code_wrong, ExitCode::PROBLEM_FOUND);

    // 3. Verification with tampered record payload fails
    let mut env: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path).unwrap()).unwrap();
    let payload = env["payload"].as_str().unwrap().to_string();
    let flipped = if payload.starts_with('e') { "f" } else { "e" };
    env["payload"] = serde_json::Value::from(format!("{flipped}{}", &payload[1..]));
    let tampered_path = temp.path().join("tampered_record.json");
    fs::write(&tampered_path, env.to_string()).unwrap();

    let mut out_tampered = Vec::new();
    let mut err_tampered = Vec::new();
    let code_tampered = run_with_args(
        [
            OsString::from("verify"),
            OsString::from("--record"),
            tampered_path.as_os_str().to_os_string(),
            OsString::from("--key"),
            key_pub_path.as_os_str().to_os_string(),
        ],
        &RealBackend,
        &mut out_tampered,
        &mut err_tampered,
    );
    assert_eq!(code_tampered, ExitCode::PROBLEM_FOUND);
}

#[test]
fn run_with_real_infra_fails_closed_and_fabricates_nothing() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join("run");
    let orig_run_dir = std::env::var_os("HERMETIC_RUN_DIR");
    std::env::set_var("HERMETIC_RUN_DIR", &run_dir);
    let req = RunRequest {
        world: temp.path().join("world"),
        task: "fixture-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };
    let res = hermetic_cli::run_flow::run_with_real_infra(req);
    match orig_run_dir {
        Some(v) => std::env::set_var("HERMETIC_RUN_DIR", v),
        None => std::env::remove_var("HERMETIC_RUN_DIR"),
    }
    assert!(
        matches!(&res, Err(BackendError::Unavailable(m)) if *m == hermetic_cli::backend::RUN_NOT_WIRED),
        "run must fail closed until real VM orchestration is wired, got {res:?}"
    );
    assert!(
        !run_dir.exists(),
        "a refused run must not write any run artifacts"
    );
}

/// Regression: the run flow used to write default "no leak" sentinels and an
/// all-blocked probe log when the run produced none, then sign the result.
/// A missing attestation input must now fail closed with no signed record.
#[test]
fn test_run_flow_missing_attestation_input_is_never_defaulted() {
    for name in [
        "date_sentinel.json",
        "harness_summary.json",
        "probe_output.jsonl",
        "world_manifest.json",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let world_dir = temp.path().join("world");
        fs::create_dir_all(&world_dir).unwrap();
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();
        let clock = FakeClock::new(1000);
        let mut infra = MockInfra::new(run_dir.clone());
        infra.drop_artifact = Some(name);
        let (pkcs8, _signer, _verifier) = generate_test_key();
        let key_file = temp.path().join("signing.key");
        fs::write(&key_file, &pkcs8).unwrap();
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        let req = RunRequest {
            world: world_dir,
            task: "fixture-task".into(),
            agent_mode: AgentMode::H,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: None,
            entrypoint: None,
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };
        let res = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_file));
        assert!(res.is_err(), "missing {name} must fail closed, got {res:?}");
        assert!(!run_dir.join(name).exists(), "{name} must not be invented");
        assert!(
            !run_dir.join("record.json").exists(),
            "no signed record may exist when {name} is missing"
        );
    }
}

#[test]
fn test_run_flow_with_valid_bundle_manifest_verifies_successfully() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    fs::set_permissions(&world_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let dummy_file = world_dir.join("world_manifest.json");
    fs::write(&dummy_file, b"{\"task_id\":\"fixture-task\"}").unwrap();
    fs::set_permissions(&dummy_file, fs::Permissions::from_mode(0o644)).unwrap();

    // Seal the bundle
    let bundle_manifest = hermetic_bundle::seal(&world_dir).unwrap();
    assert!(!bundle_manifest.root.is_empty());

    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());

    let (pkcs8, _signer, _verifier) = generate_test_key();
    let key_file = temp.path().join("signing.key");
    fs::write(&key_file, &pkcs8).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();

    let req = RunRequest {
        world: world_dir,
        task: "fixture-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_file))
        .expect("valid bundle must verify and succeed");
    assert!(outcome.ok);
}

#[test]
fn test_run_flow_with_tampered_bundle_manifest_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    fs::set_permissions(&world_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let dummy_file = world_dir.join("world_manifest.json");
    fs::write(&dummy_file, b"{\"task_id\":\"fixture-task\"}").unwrap();
    fs::set_permissions(&dummy_file, fs::Permissions::from_mode(0o644)).unwrap();

    // Seal the bundle
    hermetic_bundle::seal(&world_dir).unwrap();

    // Tamper with bundle contents after sealing
    fs::write(&dummy_file, b"{\"task_id\":\"tampered-task\"}").unwrap();

    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = MockInfra::new(run_dir.clone());

    let (pkcs8, _signer, _verifier) = generate_test_key();
    let key_file = temp.path().join("signing.key");
    fs::write(&key_file, &pkcs8).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();

    let req = RunRequest {
        world: world_dir,
        task: "fixture-task".into(),
        agent_mode: AgentMode::H,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: None,
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let err = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_file))
        .expect_err("tampered bundle must fail closed");
    match err {
        hermetic_cli::dispatch::BackendError::ProblemFound(msg) => {
            assert!(
                msg.contains("bundle") || msg.contains("verification"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected BackendError::ProblemFound, got {other:?}"),
    }
}
