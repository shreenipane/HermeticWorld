#![forbid(unsafe_code)]

//! Fake-infra tests for Mode G run flow:
//! - Complete successful Mode G flow (AgentVM with /opt/agent entrypoint and model path NetVM -> gateway -> ExtractorVM -> GraderVM -> signed run record)
//! - Validation of Mode G attestation constraints (rejects harness_command_log_head, requires gateway fields)
//! - Failure and teardown tests for EVERY step, guaranteeing zero VMs leaked
//! - Timeout at every step with FakeClock
//! - Agent quota and volume cap limit exceedances
//! - Unclean shutdown handling
//! - Extractor and grader tamper evidence
//! - Panic propagation with guaranteed teardown
//! - No-follow filesystem traversal and 0600 secret file checks

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

#[path = "../../hermetic-attest/tests/common.rs"]
#[allow(unused_imports)]
mod attest_common;

use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde_json::json;

use hermetic_attest::dsse::Statement;
use hermetic_attest::offline_key::{Ed25519Signer, Ed25519Verifier};
use hermetic_attest::verify::{verify_run_attestation, ReplayGuard, RunBinding};
use hermetic_cli::args::{AgentMode, ClockMode, RunRequest};
use hermetic_cli::dispatch::BackendError;
use hermetic_cli::run_flow::{execute_run_flow, FakeClock};
use hermetic_run::infra::{
    AgentMode as RunAgentMode, AgentOutcome, ExtractorOutcome, GraderHandle, GraderOutcome,
    GraderPayload, GraderRun, Infra, InfraError, LimitKind, NamedDeadline, PreparedWorld,
    ShutdownKind, Step, VmHandle, VmId, VmKind, WorldSpec,
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

fn write_canonical_mode_g_run_dir(dir: &Path, date_leak: bool) {
    // 1. date_sentinel.json (gateway date sentinel)
    let gateway = json!({
        "date_leak_observed": date_leak,
        "scan_incomplete": false,
        "hits": if date_leak { json!({"2026-11-18": 1}) } else { json!({}) },
        "incomplete": {},
        "bytes_scanned": 1500
    });
    fs::write(dir.join("date_sentinel.json"), gateway.to_string()).unwrap();

    // 2. harness_summary.json (empty in Mode G)
    let harness = json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 0
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

    // 6. world_manifest.json with strict Mode G constraints:
    // agent_mode == "G", harness_command_log_head == null, gateway fields present
    let manifest = json!({
        "task_id": "mode-g-task",
        "task_class": "patch",
        "seal_level": "strict",
        "agent_mode": "G",
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
        "gateway_log_head": "sha256:e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "history_rewrite_count": 3,
        "gateway_adapter_version": "v1.2.3"
    });
    fs::write(dir.join("world_manifest.json"), manifest.to_string()).unwrap();

    // 7. submitted_work.patch
    fs::write(
        dir.join("submitted_work.patch"),
        b"--- a/calc.py\n+++ b/calc.py\n@@ -1 +1 @@\n-return a - b\n+return a + b\n",
    )
    .unwrap();
}

struct ModeGMockInfra {
    fail_step: Option<Step>,
    timeout_step: Option<Step>,
    panic_step: Option<Step>,
    agent_outcome: Option<AgentOutcome>,
    shutdown_kind: ShutdownKind,
    extractor_tamper: Option<String>,
    grader_tamper: Option<String>,
    grader_r0_pass: bool,
    grader_r1_pass: bool,
    grader_r2_pass: bool,
    live_vms: BTreeMap<VmId, VmKind>,
    destroyed_vms: Vec<VmId>,
    run_dir: PathBuf,
    date_leak: bool,
}

impl ModeGMockInfra {
    fn new(run_dir: PathBuf) -> Self {
        Self {
            fail_step: None,
            timeout_step: None,
            panic_step: None,
            agent_outcome: None,
            shutdown_kind: ShutdownKind::Clean,
            extractor_tamper: None,
            grader_tamper: None,
            grader_r0_pass: true,
            grader_r1_pass: true,
            grader_r2_pass: true,
            live_vms: BTreeMap::new(),
            destroyed_vms: Vec::new(),
            run_dir,
            date_leak: false,
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

impl Infra for ModeGMockInfra {
    fn prepare_world(
        &mut self,
        world: &WorldSpec,
        _deadline: &NamedDeadline,
    ) -> Result<PreparedWorld, InfraError> {
        self.check_step(Step::PrepareWorld)?;
        write_canonical_mode_g_run_dir(&self.run_dir, self.date_leak);
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
        agent_vm: &VmHandle,
        _deadline: &NamedDeadline,
    ) -> Result<(), InfraError> {
        self.check_step(Step::WaitAgentReady)?;
        if !self.live_vms.contains_key(&agent_vm.id) {
            return Err(InfraError::VmNotFound {
                vm_id: agent_vm.id.clone(),
            });
        }
        Ok(())
    }

    fn run_agent(
        &mut self,
        agent_vm: &VmHandle,
        mode: &RunAgentMode,
        _deadline: &NamedDeadline,
    ) -> Result<AgentOutcome, InfraError> {
        self.check_step(Step::RunAgent)?;
        if !self.live_vms.contains_key(&agent_vm.id) {
            return Err(InfraError::VmNotFound {
                vm_id: agent_vm.id.clone(),
            });
        }
        // Assert Mode G autonomous entrypoint is supplied
        match mode {
            RunAgentMode::GuestAutonomous { entrypoint } => {
                assert!(
                    entrypoint.contains("agent") || entrypoint.starts_with('/'),
                    "Mode G requires autonomous entrypoint"
                );
            }
            RunAgentMode::HarnessDriven { .. } => {
                panic!("Mode G must not be harness driven");
            }
        }
        if let Some(ref outcome) = self.agent_outcome {
            return Ok(outcome.clone());
        }
        Ok(AgentOutcome::Completed { exit_code: 0 })
    }

    fn shutdown_agent(
        &mut self,
        agent_vm: &VmHandle,
        _deadline: &NamedDeadline,
    ) -> Result<ShutdownKind, InfraError> {
        self.check_step(Step::ShutdownAgent)?;
        if !self.live_vms.contains_key(&agent_vm.id) {
            return Err(InfraError::VmNotFound {
                vm_id: agent_vm.id.clone(),
            });
        }
        Ok(self.shutdown_kind)
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
            tamper_evidence: self.extractor_tamper.clone(),
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
                tests: vec![TestResult::required("test_calc", self.grader_r0_pass)],
            }),
            GraderRun::R1 => GraderPayload::R1(R1Result {
                mutated_tests: vec![MutatedTestResult::new("test_calc", self.grader_r1_pass)],
            }),
            GraderRun::R2 => GraderPayload::R2(R2Result {
                paired_tests: vec![PairedTestResult::new("test_calc", self.grader_r2_pass)],
            }),
            GraderRun::R3 => GraderPayload::R3(R3Result {
                tests: vec![TestResult::required("test_calc", true)],
            }),
            GraderRun::Base => GraderPayload::Base(R0Result {
                tests: vec![TestResult::required("test_calc", self.grader_r0_pass)],
            }),
            GraderRun::Gold => GraderPayload::Gold(R0Result {
                tests: vec![TestResult::required("test_calc", self.grader_r0_pass)],
            }),
        };
        Ok(GraderOutcome {
            run: handle.run,
            payload,
            tamper_evidence: self.grader_tamper.clone(),
        })
    }
}

fn create_sample_key_file(dir: &Path, name: &str, pkcs8: &[u8]) -> PathBuf {
    let key_path = dir.join(name);
    fs::write(&key_path, pkcs8).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    key_path
}

#[test]
fn test_mode_g_happy_path_produces_valid_signed_record_verifying_attestation() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let (pkcs8, _signer, verifier) = generate_test_key();
    let key_path = create_sample_key_file(temp.path(), "test_key.pkcs8", &pkcs8);

    let upstream_key_path = temp.path().join("fake_upstream.key");
    fs::write(&upstream_key_path, b"test-key-content-12345").unwrap();
    fs::set_permissions(&upstream_key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());

    let req = RunRequest {
        world: world_dir,
        task: "mode-g-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Hidden,
        json: true,
        key: Some(key_path.clone()),
        out: Some(run_dir.join("attestation_envelope.json")),
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: Some("test-model".to_string()),
        upstream_url: Some("http://127.0.0.1:8080/v1".to_string()),
        upstream_key_file: Some(upstream_key_path),
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_path))
        .expect("run flow should succeed");

    assert!(outcome.ok, "run flow outcome must be ok: {:?}", outcome);
    assert_eq!(
        outcome.details.get("status").unwrap().as_str().unwrap(),
        "resolved"
    );

    // Verify all VMs were destroyed
    assert!(infra.live_vms.is_empty(), "all VMs must be destroyed");
    assert!(infra
        .destroyed_vms
        .contains(&VmId("agent-vm-0".to_string())));
    assert!(infra.destroyed_vms.contains(&VmId("net-vm-0".to_string())));

    // Verify record was written to both run_dir/record.json and out
    let record_file = run_dir.join("record.json");
    let out_file = run_dir.join("attestation_envelope.json");
    assert!(record_file.exists());
    assert!(out_file.exists());

    let envelope_json = fs::read_to_string(&out_file).unwrap();
    let mut guard = ReplayGuard::new();
    let binding = RunBinding::default();
    let (statement, digest) =
        verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard)
            .expect("DSSE envelope must verify");

    // Verify Mode G specific constraints in attestation
    assert_eq!(
        statement.predicate.agent_mode,
        hermetic_attest::AgentMode::G
    );
    assert!(
        statement.predicate.harness_command_log_head.is_none(),
        "Mode G must not contain harness_command_log_head"
    );
    assert!(
        statement.predicate.gateway_log_head.is_some(),
        "Mode G requires gateway_log_head"
    );
    assert!(
        statement.predicate.history_rewrite_count.is_some(),
        "Mode G requires history_rewrite_count"
    );
    assert_eq!(
        statement.predicate.history_rewrite_count.unwrap(),
        3,
        "history_rewrite_count must match"
    );
    assert_eq!(
        statement.predicate.gateway_adapter_version.as_deref(),
        Some("v1.2.3"),
        "gateway_adapter_version must match"
    );
    assert_eq!(statement.predicate.task_id, "mode-g-task");
    assert_eq!(
        statement.predicate.run_status,
        hermetic_attest::RunStatus::Resolved
    );

    println!("Mode G run verified: digest={digest}");
}

#[test]
fn test_mode_g_attestation_rejects_harness_command_log_head() {
    let mut record = attest_common::sample_run_record();
    record.agent_mode = hermetic_attest::AgentMode::G;
    // Set gateway fields
    record.gateway_log_head = Some(
        hermetic_attest::Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
    );
    record.history_rewrite_count = Some(0);
    record.gateway_adapter_version = Some("v1".to_string());

    // Illegally inject harness_command_log_head into Mode G record
    record.harness_command_log_head = Some(
        hermetic_attest::Digest::parse(
            "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
    );

    let res = Statement::new_run_statement(record);
    assert!(
        res.is_err(),
        "attestation must reject harness_command_log_head in Mode G"
    );
}

#[test]
fn test_mode_g_attestation_rejects_missing_gateway_fields() {
    // 1. Missing gateway_log_head
    let mut record1 = attest_common::sample_run_record();
    record1.agent_mode = hermetic_attest::AgentMode::G;
    record1.harness_command_log_head = None;
    record1.gateway_log_head = None;
    record1.history_rewrite_count = Some(0);
    record1.gateway_adapter_version = Some("v1".to_string());

    let res1 = Statement::new_run_statement(record1);
    assert!(res1.is_err(), "must reject missing gateway_log_head");

    // 2. Missing history_rewrite_count
    let mut record2 = attest_common::sample_run_record();
    record2.agent_mode = hermetic_attest::AgentMode::G;
    record2.harness_command_log_head = None;
    record2.gateway_log_head = Some(
        hermetic_attest::Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
    );
    record2.history_rewrite_count = None;
    record2.gateway_adapter_version = Some("v1".to_string());

    let res2 = Statement::new_run_statement(record2);
    assert!(res2.is_err(), "must reject missing history_rewrite_count");

    // 3. Missing gateway_adapter_version
    let mut record3 = attest_common::sample_run_record();
    record3.agent_mode = hermetic_attest::AgentMode::G;
    record3.harness_command_log_head = None;
    record3.gateway_log_head = Some(
        hermetic_attest::Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
    );
    record3.history_rewrite_count = Some(0);
    record3.gateway_adapter_version = None;

    let res3 = Statement::new_run_statement(record3);
    assert!(res3.is_err(), "must reject missing gateway_adapter_version");
}

#[test]
fn test_mode_g_every_step_failure_and_clean_teardown() {
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
        let mut infra = ModeGMockInfra::new(run_dir.clone());
        infra.fail_step = Some(step);

        let req = RunRequest {
            world: world_dir,
            task: "step-fail-task".into(),
            agent_mode: AgentMode::G,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: Some(run_dir.clone()),
            entrypoint: Some("/opt/agent/run".to_string()),
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
        assert!(
            status == "infra_error" || status == "tampered",
            "expected terminal error status, got {status} for step {:?}",
            step
        );

        // Terminal verdict must exist in run_dir
        assert!(run_dir.join("verdict.json").exists());

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
fn test_mode_g_step_timeout_at_each_step() {
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
        let mut infra = ModeGMockInfra::new(run_dir.clone());
        infra.timeout_step = Some(step);

        let req = RunRequest {
            world: world_dir,
            task: "timeout-task".into(),
            agent_mode: AgentMode::G,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: Some(run_dir.clone()),
            entrypoint: Some("/opt/agent/run".to_string()),
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

        // Zero VMs leaked
        assert!(
            infra.live_vms.is_empty(),
            "VM leak detected on timeout at step {:?}",
            step
        );
    }
}

#[test]
fn test_mode_g_agent_limit_exceeded_quota_and_volume_cap() {
    for limit in [LimitKind::Quota, LimitKind::VolumeCap] {
        let temp = tempfile::tempdir().unwrap();
        let world_dir = temp.path().join("world");
        fs::create_dir_all(&world_dir).unwrap();
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();

        let clock = FakeClock::new(1000);
        let mut infra = ModeGMockInfra::new(run_dir.clone());
        infra.agent_outcome = Some(AgentOutcome::LimitExceeded {
            kind: limit,
            detail: format!("{limit} exceeded in test"),
        });

        let req = RunRequest {
            world: world_dir,
            task: "limit-task".into(),
            agent_mode: AgentMode::G,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: Some(run_dir.clone()),
            entrypoint: Some("/opt/agent/run".to_string()),
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };

        let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, None)
            .expect("limit exceeded outcome should be returned");

        assert!(!outcome.ok);
        let status = outcome.details.get("status").unwrap().as_str().unwrap();
        assert_eq!(status, "limit_exceeded");
        assert!(
            infra.live_vms.is_empty(),
            "VMs must be cleaned up on limit exceeded"
        );
    }
}

#[test]
fn test_mode_g_unclean_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let (pkcs8, _signer, _verifier) = generate_test_key();
    let key_path = create_sample_key_file(temp.path(), "test_key.pkcs8", &pkcs8);

    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());
    infra.shutdown_kind = ShutdownKind::Unclean;

    let req = RunRequest {
        world: world_dir,
        task: "unclean-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: true,
        key: Some(key_path.clone()),
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_path)).unwrap();
    assert!(outcome.ok);
    assert_eq!(
        outcome.details.get("unclean_shutdown").unwrap().as_bool(),
        Some(true)
    );

    let verdict: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("verdict.json")).unwrap()).unwrap();
    assert_eq!(verdict["unclean_shutdown"], true);
}

#[test]
fn test_mode_g_extractor_tamper_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());
    infra.extractor_tamper = Some("hash mismatch in upper layer".to_string());

    let req = RunRequest {
        world: world_dir,
        task: "tamper-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, None).unwrap();
    assert!(!outcome.ok);
    assert_eq!(
        outcome.details.get("status").unwrap().as_str().unwrap(),
        "tampered"
    );
    assert!(infra.live_vms.is_empty());
}

#[test]
fn test_mode_g_grader_failures_and_tamper() {
    // 1. R0 failure -> status "failed"
    {
        let temp = tempfile::tempdir().unwrap();
        let world_dir = temp.path().join("world");
        fs::create_dir_all(&world_dir).unwrap();
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();

        let clock = FakeClock::new(1000);
        let mut infra = ModeGMockInfra::new(run_dir.clone());
        infra.grader_r0_pass = false;
        infra.grader_r2_pass = false;

        let req = RunRequest {
            world: world_dir,
            task: "r0-fail-task".into(),
            agent_mode: AgentMode::G,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: Some(run_dir.clone()),
            entrypoint: Some("/opt/agent/run".to_string()),
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };

        let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, None).unwrap();
        assert!(!outcome.ok);
        assert_eq!(
            outcome.details.get("status").unwrap().as_str().unwrap(),
            "unresolved"
        );
        assert!(infra.live_vms.is_empty());
    }

    // 2. Grader tamper -> status "tampered"
    {
        let temp = tempfile::tempdir().unwrap();
        let world_dir = temp.path().join("world");
        fs::create_dir_all(&world_dir).unwrap();
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();

        let clock = FakeClock::new(1000);
        let mut infra = ModeGMockInfra::new(run_dir.clone());
        infra.grader_tamper = Some("grader signature corrupted".to_string());

        let req = RunRequest {
            world: world_dir,
            task: "grader-tamper-task".into(),
            agent_mode: AgentMode::G,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: Some(run_dir.clone()),
            entrypoint: Some("/opt/agent/run".to_string()),
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        };

        let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, None).unwrap();
        assert!(!outcome.ok);
        assert_eq!(
            outcome.details.get("status").unwrap().as_str().unwrap(),
            "tampered"
        );
        assert!(infra.live_vms.is_empty());
    }
}

#[test]
fn test_mode_g_panic_guarantees_vm_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());
    infra.panic_step = Some(Step::RunAgent);

    let req = RunRequest {
        world: world_dir,
        task: "panic-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = execute_run_flow(&mut infra, &clock, &req, &run_dir, None);
    }));

    assert!(result.is_err(), "panic must be propagated");
    assert!(
        infra.live_vms.is_empty(),
        "VmGuard must destroy VMs even on panic unwinding"
    );
}

#[test]
fn test_mode_g_refuses_symlinks_and_missing_paths() {
    let temp = tempfile::tempdir().unwrap();

    // 1. Symlinked world directory
    let real_world = temp.path().join("real_world");
    fs::create_dir_all(&real_world).unwrap();
    let sym_world = temp.path().join("sym_world");
    symlink(&real_world, &sym_world).unwrap();

    let run_dir = temp.path().join("run");
    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());

    let req1 = RunRequest {
        world: sym_world,
        task: "sym-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };
    let res1 = execute_run_flow(&mut infra, &clock, &req1, &run_dir, None);
    assert!(matches!(res1, Err(BackendError::Data(_))));

    // 2. Missing world directory
    let missing_world = temp.path().join("missing_world");
    let req2 = RunRequest {
        world: missing_world,
        task: "missing-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };
    let res2 = execute_run_flow(&mut infra, &clock, &req2, &run_dir, None);
    assert!(matches!(res2, Err(BackendError::Io(_))));

    // 3. Symlinked signing key
    let real_key = temp.path().join("real_key");
    fs::write(&real_key, b"key-bytes").unwrap();
    fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).unwrap();
    let sym_key = temp.path().join("sym_key");
    symlink(&real_key, &sym_key).unwrap();

    let req3 = RunRequest {
        world: real_world.clone(),
        task: "key-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: Some(sym_key.clone()),
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };
    let res3 = execute_run_flow(&mut infra, &clock, &req3, &run_dir, Some(&sym_key));
    assert!(matches!(res3, Err(BackendError::Data(_))));

    // 4. Signing key with wrong permissions (0644 instead of 0600)
    let bad_perm_key = temp.path().join("bad_perm_key");
    fs::write(&bad_perm_key, b"key-bytes").unwrap();
    fs::set_permissions(&bad_perm_key, fs::Permissions::from_mode(0o644)).unwrap();

    let req4 = RunRequest {
        world: real_world.clone(),
        task: "perm-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: Some(bad_perm_key.clone()),
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };
    let res4 = execute_run_flow(&mut infra, &clock, &req4, &run_dir, Some(&bad_perm_key));
    assert!(matches!(res4, Err(BackendError::Data(_))));

    // 5. Upstream key file with wrong permissions
    let bad_perm_up_key = temp.path().join("bad_perm_up_key");
    fs::write(&bad_perm_up_key, b"key-bytes").unwrap();
    fs::set_permissions(&bad_perm_up_key, fs::Permissions::from_mode(0o666)).unwrap();

    let req5 = RunRequest {
        world: real_world,
        task: "upkey-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: Some(bad_perm_up_key),
    };
    let res5 = execute_run_flow(&mut infra, &clock, &req5, &run_dir, None);
    assert!(matches!(res5, Err(BackendError::Data(_))));
}

#[test]
fn test_mode_g_date_leak_downgrades_to_review() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let (pkcs8, _signer, verifier) = generate_test_key();
    let key_path = create_sample_key_file(temp.path(), "test_key.pkcs8", &pkcs8);

    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());
    infra.date_leak = true; // inject date leak in gateway sentinel

    let req = RunRequest {
        world: world_dir,
        task: "leak-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Hidden,
        json: true,
        key: Some(key_path.clone()),
        out: Some(run_dir.join("record.json")),
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_path)).unwrap();
    assert!(outcome.ok);
    assert_eq!(
        outcome.details.get("status").unwrap().as_str().unwrap(),
        "review"
    );

    let envelope_json = fs::read_to_string(run_dir.join("record.json")).unwrap();
    let (statement, _) = verify_run_attestation(
        &envelope_json,
        &verifier,
        &RunBinding::default(),
        &mut ReplayGuard::new(),
    )
    .unwrap();

    assert_eq!(
        statement.predicate.run_status,
        hermetic_attest::RunStatus::Review
    );
    assert_eq!(
        statement.predicate.clock,
        hermetic_attest::ClockLevel::Faked
    );
    assert!(statement.predicate.date_leak_observed);
}

#[test]
fn test_fsutil_verify_secret_file_bare_relative_filename() {
    let filename = format!("temp_test_secret_{}.key", std::process::id());
    let path = PathBuf::from(&filename);
    let _ = fs::remove_file(&path);
    fs::write(&path, b"test-secret-bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());

    let res = hermetic_cli::fsutil::verify_secret_file_no_symlinks(Path::new(&filename));
    assert!(
        res.is_ok(),
        "bare relative filename in current directory should verify: {res:?}"
    );
}

#[test]
fn test_fsutil_prepare_output_dir_refuses_ancestor_symlinks_and_parent_traversal() {
    let temp = tempfile::tempdir().unwrap();
    let real_dir = temp.path().join("real_target");
    fs::create_dir_all(&real_dir).unwrap();

    let link_ancestor = temp.path().join("link_ancestor");
    std::os::unix::fs::symlink(&real_dir, &link_ancestor).unwrap();

    // 1. Refuses creating output directory through an ancestor symlink
    let target_through_link = link_ancestor.join("new_sub");
    let res = hermetic_cli::fsutil::prepare_output_dir(&target_through_link);
    assert!(
        res.is_err(),
        "must refuse output directory with ancestor symlink"
    );
    match res.unwrap_err() {
        BackendError::Data(msg) => assert!(
            msg.contains("symlink"),
            "expected symlink rejection, got {msg}"
        ),
        other => panic!("expected BackendError::Data, got {other:?}"),
    }

    // 2. Refuses parent traversal (..)
    let parent_traversal = temp.path().join("a").join("..").join("b");
    let res = hermetic_cli::fsutil::prepare_output_dir(&parent_traversal);
    assert!(res.is_err(), "must refuse parent traversal");
    match res.unwrap_err() {
        BackendError::Data(msg) => assert!(
            msg.contains("parent traversal"),
            "expected parent traversal rejection, got {msg}"
        ),
        other => panic!("expected BackendError::Data, got {other:?}"),
    }

    // 3. Normal directory creation succeeds and sets 0700
    let normal = temp.path().join("nested").join("output");
    let res = hermetic_cli::fsutil::prepare_output_dir(&normal);
    assert!(
        res.is_ok(),
        "normal directory creation must succeed: {res:?}"
    );
    let meta = fs::metadata(&normal).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}

#[test]
fn test_run_flow_outcome_detail_carries_canonical_run_digest() {
    let temp = tempfile::tempdir().unwrap();
    let world_dir = temp.path().join("world");
    fs::create_dir_all(&world_dir).unwrap();
    let run_dir = temp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();

    let (pkcs8, _signer, verifier) = generate_test_key();
    let key_path = create_sample_key_file(temp.path(), "test_key.pkcs8", &pkcs8);

    let clock = FakeClock::new(1000);
    let mut infra = ModeGMockInfra::new(run_dir.clone());

    let req = RunRequest {
        world: world_dir,
        task: "mode-g-task".into(),
        agent_mode: AgentMode::G,
        clock: ClockMode::Hidden,
        json: true,
        key: Some(key_path.clone()),
        out: Some(run_dir.join("attestation_envelope.json")),
        run_dir: Some(run_dir.clone()),
        entrypoint: Some("/opt/agent/run".to_string()),
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    };

    let outcome = execute_run_flow(&mut infra, &clock, &req, &run_dir, Some(&key_path))
        .expect("run flow should succeed");

    let run_digest_val = outcome
        .details
        .get("run_digest")
        .expect("outcome must include run_digest");
    let run_digest_str = run_digest_val.as_str().expect("run_digest must be string");

    // Must be sha256:... digest, NOT base64 envelope payload (which starts with eyJ)
    assert!(
        run_digest_str.starts_with("sha256:"),
        "run_digest must be a canonical sha256 digest, got: {run_digest_str}"
    );

    // Verify against verify_run_attestation digest
    let envelope_json = fs::read_to_string(run_dir.join("attestation_envelope.json")).unwrap();
    let mut guard = ReplayGuard::new();
    let binding = RunBinding::default();
    let (_, verified_digest) =
        verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard)
            .expect("DSSE envelope must verify");

    assert_eq!(run_digest_str, verified_digest.to_string());
}
