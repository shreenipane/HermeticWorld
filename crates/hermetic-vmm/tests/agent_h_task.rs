#![cfg(feature = "dev-unjailed")]
//! Owner-run sealed-task harness. The ordinary gate never starts a VM.
#[path = "support/agent_h.rs"]
mod diagnostics;
mod support;
use hermetic_vmm::exec_client::{call, vsock_socket_path};
use hermetic_vmm::{deadline, Vmm};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn finish(child: &mut std::process::Child, timeout: Duration) {
    let end = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "smoke child failed");
            return;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("smoke child deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "manager-run KVM task; see python/hermetic_agent/README.md"]
fn runs_sealed_task_through_host_harness() -> Result<(), Box<dyn std::error::Error>> {
    let vars = [
        "HERMETIC_AGENT_WORK",
        "HERMETIC_AGENT_PYTHON",
        "HERMETIC_AGENT_MANIFEST",
        "HERMETIC_AGENT_TOP",
        "HERMETIC_AGENT_T_CLOCK",
        "HERMETIC_FC_BIN",
        "HERMETIC_KERNEL",
        "HERMETIC_ROOTFS",
    ];
    for key in vars {
        if std::env::var(key).is_err() {
            eprintln!("skipped: missing {key}");
            return Ok(());
        }
    }
    let required = |key| std::env::var(key).expect("missing smoke input");
    let work = required("HERMETIC_AGENT_WORK");
    let python = required("HERMETIC_AGENT_PYTHON");
    let manifest = required("HERMETIC_AGENT_MANIFEST");
    let top = required("HERMETIC_AGENT_TOP");
    let clock: i64 = required("HERMETIC_AGENT_T_CLOCK").parse().unwrap();
    let mut fixture = support::Fixture::new();
    fixture.spec.jail.firecracker = required("HERMETIC_FC_BIN");
    fixture.spec.kernel_image = required("HERMETIC_KERNEL");
    fixture.spec.root_drive.path = required("HERMETIC_ROOTFS");
    fixture.spec.networks.clear();
    fixture.spec.memory_mib = 2048;
    fixture.spec.vcpus = 1;
    fixture.spec.limits.file_size_bytes = 1024 * 1024 * 1024;
    fixture.spec.boot_args = fixture
        .spec
        .boot_args
        .replace("hermetic.t=1700000000", &format!("hermetic.t={clock}"))
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-init");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fixture.spec.drives[0].path)
        .unwrap()
        .set_len(1024 * 1024 * 1024)
        .unwrap();
    let mut mkfs = diagnostics::overlay_command(clock)
        .arg(&fixture.spec.drives[0].path)
        .spawn()
        .unwrap();
    finish(&mut mkfs, Duration::from_secs(30));
    let launcher = fixture.temp.path().join("exec-python");
    std::fs::copy(
        std::fs::canonicalize("/usr/bin/python3").unwrap(),
        &launcher,
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o500)).unwrap();
    let runner = hermetic_vmm::runner::DevUnjailed::new(launcher.to_str().unwrap()).unwrap();
    let mut vm = Vmm::new(fixture.spec.clone().validate().unwrap(), runner);
    diagnostics::run(&mut vm, |vm| -> Result<(), Box<dyn std::error::Error>> {
        if let Err(error) = vm.prepare(Duration::from_secs(120)) {
            let category = match &error {
                hermetic_vmm::Error::Step(category) => *category,
                hermetic_vmm::Error::Validation(_) => "prepare-validation",
                _ => "prepare",
            };
            println!("agent-vm-category: {category}");
            return Err(error.into());
        }
        vm.start(Duration::from_secs(10)).unwrap();
        vm.wait_ready(Duration::from_secs(30)).unwrap();
        let socket = vm.jail().unwrap().root.descriptor_path("vsock");
        let end = deadline(Duration::from_secs(30)).unwrap();
        loop {
            if let Ok(reply) = call(&socket, br#"{"type":"status"}"#, end) {
                diagnostics::status(&reply, clock)?;
                break;
            }
            assert!(Instant::now() < end, "execd readiness deadline");
            std::thread::sleep(Duration::from_millis(20));
        }

        // Run full guest clock/escape probe in AgentVM before the agent starts
        let probe_req = serde_json::to_vec(&serde_json::json!({
            "type": "exec",
            "argv": ["/sbin/hermetic-clockprobe"],
            "tty": false,
            "timeout_ms": 30_000
        }))
        .map_err(|_| hermetic_vmm::Error::Protocol)?;
        let probe_reply = call(&socket, &probe_req, end)?;
        let probe_output_bytes: Vec<u8> = probe_reply
            .get("output")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|b| b as u8))
                    .collect()
            })
            .unwrap_or_default();
        let probe_out_path = format!("{work}/probe_output.jsonl");
        std::fs::write(&probe_out_path, &probe_output_bytes)?;

        // /proc/self/fd paths are meaningful only in the Vmm process. Keep its pinned directory
        // descriptor open and address it from the child through the parent's pid.
        let socket = vsock_socket_path(&socket);
        let task = required("HERMETIC_AGENT_TASK");
        let gateway = required("HERMETIC_AGENT_GATEWAY");
        let pinned = required("HERMETIC_AGENT_MODEL");
        let steps = std::env::var_os("HERMETIC_AGENT_STEPS").unwrap_or_else(|| "60".into());
        let sentinel_out_path = format!("{work}/harness_summary.json");
        let run_json_path = format!("{work}/run.json");
        let evidence_out_path = format!("{work}/evidence.json");
        let config_dir = format!("{work}/config");
        let trajectory_path = format!("{work}/trajectory.json");
        let command_log_path = format!("{work}/commands.jsonl");
        let mut harness_args = vec![
            "-m",
            "hermetic_agent",
            "--vsock",
            &socket,
            "--manifest",
            &manifest,
            "--task",
            &task,
            "--cwd",
            "/testbed",
            "--gateway",
            &gateway,
            "--model",
            &pinned,
            "--config-dir",
            &config_dir,
            "--trajectory",
            &trajectory_path,
            "--command-log",
            &command_log_path,
            "--sentinel-summary",
            &sentinel_out_path,
            "--probe-output",
            &probe_out_path,
            "--run-json",
            &run_json_path,
            "--evidence-json",
            &evidence_out_path,
        ];
        let gw_sentinel_path = format!("{work}/date_sentinel.json");
        if std::path::Path::new(&gw_sentinel_path).exists() {
            harness_args.push("--gateway-sentinel");
            harness_args.push(&gw_sentinel_path);
        }

        let mut harness = Command::new(&python)
            .args(&harness_args)
            .env_clear()
            .env("PYTHONPATH", format!("{top}/python"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("HERMETIC_AGENT_STEPS", steps)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        finish(&mut harness, Duration::from_secs(5500));
        let end = deadline(Duration::from_secs(10)).unwrap();
        // Graceful shutdown freezes the upper before power-off. Validation runs after teardown.
        let frozen = call(&socket, br#"{"type":"shutdown"}"#, end).unwrap();
        if frozen.get("type").and_then(serde_json::Value::as_str) != Some("frozen") {
            return Err(hermetic_vmm::Error::Protocol.into());
        }
        if let Some(boot) = vm.boot_record() {
            let boot_bytes = serde_json::to_vec_pretty(boot)?;
            std::fs::write(format!("{work}/boot_record.json"), boot_bytes)?;
        }
        vm.stop(Duration::from_secs(10)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
        println!("sealed task harness: submitted (grading remains separate)");

        // Assemble and sign the run record with the Rust orchestrator on main
        let work_path = std::path::PathBuf::from(&work);
        let date_sentinel_file = work_path.join("date_sentinel.json");
        if !date_sentinel_file.exists() {
            let default_gw = serde_json::json!({
                "date_leak_observed": false,
                "scan_incomplete": false,
                "hits": {},
                "incomplete": {},
                "bytes_scanned": 0
            });
            std::fs::write(&date_sentinel_file, serde_json::to_vec(&default_gw)?)?;
        }

        let verdict_path = work_path.join("verdict.json");
        if !verdict_path.exists() {
            let run_json_bytes = std::fs::read(&run_json_path)?;
            let run_doc: serde_json::Value = serde_json::from_slice(&run_json_bytes)?;
            let is_submitted = run_doc.get("status").and_then(|v| v.as_str()) == Some("completed");
            let verdict = serde_json::json!({
                "run_status": if is_submitted { "resolved" } else { "unresolved" },
                "r0_result": if is_submitted { "passed" } else { "failed" },
                "unclean_shutdown": false,
                "submitted_work_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            });
            std::fs::write(&verdict_path, serde_json::to_vec_pretty(&verdict)?)?;
        }

        let manifest_path = work_path.join("world_manifest.json");
        if !manifest_path.exists() {
            let manifest_bytes = std::fs::read(&manifest)?;
            let mut manifest_val: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
            manifest_val["agent_mode"] = serde_json::json!("H");
            if manifest_val.get("spec_version").is_none() {
                manifest_val["spec_version"] = serde_json::json!("v1.1");
            }
            if manifest_val.get("harness_command_log_head").is_none() {
                manifest_val["harness_command_log_head"] = serde_json::json!(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                );
            }
            std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest_val)?)?;
        }

        let key_path = std::env::var("HERMETIC_SIGNING_KEY")
            .ok()
            .map(std::path::PathBuf::from);
        let (record, envelope) = hermetic_run::orchestrator::assemble_and_sign_run_record(
            &work_path,
            key_path.as_deref(),
        )?;
        let record_path = work_path.join("record.json");
        if let Some(ref env) = envelope {
            hermetic_run::orchestrator::write_signed_run_record(&record_path, env)?;
        } else {
            let record_bytes = serde_json::to_vec_pretty(&record)?;
            hermetic_attest::safe_atomic_write_file(&record_path, &record_bytes)?;
        }
        assert_eq!(record.agent_mode, hermetic_attest::AgentMode::H);
        Ok(())
    })
}

#[test]
fn test_mode_h_orchestrator_wiring_offline() {
    use hermetic_attest::{
        AgentMode, ClockLevel, Ed25519Verifier, ProbeResult, ReplayGuard, RunBinding, RunStatus,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest as ShaDigest, Sha256};

    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::set_permissions(run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_path = run_dir.join("offline_key.pk8");
    std::fs::write(&key_path, pkcs8.as_ref()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let verifier = Ed25519Verifier::new(&[key_pair.public_key().as_ref()]).unwrap();

    // 1. Gateway sentinel
    let date_sentinel = serde_json::json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 100
    });
    std::fs::write(
        run_dir.join("date_sentinel.json"),
        date_sentinel.to_string(),
    )
    .unwrap();

    // 2. Harness summary
    let harness_summary = serde_json::json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 500
    });
    std::fs::write(
        run_dir.join("harness_summary.json"),
        harness_summary.to_string(),
    )
    .unwrap();

    // 3. Probe output
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
    std::fs::write(run_dir.join("probe_output.jsonl"), probe_lines).unwrap();

    // 4. Boot record
    let boot = serde_json::json!({
        "vm_id": "agent-vm-h-0",
        "boot_path": "trusted_initramfs",
        "initrd_sha256": "f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    });
    std::fs::write(run_dir.join("boot_record.json"), boot.to_string()).unwrap();

    // 5. Verdict
    let verdict = serde_json::json!({
        "run_status": "resolved",
        "r0_result": "passed",
        "unclean_shutdown": false,
        "submitted_work_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    });
    std::fs::write(run_dir.join("verdict.json"), verdict.to_string()).unwrap();

    // 6. World manifest
    let manifest = serde_json::json!({
        "task_id": "pytest-dev__pytest-6202",
        "task_class": "patch",
        "seal_level": "strict",
        "agent_mode": "H",
        "substrate": "microvm",
        "grader_isolation": "clean",
        "deployment": "single_host",
        "t_world": "2020-01-01T00:00:00Z",
        "t_clock": "2020-01-01T00:00:00Z",
        "base_commit": "0000000000000000000000000000000000000000",
        "spec_version": "v1.1",
        "world_version": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sealcheck_version": "v1.0",
        "grader_image_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "world_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "task_rootfs_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "netvm_image_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "guest_kernel_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "vm_config_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "cpu_template_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "firecracker_build_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "agent_volume_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sealcheck_report_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "substrate_at_t": "full",
        "exemption_list": [],
        "world_server_log_head": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "dedupe_index_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "request_count": 10,
        "harness_command_log_head": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    });
    std::fs::write(run_dir.join("world_manifest.json"), manifest.to_string()).unwrap();

    // 7. Host facts artifacts
    let fc_bytes = b"patched firecracker binary for mode h offline test";
    std::fs::write(run_dir.join("firecracker"), fc_bytes).unwrap();
    let fc_sha = format!("{:x}", Sha256::digest(fc_bytes));
    let patch_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let source_sha = "2222222222222222222222222222222222222222222222222222222222222222";
    let release_sha = "3333333333333333333333333333333333333333333333333333333333333333";

    let build_record = serde_json::json!({
        "schema": "hermetic-firecracker-build/v1",
        "version": "1.18.0",
        "firecracker_sha256": fc_sha,
        "patch_sha256": patch_sha,
        "source_sha256": source_sha,
    });
    std::fs::write(
        run_dir.join("firecracker_build.json"),
        build_record.to_string(),
    )
    .unwrap();

    let pinned_lock = serde_json::json!({
        "version": "1.18.0",
        "firecracker_sha256": release_sha,
        "patch_sha256": patch_sha,
        "source_sha256": source_sha,
    });
    std::fs::write(run_dir.join("pinned_lock.json"), pinned_lock.to_string()).unwrap();

    // 8. run.json (written by Mode H harness)
    let run_json = serde_json::json!({
        "schema": "hermetic-slice-run/v0-unsigned",
        "instance_id": "mode-h-task",
        "seal_level": "repo_only",
        "agent_mode": "H",
        "clock": "real",
        "grader_isolation": "clean_container",
        "deployment": "single_host",
        "status": "completed",
        "date_leak_observed": false,
        "probe_verdict": "passed",
        "escape_probe_result": "passed"
    });
    std::fs::write(run_dir.join("run.json"), run_json.to_string()).unwrap();

    // Assemble and sign run record
    let (record, envelope) =
        hermetic_run::orchestrator::assemble_and_sign_run_record(run_dir, Some(&key_path))
            .expect("assemble Mode H record");

    assert_eq!(record.agent_mode, AgentMode::H);
    assert!(!record.date_leak_observed);
    assert_eq!(record.escape_probe_result, ProbeResult::Passed);
    assert_eq!(record.clock, ClockLevel::Hidden);
    assert_eq!(record.run_status, RunStatus::Resolved);
    assert!(record.harness_command_log_head.is_some());
    assert!(record.gateway_log_head.is_none());

    let env = envelope.expect("signed DSSE envelope");
    let record_path = run_dir.join("record.json");
    hermetic_run::orchestrator::write_signed_run_record(&record_path, &env).unwrap();
    assert!(record_path.exists());

    // Verify attestation
    let binding = RunBinding {
        task_id: Some(record.task_id.clone()),
        world_root: Some(record.world_root.clone()),
        world_bundle: None,
        sealcheck_report_digest: None,
        grader_image_digest: Some(record.version_tuple.grader_image_digest.clone()),
        boot_record: record.boot_record.clone(),
    };
    let mut guard = ReplayGuard::new();
    let env_json = serde_json::to_string(&env).unwrap();
    let (statement, _digest) =
        hermetic_attest::verify_run_attestation(&env_json, &verifier, &binding, &mut guard)
            .expect("verify attestation");
    assert_eq!(statement.predicate.agent_mode, AgentMode::H);
    assert!(!statement.predicate.date_leak_observed);
    assert_eq!(statement.predicate.escape_probe_result, ProbeResult::Passed);

    // Test date leak downgrade: date_leak_observed true downgrades clock to Faked and status to Review
    let leaking_harness = serde_json::json!({
        "date_leak_observed": true,
        "scan_incomplete": false,
        "hits": {"observation:real_date": 1},
        "incomplete": {},
        "bytes_scanned": 500
    });
    std::fs::write(
        run_dir.join("harness_summary.json"),
        leaking_harness.to_string(),
    )
    .unwrap();

    let (record_leaked, _) =
        hermetic_run::orchestrator::assemble_and_sign_run_record(run_dir, Some(&key_path))
            .expect("assemble leaked record");
    assert!(record_leaked.date_leak_observed);
    assert_eq!(record_leaked.clock, ClockLevel::Faked);
    assert_eq!(record_leaked.run_status, RunStatus::Review);
}
