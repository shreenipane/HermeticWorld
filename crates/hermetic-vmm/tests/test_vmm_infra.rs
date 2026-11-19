#![forbid(unsafe_code)]

//! Offline tests for `VmmInfra` (TR-VMM, TR-EXT, TR-GR).
//!
//! Tests each `Infra` step against fakes at the process and vsock boundary,
//! tests hostile inputs, and verifies that missing step outputs fail closed.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hermetic_extract::disk::ExtractDiskHeader;
use hermetic_extract::format::StreamEncoder;
use hermetic_grader_result::{
    encode_disk, RunId, RunResult, SupervisorExit, SupervisorSummary, TestStatus, DISK_BYTES,
};
use hermetic_run::infra::{
    AgentMode, AgentOutcome, ExtractorOutcome, GraderHandle, GraderRun, Infra, InfraError,
    NamedDeadline, ShutdownKind, Step, VmHandle, VmKind, WorldSpec,
};
use hermetic_vmm::runner::Runner;
use hermetic_vmm::vmm_infra::VmmInfra;
use hermetic_vmm::{ApiRequest, JailPlan, ValidatedSpec};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Helper that runs a mock vsock server on a Unix socket path.
fn start_mock_vsock_server(
    socket_path: PathBuf,
    t_clock: i64,
    shutdown_clean: bool,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();

    let handle = std::thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

                    // 1. Read handshake line "CONNECT 5000\n"
                    let mut handshake = Vec::new();
                    let mut b = [0u8];
                    while let Ok(()) = stream.read_exact(&mut b) {
                        handshake.push(b[0]);
                        if b[0] == b'\n' {
                            break;
                        }
                    }
                    if !handshake.starts_with(b"CONNECT") {
                        continue;
                    }

                    // 2. Reply "OK 5000\n"
                    let _ = stream.write_all(b"OK 5000\n");

                    // 3. Read request length (4 bytes LE)
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).is_err() {
                        continue;
                    }
                    let req_len = u32::from_le_bytes(len_buf) as usize;
                    let mut req_bytes = vec![0u8; req_len];
                    if stream.read_exact(&mut req_bytes).is_err() {
                        continue;
                    }

                    if let Ok(req_val) = serde_json::from_slice::<serde_json::Value>(&req_bytes) {
                        let kind = req_val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        let resp_val = match kind {
                            "status" => serde_json::json!({
                                "type": "status",
                                "locked": true,
                                "output_bytes": 0,
                                "guest_time_unix": t_clock,
                            }),
                            "exec" => serde_json::json!({
                                "type": "exec",
                                "code": 0,
                                "output": [111, 107, 10], // "ok\n"
                                "truncated": false,
                                "timed_out": false,
                            }),
                            "shutdown" => {
                                if shutdown_clean {
                                    serde_json::json!({ "type": "frozen" })
                                } else {
                                    serde_json::json!({ "type": "error" })
                                }
                            }
                            _ => serde_json::json!({ "type": "unknown" }),
                        };

                        let resp_bytes = serde_json::to_vec(&resp_val).unwrap();
                        let resp_len = (resp_bytes.len() as u32).to_le_bytes();
                        let _ = stream.write_all(&resp_len);
                        let _ = stream.write_all(&resp_bytes);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    (running, handle)
}

/// Fake runner operating at the process boundary.
struct FakeRunner {
    spec_role: hermetic_vmm::spec::Role,
    output_drive: Option<PathBuf>,
    result_disk: Option<PathBuf>,
    nonce: [u8; 32],
    started: bool,
}

impl FakeRunner {
    fn new(spec_role: hermetic_vmm::spec::Role) -> Self {
        Self {
            spec_role,
            output_drive: None,
            result_disk: None,
            nonce: [0u8; 32],
            started: false,
        }
    }
}

impl Runner for FakeRunner {
    fn spawn(
        &mut self,
        _spec: &ValidatedSpec,
        _plan: &JailPlan,
        jail: &hermetic_vmm::fs::PreparedJail,
        _end: Instant,
    ) -> hermetic_vmm::Result<()> {
        jail.check_identity()?;
        Ok(())
    }

    fn request(
        &mut self,
        _socket: &str,
        request: &ApiRequest,
        _end: Instant,
    ) -> hermetic_vmm::Result<()> {
        if request.path == "/actions" {
            self.started = true;
        }
        Ok(())
    }

    fn exited(&mut self, _end: Instant) -> hermetic_vmm::Result<bool> {
        if !self.started {
            return Ok(false);
        }

        // If this is an extractor VM, simulate the extractor writing its output drive
        if self.spec_role == hermetic_vmm::spec::Role::Extractor {
            if let Some(ref out_path) = self.output_drive {
                // Encode a minimal valid HEXT stream
                let mut stream_bytes = Vec::new();
                StreamEncoder::write_stream_header(&mut stream_bytes).unwrap();
                let file_data = b"patch content\n";
                StreamEncoder::write_file(
                    &mut stream_bytes,
                    "submitted_work.patch",
                    0o644,
                    file_data,
                )
                .unwrap();
                StreamEncoder::write_end(&mut stream_bytes, 1, file_data.len() as u64).unwrap();

                let mut hasher = Sha256::new();
                hasher.update(&stream_bytes);
                let sha256: [u8; 32] = hasher.finalize().into();

                let header =
                    ExtractDiskHeader::new_success(self.nonce, stream_bytes.len() as u64, sha256);
                let header_bytes = header.encode();
                let mut disk_data = vec![0u8; 16 * 1024 * 1024];
                disk_data[..header_bytes.len()].copy_from_slice(&header_bytes);
                disk_data[header_bytes.len()..header_bytes.len() + stream_bytes.len()]
                    .copy_from_slice(&stream_bytes);
                let _ = fs::write(out_path, &disk_data);
                let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(0o600));
            }
        }

        // If this is a grader VM, simulate the supervisor writing HGRD format
        if self.spec_role == hermetic_vmm::spec::Role::Grader {
            if let Some(ref res_path) = self.result_disk {
                let mut tests = BTreeMap::new();
                tests.insert("test_1".to_string(), TestStatus::Passed);
                let run_id = RunId::R0;
                let sample_result = RunResult {
                    run: run_id,
                    variant_set: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                    tests,
                    supervisor: SupervisorSummary {
                        exit: SupervisorExit::Clean,
                        tests_started: 1,
                        tests_finished: 1,
                    },
                };
                if let Ok((encoded, _)) = encode_disk(&sample_result) {
                    let _ = fs::write(res_path, &encoded);
                    let _ = fs::set_permissions(res_path, fs::Permissions::from_mode(0o600));
                }
            }
        }

        Ok(true)
    }

    fn kill(&mut self, _end: Instant) -> hermetic_vmm::Result<()> {
        Ok(())
    }
}

fn create_test_world(temp: &Path, t_clock_str: &str) -> (PathBuf, PathBuf) {
    let sealed_world = temp.join("sealed-world");
    fs::create_dir_all(&sealed_world).unwrap();

    let rfc3339_clock = if let Ok(epoch) = t_clock_str.parse::<i64>() {
        time::OffsetDateTime::from_unix_timestamp(epoch)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    } else {
        t_clock_str.to_string()
    };

    let manifest = serde_json::json!({
        "spec_version": "hermetic-world/v1",
        "task_id": "test-task",
        "task_class": "dated",
        "seal_level": "repo_only",
        "cutoffs": {
            "t_world": "2020-01-01T00:00:00Z",
            "t_clock": rfc3339_clock,
            "base_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "pkg_cutoff": "2020-01-01T00:00:00Z"
        },
        "repo_tree_digest": "sha1:abcdef0123456789abcdef0123456789abcdef01",
        "rootfs_digest": "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "packages": {
            "closure_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "baseline_month": "2020-01",
            "baseline_root": "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        },
        "substrate": [],
        "substrate_at_t": "full",
        "exemptions": [],
        "dns_table": ["alpha.example.com"],
        "world_ca_cert_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000007",
        "trust_store_paths": ["/etc/ssl/certs/ca-certificates.crt"],
        "test_services": [],
        "run_spec": {
            "env": { "PATH": "/usr/bin:/bin" },
            "workdir": "/workspace",
            "user": "root",
            "entrypoint": ["/bin/sh"],
            "resources": {
                "vcpus": 2,
                "memory_mib": 2048,
                "disk_mib": 32768,
                "wall_time_s": 3600
            }
        },
        "sealcheck_report_digest": "sha256:9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "dispositions": []
    });
    fs::write(
        sealed_world.join("world_manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let run_dir = temp.join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    for name in ["firecracker", "kernel", "rootfs"] {
        let p = temp.join(name);
        fs::write(&p, format!("dummy {name}").as_bytes()).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }

    (sealed_world, run_dir)
}

#[test]
fn test_prepare_world_happy_path() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "2020-01-01T00:00:00Z");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    );

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("prepare", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();

    assert_eq!(prepared.world_id, "test-task");
    assert!(run_dir.join("agent_overlay.img").exists());
}

#[test]
fn test_prepare_world_refuses_symlinked_sealed_world() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "2020-01-01T00:00:00Z");

    let sym_world = temp.path().join("sym-world");
    std::os::unix::fs::symlink(&sealed_world, &sym_world).unwrap();

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir,
        None,
    );

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sym_world.display().to_string(),
    };
    let dl = NamedDeadline::new("prepare", 5000);
    let err = infra.prepare_world(&spec, &dl).unwrap_err();
    assert!(matches!(err, InfraError::BackendFailure { .. }));
}

#[test]
fn test_start_netvm_and_agentvm_lifecycle() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "2020-01-01T00:00:00Z");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(|spec| Ok(Box::new(FakeRunner::new(spec.role))));

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();

    let net_handle = infra.start_netvm(&prepared, &dl).unwrap();
    assert_eq!(net_handle.kind, VmKind::Net);

    let agent_handle = infra.start_agentvm(&prepared, &net_handle, &dl).unwrap();
    assert_eq!(agent_handle.kind, VmKind::Agent);

    // boot_record.json must be recorded
    assert!(run_dir.join("boot_record.json").exists());

    // Destroy VMs
    infra.destroy_vm(&agent_handle, &dl).unwrap();
    infra.destroy_vm(&net_handle, &dl).unwrap();
}

#[test]
fn test_agent_vsock_readiness_and_exec_over_socket() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let vsock_path = run_dir.join("vsock.socket");
    let (server_running, server_handle) =
        start_mock_vsock_server(vsock_path.clone(), 1700000000, true);

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_clock(1700000000)
    .with_runner_factory(|spec| Ok(Box::new(FakeRunner::new(spec.role))));

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let net = infra.start_netvm(&prepared, &dl).unwrap();
    let agent = infra.start_agentvm(&prepared, &net, &dl).unwrap();

    // 1. Wait agent ready
    infra.wait_agent_ready(&agent, &dl).unwrap();

    // 2. Run agent Mode H
    let mode_h = AgentMode::HarnessDriven {
        commands: vec!["echo hello".into()],
    };
    let outcome = infra.run_agent(&agent, &mode_h, &dl).unwrap();
    assert_eq!(outcome, AgentOutcome::Completed { exit_code: 0 });

    // 3. Run agent Mode G
    let mode_g = AgentMode::GuestAutonomous {
        entrypoint: "/opt/agent/run".into(),
    };
    let outcome_g = infra.run_agent(&agent, &mode_g, &dl).unwrap();
    assert_eq!(outcome_g, AgentOutcome::Completed { exit_code: 0 });

    // 4. Shutdown agent clean
    let shutdown = infra.shutdown_agent(&agent, &dl).unwrap();
    assert_eq!(shutdown, ShutdownKind::Clean);

    server_running.store(false, Ordering::SeqCst);
    let _ = server_handle.join();
}

#[test]
fn test_vsock_shutdown_unclean_reports_unclean() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let vsock_path = run_dir.join("vsock.socket");
    let (server_running, server_handle) =
        start_mock_vsock_server(vsock_path.clone(), 1700000000, false);

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_clock(1700000000)
    .with_runner_factory(|spec| Ok(Box::new(FakeRunner::new(spec.role))));

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let net = infra.start_netvm(&prepared, &dl).unwrap();
    let agent = infra.start_agentvm(&prepared, &net, &dl).unwrap();

    let shutdown = infra.shutdown_agent(&agent, &dl).unwrap();
    assert_eq!(shutdown, ShutdownKind::Unclean);

    server_running.store(false, Ordering::SeqCst);
    let _ = server_handle.join();
}

#[test]
fn test_run_extractor_with_output_parsing() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let out_drive = run_dir.join("extractor_output.img");
    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(move |spec| {
        let nonce = if let Some(arg) = spec
            .boot_args
            .split_whitespace()
            .find(|a| a.starts_with("hermetic.nonce="))
        {
            let hex_str = arg.strip_prefix("hermetic.nonce=").unwrap();
            let mut n = [0u8; 32];
            for i in 0..32 {
                if let Ok(b) = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                    n[i] = b;
                }
            }
            n
        } else {
            [0u8; 32]
        };
        Ok(Box::new(FakeRunner {
            spec_role: spec.role,
            output_drive: Some(out_drive.clone()),
            result_disk: None,
            nonce,
            started: false,
        }))
    });

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();

    // Must have agent overlay in place
    let overlay = run_dir.join("agent_overlay.img");
    assert!(overlay.exists());

    let outcome = infra.run_extractor(&prepared, &dl).unwrap();
    assert!(outcome.patch_digest.starts_with("sha256:"));
    assert!(run_dir.join("submitted_work.patch").exists());
}

#[test]
fn test_run_extractor_missing_overlay_fails_closed() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    );

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();

    // Remove agent overlay to simulate missing step output
    let _ = fs::remove_file(run_dir.join("agent_overlay.img"));

    let err = infra.run_extractor(&prepared, &dl).unwrap_err();
    assert!(matches!(
        err,
        InfraError::BackendFailure {
            step: Step::RunExtractor,
            ..
        }
    ));
}

#[test]
fn test_grader_runs_r0_r1_r2_and_verdict_emission() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let run_dir_clone = run_dir.clone();
    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(move |spec| {
        let suffix = spec
            .id
            .strip_prefix("grader-vm-")
            .unwrap_or("r0")
            .to_ascii_uppercase();
        let res_path = run_dir_clone.join(format!("grader_result_{suffix}.img"));
        Ok(Box::new(FakeRunner {
            spec_role: spec.role,
            output_drive: None,
            result_disk: Some(res_path),
            nonce: [0u8; 32],
            started: false,
        }))
    });

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let extracted = ExtractorOutcome {
        patch_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        tamper_evidence: None,
    };

    // Run R0
    let h0 = infra
        .start_grader(GraderRun::R0, &prepared, &extracted, &dl)
        .unwrap();
    let o0 = infra.finish_grader(h0, &dl).unwrap();
    assert_eq!(o0.run, GraderRun::R0);

    // Initial result disk must have been formatted with HGRL
    assert!(run_dir.join("grader_result_R0.img").exists());
}

#[test]
fn test_finish_grader_missing_result_disk_fails_closed() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(|spec| Ok(Box::new(FakeRunner::new(spec.role))));

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let extracted = ExtractorOutcome {
        patch_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        tamper_evidence: None,
    };

    let h0 = infra
        .start_grader(GraderRun::R0, &prepared, &extracted, &dl)
        .unwrap();

    // Delete result disk to simulate missing grader result disk
    let _ = fs::remove_file(run_dir.join("grader_result_R0.img"));

    let err = infra.finish_grader(h0, &dl).unwrap_err();
    assert!(matches!(
        err,
        InfraError::BackendFailure {
            step: Step::RunGrader(GraderRun::R0),
            ..
        }
    ));
}

#[test]
fn test_finish_grader_corrupted_disk_fails_closed() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(|spec| Ok(Box::new(FakeRunner::new(spec.role))));

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let extracted = ExtractorOutcome {
        patch_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        tamper_evidence: None,
    };

    let h0 = infra
        .start_grader(GraderRun::R0, &prepared, &extracted, &dl)
        .unwrap();

    // Overwrite result disk with corrupted bytes (bad magic)
    let bad_bytes = vec![0xffu8; DISK_BYTES];
    fs::write(run_dir.join("grader_result_R0.img"), bad_bytes).unwrap();
    fs::set_permissions(
        run_dir.join("grader_result_R0.img"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let err = infra.finish_grader(h0, &dl).unwrap_err();
    assert!(matches!(
        err,
        InfraError::BackendFailure {
            step: Step::RunGrader(GraderRun::R0),
            ..
        }
    ));
}

#[test]
fn test_finish_grader_mismatched_payload_fails_closed() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(|spec| Ok(Box::new(FakeRunner::new(spec.role))));

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let extracted = ExtractorOutcome {
        patch_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        tamper_evidence: None,
    };

    let h0 = infra
        .start_grader(GraderRun::R0, &prepared, &extracted, &dl)
        .unwrap();

    // Write R1 payload into R0 result disk
    let r1_result = RunResult {
        run: RunId::R1,
        variant_set: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        tests: BTreeMap::new(),
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 0,
            tests_finished: 0,
        },
    };
    let (encoded, _) = encode_disk(&r1_result).unwrap();
    fs::write(run_dir.join("grader_result_R0.img"), &encoded).unwrap();
    fs::set_permissions(
        run_dir.join("grader_result_R0.img"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let err = infra.finish_grader(h0, &dl).unwrap_err();
    assert!(matches!(
        err,
        InfraError::GraderPayloadMismatch {
            expected: GraderRun::R0,
            actual: GraderRun::R1,
        }
    ));
}

#[test]
fn test_nonexistent_vm_fails_closed() {
    let temp = TempDir::new().unwrap();
    let (_sealed_world, run_dir) = create_test_world(temp.path(), "1700000000");

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir,
        None,
    );

    let dl = NamedDeadline::new("step", 5000);
    let fake_handle = VmHandle::new("ghost-vm", VmKind::Agent);

    let err = infra.wait_agent_ready(&fake_handle, &dl).unwrap_err();
    assert!(matches!(err, InfraError::VmNotFound { .. }));

    let mode = AgentMode::HarnessDriven { commands: vec![] };
    let err = infra.run_agent(&fake_handle, &mode, &dl).unwrap_err();
    assert!(matches!(err, InfraError::VmNotFound { .. }));

    let err = infra.shutdown_agent(&fake_handle, &dl).unwrap_err();
    assert!(matches!(err, InfraError::VmNotFound { .. }));

    let grader_handle = GraderHandle {
        run: GraderRun::R0,
        vm: VmHandle::new("ghost-grader", VmKind::Grader),
    };
    let err = infra.finish_grader(grader_handle, &dl).unwrap_err();
    assert!(matches!(err, InfraError::VmNotFound { .. }));
}

#[test]
fn test_agentvm_spec_matches_manifest_resource_configuration() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "2020-01-01T00:00:00Z");

    // Rewrite world_manifest.json with 4 vCPUs and 8192 MiB memory
    let manifest_path = sealed_world.join("world_manifest.json");
    let mut manifest_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest_val["run_spec"]["resources"]["vcpus"] = serde_json::json!(4);
    manifest_val["run_spec"]["resources"]["memory_mib"] = serde_json::json!(8192);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest_val).unwrap(),
    )
    .unwrap();

    let captured_resources = Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured_resources.clone();

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir.clone(),
        None,
    )
    .with_runner_factory(move |spec| {
        if spec.role == hermetic_vmm::spec::Role::Agent {
            *captured_clone.lock().unwrap() = Some((spec.vcpus, spec.memory_mib));
        }
        Ok(Box::new(FakeRunner::new(spec.role)))
    });

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let prepared = infra.prepare_world(&spec, &dl).unwrap();
    let net = infra.start_netvm(&prepared, &dl).unwrap();
    let _agent = infra.start_agentvm(&prepared, &net, &dl).unwrap();

    // VmSpec resources received by runner must match manifest (4 vCPUs, 8192 MiB)
    assert_eq!(*captured_resources.lock().unwrap(), Some((4u8, 8192u32)));

    // vm-config.json descriptor must also record 4 vCPUs and 8192 MiB
    let vm_cfg_bytes = fs::read(run_dir.join("vm-config.json")).unwrap();
    let vm_cfg: serde_json::Value = serde_json::from_slice(&vm_cfg_bytes).unwrap();
    assert_eq!(vm_cfg["vcpus"], 4);
    assert_eq!(vm_cfg["mem_size_mib"], 8192);
}

#[test]
fn test_prepare_world_bounds_manifest_read() {
    let temp = TempDir::new().unwrap();
    let (sealed_world, run_dir) = create_test_world(temp.path(), "2020-01-01T00:00:00Z");

    let manifest_path = sealed_world.join("world_manifest.json");
    let file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&manifest_path)
        .unwrap();
    file.set_len(hermetic_vmm::vmm_infra::MAX_MANIFEST_BYTES as u64 + 1024)
        .unwrap();

    let mut infra = VmmInfra::new(
        temp.path().join("firecracker"),
        temp.path().join("kernel"),
        temp.path().join("rootfs"),
        None,
        run_dir,
        None,
    );

    let spec = WorldSpec {
        world_id: "test-task".into(),
        cutoff_seal: sealed_world.display().to_string(),
    };
    let dl = NamedDeadline::new("step", 5000);
    let err = infra.prepare_world(&spec, &dl).unwrap_err();
    match err {
        InfraError::BackendFailure { step, detail } => {
            assert_eq!(step, Step::PrepareWorld);
            assert!(
                detail.contains("world_manifest.json exceeds size cap"),
                "got: {detail}"
            );
        }
        other => panic!("expected BackendError, got {other:?}"),
    }
}
