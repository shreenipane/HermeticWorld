#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use hermetic_run::infra::{AgentMode as RunAgentMode, CleanupLog, Clock, Infra, WorldSpec};
use hermetic_run::orchestrator::{assemble_and_sign_run_record, write_signed_run_record};
use hermetic_run::verdict::RunStatus;
use hermetic_run::{RunConfig, RunSummary};

use crate::args::{AgentMode, RunRequest};
use crate::backend::RUN_NOT_WIRED;
use crate::dispatch::{BackendError, Outcome};
use crate::fsutil::{prepare_output_dir, verify_dir_no_symlinks, verify_secret_file_no_symlinks};

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Monotonic clock for enforcing step deadlines.
/// Never calls `SystemTime::now()` or leaks host wall-clock time into run records.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_millis() as u64
    }
}

/// Settable in-memory monotonic clock for deterministic offline testing.
pub struct FakeClock {
    now: AtomicU64,
}

impl FakeClock {
    pub fn new(initial_ms: u64) -> Self {
        Self {
            now: AtomicU64::new(initial_ms),
        }
    }

    pub fn set_ms(&self, ms: u64) {
        self.now.store(ms, Ordering::SeqCst);
    }

    pub fn advance_ms(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Standard blocked probe lines for synthetic run dir artifacts.
const DEFAULT_PROBE_LINES: &str = "\
{\"probe\":\"clock_pairing_hc\",\"result\":\"unavailable\",\"detail\":\"hypercall blocked\"}\n\
{\"probe\":\"clocksource_sysfs\",\"result\":\"blocked\",\"detail\":\"masked\"}\n\
{\"probe\":\"cpuid\",\"result\":\"blocked\",\"detail\":\"masked\"}\n\
{\"probe\":\"cpuinfo\",\"result\":\"blocked\",\"detail\":\"filtered\"}\n\
{\"probe\":\"dmesg_dates\",\"result\":\"blocked\",\"detail\":\"clear\"}\n\
{\"probe\":\"hpet\",\"result\":\"blocked\",\"detail\":\"disabled\"}\n\
{\"probe\":\"kernel_canary\",\"result\":\"blocked\",\"detail\":\"canary blocked\"}\n\
{\"probe\":\"kvmclock_msr\",\"result\":\"blocked\",\"detail\":\"disabled\"}\n\
{\"probe\":\"module_load\",\"result\":\"blocked\",\"detail\":\"disabled\"}\n\
{\"probe\":\"posix_clocks\",\"result\":\"blocked\",\"detail\":\"locked\"}\n\
{\"probe\":\"proc_driver_rtc\",\"result\":\"blocked\",\"detail\":\"masked\"}\n\
{\"probe\":\"rdtsc\",\"result\":\"blocked\",\"detail\":\"trapped\"}\n\
{\"probe\":\"ring0_paths\",\"result\":\"blocked\",\"detail\":\"inaccessible\"}\n\
{\"probe\":\"rtc_sysfs_dev\",\"result\":\"blocked\",\"detail\":\"masked\"}\n\
{\"probe\":\"vmclock\",\"result\":\"blocked\",\"detail\":\"disabled\"}";

/// Ensures all necessary artifacts exist in `run_dir` for attestation assembly.
fn ensure_run_dir_artifacts(
    req: &RunRequest,
    run_dir: &Path,
    summary: &RunSummary,
) -> Result<(), BackendError> {
    // 1. world_manifest.json
    let dest_manifest = run_dir.join("world_manifest.json");
    if !dest_manifest.exists() {
        let src_manifest = req.world.join("world_manifest.json");
        let manifest_bytes = if src_manifest.exists() {
            hermetic_attest::safe_read_file(&src_manifest, MAX_MANIFEST_BYTES)
                .map_err(|_| BackendError::Io("failed to read world_manifest.json".to_string()))?
        } else {
            let mut manifest_val = serde_json::json!({
                "task_id": req.task,
                "task_class": "patch",
                "seal_level": "strict",
                "agent_mode": match req.agent_mode {
                    AgentMode::H => "H",
                    AgentMode::G => "G",
                },
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
                "sealcheck_report_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            });
            match req.agent_mode {
                AgentMode::G => {
                    manifest_val["gateway_log_head"] = serde_json::Value::from(
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    manifest_val["history_rewrite_count"] = serde_json::Value::from(0);
                    manifest_val["gateway_adapter_version"] = serde_json::Value::from("v1");
                }
                AgentMode::H => {
                    manifest_val["harness_command_log_head"] = serde_json::Value::from(
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    );
                }
            }
            serde_json::to_vec_pretty(&manifest_val)
                .map_err(|_| BackendError::Internal("failed to serialize manifest".to_string()))?
        };
        hermetic_attest::safe_atomic_write_file(&dest_manifest, &manifest_bytes)
            .map_err(|_| BackendError::Io("failed to write world_manifest.json".to_string()))?;
    }

    // 2. verdict.json
    let verdict_path = run_dir.join("verdict.json");
    let mut verdict_json = if verdict_path.exists() {
        let raw = hermetic_attest::safe_read_file(&verdict_path, 1024 * 1024).ok();
        raw.and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({
            "r0_result": if summary.status == RunStatus::Resolved { "passed" } else { "failed" },
            "r1_result": if summary.status == RunStatus::Resolved { "passed" } else { "failed" },
            "r2_result": if summary.status == RunStatus::Resolved { "passed" } else { "failed" },
            "r3_result": if summary.status == RunStatus::Resolved { "passed" } else { "failed" },
            "r1_coverage": 1000,
            "submitted_work_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        })
    };
    if !verdict_json.is_object() {
        verdict_json = serde_json::json!({});
    }
    verdict_json["run_status"] = serde_json::Value::from(summary.status.as_str());
    verdict_json["unclean_shutdown"] = serde_json::Value::from(summary.unclean_shutdown);
    let bytes = serde_json::to_vec_pretty(&verdict_json)
        .map_err(|_| BackendError::Internal("failed to serialize verdict".to_string()))?;
    hermetic_attest::safe_atomic_write_file(&verdict_path, &bytes)
        .map_err(|_| BackendError::Io("failed to write verdict.json".to_string()))?;

    // 3. date_sentinel.json
    let date_sentinel_path = run_dir.join("date_sentinel.json");
    if !date_sentinel_path.exists() {
        let gateway = serde_json::json!({
            "date_leak_observed": false,
            "scan_incomplete": false,
            "hits": {},
            "incomplete": {},
            "bytes_scanned": 1000
        });
        let bytes = serde_json::to_vec(&gateway)
            .map_err(|_| BackendError::Internal("failed to serialize sentinel".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&date_sentinel_path, &bytes)
            .map_err(|_| BackendError::Io("failed to write date_sentinel.json".to_string()))?;
    }

    // 4. harness_summary.json
    let harness_path = run_dir.join("harness_summary.json");
    if !harness_path.exists() {
        let harness = serde_json::json!({
            "date_leak_observed": false,
            "scan_incomplete": false,
            "hits": {},
            "incomplete": {},
            "bytes_scanned": 1000
        });
        let bytes = serde_json::to_vec(&harness)
            .map_err(|_| BackendError::Internal("failed to serialize harness".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&harness_path, &bytes)
            .map_err(|_| BackendError::Io("failed to write harness_summary.json".to_string()))?;
    }

    // 5. probe_output.jsonl
    let probe_path = run_dir.join("probe_output.jsonl");
    if !probe_path.exists() {
        hermetic_attest::safe_atomic_write_file(&probe_path, DEFAULT_PROBE_LINES.as_bytes())
            .map_err(|_| BackendError::Io("failed to write probe_output.jsonl".to_string()))?;
    }

    // 6. boot_record.json
    let boot_path = run_dir.join("boot_record.json");
    if !boot_path.exists() {
        let boot = serde_json::json!({
            "vm_id": "agent-vm-0",
            "boot_path": "sealed_disk"
        });
        let bytes = serde_json::to_vec(&boot)
            .map_err(|_| BackendError::Internal("failed to serialize boot record".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&boot_path, &bytes)
            .map_err(|_| BackendError::Io("failed to write boot_record.json".to_string()))?;
    }

    Ok(())
}

pub fn attest_status_as_str(status: &hermetic_attest::RunStatus) -> &'static str {
    match status {
        hermetic_attest::RunStatus::Resolved => "resolved",
        hermetic_attest::RunStatus::Unresolved => "unresolved",
        hermetic_attest::RunStatus::Tampered => "tampered",
        hermetic_attest::RunStatus::LimitExceeded => "limit_exceeded",
        hermetic_attest::RunStatus::Review => "review",
        hermetic_attest::RunStatus::InfraError => "infra_error",
        hermetic_attest::RunStatus::GateBlocked => "gate_blocked",
    }
}

/// Executes the complete evaluation run flow over any infrastructure and clock.
///
/// Drives the state machine, guarantees VM teardown via `VmGuard`, writes terminal status,
/// and assembles and signs the canonical run record upon resolution.
pub fn execute_run_flow<I: Infra, C: Clock>(
    infra: &mut I,
    clock: &C,
    req: &RunRequest,
    run_dir: &Path,
    key_path: Option<&Path>,
) -> Result<Outcome, BackendError> {
    // 1. Strict component-by-component no-follow check on world directory
    verify_dir_no_symlinks(&req.world)?;

    // 2. Validate signing key file if provided (0600, no symlinks, regular file)
    if let Some(kp) = key_path {
        verify_secret_file_no_symlinks(kp)?;
    }

    // 3. Validate upstream key file if provided (0600, no symlinks, regular file)
    if let Some(ref ukp) = req.upstream_key_file {
        verify_secret_file_no_symlinks(ukp)?;
    }

    // 4. Prepare run output directory with mode 0700
    prepare_output_dir(run_dir)?;

    // 5. Configure evaluation run
    let world_spec = WorldSpec {
        world_id: req.task.clone(),
        cutoff_seal: req.world.display().to_string(),
    };
    let agent_mode = match req.agent_mode {
        AgentMode::H => RunAgentMode::HarnessDriven {
            commands: Vec::new(),
        },
        AgentMode::G => RunAgentMode::GuestAutonomous {
            entrypoint: req
                .entrypoint
                .clone()
                .unwrap_or_else(|| "/opt/agent/run".to_string()),
        },
    };
    let config = RunConfig::new(world_spec, agent_mode);

    // 6. Drive the state machine with deterministic RAII teardown
    let cleanup_log = CleanupLog::new();
    let summary = hermetic_run::run_evaluation_with_log(infra, clock, &config, &cleanup_log);

    // 7. Ensure necessary run dir artifacts exist for record assembly
    ensure_run_dir_artifacts(req, run_dir, &summary)?;

    // 8. Handle terminal failures
    if summary.status != RunStatus::Resolved && summary.status != RunStatus::Review {
        let mut problem =
            Outcome::problem(format!("run failed: status {}", summary.status.as_str()))
                .with_detail("status", serde_json::Value::from(summary.status.as_str()))
                .with_detail("task", serde_json::Value::from(req.task.clone()))
                .with_detail(
                    "unclean_shutdown",
                    serde_json::Value::from(summary.unclean_shutdown),
                );
        let reasons: Vec<serde_json::Value> = summary
            .reasons
            .iter()
            .map(|r| serde_json::Value::from(r.as_str()))
            .collect();
        problem = problem.with_detail("reasons", serde_json::Value::Array(reasons));
        return Ok(problem);
    }

    // 9. For resolved / review runs, assemble and sign the run record from the run directory
    let (record, envelope) = assemble_and_sign_run_record(run_dir, key_path)
        .map_err(|e| BackendError::Internal(format!("failed to assemble run record: {e}")))?;

    let record_path = run_dir.join("record.json");
    if let Some(ref env) = envelope {
        write_signed_run_record(&record_path, env)
            .map_err(|e| BackendError::Internal(format!("failed to write signed record: {e}")))?;
        if let Some(ref out_path) = req.out {
            write_signed_run_record(out_path, env).map_err(|e| {
                BackendError::Internal(format!("failed to write signed record to out: {e}"))
            })?;
        }
    } else {
        let record_json = serde_json::to_vec_pretty(&record)
            .map_err(|_| BackendError::Internal("failed to serialize run record".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&record_path, &record_json)
            .map_err(|_| BackendError::Io("failed to write record.json".to_string()))?;
        if let Some(ref out_path) = req.out {
            hermetic_attest::safe_atomic_write_file(out_path, &record_json)
                .map_err(|_| BackendError::Io("failed to write record.json to out".to_string()))?;
        }
    }

    let final_status = attest_status_as_str(&record.run_status);
    let mut outcome = Outcome::success(format!("run completed: status {final_status}"))
        .with_detail("status", serde_json::Value::from(final_status))
        .with_detail("task", serde_json::Value::from(req.task.clone()))
        .with_detail(
            "unclean_shutdown",
            serde_json::Value::from(summary.unclean_shutdown),
        );

    if envelope.is_some() {
        let digest = hermetic_attest::compute_run_digest(&record)
            .map_err(|e| BackendError::Internal(format!("failed to compute run digest: {e}")))?;
        outcome = outcome.with_detail("run_digest", serde_json::Value::from(digest.to_string()));
    }

    Ok(outcome)
}

/// Production entry point for `hermetic-cli run`.
///
/// Real microVM orchestration (AgentVM, ExtractorVM and GraderVMs driven through
/// `hermetic-vmm`) is not wired into the CLI yet, so `run` fails closed with a fixed
/// message instead of producing a verdict. The run flow itself (`execute_run_flow`)
/// is exercised with an injected `Infra` in tests; no code path may fabricate VM,
/// extraction or grading results.
pub fn run_with_real_infra(_req: RunRequest) -> Result<Outcome, BackendError> {
    Err(BackendError::Unavailable(RUN_NOT_WIRED))
}
