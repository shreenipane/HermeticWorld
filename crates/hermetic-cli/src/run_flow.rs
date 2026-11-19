#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use hermetic_run::infra::{AgentMode as RunAgentMode, CleanupLog, Clock, Infra, WorldSpec};
use hermetic_run::orchestrator::{assemble_and_sign_run_record, write_signed_run_record};
use hermetic_run::verdict::RunStatus;
use hermetic_run::RunConfig;

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

fn extract_infra_error(summary: &hermetic_run::RunSummary) -> (String, String) {
    for reason in &summary.reasons {
        if let Some(rest) = reason.strip_prefix("infra_error at step '") {
            if let Some((step, detail)) = rest.split_once("': ") {
                let kind = classify_infra_detail(detail);
                return (step.to_string(), kind.to_string());
            }
        }
        if let Some(rest) = reason.strip_prefix("tampered at step '") {
            if let Some((step, _)) = rest.split_once("': ") {
                return (step.to_string(), "tamper_detected".to_string());
            }
        }
    }
    let failed_step = summary
        .steps
        .iter()
        .find(|s| {
            s.outcome == hermetic_run::StepOutcome::Failed
                || s.outcome == hermetic_run::StepOutcome::Tampered
        })
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    (failed_step, "backend_failure".to_string())
}

fn classify_infra_detail(detail: &str) -> &'static str {
    if detail.contains("exceeded deadline") {
        "deadline_exceeded"
    } else if detail.contains("tamper detected") {
        "tamper_detected"
    } else if detail.contains("does not exist") {
        "vm_not_found"
    } else if detail.contains("expected VM kind") {
        "invalid_vm_kind"
    } else if detail.contains("returned payload for") {
        "grader_payload_mismatch"
    } else if detail.contains("invalid state transition") {
        "transition_error"
    } else {
        "backend_failure"
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
    // 0. Validate task ID as a single path segment
    if req.task.is_empty()
        || req.task.len() > 128
        || req.task == "."
        || req.task == ".."
        || req.task.contains('/')
        || req.task.contains('\\')
        || !req
            .task
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(BackendError::Data(
            "invalid task id: must be a single non-empty path segment matching [A-Za-z0-9._-]{1,128}".to_string(),
        ));
    }

    // Refuse run directory inside the sealed world
    if run_dir.starts_with(&req.world) {
        return Err(BackendError::Data(
            "run directory cannot be placed inside the sealed world".to_string(),
        ));
    }

    // 1. Strict component-by-component no-follow check on world directory
    verify_dir_no_symlinks(&req.world)?;

    // If bundle.manifest.json is present, verify that the bundle matches its recorded root
    let bundle_manifest = req.world.join(hermetic_bundle::MANIFEST_FILENAME);
    if bundle_manifest.exists() {
        let report = hermetic_bundle::verify(&req.world, None)
            .map_err(|e| BackendError::ProblemFound(format!("bundle verification failed: {e}")))?;
        if report.verdict != hermetic_bundle::Verdict::Ok || !report.manifest_root_matches {
            return Err(BackendError::ProblemFound(
                "sealed world bundle root verification failed: bundle does not match".to_string(),
            ));
        }
    }

    // Signing key and upstream key files: 0600, no symlinks, regular files
    if let Some(kp) = key_path {
        verify_secret_file_no_symlinks(kp)?;
    }
    if let Some(ref ukp) = req.upstream_key_file {
        verify_secret_file_no_symlinks(ukp)?;
    }

    // 2. Prepare run output directory with mode 0700
    prepare_output_dir(run_dir)?;

    // 3. Configure evaluation run
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

    // 4. Drive the state machine with deterministic RAII teardown
    let cleanup_log = CleanupLog::new();
    let summary = hermetic_run::run_evaluation_with_log(infra, clock, &config, &cleanup_log);

    // Every attestation input must come from the run itself; nothing is defaulted here.

    // 6. Ensure terminal status is accurately written to verdict.json in run_dir
    let verdict_path = run_dir.join("verdict.json");
    if summary.status == RunStatus::Resolved || summary.status == RunStatus::Review {
        if !verdict_path.exists() {
            return Err(BackendError::ProblemFound(
                "missing verdict.json: cannot fabricate evaluation results".to_string(),
            ));
        }
        let bytes = hermetic_attest::safe_read_file(&verdict_path, hermetic_run::MAX_VERDICT_BYTES)
            .map_err(|_| BackendError::Io("failed to read verdict.json".to_string()))?;
        let mut val: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| BackendError::ProblemFound("invalid JSON in verdict.json".to_string()))?;
        let file_status = val
            .get("run_status")
            .or_else(|| val.get("status"))
            .and_then(|s| s.as_str());
        if file_status != Some(summary.status.as_str()) {
            return Err(BackendError::ProblemFound(format!(
                "verdict run_status ({:?}) does not match summary status ({})",
                file_status,
                summary.status.as_str()
            )));
        }
        // The host observed the shutdown itself; record it alongside the grader verdict.
        if let Some(obj) = val.as_object_mut() {
            obj.insert(
                "unclean_shutdown".to_string(),
                serde_json::Value::from(summary.unclean_shutdown),
            );
        }
        let bytes = serde_json::to_vec_pretty(&val)
            .map_err(|_| BackendError::Internal("failed to serialize verdict".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&verdict_path, &bytes)
            .map_err(|_| BackendError::Io("failed to write verdict.json".to_string()))?;
    } else {
        let mut verdict_map = if verdict_path.exists() {
            let bytes =
                hermetic_attest::safe_read_file(&verdict_path, hermetic_run::MAX_VERDICT_BYTES)
                    .unwrap_or_default();
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        if let Some(obj) = verdict_map.as_object_mut() {
            obj.insert(
                "run_status".to_string(),
                serde_json::Value::from(summary.status.as_str()),
            );
            obj.insert(
                "unclean_shutdown".to_string(),
                serde_json::Value::from(summary.unclean_shutdown),
            );
            if !obj.contains_key("r0_result") {
                obj.insert("r0_result".to_string(), serde_json::Value::from("failed"));
            }
        }
        let bytes = serde_json::to_vec_pretty(&verdict_map)
            .map_err(|_| BackendError::Internal("failed to serialize verdict".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&verdict_path, &bytes)
            .map_err(|_| BackendError::Io("failed to write verdict.json".to_string()))?;
    }

    if summary.status == RunStatus::InfraError {
        let (step_name, error_kind) = extract_infra_error(&summary);
        let infra_err_doc = serde_json::json!({
            "step": step_name,
            "error_kind": error_kind,
            "error": error_kind,
        });
        if let Ok(bytes) = serde_json::to_vec_pretty(&infra_err_doc) {
            let infra_err_path = run_dir.join("infra_error.json");
            let _ = hermetic_attest::safe_atomic_write_file(&infra_err_path, &bytes);
        }
        eprintln!("infra failure at step '{step_name}': {error_kind}");
    }

    // 7. Terminal failures: sign a record of the failure when every attestation
    // input is present; if any is missing, report the failure without a record.
    if summary.status != RunStatus::Resolved && summary.status != RunStatus::Review {
        let mut problem =
            Outcome::problem(format!("run failed: status {}", summary.status.as_str()))
                .with_detail("status", serde_json::Value::from(summary.status.as_str()))
                .with_detail("task", serde_json::Value::from(req.task.clone()))
                .with_detail(
                    "unclean_shutdown",
                    serde_json::Value::from(summary.unclean_shutdown),
                );
        if summary.status == RunStatus::InfraError {
            let (step_name, error_kind) = extract_infra_error(&summary);
            problem = problem
                .with_detail("failed_step", serde_json::Value::from(step_name))
                .with_detail("error_kind", serde_json::Value::from(error_kind));
        }
        let reasons: Vec<serde_json::Value> = summary
            .reasons
            .iter()
            .map(|r| serde_json::Value::from(r.as_str()))
            .collect();
        problem = problem.with_detail("reasons", serde_json::Value::Array(reasons));
        if key_path.is_some() {
            if let Ok((record, Some(env))) = assemble_and_sign_run_record(run_dir, key_path) {
                write_record(req, run_dir, &env)?;
                problem = problem.with_detail("run_digest", run_digest(&record)?);
            }
        }
        return Ok(problem);
    }

    // 8. Resolved / review runs: assemble and sign the run record from the run directory
    let (record, envelope) = assemble_and_sign_run_record(run_dir, key_path)
        .map_err(|e| BackendError::Internal(format!("failed to assemble run record: {e}")))?;
    if let Some(ref env) = envelope {
        write_record(req, run_dir, env)?;
    } else {
        let record_json = serde_json::to_vec_pretty(&record)
            .map_err(|_| BackendError::Internal("failed to serialize run record".to_string()))?;
        hermetic_attest::safe_atomic_write_file(&run_dir.join("record.json"), &record_json)
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
        outcome = outcome.with_detail("run_digest", run_digest(&record)?);
    }
    Ok(outcome)
}

fn write_record(
    req: &RunRequest,
    run_dir: &Path,
    env: &hermetic_attest::DsseEnvelope,
) -> Result<(), BackendError> {
    write_signed_run_record(&run_dir.join("record.json"), env)
        .map_err(|e| BackendError::Internal(format!("failed to write signed record: {e}")))?;
    if let Some(ref out_path) = req.out {
        write_signed_run_record(out_path, env).map_err(|e| {
            BackendError::Internal(format!("failed to write signed record to out: {e}"))
        })?;
    }
    Ok(())
}

fn run_digest(record: &hermetic_attest::RunRecord) -> Result<serde_json::Value, BackendError> {
    let digest = hermetic_attest::compute_run_digest(record)
        .map_err(|e| BackendError::Internal(format!("failed to compute run digest: {e}")))?;
    Ok(serde_json::Value::from(digest.to_string()))
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

/// Production entry point for `hermetic-cli run`.
///
/// Real microVM orchestration (AgentVM, ExtractorVM and GraderVMs driven through
/// `hermetic-vmm`) is not wired into the CLI yet, so `run` fails closed with a fixed
/// message instead of producing a verdict. The run flow itself (`execute_run_flow`)
/// is exercised with an injected `Infra` in tests; no code path may fabricate VM,
/// extraction or grading results.
pub fn run_with_real_infra(req: RunRequest) -> Result<Outcome, BackendError> {
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    let (fc, kernel, rootfs) = (
        set("HERMETIC_FC_BIN"),
        set("HERMETIC_KERNEL"),
        set("HERMETIC_ROOTFS"),
    );
    if fc || kernel || rootfs {
        // Name the first missing input so a misconfigured host is easy to diagnose.
        if !fc {
            return Err(BackendError::Unavailable("HERMETIC_FC_BIN must be set"));
        }
        if !kernel {
            return Err(BackendError::Unavailable("HERMETIC_KERNEL must be set"));
        }
        if !rootfs {
            return Err(BackendError::Unavailable("HERMETIC_ROOTFS must be set"));
        }
        let run_dir = match req
            .run_dir
            .clone()
            .or_else(|| std::env::var_os("HERMETIC_RUN_DIR").map(std::path::PathBuf::from))
        {
            Some(rd) => rd,
            None => {
                return Err(BackendError::Unavailable(
                    "HERMETIC_RUN_DIR must be set to a directory outside the sealed world",
                ));
            }
        };

        let key_path = req
            .key
            .clone()
            .or_else(|| std::env::var_os("HERMETIC_SIGNING_KEY").map(std::path::PathBuf::from));
        let run_agent_mode = match req.agent_mode {
            AgentMode::H => hermetic_run::infra::AgentMode::HarnessDriven {
                commands: Vec::new(),
            },
            AgentMode::G => hermetic_run::infra::AgentMode::GuestAutonomous {
                entrypoint: req
                    .entrypoint
                    .clone()
                    .unwrap_or_else(|| "/opt/agent/run".to_string()),
            },
        };
        let mut infra = hermetic_vmm::vmm_infra::VmmInfra::from_env_with_run_dir(run_dir.clone())
            .map_err(|e| {
                BackendError::Internal(format!("failed to initialize VMM infrastructure: {e}"))
            })?
            .with_agent_mode(run_agent_mode);
        let clock = SystemClock;
        return execute_run_flow(&mut infra, &clock, &req, &run_dir, key_path.as_deref());
    }
    Err(BackendError::Unavailable(RUN_NOT_WIRED))
}
