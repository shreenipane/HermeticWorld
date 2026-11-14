//! Production backend: thin adapters over the Hermetic World crates.
//!
//! Subcommands whose backend is not available on this build fail closed with a
//! fixed message and exit code 70. Nothing here runs guest probes on the host;
//! `probe` only classifies captured probe output supplied as a file.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use hermetic_attest::{safe_read_file, FsError, RunRecord};
use hermetic_bundle::{BundleError, Verdict};
use hermetic_clockprobe::canary;
use hermetic_clockprobe::classify::{determine_exit_code, ProbeRecord, ProbeResult, MAX_ITEMS};

use crate::args::{ProbeRequest, RunRequest, SealRequest, VerifyBundleRequest, VerifyRequest};
use crate::dispatch::{Backend, BackendError, Outcome};

/// Fixed fail-closed messages for backends not available on this build.
pub const SEAL_NOT_WIRED: &str =
    "seal backend (cutoff computation, world build, sealcheck gate) is not available in this build";
pub const RUN_NOT_WIRED: &str =
    "run backend (microVM orchestration) is not available in this build";
pub const VERIFY_SIGNATURE_NOT_WIRED: &str = "record schema is valid, but signature and bundle cross-check verification is not available in this build";
pub const PROBE_NEEDS_INPUT: &str = "probe never runs guest probes on the host; supply --clockprobe-output or --kernel-canary-serial";

/// Cap for captured clockprobe JSON-lines output.
pub const MAX_CLOCKPROBE_OUTPUT_BYTES: usize = 1024 * 1024;
/// Cap for a run record file.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct RealBackend;

fn fs_error(err: FsError) -> BackendError {
    match err {
        FsError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            BackendError::Io("input file not found".to_string())
        }
        FsError::Io(_) => BackendError::Io("input file could not be read".to_string()),
        other => BackendError::Data(format!("refused input file: {other}")),
    }
}

fn read_input(path: &Path, max: usize) -> Result<Vec<u8>, BackendError> {
    safe_read_file(path, max).map_err(fs_error)
}

/// Requires `path` to be a real directory (not a symlink to one).
fn require_real_dir(path: &Path) -> Result<(), BackendError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BackendError::Data(
            "refused bundle directory: symlink".to_string(),
        )),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(BackendError::Data(
            "refused bundle directory: not a directory".to_string(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(BackendError::Io("bundle directory not found".to_string()))
        }
        Err(_) => Err(BackendError::Io(
            "bundle directory could not be read".to_string(),
        )),
    }
}

fn bundle_error(err: BundleError) -> BackendError {
    match err {
        BundleError::Io { .. } => BackendError::Io(err.to_string()),
        BundleError::InvalidRootDir { .. }
        | BundleError::NotADirectory { .. }
        | BundleError::InvalidExpectedRoot
        | BundleError::UnsupportedPlatform => BackendError::Data(err.to_string()),
        other => BackendError::ProblemFound(format!("bundle rejected: {other}")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProbeRecord {
    probe: String,
    result: String,
    #[serde(default)]
    value: Option<String>,
    detail: String,
}

/// Parses captured `hermetic-clockprobe` JSON-lines output strictly.
pub fn parse_clockprobe_lines(bytes: &[u8]) -> Result<Vec<ProbeRecord>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "output is not UTF-8".to_string())?;
    let mut records = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if records.len() >= MAX_ITEMS {
            return Err(format!("more than {MAX_ITEMS} probe records"));
        }
        let wire: WireProbeRecord = serde_json::from_str(line)
            .map_err(|_| format!("line {} is not a probe record", idx + 1))?;
        let result = match wire.result.as_str() {
            "blocked" => ProbeResult::Blocked,
            "leak" => ProbeResult::Leak,
            "unavailable" => ProbeResult::Unavailable,
            "error" => ProbeResult::Error,
            _ => return Err(format!("line {} has an unknown result", idx + 1)),
        };
        if wire.probe.is_empty() || wire.probe.len() > 128 {
            return Err(format!("line {} has an invalid probe name", idx + 1));
        }
        records.push(ProbeRecord::new(
            wire.probe,
            result,
            wire.value,
            wire.detail,
        ));
    }
    if records.is_empty() {
        return Err("no probe records".to_string());
    }
    Ok(records)
}

fn probes_outcome(records: &[ProbeRecord]) -> Outcome {
    let code = determine_exit_code(records);
    let list: Vec<Value> = records
        .iter()
        .map(|r| serde_json::json!({"probe": r.probe, "result": r.result.as_str()}))
        .collect();
    let leaks: Vec<&str> = records
        .iter()
        .filter(|r| r.result == ProbeResult::Leak)
        .map(|r| r.probe.as_str())
        .collect();
    let outcome = match code {
        0 => Outcome::success(format!("{} probe records, no leak", records.len())),
        2 => Outcome::problem(format!("clock leak observed: {}", leaks.join(","))),
        _ => Outcome::problem("probe error recorded; result is inconclusive"),
    };
    let verdict = match code {
        0 => "blocked",
        2 => "leak",
        _ => "error",
    };
    outcome
        .with_detail("verdict", Value::from(verdict))
        .with_detail("records", Value::Array(list))
}

impl Backend for RealBackend {
    fn seal(&self, _req: SealRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::Unavailable(SEAL_NOT_WIRED))
    }

    fn verify_bundle(&self, req: VerifyBundleRequest) -> Result<Outcome, BackendError> {
        require_real_dir(&req.dir)?;
        let report =
            hermetic_bundle::verify(&req.dir, req.root.as_deref()).map_err(bundle_error)?;
        let outcome = if report.verdict == Verdict::Ok {
            Outcome::success(format!("ok {}", report.recomputed_root))
        } else {
            Outcome::problem(format!(
                "mismatch: {} missing, {} extra, {} hash, {} size, {} mode, {} kind, {} refused, manifest root {}, expected root {}",
                report.missing_entries.len(),
                report.extra_entries.len(),
                report.hash_mismatches.len(),
                report.size_mismatches.len(),
                report.mode_mismatches.len(),
                report.kind_mismatches.len(),
                report.refused_objects.len(),
                if report.manifest_root_matches { "matches" } else { "differs" },
                match report.expected_root_matches {
                    None => "not given",
                    Some(true) => "matches",
                    Some(false) => "differs",
                },
            ))
        };
        Ok(outcome.with_detail("root", Value::from(report.recomputed_root)))
    }

    fn probe(&self, req: ProbeRequest) -> Result<Outcome, BackendError> {
        let mut records = Vec::new();
        if req.clockprobe_output.is_none() && req.kernel_canary_serial.is_none() {
            return Err(BackendError::Unavailable(PROBE_NEEDS_INPUT));
        }
        if let Some(path) = &req.clockprobe_output {
            let bytes = read_input(path, MAX_CLOCKPROBE_OUTPUT_BYTES)?;
            let parsed = parse_clockprobe_lines(&bytes)
                .map_err(|e| BackendError::Data(format!("invalid clockprobe output: {e}")))?;
            records.extend(parsed);
        }
        if let Some(path) = &req.kernel_canary_serial {
            // One byte over the cap so canary::inspect itself reports oversize.
            let bytes = read_input(path, canary::MAX_SERIAL_BYTES as usize + 1)?;
            records.push(canary::inspect(&bytes));
        }
        Ok(probes_outcome(&records))
    }

    fn run(&self, _req: RunRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::Unavailable(RUN_NOT_WIRED))
    }

    fn verify(&self, req: VerifyRequest) -> Result<Outcome, BackendError> {
        if let Some(bundle) = &req.bundle {
            require_real_dir(bundle)?;
        }
        let bytes = read_input(&req.record, MAX_RECORD_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| BackendError::ProblemFound("record invalid: not UTF-8".to_string()))?;
        RunRecord::from_json_str(text)
            .map_err(|e| BackendError::ProblemFound(format!("record invalid: {e}")))?;
        Err(BackendError::Unavailable(VERIFY_SIGNATURE_NOT_WIRED))
    }
}
