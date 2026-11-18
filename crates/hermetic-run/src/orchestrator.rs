#![forbid(unsafe_code)]

//! Run-record orchestrator (TR-ATT-1, TR-SEC-5, §12.1).
//!
//! # Crate Placement Choice
//! Assembling a signed `RunRecord` requires combining runtime execution outputs
//! (`hermetic-run::verdict`, `RunSummary`), the real-date sentinels
//! (`hermetic-sealcheck::d12_runtime::SentinelSummary`), the VMM host boot record
//! (`HostBootRecord`), escape/clock probe outputs, and world manifest digests,
//! before signing with DSSE.
//!
//! Placing this orchestrator in `hermetic-run` rather than `hermetic-attest` owns
//! strictly fewer cross-dependencies:
//! - `hermetic-attest` remains a minimal, leaf cryptographic verification crate
//!   (depended on by `hermetic-cli verify` and external offline verifiers) without
//!   dragging in the extensive dependency trees of `hermetic-sealcheck` (parsers,
//!   tar/zip decompressors, AST scanners) or VM orchestration modules.
//! - `hermetic-run` is already the evaluation engine responsible for benchmark run
//!   lifecycles and verdicts. Orchestrating the final run record at the runner layer
//!   aligns with the system hierarchy and cleanly exposes entry points for `hermetic-cli run`.
//!
//! # Run-Directory Layout
//! The orchestrator reads exactly one canonical file name per artifact from `run_dir`:
//! - `date_sentinel.json`: Gateway real-date sentinel summary (`SentinelSummary`, capped at 64 KiB).
//! - `harness_summary.json`: Test harness sentinel summary (`SentinelSummary`, capped at 1 MiB).
//! - `probe_output.jsonl`: Guest clock and escape probe JSON-lines output (`ProbeLineWire`, capped at 1 MiB).
//! - `boot_record.json`: VMM host boot record (`HostBootRecord`, capped at 64 KiB).
//! - `verdict.json`: Evaluation verdict from grading (`VerdictArtifact`, capped at 1 MiB).
//! - `world_manifest.json`: World manifest cutoffs and digests (`WorldManifestArtifact`, capped at 1 MiB).
//! - `submitted_work.patch`: Submitted patch artifact (capped at 16 MiB; optional if `submitted_work_digest` is in `verdict.json`).
//! - `firecracker`: Firecracker binary (capped at 256 MiB; optional host fact artifact).
//! - `firecracker_build.json`: Build record schema `hermetic-firecracker-build/v1` (capped at 64 KiB; optional host fact artifact).
//! - `pinned_lock.json`: Pinned Firecracker lock (capped at 64 KiB; optional host fact artifact).
//!
//! To prevent ambiguous records, no alternative or fallback file names are permitted.
//! Every file is opened without following symlinks and read within bounded byte limits.
//!
//! # Clock-Level Computation Choice
//! The clock level (`hidden`, `faked`, `real`) is never copied from an input file assertion.
//! Instead, `orchestrator` computes it directly using the exact rules of the Python run
//! classifier (`hermetic_classifier.run.clock_level`) from the probe records, host facts,
//! substrate, and date leak observations. Host facts (`patched_firecracker`, `hypercall_block`)
//! are never read as asserted booleans; they are derived by `host_facts` from `firecracker`,
//! `firecracker_build.json`, and `pinned_lock.json` as `python/hermetic_classifier/evidence.py` does.
//!
//! Computing `clock_level` directly in the orchestrator is chosen over reading `classification.json`
//! from the run directory because:
//! 1. `hermetic-run-classification/v1` documents bind to `run_digest` (the SHA-256 digest of
//!    the assembled `RunRecord`). Reading a classification document to determine `RunRecord.clock`
//!    would introduce a circular dependency (the classifier requires `run_digest`, but `run_digest`
//!    hashes `RunRecord` including `clock`).
//! 2. It keeps run record assembly self-contained and single-pass without requiring an external
//!    Python process to execute before attestation assembly.
//! 3. Parity with the classifier is verified using a shared known-answer fixture
//!    (`probe_drift_fixture.json`) checked by both Rust and Python regression test suites to
//!    guarantee that the two implementations cannot drift.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use hermetic_attest::safe_atomic_write_file;
use hermetic_attest::safe_read_file;
use hermetic_attest::safe_sha256_file;
use hermetic_attest::{
    AgentMode, ClockLevel, Deployment, Digest, DsseEnvelope, DsseError, Ed25519Signer, FsError,
    GraderIsolation, GradingRunResult, HostBootRecord, KeyError, ProbeResult, RunRecord, RunStatus,
    RunValidationError, SealLevel, Signer, SigstoreBundle, SigstoreError, SigstoreSigner,
    StateGradeRecord, Statement, SubstrateAtT, TaskClass, TeeQuote, VersionTuple,
};
use hermetic_sealcheck::d12_runtime::SentinelSummary;
use serde::{Deserialize, Serialize};

// Bounded input constants (§12.1, TR-SEC-3)
pub const MAX_SENTINEL_BYTES: usize = 64 * 1024;
pub const MAX_GATEWAY_HEAD_BYTES: usize = 64 * 1024;
pub const MAX_GATEWAY_HISTORY_BYTES: usize = 64 * 1024;
pub const MAX_HARNESS_SUMMARY_BYTES: usize = 1024 * 1024;
pub const MAX_PROBE_BYTES: usize = 1024 * 1024;
pub const MAX_BOOT_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_STATE_GRADE_BYTES: usize = 16 * 1024;
pub const MAX_VERDICT_BYTES: usize = 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_SUBMITTED_WORK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LOCK_BYTES: usize = 64 * 1024;
pub const MAX_FIRECRACKER_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PROBE_LINES: usize = 10_000;
pub const MAX_PROBE_LINE_BYTES: usize = 512;

pub const BUILD_SCHEMA: &str = "hermetic-firecracker-build/v1";
pub const RUN_SPEC_VERSION: &str = "v1.1";

pub const REQUIRED_PROBES: [&str; 15] = [
    "clock_pairing_hc",
    "clocksource_sysfs",
    "cpuid",
    "cpuinfo",
    "dmesg_dates",
    "hpet",
    "kernel_canary",
    "kvmclock_msr",
    "module_load",
    "posix_clocks",
    "proc_driver_rtc",
    "rdtsc",
    "ring0_paths",
    "rtc_sysfs_dev",
    "vmclock",
];

pub const PROBE_RESULTS: [&str; 4] = ["blocked", "leak", "unavailable", "error"];

/// Typed errors for run-record assembly and signing.
/// Diagnostics never expose host paths, timestamps, or hostile inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    Fs {
        artifact: &'static str,
        detail: String,
    },
    Json {
        artifact: &'static str,
        detail: String,
    },
    MissingArtifact(&'static str),
    MalformedArtifact {
        artifact: &'static str,
        detail: &'static str,
    },
    Validation(RunValidationError),
    Key(KeyError),
    Dsse(DsseError),
    Sigstore(SigstoreError),
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fs { artifact, detail } => {
                write!(f, "Failed to read artifact '{artifact}': {detail}")
            }
            Self::Json { artifact, detail } => {
                write!(f, "Failed to parse JSON in '{artifact}': {detail}")
            }
            Self::MissingArtifact(artifact) => {
                write!(f, "Required artifact '{artifact}' is missing")
            }
            Self::MalformedArtifact { artifact, detail } => {
                write!(f, "Malformed artifact '{artifact}': {detail}")
            }
            Self::Validation(e) => write!(f, "Run record validation failed: {e}"),
            Self::Key(e) => write!(f, "Key error: {e}"),
            Self::Dsse(e) => write!(f, "DSSE error: {e}"),
            Self::Sigstore(e) => write!(f, "Sigstore error: {e}"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<RunValidationError> for OrchestratorError {
    fn from(e: RunValidationError) -> Self {
        Self::Validation(e)
    }
}

impl From<KeyError> for OrchestratorError {
    fn from(e: KeyError) -> Self {
        Self::Key(e)
    }
}

impl From<DsseError> for OrchestratorError {
    fn from(e: DsseError) -> Self {
        Self::Dsse(e)
    }
}

impl From<SigstoreError> for OrchestratorError {
    fn from(e: SigstoreError) -> Self {
        Self::Sigstore(e)
    }
}

/// Host facts derived from verified Firecracker binary and build records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFactsArtifact {
    pub patched_firecracker: bool,
    pub hypercall_block: bool,
}

/// World manifest artifact describing world and seal digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldManifestArtifact {
    pub task_id: String,
    pub task_class: TaskClass,
    pub seal_level: SealLevel,
    pub agent_mode: AgentMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substrate: Option<String>,
    pub grader_isolation: GraderIsolation,
    pub deployment: Deployment,

    // Cutoffs
    pub t_world: String,
    pub t_clock: String,
    pub base_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkg_cutoff: Option<String>,

    // Version tuple
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    pub world_version: Digest,
    pub sealcheck_version: String,
    pub grader_image_digest: Digest,

    // Content digests
    pub world_root: Digest,
    pub task_rootfs_digest: Digest,
    pub netvm_image_digest: Digest,
    pub guest_kernel_digest: Digest,
    pub vm_config_digest: Digest,
    pub cpu_template_digest: Digest,
    pub firecracker_build_digest: Digest,
    pub agent_volume_digest: Digest,
    pub sealcheck_report_digest: Digest,

    // Substrate
    pub substrate_at_t: SubstrateAtT,
    #[serde(default)]
    pub exemption_list: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d5b_warning_list: Option<Vec<String>>,

    // WorldServer
    pub world_server_log_head: Digest,
    pub dedupe_index_digest: Digest,
    pub request_count: u64,

    // Mode-specific logs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_command_log_head: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_log_head: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_rewrite_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_adapter_version: Option<String>,

    // Optional TEE quote
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_quote: Option<TeeQuote>,
}

/// Evaluation verdict artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictArtifact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_status: Option<RunStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<RunStatus>,
    pub r0_result: GradingRunResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r1_result: Option<GradingRunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r2_result: Option<GradingRunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r3_result: Option<GradingRunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r1_coverage: Option<u32>,
    #[serde(default)]
    pub unclean_shutdown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_work_digest: Option<Digest>,
}

impl VerdictArtifact {
    pub fn resolved_status(&self) -> Result<RunStatus, OrchestratorError> {
        self.run_status
            .or(self.status)
            .ok_or(OrchestratorError::MalformedArtifact {
                artifact: "verdict.json",
                detail: "missing run_status or status field",
            })
    }
}

/// VMM host boot record artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootRecordArtifact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    pub boot_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd_digest: Option<Digest>,
}

/// Line wire format for escape/clock probe records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeLineWire {
    pub probe: String,
    pub result: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Helper to read a required file safely without following symlinks.
fn read_artifact_bytes(
    run_dir: &Path,
    artifact: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, OrchestratorError> {
    let path = run_dir.join(artifact);
    match safe_read_file(&path, max_bytes) {
        Ok(bytes) => Ok(bytes),
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(OrchestratorError::MissingArtifact(artifact))
        }
        Err(e) => Err(OrchestratorError::Fs {
            artifact,
            detail: e.to_string(),
        }),
    }
}

/// Helper to read an optional artifact safely without following symlinks.
fn read_optional_artifact_bytes(
    run_dir: &Path,
    artifact: &'static str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, OrchestratorError> {
    let path = run_dir.join(artifact);
    match safe_read_file(&path, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OrchestratorError::Fs {
            artifact,
            detail: e.to_string(),
        }),
    }
}

/// Helper to construct a sanitized JSON parse error detail without hostile parser text.
#[inline]
fn json_parse_error(line: usize, column: usize) -> String {
    format!("parse error at line {line} column {column}")
}

/// Helper to strictly parse a JSON object, rejecting duplicate keys and non-object roots.
fn parse_strict_map(
    bytes: &[u8],
    artifact: &'static str,
) -> Result<BTreeMap<String, serde_json::Value>, OrchestratorError> {
    use serde::de::{Deserializer, MapAccess, Visitor};

    struct StrictMapVisitor;

    impl<'de> Visitor<'de> for StrictMapVisitor {
        type Value = BTreeMap<String, serde_json::Value>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON object without duplicate keys")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, serde_json::Value>()? {
                if map.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate key in JSON object"));
                }
            }
            Ok(map)
        }
    }

    struct StrictMap(BTreeMap<String, serde_json::Value>);

    impl<'de> serde::Deserialize<'de> for StrictMap {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer
                .deserialize_map(StrictMapVisitor)
                .map(StrictMap)
        }
    }

    let parsed: StrictMap = serde_json::from_slice(bytes).map_err(|e| OrchestratorError::Json {
        artifact,
        detail: json_parse_error(e.line(), e.column()),
    })?;
    Ok(parsed.0)
}

/// Helper to extract and validate a 64-character lowercase hex digest field.
fn get_hex_field(
    map: &BTreeMap<String, serde_json::Value>,
    key: &str,
    artifact: &'static str,
) -> Result<String, OrchestratorError> {
    let val =
        map.get(key)
            .and_then(|v| v.as_str())
            .ok_or(OrchestratorError::MalformedArtifact {
                artifact,
                detail: "hash field missing or not a string",
            })?;
    if val.len() != 64 || !val.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(OrchestratorError::MalformedArtifact {
            artifact,
            detail: "hash field must be 64 lowercase hex characters",
        });
    }
    Ok(val.to_string())
}

/// Derives host facts from the Firecracker executable, its build record, and the pinned lock.
/// Replicates `python/hermetic_classifier/evidence.py host_facts`.
pub fn host_facts(
    firecracker_path: &Path,
    build_record_path: &Path,
    pinned_lock_path: &Path,
) -> Result<HostFactsArtifact, OrchestratorError> {
    let build_bytes =
        safe_read_file(build_record_path, MAX_LOCK_BYTES).map_err(|e| OrchestratorError::Fs {
            artifact: "firecracker_build.json",
            detail: e.to_string(),
        })?;
    let lock_bytes =
        safe_read_file(pinned_lock_path, MAX_LOCK_BYTES).map_err(|e| OrchestratorError::Fs {
            artifact: "pinned_lock.json",
            detail: e.to_string(),
        })?;

    let build_map = parse_strict_map(&build_bytes, "firecracker_build.json")?;
    let lock_map = parse_strict_map(&lock_bytes, "pinned_lock.json")?;

    match build_map.get("schema").and_then(|v| v.as_str()) {
        Some(s) if s == BUILD_SCHEMA => {}
        _ => {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "firecracker_build.json",
                detail: "unknown Firecracker build record schema",
            });
        }
    }

    let built = get_hex_field(&build_map, "firecracker_sha256", "firecracker_build.json")?;
    let lock_fc = get_hex_field(&lock_map, "firecracker_sha256", "pinned_lock.json")?;
    let build_patch = get_hex_field(&build_map, "patch_sha256", "firecracker_build.json")?;
    let lock_patch = get_hex_field(&lock_map, "patch_sha256", "pinned_lock.json")?;
    let build_source = get_hex_field(&build_map, "source_sha256", "firecracker_build.json")?;
    let lock_source = get_hex_field(&lock_map, "source_sha256", "pinned_lock.json")?;

    let actual = safe_sha256_file(firecracker_path, MAX_FIRECRACKER_BYTES).map_err(|e| {
        OrchestratorError::Fs {
            artifact: "firecracker",
            detail: e.to_string(),
        }
    })?;

    let patched = actual == built
        && built != lock_fc
        && build_patch == lock_patch
        && build_source == lock_source;

    Ok(HostFactsArtifact {
        patched_firecracker: patched,
        hypercall_block: patched,
    })
}

/// Alias for `host_facts`.
pub fn derive_host_facts(
    firecracker_path: &Path,
    build_record_path: &Path,
    pinned_lock_path: &Path,
) -> Result<HostFactsArtifact, OrchestratorError> {
    host_facts(firecracker_path, build_record_path, pinned_lock_path)
}

/// Load and derive host facts from canonical files in the run directory.
/// Returns `Ok(None)` if no host fact inputs are present. If any is present, all three must be valid.
fn load_host_facts(run_dir: &Path) -> Result<Option<HostFactsArtifact>, OrchestratorError> {
    let fc_path = run_dir.join("firecracker");
    let build_path = run_dir.join("firecracker_build.json");
    let lock_path = run_dir.join("pinned_lock.json");

    let has_fc = std::fs::symlink_metadata(&fc_path).is_ok();
    let has_build = std::fs::symlink_metadata(&build_path).is_ok();
    let has_lock = std::fs::symlink_metadata(&lock_path).is_ok();

    if !has_fc && !has_build && !has_lock {
        return Ok(None);
    }
    if !has_fc {
        return Err(OrchestratorError::MissingArtifact("firecracker"));
    }
    if !has_build {
        return Err(OrchestratorError::MissingArtifact("firecracker_build.json"));
    }
    if !has_lock {
        return Err(OrchestratorError::MissingArtifact("pinned_lock.json"));
    }

    host_facts(&fc_path, &build_path, &lock_path).map(Some)
}

/// Load and parse the gateway real-date sentinel summary.
fn load_gateway_sentinel(run_dir: &Path) -> Result<SentinelSummary, OrchestratorError> {
    let bytes = read_artifact_bytes(run_dir, "date_sentinel.json", MAX_SENTINEL_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
        artifact: "date_sentinel.json",
        detail: json_parse_error(e.line(), e.column()),
    })
}

/// Gateway head summary artifact (written by hermetic-gateway for Mode G).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHeadSummary {
    pub records: u64,
    pub head: String,
    pub history_rewrite_count: u64,
    pub adapter_version: String,
}

/// Load and parse the gateway head summary (for Mode G).
fn load_gateway_head_summary(
    run_dir: &Path,
) -> Result<Option<GatewayHeadSummary>, OrchestratorError> {
    let artifact = "gateway_head.json";
    let path = run_dir.join(artifact);
    match safe_read_file(&path, MAX_GATEWAY_HEAD_BYTES) {
        Ok(bytes) => {
            let parsed: GatewayHeadSummary =
                serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
                    artifact,
                    detail: json_parse_error(e.line(), e.column()),
                })?;
            Ok(Some(parsed))
        }
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OrchestratorError::Fs {
            artifact,
            detail: e.to_string(),
        }),
    }
}

/// Load and parse the harness summary.
fn load_harness_sentinel(run_dir: &Path) -> Result<SentinelSummary, OrchestratorError> {
    let bytes = read_artifact_bytes(run_dir, "harness_summary.json", MAX_HARNESS_SUMMARY_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
        artifact: "harness_summary.json",
        detail: json_parse_error(e.line(), e.column()),
    })
}

/// Load and parse the probe real-date sentinel summary if present.
fn load_probe_sentinel(run_dir: &Path) -> Result<Option<SentinelSummary>, OrchestratorError> {
    let maybe_bytes =
        read_optional_artifact_bytes(run_dir, "probe_sentinel.json", MAX_SENTINEL_BYTES)?;
    let Some(bytes) = maybe_bytes else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| OrchestratorError::Json {
            artifact: "probe_sentinel.json",
            detail: json_parse_error(e.line(), e.column()),
        })
}

/// Load and aggregate the dedicated escape probe output if present.
/// Returns (Digest, ProbeResult, bool /* date_leak */) if escape_probe.jsonl exists.
fn load_escape_probe_output(
    run_dir: &Path,
) -> Result<Option<(Digest, ProbeResult, bool)>, OrchestratorError> {
    let maybe_bytes = read_optional_artifact_bytes(run_dir, "escape_probe.jsonl", MAX_PROBE_BYTES)?;
    let Some(bytes) = maybe_bytes else {
        return Ok(None);
    };
    let digest = Digest::from_sha256(&bytes);
    let expected = hermetic_escapeprobe::probes::expected_probe_names();
    let verdict = hermetic_escapeprobe::report::aggregate(&bytes, &expected);

    let (result, date_leak) = match verdict {
        hermetic_escapeprobe::report::Verdict::Sealed => (ProbeResult::Passed, false),
        hermetic_escapeprobe::report::Verdict::Incomplete { .. } => (ProbeResult::Failed, false),
        hermetic_escapeprobe::report::Verdict::Escaped { ref leaks } => {
            let has_date_leak = leaks.iter().any(|l| l == "gateway.model_call_date");
            (ProbeResult::Failed, has_date_leak)
        }
        hermetic_escapeprobe::report::Verdict::Invalid { reason } => {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "escape_probe.jsonl",
                detail: reason,
            });
        }
    };

    Ok(Some((digest, result, date_leak)))
}

/// Gateway history-consistency hash log artifact (Mode G).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHistoryArtifact {
    pub gateway_log_head: Digest,
    pub history_rewrite_count: u64,
    pub gateway_adapter_version: String,
}

/// Load and parse the gateway history-consistency summary (Mode G).
fn load_gateway_history(
    run_dir: &Path,
) -> Result<Option<GatewayHistoryArtifact>, OrchestratorError> {
    let artifact = "gateway_history.json";
    let path = run_dir.join(artifact);
    match safe_read_file(&path, MAX_GATEWAY_HISTORY_BYTES) {
        Ok(bytes) => {
            let parsed: GatewayHistoryArtifact =
                serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
                    artifact,
                    detail: json_parse_error(e.line(), e.column()),
                })?;
            Ok(Some(parsed))
        }
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OrchestratorError::Fs {
            artifact,
            detail: e.to_string(),
        }),
    }
}

/// Load and parse the escape/clock probe output strictly.
fn load_probe_output(run_dir: &Path) -> Result<(Vec<ProbeLineWire>, Digest), OrchestratorError> {
    let bytes = read_artifact_bytes(run_dir, "probe_output.jsonl", MAX_PROBE_BYTES)?;
    let probe_digest = Digest::from_sha256(&bytes);
    let text = std::str::from_utf8(&bytes).map_err(|_| OrchestratorError::MalformedArtifact {
        artifact: "probe_output.jsonl",
        detail: "probe output is not valid UTF-8",
    })?;

    let mut records = Vec::new();

    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if records.len() >= MAX_PROBE_LINES {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "probe_output.jsonl",
                detail: "exceeded maximum allowed probe lines",
            });
        }
        if trimmed.len() > MAX_PROBE_LINE_BYTES {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "probe_output.jsonl",
                detail: "probe line exceeds maximum length",
            });
        }

        let wire: ProbeLineWire =
            serde_json::from_str(trimmed).map_err(|e| OrchestratorError::Json {
                artifact: "probe_output.jsonl",
                detail: json_parse_error(line_idx + 1, e.column()),
            })?;

        if wire.probe.is_empty() || wire.probe.len() > 64 {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "probe_output.jsonl",
                detail: "probe name empty or exceeds length cap",
            });
        }

        if !PROBE_RESULTS.contains(&wire.result.as_str()) {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "probe_output.jsonl",
                detail: "probe record has an unknown result",
            });
        }

        if let Some(ref v) = wire.value {
            if v.len() > 4096 {
                return Err(OrchestratorError::MalformedArtifact {
                    artifact: "probe_output.jsonl",
                    detail: "probe value exceeds length cap",
                });
            }
        }

        if let Some(ref d) = wire.detail {
            if d.len() > 4096 {
                return Err(OrchestratorError::MalformedArtifact {
                    artifact: "probe_output.jsonl",
                    detail: "probe detail exceeds length cap",
                });
            }
        }

        records.push(wire);
    }

    if records.is_empty() {
        return Err(OrchestratorError::MalformedArtifact {
            artifact: "probe_output.jsonl",
            detail: "probe output contains zero valid records",
        });
    }

    Ok((records, probe_digest))
}

/// Derive escape probe verdict from probe records.
/// Passed only when every record is blocked, with the clock_pairing_hc/kernel_canary exception.
pub fn derive_escape_probe_result(records: &[ProbeLineWire]) -> ProbeResult {
    let canary_blocked = records
        .iter()
        .any(|r| r.probe == "kernel_canary" && r.result == "blocked");

    let all_passed = records.iter().all(|r| {
        r.result == "blocked"
            || (r.probe == "clock_pairing_hc" && r.result == "unavailable" && canary_blocked)
    });

    if all_passed {
        ProbeResult::Passed
    } else {
        ProbeResult::Failed
    }
}

/// Compute clock level from probe records, substrate, host facts, and date leak observation.
/// Replicates the exact rules of the Python run classifier (`hermetic_classifier.run.clock_level`).
pub fn compute_clock_level(
    substrate: Option<&str>,
    host: Option<&HostFactsArtifact>,
    records: &[ProbeLineWire],
    date_leak_observed: bool,
) -> (ClockLevel, Vec<String>) {
    if substrate == Some("container") {
        return (ClockLevel::Real, vec!["container_substrate".to_string()]);
    }

    let mut reasons = BTreeSet::new();

    let host_patched = host.is_some_and(|h| h.patched_firecracker);
    let host_hypercall = host.is_some_and(|h| h.hypercall_block);

    if !host_patched {
        reasons.insert("no_patched_firecracker".to_string());
    }
    if !host_hypercall {
        reasons.insert("no_hypercall_block".to_string());
    }
    if date_leak_observed {
        reasons.insert("date_leak_observed".to_string());
    }

    if records.is_empty() {
        reasons.insert("probe_missing".to_string());
    } else {
        let mut seen = BTreeMap::new();
        for rec in records {
            if seen.contains_key(rec.probe.as_str()) {
                reasons.insert("probe_duplicate".to_string());
            } else if !REQUIRED_PROBES.contains(&rec.probe.as_str()) {
                reasons.insert("probe_unknown_record".to_string());
            }
            seen.entry(rec.probe.as_str())
                .or_insert(rec.result.as_str());
        }

        for required in &REQUIRED_PROBES {
            if !seen.contains_key(required) {
                reasons.insert("probe_incomplete".to_string());
                break;
            }
        }

        let canary_blocked = seen.get("kernel_canary") == Some(&"blocked");

        for rec in records {
            if rec.result == "blocked" {
                continue;
            }
            if rec.probe == "clock_pairing_hc" && rec.result == "unavailable" && canary_blocked {
                continue;
            }
            if rec.result == "leak" {
                reasons.insert("probe_leak".to_string());
            } else {
                reasons.insert("probe_not_blocked".to_string());
            }
        }
    }

    if reasons.is_empty() {
        (ClockLevel::Hidden, Vec::new())
    } else {
        (ClockLevel::Faked, reasons.into_iter().collect())
    }
}

/// Load and parse the VMM host boot record.
fn load_boot_record(run_dir: &Path) -> Result<HostBootRecord, OrchestratorError> {
    let bytes = read_artifact_bytes(run_dir, "boot_record.json", MAX_BOOT_RECORD_BYTES)?;
    let wire: BootRecordArtifact =
        serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
            artifact: "boot_record.json",
            detail: json_parse_error(e.line(), e.column()),
        })?;

    match wire.boot_path.as_str() {
        "sealed_disk" => {
            if wire.initrd_sha256.is_some() || wire.initrd_digest.is_some() {
                return Err(OrchestratorError::MalformedArtifact {
                    artifact: "boot_record.json",
                    detail: "sealed_disk must not have initrd digest",
                });
            }
            Ok(HostBootRecord::sealed_disk())
        }
        "trusted_initramfs" => {
            let digest = if let Some(d) = wire.initrd_digest {
                d
            } else if let Some(hex) = wire.initrd_sha256 {
                let digest_str = if hex.starts_with("sha256:") {
                    hex
                } else {
                    format!("sha256:{hex}")
                };
                Digest::parse(&digest_str).map_err(|_| OrchestratorError::MalformedArtifact {
                    artifact: "boot_record.json",
                    detail: "invalid initrd sha256 digest format",
                })?
            } else {
                return Err(OrchestratorError::MalformedArtifact {
                    artifact: "boot_record.json",
                    detail: "trusted_initramfs requires initrd digest",
                });
            };
            Ok(HostBootRecord::trusted_initramfs(digest))
        }
        "live_snapshot" => {
            if wire.initrd_sha256.is_some() || wire.initrd_digest.is_some() {
                return Err(OrchestratorError::MalformedArtifact {
                    artifact: "boot_record.json",
                    detail: "live_snapshot must not have initrd digest",
                });
            }
            Ok(HostBootRecord::live_snapshot())
        }
        _ => Err(OrchestratorError::MalformedArtifact {
            artifact: "boot_record.json",
            detail: "unknown boot_path in host boot record",
        }),
    }
}

/// Load and parse the state task grading path record if present (§11.4).
fn load_state_grade(run_dir: &Path) -> Result<Option<StateGradeRecord>, OrchestratorError> {
    let artifact = "state_grade.json";
    let p = run_dir.join(artifact);
    let bytes = match safe_read_file(&p, MAX_STATE_GRADE_BYTES) {
        Ok(bytes) => bytes,
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(OrchestratorError::Fs {
                artifact,
                detail: e.to_string(),
            });
        }
    };
    let record: StateGradeRecord =
        serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
            artifact,
            detail: json_parse_error(e.line(), e.column()),
        })?;
    record
        .validate()
        .map_err(|_| OrchestratorError::MalformedArtifact {
            artifact,
            detail: "state_grade validation failed",
        })?;
    Ok(Some(record))
}

/// Load and parse the evaluation verdict from hermetic-run.
fn load_verdict(run_dir: &Path) -> Result<VerdictArtifact, OrchestratorError> {
    let bytes = read_artifact_bytes(run_dir, "verdict.json", MAX_VERDICT_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
        artifact: "verdict.json",
        detail: json_parse_error(e.line(), e.column()),
    })
}

/// Load and parse the world manifest artifact describing base cutoffs and digests.
fn load_world_manifest(run_dir: &Path) -> Result<WorldManifestArtifact, OrchestratorError> {
    let bytes = read_artifact_bytes(run_dir, "world_manifest.json", MAX_MANIFEST_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Json {
        artifact: "world_manifest.json",
        detail: json_parse_error(e.line(), e.column()),
    })
}

/// Determine submitted work digest from verdict or from patch artifact.
/// Only NotFound is allowed to continue; every other error fails closed.
fn resolve_submitted_work_digest(
    run_dir: &Path,
    verdict: &VerdictArtifact,
) -> Result<Digest, OrchestratorError> {
    if let Some(ref d) = verdict.submitted_work_digest {
        return Ok(d.clone());
    }

    let patch_name = "submitted_work.patch";
    let path = run_dir.join(patch_name);
    match safe_read_file(&path, MAX_SUBMITTED_WORK_BYTES) {
        Ok(bytes) => Ok(Digest::from_sha256(&bytes)),
        Err(FsError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(OrchestratorError::MissingArtifact(
                "submitted_work_digest in verdict.json or submitted_work.patch",
            ))
        }
        Err(e) => Err(OrchestratorError::Fs {
            artifact: patch_name,
            detail: e.to_string(),
        }),
    }
}

/// Assembles a validated `RunRecord` from a run directory of artifacts.
///
/// Every artifact is read strictly without following symlinks and bounded by byte caps.
/// The gateway date sentinel and harness summary are merged with `SentinelSummary::merge`
/// into `date_leak_observed`. Clock level is derived strictly according to the classifier's
/// rules. If any leak was observed, clock is lowered to `faked` and resolved status moves to `review`.
pub fn assemble_run_record(run_dir: &Path) -> Result<RunRecord, OrchestratorError> {
    // 1. Read and parse all canonical artifacts strictly no-follow and byte-capped
    let gateway_sentinel = load_gateway_sentinel(run_dir)?;
    let harness_sentinel = load_harness_sentinel(run_dir)?;
    let probe_sentinel = load_probe_sentinel(run_dir)?;
    let (probe_records, legacy_probe_digest) = load_probe_output(run_dir)?;
    let escape_probe_artifact = load_escape_probe_output(run_dir)?;
    let boot_record = load_boot_record(run_dir)?;
    let verdict = load_verdict(run_dir)?;
    let manifest = load_world_manifest(run_dir)?;
    let gateway_history = load_gateway_history(run_dir)?;
    let gateway_head = load_gateway_head_summary(run_dir)?;
    let submitted_work_digest = resolve_submitted_work_digest(run_dir, &verdict)?;
    let state_grade = load_state_grade(run_dir)?;

    // 2. Date leak is derived from real-date sentinels (TR-SEC-5, D12)
    let mut sentinels = vec![gateway_sentinel, harness_sentinel];
    if let Some(probe_s) = probe_sentinel {
        sentinels.push(probe_s);
    }
    let merged_sentinel = SentinelSummary::merge(&sentinels);
    let escape_probe_date_leak = escape_probe_artifact
        .as_ref()
        .map(|(_, _, dl)| *dl)
        .unwrap_or(false);
    let date_leak_observed = merged_sentinel.date_leak_observed || escape_probe_date_leak;

    // 3. Derive escape probe result strictly from probe records
    let (escape_probe_digest, escape_probe_result) =
        if let Some((ep_digest, ep_result, _)) = escape_probe_artifact {
            (ep_digest, ep_result)
        } else {
            let legacy_result = derive_escape_probe_result(&probe_records);
            (legacy_probe_digest, legacy_result)
        };

    // 4. Derive host facts and clock level using the exact classifier rules
    let host = load_host_facts(run_dir)?;
    let (clock, _clock_reasons) = compute_clock_level(
        manifest.substrate.as_deref(),
        host.as_ref(),
        &probe_records,
        date_leak_observed,
    );

    // 5. Status precedence and date leak downgrade
    let mut run_status = verdict.resolved_status()?;
    if date_leak_observed && run_status == RunStatus::Resolved {
        run_status = RunStatus::Review;
    }

    // 6. Validate spec_version: must match code's own constant RUN_SPEC_VERSION
    if let Some(ref sv) = manifest.spec_version {
        if sv != RUN_SPEC_VERSION {
            return Err(OrchestratorError::MalformedArtifact {
                artifact: "world_manifest.json",
                detail: "unsupported spec_version in world manifest",
            });
        }
    }

    // Mode G gateway log head, history rewrite count, and adapter version resolution
    let (gw_head, gw_rewrites, gw_version) = if let Some(hist) = gateway_history {
        (
            Some(hist.gateway_log_head),
            Some(hist.history_rewrite_count),
            Some(hist.gateway_adapter_version),
        )
    } else if let Some(summary) = gateway_head {
        let head_digest: Digest =
            Digest::parse(&summary.head).map_err(|_| OrchestratorError::MalformedArtifact {
                artifact: "gateway_head.json",
                detail: "invalid digest string in gateway head",
            })?;
        (
            Some(head_digest),
            Some(summary.history_rewrite_count),
            Some(summary.adapter_version),
        )
    } else {
        (None, None, None)
    };

    let gateway_log_head = manifest.gateway_log_head.or(gw_head);
    let history_rewrite_count = manifest.history_rewrite_count.or(gw_rewrites);
    let gateway_adapter_version = manifest.gateway_adapter_version.or(gw_version);

    // 7. Assemble the complete RunRecord
    let record = RunRecord {
        task_id: manifest.task_id,
        task_class: manifest.task_class,
        seal_level: manifest.seal_level,
        agent_mode: manifest.agent_mode,
        clock,
        grader_isolation: manifest.grader_isolation,
        deployment: manifest.deployment,
        t_world: manifest.t_world,
        t_clock: manifest.t_clock,
        base_commit: manifest.base_commit,
        pkg_cutoff: manifest.pkg_cutoff,
        version_tuple: VersionTuple {
            spec_version: RUN_SPEC_VERSION.to_string(),
            world_version: manifest.world_version,
            sealcheck_version: manifest.sealcheck_version,
            grader_image_digest: manifest.grader_image_digest,
        },
        world_root: manifest.world_root,
        task_rootfs_digest: manifest.task_rootfs_digest,
        netvm_image_digest: manifest.netvm_image_digest,
        guest_kernel_digest: manifest.guest_kernel_digest,
        vm_config_digest: manifest.vm_config_digest,
        cpu_template_digest: manifest.cpu_template_digest,
        firecracker_build_digest: manifest.firecracker_build_digest,
        agent_volume_digest: manifest.agent_volume_digest,
        sealcheck_report_digest: manifest.sealcheck_report_digest,
        substrate_at_t: manifest.substrate_at_t,
        exemption_list: manifest.exemption_list,
        d5b_warning_list: manifest.d5b_warning_list,
        escape_probe_result,
        escape_probe_digest,
        world_server_log_head: manifest.world_server_log_head,
        dedupe_index_digest: manifest.dedupe_index_digest,
        request_count: manifest.request_count,
        harness_command_log_head: manifest.harness_command_log_head,
        gateway_log_head,
        history_rewrite_count,
        gateway_adapter_version,
        submitted_work_digest,
        r0_result: verdict.r0_result,
        r1_result: verdict.r1_result,
        r2_result: verdict.r2_result,
        r3_result: verdict.r3_result,
        r1_coverage: verdict.r1_coverage,
        run_status,
        date_leak_observed,
        unclean_shutdown: verdict.unclean_shutdown,
        tee_quote: manifest.tee_quote,
        boot_record: Some(boot_record),
        state_grade,
    };

    // 8. Full schema validation
    record.validate().map_err(OrchestratorError::Validation)?;
    Ok(record)
}

/// Signs an assembled `RunRecord` using any DSSE `Signer`.
pub fn sign_run_record(
    record: &RunRecord,
    signer: &dyn Signer,
) -> Result<DsseEnvelope, OrchestratorError> {
    record.validate().map_err(OrchestratorError::Validation)?;
    let statement =
        Statement::new_run_statement(record.clone()).map_err(OrchestratorError::Dsse)?;
    DsseEnvelope::sign_statement(&statement, signer).map_err(OrchestratorError::Dsse)
}

/// Signs an assembled `RunRecord` with an Ed25519 private key file read no-follow.
pub fn sign_run_record_with_key_path(
    record: &RunRecord,
    key_path: &Path,
) -> Result<DsseEnvelope, OrchestratorError> {
    let signer = Ed25519Signer::from_pkcs8_path(key_path).map_err(OrchestratorError::Key)?;
    sign_run_record(record, &signer)
}

/// Assembles a `RunRecord` from a run directory and optionally signs it.
/// Entry point for `hermetic-cli run`.
pub fn assemble_and_sign_run_record(
    run_dir: &Path,
    key_path: Option<&Path>,
) -> Result<(RunRecord, Option<DsseEnvelope>), OrchestratorError> {
    let record = assemble_run_record(run_dir)?;
    let envelope = match key_path {
        Some(path) => Some(sign_run_record_with_key_path(&record, path)?),
        None => None,
    };
    Ok((record, envelope))
}

/// Atomically writes a signed DSSE envelope to destination with mode 0600.
pub fn write_signed_run_record(
    output_path: &Path,
    envelope: &DsseEnvelope,
) -> Result<(), OrchestratorError> {
    let json_bytes = serde_json::to_vec(envelope).map_err(|e| OrchestratorError::Json {
        artifact: "output_record",
        detail: json_parse_error(e.line(), e.column()),
    })?;
    safe_atomic_write_file(output_path, &json_bytes).map_err(|e| OrchestratorError::Fs {
        artifact: "output_record",
        detail: e.to_string(),
    })
}

/// Signs an assembled `RunRecord` into a Sigstore bundle with a SigstoreSigner.
pub fn sign_run_record_sigstore(
    record: &RunRecord,
    signer: &SigstoreSigner,
) -> Result<SigstoreBundle, OrchestratorError> {
    record.validate().map_err(OrchestratorError::Validation)?;
    let statement =
        Statement::new_run_statement(record.clone()).map_err(OrchestratorError::Dsse)?;
    signer
        .sign_statement(&statement)
        .map_err(OrchestratorError::Sigstore)
}

/// Assembles a `RunRecord` from a run directory and signs it with a SigstoreSigner.
pub fn assemble_and_sign_run_record_sigstore(
    run_dir: &Path,
    signer: &SigstoreSigner,
) -> Result<(RunRecord, SigstoreBundle), OrchestratorError> {
    let record = assemble_run_record(run_dir)?;
    let bundle = sign_run_record_sigstore(&record, signer)?;
    Ok((record, bundle))
}

/// Atomically writes a Sigstore bundle to destination with mode 0600.
pub fn write_sigstore_bundle(
    output_path: &Path,
    bundle: &SigstoreBundle,
) -> Result<(), OrchestratorError> {
    let json_bytes = serde_json::to_vec(bundle).map_err(|e| OrchestratorError::Json {
        artifact: "output_bundle",
        detail: json_parse_error(e.line(), e.column()),
    })?;
    safe_atomic_write_file(output_path, &json_bytes).map_err(|e| OrchestratorError::Fs {
        artifact: "output_bundle",
        detail: e.to_string(),
    })
}
