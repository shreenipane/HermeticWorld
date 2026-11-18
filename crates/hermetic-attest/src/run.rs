//! hermetic-run/v1 statement definition and validation (TR-ATT-1, §12.1).

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::canonical::{bounded_json_bytes, json_error};
use crate::digest::Digest;

pub const MAX_RUN_RECORD_SIZE: usize = 1024 * 1024; // 1 MiB
pub const MAX_RECORD_TEXT_BYTES: usize = 256;
pub const MAX_SUBSTRATE_ITEMS: usize = 1024;
pub const MAX_TEE_QUOTE_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub enum RunValidationError {
    SizeCapExceeded {
        size: usize,
        limit: usize,
    },
    JsonParse(String),
    EmptyTaskId,
    TaskIdTooLong(usize),
    InvalidTaskId(String),
    EmptyBaseCommit,
    InvalidBaseCommit(String),
    InvalidTimestamp {
        field: String,
        value: String,
        reason: String,
    },
    ClockBeforeWorld {
        t_clock: String,
        t_world: String,
    },
    PkgCutoffBeforeWorld {
        pkg_cutoff: String,
        t_world: String,
    },
    StrictCarriesD5bWarning,
    UnsortedOrDuplicateExemptions,
    UnsortedOrDuplicateD5bWarnings,
    ModeHHasGatewayFields,
    ModeHMissingHarnessLog,
    ModeGHasHarnessFields,
    ModeGMissingGatewayFields,
    InvalidR1Coverage(u32),
    TaskClassIsolationMismatch {
        task_class: TaskClass,
        grader_isolation: GraderIsolation,
    },
    InvalidField(&'static str),
    WorldVersionMismatch,
    MissingBootRecord,
    BootRecordVersionMismatch,
    InvalidBootRecord(&'static str),
}

impl fmt::Display for RunValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "Invalid or oversized {field}"),
            Self::WorldVersionMismatch => write!(f, "world_version must equal world_root"),
            Self::SizeCapExceeded { size, limit } => {
                write!(f, "Run record size {size} bytes exceeds limit {limit}")
            }
            Self::JsonParse(msg) => write!(f, "Run record JSON parsing failed: {msg}"),
            Self::EmptyTaskId => write!(f, "task_id must not be empty"),
            Self::TaskIdTooLong(len) => write!(f, "task_id length {len} exceeds 256 bytes"),
            Self::InvalidTaskId(msg) => write!(f, "task_id is invalid: {msg}"),
            Self::EmptyBaseCommit => write!(f, "base_commit must not be empty"),
            Self::InvalidBaseCommit(msg) => write!(f, "base_commit is invalid: {msg}"),
            Self::InvalidTimestamp {
                field,
                value: _,
                reason: _,
            } => {
                write!(f, "Timestamp field '{field}' is invalid")
            }
            Self::ClockBeforeWorld { .. } => {
                write!(f, "t_clock cannot precede t_world")
            }
            Self::PkgCutoffBeforeWorld { .. } => {
                write!(f, "pkg_cutoff cannot precede t_world")
            }
            Self::StrictCarriesD5bWarning => {
                write!(f, "Seal level 'strict' must not carry a D5b warning list")
            }
            Self::UnsortedOrDuplicateExemptions => {
                write!(f, "exemption_list must be strictly sorted and deduplicated")
            }
            Self::UnsortedOrDuplicateD5bWarnings => {
                write!(
                    f,
                    "d5b_warning_list must be strictly sorted and deduplicated"
                )
            }
            Self::ModeHHasGatewayFields => {
                write!(
                    f,
                    "Mode H must not carry gateway log, rewrite count, or adapter version"
                )
            }
            Self::ModeHMissingHarnessLog => {
                write!(f, "Mode H must carry harness_command_log_head")
            }
            Self::ModeGHasHarnessFields => {
                write!(f, "Mode G must not carry harness_command_log_head")
            }
            Self::ModeGMissingGatewayFields => {
                write!(f, "Mode G must carry gateway_log_head, history_rewrite_count, and gateway_adapter_version")
            }
            Self::InvalidR1Coverage(cov) => {
                write!(
                    f,
                    "r1_coverage must be bounded integer per-mille (0..=1000), got {cov}"
                )
            }
            Self::TaskClassIsolationMismatch {
                task_class,
                grader_isolation,
            } => {
                write!(f, "Mismatch between task_class '{task_class:?}' and grader_isolation '{grader_isolation:?}'")
            }
            Self::MissingBootRecord => {
                write!(f, "boot_record is required for spec_version >= v1.1")
            }
            Self::BootRecordVersionMismatch => {
                write!(f, "boot_record must not be present in spec_version v1.0")
            }
            Self::InvalidBootRecord(msg) => write!(f, "Invalid boot_record: {msg}"),
        }
    }
}

impl std::error::Error for RunValidationError {}
redacted_debug!(RunValidationError);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    Patch,
    Artifact,
    State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealLevel {
    Strict,
    RepoOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentMode {
    H,
    G,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockLevel {
    Hidden,
    Faked,
    Real,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraderIsolation {
    Clean,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    Split,
    SingleHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateAtT {
    Full,
    Partial,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeResult {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GradingRunResult {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Resolved,
    Unresolved,
    Tampered,
    LimitExceeded,
    Review,
    InfraError,
    GateBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeePlatform {
    SevSnp,
    Tdx,
    AwsNitro,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeQuote {
    pub platform: TeePlatform,
    pub quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBootRecord {
    pub boot_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd_digest: Option<Digest>,
}

pub type BootRecord = HostBootRecord;

impl HostBootRecord {
    pub fn sealed_disk() -> Self {
        Self {
            boot_path: "sealed_disk".to_string(),
            initrd_digest: None,
        }
    }

    pub fn trusted_initramfs(initrd_digest: Digest) -> Self {
        Self {
            boot_path: "trusted_initramfs".to_string(),
            initrd_digest: Some(initrd_digest),
        }
    }

    pub fn live_snapshot() -> Self {
        Self {
            boot_path: "live_snapshot".to_string(),
            initrd_digest: None,
        }
    }

    pub fn validate(&self) -> Result<(), RunValidationError> {
        if !valid_record_text(&self.boot_path) {
            return Err(RunValidationError::InvalidBootRecord("invalid boot_path"));
        }
        match self.boot_path.as_str() {
            "sealed_disk" => {
                if self.initrd_digest.is_some() {
                    return Err(RunValidationError::InvalidBootRecord(
                        "sealed_disk must not carry initrd_digest",
                    ));
                }
            }
            "trusted_initramfs" => {
                if self.initrd_digest.is_none() {
                    return Err(RunValidationError::InvalidBootRecord(
                        "trusted_initramfs requires initrd_digest",
                    ));
                }
            }
            "live_snapshot" => {
                if self.initrd_digest.is_some() {
                    return Err(RunValidationError::InvalidBootRecord(
                        "live_snapshot must not carry initrd_digest",
                    ));
                }
            }
            _ => {
                return Err(RunValidationError::InvalidBootRecord("unknown boot_path"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateGradingPath {
    Live,
    Reboot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigestSize {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateGradeRecord {
    pub schema: String,
    pub grader_isolation: GraderIsolation,
    pub path: StateGradingPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    pub tests: ArtifactDigestSize,
    pub result: ArtifactDigestSize,
    pub snapshot_sha256: String,
    pub run_sha256: String,
}

impl StateGradeRecord {
    pub fn validate(&self) -> Result<(), RunValidationError> {
        if self.schema != "hermetic-state-grade/v1" {
            return Err(RunValidationError::InvalidField("state_grade.schema"));
        }
        if self.grader_isolation != GraderIsolation::Shared {
            return Err(RunValidationError::InvalidField(
                "state_grade.grader_isolation",
            ));
        }
        match self.path {
            StateGradingPath::Live => {
                if self.fallback_reason.is_some() {
                    return Err(RunValidationError::InvalidField(
                        "state_grade.fallback_reason",
                    ));
                }
            }
            StateGradingPath::Reboot => {
                let Some(ref reason) = self.fallback_reason else {
                    return Err(RunValidationError::InvalidField(
                        "state_grade.fallback_reason",
                    ));
                };
                if reason != "execd_unresponsive" && reason != "no_live_state" {
                    return Err(RunValidationError::InvalidField(
                        "state_grade.fallback_reason",
                    ));
                }
            }
        }
        if self.snapshot_sha256.len() != 64
            || !self
                .snapshot_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(RunValidationError::InvalidField(
                "state_grade.snapshot_sha256",
            ));
        }
        if self.run_sha256.len() != 64
            || !self
                .run_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(RunValidationError::InvalidField("state_grade.run_sha256"));
        }
        if self.tests.sha256.len() != 64
            || !self
                .tests
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.tests.size == 0
            || self.tests.size > 64 * 1024 * 1024 * 1024
        {
            return Err(RunValidationError::InvalidField("state_grade.tests"));
        }
        if self.result.sha256.len() != 64
            || !self
                .result
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.result.size == 0
            || self.result.size > 1024 * 1024
        {
            return Err(RunValidationError::InvalidField("state_grade.result"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionTuple {
    pub spec_version: String,
    pub world_version: Digest,
    pub sealcheck_version: String,
    pub grader_image_digest: Digest,
}

/// The hermetic-run/v1 statement holding only deterministic or digest values (§12.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    // Identity & Config
    pub task_id: String,
    pub task_class: TaskClass,
    pub seal_level: SealLevel,
    pub agent_mode: AgentMode,
    pub clock: ClockLevel,
    pub grader_isolation: GraderIsolation,
    pub deployment: Deployment,

    // Cutoffs
    pub t_world: String,
    pub t_clock: String,
    pub base_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkg_cutoff: Option<String>,

    // Version tuple
    pub version_tuple: VersionTuple,

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

    // Escape probe
    pub escape_probe_result: ProbeResult,
    pub escape_probe_digest: Digest,

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

    // Grading results
    pub submitted_work_digest: Digest,
    pub r0_result: GradingRunResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r1_result: Option<GradingRunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r2_result: Option<GradingRunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r3_result: Option<GradingRunResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r1_coverage: Option<u32>,
    pub run_status: RunStatus,

    // Observables
    pub date_leak_observed: bool,
    pub unclean_shutdown: bool,

    // Optional TEE quote
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_quote: Option<TeeQuote>,

    // Optional Host Boot Record (versioned field: required for spec_version >= v1.1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_record: Option<HostBootRecord>,

    // Optional State Grade Record (§11.4: State tasks)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_grade: Option<StateGradeRecord>,
}

impl RunRecord {
    /// Parse from JSON string with strict validation and size capping.
    pub fn from_json_str(s: &str) -> Result<Self, RunValidationError> {
        if s.len() > MAX_RUN_RECORD_SIZE {
            return Err(RunValidationError::SizeCapExceeded {
                size: s.len(),
                limit: MAX_RUN_RECORD_SIZE,
            });
        }
        let record: Self =
            serde_json::from_str(s).map_err(|e| RunValidationError::JsonParse(json_error(e)))?;
        record.validate()?;
        Ok(record)
    }

    /// Full validation of all statement constraints.
    pub fn validate(&self) -> Result<(), RunValidationError> {
        // D12: an observed (or unscanned) date leak lowers the clock below `hidden`.
        if self.clock == ClockLevel::Hidden && self.date_leak_observed {
            return Err(RunValidationError::InvalidField("clock"));
        }
        for (field, text) in [
            ("spec_version", self.version_tuple.spec_version.as_str()),
            (
                "sealcheck_version",
                self.version_tuple.sealcheck_version.as_str(),
            ),
        ] {
            if !valid_record_text(text) {
                return Err(RunValidationError::InvalidField(field));
            }
        }
        if let Some(version) = &self.gateway_adapter_version {
            if !valid_record_text(version) {
                return Err(RunValidationError::InvalidField("gateway_adapter_version"));
            }
        }
        for (field, list) in [
            ("exemption_list", Some(&self.exemption_list)),
            ("d5b_warning_list", self.d5b_warning_list.as_ref()),
        ] {
            if let Some(list) = list {
                if list.len() > MAX_SUBSTRATE_ITEMS || list.iter().any(|s| !valid_record_text(s)) {
                    return Err(RunValidationError::InvalidField(field));
                }
            }
        }
        if self
            .tee_quote
            .as_ref()
            .is_some_and(|q| q.quote.is_empty() || q.quote.len() > MAX_TEE_QUOTE_BYTES)
        {
            return Err(RunValidationError::InvalidField("tee_quote"));
        }
        bounded_json_bytes(self, MAX_RUN_RECORD_SIZE)
            .map_err(|_| RunValidationError::InvalidField("run record size"))?;
        if self.version_tuple.world_version != self.world_root {
            return Err(RunValidationError::WorldVersionMismatch);
        }
        // 1. Task ID
        if self.task_id.trim().is_empty() {
            return Err(RunValidationError::EmptyTaskId);
        }
        if self.task_id.len() > MAX_RECORD_TEXT_BYTES {
            return Err(RunValidationError::TaskIdTooLong(self.task_id.len()));
        }
        if self.task_id.chars().any(|c| c.is_control()) {
            return Err(RunValidationError::InvalidTaskId(
                "task_id contains control characters".into(),
            ));
        }

        // 2. Base commit
        if self.base_commit.trim().is_empty() {
            return Err(RunValidationError::EmptyBaseCommit);
        }
        if !matches!(self.base_commit.len(), 40 | 64)
            || !self
                .base_commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(RunValidationError::InvalidBaseCommit(
                "base_commit must be a full lowercase Git object ID".into(),
            ));
        }

        // 3. Timestamps validation (RFC 3339 UTC)
        let t_world_dt = parse_rfc3339_utc("t_world", &self.t_world)?;
        let t_clock_dt = parse_rfc3339_utc("t_clock", &self.t_clock)?;
        if t_clock_dt < t_world_dt {
            return Err(RunValidationError::ClockBeforeWorld {
                t_clock: self.t_clock.clone(),
                t_world: self.t_world.clone(),
            });
        }

        if let Some(ref pkg_cut) = self.pkg_cutoff {
            let pkg_cut_dt = parse_rfc3339_utc("pkg_cutoff", pkg_cut)?;
            if pkg_cut_dt < t_world_dt {
                return Err(RunValidationError::PkgCutoffBeforeWorld {
                    pkg_cutoff: pkg_cut.clone(),
                    t_world: self.t_world.clone(),
                });
            }
        }

        // 4. Substrate lists: sorted and strictly deduplicated
        if !is_strictly_sorted_and_unique(&self.exemption_list) {
            return Err(RunValidationError::UnsortedOrDuplicateExemptions);
        }

        // Strict seal level must not carry D5b warnings
        match self.seal_level {
            SealLevel::Strict => {
                if self.d5b_warning_list.is_some() {
                    return Err(RunValidationError::StrictCarriesD5bWarning);
                }
            }
            SealLevel::RepoOnly => {
                if let Some(ref warnings) = self.d5b_warning_list {
                    if !is_strictly_sorted_and_unique(warnings) {
                        return Err(RunValidationError::UnsortedOrDuplicateD5bWarnings);
                    }
                }
            }
        }

        // 5. AgentMode constraints: Mode H vs Mode G
        match self.agent_mode {
            AgentMode::H => {
                if self.harness_command_log_head.is_none() {
                    return Err(RunValidationError::ModeHMissingHarnessLog);
                }
                if self.gateway_log_head.is_some()
                    || self.history_rewrite_count.is_some()
                    || self.gateway_adapter_version.is_some()
                {
                    return Err(RunValidationError::ModeHHasGatewayFields);
                }
            }
            AgentMode::G => {
                if self.harness_command_log_head.is_some() {
                    return Err(RunValidationError::ModeGHasHarnessFields);
                }
                if self.gateway_log_head.is_none()
                    || self.history_rewrite_count.is_none()
                    || self.gateway_adapter_version.is_none()
                {
                    return Err(RunValidationError::ModeGMissingGatewayFields);
                }
            }
        }

        // 6. R1 coverage (per-mille: 0..=1000)
        if let Some(cov) = self.r1_coverage {
            if cov > 1000 {
                return Err(RunValidationError::InvalidR1Coverage(cov));
            }
        }

        if self.run_status == RunStatus::Resolved && self.r0_result != GradingRunResult::Passed {
            return Err(RunValidationError::InvalidField("run_status"));
        }

        // 7. Task class and grader isolation consistency (§1.4)
        match self.task_class {
            TaskClass::Patch | TaskClass::Artifact => {
                if self.grader_isolation != GraderIsolation::Clean {
                    return Err(RunValidationError::TaskClassIsolationMismatch {
                        task_class: self.task_class,
                        grader_isolation: self.grader_isolation,
                    });
                }
            }
            TaskClass::State => {
                if self.grader_isolation != GraderIsolation::Shared {
                    return Err(RunValidationError::TaskClassIsolationMismatch {
                        task_class: self.task_class,
                        grader_isolation: self.grader_isolation,
                    });
                }
            }
        }

        // 8. Boot record version gate
        match self.version_tuple.spec_version.as_str() {
            "v1.0" => {
                if self.boot_record.is_some() {
                    return Err(RunValidationError::BootRecordVersionMismatch);
                }
            }
            _ => {
                let Some(ref boot) = self.boot_record else {
                    return Err(RunValidationError::MissingBootRecord);
                };
                boot.validate()?;
            }
        }

        if let Some(ref boot) = self.boot_record {
            if boot.boot_path == "live_snapshot" && self.state_grade.is_none() {
                return Err(RunValidationError::InvalidField(
                    "live_snapshot boot requires state_grade",
                ));
            }
        }

        if let Some(ref sg) = self.state_grade {
            sg.validate()?;
            if self.task_class != TaskClass::State {
                return Err(RunValidationError::InvalidField(
                    "state_grade on non-state task",
                ));
            }
            if let Some(ref boot) = self.boot_record {
                match (sg.path, boot.boot_path.as_str()) {
                    (StateGradingPath::Live, "live_snapshot") => {}
                    (StateGradingPath::Reboot, "trusted_initramfs") => {}
                    _ => {
                        return Err(RunValidationError::InvalidField(
                            "state_grade path does not match boot path",
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

pub(crate) fn valid_record_text(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= MAX_RECORD_TEXT_BYTES
        && !text.chars().any(char::is_control)
}

fn is_strictly_sorted_and_unique(list: &[String]) -> bool {
    list.windows(2).all(|w| w[0] < w[1])
}

/// Parsed UTC timestamp for chronological comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedUtcDateTime {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    nanos: u32,
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn parse_rfc3339_utc(field: &str, s: &str) -> Result<ParsedUtcDateTime, RunValidationError> {
    let err = |reason: &str| RunValidationError::InvalidTimestamp {
        field: field.to_string(),
        value: s.to_string(),
        reason: reason.to_string(),
    };

    // Bound splitting and reject numeric parser extensions such as '+1' or short fields.
    if s.len() > 35 || !s.is_ascii() {
        return Err(err("invalid RFC 3339 timestamp"));
    }

    let (date_part, time_and_tz) = s
        .split_once(['T', 't'])
        .ok_or_else(|| err("missing 'T' separator"))?;
    let date_parts: Vec<&str> = date_part.split('-').collect();
    if date_parts.len() != 3 {
        return Err(err("date must have format YYYY-MM-DD"));
    }
    if !date_parts
        .iter()
        .zip([4, 2, 2])
        .all(|(part, len)| part.len() == len && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(err("invalid date field width"));
    }
    let year: i32 = date_parts[0].parse().map_err(|_| err("invalid year"))?;
    let month: u32 = date_parts[1].parse().map_err(|_| err("invalid month"))?;
    let day: u32 = date_parts[2].parse().map_err(|_| err("invalid day"))?;

    if !(1..=12).contains(&month) {
        return Err(err("month must be 1..=12"));
    }
    let max_days = days_in_month(year, month);
    if day < 1 || day > max_days {
        return Err(err("day out of range for month"));
    }

    // Time & timezone
    let time_part = if let Some(stripped) = time_and_tz.strip_suffix(['Z', 'z']) {
        stripped
    } else if let Some(stripped) = time_and_tz.strip_suffix("+00:00") {
        stripped
    } else {
        return Err(err("missing UTC timezone designator"));
    };

    let (hms_part, frac_part) = if let Some((hms, frac)) = time_part.split_once('.') {
        (hms, Some(frac))
    } else {
        (time_part, None)
    };

    let hms_parts: Vec<&str> = hms_part.split(':').collect();
    if hms_parts.len() != 3 {
        return Err(err("time must have format HH:MM:SS"));
    }
    if !hms_parts
        .iter()
        .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(err("invalid time field width"));
    }
    let hour: u32 = hms_parts[0].parse().map_err(|_| err("invalid hour"))?;
    let min: u32 = hms_parts[1].parse().map_err(|_| err("invalid minute"))?;
    let sec: u32 = hms_parts[2].parse().map_err(|_| err("invalid second"))?;

    if hour > 23 || min > 59 || sec > 60 {
        return Err(err("time component out of valid range"));
    }

    let mut nanos = 0u32;
    if let Some(frac) = frac_part {
        if frac.is_empty() || frac.len() > 9 || !frac.chars().all(|c| c.is_ascii_digit()) {
            return Err(err("invalid fractional seconds"));
        }
        let parsed_frac: u32 = frac
            .parse()
            .map_err(|_| err("invalid fractional seconds"))?;
        let scale = 9 - frac.len() as u32;
        nanos = parsed_frac * 10u32.pow(scale);
    }

    Ok(ParsedUtcDateTime {
        year,
        month,
        day,
        hour,
        min,
        sec,
        nanos,
    })
}
