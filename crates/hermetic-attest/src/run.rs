//! hermetic-run/v1 statement definition and validation (TR-ATT-1, §12.1).

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::digest::Digest;

pub const MAX_RUN_RECORD_SIZE: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl fmt::Display for RunValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
                value,
                reason,
            } => {
                write!(
                    f,
                    "Timestamp field '{field}' value '{value}' is invalid: {reason}"
                )
            }
            Self::ClockBeforeWorld { t_clock, t_world } => {
                write!(f, "t_clock ({t_clock}) cannot precede t_world ({t_world})")
            }
            Self::PkgCutoffBeforeWorld {
                pkg_cutoff,
                t_world,
            } => {
                write!(
                    f,
                    "pkg_cutoff ({pkg_cutoff}) cannot precede t_world ({t_world})"
                )
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
        }
    }
}

impl std::error::Error for RunValidationError {}

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
            serde_json::from_str(s).map_err(|e| RunValidationError::JsonParse(e.to_string()))?;
        record.validate()?;
        Ok(record)
    }

    /// Full validation of all statement constraints.
    pub fn validate(&self) -> Result<(), RunValidationError> {
        // 1. Task ID
        if self.task_id.trim().is_empty() {
            return Err(RunValidationError::EmptyTaskId);
        }
        if self.task_id.len() > 256 {
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
        if !self.base_commit.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RunValidationError::InvalidBaseCommit(
                "base_commit must be hexadecimal".into(),
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
                if let Some(ref warnings) = self.d5b_warning_list {
                    if !warnings.is_empty() {
                        return Err(RunValidationError::StrictCarriesD5bWarning);
                    }
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

        Ok(())
    }
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

    let (date_part, time_and_tz) = s
        .split_once(['T', 't'])
        .ok_or_else(|| err("missing 'T' separator"))?;
    let date_parts: Vec<&str> = date_part.split('-').collect();
    if date_parts.len() != 3 {
        return Err(err("date must have format YYYY-MM-DD"));
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
    let (time_part, tz_part) = if let Some(stripped) = time_and_tz.strip_suffix(['Z', 'z']) {
        (stripped, "Z")
    } else if let Some((t, tz)) = time_and_tz.split_once('+') {
        (t, tz)
    } else if let Some((t, tz)) = time_and_tz.split_once('-') {
        (t, tz)
    } else {
        return Err(err("missing UTC timezone designator"));
    };

    if tz_part != "Z" && tz_part != "00:00" {
        return Err(err("timestamp must be in UTC timezone (Z or +00:00)"));
    }

    let (hms_part, frac_part) = if let Some((hms, frac)) = time_part.split_once('.') {
        (hms, Some(frac))
    } else {
        (time_part, None)
    };

    let hms_parts: Vec<&str> = hms_part.split(':').collect();
    if hms_parts.len() != 3 {
        return Err(err("time must have format HH:MM:SS"));
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
