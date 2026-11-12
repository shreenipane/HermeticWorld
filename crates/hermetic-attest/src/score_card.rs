//! Score card generation and version tuple validation (TR-ATT-3, §12.4).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::{to_canonical_json_bytes, CanonicalJsonError};
use crate::run::{
    AgentMode, ClockLevel, GraderIsolation, RunRecord, RunStatus, SealLevel, SubstrateAtT,
    TaskClass, VersionTuple,
};

pub const MAX_SCORE_CARD_RECORDS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreCardError {
    EmptyRecords,
    RecordCountExceeded {
        count: usize,
        limit: usize,
    },
    VersionTupleMismatch {
        expected: Box<VersionTuple>,
        actual: Box<VersionTuple>,
        index: usize,
    },
    SealLevelMismatch {
        expected: SealLevel,
        actual: SealLevel,
        index: usize,
    },
    ClockLevelMismatch {
        expected: ClockLevel,
        actual: ClockLevel,
        index: usize,
    },
    AgentModeMismatch {
        expected: AgentMode,
        actual: AgentMode,
        index: usize,
    },
    CanonicalJson(CanonicalJsonError),
}

impl fmt::Display for ScoreCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRecords => {
                write!(f, "Cannot generate score card from empty run records list")
            }
            Self::RecordCountExceeded { count, limit } => {
                write!(
                    f,
                    "Record count {count} exceeds maximum allowed limit {limit}"
                )
            }
            Self::VersionTupleMismatch {
                expected,
                actual,
                index,
            } => {
                write!(
                    f,
                    "Refusing to mix records with different version tuples at index {index}: expected {expected:?}, got {actual:?}"
                )
            }
            Self::SealLevelMismatch {
                expected,
                actual,
                index,
            } => {
                write!(
                    f,
                    "Refusing to mix records with different seal levels at index {index}: expected {expected:?}, got {actual:?}"
                )
            }
            Self::ClockLevelMismatch {
                expected,
                actual,
                index,
            } => {
                write!(
                    f,
                    "Refusing to mix records with different clock levels at index {index}: expected {expected:?}, got {actual:?}"
                )
            }
            Self::AgentModeMismatch {
                expected,
                actual,
                index,
            } => {
                write!(
                    f,
                    "Refusing to mix records with different agent modes at index {index}: expected {expected:?}, got {actual:?}"
                )
            }
            Self::CanonicalJson(e) => write!(f, "Canonical JSON encoding error: {e}"),
        }
    }
}

impl std::error::Error for ScoreCardError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedTask {
    pub task_id: String,
    pub detector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairedTask {
    pub task_id: String,
    pub detector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Score card reporting published evaluation numbers (§12.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreCard {
    pub benchmark: String,
    pub benchmark_version: String,
    pub version_tuple: VersionTuple,
    pub seal_level: SealLevel,
    pub clock: ClockLevel,
    pub agent_mode: AgentMode,
    pub total_runs: u64,
    pub status_counts: BTreeMap<String, u64>,
    pub task_class_counts: BTreeMap<String, u64>,
    pub grader_isolation_counts: BTreeMap<String, u64>,
    pub substrate_at_t_spread: BTreeMap<String, u64>,
    pub excluded_tasks: Vec<ExcludedTask>,
    pub repaired_tasks: Vec<RepairedTask>,
}

impl ScoreCard {
    /// Return deterministic canonical JSON string representation.
    pub fn to_canonical_json(&self) -> Result<String, ScoreCardError> {
        let bytes = to_canonical_json_bytes(self).map_err(ScoreCardError::CanonicalJson)?;
        String::from_utf8(bytes).map_err(|e| {
            ScoreCardError::CanonicalJson(CanonicalJsonError::JsonSerialization(e.to_string()))
        })
    }
}

/// Generate a score card from a list of validated run records (§12.4, TR-ATT-3).
///
/// Refuses to mix records whose version tuple, seal level, clock level, or agent mode differs.
pub fn generate_score_card(
    benchmark: &str,
    benchmark_version: &str,
    records: &[RunRecord],
    excluded_tasks: &[ExcludedTask],
    repaired_tasks: &[RepairedTask],
) -> Result<ScoreCard, ScoreCardError> {
    if records.is_empty() {
        return Err(ScoreCardError::EmptyRecords);
    }
    if records.len() > MAX_SCORE_CARD_RECORDS {
        return Err(ScoreCardError::RecordCountExceeded {
            count: records.len(),
            limit: MAX_SCORE_CARD_RECORDS,
        });
    }

    let first = &records[0];
    let version_tuple = first.version_tuple.clone();
    let seal_level = first.seal_level;
    let clock = first.clock;
    let agent_mode = first.agent_mode;

    // Initialize counts with all variants present
    let mut status_counts = BTreeMap::new();
    status_counts.insert("resolved".to_string(), 0u64);
    status_counts.insert("unresolved".to_string(), 0u64);
    status_counts.insert("tampered".to_string(), 0u64);
    status_counts.insert("limit_exceeded".to_string(), 0u64);
    status_counts.insert("review".to_string(), 0u64);
    status_counts.insert("infra_error".to_string(), 0u64);
    status_counts.insert("gate_blocked".to_string(), 0u64);

    let mut task_class_counts = BTreeMap::new();
    task_class_counts.insert("patch".to_string(), 0u64);
    task_class_counts.insert("artifact".to_string(), 0u64);
    task_class_counts.insert("state".to_string(), 0u64);

    let mut grader_isolation_counts = BTreeMap::new();
    grader_isolation_counts.insert("clean".to_string(), 0u64);
    grader_isolation_counts.insert("shared".to_string(), 0u64);

    let mut substrate_at_t_spread = BTreeMap::new();
    substrate_at_t_spread.insert("full".to_string(), 0u64);
    substrate_at_t_spread.insert("partial".to_string(), 0u64);
    substrate_at_t_spread.insert("none".to_string(), 0u64);

    for (idx, record) in records.iter().enumerate() {
        // Enforce version tuple identity
        if record.version_tuple != version_tuple {
            return Err(ScoreCardError::VersionTupleMismatch {
                expected: Box::new(version_tuple),
                actual: Box::new(record.version_tuple.clone()),
                index: idx,
            });
        }
        // Enforce seal level identity
        if record.seal_level != seal_level {
            return Err(ScoreCardError::SealLevelMismatch {
                expected: seal_level,
                actual: record.seal_level,
                index: idx,
            });
        }
        // Enforce clock level identity
        if record.clock != clock {
            return Err(ScoreCardError::ClockLevelMismatch {
                expected: clock,
                actual: record.clock,
                index: idx,
            });
        }
        // Enforce agent mode identity
        if record.agent_mode != agent_mode {
            return Err(ScoreCardError::AgentModeMismatch {
                expected: agent_mode,
                actual: record.agent_mode,
                index: idx,
            });
        }

        // Aggregate status count
        let status_key = match record.run_status {
            RunStatus::Resolved => "resolved",
            RunStatus::Unresolved => "unresolved",
            RunStatus::Tampered => "tampered",
            RunStatus::LimitExceeded => "limit_exceeded",
            RunStatus::Review => "review",
            RunStatus::InfraError => "infra_error",
            RunStatus::GateBlocked => "gate_blocked",
        };
        *status_counts.entry(status_key.to_string()).or_default() += 1;

        // Aggregate task class count
        let class_key = match record.task_class {
            TaskClass::Patch => "patch",
            TaskClass::Artifact => "artifact",
            TaskClass::State => "state",
        };
        *task_class_counts.entry(class_key.to_string()).or_default() += 1;

        // Aggregate grader isolation count
        let isolation_key = match record.grader_isolation {
            GraderIsolation::Clean => "clean",
            GraderIsolation::Shared => "shared",
        };
        *grader_isolation_counts
            .entry(isolation_key.to_string())
            .or_default() += 1;

        // Aggregate substrate_at_t
        let substrate_key = match record.substrate_at_t {
            SubstrateAtT::Full => "full",
            SubstrateAtT::Partial => "partial",
            SubstrateAtT::None => "none",
        };
        *substrate_at_t_spread
            .entry(substrate_key.to_string())
            .or_default() += 1;
    }

    // Sort and deduplicate excluded and repaired tasks
    let mut sorted_excluded = excluded_tasks.to_vec();
    sorted_excluded.sort();
    sorted_excluded.dedup();

    let mut sorted_repaired = repaired_tasks.to_vec();
    sorted_repaired.sort();
    sorted_repaired.dedup();

    Ok(ScoreCard {
        benchmark: benchmark.to_string(),
        benchmark_version: benchmark_version.to_string(),
        version_tuple,
        seal_level,
        clock,
        agent_mode,
        total_runs: records.len() as u64,
        status_counts,
        task_class_counts,
        grader_isolation_counts,
        substrate_at_t_spread,
        excluded_tasks: sorted_excluded,
        repaired_tasks: sorted_repaired,
    })
}
