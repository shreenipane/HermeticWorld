//! Dispositions for tasks that fail the sealcheck gate (§5.5, TRD.md).
//!
//! A task that fails the leak gate must never be dropped silently, because that changes
//! the score's denominator (§5.5). Each failing task gets a disposition:
//! - `clean`: passed the gate without any gate findings.
//! - `repaired`: sealer removed the leak without changing the task, and re-scan is clean.
//! - `excluded`: the leak is the task ("the issue text is the fix"), or a non-D0 detector has
//!   no automatic removal, or re-scan remained dirty after redaction.

use serde::{Deserialize, Serialize};

/// Maximum fraction of problem statement characters that may be redacted before
/// the problem statement is considered destroyed. If redacting the leak removes
/// more than 50% of the statement, the leak *is* the task ("the issue text is the fix", §5.5).
pub const MAX_REDACTION_FRACTION: f64 = 0.50;

/// Minimum number of non-whitespace characters that must remain in the problem
/// statement after redaction. If fewer characters remain, the statement is considered destroyed.
pub const MIN_REMAINING_CHARS: usize = 20;

/// Record of a redacted span in the problem statement.
///
/// Records span byte offsets and cryptographic hash, NEVER the leaked text (§5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedSpan {
    pub start: usize,
    pub end: usize,
    pub sha256: String,
    pub hash: String,
}

/// A single entry in the per-run `dispositions.json` (§5.5, T1.14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDispositionRecord {
    pub task_id: String,
    pub disposition: String,
    pub detectors: Vec<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_version: Option<String>,
}

/// Summary counts of dispositions and detectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DispositionsSummary {
    pub total_tasks: usize,
    pub clean: usize,
    pub repaired: usize,
    pub excluded: usize,
    pub detectors: std::collections::BTreeMap<String, usize>,
}

/// Redact spans from a problem statement string.
///
/// Spans must be non-overlapping and within statement boundaries.
/// Returns `(redacted_string, redacted_spans_metadata)`.
pub fn redact_statement(
    statement: &str,
    mut spans: Vec<(usize, usize)>,
) -> (String, Vec<RedactedSpan>) {
    spans.sort_by_key(|&(s, _)| s);

    let mut metadata = Vec::new();
    for &(s, e) in &spans {
        if s <= statement.len() && e <= statement.len() && s <= e {
            let slice = &statement[s..e];
            let digest = hex::encode(blake3::hash(slice.as_bytes()).as_bytes());
            metadata.push(RedactedSpan {
                start: s,
                end: e,
                sha256: digest.clone(),
                hash: format!("blake3:{digest}"),
            });
        }
    }

    // Replace in reverse order so earlier offsets remain valid
    let mut out = statement.to_string();
    for &(s, e) in spans.iter().rev() {
        if s <= out.len() && e <= out.len() && s <= e {
            out.replace_range(s..e, "[REDACTED]");
        }
    }

    (out, metadata)
}
