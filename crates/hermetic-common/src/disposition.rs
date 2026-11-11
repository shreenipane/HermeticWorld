//! Dispositions for tasks that fail the sealcheck gate (§5.5, TRD.md).
//!
//! A task that fails the leak gate must never be dropped silently, because that changes
//! the score's denominator (§5.5). Each failing task gets a disposition:
//! - `clean`: passed the gate without any gate findings.
//! - `repaired`: sealer removed the leak without changing the task, and re-scan is clean.
//! - `excluded`: the leak is the task ("the issue text is the fix"), or a non-D0 detector has
//!   no automatic removal, or re-scan remained dirty after redaction.
//!
//! # Offsets and Hash Convention
//! Offsets are byte offsets into the UTF-8 encoding of the statement.
//! Hashes are lowercase hexadecimal SHA-256 digests over the raw UTF-8 bytes of the redacted span,
//! formatted as `sha256:<hex>` in `hash` and `<hex>` in `sha256`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::sha256_hex;

/// Maximum fraction of problem statement UTF-8 bytes that may be redacted before
/// the problem statement is considered destroyed. If redacting the leak removes
/// strictly more than 50% (`fraction > MAX_REDACTION_FRACTION`), the leak *is* the task
/// ("the issue text is the fix", §5.5). An exact 50% redaction (`fraction <= 0.50`) is eligible for repair.
pub const MAX_REDACTION_FRACTION: f64 = 0.50;

/// Minimum number of non-whitespace characters that must remain in the problem
/// statement after redaction. If strictly fewer characters remain (`chars < MIN_REMAINING_CHARS`),
/// the statement is considered destroyed. Exactly 20 remaining characters (`chars >= 20`) is eligible for repair.
pub const MIN_REMAINING_CHARS: usize = 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DispositionError {
    #[error("Span offset {0}..{1} out of bounds for statement of length {2}")]
    OutOfBounds(usize, usize, usize),
    #[error("Span offset {0} is not at a UTF-8 character boundary in statement")]
    InvalidCharBoundary(usize),
}

/// Record of a redacted span in the problem statement.
///
/// Records span byte offsets (UTF-8) and SHA-256 hash, NEVER the leaked text (§5.5).
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

/// Validate, sort, and merge overlapping or adjacent byte spans.
///
/// Returns sorted, non-overlapping, non-adjacent spans.
/// Returns an error if any span is out of bounds or not on a UTF-8 character boundary.
pub fn validate_and_merge_spans(
    statement: &str,
    mut spans: Vec<(usize, usize)>,
) -> Result<Vec<(usize, usize)>, DispositionError> {
    for &(s, e) in &spans {
        if s > e || e > statement.len() {
            return Err(DispositionError::OutOfBounds(s, e, statement.len()));
        }
        if !statement.is_char_boundary(s) {
            return Err(DispositionError::InvalidCharBoundary(s));
        }
        if !statement.is_char_boundary(e) {
            return Err(DispositionError::InvalidCharBoundary(e));
        }
    }

    if spans.is_empty() {
        return Ok(Vec::new());
    }

    // Sort by start offset, then by end offset
    spans.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    let (mut cur_s, mut cur_e) = spans[0];

    for (s, e) in spans.into_iter().skip(1) {
        if s <= cur_e {
            // Overlapping, nested, or adjacent: merge
            cur_e = cur_e.max(e);
        } else {
            merged.push((cur_s, cur_e));
            cur_s = s;
            cur_e = e;
        }
    }
    merged.push((cur_s, cur_e));

    Ok(merged)
}

/// Evaluate whether redacting `merged_spans` from `statement` excludes the task.
///
/// Returns `true` (excluded) if `fraction > MAX_REDACTION_FRACTION` or
/// `remaining_non_whitespace_chars < MIN_REMAINING_CHARS`.
pub fn should_exclude_d0(statement: &str, merged_spans: &[(usize, usize)]) -> bool {
    let stmt_bytes = statement.len();
    if stmt_bytes == 0 {
        return true;
    }

    let redacted_bytes: usize = merged_spans.iter().map(|&(s, e)| e - s).sum();
    let fraction = redacted_bytes as f64 / stmt_bytes as f64;
    if fraction > MAX_REDACTION_FRACTION {
        return true;
    }

    // Count non-whitespace chars outside the spans
    let mut non_ws_count = 0;
    let mut last_idx = 0;
    for &(s, e) in merged_spans {
        if s > last_idx {
            non_ws_count += statement[last_idx..s]
                .chars()
                .filter(|c| !c.is_whitespace())
                .count();
        }
        last_idx = e;
    }
    if last_idx < statement.len() {
        non_ws_count += statement[last_idx..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .count();
    }

    non_ws_count < MIN_REMAINING_CHARS
}

/// Redact spans from a problem statement string.
///
/// Spans are validated, sorted, and merged.
/// Offsets are byte offsets into the UTF-8 encoding of `statement`.
/// Returns `(redacted_string, redacted_spans_metadata)` where each span's hash is SHA-256.
pub fn redact_statement(
    statement: &str,
    spans: Vec<(usize, usize)>,
) -> Result<(String, Vec<RedactedSpan>), DispositionError> {
    let merged_spans = validate_and_merge_spans(statement, spans)?;

    let mut metadata = Vec::with_capacity(merged_spans.len());
    for &(s, e) in &merged_spans {
        let slice = &statement[s..e];
        let digest = sha256_hex(slice.as_bytes());
        metadata.push(RedactedSpan {
            start: s,
            end: e,
            sha256: digest.clone(),
            hash: format!("sha256:{digest}"),
        });
    }

    // Apply redactions in reverse offset order so earlier byte offsets remain unchanged
    let mut out = statement.to_string();
    for &(s, e) in merged_spans.iter().rev() {
        out.replace_range(s..e, "[REDACTED]");
    }

    Ok((out, metadata))
}
