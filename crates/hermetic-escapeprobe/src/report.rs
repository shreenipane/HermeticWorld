//! Host-side aggregation of the guest's JSON-line output into one verdict for
//! the attestation. The guest is rooted and hostile, so parsing is strict and
//! fails closed: unknown, missing, duplicate or malformed records invalidate
//! the report. Nothing from the input is copied into the verdict except probe
//! names that matched the expected list.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::classify::{is_safe_token, EscapeResult};

pub const MAX_REPORT_BYTES: usize = 256 * 1024;
pub const MAX_LINE_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every escape attempt blocked and every positive check ok.
    Sealed,
    /// All present and valid, but some checks were unavailable.
    Incomplete { unavailable: Vec<String> },
    /// At least one escape succeeded.
    Escaped { leaks: Vec<String> },
    /// The report itself cannot be trusted, or a probe errored.
    Invalid { reason: &'static str },
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Sealed => "sealed",
            Verdict::Incomplete { .. } => "incomplete",
            Verdict::Escaped { .. } => "escaped",
            Verdict::Invalid { .. } => "invalid",
        }
    }
}

/// Probes that must report `ok` rather than `blocked`.
fn is_positive(name: &str) -> bool {
    name.starts_with("positive.")
}

/// Parse one record line of exactly the shape the guest writes.
pub fn parse_line(line: &str) -> Option<(&str, EscapeResult, &str)> {
    if line.len() > MAX_LINE_BYTES {
        return None;
    }
    let rest = line.strip_prefix("{\"probe\":\"")?;
    let (probe, rest) = rest.split_once("\",\"result\":\"")?;
    let (result, rest) = rest.split_once("\",\"detail\":\"")?;
    let detail = rest.strip_suffix("\"}")?;
    if !is_safe_token(probe) || !is_safe_token(detail) {
        return None;
    }
    Some((probe, EscapeResult::parse(result)?, detail))
}

/// Aggregate a full report against the expected probe list.
pub fn aggregate(report: &[u8], expected: &[String]) -> Verdict {
    if report.len() > MAX_REPORT_BYTES {
        return Verdict::Invalid {
            reason: "report too large",
        };
    }
    let Ok(text) = std::str::from_utf8(report) else {
        return Verdict::Invalid {
            reason: "report not utf-8",
        };
    };
    let mut seen: BTreeMap<&str, EscapeResult> = BTreeMap::new();
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let Some((probe, result, _)) = parse_line(line) else {
            return Verdict::Invalid {
                reason: "malformed record",
            };
        };
        if !expected.iter().any(|e| e == probe) {
            return Verdict::Invalid {
                reason: "unknown probe",
            };
        }
        if seen.insert(probe, result).is_some() {
            return Verdict::Invalid {
                reason: "duplicate probe",
            };
        }
    }
    if seen.len() != expected.len() {
        return Verdict::Invalid {
            reason: "missing probe",
        };
    }
    let mut leaks = Vec::new();
    let mut unavailable = Vec::new();
    let mut error = false;
    for name in expected {
        let r = seen[name.as_str()];
        match (r, is_positive(name)) {
            (EscapeResult::Leak, false) => leaks.push(name.clone()),
            (EscapeResult::Blocked, false) | (EscapeResult::Ok, true) => {}
            (EscapeResult::Unavailable, _) => unavailable.push(name.clone()),
            // Error, a positive check claiming leak/blocked, or an escape
            // attempt claiming ok: all untrustworthy.
            _ => error = true,
        }
    }
    if !leaks.is_empty() {
        return Verdict::Escaped { leaks };
    }
    if error {
        return Verdict::Invalid {
            reason: "probe error or wrong result kind",
        };
    }
    if !unavailable.is_empty() {
        return Verdict::Incomplete { unavailable };
    }
    Verdict::Sealed
}
