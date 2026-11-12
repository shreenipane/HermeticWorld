//! hermetic-transcript-audit/v1 audit record definition and validation (TR-ATT-2, §12.2).
//!
//! Kept in a separate type and file so that verifying a run record never reads it.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::digest::Digest;

pub const MAX_AUDIT_RECORD_SIZE: usize = 512 * 1024; // 512 KiB
pub const MAX_EVIDENCE_SPANS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditValidationError {
    SizeCapExceeded { size: usize, limit: usize },
    JsonParse(String),
    ConfidenceOutOfBounds(u32),
    TooManyEvidenceSpans { count: usize, limit: usize },
    EmptyLogName { index: usize },
    InvalidEvidenceSpanRange { index: usize, start: u64, end: u64 },
    UnsortedEvidenceSpans,
}

impl fmt::Display for AuditValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeCapExceeded { size, limit } => {
                write!(f, "Audit record size {size} bytes exceeds limit {limit}")
            }
            Self::JsonParse(msg) => write!(f, "Audit record JSON parsing failed: {msg}"),
            Self::ConfidenceOutOfBounds(val) => {
                write!(
                    f,
                    "confidence must be bounded integer per-mille (0..=1000), got {val}"
                )
            }
            Self::TooManyEvidenceSpans { count, limit } => {
                write!(f, "Evidence spans count {count} exceeds limit {limit}")
            }
            Self::EmptyLogName { index } => {
                write!(f, "Evidence span at index {index} has empty log_name")
            }
            Self::InvalidEvidenceSpanRange { index, start, end } => {
                write!(
                    f,
                    "Evidence span at index {index} has start ({start}) > end ({end})"
                )
            }
            Self::UnsortedEvidenceSpans => {
                write!(f, "evidence_spans must be sorted and deduplicated")
            }
        }
    }
}

impl std::error::Error for AuditValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLabel {
    Derived,
    Retrieved,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpan {
    pub log_name: String,
    pub start: u64,
    pub end: u64,
}

/// The hermetic-transcript-audit/v1 statement predicate (§12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptAuditRecord {
    /// Subject = the run digest (validated `sha256:` + 64 hex).
    pub run_digest: Digest,
    /// Derived (agent solved it) or retrieved (copied from test/gold).
    pub label: AuditLabel,
    /// Bounded integer per-mille (0..=1000), never a float.
    pub confidence: u32,
    /// Evidence spans indicating where the classification signal occurred.
    #[serde(default)]
    pub evidence_spans: Vec<EvidenceSpan>,
}

impl TranscriptAuditRecord {
    /// Parse from JSON string with strict validation and size capping.
    pub fn from_json_str(s: &str) -> Result<Self, AuditValidationError> {
        if s.len() > MAX_AUDIT_RECORD_SIZE {
            return Err(AuditValidationError::SizeCapExceeded {
                size: s.len(),
                limit: MAX_AUDIT_RECORD_SIZE,
            });
        }
        let record: Self =
            serde_json::from_str(s).map_err(|e| AuditValidationError::JsonParse(e.to_string()))?;
        record.validate()?;
        Ok(record)
    }

    /// Full validation of transcript audit statement constraints.
    pub fn validate(&self) -> Result<(), AuditValidationError> {
        if self.confidence > 1000 {
            return Err(AuditValidationError::ConfidenceOutOfBounds(self.confidence));
        }

        if self.evidence_spans.len() > MAX_EVIDENCE_SPANS {
            return Err(AuditValidationError::TooManyEvidenceSpans {
                count: self.evidence_spans.len(),
                limit: MAX_EVIDENCE_SPANS,
            });
        }

        for (idx, span) in self.evidence_spans.iter().enumerate() {
            if span.log_name.trim().is_empty() {
                return Err(AuditValidationError::EmptyLogName { index: idx });
            }
            if span.start > span.end {
                return Err(AuditValidationError::InvalidEvidenceSpanRange {
                    index: idx,
                    start: span.start,
                    end: span.end,
                });
            }
        }

        // Must be sorted and deduplicated
        if !self.evidence_spans.windows(2).all(|w| w[0] < w[1]) {
            return Err(AuditValidationError::UnsortedEvidenceSpans);
        }

        Ok(())
    }
}
