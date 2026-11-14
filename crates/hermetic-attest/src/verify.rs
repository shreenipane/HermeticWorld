//! Verification policy on top of envelope verification: binding a run record to
//! the expected world (world root, world bundle version, sealcheck report, grader
//! image, task), refusing replays, and cross-checking the record against the run
//! classifier output (`hermetic-run-classification/v1`) for clock level, D12
//! `date_leak_observed` and run status.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::audit::TranscriptAuditRecord;
use crate::digest::Digest;
use crate::dsse::{verify_audit_envelope, verify_run_envelope, DsseError, Statement, Verifier};
use crate::run::{ClockLevel, RunRecord, RunStatus};

/// Largest replay guard (distinct run digests remembered).
pub const MAX_REPLAY_ENTRIES: usize = 100_000;
/// Largest classification document.
pub const MAX_CLASSIFICATION_BYTES: usize = 64 * 1024;
/// Largest number of flags or clock reasons in a classification document.
pub const MAX_CLASSIFICATION_LIST: usize = 64;
/// Schema name of the run classifier output.
pub const CLASSIFICATION_SCHEMA: &str = "hermetic-run-classification/v1";

#[derive(Clone, PartialEq, Eq)]
pub enum VerifyError {
    Envelope(DsseError),
    BindingMismatch(&'static str),
    Replay,
    ReplayGuardFull { limit: usize },
    AuditRunNotVerified,
    Classification(String),
    ClassificationMismatch(&'static str),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "envelope: {e}"),
            Self::BindingMismatch(field) => write!(f, "record does not match expected {field}"),
            Self::Replay => write!(f, "run record already verified (replay)"),
            Self::ReplayGuardFull { limit } => write!(f, "replay guard full ({limit})"),
            Self::AuditRunNotVerified => write!(f, "audit names a run that was not verified"),
            Self::Classification(msg) => write!(f, "classification: {msg}"),
            Self::ClassificationMismatch(field) => {
                write!(f, "record disagrees with classifier on {field}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}
redacted_debug!(VerifyError);

/// Values the verifier expects; `None` means "not checked".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunBinding {
    pub task_id: Option<String>,
    pub world_root: Option<Digest>,
    /// The world bundle digest (`version_tuple.world_version`).
    pub world_bundle: Option<Digest>,
    pub sealcheck_report_digest: Option<Digest>,
    pub grader_image_digest: Option<Digest>,
}

impl RunBinding {
    pub fn check(&self, record: &RunRecord) -> Result<(), VerifyError> {
        fn eq<T: PartialEq>(
            want: &Option<T>,
            got: &T,
            name: &'static str,
        ) -> Result<(), VerifyError> {
            match want {
                Some(w) if w != got => Err(VerifyError::BindingMismatch(name)),
                _ => Ok(()),
            }
        }
        eq(&self.task_id, &record.task_id, "task_id")?;
        eq(&self.world_root, &record.world_root, "world_root")?;
        eq(
            &self.world_bundle,
            &record.version_tuple.world_version,
            "world_version",
        )?;
        eq(
            &self.sealcheck_report_digest,
            &record.sealcheck_report_digest,
            "sealcheck_report_digest",
        )?;
        eq(
            &self.grader_image_digest,
            &record.version_tuple.grader_image_digest,
            "grader_image_digest",
        )
    }
}

/// Remembers verified run digests so that one signed record is accepted once.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: BTreeSet<Digest>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, digest: &Digest) -> bool {
        self.seen.contains(digest)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn admit(&mut self, digest: Digest) -> Result<(), VerifyError> {
        if self.seen.contains(&digest) {
            return Err(VerifyError::Replay);
        }
        if self.seen.len() >= MAX_REPLAY_ENTRIES {
            return Err(VerifyError::ReplayGuardFull {
                limit: MAX_REPLAY_ENTRIES,
            });
        }
        self.seen.insert(digest);
        Ok(())
    }
}

/// Verify a run envelope, check its binding, and admit it once.
pub fn verify_run_attestation(
    envelope_json: &str,
    verifier: &dyn Verifier,
    binding: &RunBinding,
    guard: &mut ReplayGuard,
) -> Result<(Statement<RunRecord>, Digest), VerifyError> {
    let statement =
        verify_run_envelope(envelope_json, None, verifier).map_err(VerifyError::Envelope)?;
    binding.check(&statement.predicate)?;
    let digest = crate::canonical::compute_run_digest(&statement.predicate)
        .map_err(|e| VerifyError::Envelope(DsseError::CanonicalJson(e)))?;
    guard.admit(digest.clone())?;
    Ok((statement, digest))
}

/// Verify an audit envelope; its run must already have been verified by `guard`.
pub fn verify_audit_attestation(
    envelope_json: &str,
    verifier: &dyn Verifier,
    run_digest: &Digest,
    guard: &ReplayGuard,
) -> Result<Statement<TranscriptAuditRecord>, VerifyError> {
    if !guard.contains(run_digest) {
        return Err(VerifyError::AuditRunNotVerified);
    }
    verify_audit_envelope(envelope_json, run_digest, verifier).map_err(VerifyError::Envelope)
}

/// Strict view of `hermetic-run-classification/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunClassification {
    pub schema: String,
    pub run_digest: Digest,
    pub clock: ClockLevel,
    pub clock_reasons: Vec<String>,
    pub label: Option<crate::audit::AuditLabel>,
    pub confidence: Option<u32>,
    pub status: RunStatus,
    pub flags: Vec<String>,
}

fn sorted_unique_bounded(list: &[String]) -> bool {
    list.len() <= MAX_CLASSIFICATION_LIST
        && list.windows(2).all(|w| w[0] < w[1])
        && list.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

impl RunClassification {
    pub fn from_json_str(s: &str) -> Result<Self, VerifyError> {
        if s.len() > MAX_CLASSIFICATION_BYTES {
            return Err(VerifyError::Classification("too large".into()));
        }
        let c: Self = serde_json::from_str(s)
            .map_err(|_| VerifyError::Classification("malformed document".into()))?;
        if c.schema != CLASSIFICATION_SCHEMA {
            return Err(VerifyError::Classification("wrong schema".into()));
        }
        if !sorted_unique_bounded(&c.flags) || !sorted_unique_bounded(&c.clock_reasons) {
            return Err(VerifyError::Classification("bad list".into()));
        }
        match (c.label, c.confidence) {
            (None, None) => {}
            (Some(_), Some(v)) if v <= 1000 => {}
            _ => return Err(VerifyError::Classification("bad label/confidence".into())),
        }
        if c.clock == ClockLevel::Hidden && !c.clock_reasons.is_empty() {
            return Err(VerifyError::Classification(
                "hidden clock with reasons".into(),
            ));
        }
        Ok(c)
    }

    /// D12: a leak, or a sentinel scan that did not run, counts as observed.
    pub fn date_leak_observed(&self) -> bool {
        self.flags
            .iter()
            .any(|f| f == "date_leak_observed" || f == "date_sentinel_not_run")
    }
}

/// Bind the classifier to this run digest and require matching clock, D12 and status.
pub fn check_against_classification(
    record: &RunRecord,
    classification: &RunClassification,
) -> Result<(), VerifyError> {
    if record.clock != classification.clock {
        return Err(VerifyError::ClassificationMismatch("clock"));
    }
    if record.date_leak_observed != classification.date_leak_observed() {
        return Err(VerifyError::ClassificationMismatch("date_leak_observed"));
    }
    if record.run_status != classification.status {
        return Err(VerifyError::ClassificationMismatch("run_status"));
    }
    let digest = crate::canonical::compute_run_digest(record)
        .map_err(|e| VerifyError::Envelope(DsseError::CanonicalJson(e)))?;
    if digest != classification.run_digest {
        return Err(VerifyError::ClassificationMismatch("run_digest"));
    }
    Ok(())
}
