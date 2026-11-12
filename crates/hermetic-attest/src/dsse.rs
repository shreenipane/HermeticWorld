//! In-toto v1 Statement and DSSE Envelope parsing, signing, and verification.
//!
//! Implements the exact Pre-Authentication Encoding (PAE) specified by DSSE:
//! `PAE(type, body) = "DSSEv1" + " " + len(type) + " " + type + " " + len(body) + " " + body`
//!
//! Verifies DSSE envelopes with strict parsing, bounded signatures, and recomputed digest checks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::audit::TranscriptAuditRecord;
use crate::base64::{base64_decode, base64_encode, Base64Error};
use crate::canonical::{compute_run_digest, to_canonical_json_bytes, CanonicalJsonError};
use crate::digest::Digest;
use crate::run::RunRecord;

pub const IN_TOTO_STATEMENT_V1_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE_RUN_V1: &str = "hermetic-run/v1";
pub const PREDICATE_TYPE_AUDIT_V1: &str = "hermetic-transcript-audit/v1";
pub const DSSE_PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

pub const MAX_ENVELOPE_JSON_BYTES: usize = 1024 * 1024; // 1 MiB
pub const MAX_PAYLOAD_BYTES: usize = 512 * 1024; // 512 KiB
pub const MAX_SIGNATURES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    SigningFailed(String),
    VerificationFailed(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed(msg) => write!(f, "Signing failed: {msg}"),
            Self::VerificationFailed(msg) => write!(f, "Signature verification failed: {msg}"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Trait for signing PAE bytes.
pub trait Signer {
    fn key_id(&self) -> Option<String>;
    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignatureError>;
}

/// Trait for verifying signatures over PAE bytes.
pub trait Verifier {
    fn verify(
        &self,
        key_id: Option<&str>,
        pae_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), SignatureError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsseError {
    SizeCapExceeded { size: usize, limit: usize },
    JsonParse(String),
    Base64(Base64Error),
    UnknownPayloadType(String),
    NoSignatures,
    TooManySignatures { count: usize, limit: usize },
    SignatureVerification(SignatureError),
    InvalidStatementType(String),
    InvalidPredicateType { expected: String, actual: String },
    SubjectDigestMismatch { expected: String, actual: String },
    MissingSubject,
    CanonicalJson(CanonicalJsonError),
    RunValidation(String),
    AuditValidation(String),
}

impl fmt::Display for DsseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeCapExceeded { size, limit } => {
                write!(f, "Envelope size {size} bytes exceeds limit {limit}")
            }
            Self::JsonParse(msg) => write!(f, "JSON parse error: {msg}"),
            Self::Base64(e) => write!(f, "Base64 decoding error: {e}"),
            Self::UnknownPayloadType(pt) => write!(f, "Unknown or disallowed payloadType: '{pt}'"),
            Self::NoSignatures => write!(f, "Envelope contains no signatures"),
            Self::TooManySignatures { count, limit } => {
                write!(f, "Signature count {count} exceeds limit {limit}")
            }
            Self::SignatureVerification(e) => write!(f, "Signature verification error: {e}"),
            Self::InvalidStatementType(st) => {
                write!(f, "Invalid in-toto statement _type: expected '{IN_TOTO_STATEMENT_V1_TYPE}', got '{st}'")
            }
            Self::InvalidPredicateType { expected, actual } => {
                write!(
                    f,
                    "Predicate type mismatch: expected '{expected}', got '{actual}'"
                )
            }
            Self::SubjectDigestMismatch { expected, actual } => {
                write!(
                    f,
                    "Subject digest mismatch: expected '{expected}', actual '{actual}'"
                )
            }
            Self::MissingSubject => write!(f, "Statement subject list is empty"),
            Self::CanonicalJson(e) => write!(f, "Canonical JSON error: {e}"),
            Self::RunValidation(msg) => write!(f, "Run validation error: {msg}"),
            Self::AuditValidation(msg) => write!(f, "Audit validation error: {msg}"),
        }
    }
}

impl std::error::Error for DsseError {}

/// Compute DSSE Pre-Authentication Encoding (PAE).
///
/// `PAE(type, body) = "DSSEv1" + " " + len(type) + " " + type + " " + len(body) + " " + body`
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let type_len_str = type_bytes.len().to_string();
    let payload_len_str = payload.len().to_string();

    let total_len = b"DSSEv1".len()
        + 1
        + type_len_str.len()
        + 1
        + type_bytes.len()
        + 1
        + payload_len_str.len()
        + 1
        + payload.len();

    let mut pae = Vec::with_capacity(total_len);
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(type_len_str.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(type_bytes);
    pae.push(b' ');
    pae.extend_from_slice(payload_len_str.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

/// Resource subject in an in-toto v1 Statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

impl StatementSubject {
    pub fn from_digest(name: impl Into<String>, digest: &Digest) -> Self {
        let mut map = BTreeMap::new();
        map.insert(digest.algorithm().to_string(), digest.hex().to_string());
        Self {
            name: name.into(),
            digest: map,
        }
    }

    /// Check whether this subject carries a matching digest.
    pub fn matches_digest(&self, expected: &Digest) -> bool {
        if let Some(val) = self.digest.get(expected.algorithm()) {
            val.eq_ignore_ascii_case(expected.hex())
        } else {
            false
        }
    }
}

/// In-toto v1 Statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement<T> {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<StatementSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: T,
}

impl Statement<RunRecord> {
    /// Create a new in-toto statement for a hermetic-run/v1 record.
    pub fn new_run_statement(run_record: RunRecord) -> Result<Self, DsseError> {
        run_record
            .validate()
            .map_err(|e| DsseError::RunValidation(e.to_string()))?;
        let run_digest = compute_run_digest(&run_record).map_err(DsseError::CanonicalJson)?;
        let subject = vec![StatementSubject::from_digest(
            &run_record.task_id,
            &run_digest,
        )];
        Ok(Self {
            statement_type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject,
            predicate_type: PREDICATE_TYPE_RUN_V1.to_string(),
            predicate: run_record,
        })
    }
}

impl Statement<TranscriptAuditRecord> {
    /// Create a new in-toto statement for a hermetic-transcript-audit/v1 record.
    pub fn new_audit_statement(audit_record: TranscriptAuditRecord) -> Result<Self, DsseError> {
        audit_record
            .validate()
            .map_err(|e| DsseError::AuditValidation(e.to_string()))?;
        let subject = vec![StatementSubject::from_digest(
            "run",
            &audit_record.run_digest,
        )];
        Ok(Self {
            statement_type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject,
            predicate_type: PREDICATE_TYPE_AUDIT_V1.to_string(),
            predicate: audit_record,
        })
    }
}

/// A signature entry in a DSSE envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    pub sig: String,
}

/// Dead Simple Signing Envelope (DSSE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Sign an in-toto statement and produce a DSSE envelope.
    pub fn sign_statement<T: Serialize>(
        statement: &Statement<T>,
        signer: &dyn Signer,
    ) -> Result<Self, DsseError> {
        let payload_bytes = to_canonical_json_bytes(statement).map_err(DsseError::CanonicalJson)?;
        let pae = dsse_pae(DSSE_PAYLOAD_TYPE_IN_TOTO, &payload_bytes);
        let sig_bytes = signer
            .sign(&pae)
            .map_err(DsseError::SignatureVerification)?;

        let envelope = Self {
            payload: base64_encode(&payload_bytes),
            payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.to_string(),
            signatures: vec![DsseSignature {
                keyid: signer.key_id(),
                sig: base64_encode(&sig_bytes),
            }],
        };
        Ok(envelope)
    }

    /// Strictly verify signatures and return decoded payload bytes.
    pub fn verify_and_decode(&self, verifier: &dyn Verifier) -> Result<Vec<u8>, DsseError> {
        // Enforce allowed payloadType
        if self.payload_type != DSSE_PAYLOAD_TYPE_IN_TOTO {
            return Err(DsseError::UnknownPayloadType(self.payload_type.clone()));
        }

        // Enforce signatures count bounds
        if self.signatures.is_empty() {
            return Err(DsseError::NoSignatures);
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(DsseError::TooManySignatures {
                count: self.signatures.len(),
                limit: MAX_SIGNATURES,
            });
        }

        // Decode payload
        let payload_bytes =
            base64_decode(&self.payload, MAX_PAYLOAD_BYTES).map_err(DsseError::Base64)?;
        let pae = dsse_pae(&self.payload_type, &payload_bytes);

        // Verify all signatures
        for sig_entry in &self.signatures {
            let sig_bytes = base64_decode(&sig_entry.sig, 64 * 1024).map_err(DsseError::Base64)?;
            verifier
                .verify(sig_entry.keyid.as_deref(), &pae, &sig_bytes)
                .map_err(DsseError::SignatureVerification)?;
        }

        Ok(payload_bytes)
    }
}

/// Verify a DSSE envelope containing a `hermetic-run/v1` statement.
///
/// Recomputes the run digest from the payload's predicate and ensures:
/// 1. Signatures are valid.
/// 2. Payload type is `application/vnd.in-toto+json`.
/// 3. Statement `_type` is `https://in-toto.io/Statement/v1`.
/// 4. `predicateType` is `hermetic-run/v1`.
/// 5. Subject digest matches recomputed run digest.
/// 6. If `expected_run_digest` is supplied, matches it as well.
pub fn verify_run_envelope(
    envelope_json: &str,
    expected_run_digest: Option<&Digest>,
    verifier: &dyn Verifier,
) -> Result<Statement<RunRecord>, DsseError> {
    if envelope_json.len() > MAX_ENVELOPE_JSON_BYTES {
        return Err(DsseError::SizeCapExceeded {
            size: envelope_json.len(),
            limit: MAX_ENVELOPE_JSON_BYTES,
        });
    }

    let envelope: DsseEnvelope =
        serde_json::from_str(envelope_json).map_err(|e| DsseError::JsonParse(e.to_string()))?;

    let payload_bytes = envelope.verify_and_decode(verifier)?;

    let statement: Statement<RunRecord> =
        serde_json::from_slice(&payload_bytes).map_err(|e| DsseError::JsonParse(e.to_string()))?;

    if statement.statement_type != IN_TOTO_STATEMENT_V1_TYPE {
        return Err(DsseError::InvalidStatementType(statement.statement_type));
    }

    if statement.predicate_type != PREDICATE_TYPE_RUN_V1 {
        return Err(DsseError::InvalidPredicateType {
            expected: PREDICATE_TYPE_RUN_V1.to_string(),
            actual: statement.predicate_type,
        });
    }

    statement
        .predicate
        .validate()
        .map_err(|e| DsseError::RunValidation(e.to_string()))?;

    // Recompute run digest from predicate
    let computed_digest =
        compute_run_digest(&statement.predicate).map_err(DsseError::CanonicalJson)?;

    if statement.subject.is_empty() {
        return Err(DsseError::MissingSubject);
    }

    let matches_subject = statement
        .subject
        .iter()
        .any(|s| s.matches_digest(&computed_digest));
    if !matches_subject {
        let actual_subject = format!("{:?}", statement.subject);
        return Err(DsseError::SubjectDigestMismatch {
            expected: computed_digest.as_str().to_string(),
            actual: actual_subject,
        });
    }

    if let Some(expected) = expected_run_digest {
        if &computed_digest != expected {
            return Err(DsseError::SubjectDigestMismatch {
                expected: expected.as_str().to_string(),
                actual: computed_digest.as_str().to_string(),
            });
        }
    }

    Ok(statement)
}

/// Verify a DSSE envelope containing a `hermetic-transcript-audit/v1` statement.
///
/// Verifies signatures and ensures:
/// 1. Signatures are valid.
/// 2. Payload type is `application/vnd.in-toto+json`.
/// 3. Statement `_type` is `https://in-toto.io/Statement/v1`.
/// 4. `predicateType` is `hermetic-transcript-audit/v1`.
/// 5. Subject digest and predicate `run_digest` match `expected_run_digest`.
pub fn verify_audit_envelope(
    envelope_json: &str,
    expected_run_digest: &Digest,
    verifier: &dyn Verifier,
) -> Result<Statement<TranscriptAuditRecord>, DsseError> {
    if envelope_json.len() > MAX_ENVELOPE_JSON_BYTES {
        return Err(DsseError::SizeCapExceeded {
            size: envelope_json.len(),
            limit: MAX_ENVELOPE_JSON_BYTES,
        });
    }

    let envelope: DsseEnvelope =
        serde_json::from_str(envelope_json).map_err(|e| DsseError::JsonParse(e.to_string()))?;

    let payload_bytes = envelope.verify_and_decode(verifier)?;

    let statement: Statement<TranscriptAuditRecord> =
        serde_json::from_slice(&payload_bytes).map_err(|e| DsseError::JsonParse(e.to_string()))?;

    if statement.statement_type != IN_TOTO_STATEMENT_V1_TYPE {
        return Err(DsseError::InvalidStatementType(statement.statement_type));
    }

    if statement.predicate_type != PREDICATE_TYPE_AUDIT_V1 {
        return Err(DsseError::InvalidPredicateType {
            expected: PREDICATE_TYPE_AUDIT_V1.to_string(),
            actual: statement.predicate_type,
        });
    }

    statement
        .predicate
        .validate()
        .map_err(|e| DsseError::AuditValidation(e.to_string()))?;

    // Check subject matches expected run digest
    if statement.subject.is_empty() {
        return Err(DsseError::MissingSubject);
    }

    let matches_subject = statement
        .subject
        .iter()
        .any(|s| s.matches_digest(expected_run_digest));
    if !matches_subject {
        let actual_subject = format!("{:?}", statement.subject);
        return Err(DsseError::SubjectDigestMismatch {
            expected: expected_run_digest.as_str().to_string(),
            actual: actual_subject,
        });
    }

    if &statement.predicate.run_digest != expected_run_digest {
        return Err(DsseError::SubjectDigestMismatch {
            expected: expected_run_digest.as_str().to_string(),
            actual: statement.predicate.run_digest.as_str().to_string(),
        });
    }

    Ok(statement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsse_pae_known_answer() {
        // Known-answer test from DSSE specification
        let payload_type = "http://example.com/HelloWorld";
        let payload = b"hello world";
        let pae = dsse_pae(payload_type, payload);
        assert_eq!(
            pae,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }
}
