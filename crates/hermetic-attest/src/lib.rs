#![forbid(unsafe_code)]

// Error diagnostics must never expose supplied text or signer backend details.
macro_rules! redacted_debug {
    ($error:ty) => {
        impl std::fmt::Debug for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(self, f)
            }
        }
    };
}

pub mod audit;
pub mod base64;
pub mod canonical;
pub mod digest;
pub mod dsse;
pub mod fs;
pub mod hex;
pub mod run;
pub mod score_card;
pub mod status;

pub use audit::{
    AuditLabel, AuditValidationError, EvidenceSpan, TranscriptAuditRecord, MAX_AUDIT_RECORD_SIZE,
    MAX_EVIDENCE_SPANS,
};
pub use canonical::{
    canonical_json_from_str, canonicalize_value, compute_run_digest, to_canonical_json_bytes,
    CanonicalJsonError,
};
pub use digest::{Digest, DigestError};
pub use dsse::{
    dsse_pae, verify_audit_envelope, verify_run_envelope, DsseEnvelope, DsseError, DsseSignature,
    SignatureError, Signer, Statement, StatementSubject, Verifier, DSSE_PAYLOAD_TYPE_IN_TOTO,
    IN_TOTO_STATEMENT_V1_TYPE, MAX_ENVELOPE_JSON_BYTES, MAX_PAYLOAD_BYTES, MAX_SIGNATURES,
    PREDICATE_TYPE_AUDIT_V1, PREDICATE_TYPE_RUN_V1,
};
pub use fs::{safe_atomic_write_file, safe_read_file, safe_sha256_file, FsError};
pub use run::{
    AgentMode, ArtifactDigestSize, BootRecord, ClockLevel, Deployment, GraderIsolation,
    GradingRunResult, HostBootRecord, ProbeResult, RunRecord, RunStatus, RunValidationError,
    SealLevel, StateGradeRecord, StateGradingPath, SubstrateAtT, TaskClass, TeePlatform, TeeQuote,
    VersionTuple, MAX_RUN_RECORD_SIZE,
};
pub use score_card::{
    generate_score_card, ExcludedTask, RepairedTask, ScoreCard, ScoreCardError,
    MAX_SCORE_CARD_RECORDS,
};
pub use status::{compute_run_status, GradingInputs};
pub mod offline_key;
pub mod sigstore;
pub mod verify;

pub use offline_key::{ed25519_key_id, Ed25519Signer, Ed25519Verifier, KeyError};
pub use sigstore::{
    verify_sigstore_bundle, ParsedCertificate, RekorKey, RekorKeyAlgorithm, RekorSignerFn,
    SigstoreBundle, SigstoreError, SigstoreSigner, SigstoreTrustRoot, MAX_FULCIO_ROOTS,
    MAX_REKOR_KEYS, MAX_SIGSTORE_BUNDLE_BYTES, MAX_TRUST_ROOT_BYTES,
    SIGSTORE_BUNDLE_MEDIA_TYPE_V02, SIGSTORE_BUNDLE_MEDIA_TYPE_V03,
    SIGSTORE_BUNDLE_MEDIA_TYPE_V03_ALT,
};
pub use verify::{
    check_against_classification, verify_audit_attestation, verify_run_attestation,
    verify_run_sigstore_attestation, ReplayGuard, RunBinding, RunClassification, VerifyError,
};
