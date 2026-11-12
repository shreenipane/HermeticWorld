#![forbid(unsafe_code)]

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
pub use fs::{safe_atomic_write_file, safe_read_file, FsError};
pub use run::{
    AgentMode, ClockLevel, Deployment, GraderIsolation, GradingRunResult, ProbeResult, RunRecord,
    RunStatus, RunValidationError, SealLevel, SubstrateAtT, TaskClass, TeePlatform, TeeQuote,
    VersionTuple, MAX_RUN_RECORD_SIZE,
};
pub use score_card::{
    generate_score_card, ExcludedTask, RepairedTask, ScoreCard, ScoreCardError,
    MAX_SCORE_CARD_RECORDS,
};
pub use status::{compute_run_status, GradingInputs};
