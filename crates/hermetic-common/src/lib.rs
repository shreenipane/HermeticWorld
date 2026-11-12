#![forbid(unsafe_code)]

pub mod cutoff;
pub mod disposition;
pub mod hash;
pub mod manifest;
pub mod wire;
pub mod world_manifest;

pub use cutoff::{
    compute_cutoffs, ensure_utc, CutoffError, Cutoffs, DiscardReason, DiscardedDate, FixCommit,
};
pub use disposition::{
    redact_statement, should_exclude_d0, validate_and_merge_spans, DispositionError,
    DispositionsSummary, RedactedSpan, TaskDispositionRecord, MAX_REDACTION_FRACTION,
    MIN_REMAINING_CHARS,
};
pub use hash::{sha256_hex, ChainError, HashChain};
pub use manifest::{CutoffsRecord, ManifestError, TaskInput, TaskJson};
pub use wire::{
    validate_authority, validate_header_name, validate_header_value, Method, RequestFrame,
    ResponseFrame, ResponseHeader, WireError, MAX_AUTHORITY_LEN, MAX_PATH_LEN,
    MAX_REQUEST_FRAME_SIZE, MAX_RESPONSE_HEADERS, MAX_RESPONSE_HEADERS_BYTES, REQUEST_HEADER_SIZE,
    REQUEST_MAGIC, RESPONSE_HEADER_SIZE, RESPONSE_MAGIC,
};
pub use world_manifest::{
    digest_file, digest_tree, verify_inclusion, Disposition, DispositionKind, InclusionProof,
    ManifestCutoffs, PackagesRecord, ProofDirection, ProofStep, Resources, RunSpec, SealLevel,
    SubstrateAtT, SubstrateEntry, SubstrateExemption, TaskClass, ValidationErrors, WebRecord,
    WorldManifest, WorldManifestError,
};
