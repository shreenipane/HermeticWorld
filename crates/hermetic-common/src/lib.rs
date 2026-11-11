#![forbid(unsafe_code)]

pub mod cutoff;
pub mod hash;
pub mod manifest;
pub mod wire;

pub use cutoff::{
    compute_cutoffs, ensure_utc, CutoffError, Cutoffs, DiscardReason, DiscardedDate, FixCommit,
};
pub use hash::{sha256_hex, ChainError, HashChain};
pub use manifest::{CutoffsRecord, ManifestError, TaskInput, TaskJson};
pub use wire::{
    validate_authority, validate_header_name, validate_header_value, Method, RequestFrame,
    ResponseFrame, ResponseHeader, WireError, MAX_AUTHORITY_LEN, MAX_REQUEST_FRAME_SIZE,
    MAX_RESPONSE_HEADERS, MAX_RESPONSE_HEADERS_BYTES, REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE,
};
