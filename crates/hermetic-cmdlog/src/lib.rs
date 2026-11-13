//! Tamper-evident append-only command log (`hermetic-cmdlog`) for Hermetic World Mode H.
//!
//! # Security & Determinism Guarantees
//! - **Zero unsafe code**: Enforced via `#![forbid(unsafe_code)]`.
//! - **Deterministic entries**: No wall-clock timestamps are stored; ordering is anchored by a
//!   strictly monotonic `u64` sequence number starting at `0` and a SHA-256 hash chain.
//! - **No leaked output bodies**: Command `stdout` and `stderr` payloads are never written to
//!   the log. Only their SHA-256 digests (`stdout_sha256`, `stderr_sha256`) and byte lengths
//!   (`stdout_len`, `stderr_len`) are recorded so the audit log cannot act as an exfiltration or
//!   post-cutoff information leak channel.
//! - **Bounded reads and counts**: Every line read, stream hash operation, field length, and
//!   entry count is bounded by a named `const` cap.
//! - **Safe file handling**: Refuses symlinks, non-regular files, and files writable by group or
//!   others, and `fsync`s after every append.

#![forbid(unsafe_code)]

pub mod entry;
pub mod log;

pub use entry::{
    encode_sha256_prefixed, hash_output_bytes, hash_output_reader, is_valid_sha256_prefixed, Entry,
    EntryKind, EntryPayload, EMPTY_SHA256, GENESIS_PREV,
};
pub use log::{verify, CmdLog, Head};

/// Maximum serialized byte length of a single canonical JSON log line (including trailing `\n`).
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Maximum number of entries permitted in a single command log (`seq` in `0..MAX_LOG_ENTRIES`).
pub const MAX_LOG_ENTRIES: u64 = 10_000_000;

/// Maximum number of arguments permitted in an `exec` entry's `argv` array.
pub const MAX_ARGV_LEN: usize = 1024;

/// Maximum byte length permitted for a single argument string in `argv`.
pub const MAX_ARG_BYTES: usize = 16 * 1024;

/// Maximum byte length permitted for a `path` field in `upload` or `download` entries.
pub const MAX_PATH_BYTES: usize = 4096;

/// Maximum logical byte length permitted for `stdout_len` or `stderr_len`.
pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// Fixed chunk size in bytes used when streaming output readers into SHA-256.
pub const HASH_CHUNK_BYTES: usize = 8192;

/// Typed errors returned by log operations and chain verification.
#[derive(Debug)]
pub enum ChainError {
    /// Underlying filesystem or stream I/O error.
    Io {
        context: String,
        source: std::io::Error,
    },
    /// Target path is a symbolic link, which is strictly refused.
    SymlinkNotAllowed { path: String },
    /// Target path is not a regular file (e.g., directory, FIFO, socket, or device).
    NotRegularFile { path: String },
    /// Target file permissions allow write access by group or others (`mode & 0o022 != 0`).
    InsecurePermissions { path: String, mode: u32 },
    /// A log line exceeded `MAX_LINE_BYTES`.
    OversizedLine { line: usize, max_bytes: usize },
    /// The final line of the log was truncated (missing terminating `\n` or incomplete record).
    TruncatedLine { line: usize },
    /// A log line was not valid UTF-8 or valid JSON matching the entry schema.
    BadJson { line: usize, detail: String },
    /// A log line contained an unrecognized JSON field.
    UnknownField { line: usize, detail: String },
    /// A log line parsed as valid entry data but was not serialized in canonical form
    /// (keys must be sorted alphabetically with no extraneous whitespace).
    NonCanonicalJson { line: usize },
    /// An entry violated kind-specific field rules, digest formatting, or named size caps.
    InvalidField { line: Option<usize>, detail: String },
    /// Entry sequence number did not match the expected monotonic counter.
    SeqGap {
        line: usize,
        expected: u64,
        actual: u64,
    },
    /// Entry `prev` digest did not match `"sha256:<previous_entry_hash>"` (or 64 zeros at seq 0).
    PrevMismatch {
        line: usize,
        expected: String,
        actual: String,
    },
    /// Log entry count exceeded `MAX_LOG_ENTRIES`.
    MaxEntriesExceeded { max: u64 },
    /// Command output stream exceeded `MAX_OUTPUT_BYTES`.
    MaxOutputExceeded { max_bytes: u64 },
    /// An earlier append failed part-way, so the on-disk tail is unknown and the writer
    /// refuses further appends (reopening re-verifies the chain).
    WriterPoisoned,
}

impl ChainError {
    /// Returns the 1-based line number where chain verification failed, if associated with a line.
    pub fn line(&self) -> Option<usize> {
        match self {
            ChainError::OversizedLine { line, .. }
            | ChainError::TruncatedLine { line }
            | ChainError::BadJson { line, .. }
            | ChainError::UnknownField { line, .. }
            | ChainError::NonCanonicalJson { line }
            | ChainError::SeqGap { line, .. }
            | ChainError::PrevMismatch { line, .. } => Some(*line),
            ChainError::InvalidField { line, .. } => *line,
            ChainError::Io { .. }
            | ChainError::SymlinkNotAllowed { .. }
            | ChainError::NotRegularFile { .. }
            | ChainError::InsecurePermissions { .. }
            | ChainError::MaxEntriesExceeded { .. }
            | ChainError::MaxOutputExceeded { .. }
            | ChainError::WriterPoisoned => None,
        }
    }

    /// Returns `true` when the error represents chain/record corruption (CLI exit code `2`),
    /// and `false` when it represents a file/permission/operational error (CLI exit code `1`).
    pub fn is_chain_corruption(&self) -> bool {
        match self {
            ChainError::OversizedLine { .. }
            | ChainError::TruncatedLine { .. }
            | ChainError::BadJson { .. }
            | ChainError::UnknownField { .. }
            | ChainError::NonCanonicalJson { .. }
            | ChainError::InvalidField { .. }
            | ChainError::SeqGap { .. }
            | ChainError::PrevMismatch { .. }
            | ChainError::MaxEntriesExceeded { .. } => true,
            ChainError::Io { .. }
            | ChainError::SymlinkNotAllowed { .. }
            | ChainError::NotRegularFile { .. }
            | ChainError::InsecurePermissions { .. }
            | ChainError::MaxOutputExceeded { .. }
            | ChainError::WriterPoisoned => false,
        }
    }
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Io { context, source } => write!(f, "I/O error ({context}): {source}"),
            ChainError::SymlinkNotAllowed { path } => {
                write!(f, "refusing to open symlink: {path}")
            }
            ChainError::NotRegularFile { path } => {
                write!(f, "refusing to open non-regular file: {path}")
            }
            ChainError::InsecurePermissions { path, mode } => write!(
                f,
                "refusing to open file writable by group or others (mode {mode:#o}): {path}"
            ),
            ChainError::OversizedLine { line, max_bytes } => {
                write!(
                    f,
                    "line {line}: exceeds maximum line size of {max_bytes} bytes"
                )
            }
            ChainError::TruncatedLine { line } => {
                write!(
                    f,
                    "line {line}: truncated line (missing newline or incomplete record)"
                )
            }
            ChainError::BadJson { line, detail } => {
                write!(f, "line {line}: malformed JSON entry: {detail}")
            }
            ChainError::UnknownField { line, detail } => {
                write!(f, "line {line}: unknown field in entry: {detail}")
            }
            ChainError::NonCanonicalJson { line } => {
                write!(f, "line {line}: entry JSON is not in canonical form")
            }
            ChainError::InvalidField {
                line: Some(line),
                detail,
            } => {
                write!(f, "line {line}: invalid entry field: {detail}")
            }
            ChainError::InvalidField { line: None, detail } => {
                write!(f, "invalid entry field: {detail}")
            }
            ChainError::SeqGap {
                line,
                expected,
                actual,
            } => write!(
                f,
                "line {line}: sequence gap (expected seq {expected}, found {actual})"
            ),
            ChainError::PrevMismatch {
                line,
                expected,
                actual,
            } => write!(
                f,
                "line {line}: prev hash mismatch (expected {expected}, found {actual})"
            ),
            ChainError::MaxEntriesExceeded { max } => {
                write!(f, "log entry count exceeds maximum cap of {max}")
            }
            ChainError::MaxOutputExceeded { max_bytes } => {
                write!(f, "output stream exceeds maximum cap of {max_bytes} bytes")
            }
            ChainError::WriterPoisoned => write!(
                f,
                "an earlier append failed part-way; reopen the log to re-verify the chain"
            ),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChainError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
