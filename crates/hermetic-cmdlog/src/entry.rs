//! Canonical command-log entry definitions, validation, and output digest helpers.
//!
//! # Why Output Bodies Are Never Stored
//! In Hermetic World Mode H, commands executed inside the sealed environment can produce
//! arbitrary `stdout` and `stderr` text. Storing raw output bodies in the host audit log would
//! create an exfiltration / post-cutoff leak channel if the log is inspected or persisted outside
//! the sealed boundary. Instead, each entry records only the cryptographic SHA-256 digests
//! (`stdout_sha256`, `stderr_sha256`) and exact byte counts (`stdout_len`, `stderr_len`) of the
//! output streams, providing full tamper detection without retaining leaked text.

use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ChainError, HASH_CHUNK_BYTES, MAX_ARGV_LEN, MAX_ARG_BYTES, MAX_LINE_BYTES, MAX_LOG_ENTRIES,
    MAX_OUTPUT_BYTES, MAX_PATH_BYTES,
};

/// The `prev` value required for the genesis entry (`seq == 0`): `"sha256:"` followed by 64 zeros.
pub const GENESIS_PREV: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// SHA-256 digest of an empty (`0`-byte) output stream.
pub const EMPTY_SHA256: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encodes a 32-byte SHA-256 digest as `"sha256:<64 lowercase hex characters>"`.
pub fn encode_sha256_prefixed(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for &byte in digest {
        out.push(HEX_LOWER[(byte >> 4) as usize] as char);
        out.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Validates that `s` has the exact format `"sha256:<64 lowercase ASCII hex digits>"`.
pub fn is_valid_sha256_prefixed(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Computes the `"sha256:<hex>"` digest and byte length of an in-memory output slice without
/// retaining the output text.
pub fn hash_output_bytes(data: &[u8]) -> Result<(String, u64), ChainError> {
    let len = data.len() as u64;
    if len > MAX_OUTPUT_BYTES {
        return Err(ChainError::MaxOutputExceeded {
            max_bytes: MAX_OUTPUT_BYTES,
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((encode_sha256_prefixed(&digest), len))
}

/// Streams an output reader through SHA-256 using a fixed stack buffer bounded by
/// `MAX_OUTPUT_BYTES`, returning `("sha256:<hex>", byte_len)` without retaining the output body.
pub fn hash_output_reader<R: Read>(mut reader: R) -> Result<(String, u64), ChainError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_CHUNK_BYTES];
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf).map_err(|source| ChainError::Io {
            context: "reading command output stream".to_string(),
            source,
        })?;
        if n == 0 {
            break;
        }
        let next_total = total
            .checked_add(n as u64)
            .ok_or(ChainError::MaxOutputExceeded {
                max_bytes: MAX_OUTPUT_BYTES,
            })?;
        if next_total > MAX_OUTPUT_BYTES {
            return Err(ChainError::MaxOutputExceeded {
                max_bytes: MAX_OUTPUT_BYTES,
            });
        }
        if let Some(chunk) = buf.get(..n) {
            hasher.update(chunk);
        }
        total = next_total;
    }

    let digest: [u8; 32] = hasher.finalize().into();
    Ok((encode_sha256_prefixed(&digest), total))
}

/// Operation kind recorded in a command log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// Execution of a command inside the sealed VM (`argv` required).
    Exec,
    /// Host-to-VM file upload (`path` required).
    Upload,
    /// VM-to-host file download (`path` required).
    Download,
    /// Channel or environment status checkpoint (neither `argv` nor `path`).
    Status,
}

/// A single tamper-evident command log entry.
///
/// Fields are declared in strict ASCII alphabetical order so `serde_json::to_string` produces
/// canonical JSON (sorted keys, no spaces) directly without intermediate `BTreeMap` allocation.
/// Command output bodies (`stdout`/`stderr` text) are deliberately absent; only their SHA-256
/// hashes and byte lengths are stored so the log cannot leak command output text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    pub exit: Option<i32>,
    pub kind: EntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub prev: String,
    pub seq: u64,
    pub stderr_len: u64,
    pub stderr_sha256: String,
    pub stdout_len: u64,
    pub stdout_sha256: String,
    pub truncated: bool,
}

impl Entry {
    /// Validates kind-specific fields, digest formats, and named size caps.
    pub fn validate(&self) -> Result<(), ChainError> {
        self.validate_at_line(None)
    }

    pub(crate) fn validate_at_line(&self, line: Option<usize>) -> Result<(), ChainError> {
        if self.seq >= MAX_LOG_ENTRIES {
            return Err(ChainError::MaxEntriesExceeded {
                max: MAX_LOG_ENTRIES,
            });
        }

        match self.kind {
            EntryKind::Exec => {
                let Some(ref argv) = self.argv else {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'exec' requires 'argv'".to_string(),
                    });
                };
                if argv.is_empty() {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'exec' requires non-empty 'argv'".to_string(),
                    });
                }
                if argv.len() > MAX_ARGV_LEN {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: format!("'argv' exceeds maximum cap of {MAX_ARGV_LEN} arguments"),
                    });
                }
                for arg in argv {
                    if arg.len() > MAX_ARG_BYTES {
                        return Err(ChainError::InvalidField {
                            line,
                            detail: format!(
                                "argument in 'argv' exceeds maximum cap of {MAX_ARG_BYTES} bytes"
                            ),
                        });
                    }
                }
                if self.path.is_some() {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'exec' must not include 'path'".to_string(),
                    });
                }
            }
            EntryKind::Upload | EntryKind::Download => {
                let Some(ref path) = self.path else {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'upload'/'download' requires 'path'".to_string(),
                    });
                };
                if path.is_empty() {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "'path' must not be empty".to_string(),
                    });
                }
                if path.len() > MAX_PATH_BYTES {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: format!("'path' exceeds maximum cap of {MAX_PATH_BYTES} bytes"),
                    });
                }
                if self.argv.is_some() {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'upload'/'download' must not include 'argv'".to_string(),
                    });
                }
            }
            EntryKind::Status => {
                if self.argv.is_some() {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'status' must not include 'argv'".to_string(),
                    });
                }
                if self.path.is_some() {
                    return Err(ChainError::InvalidField {
                        line,
                        detail: "kind 'status' must not include 'path'".to_string(),
                    });
                }
            }
        }

        if !is_valid_sha256_prefixed(&self.prev) {
            return Err(ChainError::InvalidField {
                line,
                detail: "invalid 'prev' digest format (expected sha256:<64 lowercase hex>)"
                    .to_string(),
            });
        }
        if !is_valid_sha256_prefixed(&self.stdout_sha256) {
            return Err(ChainError::InvalidField {
                line,
                detail: "invalid 'stdout_sha256' format (expected sha256:<64 lowercase hex>)"
                    .to_string(),
            });
        }
        if !is_valid_sha256_prefixed(&self.stderr_sha256) {
            return Err(ChainError::InvalidField {
                line,
                detail: "invalid 'stderr_sha256' format (expected sha256:<64 lowercase hex>)"
                    .to_string(),
            });
        }
        if self.stdout_len > MAX_OUTPUT_BYTES {
            return Err(ChainError::InvalidField {
                line,
                detail: format!("'stdout_len' exceeds maximum cap of {MAX_OUTPUT_BYTES} bytes"),
            });
        }
        if self.stderr_len > MAX_OUTPUT_BYTES {
            return Err(ChainError::InvalidField {
                line,
                detail: format!("'stderr_len' exceeds maximum cap of {MAX_OUTPUT_BYTES} bytes"),
            });
        }

        Ok(())
    }

    /// Serializes the entry to canonical JSON (alphabetically sorted keys, no spaces).
    pub fn to_canonical_json(&self) -> Result<String, ChainError> {
        self.to_canonical_json_at_line(None)
    }

    pub(crate) fn to_canonical_json_at_line(
        &self,
        line: Option<usize>,
    ) -> Result<String, ChainError> {
        self.validate_at_line(line)?;
        let json = serde_json::to_string(self).map_err(|err| ChainError::InvalidField {
            line,
            detail: format!("failed to serialize canonical JSON: {err}"),
        })?;
        // Include 1 byte for the trailing '\n' line delimiter when checking MAX_LINE_BYTES.
        if json.len().saturating_add(1) > MAX_LINE_BYTES {
            return match line {
                Some(line_num) => Err(ChainError::OversizedLine {
                    line: line_num,
                    max_bytes: MAX_LINE_BYTES,
                }),
                None => Err(ChainError::InvalidField {
                    line: None,
                    detail: format!(
                        "serialized line exceeds maximum cap of {MAX_LINE_BYTES} bytes"
                    ),
                }),
            };
        }
        Ok(json)
    }

    /// Computes `"sha256:<64 lowercase hex>"` of the entry's canonical JSON representation.
    pub fn hash(&self) -> Result<String, ChainError> {
        self.hash_at_line(None)
    }

    pub(crate) fn hash_at_line(&self, line: Option<usize>) -> Result<String, ChainError> {
        let canonical = self.to_canonical_json_at_line(line)?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(encode_sha256_prefixed(&digest))
    }
}

/// Caller-supplied fields for appending a new entry to [`crate::CmdLog`], which assigns `seq`
/// and `prev` automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPayload {
    pub kind: EntryKind,
    pub argv: Option<Vec<String>>,
    pub path: Option<String>,
    pub exit: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_len: u64,
    pub stderr_len: u64,
    pub truncated: bool,
}

impl EntryPayload {
    /// Creates an `exec` entry payload.
    pub fn exec(
        argv: Vec<String>,
        exit: Option<i32>,
        stdout_sha256: impl Into<String>,
        stderr_sha256: impl Into<String>,
        stdout_len: u64,
        stderr_len: u64,
        truncated: bool,
    ) -> Self {
        Self {
            kind: EntryKind::Exec,
            argv: Some(argv),
            path: None,
            exit,
            stdout_sha256: stdout_sha256.into(),
            stderr_sha256: stderr_sha256.into(),
            stdout_len,
            stderr_len,
            truncated,
        }
    }

    /// Creates an `upload` entry payload.
    pub fn upload(
        path: impl Into<String>,
        exit: Option<i32>,
        stdout_sha256: impl Into<String>,
        stderr_sha256: impl Into<String>,
        stdout_len: u64,
        stderr_len: u64,
        truncated: bool,
    ) -> Self {
        Self {
            kind: EntryKind::Upload,
            argv: None,
            path: Some(path.into()),
            exit,
            stdout_sha256: stdout_sha256.into(),
            stderr_sha256: stderr_sha256.into(),
            stdout_len,
            stderr_len,
            truncated,
        }
    }

    /// Creates a `download` entry payload.
    pub fn download(
        path: impl Into<String>,
        exit: Option<i32>,
        stdout_sha256: impl Into<String>,
        stderr_sha256: impl Into<String>,
        stdout_len: u64,
        stderr_len: u64,
        truncated: bool,
    ) -> Self {
        Self {
            kind: EntryKind::Download,
            argv: None,
            path: Some(path.into()),
            exit,
            stdout_sha256: stdout_sha256.into(),
            stderr_sha256: stderr_sha256.into(),
            stdout_len,
            stderr_len,
            truncated,
        }
    }

    /// Creates a `status` entry payload.
    pub fn status(
        exit: Option<i32>,
        stdout_sha256: impl Into<String>,
        stderr_sha256: impl Into<String>,
        stdout_len: u64,
        stderr_len: u64,
        truncated: bool,
    ) -> Self {
        Self {
            kind: EntryKind::Status,
            argv: None,
            path: None,
            exit,
            stdout_sha256: stdout_sha256.into(),
            stderr_sha256: stderr_sha256.into(),
            stdout_len,
            stderr_len,
            truncated,
        }
    }

    pub(crate) fn into_entry(self, seq: u64, prev: String) -> Entry {
        Entry {
            argv: self.argv,
            exit: self.exit,
            kind: self.kind,
            path: self.path,
            prev,
            seq,
            stderr_len: self.stderr_len,
            stderr_sha256: self.stderr_sha256,
            stdout_len: self.stdout_len,
            stdout_sha256: self.stdout_sha256,
            truncated: self.truncated,
        }
    }
}
