use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Result disk header magic (`b"HGRD"`).
pub const RESULT_DISK_MAGIC: &[u8; 4] = b"HGRD";

/// Result disk binary format version (`1`).
pub const RESULT_DISK_VERSION: u16 = 1;

/// Result disk binary format flags (`0`).
pub const RESULT_DISK_FLAGS: u16 = 0;

/// Result disk fixed header size in bytes:
/// `magic (4) + version u16 BE (2) + flags u16 BE (2) + payload_len u32 BE (4) + sha256 (32) = 44`.
pub const RESULT_DISK_HEADER_BYTES: usize = 44;

/// Exact total size of the serialized result disk image: 1 MiB (`1,048,576` bytes).
pub const RESULT_DISK_BYTES: usize = 1024 * 1024;

/// Maximum canonical JSON payload size that fits in the 1 MiB result disk.
pub const MAX_RESULT_PAYLOAD_BYTES: usize = RESULT_DISK_BYTES - RESULT_DISK_HEADER_BYTES;

/// Benchmark evaluation run identifier (`R0..R3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RunName {
    R0,
    R1,
    R2,
    R3,
}

/// Final outcome recorded for an expected test in the result disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinalTestOutcome {
    Passed,
    Failed,
    Skipped,
    Error,
    Missing,
}

/// Overall supervisor exit classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupervisorExit {
    Clean,
    Timeout,
    Crash,
}

/// Supervisor summary nested inside the result disk payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorSummary {
    pub exit: SupervisorExit,
    pub tests_started: u64,
    pub tests_finished: u64,
}

/// Canonical JSON payload embedded inside the 1 MiB `HGRD` result disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPayload {
    pub run: RunName,
    pub variant_set: String,
    pub tests: BTreeMap<String, FinalTestOutcome>,
    pub supervisor: SupervisorSummary,
}

/// Errors returned when encoding or decoding the 1 MiB result disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskError {
    SerializeJson(String),
    PayloadTooLarge { len: usize, max: usize },
    InvalidImageLength { actual: usize, expected: usize },
    InvalidMagic,
    UnsupportedVersion(u16),
    UnsupportedFlags(u16),
    InvalidPayloadLength { len: u32, max: usize },
    DigestMismatch,
    NonZeroPadding { offset: usize },
    DeserializeJson(String),
}

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiskError::SerializeJson(e) => write!(f, "failed to serialize canonical JSON: {}", e),
            DiskError::PayloadTooLarge { len, max } => {
                write!(f, "result payload {} bytes exceeds max {} bytes", len, max)
            }
            DiskError::InvalidImageLength { actual, expected } => {
                write!(
                    f,
                    "invalid result disk size: got {} bytes, expected {} bytes",
                    actual, expected
                )
            }
            DiskError::InvalidMagic => write!(f, "invalid result disk magic (expected HGRD)"),
            DiskError::UnsupportedVersion(v) => write!(f, "unsupported result disk version: {}", v),
            DiskError::UnsupportedFlags(fl) => write!(f, "unsupported result disk flags: {}", fl),
            DiskError::InvalidPayloadLength { len, max } => {
                write!(
                    f,
                    "invalid result disk payload length {} (max {})",
                    len, max
                )
            }
            DiskError::DigestMismatch => write!(f, "result disk SHA-256 digest mismatch"),
            DiskError::NonZeroPadding { offset } => {
                write!(f, "non-zero padding byte at offset {}", offset)
            }
            DiskError::DeserializeJson(e) => {
                write!(f, "failed to deserialize result disk JSON: {}", e)
            }
        }
    }
}

impl std::error::Error for DiskError {}

/// Serializes `payload` into the compact canonical JSON the host parser
/// (`hermetic-grader-result`) requires: keys in schema field order (`run`, `variant_set`,
/// `tests`, `supervisor` with `exit`, `tests_started`, `tests_finished`), `tests` sorted by
/// node ID, and no extraneous whitespace. The host re-serializes and rejects any other form.
pub fn canonical_payload_json(payload: &ResultPayload) -> Result<Vec<u8>, DiskError> {
    serde_json::to_vec(payload).map_err(|e| DiskError::SerializeJson(e.to_string()))
}

/// Encodes `payload` into an exact 1 MiB (`1,048,576` byte) `HGRD` result disk image.
///
/// Layout:
/// - `0..4`: `b"HGRD"`
/// - `4..6`: `version = 1u16` (big-endian)
/// - `6..8`: `flags = 0u16` (big-endian)
/// - `8..12`: `payload_len` (`u32` big-endian)
/// - `12..44`: SHA-256 digest of `payload`
/// - `44..(44 + payload_len)`: canonical JSON bytes
/// - `(44 + payload_len)..1_048_576`: `0x00` padding
pub fn encode_result_disk(payload: &ResultPayload) -> Result<Vec<u8>, DiskError> {
    let json_bytes = canonical_payload_json(payload)?;
    if json_bytes.len() > MAX_RESULT_PAYLOAD_BYTES {
        return Err(DiskError::PayloadTooLarge {
            len: json_bytes.len(),
            max: MAX_RESULT_PAYLOAD_BYTES,
        });
    }

    let payload_len_u32 =
        u32::try_from(json_bytes.len()).map_err(|_| DiskError::PayloadTooLarge {
            len: json_bytes.len(),
            max: MAX_RESULT_PAYLOAD_BYTES,
        })?;

    let digest = Sha256::digest(&json_bytes);

    let mut image = vec![0u8; RESULT_DISK_BYTES];
    if let Some(magic_slot) = image.get_mut(0..4) {
        magic_slot.copy_from_slice(RESULT_DISK_MAGIC);
    }
    if let Some(ver_slot) = image.get_mut(4..6) {
        ver_slot.copy_from_slice(&RESULT_DISK_VERSION.to_be_bytes());
    }
    if let Some(flags_slot) = image.get_mut(6..8) {
        flags_slot.copy_from_slice(&RESULT_DISK_FLAGS.to_be_bytes());
    }
    if let Some(len_slot) = image.get_mut(8..12) {
        len_slot.copy_from_slice(&payload_len_u32.to_be_bytes());
    }
    if let Some(hash_slot) = image.get_mut(12..44) {
        hash_slot.copy_from_slice(digest.as_slice());
    }
    let payload_end = RESULT_DISK_HEADER_BYTES.saturating_add(json_bytes.len());
    if let Some(payload_slot) = image.get_mut(RESULT_DISK_HEADER_BYTES..payload_end) {
        payload_slot.copy_from_slice(&json_bytes);
    }

    Ok(image)
}

/// Validates and decodes an exact 1 MiB `HGRD` result disk image.
pub fn decode_result_disk(image: &[u8]) -> Result<ResultPayload, DiskError> {
    if image.len() != RESULT_DISK_BYTES {
        return Err(DiskError::InvalidImageLength {
            actual: image.len(),
            expected: RESULT_DISK_BYTES,
        });
    }

    let magic = image.get(0..4).ok_or(DiskError::InvalidMagic)?;
    if magic != RESULT_DISK_MAGIC {
        return Err(DiskError::InvalidMagic);
    }

    let version_bytes = match (image.get(4).copied(), image.get(5).copied()) {
        (Some(b0), Some(b1)) => [b0, b1],
        _ => return Err(DiskError::InvalidMagic),
    };
    let version = u16::from_be_bytes(version_bytes);
    if version != RESULT_DISK_VERSION {
        return Err(DiskError::UnsupportedVersion(version));
    }

    let flags_bytes = match (image.get(6).copied(), image.get(7).copied()) {
        (Some(b0), Some(b1)) => [b0, b1],
        _ => return Err(DiskError::InvalidMagic),
    };
    let flags = u16::from_be_bytes(flags_bytes);
    if flags != RESULT_DISK_FLAGS {
        return Err(DiskError::UnsupportedFlags(flags));
    }

    let len_bytes = match (
        image.get(8).copied(),
        image.get(9).copied(),
        image.get(10).copied(),
        image.get(11).copied(),
    ) {
        (Some(b0), Some(b1), Some(b2), Some(b3)) => [b0, b1, b2, b3],
        _ => return Err(DiskError::InvalidMagic),
    };
    let payload_len_u32 = u32::from_be_bytes(len_bytes);
    let payload_len = payload_len_u32 as usize;
    if payload_len > MAX_RESULT_PAYLOAD_BYTES {
        return Err(DiskError::InvalidPayloadLength {
            len: payload_len_u32,
            max: MAX_RESULT_PAYLOAD_BYTES,
        });
    }

    let stored_digest = image.get(12..44).ok_or(DiskError::DigestMismatch)?;
    let payload_end = RESULT_DISK_HEADER_BYTES.saturating_add(payload_len);
    let payload_slice = image.get(RESULT_DISK_HEADER_BYTES..payload_end).ok_or(
        DiskError::InvalidPayloadLength {
            len: payload_len_u32,
            max: MAX_RESULT_PAYLOAD_BYTES,
        },
    )?;

    let computed_digest = Sha256::digest(payload_slice);
    if computed_digest.as_slice() != stored_digest {
        return Err(DiskError::DigestMismatch);
    }

    if let Some(padding) = image.get(payload_end..RESULT_DISK_BYTES) {
        if let Some((rel_idx, _)) = padding.iter().enumerate().find(|(_, &b)| b != 0) {
            return Err(DiskError::NonZeroPadding {
                offset: payload_end.saturating_add(rel_idx),
            });
        }
    }

    let payload: ResultPayload = serde_json::from_slice(payload_slice)
        .map_err(|e| DiskError::DeserializeJson(e.to_string()))?;
    Ok(payload)
}
