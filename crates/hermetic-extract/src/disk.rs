#![forbid(unsafe_code)]
//! Output drive header format for ExtractorVM (TR-EXT-2, TR-EXT-5).
//!
//! Layout of the raw output drive:
//! - `0..4`: `b"HEXD"` magic
//! - `4..6`: `version = 2u16` (big-endian)
//! - `6..8`: `status_code = 0u16` (big-endian, 0 = success, >0 = failure code)
//! - `8..16`: `payload_len` (`u64` big-endian, byte length of the HEXT stream)
//! - `16..48`: 32-byte run nonce matching kernel cmdline
//! - `48..80`: SHA-256 digest of the payload stream
//! - `80..(80 + payload_len)`: HEXT stream payload bytes
//! - `(80 + payload_len)..<drive_size>`: untouched trailing disk space

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed magic identifying an ExtractorVM output drive (`b"HEXD"`).
pub const EXTRACT_DISK_MAGIC: &[u8; 4] = b"HEXD";

/// Current wire format version (`2`).
pub const EXTRACT_DISK_VERSION: u16 = 2;

/// Fixed size of the output drive header in bytes (80).
pub const EXTRACT_DISK_HEADER_BYTES: usize = 80;

/// Hard ceiling on payload length (2 GiB).
pub const HARD_MAX_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Fixed failure codes written to the output drive header on abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum ExtractFailureCode {
    Success = 0,
    Timeout = 1,
    ConfigError = 2,
    MountError = 3,
    ExtractError = 4,
    IoError = 5,
    InternalError = 6,
    InProgress = 7,
    Unknown(u16),
}

impl ExtractFailureCode {
    pub const fn from_raw(code: u16) -> Self {
        match code {
            0 => ExtractFailureCode::Success,
            1 => ExtractFailureCode::Timeout,
            2 => ExtractFailureCode::ConfigError,
            3 => ExtractFailureCode::MountError,
            4 => ExtractFailureCode::ExtractError,
            5 => ExtractFailureCode::IoError,
            6 => ExtractFailureCode::InternalError,
            7 => ExtractFailureCode::InProgress,
            other => ExtractFailureCode::Unknown(other),
        }
    }

    pub const fn as_raw(self) -> u16 {
        match self {
            ExtractFailureCode::Success => 0,
            ExtractFailureCode::Timeout => 1,
            ExtractFailureCode::ConfigError => 2,
            ExtractFailureCode::MountError => 3,
            ExtractFailureCode::ExtractError => 4,
            ExtractFailureCode::IoError => 5,
            ExtractFailureCode::InternalError => 6,
            ExtractFailureCode::InProgress => 7,
            ExtractFailureCode::Unknown(code) => code,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ExtractFailureCode::Success => "success",
            ExtractFailureCode::Timeout => "timeout",
            ExtractFailureCode::ConfigError => "config_error",
            ExtractFailureCode::MountError => "mount_error",
            ExtractFailureCode::ExtractError => "extract_error",
            ExtractFailureCode::IoError => "io_error",
            ExtractFailureCode::InternalError => "internal_error",
            ExtractFailureCode::InProgress => "in_progress",
            ExtractFailureCode::Unknown(_) => "unknown_error",
        }
    }
}

impl fmt::Display for ExtractFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractFailureCode::Unknown(code) => write!(f, "unknown_error({})", code),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Fixed 80-byte header stored at the start of the raw output drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractDiskHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub failure_code: u16,
    pub payload_len: u64,
    pub nonce: [u8; 32],
    pub sha256: [u8; 32],
}

impl ExtractDiskHeader {
    /// Creates a success header for an extracted stream.
    pub fn new_success(nonce: [u8; 32], payload_len: u64, sha256: [u8; 32]) -> Self {
        Self {
            magic: *EXTRACT_DISK_MAGIC,
            version: EXTRACT_DISK_VERSION,
            failure_code: 0,
            payload_len,
            nonce,
            sha256,
        }
    }

    /// Creates a failure header with zero payload length and zeroed digest.
    pub fn new_failure(code: ExtractFailureCode, nonce: [u8; 32]) -> Self {
        Self {
            magic: *EXTRACT_DISK_MAGIC,
            version: EXTRACT_DISK_VERSION,
            failure_code: code.as_raw(),
            payload_len: 0,
            nonce,
            sha256: [0u8; 32],
        }
    }

    /// Serializes the header into fixed 80 bytes.
    pub fn encode(&self) -> [u8; EXTRACT_DISK_HEADER_BYTES] {
        let mut buf = [0u8; EXTRACT_DISK_HEADER_BYTES];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.version.to_be_bytes());
        buf[6..8].copy_from_slice(&self.failure_code.to_be_bytes());
        buf[8..16].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[16..48].copy_from_slice(&self.nonce);
        buf[48..80].copy_from_slice(&self.sha256);
        buf
    }

    /// Deserializes and validates basic header fields from 80 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DiskError> {
        if bytes.len() < EXTRACT_DISK_HEADER_BYTES {
            return Err(DiskError::TruncatedHeader {
                expected: EXTRACT_DISK_HEADER_BYTES,
                actual: bytes.len(),
            });
        }
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if &magic != EXTRACT_DISK_MAGIC {
            return Err(DiskError::InvalidMagic(magic));
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != EXTRACT_DISK_VERSION {
            return Err(DiskError::UnsupportedVersion(version));
        }
        let failure_code = u16::from_be_bytes([bytes[6], bytes[7]]);
        let payload_len = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[16..48]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[48..80]);

        Ok(Self {
            magic,
            version,
            failure_code,
            payload_len,
            nonce,
            sha256,
        })
    }

    /// Writes this header to the beginning of a seekable writer.
    pub fn write_to<W: Write + Seek>(&self, writer: &mut W) -> io::Result<()> {
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(&self.encode())?;
        writer.flush()
    }
}

/// Errors returned when parsing or validating an output drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskError {
    TruncatedHeader {
        expected: usize,
        actual: usize,
    },
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u16),
    NonceMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    FailureCode(u16),
    PayloadTooLarge {
        len: u64,
        max: u64,
    },
    TruncatedPayload {
        expected: u64,
        actual: u64,
    },
    Sha256Mismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    Io(String),
}

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiskError::TruncatedHeader { expected, actual } => {
                write!(
                    f,
                    "truncated output drive header: expected {} bytes, got {}",
                    expected, actual
                )
            }
            DiskError::InvalidMagic(m) => {
                write!(f, "invalid output drive magic (got {:?}, expected HEXD)", m)
            }
            DiskError::UnsupportedVersion(v) => {
                write!(f, "unsupported output drive version: {}", v)
            }
            DiskError::NonceMismatch { expected, actual } => {
                write!(
                    f,
                    "output drive nonce mismatch: expected {}, got {}",
                    crate::format::format_hex(expected),
                    crate::format::format_hex(actual),
                )
            }
            DiskError::FailureCode(c) => {
                let code_enum = ExtractFailureCode::from_raw(*c);
                write!(f, "extractor reported failure code {}: {}", c, code_enum)
            }
            DiskError::PayloadTooLarge { len, max } => {
                write!(f, "output payload length {} exceeds cap {} bytes", len, max)
            }
            DiskError::TruncatedPayload { expected, actual } => {
                write!(
                    f,
                    "truncated output payload: expected {} bytes, got {}",
                    expected, actual
                )
            }
            DiskError::Sha256Mismatch { expected, actual } => {
                write!(
                    f,
                    "output payload SHA-256 mismatch: expected {}, got {}",
                    crate::format::format_hex(expected),
                    crate::format::format_hex(actual)
                )
            }
            DiskError::Io(e) => write!(f, "I/O error during output drive operation: {}", e),
        }
    }
}

impl std::error::Error for DiskError {}

/// Parses and validates the output drive image from a byte slice.
///
/// Refuses truncated headers, invalid magic, unsupported versions, nonce mismatches,
/// non-zero failure codes, payload sizes exceeding `max_payload_bytes`, truncated payloads,
/// and SHA-256 digest mismatches.
pub fn parse_and_validate_disk<'a>(
    data: &'a [u8],
    expected_nonce: &[u8; 32],
    max_payload_bytes: u64,
) -> Result<(ExtractDiskHeader, &'a [u8]), DiskError> {
    let header = ExtractDiskHeader::decode(data)?;
    if header.nonce != *expected_nonce {
        return Err(DiskError::NonceMismatch {
            expected: *expected_nonce,
            actual: header.nonce,
        });
    }
    if header.failure_code != 0 {
        return Err(DiskError::FailureCode(header.failure_code));
    }
    let effective_cap = max_payload_bytes.min(HARD_MAX_PAYLOAD_BYTES);
    if header.payload_len > effective_cap {
        return Err(DiskError::PayloadTooLarge {
            len: header.payload_len,
            max: effective_cap,
        });
    }
    let payload_len_usize = match usize::try_from(header.payload_len) {
        Ok(len) => len,
        Err(_) => {
            return Err(DiskError::PayloadTooLarge {
                len: header.payload_len,
                max: effective_cap,
            });
        }
    };
    let total_required = EXTRACT_DISK_HEADER_BYTES.saturating_add(payload_len_usize);
    if data.len() < total_required {
        let available = data.len().saturating_sub(EXTRACT_DISK_HEADER_BYTES) as u64;
        return Err(DiskError::TruncatedPayload {
            expected: header.payload_len,
            actual: available,
        });
    }
    let payload = &data[EXTRACT_DISK_HEADER_BYTES..total_required];
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let computed_digest: [u8; 32] = hasher.finalize().into();
    if computed_digest != header.sha256 {
        return Err(DiskError::Sha256Mismatch {
            expected: header.sha256,
            actual: computed_digest,
        });
    }
    Ok((header, payload))
}

/// Helper that reads the output drive header and payload from any `Read + Seek`.
pub fn read_output_drive_stream<R: Read + Seek>(
    reader: &mut R,
    expected_nonce: &[u8; 32],
    max_payload_bytes: u64,
) -> Result<(ExtractDiskHeader, Vec<u8>), DiskError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| DiskError::Io(e.to_string()))?;
    let mut header_buf = [0u8; EXTRACT_DISK_HEADER_BYTES];
    reader
        .read_exact(&mut header_buf)
        .map_err(|_| DiskError::TruncatedHeader {
            expected: EXTRACT_DISK_HEADER_BYTES,
            actual: 0,
        })?;
    let header = ExtractDiskHeader::decode(&header_buf)?;
    if header.nonce != *expected_nonce {
        return Err(DiskError::NonceMismatch {
            expected: *expected_nonce,
            actual: header.nonce,
        });
    }
    if header.failure_code != 0 {
        return Err(DiskError::FailureCode(header.failure_code));
    }
    let effective_cap = max_payload_bytes.min(HARD_MAX_PAYLOAD_BYTES);
    if header.payload_len > effective_cap {
        return Err(DiskError::PayloadTooLarge {
            len: header.payload_len,
            max: effective_cap,
        });
    }
    let payload_len_usize = match usize::try_from(header.payload_len) {
        Ok(len) => len,
        Err(_) => {
            return Err(DiskError::PayloadTooLarge {
                len: header.payload_len,
                max: effective_cap,
            });
        }
    };

    let mut payload = vec![0u8; payload_len_usize];
    reader
        .read_exact(&mut payload)
        .map_err(|_| DiskError::TruncatedPayload {
            expected: header.payload_len,
            actual: 0,
        })?;

    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let computed_digest: [u8; 32] = hasher.finalize().into();
    if computed_digest != header.sha256 {
        return Err(DiskError::Sha256Mismatch {
            expected: header.sha256,
            actual: computed_digest,
        });
    }

    Ok((header, payload))
}
