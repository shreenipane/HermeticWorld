use std::fmt;
use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

use crate::{
    validate_relative_path, CapName, Caps, ExtractError, HARD_MAX_DEPTH, HARD_MAX_ENTRIES,
    HARD_MAX_FILE_BYTES, HARD_MAX_PATH_LEN, HARD_MAX_TOTAL_BYTES, MAX_CHUNK_BYTES,
    MAX_EINTR_RETRIES,
};

/// Magic header identifying a Hermetic Extract (`HEXT`) stream.
pub const STREAM_MAGIC: &[u8; 4] = b"HEXT";
/// Current wire format version.
pub const STREAM_VERSION: u16 = 1;

pub const RECORD_TYPE_FILE: u8 = 1;
pub const RECORD_TYPE_DIR: u8 = 2;
pub const RECORD_TYPE_DELETE: u8 = 3;
pub const RECORD_TYPE_END: u8 = 4;

pub const MODE_FILE_DEFAULT: u32 = 0o644;
pub const MODE_FILE_EXEC: u32 = 0o755;
pub const MODE_DIR: u32 = 0o755;
pub const MODE_ZERO: u32 = 0;

const STREAM_HEADER_LEN: usize = 6;
const RECORD_FIXED_HEADER_LEN: usize = 1 + 2 + 4 + 8 + 32;

/// Decoded stream record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    File {
        path: String,
        mode: u32,
        sha256: [u8; 32],
        data: Vec<u8>,
    },
    Dir {
        path: String,
        mode: u32,
    },
    Delete {
        path: String,
    },
    End {
        record_count: u64,
        stream_sha256: [u8; 32],
    },
}

/// Streaming writer that tracks record count and cumulative SHA-256 of preceding bytes.
pub(crate) struct StreamWriter<W: Write> {
    writer: W,
    hasher: Sha256,
    record_count: u64,
}

impl<W: Write> StreamWriter<W> {
    pub(crate) fn new(mut writer: W) -> Result<Self, ExtractError> {
        let mut header = [0u8; STREAM_HEADER_LEN];
        header[0..4].copy_from_slice(STREAM_MAGIC);
        header[4..6].copy_from_slice(&STREAM_VERSION.to_le_bytes());

        let mut hasher = Sha256::new();
        write_all_bounded(&mut writer, &header, "stream header", None)?;
        hasher.update(header);

        Ok(Self {
            writer,
            hasher,
            record_count: 0,
        })
    }

    pub(crate) fn write_file(
        &mut self,
        path: &str,
        mode: u32,
        sha256: [u8; 32],
        data: &[u8],
    ) -> Result<(), ExtractError> {
        if mode != MODE_FILE_DEFAULT && mode != MODE_FILE_EXEC {
            return Err(ExtractError::InvalidPath {
                path: path.to_string(),
                reason: "invalid file mode",
            });
        }
        let path_len = u16::try_from(path.len()).map_err(|_| ExtractError::CapExceeded {
            cap: CapName::PathLength,
            limit: u16::MAX as u64,
            actual: path.len() as u64,
        })?;
        let next_count = self
            .record_count
            .checked_add(1)
            .ok_or(ExtractError::RecordCountOverflow)?;

        self.write_record_prefix(
            RECORD_TYPE_FILE,
            path_len,
            path.as_bytes(),
            mode,
            data.len() as u64,
            &sha256,
            Some(path),
        )?;

        let mut offset: usize = 0;
        let max_chunks = (data.len() / MAX_CHUNK_BYTES).saturating_add(2);
        for _ in 0..max_chunks {
            if offset >= data.len() {
                break;
            }
            let end = offset.saturating_add(MAX_CHUNK_BYTES).min(data.len());
            if let Some(slice) = data.get(offset..end) {
                write_all_bounded(&mut self.writer, slice, "file payload", Some(path))?;
                self.hasher.update(slice);
            }
            offset = end;
        }

        self.record_count = next_count;
        Ok(())
    }

    pub(crate) fn write_dir(&mut self, path: &str) -> Result<(), ExtractError> {
        let path_len = u16::try_from(path.len()).map_err(|_| ExtractError::CapExceeded {
            cap: CapName::PathLength,
            limit: u16::MAX as u64,
            actual: path.len() as u64,
        })?;
        let next_count = self
            .record_count
            .checked_add(1)
            .ok_or(ExtractError::RecordCountOverflow)?;

        self.write_record_prefix(
            RECORD_TYPE_DIR,
            path_len,
            path.as_bytes(),
            MODE_DIR,
            0,
            &[0u8; 32],
            Some(path),
        )?;

        self.record_count = next_count;
        Ok(())
    }

    pub(crate) fn write_delete(&mut self, path: &str) -> Result<(), ExtractError> {
        let path_len = u16::try_from(path.len()).map_err(|_| ExtractError::CapExceeded {
            cap: CapName::PathLength,
            limit: u16::MAX as u64,
            actual: path.len() as u64,
        })?;
        let next_count = self
            .record_count
            .checked_add(1)
            .ok_or(ExtractError::RecordCountOverflow)?;

        self.write_record_prefix(
            RECORD_TYPE_DELETE,
            path_len,
            path.as_bytes(),
            MODE_ZERO,
            0,
            &[0u8; 32],
            Some(path),
        )?;

        self.record_count = next_count;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<W, ExtractError> {
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        self.write_record_prefix(
            RECORD_TYPE_END,
            0,
            &[],
            MODE_ZERO,
            self.record_count,
            &digest,
            None,
        )?;
        self.writer.flush().map_err(|e| ExtractError::Io {
            context: "stream flush",
            path: None,
            kind: e.kind(),
        })?;
        Ok(self.writer)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_record_prefix(
        &mut self,
        record_type: u8,
        path_len: u16,
        path_bytes: &[u8],
        mode: u32,
        size: u64,
        sha256: &[u8; 32],
        path_ctx: Option<&str>,
    ) -> Result<(), ExtractError> {
        let mut head = [0u8; 3];
        head[0] = record_type;
        head[1..3].copy_from_slice(&path_len.to_le_bytes());

        let mut tail = [0u8; 4 + 8 + 32];
        tail[0..4].copy_from_slice(&mode.to_le_bytes());
        tail[4..12].copy_from_slice(&size.to_le_bytes());
        tail[12..44].copy_from_slice(sha256);

        write_all_bounded(&mut self.writer, &head, "record header", path_ctx)?;
        self.hasher.update(head);

        if !path_bytes.is_empty() {
            write_all_bounded(&mut self.writer, path_bytes, "record path", path_ctx)?;
            self.hasher.update(path_bytes);
        }

        write_all_bounded(&mut self.writer, &tail, "record metadata", path_ctx)?;
        self.hasher.update(tail);
        Ok(())
    }
}

fn write_all_bounded<W: Write>(
    writer: &mut W,
    buf: &[u8],
    context: &'static str,
    path: Option<&str>,
) -> Result<(), ExtractError> {
    let mut written: usize = 0;
    let mut eintr_count: usize = 0;
    let max_iters = buf
        .len()
        .saturating_add(MAX_EINTR_RETRIES)
        .saturating_add(1);
    for _ in 0..max_iters {
        if written >= buf.len() {
            return Ok(());
        }
        let rem = buf.get(written..).unwrap_or(&[]);
        match writer.write(rem) {
            Ok(0) => {
                return Err(ExtractError::Io {
                    context,
                    path: path.map(str::to_string),
                    kind: io::ErrorKind::WriteZero,
                });
            }
            Ok(n) => {
                written = written.saturating_add(n);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                eintr_count = eintr_count.saturating_add(1);
                if eintr_count > MAX_EINTR_RETRIES {
                    return Err(ExtractError::Io {
                        context,
                        path: path.map(str::to_string),
                        kind: io::ErrorKind::Interrupted,
                    });
                }
            }
            Err(e) => {
                return Err(ExtractError::Io {
                    context,
                    path: path.map(str::to_string),
                    kind: e.kind(),
                });
            }
        }
    }
    Err(ExtractError::Io {
        context,
        path: path.map(str::to_string),
        kind: io::ErrorKind::Other,
    })
}

/// Typed error enum returned by [`decode`] and [`decode_with_caps`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    InvalidCaps {
        cap: CapName,
        reason: &'static str,
    },
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidRecordType(u8),
    InvalidUtf8,
    InvalidPath {
        path: String,
        reason: &'static str,
    },
    InvalidEndRecord {
        reason: &'static str,
    },
    InvalidMode {
        record_type: u8,
        mode: u32,
    },
    NonZeroSize {
        record_type: u8,
        size: u64,
    },
    NonZeroHash {
        record_type: u8,
    },
    CapExceeded {
        cap: CapName,
        limit: u64,
        actual: u64,
    },
    AllocationFailed,
    FileHashMismatch {
        path: String,
    },
    EndRecordCountMismatch {
        expected: u64,
        actual: u64,
    },
    StreamHashMismatch,
    TrailingBytes,
    Io(io::ErrorKind),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidCaps { cap, reason } => {
                write!(f, "invalid cap {}: {}", cap, reason)
            }
            DecodeError::Truncated => write!(f, "unexpected end of stream (truncated)"),
            DecodeError::InvalidMagic => write!(f, "invalid stream magic (expected HEXT)"),
            DecodeError::UnsupportedVersion(v) => write!(f, "unsupported stream version: {}", v),
            DecodeError::InvalidRecordType(t) => write!(f, "invalid record type: {}", t),
            DecodeError::InvalidUtf8 => write!(f, "record path is not valid UTF-8"),
            DecodeError::InvalidPath { path, reason } => {
                write!(f, "invalid record path '{}': {}", path, reason)
            }
            DecodeError::InvalidEndRecord { reason } => {
                write!(f, "invalid end record: {}", reason)
            }
            DecodeError::InvalidMode { record_type, mode } => {
                write!(
                    f,
                    "invalid mode 0o{:o} for record type {}",
                    mode, record_type
                )
            }
            DecodeError::NonZeroSize { record_type, size } => {
                write!(
                    f,
                    "expected zero size for record type {}, got {}",
                    record_type, size
                )
            }
            DecodeError::NonZeroHash { record_type } => {
                write!(f, "expected zero sha256 for record type {}", record_type)
            }
            DecodeError::CapExceeded { cap, limit, actual } => {
                write!(
                    f,
                    "cap exceeded while decoding: {} (limit {}, actual {})",
                    cap, limit, actual
                )
            }
            DecodeError::AllocationFailed => write!(f, "bounded allocation failed"),
            DecodeError::FileHashMismatch { path } => {
                write!(f, "file SHA-256 mismatch for '{}'", path)
            }
            DecodeError::EndRecordCountMismatch { expected, actual } => {
                write!(
                    f,
                    "end record count mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            DecodeError::StreamHashMismatch => {
                write!(f, "end record stream SHA-256 mismatch")
            }
            DecodeError::TrailingBytes => {
                write!(f, "unexpected trailing bytes after end record")
            }
            DecodeError::Io(kind) => write!(f, "stream I/O error: {:?}", kind),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decodes a `HEXT` stream using default [`Caps`].
pub fn decode<R: Read>(reader: R) -> Result<Vec<Record>, DecodeError> {
    decode_with_caps(reader, &Caps::default())
}

/// Decodes a `HEXT` stream while strictly enforcing `caps` prior to any allocation.
pub fn decode_with_caps<R: Read>(mut reader: R, caps: &Caps) -> Result<Vec<Record>, DecodeError> {
    caps.validate().map_err(|e| match e {
        ExtractError::InvalidCaps { cap, reason } => DecodeError::InvalidCaps { cap, reason },
        _ => DecodeError::InvalidCaps {
            cap: CapName::Entries,
            reason: "invalid caps",
        },
    })?;

    let mut header = [0u8; STREAM_HEADER_LEN];
    read_exact_or_truncated(&mut reader, &mut header)?;

    if header.get(0..4) != Some(STREAM_MAGIC.as_slice()) {
        return Err(DecodeError::InvalidMagic);
    }
    let ver_bytes = [header[4], header[5]];
    let version = u16::from_le_bytes(ver_bytes);
    if version != STREAM_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let mut stream_hasher = Sha256::new();
    stream_hasher.update(header);

    let mut records: Vec<Record> = Vec::new();
    let mut non_end_count: u64 = 0;
    let mut total_file_bytes: u64 = 0;

    let max_loop_records = caps.max_entries.min(HARD_MAX_ENTRIES).saturating_add(1);

    for _ in 0..max_loop_records {
        let mut type_and_len = [0u8; 3];
        read_exact_or_truncated(&mut reader, &mut type_and_len)?;

        let record_type = type_and_len[0];
        if !(RECORD_TYPE_FILE..=RECORD_TYPE_END).contains(&record_type) {
            return Err(DecodeError::InvalidRecordType(record_type));
        }

        let path_len = u16::from_le_bytes([type_and_len[1], type_and_len[2]]) as usize;
        if path_len > caps.max_path_len || path_len > HARD_MAX_PATH_LEN {
            return Err(DecodeError::CapExceeded {
                cap: CapName::PathLength,
                limit: caps.max_path_len as u64,
                actual: path_len as u64,
            });
        }

        let mut path_buf: Vec<u8> = Vec::new();
        if path_len > 0 {
            path_buf
                .try_reserve_exact(path_len)
                .map_err(|_| DecodeError::AllocationFailed)?;
            path_buf.resize(path_len, 0);
            read_exact_or_truncated(&mut reader, &mut path_buf)?;
        }

        let mut fixed_tail = [0u8; RECORD_FIXED_HEADER_LEN - 3];
        read_exact_or_truncated(&mut reader, &mut fixed_tail)?;

        let mode = u32::from_le_bytes([fixed_tail[0], fixed_tail[1], fixed_tail[2], fixed_tail[3]]);
        let size = u64::from_le_bytes([
            fixed_tail[4],
            fixed_tail[5],
            fixed_tail[6],
            fixed_tail[7],
            fixed_tail[8],
            fixed_tail[9],
            fixed_tail[10],
            fixed_tail[11],
        ]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&fixed_tail[12..44]);

        if record_type == RECORD_TYPE_END {
            if !path_buf.is_empty() {
                return Err(DecodeError::InvalidEndRecord {
                    reason: "end record path must be empty",
                });
            }
            if mode != MODE_ZERO {
                return Err(DecodeError::InvalidMode {
                    record_type: RECORD_TYPE_END,
                    mode,
                });
            }
            if size != non_end_count {
                return Err(DecodeError::EndRecordCountMismatch {
                    expected: non_end_count,
                    actual: size,
                });
            }
            let expected_stream_digest: [u8; 32] = stream_hasher.finalize().into();
            if expected_stream_digest != sha256 {
                return Err(DecodeError::StreamHashMismatch);
            }

            // Ensure no trailing bytes exist after the end record.
            let mut trailing = [0u8; 1];
            match read_single_probe(&mut reader, &mut trailing)? {
                0 => {}
                _ => return Err(DecodeError::TrailingBytes),
            }

            records
                .try_reserve_exact(1)
                .map_err(|_| DecodeError::AllocationFailed)?;
            records.push(Record::End {
                record_count: size,
                stream_sha256: sha256,
            });
            return Ok(records);
        }

        // Non-end record: enforce entry count cap.
        let next_entries = non_end_count
            .checked_add(1)
            .ok_or(DecodeError::CapExceeded {
                cap: CapName::Entries,
                limit: caps.max_entries as u64,
                actual: u64::MAX,
            })?;
        if next_entries > caps.max_entries as u64 || next_entries > HARD_MAX_ENTRIES as u64 {
            return Err(DecodeError::CapExceeded {
                cap: CapName::Entries,
                limit: caps.max_entries as u64,
                actual: next_entries,
            });
        }

        let path = String::from_utf8(path_buf).map_err(|_| DecodeError::InvalidUtf8)?;
        validate_relative_path(&path).map_err(|e| match e {
            ExtractError::CapExceeded { cap, limit, actual } => {
                DecodeError::CapExceeded { cap, limit, actual }
            }
            ExtractError::InvalidPath { path, reason } => DecodeError::InvalidPath { path, reason },
            _ => DecodeError::InvalidPath {
                path: path.clone(),
                reason: "invalid relative path",
            },
        })?;

        let depth = path.split('/').count();
        if depth > caps.max_depth || depth > HARD_MAX_DEPTH {
            return Err(DecodeError::CapExceeded {
                cap: CapName::Depth,
                limit: caps.max_depth as u64,
                actual: depth as u64,
            });
        }

        // Update stream hasher with this record's header fields.
        stream_hasher.update(type_and_len);
        stream_hasher.update(path.as_bytes());
        stream_hasher.update(fixed_tail);

        match record_type {
            RECORD_TYPE_FILE => {
                if mode != MODE_FILE_DEFAULT && mode != MODE_FILE_EXEC {
                    return Err(DecodeError::InvalidMode {
                        record_type: RECORD_TYPE_FILE,
                        mode,
                    });
                }
                if size > caps.max_file_bytes || size > HARD_MAX_FILE_BYTES {
                    return Err(DecodeError::CapExceeded {
                        cap: CapName::PerFileBytes,
                        limit: caps.max_file_bytes,
                        actual: size,
                    });
                }
                let next_total =
                    total_file_bytes
                        .checked_add(size)
                        .ok_or(DecodeError::CapExceeded {
                            cap: CapName::TotalBytes,
                            limit: caps.max_total_bytes,
                            actual: u64::MAX,
                        })?;
                if next_total > caps.max_total_bytes || next_total > HARD_MAX_TOTAL_BYTES {
                    return Err(DecodeError::CapExceeded {
                        cap: CapName::TotalBytes,
                        limit: caps.max_total_bytes,
                        actual: next_total,
                    });
                }

                let size_usize =
                    usize::try_from(size).map_err(|_| DecodeError::AllocationFailed)?;
                let mut data: Vec<u8> = Vec::new();
                if size_usize > 0 {
                    data.try_reserve_exact(size_usize)
                        .map_err(|_| DecodeError::AllocationFailed)?;
                }

                let mut file_hasher = Sha256::new();
                let mut chunk = [0u8; MAX_CHUNK_BYTES];
                let mut remaining = size_usize;
                let max_chunks = (size_usize / MAX_CHUNK_BYTES).saturating_add(2);

                for _ in 0..max_chunks {
                    if remaining == 0 {
                        break;
                    }
                    let to_read = remaining.min(MAX_CHUNK_BYTES);
                    if let Some(buf_slice) = chunk.get_mut(..to_read) {
                        read_exact_or_truncated(&mut reader, buf_slice)?;
                        file_hasher.update(&*buf_slice);
                        stream_hasher.update(&*buf_slice);
                        data.extend_from_slice(buf_slice);
                    }
                    remaining = remaining.saturating_sub(to_read);
                }

                let computed_file_hash: [u8; 32] = file_hasher.finalize().into();
                if computed_file_hash != sha256 {
                    return Err(DecodeError::FileHashMismatch { path });
                }

                total_file_bytes = next_total;
                non_end_count = next_entries;
                records
                    .try_reserve_exact(1)
                    .map_err(|_| DecodeError::AllocationFailed)?;
                records.push(Record::File {
                    path,
                    mode,
                    sha256,
                    data,
                });
            }
            RECORD_TYPE_DIR => {
                if mode != MODE_DIR {
                    return Err(DecodeError::InvalidMode {
                        record_type: RECORD_TYPE_DIR,
                        mode,
                    });
                }
                if size != 0 {
                    return Err(DecodeError::NonZeroSize {
                        record_type: RECORD_TYPE_DIR,
                        size,
                    });
                }
                if sha256 != [0u8; 32] {
                    return Err(DecodeError::NonZeroHash {
                        record_type: RECORD_TYPE_DIR,
                    });
                }
                non_end_count = next_entries;
                records
                    .try_reserve_exact(1)
                    .map_err(|_| DecodeError::AllocationFailed)?;
                records.push(Record::Dir { path, mode });
            }
            RECORD_TYPE_DELETE => {
                if mode != MODE_ZERO {
                    return Err(DecodeError::InvalidMode {
                        record_type: RECORD_TYPE_DELETE,
                        mode,
                    });
                }
                if size != 0 {
                    return Err(DecodeError::NonZeroSize {
                        record_type: RECORD_TYPE_DELETE,
                        size,
                    });
                }
                if sha256 != [0u8; 32] {
                    return Err(DecodeError::NonZeroHash {
                        record_type: RECORD_TYPE_DELETE,
                    });
                }
                non_end_count = next_entries;
                records
                    .try_reserve_exact(1)
                    .map_err(|_| DecodeError::AllocationFailed)?;
                records.push(Record::Delete { path });
            }
            other => return Err(DecodeError::InvalidRecordType(other)),
        }
    }

    Err(DecodeError::CapExceeded {
        cap: CapName::Entries,
        limit: caps.max_entries as u64,
        actual: non_end_count.saturating_add(1),
    })
}

fn read_exact_or_truncated<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), DecodeError> {
    let mut filled: usize = 0;
    let mut eintr_count: usize = 0;
    let max_iters = buf
        .len()
        .saturating_add(MAX_EINTR_RETRIES)
        .saturating_add(1);
    for _ in 0..max_iters {
        if filled >= buf.len() {
            return Ok(());
        }
        let rem = buf.get_mut(filled..).unwrap_or(&mut []);
        match reader.read(rem) {
            Ok(0) => return Err(DecodeError::Truncated),
            Ok(n) => {
                filled = filled.saturating_add(n);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                eintr_count = eintr_count.saturating_add(1);
                if eintr_count > MAX_EINTR_RETRIES {
                    return Err(DecodeError::Io(io::ErrorKind::Interrupted));
                }
            }
            Err(e) => return Err(DecodeError::Io(e.kind())),
        }
    }
    Err(DecodeError::Truncated)
}

fn read_single_probe<R: Read>(reader: &mut R, buf: &mut [u8; 1]) -> Result<usize, DecodeError> {
    let mut eintr_count: usize = 0;
    for _ in 0..=MAX_EINTR_RETRIES {
        match reader.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                eintr_count = eintr_count.saturating_add(1);
            }
            Err(e) => return Err(DecodeError::Io(e.kind())),
        }
    }
    Err(DecodeError::Io(io::ErrorKind::Interrupted))
}
