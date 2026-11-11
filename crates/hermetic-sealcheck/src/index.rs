#![forbid(unsafe_code)]

//! Layer index and per-task query module (TR-SC-10).
//!
//! # Format Specification
//!
//! An index file is a `zstd`-compressed stream representing a serialized layer index.
//!
//! ## Header
//!
//! - **Magic** (6 bytes): ASCII `HWIDX1`
//! - **Format Version** (2 bytes, `u16` little-endian): `1`
//! - **Root Path Length** (4 bytes, `u32` little-endian): byte length of the UTF-8 root path
//! - **Root Path** (`root_len` bytes): UTF-8 string of the scan root directory
//! - **Unit Count** (8 bytes, `u64` little-endian): total number of unit records in the index
//!
//! ## Unit Records
//!
//! Following the header is a sequence of `unit_count` length-prefixed records.
//! Each record begins with:
//! - **Record Length** (4 bytes, `u32` little-endian): byte length of the record payload.
//!
//! Inside the record payload:
//! - **Path Length** (2 bytes, `u16` little-endian): byte length of the unit path
//! - **Unit Path** (UTF-8 bytes): root-relative path (with `!/` for container members and `#` for cells/blobs)
//! - **Size** (8 bytes, `u64` little-endian): unit size in bytes
//! - **Mtime** (8 bytes, `i64` little-endian): Unix timestamp in seconds
//! - **Mode** (4 bytes, `u32` little-endian): filesystem permissions / mode bits
//! - **Flags** (1 byte, `u8` bitfield):
//!   - Bit 0 (`0x01`): contains `UnitHashes` (text unit)
//!   - Bit 1 (`0x02`): contains `BinaryHashes` (binary unit / minified bundle / pyc)
//!   - Bit 2 (`0x04`): contains `PkgMetadata` (package metadata unit)
//!   - Bit 3 (`0x08`): contains `BuiltinD9Hits` (builtin D9 content hits)
//!   - Bit 4 (`0x10`): contains info findings (errors, bombs, skipped files)
//!
//! Optional fields based on `Flags`:
//!
//! - If Bit 0 (`UnitHashes`):
//!   - `line_hashes`: `u32` count + `count * 8` bytes (`u64` LE each)
//!   - `window_hashes`: `u32` count + `count * 8` bytes (`u64` LE each)
//!   - `removed_marker_hashes`: `u32` count + `count * 8` bytes (`u64` LE each)
//!   - `diff_shape_hashes`: `u32` count + `count * 8` bytes (`u64` LE each)
//!   - `winnow_hashes`: `u32` count + `count * 8` bytes (`u64` LE each)
//!
//! - If Bit 1 (`BinaryHashes`):
//!   - `channel`: `u8` length + UTF-8 channel string
//!   - `exact_strings`: `u32` count + `count * 8` bytes (`u64` LE each)
//!   - `token_hashes`: `u32` count + `count * 8` bytes (`u64` LE each)
//!
//!   *Limit Note*: Binary items containing characters outside `[A-Za-z0-9_]` can only match
//!   a stored exact string, not a run token.
//!
//! - If Bit 2 (`PkgMetadata`):
//!   - `has_name`: `u8` (0 or 1). If 1: `u16` length + UTF-8 name
//!   - `has_version`: `u8` (0 or 1). If 1: `u16` length + UTF-8 version
//!
//! - If Bit 3 (`BuiltinD9Hits`):
//!   - `canary_count`: `u16` LE. For each: `u16` length + UTF-8 canary string
//!   - `host_count`: `u16` LE. For each: `u16` length + UTF-8 host string
//!   - `dataset_dump`: `u8` (0 or 1)
//!
//! - If Bit 4 (info findings):
//!   - `finding_count`: `u16` LE.
//!   - For each finding:
//!     - `detector`: `u8` length + UTF-8
//!     - `channel`: `u8` length + UTF-8
//!     - `path`: `u16` length + UTF-8
//!     - `severity`: `u8` (0 = Gate, 1 = Review, 2 = Info)
//!     - `confidence`: `f64` (8 bytes LE)
//!     - `hunk`: `i32` LE (-1 if None, else hunk index)
//!     - `evidence_count`: `u16` LE. For each: `u16` length + UTF-8

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::benchmark::{
    check_d9_path_with_display, check_is_dataset_dump, BUILTIN_CANARIES, BUILTIN_DATASET_HOSTS,
};
use crate::binary::{
    extract_printable_runs, extract_pyc_strings, is_minified_bundle, parse_class, parse_elf,
    parse_minified, parse_wasm, BinaryMalformed, BinaryStrings,
};
use crate::containers::{
    detect_container_type, extract_pyc_constants, is_tar, ContainerType, CountingReader,
};
use crate::d5a::{check_d5a_name_and_version, is_pkg_metadata_file, parse_pkg_metadata};
use crate::fingerprint::{sha256_u64, FingerprintSet};
use crate::scan::{
    compute_unit_hashes, match_unit_hashes, Finding, ScanOptions, Severity, UnitHashes, Visibility,
};

pub const INDEX_MAGIC: &[u8; 6] = b"HWIDX1";
pub const INDEX_FORMAT_VERSION: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid magic: expected HWIDX1")]
    BadMagic,
    #[error("Unsupported index format version: {0}")]
    UnsupportedVersion(u16),
    #[error("Truncated index stream: {0}")]
    Truncated(String),
    #[error("Invalid count or length: {0}")]
    InvalidCount(String),
    #[error("Malformed record: {0}")]
    Malformed(String),
    #[error("Decompression error: {0}")]
    Decompress(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexHeader {
    pub magic: [u8; 6],
    pub version: u16,
    pub root_path: String,
    pub unit_count: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnitMeta {
    pub size: u64,
    pub mtime: i64,
    pub mode: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BinaryHashes {
    pub channel: String,
    pub exact_strings: Vec<u64>,
    pub token_hashes: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PkgMetadata {
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuiltinD9Hits {
    pub canaries: Vec<String>,
    pub dataset_hosts: Vec<String>,
    pub dataset_dump: bool,
}

impl BuiltinD9Hits {
    pub fn is_empty(&self) -> bool {
        self.canaries.is_empty() && self.dataset_hosts.is_empty() && !self.dataset_dump
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IndexRecord {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub mode: u32,
    pub text_hashes: Option<UnitHashes>,
    pub builtin_d9: BuiltinD9Hits,
    pub binary_hashes: Option<BinaryHashes>,
    pub pkg_metadata: Option<PkgMetadata>,
    pub info_findings: Vec<Finding>,
}

fn read_exact_bytes<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8], IndexError> {
    if cursor.len() < n {
        return Err(IndexError::Truncated(format!(
            "needed {} bytes, but only {} remaining",
            n,
            cursor.len()
        )));
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

fn read_u8(cursor: &mut &[u8]) -> Result<u8, IndexError> {
    let slice = read_exact_bytes(cursor, 1)?;
    Ok(slice[0])
}

fn read_u16_le(cursor: &mut &[u8]) -> Result<u16, IndexError> {
    let slice = read_exact_bytes(cursor, 2)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(cursor: &mut &[u8]) -> Result<u32, IndexError> {
    let slice = read_exact_bytes(cursor, 4)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i64_le(cursor: &mut &[u8]) -> Result<i64, IndexError> {
    let slice = read_exact_bytes(cursor, 8)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(slice);
    Ok(i64::from_le_bytes(b))
}

fn read_u64_le(cursor: &mut &[u8]) -> Result<u64, IndexError> {
    let slice = read_exact_bytes(cursor, 8)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(slice);
    Ok(u64::from_le_bytes(b))
}

fn read_f64_le(cursor: &mut &[u8]) -> Result<f64, IndexError> {
    let slice = read_exact_bytes(cursor, 8)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(slice);
    Ok(f64::from_le_bytes(b))
}

fn read_string_u16(cursor: &mut &[u8]) -> Result<String, IndexError> {
    let len = read_u16_le(cursor)? as usize;
    let bytes = read_exact_bytes(cursor, len)?;
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| IndexError::Malformed(format!("invalid UTF-8 string: {e}")))
}

fn read_string_u8(cursor: &mut &[u8]) -> Result<String, IndexError> {
    let len = read_u8(cursor)? as usize;
    let bytes = read_exact_bytes(cursor, len)?;
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| IndexError::Malformed(format!("invalid UTF-8 string: {e}")))
}

fn read_u64_vec(cursor: &mut &[u8]) -> Result<Vec<u64>, IndexError> {
    let count = read_u32_le(cursor)? as usize;
    let total_bytes = count
        .checked_mul(8)
        .ok_or_else(|| IndexError::InvalidCount("u64 array count overflow".into()))?;
    if cursor.len() < total_bytes {
        return Err(IndexError::Truncated(format!(
            "u64 array requires {} bytes, only {} available",
            total_bytes,
            cursor.len()
        )));
    }
    let mut vec = Vec::with_capacity(count);
    for _ in 0..count {
        vec.push(read_u64_le(cursor)?);
    }
    Ok(vec)
}

fn read_u64_hashset(cursor: &mut &[u8]) -> Result<HashSet<u64>, IndexError> {
    let vec = read_u64_vec(cursor)?;
    Ok(vec.into_iter().collect())
}

/// Extract all `[A-Za-z0-9_]+` tokens of at least 8 characters from printable runs,
/// and hash each to u64 using the first 8 bytes of its sha256.
pub fn extract_token_hashes_from_runs(runs: &[String]) -> Vec<u64> {
    let mut hashes = HashSet::new();
    for run in runs {
        let mut start = None;
        for (i, b) in run.bytes().enumerate() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                let token = &run[s..i];
                if token.len() >= 8 {
                    hashes.insert(sha256_u64(token.as_bytes()));
                }
                start = None;
            }
        }
        if let Some(s) = start {
            let token = &run[s..];
            if token.len() >= 8 {
                hashes.insert(sha256_u64(token.as_bytes()));
            }
        }
    }
    let mut vec: Vec<u64> = hashes.into_iter().collect();
    vec.sort_unstable();
    vec
}

pub fn hash_exact_strings(exact_strings: &HashSet<String>) -> Vec<u64> {
    let mut vec: Vec<u64> = exact_strings
        .iter()
        .map(|s| sha256_u64(s.as_bytes()))
        .collect();
    vec.sort_unstable();
    vec.dedup();
    vec
}

/// Encode a single IndexRecord into little-endian bytes without the leading u32 record length.
pub fn encode_record_payload(record: &IndexRecord) -> Vec<u8> {
    let mut buf = Vec::new();

    // path: u16 len + UTF-8
    let path_bytes = record.path.as_bytes();
    buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(path_bytes);

    // size: u64
    buf.extend_from_slice(&record.size.to_le_bytes());

    // mtime: i64
    buf.extend_from_slice(&record.mtime.to_le_bytes());

    // mode: u32
    buf.extend_from_slice(&record.mode.to_le_bytes());

    // flags: u8
    let mut flags: u8 = 0;
    if record.text_hashes.is_some() {
        flags |= 0x01;
    }
    if record.binary_hashes.is_some() {
        flags |= 0x02;
    }
    if record.pkg_metadata.is_some() {
        flags |= 0x04;
    }
    if !record.builtin_d9.is_empty() {
        flags |= 0x08;
    }
    if !record.info_findings.is_empty() {
        flags |= 0x10;
    }
    buf.push(flags);

    // Bit 0: UnitHashes
    if let Some(ref uh) = record.text_hashes {
        let mut write_hash_set = |set: &HashSet<u64>| {
            let mut items: Vec<u64> = set.iter().copied().collect();
            items.sort_unstable();
            buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
            for h in items {
                buf.extend_from_slice(&h.to_le_bytes());
            }
        };
        write_hash_set(&uh.line_hashes);
        write_hash_set(&uh.window_hashes);
        write_hash_set(&uh.removed_marker_hashes);
        write_hash_set(&uh.diff_shape_hashes);
        write_hash_set(&uh.winnow_hashes);
    }

    // Bit 1: BinaryHashes
    if let Some(ref bh) = record.binary_hashes {
        let ch_bytes = bh.channel.as_bytes();
        buf.push(ch_bytes.len() as u8);
        buf.extend_from_slice(ch_bytes);

        buf.extend_from_slice(&(bh.exact_strings.len() as u32).to_le_bytes());
        for h in &bh.exact_strings {
            buf.extend_from_slice(&h.to_le_bytes());
        }

        buf.extend_from_slice(&(bh.token_hashes.len() as u32).to_le_bytes());
        for h in &bh.token_hashes {
            buf.extend_from_slice(&h.to_le_bytes());
        }
    }

    // Bit 2: PkgMetadata
    if let Some(ref meta) = record.pkg_metadata {
        if let Some(ref name) = meta.name {
            buf.push(1);
            let nb = name.as_bytes();
            buf.extend_from_slice(&(nb.len() as u16).to_le_bytes());
            buf.extend_from_slice(nb);
        } else {
            buf.push(0);
        }

        if let Some(ref ver) = meta.version {
            buf.push(1);
            let vb = ver.as_bytes();
            buf.extend_from_slice(&(vb.len() as u16).to_le_bytes());
            buf.extend_from_slice(vb);
        } else {
            buf.push(0);
        }
    }

    // Bit 3: BuiltinD9Hits
    if !record.builtin_d9.is_empty() {
        buf.extend_from_slice(&(record.builtin_d9.canaries.len() as u16).to_le_bytes());
        for canary in &record.builtin_d9.canaries {
            let cb = canary.as_bytes();
            buf.extend_from_slice(&(cb.len() as u16).to_le_bytes());
            buf.extend_from_slice(cb);
        }

        buf.extend_from_slice(&(record.builtin_d9.dataset_hosts.len() as u16).to_le_bytes());
        for host in &record.builtin_d9.dataset_hosts {
            let hb = host.as_bytes();
            buf.extend_from_slice(&(hb.len() as u16).to_le_bytes());
            buf.extend_from_slice(hb);
        }

        buf.push(if record.builtin_d9.dataset_dump { 1 } else { 0 });
    }

    // Bit 4: info_findings
    if !record.info_findings.is_empty() {
        buf.extend_from_slice(&(record.info_findings.len() as u16).to_le_bytes());
        for f in &record.info_findings {
            let det_bytes = f.detector.as_bytes();
            buf.push(det_bytes.len() as u8);
            buf.extend_from_slice(det_bytes);

            let ch_bytes = f.channel.as_bytes();
            buf.push(ch_bytes.len() as u8);
            buf.extend_from_slice(ch_bytes);

            let p_bytes = f.path.as_bytes();
            buf.extend_from_slice(&(p_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(p_bytes);

            let sev = match f.severity {
                Severity::Gate => 0u8,
                Severity::Review => 1u8,
                Severity::Info => 2u8,
            };
            buf.push(sev);

            buf.extend_from_slice(&f.confidence.to_le_bytes());

            let hunk_val: i32 = match f.hunk {
                Some(idx) => idx as i32,
                None => -1,
            };
            buf.extend_from_slice(&hunk_val.to_le_bytes());

            buf.extend_from_slice(&(f.evidence.len() as u16).to_le_bytes());
            for ev in &f.evidence {
                let ev_bytes = ev.as_bytes();
                buf.extend_from_slice(&(ev_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(ev_bytes);
            }
        }
    }

    buf
}

/// Decode an IndexRecord from a buffer slice starting with the record payload.
pub fn decode_record_payload(mut cursor: &[u8]) -> Result<IndexRecord, IndexError> {
    let path = read_string_u16(&mut cursor)?;
    let size = read_u64_le(&mut cursor)?;
    let mtime = read_i64_le(&mut cursor)?;
    let mode = read_u32_le(&mut cursor)?;
    let flags = read_u8(&mut cursor)?;

    let text_hashes = if (flags & 0x01) != 0 {
        let line_hashes = read_u64_hashset(&mut cursor)?;
        let window_hashes = read_u64_hashset(&mut cursor)?;
        let removed_marker_hashes = read_u64_hashset(&mut cursor)?;
        let diff_shape_hashes = read_u64_hashset(&mut cursor)?;
        let winnow_hashes = read_u64_hashset(&mut cursor)?;
        Some(UnitHashes {
            line_hashes,
            window_hashes,
            removed_marker_hashes,
            diff_shape_hashes,
            winnow_hashes,
        })
    } else {
        None
    };

    let binary_hashes = if (flags & 0x02) != 0 {
        let channel = read_string_u8(&mut cursor)?;
        let exact_strings = read_u64_vec(&mut cursor)?;
        let token_hashes = read_u64_vec(&mut cursor)?;
        Some(BinaryHashes {
            channel,
            exact_strings,
            token_hashes,
        })
    } else {
        None
    };

    let pkg_metadata = if (flags & 0x04) != 0 {
        let has_name = read_u8(&mut cursor)?;
        let name = if has_name != 0 {
            Some(read_string_u16(&mut cursor)?)
        } else {
            None
        };

        let has_version = read_u8(&mut cursor)?;
        let version = if has_version != 0 {
            Some(read_string_u16(&mut cursor)?)
        } else {
            None
        };
        Some(PkgMetadata { name, version })
    } else {
        None
    };

    let builtin_d9 = if (flags & 0x08) != 0 {
        let canary_count = read_u16_le(&mut cursor)? as usize;
        let mut canaries = Vec::with_capacity(canary_count);
        for _ in 0..canary_count {
            canaries.push(read_string_u16(&mut cursor)?);
        }

        let host_count = read_u16_le(&mut cursor)? as usize;
        let mut dataset_hosts = Vec::with_capacity(host_count);
        for _ in 0..host_count {
            dataset_hosts.push(read_string_u16(&mut cursor)?);
        }

        let dump_byte = read_u8(&mut cursor)?;
        BuiltinD9Hits {
            canaries,
            dataset_hosts,
            dataset_dump: dump_byte != 0,
        }
    } else {
        BuiltinD9Hits::default()
    };

    let info_findings = if (flags & 0x10) != 0 {
        let finding_count = read_u16_le(&mut cursor)? as usize;
        let mut findings = Vec::with_capacity(finding_count);
        for _ in 0..finding_count {
            let detector = read_string_u8(&mut cursor)?;
            let channel = read_string_u8(&mut cursor)?;
            let path = read_string_u16(&mut cursor)?;
            let sev_byte = read_u8(&mut cursor)?;
            let severity = match sev_byte {
                0 => Severity::Gate,
                1 => Severity::Review,
                _ => Severity::Info,
            };
            let confidence = read_f64_le(&mut cursor)?;
            let hunk_val = read_u32_le(&mut cursor)? as i32;
            let hunk = if hunk_val >= 0 {
                Some(hunk_val as usize)
            } else {
                None
            };
            let ev_count = read_u16_le(&mut cursor)? as usize;
            let mut evidence = Vec::with_capacity(ev_count);
            for _ in 0..ev_count {
                evidence.push(read_string_u16(&mut cursor)?);
            }
            findings.push(Finding {
                detector,
                channel,
                path,
                visibility: Visibility::AgentVisible,
                severity,
                confidence,
                hunk,
                evidence,
            });
        }
        findings
    } else {
        Vec::new()
    };

    Ok(IndexRecord {
        path,
        size,
        mtime,
        mode,
        text_hashes,
        builtin_d9,
        binary_hashes,
        pkg_metadata,
        info_findings,
    })
}

/// Write a full layer index to a writer, compressed with zstd.
pub fn write_index<W: Write>(
    root_path: &str,
    records: &[IndexRecord],
    writer: W,
) -> Result<(), IndexError> {
    let mut encoder = zstd::stream::write::Encoder::new(writer, 3)
        .map_err(|e| IndexError::Io(io::Error::other(format!("zstd init error: {e}"))))?;

    // Header:
    // Magic: HWIDX1
    encoder.write_all(INDEX_MAGIC)?;
    // Version: u16 LE
    encoder.write_all(&INDEX_FORMAT_VERSION.to_le_bytes())?;
    // Root path: u32 len + UTF-8
    let root_bytes = root_path.as_bytes();
    encoder.write_all(&(root_bytes.len() as u32).to_le_bytes())?;
    encoder.write_all(root_bytes)?;
    // Unit count: u64 LE
    encoder.write_all(&(records.len() as u64).to_le_bytes())?;

    // Records
    for r in records {
        let payload = encode_record_payload(r);
        encoder.write_all(&(payload.len() as u32).to_le_bytes())?;
        encoder.write_all(&payload)?;
    }

    encoder
        .finish()
        .map_err(|e| IndexError::Io(io::Error::other(format!("zstd finish error: {e}"))))?;
    Ok(())
}

/// Read and validate an index from a reader. Rejects bad magic, unsupported version,
/// truncation, oversized lengths, and corrupt zstd frames without panicking.
pub fn read_index<R: Read>(reader: R) -> Result<(IndexHeader, Vec<IndexRecord>), IndexError> {
    let mut decoder = match zstd::stream::read::Decoder::new(reader) {
        Ok(d) => d,
        Err(e) => return Err(IndexError::Decompress(format!("invalid zstd frame: {e}"))),
    };

    let mut decompressed = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut decompressed) {
        return Err(IndexError::Decompress(format!(
            "error decompressing index stream: {e}"
        )));
    }

    let mut cursor = decompressed.as_slice();

    // 1. Magic
    let magic_bytes = read_exact_bytes(&mut cursor, 6)
        .map_err(|_| IndexError::Truncated("missing magic".into()))?;
    if magic_bytes != INDEX_MAGIC {
        return Err(IndexError::BadMagic);
    }
    let mut magic = [0u8; 6];
    magic.copy_from_slice(magic_bytes);

    // 2. Version
    let version = read_u16_le(&mut cursor)
        .map_err(|_| IndexError::Truncated("missing format version".into()))?;
    if version != INDEX_FORMAT_VERSION {
        return Err(IndexError::UnsupportedVersion(version));
    }

    // 3. Root path length and string
    let root_len = read_u32_le(&mut cursor)
        .map_err(|_| IndexError::Truncated("missing root path length".into()))?
        as usize;
    if cursor.len() < root_len {
        return Err(IndexError::Truncated(format!(
            "root path length {} exceeds remaining bytes {}",
            root_len,
            cursor.len()
        )));
    }
    let root_bytes = read_exact_bytes(&mut cursor, root_len)?;
    let root_path = std::str::from_utf8(root_bytes)
        .map_err(|e| IndexError::Malformed(format!("invalid root path UTF-8: {e}")))?
        .to_string();

    // 4. Unit count
    let unit_count =
        read_u64_le(&mut cursor).map_err(|_| IndexError::Truncated("missing unit count".into()))?;

    // Cap unit count by remaining bytes: each record is at least 4 bytes (len prefix)
    let max_possible_records = (cursor.len() / 4) as u64;
    if unit_count > max_possible_records && unit_count > 0 {
        return Err(IndexError::InvalidCount(format!(
            "declared unit count {} exceeds maximum possible {} in remaining {} bytes",
            unit_count,
            max_possible_records,
            cursor.len()
        )));
    }

    let header = IndexHeader {
        magic,
        version,
        root_path,
        unit_count,
    };

    let mut records = Vec::with_capacity(unit_count as usize);

    for idx in 0..unit_count {
        if cursor.len() < 4 {
            return Err(IndexError::Truncated(format!(
                "reached EOF before reading length for record {}",
                idx
            )));
        }
        let rec_len = read_u32_le(&mut cursor)? as usize;
        if cursor.len() < rec_len {
            return Err(IndexError::Truncated(format!(
                "record {} declares length {} exceeding remaining {} bytes",
                idx,
                rec_len,
                cursor.len()
            )));
        }
        let rec_payload = read_exact_bytes(&mut cursor, rec_len)?;
        let record = decode_record_payload(rec_payload)?;
        records.push(record);
    }

    Ok((header, records))
}

/// Helper scanner that walks a tree and builds index records.
pub struct IndexBuilder<'a> {
    pub root: &'a Path,
    pub root_str: String,
    pub opts: &'a ScanOptions,
    pub records: Vec<IndexRecord>,
    pub total_expanded: u64,
}

impl<'a> IndexBuilder<'a> {
    pub fn new(root: &'a Path, opts: &'a ScanOptions) -> Self {
        let root_str = root.display().to_string();
        Self {
            root,
            root_str,
            opts,
            records: Vec::new(),
            total_expanded: 0,
        }
    }

    fn rel_path(&self, p: &Path) -> String {
        let rel = p.strip_prefix(self.root).unwrap_or(p);
        let s = rel.to_string_lossy().replace('\\', "/");
        s.trim_start_matches('/').to_string()
    }

    pub fn scan_container_or_unit(
        &mut self,
        rel_path: &str,
        bytes: &[u8],
        meta: UnitMeta,
        depth: usize,
    ) {
        let container_type = detect_container_type(bytes, rel_path);

        if let Some(ctype) = container_type {
            if depth > self.opts.max_depth {
                self.records.push(IndexRecord {
                    path: rel_path.to_string(),
                    size: meta.size,
                    mtime: meta.mtime,
                    mode: meta.mode,
                    text_hashes: None,
                    builtin_d9: BuiltinD9Hits::default(),
                    binary_hashes: None,
                    pkg_metadata: None,
                    info_findings: vec![Finding {
                        detector: "D2".into(),
                        channel: "container_depth".into(),
                        path: rel_path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!(
                            "container depth {} exceeds limit {}",
                            depth, self.opts.max_depth
                        )],
                    }],
                });
                return;
            }

            match ctype {
                ContainerType::Zip => self.scan_zip(rel_path, bytes, meta, depth),
                ContainerType::Tar => self.scan_tar(rel_path, bytes, meta, depth),
                ContainerType::Gzip
                | ContainerType::Bzip2
                | ContainerType::Xz
                | ContainerType::Zstd => {
                    self.decompress_and_scan(rel_path, bytes, meta, ctype, depth);
                }
                ContainerType::Sqlite => self.scan_sqlite(rel_path, bytes, meta),
                ContainerType::Pyc => self.scan_pyc(rel_path, bytes, meta),
                ContainerType::GitPack => {
                    self.scan_git_pack(rel_path, bytes, meta, depth);
                }
            }
        } else {
            self.scan_plain_unit(rel_path, bytes, meta);
        }
    }

    fn scan_plain_unit(&mut self, rel_path: &str, bytes: &[u8], meta: UnitMeta) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        // Recognised binaries (ELF, Java .class, Mach-O, wasm) for D3b
        let (binary_channel, binary_result) = if bytes.starts_with(b"\x7fELF") {
            ("binary_elf", Some(parse_elf(bytes)))
        } else if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
            && bytes.len() >= 8
            && u16::from_be_bytes([bytes[6], bytes[7]]) >= 45
        {
            ("binary_class", Some(parse_class(bytes)))
        } else if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
            (
                "binary_macho",
                Some(Ok(BinaryStrings {
                    exact_strings: HashSet::new(),
                    printable_runs: extract_printable_runs(bytes, 6),
                })),
            )
        } else if bytes.starts_with(b"\0asm") {
            ("binary_wasm", Some(parse_wasm(bytes)))
        } else {
            ("", None)
        };

        if let Some(res) = binary_result {
            match res {
                Ok(extracted) => {
                    let exact_strings = hash_exact_strings(&extracted.exact_strings);
                    let token_hashes = extract_token_hashes_from_runs(&extracted.printable_runs);
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size,
                        mtime,
                        mode,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: Some(BinaryHashes {
                            channel: binary_channel.to_string(),
                            exact_strings,
                            token_hashes,
                        }),
                        pkg_metadata: None,
                        info_findings: Vec::new(),
                    });
                }
                Err(BinaryMalformed(err)) => {
                    let finding = Finding {
                        detector: "D3b".into(),
                        channel: "binary_malformed".into(),
                        path: rel_path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("malformed {}: {}", binary_channel, err)],
                    };
                    let fallback_runs = extract_printable_runs(bytes, 6);
                    let token_hashes = extract_token_hashes_from_runs(&fallback_runs);
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size,
                        mtime,
                        mode,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: Some(BinaryHashes {
                            channel: binary_channel.to_string(),
                            exact_strings: Vec::new(),
                            token_hashes,
                        }),
                        pkg_metadata: None,
                        info_findings: vec![finding],
                    });
                }
            }
            return;
        }

        // Check binary (NUL byte in first 8 KiB)
        let check_len = bytes.len().min(8192);
        if bytes[..check_len].contains(&0) {
            self.records.push(IndexRecord {
                path: rel_path.to_string(),
                size,
                mtime,
                mode,
                text_hashes: None,
                builtin_d9: BuiltinD9Hits::default(),
                binary_hashes: None,
                pkg_metadata: None,
                info_findings: vec![Finding {
                    detector: "D2".into(),
                    channel: "file".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec!["skipped binary file (contains NUL byte)".into()],
                }],
            });
            return;
        }

        let text = String::from_utf8_lossy(bytes);

        // Package metadata units (D5a)
        let pkg_metadata = if is_pkg_metadata_file(Path::new(rel_path)) {
            let (name, version) = parse_pkg_metadata(&text);
            Some(PkgMetadata { name, version })
        } else {
            None
        };

        // Builtin D9 hits
        let mut canaries = Vec::new();
        for &canary in BUILTIN_CANARIES {
            if text.contains(canary) {
                canaries.push(canary.to_string());
            }
        }
        let mut dataset_hosts = Vec::new();
        for &host in BUILTIN_DATASET_HOSTS {
            if text.contains(host) {
                dataset_hosts.push(host.to_string());
            }
        }
        let dataset_dump = check_is_dataset_dump(&text, rel_path);
        let builtin_d9 = BuiltinD9Hits {
            canaries,
            dataset_hosts,
            dataset_dump,
        };

        // Binary tier for minified bundles
        let binary_hashes = if is_minified_bundle(rel_path, &text) {
            let extracted = parse_minified(&text);
            let exact_strings = hash_exact_strings(&extracted.exact_strings);
            Some(BinaryHashes {
                channel: "binary_minified".to_string(),
                exact_strings,
                token_hashes: Vec::new(),
            })
        } else {
            None
        };

        let text_hashes = Some(compute_unit_hashes(&text));

        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes,
            builtin_d9,
            binary_hashes,
            pkg_metadata,
            info_findings: Vec::new(),
        });
    }

    fn scan_pyc(&mut self, rel_path: &str, bytes: &[u8], meta: UnitMeta) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        let constants_text = extract_pyc_constants(bytes);
        let text_hashes = if !constants_text.is_empty() {
            Some(compute_unit_hashes(&constants_text))
        } else {
            None
        };

        let mut canaries = Vec::new();
        for &canary in BUILTIN_CANARIES {
            if constants_text.contains(canary) {
                canaries.push(canary.to_string());
            }
        }
        let mut dataset_hosts = Vec::new();
        for &host in BUILTIN_DATASET_HOSTS {
            if constants_text.contains(host) {
                dataset_hosts.push(host.to_string());
            }
        }
        let dataset_dump = check_is_dataset_dump(&constants_text, rel_path);
        let builtin_d9 = BuiltinD9Hits {
            canaries,
            dataset_hosts,
            dataset_dump,
        };

        let header = crate::bytecode::pyc_magic(bytes)
            .map(crate::bytecode::pyc_header_len)
            .unwrap_or(0);
        let body = bytes.get(header..).unwrap_or(&[]);
        let exact_strings_set = extract_pyc_strings(body);
        let exact_strings = hash_exact_strings(&exact_strings_set);

        let binary_hashes = Some(BinaryHashes {
            channel: "binary_pyc".to_string(),
            exact_strings,
            token_hashes: Vec::new(),
        });

        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes,
            builtin_d9,
            binary_hashes,
            pkg_metadata: None,
            info_findings: Vec::new(),
        });
    }

    fn scan_zip(&mut self, rel_path: &str, bytes: &[u8], meta: UnitMeta, depth: usize) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        // Record the container unit itself (for D4 metadata and D9 path checks)
        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes: None,
            builtin_d9: BuiltinD9Hits::default(),
            binary_hashes: None,
            pkg_metadata: None,
            info_findings: Vec::new(),
        });

        let reader = Cursor::new(bytes);
        let mut archive = match zip::ZipArchive::new(reader) {
            Ok(a) => a,
            Err(e) => {
                let finding = Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to open zip archive: {e}")],
                };
                if let Some(rec) = self.records.last_mut() {
                    rec.info_findings.push(finding);
                }
                return;
            }
        };

        for i in 0..archive.len() {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: rel_path.to_string(),
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("failed to read zip member index {i}: {e}")],
                        }],
                    });
                    continue;
                }
            };

            if file.is_dir() {
                continue;
            }

            let member_name = file.name().to_string();
            let member_path = format!("{}!/{}", rel_path, member_name);
            let compressed_size = file.compressed_size();
            let m_size = file.size();
            let m_mode = file.unix_mode().unwrap_or(0o644);

            let mut member_bytes = Vec::new();
            let mut counting = CountingReader::new(
                &mut file,
                &mut self.total_expanded,
                compressed_size,
                self.opts,
            );

            if let Err(e) = counting.read_to_end(&mut member_bytes) {
                let msg = e.to_string();
                if msg.starts_with("bomb limit exceeded") {
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size,
                        mtime,
                        mode,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_bomb".into(),
                            path: rel_path.to_string(),
                            visibility: self.opts.visibility,
                            severity: Severity::Review,
                            confidence: 1.0,
                            hunk: None,
                            evidence: vec![msg],
                        }],
                    });
                    return;
                } else {
                    self.records.push(IndexRecord {
                        path: member_path.clone(),
                        size: m_size,
                        mtime: 0,
                        mode: m_mode,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: member_path,
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("error reading zip entry: {msg}")],
                        }],
                    });
                    continue;
                }
            }

            self.scan_container_or_unit(
                &member_path,
                &member_bytes,
                UnitMeta {
                    size: m_size,
                    mtime: 0,
                    mode: m_mode,
                },
                depth + 1,
            );
        }
    }

    fn scan_tar(&mut self, rel_path: &str, bytes: &[u8], meta: UnitMeta, depth: usize) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes: None,
            builtin_d9: BuiltinD9Hits::default(),
            binary_hashes: None,
            pkg_metadata: None,
            info_findings: Vec::new(),
        });

        let cursor = Cursor::new(bytes);
        let mut archive = tar::Archive::new(cursor);

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                let finding = Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to read tar entries: {e}")],
                };
                if let Some(rec) = self.records.last_mut() {
                    rec.info_findings.push(finding);
                }
                return;
            }
        };

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: rel_path.to_string(),
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("tar entry read error: {e}")],
                        }],
                    });
                    continue;
                }
            };

            let entry_type = entry.header().entry_type();
            match entry_type {
                tar::EntryType::Regular
                | tar::EntryType::GNUSparse
                | tar::EntryType::Continuous => {}
                tar::EntryType::Directory | tar::EntryType::Symlink | tar::EntryType::Link => {
                    continue;
                }
                _ => {
                    let entry_path = entry
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "unknown".into());
                    let member_path = format!("{}!/{}", rel_path, entry_path);
                    self.records.push(IndexRecord {
                        path: member_path.clone(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_skipped".into(),
                            path: member_path,
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("tar member type '{:?}' skipped", entry_type)],
                        }],
                    });
                    continue;
                }
            }

            let entry_path = match entry.path() {
                Ok(p) => p.display().to_string(),
                Err(e) => {
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: rel_path.to_string(),
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("invalid tar entry path: {e}")],
                        }],
                    });
                    continue;
                }
            };

            let member_path = format!("{}!/{}", rel_path, entry_path);
            let m_size = entry.header().size().unwrap_or(0);
            let m_mtime = entry.header().mtime().unwrap_or(0) as i64;
            let m_mode = entry.header().mode().unwrap_or(0o644);

            let mut member_bytes = Vec::new();
            let mut counting =
                CountingReader::new(&mut entry, &mut self.total_expanded, m_size, self.opts);

            if let Err(e) = counting.read_to_end(&mut member_bytes) {
                let msg = e.to_string();
                if msg.starts_with("bomb limit exceeded") {
                    self.records.push(IndexRecord {
                        path: rel_path.to_string(),
                        size,
                        mtime,
                        mode,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_bomb".into(),
                            path: rel_path.to_string(),
                            visibility: self.opts.visibility,
                            severity: Severity::Review,
                            confidence: 1.0,
                            hunk: None,
                            evidence: vec![msg],
                        }],
                    });
                    return;
                } else {
                    self.records.push(IndexRecord {
                        path: member_path.clone(),
                        size: m_size,
                        mtime: m_mtime,
                        mode: m_mode,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: member_path,
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("error reading tar entry: {msg}")],
                        }],
                    });
                    continue;
                }
            }

            self.scan_container_or_unit(
                &member_path,
                &member_bytes,
                UnitMeta {
                    size: m_size,
                    mtime: m_mtime,
                    mode: m_mode,
                },
                depth + 1,
            );
        }
    }

    fn decompress_and_scan(
        &mut self,
        rel_path: &str,
        compressed_bytes: &[u8],
        meta: UnitMeta,
        kind: ContainerType,
        depth: usize,
    ) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes: None,
            builtin_d9: BuiltinD9Hits::default(),
            binary_hashes: None,
            pkg_metadata: None,
            info_findings: Vec::new(),
        });

        let mut decompressed_bytes = Vec::new();
        let comp_len = compressed_bytes.len() as u64;

        let res = match kind {
            ContainerType::Gzip => {
                let decoder = flate2::read::GzDecoder::new(Cursor::new(compressed_bytes));
                let mut counting =
                    CountingReader::new(decoder, &mut self.total_expanded, comp_len, self.opts);
                counting.read_to_end(&mut decompressed_bytes)
            }
            ContainerType::Bzip2 => {
                let decoder = bzip2::read::BzDecoder::new(Cursor::new(compressed_bytes));
                let mut counting =
                    CountingReader::new(decoder, &mut self.total_expanded, comp_len, self.opts);
                counting.read_to_end(&mut decompressed_bytes)
            }
            ContainerType::Xz => {
                let decoder = xz2::read::XzDecoder::new(Cursor::new(compressed_bytes));
                let mut counting =
                    CountingReader::new(decoder, &mut self.total_expanded, comp_len, self.opts);
                counting.read_to_end(&mut decompressed_bytes)
            }
            ContainerType::Zstd => {
                match zstd::stream::read::Decoder::new(Cursor::new(compressed_bytes)) {
                    Ok(decoder) => {
                        let mut counting = CountingReader::new(
                            decoder,
                            &mut self.total_expanded,
                            comp_len,
                            self.opts,
                        );
                        counting.read_to_end(&mut decompressed_bytes)
                    }
                    Err(e) => Err(e),
                }
            }
            _ => return,
        };

        if let Err(e) = res {
            let msg = e.to_string();
            let finding = if msg.starts_with("bomb limit exceeded") {
                Finding {
                    detector: "D2".into(),
                    channel: "container_bomb".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Review,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![msg],
                }
            } else {
                Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("decompression error: {msg}")],
                }
            };
            if let Some(rec) = self.records.last_mut() {
                rec.info_findings.push(finding);
            }
            return;
        }

        if is_tar(&decompressed_bytes) {
            self.scan_tar(
                rel_path,
                &decompressed_bytes,
                UnitMeta {
                    size: decompressed_bytes.len() as u64,
                    mtime,
                    mode,
                },
                depth,
            );
        } else {
            let inner_name = Path::new(rel_path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(strip_compression_suffix)
                .unwrap_or_else(|| "uncompressed".into());
            let member_path = format!("{}!/{}", rel_path, inner_name);
            let d_len = decompressed_bytes.len() as u64;
            self.scan_container_or_unit(
                &member_path,
                &decompressed_bytes,
                UnitMeta {
                    size: d_len,
                    mtime,
                    mode,
                },
                depth + 1,
            );
        }
    }

    fn scan_sqlite(&mut self, rel_path: &str, bytes: &[u8], meta: UnitMeta) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes: None,
            builtin_d9: BuiltinD9Hits::default(),
            binary_hashes: None,
            pkg_metadata: None,
            info_findings: Vec::new(),
        });

        let temp_file = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                if let Some(rec) = self.records.last_mut() {
                    rec.info_findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: rel_path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("failed to create temp file for sqlite: {e}")],
                    });
                }
                return;
            }
        };

        if let Err(e) = std::fs::write(temp_file.path(), bytes) {
            if let Some(rec) = self.records.last_mut() {
                rec.info_findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to write temp sqlite file: {e}")],
                });
            }
            return;
        }

        let conn = match rusqlite::Connection::open_with_flags(
            temp_file.path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            Ok(c) => c,
            Err(e) => {
                if let Some(rec) = self.records.last_mut() {
                    rec.info_findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: rel_path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("sqlite open error: {e}")],
                    });
                }
                return;
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        ) {
            Ok(s) => s,
            Err(e) => {
                if let Some(rec) = self.records.last_mut() {
                    rec.info_findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: rel_path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("sqlite tables query error: {e}")],
                    });
                }
                return;
            }
        };

        let table_names: Vec<String> = match stmt.query_map([], |row| row.get(0)) {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                if let Some(rec) = self.records.last_mut() {
                    rec.info_findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: rel_path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("sqlite table names map error: {e}")],
                    });
                }
                return;
            }
        };

        for table in table_names {
            let escaped_table = table.replace('"', "\"\"");
            let query = format!("SELECT rowid, * FROM \"{}\"", escaped_table);
            let has_rowid = conn.prepare(&query).is_ok();

            let (sql, has_explicit_rowid) = if has_rowid {
                (query, true)
            } else {
                (format!("SELECT * FROM \"{}\"", escaped_table), false)
            };

            let mut row_stmt = match conn.prepare(&sql) {
                Ok(s) => s,
                Err(e) => {
                    self.records.push(IndexRecord {
                        path: format!("{}::{}", rel_path, table),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: format!("{}::{}", rel_path, table),
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!(
                                "failed to prepare statement for table '{}': {e}",
                                table
                            )],
                        }],
                    });
                    continue;
                }
            };

            let col_count = row_stmt.column_count();
            let mut rows = match row_stmt.query([]) {
                Ok(r) => r,
                Err(e) => {
                    self.records.push(IndexRecord {
                        path: format!("{}::{}", rel_path, table),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: format!("{}::{}", rel_path, table),
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!(
                                "failed to query rows for table '{}': {e}",
                                table
                            )],
                        }],
                    });
                    continue;
                }
            };

            let mut row_idx: i64 = 0;
            loop {
                let row = match rows.next() {
                    Ok(Some(r)) => r,
                    Ok(None) => break,
                    Err(e) => {
                        self.records.push(IndexRecord {
                            path: format!("{}::{}", rel_path, table),
                            size: 0,
                            mtime: 0,
                            mode: 0,
                            text_hashes: None,
                            builtin_d9: BuiltinD9Hits::default(),
                            binary_hashes: None,
                            pkg_metadata: None,
                            info_findings: vec![Finding {
                                detector: "D2".into(),
                                channel: "container_error".into(),
                                path: format!("{}::{}", rel_path, table),
                                visibility: self.opts.visibility,
                                severity: Severity::Info,
                                confidence: 0.0,
                                hunk: None,
                                evidence: vec![format!(
                                    "failed to fetch row for table '{}': {e}",
                                    table
                                )],
                            }],
                        });
                        break;
                    }
                };
                row_idx += 1;
                let rowid_str = if has_explicit_rowid {
                    let id: i64 = row.get(0).unwrap_or(row_idx);
                    id.to_string()
                } else {
                    row_idx.to_string()
                };

                let start_col = if has_explicit_rowid { 1 } else { 0 };
                let mut row_text_parts = Vec::new();

                for c in start_col..col_count {
                    if let Ok(val) = row.get_ref(c) {
                        match val {
                            rusqlite::types::ValueRef::Text(s) => {
                                if let Ok(s_str) = std::str::from_utf8(s) {
                                    row_text_parts.push(s_str.to_string());
                                }
                            }
                            rusqlite::types::ValueRef::Blob(b) => {
                                if let Ok(s_str) = std::str::from_utf8(b) {
                                    row_text_parts.push(s_str.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if !row_text_parts.is_empty() {
                    let row_text = row_text_parts.join("\n");
                    let row_path = format!("{}::{}#{}", rel_path, table, rowid_str);
                    let text_hashes = Some(compute_unit_hashes(&row_text));

                    let mut canaries = Vec::new();
                    for &canary in BUILTIN_CANARIES {
                        if row_text.contains(canary) {
                            canaries.push(canary.to_string());
                        }
                    }
                    let mut dataset_hosts = Vec::new();
                    for &host in BUILTIN_DATASET_HOSTS {
                        if row_text.contains(host) {
                            dataset_hosts.push(host.to_string());
                        }
                    }
                    let dataset_dump = check_is_dataset_dump(&row_text, &row_path);
                    let builtin_d9 = BuiltinD9Hits {
                        canaries,
                        dataset_hosts,
                        dataset_dump,
                    };

                    self.records.push(IndexRecord {
                        path: row_path,
                        size: row_text.len() as u64,
                        mtime: 0,
                        mode: 0,
                        text_hashes,
                        builtin_d9,
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: Vec::new(),
                    });
                }
            }
        }
    }

    fn scan_git_pack(&mut self, rel_path: &str, bytes: &[u8], meta: UnitMeta, depth: usize) {
        let size = meta.size;
        let mtime = meta.mtime;
        let mode = meta.mode;
        let (blobs, has_unresolved_ref_delta, error) =
            crate::gitstore::scan_stray_pack_slice(bytes, self.opts, &mut self.total_expanded);

        let mut findings = Vec::new();
        if has_unresolved_ref_delta {
            findings.push(Finding {
                detector: "D2".into(),
                channel: "container_skipped".into(),
                path: rel_path.to_string(),
                visibility: self.opts.visibility,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec!["unresolved REF_DELTA in stray pack".into()],
            });
        }
        match error {
            None => {}
            Some(crate::gitstore::GitError::LimitExceeded(msg)) => {
                findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_bomb".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Review,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![msg],
                });
            }
            Some(e) => {
                findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: rel_path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to parse stray git pack: {e}")],
                });
            }
        }

        self.records.push(IndexRecord {
            path: rel_path.to_string(),
            size,
            mtime,
            mode,
            text_hashes: None,
            builtin_d9: BuiltinD9Hits::default(),
            binary_hashes: None,
            pkg_metadata: None,
            info_findings: findings,
        });

        for (offset, blob_bytes) in blobs {
            let blob_path = format!("{}#{}", rel_path, offset);
            let b_len = blob_bytes.len() as u64;
            self.scan_container_or_unit(
                &blob_path,
                &blob_bytes,
                UnitMeta {
                    size: b_len,
                    mtime: 0,
                    mode: 0,
                },
                depth + 1,
            );
        }
    }
}

fn strip_compression_suffix(name: &str) -> String {
    if let Some(s) = name.strip_suffix(".tar.gz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tgz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tar.bz2") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tbz2") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tar.xz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".txz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tar.zst") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".gz") {
        s.to_string()
    } else if let Some(s) = name.strip_suffix(".bz2") {
        s.to_string()
    } else if let Some(s) = name.strip_suffix(".xz") {
        s.to_string()
    } else if let Some(s) = name.strip_suffix(".zst") {
        s.to_string()
    } else {
        name.to_string()
    }
}

fn get_mtime(meta: &std::fs::Metadata) -> i64 {
    match meta.modified() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        },
        Err(_) => 0,
    }
}

#[cfg(unix)]
fn get_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode()
}

#[cfg(not(unix))]
fn get_mode(meta: &std::fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

/// Walk the tree exactly as `scan_tree` does, with pruning, symlink handling, size limits,
/// and container recursion, returning all unit records for indexing.
pub fn index_tree(root: &Path, opts: &ScanOptions) -> Result<Vec<IndexRecord>, IndexError> {
    let mut builder = IndexBuilder::new(root, opts);

    let is_git_dir = |p: &Path| {
        p.join("HEAD").is_file() && p.join("objects").is_dir() && p.join("refs").is_dir()
    };

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        let path = e.path();
        if root == Path::new("/") {
            let path_str = path.to_string_lossy();
            if path_str == "/proc" || path_str == "/sys" || path_str == "/dev" {
                return false;
            }
        }
        if e.file_type().is_dir() {
            if e.file_name() == "objects" && path.parent().is_some_and(is_git_dir) {
                return false;
            }
            if !opts.exclude_dirs.is_empty() {
                if let Ok(canon) = path.canonicalize() {
                    return !opts.exclude_dirs.iter().any(|d| canon.starts_with(d));
                }
            }
        }
        true
    });

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let path_str = e
                    .path()
                    .map(|p| builder.rel_path(p))
                    .unwrap_or_else(|| "".into());
                builder.records.push(IndexRecord {
                    path: path_str.clone(),
                    size: 0,
                    mtime: 0,
                    mode: 0,
                    text_hashes: None,
                    builtin_d9: BuiltinD9Hits::default(),
                    binary_hashes: None,
                    pkg_metadata: None,
                    info_findings: vec![Finding {
                        detector: "D2".into(),
                        channel: "scan_error".into(),
                        path: path_str,
                        visibility: opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("walk error: {e}")],
                    }],
                });
                continue;
            }
        };

        let file_path = entry.path();
        let rel_path = builder.rel_path(file_path);

        let metadata = if entry.path_is_symlink() {
            match std::fs::metadata(file_path) {
                Ok(m) if m.is_file() => m,
                Ok(_) => {
                    builder.records.push(IndexRecord {
                        path: rel_path.clone(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "scan_error".into(),
                            path: rel_path,
                            visibility: opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec!["symlink to a non-file not followed".into()],
                        }],
                    });
                    continue;
                }
                Err(e) => {
                    builder.records.push(IndexRecord {
                        path: rel_path.clone(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "scan_error".into(),
                            path: rel_path,
                            visibility: opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("broken symlink: {e}")],
                        }],
                    });
                    continue;
                }
            }
        } else if entry.file_type().is_file() {
            match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    builder.records.push(IndexRecord {
                        path: rel_path.clone(),
                        size: 0,
                        mtime: 0,
                        mode: 0,
                        text_hashes: None,
                        builtin_d9: BuiltinD9Hits::default(),
                        binary_hashes: None,
                        pkg_metadata: None,
                        info_findings: vec![Finding {
                            detector: "D2".into(),
                            channel: "scan_error".into(),
                            path: rel_path,
                            visibility: opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("metadata error: {e}")],
                        }],
                    });
                    continue;
                }
            }
        } else {
            continue;
        };

        let size = metadata.len();
        let mtime = get_mtime(&metadata);
        let mode = get_mode(&metadata);

        // Size check for loose file
        if size > opts.max_file_bytes {
            let is_large_archive = if size <= opts.max_member_bytes {
                if let Ok(mut f) = File::open(file_path) {
                    let mut head = [0u8; 512];
                    if let Ok(n) = f.read(&mut head) {
                        matches!(
                            detect_container_type(&head[..n], &rel_path),
                            Some(
                                ContainerType::Zip
                                    | ContainerType::Tar
                                    | ContainerType::Gzip
                                    | ContainerType::Bzip2
                                    | ContainerType::Xz
                                    | ContainerType::Zstd
                            )
                        )
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if !is_large_archive {
                builder.records.push(IndexRecord {
                    path: rel_path.clone(),
                    size,
                    mtime,
                    mode,
                    text_hashes: None,
                    builtin_d9: BuiltinD9Hits::default(),
                    binary_hashes: None,
                    pkg_metadata: None,
                    info_findings: vec![Finding {
                        detector: "D2".into(),
                        channel: "file".into(),
                        path: rel_path,
                        visibility: opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!(
                            "skipped file exceeding max size ({} bytes > {} bytes)",
                            size, opts.max_file_bytes
                        )],
                    }],
                });
                continue;
            }
        }

        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                builder.records.push(IndexRecord {
                    path: rel_path.clone(),
                    size,
                    mtime,
                    mode,
                    text_hashes: None,
                    builtin_d9: BuiltinD9Hits::default(),
                    binary_hashes: None,
                    pkg_metadata: None,
                    info_findings: vec![Finding {
                        detector: "D2".into(),
                        channel: "scan_error".into(),
                        path: rel_path,
                        visibility: opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("read error: {e}")],
                    }],
                });
                continue;
            }
        };

        builder.scan_container_or_unit(&rel_path, &bytes, UnitMeta { size, mtime, mode }, 0);
    }

    Ok(builder.records)
}

/// Index a layer tree and write it to `out_file`.
pub fn index_tree_to_file(
    root: &Path,
    out_file: &Path,
    opts: &ScanOptions,
) -> Result<(), IndexError> {
    let records = index_tree(root, opts)?;
    let root_str = root.display().to_string();
    let file = File::create(out_file)?;
    write_index(&root_str, &records, file)
}

/// Match extracted binary strings against FingerprintSet binary tier.
pub fn match_binary_hashes(
    binary: &BinaryHashes,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exact_set: HashSet<u64> = binary.exact_strings.iter().copied().collect();
    let token_set: HashSet<u64> = binary.token_hashes.iter().copied().collect();

    for hunk in &fp.hunks {
        if hunk.binary_items.len() < 2 {
            continue;
        }

        let mut matched_items = Vec::new();
        for item in &hunk.binary_items {
            let h = sha256_u64(item.as_bytes());
            let mut matched = exact_set.contains(&h);
            // Items containing characters outside [A-Za-z0-9_] can only match exact strings
            if !matched
                && item.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && token_set.contains(&h)
            {
                matched = true;
            }
            if matched {
                matched_items.push(item.clone());
            }
        }

        let confidence = matched_items.len() as f64 / hunk.binary_items.len() as f64;
        if confidence >= opts.binary_threshold {
            findings.push(Finding {
                detector: "D3b".into(),
                channel: binary.channel.clone(),
                path: path.to_string(),
                visibility: opts.visibility,
                severity: Severity::Gate,
                confidence: (confidence * 100.0).round() / 100.0,
                hunk: Some(hunk.hunk_index),
                evidence: matched_items.into_iter().take(5).collect(),
            });
        }
    }

    findings
}

/// Query one or more index files against a FingerprintSet, returning all findings.
pub fn query_indexes(
    indexes: &[PathBuf],
    visibilities: &[Visibility],
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Result<Vec<Finding>, IndexError> {
    let mut all_findings = Vec::new();

    for (idx, index_path) in indexes.iter().enumerate() {
        let vis = visibilities.get(idx).copied().unwrap_or(opts.visibility);
        let mut query_opts = opts.clone();
        query_opts.visibility = vis;

        let file = File::open(index_path)?;
        let (header, records) = read_index(file)?;
        let root_str = header.root_path;

        for record in records {
            let display_path = if root_str.is_empty() {
                record.path.clone()
            } else {
                let r = root_str.trim_end_matches(['/', '\\']);
                if r.is_empty() {
                    format!("/{}", record.path)
                } else {
                    format!("{}/{}", r, record.path)
                }
            };

            // 1. D9 path check
            let path_findings = check_d9_path_with_display(
                &record.path,
                &display_path,
                &query_opts.signatures,
                vis,
            );
            all_findings.extend(path_findings);

            // 2. Text units: match_unit_hashes for tiers 1, 3 and diff shapes
            if let Some(ref uh) = record.text_hashes {
                let text_findings =
                    match_unit_hashes(uh, fp, &query_opts, "D2", "file", &display_path);
                all_findings.extend(text_findings);
            }

            // 3. Builtin D9 content hits
            for canary in &record.builtin_d9.canaries {
                all_findings.push(Finding {
                    detector: "D9".into(),
                    channel: "canary".into(),
                    path: display_path.clone(),
                    visibility: vis,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![format!("canary string '{}' present in content", canary)],
                });
            }

            for host in &record.builtin_d9.dataset_hosts {
                all_findings.push(Finding {
                    detector: "D9".into(),
                    channel: "dataset_host".into(),
                    path: display_path.clone(),
                    visibility: vis,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![format!("dataset host '{}' present in content", host)],
                });
            }

            if record.builtin_d9.dataset_dump {
                all_findings.push(Finding {
                    detector: "D9".into(),
                    channel: "dataset_dump".into(),
                    path: display_path.clone(),
                    visibility: vis,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![
                        "file records contain both 'instance_id' and 'patch' keys".into()
                    ],
                });
            }

            // 4. Binary tier against hashed strings
            if let Some(ref bh) = record.binary_hashes {
                let bin_findings = match_binary_hashes(bh, fp, &query_opts, &display_path);
                all_findings.extend(bin_findings);
            }

            // 5. D5a against stored metadata
            if let Some(ref meta) = record.pkg_metadata {
                if let Some(ref name) = meta.name {
                    let d5a_findings = check_d5a_name_and_version(
                        name,
                        meta.version.as_deref(),
                        &display_path,
                        &query_opts,
                    );
                    all_findings.extend(d5a_findings);
                }
            }

            // 6. Stored info findings
            for info in record.info_findings {
                let mut f = info;
                f.path = display_path.clone();
                f.visibility = vis;
                all_findings.push(f);
            }
        }
    }

    Ok(all_findings)
}
