//! Layer index and per-task query (TR-SC-10).
//!
//! `index` walks a tree once, exactly as `scan_tree` does, and records each unit's
//! task-independent facts. `query` matches one task's fingerprints against those records
//! without reading the tree again.
//!
//! # File format (version 2)
//!
//! The file is one zstd stream. Decompressed, it holds:
//!
//! ```text
//! magic           6 bytes   "HWIDX1"
//! version         u32       2
//! root            str       the indexed root, as `scan` would display it
//! canonical_root  str       root canonicalized at index time ("" if failed)
//! count           u64       number of records
//! record*         count times:
//!     len         u64       payload length (at most MAX_RECORD_BYTES)
//!     payload     len bytes: tag u8, then the fields below
//! ```
//!
//! Integers are little-endian. `str` is a u32 byte length then UTF-8. `path` is a u8 kind
//! (0: relative, so the full path is `root` + the string; 1: absolute) then a `str`.
//! `set` is a u64 count then that many u64s, sorted ascending. `opt<T>` is a u8 (0 or 1)
//! then `T` when 1.
//!
//! | tag | record    | fields |
//! |-----|-----------|--------|
//! | 1   | file      | path, size u64, mtime seconds i64, mtime nanos u32, mode u32 |
//! | 2   | fixed     | path, detector str, channel str, severity u8, confidence f64, hunk opt<u64>, evidence (u32 count, str*) |
//! | 3   | path      | path |
//! | 4   | text      | path, D9 flags u8, line set, window set, removed-marker set, diff-shape set, winnow set |
//! | 5   | binary    | path, channel str, exact set, token set |
//! | 6   | pkg       | path, name str, version opt<str> |
//! | 7   | text cont | path, line set, window set, removed-marker set, diff-shape set, winnow set |
//! | 8   | bin cont  | path, channel str, exact set, token set |
//!
//! `fixed` holds a finding that depends on the unit alone (errors, bombs, skipped
//! binaries); its visibility comes from the query. Text hashes are the first 8 bytes of
//! each sha256 (`sha256_u64`); winnow hashes are already 64-bit. D9 flags are those of
//! `d9_builtin_content_flags`.
//!
//! Binary strings are stored hashed: `exact` holds every exact string and every whole
//! printable run, `token` the `[A-Za-z0-9_]+` pieces of the runs. **Limit:** a binary item
//! holding a character outside `[A-Za-z0-9_]` matches only a whole stored string, not a
//! substring of a printable run, as `scan` would allow.
//!
//! # Continuation records and unit limits
//!
//! Records exceeding `MAX_RECORD_BYTES` are split into continuation records (`TextCont`,
//! `BinaryCont`). When reading or querying, continuation records are merged into their
//! predecessor. The total encoded hash bytes (8 per hash, summed over all sets) of one unit
//! after merging cannot exceed `MAX_UNIT_BYTES` (1 GiB). Exceeding `MAX_UNIT_BYTES` while
//! merging is `IndexError::Malformed`, checked before extending the sets.
//!
//! The writer never produces a unit exceeding `MAX_UNIT_BYTES`: when a Text or Binary unit's
//! total hash bytes exceed `MAX_UNIT_BYTES`, its hashes are not written. Instead, a `Fixed`
//! record (detector "D2", channel "index_skipped", severity Info, confidence 0.0, no hunk,
//! evidence `["unit too large to index: N hashes"]`) is emitted for that path, so the query
//! reports the gap instead of hiding it. D9 content flags are kept: for an oversized Text
//! unit with non-zero D9 flags, a Text record with empty hash sets is also written, so
//! canary, dataset host, and dataset dump findings are still reported. Note that `scan` and
//! `query` differ for such an oversized unit: `scan` scans the large unit in memory, whereas
//! `query` reports the `index_skipped` Info finding alongside any D9 content findings.
//!
//! # Not covered by a query
//!
//! D1 (git stores), D3 (`.pyc` headers against source), D6 (OCI metadata), the D9
//! instance-id check and external signatures need the live tree or the task's identity.
//! A query report says so in `not_covered`.
//!
//! # Reading hostile files
//!
//! The reader never trusts a length or count: no buffer is sized from one, every count is
//! capped by the bytes left in its record, a short read is `Truncated`, and bytes after the
//! last record are rejected.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::benchmark::{
    check_d9_path_builtin, d9_builtin_content_findings, d9_builtin_content_flags,
};
use crate::binary::{match_hashed_binary_items, BinaryStrings, HashedBinaryStrings};
use crate::containers::UnitSink;
use crate::d5a::{check_d5a_name_and_version, is_pkg_metadata_file, parse_pkg_metadata};
use crate::fingerprint::FingerprintSet;
use crate::scan::{
    compute_unit_hashes, match_unit_hashes, walk_tree, Finding, ScanOptions, Severity, TreeSink,
    UnitHashes,
};

pub const MAGIC: &[u8; 6] = b"HWIDX1";
pub const FORMAT_VERSION: u32 = 2;
/// The largest record payload the reader accepts.
pub const MAX_RECORD_BYTES: u64 = 256 * 1024 * 1024;
/// The maximum encoded hash bytes of one unit after merging continuations (1 GiB).
pub const MAX_UNIT_BYTES: u64 = 1024 * 1024 * 1024;
/// The longest root path the reader accepts.
pub const MAX_ROOT_BYTES: u32 = 64 * 1024;

/// Detectors a query can't answer from an index.
pub const NOT_COVERED: &[&str] = &["D1", "D3", "D6", "D9:instance_id", "D9:external"];

const TAG_FILE: u8 = 1;
const TAG_FIXED: u8 = 2;
const TAG_PATH: u8 = 3;
const TAG_TEXT: u8 = 4;
const TAG_BINARY: u8 = 5;
const TAG_PKG: u8 = 6;
const TAG_TEXT_CONT: u8 = 7;
const TAG_BINARY_CONT: u8 = 8;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("not a sealcheck index (bad magic)")]
    BadMagic,
    #[error("unsupported index format version {0}")]
    UnsupportedVersion(u32),
    #[error("index truncated: {0}")]
    Truncated(String),
    #[error("malformed index: {0}")]
    Malformed(String),
    #[error("index root is not valid UTF-8: {0}")]
    NonUtf8Root(PathBuf),
}

/// A unit path: relative to the index root (the full path is `root + rel`), or absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexPath {
    Rel(String),
    Abs(String),
}

impl IndexPath {
    fn from_display(root: &str, display: &str) -> Self {
        match display.strip_prefix(root) {
            Some(rel) if !root.is_empty() => IndexPath::Rel(rel.to_string()),
            _ => IndexPath::Abs(display.to_string()),
        }
    }

    /// The path as `scan` reports it.
    pub fn display(&self, root: &str) -> String {
        match self {
            IndexPath::Rel(rel) => format!("{root}{rel}"),
            IndexPath::Abs(abs) => abs.clone(),
        }
    }
}

/// A finding that depends on the unit alone. Visibility is applied at query time.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredFinding {
    pub detector: String,
    pub channel: String,
    pub path: IndexPath,
    pub severity: Severity,
    pub confidence: f64,
    pub hunk: Option<u64>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IndexRecord {
    File {
        path: IndexPath,
        size: u64,
        mtime_secs: i64,
        mtime_nanos: u32,
        mode: u32,
    },
    Fixed(StoredFinding),
    Path {
        path: IndexPath,
    },
    Text {
        path: IndexPath,
        d9_flags: u8,
        hashes: UnitHashes,
    },
    Binary {
        path: IndexPath,
        channel: String,
        strings: HashedBinaryStrings,
    },
    Pkg {
        path: IndexPath,
        name: String,
        version: Option<String>,
    },
    TextCont {
        path: IndexPath,
        hashes: UnitHashes,
    },
    BinaryCont {
        path: IndexPath,
        channel: String,
        strings: HashedBinaryStrings,
    },
}

// ---------------------------------------------------------------------------------------
// Building records
// ---------------------------------------------------------------------------------------

/// The `TreeSink` that turns every unit the walk reaches into an `IndexRecord`.
pub struct IndexSink<F: FnMut(IndexRecord)> {
    root: String,
    emit: F,
}

impl<F: FnMut(IndexRecord)> IndexSink<F> {
    pub fn new(root: String, emit: F) -> Self {
        Self { root, emit }
    }

    fn ipath(&self, display: &str) -> IndexPath {
        IndexPath::from_display(&self.root, display)
    }
}

impl<F: FnMut(IndexRecord)> UnitSink for IndexSink<F> {
    fn fixed(&mut self, finding: Finding) {
        let path = self.ipath(&finding.path);
        (self.emit)(IndexRecord::Fixed(StoredFinding {
            detector: finding.detector,
            channel: finding.channel,
            path,
            severity: finding.severity,
            confidence: finding.confidence,
            hunk: finding.hunk.map(|h| h as u64),
            evidence: finding.evidence,
        }));
    }

    fn path(&mut self, _match_path: &str, display_path: &str) {
        let path = self.ipath(display_path);
        (self.emit)(IndexRecord::Path { path });
    }

    fn text(&mut self, path: &str, text: &str) {
        let record = IndexRecord::Text {
            path: self.ipath(path),
            d9_flags: d9_builtin_content_flags(path, text),
            hashes: compute_unit_hashes(text),
        };
        (self.emit)(record);
    }

    fn binary(&mut self, path: &str, channel: &str, strings: BinaryStrings) {
        let record = IndexRecord::Binary {
            path: self.ipath(path),
            channel: channel.to_string(),
            strings: HashedBinaryStrings::from_strings(&strings),
        };
        (self.emit)(record);
    }

    fn pkg_metadata(&mut self, path: &str, bytes: &[u8]) {
        if !is_pkg_metadata_file(Path::new(path)) {
            return;
        }
        let text = String::from_utf8_lossy(bytes);
        if let (Some(name), version) = parse_pkg_metadata(&text) {
            let record = IndexRecord::Pkg {
                path: self.ipath(path),
                name,
                version,
            };
            (self.emit)(record);
        }
    }
}

impl<F: FnMut(IndexRecord)> TreeSink for IndexSink<F> {
    fn git_repo(&mut self, _dir: &Path) {}
    fn d1_finding(&mut self, _finding: Finding) {}
    fn pyc_file(&mut self, _path: &Path, _display_path: &str) {}

    fn loose_file(&mut self, display_path: &str, metadata: &std::fs::Metadata) {
        let (mtime_secs, mtime_nanos) = match metadata.modified() {
            Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => (
                    i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                    d.subsec_nanos(),
                ),
                Err(e) => {
                    let d = e.duration();
                    let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                    if d.subsec_nanos() == 0 {
                        (-secs, 0)
                    } else {
                        (-secs - 1, 1_000_000_000 - d.subsec_nanos())
                    }
                }
            },
            Err(_) => (0, 0),
        };
        let record = IndexRecord::File {
            path: self.ipath(display_path),
            size: metadata.len(),
            mtime_secs,
            mtime_nanos,
            mode: file_mode(metadata),
        };
        (self.emit)(record);
    }
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

/// The options an index walk uses: the default limits, with no task.
pub fn index_scan_options() -> ScanOptions {
    ScanOptions::default()
}

/// Walk `root` and collect its records in memory.
pub fn collect_records(root: &Path) -> Vec<IndexRecord> {
    let root_str = root.display().to_string();
    let mut records = Vec::new();
    let opts = index_scan_options();
    walk_tree(root, &opts, IndexSink::new(root_str, |r| records.push(r)));
    records
}

/// Statistics from building an index.
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexStats {
    pub records: u64,
    pub files: u64,
}

/// Total count of hashes in a UnitHashes set.
pub fn text_hash_count(hashes: &UnitHashes) -> usize {
    hashes.line_hashes.len()
        + hashes.window_hashes.len()
        + hashes.removed_marker_hashes.len()
        + hashes.diff_shape_hashes.len()
        + hashes.winnow_hashes.len()
}

/// Total encoded hash bytes (8 per hash) in a UnitHashes set.
pub fn text_hash_bytes(hashes: &UnitHashes) -> u64 {
    (text_hash_count(hashes) as u64).saturating_mul(8)
}

/// Total count of hashes in a HashedBinaryStrings set.
pub fn binary_hash_count(strings: &HashedBinaryStrings) -> usize {
    strings.exact.len() + strings.tokens.len()
}

/// Total encoded hash bytes (8 per hash) in a HashedBinaryStrings set.
pub fn binary_hash_bytes(strings: &HashedBinaryStrings) -> u64 {
    (binary_hash_count(strings) as u64).saturating_mul(8)
}

/// Index `root` into the file `out`. The file is written to a temporary name beside `out`
/// and renamed into place, so a failed run never leaves a partial index.
pub fn write_index(root: &Path, out: &Path) -> Result<IndexStats, IndexError> {
    write_index_with_limits(root, out, MAX_RECORD_BYTES, MAX_UNIT_BYTES)
}

/// `write_index` with a configurable record split threshold (for testing).
pub fn write_index_with_threshold(
    root: &Path,
    out: &Path,
    max_record_bytes: u64,
) -> Result<IndexStats, IndexError> {
    write_index_with_limits(root, out, max_record_bytes, MAX_UNIT_BYTES)
}

fn write_record_to<W: Write>(
    w: &mut W,
    rec: &IndexRecord,
    payload: &mut Vec<u8>,
    stats: &mut IndexStats,
    max_record_bytes: u64,
) -> io::Result<()> {
    payload.clear();
    encode_record(rec, payload);
    if payload.len() as u64 <= max_record_bytes {
        w.write_all(&(payload.len() as u64).to_le_bytes())?;
        w.write_all(payload)?;
        stats.records += 1;
    } else if let Some(chunks) = split_record(rec, max_record_bytes) {
        for chunk in chunks {
            w.write_all(&(chunk.len() as u64).to_le_bytes())?;
            w.write_all(&chunk)?;
            stats.records += 1;
        }
    } else {
        w.write_all(&(payload.len() as u64).to_le_bytes())?;
        w.write_all(payload)?;
        stats.records += 1;
    }
    Ok(())
}

/// `write_index` with configurable record threshold and unit limit (for testing).
pub fn write_index_with_limits(
    root: &Path,
    out: &Path,
    max_record_bytes: u64,
    max_unit_bytes: u64,
) -> Result<IndexStats, IndexError> {
    let root_str = root
        .to_str()
        .map(|_| root.display().to_string())
        .ok_or_else(|| IndexError::NonUtf8Root(root.to_path_buf()))?;
    let canonical_root_str = root
        .canonicalize()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };

    // Records go to a scratch file first: the header's count is known only at the end.
    let mut scratch = tempfile::tempfile_in(&dir)?;
    let mut stats = IndexStats::default();
    let mut write_err: Option<io::Error> = None;
    {
        let mut w = BufWriter::new(&mut scratch);
        let mut payload = Vec::new();
        let opts = index_scan_options();
        walk_tree(
            root,
            &opts,
            IndexSink::new(root_str.clone(), |r| {
                if write_err.is_some() {
                    return;
                }
                if matches!(r, IndexRecord::File { .. }) {
                    stats.files += 1;
                }
                let mut write_one = |rec: &IndexRecord| {
                    if write_err.is_none() {
                        if let Err(e) =
                            write_record_to(&mut w, rec, &mut payload, &mut stats, max_record_bytes)
                        {
                            write_err = Some(e);
                        }
                    }
                };
                match r {
                    IndexRecord::Text {
                        path,
                        d9_flags,
                        hashes,
                    } => {
                        let count = text_hash_count(&hashes);
                        let bytes = (count as u64).saturating_mul(8);
                        if bytes > max_unit_bytes {
                            let skipped = IndexRecord::Fixed(StoredFinding {
                                detector: "D2".to_string(),
                                channel: "index_skipped".to_string(),
                                path: path.clone(),
                                severity: Severity::Info,
                                confidence: 0.0,
                                hunk: None,
                                evidence: vec![format!("unit too large to index: {count} hashes")],
                            });
                            write_one(&skipped);
                            if d9_flags != 0 {
                                let d9_rec = IndexRecord::Text {
                                    path,
                                    d9_flags,
                                    hashes: UnitHashes::default(),
                                };
                                write_one(&d9_rec);
                            }
                        } else {
                            write_one(&IndexRecord::Text {
                                path,
                                d9_flags,
                                hashes,
                            });
                        }
                    }
                    IndexRecord::Binary {
                        path,
                        channel,
                        strings,
                    } => {
                        let count = binary_hash_count(&strings);
                        let bytes = (count as u64).saturating_mul(8);
                        if bytes > max_unit_bytes {
                            let skipped = IndexRecord::Fixed(StoredFinding {
                                detector: "D2".to_string(),
                                channel: "index_skipped".to_string(),
                                path,
                                severity: Severity::Info,
                                confidence: 0.0,
                                hunk: None,
                                evidence: vec![format!("unit too large to index: {count} hashes")],
                            });
                            write_one(&skipped);
                        } else {
                            write_one(&IndexRecord::Binary {
                                path,
                                channel,
                                strings,
                            });
                        }
                    }
                    other => write_one(&other),
                }
            }),
        );
        if let Some(e) = write_err {
            return Err(e.into());
        }
        w.flush()?;
    }
    scratch.seek(SeekFrom::Start(0))?;

    let tmp_out = tempfile::NamedTempFile::new_in(&dir)?;
    {
        let mut enc = zstd::stream::write::Encoder::new(BufWriter::new(tmp_out.as_file()), 3)?;
        // A checksum makes a corrupted frame an error, not silently different records.
        enc.include_checksum(true)?;
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        put_str(&mut header, &root_str);
        put_str(&mut header, &canonical_root_str);
        header.extend_from_slice(&stats.records.to_le_bytes());
        enc.write_all(&header)?;
        io::copy(&mut BufReader::new(&mut scratch), &mut enc)?;
        let mut inner = enc.finish()?;
        inner.flush()?;
    }
    tmp_out.persist(out).map_err(|e| IndexError::Io(e.error))?;
    Ok(stats)
}

// ---------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------

fn put_u8(b: &mut Vec<u8>, v: u8) {
    b.push(v);
}
fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_str(b: &mut Vec<u8>, s: &str) {
    // Unit text and paths come from members capped far below 4 GiB, but never wrap.
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    put_u32(b, len);
    b.extend_from_slice(&bytes[..len as usize]);
}
fn put_opt_str(b: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => {
            put_u8(b, 1);
            put_str(b, s);
        }
        None => put_u8(b, 0),
    }
}
fn put_path(b: &mut Vec<u8>, p: &IndexPath) {
    match p {
        IndexPath::Rel(s) => {
            put_u8(b, 0);
            put_str(b, s);
        }
        IndexPath::Abs(s) => {
            put_u8(b, 1);
            put_str(b, s);
        }
    }
}
fn put_hash_slice(b: &mut Vec<u8>, slice: &[u64]) {
    put_u64(b, slice.len() as u64);
    for h in slice {
        put_u64(b, *h);
    }
}

fn put_set(b: &mut Vec<u8>, set: &HashSet<u64>) {
    let mut v: Vec<u64> = set.iter().copied().collect();
    v.sort_unstable();
    put_hash_slice(b, &v);
}
fn severity_code(s: Severity) -> u8 {
    match s {
        Severity::Gate => 0,
        Severity::Review => 1,
        Severity::Info => 2,
    }
}

/// Split a text or binary record across consecutive records when its encoded payload
/// exceeds `max_record_bytes`.
fn split_record(r: &IndexRecord, max_record_bytes: u64) -> Option<Vec<Vec<u8>>> {
    match r {
        IndexRecord::Text {
            path,
            d9_flags,
            hashes,
        } => {
            let mut line_v: Vec<u64> = hashes.line_hashes.iter().copied().collect();
            line_v.sort_unstable();
            let mut window_v: Vec<u64> = hashes.window_hashes.iter().copied().collect();
            window_v.sort_unstable();
            let mut removed_v: Vec<u64> = hashes.removed_marker_hashes.iter().copied().collect();
            removed_v.sort_unstable();
            let mut diff_v: Vec<u64> = hashes.diff_shape_hashes.iter().copied().collect();
            diff_v.sort_unstable();
            let mut winnow_v: Vec<u64> = hashes.winnow_hashes.iter().copied().collect();
            winnow_v.sort_unstable();

            let mut line_idx = 0;
            let mut window_idx = 0;
            let mut removed_idx = 0;
            let mut diff_idx = 0;
            let mut winnow_idx = 0;

            let mut is_first = true;
            let mut chunks = Vec::new();

            loop {
                let mut buf = Vec::new();
                if is_first {
                    put_u8(&mut buf, TAG_TEXT);
                    put_path(&mut buf, path);
                    put_u8(&mut buf, *d9_flags);
                } else {
                    put_u8(&mut buf, TAG_TEXT_CONT);
                    put_path(&mut buf, path);
                }
                let overhead = buf.len() + 5 * 8;
                let budget_bytes = max_record_bytes.saturating_sub(overhead as u64);
                let mut budget_hashes = (budget_bytes / 8) as usize;
                if budget_hashes == 0 {
                    budget_hashes = 1;
                }

                let take_line = budget_hashes.min(line_v.len() - line_idx);
                let line_slice = &line_v[line_idx..line_idx + take_line];
                line_idx += take_line;
                budget_hashes -= take_line;

                let take_window = budget_hashes.min(window_v.len() - window_idx);
                let window_slice = &window_v[window_idx..window_idx + take_window];
                window_idx += take_window;
                budget_hashes -= take_window;

                let take_removed = budget_hashes.min(removed_v.len() - removed_idx);
                let removed_slice = &removed_v[removed_idx..removed_idx + take_removed];
                removed_idx += take_removed;
                budget_hashes -= take_removed;

                let take_diff = budget_hashes.min(diff_v.len() - diff_idx);
                let diff_slice = &diff_v[diff_idx..diff_idx + take_diff];
                diff_idx += take_diff;
                budget_hashes -= take_diff;

                let take_winnow = budget_hashes.min(winnow_v.len() - winnow_idx);
                let winnow_slice = &winnow_v[winnow_idx..winnow_idx + take_winnow];
                winnow_idx += take_winnow;

                put_hash_slice(&mut buf, line_slice);
                put_hash_slice(&mut buf, window_slice);
                put_hash_slice(&mut buf, removed_slice);
                put_hash_slice(&mut buf, diff_slice);
                put_hash_slice(&mut buf, winnow_slice);

                chunks.push(buf);
                is_first = false;

                if line_idx == line_v.len()
                    && window_idx == window_v.len()
                    && removed_idx == removed_v.len()
                    && diff_idx == diff_v.len()
                    && winnow_idx == winnow_v.len()
                {
                    break;
                }
            }
            Some(chunks)
        }
        IndexRecord::Binary {
            path,
            channel,
            strings,
        } => {
            let mut exact_v: Vec<u64> = strings.exact.iter().copied().collect();
            exact_v.sort_unstable();
            let mut token_v: Vec<u64> = strings.tokens.iter().copied().collect();
            token_v.sort_unstable();

            let mut exact_idx = 0;
            let mut token_idx = 0;

            let mut is_first = true;
            let mut chunks = Vec::new();

            loop {
                let mut buf = Vec::new();
                if is_first {
                    put_u8(&mut buf, TAG_BINARY);
                    put_path(&mut buf, path);
                    put_str(&mut buf, channel);
                } else {
                    put_u8(&mut buf, TAG_BINARY_CONT);
                    put_path(&mut buf, path);
                    put_str(&mut buf, channel);
                }
                let overhead = buf.len() + 2 * 8;
                let budget_bytes = max_record_bytes.saturating_sub(overhead as u64);
                let mut budget_hashes = (budget_bytes / 8) as usize;
                if budget_hashes == 0 {
                    budget_hashes = 1;
                }

                let take_exact = budget_hashes.min(exact_v.len() - exact_idx);
                let exact_slice = &exact_v[exact_idx..exact_idx + take_exact];
                exact_idx += take_exact;
                budget_hashes -= take_exact;

                let take_token = budget_hashes.min(token_v.len() - token_idx);
                let token_slice = &token_v[token_idx..token_idx + take_token];
                token_idx += take_token;

                put_hash_slice(&mut buf, exact_slice);
                put_hash_slice(&mut buf, token_slice);

                chunks.push(buf);
                is_first = false;

                if exact_idx == exact_v.len() && token_idx == token_v.len() {
                    break;
                }
            }
            Some(chunks)
        }
        _ => None,
    }
}

/// Encode one record's payload (tag and fields, without the length prefix).
pub fn encode_record(r: &IndexRecord, b: &mut Vec<u8>) {
    match r {
        IndexRecord::File {
            path,
            size,
            mtime_secs,
            mtime_nanos,
            mode,
        } => {
            put_u8(b, TAG_FILE);
            put_path(b, path);
            put_u64(b, *size);
            b.extend_from_slice(&mtime_secs.to_le_bytes());
            put_u32(b, *mtime_nanos);
            put_u32(b, *mode);
        }
        IndexRecord::Fixed(f) => {
            put_u8(b, TAG_FIXED);
            put_path(b, &f.path);
            put_str(b, &f.detector);
            put_str(b, &f.channel);
            put_u8(b, severity_code(f.severity));
            b.extend_from_slice(&f.confidence.to_le_bytes());
            match f.hunk {
                Some(h) => {
                    put_u8(b, 1);
                    put_u64(b, h);
                }
                None => put_u8(b, 0),
            }
            let n = u32::try_from(f.evidence.len()).unwrap_or(u32::MAX);
            put_u32(b, n);
            for e in f.evidence.iter().take(n as usize) {
                put_str(b, e);
            }
        }
        IndexRecord::Path { path } => {
            put_u8(b, TAG_PATH);
            put_path(b, path);
        }
        IndexRecord::Text {
            path,
            d9_flags,
            hashes,
        } => {
            put_u8(b, TAG_TEXT);
            put_path(b, path);
            put_u8(b, *d9_flags);
            put_set(b, &hashes.line_hashes);
            put_set(b, &hashes.window_hashes);
            put_set(b, &hashes.removed_marker_hashes);
            put_set(b, &hashes.diff_shape_hashes);
            put_set(b, &hashes.winnow_hashes);
        }
        IndexRecord::Binary {
            path,
            channel,
            strings,
        } => {
            put_u8(b, TAG_BINARY);
            put_path(b, path);
            put_str(b, channel);
            put_set(b, &strings.exact);
            put_set(b, &strings.tokens);
        }
        IndexRecord::Pkg {
            path,
            name,
            version,
        } => {
            put_u8(b, TAG_PKG);
            put_path(b, path);
            put_str(b, name);
            put_opt_str(b, version.as_deref());
        }
        IndexRecord::TextCont { path, hashes } => {
            put_u8(b, TAG_TEXT_CONT);
            put_path(b, path);
            put_set(b, &hashes.line_hashes);
            put_set(b, &hashes.window_hashes);
            put_set(b, &hashes.removed_marker_hashes);
            put_set(b, &hashes.diff_shape_hashes);
            put_set(b, &hashes.winnow_hashes);
        }
        IndexRecord::BinaryCont {
            path,
            channel,
            strings,
        } => {
            put_u8(b, TAG_BINARY_CONT);
            put_path(b, path);
            put_str(b, channel);
            put_set(b, &strings.exact);
            put_set(b, &strings.tokens);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------

/// A bounds-checked cursor over one record's payload.
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], IndexError> {
        if n > self.remaining() {
            return Err(IndexError::Malformed(format!(
                "{what}: needs {n} bytes, record has {} left",
                self.remaining()
            )));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self, what: &str) -> Result<u8, IndexError> {
        Ok(self.take(1, what)?[0])
    }
    fn u32(&mut self, what: &str) -> Result<u32, IndexError> {
        let s = self.take(4, what)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn arr8(&mut self, what: &str) -> Result<[u8; 8], IndexError> {
        let s = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn u64(&mut self, what: &str) -> Result<u64, IndexError> {
        Ok(u64::from_le_bytes(self.arr8(what)?))
    }
    fn i64(&mut self, what: &str) -> Result<i64, IndexError> {
        Ok(i64::from_le_bytes(self.arr8(what)?))
    }
    fn f64(&mut self, what: &str) -> Result<f64, IndexError> {
        Ok(f64::from_le_bytes(self.arr8(what)?))
    }
    fn str(&mut self, what: &str) -> Result<String, IndexError> {
        let len = self.u32(what)? as usize;
        let s = self.take(len, what)?;
        String::from_utf8(s.to_vec())
            .map_err(|_| IndexError::Malformed(format!("{what}: not UTF-8")))
    }
    fn flag(&mut self, what: &str) -> Result<bool, IndexError> {
        match self.u8(what)? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(IndexError::Malformed(format!("{what}: bad flag {v}"))),
        }
    }
    fn path(&mut self) -> Result<IndexPath, IndexError> {
        let abs = self.flag("path kind")?;
        let s = self.str("path")?;
        Ok(if abs {
            IndexPath::Abs(s)
        } else {
            IndexPath::Rel(s)
        })
    }
    fn set(&mut self, what: &str) -> Result<HashSet<u64>, IndexError> {
        let n = self.u64(what)?;
        // Cap the count by the bytes left before allocating anything.
        if n > (self.remaining() / 8) as u64 {
            return Err(IndexError::Malformed(format!(
                "{what}: count {n} exceeds the {} bytes left",
                self.remaining()
            )));
        }
        let n = n as usize;
        let mut set = HashSet::with_capacity(n);
        for _ in 0..n {
            set.insert(self.u64(what)?);
        }
        Ok(set)
    }
}

/// Decode one record's payload. The whole payload must be used.
pub fn decode_record(payload: &[u8]) -> Result<IndexRecord, IndexError> {
    let mut c = Cur { b: payload, pos: 0 };
    let tag = c.u8("record tag")?;
    let rec = match tag {
        TAG_FILE => IndexRecord::File {
            path: c.path()?,
            size: c.u64("file size")?,
            mtime_secs: c.i64("mtime")?,
            mtime_nanos: {
                let n = c.u32("mtime nanos")?;
                if n >= 1_000_000_000 {
                    return Err(IndexError::Malformed(format!(
                        "mtime nanos {n} out of range"
                    )));
                }
                n
            },
            mode: c.u32("mode")?,
        },
        TAG_FIXED => {
            let path = c.path()?;
            let detector = c.str("detector")?;
            let channel = c.str("channel")?;
            let severity = match c.u8("severity")? {
                0 => Severity::Gate,
                1 => Severity::Review,
                2 => Severity::Info,
                v => return Err(IndexError::Malformed(format!("bad severity {v}"))),
            };
            let confidence = c.f64("confidence")?;
            let hunk = if c.flag("hunk flag")? {
                Some(c.u64("hunk")?)
            } else {
                None
            };
            let n = c.u32("evidence count")?;
            // Each evidence string takes at least its 4-byte length.
            if n as usize > c.remaining() / 4 {
                return Err(IndexError::Malformed(format!(
                    "evidence count {n} exceeds the bytes left"
                )));
            }
            let mut evidence = Vec::with_capacity(n as usize);
            for _ in 0..n {
                evidence.push(c.str("evidence")?);
            }
            IndexRecord::Fixed(StoredFinding {
                detector,
                channel,
                path,
                severity,
                confidence,
                hunk,
                evidence,
            })
        }
        TAG_PATH => IndexRecord::Path { path: c.path()? },
        TAG_TEXT => IndexRecord::Text {
            path: c.path()?,
            d9_flags: c.u8("d9 flags")?,
            hashes: UnitHashes {
                line_hashes: c.set("line hashes")?,
                window_hashes: c.set("window hashes")?,
                removed_marker_hashes: c.set("removed-marker hashes")?,
                diff_shape_hashes: c.set("diff-shape hashes")?,
                winnow_hashes: c.set("winnow hashes")?,
            },
        },
        TAG_BINARY => IndexRecord::Binary {
            path: c.path()?,
            channel: c.str("binary channel")?,
            strings: HashedBinaryStrings {
                exact: c.set("exact strings")?,
                tokens: c.set("run tokens")?,
            },
        },
        TAG_PKG => {
            let path = c.path()?;
            let name = c.str("package name")?;
            let version = if c.flag("version flag")? {
                Some(c.str("package version")?)
            } else {
                None
            };
            IndexRecord::Pkg {
                path,
                name,
                version,
            }
        }
        TAG_TEXT_CONT => IndexRecord::TextCont {
            path: c.path()?,
            hashes: UnitHashes {
                line_hashes: c.set("line hashes")?,
                window_hashes: c.set("window hashes")?,
                removed_marker_hashes: c.set("removed-marker hashes")?,
                diff_shape_hashes: c.set("diff-shape hashes")?,
                winnow_hashes: c.set("winnow hashes")?,
            },
        },
        TAG_BINARY_CONT => IndexRecord::BinaryCont {
            path: c.path()?,
            channel: c.str("binary channel")?,
            strings: HashedBinaryStrings {
                exact: c.set("exact strings")?,
                tokens: c.set("run tokens")?,
            },
        },
        t => return Err(IndexError::Malformed(format!("unknown record tag {t}"))),
    };
    if c.remaining() != 0 {
        return Err(IndexError::Malformed(format!(
            "{} trailing bytes in record",
            c.remaining()
        )));
    }
    Ok(rec)
}

/// Read exactly `n` bytes, or report what was being read as truncated.
fn read_exact_or_truncated<R: Read>(
    r: &mut R,
    buf: &mut [u8],
    what: &str,
) -> Result<(), IndexError> {
    r.read_exact(buf).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => IndexError::Truncated(what.to_string()),
        _ => IndexError::Io(e),
    })
}

/// Streams the records of one index file.
pub struct IndexReader<R: Read> {
    inner: R,
    root: String,
    canonical_root: String,
    count: u64,
    read: u64,
    finished: bool,
}

impl IndexReader<zstd::stream::read::Decoder<'static, BufReader<File>>> {
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        let f = File::open(path)?;
        let dec = zstd::stream::read::Decoder::new(f)?;
        Self::new(dec)
    }
}

impl<R: Read> IndexReader<R> {
    /// Read the header from a decompressed stream.
    pub fn new(mut inner: R) -> Result<Self, IndexError> {
        let mut magic = [0u8; 6];
        read_exact_or_truncated(&mut inner, &mut magic, "magic")?;
        if &magic != MAGIC {
            return Err(IndexError::BadMagic);
        }
        let mut b4 = [0u8; 4];
        read_exact_or_truncated(&mut inner, &mut b4, "version")?;
        let version = u32::from_le_bytes(b4);
        if version != FORMAT_VERSION {
            return Err(IndexError::UnsupportedVersion(version));
        }
        read_exact_or_truncated(&mut inner, &mut b4, "root length")?;
        let root_len = u32::from_le_bytes(b4);
        if root_len > MAX_ROOT_BYTES {
            return Err(IndexError::Malformed(format!(
                "root length {root_len} over the {MAX_ROOT_BYTES}-byte limit"
            )));
        }
        let mut root = vec![0u8; root_len as usize];
        read_exact_or_truncated(&mut inner, &mut root, "root")?;
        let root = String::from_utf8(root)
            .map_err(|_| IndexError::Malformed("root is not UTF-8".into()))?;

        read_exact_or_truncated(&mut inner, &mut b4, "canonical_root length")?;
        let canonical_root_len = u32::from_le_bytes(b4);
        if canonical_root_len > MAX_ROOT_BYTES {
            return Err(IndexError::Malformed(format!(
                "canonical_root length {canonical_root_len} over the {MAX_ROOT_BYTES}-byte limit"
            )));
        }
        let mut canonical_root = vec![0u8; canonical_root_len as usize];
        read_exact_or_truncated(&mut inner, &mut canonical_root, "canonical_root")?;
        let canonical_root = String::from_utf8(canonical_root)
            .map_err(|_| IndexError::Malformed("canonical_root is not UTF-8".into()))?;

        let mut b8 = [0u8; 8];
        read_exact_or_truncated(&mut inner, &mut b8, "record count")?;
        let count = u64::from_le_bytes(b8);
        Ok(Self {
            inner,
            root,
            canonical_root,
            count,
            read: 0,
            finished: false,
        })
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn canonical_root(&self) -> &str {
        &self.canonical_root
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// The next record, `None` after the last one. A count larger than the records present
    /// is `Truncated`; bytes after the last record are `Malformed`.
    ///
    /// Continuations are merged only by `query_reader` and `merge_continuations`.
    pub fn next_record(&mut self) -> Result<Option<IndexRecord>, IndexError> {
        if self.finished {
            return Ok(None);
        }
        if self.read == self.count {
            let mut probe = [0u8; 1];
            loop {
                match self.inner.read(&mut probe) {
                    Ok(0) => break,
                    Ok(_) => {
                        return Err(IndexError::Malformed("data after the last record".into()))
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(IndexError::Io(e)),
                }
            }
            self.finished = true;
            return Ok(None);
        }
        let what = format!("record {} of {}", self.read + 1, self.count);
        let mut b8 = [0u8; 8];
        read_exact_or_truncated(&mut self.inner, &mut b8, &what)?;
        let len = u64::from_le_bytes(b8);
        if len > MAX_RECORD_BYTES {
            return Err(IndexError::Malformed(format!(
                "{what}: length {len} over the {MAX_RECORD_BYTES}-byte limit"
            )));
        }
        // Grow only as bytes arrive: a hostile length can't force a large allocation.
        let mut payload = Vec::new();
        (&mut self.inner).take(len).read_to_end(&mut payload)?;
        if payload.len() as u64 != len {
            return Err(IndexError::Truncated(format!(
                "{what}: length {len} runs past the end ({} bytes present)",
                payload.len()
            )));
        }
        let rec = decode_record(&payload)?;
        self.read += 1;
        Ok(Some(rec))
    }

    /// Read every remaining record.
    ///
    /// Continuations are merged only by `query_reader` and `merge_continuations`.
    pub fn read_all(&mut self) -> Result<Vec<IndexRecord>, IndexError> {
        let mut out = Vec::new();
        while let Some(r) = self.next_record()? {
            out.push(r);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------------------
// Merging continuations
// ---------------------------------------------------------------------------------------

/// Helper that merges continuation records into their predecessor.
///
/// Shared between `query_reader` and `merge_continuations`.
///
/// The unit size bound counts every hash received, including duplicates of hashes already
/// merged, on purpose: it bounds the bytes a hostile index can make the reader process,
/// and the writer never repeats a hash across the records of one unit, so valid indexes
/// are unaffected.
struct ContinuationMerger<F> {
    max_unit_bytes: u64,
    pending: Option<IndexRecord>,
    pending_unit_bytes: u64,
    emit: F,
}

impl<F: FnMut(IndexRecord) -> Result<(), IndexError>> ContinuationMerger<F> {
    fn new(max_unit_bytes: u64, emit: F) -> Self {
        Self {
            max_unit_bytes,
            pending: None,
            pending_unit_bytes: 0,
            emit,
        }
    }

    fn push(&mut self, rec: IndexRecord) -> Result<(), IndexError> {
        match rec {
            IndexRecord::TextCont { path, hashes } => match self.pending.as_mut() {
                Some(IndexRecord::Text {
                    path: prev_path,
                    hashes: prev_hashes,
                    ..
                }) if prev_path == &path => {
                    let add_bytes = text_hash_bytes(&hashes);
                    if self.pending_unit_bytes.saturating_add(add_bytes) > self.max_unit_bytes {
                        return Err(IndexError::Malformed(format!(
                            "unit hash bytes exceed the {}-byte limit",
                            self.max_unit_bytes
                        )));
                    }
                    self.pending_unit_bytes += add_bytes;
                    prev_hashes.line_hashes.extend(hashes.line_hashes);
                    prev_hashes.window_hashes.extend(hashes.window_hashes);
                    prev_hashes
                        .removed_marker_hashes
                        .extend(hashes.removed_marker_hashes);
                    prev_hashes
                        .diff_shape_hashes
                        .extend(hashes.diff_shape_hashes);
                    prev_hashes.winnow_hashes.extend(hashes.winnow_hashes);
                }
                _ => {
                    return Err(IndexError::Malformed(
                        "text continuation without matching predecessor".to_string(),
                    ));
                }
            },
            IndexRecord::BinaryCont {
                path,
                channel,
                strings,
            } => match self.pending.as_mut() {
                Some(IndexRecord::Binary {
                    path: prev_path,
                    channel: prev_channel,
                    strings: prev_strings,
                    ..
                }) if prev_path == &path && prev_channel == &channel => {
                    let add_bytes = binary_hash_bytes(&strings);
                    if self.pending_unit_bytes.saturating_add(add_bytes) > self.max_unit_bytes {
                        return Err(IndexError::Malformed(format!(
                            "unit hash bytes exceed the {}-byte limit",
                            self.max_unit_bytes
                        )));
                    }
                    self.pending_unit_bytes += add_bytes;
                    prev_strings.exact.extend(strings.exact);
                    prev_strings.tokens.extend(strings.tokens);
                }
                _ => {
                    return Err(IndexError::Malformed(
                        "binary continuation without matching predecessor".to_string(),
                    ));
                }
            },
            other => {
                if let Some(prev) = self.pending.take() {
                    (self.emit)(prev)?;
                }
                let unit_bytes = match &other {
                    IndexRecord::Text { hashes, .. } => {
                        let b = text_hash_bytes(hashes);
                        if b > self.max_unit_bytes {
                            return Err(IndexError::Malformed(format!(
                                "unit hash bytes exceed the {}-byte limit",
                                self.max_unit_bytes
                            )));
                        }
                        b
                    }
                    IndexRecord::Binary { strings, .. } => {
                        let b = binary_hash_bytes(strings);
                        if b > self.max_unit_bytes {
                            return Err(IndexError::Malformed(format!(
                                "unit hash bytes exceed the {}-byte limit",
                                self.max_unit_bytes
                            )));
                        }
                        b
                    }
                    _ => 0,
                };
                self.pending = Some(other);
                self.pending_unit_bytes = unit_bytes;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), IndexError> {
        if let Some(prev) = self.pending.take() {
            (self.emit)(prev)?;
        }
        Ok(())
    }
}

/// Merge continuation records into their predecessor.
///
/// Continuations are merged only by `query_reader` and `merge_continuations`.
pub fn merge_continuations(records: Vec<IndexRecord>) -> Result<Vec<IndexRecord>, IndexError> {
    merge_continuations_with_limit(records, MAX_UNIT_BYTES)
}

/// `merge_continuations` with a configurable unit limit (for testing).
pub fn merge_continuations_with_limit(
    records: Vec<IndexRecord>,
    max_unit_bytes: u64,
) -> Result<Vec<IndexRecord>, IndexError> {
    let mut out = Vec::with_capacity(records.len());
    let mut merger = ContinuationMerger::new(max_unit_bytes, |rec| {
        out.push(rec);
        Ok(())
    });
    for rec in records {
        merger.push(rec)?;
    }
    merger.finish()?;
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------------------

fn strip_leading_sep(rel: &str) -> &str {
    #[cfg(windows)]
    {
        rel.trim_start_matches(['/', '\\'])
    }
    #[cfg(not(windows))]
    {
        rel.trim_start_matches('/')
    }
}

/// Whether `path` lies inside one of the excluded directories.
/// Compares component-wise with `Path::starts_with` on the canonical root.
fn is_excluded(path: &IndexPath, canon_root: &Path, exclude: &[PathBuf]) -> bool {
    if exclude.is_empty() {
        return false;
    }
    let full = match path {
        IndexPath::Rel(rel) => canon_root.join(strip_leading_sep(rel)),
        IndexPath::Abs(abs) => PathBuf::from(abs),
    };
    exclude.iter().any(|d| full.starts_with(d))
}

/// Match one record against a task, appending its findings.
fn query_record(
    rec: &IndexRecord,
    root: &str,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    findings: &mut Vec<Finding>,
) {
    match rec {
        IndexRecord::File { .. }
        | IndexRecord::TextCont { .. }
        | IndexRecord::BinaryCont { .. } => {}
        IndexRecord::Fixed(f) => findings.push(Finding {
            detector: f.detector.clone(),
            channel: f.channel.clone(),
            path: f.path.display(root),
            visibility: opts.visibility,
            severity: f.severity,
            confidence: f.confidence,
            hunk: f.hunk.and_then(|h| usize::try_from(h).ok()),
            evidence: f.evidence.clone(),
        }),
        IndexRecord::Path { path } => {
            let display = path.display(root);
            let match_path = match display.get(root.len()..) {
                Some(rel) if !rel.is_empty() => rel.trim_start_matches(['/', '\\']),
                _ => display.as_str(),
            };
            findings.extend(check_d9_path_builtin(match_path, &display, opts.visibility));
        }
        IndexRecord::Text {
            path,
            d9_flags,
            hashes,
        } => {
            let display = path.display(root);
            findings.extend(d9_builtin_content_findings(
                &display,
                *d9_flags,
                opts.visibility,
            ));
            findings.extend(match_unit_hashes(hashes, fp, opts, "D2", "file", &display));
        }
        IndexRecord::Binary {
            path,
            channel,
            strings,
        } => {
            let display = path.display(root);
            findings.extend(match_hashed_binary_items(
                strings, fp, opts, channel, &display,
            ));
        }
        IndexRecord::Pkg {
            path,
            name,
            version,
        } => {
            if opts.undated {
                return;
            }
            let display = path.display(root);
            findings.extend(check_d5a_name_and_version(
                name,
                version.as_deref(),
                &display,
                opts,
            ));
        }
    }
}

/// Match a task against every record of one index file. `opts.visibility` is the
/// visibility of the indexed root; `opts.exclude_dirs` are skipped as `scan` skips them.
pub fn query_index(
    index: &Path,
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Result<Vec<Finding>, IndexError> {
    query_index_with_limit(index, fp, opts, MAX_UNIT_BYTES)
}

/// `query_index` with a configurable unit limit (for testing).
pub fn query_index_with_limit(
    index: &Path,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    max_unit_bytes: u64,
) -> Result<Vec<Finding>, IndexError> {
    let mut reader = IndexReader::open(index)?;
    query_reader_with_limit(&mut reader, fp, opts, max_unit_bytes)
}

/// `query_index` over an already opened reader.
///
/// Continuations are merged only by `query_reader` and `merge_continuations`.
pub fn query_reader<R: Read>(
    reader: &mut IndexReader<R>,
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Result<Vec<Finding>, IndexError> {
    query_reader_with_limit(reader, fp, opts, MAX_UNIT_BYTES)
}

/// `query_reader` with a configurable unit limit (for testing).
pub fn query_reader_with_limit<R: Read>(
    reader: &mut IndexReader<R>,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    max_unit_bytes: u64,
) -> Result<Vec<Finding>, IndexError> {
    let root = reader.root().to_string();
    let canon_root = if opts.exclude_dirs.is_empty() {
        PathBuf::new()
    } else {
        let cr = reader.canonical_root();
        if !cr.is_empty() {
            PathBuf::from(cr)
        } else {
            Path::new(&root)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(&root))
        }
    };
    let mut findings = Vec::new();
    let mut merger = ContinuationMerger::new(max_unit_bytes, |rec| {
        let path = match &rec {
            IndexRecord::File { path, .. }
            | IndexRecord::Path { path }
            | IndexRecord::Text { path, .. }
            | IndexRecord::Binary { path, .. }
            | IndexRecord::Pkg { path, .. } => path,
            IndexRecord::Fixed(f) => &f.path,
            IndexRecord::TextCont { path, .. } | IndexRecord::BinaryCont { path, .. } => path,
        };
        if !is_excluded(path, &canon_root, &opts.exclude_dirs) {
            query_record(&rec, &root, fp, opts, &mut findings);
        }
        Ok(())
    });
    while let Some(rec) = reader.next_record()? {
        merger.push(rec)?;
    }
    merger.finish()?;
    Ok(findings)
}
