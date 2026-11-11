#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

pub const INITIAL_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub trait LogWriter: Write + Send {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogWriter for File {
    fn sync_all(&mut self) -> std::io::Result<()> {
        File::sync_all(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("requests.log already exists and is non-empty; pass --resume-log to resume")]
    ExistingLogNonEmpty,
    #[error("Failed to verify existing log for resume: {0}")]
    ResumeVerification(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("Bad line {line}: {reason}")]
    BadLine { line: usize, reason: String },
    #[error("I/O error on {path}: {message}")]
    Io { path: String, message: String },
    #[error("unanchored (no head file)")]
    Unanchored,
    #[error("Head mismatch: expected seq {expected_seq} hash {expected_hash}, got seq {actual_seq} hash {actual_hash}")]
    HeadMismatch {
        expected_seq: u64,
        expected_hash: String,
        actual_seq: u64,
        actual_hash: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogHead {
    pub seq: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DedupeEntry {
    pub authority: String,
    pub path_and_query: String,
    pub status: String,
    pub count: u64,
    pub first_seen_seq: u64,
    pub last_seen_seq: u64,
}

#[derive(Debug, Clone)]
pub struct LogEventParams<'a> {
    pub elapsed_ms: u64,
    pub request_id: u64,
    pub method: &'a str,
    pub authority: &'a str,
    pub path_and_query: &'a str,
    pub range: Option<(u64, u64)>,
    pub status: &'a str,
    pub bytes: u64,
}

pub struct LogManager {
    log_dir: PathBuf,
    log_file: Box<dyn LogWriter>,
    seq: u64,
    prev_hash: String,
    dedupe: BTreeMap<(String, String, String), DedupeEntry>,
}

impl LogManager {
    pub fn new<P: AsRef<Path>>(log_dir: P) -> Result<Self, LogError> {
        Self::new_opts(log_dir, false)
    }

    pub fn new_opts<P: AsRef<Path>>(log_dir: P, resume_log: bool) -> Result<Self, LogError> {
        Self::new_opts_recover(log_dir, resume_log, false)
    }

    pub fn new_opts_recover<P: AsRef<Path>>(
        log_dir: P,
        resume_log: bool,
        recover: bool,
    ) -> Result<Self, LogError> {
        let log_dir = log_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&log_dir)?;

        let log_path = log_dir.join("requests.log");
        let exists = log_path.exists();
        let non_empty = if exists {
            let meta = std::fs::metadata(&log_path)?;
            meta.len() > 0
        } else {
            false
        };

        if non_empty && !resume_log {
            return Err(LogError::ExistingLogNonEmpty);
        }

        let mut seq = 0;
        let mut prev_hash = INITIAL_PREV_HASH.to_string();
        let mut dedupe = BTreeMap::new();

        let head_path = head_path_for(&log_path);
        let head_exists = head_path.is_file();

        if resume_log && (non_empty || head_exists) {
            if !exists {
                File::create(&log_path)?;
            }
            // Verify existing log including head file, recovering if requested
            verify_log_recover(&log_path, false, recover)
                .map_err(|e| LogError::ResumeVerification(e.to_string()))?;

            let head_data = std::fs::read_to_string(&head_path)?;
            let head: LogHead = serde_json::from_str(&head_data)?;
            seq = head.seq;
            prev_hash = head.hash;

            // Rebuild dedupe index from verified log up to recovered head seq
            dedupe = Self::rebuild_dedupe_from_log_up_to(&log_path, seq)?;
        }

        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        Ok(Self {
            log_dir,
            log_file: Box::new(log_file),
            seq,
            prev_hash,
            dedupe,
        })
    }

    /// Rebuild dedupe index from verified log records in requests.log.
    pub fn rebuild_dedupe_from_log(
        log_path: &Path,
    ) -> Result<BTreeMap<(String, String, String), DedupeEntry>, LogError> {
        Self::rebuild_dedupe_from_log_up_to(log_path, u64::MAX)
    }

    /// Rebuild dedupe index from verified log records in requests.log up to max_seq.
    pub fn rebuild_dedupe_from_log_up_to(
        log_path: &Path,
        max_seq: u64,
    ) -> Result<BTreeMap<(String, String, String), DedupeEntry>, LogError> {
        let mut dedupe = BTreeMap::new();
        if !log_path.exists() {
            return Ok(dedupe);
        }

        let file = File::open(log_path)?;
        let reader = BufReader::new(file);

        for line_res in reader.lines() {
            let line = line_res?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                let authority = val.get("authority").and_then(|v| v.as_str());
                let path_and_query = val.get("path_and_query").and_then(|v| v.as_str());
                let status = val.get("status").and_then(|v| v.as_str());
                let seq = val.get("seq").and_then(|v| v.as_u64());

                if let (Some(auth), Some(pq), Some(st), Some(sq)) =
                    (authority, path_and_query, status, seq)
                {
                    if sq > max_seq {
                        continue;
                    }
                    let key = (auth.to_string(), pq.to_string(), st.to_string());
                    match dedupe.get_mut(&key) {
                        Some(entry) => {
                            entry.count += 1;
                            entry.last_seen_seq = sq;
                        }
                        None => {
                            dedupe.insert(
                                key,
                                DedupeEntry {
                                    authority: auth.to_string(),
                                    path_and_query: pq.to_string(),
                                    status: st.to_string(),
                                    count: 1,
                                    first_seen_seq: sq,
                                    last_seen_seq: sq,
                                },
                            );
                        }
                    }
                }
            }
        }

        Ok(dedupe)
    }

    pub fn new_with_writer<P: AsRef<Path>, W: LogWriter + 'static>(log_dir: P, writer: W) -> Self {
        Self {
            log_dir: log_dir.as_ref().to_path_buf(),
            log_file: Box::new(writer),
            seq: 0,
            prev_hash: INITIAL_PREV_HASH.to_string(),
            dedupe: BTreeMap::new(),
        }
    }

    /// Compute canonical JSON without hash and hash = BLAKE3(prev_hash_hex || canonical_json_without_hash)
    pub fn compute_hash(
        prev_hash: &str,
        seq: u64,
        params: &LogEventParams<'_>,
    ) -> Result<(String, String), LogError> {
        let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        map.insert("authority".into(), serde_json::json!(params.authority));
        map.insert("bytes".into(), serde_json::json!(params.bytes));
        map.insert("elapsed_ms".into(), serde_json::json!(params.elapsed_ms));
        map.insert("method".into(), serde_json::json!(params.method));
        map.insert(
            "path_and_query".into(),
            serde_json::json!(params.path_and_query),
        );
        map.insert("prev".into(), serde_json::json!(prev_hash));
        map.insert(
            "range".into(),
            match params.range {
                Some((s, e)) => serde_json::json!([s, e]),
                None => serde_json::Value::Null,
            },
        );
        map.insert("request_id".into(), serde_json::json!(params.request_id));
        map.insert("seq".into(), serde_json::json!(seq));
        map.insert("status".into(), serde_json::json!(params.status));

        let canonical_json_without_hash = serde_json::to_string(&map)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(canonical_json_without_hash.as_bytes());
        let hash = hasher.finalize().to_hex().to_string();

        map.insert("hash".into(), serde_json::json!(hash));
        let full_line = serde_json::to_string(&map)?;

        Ok((hash, full_line))
    }

    /// Append a log record to requests.log and update dedupe index.
    pub fn log_event(&mut self, params: &LogEventParams<'_>) -> Result<(), LogError> {
        let next_seq = self.seq + 1;
        let (hash, line) = Self::compute_hash(&self.prev_hash, next_seq, params)?;

        writeln!(self.log_file, "{line}")?;
        self.log_file.flush()?;

        // Commit only after write and flush succeed
        self.seq = next_seq;
        self.prev_hash = hash;

        // Update dedupe map
        let key = (
            params.authority.to_string(),
            params.path_and_query.to_string(),
            params.status.to_string(),
        );
        match self.dedupe.get_mut(&key) {
            Some(entry) => {
                entry.count += 1;
                entry.last_seen_seq = self.seq;
            }
            None => {
                self.dedupe.insert(
                    key,
                    DedupeEntry {
                        authority: params.authority.to_string(),
                        path_and_query: params.path_and_query.to_string(),
                        status: params.status.to_string(),
                        count: 1,
                        first_seen_seq: self.seq,
                        last_seen_seq: self.seq,
                    },
                );
            }
        }

        if self.seq.is_multiple_of(100) {
            self.write_dedupe_atomic()?;
        }

        Ok(())
    }

    /// Atomically write dedupe.json (temp file + rename).
    pub fn write_dedupe_atomic(&self) -> Result<(), LogError> {
        let tmp_path = self
            .log_dir
            .join(format!(".dedupe.json.tmp.{}", std::process::id()));
        let final_path = self.log_dir.join("dedupe.json");

        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;

            // Represent dedupe index as a map of compound key to DedupeEntry
            let mut out_map: BTreeMap<String, &DedupeEntry> = BTreeMap::new();
            for ((auth, pq, st), entry) in &self.dedupe {
                let compound_key = format!("{auth} {pq} {st}");
                out_map.insert(compound_key, entry);
            }

            let data = serde_json::to_string_pretty(&out_map)?;
            file.write_all(data.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }

        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Flush and fsync the log file and dedupe index, and write requests.log.head fsynced.
    pub fn finish(&mut self) -> Result<(), LogError> {
        self.log_file.flush()?;
        self.log_file.sync_all()?;
        self.write_dedupe_atomic()?;

        let head_path = head_path_for(&self.log_dir.join("requests.log"));
        let head = LogHead {
            seq: self.seq,
            hash: self.prev_hash.clone(),
        };
        write_head_atomic(&head_path, &head)?;

        Ok(())
    }

    pub fn current_seq(&self) -> u64 {
        self.seq
    }

    pub fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
}

/// Construct the head path for a given log file path, preserving native path bytes.
pub fn head_path_for(log_path: &Path) -> PathBuf {
    let mut os = log_path.as_os_str().to_os_string();
    os.push(".head");
    PathBuf::from(os)
}

/// Atomically write a LogHead to head_path (write to temp file in same dir, sync, rename, sync dir).
pub fn write_head_atomic(head_path: &Path, head: &LogHead) -> std::io::Result<()> {
    let dir = head_path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = dir.join(format!(
        ".head.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let head_json = serde_json::to_string_pretty(head).map_err(std::io::Error::other)?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        file.write_all(head_json.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
    }
    let res = std::fs::rename(&tmp_path, head_path);
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    res?;
    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

/// Truncate a trailing partial line in a log file (i.e. bytes after the last '\n' without a final newline).
pub fn truncate_trailing_partial_line(path: &Path) -> std::io::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let metadata = std::fs::metadata(path)?;
    let len = metadata.len();
    if len == 0 {
        return Ok(false);
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(std::io::SeekFrom::End(-1))?;
    let mut last_byte = [0u8; 1];
    file.read_exact(&mut last_byte)?;
    if last_byte[0] == b'\n' {
        return Ok(false);
    }

    // Trailing partial line detected (no final newline).
    // Find the last newline in the file.
    let mut pos = len - 1;
    let mut found_newline_pos = None;
    let chunk_size = 8192;
    let mut buf = vec![0u8; chunk_size];

    while pos > 0 {
        let read_size = (pos as usize).min(chunk_size);
        let start_pos = pos - read_size as u64;
        file.seek(std::io::SeekFrom::Start(start_pos))?;
        file.read_exact(&mut buf[..read_size])?;
        if let Some(idx) = buf[..read_size].iter().rposition(|&b| b == b'\n') {
            found_newline_pos = Some(start_pos + idx as u64);
            break;
        }
        pos = start_pos;
    }

    let new_len = match found_newline_pos {
        Some(newline_pos) => newline_pos + 1,
        None => 0,
    };

    file.set_len(new_len)?;
    file.sync_all()?;
    Ok(true)
}

/// Verify hash chain of requests.log with default anchored requirement.
pub fn verify_log<P: AsRef<Path>>(path: P) -> Result<usize, VerifyError> {
    verify_log_recover(path, false, false)
}

/// Verify hash chain of requests.log, optionally allowing unanchored log (no head file).
pub fn verify_log_ext<P: AsRef<Path>>(
    path: P,
    allow_unanchored: bool,
) -> Result<usize, VerifyError> {
    verify_log_recover(path, allow_unanchored, false)
}

/// Verify hash chain of requests.log with optional crash recovery.
pub fn verify_log_recover<P: AsRef<Path>>(
    path: P,
    allow_unanchored: bool,
    recover: bool,
) -> Result<usize, VerifyError> {
    let p = path.as_ref();
    let mut had_partial_line = false;
    if recover && p.exists() {
        had_partial_line = truncate_trailing_partial_line(p).map_err(|e| VerifyError::Io {
            path: p.display().to_string(),
            message: format!("failed to truncate partial line: {e}"),
        })?;
    }

    let file = File::open(p).map_err(|e| VerifyError::Io {
        path: p.display().to_string(),
        message: e.to_string(),
    })?;

    let reader = BufReader::new(file);
    let mut expected_prev = INITIAL_PREV_HASH.to_string();
    let mut line_num = 0;
    let mut verified_hashes = Vec::new();

    for line_res in reader.lines() {
        line_num += 1;
        let line = line_res.map_err(|e| VerifyError::BadLine {
            line: line_num,
            reason: format!("I/O reading line: {e}"),
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let mut map: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&line).map_err(|e| VerifyError::BadLine {
                line: line_num,
                reason: format!("invalid JSON: {e}"),
            })?;

        let recorded_hash = map
            .remove("hash")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| VerifyError::BadLine {
                line: line_num,
                reason: "missing 'hash' field".into(),
            })?;

        let recorded_prev = map
            .get("prev")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| VerifyError::BadLine {
                line: line_num,
                reason: "missing 'prev' field".into(),
            })?;

        let recorded_seq =
            map.get("seq")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| VerifyError::BadLine {
                    line: line_num,
                    reason: "missing or invalid 'seq' field".into(),
                })?;

        if recorded_seq != line_num as u64 {
            return Err(VerifyError::BadLine {
                line: line_num,
                reason: format!("seq mismatch: expected {line_num}, got {recorded_seq}"),
            });
        }

        if recorded_prev != expected_prev {
            return Err(VerifyError::BadLine {
                line: line_num,
                reason: format!(
                    "prev hash mismatch: expected {expected_prev}, got {recorded_prev}"
                ),
            });
        }

        let canonical_without_hash =
            serde_json::to_string(&map).map_err(|e| VerifyError::BadLine {
                line: line_num,
                reason: format!("failed to serialize canonical json: {e}"),
            })?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(recorded_prev.as_bytes());
        hasher.update(canonical_without_hash.as_bytes());
        let computed_hash = hasher.finalize().to_hex().to_string();

        if computed_hash != recorded_hash {
            return Err(VerifyError::BadLine {
                line: line_num,
                reason: format!("hash mismatch: expected {computed_hash}, got {recorded_hash}"),
            });
        }

        expected_prev = recorded_hash.clone();
        verified_hashes.push(recorded_hash);
    }

    let head_path = head_path_for(p);
    let existing_head = if head_path.is_file() {
        let head_data = std::fs::read_to_string(&head_path).map_err(|e| VerifyError::Io {
            path: head_path.display().to_string(),
            message: e.to_string(),
        })?;
        let head: LogHead = serde_json::from_str(&head_data).map_err(|e| VerifyError::Io {
            path: head_path.display().to_string(),
            message: format!("invalid head JSON: {e}"),
        })?;
        Some(head)
    } else {
        None
    };

    if recover {
        if let Some(ref head) = existing_head {
            if head.seq > line_num as u64 {
                return Err(VerifyError::HeadMismatch {
                    expected_seq: head.seq,
                    expected_hash: head.hash.clone(),
                    actual_seq: line_num as u64,
                    actual_hash: expected_prev.clone(),
                });
            }
            let actual_hash_at_head = if head.seq == 0 {
                INITIAL_PREV_HASH
            } else {
                &verified_hashes[(head.seq - 1) as usize]
            };
            if actual_hash_at_head != head.hash {
                return Err(VerifyError::HeadMismatch {
                    expected_seq: head.seq,
                    expected_hash: head.hash.clone(),
                    actual_seq: head.seq,
                    actual_hash: actual_hash_at_head.to_string(),
                });
            }
        }

        let needs_recovery = match &existing_head {
            None => true,
            Some(head) => head.seq < line_num as u64 || had_partial_line,
        };

        if needs_recovery {
            // Sync requests.log before publishing the new head
            let log_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(p)
                .or_else(|_| File::open(p))
                .map_err(|e| VerifyError::Io {
                    path: p.display().to_string(),
                    message: format!("failed to open log file for sync: {e}"),
                })?;
            log_file.sync_all().map_err(|e| VerifyError::Io {
                path: p.display().to_string(),
                message: format!("failed to sync log file: {e}"),
            })?;

            let checkpoint_seq = existing_head.as_ref().map(|h| h.seq).unwrap_or(0);
            let m = (line_num as u64).saturating_sub(checkpoint_seq);

            let new_head = LogHead {
                seq: line_num as u64,
                hash: expected_prev.clone(),
            };

            write_head_atomic(&head_path, &new_head).map_err(|e| VerifyError::Io {
                path: head_path.display().to_string(),
                message: format!("failed to write head file: {e}"),
            })?;

            println!(
                "recovered: head re-anchored at seq {line_num} ({m} records after the last checkpoint)"
            );
        }
    } else {
        match existing_head {
            Some(head) => {
                if head.seq != line_num as u64 || head.hash != expected_prev {
                    return Err(VerifyError::HeadMismatch {
                        expected_seq: head.seq,
                        expected_hash: head.hash,
                        actual_seq: line_num as u64,
                        actual_hash: expected_prev,
                    });
                }
            }
            None => {
                if !allow_unanchored {
                    return Err(VerifyError::Unanchored);
                }
            }
        }
    }

    Ok(line_num)
}
