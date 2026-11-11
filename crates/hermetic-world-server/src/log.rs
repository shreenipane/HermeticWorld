#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const INITIAL_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("Bad line {line}: {reason}")]
    BadLine { line: usize, reason: String },
    #[error("I/O error on {path}: {message}")]
    Io { path: String, message: String },
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
    log_file: File,
    seq: u64,
    prev_hash: String,
    dedupe: BTreeMap<(String, String, String), DedupeEntry>,
}

impl LogManager {
    pub fn new<P: AsRef<Path>>(log_dir: P) -> Result<Self, LogError> {
        let log_dir = log_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&log_dir)?;

        let log_path = log_dir.join("requests.log");
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        Ok(Self {
            log_dir,
            log_file,
            seq: 0,
            prev_hash: INITIAL_PREV_HASH.to_string(),
            dedupe: BTreeMap::new(),
        })
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
        self.seq += 1;
        let (hash, line) = Self::compute_hash(&self.prev_hash, self.seq, params)?;

        self.prev_hash = hash;
        writeln!(self.log_file, "{line}")?;
        self.log_file.flush()?;

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

    /// Flush and fsync the log file and dedupe index at server shutdown.
    pub fn finish(&mut self) -> Result<(), LogError> {
        self.write_dedupe_atomic()?;
        self.log_file.flush()?;
        self.log_file.sync_all()?;
        Ok(())
    }

    pub fn current_seq(&self) -> u64 {
        self.seq
    }
}

/// Verify hash chain of requests.log. Returns total records verified or error on first bad line.
pub fn verify_log<P: AsRef<Path>>(path: P) -> Result<usize, VerifyError> {
    let p = path.as_ref();
    let file = File::open(p).map_err(|e| VerifyError::Io {
        path: p.display().to_string(),
        message: e.to_string(),
    })?;

    let reader = BufReader::new(file);
    let mut expected_prev = INITIAL_PREV_HASH.to_string();
    let mut line_num = 0;

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

        expected_prev = recorded_hash;
    }

    Ok(line_num)
}
