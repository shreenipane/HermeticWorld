#![forbid(unsafe_code)]

use crate::safe_fs::{invalid, Directory};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MAX_LOG_LINE_BYTES: u64 = 128 * 1024;
pub const MAX_CHECKPOINT_BYTES: u64 = 1024;
pub const MAX_LOG_RECORDS: u64 = 16384;
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DEDUPE_ENTRIES: usize = 8320;
pub const TERMINAL_RESERVE_ENTRIES: usize = 64;
pub const TERMINAL_RESERVE_RECORDS: u64 = 64;
pub const MAX_DEDUPE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EVENT_TEXT_BYTES: usize = 16 * 1024;

pub const INITIAL_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub trait LogWriter: Write + Send {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("durable audit writer required"))
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

#[derive(Default, Clone, Debug)]
pub struct RunState {
    pub requests: u64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub binding: Option<String>,
    pub incomplete_transmissions: u64,
}

type Dedupe = BTreeMap<(String, String, String), DedupeEntry>;

pub struct LogManager {
    log_dir: PathBuf,
    directory: Option<Directory>,
    log_file: Box<dyn LogWriter>,
    seq: u64,
    prev_hash: String,
    log_bytes: u64,
    dedupe_bytes: usize,
    dedupe: Dedupe,
    state: RunState,
    failed: bool,
}

pub fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        "tampered"
            | "limit_exceeded"
            | "clock_exhausted"
            | "write_error"
            | "frame_timeout"
            | "read_timeout"
    )
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
        Self::new_opts_recover_binding(log_dir, resume_log, recover, None)
    }
    pub fn new_opts_recover_binding<P: AsRef<Path>>(
        log_dir: P,
        resume_log: bool,
        recover: bool,
        expected_binding: Option<&str>,
    ) -> Result<Self, LogError> {
        let log_dir = log_dir.as_ref().to_path_buf();
        let directory = Directory::create(&log_dir)?;
        let log_name = Path::new("requests.log");
        let exists = entry_exists(&directory, log_name)?;

        if resume_log && !exists {
            return Err(LogError::ResumeVerification("requests.log missing".into()));
        }

        // Fresh startup must never reuse any artifact, including an empty log.
        if !resume_log {
            for name in [
                "requests.log",
                "requests.log.head",
                "dedupe.json",
                ".dedupe.json.tmp",
                ".head.tmp",
            ] {
                if entry_exists(&directory, Path::new(name))? {
                    return Err(LogError::ExistingLogNonEmpty);
                }
            }
        }
        let mut log_file = directory.open_file(log_name, true, !exists)?;
        let mut seq = 0;
        let mut prev_hash = INITIAL_PREV_HASH.to_string();
        let mut state = RunState::default();
        let mut dedupe = BTreeMap::new();
        if resume_log {
            // Retain open descriptor through binding validation, scanning, recovery, rebuilding, and appending
            let scan = verify_on_file(
                &directory,
                log_name,
                &mut log_file,
                false,
                recover,
                true,
                expected_binding,
            )
            .map_err(|e| LogError::ResumeVerification(e.to_string()))?;
            seq = scan.count;
            prev_hash = scan.hash;
            state = scan.state;
            dedupe = scan.dedupe;
        }
        let log_bytes = log_file.metadata()?.len();
        directory.sync()?;
        let dedupe_bytes = dedupe.keys().map(key_cost).sum();
        Ok(Self {
            log_dir,
            directory: Some(directory),
            log_file: Box::new(log_file),
            seq,
            prev_hash,
            log_bytes,
            dedupe_bytes,
            dedupe,
            state,
            failed: false,
        })
    }

    pub fn validate_binding(log_dir: &Path, binding: &str) -> Result<(), LogError> {
        let directory = Directory::open(log_dir)?;
        let mut file = directory.open_file(Path::new("requests.log"), false, false)?;
        let scan = verify_on_file(
            &directory,
            Path::new("requests.log"),
            &mut file,
            false,
            true,
            false,
            Some(binding),
        )
        .map_err(|e| LogError::ResumeVerification(e.to_string()))?;
        if scan.state.binding.as_deref() != Some(binding) {
            return Err(invalid().into());
        }
        Ok(())
    }

    pub(crate) fn descriptor_path(&self) -> io::Result<PathBuf> {
        Ok(self.directory()?.descriptor_path())
    }

    pub fn run_state(&self) -> &RunState {
        &self.state
    }

    pub fn rebuild_dedupe_from_log(log_path: &Path) -> Result<Dedupe, LogError> {
        Self::rebuild_dedupe_from_log_up_to(log_path, MAX_LOG_RECORDS)
    }
    pub fn rebuild_dedupe_from_log_up_to(
        log_path: &Path,
        max_seq: u64,
    ) -> Result<Dedupe, LogError> {
        let (directory, name) = directory_and_name(log_path)?;
        verify_in_directory(&directory, &name, true, false, false)
            .map_err(|e| LogError::ResumeVerification(e.to_string()))?;
        rebuild(&directory, &name, max_seq.min(MAX_LOG_RECORDS))
    }

    pub fn new_with_writer<P: AsRef<Path>, W: LogWriter + 'static>(log_dir: P, writer: W) -> Self {
        Self {
            log_dir: log_dir.as_ref().to_path_buf(),
            directory: None,
            log_file: Box::new(writer),
            seq: 0,
            prev_hash: INITIAL_PREV_HASH.to_string(),
            dedupe: BTreeMap::new(),
            dedupe_bytes: 0,
            log_bytes: 0,
            state: RunState::default(),
            failed: false,
        }
    }
    /// Compute canonical JSON without hash and hash = BLAKE3(prev_hash_hex || canonical_json_without_hash)
    pub fn compute_hash(
        prev_hash: &str,
        seq: u64,
        params: &LogEventParams<'_>,
    ) -> Result<(String, String), LogError> {
        validate_params(params)?;
        if prev_hash.len() != 64 || seq > MAX_LOG_RECORDS {
            return Err(invalid().into());
        }
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

    /// Each record is durable before its caller can transmit content.
    pub fn log_event(&mut self, params: &LogEventParams<'_>) -> Result<(), LogError> {
        if self.failed {
            return Err(invalid().into());
        }
        validate_params(params)?;
        let is_terminal = is_terminal_status(params.status);
        let max_records = if is_terminal {
            MAX_LOG_RECORDS
        } else {
            MAX_LOG_RECORDS.saturating_sub(TERMINAL_RESERVE_RECORDS)
        };
        let next_seq = self
            .seq
            .checked_add(1)
            .filter(|n| *n <= max_records)
            .ok_or_else(invalid)?;
        let key = (
            params.authority.to_owned(),
            params.path_and_query.to_owned(),
            params.status.to_owned(),
        );
        let cost = if self.dedupe.contains_key(&key) {
            0
        } else {
            key_cost(&key)
        };
        let max_entries = if is_terminal {
            MAX_DEDUPE_ENTRIES.saturating_add(TERMINAL_RESERVE_ENTRIES)
        } else {
            MAX_DEDUPE_ENTRIES
        };
        if cost > 0
            && (self.dedupe.len() >= max_entries
                || self.dedupe_bytes.saturating_add(cost) > MAX_DEDUPE_BYTES)
        {
            return Err(invalid().into());
        }
        let mut state = self.state.clone();
        update_state(&mut state, params)?;
        let (hash, line) = Self::compute_hash(&self.prev_hash, next_seq, params)?;
        let bytes = (line.len() as u64).checked_add(1).ok_or_else(invalid)?;
        if bytes > MAX_LOG_LINE_BYTES || self.log_bytes.saturating_add(bytes) > MAX_LOG_BYTES {
            return Err(invalid().into());
        }
        let result = (|| -> io::Result<()> {
            writeln!(self.log_file, "{line}")?;
            self.log_file.flush()?;
            self.log_file.sync_all()
        })();
        if let Err(e) = result {
            self.failed = true;
            return Err(e.into());
        }
        self.seq = next_seq;
        self.prev_hash = hash;
        self.log_bytes = self.log_bytes.saturating_add(bytes);
        self.dedupe_bytes = self.dedupe_bytes.saturating_add(cost);
        self.state = state;
        update_dedupe(&mut self.dedupe, key, self.seq)?;
        if self.seq.is_multiple_of(100) {
            self.write_dedupe_atomic()?;
        }
        Ok(())
    }

    fn directory(&self) -> io::Result<Directory> {
        match &self.directory {
            Some(d) => Ok(d.clone()),
            None => Directory::open(&self.log_dir),
        }
    }
    pub fn write_dedupe_atomic(&self) -> Result<(), LogError> {
        let mut map = BTreeMap::new();
        for ((auth, pq, status), entry) in &self.dedupe {
            map.insert(format!("{auth} {pq} {status}"), entry);
        }
        let data = serde_json::to_vec_pretty(&map)?;
        self.directory()?.atomic_write(
            Path::new("dedupe.json"),
            Path::new(".dedupe.json.tmp"),
            &data,
        )?;
        Ok(())
    }
    pub fn finish(&mut self) -> Result<(), LogError> {
        if self.failed {
            return Err(invalid().into());
        }
        self.log_file.flush()?;
        self.log_file.sync_all()?;
        self.write_dedupe_atomic()?;
        publish_head(
            &self.directory()?,
            Path::new("requests.log.head"),
            &LogHead {
                seq: self.seq,
                hash: self.prev_hash.clone(),
            },
        )?;
        Ok(())
    }
    pub fn current_seq(&self) -> u64 {
        self.seq
    }
    pub fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
}

fn validate_params(params: &LogEventParams<'_>) -> io::Result<()> {
    for text in [
        params.authority,
        params.path_and_query,
        params.method,
        params.status,
    ] {
        if text.len() > MAX_EVENT_TEXT_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}
fn key_cost(key: &(String, String, String)) -> usize {
    key.0
        .len()
        .saturating_add(key.1.len())
        .saturating_add(key.2.len())
        .saturating_mul(2)
        .saturating_add(256)
}
fn update_dedupe(dedupe: &mut Dedupe, key: (String, String, String), seq: u64) -> io::Result<()> {
    if !dedupe.contains_key(&key)
        && (dedupe.len() >= MAX_DEDUPE_ENTRIES.saturating_add(TERMINAL_RESERVE_ENTRIES)
            || dedupe
                .keys()
                .map(key_cost)
                .sum::<usize>()
                .saturating_add(key_cost(&key))
                > MAX_DEDUPE_BYTES)
    {
        return Err(invalid());
    }
    match dedupe.get_mut(&key) {
        Some(entry) => {
            entry.count = entry.count.checked_add(1).ok_or_else(invalid)?;
            entry.last_seen_seq = seq;
        }
        None => {
            dedupe.insert(
                key.clone(),
                DedupeEntry {
                    authority: key.0,
                    path_and_query: key.1,
                    status: key.2,
                    count: 1,
                    first_seen_seq: seq,
                    last_seen_seq: seq,
                },
            );
        }
    }
    Ok(())
}
fn update_state(state: &mut RunState, params: &LogEventParams<'_>) -> io::Result<()> {
    state.elapsed_ms = state.elapsed_ms.max(params.elapsed_ms);
    match params.status {
        "run_config" => {
            if state.binding.is_some() {
                return Err(invalid());
            }
            state.binding = Some(params.path_and_query.to_owned());
        }
        "transmission_intent" => {
            state.requests = state.requests.checked_add(1).ok_or_else(invalid)?;
            state.bytes = state.bytes.checked_add(params.bytes).ok_or_else(invalid)?;
            state.incomplete_transmissions = state
                .incomplete_transmissions
                .checked_add(1)
                .ok_or_else(invalid)?;
        }
        "write_error" | "200" | "206" | "404" | "416" | "frame_timeout" | "read_timeout" => {
            state.incomplete_transmissions = state.incomplete_transmissions.saturating_sub(1);
        }
        _ => (),
    }
    Ok(())
}

fn entry_exists(directory: &Directory, name: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(directory.path(name)?) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
fn directory_and_name(path: &Path) -> io::Result<(Directory, PathBuf)> {
    Ok((
        Directory::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?,
        PathBuf::from(path.file_name().ok_or_else(invalid)?),
    ))
}
pub fn head_path_for(log_path: &Path) -> PathBuf {
    let mut os = log_path.as_os_str().to_os_string();
    os.push(".head");
    PathBuf::from(os)
}
fn publish_head(directory: &Directory, name: &Path, head: &LogHead) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(head).map_err(|_| invalid())?;
    if data.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(invalid());
    }
    directory.atomic_write(name, Path::new(".head.tmp"), &data)
}
pub fn write_head_atomic(head_path: &Path, head: &LogHead) -> io::Result<()> {
    let (directory, name) = directory_and_name(head_path)?;
    publish_head(&directory, &name, head)
}

// All callers share the same line and whole-file budgets, including rebuilds.
fn next_line<R: Read>(reader: &mut BufReader<R>) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    reader
        .take(MAX_LOG_LINE_BYTES.saturating_add(1))
        .read_until(b'\n', &mut line)?;
    if line.len() as u64 > MAX_LOG_LINE_BYTES {
        return Err(invalid());
    }
    Ok(line)
}

fn params_from_value(value: &serde_json::Value) -> io::Result<LogEventParams<'_>> {
    let text = |key| value.get(key).and_then(|v| v.as_str()).ok_or_else(invalid);
    Ok(LogEventParams {
        elapsed_ms: value
            .get("elapsed_ms")
            .and_then(|v| v.as_u64())
            .ok_or_else(invalid)?,
        request_id: value
            .get("request_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(invalid)?,
        method: text("method")?,
        authority: text("authority")?,
        path_and_query: text("path_and_query")?,
        range: None,
        status: text("status")?,
        bytes: value
            .get("bytes")
            .and_then(|v| v.as_u64())
            .ok_or_else(invalid)?,
    })
}

fn rebuild(directory: &Directory, name: &Path, _max_seq: u64) -> Result<Dedupe, LogError> {
    let scan = verify_in_directory(directory, name, true, false, false)
        .map_err(|e| LogError::ResumeVerification(e.to_string()))?;
    Ok(scan.dedupe)
}

struct Scan {
    count: u64,
    hash: String,
    state: RunState,
    dedupe: Dedupe,
}

fn bad(line: u64, reason: &str) -> VerifyError {
    VerifyError::BadLine {
        line: usize::try_from(line).unwrap_or(usize::MAX),
        reason: reason.into(),
    }
}
fn io_error(_: io::Error) -> VerifyError {
    VerifyError::Io {
        path: "audit artifact".into(),
        message: "audit I/O failed".into(),
    }
}

fn verify_on_file(
    directory: &Directory,
    name: &Path,
    file: &mut File,
    allow_unanchored: bool,
    recover: bool,
    mutate: bool,
    expected_binding: Option<&str>,
) -> Result<Scan, VerifyError> {
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let head_name = head_path_for(name);
    let head = if entry_exists(directory, &head_name).map_err(io_error)? {
        let data = directory
            .read(&head_name, MAX_CHECKPOINT_BYTES)
            .map_err(io_error)?;
        let head: LogHead =
            serde_json::from_slice(&data).map_err(|_| bad(0, "invalid checkpoint"))?;
        if head.seq > MAX_LOG_RECORDS
            || head.hash.len() != 64
            || !head.hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(bad(0, "invalid checkpoint"));
        }
        Some(head)
    } else if name != Path::new("requests.log")
        && name
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("requests.log"))
        && entry_exists(directory, Path::new("requests.log.head")).map_err(io_error)?
    {
        let data = directory
            .read(Path::new("requests.log.head"), MAX_CHECKPOINT_BYTES)
            .map_err(io_error)?;
        let head: LogHead =
            serde_json::from_slice(&data).map_err(|_| bad(0, "invalid checkpoint"))?;
        if head.seq > MAX_LOG_RECORDS
            || head.hash.len() != 64
            || !head.hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(bad(0, "invalid checkpoint"));
        }
        Some(head)
    } else {
        None
    };

    if file.metadata().map_err(io_error)?.len() > MAX_LOG_BYTES {
        return Err(bad(0, "log size limit"));
    }

    let mut count = 0u64;
    let mut length = 0u64;
    let mut partial = false;
    let mut hash = INITIAL_PREV_HASH.to_string();
    let mut hash_at_checkpoint = if head.as_ref().is_some_and(|h| h.seq == 0) {
        Some(hash.clone())
    } else {
        None
    };
    let mut state = RunState::default();
    let mut dedupe = BTreeMap::new();
    let mut reader = BufReader::new(std::io::Read::by_ref(file));
    loop {
        let line = next_line(&mut reader)
            .map_err(|_| bad(count.saturating_add(1), "record size or I/O limit"))?;
        if line.is_empty() {
            break;
        }
        if count >= MAX_LOG_RECORDS {
            return Err(bad(count, "record count limit"));
        }
        if line.last() != Some(&b'\n') {
            if !recover {
                return Err(bad(count.saturating_add(1), "partial record"));
            }
            partial = true;
            break;
        }
        let seq = count
            .checked_add(1)
            .ok_or_else(|| bad(count, "record count limit"))?;
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(bad(seq, "blank record"));
        }
        let mut map: BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&line).map_err(|_| bad(seq, "invalid JSON"))?;
        let recorded_hash = map
            .remove("hash")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| bad(seq, "missing hash"))?;
        if map.get("seq").and_then(|v| v.as_u64()) != Some(seq) {
            return Err(bad(seq, "seq mismatch"));
        }
        if map.get("prev").and_then(|v| v.as_str()) != Some(&hash) {
            return Err(bad(seq, "prev hash mismatch"));
        }
        let canonical = serde_json::to_vec(&map).map_err(|_| bad(seq, "invalid record"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(hash.as_bytes());
        hasher.update(&canonical);
        if hasher.finalize().to_hex().as_str() != recorded_hash {
            return Err(bad(seq, "hash mismatch"));
        }
        let value = serde_json::to_value(&map).map_err(|_| bad(seq, "invalid record"))?;
        let params = params_from_value(&value).map_err(|_| bad(seq, "invalid record"))?;
        validate_params(&params).map_err(|_| bad(seq, "record field limit"))?;
        update_state(&mut state, &params).map_err(|_| bad(seq, "invalid run state"))?;
        if seq == 1 {
            if let Some(expected) = expected_binding {
                if state.binding.as_deref() != Some(expected) {
                    return Err(bad(seq, "binding mismatch"));
                }
            }
        }
        update_dedupe(
            &mut dedupe,
            (
                params.authority.to_owned(),
                params.path_and_query.to_owned(),
                params.status.to_owned(),
            ),
            seq,
        )
        .map_err(|_| bad(seq, "dedupe budget"))?;
        count = seq;
        hash = recorded_hash;
        length = length
            .checked_add(line.len() as u64)
            .filter(|n| *n <= MAX_LOG_BYTES)
            .ok_or_else(|| bad(seq, "log size limit"))?;
        if head.as_ref().is_some_and(|h| h.seq == seq) {
            hash_at_checkpoint = Some(hash.clone());
        }
    }
    drop(reader);

    if let Some(checkpoint) = &head {
        let actual = hash_at_checkpoint.as_deref().unwrap_or(&hash);
        if checkpoint.seq > count
            || actual != checkpoint.hash
            || (!recover && (checkpoint.seq != count || checkpoint.hash != hash))
        {
            return Err(VerifyError::HeadMismatch {
                expected_seq: checkpoint.seq,
                expected_hash: checkpoint.hash.clone(),
                actual_seq: count,
                actual_hash: actual.into(),
            });
        }
    } else if !recover && !allow_unanchored {
        return Err(VerifyError::Unanchored);
    }

    // No input changes occur until every complete record and the checkpoint verify.
    if recover && mutate && (partial || head.as_ref().is_none_or(|h| h.seq != count)) {
        if partial {
            file.set_len(length).map_err(io_error)?;
        }
        file.sync_all().map_err(io_error)?;
        publish_head(
            directory,
            &head_name,
            &LogHead {
                seq: count,
                hash: hash.clone(),
            },
        )
        .map_err(io_error)?;
    }
    if recover && mutate {
        directory.sync().map_err(io_error)?;
    }
    file.seek(SeekFrom::End(0)).map_err(io_error)?;
    Ok(Scan {
        count,
        hash,
        state,
        dedupe,
    })
}

fn verify_in_directory(
    directory: &Directory,
    name: &Path,
    allow_unanchored: bool,
    recover: bool,
    mutate: bool,
) -> Result<Scan, VerifyError> {
    let mut file = directory
        .open_file(name, recover && mutate, false)
        .map_err(io_error)?;
    verify_on_file(
        directory,
        name,
        &mut file,
        allow_unanchored,
        recover,
        mutate,
        None,
    )
}

/// Only truncate a suffix after validating the checkpoint and complete chain.
pub fn truncate_trailing_partial_line(path: &Path) -> io::Result<bool> {
    let before = std::fs::symlink_metadata(path)?.len();
    verify_log_recover(path, false, true).map_err(|_| invalid())?;
    Ok(std::fs::symlink_metadata(path)?.len() != before)
}
pub fn verify_log<P: AsRef<Path>>(path: P) -> Result<usize, VerifyError> {
    verify_log_recover(path, false, false)
}
pub fn verify_log_ext<P: AsRef<Path>>(
    path: P,
    allow_unanchored: bool,
) -> Result<usize, VerifyError> {
    verify_log_recover(path, allow_unanchored, false)
}
pub fn verify_log_recover<P: AsRef<Path>>(
    path: P,
    allow_unanchored: bool,
    recover: bool,
) -> Result<usize, VerifyError> {
    let (directory, name) = directory_and_name(path.as_ref()).map_err(io_error)?;
    let scan = verify_in_directory(&directory, &name, allow_unanchored, recover, true)?;
    usize::try_from(scan.count).map_err(|_| bad(scan.count, "record count limit"))
}
