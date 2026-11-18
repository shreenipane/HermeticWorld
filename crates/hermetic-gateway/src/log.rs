#![forbid(unsafe_code)]

use hermetic_common::hash::HashChain;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::quota::QuotaSnapshot;

pub const ANTHROPIC_ADAPTER_VERSION: &str = "2026-11-1";

pub const GATEWAY_HEAD_FILE: &str = "gateway_head.json";
pub const GATEWAY_LOG_HEAD_FILE: &str = "gateway.jsonl.head";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayHeadSummary {
    pub records: u64,
    pub head: String,
    pub history_rewrite_count: u64,
    pub adapter_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostLogEntry {
    pub timestamp: String,
    pub adapter_version: String,
    pub endpoint: String,
    pub model: Option<String>,
    pub stream: bool,
    pub client_status: u16,
    pub upstream_status: Option<u16>,
    pub dropped_headers: BTreeMap<String, String>,
    pub original_error_body: Option<String>,
    pub history_rewrite: bool,
    pub history_rewrites_total: u64,
    pub quotas: QuotaSnapshot,
}

/// Default most bytes the host log may hold for one run (`gateway.jsonl`).
pub const MAX_HOST_LOG_BYTES: u64 = 256 * 1024 * 1024;

/// Longest upstream body or header value copied into one log entry; longer ones are cut.
pub const MAX_LOGGED_FIELD_BYTES: usize = 64 * 1024;

/// Text that replaces every occurrence of a secret (the upstream API key) in the log.
pub const REDACTED: &str = "<redacted>";

struct LogState {
    file: Option<std::fs::File>,
    written: u64,
    exhausted: bool,
    chain: HashChain,
    records: u64,
}

/// Append-only JSON-lines host log.
///
/// - The file is opened through `fsutil` (no symlinks anywhere in the directory path or the
///   leaf, regular file only, mode 0600).
/// - Every configured secret is replaced by `REDACTED` in each line before it is written, so
///   an upstream that echoes the API key (in an error body or a header) cannot put it on disk.
/// - Long fields are cut to `MAX_LOGGED_FIELD_BYTES`.
/// - The log holds at most `budget` bytes per run (counting what the file already held). An
///   entry that does not fit is not written; `log` returns false, the logger stays exhausted
///   for the rest of the run, and the gateway then refuses all further requests (it must not
///   serve what it can no longer record).
pub struct HostLogger {
    log_file_path: PathBuf,
    state: Mutex<LogState>,
    secrets: Vec<String>,
    budget: u64,
}

fn cut(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("...[truncated]");
    }
}

impl HostLogger {
    /// Opens `<log_dir>/gateway.jsonl` with the default budget and no secrets.
    pub fn new(log_dir: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        Self::open(log_dir, Vec::new(), MAX_HOST_LOG_BYTES)
    }

    /// Opens `<log_dir>/gateway.jsonl`, redacting `secrets`, holding at most `budget` bytes.
    pub fn open(
        log_dir: impl AsRef<Path>,
        secrets: Vec<String>,
        budget: u64,
    ) -> Result<Self, std::io::Error> {
        let dir = log_dir.as_ref();
        let dir_file = crate::fsutil::open_dir_nofollow_create(dir)?;
        let file = crate::fsutil::open_log_file(&dir_file, "gateway.jsonl")?;
        let written = file.metadata()?.len();
        Ok(Self {
            log_file_path: dir.join("gateway.jsonl"),
            state: Mutex::new(LogState {
                file: Some(file),
                written,
                exhausted: written >= budget,
                chain: HashChain::new(),
                records: 0,
            }),
            secrets: secrets.into_iter().filter(|s| !s.is_empty()).collect(),
            budget,
        })
    }

    fn redact(&self, mut line: String) -> String {
        for secret in &self.secrets {
            if line.contains(secret.as_str()) {
                line = line.replace(secret.as_str(), REDACTED);
            }
            // The JSON-escaped form, should the secret contain characters JSON escapes.
            if let Ok(quoted) = serde_json::to_string(secret) {
                let escaped = &quoted[1..quoted.len().saturating_sub(1)];
                if !escaped.is_empty() && escaped != secret && line.contains(escaped) {
                    line = line.replace(escaped, REDACTED);
                }
            }
        }
        line
    }

    /// Writes one entry. Returns false if it was not written (budget exhausted or I/O error).
    pub fn log(&self, entry: &HostLogEntry) -> bool {
        let mut entry = entry.clone();
        if let Some(body) = entry.original_error_body.as_mut() {
            *body = self.redact(std::mem::take(body));
            cut(body, MAX_LOGGED_FIELD_BYTES);
        }
        for v in entry.dropped_headers.values_mut() {
            *v = self.redact(std::mem::take(v));
            cut(v, MAX_LOGGED_FIELD_BYTES);
        }
        let json_line = match serde_json::to_string(&entry) {
            Ok(s) => {
                let mut s = self.redact(s);
                s.push('\n');
                s
            }
            Err(_) => return false,
        };

        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.exhausted {
            return false;
        }
        let len = json_line.len() as u64;
        if state.written.saturating_add(len) > self.budget {
            state.exhausted = true;
            state.file = None;
            return false;
        }
        let ok = match state.file.as_mut() {
            Some(file) => file.write_all(json_line.as_bytes()).is_ok() && file.flush().is_ok(),
            None => false,
        };
        if ok {
            state.written = state.written.saturating_add(len);
            state.chain.append(json_line.as_bytes());
            state.records = state.records.saturating_add(1);
        } else {
            state.exhausted = true;
            state.file = None;
        }
        ok
    }

    /// Current hash chain head as lowercase hexadecimal string.
    pub fn head_hex(&self) -> String {
        let state = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.chain.head_hex()
    }

    /// Current hash chain head formatted as standard digest `sha256:<hex>`.
    pub fn head_digest(&self) -> String {
        format!("sha256:{}", self.head_hex())
    }

    /// Total count of log records recorded in the hash chain.
    pub fn records_count(&self) -> u64 {
        let state = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.records
    }

    pub fn persist_head_with_dir(
        &self,
        dir: &std::fs::File,
        history_rewrite_count: u64,
        adapter_version: &str,
    ) -> Result<(), std::io::Error> {
        let (head, records) = {
            let state = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            (format!("sha256:{}", state.chain.head_hex()), state.records)
        };
        let summary = GatewayHeadSummary {
            records,
            head,
            history_rewrite_count,
            adapter_version: adapter_version.to_string(),
        };
        let bytes = serde_json::to_vec(&summary)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::fsutil::write_state_file(dir, GATEWAY_HEAD_FILE, &bytes)?;
        crate::fsutil::write_state_file(dir, GATEWAY_LOG_HEAD_FILE, &bytes)?;
        Ok(())
    }

    /// Atomically persists the gateway log head summary to `GATEWAY_HEAD_FILE` and
    /// `GATEWAY_LOG_HEAD_FILE` in `log_dir`.
    pub fn persist_head(
        &self,
        log_dir: &Path,
        history_rewrite_count: u64,
        adapter_version: &str,
    ) -> Result<(), std::io::Error> {
        let dir = crate::fsutil::open_dir_nofollow_create(log_dir)?;
        self.persist_head_with_dir(&dir, history_rewrite_count, adapter_version)
    }

    /// True once the log can no longer be written for this run.
    pub fn is_exhausted(&self) -> bool {
        match self.state.lock() {
            Ok(g) => g.exhausted,
            Err(p) => p.into_inner().exhausted,
        }
    }

    pub fn path(&self) -> &Path {
        &self.log_file_path
    }
}
