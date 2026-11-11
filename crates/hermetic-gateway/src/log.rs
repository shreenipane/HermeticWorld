#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::quota::QuotaSnapshot;

pub const ANTHROPIC_ADAPTER_VERSION: &str = "2026-11-1";

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

pub struct HostLogger {
    log_file_path: PathBuf,
    file_mutex: Mutex<Option<std::fs::File>>,
}

impl HostLogger {
    pub fn new(log_dir: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let dir = log_dir.as_ref();
        create_dir_all(dir)?;
        let log_file_path = dir.join("gateway.jsonl");

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;

        Ok(Self {
            log_file_path,
            file_mutex: Mutex::new(Some(file)),
        })
    }

    pub fn log(&self, entry: &HostLogEntry) {
        let json_line = match serde_json::to_string(entry) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(_) => return,
        };

        let mut lock = match self.file_mutex.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(ref mut file) = *lock {
            let _ = file.write_all(json_line.as_bytes());
            let _ = file.flush();
        }
    }

    pub fn path(&self) -> &Path {
        &self.log_file_path
    }
}
