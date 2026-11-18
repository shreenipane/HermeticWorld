#![forbid(unsafe_code)]

//! Substrate exemption list verification for D4 and D6 (TR-SC-7, D4, D6).
//!
//! Exemption entries specify exact `(path, sha256, detector, reason)`. D4 and D6
//! skip only an exact `(path, digest)` match from this list; anything else,
//! including the same path with another digest, still fails.
//!
//! Never exempt anything inside the repository or the task's dependency closure;
//! never exempt by pattern or directory.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_EXEMPTIONS: usize = 1024;
pub const MAX_EXEMPTIONS_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_REASON_BYTES: usize = 256;
pub const MAX_VERIFY_FILE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
pub const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const READ_CHUNK_BYTES: usize = 65_536;
pub const MAX_VERIFY_READ_CHUNKS: usize = (MAX_VERIFY_FILE_BYTES as usize / READ_CHUNK_BYTES) + 1;

#[derive(Debug, thiserror::Error)]
pub enum ExemptionError {
    #[error("I/O error reading exemptions: {0}")]
    Io(#[from] io::Error),
    #[error("Exemptions JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Exemption list exceeds cap of {MAX_EXEMPTIONS}")]
    CountCapExceeded,
    #[error("Exemption file exceeds size cap of {MAX_EXEMPTIONS_BYTES} bytes")]
    SizeCapExceeded,
    #[error("Exemption path is invalid: '{0}'")]
    InvalidPath(String),
    #[error("Exemption reason is invalid: '{0}'")]
    InvalidReason(String),
    #[error("Invalid detector '{0}' in exemption (must be D4 or D6)")]
    InvalidDetector(String),
    #[error("Invalid SHA-256 digest in exemption: '{0}'")]
    InvalidDigest(String),
    #[error("Duplicate exemption entry for detector '{0}' and path '{1}'")]
    DuplicateEntry(String, String),
    #[error("Forbidden exemption for repository or task dependency path '{0}'")]
    ForbiddenPath(String),
    #[error("Exemption by pattern or directory is forbidden: '{0}'")]
    PatternOrDirectoryForbidden(String),
}

/// A named exemption record: exact `(path, sha256, detector, reason)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedExemption {
    pub path: String,
    pub sha256: String,
    pub detector: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ExemptionDocument {
    pub exemptions: Vec<NamedExemption>,
}

/// Normalizes a path string by removing leading `./` and `/`, ensuring standard forward slashes.
pub fn normalize_exemption_path(path_str: &str) -> String {
    let mut s = path_str.trim();
    for _ in 0..MAX_PATH_BYTES {
        if let Some(stripped) = s.strip_prefix("./") {
            s = stripped;
        } else if let Some(stripped) = s.strip_prefix('/') {
            s = stripped;
        } else {
            break;
        }
    }
    s.to_string()
}

/// Validates that an exemption path complies with security rules:
/// - Relative path, no `..`, non-empty, within byte limit
/// - No wildcards (*, ?, [, ])
/// - Not a directory (no trailing /)
/// - Never inside repository (`testbed/`) or task dependency closure (`opt/.../envs/`)
pub fn validate_exemption_path(path_str: &str) -> Result<String, ExemptionError> {
    let norm = normalize_exemption_path(path_str);
    if norm.is_empty() || norm.len() > MAX_PATH_BYTES {
        return Err(ExemptionError::InvalidPath(path_str.to_string()));
    }
    if norm.chars().any(char::is_control) {
        return Err(ExemptionError::InvalidPath(path_str.to_string()));
    }
    if norm.contains('*') || norm.contains('?') || norm.contains('[') || norm.contains(']') {
        return Err(ExemptionError::PatternOrDirectoryForbidden(
            path_str.to_string(),
        ));
    }
    if path_str.ends_with('/') || norm.ends_with('/') {
        return Err(ExemptionError::PatternOrDirectoryForbidden(
            path_str.to_string(),
        ));
    }

    let p = Path::new(&norm);
    if p.is_absolute() {
        return Err(ExemptionError::InvalidPath(path_str.to_string()));
    }
    for component in p.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ExemptionError::InvalidPath(path_str.to_string()));
            }
        }
    }

    // Never exempt anything inside the repository, git metadata, or the task's dependency closure
    if norm == ".git"
        || norm.starts_with(".git/")
        || norm.contains("/.git/")
        || norm.ends_with("/.git")
        || p.components().any(|c| c.as_os_str() == ".git")
    {
        return Err(ExemptionError::ForbiddenPath(norm));
    }
    if norm == "testbed" || norm.starts_with("testbed/") || norm.contains("/testbed/") {
        return Err(ExemptionError::ForbiddenPath(norm));
    }
    if norm.starts_with("opt/miniconda3/envs/") || norm.starts_with("opt/conda/envs/") {
        return Err(ExemptionError::ForbiddenPath(norm));
    }

    Ok(norm)
}

/// Validates all fields of a NamedExemption.
pub fn validate_exemption(entry: &NamedExemption) -> Result<NamedExemption, ExemptionError> {
    let detector = entry.detector.trim();
    if detector != "D4" && detector != "D6" {
        return Err(ExemptionError::InvalidDetector(entry.detector.clone()));
    }

    let sha = entry.sha256.trim().to_ascii_lowercase();
    if sha.len() != 64
        || !sha
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(ExemptionError::InvalidDigest(entry.sha256.clone()));
    }

    let reason = entry.reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.chars().any(char::is_control)
    {
        return Err(ExemptionError::InvalidReason(entry.reason.clone()));
    }

    let path = validate_exemption_path(&entry.path)?;

    Ok(NamedExemption {
        path,
        sha256: sha,
        detector: detector.to_string(),
        reason: reason.to_string(),
    })
}

/// Bounded, deterministic map of active substrate exemptions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExemptionMap {
    entries: BTreeMap<(String, String), NamedExemption>,
}

impl ExemptionMap {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn empty() -> Self {
        Self::new()
    }

    pub fn from_entries(raw_entries: Vec<NamedExemption>) -> Result<Self, ExemptionError> {
        if raw_entries.len() > MAX_EXEMPTIONS {
            return Err(ExemptionError::CountCapExceeded);
        }
        let mut map = BTreeMap::new();
        for raw in raw_entries {
            let valid = validate_exemption(&raw)?;
            let key = (valid.detector.clone(), valid.path.clone());
            if map.insert(key.clone(), valid).is_some() {
                return Err(ExemptionError::DuplicateEntry(key.0, key.1));
            }
        }
        Ok(Self { entries: map })
    }

    /// Load exemptions from JSON file bounded by MAX_EXEMPTIONS_BYTES.
    /// Accepts either `{"exemptions": [...]}` or `[...]`.
    pub fn load(path: &Path) -> Result<Self, ExemptionError> {
        let bytes = crate::safe_fs::read(path, MAX_EXEMPTIONS_BYTES).map_err(|e| {
            if e.to_string().contains("byte cap exceeded") {
                ExemptionError::SizeCapExceeded
            } else {
                ExemptionError::Io(e)
            }
        })?;

        let doc: Result<ExemptionDocument, _> = serde_json::from_slice(&bytes);
        let entries = match doc {
            Ok(d) => d.exemptions,
            Err(_) => {
                let list: Vec<NamedExemption> = serde_json::from_slice(&bytes)?;
                list
            }
        };

        Self::from_entries(entries)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, detector: &str, path: &str) -> Option<&NamedExemption> {
        let norm = normalize_exemption_path(path);
        if let Some(entry) = self.entries.get(&(detector.to_string(), norm.clone())) {
            return Some(entry);
        }
        if detector != "D4" {
            if let Some(name) = Path::new(&norm).file_name().and_then(|n| n.to_str()) {
                if let Some(entry) = self.entries.get(&(detector.to_string(), name.to_string())) {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Check if exact (path, digest) match exists for this detector and byte content.
    pub fn check_bytes(&self, detector: &str, path: &str, bytes: &[u8]) -> bool {
        if let Some(ex) = self.get(detector, path) {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let actual = hex::encode(hasher.finalize());
            actual == ex.sha256
        } else {
            false
        }
    }

    /// Check if exact (path, digest) match exists by safely reading the file on disk.
    pub fn check_file(&self, detector: &str, path: &str, file_on_disk: &Path) -> bool {
        if let Some(ex) = self.get(detector, path) {
            let mut file = match crate::safe_fs::open_regular(file_on_disk) {
                Ok(f) => f,
                Err(_) => return false,
            };
            if let Ok(meta) = file.metadata() {
                if meta.len() > MAX_VERIFY_FILE_BYTES {
                    return false;
                }
            }
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; READ_CHUNK_BYTES];
            let mut total_read = 0u64;
            let mut chunks = 0usize;
            loop {
                if chunks >= MAX_VERIFY_READ_CHUNKS {
                    return false;
                }
                chunks = chunks.saturating_add(1);
                let n = match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return false,
                };
                total_read = total_read.saturating_add(n as u64);
                if total_read > MAX_VERIFY_FILE_BYTES {
                    return false;
                }
                hasher.update(&buffer[..n]);
            }
            let actual = hex::encode(hasher.finalize());
            actual == ex.sha256
        } else {
            false
        }
    }

    /// Return all entries sorted by (detector, path).
    pub fn entries(&self) -> Vec<&NamedExemption> {
        self.entries.values().collect()
    }
}
