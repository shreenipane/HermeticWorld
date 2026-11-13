#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::format::format_hex;

/// Deterministic validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractReport {
    pub accepted: Vec<AcceptedPath>,
    pub dropped: Vec<DroppedPath>,
    pub restored: Vec<RestoredPath>,
    pub flags: Vec<ReportFlag>,
    pub totals: ReportTotals,
    pub tree_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedPath {
    pub path: String,
    pub kind: String,
    pub mode: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedPath {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoredPath {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportFlag {
    pub flag_type: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportTotals {
    pub records_received: u64,
    pub files_accepted: u64,
    pub directories_accepted: u64,
    pub deletions_accepted: u64,
    pub total_bytes_accepted: u64,
    pub paths_dropped: u64,
    pub paths_restored: u64,
    pub tree_file_count: u64,
    pub tree_total_bytes: u64,
}

impl ExtractReport {
    /// Sort all lists to guarantee deterministic JSON output.
    pub fn sort_deterministic(&mut self) {
        self.accepted.sort_by(|a, b| a.path.cmp(&b.path));
        self.dropped.sort_by(|a, b| a.path.cmp(&b.path));
        self.restored.sort_by(|a, b| a.path.cmp(&b.path));
        self.flags
            .sort_by(|a, b| (&a.flag_type, &a.path).cmp(&(&b.flag_type, &b.path)));
    }
}

/// Helper to walk output directory and produce deterministic tree manifest and SHA-256 digest.
pub fn generate_tree_manifest(root: &Path) -> io::Result<(String, u64, u64)> {
    let root = crate::safe_fs::open_dir_path(root).map_err(io::Error::other)?;
    generate_tree_manifest_fd(&root).map_err(io::Error::other)
}

/// Manifest lines contain a JSON path string, mode and hash. Directories have
/// a zero hash, binding empty directories and disambiguating newlines in names.
pub fn generate_tree_manifest_fd(
    root: &OwnedFd,
) -> Result<(String, u64, u64), crate::error::ExtractError> {
    let entries = crate::safe_fs::copy_base_tree(root, None)?;
    let mut manifest = Sha256::new();
    let mut file_count = 0;
    let mut total_bytes = 0;
    for (path, entry) in entries {
        let mut hash = [0u8; 32];
        if !entry.is_dir {
            let file = crate::safe_fs::open_relative_regular(root, &path)?;
            let mut file = file.take(entry.size + 1);
            let mut digest = Sha256::new();
            let mut buf = [0u8; crate::format::CHUNK_SIZE];
            let mut bytes = 0u64;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                digest.update(&buf[..n]);
                bytes += n as u64;
            }
            if bytes != entry.size {
                return Err(crate::error::QuotaError::ResourceLimit("changed tree file").into());
            }
            hash = digest.finalize().into();
            file_count += 1;
            total_bytes += bytes;
        }
        let quoted_path = serde_json::to_string(&path).map_err(io::Error::other)?;
        manifest
            .update(format!("{quoted_path} {:04o} {}\n", entry.mode, format_hex(&hash)).as_bytes());
    }
    let hash: [u8; 32] = manifest.finalize().into();
    Ok((format_hex(&hash), file_count, total_bytes))
}
