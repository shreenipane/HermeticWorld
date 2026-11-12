#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
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
    let mut file_entries = Vec::new();
    walk_regular_files(root, "", &mut file_entries)?;

    // Sort by relative path
    file_entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let mut manifest_bytes = Vec::new();
    let mut total_bytes = 0u64;

    for entry in &file_entries {
        let line = format!("{} {:04o} {}\n", entry.rel_path, entry.mode, entry.sha256);
        manifest_bytes.extend_from_slice(line.as_bytes());
        total_bytes += entry.size;
    }

    let mut hasher = Sha256::new();
    hasher.update(&manifest_bytes);
    let digest: [u8; 32] = hasher.finalize().into();

    Ok((format_hex(&digest), file_entries.len() as u64, total_bytes))
}

struct ManifestEntry {
    rel_path: String,
    mode: u32,
    size: u64,
    sha256: String,
}

fn walk_regular_files(root: &Path, rel_dir: &str, out: &mut Vec<ManifestEntry>) -> io::Result<()> {
    let current = if rel_dir.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_dir)
    };

    let entries = std::fs::read_dir(&current)?;
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let name_str = name
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 file name in output tree"))?;

        let rel_path = if rel_dir.is_empty() {
            name_str.to_string()
        } else {
            format!("{rel_dir}/{name_str}")
        };

        if file_type.is_symlink() {
            return Err(io::Error::other(format!(
                "forbidden symlink in output tree: {rel_path}"
            )));
        }

        if file_type.is_dir() {
            walk_regular_files(root, &rel_path, out)?;
        } else if file_type.is_file() {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            let mode = meta.mode() & 0o777;
            let size = meta.len();

            let mut file = File::open(&path)?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let hash: [u8; 32] = hasher.finalize().into();

            out.push(ManifestEntry {
                rel_path,
                mode,
                size,
                sha256: format_hex(&hash),
            });
        } else {
            return Err(io::Error::other(format!(
                "forbidden special entry in output tree: {rel_path}"
            )));
        }
    }

    Ok(())
}
