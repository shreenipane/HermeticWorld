#![forbid(unsafe_code)]

pub mod stream;
pub mod walk;

use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use stream::{decode, decode_with_caps, DecodeError, Record, STREAM_MAGIC, STREAM_VERSION};

/// Bounded chunk size used for all file reads, stream writes, and SHA-256 updates.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// Hard upper ceiling on total entries processed or decoded.
pub const HARD_MAX_ENTRIES: usize = 1_000_000;
/// Hard upper ceiling on directory/path depth.
pub const HARD_MAX_DEPTH: usize = 256;
/// Hard upper ceiling on relative UTF-8 path byte length (must fit in `u16`).
pub const HARD_MAX_PATH_LEN: usize = 4096;
/// Hard upper ceiling on a single file's byte length.
pub const HARD_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Hard upper ceiling on cumulative emitted file bytes across a stream.
pub const HARD_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Default maximum entries per extraction.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
/// Default maximum relative path depth (number of `/` components).
pub const DEFAULT_MAX_DEPTH: usize = 64;
/// Default maximum relative path length in UTF-8 bytes.
pub const DEFAULT_MAX_PATH_LEN: usize = 4096;
/// Default maximum byte size per individual file.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum total file payload bytes across the entire extraction.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum number of comma-separated paths permitted in `artifact:` task classes.
pub const MAX_DECLARED_PATHS: usize = 4096;
/// Maximum retries on `io::ErrorKind::Interrupted`.
pub const MAX_EINTR_RETRIES: usize = 1024;

/// Identifies one of the five resource caps enforced during extraction and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapName {
    Entries,
    Depth,
    PathLength,
    PerFileBytes,
    TotalBytes,
}

impl CapName {
    pub const fn as_str(self) -> &'static str {
        match self {
            CapName::Entries => "entries",
            CapName::Depth => "depth",
            CapName::PathLength => "path_length",
            CapName::PerFileBytes => "per_file_bytes",
            CapName::TotalBytes => "total_bytes",
        }
    }
}

impl fmt::Display for CapName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resource bounds enforced on traversal, file reads, stream emission, and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_path_len: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_path_len: DEFAULT_MAX_PATH_LEN,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

impl Caps {
    /// Validates that configured caps do not exceed compile-time hard ceilings.
    pub fn validate(&self) -> Result<(), ExtractError> {
        if self.max_entries > HARD_MAX_ENTRIES {
            return Err(ExtractError::InvalidCaps {
                cap: CapName::Entries,
                reason: "exceeds compile-time hard ceiling",
            });
        }
        if self.max_depth > HARD_MAX_DEPTH {
            return Err(ExtractError::InvalidCaps {
                cap: CapName::Depth,
                reason: "exceeds compile-time hard ceiling",
            });
        }
        if self.max_path_len > HARD_MAX_PATH_LEN || self.max_path_len > u16::MAX as usize {
            return Err(ExtractError::InvalidCaps {
                cap: CapName::PathLength,
                reason: "exceeds compile-time hard ceiling or u16::MAX",
            });
        }
        if self.max_file_bytes > HARD_MAX_FILE_BYTES {
            return Err(ExtractError::InvalidCaps {
                cap: CapName::PerFileBytes,
                reason: "exceeds compile-time hard ceiling",
            });
        }
        if self.max_total_bytes > HARD_MAX_TOTAL_BYTES {
            return Err(ExtractError::InvalidCaps {
                cap: CapName::TotalBytes,
                reason: "exceeds compile-time hard ceiling",
            });
        }
        Ok(())
    }
}

/// Benchmark task class determining which part of the work tree is extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskClass {
    /// Extract changes within a repository directory (`""` denotes the tree root).
    Patch { repo_dir: String },
    /// Extract changes only for explicitly declared relative paths.
    Artifact { paths: Vec<String> },
    /// Extract nothing (produces a valid header + empty end record).
    State,
}

/// Parses a CLI `--class` specification (`patch:REPO`, `patch:` for the tree root,
/// `artifact:P1,P2`, or `state`).
pub fn parse_task_class(spec: &str) -> Result<TaskClass, ExtractError> {
    if spec == "state" {
        return Ok(TaskClass::State);
    }
    if let Some(repo) = spec.strip_prefix("patch:") {
        // The tree root is spelled as the empty string (`patch:`), matching the host
        // validator's `repo_dir: ""`. Any other spelling of the root is refused.
        if repo == "." || repo == "./" || repo == "/" {
            return Err(ExtractError::InvalidTaskClass {
                reason: "tree root must be spelled `patch:` (empty repo path), not '.' or '/'",
            });
        }
        if !repo.is_empty() {
            validate_relative_path(repo)?;
        }
        return Ok(TaskClass::Patch {
            repo_dir: repo.to_string(),
        });
    }
    if let Some(list) = spec.strip_prefix("artifact:") {
        if list.is_empty() {
            return Err(ExtractError::InvalidTaskClass {
                reason: "artifact path list must not be empty",
            });
        }
        let mut paths = Vec::new();
        for (idx, raw) in list.split(',').enumerate() {
            if idx >= MAX_DECLARED_PATHS {
                return Err(ExtractError::InvalidTaskClass {
                    reason: "too many declared artifact paths",
                });
            }
            if raw.is_empty() {
                return Err(ExtractError::InvalidTaskClass {
                    reason: "artifact path entry must not be empty",
                });
            }
            validate_relative_path(raw)?;
            paths.push(raw.to_string());
        }
        return Ok(TaskClass::Artifact { paths });
    }
    Err(ExtractError::InvalidTaskClass {
        reason: "expected patch:REPO, artifact:P1,P2, or state",
    })
}

/// Validates a normalized relative UTF-8 `/`-separated path without `.` or `..` components.
pub fn validate_relative_path(path: &str) -> Result<(), ExtractError> {
    if path.is_empty() {
        return Err(ExtractError::InvalidPath {
            path: String::new(),
            reason: "path must not be empty",
        });
    }
    if path.len() > HARD_MAX_PATH_LEN || path.len() > u16::MAX as usize {
        return Err(ExtractError::CapExceeded {
            cap: CapName::PathLength,
            limit: HARD_MAX_PATH_LEN as u64,
            actual: path.len() as u64,
        });
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(ExtractError::InvalidPath {
            path: path.to_string(),
            reason: "path must be relative without leading or trailing slash",
        });
    }
    if path.contains('\0') || path.contains('\\') {
        return Err(ExtractError::InvalidPath {
            path: path.to_string(),
            reason: "path contains forbidden character",
        });
    }
    let mut depth: usize = 0;
    for seg in path.split('/') {
        depth = depth.saturating_add(1);
        if depth > HARD_MAX_DEPTH {
            return Err(ExtractError::CapExceeded {
                cap: CapName::Depth,
                limit: HARD_MAX_DEPTH as u64,
                actual: depth as u64,
            });
        }
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(ExtractError::InvalidPath {
                path: path.to_string(),
                reason: "path contains empty, '.', or '..' segment",
            });
        }
    }
    Ok(())
}

/// Category of non-regular or hard-linked work-tree entry skipped during extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkippedKind {
    Symlink,
    Device,
    Fifo,
    Socket,
    Hardlink,
    Other,
}

/// Single skipped entry recorded in the deterministic JSON report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub path: String,
    pub kind: SkippedKind,
}

/// Separate JSON report listing skipped work-tree entries (relative paths only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractReport {
    pub skipped: Vec<SkippedEntry>,
}

/// Typed error enum for all extraction failures (contains no host paths or host metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    InvalidCaps {
        cap: CapName,
        reason: &'static str,
    },
    InvalidTaskClass {
        reason: &'static str,
    },
    InvalidPath {
        path: String,
        reason: &'static str,
    },
    InvalidUtf8Path,
    InvalidTreeRoot {
        which: &'static str,
    },
    MissingRepoDir {
        repo_dir: String,
    },
    CapExceeded {
        cap: CapName,
        limit: u64,
        actual: u64,
    },
    FileChangedDuringRead {
        path: String,
    },
    AllocationFailed {
        path: String,
    },
    RecordCountOverflow,
    Io {
        context: &'static str,
        path: Option<String>,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractError::InvalidCaps { cap, reason } => {
                write!(f, "invalid cap {}: {}", cap, reason)
            }
            ExtractError::InvalidTaskClass { reason } => {
                write!(f, "invalid task class: {}", reason)
            }
            ExtractError::InvalidPath { path, reason } => {
                write!(f, "invalid path '{}': {}", path, reason)
            }
            ExtractError::InvalidUtf8Path => {
                write!(f, "encountered non-UTF-8 path in tree")
            }
            ExtractError::InvalidTreeRoot { which } => {
                write!(
                    f,
                    "{} root does not exist or is not a real directory",
                    which
                )
            }
            ExtractError::MissingRepoDir { repo_dir } => {
                write!(
                    f,
                    "repository directory '{}' missing from both trees",
                    repo_dir
                )
            }
            ExtractError::CapExceeded { cap, limit, actual } => {
                write!(
                    f,
                    "cap exceeded: {} (limit {}, actual {})",
                    cap, limit, actual
                )
            }
            ExtractError::FileChangedDuringRead { path } => {
                write!(f, "file changed size or dev/ino while reading: '{}'", path)
            }
            ExtractError::AllocationFailed { path } => {
                write!(f, "bounded allocation failed while reading: '{}'", path)
            }
            ExtractError::RecordCountOverflow => {
                write!(f, "stream record count overflowed u64")
            }
            ExtractError::Io {
                context,
                path: Some(p),
                kind,
            } => write!(f, "I/O error during {} on '{}': {:?}", context, p, kind),
            ExtractError::Io {
                context,
                path: None,
                kind,
            } => write!(f, "I/O error during {}: {:?}", context, kind),
        }
    }
}

impl std::error::Error for ExtractError {}

/// Extracts deterministic changes between `base` and `work` into `writer`.
pub fn extract<W: Write>(
    base: &Path,
    work: &Path,
    task_class: &TaskClass,
    caps: &Caps,
    writer: W,
) -> Result<ExtractReport, ExtractError> {
    type NoHook = fn(&str) -> io::Result<()>;
    walk::run_extract::<W, NoHook>(base, work, task_class, caps, writer, None)
}

/// Extracts deterministic changes with an optional hook invoked between `stat` and `read`
/// for each candidate regular file in `work`.
pub fn extract_with_hook<W, F>(
    base: &Path,
    work: &Path,
    task_class: &TaskClass,
    caps: &Caps,
    writer: W,
    hook: Option<&mut F>,
) -> Result<ExtractReport, ExtractError>
where
    W: Write,
    F: FnMut(&str) -> io::Result<()>,
{
    walk::run_extract(base, work, task_class, caps, writer, hook)
}
