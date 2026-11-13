use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

/// Chunk size used when streaming regular files into SHA-256.
pub const HASH_CHUNK_SIZE: usize = 64 * 1024;

/// Default maximum number of filesystem entries inspected in a single `diff_trees` call.
pub const DEFAULT_MAX_ENTRIES_WALKED: usize = 100_000;

/// Default maximum directory nesting depth relative to the tree root.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Default maximum byte size allowed for a single regular file.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Default maximum cumulative bytes hashed across all files in a single `diff_trees` call.
pub const DEFAULT_MAX_TOTAL_BYTES_HASHED: u64 = 512 * 1024 * 1024;

/// Default maximum UTF-8 byte length of any relative output path.
pub const DEFAULT_MAX_PATH_LENGTH: usize = 4096;

/// Hard upper bound on path components in any `TaskClass` scope path.
pub const MAX_PATH_COMPONENTS: usize = 512;

/// Hard upper bound on raw `read_dir` iterations per directory scan.
pub const MAX_RAW_DIR_ITERATIONS: usize = 1_000_000;

/// Hard upper bound on scope paths accepted in `TaskClass::Artifact`.
pub const MAX_ARTIFACT_PATHS: usize = 10_000;

/// Resource limits enforced during tree traversal and hashing.
///
/// Exceeding any limit causes [`diff_trees`] to fail closed with [`WalkError::CapExceeded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps {
    pub max_entries_walked: usize,
    pub max_depth: usize,
    pub max_file_size: u64,
    pub max_total_bytes_hashed: u64,
    pub max_path_length: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_entries_walked: DEFAULT_MAX_ENTRIES_WALKED,
            max_depth: DEFAULT_MAX_DEPTH,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_total_bytes_hashed: DEFAULT_MAX_TOTAL_BYTES_HASHED,
            max_path_length: DEFAULT_MAX_PATH_LENGTH,
        }
    }
}

/// Identifies which resource cap in [`Caps`] was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapKind {
    MaxEntriesWalked,
    MaxDepth,
    MaxFileSize,
    MaxTotalBytesHashed,
    MaxPathLength,
}

impl CapKind {
    /// Returns the canonical snake_case name of this cap.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxEntriesWalked => "max_entries_walked",
            Self::MaxDepth => "max_depth",
            Self::MaxFileSize => "max_file_size",
            Self::MaxTotalBytesHashed => "max_total_bytes_hashed",
            Self::MaxPathLength => "max_path_length",
        }
    }
}

impl fmt::Display for CapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extraction scope selecting which parts of `work` are compared against `base`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    /// Extract changes only inside `repo_dir` (relative to `base` and `work`).
    Patch { repo_dir: PathBuf },
    /// Extract changes only for the declared relative `paths`.
    Artifact { paths: Vec<PathBuf> },
    /// Extract nothing and return an empty [`ChangeSet`].
    State,
}

/// Supported filesystem entry kinds included in [`ChangeSet::changes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
}

/// Classification of a detected change between `base` and `work`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    TypeChanged,
}

/// A single extracted difference between `base` and `work`.
///
/// Fields are declared in alphabetical order so compact `serde_json` output has sorted keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub change: ChangeKind,
    pub kind: EntryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Reason an entry in `work` was refused rather than read or followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusedKind {
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    HardLink,
    NonUtf8Path,
    Other,
}

/// An entry in `work` that was refused without reading or following it.
///
/// Fields are declared in alphabetical order so compact `serde_json` output has sorted keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RefusedEntry {
    pub kind: RefusedKind,
    pub path: String,
}

/// Deterministic extraction output containing sorted changes and refused entries.
///
/// Fields are declared in alphabetical order so compact `serde_json` output has sorted keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub changes: Vec<Change>,
    pub refused: Vec<RefusedEntry>,
}

impl ChangeSet {
    /// Serializes this [`ChangeSet`] as compact canonical JSON with lexicographically sorted keys.
    pub fn to_canonical_json(&self) -> Result<String, WalkError> {
        serde_json::to_string(self).map_err(|e| WalkError::Serialization(e.to_string()))
    }
}

/// Identifies whether a root validation error occurred on `base` or `work`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSide {
    Base,
    Work,
}

impl fmt::Display for RootSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base => f.write_str("base"),
            Self::Work => f.write_str("work"),
        }
    }
}

/// Typed error returned when [`diff_trees`] fails closed.
///
/// Error messages never include absolute host paths, hostnames, or host timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    CapExceeded {
        cap: CapKind,
        limit: u64,
        observed: u64,
    },
    InvalidRoot {
        side: RootSide,
        reason: String,
    },
    InvalidScopePath {
        reason: String,
    },
    TooManyScopePaths {
        limit: usize,
        observed: usize,
    },
    MetadataMismatch {
        path: String,
    },
    Io {
        path: String,
        kind: String,
    },
    CounterOverflow {
        counter: &'static str,
    },
    Serialization(String),
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExceeded {
                cap,
                limit,
                observed,
            } => write!(
                f,
                "cap exceeded ({cap}): observed {observed} exceeds limit {limit}"
            ),
            Self::InvalidRoot { side, reason } => {
                write!(f, "invalid {side} root directory: {reason}")
            }
            Self::InvalidScopePath { reason } => {
                write!(f, "invalid task scope path: {reason}")
            }
            Self::TooManyScopePaths { limit, observed } => write!(
                f,
                "too many artifact scope paths: observed {observed} exceeds limit {limit}"
            ),
            Self::MetadataMismatch { path } => {
                write!(f, "file metadata changed during open/read at '{path}'")
            }
            Self::Io { path, kind } => {
                write!(f, "I/O error ({kind}) at '{path}'")
            }
            Self::CounterOverflow { counter } => {
                write!(f, "arithmetic overflow on counter '{counter}'")
            }
            Self::Serialization(msg) => {
                write!(f, "JSON serialization error: {msg}")
            }
        }
    }
}

impl std::error::Error for WalkError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeSide {
    Base,
    Work,
}

struct FileInfo {
    mode: &'static str,
    size: u64,
    meta: Metadata,
}

enum EntryProbe {
    Absent,
    File(FileInfo),
    Dir,
    Refused(RefusedKind),
}

struct WalkState<'a> {
    cfg: &'a Caps,
    entries_walked: usize,
    total_bytes_hashed: u64,
    changes: Vec<Change>,
    refused: BTreeSet<RefusedEntry>,
}

impl<'a> WalkState<'a> {
    fn new(cfg: &'a Caps) -> Self {
        Self {
            cfg,
            entries_walked: 0,
            total_bytes_hashed: 0,
            changes: Vec::new(),
            refused: BTreeSet::new(),
        }
    }

    fn record_entry(&mut self) -> Result<(), WalkError> {
        self.entries_walked =
            self.entries_walked
                .checked_add(1)
                .ok_or(WalkError::CounterOverflow {
                    counter: "entries_walked",
                })?;
        if self.entries_walked > self.cfg.max_entries_walked {
            return Err(WalkError::CapExceeded {
                cap: CapKind::MaxEntriesWalked,
                limit: self.cfg.max_entries_walked as u64,
                observed: self.entries_walked as u64,
            });
        }
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), WalkError> {
        if depth > self.cfg.max_depth {
            return Err(WalkError::CapExceeded {
                cap: CapKind::MaxDepth,
                limit: self.cfg.max_depth as u64,
                observed: depth as u64,
            });
        }
        Ok(())
    }

    fn check_path_len(&self, rel_path: &str) -> Result<(), WalkError> {
        if rel_path.len() > self.cfg.max_path_length {
            return Err(WalkError::CapExceeded {
                cap: CapKind::MaxPathLength,
                limit: self.cfg.max_path_length as u64,
                observed: rel_path.len() as u64,
            });
        }
        Ok(())
    }

    fn check_file_size(&self, size: u64) -> Result<(), WalkError> {
        if size > self.cfg.max_file_size {
            return Err(WalkError::CapExceeded {
                cap: CapKind::MaxFileSize,
                limit: self.cfg.max_file_size,
                observed: size,
            });
        }
        Ok(())
    }

    fn add_hashed_bytes(&mut self, n: u64) -> Result<(), WalkError> {
        self.total_bytes_hashed =
            self.total_bytes_hashed
                .checked_add(n)
                .ok_or(WalkError::CounterOverflow {
                    counter: "total_bytes_hashed",
                })?;
        if self.total_bytes_hashed > self.cfg.max_total_bytes_hashed {
            return Err(WalkError::CapExceeded {
                cap: CapKind::MaxTotalBytesHashed,
                limit: self.cfg.max_total_bytes_hashed,
                observed: self.total_bytes_hashed,
            });
        }
        Ok(())
    }
}

/// Compares `work` against `base` according to `class` while enforcing [`Caps`].
///
/// # `.git` Handling
/// Any entry named `.git` (whether directory, regular file, symlink, or special node) at any
/// depth in either `base` or `work` is completely ignored: it is never descended into, never
/// opened or hashed, and never reported in [`ChangeSet`].
///
/// # Symlink and Hard-Link Policy
/// Symlinks, block/char devices, FIFOs, sockets, and hard-linked regular files (`st_nlink > 1`)
/// in `work` are never followed or read; they are recorded in [`ChangeSet::refused`] while
/// extraction continues for all valid entries.
pub fn diff_trees(
    base: &Path,
    work: &Path,
    class: TaskClass,
    cfg: &Caps,
) -> Result<ChangeSet, WalkError> {
    if matches!(class, TaskClass::State) {
        return Ok(ChangeSet::default());
    }

    validate_root_dir(base, RootSide::Base)?;
    validate_root_dir(work, RootSide::Work)?;

    let mut state = WalkState::new(cfg);

    match class {
        TaskClass::State => return Ok(ChangeSet::default()),
        TaskClass::Patch { repo_dir } => {
            if let Some(components) = normalize_scope_path(&repo_dir)? {
                diff_scoped_target(base, work, &components, &mut state)?;
            }
        }
        TaskClass::Artifact { paths } => {
            if paths.len() > MAX_ARTIFACT_PATHS {
                return Err(WalkError::TooManyScopePaths {
                    limit: MAX_ARTIFACT_PATHS,
                    observed: paths.len(),
                });
            }

            let mut normalized_targets: Vec<Vec<String>> = Vec::new();
            let mut bounded_iter = paths.iter().take(MAX_ARTIFACT_PATHS);
            for raw_path in &mut bounded_iter {
                if let Some(components) = normalize_scope_path(raw_path)? {
                    normalized_targets.push(components);
                }
            }

            normalized_targets.sort();
            normalized_targets.dedup();

            let mut filtered_targets: Vec<Vec<String>> = Vec::new();
            for candidate in normalized_targets {
                let covered_by_ancestor = filtered_targets
                    .iter()
                    .any(|existing| is_component_prefix(existing, &candidate));
                if !covered_by_ancestor {
                    filtered_targets.push(candidate);
                }
            }

            for components in &filtered_targets {
                diff_scoped_target(base, work, components, &mut state)?;
            }
        }
    }

    state
        .changes
        .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    Ok(ChangeSet {
        changes: state.changes,
        refused: state.refused.into_iter().collect(),
    })
}

fn validate_root_dir(root: &Path, side: RootSide) -> Result<(), WalkError> {
    let meta = fs::symlink_metadata(root).map_err(|e| WalkError::InvalidRoot {
        side,
        reason: e.kind().to_string(),
    })?;
    let ft = meta.file_type();
    if ft.is_symlink() || !ft.is_dir() {
        return Err(WalkError::InvalidRoot {
            side,
            reason: "root path must be a real directory, not a symlink or file".to_string(),
        });
    }
    Ok(())
}

fn is_component_prefix(prefix: &[String], full: &[String]) -> bool {
    if prefix.len() > full.len() {
        return false;
    }
    prefix
        .iter()
        .zip(full.iter())
        .all(|(a, b)| a.as_bytes() == b.as_bytes())
}

/// Validates and normalizes a relative scope path into clean path components.
///
/// Returns `Ok(None)` if any component is `.git` (so it is silently ignored).
fn normalize_scope_path(path: &Path) -> Result<Option<Vec<String>>, WalkError> {
    let mut components: Vec<String> = Vec::new();
    let mut count: usize = 0;

    for comp in path.components() {
        count = count.checked_add(1).ok_or(WalkError::CounterOverflow {
            counter: "scope_path_components",
        })?;
        if count > MAX_PATH_COMPONENTS {
            return Err(WalkError::InvalidScopePath {
                reason: "scope path exceeds maximum component count".to_string(),
            });
        }

        match comp {
            Component::CurDir => {}
            Component::Normal(os_str) => {
                let s = os_str.to_str().ok_or_else(|| WalkError::InvalidScopePath {
                    reason: "scope path must be valid UTF-8".to_string(),
                })?;
                if s.contains('/') || s.contains('\0') {
                    return Err(WalkError::InvalidScopePath {
                        reason: "scope path component contains invalid separator".to_string(),
                    });
                }
                if s == ".git" {
                    return Ok(None);
                }
                components.push(s.to_string());
            }
            Component::ParentDir => {
                return Err(WalkError::InvalidScopePath {
                    reason: "parent traversal ('..') is forbidden in scope paths".to_string(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(WalkError::InvalidScopePath {
                    reason: "absolute paths are forbidden in scope paths".to_string(),
                });
            }
        }
    }

    Ok(Some(components))
}

/// Traverses component-by-component to `components` without following symlinks on intermediate
/// segments, then compares the target subtree or leaf.
fn diff_scoped_target(
    base_root: &Path,
    work_root: &Path,
    components: &[String],
    state: &mut WalkState<'_>,
) -> Result<(), WalkError> {
    if components.is_empty() {
        return walk_dir_children(Some(base_root), Some(work_root), "", 1, state);
    }

    let full_rel = components.join("/");
    state.check_path_len(&full_rel)?;
    state.check_depth(components.len())?;

    let mut cur_base = base_root.to_path_buf();
    let mut cur_work = work_root.to_path_buf();
    let mut base_alive = true;
    let mut work_alive = true;
    let mut rel_so_far = String::new();

    let last_idx = components.len().saturating_sub(1);
    let mut idx: usize = 0;
    while idx < last_idx && idx < MAX_PATH_COMPONENTS {
        let Some(part) = components.get(idx) else {
            break;
        };
        if !rel_so_far.is_empty() {
            rel_so_far.push('/');
        }
        rel_so_far.push_str(part);

        let depth = idx.saturating_add(1);
        state.check_depth(depth)?;
        state.check_path_len(&rel_so_far)?;

        if work_alive {
            cur_work.push(part);
            state.record_entry()?;
            match probe_entry(&cur_work, &rel_so_far, TreeSide::Work, state.cfg)? {
                EntryProbe::Dir => {}
                EntryProbe::Refused(rkind) => {
                    state.refused.insert(RefusedEntry {
                        kind: rkind,
                        path: rel_so_far.clone(),
                    });
                    work_alive = false;
                }
                EntryProbe::Absent | EntryProbe::File(_) => {
                    work_alive = false;
                }
            }
        }

        if base_alive {
            cur_base.push(part);
            state.record_entry()?;
            match probe_entry(&cur_base, &rel_so_far, TreeSide::Base, state.cfg)? {
                EntryProbe::Dir => {}
                EntryProbe::Absent | EntryProbe::File(_) | EntryProbe::Refused(_) => {
                    base_alive = false;
                }
            }
        }

        if !base_alive && !work_alive {
            return Ok(());
        }

        idx = idx.saturating_add(1);
    }

    let Some(target_name) = components.get(last_idx) else {
        return Ok(());
    };
    let base_target = if base_alive {
        Some(cur_base.join(target_name))
    } else {
        None
    };
    let work_target = if work_alive {
        Some(cur_work.join(target_name))
    } else {
        None
    };

    compare_node(
        base_target.as_deref(),
        work_target.as_deref(),
        &full_rel,
        components.len(),
        state,
    )
}

fn compare_node(
    base_path: Option<&Path>,
    work_path: Option<&Path>,
    rel_path: &str,
    depth: usize,
    state: &mut WalkState<'_>,
) -> Result<(), WalkError> {
    state.check_depth(depth)?;
    state.check_path_len(rel_path)?;

    let base_probe = match base_path {
        Some(p) => {
            state.record_entry()?;
            probe_entry(p, rel_path, TreeSide::Base, state.cfg)?
        }
        None => EntryProbe::Absent,
    };

    let work_probe = match work_path {
        Some(p) => {
            state.record_entry()?;
            probe_entry(p, rel_path, TreeSide::Work, state.cfg)?
        }
        None => EntryProbe::Absent,
    };

    match (base_probe, work_probe) {
        (_, EntryProbe::Refused(rkind)) => {
            state.refused.insert(RefusedEntry {
                kind: rkind,
                path: rel_path.to_string(),
            });
        }
        (
            EntryProbe::Absent | EntryProbe::Refused(_),
            EntryProbe::Absent | EntryProbe::Refused(_),
        ) => {}
        (EntryProbe::Absent | EntryProbe::Refused(_), EntryProbe::File(w_info)) => {
            let Some(wp) = work_path else {
                return Ok(());
            };
            let sha256 = hash_regular_file(wp, rel_path, &w_info.meta, state)?;
            state.changes.push(Change {
                change: ChangeKind::Added,
                kind: EntryKind::File,
                mode: Some(w_info.mode.to_string()),
                path: rel_path.to_string(),
                sha256: Some(sha256),
                size: Some(w_info.size),
            });
        }
        (EntryProbe::Absent | EntryProbe::Refused(_), EntryProbe::Dir) => {
            state.changes.push(Change {
                change: ChangeKind::Added,
                kind: EntryKind::Dir,
                mode: None,
                path: rel_path.to_string(),
                sha256: None,
                size: None,
            });
            let next_depth = depth
                .checked_add(1)
                .ok_or(WalkError::CounterOverflow { counter: "depth" })?;
            walk_dir_children(None, work_path, rel_path, next_depth, state)?;
        }
        (EntryProbe::File(_), EntryProbe::Absent) => {
            state.changes.push(Change {
                change: ChangeKind::Deleted,
                kind: EntryKind::File,
                mode: None,
                path: rel_path.to_string(),
                sha256: None,
                size: None,
            });
        }
        (EntryProbe::Dir, EntryProbe::Absent) => {
            state.changes.push(Change {
                change: ChangeKind::Deleted,
                kind: EntryKind::Dir,
                mode: None,
                path: rel_path.to_string(),
                sha256: None,
                size: None,
            });
            let next_depth = depth
                .checked_add(1)
                .ok_or(WalkError::CounterOverflow { counter: "depth" })?;
            walk_dir_children(base_path, None, rel_path, next_depth, state)?;
        }
        (EntryProbe::File(b_info), EntryProbe::File(w_info)) => {
            let (Some(bp), Some(wp)) = (base_path, work_path) else {
                return Ok(());
            };
            state.check_file_size(b_info.size)?;
            let w_sha = hash_regular_file(wp, rel_path, &w_info.meta, state)?;
            let changed = if b_info.size != w_info.size || b_info.mode != w_info.mode {
                true
            } else {
                let b_sha = hash_regular_file(bp, rel_path, &b_info.meta, state)?;
                b_sha != w_sha
            };
            if changed {
                state.changes.push(Change {
                    change: ChangeKind::Modified,
                    kind: EntryKind::File,
                    mode: Some(w_info.mode.to_string()),
                    path: rel_path.to_string(),
                    sha256: Some(w_sha),
                    size: Some(w_info.size),
                });
            }
        }
        (EntryProbe::Dir, EntryProbe::Dir) => {
            let next_depth = depth
                .checked_add(1)
                .ok_or(WalkError::CounterOverflow { counter: "depth" })?;
            walk_dir_children(base_path, work_path, rel_path, next_depth, state)?;
        }
        (EntryProbe::File(_), EntryProbe::Dir) => {
            state.changes.push(Change {
                change: ChangeKind::TypeChanged,
                kind: EntryKind::Dir,
                mode: None,
                path: rel_path.to_string(),
                sha256: None,
                size: None,
            });
            let next_depth = depth
                .checked_add(1)
                .ok_or(WalkError::CounterOverflow { counter: "depth" })?;
            walk_dir_children(None, work_path, rel_path, next_depth, state)?;
        }
        (EntryProbe::Dir, EntryProbe::File(w_info)) => {
            let Some(wp) = work_path else {
                return Ok(());
            };
            let w_sha = hash_regular_file(wp, rel_path, &w_info.meta, state)?;
            state.changes.push(Change {
                change: ChangeKind::TypeChanged,
                kind: EntryKind::File,
                mode: Some(w_info.mode.to_string()),
                path: rel_path.to_string(),
                sha256: Some(w_sha),
                size: Some(w_info.size),
            });
        }
    }

    Ok(())
}

fn walk_dir_children(
    base_dir: Option<&Path>,
    work_dir: Option<&Path>,
    rel_prefix: &str,
    child_depth: usize,
    state: &mut WalkState<'_>,
) -> Result<(), WalkError> {
    let mut children: BTreeMap<String, (bool, bool)> = BTreeMap::new();

    if let Some(b_dir) = base_dir {
        collect_dir_entries(
            b_dir,
            rel_prefix,
            child_depth,
            TreeSide::Base,
            state,
            &mut children,
        )?;
    }

    if let Some(w_dir) = work_dir {
        collect_dir_entries(
            w_dir,
            rel_prefix,
            child_depth,
            TreeSide::Work,
            state,
            &mut children,
        )?;
    }

    for (name, (in_base, in_work)) in children {
        let child_rel = join_rel_path(rel_prefix, &name);
        let child_base = if in_base {
            base_dir.map(|d| d.join(&name))
        } else {
            None
        };
        let child_work = if in_work {
            work_dir.map(|d| d.join(&name))
        } else {
            None
        };
        compare_node(
            child_base.as_deref(),
            child_work.as_deref(),
            &child_rel,
            child_depth,
            state,
        )?;
    }

    Ok(())
}

fn collect_dir_entries(
    dir_path: &Path,
    rel_prefix: &str,
    child_depth: usize,
    side: TreeSide,
    state: &mut WalkState<'_>,
    children: &mut BTreeMap<String, (bool, bool)>,
) -> Result<(), WalkError> {
    let read_dir = fs::read_dir(dir_path).map_err(|e| WalkError::Io {
        path: rel_prefix.to_string(),
        kind: e.kind().to_string(),
    })?;

    let mut raw_iters: usize = 0;
    for entry_res in read_dir {
        raw_iters = raw_iters.checked_add(1).ok_or(WalkError::CounterOverflow {
            counter: "raw_dir_iterations",
        })?;
        if raw_iters > MAX_RAW_DIR_ITERATIONS {
            return Err(WalkError::CapExceeded {
                cap: CapKind::MaxEntriesWalked,
                limit: state.cfg.max_entries_walked as u64,
                observed: raw_iters as u64,
            });
        }

        let entry = entry_res.map_err(|e| WalkError::Io {
            path: rel_prefix.to_string(),
            kind: e.kind().to_string(),
        })?;

        let raw_name = entry.file_name();
        if raw_name == OsStr::new(".git") {
            // Never descend into, read, or report any `.git` file or directory at any depth.
            continue;
        }

        state.check_depth(child_depth)?;

        match raw_name.to_str() {
            Some(name_str) => {
                let entry_flags = children
                    .entry(name_str.to_string())
                    .or_insert((false, false));
                match side {
                    TreeSide::Base => entry_flags.0 = true,
                    TreeSide::Work => entry_flags.1 = true,
                }
            }
            None => {
                if side == TreeSide::Work {
                    state.record_entry()?;
                    let escaped = format_non_utf8_rel_path(rel_prefix, &raw_name);
                    state.check_path_len(&escaped)?;
                    state.refused.insert(RefusedEntry {
                        kind: RefusedKind::NonUtf8Path,
                        path: escaped,
                    });
                }
            }
        }
    }

    Ok(())
}

fn join_rel_path(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        let mut out =
            String::with_capacity(prefix.len().saturating_add(1).saturating_add(name.len()));
        out.push_str(prefix);
        out.push('/');
        out.push_str(name);
        out
    }
}

/// Formats a path whose leaf name is not valid UTF-8 into an unambiguous, lossless UTF-8 string
/// without using lossy U+FFFD replacement characters.
fn format_non_utf8_rel_path(prefix: &str, raw_name: &OsStr) -> String {
    let hex_name = encode_os_str_hex(raw_name);
    let tag = format!("<non-utf8:{hex_name}>");
    join_rel_path(prefix, &tag)
}

#[cfg(unix)]
fn encode_os_str_hex(s: &OsStr) -> String {
    encode_hex_lower(s.as_bytes())
}

#[cfg(not(unix))]
fn encode_os_str_hex(s: &OsStr) -> String {
    let dbg = format!("{s:?}");
    encode_hex_lower(dbg.as_bytes())
}

fn probe_entry(
    path: &Path,
    rel_path: &str,
    side: TreeSide,
    cfg: &Caps,
) -> Result<EntryProbe, WalkError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(EntryProbe::Absent),
        Err(e) => {
            return Err(WalkError::Io {
                path: rel_path.to_string(),
                kind: e.kind().to_string(),
            });
        }
    };

    let ft = meta.file_type();
    if ft.is_symlink() {
        return Ok(EntryProbe::Refused(RefusedKind::Symlink));
    }

    #[cfg(unix)]
    {
        if ft.is_fifo() {
            return Ok(EntryProbe::Refused(RefusedKind::Fifo));
        }
        if ft.is_socket() {
            return Ok(EntryProbe::Refused(RefusedKind::Socket));
        }
        if ft.is_block_device() {
            return Ok(EntryProbe::Refused(RefusedKind::BlockDevice));
        }
        if ft.is_char_device() {
            return Ok(EntryProbe::Refused(RefusedKind::CharDevice));
        }
    }

    if ft.is_dir() {
        return Ok(EntryProbe::Dir);
    }

    if !ft.is_file() {
        return Ok(EntryProbe::Refused(RefusedKind::Other));
    }

    #[cfg(unix)]
    if side == TreeSide::Work && meta.nlink() > 1 {
        return Ok(EntryProbe::Refused(RefusedKind::HardLink));
    }
    #[cfg(not(unix))]
    let _ = side;

    let size = meta.len();
    if size > cfg.max_file_size {
        return Err(WalkError::CapExceeded {
            cap: CapKind::MaxFileSize,
            limit: cfg.max_file_size,
            observed: size,
        });
    }

    let mode = file_mode_str(&meta);
    Ok(EntryProbe::File(FileInfo { mode, size, meta }))
}

#[cfg(unix)]
fn file_mode_str(meta: &Metadata) -> &'static str {
    if meta.permissions().mode() & 0o111 != 0 {
        "0755"
    } else {
        "0644"
    }
}

#[cfg(not(unix))]
fn file_mode_str(_meta: &Metadata) -> &'static str {
    "0644"
}

fn hash_regular_file(
    path: &Path,
    rel_path: &str,
    expected_lstat: &Metadata,
    state: &mut WalkState<'_>,
) -> Result<String, WalkError> {
    state.check_file_size(expected_lstat.len())?;

    let mut file = File::open(path).map_err(|e| WalkError::Io {
        path: rel_path.to_string(),
        kind: e.kind().to_string(),
    })?;

    let opened_meta = file.metadata().map_err(|e| WalkError::Io {
        path: rel_path.to_string(),
        kind: e.kind().to_string(),
    })?;

    if !opened_meta.file_type().is_file() {
        return Err(WalkError::MetadataMismatch {
            path: rel_path.to_string(),
        });
    }

    #[cfg(unix)]
    {
        if opened_meta.dev() != expected_lstat.dev()
            || opened_meta.ino() != expected_lstat.ino()
            || opened_meta.nlink() != expected_lstat.nlink()
        {
            return Err(WalkError::MetadataMismatch {
                path: rel_path.to_string(),
            });
        }
    }

    state.check_file_size(opened_meta.len())?;

    let max_chunks = (state.cfg.max_file_size / (HASH_CHUNK_SIZE as u64)).saturating_add(2);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_CHUNK_SIZE];
    let mut file_bytes: u64 = 0;
    let mut chunks_read: u64 = 0;
    let mut reached_eof = false;

    while chunks_read < max_chunks {
        chunks_read = chunks_read.saturating_add(1);
        let n = file.read(&mut buf).map_err(|e| WalkError::Io {
            path: rel_path.to_string(),
            kind: e.kind().to_string(),
        })?;
        if n == 0 {
            reached_eof = true;
            break;
        }

        let n_u64 = n as u64;
        file_bytes = file_bytes
            .checked_add(n_u64)
            .ok_or(WalkError::CounterOverflow {
                counter: "file_bytes",
            })?;
        state.check_file_size(file_bytes)?;
        state.add_hashed_bytes(n_u64)?;

        let slice = buf.get(..n).ok_or(WalkError::CounterOverflow {
            counter: "chunk_slice",
        })?;
        hasher.update(slice);
    }

    if !reached_eof || file_bytes != opened_meta.len() {
        return Err(WalkError::MetadataMismatch {
            path: rel_path.to_string(),
        });
    }

    let digest = hasher.finalize();
    Ok(encode_hex_lower(digest.as_slice()))
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = HEX.get((b >> 4) as usize).copied().unwrap_or(b'0');
        let lo = HEX.get((b & 0x0f) as usize).copied().unwrap_or(b'0');
        out.push(hi as char);
        out.push(lo as char);
    }
    out
}
