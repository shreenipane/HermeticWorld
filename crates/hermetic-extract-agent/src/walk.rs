use std::collections::BTreeSet;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use sha2::{Digest, Sha256};

use crate::stream::{StreamWriter, MODE_FILE_DEFAULT, MODE_FILE_EXEC};
use crate::{
    validate_relative_path, CapName, Caps, ExtractError, ExtractReport, SkippedEntry, SkippedKind,
    TaskClass, HARD_MAX_DEPTH, HARD_MAX_ENTRIES, MAX_CHUNK_BYTES, MAX_EINTR_RETRIES,
};

/// Upper bound on raw directory entries scanned in a single `read_dir` call.
const MAX_DIR_SCAN_ENTRIES: usize = HARD_MAX_ENTRIES.saturating_add(4096);

enum BaseNode {
    Absent,
    Dir,
    File(Metadata),
}

enum WorkNode {
    Absent,
    Skipped,
    Dir,
    File(Metadata),
}

enum ReadFileOutcome {
    Unchanged,
    Changed {
        mode: u32,
        sha256: [u8; 32],
        data: Vec<u8>,
    },
}

struct ExtractState<'a, W: Write, F> {
    base_root: &'a Path,
    work_root: &'a Path,
    caps: &'a Caps,
    writer: StreamWriter<W>,
    skipped: Vec<SkippedEntry>,
    entries_seen: usize,
    total_bytes: u64,
    emitted_dirs: BTreeSet<String>,
    hook: Option<&'a mut F>,
}

impl<'a, W, F> ExtractState<'a, W, F>
where
    W: Write,
    F: FnMut(&str) -> io::Result<()>,
{
    fn check_entry_budget(&mut self, rel_path: &str, depth: usize) -> Result<(), ExtractError> {
        if rel_path.len() > self.caps.max_path_len {
            return Err(ExtractError::CapExceeded {
                cap: CapName::PathLength,
                limit: self.caps.max_path_len as u64,
                actual: rel_path.len() as u64,
            });
        }
        if depth > self.caps.max_depth || depth > HARD_MAX_DEPTH {
            return Err(ExtractError::CapExceeded {
                cap: CapName::Depth,
                limit: self.caps.max_depth as u64,
                actual: depth as u64,
            });
        }
        let next_entries = self
            .entries_seen
            .checked_add(1)
            .ok_or(ExtractError::CapExceeded {
                cap: CapName::Entries,
                limit: self.caps.max_entries as u64,
                actual: u64::MAX,
            })?;
        if next_entries > self.caps.max_entries || next_entries > HARD_MAX_ENTRIES {
            return Err(ExtractError::CapExceeded {
                cap: CapName::Entries,
                limit: self.caps.max_entries as u64,
                actual: next_entries as u64,
            });
        }
        self.entries_seen = next_entries;
        Ok(())
    }

    fn ensure_missing_ancestors(&mut self, rel_path: &str) -> Result<(), ExtractError> {
        let mut current = String::new();
        let parts: Vec<&str> = rel_path.split('/').collect();
        if parts.len() <= 1 {
            return Ok(());
        }
        let ancestor_count = parts.len().saturating_sub(1);
        for (idx, seg) in parts.iter().take(ancestor_count).enumerate() {
            if idx > 0 {
                current.push('/');
            }
            current.push_str(seg);
            if self.emitted_dirs.contains(&current) {
                continue;
            }
            let base_fs = join_rel_path(self.base_root, &current);
            let work_fs = join_rel_path(self.work_root, &current);
            let base_node = inspect_base_node(&base_fs, &current)?;
            let work_node = inspect_work_node(&work_fs, &current, &mut self.skipped)?;
            if matches!(work_node, WorkNode::Dir) && !matches!(base_node, BaseNode::Dir) {
                let depth = idx.saturating_add(1);
                self.check_entry_budget(&current, depth)?;
                if matches!(base_node, BaseNode::File(_)) {
                    self.writer.write_delete(&current)?;
                }
                self.writer.write_dir(&current)?;
                self.emitted_dirs.insert(current.clone());
            }
        }
        Ok(())
    }

    fn diff_node(&mut self, rel_path: &str, depth: usize) -> Result<(), ExtractError> {
        self.check_entry_budget(rel_path, depth)?;

        let base_fs = join_rel_path(self.base_root, rel_path);
        let work_fs = join_rel_path(self.work_root, rel_path);

        let work_node = inspect_work_node(&work_fs, rel_path, &mut self.skipped)?;
        let base_node = inspect_base_node(&base_fs, rel_path)?;

        match (base_node, work_node) {
            (_, WorkNode::Skipped) => Ok(()),
            (BaseNode::Absent, WorkNode::Absent) => Ok(()),
            (BaseNode::Dir | BaseNode::File(_), WorkNode::Absent) => {
                self.writer.write_delete(rel_path)
            }
            (BaseNode::Absent, WorkNode::Dir) => {
                if !self.emitted_dirs.contains(rel_path) {
                    self.writer.write_dir(rel_path)?;
                    self.emitted_dirs.insert(rel_path.to_string());
                }
                self.walk_dir(rel_path, depth)
            }
            (BaseNode::File(_), WorkNode::Dir) => {
                self.writer.write_delete(rel_path)?;
                if !self.emitted_dirs.contains(rel_path) {
                    self.writer.write_dir(rel_path)?;
                    self.emitted_dirs.insert(rel_path.to_string());
                }
                self.walk_dir(rel_path, depth)
            }
            (BaseNode::Dir, WorkNode::Dir) => self.walk_dir(rel_path, depth),
            (BaseNode::Absent, WorkNode::File(work_meta)) => {
                self.emit_file_if_changed(&work_fs, None, rel_path, &work_meta)
            }
            (BaseNode::Dir, WorkNode::File(work_meta)) => {
                self.writer.write_delete(rel_path)?;
                self.emit_file_if_changed(&work_fs, None, rel_path, &work_meta)
            }
            (BaseNode::File(base_meta), WorkNode::File(work_meta)) => {
                let base_cmp = if base_meta.len() == work_meta.len()
                    && file_mode_from_meta(&base_meta) == file_mode_from_meta(&work_meta)
                {
                    Some((base_fs.as_path(), &base_meta))
                } else {
                    None
                };
                self.emit_file_if_changed(&work_fs, base_cmp, rel_path, &work_meta)
            }
        }
    }

    fn walk_dir(&mut self, rel_dir: &str, dir_depth: usize) -> Result<(), ExtractError> {
        let base_dir_fs = if rel_dir.is_empty() {
            self.base_root.to_path_buf()
        } else {
            join_rel_path(self.base_root, rel_dir)
        };
        let work_dir_fs = if rel_dir.is_empty() {
            self.work_root.to_path_buf()
        } else {
            join_rel_path(self.work_root, rel_dir)
        };

        let mut names = BTreeSet::new();
        collect_dir_names_if_real_dir(&base_dir_fs, rel_dir, &mut names)?;
        collect_dir_names_if_real_dir(&work_dir_fs, rel_dir, &mut names)?;

        let child_depth = dir_depth.saturating_add(1);
        for name in names {
            let child_rel = if rel_dir.is_empty() {
                name
            } else {
                let mut s = String::with_capacity(
                    rel_dir.len().saturating_add(1).saturating_add(name.len()),
                );
                s.push_str(rel_dir);
                s.push('/');
                s.push_str(&name);
                s
            };
            self.diff_node(&child_rel, child_depth)?;
        }
        Ok(())
    }

    fn emit_file_if_changed(
        &mut self,
        work_fs_path: &Path,
        base_cmp: Option<(&Path, &Metadata)>,
        rel_path: &str,
        work_meta: &Metadata,
    ) -> Result<(), ExtractError> {
        let hook_ref = self.hook.as_deref_mut();
        let outcome = read_work_file_once(
            work_fs_path,
            base_cmp,
            rel_path,
            work_meta,
            self.caps,
            self.total_bytes,
            hook_ref,
        )?;
        match outcome {
            ReadFileOutcome::Unchanged => Ok(()),
            ReadFileOutcome::Changed { mode, sha256, data } => {
                let next_total = self.total_bytes.checked_add(data.len() as u64).ok_or(
                    ExtractError::CapExceeded {
                        cap: CapName::TotalBytes,
                        limit: self.caps.max_total_bytes,
                        actual: u64::MAX,
                    },
                )?;
                if next_total > self.caps.max_total_bytes {
                    return Err(ExtractError::CapExceeded {
                        cap: CapName::TotalBytes,
                        limit: self.caps.max_total_bytes,
                        actual: next_total,
                    });
                }
                self.writer.write_file(rel_path, mode, sha256, &data)?;
                self.total_bytes = next_total;
                Ok(())
            }
        }
    }
}

pub(crate) fn run_extract<W, F>(
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
    caps.validate()?;
    verify_real_directory(base, "base")?;
    verify_real_directory(work, "work")?;

    let stream_writer = StreamWriter::new(writer)?;
    let mut state = ExtractState {
        base_root: base,
        work_root: work,
        caps,
        writer: stream_writer,
        skipped: Vec::new(),
        entries_seen: 0,
        total_bytes: 0,
        emitted_dirs: BTreeSet::new(),
        hook,
    };

    match task_class {
        TaskClass::State => {}
        TaskClass::Patch { repo_dir } => {
            if repo_dir == "." {
                state.walk_dir("", 0)?;
            } else {
                validate_relative_path(repo_dir)?;
                if path_has_dot_git(repo_dir) {
                    return Err(ExtractError::InvalidTaskClass {
                        reason: "patch repository path must not traverse .git",
                    });
                }
                let depth = repo_dir.split('/').count();
                let base_fs = join_rel_path(base, repo_dir);
                let work_fs = join_rel_path(work, repo_dir);
                let base_exists =
                    !matches!(inspect_base_node(&base_fs, repo_dir)?, BaseNode::Absent);
                let work_exists = match fs::symlink_metadata(&work_fs) {
                    Ok(_) => true,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                    Err(e) => {
                        return Err(ExtractError::Io {
                            context: "stat repo_dir",
                            path: Some(repo_dir.clone()),
                            kind: e.kind(),
                        })
                    }
                };
                if !base_exists && !work_exists {
                    return Err(ExtractError::MissingRepoDir {
                        repo_dir: repo_dir.clone(),
                    });
                }
                state.ensure_missing_ancestors(repo_dir)?;
                state.diff_node(repo_dir, depth)?;
            }
        }
        TaskClass::Artifact { paths } => {
            let mut canonical_targets = BTreeSet::new();
            for p in paths {
                validate_relative_path(p)?;
                if path_has_dot_git(p) {
                    continue;
                }
                canonical_targets.insert(p.clone());
            }

            // Filter out targets already covered by an ancestor target directory.
            let mut filtered_targets = Vec::new();
            for candidate in &canonical_targets {
                let covered = filtered_targets.iter().any(|parent: &String| {
                    candidate.starts_with(parent.as_str())
                        && candidate.as_bytes().get(parent.len()) == Some(&b'/')
                });
                if !covered {
                    filtered_targets.push(candidate.clone());
                }
            }

            for target in &filtered_targets {
                let depth = target.split('/').count();
                state.ensure_missing_ancestors(target)?;
                state.diff_node(target, depth)?;
            }
        }
    }

    state.skipped.sort();
    let _writer = state.writer.finish()?;
    Ok(ExtractReport {
        skipped: state.skipped,
    })
}

fn verify_real_directory(root: &Path, which: &'static str) -> Result<(), ExtractError> {
    let meta = fs::symlink_metadata(root).map_err(|_| ExtractError::InvalidTreeRoot { which })?;
    let ft = meta.file_type();
    if ft.is_symlink() || !ft.is_dir() {
        return Err(ExtractError::InvalidTreeRoot { which });
    }
    Ok(())
}

fn path_has_dot_git(rel_path: &str) -> bool {
    rel_path.split('/').any(|seg| seg == ".git")
}

fn join_rel_path(root: &Path, rel_path: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for seg in rel_path.split('/') {
        if !seg.is_empty() {
            out.push(seg);
        }
    }
    out
}

fn collect_dir_names_if_real_dir(
    dir_fs: &Path,
    rel_dir: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), ExtractError> {
    let meta = match fs::symlink_metadata(dir_fs) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(ExtractError::Io {
                context: "stat directory",
                path: (!rel_dir.is_empty()).then(|| rel_dir.to_string()),
                kind: e.kind(),
            })
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() || !ft.is_dir() {
        return Ok(());
    }

    let read_dir = fs::read_dir(dir_fs).map_err(|e| ExtractError::Io {
        context: "read_dir",
        path: (!rel_dir.is_empty()).then(|| rel_dir.to_string()),
        kind: e.kind(),
    })?;

    for (scanned, entry_res) in read_dir.enumerate() {
        if scanned >= MAX_DIR_SCAN_ENTRIES {
            return Err(ExtractError::CapExceeded {
                cap: CapName::Entries,
                limit: HARD_MAX_ENTRIES as u64,
                actual: scanned.saturating_add(1) as u64,
            });
        }
        let entry = entry_res.map_err(|e| ExtractError::Io {
            context: "read_dir entry",
            path: (!rel_dir.is_empty()).then(|| rel_dir.to_string()),
            kind: e.kind(),
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExtractError::InvalidUtf8Path)?;

        // Ignore ".git" at any depth.
        if name == ".git" {
            continue;
        }
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
        {
            return Err(ExtractError::InvalidPath {
                path: name,
                reason: "invalid directory entry name",
            });
        }
        out.insert(name);
    }

    Ok(())
}

fn inspect_base_node(base_fs: &Path, rel_path: &str) -> Result<BaseNode, ExtractError> {
    let meta = match fs::symlink_metadata(base_fs) {
        Ok(m) => m,
        Err(e)
            if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::NotADirectory =>
        {
            return Ok(BaseNode::Absent)
        }
        Err(e) => {
            return Err(ExtractError::Io {
                context: "stat base entry",
                path: Some(rel_path.to_string()),
                kind: e.kind(),
            })
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Ok(BaseNode::Absent);
    }
    if ft.is_dir() {
        return Ok(BaseNode::Dir);
    }
    if ft.is_file() {
        return Ok(BaseNode::File(meta));
    }
    Ok(BaseNode::Absent)
}

fn inspect_work_node(
    work_fs: &Path,
    rel_path: &str,
    skipped: &mut Vec<SkippedEntry>,
) -> Result<WorkNode, ExtractError> {
    let meta = match fs::symlink_metadata(work_fs) {
        Ok(m) => m,
        Err(e)
            if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::NotADirectory =>
        {
            return Ok(WorkNode::Absent)
        }
        Err(e) => {
            return Err(ExtractError::Io {
                context: "stat work entry",
                path: Some(rel_path.to_string()),
                kind: e.kind(),
            })
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        skipped.push(SkippedEntry {
            path: rel_path.to_string(),
            kind: SkippedKind::Symlink,
        });
        return Ok(WorkNode::Skipped);
    }
    if ft.is_dir() {
        return Ok(WorkNode::Dir);
    }
    if ft.is_file() {
        #[cfg(unix)]
        if meta.nlink() > 1 {
            skipped.push(SkippedEntry {
                path: rel_path.to_string(),
                kind: SkippedKind::Hardlink,
            });
            return Ok(WorkNode::Skipped);
        }
        return Ok(WorkNode::File(meta));
    }

    let kind = classify_special_file_type(&ft);
    skipped.push(SkippedEntry {
        path: rel_path.to_string(),
        kind,
    });
    Ok(WorkNode::Skipped)
}

#[cfg(unix)]
fn classify_special_file_type(ft: &fs::FileType) -> SkippedKind {
    if ft.is_block_device() || ft.is_char_device() {
        SkippedKind::Device
    } else if ft.is_fifo() {
        SkippedKind::Fifo
    } else if ft.is_socket() {
        SkippedKind::Socket
    } else {
        SkippedKind::Other
    }
}

#[cfg(not(unix))]
fn classify_special_file_type(_ft: &fs::FileType) -> SkippedKind {
    SkippedKind::Other
}

#[cfg(unix)]
fn file_mode_from_meta(meta: &Metadata) -> u32 {
    if meta.permissions().mode() & 0o111 != 0 {
        MODE_FILE_EXEC
    } else {
        MODE_FILE_DEFAULT
    }
}

#[cfg(not(unix))]
fn file_mode_from_meta(_meta: &Metadata) -> u32 {
    MODE_FILE_DEFAULT
}

fn read_work_file_once<F>(
    work_fs_path: &Path,
    base_cmp: Option<(&Path, &Metadata)>,
    rel_path: &str,
    stat_meta: &Metadata,
    caps: &Caps,
    total_bytes: u64,
    mut hook: Option<&mut F>,
) -> Result<ReadFileOutcome, ExtractError>
where
    F: FnMut(&str) -> io::Result<()>,
{
    let expected_size = stat_meta.len();
    let mode = file_mode_from_meta(stat_meta);
    #[cfg(unix)]
    let (expected_dev, expected_ino) = (stat_meta.dev(), stat_meta.ino());

    if expected_size > caps.max_file_bytes {
        return Err(ExtractError::CapExceeded {
            cap: CapName::PerFileBytes,
            limit: caps.max_file_bytes,
            actual: expected_size,
        });
    }
    let projected_total =
        total_bytes
            .checked_add(expected_size)
            .ok_or(ExtractError::CapExceeded {
                cap: CapName::TotalBytes,
                limit: caps.max_total_bytes,
                actual: u64::MAX,
            })?;
    if projected_total > caps.max_total_bytes {
        return Err(ExtractError::CapExceeded {
            cap: CapName::TotalBytes,
            limit: caps.max_total_bytes,
            actual: projected_total,
        });
    }

    if let Some(h) = hook.as_mut() {
        h(rel_path).map_err(|e| ExtractError::Io {
            context: "test hook",
            path: Some(rel_path.to_string()),
            kind: e.kind(),
        })?;
    }

    let mut work_file = File::open(work_fs_path).map_err(|e| ExtractError::Io {
        context: "open work file",
        path: Some(rel_path.to_string()),
        kind: e.kind(),
    })?;

    let open_meta = work_file.metadata().map_err(|e| ExtractError::Io {
        context: "fstat work file",
        path: Some(rel_path.to_string()),
        kind: e.kind(),
    })?;

    if !open_meta.file_type().is_file()
        || open_meta.file_type().is_symlink()
        || open_meta.len() != expected_size
    {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }
    #[cfg(unix)]
    if open_meta.dev() != expected_dev || open_meta.ino() != expected_ino || open_meta.nlink() != 1
    {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }

    let mut base_file_opt: Option<File> = match base_cmp {
        Some((base_path, base_stat)) => {
            let bf = File::open(base_path).map_err(|e| ExtractError::Io {
                context: "open base file",
                path: Some(rel_path.to_string()),
                kind: e.kind(),
            })?;
            let bf_meta = bf.metadata().map_err(|e| ExtractError::Io {
                context: "fstat base file",
                path: Some(rel_path.to_string()),
                kind: e.kind(),
            })?;
            if bf_meta.file_type().is_file() && bf_meta.len() == base_stat.len() {
                Some(bf)
            } else {
                None
            }
        }
        None => None,
    };

    let expected_usize =
        usize::try_from(expected_size).map_err(|_| ExtractError::AllocationFailed {
            path: rel_path.to_string(),
        })?;
    let mut data: Vec<u8> = Vec::new();
    if expected_usize > 0 {
        data.try_reserve_exact(expected_usize)
            .map_err(|_| ExtractError::AllocationFailed {
                path: rel_path.to_string(),
            })?;
    }

    let mut hasher = Sha256::new();
    let mut work_chunk = [0u8; MAX_CHUNK_BYTES];
    let mut base_chunk = [0u8; MAX_CHUNK_BYTES];
    let mut bytes_read: u64 = 0;
    let mut eintr_count: usize = 0;
    let mut still_matches_base = base_file_opt.is_some();

    let max_iters = (expected_size / (MAX_CHUNK_BYTES as u64))
        .saturating_add(MAX_EINTR_RETRIES as u64)
        .saturating_add(4);

    for _ in 0..max_iters {
        match work_file.read(&mut work_chunk) {
            Ok(0) => break,
            Ok(n) => {
                bytes_read = bytes_read.checked_add(n as u64).ok_or_else(|| {
                    ExtractError::FileChangedDuringRead {
                        path: rel_path.to_string(),
                    }
                })?;
                if bytes_read > expected_size {
                    return Err(ExtractError::FileChangedDuringRead {
                        path: rel_path.to_string(),
                    });
                }
                if bytes_read > caps.max_file_bytes {
                    return Err(ExtractError::CapExceeded {
                        cap: CapName::PerFileBytes,
                        limit: caps.max_file_bytes,
                        actual: bytes_read,
                    });
                }
                let running_total =
                    total_bytes
                        .checked_add(bytes_read)
                        .ok_or(ExtractError::CapExceeded {
                            cap: CapName::TotalBytes,
                            limit: caps.max_total_bytes,
                            actual: u64::MAX,
                        })?;
                if running_total > caps.max_total_bytes {
                    return Err(ExtractError::CapExceeded {
                        cap: CapName::TotalBytes,
                        limit: caps.max_total_bytes,
                        actual: running_total,
                    });
                }

                let slice = work_chunk.get(..n).unwrap_or(&[]);
                hasher.update(slice);

                if still_matches_base {
                    if let Some(bf) = base_file_opt.as_mut() {
                        if let Some(base_slice) = base_chunk.get_mut(..n) {
                            match read_exact_base_chunk(bf, base_slice) {
                                Ok(true) => {
                                    if base_slice != slice {
                                        still_matches_base = false;
                                    }
                                }
                                Ok(false) => {
                                    still_matches_base = false;
                                }
                                Err(kind) => {
                                    return Err(ExtractError::Io {
                                        context: "read base file",
                                        path: Some(rel_path.to_string()),
                                        kind,
                                    });
                                }
                            }
                        }
                    }
                }

                data.extend_from_slice(slice);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                eintr_count = eintr_count.saturating_add(1);
                if eintr_count > MAX_EINTR_RETRIES {
                    return Err(ExtractError::Io {
                        context: "read work file",
                        path: Some(rel_path.to_string()),
                        kind: io::ErrorKind::Interrupted,
                    });
                }
            }
            Err(e) => {
                return Err(ExtractError::Io {
                    context: "read work file",
                    path: Some(rel_path.to_string()),
                    kind: e.kind(),
                });
            }
        }
    }

    if bytes_read != expected_size {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }

    // Re-verify open file descriptor metadata and path metadata after reading.
    let post_open_meta = work_file.metadata().map_err(|e| ExtractError::Io {
        context: "post-read fstat work file",
        path: Some(rel_path.to_string()),
        kind: e.kind(),
    })?;
    if !post_open_meta.file_type().is_file() || post_open_meta.len() != expected_size {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }
    #[cfg(unix)]
    if post_open_meta.dev() != expected_dev || post_open_meta.ino() != expected_ino {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }

    let post_path_meta =
        fs::symlink_metadata(work_fs_path).map_err(|_| ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        })?;
    if !post_path_meta.file_type().is_file()
        || post_path_meta.file_type().is_symlink()
        || post_path_meta.len() != expected_size
    {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }
    #[cfg(unix)]
    if post_path_meta.dev() != expected_dev || post_path_meta.ino() != expected_ino {
        return Err(ExtractError::FileChangedDuringRead {
            path: rel_path.to_string(),
        });
    }

    if still_matches_base {
        return Ok(ReadFileOutcome::Unchanged);
    }

    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(ReadFileOutcome::Changed { mode, sha256, data })
}

fn read_exact_base_chunk(file: &mut File, buf: &mut [u8]) -> Result<bool, io::ErrorKind> {
    let mut filled: usize = 0;
    let mut eintr_count: usize = 0;
    let max_iters = buf
        .len()
        .saturating_add(MAX_EINTR_RETRIES)
        .saturating_add(1);
    for _ in 0..max_iters {
        if filled >= buf.len() {
            return Ok(true);
        }
        let rem = buf.get_mut(filled..).unwrap_or(&mut []);
        match file.read(rem) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                filled = filled.saturating_add(n);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                eintr_count = eintr_count.saturating_add(1);
                if eintr_count > MAX_EINTR_RETRIES {
                    return Err(io::ErrorKind::Interrupted);
                }
            }
            Err(e) => return Err(e.kind()),
        }
    }
    Ok(false)
}
