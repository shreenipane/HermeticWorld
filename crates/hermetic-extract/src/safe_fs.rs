#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{
    fchmod, fstat, mkdirat, openat, renameat, statat, unlinkat, AtFlags, Mode, OFlags,
};

use crate::error::{ExtractError, FsSecurityError, QuotaError};

pub const MAX_TREE_ENTRIES: usize = 100_000;
pub const MAX_TREE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_TREE_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TREE_DEPTH: usize = 64;
pub const MAX_TREE_PATH_BYTES: usize = 4096;
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn security() -> ExtractError {
    FsSecurityError::TamperingDetected("unsafe or changed filesystem entry".into()).into()
}

fn same(a: &rustix::fs::Stat, b: &rustix::fs::Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode
}

/// Resolve every host path component without following a symlink.
pub fn open_dir_path(path: &Path) -> Result<OwnedFd, ExtractError> {
    let mut fd = openat(
        rustix::fs::CWD,
        if path.is_absolute() { "/" } else { "." },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| security())?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => fd = open_child_dir(&fd, name)?,
            _ => return Err(security()),
        }
    }
    Ok(fd)
}

pub fn open_child_dir(fd: &OwnedFd, name: &OsStr) -> Result<OwnedFd, ExtractError> {
    let before = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| security())?;
    if before.st_mode & 0o170000 != 0o040000 {
        return Err(security());
    }
    let child = openat(
        fd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| security())?;
    if !same(&before, &fstat(&child).map_err(|_| security())?) {
        return Err(security());
    }
    Ok(child)
}

pub fn open_regular_at(fd: &OwnedFd, name: &OsStr) -> Result<File, ExtractError> {
    let before = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| security())?;
    if before.st_mode & 0o170000 != 0o100000 {
        return Err(security());
    }
    let child = openat(
        fd,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| security())?;
    if !same(&before, &fstat(&child).map_err(|_| security())?) {
        return Err(security());
    }
    Ok(File::from(child))
}

pub fn open_regular_path(path: &Path) -> Result<File, ExtractError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let fd = open_dir_path(parent)?;
    open_regular_at(&fd, path.file_name().ok_or_else(security)?)
}

pub fn directory_names(fd: &OwnedFd) -> Result<Vec<OsString>, ExtractError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))? {
        if names.len() == MAX_TREE_ENTRIES {
            return Err(QuotaError::ResourceLimit("MAX_TREE_ENTRIES").into());
        }
        names.push(entry?.file_name());
    }
    names.sort();
    Ok(names)
}

/// The guard is armed only after exclusive creation and retains the created inode.
pub struct CleanupGuard<'a> {
    parent_fd: &'a OwnedFd,
    staging_fd: &'a OwnedFd,
    tmp_name: String,
    armed: bool,
}

impl<'a> CleanupGuard<'a> {
    pub fn new(parent_fd: &'a OwnedFd, staging_fd: &'a OwnedFd, tmp_name: String) -> Self {
        Self {
            parent_fd,
            staging_fd,
            tmp_name,
            armed: true,
        }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let (Ok(named), Ok(held)) = (
                statat(
                    self.parent_fd,
                    self.tmp_name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ),
                fstat(self.staging_fd),
            ) {
                if same(&named, &held) {
                    let _ = remove_entry_recursive(self.parent_fd, OsStr::new(&self.tmp_name));
                }
            }
        }
    }
}

pub fn remove_entry_recursive(dir_fd: &OwnedFd, name: &OsStr) -> Result<(), ExtractError> {
    let mut remaining =
        MAX_TREE_ENTRIES + crate::validator::MAX_STREAM_RECORDS as usize * MAX_TREE_DEPTH;
    remove_bounded(dir_fd, name, 0, &mut remaining)
}

fn remove_bounded(
    dir_fd: &OwnedFd,
    name: &OsStr,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), ExtractError> {
    if depth > MAX_TREE_DEPTH || *remaining == 0 {
        return Err(QuotaError::ResourceLimit("cleanup depth or entries").into());
    }
    *remaining -= 1;
    let stat = match statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(_) => return Err(security()),
    };
    if stat.st_mode & 0o170000 == 0o040000 {
        let child = open_child_dir(dir_fd, name)?;
        // Iterate rather than collecting: a rejected tree may contain both the
        // maximum pristine base and the maximum number of new stream entries.
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", child.as_raw_fd()))? {
            remove_bounded(&child, &entry?.file_name(), depth + 1, remaining)?;
        }
        unlinkat(dir_fd, name, AtFlags::REMOVEDIR).map_err(|_| security())?;
    } else {
        unlinkat(dir_fd, name, AtFlags::empty()).map_err(|_| security())?;
    }
    Ok(())
}

pub fn prepare_output_dir(
    out_dir: &Path,
) -> Result<(OwnedFd, OwnedFd, String, String), ExtractError> {
    let parent = out_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_fd = open_dir_path(parent)?;
    let out_name = out_dir
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(security)?
        .to_owned();
    match statat(&parent_fd, out_name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {
            mkdirat(&parent_fd, out_name.as_str(), Mode::from_raw_mode(0o700))
                .map_err(|_| security())?
        }
        Err(_) => return Err(security()),
        Ok(_) => {}
    }
    let out_fd = open_child_dir(&parent_fd, OsStr::new(&out_name))?;
    let stat = fstat(&out_fd).map_err(|_| security())?;
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(FsSecurityError::OutputDirNotOwned("destination".into()).into());
    }
    if !directory_names(&out_fd)?.is_empty() {
        return Err(FsSecurityError::OutputDirNotEmpty("destination".into()).into());
    }
    let tmp_name = format!(
        ".extract_tmp_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    Ok((parent_fd, out_fd, out_name, tmp_name))
}

pub fn create_staging_dir(parent_fd: &OwnedFd, tmp_name: &str) -> Result<OwnedFd, ExtractError> {
    mkdirat(parent_fd, tmp_name, Mode::from_raw_mode(0o700)).map_err(|_| security())?;
    open_child_dir(parent_fd, OsStr::new(tmp_name))
}

pub fn resolve_or_create_parent_dir(
    root_fd: &OwnedFd,
    path: &str,
) -> Result<(OwnedFd, String), ExtractError> {
    let mut parts = path.split('/').peekable();
    let mut fd = root_fd.try_clone()?;
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(security());
        }
        if parts.peek().is_none() {
            return Ok((fd, part.to_owned()));
        }
        match statat(&fd, part, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {
                mkdirat(&fd, part, Mode::from_raw_mode(0o755)).map_err(|_| security())?
            }
            Err(_) => return Err(security()),
            Ok(_) => {}
        }
        let child = open_child_dir(&fd, OsStr::new(part))?;
        fchmod(&child, Mode::from_raw_mode(0o755)).map_err(|_| security())?;
        fd = child;
    }
    Err(security())
}

/// Deleting a nonexistent descendant must not create its missing ancestors.
pub fn resolve_existing_parent(
    root_fd: &OwnedFd,
    path: &str,
) -> Result<Option<(OwnedFd, String)>, ExtractError> {
    let mut parts = path.split('/').peekable();
    let mut fd = root_fd.try_clone()?;
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(security());
        }
        if parts.peek().is_none() {
            return Ok(Some((fd, part.to_owned())));
        }
        match statat(&fd, part, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(security()),
            Ok(_) => {}
        }
        fd = open_child_dir(&fd, OsStr::new(part))?;
    }
    Err(security())
}

pub fn create_file_exclusive(
    parent_fd: &OwnedFd,
    leaf_name: &str,
    mode: u32,
) -> Result<File, ExtractError> {
    match statat(parent_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if stat.st_mode & 0o170000 == 0o100000 => {
            unlinkat(parent_fd, leaf_name, AtFlags::empty()).map_err(|_| security())?
        }
        Ok(_) => return Err(security()),
        Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(security()),
    }
    let fd = openat(
        parent_fd,
        leaf_name,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| security())?;
    fchmod(&fd, Mode::from_raw_mode(mode)).map_err(|_| security())?;
    Ok(File::from(fd))
}

pub fn create_directory(
    parent_fd: &OwnedFd,
    leaf_name: &str,
    mode: u32,
) -> Result<(), ExtractError> {
    match statat(parent_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {
            mkdirat(parent_fd, leaf_name, Mode::from_raw_mode(0o700)).map_err(|_| security())?
        }
        Err(_) => return Err(security()),
        Ok(_) => {}
    }
    let fd = open_child_dir(parent_fd, OsStr::new(leaf_name))?;
    fchmod(&fd, Mode::from_raw_mode(mode)).map_err(|_| security())?;
    Ok(())
}

pub fn delete_entry(parent_fd: &OwnedFd, leaf_name: &str) -> Result<(), ExtractError> {
    remove_entry_recursive(parent_fd, OsStr::new(leaf_name))
}

pub fn publish_atomically(
    parent_fd: &OwnedFd,
    out_fd: &OwnedFd,
    staging_fd: &OwnedFd,
    tmp_name: &str,
    out_name: &str,
) -> Result<(), ExtractError> {
    let named = statat(parent_fd, out_name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| security())?;
    if !same(&named, &fstat(out_fd).map_err(|_| security())?)
        || !directory_names(out_fd)?.is_empty()
    {
        return Err(security());
    }
    let staged = statat(parent_fd, tmp_name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| security())?;
    if !same(&staged, &fstat(staging_fd).map_err(|_| security())?) {
        return Err(security());
    }
    // Change mode through the held descriptor, never through the publication name.
    fchmod(staging_fd, Mode::from_raw_mode(0o755)).map_err(|_| security())?;
    renameat(parent_fd, tmp_name, parent_fd, out_name).map_err(|_| security())?;
    Ok(())
}

#[derive(Clone)]
pub struct TreeEntry {
    pub is_dir: bool,
    pub mode: u32,
    pub size: u64,
}
pub type TreeIndex = BTreeMap<String, TreeEntry>;

pub fn restore_base_entry(
    base: &OwnedFd,
    index: &TreeIndex,
    staging: &OwnedFd,
    path: &str,
) -> Result<(), ExtractError> {
    let prefix = format!("{path}/");
    for (entry_path, entry) in index
        .iter()
        .filter(|(p, _)| p.as_str() == path || p.starts_with(&prefix))
    {
        let (parent, leaf) = resolve_or_create_parent_dir(staging, entry_path)?;
        if entry.is_dir {
            create_directory(&parent, &leaf, 0o755)?;
        } else {
            let mut file = open_relative_regular(base, entry_path)?.take(entry.size + 1);
            let mut out = create_file_exclusive(&parent, &leaf, entry.mode)?;
            if io::copy(&mut file, &mut out)? != entry.size {
                return Err(security());
            }
        }
    }
    Ok(())
}

/// Inventory and copy use held descriptors and fixed caps independent of stream quotas.
pub fn copy_base_tree(
    base_fd: &OwnedFd,
    staging_fd: Option<&OwnedFd>,
) -> Result<TreeIndex, ExtractError> {
    let mut index = BTreeMap::new();
    let mut bytes = 0;
    walk_tree(base_fd, staging_fd, "", &mut index, &mut bytes)?;
    Ok(index)
}

fn walk_tree(
    source: &OwnedFd,
    dest: Option<&OwnedFd>,
    prefix: &str,
    index: &mut TreeIndex,
    bytes: &mut u64,
) -> Result<(), ExtractError> {
    for name in directory_names(source)? {
        let name_str = name.to_str().ok_or_else(security)?;
        let path = if prefix.is_empty() {
            name_str.to_owned()
        } else {
            format!("{prefix}/{name_str}")
        };
        if index.len() >= MAX_TREE_ENTRIES
            || path.len() > MAX_TREE_PATH_BYTES
            || path.split('/').count() > MAX_TREE_DEPTH
        {
            return Err(QuotaError::ResourceLimit("base tree entries, path or depth").into());
        }
        let stat =
            statat(source, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(|_| security())?;
        let mode = stat.st_mode;
        let is_dir = mode & 0o170000 == 0o040000;
        if !is_dir && mode & 0o170000 != 0o100000 {
            return Err(security());
        }
        let size = u64::try_from(stat.st_size).map_err(|_| security())?;
        let clean_mode = if is_dir || mode & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        index.insert(
            path.clone(),
            TreeEntry {
                is_dir,
                mode: clean_mode,
                size: if is_dir { 0 } else { size },
            },
        );
        if is_dir {
            let child = open_child_dir(source, &name)?;
            let target = if let Some(dest) = dest {
                create_directory(dest, name_str, 0o755)?;
                Some(open_child_dir(dest, &name)?)
            } else {
                None
            };
            walk_tree(&child, target.as_ref(), &path, index, bytes)?;
        } else {
            if size > MAX_TREE_FILE_BYTES {
                return Err(QuotaError::ResourceLimit("MAX_TREE_FILE_BYTES").into());
            }
            *bytes = bytes
                .checked_add(size)
                .filter(|n| *n <= MAX_TREE_BYTES)
                .ok_or(QuotaError::ResourceLimit("MAX_TREE_BYTES"))?;
            let mut file = open_regular_at(source, &name)?;
            if let Some(dest) = dest {
                let mut output = create_file_exclusive(dest, name_str, clean_mode)?;
                let copied = io::copy(&mut Read::by_ref(&mut file).take(size + 1), &mut output)?;
                if copied != size {
                    return Err(security());
                }
                output.flush()?;
            }
        }
    }
    Ok(())
}

pub fn read_base_file(root: &OwnedFd, path: &str, cap: u64) -> Result<Vec<u8>, ExtractError> {
    let file = open_relative_regular(root, path)?;
    let mut data = Vec::new();
    file.take(cap + 1).read_to_end(&mut data)?;
    if data.len() as u64 > cap {
        return Err(QuotaError::ResourceLimit("base section bytes").into());
    }
    Ok(data)
}

pub fn open_relative_regular(root: &OwnedFd, path: &str) -> Result<File, ExtractError> {
    let mut parts = path.split('/').peekable();
    let mut fd = root.try_clone()?;
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(security());
        }
        if parts.peek().is_some() {
            fd = open_child_dir(&fd, OsStr::new(part))?;
        } else {
            return open_regular_at(&fd, OsStr::new(part));
        }
    }
    Err(security())
}
