#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{chmodat, mkdirat, openat, renameat, statat, unlinkat, AtFlags, Mode, OFlags};

use crate::error::{ExtractError, FsSecurityError};

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// RAII cleanup guard that removes a temporary directory relative to its parent descriptor on failure.
pub struct CleanupGuard<'a> {
    parent_fd: &'a OwnedFd,
    tmp_name: String,
    armed: bool,
}

impl<'a> CleanupGuard<'a> {
    pub fn new(parent_fd: &'a OwnedFd, tmp_name: String) -> Self {
        Self {
            parent_fd,
            tmp_name,
            armed: true,
        }
    }

    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<'a> Drop for CleanupGuard<'a> {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_entry_recursive(self.parent_fd, &self.tmp_name);
        }
    }
}

/// Recursively removes a directory entry relative to a directory descriptor.
pub fn remove_entry_recursive(dir_fd: &OwnedFd, name: &str) -> io::Result<()> {
    // Try unlink as file first
    if unlinkat(dir_fd, name, AtFlags::empty()).is_ok() {
        return Ok(());
    }

    // If it's a directory, open it and remove its contents
    let child_fd = match openat(
        dir_fd,
        name,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => {
            // Try rmdir directly if empty or fallback
            return unlinkat(dir_fd, name, AtFlags::REMOVEDIR)
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()));
        }
    };

    // Read entries from child_fd
    let proc_path = format!("/proc/self/fd/{}", child_fd.as_raw_fd());
    if let Ok(entries) = std::fs::read_dir(&proc_path) {
        for entry in entries.flatten() {
            let sub_name = entry.file_name();
            if let Some(sub_str) = sub_name.to_str() {
                let _ = remove_entry_recursive(&child_fd, sub_str);
            }
        }
    }

    unlinkat(dir_fd, name, AtFlags::REMOVEDIR)
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

/// Verifies that the destination directory exists, is owned by caller, is empty, and not a symlink.
pub fn prepare_output_dir(out_dir: &Path) -> Result<(OwnedFd, String, String), ExtractError> {
    if out_dir.as_os_str().is_empty() {
        return Err(ExtractError::FsSecurity(
            FsSecurityError::OutputDirNotEmpty(out_dir.display().to_string()),
        ));
    }

    let meta = match std::fs::symlink_metadata(out_dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Create the directory if it does not exist
            std::fs::create_dir_all(out_dir).map_err(|e| {
                ExtractError::Config(format!(
                    "cannot create output directory '{}': {e}",
                    out_dir.display()
                ))
            })?;
            std::fs::symlink_metadata(out_dir).map_err(|e| {
                ExtractError::Config(format!(
                    "cannot stat created output directory '{}': {e}",
                    out_dir.display()
                ))
            })?
        }
        Err(e) => {
            return Err(ExtractError::Config(format!(
                "cannot stat output directory '{}': {e}",
                out_dir.display()
            )));
        }
    };

    if meta.file_type().is_symlink() {
        return Err(ExtractError::FsSecurity(
            FsSecurityError::OutputDirIsSymlink(out_dir.display().to_string()),
        ));
    }

    if !meta.file_type().is_dir() {
        return Err(ExtractError::FsSecurity(
            FsSecurityError::OutputDirNotEmpty(out_dir.display().to_string()),
        ));
    }

    let current_euid = rustix::process::geteuid().as_raw();
    if meta.uid() != current_euid {
        return Err(ExtractError::FsSecurity(
            FsSecurityError::OutputDirNotOwned(out_dir.display().to_string()),
        ));
    }

    // Check directory is empty
    let mut read_dir = std::fs::read_dir(out_dir).map_err(|e| {
        ExtractError::Config(format!(
            "cannot read output directory '{}': {e}",
            out_dir.display()
        ))
    })?;
    if read_dir.next().is_some() {
        return Err(ExtractError::FsSecurity(
            FsSecurityError::OutputDirNotEmpty(out_dir.display().to_string()),
        ));
    }

    let parent_path = out_dir.parent().unwrap_or_else(|| Path::new("."));
    let out_name = out_dir
        .file_name()
        .ok_or_else(|| {
            ExtractError::Config(format!(
                "invalid output directory name '{}'",
                out_dir.display()
            ))
        })?
        .to_str()
        .ok_or_else(|| {
            ExtractError::Config(format!(
                "non-UTF8 output directory name '{}'",
                out_dir.display()
            ))
        })?
        .to_string();

    let parent_fd = openat(
        rustix::fs::CWD,
        parent_path,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        ExtractError::Config(format!(
            "cannot open parent directory '{}': {e}",
            parent_path.display()
        ))
    })?;

    let tmp_name = format!(
        ".extract_tmp_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );

    Ok((parent_fd, out_name, tmp_name))
}

/// Creates a private staging directory in `parent_fd` and opens it.
pub fn create_staging_dir(parent_fd: &OwnedFd, tmp_name: &str) -> Result<OwnedFd, ExtractError> {
    mkdirat(parent_fd, tmp_name, Mode::from_raw_mode(0o700)).map_err(|e| {
        ExtractError::Config(format!(
            "failed to create temporary staging directory '{tmp_name}': {e}"
        ))
    })?;

    let staging_fd = openat(
        parent_fd,
        tmp_name,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        ExtractError::Config(format!(
            "failed to open temporary staging directory '{tmp_name}': {e}"
        ))
    })?;

    Ok(staging_fd)
}

/// Resolves or creates ancestor directories relative to a directory descriptor.
/// Each component is opened with O_NOFOLLOW to prevent symlink traversal.
pub fn resolve_or_create_parent_dir(
    root_fd: &OwnedFd,
    path: &str,
) -> Result<(OwnedFd, String), ExtractError> {
    let mut parts: Vec<&str> = path.split('/').collect();
    let leaf = parts
        .pop()
        .ok_or(ExtractError::PathValidation(crate::error::PathError::Empty))?;

    let mut current_fd = root_fd.try_clone().map_err(ExtractError::Io)?;

    for part in parts {
        match openat(
            &current_fd,
            part,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(child_fd) => {
                current_fd = child_fd;
            }
            Err(_) => {
                // Create directory with mode 0755
                mkdirat(&current_fd, part, Mode::from_raw_mode(0o755)).map_err(|e| {
                    ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
                        "cannot create directory '{part}': {e}"
                    )))
                })?;
                current_fd = openat(
                    &current_fd,
                    part,
                    OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|e| {
                    ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
                        "cannot open created directory '{part}': {e}"
                    )))
                })?;
            }
        }
    }

    Ok((current_fd, leaf.to_string()))
}

/// Creates a new regular file exclusively relative to a parent directory descriptor.
pub fn create_file_exclusive(
    parent_fd: &OwnedFd,
    leaf_name: &str,
    mode: u32,
) -> Result<File, ExtractError> {
    // If an existing entry was there (e.g. from base tree), remove it first
    let _ = unlinkat(parent_fd, leaf_name, AtFlags::empty());

    let fd = openat(
        parent_fd,
        leaf_name,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(mode),
    )
    .map_err(|e| {
        ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
            "failed to create file '{leaf_name}' exclusively: {e}"
        )))
    })?;

    Ok(File::from(fd))
}

/// Creates a directory relative to a parent directory descriptor.
pub fn create_directory(
    parent_fd: &OwnedFd,
    leaf_name: &str,
    mode: u32,
) -> Result<(), ExtractError> {
    // Check if it already exists as a directory
    if let Ok(stat) = statat(parent_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        if (stat.st_mode & 0o170000) == 0o040000 {
            return Ok(());
        } else {
            return Err(ExtractError::FsSecurity(
                FsSecurityError::TamperingDetected(format!(
                    "entry '{leaf_name}' exists but is not a directory"
                )),
            ));
        }
    }

    mkdirat(parent_fd, leaf_name, Mode::from_raw_mode(mode)).map_err(|e| {
        ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
            "failed to create directory '{leaf_name}': {e}"
        )))
    })?;

    Ok(())
}

/// Deletes an entry (file or directory) relative to a parent directory descriptor.
pub fn delete_entry(parent_fd: &OwnedFd, leaf_name: &str) -> Result<(), ExtractError> {
    let stat = match statat(parent_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(s) => s,
        Err(_) => return Ok(()), // Already deleted or nonexistent
    };

    if (stat.st_mode & 0o170000) == 0o040000 {
        remove_entry_recursive(parent_fd, leaf_name).map_err(|e| {
            ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
                "failed to remove directory '{leaf_name}': {e}"
            )))
        })?;
    } else {
        unlinkat(parent_fd, leaf_name, AtFlags::empty()).map_err(|e| {
            ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
                "failed to remove file '{leaf_name}': {e}"
            )))
        })?;
    }

    Ok(())
}

/// Atomically publishes the staging directory to the destination path.
pub fn publish_atomically(
    parent_fd: &OwnedFd,
    tmp_name: &str,
    out_name: &str,
) -> Result<(), ExtractError> {
    renameat(parent_fd, tmp_name, parent_fd, out_name).map_err(|e| {
        ExtractError::FsSecurity(FsSecurityError::TamperingDetected(format!(
            "atomic publication failed (rename '{tmp_name}' -> '{out_name}'): {e}"
        )))
    })?;

    // Set destination mode to 0755
    let _ = chmodat(
        parent_fd,
        out_name,
        Mode::from_raw_mode(0o755),
        AtFlags::SYMLINK_NOFOLLOW,
    );

    Ok(())
}

/// Safely copies the pristine base tree into the staging directory.
/// Symlinks, FIFOs, devices, and sockets in the base tree are strictly rejected.
pub fn copy_base_tree(base_dir: &Path, staging_fd: &OwnedFd) -> Result<(), ExtractError> {
    if !base_dir.exists() {
        return Ok(());
    }

    walk_and_copy_dir(base_dir, "", staging_fd)
}

fn walk_and_copy_dir(
    base_root: &Path,
    rel_path: &str,
    staging_fd: &OwnedFd,
) -> Result<(), ExtractError> {
    let current_dir = if rel_path.is_empty() {
        base_root.to_path_buf()
    } else {
        base_root.join(rel_path)
    };

    let entries = std::fs::read_dir(&current_dir).map_err(|e| {
        ExtractError::Config(format!(
            "cannot read base tree directory '{}': {e}",
            current_dir.display()
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(ExtractError::Io)?;
        let name = entry.file_name();
        let name_str = name.to_str().ok_or_else(|| {
            ExtractError::Config(format!(
                "non-UTF8 file name in base tree: '{}'",
                entry.path().display()
            ))
        })?;

        let entry_rel = if rel_path.is_empty() {
            name_str.to_string()
        } else {
            format!("{rel_path}/{name_str}")
        };

        let meta = std::fs::symlink_metadata(entry.path()).map_err(ExtractError::Io)?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            return Err(ExtractError::FsSecurity(FsSecurityError::SymlinkRejected(
                entry_rel,
            )));
        }

        if file_type.is_dir() {
            let (parent_dir_fd, leaf) = resolve_or_create_parent_dir(staging_fd, &entry_rel)?;
            create_directory(&parent_dir_fd, &leaf, 0o755)?;
            walk_and_copy_dir(base_root, &entry_rel, staging_fd)?;
        } else if file_type.is_file() {
            let (parent_dir_fd, leaf) = resolve_or_create_parent_dir(staging_fd, &entry_rel)?;
            let exec_bit = (meta.mode() & 0o111) != 0;
            let target_mode = if exec_bit { 0o755 } else { 0o644 };

            let mut in_file = File::open(entry.path()).map_err(ExtractError::Io)?;
            let mut out_file = create_file_exclusive(&parent_dir_fd, &leaf, target_mode)?;

            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = in_file.read(&mut buf).map_err(ExtractError::Io)?;
                if n == 0 {
                    break;
                }
                out_file.write_all(&buf[..n]).map_err(ExtractError::Io)?;
            }
        } else {
            return Err(ExtractError::FsSecurity(
                FsSecurityError::SpecialFileRejected(entry_rel),
            ));
        }
    }

    Ok(())
}
