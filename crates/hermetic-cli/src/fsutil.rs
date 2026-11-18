#![forbid(unsafe_code)]

//! Strict filesystem traversal and validation for hermetic-cli.
//!
//! Follows no symlinks, verifies path components one-by-one, rejects
//! parent traversal (`..`), FIFOs, devices, sockets, and enforces
//! private permissions (0700 for directories, 0600 for secrets).

use std::path::{Component, Path};

use rustix::fd::OwnedFd;
use rustix::fs::{fchmod, mkdirat, openat, statat, AtFlags, Mode, OFlags};

use crate::dispatch::BackendError;

/// Maximum number of path components permitted in a verified directory or file path.
pub const MAX_PATH_COMPONENTS: usize = 256;

/// Opens and verifies directory path component-by-component without following any symlinks,
/// refusing symlinks, FIFOs, devices, sockets, and parent directory traversal (`..`).
pub fn open_dir_no_symlinks(path: &Path) -> Result<OwnedFd, BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data("empty path".to_string()));
    }
    let mut current_fd = openat(
        rustix::fs::CWD,
        if path.is_absolute() { "/" } else { "." },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
            BackendError::Io("input directory not found".to_string())
        } else {
            BackendError::Data("refused path: cannot open root directory".to_string())
        }
    })?;

    let mut component_count = 0usize;
    for component in path.components() {
        component_count += 1;
        if component_count > MAX_PATH_COMPONENTS {
            return Err(BackendError::Data(
                "refused path: too many path components".to_string(),
            ));
        }
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(BackendError::Data(
                    "refused path: parent traversal (..) is forbidden".to_string(),
                ));
            }
            Component::Normal(name) => {
                let st = statat(&current_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
                    if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
                        BackendError::Io("input directory not found".to_string())
                    } else if e.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
                        BackendError::Data("refused path: symlink encountered".to_string())
                    } else {
                        BackendError::Data("refused path component".to_string())
                    }
                })?;
                let mode = st.st_mode & 0o170000;
                if mode == 0o120000 {
                    return Err(BackendError::Data(
                        "refused path: symlink encountered".to_string(),
                    ));
                }
                if mode != 0o040000 {
                    return Err(BackendError::Data(
                        "refused path: component is not a directory".to_string(),
                    ));
                }
                let next_fd = openat(
                    &current_fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| {
                    BackendError::Data("refused path: cannot traverse directory".to_string())
                })?;
                current_fd = next_fd;
            }
            Component::Prefix(_) => {
                return Err(BackendError::Data("refused path: prefix".to_string()));
            }
        }
    }
    Ok(current_fd)
}

/// Verifies that every path component exists without following any symlinks,
/// refusing symlinks, FIFOs, devices, sockets, and parent directory traversal (`..`).
pub fn verify_dir_no_symlinks(path: &Path) -> Result<(), BackendError> {
    open_dir_no_symlinks(path).map(|_| ())
}

/// Verifies that a secret file (e.g., private key or API key file) exists,
/// is a regular file (not a symlink, FIFO, or device), and has mode 0600.
pub fn verify_secret_file_no_symlinks(path: &Path) -> Result<(), BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data("empty key path".to_string()));
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let filename = path
        .file_name()
        .ok_or_else(|| BackendError::Data("path has no filename".to_string()))?;

    let parent_fd = open_dir_no_symlinks(parent)?;

    let st = statat(&parent_fd, filename, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
        if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
            BackendError::Io("secret file not found".to_string())
        } else if e.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
            BackendError::Data("refused secret file: symlink".to_string())
        } else {
            BackendError::Data("refused secret file".to_string())
        }
    })?;

    let file_type = st.st_mode & 0o170000;
    if file_type != 0o100000 {
        return Err(BackendError::Data(
            "refused secret file: not a regular file".to_string(),
        ));
    }
    let permissions = st.st_mode & 0o777;
    if permissions != 0o600 {
        return Err(BackendError::Data(format!(
            "refused secret file: permissions must be 0600, got 0{:o}",
            permissions
        )));
    }
    Ok(())
}

/// Prepares an output directory with mode 0700 using descriptor-based no-follow traversal.
/// Refuses any path containing symlinks or parent traversal (`..`).
pub fn prepare_output_dir(path: &Path) -> Result<(), BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data(
            "empty output directory path".to_string(),
        ));
    }
    let mut current_fd = openat(
        rustix::fs::CWD,
        if path.is_absolute() { "/" } else { "." },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
            BackendError::Io("output directory root not found".to_string())
        } else {
            BackendError::Data("refused path: cannot open root directory".to_string())
        }
    })?;

    let mut component_count = 0usize;
    for component in path.components() {
        component_count += 1;
        if component_count > MAX_PATH_COMPONENTS {
            return Err(BackendError::Data(
                "refused path: too many path components".to_string(),
            ));
        }
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(BackendError::Data(
                    "refused path: parent traversal (..) is forbidden".to_string(),
                ));
            }
            Component::Prefix(_) => {
                return Err(BackendError::Data("refused path: prefix".to_string()));
            }
            Component::Normal(name) => {
                match statat(&current_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(st) => {
                        let mode = st.st_mode & 0o170000;
                        if mode == 0o120000 {
                            return Err(BackendError::Data(
                                "refused output directory: symlink encountered".to_string(),
                            ));
                        }
                        if mode != 0o040000 {
                            return Err(BackendError::Data(
                                "refused output directory: component is not a directory"
                                    .to_string(),
                            ));
                        }
                    }
                    Err(e) if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() => {
                        mkdirat(&current_fd, name, Mode::from_raw_mode(0o700)).map_err(|_| {
                            BackendError::Io("cannot create output directory component".to_string())
                        })?;
                    }
                    Err(e) if e.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() => {
                        return Err(BackendError::Data(
                            "refused output directory: symlink encountered".to_string(),
                        ));
                    }
                    Err(_) => {
                        return Err(BackendError::Data(
                            "refused output directory component".to_string(),
                        ));
                    }
                }

                let next_fd = openat(
                    &current_fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| {
                    BackendError::Data(
                        "refused output directory: cannot traverse directory".to_string(),
                    )
                })?;
                current_fd = next_fd;
            }
        }
    }

    fchmod(&current_fd, Mode::from_raw_mode(0o700))
        .map_err(|_| BackendError::Io("cannot set output directory permissions".to_string()))?;

    Ok(())
}
