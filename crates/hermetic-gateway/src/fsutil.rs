#![forbid(unsafe_code)]

//! Hardened file access for the gateway's host-side files (config, API key, host log).
//!
//! - Leaf files are opened with `O_NOFOLLOW | O_NONBLOCK` (a symlink fails to open, a FIFO
//!   never blocks) and must then be regular files (checked on the open descriptor).
//! - Reads are capped: at most `cap` bytes, and a larger file is an error, not a truncation.
//! - The log directory is walked component by component relative to the previous directory's
//!   descriptor (through `/proc/self/fd/<fd>/<name>`, which names exactly the directory already
//!   opened), with `O_NOFOLLOW | O_DIRECTORY`, so no component may be a symlink and nothing can
//!   be swapped between check and use. Missing directories are created with mode 0700.
//! - The log file is created with mode 0600, and an existing one is reset to 0600.
//!
//! Linux only (the gateway runs on Linux): the flag values below are the Linux ABI values for
//! the listed architectures.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
mod flags {
    pub const O_NOFOLLOW: i32 = 0o100000;
    pub const O_DIRECTORY: i32 = 0o40000;
}
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
mod flags {
    pub const O_NOFOLLOW: i32 = 0o400000;
    pub const O_DIRECTORY: i32 = 0o200000;
}
const O_NONBLOCK: i32 = 0o4000;

/// Largest gateway config file accepted.
pub const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
/// Largest API-key file accepted.
pub const MAX_API_KEY_FILE_BYTES: u64 = 16 * 1024;

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Reads a regular file (leaf symlinks, FIFOs, devices and sockets refused) of at most `cap`
/// bytes.
pub fn read_regular_file_capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let (file, meta) = open_input(path)?;
    if meta.len() > cap {
        return Err(invalid(format!(
            "{} is larger than the {cap}-byte limit",
            path.display()
        )));
    }
    let mut buf = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(invalid(format!(
            "{} is larger than the {cap}-byte limit",
            path.display()
        )));
    }
    Ok(buf)
}

/// Reads a secret only when its pinned inode has exactly owner read/write permissions.
pub fn read_secret_file_capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let (file, meta) = open_input(path)?;
    if meta.permissions().mode() & 0o7777 != 0o600 || meta.len() > cap {
        return Err(invalid(
            "secret file requires mode 0600 and bounded size".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(invalid("secret file exceeds byte cap".into()));
    }
    Ok(bytes)
}

fn open_input(path: &Path) -> io::Result<(File, std::fs::Metadata)> {
    const MAX_PATH_COMPONENTS: usize = 256;
    const O_PATH: i32 = 0o10000000;
    if path.as_os_str().len() > 4096 {
        return Err(invalid("input path too long".into()));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(flags::O_DIRECTORY | flags::O_NOFOLLOW)
        .open(if path.is_absolute() { "/" } else { "." })?;
    let mut parts = path.components().peekable();
    let mut count = 0usize;
    while let Some(part) = parts.next() {
        count = count.saturating_add(1);
        if count > MAX_PATH_COMPONENTS {
            return Err(invalid("input path too deep".into()));
        }
        let name = match part {
            Component::Normal(name) => name,
            Component::RootDir | Component::CurDir => continue,
            _ => return Err(invalid("invalid input path".into())),
        };
        let entry = fd_path(&directory, name);
        let before = std::fs::symlink_metadata(&entry)?;
        if parts.peek().is_some() {
            if !before.is_dir() {
                return Err(invalid("unsafe input directory".into()));
            }
            let next = open_dir_at(&directory, name)?;
            let after = next.metadata()?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(invalid("input directory changed".into()));
            }
            directory = next;
        } else {
            if !before.is_file() {
                return Err(invalid("input is not a regular file".into()));
            }
            // O_PATH pins without opening a device if the name is raced after lstat.
            let pinned = OpenOptions::new()
                .read(true)
                .custom_flags(O_PATH | flags::O_NOFOLLOW)
                .open(entry)?;
            let after = pinned.metadata()?;
            if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(invalid("input file changed".into()));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(O_NONBLOCK)
                .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
            return Ok((file, after));
        }
    }
    Err(invalid("input requires a file name".into()))
}

fn fd_path(dir: &File, name: &std::ffi::OsStr) -> PathBuf {
    let mut p = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    p.push(name);
    p
}

fn open_dir_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(flags::O_NOFOLLOW | flags::O_DIRECTORY)
        .open(fd_path(parent, name))
}

/// Opens (creating missing components with mode 0700) the directory `path`, refusing any
/// component that is a symlink or not a directory. `..` components are refused.
pub fn open_dir_nofollow_create(path: &Path) -> io::Result<File> {
    let mut current: File = if path.is_absolute() {
        OpenOptions::new()
            .read(true)
            .custom_flags(flags::O_DIRECTORY)
            .open("/")?
    } else {
        OpenOptions::new()
            .read(true)
            .custom_flags(flags::O_DIRECTORY)
            .open(".")?
    };
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) | Component::ParentDir => {
                return Err(invalid(format!(
                    "log directory {} must not contain '..'",
                    path.display()
                )));
            }
            Component::Normal(name) => {
                let next = match open_dir_at(&current, name) {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        match std::fs::DirBuilder::new()
                            .mode(0o700)
                            .create(fd_path(&current, name))
                        {
                            Ok(()) => {}
                            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(e) => return Err(e),
                        }
                        open_dir_at(&current, name)?
                    }
                    Err(e) => {
                        return Err(invalid(format!(
                            "log directory component {:?} of {} is not a real directory \
                             (symlinks are refused): {e}",
                            name,
                            path.display()
                        )))
                    }
                };
                current = next;
            }
        }
    }
    Ok(current)
}

/// Opens `dir/name` for appending: created with mode 0600 if missing; an existing entry must be
/// a regular file (not a symlink, FIFO or device) and is reset to mode 0600.
pub fn open_log_file(dir: &File, name: &str) -> io::Result<File> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(flags::O_NOFOLLOW | O_NONBLOCK)
        .open(fd_path(dir, std::ffi::OsStr::new(name)))
        .map_err(|e| {
            invalid(format!(
                "cannot open log file {name} as a regular file (symlinks and FIFOs are refused): {e}"
            ))
        })?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(invalid(format!("log file {name} is not a regular file")));
    }
    if meta.permissions().mode() & 0o777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}
