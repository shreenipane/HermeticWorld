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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags::O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            invalid(format!(
                "cannot open {} as a regular file without following symlinks: {e}",
                path.display()
            ))
        })?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(invalid(format!("{} is not a regular file", path.display())));
    }
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

/// Atomically replace a regular state file using an exclusive 0600 temporary
/// file in the held directory. Existing links and special files are refused.
pub fn write_state_file(dir: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    const MAX_STATE_BYTES: usize = 64 * 1024;
    const MAX_TEMP_ATTEMPTS: usize = 64;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || bytes.len() > MAX_STATE_BYTES
    {
        return Err(invalid("invalid state file input".into()));
    }
    let destination = fd_path(dir, std::ffi::OsStr::new(name));
    match std::fs::symlink_metadata(&destination) {
        Ok(meta) if meta.is_file() => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(invalid("state destination is not a regular file".into())),
    }
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temporary = fd_path(dir, std::ffi::OsStr::new(&format!(".tmp.state.{attempt}")));
        if temporary == destination {
            continue;
        }
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(flags::O_NOFOLLOW | O_NONBLOCK)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &destination)?;
            dir.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        return result;
    }
    Err(invalid("state temporary attempts exhausted".into()))
}

#[cfg(test)]
mod state_tests {
    use super::*;
    #[test]
    fn state_replace_is_atomic_for_held_readers_and_preserves_external_hardlinks() {
        let temp = tempfile::tempdir().unwrap();
        let dir = File::open(temp.path()).unwrap();
        let state = temp.path().join("state.json");
        std::fs::write(&state, b"old complete record").unwrap();
        let held = File::open(&state).unwrap();
        let external = temp.path().join("external");
        std::fs::hard_link(&state, &external).unwrap();
        write_state_file(&dir, "state.json", b"new complete record").unwrap();
        let mut old = Vec::new();
        held.take(1024).read_to_end(&mut old).unwrap();
        assert_eq!(old, b"old complete record");
        assert_eq!(std::fs::read(&external).unwrap(), old);
        assert_eq!(std::fs::read(&state).unwrap(), b"new complete record");
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn state_refuses_escape_names_and_symlinks_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let dir = File::open(temp.path()).unwrap();
        std::fs::write(temp.path().join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink("secret", temp.path().join("state")).unwrap();
        for name in ["state", "../outside", "/tmp/outside", "", ".", ".."] {
            assert!(write_state_file(&dir, name, b"new").is_err());
        }
        assert_eq!(
            std::fs::read(temp.path().join("secret")).unwrap(),
            b"secret"
        );
    }
}
