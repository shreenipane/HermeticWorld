//! Safe file operations applying the security checklist rules:
//! - Never follow symlinks; lstat / symlink_metadata before opening.
//! - Refuse FIFOs, sockets, character devices, block devices, and directories.
//! - Bounded reads enforced by a named cap.
//! - Atomic writes via temporary file and atomic rename.
//! - Fail closed.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

#[derive(Debug)]
pub enum FsError {
    Io(io::Error),
    SymlinkForbidden(String),
    NonRegularFile(String),
    FileTooLarge {
        path: String,
        size: u64,
        limit: usize,
    },
    InvalidPath(String),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::SymlinkForbidden(p) => write!(f, "Refusing symlink at path: '{p}'"),
            Self::NonRegularFile(p) => write!(f, "Refusing non-regular file at path: '{p}'"),
            Self::FileTooLarge { path, size, limit } => {
                write!(
                    f,
                    "File at '{path}' size {size} exceeds limit {limit} bytes"
                )
            }
            Self::InvalidPath(p) => write!(f, "Invalid file path: '{p}'"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Safely read a regular file up to `max_bytes`, refusing symlinks, FIFOs, and devices.
pub fn safe_read_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, FsError> {
    let path_str = path.display().to_string();

    let meta = fs::symlink_metadata(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => FsError::Io(e),
        _ => FsError::Io(e),
    })?;

    if meta.file_type().is_symlink() {
        return Err(FsError::SymlinkForbidden(path_str));
    }

    if !meta.is_file() {
        return Err(FsError::NonRegularFile(path_str));
    }

    if meta.len() > max_bytes as u64 {
        return Err(FsError::FileTooLarge {
            path: path_str,
            size: meta.len(),
            limit: max_bytes,
        });
    }

    let mut file = File::open(path)?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    Read::take(&mut file, (max_bytes + 1) as u64).read_to_end(&mut buf)?;

    if buf.len() > max_bytes {
        return Err(FsError::FileTooLarge {
            path: path_str,
            size: buf.len() as u64,
            limit: max_bytes,
        });
    }

    Ok(buf)
}

/// Safely write content to a file atomically via a temporary file and rename.
pub fn safe_atomic_write_file(path: &Path, content: &[u8]) -> Result<(), FsError> {
    let parent = path
        .parent()
        .ok_or_else(|| FsError::InvalidPath(path.display().to_string()))?;
    if !parent.as_os_str().is_empty() {
        let parent_meta = fs::symlink_metadata(parent)?;
        if parent_meta.file_type().is_symlink() {
            return Err(FsError::SymlinkForbidden(parent.display().to_string()));
        }
    }

    let filename = path
        .file_name()
        .ok_or_else(|| FsError::InvalidPath(path.display().to_string()))?
        .to_string_lossy();

    let pid = std::process::id();
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_name = format!(".tmp.{filename}.{pid}.{count}");
    let tmp_path = parent.join(tmp_name);

    {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);

        let mut tmp_file = opts.open(&tmp_path)?;
        tmp_file.write_all(content)?;
        tmp_file.sync_all()?;
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(FsError::Io(e));
    }

    Ok(())
}
