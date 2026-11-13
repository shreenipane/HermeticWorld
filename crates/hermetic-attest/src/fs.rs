//! Descriptor-pinned, bounded Linux file operations. Requires a trusted procfs.
//! Every supplied component is inspected without following links, then pinned with
//! O_PATH | O_NOFOLLOW before use. Special files are never opened for I/O.
//! Atomic publication requires an output directory owned by this process's user
//! and not writable by other users; temporary entries remain in that pinned directory.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("attestation file operations require Linux x86_64 or aarch64");

// Linux ABI flags; keeping these here avoids adding a system-call dependency.
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(target_arch = "aarch64")]
const O_DIRECTORY: i32 = 0o40000;
const O_PATH: i32 = 0o10000000;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_PATH_COMPONENTS: usize = 256;
pub const MAX_TEMP_ATTEMPTS: usize = 32;
const TEMP_PREFIX: &str = ".attest-tmp-";

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
            Self::Io(_) => write!(f, "File I/O failed"),
            Self::SymlinkForbidden(_) => write!(f, "Symlink forbidden"),
            Self::NonRegularFile(_) => write!(f, "Regular file required"),
            Self::FileTooLarge { size, limit, .. } => {
                write!(f, "File size {size} exceeds {limit} bytes")
            }
            Self::InvalidPath(_) => write!(f, "Invalid or unsafe file path"),
        }
    }
}

impl std::error::Error for FsError {}
redacted_debug!(FsError);
impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn invalid_path() -> FsError {
    FsError::InvalidPath("invalid path".into())
}

fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn child_path(parent: &File, name: &OsStr) -> PathBuf {
    descriptor_path(parent).join(name)
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn check_type(meta: &Metadata, directory: bool) -> Result<(), FsError> {
    if meta.file_type().is_symlink() {
        return Err(FsError::SymlinkForbidden("entry".into()));
    }
    if if directory {
        !meta.is_dir()
    } else {
        !meta.is_file()
    } {
        return Err(FsError::NonRegularFile("entry".into()));
    }
    Ok(())
}

fn pin_entry(path: &Path, before: &Metadata, directory: bool) -> Result<File, FsError> {
    check_type(before, directory)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW | if directory { O_DIRECTORY } else { 0 })
        .open(path)?;
    let after = file.metadata()?;
    check_type(&after, directory)?;
    if !same_file(before, &after) {
        return Err(invalid_path());
    }
    Ok(file)
}

fn open_parent(path: &Path) -> Result<(File, &OsStr), FsError> {
    // Validate the entire path before touching the filesystem.
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(invalid_path());
    }
    let components: Vec<_> = path.components().take(MAX_PATH_COMPONENTS + 1).collect();
    if components.len() > MAX_PATH_COMPONENTS
        || components
            .iter()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(invalid_path());
    }
    let (Component::Normal(name), ancestors) = components.split_last().ok_or_else(invalid_path)?
    else {
        return Err(invalid_path());
    };
    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = pin_entry(start, &fs::symlink_metadata(start)?, true)?;
    for component in ancestors {
        if let Component::Normal(name) = component {
            let next = child_path(&directory, name);
            directory = pin_entry(&next, &fs::symlink_metadata(&next)?, true)?;
        }
    }
    Ok((directory, name))
}

/// Read at most the smaller of `max_bytes` and `MAX_FILE_BYTES`.
pub fn safe_read_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, FsError> {
    read_with_hook(path, max_bytes, || {})
}

fn read_with_hook(
    path: &Path,
    max_bytes: usize,
    after_lstat: impl FnOnce(),
) -> Result<Vec<u8>, FsError> {
    let max_bytes = max_bytes.min(MAX_FILE_BYTES);
    let (parent, name) = open_parent(path)?;
    let leaf_path = child_path(&parent, name);
    let before = fs::symlink_metadata(&leaf_path)?;
    check_type(&before, false)?;
    after_lstat();
    let pinned = pin_entry(&leaf_path, &before, false)?;
    let meta = pinned.metadata()?;
    if meta.len() > max_bytes as u64 {
        return Err(FsError::FileTooLarge {
            path: "file".into(),
            size: meta.len(),
            limit: max_bytes,
        });
    }
    // This intentional procfs link names the already checked regular inode.
    let file = File::open(descriptor_path(&pinned))?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(FsError::FileTooLarge {
            path: "file".into(),
            size: bytes.len() as u64,
            limit: max_bytes,
        });
    }
    Ok(bytes)
}

struct TemporaryEntry(Option<PathBuf>);
impl Drop for TemporaryEntry {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Publish bounded content atomically with mode 0600; sync data and directory.
pub fn safe_atomic_write_file(path: &Path, content: &[u8]) -> Result<(), FsError> {
    write_with_hook(path, content, || {})
}

fn write_with_hook(
    path: &Path,
    content: &[u8],
    after_parent: impl FnOnce(),
) -> Result<(), FsError> {
    if path
        .file_name()
        .is_some_and(|name| name.as_bytes().starts_with(TEMP_PREFIX.as_bytes()))
    {
        return Err(invalid_path());
    }
    if content.len() > MAX_FILE_BYTES {
        return Err(FsError::FileTooLarge {
            path: "file".into(),
            size: content.len() as u64,
            limit: MAX_FILE_BYTES,
        });
    }
    let (parent, name) = open_parent(path)?;
    let meta = parent.metadata()?;
    if meta.mode() & 0o022 != 0 || meta.uid() != fs::metadata("/proc/self")?.uid() {
        return Err(invalid_path());
    }
    let destination = child_path(&parent, name);
    match fs::symlink_metadata(&destination) {
        Ok(meta) => check_type(&meta, false)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    after_parent();
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = child_path(&parent, OsStr::new(&format!("{TEMP_PREFIX}{count}")));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        };
        let mut guard = TemporaryEntry(Some(temporary.clone()));
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        guard.0 = None;
        File::open(descriptor_path(&parent))?.sync_all()?;
        return Ok(());
    }
    Err(invalid_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn review_atomic_write_rejects_reserved_destinations() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in [".attest-tmp-0", ".attest-tmp-123", ".attest-tmp-"] {
            let path = dir.path().join(name);
            assert!(matches!(
                safe_atomic_write_file(&path, b"replacement"),
                Err(FsError::InvalidPath(_))
            ));
            assert!(!path.exists());
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        safe_atomic_write_file(&dir.path().join("run.json"), b"record").unwrap();
        assert_eq!(fs::read(dir.path().join("run.json")).unwrap(), b"record");
    }

    #[test]
    fn read_refuses_leaf_swapped_after_lstat() {
        let dir = tempfile::tempdir().unwrap();
        let leaf = dir.path().join("record");
        let secret = dir.path().join("secret");
        fs::write(&leaf, b"record").unwrap();
        fs::write(&secret, b"secret").unwrap();
        assert!(read_with_hook(&leaf, 100, || {
            fs::remove_file(&leaf).unwrap();
            symlink(&secret, &leaf).unwrap();
        })
        .is_err());
    }

    #[test]
    fn read_stays_in_pinned_parent_after_ancestor_swap() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        let saved = dir.path().join("saved");
        let outside = dir.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("record"), b"record").unwrap();
        fs::write(outside.join("record"), b"secret").unwrap();
        let bytes = read_with_hook(&parent.join("record"), 100, || {
            fs::rename(&parent, &saved).unwrap();
            symlink(&outside, &parent).unwrap();
        })
        .unwrap();
        assert_eq!(bytes, b"record");
    }

    #[test]
    fn write_stays_in_pinned_parent_after_ancestor_swap() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        let saved = dir.path().join("saved");
        let outside = dir.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&outside).unwrap();
        write_with_hook(&parent.join("record"), b"record", || {
            fs::rename(&parent, &saved).unwrap();
            symlink(&outside, &parent).unwrap();
        })
        .unwrap();
        assert_eq!(fs::read(saved.join("record")).unwrap(), b"record");
        assert!(!outside.join("record").exists());
    }
}
