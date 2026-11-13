//! Linux file operations anchored to inspected directory and inode handles.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::table::TableError;

const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 256;
const O_NOFOLLOW: i32 = 0x20000;
const O_DIRECTORY: i32 = 0x10000;
const O_PATH: i32 = 0x200000;
const O_NONBLOCK: i32 = 0x800;

pub(crate) fn io_error(error: io::Error) -> TableError {
    TableError::Io(format!("{:?}", error.kind()))
}

fn handle_path(file: &File) -> PathBuf {
    // The kernel-owned magic link pins this handle's inode. User paths are never
    // resolved again after their component has been opened.
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

pub(crate) fn child_path(directory: &File, name: &std::ffi::OsStr) -> PathBuf {
    handle_path(directory).join(name)
}

fn same_inode(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
}

pub(crate) fn inspect_regular(path: &Path) -> Result<Option<fs::Metadata>, TableError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    if meta.file_type().is_symlink() {
        return Err(TableError::SymlinkNotAllowed);
    }
    if !meta.is_file() {
        return Err(TableError::NotRegularFile);
    }
    Ok(Some(meta))
}

pub(crate) fn open_parent(path: &Path) -> Result<(File, std::ffi::OsString), TableError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(TableError::Io("Unsupported".into()));
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || bytes.contains(&0)
        || (bytes.ends_with(b"/") || bytes.ends_with(b"/."))
    {
        return Err(TableError::InvalidDestinationPath);
    }
    let components: Vec<_> = path.components().collect();
    if components.len() > MAX_PATH_COMPONENTS
        || components
            .iter()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(TableError::InvalidDestinationPath);
    }
    let names: Vec<_> = components
        .iter()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(*name),
            _ => None,
        })
        .collect();
    let (leaf, ancestors) = names
        .split_last()
        .ok_or(TableError::InvalidDestinationPath)?;
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_DIRECTORY)
        .open(if path.is_absolute() { "/" } else { "." })
        .map_err(io_error)?;
    for component in ancestors {
        let child = child_path(&directory, component);
        let before = fs::symlink_metadata(&child).map_err(io_error)?;
        if before.file_type().is_symlink() {
            return Err(TableError::SymlinkNotAllowed);
        }
        if !before.is_dir() {
            return Err(TableError::NotRegularFile);
        }
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_DIRECTORY)
            .open(child)
            .map_err(io_error)?;
        if !same_inode(&before, &opened.metadata().map_err(io_error)?) {
            return Err(TableError::Io("ChangedPath".into()));
        }
        directory = opened;
    }
    Ok((directory, (*leaf).to_owned()))
}

pub(crate) fn open_regular(path: &Path, max_bytes: usize) -> Result<File, TableError> {
    open_regular_after_inspection(path, max_bytes, || {})
}

fn open_regular_after_inspection(
    path: &Path,
    max_bytes: usize,
    after_inspection: impl FnOnce(),
) -> Result<File, TableError> {
    let (directory, leaf) = open_parent(path)?;
    let child = child_path(&directory, &leaf);
    let before = inspect_regular(&child)?.ok_or_else(|| TableError::Io("NotFound".into()))?;
    if before.len() > max_bytes as u64 {
        return Err(TableError::InputTooLarge {
            size: usize::try_from(before.len()).unwrap_or(usize::MAX),
            max: max_bytes,
        });
    }
    after_inspection();
    // O_PATH acquires metadata only: replacing the file with a FIFO or device
    // cannot run device-open code or block waiting for a writer.
    let pinned = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW)
        .open(child)
        .map_err(io_error)?;
    let inspected = pinned.metadata().map_err(io_error)?;
    if !inspected.is_file() || !same_inode(&before, &inspected) {
        return Err(TableError::NotRegularFile);
    }
    let readable = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(handle_path(&pinned))
        .map_err(io_error)?;
    if !same_inode(&inspected, &readable.metadata().map_err(io_error)?) {
        return Err(TableError::NotRegularFile);
    }
    Ok(readable)
}

pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dns-io-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn leaf_exchange_to_symlink_or_fifo_never_opens_replacement() {
        for fifo in [false, true] {
            let scratch = Scratch::new();
            let input = scratch.0.join("input");
            let other = scratch.0.join("other");
            fs::write(&input, b"original").unwrap();
            fs::write(&other, b"secret").unwrap();
            let result = open_regular_after_inspection(&input, 1024, || {
                fs::remove_file(&input).unwrap();
                if fifo {
                    let output = std::process::Command::new("mkfifo")
                        .arg(&input)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                } else {
                    symlink(&other, &input).unwrap();
                }
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn pinned_parent_survives_directory_exchange_and_files_are_private() {
        let scratch = Scratch::new();
        let parent = scratch.0.join("parent");
        let moved = scratch.0.join("moved");
        let outside = scratch.0.join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        let (directory, leaf) = open_parent(&parent.join("output")).unwrap();
        fs::rename(&parent, &moved).unwrap();
        symlink(&outside, &parent).unwrap();
        let anchored = child_path(&directory, &leaf);
        let file = create_private(&anchored).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(moved.join("output").is_file());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
    }
}
