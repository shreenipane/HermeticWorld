#![forbid(unsafe_code)]
//! Descriptor-anchored Linux inputs. No user-controlled symlink is traversed.
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_PATH_COMPONENTS: usize = 128;
const O_PATH: i32 = 0x200000;
const O_NOFOLLOW: i32 = 0x20000;
const O_DIRECTORY: i32 = 0x10000;

fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
pub(crate) fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
}

/// Pin a metadata-only handle after lstat; never open a device or FIFO for I/O.
pub(crate) fn pin(path: &Path) -> io::Result<File> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
        return Err(invalid());
    }
    let parts: Vec<_> = path.components().collect();
    if parts.len() > MAX_PATH_COMPONENTS
        || parts
            .iter()
            .any(|p| matches!(p, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(invalid());
    }
    let names: Vec<_> = parts
        .iter()
        .filter_map(|p| {
            if let Component::Normal(n) = p {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    let (leaf, ancestors) = names.split_last().ok_or_else(invalid)?;
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW | O_DIRECTORY)
        .open(if path.is_absolute() { "/" } else { "." })?;
    for (name, directory) in ancestors
        .iter()
        .map(|n| (*n, true))
        .chain(std::iter::once((*leaf, false)))
    {
        let child = fd_path(&parent).join(name);
        let before = fs::symlink_metadata(&child)?;
        if before.file_type().is_symlink() || (directory && !before.is_dir()) {
            return Err(invalid());
        }
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH | O_NOFOLLOW | if directory { O_DIRECTORY } else { 0 })
            .open(child)?;
        if !same(&before, &opened.metadata()?) {
            return Err(invalid());
        }
        parent = opened;
    }
    Ok(parent)
}

/// Return a regular readable descriptor with a caller's named byte cap.
pub fn regular(path: &Path, cap: u64) -> io::Result<File> {
    let pinned = pin(path)?;
    let meta = pinned.metadata()?;
    if !meta.is_file() || meta.len() > cap {
        return Err(invalid());
    }
    let readable = File::open(fd_path(&pinned))?;
    if !same(&meta, &readable.metadata()?) {
        return Err(invalid());
    }
    Ok(readable)
}

/// Pin a directory for private fixture publication. All ancestors are checked
/// without following symlinks, and callers operate through the held descriptor.
pub fn private_directory(path: &Path) -> io::Result<File> {
    let pinned = pin(path)?;
    let meta = pinned.metadata()?;
    if !meta.is_dir() || meta.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let directory = File::open(fd_path(&pinned))?;
    if !same(&meta, &directory.metadata()?) {
        return Err(invalid());
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inputs_refuse_symlink_ancestors_and_cap_regular_reads() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::write(parent.join("input"), b"1234").unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&parent, &link).unwrap();
        assert!(regular(&link.join("input"), 4).is_err());
        assert!(regular(&parent.join("input"), 3).is_err());
        let mut input = regular(&parent.join("input"), 4).unwrap();
        use std::io::Read;
        let mut actual = String::new();
        input.read_to_string(&mut actual).unwrap();
        assert_eq!(actual, "1234");
    }
}
