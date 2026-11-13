//! Bounded Linux file I/O with inspected, pinned handles for every path component.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub const MAX_PATH_COMPONENTS: usize = 256;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_DIRECTORY_ENTRIES: usize = 10_000;
pub const MAX_TREE_ENTRIES: usize = 100_000;
pub const MAX_TREE_DEPTH: usize = 64;
pub const MAX_TREE_BYTES: u64 = 256 * 1024 * 1024;
// Linux open(2) ABI. O_PATH pins even a device without opening the device driver.
const O_PATH: i32 = 0o10000000;
const O_NOFOLLOW: i32 = 0o400000;
const O_DIRECTORY: i32 = 0o200000;
const O_NONBLOCK: i32 = 0o4000;

fn refused() -> io::Error {
    io::Error::other("unsafe or changed filesystem object")
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
}

fn proc_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn pin_child(parent: &File, name: &Path, directory: bool) -> io::Result<File> {
    let path = proc_path(parent).join(name);
    let before = std::fs::symlink_metadata(&path)?;
    if directory && !before.is_dir() {
        return Err(refused());
    }
    let pinned = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW | if directory { O_DIRECTORY } else { 0 })
        .open(&path)?;
    if !same(&before, &pinned.metadata()?) {
        return Err(refused());
    }
    Ok(pinned)
}

fn parent(path: &Path) -> io::Result<(File, PathBuf)> {
    use std::os::unix::ffi::OsStrExt;
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(refused());
    }
    let mut names = Vec::new();
    for part in path.components() {
        match part {
            Component::Normal(name) => names.push(PathBuf::from(name)),
            Component::RootDir | Component::CurDir => {}
            _ => return Err(refused()),
        }
        if names.len() > MAX_PATH_COMPONENTS {
            return Err(refused());
        }
    }
    let leaf = names.pop().unwrap_or_else(|| PathBuf::from("."));
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_DIRECTORY)
        .open(if path.is_absolute() { "/" } else { "." })?;
    for name in names {
        dir = pin_child(&dir, &name, true)?;
    }
    Ok((dir, leaf))
}

pub fn metadata(path: &Path) -> io::Result<Metadata> {
    let (dir, leaf) = parent(path)?;
    std::fs::symlink_metadata(proc_path(&dir).join(leaf))
}

pub fn read_link(path: &Path) -> io::Result<PathBuf> {
    let (dir, leaf) = parent(path)?;
    std::fs::read_link(proc_path(&dir).join(leaf))
}

pub fn open_regular(path: &Path) -> io::Result<File> {
    if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(refused());
    }
    // An explicitly inherited descriptor is a capability supplied by the caller,
    // not a filesystem symlink in the world. The rootfs builder hands off its
    // unpublished image this way. Only the kernel-owned, numeric self/fd form
    // is accepted; pin it before inspecting or opening the underlying inode.
    if path.parent() == Some(Path::new("/proc/self/fd")) {
        let number = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<i32>().ok())
            .ok_or_else(refused)?;
        let pinned = OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH)
            .open(format!("/proc/self/fd/{number}"))?;
        return readable_pinned(pinned);
    }
    let (dir, leaf) = parent(path)?;
    let pinned = pin_child(&dir, &leaf, false)?;
    readable_pinned(pinned)
}

fn readable_pinned(pinned: File) -> io::Result<File> {
    let meta = pinned.metadata()?;
    if !meta.is_file() {
        return Err(refused());
    }
    let readable = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(proc_path(&pinned))?;
    if !same(&meta, &readable.metadata()?) {
        return Err(refused());
    }
    Ok(readable)
}

pub fn read(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    read_counted(path, cap, &mut 0)
}

pub fn read_counted(path: &Path, cap: u64, consumed: &mut u64) -> io::Result<Vec<u8>> {
    let mut file = open_regular(path)?;
    read_open(&mut file, cap, consumed)
}

pub(crate) fn read_open(file: &mut File, cap: u64, consumed: &mut u64) -> io::Result<Vec<u8>> {
    if file.metadata()?.len() > cap {
        return Err(io::Error::other("file byte cap exceeded"));
    }
    read_stream(file, cap, consumed)
}

fn read_stream(reader: impl Read, cap: u64, consumed: &mut u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let result = reader.take(cap.saturating_add(1)).read_to_end(&mut bytes);
    *consumed = consumed.saturating_add(bytes.len() as u64);
    result?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::other("file byte cap exceeded"));
    }
    Ok(bytes)
}

pub fn read_dir(path: &Path) -> io::Result<Vec<PathBuf>> {
    let (dir, leaf) = parent(path)?;
    let pinned = pin_child(&dir, &leaf, true)?;
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(proc_path(&pinned))? {
        if entries.len() >= MAX_DIRECTORY_ENTRIES {
            return Err(io::Error::other("directory entry cap exceeded"));
        }
        entries.push(path.join(entry?.file_name()));
    }
    entries.sort();
    Ok(entries)
}

pub fn is_dir(path: &Path) -> bool {
    metadata(path).is_ok_and(|m| m.is_dir())
}

pub fn is_file(path: &Path) -> bool {
    metadata(path).is_ok_and(|m| m.is_file())
}

/// A sorted, capped walk. Excluded entries and subtrees are never returned or
/// listed. Each directory listing uses a pinned handle.
pub fn walk(root: &Path, descend: impl Fn(&Path) -> bool) -> Vec<io::Result<PathBuf>> {
    let mut output = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut scheduled = 1usize;
    while let Some((path, depth)) = stack.pop() {
        if !descend(&path) {
            continue;
        }
        let meta = match metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                output.push(Err(e));
                continue;
            }
        };
        if meta.is_dir() {
            if depth >= MAX_TREE_DEPTH {
                output.push(Err(io::Error::other("tree depth cap exceeded")));
                break;
            }
            match read_dir(&path) {
                Ok(entries) => {
                    scheduled = scheduled.saturating_add(entries.len());
                    if scheduled > MAX_TREE_ENTRIES {
                        output.push(Err(io::Error::other("tree entry cap exceeded")));
                        break;
                    }
                    stack.extend(entries.into_iter().rev().map(|p| (p, depth + 1)));
                }
                Err(e) => output.push(Err(e)),
            }
        }
        output.push(Ok(path));
    }
    output
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (dir, leaf) = parent(path)?;
    let pinned_dir = proc_path(&dir);
    let destination = pinned_dir.join(leaf);
    match std::fs::symlink_metadata(&destination) {
        Ok(m) if !m.is_file() => return Err(refused()),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&pinned_dir)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(destination).map_err(|e| e.error)?;
    File::open(pinned_dir)?.sync_all()
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn partial_failed_reads_consume_the_tree_budget() {
        struct FailingReader(bool);
        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("injected read failure"));
                }
                let count = buffer.len().min(3);
                buffer
                    .get_mut(..count)
                    .unwrap()
                    .copy_from_slice(&b"abc"[..count]);
                self.0 = true;
                Ok(count)
            }
        }
        let mut consumed = 1;
        assert!(read_stream(FailingReader(false), 4, &mut consumed).is_err());
        assert_eq!(consumed, 4);
    }
}
