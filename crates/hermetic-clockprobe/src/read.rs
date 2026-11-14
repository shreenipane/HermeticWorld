//! Read-only Linux guest inspection. Every pathname is resolved from a pinned
//! directory descriptor. Only the internally constructed /proc/self/fd link is
//! followed by the OS; external symlinks are expanded within the selected root.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_COMPONENTS: usize = 64;
pub const MAX_SYMLINKS: usize = 32;
/// Bounded, but above a lockdown guest's /dev: 256 legacy PTY pairs alone are 512 nodes.
pub const MAX_DIR_ENTRIES: usize = 4096;
// Linux x86_64 UAPI asm-generic/fcntl.h. No arbitrary devices are opened.
const O_NOFOLLOW: i32 = 0o400000;
const O_DIRECTORY: i32 = 0o200000;
const O_NONBLOCK: i32 = 0o4000;
const O_PATH: i32 = 0o10000000;

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
fn descriptor(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn same(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev() && before.ino() == after.ino() && before.mode() == after.mode()
}

fn open_checked(path: &Path, directory: bool, device: Option<u64>) -> io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    let acceptable = |m: &Metadata| {
        if directory {
            m.is_dir()
        } else if let Some(rdev) = device {
            m.file_type().is_char_device() && m.rdev() == rdev
        } else {
            m.is_file()
        }
    };
    if !acceptable(&before) {
        return Err(invalid());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW | if directory { O_DIRECTORY } else { 0 })
        .open(path)?;
    let after = file.metadata()?;
    if !acceptable(&after) || !same(&before, &after) {
        return Err(invalid());
    }
    if directory {
        return Ok(file);
    }
    // O_PATH cannot activate a substituted FIFO/device. Only after descriptor
    // validation do we reopen this pinned object through our own descriptor.
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(descriptor(&file))
}

pub struct Root {
    dir: File,
}
impl Root {
    pub fn new(path: &Path) -> io::Result<Self> {
        // Pin each ancestor, rejecting symlinked roots rather than canonicalizing.
        if !path.is_absolute() || path.as_os_str().len() > MAX_PATH_BYTES {
            return Err(invalid());
        }
        let mut dir = open_checked(Path::new("/"), true, None)?;
        let mut count = 0;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    count += 1;
                    if count > MAX_COMPONENTS {
                        return Err(invalid());
                    }
                    dir = open_checked(&descriptor(&dir).join(name), true, None)?;
                }
                _ => return Err(invalid()),
            }
        }
        Ok(Self { dir })
    }
    fn parts(path: &Path) -> io::Result<VecDeque<std::ffi::OsString>> {
        if path.as_os_str().len() > MAX_PATH_BYTES || path.is_absolute() {
            return Err(invalid());
        }
        let mut parts = VecDeque::new();
        for c in path.components() {
            match c {
                Component::Normal(n) => parts.push_back(n.to_owned()),
                Component::ParentDir => parts.push_back("..".into()),
                Component::CurDir => {}
                _ => return Err(invalid()),
            }
            if parts.len() > MAX_COMPONENTS {
                return Err(invalid());
            }
        }
        Ok(parts)
    }
    fn resolve(&self, path: &str) -> io::Result<(File, PathBuf)> {
        let mut parts = Self::parts(Path::new(path))?;
        let mut parents = vec![self.dir.try_clone()?];
        let mut links = 0;
        let mut steps = 0;
        while let Some(part) = parts.pop_front() {
            steps += 1;
            if steps > MAX_COMPONENTS * (MAX_SYMLINKS + 1) {
                return Err(invalid());
            }
            if part == ".." {
                if parents.len() <= 1 {
                    return Err(invalid());
                }
                parents.pop();
                continue;
            }
            let parent = parents.last().ok_or_else(invalid)?;
            let at = descriptor(parent).join(&part);
            let meta = fs::symlink_metadata(&at)?;
            if meta.file_type().is_symlink() {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(invalid());
                }
                let target = fs::read_link(&at)?;
                let mut expanded = Self::parts(&target)?;
                expanded.extend(parts);
                if expanded.len() > MAX_COMPONENTS {
                    return Err(invalid());
                }
                parts = expanded;
            } else if parts.is_empty() {
                return Ok((parent.try_clone()?, PathBuf::from(part)));
            } else {
                if parents.len() >= MAX_COMPONENTS {
                    return Err(invalid());
                }
                parents.push(open_checked(&at, true, None)?);
            }
        }
        Ok((
            parents.last().ok_or_else(invalid)?.try_clone()?,
            PathBuf::from("."),
        ))
    }
    pub fn open(&self, path: &str) -> io::Result<File> {
        let (parent, name) = self.resolve(path)?;
        open_checked(&descriptor(&parent).join(name), false, None)
    }
    pub fn device(&self, path: &str, rdev: u64) -> io::Result<File> {
        let (parent, name) = self.resolve(path)?;
        open_checked(&descriptor(&parent).join(name), false, Some(rdev))
    }
    pub fn present(&self, path: &str) -> io::Result<bool> {
        match self.resolve(path) {
            Ok((parent, name)) => {
                fs::symlink_metadata(descriptor(&parent).join(name)).map(|_| true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn text(&self, path: &str, cap: u64) -> io::Result<String> {
        read_text(self.open(path)?, cap)
    }
    pub fn list(&self, path: &str) -> io::Result<Vec<String>> {
        let (parent, name) = self.resolve(path)?;
        let dir = open_checked(&descriptor(&parent).join(name), true, None)?;
        let mut names = Vec::new();
        for entry in fs::read_dir(descriptor(&dir))?.take(MAX_DIR_ENTRIES + 1) {
            if names.len() == MAX_DIR_ENTRIES {
                return Err(invalid());
            }
            let name = entry?.file_name().into_string().map_err(|_| invalid())?;
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
}

pub fn read_text(file: File, cap: u64) -> io::Result<String> {
    let limit = cap.checked_add(1).ok_or_else(invalid)?;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| invalid())? > cap {
        return Err(invalid());
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
