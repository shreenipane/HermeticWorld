#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub const MAX_PATH_COMPONENTS: usize = 128;
pub const MAX_PATH_BYTES: usize = 8192;

pub fn invalid() -> io::Error {
    io::Error::other("invalid or unsupported filesystem entry")
}

pub fn normalize_path(path: &Path) -> PathBuf {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    let mut out = PathBuf::new();
    for comp in base.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir) => {}
                _ => {
                    out.push(comp.as_os_str());
                }
            },
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// Linux descriptor paths pin each directory while resolving a single child.
/// O_NOFOLLOW protects the child; O_NONBLOCK prevents a raced FIFO from blocking.
#[derive(Clone, Debug)]
pub struct Directory(Arc<File>);

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(test)]
        if FAIL_OPEN.get() {
            return Err(io::Error::other("directory open failed"));
        }
        if path.as_os_str().len() > MAX_PATH_BYTES {
            return Err(invalid());
        }
        let norm = normalize_path(path);
        let mut dir = Self(Arc::new(File::open(if norm.is_absolute() {
            "/"
        } else {
            "."
        })?));
        for (count, part) in norm.components().enumerate() {
            if count >= MAX_PATH_COMPONENTS {
                return Err(invalid());
            }
            match part {
                Component::RootDir | Component::CurDir => (),
                Component::Normal(name) => dir = dir.child_dir(Path::new(name))?,
                _ => return Err(invalid()),
            }
        }
        Ok(dir)
    }

    pub fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
    }

    pub fn path(&self, name: &Path) -> io::Result<PathBuf> {
        let mut parts = name.components();
        if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
            return Err(invalid());
        }
        Ok(self.descriptor_path().join(name))
    }

    fn child_dir(&self, name: &Path) -> io::Result<Self> {
        let path = self.path(name)?;
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(invalid());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(invalid());
        }
        Ok(Self(Arc::new(file)))
    }

    pub fn create(path: &Path) -> io::Result<Self> {
        match Self::open(path) {
            Ok(dir) => Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let parent = Self::open(
                    path.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                )?;
                let name = path.file_name().ok_or_else(invalid)?;
                fs::create_dir(parent.path(Path::new(name))?)?;
                parent.child_dir(Path::new(name))
            }
            Err(e) => Err(e),
        }
    }

    pub fn parent(&self, relative: &Path) -> io::Result<(Self, PathBuf)> {
        if relative.as_os_str().len() > MAX_PATH_BYTES {
            return Err(invalid());
        }
        let mut dir = self.clone();
        let mut parts = relative.components().peekable();
        let mut count = 0usize;
        while let Some(part) = parts.next() {
            count = count.checked_add(1).ok_or_else(invalid)?;
            if count > MAX_PATH_COMPONENTS {
                return Err(invalid());
            }
            let Component::Normal(name) = part else {
                return Err(invalid());
            };
            if parts.peek().is_none() {
                return Ok((dir, PathBuf::from(name)));
            }
            dir = dir.child_dir(Path::new(name))?;
        }
        Err(invalid())
    }

    pub fn open_file(&self, relative: &Path, write: bool, create: bool) -> io::Result<File> {
        self.open_file_hook(relative, write, create, || {})
    }

    fn open_file_hook(
        &self,
        relative: &Path,
        write: bool,
        create: bool,
        hook: impl FnOnce(),
    ) -> io::Result<File> {
        let (parent, name) = self.parent(relative)?;
        let path = parent.path(&name)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err(invalid()),
            Ok(_) => (),
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        hook();
        let file = OpenOptions::new()
            .read(true)
            .append(write)
            .create_new(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        Ok(file)
    }

    pub fn read(&self, name: &Path, cap: u64) -> io::Result<Vec<u8>> {
        let file = self.open_file(name, false, false)?;
        if file.metadata()?.len() > cap {
            return Err(invalid());
        }
        let mut data = Vec::new();
        file.take(cap.checked_add(1).ok_or_else(invalid)?)
            .read_to_end(&mut data)?;
        if data.len() as u64 > cap {
            return Err(invalid());
        }
        Ok(data)
    }

    pub fn sync(&self) -> io::Result<()> {
        #[cfg(test)]
        sync_failure()?;
        self.0.sync_all()
    }

    pub fn atomic_write(&self, name: &Path, temp: &Path, data: &[u8]) -> io::Result<()> {
        // Check the destination before creating any temporary artifact.
        let destination = self.path(name)?;
        match fs::symlink_metadata(&destination) {
            Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err(invalid()),
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let temporary = self.path(temp)?;
        let mut file = self.open_file(temp, true, true)?;
        let result = (|| {
            file.write_all(data)?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            self.sync()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_OPEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn sync_failure() -> io::Result<()> {
    if FAIL_SYNC.get() {
        Err(io::Error::other("directory sync failed"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn checked_file_and_ancestor_swaps_never_escape_or_block() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::write(root.join("a/f"), b"inside").unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"secret").unwrap();
        let dir = Directory::open(&root).unwrap();
        assert!(dir
            .open_file_hook(Path::new("a/f"), false, false, || {
                fs::remove_file(root.join("a/f")).unwrap();
                symlink(&outside, root.join("a/f")).unwrap();
            })
            .is_err());
        fs::remove_file(root.join("a/f")).unwrap();
        fs::write(root.join("a/f"), b"inside").unwrap();
        let mut file = dir
            .open_file_hook(Path::new("a/f"), false, false, || {
                fs::rename(root.join("a"), root.join("old")).unwrap();
                symlink(temp.path(), root.join("a")).unwrap();
            })
            .unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "inside");
        assert!(dir
            .open_file_hook(Path::new("old/f"), false, false, || {
                fs::remove_file(root.join("old/f")).unwrap();
                assert!(std::process::Command::new("mkfifo")
                    .arg(root.join("old/f"))
                    .status()
                    .unwrap()
                    .success());
            })
            .is_err());
    }

    #[test]
    fn directory_open_failure_is_propagated_by_finalization_and_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let writer = File::create(temp.path().join("requests.log")).unwrap();
        let mut log = crate::log::LogManager::new_with_writer(temp.path(), writer);
        FAIL_OPEN.set(true);
        assert!(log.finish().is_err());
        assert!(
            crate::log::verify_log_recover(temp.path().join("requests.log"), false, true).is_err()
        );
        FAIL_OPEN.set(false);
        assert!(!temp.path().join("requests.log.head").exists());
    }

    #[test]
    fn directory_sync_failure_is_propagated_by_finalization_and_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let mut log = crate::log::LogManager::new(temp.path()).unwrap();
        FAIL_SYNC.set(true);
        assert!(log.finish().is_err());
        // Recovery also publishes through the same checked directory sync.
        assert!(
            crate::log::verify_log_recover(temp.path().join("requests.log"), false, true).is_err()
        );
        FAIL_SYNC.set(false);
    }
}
