//! No-follow, descriptor-relative guest filesystem access.
use crate::*;
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use std::{fs::File, io::Write, os::fd::OwnedFd};

pub struct Root {
    dir: OwnedFd,
    sequence: u64,
}
impl Root {
    pub fn new(dir: OwnedFd) -> Result<Self> {
        if fs::FileType::from_raw_mode(fs::fstat(&dir)?.st_mode) != fs::FileType::Directory {
            return Err(Error::InvalidInput);
        }
        Ok(Self { dir, sequence: 0 })
    }
    pub fn open_root(path: &str) -> Result<Self> {
        Self::new(fs::openat2(
            fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?)
    }
    pub fn directory(&self, path: &str) -> Result<OwnedFd> {
        spec::path(path)?;
        Ok(fs::openat2(
            &self.dir,
            relative(path),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?)
    }
    fn parent(&self, path: &str) -> Result<(OwnedFd, String)> {
        spec::path(path)?;
        let (dir, name) = path.rsplit_once('/').ok_or(Error::InvalidInput)?;
        if name.is_empty() {
            return Err(Error::InvalidInput);
        }
        Ok((
            self.directory(if dir.is_empty() { "/" } else { dir })?,
            name.into(),
        ))
    }
    pub fn node(&self, path: &str, kind: fs::FileType) -> Result<OwnedFd> {
        let (dir, name) = self.parent(path)?;
        // lstat is advisory; O_NOFOLLOW, O_NONBLOCK and fstat make races safe.
        let before = fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        if fs::FileType::from_raw_mode(before.st_mode) != kind {
            return Err(Error::InvalidInput);
        }
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let after = fs::fstat(&fd)?;
        if fs::FileType::from_raw_mode(after.st_mode) != kind
            || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
        {
            return Err(Error::InvalidInput);
        }
        Ok(fd)
    }
    pub fn regular(&self, path: &str) -> Result<File> {
        use std::os::fd::AsRawFd;
        let pinned = self.node(path, fs::FileType::RegularFile)?;
        // Kernel-owned magic link: the inode was pinned with O_PATH and fstat
        // before any read-capable open, so device replacement cannot be opened.
        Ok(File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?)
    }
    pub fn read(&self, path: &str, cap: usize) -> Result<Vec<u8>> {
        read_capped(self.regular(path)?, cap)
    }
    pub fn atomic(&mut self, path: &str, data: &[u8], clock: i64) -> Result<()> {
        spec::path(path)?;
        if data.len() > MAX_TRANSFER {
            return Err(Error::Limit);
        }
        let (parent, name) = self.parent(path)?;
        match fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if fs::FileType::from_raw_mode(st.st_mode) != fs::FileType::RegularFile => {
                return Err(Error::InvalidInput)
            }
            Err(e) if e != rustix::io::Errno::NOENT => return Err(e.into()),
            _ => {}
        }
        // The new inode is never opened by name after creation. O_EXCL rejects
        // collisions and symlinks. Rename replaces the destination atomically.
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Limit)?;
        let temp = format!(".hermetic-upload-{}", self.sequence);
        let fd = fs::openat(
            &parent,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        let result = (|| {
            file.write_all(data)?;
            stamp(&file, clock)?;
            file.sync_all()?;
            fs::renameat(&parent, temp.as_str(), &parent, name.as_str())?;
            fs::fsync(&parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&parent, temp.as_str(), AtFlags::empty());
        }
        result
    }
}
fn relative(path: &str) -> &str {
    path.strip_prefix('/')
        .filter(|s| !s.is_empty())
        .unwrap_or(".")
}
pub fn stamp(fd: impl std::os::fd::AsFd, clock: i64) -> Result<()> {
    let t = rustix::time::Timespec {
        tv_sec: clock,
        tv_nsec: 0,
    };
    fs::futimens(
        fd,
        &fs::Timestamps {
            last_access: t,
            last_modification: t,
        },
    )?;
    Ok(())
}
