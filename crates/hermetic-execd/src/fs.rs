//! No-follow, descriptor-relative guest filesystem access.
use crate::*;
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    io::Write,
    os::fd::{AsRawFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

pub(crate) const SEALED_SHELL: &str = "/bin/bash";

/// Pinned before any guest command runs; a later mount covering /proc cannot
/// redirect internal process metadata, descriptor reopens, or helper execution.
pub struct Proc {
    pub(crate) dir: OwnedFd,
    process: OwnedFd,
    pub(crate) fds: OwnedFd,
}
impl Proc {
    fn open() -> Result<Self> {
        let dir = fs::openat2(
            fs::CWD,
            "/proc",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?;
        if fs::fstatfs(&dir)?.f_type != fs::PROC_SUPER_MAGIC {
            return Err(Error::Boot);
        }
        let process = fs::openat(
            &dir,
            rustix::process::getpid().as_raw_nonzero().to_string(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let fds = fs::openat(
            &process,
            "fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { dir, process, fds })
    }
    pub(crate) fn reopen(&self, pinned: &OwnedFd, flags: OFlags) -> std::io::Result<File> {
        // Only this kernel-generated magic link is followed, relative to the
        // retained proc descriptor, never through the mutable guest root.
        Ok(fs::openat(
            &self.fds,
            pinned.as_raw_fd().to_string(),
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into())
    }
    pub(crate) fn executable(&self) -> Result<File> {
        let file = File::from(fs::openat(
            &self.process,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if !file.metadata()?.is_file() {
            return Err(Error::Boot);
        }
        Ok(file)
    }
    pub(crate) fn children(&self) -> Result<Vec<u8>> {
        let path = format!(
            "task/{}/children",
            rustix::process::getpid().as_raw_nonzero()
        );
        let fd = fs::openat2(
            &self.process,
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        read_capped(File::from(fd), MAX_CHILDREN_BYTES)
    }
}

pub struct Root {
    dir: OwnedFd,
    pub(crate) proc: Rc<Proc>,
    sequence: u64,
}
impl Root {
    pub fn new(dir: OwnedFd) -> Result<Self> {
        if fs::FileType::from_raw_mode(fs::fstat(&dir)?.st_mode) != fs::FileType::Directory {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            dir,
            proc: Rc::new(Proc::open()?),
            sequence: 0,
        })
    }
    pub(crate) fn reroot(&self, dir: OwnedFd) -> Result<Self> {
        if fs::FileType::from_raw_mode(fs::fstat(&dir)?.st_mode) != fs::FileType::Directory {
            return Err(Error::Boot);
        }
        Ok(Self {
            dir,
            proc: self.proc.clone(),
            sequence: 0,
        })
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
        let pinned = self.node(path, fs::FileType::RegularFile)?;
        self.regular_pinned(pinned)
    }
    fn regular_pinned(&self, pinned: OwnedFd) -> Result<File> {
        if fs::FileType::from_raw_mode(fs::fstat(&pinned)?.st_mode) != fs::FileType::RegularFile {
            return Err(Error::InvalidInput);
        }
        // Ordinary files may only come from local guest storage. In particular,
        // procfs regular-looking streams such as kmsg must never be opened.
        match fs::fstatfs(&pinned)?.f_type as u64 {
            0xef53 | 0x01021994 | 0x794c7630 => {} // ext4, tmpfs, overlayfs
            _ => return Err(Error::InvalidInput),
        }
        Ok(self
            .proc
            .reopen(&pinned, OFlags::RDONLY | OFlags::NONBLOCK)?)
    }
    pub(crate) fn sealed_shell(&self) -> Result<File> {
        self.regular_pinned(self.image_node(SEALED_SHELL)?)
    }
    fn image_node(&self, path: &str) -> Result<OwnedFd> {
        spec::path(path)?;
        // IN_ROOT resolves absolute links and '..' within the held image, never
        // the caller's filesystem root. The kernel bounds expansion by PATH_MAX
        // and MAXSYMLINKS; magic links (including proc descriptor links) fail.
        // O_PATH pins without opening a FIFO/device for I/O. Inspect that inode
        // before its data open, then reopen only through the retained proc fd.
        // Mounted runtime storage is not part of the sealed image either.
        Ok(fs::openat2(
            &self.dir,
            relative(path),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
        )?)
    }
    pub fn read(&self, path: &str, cap: usize) -> Result<Vec<u8>> {
        read_file_capped(
            self.regular(path)?,
            cap,
            Instant::now() + Duration::from_millis(FILE_IO_TIMEOUT_MS),
        )
    }
    pub fn atomic(&mut self, path: &str, data: &[u8], clock: i64) -> Result<()> {
        self.atomic_as(path, data, clock, None, Mode::RUSR | Mode::WUSR)
    }
    pub fn atomic_as(
        &mut self,
        path: &str,
        data: &[u8],
        clock: i64,
        owner: Option<(rustix::process::Uid, rustix::process::Gid)>,
        mode: Mode,
    ) -> Result<()> {
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
        let mut created = None;
        for _ in 0..MAX_UPLOAD_ATTEMPTS {
            self.sequence = self.sequence.checked_add(1).ok_or(Error::Limit)?;
            let temp = format!(".hermetic-upload-{}", self.sequence);
            if temp == name {
                continue;
            }
            match fs::openat(
                &parent,
                temp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    created = Some((temp, fd));
                    break;
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let (temp, fd) = created.ok_or(Error::Limit)?;
        let mut file = File::from(fd);
        let result = (|| {
            file.write_all(data)?;
            if let Some((uid, gid)) = owner {
                fs::fchown(&file, Some(uid), Some(gid))?;
            }
            fs::fchmod(&file, mode)?;
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

fn read_file_capped(mut file: impl Read, cap: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let bound = cap.checked_add(1).ok_or(Error::Limit)?;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let mut buffer = [0; IO_BUFFER];
        let wanted = buffer.len().min(bound.saturating_sub(bytes.len()));
        let result = file.read(buffer.get_mut(..wanted).ok_or(Error::Io)?);
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        match result {
            Ok(0) => return Ok(bytes),
            Ok(n) => {
                bytes.extend_from_slice(buffer.get(..n).ok_or(Error::Io)?);
                if bytes.len() > cap {
                    return Err(Error::Limit);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Err(Error::Timeout),
            Err(e) => return Err(e.into()),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn sealed_shell_resolves_image_links_and_pins_the_inode() {
        for target in ["usr/bin", "/usr/bin"] {
            let image = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(image.path().join("usr/bin")).unwrap();
            std::fs::create_dir(image.path().join("usr/lib")).unwrap();
            std::fs::write(image.path().join("usr/lib/shell"), b"sealed shell").unwrap();
            symlink("../lib/shell", image.path().join("usr/bin/bash")).unwrap();
            symlink(target, image.path().join("bin")).unwrap();
            let mut root = Root::open_root(image.path().to_str().unwrap()).unwrap();
            let shell = root.sealed_shell().unwrap();
            assert!(root.regular(SEALED_SHELL).is_err());
            assert!(root.read(SEALED_SHELL, MAX_STRING).is_err());
            assert!(root.atomic(SEALED_SHELL, b"attack", 1).is_err());
            std::fs::rename(
                image.path().join("usr/lib/shell"),
                image.path().join("original"),
            )
            .unwrap();
            std::fs::write(image.path().join("usr/lib/shell"), b"replacement").unwrap();
            assert_eq!(read_capped(shell, MAX_STRING).unwrap(), b"sealed shell");
        }
    }

    #[test]
    fn sealed_shell_hostile_links_never_open_host_or_special_files() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("sentinel"), b"outside secret").unwrap();
        let absolute = outside.path().join("sentinel").to_str().unwrap().to_owned();
        let relative = format!("../../{}", absolute.trim_start_matches('/'));
        for target in [
            absolute.as_str(),
            relative.as_str(),
            "/proc/self/exe",
            "/dev/null",
            "bash",
            "missing",
            "/",
        ] {
            let image = tempfile::tempdir().unwrap();
            std::fs::create_dir(image.path().join("bin")).unwrap();
            symlink(target, image.path().join("bin/bash")).unwrap();
            let root = Root::open_root(image.path().to_str().unwrap()).unwrap();
            assert!(root.sealed_shell().is_err(), "{target}");
        }
        // Absolute and parent-relative targets must resolve against the held
        // image even when the same target also names a real host file.
        for target in [absolute.as_str(), relative.as_str()] {
            let image = tempfile::tempdir().unwrap();
            std::fs::create_dir(image.path().join("bin")).unwrap();
            let guest_target = image.path().join(absolute.trim_start_matches('/'));
            std::fs::create_dir_all(guest_target.parent().unwrap()).unwrap();
            std::fs::write(guest_target, b"image file").unwrap();
            symlink(target, image.path().join("bin/bash")).unwrap();
            let root = Root::open_root(image.path().to_str().unwrap()).unwrap();
            assert_eq!(
                read_capped(root.sealed_shell().unwrap(), MAX_STRING).unwrap(),
                b"image file"
            );
        }
        let image = tempfile::tempdir().unwrap();
        std::fs::create_dir(image.path().join("bin")).unwrap();
        fs::mknodat(
            fs::CWD,
            image.path().join("fifo"),
            fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        symlink("/fifo", image.path().join("bin/bash")).unwrap();
        let root = Root::open_root(image.path().to_str().unwrap()).unwrap();
        assert!(root.sealed_shell().is_err());
        let device = fs::open("/dev/null", OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert!(root.regular_pinned(device).is_err());
        assert_eq!(
            std::fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside secret"
        );
    }

    #[test]
    fn sealed_shell_link_expansion_is_bounded() {
        const KERNEL_MAXSYMLINKS: usize = 40;
        for count in [KERNEL_MAXSYMLINKS, KERNEL_MAXSYMLINKS + 1] {
            let image = tempfile::tempdir().unwrap();
            std::fs::create_dir(image.path().join("bin")).unwrap();
            std::fs::write(image.path().join("bin/shell"), b"sealed shell").unwrap();
            for index in 0..count {
                let name = if index == 0 {
                    "bash".into()
                } else {
                    format!("link-{index}")
                };
                let next = if index + 1 == count {
                    "shell".into()
                } else {
                    format!("link-{}", index + 1)
                };
                symlink(next, image.path().join("bin").join(name)).unwrap();
            }
            let root = Root::open_root(image.path().to_str().unwrap()).unwrap();
            if count == KERNEL_MAXSYMLINKS {
                assert_eq!(
                    read_capped(root.sealed_shell().unwrap(), MAX_STRING).unwrap(),
                    b"sealed shell"
                );
            } else {
                assert!(root.sealed_shell().is_err());
            }
        }
    }

    #[test]
    fn sealed_image_lookup_refuses_runtime_mounts_and_proc_magic_links() {
        // Root::new has verified that /proc is procfs, so this is an actual
        // mount boundary, with no mount privileges required for the test.
        let root = Root::open_root("/").unwrap();
        assert!(root.image_node("/proc").is_err());
        let proc = root
            .reroot(rustix::io::dup(&root.proc.dir).unwrap())
            .unwrap();
        assert!(proc.image_node("/self/exe").is_err());
        assert!(proc.image_node("/self/root").is_err());
    }
    #[test]
    fn pinned_proc_reopens_work_when_visible_proc_opens_are_denied() {
        const CHILD: &str = "HERMETIC_TEST_PINNED_PROC";
        if let Some(path) = std::env::var_os(CHILD) {
            let path = std::path::PathBuf::from(path);
            std::fs::write(path.join("file"), b"original").unwrap();
            let root = Root::open_root(path.to_str().unwrap()).unwrap();
            let pinned = root.node("/file", fs::FileType::RegularFile).unwrap();
            std::fs::rename(path.join("file"), path.join("old")).unwrap();
            std::fs::write(path.join("file"), b"substitute").unwrap();
            crate::sys::deny_cwd_opens().unwrap();
            assert!(File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd())).is_err());
            let original = root.proc.reopen(&pinned, OFlags::RDONLY).unwrap();
            assert_eq!(read_capped(original, 100).unwrap(), b"original");
            // Also exercise the public transfer path, which must use the same
            // retained proc handles rather than rediscover visible /proc.
            assert_eq!(root.read("/file", 100).unwrap(), b"substitute");
            let rerooted = root.reroot(root.directory("/").unwrap()).unwrap();
            assert!(Rc::ptr_eq(&root.proc, &rerooted.proc));
            assert_eq!(rerooted.read("/old", 100).unwrap(), b"original");
            // TempDir cleanup also uses paths; leave it to the parent fixture
            // rather than attempting forbidden opens under this test filter.
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fs::tests::pinned_proc_reopens_work_when_visible_proc_opens_are_denied",
                "--nocapture",
            ])
            .env_clear()
            .env(CHILD, temp.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn file_read_caps_deadlines_and_nonblocking_failures() {
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            read_file_capped(b"abc".as_slice(), 3, deadline).unwrap(),
            b"abc"
        );
        assert_eq!(
            read_file_capped(b"abcd".as_slice(), 3, deadline),
            Err(Error::Limit)
        );
        assert_eq!(read_file_capped(b"".as_slice(), 0, deadline).unwrap(), b"");
        assert_eq!(
            read_file_capped(b"a".as_slice(), 0, deadline),
            Err(Error::Limit)
        );
        assert_eq!(
            read_file_capped(b"a".as_slice(), usize::MAX, deadline),
            Err(Error::Limit)
        );
        assert_eq!(
            read_file_capped(b"abc".as_slice(), 3, Instant::now()),
            Err(Error::Timeout)
        );
        struct Retry(std::io::ErrorKind);
        impl Read for Retry {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(self.0.into())
            }
        }
        assert_eq!(
            read_file_capped(Retry(std::io::ErrorKind::WouldBlock), 10, deadline),
            Err(Error::Timeout)
        );
        assert_eq!(
            read_file_capped(
                Retry(std::io::ErrorKind::Interrupted),
                10,
                Instant::now() + Duration::from_millis(10)
            ),
            Err(Error::Timeout)
        );
    }
}
