#![forbid(unsafe_code)]
//! Descriptor-pinned filesystem access for the audit log and endpoints.
//!
//! Atomic publication and endpoint reclaim end in `rename(2)`/`unlink(2)`,
//! which act on names, not descriptors. They are therefore only performed in
//! a directory that the held descriptor shows (by `fstat`) to be owned by the
//! server's effective uid and writable by nobody else (`mode & 0o022 == 0`).
//! After that check the only parties able to race those names are the
//! server's own uid and root, both inside the trust boundary.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// Effective uid of this process, read once from `/proc/self/status`.
/// The server calls this before installing the sandbox, which denies `/proc`.
pub fn process_uid() -> io::Result<u32> {
    static UID: OnceLock<u32> = OnceLock::new();
    if let Some(uid) = UID.get() {
        return Ok(*uid);
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|euid| euid.parse::<u32>().ok())
        .ok_or_else(|| io::Error::other("cannot determine effective uid"))?;
    Ok(*UID.get_or_init(|| uid))
}

pub const MAX_PATH_COMPONENTS: usize = 128;
pub const MAX_PATH_BYTES: usize = 8192;
pub const MAX_ATOMIC_WRITE_BYTES: usize = 128 * 1024 * 1024;

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

    /// A separate open description makes ownership exclusive even within one process.
    /// Lock the pinned directory itself: no removable lock pathname or stale artifact.
    pub fn try_lock(&self) -> io::Result<File> {
        let file = File::open(self.descriptor_path())?;
        file.try_lock()
            .map_err(|_| io::Error::other("audit ownership unavailable"))?;
        Ok(file)
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

    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.0.metadata()
    }

    pub fn identity(&self) -> io::Result<DirIdentity> {
        let meta = self.metadata()?;
        Ok(DirIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    pub fn parent_dir(&self) -> io::Result<Self> {
        let path = PathBuf::from(format!("/proc/self/fd/{}/..", self.0.as_raw_fd()));
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(invalid());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        if !file.metadata()?.is_dir() {
            return Err(invalid());
        }
        Ok(Self(Arc::new(file)))
    }

    pub fn create_child_dir(&self, name: &Path) -> io::Result<Self> {
        let path = self.path(name)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Ok(_) => return Err(invalid()),
            Err(e) => return Err(e),
        }
        // Private from creation, so it qualifies for name-based publication.
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        self.child_dir(name)
    }

    pub fn create(path: &Path) -> io::Result<Self> {
        LogTarget::resolve(path)?.into_directory()
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

    pub fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        rustix::fs::renameat_with(
            &*self.0,
            from,
            &*self.0,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }

    pub fn atomic_write(&self, name: &Path, temp: &Path, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_ATOMIC_WRITE_BYTES {
            return Err(invalid());
        }
        // Refuse before any artifact is created or removed.
        self.check_exclusive()?;
        self.validate_atomic_write(name, temp)?;
        // Check the destination before creating any temporary artifact:
        // publication uses renameat2(RENAME_NOREPLACE) and refuses to overwrite an existing destination.
        let destination = self.path(name)?;
        let temporary = self.path(temp)?;

        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("destination '{}' already exists", name.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }

        match fs::symlink_metadata(&temporary) {
            Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err(invalid()),
            Ok(_) => {
                // Safely remove abandoned temporary artifact from a prior crash before recreating.
                fs::remove_file(&temporary)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let mut file = self.open_file(temp, true, true)?;
        let written = file.metadata()?;
        let id = (written.dev(), written.ino());
        #[cfg(test)]
        publication_tests::at_boundary(temp, "created");
        let result = (|| {
            file.write_all(data)?;
            #[cfg(test)]
            publication_tests::at_boundary(temp, "written");
            file.sync_all()?;
            #[cfg(test)]
            publication_tests::at_boundary(temp, "synced");
            // renameat2(RENAME_NOREPLACE) ensures create-exclusive publication.
            // Check temporary entry dev/ino immediately before rename.
            if !entry_is(&temporary, id)? {
                return Err(invalid());
            }
            rustix::fs::renameat_with(
                &self.0,
                temp,
                &self.0,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            if !entry_is(&destination, id)? {
                return Err(invalid());
            }
            self.sync()
        })();
        if result.is_err() && entry_is(&temporary, id).unwrap_or(false) {
            // Remove only the artifact this call created, never a replacement.
            let _ = fs::remove_file(temporary);
        }
        result
    }

    /// Explicit, documented replace path for callers that legitimately replace an existing file
    /// (such as updating dedupe index or head checkpoint).
    ///
    /// Writes to a temporary staging file, syncs, and atomically replaces `name` while
    /// verifying the replaced inode. If a same-uid process attempts to swap or redirect the destination
    /// file before replacement, the mismatch is detected and the operation is refused.
    pub fn atomic_replace(&self, name: &Path, temp: &Path, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_ATOMIC_WRITE_BYTES {
            return Err(invalid());
        }
        self.check_exclusive()?;
        self.validate_atomic_write(name, temp)?;
        let destination = self.path(name)?;
        let temporary = self.path(temp)?;

        match fs::symlink_metadata(&temporary) {
            Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err(invalid()),
            Ok(_) => {
                fs::remove_file(&temporary)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }

        // Record expected destination identity before writing or syncing the staging file.
        let initial_dest_id = match fs::symlink_metadata(&destination) {
            Ok(dest_meta) => {
                if !dest_meta.is_file() || dest_meta.file_type().is_symlink() {
                    return Err(invalid());
                }
                Some((dest_meta.dev(), dest_meta.ino()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };

        let mut file = self.open_file(temp, true, true)?;
        let written = file.metadata()?;
        let id = (written.dev(), written.ino());
        #[cfg(test)]
        publication_tests::at_boundary(temp, "created");
        let result = (|| {
            file.write_all(data)?;
            #[cfg(test)]
            publication_tests::at_boundary(temp, "written");
            file.sync_all()?;
            #[cfg(test)]
            {
                publication_tests::at_boundary(temp, "synced");
                publication_tests::at_boundary(name, "synced");
            }

            if !entry_is(&temporary, id)? {
                return Err(invalid());
            }

            let Some(expected_replaced_id) = initial_dest_id else {
                // Destination did not exist initially: attempt create-exclusive rename.
                rustix::fs::renameat_with(
                    &self.0,
                    temp,
                    &self.0,
                    name,
                    rustix::fs::RenameFlags::NOREPLACE,
                )?;
                if !entry_is(&destination, id)? {
                    return Err(invalid());
                }
                return self.sync();
            };

            #[cfg(test)]
            {
                publication_tests::at_boundary(name, "before_replace");
                publication_tests::at_boundary(temp, "before_replace");
            }

            // RENAME_EXCHANGE atomically swaps temporary and destination.
            rustix::fs::renameat_with(
                &self.0,
                temp,
                &self.0,
                name,
                rustix::fs::RenameFlags::EXCHANGE,
            )?;

            // Verify that what was swapped into temporary is exactly the expected replaced inode.
            let swapped_meta = match fs::symlink_metadata(&temporary) {
                Ok(m) => (m.dev(), m.ino()),
                Err(_) => {
                    let _ = rustix::fs::renameat_with(
                        &self.0,
                        temp,
                        &self.0,
                        name,
                        rustix::fs::RenameFlags::EXCHANGE,
                    );
                    return Err(invalid());
                }
            };

            if swapped_meta != expected_replaced_id {
                // Inode mismatch: the destination was swapped out from under us!
                // Swap back to restore, and refuse.
                let _ = rustix::fs::renameat_with(
                    &self.0,
                    temp,
                    &self.0,
                    name,
                    rustix::fs::RenameFlags::EXCHANGE,
                );
                return Err(invalid());
            }

            // Verify destination now holds our written file.
            if !matches!(entry_is(&destination, id), Ok(true)) {
                let _ = rustix::fs::renameat_with(
                    &self.0,
                    temp,
                    &self.0,
                    name,
                    rustix::fs::RenameFlags::EXCHANGE,
                );
                return Err(invalid());
            }

            // Safely clean up the replaced old inode now in temporary.
            let _ = fs::remove_file(&temporary);

            self.sync()
        })();

        if result.is_err() && entry_is(&temporary, id).unwrap_or(false) {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    /// Name-based operations (publication renames, endpoint reclaim) are only
    /// safe in a directory no other user can modify. `fstat` on the held
    /// descriptor must show a directory owned by this process's effective
    /// uid with no group or other write permission; then only this uid or
    /// root, both trusted, can replace entries in it.
    pub fn check_exclusive(&self) -> io::Result<()> {
        let meta = self.metadata()?;
        let uid = process_uid()?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "directory must be owned by uid {uid} and not writable by group or others \
                     (owner {}, mode {:o})",
                    meta.uid(),
                    meta.mode() & 0o7777
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_atomic_write(&self, name: &Path, temp: &Path) -> io::Result<()> {
        if name == temp {
            return Err(invalid());
        }
        for entry in [name, temp] {
            match fs::symlink_metadata(self.path(entry)?) {
                Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
                    return Err(invalid());
                }
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Whether `path` (never followed) is the single-link regular file `id`.
fn entry_is(path: &Path, id: (u64, u64)) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            Ok(meta.file_type().is_file() && (meta.dev(), meta.ino()) == id && meta.nlink() == 1)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

pub const MAX_ANCESTRY_DEPTH: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DirIdentity {
    pub dev: u64,
    pub ino: u64,
}

pub fn is_descendant_of(descendant: &Directory, target_id: &DirIdentity) -> io::Result<bool> {
    let desc_id = descendant.identity()?;
    if desc_id == *target_id {
        return Ok(true);
    }
    let mut curr = descendant.clone();
    let mut curr_id = desc_id;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let parent = curr.parent_dir()?;
        let parent_id = parent.identity()?;
        if parent_id == *target_id {
            return Ok(true);
        }
        if parent_id == curr_id {
            return Ok(false);
        }
        curr = parent;
        curr_id = parent_id;
    }
    Err(invalid())
}

#[derive(Clone, Debug)]
pub enum LogTarget {
    Existing(Directory),
    ToCreate { parent: Directory, name: PathBuf },
}

impl LogTarget {
    pub fn resolve(path: &Path) -> io::Result<Self> {
        if path.as_os_str().len() > MAX_PATH_BYTES {
            return Err(invalid());
        }
        let norm = normalize_path(path);
        match Directory::open(&norm) {
            Ok(dir) => Ok(LogTarget::Existing(dir)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let parent_path = norm
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                let name = norm.file_name().ok_or_else(invalid)?;
                let mut parts = Path::new(name).components();
                if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
                    return Err(invalid());
                }
                let parent = Directory::open(parent_path)?;
                let child_path = parent.path(Path::new(name))?;
                match fs::symlink_metadata(&child_path) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    Ok(_) => return Err(invalid()),
                    Err(e) => return Err(e),
                }
                Ok(LogTarget::ToCreate {
                    parent,
                    name: PathBuf::from(name),
                })
            }
            Err(e) => Err(e),
        }
    }

    pub fn into_directory(self) -> io::Result<Directory> {
        match self {
            LogTarget::Existing(dir) => Ok(dir),
            LogTarget::ToCreate { parent, name } => parent.create_child_dir(&name),
        }
    }
}

/// `crate::safe_fs::private_tempdir()` honours the umask (0002 gives 0775); publication and
/// endpoint reclaim require a directory not writable by group or others.
#[cfg(test)]
pub(crate) fn private_tempdir() -> io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[cfg(test)]
thread_local! {
    static FAIL_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_OPEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use crate::log::{verify_log_recover, DedupeEntry, LogEventParams, LogHead, LogManager};
    use std::collections::BTreeMap;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
    thread_local! {
        static STOP_AT: std::cell::RefCell<Option<(String, String, PathBuf)>> = const { std::cell::RefCell::new(None) };
        /// (temporary name, directory, outside target, replace with a symlink)
        static REPLACE_AT: std::cell::RefCell<Option<(String, PathBuf, PathBuf, bool)>> = const { std::cell::RefCell::new(None) };
    }

    pub(super) fn at_boundary(temp: &Path, boundary: &str) {
        if boundary == "synced" || boundary == "before_replace" {
            let selected = REPLACE_AT.with(|point| {
                let mut point = point.borrow_mut();
                if point
                    .as_ref()
                    .is_some_and(|(name, ..)| temp == Path::new(name))
                {
                    point.take()
                } else {
                    None
                }
            });
            if let Some((name, dir, outside, use_symlink)) = selected {
                // Atomically swap a forged entry in for the temporary or destination.
                let staged = dir.join("forged.staging");
                if use_symlink {
                    std::os::unix::fs::symlink(&outside, &staged).unwrap();
                } else {
                    fs::write(&staged, b"forged").unwrap();
                }
                fs::rename(&staged, dir.join(name)).unwrap();
            }
        }
        STOP_AT.with(|point| {
            if let Some((selected_temp, selected_boundary, ready)) = point.borrow().as_ref() {
                if temp == Path::new(selected_temp) && boundary == selected_boundary {
                    fs::write(ready, b"ready").unwrap();
                    // A missed parent kill still has a finite bound.
                    std::thread::sleep(CHILD_TIMEOUT);
                    panic!("publication child was not killed");
                }
            }
        });
    }

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn event() -> LogEventParams<'static> {
        LogEventParams {
            elapsed_ms: 0,
            request_id: 1,
            method: "GET",
            authority: "example.org",
            path_and_query: "/item",
            range: None,
            status: "200",
            bytes: 0,
        }
    }

    #[test]
    fn publication_crash_child() {
        let Some(root) = std::env::var_os("PUBLICATION_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut log = LogManager::new_opts_recover(&root, true, true).unwrap();
        log.log_event(&event()).unwrap();
        STOP_AT.with(|point| {
            *point.borrow_mut() = Some((
                std::env::var("PUBLICATION_TEST_TEMP").unwrap(),
                std::env::var("PUBLICATION_TEST_BOUNDARY").unwrap(),
                root.join("ready"),
            ))
        });
        log.finish().unwrap();
        panic!("publication boundary was not reached");
    }

    #[test]
    fn priorcheck_2_group_or_world_writable_publication_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o770, 0o775, 0o720, 0o702, 0o777] {
            let root = crate::safe_fs::private_tempdir().unwrap();
            let dir = root.path().join("log");
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            let mut log = LogManager::new(&dir).unwrap();
            log.log_event(&event()).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            let error = log.finish().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("not writable by group or others"),
                "{mode:o}: {error}"
            );
            for name in [
                "requests.log.head",
                "dedupe.json",
                ".head.tmp",
                ".dedupe.json.tmp",
            ] {
                assert!(
                    fs::symlink_metadata(dir.join(name)).is_err(),
                    "{mode:o}: {name} was written"
                );
            }
            // The same directory made private again publishes normally.
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            log.finish().unwrap();
            verify_log_recover(dir.join("requests.log"), false, false).unwrap();
        }
    }

    #[test]
    fn rereview_2_replaced_synced_temporaries_are_never_published() {
        for artifact in [".head.tmp", ".dedupe.json.tmp"] {
            for use_symlink in [false, true] {
                let root = crate::safe_fs::private_tempdir().unwrap();
                let dir = root.path().join("log");
                fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
                let outside = root.path().join("outside");
                fs::write(&outside, b"forged").unwrap();
                let mut log = LogManager::new(&dir).unwrap();
                log.log_event(&event()).unwrap();
                REPLACE_AT.with(|point| {
                    *point.borrow_mut() =
                        Some((artifact.into(), dir.clone(), outside.clone(), use_symlink))
                });
                let result = log.finish();
                let fired = REPLACE_AT.with(|point| point.borrow_mut().take().is_none());
                assert!(fired, "{artifact}: replacement boundary not reached");
                let published = dir.join(if artifact == ".head.tmp" {
                    "requests.log.head"
                } else {
                    "dedupe.json"
                });
                // Either rejected (nothing published) or the original bytes.
                match fs::symlink_metadata(&published) {
                    Ok(meta) => {
                        assert!(
                            meta.file_type().is_file(),
                            "{artifact} symlink={use_symlink}: published a non-file"
                        );
                        assert_ne!(
                            fs::read(&published).unwrap(),
                            b"forged",
                            "{artifact} symlink={use_symlink}: published the replacement"
                        );
                    }
                    Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
                }
                assert_eq!(fs::read(&outside).unwrap(), b"forged");
                if result.is_ok() {
                    verify_log_recover(dir.join("requests.log"), false, false).unwrap();
                }
            }
        }
    }

    #[test]
    fn review_7_killed_atomic_publications_resume_with_verified_head_and_dedupe() {
        for artifact in [".head.tmp", ".dedupe.json.tmp"] {
            for boundary in ["created", "written", "synced"] {
                let root = crate::safe_fs::private_tempdir().unwrap();
                let mut initial = LogManager::new(root.path()).unwrap();
                initial.log_event(&event()).unwrap();
                initial.finish().unwrap();
                let mut child = OwnedChild(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "safe_fs::publication_tests::publication_crash_child",
                        ])
                        .env("PUBLICATION_TEST_ROOT", root.path())
                        .env("PUBLICATION_TEST_TEMP", artifact)
                        .env("PUBLICATION_TEST_BOUNDARY", boundary)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                let deadline = Instant::now() + CHILD_TIMEOUT;
                while !root.path().join("ready").exists() {
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "child exited before publication boundary"
                    );
                    assert!(Instant::now() < deadline, "publication boundary timeout");
                    std::thread::sleep(Duration::from_millis(5));
                }
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                assert!(root.path().join(artifact).is_file());
                let mut resumed = LogManager::new_opts_recover(root.path(), true, true).unwrap();
                assert_eq!(resumed.current_seq(), 2);
                resumed.log_event(&event()).unwrap();
                resumed.finish().unwrap();
                let path = root.path().join("requests.log");
                assert_eq!(verify_log_recover(&path, false, false).unwrap(), 3);
                let head: LogHead = serde_json::from_slice(
                    &fs::read(root.path().join("requests.log.head")).unwrap(),
                )
                .unwrap();
                assert_eq!(head.seq, 3);
                assert_eq!(head.hash, resumed.prev_hash());
                let dedupe: BTreeMap<String, DedupeEntry> =
                    serde_json::from_slice(&fs::read(root.path().join("dedupe.json")).unwrap())
                        .unwrap();
                let rebuilt = LogManager::rebuild_dedupe_from_log(&path).unwrap();
                assert_eq!(
                    dedupe.values().collect::<Vec<_>>(),
                    rebuilt.values().collect::<Vec<_>>()
                );
                assert_eq!(dedupe.values().map(|entry| entry.count).sum::<u64>(), 3);
                assert!(!root.path().join(".head.tmp").exists());
                assert!(!root.path().join(".dedupe.json.tmp").exists());
            }
        }
    }

    #[test]
    fn test_atomic_write_refuses_to_overwrite_existing_destination() {
        let root = crate::safe_fs::private_tempdir().unwrap();
        let dir = Directory::open(root.path()).unwrap();
        let target = Path::new("dest.txt");
        let temp = Path::new(".dest.tmp");

        // First atomic_write creates and publishes successfully.
        dir.atomic_write(target, temp, b"initial payload").unwrap();
        assert_eq!(
            fs::read(root.path().join(target)).unwrap(),
            b"initial payload"
        );
        assert!(!root.path().join(temp).exists());

        // Second atomic_write refuses to overwrite existing destination.
        let err = dir
            .atomic_write(target, temp, b"second payload")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(root.path().join(target)).unwrap(),
            b"initial payload"
        );
        assert!(!root.path().join(temp).exists());

        // Pre-existing file created outside atomic_write also causes immediate refusal.
        let other = Path::new("preexisting.txt");
        let other_temp = Path::new(".preexisting.tmp");
        fs::write(root.path().join(other), b"adversary content").unwrap();
        let err2 = dir
            .atomic_write(other, other_temp, b"new content")
            .unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(root.path().join(other)).unwrap(),
            b"adversary content"
        );
        assert!(!root.path().join(other_temp).exists());
    }

    #[test]
    fn test_atomic_replace_legitimate_replacement_and_inode_verification() {
        let root = crate::safe_fs::private_tempdir().unwrap();
        let dir = Directory::open(root.path()).unwrap();
        let target = Path::new("replace.txt");
        let temp = Path::new(".replace.tmp");

        // Initial atomic_replace succeeds (creates new file).
        dir.atomic_replace(target, temp, b"version 1").unwrap();
        assert_eq!(fs::read(root.path().join(target)).unwrap(), b"version 1");
        assert!(!root.path().join(temp).exists());

        // Legitimate replacement succeeds and overwrites destination.
        dir.atomic_replace(target, temp, b"version 2").unwrap();
        assert_eq!(fs::read(root.path().join(target)).unwrap(), b"version 2");
        assert!(!root.path().join(temp).exists());

        // Another legitimate replacement.
        dir.atomic_replace(target, temp, b"version 3").unwrap();
        assert_eq!(fs::read(root.path().join(target)).unwrap(), b"version 3");
        assert!(!root.path().join(temp).exists());
    }

    #[test]
    fn test_atomic_replace_refuses_when_destination_inode_swapped() {
        for use_symlink in [false, true] {
            let root = crate::safe_fs::private_tempdir().unwrap();
            let dir = Directory::open(root.path()).unwrap();
            let target = Path::new("swapped.txt");
            let temp = Path::new(".swapped.tmp");
            let outside = root.path().join("outside.txt");
            fs::write(&outside, b"outside secret").unwrap();

            // Establish legitimate target file.
            dir.atomic_replace(target, temp, b"original legitimate")
                .unwrap();
            assert_eq!(
                fs::read(root.path().join(target)).unwrap(),
                b"original legitimate"
            );

            // Setup hook: right before the exchange rename, swap the destination file with forged entry.
            REPLACE_AT.with(|point| {
                *point.borrow_mut() = Some((
                    "swapped.txt".into(),
                    root.path().to_path_buf(),
                    outside.clone(),
                    use_symlink,
                ));
            });

            // atomic_replace should detect that destination inode was swapped out from under it and refuse.
            let result = dir.atomic_replace(target, temp, b"tampered replacement");
            assert!(
                result.is_err(),
                "symlink={use_symlink}: expected atomic_replace failure on swapped inode"
            );

            let fired = REPLACE_AT.with(|point| point.borrow_mut().take().is_none());
            assert!(
                fired,
                "symlink={use_symlink}: replacement boundary hook was not called"
            );

            // Destination must NOT have been replaced by "tampered replacement".
            if use_symlink {
                let meta = fs::symlink_metadata(root.path().join(target)).unwrap();
                assert!(meta.file_type().is_symlink());
                assert_eq!(fs::read(&outside).unwrap(), b"outside secret");
            } else {
                assert_eq!(fs::read(root.path().join(target)).unwrap(), b"forged");
            }
            assert!(!root.path().join(temp).exists());
        }
    }

    #[test]
    fn test_atomic_replace_refuses_when_destination_inode_swapped_at_synced() {
        for use_symlink in [false, true] {
            let root = crate::safe_fs::private_tempdir().unwrap();
            let dir = Directory::open(root.path()).unwrap();
            let target = Path::new("swapped.txt");
            let temp = Path::new(".swapped.tmp");
            let outside = root.path().join("outside.txt");
            fs::write(&outside, b"outside secret").unwrap();

            // Establish legitimate target file.
            dir.atomic_replace(target, temp, b"original legitimate")
                .unwrap();
            assert_eq!(
                fs::read(root.path().join(target)).unwrap(),
                b"original legitimate"
            );

            // Setup hook: at the synced boundary, swap the destination file with forged entry.
            REPLACE_AT.with(|point| {
                *point.borrow_mut() = Some((
                    "swapped.txt".into(),
                    root.path().to_path_buf(),
                    outside.clone(),
                    use_symlink,
                ));
            });

            // atomic_replace should detect that destination inode was swapped during staging and refuse.
            let result = dir.atomic_replace(target, temp, b"tampered replacement");
            assert!(
                result.is_err(),
                "symlink={use_symlink}: expected atomic_replace failure on destination swapped at synced"
            );

            let fired = REPLACE_AT.with(|point| point.borrow_mut().take().is_none());
            assert!(
                fired,
                "symlink={use_symlink}: replacement boundary hook was not called at synced"
            );

            // Substituted file must NOT be deleted, and destination must NOT have been replaced by tampered replacement.
            if use_symlink {
                let meta = fs::symlink_metadata(root.path().join(target)).unwrap();
                assert!(meta.file_type().is_symlink());
                assert_eq!(fs::read(&outside).unwrap(), b"outside secret");
            } else {
                assert_eq!(fs::read(root.path().join(target)).unwrap(), b"forged");
            }
            assert!(!root.path().join(temp).exists());
        }
    }

    #[test]
    fn test_atomic_replace_restores_destination_when_temp_swapped_before_exchange() {
        for use_symlink in [false, true] {
            let root = crate::safe_fs::private_tempdir().unwrap();
            let dir = Directory::open(root.path()).unwrap();
            let target = Path::new("target.txt");
            let temp = Path::new(".target.tmp");
            let outside = root.path().join("outside.txt");
            fs::write(&outside, b"outside secret").unwrap();

            // Establish legitimate target file.
            dir.atomic_replace(target, temp, b"original destination")
                .unwrap();
            assert_eq!(
                fs::read(root.path().join(target)).unwrap(),
                b"original destination"
            );

            // Setup hook: immediately before the exchange rename, swap the temporary staging file with forged entry.
            REPLACE_AT.with(|point| {
                *point.borrow_mut() = Some((
                    ".target.tmp".into(),
                    root.path().to_path_buf(),
                    outside.clone(),
                    use_symlink,
                ));
            });

            // atomic_replace should detect destination staging mismatch and restore destination.
            let result = dir.atomic_replace(target, temp, b"tampered replacement");
            assert!(
                result.is_err(),
                "symlink={use_symlink}: expected atomic_replace failure when temp swapped"
            );

            let fired = REPLACE_AT.with(|point| point.borrow_mut().take().is_none());
            assert!(
                fired,
                "symlink={use_symlink}: replacement boundary hook was not called"
            );

            // Displaced destination must have been restored.
            assert_eq!(
                fs::read(root.path().join(target)).unwrap(),
                b"original destination",
                "symlink={use_symlink}: destination was not restored"
            );

            // Temporary file containing forged entry was not deleted by outer cleanup.
            let temp_meta = fs::symlink_metadata(root.path().join(temp)).unwrap();
            if use_symlink {
                assert!(temp_meta.file_type().is_symlink());
                assert_eq!(fs::read(&outside).unwrap(), b"outside secret");
            } else {
                assert_eq!(fs::read(root.path().join(temp)).unwrap(), b"forged");
            }
        }
    }
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
        let temp = crate::safe_fs::private_tempdir().unwrap();
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
        let temp = crate::safe_fs::private_tempdir().unwrap();
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
        let temp = crate::safe_fs::private_tempdir().unwrap();
        let mut log = crate::log::LogManager::new(temp.path()).unwrap();
        FAIL_SYNC.set(true);
        assert!(log.finish().is_err());
        // Recovery also publishes through the same checked directory sync.
        assert!(
            crate::log::verify_log_recover(temp.path().join("requests.log"), false, true).is_err()
        );
        FAIL_SYNC.set(false);
    }

    #[test]
    fn descriptor_identity_and_ancestry_traversal() {
        let temp = crate::safe_fs::private_tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::create_dir(root.join("sub/leaf")).unwrap();
        fs::create_dir(root.join("sibling")).unwrap();

        let root_dir = Directory::open(&root).unwrap();
        let sub_dir = Directory::open(&root.join("sub")).unwrap();
        let leaf_dir = Directory::open(&root.join("sub/leaf")).unwrap();
        let sibling_dir = Directory::open(&root.join("sibling")).unwrap();

        let root_id = root_dir.identity().unwrap();
        let sub_id = sub_dir.identity().unwrap();
        let leaf_id = leaf_dir.identity().unwrap();
        let _sibling_id = sibling_dir.identity().unwrap();

        assert!(is_descendant_of(&leaf_dir, &sub_id).unwrap());
        assert!(is_descendant_of(&leaf_dir, &root_id).unwrap());
        assert!(is_descendant_of(&leaf_dir, &leaf_id).unwrap());
        assert!(is_descendant_of(&sub_dir, &root_id).unwrap());
        assert!(!is_descendant_of(&sub_dir, &leaf_id).unwrap());
        assert!(!is_descendant_of(&sibling_dir, &sub_id).unwrap());
        assert!(is_descendant_of(&sibling_dir, &root_id).unwrap());

        // Rename sub to sub_renamed and verify descriptor ancestry is invariant
        let renamed = root.join("sub_renamed");
        fs::rename(root.join("sub"), &renamed).unwrap();
        assert!(is_descendant_of(&leaf_dir, &sub_id).unwrap());
        assert!(is_descendant_of(&leaf_dir, &root_id).unwrap());
    }
}
