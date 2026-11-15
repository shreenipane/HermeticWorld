#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

use crate::error::TrustError;
use crate::jks::{inject_ca_into_jks, is_pkcs12};

/// Skipped path entry in report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPath {
    pub path: String,
    pub reason: String,
}

/// Installation report schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub ca_cert_sha256: String,
    pub modified_paths: Vec<String>,
    pub skipped_paths: Vec<SkippedPath>,
    pub env_defaults: BTreeMap<String, String>,
}

/// Guest owner assigned to every file and directory the installer creates in a
/// rootfs. Replaced files keep their existing owner; new entries never inherit
/// the identity of the sealing process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestOwner {
    pub uid: u32,
    pub gid: u32,
}

impl GuestOwner {
    /// Guest root (0:0), the default owner of created entries.
    pub const ROOT: GuestOwner = GuestOwner { uid: 0, gid: 0 };
}

impl Default for GuestOwner {
    fn default() -> Self {
        GuestOwner::ROOT
    }
}

/// Mode of every trust bundle or anchor file the installer creates.
pub const NEW_FILE_MODE: u32 = 0o644;
/// Mode of every directory the installer creates.
pub const NEW_DIR_MODE: u32 = 0o755;

/// Options for [`install_ca_with_options`].
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Owner of created rootfs entries (default: guest root 0:0). Installation
    /// fails before mutating the rootfs if this ownership cannot be applied.
    pub owner: GuestOwner,
    /// Destination of the JSON report, if any. It is checked against every
    /// target of the discovery plan before the rootfs is mutated.
    pub report_path: Option<PathBuf>,
}

/// Safely join relative path components to rootfs, guaranteeing no escape outside rootfs.
/// Any ".." components at the rootfs boundary remain at the boundary (like a Unix chroot).
pub fn safe_join_rootfs(rootfs: &Path, rel: &Path) -> PathBuf {
    let mut stack = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => stack.push(c),
            Component::ParentDir => {
                stack.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    let mut out = rootfs.to_path_buf();
    for comp in stack {
        out.push(comp);
    }
    out
}

/// Safely join relative path components from a specific directory within rootfs.
pub fn safe_join_rootfs_from(rootfs: &Path, base_dir: &Path, target: &Path) -> PathBuf {
    let rel_base = match base_dir.strip_prefix(rootfs) {
        Ok(r) => r,
        Err(_) => Path::new(""),
    };
    let combined = rel_base.join(target);
    safe_join_rootfs(rootfs, &combined)
}

/// Result of resolving a path inside a rootfs.
#[derive(Debug)]
pub enum Resolution {
    /// The path exists. `rel` is the symlink-free rootfs-relative location and
    /// `meta` was obtained with lstat through a validated directory descriptor.
    Exists { rel: PathBuf, meta: fs::Metadata },
    /// The final component (and possibly some parent directories) does not
    /// exist. `rel` is a validated existing directory followed only by plain
    /// missing names, so creating it cannot traverse any symlink.
    Missing { rel: PathBuf },
    /// A missing component is followed by `..`; the kernel fails such a lookup
    /// with ENOENT, so the path names nothing and cannot be created.
    Unresolvable,
}

/// Resolves symlinks strictly within the rootfs as if rootfs were `/`.
/// Absolute symlink targets are interpreted relative to rootfs.
/// Every component is looked up through validated directory descriptors; no
/// metadata is ever read through a path that could traverse a host symlink.
/// Detects symlink loops and limits hop depth to 40.
pub fn resolve_in_rootfs(rootfs: &Path, path: &Path) -> Result<Resolution, TrustError> {
    let root_handle = open_dir_handle(rootfs)?;
    let rootfs_canon = rootfs
        .canonicalize()
        .unwrap_or_else(|_| rootfs.to_path_buf());

    let rel = if let Ok(r) = path.strip_prefix(rootfs) {
        r.to_path_buf()
    } else if let Ok(r) = path.strip_prefix(&rootfs_canon) {
        r.to_path_buf()
    } else if path.is_absolute() {
        path.strip_prefix("/").unwrap_or(path).to_path_buf()
    } else {
        path.to_path_buf()
    };
    resolve_rel(&root_handle, &rel)
}

/// Descriptor-anchored resolver behind [`resolve_in_rootfs`]: resolves `rel`
/// relative to the rootfs directory `root_handle`.
fn resolve_rel(root_handle: &fs::File, rel: &Path) -> Result<Resolution, TrustError> {
    let mut queue: VecDeque<PathBuf> = VecDeque::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => queue.push_back(PathBuf::from(c)),
            Component::ParentDir => queue.push_back(PathBuf::from("..")),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }

    // Only the current directory handle (plus the root handle) is kept open; the
    // path is tracked as a rootfs-relative PathBuf and `..` re-opens the parent
    // from the root handle, so descriptor use does not grow with path depth.
    let mut current_dir = root_handle.try_clone()?;
    let mut current_rel = PathBuf::new();
    let mut hops = 0;
    const MAX_HOPS: usize = 40;

    while let Some(comp) = queue.pop_front() {
        if comp == Path::new("..") {
            if current_rel.pop() {
                current_dir = open_rel_dir_from_root(root_handle, &current_rel)?;
            }
            continue;
        }

        let current_fd = current_dir.as_raw_fd();
        let child_proc = proc_child(current_fd, comp.as_os_str());

        // lstat relative to the validated directory descriptor.
        let meta = match fs::symlink_metadata(&child_proc) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A missing directory followed by `..` fails in the kernel; it
                // must not be normalised away lexically.
                if queue.iter().any(|c| c == Path::new("..")) {
                    return Ok(Resolution::Unresolvable);
                }
                current_rel.push(&comp);
                for rem in queue {
                    current_rel.push(rem);
                }
                return Ok(Resolution::Missing { rel: current_rel });
            }
            // Host-side I/O failures (EMFILE, EACCES, ...) are not rootfs
            // content problems: surface them as I/O errors so callers fail closed.
            Err(e) => return Err(TrustError::Io(e)),
        };

        if meta.is_symlink() {
            hops += 1;
            if hops > MAX_HOPS {
                return Err(TrustError::Symlink("symlink loop detected".to_string()));
            }

            let target = fs::read_link(&child_proc)?;

            if target.is_absolute() {
                current_dir = root_handle.try_clone()?;
                current_rel = PathBuf::new();
            }
            let target_comps: Vec<PathBuf> = target
                .components()
                .filter_map(|c| match c {
                    Component::Normal(n) => Some(PathBuf::from(n)),
                    Component::ParentDir => Some(PathBuf::from("..")),
                    Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
                })
                .collect();

            for c in target_comps.into_iter().rev() {
                queue.push_front(c);
            }
        } else if meta.is_dir() {
            let next_dir = open_child_dir(current_fd, comp.as_os_str())?;
            current_dir = next_dir;
            current_rel.push(&comp);
        } else {
            current_rel.push(&comp);
            if !queue.is_empty() {
                return Err(TrustError::Symlink(format!(
                    "not a directory in path: {}",
                    comp.display()
                )));
            }
            return Ok(Resolution::Exists {
                rel: current_rel,
                meta,
            });
        }
    }

    // Resolution ended on a directory: fstat the validated descriptor.
    let meta = current_dir.metadata()?;
    Ok(Resolution::Exists {
        rel: current_rel,
        meta,
    })
}

/// `/proc/self/fd/<fd>/<name>`: a path whose lookup starts at the directory
/// descriptor `fd` and does not follow `name` when used with lstat/O_NOFOLLOW.
fn proc_child(fd: std::os::unix::io::RawFd, name: &OsStr) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd)).join(name)
}

/// Named cap for CA certificate input (1 MiB)
pub const MAX_CA_CERT_INPUT_BYTES: u64 = 1024 * 1024;
/// Named cap for PEM bundles (16 MiB)
pub const MAX_PEM_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
/// Named cap for Java KeyStores (8 MiB)
pub const MAX_JKS_BYTES: u64 = 8 * 1024 * 1024;

/// Named limit for total discovered entries in rootfs tree
pub const MAX_TREE_ENTRIES: usize = 100_000;
/// Named limit for directory depth in rootfs tree
pub const MAX_TREE_DEPTH: usize = 64;
/// Named limit for aggregate bytes of discovered candidate bundles
pub const MAX_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
/// Named limit for total report entries
pub const MAX_REPORT_ENTRIES: usize = 10_000;

// Linux x86_64 open(2) flag and errno values. They differ on other targets
// (e.g. on aarch64 0o400000 is O_LARGEFILE and 0o200000 is O_DIRECT), which would
// silently disable every symlink protection, so any other target is rejected.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!(
    "hermetic-trust hard-codes Linux x86_64 open(2) flag values (O_NOFOLLOW, O_DIRECTORY, ...); \
     add correct values for this target before building"
);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_CLOEXEC: i32 = 0o2000000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ELOOP: i32 = 40;

// Test injection is per-thread only (no process-global hooks): it can affect
// only the thread that installed it, and is off unless a guard is held.
thread_local! {
    static THREAD_CHOWN_FAILURE: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
    static THREAD_BEFORE_USE_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    static THREAD_BEFORE_DIR_ENUM_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    static THREAD_OWNERSHIP_RECORDS: std::cell::RefCell<Option<Vec<OwnershipRecord>>> = const { std::cell::RefCell::new(None) };
}

/// What an ownership step was applied to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipTarget {
    /// Host probe run before mutation to check the guest owner is settable.
    Probe,
    /// Directory created in the rootfs.
    NewDirectory,
    /// File (anchor or bundle) created in the rootfs.
    NewFile,
    /// Replacement of an existing file, keeping its owner and mode.
    ExistingFile,
}

/// One ownership step as recorded by [`record_ownership_guard`]: the owner and
/// mode the installer asked for, and the name of the entry (empty for the probe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRecord {
    pub target: OwnershipTarget,
    pub name: OsString,
    pub uid: u32,
    pub gid: u32,
    pub mode: Option<u32>,
}

/// Thread-local ownership recorder for tests. While the guard lives, each
/// ownership step on this thread is recorded instead of performing fchown
/// (an injected failure from [`set_chown_failure_guard`] still applies first);
/// modes are still set through descriptors.
pub struct OwnershipRecordGuard;
impl OwnershipRecordGuard {
    /// Ownership steps recorded so far, in order.
    pub fn records(&self) -> Vec<OwnershipRecord> {
        THREAD_OWNERSHIP_RECORDS.with(|c| c.borrow().clone().unwrap_or_default())
    }
}
impl Drop for OwnershipRecordGuard {
    fn drop(&mut self) {
        THREAD_OWNERSHIP_RECORDS.with(|c| *c.borrow_mut() = None);
    }
}

pub fn record_ownership_guard() -> OwnershipRecordGuard {
    THREAD_OWNERSHIP_RECORDS.with(|c| *c.borrow_mut() = Some(Vec::new()));
    OwnershipRecordGuard
}

pub struct ChownFailureGuard;
impl Drop for ChownFailureGuard {
    fn drop(&mut self) {
        THREAD_CHOWN_FAILURE.with(|c| *c.borrow_mut() = false);
    }
}

pub fn set_chown_failure_guard() -> ChownFailureGuard {
    THREAD_CHOWN_FAILURE.with(|c| *c.borrow_mut() = true);
    ChownFailureGuard
}

pub struct BeforeUseHookGuard;
impl Drop for BeforeUseHookGuard {
    fn drop(&mut self) {
        THREAD_BEFORE_USE_HOOK.with(|c| *c.borrow_mut() = None);
    }
}

pub fn set_before_use_hook_guard<F: Fn() + 'static>(f: F) -> BeforeUseHookGuard {
    THREAD_BEFORE_USE_HOOK.with(|c| *c.borrow_mut() = Some(Box::new(f)));
    BeforeUseHookGuard
}

pub struct BeforeDirEnumHookGuard;
impl Drop for BeforeDirEnumHookGuard {
    fn drop(&mut self) {
        THREAD_BEFORE_DIR_ENUM_HOOK.with(|c| *c.borrow_mut() = None);
    }
}

pub fn set_before_dir_enum_hook_guard<F: Fn() + 'static>(f: F) -> BeforeDirEnumHookGuard {
    THREAD_BEFORE_DIR_ENUM_HOOK.with(|c| *c.borrow_mut() = Some(Box::new(f)));
    BeforeDirEnumHookGuard
}

/// Losslessly encode a filesystem path into a valid UTF-8 String for reporting.
pub fn encode_path_lossless(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                let mut out = String::with_capacity(bytes.len() * 4);
                let mut i = 0;
                while i < bytes.len() {
                    match std::str::from_utf8(&bytes[i..]) {
                        Ok(valid) => {
                            out.push_str(valid);
                            break;
                        }
                        Err(err) => {
                            let valid_len = err.valid_up_to();
                            if valid_len > 0 {
                                if let Ok(s) = std::str::from_utf8(&bytes[i..i + valid_len]) {
                                    out.push_str(s);
                                }
                                i += valid_len;
                            }
                            if let Some(error_len) = err.error_len() {
                                for &b in &bytes[i..i + error_len] {
                                    use std::fmt::Write;
                                    let _ = write!(out, "\\x{:02x}", b);
                                }
                                i += error_len;
                            } else {
                                for &b in &bytes[i..] {
                                    use std::fmt::Write;
                                    let _ = write!(out, "\\x{:02x}", b);
                                }
                                break;
                            }
                        }
                    }
                }
                out
            }
        }
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().to_string()
    }
}

/// Open a directory handle safely without following symlinks.
pub fn open_dir_handle(path: &Path) -> Result<fs::File, TrustError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    options.open(path).map_err(TrustError::Io)
}

/// Validate that `name` is exactly one plain file-name component: not empty, no
/// `/`, not `.` or `..`. Descriptor-relative helpers only accept such names, so
/// a lookup can never traverse an intermediate (possibly symlinked) directory.
fn single_component(name: &OsStr) -> Result<&OsStr, TrustError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&b'/') || bytes == b"." || bytes == b".." {
        return Err(TrustError::Symlink(format!(
            "'{}' is not a single file-name component",
            encode_path_lossless(Path::new(name))
        )));
    }
    Ok(name)
}

/// Open a child directory through an existing directory handle without following symlinks.
/// `comp` must be a single file-name component.
pub fn open_child_dir<P: AsRef<std::ffi::OsStr> + ?Sized>(
    parent_fd: std::os::unix::io::RawFd,
    comp: &P,
) -> Result<fs::File, TrustError> {
    let comp = single_component(comp.as_ref())?;
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", parent_fd)).join(comp);
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    let f = options.open(&proc_path).map_err(TrustError::Io)?;
    let meta = f.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(TrustError::Cert("not a directory".to_string()));
    }
    Ok(f)
}

/// Build the error that aborts an install when discovery hits a host-side
/// failure (I/O error, descriptor exhaustion, ...) rather than a rootfs content
/// problem. Discovery never silently skips on such failures.
fn discovery_failure(path: &str, e: &dyn std::fmt::Display) -> TrustError {
    TrustError::Cert(format!("rootfs discovery failed at '{}': {}", path, e))
}

/// Open the directory at `rel` (relative to the directory `root`) by walking one
/// component at a time from `root` with O_DIRECTORY | O_NOFOLLOW. At most two
/// descriptors (plus `root`) are open at any moment. An empty `rel` returns a
/// fresh handle to `root` itself.
fn open_rel_dir_from_root(root: &fs::File, rel: &Path) -> Result<fs::File, TrustError> {
    use std::os::unix::io::AsRawFd;

    let mut current = root.try_clone()?;
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => {
                let next = open_child_dir(current.as_raw_fd(), c)?;
                current = next;
            }
            _ => {
                return Err(TrustError::Cert(
                    "unexpected non-normal path component".to_string(),
                ))
            }
        }
    }
    Ok(current)
}

/// Split a rootfs-relative path into validated parent components and a final
/// name. Only plain names are accepted: absolute paths, `.` and `..` are refused
/// so that every component is opened from a validated directory descriptor.
fn validated_rel_components(rel: &Path) -> Result<(Vec<OsString>, OsString), TrustError> {
    let mut comps: Vec<OsString> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => comps.push(c.to_os_string()),
            _ => {
                return Err(TrustError::Symlink(format!(
                    "relative path '{}' must contain only plain components",
                    encode_path_lossless(rel)
                )))
            }
        }
    }
    let file_name = comps
        .pop()
        .ok_or_else(|| TrustError::Cert("empty relative path".to_string()))?;
    Ok((comps, file_name))
}

/// Open the parent directory of `rel` (relative to the rootfs directory `root`)
/// one component at a time with O_DIRECTORY | O_NOFOLLOW, and return it with the
/// final name. Any symlink or non-directory among the parents is refused.
fn open_parent_from_root(root: &fs::File, rel: &Path) -> Result<(fs::File, OsString), TrustError> {
    let (parents, file_name) = validated_rel_components(rel)?;
    let mut current = root.try_clone()?;
    for comp in &parents {
        let next = open_child_dir(current.as_raw_fd(), comp.as_os_str())?;
        current = next;
    }
    Ok((current, file_name))
}

/// Open parent directory handle for a rootfs-relative path, anchoring every step to descriptors.
pub fn open_parent_dir_handle(
    rootfs: &Path,
    rel_path: &Path,
) -> Result<(fs::File, std::ffi::OsString), TrustError> {
    let root = open_dir_handle(rootfs)?;
    open_parent_from_root(&root, rel_path)
}

fn chown_failure_injected() -> bool {
    THREAD_CHOWN_FAILURE.with(|c| *c.borrow())
}

/// Set ownership through an open descriptor (never through a path).
/// `target`, `name` and `mode` describe the step for the test recorder.
fn set_owner_fd(
    file: &fs::File,
    uid: u32,
    gid: u32,
    target: OwnershipTarget,
    name: &OsStr,
    mode: Option<u32>,
) -> Result<(), TrustError> {
    if chown_failure_injected() {
        return Err(TrustError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "forced chown failure for test: Operation not permitted",
        )));
    }
    let recorded = THREAD_OWNERSHIP_RECORDS.with(|c| {
        if let Some(records) = c.borrow_mut().as_mut() {
            records.push(OwnershipRecord {
                target,
                name: name.to_os_string(),
                uid,
                gid,
                mode,
            });
            true
        } else {
            false
        }
    });
    if recorded {
        return Ok(());
    }
    std::os::unix::fs::fchown(file, Some(uid), Some(gid)).map_err(|e| {
        TrustError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot set ownership {}:{}: {}", uid, gid, e),
        ))
    })
}

/// Fail before any rootfs mutation if the guest owner cannot be applied to new
/// entries by this process (for example an unprivileged process asked for 0:0).
/// The probe is an unnamed host temporary file, so the rootfs is not touched.
fn verify_guest_owner_settable(owner: GuestOwner) -> Result<(), TrustError> {
    let probe = tempfile::tempfile().map_err(TrustError::Io)?;
    set_owner_fd(
        &probe,
        owner.uid,
        owner.gid,
        OwnershipTarget::Probe,
        OsStr::new(""),
        None,
    )
}

/// Create directory `name` under `parent` and give it the guest owner and
/// [`NEW_DIR_MODE`] through its descriptor, independent of the process umask.
/// The directory is removed again if its attributes cannot be set.
fn create_dir_in(
    parent: &fs::File,
    name: &OsStr,
    owner: GuestOwner,
) -> Result<fs::File, TrustError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let path = proc_child(parent.as_raw_fd(), name);
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let res = (|| -> Result<fs::File, TrustError> {
        let dir = open_child_dir(parent.as_raw_fd(), name)?;
        set_owner_fd(
            &dir,
            owner.uid,
            owner.gid,
            OwnershipTarget::NewDirectory,
            name,
            Some(NEW_DIR_MODE),
        )?;
        dir.set_permissions(fs::Permissions::from_mode(NEW_DIR_MODE))?;
        Ok(dir)
    })();
    if res.is_err() {
        let _ = fs::remove_dir(&path);
    }
    res
}

/// Directories created by [`ensure_parent_dirs`], as (parent handle, name).
type CreatedDirs = Vec<(fs::File, OsString)>;

/// Remove directories recorded in `created`, deepest first.
fn remove_created_dirs(created: CreatedDirs) {
    for (parent, name) in created.into_iter().rev() {
        let _ = fs::remove_dir(proc_child(parent.as_raw_fd(), &name));
    }
}

/// Ensure all parent directories of `rel` exist inside the rootfs, creating
/// missing ones with the guest owner and [`NEW_DIR_MODE`]. Every created
/// directory is recorded in `created` so the caller can roll back on failure.
fn ensure_parent_dirs(
    root: &fs::File,
    rel: &Path,
    owner: GuestOwner,
    created: &mut CreatedDirs,
) -> Result<(fs::File, OsString), TrustError> {
    let (parents, file_name) = validated_rel_components(rel)?;
    let mut current = root.try_clone()?;
    for comp in &parents {
        let next = match open_child_dir(current.as_raw_fd(), comp.as_os_str()) {
            Ok(d) => d,
            Err(TrustError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                let d = create_dir_in(&current, comp, owner)?;
                created.push((current.try_clone()?, comp.clone()));
                d
            }
            Err(e) => return Err(e),
        };
        current = next;
    }
    Ok((current, file_name))
}

/// Read a file up to `cap` bytes through a parent directory handle.
/// `file_name` must be a single file-name component.
/// Prevents symlink following and FIFO blocking, validating the opened descriptor.
pub fn read_file_capped_from_parent<P: AsRef<std::ffi::OsStr> + ?Sized>(
    parent_dir: &fs::File,
    file_name: &P,
    cap: u64,
) -> Result<Vec<u8>, TrustError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file_name = single_component(file_name.as_ref())?;
    let proc_path =
        PathBuf::from(format!("/proc/self/fd/{}", parent_dir.as_raw_fd())).join(file_name);
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

    THREAD_BEFORE_USE_HOOK.with(|cell| {
        if let Some(ref hook) = *cell.borrow() {
            hook();
        }
    });

    let file = options.open(&proc_path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(ELOOP) {
            return TrustError::Symlink("symlink target refused".to_string());
        }
        TrustError::Io(e)
    })?;

    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(TrustError::Cert("not a regular file".to_string()));
    }
    if meta.len() > cap {
        return Err(TrustError::Cert(format!(
            "file exceeds size cap of {} bytes",
            cap
        )));
    }

    let mut buf = Vec::new();
    let mut handle = file.take(cap + 1);
    handle.read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(TrustError::Cert(format!(
            "file exceeds size cap of {} bytes",
            cap
        )));
    }
    Ok(buf)
}

/// Write data atomically into parent directory handle: writes to a temporary file
/// anchored to the directory handle, sets permissions and ownership through descriptors,
/// flushes, and replaces atomically through the handle.
///
/// `file_name` must be a single file-name component.
///
/// An existing target keeps its owner and mode. A new target gets `new_owner`
/// and exactly `new_file_mode` (independent of the umask); failure to set either
/// aborts the write without creating the target.
pub fn atomic_write_preserving_handle<P: AsRef<std::ffi::OsStr> + ?Sized>(
    parent_dir: &fs::File,
    file_name: &P,
    data: &[u8],
    new_file_mode: u32,
    new_owner: GuestOwner,
) -> Result<(), TrustError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let file_name = single_component(file_name.as_ref())?;
    let parent_fd = parent_dir.as_raw_fd();
    let target_proc_path = proc_child(parent_fd, file_name);

    // Validate target through handle with O_NOFOLLOW | O_NONBLOCK
    let mut check_opts = fs::OpenOptions::new();
    check_opts.read(true);
    #[cfg(unix)]
    check_opts.custom_flags(O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

    let existing_meta = match check_opts.open(&target_proc_path) {
        Ok(existing_file) => {
            let meta = existing_file.metadata()?;
            if meta.file_type().is_symlink() {
                return Err(TrustError::Symlink(format!(
                    "target '{}' is a symlink",
                    file_name.to_string_lossy()
                )));
            }
            if !meta.file_type().is_file() {
                return Err(TrustError::Symlink(format!(
                    "target '{}' is not a regular file",
                    file_name.to_string_lossy()
                )));
            }
            Some(meta)
        }
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(ELOOP) => {
            return Err(TrustError::Symlink(format!(
                "target '{}' is a symlink",
                file_name.to_string_lossy()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(TrustError::Io(e)),
    };

    THREAD_BEFORE_USE_HOOK.with(|cell| {
        if let Some(ref hook) = *cell.borrow() {
            hook();
        }
    });

    // Create unique temp file in parent dir through handle
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let tmp_name = format!(
            ".tmp-trust-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            attempt
        );
        let tmp_proc_path = proc_child(parent_fd, OsStr::new(&tmp_name));

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.custom_flags(O_NOFOLLOW | O_CLOEXEC);
            options.mode(0o600);
        }

        match options.open(&tmp_proc_path) {
            Ok(mut temp_file) => {
                let write_res = (|| -> Result<(), TrustError> {
                    temp_file.write_all(data)?;
                    temp_file.sync_all()?;

                    if let Some(ref meta) = existing_meta {
                        let target_uid = meta.uid();
                        let target_gid = meta.gid();
                        let temp_meta = temp_file.metadata()?;

                        // Change ownership if either UID or GID differs; the
                        // injected failure goes through the same operation.
                        if chown_failure_injected()
                            || target_uid != temp_meta.uid()
                            || target_gid != temp_meta.gid()
                        {
                            set_owner_fd(
                                &temp_file,
                                target_uid,
                                target_gid,
                                OwnershipTarget::ExistingFile,
                                file_name,
                                Some(meta.mode() & 0o7777),
                            )?;
                        }

                        // Restore permissions AFTER ownership changes so special mode bits are preserved
                        temp_file.set_permissions(meta.permissions())?;
                    } else {
                        // New entry: explicit guest owner and deterministic mode.
                        set_owner_fd(
                            &temp_file,
                            new_owner.uid,
                            new_owner.gid,
                            OwnershipTarget::NewFile,
                            file_name,
                            Some(new_file_mode),
                        )?;
                        temp_file.set_permissions(fs::Permissions::from_mode(new_file_mode))?;
                    }
                    temp_file.sync_all()?;

                    drop(temp_file);

                    // Re-check target before replacement
                    if let Ok(m) = fs::symlink_metadata(&target_proc_path) {
                        if m.file_type().is_symlink() {
                            return Err(TrustError::Symlink(format!(
                                "target '{}' is a symlink",
                                file_name.to_string_lossy()
                            )));
                        }
                    }

                    // Replacement through directory handle
                    fs::rename(&tmp_proc_path, &target_proc_path)?;
                    Ok(())
                })();

                if write_res.is_err() {
                    let _ = fs::remove_file(&tmp_proc_path);
                }
                return write_res;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if attempt > 1000 {
                    return Err(TrustError::Io(e));
                }
                continue;
            }
            Err(e) => return Err(TrustError::Io(e)),
        }
    }
}

/// Atomically write `data` to `rel` inside the rootfs directory `root`.
///
/// `rel` must consist of plain components only; every parent is opened from
/// `root` with O_DIRECTORY | O_NOFOLLOW, so a symlinked or missing ancestor is
/// refused and nothing outside the rootfs is read, written or created. Parent
/// directories are never created. Ownership and mode follow
/// [`atomic_write_preserving_handle`].
pub fn atomic_write_in_root(
    root: &fs::File,
    rel: &Path,
    data: &[u8],
    new_file_mode: u32,
    new_owner: GuestOwner,
) -> Result<(), TrustError> {
    let (parent, file_name) = open_parent_from_root(root, rel)?;
    atomic_write_preserving_handle(&parent, &file_name, data, new_file_mode, new_owner)
}

/// Append `pem` to `content`, separating it with a newline and ending in one.
fn append_pem(mut content: Vec<u8>, pem: &str) -> Vec<u8> {
    if !content.is_empty() && !content.ends_with(b"\n") {
        content.push(b'\n');
    }
    content.extend_from_slice(pem.as_bytes());
    if !content.ends_with(b"\n") {
        content.push(b'\n');
    }
    content
}

/// Append a CA certificate to the PEM bundle at `rel` inside the rootfs
/// directory `root`, idempotently and atomically, with the same descriptor
/// anchoring as [`atomic_write_in_root`]. A new bundle gets `new_owner` and
/// [`NEW_FILE_MODE`]. Returns Ok(true) if modified, Ok(false) if already present.
pub fn append_pem_bundle_in_root(
    root: &fs::File,
    rel: &Path,
    ca_pem: &str,
    ca_der: &[u8],
    new_owner: GuestOwner,
) -> Result<bool, TrustError> {
    let (parent, file_name) = open_parent_from_root(root, rel)?;
    let content = match read_file_capped_from_parent(&parent, &file_name, MAX_PEM_BUNDLE_BYTES) {
        Ok(c) => c,
        Err(TrustError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };

    if !content.is_empty() && bundle_contains_cert(&content, ca_pem, ca_der) {
        return Ok(false);
    }

    let new_content = append_pem(content, ca_pem);
    atomic_write_preserving_handle(&parent, &file_name, &new_content, NEW_FILE_MODE, new_owner)?;
    Ok(true)
}

/// Check if a PEM bundle already contains the given certificate DER.
pub fn bundle_contains_cert(bundle_content: &[u8], ca_cert_pem: &str, ca_cert_der: &[u8]) -> bool {
    let trimmed_ca_pem = ca_cert_pem.trim().as_bytes();
    if !trimmed_ca_pem.is_empty()
        && bundle_content
            .windows(trimmed_ca_pem.len())
            .any(|w| w == trimmed_ca_pem)
    {
        return true;
    }

    let ca_b64: Vec<u8> = ca_cert_pem
        .lines()
        .filter(|l| !l.trim().starts_with("---"))
        .flat_map(|l| l.bytes())
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    const BEGIN_MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END_MARKER: &[u8] = b"-----END CERTIFICATE-----";

    let mut pos = 0;
    while pos + BEGIN_MARKER.len() <= bundle_content.len() {
        if let Some(offset) = bundle_content[pos..]
            .windows(BEGIN_MARKER.len())
            .position(|w| w == BEGIN_MARKER)
        {
            let block_start = pos + offset;
            let body_start = block_start + BEGIN_MARKER.len();
            if let Some(end_offset) = bundle_content[body_start..]
                .windows(END_MARKER.len())
                .position(|w| w == END_MARKER)
            {
                let body_end = body_start + end_offset;
                let block_end = body_end + END_MARKER.len();
                let body = &bundle_content[body_start..body_end];

                if !ca_b64.is_empty() {
                    let body_non_ws = body.iter().copied().filter(|b| !b.is_ascii_whitespace());
                    if body_non_ws.eq(ca_b64.iter().copied()) {
                        return true;
                    }
                }

                let block_slice = &bundle_content[block_start..block_end];
                if let Ok(p) = pem::parse(block_slice) {
                    if p.tag() == "CERTIFICATE" && p.contents() == ca_cert_der {
                        return true;
                    }
                }

                pos = block_end;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    false
}

/// Known system trust bundles, in environment-default priority order.
const KNOWN_SYSTEM_BUNDLES: [&str; 4] = [
    "etc/ssl/certs/ca-certificates.crt",
    "etc/pki/tls/certs/ca-bundle.crt",
    "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "etc/ssl/cert.pem",
];

/// Anchor directories and the anchor file dropped into each when it exists.
const ANCHOR_TARGETS: [(&str, &str); 2] = [
    (
        "usr/local/share/ca-certificates",
        "usr/local/share/ca-certificates/hermetic-world-ca.crt",
    ),
    (
        "etc/pki/ca-trust/source/anchors",
        "etc/pki/ca-trust/source/anchors/hermetic-world-ca.pem",
    ),
];

/// System bundle established when no existing system bundle could be used.
const FALLBACK_BUNDLE_REL: &str = "etc/ssl/certs/ca-certificates.crt";
const FALLBACK_BUNDLE_GUEST_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateFormat {
    Pem,
    Jks,
}

#[derive(Debug, Clone)]
struct Candidate {
    rel_path: PathBuf,
    target_rel: PathBuf,
    format: CandidateFormat,
    /// Whether the target existed at discovery (false: it will be created).
    exists: bool,
}

impl Candidate {
    fn is_system_bundle(&self) -> bool {
        KNOWN_SYSTEM_BUNDLES
            .iter()
            .any(|&k| Path::new(k) == self.rel_path)
    }
}

/// Complete, bounded discovery plan. Installation mutates only targets of this
/// plan, and the report destination is checked against the same plan.
struct InstallPlan {
    /// Non-conflicting candidates in deterministic order.
    candidates: Vec<Candidate>,
    skipped_paths: Vec<SkippedPath>,
    conflicted_targets: HashSet<PathBuf>,
    /// Known system bundle -> resolved existing target, for every system candidate.
    system_targets: Vec<(&'static str, PathBuf)>,
    /// Resolved location of the fallback bundle (existing or to be created).
    fallback_target: Option<PathBuf>,
    fallback_missing: bool,
    fallback_unresolvable: bool,
}

fn charge_aggregate(aggregate_bytes: &mut u64, len: u64) -> Result<(), TrustError> {
    *aggregate_bytes = aggregate_bytes.saturating_add(len);
    if *aggregate_bytes > MAX_AGGREGATE_BYTES {
        return Err(TrustError::Cert("aggregate bytes exceed limit".to_string()));
    }
    Ok(())
}

fn size_cap_reason(cap: u64) -> String {
    format!("file exceeds size cap of {} bytes", cap)
}

/// Classify a `cacert.pem` / `cacerts` entry found by the tree walk.
fn discover_store_file(
    root: &fs::File,
    entry_rel: PathBuf,
    format: CandidateFormat,
    candidates: &mut Vec<Candidate>,
    skipped_paths: &mut Vec<SkippedPath>,
    aggregate_bytes: &mut u64,
) -> Result<(), TrustError> {
    let cap = match format {
        CandidateFormat::Pem => MAX_PEM_BUNDLE_BYTES,
        CandidateFormat::Jks => MAX_JKS_BYTES,
    };
    let skip = |skipped: &mut Vec<SkippedPath>, path: &Path, reason: String| {
        skipped.push(SkippedPath {
            path: encode_path_lossless(path),
            reason,
        });
    };
    match resolve_rel(root, &entry_rel) {
        Ok(Resolution::Exists {
            rel: rel_target,
            meta,
        }) => {
            if meta.is_dir() {
                skip(skipped_paths, &entry_rel, "bundle_is_directory".to_string());
            } else if !meta.file_type().is_file() {
                skip(skipped_paths, &entry_rel, "not a regular file".to_string());
            } else if meta.len() > cap {
                skip(skipped_paths, &rel_target, size_cap_reason(cap));
            } else {
                charge_aggregate(aggregate_bytes, meta.len())?;
                candidates.push(Candidate {
                    rel_path: entry_rel,
                    target_rel: rel_target,
                    format,
                    exists: true,
                });
            }
        }
        Ok(Resolution::Missing { .. }) | Ok(Resolution::Unresolvable) => {
            skip(skipped_paths, &entry_rel, "cannot stat target".to_string());
        }
        Err(TrustError::Symlink(reason)) => skip(skipped_paths, &entry_rel, reason),
        Err(e) => return Err(discovery_failure(&encode_path_lossless(&entry_rel), &e)),
    }
    Ok(())
}

/// Discover every trust store under the rootfs directory `root`, within the
/// named entry, depth, byte and report budgets. Any host-side failure aborts
/// discovery; nothing is modified.
fn discover_plan(root: &fs::File) -> Result<InstallPlan, TrustError> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut skipped_paths: Vec<SkippedPath> = Vec::new();
    let mut system_targets: Vec<(&'static str, PathBuf)> = Vec::new();
    let mut fallback_target: Option<PathBuf> = None;
    let mut fallback_missing = false;
    let mut fallback_unresolvable = false;
    let mut total_tree_entries: usize = 0;
    let mut aggregate_bytes: u64 = 0;

    // 1. Discover Known System Bundles
    for rel_str in KNOWN_SYSTEM_BUNDLES {
        let is_fallback = rel_str == FALLBACK_BUNDLE_REL;
        match resolve_rel(root, Path::new(rel_str)) {
            Ok(Resolution::Exists {
                rel: rel_target,
                meta,
            }) => {
                if is_fallback {
                    fallback_target = Some(rel_target.clone());
                }
                if meta.is_dir() {
                    skipped_paths.push(SkippedPath {
                        path: rel_str.to_string(),
                        reason: "bundle_is_directory".to_string(),
                    });
                    continue;
                }
                if !meta.file_type().is_file() {
                    skipped_paths.push(SkippedPath {
                        path: rel_str.to_string(),
                        reason: "not a regular file".to_string(),
                    });
                    continue;
                }
                if meta.len() > MAX_PEM_BUNDLE_BYTES {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&rel_target),
                        reason: size_cap_reason(MAX_PEM_BUNDLE_BYTES),
                    });
                    continue;
                }
                charge_aggregate(&mut aggregate_bytes, meta.len())?;
                system_targets.push((rel_str, rel_target.clone()));
                candidates.push(Candidate {
                    rel_path: PathBuf::from(rel_str),
                    target_rel: rel_target,
                    format: CandidateFormat::Pem,
                    exists: true,
                });
            }
            Ok(Resolution::Missing { rel }) => {
                if is_fallback {
                    fallback_target = Some(rel);
                    fallback_missing = true;
                }
            }
            Ok(Resolution::Unresolvable) => {
                if is_fallback {
                    fallback_unresolvable = true;
                }
            }
            Err(TrustError::Symlink(reason)) => {
                skipped_paths.push(SkippedPath {
                    path: rel_str.to_string(),
                    reason,
                });
            }
            Err(e) => return Err(discovery_failure(rel_str, &e)),
        }
    }

    // 2. Discover Anchor Targets
    for (dir_rel, file_rel) in ANCHOR_TARGETS {
        let dir_exists = match resolve_rel(root, Path::new(dir_rel)) {
            Ok(Resolution::Exists { meta, .. }) => meta.is_dir(),
            Ok(Resolution::Missing { .. }) | Ok(Resolution::Unresolvable) => false,
            Err(TrustError::Symlink(_)) => false,
            Err(e) => return Err(discovery_failure(dir_rel, &e)),
        };
        if !dir_exists {
            continue;
        }

        match resolve_rel(root, Path::new(file_rel)) {
            Ok(Resolution::Exists {
                rel: rel_target,
                meta,
            }) => {
                let reason = if meta.is_dir() {
                    Some("bundle_is_directory".to_string())
                } else if !meta.file_type().is_file() {
                    Some("not a regular file".to_string())
                } else if meta.len() > MAX_PEM_BUNDLE_BYTES {
                    Some(size_cap_reason(MAX_PEM_BUNDLE_BYTES))
                } else {
                    None
                };
                if let Some(reason) = reason {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&rel_target),
                        reason,
                    });
                    continue;
                }
                charge_aggregate(&mut aggregate_bytes, meta.len())?;
                candidates.push(Candidate {
                    rel_path: PathBuf::from(file_rel),
                    target_rel: rel_target,
                    format: CandidateFormat::Pem,
                    exists: true,
                });
            }
            Ok(Resolution::Missing { rel: rel_target }) => {
                candidates.push(Candidate {
                    rel_path: PathBuf::from(file_rel),
                    target_rel: rel_target,
                    format: CandidateFormat::Pem,
                    exists: false,
                });
            }
            Ok(Resolution::Unresolvable) => {
                skipped_paths.push(SkippedPath {
                    path: file_rel.to_string(),
                    reason: "unresolvable_target".to_string(),
                });
            }
            Err(TrustError::Symlink(reason)) => {
                skipped_paths.push(SkippedPath {
                    path: file_rel.to_string(),
                    reason,
                });
            }
            Err(e) => return Err(discovery_failure(file_rel, &e)),
        }
    }

    // 3. Tree Walk (Bounded Discovery).
    //
    // The pending queue holds rootfs-relative paths, never open descriptors, so the
    // number of descriptors held is bounded (root handle, at most two handles while
    // re-opening a directory component by component, and one for enumeration)
    // regardless of tree shape. Each directory is re-opened from the root handle
    // with O_DIRECTORY|O_NOFOLLOW per component. Any open or enumeration failure
    // aborts the whole install before anything in the rootfs is modified, so the
    // result never depends on the host's open-file limit.
    let mut dirs_to_visit: Vec<(PathBuf, usize)> = vec![(PathBuf::new(), 0usize)];

    while let Some((current_rel, depth)) = dirs_to_visit.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(TrustError::Cert(
                "rootfs directory depth exceeds limit".to_string(),
            ));
        }

        THREAD_BEFORE_DIR_ENUM_HOOK.with(|cell| {
            if let Some(ref hook) = *cell.borrow() {
                hook();
            }
        });

        let discovery_err = |what: &str, e: &dyn std::fmt::Display| {
            TrustError::Cert(format!(
                "rootfs discovery failed: {} '{}': {}",
                what,
                encode_path_lossless(&current_rel),
                e
            ))
        };

        let current_dir_handle = open_rel_dir_from_root(root, &current_rel)
            .map_err(|e| discovery_err("cannot open directory", &e))?;

        let current_proc_path = format!("/proc/self/fd/{}", current_dir_handle.as_raw_fd());
        let dir_entries = fs::read_dir(&current_proc_path)
            .map_err(|e| discovery_err("cannot enumerate directory", &e))?;

        // Enforce entry budget WHILE enumerating, before retaining each entry
        let mut sorted_entries = Vec::new();
        for entry in dir_entries {
            total_tree_entries += 1;
            if total_tree_entries > MAX_TREE_ENTRIES {
                return Err(TrustError::Cert(
                    "rootfs entry count exceeds limit".to_string(),
                ));
            }

            let e = entry.map_err(|e| discovery_err("cannot enumerate directory", &e))?;
            let file_type = e
                .file_type()
                .map_err(|err| discovery_err("cannot read entry type in", &err))?;
            sorted_entries.push((e.file_name(), file_type));
        }
        // Release enumeration and directory descriptors before descending.
        drop(current_dir_handle);
        sorted_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let parent_name = current_rel
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let in_bundle_dir = parent_name == "certifi" || parent_name == "ssl";

        for (file_name, file_type) in sorted_entries {
            let entry_rel = current_rel.join(&file_name);

            if file_type.is_dir() {
                if (file_name == "cacert.pem" && in_bundle_dir) || file_name == "cacerts" {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&entry_rel),
                        reason: "bundle_is_directory".to_string(),
                    });
                    continue;
                }

                // Queue the relative path only; it is re-opened from the root
                // handle (O_DIRECTORY | O_NOFOLLOW per component) when visited.
                dirs_to_visit.push((entry_rel, depth + 1));
                continue;
            }

            if file_name == "cacert.pem" {
                if in_bundle_dir {
                    discover_store_file(
                        root,
                        entry_rel,
                        CandidateFormat::Pem,
                        &mut candidates,
                        &mut skipped_paths,
                        &mut aggregate_bytes,
                    )?;
                }
            } else if file_name == "cacerts" {
                discover_store_file(
                    root,
                    entry_rel,
                    CandidateFormat::Jks,
                    &mut candidates,
                    &mut skipped_paths,
                    &mut aggregate_bytes,
                )?;
            }
        }
    }

    if candidates.len() + skipped_paths.len() > MAX_REPORT_ENTRIES {
        return Err(TrustError::Cert("report size exceeds limit".to_string()));
    }

    // 4. Deterministic Discovery & Target Conflict Detection
    let mut candidate_targets: BTreeMap<PathBuf, CandidateFormat> = BTreeMap::new();
    let mut conflicted_targets: HashSet<PathBuf> = HashSet::new();

    for cand in &candidates {
        if let Some(&existing_fmt) = candidate_targets.get(&cand.target_rel) {
            if existing_fmt != cand.format {
                conflicted_targets.insert(cand.target_rel.clone());
            }
        } else {
            candidate_targets.insert(cand.target_rel.clone(), cand.format);
        }
    }

    // Collect format conflict skips
    for cand in &candidates {
        if conflicted_targets.contains(&cand.target_rel) {
            skipped_paths.push(SkippedPath {
                path: encode_path_lossless(&cand.rel_path),
                reason: "conflicting_target_format".to_string(),
            });
        }
    }

    // Retain only non-conflicted candidates
    candidates.retain(|c| !conflicted_targets.contains(&c.target_rel));

    // Sort candidates deterministically
    candidates.sort_by(|a, b| {
        a.rel_path
            .cmp(&b.rel_path)
            .then_with(|| a.target_rel.cmp(&b.target_rel))
    });

    Ok(InstallPlan {
        candidates,
        skipped_paths,
        conflicted_targets,
        system_targets,
        fallback_target,
        fallback_missing,
        fallback_unresolvable,
    })
}

/// Reject a report destination that equals, contains or lies inside any rootfs
/// location the plan may write.
fn check_report_against_plan(
    rootfs: &Path,
    report_path: &Path,
    plan: &InstallPlan,
) -> Result<(), TrustError> {
    let mut targets: Vec<&Path> = plan
        .candidates
        .iter()
        .map(|c| c.target_rel.as_path())
        .collect();
    if let Some(ref t) = plan.fallback_target {
        targets.push(t.as_path());
    }
    targets.sort();
    targets.dedup();
    for target in targets {
        crate::cert::check_not_alias(
            report_path,
            &rootfs.join(target),
            "report",
            "trust store target",
        )?;
    }
    Ok(())
}

/// Install the CA certificate into every trust store found under rootfs,
/// creating new entries as guest root (0:0). See [`install_ca_with_options`].
///
/// # Precondition
/// The rootfs must not be modified concurrently during install (exclusive access).
pub fn install_ca(rootfs: &Path, ca_cert_pem: &str) -> Result<InstallReport, TrustError> {
    install_ca_with_options(rootfs, ca_cert_pem, &InstallOptions::default())
}

/// Install the CA certificate into every trust store found under rootfs.
///
/// Discovery completes (within its budgets) before anything is modified. The
/// report destination, if given, is checked against the discovery plan, and the
/// guest owner is verified to be settable when entries must be created, both
/// before the first mutation.
///
/// # Precondition
/// The rootfs must not be modified concurrently during install (exclusive access).
pub fn install_ca_with_options(
    rootfs: &Path,
    ca_cert_pem: &str,
    options: &InstallOptions,
) -> Result<InstallReport, TrustError> {
    // Enforce named certificate-input cap
    if ca_cert_pem.len() as u64 > MAX_CA_CERT_INPUT_BYTES {
        return Err(TrustError::Cert(format!(
            "ca-cert input exceeds size cap of {} bytes",
            MAX_CA_CERT_INPUT_BYTES
        )));
    }

    if ca_cert_pem.contains("PRIVATE KEY") {
        return Err(TrustError::Cert(
            "ca-cert contains a private key".to_string(),
        ));
    }

    let parsed_blocks = pem::parse_many(ca_cert_pem.as_bytes())
        .map_err(|e| TrustError::Cert(format!("invalid PEM in ca-cert: {}", e)))?;

    if parsed_blocks.is_empty() {
        return Err(TrustError::Cert(
            "ca-cert contains no PEM blocks".to_string(),
        ));
    }

    for block in &parsed_blocks {
        if block.tag().contains("PRIVATE KEY") {
            return Err(TrustError::Cert(
                "ca-cert contains a private key".to_string(),
            ));
        }
        if block.tag() != "CERTIFICATE" {
            return Err(TrustError::Cert(format!(
                "unexpected block type '{}' in ca-cert; expected only CERTIFICATE",
                block.tag()
            )));
        }
    }

    if parsed_blocks.len() != 1 {
        return Err(TrustError::Cert(format!(
            "expected exactly one CERTIFICATE block in ca-cert, found {}",
            parsed_blocks.len()
        )));
    }

    let ca_cert_der = parsed_blocks[0].contents();

    // Validate complete X.509 CA certificate, including basicConstraints (CA:true) and signature
    crate::asn1::validate_ca_certificate(ca_cert_der)?;

    let mut canonical_ca_pem = pem::encode(&pem::Pem::new("CERTIFICATE", ca_cert_der.to_vec()));
    if !canonical_ca_pem.ends_with('\n') {
        canonical_ca_pem.push('\n');
    }

    let mut hasher = Sha256::new();
    hasher.update(ca_cert_der);
    let ca_cert_sha256 = hex::encode(hasher.finalize());

    let root_handle = open_dir_handle(rootfs)?;
    let owner = options.owner;

    // PHASE 1: complete discovery; nothing is modified before it succeeds.
    let plan = discover_plan(&root_handle)?;

    if let Some(ref report_path) = options.report_path {
        check_report_against_plan(rootfs, report_path, &plan)?;
    }

    let has_system_candidate = plan.candidates.iter().any(|c| c.is_system_bundle());
    if !has_system_candidate && plan.fallback_unresolvable {
        return Err(TrustError::Cert(
            "failed to establish a usable system trust bundle containing CA: fallback target cannot be resolved".to_string(),
        ));
    }
    let creates_entries = plan.candidates.iter().any(|c| !c.exists)
        || (!has_system_candidate && plan.fallback_missing);
    if creates_entries {
        verify_guest_owner_settable(owner)?;
    }

    let InstallPlan {
        candidates,
        mut skipped_paths,
        conflicted_targets,
        system_targets,
        ..
    } = plan;

    let mut modified_paths: HashSet<PathBuf> = HashSet::new();
    let mut processed_targets: HashSet<PathBuf> = HashSet::new();
    let mut successful_system_bundle_targets: HashSet<PathBuf> = HashSet::new();
    let mut first_existing_system_bundle: Option<String> = None;

    // PHASE 2: Execution (Handle-Anchored Mutations)
    for cand in candidates {
        let is_system_bundle = cand.is_system_bundle();

        if processed_targets.insert(cand.target_rel.clone()) {
            let (parent_dir, file_name) =
                match open_parent_from_root(&root_handle, &cand.target_rel) {
                    Ok(p) => p,
                    Err(e) => {
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&cand.target_rel),
                            reason: e.to_string(),
                        });
                        continue;
                    }
                };

            match cand.format {
                CandidateFormat::Pem => {
                    let content = match read_file_capped_from_parent(
                        &parent_dir,
                        &file_name,
                        MAX_PEM_BUNDLE_BYTES,
                    ) {
                        Ok(c) => c,
                        Err(TrustError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                            Vec::new()
                        }
                        Err(e) => {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&cand.target_rel),
                                reason: e.to_string(),
                            });
                            continue;
                        }
                    };

                    // Reject if file appears to be a JKS or PKCS#12 keystore
                    if (content.len() >= 4 && content[0..4] == [0xFE, 0xED, 0xFE, 0xED])
                        || is_pkcs12(&content)
                    {
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&cand.target_rel),
                            reason: "conflicting_target_format".to_string(),
                        });
                        continue;
                    }

                    if !content.is_empty()
                        && bundle_contains_cert(&content, &canonical_ca_pem, ca_cert_der)
                    {
                        if is_system_bundle {
                            successful_system_bundle_targets.insert(cand.target_rel.clone());
                        }
                        continue;
                    }

                    let new_content = append_pem(content, &canonical_ca_pem);

                    match atomic_write_preserving_handle(
                        &parent_dir,
                        &file_name,
                        &new_content,
                        NEW_FILE_MODE,
                        owner,
                    ) {
                        Ok(()) => {
                            modified_paths.insert(cand.target_rel.clone());
                            if is_system_bundle {
                                successful_system_bundle_targets.insert(cand.target_rel.clone());
                            }
                        }
                        Err(e) => {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&cand.target_rel),
                                reason: e.to_string(),
                            });
                        }
                    }
                }
                CandidateFormat::Jks => {
                    let content = match read_file_capped_from_parent(
                        &parent_dir,
                        &file_name,
                        MAX_JKS_BYTES,
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&cand.target_rel),
                                reason: e.to_string(),
                            });
                            continue;
                        }
                    };

                    if is_pkcs12(&content) {
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&cand.target_rel),
                            reason: "unsupported_pkcs12".to_string(),
                        });
                        continue;
                    }

                    match inject_ca_into_jks(&content, ca_cert_der, 0) {
                        Ok(Some(new_jks_bytes)) => {
                            match atomic_write_preserving_handle(
                                &parent_dir,
                                &file_name,
                                &new_jks_bytes,
                                NEW_FILE_MODE,
                                owner,
                            ) {
                                Ok(()) => {
                                    modified_paths.insert(cand.target_rel.clone());
                                }
                                Err(e) => {
                                    skipped_paths.push(SkippedPath {
                                        path: encode_path_lossless(&cand.target_rel),
                                        reason: e.to_string(),
                                    });
                                }
                            }
                        }
                        Ok(None) => {
                            // Already present and identical
                        }
                        Err(e) => {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&cand.target_rel),
                                reason: e.to_string(),
                            });
                        }
                    }
                }
            }
        } else if is_system_bundle && successful_system_bundle_targets.contains(&cand.target_rel) {
            successful_system_bundle_targets.insert(cand.target_rel.clone());
        }
    }

    // Select first existing system bundle by known_system_bundles priority order
    for rel_str in KNOWN_SYSTEM_BUNDLES {
        if let Some((_, target)) = system_targets.iter().find(|(k, _)| *k == rel_str) {
            if successful_system_bundle_targets.contains(target) {
                first_existing_system_bundle = Some(format!("/{}", rel_str));
                break;
            }
        }
    }

    // 6. System Bundle Establishment & Fallback
    let mut established_system_bundle = first_existing_system_bundle;

    if established_system_bundle.is_none() {
        let (rel_target, target_meta) = match resolve_rel(
            &root_handle,
            Path::new(FALLBACK_BUNDLE_REL),
        )? {
            Resolution::Exists { rel, meta } => (rel, Some(meta)),
            Resolution::Missing { rel } => (rel, None),
            Resolution::Unresolvable => {
                return Err(TrustError::Cert(
                        "failed to establish a usable system trust bundle containing CA: fallback target cannot be resolved".to_string(),
                    ));
            }
        };

        // Fallback processing must apply format-conflict exclusions and candidate plan
        if conflicted_targets.contains(&rel_target) {
            skipped_paths.push(SkippedPath {
                path: encode_path_lossless(&rel_target),
                reason: "conflicting_target_format".to_string(),
            });
            return Err(TrustError::Cert(
                "failed to establish a usable system trust bundle containing CA: fallback target has format conflict".to_string(),
            ));
        }

        match target_meta {
            Some(meta) => {
                if meta.is_dir() {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&rel_target),
                        reason: "bundle_is_directory".to_string(),
                    });
                } else if !meta.file_type().is_file() {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&rel_target),
                        reason: "not a regular file".to_string(),
                    });
                } else if meta.len() > MAX_PEM_BUNDLE_BYTES {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&rel_target),
                        reason: size_cap_reason(MAX_PEM_BUNDLE_BYTES),
                    });
                } else {
                    let (parent_dir, file_name) = open_parent_from_root(&root_handle, &rel_target)?;
                    let content = read_file_capped_from_parent(
                        &parent_dir,
                        &file_name,
                        MAX_PEM_BUNDLE_BYTES,
                    )?;

                    // Exclude JKS and PKCS#12 targets, preserve rejected targets byte-for-byte
                    if (content.len() >= 4 && content[0..4] == [0xFE, 0xED, 0xFE, 0xED])
                        || is_pkcs12(&content)
                    {
                        let reason = if is_pkcs12(&content) {
                            "unsupported_pkcs12"
                        } else {
                            "conflicting_target_format"
                        };
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&rel_target),
                            reason: reason.to_string(),
                        });
                        return Err(TrustError::Cert(
                            "failed to establish a usable system trust bundle containing CA: fallback target format rejected".to_string(),
                        ));
                    }

                    let contains = !content.is_empty()
                        && bundle_contains_cert(&content, &canonical_ca_pem, ca_cert_der);
                    if !contains {
                        let new_content = append_pem(content, &canonical_ca_pem);
                        atomic_write_preserving_handle(
                            &parent_dir,
                            &file_name,
                            &new_content,
                            NEW_FILE_MODE,
                            owner,
                        )?;
                        modified_paths.insert(rel_target);
                    }
                    established_system_bundle = Some(FALLBACK_BUNDLE_GUEST_PATH.to_string());
                }
            }
            None => {
                // Create the fallback bundle and any missing parent directories
                // with the guest owner and deterministic modes; roll back the
                // created directories if anything fails.
                let mut created: CreatedDirs = Vec::new();
                let res = (|| -> Result<(), TrustError> {
                    let (parent_dir, file_name) =
                        ensure_parent_dirs(&root_handle, &rel_target, owner, &mut created)?;
                    atomic_write_preserving_handle(
                        &parent_dir,
                        &file_name,
                        canonical_ca_pem.as_bytes(),
                        NEW_FILE_MODE,
                        owner,
                    )
                })();
                if let Err(e) = res {
                    remove_created_dirs(created);
                    return Err(e);
                }
                modified_paths.insert(rel_target);
                established_system_bundle = Some(FALLBACK_BUNDLE_GUEST_PATH.to_string());
            }
        }
    }

    let chosen_bundle = match established_system_bundle {
        Some(b) => b,
        None => {
            return Err(TrustError::Cert(
                "failed to establish a usable system trust bundle containing CA".to_string(),
            ));
        }
    };

    let mut env_defaults = BTreeMap::new();
    env_defaults.insert("SSL_CERT_FILE".to_string(), chosen_bundle.clone());
    env_defaults.insert("REQUESTS_CA_BUNDLE".to_string(), chosen_bundle.clone());
    env_defaults.insert("CURL_CA_BUNDLE".to_string(), chosen_bundle.clone());
    env_defaults.insert("PIP_CERT".to_string(), chosen_bundle.clone());
    env_defaults.insert("NODE_EXTRA_CA_CERTS".to_string(), chosen_bundle.clone());
    env_defaults.insert("GIT_SSL_CAINFO".to_string(), chosen_bundle.clone());
    env_defaults.insert("CARGO_HTTP_CAINFO".to_string(), chosen_bundle);

    let mut modified_vec: Vec<PathBuf> = modified_paths.into_iter().collect();
    modified_vec.sort();
    let modified_strings: Vec<String> = modified_vec
        .iter()
        .map(|p| encode_path_lossless(p))
        .collect();

    skipped_paths.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.reason.cmp(&b.reason)));
    skipped_paths.dedup();

    Ok(InstallReport {
        ca_cert_sha256,
        modified_paths: modified_strings,
        skipped_paths,
        env_defaults,
    })
}

/// Check that a report destination does not collide with any trust store the
/// installer may write. Runs the same complete, bounded discovery as
/// installation and fails on any discovery error.
pub fn check_report_target_collision(rootfs: &Path, report_path: &Path) -> Result<(), TrustError> {
    let root_handle = open_dir_handle(rootfs)?;
    let plan = discover_plan(&root_handle)?;
    check_report_against_plan(rootfs, report_path, &plan)
}
