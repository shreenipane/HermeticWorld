#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
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

/// Resolves symlinks strictly within the rootfs as if rootfs were `/`.
/// Absolute symlink targets are interpreted relative to rootfs.
/// Retains a root directory handle and resolves each component through validated directory handles.
/// Detects symlink loops and limits hop depth to 40.
pub fn resolve_in_rootfs(rootfs: &Path, path: &Path) -> Result<PathBuf, TrustError> {
    use std::collections::VecDeque;
    use std::os::unix::io::AsRawFd;

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

    let mut queue = VecDeque::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => queue.push_back(PathBuf::from(c)),
            Component::ParentDir => queue.push_back(PathBuf::from("..")),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }

    // Stack of open directory handles: (File, rel_path)
    let mut handle_stack: Vec<(fs::File, PathBuf)> = vec![(root_handle, PathBuf::new())];
    let mut hops = 0;
    const MAX_HOPS: usize = 40;

    while let Some(comp) = queue.pop_front() {
        if comp == Path::new("..") {
            if handle_stack.len() > 1 {
                handle_stack.pop();
            }
            continue;
        }

        let current_fd = handle_stack.last().unwrap().0.as_raw_fd();
        let child_proc = PathBuf::from(format!("/proc/self/fd/{}", current_fd)).join(&comp);

        let meta = match fs::symlink_metadata(&child_proc) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut current_rel = handle_stack.last().unwrap().1.clone();
                current_rel.push(&comp);
                for rem in queue {
                    if rem == Path::new("..") {
                        current_rel.pop();
                    } else {
                        current_rel.push(rem);
                    }
                }
                return Ok(rootfs.join(current_rel));
            }
            Err(e) => {
                return Err(TrustError::Symlink(format!(
                    "metadata {}: {}",
                    comp.display(),
                    e
                )));
            }
        };

        if meta.is_symlink() {
            hops += 1;
            if hops > MAX_HOPS {
                return Err(TrustError::Symlink("symlink loop detected".to_string()));
            }

            let target = fs::read_link(&child_proc)
                .map_err(|e| TrustError::Symlink(format!("read_link {}: {}", comp.display(), e)))?;

            if target.is_absolute() {
                handle_stack.truncate(1);
                let rel_target = target.strip_prefix("/").unwrap_or(&target);
                let target_comps: Vec<PathBuf> = rel_target
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
            } else {
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
            }
        } else if meta.is_dir() {
            let next_dir = open_child_dir(current_fd, comp.as_os_str())?;
            let next_rel = handle_stack.last().unwrap().1.join(&comp);
            handle_stack.push((next_dir, next_rel));
        } else {
            let mut current_rel = handle_stack.last().unwrap().1.clone();
            current_rel.push(&comp);
            if !queue.is_empty() {
                return Err(TrustError::Symlink(format!(
                    "not a directory in path: {}",
                    comp.display()
                )));
            }
            return Ok(rootfs.join(current_rel));
        }
    }

    let final_rel = &handle_stack.last().unwrap().1;
    Ok(rootfs.join(final_rel))
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

#[cfg(unix)]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(unix)]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(unix)]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(unix)]
const O_CLOEXEC: i32 = 0o2000000;
#[cfg(unix)]
const ELOOP: i32 = 40;

pub static FORCE_CHOWN_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub static BEFORE_USE_HOOK: std::sync::RwLock<Option<Box<dyn Fn() + Send + Sync>>> =
    std::sync::RwLock::new(None);

thread_local! {
    static THREAD_CHOWN_FAILURE: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
    static THREAD_BEFORE_USE_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    static THREAD_BEFORE_DIR_ENUM_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
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

/// Open a child directory through an existing directory handle without following symlinks.
pub fn open_child_dir<P: AsRef<std::ffi::OsStr> + ?Sized>(
    parent_fd: std::os::unix::io::RawFd,
    comp: &P,
) -> Result<fs::File, TrustError> {
    let comp = comp.as_ref();
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

/// Open parent directory handle for a rootfs-relative path, anchoring every step to descriptors.
pub fn open_parent_dir_handle(
    rootfs: &Path,
    rel_path: &Path,
) -> Result<(fs::File, std::ffi::OsString), TrustError> {
    use std::os::unix::io::AsRawFd;

    let mut current_dir = open_dir_handle(rootfs)?;
    let mut comps: Vec<std::ffi::OsString> = Vec::new();
    for comp in rel_path.components() {
        if let Component::Normal(c) = comp {
            comps.push(c.to_os_string());
        }
    }
    if comps.is_empty() {
        return Err(TrustError::Cert("empty relative path".to_string()));
    }
    let file_name = comps.pop().unwrap();

    for comp in &comps {
        let next_dir = open_child_dir(current_dir.as_raw_fd(), comp.as_os_str())?;
        current_dir = next_dir;
    }

    Ok((current_dir, file_name))
}

/// Ensure all parent directories exist inside rootfs and return parent directory handle and filename.
pub fn ensure_parent_dirs_in_rootfs(
    rootfs: &Path,
    rel_path: &Path,
) -> Result<(fs::File, std::ffi::OsString), TrustError> {
    use std::os::unix::io::AsRawFd;

    let mut current_dir = open_dir_handle(rootfs)?;
    let mut comps: Vec<std::ffi::OsString> = Vec::new();
    for comp in rel_path.components() {
        if let Component::Normal(c) = comp {
            comps.push(c.to_os_string());
        }
    }
    if comps.is_empty() {
        return Err(TrustError::Cert("empty relative path".to_string()));
    }
    let file_name = comps.pop().unwrap();

    for comp in &comps {
        let fd = current_dir.as_raw_fd();
        let child_proc = PathBuf::from(format!("/proc/self/fd/{}", fd)).join(comp);
        match open_child_dir(fd, comp.as_os_str()) {
            Ok(d) => current_dir = d,
            Err(_) => {
                let _ = fs::create_dir(&child_proc);
                let next_dir = open_child_dir(fd, comp.as_os_str())?;
                current_dir = next_dir;
            }
        }
    }

    Ok((current_dir, file_name))
}

/// Read a file up to `cap` bytes through a parent directory handle.
/// Prevents symlink following and FIFO blocking, validating the opened descriptor.
pub fn read_file_capped_from_parent<P: AsRef<std::ffi::OsStr> + ?Sized>(
    parent_dir: &fs::File,
    file_name: &P,
    cap: u64,
) -> Result<Vec<u8>, TrustError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file_name = file_name.as_ref();
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
    if let Ok(guard) = BEFORE_USE_HOOK.read() {
        if let Some(ref hook) = *guard {
            hook();
        }
    }

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

/// Read a file up to `cap` bytes by anchoring to its parent directory handle.
fn read_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>, TrustError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_file = open_dir_handle(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| TrustError::Cert("invalid path has no file name".to_string()))?;
    read_file_capped_from_parent(&parent_file, file_name, cap)
}

/// Write data atomically into parent directory handle: writes to a temporary file
/// anchored to the directory handle, sets permissions and ownership through descriptors,
/// flushes, and replaces atomically through the handle.
pub fn atomic_write_preserving_handle<P: AsRef<std::ffi::OsStr> + ?Sized>(
    parent_dir: &fs::File,
    file_name: &P,
    data: &[u8],
    new_file_mode: Option<u32>,
) -> Result<(), TrustError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    let file_name = file_name.as_ref();
    let parent_fd = parent_dir.as_raw_fd();
    let target_proc_path = PathBuf::from(format!("/proc/self/fd/{}", parent_fd)).join(file_name);

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
    if let Ok(guard) = BEFORE_USE_HOOK.read() {
        if let Some(ref hook) = *guard {
            hook();
        }
    }

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
        let tmp_proc_path = PathBuf::from(format!("/proc/self/fd/{}", parent_fd)).join(&tmp_name);

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

                    #[cfg(unix)]
                    {
                        if let Some(ref meta) = existing_meta {
                            let target_uid = meta.uid();
                            let target_gid = meta.gid();
                            let temp_meta = temp_file.metadata()?;
                            let temp_uid = temp_meta.uid();
                            let temp_gid = temp_meta.gid();

                            let is_injected = THREAD_CHOWN_FAILURE.with(|c| *c.borrow())
                                || FORCE_CHOWN_FAILURE.load(std::sync::atomic::Ordering::SeqCst);

                            // Defects 8 & 10: Change ownership if either UID or GID differs,
                            // or inject failure at the ownership operation, through normal execution path
                            if is_injected || target_uid != temp_uid || target_gid != temp_gid {
                                let temp_proc = format!("/proc/self/fd/{}", temp_file.as_raw_fd());
                                let chown_res = if is_injected {
                                    Err(std::io::Error::new(
                                        std::io::ErrorKind::PermissionDenied,
                                        "forced chown failure for test: Operation not permitted",
                                    ))
                                } else {
                                    std::os::unix::fs::chown(
                                        &temp_proc,
                                        Some(target_uid),
                                        Some(target_gid),
                                    )
                                };
                                chown_res.map_err(TrustError::Io)?;
                            }

                            // Defect 8: Restore permissions AFTER ownership changes so special mode bits are preserved
                            let perms = meta.permissions();
                            temp_file.set_permissions(perms)?;
                        } else if let Some(mode) = new_file_mode {
                            let perms = fs::Permissions::from_mode(mode);
                            temp_file.set_permissions(perms)?;
                        }
                    }

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

/// Write data atomically into target_path: anchors to parent directory handle,
/// writes to a temporary file, sets matching permissions and ownership (propagating failures),
/// flushes, and renames through the handle.
pub fn atomic_write_preserving(
    target_path: &Path,
    data: &[u8],
    new_file_mode: Option<u32>,
) -> Result<(), TrustError> {
    if let Ok(m) = fs::symlink_metadata(target_path) {
        if m.file_type().is_symlink() {
            return Err(TrustError::Symlink(format!(
                "target '{}' is a symlink",
                target_path.display()
            )));
        }
        if !m.file_type().is_file() {
            return Err(TrustError::Symlink(format!(
                "target '{}' is not a regular file",
                target_path.display()
            )));
        }
    }

    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let parent_file = open_dir_handle(parent)?;
    let file_name = target_path
        .file_name()
        .ok_or_else(|| TrustError::Cert("invalid target path has no file name".to_string()))?;
    atomic_write_preserving_handle(&parent_file, file_name, data, new_file_mode)
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

/// Append CA certificate to a PEM bundle file idempotently and atomically.
/// Returns Ok(true) if modified, Ok(false) if already present.
pub fn append_pem_bundle_idempotent(
    target_path: &Path,
    ca_pem: &str,
    ca_der: &[u8],
) -> Result<bool, TrustError> {
    let content = match read_file_capped(target_path, MAX_PEM_BUNDLE_BYTES) {
        Ok(c) => c,
        Err(TrustError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };

    if !content.is_empty() && bundle_contains_cert(&content, ca_pem, ca_der) {
        return Ok(false);
    }

    let mut new_content = content;
    if !new_content.is_empty() && !new_content.ends_with(b"\n") {
        new_content.push(b'\n');
    }
    new_content.extend_from_slice(ca_pem.as_bytes());
    if !new_content.ends_with(b"\n") {
        new_content.push(b'\n');
    }

    atomic_write_preserving(target_path, &new_content, Some(0o644))?;
    Ok(true)
}

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
}

/// Install the CA certificate into every trust store found under rootfs.
///
/// # Precondition
/// The rootfs must not be modified concurrently during install (exclusive access).
pub fn install_ca(rootfs: &Path, ca_cert_pem: &str) -> Result<InstallReport, TrustError> {
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

    let rootfs_canon = rootfs
        .canonicalize()
        .unwrap_or_else(|_| rootfs.to_path_buf());

    // Helper to turn absolute path inside rootfs into a rootfs-relative PathBuf
    let make_rel_path = |p: &Path| -> PathBuf {
        p.strip_prefix(rootfs)
            .or_else(|_| p.strip_prefix(&rootfs_canon))
            .map(|r| r.to_path_buf())
            .unwrap_or_else(|_| p.to_path_buf())
    };

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut skipped_paths: Vec<SkippedPath> = Vec::new();
    let mut total_tree_entries: usize = 0;
    let mut aggregate_bytes: u64 = 0;

    let root_handle = open_dir_handle(rootfs)?;

    // 1. Discover Known System Bundles
    let known_system_bundles = [
        "etc/ssl/certs/ca-certificates.crt",
        "etc/pki/tls/certs/ca-bundle.crt",
        "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "etc/ssl/cert.pem",
    ];

    for rel_str in &known_system_bundles {
        let bundle_path = rootfs.join(rel_str);
        match resolve_in_rootfs(rootfs, &bundle_path) {
            Ok(target) => {
                let target_meta = match fs::symlink_metadata(&target) {
                    Ok(m) => m,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        skipped_paths.push(SkippedPath {
                            path: rel_str.to_string(),
                            reason: "cannot stat target".to_string(),
                        });
                        continue;
                    }
                };

                let rel_target = make_rel_path(&target);
                if target_meta.is_dir() {
                    skipped_paths.push(SkippedPath {
                        path: rel_str.to_string(),
                        reason: "bundle_is_directory".to_string(),
                    });
                    continue;
                }
                if !target_meta.file_type().is_file() {
                    skipped_paths.push(SkippedPath {
                        path: rel_str.to_string(),
                        reason: "not a regular file".to_string(),
                    });
                    continue;
                }
                if target_meta.len() > MAX_PEM_BUNDLE_BYTES {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&rel_target),
                        reason: format!("file exceeds size cap of {} bytes", MAX_PEM_BUNDLE_BYTES),
                    });
                    continue;
                }

                aggregate_bytes = aggregate_bytes.saturating_add(target_meta.len());
                if aggregate_bytes > MAX_AGGREGATE_BYTES {
                    return Err(TrustError::Cert("aggregate bytes exceed limit".to_string()));
                }

                candidates.push(Candidate {
                    rel_path: PathBuf::from(rel_str),
                    target_rel: rel_target,
                    format: CandidateFormat::Pem,
                });
            }
            Err(e) => {
                let reason = match e {
                    TrustError::Symlink(ref s) => s.clone(),
                    _ => "cannot stat target".to_string(),
                };
                skipped_paths.push(SkippedPath {
                    path: rel_str.to_string(),
                    reason,
                });
            }
        }
    }

    // 2. Discover Anchor Targets
    let anchor_targets = [
        (
            "usr/local/share/ca-certificates",
            "usr/local/share/ca-certificates/hermetic-world-ca.crt",
        ),
        (
            "etc/pki/ca-trust/source/anchors",
            "etc/pki/ca-trust/source/anchors/hermetic-world-ca.pem",
        ),
    ];

    for (dir_rel, file_rel) in &anchor_targets {
        let dir_path = rootfs.join(dir_rel);
        let dir_exists = match resolve_in_rootfs(rootfs, &dir_path) {
            Ok(resolved_dir) => match fs::symlink_metadata(&resolved_dir) {
                Ok(m) => m.is_dir(),
                Err(_) => false,
            },
            Err(_) => false,
        };

        if dir_exists {
            let file_path = rootfs.join(file_rel);
            match resolve_in_rootfs(rootfs, &file_path) {
                Ok(target) => {
                    let rel_target = make_rel_path(&target);
                    if let Ok(m) = fs::symlink_metadata(&target) {
                        if m.is_dir() {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&rel_target),
                                reason: "bundle_is_directory".to_string(),
                            });
                            continue;
                        }
                        if !m.file_type().is_file() {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&rel_target),
                                reason: "not a regular file".to_string(),
                            });
                            continue;
                        }
                        if m.len() > MAX_PEM_BUNDLE_BYTES {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&rel_target),
                                reason: format!(
                                    "file exceeds size cap of {} bytes",
                                    MAX_PEM_BUNDLE_BYTES
                                ),
                            });
                            continue;
                        }
                        aggregate_bytes = aggregate_bytes.saturating_add(m.len());
                        if aggregate_bytes > MAX_AGGREGATE_BYTES {
                            return Err(TrustError::Cert(
                                "aggregate bytes exceed limit".to_string(),
                            ));
                        }
                    }

                    candidates.push(Candidate {
                        rel_path: PathBuf::from(file_rel),
                        target_rel: rel_target,
                        format: CandidateFormat::Pem,
                    });
                }
                Err(e) => {
                    let reason = match e {
                        TrustError::Symlink(ref s) => s.clone(),
                        _ => "cannot stat target".to_string(),
                    };
                    skipped_paths.push(SkippedPath {
                        path: file_rel.to_string(),
                        reason,
                    });
                }
            }
        }
    }

    // 3. Tree Walk (Bounded Discovery using validated directory handles)
    let mut dirs_to_visit = vec![(root_handle.try_clone()?, PathBuf::new(), 0usize)];

    while let Some((current_dir_handle, current_rel, depth)) = dirs_to_visit.pop() {
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

        let current_proc_path = format!("/proc/self/fd/{}", current_dir_handle.as_raw_fd());
        let dir_entries = match fs::read_dir(&current_proc_path) {
            Ok(e) => e,
            Err(_) => {
                skipped_paths.push(SkippedPath {
                    path: encode_path_lossless(&current_rel),
                    reason: "read_dir error".to_string(),
                });
                continue;
            }
        };

        // Defect 3: Enforce entry budget WHILE enumerating, before retaining each entry
        let mut sorted_entries = Vec::new();
        for entry in dir_entries {
            total_tree_entries += 1;
            if total_tree_entries > MAX_TREE_ENTRIES {
                return Err(TrustError::Cert(
                    "rootfs entry count exceeds limit".to_string(),
                ));
            }

            match entry {
                Ok(e) => sorted_entries.push(e),
                Err(_) => {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&current_rel),
                        reason: "read_dir error".to_string(),
                    });
                }
            }
        }
        sorted_entries.sort_by_key(|e| e.file_name());

        for entry in sorted_entries {
            let file_name = entry.file_name();
            let entry_rel = current_rel.join(&file_name);
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&entry_rel),
                        reason: "file_type error".to_string(),
                    });
                    continue;
                }
            };

            if file_type.is_dir() {
                if file_name == "cacert.pem" {
                    let parent_name = current_rel
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    if parent_name == "certifi" || parent_name == "ssl" {
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&entry_rel),
                            reason: "bundle_is_directory".to_string(),
                        });
                        continue;
                    }
                } else if file_name == "cacerts" {
                    skipped_paths.push(SkippedPath {
                        path: encode_path_lossless(&entry_rel),
                        reason: "bundle_is_directory".to_string(),
                    });
                    continue;
                }

                // Defect 1: Open child directory handle safely with O_DIRECTORY | O_NOFOLLOW
                match open_child_dir(current_dir_handle.as_raw_fd(), comp_as_os_str(&file_name)) {
                    Ok(child_handle) => {
                        dirs_to_visit.push((child_handle, entry_rel, depth + 1));
                    }
                    Err(_) => {
                        continue;
                    }
                }
                continue;
            }

            let entry_path = rootfs.join(&entry_rel);

            if file_name == "cacert.pem" {
                let parent_name = current_rel
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();

                if parent_name == "certifi" || parent_name == "ssl" {
                    match resolve_in_rootfs(rootfs, &entry_path) {
                        Ok(target) => {
                            let target_meta = match fs::symlink_metadata(&target) {
                                Ok(m) => m,
                                Err(_) => {
                                    skipped_paths.push(SkippedPath {
                                        path: encode_path_lossless(&entry_rel),
                                        reason: "cannot stat target".to_string(),
                                    });
                                    continue;
                                }
                            };

                            let rel_target = make_rel_path(&target);
                            if target_meta.is_dir() {
                                skipped_paths.push(SkippedPath {
                                    path: encode_path_lossless(&entry_rel),
                                    reason: "bundle_is_directory".to_string(),
                                });
                                continue;
                            }
                            if !target_meta.file_type().is_file() {
                                skipped_paths.push(SkippedPath {
                                    path: encode_path_lossless(&entry_rel),
                                    reason: "not a regular file".to_string(),
                                });
                                continue;
                            }
                            if target_meta.len() > MAX_PEM_BUNDLE_BYTES {
                                skipped_paths.push(SkippedPath {
                                    path: encode_path_lossless(&rel_target),
                                    reason: format!(
                                        "file exceeds size cap of {} bytes",
                                        MAX_PEM_BUNDLE_BYTES
                                    ),
                                });
                                continue;
                            }

                            aggregate_bytes = aggregate_bytes.saturating_add(target_meta.len());
                            if aggregate_bytes > MAX_AGGREGATE_BYTES {
                                return Err(TrustError::Cert(
                                    "aggregate bytes exceed limit".to_string(),
                                ));
                            }

                            candidates.push(Candidate {
                                rel_path: entry_rel,
                                target_rel: rel_target,
                                format: CandidateFormat::Pem,
                            });
                        }
                        Err(e) => {
                            let reason = match e {
                                TrustError::Symlink(ref s) => s.clone(),
                                _ => "cannot stat target".to_string(),
                            };
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&entry_rel),
                                reason,
                            });
                        }
                    }
                }
            } else if file_name == "cacerts" {
                match resolve_in_rootfs(rootfs, &entry_path) {
                    Ok(target) => {
                        let target_meta = match fs::symlink_metadata(&target) {
                            Ok(m) => m,
                            Err(_) => {
                                skipped_paths.push(SkippedPath {
                                    path: encode_path_lossless(&entry_rel),
                                    reason: "cannot stat target".to_string(),
                                });
                                continue;
                            }
                        };

                        let rel_target = make_rel_path(&target);
                        if target_meta.is_dir() {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&entry_rel),
                                reason: "bundle_is_directory".to_string(),
                            });
                            continue;
                        }
                        if !target_meta.file_type().is_file() {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&entry_rel),
                                reason: "not a regular file".to_string(),
                            });
                            continue;
                        }
                        if target_meta.len() > MAX_JKS_BYTES {
                            skipped_paths.push(SkippedPath {
                                path: encode_path_lossless(&rel_target),
                                reason: format!("file exceeds size cap of {} bytes", MAX_JKS_BYTES),
                            });
                            continue;
                        }

                        aggregate_bytes = aggregate_bytes.saturating_add(target_meta.len());
                        if aggregate_bytes > MAX_AGGREGATE_BYTES {
                            return Err(TrustError::Cert(
                                "aggregate bytes exceed limit".to_string(),
                            ));
                        }

                        candidates.push(Candidate {
                            rel_path: entry_rel,
                            target_rel: rel_target,
                            format: CandidateFormat::Jks,
                        });
                    }
                    Err(e) => {
                        let reason = match e {
                            TrustError::Symlink(ref s) => s.clone(),
                            _ => "cannot stat target".to_string(),
                        };
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&entry_rel),
                            reason,
                        });
                    }
                }
            }
        }
    }

    if candidates.len() + skipped_paths.len() > MAX_REPORT_ENTRIES {
        return Err(TrustError::Cert("report size exceeds limit".to_string()));
    }

    // 4. Deterministic Discovery & Target Conflict Detection
    let mut candidate_targets: BTreeMap<PathBuf, (CandidateFormat, PathBuf)> = BTreeMap::new();
    let mut conflicted_targets: HashSet<PathBuf> = HashSet::new();

    for cand in &candidates {
        if let Some(&(existing_fmt, _)) = candidate_targets.get(&cand.target_rel) {
            if existing_fmt != cand.format {
                conflicted_targets.insert(cand.target_rel.clone());
            }
        } else {
            candidate_targets.insert(
                cand.target_rel.clone(),
                (cand.format, cand.rel_path.clone()),
            );
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

    let mut modified_paths: HashSet<PathBuf> = HashSet::new();
    let mut processed_targets: HashSet<PathBuf> = HashSet::new();
    let mut successful_system_bundle_targets: HashSet<PathBuf> = HashSet::new();
    let mut first_existing_system_bundle: Option<String> = None;

    // 5. PHASE 2: Execution (Handle-Anchored Mutations)
    for cand in candidates {
        let is_system_bundle = known_system_bundles
            .iter()
            .any(|&k| Path::new(k) == cand.rel_path);

        if processed_targets.insert(cand.target_rel.clone()) {
            let parent_res = open_parent_dir_handle(rootfs, &cand.target_rel);
            let (parent_dir, file_name) = match parent_res {
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
                    if content.len() >= 4 && content[0..4] == [0xFE, 0xED, 0xFE, 0xED] {
                        skipped_paths.push(SkippedPath {
                            path: encode_path_lossless(&cand.target_rel),
                            reason: "conflicting_target_format".to_string(),
                        });
                        continue;
                    }
                    if is_pkcs12(&content) {
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

                    let mut new_content = content;
                    if !new_content.is_empty() && !new_content.ends_with(b"\n") {
                        new_content.push(b'\n');
                    }
                    new_content.extend_from_slice(canonical_ca_pem.as_bytes());
                    if !new_content.ends_with(b"\n") {
                        new_content.push(b'\n');
                    }

                    match atomic_write_preserving_handle(
                        &parent_dir,
                        &file_name,
                        &new_content,
                        Some(0o644),
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
                                None,
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
    for rel_str in &known_system_bundles {
        let bundle_path = rootfs.join(rel_str);
        if let Ok(target) = resolve_in_rootfs(rootfs, &bundle_path) {
            let rel_target = make_rel_path(&target);
            if successful_system_bundle_targets.contains(&rel_target) {
                first_existing_system_bundle = Some(format!("/{}", rel_str));
                break;
            }
        }
    }

    // 6. System Bundle Establishment & Fallback
    let mut established_system_bundle = first_existing_system_bundle;

    if established_system_bundle.is_none() {
        let fallback_rel = PathBuf::from("etc/ssl/certs/ca-certificates.crt");
        let fallback_path = rootfs.join(&fallback_rel);
        let target = resolve_in_rootfs(rootfs, &fallback_path)?;
        let rel_target = make_rel_path(&target);

        // Defect 4: Fallback processing must apply format-conflict exclusions and candidate plan
        if conflicted_targets.contains(&rel_target) {
            skipped_paths.push(SkippedPath {
                path: encode_path_lossless(&rel_target),
                reason: "conflicting_target_format".to_string(),
            });
            return Err(TrustError::Cert(
                "failed to establish a usable system trust bundle containing CA: fallback target has format conflict".to_string(),
            ));
        }

        match fs::symlink_metadata(&target) {
            Ok(meta) => {
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
                        reason: format!("file exceeds size cap of {} bytes", MAX_PEM_BUNDLE_BYTES),
                    });
                } else {
                    let (parent_dir, file_name) = open_parent_dir_handle(rootfs, &rel_target)?;
                    let content = read_file_capped_from_parent(
                        &parent_dir,
                        &file_name,
                        MAX_PEM_BUNDLE_BYTES,
                    )?;

                    // Defect 4: Exclude JKS and PKCS#12 targets, preserve rejected targets byte-for-byte
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
                    if contains {
                        established_system_bundle =
                            Some("/etc/ssl/certs/ca-certificates.crt".to_string());
                    } else {
                        let mut new_content = content;
                        if !new_content.is_empty() && !new_content.ends_with(b"\n") {
                            new_content.push(b'\n');
                        }
                        new_content.extend_from_slice(canonical_ca_pem.as_bytes());
                        if !new_content.ends_with(b"\n") {
                            new_content.push(b'\n');
                        }

                        atomic_write_preserving_handle(
                            &parent_dir,
                            &file_name,
                            &new_content,
                            Some(0o644),
                        )?;
                        modified_paths.insert(rel_target);
                        established_system_bundle =
                            Some("/etc/ssl/certs/ca-certificates.crt".to_string());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (parent_dir, file_name) = ensure_parent_dirs_in_rootfs(rootfs, &rel_target)?;
                atomic_write_preserving_handle(
                    &parent_dir,
                    &file_name,
                    canonical_ca_pem.as_bytes(),
                    Some(0o644),
                )?;
                modified_paths.insert(rel_target);
                established_system_bundle = Some("/etc/ssl/certs/ca-certificates.crt".to_string());
            }
            Err(e) => {
                return Err(TrustError::Io(e));
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

fn comp_as_os_str(name: &std::ffi::OsStr) -> &std::ffi::OsStr {
    name
}

/// Check if report destination collides with any existing or planned trust store target in rootfs.
pub fn check_report_target_collision(rootfs: &Path, report_path: &Path) -> Result<(), TrustError> {
    use std::os::unix::io::AsRawFd;

    let known_system_bundles = [
        "etc/ssl/certs/ca-certificates.crt",
        "etc/pki/tls/certs/ca-bundle.crt",
        "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "etc/ssl/cert.pem",
    ];

    for rel_str in &known_system_bundles {
        let p = safe_join_rootfs(rootfs, Path::new(rel_str));
        crate::cert::check_not_alias(report_path, &p, "report", "planned trust store target")?;
        if let Ok(target) = resolve_in_rootfs(rootfs, &p) {
            crate::cert::check_not_alias(
                report_path,
                &target,
                "report",
                "resolved trust store target",
            )?;
        }
    }

    let anchor_targets = [
        "usr/local/share/ca-certificates/hermetic-world-ca.crt",
        "etc/pki/ca-trust/source/anchors/hermetic-world-ca.pem",
    ];

    for rel_str in &anchor_targets {
        let p = safe_join_rootfs(rootfs, Path::new(rel_str));
        crate::cert::check_not_alias(report_path, &p, "report", "planned anchor target")?;
        if let Ok(target) = resolve_in_rootfs(rootfs, &p) {
            crate::cert::check_not_alias(report_path, &target, "report", "resolved anchor target")?;
        }
    }

    // Planned fallback bundle target:
    let fallback_p = safe_join_rootfs(rootfs, Path::new("etc/ssl/certs/ca-certificates.crt"));
    crate::cert::check_not_alias(
        report_path,
        &fallback_p,
        "report",
        "planned fallback target",
    )?;
    if let Ok(target) = resolve_in_rootfs(rootfs, &fallback_p) {
        crate::cert::check_not_alias(report_path, &target, "report", "resolved fallback target")?;
    }

    // Also check discovered files in rootfs if rootfs exists
    if let Ok(root_handle) = open_dir_handle(rootfs) {
        let mut dirs = vec![(root_handle, PathBuf::new(), 0usize)];
        while let Some((h, rel, d)) = dirs.pop() {
            if d > 16 {
                continue;
            }
            let p_path = format!("/proc/self/fd/{}", h.as_raw_fd());
            if let Ok(rd) = fs::read_dir(&p_path) {
                for ent in rd.flatten() {
                    let name = ent.file_name();
                    let child_rel = rel.join(&name);
                    if let Ok(ft) = ent.file_type() {
                        if ft.is_dir() {
                            if let Ok(ch) = open_child_dir(h.as_raw_fd(), &name) {
                                dirs.push((ch, child_rel, d + 1));
                            }
                        } else if name == "cacert.pem" || name == "cacerts" {
                            let abs = safe_join_rootfs(rootfs, &child_rel);
                            crate::cert::check_not_alias(
                                report_path,
                                &abs,
                                "report",
                                "discovered trust store target",
                            )?;
                            if let Ok(target) = resolve_in_rootfs(rootfs, &abs) {
                                crate::cert::check_not_alias(
                                    report_path,
                                    &target,
                                    "report",
                                    "resolved discovered target",
                                )?;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
