#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use rustix::fs::{openat, statat, AtFlags, Mode, OFlags};

use crate::args::SealRequest;
use crate::backend::SEAL_NOT_WIRED;
use crate::dispatch::{BackendError, Outcome};

pub const MAX_SEAL_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_SEALER_WAIT_SECONDS: u64 = 1800;
pub const MAX_SEALER_POLL_ITERATIONS: usize = 36_000;

/// Verifies that every path component exists without following any symlinks,
/// refusing symlinks, FIFOs, devices, sockets, and parent directory traversal (`..`).
pub fn verify_dir_no_symlinks(path: &Path) -> Result<(), BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data("empty path".to_string()));
    }
    let mut current_fd = openat(
        rustix::fs::CWD,
        if path.is_absolute() { "/" } else { "." },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
            BackendError::Io("input directory not found".to_string())
        } else {
            BackendError::Data("refused path: cannot open root directory".to_string())
        }
    })?;

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(BackendError::Data(
                    "refused path: parent traversal (..) is forbidden".to_string(),
                ));
            }
            Component::Normal(name) => {
                let st = statat(&current_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
                    if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
                        BackendError::Io("input directory not found".to_string())
                    } else if e.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
                        BackendError::Data("refused path: symlink encountered".to_string())
                    } else {
                        BackendError::Data("refused path component".to_string())
                    }
                })?;
                let mode = st.st_mode & 0o170000;
                if mode == 0o120000 {
                    return Err(BackendError::Data(
                        "refused path: symlink encountered".to_string(),
                    ));
                }
                if mode != 0o040000 {
                    return Err(BackendError::Data(
                        "refused path: component is not a directory".to_string(),
                    ));
                }
                let next_fd = openat(
                    &current_fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| {
                    BackendError::Data("refused path: cannot traverse directory".to_string())
                })?;
                current_fd = next_fd;
            }
            Component::Prefix(_) => {
                return Err(BackendError::Data("refused path: prefix".to_string()));
            }
        }
    }
    Ok(())
}

/// Verifies that an executable file exists, is regular, executable, and contains no symlinks.
pub fn verify_executable_file_no_symlinks(path: &Path) -> Result<(), BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data("empty executable path".to_string()));
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    verify_dir_no_symlinks(parent)?;
    let filename = path
        .file_name()
        .ok_or_else(|| BackendError::Data("path has no filename".to_string()))?;

    let parent_fd = openat(
        rustix::fs::CWD,
        if parent.is_absolute() {
            parent
        } else {
            Path::new(".")
        },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| BackendError::Data("cannot open executable parent directory".to_string()))?;

    let st = statat(&parent_fd, filename, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
        if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
            BackendError::Io("executable binary not found".to_string())
        } else if e.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
            BackendError::Data("refused executable binary: symlink".to_string())
        } else {
            BackendError::Data("refused executable binary".to_string())
        }
    })?;

    let mode = st.st_mode & 0o170000;
    if mode == 0o120000 {
        return Err(BackendError::Data(
            "refused executable binary: symlink".to_string(),
        ));
    }
    if mode != 0o100000 {
        return Err(BackendError::Data(
            "refused executable binary: not a regular file".to_string(),
        ));
    }
    if st.st_mode & 0o111 == 0 {
        return Err(BackendError::Data(
            "refused executable binary: not marked executable".to_string(),
        ));
    }
    Ok(())
}

/// Verifies that a regular file exists, is regular, and contains no symlinks.
pub fn verify_regular_file_no_symlinks(path: &Path) -> Result<(), BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data("empty file path".to_string()));
    }
    let raw_parent = path.parent().unwrap_or(Path::new(""));
    let parent = if raw_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        raw_parent
    };
    verify_dir_no_symlinks(parent)?;
    let filename = path
        .file_name()
        .ok_or_else(|| BackendError::Data("path has no filename".to_string()))?;

    let parent_fd = openat(
        rustix::fs::CWD,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| BackendError::Data("cannot open file parent directory".to_string()))?;

    let st = statat(&parent_fd, filename, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
        if e.raw_os_error() == rustix::io::Errno::NOENT.raw_os_error() {
            BackendError::Io("file not found".to_string())
        } else if e.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
            BackendError::Data("refused file: symlink".to_string())
        } else {
            BackendError::Data("refused file".to_string())
        }
    })?;

    let mode = st.st_mode & 0o170000;
    if mode == 0o120000 {
        return Err(BackendError::Data("refused file: symlink".to_string()));
    }
    if mode != 0o100000 {
        return Err(BackendError::Data(
            "refused file: not a regular file".to_string(),
        ));
    }
    Ok(())
}

/// Prepares the output directory with mode 0700, refusing symlinks and non-empty existing dirs.
pub fn prepare_output_dir(path: &Path) -> Result<(), BackendError> {
    if path.as_os_str().is_empty() {
        return Err(BackendError::Data("empty output path".to_string()));
    }
    if path.exists() {
        verify_dir_no_symlinks(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| BackendError::Io("failed to set directory mode 0700".to_string()))?;
        let mut entries = fs::read_dir(path)
            .map_err(|_| BackendError::Io("cannot inspect output directory".to_string()))?;
        if entries.next().is_some() {
            return Err(BackendError::Data(
                "refused output directory: already exists and is not empty".to_string(),
            ));
        }
    } else {
        let parent = path.parent().unwrap_or(Path::new("."));
        verify_dir_no_symlinks(parent)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| BackendError::Io("failed to create output directory".to_string()))?;
    }
    Ok(())
}

fn validate_timestamp(t_clock: &str) -> Result<(), BackendError> {
    if t_clock.is_empty() || t_clock.len() > 64 || t_clock.starts_with('-') {
        return Err(BackendError::Data(
            "invalid t_clock format: must be RFC 3339 UTC or integer epoch".to_string(),
        ));
    }
    // Accept non-negative integer epoch
    if t_clock.chars().all(|c| c.is_ascii_digit()) {
        return Ok(());
    }
    // Parse as real RFC 3339 UTC
    crate::args::validate_rfc3339_utc(t_clock).map_err(|e| {
        BackendError::Data(format!(
            "invalid t_clock format: must be RFC 3339 UTC or integer epoch: {e}"
        ))
    })
}

fn validate_world_id(world_id: &str) -> Result<(), BackendError> {
    if world_id.is_empty() || world_id.len() > 200 {
        return Err(BackendError::Data("invalid world_id length".to_string()));
    }
    if !world_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(BackendError::Data(
            "invalid characters in world_id".to_string(),
        ));
    }
    Ok(())
}

/// Executes the real sealing workflow: input checks, sealer subprocess, and bundle manifest generation.
pub fn execute_seal(req: SealRequest) -> Result<Outcome, BackendError> {
    // 1. Strict component-by-component no-follow input verification
    verify_dir_no_symlinks(&req.src)?;
    let src_meta = fs::symlink_metadata(&req.src)
        .map_err(|_| BackendError::Io("source directory could not be inspected".to_string()))?;
    if !src_meta.is_dir() {
        return Err(BackendError::Data(
            "source path is not a directory".to_string(),
        ));
    }

    validate_timestamp(&req.t_clock)?;
    validate_world_id(&req.world_id)?;

    // 2. Check if the sealer binary is available before creating any directories or files
    let sealer_bin = match std::env::var_os("HERMETIC_SEALER_BIN") {
        Some(val) => PathBuf::from(val),
        None => {
            // Sealer backend is not configured in this environment
            return Err(BackendError::Unavailable(SEAL_NOT_WIRED));
        }
    };

    verify_executable_file_no_symlinks(&sealer_bin)?;

    // 3. Output directory must be prepared with mode 0700 without following symlinks
    prepare_output_dir(&req.out)?;

    let mut cmd = Command::new(&sealer_bin);
    cmd.args([
        "--src",
        req.src
            .to_str()
            .ok_or_else(|| BackendError::Data("non-utf8 source path".to_string()))?,
        "--out",
        req.out
            .to_str()
            .ok_or_else(|| BackendError::Data("non-utf8 output path".to_string()))?,
        "--t-clock",
        &req.t_clock,
        "--world-id",
        &req.world_id,
        "--seal-level",
        req.seal_level.as_str(),
    ]);

    if let Some(ref pkg_rec) = req.packages_record {
        verify_regular_file_no_symlinks(pkg_rec)?;
        cmd.args([
            "--packages-record",
            pkg_rec
                .to_str()
                .ok_or_else(|| BackendError::Data("non-utf8 packages_record path".to_string()))?,
        ]);
    }

    if let Some(ref sub) = req.substrate {
        verify_regular_file_no_symlinks(sub)?;
        cmd.args([
            "--substrate",
            sub.to_str()
                .ok_or_else(|| BackendError::Data("non-utf8 substrate path".to_string()))?,
        ]);
    }

    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("LC_ALL", "C");
    cmd.env("TZ", "UTC");
    if let Some(sealcheck) = std::env::var_os("HERMETIC_SEALCHECK_BIN") {
        cmd.env("HERMETIC_SEALCHECK_BIN", sealcheck);
    }
    // Directory of the static guest binaries (hermetic-init, hermetic-execd,
    // hermetic-clockprobe) the sealer installs into the rootfs.
    if let Some(dir) = std::env::var_os("HERMETIC_GUEST_BIN_DIR") {
        cmd.env("HERMETIC_GUEST_BIN_DIR", dir);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let mut child = cmd
        .spawn()
        .map_err(|_| BackendError::Internal("failed to spawn sealer subprocess".to_string()))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(MAX_SEALER_WAIT_SECONDS);
    let mut iterations: usize = 0;
    let status = loop {
        iterations = iterations.saturating_add(1);
        if iterations > MAX_SEALER_POLL_ITERATIONS {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackendError::Internal(
                "sealer subprocess deadline exceeded".to_string(),
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError::Internal(
                        "sealer subprocess deadline exceeded".to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BackendError::Internal(
                    "error waiting for sealer subprocess".to_string(),
                ));
            }
        }
    };

    let exit_code = status.code().unwrap_or(70);
    match exit_code {
        0 => {}
        2 => {
            return Err(BackendError::ProblemFound(
                "sealcheck gate rejected sealed world: problem found".to_string(),
            ));
        }
        65 => {
            return Err(BackendError::Data(
                "sealer rejected invalid input data".to_string(),
            ));
        }
        74 => {
            return Err(BackendError::Io(
                "sealer encountered I/O failure".to_string(),
            ));
        }
        _ => {
            return Err(BackendError::Internal(
                "sealer subprocess failed".to_string(),
            ));
        }
    }

    // 4. Ensure world_manifest.json exists in req.out before bundle sealing
    let world_manifest_path = req.out.join("world_manifest.json");
    if !world_manifest_path.exists() {
        return Err(BackendError::Internal(
            "sealer did not produce world_manifest.json".to_string(),
        ));
    }

    // 5. Output a sealed world directory and its manifest
    let manifest = hermetic_bundle::seal(&req.out)
        .map_err(|e| BackendError::Internal(format!("failed to seal bundle manifest: {e}")))?;

    let outcome = Outcome::success(format!(
        "sealed world {} in {}",
        req.world_id,
        hermetic_bundle::MANIFEST_FILENAME
    ))
    .with_detail("world_id", serde_json::Value::from(req.world_id))
    .with_detail("root", serde_json::Value::from(manifest.root))
    .with_detail(
        "seal_level",
        serde_json::Value::from(req.seal_level.as_str()),
    );

    Ok(outcome)
}
