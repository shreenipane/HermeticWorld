#![forbid(unsafe_code)]
//! ExtractorVM PID 1 implementation (TR-EXT-1, TR-EXT-2, TR-EXT-3, TR-EXT-5).
//!
//! Sequence:
//! 1. Verify PID 1.
//! 2. Mount procfs read-only and devtmpfs minimally.
//! 3. Read and validate config from `/proc/cmdline` or fixed config file.
//! 4. Mount the pristine base image read-only.
//! 5. Mount the CoW copy of the agent overlay disk read-write (allows ext4 journal replay).
//! 6. Assemble read-only overlayfs with exact options:
//!    `nodev,nosuid,noexec,redirect_dir=nofollow,metacopy=off,index=off`.
//! 7. Run in-process tree walk/stream (never invokes `git`, ignores `.git`).
//! 8. Write length-prefixed stream plus 48-byte header (`HEXD`) onto raw output drive.
//! 9. Every step has a deadline; on failure, write fixed failure code to header.
//! 10. Sync and power off.

use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use hermetic_extract::disk::{
    ExtractDiskHeader, ExtractFailureCode, EXTRACT_DISK_HEADER_BYTES, HARD_MAX_PAYLOAD_BYTES,
};
use rustix::mount::MountFlags;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::walk::run_extract;
use crate::{
    parse_task_class, CapName, Caps, ExtractError, ExtractReport, TaskClass, HARD_MAX_FILE_BYTES,
    HARD_MAX_TOTAL_BYTES,
};

/// Exact mount flags required for the read-only overlayfs mount (TR-EXT-2).
pub const OVERLAY_MOUNT_FLAGS: MountFlags = {
    MountFlags::RDONLY
        .union(MountFlags::NODEV)
        .union(MountFlags::NOSUID)
        .union(MountFlags::NOEXEC)
};

/// Exact data option string required for the overlayfs mount (TR-EXT-2).
pub const OVERLAY_DATA_OPTIONS: &str = "redirect_dir=nofollow,metacopy=off,index=off";

/// Default path for base mount point inside ExtractorVM.
pub const DEFAULT_BASE_MOUNT: &str = "/mnt/base";
/// Default path for overlay mount point inside ExtractorVM.
pub const DEFAULT_OVERLAY_MOUNT: &str = "/mnt/overlay";
/// Default path for assembled read-only overlayfs view.
pub const DEFAULT_MERGED_MOUNT: &str = "/mnt/merged";

/// Default device paths according to VMM drive layout.
pub const DEFAULT_OUTPUT_DEV: &str = "/dev/vdb";
pub const DEFAULT_BASE_DEV: &str = "/dev/vdc";
pub const DEFAULT_OVERLAY_DEV: &str = "/dev/vdd";

/// Standard config file path if baked into extractor image.
pub const DEFAULT_CONFIG_FILE: &str = "/etc/hermetic/extractor/config.json";
pub const ALT_CONFIG_FILE: &str = "/etc/hermetic/extract.json";

/// Default step deadline duration.
pub const DEFAULT_STEP_DEADLINE: Duration = Duration::from_secs(30);
/// Default overall extraction deadline duration.
pub const DEFAULT_OVERALL_DEADLINE: Duration = Duration::from_secs(120);
/// Maximum configuration file byte size (1 MiB).
pub const MAX_CONFIG_FILE_BYTES: usize = 1024 * 1024;

/// Parsed, validated configuration for ExtractorVM PID 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractorConfig {
    pub task_class: TaskClass,
    pub caps: Caps,
    pub base_dev: String,
    pub overlay_dev: String,
    pub output_dev: String,
    pub base_mount: String,
    pub overlay_mount: String,
    pub merged_mount: String,
    pub nonce: [u8; 32],
    pub overall_deadline: Duration,
    pub step_deadline: Duration,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            task_class: TaskClass::Patch {
                repo_dir: String::new(),
            },
            caps: Caps::default(),
            base_dev: DEFAULT_BASE_DEV.to_string(),
            overlay_dev: DEFAULT_OVERLAY_DEV.to_string(),
            output_dev: DEFAULT_OUTPUT_DEV.to_string(),
            base_mount: DEFAULT_BASE_MOUNT.to_string(),
            overlay_mount: DEFAULT_OVERLAY_MOUNT.to_string(),
            merged_mount: DEFAULT_MERGED_MOUNT.to_string(),
            nonce: [0u8; 32],
            overall_deadline: DEFAULT_OVERALL_DEADLINE,
            step_deadline: DEFAULT_STEP_DEADLINE,
        }
    }
}

const KNOWN_HERMETIC_KEYS: &[&str] = &[
    "hermetic.class",
    "hermetic.base",
    "hermetic.overlay",
    "hermetic.output",
    "hermetic.nonce",
    "hermetic.t",
    "hermetic.deadline_secs",
    "hermetic.max_file_bytes",
    "hermetic.max_total_bytes",
];

impl ExtractorConfig {
    /// Parses configuration from kernel command line bytes (e.g. `/proc/cmdline`).
    ///
    /// Requires exactly one task class, explicit device paths matching expected set,
    /// valid 64-hex run nonce, and refuses unknown or duplicate `hermetic.*` keys.
    pub fn parse_cmdline(cmdline: &[u8]) -> Result<Self, InitError> {
        let text = std::str::from_utf8(cmdline)
            .map_err(|_| InitError::Config("cmdline is not valid UTF-8".into()))?;

        let mut class_opt: Option<TaskClass> = None;
        let mut base_dev: Option<String> = None;
        let mut overlay_dev: Option<String> = None;
        let mut output_dev: Option<String> = None;
        let mut nonce_opt: Option<[u8; 32]> = None;
        let mut overall_deadline = DEFAULT_OVERALL_DEADLINE;
        let mut caps = Caps::default();
        let mut seen_keys = std::collections::BTreeSet::new();

        for arg in text.split_ascii_whitespace() {
            if arg.starts_with("hermetic.") {
                let key = match arg.split_once('=') {
                    Some((k, _)) => k,
                    None => arg,
                };
                if !KNOWN_HERMETIC_KEYS.contains(&key) {
                    return Err(InitError::Config(format!(
                        "unknown hermetic cmdline key: '{key}'"
                    )));
                }
                if !seen_keys.insert(key.to_string()) {
                    return Err(InitError::Config(format!(
                        "duplicate hermetic cmdline key: '{key}'"
                    )));
                }
            }

            if let Some(val) = arg.strip_prefix("hermetic.class=") {
                let tc = parse_task_class(val)
                    .map_err(|e| InitError::Config(format!("invalid hermetic.class: {}", e)))?;
                class_opt = Some(tc);
            } else if let Some(val) = arg.strip_prefix("hermetic.base=") {
                validate_dev_path(val)?;
                if val != DEFAULT_BASE_DEV {
                    return Err(InitError::Config(format!(
                        "unexpected base device: '{val}', expected '{DEFAULT_BASE_DEV}'"
                    )));
                }
                base_dev = Some(val.to_string());
            } else if let Some(val) = arg.strip_prefix("hermetic.overlay=") {
                validate_dev_path(val)?;
                if val != DEFAULT_OVERLAY_DEV {
                    return Err(InitError::Config(format!(
                        "unexpected overlay device: '{val}', expected '{DEFAULT_OVERLAY_DEV}'"
                    )));
                }
                overlay_dev = Some(val.to_string());
            } else if let Some(val) = arg.strip_prefix("hermetic.output=") {
                validate_dev_path(val)?;
                if val != DEFAULT_OUTPUT_DEV {
                    return Err(InitError::Config(format!(
                        "unexpected output device: '{val}', expected '{DEFAULT_OUTPUT_DEV}'"
                    )));
                }
                output_dev = Some(val.to_string());
            } else if let Some(val) = arg.strip_prefix("hermetic.nonce=") {
                if val.len() != 64 {
                    return Err(InitError::Config(
                        "hermetic.nonce must be exactly 64 hex characters".into(),
                    ));
                }
                if !val.is_ascii() {
                    return Err(InitError::Config(
                        "invalid hex character in hermetic.nonce".into(),
                    ));
                }
                let mut nonce = [0u8; 32];
                for i in 0..32 {
                    nonce[i] = u8::from_str_radix(&val[i * 2..i * 2 + 2], 16).map_err(|_| {
                        InitError::Config("invalid hex character in hermetic.nonce".into())
                    })?;
                }
                nonce_opt = Some(nonce);
            } else if let Some(val) = arg.strip_prefix("hermetic.deadline_secs=") {
                let secs = val
                    .parse::<u64>()
                    .map_err(|_| InitError::Config("invalid hermetic.deadline_secs".into()))?;
                if secs == 0 || secs > 86400 {
                    return Err(InitError::Config("deadline_secs out of range".into()));
                }
                overall_deadline = Duration::from_secs(secs);
            } else if let Some(val) = arg.strip_prefix("hermetic.max_file_bytes=") {
                let bytes = val
                    .parse::<u64>()
                    .map_err(|_| InitError::Config("invalid hermetic.max_file_bytes".into()))?;
                if bytes > HARD_MAX_FILE_BYTES {
                    return Err(InitError::Config("max_file_bytes exceeds ceiling".into()));
                }
                caps.max_file_bytes = bytes;
            } else if let Some(val) = arg.strip_prefix("hermetic.max_total_bytes=") {
                let bytes = val
                    .parse::<u64>()
                    .map_err(|_| InitError::Config("invalid hermetic.max_total_bytes".into()))?;
                if bytes > HARD_MAX_TOTAL_BYTES {
                    return Err(InitError::Config("max_total_bytes exceeds ceiling".into()));
                }
                caps.max_total_bytes = bytes;
            }
        }

        let task_class =
            class_opt.ok_or_else(|| InitError::Config("missing required hermetic.class".into()))?;

        let (base_dev, overlay_dev, output_dev) = match (base_dev, overlay_dev, output_dev) {
            (Some(b), Some(o), Some(out)) => (b, o, out),
            _ => {
                return Err(InitError::Config(
                    "missing required explicit device paths on cmdline".into(),
                ));
            }
        };

        let nonce = nonce_opt.ok_or_else(|| {
            InitError::Config("missing required hermetic.nonce on cmdline".into())
        })?;

        caps.validate()
            .map_err(|e| InitError::Config(e.to_string()))?;

        Ok(Self {
            task_class,
            base_dev,
            overlay_dev,
            output_dev,
            nonce,
            overall_deadline,
            caps,
            ..Self::default()
        })
    }

    /// Parses configuration from JSON bytes.
    pub fn parse_json(json_bytes: &[u8]) -> Result<Self, InitError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JsonConfig {
            task_class: String,
            base_dev: String,
            overlay_dev: String,
            output_dev: String,
            nonce: String,
            deadline_seconds: Option<u64>,
            max_entries: Option<usize>,
            max_depth: Option<usize>,
            max_path_len: Option<usize>,
            max_file_bytes: Option<u64>,
            max_total_bytes: Option<u64>,
        }

        if json_bytes.len() > MAX_CONFIG_FILE_BYTES {
            return Err(InitError::Config("config file too large".into()));
        }

        let parsed: JsonConfig = serde_json::from_slice(json_bytes)
            .map_err(|e| InitError::Config(format!("invalid config JSON: {}", e)))?;

        let task_class = parse_task_class(&parsed.task_class)
            .map_err(|e| InitError::Config(format!("invalid task_class in JSON: {}", e)))?;

        validate_dev_path(&parsed.base_dev)?;
        if parsed.base_dev != DEFAULT_BASE_DEV {
            return Err(InitError::Config(format!(
                "unexpected base device: '{}', expected '{DEFAULT_BASE_DEV}'",
                parsed.base_dev
            )));
        }

        validate_dev_path(&parsed.overlay_dev)?;
        if parsed.overlay_dev != DEFAULT_OVERLAY_DEV {
            return Err(InitError::Config(format!(
                "unexpected overlay device: '{}', expected '{DEFAULT_OVERLAY_DEV}'",
                parsed.overlay_dev
            )));
        }

        validate_dev_path(&parsed.output_dev)?;
        if parsed.output_dev != DEFAULT_OUTPUT_DEV {
            return Err(InitError::Config(format!(
                "unexpected output device: '{}', expected '{DEFAULT_OUTPUT_DEV}'",
                parsed.output_dev
            )));
        }

        if parsed.nonce.len() != 64 {
            return Err(InitError::Config(
                "nonce in JSON must be exactly 64 hex characters".into(),
            ));
        }
        if !parsed.nonce.is_ascii() {
            return Err(InitError::Config("invalid hex character in nonce".into()));
        }
        let mut nonce = [0u8; 32];
        for i in 0..32 {
            nonce[i] = u8::from_str_radix(&parsed.nonce[i * 2..i * 2 + 2], 16)
                .map_err(|_| InitError::Config("invalid hex character in nonce".into()))?;
        }

        let overall_deadline = if let Some(d) = parsed.deadline_seconds {
            if d == 0 || d > 86400 {
                return Err(InitError::Config("deadline_seconds out of range".into()));
            }
            Duration::from_secs(d)
        } else {
            DEFAULT_OVERALL_DEADLINE
        };

        let mut caps = Caps::default();
        if let Some(v) = parsed.max_entries {
            caps.max_entries = v;
        }
        if let Some(v) = parsed.max_depth {
            caps.max_depth = v;
        }
        if let Some(v) = parsed.max_path_len {
            caps.max_path_len = v;
        }
        if let Some(v) = parsed.max_file_bytes {
            caps.max_file_bytes = v;
        }
        if let Some(v) = parsed.max_total_bytes {
            caps.max_total_bytes = v;
        }

        caps.validate()
            .map_err(|e| InitError::Config(e.to_string()))?;

        Ok(Self {
            task_class,
            base_dev: parsed.base_dev,
            overlay_dev: parsed.overlay_dev,
            output_dev: parsed.output_dev,
            nonce,
            overall_deadline,
            caps,
            ..Self::default()
        })
    }
}

fn validate_dev_path(p: &str) -> Result<(), InitError> {
    if !p.starts_with('/') || p.contains("..") || p.contains('\0') {
        return Err(InitError::Config(format!("invalid device path: '{}'", p)));
    }
    Ok(())
}

/// Verifies that the agent overlay disk matches the execd layout (`upper` and `work` directories).
///
/// Refuses symlinks and non-directories using `symlink_metadata` (lstat without following symlinks).
/// Fails closed if `upper` or `work` is missing, is a symlink, or is not a real directory (TR-EXT-2).
pub fn verify_overlay_layout(overlay_mount: &str) -> Result<String, InitError> {
    let overlay_meta = std::fs::symlink_metadata(overlay_mount).map_err(|e| InitError::Mount {
        step: "overlay_layout",
        detail: format!("cannot stat overlay mount: {e}"),
    })?;
    if overlay_meta.file_type().is_symlink() || !overlay_meta.file_type().is_dir() {
        return Err(InitError::Mount {
            step: "overlay_layout",
            detail: "overlay mount is not a real directory".into(),
        });
    }

    for name in ["upper", "work"] {
        let child_path = format!("{}/{}", overlay_mount, name);
        let child_meta = std::fs::symlink_metadata(&child_path).map_err(|e| InitError::Mount {
            step: "overlay_layout",
            detail: format!("missing or inaccessible '{name}' directory: {e}"),
        })?;
        if child_meta.file_type().is_symlink() {
            return Err(InitError::Mount {
                step: "overlay_layout",
                detail: format!("'{name}' component on overlay must not be a symlink"),
            });
        }
        if !child_meta.file_type().is_dir() {
            return Err(InitError::Mount {
                step: "overlay_layout",
                detail: format!("'{name}' component on overlay must be a real directory"),
            });
        }
    }

    Ok(format!("{}/upper", overlay_mount))
}

/// Constructs exact overlayfs mount options string.
pub fn overlayfs_options(lowerdir: &str) -> String {
    format!("lowerdir={},{}", lowerdir, OVERLAY_DATA_OPTIONS)
}

/// Typed errors encountered during Extractor PID 1 lifecycle.
#[derive(Debug)]
pub enum InitError {
    NotPid1,
    Timeout(&'static str),
    Config(String),
    Mount {
        step: &'static str,
        detail: String,
    },
    Extract(ExtractError),
    Io {
        context: &'static str,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::NotPid1 => write!(f, "extractor init must be run as PID 1"),
            InitError::Timeout(step) => write!(f, "deadline exceeded during {}", step),
            InitError::Config(msg) => write!(f, "configuration error: {}", msg),
            InitError::Mount { step, detail } => {
                write!(f, "mount failed during {}: {}", step, detail)
            }
            InitError::Extract(e) => write!(f, "extraction failed: {}", e),
            InitError::Io { context, kind } => {
                write!(f, "I/O error during {}: {:?}", context, kind)
            }
        }
    }
}

impl std::error::Error for InitError {}

impl InitError {
    pub fn to_failure_code(&self) -> ExtractFailureCode {
        match self {
            InitError::Timeout(_) => ExtractFailureCode::Timeout,
            InitError::Config(_) => ExtractFailureCode::ConfigError,
            InitError::Mount { .. } => ExtractFailureCode::MountError,
            InitError::Extract(_) => ExtractFailureCode::ExtractError,
            InitError::Io { .. } => ExtractFailureCode::IoError,
            InitError::NotPid1 => ExtractFailureCode::InternalError,
        }
    }
}

/// Seekable output writer trait object used for testing and production.
pub trait OutputWriter: Write + Seek + Send {}
impl<T: Write + Seek + Send> OutputWriter for T {}

/// System abstraction for testing PID 1 without privileged host execution.
pub trait ExtractorSys {
    fn is_pid1(&self) -> bool;
    fn read_cmdline(&mut self) -> io::Result<Vec<u8>>;
    fn read_config_file(&mut self, path: &str) -> io::Result<Option<Vec<u8>>>;
    fn mount_proc(&mut self) -> io::Result<()>;
    fn mount_dev(&mut self) -> io::Result<()>;
    fn mount_base(&mut self, source: &str, target: &str) -> io::Result<()>;
    fn mount_overlay(&mut self, source: &str, target: &str) -> io::Result<()>;
    fn mount_overlayfs(&mut self, lowerdir: &str, target: &str) -> io::Result<()>;
    fn open_output(&mut self, path: &str) -> io::Result<Box<dyn OutputWriter>>;
    fn sync(&mut self) -> io::Result<()>;
    fn power_off(&mut self) -> io::Result<()>;
    fn now(&self) -> Instant;
}

/// Writer wrapper that computes SHA-256 and counts bytes on the fly.
struct HashingCountingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes_written: u64,
}

impl<W: Write> HashingCountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    fn finalize(self) -> (u64, [u8; 32]) {
        let digest = self.hasher.finalize().into();
        (self.bytes_written, digest)
    }
}

impl<W: Write> Write for HashingCountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_written = self.bytes_written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Executes the full ExtractorVM PID 1 lifecycle.
///
/// Always writes a definitive header to the output drive (success with stream bytes
/// or failure code with zero length), performs bounded sync, and powers off.
pub fn run_extractor_init<S: ExtractorSys>(
    sys: &mut S,
    config_override: Option<ExtractorConfig>,
) -> Result<ExtractReport, InitError> {
    if !sys.is_pid1() {
        return Err(InitError::NotPid1);
    }

    let res = run_extractor_init_inner(sys, config_override);

    // Bounded sync
    let _ = sys.sync();
    // Power off
    let _ = sys.power_off();

    res
}

fn run_extractor_init_inner<S: ExtractorSys>(
    sys: &mut S,
    config_override: Option<ExtractorConfig>,
) -> Result<ExtractReport, InitError> {
    let start_time = sys.now();

    // 1. Mount procfs early and read config
    let config = match config_override {
        Some(cfg) => cfg,
        None => {
            sys.mount_proc().map_err(|e| InitError::Mount {
                step: "proc",
                detail: e.to_string(),
            })?;

            // Try fixed config file first, then fall back to /proc/cmdline
            // A config-file read error other than NotFound must fail closed.
            let file_cfg = match sys.read_config_file(DEFAULT_CONFIG_FILE) {
                Ok(Some(json_bytes)) => Some(ExtractorConfig::parse_json(&json_bytes)?),
                Ok(None) => match sys.read_config_file(ALT_CONFIG_FILE) {
                    Ok(Some(json_bytes)) => Some(ExtractorConfig::parse_json(&json_bytes)?),
                    Ok(None) => None,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                    Err(e) => {
                        return Err(InitError::Io {
                            context: "read alt config file",
                            kind: e.kind(),
                        });
                    }
                },
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(InitError::Io {
                        context: "read config file",
                        kind: e.kind(),
                    });
                }
            };
            match file_cfg {
                Some(cfg) => cfg,
                None => {
                    let cmdline = sys.read_cmdline().map_err(|e| InitError::Io {
                        context: "read cmdline",
                        kind: e.kind(),
                    })?;
                    ExtractorConfig::parse_cmdline(&cmdline)?
                }
            }
        }
    };

    let overall_deadline = start_time
        .checked_add(config.overall_deadline)
        .unwrap_or(start_time);

    // 2. Open output drive handle early so any failure can write the header
    let mut output_writer = sys
        .open_output(&config.output_dev)
        .map_err(|e| InitError::Io {
            context: "open output drive",
            kind: e.kind(),
        })?;

    // 3. Write in-progress failure header before any other step (TR-EXT-5, item E(3))
    let in_progress = ExtractDiskHeader::new_failure(ExtractFailureCode::InProgress, config.nonce);
    in_progress
        .write_to(&mut output_writer)
        .map_err(|e| InitError::Io {
            context: "write initial in-progress header",
            kind: e.kind(),
        })?;

    // Inner execution that captures any failure to write fixed failure header
    let run_res = run_steps(
        sys,
        &config,
        &mut output_writer,
        start_time,
        overall_deadline,
    );

    // Finalize output drive header
    match &run_res {
        Ok((total_bytes, sha256, _report)) => {
            let header = ExtractDiskHeader::new_success(config.nonce, *total_bytes, *sha256);
            if let Err(e) = header.write_to(&mut output_writer) {
                eprintln!("extractor: failed writing success header: {}", e);
            }
        }
        Err(err) => {
            eprintln!("extractor failed: {}", err);
            let failure_code = err.to_failure_code();
            let header = ExtractDiskHeader::new_failure(failure_code, config.nonce);
            if let Err(e) = header.write_to(&mut output_writer) {
                eprintln!("extractor: failed writing failure header: {}", e);
            }
        }
    }

    run_res.map(|(_, _, report)| report)
}

fn check_deadline(
    now: Instant,
    deadline: Instant,
    step_start: Instant,
    step_timeout: Duration,
    step_name: &'static str,
) -> Result<(), InitError> {
    if now >= deadline || now.saturating_duration_since(step_start) >= step_timeout {
        return Err(InitError::Timeout(step_name));
    }
    Ok(())
}

fn run_steps<S: ExtractorSys>(
    sys: &mut S,
    config: &ExtractorConfig,
    output: &mut Box<dyn OutputWriter>,
    _start_time: Instant,
    overall_deadline: Instant,
) -> Result<(u64, [u8; 32], ExtractReport), InitError> {
    // Mount /dev
    let step_start = sys.now();
    check_deadline(
        step_start,
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_dev",
    )?;
    sys.mount_dev().map_err(|e| InitError::Mount {
        step: "dev",
        detail: e.to_string(),
    })?;
    check_deadline(
        sys.now(),
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_dev",
    )?;

    // Mount base image read-only
    let step_start = sys.now();
    check_deadline(
        step_start,
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_base",
    )?;
    sys.mount_base(&config.base_dev, &config.base_mount)
        .map_err(|e| InitError::Mount {
            step: "base",
            detail: e.to_string(),
        })?;
    check_deadline(
        sys.now(),
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_base",
    )?;

    // Mount overlay image read-write
    let step_start = sys.now();
    check_deadline(
        step_start,
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_overlay",
    )?;
    sys.mount_overlay(&config.overlay_dev, &config.overlay_mount)
        .map_err(|e| InitError::Mount {
            step: "overlay",
            detail: e.to_string(),
        })?;
    check_deadline(
        sys.now(),
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_overlay",
    )?;

    // Verify overlay layout (upper and work directories, no symlinks, fail closed)
    let upper_path = verify_overlay_layout(&config.overlay_mount)?;
    let lower_dirs = format!("{}:{}", upper_path, config.base_mount);

    // Assemble read-only overlayfs
    let step_start = sys.now();
    check_deadline(
        step_start,
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_overlayfs",
    )?;
    sys.mount_overlayfs(&lower_dirs, &config.merged_mount)
        .map_err(|e| InitError::Mount {
            step: "overlayfs",
            detail: e.to_string(),
        })?;
    check_deadline(
        sys.now(),
        overall_deadline,
        step_start,
        config.step_deadline,
        "mount_overlayfs",
    )?;

    // Seek past 48-byte header on output drive
    output
        .seek(SeekFrom::Start(EXTRACT_DISK_HEADER_BYTES as u64))
        .map_err(|e| InitError::Io {
            context: "seek output drive",
            kind: e.kind(),
        })?;

    // Set up stream writer with hashing & counting
    let mut counting_writer = HashingCountingWriter::new(output);

    // Deadline check hook during traversal
    let mut hook = |_: &str| -> io::Result<()> {
        if sys.now() >= overall_deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"));
        }
        Ok(())
    };

    // Run walk / stream in-process
    let base_path = Path::new(&config.base_mount);
    let work_path = Path::new(&config.merged_mount);

    let report = run_extract(
        base_path,
        work_path,
        &config.task_class,
        &config.caps,
        &mut counting_writer,
        Some(&mut hook),
    )
    .map_err(InitError::Extract)?;

    counting_writer.flush().map_err(|e| InitError::Io {
        context: "flush stream",
        kind: e.kind(),
    })?;

    let (total_bytes, sha256) = counting_writer.finalize();

    // Verify written payload fits in cap
    if total_bytes > config.caps.max_total_bytes || total_bytes > HARD_MAX_PAYLOAD_BYTES {
        return Err(InitError::Extract(ExtractError::CapExceeded {
            cap: CapName::TotalBytes,
            limit: config.caps.max_total_bytes,
            actual: total_bytes,
        }));
    }

    Ok((total_bytes, sha256, report))
}

/// Linux guest implementation using real rustix syscalls.
pub struct LinuxExtractorSys;

impl LinuxExtractorSys {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxExtractorSys {
    fn default() -> Self {
        Self::new()
    }
}

fn ensure_dir_nofollow(path: &str) -> io::Result<()> {
    match rustix::fs::mkdir(path, rustix::fs::Mode::from_raw_mode(0o755)) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => {
            let st = rustix::fs::lstat(path)
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
            if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Directory {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "target exists and is not a directory",
                ));
            }
            Ok(())
        }
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

impl ExtractorSys for LinuxExtractorSys {
    fn is_pid1(&self) -> bool {
        rustix::process::getpid().as_raw_nonzero().get() == 1
    }

    fn read_cmdline(&mut self) -> io::Result<Vec<u8>> {
        let file = File::open("/proc/cmdline")?;
        let mut buf = Vec::new();
        file.take(4096).read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn read_config_file(&mut self, path: &str) -> io::Result<Option<Vec<u8>>> {
        match File::open(path) {
            Ok(file) => {
                let mut buf = Vec::new();
                file.take(MAX_CONFIG_FILE_BYTES as u64)
                    .read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn mount_proc(&mut self) -> io::Result<()> {
        ensure_dir_nofollow("/proc")?;
        rustix::mount::mount(
            "proc",
            "/proc",
            "proc",
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn mount_dev(&mut self) -> io::Result<()> {
        ensure_dir_nofollow("/dev")?;
        match rustix::mount::mount(
            "devtmpfs",
            "/dev",
            "devtmpfs",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            None,
        ) {
            Ok(()) | Err(rustix::io::Errno::BUSY) => Ok(()),
            Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }

    fn mount_base(&mut self, source: &str, target: &str) -> io::Result<()> {
        ensure_dir_nofollow(target)?;
        rustix::mount::mount(
            source,
            target,
            "ext4",
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn mount_overlay(&mut self, source: &str, target: &str) -> io::Result<()> {
        ensure_dir_nofollow(target)?;
        rustix::mount::mount(
            source,
            target,
            "ext4",
            MountFlags::NOSUID | MountFlags::NODEV,
            None,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn mount_overlayfs(&mut self, lowerdir: &str, target: &str) -> io::Result<()> {
        ensure_dir_nofollow(target)?;
        let data = overlayfs_options(lowerdir);
        let c_data =
            CString::new(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        rustix::mount::mount(
            "overlay",
            target,
            "overlay",
            OVERLAY_MOUNT_FLAGS,
            Some(c_data.as_c_str()),
        )
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn open_output(&mut self, path: &str) -> io::Result<Box<dyn OutputWriter>> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Box::new(file))
    }

    fn sync(&mut self) -> io::Result<()> {
        rustix::fs::sync();
        Ok(())
    }

    fn power_off(&mut self) -> io::Result<()> {
        // Ends the Firecracker VM through i8042 restart when kernel boot arg reboot=k is set.
        rustix::system::reboot(rustix::system::RebootCommand::Restart)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}
