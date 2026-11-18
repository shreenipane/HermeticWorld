#![forbid(unsafe_code)]
//! Host-side ExtractorVM orchestration and stream collection (TR-EXT-1 .. TR-EXT-6).
//!
//! Enforces:
//! 1. The host never mounts the agent disk (TR-EXT-1).
//! 2. Throwaway copy-on-write copy of the agent overlay disk is created via plain
//!    file copy or reflink without mounting.
//! 3. Extractor VM spec/plan with read-only base drive, writable overlay CoW copy,
//!    writable raw output drive, no network, and no vsock exec.
//! 4. Bounded read-back of the output drive, SHA-256 verification, and host-side
//!    stream validation returning an `ExtractorOutcome` compatible with `hermetic-run`.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use hermetic_extract::config::{ExtractConfig, TaskClass as HostTaskClass};
use hermetic_extract::disk::{
    DiskError, ExtractDiskHeader, EXTRACT_DISK_HEADER_BYTES, HARD_MAX_PAYLOAD_BYTES,
};
use hermetic_extract::validator::validate_stream;
use hermetic_run::ExtractorOutcome;
use rustix::fs::{copy_file_range, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::spec::{Clock, Drive, JailConfig, Limits, Role, VmSpec, Vsock};
use crate::{Error, ValidatedSpec};

pub const DEFAULT_EXTRACTOR_VCPUS: u8 = 2;
pub const DEFAULT_EXTRACTOR_MEM_MIB: u32 = 256;
pub const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RPC_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_READ_CHUNKS: usize = 4096;
pub const STREAM_CHUNK_BYTES: usize = 4096;

/// Canonical wire magic for the extractor stream ("HEXT").
pub const EXTRACTOR_STREAM_MAGIC: [u8; 4] = *b"HEXT";

/// Bounded buffer size for host file operations (64 KiB).
pub const HOST_CHUNK_BYTES: usize = 64 * 1024;

/// Default resource limits for ExtractorVM processes.
pub const EXTRACTOR_LIMITS: Limits = Limits {
    pids: 128,
    file_size_bytes: 67108864,
    open_files: 128,
};

/// Default size for fresh output drive (16 MiB).
pub const DEFAULT_OUTPUT_DRIVE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum allowed output drive size (64 GiB).
pub const MAX_OUTPUT_DRIVE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Maximum allowed overlay copy size (64 GiB).
pub const MAX_OVERLAY_COPY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Drive and kernel image paths for an ExtractorVM.
#[derive(Debug, Clone)]
pub struct ExtractorDrives {
    pub kernel_image: String,
    pub rootfs_path: String,
    pub base_drive_path: String,
    pub overlay_drive_path: String,
    pub cpu_template: String,
}

/// Specification plan for the throwaway ExtractorVM.
#[derive(Debug, Clone)]
pub struct ExtractorPlan {
    pub id: String,
    pub drives: ExtractorDrives,
    pub t_clock: u64,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub vsock_socket_path: String,
    pub jail: JailConfig,
    pub limits: Limits,
}

impl ExtractorPlan {
    pub fn new(
        id: impl Into<String>,
        drives: ExtractorDrives,
        t_clock: u64,
        jail: JailConfig,
    ) -> Self {
        Self {
            id: id.into(),
            drives,
            t_clock,
            vcpus: DEFAULT_EXTRACTOR_VCPUS,
            memory_mib: DEFAULT_EXTRACTOR_MEM_MIB,
            vsock_socket_path: "/vsock".into(),
            jail,
            limits: Limits {
                pids: 128,
                file_size_bytes: 67_108_864,
                open_files: 128,
            },
        }
    }

    /// Converts this plan into a `VmSpec` configured for the `Role::Extractor` role.
    pub fn to_vm_spec(&self) -> VmSpec {
        VmSpec {
            id: self.id.clone(),
            role: Role::Extractor,
            index: 0,
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            kernel_image: self.drives.kernel_image.clone(),
            initrd: None,
            boot_args: format!(
                "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda init=/sbin/hermetic-init clocksource=tsc tsc=reliable hermetic.t={} ro",
                self.t_clock
            ),
            root_drive: Drive {
                id: "rootfs".into(),
                path: self.drives.rootfs_path.clone(),
                read_only: true,
            },
            drives: vec![
                Drive {
                    id: "base".into(),
                    path: self.drives.base_drive_path.clone(),
                    read_only: true,
                },
                Drive {
                    id: "overlay".into(),
                    path: self.drives.overlay_drive_path.clone(),
                    read_only: true,
                },
            ],
            reserved_drives: vec![],
            vsock: Some(Vsock {
                guest_cid: 3,
                socket_path: self.vsock_socket_path.clone(),
            }),
            networks: vec![],
            cpu_template: self.drives.cpu_template.clone(),
            clock: Clock::Faked,
            limits: self.limits.clone(),
            jail: self.jail.clone(),
        }
    }

    /// Validates the resulting `VmSpec` under the strict rules of `Role::Extractor`.
    pub fn validate(&self) -> Result<ValidatedSpec, Error> {
        self.to_vm_spec().validate()
    }
}

/// Reads a 4-byte little-endian length followed by exactly `length` bytes from `reader`.
///
/// Bounded by `max_bytes` to prevent uncontrolled allocation from untrusted guest data.
pub fn read_length_prefixed_stream<R: Read>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|_| Error::Protocol)?;
    let length = u32::from_le_bytes(len_bytes) as usize;
    if length == 0 || length > max_bytes {
        return Err(Error::Protocol);
    }
    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .map_err(|_| Error::Protocol)?;
    Ok(buffer)
}

/// Verifies that `stream` begins with the 4-byte stream magic and at least an 8-byte header.
pub fn check_stream_header(stream: &[u8]) -> Result<(), Error> {
    if stream.len() < 8 {
        return Err(Error::Protocol);
    }
    if stream[0..4] != EXTRACTOR_STREAM_MAGIC {
        return Err(Error::Protocol);
    }
    Ok(())
}

/// Configuration parameters for generating an ExtractorVM spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractorVmConfig {
    pub vm_id: String,
    pub index: u32,
    pub extractor_image: String,
    pub kernel_image: String,
    pub base_drive: String,
    pub overlay_cow_drive: String,
    pub output_drive: String,
    pub task_class: String,
    pub run_nonce: [u8; 32],
    pub t_clock: u64,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub cpu_template: String,
    pub jail: JailConfig,
}

/// Creates a copy-on-write copy of the agent overlay image via reflink/plain copy.
///
/// Refuses symlinks and non-regular files; verifies parent without following symlinks;
/// opens destination with `O_EXCL` (refuses existing destination); caps copied size;
/// creates target file with mode 0600. The host kernel NEVER mounts this image (TR-EXT-1).
pub fn create_overlay_cow_copy(src_overlay: &Path, dst_cow: &Path) -> Result<(), ExtractorError> {
    // 1. Verify source using symlink_metadata (lstat)
    let src_meta = std::fs::symlink_metadata(src_overlay).map_err(|e| ExtractorError::Io {
        context: "lstat source overlay",
        source: e,
    })?;
    if src_meta.file_type().is_symlink() || !src_meta.file_type().is_file() {
        return Err(ExtractorError::Validation(
            "source overlay must be a regular file, not a symlink or special device",
        ));
    }

    let file_len = src_meta.len();
    if file_len > MAX_OVERLAY_COPY_BYTES {
        return Err(ExtractorError::Validation(
            "source overlay file size exceeds maximum copy limit of 64 GiB",
        ));
    }

    // 2. Open source with O_NOFOLLOW
    let src_fd = rustix::fs::open(
        src_overlay,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ExtractorError::Io {
        context: "open source overlay with O_NOFOLLOW",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;

    // Verify opened fd dev/ino matches lstat
    let fd_stat = rustix::fs::fstat(&src_fd).map_err(|e| ExtractorError::Io {
        context: "fstat source overlay fd",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    if fd_stat.st_dev != src_meta.dev() || fd_stat.st_ino != src_meta.ino() {
        return Err(ExtractorError::Validation(
            "source overlay changed dev/ino between stat and open",
        ));
    }

    // 3. Verify destination parent directory without following symlinks
    let parent = dst_cow.parent().ok_or(ExtractorError::Validation(
        "destination CoW overlay must have a parent directory",
    ))?;
    let parent_meta = std::fs::symlink_metadata(parent).map_err(|e| ExtractorError::Io {
        context: "lstat destination parent directory",
        source: e,
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
        return Err(ExtractorError::Validation(
            "destination parent must be a real directory, not a symlink",
        ));
    }
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ExtractorError::Io {
        context: "open destination parent directory with O_NOFOLLOW",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    let parent_fstat = rustix::fs::fstat(&parent_fd).map_err(|e| ExtractorError::Io {
        context: "fstat destination parent directory fd",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    if parent_fstat.st_dev != parent_meta.dev() || parent_fstat.st_ino != parent_meta.ino() {
        return Err(ExtractorError::Validation(
            "destination parent directory changed dev/ino between stat and open",
        ));
    }

    // 4. Open destination exclusively with O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW and mode 0600 relative to parent_fd
    let dst_filename = dst_cow.file_name().ok_or(ExtractorError::Validation(
        "destination CoW overlay must have a file name",
    ))?;
    let dst_fd = rustix::fs::openat(
        &parent_fd,
        dst_filename,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| ExtractorError::Io {
        context: "create destination CoW overlay with mode 0600 (O_EXCL)",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;

    // 5. Copy data using copy_file_range (reflink where supported), falling back to chunked copy
    let mut total_copied = 0u64;

    while total_copied < file_len {
        let remaining = (file_len - total_copied) as usize;
        let to_copy = remaining.min(1024 * 1024);
        match copy_file_range(&src_fd, None, &dst_fd, None, to_copy) {
            Ok(0) => {
                return Err(ExtractorError::Validation(
                    "source overlay truncated during copy",
                ));
            }
            Ok(n) => {
                total_copied = total_copied.saturating_add(n as u64);
                if total_copied > MAX_OVERLAY_COPY_BYTES {
                    return Err(ExtractorError::Validation(
                        "total copied bytes exceeded maximum overlay copy limit",
                    ));
                }
            }
            Err(
                rustix::io::Errno::XDEV | rustix::io::Errno::NOSYS | rustix::io::Errno::OPNOTSUPP,
            ) => {
                // Fall back to userspace chunked copy
                return fallback_chunked_copy(&src_fd, &dst_fd, file_len, total_copied);
            }
            Err(e) => {
                return Err(ExtractorError::Io {
                    context: "copy_file_range on overlay",
                    source: io::Error::from_raw_os_error(e.raw_os_error()),
                });
            }
        }
    }

    Ok(())
}

pub fn fallback_chunked_copy(
    src_fd: &rustix::fd::OwnedFd,
    dst_fd: &rustix::fd::OwnedFd,
    file_len: u64,
    mut total_copied: u64,
) -> Result<(), ExtractorError> {
    let mut buf = [0u8; HOST_CHUNK_BYTES];
    while total_copied < file_len {
        let read_n = rustix::io::read(src_fd, &mut buf).map_err(|e| ExtractorError::Io {
            context: "read source overlay chunk",
            source: io::Error::from_raw_os_error(e.raw_os_error()),
        })?;
        if read_n == 0 {
            return Err(ExtractorError::Validation(
                "source overlay truncated during copy",
            ));
        }
        let mut written = 0;
        while written < read_n {
            let write_n = rustix::io::write(dst_fd, &buf[written..read_n]).map_err(|e| {
                ExtractorError::Io {
                    context: "write destination CoW overlay chunk",
                    source: io::Error::from_raw_os_error(e.raw_os_error()),
                }
            })?;
            written = written.saturating_add(write_n);
        }
        total_copied = total_copied.saturating_add(read_n as u64);
        if total_copied > MAX_OVERLAY_COPY_BYTES {
            return Err(ExtractorError::Validation(
                "total copied bytes exceeded maximum overlay copy limit",
            ));
        }
    }
    Ok(())
}

/// Creates a fresh, zero-filled raw output drive for ExtractorVM (item E(1)).
///
/// Uses `O_CREAT | O_EXCL` with mode 0600; checks destination parent without following symlinks;
/// refuses existing files and zero-fills the drive up to `size_bytes`.
pub fn create_fresh_output_drive(dst_path: &Path, size_bytes: u64) -> Result<(), ExtractorError> {
    if size_bytes == 0 || size_bytes > MAX_OUTPUT_DRIVE_BYTES {
        return Err(ExtractorError::Validation(
            "output drive size is out of valid bounds (1 byte to 64 GiB)",
        ));
    }

    // 1. Check destination parent without following symlinks
    let parent = dst_path.parent().ok_or(ExtractorError::Validation(
        "output drive must have a parent directory",
    ))?;
    let parent_meta = std::fs::symlink_metadata(parent).map_err(|e| ExtractorError::Io {
        context: "lstat output drive parent directory",
        source: e,
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
        return Err(ExtractorError::Validation(
            "output drive parent must be a real directory, not a symlink",
        ));
    }
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ExtractorError::Io {
        context: "open output drive parent directory with O_NOFOLLOW",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    let parent_fstat = rustix::fs::fstat(&parent_fd).map_err(|e| ExtractorError::Io {
        context: "fstat output drive parent directory fd",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    if parent_fstat.st_dev != parent_meta.dev() || parent_fstat.st_ino != parent_meta.ino() {
        return Err(ExtractorError::Validation(
            "output drive parent directory changed dev/ino between stat and open",
        ));
    }

    // 2. Open destination exclusively with O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW and mode 0600 relative to parent_fd
    let dst_filename = dst_path.file_name().ok_or(ExtractorError::Validation(
        "output drive path must have a file name",
    ))?;
    let dst_fd = rustix::fs::openat(
        &parent_fd,
        dst_filename,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| ExtractorError::Io {
        context: "create fresh output drive with mode 0600 (O_EXCL)",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;

    // 3. Zero-fill the drive
    let zero_buf = [0u8; HOST_CHUNK_BYTES];
    let mut total_written = 0u64;
    while total_written < size_bytes {
        let remaining = (size_bytes - total_written) as usize;
        let to_write = remaining.min(HOST_CHUNK_BYTES);
        let written =
            rustix::io::write(&dst_fd, &zero_buf[..to_write]).map_err(|e| ExtractorError::Io {
                context: "zero-fill fresh output drive",
                source: io::Error::from_raw_os_error(e.raw_os_error()),
            })?;
        if written == 0 {
            return Err(ExtractorError::Validation(
                "zero-fill write returned 0 bytes",
            ));
        }
        total_written = total_written.saturating_add(written as u64);
    }

    Ok(())
}

/// Generates a random 32-byte run nonce from `/dev/urandom`.
pub fn generate_run_nonce() -> io::Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(&mut nonce)?;
    Ok(nonce)
}

/// Constructs a validated `VmSpec` for ExtractorVM.
pub fn extractor_spec(config: &ExtractorVmConfig) -> Result<VmSpec, Error> {
    // 1. Refuse whitespace or control characters in task_class (item F)
    if config
        .task_class
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::Validation(
            "task_class contains whitespace or control characters",
        ));
    }

    // 2. Parse and validate with the same parser the init uses (item F)
    hermetic_extract::config::parse_task_class_spec(&config.task_class)
        .map_err(|_| Error::Validation("invalid task_class specification"))?;

    // 3. Format kernel cmdline passing explicit device paths and run nonce hex (items D, E(2))
    let hex_nonce = config
        .run_nonce
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda init=/sbin/hermetic-extract-init clocksource=tsc tsc=reliable hermetic.t={} ro hermetic.class={} hermetic.base=/dev/vdc hermetic.overlay=/dev/vdd hermetic.output=/dev/vdb hermetic.nonce={}",
        config.t_clock, config.task_class, hex_nonce
    );

    let spec = VmSpec {
        id: config.vm_id.clone(),
        role: Role::Extractor,
        index: config.index,
        vcpus: config.vcpus,
        memory_mib: config.memory_mib,
        kernel_image: config.kernel_image.clone(),
        initrd: None,
        boot_args,
        root_drive: Drive {
            id: "rootfs".into(),
            path: config.extractor_image.clone(),
            read_only: true,
        },
        drives: vec![
            Drive {
                id: "output".into(),
                path: config.output_drive.clone(),
                read_only: false,
            },
            Drive {
                id: "base".into(),
                path: config.base_drive.clone(),
                read_only: true,
            },
            Drive {
                id: "overlay".into(),
                path: config.overlay_cow_drive.clone(),
                read_only: false,
            },
        ],
        reserved_drives: vec![],
        vsock: None,
        networks: vec![],
        cpu_template: config.cpu_template.clone(),
        clock: Clock::Faked,
        limits: EXTRACTOR_LIMITS,
        jail: config.jail.clone(),
    };

    // Run existing VmSpec validation on the result (item F)
    spec.clone().validate()?;

    Ok(spec)
}

/// Reads the raw output drive back, bounds the read by header length, verifies SHA-256 and run nonce,
/// passes the stream to `hermetic-extract` validator, and produces an `ExtractorOutcome`.
pub fn read_extractor_output(
    output_drive_path: &Path,
    expected_nonce: &[u8; 32],
    base_dir: &Path,
    out_dir: &Path,
    class: HostTaskClass,
    extract_config: &ExtractConfig,
) -> Result<ExtractorOutcome, ExtractorError> {
    // 1. Inspect output drive path (no symlinks)
    let meta = std::fs::symlink_metadata(output_drive_path).map_err(|e| ExtractorError::Io {
        context: "lstat output drive",
        source: e,
    })?;
    if meta.file_type().is_symlink() {
        return Err(ExtractorError::Validation(
            "output drive must not be a symlink",
        ));
    }

    // 2. Open output drive with O_NOFOLLOW
    let fd = rustix::fs::open(
        output_drive_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ExtractorError::Io {
        context: "open output drive with O_NOFOLLOW",
        source: io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    let mut file = File::from(fd);

    // 3. Read 80-byte header
    let mut header_buf = [0u8; EXTRACT_DISK_HEADER_BYTES];
    file.seek(SeekFrom::Start(0))
        .map_err(|e| ExtractorError::Io {
            context: "seek to start of output drive",
            source: e,
        })?;
    file.read_exact(&mut header_buf).map_err(|_| {
        ExtractorError::Disk(DiskError::TruncatedHeader {
            expected: EXTRACT_DISK_HEADER_BYTES,
            actual: 0,
        })
    })?;

    let header = ExtractDiskHeader::decode(&header_buf).map_err(ExtractorError::Disk)?;

    // 4. Verify run nonce binding (item E(2))
    if header.nonce != *expected_nonce {
        return Err(ExtractorError::Disk(DiskError::NonceMismatch {
            expected: *expected_nonce,
            actual: header.nonce,
        }));
    }

    // 5. Verify failure code
    if header.failure_code != 0 {
        return Err(ExtractorError::Disk(DiskError::FailureCode(
            header.failure_code,
        )));
    }

    // 5. Bound payload size
    let effective_cap = extract_config.max_total_bytes.min(HARD_MAX_PAYLOAD_BYTES);
    if header.payload_len > effective_cap {
        return Err(ExtractorError::Disk(DiskError::PayloadTooLarge {
            len: header.payload_len,
            max: effective_cap,
        }));
    }

    let payload_len = match usize::try_from(header.payload_len) {
        Ok(len) => len,
        Err(_) => {
            return Err(ExtractorError::Disk(DiskError::PayloadTooLarge {
                len: header.payload_len,
                max: effective_cap,
            }));
        }
    };

    // 6. Read payload bytes bounded by header length
    let mut payload = vec![0u8; payload_len];
    file.read_exact(&mut payload).map_err(|_| {
        ExtractorError::Disk(DiskError::TruncatedPayload {
            expected: header.payload_len,
            actual: 0,
        })
    })?;

    // 7. Verify SHA-256 digest
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let computed_digest: [u8; 32] = hasher.finalize().into();
    if computed_digest != header.sha256 {
        return Err(ExtractorError::Disk(DiskError::Sha256Mismatch {
            expected: header.sha256,
            actual: computed_digest,
        }));
    }

    // 8. Stream through hermetic-extract validator
    let mut cursor = &payload[..];
    let report = validate_stream(&mut cursor, base_dir, out_dir, class, extract_config)
        .map_err(ExtractorError::Extract)?;

    // 9. Collect tamper evidence if test infrastructure was touched or paths dropped
    let mut tamper_parts = Vec::new();
    if !report.dropped.is_empty() {
        tamper_parts.push(format!("dropped:{}", report.dropped.len()));
    }
    if !report.restored.is_empty() {
        tamper_parts.push(format!("restored:{}", report.restored.len()));
    }
    for flag in &report.flags {
        tamper_parts.push(format!("flag:{}:{}", flag.flag_type, flag.path));
    }
    let tamper_evidence = if tamper_parts.is_empty() {
        None
    } else {
        Some(tamper_parts.join(";"))
    };

    Ok(ExtractorOutcome {
        patch_digest: format!("sha256:{}", report.tree_manifest_sha256),
        tamper_evidence,
    })
}

/// Errors originating from host-side ExtractorVM orchestration.
#[derive(Debug)]
pub enum ExtractorError {
    Disk(DiskError),
    Extract(hermetic_extract::error::ExtractError),
    Validation(&'static str),
    Io {
        context: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for ExtractorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractorError::Disk(e) => write!(f, "output drive error: {}", e),
            ExtractorError::Extract(e) => write!(f, "extract validation error: {}", e),
            ExtractorError::Validation(msg) => write!(f, "validation error: {}", msg),
            ExtractorError::Io { context, source } => {
                write!(f, "I/O error during {}: {}", context, source)
            }
        }
    }
}

impl std::error::Error for ExtractorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExtractorError::Disk(e) => Some(e),
            ExtractorError::Extract(e) => Some(e),
            ExtractorError::Io { source, .. } => Some(source),
            ExtractorError::Validation(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_jail() -> JailConfig {
        JailConfig {
            base: "/jails".into(),
            uid_start: 200000,
            gid_start: 200000,
            count: 16,
            firecracker: "/bin/firecracker".into(),
            jailer: "/bin/jailer".into(),
            netns: "isolated-0".into(),
        }
    }

    #[test]
    fn extractor_plan_validates_cleanly() {
        let drives = ExtractorDrives {
            kernel_image: "/images/kernel".into(),
            rootfs_path: "/images/rootfs".into(),
            base_drive_path: "/images/base".into(),
            overlay_drive_path: "/images/overlay".into(),
            cpu_template: "/images/template".into(),
        };
        let plan = ExtractorPlan::new("extractor-vm", drives, 1_700_000_000, sample_jail());
        let spec = plan.validate().expect("extractor spec must validate");
        assert_eq!(spec.spec().role, Role::Extractor);
        assert!(spec.spec().networks.is_empty());
        assert_eq!(spec.spec().vsock.as_ref().unwrap().guest_cid, 3);
        assert_eq!(spec.spec().drives.len(), 2);
        assert!(spec.spec().drives[0].read_only);
        assert!(spec.spec().drives[1].read_only);
    }

    #[test]
    fn stream_header_check_accepts_hext_and_rejects_garbage() {
        assert!(check_stream_header(b"HEXT\x01\x00\x00\x00data").is_ok());
        assert!(check_stream_header(b"HEXT").is_err());
        assert!(check_stream_header(b"BAAD\x01\x00\x00\x00").is_err());
    }

    #[test]
    fn read_length_prefixed_stream_bounds_and_validates() {
        let payload = b"HEXT\x01\x00\x00\x00payload-content";
        let mut data = Vec::new();
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);

        let mut cursor = std::io::Cursor::new(data);
        let read = read_length_prefixed_stream(&mut cursor, 1024).unwrap();
        assert_eq!(read, payload);

        // Reject zero length
        let zero_len = 0u32.to_le_bytes();
        let mut cursor = std::io::Cursor::new(zero_len);
        assert!(read_length_prefixed_stream(&mut cursor, 1024).is_err());

        // Reject length exceeding max_bytes
        let big_len = 2048u32.to_le_bytes();
        let mut cursor = std::io::Cursor::new(big_len);
        assert!(read_length_prefixed_stream(&mut cursor, 1024).is_err());
    }
}
