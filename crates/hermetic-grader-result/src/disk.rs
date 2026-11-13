#![forbid(unsafe_code)]

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub const DISK_BYTES: usize = 1_048_576;
pub const HEADER_BYTES: usize = 44;
pub const PAYLOAD_CAP: usize = 1_048_532;
pub const MAGIC: [u8; 4] = *b"HGRD";
pub const FORMAT_VERSION: u16 = 1;
pub const FLAGS_ZERO: u16 = 0;
pub const SHA256_BYTES: usize = 32;
pub const SHA256_HEX_LEN: usize = 64;
pub const MAX_TESTS: usize = 100_000;
pub const MAX_NODE_ID_BYTES: usize = 1_024;
pub const MAX_INPUT_FILE_BYTES: usize = DISK_BYTES;
pub const READ_CHUNK_BYTES: usize = 4_096;
pub const MAX_READ_ITERATIONS: usize = 16_384;
pub const MAX_WRITE_ITERATIONS: usize = 16_384;
pub const MAX_TEMP_ATTEMPTS: u32 = 64;
pub const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RunId {
    R0,
    R1,
    R2,
    R3,
}

impl RunId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R0 => "R0",
            Self::R1 => "R1",
            Self::R2 => "R2",
            Self::R3 => "R3",
        }
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Error,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupervisorExit {
    Clean,
    Timeout,
    Crash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorSummary {
    pub exit: SupervisorExit,
    pub tests_started: u32,
    pub tests_finished: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    pub run: RunId,
    pub variant_set: String,
    #[serde(deserialize_with = "deserialize_strict_tests_map")]
    pub tests: BTreeMap<String, TestStatus>,
    pub supervisor: SupervisorSummary,
}

impl RunResult {
    pub fn disk_sha256(&self) -> Result<[u8; SHA256_BYTES], DiskError> {
        let (_, digest) = encode_disk(self)?;
        Ok(digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidFileType {
    Symlink,
    Fifo,
    Device,
    Socket,
    Directory,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperReason {
    InvalidDiskSize {
        actual: u64,
    },
    BadMagic,
    UnsupportedVersion(u16),
    NonZeroFlags(u16),
    PayloadLengthExceedsCap {
        len: u32,
    },
    PayloadHashMismatch,
    NonZeroPadding {
        offset: usize,
    },
    InvalidUtf8,
    DuplicateJsonKey,
    InvalidJson,
    NonCanonicalJson,
    InvalidVariantSet,
    TooManyTests {
        count: usize,
    },
    InvalidNodeId,
    InconsistentCounts {
        tests_count: u32,
        started: u32,
        finished: u32,
        passed_count: u32,
    },
    FileIdentityChanged,
    NotRegularFile(InvalidFileType),
}

impl TamperReason {
    pub const fn rule_name(&self) -> &'static str {
        match self {
            Self::InvalidDiskSize { .. } => "invalid_disk_size",
            Self::BadMagic => "bad_magic",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::NonZeroFlags(_) => "non_zero_flags",
            Self::PayloadLengthExceedsCap { .. } => "payload_length_exceeds_cap",
            Self::PayloadHashMismatch => "payload_hash_mismatch",
            Self::NonZeroPadding { .. } => "non_zero_padding",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::DuplicateJsonKey => "duplicate_json_key",
            Self::InvalidJson => "invalid_json",
            Self::NonCanonicalJson => "non_canonical_json",
            Self::InvalidVariantSet => "invalid_variant_set",
            Self::TooManyTests { .. } => "too_many_tests",
            Self::InvalidNodeId => "invalid_node_id",
            Self::InconsistentCounts { .. } => "inconsistent_counts",
            Self::FileIdentityChanged => "file_identity_changed",
            Self::NotRegularFile(_) => "not_regular_file",
        }
    }
}

impl fmt::Display for TamperReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.rule_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskError {
    Tamper(TamperReason),
    NotRegularFile(InvalidFileType),
    Io(io::ErrorKind),
}

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tamper(reason) => write!(f, "tampered disk image: {}", reason.rule_name()),
            Self::NotRegularFile(kind) => write!(f, "refused non-regular file: {:?}", kind),
            Self::Io(kind) => write!(f, "disk I/O error: {:?}", kind),
        }
    }
}

impl std::error::Error for DiskError {}

const ERR_DUPLICATE_KEY: &str = "HERMETIC_ERR_DUPLICATE_KEY";
const ERR_TOO_MANY_TESTS: &str = "HERMETIC_ERR_TOO_MANY_TESTS";
const ERR_INVALID_NODE_ID: &str = "HERMETIC_ERR_INVALID_NODE_ID";

struct StrictTestsVisitor;

impl<'de> Visitor<'de> for StrictTestsVisitor {
    type Value = BTreeMap<String, TestStatus>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of test node IDs to test statuses with no duplicate keys")
    }

    fn visit_map<M>(self, mut access: M) -> Result<BTreeMap<String, TestStatus>, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        let mut count: usize = 0;

        while let Some((key, value)) = access.next_entry::<String, TestStatus>()? {
            let next_count = count
                .checked_add(1)
                .ok_or_else(|| serde::de::Error::custom(ERR_TOO_MANY_TESTS))?;
            if next_count > MAX_TESTS {
                return Err(serde::de::Error::custom(ERR_TOO_MANY_TESTS));
            }
            count = next_count;

            if !is_valid_node_id(&key) {
                return Err(serde::de::Error::custom(ERR_INVALID_NODE_ID));
            }

            if map.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(ERR_DUPLICATE_KEY));
            }
        }

        Ok(map)
    }
}

fn deserialize_strict_tests_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, TestStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(StrictTestsVisitor)
}

pub fn is_valid_node_id(node_id: &str) -> bool {
    if node_id.is_empty() || node_id.len() > MAX_NODE_ID_BYTES {
        return false;
    }
    node_id
        .bytes()
        .take(MAX_NODE_ID_BYTES)
        .all(|b| (0x20..=0x7E).contains(&b))
}

pub fn is_valid_variant_set(variant_set: &str) -> bool {
    if variant_set.len() != SHA256_HEX_LEN {
        return false;
    }
    variant_set
        .bytes()
        .take(SHA256_HEX_LEN)
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_run_result(result: &RunResult) -> Result<(), DiskError> {
    if !is_valid_variant_set(&result.variant_set) {
        return Err(DiskError::Tamper(TamperReason::InvalidVariantSet));
    }

    if result.tests.len() > MAX_TESTS {
        return Err(DiskError::Tamper(TamperReason::TooManyTests {
            count: result.tests.len(),
        }));
    }

    let mut passed_count: u32 = 0;
    for (node_id, status) in result.tests.iter().take(MAX_TESTS) {
        if !is_valid_node_id(node_id) {
            return Err(DiskError::Tamper(TamperReason::InvalidNodeId));
        }
        if *status == TestStatus::Passed {
            passed_count = passed_count.saturating_add(1);
        }
    }

    let tests_count = u32::try_from(result.tests.len()).map_err(|_| {
        DiskError::Tamper(TamperReason::TooManyTests {
            count: result.tests.len(),
        })
    })?;
    let started = result.supervisor.tests_started;
    let finished = result.supervisor.tests_finished;

    if finished > started || started > tests_count || passed_count > finished {
        return Err(DiskError::Tamper(TamperReason::InconsistentCounts {
            tests_count,
            started,
            finished,
            passed_count,
        }));
    }

    Ok(())
}

pub fn sha256_bytes(data: &[u8]) -> [u8; SHA256_BYTES] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; SHA256_BYTES];
    for (dst, src) in out.iter_mut().zip(digest.iter()).take(SHA256_BYTES) {
        *dst = *src;
    }
    out
}

pub fn sha256_hex(digest: &[u8; SHA256_BYTES]) -> String {
    let mut out = String::with_capacity(SHA256_HEX_LEN);
    for byte in digest.iter().take(SHA256_BYTES) {
        let hi = usize::from(*byte >> 4);
        let lo = usize::from(*byte & 0x0F);
        if let Some(&c_hi) = HEX_DIGITS.get(hi) {
            out.push(char::from(c_hi));
        }
        if let Some(&c_lo) = HEX_DIGITS.get(lo) {
            out.push(char::from(c_lo));
        }
    }
    out
}

fn copy_slice_into(dst: &mut [u8], offset: usize, src: &[u8]) -> Result<(), DiskError> {
    let dst_len = dst.len() as u64;
    let end =
        offset
            .checked_add(src.len())
            .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
                actual: DISK_BYTES as u64,
            }))?;
    let target =
        dst.get_mut(offset..end)
            .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
                actual: dst_len,
            }))?;
    target.copy_from_slice(src);
    Ok(())
}

// The serializer must enforce the cap before growing its buffer, including when
// called on an in-memory result rather than an already size-checked disk.
struct PayloadBuffer {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Write for PayloadBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > PAYLOAD_CAP.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_payload(result: &RunResult) -> Result<Vec<u8>, DiskError> {
    let mut buffer = PayloadBuffer {
        bytes: Vec::with_capacity(PAYLOAD_CAP),
        exceeded: false,
    };
    let serialized = serde_json::to_writer(&mut buffer, result);
    if buffer.exceeded {
        return Err(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            // Serialization stopped at the cap; no claimed full length is trusted.
            len: (PAYLOAD_CAP as u32).saturating_add(1),
        }));
    }
    serialized.map_err(|_| DiskError::Tamper(TamperReason::InvalidJson))?;
    Ok(buffer.bytes)
}

pub fn encode_disk(result: &RunResult) -> Result<(Vec<u8>, [u8; SHA256_BYTES]), DiskError> {
    validate_run_result(result)?;

    let payload = canonical_payload(result)?;

    let payload_len_u32 = u32::try_from(payload.len())
        .map_err(|_| DiskError::Tamper(TamperReason::PayloadLengthExceedsCap { len: u32::MAX }))?;
    let payload_hash = sha256_bytes(&payload);

    let mut image = vec![0u8; DISK_BYTES];
    copy_slice_into(&mut image, 0, &MAGIC)?;
    copy_slice_into(&mut image, 4, &FORMAT_VERSION.to_be_bytes())?;
    copy_slice_into(&mut image, 6, &FLAGS_ZERO.to_be_bytes())?;
    copy_slice_into(&mut image, 8, &payload_len_u32.to_be_bytes())?;
    copy_slice_into(&mut image, 12, &payload_hash)?;
    copy_slice_into(&mut image, HEADER_BYTES, &payload)?;

    let disk_hash = sha256_bytes(&image);
    Ok((image, disk_hash))
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Result<u16, DiskError> {
    let end = offset
        .checked_add(2)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let sub = bytes
        .get(offset..end)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let b0 = *sub
        .first()
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let b1 = *sub
        .get(1)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    Ok(u16::from_be_bytes([b0, b1]))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32, DiskError> {
    let end = offset
        .checked_add(4)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let sub = bytes
        .get(offset..end)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let b0 = *sub
        .first()
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let b1 = *sub
        .get(1)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let b2 = *sub
        .get(2)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    let b3 = *sub
        .get(3)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    Ok(u32::from_be_bytes([b0, b1, b2, b3]))
}

pub fn parse_disk_bytes(bytes: &[u8]) -> Result<RunResult, DiskError> {
    if bytes.len() != DISK_BYTES {
        return Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }));
    }

    let magic = bytes
        .get(0..4)
        .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        }))?;
    if magic != MAGIC.as_slice() {
        return Err(DiskError::Tamper(TamperReason::BadMagic));
    }

    let version = read_u16_be(bytes, 4)?;
    if version != FORMAT_VERSION {
        return Err(DiskError::Tamper(TamperReason::UnsupportedVersion(version)));
    }

    let flags = read_u16_be(bytes, 6)?;
    if flags != FLAGS_ZERO {
        return Err(DiskError::Tamper(TamperReason::NonZeroFlags(flags)));
    }

    let payload_len_u32 = read_u32_be(bytes, 8)?;
    let payload_len = usize::try_from(payload_len_u32).map_err(|_| {
        DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: payload_len_u32,
        })
    })?;
    if payload_len > PAYLOAD_CAP {
        return Err(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: payload_len_u32,
        }));
    }

    let expected_hash =
        bytes
            .get(12..HEADER_BYTES)
            .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
                actual: bytes.len() as u64,
            }))?;

    let payload_end = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: payload_len_u32,
        }))?;
    let payload_bytes = bytes
        .get(HEADER_BYTES..payload_end)
        .ok_or(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: payload_len_u32,
        }))?;

    let actual_hash = sha256_bytes(payload_bytes);
    if actual_hash.as_slice() != expected_hash {
        return Err(DiskError::Tamper(TamperReason::PayloadHashMismatch));
    }

    let padding_bytes = bytes.get(payload_end..DISK_BYTES).ok_or(DiskError::Tamper(
        TamperReason::InvalidDiskSize {
            actual: bytes.len() as u64,
        },
    ))?;
    for (idx, &byte) in padding_bytes.iter().enumerate().take(DISK_BYTES) {
        if byte != 0 {
            let offset = payload_end.saturating_add(idx);
            return Err(DiskError::Tamper(TamperReason::NonZeroPadding { offset }));
        }
    }

    let payload_str = std::str::from_utf8(payload_bytes)
        .map_err(|_| DiskError::Tamper(TamperReason::InvalidUtf8))?;

    let result: RunResult = serde_json::from_str(payload_str).map_err(classify_json_error)?;

    validate_run_result(&result)?;

    let canonical_payload = canonical_payload(&result)?;
    if canonical_payload.as_slice() != payload_bytes {
        return Err(DiskError::Tamper(TamperReason::NonCanonicalJson));
    }

    Ok(result)
}

fn classify_json_error(err: serde_json::Error) -> DiskError {
    let msg = err.to_string();
    if msg.starts_with("duplicate field `") || msg.starts_with(ERR_DUPLICATE_KEY) {
        DiskError::Tamper(TamperReason::DuplicateJsonKey)
    } else if msg.starts_with(ERR_TOO_MANY_TESTS) {
        DiskError::Tamper(TamperReason::TooManyTests {
            count: MAX_TESTS.saturating_add(1),
        })
    } else if msg.starts_with(ERR_INVALID_NODE_ID) {
        DiskError::Tamper(TamperReason::InvalidNodeId)
    } else {
        DiskError::Tamper(TamperReason::InvalidJson)
    }
}

// Linux x86_64 open(2) flag and errno values (from the Linux UAPI headers).
// std exposes no named constants for them without an extra dependency, and they
// differ on other targets (on aarch64, for example, 0o400000 is O_LARGEFILE), which
// would silently disable the symlink and FIFO protections. This crate therefore
// targets Linux x86_64 only and refuses to build anywhere else.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!(
    "hermetic-grader-result hard-codes Linux x86_64 open(2) flag values (O_NOFOLLOW, \
     O_NONBLOCK, O_NOCTTY, O_DIRECTORY) and ELOOP; add correct values for this target first"
);
/// Linux x86_64 `O_NOFOLLOW`: fail with ELOOP if the final path component is a symlink.
const LINUX_O_NOFOLLOW: i32 = 0o400_000;
/// Linux x86_64 `O_NONBLOCK`: opening a FIFO never waits for a peer.
const LINUX_O_NONBLOCK: i32 = 0o4_000;
/// Linux x86_64 `O_NOCTTY`: a terminal device never becomes the controlling terminal.
const LINUX_O_NOCTTY: i32 = 0o400;
/// Linux x86_64 `O_DIRECTORY`: fail unless the opened object is a directory.
const LINUX_O_DIRECTORY: i32 = 0o200_000;
/// Linux x86_64 `ELOOP`, returned by `O_NOFOLLOW` opens of a symlink.
const LINUX_ELOOP: i32 = 40;
/// Flags for every open of an existing path in this crate.
const SAFE_OPEN_FLAGS: i32 = LINUX_O_NOFOLLOW | LINUX_O_NONBLOCK | LINUX_O_NOCTTY;
/// Named cap on path components walked by the ancestor symlink check.
pub const MAX_PATH_COMPONENTS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    fn of(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

fn map_open_error(err: io::Error) -> DiskError {
    if err.raw_os_error() == Some(LINUX_ELOOP) {
        DiskError::NotRegularFile(InvalidFileType::Symlink)
    } else {
        DiskError::Io(err.kind())
    }
}

fn verify_regular_metadata(meta: &Metadata) -> Result<(), DiskError> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Symlink));
    }
    if ft.is_fifo() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Fifo));
    }
    if ft.is_char_device() || ft.is_block_device() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Device));
    }
    if ft.is_socket() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Socket));
    }
    if ft.is_dir() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Directory));
    }
    if !ft.is_file() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Other));
    }
    Ok(())
}

fn verify_same_file_identity(sym_meta: &Metadata, open_meta: &Metadata) -> Result<(), DiskError> {
    if FileIdentity::of(sym_meta) != FileIdentity::of(open_meta) {
        return Err(DiskError::Tamper(TamperReason::FileIdentityChanged));
    }
    Ok(())
}

/// Refuses `path` if any ancestor component (every prefix of its parent) is a
/// symlink. Relative paths are checked from the current directory, which is
/// trusted caller state.
fn check_no_symlink_ancestors(path: &Path) -> Result<(), DiskError> {
    let parent = match path.parent() {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut prefix = PathBuf::new();
    for (index, component) in parent.components().enumerate() {
        if index >= MAX_PATH_COMPONENTS {
            return Err(DiskError::Io(io::ErrorKind::InvalidInput));
        }
        prefix.push(component);
        if matches!(component, Component::RootDir | Component::CurDir) {
            continue;
        }
        let meta = fs::symlink_metadata(&prefix).map_err(|e| DiskError::Io(e.kind()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(DiskError::NotRegularFile(InvalidFileType::Symlink));
        }
        if !ft.is_dir() {
            return Err(DiskError::NotRegularFile(InvalidFileType::Other));
        }
    }
    Ok(())
}

pub fn open_regular_file_nofol(path: &Path) -> Result<(File, Metadata), DiskError> {
    open_regular_file_checked(path, &mut || {}, &mut || {})
}

fn open_regular_file_checked(
    path: &Path,
    before_open: &mut dyn FnMut(),
    after_open: &mut dyn FnMut(),
) -> Result<(File, Metadata), DiskError> {
    check_no_symlink_ancestors(path)?;
    let sym_meta = fs::symlink_metadata(path).map_err(|e| DiskError::Io(e.kind()))?;
    verify_regular_metadata(&sym_meta)?;

    before_open();
    // O_NOFOLLOW closes the final-component symlink race and O_NONBLOCK makes a
    // FIFO swapped in after the check open immediately instead of hanging; the
    // fstat below then refuses it.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(SAFE_OPEN_FLAGS)
        .open(path)
        .map_err(map_open_error)?;
    let open_meta = file.metadata().map_err(|e| DiskError::Io(e.kind()))?;
    verify_regular_metadata(&open_meta)?;
    verify_same_file_identity(&sym_meta, &open_meta)?;

    after_open();
    // Re-check after opening: an ancestor swapped for a symlink, or the entry
    // replaced, while the open was in flight is refused.
    check_no_symlink_ancestors(path)?;
    let again = fs::symlink_metadata(path).map_err(|e| DiskError::Io(e.kind()))?;
    verify_regular_metadata(&again)?;
    verify_same_file_identity(&again, &open_meta)?;

    Ok((file, open_meta))
}

pub fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, DiskError> {
    if max_bytes > MAX_INPUT_FILE_BYTES {
        return Err(DiskError::Io(io::ErrorKind::InvalidInput));
    }
    let (mut file, open_meta) = open_regular_file_nofol(path)?;
    let file_len =
        usize::try_from(open_meta.len()).map_err(|_| DiskError::Io(io::ErrorKind::InvalidData))?;
    if file_len > max_bytes {
        return Err(DiskError::Io(io::ErrorKind::InvalidData));
    }

    let mut buf = Vec::with_capacity(max_bytes);
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    let mut total: usize = 0;

    for _ in 0..MAX_READ_ITERATIONS {
        let n = file.read(&mut chunk).map_err(|e| DiskError::Io(e.kind()))?;
        if n == 0 {
            return Ok(buf);
        }
        let next_total = total
            .checked_add(n)
            .ok_or(DiskError::Io(io::ErrorKind::InvalidData))?;
        if next_total > max_bytes {
            return Err(DiskError::Io(io::ErrorKind::InvalidData));
        }
        let read_slice = chunk
            .get(..n)
            .ok_or(DiskError::Io(io::ErrorKind::InvalidData))?;
        buf.extend_from_slice(read_slice);
        total = next_total;
    }

    Err(DiskError::Io(io::ErrorKind::Other))
}

pub fn read_disk<P: AsRef<Path>>(path: P) -> Result<RunResult, DiskError> {
    read_disk_checked(path.as_ref(), &mut || {}, &mut || {})
}

fn read_disk_checked(
    path: &Path,
    before_open: &mut dyn FnMut(),
    after_open: &mut dyn FnMut(),
) -> Result<RunResult, DiskError> {
    let (mut file, open_meta) =
        open_regular_file_checked(path, before_open, after_open).map_err(|err| match err {
            DiskError::NotRegularFile(kind) => {
                DiskError::Tamper(TamperReason::NotRegularFile(kind))
            }
            other => other,
        })?;
    let meta_len = open_meta.len();
    if meta_len != DISK_BYTES as u64 {
        return Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: meta_len,
        }));
    }

    let mut buf = vec![0u8; DISK_BYTES];
    let mut total_read: usize = 0;

    for _ in 0..MAX_READ_ITERATIONS {
        if total_read == DISK_BYTES {
            break;
        }
        let rem =
            buf.get_mut(total_read..)
                .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
                    actual: total_read as u64,
                }))?;
        let n = file.read(rem).map_err(|e| DiskError::Io(e.kind()))?;
        if n == 0 {
            return Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
                actual: total_read as u64,
            }));
        }
        total_read =
            total_read
                .checked_add(n)
                .ok_or(DiskError::Tamper(TamperReason::InvalidDiskSize {
                    actual: DISK_BYTES as u64,
                }))?;
    }

    if total_read != DISK_BYTES {
        return Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: total_read as u64,
        }));
    }

    let mut extra = [0u8; 1];
    let extra_n = file.read(&mut extra).map_err(|e| DiskError::Io(e.kind()))?;
    if extra_n > 0 {
        return Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: (DISK_BYTES as u64).saturating_add(extra_n as u64),
        }));
    }

    parse_disk_bytes(&buf)
}

fn check_destination_not_special(path: &Path) -> Result<(), DiskError> {
    check_no_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => verify_regular_metadata(&meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DiskError::Io(e.kind())),
    }
}

fn parent_directory(path: &Path) -> Result<(&Path, FileIdentity), DiskError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let meta = fs::symlink_metadata(parent).map_err(|e| DiskError::Io(e.kind()))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Symlink));
    }
    if !ft.is_dir() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Other));
    }
    Ok((parent, FileIdentity::of(&meta)))
}

/// Opens the parent directory without following a symlink, requires it to be
/// the directory identified before the write, and fsyncs it.
fn sync_directory(parent: &Path, expected: FileIdentity) -> Result<(), DiskError> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(SAFE_OPEN_FLAGS | LINUX_O_DIRECTORY)
        .open(parent)
        .map_err(map_open_error)?;
    let meta = dir.metadata().map_err(|e| DiskError::Io(e.kind()))?;
    if !meta.file_type().is_dir() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Other));
    }
    if FileIdentity::of(&meta) != expected {
        return Err(DiskError::Tamper(TamperReason::FileIdentityChanged));
    }
    dir.sync_all().map_err(|e| DiskError::Io(e.kind()))
}

/// Unlinks `path` only while it still names the inode this writer created.
/// Anything else at that name (a replacement planted by someone else) is left
/// untouched. Returns whether the entry was removed.
fn remove_if_owned(path: &Path, owned: FileIdentity) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() && FileIdentity::of(&meta) == owned => {
            fs::remove_file(path).is_ok()
        }
        _ => false,
    }
}

fn make_temp_path(parent: &Path, digest_hex: &str, attempt: u32) -> PathBuf {
    let prefix = digest_hex.get(..16).unwrap_or("0000000000000000");
    let file_name = format!(".hgrd-tmp-{}-{}", prefix, attempt);
    parent.join(file_name)
}

fn write_all_bounded(file: &mut File, data: &[u8]) -> Result<(), DiskError> {
    let mut written: usize = 0;
    for _ in 0..MAX_WRITE_ITERATIONS {
        if written == data.len() {
            return Ok(());
        }
        let rem = data
            .get(written..)
            .ok_or(DiskError::Io(io::ErrorKind::WriteZero))?;
        let n = file.write(rem).map_err(|e| DiskError::Io(e.kind()))?;
        if n == 0 {
            return Err(DiskError::Io(io::ErrorKind::WriteZero));
        }
        written = written
            .checked_add(n)
            .ok_or(DiskError::Io(io::ErrorKind::WriteZero))?;
    }
    Err(DiskError::Io(io::ErrorKind::WriteZero))
}

pub fn write_disk<P: AsRef<Path>>(
    result: &RunResult,
    path: P,
) -> Result<[u8; SHA256_BYTES], DiskError> {
    write_disk_checked(
        result,
        path.as_ref(),
        WriteHooks {
            before_rename: &mut |_| {},
            after_rename: &mut |_| {},
            sync_parent: &mut sync_directory,
        },
    )
}

/// Test seams around the publication steps; production uses no-op hooks and
/// `sync_directory`.
struct WriteHooks<'a> {
    before_rename: &'a mut dyn FnMut(&Path),
    after_rename: &'a mut dyn FnMut(&Path),
    sync_parent: &'a mut dyn FnMut(&Path, FileIdentity) -> Result<(), DiskError>,
}

#[cfg(test)]
fn write_disk_with_parent_sync(
    result: &RunResult,
    dest: &Path,
    mut sync_parent: impl FnMut(&Path) -> io::Result<()>,
) -> Result<[u8; SHA256_BYTES], DiskError> {
    write_disk_checked(
        result,
        dest,
        WriteHooks {
            before_rename: &mut |_| {},
            after_rename: &mut |_| {},
            sync_parent: &mut |parent, _| sync_parent(parent).map_err(|e| DiskError::Io(e.kind())),
        },
    )
}

fn write_disk_checked(
    result: &RunResult,
    dest: &Path,
    hooks: WriteHooks<'_>,
) -> Result<[u8; SHA256_BYTES], DiskError> {
    let (image, disk_hash) = encode_disk(result)?;

    check_destination_not_special(dest)?;
    let (parent, parent_id) = parent_directory(dest)?;
    let digest_hex = sha256_hex(&disk_hash);

    let mut created_temp: Option<(File, PathBuf)> = None;
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let candidate = make_temp_path(parent, &digest_hex, attempt);
        let mut options = OpenOptions::new();
        // create_new is O_CREAT|O_EXCL, which never follows a symlink; the
        // extra flags keep every open in this crate uniform.
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(SAFE_OPEN_FLAGS);
        match options.open(&candidate) {
            Ok(file) => {
                created_temp = Some((file, candidate));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(map_open_error(e)),
        }
    }

    // The handle stays open until return, so the owned inode cannot be freed
    // and its number reused while identities are being compared.
    let (mut tmp_file, tmp_path) =
        created_temp.ok_or(DiskError::Io(io::ErrorKind::AlreadyExists))?;
    let tmp_meta = tmp_file.metadata().map_err(|e| DiskError::Io(e.kind()))?;
    let tmp_id = FileIdentity::of(&tmp_meta);
    if let Err(err) = verify_regular_metadata(&tmp_meta) {
        remove_if_owned(&tmp_path, tmp_id);
        return Err(err);
    }

    let write_res = (|| -> Result<(), DiskError> {
        let sym_meta = fs::symlink_metadata(&tmp_path).map_err(|e| DiskError::Io(e.kind()))?;
        verify_regular_metadata(&sym_meta)?;
        verify_same_file_identity(&sym_meta, &tmp_meta)?;
        write_all_bounded(&mut tmp_file, &image)?;
        tmp_file.sync_all().map_err(|e| DiskError::Io(e.kind()))?;
        Ok(())
    })();
    if let Err(err) = write_res {
        remove_if_owned(&tmp_path, tmp_id);
        return Err(err);
    }

    (hooks.before_rename)(&tmp_path);

    // The name being renamed must still be the inode written above; otherwise
    // other bytes would be published under this digest. A foreign entry is
    // never unlinked.
    match fs::symlink_metadata(&tmp_path) {
        Ok(meta) if meta.file_type().is_file() && FileIdentity::of(&meta) == tmp_id => {}
        Ok(_) => return Err(DiskError::Tamper(TamperReason::FileIdentityChanged)),
        Err(e) => return Err(DiskError::Io(e.kind())),
    }

    if let Err(err) = check_destination_not_special(dest) {
        remove_if_owned(&tmp_path, tmp_id);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, dest) {
        remove_if_owned(&tmp_path, tmp_id);
        return Err(DiskError::Io(err.kind()));
    }

    (hooks.after_rename)(dest);

    // The published name must hold exactly the inode written through tmp_file.
    check_no_symlink_ancestors(dest)?;
    let dest_meta = fs::symlink_metadata(dest).map_err(|e| DiskError::Io(e.kind()))?;
    if !dest_meta.file_type().is_file() || FileIdentity::of(&dest_meta) != tmp_id {
        return Err(DiskError::Tamper(TamperReason::FileIdentityChanged));
    }

    (hooks.sync_parent)(parent, parent_id)?;
    drop(tmp_file);

    Ok(disk_hash)
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn payload_buffer_rejects_growth_before_allocation() {
        let mut buffer = PayloadBuffer {
            bytes: vec![0; PAYLOAD_CAP],
            exceeded: false,
        };
        let capacity = buffer.bytes.capacity();
        assert_eq!(
            buffer.write(b"x").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(buffer.exceeded);
        assert_eq!(buffer.bytes.len(), PAYLOAD_CAP);
        assert_eq!(buffer.bytes.capacity(), capacity);
    }

    #[test]
    fn parent_directory_open_and_sync_failures_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("disk");
        let result = RunResult {
            run: RunId::R0,
            variant_set: "a".repeat(SHA256_HEX_LEN),
            tests: BTreeMap::new(),
            supervisor: SupervisorSummary {
                exit: SupervisorExit::Clean,
                tests_started: 0,
                tests_finished: 0,
            },
        };
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::Other] {
            let mut called = false;
            let outcome = write_disk_with_parent_sync(&result, &dest, |parent| {
                called = true;
                assert_eq!(parent, dir.path());
                // The image has already been atomically published, but its
                // durability cannot be claimed if opening/fsyncing the parent fails.
                assert_eq!(read_disk(&dest).unwrap(), result);
                Err(kind.into())
            });
            assert!(called);
            assert_eq!(outcome, Err(DiskError::Io(kind)));
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    fn sample() -> RunResult {
        let mut tests = BTreeMap::new();
        tests.insert("t::a".to_string(), TestStatus::Passed);
        RunResult {
            run: RunId::R0,
            variant_set: "b".repeat(SHA256_HEX_LEN),
            tests,
            supervisor: SupervisorSummary {
                exit: SupervisorExit::Clean,
                tests_started: 1,
                tests_finished: 1,
            },
        }
    }

    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn read_refuses_final_symlink_swapped_in_after_check_even_to_same_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk");
        let moved = dir.path().join("moved");
        write_disk(&sample(), &path).unwrap();
        // The symlink points at the very inode that was checked, so only a
        // no-follow open (not the dev/ino comparison) can refuse it.
        let outcome = read_disk_checked(
            &path,
            &mut || {
                fs::rename(&path, &moved).unwrap();
                std::os::unix::fs::symlink(&moved, &path).unwrap();
            },
            // Restoring the regular file afterwards defeats the post-open
            // re-check, so only the no-follow open itself can refuse this.
            &mut || {
                fs::remove_file(&path).unwrap();
                fs::rename(&moved, &path).unwrap();
            },
        );
        assert_eq!(
            outcome,
            Err(DiskError::Tamper(TamperReason::NotRegularFile(
                InvalidFileType::Symlink
            )))
        );
    }

    #[test]
    fn read_never_blocks_on_fifo_swapped_in_after_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk");
        write_disk(&sample(), &path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread_path = path.clone();
        std::thread::spawn(move || {
            let outcome = read_disk_checked(
                &thread_path,
                &mut || {
                    fs::remove_file(&thread_path).unwrap();
                    mkfifo(&thread_path);
                },
                &mut || {},
            );
            let _ = tx.send(outcome);
        });
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("reader blocked on a FIFO");
        assert_eq!(
            outcome,
            Err(DiskError::Tamper(TamperReason::NotRegularFile(
                InvalidFileType::Fifo
            )))
        );
    }

    #[test]
    fn ancestor_symlinks_are_refused_on_read_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::create_dir(real.join("sub")).unwrap();
        write_disk(&sample(), real.join("sub").join("disk")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            read_disk(link.join("sub").join("disk")),
            Err(DiskError::Tamper(TamperReason::NotRegularFile(
                InvalidFileType::Symlink
            )))
        );
        assert_eq!(
            read_bounded_regular_file(&link.join("sub").join("disk"), DISK_BYTES),
            Err(DiskError::NotRegularFile(InvalidFileType::Symlink))
        );
        // Immediate parent and a deeper ancestor are both refused for writes,
        // and nothing is created behind the link.
        assert_eq!(
            write_disk(&sample(), link.join("new")),
            Err(DiskError::NotRegularFile(InvalidFileType::Symlink))
        );
        assert_eq!(
            write_disk(&sample(), link.join("sub").join("new")),
            Err(DiskError::NotRegularFile(InvalidFileType::Symlink))
        );
        assert_eq!(fs::read_dir(&real).unwrap().count(), 1);
        assert_eq!(fs::read_dir(real.join("sub")).unwrap().count(), 1);
    }

    #[test]
    fn read_rechecks_ancestors_after_open() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        let moved = dir.path().join("moved");
        fs::create_dir(&sub).unwrap();
        let path = sub.join("disk");
        write_disk(&sample(), &path).unwrap();
        let outcome = read_disk_checked(&path, &mut || {}, &mut || {
            fs::rename(&sub, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &sub).unwrap();
        });
        assert_eq!(
            outcome,
            Err(DiskError::Tamper(TamperReason::NotRegularFile(
                InvalidFileType::Symlink
            )))
        );
    }

    #[test]
    fn read_rechecks_entry_identity_after_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk");
        let other = dir.path().join("other");
        write_disk(&sample(), &path).unwrap();
        write_disk(&sample(), &other).unwrap();
        let outcome = read_disk_checked(&path, &mut || {}, &mut || {
            fs::rename(&other, &path).unwrap();
        });
        assert_eq!(
            outcome,
            Err(DiskError::Tamper(TamperReason::FileIdentityChanged))
        );
    }

    #[test]
    fn publication_refuses_swapped_temp_and_keeps_foreign_entry() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("disk");
        let foreign = dir.path().join("foreign");
        let mut swapped_tmp: Option<PathBuf> = None;
        let outcome = write_disk_checked(
            &sample(),
            &dest,
            WriteHooks {
                before_rename: &mut |tmp| {
                    fs::write(&foreign, b"foreign bytes").unwrap();
                    fs::rename(&foreign, tmp).unwrap();
                    swapped_tmp = Some(tmp.to_path_buf());
                },
                after_rename: &mut |_| {},
                sync_parent: &mut sync_directory,
            },
        );
        assert_eq!(
            outcome,
            Err(DiskError::Tamper(TamperReason::FileIdentityChanged))
        );
        assert!(fs::symlink_metadata(&dest).is_err());
        let tmp = swapped_tmp.unwrap();
        assert_eq!(fs::read(&tmp).unwrap(), b"foreign bytes");
    }

    #[test]
    fn publication_verifies_destination_inode_after_rename() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("disk");
        let other = dir.path().join("other");
        let outcome = write_disk_checked(
            &sample(),
            &dest,
            WriteHooks {
                before_rename: &mut |_| {},
                after_rename: &mut |dest| {
                    fs::write(&other, b"other bytes").unwrap();
                    fs::rename(&other, dest).unwrap();
                },
                sync_parent: &mut sync_directory,
            },
        );
        assert_eq!(
            outcome,
            Err(DiskError::Tamper(TamperReason::FileIdentityChanged))
        );
        // The foreign destination is left in place, never unlinked.
        assert_eq!(fs::read(&dest).unwrap(), b"other bytes");
    }

    #[test]
    fn cleanup_never_unlinks_a_foreign_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entry");
        fs::write(&path, b"x").unwrap();
        let real = FileIdentity::of(&fs::symlink_metadata(&path).unwrap());
        let wrong = FileIdentity {
            dev: real.dev,
            ino: real.ino.wrapping_add(1),
        };
        assert!(!remove_if_owned(&path, wrong));
        assert!(path.exists());
        assert!(remove_if_owned(&path, real));
        assert!(!path.exists());
    }

    #[test]
    fn directory_sync_requires_the_identified_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = FileIdentity::of(&fs::symlink_metadata(dir.path()).unwrap());
        assert_eq!(sync_directory(dir.path(), real), Ok(()));
        let wrong = FileIdentity {
            dev: real.dev,
            ino: real.ino.wrapping_add(1),
        };
        assert_eq!(
            sync_directory(dir.path(), wrong),
            Err(DiskError::Tamper(TamperReason::FileIdentityChanged))
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        // Following the link would reach the identified directory and succeed;
        // the no-follow directory open makes the kernel refuse it (ENOTDIR).
        assert_eq!(
            sync_directory(&link, real),
            Err(DiskError::Io(io::ErrorKind::NotADirectory))
        );
    }
}
