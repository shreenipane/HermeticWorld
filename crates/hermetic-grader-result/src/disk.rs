#![forbid(unsafe_code)]

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

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

pub fn encode_disk(result: &RunResult) -> Result<(Vec<u8>, [u8; SHA256_BYTES]), DiskError> {
    validate_run_result(result)?;

    let payload =
        serde_json::to_vec(result).map_err(|_| DiskError::Tamper(TamperReason::InvalidJson))?;

    if payload.len() > PAYLOAD_CAP {
        let capped_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        return Err(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: capped_len,
        }));
    }

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

    let canonical_payload =
        serde_json::to_vec(&result).map_err(|_| DiskError::Tamper(TamperReason::InvalidJson))?;
    if canonical_payload.as_slice() != payload_bytes {
        return Err(DiskError::Tamper(TamperReason::NonCanonicalJson));
    }

    Ok(result)
}

fn classify_json_error(err: serde_json::Error) -> DiskError {
    let msg = err.to_string();
    if msg.contains("duplicate field") || msg.contains(ERR_DUPLICATE_KEY) {
        DiskError::Tamper(TamperReason::DuplicateJsonKey)
    } else if msg.contains(ERR_TOO_MANY_TESTS) {
        DiskError::Tamper(TamperReason::TooManyTests {
            count: MAX_TESTS.saturating_add(1),
        })
    } else if msg.contains(ERR_INVALID_NODE_ID) {
        DiskError::Tamper(TamperReason::InvalidNodeId)
    } else {
        DiskError::Tamper(TamperReason::InvalidJson)
    }
}

fn verify_regular_metadata(meta: &Metadata) -> Result<(), DiskError> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(DiskError::NotRegularFile(InvalidFileType::Symlink));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return Err(DiskError::NotRegularFile(InvalidFileType::Fifo));
        }
        if ft.is_char_device() || ft.is_block_device() {
            return Err(DiskError::NotRegularFile(InvalidFileType::Device));
        }
        if ft.is_socket() {
            return Err(DiskError::NotRegularFile(InvalidFileType::Socket));
        }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if sym_meta.dev() != open_meta.dev() || sym_meta.ino() != open_meta.ino() {
            return Err(DiskError::Tamper(TamperReason::FileIdentityChanged));
        }
    }
    #[cfg(not(unix))]
    {
        if sym_meta.len() != open_meta.len() {
            return Err(DiskError::Tamper(TamperReason::FileIdentityChanged));
        }
    }
    Ok(())
}

pub fn open_regular_file_nofol(path: &Path) -> Result<(File, Metadata), DiskError> {
    let sym_meta = fs::symlink_metadata(path).map_err(|e| DiskError::Io(e.kind()))?;
    verify_regular_metadata(&sym_meta)?;

    let file = File::open(path).map_err(|e| DiskError::Io(e.kind()))?;
    let open_meta = file.metadata().map_err(|e| DiskError::Io(e.kind()))?;
    verify_regular_metadata(&open_meta)?;
    verify_same_file_identity(&sym_meta, &open_meta)?;

    Ok((file, open_meta))
}

pub fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, DiskError> {
    let (mut file, open_meta) = open_regular_file_nofol(path)?;
    let file_len =
        usize::try_from(open_meta.len()).map_err(|_| DiskError::Io(io::ErrorKind::InvalidData))?;
    if file_len > max_bytes {
        return Err(DiskError::Io(io::ErrorKind::InvalidData));
    }

    let mut buf = Vec::with_capacity(file_len);
    let mut chunk = [0u8; 4096];
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
    let (mut file, open_meta) = open_regular_file_nofol(path.as_ref())?;
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
    match fs::symlink_metadata(path) {
        Ok(meta) => verify_regular_metadata(&meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DiskError::Io(e.kind())),
    }
}

fn parent_directory(path: &Path) -> Result<&Path, DiskError> {
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
    Ok(parent)
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
    let dest = path.as_ref();
    let (image, disk_hash) = encode_disk(result)?;

    check_destination_not_special(dest)?;
    let parent = parent_directory(dest)?;
    let digest_hex = sha256_hex(&disk_hash);

    let mut created_temp: Option<(File, PathBuf)> = None;
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let candidate = make_temp_path(parent, &digest_hex, attempt);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                created_temp = Some((file, candidate));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(DiskError::Io(e.kind())),
        }
    }

    let (mut tmp_file, tmp_path) =
        created_temp.ok_or(DiskError::Io(io::ErrorKind::AlreadyExists))?;

    let write_res = (|| -> Result<(), DiskError> {
        let sym_meta = fs::symlink_metadata(&tmp_path).map_err(|e| DiskError::Io(e.kind()))?;
        verify_regular_metadata(&sym_meta)?;
        let open_meta = tmp_file.metadata().map_err(|e| DiskError::Io(e.kind()))?;
        verify_regular_metadata(&open_meta)?;
        verify_same_file_identity(&sym_meta, &open_meta)?;

        write_all_bounded(&mut tmp_file, &image)?;
        tmp_file.sync_all().map_err(|e| DiskError::Io(e.kind()))?;
        Ok(())
    })();

    drop(tmp_file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = check_destination_not_special(dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(DiskError::Io(err.kind()));
    }

    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    Ok(disk_hash)
}
