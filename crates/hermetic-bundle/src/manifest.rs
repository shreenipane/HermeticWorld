use crate::BundleError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Manifest schema format identifier.
pub const FORMAT_VERSION: &str = "hermetic-bundle/v1";

/// Canonical filename written at the bundle root.
pub const MANIFEST_FILENAME: &str = "bundle.manifest.json";

/// Maximum number of entries allowed in a single bundle manifest.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Maximum UTF-8 byte length of a bundle-relative path.
pub const MAX_PATH_BYTES: usize = 4_096;

/// Maximum UTF-8 byte length of any single path component.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Maximum directory tree depth (number of path components).
pub const MAX_DEPTH: usize = 128;

/// Maximum cumulative byte size across all regular files in a bundle (64 GiB).
pub const MAX_TOTAL_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Streaming buffer size used when hashing file contents (64 KiB).
pub const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum byte size allowed when reading `bundle.manifest.json` (512 MiB).
pub const MAX_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum directory entries inspected across a single tree walk.
pub const MAX_DIR_ITERATIONS: usize = 2_000_000;

/// Maximum JSON object/array nesting depth accepted when parsing manifests.
pub const MAX_JSON_NESTING_DEPTH: usize = 16;

/// Maximum number of atomic temporary file name attempts when writing manifests.
pub const MAX_TEMP_ATTEMPTS: u32 = 64;

/// Multiplier for maximum parser steps per byte during duplicate key scanning.
pub const MAX_JSON_SCAN_STEPS_MULTIPLIER: usize = 4;

/// Base step allowance for duplicate key scanning.
pub const MAX_JSON_SCAN_STEPS_BASE: usize = 1024;

/// No schema object contains more than six keys.
const MAX_JSON_OBJECT_KEYS: usize = 6;
/// Longest decoded JSON string permitted before schema deserialization.
const MAX_JSON_STRING_BYTES: usize = MAX_PATH_BYTES;
const MAX_JSON_ARRAY_ITEMS: usize = MAX_ENTRIES;

const HEX_DIGEST_LEN: usize = 64;
const ROOT_PREFIX: &str = "sha256:";

/// Type of filesystem object recorded in a bundle manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryKind::File => write!(f, "file"),
            EntryKind::Dir => write!(f, "dir"),
        }
    }
}

/// Normalized POSIX permission mode recorded in a bundle manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EntryMode {
    #[serde(rename = "0644")]
    Mode0644,
    #[serde(rename = "0755")]
    Mode0755,
}

impl fmt::Display for EntryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryMode::Mode0644 => write!(f, "0644"),
            EntryMode::Mode0755 => write!(f, "0755"),
        }
    }
}

/// A single file or directory entry inside `bundle.manifest.json`.
///
/// Field declaration order matches the canonical JSON schema:
/// `path`, `kind`, `mode`, and (for files only) `size` and `sha256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: String,
    pub kind: EntryKind,
    pub mode: EntryMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl ManifestEntry {
    /// Serializes this entry to its canonical compact UTF-8 JSON bytes.
    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, BundleError> {
        self.validate()?;
        bounded_json(self)
    }

    fn validate(&self) -> Result<(), BundleError> {
        validate_relative_path(&self.path)?;
        match self.kind {
            EntryKind::File => {
                let size = self
                    .size
                    .ok_or_else(|| invalid("file entry missing size"))?;
                if size > MAX_TOTAL_FILE_BYTES {
                    return Err(BundleError::LimitExceeded {
                        limit: "MAX_TOTAL_FILE_BYTES",
                        max: MAX_TOTAL_FILE_BYTES,
                    });
                }
                if !self.sha256.as_deref().is_some_and(is_lower_hex_64) {
                    return Err(invalid("file entry has invalid or missing sha256"));
                }
            }
            EntryKind::Dir => {
                if self.mode != EntryMode::Mode0755 || self.size.is_some() || self.sha256.is_some()
                {
                    return Err(invalid(
                        "directory entry must have mode 0755 and no file fields",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Top-level canonical manifest written to `bundle.manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub entries: Vec<ManifestEntry>,
    pub root: String,
}

impl Manifest {
    /// Serializes the manifest to canonical compact UTF-8 JSON bytes.
    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, BundleError> {
        self.validate()?;
        bounded_json(self)
    }

    /// Parses and validates canonical manifest JSON bytes, rejecting duplicate keys,
    /// unknown fields, unsorted or invalid paths, and out-of-range caps.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Manifest, BundleError> {
        if (bytes.len() as u64) > MAX_MANIFEST_BYTES {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_MANIFEST_BYTES",
                max: MAX_MANIFEST_BYTES,
            });
        }
        validate_json_no_duplicate_keys(bytes)?;
        let manifest: Manifest =
            serde_json::from_slice(bytes).map_err(|_| invalid("JSON parse/schema error"))?;
        manifest.validate()?;
        if manifest.to_canonical_json_bytes()? != bytes {
            return Err(invalid("manifest JSON is not canonical"));
        }
        Ok(manifest)
    }

    /// Validates all structural, path, sorting, case-uniqueness, and cap invariants.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.format != FORMAT_VERSION {
            return Err(BundleError::ManifestInvalid {
                reason: "unsupported manifest format".to_string(),
            });
        }

        validate_root_digest(&self.root)?;

        if self.entries.len() > MAX_ENTRIES {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_ENTRIES",
                max: MAX_ENTRIES as u64,
            });
        }

        let mut prev_path: Option<&[u8]> = None;
        let mut seen_lower: BTreeSet<String> = BTreeSet::new();
        let mut total_bytes: u64 = 0;
        let mut parents = std::collections::BTreeMap::new();

        for entry in &self.entries {
            entry.validate()?;
            if let Some((parent, _)) = entry.path.rsplit_once('/') {
                if parents.get(parent) != Some(&EntryKind::Dir) {
                    return Err(invalid("entry parent must be an earlier directory entry"));
                }
            }
            parents.insert(entry.path.as_str(), entry.kind);

            let path_bytes = entry.path.as_bytes();
            if let Some(prev) = prev_path {
                if prev >= path_bytes {
                    return Err(BundleError::ManifestInvalid {
                        reason: format!(
                            "entries not strictly sorted by path bytes at '{}'",
                            entry.path
                        ),
                    });
                }
            }
            prev_path = Some(path_bytes);

            let lower = entry.path.to_ascii_lowercase();
            if !seen_lower.insert(lower) {
                return Err(BundleError::ManifestInvalid {
                    reason: format!("ASCII case collision on path '{}'", entry.path),
                });
            }

            match entry.kind {
                EntryKind::File => {
                    let size = entry.size.ok_or_else(|| BundleError::ManifestInvalid {
                        reason: format!("file entry '{}' missing size", entry.path),
                    })?;
                    let sha =
                        entry
                            .sha256
                            .as_deref()
                            .ok_or_else(|| BundleError::ManifestInvalid {
                                reason: format!("file entry '{}' missing sha256", entry.path),
                            })?;
                    if !is_lower_hex_64(sha) {
                        return Err(BundleError::ManifestInvalid {
                            reason: format!("file entry '{}' has invalid sha256", entry.path),
                        });
                    }
                    total_bytes =
                        total_bytes
                            .checked_add(size)
                            .ok_or(BundleError::LimitExceeded {
                                limit: "MAX_TOTAL_FILE_BYTES",
                                max: MAX_TOTAL_FILE_BYTES,
                            })?;
                    if total_bytes > MAX_TOTAL_FILE_BYTES {
                        return Err(BundleError::LimitExceeded {
                            limit: "MAX_TOTAL_FILE_BYTES",
                            max: MAX_TOTAL_FILE_BYTES,
                        });
                    }
                }
                EntryKind::Dir => {
                    if entry.mode != EntryMode::Mode0755 {
                        return Err(BundleError::ManifestInvalid {
                            reason: format!("directory entry '{}' must have mode 0755", entry.path),
                        });
                    }
                    if entry.size.is_some() || entry.sha256.is_some() {
                        return Err(BundleError::ManifestInvalid {
                            reason: format!(
                                "directory entry '{}' must not carry size or sha256",
                                entry.path
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

/// Overall verification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Ok,
    Mismatch,
}

/// File size discrepancy between manifest and filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeMismatch {
    pub path: String,
    pub expected: u64,
    pub actual: u64,
}

/// File SHA-256 digest discrepancy between manifest and filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashMismatch {
    pub path: String,
    pub expected: String,
    pub actual: String,
}

/// Normalized mode discrepancy between manifest and filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeMismatch {
    pub path: String,
    pub expected: EntryMode,
    pub actual: EntryMode,
}

/// Object kind discrepancy (`file` vs `dir`) between manifest and filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindMismatch {
    pub path: String,
    pub expected: EntryKind,
    pub actual: EntryKind,
}

/// Category of filesystem object or path refused by Hermetic World sealing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusedKind {
    Symlink,
    HardLink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    SpecialFile,
    InvalidPath,
    CaseCollision,
}

impl fmt::Display for RefusedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RefusedKind::Symlink => "symlink",
            RefusedKind::HardLink => "hard_link",
            RefusedKind::Fifo => "fifo",
            RefusedKind::Socket => "socket",
            RefusedKind::BlockDevice => "block_device",
            RefusedKind::CharDevice => "char_device",
            RefusedKind::SpecialFile => "special_file",
            RefusedKind::InvalidPath => "invalid_path",
            RefusedKind::CaseCollision => "case_collision",
        };
        write!(f, "{s}")
    }
}

/// A refused filesystem object encountered at a bundle-relative path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedObject {
    pub path: String,
    pub kind: RefusedKind,
}

/// Verification report emitted by `verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub verdict: Verdict,
    pub manifest_root: String,
    pub recomputed_root: String,
    pub manifest_root_matches: bool,
    pub expected_root: Option<String>,
    pub expected_root_matches: Option<bool>,
    pub missing_entries: Vec<String>,
    pub extra_entries: Vec<String>,
    pub size_mismatches: Vec<SizeMismatch>,
    pub hash_mismatches: Vec<HashMismatch>,
    pub mode_mismatches: Vec<ModeMismatch>,
    pub kind_mismatches: Vec<KindMismatch>,
    pub refused_objects: Vec<RefusedObject>,
}

/// Validates a bundle-relative path according to Hermetic World rules:
/// - non-empty UTF-8 string, at most `MAX_PATH_BYTES` (4096) bytes
/// - `/` separators, no leading `/`, no trailing `/`, no empty components
/// - no `.` or `..` components, no NUL bytes, no `\` characters
/// - each component at most `MAX_COMPONENT_BYTES` (255) bytes
/// - at most `MAX_DEPTH` (128) components
/// - not equal to `bundle.manifest.json`
pub fn validate_relative_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty() {
        return Err(BundleError::InvalidPath {
            path: String::new(),
            reason: "empty path",
        });
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_PATH_BYTES",
            max: MAX_PATH_BYTES as u64,
        });
    }
    if path.starts_with('/') {
        return Err(BundleError::InvalidPath {
            path: "<invalid>".to_string(),
            reason: "leading slash in path",
        });
    }
    if path.as_bytes().contains(&0) {
        return Err(BundleError::InvalidPath {
            path: sanitize_path_for_error(path),
            reason: "NUL byte in path",
        });
    }
    if path.contains('\\') {
        return Err(BundleError::InvalidPath {
            path: path.to_string(),
            reason: "backslash in path",
        });
    }
    if path.ends_with('/') {
        return Err(BundleError::InvalidPath {
            path: path.to_string(),
            reason: "trailing slash in path",
        });
    }
    if path
        .split('/')
        .next()
        .is_some_and(|part| part.eq_ignore_ascii_case(MANIFEST_FILENAME))
    {
        return Err(BundleError::InvalidPath {
            path: path.to_string(),
            reason: "manifest filename cannot be a bundle entry",
        });
    }

    let mut depth: usize = 0;
    for component in path.split('/') {
        depth = depth.checked_add(1).ok_or(BundleError::LimitExceeded {
            limit: "MAX_DEPTH",
            max: MAX_DEPTH as u64,
        })?;
        if depth > MAX_DEPTH {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_DEPTH",
                max: MAX_DEPTH as u64,
            });
        }
        if component.is_empty() {
            return Err(BundleError::InvalidPath {
                path: path.to_string(),
                reason: "empty path component",
            });
        }
        if component == "." || component == ".." {
            return Err(BundleError::InvalidPath {
                path: path.to_string(),
                reason: "dot or dot-dot component",
            });
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_COMPONENT_BYTES",
                max: MAX_COMPONENT_BYTES as u64,
            });
        }
    }

    Ok(())
}

/// Validates that `root` has the exact form `"sha256:<64 lowercase hex characters>"`.
pub fn validate_root_digest(root: &str) -> Result<(), BundleError> {
    let hex_part = root
        .strip_prefix(ROOT_PREFIX)
        .ok_or_else(|| BundleError::ManifestInvalid {
            reason: "root must start with 'sha256:'".to_string(),
        })?;
    if !is_lower_hex_64(hex_part) {
        return Err(BundleError::ManifestInvalid {
            reason: "root digest must be 64 lowercase hex characters".to_string(),
        });
    }
    Ok(())
}

/// Computes the Merkle-style bundle root digest:
/// `root = "sha256:" + hex(SHA-256(concat_{e in entries} SHA-256(canonical_json(e))))`
/// where `entries` are sorted by `e.path.as_bytes()`.
pub fn compute_root(entries: &[ManifestEntry]) -> Result<String, BundleError> {
    if entries.len() > MAX_ENTRIES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_ENTRIES",
            max: MAX_ENTRIES as u64,
        });
    }

    let mut total = 0u64;
    for entry in entries {
        entry.validate()?;
        total = total
            .checked_add(entry.size.unwrap_or(0))
            .ok_or(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            })?;
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            });
        }
    }
    let mut ordered: Vec<&ManifestEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    let mut outer = Sha256::new();
    for entry in ordered {
        let canonical_entry = entry.to_canonical_json_bytes()?;
        let inner_digest = Sha256::digest(&canonical_entry);
        outer.update(inner_digest);
    }

    let root_bytes = outer.finalize();
    let hex = encode_lower_hex(&root_bytes);
    Ok(format!("{ROOT_PREFIX}{hex}"))
}

pub(crate) fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = usize::from((b >> 4) & 0x0f);
        let lo = usize::from(b & 0x0f);
        if let (Some(&c_hi), Some(&c_lo)) = (HEX_CHARS.get(hi), HEX_CHARS.get(lo)) {
            out.push(char::from(c_hi));
            out.push(char::from(c_lo));
        }
    }
    out
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == HEX_DIGEST_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sanitize_path_for_error(path: &str) -> String {
    path.chars()
        .map(|c| if c == '\0' { '?' } else { c })
        .collect()
}

/// Validates JSON syntax up to `MAX_JSON_NESTING_DEPTH` and rejects any JSON object
/// containing duplicate keys (including keys that match after JSON `\uXXXX` unescaping).
fn validate_json_no_duplicate_keys(bytes: &[u8]) -> Result<(), BundleError> {
    let mut parser = JsonKeyScanner::new(bytes);
    parser.skip_ws();
    parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != bytes.len() {
        return Err(BundleError::ManifestInvalid {
            reason: "trailing non-whitespace bytes after JSON root".to_string(),
        });
    }
    Ok(())
}

struct JsonKeyScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    steps: usize,
    max_steps: usize,
}

impl<'a> JsonKeyScanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        let max_steps = bytes
            .len()
            .saturating_mul(MAX_JSON_SCAN_STEPS_MULTIPLIER)
            .saturating_add(MAX_JSON_SCAN_STEPS_BASE);
        Self {
            bytes,
            pos: 0,
            steps: 0,
            max_steps,
        }
    }

    fn tick(&mut self) -> Result<(), BundleError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.max_steps {
            return Err(BundleError::ManifestInvalid {
                reason: "JSON parser step bound exceeded".to_string(),
            });
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.bytes.get(self.pos).copied()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<(), BundleError> {
        self.tick()?;
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(BundleError::ManifestInvalid {
                reason: "JSON nesting depth exceeded".to_string(),
            });
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth.saturating_add(1)),
            Some(b'[') => self.parse_array(depth.saturating_add(1)),
            Some(b'"') => {
                let _ = self.parse_string()?;
                Ok(())
            }
            Some(b't') => self.expect_literal(b"true"),
            Some(b'f') => self.expect_literal(b"false"),
            Some(b'n') => self.expect_literal(b"null"),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(BundleError::ManifestInvalid {
                reason: "unexpected JSON token".to_string(),
            }),
        }
    }

    fn expect_literal(&mut self, lit: &[u8]) -> Result<(), BundleError> {
        for &expected in lit {
            if self.bump() != Some(expected) {
                return Err(BundleError::ManifestInvalid {
                    reason: "invalid JSON literal".to_string(),
                });
            }
        }
        Ok(())
    }

    fn parse_number(&mut self) -> Result<(), BundleError> {
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => {
                self.bump();
            }
            Some(b'1'..=b'9') => {
                self.bump();
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.bump();
                }
            }
            _ => {
                return Err(BundleError::ManifestInvalid {
                    reason: "invalid JSON number".to_string(),
                });
            }
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(BundleError::ManifestInvalid {
                    reason: "invalid JSON fraction".to_string(),
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(BundleError::ManifestInvalid {
                    reason: "invalid JSON exponent".to_string(),
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.bump();
            }
        }
        Ok(())
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), BundleError> {
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(invalid("JSON nesting depth exceeded"));
        }
        if self.bump() != Some(b'{') {
            return Err(BundleError::ManifestInvalid {
                reason: "expected '{'".to_string(),
            });
        }
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(());
        }

        let mut seen_keys: BTreeSet<String> = BTreeSet::new();
        loop {
            self.tick()?;
            self.skip_ws();
            let key = self.parse_string()?;
            if seen_keys.len() >= MAX_JSON_OBJECT_KEYS {
                return Err(BundleError::LimitExceeded {
                    limit: "MAX_JSON_OBJECT_KEYS",
                    max: MAX_JSON_OBJECT_KEYS as u64,
                });
            }
            if !seen_keys.insert(key) {
                return Err(BundleError::ManifestInvalid {
                    reason: "duplicate key in JSON object".to_string(),
                });
            }
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(BundleError::ManifestInvalid {
                    reason: "expected ':' after JSON object key".to_string(),
                });
            }
            self.parse_value(depth)?;
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(()),
                _ => {
                    return Err(BundleError::ManifestInvalid {
                        reason: "expected ',' or '}' in JSON object".to_string(),
                    });
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), BundleError> {
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(invalid("JSON nesting depth exceeded"));
        }
        if self.bump() != Some(b'[') {
            return Err(BundleError::ManifestInvalid {
                reason: "expected '['".to_string(),
            });
        }
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(());
        }

        let mut count = 0usize;
        loop {
            if count >= MAX_JSON_ARRAY_ITEMS {
                return Err(BundleError::LimitExceeded {
                    limit: "MAX_ENTRIES",
                    max: MAX_ENTRIES as u64,
                });
            }
            count = count.saturating_add(1);
            self.tick()?;
            self.parse_value(depth)?;
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => return Ok(()),
                _ => {
                    return Err(BundleError::ManifestInvalid {
                        reason: "expected ',' or ']' in JSON array".to_string(),
                    });
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, BundleError> {
        if self.bump() != Some(b'"') {
            return Err(BundleError::ManifestInvalid {
                reason: "expected JSON string".to_string(),
            });
        }
        let mut raw_utf8: Vec<u8> = Vec::new();
        let mut utf16_units: Vec<u16> = Vec::new();

        loop {
            let b = self.bump().ok_or_else(|| BundleError::ManifestInvalid {
                reason: "unterminated JSON string".to_string(),
            })?;
            if b == b'"' {
                flush_utf16(&mut utf16_units, &mut raw_utf8)?;
                if raw_utf8.len() > MAX_JSON_STRING_BYTES {
                    return Err(BundleError::LimitExceeded {
                        limit: "MAX_JSON_STRING_BYTES",
                        max: MAX_JSON_STRING_BYTES as u64,
                    });
                }
                return String::from_utf8(raw_utf8).map_err(|_| BundleError::ManifestInvalid {
                    reason: "invalid UTF-8 in JSON string".to_string(),
                });
            }
            if b < 0x20 {
                return Err(BundleError::ManifestInvalid {
                    reason: "unescaped control character in JSON string".to_string(),
                });
            }
            if b == b'\\' {
                let esc = self.bump().ok_or_else(|| BundleError::ManifestInvalid {
                    reason: "unterminated escape in JSON string".to_string(),
                })?;
                if esc == b'u' {
                    let unit = self.parse_hex_u16()?;
                    if utf16_units.len() >= MAX_JSON_STRING_BYTES {
                        return Err(BundleError::LimitExceeded {
                            limit: "MAX_JSON_STRING_BYTES",
                            max: MAX_JSON_STRING_BYTES as u64,
                        });
                    }
                    utf16_units.push(unit);
                } else {
                    flush_utf16(&mut utf16_units, &mut raw_utf8)?;
                    let mapped = match esc {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        _ => {
                            return Err(BundleError::ManifestInvalid {
                                reason: "invalid escape sequence in JSON string".to_string(),
                            });
                        }
                    };
                    push_string_byte(&mut raw_utf8, mapped)?;
                }
            } else {
                flush_utf16(&mut utf16_units, &mut raw_utf8)?;
                push_string_byte(&mut raw_utf8, b)?;
            }
        }
    }

    fn parse_hex_u16(&mut self) -> Result<u16, BundleError> {
        let mut acc: u16 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| BundleError::ManifestInvalid {
                reason: "incomplete \\u escape".to_string(),
            })?;
            let nibble = match b {
                b'0'..=b'9' => u16::from(b - b'0'),
                b'a'..=b'f' => u16::from(b - b'a').saturating_add(10),
                b'A'..=b'F' => u16::from(b - b'A').saturating_add(10),
                _ => {
                    return Err(BundleError::ManifestInvalid {
                        reason: "non-hex digit in \\u escape".to_string(),
                    });
                }
            };
            acc = (acc << 4) | nibble;
        }
        Ok(acc)
    }
}

fn push_string_byte(out: &mut Vec<u8>, byte: u8) -> Result<(), BundleError> {
    if out.len() >= MAX_JSON_STRING_BYTES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_JSON_STRING_BYTES",
            max: MAX_JSON_STRING_BYTES as u64,
        });
    }
    out.push(byte);
    Ok(())
}

fn flush_utf16(units: &mut Vec<u16>, out_utf8: &mut Vec<u8>) -> Result<(), BundleError> {
    if units.is_empty() {
        return Ok(());
    }
    let mut enc_buf = [0u8; 4];
    for decoded in char::decode_utf16(units.iter().copied()) {
        let ch = decoded.map_err(|_| BundleError::ManifestInvalid {
            reason: "unpaired UTF-16 surrogate in JSON string".to_string(),
        })?;
        let s = ch.encode_utf8(&mut enc_buf);
        if out_utf8.len().saturating_add(s.len()) > MAX_JSON_STRING_BYTES {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_JSON_STRING_BYTES",
                max: MAX_JSON_STRING_BYTES as u64,
            });
        }
        out_utf8.extend_from_slice(s.as_bytes());
    }
    units.clear();
    Ok(())
}

fn invalid(reason: &'static str) -> BundleError {
    BundleError::ManifestInvalid {
        reason: reason.to_string(),
    }
}

/// Bound the output while serializing, rather than after allocating it.
fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>, BundleError> {
    bounded_json_with_cap(value, MAX_MANIFEST_BYTES)
}

fn bounded_json_with_cap(value: &impl Serialize, cap: u64) -> Result<Vec<u8>, BundleError> {
    struct CappedJson {
        bytes: Vec<u8>,
        cap: u64,
        exceeded: bool,
    }
    impl std::io::Write for CappedJson {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if (self.bytes.len() as u64).saturating_add(bytes.len() as u64) > self.cap {
                self.exceeded = true;
                return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = CappedJson {
        bytes: Vec::new(),
        cap,
        exceeded: false,
    };
    if serde_json::to_writer(&mut out, value).is_err() {
        if out.exceeded {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_MANIFEST_BYTES",
                max: cap,
            });
        }
        return Err(invalid("JSON serialization error"));
    }
    Ok(out.bytes)
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    #[test]
    fn scanner_bounds_allocations_before_schema_deserialization() {
        for string in [
            format!("\"{}\"", "a".repeat(MAX_JSON_STRING_BYTES + 1)),
            format!("\"{}\"", "\\u0061".repeat(MAX_JSON_STRING_BYTES + 1)),
        ] {
            assert!(matches!(
                validate_json_no_duplicate_keys(string.as_bytes()),
                Err(BundleError::LimitExceeded {
                    limit: "MAX_JSON_STRING_BYTES",
                    ..
                })
            ));
        }
        let array = format!("[{}0]", "0,".repeat(MAX_ENTRIES));
        assert!(matches!(
            validate_json_no_duplicate_keys(array.as_bytes()),
            Err(BundleError::LimitExceeded {
                limit: "MAX_ENTRIES",
                ..
            })
        ));
        let object = br#"{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0}"#;
        assert!(matches!(
            validate_json_no_duplicate_keys(object),
            Err(BundleError::LimitExceeded {
                limit: "MAX_JSON_OBJECT_KEYS",
                ..
            })
        ));
    }

    #[test]
    fn scanner_enforces_the_exact_nesting_cap() {
        let allowed = format!(
            "{}{}",
            "[".repeat(MAX_JSON_NESTING_DEPTH),
            "]".repeat(MAX_JSON_NESTING_DEPTH)
        );
        assert!(validate_json_no_duplicate_keys(allowed.as_bytes()).is_ok());
        let too_deep = format!("[{allowed}]");
        assert!(validate_json_no_duplicate_keys(too_deep.as_bytes()).is_err());
        let objects = format!(
            "{}0{}",
            "{\"k\":".repeat(MAX_JSON_NESTING_DEPTH + 1),
            "}".repeat(MAX_JSON_NESTING_DEPTH + 1)
        );
        assert!(validate_json_no_duplicate_keys(objects.as_bytes()).is_err());
    }

    #[test]
    fn serialization_stops_at_the_byte_cap() {
        assert_eq!(bounded_json_with_cap(&"abc", 5).unwrap(), b"\"abc\"");
        assert!(matches!(
            bounded_json_with_cap(&"abc", 4),
            Err(BundleError::LimitExceeded {
                limit: "MAX_MANIFEST_BYTES",
                max: 4
            })
        ));
    }
}
