use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::safe_io;

/// Maximum JSON manifest size accepted for DNS table loading (1 MiB).
pub const MAX_TABLE_JSON_BYTES: usize = 1024 * 1024;
/// Maximum number of distinct domain names permitted in a DNS table.
pub const MAX_TABLE_RECORDS: usize = 4096;
/// Maximum number of IPv4 A records per domain name so that even a maximum-length
/// 253-byte domain name fits within a 512-byte UDP response (12 + 259 + 15 * 16 = 511).
pub const MAX_A_RECORDS_PER_NAME: usize = 15;
/// Maximum textual DNS name length in bytes (excluding optional query trailing dot).
pub const MAX_DNS_NAME_LEN: usize = 253;
/// Maximum number of labels in a DNS name.
pub const MAX_DNS_LABELS: usize = 127;
/// Minimum length of a non-root DNS label in bytes.
pub const MIN_DNS_LABEL_LEN: usize = 1;
/// Maximum length of a single DNS label in bytes.
pub const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum attempts to create a unique temporary file in the same directory during atomic write.
const MAX_ATOMIC_TMP_ATTEMPTS: usize = 64;

/// Typed errors returned when loading, validating, or persisting a [`DnsTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    InputTooLarge {
        size: usize,
        max: usize,
    },
    JsonParse(String),
    TooManyRecords {
        count: usize,
        max: usize,
    },
    InvalidName(String),
    DuplicateName(String),
    TooManyAddresses {
        name: String,
        count: usize,
        max: usize,
    },
    InvalidIpv4 {
        name: String,
        address: String,
    },
    AddressOutOfWorldRange {
        name: String,
        address: Ipv4Addr,
    },
    DuplicateAddress {
        name: String,
        address: Ipv4Addr,
    },
    NonEmptyAaaa {
        name: String,
        count: usize,
    },
    SymlinkNotAllowed,
    NotRegularFile,
    InvalidDestinationPath,
    AtomicWriteExhausted,
    Io(String),
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TableError::InputTooLarge { size, max } => {
                write!(f, "table JSON input size {size} exceeds cap {max}")
            }
            TableError::JsonParse(_) => write!(f, "invalid table JSON"),
            TableError::TooManyRecords { count, max } => {
                write!(f, "table record count {count} exceeds cap {max}")
            }
            TableError::InvalidName(_) => write!(f, "invalid DNS name in table"),
            TableError::DuplicateName(_) => write!(f, "duplicate DNS name in table"),
            TableError::TooManyAddresses { count, max, .. } => {
                write!(f, "A address count {count} exceeds cap {max}")
            }
            TableError::InvalidIpv4 { .. } => write!(f, "invalid IPv4 address"),
            TableError::AddressOutOfWorldRange { .. } => {
                write!(f, "IPv4 address outside world range")
            }
            TableError::DuplicateAddress { .. } => write!(f, "duplicate IPv4 address"),
            TableError::NonEmptyAaaa { count, .. } => {
                write!(f, "AAAA list must be empty (count {count})")
            }
            TableError::SymlinkNotAllowed => {
                write!(f, "refusing to open or overwrite a symbolic link")
            }
            TableError::NotRegularFile => {
                write!(
                    f,
                    "expected a regular file (refusing FIFO, device, or directory)"
                )
            }
            TableError::InvalidDestinationPath => {
                write!(f, "invalid destination file path for atomic write")
            }
            TableError::AtomicWriteExhausted => {
                write!(
                    f,
                    "exhausted bounded temporary file attempts during atomic write"
                )
            }
            TableError::Io(kind) => write!(f, "I/O error ({kind})"),
        }
    }
}

impl Error for TableError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    records: Vec<RawRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    name: String,
    a: Vec<String>,
    #[serde(default)]
    aaaa: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SerializedManifest<'a> {
    records: Vec<SerializedRecord<'a>>,
}

#[derive(Debug, Serialize)]
struct SerializedRecord<'a> {
    name: &'a str,
    a: Vec<String>,
    aaaa: [&'static str; 0],
}

struct CappedJsonWriter(Vec<u8>);

impl Write for CappedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_TABLE_JSON_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Table output cap exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deterministic, bounded in-memory DNS manifest table for NetVM.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsTable {
    records: BTreeMap<String, Vec<Ipv4Addr>>,
}

impl DnsTable {
    /// Creates an empty DNS table.
    pub fn empty() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Returns the number of domain names in the table.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Canonical manifest host names in stable byte order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.records.keys().map(String::as_str)
    }

    /// Returns `true` if the table has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Loads and validates a [`DnsTable`] from a JSON byte slice.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, TableError> {
        if bytes.len() > MAX_TABLE_JSON_BYTES {
            return Err(TableError::InputTooLarge {
                size: bytes.len(),
                max: MAX_TABLE_JSON_BYTES,
            });
        }

        let raw: RawManifest = serde_json::from_slice(bytes)
            .map_err(|_| TableError::JsonParse("InvalidJson".into()))?;

        if raw.records.len() > MAX_TABLE_RECORDS {
            return Err(TableError::TooManyRecords {
                count: raw.records.len(),
                max: MAX_TABLE_RECORDS,
            });
        }

        let mut records = BTreeMap::new();

        for rec in raw.records {
            validate_table_name(&rec.name)?;

            if records.contains_key(&rec.name) {
                return Err(TableError::DuplicateName(String::new()));
            }

            if !rec.aaaa.is_empty() {
                return Err(TableError::NonEmptyAaaa {
                    name: String::new(),
                    count: rec.aaaa.len(),
                });
            }

            if rec.a.len() > MAX_A_RECORDS_PER_NAME {
                return Err(TableError::TooManyAddresses {
                    name: String::new(),
                    count: rec.a.len(),
                    max: MAX_A_RECORDS_PER_NAME,
                });
            }

            let mut ipv4s = Vec::with_capacity(rec.a.len());
            for addr_str in rec.a {
                let ip: Ipv4Addr = addr_str.parse().map_err(|_| TableError::InvalidIpv4 {
                    name: String::new(),
                    address: String::new(),
                })?;

                if ip.octets()[0] != 10 {
                    return Err(TableError::AddressOutOfWorldRange {
                        name: String::new(),
                        address: Ipv4Addr::UNSPECIFIED,
                    });
                }

                ipv4s.push(ip);
            }

            ipv4s.sort();
            if ipv4s.windows(2).any(|w| w[0] == w[1]) {
                return Err(TableError::DuplicateAddress {
                    name: String::new(),
                    address: Ipv4Addr::UNSPECIFIED,
                });
            }

            records.insert(rec.name, ipv4s);
        }

        Ok(Self { records })
    }

    /// Test-only fixture constructor allowing arbitrary addresses (such as 127.0.0.1)
    /// to declare test listener addresses without production world-range restrictions.
    pub fn test_fixture<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (S, Vec<Ipv4Addr>)>,
        S: Into<String>,
    {
        let mut records = BTreeMap::new();
        for (name, mut ips) in entries {
            ips.sort();
            records.insert(name.into(), ips);
        }
        Self { records }
    }

    /// Loads and validates a [`DnsTable`] from a JSON string.
    pub fn from_json_str(json: &str) -> Result<Self, TableError> {
        Self::from_json_bytes(json.as_bytes())
    }

    /// Reads at most [`MAX_TABLE_JSON_BYTES`] from `reader` and parses a [`DnsTable`].
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, TableError> {
        let mut buf = Vec::new();
        let limit = (MAX_TABLE_JSON_BYTES + 1) as u64;
        reader
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|e| TableError::Io(format!("{:?}", e.kind())))?;

        if buf.len() > MAX_TABLE_JSON_BYTES {
            return Err(TableError::InputTooLarge {
                size: buf.len(),
                max: MAX_TABLE_JSON_BYTES,
            });
        }

        Self::from_json_bytes(&buf)
    }

    /// Opens a regular file without following symlinks, refusing FIFOs/devices/directories,
    /// and loads a [`DnsTable`] bounded by [`MAX_TABLE_JSON_BYTES`].
    pub fn from_file(path: &Path) -> Result<Self, TableError> {
        Self::from_reader(safe_io::open_regular(path, MAX_TABLE_JSON_BYTES)?)
    }

    /// Serializes the table deterministically as canonical JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, TableError> {
        let records = self
            .records
            .iter()
            .map(|(name, ips)| SerializedRecord {
                name: name.as_str(),
                a: ips.iter().map(Ipv4Addr::to_string).collect(),
                aaaa: [],
            })
            .collect();

        let manifest = SerializedManifest { records };
        let mut writer = CappedJsonWriter(Vec::new());
        serde_json::to_writer_pretty(&mut writer, &manifest).map_err(|_| {
            TableError::InputTooLarge {
                size: MAX_TABLE_JSON_BYTES + 1,
                max: MAX_TABLE_JSON_BYTES,
            }
        })?;
        Ok(writer.0)
    }

    /// Atomically writes the serialized JSON table to `path` using a temporary file in the same
    /// directory, `fsync`, and `rename`, refusing symlinks and non-regular files.
    pub fn write_atomic(&self, path: &Path) -> Result<(), TableError> {
        self.write_atomic_after_parent(path, || {})
    }

    fn write_atomic_after_parent(
        &self,
        path: &Path,
        after_parent: impl FnOnce(),
    ) -> Result<(), TableError> {
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(TableError::InvalidDestinationPath)?;
        if file_name.is_empty() {
            return Err(TableError::InvalidDestinationPath);
        }

        let payload = self.to_json_bytes()?;
        let (directory, leaf) = safe_io::open_parent(path)?;
        after_parent();
        let destination = safe_io::child_path(&directory, &leaf);
        safe_io::inspect_regular(&destination)?;
        for attempt in 0..MAX_ATOMIC_TMP_ATTEMPTS {
            let tmp_name = format!(".{file_name}.tmp.{attempt}");
            let tmp_path = safe_io::child_path(&directory, std::ffi::OsStr::new(&tmp_name));
            match safe_io::create_private(&tmp_path) {
                Ok(mut tmp_file) => {
                    let result = (|| {
                        tmp_file.write_all(&payload).map_err(safe_io::io_error)?;
                        tmp_file.sync_all().map_err(safe_io::io_error)?;
                        fs::rename(&tmp_path, &destination).map_err(safe_io::io_error)?;
                        directory.sync_all().map_err(safe_io::io_error)
                    })();
                    if result.is_err() {
                        let _ = fs::remove_file(&tmp_path);
                    }
                    return result;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(safe_io::io_error(error)),
            }
        }
        Err(TableError::AtomicWriteExhausted)
    }

    /// Looks up a domain name in the table.
    ///
    /// Lookup is ASCII case-insensitive and ignores at most one trailing dot.
    pub fn lookup(&self, qname: &str) -> Option<&[Ipv4Addr]> {
        let trimmed = qname.strip_suffix('.').unwrap_or(qname);
        if trimmed.is_empty() || trimmed.len() > MAX_DNS_NAME_LEN {
            return None;
        }

        let mut normalized_buf = [0u8; MAX_DNS_NAME_LEN];
        for (dst, &src) in normalized_buf.iter_mut().zip(trimmed.as_bytes().iter()) {
            if !src.is_ascii() {
                return None;
            }
            *dst = src.to_ascii_lowercase();
        }

        let slice = normalized_buf.get(..trimmed.len())?;
        let normalized = std::str::from_utf8(slice).ok()?;
        self.records.get(normalized).map(Vec::as_slice)
    }
}

/// Validates a canonical table domain name:
/// - 1..=253 bytes total
/// - Labels separated by `.`, each 1..=63 bytes of `[a-z0-9-]`
/// - No label starts or ends with `-`
/// - No wildcards, no uppercase, no trailing or leading dots
pub fn validate_table_name(name: &str) -> Result<(), TableError> {
    if name.is_empty() || name.len() > MAX_DNS_NAME_LEN {
        return Err(TableError::InvalidName(String::new()));
    }

    let mut label_count: usize = 0;
    for label in name.split('.') {
        label_count += 1;
        if label_count > MAX_DNS_LABELS {
            return Err(TableError::InvalidName(String::new()));
        }

        let len = label.len();
        if !(MIN_DNS_LABEL_LEN..=MAX_DNS_LABEL_LEN).contains(&len) {
            return Err(TableError::InvalidName(String::new()));
        }

        let bytes = label.as_bytes();
        let first = match bytes.first() {
            Some(&b) => b,
            None => return Err(TableError::InvalidName(String::new())),
        };
        let last = match bytes.last() {
            Some(&b) => b,
            None => return Err(TableError::InvalidName(String::new())),
        };

        if first == b'-' || last == b'-' {
            return Err(TableError::InvalidName(String::new()));
        }

        for &b in bytes {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err(TableError::InvalidName(String::new()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn manifest_parent_exchange_does_not_redirect_publication() {
        let root = std::env::temp_dir().join(format!("dns-manifest-swap-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let parent = root.join("parent");
        let moved = root.join("moved");
        let outside = root.join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("output"), b"secret").unwrap();
        DnsTable::empty()
            .write_atomic_after_parent(&parent.join("output"), || {
                fs::rename(&parent, &moved).unwrap();
                symlink(&outside, &parent).unwrap();
            })
            .unwrap();
        assert_eq!(fs::read(outside.join("output")).unwrap(), b"secret");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        assert_eq!(
            DnsTable::from_file(&moved.join("output")).unwrap(),
            DnsTable::empty()
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serialization_never_extends_buffer_past_cap() {
        let mut writer = CappedJsonWriter(Vec::new());
        writer.write_all(&vec![b'x'; MAX_TABLE_JSON_BYTES]).unwrap();
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.0.len(), MAX_TABLE_JSON_BYTES);
    }
}
