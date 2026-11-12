#![forbid(unsafe_code)]

use crate::error::TrustError;
use sha1::{Digest, Sha1};

pub const JKS_MAGIC: u32 = 0xFEEDFEED;
pub const JKS_VERSION_2: u32 = 2;
pub const JKS_DEFAULT_PASSWORD: &str = "changeit";
pub const JKS_APHRODITE: &[u8] = b"Mighty Aphrodite";

/// Status after attempting to process a Java keystore (`cacerts`).
#[derive(Debug, PartialEq, Eq)]
pub enum JksProcessStatus {
    /// JKS was modified and updated with the CA cert.
    Modified,
    /// JKS already contains this exact CA cert under alias hermetic-world-ca (idempotent).
    AlreadyPresent,
    /// The file is PKCS#12, not JKS.
    UnsupportedPkcs12,
    /// The file was skipped with a specific reason.
    Skipped(String),
}

/// A parsed entry from a JKS keystore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JksEntry {
    PrivateKey {
        alias: String,
        date_ms: i64,
        raw_entry_bytes: Vec<u8>,
    },
    TrustedCert {
        alias: String,
        date_ms: i64,
        cert_type: String,
        cert_der: Vec<u8>,
        raw_entry_bytes: Vec<u8>,
    },
}

impl JksEntry {
    pub fn alias(&self) -> &str {
        match self {
            Self::PrivateKey { alias, .. } => alias,
            Self::TrustedCert { alias, .. } => alias,
        }
    }
}

/// Checks if bytes appear to be a PKCS#12 keystore.
pub fn is_pkcs12(data: &[u8]) -> bool {
    // PKCS#12 starts with SEQUENCE (0x30)
    if data.len() < 4 || data[0] != 0x30 {
        return false;
    }
    // Typically version 3: tag 0x02, len 0x01, value 0x03
    // Check if the first inner element is integer 3 or OID
    if data.len() >= 6 {
        // Tag 0x30, length (1 or 2 bytes), then 0x02 0x01 0x03
        if data[2..5] == [0x02, 0x01, 0x03]
            || (data[1] == 0x82 && data.len() >= 7 && data[4..7] == [0x02, 0x01, 0x03])
        {
            return true;
        }
    }
    // Any ASN.1 SEQUENCE in a cacerts file is considered PKCS#12
    true
}

/// Compute the JKS integrity SHA-1 hash over password-as-UTF16BE + "Mighty Aphrodite" + data.
pub fn compute_jks_integrity_hash(password: &str, data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for c in password.encode_utf16() {
        hasher.update(c.to_be_bytes());
    }
    hasher.update(JKS_APHRODITE);
    hasher.update(data);
    hasher.finalize().into()
}

/// Safely read a Java DataInputStream modified UTF string.
fn read_utf(data: &[u8], offset: &mut usize) -> Result<String, TrustError> {
    if *offset + 2 > data.len() {
        return Err(TrustError::Jks("truncated reading UTF length".to_string()));
    }
    let len = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as usize;
    *offset += 2;
    if *offset + len > data.len() {
        return Err(TrustError::Jks("truncated reading UTF content".to_string()));
    }
    let s = String::from_utf8_lossy(&data[*offset..*offset + len]).to_string();
    *offset += len;
    Ok(s)
}

/// Safely write a Java DataInputStream modified UTF string.
fn write_utf(s: &str, out: &mut Vec<u8>) -> Result<(), TrustError> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(TrustError::Jks("string too long for JKS UTF".to_string()));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Parse a JKS keystore, returning its version, entries, and integrity hash.
pub fn parse_jks(data: &[u8]) -> Result<(u32, Vec<JksEntry>, [u8; 20]), TrustError> {
    if data.len() < 28 {
        return Err(TrustError::Jks(
            "keystore shorter than header and digest".to_string(),
        ));
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != JKS_MAGIC {
        return Err(TrustError::Jks(format!("invalid magic {:#X}", magic)));
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != JKS_VERSION_2 {
        return Err(TrustError::Jks(format!("unsupported version {}", version)));
    }

    let entry_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    // Hostile input check: reasonable upper bound on entry count
    if entry_count > 50_000 || entry_count * 16 > data.len() {
        return Err(TrustError::Jks(format!(
            "hostile entry count {}",
            entry_count
        )));
    }

    let mut offset = 12;
    let mut entries = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        let entry_start = offset;
        if offset + 4 > data.len() - 20 {
            return Err(TrustError::Jks("truncated reading entry tag".to_string()));
        }
        let tag = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let alias = read_utf(data, &mut offset)?;
        if offset + 8 > data.len() - 20 {
            return Err(TrustError::Jks("truncated reading entry date".to_string()));
        }
        let date_ms = i64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        match tag {
            1 => {
                // KeyEntry
                if offset + 4 > data.len() - 20 {
                    return Err(TrustError::Jks("truncated reading key length".to_string()));
                }
                let key_len = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;
                offset += 4;
                if offset + key_len > data.len() - 20 {
                    return Err(TrustError::Jks("truncated reading key bytes".to_string()));
                }
                offset += key_len;

                if offset + 4 > data.len() - 20 {
                    return Err(TrustError::Jks(
                        "truncated reading chain length".to_string(),
                    ));
                }
                let chain_len = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;
                offset += 4;
                if chain_len > 1_000 {
                    return Err(TrustError::Jks(
                        "hostile certificate chain length".to_string(),
                    ));
                }

                for _ in 0..chain_len {
                    let _cert_type = read_utf(data, &mut offset)?;
                    if offset + 4 > data.len() - 20 {
                        return Err(TrustError::Jks("truncated reading cert length".to_string()));
                    }
                    let cert_len = u32::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;
                    offset += 4;
                    if offset + cert_len > data.len() - 20 {
                        return Err(TrustError::Jks("truncated reading cert bytes".to_string()));
                    }
                    offset += cert_len;
                }

                let raw_entry_bytes = data[entry_start..offset].to_vec();
                entries.push(JksEntry::PrivateKey {
                    alias,
                    date_ms,
                    raw_entry_bytes,
                });
            }
            2 => {
                // TrustedCertEntry
                let cert_type = read_utf(data, &mut offset)?;
                if offset + 4 > data.len() - 20 {
                    return Err(TrustError::Jks("truncated reading cert length".to_string()));
                }
                let cert_len = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;
                offset += 4;
                if offset + cert_len > data.len() - 20 {
                    return Err(TrustError::Jks("truncated reading cert bytes".to_string()));
                }
                let cert_der = data[offset..offset + cert_len].to_vec();
                offset += cert_len;

                let raw_entry_bytes = data[entry_start..offset].to_vec();
                entries.push(JksEntry::TrustedCert {
                    alias,
                    date_ms,
                    cert_type,
                    cert_der,
                    raw_entry_bytes,
                });
            }
            other => {
                return Err(TrustError::Jks(format!("unknown entry tag {}", other)));
            }
        }
    }

    if offset != data.len() - 20 {
        return Err(TrustError::Jks(format!(
            "trailing data after entries: offset {} != expected {}",
            offset,
            data.len() - 20
        )));
    }

    let mut hash = [0u8; 20];
    hash.copy_from_slice(&data[offset..offset + 20]);
    Ok((version, entries, hash))
}

/// Create a new, valid empty JKS keystore with password.
pub fn create_empty_jks(password: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&JKS_MAGIC.to_be_bytes());
    data.extend_from_slice(&JKS_VERSION_2.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes()); // 0 entries

    let hash = compute_jks_integrity_hash(password, &data);
    data.extend_from_slice(&hash);
    data
}

/// Update a JKS keystore by adding the trusted CA certificate entry with alias `hermetic-world-ca`.
/// If already present and identical, returns Ok(None) (idempotent).
/// If successful, returns Ok(Some(new_bytes)).
pub fn inject_ca_into_jks(
    data: &[u8],
    ca_cert_der: &[u8],
    timestamp_ms: i64,
) -> Result<Option<Vec<u8>>, TrustError> {
    let (_version, entries, existing_hash) = parse_jks(data)?;

    let digest_len = 20usize;
    let data_len_without_digest = data
        .len()
        .checked_sub(digest_len)
        .ok_or_else(|| TrustError::Jks("keystore data shorter than digest".to_string()))?;
    let data_to_hash = data
        .get(..data_len_without_digest)
        .ok_or_else(|| TrustError::Jks("keystore data slice error".to_string()))?;

    // FIX 4: Verify existing integrity digest with "changeit" first
    let expected_hash = compute_jks_integrity_hash(JKS_DEFAULT_PASSWORD, data_to_hash);
    if existing_hash != expected_hash {
        return Err(TrustError::UnknownKeystorePassword);
    }

    // 1. Check for private key alias collision with hermetic-world-ca across all entries
    for entry in &entries {
        if entry.alias().eq_ignore_ascii_case("hermetic-world-ca")
            && matches!(entry, JksEntry::PrivateKey { .. })
        {
            return Err(TrustError::AliasCollisionWithPrivateKey);
        }
    }

    // 2. Validate all entries and reject duplicate aliases
    let mut seen_aliases = std::collections::HashSet::new();
    for entry in &entries {
        let alias_norm = entry.alias().to_lowercase();
        if !seen_aliases.insert(alias_norm) {
            return Err(TrustError::Jks(format!(
                "duplicate alias '{}' in keystore",
                entry.alias()
            )));
        }
    }

    // 3. Check if hermetic-world-ca exact CA cert is already present (idempotent)
    for entry in &entries {
        if let JksEntry::TrustedCert {
            cert_der, alias, ..
        } = entry
        {
            if alias.eq_ignore_ascii_case("hermetic-world-ca") && cert_der.as_slice() == ca_cert_der
            {
                return Ok(None); // Exact cert already present: idempotent!
            }
        }
    }

    // Build new JKS data
    let mut new_data = Vec::with_capacity(data.len() + ca_cert_der.len() + 64);
    new_data.extend_from_slice(&JKS_MAGIC.to_be_bytes());
    new_data.extend_from_slice(&JKS_VERSION_2.to_be_bytes());

    // Filter out only existing TrustedCert entry with alias "hermetic-world-ca"
    let filtered_entries: Vec<&JksEntry> = entries
        .iter()
        .filter(|e| {
            !(e.alias().eq_ignore_ascii_case("hermetic-world-ca")
                && matches!(e, JksEntry::TrustedCert { .. }))
        })
        .collect();

    let new_count = (filtered_entries.len() + 1) as u32;
    new_data.extend_from_slice(&new_count.to_be_bytes());

    for entry in filtered_entries {
        match entry {
            JksEntry::PrivateKey {
                raw_entry_bytes, ..
            } => {
                new_data.extend_from_slice(raw_entry_bytes);
            }
            JksEntry::TrustedCert {
                raw_entry_bytes, ..
            } => {
                new_data.extend_from_slice(raw_entry_bytes);
            }
        }
    }

    // Append trusted-certificate entry:
    // tag = 2 (u32)
    new_data.extend_from_slice(&2u32.to_be_bytes());
    // alias = "hermetic-world-ca"
    write_utf("hermetic-world-ca", &mut new_data)?;
    // date_ms
    new_data.extend_from_slice(&timestamp_ms.to_be_bytes());
    // cert_type = "X.509"
    write_utf("X.509", &mut new_data)?;
    // cert_len (u32)
    new_data.extend_from_slice(&(ca_cert_der.len() as u32).to_be_bytes());
    // cert_der
    new_data.extend_from_slice(ca_cert_der);

    // Compute integrity hash with default password "changeit"
    let new_hash = compute_jks_integrity_hash(JKS_DEFAULT_PASSWORD, &new_data);
    new_data.extend_from_slice(&new_hash);

    Ok(Some(new_data))
}
