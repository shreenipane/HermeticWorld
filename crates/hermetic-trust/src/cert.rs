#![forbid(unsafe_code)]

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use std::path::Path;
use time::OffsetDateTime;

use crate::asn1::*;
use crate::error::TrustError;

/// Salt for CA key derivation via HKDF-SHA256
pub const CA_HKDF_SALT: &[u8] = b"hermetic-world-ca-v1";

/// Represents a minted CA certificate and private key.
#[derive(Clone)]
pub struct Ca {
    pub world_id: String,
    pub seed: [u8; 32],
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub key_pem: String,
    pub key: RsaPrivateKey,
    pub subject_dn_der: Vec<u8>,
    pub ski: [u8; 20],
}

/// Represents a minted leaf certificate and private key.
#[derive(Clone, Debug)]
pub struct LeafCert {
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub key_pem: String,
    pub key_der: Vec<u8>,
}

/// Derive deterministic 32-byte seed from host secret and world ID using HKDF-SHA256.
pub fn derive_ca_seed(ca_seed_secret: &[u8; 32], world_id: &str) -> Result<[u8; 32], TrustError> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(CA_HKDF_SALT), ca_seed_secret);
    let mut seed = [0u8; 32];
    hk.expand(world_id.as_bytes(), &mut seed)
        .map_err(|e| TrustError::Hkdf(e.to_string()))?;
    Ok(seed)
}

/// Generate deterministic RSA-2048 private key from a 32-byte seed.
pub fn generate_rsa_key_from_seed(seed: [u8; 32]) -> Result<RsaPrivateKey, TrustError> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = RsaPrivateKey::new(&mut rng, 2048)?;
    Ok(key)
}

/// Compute CA validity window: T_clock - 10 years to T_clock + 10 years (whole seconds, UTC).
pub fn compute_ca_validity(
    t_clock: OffsetDateTime,
) -> Result<(OffsetDateTime, OffsetDateTime), TrustError> {
    let t_utc = t_clock.to_offset(time::UtcOffset::UTC);
    let t_utc = t_utc
        .replace_nanosecond(0)
        .map_err(|e| TrustError::Time(e.to_string()))?;

    let start_year = t_utc.year() - 10;
    let end_year = t_utc.year() + 10;
    let month = t_utc.month();
    let day = t_utc.day();

    let start_day =
        if month == time::Month::February && day == 29 && !time::util::is_leap_year(start_year) {
            28
        } else {
            day
        };
    let end_day =
        if month == time::Month::February && day == 29 && !time::util::is_leap_year(end_year) {
            28
        } else {
            day
        };

    let not_before = time::Date::from_calendar_date(start_year, month, start_day)
        .map_err(|e| TrustError::Time(e.to_string()))?
        .with_time(t_utc.time())
        .assume_utc();

    let not_after = time::Date::from_calendar_date(end_year, month, end_day)
        .map_err(|e| TrustError::Time(e.to_string()))?
        .with_time(t_utc.time())
        .assume_utc();

    Ok((not_before, not_after))
}

/// Compute leaf validity window: T_clock - 7 days to T_clock + 365 days (whole seconds, UTC).
pub fn compute_leaf_validity(
    t_clock: OffsetDateTime,
) -> Result<(OffsetDateTime, OffsetDateTime), TrustError> {
    let t_utc = t_clock.to_offset(time::UtcOffset::UTC);
    let t_utc = t_utc
        .replace_nanosecond(0)
        .map_err(|e| TrustError::Time(e.to_string()))?;

    let not_before = t_utc - time::Duration::days(7);
    let not_after = t_utc + time::Duration::days(365);
    Ok((not_before, not_after))
}

/// Compute serial number: first 16 bytes of SHA-256(info) with top bit cleared.
pub fn compute_serial_number(info: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(info);
    let digest = hasher.finalize();

    let mut serial = [0u8; 16];
    serial.copy_from_slice(&digest[..16]);
    serial[0] &= 0x7F;
    if serial.iter().all(|&b| b == 0) {
        serial[15] = 1;
    }
    serial
}

/// Encode Distinguished Name (RDNSequence).
pub fn encode_dn(cn: &str, o: Option<&str>) -> Vec<u8> {
    let mut rdns = Vec::new();

    // CommonName (CN)
    let cn_attr = encode_sequence(&[&encode_oid(OID_COMMON_NAME), &encode_utf8_string(cn)]);
    rdns.push(encode_set(&[&cn_attr]));

    // OrganizationName (O)
    if let Some(org) = o {
        let o_attr =
            encode_sequence(&[&encode_oid(OID_ORGANIZATION_NAME), &encode_utf8_string(org)]);
        rdns.push(encode_set(&[&o_attr]));
    }

    let rdn_refs: Vec<&[u8]> = rdns.iter().map(|v| v.as_slice()).collect();
    encode_sequence(&rdn_refs)
}

/// Mint per-world CA certificate and private key.
pub fn mint_ca(
    world_id: &str,
    t_clock: OffsetDateTime,
    ca_seed_secret: &[u8; 32],
) -> Result<Ca, TrustError> {
    // 1. Derive seed
    let ca_seed = derive_ca_seed(ca_seed_secret, world_id)?;

    // 2. Deterministic RSA-2048 key
    let private_key = generate_rsa_key_from_seed(ca_seed)?;
    let public_key = private_key.to_public_key();

    // 3. Subject and Issuer: CN=Hermetic World CA <first 16 hex of BLAKE3(world_id)>, O=Hermetic World
    let blake3_hash = blake3::hash(world_id.as_bytes());
    let blake3_hex = hex::encode(blake3_hash.as_bytes());
    let cn = format!("Hermetic World CA {}", &blake3_hex[..16]);
    let dn_der = encode_dn(&cn, Some("Hermetic World"));

    // 4. Serial: first 16 bytes of SHA-256("serial:" + world_id) with top bit cleared
    let mut serial_input = Vec::new();
    serial_input.extend_from_slice(b"serial:");
    serial_input.extend_from_slice(world_id.as_bytes());
    let serial = compute_serial_number(&serial_input);

    // 5. Validity: T_clock - 10 years to T_clock + 10 years
    let (not_before, not_after) = compute_ca_validity(t_clock)?;

    // 6. SubjectPublicKeyInfo & SubjectKeyIdentifier
    let pkcs1_der = public_key.to_pkcs1_der()?;
    let spk_bit_string = encode_bit_string(0, pkcs1_der.as_bytes());
    let spki_der = encode_sequence(&[&encode_rsa_algorithm(), &spk_bit_string]);

    let mut sha1_hasher = sha1::Sha1::new();
    sha1_hasher.update(pkcs1_der.as_bytes());
    let ski: [u8; 20] = sha1_hasher.finalize().into();

    // 7. Extensions:
    // basicConstraints CA:true critical
    let bc_value = encode_sequence(&[&encode_boolean(true)]);
    let bc_extn = encode_sequence(&[
        &encode_oid(OID_BASIC_CONSTRAINTS),
        &encode_boolean(true), // critical
        &encode_octet_string(&bc_value),
    ]);

    // keyUsage keyCertSign + cRLSign critical
    // Bit 5 (keyCertSign) and Bit 6 (cRLSign) -> 0x06, 1 unused bit
    let ku_bits = encode_bit_string(1, &[0x06]);
    let ku_extn = encode_sequence(&[
        &encode_oid(OID_KEY_USAGE),
        &encode_boolean(true), // critical
        &encode_octet_string(&ku_bits),
    ]);

    // subjectKeyIdentifier (non-critical)
    let ski_inner = encode_octet_string(&ski);
    let ski_extn = encode_sequence(&[
        &encode_oid(OID_SUBJECT_KEY_IDENTIFIER),
        &encode_octet_string(&ski_inner),
    ]);

    let extensions_seq = encode_sequence(&[&bc_extn, &ku_extn, &ski_extn]);
    let extensions_der = encode_explicit(3, &extensions_seq);

    // 8. TBSCertificate
    let version_der = encode_explicit(0, &encode_integer(&[2])); // v3 = 2
    let serial_der = encode_integer(&serial);
    let sig_alg_der = encode_sha256_with_rsa_algorithm();
    let validity_der =
        encode_sequence(&[&encode_der_time(not_before), &encode_der_time(not_after)]);

    let tbs_der = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &dn_der,
        &validity_der,
        &dn_der, // Self-signed: subject == issuer
        &spki_der,
        &extensions_der,
    ]);

    // 9. Sign with RSA PKCS#1 v1.5 SHA-256
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign(&tbs_der);
    let signature_bit_string = encode_bit_string(0, &signature.to_vec());

    // 10. Complete Certificate DER
    let cert_der = encode_sequence(&[&tbs_der, &sig_alg_der, &signature_bit_string]);

    // 11. Format PEM
    let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone()));
    let key_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;

    Ok(Ca {
        world_id: world_id.to_string(),
        seed: ca_seed,
        cert_pem,
        cert_der,
        key_pem: key_pem.to_string(),
        key: private_key,
        subject_dn_der: dn_der,
        ski,
    })
}

/// Mint leaf certificate for the given DNS hostnames signed by the CA.
pub fn mint_leaf(
    ca: &Ca,
    hostnames: &[impl AsRef<str>],
    t_clock: OffsetDateTime,
) -> Result<LeafCert, TrustError> {
    if hostnames.is_empty() {
        return Err(TrustError::Cert(
            "Cannot mint leaf with empty hostnames list".to_string(),
        ));
    }

    // Sort hostnames deterministically
    let mut sorted: Vec<String> = hostnames.iter().map(|h| h.as_ref().to_string()).collect();
    sorted.sort();

    // 1. Derive leaf RSA key from HKDF(ca seed, info = "leaf:" + sorted hostnames)
    let mut info = Vec::new();
    info.extend_from_slice(b"leaf:");
    info.extend_from_slice(sorted.join(",").as_bytes());

    let hk = hkdf::Hkdf::<Sha256>::new(None, &ca.seed);
    let mut leaf_seed = [0u8; 32];
    hk.expand(&info, &mut leaf_seed)
        .map_err(|e| TrustError::Hkdf(e.to_string()))?;

    let leaf_key = generate_rsa_key_from_seed(leaf_seed)?;
    let leaf_pub = leaf_key.to_public_key();

    // 2. Leaf Subject DN
    let leaf_cn = &sorted[0];
    let leaf_subject_dn = encode_dn(leaf_cn, Some("Hermetic World"));

    // 3. Leaf Serial
    let mut serial_input = Vec::new();
    serial_input.extend_from_slice(b"serial:leaf:");
    serial_input.extend_from_slice(ca.world_id.as_bytes());
    serial_input.extend_from_slice(b":");
    serial_input.extend_from_slice(sorted.join(",").as_bytes());
    let serial = compute_serial_number(&serial_input);

    // 4. Validity: T_clock - 7 days to T_clock + 365 days
    let (not_before, not_after) = compute_leaf_validity(t_clock)?;

    // 5. SubjectPublicKeyInfo & SubjectKeyIdentifier
    let pkcs1_der = leaf_pub.to_pkcs1_der()?;
    let spk_bit_string = encode_bit_string(0, pkcs1_der.as_bytes());
    let spki_der = encode_sequence(&[&encode_rsa_algorithm(), &spk_bit_string]);

    let mut sha1_hasher = sha1::Sha1::new();
    sha1_hasher.update(pkcs1_der.as_bytes());
    let leaf_ski: [u8; 20] = sha1_hasher.finalize().into();

    // 6. Extensions:
    // basicConstraints CA:false (non-critical): DER requires omitting DEFAULT false, so empty SEQUENCE (30 00)
    let bc_value = encode_sequence(&[]);
    let bc_extn = encode_sequence(&[
        &encode_oid(OID_BASIC_CONSTRAINTS),
        &encode_octet_string(&bc_value),
    ]);

    // keyUsage digitalSignature + keyEncipherment critical
    // Bit 0 (0x80) + Bit 2 (0x20) -> 0xA0, 5 unused bits
    let ku_bits = encode_bit_string(5, &[0xA0]);
    let ku_extn = encode_sequence(&[
        &encode_oid(OID_KEY_USAGE),
        &encode_boolean(true),
        &encode_octet_string(&ku_bits),
    ]);

    // subjectKeyIdentifier
    let ski_inner = encode_octet_string(&leaf_ski);
    let ski_extn = encode_sequence(&[
        &encode_oid(OID_SUBJECT_KEY_IDENTIFIER),
        &encode_octet_string(&ski_inner),
    ]);

    // authorityKeyIdentifier: [0] IMPLICIT KeyIdentifier (CA's SKI)
    let aki_key_id = encode_implicit_primitive(0, &ca.ski);
    let aki_seq = encode_sequence(&[&aki_key_id]);
    let aki_extn = encode_sequence(&[
        &encode_oid(OID_AUTHORITY_KEY_IDENTIFIER),
        &encode_octet_string(&aki_seq),
    ]);

    // subjectAltName: SEQUENCE OF GeneralName (dNSName [2] IA5String)
    let mut san_entries = Vec::new();
    for name in &sorted {
        san_entries.push(encode_implicit_primitive(2, name.as_bytes()));
    }
    let san_refs: Vec<&[u8]> = san_entries.iter().map(|v| v.as_slice()).collect();
    let san_seq = encode_sequence(&san_refs);
    let san_extn = encode_sequence(&[
        &encode_oid(OID_SUBJECT_ALT_NAME),
        &encode_octet_string(&san_seq),
    ]);

    let extensions_seq = encode_sequence(&[&bc_extn, &ku_extn, &ski_extn, &aki_extn, &san_extn]);
    let extensions_der = encode_explicit(3, &extensions_seq);

    // 7. TBSCertificate
    let version_der = encode_explicit(0, &encode_integer(&[2]));
    let serial_der = encode_integer(&serial);
    let sig_alg_der = encode_sha256_with_rsa_algorithm();
    let validity_der =
        encode_sequence(&[&encode_der_time(not_before), &encode_der_time(not_after)]);

    let tbs_der = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der, // Leaf issuer == CA subject
        &validity_der,
        &leaf_subject_dn,
        &spki_der,
        &extensions_der,
    ]);

    // 8. Sign with CA private key
    let ca_signer = SigningKey::<Sha256>::new(ca.key.clone());
    let signature = ca_signer.sign(&tbs_der);
    let signature_bit_string = encode_bit_string(0, &signature.to_vec());

    // 9. Complete Certificate DER & PEM
    let cert_der = encode_sequence(&[&tbs_der, &sig_alg_der, &signature_bit_string]);
    let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone()));
    let key_pem = leaf_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
    let key_der = leaf_key.to_pkcs8_der()?;

    Ok(LeafCert {
        cert_pem,
        cert_der,
        key_pem: key_pem.to_string(),
        key_der: key_der.as_bytes().to_vec(),
    })
}

#[cfg(unix)]
fn get_current_uid() -> Result<u32, TrustError> {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(euid) = parts[1].parse::<u32>() {
                        return Ok(euid);
                    }
                }
            }
        }
    }
    use std::os::unix::fs::MetadataExt;
    let temp = tempfile::NamedTempFile::new()
        .map_err(|e| TrustError::Cert(format!("cannot determine current process uid: {}", e)))?;
    let meta = temp
        .path()
        .metadata()
        .map_err(|e| TrustError::Cert(format!("cannot determine current process uid: {}", e)))?;
    Ok(meta.uid())
}

/// Read and validate seed file: regular file owned by current user, mode & 0o077 == 0, exactly 32 bytes.
pub fn read_seed_file(path: &Path) -> Result<[u8; 32], TrustError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(TrustError::Cert(format!(
                "seed file '{}' is not a regular file",
                path.display()
            )));
        }
        let mode = metadata.permissions().mode();
        if (mode & 0o077) != 0 {
            return Err(TrustError::InsecureSeedFilePermissions(mode));
        }
        let current_uid = get_current_uid()?;
        if metadata.uid() != current_uid {
            return Err(TrustError::Cert(format!(
                "seed file '{}' is not owned by current user (file uid: {}, current uid: {})",
                path.display(),
                metadata.uid(),
                current_uid
            )));
        }
    }

    let bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        return Err(TrustError::InvalidSeedFileLength(bytes.len()));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Write private key to key_out with mode 0600 atomically via a temp file.
pub fn write_private_key_file(path: &Path, pem_contents: &str) -> Result<(), TrustError> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
    }

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let tmp_name = format!(
            ".tmp-key-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            attempt
        );
        let tmp_path = parent.join(tmp_name);

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&tmp_path) {
            Ok(mut file) => {
                let write_res = (|| -> Result<(), TrustError> {
                    file.write_all(pem_contents.as_bytes())?;
                    file.sync_all()?;
                    drop(file);
                    std::fs::rename(&tmp_path, path)?;
                    Ok(())
                })();
                if write_res.is_err() {
                    let _ = std::fs::remove_file(&tmp_path);
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
