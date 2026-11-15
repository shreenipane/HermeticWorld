#![forbid(unsafe_code)]

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use crate::asn1::*;
use crate::error::TrustError;

/// Salt for CA key derivation via HKDF-SHA256
pub const CA_HKDF_SALT: &[u8] = b"hermetic-world-ca-v1";

/// Maximum number of DNS hostnames allowed on a single leaf certificate.
pub const MAX_LEAF_HOSTNAMES: usize = 100;

/// Maximum length in bytes for a single DNS hostname.
pub const MAX_HOSTNAME_BYTES: usize = 253;

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
    pub spki_der: Vec<u8>,
}

/// Represents a minted leaf certificate and private key.
#[derive(Clone)]
pub struct LeafCert {
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub key_pem: String,
    pub key_der: Vec<u8>,
}

// Secret material is wiped when it is dropped (the RSA key wipes itself).
impl Drop for Ca {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
        self.key_pem.zeroize();
    }
}

impl Drop for LeafCert {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_pem.zeroize();
        self.key_der.zeroize();
    }
}

impl std::fmt::Debug for LeafCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafCert")
            .field("cert_pem", &self.cert_pem)
            .field("cert_der", &self.cert_der)
            .field("key_pem", &"[REDACTED]")
            .field("key_der", &"[REDACTED]")
            .finish()
    }
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
    let t_utc = t_clock
        .checked_to_offset(time::UtcOffset::UTC)
        .ok_or_else(|| TrustError::Time("overflow converting date to UTC".to_string()))?;
    let t_utc = t_utc
        .replace_nanosecond(0)
        .map_err(|e| TrustError::Time(e.to_string()))?;

    let start_year = t_utc
        .year()
        .checked_sub(10)
        .ok_or_else(|| TrustError::Time("underflow computing start_year".to_string()))?;
    let end_year = t_utc
        .year()
        .checked_add(10)
        .ok_or_else(|| TrustError::Time("overflow computing end_year".to_string()))?;

    if start_year < 0 || end_year > 9999 {
        return Err(TrustError::Time(
            "validity window out of X.509 supported range 0000..=9999".to_string(),
        ));
    }

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
    let t_utc = t_clock
        .checked_to_offset(time::UtcOffset::UTC)
        .ok_or_else(|| TrustError::Time("overflow converting date to UTC".to_string()))?;
    let t_utc = t_utc
        .replace_nanosecond(0)
        .map_err(|e| TrustError::Time(e.to_string()))?;

    let not_before = t_utc
        .checked_sub(time::Duration::days(7))
        .ok_or_else(|| TrustError::Time("underflow computing not_before".to_string()))?;
    let not_after = t_utc
        .checked_add(time::Duration::days(365))
        .ok_or_else(|| TrustError::Time("overflow computing not_after".to_string()))?;

    if not_before.year() < 0
        || not_before.year() > 9999
        || not_after.year() < 0
        || not_after.year() > 9999
    {
        return Err(TrustError::Time(
            "validity window out of X.509 supported range 0000..=9999".to_string(),
        ));
    }

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
    // 1. Validity check before generating keys
    compute_ca_validity(t_clock)?;

    // 2. Derive seed
    let ca_seed = derive_ca_seed(ca_seed_secret, world_id)?;

    // 3. Deterministic RSA-2048 key
    let private_key = generate_rsa_key_from_seed(ca_seed)?;
    ca_from_key(world_id, t_clock, ca_seed, private_key)
}

/// Restore only per-world CA material delivered to the isolated NetVM. The
/// caller binds the regenerated certificate to the sealed public CA digest.
pub fn restore_ca(
    world_id: &str,
    t_clock: OffsetDateTime,
    ca_seed: [u8; 32],
    key_pem: &str,
) -> Result<Ca, TrustError> {
    if world_id.is_empty() || world_id.len() > 256 || key_pem.len() > 4096 {
        return Err(TrustError::Cert("invalid CA material".into()));
    }
    let private_key = RsaPrivateKey::from_pkcs8_pem(key_pem)
        .map_err(|_| TrustError::Cert("invalid CA material".into()))?;
    if private_key.n().bits() != 2048 || private_key.e() != &rsa::BigUint::from(65537u32) {
        return Err(TrustError::Cert("invalid CA material".into()));
    }
    private_key
        .validate()
        .map_err(|_| TrustError::Cert("invalid CA material".into()))?;
    ca_from_key(world_id, t_clock, ca_seed, private_key)
}

fn ca_from_key(
    world_id: &str,
    t_clock: OffsetDateTime,
    ca_seed: [u8; 32],
    private_key: RsaPrivateKey,
) -> Result<Ca, TrustError> {
    let (not_before, not_after) = compute_ca_validity(t_clock)?;
    let public_key = private_key.to_public_key();

    // 4. Subject and Issuer: CN=Hermetic World CA <first 16 hex of BLAKE3(world_id)>, O=Hermetic World
    let blake3_hash = blake3::hash(world_id.as_bytes());
    let blake3_hex = hex::encode(blake3_hash.as_bytes());
    let cn = format!("Hermetic World CA {}", &blake3_hex[..16]);
    let dn_der = encode_dn(&cn, Some("Hermetic World"));

    // 5. Serial: first 16 bytes of SHA-256("serial:" + world_id) with top bit cleared
    let mut serial_input = Vec::new();
    serial_input.extend_from_slice(b"serial:");
    serial_input.extend_from_slice(world_id.as_bytes());
    let serial = compute_serial_number(&serial_input);

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
        spki_der,
    })
}

/// Mint leaf certificate for the given DNS hostnames signed by the CA.
pub fn mint_leaf(
    ca: &Ca,
    hostnames: &[impl AsRef<str>],
    t_clock: OffsetDateTime,
) -> Result<LeafCert, TrustError> {
    // 1. Validity check before generating keys
    let (not_before, not_after) = compute_leaf_validity(t_clock)?;

    if hostnames.is_empty() {
        return Err(TrustError::Cert(
            "Cannot mint leaf with empty hostnames list".to_string(),
        ));
    }
    if hostnames.len() > MAX_LEAF_HOSTNAMES {
        return Err(TrustError::Cert(format!(
            "hostname count {} exceeds maximum allowed {}",
            hostnames.len(),
            MAX_LEAF_HOSTNAMES
        )));
    }

    for h in hostnames {
        validate_dns_name(h.as_ref())?;
    }

    // Sort hostnames deterministically
    let mut sorted: Vec<String> = hostnames.iter().map(|h| h.as_ref().to_string()).collect();
    sorted.sort();

    // 2. Derive leaf RSA key from HKDF(ca seed, unambiguous framing of sorted hostnames)
    let mut info = Vec::new();
    info.extend_from_slice(b"leaf:");
    info.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for name in &sorted {
        info.extend_from_slice(&(name.len() as u32).to_be_bytes());
        info.extend_from_slice(name.as_bytes());
    }

    let hk = hkdf::Hkdf::<Sha256>::new(None, &ca.seed);
    let mut leaf_seed = [0u8; 32];
    hk.expand(&info, &mut leaf_seed)
        .map_err(|e| TrustError::Hkdf(e.to_string()))?;

    let leaf_key = generate_rsa_key_from_seed(leaf_seed)?;
    let leaf_pub = leaf_key.to_public_key();

    // 3. Leaf Subject DN
    let leaf_cn = &sorted[0];
    let leaf_subject_dn = encode_dn(leaf_cn, Some("Hermetic World"));

    // 4. Leaf Serial: unambiguous framing
    let mut serial_input = Vec::new();
    serial_input.extend_from_slice(b"serial:leaf:");
    serial_input.extend_from_slice(&(ca.world_id.len() as u32).to_be_bytes());
    serial_input.extend_from_slice(ca.world_id.as_bytes());
    serial_input.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for name in &sorted {
        serial_input.extend_from_slice(&(name.len() as u32).to_be_bytes());
        serial_input.extend_from_slice(name.as_bytes());
    }
    let serial = compute_serial_number(&serial_input);

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
pub(crate) fn get_current_uid() -> Result<u32, TrustError> {
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

// Linux x86_64 open(2) flags: O_NOFOLLOW (0o400000) prevents following symlinks,
// O_NONBLOCK (0o4000) prevents blocking on FIFOs. The values differ on other
// targets (aarch64: 0o400000 is O_LARGEFILE), so any other target is rejected.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!(
    "hermetic-trust hard-codes Linux x86_64 open(2) flag values (O_NOFOLLOW, O_NONBLOCK); \
     add correct values for this target before building"
);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NONBLOCK: i32 = 0o4000;

/// Read and validate seed file: regular file owned by current user, mode & 0o077 == 0, exactly 32 bytes.
pub fn read_seed_file(path: &Path) -> Result<[u8; 32], TrustError> {
    use std::io::Read;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    }

    let file = options.open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let metadata = file.metadata()?;
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

    let mut bytes = Vec::new();
    file.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return Err(TrustError::InvalidSeedFileLength(bytes.len()));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Read and validate CA cert file: regular file, not a symlink, bounded by MAX_CA_CERT_INPUT_BYTES.
pub fn read_cert_file_bounded(path: &Path) -> Result<String, TrustError> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    }

    let file = options.open(path).map_err(|e| {
        TrustError::Cert(format!(
            "failed to open ca-cert file '{}': {}",
            path.display(),
            e
        ))
    })?;

    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(TrustError::Cert(format!(
                "ca-cert file '{}' is not a regular file",
                path.display()
            )));
        }
        if metadata.len() > crate::install::MAX_CA_CERT_INPUT_BYTES {
            return Err(TrustError::Cert(format!(
                "ca-cert file '{}' exceeds size cap of {} bytes",
                path.display(),
                crate::install::MAX_CA_CERT_INPUT_BYTES
            )));
        }
    }

    let mut bytes = Vec::new();
    file.take(crate::install::MAX_CA_CERT_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > crate::install::MAX_CA_CERT_INPUT_BYTES {
        return Err(TrustError::Cert(format!(
            "ca-cert file '{}' exceeds size cap of {} bytes",
            path.display(),
            crate::install::MAX_CA_CERT_INPUT_BYTES
        )));
    }

    String::from_utf8(bytes).map_err(|e| {
        TrustError::Cert(format!(
            "ca-cert file '{}' is not valid UTF-8: {}",
            path.display(),
            e
        ))
    })
}

/// Validate a single DNS hostname according to RFC 5280 / RFC 1035 rules and bounds.
pub fn validate_dns_name(s: &str) -> Result<(), TrustError> {
    if s.is_empty() {
        return Err(TrustError::Cert("empty hostname not allowed".to_string()));
    }
    if s.len() > MAX_HOSTNAME_BYTES {
        return Err(TrustError::Cert(format!(
            "hostname '{}' length {} exceeds max {}",
            s,
            s.len(),
            MAX_HOSTNAME_BYTES
        )));
    }
    if !s.is_ascii() {
        return Err(TrustError::Cert(format!(
            "hostname '{}' contains non-ASCII characters",
            s
        )));
    }
    if s.contains('\0') {
        return Err(TrustError::Cert(format!(
            "hostname '{}' contains NUL byte",
            s
        )));
    }
    if s.contains(',') {
        return Err(TrustError::Cert(format!("hostname '{}' contains comma", s)));
    }
    // Validate DNS labels
    for label in s.split('.') {
        if label.is_empty() {
            return Err(TrustError::Cert(format!(
                "hostname '{}' contains empty DNS label",
                s
            )));
        }
        if label.len() > 63 {
            return Err(TrustError::Cert(format!(
                "DNS label '{}' in '{}' exceeds 63 bytes",
                label, s
            )));
        }
        for b in label.bytes() {
            if !b.is_ascii_alphanumeric() && b != b'-' && b != b'_' && b != b'*' {
                return Err(TrustError::Cert(format!(
                    "invalid character '{}' in hostname '{}'",
                    b as char, s
                )));
            }
        }
    }
    Ok(())
}

/// Validate output path to ensure it is not a symlink or non-regular file.
pub fn validate_output_path(path: &Path) -> Result<(), TrustError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(TrustError::Symlink(format!(
                "output path '{}' is a symlink",
                path.display()
            )));
        }
        if !meta.file_type().is_file() {
            return Err(TrustError::Cert(format!(
                "output path '{}' is not a regular file",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Resolve an output path to the absolute physical location the operating system
/// would write it to, without creating anything.
///
/// Relative paths are anchored at the current directory. The longest existing
/// ancestor of the destination's parent is canonicalized (it must be a directory);
/// the components below it do not exist yet and must all be plain names (a `..`
/// after a missing directory cannot be resolved by the kernel either). The final
/// component itself is never followed.
pub(crate) fn physical_destination(path: &Path) -> Result<PathBuf, TrustError> {
    use std::path::Component;

    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let file_name = abs
        .file_name()
        .ok_or_else(|| {
            TrustError::Cert(format!(
                "invalid output path has no file name: '{}'",
                path.display()
            ))
        })?
        .to_os_string();
    let parent = abs.parent().ok_or_else(|| {
        TrustError::Cert(format!(
            "invalid output path has no parent: '{}'",
            path.display()
        ))
    })?;

    let comps: Vec<Component> = parent.components().collect();
    let mut existing = comps.len();
    loop {
        if existing == 0 {
            return Err(TrustError::Cert(format!(
                "output path '{}' has no existing ancestor",
                path.display()
            )));
        }
        let prefix: PathBuf = comps[..existing].iter().collect();
        match std::fs::metadata(&prefix) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(TrustError::Cert(format!(
                        "ancestor '{}' of output path '{}' is not a directory",
                        prefix.display(),
                        path.display()
                    )));
                }
                let mut out = prefix.canonicalize()?;
                for comp in &comps[existing..] {
                    match comp {
                        Component::Normal(n) => out.push(n),
                        _ => {
                            return Err(TrustError::Cert(format!(
                            "output path '{}' cannot be resolved: '..' follows a missing directory",
                            path.display()
                        )))
                        }
                    }
                }
                out.push(&file_name);
                return Ok(out);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::NotADirectory =>
            {
                existing -= 1;
            }
            Err(e) => return Err(TrustError::Io(e)),
        }
    }
}

/// Check that two output paths do not alias the same filesystem location or inode,
/// and that neither is an ancestor of the other.
///
/// Both destinations are resolved to absolute physical locations against their
/// longest existing ancestor (which must be a directory) before anything is
/// written, so relative and absolute spellings of the same new file, and an
/// existing file used as a parent directory of the other output, are rejected.
pub fn check_not_alias(
    path1: &Path,
    path2: &Path,
    desc1: &str,
    desc2: &str,
) -> Result<(), TrustError> {
    if path1 == path2 {
        return Err(TrustError::Cert(format!(
            "{} and {} point to the same path '{}'",
            desc1,
            desc2,
            path1.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(m1), Ok(m2)) = (
            std::fs::symlink_metadata(path1),
            std::fs::symlink_metadata(path2),
        ) {
            if m1.dev() == m2.dev() && m1.ino() == m2.ino() {
                return Err(TrustError::Cert(format!(
                    "{} and {} alias the same inode (dev {}, ino {})",
                    desc1,
                    desc2,
                    m1.dev(),
                    m1.ino()
                )));
            }
        }
    }

    let dest1 = physical_destination(path1)?;
    let dest2 = physical_destination(path2)?;

    if dest1 == dest2 {
        return Err(TrustError::Cert(format!(
            "{} ('{}') and {} ('{}') alias the same destination '{}'",
            desc1,
            path1.display(),
            desc2,
            path2.display(),
            dest1.display()
        )));
    }
    if dest1.starts_with(&dest2) || dest2.starts_with(&dest1) {
        return Err(TrustError::Cert(format!(
            "{} ('{}') and {} ('{}') conflict: one is an ancestor of the other",
            desc1,
            path1.display(),
            desc2,
            path2.display()
        )));
    }

    Ok(())
}

/// Atomically write content to a file: creates parent dirs, writes to a temp file, flushes, syncs,
/// verifies target is not a symlink, and renames atomically.
pub fn atomic_write_file(path: &Path, content: &[u8], mode: Option<u32>) -> Result<(), TrustError> {
    validate_output_path(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
    }

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let tmp_name = format!(
            ".tmp-out-{}-{}-{}",
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
            options.mode(mode.unwrap_or(0o644));
        }

        match options.open(&tmp_path) {
            Ok(mut file) => {
                let write_res = (|| -> Result<(), TrustError> {
                    use std::io::Write;
                    file.write_all(content)?;
                    file.sync_all()?;
                    drop(file);
                    validate_output_path(path)?;
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

/// Write private key to key_out with mode 0600 atomically via a temp file.
pub fn write_private_key_file(path: &Path, pem_contents: &str) -> Result<(), TrustError> {
    atomic_write_file(path, pem_contents.as_bytes(), Some(0o600))
}
