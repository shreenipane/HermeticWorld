#![forbid(unsafe_code)]

//! Sigstore keyless signing and offline verification for run records.
//!
//! Implements Sigstore Bundle (Fulcio certificate, Rekor entry, DSSE envelope)
//! generation and offline verification against a pinned trust root containing
//! trusted Fulcio CA certificates and Rekor public keys.
//!
//! # Verification Guarantees
//! 1. Bounded JSON, DER, and signature parsing (strict named limits, fail closed).
//! 2. Verification of DSSE envelope over in-toto run statement using the Fulcio leaf key.
//! 3. Fulcio leaf certificate validation chaining to a pinned Fulcio root CA.
//! 4. Certificate validity window check against Rekor integratedTime.
//! 5. Optional SAN (Subject Alternative Name) and OIDC Issuer extension policy checks.
//! 6. Rekor transparency log entry verification:
//!    - Rekor log ID matches a pinned Rekor public key.
//!    - Signed Entry Timestamp (SET) verified with the Rekor public key.
//!    - Rekor entry body matches the SHA-256 digest of the DSSE payload.
//! 7. In-toto Statement recomputed run digest verification against `RunRecord`.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;

use crate::base64::{base64_decode, base64_encode, Base64Error};
use crate::canonical::{
    bounded_json_bytes, compute_run_digest, json_error, to_canonical_json_bytes, CanonicalJsonError,
};
use crate::digest::Digest;
use crate::dsse::{
    dsse_pae, DsseEnvelope, DsseError, Statement, DSSE_PAYLOAD_TYPE_IN_TOTO,
    IN_TOTO_STATEMENT_V1_TYPE, MAX_PAYLOAD_BYTES, MAX_SIGNATURES, MAX_SIGNATURE_BYTES,
    PREDICATE_TYPE_RUN_V1,
};
use crate::hex::{hex_decode, hex_encode};
use crate::run::RunRecord;

/// Maximum size in bytes of a Sigstore Bundle JSON document (1 MiB).
pub const MAX_SIGSTORE_BUNDLE_BYTES: usize = 1024 * 1024;
/// Maximum size in bytes of a DER-encoded X.509 certificate (64 KiB).
pub const MAX_CERT_DER_BYTES: usize = 64 * 1024;
/// Maximum size in bytes of a Rekor canonicalized body (64 KiB).
pub const MAX_REKOR_BODY_BYTES: usize = 64 * 1024;
/// Maximum size in bytes of a Rekor SET signature (1 KiB).
pub const MAX_SET_BYTES: usize = 1024;
/// Maximum number of transparency log entries in a bundle.
pub const MAX_TLOG_ENTRIES: usize = 16;
/// Maximum number of X.509 extensions parsed in a certificate.
pub const MAX_EXTENSIONS: usize = 32;
/// Maximum number of Subject Alternative Names parsed in a certificate.
pub const MAX_SAN_ENTRIES: usize = 32;
/// Maximum number of trailing items parsed in TBSCertificate.
pub const MAX_TBS_TRAILING_ITEMS: usize = 16;
/// Maximum size in bytes of a trust root document (1 MiB).
pub const MAX_TRUST_ROOT_BYTES: usize = 1024 * 1024;
/// Maximum number of Fulcio root certificates in a trust root.
pub const MAX_FULCIO_ROOTS: usize = 16;
/// Maximum number of Rekor public keys in a trust root.
pub const MAX_REKOR_KEYS: usize = 16;

/// Standard Sigstore bundle media types.
pub const SIGSTORE_BUNDLE_MEDIA_TYPE_V02: &str =
    "application/vnd.dev.sigstore.bundle+json;version=0.2";
pub const SIGSTORE_BUNDLE_MEDIA_TYPE_V03: &str =
    "application/vnd.dev.sigstore.bundle+json;version=0.3";
pub const SIGSTORE_BUNDLE_MEDIA_TYPE_V03_ALT: &str =
    "application/vnd.dev.sigstore.bundle.v0.3+json";

// Standard OIDs
// Fulcio OIDC Issuer OID: 1.3.6.1.4.1.57264.1.1
pub const OID_FULCIO_ISSUER: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
// Subject Alternative Name: 2.5.29.17
pub const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];
// Basic Constraints: 2.5.29.19
pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
// Key Usage: 2.5.29.15
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
// id-ecPublicKey: 1.2.840.10045.2.1
pub const OID_ID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
// secp256r1 (prime256v1): 1.2.840.10045.3.1.7
pub const OID_SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
// ecdsa-with-SHA256: 1.2.840.10045.4.3.2
pub const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
// Ed25519: 1.3.101.112
pub const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
// rsaEncryption: 1.2.840.113549.1.1.1
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
// sha256WithRSAEncryption: 1.2.840.113549.1.1.11
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

#[derive(Clone, PartialEq, Eq)]
pub enum SigstoreError {
    SizeCapExceeded {
        size: usize,
        limit: usize,
    },
    JsonParse(String),
    Base64(Base64Error),
    UnsupportedMediaType(String),
    MissingVerificationMaterial,
    MissingCertificate,
    MissingTlogEntries,
    TooManyTlogEntries {
        count: usize,
        limit: usize,
    },
    InvalidCertificate(String),
    CertExpired {
        valid_until: u64,
        current: u64,
    },
    CertNotYetValid {
        valid_from: u64,
        current: u64,
    },
    CertUntrustedRoot,
    CertSignatureInvalid,
    SanMismatch {
        expected: String,
        actual: String,
    },
    /// The trust root pins no signer identity (SAN and OIDC issuer); without it any
    /// Fulcio certificate would be accepted, so verification refuses.
    IdentityPolicyMissing,
    IssuerMismatch {
        expected: String,
        actual: String,
    },
    UnknownRekorKey(String),
    RekorSignatureInvalid,
    RekorPayloadMismatch,
    DsseError(DsseError),
    InvalidStatementType(String),
    InvalidPredicateType {
        expected: String,
        actual: String,
    },
    SubjectDigestMismatch {
        expected: String,
        actual: String,
    },
    MissingSubject,
    CanonicalJson(CanonicalJsonError),
    RunValidation(String),
    TrustRootError(String),
}

impl fmt::Display for SigstoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeCapExceeded { size, limit } => {
                write!(f, "Sigstore bundle size {size} exceeds limit {limit}")
            }
            Self::JsonParse(msg) => write!(f, "JSON parse error: {msg}"),
            Self::Base64(e) => write!(f, "Base64 decode error: {e}"),
            Self::UnsupportedMediaType(_) => write!(f, "Unsupported bundle mediaType"),
            Self::MissingVerificationMaterial => {
                write!(f, "Bundle missing verificationMaterial")
            }
            Self::MissingCertificate => {
                write!(f, "Bundle missing Fulcio certificate")
            }
            Self::MissingTlogEntries => {
                write!(f, "Bundle contains no transparency log entries")
            }
            Self::TooManyTlogEntries { count, limit } => {
                write!(f, "Tlog entries count {count} exceeds limit {limit}")
            }
            Self::InvalidCertificate(msg) => write!(f, "Invalid certificate: {msg}"),
            Self::CertExpired { .. } => write!(f, "Certificate was expired at Rekor entry time"),
            Self::CertNotYetValid { .. } => {
                write!(f, "Certificate was not yet valid at Rekor entry time")
            }
            Self::CertUntrustedRoot => {
                write!(f, "Certificate does not chain to pinned Fulcio root")
            }
            Self::CertSignatureInvalid => write!(f, "Certificate signature verification failed"),
            Self::SanMismatch { .. } => write!(f, "Certificate SAN identity mismatch"),
            Self::IdentityPolicyMissing => write!(
                f,
                "Trust root does not pin expected_san and expected_issuer"
            ),
            Self::IssuerMismatch { .. } => write!(f, "Certificate OIDC issuer mismatch"),
            Self::UnknownRekorKey(_) => write!(f, "Rekor log ID not found in trusted keys"),
            Self::RekorSignatureInvalid => write!(f, "Rekor SET signature verification failed"),
            Self::RekorPayloadMismatch => {
                write!(f, "Rekor entry body does not bind to DSSE payload")
            }
            Self::DsseError(e) => write!(f, "DSSE verification error: {e}"),
            Self::InvalidStatementType(_) => write!(f, "Invalid in-toto statement _type"),
            Self::InvalidPredicateType { .. } => write!(f, "Predicate type mismatch"),
            Self::SubjectDigestMismatch { .. } => write!(f, "Subject digest mismatch"),
            Self::MissingSubject => write!(f, "Statement subject list is empty"),
            Self::CanonicalJson(e) => write!(f, "Canonical JSON error: {e}"),
            Self::RunValidation(msg) => write!(f, "Run validation error: {msg}"),
            Self::TrustRootError(msg) => write!(f, "Trust root error: {msg}"),
        }
    }
}

impl std::error::Error for SigstoreError {}
redacted_debug!(SigstoreError);

// ============================================================================
// ASN.1 DER Parser for X.509
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate<'a> {
    pub raw_der: &'a [u8],
    pub tbs_der: &'a [u8],
    pub sig_alg_oid: &'a [u8],
    pub sig_bytes: &'a [u8],
    pub issuer_der: &'a [u8],
    pub subject_der: &'a [u8],
    pub not_before: u64,
    pub not_after: u64,
    pub spki_der: &'a [u8],
    pub spki_algorithm_oid: &'a [u8],
    pub public_key_bytes: &'a [u8],
    pub san_entries: Vec<String>,
    pub oidc_issuer: Option<String>,
}

fn der_read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), SigstoreError> {
    if input.is_empty() {
        return Err(SigstoreError::InvalidCertificate(
            "empty DER input".to_string(),
        ));
    }
    let tag = input[0];
    if input.len() < 2 {
        return Err(SigstoreError::InvalidCertificate(
            "truncated DER length".to_string(),
        ));
    }
    let (len, header_len) = if input[1] < 0x80 {
        (input[1] as usize, 2)
    } else {
        let num_octets = (input[1] & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(SigstoreError::InvalidCertificate(
                "unsupported DER length octets".to_string(),
            ));
        }
        if input.len() < 2 + num_octets {
            return Err(SigstoreError::InvalidCertificate(
                "truncated DER length octets".to_string(),
            ));
        }
        let mut l: usize = 0;
        for &b in &input[2..2 + num_octets] {
            l = l
                .checked_mul(256)
                .and_then(|val| val.checked_add(b as usize))
                .ok_or_else(|| {
                    SigstoreError::InvalidCertificate("DER length overflow".to_string())
                })?;
        }
        // Canonical DER: shortest form
        if num_octets == 1 && l < 0x80 {
            return Err(SigstoreError::InvalidCertificate(
                "non-canonical DER length".to_string(),
            ));
        }
        (l, 2 + num_octets)
    };

    let total = header_len.checked_add(len).ok_or_else(|| {
        SigstoreError::InvalidCertificate("DER total length overflow".to_string())
    })?;
    if input.len() < total {
        return Err(SigstoreError::InvalidCertificate(
            "truncated DER payload".to_string(),
        ));
    }
    Ok((tag, &input[header_len..total], &input[total..]))
}

fn der_expect_tag(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), SigstoreError> {
    let (tag, value, rem) = der_read_tlv(input)?;
    if tag != expected_tag {
        return Err(SigstoreError::InvalidCertificate(format!(
            "unexpected DER tag 0x{tag:02x}, expected 0x{expected_tag:02x}"
        )));
    }
    Ok((value, rem))
}

fn der_expect_sequence(input: &[u8]) -> Result<(&[u8], &[u8]), SigstoreError> {
    der_expect_tag(input, 0x30)
}

fn days_from_civil(mut y: i64, m: u64, d: u64) -> i64 {
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

fn parse_der_time(bytes: &[u8], is_utc: bool) -> Result<u64, SigstoreError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| SigstoreError::InvalidCertificate("non-UTF8 time string".to_string()))?;
    // ASCII only: the fixed-offset slicing below would panic on a multibyte char.
    if !s.is_ascii() || !s.ends_with('Z') {
        return Err(SigstoreError::InvalidCertificate(
            "time must be ASCII and end with 'Z'".to_string(),
        ));
    }
    let body = &s[..s.len() - 1];
    let (year, rem) = if is_utc {
        if body.len() != 12 {
            return Err(SigstoreError::InvalidCertificate(
                "invalid UTCTime length".to_string(),
            ));
        }
        let yy: i64 = body[0..2]
            .parse()
            .map_err(|_| SigstoreError::InvalidCertificate("invalid UTCTime year".to_string()))?;
        let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (full_year, &body[2..])
    } else {
        if body.len() != 14 {
            return Err(SigstoreError::InvalidCertificate(
                "invalid GeneralizedTime length".to_string(),
            ));
        }
        let yyyy: i64 = body[0..4].parse().map_err(|_| {
            SigstoreError::InvalidCertificate("invalid GeneralizedTime year".to_string())
        })?;
        (yyyy, &body[4..])
    };

    let month: u64 = rem[0..2]
        .parse()
        .map_err(|_| SigstoreError::InvalidCertificate("invalid month".to_string()))?;
    let day: u64 = rem[2..4]
        .parse()
        .map_err(|_| SigstoreError::InvalidCertificate("invalid day".to_string()))?;
    let hour: u64 = rem[4..6]
        .parse()
        .map_err(|_| SigstoreError::InvalidCertificate("invalid hour".to_string()))?;
    let min: u64 = rem[6..8]
        .parse()
        .map_err(|_| SigstoreError::InvalidCertificate("invalid minute".to_string()))?;
    let sec: u64 = rem[8..10]
        .parse()
        .map_err(|_| SigstoreError::InvalidCertificate("invalid second".to_string()))?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return Err(SigstoreError::InvalidCertificate(
            "date component out of bounds".to_string(),
        ));
    }

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(SigstoreError::InvalidCertificate(
            "date predates 1970-01-01 UTC".to_string(),
        ));
    }
    let secs = (days as u64)
        .checked_mul(86400)
        .and_then(|v| v.checked_add(hour * 3600))
        .and_then(|v| v.checked_add(min * 60))
        .and_then(|v| v.checked_add(sec))
        .ok_or_else(|| SigstoreError::InvalidCertificate("time seconds overflow".to_string()))?;
    Ok(secs)
}

impl<'a> ParsedCertificate<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Self, SigstoreError> {
        if der.len() > MAX_CERT_DER_BYTES {
            return Err(SigstoreError::SizeCapExceeded {
                size: der.len(),
                limit: MAX_CERT_DER_BYTES,
            });
        }
        let (cert_seq, rem) = der_expect_sequence(der)?;
        if !rem.is_empty() {
            return Err(SigstoreError::InvalidCertificate(
                "trailing bytes after certificate SEQUENCE".to_string(),
            ));
        }

        // 1. TBSCertificate
        let (tag, tbs_inner, after_tbs) = der_read_tlv(cert_seq)?;
        if tag != 0x30 {
            return Err(SigstoreError::InvalidCertificate(
                "TBSCertificate must be a SEQUENCE".to_string(),
            ));
        }
        // Calculate tbs_der slice (including tag and length)
        let tbs_len = cert_seq.len() - after_tbs.len();
        let tbs_der = &cert_seq[..tbs_len];

        // 2. SignatureAlgorithm
        let (sig_alg_seq, after_sig_alg) = der_expect_sequence(after_tbs)?;
        let (sig_alg_oid, _) = der_expect_tag(sig_alg_seq, 0x06)?;

        // 3. SignatureValue (BIT STRING 0x03)
        let (sig_bits, rem_cert) = der_expect_tag(after_sig_alg, 0x03)?;
        if !rem_cert.is_empty() {
            return Err(SigstoreError::InvalidCertificate(
                "trailing bytes after signatureValue".to_string(),
            ));
        }
        if sig_bits.is_empty() {
            return Err(SigstoreError::InvalidCertificate(
                "empty signatureValue".to_string(),
            ));
        }
        if sig_bits[0] != 0 {
            return Err(SigstoreError::InvalidCertificate(
                "signatureValue bit string has unused bits".to_string(),
            ));
        }
        let sig_bytes = &sig_bits[1..];

        // Now parse inside tbs_inner
        let mut cur = tbs_inner;

        // Optional [0] EXPLICIT version
        if let Ok((tag, _, after_ver)) = der_read_tlv(cur) {
            if tag == 0xA0 {
                cur = after_ver;
            }
        }

        // SerialNumber (INTEGER 0x02)
        let (_, cur_rem) = der_expect_tag(cur, 0x02)?;
        cur = cur_rem;

        // Signature (AlgorithmIdentifier 0x30)
        let (_, cur_rem) = der_expect_sequence(cur)?;
        cur = cur_rem;

        // Issuer (Name 0x30)
        let (tag, issuer_val, cur_rem) = der_read_tlv(cur)?;
        if tag != 0x30 {
            return Err(SigstoreError::InvalidCertificate(
                "Issuer must be a SEQUENCE".to_string(),
            ));
        }
        let issuer_len = cur.len() - cur_rem.len();
        let issuer_der = &cur[..issuer_len];
        let _ = issuer_val;
        cur = cur_rem;

        // Validity (SEQUENCE 0x30)
        let (validity_seq, cur_rem) = der_expect_sequence(cur)?;
        cur = cur_rem;
        let (tag1, nb_val, val_rem) = der_read_tlv(validity_seq)?;
        let not_before = match tag1 {
            0x17 => parse_der_time(nb_val, true)?,
            0x18 => parse_der_time(nb_val, false)?,
            _ => {
                return Err(SigstoreError::InvalidCertificate(
                    "notBefore invalid time tag".to_string(),
                ))
            }
        };
        let (tag2, na_val, val_rem2) = der_read_tlv(val_rem)?;
        if !val_rem2.is_empty() {
            return Err(SigstoreError::InvalidCertificate(
                "trailing bytes in Validity sequence".to_string(),
            ));
        }
        let not_after = match tag2 {
            0x17 => parse_der_time(na_val, true)?,
            0x18 => parse_der_time(na_val, false)?,
            _ => {
                return Err(SigstoreError::InvalidCertificate(
                    "notAfter invalid time tag".to_string(),
                ))
            }
        };

        // Subject (Name 0x30)
        let (tag, subject_val, cur_rem) = der_read_tlv(cur)?;
        if tag != 0x30 {
            return Err(SigstoreError::InvalidCertificate(
                "Subject must be a SEQUENCE".to_string(),
            ));
        }
        let subject_len = cur.len() - cur_rem.len();
        let subject_der = &cur[..subject_len];
        let _ = subject_val;
        cur = cur_rem;

        // SubjectPublicKeyInfo (SEQUENCE 0x30)
        let (spki_seq, cur_rem) = der_expect_sequence(cur)?;
        let spki_len = cur.len() - cur_rem.len();
        let spki_der = &cur[..spki_len];
        cur = cur_rem;

        // Inside SPKI
        let (spki_alg_seq, spki_after_alg) = der_expect_sequence(spki_seq)?;
        let (spki_algorithm_oid, _) = der_expect_tag(spki_alg_seq, 0x06)?;
        let (pub_bits, spki_rem) = der_expect_tag(spki_after_alg, 0x03)?;
        if !spki_rem.is_empty() {
            return Err(SigstoreError::InvalidCertificate(
                "trailing bytes in SPKI".to_string(),
            ));
        }
        if pub_bits.is_empty() || pub_bits[0] != 0 {
            return Err(SigstoreError::InvalidCertificate(
                "invalid public key bit string".to_string(),
            ));
        }
        let public_key_bytes = &pub_bits[1..];

        // Extensions (optional [3] EXPLICIT SEQUENCE OF Extension)
        let mut san_entries = Vec::new();
        let mut oidc_issuer = None;

        let mut tbs_item_count = 0;
        while !cur.is_empty() {
            tbs_item_count += 1;
            if tbs_item_count > MAX_TBS_TRAILING_ITEMS {
                return Err(SigstoreError::SizeCapExceeded {
                    size: tbs_item_count,
                    limit: MAX_TBS_TRAILING_ITEMS,
                });
            }
            let (tag, ext_wrap, next_cur) = der_read_tlv(cur)?;
            cur = next_cur;
            if tag == 0xA3 {
                // Extensions sequence
                let (mut exts_seq, _) = der_expect_sequence(ext_wrap)?;
                let mut ext_count = 0;
                while !exts_seq.is_empty() {
                    ext_count += 1;
                    if ext_count > MAX_EXTENSIONS {
                        return Err(SigstoreError::SizeCapExceeded {
                            size: ext_count,
                            limit: MAX_EXTENSIONS,
                        });
                    }
                    let (single_ext, next_exts) = der_expect_sequence(exts_seq)?;
                    exts_seq = next_exts;
                    let (ext_oid, ext_rem) = der_expect_tag(single_ext, 0x06)?;
                    let mut ext_body = ext_rem;
                    // Optional critical BOOLEAN
                    if let Ok((0x01, _, rem_after_crit)) = der_read_tlv(ext_body) {
                        ext_body = rem_after_crit;
                    }
                    // extnValue OCTET STRING (0x04)
                    let (extn_value, _) = der_expect_tag(ext_body, 0x04)?;

                    if ext_oid == OID_SAN {
                        // GeneralNames SEQUENCE OF GeneralName
                        if let Ok((mut san_seq, _)) = der_expect_sequence(extn_value) {
                            let mut san_count = 0;
                            while !san_seq.is_empty() {
                                san_count += 1;
                                if san_count > MAX_SAN_ENTRIES {
                                    return Err(SigstoreError::SizeCapExceeded {
                                        size: san_count,
                                        limit: MAX_SAN_ENTRIES,
                                    });
                                }
                                let (name_tag, name_val, next_san) = der_read_tlv(san_seq)?;
                                san_seq = next_san;
                                // [1] rfc822Name (0x81) or [6] URI (0x86)
                                if name_tag == 0x81 || name_tag == 0x86 {
                                    if let Ok(name_str) = std::str::from_utf8(name_val) {
                                        san_entries.push(name_str.to_string());
                                    }
                                }
                            }
                        }
                    } else if ext_oid == OID_FULCIO_ISSUER {
                        // UTF8String (0x0C)
                        if let Ok((0x0C, issuer_val, _)) = der_read_tlv(extn_value) {
                            if let Ok(iss_str) = std::str::from_utf8(issuer_val) {
                                oidc_issuer = Some(iss_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            raw_der: der,
            tbs_der,
            sig_alg_oid,
            sig_bytes,
            issuer_der,
            subject_der,
            not_before,
            not_after,
            spki_der,
            spki_algorithm_oid,
            public_key_bytes,
            san_entries,
            oidc_issuer,
        })
    }
}

// ============================================================================
// Sigstore Bundle and Trust Root Data Structures
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCert {
    #[serde(rename = "rawBytes")]
    pub raw_bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509CertChain {
    pub certificates: Vec<RawCert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationMaterial {
    #[serde(
        default,
        rename = "x509CertificateChain",
        skip_serializing_if = "Option::is_none"
    )]
    pub x509_certificate_chain: Option<X509CertChain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<RawCert>,
    #[serde(default, rename = "tlogEntries")]
    pub tlog_entries: Vec<TlogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogId {
    #[serde(rename = "keyId")]
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionPromise {
    #[serde(rename = "signedEntryTimestamp")]
    pub signed_entry_timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    #[serde(default, rename = "logIndex")]
    pub log_index: serde_json::Value,
    #[serde(default, rename = "rootHash")]
    pub root_hash: Option<String>,
    #[serde(default, rename = "treeSize")]
    pub tree_size: Option<serde_json::Value>,
    #[serde(default)]
    pub hashes: Vec<String>,
    #[serde(default)]
    pub checkpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlogEntry {
    #[serde(rename = "logIndex")]
    pub log_index: serde_json::Value,
    #[serde(rename = "logId")]
    pub log_id: LogId,
    #[serde(rename = "integratedTime")]
    pub integrated_time: serde_json::Value,
    #[serde(
        default,
        rename = "inclusionPromise",
        skip_serializing_if = "Option::is_none"
    )]
    pub inclusion_promise: Option<InclusionPromise>,
    #[serde(
        default,
        rename = "inclusionProof",
        skip_serializing_if = "Option::is_none"
    )]
    pub inclusion_proof: Option<InclusionProof>,
    #[serde(rename = "canonicalizedBody")]
    pub canonicalized_body: String,
}

impl TlogEntry {
    pub fn parse_integrated_time(&self) -> Result<u64, SigstoreError> {
        match &self.integrated_time {
            serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| {
                SigstoreError::JsonParse("invalid integratedTime number".to_string())
            }),
            serde_json::Value::String(s) => {
                if let Ok(val) = s.parse::<u64>() {
                    Ok(val)
                } else if s.ends_with('Z') {
                    parse_der_time(s.as_bytes(), false)
                        .or_else(|_| parse_der_time(s.as_bytes(), true))
                } else {
                    Err(SigstoreError::JsonParse(
                        "cannot parse integratedTime string".to_string(),
                    ))
                }
            }
            _ => Err(SigstoreError::JsonParse(
                "integratedTime must be number or string".to_string(),
            )),
        }
    }
}

/// Sigstore Bundle representing in-toto statement signed keyless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreBundle {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "verificationMaterial")]
    pub verification_material: VerificationMaterial,
    #[serde(rename = "dsseEnvelope")]
    pub dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RekorKeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RekorKey {
    pub key_id: String,
    pub algorithm: RekorKeyAlgorithm,
    pub public_key: String,
}

/// Pinned trust root for offline Sigstore verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreTrustRoot {
    pub fulcio_roots: Vec<String>,
    pub rekor_keys: Vec<RekorKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_san: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_issuer: Option<String>,
}

impl SigstoreTrustRoot {
    pub fn from_json_str(json_str: &str) -> Result<Self, SigstoreError> {
        if json_str.len() > MAX_TRUST_ROOT_BYTES {
            return Err(SigstoreError::SizeCapExceeded {
                size: json_str.len(),
                limit: MAX_TRUST_ROOT_BYTES,
            });
        }
        let root: Self =
            serde_json::from_str(json_str).map_err(|e| SigstoreError::JsonParse(json_error(e)))?;
        if root.fulcio_roots.is_empty() {
            return Err(SigstoreError::TrustRootError(
                "no Fulcio roots in trust root".to_string(),
            ));
        }
        if root.fulcio_roots.len() > MAX_FULCIO_ROOTS {
            return Err(SigstoreError::SizeCapExceeded {
                size: root.fulcio_roots.len(),
                limit: MAX_FULCIO_ROOTS,
            });
        }
        if root.rekor_keys.is_empty() {
            return Err(SigstoreError::TrustRootError(
                "no Rekor keys in trust root".to_string(),
            ));
        }
        if root.rekor_keys.len() > MAX_REKOR_KEYS {
            return Err(SigstoreError::SizeCapExceeded {
                size: root.rekor_keys.len(),
                limit: MAX_REKOR_KEYS,
            });
        }
        Ok(root)
    }
}

// ============================================================================
// Verification Implementation
// ============================================================================

/// Verify signature over payload using a parsed public key.
fn verify_signature(
    alg_oid: &[u8],
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SigstoreError> {
    if alg_oid == OID_ECDSA_SHA256 || alg_oid == OID_ID_EC_PUBLIC_KEY {
        let peer_pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            public_key_bytes,
        );
        if peer_pk.verify(message, signature).is_ok() {
            return Ok(());
        }
        let peer_pk_fixed = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            public_key_bytes,
        );
        peer_pk_fixed.verify(message, signature).map_err(|_| {
            SigstoreError::DsseError(DsseError::SignatureVerification(
                crate::dsse::SignatureError::VerificationFailed(
                    "ECDSA signature failed".to_string(),
                ),
            ))
        })
    } else if alg_oid == OID_ED25519 {
        let peer_pk =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);
        peer_pk.verify(message, signature).map_err(|_| {
            SigstoreError::DsseError(DsseError::SignatureVerification(
                crate::dsse::SignatureError::VerificationFailed(
                    "Ed25519 signature failed".to_string(),
                ),
            ))
        })
    } else if alg_oid == OID_SHA256_WITH_RSA || alg_oid == OID_RSA_ENCRYPTION {
        let peer_pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        peer_pk.verify(message, signature).map_err(|_| {
            SigstoreError::DsseError(DsseError::SignatureVerification(
                crate::dsse::SignatureError::VerificationFailed("RSA signature failed".to_string()),
            ))
        })
    } else {
        Err(SigstoreError::InvalidCertificate(
            "unsupported public key algorithm OID".to_string(),
        ))
    }
}

/// Verify Rekor SET signature against a trusted RekorKey.
fn verify_rekor_set(
    rekor_key: &RekorKey,
    canonicalized_body: &[u8],
    set_sig: &[u8],
) -> Result<(), SigstoreError> {
    let pk_bytes = base64_decode(&rekor_key.public_key, 4096)
        .or_else(|_| hex_decode(&rekor_key.public_key))
        .map_err(|_| {
            SigstoreError::TrustRootError("invalid Rekor public key encoding".to_string())
        })?;

    let body_sha256 = Sha256::digest(canonicalized_body);

    match rekor_key.algorithm {
        RekorKeyAlgorithm::Ed25519 => {
            let peer =
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes);
            if peer.verify(canonicalized_body, set_sig).is_ok()
                || peer.verify(&body_sha256, set_sig).is_ok()
            {
                return Ok(());
            }
            Err(SigstoreError::RekorSignatureInvalid)
        }
        RekorKeyAlgorithm::EcdsaP256 => {
            let peer_asn1 = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                &pk_bytes,
            );
            if peer_asn1.verify(canonicalized_body, set_sig).is_ok()
                || peer_asn1.verify(&body_sha256, set_sig).is_ok()
            {
                return Ok(());
            }
            let peer_fixed = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                &pk_bytes,
            );
            if peer_fixed.verify(canonicalized_body, set_sig).is_ok()
                || peer_fixed.verify(&body_sha256, set_sig).is_ok()
            {
                return Ok(());
            }
            Err(SigstoreError::RekorSignatureInvalid)
        }
        RekorKeyAlgorithm::Rsa2048 => {
            let peer = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                &pk_bytes,
            );
            if peer.verify(canonicalized_body, set_sig).is_ok()
                || peer.verify(&body_sha256, set_sig).is_ok()
            {
                return Ok(());
            }
            Err(SigstoreError::RekorSignatureInvalid)
        }
    }
}

/// Verify a Sigstore Bundle containing a `hermetic-run/v1` statement.
pub fn verify_sigstore_bundle(
    bundle_json: &str,
    trust_root: &SigstoreTrustRoot,
    expected_run_digest: Option<&Digest>,
) -> Result<Statement<RunRecord>, SigstoreError> {
    if bundle_json.len() > MAX_SIGSTORE_BUNDLE_BYTES {
        return Err(SigstoreError::SizeCapExceeded {
            size: bundle_json.len(),
            limit: MAX_SIGSTORE_BUNDLE_BYTES,
        });
    }

    let bundle: SigstoreBundle =
        serde_json::from_str(bundle_json).map_err(|e| SigstoreError::JsonParse(json_error(e)))?;

    // 1. Validate MediaType
    if bundle.media_type != SIGSTORE_BUNDLE_MEDIA_TYPE_V02
        && bundle.media_type != SIGSTORE_BUNDLE_MEDIA_TYPE_V03
        && bundle.media_type != SIGSTORE_BUNDLE_MEDIA_TYPE_V03_ALT
    {
        return Err(SigstoreError::UnsupportedMediaType(bundle.media_type));
    }

    // 2. Extract Fulcio leaf certificate DER
    let leaf_raw = if let Some(ref cert) = bundle.verification_material.certificate {
        &cert.raw_bytes
    } else if let Some(ref chain) = bundle.verification_material.x509_certificate_chain {
        if chain.certificates.is_empty() {
            return Err(SigstoreError::MissingCertificate);
        }
        &chain.certificates[0].raw_bytes
    } else {
        return Err(SigstoreError::MissingCertificate);
    };

    let leaf_der = base64_decode(leaf_raw, MAX_CERT_DER_BYTES).map_err(SigstoreError::Base64)?;
    let leaf_cert = ParsedCertificate::parse(&leaf_der)?;

    // 3. Extract and validate Rekor entries
    if bundle.verification_material.tlog_entries.is_empty() {
        return Err(SigstoreError::MissingTlogEntries);
    }
    if bundle.verification_material.tlog_entries.len() > MAX_TLOG_ENTRIES {
        return Err(SigstoreError::TooManyTlogEntries {
            count: bundle.verification_material.tlog_entries.len(),
            limit: MAX_TLOG_ENTRIES,
        });
    }

    let entry = &bundle.verification_material.tlog_entries[0];
    let integrated_time = entry.parse_integrated_time()?;

    // 4. Verify certificate validity window at integratedTime
    if integrated_time < leaf_cert.not_before {
        return Err(SigstoreError::CertNotYetValid {
            valid_from: leaf_cert.not_before,
            current: integrated_time,
        });
    }
    if integrated_time > leaf_cert.not_after {
        return Err(SigstoreError::CertExpired {
            valid_until: leaf_cert.not_after,
            current: integrated_time,
        });
    }

    // 5. Verify certificate chains to a pinned Fulcio root
    let mut verified_chain = false;
    for root_b64 in &trust_root.fulcio_roots {
        let root_der = base64_decode(root_b64, MAX_CERT_DER_BYTES)
            .map_err(|e| SigstoreError::TrustRootError(e.to_string()))?;
        let root_cert = ParsedCertificate::parse(&root_der)?;
        if leaf_cert.issuer_der == root_cert.subject_der {
            // Verify signature on leaf cert with root cert public key
            if verify_signature(
                root_cert.spki_algorithm_oid,
                root_cert.public_key_bytes,
                leaf_cert.tbs_der,
                leaf_cert.sig_bytes,
            )
            .is_ok()
            {
                verified_chain = true;
                break;
            }
        }
    }
    if !verified_chain {
        return Err(SigstoreError::CertUntrustedRoot);
    }

    // 6. Policy checks: SAN and OIDC Issuer, both required. A Fulcio chain alone
    // only proves that some account signed, not that the expected signer did.
    if trust_root.expected_san.is_none() || trust_root.expected_issuer.is_none() {
        return Err(SigstoreError::IdentityPolicyMissing);
    }
    if let Some(ref want_san) = trust_root.expected_san {
        if !leaf_cert.san_entries.contains(want_san) {
            return Err(SigstoreError::SanMismatch {
                expected: want_san.clone(),
                actual: leaf_cert.san_entries.join(", "),
            });
        }
    }
    if let Some(ref want_issuer) = trust_root.expected_issuer {
        match &leaf_cert.oidc_issuer {
            Some(actual) if actual == want_issuer => {}
            Some(actual) => {
                return Err(SigstoreError::IssuerMismatch {
                    expected: want_issuer.clone(),
                    actual: actual.clone(),
                })
            }
            None => {
                return Err(SigstoreError::IssuerMismatch {
                    expected: want_issuer.clone(),
                    actual: "none".to_string(),
                })
            }
        }
    }

    // 7. Verify Rekor entry: SET signature and entry body
    let trusted_rekor_key = trust_root
        .rekor_keys
        .iter()
        .find(|k| {
            k.key_id == entry.log_id.key_id
                || k.key_id == hex_encode(&Sha256::digest(entry.log_id.key_id.as_bytes()))
        })
        .ok_or_else(|| SigstoreError::UnknownRekorKey(entry.log_id.key_id.clone()))?;

    let canonical_body_bytes = base64_decode(&entry.canonicalized_body, MAX_REKOR_BODY_BYTES)
        .map_err(SigstoreError::Base64)?;

    // The SET is the only Rekor evidence checked offline (inclusion proofs are not
    // verified), so a bundle without one is refused rather than accepted unlogged.
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(SigstoreError::RekorSignatureInvalid)?;
    let set_sig = base64_decode(&promise.signed_entry_timestamp, MAX_SET_BYTES)
        .map_err(SigstoreError::Base64)?;
    verify_rekor_set(trusted_rekor_key, &canonical_body_bytes, &set_sig)?;

    // 8. Verify DSSE envelope
    if bundle.dsse_envelope.payload_type != DSSE_PAYLOAD_TYPE_IN_TOTO {
        return Err(SigstoreError::DsseError(DsseError::UnknownPayloadType(
            bundle.dsse_envelope.payload_type.clone(),
        )));
    }
    if bundle.dsse_envelope.signatures.is_empty() {
        return Err(SigstoreError::DsseError(DsseError::NoSignatures));
    }
    if bundle.dsse_envelope.signatures.len() > MAX_SIGNATURES {
        return Err(SigstoreError::DsseError(DsseError::TooManySignatures {
            count: bundle.dsse_envelope.signatures.len(),
            limit: MAX_SIGNATURES,
        }));
    }

    let payload_bytes = base64_decode(&bundle.dsse_envelope.payload, MAX_PAYLOAD_BYTES)
        .map_err(|e| SigstoreError::DsseError(DsseError::Base64(e)))?;
    let pae = dsse_pae(&bundle.dsse_envelope.payload_type, &payload_bytes);

    // Verify DSSE signature with Fulcio leaf cert public key
    let sig_entry = &bundle.dsse_envelope.signatures[0];
    let sig_bytes = base64_decode(&sig_entry.sig, MAX_SIGNATURE_BYTES)
        .map_err(|e| SigstoreError::DsseError(DsseError::Base64(e)))?;

    verify_signature(
        leaf_cert.spki_algorithm_oid,
        leaf_cert.public_key_bytes,
        &pae,
        &sig_bytes,
    )?;

    // 9. Verify Rekor canonicalized body binds to DSSE payload
    let payload_sha256_hex = hex_encode(&Sha256::digest(&payload_bytes));
    let envelope_sha256_hex = hex_encode(&Sha256::digest(
        serde_json::to_vec(&bundle.dsse_envelope)
            .map_err(|e| SigstoreError::JsonParse(json_error(e)))?,
    ));
    let body_str = std::str::from_utf8(&canonical_body_bytes)
        .map_err(|_| SigstoreError::RekorPayloadMismatch)?;
    if !body_str.contains(&payload_sha256_hex) && !body_str.contains(&envelope_sha256_hex) {
        return Err(SigstoreError::RekorPayloadMismatch);
    }

    // 10. Decode Statement<RunRecord> and verify subject digest
    let statement: Statement<RunRecord> = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SigstoreError::JsonParse(json_error(e)))?;

    if statement.statement_type != IN_TOTO_STATEMENT_V1_TYPE {
        return Err(SigstoreError::InvalidStatementType(
            statement.statement_type,
        ));
    }
    if statement.predicate_type != PREDICATE_TYPE_RUN_V1 {
        return Err(SigstoreError::InvalidPredicateType {
            expected: PREDICATE_TYPE_RUN_V1.to_string(),
            actual: statement.predicate_type,
        });
    }
    statement
        .predicate
        .validate()
        .map_err(|e| SigstoreError::RunValidation(e.to_string()))?;

    let recomputed_run_digest =
        compute_run_digest(&statement.predicate).map_err(SigstoreError::CanonicalJson)?;

    if statement.subject.is_empty() {
        return Err(SigstoreError::MissingSubject);
    }
    if !statement.subject[0].matches_digest(&recomputed_run_digest) {
        return Err(SigstoreError::SubjectDigestMismatch {
            expected: recomputed_run_digest.to_string(),
            actual: statement.subject[0]
                .digest
                .get(recomputed_run_digest.algorithm())
                .cloned()
                .unwrap_or_default(),
        });
    }

    if let Some(expected) = expected_run_digest {
        if &recomputed_run_digest != expected {
            return Err(SigstoreError::SubjectDigestMismatch {
                expected: expected.to_string(),
                actual: recomputed_run_digest.to_string(),
            });
        }
    }

    Ok(statement)
}

// ============================================================================
// Sigstore Offline Signer
// ============================================================================

/// Closure type for signing Rekor SET entry payloads.
pub type RekorSignerFn = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, crate::dsse::SignatureError>>;

/// Offline Sigstore Signer that packages an ephemeral DSSE signature,
/// Fulcio certificate, and Rekor entry into a valid Sigstore bundle.
pub struct SigstoreSigner {
    pub leaf_cert_der: Vec<u8>,
    pub dsse_signer: Box<dyn crate::dsse::Signer>,
    pub rekor_key_id: String,
    pub integrated_time: u64,
    pub rekor_signer: RekorSignerFn,
}

impl SigstoreSigner {
    /// Sign an in-toto run statement and produce a `SigstoreBundle`.
    pub fn sign_statement(
        &self,
        statement: &Statement<RunRecord>,
    ) -> Result<SigstoreBundle, SigstoreError> {
        let envelope = DsseEnvelope::sign_statement(statement, self.dsse_signer.as_ref())
            .map_err(SigstoreError::DsseError)?;

        let payload_bytes = base64_decode(&envelope.payload, MAX_PAYLOAD_BYTES)
            .map_err(|e| SigstoreError::DsseError(DsseError::Base64(e)))?;
        let payload_sha256_hex = hex_encode(&Sha256::digest(&payload_bytes));

        // Build canonicalized body for Rekor intoto entry
        let rekor_body = serde_json::json!({
            "apiVersion": "0.0.2",
            "kind": "intoto",
            "spec": {
                "content": {
                    "envelope": {
                        "payloadType": DSSE_PAYLOAD_TYPE_IN_TOTO,
                        "payloadHash": {
                            "algorithm": "sha256",
                            "value": payload_sha256_hex,
                        }
                    },
                    "hash": {
                        "algorithm": "sha256",
                        "value": payload_sha256_hex,
                    }
                }
            }
        });
        let canonical_body_bytes =
            to_canonical_json_bytes(&rekor_body).map_err(SigstoreError::CanonicalJson)?;

        let set_sig_bytes = (self.rekor_signer)(&canonical_body_bytes)
            .map_err(|_| SigstoreError::RekorSignatureInvalid)?;

        let entry = TlogEntry {
            log_index: serde_json::Value::from(1),
            log_id: LogId {
                key_id: self.rekor_key_id.clone(),
            },
            integrated_time: serde_json::Value::from(self.integrated_time),
            inclusion_promise: Some(InclusionPromise {
                signed_entry_timestamp: base64_encode(&set_sig_bytes),
            }),
            inclusion_proof: None,
            canonicalized_body: base64_encode(&canonical_body_bytes),
        };

        let bundle = SigstoreBundle {
            media_type: SIGSTORE_BUNDLE_MEDIA_TYPE_V03.to_string(),
            verification_material: VerificationMaterial {
                x509_certificate_chain: None,
                certificate: Some(RawCert {
                    raw_bytes: base64_encode(&self.leaf_cert_der),
                }),
                tlog_entries: vec![entry],
            },
            dsse_envelope: envelope,
        };

        bounded_json_bytes(&bundle, MAX_SIGSTORE_BUNDLE_BYTES)
            .map_err(SigstoreError::CanonicalJson)?;
        Ok(bundle)
    }
}
