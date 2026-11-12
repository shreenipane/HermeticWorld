#![forbid(unsafe_code)]

use crate::error::TrustError;

/// Encode Tag-Length-Value in ASN.1 DER format.
pub fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// Encode DER length bytes.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len < 16777216 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Encode ASN.1 SEQUENCE (0x30).
pub fn encode_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut val = Vec::new();
    for item in items {
        val.extend_from_slice(item);
    }
    encode_tlv(0x30, &val)
}

/// Encode ASN.1 SET (0x31).
pub fn encode_set(items: &[&[u8]]) -> Vec<u8> {
    let mut val = Vec::new();
    for item in items {
        val.extend_from_slice(item);
    }
    encode_tlv(0x31, &val)
}

/// Encode ASN.1 INTEGER (0x02) from big-endian bytes.
/// Canonical DER requires minimum octets (strip leading redundant zeros)
/// and a leading 0x00 if the most significant bit is set (positive integer).
pub fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return encode_tlv(0x02, &[0x00]);
    }
    // Strip leading zeros, but keep at least one byte
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let trimmed = &bytes[start..];

    // If top bit is 1, prepend 0x00 so it is interpreted as a positive integer
    if (trimmed[0] & 0x80) != 0 {
        let mut val = Vec::with_capacity(trimmed.len() + 1);
        val.push(0x00);
        val.extend_from_slice(trimmed);
        encode_tlv(0x02, &val)
    } else {
        encode_tlv(0x02, trimmed)
    }
}

/// Encode ASN.1 BIT STRING (0x03).
pub fn encode_bit_string(unused_bits: u8, data: &[u8]) -> Vec<u8> {
    let mut val = Vec::with_capacity(data.len() + 1);
    val.push(unused_bits);
    val.extend_from_slice(data);
    encode_tlv(0x03, &val)
}

/// Encode ASN.1 OCTET STRING (0x04).
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    encode_tlv(0x04, data)
}

/// Encode ASN.1 NULL (0x05).
pub fn encode_null() -> Vec<u8> {
    encode_tlv(0x05, &[])
}

/// Encode ASN.1 OBJECT IDENTIFIER (0x06).
pub fn encode_oid(oid_bytes: &[u8]) -> Vec<u8> {
    encode_tlv(0x06, oid_bytes)
}

/// Encode ASN.1 UTF8String (0x0C).
pub fn encode_utf8_string(s: &str) -> Vec<u8> {
    encode_tlv(0x0C, s.as_bytes())
}

/// Encode ASN.1 PrintableString (0x13).
pub fn encode_printable_string(s: &str) -> Vec<u8> {
    encode_tlv(0x13, s.as_bytes())
}

/// Encode ASN.1 IA5String (0x16).
pub fn encode_ia5_string(s: &str) -> Vec<u8> {
    encode_tlv(0x16, s.as_bytes())
}

/// Encode ASN.1 BOOLEAN (0x01).
pub fn encode_boolean(b: bool) -> Vec<u8> {
    encode_tlv(0x01, &[if b { 0xFF } else { 0x00 }])
}

/// Encode Context-Specific Explicit Tag [tag_num] (0xA0 | tag_num).
pub fn encode_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    encode_tlv(0xA0 | (tag_num & 0x1F), inner)
}

/// Encode Context-Specific Implicit Tag [tag_num] Primitive (0x80 | tag_num).
pub fn encode_implicit_primitive(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    encode_tlv(0x80 | (tag_num & 0x1F), inner)
}

/// Encode X.509 Time: UTCTime (0x17) for 1950..=2049, GeneralizedTime (0x18) otherwise.
pub fn encode_der_time(dt: time::OffsetDateTime) -> Vec<u8> {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    let year = dt.year();
    if (1950..=2049).contains(&year) {
        let yy = (year % 100).unsigned_abs() as u8;
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            yy,
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        encode_tlv(0x17, s.as_bytes())
    } else {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        encode_tlv(0x18, s.as_bytes())
    }
}

// Well-known DER OID byte slices:
// sha256WithRSAEncryption: 1.2.840.113549.1.1.11
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
// rsaEncryption: 1.2.840.113549.1.1.1
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
// CommonName (CN): 2.5.4.3
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
// OrganizationName (O): 2.5.4.10
pub const OID_ORGANIZATION_NAME: &[u8] = &[0x55, 0x04, 0x0A];
// basicConstraints: 2.5.29.19
pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
// keyUsage: 2.5.29.15
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
// subjectKeyIdentifier: 2.5.29.14
pub const OID_SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x0E];
// authorityKeyIdentifier: 2.5.29.35
pub const OID_AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x23];
// subjectAltName: 2.5.29.17
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

/// Encode AlgorithmIdentifier for sha256WithRSAEncryption:
/// SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }
pub fn encode_sha256_with_rsa_algorithm() -> Vec<u8> {
    encode_sequence(&[&encode_oid(OID_SHA256_WITH_RSA), &encode_null()])
}

/// Encode AlgorithmIdentifier for rsaEncryption:
/// SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
pub fn encode_rsa_algorithm() -> Vec<u8> {
    encode_sequence(&[&encode_oid(OID_RSA_ENCRYPTION), &encode_null()])
}

/// Represents a parsed ASN.1 TLV item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

/// Decode a single DER TLV from input. Returns the parsed TLV and remaining bytes.
pub fn parse_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), TrustError> {
    if input.is_empty() {
        return Err(TrustError::Cert("empty ASN.1 DER input".to_string()));
    }
    let tag = input[0];
    if input.len() < 2 {
        return Err(TrustError::Cert("truncated ASN.1 DER length".to_string()));
    }

    let (length, header_len) = if input[1] < 0x80 {
        (input[1] as usize, 2)
    } else {
        let num_octets = (input[1] & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(TrustError::Cert(
                "unsupported ASN.1 DER length encoding".to_string(),
            ));
        }
        if input.len() < 2 + num_octets {
            return Err(TrustError::Cert(
                "truncated ASN.1 DER length octets".to_string(),
            ));
        }
        let mut len: usize = 0;
        for &byte in &input[2..2 + num_octets] {
            len = len
                .checked_mul(256)
                .and_then(|l| l.checked_add(byte as usize))
                .ok_or_else(|| TrustError::Cert("ASN.1 DER length overflow".to_string()))?;
        }
        // Canonical DER rule: shortest length encoding
        if num_octets == 1 && len < 0x80 {
            return Err(TrustError::Cert(
                "non-canonical ASN.1 DER length".to_string(),
            ));
        }
        (len, 2 + num_octets)
    };

    let total_len = header_len
        .checked_add(length)
        .ok_or_else(|| TrustError::Cert("ASN.1 DER total length overflow".to_string()))?;
    if input.len() < total_len {
        return Err(TrustError::Cert("truncated ASN.1 DER payload".to_string()));
    }

    let value = &input[header_len..total_len];
    let raw = &input[..total_len];
    let rem = &input[total_len..];
    Ok((Tlv { tag, value, raw }, rem))
}

/// Parse all consecutive TLVs inside a container (e.g. inside a SEQUENCE).
pub fn parse_sequence_items(mut input: &[u8]) -> Result<Vec<Tlv<'_>>, TrustError> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let (tlv, rem) = parse_tlv(input)?;
        items.push(tlv);
        input = rem;
    }
    Ok(items)
}

/// Validate a complete X.509 CA certificate, including basicConstraints (CA:true)
/// and cryptographic signature before any mutation.
pub fn validate_ca_certificate(der: &[u8]) -> Result<(), TrustError> {
    let (root, rem) = parse_tlv(der)?;
    if !rem.is_empty() {
        return Err(TrustError::Cert(
            "trailing bytes after certificate DER".to_string(),
        ));
    }
    if root.tag != 0x30 {
        return Err(TrustError::Cert(
            "certificate DER is not a SEQUENCE".to_string(),
        ));
    }

    let cert_items = parse_sequence_items(root.value)?;
    if cert_items.len() != 3 {
        return Err(TrustError::Cert(format!(
            "expected 3 items in Certificate SEQUENCE (tbs, sig_alg, sig_val), found {}",
            cert_items.len()
        )));
    }
    let tbs_tlv = &cert_items[0];
    let sig_alg_tlv = &cert_items[1];
    let sig_val_tlv = &cert_items[2];

    if tbs_tlv.tag != 0x30 {
        return Err(TrustError::Cert(
            "tbsCertificate is not a SEQUENCE".to_string(),
        ));
    }
    if sig_alg_tlv.tag != 0x30 {
        return Err(TrustError::Cert(
            "signatureAlgorithm is not a SEQUENCE".to_string(),
        ));
    }
    if sig_val_tlv.tag != 0x03 {
        return Err(TrustError::Cert(
            "signatureValue is not a BIT STRING".to_string(),
        ));
    }

    let tbs_items = parse_sequence_items(tbs_tlv.value)?;
    if tbs_items.len() < 6 {
        return Err(TrustError::Cert(
            "too few items in TBSCertificate".to_string(),
        ));
    }
    let mut idx = 0;
    // Optional version: tag 0xA0 [0]
    if tbs_items[idx].tag == 0xA0 {
        let ver_items = parse_sequence_items(tbs_items[idx].value)?;
        if ver_items.len() != 1 || ver_items[0].tag != 0x02 {
            return Err(TrustError::Cert(
                "invalid version in TBSCertificate".to_string(),
            ));
        }
        idx += 1;
    }
    if idx >= tbs_items.len() || tbs_items[idx].tag != 0x02 {
        return Err(TrustError::Cert(
            "missing or invalid serialNumber in TBSCertificate".to_string(),
        ));
    }
    idx += 1;
    if idx >= tbs_items.len() || tbs_items[idx].tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid signature in TBSCertificate".to_string(),
        ));
    }
    idx += 1;
    if idx >= tbs_items.len() || tbs_items[idx].tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid issuer in TBSCertificate".to_string(),
        ));
    }
    let issuer_tlv = &tbs_items[idx];
    idx += 1;
    if idx >= tbs_items.len() || tbs_items[idx].tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid validity in TBSCertificate".to_string(),
        ));
    }
    idx += 1;
    if idx >= tbs_items.len() || tbs_items[idx].tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid subject in TBSCertificate".to_string(),
        ));
    }
    let subject_tlv = &tbs_items[idx];
    idx += 1;
    if idx >= tbs_items.len() || tbs_items[idx].tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid subjectPublicKeyInfo in TBSCertificate".to_string(),
        ));
    }
    let spki_tlv = &tbs_items[idx];
    idx += 1;

    // Skip optional [1] issuerUniqueID, [2] subjectUniqueID
    while idx < tbs_items.len()
        && (tbs_items[idx].tag == 0x81
            || tbs_items[idx].tag == 0x82
            || tbs_items[idx].tag == 0xA1
            || tbs_items[idx].tag == 0xA2)
    {
        idx += 1;
    }

    // Find extensions ([3] EXPLICIT tag 0xA3)
    let mut found_ca_true = false;
    if idx < tbs_items.len() && tbs_items[idx].tag == 0xA3 {
        let ext_seq_items = parse_sequence_items(tbs_items[idx].value)?;
        if ext_seq_items.len() == 1 && ext_seq_items[0].tag == 0x30 {
            let extensions = parse_sequence_items(ext_seq_items[0].value)?;
            for ext in extensions {
                if ext.tag != 0x30 {
                    continue;
                }
                let ext_parts = parse_sequence_items(ext.value)?;
                if ext_parts.len() < 2 {
                    continue;
                }
                if ext_parts[0].tag == 0x06 && ext_parts[0].value == OID_BASIC_CONSTRAINTS {
                    let last = &ext_parts[ext_parts.len() - 1];
                    if last.tag == 0x04 {
                        if let Ok(bc_items) = parse_sequence_items(last.value) {
                            if bc_items.len() == 1 && bc_items[0].tag == 0x30 {
                                if let Ok(bc_inner) = parse_sequence_items(bc_items[0].value) {
                                    if !bc_inner.is_empty()
                                        && bc_inner[0].tag == 0x01
                                        && bc_inner[0].value.iter().any(|&b| b != 0)
                                    {
                                        found_ca_true = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !found_ca_true {
        return Err(TrustError::Cert(
            "certificate is not a CA: missing or false basicConstraints CA:true".to_string(),
        ));
    }

    // Parse RSA Public Key from SPKI
    let spki_parts = parse_sequence_items(spki_tlv.value)?;
    if spki_parts.len() != 2 {
        return Err(TrustError::Cert("invalid SPKI in certificate".to_string()));
    }
    let alg_tlv = &spki_parts[0];
    let spk_bit_string = &spki_parts[1];
    if alg_tlv.tag != 0x30 || spk_bit_string.tag != 0x03 {
        return Err(TrustError::Cert(
            "invalid SPKI algorithm or public key tag".to_string(),
        ));
    }
    if spk_bit_string.value.is_empty() || spk_bit_string.value[0] != 0 {
        return Err(TrustError::Cert("invalid BIT STRING in SPKI".to_string()));
    }
    let pkcs1_der = &spk_bit_string.value[1..];
    use rsa::pkcs1::DecodeRsaPublicKey;
    let public_key = rsa::RsaPublicKey::from_pkcs1_der(pkcs1_der).map_err(|e| {
        TrustError::Cert(format!("failed to parse RSA public key from SPKI: {}", e))
    })?;

    // Verify self-signed signature if issuer == subject
    if sig_val_tlv.value.is_empty() || sig_val_tlv.value[0] != 0 {
        return Err(TrustError::Cert("invalid signature BIT STRING".to_string()));
    }
    let sig_bytes = &sig_val_tlv.value[1..];

    if issuer_tlv.raw == subject_tlv.raw {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        use sha2::Sha256;

        let signature = Signature::try_from(sig_bytes)
            .map_err(|e| TrustError::Cert(format!("invalid RSA signature length: {}", e)))?;
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        verifying_key.verify(tbs_tlv.raw, &signature).map_err(|e| {
            TrustError::Cert(format!("CA self-signature verification failed: {}", e))
        })?;
    }

    Ok(())
}
