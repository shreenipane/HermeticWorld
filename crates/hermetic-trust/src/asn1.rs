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

fn parse_ascii_2digits(bytes: &[u8], offset: usize) -> Result<u8, TrustError> {
    let d0 = bytes
        .get(offset)
        .ok_or_else(|| TrustError::Cert("truncated ASN.1 time digits".to_string()))?;
    let next_off = offset
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("offset overflow".to_string()))?;
    let d1 = bytes
        .get(next_off)
        .ok_or_else(|| TrustError::Cert("truncated ASN.1 time digits".to_string()))?;

    if !d0.is_ascii_digit() || !d1.is_ascii_digit() {
        return Err(TrustError::Cert(
            "non-ASCII digit in ASN.1 time".to_string(),
        ));
    }
    let tens = (d0.wrapping_sub(b'0'))
        .checked_mul(10)
        .ok_or_else(|| TrustError::Cert("arithmetic overflow in ASN.1 time".to_string()))?;
    let units = d1.wrapping_sub(b'0');
    tens.checked_add(units)
        .ok_or_else(|| TrustError::Cert("arithmetic overflow in ASN.1 time".to_string()))
}

fn parse_ascii_4digits(bytes: &[u8], offset: usize) -> Result<i32, TrustError> {
    let hi = parse_ascii_2digits(bytes, offset)? as i32;
    let next_off = offset
        .checked_add(2)
        .ok_or_else(|| TrustError::Cert("offset overflow".to_string()))?;
    let lo = parse_ascii_2digits(bytes, next_off)? as i32;
    let hi_val = hi
        .checked_mul(100)
        .ok_or_else(|| TrustError::Cert("arithmetic overflow in ASN.1 time".to_string()))?;
    hi_val
        .checked_add(lo)
        .ok_or_else(|| TrustError::Cert("arithmetic overflow in ASN.1 time".to_string()))
}

/// Parse an ASN.1 Time (UTCTime tag 0x17 or GeneralizedTime tag 0x18) into OffsetDateTime.
pub fn parse_asn1_time(tlv: &Tlv<'_>) -> Result<time::OffsetDateTime, TrustError> {
    match tlv.tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ (13 chars)
            if tlv.value.len() != 13 {
                return Err(TrustError::Cert(format!(
                    "invalid UTCTime length {}, expected 13 (YYMMDDHHMMSSZ)",
                    tlv.value.len()
                )));
            }
            if tlv.value.get(12) != Some(&b'Z') {
                return Err(TrustError::Cert("UTCTime must end with 'Z'".to_string()));
            }
            let yy = parse_ascii_2digits(tlv.value, 0)? as i32;
            let year = if yy >= 50 {
                1900i32
                    .checked_add(yy)
                    .ok_or_else(|| TrustError::Cert("year overflow".to_string()))?
            } else {
                2000i32
                    .checked_add(yy)
                    .ok_or_else(|| TrustError::Cert("year overflow".to_string()))?
            };
            let month_num = parse_ascii_2digits(tlv.value, 2)?;
            let month = time::Month::try_from(month_num)
                .map_err(|_| TrustError::Cert("invalid UTCTime month number".to_string()))?;
            let day = parse_ascii_2digits(tlv.value, 4)?;
            let hour = parse_ascii_2digits(tlv.value, 6)?;
            let minute = parse_ascii_2digits(tlv.value, 8)?;
            let second = parse_ascii_2digits(tlv.value, 10)?;

            let date = time::Date::from_calendar_date(year, month, day).map_err(|e| {
                TrustError::Cert(format!("invalid calendar date in UTCTime: {}", e))
            })?;
            let time = time::Time::from_hms(hour, minute, second)
                .map_err(|e| TrustError::Cert(format!("invalid time in UTCTime: {}", e)))?;
            Ok(time::OffsetDateTime::new_utc(date, time))
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ (15 chars)
            if tlv.value.len() != 15 {
                return Err(TrustError::Cert(format!(
                    "invalid GeneralizedTime length {}, expected 15 (YYYYMMDDHHMMSSZ)",
                    tlv.value.len()
                )));
            }
            if tlv.value.get(14) != Some(&b'Z') {
                return Err(TrustError::Cert(
                    "GeneralizedTime must end with 'Z'".to_string(),
                ));
            }
            let year = parse_ascii_4digits(tlv.value, 0)?;
            let month_num = parse_ascii_2digits(tlv.value, 4)?;
            let month = time::Month::try_from(month_num).map_err(|_| {
                TrustError::Cert("invalid GeneralizedTime month number".to_string())
            })?;
            let day = parse_ascii_2digits(tlv.value, 6)?;
            let hour = parse_ascii_2digits(tlv.value, 8)?;
            let minute = parse_ascii_2digits(tlv.value, 10)?;
            let second = parse_ascii_2digits(tlv.value, 12)?;

            let date = time::Date::from_calendar_date(year, month, day).map_err(|e| {
                TrustError::Cert(format!("invalid calendar date in GeneralizedTime: {}", e))
            })?;
            let time = time::Time::from_hms(hour, minute, second)
                .map_err(|e| TrustError::Cert(format!("invalid time in GeneralizedTime: {}", e)))?;
            Ok(time::OffsetDateTime::new_utc(date, time))
        }
        _ => Err(TrustError::Cert("invalid time tag in validity".to_string())),
    }
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

    let expected_sig_alg = encode_sha256_with_rsa_algorithm();
    if sig_alg_tlv.raw != expected_sig_alg.as_slice() {
        return Err(TrustError::Cert(
            "unsupported signature algorithm: expected sha256WithRSAEncryption with NULL parameters".to_string(),
        ));
    }

    let tbs_items = parse_sequence_items(tbs_tlv.value)?;
    if tbs_items.len() < 6 {
        return Err(TrustError::Cert(
            "too few items in TBSCertificate".to_string(),
        ));
    }
    let mut idx = 0;
    // Version: tag 0xA0 [0]
    let ver_item = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("too few items in TBSCertificate".to_string()))?;
    if ver_item.tag == 0xA0 {
        let ver_items = parse_sequence_items(ver_item.value)?;
        if ver_items.len() != 1 {
            return Err(TrustError::Cert(
                "invalid version sequence in TBSCertificate".to_string(),
            ));
        }
        let ver_val = ver_items
            .first()
            .ok_or_else(|| TrustError::Cert("missing version item".to_string()))?;
        if ver_val.tag != 0x02 || ver_val.value != [0x02] {
            return Err(TrustError::Cert(
                "unsupported certificate version: expected v3 (2)".to_string(),
            ));
        }
        idx = idx
            .checked_add(1)
            .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    } else {
        return Err(TrustError::Cert(
            "missing version in TBSCertificate: CA certificates with extensions must be v3"
                .to_string(),
        ));
    }
    let serial_item = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("missing serialNumber in TBSCertificate".to_string()))?;
    if serial_item.tag != 0x02 {
        return Err(TrustError::Cert(
            "missing or invalid serialNumber in TBSCertificate".to_string(),
        ));
    }
    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    let tbs_sig_alg = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("missing signature in TBSCertificate".to_string()))?;
    if tbs_sig_alg.tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid signature in TBSCertificate".to_string(),
        ));
    }
    if sig_alg_tlv.raw != tbs_sig_alg.raw {
        return Err(TrustError::Cert(
            "certificate signatureAlgorithm does not match tbsCertificate.signature".to_string(),
        ));
    }
    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    let issuer_tlv = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("missing issuer in TBSCertificate".to_string()))?;
    if issuer_tlv.tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid issuer in TBSCertificate".to_string(),
        ));
    }
    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    let validity_tlv = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("missing validity in TBSCertificate".to_string()))?;
    if validity_tlv.tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid validity in TBSCertificate".to_string(),
        ));
    }
    let validity_items = parse_sequence_items(validity_tlv.value)?;
    if validity_items.len() != 2 {
        return Err(TrustError::Cert(
            "validity must contain exactly notBefore and notAfter".to_string(),
        ));
    }
    let not_before_item = validity_items
        .first()
        .ok_or_else(|| TrustError::Cert("missing notBefore".to_string()))?;
    let not_after_item = validity_items
        .get(1)
        .ok_or_else(|| TrustError::Cert("missing notAfter".to_string()))?;
    let not_before = parse_asn1_time(not_before_item)?;
    let not_after = parse_asn1_time(not_after_item)?;
    if not_before > not_after {
        return Err(TrustError::Cert(
            "validity notBefore is after notAfter".to_string(),
        ));
    }
    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    let subject_tlv = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("missing subject in TBSCertificate".to_string()))?;
    if subject_tlv.tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid subject in TBSCertificate".to_string(),
        ));
    }

    // Require and verify self-signed CA format: issuer must match subject
    if issuer_tlv.raw != subject_tlv.raw {
        return Err(TrustError::Cert(
            "CA certificate is not self-signed: issuer does not match subject".to_string(),
        ));
    }

    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    let spki_tlv = tbs_items.get(idx).ok_or_else(|| {
        TrustError::Cert("missing subjectPublicKeyInfo in TBSCertificate".to_string())
    })?;
    if spki_tlv.tag != 0x30 {
        return Err(TrustError::Cert(
            "missing or invalid subjectPublicKeyInfo in TBSCertificate".to_string(),
        ));
    }
    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;

    // Optional [1] issuerUniqueID, [2] subjectUniqueID: IMPLICIT BIT STRINGs
    // (primitive in DER), each at most once and in order.
    let mut last_unique_tag = 0u8;
    while let Some(item) = tbs_items.get(idx) {
        if item.tag == 0xA1 || item.tag == 0xA2 {
            return Err(TrustError::Cert(
                "unique identifier must be a primitive BIT STRING".to_string(),
            ));
        }
        if item.tag != 0x81 && item.tag != 0x82 {
            break;
        }
        if item.tag <= last_unique_tag {
            return Err(TrustError::Cert(
                "unique identifiers repeated or out of order".to_string(),
            ));
        }
        last_unique_tag = item.tag;
        validate_bit_string_value(item.value, "unique identifier")?;
        idx = idx
            .checked_add(1)
            .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;
    }

    // Find extensions ([3] EXPLICIT tag 0xA3)
    let ext_tlv = tbs_items
        .get(idx)
        .ok_or_else(|| TrustError::Cert("missing extensions in CA certificate".to_string()))?;
    if ext_tlv.tag != 0xA3 {
        return Err(TrustError::Cert(
            "expected [3] EXPLICIT extensions in TBSCertificate".to_string(),
        ));
    }
    let ext_seq_items = parse_sequence_items(ext_tlv.value)?;
    if ext_seq_items.len() != 1 {
        return Err(TrustError::Cert(
            "invalid extensions wrapper in TBSCertificate".to_string(),
        ));
    }
    let ext_seq = ext_seq_items
        .first()
        .ok_or_else(|| TrustError::Cert("missing extensions sequence".to_string()))?;
    if ext_seq.tag != 0x30 {
        return Err(TrustError::Cert(
            "extensions wrapper is not a SEQUENCE".to_string(),
        ));
    }

    let mut found_ca_true = false;
    let mut seen_oids = std::collections::HashSet::new();

    let extensions = parse_sequence_items(ext_seq.value)?;
    for ext in &extensions {
        if ext.tag != 0x30 {
            return Err(TrustError::Cert(
                "extension item is not a SEQUENCE".to_string(),
            ));
        }
        let ext_parts = parse_sequence_items(ext.value)?;
        let (oid, is_critical, extn_value) = match ext_parts.len() {
            2 => {
                let p0 = ext_parts
                    .first()
                    .ok_or_else(|| TrustError::Cert("missing extension OID".to_string()))?;
                let p1 = ext_parts
                    .get(1)
                    .ok_or_else(|| TrustError::Cert("missing extension value".to_string()))?;
                if p0.tag != 0x06 {
                    return Err(TrustError::Cert("missing extension OID".to_string()));
                }
                if p1.tag != 0x04 {
                    return Err(TrustError::Cert(
                        "invalid extension value tag: expected OCTET STRING".to_string(),
                    ));
                }
                (p0.value, false, p1.value)
            }
            3 => {
                let p0 = ext_parts
                    .first()
                    .ok_or_else(|| TrustError::Cert("missing extension OID".to_string()))?;
                let p1 = ext_parts
                    .get(1)
                    .ok_or_else(|| TrustError::Cert("missing extension critical".to_string()))?;
                let p2 = ext_parts
                    .get(2)
                    .ok_or_else(|| TrustError::Cert("missing extension value".to_string()))?;
                if p0.tag != 0x06 {
                    return Err(TrustError::Cert("missing extension OID".to_string()));
                }
                if p1.tag != 0x01 {
                    return Err(TrustError::Cert(
                        "invalid extension critical tag: expected BOOLEAN".to_string(),
                    ));
                }
                if p2.tag != 0x04 {
                    return Err(TrustError::Cert(
                        "invalid extension value tag: expected OCTET STRING".to_string(),
                    ));
                }
                // DER: critical is DEFAULT FALSE, so an explicit value must be TRUE.
                if !der_boolean(p1.value, "extension critical")? {
                    return Err(TrustError::Cert(
                        "explicit critical FALSE is not DER".to_string(),
                    ));
                }
                (p0.value, true, p2.value)
            }
            _ => {
                return Err(TrustError::Cert(
                    "invalid extension SEQUENCE structure".to_string(),
                ));
            }
        };

        if !seen_oids.insert(oid.to_vec()) {
            return Err(TrustError::Cert(format!(
                "duplicate extension in certificate: OID {:?}",
                oid
            )));
        }

        let is_known = matches!(
            oid,
            OID_BASIC_CONSTRAINTS
                | OID_KEY_USAGE
                | OID_SUBJECT_KEY_IDENTIFIER
                | OID_AUTHORITY_KEY_IDENTIFIER
                | OID_SUBJECT_ALT_NAME
        );
        if is_critical && !is_known {
            return Err(TrustError::Cert(format!(
                "unknown critical extension: OID {:?}",
                oid
            )));
        }

        if oid == OID_BASIC_CONSTRAINTS {
            let (bc_tlv, rem) = parse_tlv(extn_value)?;
            if !rem.is_empty() || bc_tlv.tag != 0x30 {
                return Err(TrustError::Cert(
                    "invalid basicConstraints OCTET STRING: expected SEQUENCE".to_string(),
                ));
            }
            let bc_items = parse_sequence_items(bc_tlv.value)?;
            if !bc_items.is_empty() {
                let ca_bool = bc_items
                    .first()
                    .ok_or_else(|| TrustError::Cert("missing cA".to_string()))?;
                if ca_bool.tag != 0x01 {
                    return Err(TrustError::Cert(
                        "invalid basicConstraints cA: expected BOOLEAN".to_string(),
                    ));
                }
                // DER: cA is DEFAULT FALSE, so an explicit value must be TRUE.
                if !der_boolean(ca_bool.value, "basicConstraints cA")? {
                    return Err(TrustError::Cert(
                        "explicit basicConstraints cA FALSE is not DER".to_string(),
                    ));
                }
                found_ca_true = true;
                if bc_items.len() > 2 {
                    return Err(TrustError::Cert(
                        "invalid basicConstraints: too many elements".to_string(),
                    ));
                }
                if bc_items.len() == 2 {
                    let path_len = bc_items
                        .get(1)
                        .ok_or_else(|| TrustError::Cert("missing pathLen".to_string()))?;
                    if path_len.tag != 0x02 {
                        return Err(TrustError::Cert(
                            "invalid basicConstraints pathLenConstraint: expected INTEGER"
                                .to_string(),
                        ));
                    }
                    validate_path_len(path_len.value)?;
                }
            }
        } else if oid == OID_SUBJECT_KEY_IDENTIFIER {
            validate_ski(extn_value)?;
        } else if oid == OID_AUTHORITY_KEY_IDENTIFIER {
            validate_aki(extn_value)?;
        } else if oid == OID_SUBJECT_ALT_NAME {
            validate_san(extn_value)?;
        } else if oid == OID_KEY_USAGE {
            let (ku_tlv, rem) = parse_tlv(extn_value)?;
            if !rem.is_empty() || ku_tlv.tag != 0x03 {
                return Err(TrustError::Cert(
                    "invalid keyUsage OCTET STRING: expected BIT STRING".to_string(),
                ));
            }
            let unused_bits = *ku_tlv
                .value
                .first()
                .ok_or_else(|| TrustError::Cert("empty keyUsage BIT STRING".to_string()))?;
            if unused_bits > 7 {
                return Err(TrustError::Cert(
                    "invalid unused bits count in keyUsage BIT STRING".to_string(),
                ));
            }
            let has_key_cert_sign =
                if ku_tlv.value.len() < 2 || (ku_tlv.value.len() == 2 && unused_bits > 2) {
                    false
                } else {
                    let b1 = *ku_tlv
                        .value
                        .get(1)
                        .ok_or_else(|| TrustError::Cert("missing keyUsage byte".to_string()))?;
                    (b1 & 0x04) != 0
                };
            if !has_key_cert_sign {
                return Err(TrustError::Cert(
                    "keyUsage does not permit keyCertSign".to_string(),
                ));
            }
        }
    }

    if !found_ca_true {
        return Err(TrustError::Cert(
            "certificate is not a CA: missing or false basicConstraints CA:true".to_string(),
        ));
    }

    idx = idx
        .checked_add(1)
        .ok_or_else(|| TrustError::Cert("idx overflow".to_string()))?;

    // Validate that there are no trailing fields in TBSCertificate
    if idx != tbs_items.len() {
        return Err(TrustError::Cert(
            "trailing fields in TBSCertificate".to_string(),
        ));
    }

    // Parse RSA Public Key from SPKI
    let spki_parts = parse_sequence_items(spki_tlv.value)?;
    if spki_parts.len() != 2 {
        return Err(TrustError::Cert("invalid SPKI in certificate".to_string()));
    }
    let alg_tlv = spki_parts
        .first()
        .ok_or_else(|| TrustError::Cert("missing SPKI alg".to_string()))?;
    let spk_bit_string = spki_parts
        .get(1)
        .ok_or_else(|| TrustError::Cert("missing SPKI pubkey".to_string()))?;
    if alg_tlv.tag != 0x30 || spk_bit_string.tag != 0x03 {
        return Err(TrustError::Cert(
            "invalid SPKI algorithm or public key tag".to_string(),
        ));
    }

    let expected_spki_alg = encode_rsa_algorithm();
    if alg_tlv.raw != expected_spki_alg.as_slice() {
        return Err(TrustError::Cert(
            "unsupported SPKI algorithm: expected rsaEncryption".to_string(),
        ));
    }

    if spk_bit_string.value.is_empty() || spk_bit_string.value.first() != Some(&0) {
        return Err(TrustError::Cert("invalid BIT STRING in SPKI".to_string()));
    }
    let pkcs1_der = spk_bit_string
        .value
        .get(1..)
        .ok_or_else(|| TrustError::Cert("empty SPKI BIT STRING".to_string()))?;
    use rsa::pkcs1::DecodeRsaPublicKey;
    let public_key = rsa::RsaPublicKey::from_pkcs1_der(pkcs1_der).map_err(|e| {
        TrustError::Cert(format!("failed to parse RSA public key from SPKI: {}", e))
    })?;

    // Verify self-signed signature
    if sig_val_tlv.value.is_empty() || sig_val_tlv.value.first() != Some(&0) {
        return Err(TrustError::Cert("invalid signature BIT STRING".to_string()));
    }
    let sig_bytes = sig_val_tlv
        .value
        .get(1..)
        .ok_or_else(|| TrustError::Cert("empty signature BIT STRING".to_string()))?;

    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Sha256;

    let signature = Signature::try_from(sig_bytes)
        .map_err(|e| TrustError::Cert(format!("invalid RSA signature length: {}", e)))?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    verifying_key
        .verify(tbs_tlv.raw, &signature)
        .map_err(|e| TrustError::Cert(format!("CA self-signature verification failed: {}", e)))?;

    Ok(())
}

/// DER BOOLEAN contents: exactly one byte, 0x00 (FALSE) or 0xFF (TRUE).
fn der_boolean(value: &[u8], what: &str) -> Result<bool, TrustError> {
    match value {
        [0x00] => Ok(false),
        [0xFF] => Ok(true),
        _ => Err(TrustError::Cert(format!("invalid DER BOOLEAN in {what}"))),
    }
}

/// BIT STRING contents: an unused-bits byte (0..=7, and 0 when empty) and, in
/// DER, zero padding bits.
fn validate_bit_string_value(value: &[u8], what: &str) -> Result<(), TrustError> {
    let (&unused, data) = value
        .split_first()
        .ok_or_else(|| TrustError::Cert(format!("empty BIT STRING in {what}")))?;
    if unused > 7 || (data.is_empty() && unused != 0) {
        return Err(TrustError::Cert(format!("invalid BIT STRING in {what}")));
    }
    if let Some(&last) = data.last() {
        if last & ((1u8 << unused) - 1) != 0 {
            return Err(TrustError::Cert(format!(
                "non-zero BIT STRING padding in {what}"
            )));
        }
    }
    Ok(())
}

/// pathLenConstraint: a minimally encoded, non-negative INTEGER that fits u32.
fn validate_path_len(value: &[u8]) -> Result<(), TrustError> {
    let invalid = || TrustError::Cert("invalid basicConstraints pathLenConstraint".to_string());
    let (&first, rest) = value.split_first().ok_or_else(invalid)?;
    if first & 0x80 != 0 {
        return Err(invalid()); // negative
    }
    if first == 0 && rest.first().is_some_and(|b| b & 0x80 == 0) {
        return Err(invalid()); // non-minimal
    }
    let magnitude = if first == 0 { rest } else { value };
    if magnitude.len() > 4 {
        return Err(invalid());
    }
    Ok(())
}

fn single_tlv<'a>(value: &'a [u8], tag: u8, what: &str) -> Result<Tlv<'a>, TrustError> {
    let (tlv, rem) = parse_tlv(value)?;
    if !rem.is_empty() || tlv.tag != tag {
        return Err(TrustError::Cert(format!("invalid {what} encoding")));
    }
    Ok(tlv)
}

/// subjectKeyIdentifier: a non-empty OCTET STRING.
fn validate_ski(value: &[u8]) -> Result<(), TrustError> {
    let ski = single_tlv(value, 0x04, "subjectKeyIdentifier")?;
    if ski.value.is_empty() {
        return Err(TrustError::Cert("empty subjectKeyIdentifier".to_string()));
    }
    Ok(())
}

/// authorityKeyIdentifier: SEQUENCE of optional [0] keyIdentifier (primitive),
/// [1] authorityCertIssuer (constructed) and [2] serial (primitive), in order.
fn validate_aki(value: &[u8]) -> Result<(), TrustError> {
    let aki = single_tlv(value, 0x30, "authorityKeyIdentifier")?;
    let mut last = None;
    for item in parse_sequence_items(aki.value)? {
        let rank = match item.tag {
            0x80 => 0,
            0xA1 => 1,
            0x82 => 2,
            _ => {
                return Err(TrustError::Cert(
                    "unexpected field in authorityKeyIdentifier".to_string(),
                ))
            }
        };
        if last.is_some_and(|l| rank <= l) {
            return Err(TrustError::Cert(
                "authorityKeyIdentifier fields repeated or out of order".to_string(),
            ));
        }
        if item.value.is_empty() {
            return Err(TrustError::Cert(
                "empty authorityKeyIdentifier field".to_string(),
            ));
        }
        if item.tag == 0xA1 {
            parse_sequence_items(item.value)?;
        }
        last = Some(rank);
    }
    if last.is_none() {
        return Err(TrustError::Cert("empty authorityKeyIdentifier".to_string()));
    }
    Ok(())
}

/// subjectAltName: a non-empty SEQUENCE of GeneralName. Every name is a context
/// tag 0..=8 with the DER form (constructed for otherName, x400Address,
/// directoryName and ediPartyName); dNSName, rfc822Name and URI are printable
/// ASCII, and iPAddress is 4 or 16 bytes.
fn validate_san(value: &[u8]) -> Result<(), TrustError> {
    let san = single_tlv(value, 0x30, "subjectAltName")?;
    let names = parse_sequence_items(san.value)?;
    if names.is_empty() {
        return Err(TrustError::Cert("empty subjectAltName".to_string()));
    }
    for name in names {
        let invalid = || TrustError::Cert("invalid subjectAltName GeneralName".to_string());
        match name.tag {
            0xA0 | 0xA3 | 0xA4 | 0xA5 => {
                parse_sequence_items(name.value)?;
            }
            0x81 | 0x82 | 0x86 => {
                if name.value.is_empty() || !name.value.iter().all(|b| (0x21..=0x7e).contains(b)) {
                    return Err(invalid());
                }
            }
            0x87 => {
                if name.value.len() != 4 && name.value.len() != 16 {
                    return Err(invalid());
                }
            }
            0x88 => {
                if name.value.is_empty() {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    Ok(())
}
