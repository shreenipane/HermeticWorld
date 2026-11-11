#![forbid(unsafe_code)]

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
