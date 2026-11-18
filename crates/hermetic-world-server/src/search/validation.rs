#![forbid(unsafe_code)]

use std::collections::HashSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::types::{
    SearchError, ALLOWED_SOURCES, MAX_PAYLOAD_BYTES, MAX_TITLE_BYTES, MAX_TOTAL_PAYLOAD_BYTES,
    MAX_URL_BYTES,
};

pub fn validate_digest(val: &str) -> Result<(), SearchError> {
    if val.len() != 64
        || !val
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(SearchError::InvalidDigest);
    }
    Ok(())
}

pub fn parse_timestamp_nanos(val: &str) -> Result<i128, SearchError> {
    let dt = OffsetDateTime::parse(val, &Rfc3339).map_err(|_| SearchError::InvalidTimestamp)?;
    // Ensure UTC
    if dt.offset() != time::UtcOffset::UTC {
        return Err(SearchError::InvalidTimestamp);
    }
    Ok(dt.unix_timestamp_nanos())
}

pub fn parse_month_boundary_nanos(month_str: &str) -> Result<(i128, String), SearchError> {
    if month_str.len() != 7 {
        return Err(SearchError::InvalidMonth);
    }
    let bytes = month_str.as_bytes();
    if bytes[4] != b'-'
        || !bytes[0..4].iter().all(|b| b.is_ascii_digit())
        || !bytes[5..7].iter().all(|b| b.is_ascii_digit())
    {
        return Err(SearchError::InvalidMonth);
    }
    let year: i32 = month_str[0..4]
        .parse()
        .map_err(|_| SearchError::InvalidMonth)?;
    let month_num: u8 = month_str[5..7]
        .parse()
        .map_err(|_| SearchError::InvalidMonth)?;
    if year < 1000 || !(1..=12).contains(&month_num) {
        return Err(SearchError::InvalidMonth);
    }
    let first_day_rfc3339 = format!("{month_str}-01T00:00:00Z");
    let nanos = parse_timestamp_nanos(&first_day_rfc3339)?;
    Ok((nanos, first_day_rfc3339))
}

pub fn validate_title(val: &str) -> Result<(), SearchError> {
    if val.len() > MAX_TITLE_BYTES {
        return Err(SearchError::InvalidTitle);
    }
    if val.chars().any(|c| (c as u32) < 32 || (c as u32) == 127) {
        return Err(SearchError::InvalidTitle);
    }
    Ok(())
}

pub fn validate_source(val: &str) -> Result<(), SearchError> {
    if !ALLOWED_SOURCES.contains(&val) {
        return Err(SearchError::InvalidSource);
    }
    Ok(())
}

pub fn validate_url(val: &str) -> Result<(), SearchError> {
    if val.is_empty() || val.len() > MAX_URL_BYTES || !val.is_ascii() {
        return Err(SearchError::InvalidUrl);
    }
    if val
        .bytes()
        .any(|b| b <= 32 || b >= 127 || b == b'\\' || b == b'#')
    {
        return Err(SearchError::InvalidUrl);
    }

    let (scheme, rest) = if let Some(r) = val.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = val.strip_prefix("https://") {
        ("https", r)
    } else {
        return Err(SearchError::NoncanonicalUrl);
    };

    let (authority, path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => return Err(SearchError::NoncanonicalUrl),
    };

    if authority.is_empty() || authority.len() > 253 {
        return Err(SearchError::NoncanonicalUrl);
    }
    if authority.contains('@') || authority.contains(':') {
        return Err(SearchError::NoncanonicalUrl);
    }
    if !authority.contains('.') {
        return Err(SearchError::NoncanonicalUrl);
    }

    for label in authority.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(SearchError::NoncanonicalUrl);
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return Err(SearchError::NoncanonicalUrl);
        }
        if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        {
            return Err(SearchError::NoncanonicalUrl);
        }
        for &b in bytes {
            if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'-' {
                return Err(SearchError::NoncanonicalUrl);
            }
        }
    }

    if !path_and_query.starts_with('/') {
        return Err(SearchError::NoncanonicalUrl);
    }

    let (path_only, _query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    for segment in path_only.split('/') {
        if segment == "." || segment == ".." {
            return Err(SearchError::NoncanonicalUrl);
        }
    }

    // Check percent-encoding
    let mut i = 0;
    let b = val.as_bytes();
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(SearchError::NoncanonicalUrl);
            }
            let h1 = b[i + 1];
            let h2 = b[i + 2];
            let is_upper_hex = |c: u8| c.is_ascii_digit() || (b'A'..=b'F').contains(&c);
            if !is_upper_hex(h1) || !is_upper_hex(h2) {
                return Err(SearchError::NoncanonicalUrl);
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    let _ = scheme;
    Ok(())
}

pub fn validate_blobs_and_references(
    blobs: &std::collections::HashMap<String, Vec<u8>>,
    references: &HashSet<String>,
) -> Result<(), SearchError> {
    if blobs.len() > super::types::MAX_DOCUMENTS {
        return Err(SearchError::RecordCapExceeded);
    }
    let mut total: u64 = 0;
    for (digest, body) in blobs {
        validate_digest(digest)?;
        if body.len() as u64 > MAX_PAYLOAD_BYTES {
            return Err(SearchError::PayloadCapExceeded);
        }
        total = total
            .checked_add(body.len() as u64)
            .ok_or(SearchError::AggregatePayloadCapExceeded)?;
        if total > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(SearchError::AggregatePayloadCapExceeded);
        }
        let actual_sha = hermetic_common::hash::sha256_hex(body);
        if actual_sha != *digest {
            return Err(SearchError::PayloadDigestMismatch);
        }
    }

    let blob_keys: HashSet<String> = blobs.keys().cloned().collect();
    if blob_keys != *references {
        return Err(SearchError::PolicyMismatch(
            "blobs do not match references".to_string(),
        ));
    }
    Ok(())
}
