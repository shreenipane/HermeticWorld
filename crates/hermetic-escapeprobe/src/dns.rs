//! Minimal DNS wire handling for the escape probe: build one query, classify
//! one response by its header only. Answer data is never parsed or echoed.
#![forbid(unsafe_code)]

use crate::classify::EscapeResult;

pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_AAAA: u16 = 28;
pub const MAX_RESPONSE_BYTES: usize = 4096;

/// Build a standard recursive query. Returns `None` for an invalid name.
/// The name is a fixed probe constant; `.` alone means the root.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.len() > 253 {
        return None;
    }
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Some(out)
}

/// Classify a response to a query for a name outside the world.
/// Any answer or authority record (a referral is delegation) is a leak.
/// NXDOMAIN, REFUSED, SERVFAIL and empty NOERROR are blocked.
/// Malformed, mismatched or non-response packets are errors (fail closed).
pub fn classify_response(query_id: u16, packet: &[u8]) -> (EscapeResult, &'static str) {
    if packet.len() < 12 {
        return (EscapeResult::Error, "dns response too short");
    }
    if packet.len() > MAX_RESPONSE_BYTES {
        return (EscapeResult::Error, "dns response too large");
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    if id != query_id {
        return (EscapeResult::Error, "dns response id mismatch");
    }
    if packet[2] & 0x80 == 0 {
        return (EscapeResult::Error, "dns packet is not a response");
    }
    let rcode = packet[3] & 0x0f;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    if ancount > 0 {
        return (EscapeResult::Leak, "real name answered");
    }
    if nscount > 0 && rcode == 0 {
        return (EscapeResult::Leak, "delegation returned");
    }
    match rcode {
        0 => (EscapeResult::Blocked, "empty answer"),
        2 => (EscapeResult::Blocked, "servfail"),
        3 => (EscapeResult::Blocked, "nxdomain"),
        5 => (EscapeResult::Blocked, "refused"),
        _ => (EscapeResult::Error, "unexpected rcode"),
    }
}
