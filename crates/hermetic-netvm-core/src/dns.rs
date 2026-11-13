//! Bounded, non-forwarding UDP DNS responder loop with fixed per-source token-bucket rate limiting.

use std::collections::BTreeMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::Metrics;

/// Maximum accepted or emitted DNS UDP datagram payload size in bytes.
pub const MAX_DNS_PACKET_BYTES: usize = 512;

/// Fixed burst capacity (in packets) for each per-source token bucket.
pub const DNS_BUCKET_CAPACITY: u32 = 10;

/// Fixed sustained refill rate (in packets per second) for each per-source token bucket.
pub const DNS_BUCKET_REFILL_PER_SEC: u32 = 5;

/// Maximum number of distinct source IPs tracked concurrently in the rate limiter.
pub const DNS_MAX_TRACKED_SOURCES: usize = 4096;

/// Bounded socket read poll timeout so shutdown signals are observed promptly.
pub const DNS_POLL_TIMEOUT: Duration = Duration::from_millis(25);

/// Bounded socket write timeout for UDP replies.
pub const DNS_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

/// Maximum uncompressed wire length of a DNS domain name.
pub const MAX_DNS_NAME_WIRE_BYTES: usize = 255;

/// Maximum number of labels in a DNS domain name.
pub const MAX_DNS_LABELS: usize = 128;

/// Pluggable DNS responder trait.
pub trait DnsResponder: Send + Sync {
    /// Produces a serialized DNS wire response for `packet`, or `None` to drop the datagram.
    fn respond(&self, packet: &[u8]) -> Option<Vec<u8>>;
}

/// Errors produced when encoding or decoding DNS wire packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    PacketTooShort,
    PacketTooLarge,
    InvalidDomainName,
    InvalidQuery,
    InvalidResponse,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::PacketTooShort => write!(f, "DNS packet shorter than 12-byte header"),
            DnsError::PacketTooLarge => write!(f, "DNS packet exceeds 512 bytes"),
            DnsError::InvalidDomainName => write!(f, "invalid DNS domain name"),
            DnsError::InvalidQuery => write!(f, "malformed or unsupported DNS query"),
            DnsError::InvalidResponse => write!(f, "malformed DNS response"),
        }
    }
}

impl std::error::Error for DnsError {}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens_milli: u64,
    last_update: Instant,
    last_seen: Instant,
}

/// Deterministic, memory-bounded per-source token-bucket rate limiter.
#[derive(Debug, Clone)]
pub struct SourceRateLimiter {
    capacity_milli: u64,
    refill_milli_per_sec: u64,
    max_sources: usize,
    buckets: BTreeMap<IpAddr, TokenBucket>,
}

impl Default for SourceRateLimiter {
    fn default() -> Self {
        Self::new(
            DNS_BUCKET_CAPACITY,
            DNS_BUCKET_REFILL_PER_SEC,
            DNS_MAX_TRACKED_SOURCES,
        )
    }
}

impl SourceRateLimiter {
    /// Creates a rate limiter with fixed capacity, refill rate, and table bound.
    pub fn new(capacity: u32, refill_per_sec: u32, max_sources: usize) -> Self {
        Self {
            capacity_milli: u64::from(capacity).saturating_mul(1000),
            refill_milli_per_sec: u64::from(refill_per_sec).saturating_mul(1000),
            max_sources: max_sources.max(1),
            buckets: BTreeMap::new(),
        }
    }

    /// Consumes 1 packet token for `source` at monotonic instant `now`, returning `true` if allowed.
    pub fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        if self.capacity_milli < 1000 {
            return false;
        }

        if !self.buckets.contains_key(&source) {
            if self.buckets.len() >= self.max_sources {
                self.evict_stalest();
            }
            self.buckets.insert(
                source,
                TokenBucket {
                    tokens_milli: self.capacity_milli,
                    last_update: now,
                    last_seen: now,
                },
            );
        }

        if let Some(bucket) = self.buckets.get_mut(&source) {
            bucket.last_seen = now;
            if self.refill_milli_per_sec > 0 {
                let elapsed_ms = now
                    .saturating_duration_since(bucket.last_update)
                    .as_millis() as u64;
                let added_milli = elapsed_ms.saturating_mul(self.refill_milli_per_sec) / 1000;
                if added_milli > 0 {
                    bucket.tokens_milli = bucket
                        .tokens_milli
                        .saturating_add(added_milli)
                        .min(self.capacity_milli);
                    let consumed_ms =
                        (added_milli.saturating_mul(1000)) / self.refill_milli_per_sec;
                    bucket.last_update += Duration::from_millis(consumed_ms);
                }
            }

            if bucket.tokens_milli >= 1000 {
                bucket.tokens_milli -= 1000;
                return true;
            }
        }

        false
    }

    fn evict_stalest(&mut self) {
        let mut oldest: Option<(IpAddr, Instant)> = None;
        for (&ip, bucket) in &self.buckets {
            match oldest {
                None => oldest = Some((ip, bucket.last_seen)),
                Some((_, best_time)) if bucket.last_seen < best_time => {
                    oldest = Some((ip, bucket.last_seen));
                }
                _ => {}
            }
        }
        if let Some((evict_ip, _)) = oldest {
            self.buckets.remove(&evict_ip);
        }
    }
}

/// Fixed-table in-memory `DnsResponder` answering IPv4 `A` queries deterministically.
#[derive(Debug, Clone, Default)]
pub struct StaticDnsResponder {
    records: BTreeMap<String, [u8; 4]>,
}

impl StaticDnsResponder {
    /// Creates an empty DNS responder table.
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Inserts a domain name (case-insensitive, optional trailing dot) mapped to an IPv4 address.
    pub fn insert(&mut self, domain: &str, ipv4: [u8; 4]) {
        let normalized = normalize_domain(domain);
        if !normalized.is_empty() {
            self.records.insert(normalized, ipv4);
        }
    }
}

impl DnsResponder for StaticDnsResponder {
    fn respond(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 12 || packet.len() > MAX_DNS_PACKET_BYTES {
            return None;
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);

        // Must be a standard query (QR=0, OPCODE=0) with at least one question.
        let is_response = (flags & 0x8000) != 0;
        let opcode = (flags >> 11) & 0x0F;
        if is_response || opcode != 0 || qdcount == 0 {
            return None;
        }

        let (qname, qend) = decode_qname(packet, 12).ok()?;
        if qend.checked_add(4)? > packet.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([packet[qend], packet[qend + 1]]);
        let qclass = u16::from_be_bytes([packet[qend + 2], packet[qend + 3]]);

        let question_wire = packet.get(12..qend.checked_add(4)?)?;
        let rd = flags & 0x0100;

        // Only IN (1) A (1) queries for names in the fixed table are answered with an address.
        // Other record types for a known name get an empty NOERROR answer, and every name not
        // in the table gets NXDOMAIN (TR-NET-2); nothing is ever forwarded upstream.
        let ipv4 = match self.records.get(&qname) {
            Some(ip) if qclass == 1 && qtype == 1 => ip,
            Some(_) => return Some(empty_reply(id, rd, DNS_RCODE_NOERROR, question_wire)),
            None => return Some(empty_reply(id, rd, DNS_RCODE_NXDOMAIN, question_wire)),
        };

        let resp_flags: u16 = 0x8400 | rd; // QR=1, AA=1, RD copied, RCODE=0

        let mut out = Vec::with_capacity(12 + question_wire.len() + 16);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&resp_flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        out.extend_from_slice(question_wire);

        // Answer RR: pointer to QNAME at offset 12 (0xC00C), TYPE=A(1), CLASS=IN(1), TTL=60, RDLENGTH=4
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(ipv4);

        if out.len() > MAX_DNS_PACKET_BYTES {
            return None;
        }
        Some(out)
    }
}

/// DNS response code for success.
pub const DNS_RCODE_NOERROR: u16 = 0;

/// DNS response code for a name that does not exist.
pub const DNS_RCODE_NXDOMAIN: u16 = 3;

/// Builds an authoritative reply with no answer records, echoing the single question.
fn empty_reply(id: u16, rd: u16, rcode: u16, question_wire: &[u8]) -> Vec<u8> {
    let resp_flags: u16 = 0x8400 | rd | (rcode & 0x000F); // QR=1, AA=1, RD copied
    let mut out = Vec::with_capacity(12 + question_wire.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    out.extend_from_slice(question_wire);
    out
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn decode_qname(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut pos = start;
    let mut labels = Vec::new();
    let mut wire_bytes = 0usize;

    loop {
        if pos >= packet.len() {
            return Err(DnsError::InvalidQuery);
        }
        let len = packet[pos] as usize;
        pos += 1;
        wire_bytes += 1;

        if len == 0 {
            break;
        }
        // Reject compression pointers or reserved label bits in query names.
        if (len & 0xC0) != 0 || len > 63 {
            return Err(DnsError::InvalidQuery);
        }
        if labels.len() >= MAX_DNS_LABELS {
            return Err(DnsError::InvalidQuery);
        }
        wire_bytes = wire_bytes.checked_add(len).ok_or(DnsError::InvalidQuery)?;
        if wire_bytes > MAX_DNS_NAME_WIRE_BYTES {
            return Err(DnsError::InvalidQuery);
        }
        let end = pos.checked_add(len).ok_or(DnsError::InvalidQuery)?;
        if end > packet.len() {
            return Err(DnsError::InvalidQuery);
        }
        let label_bytes = &packet[pos..end];
        if !label_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DnsError::InvalidQuery);
        }
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| DnsError::InvalidQuery)?
            .to_ascii_lowercase();
        labels.push(label);
        pos = end;
    }

    Ok((labels.join("."), pos))
}

/// Encodes a standard DNS wire `A` query packet for `domain` with transaction ID `id`.
pub fn encode_dns_a_query(id: u16, domain: &str) -> Result<Vec<u8>, DnsError> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(DnsError::InvalidDomainName);
    }

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DnsError::InvalidDomainName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    if out.len() > MAX_DNS_PACKET_BYTES {
        return Err(DnsError::PacketTooLarge);
    }
    Ok(out)
}

/// Decodes the first IPv4 `A` answer record from a DNS response packet, returning `(id, ipv4)`.
pub fn decode_dns_a_answer(packet: &[u8]) -> Result<(u16, [u8; 4]), DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }
    if packet.len() > MAX_DNS_PACKET_BYTES {
        return Err(DnsError::PacketTooLarge);
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);

    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 || qdcount != 1 || ancount == 0 {
        return Err(DnsError::InvalidResponse);
    }

    let (_qname, qend) = decode_qname(packet, 12).map_err(|_| DnsError::InvalidResponse)?;
    let ans_start = qend.checked_add(4).ok_or(DnsError::InvalidResponse)?;
    if ans_start.checked_add(16).ok_or(DnsError::InvalidResponse)? > packet.len() {
        return Err(DnsError::InvalidResponse);
    }

    // Skip answer NAME (either compression pointer 2 bytes or uncompressed labels).
    let mut pos = ans_start;
    if (packet[pos] & 0xC0) == 0xC0 {
        pos += 2;
    } else {
        let (_, next) = decode_qname(packet, pos).map_err(|_| DnsError::InvalidResponse)?;
        pos = next;
    }

    if pos.checked_add(14).ok_or(DnsError::InvalidResponse)? > packet.len() {
        return Err(DnsError::InvalidResponse);
    }
    let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]);
    if rtype != 1 || rclass != 1 || rdlen != 4 {
        return Err(DnsError::InvalidResponse);
    }

    let rdata_start = pos + 10;
    let ipv4 = [
        packet[rdata_start],
        packet[rdata_start + 1],
        packet[rdata_start + 2],
        packet[rdata_start + 3],
    ];
    Ok((id, ipv4))
}

/// Runs the bounded, non-forwarding UDP DNS loop until `shutdown` becomes `true`.
pub fn run_dns_loop(
    socket: &UdpSocket,
    responder: &dyn DnsResponder,
    metrics: &Metrics,
    shutdown: &AtomicBool,
    rate_limiter: &mut SourceRateLimiter,
) {
    let _ = socket.set_read_timeout(Some(DNS_POLL_TIMEOUT));
    let _ = socket.set_write_timeout(Some(DNS_WRITE_TIMEOUT));

    // Allocate 1 extra byte beyond MAX_DNS_PACKET_BYTES so oversized datagrams
    // are detected and dropped instead of silently truncated.
    let mut buf = [0u8; MAX_DNS_PACKET_BYTES + 1];

    while !shutdown.load(Ordering::Acquire) {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                metrics.inc_dns_received();

                if n > MAX_DNS_PACKET_BYTES {
                    metrics.inc_dns_dropped_oversized();
                    continue;
                }

                if !rate_limiter.allow(src.ip(), Instant::now()) {
                    metrics.inc_dns_dropped_rate_limited();
                    continue;
                }

                match responder.respond(&buf[..n]) {
                    Some(reply) if reply.len() <= MAX_DNS_PACKET_BYTES => {
                        match socket.send_to(&reply, src) {
                            Ok(_) => metrics.inc_dns_answered(),
                            Err(_) => metrics.inc_dns_send_errors(),
                        }
                    }
                    _ => {
                        metrics.inc_dns_dropped_unanswered();
                    }
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => {
                metrics.inc_dns_send_errors();
            }
        }
    }
}
