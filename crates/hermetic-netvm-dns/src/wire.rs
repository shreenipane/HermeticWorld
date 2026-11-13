use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

use crate::table::{MAX_DNS_LABELS, MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN};

/// Maximum DNS UDP payload size without EDNS0 (RFC 1035 Section 4.2.1).
pub const MAX_UDP_PAYLOAD_BYTES: usize = 512;
/// Fixed DNS header size in bytes (RFC 1035 Section 4.1.1).
pub const DNS_HEADER_LEN: usize = 12;
/// Maximum wire length of an uncompressed domain name including length octets and root null.
pub const MAX_WIRE_NAME_LEN: usize = 255;
/// Maximum number of answer records permitted in an encoded response.
pub const MAX_RESPONSE_ANSWERS: usize = 15;
/// Fixed TTL (in seconds) emitted on all positive A answers.
pub const DEFAULT_TTL_SECONDS: u32 = 300;

/// DNS Resource Record / Query Type `A` (host IPv4 address).
pub const QTYPE_A: u16 = 1;
/// DNS Resource Record / Query Type `AAAA` (host IPv6 address).
pub const QTYPE_AAAA: u16 = 28;
/// DNS Class `IN` (Internet).
pub const QCLASS_IN: u16 = 1;

/// High two bits indicating a DNS message compression pointer (`11xxxxxx`).
const COMPRESSION_POINTER_TAG: u8 = 0xC0;
/// Mask for the top two label-type bits in a DNS label length octet.
const LABEL_TYPE_MASK: u8 = 0xC0;
/// Compression pointer `0xC00C` referencing offset 12 (the Question QNAME).
const QNAME_OFFSET_PTR: u16 = 0xC00C;
/// RDLENGTH of an IPv4 A record in bytes.
const A_RDATA_LEN: u16 = 4;
/// Total encoded byte size of a compressed A resource record (`2 + 2 + 2 + 4 + 2 + 4`).
const A_RR_WIRE_LEN: usize = 16;

/// DNS Response Codes (RFC 1035 Section 4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl Rcode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Typed errors produced by strict DNS wire parsing and encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    PacketTooShort {
        len: usize,
    },
    PacketTooLong {
        len: usize,
        max: usize,
    },
    UnexpectedResponsePacket,
    InvalidQueryFlags,
    InvalidResponseStructure,
    TruncatedQuery,
    UnsupportedOpcode {
        opcode: u8,
    },
    InvalidQuestionCount {
        qdcount: u16,
    },
    NonEmptyQuerySections {
        ancount: u16,
        nscount: u16,
        arcount: u16,
    },
    CompressionPointerInQuestion,
    InvalidLabelType {
        tag: u8,
    },
    LabelTooLong {
        len: usize,
        max: usize,
    },
    NameTooLong {
        wire_len: usize,
        max: usize,
    },
    TooManyLabels {
        count: usize,
        max: usize,
    },
    InvalidLabelByte {
        byte: u8,
    },
    TruncatedName,
    TruncatedQuestion,
    TrailingData {
        extra_bytes: usize,
    },
    TooManyAnswers {
        count: usize,
        max: usize,
    },
    ResponseTooLarge {
        len: usize,
        max: usize,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::PacketTooShort { len } => {
                write!(f, "DNS packet too short for header ({len} < {DNS_HEADER_LEN})")
            }
            WireError::PacketTooLong { len, max } => {
                write!(f, "DNS UDP packet length {len} exceeds maximum {max}")
            }
            WireError::InvalidQueryFlags => write!(f, "unsupported DNS query flags"),
            WireError::InvalidResponseStructure => write!(f, "inconsistent DNS response sections"),
            WireError::UnexpectedResponsePacket => {
                write!(f, "received DNS packet with QR=1 (response) instead of QR=0 (query)")
            }
            WireError::TruncatedQuery => write!(f, "received DNS query with TC=1"),
            WireError::UnsupportedOpcode { opcode } => {
                write!(f, "unsupported DNS opcode {opcode}")
            }
            WireError::InvalidQuestionCount { qdcount } => {
                write!(f, "expected exactly 1 question, got QDCOUNT={qdcount}")
            }
            WireError::NonEmptyQuerySections {
                ancount,
                nscount,
                arcount,
            } => write!(
                f,
                "expected empty non-question sections in query, got AN={ancount} NS={nscount} AR={arcount}"
            ),
            WireError::CompressionPointerInQuestion => {
                write!(f, "compression pointers are forbidden in the DNS question section")
            }
            WireError::InvalidLabelType { tag } => {
                write!(f, "invalid DNS label type bits 0x{tag:02X}")
            }
            WireError::LabelTooLong { len, max } => {
                write!(f, "DNS label length {len} exceeds cap {max}")
            }
            WireError::NameTooLong { wire_len, max } => {
                write!(f, "DNS wire name length {wire_len} exceeds cap {max}")
            }
            WireError::TooManyLabels { count, max } => {
                write!(f, "DNS label count {count} exceeds cap {max}")
            }
            WireError::InvalidLabelByte { byte } => {
                write!(f, "invalid DNS label byte 0x{byte:02X}")
            }
            WireError::TruncatedName => write!(f, "truncated domain name in DNS packet"),
            WireError::TruncatedQuestion => write!(f, "truncated question tail in DNS packet"),
            WireError::TrailingData { extra_bytes } => {
                write!(f, "trailing data ({extra_bytes} bytes) after DNS question")
            }
            WireError::TooManyAnswers { count, max } => {
                write!(f, "response answer count {count} exceeds cap {max}")
            }
            WireError::ResponseTooLarge { len, max } => {
                write!(f, "encoded DNS response length {len} exceeds cap {max}")
            }
        }
    }
}

impl Error for WireError {}

/// Parsed 12-byte DNS message header (RFC 1035 Section 4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    /// Parses the 12-byte DNS header from the front of `packet`.
    pub fn parse(packet: &[u8]) -> Result<Self, WireError> {
        let hdr = packet
            .get(..DNS_HEADER_LEN)
            .ok_or(WireError::PacketTooShort { len: packet.len() })?;

        let id = u16::from_be_bytes([hdr[0], hdr[1]]);
        let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
        let qdcount = u16::from_be_bytes([hdr[4], hdr[5]]);
        let ancount = u16::from_be_bytes([hdr[6], hdr[7]]);
        let nscount = u16::from_be_bytes([hdr[8], hdr[9]]);
        let arcount = u16::from_be_bytes([hdr[10], hdr[11]]);

        Ok(Self {
            id,
            qr: (flags & 0x8000) != 0,
            opcode: ((flags >> 11) & 0x000F) as u8,
            aa: (flags & 0x0400) != 0,
            tc: (flags & 0x0200) != 0,
            rd: (flags & 0x0100) != 0,
            ra: (flags & 0x0080) != 0,
            z: ((flags >> 4) & 0x0007) as u8,
            rcode: (flags & 0x000F) as u8,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    /// Encodes the 12-byte DNS header into `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut flags: u16 = 0;
        if self.qr {
            flags |= 0x8000;
        }
        flags |= (u16::from(self.opcode) & 0x000F) << 11;
        if self.aa {
            flags |= 0x0400;
        }
        if self.tc {
            flags |= 0x0200;
        }
        if self.rd {
            flags |= 0x0100;
        }
        if self.ra {
            flags |= 0x0080;
        }
        flags |= (u16::from(self.z) & 0x0007) << 4;
        flags |= u16::from(self.rcode) & 0x000F;

        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&self.qdcount.to_be_bytes());
        out.extend_from_slice(&self.ancount.to_be_bytes());
        out.extend_from_slice(&self.nscount.to_be_bytes());
        out.extend_from_slice(&self.arcount.to_be_bytes());
    }
}

/// Parsed DNS Question entry (RFC 1035 Section 4.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Canonical lower-case ASCII domain name without trailing dot (empty string for root `.`).
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Parsed DNS standard query with header and single question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub header: DnsHeader,
    pub question: DnsQuestion,
}

/// IPv4 `A` Resource Record for the Answer section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRecordA {
    pub ttl: u32,
    pub address: Ipv4Addr,
}

/// Outgoing DNS response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub header: DnsHeader,
    pub question: Option<DnsQuestion>,
    pub answers: Vec<ResourceRecordA>,
}

impl DnsResponse {
    /// Encodes the response into wire format, guaranteeing the output is at most
    /// [`MAX_UDP_PAYLOAD_BYTES`] (512 bytes).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.answers.len() > MAX_RESPONSE_ANSWERS {
            return Err(WireError::TooManyAnswers {
                count: self.answers.len(),
                max: MAX_RESPONSE_ANSWERS,
            });
        }

        let expected_qd = u16::from(self.question.is_some());
        if self.header.qdcount != expected_qd {
            return Err(WireError::InvalidQuestionCount {
                qdcount: self.header.qdcount,
            });
        }

        if self.header.ancount as usize != self.answers.len()
            || self.header.nscount != 0
            || self.header.arcount != 0
            || (!self.answers.is_empty() && self.question.is_none())
            || !self.header.qr
        {
            return Err(WireError::InvalidResponseStructure);
        }
        let mut out = Vec::with_capacity(MAX_UDP_PAYLOAD_BYTES);
        self.header.encode_into(&mut out);

        if let Some(ref q) = self.question {
            encode_wire_name(&q.qname, &mut out)?;
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }

        for ans in &self.answers {
            if out.len() + A_RR_WIRE_LEN > MAX_UDP_PAYLOAD_BYTES {
                return Err(WireError::ResponseTooLarge {
                    len: out.len() + A_RR_WIRE_LEN,
                    max: MAX_UDP_PAYLOAD_BYTES,
                });
            }
            out.extend_from_slice(&QNAME_OFFSET_PTR.to_be_bytes());
            out.extend_from_slice(&QTYPE_A.to_be_bytes());
            out.extend_from_slice(&QCLASS_IN.to_be_bytes());
            out.extend_from_slice(&ans.ttl.to_be_bytes());
            out.extend_from_slice(&A_RDATA_LEN.to_be_bytes());
            out.extend_from_slice(&ans.address.octets());
        }

        if out.len() > MAX_UDP_PAYLOAD_BYTES {
            return Err(WireError::ResponseTooLarge {
                len: out.len(),
                max: MAX_UDP_PAYLOAD_BYTES,
            });
        }

        Ok(out)
    }
}

/// Strictly parses a DNS UDP query payload up to [`MAX_UDP_PAYLOAD_BYTES`] (512 bytes).
///
/// Enforces:
/// - Packet length `12..=512`
/// - `QR == 0`, `TC == 0`, `OPCODE == 0`
/// - `QDCOUNT == 1`, `ANCOUNT == 0`, `NSCOUNT == 0`, `ARCOUNT == 0`
/// - No compression pointers in Question
/// - Label length `1..=63`, total wire name `<= 255`
/// - No truncated or trailing data
pub fn parse_query(packet: &[u8]) -> Result<DnsQuery, WireError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(WireError::PacketTooShort { len: packet.len() });
    }
    if packet.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(WireError::PacketTooLong {
            len: packet.len(),
            max: MAX_UDP_PAYLOAD_BYTES,
        });
    }

    let header = DnsHeader::parse(packet)?;
    if header.qr {
        return Err(WireError::UnexpectedResponsePacket);
    }
    // This responder supports standard queries with only RD set. DNSSEC and
    // response-only flags are unsupported; in particular the reserved Z bit is zero.
    if header.z != 0 || header.aa || header.ra || header.rcode != 0 {
        return Err(WireError::InvalidQueryFlags);
    }
    if header.tc {
        return Err(WireError::TruncatedQuery);
    }
    if header.opcode != 0 {
        return Err(WireError::UnsupportedOpcode {
            opcode: header.opcode,
        });
    }
    if header.qdcount != 1 {
        return Err(WireError::InvalidQuestionCount {
            qdcount: header.qdcount,
        });
    }
    if header.ancount != 0 || header.nscount != 0 || header.arcount != 0 {
        return Err(WireError::NonEmptyQuerySections {
            ancount: header.ancount,
            nscount: header.nscount,
            arcount: header.arcount,
        });
    }

    let (question, end_offset) = parse_question(packet, DNS_HEADER_LEN)?;
    if end_offset != packet.len() {
        return Err(WireError::TrailingData {
            extra_bytes: packet.len() - end_offset,
        });
    }

    Ok(DnsQuery { header, question })
}

/// Parses a single uncompressed DNS Question starting at `offset` in `packet`.
pub fn parse_question(packet: &[u8], offset: usize) -> Result<(DnsQuestion, usize), WireError> {
    let mut pos = offset;
    let mut name_buf = [0u8; MAX_DNS_NAME_LEN];
    let mut name_len: usize = 0;
    let mut wire_len: usize = 0;
    let mut label_count: usize = 0;

    let max_iterations = MAX_DNS_LABELS + 1;
    let mut finished_name = false;

    for _ in 0..max_iterations {
        let len_octet = *packet.get(pos).ok_or(WireError::TruncatedName)?;
        pos += 1;
        wire_len += 1;

        let tag = len_octet & LABEL_TYPE_MASK;
        if tag == COMPRESSION_POINTER_TAG {
            return Err(WireError::CompressionPointerInQuestion);
        }
        if tag != 0 {
            return Err(WireError::InvalidLabelType { tag });
        }

        let label_len = len_octet as usize;
        if label_len == 0 {
            finished_name = true;
            break;
        }

        label_count += 1;
        if label_count > MAX_DNS_LABELS {
            return Err(WireError::TooManyLabels {
                count: label_count,
                max: MAX_DNS_LABELS,
            });
        }
        if label_len > MAX_DNS_LABEL_LEN {
            return Err(WireError::LabelTooLong {
                len: label_len,
                max: MAX_DNS_LABEL_LEN,
            });
        }

        wire_len += label_len;
        if wire_len > MAX_WIRE_NAME_LEN {
            return Err(WireError::NameTooLong {
                wire_len,
                max: MAX_WIRE_NAME_LEN,
            });
        }

        let label_end = pos.saturating_add(label_len);
        let label = packet.get(pos..label_end).ok_or(WireError::TruncatedName)?;
        pos = label_end;

        if name_len > 0 {
            let dot_slot = name_buf.get_mut(name_len).ok_or(WireError::NameTooLong {
                wire_len,
                max: MAX_WIRE_NAME_LEN,
            })?;
            *dot_slot = b'.';
            name_len += 1;
        }

        for &b in label {
            if !(0x21..=0x7E).contains(&b) || b == b'.' {
                return Err(WireError::InvalidLabelByte { byte: b });
            }
            let slot = name_buf.get_mut(name_len).ok_or(WireError::NameTooLong {
                wire_len,
                max: MAX_WIRE_NAME_LEN,
            })?;
            *slot = b.to_ascii_lowercase();
            name_len += 1;
        }
    }

    if !finished_name {
        return Err(WireError::TooManyLabels {
            count: label_count,
            max: MAX_DNS_LABELS,
        });
    }

    let tail = packet
        .get(pos..pos + 4)
        .ok_or(WireError::TruncatedQuestion)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    pos += 4;

    let slice = name_buf.get(..name_len).ok_or(WireError::NameTooLong {
        wire_len,
        max: MAX_WIRE_NAME_LEN,
    })?;
    let qname = std::str::from_utf8(slice)
        .map_err(|_| WireError::InvalidLabelByte { byte: 0 })?
        .to_string();

    Ok((
        DnsQuestion {
            qname,
            qtype,
            qclass,
        },
        pos,
    ))
}

/// Encodes a lower-case DNS name (without trailing dot, or `""` for root `.`) into wire labels.
pub fn encode_wire_name(name: &str, out: &mut Vec<u8>) -> Result<(), WireError> {
    if name.is_empty() {
        if out.len() + 1 > MAX_UDP_PAYLOAD_BYTES {
            return Err(WireError::ResponseTooLarge {
                len: out.len() + 1,
                max: MAX_UDP_PAYLOAD_BYTES,
            });
        }
        out.push(0);
        return Ok(());
    }

    if name.len() > MAX_DNS_NAME_LEN {
        return Err(WireError::NameTooLong {
            wire_len: name.len() + 2,
            max: MAX_WIRE_NAME_LEN,
        });
    }

    let mut label_count: usize = 0;
    let mut wire_len: usize = 0;

    for label in name.split('.') {
        label_count += 1;
        if label_count > MAX_DNS_LABELS {
            return Err(WireError::TooManyLabels {
                count: label_count,
                max: MAX_DNS_LABELS,
            });
        }
        let len = label.len();
        if len == 0 || len > MAX_DNS_LABEL_LEN {
            return Err(WireError::LabelTooLong {
                len,
                max: MAX_DNS_LABEL_LEN,
            });
        }
        wire_len += 1 + len;
        if wire_len + 1 > MAX_WIRE_NAME_LEN {
            return Err(WireError::NameTooLong {
                wire_len: wire_len + 1,
                max: MAX_WIRE_NAME_LEN,
            });
        }
        if out.len() + 1 + len + 1 > MAX_UDP_PAYLOAD_BYTES {
            return Err(WireError::ResponseTooLarge {
                len: out.len() + 1 + len + 1,
                max: MAX_UDP_PAYLOAD_BYTES,
            });
        }
        out.push(len as u8);
        for &b in label.as_bytes() {
            if !(0x21..=0x7E).contains(&b) || b == b'.' {
                return Err(WireError::InvalidLabelByte { byte: b });
            }
            out.push(b.to_ascii_lowercase());
        }
    }

    out.push(0);
    Ok(())
}
