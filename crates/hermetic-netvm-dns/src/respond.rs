use crate::table::DnsTable;
use crate::wire::{
    parse_query, DnsHeader, DnsResponse, Rcode, ResourceRecordA, DEFAULT_TTL_SECONDS,
    MAX_RESPONSE_ANSWERS, MAX_UDP_PAYLOAD_BYTES, QCLASS_IN, QTYPE_A, QTYPE_AAAA,
};

/// Processes a single incoming UDP DNS packet against a static [`DnsTable`].
///
/// Rules:
/// - If fewer than 12 bytes are present (header unreadable) or `QR == 1`, returns `None` (drop).
/// - Oversized (> 512 bytes) or otherwise malformed packets with a readable header return `FORMERR`
///   echoing the request `ID` and `RD`.
/// - `OPCODE != 0` returns `NOTIMP`.
/// - `QCLASS != IN` returns `REFUSED`.
/// - Known name + `QTYPE == A` returns `NOERROR` with sorted `A` records (`TTL = 300`, no other sections).
/// - Known name + `QTYPE == AAAA` or any other `QTYPE` returns `NOERROR` with empty answer section.
/// - Unknown name returns `NXDOMAIN` (`RCODE = 3`) with empty sections.
/// - Responses always set `QR = 1` and `AA = 1`, copy `RD`, never set `RA`, and never include EDNS.
pub fn respond(packet: &[u8], table: &DnsTable) -> Option<Vec<u8>> {
    let raw_header = DnsHeader::parse(packet).ok()?;

    // Never respond to DNS response packets (QR == 1).
    if raw_header.qr {
        return None;
    }

    // Refuse oversized UDP payloads (> 512 bytes) immediately before allocating or parsing body.
    if packet.len() > MAX_UDP_PAYLOAD_BYTES {
        return build_header_only_response(raw_header, Rcode::FormErr);
    }

    // Standard queries must use OPCODE == 0; any other opcode returns NOTIMP.
    if raw_header.opcode != 0 {
        return build_header_only_response(raw_header, Rcode::NotImp);
    }

    let query = match parse_query(packet) {
        Ok(q) => q,
        Err(_) => return build_header_only_response(raw_header, Rcode::FormErr),
    };

    if query.question.qclass != QCLASS_IN {
        let resp = DnsResponse {
            header: make_response_header(query.header, Rcode::Refused, 1, 0),
            question: Some(query.question),
            answers: Vec::new(),
        };
        return resp.encode().ok();
    }

    match table.lookup(&query.question.qname) {
        None => {
            let resp = DnsResponse {
                header: make_response_header(query.header, Rcode::NxDomain, 1, 0),
                question: Some(query.question),
                answers: Vec::new(),
            };
            resp.encode().ok()
        }
        Some(ips) => {
            if query.question.qtype == QTYPE_A {
                let count = ips.len().min(MAX_RESPONSE_ANSWERS);
                let limited_ips = ips.get(..count).unwrap_or(&[]);
                let answers: Vec<ResourceRecordA> = limited_ips
                    .iter()
                    .copied()
                    .map(|address| ResourceRecordA {
                        ttl: DEFAULT_TTL_SECONDS,
                        address,
                    })
                    .collect();

                let resp = DnsResponse {
                    header: make_response_header(
                        query.header,
                        Rcode::NoError,
                        1,
                        answers.len() as u16,
                    ),
                    question: Some(query.question),
                    answers,
                };
                resp.encode().ok()
            } else if query.question.qtype == QTYPE_AAAA {
                let resp = DnsResponse {
                    header: make_response_header(query.header, Rcode::NoError, 1, 0),
                    question: Some(query.question),
                    answers: Vec::new(),
                };
                resp.encode().ok()
            } else {
                let resp = DnsResponse {
                    header: make_response_header(query.header, Rcode::NoError, 1, 0),
                    question: Some(query.question),
                    answers: Vec::new(),
                };
                resp.encode().ok()
            }
        }
    }
}

fn make_response_header(req: DnsHeader, rcode: Rcode, qdcount: u16, ancount: u16) -> DnsHeader {
    DnsHeader {
        id: req.id,
        qr: true,
        opcode: req.opcode,
        aa: true,
        tc: false,
        rd: req.rd,
        ra: false,
        z: 0,
        rcode: rcode.as_u8(),
        qdcount,
        ancount,
        nscount: 0,
        arcount: 0,
    }
}

fn build_header_only_response(req: DnsHeader, rcode: Rcode) -> Option<Vec<u8>> {
    let resp = DnsResponse {
        header: make_response_header(req, rcode, 0, 0),
        question: None,
        answers: Vec::new(),
    };
    resp.encode().ok()
}
