use hermetic_escapeprobe::classify::EscapeResult;
use hermetic_escapeprobe::dns::*;
use hermetic_escapeprobe::probes::{classify_dns_exchange, DELEGATION, REAL_NAMES};
use hermetic_netvm_dns::{respond, DnsTable};

fn header(id: u16, flags3: u8, an: u16, ns: u16) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&[0x81, flags3, 0, 1]);
    p.extend_from_slice(&an.to_be_bytes());
    p.extend_from_slice(&ns.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p
}

#[test]
fn query_builder_rejects_bad_names() {
    assert!(build_query(1, "www.google.com", QTYPE_A).is_some());
    let root = build_query(1, ".", QTYPE_NS).unwrap();
    assert_eq!(root.len(), 12 + 1 + 4);
    assert!(build_query(1, "a..b", QTYPE_A).is_none());
    assert!(build_query(1, "a b", QTYPE_A).is_none());
    assert!(build_query(1, &"a".repeat(64), QTYPE_A).is_none());
    assert!(build_query(1, &"a.".repeat(130), QTYPE_A).is_none());
}

#[test]
fn response_classification_every_path() {
    assert_eq!(
        classify_response(7, &header(7, 0x80, 1, 0)).0,
        EscapeResult::Leak
    );
    assert_eq!(
        classify_response(7, &header(7, 0x80, 0, 1)).0,
        EscapeResult::Leak
    );
    assert_eq!(
        classify_response(7, &header(7, 0x83, 0, 1)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_response(7, &header(7, 0x80, 0, 0)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_response(7, &header(7, 0x82, 0, 0)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_response(7, &header(7, 0x83, 0, 0)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_response(7, &header(7, 0x85, 0, 0)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_response(7, &header(7, 0x84, 0, 0)).0,
        EscapeResult::Error
    );
    assert_eq!(
        classify_response(8, &header(7, 0x80, 1, 0)).0,
        EscapeResult::Error
    );
    let mut q = header(7, 0x80, 1, 0);
    q[2] = 0x01; // query, not a response
    assert_eq!(classify_response(7, &q).0, EscapeResult::Error);
    assert_eq!(classify_response(7, &[0; 11]).0, EscapeResult::Error);
    let mut big = header(7, 0x80, 0, 0);
    big.resize(MAX_RESPONSE_BYTES + 1, 0);
    assert_eq!(classify_response(7, &big).0, EscapeResult::Error);
    assert_eq!(classify_dns_exchange(7, Ok(None)).0, EscapeResult::Blocked);
    assert_eq!(
        classify_dns_exchange(7, Err(libc::ECONNREFUSED)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_dns_exchange(7, Err(libc::EIO)).0,
        EscapeResult::Error
    );
}

#[test]
fn netvm_table_resolver_blocks_every_real_name_and_delegation() {
    let table = DnsTable::from_json_str(
        r#"{"records":[{"name":"pypi.org","a":["10.200.0.2"],"aaaa":[]}]}"#,
    )
    .unwrap();
    for (i, (_, name, qtype)) in REAL_NAMES.iter().chain(DELEGATION).enumerate() {
        let id = 100 + i as u16;
        let q = build_query(id, name, *qtype).unwrap();
        let reply = respond(&q, &table);
        let r = classify_dns_exchange(id, Ok(reply));
        assert_eq!(r.0, EscapeResult::Blocked, "{name}");
    }
    // Sanity: the same responder does answer a world name, which would be a leak
    // if it were a real name.
    let q = build_query(9, "pypi.org", QTYPE_A).unwrap();
    let reply = respond(&q, &table).unwrap();
    assert_eq!(classify_response(9, &reply).0, EscapeResult::Leak);
}
