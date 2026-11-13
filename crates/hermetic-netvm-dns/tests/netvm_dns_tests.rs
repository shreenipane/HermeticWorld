#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use hermetic_netvm_dns::{
    respond, DnsHeader, DnsTable, TableError, MAX_DNS_NAME_LEN, MAX_TABLE_JSON_BYTES,
    MAX_TABLE_RECORDS, MAX_UDP_PAYLOAD_BYTES, QCLASS_IN, QTYPE_A, QTYPE_AAAA,
};

static TEMP_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let id = TEMP_DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("hermetic_netvm_dns_test_{tag}_{id}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        Self { path: dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sample_table() -> DnsTable {
    let json = r#"{
        "records": [
            { "name": "pypi.org", "a": ["10.200.0.2"], "aaaa": [] },
            { "name": "multi.example.org", "a": ["10.0.0.20", "10.0.0.10"], "aaaa": [] }
        ]
    }"#;
    DnsTable::from_json_str(json).expect("valid sample table")
}

/// Helper to build a standard uncompressed DNS query packet for test fixtures.
fn build_query_packet(id: u16, rd: bool, labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if rd { 0x0100 } else { 0x0000 };
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    for label in labels {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label);
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&qclass.to_be_bytes());
    pkt
}

#[test]
fn known_answer_vector_a_hit_single() {
    let table = sample_table();
    let query = build_query_packet(0x1234, true, &[b"pypi", b"org"], QTYPE_A, QCLASS_IN);

    let resp = respond(&query, &table).expect("expected response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // Header: ID=0x1234, Flags=0x8500 (QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=0, Z=0, RCODE=0)
        0x12, 0x34,
        0x85, 0x00,
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question: pypi.org, TYPE A (1), CLASS IN (1)
        0x04, b'p', b'y', b'p', b'i',
        0x03, b'o', b'r', b'g',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        // Answer: ptr 0xC00C, TYPE A (1), CLASS IN (1), TTL 300 (0x0000012C), RDLEN 4, 10.200.0.2
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04,
        10, 200, 0, 2,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_a_hit_multiple_sorted_and_rd_zero() {
    let table = sample_table();
    let query = build_query_packet(
        0xABCD,
        false,
        &[b"MULTI", b"Example", b"ORG"],
        QTYPE_A,
        QCLASS_IN,
    );

    let resp = respond(&query, &table).expect("expected response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // Header: ID=0xABCD, Flags=0x8400 (QR=1, AA=1, RD=0, RA=0, RCODE=0)
        0xAB, 0xCD,
        0x84, 0x00,
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x02, // ANCOUNT = 2
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question: multi.example.org, TYPE A, CLASS IN
        0x05, b'm', b'u', b'l', b't', b'i',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'o', b'r', b'g',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        // Answer 1 (sorted ascending): 10.0.0.10
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04,
        10, 0, 0, 10,
        // Answer 2: 10.0.0.20
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04,
        10, 0, 0, 20,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_aaaa_known_name() {
    let table = sample_table();
    let query = build_query_packet(0x2222, true, &[b"pypi", b"org"], QTYPE_AAAA, QCLASS_IN);

    let resp = respond(&query, &table).expect("expected response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // Header: ID=0x2222, Flags=0x8500 (QR=1, AA=1, RD=1, RA=0, RCODE=0 NOERROR)
        0x22, 0x22,
        0x85, 0x00,
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question: pypi.org, TYPE AAAA (28), CLASS IN (1)
        0x04, b'p', b'y', b'p', b'i',
        0x03, b'o', b'r', b'g',
        0x00,
        0x00, 0x1C,
        0x00, 0x01,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_other_qtype_known_name() {
    let table = sample_table();
    // QTYPE = 16 (TXT) for known name pypi.org -> NOERROR with empty answer
    let query = build_query_packet(0x3333, false, &[b"pypi", b"org"], 16, QCLASS_IN);

    let resp = respond(&query, &table).expect("expected response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0x33, 0x33,
        0x84, 0x00, // QR=1, AA=1, RD=0, RA=0, RCODE=0 (NOERROR)
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x04, b'p', b'y', b'p', b'i',
        0x03, b'o', b'r', b'g',
        0x00,
        0x00, 0x10,
        0x00, 0x01,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_nxdomain() {
    let table = sample_table();
    let query = build_query_packet(0x4444, true, &[b"evil", b"com"], QTYPE_A, QCLASS_IN);

    let resp = respond(&query, &table).expect("expected response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // Header: ID=0x4444, Flags=0x8503 (QR=1, AA=1, RD=1, RA=0, RCODE=3 NXDOMAIN)
        0x44, 0x44,
        0x85, 0x03,
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question: evil.com, TYPE A, CLASS IN
        0x04, b'e', b'v', b'i', b'l',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_notimp() {
    let table = sample_table();
    // OPCODE = 2 (STATUS, bits 14..11 = 0010 -> 0x1000), RD = 1 -> flags = 0x1100
    #[rustfmt::skip]
    let query: Vec<u8> = vec![
        0x55, 0x55,
        0x11, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ];

    let resp = respond(&query, &table).expect("expected NOTIMP response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // QR=1 (0x8000) | OPCODE=2 (0x1000) | AA=1 (0x0400) | RD=1 (0x0100) | RCODE=4 (0x0004) = 0x9504
        0x55, 0x55,
        0x95, 0x04,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_refused_non_in_class() {
    let table = sample_table();
    // QCLASS = 3 (CH / Chaos) even for a known name
    let query = build_query_packet(0x6666, true, &[b"pypi", b"org"], QTYPE_A, 3);

    let resp = respond(&query, &table).expect("expected REFUSED response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // Header: ID=0x6666, Flags=0x8505 (QR=1, AA=1, RD=1, RA=0, RCODE=5 REFUSED)
        0x66, 0x66,
        0x85, 0x05,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        // Question: pypi.org, TYPE A, CLASS CH (3)
        0x04, b'p', b'y', b'p', b'i',
        0x03, b'o', b'r', b'g',
        0x00,
        0x00, 0x01,
        0x00, 0x03,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn known_answer_vector_formerr_and_short_drop() {
    let table = sample_table();

    // Packet shorter than 12 bytes -> dropped (None)
    assert_eq!(respond(&[0x77, 0x77, 0x01, 0x00, 0x00], &table), None);
    assert_eq!(respond(&[], &table), None);

    // Response packet (QR = 1) -> dropped (None)
    let qr1_pkt = [0x77, 0x77, 0x81, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(respond(&qr1_pkt, &table), None);

    // Malformed packet with compression pointer in QUESTION -> FORMERR echoing ID 0x7777
    #[rustfmt::skip]
    let compressed_q: Vec<u8> = vec![
        0x77, 0x77,
        0x01, 0x00, // QR=0, OPCODE=0, RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xC0, 0x0C, // compression pointer in question -> forbidden
        0x00, 0x01,
        0x00, 0x01,
    ];

    let resp = respond(&compressed_q, &table).expect("expected FORMERR response");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        // ID=0x7777, QR=1, AA=1, RD=1, RA=0, RCODE=1 (FORMERR) -> 0x8501
        0x77, 0x77,
        0x85, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ];

    assert_eq!(resp, expected);
}

#[test]
fn wire_parser_rejects_bad_counts_trailing_and_oversized_packets() {
    let table = sample_table();

    // QDCOUNT = 0 -> FORMERR
    let qd0 = [0x11, 0x11, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    let r0 = DnsHeader::parse(&respond(&qd0, &table).unwrap()).unwrap();
    assert_eq!(r0.rcode, 1);
    assert_eq!(r0.id, 0x1111);

    // QDCOUNT = 2 -> FORMERR
    let mut qd2 = build_query_packet(0x1112, true, &[b"pypi", b"org"], QTYPE_A, QCLASS_IN);
    qd2[5] = 2;
    let r2 = DnsHeader::parse(&respond(&qd2, &table).unwrap()).unwrap();
    assert_eq!(r2.rcode, 1);

    // ARCOUNT = 1 (e.g. EDNS OPT record) -> FORMERR and response never includes EDNS
    let mut ar1 = build_query_packet(0x1113, true, &[b"pypi", b"org"], QTYPE_A, QCLASS_IN);
    ar1[11] = 1;
    ar1.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let r_ar = DnsHeader::parse(&respond(&ar1, &table).unwrap()).unwrap();
    assert_eq!(r_ar.rcode, 1);
    assert_eq!(r_ar.arcount, 0);

    // Trailing byte after valid question -> FORMERR
    let mut trailing = build_query_packet(0x1114, false, &[b"pypi", b"org"], QTYPE_A, QCLASS_IN);
    trailing.push(0x00);
    let r_trail = DnsHeader::parse(&respond(&trailing, &table).unwrap()).unwrap();
    assert_eq!(r_trail.rcode, 1);

    // Oversized packet (513 bytes) -> FORMERR echoing ID without over-allocating
    let mut oversized = vec![0u8; MAX_UDP_PAYLOAD_BYTES + 1];
    oversized[0] = 0x99;
    oversized[1] = 0x88;
    oversized[2] = 0x01; // RD=1
    let r_over = respond(&oversized, &table).unwrap();
    assert_eq!(r_over.len(), 12);
    let h_over = DnsHeader::parse(&r_over).unwrap();
    assert_eq!(h_over.id, 0x9988);
    assert_eq!(h_over.rcode, 1);
    assert!(h_over.aa);
    assert!(h_over.rd);
    assert!(!h_over.ra);
}

#[test]
fn table_validation_all_rules() {
    // 1. Size cap 1 MiB
    let huge = vec![b' '; MAX_TABLE_JSON_BYTES + 1];
    assert!(matches!(
        DnsTable::from_json_bytes(&huge),
        Err(TableError::InputTooLarge { .. })
    ));

    // 2. Deny unknown fields (top-level and per-record)
    let unknown_top = r#"{"records": [], "extra_field": 123}"#;
    assert!(matches!(
        DnsTable::from_json_str(unknown_top),
        Err(TableError::JsonParse(_))
    ));
    let unknown_rec =
        r#"{"records": [{"name": "pypi.org", "a": ["10.0.0.1"], "aaaa": [], "ttl": 300}]}"#;
    assert!(matches!(
        DnsTable::from_json_str(unknown_rec),
        Err(TableError::JsonParse(_))
    ));

    // 3. Max 4096 names (4096 succeeds, 4097 fails)
    let mut records_4096 = Vec::with_capacity(MAX_TABLE_RECORDS);
    for i in 0..MAX_TABLE_RECORDS {
        records_4096.push(format!(
            r#"{{"name":"h{i}.example.org","a":["10.0.0.1"],"aaaa":[]}}"#
        ));
    }
    let json_4096 = format!(r#"{{"records":[{}]}}"#, records_4096.join(","));
    let tbl_4096 = DnsTable::from_json_str(&json_4096).expect("4096 records should succeed");
    assert_eq!(tbl_4096.len(), MAX_TABLE_RECORDS);

    let json_4097 = format!(
        r#"{{"records":[{},{{"name":"overflow.example.org","a":["10.0.0.1"],"aaaa":[]}}]}}"#,
        records_4096.join(",")
    );
    assert!(matches!(
        DnsTable::from_json_str(&json_4097),
        Err(TableError::TooManyRecords { count: 4097, .. })
    ));

    // 4. Name validation: uppercase, wildcards, hyphens at start/end, label > 63, name > 253, duplicates
    let invalid_names = [
        "PYPI.ORG",
        "pypi.Org",
        "*.pypi.org",
        "*",
        "-leading.org",
        "trailing-.org",
        "bad_char.org",
        "space char.org",
        "double..dot.org",
        ".leadingdot.org",
        "trailingdot.org.",
        "",
    ];
    for bad in invalid_names {
        let j = format!(r#"{{"records":[{{"name":"{bad}","a":["10.0.0.1"],"aaaa":[]}}]}}"#);
        assert!(
            matches!(DnsTable::from_json_str(&j), Err(TableError::InvalidName(_))),
            "expected InvalidName for {bad:?}"
        );
    }

    // Label length 63 succeeds, 64 fails
    let label_63 = "a".repeat(63);
    let ok_63 =
        format!(r#"{{"records":[{{"name":"{label_63}.org","a":["10.0.0.1"],"aaaa":[]}}]}}"#);
    assert!(DnsTable::from_json_str(&ok_63).is_ok());

    let label_64 = "a".repeat(64);
    let bad_64 =
        format!(r#"{{"records":[{{"name":"{label_64}.org","a":["10.0.0.1"],"aaaa":[]}}]}}"#);
    assert!(matches!(
        DnsTable::from_json_str(&bad_64),
        Err(TableError::InvalidName(_))
    ));

    // Total name length 253 succeeds, 254 fails
    // 61 + 1 + 63 + 1 + 63 + 1 + 63 = 253
    let name_253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(61),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63)
    );
    assert_eq!(name_253.len(), MAX_DNS_NAME_LEN);
    let ok_253 = format!(r#"{{"records":[{{"name":"{name_253}","a":["10.0.0.1"],"aaaa":[]}}]}}"#);
    assert!(DnsTable::from_json_str(&ok_253).is_ok());

    let name_254 = format!(
        "{}.{}.{}.{}",
        "a".repeat(62),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63)
    );
    assert_eq!(name_254.len(), MAX_DNS_NAME_LEN + 1);
    let bad_254 = format!(r#"{{"records":[{{"name":"{name_254}","a":["10.0.0.1"],"aaaa":[]}}]}}"#);
    assert!(matches!(
        DnsTable::from_json_str(&bad_254),
        Err(TableError::InvalidName(_))
    ));

    // Duplicate names rejected
    let dup_json = r#"{
        "records": [
            { "name": "pypi.org", "a": ["10.0.0.1"], "aaaa": [] },
            { "name": "pypi.org", "a": ["10.0.0.2"], "aaaa": [] }
        ]
    }"#;
    assert!(matches!(
        DnsTable::from_json_str(dup_json),
        Err(TableError::DuplicateName(_))
    ));

    // 5. IPv4 must be in 10.0.0.0/8
    for non_world_ip in [
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "8.8.8.8",
        "11.0.0.1",
        "9.255.255.255",
    ] {
        let j =
            format!(r#"{{"records":[{{"name":"pypi.org","a":["{non_world_ip}"],"aaaa":[]}}]}}"#);
        assert!(
            matches!(
                DnsTable::from_json_str(&j),
                Err(TableError::AddressOutOfWorldRange { .. })
            ),
            "expected AddressOutOfWorldRange for {non_world_ip}"
        );
    }

    // 6. AAAA list must be empty
    let non_empty_aaaa = r#"{
        "records": [
            { "name": "pypi.org", "a": ["10.0.0.1"], "aaaa": ["fd00::1"] }
        ]
    }"#;
    assert!(matches!(
        DnsTable::from_json_str(non_empty_aaaa),
        Err(TableError::NonEmptyAaaa { .. })
    ));
}

#[test]
fn lookup_case_insensitive_and_ignores_one_trailing_dot() {
    let table = sample_table();
    let expected = [std::net::Ipv4Addr::new(10, 200, 0, 2)];

    assert_eq!(table.lookup("pypi.org"), Some(expected.as_slice()));
    assert_eq!(table.lookup("PYPI.ORG"), Some(expected.as_slice()));
    assert_eq!(table.lookup("PyPi.OrG."), Some(expected.as_slice()));
    // Two trailing dots are NOT ignored
    assert_eq!(table.lookup("pypi.org.."), None);
    assert_eq!(table.lookup(""), None);
    assert_eq!(table.lookup("."), None);
}

#[test]
fn file_loading_refuses_symlinks_and_atomic_write_works() {
    let tmp = TempDir::new("file_ops");
    let table = sample_table();
    let target = tmp.path.join("manifest.json");

    table.write_atomic(&target).expect("atomic write succeeds");
    let reloaded = DnsTable::from_file(&target).expect("regular file load succeeds");
    assert_eq!(reloaded, table);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link_path = tmp.path.join("manifest_link.json");
        symlink(&target, &link_path).expect("create symlink");
        assert!(matches!(
            DnsTable::from_file(&link_path),
            Err(TableError::SymlinkNotAllowed)
        ));
        assert!(matches!(
            table.write_atomic(&link_path),
            Err(TableError::SymlinkNotAllowed)
        ));
    }
}

#[test]
fn deterministic_output_across_input_orderings() {
    let json_a = r#"{
        "records": [
            { "name": "b.example.org", "a": ["10.0.0.2"], "aaaa": [] },
            { "name": "a.example.org", "a": ["10.0.0.9", "10.0.0.1"], "aaaa": [] }
        ]
    }"#;
    let json_b = r#"{
        "records": [
            { "name": "a.example.org", "a": ["10.0.0.1", "10.0.0.9"], "aaaa": [] },
            { "name": "b.example.org", "a": ["10.0.0.2"], "aaaa": [] }
        ]
    }"#;

    let t1 = DnsTable::from_json_str(json_a).unwrap();
    let t2 = DnsTable::from_json_str(json_b).unwrap();
    let q = build_query_packet(
        0xBEEF,
        true,
        &[b"a", b"example", b"org"],
        QTYPE_A,
        QCLASS_IN,
    );

    assert_eq!(respond(&q, &t1), respond(&q, &t2));
}

#[test]
fn truncation_at_every_offset_never_panics() {
    let table = sample_table();
    let valid_query = build_query_packet(0xCAFE, true, &[b"pypi", b"org"], QTYPE_A, QCLASS_IN);

    for cut in 0..=valid_query.len() {
        let slice = &valid_query[..cut];
        let out = respond(slice, &table);
        if cut < 12 {
            assert_eq!(out, None, "offset {cut} < 12 should drop");
        } else if cut < valid_query.len() {
            let resp = out.expect("offset >= 12 should return FORMERR");
            assert!(resp.len() <= MAX_UDP_PAYLOAD_BYTES);
            let hdr = DnsHeader::parse(&resp).expect("valid response header");
            assert_eq!(hdr.id, 0xCAFE);
            assert_eq!(hdr.rcode, 1); // FORMERR
            assert!(hdr.qr);
            assert!(hdr.aa);
            assert!(hdr.rd);
            assert!(!hdr.ra);
            assert_eq!(hdr.arcount, 0);
        } else {
            let resp = out.expect("full query should succeed");
            let hdr = DnsHeader::parse(&resp).expect("valid response header");
            assert_eq!(hdr.id, 0xCAFE);
            assert_eq!(hdr.rcode, 0); // NOERROR
            assert_eq!(hdr.ancount, 1);
        }
    }
}

/// Hand-written deterministic Xorshift64 PRNG for offline fuzz testing.
struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        (self.next_u64() as usize) % upper_exclusive
    }
}

#[test]
fn fuzz_100000_xorshift_packets_never_panic_and_respect_bounds() {
    let table = sample_table();
    let base_query = build_query_packet(0x4242, true, &[b"pypi", b"org"], QTYPE_A, QCLASS_IN);
    let mut rng = Xorshift64::new(0xDEAD_BEEF_CAFE_BABE);
    let mut buf = Vec::with_capacity(600);

    for i in 0..100_000usize {
        buf.clear();

        if i % 4 == 0 {
            // Mutate a valid query to exercise deep parser branches
            buf.extend_from_slice(&base_query);
            let mutations = 1 + rng.next_usize(4);
            for _ in 0..mutations {
                let idx = rng.next_usize(buf.len());
                buf[idx] ^= (rng.next_u64() & 0xFF) as u8;
            }
        } else {
            // Pure pseudo-random packet of length 0..=600
            let len = rng.next_usize(601);
            let mut produced = 0;
            while produced < len {
                let word = rng.next_u64().to_le_bytes();
                let take = (len - produced).min(8);
                buf.extend_from_slice(&word[..take]);
                produced += take;
            }
        }

        let resp_opt = respond(&buf, &table);
        // Determinism check on every 100th packet
        if i % 100 == 0 {
            assert_eq!(resp_opt, respond(&buf, &table));
        }

        if let Some(resp) = resp_opt {
            assert!(resp.len() >= 12);
            assert!(resp.len() <= MAX_UDP_PAYLOAD_BYTES);

            let in_hdr = DnsHeader::parse(&buf).expect("input had readable header");
            let out_hdr = DnsHeader::parse(&resp).expect("output has valid header");

            assert_eq!(out_hdr.id, in_hdr.id);
            assert!(out_hdr.qr);
            assert!(out_hdr.aa);
            assert!(!out_hdr.ra);
            assert_eq!(out_hdr.rd, in_hdr.rd);
            assert_eq!(out_hdr.nscount, 0);
            assert_eq!(out_hdr.arcount, 0);
        }
    }
}
