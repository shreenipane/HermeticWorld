//! Regressions for strict section validation and private descriptor-anchored I/O.

use hermetic_netvm_dns::{respond, DnsHeader, DnsQuestion, DnsResponse, DnsTable, ResourceRecordA};
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dns-review-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn query() -> Vec<u8> {
    vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ]
}

#[test]
fn reserved_and_unsupported_query_flags_are_formerr() {
    let table = DnsTable::empty();
    for flag in [0x0040u16, 0x0020, 0x0010, 0x0080, 0x0400, 0x0001] {
        let mut packet = query();
        let bytes = (0x0100 | flag).to_be_bytes();
        packet[2..4].copy_from_slice(&bytes);
        let answer = respond(&packet, &table).unwrap();
        assert_eq!(DnsHeader::parse(&answer).unwrap().rcode, 1);
    }
}

#[test]
fn inconsistent_response_sections_are_rejected() {
    let mut header = DnsHeader::parse(&query()).unwrap();
    header.qr = true;
    let question = DnsQuestion {
        qname: "a".into(),
        qtype: 1,
        qclass: 1,
    };
    let answer = ResourceRecordA {
        ttl: 300,
        address: Ipv4Addr::new(10, 0, 0, 1),
    };
    let base = DnsResponse {
        header,
        question: Some(question),
        answers: vec![answer],
    };
    assert!(base.encode().is_err()); // ANCOUNT=0 with one answer
    let mut response = base.clone();
    response.header.ancount = 1;
    assert!(response.encode().is_ok());
    response.header.nscount = 1;
    assert!(response.encode().is_err());
    response.header.nscount = 0;
    response.header.arcount = 1;
    assert!(response.encode().is_err());
    response.header.arcount = 0;
    response.question = None;
    response.header.qdcount = 0;
    assert!(response.encode().is_err());
}

#[test]
fn diagnostics_do_not_retain_rejected_secrets() {
    for json in [
        r#"{"TOKEN_SENTINEL":[],"records":[]}"#,
        r#"{"records":[{"name":"TOKEN_SENTINEL","a":[]}]}"#,
        r#"{"records":[{"name":"a","a":["TOKEN_SENTINEL"]}]}"#,
    ] {
        let error = DnsTable::from_json_str(json).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("TOKEN_SENTINEL"));
    }
}

#[test]
fn ancestors_are_never_followed_for_reads_or_writes() {
    let scratch = Scratch::new();
    let outside = scratch.0.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("input"), br#"{"records":[]}"#).unwrap();
    let mut root = scratch.0.join("root");
    fs::create_dir(&root).unwrap();
    for index in 0..3 {
        let link = root.join("link");
        symlink(&outside, &link).unwrap();
        assert!(DnsTable::from_file(&link.join("input")).is_err());
        assert!(DnsTable::empty()
            .write_atomic(&link.join("output"))
            .is_err());
        assert!(!outside.join("output").exists());
        root = root.join(index.to_string());
        fs::create_dir(&root).unwrap();
    }
}

#[test]
fn atomic_dns_output_is_private_and_durable() {
    let scratch = Scratch::new();
    let output = scratch.0.join("output");
    DnsTable::empty().write_atomic(&output).unwrap();
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(DnsTable::from_file(&output).unwrap(), DnsTable::empty());
}
