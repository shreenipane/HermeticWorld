//! Archived pages (WARC records) are scanned against the fix fingerprints:
//! plain WARC, gzip-member WARC, and an HTTP payload that is itself
//! gzip-encoded inside the record (D10 hunk-fingerprint matching).

use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity, Visibility};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

const GOLD: &str = "diff --git a/app/core.py b/app/core.py\n--- a/app/core.py\n+++ b/app/core.py\n@@ -2,3 +2,4 @@\n     total = 0\n     for item in items:\n+        validate_item_security_checks(item)\n         total += item.value\n";
const BASE: &str = "def process_data(items):\n    total = 0\n    for item in items:\n        total += item.value\n    return total\n";
const PAGE: &str = "<html><body><pre>\ndef process_data(items):\n    total = 0\n    for item in items:\n        validate_item_security_checks(item)\n        total += item.value\n</pre></body></html>\n";

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn warc_record(http: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "WARC/1.1\r\nWARC-Type: response\r\nWARC-Date: 2019-01-01T00:00:00Z\r\nContent-Length: {}\r\n\r\n",
        http.len()
    )
    .into_bytes();
    out.extend_from_slice(http);
    out.extend_from_slice(b"\r\n\r\n");
    out
}

fn http(body: &[u8], gzip_encoded: bool) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n".to_vec();
    if gzip_encoded {
        out.extend_from_slice(b"Content-Encoding: gzip\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn gates(name: &str, bytes: &[u8]) -> usize {
    let base = tempdir().unwrap();
    fs::create_dir_all(base.path().join("app")).unwrap();
    fs::write(base.path().join("app/core.py"), BASE).unwrap();
    let fp = FingerprintSet::from_task(GOLD, "", base.path()).unwrap();
    let target = tempdir().unwrap();
    fs::write(target.path().join(name), bytes).unwrap();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    scan_tree(target.path(), &fp, &opts)
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .count()
}

#[test]
fn fix_inside_a_plain_warc_record_gates() {
    assert!(gates("pages.warc", &warc_record(&http(PAGE.as_bytes(), false))) > 0);
}

#[test]
fn fix_inside_a_gzip_member_warc_gates() {
    assert!(
        gates(
            "pages.warc.gz",
            &gzip(&warc_record(&http(PAGE.as_bytes(), false)))
        ) > 0
    );
}

#[test]
fn fix_inside_a_gzip_encoded_http_payload_gates() {
    let record = warc_record(&http(&gzip(PAGE.as_bytes()), true));
    assert!(gates("pages.warc", &record) > 0, "plain WARC, gzip payload");
    assert!(
        gates("pages.warc.gz", &gzip(&record)) > 0,
        "gzip WARC, gzip payload"
    );
}

#[test]
fn archive_without_the_fix_does_not_gate() {
    let page = "<html><body>unrelated page</body></html>";
    assert_eq!(
        gates("pages.warc", &warc_record(&http(page.as_bytes(), false))),
        0
    );
    assert_eq!(
        gates(
            "pages.warc",
            &warc_record(&http(&gzip(page.as_bytes()), true))
        ),
        0
    );
}

fn findings(name: &str, bytes: &[u8]) -> Vec<hermetic_sealcheck::Finding> {
    let base = tempdir().unwrap();
    fs::create_dir_all(base.path().join("app")).unwrap();
    fs::write(base.path().join("app/core.py"), BASE).unwrap();
    let fp = FingerprintSet::from_task(GOLD, "", base.path()).unwrap();
    let target = tempdir().unwrap();
    fs::write(target.path().join(name), bytes).unwrap();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    scan_tree(target.path(), &fp, &opts)
}

fn http_with(headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\n{headers}\r\n").into_bytes();
    out.extend_from_slice(body);
    out
}

#[test]
fn chunked_and_deflate_payloads_are_decoded() {
    // Chunked, split inside the fixed line.
    let page = PAGE.as_bytes();
    let (a, b) = page.split_at(70);
    let mut chunked = format!("{:x}\r\n", a.len()).into_bytes();
    chunked.extend_from_slice(a);
    chunked.extend_from_slice(format!("\r\n{:x}\r\n", b.len()).as_bytes());
    chunked.extend_from_slice(b);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let rec = warc_record(&http_with("Transfer-Encoding: chunked\r\n", &chunked));
    assert!(gates("chunked.warc", &rec) > 0, "chunked");

    // zlib-wrapped and raw deflate.
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(page).unwrap();
    let rec = warc_record(&http_with(
        "Content-Encoding: deflate\r\n",
        &z.finish().unwrap(),
    ));
    assert!(gates("zlib.warc", &rec) > 0, "zlib deflate");
    let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    d.write_all(page).unwrap();
    let rec = warc_record(&http_with(
        "Content-Encoding: deflate\r\n",
        &d.finish().unwrap(),
    ));
    assert!(gates("raw.warc", &rec) > 0, "raw deflate");
}

#[test]
fn undecodable_or_malformed_records_are_review_findings() {
    let gap = |name: &str, bytes: &[u8]| {
        findings(name, bytes)
            .iter()
            .any(|f| f.channel == "warc_payload_unscanned" && f.severity == Severity::Review)
    };
    let br = warc_record(&http_with("Content-Encoding: br\r\n", b"\x1b\x00opaque"));
    assert!(gap("br.warc", &br), "unsupported encoding");
    let mut truncated = warc_record(&http(PAGE.as_bytes(), false));
    truncated.truncate(truncated.len() - 40);
    assert!(gap("trunc.warc", &truncated), "truncated record");
    let no_len = b"WARC/1.1\r\nWARC-Type: response\r\n\r\nbody".to_vec();
    assert!(gap("nolen.warc", &no_len), "missing Content-Length");
    let bad_chunks = warc_record(&http_with(
        "Transfer-Encoding: chunked\r\n",
        b"zz\r\nabc\r\n",
    ));
    assert!(gap("chunks.warc", &bad_chunks), "malformed chunks");
    let bad_gzip = warc_record(&http_with(
        "Content-Encoding: gzip\r\n",
        b"\x1f\x8bnot gzip",
    ));
    assert!(gap("gz.warc", &bad_gzip), "corrupt gzip payload");
}

#[test]
fn gzip_bomb_payload_is_bounded() {
    let bomb = gzip(&vec![b'a'; 64 * 1024 * 1024]);
    let rec = warc_record(&http_with("Content-Encoding: gzip\r\n", &bomb));
    let f = findings("bomb.warc", &rec);
    assert!(
        f.iter().any(|f| f.channel == "warc_payload_unscanned"),
        "{f:?}"
    );
}
