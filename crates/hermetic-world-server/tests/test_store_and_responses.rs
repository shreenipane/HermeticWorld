#![forbid(unsafe_code)]

use hermetic_common::{Method, RequestFrame, ResponseFrame};
use hermetic_world_server::{format_imf_fixdate, DirStore, ServerConfig, Store, WorldServer};
use std::fs;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;

fn start_test_server(
    store_dir: &Path,
    log_dir: &Path,
    socket_path: &Path,
    t_clock: OffsetDateTime,
) -> PathBuf {
    let socket = socket_path.to_path_buf();
    let config = ServerConfig {
        store_dir: store_dir.to_path_buf(),
        socket_path: socket.clone(),
        log_dir: log_dir.to_path_buf(),
        t_clock,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
    };

    let server = WorldServer::new(config).expect("create server");
    thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..100 {
        if socket.exists() && UnixStream::connect(&socket).is_ok() {
            return socket;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("Server failed to bind socket in time");
}

fn send_req(socket: &Path, req: &RequestFrame) -> ResponseFrame {
    let mut stream = UnixStream::connect(socket).expect("connect to socket");
    let encoded = req.encode().expect("encode req");
    stream.write_all(&encoded).expect("write req");
    ResponseFrame::read_from(&mut stream, 10 * 1024 * 1024).expect("read response")
}

#[test]
fn test_get_head_range_miss_and_headers() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    let t_clock = datetime!(2024-03-01 12:00:00 UTC);

    // Populate store
    let auth_dir = store_dir.join("pypi.org");
    fs::create_dir_all(&auth_dir).expect("create auth dir");

    // Regular file: /simple/requests/index.html
    let req_dir = auth_dir.join("simple").join("requests");
    fs::create_dir_all(&req_dir).expect("create requests dir");
    let html_file = req_dir.join("index.html");
    let html_body = b"<!DOCTYPE html><html><body>requests package</body></html>";
    fs::write(&html_file, html_body).expect("write html");

    // Sidecar for index.html with custom headers and forbidden headers to test stripping
    let sidecar_file = req_dir.join("index.html.headers.json");
    let sidecar_json = r#"{
        "content_type": "text/html; charset=utf-8",
        "headers": {
            "etag": "bar",
            "memento-datetime": "Thu, 01 Jan 1970 00:00:00 GMT",
            "x-archive-orig-date": "1999-01-01",
            "server": "pywb/2.6.7"
        }
    }"#;
    fs::write(&sidecar_file, sidecar_json).expect("write sidecar");

    // Query string file: /api/search?q=requests -> stored as search%3Fq=requests
    let api_dir = auth_dir.join("api");
    fs::create_dir_all(&api_dir).expect("create api dir");
    let query_file = api_dir.join("search%3Fq=requests");
    let query_body = b"{\"results\": [\"requests\"]}";
    fs::write(&query_file, query_body).expect("write query file");

    // Per-authority .404.json
    let c404_file = auth_dir.join(".404.json");
    let c404_json = r#"{
        "status": 404,
        "content_type": "application/json",
        "body": "{\"error\": \"not found on pypi.org\"}"
    }"#;
    fs::write(&c404_file, c404_json).expect("write custom 404");

    let sock = start_test_server(&store_dir, &log_dir, &socket_path, t_clock);

    // 1. GET regular file
    let req_get = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "pypi.org".into(),
        path_and_query: "/simple/requests/".into(),
        range: None,
    };
    let resp_get = send_req(&sock, &req_get);
    assert_eq!(resp_get.request_id, 1);
    assert_eq!(resp_get.status, 200);
    assert_eq!(resp_get.body, html_body);

    // Check headers
    let get_headers: std::collections::HashMap<_, _> = resp_get
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert_eq!(
        get_headers.get("content-type"),
        Some(&"text/html; charset=utf-8")
    );
    assert_eq!(
        get_headers.get("content-length"),
        Some(&html_body.len().to_string().as_str())
    );
    assert_eq!(get_headers.get("etag"), Some(&"bar"));
    assert!(get_headers.contains_key("date"));
    // Ensure stripped headers are absent
    assert!(!get_headers.contains_key("memento-datetime"));
    assert!(!get_headers.contains_key("x-archive-orig-date"));
    assert!(!get_headers.contains_key("server"));

    // 2. HEAD regular file
    let req_head = RequestFrame {
        method: Method::Head,
        request_id: 2,
        authority: "pypi.org".into(),
        path_and_query: "/simple/requests/index.html".into(),
        range: None,
    };
    let resp_head = send_req(&sock, &req_head);
    assert_eq!(resp_head.request_id, 2);
    assert_eq!(resp_head.status, 200);
    assert!(resp_head.body.is_empty(), "HEAD body must be empty");
    let head_headers: std::collections::HashMap<_, _> = resp_head
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert_eq!(
        head_headers.get("content-length"),
        Some(&html_body.len().to_string().as_str())
    );

    // 3. Satisfiable Range 206
    let req_range = RequestFrame {
        method: Method::Get,
        request_id: 3,
        authority: "pypi.org".into(),
        path_and_query: "/simple/requests/index.html".into(),
        range: Some((0, 14)), // first 15 bytes: "<!DOCTYPE html>"
    };
    let resp_range = send_req(&sock, &req_range);
    assert_eq!(resp_range.request_id, 3);
    assert_eq!(resp_range.status, 206);
    assert_eq!(resp_range.body, b"<!DOCTYPE html>");
    let range_headers: std::collections::HashMap<_, _> = resp_range
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert_eq!(range_headers.get("content-length"), Some(&"15"));
    assert_eq!(
        range_headers.get("content-range"),
        Some(&format!("bytes 0-14/{}", html_body.len()).as_str())
    );

    // Clamped range end
    let req_range_clamp = RequestFrame {
        method: Method::Get,
        request_id: 4,
        authority: "pypi.org".into(),
        path_and_query: "/simple/requests/index.html".into(),
        range: Some((10, 99999)),
    };
    let resp_clamp = send_req(&sock, &req_range_clamp);
    assert_eq!(resp_clamp.status, 206);
    assert_eq!(resp_clamp.body, &html_body[10..]);

    // 4. Unsatisfiable Range 416
    let req_range_416 = RequestFrame {
        method: Method::Get,
        request_id: 5,
        authority: "pypi.org".into(),
        path_and_query: "/simple/requests/index.html".into(),
        range: Some((99999, 100000)),
    };
    let resp_416 = send_req(&sock, &req_range_416);
    assert_eq!(resp_416.status, 416);
    let r416_headers: std::collections::HashMap<_, _> = resp_416
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert_eq!(
        r416_headers.get("content-range"),
        Some(&format!("bytes */{}", html_body.len()).as_str())
    );

    // 5. Query string selection (%3F)
    let req_query = RequestFrame {
        method: Method::Get,
        request_id: 6,
        authority: "pypi.org".into(),
        path_and_query: "/api/search?q=requests".into(),
        range: None,
    };
    let resp_query = send_req(&sock, &req_query);
    assert_eq!(resp_query.status, 200);
    assert_eq!(resp_query.body, query_body);

    // 6. Per-authority .404.json
    let req_miss_pypi = RequestFrame {
        method: Method::Get,
        request_id: 7,
        authority: "pypi.org".into(),
        path_and_query: "/nonexistent".into(),
        range: None,
    };
    let resp_miss_pypi = send_req(&sock, &req_miss_pypi);
    assert_eq!(resp_miss_pypi.status, 404);
    assert_eq!(
        resp_miss_pypi.body,
        b"{\"error\": \"not found on pypi.org\"}"
    );

    // 7. Default 404 (different authority without .404.json)
    let req_miss_other = RequestFrame {
        method: Method::Get,
        request_id: 8,
        authority: "example.com".into(),
        path_and_query: "/missing".into(),
        range: None,
    };
    let resp_miss_other = send_req(&sock, &req_miss_other);
    assert_eq!(resp_miss_other.status, 404);
    assert!(String::from_utf8_lossy(&resp_miss_other.body).contains("404 Not Found"));

    // 8. Traversal rejection: /../, %2e%2e, %00
    let traversal_paths = [
        "/../secret.txt",
        "/simple/../requests",
        "/%2e%2e/etc",
        "/simple/%2e%2e",
        "/simple%00/requests",
        "/simple//requests",
    ];
    for (idx, tp) in traversal_paths.iter().enumerate() {
        let req_trav = RequestFrame {
            method: Method::Get,
            request_id: 100 + idx as u64,
            authority: "pypi.org".into(),
            path_and_query: tp.to_string(),
            range: None,
        };
        let resp_trav = send_req(&sock, &req_trav);
        assert_eq!(
            resp_trav.status, 404,
            "traversal path {tp} must be rejected as a miss (404)"
        );
    }
}

#[test]
fn test_date_header_advances() {
    let t_start = datetime!(2025-01-01 00:00:00 UTC);
    let s1 = format_imf_fixdate(t_start);
    assert_eq!(s1, "Wed, 01 Jan 2025 00:00:00 GMT");

    let t_plus = t_start + Duration::from_secs(3665);
    let s2 = format_imf_fixdate(t_plus);
    assert_eq!(s2, "Wed, 01 Jan 2025 01:01:05 GMT");
}

#[test]
fn test_fix1_authority_traversal_and_sibling_protection() {
    let temp = tempdir().expect("tempdir");
    let parent = temp.path();
    let store_dir = parent.join("store");
    fs::create_dir_all(&store_dir).expect("create store dir");

    // Sibling secret file next to store dir
    let sibling_secret = parent.join("secret.txt");
    fs::write(&sibling_secret, b"super-secret-sibling-data").expect("write secret");

    // Sibling .404.json next to store dir
    let sibling_404 = parent.join(".404.json");
    fs::write(
        &sibling_404,
        r#"{"status": 404, "body": "sibling custom 404 leaked"}"#,
    )
    .expect("write sibling 404");

    let store = DirStore::new(&store_dir);

    // FIX 1: authorities "..", ".", "a..b", ".a", "a.", "-a.com", "a-.com", "../etc", and "example.com:0"
    // are rejected at lookup
    let bad_authorities = [
        "..",
        ".",
        "a..b",
        ".a",
        "a.",
        "-a.com",
        "a-.com",
        "../etc",
        "example.com:0",
    ];
    for bad_auth in bad_authorities {
        assert!(
            store.get(bad_auth, "/secret.txt").is_none(),
            "lookup with bad authority {bad_auth} must return None"
        );
        let (_st, _ct, body) = store.get_404(bad_auth);
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            !body_str.contains("sibling custom 404 leaked"),
            "get_404 with bad authority {bad_auth} must not read sibling .404.json"
        );
    }

    // Verify crafting to reach a sibling never returns it
    let res = store.get("..", "/secret.txt");
    assert!(res.is_none(), "store.get must never reach sibling");

    let (_status, _ct, body404) = store.get_404("..");
    assert!(
        !String::from_utf8_lossy(&body404).contains("sibling custom 404 leaked"),
        "store.get_404 must never reach sibling"
    );

    // Also verify via server
    let log_dir = parent.join("log");
    let socket_path = parent.join("server.sock");
    let sock = start_test_server(
        &store_dir,
        &log_dir,
        &socket_path,
        datetime!(2024-03-01 12:00:00 UTC),
    );

    let req_sibling = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.com".into(),
        path_and_query: "/../secret.txt".into(),
        range: None,
    };
    let resp = send_req(&sock, &req_sibling);
    assert_eq!(resp.status, 404);
    assert!(
        !String::from_utf8_lossy(&resp.body).contains("super-secret-sibling-data"),
        "Server must never serve sibling secret"
    );
}

#[test]
fn test_fix4_deterministic_headers() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let obj_dir = store_dir.join("example.com").join("files");
    fs::create_dir_all(&obj_dir).expect("create obj dir");

    let file_path = obj_dir.join("data.txt");
    fs::write(&file_path, b"determinism test content").expect("write data.txt");

    // Sidecar with 20 headers in non-alphabetical order
    let sidecar_path = obj_dir.join("data.txt.headers.json");
    let mut header_pairs = Vec::new();
    for i in (1..=20).rev() {
        header_pairs.push(format!("\"x-header-{i:02}\": \"val-{i}\""));
    }
    let sidecar_content = format!(
        "{{\n\"content_type\": \"text/plain\",\n\"headers\": {{\n{}\n}}\n}}",
        header_pairs.join(",\n")
    );
    fs::write(&sidecar_path, sidecar_content).expect("write sidecar");

    // Server instance 1
    let log_dir1 = temp.path().join("log1");
    let sock_path1 = temp.path().join("s1.sock");
    let t_clock = datetime!(2024-01-01 00:00:00 UTC);
    let sock1 = start_test_server(&store_dir, &log_dir1, &sock_path1, t_clock);

    let req = RequestFrame {
        method: Method::Get,
        request_id: 10,
        authority: "example.com".into(),
        path_and_query: "/files/data.txt".into(),
        range: None,
    };
    let resp1 = send_req(&sock1, &req);

    // Server instance 2
    let log_dir2 = temp.path().join("log2");
    let sock_path2 = temp.path().join("s2.sock");
    let sock2 = start_test_server(&store_dir, &log_dir2, &sock_path2, t_clock);

    let resp2 = send_req(&sock2, &req);

    let mut resp1_nodate = resp1.clone();
    resp1_nodate.headers.retain(|h| h.name != "date");
    let mut resp2_nodate = resp2.clone();
    resp2_nodate.headers.retain(|h| h.name != "date");

    let bytes1 = resp1_nodate.encode(1024 * 1024).expect("encode resp1");
    let bytes2 = resp2_nodate.encode(1024 * 1024).expect("encode resp2");

    // FIX 6: Compare the frames with the date header removed, so the test checks header ordering only
    assert_eq!(
        bytes1, bytes2,
        "Two server instances must yield byte-identical response frames with date header removed"
    );

    // Extra headers must appear in alphabetical order
    let x_headers: Vec<&str> = resp1
        .headers
        .iter()
        .map(|h| h.name.as_str())
        .filter(|n| n.starts_with("x-header-"))
        .collect();
    let mut sorted_x_headers = x_headers.clone();
    sorted_x_headers.sort();
    assert_eq!(
        x_headers, sorted_x_headers,
        "Headers must be sorted by name"
    );
}

#[test]
fn test_fix6_filter_headers_sidecar_validation() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let obj_dir = store_dir.join("example.com").join("fix6");
    fs::create_dir_all(&obj_dir).expect("create obj dir");

    let file_path = obj_dir.join("index.html");
    fs::write(&file_path, b"valid body content").expect("write file");

    // FIX 6: sidecar with an obs-text value, a 20 KiB value, 100 headers and a bad content_type
    let sidecar_path = obj_dir.join("index.html.headers.json");

    let huge_value = "A".repeat(20 * 1024);
    let mut extra_headers = Vec::new();
    // 1. obs-text value (0x80)
    extra_headers.push(r#""x-bad-obs": "bad\u0080val""#.to_string());
    // 2. 20 KiB value
    extra_headers.push(format!("\"x-bad-huge\": \"{huge_value}\""));
    // 3. 98 other headers -> total 100 headers in sidecar
    for (i, name) in std::iter::once(&"cache-control")
        .chain(
            hermetic_world_server::server::ALLOWED_SIDECAR_HEADERS
                .iter()
                .filter(|&&h| h != "cache-control"),
        )
        .take(98)
        .enumerate()
    {
        extra_headers.push(format!("\"{name}\": \"val-{i}\""));
    }

    let sidecar_json = format!(
        "{{\n\"content_type\": \"text/html\\u0080bad\",\n\"headers\": {{\n{}\n}}\n}}",
        extra_headers.join(",\n")
    );
    fs::write(&sidecar_path, sidecar_json).expect("write sidecar");

    let log_dir = temp.path().join("log");
    let sock_path = temp.path().join("server.sock");
    let sock = start_test_server(
        &store_dir,
        &log_dir,
        &sock_path,
        datetime!(2024-03-01 12:00:00 UTC),
    );

    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.com".into(),
        path_and_query: "/fix6/index.html".into(),
        range: None,
    };
    let resp = send_req(&sock, &req);

    // Serves the object with valid headers only
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"valid body content");

    let hdrs: std::collections::HashMap<_, _> = resp
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();

    // Bad content_type fell back to application/octet-stream
    assert_eq!(
        hdrs.get("content-type"),
        Some(&"application/octet-stream"),
        "Bad content-type must fall back to application/octet-stream"
    );

    // Obs-text and 20 KiB headers are dropped
    assert!(!hdrs.contains_key("x-bad-obs"));
    assert!(!hdrs.contains_key("x-bad-huge"));

    // Caps are respected: header_count <= 64, header_bytes <= 8192
    assert_eq!(
        resp.headers.len(),
        hermetic_common::MAX_RESPONSE_HEADERS,
        "Header count should be capped at MAX_RESPONSE_HEADERS"
    );
    let total_header_bytes: usize = resp
        .headers
        .iter()
        .map(|h| h.name.len() + h.value.len())
        .sum();
    assert!(
        total_header_bytes <= hermetic_common::MAX_RESPONSE_HEADERS_BYTES,
        "Header bytes {total_header_bytes} exceeds MAX_RESPONSE_HEADERS_BYTES"
    );

    // Valid headers are present
    assert_eq!(hdrs.get("cache-control"), Some(&"val-0"));
}

#[test]
fn test_fix1_relative_store_root_with_parent_dir() {
    let temp = tempdir().expect("tempdir");
    let actual_store = temp.path().join("store");
    let obj_dir = actual_store.join("example.com");
    fs::create_dir_all(&obj_dir).expect("create obj dir");
    fs::write(obj_dir.join("hello.txt"), b"relative root content").expect("write file");

    let dummy_dir = temp.path().join("dummy");
    fs::create_dir_all(&dummy_dir).expect("create dummy dir");

    // Relative path containing "../"
    let rel_path = dummy_dir.join("..").join("store");
    let store = DirStore::new(&rel_path);

    let obj = store.get("example.com", "/hello.txt");
    assert!(
        obj.is_some(),
        "DirStore::new with a relative path containing '../' must find the file"
    );
    assert_eq!(obj.unwrap().body, b"relative root content");

    // Missing store directory at startup fails with StartupFailed
    let missing_store = temp.path().join("nonexistent_store");
    let config = ServerConfig {
        store_dir: missing_store,
        socket_path: temp.path().join("server.sock"),
        log_dir: temp.path().join("log"),
        t_clock: datetime!(2024-01-01 00:00:00 UTC),
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
    };
    let server_res = WorldServer::new(config);
    assert!(
        matches!(
            server_res,
            Err(hermetic_world_server::ServerExit::StartupFailed)
        ),
        "WorldServer::new with missing root must return StartupFailed"
    );
}

#[test]
fn test_fix2_mixed_case_sidecar_headers() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let obj_dir = store_dir.join("example.com").join("headers");
    fs::create_dir_all(&obj_dir).expect("create obj dir");

    let file_path = obj_dir.join("item.json");
    fs::write(&file_path, b"{\"status\": \"ok\"}").expect("write file");

    let sidecar_path = obj_dir.join("item.json.headers.json");
    let sidecar_content = r#"{
        "content_type": "application/json",
        "headers": {
            "ETag": "\"abcdef123456\"",
            "Cache-Control": "public, max-age=86400",
            "Content-Language": "custom-val"
        }
    }"#;
    fs::write(&sidecar_path, sidecar_content).expect("write sidecar");

    let log_dir = temp.path().join("log");
    let sock_path = temp.path().join("server.sock");
    let sock = start_test_server(
        &store_dir,
        &log_dir,
        &sock_path,
        datetime!(2024-03-01 12:00:00 UTC),
    );

    let req = RequestFrame {
        method: Method::Get,
        request_id: 42,
        authority: "example.com".into(),
        path_and_query: "/headers/item.json".into(),
        range: None,
    };
    let resp = send_req(&sock, &req);
    assert_eq!(resp.status, 200);

    let hdrs: std::collections::HashMap<_, _> = resp
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();

    assert_eq!(
        hdrs.get("etag"),
        Some(&"\"abcdef123456\""),
        "ETag sidecar header must be lowercased to etag"
    );
    assert_eq!(
        hdrs.get("cache-control"),
        Some(&"public, max-age=86400"),
        "Cache-Control sidecar header must be lowercased to cache-control"
    );
    assert_eq!(
        hdrs.get("content-language"),
        Some(&"custom-val"),
        "Mixed-case headers must be lowercased and retained"
    );
}

#[test]
fn test_finding_reserve_header_space_for_content_range() {
    use hermetic_world_server::filter_headers;

    // 1. Direct unit test of filter_headers:
    // With 8100-byte printable content-type, content-range must not be dropped.
    let long_ct = "text/".to_string() + &"x".repeat(8095);
    let cr_val = "bytes 0-0/1";
    let headers = filter_headers(
        Vec::new(),
        Some(&long_ct),
        1,
        "Mon, 01 Jan 2024 00:00:00 GMT",
        Some(cr_val),
    );

    let cr_hdr = headers.iter().find(|h| h.name == "content-range");
    assert!(
        cr_hdr.is_some(),
        "content-range header must be retained even with large content-type"
    );
    assert_eq!(cr_hdr.unwrap().value, cr_val);

    let ct_hdr = headers.iter().find(|h| h.name == "content-type");
    assert!(ct_hdr.is_some(), "content-type header must be present");
    assert_eq!(
        ct_hdr.unwrap().value,
        "application/octet-stream",
        "content-type must fall back to application/octet-stream to fit content-range"
    );

    // 2. Integration test through server handling a single-part 206 range request
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let obj_dir = store_dir.join("example.com").join("files");
    fs::create_dir_all(&obj_dir).expect("create obj dir");

    let file_path = obj_dir.join("data.bin");
    fs::write(&file_path, b"abcdef").expect("write file");

    let sidecar_path = obj_dir.join("data.bin.headers.json");
    let sidecar_content = serde_json::json!({
        "content_type": long_ct,
    });
    fs::write(
        &sidecar_path,
        serde_json::to_string(&sidecar_content).expect("json"),
    )
    .expect("write sidecar");

    let log_dir = temp.path().join("log");
    let sock_path = temp.path().join("server.sock");
    let sock = start_test_server(
        &store_dir,
        &log_dir,
        &sock_path,
        datetime!(2024-03-01 12:00:00 UTC),
    );

    let req = RequestFrame {
        method: Method::Get,
        request_id: 101,
        authority: "example.com".into(),
        path_and_query: "/files/data.bin".into(),
        range: Some((0, 0)),
    };
    let resp = send_req(&sock, &req);
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body, b"a");

    let hdrs: std::collections::HashMap<_, _> = resp
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();

    assert_eq!(
        hdrs.get("content-range"),
        Some(&"bytes 0-0/6"),
        "206 response must contain Content-Range header"
    );
    assert_eq!(
        hdrs.get("content-type"),
        Some(&"application/octet-stream"),
        "Content-Type must fall back to application/octet-stream"
    );
}
