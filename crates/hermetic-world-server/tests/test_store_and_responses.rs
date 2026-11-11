#![forbid(unsafe_code)]

use hermetic_common::{Method, RequestFrame, ResponseFrame};
use hermetic_world_server::{format_imf_fixdate, ServerConfig, WorldServer};
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
            "x-custom-foo": "bar",
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
    assert_eq!(get_headers.get("x-custom-foo"), Some(&"bar"));
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
