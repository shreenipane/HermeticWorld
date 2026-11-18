#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use hermetic_escapeprobe::classify::EscapeResult;
use hermetic_escapeprobe::config::{GatewayConfig, SentinelConfig};
use hermetic_escapeprobe::gateway::*;
use hermetic_escapeprobe::http::{HttpError, HttpResponse};
use hermetic_sealcheck::d12::D12Options;

#[test]
fn test_classify_abuse_probes_fixtures() {
    // 1. remote_source
    assert_eq!(classify_remote_source(Ok(400)).0, EscapeResult::Blocked);
    assert_eq!(classify_remote_source(Ok(200)).0, EscapeResult::Leak);
    assert_eq!(classify_remote_source(Ok(500)).0, EscapeResult::Error);
    assert_eq!(
        classify_remote_source(Err(&HttpError::Timeout)).0,
        EscapeResult::Blocked
    );

    // 2. provider_tools
    assert_eq!(classify_provider_tools(Ok(400)).0, EscapeResult::Blocked);
    assert_eq!(classify_provider_tools(Ok(200)).0, EscapeResult::Leak);

    // 3. other_endpoint
    assert_eq!(classify_other_endpoint(Ok(404)).0, EscapeResult::Blocked);
    assert_eq!(classify_other_endpoint(Ok(400)).0, EscapeResult::Blocked);
    assert_eq!(classify_other_endpoint(Ok(200)).0, EscapeResult::Leak);

    // 4. other_model
    assert_eq!(classify_other_model(Ok(400)).0, EscapeResult::Blocked);
    assert_eq!(classify_other_model(Ok(200)).0, EscapeResult::Leak);

    // 5. unlisted_beta
    assert_eq!(classify_unlisted_beta(Ok(400)).0, EscapeResult::Blocked);
    assert_eq!(classify_unlisted_beta(Ok(200)).0, EscapeResult::Leak);

    // 6. quota
    assert_eq!(classify_quota(Ok(413)).0, EscapeResult::Blocked);
    assert_eq!(classify_quota(Ok(429)).0, EscapeResult::Blocked);
    assert_eq!(classify_quota(Ok(200)).0, EscapeResult::Leak);
}

#[test]
fn test_model_call_date_scan_clean_and_leaks() {
    let sentinel_cfg = SentinelConfig {
        real_date: "2024-10-22".to_string(),
        tolerance_days: 1,
        host_names: vec!["secret-worker-99".to_string()],
        host_paths: vec!["/srv/secret-storage".to_string()],
    };
    let date = sentinel_cfg.parse_date().unwrap();
    let opts = D12Options {
        real_date: date,
        tolerance_days: 1,
        host_names: sentinel_cfg.host_names.clone(),
        host_paths: sentinel_cfg.host_paths.clone(),
    };

    // Clean response: sanitized guest date, no host metadata
    let clean_resp = HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "date".to_string(),
                "Tue, 14 Nov 2023 22:13:20 GMT".to_string(),
            ),
        ],
        body: br#"{"id":"1","type":"message","content":[{"type":"text","text":"pong"}]}"#.to_vec(),
    };
    let (res, detail, summary) = classify_model_call_date(Ok(&clean_resp), Some(&opts));
    assert_eq!(res, EscapeResult::Blocked, "{detail}");
    assert!(!summary.unwrap().date_leak_observed);

    // Leak in Date header
    let leaked_date_header = HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "date".to_string(),
                "Tue, 22 Oct 2024 10:00:00 GMT".to_string(),
            ),
        ],
        body: br#"{"id":"1","type":"message","content":[{"type":"text","text":"pong"}]}"#.to_vec(),
    };
    let (res, detail, summary) = classify_model_call_date(Ok(&leaked_date_header), Some(&opts));
    assert_eq!(res, EscapeResult::Leak, "{detail}");
    assert!(summary.unwrap().date_leak_observed);

    // Leak in response body (date string)
    let leaked_body_date = HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "date".to_string(),
                "Tue, 14 Nov 2023 22:13:20 GMT".to_string(),
            ),
        ],
        body: br#"{"id":"1","content":[{"type":"text","text":"Today is 2024-10-22."}]}"#.to_vec(),
    };
    let (res, _, summary) = classify_model_call_date(Ok(&leaked_body_date), Some(&opts));
    assert_eq!(res, EscapeResult::Leak);
    assert!(summary.unwrap().date_leak_observed);

    // Leak in response body (host name)
    let leaked_host_name = HttpResponse {
        status: 200,
        headers: vec![],
        body: br#"{"error":"Internal error on secret-worker-99"}"#.to_vec(),
    };
    let (res, _, summary) = classify_model_call_date(Ok(&leaked_host_name), Some(&opts));
    assert_eq!(res, EscapeResult::Leak);
    assert!(summary.unwrap().date_leak_observed);

    // Leak in response body (host path)
    let leaked_host_path = HttpResponse {
        status: 200,
        headers: vec![],
        body: br#"{"error":"File not found in /srv/secret-storage/run.log"}"#.to_vec(),
    };
    let (res, _, summary) = classify_model_call_date(Ok(&leaked_host_path), Some(&opts));
    assert_eq!(res, EscapeResult::Leak);
    assert!(summary.unwrap().date_leak_observed);
}

#[test]
fn test_unconfigured_gateway_returns_unavailable() {
    let (recs, summary) = run_gateway_probes(None, Duration::from_millis(50));
    assert_eq!(recs.len(), 7);
    for r in &recs {
        assert_eq!(r.result, EscapeResult::Unavailable);
    }
    assert!(summary.is_none());
}

const MAX_MOCK_HEADER_BYTES: usize = 65536;
const MAX_MOCK_BODY_BUFFER_BYTES: usize = 65536;

fn read_mock_request(stream: &mut std::net::TcpStream) -> (String, usize) {
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    while header_buf.len() < MAX_MOCK_HEADER_BYTES {
        if stream.read_exact(&mut byte).is_err() {
            break;
        }
        header_buf.push(byte[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header_str = String::from_utf8_lossy(&header_buf).to_string();
    let content_length = header_str
        .lines()
        .find_map(|l| {
            if let Some((k, v)) = l.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    return v.trim().parse::<usize>().ok();
                }
            }
            None
        })
        .unwrap_or(0);

    let mut full_req = header_str;
    let to_read = content_length.min(MAX_MOCK_BODY_BUFFER_BYTES);
    if to_read > 0 {
        let mut body_buf = vec![0u8; to_read];
        if stream.read_exact(&mut body_buf).is_ok() {
            full_req.push_str(&String::from_utf8_lossy(&body_buf));
        }
    }
    (full_req, content_length)
}

#[test]
fn test_mock_gateway_live_probes_sealed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        for _ in 0..7 {
            let (mut stream, _) = listener.accept().unwrap();
            let (req_str, content_length) = read_mock_request(&mut stream);

            if req_str.contains("POST /v1/complete") {
                // other_endpoint
                let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp).unwrap();
            } else if req_str.contains("web_search_20250101")
                || req_str.contains("unpinned-prohibited-model")
                || req_str.contains("unlisted-prohibited-beta-2026")
                || req_str.contains("evil.png")
            {
                // remote_source, provider_tools, other_model, unlisted_beta
                let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp).unwrap();
            } else if content_length > 2000 {
                // quota (large body)
                let resp = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp).unwrap();
            } else {
                // clean model call
                let body =
                    br#"{"id":"1","type":"message","content":[{"type":"text","text":"clean"}]}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nDate: Tue, 14 Nov 2023 22:13:20 GMT\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(body).unwrap();
            }
        }
    });

    let config = GatewayConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        pinned_model: "test-model".to_string(),
        api_version: "2023-06-01".to_string(),
        allowed_beta: None,
        sentinel: Some(SentinelConfig {
            real_date: "2024-10-22".to_string(),
            tolerance_days: 1,
            host_names: vec!["host-forbidden".to_string()],
            host_paths: vec!["/host/forbidden".to_string()],
        }),
    };

    let (records, summary) = run_gateway_probes(Some(&config), Duration::from_millis(500));
    server_thread.join().unwrap();

    assert_eq!(records.len(), 7);
    for r in &records {
        assert_eq!(
            r.result,
            EscapeResult::Blocked,
            "probe {} failed: {}",
            r.probe,
            r.detail
        );
    }
    assert!(summary.is_some());
    assert!(!summary.unwrap().date_leak_observed);
}

#[test]
fn test_regression_quota_oversized_response_returns_error() {
    let (res, detail) = classify_quota(Err(&HttpError::ResponseTooLarge));
    assert_eq!(res, EscapeResult::Error);
    assert_eq!(detail, "oversized response received from gateway");
}

#[test]
fn test_regression_model_call_date_without_options_returns_unavailable() {
    let resp = HttpResponse {
        status: 200,
        headers: vec![],
        body: b"{}".to_vec(),
    };
    let (res, detail, summary) = classify_model_call_date(Ok(&resp), None);
    assert_eq!(res, EscapeResult::Unavailable);
    assert_eq!(detail, "gateway responded without date options");
    assert!(summary.is_none());
}

#[test]
fn test_regression_model_call_unsuccessful_status_returns_error() {
    let sentinel_cfg = SentinelConfig {
        real_date: "2024-10-22".to_string(),
        tolerance_days: 1,
        host_names: vec!["host-forbidden".to_string()],
        host_paths: vec!["/host/forbidden".to_string()],
    };
    let date = sentinel_cfg.parse_date().unwrap();
    let opts = D12Options {
        real_date: date,
        tolerance_days: 1,
        host_names: sentinel_cfg.host_names.clone(),
        host_paths: sentinel_cfg.host_paths.clone(),
    };

    // A 500 Internal Server Error without date leak must return Error, not Blocked
    let error_resp = HttpResponse {
        status: 500,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: br#"{"error":"upstream unavailable"}"#.to_vec(),
    };
    let (res, detail, summary) = classify_model_call_date(Ok(&error_resp), Some(&opts));
    assert_eq!(res, EscapeResult::Error);
    assert_eq!(detail, "model call response status was not successful");
    assert!(!summary.unwrap().date_leak_observed);

    // But if a 500 response leaks a date, it must still report Leak
    let leaking_error_resp = HttpResponse {
        status: 500,
        headers: vec![(
            "date".to_string(),
            "Tue, 22 Oct 2024 10:00:00 GMT".to_string(),
        )],
        body: br#"{"error":"upstream unavailable"}"#.to_vec(),
    };
    let (res, detail, summary) = classify_model_call_date(Ok(&leaking_error_resp), Some(&opts));
    assert_eq!(res, EscapeResult::Leak);
    assert_eq!(detail, "real date leaked in model call response");
    assert!(summary.unwrap().date_leak_observed);
}

#[test]
fn test_regression_mock_server_fragmented_request_handling() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (req_str, content_length) = read_mock_request(&mut stream);
        assert!(req_str.contains("evil.png"));
        assert_eq!(content_length, 25);
        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(resp).unwrap();
    });

    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let headers = b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 25\r\n\r\n";
    let body = b"{\"url\":\"http://evil.png\"}";

    // Write headers and flush (simulating packet boundary / fragment 1)
    client.write_all(headers).unwrap();
    client.flush().unwrap();
    std::thread::sleep(Duration::from_millis(10));

    // Write body (fragment 2)
    client.write_all(body).unwrap();
    client.flush().unwrap();

    let mut resp = Vec::new();
    client.read_to_end(&mut resp).unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request"));

    server_thread.join().unwrap();
}
