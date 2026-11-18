#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use hermetic_escapeprobe::classify::EscapeResult;
use hermetic_escapeprobe::config::SentinelConfig;
use hermetic_escapeprobe::gateway::classify_model_call_date;
use hermetic_escapeprobe::http::*;
use hermetic_sealcheck::d12::D12Options;

#[test]
fn test_regression_chunked_response_decoding() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\nhost\r\n6\r\nsecret\r\n0\r\n\r\n";
    let resp = parse_response(raw).expect("parse chunked response");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hostsecret");
}

#[test]
fn test_regression_chunked_response_date_sentinel_leak() {
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

    // The host name "secret-worker-99" is split across chunks "secret-" and "worker-99"
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nsecret-\r\n9\r\nworker-99\r\n0\r\n\r\n";
    let resp = parse_response(raw).expect("parse chunked response");
    let (res, detail, summary) = classify_model_call_date(Ok(&resp), Some(&opts));
    assert_eq!(res, EscapeResult::Leak, "{detail}");
    assert!(summary.unwrap().date_leak_observed);
}

#[test]
fn test_regression_incomplete_length_delimited_response_rejected() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello";
    let err = parse_response(raw).expect_err("incomplete body must be rejected");
    assert_eq!(
        err,
        HttpError::ProtocolViolation("incomplete response body")
    );

    let raw_empty = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    let err_empty = parse_response(raw_empty)
        .expect_err("empty body with non-zero Content-Length must be rejected");
    assert_eq!(
        err_empty,
        HttpError::ProtocolViolation("incomplete response body")
    );
}

#[test]
fn test_regression_http_request_enforces_elapsed_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        // Slowly trickle bytes: send 1 byte every 80ms
        const MAX_TRICKLE_BYTES: usize = 10;
        for _ in 0..MAX_TRICKLE_BYTES {
            thread::sleep(Duration::from_millis(80));
            if stream.write_all(b"x").is_err() {
                break;
            }
        }
    });

    let start = std::time::Instant::now();
    let res = request(
        &format!("http://127.0.0.1:{port}/test"),
        "GET",
        &[],
        &[],
        Duration::from_millis(100),
    );
    let elapsed = start.elapsed();
    assert_eq!(res, Err(HttpError::Timeout));
    assert!(
        elapsed < Duration::from_millis(500),
        "request took too long: {elapsed:?}"
    );

    let _ = server_thread.join();
}
