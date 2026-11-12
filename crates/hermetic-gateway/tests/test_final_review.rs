//! Regression tests for the T2.2 final-review blocking defects (a), (b), (e), (f) and the
//! concurrency grace of (c). Every wait is bounded.

mod common;

use common::TestEnv;
use hermetic_gateway::quota::{QuotaTracker, QuotasConfig};
use hermetic_gateway::response::{
    convert_retry_after, parse_date_or_rfc3339, FALLBACK_RETRY_AFTER_SECS, MAX_RETRY_AFTER_SECS,
};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tiny_http::{Header, Response};

const RAW_WAIT: Duration = Duration::from_secs(10);

fn t_clock_2019() -> OffsetDateTime {
    OffsetDateTime::parse("2019-06-15T10:30:00Z", &Rfc3339).unwrap()
}

fn connect(url: &str) -> TcpStream {
    let addr = url.trim_start_matches("http://");
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(RAW_WAIT)).unwrap();
    s.set_write_timeout(Some(RAW_WAIT)).unwrap();
    s
}

/// Reads until EOF, a read error, or `RAW_WAIT` overall; returns what arrived.
fn read_all_bounded(s: &mut TcpStream) -> String {
    let deadline = Instant::now() + RAW_WAIT;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline && out.len() < 1024 * 1024 {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// No `Server` header, and no `Date` within an hour of the host clock.
fn assert_no_host_date_or_server(raw: &str, what: &str) {
    let host_now = OffsetDateTime::now_utc();
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        assert!(
            !lower.starts_with("server:"),
            "{what}: Server header leaked: {raw:?}"
        );
        if let Some(v) = lower.strip_prefix("date:") {
            let original = &line[line.len() - v.len()..];
            if let Some(d) = parse_date_or_rfc3339(original) {
                assert!(
                    (d - host_now).whole_seconds().abs() > 3600,
                    "{what}: Date within an hour of host clock: {line:?}"
                );
            }
        }
    }
    assert!(!raw.contains("tiny-http"), "{what}: implementation leaked");
}

fn env_2019() -> TestEnv {
    TestEnv::new_with_options(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
        t_clock_2019(),
        None,
    )
}

// ---------- (a) self-generated replies of the HTTP layer ----------

#[test]
fn test_malformed_request_line_is_closed_without_host_dated_reply() {
    let env = env_2019();
    let mut s = connect(&env.gateway_url);
    s.write_all(b"GARBAGE\r\n\r\n").unwrap();
    let raw = read_all_bounded(&mut s);
    assert_no_host_date_or_server(&raw, "malformed request line");
    assert!(raw.is_empty(), "expected a bare close, got {raw:?}");
}

#[test]
fn test_malformed_header_is_closed_without_host_dated_reply() {
    let env = env_2019();
    let mut s = connect(&env.gateway_url);
    s.write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nthis header has no colon\r\n\r\n")
        .unwrap();
    let raw = read_all_bounded(&mut s);
    assert_no_host_date_or_server(&raw, "malformed header");
    assert!(raw.is_empty(), "expected a bare close, got {raw:?}");
}

#[test]
fn test_http2_preface_is_closed_without_host_dated_reply() {
    let env = env_2019();
    let mut s = connect(&env.gateway_url);
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    let raw = read_all_bounded(&mut s);
    assert_no_host_date_or_server(&raw, "HTTP/2 preface");
    assert!(raw.is_empty(), "expected a bare close, got {raw:?}");
}

#[test]
fn test_unknown_expect_is_closed_without_host_dated_reply() {
    let env = env_2019();
    let mut s = connect(&env.gateway_url);
    s.write_all(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nExpect: something-else\r\nContent-Length: 2\r\n\r\n{}",
    )
    .unwrap();
    let raw = read_all_bounded(&mut s);
    assert_no_host_date_or_server(&raw, "unknown Expect");
    assert!(raw.is_empty(), "expected a bare close, got {raw:?}");
}

#[test]
fn test_expect_100_continue_interim_and_final_reply_carry_no_host_date() {
    let env = env_2019();
    let body = r#"{"model":"claude-unpinned","messages":[{"role":"user","content":"Hi"}]}"#;
    let mut s = connect(&env.gateway_url);
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nExpect: 100-continue\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    // The interim reply is a bare status line.
    let mut interim = [0u8; 25];
    s.read_exact(&mut interim)
        .expect("100 Continue within timeout");
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(body.as_bytes()).unwrap();
    let raw = read_all_bounded(&mut s);
    assert!(raw.starts_with("HTTP/1.1 400"), "final reply: {raw:?}");
    assert_no_host_date_or_server(&raw, "100-continue final reply");
    let date_line = raw
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("date:"))
        .expect("final reply carries a Date");
    assert!(
        date_line.contains("2019"),
        "guest Date expected: {date_line}"
    );
}

#[test]
fn test_slow_incomplete_request_gets_no_host_dated_reply() {
    let env = env_2019();
    // Headers never finished.
    let mut s = connect(&env.gateway_url);
    s.write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!(
            "unexpected reply to an incomplete request: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(e) => assert!(
            matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "{e}"
        ),
    }
    s.set_read_timeout(Some(RAW_WAIT)).unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    let raw = read_all_bounded(&mut s);
    assert_no_host_date_or_server(&raw, "incomplete headers");
    assert!(raw.is_empty(), "expected a bare close, got {raw:?}");

    // Body shorter than declared, then the client gives up: any reply comes from the gateway.
    let mut s2 = connect(&env.gateway_url);
    s2.write_all(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: 5000\r\n\r\n{\"mod",
    )
    .unwrap();
    thread::sleep(Duration::from_millis(300));
    s2.shutdown(Shutdown::Write).unwrap();
    let raw2 = read_all_bounded(&mut s2);
    assert_no_host_date_or_server(&raw2, "incomplete body");
}

#[test]
fn test_gateway_responses_never_carry_server_header() {
    let env = env_2019();
    let err = common::test_client()
        .post(&format!("{}/v1/nope", env.gateway_url))
        .send_string("{}")
        .unwrap_err();
    match err {
        ureq::Error::Status(404, resp) => {
            assert!(resp.header("server").is_none());
            assert_eq!(resp.all("date").len(), 1);
            assert!(resp.header("date").unwrap_or("").contains("2019"));
        }
        other => panic!("expected 404, got {other:?}"),
    }
}

#[test]
fn test_huge_declared_content_length_does_not_crash_gateway() {
    let env = env_2019();
    let mut s = connect(&env.gateway_url);
    s.write_all(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: 18446744073709551615\r\n\r\n{}",
    )
    .unwrap();
    thread::sleep(Duration::from_millis(300));
    s.shutdown(Shutdown::Write).unwrap();
    let raw = read_all_bounded(&mut s);
    assert!(raw.starts_with("HTTP/1.1 413"), "got {raw:?}");
    assert_no_host_date_or_server(&raw, "huge Content-Length");
    // Still serving.
    let err = common::test_client()
        .post(&format!("{}/v1/nope", env.gateway_url))
        .send_string("{}")
        .unwrap_err();
    assert!(matches!(err, ureq::Error::Status(404, _)), "{err:?}");
}

// ---------- (b) guest Date always present; startup validation ----------

#[test]
fn test_startup_refuses_t_clock_plus_wall_limit_past_year_9999() {
    use hermetic_gateway::config::GatewayConfig;
    use hermetic_gateway::server::GatewayServer;
    let dir = tempfile::TempDir::new().unwrap();
    let mut config = GatewayConfig::from_raw(
        "http://127.0.0.1:9".to_string(),
        "2023-06-01".to_string(),
        vec![],
        vec!["m".to_string()],
        QuotasConfig {
            max_wall_time_seconds: Some(7200),
            ..Default::default()
        },
        dir.path().join("logs"),
        dir.path().join("k"),
        "k".to_string(),
    );
    let late = OffsetDateTime::parse("9999-12-31T23:00:00Z", &Rfc3339).unwrap();
    assert!(GatewayServer::new(config.clone(), late).is_err());
    let overflow = OffsetDateTime::parse("9999-12-31T23:59:59-01:00", &Rfc3339).unwrap();
    config.quotas.max_wall_time_seconds = None;
    assert!(GatewayServer::new(config.clone(), overflow).is_err());
    let ok = OffsetDateTime::parse("9999-12-31T21:00:00Z", &Rfc3339).unwrap();
    config.quotas.max_wall_time_seconds = Some(7200);
    assert!(GatewayServer::new(config, ok).is_ok());
}

// ---------- (c) concurrency grace ----------

#[test]
fn test_concurrency_check_waits_briefly_for_a_released_slot() {
    let tracker = Arc::new(QuotaTracker::new(QuotasConfig {
        max_concurrent_requests: Some(1),
        ..Default::default()
    }));
    tracker.check_and_acquire(0).unwrap();
    let t2 = tracker.clone();
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        t2.release_concurrent();
    });
    tracker
        .check_and_acquire(0)
        .expect("slot released within the grace period must be reused, not a breach");
    assert!(!tracker.snapshot().limit_exceeded);
    common::join_within(releaser);
    // Without a release the breach is still declared after the grace period.
    let start = Instant::now();
    assert!(tracker.check_and_acquire(0).is_err());
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(tracker.snapshot().limit_exceeded);
}

// ---------- (e) Retry-After ----------

#[test]
fn test_retry_after_date_without_upstream_date_uses_fixed_delay() {
    let real = "Thu, 12 Nov 2026 14:00:00 GMT";
    assert_eq!(
        convert_retry_after(real, None),
        FALLBACK_RETRY_AFTER_SECS.to_string()
    );
    // An upstream Date the gateway cannot parse (RFC 850) is treated as missing.
    assert_eq!(
        convert_retry_after(real, Some("Thursday, 12-Nov-26 13:59:00 GMT")),
        FALLBACK_RETRY_AFTER_SECS.to_string()
    );
    assert_eq!(
        convert_retry_after("2026-11-12T14:00:00Z", None),
        FALLBACK_RETRY_AFTER_SECS.to_string()
    );
    // Measured against upstream's own Date, clamped.
    assert_eq!(
        convert_retry_after(real, Some("Thu, 12 Nov 2026 13:59:00 GMT")),
        "60"
    );
    assert_eq!(
        convert_retry_after(real, Some("Thu, 01 Jan 1970 00:00:00 GMT")),
        MAX_RETRY_AFTER_SECS.to_string()
    );
    assert_eq!(
        convert_retry_after("99999999999", None),
        MAX_RETRY_AFTER_SECS.to_string()
    );
}

#[test]
fn test_retry_after_date_without_upstream_date_end_to_end() {
    let env = env_2019();
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let real_later = hermetic_gateway::format_imf_fixdate(
            OffsetDateTime::now_utc() + time::Duration::seconds(60),
        )
        .unwrap();
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"x"}}"#,
        )
        .with_status_code(429);
        resp.add_header(Header::from_bytes(&b"Retry-After"[..], real_later.as_bytes()).unwrap());
        req.respond(resp).unwrap();
    });
    let err = common::test_client()
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(
            r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#,
        )
        .unwrap_err();
    common::join_within(h);
    match err {
        ureq::Error::Status(429, resp) => assert_eq!(
            resp.header("retry-after"),
            Some(FALLBACK_RETRY_AFTER_SECS.to_string().as_str())
        ),
        other => panic!("expected 429, got {other:?}"),
    }
}

// ---------- (f) bounded memory ----------

/// Small caps so the test itself stays small: 2 handler threads, 256 KiB of buffered bodies.
fn env_small_caps() -> TestEnv {
    TestEnv::new_with_request_limits(QuotasConfig::default(), t_clock_2019(), 2, 256 * 1024)
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + common::TEST_WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn open_pending_body(url: &str, declared: usize, send: usize) -> TcpStream {
    let mut s = connect(url);
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {declared}\r\n\r\n"
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(&vec![b' '; send]).unwrap();
    s
}

#[test]
fn test_in_flight_cap_closes_extra_requests_without_reading_them() {
    let env = env_small_caps();
    let a = open_pending_body(&env.gateway_url, 5000, 10);
    let b = open_pending_body(&env.gateway_url, 5000, 10);
    wait_until("2 in-flight requests", || {
        env.gateway_server.in_flight_requests() == 2
    });
    let mut c = open_pending_body(&env.gateway_url, 5000, 10);
    let raw = read_all_bounded(&mut c);
    assert!(
        raw.is_empty(),
        "over-cap request must be closed, got {raw:?}"
    );
    assert_eq!(env.gateway_server.in_flight_requests(), 2);
    drop(a);
    drop(b);
    wait_until("in-flight requests to drain", || {
        env.gateway_server.in_flight_requests() == 0
    });
}

#[test]
fn test_body_budget_refuses_with_overloaded_before_buffering() {
    let env = env_small_caps();
    // 200 KiB of a 300 KiB body pending: 200 KiB of the 256 KiB budget is in use.
    let pending = open_pending_body(&env.gateway_url, 300 * 1024, 200 * 1024);
    wait_until("200 KiB buffered", || {
        env.gateway_server.buffered_body_bytes() >= 200 * 1024
    });
    let mut s = open_pending_body(&env.gateway_url, 100 * 1024, 100 * 1024);
    let raw = read_all_bounded(&mut s);
    assert!(raw.starts_with("HTTP/1.1 529"), "got {raw:?}");
    assert!(raw.contains("overloaded_error"));
    assert_no_host_date_or_server(&raw, "529 overloaded");
    assert!(!env.gateway_server.quota().snapshot().limit_exceeded);
    drop(pending);
    wait_until("budget returned", || {
        env.gateway_server.buffered_body_bytes() == 0
    });
}

#[test]
fn test_limit_exceeded_refuses_before_reading_body() {
    let env = env_2019();
    env.gateway_server
        .quota()
        .trigger_limit_exceeded("test".to_string());
    // Declares 30 MiB but sends none of it: the 429 must come without waiting for the body.
    let mut s = open_pending_body(&env.gateway_url, 30 * 1024 * 1024, 0);
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf).expect("reply within timeout");
    assert_eq!(&buf, b"HTTP/1.1 429");
    assert_eq!(env.gateway_server.buffered_body_bytes(), 0);
}

#[test]
fn test_gateway_config_debug_redacts_api_key() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = hermetic_gateway::config::GatewayConfig::from_raw(
        "http://127.0.0.1:9".to_string(),
        "2023-06-01".to_string(),
        vec![],
        vec![],
        QuotasConfig::default(),
        dir.path().join("logs"),
        dir.path().join("k"),
        "sk-secret-value-123".to_string(),
    );
    let dbg = format!("{config:?}");
    assert!(!dbg.contains("sk-secret-value-123"));
    assert!(dbg.contains("<redacted>"));
}
