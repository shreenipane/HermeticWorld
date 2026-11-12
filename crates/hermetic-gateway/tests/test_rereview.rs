//! Regression tests for the T2.2 Codex re-review (2026-11-12) BLOCKING findings 1-15.
//! Every wait is bounded and every producer is capped, so a regression fails instead of
//! hanging or exhausting memory.

mod common;

use common::TestEnv;
use hermetic_gateway::history::HistoryLog;
use hermetic_gateway::log::HostLogger;
use hermetic_gateway::quota::QuotasConfig;
use hermetic_gateway::response::{rewrite_json_timestamps, GuestClock, SanitizingSseReader};
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tiny_http::{Header, Response};

const RAW_WAIT: Duration = Duration::from_secs(10);
const MODEL: &str = "claude-3-5-sonnet-20241022";
const REAL_DATE: &str = "2026-11-12";

fn t_clock_2019() -> OffsetDateTime {
    OffsetDateTime::parse("2019-06-15T10:30:00Z", &Rfc3339).unwrap()
}

fn env_2019(quotas: QuotasConfig) -> TestEnv {
    TestEnv::new_with_options(
        vec![MODEL.to_string()],
        vec![],
        quotas,
        t_clock_2019(),
        None,
    )
}

fn connect(url: &str) -> TcpStream {
    let s = TcpStream::connect(url.trim_start_matches("http://")).expect("connect");
    s.set_read_timeout(Some(RAW_WAIT)).unwrap();
    s.set_write_timeout(Some(RAW_WAIT)).unwrap();
    s
}

fn read_all_bounded(s: &mut TcpStream, max: usize) -> String {
    let deadline = Instant::now() + RAW_WAIT;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    while Instant::now() < deadline && out.len() < max {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[allow(clippy::result_large_err)]
fn post(env: &TestEnv, body: &str) -> Result<ureq::Response, ureq::Error> {
    common::test_client()
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
}

fn simple_body(stream: bool) -> String {
    format!(
        r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":"Hi"}}],"stream":{stream}}}"#
    )
}

fn sse_response(text: String) -> Response<Cursor<Vec<u8>>> {
    let len = text.len();
    Response::new(
        200.into(),
        vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
        Cursor::new(text.into_bytes()),
        Some(len),
        None,
    )
}

fn expect_status(res: Result<ureq::Response, ureq::Error>, status: u16) -> String {
    match res {
        Err(ureq::Error::Status(s, resp)) if s == status => resp.into_string().unwrap(),
        Ok(r) if r.status() == status => r.into_string().unwrap(),
        other => panic!("expected {status}, got {other:?}"),
    }
}

/// A capped producer: yields `chunk` repeatedly until `cap` bytes, counting what it produced,
/// optionally sleeping between chunks.
struct CappedProducer {
    chunk: Vec<u8>,
    pos: usize,
    cap: usize,
    produced: Arc<AtomicUsize>,
    pause: Duration,
}

impl Read for CappedProducer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let done = self.produced.load(Ordering::SeqCst);
        if done >= self.cap {
            return Ok(0);
        }
        if self.pos == 0 && !self.pause.is_zero() {
            thread::sleep(self.pause);
        }
        let n = buf
            .len()
            .min(self.chunk.len() - self.pos)
            .min(self.cap - done);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos = (self.pos + n) % self.chunk.len();
        self.produced.fetch_add(n, Ordering::SeqCst);
        Ok(n)
    }
}

// ---------- 1. fail-closed sanitisation ----------

#[test]
fn test_1_unverifiable_2xx_bodies_never_reach_client() {
    let env = env_2019(QuotasConfig::default());
    let deep = format!(
        "{}{{\"created_at\":\"{REAL_DATE}T09:00:00Z\"}}{}",
        "{\"a\":".repeat(130),
        "}".repeat(130)
    );
    let bodies = vec![deep, format!("plain text {REAL_DATE}T09:00:00Z")];
    let mock = env.mock_server.clone();
    let mock_bodies = bodies.clone();
    let h = thread::spawn(move || {
        for b in mock_bodies {
            let req = common::recv_upstream(&mock);
            req.respond(Response::from_string(b)).unwrap();
        }
    });
    for _ in &bodies {
        let out = expect_status(post(&env, &simple_body(false)), 502);
        assert!(out.contains("api_error"), "{out}");
        assert!(!out.contains(REAL_DATE), "original body leaked: {out}");
    }
    common::join_within(h);
}

#[test]
fn test_1_sse_auxiliary_lines_and_unknown_events_are_dropped() {
    let env = env_2019(QuotasConfig::default());
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let sse = format!(
            ": comment {REAL_DATE}T09:00:00Z\nid: {REAL_DATE}\nretry: 5\n\
event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"m\"}}}}\n\n\
event: x-{REAL_DATE}\ndata: {{\"a\":1}}\n\n\
event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
        );
        req.respond(sse_response(sse)).unwrap();
    });
    let out = post(&env, &simple_body(true))
        .expect("stream")
        .into_string()
        .unwrap();
    common::join_within(h);
    assert!(out.contains("event: message_stop"), "{out}");
    assert!(out.contains("event: message_start"), "{out}");
    assert!(!out.contains(REAL_DATE), "auxiliary text leaked: {out}");
    assert!(!out.contains("retry"), "{out}");
}

// ---------- 2. timestamp traversal ----------

#[test]
fn test_2_timestamps_in_nested_containers_and_input_objects_are_rewritten() {
    let clock = GuestClock::frozen(t_clock_2019(), Duration::from_secs(0));
    let mut v: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"created":{{"created_at":"{REAL_DATE}T00:00:00Z"}},
            "expires_at":[{{"updated_at":1762905600}}],
            "input":{{"created_at":"{REAL_DATE}T01:00:00Z"}},
            "content":[{{"type":"tool_use","id":"t","name":"n","input":{{"created_at":1700000000}}}}]}}"#
    ))
    .unwrap();
    rewrite_json_timestamps(&mut v, &clock);
    let text = v.to_string();
    assert!(!text.contains(REAL_DATE), "{text}");
    assert!(!text.contains("1762905600"), "{text}");
    assert_eq!(
        v["content"][0]["input"]["created_at"].as_i64(),
        Some(1700000000),
        "tool_use input must stay opaque"
    );
    assert_eq!(v["created"]["created_at"], "2019-06-15T10:30:00Z");
}

// ---------- 3. oversized SSE lines and events ----------

fn sanitize_all(input: Vec<u8>) -> String {
    let clock = GuestClock::frozen(t_clock_2019(), Duration::from_secs(0));
    let mut r = SanitizingSseReader::new(Cursor::new(input), clock);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

const STD_API_ERROR_EVENT: &str =
    "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"Upstream API error\"}}\n\n";

#[test]
fn test_3_oversized_sse_line_or_event_is_rejected_whole() {
    let good = "event: ping\ndata: {\"type\":\"ping\"}\n\n";
    // A single data line over MAX_LINE_BYTES (1 MiB).
    let long_line = format!(
        "{good}event: message_start\ndata: {{\"created_at\":\"{REAL_DATE}T09:00:00Z\",\"pad\":\"{}\"}}\n\n",
        "x".repeat(1536 * 1024)
    );
    let out = sanitize_all(long_line.into_bytes());
    assert_eq!(out, format!("{good}{STD_API_ERROR_EVENT}"));

    // Lines under the line cap whose event exceeds MAX_EVENT_BYTES (4 MiB).
    let mut big_event = format!("event: message_start\ndata: {{\"created_at\":\"{REAL_DATE}\",\n");
    for _ in 0..5 {
        big_event.push_str(&format!("data: \"{}\",\n", "y".repeat(900 * 1024)));
    }
    big_event.push_str("data: \"z\"}\n\n");
    let out = sanitize_all(big_event.into_bytes());
    assert_eq!(out, STD_API_ERROR_EVENT);

    // The line cap falls inside a multi-byte UTF-8 character.
    let mut utf8 = b"event: message_start\ndata: {\"t\":\"".to_vec();
    utf8.extend("é".repeat(600 * 1024).as_bytes());
    utf8.extend_from_slice(b"\"}\n\n");
    let out = sanitize_all(utf8);
    assert_eq!(out, STD_API_ERROR_EVENT);

    // Invalid UTF-8 inside an event.
    let mut bad = b"event: message_start\ndata: {\"t\":\"".to_vec();
    bad.extend_from_slice(&[0xff, 0xfe]);
    bad.extend_from_slice(format!("{REAL_DATE}\"}}\n\n").as_bytes());
    let out = sanitize_all(bad);
    assert_eq!(out, STD_API_ERROR_EVENT);
}

// ---------- 4. oversized 2xx body is refused, not truncated ----------

#[test]
fn test_4_upstream_body_over_cap_is_refused() {
    let env = env_2019(QuotasConfig::default());
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let cap = hermetic_gateway::upstream::UpstreamClient::MAX_RESPONSE_BYTES + 1024;
        let produced = Arc::new(AtomicUsize::new(0));
        let mut chunk = b"{\"ORIGINAL_MARKER\":\"".to_vec();
        chunk.extend(vec![b'a'; 64 * 1024]);
        let body = CappedProducer {
            chunk,
            pos: 0,
            cap,
            produced,
            pause: Duration::ZERO,
        };
        let _ = req.respond(Response::new(200.into(), vec![], body, Some(cap), None));
    });
    let out = expect_status(post(&env, &simple_body(false)), 502);
    common::join_within(h);
    assert!(out.contains("api_error"), "{out}");
    assert!(!out.contains("ORIGINAL_MARKER"), "{out}");
}

// ---------- 5. non-2xx on a streaming request ----------

#[test]
fn test_5_streaming_redirect_is_replaced_with_standard_error() {
    let env = env_2019(QuotasConfig::default());
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let mut resp = Response::from_string(format!(
            "<html>internal host build-7 {REAL_DATE}T09:00:00Z</html>"
        ))
        .with_status_code(302);
        resp.add_header(Header::from_bytes(&b"Location"[..], &b"http://10.0.0.7/x"[..]).unwrap());
        req.respond(resp).unwrap();
    });
    let out = expect_status(post(&env, &simple_body(true)), 502);
    common::join_within(h);
    assert!(out.contains("api_error"), "{out}");
    assert!(!out.contains("internal host"), "{out}");
    assert!(!out.contains(REAL_DATE), "{out}");
}

// ---------- 6. type discriminators ----------

#[test]
fn test_6_unknown_type_discriminators_are_rejected_before_upstream() {
    let env = env_2019(QuotasConfig::default());
    let bodies = [
        format!(
            r#"{{"model":"{MODEL}","system":[{{"type":"search_result","text":"x"}}],"messages":[{{"role":"user","content":"Hi"}}]}}"#
        ),
        format!(
            r#"{{"model":"{MODEL}","system":[{{"type":"text","text":"x","cache_control":{{"type":"persistent"}}}}],"messages":[{{"role":"user","content":"Hi"}}]}}"#
        ),
        format!(
            r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t","content":[{{"type":"search_result","text":"x"}}]}}]}}]}}"#
        ),
        format!(
            r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t","content":[{{"type":"picture","source":{{"type":"base64","media_type":"image/png","data":"AA=="}}}}]}}]}}]}}"#
        ),
        format!(r#"{{"model":"{MODEL}","messages":[{{"role":"system","content":"Hi"}}]}}"#),
    ];
    for b in &bodies {
        let out = expect_status(post(&env, b), 400);
        assert!(out.contains("invalid_request_error"), "{b}: {out}");
    }
    match env.mock_server.recv_timeout(Duration::from_millis(300)) {
        Ok(None) => {}
        other => panic!(
            "upstream must receive nothing, got {:?}",
            other.map(|r| r.is_some())
        ),
    }
}

// ---------- 7. no unbounded buffering of an unknown-length response ----------

fn endless_ping_upstream(env: &TestEnv, cap: usize) -> (Arc<AtomicUsize>, thread::JoinHandle<()>) {
    let produced = Arc::new(AtomicUsize::new(0));
    let p = produced.clone();
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let body = CappedProducer {
            chunk: b"event: ping\ndata: {\"type\":\"ping\"}\n\n".to_vec(),
            pos: 0,
            cap,
            produced: p,
            pause: Duration::ZERO,
        };
        let _ = req.respond(Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            body,
            None,
            None,
        ));
    });
    (produced, h)
}

fn raw_stream_request(env: &TestEnv, version: &str, extra: &str) -> TcpStream {
    let body = simple_body(true);
    let mut s = connect(&env.gateway_url);
    let head = format!(
        "POST /v1/messages {version}\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s
}

#[test]
fn test_7_te_identity_does_not_buffer_the_stream() {
    const CAP: usize = 24 * 1024 * 1024;
    let env = env_2019(QuotasConfig::default());
    let (produced, h) = endless_ping_upstream(&env, CAP);
    let mut s = raw_stream_request(&env, "HTTP/1.1", "TE: identity\r\n");
    let mut head = [0u8; 256];
    let n = s.read(&mut head).expect("response head within timeout");
    let at_head = produced.load(Ordering::SeqCst);
    let head = String::from_utf8_lossy(&head[..n]).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        at_head < 16 * 1024 * 1024,
        "gateway buffered {at_head} bytes before answering"
    );
    drop(s);
    common::join_within(h);
}

#[test]
fn test_7_http10_stream_buffering_is_capped() {
    const CAP: usize = 24 * 1024 * 1024;
    let env = env_2019(QuotasConfig::default());
    let (produced, h) = endless_ping_upstream(&env, CAP);
    let mut s = raw_stream_request(&env, "HTTP/1.0", "");
    let out = read_all_bounded(&mut s, 32 * 1024 * 1024);
    common::join_within(h);
    let total = produced.load(Ordering::SeqCst);
    assert!(
        out.is_empty(),
        "expected a bare close, got {} bytes",
        out.len()
    );
    assert!(
        total < 16 * 1024 * 1024,
        "gateway read {total} bytes of an unbounded stream"
    );
}

// ---------- 8. client read deadlines ----------

#[test]
fn test_8_stalled_clients_are_dropped_at_the_deadline_and_service_recovers() {
    let env = TestEnv::new_with_setup(QuotasConfig::default(), t_clock_2019(), None, |g| {
        g.with_request_limits(2, 1024 * 1024)
            .with_client_deadlines(Duration::from_secs(1), Duration::from_secs(1))
    });
    let stall = |declared: usize| {
        let mut s = connect(&env.gateway_url);
        s.write_all(
            format!(
                "POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {declared}\r\n\r\n{{"
            )
            .as_bytes(),
        )
        .unwrap();
        s
    };
    let a = stall(5000);
    let b = stall(5000);
    let deadline = Instant::now() + common::TEST_WAIT;
    while env.gateway_server.in_flight_requests() < 2 {
        assert!(
            Instant::now() < deadline,
            "stalled requests never in flight"
        );
        thread::sleep(Duration::from_millis(10));
    }
    // Both handlers are stalled; they must be freed by the body deadline.
    let start = Instant::now();
    while env.gateway_server.in_flight_requests() > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "stalled bodies still hold handlers after {:?}",
            start.elapsed()
        );
        thread::sleep(Duration::from_millis(20));
    }
    let err = common::test_client()
        .post(&format!("{}/v1/nope", env.gateway_url))
        .send_string("{}")
        .unwrap_err();
    assert!(matches!(err, ureq::Error::Status(404, _)), "{err:?}");
    drop(a);
    drop(b);

    // An unfinished request head is closed at the head deadline.
    let mut s = connect(&env.gateway_url);
    s.write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    let start = Instant::now();
    let out = read_all_bounded(&mut s, 4096);
    assert!(out.is_empty(), "{out}");
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "{:?}",
        start.elapsed()
    );
}

// ---------- 9. quotas enforced while a request runs ----------

#[test]
fn test_9_stream_crossing_token_cap_is_stopped() {
    let env = env_2019(QuotasConfig {
        max_output_tokens: Some(10),
        ..Default::default()
    });
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":50}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"AFTER_BREACH\"}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
            .to_string();
        req.respond(sse_response(sse)).unwrap();
    });
    let out = post(&env, &simple_body(true))
        .expect("stream")
        .into_string()
        .unwrap();
    common::join_within(h);
    assert!(out.contains("rate_limit_error"), "{out}");
    assert!(!out.contains("AFTER_BREACH"), "{out}");
    assert!(!out.contains("message_stop"), "{out}");
    assert!(env.gateway_server.quota().snapshot().limit_exceeded);
}

#[test]
fn test_9_stream_crossing_wall_time_is_stopped() {
    let env = env_2019(QuotasConfig {
        max_wall_time_seconds: Some(2),
        ..Default::default()
    });
    let produced = Arc::new(AtomicUsize::new(0));
    let p = produced.clone();
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        // A large ping (so each one is flushed at once) every 200 ms, for at most ~30 s.
        let chunk = format!(
            "event: ping\ndata: {{\"type\":\"ping\",\"pad\":\"{}\"}}\n\n",
            "p".repeat(9000)
        )
        .into_bytes();
        let cap = chunk.len() * 150;
        let body = CappedProducer {
            chunk,
            pos: 0,
            cap,
            produced: p,
            pause: Duration::from_millis(200),
        };
        let _ = req.respond(Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            body,
            None,
            None,
        ));
    });
    let start = Instant::now();
    let res = post(&env, &simple_body(true)).expect("stream starts before the limit");
    let mut out = String::new();
    let _ = res
        .into_reader()
        .take(64 * 1024 * 1024)
        .read_to_string(&mut out);
    let took = start.elapsed();
    assert!(out.contains("rate_limit_error"), "{out}");
    assert!(
        took < Duration::from_secs(10),
        "stream ran {took:?} past the wall limit"
    );
    assert!(env.gateway_server.quota().snapshot().limit_exceeded);
    common::join_within(h);
}

// ---------- 10. write half-close does not free the slot early ----------

#[test]
fn test_10_half_close_does_not_let_upstream_concurrency_exceed_one() {
    let env = env_2019(QuotasConfig {
        max_concurrent_requests: Some(1),
        ..Default::default()
    });
    let active = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let (a2, m2) = (active.clone(), max_seen.clone());
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let req = common::recv_upstream(&mock);
            let now = a2.fetch_add(1, Ordering::SeqCst) + 1;
            m2.fetch_max(now, Ordering::SeqCst);
            let a3 = a2.clone();
            workers.push(thread::spawn(move || {
                thread::sleep(Duration::from_secs(1));
                a3.fetch_sub(1, Ordering::SeqCst);
                req.respond(Response::from_string(
                    r#"{"id":"m","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
                ))
                .unwrap();
            }));
        }
        for w in workers {
            common::join_within(w);
        }
    });

    let body = simple_body(false);
    let mut a = connect(&env.gateway_url);
    a.write_all(
        format!(
            "POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    a.shutdown(Shutdown::Write).unwrap();
    thread::sleep(Duration::from_millis(300));

    let res_b = post(&env, &body).expect("second request served after the first ends");
    assert_eq!(res_b.status(), 200);
    let out_a = read_all_bounded(&mut a, 64 * 1024);
    assert!(
        out_a.starts_with("HTTP/1.1 200"),
        "half-closed client still gets its reply: {out_a}"
    );
    common::join_within(h);
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "upstream concurrency exceeded 1"
    );
    assert!(!env.gateway_server.quota().snapshot().limit_exceeded);
}

// ---------- 11. host log file safety ----------

fn mkfifo(path: &std::path::Path) {
    let st = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo");
    assert!(st.success());
}

#[test]
fn test_11_log_refuses_symlinks_and_fifos_and_is_private() {
    let tmp = tempfile::TempDir::new().unwrap();
    let outside = tmp.path().join("outside.txt");
    std::fs::write(&outside, b"keep").unwrap();

    // Leaf symlink.
    let d1 = tmp.path().join("d1");
    std::fs::create_dir(&d1).unwrap();
    std::os::unix::fs::symlink(&outside, d1.join("gateway.jsonl")).unwrap();
    assert!(HostLogger::new(&d1).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");

    // Ancestor symlink.
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();
    assert!(HostLogger::new(tmp.path().join("link").join("logs")).is_err());
    assert!(!real.join("logs").exists());

    // FIFO: refused without blocking.
    let d2 = tmp.path().join("d2");
    std::fs::create_dir(&d2).unwrap();
    mkfifo(&d2.join("gateway.jsonl"));
    let d2c = d2.clone();
    let h = thread::spawn(move || HostLogger::new(&d2c).is_err());
    assert!(common::join_within(h), "FIFO must be refused");

    // New file 0600; an existing 0644 file is reset to 0600.
    let d3 = tmp.path().join("d3").join("nested");
    HostLogger::new(&d3).unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&d3.join("gateway.jsonl")), 0o600);
    let d4 = tmp.path().join("d4");
    std::fs::create_dir(&d4).unwrap();
    std::fs::write(d4.join("gateway.jsonl"), b"").unwrap();
    std::fs::set_permissions(
        d4.join("gateway.jsonl"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    HostLogger::new(&d4).unwrap();
    assert_eq!(mode(&d4.join("gateway.jsonl")), 0o600);
}

// ---------- 12. config and key reads ----------

#[test]
fn test_12_config_and_key_reads_are_capped_and_regular_only() {
    use hermetic_gateway::config::GatewayConfig;
    let tmp = tempfile::TempDir::new().unwrap();
    let write_config = |name: &str, key_path: &std::path::Path| {
        let p = tmp.path().join(name);
        std::fs::write(
            &p,
            serde_json::json!({
                "anthropic_version": "2023-06-01",
                "pinned_models": [MODEL],
                "log_dir": tmp.path().join("logs"),
                "api_key_file": key_path,
            })
            .to_string(),
        )
        .unwrap();
        p
    };
    let good_key = tmp.path().join("key");
    std::fs::write(&good_key, b"sk-test").unwrap();
    assert!(GatewayConfig::load_from_file(write_config("ok.json", &good_key)).is_ok());

    let big_key = tmp.path().join("bigkey");
    std::fs::write(&big_key, vec![b'k'; 20 * 1024]).unwrap();
    assert!(GatewayConfig::load_from_file(write_config("c1.json", &big_key)).is_err());

    let link_key = tmp.path().join("linkkey");
    std::os::unix::fs::symlink(&good_key, &link_key).unwrap();
    assert!(GatewayConfig::load_from_file(write_config("c2.json", &link_key)).is_err());

    let zero = std::path::PathBuf::from("/dev/zero");
    let c3 = write_config("c3.json", &zero);
    let h = thread::spawn(move || GatewayConfig::load_from_file(c3).is_err());
    assert!(common::join_within(h), "/dev/zero must be refused");

    let fifo_key = tmp.path().join("fifokey");
    mkfifo(&fifo_key);
    let c4 = write_config("c4.json", &fifo_key);
    let h = thread::spawn(move || GatewayConfig::load_from_file(c4).is_err());
    assert!(common::join_within(h), "FIFO key must be refused");

    let ok_cfg = tmp.path().join("ok.json");
    let link_cfg = tmp.path().join("linkcfg.json");
    std::os::unix::fs::symlink(&ok_cfg, &link_cfg).unwrap();
    assert!(GatewayConfig::load_from_file(&link_cfg).is_err());

    let big_cfg = tmp.path().join("big.json");
    let mut f = std::fs::File::create(&big_cfg).unwrap();
    f.write_all(&vec![b' '; 2 * 1024 * 1024]).unwrap();
    assert!(GatewayConfig::load_from_file(&big_cfg).is_err());
}

// ---------- 13. host log budget ----------

#[test]
fn test_13_host_log_is_bounded_by_its_budget() {
    let env = TestEnv::new_with_setup(QuotasConfig::default(), t_clock_2019(), None, |g| {
        g.with_host_log_budget(4096).expect("logger")
    });
    let client = common::test_client();
    for _ in 0..60 {
        match client
            .post(&format!("{}/v1/nope", env.gateway_url))
            .send_string("{}")
        {
            Err(ureq::Error::Status(404, _)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let size = std::fs::metadata(env.temp_dir.path().join("logs").join("gateway.jsonl"))
        .unwrap()
        .len();
    assert!(size <= 4096, "log grew to {size} bytes");
    // Once the log cannot be written the gateway refuses to serve.
    assert!(env.gateway_server.quota().snapshot().limit_exceeded);
    let out = expect_status(post(&env, &simple_body(false)), 429);
    assert!(out.contains("rate_limit_error"), "{out}");
    match env.mock_server.recv_timeout(Duration::from_millis(200)) {
        Ok(None) => {}
        _ => panic!("upstream must not be called after the log budget is exhausted"),
    }
}

// ---------- 14. history state bound ----------

#[test]
fn test_14_history_state_is_bounded() {
    let h = HistoryLog::with_capacity(8);
    for i in 0..200u32 {
        let msg = format!("{{\"role\":\"user\",\"content\":\"conversation {i}\"}}").into_bytes();
        h.check_and_record(b"sys", &[msg]);
        assert!(h.tip_count() <= 8, "history holds {} tips", h.tip_count());
    }
    assert_eq!(HistoryLog::new().tip_count(), 0);
}

// ---------- 15. API key never reaches the host log ----------

#[test]
fn test_15_echoed_api_key_is_redacted_in_host_log() {
    let env = env_2019(QuotasConfig::default());
    let key = env.api_key.clone();
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let got = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("x-api-key"))
            .map(|h| h.value.as_str().to_string())
            .unwrap_or_default();
        let mut resp = Response::from_string(format!(
            r#"{{"type":"error","error":{{"type":"invalid_request_error","message":"bad key {got}"}}}}"#
        ))
        .with_status_code(400);
        resp.add_header(Header::from_bytes(&b"x-echo-key"[..], got.as_bytes()).unwrap());
        req.respond(resp).unwrap();
    });
    let out = expect_status(post(&env, &simple_body(false)), 400);
    common::join_within(h);
    assert!(!out.contains(&key));
    let log =
        std::fs::read_to_string(env.temp_dir.path().join("logs").join("gateway.jsonl")).unwrap();
    assert!(!log.contains(&key), "API key in host log: {log}");
    assert!(log.contains("<redacted>"), "{log}");
}

// ---------- prior-check follow-ups (2, 6, 8, 9, 10) ----------

#[test]
fn test_2b_tool_input_exemption_only_at_tool_content_locations() {
    let clock = GuestClock::frozen(t_clock_2019(), Duration::from_secs(0));
    // The reviewer's case: a tool_use-shaped object outside message content.
    let mut v: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"metadata":{{"type":"tool_use","input":{{"created_at":"{REAL_DATE}T00:00:00Z"}}}}}}"#
    ))
    .unwrap();
    rewrite_json_timestamps(&mut v, &clock);
    assert!(!v.to_string().contains(REAL_DATE), "{v}");

    // Nested deeper inside a content block's other fields: still rewritten.
    let mut v: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"content":[{{"type":"text","text":"x","extra":{{"type":"tool_use","input":{{"created_at":"{REAL_DATE}T00:00:00Z"}}}}}}]}}"#
    ))
    .unwrap();
    rewrite_json_timestamps(&mut v, &clock);
    assert!(!v.to_string().contains(REAL_DATE), "{v}");

    // The validated locations keep tool input unchanged.
    let mut start: serde_json::Value = serde_json::from_str(
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"n","input":{"created_at":1700000000}}}"#,
    )
    .unwrap();
    rewrite_json_timestamps(&mut start, &clock);
    assert_eq!(start["content_block"]["input"]["created_at"], 1700000000);
    let mut msg_start: serde_json::Value = serde_json::from_str(
        r#"{"type":"message_start","message":{"content":[{"type":"tool_use","id":"t","name":"n","input":{"created_at":1700000000}}]}}"#,
    )
    .unwrap();
    rewrite_json_timestamps(&mut msg_start, &clock);
    assert_eq!(
        msg_start["message"]["content"][0]["input"]["created_at"],
        1700000000
    );
    // But not a `content_block` outside a content_block_start event.
    let mut other: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"type":"something_else","content_block":{{"type":"tool_use","input":{{"created_at":"{REAL_DATE}T00:00:00Z"}}}}}}"#
    ))
    .unwrap();
    rewrite_json_timestamps(&mut other, &clock);
    assert!(!other.to_string().contains(REAL_DATE), "{other}");
}

#[test]
fn test_6b_nested_typed_blocks_reject_unknown_fields() {
    let env = env_2019(QuotasConfig::default());
    let img = r#"{"type":"base64","media_type":"image/png","data":"AA=="}"#;
    let bodies = [
        format!(
            r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t","content":[{{"type":"image","source":{img},"unexpected":true}}]}}]}}]}}"#
        ),
        format!(
            r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t","content":[{{"type":"text","text":"x","unexpected":true}}]}}]}}]}}"#
        ),
        format!(
            r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":[{{"type":"image","source":{img},"unexpected":true}}]}}]}}"#
        ),
        format!(
            r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":[{{"type":"text","text":"x","cache_control":{{"type":"ephemeral","unexpected":1}}}}]}}]}}"#
        ),
    ];
    for b in &bodies {
        let out = expect_status(post(&env, b), 400);
        assert!(out.contains("invalid_request_error"), "{b}: {out}");
    }
    match env.mock_server.recv_timeout(Duration::from_millis(300)) {
        Ok(None) => {}
        other => panic!(
            "upstream must receive nothing, got {:?}",
            other.map(|r| r.is_some())
        ),
    }
}

#[test]
fn test_8b_slow_readers_are_dropped_at_the_write_deadline_and_service_recovers() {
    let env = TestEnv::new_with_setup(QuotasConfig::default(), t_clock_2019(), None, |g| {
        g.with_request_limits(2, 1024 * 1024)
            .with_response_write_deadlines(Duration::from_secs(1), Duration::from_secs(1))
    });
    // Upstream: a 20 MiB non-streaming reply (more than loopback socket buffers hold) and an
    // endless (capped) stream; neither client reads.
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let req = common::recv_upstream(&mock);
            workers.push(thread::spawn(move || {
                let mut req = req;
                let mut body = String::new();
                let _ = req.as_reader().take(1024 * 1024).read_to_string(&mut body);
                if body.contains("\"stream\":true") {
                    let produced = Arc::new(AtomicUsize::new(0));
                    let p = CappedProducer {
                        chunk: b"event: ping\ndata: {\"type\":\"ping\"}\n\n".to_vec(),
                        pos: 0,
                        cap: 24 * 1024 * 1024,
                        produced,
                        pause: Duration::ZERO,
                    };
                    let _ = req.respond(Response::new(
                        200.into(),
                        vec![
                            Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..])
                                .unwrap(),
                        ],
                        p,
                        None,
                        None,
                    ));
                } else {
                    let big = format!(
                        "{{\"id\":\"m\",\"type\":\"message\",\"content\":[],\"pad\":\"{}\"}}",
                        "x".repeat(20 * 1024 * 1024)
                    );
                    let _ = req.respond(Response::from_string(big));
                }
            }));
        }
        for w in workers {
            common::join_within(w);
        }
    });

    let send = |stream: bool| {
        let body = simple_body(stream);
        let mut s = connect(&env.gateway_url);
        s.write_all(
            format!(
                "POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
        s
    };
    let a = send(false);
    let b = send(true);
    let deadline = Instant::now() + common::TEST_WAIT;
    while env.gateway_server.in_flight_requests() < 2 {
        assert!(Instant::now() < deadline, "slow readers never in flight");
        thread::sleep(Duration::from_millis(10));
    }
    // Neither client reads; both handlers must be freed by the write deadlines.
    let start = Instant::now();
    while env.gateway_server.in_flight_requests() > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "slow readers still hold handlers after {:?}",
            start.elapsed()
        );
        thread::sleep(Duration::from_millis(20));
    }
    let err = common::test_client()
        .post(&format!("{}/v1/nope", env.gateway_url))
        .send_string("{}")
        .unwrap_err();
    assert!(matches!(err, ureq::Error::Status(404, _)), "{err:?}");
    drop(a);
    drop(b);
    common::join_within(h);
}

/// Yields `first`, then waits (bounded) until `gate` reaches `n`, pauses, then yields `second`.
struct TwoPhase {
    first: Cursor<Vec<u8>>,
    second: Cursor<Vec<u8>>,
    gate: Arc<AtomicUsize>,
    n: usize,
    counted: bool,
}

impl Read for TwoPhase {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.first.read(buf)?;
        if k > 0 {
            return Ok(k);
        }
        if !self.counted {
            self.counted = true;
            self.gate.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.gate.load(Ordering::SeqCst) < self.n && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            thread::sleep(Duration::from_millis(500));
        }
        self.second.read(buf)
    }
}

#[test]
fn test_9b_concurrent_streams_share_the_token_cap() {
    let env = env_2019(QuotasConfig {
        max_output_tokens: Some(10),
        ..Default::default()
    });
    let pad = "p".repeat(10_000); // large events, so each is flushed to the gateway at once
    let gate = Arc::new(AtomicUsize::new(0));
    let mock = env.mock_server.clone();
    let mock_pad = pad.clone();
    let h = thread::spawn(move || {
        let mut workers = Vec::new();
        for i in 0..2 {
            let req = common::recv_upstream(&mock);
            let gate = gate.clone();
            let pad = mock_pad.clone();
            workers.push(thread::spawn(move || {
                // The event, then a long comment so the mock's chunked writer flushes the
                // whole event before this stream pauses (the gateway drops comments).
                let first = format!(
                    "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"m{i}\",\"usage\":{{\"input_tokens\":1,\"output_tokens\":6}}}}}}\n\n: {pad}{pad}\n\n"
                );
                let second = format!(
                    "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"AFTER_BREACH_{i}{pad}\"}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
                );
                let body = TwoPhase {
                    first: Cursor::new(first.into_bytes()),
                    second: Cursor::new(second.into_bytes()),
                    gate,
                    n: 2,
                    counted: false,
                };
                let _ = req.respond(Response::new(
                    200.into(),
                    vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..])
                        .unwrap()],
                    body,
                    None,
                    None,
                ));
            }));
        }
        for w in workers {
            common::join_within(w);
        }
    });

    let url = env.gateway_url.clone();
    let clients: Vec<_> = (0..2)
        .map(|_| {
            let url = url.clone();
            thread::spawn(move || {
                let res = common::test_client()
                    .post(&format!("{url}/v1/messages"))
                    .set("anthropic-version", "2023-06-01")
                    .set("content-type", "application/json")
                    .send_string(&simple_body(true));
                match res {
                    Ok(r) => {
                        let mut out = String::new();
                        let _ = r.into_reader().take(1024 * 1024).read_to_string(&mut out);
                        out
                    }
                    Err(e) => format!("ERR {e}"),
                }
            })
        })
        .collect();
    let outs: Vec<String> = clients.into_iter().map(common::join_within).collect();
    common::join_within(h);
    for out in &outs {
        assert!(
            !out.contains("AFTER_BREACH"),
            "stream continued past the shared cap"
        );
        assert!(
            out.contains("rate_limit_error"),
            "stream not stopped: {}",
            &out[..out.len().min(300)]
        );
    }
    let snap = env.gateway_server.quota().snapshot();
    assert!(snap.limit_exceeded, "{snap:?}");
}

#[test]
fn test_10b_waiting_past_the_drain_deadline_gets_bounded_529() {
    let env = TestEnv::new_with_setup(
        QuotasConfig {
            max_concurrent_requests: Some(1),
            ..Default::default()
        },
        t_clock_2019(),
        None,
        |g| g.with_drain_wait(Duration::from_secs(1)),
    );
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        // Only the first request ever reaches upstream; it is held past the drain deadline.
        let req = common::recv_upstream(&mock);
        thread::sleep(Duration::from_secs(4));
        req.respond(Response::from_string(
            r#"{"id":"m","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
        ))
        .unwrap();
    });

    let body = simple_body(false);
    let mut a = connect(&env.gateway_url);
    a.write_all(
        format!(
            "POST /v1/messages HTTP/1.1\r\nHost: x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    a.shutdown(Shutdown::Write).unwrap();
    thread::sleep(Duration::from_millis(300));

    let start = Instant::now();
    let out = expect_status(post(&env, &body), 529);
    let waited = start.elapsed();
    assert!(out.contains("overloaded_error"), "{out}");
    assert!(
        waited < Duration::from_secs(3),
        "wait not bounded: {waited:?}"
    );
    let snap = env.gateway_server.quota().snapshot();
    assert_eq!(snap.concurrent_requests, 1, "slot must stay held: {snap:?}");
    assert!(!snap.limit_exceeded, "{snap:?}");
    match env.mock_server.recv_timeout(Duration::from_millis(200)) {
        Ok(None) => {}
        _ => panic!("a second upstream call was made"),
    }
    common::join_within(h);
    let out_a = read_all_bounded(&mut a, 64 * 1024);
    assert!(out_a.starts_with("HTTP/1.1 200"), "{out_a}");
}
