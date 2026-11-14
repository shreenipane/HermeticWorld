//! D12 real-date sentinel (TR-SEC-5) in the gateway: agent requests and every forwarded
//! upstream response are scanned; the summary is counts only and fails closed on caps.

mod common;

use common::TestEnv;
use hermetic_gateway::config::{DateSentinelConfig, GatewayConfig};
use hermetic_gateway::quota::QuotasConfig;
use hermetic_gateway::server::{GatewayServer, DATE_SENTINEL_FILE};
use hermetic_sealcheck::d12::D12Options;
use hermetic_sealcheck::d12_runtime::{DateSentinel, SentinelSummary};
use std::io::{Cursor, Read};
use std::thread;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};
use tiny_http::{Header, Response};

const MODEL: &str = "claude-3-5-sonnet-20241022";

/// Far from the test T_clock (2026-11-11), so guest-time rewrites never count as hits.
fn real_date() -> Date {
    Date::from_calendar_date(2030, Month::June, 15).unwrap()
}

fn opts() -> D12Options {
    D12Options {
        real_date: real_date(),
        tolerance_days: 1,
        host_names: vec!["buildhost-7".into()],
        host_paths: vec!["/srv/hostonly".into()],
    }
}

fn env() -> TestEnv {
    let t_clock = OffsetDateTime::parse("2026-11-11T12:00:00Z", &Rfc3339).unwrap();
    TestEnv::new_with_setup(QuotasConfig::default(), t_clock, None, |g| {
        g.with_date_sentinel(opts()).unwrap()
    })
}

fn env_with(sentinel: DateSentinel) -> TestEnv {
    let t_clock = OffsetDateTime::parse("2026-11-11T12:00:00Z", &Rfc3339).unwrap();
    TestEnv::new_with_setup(QuotasConfig::default(), t_clock, None, move |g| {
        g.with_date_sentinel_instance(sentinel)
    })
}

fn json_ok(body: &str) -> Response<Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_status_code(200)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
}

const CLEAN_REPLY: &str = r#"{"id":"m1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}"#;

fn request_body(content: &str) -> String {
    serde_json::json!({
        "model": MODEL,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": content}],
    })
    .to_string()
}

fn post(env: &TestEnv, body: &[u8]) -> (u16, String) {
    let res = common::test_client()
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_bytes(body);
    let res = match res {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("transport error: {e}"),
    };
    let status = res.status();
    let mut text = String::new();
    res.into_reader().read_to_string(&mut text).unwrap();
    (status, text)
}

/// Spawns a mock upstream answering one request with `resp`.
fn mock_once(env: &TestEnv, resp: Response<Cursor<Vec<u8>>>) -> thread::JoinHandle<String> {
    let mock = env.mock_server.clone();
    thread::spawn(move || {
        let mut req = common::recv_upstream(&mock);
        let mut sent = String::new();
        req.as_reader().read_to_string(&mut sent).unwrap();
        req.respond(resp).unwrap();
        sent
    })
}

/// Waits for the persisted summary file to satisfy `pred`.
fn wait_file(env: &TestEnv, pred: impl Fn(&SentinelSummary) -> bool) -> (SentinelSummary, String) {
    let path = env.temp_dir.path().join("logs").join(DATE_SENTINEL_FILE);
    let deadline = Instant::now() + common::TEST_WAIT;
    loop {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(s) = serde_json::from_str::<SentinelSummary>(&raw) {
                if pred(&s) {
                    return (s, raw);
                }
            }
        }
        assert!(Instant::now() < deadline, "summary never matched");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn gw_d12_clean_exchange_records_no_leak() {
    let env = env();
    let h = mock_once(&env, json_ok(CLEAN_REPLY));
    let (status, _) = post(&env, request_body("hello on 2026-11-11").as_bytes());
    assert_eq!(status, 200);
    common::join_within(h);
    let (s, _) = wait_file(&env, |s| s.bytes_scanned > 0);
    assert!(!s.date_leak_observed);
    assert!(!s.scan_incomplete);
    assert!(s.hits.is_empty());
}

#[test]
fn gw_d12_agent_prompt_with_real_date_is_recorded_without_echo() {
    let env = env();
    let h = mock_once(&env, json_ok(CLEAN_REPLY));
    let (status, _) = post(
        &env,
        request_body("today is 2030-06-15 on buildhost-7 in /srv/hostonly/x").as_bytes(),
    );
    assert_eq!(status, 200, "the sentinel records; it does not block");
    common::join_within(h);
    let (s, raw) = wait_file(&env, |s| s.date_leak_observed);
    assert!(s.hits.contains_key("agent_request:real_date"));
    assert!(s.hits.contains_key("agent_request:host_name"));
    assert!(s.hits.contains_key("agent_request:host_path"));
    assert!(!raw.contains("2030-06-15") && !raw.contains("buildhost") && !raw.contains("/srv"));
    let logs = std::fs::read_to_string(env.temp_dir.path().join("logs/gateway.jsonl")).unwrap();
    assert!(
        !logs.contains("buildhost"),
        "host log must not echo matches"
    );
}

#[test]
fn gw_d12_json_escaped_date_in_prompt_detected() {
    let env = env();
    let h = mock_once(&env, json_ok(CLEAN_REPLY));
    // A digit and each hyphen sent as JSON \u escapes.
    let body = format!(
        r#"{{"model":"{MODEL}","max_tokens":16,"messages":[{{"role":"user","content":"d=2030-06-15"}}]}}"#
    );
    let (status, _) = post(&env, body.as_bytes());
    assert_eq!(status, 200);
    common::join_within(h);
    let (s, _) = wait_file(&env, |s| s.date_leak_observed);
    assert!(s.hits.contains_key("agent_request:real_date"));
}

#[test]
fn gw_d12_refused_non_utf8_request_still_scanned() {
    let env = env();
    let mut body = b"{\"x\":\"June 15, 2030 ".to_vec();
    body.push(0xff);
    body.extend_from_slice(b"\"}");
    let (status, _) = post(&env, &body);
    assert_eq!(status, 400);
    let (s, _) = wait_file(&env, |s| s.date_leak_observed);
    assert!(s.hits.contains_key("agent_request:real_date"));
}

#[test]
fn gw_d12_upstream_json_response_scanned() {
    let env = env();
    let reply = r#"{"id":"m1","type":"message","role":"assistant","content":[{"type":"text","text":"It is Sat, 15 Jun 2030 10:00:00 GMT"}],"usage":{"input_tokens":1,"output_tokens":1}}"#;
    let h = mock_once(&env, json_ok(reply));
    let (status, _) = post(&env, request_body("hi").as_bytes());
    assert_eq!(status, 200);
    common::join_within(h);
    let (s, _) = wait_file(&env, |s| s.date_leak_observed);
    assert!(s.hits.contains_key("upstream_response:real_date"));
    assert!(!s.hits.keys().any(|k| k.starts_with("agent_request")));
}

#[test]
fn gw_d12_upstream_error_body_scanned() {
    let env = env();
    let err = r#"{"type":"error","error":{"type":"api_error","message":"failed on buildhost-7"}}"#;
    let h = mock_once(&env, json_ok(err).with_status_code(500));
    let (status, text) = post(&env, request_body("hi").as_bytes());
    assert_eq!(status, 500);
    common::join_within(h);
    // Whatever the sanitiser forwards is scanned: a host name reaching the agent is recorded.
    let (s, _) = wait_file(&env, |s| s.bytes_scanned > 0);
    assert_eq!(
        text.contains("buildhost-7"),
        s.hits.contains_key("upstream_response:host_name"),
        "{text}"
    );
}

fn sse_delta(text: &str) -> String {
    format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
    )
}

fn stream_reply(deltas: &[&str]) -> String {
    let mut s = String::from(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
    );
    for d in deltas {
        s.push_str(&sse_delta(d));
    }
    s.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    s
}

/// Reader handing out a few bytes per read, so the stream arrives in many chunks.
struct Dribble(Cursor<Vec<u8>>);
impl Read for Dribble {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(5);
        self.0.read(&mut buf[..n])
    }
}

fn post_stream(env: &TestEnv, payload: String) -> String {
    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Dribble(Cursor::new(payload.into_bytes())),
            None,
            None,
        );
        req.respond(resp).unwrap();
    });
    let body = serde_json::json!({
        "model": MODEL, "max_tokens": 16, "stream": true,
        "messages": [{"role": "user", "content": "hi"}],
    })
    .to_string();
    let (status, text) = post(env, body.as_bytes());
    assert_eq!(status, 200);
    common::join_within(h);
    text
}

#[test]
fn gw_d12_sse_date_split_across_deltas_detected() {
    let env = env();
    let text = post_stream(
        &env,
        stream_reply(&["The date is 2030-", "06-", "15 today"]),
    );
    assert!(text.contains("message_stop"));
    let (s, _) = wait_file(&env, |s| s.date_leak_observed);
    assert!(s.hits.contains_key("upstream_stream:real_date"));
}

#[test]
fn gw_d12_sse_clean_stream_not_flagged() {
    let env = env();
    post_stream(
        &env,
        stream_reply(&["The date is 2026-", "11-", "11 today"]),
    );
    let (s, _) = wait_file(&env, |s| s.bytes_scanned > 0);
    assert!(!s.date_leak_observed, "{s:?}");
}

#[test]
fn gw_d12_byte_cap_fails_closed() {
    let env = env_with(DateSentinel::with_max_bytes(opts(), 32).unwrap());
    let h = mock_once(&env, json_ok(CLEAN_REPLY));
    let (status, _) = post(
        &env,
        request_body("a clean but long enough prompt").as_bytes(),
    );
    assert_eq!(status, 200);
    common::join_within(h);
    let (s, _) = wait_file(&env, |s| s.scan_incomplete);
    assert!(s.date_leak_observed);
    assert!(s.incomplete.keys().any(|k| k.ends_with(":run_byte_cap")));
}

#[test]
fn gw_d12_option_cap_refuses_start() {
    let dir = tempfile::TempDir::new().unwrap();
    let key = dir.path().join("k");
    std::fs::write(&key, "k").unwrap();
    let cfg = GatewayConfig::from_raw(
        "http://127.0.0.1:9".into(),
        "2023-06-01".into(),
        vec![],
        vec![MODEL.into()],
        QuotasConfig::default(),
        dir.path().join("logs"),
        key,
        "k".into(),
    )
    .with_date_sentinel(DateSentinelConfig {
        host_names: vec!["h".into(); 10_001],
        host_paths: vec![],
        tolerance_days: 1,
    });
    let t = OffsetDateTime::parse("2026-11-11T12:00:00Z", &Rfc3339).unwrap();
    let err = GatewayServer::new(cfg, t).err().expect("must refuse");
    assert!(err.contains("date sentinel"), "{err}");
}

#[test]
fn gw_d12_config_debug_hides_host_data() {
    let cfg = DateSentinelConfig {
        host_names: vec!["buildhost-7".into()],
        host_paths: vec!["/srv/hostonly".into()],
        tolerance_days: 1,
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("buildhost") && !dbg.contains("hostonly"));
}
