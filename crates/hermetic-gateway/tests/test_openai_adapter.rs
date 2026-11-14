use hermetic_gateway::{config::GatewayConfig, openai, GatewayServer};
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

fn base_request(stream: bool) -> Value {
    json!({"model":"pinned","max_tokens":128,"stream":stream,"system":"world",
        "messages":[{"role":"user","content":"fix"}],
        "tools":[{"name":"bash","input_schema":{"type":"object","properties":{"command":{"type":"string"}}}}]})
}

struct Fixture {
    _dir: tempfile::TempDir,
    gateway: Arc<GatewayServer>,
    worker: Option<std::thread::JoinHandle<()>>,
    upstream: Arc<tiny_http::Server>,
    url: String,
    log_path: std::path::PathBuf,
}
impl Fixture {
    fn new(output_cap: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        std::fs::write(&key, "fake-private-key").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let upstream = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let config_path = dir.path().join("gateway.json");
        std::fs::write(
            &config_path,
            json!({"upstream_protocol":"openai_chat",
            "upstream_base_url":format!("http://{}",upstream.server_addr()),
            "anthropic_version":"2023-06-01","pinned_models":["pinned"],
            "api_key_file":key,"log_dir":dir.path().join("logs"),
            "quotas":{"max_output_tokens":output_cap}})
            .to_string(),
        )
        .unwrap();
        let config = GatewayConfig::load_from_file(config_path).unwrap();
        let clock = time::OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap();
        let gateway = Arc::new(GatewayServer::new(config, clock).unwrap());
        let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", http.server_addr());
        let g = gateway.clone();
        let worker = Some(std::thread::spawn(move || g.run_loop(http)));
        let log_path = dir.path().join("logs/gateway.jsonl");
        Self {
            _dir: dir,
            gateway,
            worker,
            upstream,
            url,
            log_path,
        }
    }
    fn post(&self, value: &Value) -> ureq::Response {
        let response = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .post(&format!("{}/v1/messages", self.url))
            .set("content-type", "application/json")
            .set("anthropic-version", "2023-06-01")
            .send_string(&value.to_string());
        match response {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("request failed: {e}"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.gateway.stop();
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn chat_translation_preserves_nonce_tools_results_and_usage() {
    let fixture = Fixture::new(1000);
    let upstream = fixture.upstream.clone();
    let server = std::thread::spawn(move || {
        let mut req = upstream
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(req.url(), "/chat/completions");
        assert!(req.headers().iter().any(
            |h| h.field.equiv("authorization") && h.value.as_str() == "Bearer fake-private-key"
        ));
        assert!(!req.headers().iter().any(|h| h.field.equiv("x-api-key")));
        let mut raw = String::new();
        req.as_reader().read_to_string(&mut raw).unwrap();
        let request: Value = serde_json::from_str(&raw).unwrap();
        assert!(request["messages"][0]["content"]
            .as_str()
            .unwrap()
            .starts_with("[run-nonce "));
        assert_eq!(
            request["messages"][2]["tool_calls"][0]["function"]["arguments"],
            r#"{"command":"true"}"#
        );
        assert_eq!(
            request["messages"][3],
            json!({"role":"tool","tool_call_id":"call0","content":"ok"})
        );
        assert_eq!(request["tools"][0]["type"], "function");
        req.respond(tiny_http::Response::from_string(json!({"id":"host-identity","created":9999999999u64,
            "model":"host-model","choices":[{"index":0,"message":{"role":"assistant","content":null,
                "tool_calls":[{"id":"host-id","type":"function","function":{"name":"bash","arguments":"{\"command\":\"true\"}"}}]},
                "finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":11},"host":"host-identity"}).to_string())
            .with_header(tiny_http::Header::from_bytes("x-host","host-identity").unwrap())
            .with_header(tiny_http::Header::from_bytes("Date","Tue, 01 Jan 2030 00:00:00 GMT").unwrap())).unwrap();
    });
    let mut request = base_request(false);
    request["messages"] = json!([{"role":"user","content":"fix"},
        {"role":"assistant","content":[{"type":"tool_use","id":"call0","name":"bash","input":{"command":"true"}}]},
        {"role":"user","content":[{"type":"tool_result","tool_use_id":"call0","content":"ok"}]}]);
    let response = fixture.post(&request);
    assert_eq!(response.status(), 200);
    assert!(response.header("x-host").is_none());
    assert!(!response.header("date").unwrap().contains("2030"));
    let body = response.into_string().unwrap();
    assert!(!body.contains("host-"));
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body["content"][0],
        json!({"type":"tool_use","id":"toolu_0","name":"bash","input":{"command":"true"}})
    );
    assert_eq!(body["usage"], json!({"input_tokens":7,"output_tokens":11}));
    assert_eq!(body["stop_reason"], "tool_use");
    server.join().unwrap();
}

#[test]
fn chat_path_retains_hard_token_caps() {
    let fixture = Fixture::new(2);
    let upstream = fixture.upstream.clone();
    let worker = std::thread::spawn(move || {
        let req = upstream
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        req.respond(tiny_http::Response::from_string(
            json!({"choices":[{"index":0,"message":{"role":"assistant","content":"secret-result"},
            "finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":3}})
            .to_string(),
        ))
        .unwrap();
    });
    let response = fixture.post(&base_request(false));
    assert_eq!(response.status(), 429);
    assert!(!response.into_string().unwrap().contains("secret-result"));
    worker.join().unwrap();
}

#[test]
fn chat_sse_uses_gateway_sanitizer_and_hard_token_accounting() {
    for cap in [1000, 2] {
        let fixture = Fixture::new(cap);
        let upstream = fixture.upstream.clone();
        let worker = std::thread::spawn(move || {
            let mut req = upstream
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap();
            let mut request = String::new();
            req.as_reader().read_to_string(&mut request).unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["stream_options"], json!({"include_usage":true}));
            let frames = [
                json!({"host":"host-secret","created":9999999999u64,"choices":[{"index":0,
                    "delta":{"content":"hello"},"finish_reason":null}]}),
                json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
                json!({"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":4}}),
            ];
            let raw = frames
                .iter()
                .map(|v| format!("data: {v}\n\n"))
                .collect::<String>()
                + "data: [DONE]\n\n";
            req.respond(tiny_http::Response::from_string(raw).with_header(
                tiny_http::Header::from_bytes("Content-Type", "text/event-stream").unwrap(),
            ))
            .unwrap();
        });
        let response = fixture.post(&base_request(true));
        assert_eq!(response.status(), 200);
        assert_eq!(response.header("content-type"), Some("text/event-stream"));
        let body = response.into_string().unwrap();
        assert!(!body.contains("host-secret") && !body.contains("9999999999"));
        if cap == 2 {
            assert!(body.contains("rate_limit_error"));
            assert!(!body.contains("message_stop"));
        } else {
            assert!(body.contains("message_stop"));
            assert!(body.contains("\"output_tokens\":4"));
        }
        worker.join().unwrap();
    }
}

#[test]
fn upstream_errors_are_standard_and_key_redacted_in_log() {
    let fixture = Fixture::new(1000);
    let upstream = fixture.upstream.clone();
    let worker = std::thread::spawn(move || {
        let req = upstream
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        req.respond(
            tiny_http::Response::from_string("host-date fake-private-key").with_status_code(500),
        )
        .unwrap();
    });
    let response = fixture.post(&base_request(false));
    assert_eq!(response.status(), 500);
    let body = response.into_string().unwrap();
    assert!(!body.contains("host-date") && !body.contains("fake-private-key"));
    worker.join().unwrap();
    let log = std::fs::read_to_string(&fixture.log_path).unwrap();
    assert!(!log.contains("fake-private-key"));
    assert!(log.contains(openai::ADAPTER_VERSION));
}

#[test]
fn sse_translates_incremental_text_tools_and_usage_without_metadata() {
    let frames = [
        json!({"id":"host-secret","created":9999999999u64,"choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"host-id","type":"function","function":{"name":"bash","arguments":"{\"command\":"}}]},"finish_reason":null}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"true\"}"}}]},"finish_reason":"tool_calls"}]}),
        json!({"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":4}}),
    ];
    let raw = frames
        .iter()
        .map(|v| format!("data: {v}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    let mut reader = openai::SseReader::new(Box::new(Cursor::new(raw)), "pinned".into());
    let mut out = String::new();
    reader.read_to_string(&mut out).unwrap();
    assert!(!out.contains("host-") && !out.contains("9999999999"));
    assert!(out.contains("text_delta") && out.contains("input_json_delta"));
    assert!(out.contains("\"input_tokens\":2") && out.contains("\"output_tokens\":4"));
    assert!(out.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
}

#[test]
fn hostile_upstream_shapes_and_incomplete_or_oversized_streams_fail_closed() {
    for raw in [
        "null",
        "{}",
        r#"{"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0}}"#,
        r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}]}"#,
    ] {
        assert!(openai::response(raw, "pinned").is_err());
    }
    for raw in [
        "data: [DONE]\n\n".into(),
        "data: {}\n\n".into(),
        "x".repeat(openai::MAX_SSE_EVENT_BYTES + 1),
        "data: {\"choices\":[],\"error\":\"host-secret\"}\n\n".into(),
    ] {
        let mut reader = openai::SseReader::new(Box::new(Cursor::new(raw)), "pinned".into());
        let mut out = String::new();
        assert!(reader.read_to_string(&mut out).is_err());
        assert!(!out.contains("host-secret"));
    }
    for url in [
        "https://evil.example",
        "http://127.0.0.1:80@evil",
        "http://127.0.0.1:0",
        "http://127.0.0.1:80/redirect",
    ] {
        assert!(openai::validate_base_url(url).is_err());
    }
}

#[test]
fn secret_file_permissions_and_all_symlink_components_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key");
    std::fs::write(&key, "fake-key").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(hermetic_gateway::fsutil::read_secret_file_capped(&key, 100).is_err());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        hermetic_gateway::fsutil::read_secret_file_capped(&key, 100).unwrap(),
        b"fake-key"
    );
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();
    assert!(hermetic_gateway::fsutil::read_secret_file_capped(&link.join("key"), 100).is_err());
    assert!(hermetic_gateway::fsutil::read_regular_file_capped(&link.join("key"), 100).is_err());
}

#[test]
fn abandoned_chat_stream_cannot_bypass_token_accounting() {
    use hermetic_gateway::{
        quota::{QuotaTracker, QuotasConfig},
        response::{StreamSlotGuard, StreamUsage},
    };
    use std::sync::Mutex;
    let quota = Arc::new(QuotaTracker::new(QuotasConfig::default()));
    quota.check_and_acquire(0).unwrap();
    let slot = Arc::new(StreamSlotGuard::new(
        quota.clone(),
        Arc::new(Mutex::new(StreamUsage::default())),
    ));
    let raw = format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":{"content":"unmetered text"},"finish_reason":null}]})
    );
    let mut reader = openai::SseReader::new(Box::new(Cursor::new(raw)), "pinned".into())
        .with_accounting(slot.clone(), quota.clone());
    let mut byte = [0; 1];
    assert_eq!(reader.read(&mut byte).unwrap(), 1);
    drop(reader); // The peer abandons before the provider's terminal usage frame.
    slot.record_and_release().unwrap_err();
    assert!(quota.is_limit_exceeded());
    assert!(quota.check_and_acquire(0).is_err());
}

#[test]
fn malformed_generated_content_still_consumes_reported_budget() {
    let fixture = Fixture::new(2);
    let upstream = fixture.upstream.clone();
    let worker = std::thread::spawn(move || {
        let req = upstream
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        req.respond(tiny_http::Response::from_string(
            json!({"choices":[{"index":0,
            "message":{"role":"assistant","content":null,"tool_calls":[{"type":"function",
                "function":{"name":"bash","arguments":"{"}}]},"finish_reason":"length"}],
            "usage":{"prompt_tokens":1,"completion_tokens":3}})
            .to_string(),
        ))
        .unwrap();
    });
    let response = fixture.post(&base_request(false));
    assert_eq!(response.status(), 429);
    assert!(response.into_string().unwrap().contains("rate_limit_error"));
    worker.join().unwrap();
    let log = std::fs::read_to_string(&fixture.log_path).unwrap();
    let record: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(record["quotas"]["output_tokens"], 3);
    // A second request is refused locally and never reaches the upstream.
    assert_eq!(fixture.post(&base_request(false)).status(), 429);
    assert!(fixture
        .upstream
        .recv_timeout(Duration::from_millis(20))
        .unwrap()
        .is_none());
}

#[test]
fn unreadable_chat_usage_ends_run_before_another_upstream_call() {
    for (body, encoding) in [
        (vec![0xff], None),
        (b"not decoded".to_vec(), Some("gzip")),
        (
            vec![b' '; hermetic_gateway::upstream::UpstreamClient::MAX_RESPONSE_BYTES + 1],
            None,
        ),
    ] {
        let fixture = Fixture::new(1000);
        let upstream = fixture.upstream.clone();
        let worker = std::thread::spawn(move || {
            let req = upstream
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap();
            let mut response = tiny_http::Response::from_data(body);
            if let Some(encoding) = encoding {
                response.add_header(
                    tiny_http::Header::from_bytes("Content-Encoding", encoding).unwrap(),
                );
            }
            let _ = req.respond(response);
        });
        assert_eq!(fixture.post(&base_request(false)).status(), 429);
        worker.join().unwrap();
        assert_eq!(fixture.post(&base_request(false)).status(), 429);
        assert!(fixture
            .upstream
            .recv_timeout(Duration::from_millis(20))
            .unwrap()
            .is_none());
    }
}

#[test]
fn streaming_usage_breach_does_not_read_another_upstream_event() {
    use hermetic_gateway::{
        quota::{QuotaTracker, QuotasConfig},
        response::{StreamSlotGuard, StreamUsage},
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    struct Frames {
        frames: std::collections::VecDeque<Cursor<Vec<u8>>>,
        reads: Arc<AtomicUsize>,
    }
    impl Read for Frames {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while let Some(frame) = self.frames.front_mut() {
                let n = frame.read(buf)?;
                if n > 0 {
                    self.reads.fetch_add(1, Ordering::SeqCst);
                    return Ok(n);
                }
                self.frames.pop_front();
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no further frame",
            ))
        }
    }
    let quota = Arc::new(QuotaTracker::new(QuotasConfig {
        max_output_tokens: Some(2),
        ..Default::default()
    }));
    quota.check_and_acquire(0).unwrap();
    let slot = Arc::new(StreamSlotGuard::new(
        quota.clone(),
        Arc::new(Mutex::new(StreamUsage::default())),
    ));
    let reads = Arc::new(AtomicUsize::new(0));
    let frames = [
        json!({"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":null}]}),
        json!({"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":3}}),
        json!({"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":4}}),
    ]
    .into_iter()
    .map(|v| Cursor::new(format!("data: {v}\n\n").into_bytes()))
    .collect();
    let mut reader = openai::SseReader::new(
        Box::new(Frames {
            frames,
            reads: reads.clone(),
        }),
        "pinned".into(),
    )
    .with_accounting(slot.clone(), quota.clone());
    assert!(reader.read_to_end(&mut Vec::new()).is_err());
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert!(quota.is_limit_exceeded());
    drop(reader);
    slot.record_and_release().unwrap_err();
    assert_eq!(quota.snapshot().output_tokens, 3);
}

#[test]
fn chat_usage_accumulates_input_and_output_once_across_requests() {
    let fixture = Fixture::new(7);
    let upstream = fixture.upstream.clone();
    let worker = std::thread::spawn(move || {
        for _ in 0..2 {
            let req = upstream
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap();
            req.respond(tiny_http::Response::from_string(
                json!({"choices":[{"index":0,
                "message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":5,"completion_tokens":4}})
                .to_string(),
            ))
            .unwrap();
        }
    });
    assert_eq!(fixture.post(&base_request(false)).status(), 200);
    assert_eq!(fixture.post(&base_request(false)).status(), 429);
    worker.join().unwrap();
    let log = std::fs::read_to_string(&fixture.log_path).unwrap();
    let record: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(record["quotas"]["input_tokens"], 10);
    assert_eq!(record["quotas"]["output_tokens"], 8);
}
