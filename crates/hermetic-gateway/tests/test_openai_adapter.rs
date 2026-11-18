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
        let http =
            tiny_http::Server::http_with_deadlines("127.0.0.1:0", gateway.client_deadlines())
                .unwrap();
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

#[test]
fn nvidia_endpoint_is_admitted_only_exactly() {
    assert!(openai::validate_base_url("https://integrate.api.nvidia.com/v1").is_ok());
    assert!(openai::validate_base_url("https://integrate.api.nvidia.com/v1/").is_ok());
    for url in [
        "http://integrate.api.nvidia.com/v1",
        "https://integrate.api.nvidia.com/v1/extra",
        "https://integrate.api.nvidia.com",
        "https://user@integrate.api.nvidia.com/v1",
        "https://integrate.api.nvidia.com.evil.example/v1",
        "https://integrate.api.nvidia.com:8443/v1",
    ] {
        assert!(openai::validate_base_url(url).is_err(), "{url}");
    }
}

#[test]
fn test_base_url_allowlist_full_validation() {
    for url in [
        "https://api.openai.com/v1",
        "https://api.openai.com/v1/",
        "https://openrouter.ai/api/v1",
        "https://openrouter.ai/api/v1/",
        "https://integrate.api.nvidia.com/v1",
        "https://integrate.api.nvidia.com/v1/",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8080/v1",
        "http://127.0.0.1:8080/v1beta/openai",
    ] {
        assert!(
            openai::validate_base_url(url).is_ok(),
            "Expected valid: {url}"
        );
    }

    for url in [
        "https://api.openai.com",
        "https://api.openai.com/v2",
        "https://api.openai.com/v1/extra",
        "https://openrouter.ai",
        "https://openrouter.ai/v1",
        "http://api.openai.com/v1",
        "https://evil.example.com/v1",
        "http://127.0.0.1:8080/other",
        "http://127.0.0.1:0",
        "http://127.0.0.1:99999",
        "http://127.0.0.1:8080@evil.com",
        "http://127.0.0.1:8080/v1/../evil",
        "http://localhost:8080",
        "http://[::1]:8080",
        "ftp://127.0.0.1:8080",
    ] {
        assert!(
            openai::validate_base_url(url).is_err(),
            "Expected invalid: {url}"
        );
    }
}

#[test]
fn test_known_answer_request_translation_fixtures() {
    let body = json!({
        "model": "pinned",
        "system": "System instructions here",
        "messages": [{"role": "user", "content": "Hello world"}],
        "max_tokens": 256,
        "temperature": 0.5,
        "top_p": 0.9,
        "stop_sequences": ["\n\nEnd"],
        "stream": true
    })
    .to_string();

    let (endpoint, req_json) = openai::request(&body, "/v1/messages").unwrap();
    assert_eq!(endpoint, "/chat/completions");
    let val: Value = serde_json::from_str(&req_json).unwrap();
    assert_eq!(val["model"], "pinned");
    assert_eq!(val["max_tokens"], 256);
    assert_eq!(val["temperature"], 0.5);
    assert_eq!(val["top_p"], 0.9);
    assert_eq!(val["stop"], json!(["\n\nEnd"]));
    assert_eq!(val["stream"], true);
    assert_eq!(val["stream_options"], json!({"include_usage": true}));
    assert_eq!(
        val["messages"][0],
        json!({"role": "system", "content": "System instructions here"})
    );
    assert_eq!(
        val["messages"][1],
        json!({"role": "user", "content": "Hello world"})
    );

    let body_sys_blocks = json!({
        "model": "pinned",
        "system": [
            {"type": "text", "text": "Part 1"},
            {"type": "text", "text": "Part 2"}
        ],
        "messages": [{"role": "user", "content": "Go"}]
    })
    .to_string();
    let (_, req_sys) = openai::request(&body_sys_blocks, "/v1/messages").unwrap();
    let val_sys: Value = serde_json::from_str(&req_sys).unwrap();
    assert_eq!(val_sys["messages"][0]["content"], "Part 1\nPart 2");

    let body_img = json!({
        "model": "pinned",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "Look at this:"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
            ]
        }]
    })
    .to_string();
    let (_, req_img) = openai::request(&body_img, "/v1/messages").unwrap();
    let val_img: Value = serde_json::from_str(&req_img).unwrap();
    assert_eq!(
        val_img["messages"][0]["content"][0],
        json!({"type": "text", "text": "Look at this:"})
    );
    assert_eq!(
        val_img["messages"][0]["content"][1],
        json!({"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}})
    );

    let body_tools = json!({
        "model": "pinned",
        "messages": [{"role": "user", "content": "run calculation"}],
        "tools": [{
            "name": "calc",
            "description": "Performs math",
            "input_schema": {
                "type": "object",
                "properties": {"expr": {"type": "string"}},
                "required": ["expr"]
            }
        }],
        "tool_choice": {"type": "tool", "name": "calc", "disable_parallel_tool_use": true}
    })
    .to_string();
    let (_, req_tools) = openai::request(&body_tools, "/v1/messages").unwrap();
    let val_tools: Value = serde_json::from_str(&req_tools).unwrap();
    assert_eq!(val_tools["tools"][0]["type"], "function");
    assert_eq!(val_tools["tools"][0]["function"]["name"], "calc");
    assert_eq!(
        val_tools["tools"][0]["function"]["description"],
        "Performs math"
    );
    assert_eq!(
        val_tools["tool_choice"],
        json!({"type": "function", "function": {"name": "calc"}})
    );
    assert_eq!(val_tools["parallel_tool_calls"], false);

    for (tc_in, tc_out) in [
        (json!({"type": "auto"}), json!("auto")),
        (json!({"type": "any"}), json!("required")),
    ] {
        let b = json!({
            "model": "pinned",
            "messages": [{"role": "user", "content": "test"}],
            "tool_choice": tc_in
        })
        .to_string();
        let (_, r) = openai::request(&b, "/v1/messages").unwrap();
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["tool_choice"], tc_out);
    }
}

#[test]
fn test_hostile_request_rejection_vectors() {
    let base = json!({"model": "pinned", "messages": [{"role": "user", "content": "test"}]});

    assert!(openai::request(&base.to_string(), "/v1/messages/count_tokens").is_err());
    assert!(openai::request(&base.to_string(), "/v1/complete").is_err());
    assert!(openai::request(&base.to_string(), "/chat/completions").is_err());

    let forbidden_keys = [
        ("top_k", json!(40)),
        (
            "thinking",
            json!({"type": "enabled", "budget_tokens": 1024}),
        ),
        ("metadata", json!({"user_id": "test"})),
    ];
    for (k, v) in forbidden_keys {
        let mut req = base.clone();
        req[k] = v;
        assert!(
            openai::request(&req.to_string(), "/v1/messages").is_err(),
            "Key {k} should fail"
        );
    }

    let doc_req = json!({
        "model": "pinned",
        "messages": [{
            "role": "user",
            "content": [{
                "type": "document",
                "source": {"type": "base64", "media_type": "application/pdf", "data": "dGVzdA=="}
            }]
        }]
    });
    assert!(openai::request(&doc_req.to_string(), "/v1/messages").is_err());

    let bad_role_req = json!({
        "model": "pinned",
        "messages": [{
            "role": "assistant",
            "content": [{"type": "tool_result", "tool_use_id": "call0", "content": "ok"}]
        }]
    });
    assert!(openai::request(&bad_role_req.to_string(), "/v1/messages").is_err());

    let tool_in_user = json!({
        "model": "pinned",
        "messages": [{
            "role": "user",
            "content": [{"type": "tool_use", "id": "call0", "name": "bash", "input": {}}]
        }]
    });
    assert!(openai::request(&tool_in_user.to_string(), "/v1/messages").is_err());

    for bad_name in [
        "",
        "tool with space",
        "tool;cmd",
        "tool/path",
        &"a".repeat(129),
    ] {
        let bad_tool = json!({
            "model": "pinned",
            "messages": [{
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "c0", "name": bad_name, "input": {}}]
            }]
        });
        assert!(openai::request(&bad_tool.to_string(), "/v1/messages").is_err());
    }

    for non_object in [json!("string"), json!(123), json!([1, 2]), json!(true)] {
        let bad_input = json!({
            "model": "pinned",
            "messages": [{
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "c0", "name": "bash", "input": non_object}]
            }]
        });
        assert!(openai::request(&bad_input.to_string(), "/v1/messages").is_err());
    }

    let mut excess_calls = Vec::new();
    for i in 0..129 {
        excess_calls
            .push(json!({"type": "tool_use", "id": format!("c{i}"), "name": "bash", "input": {}}));
    }
    let excess_req = json!({
        "model": "pinned",
        "messages": [{"role": "assistant", "content": excess_calls}]
    });
    assert!(openai::request(&excess_req.to_string(), "/v1/messages").is_err());
}

#[test]
fn test_known_answer_response_translation_fixtures() {
    let raw_text = json!({
        "id": "chatcmpl-raw123",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "provider-model-xyz",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Calculated value is 42."},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8}
    })
    .to_string();

    let res = openai::response(&raw_text, "pinned").unwrap();
    let val: Value = serde_json::from_str(&res).unwrap();
    assert_eq!(val["id"], "msg_gateway");
    assert_eq!(val["type"], "message");
    assert_eq!(val["role"], "assistant");
    assert_eq!(val["model"], "pinned");
    assert_eq!(val["stop_reason"], "end_turn");
    assert_eq!(
        val["content"][0],
        json!({"type": "text", "text": "Calculated value is 42."})
    );
    assert_eq!(
        val["usage"],
        json!({"input_tokens": 12, "output_tokens": 8})
    );
    assert!(!res.contains("chatcmpl-raw123"));
    assert!(!res.contains("provider-model-xyz"));
    assert!(!res.contains("1700000000"));

    let raw_length = json!({
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Truncated answer..."},
            "finish_reason": "length"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 100}
    })
    .to_string();
    let res_len = openai::response(&raw_length, "pinned").unwrap();
    let val_len: Value = serde_json::from_str(&res_len).unwrap();
    assert_eq!(val_len["stop_reason"], "max_tokens");

    let raw_tools = json!({
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {"id": "call_abc123", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"foo.rs\"}"}},
                    {"id": "call_def456", "type": "function", "function": {"name": "run_test", "arguments": "{\"filter\":\"unit\"}"}}
                ]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 20, "completion_tokens": 15}
    })
    .to_string();
    let res_tools = openai::response(&raw_tools, "pinned").unwrap();
    let val_tools: Value = serde_json::from_str(&res_tools).unwrap();
    assert_eq!(val_tools["stop_reason"], "tool_use");
    assert_eq!(
        val_tools["content"][0],
        json!({"type": "tool_use", "id": "toolu_0", "name": "read_file", "input": {"path": "foo.rs"}})
    );
    assert_eq!(
        val_tools["content"][1],
        json!({"type": "tool_use", "id": "toolu_1", "name": "run_test", "input": {"filter": "unit"}})
    );
}

#[test]
fn test_hostile_response_rejection_vectors() {
    let valid_base = json!({
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}
    });

    let empty_choices =
        json!({"choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1}});
    assert!(openai::response(&empty_choices.to_string(), "pinned").is_err());

    let multi_choices = json!({
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "1"}, "finish_reason": "stop"},
            {"index": 1, "message": {"role": "assistant", "content": "2"}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}
    });
    assert!(openai::response(&multi_choices.to_string(), "pinned").is_err());

    let bad_index = json!({
        "choices": [{"index": 1, "message": {"role": "assistant", "content": "x"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}
    });
    assert!(openai::response(&bad_index.to_string(), "pinned").is_err());

    for bad_role in ["user", "system", "tool", "function", "unknown"] {
        let mut r = valid_base.clone();
        r["choices"][0]["message"]["role"] = json!(bad_role);
        assert!(openai::response(&r.to_string(), "pinned").is_err());
    }

    let bad_tool_type = json!({
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{"id": "c0", "type": "code_interpreter", "function": {"name": "bash", "arguments": "{}"}}]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}
    });
    assert!(openai::response(&bad_tool_type.to_string(), "pinned").is_err());

    for bad_arg in ["not-json", "[]", "123", "\"plain string\"", "true", "null"] {
        let bad_tool_arg = json!({
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{"id": "c0", "type": "function", "function": {"name": "bash", "arguments": bad_arg}}]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        });
        assert!(openai::response(&bad_tool_arg.to_string(), "pinned").is_err());
    }

    for bad_finish in [
        "content_filter",
        "function_call",
        "null",
        "",
        "cancelled",
        "unknown",
    ] {
        let mut r = valid_base.clone();
        r["choices"][0]["finish_reason"] = json!(bad_finish);
        assert!(openai::response(&r.to_string(), "pinned").is_err());
    }

    let no_usage = json!({
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "x"}, "finish_reason": "stop"}]
    });
    assert!(openai::response(&no_usage.to_string(), "pinned").is_err());
    assert!(openai::reported_usage(&no_usage.to_string()).is_err());

    let float_usage = json!({
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "x"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1.5, "completion_tokens": 2}
    });
    assert!(openai::response(&float_usage.to_string(), "pinned").is_err());
    assert!(openai::reported_usage(&float_usage.to_string()).is_err());
}

#[test]
fn test_known_answer_streaming_translation_fixtures() {
    let frames = [
        json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": "First "}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"content": "Second"}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
        json!({"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}),
    ];
    let raw = frames
        .iter()
        .map(|f| format!("data: {f}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    let mut reader = openai::SseReader::new(Box::new(Cursor::new(raw)), "pinned".into());
    let mut output = String::new();
    reader.read_to_string(&mut output).unwrap();

    assert!(output.contains("event: message_start\n"));
    assert!(output.contains("event: content_block_start\ndata: {\"content_block\":{\"text\":\"\",\"type\":\"text\"},\"index\":0,\"type\":\"content_block_start\"}\n"));
    assert!(output.contains("event: content_block_delta\ndata: {\"delta\":{\"text\":\"First \",\"type\":\"text_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n"));
    assert!(output.contains("event: content_block_delta\ndata: {\"delta\":{\"text\":\"Second\",\"type\":\"text_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n"));
    assert!(output.contains(
        "event: content_block_stop\ndata: {\"index\":0,\"type\":\"content_block_stop\"}\n"
    ));
    assert!(output.contains("event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"type\":\"message_delta\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}\n"));
    assert!(output.contains("event: message_stop\ndata: {\"type\":\"message_stop\"}\n"));

    let tool_frames = [
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "type": "function", "function": {"name": "run_calc"}}]}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"x\": "}}]}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "42}"}}]}, "finish_reason": "tool_calls"}]}),
        json!({"choices": [], "usage": {"prompt_tokens": 15, "completion_tokens": 20}}),
    ];
    let tool_raw = tool_frames
        .iter()
        .map(|f| format!("data: {f}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    let mut tool_reader = openai::SseReader::new(Box::new(Cursor::new(tool_raw)), "pinned".into());
    let mut tool_out = String::new();
    tool_reader.read_to_string(&mut tool_out).unwrap();

    assert!(tool_out.contains("event: content_block_start\ndata: {\"content_block\":{\"id\":\"toolu_0\",\"input\":{},\"name\":\"run_calc\",\"type\":\"tool_use\"},\"index\":0,\"type\":\"content_block_start\"}\n"));
    assert!(tool_out.contains("event: content_block_delta\ndata: {\"delta\":{\"partial_json\":\"{\\\"x\\\": \",\"type\":\"input_json_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n"));
    assert!(tool_out.contains("event: content_block_delta\ndata: {\"delta\":{\"partial_json\":\"42}\",\"type\":\"input_json_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n"));
    assert!(tool_out.contains(
        "event: content_block_stop\ndata: {\"index\":0,\"type\":\"content_block_stop\"}\n"
    ));
    assert!(tool_out.contains("\"stop_reason\":\"tool_use\""));
    assert!(tool_out.contains("\"input_tokens\":15,\"output_tokens\":20"));
}

#[test]
fn test_hostile_streaming_rejection_vectors() {
    let mutate_name = [
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "type": "function", "function": {"name": "func_a"}}]}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"name": "func_b"}}]}, "finish_reason": null}]}),
    ]
    .iter()
    .map(|f| format!("data: {f}\n\n"))
    .collect::<String>();
    let mut r1 = openai::SseReader::new(Box::new(Cursor::new(mutate_name)), "pinned".into());
    assert!(r1.read_to_end(&mut Vec::new()).is_err());

    let bad_json_finish = [
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "type": "function", "function": {"name": "func_a"}}]}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"unclosed_json"}}]}, "finish_reason": "tool_calls"}]}),
    ]
    .iter()
    .map(|f| format!("data: {f}\n\n"))
    .collect::<String>();
    let mut r2 = openai::SseReader::new(Box::new(Cursor::new(bad_json_finish)), "pinned".into());
    assert!(r2.read_to_end(&mut Vec::new()).is_err());

    let no_usage_done = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": "stop"}]})
    );
    let mut r3 = openai::SseReader::new(Box::new(Cursor::new(no_usage_done)), "pinned".into());
    assert!(r3.read_to_end(&mut Vec::new()).is_err());

    let no_finish_done = format!(
        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": null}]}),
        json!({"choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    );
    let mut r4 = openai::SseReader::new(Box::new(Cursor::new(no_finish_done)), "pinned".into());
    assert!(r4.read_to_end(&mut Vec::new()).is_err());

    let high_tool_index = format!(
        "data: {}\n\n",
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 128, "type": "function", "function": {"name": "bash"}}]}, "finish_reason": null}]})
    );
    let mut r5 = openai::SseReader::new(Box::new(Cursor::new(high_tool_index)), "pinned".into());
    assert!(r5.read_to_end(&mut Vec::new()).is_err());

    let multi_choice = format!(
        "data: {}\n\n",
        json!({"choices": [
            {"index": 0, "delta": {"content": "a"}, "finish_reason": null},
            {"index": 1, "delta": {"content": "b"}, "finish_reason": null}
        ]})
    );
    let mut r6 = openai::SseReader::new(Box::new(Cursor::new(multi_choice)), "pinned".into());
    assert!(r6.read_to_end(&mut Vec::new()).is_err());

    let invalid_line = "bogus_event_line_without_prefix\n\n";
    let mut r7 = openai::SseReader::new(Box::new(Cursor::new(invalid_line)), "pinned".into());
    assert!(r7.read_to_end(&mut Vec::new()).is_err());
}

#[test]
fn test_gateway_e2e_openai_count_tokens_fails_closed() {
    let fixture = Fixture::new(1000);
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build()
        .post(&format!("{}/v1/messages/count_tokens", fixture.url))
        .set("content-type", "application/json")
        .set("anthropic-version", "2023-06-01")
        .send_string(&base_request(false).to_string());

    let resp = match response {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("request failed: {e}"),
    };
    assert_eq!(resp.status(), 400);
    let body = resp.into_string().unwrap();
    assert!(body.contains("invalid_request_error"));
    assert!(fixture
        .upstream
        .recv_timeout(Duration::from_millis(50))
        .unwrap()
        .is_none());
}

#[test]
fn test_gateway_e2e_openai_inline_image_and_tool_flow() {
    let fixture = Fixture::new(1000);
    let upstream = fixture.upstream.clone();
    let worker = std::thread::spawn(move || {
        let mut req = upstream
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(req.url(), "/chat/completions");
        let mut body_str = String::new();
        req.as_reader().read_to_string(&mut body_str).unwrap();
        let parsed: Value = serde_json::from_str(&body_str).unwrap();
        assert!(parsed["messages"][0]["content"]
            .as_str()
            .unwrap()
            .starts_with("[run-nonce "));
        let user_content = &parsed["messages"][1]["content"];
        assert_eq!(user_content[0]["type"], "text");
        assert_eq!(user_content[1]["type"], "image_url");
        assert!(user_content[1]["image_url"]["url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,"));
        assert_eq!(parsed["tools"][0]["function"]["name"], "calculator");

        req.respond(tiny_http::Response::from_string(
            json!({
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "upstream_call_id_secret",
                            "type": "function",
                            "function": {"name": "calculator", "arguments": "{\"expr\":\"2+2\"}"}
                        }]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"prompt_tokens": 18, "completion_tokens": 12}
            })
            .to_string(),
        ))
        .unwrap();
    });

    let req = json!({
        "model": "pinned",
        "max_tokens": 128,
        "system": "Solve problems",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
            ]
        }],
        "tools": [{
            "name": "calculator",
            "description": "Calculate math",
            "input_schema": {"type": "object", "properties": {"expr": {"type": "string"}}}
        }]
    });

    let resp = fixture.post(&req);
    assert_eq!(resp.status(), 200);
    let body = resp.into_string().unwrap();
    assert!(!body.contains("upstream_call_id_secret"));
    let val: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(val["content"][0]["type"], "tool_use");
    assert_eq!(val["content"][0]["name"], "calculator");
    assert_eq!(val["content"][0]["id"], "toolu_0");
    assert_eq!(val["content"][0]["input"], json!({"expr": "2+2"}));
    assert_eq!(val["stop_reason"], "tool_use");
    assert_eq!(
        val["usage"],
        json!({"input_tokens": 18, "output_tokens": 12})
    );
    worker.join().unwrap();
}

#[test]
fn test_nested_vm_smoke_skips_cleanly_without_env_vars() {
    for path in [
        std::path::Path::new("scripts/integration/gw-adapter-smoke.sh"),
        std::path::Path::new("../../scripts/integration/gw-adapter-smoke.sh"),
    ] {
        if path.exists() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
        }
    }
    for var_name in [
        "HERMETIC_FC_BIN",
        "HERMETIC_FIRECRACKER_LOCK",
        "HERMETIC_KERNEL",
    ] {
        if std::env::var_os(var_name).is_none() {
            eprintln!("skipped: nested VM test requires {var_name}");
            return;
        }
    }
}
