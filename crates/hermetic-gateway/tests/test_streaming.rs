mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::io::{BufRead, BufReader, Cursor};
use std::thread;
use tiny_http::{Header, Response};

#[test]
fn test_sse_streaming_timestamp_rewrite_and_token_counting() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);

        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"created_at\":1600000000,\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello world\"}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    assert_eq!(res.status(), 200);

    let mut reader = BufReader::new(res.into_reader());
    let mut all_stream_text = String::new();
    let mut line = String::new();

    while reader.read_line(&mut line).unwrap() > 0 {
        all_stream_text.push_str(&line);
        line.clear();
    }

    common::join_within(mock_handle);

    // Verify created_at timestamp in message_start was rewritten to guest time
    let guest_unix = env.t_clock.unix_timestamp();
    assert!(
        common::contains_guest_unix_created_at(&all_stream_text, guest_unix),
        "Expected guest timestamp near {guest_unix} in stream: {all_stream_text}"
    );

    // Verify deltas passed through
    assert!(all_stream_text.contains("Hello world"));
    assert!(all_stream_text.contains("event: message_stop"));

    // Verify token usage: message_delta output_tokens is cumulative (15, not 1 + 15 = 16)
    let snap = env.gateway_server.quota().snapshot();
    assert_eq!(snap.input_tokens, 25);
    assert_eq!(snap.output_tokens, 15);
}

#[test]
fn test_sse_streaming_multiple_message_delta_cumulative_output_tokens() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);

        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"created_at\":1600000000,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":10}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    let mut reader = BufReader::new(res.into_reader());
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        line.clear();
    }
    common::join_within(mock_handle);

    let snap = env.gateway_server.quota().snapshot();
    assert_eq!(snap.input_tokens, 10);
    // Must be latest cumulative value (15), NOT sum (1 + 5 + 10 + 15 = 31)
    assert_eq!(snap.output_tokens, 15);
}

#[test]
fn test_streamed_tokens_count_toward_max_output_tokens_and_second_request_refused() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_output_tokens: Some(10),
            ..Default::default()
        },
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);

        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"created_at\":1600000000,\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    // First request streams 15 output tokens, pushing over max_output_tokens (10)
    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    assert_eq!(res.status(), 200);

    let mut reader = BufReader::new(res.into_reader());
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        line.clear();
    }
    common::join_within(mock_handle);

    let snap = env.gateway_server.quota().snapshot();
    assert_eq!(snap.output_tokens, 15);
    assert!(snap.limit_exceeded);

    // Second request must be refused with 429
    let err2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    if let ureq::Error::Status(429, resp) = err2 {
        let b = resp.into_string().unwrap();
        assert!(b.contains("rate_limit_error"));
    } else {
        panic!("Expected 429 for second request");
    }
}

#[test]
fn test_streamed_response_client_disconnect_records_usage_and_releases_slot() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);

        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"created_at\":1600000000,\"usage\":{\"input_tokens\":20,\"output_tokens\":5}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Chunk 1\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Chunk 2\"}}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    assert_eq!(res.status(), 200);

    // Read only the first line/event then DROP the reader (simulate disconnect mid-stream)
    {
        let mut reader = BufReader::new(res.into_reader());
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        // Explicitly drop reader here
    }

    common::join_within(mock_handle);

    // Give server thread a moment to finalize drop cleanup
    thread::sleep(std::time::Duration::from_millis(100));

    let snap = env.gateway_server.quota().snapshot();
    assert_eq!(snap.concurrent_requests, 0, "Slot must be released");
    assert_eq!(snap.input_tokens, 20, "Input tokens must be recorded");
    assert!(
        snap.output_tokens >= 5,
        "Output tokens parsed before drop must be recorded"
    );
}

#[test]
fn test_streaming_tool_use_input_created_at_unchanged() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);

        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"created_at\":1600000000,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"schedule\",\"input\":{}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"created_at\\\": 1700000000}\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    assert_eq!(res.status(), 200);

    let mut reader = BufReader::new(res.into_reader());
    let mut all_stream_text = String::new();
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        all_stream_text.push_str(&line);
        line.clear();
    }

    common::join_within(mock_handle);

    // Verify top-level message created_at was rewritten to guest time
    let guest_unix = env.t_clock.unix_timestamp();
    assert!(common::contains_guest_unix_created_at(
        &all_stream_text,
        guest_unix
    ));

    // Verify tool_use partial_json containing created_at: 1700000000 reached agent unchanged
    assert!(
        all_stream_text.contains(r#"\"created_at\": 1700000000"#),
        "Expected created_at 1700000000 unchanged in stream: {all_stream_text}"
    );

    // Also parse content_block_delta event JSON to confirm partial_json value exactly
    let delta_line = all_stream_text
        .lines()
        .find(|l| l.contains("input_json_delta"))
        .expect("content_block_delta line present");
    let json_str = delta_line.strip_prefix("data: ").unwrap();
    let delta_val: serde_json::Value = serde_json::from_str(json_str).unwrap();
    assert_eq!(
        delta_val["delta"]["partial_json"].as_str().unwrap(),
        r#"{"created_at": 1700000000}"#,
        "partial_json string must be untouched"
    );
}

#[test]
fn test_sse_error_event_replacement() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);

        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\"}}\n\n\
event: error\n\
data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Internal node failure at 2026-11-11T20:45:00Z on cluster 7\"}}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    let mut reader = BufReader::new(res.into_reader());
    let mut all_stream_text = String::new();
    let mut line = String::new();

    while reader.read_line(&mut line).unwrap() > 0 {
        all_stream_text.push_str(&line);
        line.clear();
    }

    common::join_within(mock_handle);

    // Verify the error event was replaced with standard error body
    assert!(all_stream_text.contains("event: error"));
    assert!(all_stream_text.contains("\"message\":\"Overloaded\""));
    assert!(!all_stream_text.contains("cluster 7"));
}

struct PausingStreamReader {
    data: Cursor<Vec<u8>>,
    paused_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl std::io::Read for PausingStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.read(buf)?;
        if n > 0 {
            Ok(n)
        } else {
            self.paused_flag
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // Upstream goes idle mid-stream (well under the gateway's 120 s read timeout).
            std::thread::sleep(std::time::Duration::from_secs(3));
            Ok(0)
        }
    }
}

/// Defect (c) / re-review 10: a client that cancels a stream while upstream is idle must not
/// have its next request counted as a (terminal) concurrency breach, and the slot is released
/// only when the cancelled upstream work has really ended (upstream concurrency stays <= 1).
#[test]
fn test_stream_client_disconnect_during_upstream_pause_releases_slot_within_bound() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let t_clock = time::OffsetDateTime::parse(
        "2026-11-11T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    // Default upstream read timeout (120 s): only the disconnect watcher can free the slot.
    let env = TestEnv::new_with_options(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_concurrent_requests: Some(1),
            ..Default::default()
        },
        t_clock,
        None,
    );

    let paused_flag = Arc::new(AtomicBool::new(false));
    let paused_flag_clone = paused_flag.clone();
    let upstream_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let upstream_active_2 = upstream_active.clone();
    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        // First request: a stream that pauses after its first event.
        let req1 = common::recv_upstream(&mock);
        upstream_active_2.fetch_add(1, Ordering::SeqCst);
        let active_1 = upstream_active_2.clone();
        let h1 = thread::spawn(move || {
            let mut event = String::from(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n",
            );
            for _ in 0..15 {
                event.push_str(&format!(": {}\n\n", "p".repeat(95)));
            }
            let resp = Response::new(
                200.into(),
                vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
                PausingStreamReader {
                    data: Cursor::new(event.into_bytes()),
                    paused_flag: paused_flag_clone,
                },
                None,
                None,
            );
            let _ = req1.respond(resp);
            active_1.fetch_sub(1, Ordering::SeqCst);
        });
        // Second request (sent right after the cancel): a normal reply. It may only reach
        // upstream once the first upstream exchange has ended.
        let req2 = common::recv_upstream(&mock);
        let overlap = upstream_active_2.load(Ordering::SeqCst);
        req2.respond(Response::from_string(
            r#"{"id":"msg_2","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
        ))
        .unwrap();
        common::join_within(h1);
        overlap
    });

    let client = common::test_client();
    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(
            r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}],"stream":true}"#,
        )
        .expect("send stream ok");
    assert_eq!(res.status(), 200);

    // Read the first line, wait until upstream is idle, then cancel (drop the connection).
    let mut reader = BufReader::new(res.into_reader());
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !paused_flag.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(paused_flag.load(Ordering::SeqCst), "upstream never paused");
    let cancelled_at = Instant::now();
    drop(reader);

    // The next request goes out at once, on a new connection, while upstream is still idle.
    let fresh = common::test_client();
    let res2 = fresh
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(
            r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#,
        )
        .expect("second request must not be refused as a concurrency breach");
    assert_eq!(res2.status(), 200);
    let _ = res2.into_string();
    assert!(
        cancelled_at.elapsed() < Duration::from_secs(20),
        "second request must be served once the cancelled stream drains, took {:?}",
        cancelled_at.elapsed()
    );
    let snap = env.gateway_server.quota().snapshot();
    assert!(!snap.limit_exceeded, "cancel counted as breach: {snap:?}");

    let overlap = common::join_within(mock_handle);
    assert_eq!(overlap, 0, "second upstream request overlapped the first");
}
