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
        let req = mock.recv().unwrap();

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

    let client = ureq::AgentBuilder::new().build();
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

    mock_handle.join().unwrap();

    // Verify created_at timestamp in message_start was rewritten to guest time
    let guest_unix = env.t_clock.unix_timestamp();
    assert!(
        all_stream_text.contains(&format!("\"created_at\":{guest_unix}")),
        "Expected guest timestamp {guest_unix} in stream: {all_stream_text}"
    );

    // Verify deltas passed through
    assert!(all_stream_text.contains("Hello world"));
    assert!(all_stream_text.contains("event: message_stop"));
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
        let req = mock.recv().unwrap();

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

    let client = ureq::AgentBuilder::new().build();
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

    mock_handle.join().unwrap();

    // Verify the error event was replaced with standard error body
    assert!(all_stream_text.contains("event: error"));
    assert!(all_stream_text.contains("\"message\":\"Overloaded\""));
    assert!(!all_stream_text.contains("cluster 7"));
}
