mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Response};

#[test]
fn test_response_headers_filtered_and_date_replaced() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");

        let mut resp = Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)
            .with_status_code(200);

        // Add headers from upstream mock:
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Date"[..], &b"Sun, 06 Nov 1994 08:49:37 GMT"[..]).unwrap(),
        );
        resp.add_header(Header::from_bytes(&b"cf-ray"[..], &b"8f123456789abcde"[..]).unwrap());
        resp.add_header(Header::from_bytes(&b"x-request-id"[..], &b"req_xyz_123"[..]).unwrap());
        resp.add_header(
            Header::from_bytes(&b"anthropic-ratelimit-requests-limit"[..], &b"1000"[..]).unwrap(),
        );

        req.respond(resp).unwrap();
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send ok");

    assert_eq!(res.status(), 200);

    // Dropped headers must NOT reach the agent
    assert!(res.header("cf-ray").is_none());
    assert!(res.header("x-request-id").is_none());
    assert!(res.header("anthropic-ratelimit-requests-limit").is_none());

    // Date must be replaced with guest time (2026-11-11...)
    let date_hdr = res.header("date").expect("Date header present");
    assert!(
        date_hdr.contains("2026"),
        "Date header '{date_hdr}' should be guest time in 2026"
    );

    mock_handle.join().unwrap();

    // Verify dropped headers were written to host log
    let logs = env.read_host_logs();
    assert!(!logs.is_empty());
    let last_log = logs.last().unwrap();
    let dropped = &last_log["dropped_headers"];
    assert_eq!(dropped["cf-ray"], "8f123456789abcde");
    assert_eq!(dropped["x-request-id"], "req_xyz_123");
    assert_eq!(dropped["anthropic-ratelimit-requests-limit"], "1000");
}

#[test]
fn test_retry_after_seconds_input() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Slow down"}}"#,
        )
        .with_status_code(429);
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(Header::from_bytes(&b"Retry-After"[..], &b"120"[..]).unwrap());
        req.respond(resp).unwrap();
    });

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body);

    h.join().unwrap();

    match res {
        Err(ureq::Error::Status(429, resp)) => {
            assert_eq!(
                resp.header("retry-after"),
                Some("120"),
                "Headers: {:?}",
                resp.headers_names()
            );
        }
        other => panic!("Expected 429 status, got {other:?}"),
    }
}

#[test]
fn test_retry_after_http_date_input() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Wait"}}"#,
        )
        .with_status_code(429);
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Date"[..], &b"Wed, 11 Nov 2026 12:00:00 GMT"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Retry-After"[..], &b"Wed, 11 Nov 2026 12:01:30 GMT"[..]).unwrap(),
        );
        req.respond(resp).unwrap();
    });

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body);

    h.join().unwrap();

    match res {
        Err(ureq::Error::Status(429, resp)) => {
            assert_eq!(
                resp.header("retry-after"),
                Some("90"),
                "Headers: {:?}",
                resp.headers_names()
            );
        }
        other => panic!("Expected 429 status, got {other:?}"),
    }
}

#[test]
fn test_retry_after_rfc3339_input() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Wait"}}"#,
        )
        .with_status_code(429);
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Date"[..], &b"Wed, 11 Nov 2026 12:00:00 GMT"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Retry-After"[..], &b"2026-11-11T12:02:15Z"[..]).unwrap(),
        );
        req.respond(resp).unwrap();
    });

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body);

    h.join().unwrap();

    match res {
        Err(ureq::Error::Status(429, resp)) => {
            assert_eq!(
                resp.header("retry-after"),
                Some("135"),
                "Headers: {:?}",
                resp.headers_names()
            );
        }
        other => panic!("Expected 429 status, got {other:?}"),
    }
}

#[test]
fn test_body_timestamp_rewrites_in_json() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp_json = r#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "created": 1700000000,
            "created_at": 1700000001,
            "updated_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-02T00:00:00Z",
            "content": [{"type": "text", "text": "Hello"}],
            "nested": {
                "created_at": 1700000002,
                "other_field": 123
            },
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;

        let resp = Response::from_string(resp_json)
            .with_status_code(200)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
            );
        req.respond(resp).unwrap();
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("success");

    let resp_str = res.into_string().unwrap();
    let val: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

    let guest_unix = env.t_clock.unix_timestamp();

    // Verify numbers rewritten to guest unix seconds
    assert_eq!(val["created"].as_i64(), Some(guest_unix));
    assert_eq!(val["created_at"].as_i64(), Some(guest_unix));
    assert_eq!(val["nested"]["created_at"].as_i64(), Some(guest_unix));
    assert_eq!(val["nested"]["other_field"].as_i64(), Some(123)); // untouched

    // Verify RFC 3339 strings rewritten to guest RFC 3339
    assert_eq!(val["updated_at"].as_str(), Some("2026-11-11T12:00:00Z"));
    assert_eq!(val["expires_at"].as_str(), Some("2026-11-11T12:00:00Z"));

    h.join().unwrap();
}

#[test]
fn test_non_2xx_bodies_recognised_type_replaced_with_standard_error() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let req_body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    // Upstream 529 Overloaded with leak in message
    let mock = env.mock_server.clone();
    let h1 = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp = Response::from_string(r#"{"type":"error","error":{"type":"overloaded_error","message":"Server overloaded at host cluster dc4-2026-11-11T20:30:00Z"}}"#)
            .with_status_code(529)
            .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
        req.respond(resp).unwrap();
    });

    let err1 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(req_body)
        .unwrap_err();

    if let ureq::Error::Status(529, resp) = err1 {
        let b = resp.into_string().unwrap();
        let val: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(val["type"], "error");
        assert_eq!(val["error"]["type"], "overloaded_error");
        // Message must be replaced with standard text
        assert_eq!(val["error"]["message"], "Overloaded");
    } else {
        panic!("Expected 529");
    }
    h1.join().unwrap();
}

#[test]
fn test_non_2xx_bodies_unrecognised_type_html_replaced_with_api_error() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let req_body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock2 = env.mock_server.clone();
    let h2 = thread::spawn(move || {
        let req = mock2
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp = Response::from_string(
            "<html><body>502 Bad Gateway - Cloudflare host node 42</body></html>",
        )
        .with_status_code(502)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap());
        req.respond(resp).unwrap();
    });

    let err2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(req_body)
        .unwrap_err();

    if let ureq::Error::Status(502, resp) = err2 {
        assert_eq!(
            resp.header("content-type"),
            Some("application/json; charset=utf-8"),
            "Sanitized 502 error body must have application/json; charset=utf-8 content-type"
        );
        let b = resp.into_string().unwrap();
        let val: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(val["type"], "error");
        // Unrecognised becomes api_error
        assert_eq!(val["error"]["type"], "api_error");
        assert_eq!(val["error"]["message"], "Upstream API error");
    } else {
        panic!("Expected 502");
    }
    h2.join().unwrap();

    // Verify original error bodies are in host log
    let logs = env.read_host_logs();
    assert!(logs.iter().any(|l| {
        l["original_error_body"]
            .as_str()
            .map(|s| s.contains("Cloudflare host node 42"))
            .unwrap_or(false)
    }));
}

#[test]
fn test_non_streaming_tool_use_input_created_at_unchanged() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp_json = r#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "created_at": 1600000000,
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "schedule",
                    "input": {
                        "created_at": 1700000000,
                        "title": "Planning"
                    }
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;

        let resp = Response::from_string(resp_json)
            .with_status_code(200)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
            );
        req.respond(resp).unwrap();
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("success");

    let resp_str = res.into_string().unwrap();
    let val: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

    let guest_unix = env.t_clock.unix_timestamp();

    // Top-level created_at must be rewritten to guest_unix
    assert_eq!(val["created_at"].as_i64(), Some(guest_unix));

    // tool_use.input.created_at must NOT be rewritten; remains 1700000000
    assert_eq!(
        val["content"][0]["input"]["created_at"].as_i64(),
        Some(1700000000),
        "tool_use.input.created_at must remain unchanged"
    );
    assert_eq!(val["content"][0]["input"]["title"], "Planning");

    h.join().unwrap();
}

#[test]
fn test_format_imf_fixdate_utc_conversion_and_timezone_offsets() {
    use hermetic_gateway::format_imf_fixdate;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    // +02:00 offset: 12:00:00+02:00 -> 10:00:00 GMT
    let dt_plus = OffsetDateTime::parse("2026-11-11T12:00:00+02:00", &Rfc3339).unwrap();
    let s_plus = format_imf_fixdate(dt_plus).unwrap();
    assert_eq!(s_plus, "Wed, 11 Nov 2026 10:00:00 GMT");

    // -05:00 offset: 12:00:00-05:00 -> 17:00:00 GMT
    let dt_minus = OffsetDateTime::parse("2026-11-11T12:00:00-05:00", &Rfc3339).unwrap();
    let s_minus = format_imf_fixdate(dt_minus).unwrap();
    assert_eq!(s_minus, "Wed, 11 Nov 2026 17:00:00 GMT");

    // Out of range: year 9999 with -12:00 offset overflows on converting to UTC (adds 12 hours)
    let out_of_range = time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(9999, time::Month::December, 31).unwrap(),
        time::Time::from_hms(23, 59, 59).unwrap(),
    )
    .assume_offset(time::UtcOffset::from_hms(-12, 0, 0).unwrap());
    assert!(format_imf_fixdate(out_of_range).is_err());
}

#[test]
fn test_gateway_date_header_with_plus_0200_and_minus_0500_t_clock() {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    // Test with +02:00 T_clock
    {
        let t_clock = OffsetDateTime::parse("2026-11-11T12:00:00+02:00", &Rfc3339).unwrap();
        let env = TestEnv::new_with_options(
            vec!["claude-3-5-sonnet-20241022".to_string()],
            vec![],
            QuotasConfig::default(),
            t_clock,
            None,
        );

        let mock = env.mock_server.clone();
        let h = thread::spawn(move || {
            let req = mock.recv().unwrap();
            req.respond(Response::from_string(
                r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
            ))
            .unwrap();
        });

        let client = ureq::AgentBuilder::new().build();
        let body =
            r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

        let res = client
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(body)
            .expect("success");

        assert_eq!(res.status(), 200);
        let date_hdr = res.header("date").expect("Date header present");
        assert_eq!(date_hdr, "Wed, 11 Nov 2026 10:00:00 GMT");
        h.join().unwrap();
    }

    // Test with -05:00 T_clock
    {
        let t_clock = OffsetDateTime::parse("2026-11-11T12:00:00-05:00", &Rfc3339).unwrap();
        let env = TestEnv::new_with_options(
            vec!["claude-3-5-sonnet-20241022".to_string()],
            vec![],
            QuotasConfig::default(),
            t_clock,
            None,
        );

        let mock = env.mock_server.clone();
        let h = thread::spawn(move || {
            let req = mock.recv().unwrap();
            req.respond(Response::from_string(
                r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
            ))
            .unwrap();
        });

        let client = ureq::AgentBuilder::new().build();
        let body =
            r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

        let res = client
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(body)
            .expect("success");

        assert_eq!(res.status(), 200);
        let date_hdr = res.header("date").expect("Date header present");
        assert_eq!(date_hdr, "Wed, 11 Nov 2026 17:00:00 GMT");
        h.join().unwrap();
    }
}

struct StallingReader;
impl std::io::Read for StallingReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        // Sleep for 6 seconds to simulate stalled upstream body
        std::thread::sleep(Duration::from_secs(6));
        Ok(0)
    }
}

#[test]
fn test_mock_upstream_sends_headers_then_stalls_is_cut_off_after_timeout() {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let t_clock = OffsetDateTime::parse("2026-11-11T12:00:00Z", &Rfc3339).unwrap();
    // Configure gateway with 1-second upstream read timeout
    let env = TestEnv::new_with_options(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
        t_clock,
        Some(1),
    );

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock.recv().unwrap();
        // Upstream sends 200 headers with Content-Length: 100, then stalls on reading body
        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()],
            StallingReader,
            Some(100),
            None,
        );
        let _ = req.respond(resp);
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let start = std::time::Instant::now();
    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();
    let elapsed = start.elapsed();

    // Must be cut off around 1s, well before the 6s stall
    assert!(
        elapsed < Duration::from_secs(4),
        "Expected cutoff around 1s, but took {elapsed:?}"
    );

    // Timeout returns standard api_error
    if let ureq::Error::Status(500, resp) = err {
        assert_eq!(
            resp.header("content-type"),
            Some("application/json; charset=utf-8")
        );
        let b = resp.into_string().unwrap();
        let val: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(val["type"], "error");
        assert_eq!(val["error"]["type"], "api_error");
        assert_eq!(val["error"]["message"], "Upstream API error");
    } else {
        panic!("Expected 500 status for timeout, got {err:?}");
    }

    // Slot must be released
    assert_eq!(
        env.gateway_server.quota().snapshot().concurrent_requests,
        0,
        "Concurrency slot must be released on timeout"
    );

    // Logged in host log
    let logs = env.read_host_logs();
    assert!(
        logs.iter().any(|l| {
            l["original_error_body"]
                .as_str()
                .map(|s| {
                    s.to_lowercase().contains("timed out") || s.to_lowercase().contains("timeout")
                })
                .unwrap_or(false)
        }),
        "Host log must record upstream timeout"
    );

    h.join().unwrap();
}
