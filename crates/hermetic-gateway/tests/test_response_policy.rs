mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
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

    let client = common::test_client();
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

    common::join_within(mock_handle);

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

    let client = common::test_client();
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

    common::join_within(h);

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

    let client = common::test_client();
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

    common::join_within(h);

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

    let client = common::test_client();
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

    common::join_within(h);

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

    let client = common::test_client();
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

    // Verify numbers rewritten to guest unix seconds within range
    let created = val["created"].as_i64().expect("created present");
    let created_at = val["created_at"].as_i64().expect("created_at present");
    let nested_created_at = val["nested"]["created_at"]
        .as_i64()
        .expect("nested created_at present");
    assert!(
        created >= guest_unix && created <= guest_unix + common::GUEST_CLOCK_SLACK_SECS,
        "created {created} in range [{guest_unix}, {}]",
        guest_unix + common::GUEST_CLOCK_SLACK_SECS
    );
    assert!(
        created_at >= guest_unix && created_at <= guest_unix + common::GUEST_CLOCK_SLACK_SECS,
        "created_at {created_at} in range [{guest_unix}, {}]",
        guest_unix + common::GUEST_CLOCK_SLACK_SECS
    );
    assert!(
        nested_created_at >= guest_unix
            && nested_created_at <= guest_unix + common::GUEST_CLOCK_SLACK_SECS,
        "nested created_at {nested_created_at} in range [{guest_unix}, {}]",
        guest_unix + common::GUEST_CLOCK_SLACK_SECS
    );
    assert_eq!(val["nested"]["other_field"].as_i64(), Some(123)); // untouched

    // Verify RFC 3339 strings rewritten to guest RFC 3339 within range
    let updated_at_str = val["updated_at"].as_str().expect("updated_at present");
    let expires_at_str = val["expires_at"].as_str().expect("expires_at present");
    let updated_dt =
        OffsetDateTime::parse(updated_at_str, &Rfc3339).expect("valid RFC 3339 updated_at");
    let expires_dt =
        OffsetDateTime::parse(expires_at_str, &Rfc3339).expect("valid RFC 3339 expires_at");
    assert!(
        updated_dt >= env.t_clock
            && updated_dt <= env.t_clock + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS),
        "updated_at {updated_dt} in range [{}, {}]",
        env.t_clock,
        env.t_clock + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS)
    );
    assert!(
        expires_dt >= env.t_clock
            && expires_dt <= env.t_clock + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS),
        "expires_at {expires_dt} in range [{}, {}]",
        env.t_clock,
        env.t_clock + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS)
    );

    common::join_within(h);
}

#[test]
fn test_non_2xx_bodies_recognised_type_replaced_with_standard_error() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
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
    common::join_within(h1);
}

#[test]
fn test_non_2xx_bodies_unrecognised_type_html_replaced_with_api_error() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
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
    common::join_within(h2);

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

    let client = common::test_client();
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
    let created = val["created_at"].as_i64().expect("created_at present");
    assert!(
        created >= guest_unix && created <= guest_unix + common::GUEST_CLOCK_SLACK_SECS,
        "created_at {created} should be in range [{guest_unix}, {}]",
        guest_unix + common::GUEST_CLOCK_SLACK_SECS
    );

    // tool_use.input.created_at must NOT be rewritten; remains 1700000000
    assert_eq!(
        val["content"][0]["input"]["created_at"].as_i64(),
        Some(1700000000),
        "tool_use.input.created_at must remain unchanged"
    );
    assert_eq!(val["content"][0]["input"]["title"], "Planning");

    common::join_within(h);
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
            let req = common::recv_upstream(&mock);
            req.respond(Response::from_string(
                r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
            ))
            .unwrap();
        });

        let client = common::test_client();
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
        let parsed = hermetic_gateway::response::parse_date_or_rfc3339(date_hdr)
            .expect("Date header must be valid IMF-fixdate or RFC3339");
        let expected_base = OffsetDateTime::parse("2026-11-11T10:00:00Z", &Rfc3339).unwrap();
        assert!(
            parsed >= expected_base
                && parsed
                    <= expected_base + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS),
            "Date header {date_hdr} ({parsed}) should be in range [{expected_base}, {}]",
            expected_base + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS)
        );
        common::join_within(h);
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
            let req = common::recv_upstream(&mock);
            req.respond(Response::from_string(
                r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
            ))
            .unwrap();
        });

        let client = common::test_client();
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
        let parsed = hermetic_gateway::response::parse_date_or_rfc3339(date_hdr)
            .expect("Date header must be valid IMF-fixdate or RFC3339");
        let expected_base = OffsetDateTime::parse("2026-11-11T17:00:00Z", &Rfc3339).unwrap();
        assert!(
            parsed >= expected_base
                && parsed
                    <= expected_base + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS),
            "Date header {date_hdr} ({parsed}) should be in range [{expected_base}, {}]",
            expected_base + time::Duration::seconds(common::GUEST_CLOCK_SLACK_SECS)
        );
        common::join_within(h);
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
        let req = common::recv_upstream(&mock);
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

    let client = common::test_client();
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

    common::join_within(h);
}

#[test]
fn test_guest_clock_frozen_constructor() {
    use hermetic_gateway::GuestClock;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let t_clock = OffsetDateTime::parse("2026-11-11T12:00:00Z", &Rfc3339).unwrap();
    let clock = GuestClock::frozen(t_clock, std::time::Duration::from_secs(120));

    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(clock.elapsed_secs(), 120);
    assert_eq!(clock.now(), t_clock + time::Duration::seconds(120));
    assert_eq!(
        clock.format_imf_fixdate().unwrap(),
        "Wed, 11 Nov 2026 12:02:00 GMT"
    );
}

#[test]
fn test_startup_validation_refuses_invalid_t_clock_and_wall_limit() {
    use hermetic_gateway::config::GatewayConfig;
    use hermetic_gateway::quota::QuotasConfig;
    use hermetic_gateway::server::GatewayServer;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("api_key.txt");
    std::fs::write(&key_path, "secret").unwrap();

    let config = GatewayConfig::from_raw(
        "http://127.0.0.1:8080".to_string(),
        "2023-06-01".to_string(),
        vec![],
        vec!["claude-3-5-sonnet-20241022".to_string()],
        QuotasConfig::default(),
        temp_dir.path().join("logs"),
        key_path,
        "secret".to_string(),
    );

    // Invalid t_clock: year out of IMF-fixdate 4-digit range (year 9999 with -12:00 offset rolls to year 10000 in UTC)
    let invalid_dt = time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(9999, time::Month::December, 31).unwrap(),
        time::Time::from_hms(23, 59, 59).unwrap(),
    )
    .assume_offset(time::UtcOffset::from_hms(-12, 0, 0).unwrap());

    let res = GatewayServer::new(config.clone(), invalid_dt);
    assert!(
        res.is_err(),
        "Server must refuse to start with unformattable T_clock"
    );

    // Invalid T_clock + wall-time limit: T_clock in year 9999, wall limit is 1 year (overflows 4-digit year)
    let end_of_9999 = time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(9999, time::Month::December, 31).unwrap(),
        time::Time::from_hms(12, 0, 0).unwrap(),
    )
    .assume_utc();

    let mut config_with_wall_limit = config;
    config_with_wall_limit.quotas.max_wall_time_seconds = Some(86400 * 365);
    let res2 = GatewayServer::new(config_with_wall_limit, end_of_9999);
    assert!(
        res2.is_err(),
        "Server must refuse to start when T_clock + wall-time limit overflows IMF-fixdate"
    );
}

#[test]
fn test_every_response_kind_carries_exactly_one_guest_date_header_and_never_host_clock() {
    use hermetic_gateway::quota::QuotasConfig;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    // Choose T_clock in 2019 so difference from host clock is unmistakable
    let t_clock = OffsetDateTime::parse("2019-06-15T10:30:00Z", &Rfc3339).unwrap();

    let env = TestEnv::new_with_options(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec!["prompt-caching-2024-07-31".to_string()],
        QuotasConfig {
            max_requests: Some(2), // Allow 2 requests so request 3 gets 429
            ..Default::default()
        },
        t_clock,
        None,
    );

    fn check_guest_date(res: &ureq::Response, t_clock: OffsetDateTime, kind: &str) {
        let date_vals = res.all("date");
        assert_eq!(
            date_vals.len(),
            1,
            "Response for {kind} (status {}) must carry exactly one Date header, got: {date_vals:?}",
            res.status()
        );
        let date_str = date_vals[0];
        let parsed =
            hermetic_gateway::response::parse_date_or_rfc3339(date_str).unwrap_or_else(|| {
                panic!("Date header for {kind} must be valid IMF-fixdate: '{date_str}'")
            });
        assert_eq!(
            parsed.year(),
            2019,
            "Date header for {kind} must equal guest time year 2019, got '{date_str}'"
        );
        let diff = (parsed - t_clock).whole_seconds().abs();
        assert!(
            diff <= 120,
            "Date header for {kind} ('{date_str}') must be within 120s of t_clock ({t_clock}), diff={diff}s"
        );
        let host_now = OffsetDateTime::now_utc();
        let host_diff = (parsed - host_now).whole_seconds().abs();
        assert!(
            host_diff > 86400 * 365,
            "Date header for {kind} ('{date_str}') must never be near host clock ({host_now})"
        );
    }

    let make_client = || common::test_client();

    // 1. Success (200 non-stream)
    {
        let mock = env.mock_server.clone();
        let h = thread::spawn(move || {
            let req = common::recv_upstream(&mock);
            req.respond(Response::from_string(
                r#"{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#,
            ))
            .unwrap();
        });

        let res = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#)
            .expect("200 success");
        assert_eq!(res.status(), 200);
        check_guest_date(&res, t_clock, "200 success");
        let _ = res.into_string();
        common::join_within(h);
    }

    // 2. Stream (200 stream)
    {
        let mock = env.mock_server.clone();
        let h = thread::spawn(move || {
            let req = common::recv_upstream(&mock);
            let sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"1\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
            req.respond(Response::new(
                200.into(),
                vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
                std::io::Cursor::new(sse.as_bytes().to_vec()),
                Some(sse.len()),
                None,
            ))
            .unwrap();
        });

        let res = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}],"stream":true}"#)
            .expect("200 stream success");
        assert_eq!(res.status(), 200);
        check_guest_date(&res, t_clock, "200 stream");
        let mut body = String::new();
        let _ = res.into_reader().read_to_string(&mut body);
        common::join_within(h);
    }

    // 4. 404 Not Found (wrong endpoint)
    {
        let err = make_client()
            .post(&format!("{}/v1/nonexistent", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string("{}")
            .unwrap_err();
        if let ureq::Error::Status(404, resp) = err {
            check_guest_date(&resp, t_clock, "404 not found");
        } else {
            panic!("Expected 404, got {err:?}");
        }
    }

    // 5. 413 Request Too Large (> 32 MiB via declared Content-Length)
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .set("Content-Length", "34000000") // 34 MB declared length > 32 MB limit
            .set("connection", "close")
            .send(std::io::Cursor::new(vec![b'A'; 100]))
            .unwrap_err();
        if let ureq::Error::Status(413, resp) = err {
            check_guest_date(&resp, t_clock, "413 request too large");
        } else {
            panic!("Expected 413, got {err:?}");
        }
    }

    // 6. Error path: 400 missing anthropic-version
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#)
            .unwrap_err();
        if let ureq::Error::Status(400, resp) = err {
            check_guest_date(&resp, t_clock, "400 missing version");
        } else {
            panic!("Expected 400, got {err:?}");
        }
    }

    // 7. Error path: 400 invalid anthropic-version
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "1999-01-01")
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#)
            .unwrap_err();
        if let ureq::Error::Status(400, resp) = err {
            check_guest_date(&resp, t_clock, "400 invalid version");
        } else {
            panic!("Expected 400, got {err:?}");
        }
    }

    // 8. Error path: 400 unlisted beta flag
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("anthropic-beta", "unlisted-beta-flag-xyz")
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#)
            .unwrap_err();
        if let ureq::Error::Status(400, resp) = err {
            check_guest_date(&resp, t_clock, "400 unlisted beta");
        } else {
            panic!("Expected 400, got {err:?}");
        }
    }

    // 9. Error path: 400 Content-Type not application/json
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "text/plain")
            .send_string("not json")
            .unwrap_err();
        if let ureq::Error::Status(400, resp) = err {
            check_guest_date(&resp, t_clock, "400 bad content-type");
        } else {
            panic!("Expected 400, got {err:?}");
        }
    }

    // 10. Error path: 400 invalid UTF-8
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_bytes(&[0xff, 0xfe, 0xfd])
            .unwrap_err();
        if let ureq::Error::Status(400, resp) = err {
            check_guest_date(&resp, t_clock, "400 invalid utf8");
        } else {
            panic!("Expected 400, got {err:?}");
        }
    }

    // 11. Error path: 400 unpinned model
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(
                r#"{"model":"claude-unpinned-xyz","messages":[{"role":"user","content":"Hi"}]}"#,
            )
            .unwrap_err();
        if let ureq::Error::Status(400, resp) = err {
            check_guest_date(&resp, t_clock, "400 unpinned model");
        } else {
            panic!("Expected 400, got {err:?}");
        }
    }

    // 3. 429 Limit Exceeded (Quota refusal) - 2 requests completed, the 3rd exceeds the quota.
    // Runs last on this env: once limit_exceeded, requests are refused before the body is read.
    {
        let err = make_client()
            .post(&format!("{}/v1/messages", env.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#)
            .unwrap_err();
        if let ureq::Error::Status(429, resp) = err {
            check_guest_date(&resp, t_clock, "429 limit exceeded");
        } else {
            panic!("Expected 429 status for quota breach, got {err:?}");
        }
    }

    // 12. Upstream non-2xx error path: 502/500
    {
        let env_upstream_err = TestEnv::new_with_options(
            vec!["claude-3-5-sonnet-20241022".to_string()],
            vec![],
            QuotasConfig::default(),
            t_clock,
            None,
        );
        let mock = env_upstream_err.mock_server.clone();
        let h = thread::spawn(move || {
            let req = common::recv_upstream(&mock);
            req.respond(Response::new(
                500.into(),
                vec![Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()],
                std::io::Cursor::new(
                    br#"{"type":"error","error":{"type":"api_error","message":"Internal"}}"#
                        .to_vec(),
                ),
                Some(61),
                None,
            ))
            .unwrap();
        });

        let err = make_client()
            .post(&format!("{}/v1/messages", env_upstream_err.gateway_url))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#)
            .unwrap_err();
        if let ureq::Error::Status(500, resp) = err {
            check_guest_date(&resp, t_clock, "500 upstream error");
        } else {
            panic!("Expected 500, got {err:?}");
        }
        common::join_within(h);
    }
}
