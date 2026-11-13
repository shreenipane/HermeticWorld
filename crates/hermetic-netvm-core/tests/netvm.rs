use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hermetic_netvm_core::dns::{
    decode_dns_a_answer, encode_dns_a_query, StaticDnsResponder, DNS_BUCKET_CAPACITY,
    MAX_DNS_PACKET_BYTES,
};
use hermetic_netvm_core::headers::parse_http_date_epoch_secs;
use hermetic_netvm_core::http::{
    FilterDecision, HttpRuntimeConfig, MethodAllowFilter, RequestFilter, StaticUpstream, Upstream,
    UpstreamError, UpstreamResponse, NOT_ALLOWED_RESPONSE_BYTES,
};
use hermetic_netvm_core::{NetvmConfig, RunningNetvm, VecLogSink};

fn start_test_server(
    http_config: HttpRuntimeConfig,
    dns: StaticDnsResponder,
    filter: Arc<dyn RequestFilter>,
    upstream: Arc<dyn Upstream>,
) -> (RunningNetvm, Arc<VecLogSink>) {
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP");
    let http_listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral TCP");
    let log_sink = Arc::new(VecLogSink::new());

    let server = RunningNetvm::start(
        dns_socket,
        http_listener,
        http_config,
        Arc::new(dns),
        filter,
        upstream,
        log_sink.clone(),
    )
    .expect("start netvm");

    (server, log_sink)
}

fn default_test_http_config(t_clock: i64) -> HttpRuntimeConfig {
    HttpRuntimeConfig::bounded(16, 2_000, 1_000, 5_000, t_clock)
}

fn send_http_and_read_all(addr: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect TCP");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("set write timeout");
    stream.write_all(request).expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    response
}

fn split_head_body(raw_response: &[u8]) -> (String, Vec<u8>) {
    let marker = raw_response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response must contain CRLFCRLF");
    let head = std::str::from_utf8(&raw_response[..marker]).expect("valid UTF-8 response head");
    let body = raw_response[(marker + 4)..].to_vec();
    (head.to_string(), body)
}

#[test]
fn test_dns_round_trip_via_fake() {
    let mut dns = StaticDnsResponder::new();
    dns.insert("crates.hermetic.local", [10, 42, 0, 7]);

    let (server, _logs) = start_test_server(
        default_test_http_config(1_700_000_000),
        dns,
        Arc::new(MethodAllowFilter),
        Arc::new(StaticUpstream::new()),
    );

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client UDP");
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .expect("set timeout");

    let query = encode_dns_a_query(0x1234, "crates.hermetic.local").expect("encode query");
    client
        .send_to(&query, server.dns_addr())
        .expect("send DNS query");

    let mut reply_buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut reply_buf).expect("receive DNS reply");
    let (resp_id, ipv4) = decode_dns_a_answer(&reply_buf[..n]).expect("decode DNS answer");
    assert_eq!(resp_id, 0x1234);
    assert_eq!(ipv4, [10, 42, 0, 7]);

    // Unknown domain gets an authoritative NXDOMAIN (TR-NET-2), never forwarded anywhere.
    let unknown_query = encode_dns_a_query(0x5678, "unknown.example.com").expect("encode query");
    client
        .send_to(&unknown_query, server.dns_addr())
        .expect("send unknown DNS query");
    let (n, _) = client
        .recv_from(&mut reply_buf)
        .expect("receive NXDOMAIN reply");
    let reply = &reply_buf[..n];
    assert_eq!(&reply[0..2], &0x5678u16.to_be_bytes());
    assert_eq!(reply[3] & 0x0F, 3, "RCODE must be NXDOMAIN");
    assert_eq!(&reply[6..8], &[0, 0], "no answer records");
    assert!(decode_dns_a_answer(reply).is_err());

    // A malformed datagram (a response, QR=1) is still dropped without a reply.
    let mut bogus = encode_dns_a_query(0x5679, "crates.hermetic.local").expect("encode query");
    bogus[2] |= 0x80;
    client
        .send_to(&bogus, server.dns_addr())
        .expect("send malformed DNS datagram");
    assert!(client.recv_from(&mut reply_buf).is_err());

    let snap = server.metrics().snapshot();
    assert_eq!(snap.dns_answered, 2);
    assert_eq!(snap.dns_dropped_unanswered, 1);

    server.stop();
}

#[test]
fn test_dns_oversized_datagram_dropped() {
    let mut dns = StaticDnsResponder::new();
    dns.insert("crates.hermetic.local", [10, 42, 0, 7]);

    let (server, _logs) = start_test_server(
        default_test_http_config(1_700_000_000),
        dns,
        Arc::new(MethodAllowFilter),
        Arc::new(StaticUpstream::new()),
    );

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client UDP");
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set timeout");

    let mut oversized = encode_dns_a_query(0x9999, "crates.hermetic.local").expect("encode query");
    oversized.resize(MAX_DNS_PACKET_BYTES + 1, 0);

    client
        .send_to(&oversized, server.dns_addr())
        .expect("send oversized datagram");

    let mut reply_buf = [0u8; 512];
    assert!(client.recv_from(&mut reply_buf).is_err());

    let snap = server.metrics().snapshot();
    assert_eq!(snap.dns_dropped_oversized, 1);
    assert_eq!(snap.dns_answered, 0);

    server.stop();
}

#[test]
fn test_dns_per_source_rate_cap() {
    let mut dns = StaticDnsResponder::new();
    dns.insert("crates.hermetic.local", [10, 42, 0, 7]);

    let (server, _logs) = start_test_server(
        default_test_http_config(1_700_000_000),
        dns,
        Arc::new(MethodAllowFilter),
        Arc::new(StaticUpstream::new()),
    );

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client UDP");
    client
        .set_read_timeout(Some(Duration::from_millis(120)))
        .expect("set timeout");

    let total_sent = DNS_BUCKET_CAPACITY + 6;
    for i in 0..total_sent {
        let q = encode_dns_a_query(0x2000 + i as u16, "crates.hermetic.local").expect("encode");
        client.send_to(&q, server.dns_addr()).expect("send");
    }

    let mut answered = 0u32;
    let mut reply_buf = [0u8; 512];
    while let Ok((n, _)) = client.recv_from(&mut reply_buf) {
        let (_id, ipv4) = decode_dns_a_answer(&reply_buf[..n]).expect("valid answer");
        assert_eq!(ipv4, [10, 42, 0, 7]);
        answered += 1;
    }

    assert!(answered <= DNS_BUCKET_CAPACITY + 1);
    assert!(answered >= DNS_BUCKET_CAPACITY);

    let snap = server.metrics().snapshot();
    assert!(snap.dns_dropped_rate_limited >= 5);

    server.stop();
}

#[test]
fn test_http_get_forwarded_with_header_filtering() {
    let t_clock = parse_http_date_epoch_secs("Wed, 15 Nov 2023 00:00:00 GMT").expect("valid date");
    let mut upstream = StaticUpstream::new();
    upstream.insert(
        "GET",
        "/index.json",
        200,
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Length".to_string(), "13".to_string()),
            ("ETag".to_string(), "\"v1-hermetic\"".to_string()),
            (
                "Last-Modified".to_string(),
                "Tue, 14 Nov 2023 12:00:00 GMT".to_string(),
            ),
            ("Content-Encoding".to_string(), "identity".to_string()),
            ("Accept-Ranges".to_string(), "bytes".to_string()),
            ("Content-Range".to_string(), "bytes 0-12/13".to_string()),
            // Forbidden headers that MUST be stripped:
            (
                "Date".to_string(),
                "Fri, 13 Nov 2026 01:00:00 GMT".to_string(),
            ),
            ("Server".to_string(), "Apache/2.4.99".to_string()),
            ("Set-Cookie".to_string(), "session=leak".to_string()),
            ("Age".to_string(), "3600".to_string()),
            ("Via".to_string(), "1.1 proxy.internal".to_string()),
            ("X-Powered-By".to_string(), "SecretStack".to_string()),
            ("X-Custom-Leak".to_string(), "forbidden".to_string()),
        ],
        b"{\"ok\":true}\n\n".to_vec(),
    );

    let (server, _logs) = start_test_server(
        default_test_http_config(t_clock),
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(upstream),
    );

    let raw = send_http_and_read_all(
        server.http_addr(),
        b"GET /index.json HTTP/1.1\r\nHost: crates.hermetic.local\r\n\r\n",
    );
    let (head, body) = split_head_body(&raw);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body, b"{\"ok\":true}\n\n");

    let lower_head = head.to_ascii_lowercase();
    for allowed in [
        "content-type: application/json",
        "content-length: 13",
        "etag: \"v1-hermetic\"",
        "last-modified: tue, 14 nov 2023 12:00:00 gmt",
        "content-encoding: identity",
        "accept-ranges: bytes",
        "content-range: bytes 0-12/13",
    ] {
        assert!(
            lower_head.contains(allowed),
            "expected allowed header `{allowed}` in:\n{head}"
        );
    }

    for forbidden in [
        "\ndate:",
        "\nserver:",
        "\nset-cookie:",
        "\nage:",
        "\nvia:",
        "\nx-",
    ] {
        assert!(
            !lower_head.contains(forbidden),
            "forbidden header `{forbidden}` leaked in:\n{head}"
        );
    }

    server.stop();
}

#[test]
fn test_http_last_modified_after_t_clock_dropped() {
    let t_clock = parse_http_date_epoch_secs("Wed, 15 Nov 2023 00:00:00 GMT").expect("valid date");
    let mut upstream = StaticUpstream::new();

    upstream.insert(
        "GET",
        "/before",
        200,
        vec![
            (
                "Last-Modified".to_string(),
                "Tue, 14 Nov 2023 23:59:59 GMT".to_string(),
            ),
            ("Content-Length".to_string(), "2".to_string()),
        ],
        b"ok".to_vec(),
    );
    upstream.insert(
        "GET",
        "/equal",
        200,
        vec![
            (
                "Last-Modified".to_string(),
                "Wed, 15 Nov 2023 00:00:00 GMT".to_string(),
            ),
            ("Content-Length".to_string(), "2".to_string()),
        ],
        b"ok".to_vec(),
    );
    upstream.insert(
        "GET",
        "/after",
        200,
        vec![
            (
                "Last-Modified".to_string(),
                "Wed, 15 Nov 2023 00:00:01 GMT".to_string(),
            ),
            ("Content-Length".to_string(), "2".to_string()),
        ],
        b"ok".to_vec(),
    );

    let (server, _logs) = start_test_server(
        default_test_http_config(t_clock),
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(upstream),
    );

    let (head_before, _) = split_head_body(&send_http_and_read_all(
        server.http_addr(),
        b"GET /before HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ));
    assert!(head_before.contains("Last-Modified: Tue, 14 Nov 2023 23:59:59 GMT"));

    let (head_equal, _) = split_head_body(&send_http_and_read_all(
        server.http_addr(),
        b"GET /equal HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ));
    assert!(head_equal.contains("Last-Modified: Wed, 15 Nov 2023 00:00:00 GMT"));

    let (head_after, _) = split_head_body(&send_http_and_read_all(
        server.http_addr(),
        b"GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ));
    assert!(
        !head_after.to_ascii_lowercase().contains("last-modified:"),
        "Last-Modified after T_clock must be dropped, got:\n{head_after}"
    );

    server.stop();
}

#[test]
fn test_http_405_reply_bytes_exact() {
    let (server, _logs) = start_test_server(
        default_test_http_config(1_700_000_000),
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(StaticUpstream::new()),
    );

    for req in [
        b"POST /api/push HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ndata".as_slice(),
        b"PUT /item HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
        b"DELETE /item HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
    ] {
        let reply = send_http_and_read_all(server.http_addr(), req);
        assert_eq!(reply, NOT_ALLOWED_RESPONSE_BYTES);
    }

    assert_eq!(server.metrics().snapshot().http_not_allowed, 3);
    server.stop();
}

#[test]
fn test_http_reject_closes_silently() {
    struct AlwaysRejectFilter;
    impl RequestFilter for AlwaysRejectFilter {
        fn check(&self, _head: &[u8], _tls: bool, _sni: Option<&str>) -> FilterDecision {
            FilterDecision::Reject
        }
    }

    let (server, _logs) = start_test_server(
        default_test_http_config(1_700_000_000),
        StaticDnsResponder::new(),
        Arc::new(AlwaysRejectFilter),
        Arc::new(StaticUpstream::new()),
    );

    let reply = send_http_and_read_all(
        server.http_addr(),
        b"GET /anything HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert!(
        reply.is_empty(),
        "Reject must close without sending any bytes"
    );
    assert_eq!(server.metrics().snapshot().http_rejected, 1);

    server.stop();
}

#[test]
fn test_http_slow_loris_head_hits_deadline() {
    let mut upstream = StaticUpstream::new();
    upstream.insert(
        "GET",
        "/fast",
        200,
        vec![("Content-Length".to_string(), "2".to_string())],
        b"ok".to_vec(),
    );

    // 120ms head deadline, 1 connection slot so we also verify the slow client releases its slot.
    let cfg = HttpRuntimeConfig::bounded(1, 120, 500, 2_000, 1_700_000_000);
    let (server, _logs) = start_test_server(
        cfg,
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(upstream),
    );

    let start = Instant::now();
    let mut slow_client = TcpStream::connect(server.http_addr()).expect("connect slow client");
    slow_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    slow_client
        .write_all(b"GET /fast HTTP/1.1\r\nHost: example.com\r\n")
        .expect("write partial head");

    // Server must time out the incomplete head and close the connection promptly.
    let mut buf = Vec::new();
    slow_client.read_to_end(&mut buf).expect("EOF from server");
    let elapsed = start.elapsed();
    assert!(buf.is_empty());
    assert!(elapsed < Duration::from_secs(1));
    assert_eq!(server.metrics().snapshot().http_head_timeouts, 1);

    // The single slot must now be free for a legitimate request.
    let (head, body) = split_head_body(&send_http_and_read_all(
        server.http_addr(),
        b"GET /fast HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ));
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body, b"ok");

    server.stop();
}

#[test]
fn test_http_slow_reader_hits_write_deadline() {
    // 4 MiB body exceeds OS loopback socket buffers, forcing writes to block until read.
    let large_body = vec![b'A'; 4 * 1024 * 1024];
    let mut upstream = StaticUpstream::new();
    upstream.insert(
        "GET",
        "/large",
        200,
        vec![("Content-Length".to_string(), large_body.len().to_string())],
        large_body,
    );
    upstream.insert(
        "GET",
        "/after",
        200,
        vec![("Content-Length".to_string(), "4".to_string())],
        b"done".to_vec(),
    );

    // 1 slot, 120ms per-chunk write timeout, 5000ms overall timeout.
    let cfg = HttpRuntimeConfig::bounded(1, 1_000, 120, 5_000, 1_700_000_000);
    let (server, _logs) = start_test_server(
        cfg,
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(upstream),
    );

    let mut slow_reader = TcpStream::connect(server.http_addr()).expect("connect slow reader");
    slow_reader
        .write_all(b"GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("send GET /large");
    // Intentionally never read from `slow_reader` so kernel send buffer stalls.

    // Wait for the chunk write deadline to expire and free the single connection slot.
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.metrics().snapshot().http_write_timeouts == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(server.metrics().snapshot().http_write_timeouts, 1);

    drop(slow_reader);

    // Slot is free; next request succeeds immediately.
    let (head, body) = split_head_body(&send_http_and_read_all(
        server.http_addr(),
        b"GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ));
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body, b"done");

    server.stop();
}

#[test]
fn test_http_connection_cap_closes_extra_immediately() {
    let mut upstream = StaticUpstream::new();
    upstream.insert(
        "GET",
        "/ok",
        200,
        vec![("Content-Length".to_string(), "2".to_string())],
        b"ok".to_vec(),
    );

    // Cap at 2 concurrent connections; 350ms head timeout so held connections stay active briefly.
    let cfg = HttpRuntimeConfig::bounded(2, 350, 500, 2_000, 1_700_000_000);
    let (server, _logs) = start_test_server(
        cfg,
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(upstream),
    );

    // Occupy both connection slots with incomplete request heads.
    let mut c1 = TcpStream::connect(server.http_addr()).expect("connect c1");
    c1.write_all(b"GET /ok HTTP/1.1\r\n").expect("write c1");
    let mut c2 = TcpStream::connect(server.http_addr()).expect("connect c2");
    c2.write_all(b"GET /ok HTTP/1.1\r\n").expect("write c2");

    let wait_accept = Instant::now() + Duration::from_secs(1);
    while server.metrics().snapshot().http_connections_accepted < 2 && Instant::now() < wait_accept
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.metrics().snapshot().http_connections_accepted, 2);

    // 3rd connection exceeds cap and must be closed immediately with 0 bytes.
    let mut c3 = TcpStream::connect(server.http_addr()).expect("connect c3");
    c3.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set timeout c3");
    let _ = c3.write_all(b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let mut c3_buf = Vec::new();
    let read_res = c3.read_to_end(&mut c3_buf);
    assert!(read_res.is_ok() || c3_buf.is_empty());
    assert!(c3_buf.is_empty());
    assert!(server.metrics().snapshot().http_connections_rejected_cap >= 1);

    let _ = c1.shutdown(Shutdown::Both);
    let _ = c2.shutdown(Shutdown::Both);
    drop(c1);
    drop(c2);

    // Once c1/c2 close, subsequent connection succeeds.
    std::thread::sleep(Duration::from_millis(50));
    let (head, body) = split_head_body(&send_http_and_read_all(
        server.http_addr(),
        b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ));
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body, b"ok");

    server.stop();
}

#[test]
fn test_no_date_or_server_ever_and_structured_logs_valid() {
    struct CustomUpstream;
    impl Upstream for CustomUpstream {
        fn fetch(
            &self,
            request_json: &[u8],
            _deadline: Instant,
        ) -> Result<UpstreamResponse, UpstreamError> {
            let text = std::str::from_utf8(request_json).unwrap_or("");
            if text.contains("/timeout") {
                return Err(UpstreamError::Timeout);
            }
            if text.contains("/error") {
                return Err(UpstreamError::Backend("boom".to_string()));
            }
            Ok(UpstreamResponse {
                status: 200,
                headers: vec![
                    ("Content-Type".to_string(), "text/plain".to_string()),
                    ("Content-Length".to_string(), "5".to_string()),
                    (
                        "Date".to_string(),
                        "Fri, 13 Nov 2026 01:00:00 GMT".to_string(),
                    ),
                    ("Server".to_string(), "LeakyServer/1.0".to_string()),
                ],
                body: Box::new(std::io::Cursor::new(b"hello".to_vec())),
            })
        }
    }

    let (server, log_sink) = start_test_server(
        default_test_http_config(1_700_000_000),
        StaticDnsResponder::new(),
        Arc::new(MethodAllowFilter),
        Arc::new(CustomUpstream),
    );

    let secret_marker = "SECRET_REQUEST_BODY_SHOULD_NEVER_BE_LOGGED";
    let post_with_body = format!(
        "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n{}",
        secret_marker.len(),
        secret_marker
    );

    let responses = [
        send_http_and_read_all(
            server.http_addr(),
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
        send_http_and_read_all(
            server.http_addr(),
            b"HEAD /ok HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
        send_http_and_read_all(server.http_addr(), post_with_body.as_bytes()),
        send_http_and_read_all(
            server.http_addr(),
            b"GET /timeout HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
        send_http_and_read_all(
            server.http_addr(),
            b"GET /error HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
    ];

    for raw in &responses {
        let lower = String::from_utf8_lossy(raw).to_ascii_lowercase();
        assert!(!lower.contains("\ndate:"), "Date header leaked: {lower}");
        assert!(
            !lower.contains("\nserver:"),
            "Server header leaked: {lower}"
        );
    }

    // HEAD response must have headers but zero body bytes.
    let (_head_line, head_body) = split_head_body(&responses[1]);
    assert!(head_body.is_empty());

    server.stop();

    let lines = log_sink.lines();
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(!line.contains(secret_marker));
        assert!(!line.contains("timestamp"));
        assert!(!line.contains("2026"));

        let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON log line");
        let obj = parsed.as_object().expect("JSON log line must be an object");
        for (k, v) in obj {
            if k == "event" {
                assert!(v.is_string());
            } else {
                assert!(
                    v.is_u64(),
                    "log field `{k}` must be an integer counter, got {v}"
                );
            }
        }
    }
}

#[test]
fn test_config_parsing_with_http_date_and_integer_t_clock() {
    let cfg_str = r#"{
        "t_clock": "Wed, 15 Nov 2023 00:00:00 GMT",
        "max_connections": 8,
        "dns_records": { "example.com": "93.184.216.34" },
        "static_routes": [
            {
                "method": "GET",
                "target": "/hello",
                "status": 200,
                "headers": [["Content-Type", "text/plain"], ["Content-Length", "5"]],
                "body": "world"
            }
        ]
    }"#;
    let cfg = NetvmConfig::from_json_str(cfg_str).expect("parse config");
    assert_eq!(cfg.t_clock, 1_700_006_400);
    let (_dns, _filter, _upstream) = cfg.build_default_components().expect("build components");
}

#[test]
fn regression_dns_unknown_name_nxdomain_and_known_name_other_type_nodata() {
    use hermetic_netvm_core::dns::DnsResponder;
    let mut dns = StaticDnsResponder::new();
    dns.insert("crates.hermetic.local", [10, 42, 0, 7]);

    let unknown = encode_dns_a_query(0x0101, "post-cutoff.example").expect("encode");
    let reply = dns
        .respond(&unknown)
        .expect("unknown names must be answered");
    assert_eq!(&reply[0..2], &0x0101u16.to_be_bytes());
    assert_ne!(reply[2] & 0x80, 0, "QR bit set");
    assert_eq!(reply[3] & 0x0F, 3, "NXDOMAIN");
    assert_eq!(&reply[4..6], &[0, 1]);
    assert_eq!(&reply[6..8], &[0, 0]);
    assert_eq!(&reply[12..], &unknown[12..]);

    // AAAA (28) for a known name: NOERROR with no answers.
    let mut aaaa = encode_dns_a_query(0x0202, "crates.hermetic.local").expect("encode");
    let len = aaaa.len();
    aaaa[len - 4..len - 2].copy_from_slice(&28u16.to_be_bytes());
    let reply = dns
        .respond(&aaaa)
        .expect("known name, other type is answered");
    assert_eq!(reply[3] & 0x0F, 0, "NOERROR");
    assert_eq!(&reply[6..8], &[0, 0]);
}

#[test]
fn regression_missing_or_duplicate_host_is_rejected() {
    let filter = MethodAllowFilter;
    assert_eq!(
        filter.check(b"GET / HTTP/1.1\r\n\r\n", false, None),
        FilterDecision::Reject
    );
    assert_eq!(
        filter.check(b"GET / HTTP/1.1\r\nHost:\r\n\r\n", false, None),
        FilterDecision::Reject
    );
    assert_eq!(
        filter.check(
            b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
            false,
            None
        ),
        FilterDecision::Reject
    );
    assert!(matches!(
        filter.check(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", false, None),
        FilterDecision::Forward(_)
    ));
}

#[test]
fn regression_config_unknown_field_rejected() {
    let err = NetvmConfig::from_json_str(r#"{"t_clock": 1700000000, "max_connection": 2}"#);
    assert!(err.is_err(), "misspelled setting must fail closed");
    let err = NetvmConfig::from_json_str(
        r#"{"t_clock": 1700000000, "static_routes": [{"target": "/", "bodyy": "x"}]}"#,
    );
    assert!(err.is_err());
}
