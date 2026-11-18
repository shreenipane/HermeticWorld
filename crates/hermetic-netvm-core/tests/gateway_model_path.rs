#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hermetic_common::hash::HashChain;
use hermetic_gateway::config::GatewayConfig;
use hermetic_gateway::log::{GatewayHeadSummary, GATEWAY_HEAD_FILE};
use hermetic_gateway::server::GatewayServer;
use hermetic_netvm_core::firewall::InterceptionPath;
use hermetic_netvm_core::http::{HttpRuntimeConfig, RequestFilter, NOT_ALLOWED_RESPONSE_BYTES};
use hermetic_netvm_core::runtime::{WorldDns, WorldFilter};
use hermetic_netvm_core::upstream::{GatewayUpstream, VsockUpstream};
use hermetic_netvm_core::{RunningNetvm, VecLogSink};
use hermetic_netvm_dns::DnsTable;
use hermetic_world_server::{ServerConfig as WorldServerConfig, WorldServer};
use tempfile::tempdir;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const MODEL_HOST: &str = "api.anthropic.com";
const WORLD_HOST: &str = "files.example";
const MODEL_IP: &str = "10.9.0.2";
const WORLD_IP: &str = "10.9.0.1";

fn table() -> DnsTable {
    DnsTable::from_json_str(
        r#"{"records":[{"name":"api.anthropic.com","a":["10.9.0.2"]},{"name":"files.example","a":["10.9.0.1"]}]}"#,
    )
    .expect("test dns table")
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create dir");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod 0700");
}

fn start_mock_gateway_socket(
    socket_path: &Path,
) -> (thread::JoinHandle<()>, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = UnixListener::bind(socket_path).expect("bind gateway test socket");
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count_clone = Arc::clone(&count);

    let handle = thread::spawn(move || {
        let (mut stream, _) = match listener.accept() {
            Ok(p) => p,
            Err(_) => return,
        };
        count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        const MAX_MOCK_HEAD_BYTES: usize = 16 * 1024;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while buf.len() < MAX_MOCK_HEAD_BYTES {
            let n = match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let req_str = String::from_utf8_lossy(&buf);

        assert!(req_str.contains("POST /v1/messages HTTP/1.1"));
        assert!(req_str.contains("connection: close"));

        let response_body = r#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"model reply"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });

    (handle, count)
}

#[test]
fn test_gateway_model_path_post_forwarded_and_response_returned() {
    let temp = tempdir().expect("tempdir");
    let gw_socket = temp.path().join("gateway.sock");
    let (gw_thread, gw_count) = start_mock_gateway_socket(&gw_socket);

    let dns_table = table();
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("local addr");

    let filter = Arc::new(WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Redirect,
        Some(MODEL_HOST.to_string()),
    ));
    let upstream = Arc::new(VsockUpstream::unix(temp.path().join("absent_world.sock")));
    let gateway_upstream = Arc::new(GatewayUpstream::unix(&gw_socket));
    let log_sink = Arc::new(VecLogSink::new());

    let server = RunningNetvm::start_with_gateway(
        dns_socket,
        http_listener,
        HttpRuntimeConfig::bounded(16, 5000, 2000, 10000, 1_700_000_000),
        Arc::new(WorldDns(dns_table)),
        filter,
        upstream,
        Some(gateway_upstream),
        log_sink,
    )
    .expect("start netvm");

    let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();

    let request_body = r#"{"model":"model-1","messages":[{"role":"user","content":"hello"}]}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        MODEL_HOST,
        request_body.len(),
        request_body
    );

    client.write_all(request.as_bytes()).expect("write request");
    client.flush().expect("flush request");

    let mut response = Vec::new();
    client.read_to_end(&mut response).expect("read response");
    let resp_str = String::from_utf8_lossy(&response);

    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK\r\n"),
        "response: {resp_str}"
    );
    assert!(resp_str.contains("model reply"), "response: {resp_str}");
    assert_eq!(gw_count.load(std::sync::atomic::Ordering::SeqCst), 1);

    gw_thread.join().expect("join mock thread");
    server.stop();
}

#[test]
fn test_gateway_model_path_get_is_405_not_allowed() {
    let temp = tempdir().expect("tempdir");
    let gw_socket = temp.path().join("gateway.sock");

    let dns_table = table();
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("local addr");

    let filter = Arc::new(WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Redirect,
        Some(MODEL_HOST.to_string()),
    ));
    let upstream = Arc::new(VsockUpstream::unix(temp.path().join("absent_world.sock")));
    let gateway_upstream = Arc::new(GatewayUpstream::unix(&gw_socket));
    let log_sink = Arc::new(VecLogSink::new());

    let server = RunningNetvm::start_with_gateway(
        dns_socket,
        http_listener,
        HttpRuntimeConfig::bounded(16, 5000, 2000, 10000, 1_700_000_000),
        Arc::new(WorldDns(dns_table)),
        filter,
        upstream,
        Some(gateway_upstream),
        log_sink,
    )
    .expect("start netvm");

    let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();

    let request = format!("GET /v1/messages HTTP/1.1\r\nHost: {}\r\n\r\n", MODEL_HOST);
    client.write_all(request.as_bytes()).expect("write request");
    client.flush().expect("flush request");

    let mut response = Vec::new();
    client.read_to_end(&mut response).expect("read response");
    assert_eq!(response.as_slice(), NOT_ALLOWED_RESPONSE_BYTES);

    server.stop();
}

#[test]
fn test_gateway_model_path_non_adapter_endpoint_is_rejected() {
    let temp = tempdir().expect("tempdir");
    let gw_socket = temp.path().join("gateway.sock");

    let dns_table = table();
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("local addr");

    let filter = Arc::new(WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Redirect,
        Some(MODEL_HOST.to_string()),
    ));
    let upstream = Arc::new(VsockUpstream::unix(temp.path().join("absent_world.sock")));
    let gateway_upstream = Arc::new(GatewayUpstream::unix(&gw_socket));
    let log_sink = Arc::new(VecLogSink::new());

    let server = RunningNetvm::start_with_gateway(
        dns_socket,
        http_listener,
        HttpRuntimeConfig::bounded(16, 5000, 2000, 10000, 1_700_000_000),
        Arc::new(WorldDns(dns_table)),
        filter,
        upstream,
        Some(gateway_upstream),
        log_sink,
    )
    .expect("start netvm");

    let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();

    // POST to non-adapter endpoint /v1/evil
    let request = format!(
        "POST /v1/evil HTTP/1.1\r\nHost: {}\r\nContent-Length: 2\r\n\r\n{{}}",
        MODEL_HOST
    );
    client.write_all(request.as_bytes()).expect("write request");
    client.flush().expect("flush request");

    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    // Connection must be reset / closed without forwarding
    assert!(
        response.is_empty(),
        "expected empty response on reject, got: {:?}",
        response
    );

    server.stop();
}

#[test]
fn test_gateway_model_path_destination_ip_mismatch_is_rejected() {
    let dns_table = table();
    let filter = WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Tproxy,
        Some(MODEL_HOST.to_string()),
    );

    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {}\r\nContent-Length: 2\r\n\r\n",
        MODEL_HOST
    );

    // Matching destination IP -> ForwardGateway
    let correct_ip: std::net::IpAddr = MODEL_IP.parse().unwrap();
    let dec = filter.check_with_dest(head.as_bytes(), false, None, Some(correct_ip));
    assert_eq!(
        dec,
        hermetic_netvm_core::http::FilterDecision::ForwardGateway
    );

    // Mismatched destination IP -> Reject
    let wrong_ip: std::net::IpAddr = WORLD_IP.parse().unwrap();
    let dec = filter.check_with_dest(head.as_bytes(), false, None, Some(wrong_ip));
    assert_eq!(dec, hermetic_netvm_core::http::FilterDecision::Reject);

    // Unknown IP -> Reject
    let unknown_ip: std::net::IpAddr = "10.9.0.99".parse().unwrap();
    let dec = filter.check_with_dest(head.as_bytes(), false, None, Some(unknown_ip));
    assert_eq!(dec, hermetic_netvm_core::http::FilterDecision::Reject);
}

#[test]
fn test_gateway_and_world_server_isolation_end_to_end() {
    let temp = tempdir().expect("tempdir");

    // 1. Setup WorldServer
    let store = temp.path().join("store");
    private_dir(&store.join(WORLD_HOST));
    std::fs::write(store.join(WORLD_HOST).join("index.html"), b"world hello\n").unwrap();
    private_dir(&temp.path().join("world_log"));
    let world_socket = temp.path().join("world.sock");
    let world_server = WorldServer::new(WorldServerConfig {
        store_dir: store,
        socket_path: world_socket.clone(),
        log_dir: temp.path().join("world_log"),
        t_clock: time::macros::datetime!(2023-11-14 22:13:20 UTC),
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: None,
        replay_index_path: None,
    })
    .unwrap();
    thread::spawn(move || {
        let _ = world_server.run();
    });

    let end = Instant::now() + TEST_TIMEOUT;
    while std::os::unix::net::UnixStream::connect(&world_socket).is_err() {
        assert!(Instant::now() < end, "world server did not start");
        thread::sleep(Duration::from_millis(10));
    }

    // 2. Setup mock Gateway
    let gw_socket = temp.path().join("gateway.sock");
    let (gw_thread, gw_count) = start_mock_gateway_socket(&gw_socket);

    // 3. Setup NetVM
    let dns_table = table();
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("local addr");

    let filter = Arc::new(WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Redirect,
        Some(MODEL_HOST.to_string()),
    ));
    let world_upstream = Arc::new(VsockUpstream::unix(&world_socket));
    let gateway_upstream = Arc::new(GatewayUpstream::unix(&gw_socket));
    let log_sink = Arc::new(VecLogSink::new());

    let server = RunningNetvm::start_with_gateway(
        dns_socket,
        http_listener,
        HttpRuntimeConfig::bounded(16, 5000, 2000, 10000, 1_700_000_000),
        Arc::new(WorldDns(dns_table)),
        filter,
        world_upstream,
        Some(gateway_upstream),
        log_sink,
    )
    .expect("start netvm");

    // Test A: Request to WorldServer -> goes to WorldServer
    {
        let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request = format!("GET /index.html HTTP/1.1\r\nHost: {}\r\n\r\n", WORLD_HOST);
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let resp_str = String::from_utf8_lossy(&response);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp_str.contains("world hello"));
        // Gateway must not have received this
        assert_eq!(gw_count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // Test B: POST to WorldServer -> 405 Method Not Allowed
    {
        let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request = format!(
            "POST /index.html HTTP/1.1\r\nHost: {}\r\nContent-Length: 2\r\n\r\n{{}}",
            WORLD_HOST
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response.as_slice(), NOT_ALLOWED_RESPONSE_BYTES);
        // Gateway must not have received this
        assert_eq!(gw_count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // Test C: Request to Gateway -> goes to Gateway
    {
        let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request_body = r#"{"model":"model-1","messages":[{"role":"user","content":"hello"}]}"#;
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            MODEL_HOST,
            request_body.len(),
            request_body
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let resp_str = String::from_utf8_lossy(&response);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp_str.contains("model reply"));
        assert_eq!(gw_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    gw_thread.join().expect("join mock thread");
    server.stop();
}

#[test]
fn test_netvm_to_gateway_end_to_end_with_hermetic_gateway_server() {
    let temp = tempdir().expect("tempdir");

    // 1. Fake upstream that answers 1 model call
    let mock_upstream = tiny_http::Server::http("127.0.0.1:0").expect("bind fake upstream");
    let upstream_addr = mock_upstream.server_addr().to_string();
    let upstream_thread = thread::spawn(move || {
        let req = mock_upstream
            .recv()
            .expect("fake upstream receives request");
        assert_eq!(req.url(), "/v1/messages");
        let body = r#"{"id":"msg_gateway_1","type":"message","role":"assistant","content":[{"type":"text","text":"fake upstream reply"}],"model":"model-test","usage":{"input_tokens":12,"output_tokens":6}}"#;
        let resp = tiny_http::Response::from_string(body)
            .with_status_code(200)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            );
        req.respond(resp).expect("respond from fake upstream");
    });

    // 2. Gateway setup listening on Unix domain socket
    let log_dir = temp.path().join("gateway_logs");
    private_dir(&log_dir);
    let key_file = temp.path().join("test_key.txt");
    std::fs::write(&key_file, "test-upstream-key-12345\n").unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let gw_socket = temp.path().join("gateway.sock");
    let config_path = temp.path().join("gateway_config.json");
    let config_json = serde_json::json!({
        "upstream_protocol": "anthropic",
        "upstream_base_url": format!("http://{upstream_addr}"),
        "anthropic_version": "2023-06-01",
        "pinned_models": ["model-test"],
        "api_key_file": key_file,
        "log_dir": log_dir.clone(),
        "quotas": {}
    });
    std::fs::write(&config_path, config_json.to_string()).unwrap();
    let config = GatewayConfig::load_from_file(config_path).expect("load gateway config");
    let t_clock = time::OffsetDateTime::parse(
        "2026-11-18T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let gateway_server =
        Arc::new(GatewayServer::new(config, t_clock).expect("create gateway server"));
    let gw_listener = std::os::unix::net::UnixListener::bind(&gw_socket).expect("bind gw listener");
    let http_gateway = tiny_http::Server::from_listener_with_deadlines(
        gw_listener,
        None,
        gateway_server.client_deadlines(),
    )
    .expect("gateway server from listener");

    let gw_clone = gateway_server.clone();
    let gw_worker = thread::spawn(move || {
        gw_clone.run_loop(http_gateway);
    });

    // 3. NetVM setup
    let dns_table = table();
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("local addr");

    let filter = Arc::new(WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Redirect,
        Some(MODEL_HOST.to_string()),
    ));
    let world_upstream = Arc::new(VsockUpstream::unix(temp.path().join("absent.sock")));
    let gateway_upstream = Arc::new(GatewayUpstream::unix(&gw_socket));
    let log_sink = Arc::new(VecLogSink::new());

    let netvm = RunningNetvm::start_with_gateway(
        dns_socket,
        http_listener,
        HttpRuntimeConfig::bounded(16, 5000, 2000, 10000, 1_700_000_000),
        Arc::new(WorldDns(dns_table)),
        filter,
        world_upstream,
        Some(gateway_upstream),
        log_sink,
    )
    .expect("start netvm");

    // 4. Client call through NetVM
    let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();

    let request_body = serde_json::json!({
        "model": "model-test",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hello"}]
    });
    let request_str = request_body.to_string();
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {}\r\nAnthropic-Version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        MODEL_HOST,
        request_str.len(),
        request_str
    );

    client
        .write_all(request.as_bytes())
        .expect("write to netvm");
    client.flush().expect("flush to netvm");

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read response from netvm");
    let resp_str = String::from_utf8_lossy(&response);

    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK\r\n"),
        "response: {resp_str}"
    );
    assert!(
        resp_str.contains("fake upstream reply"),
        "response: {resp_str}"
    );
    // Verify response carries guest date header and NOT host date
    assert!(
        resp_str.contains("date: Wed, 18 Nov 2026 12:00:00 GMT")
            || resp_str.contains("Date: Wed, 18 Nov 2026 12:00:00 GMT")
    );

    upstream_thread.join().expect("join fake upstream");

    // Stop gateway and netvm
    gateway_server.stop();
    gw_worker.join().expect("join gateway worker");
    netvm.stop();

    // 5. Verify gateway head persistence
    let head_file = log_dir.join(GATEWAY_HEAD_FILE);
    assert!(head_file.exists(), "gateway_head.json must be persisted");
    let raw = std::fs::read_to_string(&head_file).expect("read head file");
    let summary: GatewayHeadSummary = serde_json::from_str(&raw).expect("parse summary");
    assert_eq!(summary.records, 1);
    assert!(summary.head.starts_with("sha256:"));
    assert_eq!(summary.history_rewrite_count, 0);
    assert_eq!(summary.adapter_version, "2026-11-1");

    // 6. Verify hash chain independently against gateway.jsonl
    let log_file = log_dir.join("gateway.jsonl");
    let log_content = std::fs::read(&log_file).expect("read log");
    let head_hex = summary.head.strip_prefix("sha256:").unwrap();
    let verified_head =
        HashChain::verify_records([log_content.as_slice()], head_hex).expect("verify records");
    assert_eq!(verified_head, head_hex);
}

#[test]
fn test_netvm_to_gateway_streaming_sse_response() {
    let temp = tempdir().expect("tempdir");

    // 1. Fake upstream that returns an SSE stream
    let mock_upstream = tiny_http::Server::http("127.0.0.1:0").expect("bind fake upstream");
    let upstream_addr = mock_upstream.server_addr().to_string();
    let upstream_thread = thread::spawn(move || {
        let req = mock_upstream
            .recv()
            .expect("fake upstream receives request");
        assert_eq!(req.url(), "/v1/messages");
        let sse_payload = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"created_at\":1600000000,\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello from streaming model\"}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

        let resp = tiny_http::Response::new(
            200.into(),
            vec![
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..])
                    .unwrap(),
            ],
            std::io::Cursor::new(sse_payload.as_bytes().to_vec()),
            Some(sse_payload.len()),
            None,
        );
        req.respond(resp).expect("respond from fake upstream");
    });

    // 2. Gateway setup
    let log_dir = temp.path().join("gateway_logs");
    private_dir(&log_dir);
    let key_file = temp.path().join("test_key.txt");
    std::fs::write(&key_file, "test-upstream-key-12345\n").unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let gw_socket = temp.path().join("gateway.sock");
    let config_path = temp.path().join("gateway_config.json");
    let config_json = serde_json::json!({
        "upstream_protocol": "anthropic",
        "upstream_base_url": format!("http://{upstream_addr}"),
        "anthropic_version": "2023-06-01",
        "pinned_models": ["model-test"],
        "api_key_file": key_file,
        "log_dir": log_dir.clone(),
        "quotas": {}
    });
    std::fs::write(&config_path, config_json.to_string()).unwrap();
    let config = GatewayConfig::load_from_file(config_path).expect("load gateway config");
    let t_clock = time::OffsetDateTime::parse(
        "2026-11-18T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let gateway_server =
        Arc::new(GatewayServer::new(config, t_clock).expect("create gateway server"));
    let gw_listener = std::os::unix::net::UnixListener::bind(&gw_socket).expect("bind gw listener");
    let http_gateway = tiny_http::Server::from_listener_with_deadlines(
        gw_listener,
        None,
        gateway_server.client_deadlines(),
    )
    .expect("gateway server from listener");

    let gw_clone = gateway_server.clone();
    let gw_worker = thread::spawn(move || {
        gw_clone.run_loop(http_gateway);
    });

    // 3. NetVM setup
    let dns_table = table();
    let dns_socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("local addr");

    let filter = Arc::new(WorldFilter::with_gateway(
        &dns_table,
        InterceptionPath::Redirect,
        Some(MODEL_HOST.to_string()),
    ));
    let world_upstream = Arc::new(VsockUpstream::unix(temp.path().join("absent.sock")));
    let gateway_upstream = Arc::new(GatewayUpstream::unix(&gw_socket));
    let log_sink = Arc::new(VecLogSink::new());

    let netvm = RunningNetvm::start_with_gateway(
        dns_socket,
        http_listener,
        HttpRuntimeConfig::bounded(16, 5000, 2000, 10000, 1_700_000_000),
        Arc::new(WorldDns(dns_table)),
        filter,
        world_upstream,
        Some(gateway_upstream),
        log_sink,
    )
    .expect("start netvm");

    // 4. Client call with stream: true
    let mut client = TcpStream::connect(http_addr).expect("connect to netvm");
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();

    let request_body = serde_json::json!({
        "model": "model-test",
        "max_tokens": 100,
        "stream": true,
        "messages": [{"role": "user", "content": "stream please"}]
    });
    let request_str = request_body.to_string();
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {}\r\nAnthropic-Version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        MODEL_HOST,
        request_str.len(),
        request_str
    );

    client
        .write_all(request.as_bytes())
        .expect("write to netvm");
    client.flush().expect("flush to netvm");

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read response from netvm");
    let resp_str = String::from_utf8_lossy(&response);

    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK\r\n"),
        "response: {resp_str}"
    );
    assert!(
        resp_str.contains("event: message_start"),
        "response: {resp_str}"
    );
    assert!(
        resp_str.contains("Hello from streaming model"),
        "response: {resp_str}"
    );
    assert!(
        resp_str.contains("event: message_stop"),
        "response: {resp_str}"
    );

    upstream_thread.join().expect("join fake upstream");
    gateway_server.stop();
    gw_worker.join().expect("join gateway worker");
    netvm.stop();

    // 5. Verify head persistence
    let head_file = log_dir.join(GATEWAY_HEAD_FILE);
    assert!(head_file.exists(), "gateway_head.json must be persisted");
    let raw = std::fs::read_to_string(&head_file).expect("read head file");
    let summary: GatewayHeadSummary = serde_json::from_str(&raw).expect("parse summary");
    assert_eq!(summary.records, 1);
}

#[test]
fn test_mock_gateway_accumulates_fragmented_request_headers() {
    let temp = tempdir().expect("tempdir");
    let gw_socket = temp.path().join("frag_gateway.sock");
    let (gw_thread, gw_count) = start_mock_gateway_socket(&gw_socket);

    let mut stream =
        std::os::unix::net::UnixStream::connect(&gw_socket).expect("connect to mock gateway");
    stream
        .write_all(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n")
        .expect("write fragment 1");
    stream.flush().expect("flush fragment 1");
    std::thread::sleep(Duration::from_millis(30));
    stream
        .write_all(b"Content-Length: 0\r\nconnection: close\r\n\r\n")
        .expect("write fragment 2");
    stream.flush().expect("flush fragment 2");

    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(resp.contains("model reply"));

    gw_thread.join().expect("join mock gateway thread");
    assert_eq!(gw_count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn test_gateway_upstream_carries_configured_port() {
    let custom_up = GatewayUpstream::guest(5003);
    assert_eq!(custom_up.vsock_port(), Some(5003));

    let default_up = GatewayUpstream::guest_default();
    assert_eq!(default_up.vsock_port(), Some(5002));

    let cfg_json = r#"{
        "t_clock": 1700000000,
        "gateway": {
            "host": "api.anthropic.com",
            "port": 5003
        }
    }"#;
    let cfg = hermetic_netvm_core::runtime::WorldConfig::parse(cfg_json.as_bytes()).unwrap();
    let gw_cfg = cfg.gateway.unwrap();
    assert_eq!(gw_cfg.port, 5003);
    let parsed_guest_up = GatewayUpstream::guest(gw_cfg.port as u32);
    assert_eq!(parsed_guest_up.vsock_port(), Some(5003));

    let cfg_default_json = r#"{
        "t_clock": 1700000000,
        "gateway": {
            "host": "api.anthropic.com"
        }
    }"#;
    let cfg_default =
        hermetic_netvm_core::runtime::WorldConfig::parse(cfg_default_json.as_bytes()).unwrap();
    let gw_default_cfg = cfg_default.gateway.unwrap();
    assert_eq!(gw_default_cfg.port, 5002);
    let parsed_default_up = GatewayUpstream::guest(gw_default_cfg.port as u32);
    assert_eq!(parsed_default_up.vsock_port(), Some(5002));
}
