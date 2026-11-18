#![forbid(unsafe_code)]
//! Tests for NetVM TLS termination, minting, and HTTP forwarding policies across
//! the sealed ecosystem authorities: npm, crates.io, and Go modules.

use hermetic_netvm_core::{
    http::{HttpRuntimeConfig, Upstream, UpstreamError, UpstreamResponse},
    runtime::WorldFilter,
    tls::{self, FrozenTime},
    Metrics, VecLogSink,
};
use hermetic_netvm_dns::DnsTable;
use hermetic_trust::{mint_ca, Ca};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use std::{
    io::{self, Cursor, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

const EPOCH: i64 = 1_700_000_000;
const ECOSYSTEM_HOSTS: [&str; 5] = [
    "registry.npmjs.org",
    "index.crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
];

fn ca() -> &'static Ca {
    static CA: OnceLock<Ca> = OnceLock::new();
    CA.get_or_init(|| {
        mint_ca(
            "ecosystems-world",
            time::OffsetDateTime::from_unix_timestamp(EPOCH).expect("valid epoch"),
            &[42; 32],
        )
        .expect("mint ca")
    })
}

fn ecosystem_dns_table() -> DnsTable {
    let loopback = vec!["127.0.0.1".parse::<Ipv4Addr>().expect("valid ip")];
    DnsTable::test_fixture(ECOSYSTEM_HOSTS.iter().map(|&h| (h, loopback.clone())))
}

struct TrackingUpstream {
    requests: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    call_count: AtomicUsize,
}

impl TrackingUpstream {
    fn new() -> Self {
        Self {
            requests: Arc::new(std::sync::Mutex::new(Vec::new())),
            call_count: AtomicUsize::new(0),
        }
    }
}

impl Upstream for TrackingUpstream {
    fn fetch(&self, descriptor: &[u8], _: Instant) -> Result<UpstreamResponse, UpstreamError> {
        let d: serde_json::Value = serde_json::from_slice(descriptor)
            .map_err(|e| UpstreamError::BadRequest(e.to_string()))?;
        let authority = d["authority"].as_str().unwrap_or("").to_owned();
        let path = d["path"].as_str().unwrap_or("").to_owned();
        self.requests.lock().expect("lock").push((authority, path));
        self.call_count.fetch_add(1, Ordering::Relaxed);
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![
                ("Content-Length".into(), "11".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Box::new(Cursor::new(b"ok-response")),
        })
    }
}

fn client_config(trust_ca: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if trust_ca {
        roots
            .add(CertificateDer::from(ca().cert_der.clone()))
            .expect("add root");
    }
    let mut config = ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        Arc::new(FrozenTime(EPOCH as u64)),
    )
    .with_safe_default_protocol_versions()
    .expect("safe protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn send_request(
    server_cfg: Arc<rustls::ServerConfig>,
    upstream: Arc<TrackingUpstream>,
    dns_table: &DnsTable,
    host: &str,
    request_bytes: &[u8],
    trust_ca: bool,
) -> (io::Result<usize>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let filter = Arc::new(WorldFilter::new(dns_table));
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept socket");
        tls::handle_connection(
            socket,
            server_cfg,
            HttpRuntimeConfig::bounded(1, 500, 500, 2000, EPOCH),
            filter.as_ref(),
            upstream.as_ref(),
            &Metrics::new(Arc::new(VecLogSink::new())),
        );
    });

    let socket = TcpStream::connect(addr).expect("connect to netvm");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");

    let server_name = match ServerName::try_from(host.to_owned()) {
        Ok(sn) => sn,
        Err(_) => {
            let _ = worker.join();
            return (
                Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host")),
                Vec::new(),
            );
        }
    };

    let conn_res = ClientConnection::new(client_config(trust_ca), server_name);
    let conn = match conn_res {
        Ok(c) => c,
        Err(e) => {
            let _ = worker.join();
            return (
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    e.to_string(),
                )),
                Vec::new(),
            );
        }
    };

    let mut stream = StreamOwned::new(conn, socket);
    let mut out = Vec::new();
    let result = stream
        .write_all(request_bytes)
        .and_then(|_| stream.flush())
        .and_then(|_| stream.read_to_end(&mut out));
    drop(stream);
    let _ = worker.join();
    (result, out)
}

#[test]
fn test_netvm_ecosystem_authorities_tls_termination_and_forwarding() {
    let table = ecosystem_dns_table();
    let (server_cfg, resolver) =
        tls::server_config_with_resolver(ca().clone(), &table, EPOCH).expect("server config");
    let upstream = Arc::new(TrackingUpstream::new());

    let test_paths = [
        ("registry.npmjs.org", "/express"),
        ("index.crates.io", "/se/rd/serde"),
        ("static.crates.io", "/crates/serde/serde-1.0.100.crate"),
        (
            "proxy.golang.org",
            "/github.com/gin-gonic/gin/@v/v1.9.1.mod",
        ),
        ("sum.golang.org", "/lookup/github.com/gin-gonic/gin@v1.9.1"),
    ];

    for (host, path) in test_paths {
        // 1. GET request succeeds and forwards
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let (res, out) = send_request(
            server_cfg.clone(),
            upstream.clone(),
            &table,
            host,
            req.as_bytes(),
            true,
        );
        assert!(res.is_ok(), "GET to {host} failed: {res:?}");
        assert!(
            out.starts_with(b"HTTP/1.1 200 "),
            "Expected 200 OK from {host}, got: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(out.ends_with(b"ok-response"), "Expected body from {host}");

        // 2. HEAD request succeeds
        let head_req = format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let (head_res, head_out) = send_request(
            server_cfg.clone(),
            upstream.clone(),
            &table,
            host,
            head_req.as_bytes(),
            true,
        );
        assert!(head_res.is_ok(), "HEAD to {host} failed: {head_res:?}");
        assert!(
            head_out.starts_with(b"HTTP/1.1 200 "),
            "Expected 200 OK from HEAD to {host}"
        );
        assert!(
            !head_out.ends_with(b"ok-response"),
            "HEAD must not include body"
        );

        // 3. POST request returns 405 Method Not Allowed and does NOT reach upstream
        let post_req = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let calls_before = upstream.call_count.load(Ordering::Relaxed);
        let (post_res, post_out) = send_request(
            server_cfg.clone(),
            upstream.clone(),
            &table,
            host,
            post_req.as_bytes(),
            true,
        );
        assert!(
            post_res.is_ok(),
            "POST to {host} should return HTTP response: {post_res:?}"
        );
        assert!(
            post_out.starts_with(b"HTTP/1.1 405 "),
            "POST to {host} must return 405, got: {:?}",
            String::from_utf8_lossy(&post_out)
        );
        assert_eq!(
            upstream.call_count.load(Ordering::Relaxed),
            calls_before,
            "POST must never reach upstream"
        );

        // 4. PUT request returns 405 Method Not Allowed
        let put_req = format!(
            "PUT {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let calls_before = upstream.call_count.load(Ordering::Relaxed);
        let (put_res, put_out) = send_request(
            server_cfg.clone(),
            upstream.clone(),
            &table,
            host,
            put_req.as_bytes(),
            true,
        );
        assert!(
            put_res.is_ok(),
            "PUT to {host} should return HTTP response: {put_res:?}"
        );
        assert!(
            put_out.starts_with(b"HTTP/1.1 405 "),
            "PUT to {host} must return 405, got: {:?}",
            String::from_utf8_lossy(&put_out)
        );
        assert_eq!(
            upstream.call_count.load(Ordering::Relaxed),
            calls_before,
            "PUT must never reach upstream"
        );
    }

    assert_eq!(
        resolver.issuances(),
        ECOSYSTEM_HOSTS.len(),
        "Each distinct ecosystem host gets exactly one minted certificate"
    );
}

#[test]
fn test_netvm_ecosystem_rejects_unknown_host_and_untrusted_ca() {
    let table = ecosystem_dns_table();
    let server_cfg = tls::server_config(ca().clone(), &table, EPOCH).expect("server config");
    let upstream = Arc::new(TrackingUpstream::new());

    // 1. Unknown host not in DNS table fails TLS handshake
    let req = b"GET /package HTTP/1.1\r\nHost: evil-registry.example\r\nConnection: close\r\n\r\n";
    let (res, _) = send_request(
        server_cfg.clone(),
        upstream.clone(),
        &table,
        "evil-registry.example",
        req,
        true,
    );
    assert!(res.is_err(), "Unknown host must fail TLS handshake");

    // 2. Client that does not trust the World CA fails TLS verification
    let valid_req =
        b"GET /express HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n";
    let (untrusted_res, _) = send_request(
        server_cfg.clone(),
        upstream.clone(),
        &table,
        "registry.npmjs.org",
        valid_req,
        false,
    );
    assert!(
        untrusted_res.is_err(),
        "Untrusted CA must fail TLS verification"
    );

    // Upstream was never called for rejected connections
    assert_eq!(upstream.call_count.load(Ordering::Relaxed), 0);
}
