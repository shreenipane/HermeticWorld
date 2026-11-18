//! Offline TLS and boot-protocol regressions. No host trust store, DNS or clock.
use hermetic_netvm_core::{
    http::{HttpRuntimeConfig, Upstream, UpstreamError, UpstreamResponse},
    runtime::{WorldConfig, WorldFilter},
    tls::{self, BootMaterial, FrozenTime},
    Metrics, VecLogSink,
};
use hermetic_netvm_dns::DnsTable;
use hermetic_trust::{mint_ca, mint_leaf, Ca};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use std::{
    io::{self, Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
const EPOCH: i64 = 1_700_000_000;
const DNS: &[u8] = br#"{"records":[{"name":"files.example","a":["10.9.0.1"]},{"name":"other.example","a":["10.9.0.2"]}]}"#;
fn ca() -> &'static Ca {
    static CA: OnceLock<Ca> = OnceLock::new();
    CA.get_or_init(|| {
        mint_ca(
            "test-world",
            time::OffsetDateTime::from_unix_timestamp(EPOCH).unwrap(),
            &[7; 32],
        )
        .unwrap()
    })
}
fn table() -> DnsTable {
    DnsTable::from_json_str(std::str::from_utf8(DNS).unwrap()).unwrap()
}
fn material() -> (Vec<u8>, WorldConfig) {
    let m = BootMaterial::from_ca(ca(), EPOCH, DNS);
    (
        m.encode().unwrap(),
        WorldConfig {
            t_clock: EPOCH,
            tls: Some(m.identity(ca()).unwrap()),
            redirect_fallback: false,
            gateway: None,
        },
    )
}
fn boot(frame: Vec<u8>, config: &WorldConfig) -> io::Result<Ca> {
    let (recv, mut send) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = send.write_all(&frame);
        send.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let result = tls::receive_material(recv, config, Instant::now() + Duration::from_secs(2));
    writer.join().unwrap();
    result
}
#[test]
fn ca_boot_transfer_is_exact_bounded_and_bound_to_sealed_world() {
    let (frame, config) = material();
    let restored = boot(frame.clone(), &config).unwrap();
    assert_eq!(restored.cert_der, ca().cert_der);
    assert_eq!(restored.key_pem, ca().key_pem);
    for len in [0, 1, 3, 4, frame.len() - 1] {
        assert!(boot(frame[..len].to_vec(), &config).is_err());
    }
    for mut bad in [
        vec![0; 4],
        (tls::MAX_BOOT_BYTES as u32 + 1).to_le_bytes().to_vec(),
        frame.clone(),
    ] {
        bad.extend_from_slice(b"extra frame");
        assert!(boot(bad, &config).is_err());
    }
    for field in ["world", "clock", "dns", "ca", "material"] {
        let mut bad = WorldConfig::parse(serde_json::to_vec(&config).unwrap().as_slice()).unwrap();
        let identity = bad.tls.as_mut().unwrap();
        match field {
            "world" => identity.world_id = "another-world".into(),
            "clock" => bad.t_clock += 1,
            "dns" => identity.dns_sha256 = "0".repeat(64),
            "ca" => identity.ca_sha256 = "0".repeat(64),
            "material" => identity.material_sha256 = "0".repeat(64),
            _ => unreachable!(),
        }
        assert!(boot(frame.clone(), &bad).is_err(), "{field}");
    }
    // The public identity never contains the key or per-world issuance seed.
    let public = serde_json::to_string(&config).unwrap();
    assert!(!public.contains("PRIVATE KEY") && !public.contains("ca_seed"));
    let mut corrupt = frame.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(boot(corrupt, &config).is_err());
}
#[test]
fn ca_boot_silent_peer_and_missing_eof_share_one_deadline() {
    let (frame, config) = material();
    for sent in [&[][..], frame.as_slice()] {
        let (recv, mut send) = UnixStream::pair().unwrap();
        send.write_all(sent).unwrap();
        let start = Instant::now();
        assert!(tls::receive_material(recv, &config, start + Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}

struct FrozenUpstream(AtomicUsize);
impl Upstream for FrozenUpstream {
    fn fetch(&self, descriptor: &[u8], _: Instant) -> Result<UpstreamResponse, UpstreamError> {
        let d: serde_json::Value = serde_json::from_slice(descriptor).unwrap();
        assert_eq!(d["authority"], "files.example");
        assert_eq!(d["path"], "/hello.txt");
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![
                ("Content-Length".into(), "7".into()),
                ("Date".into(), "HOST-CLOCK".into()),
                ("Server".into(), "HOST-NAME".into()),
            ],
            body: Box::new(Cursor::new(b"frozen\n")),
        })
    }
}
fn client_config(trust: bool, sni: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if trust {
        roots
            .add(CertificateDer::from(ca().cert_der.clone()))
            .unwrap();
    }
    let mut config = ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        Arc::new(FrozenTime(EPOCH as u64)),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.enable_sni = sni;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
fn fixture_table() -> DnsTable {
    DnsTable::test_fixture([
        (
            "files.example",
            vec!["127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()],
        ),
        (
            "other.example",
            vec!["127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()],
        ),
    ])
}
fn ask(
    server: Arc<rustls::ServerConfig>,
    upstream: Arc<FrozenUpstream>,
    name: &str,
    head: &[u8],
    trust: bool,
    sni: bool,
) -> (io::Result<usize>, Vec<u8>) {
    ask_with_client(server, upstream, name, head, client_config(trust, sni))
}
fn ask_with_client(
    server: Arc<rustls::ServerConfig>,
    upstream: Arc<FrozenUpstream>,
    name: &str,
    head: &[u8],
    client: Arc<ClientConfig>,
) -> (io::Result<usize>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let filter = Arc::new(WorldFilter::new(&fixture_table()));
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        tls::handle_connection(
            socket,
            server,
            HttpRuntimeConfig::bounded(1, 500, 500, 2000, EPOCH),
            filter.as_ref(),
            upstream.as_ref(),
            &Metrics::new(Arc::new(VecLogSink::new())),
        );
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let conn =
        ClientConnection::new(client, ServerName::try_from(name.to_owned()).unwrap()).unwrap();
    let mut stream = StreamOwned::new(conn, socket);
    let mut out = Vec::new();
    let result = stream
        .write_all(head)
        .and_then(|_| stream.flush())
        .and_then(|_| stream.read_to_end(&mut out));
    drop(stream);
    worker.join().unwrap();
    (result, out)
}
#[test]
fn verified_https_get_head_and_policy_rejections_never_reach_unsealed_upstream() {
    let server = tls::server_config(ca().clone(), &table(), EPOCH).unwrap();
    let upstream = Arc::new(FrozenUpstream(AtomicUsize::new(0)));
    let get = b"GET /hello.txt HTTP/1.1\r\nHost: files.example:443\r\n\r\n";
    let (result, out) = ask(
        server.clone(),
        upstream.clone(),
        "files.example",
        get,
        true,
        true,
    );
    assert!(result.is_ok(), "{result:?} {out:?}");
    assert!(
        out.starts_with(b"HTTP/1.1 200 ") && out.ends_with(b"frozen\n"),
        "{out:?}"
    );
    assert!(!out.windows(4).any(|s| s == b"HOST"));
    let (result, out) = ask(
        server.clone(),
        upstream.clone(),
        "files.example",
        b"HEAD /hello.txt HTTP/1.1\r\nHost: files.example\r\n\r\n",
        true,
        true,
    );
    assert!(result.is_ok(), "{result:?}");
    assert!(out.ends_with(b"\r\n\r\n") && out.starts_with(b"HTTP/1.1 200 "));
    let (result, out) = ask(
        server.clone(),
        upstream.clone(),
        "files.example",
        b"POST /hello.txt HTTP/1.1\r\nHost: files.example\r\nContent-Length: 0\r\n\r\n",
        true,
        true,
    );
    assert!(result.is_ok());
    assert!(out.starts_with(b"HTTP/1.1 405 "));
    assert_eq!(upstream.0.load(Ordering::Relaxed), 2);
    for (name, head, trust, sni) in [
        ("unknown.example", &get[..], true, true),
        ("files.example", get, false, true),
        ("files.example", get, true, false),
        (
            "files.example",
            b"GET /hello.txt HTTP/1.1\r\nHost: other.example\r\n\r\n",
            true,
            true,
        ),
        (
            "files.example",
            b"POST /hello.txt HTTP/1.1\r\nHost: other.example\r\n\r\n",
            true,
            true,
        ),
        (
            "files.example",
            b"GET /hello.txt HTTP/1.1\r\nHost: files.example:80\r\n\r\n",
            true,
            true,
        ),
        (
            "files.example",
            b"GET /hello.txt HTTP/1.1\r\n\r\n",
            true,
            true,
        ),
    ] {
        let (_, out) = ask(server.clone(), upstream.clone(), name, head, trust, sni);
        assert!(out.is_empty(), "rejected request got response: {out:?}");
        assert_eq!(upstream.0.load(Ordering::Relaxed), 2);
    }
}
#[test]
fn leaves_restore_deterministically_with_sealed_validity() {
    let clock = time::OffsetDateTime::from_unix_timestamp(EPOCH).unwrap();
    let original = mint_leaf(ca(), &["files.example"], clock).unwrap();
    let (frame, config) = material();
    let restored = boot(frame, &config).unwrap();
    let again = mint_leaf(&restored, &["files.example"], clock).unwrap();
    assert_eq!(original.cert_der, again.cert_der);
    assert_eq!(original.key_der, again.key_der);
    let (start, end) = hermetic_trust::compute_leaf_validity(clock).unwrap();
    assert_eq!(start.unix_timestamp(), EPOCH - 7 * 86400);
    assert_eq!(end.unix_timestamp(), EPOCH + 365 * 86400);
    // Full DER known answer is also stable across boot transfer.
    assert_eq!(
        tls::digest(&original.cert_der),
        "2bb5e9d0d02abefff6b3154a9cbea4d46a1b4618d718ec557869f74acb5d8d21"
    );
}

#[test]
fn malformed_ca_material_fails_with_redacted_errors_even_with_matching_frame_digest() {
    let (_, config) = material();
    let m = BootMaterial::from_ca(ca(), EPOCH, DNS);
    let valid: serde_json::Value = serde_json::from_slice(&m.encode().unwrap()[4..]).unwrap();
    for document in [
        serde_json::json!({"world_id":"test-world", "ca_key_pem":"SECRET-MARKER"}),
        {
            let mut d = valid.clone();
            d["ca_key_pem"] = "SECRET-MARKER".into();
            d
        },
        {
            let mut d = valid.clone();
            d["ca_seed"] = serde_json::json!([1, 2, 3]);
            d
        },
        {
            let mut d = valid.clone();
            d["extra"] = true.into();
            d
        },
    ] {
        let body = serde_json::to_vec(&document).unwrap();
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend(body);
        let mut expected =
            WorldConfig::parse(serde_json::to_vec(&config).unwrap().as_slice()).unwrap();
        expected.tls.as_mut().unwrap().material_sha256 = tls::digest(&frame);
        let err = boot(frame, &expected).err().expect("invalid key accepted");
        assert!(!err.to_string().contains("SECRET-MARKER"));
    }
}

#[test]
fn tls_host_mismatch_resets_the_connection() {
    let server = tls::server_config(ca().clone(), &table(), EPOCH).unwrap();
    let upstream = Arc::new(FrozenUpstream(AtomicUsize::new(0)));
    let (result, out) = ask(
        server,
        upstream.clone(),
        "files.example",
        b"GET /hello.txt HTTP/1.1\r\nHost: other.example\r\n\r\n",
        true,
        true,
    );
    assert!(out.is_empty());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(upstream.0.load(Ordering::Relaxed), 0);
}

#[test]
fn verified_https_also_supports_tls12() {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca().cert_der.clone()))
        .unwrap();
    let config = ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        Arc::new(FrozenTime(EPOCH as u64)),
    )
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server = tls::server_config(ca().clone(), &table(), EPOCH).unwrap();
    let upstream = Arc::new(FrozenUpstream(AtomicUsize::new(0)));
    let (result, out) = ask_with_client(
        server,
        upstream.clone(),
        "files.example",
        b"GET /hello.txt HTTP/1.1\r\nHost: files.example\r\n\r\n",
        Arc::new(config),
    );
    assert!(result.is_ok(), "{result:?}");
    assert!(out.starts_with(b"HTTP/1.1 200 ") && out.ends_with(b"frozen\n"));
    assert_eq!(upstream.0.load(Ordering::Relaxed), 1);
}

#[test]
fn tls_client_hello_for_world_host_dialled_to_mismatched_address_is_reset_before_certificate_minted_or_sent(
) {
    // table() defines: files.example -> 10.9.0.1, other.example -> 10.9.0.2.
    // The test server listens on 127.0.0.1:0.
    // When the client connects to 127.0.0.1 and sends a ClientHello with SNI=files.example,
    // the dialled address (127.0.0.1) does NOT match the world host's table address (10.9.0.1).
    // The server must reset the connection immediately, before any leaf certificate is minted
    // and before any TLS response (ServerHello / Certificate) is sent.
    let (server, resolver) =
        tls::server_config_with_resolver(ca().clone(), &table(), EPOCH).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let filter = Arc::new(WorldFilter::new(&table()));
    let upstream = Arc::new(FrozenUpstream(AtomicUsize::new(0)));
    let upstream_clone = upstream.clone();
    let metrics = Arc::new(Metrics::new(Arc::new(VecLogSink::new())));
    let metrics_clone = metrics.clone();

    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        tls::handle_connection(
            socket,
            server,
            HttpRuntimeConfig::bounded(1, 500, 500, 2000, EPOCH),
            filter.as_ref(),
            upstream_clone.as_ref(),
            &metrics_clone,
        );
    });

    let mut client_socket = TcpStream::connect(address).unwrap();
    client_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client_socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Generate real TLS ClientHello with SNI "files.example"
    let client_cfg = client_config(true, true);
    let mut conn = ClientConnection::new(
        client_cfg,
        ServerName::try_from("files.example".to_string()).unwrap(),
    )
    .unwrap();
    let mut hello_wire = Vec::new();
    conn.write_tls(&mut hello_wire).unwrap();
    assert!(
        !hello_wire.is_empty(),
        "client hello wire must not be empty"
    );

    // Send ClientHello to the server
    client_socket.write_all(&hello_wire).unwrap();
    client_socket.flush().unwrap();

    // Read from the socket: verify connection is reset and ZERO bytes were sent by server
    let mut response_buf = [0u8; 1024];
    let read_result = client_socket.read(&mut response_buf);
    match read_result {
        Ok(0) => {} // Immediate EOF from TCP reset
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
        other => panic!("expected EOF or ConnectionReset, got {other:?}"),
    }

    worker.join().unwrap();

    // Verify:
    // 1. Zero leaf certificates were minted
    assert_eq!(
        resolver.issuances(),
        0,
        "a certificate was minted despite mismatched destination address!"
    );
    // 2. HTTP rejection metric incremented
    assert_eq!(metrics.snapshot().http_rejected, 1);
    // 3. Upstream was never contacted
    assert_eq!(upstream.0.load(Ordering::Relaxed), 0);
}
