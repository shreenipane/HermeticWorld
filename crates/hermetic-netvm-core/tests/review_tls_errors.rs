//! Complete HTTPS error responses must include an authenticated TLS close.
use hermetic_netvm_core::{
    http::{HttpRuntimeConfig, Upstream, UpstreamError, UpstreamResponse},
    runtime::WorldFilter,
    tls::{self, FrozenTime},
    Metrics, VecLogSink,
};
use hermetic_netvm_dns::DnsTable;
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use std::{
    io::{Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

const EPOCH: i64 = 1_700_000_000;

struct FailingUpstream(u16);
impl Upstream for FailingUpstream {
    fn fetch(&self, _: &[u8], _: Instant) -> Result<UpstreamResponse, UpstreamError> {
        match self.0 {
            504 => Err(UpstreamError::Timeout),
            502 => Err(UpstreamError::Backend("private backend detail".into())),
            _ => Ok(UpstreamResponse {
                status: 600,
                headers: vec![],
                body: Box::new(Cursor::new(Vec::<u8>::new())),
            }),
        }
    }
}

#[test]
fn upstream_errors_and_invalid_status_finish_https_without_truncation() {
    let ca = hermetic_trust::mint_ca(
        "tls-error-test",
        time::OffsetDateTime::from_unix_timestamp(EPOCH).unwrap(),
        &[7; 32],
    )
    .unwrap();
    let table =
        DnsTable::from_json_str(r#"{"records":[{"name":"files.example","a":["10.9.0.1"]}]}"#)
            .unwrap();
    let server = tls::server_config(ca.clone(), &table, EPOCH).unwrap();
    let filter = Arc::new(WorldFilter::new(&table));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let client = Arc::new(
        ClientConfig::builder_with_details(
            Arc::new(rustls::crypto::ring::default_provider()),
            Arc::new(FrozenTime(EPOCH as u64)),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    for failure in [504, 502, 600] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server = server.clone();
        let filter = filter.clone();
        let worker = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            tls::handle_connection(
                socket,
                server,
                HttpRuntimeConfig::bounded(1, 500, 500, 2000, EPOCH),
                filter.as_ref(),
                &FailingUpstream(failure),
                &Metrics::new(Arc::new(VecLogSink::new())),
            );
        });
        let connection = ClientConnection::new(
            client.clone(),
            ServerName::try_from("files.example").unwrap(),
        )
        .unwrap();
        let mut stream = StreamOwned::new(connection, socket);
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: files.example\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        let result = stream.read_to_end(&mut response);
        drop(stream);
        worker.join().unwrap();
        let expected = if failure == 504 { 504 } else { 502 };
        assert!(response.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()));
        assert!(response.ends_with(b"Content-Length: 0\r\nConnection: close\r\n\r\n"));
        assert!(result.is_ok(), "failure {failure}: {result:?}");
    }
}
