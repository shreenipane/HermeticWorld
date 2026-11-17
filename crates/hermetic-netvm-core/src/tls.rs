#![forbid(unsafe_code)]
//! Per-world TLS: sealed identity, one bounded boot transfer, memory-only keys.
use crate::{http, runtime::WorldConfig, sys, Metrics};
use hermetic_netvm_dns::DnsTable;
use hermetic_trust::{mint_leaf, restore_ca, Ca};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig, ServerConnection, StreamOwned,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub const BOOT_PORT: u32 = 5003;
pub const MAX_BOOT_BYTES: usize = 64 * 1024;
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_WORLD_ID_BYTES: usize = 256;
pub const MAX_CA_KEY_BYTES: usize = 4096;
pub const MAX_TLS_CACHE_ENTRIES: usize = 64;
pub const MAX_TLS_ISSUANCES: usize = 4096;
/// The TLS loop handles one connection at a time; no handshake worker queue.
pub const MAX_TLS_CONNECTIONS: usize = 1;
pub const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
pub const MAX_TLS_RECORD_BYTES: usize = 18 * 1024;
pub const MAX_TLS_INPUT_BYTES: usize = 128 * 1024;
pub const MAX_TLS_BUFFER_BYTES: usize = 16 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsIdentity {
    pub world_id: String,
    pub dns_sha256: String,
    pub ca_sha256: String,
    pub material_sha256: String,
}
impl TlsIdentity {
    pub fn validate(&self) -> io::Result<()> {
        if self.world_id.is_empty()
            || self.world_id.len() > MAX_WORLD_ID_BYTES
            || !self
                .world_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || [&self.dns_sha256, &self.ca_sha256, &self.material_sha256]
                .iter()
                .any(|s| {
                    s.len() != 64
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
        {
            return Err(invalid());
        }
        Ok(())
    }
}

// Deliberately no Debug: neither keys nor their derivation seed may enter logs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootMaterial {
    pub world_id: String,
    pub t_clock: i64,
    pub dns_sha256: String,
    pub ca_seed: [u8; 32],
    pub ca_key_pem: String,
}
impl BootMaterial {
    pub fn from_ca(ca: &Ca, t_clock: i64, dns: &[u8]) -> Self {
        Self {
            world_id: ca.world_id.clone(),
            t_clock,
            dns_sha256: digest(dns),
            ca_seed: ca.seed,
            ca_key_pem: ca.key_pem.clone(),
        }
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.world_id.is_empty()
            || self.world_id.len() > MAX_WORLD_ID_BYTES
            || self.ca_key_pem.len() > MAX_CA_KEY_BYTES
            || self.dns_sha256.len() != 64
        {
            return Err(invalid());
        }
        let body = serde_json::to_vec(self).map_err(|_| invalid())?;
        if body.is_empty() || body.len() > MAX_BOOT_BYTES {
            return Err(invalid());
        }
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend(body);
        Ok(frame)
    }
    pub fn identity(&self, ca: &Ca) -> io::Result<TlsIdentity> {
        let frame = self.encode()?;
        let identity = TlsIdentity {
            world_id: self.world_id.clone(),
            dns_sha256: self.dns_sha256.clone(),
            ca_sha256: digest(&ca.cert_der),
            material_sha256: digest(&frame),
        };
        identity.validate()?;
        Ok(identity)
    }
}

/// Receive exactly one frame and EOF from a private Firecracker host endpoint.
/// Every read shares the boot deadline; no network interface is up at this point.
pub fn receive_material(
    mut stream: UnixStream,
    config: &WorldConfig,
    deadline: Instant,
) -> io::Result<Ca> {
    let expected = config.tls.as_ref().ok_or_else(invalid)?;
    expected.validate()?;
    stream.set_nonblocking(true)?;
    fn exact(stream: &mut UnixStream, mut bytes: &mut [u8], end: Instant) -> io::Result<()> {
        while !bytes.is_empty() {
            sys::ready(stream, false, end)?;
            match stream.read(bytes) {
                Ok(0) => return Err(invalid()),
                Ok(n) => bytes = bytes.get_mut(n..).ok_or_else(invalid)?,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => return Err(invalid()),
            }
        }
        Ok(())
    }
    let mut length = [0; 4];
    exact(&mut stream, &mut length, deadline)?;
    let count = u32::from_le_bytes(length) as usize;
    if count == 0 || count > MAX_BOOT_BYTES {
        return Err(invalid());
    }
    let mut frame = length.to_vec();
    let mut body = vec![0; count];
    exact(&mut stream, &mut body, deadline)?;
    frame.extend_from_slice(&body);
    // Require the sender to close its write side. A second frame or trailing
    // bytes is never silently accepted, including when sent after a delay.
    loop {
        sys::ready(&stream, false, deadline)?;
        match stream.read(&mut [0]) {
            Ok(0) => break,
            Ok(_) => return Err(invalid()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err(invalid()),
        }
    }
    if digest(&frame) != expected.material_sha256 {
        return Err(invalid());
    }
    let material: BootMaterial = serde_json::from_slice(&body).map_err(|_| invalid())?;
    if material.world_id != expected.world_id
        || material.t_clock != config.t_clock
        || material.dns_sha256 != expected.dns_sha256
        || material.ca_key_pem.len() > MAX_CA_KEY_BYTES
    {
        return Err(invalid());
    }
    let clock = time::OffsetDateTime::from_unix_timestamp(config.t_clock).map_err(|_| invalid())?;
    let ca = restore_ca(
        &material.world_id,
        clock,
        material.ca_seed,
        &material.ca_key_pem,
    )
    .map_err(|_| invalid())?;
    if digest(&ca.cert_der) != expected.ca_sha256 {
        return Err(invalid());
    }
    Ok(ca)
}
pub fn receive_guest(config: &WorldConfig) -> io::Result<Ca> {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    receive_material(sys::vsock(BOOT_PORT, deadline)?, config, deadline)
}

#[derive(Debug)]
pub struct FrozenTime(pub u64);
impl rustls::time_provider::TimeProvider for FrozenTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

struct Certificates {
    ca: Ca,
    clock: time::OffsetDateTime,
    hosts: BTreeSet<String>,
    cache: BTreeMap<String, Arc<CertifiedKey>>,
    issuances: usize,
}
pub struct Resolver(Mutex<Certificates>);
impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorldCertificates")
    }
}
impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        if hello
            .alpn()
            .is_some_and(|mut protocols| !protocols.any(|p| p == b"http/1.1"))
        {
            return None;
        }
        self.certificate(name)
    }
}
impl Resolver {
    pub fn issuances(&self) -> usize {
        self.0.lock().map(|s| s.issuances).unwrap_or(0)
    }

    fn certificate(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let mut state = self.0.lock().ok()?;
        if !state.hosts.contains(name) {
            return None;
        }
        if let Some(key) = state.cache.get(name) {
            return Some(key.clone());
        }
        if state.issuances >= MAX_TLS_ISSUANCES {
            return None;
        }
        state.issuances += 1;
        let mut leaf = mint_leaf(&state.ca, &[name], state.clock).ok()?;
        // Take the buffers (no copy of the key); the leaf's PEM is wiped on drop.
        let key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(std::mem::take(&mut leaf.key_der)),
        ))
        .ok()?;
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(std::mem::take(&mut leaf.cert_der))],
            key,
        ));
        if state.cache.len() >= MAX_TLS_CACHE_ENTRIES {
            // Deterministic eviction, independent of host time or environment.
            state.cache.pop_first();
        }
        state.cache.insert(name.to_owned(), certified.clone());
        Some(certified)
    }
}
pub fn server_config_with_resolver(
    ca: Ca,
    table: &DnsTable,
    epoch: i64,
) -> io::Result<(Arc<ServerConfig>, Arc<Resolver>)> {
    let clock = time::OffsetDateTime::from_unix_timestamp(epoch).map_err(|_| invalid())?;
    let epoch = u64::try_from(epoch).map_err(|_| invalid())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let resolver = Arc::new(Resolver(Mutex::new(Certificates {
        ca,
        clock,
        hosts: table.names().map(str::to_owned).collect(),
        cache: BTreeMap::new(),
        issuances: 0,
    })));
    let mut config = ServerConfig::builder_with_details(provider, Arc::new(FrozenTime(epoch)))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_fragment_size = Some(MAX_TLS_BUFFER_BYTES);
    Ok((Arc::new(config), resolver))
}

pub fn server_config(ca: Ca, table: &DnsTable, epoch: i64) -> io::Result<Arc<ServerConfig>> {
    server_config_with_resolver(ca, table, epoch).map(|(cfg, _)| cfg)
}

/// Each syscall uses the remaining absolute budget, including rustls internal
/// read/write loops. Slow records cannot renew the handshake or HTTP deadline.
pub struct DeadlineTcp {
    socket: TcpStream,
    deadline: Instant,
    remaining_input: usize,
}
impl DeadlineTcp {
    pub fn new(socket: TcpStream, deadline: Instant) -> Self {
        Self {
            socket,
            deadline,
            remaining_input: MAX_TLS_INPUT_BYTES,
        }
    }
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
    fn budget(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(io::ErrorKind::TimedOut.into())
    }
    pub fn reset(&self) {
        let _ = sys::reset_tcp(&self.socket);
    }
    pub fn shutdown(&self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }
}
impl Read for DeadlineTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining_input == 0 {
            return Err(invalid());
        }
        self.socket.set_read_timeout(Some(self.budget()?))?;
        let take = buf.len().min(self.remaining_input);
        let n = self.socket.read(buf.get_mut(..take).ok_or_else(invalid)?)?;
        self.remaining_input = self.remaining_input.checked_sub(n).ok_or_else(invalid)?;
        Ok(n)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.budget()?))?;
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// A minimal framing gate rejects ECH before rustls can ignore an unknown
// extension. rustls still validates the complete ClientHello and handshake.
fn take<'a>(bytes: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    let out = bytes.get(..count).ok_or_else(invalid)?;
    *bytes = bytes.get(count..).ok_or_else(invalid)?;
    Ok(out)
}
fn number(bytes: &mut &[u8], count: usize) -> io::Result<usize> {
    take(bytes, count)?.iter().try_fold(0usize, |n, b| {
        n.checked_mul(256)
            .and_then(|n| n.checked_add(usize::from(*b)))
            .ok_or_else(invalid)
    })
}
fn vector<'a>(bytes: &mut &'a [u8], width: usize) -> io::Result<&'a [u8]> {
    let n = number(bytes, width)?;
    take(bytes, n)
}
fn parse_client_hello_extensions(mut hello: &[u8]) -> io::Result<Option<String>> {
    take(&mut hello, 34)?; // legacy version and random
    vector(&mut hello, 1)?; // session id
    vector(&mut hello, 2)?; // cipher suites
    vector(&mut hello, 1)?; // compression methods
    let mut extensions = vector(&mut hello, 2)?;
    if !hello.is_empty() {
        return Err(invalid());
    }
    let mut sni = None;
    while !extensions.is_empty() {
        let kind = number(&mut extensions, 2)?;
        let mut ext_data = vector(&mut extensions, 2)?;
        if kind == 0xfe0d {
            return Err(invalid());
        }
        if kind == 0 {
            // RFC 6066: server_name extension
            let mut list = vector(&mut ext_data, 2)?;
            if !ext_data.is_empty() {
                return Err(invalid());
            }
            while !list.is_empty() {
                let name_type = number(&mut list, 1)?;
                let host_bytes = vector(&mut list, 2)?;
                if name_type == 0 && sni.is_none() {
                    let s = std::str::from_utf8(host_bytes).map_err(|_| invalid())?;
                    if s.is_empty() || s.len() > 255 {
                        return Err(invalid());
                    }
                    sni = Some(s.to_ascii_lowercase());
                }
            }
        }
    }
    Ok(sni)
}

fn check_extensions(hello: &[u8]) -> io::Result<()> {
    parse_client_hello_extensions(hello).map(|_| ())
}

fn client_hello(socket: &mut DeadlineTcp) -> io::Result<(Vec<u8>, Option<String>)> {
    let mut wire = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0; 5];
        socket.read_exact(&mut header)?;
        let mut fields = header.as_slice();
        if number(&mut fields, 1)? != 22 {
            return Err(invalid());
        }
        let _ = number(&mut fields, 2)?;
        let len = number(&mut fields, 2)?;
        if len == 0
            || len > MAX_TLS_RECORD_BYTES
            || wire.len().saturating_add(5 + len) > MAX_TLS_INPUT_BYTES
        {
            return Err(invalid());
        }
        let mut record = vec![0; len];
        socket.read_exact(&mut record)?;
        wire.extend(header);
        wire.extend_from_slice(&record);
        handshake.extend(record);
        if handshake.len() > MAX_CLIENT_HELLO_BYTES {
            return Err(invalid());
        }
        if handshake.len() < 4 {
            continue;
        }
        let mut fields = handshake.as_slice();
        if number(&mut fields, 1)? != 1 {
            return Err(invalid());
        }
        let len = number(&mut fields, 3)?;
        if len > MAX_CLIENT_HELLO_BYTES.saturating_sub(4) {
            return Err(invalid());
        }
        if fields.len() < len {
            continue;
        }
        let sni = parse_client_hello_extensions(take(&mut fields, len)?)?;
        if !fields.is_empty() {
            return Err(invalid());
        }
        return Ok((wire, sni));
    }
}

// Inspect every plaintext handshake message, including a second ClientHello
// after HelloRetryRequest. Unsupported extensions must not become an ECH bypass.
fn inspect_handshakes(pending: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    if pending.len().saturating_add(bytes.len()) > MAX_CLIENT_HELLO_BYTES {
        return Err(invalid());
    }
    pending.extend_from_slice(bytes);
    loop {
        if pending.len() < 4 {
            return Ok(());
        }
        let mut fields = pending.as_slice();
        let kind = number(&mut fields, 1)?;
        let len = number(&mut fields, 3)?;
        if len > MAX_CLIENT_HELLO_BYTES.saturating_sub(4) {
            return Err(invalid());
        }
        if fields.len() < len {
            return Ok(());
        }
        let message = take(&mut fields, len)?;
        if kind == 1 {
            check_extensions(message)?;
        }
        let consumed = pending
            .len()
            .checked_sub(fields.len())
            .ok_or_else(invalid)?;
        pending.drain(..consumed);
    }
}
fn handshake_io(conn: &mut ServerConnection, socket: &mut DeadlineTcp) -> io::Result<()> {
    let mut pending = Vec::new();
    let mut encrypted_tls12 = false;
    loop {
        while conn.wants_write() {
            if conn.write_tls(socket)? == 0 {
                return Err(invalid());
            }
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        let mut header = [0; 5];
        socket.read_exact(&mut header)?;
        let mut fields = header.as_slice();
        let kind = number(&mut fields, 1)?;
        number(&mut fields, 2)?;
        let len = number(&mut fields, 2)?;
        if len == 0 || len > MAX_TLS_RECORD_BYTES {
            return Err(invalid());
        }
        let mut body = vec![0; len];
        socket.read_exact(&mut body)?;
        if kind == 20 && conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_2) {
            encrypted_tls12 = true;
        }
        if kind == 22 && !encrypted_tls12 {
            inspect_handshakes(&mut pending, &body)?;
        }
        let mut record = header.to_vec();
        record.extend(body);
        let mut input = io::Cursor::new(record);
        while input.position() < input.get_ref().len() as u64 {
            if conn.read_tls(&mut input)? == 0 {
                return Err(invalid());
            }
            conn.process_new_packets().map_err(|_| invalid())?;
        }
    }
}

pub fn handle_connection(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    http_config: http::HttpRuntimeConfig,
    filter: &dyn http::RequestFilter,
    upstream: &dyn http::Upstream,
    metrics: &Metrics,
) {
    let mut socket = DeadlineTcp::new(socket, Instant::now() + HANDSHAKE_TIMEOUT);
    let result = (|| -> io::Result<(ServerConnection, String)> {
        let (hello, sni) = client_hello(&mut socket)?;
        let name = sni.ok_or_else(invalid)?;
        let dialled = socket.local_addr().ok().map(|sa| sa.ip());
        // Verify destination before creating ServerConnection or invoking handshake_io:
        // ClientHello whose SNI does not match dialled IP must be reset before minting
        // or sending any certificate.
        if !filter.check_destination(&name, dialled) {
            return Err(invalid());
        }
        let mut conn = ServerConnection::new(config).map_err(|_| invalid())?;
        conn.set_buffer_limit(Some(MAX_TLS_BUFFER_BYTES));
        let mut input = io::Cursor::new(hello);
        while input.position() < input.get_ref().len() as u64 {
            if conn.read_tls(&mut input)? == 0 {
                return Err(invalid());
            }
            conn.process_new_packets().map_err(|_| invalid())?;
        }
        handshake_io(&mut conn, &mut socket)?;
        let server_name = conn.server_name().ok_or_else(invalid)?;
        if !server_name.eq_ignore_ascii_case(&name) {
            return Err(invalid());
        }
        if !filter.check_destination(server_name, dialled) {
            return Err(invalid());
        }
        Ok((conn, name))
    })();
    match result {
        Ok((conn, name)) => http::handle_stream(
            http::HttpStream::Tls(Box::new(StreamOwned::new(conn, socket))),
            true,
            Some(&name),
            http_config,
            filter,
            upstream,
            metrics,
        ),
        Err(_) => {
            metrics.inc_http_rejected();
            socket.reset();
        }
    }
}

pub fn run_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    http_config: http::HttpRuntimeConfig,
    filter: Arc<dyn http::RequestFilter>,
    upstream: Arc<dyn http::Upstream>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
) {
    if listener.set_nonblocking(true).is_err() {
        shutdown.store(true, Ordering::Release);
        return;
    }
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((socket, _)) => {
                if socket.set_nonblocking(false).is_err() {
                    continue;
                }
                handle_connection(
                    socket,
                    config.clone(),
                    http_config,
                    filter.as_ref(),
                    upstream.as_ref(),
                    &metrics,
                );
            }
            Err(_) => std::thread::sleep(http::HTTP_ACCEPT_POLL_TIMEOUT),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (DeadlineTcp, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (receiver, _) = listener.accept().unwrap();
        (
            DeadlineTcp::new(receiver, Instant::now() + Duration::from_millis(200)),
            sender,
        )
    }
    fn hello(ech: bool) -> Vec<u8> {
        let mut body = vec![0; 34];
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        if ech {
            body.extend([0, 4, 0xfe, 0x0d, 0, 0]);
        } else {
            body.extend([0, 0]);
        }
        body
    }
    fn handshake(body: &[u8]) -> Vec<u8> {
        let mut h = vec![1];
        h.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        h.extend_from_slice(body);
        h
    }
    fn record(bytes: &[u8]) -> Vec<u8> {
        let mut r = vec![22, 3, 3];
        r.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        r.extend_from_slice(bytes);
        r
    }
    #[test]
    fn fragmented_client_hello_rejects_ech_plaintext_and_hostile_lengths() {
        for ech in [false, true] {
            let h = handshake(&hello(ech));
            let wire: Vec<_> = h.chunks(3).flat_map(record).collect();
            let (mut receiver, mut sender) = pair();
            sender.write_all(&wire).unwrap();
            let result = client_hello(&mut receiver);
            assert_eq!(result.is_err(), ech);
            if !ech {
                let (got_wire, sni) = result.unwrap();
                assert_eq!(got_wire, wire);
                assert_eq!(sni, None);
            }
        }
        for bytes in [
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            vec![22, 3, 3, 255, 255],
            record(&[1, 255, 255, 255]),
            record(&[2, 0, 0, 0]),
        ] {
            let (mut receiver, mut sender) = pair();
            sender.write_all(&bytes).unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
            assert!(client_hello(&mut receiver).is_err());
        }
        let valid = hello(false);
        for cut in 0..valid.len() {
            assert!(check_extensions(&valid[..cut]).is_err());
        }
        assert!(check_extensions(&valid).is_ok());
    }
    #[test]
    fn retry_client_hello_cannot_add_ech_even_when_fragmented() {
        let mut pending = Vec::new();
        let first = handshake(&hello(false));
        inspect_handshakes(&mut pending, &first).unwrap();
        assert!(pending.is_empty());
        let retry = handshake(&hello(true));
        let mut rejected = false;
        for fragment in retry.chunks(3) {
            if inspect_handshakes(&mut pending, fragment).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
    }
    #[test]
    fn tls_reads_obey_a_total_byte_cap_and_absolute_deadline() {
        let (mut receiver, mut sender) = pair();
        let writer = std::thread::spawn(move || {
            let _ = sender.write_all(&vec![0; MAX_TLS_INPUT_BYTES + 1]);
        });
        let mut out = Vec::new();
        assert!(receiver.read_to_end(&mut out).is_err());
        assert_eq!(out.len(), MAX_TLS_INPUT_BYTES);
        writer.join().unwrap();
        let (mut receiver, mut sender) = pair();
        receiver.set_deadline(Instant::now() + Duration::from_millis(40));
        let writer = std::thread::spawn(move || {
            for _ in 0..10 {
                if sender.write_all(&[22]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        let start = Instant::now();
        assert!(client_hello(&mut receiver).is_err());
        assert!(start.elapsed() < Duration::from_millis(150));
        drop(receiver);
        writer.join().unwrap();
    }
}

#[cfg(test)]
mod certificate_limits {
    use super::*;
    #[test]
    fn certificate_cache_and_issuance_budget_are_enforced_without_host_clock() {
        let clock = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ca = hermetic_trust::mint_ca("cache-test", clock, &[7; 32]).unwrap();
        let resolver = Resolver(Mutex::new(Certificates {
            ca,
            clock,
            hosts: ["a.example".into(), "b.example".into()]
                .into_iter()
                .collect(),
            cache: BTreeMap::new(),
            issuances: 0,
        }));
        assert!(resolver.certificate("unknown.example").is_none());
        let key = resolver.certificate("a.example").unwrap();
        assert!(Arc::ptr_eq(
            &key,
            &resolver.certificate("a.example").unwrap()
        ));
        {
            let mut state = resolver.0.lock().unwrap();
            assert_eq!(state.issuances, 1);
            for n in 1..MAX_TLS_CACHE_ENTRIES {
                state.cache.insert(format!("z{n:03}.example"), key.clone());
            }
        }
        assert!(resolver.certificate("b.example").is_some());
        {
            let mut state = resolver.0.lock().unwrap();
            assert_eq!(state.cache.len(), MAX_TLS_CACHE_ENTRIES);
            assert!(!state.cache.contains_key("a.example"));
            assert_eq!(state.issuances, 2);
            state.issuances = MAX_TLS_ISSUANCES;
        }
        assert!(resolver.certificate("a.example").is_none());
        assert!(resolver.certificate("b.example").is_some());
    }
}
