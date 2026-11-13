//! Certificate-verifying static HTTPS client for the owner-run network smoke.
use hermetic_netvm_core::{
    files,
    tls::{DeadlineTcp, FrozenTime},
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_ARGUMENTS: usize = 8;
const MAX_CA_BYTES: u64 = 16 * 1024;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);
fn arguments(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Vec<String>, &'static str> {
    args.into_iter()
        .take(MAX_ARGUMENTS)
        .map(|arg| {
            if arg.len() > MAX_ARGUMENT_BYTES {
                return Err("invalid_arguments");
            }
            arg.into_string().map_err(|_| "invalid_arguments")
        })
        .collect()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = arguments(std::env::args_os())?;
    if args.len() != 7 || args.iter().any(|s| s.len() > 4096) {
        return Err("invalid_arguments".into());
    }
    // No name resolution or ambient host trust/configuration.
    let ip: Ipv4Addr = args[2].parse()?;
    let name = ServerName::try_from(args[3].clone())?;
    let epoch: u64 = args[6].parse()?;
    if !matches!(args[5].as_str(), "GET" | "HEAD")
        || !args[4].starts_with('/')
        || args[4].bytes().any(|b| b <= b' ' || b >= 127)
        || !args[3]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err("invalid_arguments".into());
    }
    let mut cert = Vec::new();
    files::regular(Path::new(&args[1]), MAX_CA_BYTES)?
        .take(MAX_CA_BYTES + 1)
        .read_to_end(&mut cert)?;
    if cert.len() as u64 > MAX_CA_BYTES {
        return Err("invalid_certificate".into());
    }
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let mut config = ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        Arc::new(FrozenTime(epoch)),
    )
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let end = Instant::now() + FETCH_TIMEOUT;
    let socket = TcpStream::connect_timeout(&SocketAddr::from((ip, 443)), CONNECT_TIMEOUT)?;
    let mut stream = StreamOwned::new(
        ClientConnection::new(Arc::new(config), name)?,
        DeadlineTcp::new(socket, end),
    );
    write!(
        stream,
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        args[5], args[4], args[3]
    )?;
    stream.flush()?;
    let mut output = Vec::new();
    let result = stream.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut output);
    // A truncated TLS close is an error. The server sends close_notify.
    result?;
    if output.len() as u64 > MAX_RESPONSE_BYTES || !output.starts_with(b"HTTP/1.1 200 ") {
        return Err("invalid_response".into());
    }
    std::io::stdout().write_all(&output)?;
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("https_fetch_failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    #[test]
    fn hostile_arguments_are_rejected_without_panicking() {
        assert!(arguments([std::ffi::OsString::from_vec(vec![255])]).is_err());
        assert!(arguments([std::ffi::OsString::from("x".repeat(MAX_ARGUMENT_BYTES + 1))]).is_err());
    }
}
