#![forbid(unsafe_code)]

//! CLI entry point: `hermetic-netvm --dns 127.0.0.1:PORT --http 127.0.0.1:PORT --config FILE`

use std::fmt;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use hermetic_netvm_core::{NetvmConfig, RunningNetvm, StderrLogSink};

const IDLE_SLEEP: Duration = Duration::from_millis(100);

#[derive(Debug, PartialEq, Eq)]
struct CliArgs {
    dns_addr: SocketAddr,
    http_addr: SocketAddr,
    config_path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum CliError {
    HelpRequested,
    MissingFlag(&'static str),
    MissingValue(&'static str),
    UnknownFlag(String),
    InvalidSocketAddr(&'static str, String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::HelpRequested => write!(
                f,
                "Usage: hermetic-netvm --dns 127.0.0.1:PORT --http 127.0.0.1:PORT --config FILE"
            ),
            CliError::MissingFlag(flag) => write!(f, "missing required flag: {flag}"),
            CliError::MissingValue(flag) => write!(f, "missing value for flag: {flag}"),
            CliError::UnknownFlag(flag) => write!(f, "unknown argument: {flag}"),
            CliError::InvalidSocketAddr(flag, val) => {
                write!(f, "invalid socket address for {flag}: {val}")
            }
        }
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut iter = args.into_iter();
    let _program = iter.next();

    let mut dns_raw: Option<String> = None;
    let mut http_raw: Option<String> = None;
    let mut config_raw: Option<String> = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(CliError::HelpRequested),
            "--dns" => {
                let val = iter.next().ok_or(CliError::MissingValue("--dns"))?;
                dns_raw = Some(val);
            }
            "--http" => {
                let val = iter.next().ok_or(CliError::MissingValue("--http"))?;
                http_raw = Some(val);
            }
            "--config" => {
                let val = iter.next().ok_or(CliError::MissingValue("--config"))?;
                config_raw = Some(val);
            }
            _ => return Err(CliError::UnknownFlag(arg)),
        }
    }

    let dns_str = dns_raw.ok_or(CliError::MissingFlag("--dns"))?;
    let http_str = http_raw.ok_or(CliError::MissingFlag("--http"))?;
    let config_str = config_raw.ok_or(CliError::MissingFlag("--config"))?;

    let dns_addr: SocketAddr = dns_str
        .parse()
        .map_err(|_| CliError::InvalidSocketAddr("--dns", dns_str))?;
    let http_addr: SocketAddr = http_str
        .parse()
        .map_err(|_| CliError::InvalidSocketAddr("--http", http_str))?;

    Ok(CliArgs {
        dns_addr,
        http_addr,
        config_path: PathBuf::from(config_str),
    })
}

/// Reads the configuration file, refusing anything larger than `MAX_CONFIG_BYTES`.
fn read_config_bounded(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("failed to read config file: {e}"))?;
    let mut buf = String::new();
    file.take(hermetic_netvm_core::MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_string(&mut buf)
        .map_err(|e| format!("failed to read config file: {e}"))?;
    if buf.len() as u64 > hermetic_netvm_core::MAX_CONFIG_BYTES {
        return Err(format!(
            "config file exceeds {} bytes",
            hermetic_netvm_core::MAX_CONFIG_BYTES
        ));
    }
    Ok(buf)
}

fn run() -> Result<(), String> {
    let cli = parse_args(std::env::args()).map_err(|e| e.to_string())?;
    let config_bytes = read_config_bounded(&cli.config_path)?;
    let config = NetvmConfig::from_json_str(&config_bytes).map_err(|e| e.to_string())?;
    let (dns_responder, filter, upstream) = config
        .build_default_components()
        .map_err(|e| e.to_string())?;

    let dns_socket =
        UdpSocket::bind(cli.dns_addr).map_err(|e| format!("failed to bind DNS socket: {e}"))?;
    let http_listener = TcpListener::bind(cli.http_addr)
        .map_err(|e| format!("failed to bind HTTP listener: {e}"))?;

    let server = RunningNetvm::start(
        dns_socket,
        http_listener,
        config.http_runtime_config(),
        Arc::new(dns_responder),
        Arc::new(filter),
        Arc::new(upstream),
        Arc::new(StderrLogSink),
    )
    .map_err(|e| e.to_string())?;

    let shutdown = server.shutdown_flag();
    while !shutdown.load(Ordering::Acquire) {
        std::thread::sleep(IDLE_SLEEP);
    }

    server.stop();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}
