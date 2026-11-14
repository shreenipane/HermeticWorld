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
    let file = hermetic_netvm_core::files::regular(path, hermetic_netvm_core::MAX_CONFIG_BYTES)
        .map_err(|_| "invalid_config".to_string())?;
    let mut buf = String::new();
    file.take(hermetic_netvm_core::MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut buf)
        .map_err(|_| "invalid_config".to_string())?;
    if buf.len() as u64 > hermetic_netvm_core::MAX_CONFIG_BYTES {
        return Err("invalid_config".into());
    }
    Ok(buf)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args_os()
        .take(MAX_CLI_ARGS + 1)
        .map(|arg| {
            let value = arg.into_string().map_err(|_| "invalid_arguments")?;
            if value.len() > MAX_CLI_ARG_BYTES {
                return Err("invalid_arguments");
            }
            Ok(value)
        })
        .collect::<Result<_, _>>()?;
    if args.len() > MAX_CLI_ARGS {
        return Err("invalid_arguments".into());
    }
    if std::process::id() == 1 || args.get(1).is_some_and(|a| a == "--pid1") {
        if std::process::id() != 1 || args.len() != 1 {
            return Err("pid1_required".into());
        }
        return run_world(true, &args);
    }
    if args.get(1).is_some_and(|a| a == "serve") {
        return run_world(false, &args);
    }
    let cli = parse_args(args).map_err(|_| "invalid_arguments")?;
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
            eprintln!("netvm_start_failed: {msg}");
            if std::process::id() == 1 {
                // PID 1 must never exit (kernel panic); power the VM off instead.
                let _ = run_command("/sbin/hermetic-busybox", &["poweroff", "-f"]);
                loop {
                    std::thread::sleep(IDLE_SLEEP);
                }
            }
            ExitCode::FAILURE
        }
    }
}

const MAX_CLI_ARGS: usize = 16;
const MAX_CLI_ARG_BYTES: usize = 4096;

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    use hermetic_netvm_core::runtime::{BOOT_COMMAND_TIMEOUT_MS, BOOT_POLL_MS};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut child = Command::new(program)
        // BusyBox dispatches by basename; the sealed executable has a project name.
        .arg0("busybox")
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "boot_failed".to_string())?;
    let end = Instant::now() + Duration::from_millis(BOOT_COMMAND_TIMEOUT_MS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err("boot_failed".into())
                }
            }
            Ok(None) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(BOOT_POLL_MS))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("boot_failed".into());
            }
        }
    }
}

fn run_world(pid1: bool, args: &[String]) -> Result<(), String> {
    use hermetic_netvm_core::{
        files,
        runtime::{self, WorldConfig, WorldDns, WorldFilter},
        upstream::VsockUpstream,
    };
    use hermetic_netvm_dns::DnsTable;
    let mut flags = std::collections::BTreeMap::new();
    if !pid1 {
        let mut iter = args.iter().skip(2);
        while let Some(key) = iter.next() {
            if !matches!(
                key.as_str(),
                "--config" | "--dns-table" | "--world-socket" | "--dns" | "--http"
            ) {
                return Err("invalid_arguments".into());
            }
            let value = iter.next().ok_or("invalid_arguments")?;
            if flags.insert(key.as_str(), value.as_str()).is_some() {
                return Err("invalid_arguments".into());
            }
        }
        if flags.len() != 5 {
            return Err("invalid_arguments".into());
        }
    } else {
        // The sealed image and PID check make this single bootstrap executable trusted.
        run_command(
            "/sbin/hermetic-busybox",
            &[
                "mount",
                "-t",
                "proc",
                "-o",
                "nosuid,nodev,noexec",
                "proc",
                "/proc",
            ],
        )?;
    }
    let config_path = if pid1 {
        "/etc/hermetic/netvm.json"
    } else {
        *flags.get("--config").ok_or("invalid_arguments")?
    };
    let dns_path = if pid1 {
        "/etc/hermetic/dns.json"
    } else {
        *flags.get("--dns-table").ok_or("invalid_arguments")?
    };
    let config = WorldConfig::parse(
        files::regular(
            std::path::Path::new(config_path),
            runtime::MAX_RUNTIME_CONFIG_BYTES,
        )
        .map_err(|_| "invalid_config")?,
    )
    .map_err(str::to_owned)?;
    let mut dns_bytes = Vec::new();
    use std::io::Read;
    files::regular(
        std::path::Path::new(dns_path),
        hermetic_netvm_dns::MAX_TABLE_JSON_BYTES as u64,
    )
    .map_err(|_| "invalid_dns")?
    .take(hermetic_netvm_dns::MAX_TABLE_JSON_BYTES as u64 + 1)
    .read_to_end(&mut dns_bytes)
    .map_err(|_| "invalid_dns")?;
    let table =
        DnsTable::from_json_str(std::str::from_utf8(&dns_bytes).map_err(|_| "invalid_dns")?)
            .map_err(|_| "invalid_dns")?;
    let tls_config = if pid1 {
        let identity = config.tls.as_ref().ok_or("invalid_tls_identity")?;
        if hermetic_netvm_core::tls::digest(&dns_bytes) != identity.dns_sha256 {
            return Err("invalid_tls_identity".into());
        }
        let ca =
            hermetic_netvm_core::tls::receive_guest(&config).map_err(|_| "invalid_tls_material")?;
        Some(
            hermetic_netvm_core::tls::server_config(ca, &table, config.t_clock)
                .map_err(|_| "invalid_tls_material")?,
        )
    } else {
        None
    };
    runtime::world_addresses(&table).map_err(str::to_owned)?;
    let filter = WorldFilter::new(&table);
    let upstream = if pid1 {
        VsockUpstream::guest()
    } else {
        VsockUpstream::unix(flags.get("--world-socket").ok_or("invalid_arguments")?)
    };
    let dns_addr = if pid1 {
        format!("{}:53", runtime::NETVM_ADDRESS)
    } else {
        flags.get("--dns").ok_or("invalid_arguments")?.to_string()
    };
    let http_addr = if pid1 {
        "0.0.0.0:80".to_string()
    } else {
        flags.get("--http").ok_or("invalid_arguments")?.to_string()
    };
    let dns_addr: SocketAddr = dns_addr.parse().map_err(|_| "invalid_arguments")?;
    let http_addr: SocketAddr = http_addr.parse().map_err(|_| "invalid_arguments")?;
    if pid1 {
        let epoch = format!("@{}", config.t_clock);
        run_command("/sbin/hermetic-busybox", &["date", "-u", "-s", &epoch])?;
        hermetic_netvm_core::firewall::install().map_err(|_| "boot_failed")?;
        runtime::configure(&table, |command| {
            let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
            run_command(command.program, &args).map_err(|_| "boot_failed")
        })
        .map_err(str::to_owned)?;
    }
    let https = if pid1 {
        Some(TcpListener::bind("0.0.0.0:443").map_err(|_| "bind_failed")?)
    } else {
        None
    };
    let dns = UdpSocket::bind(dns_addr).map_err(|_| "bind_failed")?;
    let http = TcpListener::bind(http_addr).map_err(|_| "bind_failed")?;
    let filter = Arc::new(filter);
    let upstream = Arc::new(upstream);
    let server = RunningNetvm::start(
        dns,
        http,
        hermetic_netvm_core::http::HttpRuntimeConfig::bounded(
            64,
            5000,
            2000,
            30000,
            config.t_clock,
        ),
        Arc::new(WorldDns(table)),
        filter.clone(),
        upstream.clone(),
        Arc::new(StderrLogSink),
    )
    .map_err(|_| "start_failed")?;
    let tls_thread = if let (Some(listener), Some(tls_config)) = (https, tls_config) {
        let shutdown = server.shutdown_flag();
        let metrics = Arc::new(hermetic_netvm_core::Metrics::new(Arc::new(StderrLogSink)));
        Some(
            std::thread::Builder::new()
                .name("hermetic-https".into())
                .spawn(move || {
                    hermetic_netvm_core::tls::run_loop(
                        listener,
                        tls_config,
                        hermetic_netvm_core::http::HttpRuntimeConfig::bounded(
                            1,
                            5000,
                            2000,
                            30000,
                            config.t_clock,
                        ),
                        filter,
                        upstream,
                        metrics,
                        shutdown,
                    );
                })
                .map_err(|_| "start_failed")?,
        )
    } else {
        None
    };
    if pid1 {
        runtime::write_ready_status(std::io::stderr()).map_err(|_| "status_failed")?;
    }
    let shutdown = server.shutdown_flag();
    while !shutdown.load(Ordering::Acquire) {
        std::thread::sleep(IDLE_SLEEP);
    }
    server.stop();
    if let Some(thread) = tls_thread {
        let _ = thread.join();
    }
    Ok(())
}

#[cfg(test)]
mod boot_tests {
    use super::*;

    #[test]
    fn renamed_busybox_dispatches_boot_applets() {
        let temp = tempfile::tempdir().unwrap();
        let renamed = temp.path().join("hermetic-busybox");
        std::fs::copy("/usr/bin/busybox", &renamed).unwrap();
        // Exercise the same renamed executable and dispatcher as PID 1 without
        // mounting filesystems, changing the clock or configuring host networking.
        assert_eq!(run_command(renamed.to_str().unwrap(), &["true"]), Ok(()));
        assert_eq!(
            run_command(
                renamed.to_str().unwrap(),
                &["date", "-u", "-d", "@1700000000", "+%s"]
            ),
            Ok(())
        );
    }
}
