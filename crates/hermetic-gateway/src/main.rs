#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tiny_http::Server;

use hermetic_gateway::config::GatewayConfig;
use hermetic_gateway::server::GatewayServer;

#[derive(Parser, Debug)]
#[command(name = "hermetic-gateway", about = "Hermetic World model gateway")]
struct Args {
    #[arg(long, help = "Path to the configuration JSON file")]
    config: PathBuf,

    #[arg(long, help = "Host and port to listen on (e.g. 127.0.0.1:8080)")]
    listen: Option<String>,

    #[arg(
        long,
        help = "Unix domain socket path to listen on (e.g. /path/to/vsock_5002)"
    )]
    socket: Option<PathBuf>,

    #[arg(long = "t-clock", help = "World clock time in RFC 3339 format")]
    t_clock: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let t_clock = match OffsetDateTime::parse(&args.t_clock, &Rfc3339) {
        Ok(dt) => dt,
        Err(e) => {
            eprintln!(
                "Invalid RFC 3339 format for --t-clock '{}': {e}",
                args.t_clock
            );
            return ExitCode::from(1);
        }
    };

    let config = match GatewayConfig::load_from_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            return ExitCode::from(1);
        }
    };

    // Validates T_clock (and T_clock + wall-time limit) before anything listens.
    let gateway = match GatewayServer::new(config, t_clock) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to initialize gateway server: {e}");
            return ExitCode::from(1);
        }
    };

    let socket_path = args.socket.or_else(|| {
        args.listen.as_ref().and_then(|l| {
            if l.starts_with('/') || l.starts_with('.') {
                Some(PathBuf::from(l))
            } else {
                None
            }
        })
    });

    let server_http = if let Some(path) = socket_path {
        let listener = match hermetic_gateway::fsutil::bind_unix_socket(&path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind Unix socket on '{}': {e}", path.display());
                return ExitCode::from(1);
            }
        };
        match Server::from_listener_with_deadlines(listener, None, gateway.client_deadlines()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "Failed to initialize server from socket '{}': {e}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        }
    } else if let Some(listen_addr) = args.listen {
        match Server::http_with_deadlines(&listen_addr, gateway.client_deadlines()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to bind server on '{listen_addr}': {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        eprintln!("Must specify either --listen or --socket");
        return ExitCode::from(1);
    };

    gateway.run_loop(server_http);

    ExitCode::SUCCESS
}
