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
    listen: String,

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

    let server_http = match Server::http(&args.listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind server on '{}': {e}", args.listen);
            return ExitCode::from(1);
        }
    };

    let gateway = match GatewayServer::new(config, t_clock) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to initialize gateway server: {e}");
            return ExitCode::from(1);
        }
    };

    gateway.run_loop(server_http);

    ExitCode::SUCCESS
}
