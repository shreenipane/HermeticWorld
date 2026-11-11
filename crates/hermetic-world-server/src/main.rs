#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use hermetic_world_server::{verify_log_recover, ServerConfig, ServerExit, WorldServer};
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Parser, Debug)]
#[command(
    name = "hermetic-world-server",
    about = "Hermetic World host-side server"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,

    #[arg(long)]
    store: Option<PathBuf>,

    #[arg(long)]
    socket: Option<PathBuf>,

    #[arg(long)]
    log: Option<PathBuf>,

    #[arg(long)]
    t_clock: Option<String>,

    #[arg(long)]
    rate_rps: Option<f64>,

    #[arg(long)]
    burst: Option<f64>,

    #[arg(long)]
    max_requests: Option<u64>,

    #[arg(long)]
    max_bytes: Option<u64>,

    #[arg(long, default_value_t = false)]
    allow_no_landlock: bool,

    #[arg(long, default_value_t = false)]
    no_sandbox: bool,

    #[arg(long, default_value_t = false)]
    resume_log: bool,

    #[arg(long, default_value_t = false)]
    recover: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "verify-log")]
    VerifyLog {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        #[arg(long)]
        log: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        allow_unanchored: bool,

        #[arg(long, default_value_t = false)]
        recover: bool,
    },
}

fn run_sandbox_child_test() {
    let store_path = std::env::var("HERMETIC_TEST_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("hw_test_store"));
    let log_path = std::env::var("HERMETIC_TEST_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("hw_test_log"));
    let _ = std::fs::create_dir_all(&store_path);
    let _ = std::fs::create_dir_all(&log_path);

    let store_file = store_path.join("test.txt");
    let _ = std::fs::write(&store_file, b"read only content");

    // FIX 7: Create the outside file BEFORE applying the sandbox; hard fail on error
    let outside = std::env::var("HERMETIC_TEST_OUTSIDE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("hw_test_outside.txt"));
    if let Err(e) = std::fs::write(&outside, b"secret") {
        eprintln!("Failed to create outside fixture file {:?}: {e}", outside);
        std::process::exit(2);
    }

    let status = match hermetic_world_server::apply_sandbox(&store_path, &log_path, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to apply sandbox: {e}");
            std::process::exit(1);
        }
    };

    if status == hermetic_world_server::SandboxLandlockStatus::NotEnforced {
        println!("Note: Landlock not supported by running kernel, checking only seccomp");
    } else {
        // 1. Opening a file outside allowed paths fails with PermissionDenied
        match std::fs::File::open(&outside) {
            Ok(_) => {
                eprintln!("Opening file outside allowed paths unexpectedly succeeded");
                std::process::exit(10);
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    eprintln!("Expected PermissionDenied opening outside file, got: {e}");
                    std::process::exit(10);
                }
            }
        }

        // 2. Writing into the store fails
        if std::fs::write(store_path.join("probe.txt"), b"bad").is_ok() {
            eprintln!("Writing into store unexpectedly succeeded");
            std::process::exit(11);
        }
    }

    // 3. Command::new("true").status() fails
    let cmd_status = std::process::Command::new("true").status();
    if let Ok(s) = cmd_status {
        if s.success() {
            eprintln!("Command::new('true') unexpectedly succeeded");
            std::process::exit(12);
        }
    }

    // 4. Creating an AF_INET socket fails
    println!("CHECKPOINT: BEFORE_AF_INET");
    let sock_res = std::net::TcpListener::bind("127.0.0.1:0");
    if sock_res.is_ok() {
        eprintln!("Creating AF_INET socket unexpectedly succeeded");
        std::process::exit(13);
    }

    println!("CHECKPOINT: ALL_PASSED");
    std::process::exit(0);
}

fn main() {
    // Check if invoked as a sandbox test child
    if let Ok(role) = std::env::var("HERMETIC_CHILD_ROLE") {
        if role == "sandbox" {
            run_sandbox_child_test();
            return;
        }
    }

    let cli = Cli::parse();

    if let Some(Commands::VerifyLog {
        path,
        log,
        allow_unanchored,
        recover,
    }) = cli.cmd
    {
        let target_path = path
            .or(log)
            .unwrap_or_else(|| PathBuf::from("requests.log"));

        let log_file = if target_path.is_dir() {
            target_path.join("requests.log")
        } else {
            target_path
        };

        match verify_log_recover(&log_file, allow_unanchored, recover) {
            Ok(count) => {
                println!("Log verified: {count} records in {}", log_file.display());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("verify-log failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // Otherwise running server
    let store_dir = cli.store.unwrap_or_else(|| {
        eprintln!("Error: --store DIR is required");
        std::process::exit(1);
    });
    let socket_path = cli.socket.unwrap_or_else(|| {
        eprintln!("Error: --socket PATH is required");
        std::process::exit(1);
    });
    let log_dir = cli.log.unwrap_or_else(|| {
        eprintln!("Error: --log DIR is required");
        std::process::exit(1);
    });
    let t_clock_str = cli.t_clock.unwrap_or_else(|| {
        eprintln!("Error: --t-clock RFC3339 is required");
        std::process::exit(1);
    });

    let t_clock = OffsetDateTime::parse(&t_clock_str, &Rfc3339).unwrap_or_else(|e| {
        eprintln!("Error parsing --t-clock: {e}");
        std::process::exit(1);
    });

    let config = ServerConfig {
        store_dir,
        socket_path,
        log_dir,
        t_clock,
        rate_rps: cli.rate_rps,
        burst: cli.burst,
        max_requests: cli.max_requests,
        max_bytes: cli.max_bytes,
        allow_no_landlock: cli.allow_no_landlock,
        no_sandbox: cli.no_sandbox,
        resume_log: cli.resume_log,
        recover: cli.recover,
    };

    let server = match WorldServer::new(config) {
        Ok(s) => s,
        Err(ServerExit::StartupFailed) => std::process::exit(1),
        Err(e) => {
            eprintln!("Server initialization error: {e}");
            std::process::exit(1);
        }
    };

    match server.run() {
        Ok(()) => std::process::exit(0),
        Err(ServerExit::Normal) => std::process::exit(0),
        Err(ServerExit::StartupFailed) => std::process::exit(1),
        Err(ServerExit::Tampered) => std::process::exit(3),
        Err(ServerExit::LimitExceeded) => std::process::exit(4),
        Err(ServerExit::LogFailed) => std::process::exit(5),
    }
}
