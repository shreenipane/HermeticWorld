//! CLI entrypoint for `hermetic-cmdlog`.
//!
//! Usage:
//!   `hermetic-cmdlog verify FILE`
//!
//! Exit codes:
//!   `0` — valid chain (prints `{"seq":...,"head":"sha256:..."}` to stdout)
//!   `2` — broken chain (bad JSON, unknown field, seq gap, prev mismatch, oversized/truncated line)
//!   `1` — usage, I/O, or file safety error (e.g. missing file, symlink, group-writable file)

#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

use hermetic_cmdlog::verify;

// Include one extra argument so excess arguments are rejected without collecting them all.
const MAX_CLI_ARGS: usize = 4;

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().take(MAX_CLI_ARGS).collect();
    match args.as_slice() {
        [_, subcommand, file_path] if subcommand == "verify" => match verify(file_path) {
            Ok(head) => match serde_json::to_string(&head) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::from(0)
                }
                Err(err) => {
                    eprintln!("error: failed to serialize head JSON: {err}");
                    ExitCode::from(1)
                }
            },
            Err(err) => {
                eprintln!("error: {err}");
                if err.is_chain_corruption() {
                    ExitCode::from(2)
                } else {
                    ExitCode::from(1)
                }
            }
        },
        _ => {
            eprintln!("usage: hermetic-cmdlog verify FILE");
            ExitCode::from(1)
        }
    }
}
