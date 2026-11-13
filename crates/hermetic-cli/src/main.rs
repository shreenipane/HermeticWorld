#![forbid(unsafe_code)]

use std::io::{self, BufWriter};
use std::process::ExitCode;

use hermetic_cli::{run_from_env_args, NotImplementedBackend};

fn main() -> ExitCode {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out_lock = BufWriter::new(stdout.lock());
    let mut err_lock = BufWriter::new(stderr.lock());
    let backend = NotImplementedBackend;
    run_from_env_args(std::env::args_os(), &backend, &mut out_lock, &mut err_lock).into()
}
