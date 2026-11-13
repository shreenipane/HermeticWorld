#![forbid(unsafe_code)]

use std::io::{self, Write};

use hermetic_clockprobe::{classify, probes};

fn main() {
    let records = probes::run_all_probes();
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for rec in &records {
        let line = rec.to_json_line();
        if writeln!(handle, "{line}").is_err() {
            std::process::exit(1);
        }
    }
    if handle.flush().is_err() {
        std::process::exit(1);
    }
    std::process::exit(classify::determine_exit_code(&records));
}
