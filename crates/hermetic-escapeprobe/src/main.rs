#![forbid(unsafe_code)]
//! `hermetic-escapeprobe` runs every probe and prints one JSON line each.
//! `hermetic-escapeprobe --aggregate` reads a report on stdin (host side) and
//! prints the verdict. Exit codes: 0 sealed, 2 leak/escaped, 1 otherwise.

use std::io::{self, Read, Write};

use hermetic_escapeprobe::{classify, probes, report};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).take(2).collect();
    match args.as_slice() {
        [] => {
            let records = probes::run_all();
            let mut out = io::stdout().lock();
            for r in &records {
                if writeln!(out, "{}", r.to_json_line()).is_err() {
                    std::process::exit(1);
                }
            }
            if out.flush().is_err() {
                std::process::exit(1);
            }
            std::process::exit(classify::exit_code(&records));
        }
        [a] if a == "--aggregate" => {
            let mut buf = Vec::new();
            if io::stdin()
                .lock()
                .take(report::MAX_REPORT_BYTES as u64 + 1)
                .read_to_end(&mut buf)
                .is_err()
            {
                std::process::exit(1);
            }
            let v = report::aggregate(&buf, &probes::expected_probe_names());
            if writeln!(io::stdout().lock(), "{}", v.as_str()).is_err() {
                std::process::exit(1);
            }
            std::process::exit(match v {
                report::Verdict::Sealed => 0,
                report::Verdict::Escaped { .. } => 2,
                _ => 1,
            });
        }
        _ => std::process::exit(1),
    }
}
