#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use hermetic_clockprobe::{classify, lockdown, probes};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).take(2).collect();
    let records = match args.as_slice() {
        [] => probes::run_all_probes(),
        [arg] if arg == "--lockdown-only" => lockdown::run(),
        [arg] if arg == "--kernel-canary-serial" => {
            let mut serial = Vec::new();
            if io::stdin()
                .lock()
                .take(hermetic_clockprobe::canary::MAX_SERIAL_BYTES + 1)
                .read_to_end(&mut serial)
                .is_err()
            {
                std::process::exit(1);
            }
            vec![hermetic_clockprobe::canary::inspect(&serial)]
        }
        _ => std::process::exit(1),
    };
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
