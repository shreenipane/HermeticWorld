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
        // Host-side build step: list the dates a substrate image (the guest
        // kernel) contains. Pure parsing of stdin; no probe runs.
        [arg] if arg == "--extract-substrate-dates" => {
            let mut image = Vec::new();
            if io::stdin()
                .lock()
                .take(classify::MAX_SUBSTRATE_IMAGE_BYTES + 1)
                .read_to_end(&mut image)
                .is_err()
                || image.len() as u64 > classify::MAX_SUBSTRATE_IMAGE_BYTES
            {
                std::process::exit(1);
            }
            let Some(list) = classify::extract_substrate_dates(&image) else {
                std::process::exit(1);
            };
            if io::stdout().lock().write_all(list.as_bytes()).is_err() {
                std::process::exit(1);
            }
            std::process::exit(0);
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
