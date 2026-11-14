#![forbid(unsafe_code)]
//! `hermetic-escapeprobe` runs every probe and prints one JSON line each.
//! `hermetic-escapeprobe --aggregate` reads a report on stdin (host side) and
//! prints the verdict. Exit codes: 0 sealed, 2 leak/escaped, 1 otherwise.

use std::io::{self, Read, Write};

use hermetic_escapeprobe::{classify, probes, report};

// A stalled kernel operation must not consume execd's entire command deadline.
// A partial report is invalid at the aggregator, so expiry fails closed.
fn start_watchdog(timeout: std::time::Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        std::process::exit(1);
    });
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).take(2).collect();
    match args.as_slice() {
        [] => {
            start_watchdog(probes::MAX_PROBE_RUNTIME);
            let mut out = io::stdout().lock();
            let records = probes::run_with(|r| {
                if writeln!(out, "{}", r.to_json_line())
                    .and_then(|()| out.flush())
                    .is_err()
                {
                    std::process::exit(1);
                }
            });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn watchdog_bounds_stalled_probe_and_preserves_flushed_output() {
        const CHILD_FLAG: &str = "HERMETIC_WATCHDOG_TEST_CHILD";
        if std::env::var_os(CHILD_FLAG).is_some() {
            start_watchdog(Duration::from_millis(25));
            let mut out = io::stdout().lock();
            writeln!(out, "completed record").unwrap();
            out.flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::watchdog_bounds_stalled_probe_and_preserves_flushed_output",
                "--nocapture",
            ])
            .env(CHILD_FLAG, "1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("watchdog failed to terminate stalled probe");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(1));
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(1024)
            .read_to_string(&mut output)
            .unwrap();
        assert!(output.contains("completed record\n"));
    }
}
