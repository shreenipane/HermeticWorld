#![forbid(unsafe_code)]
//! Trusted guest TSC measurement helper.
//!
//! Under Phase 3b clock-hiding rules, RDTSC may be trapped for unprivileged
//! agent processes. This helper is executed by the trusted guest supervisor
//! (execd) to sample the guest TSC directly via RDTSC, enabling host-side
//! drift tracking against the 2.0 GHz virtual TSC without exposing raw timing
//! channels to untrusted workloads.

use std::io::{self, Write};

fn main() {
    let Some(val) = hermetic_clockprobe::read_tsc() else {
        std::process::exit(1);
    };
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if writeln!(handle, "{{\"tsc\":{val}}}").is_err() || handle.flush().is_err() {
        std::process::exit(1);
    }
    std::process::exit(0);
}
