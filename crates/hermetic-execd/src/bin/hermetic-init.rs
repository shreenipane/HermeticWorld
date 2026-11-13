#![forbid(unsafe_code)]
//! First-boot PID 1 shim: read-only procfs at /proc, then exec hermetic-execd.
use hermetic_execd::early::{run, LinuxEarly};

fn main() {
    // run() only returns on failure (it has already requested poweroff).
    let _ = run(&mut LinuxEarly);
    std::process::exit(1);
}
