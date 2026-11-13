#![forbid(unsafe_code)]
//! GraderVM PID 1: read-only proc, clock from hermetic.t, /tmp and devpts, run the
//! supervisor with fixed arguments, sync, power off. No vsock, no network.
use hermetic_execd::grader::{run, LinuxGrader};

fn main() {
    // run() powers off on every path once PID 1 is confirmed.
    let _ = run(&mut LinuxGrader);
    std::process::exit(1);
}
