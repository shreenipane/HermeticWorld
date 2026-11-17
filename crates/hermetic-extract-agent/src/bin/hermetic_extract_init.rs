#![forbid(unsafe_code)]
//! ExtractorVM PID 1 binary (`/sbin/hermetic-extract-init`).
//!
//! Mounts proc/dev minimally, mounts base read-only and overlay read-write,
//! assembles read-only overlayfs with exact TR-EXT-2 options, runs the in-process
//! extraction, writes length-prefixed stream plus 48-byte header to the output drive,
//! syncs, and powers off.

use hermetic_extract_agent::init::{run_extractor_init, LinuxExtractorSys};

fn main() {
    let mut sys = LinuxExtractorSys::new();
    let _ = run_extractor_init(&mut sys, None);
    std::process::exit(1);
}
