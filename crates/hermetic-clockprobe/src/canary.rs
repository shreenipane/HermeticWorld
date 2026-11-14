//! Manager-only validation of the disposable kernel's bounded serial transcript.
#![forbid(unsafe_code)]
use crate::classify::{ProbeRecord, ProbeResult};
use std::collections::BTreeSet;

pub const MAX_SERIAL_BYTES: u64 = 262_144;
pub const EXPECTED: [&str; 6] = [
    "msr=00000011 rd=gp wr=gp page=unchanged",
    "msr=00000012 rd=gp wr=gp page=unchanged",
    "msr=4b564d00 rd=gp wr=gp page=unchanged",
    "msr=4b564d01 rd=gp wr=gp page=unchanged",
    "hypercall=9 ret=enosys page=unchanged",
    "result=pass",
];

pub fn inspect(serial: &[u8]) -> ProbeRecord {
    let error = || {
        ProbeRecord::new(
            "kernel_canary",
            ProbeResult::Error,
            None,
            "Missing, duplicate, malformed or oversized kernel canary evidence",
        )
    };
    if serial.len() as u64 > MAX_SERIAL_BYTES {
        return error();
    }
    let Ok(text) = std::str::from_utf8(serial) else {
        return error();
    };
    let mut found = BTreeSet::new();
    for line in text.split_inclusive('\n') {
        if let Some((_, payload)) = line.split_once("hermetic-canary/v1") {
            let Some(payload) = payload.strip_prefix(' ').and_then(|p| p.strip_suffix('\n')) else {
                return error();
            };
            let payload = payload.strip_suffix('\r').unwrap_or(payload);
            if !EXPECTED.contains(&payload) {
                return ProbeRecord::new(
                    "kernel_canary",
                    ProbeResult::Leak,
                    None,
                    "Kernel canary observed an accepted access or modified page",
                );
            }
            if !found.insert(payload) {
                return error();
            }
        }
    }
    if found.len() != EXPECTED.len() {
        return error();
    }
    ProbeRecord::new("kernel_canary", ProbeResult::Blocked, None,
        "All four KVM clock MSRs faulted on reads and writes; hypercall returned ENOSYS; pages unchanged")
}
