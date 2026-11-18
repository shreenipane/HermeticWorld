#![deny(unsafe_code)]

mod arch_x86;
pub mod classify;
pub mod lockdown;
pub mod probes;
pub mod read;

#[path = "../../../vmm/cpu-baseline.rs"]
pub mod baseline;
pub mod canary;
pub mod identity;

/// Read the guest Time Stamp Counter (TSC) using RDTSC on x86_64.
/// Returns None on non-x86_64 architectures or if unavailable.
pub fn read_tsc() -> Option<u64> {
    arch_x86::read_tsc()
}
