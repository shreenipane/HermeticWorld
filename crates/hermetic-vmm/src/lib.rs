#![deny(unsafe_code)]
//! Bounded, descriptor-pinned microVM orchestration. No guest filesystem is mounted.
pub mod api;
pub mod exec_client;
pub mod extractor;
pub mod fs;
pub mod host_audit;
pub mod lifecycle;
pub mod pin;
pub mod plan;
pub mod runner;
pub mod spec;
pub mod tsc_drift;
pub mod verity;
pub mod vmm_infra;

pub use extractor::{
    create_fresh_output_drive, create_overlay_cow_copy, extractor_spec, fallback_chunked_copy,
    generate_run_nonce, read_extractor_output, ExtractorError, ExtractorVmConfig,
    DEFAULT_OUTPUT_DRIVE_BYTES, MAX_OUTPUT_DRIVE_BYTES, MAX_OVERLAY_COPY_BYTES,
};
pub use host_audit::{audit_host_live, audit_host_offline, HostAuditError, HostAuditReport};
pub use lifecycle::{State, Vmm};
pub use plan::{api_requests, jail_plan, ApiRequest, JailPlan};
pub use spec::{drive_id, valid_drive_id, ValidatedSpec, VmSpec};
pub use tsc_drift::{TscDriftError, TscDriftReport, TscDriftTracker};
pub use verity::{parse_dm_create, VerityTable};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Validation(&'static str),
    Io,
    IoNoSpace,
    Protocol,
    Api(u16),
    Deadline(&'static str),
    State,
    Step(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(rule) => write!(f, "refused: {rule}"),
            Self::Io => f.write_str("I/O operation failed"),
            Self::IoNoSpace => f.write_str("I/O operation failed: no-space"),
            Self::Protocol => f.write_str("invalid Firecracker response"),
            Self::Api(status) => write!(f, "Firecracker refused request ({status})"),
            Self::Deadline(step) => write!(f, "deadline exceeded: {step}"),
            Self::State => f.write_str("invalid VM state transition"),
            Self::Step(step) => write!(f, "VM step failed: {step}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        match error.raw_os_error() {
            Some(code)
                if code == rustix::io::Errno::NOSPC.raw_os_error()
                    || code == rustix::io::Errno::DQUOT.raw_os_error() =>
            {
                Self::IoNoSpace
            }
            _ => Self::Io,
        }
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        Self::from(std::io::Error::from(error))
    }
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn deadline(timeout: std::time::Duration) -> Result<std::time::Instant> {
    if timeout.is_zero() || timeout > std::time::Duration::from_secs(300) {
        return Err(Error::Validation("deadline must be in (0, 300s]"));
    }
    std::time::Instant::now()
        .checked_add(timeout)
        .ok_or(Error::Deadline("deadline"))
}
pub fn remaining(end: std::time::Instant, step: &'static str) -> Result<std::time::Duration> {
    end.checked_duration_since(std::time::Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Deadline(step))
}
