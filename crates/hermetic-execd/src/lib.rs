#![deny(unsafe_code)]
//! Guest PID 1. Policy is separate from the privileged Linux implementation.

pub mod boot;
pub mod early;
pub mod fs;
pub mod grader;
pub mod network;
pub mod real;
pub mod rpc;
pub mod spec;
mod sys;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;

pub type Result<T> = std::result::Result<T, Error>;

/// Deliberately contains no input, paths, OS error strings or process output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidClock,
    InvalidInput,
    Limit,
    Io,
    Boot,
    Network,
    Locked,
    Timeout,
    Shutdown,
    ChildStuck,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(_: rustix::io::Errno) -> Self {
        Self::Io
    }
}

pub const MAX_CMDLINE: usize = 4096;
pub const MAX_SPEC: usize = 64 * 1024;
pub const MAX_PATH: usize = 4096;
pub const MAX_COMPONENTS: usize = 128;
pub const MAX_ARGS: usize = 128;
pub const MAX_ARG_BYTES: usize = 32 * 1024;
pub const MAX_CHILD_PAYLOAD: usize = 120 * 1024;
pub const MAX_CHILDREN_BYTES: usize = 64 * 1024;
pub const MAX_PROC_STAT: usize = 4096;
pub const FILE_IO_TIMEOUT_MS: u64 = 5000;
pub const MAX_UPLOAD_ATTEMPTS: usize = 16;
pub const MAX_STRING: usize = 4096;
pub const MAX_ENV: usize = 128;
pub const MAX_ENV_NAME: usize = 128;
pub const MAX_HOSTNAME: usize = 63;
pub const MAX_COMPONENT_BYTES: usize = 255;
pub const MAX_VCPUS: u32 = 256;
pub const MAX_MEMORY_MIB: u64 = 1_048_576;
pub const MAX_DISK_MIB: u64 = 16_777_216;
pub const MAX_WALL_TIME_S: u64 = 86400;
pub const MAX_TRANSFER: usize = 1024 * 1024;
pub const MAX_FRAME: usize = 4 * 1024 * 1024 + 65536;
pub const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;
pub const MAX_RUN_OUTPUT: usize = 16 * 1024 * 1024;
pub const MAX_TIMEOUT_MS: u64 = 300_000;
pub const MAX_CONNECTIONS: usize = 1;
pub const MAX_COMMANDS: usize = 2; // one entry point and one foreground RPC
pub const MAX_DEV_NODES: usize = 16384;
pub const MAX_DEV_DEPTH: usize = 32;
pub const MAX_REAP_BATCH: usize = 4096;
pub const SHUTDOWN_WAIT_MS: u64 = 2000;
pub const CHILD_KILL_WAIT_MS: u64 = 2000;
pub const CHILD_START_TIMEOUT_MS: u64 = 5000;
pub const MAX_DRAIN_READS: usize = 16;
pub const IO_BUFFER: usize = 8192;
pub const MAX_FINAL_DRAIN_READS: usize = MAX_COMMAND_OUTPUT / IO_BUFFER + MAX_DRAIN_READS;
pub const FRAME_TIMEOUT_MS: u64 = 5000;
pub const VSOCK_PORT: u32 = 5000;

pub fn read_capped(reader: impl std::io::Read, cap: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let bound = u64::try_from(cap)
        .map_err(|_| Error::Limit)?
        .checked_add(1)
        .ok_or(Error::Limit)?;
    reader.take(bound).read_to_end(&mut data)?;
    if data.len() > cap {
        return Err(Error::Limit);
    }
    Ok(data)
}
