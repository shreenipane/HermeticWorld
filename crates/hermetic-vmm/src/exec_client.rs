#![forbid(unsafe_code)]

//! Host-side client for the in-guest execd RPC protocol over vsock (TR-EXD-4).
//!
//! Factors the vsock connect handshake and length-prefixed JSON framing out of
//! test harnesses into a strict, bounded library client.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::api;
use crate::{Error, Result};

pub const MAX_RPC_BYTES: usize = 16 * 1024;
pub const MAX_REPLY_BYTES: usize = 64 * 1024;
pub const MAX_HANDSHAKE_BYTES: usize = 64;
pub const CLOCK_TOLERANCE_SECONDS: u64 = 20;

/// Typed reply returned by guest command execution (`type: "exec"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub code: Option<i32>,
    pub output: Vec<u8>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub timed_out: bool,
}

/// Typed reply returned by guest status query (`type: "status"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub output_bytes: usize,
    pub guest_time_unix: i64,
}

/// Executes a raw length-prefixed request/reply frame over the Firecracker vsock UDS socket.
///
/// 1. Connects to `socket_path` before `end`.
/// 2. Sends `CONNECT 5000\n`.
/// 3. Reads handshake response line bounded by `MAX_HANDSHAKE_BYTES`, requiring `OK ...\n`.
/// 4. Sends 4-byte little-endian length followed by `request` (capped at `MAX_RPC_BYTES`).
/// 5. Reads 4-byte little-endian length (capped at `MAX_REPLY_BYTES`), then exact body bytes.
pub fn call_raw(socket_path: &str, request: &[u8], end: Instant) -> Result<Vec<u8>> {
    if request.is_empty() || request.len() > MAX_RPC_BYTES {
        return Err(Error::Validation("RPC request size cap"));
    }

    let mut stream = api::connect(socket_path, end)?;
    api::write_deadline(&mut stream, b"CONNECT 5000\n", end)?;

    let mut line = Vec::new();
    for _ in 0..MAX_HANDSHAKE_BYTES {
        let mut byte = [0u8];
        api::read_exact_deadline(&mut stream, &mut byte, end)?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }

    if !line.starts_with(b"OK ") || !line.ends_with(b"\n") {
        return Err(Error::Protocol);
    }

    let req_len = (request.len() as u32).to_le_bytes();
    api::write_deadline(&mut stream, &req_len, end)?;
    api::write_deadline(&mut stream, request, end)?;

    let mut length_bytes = [0u8; 4];
    api::read_exact_deadline(&mut stream, &mut length_bytes, end)?;
    let length = u32::from_le_bytes(length_bytes) as usize;

    if length == 0 || length > MAX_REPLY_BYTES {
        return Err(Error::Protocol);
    }

    let mut raw = vec![0u8; length];
    api::read_exact_deadline(&mut stream, &mut raw, end)?;
    Ok(raw)
}

/// Sends a JSON request and parses the JSON reply.
pub fn call_json<T: Serialize, R: for<'a> Deserialize<'a>>(
    socket_path: &str,
    request: &T,
    end: Instant,
) -> Result<R> {
    let payload = serde_json::to_vec(request).map_err(|_| Error::Validation("invalid JSON"))?;
    let reply_bytes = call_raw(socket_path, &payload, end)?;
    serde_json::from_slice(&reply_bytes).map_err(|_| Error::Protocol)
}

/// Queries execd status and verifies that guest time matches expected clock within tolerance.
pub fn check_status(socket_path: &str, expected_clock: i64, end: Instant) -> Result<StatusResult> {
    #[derive(Serialize)]
    struct StatusReq<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
    }

    #[derive(Deserialize)]
    struct StatusResp {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        locked: bool,
        #[serde(default)]
        output_bytes: usize,
        guest_time_unix: i64,
    }

    let resp: StatusResp = call_json(socket_path, &StatusReq { kind: "status" }, end)?;
    if resp.kind != "status" {
        return Err(Error::Protocol);
    }

    if resp.guest_time_unix.abs_diff(expected_clock) > CLOCK_TOLERANCE_SECONDS {
        return Err(Error::Protocol);
    }

    Ok(StatusResult {
        locked: resp.locked,
        output_bytes: resp.output_bytes,
        guest_time_unix: resp.guest_time_unix,
    })
}

/// Executes a command in the guest through execd.
pub fn exec(
    socket_path: &str,
    argv: &[String],
    tty: bool,
    timeout_ms: u64,
    end: Instant,
) -> Result<ExecResult> {
    if argv.is_empty() {
        return Err(Error::Validation("argv must not be empty"));
    }

    #[derive(Serialize)]
    struct ExecReq<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        argv: &'a [String],
        tty: bool,
        timeout_ms: u64,
    }

    #[derive(Deserialize)]
    struct ExecResp {
        code: Option<i32>,
        output: Vec<u8>,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        timed_out: bool,
    }

    let resp: ExecResp = call_json(
        socket_path,
        &ExecReq {
            kind: "exec",
            argv,
            tty,
            timeout_ms,
        },
        end,
    )?;

    Ok(ExecResult {
        code: resp.code,
        output: resp.output,
        truncated: resp.truncated,
        timed_out: resp.timed_out,
    })
}

/// Requests graceful freeze/shutdown of execd before VM power-off.
pub fn shutdown(socket_path: &str, end: Instant) -> Result<()> {
    #[derive(Serialize)]
    struct ShutdownReq<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
    }

    #[derive(Deserialize)]
    struct ShutdownResp {
        #[serde(rename = "type")]
        kind: String,
    }

    let resp: ShutdownResp = call_json(socket_path, &ShutdownReq { kind: "shutdown" }, end)?;
    if resp.kind != "frozen" {
        return Err(Error::Protocol);
    }

    Ok(())
}

/// Sends a raw byte request and parses JSON reply.
pub fn call(socket_path: &str, request: &[u8], end: Instant) -> Result<serde_json::Value> {
    let raw = call_raw(socket_path, request, end)?;
    serde_json::from_slice(&raw).map_err(|_| Error::Protocol)
}

/// Formats a descriptor path for a vsock socket under `proc` or jail directory.
pub fn vsock_socket_path(path: &str) -> String {
    path.replacen("/proc/self/", &format!("/proc/{}/", std::process::id()), 1)
}
