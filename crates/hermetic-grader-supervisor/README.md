
# `hermetic-grader-supervisor`

PID 1 grading supervisor and result disk writer for Hermetic World benchmark VMs.

## Overview

`hermetic-grader-supervisor` executes untrusted agent test suites inside an isolated grading VM and writes a deterministic, self-verifying 1 MiB result disk once the entire test process tree has terminated.

### Key Properties

- **Safe Rust (`#![forbid(unsafe_code)]`)**: Zero `unsafe` blocks, zero panics on untrusted input, and typed error enums across all modules.
- **Minimal Dependencies**: Only `serde` (`derive`), `serde_json`, and `sha2` (`0.10`), plus `tempfile` (`3`) for offline tests.
- **Bounded Execution**: Every file read, pipe chunk, record frame (`64 KiB` cap), stream buffer, record count, supervisor poll loop, and deadline wait is governed by named constants.
- **OS Abstraction (`Os` trait)**: All process, pipe, clock, and filesystem effects pass through `hermetic_grader_supervisor::Os`, with `RealOs` (`std::process`-only) for production and `FakeOs` for deterministic offline testing.

## CLI Usage

hermetic-grader-supervisor --config /path/to/run_config.json --result-disk /dev/vdb


## Wire Protocol (`HGR1`)

1. Stream header: `b"HGR1"` (4 bytes).
2. Repeated frames:
* `type`: `u8` (`1` = `START`, `2` = `FINISH`, `3` = `END`)
* `length`: `u32` little-endian (capped at `65,536` bytes)
* `payload`: UTF-8 JSON:
* `START`: `{"seq": <u64>, "nodeid": <string>}`
* `FINISH`: `{"seq": <u64>, "nodeid": <string>, "outcome": "passed"|"failed"|"skipped"|"error", "duration_ms": <u64>}`
* `END`: `{"count": <u64>}`





Strict decoding preserves all valid records prior to any stream corruption and marks remaining expected tests `"failed"`.

## Result Disk Format (`HGRD`, Exact 1 MiB)

* `0..4`: Magic `b"HGRD"`
* `4..6`: Version `1u16` (LE)
* `6..8`: Flags `0u16` (LE)
* `8..12`: Payload length `u32` (LE)
* `12..44`: SHA-256 digest of the canonical JSON payload
* `44..(44 + length)`: Compact canonical JSON payload (`run`, `supervisor`, `tests`, `variant_set`)
* `(44 + length)..1_048_576`: Zero padding (`0x00`)

## Future Privileged Hardening

Because `RealOs` is restricted to safe `std::process` without `unsafe` FFI, a later privileged release must add:

* Linux namespace isolation (`PID`, `mount`, `network`, `IPC`, `UTS`, `cgroup`).
* Full Linux capability drop (`PR_CAPBSET_DROP` + `capset`) and `PR_SET_NO_NEW_PRIVS`.
* Device cgroup enforcement denying access to the result disk device from the test tree.
* Dedicated result pipe fd (`dup2` onto fd 3) and process-group kill (`kill(-pgid, SIGKILL)`).

