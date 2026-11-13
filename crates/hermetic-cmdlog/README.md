
# `hermetic-cmdlog`

Tamper-evident, append-only command log library and CLI for **Hermetic World Mode H**.

## Overview

In Mode H, the evaluation harness sends every agent command over a host channel and records each
operation and its result in an append-only hash-chained JSONL log. The final head hash is placed
into the signed run record.

### Security & Determinism Design

- **`#![forbid(unsafe_code)]`**: Pure safe Rust with only `serde`, `serde_json`, and `sha2`.
- **No leaked output bodies**: Command `stdout` and `stderr` text are never stored in the log;
  only their SHA-256 digests (`stdout_sha256`, `stderr_sha256`) and byte lengths (`stdout_len`,
  `stderr_len`) are recorded so the log cannot leak post-cutoff or host information.
- **Deterministic entries**: Wall-clock timestamps are omitted; entries are ordered by a
  0-based monotonic `seq` counter and chained via `prev = "sha256:<previous_entry_hash>"`
  (`64` zeros at `seq == 0`).
- **Canonical JSON hashing**: Each entry's hash is the SHA-256 digest of its canonical JSON
  line (alphabetically sorted keys, no spaces).
- **Bounded reads and counts**: Every line read, stream hash, field length, and sequence count
  is bounded by named `const` caps (`MAX_LINE_BYTES`, `MAX_LOG_ENTRIES`, `MAX_ARGV_LEN`,
  `MAX_ARG_BYTES`, `MAX_PATH_BYTES`, `MAX_OUTPUT_BYTES`).
- **Safe file handling**: Refuses symlinks, non-regular files, and files writable by group or
  others (`mode & 0o022 != 0`), verifies existing chains on open, and `fsync`s after each append.

## CLI Usage

hermetic-cmdlog verify path/to/cmdlog.jsonl


* **Exit `0**`: Chain is valid; prints `{"seq":<u64>,"head":"sha256:<hex>"}` to `stdout`.
* **Exit `2**`: Chain is broken (bad JSON, unknown field, `seq` gap, `prev` mismatch, oversized or truncated line).
* **Exit `1**`: Operational, usage, permission, symlink, or I/O error.


