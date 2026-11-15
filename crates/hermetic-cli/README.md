
# hermetic-cli

Strict, deterministic command-line front end and dispatch layer for **Hermetic World** (`hermetic`).

## Design Guarantees

- **Zero argument-parsing crates:** Custom `OsString` parser in `src/args.rs` supporting `--flag value`, `--flag=value`, and `--` end-of-options, while rejecting short flags, unknown flags, missing values, repeated flags, and stray positional arguments.
- **Bounded input:** at most `MAX_ARGS` (64) argument tokens, each at most `MAX_ARG_BYTES` (4096) bytes; anything larger is a usage error (exit `64`).
- **Strict UTF-8 handling:** Arguments are read as `OsString` and validated without lossy conversion; invalid UTF-8 is refused with exit code `64`.
- **Pre-dispatch validation:** Validates UTC RFC 3339 timestamps (`Z` suffix with calendar checks), world IDs (`[a-z0-9-]{1,64}`), task IDs (`[A-Za-z0-9._-]{1,128}`), SHA-256 root digests (`sha256:` + 64 lowercase hex), and non-empty NUL-free paths before calling any backend.
- **Deterministic output:** Emits either one short human line or one canonical JSON object (sorted keys) on `stdout`, never includes host time, host name, or environment variable values, and forbids `unsafe` code (`#![forbid(unsafe_code)]`).

## Command Grammar

hermetic seal --src DIR --out DIR --t-clock RFC3339 --world-id ID [--seal-level strict|repo_only]
hermetic verify-bundle DIR [--root sha256:HEX]
hermetic probe --world DIR [--clockprobe-output FILE] [--kernel-canary-serial FILE] [--json]
hermetic run --world DIR --task ID --agent-mode H|G [--clock faked|hidden] [--json]
hermetic verify --record FILE --key FILE [--bundle DIR] [--classification FILE]
hermetic --version
hermetic help [SUBCOMMAND]


## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Operation ran and found a problem (for example, verification failed) |
| `64` | Command-line usage error |
| `65` | Invalid input data |
| `70` | Internal error or feature not implemented (including `--clock hidden` and unwired backend calls) |
| `74` | I/O error |


## verify

`--record` is a signed run attestation (DSSE envelope). `--key` is the trusted raw
32-byte Ed25519 public key. With `--bundle`, the bundle must pass integrity
verification and its root must equal the record's `world_root`. With
`--classification`, the record must agree with the run classifier on clock level,
`date_leak_observed`, run status and run digest. Any failure exits 2; refused or
malformed input files exit 65.
