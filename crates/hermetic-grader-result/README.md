# hermetic-grader-result

## Overview
This crate implements the Hermetic World fixed-size grader result disk image format (TR-GR-1, TR-GR-6, TR-GR-7) and the differential verdict engine across grading runs R0, R1, R2, and optional R3.

## Disk Format (`DISK_BYTES` = 1,048,576 bytes)
Every result disk image is exactly 1 MiB so runs are indistinguishable by size from outside the VM.

1. **Header** (44 bytes, big-endian integers):
   * Bytes 0..4: magic ASCII bytes `"HGRD"`
   * Bytes 4..6: format version `u16 = 1`
   * Bytes 6..8: flags `u16 = 0`
   * Bytes 8..12: payload byte length `u32` (at most 1,048,532)
   * Bytes 12..44: raw 32-byte SHA-256 digest of the payload bytes

2. **Payload** (44 .. 44 + payload_len):
   * Canonical UTF-8 JSON matching the `RunResult` schema with `deny_unknown_fields` and no duplicate keys.

3. **Zero Padding** (44 + payload_len .. 1,048,576):
   * Every remaining byte must be 0x00.

## Differential Verdict Precedence
The differential verdict evaluates all rules and selects the final status using the following strict priority order (from highest to lowest):

1. `tampered`: any `DiskError::Tamper` on any run, run slot mismatch, any mutated test not failing in R1 (reason `"mutant_passed"`), or any paired test differing between R0 and R2 (reason `"equivalence_mismatch"`).
2. `infra_error`: R0 supervisor timeout or crash, or disk I/O error.
3. `unresolved`: any F2P or P2P test not passing in R0.
4. `review`: R3 (when present) passing all F2P tests (reason `"fix_removal_passed"`).
5. `resolved`: all checks pass.

## CLI Usage
```
hermetic-grader-verdict --r0 PATH --r1 PATH --r2 PATH [--r3 PATH] --plan PATH
```

Exit codes:
* `0`: verdict status is "resolved"
* `2`: verdict status is "tampered", "infra_error", "unresolved", or "review"
* `1`: command-line usage error or file I/O error
