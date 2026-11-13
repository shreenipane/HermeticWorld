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

## File Handling
The crate targets Linux x86_64 only and refuses to build elsewhere: std has no named open(2) flag constants, so the Linux x86_64 values of `O_NOFOLLOW` (0o400000), `O_NONBLOCK` (0o4000), `O_NOCTTY` (0o400), `O_DIRECTORY` (0o200000) and `ELOOP` (40) are written as named constants in `src/disk.rs`.

Reading (`read_disk`, `read_bounded_regular_file`):
1. Every ancestor of the path (each prefix of its parent) is checked with `symlink_metadata`; any symlink is refused. Relative paths are checked from the current directory, which is trusted.
2. `symlink_metadata` of the path itself must be a regular file.
3. The file is opened once with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`, so a symlink swapped in fails with `ELOOP` and a FIFO swapped in opens without waiting.
4. `fstat` of the opened handle must be a regular file with the same dev/ino as step 2.
5. Ancestors and the entry are checked again after the open; any change is refused.
For result disks every refusal is classified as tampering.

Writing (`write_disk`):
1. The destination's ancestors must not be symlinks and the destination, if present, must be a regular file.
2. A temporary file is created in the same directory with `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600. Its dev/ino is recorded from the handle, and the handle stays open until return so the inode number cannot be reused.
3. The image is written and fsynced through that handle.
4. Before the rename the temporary name must still hold that inode; then it is renamed over the destination.
5. After the rename the destination must hold the same dev/ino, otherwise an error is returned and no digest.
6. The parent directory is opened with `O_DIRECTORY | O_NOFOLLOW`, must have the dev/ino recorded at the start, and is fsynced.
Cleanup unlinks a temporary name only while it still holds the owned inode; a foreign entry is never removed.

Residual races (documented, not closed): the checks are path-based because std offers no descriptor-relative `openat`/`renameat` without unsafe code or another dependency. An attacker who can write to an ancestor directory and swaps a component to a symlink and back between two checks can still redirect one open or rename; the re-checks narrow the window and detect any swap still in place. Between the final identity check and the unlink during cleanup the name could be replaced, so in that window a foreign entry could be unlinked. A device node swapped in after the type check is opened (non-blocking, without becoming a controlling terminal) before `fstat` refuses it. Result disks must therefore be read from, and written to, directories that no untrusted party can write.

## CLI Usage
```
hermetic-grader-verdict --r0 PATH --r1 PATH --r2 PATH [--r3 PATH] --plan PATH
```

Plan collections are bounded and reject duplicate test IDs and equivalent-pair keys. R3 passing all F2P tests also includes an empty F2P set. Non-regular result files are classified as tampering. Result files are created with mode 0600; failures to sync the parent directory are returned as I/O errors.

Exit codes:
* `0`: verdict status is "resolved"
* `2`: verdict status is "tampered", "infra_error", "unresolved", or "review"
* `1`: command-line usage error or input/output error
