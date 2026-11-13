
# hermetic-extract-agent

Guest-side deterministic change extractor for Hermetic World. Reads a read-only base tree and a read-only merged work tree without invoking `git` or following symlinks, streams canonical change records in the `HEXT` v1 binary format, and writes a deterministic JSON report of skipped non-regular/hard-linked work-tree entries.

## Security & Determinism Guarantees

- `#![forbid(unsafe_code)]` across library, binary, and integration tests.
- Zero panics on untrusted inputs: all reads, counts, allocations, and loops are bounded by named `const` caps and checked arithmetic.
- Symlinks are never followed (`symlink_metadata` / `lstat` inspection); opened files verify `dev`, `ino`, `nlink == 1`, and file size before and after a single bounded-chunk read, failing closed on concurrent modification.
- Deterministic traversal (`BTreeSet` / sorted paths) ignoring `.git` at any depth.
- Output stream and JSON report contain only relative UTF-8 `/`-separated paths—no host timestamps, hostnames, or absolute host paths.

## Wire Format (`HEXT` v1)

1. **Header**: `b"HEXT"` (4 bytes) + version `1u16` LE (2 bytes).
2. **Records** (repeated until `type == 4`):
   - `type`: `u8` (`1` = file, `2` = dir, `3` = delete, `4` = end)
   - `path_len`: `u16` LE (`0` for `end`)
   - `path`: `path_len` UTF-8 bytes, relative `/`-separated
   - `mode`: `u32` LE (`0o644` or `0o755` for files, `0o755` for dirs, `0` otherwise)
   - `size`: `u64` LE (file byte length for files, `0` for dirs/deletes, preceding record count for `end`)
   - `sha256`: 32 bytes (SHA-256 of file bytes for files, all zeros for dirs/deletes, SHA-256 of all preceding stream bytes for `end`)
   - `file_bytes`: `size` raw bytes (present only when `type == 1`)

## CLI Usage

hermetic-extract-agent \
  --base /mnt/base \
  --work /mnt/work \
  --class patch:repo \
  --out /mnt/out/changes.hext \
  --report /mnt/out/report.json


Supported `--class` forms:

* `patch:REPO` (`REPO` may be `.` for the tree root or a relative subdirectory)
* `artifact:P1,P2` (comma-separated relative file/directory paths)
* `state` (emits no change records; writes header and `end` record)

