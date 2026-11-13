
# hermetic-extract-agent

Guest-side deterministic change extractor for Hermetic World. Reads a read-only base tree and a read-only merged work tree without invoking `git` or following symlinks, streams canonical change records in the `HEXT` v1 binary format, and writes a deterministic JSON report of skipped non-regular/hard-linked work-tree entries.

## Security & Determinism Guarantees

- `#![forbid(unsafe_code)]` across library, binary, and integration tests.
- Zero panics on untrusted inputs: all reads, counts, allocations, and loops are bounded by named `const` caps and checked arithmetic.
- Symlinks are never followed (`symlink_metadata` / `lstat` inspection); opened files verify `dev`, `ino`, `nlink == 1`, and file size before and after a single bounded-chunk read, failing closed on concurrent modification.
- Deterministic traversal (`BTreeSet` / sorted paths) ignoring `.git` at any depth.
- Output stream and JSON report contain only relative UTF-8 `/`-separated paths—no host timestamps, hostnames, or absolute host paths.

## Wire Format (`HEXT` v1)

The host validator in `crates/hermetic-extract` (`format.rs`, TR-EXT-5) defines the format; this crate emits it byte for byte. `tests/validator_compat.rs` feeds agent streams to the validator and checks the agent's bytes against the validator's own encoder.

1. **Stream header** (8 bytes): `b"HEXT"` + version `1u32` LE.
2. **Records**, each a fixed 60-byte little-endian header, then the path, then the payload:

   | Offset | Size | Field |
   |---|---|---|
   | 0 | 1 | `type`: `1` file, `2` dir, `3` delete, `4` end |
   | 1 | 1 | `flags`: must be `0` |
   | 2 | 2 | reserved: must be `0` |
   | 4 | 4 | `path_len` (`u32`, `0` for end) |
   | 8 | 4 | `mode`: `0o644`/`0o755` for files, `0o755` for dirs, `0` otherwise |
   | 12 | 8 | `size`: file byte length; `0` for dirs/deletes; for end, the total file payload bytes of the stream |
   | 20 | 8 | `record_count`: `0` except in the end record, where it is the number of preceding records |
   | 28 | 32 | `sha256`: SHA-256 of the file bytes for files, all zeros otherwise |

   After the header: `path_len` UTF-8 path bytes (relative, `/`-separated), then `size` raw bytes for files.
3. The end record is last; any byte after it is an error.

## CLI Usage

hermetic-extract-agent \
  --base /mnt/base \
  --work /mnt/work \
  --class patch:repo \
  --out /mnt/out/changes.hext \
  --report /mnt/out/report.json


Supported `--class` forms:

* `patch:REPO` (a relative subdirectory; record paths keep the `REPO/` prefix, matching validator config `repo_dir: "REPO"`)
* `patch:` (empty: the whole tree root, matching validator config `repo_dir: ""`). `patch:.` and `patch:/` are refused with `InvalidTaskClass`; the validator likewise refuses `repo_dir: "."`.
* `artifact:P1,P2` (comma-separated relative file/directory paths)
* `state` (emits no change records; writes header and `end` record)

