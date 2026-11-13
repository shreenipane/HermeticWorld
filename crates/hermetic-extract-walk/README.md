
# hermetic-extract-walk

Bounded, symlink-safe tree diff extractor for Hermetic World software-engineering benchmark evaluations.

## Security Model

After an AI agent finishes executing inside a sealed world, `hermetic-extract-walk` compares the agent-controlled `work` directory against the original `base` directory and extracts only valid changes.

- **Never reads or traverses `.git`**: Any file, directory, symlink, or special node named `.git` at any depth in either `base` or `work` is skipped immediately—never descended into, never opened, never hashed, and never reported.
- **Never follows symlinks**: Every filesystem entry is inspected with `symlink_metadata`. When opening regular files to compute SHA-256 digests, the opened file descriptor's `metadata()` (`dev`, `ino`, `nlink`, `is_file`, `len`) is verified against the prior `symlink_metadata` before and after reading.
- **Refuses unsafe work entries without aborting**: Symlinks, block/character devices, FIFOs, sockets, hard-linked regular files (`st_nlink > 1`), and non-UTF-8 entry names in `work` are never followed or read; they are recorded in `ChangeSet.refused` while valid entries continue to be extracted.
- **Fail-closed resource caps**: Exceeding `max_entries_walked`, `max_depth`, `max_file_size`, `max_total_bytes_hashed`, or `max_path_length` aborts immediately with a typed `WalkError::CapExceeded` and produces no partial result.
- **Deterministic, host-sanitized output**: Output paths are relative, UTF-8, and `/`-separated, sorted by path bytes with lexicographically sorted JSON object keys and no host paths, hostnames, or timestamps.

## Library Usage

use hermetic_extract_walk::{diff_trees, Caps, TaskClass};
use std::path::{Path, PathBuf};

let changeset = diff_trees(
    Path::new("/path/to/base"),
    Path::new("/path/to/work"),
    TaskClass::Patch {
        repo_dir: PathBuf::from("repo"),
    },
    &Caps::default(),
)?;
println!("{}", changeset.to_canonical_json()?);


## CLI Usage

hermetic-extract-walk [--patch <REPO_DIR> | --artifact <PATH>... | --state] <BASE_DIR> <WORK_DIR>


### Exit Codes

* `0`: Success with no refused entries.
* `1`: Error (invalid arguments, I/O failure, metadata mismatch, or resource cap exceeded).
* `2`: Success with one or more refused entries recorded in `ChangeSet.refused`.


