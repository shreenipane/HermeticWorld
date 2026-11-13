#![forbid(unsafe_code)]

//! Bounded, symlink-safe tree diff extractor for Hermetic World evaluations.
//!
//! # Security Guarantees
//! - **Never follows symlinks**: every entry is inspected via `symlink_metadata`, and every
//!   opened regular file has its `(dev, ino)` verified against `symlink_metadata` before reading.
//! - **Never reads `.git`**: any directory or file named `.git` at any depth in either tree is
//!   completely skipped—never descended into, never opened, and never reported.
//! - **Fail-closed resource caps**: entry count, depth, single-file size, cumulative hashed bytes,
//!   and relative path byte length are bounded by [`Caps`] and named `const` limits.
//! - **Deterministic, host-sanitized output**: results are sorted by UTF-8 path bytes using
//!   [`std::collections::BTreeMap`], containing no host paths, hostnames, or timestamps.

pub mod walk;

pub use walk::{
    diff_trees, CapKind, Caps, Change, ChangeKind, ChangeSet, EntryKind, RefusedEntry, RefusedKind,
    TaskClass, WalkError, DEFAULT_MAX_DEPTH, DEFAULT_MAX_ENTRIES_WALKED, DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_PATH_LENGTH, DEFAULT_MAX_TOTAL_BYTES_HASHED, HASH_CHUNK_SIZE,
};
