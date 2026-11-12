use crate::manifest::{
    encode_lower_hex, validate_relative_path, EntryKind, EntryMode, ManifestEntry, RefusedKind,
    RefusedObject, HASH_CHUNK_BYTES, MANIFEST_FILENAME, MAX_DEPTH, MAX_DIR_ITERATIONS, MAX_ENTRIES,
    MAX_TOTAL_FILE_BYTES,
};
use crate::BundleError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const MAX_CHUNKS_PER_FILE: u64 = (MAX_TOTAL_FILE_BYTES / (HASH_CHUNK_BYTES as u64)) + 2;

pub(crate) struct VerifyWalkOutcome {
    pub entries: Vec<ManifestEntry>,
    pub refused_objects: Vec<RefusedObject>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum WalkPolicy {
    StrictSeal,
    CollectVerify,
}

struct DirFrame {
    host_path: PathBuf,
    rel_path: String,
    depth: usize,
    expected_dev: u64,
    expected_ino: u64,
}

pub(crate) fn walk_for_seal(root_dir: &Path) -> Result<Vec<ManifestEntry>, BundleError> {
    let outcome = walk_tree(root_dir, WalkPolicy::StrictSeal)?;
    Ok(outcome.entries)
}

pub(crate) fn walk_for_verify(root_dir: &Path) -> Result<VerifyWalkOutcome, BundleError> {
    walk_tree(root_dir, WalkPolicy::CollectVerify)
}

/// Walks `root_dir` without following symlinks and without unbounded recursion.
///
/// Directory race mitigation:
/// Before calling `std::fs::read_dir` on a directory path, we record `(dev, ino)`
/// via `symlink_metadata` (lstat) and verify it is a real directory. Immediately
/// after `std::fs::read_dir` opens the directory stream, we re-check `(dev, ino)`
/// via `symlink_metadata` on the same path to detect a directory-to-symlink swap.
/// Because `std::fs::read_dir` does not expose `O_NOFOLLOW | O_DIRECTORY` or `fstat`
/// on the underlying `DIR*` descriptor without `libc`/`unsafe`, a narrow TOCTOU
/// window remains if a privileged adversary swaps a directory to a symlink and
/// swaps it back around `read_dir`. Every child entry is independently checked via
/// `symlink_metadata`, and every regular file is verified via `fstat` `(dev, ino)`
/// after `File::open`.
#[cfg(unix)]
fn walk_tree(root_dir: &Path, policy: WalkPolicy) -> Result<VerifyWalkOutcome, BundleError> {
    let root_meta = fs::symlink_metadata(root_dir).map_err(|_| BundleError::InvalidRootDir {
        reason: "cannot stat bundle root",
    })?;
    if root_meta.file_type().is_symlink() {
        return Err(BundleError::RefusedObject {
            path: ".".to_string(),
            kind: RefusedKind::Symlink,
        });
    }
    if !root_meta.file_type().is_dir() {
        return Err(BundleError::NotADirectory {
            path: ".".to_string(),
        });
    }

    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut refused_objects: Vec<RefusedObject> = Vec::new();
    let mut seen_lower: BTreeMap<String, String> = BTreeMap::new();
    let mut total_file_bytes: u64 = 0;
    let mut total_dir_items: usize = 0;
    let mut stack_pushes: usize = 0;

    let mut stack: Vec<DirFrame> = Vec::new();
    stack.push(DirFrame {
        host_path: root_dir.to_path_buf(),
        rel_path: String::new(),
        depth: 0,
        expected_dev: root_meta.dev(),
        expected_ino: root_meta.ino(),
    });

    while let Some(frame) = stack.pop() {
        if frame.depth > MAX_DEPTH {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_DEPTH",
                max: MAX_DEPTH as u64,
            });
        }

        let display_dir = if frame.rel_path.is_empty() {
            ".".to_string()
        } else {
            frame.rel_path.clone()
        };

        let pre_meta = fs::symlink_metadata(&frame.host_path).map_err(|_| {
            BundleError::ConcurrentModification {
                path: display_dir.clone(),
            }
        })?;
        if pre_meta.file_type().is_symlink()
            || !pre_meta.file_type().is_dir()
            || pre_meta.dev() != frame.expected_dev
            || pre_meta.ino() != frame.expected_ino
        {
            return Err(BundleError::ConcurrentModification { path: display_dir });
        }

        let read_dir = fs::read_dir(&frame.host_path).map_err(|e| BundleError::Io {
            path: display_dir.clone(),
            kind: e.kind(),
        })?;

        let post_meta = fs::symlink_metadata(&frame.host_path).map_err(|_| {
            BundleError::ConcurrentModification {
                path: display_dir.clone(),
            }
        })?;
        if post_meta.file_type().is_symlink()
            || !post_meta.file_type().is_dir()
            || post_meta.dev() != frame.expected_dev
            || post_meta.ino() != frame.expected_ino
        {
            return Err(BundleError::ConcurrentModification { path: display_dir });
        }

        let mut child_names: Vec<OsString> = Vec::new();
        for dir_entry_res in read_dir {
            total_dir_items = total_dir_items
                .checked_add(1)
                .ok_or(BundleError::LimitExceeded {
                    limit: "MAX_DIR_ITERATIONS",
                    max: MAX_DIR_ITERATIONS as u64,
                })?;
            if total_dir_items > MAX_DIR_ITERATIONS {
                return Err(BundleError::LimitExceeded {
                    limit: "MAX_DIR_ITERATIONS",
                    max: MAX_DIR_ITERATIONS as u64,
                });
            }

            let dir_entry = dir_entry_res.map_err(|e| BundleError::Io {
                path: display_dir.clone(),
                kind: e.kind(),
            })?;
            child_names.push(dir_entry.file_name());
        }

        child_names.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));

        for child_os in child_names {
            let child_name = match child_os.to_str() {
                Some(s) => s,
                None => {
                    let lossy_name = child_os.to_string_lossy();
                    let lossy_rel = join_rel_path(&frame.rel_path, &lossy_name);
                    match policy {
                        WalkPolicy::StrictSeal => {
                            return Err(BundleError::InvalidPath {
                                path: lossy_rel,
                                reason: "non-UTF-8 path",
                            });
                        }
                        WalkPolicy::CollectVerify => {
                            refused_objects.push(RefusedObject {
                                path: lossy_rel,
                                kind: RefusedKind::InvalidPath,
                            });
                            continue;
                        }
                    }
                }
            };

            if frame.depth == 0 && child_name == MANIFEST_FILENAME {
                continue;
            }

            let child_rel = join_rel_path(&frame.rel_path, child_name);

            if let Err(path_err) = validate_relative_path(&child_rel) {
                match (policy, &path_err) {
                    (WalkPolicy::CollectVerify, BundleError::InvalidPath { .. }) => {
                        refused_objects.push(RefusedObject {
                            path: child_rel,
                            kind: RefusedKind::InvalidPath,
                        });
                        continue;
                    }
                    _ => return Err(path_err),
                }
            }

            let child_lower = child_rel.to_ascii_lowercase();
            if let Some(existing) = seen_lower.get(&child_lower) {
                match policy {
                    WalkPolicy::StrictSeal => {
                        return Err(BundleError::CaseCollision {
                            first: existing.clone(),
                            second: child_rel,
                        });
                    }
                    WalkPolicy::CollectVerify => {
                        refused_objects.push(RefusedObject {
                            path: child_rel,
                            kind: RefusedKind::CaseCollision,
                        });
                        continue;
                    }
                }
            }
            seen_lower.insert(child_lower, child_rel.clone());

            let child_host = frame.host_path.join(child_name);
            let child_meta = fs::symlink_metadata(&child_host).map_err(|e| BundleError::Io {
                path: child_rel.clone(),
                kind: e.kind(),
            })?;

            let ft = child_meta.file_type();
            let refused_kind = if ft.is_symlink() {
                Some(RefusedKind::Symlink)
            } else if ft.is_fifo() {
                Some(RefusedKind::Fifo)
            } else if ft.is_socket() {
                Some(RefusedKind::Socket)
            } else if ft.is_block_device() {
                Some(RefusedKind::BlockDevice)
            } else if ft.is_char_device() {
                Some(RefusedKind::CharDevice)
            } else if !ft.is_file() && !ft.is_dir() {
                Some(RefusedKind::SpecialFile)
            } else {
                None
            };

            if let Some(kind) = refused_kind {
                match policy {
                    WalkPolicy::StrictSeal => {
                        return Err(BundleError::RefusedObject {
                            path: child_rel,
                            kind,
                        });
                    }
                    WalkPolicy::CollectVerify => {
                        refused_objects.push(RefusedObject {
                            path: child_rel,
                            kind,
                        });
                        continue;
                    }
                }
            }

            if ft.is_dir() {
                if entries.len() >= MAX_ENTRIES {
                    return Err(BundleError::LimitExceeded {
                        limit: "MAX_ENTRIES",
                        max: MAX_ENTRIES as u64,
                    });
                }
                entries.push(ManifestEntry {
                    path: child_rel.clone(),
                    kind: EntryKind::Dir,
                    mode: EntryMode::Mode0755,
                    size: None,
                    sha256: None,
                });

                let next_depth = frame
                    .depth
                    .checked_add(1)
                    .ok_or(BundleError::LimitExceeded {
                        limit: "MAX_DEPTH",
                        max: MAX_DEPTH as u64,
                    })?;
                stack_pushes = stack_pushes
                    .checked_add(1)
                    .ok_or(BundleError::LimitExceeded {
                        limit: "MAX_ENTRIES",
                        max: MAX_ENTRIES as u64,
                    })?;
                if stack_pushes > MAX_ENTRIES {
                    return Err(BundleError::LimitExceeded {
                        limit: "MAX_ENTRIES",
                        max: MAX_ENTRIES as u64,
                    });
                }

                stack.push(DirFrame {
                    host_path: child_host,
                    rel_path: child_rel,
                    depth: next_depth,
                    expected_dev: child_meta.dev(),
                    expected_ino: child_meta.ino(),
                });
            } else if ft.is_file() {
                if child_meta.nlink() > 1 {
                    match policy {
                        WalkPolicy::StrictSeal => {
                            return Err(BundleError::RefusedObject {
                                path: child_rel,
                                kind: RefusedKind::HardLink,
                            });
                        }
                        WalkPolicy::CollectVerify => {
                            refused_objects.push(RefusedObject {
                                path: child_rel,
                                kind: RefusedKind::HardLink,
                            });
                            continue;
                        }
                    }
                }

                if entries.len() >= MAX_ENTRIES {
                    return Err(BundleError::LimitExceeded {
                        limit: "MAX_ENTRIES",
                        max: MAX_ENTRIES as u64,
                    });
                }

                let file_entry =
                    hash_regular_file(&child_host, &child_rel, &child_meta, &mut total_file_bytes)?;
                entries.push(file_entry);
            }
        }
    }

    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    refused_objects.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then_with(|| a.kind.cmp(&b.kind))
    });

    Ok(VerifyWalkOutcome {
        entries,
        refused_objects,
    })
}

#[cfg(not(unix))]
fn walk_tree(_root_dir: &Path, _policy: WalkPolicy) -> Result<VerifyWalkOutcome, BundleError> {
    Err(BundleError::UnsupportedPlatform)
}

#[cfg(unix)]
fn hash_regular_file(
    host_path: &Path,
    rel_path: &str,
    sym_meta: &fs::Metadata,
    total_file_bytes: &mut u64,
) -> Result<ManifestEntry, BundleError> {
    let declared_size = sym_meta.len();
    let projected_total =
        total_file_bytes
            .checked_add(declared_size)
            .ok_or(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            })?;
    if projected_total > MAX_TOTAL_FILE_BYTES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_TOTAL_FILE_BYTES",
            max: MAX_TOTAL_FILE_BYTES,
        });
    }

    let mut file = File::open(host_path).map_err(|e| BundleError::Io {
        path: rel_path.to_string(),
        kind: e.kind(),
    })?;
    let opened_meta = file.metadata().map_err(|e| BundleError::Io {
        path: rel_path.to_string(),
        kind: e.kind(),
    })?;

    if opened_meta.dev() != sym_meta.dev()
        || opened_meta.ino() != sym_meta.ino()
        || !opened_meta.file_type().is_file()
        || opened_meta.nlink() > 1
    {
        return Err(BundleError::ConcurrentModification {
            path: rel_path.to_string(),
        });
    }

    let mode = if (opened_meta.mode() & 0o111) != 0 {
        EntryMode::Mode0755
    } else {
        EntryMode::Mode0644
    };

    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; HASH_CHUNK_BYTES];
    let mut actual_size: u64 = 0;
    let mut chunks_read: u64 = 0;

    loop {
        chunks_read = chunks_read
            .checked_add(1)
            .ok_or(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            })?;
        if chunks_read > MAX_CHUNKS_PER_FILE {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            });
        }

        let n = match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(BundleError::Io {
                    path: rel_path.to_string(),
                    kind: e.kind(),
                });
            }
        };

        let n_u64 = u64::try_from(n).map_err(|_| BundleError::LimitExceeded {
            limit: "MAX_TOTAL_FILE_BYTES",
            max: MAX_TOTAL_FILE_BYTES,
        })?;
        actual_size = actual_size
            .checked_add(n_u64)
            .ok_or(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            })?;
        *total_file_bytes =
            total_file_bytes
                .checked_add(n_u64)
                .ok_or(BundleError::LimitExceeded {
                    limit: "MAX_TOTAL_FILE_BYTES",
                    max: MAX_TOTAL_FILE_BYTES,
                })?;
        if *total_file_bytes > MAX_TOTAL_FILE_BYTES {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_TOTAL_FILE_BYTES",
                max: MAX_TOTAL_FILE_BYTES,
            });
        }

        if let Some(slice) = chunk.get(..n) {
            hasher.update(slice);
        }
    }

    let digest = hasher.finalize();
    let sha256 = encode_lower_hex(&digest);

    Ok(ManifestEntry {
        path: rel_path.to_string(),
        kind: EntryKind::File,
        mode,
        size: Some(actual_size),
        sha256: Some(sha256),
    })
}

fn join_rel_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}
