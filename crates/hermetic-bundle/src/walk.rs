use crate::manifest::{
    encode_lower_hex, validate_relative_path, EntryKind, EntryMode, ManifestEntry, RefusedKind,
    RefusedObject, HASH_CHUNK_BYTES, MANIFEST_FILENAME, MAX_DEPTH, MAX_DIR_ITERATIONS, MAX_ENTRIES,
    MAX_TOTAL_FILE_BYTES,
};
use crate::BundleError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;

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

enum PendingDirectory {
    Root(Arc<File>),
    Child {
        parent: Arc<File>,
        name: OsString,
        meta: fs::Metadata,
    },
}

struct DirFrame {
    directory: PendingDirectory,
    rel_path: String,
    depth: usize,
}

pub(crate) fn walk_for_seal(root_dir: &File) -> Result<Vec<ManifestEntry>, BundleError> {
    let outcome = walk_tree(root_dir, WalkPolicy::StrictSeal)?;
    Ok(outcome.entries)
}

pub(crate) fn walk_for_verify(root_dir: &File) -> Result<VerifyWalkOutcome, BundleError> {
    walk_tree(root_dir, WalkPolicy::CollectVerify)
}

/// Enumerates directories through pinned descriptors. Child lookups contain only
/// one validated component, so renaming an ancestor cannot redirect a lookup.
#[cfg(unix)]
fn walk_tree(root_dir: &File, policy: WalkPolicy) -> Result<VerifyWalkOutcome, BundleError> {
    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut refused_objects: Vec<RefusedObject> = Vec::new();
    let mut seen_lower: BTreeMap<String, String> = BTreeMap::new();
    let mut total_file_bytes: u64 = 0;
    let mut total_dir_items: usize = 0;
    let mut stack_pushes: usize = 0;

    let mut stack: Vec<DirFrame> = Vec::new();
    stack.push(DirFrame {
        directory: PendingDirectory::Root(Arc::new(
            root_dir.try_clone().map_err(|e| io_error(".", e))?,
        )),
        rel_path: String::new(),
        depth: 0,
    });

    while let Some(frame) = stack.pop() {
        if frame.depth > MAX_DEPTH {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_DEPTH",
                max: MAX_DEPTH as u64,
            });
        }
        let display_dir = if frame.rel_path.is_empty() {
            "."
        } else {
            &frame.rel_path
        };
        // Pending siblings share their parent's handle. Only the active ancestor
        // chain holds distinct handles, bounded by MAX_DEPTH plus the root.
        let handle = match frame.directory {
            PendingDirectory::Root(handle) => handle,
            PendingDirectory::Child { parent, name, meta } => Arc::new(open_directory(
                &child_path(&parent, &name),
                &meta,
                display_dir,
            )?),
        };
        let read_dir = fs::read_dir(handle_path(&handle)).map_err(|e| io_error(display_dir, e))?;

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
                path: display_dir.to_string(),
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
                // The manifest is excluded from the digest, but is still an
                // object in the tree and must satisfy the regular-file rules.
                let path = child_path(&handle, child_os.as_os_str());
                let meta =
                    fs::symlink_metadata(&path).map_err(|e| io_error(MANIFEST_FILENAME, e))?;
                validate_manifest_object(&meta)?;
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

            let child_host = child_path(&handle, child_os.as_os_str());
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
                    directory: PendingDirectory::Child {
                        parent: Arc::clone(&handle),
                        name: child_os.clone(),
                        meta: child_meta,
                    },
                    rel_path: child_rel,
                    depth: next_depth,
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
fn walk_tree(_root_dir: &File, _policy: WalkPolicy) -> Result<VerifyWalkOutcome, BundleError> {
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

    let mut file = open_regular_file(host_path, sym_meta, rel_path)?;
    let opened_meta = file.metadata().map_err(|e| io_error(rel_path, e))?;

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

    let final_meta = file.metadata().map_err(|e| io_error(rel_path, e))?;
    let path_meta = fs::symlink_metadata(host_path).map_err(|e| io_error(rel_path, e))?;
    if !same_file_state(&opened_meta, &final_meta)
        || !same_file_state(&final_meta, &path_meta)
        || actual_size != final_meta.len()
    {
        return Err(BundleError::ConcurrentModification {
            path: rel_path.to_string(),
        });
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

// Linux x86_64 is the project host platform (TRD section 1). Do not silently
// reuse these flag values on another ABI.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("hermetic-bundle descriptor operations require Linux x86_64");
const O_NOFOLLOW: i32 = 0o400000;
const O_DIRECTORY: i32 = 0o200000;
const O_PATH: i32 = 0o10000000;
const O_NONBLOCK: i32 = 0o4000;
const MAX_ROOT_PATH_BYTES: usize = 8192;
const MAX_ROOT_COMPONENTS: usize = 4096;

pub(crate) fn io_error(rel: &str, e: std::io::Error) -> BundleError {
    BundleError::Io {
        path: rel.to_string(),
        kind: e.kind(),
    }
}

pub(crate) fn handle_path(handle: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()))
}

fn child_path(handle: &File, name: &std::ffi::OsStr) -> PathBuf {
    handle_path(handle).join(name)
}

pub(crate) fn open_root(path: &Path) -> Result<File, BundleError> {
    if path.as_os_str().len() > MAX_ROOT_PATH_BYTES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_ROOT_PATH_BYTES",
            max: MAX_ROOT_PATH_BYTES as u64,
        });
    }
    if path.as_os_str().is_empty() {
        return Err(BundleError::InvalidRootDir {
            reason: "empty root path",
        });
    }
    let mut count = 0usize;
    for _ in path.components() {
        count = count.saturating_add(1);
        if count > MAX_ROOT_COMPONENTS {
            return Err(BundleError::LimitExceeded {
                limit: "MAX_ROOT_COMPONENTS",
                max: MAX_ROOT_COMPONENTS as u64,
            });
        }
    }
    let base = Path::new(if path.is_absolute() { "/" } else { "." });
    let meta = fs::symlink_metadata(base).map_err(|_| BundleError::InvalidRootDir {
        reason: "cannot stat bundle root",
    })?;
    let mut handle = pin_directory(base, &meta, ".", true)?;
    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::RootDir | Component::CurDir => continue,
            Component::Prefix(_) => {
                return Err(BundleError::InvalidRootDir {
                    reason: "unsupported root prefix",
                })
            }
        };
        let child = child_path(&handle, name);
        let meta = fs::symlink_metadata(&child).map_err(|_| BundleError::InvalidRootDir {
            reason: "cannot stat bundle root",
        })?;
        handle = pin_directory(&child, &meta, ".", true)?;
    }
    // Reopen the pinned root through trusted procfs for enumeration and sync.
    File::open(handle_path(&handle)).map_err(|e| io_error(".", e))
}

fn open_directory(path: &Path, meta: &fs::Metadata, rel: &str) -> Result<File, BundleError> {
    pin_directory(path, meta, rel, false)
}

fn pin_directory(
    path: &Path,
    meta: &fs::Metadata,
    rel: &str,
    path_only: bool,
) -> Result<File, BundleError> {
    if meta.is_symlink() {
        return Err(BundleError::RefusedObject {
            path: rel.to_string(),
            kind: RefusedKind::Symlink,
        });
    }
    if !meta.is_dir() {
        return Err(BundleError::NotADirectory {
            path: rel.to_string(),
        });
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(
            O_DIRECTORY
                | O_NONBLOCK
                | if path_only {
                    O_PATH | O_NOFOLLOW
                } else {
                    O_NOFOLLOW
                },
        )
        .open(path)
        .map_err(|e| io_error(rel, e))?;
    let opened = handle.metadata().map_err(|e| io_error(rel, e))?;
    if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
        return Err(BundleError::ConcurrentModification {
            path: rel.to_string(),
        });
    }
    Ok(handle)
}

pub(crate) fn validate_manifest_object(meta: &fs::Metadata) -> Result<(), BundleError> {
    let ft = meta.file_type();
    let kind = if ft.is_symlink() {
        Some(RefusedKind::Symlink)
    } else if ft.is_fifo() {
        Some(RefusedKind::Fifo)
    } else if ft.is_socket() {
        Some(RefusedKind::Socket)
    } else if ft.is_block_device() {
        Some(RefusedKind::BlockDevice)
    } else if ft.is_char_device() {
        Some(RefusedKind::CharDevice)
    } else if ft.is_file() && meta.nlink() > 1 {
        Some(RefusedKind::HardLink)
    } else if !ft.is_file() {
        Some(RefusedKind::SpecialFile)
    } else {
        None
    };
    if let Some(kind) = kind {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind,
        });
    }
    Ok(())
}

pub(crate) fn open_regular_file(
    path: &Path,
    meta: &fs::Metadata,
    rel: &str,
) -> Result<File, BundleError> {
    // O_PATH pins the object without opening a device or waiting on a FIFO.
    // O_NOFOLLOW pins a substituted symlink itself; fstat rejects it below.
    let pinned = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW)
        .open(path)
        .map_err(|e| io_error(rel, e))?;
    let pinned_meta = pinned.metadata().map_err(|e| io_error(rel, e))?;
    if !pinned_meta.is_file() || pinned_meta.nlink() > 1 || !same_file_state(meta, &pinned_meta) {
        return Err(BundleError::ConcurrentModification {
            path: rel.to_string(),
        });
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(handle_path(&pinned))
        .map_err(|e| io_error(rel, e))?;
    let opened = file.metadata().map_err(|e| io_error(rel, e))?;
    if !same_file_state(&pinned_meta, &opened) {
        return Err(BundleError::ConcurrentModification {
            path: rel.to_string(),
        });
    }
    Ok(file)
}

fn same_file_state(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn file_swapped_to_symlink_is_refused_even_with_the_same_target_inode() {
        let tree = TempDir::new().unwrap();
        let file = tree.path().join("file");
        fs::write(&file, b"data").unwrap();
        let meta = fs::symlink_metadata(&file).unwrap();
        fs::rename(&file, tree.path().join("saved")).unwrap();
        symlink("saved", &file).unwrap();
        assert!(matches!(
            hash_regular_file(&file, "file", &meta, &mut 0),
            Err(BundleError::ConcurrentModification { .. })
        ));
    }

    #[test]
    fn file_swapped_to_fifo_does_not_block() {
        let tree = TempDir::new().unwrap();
        let file = tree.path().join("file");
        fs::write(&file, b"data").unwrap();
        let meta = fs::symlink_metadata(&file).unwrap();
        fs::remove_file(&file).unwrap();
        match Command::new("mkfifo").arg(&file).status() {
            Ok(status) if status.success() => {
                let (send, receive) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result = hash_regular_file(&file, "file", &meta, &mut 0);
                    let _ = send.send(result);
                });
                const MAX_FIFO_TEST_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
                assert!(matches!(
                    receive
                        .recv_timeout(MAX_FIFO_TEST_WAIT)
                        .expect("opening a substituted FIFO blocked"),
                    Err(BundleError::ConcurrentModification { .. })
                ));
            }
            _ => eprintln!("skipping swapped-FIFO fixture: mkfifo unavailable"),
        }
    }

    #[test]
    fn file_changed_since_lstat_is_refused() {
        let tree = TempDir::new().unwrap();
        let file = tree.path().join("file");
        fs::write(&file, b"first").unwrap();
        let meta = fs::symlink_metadata(&file).unwrap();
        fs::write(&file, b"second").unwrap();
        assert!(matches!(
            hash_regular_file(&file, "file", &meta, &mut 0),
            Err(BundleError::ConcurrentModification { .. })
        ));
    }
}
