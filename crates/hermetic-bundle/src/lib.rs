#![forbid(unsafe_code)]

pub mod manifest;
pub mod walk;

pub use manifest::{
    compute_root, validate_relative_path, validate_root_digest, EntryKind, EntryMode, HashMismatch,
    KindMismatch, Manifest, ManifestEntry, ModeMismatch, RefusedKind, RefusedObject, Report,
    SizeMismatch, Verdict, FORMAT_VERSION, HASH_CHUNK_BYTES, MANIFEST_FILENAME,
    MAX_COMPONENT_BYTES, MAX_DEPTH, MAX_DIR_ITERATIONS, MAX_ENTRIES, MAX_JSON_NESTING_DEPTH,
    MAX_MANIFEST_BYTES, MAX_PATH_BYTES, MAX_TEMP_ATTEMPTS, MAX_TOTAL_FILE_BYTES,
};

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

/// Typed error returned by sealing, verification, and manifest validation operations.
///
/// Error values never contain host timestamps, host names, user names, environment
/// variables, or absolute host paths; any path included is bundle-relative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    InvalidRootDir {
        reason: &'static str,
    },
    NotADirectory {
        path: String,
    },
    RefusedObject {
        path: String,
        kind: RefusedKind,
    },
    InvalidPath {
        path: String,
        reason: &'static str,
    },
    CaseCollision {
        first: String,
        second: String,
    },
    LimitExceeded {
        limit: &'static str,
        max: u64,
    },
    ConcurrentModification {
        path: String,
    },
    ManifestMissing,
    ManifestInvalid {
        reason: String,
    },
    InvalidExpectedRoot,
    Io {
        path: String,
        kind: std::io::ErrorKind,
    },
    UnsupportedPlatform,
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::InvalidRootDir { reason } => {
                write!(f, "invalid bundle root directory: {reason}")
            }
            BundleError::NotADirectory { path } => {
                write!(f, "expected directory at bundle path: {path}")
            }
            BundleError::RefusedObject { path, kind } => {
                write!(f, "refused object at bundle path '{path}': {kind}")
            }
            BundleError::InvalidPath { path, reason } => {
                write!(f, "invalid bundle path '{path}': {reason}")
            }
            BundleError::CaseCollision { first, second } => {
                write!(
                    f,
                    "ASCII case collision between bundle paths '{first}' and '{second}'"
                )
            }
            BundleError::LimitExceeded { limit, max } => {
                write!(f, "bundle limit exceeded ({limit} max {max})")
            }
            BundleError::ConcurrentModification { path } => {
                write!(
                    f,
                    "concurrent filesystem modification detected at bundle path '{path}'"
                )
            }
            BundleError::ManifestMissing => {
                write!(f, "missing manifest file '{MANIFEST_FILENAME}'")
            }
            BundleError::ManifestInvalid { reason } => {
                write!(f, "invalid manifest: {reason}")
            }
            BundleError::InvalidExpectedRoot => {
                write!(
                    f,
                    "invalid expected root format (expected 'sha256:<64 lowercase hex>')"
                )
            }
            BundleError::Io { path, kind } => {
                write!(f, "I/O error at bundle path '{path}': {kind:?}")
            }
            BundleError::UnsupportedPlatform => {
                write!(f, "hermetic-bundle requires a Unix-like platform")
            }
        }
    }
}

impl Error for BundleError {}

/// Seals the directory tree at `dir`, writes `bundle.manifest.json` atomically,
/// and returns the resulting canonical `Manifest`.
pub fn seal(dir: impl AsRef<Path>) -> Result<Manifest, BundleError> {
    let root_dir = dir.as_ref();
    let entries = walk::walk_for_seal(root_dir)?;
    let root = compute_root(&entries)?;
    let manifest = Manifest {
        format: FORMAT_VERSION.to_string(),
        entries,
        root,
    };
    manifest.validate()?;
    let canonical_bytes = manifest.to_canonical_json_bytes()?;
    write_manifest_atomically(root_dir, &manifest.root, &canonical_bytes)?;
    Ok(manifest)
}

/// Verifies the directory tree at `dir` against `bundle.manifest.json` and an
/// optional expected root digest (`"sha256:<64 lowercase hex>"`).
///
/// Verification never modifies the directory tree.
pub fn verify(dir: impl AsRef<Path>, expected_root: Option<&str>) -> Result<Report, BundleError> {
    if let Some(expected) = expected_root {
        validate_root_digest(expected).map_err(|_| BundleError::InvalidExpectedRoot)?;
    }

    let root_dir = dir.as_ref();
    let manifest = read_and_validate_manifest(root_dir)?;
    let walk_outcome = walk::walk_for_verify(root_dir)?;
    let recomputed_root = compute_root(&walk_outcome.entries)?;

    let manifest_root_matches = recomputed_root == manifest.root;
    let expected_root_matches = expected_root.map(|exp| recomputed_root == exp);

    let mut manifest_map: BTreeMap<&str, &ManifestEntry> = BTreeMap::new();
    for entry in &manifest.entries {
        manifest_map.insert(entry.path.as_str(), entry);
    }

    let mut disk_map: BTreeMap<&str, &ManifestEntry> = BTreeMap::new();
    for entry in &walk_outcome.entries {
        disk_map.insert(entry.path.as_str(), entry);
    }

    let mut missing_entries = Vec::new();
    let mut extra_entries = Vec::new();
    let mut size_mismatches = Vec::new();
    let mut hash_mismatches = Vec::new();
    let mut mode_mismatches = Vec::new();
    let mut kind_mismatches = Vec::new();

    for (path, m_entry) in &manifest_map {
        match disk_map.get(path) {
            None => {
                missing_entries.push((*path).to_string());
            }
            Some(d_entry) => {
                if m_entry.kind != d_entry.kind {
                    kind_mismatches.push(KindMismatch {
                        path: (*path).to_string(),
                        expected: m_entry.kind,
                        actual: d_entry.kind,
                    });
                    continue;
                }

                if m_entry.mode != d_entry.mode {
                    mode_mismatches.push(ModeMismatch {
                        path: (*path).to_string(),
                        expected: m_entry.mode,
                        actual: d_entry.mode,
                    });
                }

                if m_entry.kind == EntryKind::File {
                    if let (Some(exp_size), Some(act_size)) = (m_entry.size, d_entry.size) {
                        if exp_size != act_size {
                            size_mismatches.push(SizeMismatch {
                                path: (*path).to_string(),
                                expected: exp_size,
                                actual: act_size,
                            });
                        }
                    }
                    if let (Some(exp_sha), Some(act_sha)) =
                        (m_entry.sha256.as_ref(), d_entry.sha256.as_ref())
                    {
                        if exp_sha != act_sha {
                            hash_mismatches.push(HashMismatch {
                                path: (*path).to_string(),
                                expected: exp_sha.clone(),
                                actual: act_sha.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    for path in disk_map.keys() {
        if !manifest_map.contains_key(path) {
            extra_entries.push((*path).to_string());
        }
    }

    missing_entries.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    extra_entries.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    size_mismatches.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    hash_mismatches.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    mode_mismatches.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    kind_mismatches.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    let mut refused_objects = walk_outcome.refused_objects;
    refused_objects.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then_with(|| a.kind.cmp(&b.kind))
    });

    let all_clean = manifest_root_matches
        && expected_root_matches != Some(false)
        && missing_entries.is_empty()
        && extra_entries.is_empty()
        && size_mismatches.is_empty()
        && hash_mismatches.is_empty()
        && mode_mismatches.is_empty()
        && kind_mismatches.is_empty()
        && refused_objects.is_empty();

    let verdict = if all_clean {
        Verdict::Ok
    } else {
        Verdict::Mismatch
    };

    Ok(Report {
        verdict,
        manifest_root: manifest.root,
        recomputed_root,
        manifest_root_matches,
        expected_root: expected_root.map(str::to_string),
        expected_root_matches,
        missing_entries,
        extra_entries,
        size_mismatches,
        hash_mismatches,
        mode_mismatches,
        kind_mismatches,
        refused_objects,
    })
}

#[cfg(unix)]
fn read_and_validate_manifest(root_dir: &Path) -> Result<Manifest, BundleError> {
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

    let manifest_path = root_dir.join(MANIFEST_FILENAME);
    let sym_meta = match fs::symlink_metadata(&manifest_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(BundleError::ManifestMissing);
        }
        Err(e) => {
            return Err(BundleError::Io {
                path: MANIFEST_FILENAME.to_string(),
                kind: e.kind(),
            });
        }
    };

    let ft = sym_meta.file_type();
    if ft.is_symlink() {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind: RefusedKind::Symlink,
        });
    }
    if ft.is_fifo() {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind: RefusedKind::Fifo,
        });
    }
    if ft.is_socket() {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind: RefusedKind::Socket,
        });
    }
    if ft.is_block_device() {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind: RefusedKind::BlockDevice,
        });
    }
    if ft.is_char_device() {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind: RefusedKind::CharDevice,
        });
    }
    if !ft.is_file() {
        return Err(BundleError::ManifestInvalid {
            reason: "manifest is not a regular file".to_string(),
        });
    }
    if sym_meta.nlink() > 1 {
        return Err(BundleError::RefusedObject {
            path: MANIFEST_FILENAME.to_string(),
            kind: RefusedKind::HardLink,
        });
    }

    let declared_len = sym_meta.len();
    if declared_len > MAX_MANIFEST_BYTES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_MANIFEST_BYTES",
            max: MAX_MANIFEST_BYTES,
        });
    }

    let file = File::open(&manifest_path).map_err(|e| BundleError::Io {
        path: MANIFEST_FILENAME.to_string(),
        kind: e.kind(),
    })?;
    let opened_meta = file.metadata().map_err(|e| BundleError::Io {
        path: MANIFEST_FILENAME.to_string(),
        kind: e.kind(),
    })?;

    if opened_meta.dev() != sym_meta.dev()
        || opened_meta.ino() != sym_meta.ino()
        || !opened_meta.file_type().is_file()
        || opened_meta.nlink() > 1
    {
        return Err(BundleError::ConcurrentModification {
            path: MANIFEST_FILENAME.to_string(),
        });
    }

    let initial_cap = usize::try_from(declared_len)
        .unwrap_or(0)
        .min(HASH_CHUNK_BYTES);
    let mut buf = Vec::with_capacity(initial_cap);
    let read_limit = MAX_MANIFEST_BYTES
        .checked_add(1)
        .ok_or(BundleError::LimitExceeded {
            limit: "MAX_MANIFEST_BYTES",
            max: MAX_MANIFEST_BYTES,
        })?;
    let bytes_read = file
        .take(read_limit)
        .read_to_end(&mut buf)
        .map_err(|e| BundleError::Io {
            path: MANIFEST_FILENAME.to_string(),
            kind: e.kind(),
        })?;

    if (bytes_read as u64) > MAX_MANIFEST_BYTES {
        return Err(BundleError::LimitExceeded {
            limit: "MAX_MANIFEST_BYTES",
            max: MAX_MANIFEST_BYTES,
        });
    }

    Manifest::from_json_bytes(&buf)
}

#[cfg(not(unix))]
fn read_and_validate_manifest(_root_dir: &Path) -> Result<Manifest, BundleError> {
    Err(BundleError::UnsupportedPlatform)
}

#[cfg(unix)]
fn write_manifest_atomically(
    root_dir: &Path,
    root_digest: &str,
    canonical_bytes: &[u8],
) -> Result<(), BundleError> {
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

    let tag: String = root_digest
        .strip_prefix("sha256:")
        .unwrap_or("00000000")
        .chars()
        .take(12)
        .collect();

    let mut attempt: u32 = 0;
    let (mut temp_file, temp_name, temp_path) = loop {
        if attempt >= MAX_TEMP_ATTEMPTS {
            return Err(BundleError::Io {
                path: MANIFEST_FILENAME.to_string(),
                kind: std::io::ErrorKind::AlreadyExists,
            });
        }
        let candidate_name = format!(".{MANIFEST_FILENAME}.tmp.{tag}.{attempt}");
        let candidate_path = root_dir.join(&candidate_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate_path)
        {
            Ok(f) => break (f, candidate_name, candidate_path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.saturating_add(1);
            }
            Err(e) => {
                return Err(BundleError::Io {
                    path: candidate_name,
                    kind: e.kind(),
                });
            }
        }
    };

    let write_res: Result<(), BundleError> = (|| {
        temp_file
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|e| BundleError::Io {
                path: temp_name.clone(),
                kind: e.kind(),
            })?;
        temp_file
            .write_all(canonical_bytes)
            .map_err(|e| BundleError::Io {
                path: temp_name.clone(),
                kind: e.kind(),
            })?;
        temp_file.sync_all().map_err(|e| BundleError::Io {
            path: temp_name.clone(),
            kind: e.kind(),
        })?;
        Ok(())
    })();

    drop(temp_file);

    if let Err(e) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    let final_path = root_dir.join(MANIFEST_FILENAME);
    if let Err(e) = fs::rename(&temp_path, &final_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(BundleError::Io {
            path: MANIFEST_FILENAME.to_string(),
            kind: e.kind(),
        });
    }

    if let Ok(dir_handle) = File::open(root_dir) {
        if let Ok(dir_meta) = dir_handle.metadata() {
            if dir_meta.dev() == root_meta.dev() && dir_meta.ino() == root_meta.ino() {
                let _ = dir_handle.sync_all();
            }
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn write_manifest_atomically(
    _root_dir: &Path,
    _root_digest: &str,
    _canonical_bytes: &[u8],
) -> Result<(), BundleError> {
    Err(BundleError::UnsupportedPlatform)
}
