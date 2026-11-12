#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::error::TrustError;
use crate::jks::{inject_ca_into_jks, is_pkcs12};

/// Skipped path entry in report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPath {
    pub path: String,
    pub reason: String,
}

/// Installation report schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub ca_cert_sha256: String,
    pub modified_paths: Vec<String>,
    pub skipped_paths: Vec<SkippedPath>,
    pub env_defaults: BTreeMap<String, String>,
}

/// Safely join relative path components to rootfs, guaranteeing no escape outside rootfs.
/// Any ".." components at the rootfs boundary remain at the boundary (like a Unix chroot).
pub fn safe_join_rootfs(rootfs: &Path, rel: &Path) -> PathBuf {
    let mut stack = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => stack.push(c),
            Component::ParentDir => {
                stack.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    let mut out = rootfs.to_path_buf();
    for comp in stack {
        out.push(comp);
    }
    out
}

/// Safely join relative path components from a specific directory within rootfs.
pub fn safe_join_rootfs_from(rootfs: &Path, base_dir: &Path, target: &Path) -> PathBuf {
    let rel_base = match base_dir.strip_prefix(rootfs) {
        Ok(r) => r,
        Err(_) => Path::new(""),
    };
    let combined = rel_base.join(target);
    safe_join_rootfs(rootfs, &combined)
}

/// Resolves symlinks strictly within the rootfs as if rootfs were `/`.
/// Absolute symlink targets are interpreted relative to rootfs.
/// Detects symlink loops and limits hop depth to 40.
pub fn resolve_in_rootfs(rootfs: &Path, path: &Path) -> Result<PathBuf, TrustError> {
    use std::collections::VecDeque;

    let rootfs_canon = rootfs
        .canonicalize()
        .unwrap_or_else(|_| rootfs.to_path_buf());

    let rel = if let Ok(r) = path.strip_prefix(rootfs) {
        r.to_path_buf()
    } else if let Ok(r) = path.strip_prefix(&rootfs_canon) {
        r.to_path_buf()
    } else if path.is_absolute() {
        path.strip_prefix("/").unwrap_or(path).to_path_buf()
    } else {
        path.to_path_buf()
    };

    let mut queue = VecDeque::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => queue.push_back(PathBuf::from(c)),
            Component::ParentDir => queue.push_back(PathBuf::from("..")),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }

    let mut current = rootfs.to_path_buf();
    let mut hops = 0;
    const MAX_HOPS: usize = 40;

    while let Some(comp) = queue.pop_front() {
        if comp == Path::new("..") {
            let at_root = current == rootfs
                || current == rootfs_canon
                || match current.strip_prefix(rootfs) {
                    Ok(p) => p.as_os_str().is_empty(),
                    Err(_) => match current.strip_prefix(&rootfs_canon) {
                        Ok(p) => p.as_os_str().is_empty(),
                        Err(_) => false,
                    },
                };
            if !at_root {
                current.pop();
            }
            continue;
        }

        let candidate = current.join(&comp);
        let meta = match fs::symlink_metadata(&candidate) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                current = candidate;
                continue;
            }
            Err(e) => {
                return Err(TrustError::Symlink(format!(
                    "metadata {}: {}",
                    candidate.display(),
                    e
                )));
            }
        };

        if meta.is_symlink() {
            hops += 1;
            if hops > MAX_HOPS {
                return Err(TrustError::Symlink("symlink loop detected".to_string()));
            }

            let target = fs::read_link(&candidate).map_err(|e| {
                TrustError::Symlink(format!("read_link {}: {}", candidate.display(), e))
            })?;

            if target.is_absolute() {
                current = rootfs.to_path_buf();
                let rel_target = target.strip_prefix("/").unwrap_or(&target);
                let target_comps: Vec<PathBuf> = rel_target
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(n) => Some(PathBuf::from(n)),
                        Component::ParentDir => Some(PathBuf::from("..")),
                        Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
                    })
                    .collect();

                for c in target_comps.into_iter().rev() {
                    queue.push_front(c);
                }
            } else {
                let target_comps: Vec<PathBuf> = target
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(n) => Some(PathBuf::from(n)),
                        Component::ParentDir => Some(PathBuf::from("..")),
                        Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
                    })
                    .collect();

                for c in target_comps.into_iter().rev() {
                    queue.push_front(c);
                }
            }
        } else {
            current = candidate;
        }
    }

    Ok(current)
}

/// Named cap for PEM bundles (16 MiB)
pub const MAX_PEM_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
/// Named cap for Java KeyStores (8 MiB)
pub const MAX_JKS_BYTES: u64 = 8 * 1024 * 1024;

/// Read a file up to `cap` bytes. If reported metadata length exceeds `cap` or if reading
/// yields more than `cap` bytes, an error is returned.
fn read_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>, TrustError> {
    use std::io::Read;
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(TrustError::Cert(format!(
            "file '{}' is not a regular file",
            path.display()
        )));
    }
    if meta.len() > cap {
        return Err(TrustError::Cert(format!(
            "file '{}' exceeds size cap of {} bytes (size {})",
            path.display(),
            cap,
            meta.len()
        )));
    }

    let file = fs::File::open(path)?;
    let mut buf = Vec::new();
    let mut handle = file.take(cap + 1);
    handle.read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(TrustError::Cert(format!(
            "file '{}' exceeds size cap of {} bytes",
            path.display(),
            cap
        )));
    }
    Ok(buf)
}

/// Write data atomically into target_path: writes to a temporary file in the same directory,
/// sets matching permissions and ownership (best-effort), flushes, and renames.
pub fn atomic_write_preserving(
    target_path: &Path,
    data: &[u8],
    new_file_mode: Option<u32>,
) -> Result<(), TrustError> {
    if let Ok(m) = fs::symlink_metadata(target_path) {
        if m.file_type().is_symlink() {
            return Err(TrustError::Symlink(format!(
                "target '{}' is a symlink",
                target_path.display()
            )));
        }
        if !m.file_type().is_file() {
            return Err(TrustError::Symlink(format!(
                "target '{}' is not a regular file",
                target_path.display()
            )));
        }
    }

    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    // Get existing metadata if file exists
    let existing_meta = match fs::symlink_metadata(target_path) {
        Ok(m) if m.file_type().is_file() => Some(m),
        _ => None,
    };

    // Create temporary file in same directory
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        if let Some(ref meta) = existing_meta {
            let temp_meta = fs::symlink_metadata(temp.path())?;
            if !temp_meta.file_type().is_file() {
                return Err(TrustError::Cert(
                    "temporary file is not a regular file".to_string(),
                ));
            }
            let perms = meta.permissions();
            fs::set_permissions(temp.path(), perms)?;

            let temp_meta = fs::symlink_metadata(temp.path())?;
            if !temp_meta.file_type().is_file() {
                return Err(TrustError::Cert(
                    "temporary file is not a regular file".to_string(),
                ));
            }
            let uid = meta.uid();
            let gid = meta.gid();
            let _ = std::os::unix::fs::chown(temp.path(), Some(uid), Some(gid));
        } else if let Some(mode) = new_file_mode {
            let temp_meta = fs::symlink_metadata(temp.path())?;
            if !temp_meta.file_type().is_file() {
                return Err(TrustError::Cert(
                    "temporary file is not a regular file".to_string(),
                ));
            }
            let perms = fs::Permissions::from_mode(mode);
            fs::set_permissions(temp.path(), perms)?;
        }
    }

    temp.persist(target_path)
        .map_err(|e| TrustError::Io(e.error))?;
    Ok(())
}

/// Check if a PEM bundle already contains the given certificate DER.
pub fn bundle_contains_cert(bundle_content: &[u8], ca_cert_pem: &str, ca_cert_der: &[u8]) -> bool {
    // 1. Direct substring check of the exact PEM (fast path, zero-alloc)
    let trimmed_ca_pem = ca_cert_pem.trim().as_bytes();
    if !trimmed_ca_pem.is_empty()
        && bundle_content
            .windows(trimmed_ca_pem.len())
            .any(|w| w == trimmed_ca_pem)
    {
        return true;
    }

    // 2. Check base64 payload match without large copies
    let ca_b64: Vec<u8> = ca_cert_pem
        .lines()
        .filter(|l| !l.trim().starts_with("---"))
        .flat_map(|l| l.bytes())
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    const BEGIN_MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END_MARKER: &[u8] = b"-----END CERTIFICATE-----";

    let mut pos = 0;
    while pos + BEGIN_MARKER.len() <= bundle_content.len() {
        if let Some(offset) = bundle_content[pos..]
            .windows(BEGIN_MARKER.len())
            .position(|w| w == BEGIN_MARKER)
        {
            let block_start = pos + offset;
            let body_start = block_start + BEGIN_MARKER.len();
            if let Some(end_offset) = bundle_content[body_start..]
                .windows(END_MARKER.len())
                .position(|w| w == END_MARKER)
            {
                let body_end = body_start + end_offset;
                let block_end = body_end + END_MARKER.len();
                let body = &bundle_content[body_start..body_end];

                if !ca_b64.is_empty() {
                    let body_non_ws = body.iter().copied().filter(|b| !b.is_ascii_whitespace());
                    if body_non_ws.eq(ca_b64.iter().copied()) {
                        return true;
                    }
                }

                let block_slice = &bundle_content[block_start..block_end];
                if let Ok(p) = pem::parse(block_slice) {
                    if p.tag() == "CERTIFICATE" && p.contents() == ca_cert_der {
                        return true;
                    }
                }

                pos = block_end;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    false
}

/// Append CA certificate to a PEM bundle file idempotently and atomically.
/// Returns Ok(true) if modified, Ok(false) if already present.
pub fn append_pem_bundle_idempotent(
    target_path: &Path,
    ca_pem: &str,
    ca_der: &[u8],
) -> Result<bool, TrustError> {
    let content = match read_file_capped(target_path, MAX_PEM_BUNDLE_BYTES) {
        Ok(c) => c,
        Err(TrustError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };

    if !content.is_empty() && bundle_contains_cert(&content, ca_pem, ca_der) {
        return Ok(false);
    }

    let mut new_content = content;
    if !new_content.is_empty() && !new_content.ends_with(b"\n") {
        new_content.push(b'\n');
    }
    new_content.extend_from_slice(ca_pem.as_bytes());
    if !new_content.ends_with(b"\n") {
        new_content.push(b'\n');
    }

    atomic_write_preserving(target_path, &new_content, Some(0o644))?;
    Ok(true)
}

/// Install the CA certificate into every trust store found under rootfs.
///
/// # Precondition
/// The rootfs must not be modified concurrently during install (exclusive access).
pub fn install_ca(rootfs: &Path, ca_cert_pem: &str) -> Result<InstallReport, TrustError> {
    // FIX 1: Parse --ca-cert, require exactly one CERTIFICATE block and reject any
    // file containing a PRIVATE KEY (any "PRIVATE KEY" label) or other block types with a clear error;
    // re-encode the single parsed certificate as canonical PEM and write only that everywhere.
    if ca_cert_pem.contains("PRIVATE KEY") {
        return Err(TrustError::Cert(
            "ca-cert contains a private key".to_string(),
        ));
    }

    let parsed_blocks = pem::parse_many(ca_cert_pem.as_bytes())
        .map_err(|e| TrustError::Cert(format!("invalid PEM in ca-cert: {}", e)))?;

    if parsed_blocks.is_empty() {
        return Err(TrustError::Cert(
            "ca-cert contains no PEM blocks".to_string(),
        ));
    }

    for block in &parsed_blocks {
        if block.tag().contains("PRIVATE KEY") {
            return Err(TrustError::Cert(
                "ca-cert contains a private key".to_string(),
            ));
        }
        if block.tag() != "CERTIFICATE" {
            return Err(TrustError::Cert(format!(
                "unexpected block type '{}' in ca-cert; expected only CERTIFICATE",
                block.tag()
            )));
        }
    }

    if parsed_blocks.len() != 1 {
        return Err(TrustError::Cert(format!(
            "expected exactly one CERTIFICATE block in ca-cert, found {}",
            parsed_blocks.len()
        )));
    }

    let ca_cert_der = parsed_blocks[0].contents();
    let mut canonical_ca_pem = pem::encode(&pem::Pem::new("CERTIFICATE", ca_cert_der.to_vec()));
    if !canonical_ca_pem.ends_with('\n') {
        canonical_ca_pem.push('\n');
    }

    // Compute SHA-256 hex digest of the CA certificate DER
    let mut hasher = Sha256::new();
    hasher.update(ca_cert_der);
    let ca_cert_sha256 = hex::encode(hasher.finalize());

    let mut modified_paths = HashSet::new();
    let mut skipped_paths = Vec::new();
    let mut processed_targets = HashSet::new();

    let rootfs_canon = rootfs
        .canonicalize()
        .unwrap_or_else(|_| rootfs.to_path_buf());

    // Helper to turn absolute path inside rootfs into a rootfs-relative string
    let make_rel = |p: &Path| -> String {
        p.strip_prefix(rootfs)
            .or_else(|_| p.strip_prefix(&rootfs_canon))
            .map(|r| r.to_string_lossy().to_string())
            .unwrap_or_else(|_| p.to_string_lossy().to_string())
    };

    // 1. Known System Bundles
    let known_system_bundles = [
        "etc/ssl/certs/ca-certificates.crt",
        "etc/pki/tls/certs/ca-bundle.crt",
        "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "etc/ssl/cert.pem",
    ];

    let mut first_existing_system_bundle: Option<String> = None;
    let mut successful_bundle_targets: HashSet<PathBuf> = HashSet::new();

    for rel_str in &known_system_bundles {
        let bundle_path = rootfs.join(rel_str);
        match resolve_in_rootfs(rootfs, &bundle_path) {
            Ok(target) => {
                let target_meta = match fs::symlink_metadata(&target) {
                    Ok(m) => m,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        continue;
                    }
                    Err(e) => {
                        skipped_paths.push(SkippedPath {
                            path: make_rel(&bundle_path),
                            reason: format!("cannot stat target: {}", e),
                        });
                        continue;
                    }
                };

                if target_meta.is_dir() {
                    skipped_paths.push(SkippedPath {
                        path: make_rel(&bundle_path),
                        reason: "bundle_is_directory".to_string(),
                    });
                    continue;
                }

                if !target_meta.file_type().is_file() {
                    skipped_paths.push(SkippedPath {
                        path: make_rel(&bundle_path),
                        reason: "not a regular file".to_string(),
                    });
                    continue;
                }

                if processed_targets.insert(target.clone()) {
                    let rechecked = resolve_in_rootfs(rootfs, &bundle_path)?;
                    if rechecked != target {
                        return Err(TrustError::Symlink(format!(
                            "target path changed during install for '{}'",
                            bundle_path.display()
                        )));
                    }

                    match append_pem_bundle_idempotent(&target, &canonical_ca_pem, ca_cert_der) {
                        Ok(modified) => {
                            successful_bundle_targets.insert(target.clone());
                            if modified {
                                modified_paths.insert(make_rel(&target));
                            }
                            if first_existing_system_bundle.is_none() {
                                first_existing_system_bundle = Some(format!("/{}", rel_str));
                            }
                        }
                        Err(e) => {
                            skipped_paths.push(SkippedPath {
                                path: make_rel(&target),
                                reason: e.to_string(),
                            });
                        }
                    }
                } else if successful_bundle_targets.contains(&target)
                    && first_existing_system_bundle.is_none()
                {
                    first_existing_system_bundle = Some(format!("/{}", rel_str));
                }
            }
            Err(e) => {
                skipped_paths.push(SkippedPath {
                    path: rel_str.to_string(),
                    reason: e.to_string(),
                });
            }
        }
    }

    // Also drop PEM at anchor directories when they exist
    let anchor_targets = [
        (
            "usr/local/share/ca-certificates",
            "usr/local/share/ca-certificates/hermetic-world-ca.crt",
        ),
        (
            "etc/pki/ca-trust/source/anchors",
            "etc/pki/ca-trust/source/anchors/hermetic-world-ca.pem",
        ),
    ];

    for (dir_rel, file_rel) in &anchor_targets {
        let dir_path = rootfs.join(dir_rel);
        let dir_exists = match resolve_in_rootfs(rootfs, &dir_path) {
            Ok(resolved_dir) => match fs::symlink_metadata(&resolved_dir) {
                Ok(m) => m.is_dir(),
                Err(_) => false,
            },
            Err(_) => false,
        };

        if dir_exists {
            let file_path = rootfs.join(file_rel);
            match resolve_in_rootfs(rootfs, &file_path) {
                Ok(target) => {
                    if let Ok(m) = fs::symlink_metadata(&target) {
                        if !m.file_type().is_file() {
                            skipped_paths.push(SkippedPath {
                                path: make_rel(&target),
                                reason: if m.is_dir() {
                                    "bundle_is_directory".to_string()
                                } else {
                                    "not a regular file".to_string()
                                },
                            });
                            continue;
                        }
                    }
                    if processed_targets.insert(target.clone()) {
                        let content = canonical_ca_pem.as_bytes();
                        let existing = match read_file_capped(&target, MAX_PEM_BUNDLE_BYTES) {
                            Ok(c) => Some(c),
                            Err(TrustError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                                None
                            }
                            Err(e) => {
                                skipped_paths.push(SkippedPath {
                                    path: make_rel(&target),
                                    reason: e.to_string(),
                                });
                                continue;
                            }
                        };
                        if existing.as_deref() != Some(content) {
                            let rechecked = resolve_in_rootfs(rootfs, &file_path)?;
                            if rechecked != target {
                                return Err(TrustError::Symlink(format!(
                                    "target path changed during install for '{}'",
                                    file_path.display()
                                )));
                            }

                            match atomic_write_preserving(&target, content, Some(0o644)) {
                                Ok(()) => {
                                    modified_paths.insert(make_rel(&target));
                                }
                                Err(e) => {
                                    skipped_paths.push(SkippedPath {
                                        path: make_rel(&target),
                                        reason: e.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    skipped_paths.push(SkippedPath {
                        path: file_rel.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }
    }

    // 2. Walk directory tree without following symlinks
    // Find every certifi/cacert.pem, conda ssl/cacert.pem, and Java cacerts
    let mut dirs_to_visit = vec![rootfs.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        let entries = match fs::read_dir(&current_dir) {
            Ok(e) => e,
            Err(e) => {
                skipped_paths.push(SkippedPath {
                    path: make_rel(&current_dir),
                    reason: format!("read_dir error: {}", e),
                });
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    skipped_paths.push(SkippedPath {
                        path: make_rel(&current_dir),
                        reason: format!("entry error: {}", e),
                    });
                    continue;
                }
            };

            let entry_path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    skipped_paths.push(SkippedPath {
                        path: make_rel(&entry_path),
                        reason: format!("file_type error: {}", e),
                    });
                    continue;
                }
            };

            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_type.is_dir() {
                if file_name_str == "cacert.pem" {
                    let parent_name = entry_path
                        .parent()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default();
                    if parent_name == "certifi" || parent_name == "ssl" {
                        skipped_paths.push(SkippedPath {
                            path: make_rel(&entry_path),
                            reason: "bundle_is_directory".to_string(),
                        });
                        continue;
                    }
                } else if file_name_str == "cacerts" {
                    skipped_paths.push(SkippedPath {
                        path: make_rel(&entry_path),
                        reason: "bundle_is_directory".to_string(),
                    });
                    continue;
                }

                dirs_to_visit.push(entry_path);
                continue;
            }

            // Match certifi/cacert.pem or conda ssl/cacert.pem
            if file_name_str == "cacert.pem" {
                let parent_name = entry_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();

                if parent_name == "certifi" || parent_name == "ssl" {
                    match resolve_in_rootfs(rootfs, &entry_path) {
                        Ok(target) => {
                            let target_meta = match fs::symlink_metadata(&target) {
                                Ok(m) => m,
                                Err(e) => {
                                    skipped_paths.push(SkippedPath {
                                        path: make_rel(&entry_path),
                                        reason: format!("cannot stat target: {}", e),
                                    });
                                    continue;
                                }
                            };

                            if target_meta.is_dir() {
                                skipped_paths.push(SkippedPath {
                                    path: make_rel(&entry_path),
                                    reason: "bundle_is_directory".to_string(),
                                });
                                continue;
                            }

                            if !target_meta.file_type().is_file() {
                                skipped_paths.push(SkippedPath {
                                    path: make_rel(&entry_path),
                                    reason: "not a regular file".to_string(),
                                });
                                continue;
                            }

                            if processed_targets.insert(target.clone()) {
                                let rechecked = resolve_in_rootfs(rootfs, &entry_path)?;
                                if rechecked != target {
                                    return Err(TrustError::Symlink(format!(
                                        "target path changed during install for '{}'",
                                        entry_path.display()
                                    )));
                                }

                                match append_pem_bundle_idempotent(
                                    &target,
                                    &canonical_ca_pem,
                                    ca_cert_der,
                                ) {
                                    Ok(true) => {
                                        modified_paths.insert(make_rel(&target));
                                    }
                                    Ok(false) => {} // already present
                                    Err(e) => {
                                        skipped_paths.push(SkippedPath {
                                            path: make_rel(&target),
                                            reason: e.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            skipped_paths.push(SkippedPath {
                                path: make_rel(&entry_path),
                                reason: e.to_string(),
                            });
                        }
                    }
                }
            } else if file_name_str == "cacerts" {
                // Java keystore named cacerts
                match resolve_in_rootfs(rootfs, &entry_path) {
                    Ok(target) => {
                        let target_meta = match fs::symlink_metadata(&target) {
                            Ok(m) => m,
                            Err(e) => {
                                skipped_paths.push(SkippedPath {
                                    path: make_rel(&entry_path),
                                    reason: format!("cannot stat target: {}", e),
                                });
                                continue;
                            }
                        };

                        if target_meta.is_dir() {
                            skipped_paths.push(SkippedPath {
                                path: make_rel(&entry_path),
                                reason: "bundle_is_directory".to_string(),
                            });
                            continue;
                        }

                        if !target_meta.file_type().is_file() {
                            skipped_paths.push(SkippedPath {
                                path: make_rel(&entry_path),
                                reason: "not a regular file".to_string(),
                            });
                            continue;
                        }

                        if processed_targets.insert(target.clone()) {
                            let content = match read_file_capped(&target, MAX_JKS_BYTES) {
                                Ok(c) => c,
                                Err(e) => {
                                    skipped_paths.push(SkippedPath {
                                        path: make_rel(&target),
                                        reason: format!("read error: {}", e),
                                    });
                                    continue;
                                }
                            };

                            if is_pkcs12(&content) {
                                skipped_paths.push(SkippedPath {
                                    path: make_rel(&target),
                                    reason: "unsupported_pkcs12".to_string(),
                                });
                                continue;
                            }

                            // Process JKS
                            match inject_ca_into_jks(&content, ca_cert_der, 0) {
                                Ok(Some(new_jks_bytes)) => {
                                    let rechecked = resolve_in_rootfs(rootfs, &entry_path)?;
                                    if rechecked != target {
                                        return Err(TrustError::Symlink(format!(
                                            "target path changed during install for '{}'",
                                            entry_path.display()
                                        )));
                                    }

                                    match atomic_write_preserving(&target, &new_jks_bytes, None) {
                                        Ok(()) => {
                                            modified_paths.insert(make_rel(&target));
                                        }
                                        Err(e) => {
                                            skipped_paths.push(SkippedPath {
                                                path: make_rel(&target),
                                                reason: e.to_string(),
                                            });
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // Already present and identical (idempotent)
                                }
                                Err(e) => {
                                    skipped_paths.push(SkippedPath {
                                        path: make_rel(&target),
                                        reason: e.to_string(),
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        skipped_paths.push(SkippedPath {
                            path: make_rel(&entry_path),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }
    }

    // Default system bundle path for env spec
    let chosen_bundle = match first_existing_system_bundle {
        Some(b) => b,
        None => {
            // FIX 7: if no system bundle exists in the rootfs, create one at etc/ssl/certs/ca-certificates.crt
            // containing only the CA (creating parent directories inside the rootfs, checked as in FIX 9),
            // and point the defaults at it; record the creation in the report.
            let fallback_rel = "etc/ssl/certs/ca-certificates.crt";
            let fallback_path = rootfs.join(fallback_rel);
            let target = resolve_in_rootfs(rootfs, &fallback_path)?;

            match fs::symlink_metadata(&target) {
                Ok(meta) => {
                    let rel_target = make_rel(&target);
                    if meta.is_dir() {
                        if !skipped_paths.iter().any(|s| s.path == rel_target) {
                            skipped_paths.push(SkippedPath {
                                path: rel_target,
                                reason: "bundle_is_directory".to_string(),
                            });
                        }
                    } else if !meta.file_type().is_file() {
                        if !skipped_paths.iter().any(|s| s.path == rel_target) {
                            skipped_paths.push(SkippedPath {
                                path: rel_target,
                                reason: "not a regular file".to_string(),
                            });
                        }
                    } else {
                        let rechecked = resolve_in_rootfs(rootfs, &fallback_path)?;
                        if rechecked != target {
                            return Err(TrustError::Symlink(format!(
                                "target path changed during install for '{}'",
                                fallback_path.display()
                            )));
                        }

                        match append_pem_bundle_idempotent(&target, &canonical_ca_pem, ca_cert_der)
                        {
                            Ok(modified) => {
                                if modified {
                                    modified_paths.insert(rel_target);
                                }
                            }
                            Err(e) => {
                                skipped_paths.push(SkippedPath {
                                    path: rel_target,
                                    reason: e.to_string(),
                                });
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    let rechecked = resolve_in_rootfs(rootfs, &fallback_path)?;
                    if rechecked != target {
                        return Err(TrustError::Symlink(format!(
                            "target path changed during install for '{}'",
                            fallback_path.display()
                        )));
                    }

                    atomic_write_preserving(&target, canonical_ca_pem.as_bytes(), Some(0o644))?;
                    modified_paths.insert(make_rel(&target));
                }
                Err(e) => {
                    let rel_target = make_rel(&target);
                    skipped_paths.push(SkippedPath {
                        path: rel_target,
                        reason: format!("cannot stat target: {}", e),
                    });
                }
            }

            "/etc/ssl/certs/ca-certificates.crt".to_string()
        }
    };

    let mut env_defaults = BTreeMap::new();
    env_defaults.insert("SSL_CERT_FILE".to_string(), chosen_bundle.clone());
    env_defaults.insert("REQUESTS_CA_BUNDLE".to_string(), chosen_bundle.clone());
    env_defaults.insert("CURL_CA_BUNDLE".to_string(), chosen_bundle.clone());
    env_defaults.insert("PIP_CERT".to_string(), chosen_bundle.clone());
    env_defaults.insert("NODE_EXTRA_CA_CERTS".to_string(), chosen_bundle.clone());
    env_defaults.insert("GIT_SSL_CAINFO".to_string(), chosen_bundle.clone());
    env_defaults.insert("CARGO_HTTP_CAINFO".to_string(), chosen_bundle);

    let mut modified_vec: Vec<String> = modified_paths.into_iter().collect();
    modified_vec.sort();

    Ok(InstallReport {
        ca_cert_sha256,
        modified_paths: modified_vec,
        skipped_paths,
        env_defaults,
    })
}
