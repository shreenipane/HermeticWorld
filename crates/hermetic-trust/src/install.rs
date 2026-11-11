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
    let mut current = path.to_path_buf();
    let mut hops = 0;
    const MAX_HOPS: usize = 40;

    while hops < MAX_HOPS {
        let meta = match fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(current);
            }
            Err(e) => {
                return Err(TrustError::Symlink(format!(
                    "metadata {}: {}",
                    current.display(),
                    e
                )));
            }
        };

        if !meta.is_symlink() {
            return Ok(current);
        }

        hops += 1;
        let target = fs::read_link(&current)
            .map_err(|e| TrustError::Symlink(format!("read_link {}: {}", current.display(), e)))?;

        let next = if target.is_absolute() {
            let rel = target.strip_prefix("/").unwrap_or(&target);
            safe_join_rootfs(rootfs, rel)
        } else {
            let parent = current.parent().unwrap_or(rootfs);
            safe_join_rootfs_from(rootfs, parent, &target)
        };

        current = next;
    }

    Err(TrustError::Symlink("symlink loop detected".to_string()))
}

/// Write data atomically into target_path: writes to a temporary file in the same directory,
/// sets matching permissions and ownership (best-effort), flushes, and renames.
pub fn atomic_write_preserving(
    target_path: &Path,
    data: &[u8],
    new_file_mode: Option<u32>,
) -> Result<(), TrustError> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    // Get existing metadata if file exists
    let existing_meta = fs::symlink_metadata(target_path).ok();

    // Create temporary file in same directory
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        if let Some(ref meta) = existing_meta {
            let perms = meta.permissions();
            let _ = fs::set_permissions(temp.path(), perms);

            let uid = meta.uid();
            let gid = meta.gid();
            let _ = std::os::unix::fs::chown(temp.path(), Some(uid), Some(gid));
        } else if let Some(mode) = new_file_mode {
            let perms = fs::Permissions::from_mode(mode);
            let _ = fs::set_permissions(temp.path(), perms);
        }
    }

    temp.persist(target_path)
        .map_err(|e| TrustError::Io(e.error))?;
    Ok(())
}

/// Check if a PEM bundle already contains the given certificate DER.
pub fn bundle_contains_cert(bundle_content: &[u8], ca_cert_pem: &str, ca_cert_der: &[u8]) -> bool {
    let bundle_str = String::from_utf8_lossy(bundle_content);

    // 1. Direct substring check of the exact PEM (fast path)
    let trimmed_ca_pem = ca_cert_pem.trim();
    if bundle_str.contains(trimmed_ca_pem) {
        return true;
    }

    // 2. Check base64 payload match
    let ca_b64: String = ca_cert_pem
        .lines()
        .filter(|l| !l.trim().starts_with("---"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    // Split bundle by PEM blocks
    for part in bundle_str.split("-----BEGIN CERTIFICATE-----") {
        if let Some((body, _)) = part.split_once("-----END CERTIFICATE-----") {
            let body_b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            if body_b64 == ca_b64 {
                return true;
            }
            if let Ok(p) = pem::parse(format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                body
            )) {
                if p.contents() == ca_cert_der {
                    return true;
                }
            }
        }
    }

    // 3. Fallback to pem::parse_many
    if let Ok(pems) = pem::parse_many(bundle_content) {
        for p in pems {
            if p.tag() == "CERTIFICATE" && p.contents() == ca_cert_der {
                return true;
            }
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
    let content = match fs::read(target_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(TrustError::Io(e)),
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
pub fn install_ca(rootfs: &Path, ca_cert_pem: &str) -> Result<InstallReport, TrustError> {
    // Decode CA DER from PEM
    let parsed_pem =
        pem::parse(ca_cert_pem).map_err(|e| TrustError::Cert(format!("invalid CA PEM: {}", e)))?;
    let ca_cert_der = parsed_pem.contents();

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

    for rel_str in &known_system_bundles {
        let bundle_path = rootfs.join(rel_str);
        if fs::symlink_metadata(&bundle_path).is_ok() {
            // Found a bundle candidate
            match resolve_in_rootfs(rootfs, &bundle_path) {
                Ok(target) => {
                    let target_meta = match fs::metadata(&target) {
                        Ok(m) => m,
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

                    if first_existing_system_bundle.is_none() {
                        first_existing_system_bundle = Some(format!("/{}", rel_str));
                    }

                    if processed_targets.insert(target.clone()) {
                        match append_pem_bundle_idempotent(&target, ca_cert_pem, ca_cert_der) {
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
                        path: rel_str.to_string(),
                        reason: e.to_string(),
                    });
                }
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
        if dir_path.is_dir() {
            let file_path = rootfs.join(file_rel);
            match resolve_in_rootfs(rootfs, &file_path) {
                Ok(target) => {
                    if processed_targets.insert(target.clone()) {
                        let content = ca_cert_pem.as_bytes();
                        let existing = fs::read(&target).ok();
                        if existing.as_deref() != Some(content) {
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
                            let target_meta = match fs::metadata(&target) {
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

                            if processed_targets.insert(target.clone()) {
                                match append_pem_bundle_idempotent(
                                    &target,
                                    ca_cert_pem,
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
                        let target_meta = match fs::metadata(&target) {
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

                        if processed_targets.insert(target.clone()) {
                            let content = match fs::read(&target) {
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
    let chosen_bundle = first_existing_system_bundle
        .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".to_string());

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
