#![forbid(unsafe_code)]

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Helper to normalize path components lexically.
fn normalize_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Prefix(p) => out.push(p.as_os_str()),
            std::path::Component::RootDir => out.push(comp.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => match out.components().next_back() {
                Some(std::path::Component::Normal(_)) => {
                    out.pop();
                }
                Some(std::path::Component::RootDir) => {}
                _ => {
                    out.push(comp.as_os_str());
                }
            },
            std::path::Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// Verify component-wise that path stays inside root (never string prefix).
pub fn is_inside_root(root: &Path, path: &Path) -> bool {
    let norm_root = normalize_components(root);
    let norm_path = normalize_components(path);

    let mut root_comps = norm_root.components();
    let mut path_comps = norm_path.components();

    for r in &mut root_comps {
        match path_comps.next() {
            Some(p) if p == r => {}
            _ => return false,
        }
    }

    if path_comps.next().is_none() {
        return false;
    }

    if let Ok(canon_root) = root.canonicalize() {
        if let Ok(canon_path) = path.canonicalize() {
            let mut c_root_comps = canon_root.components();
            let mut c_path_comps = canon_path.components();
            for r in &mut c_root_comps {
                match c_path_comps.next() {
                    Some(p) if p == r => {}
                    _ => return false,
                }
            }
            if c_path_comps.next().is_none() {
                return false;
            }
        } else if path.is_symlink() {
            return false;
        }
    }

    true
}

/// An object retrieved from a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub extra_headers: Vec<(String, String)>,
}

/// A pluggable storage backend for WorldServer.
pub trait Store: Send + Sync {
    fn get(&self, authority: &str, path_and_query: &str) -> Option<StoredObject>;
}

/// Filesystem directory-based store.
#[derive(Debug, Clone)]
pub struct DirStore {
    root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct SidecarHeaders {
    content_type: Option<String>,
    #[serde(rename = "content-type")]
    content_type_dash: Option<String>,
    headers: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct Custom404 {
    status: Option<u16>,
    content_type: Option<String>,
    #[serde(rename = "content-type")]
    content_type_dash: Option<String>,
    body: Option<String>,
}

impl DirStore {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        let p = root.as_ref();
        let canon = p.canonicalize().unwrap_or_else(|_| normalize_components(p));
        Self { root: canon }
    }

    /// Return custom or default 404 response for the given authority: (status, content_type, body).
    pub fn get_404(&self, authority: &str) -> (u16, Option<String>, Vec<u8>) {
        if hermetic_common::validate_authority(authority.as_bytes()).is_err() {
            return (
                404,
                Some("text/html".to_string()),
                b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>".to_vec(),
            );
        }

        let sidecar_path = self.root.join(authority).join(".404.json");
        if is_inside_root(&self.root, &sidecar_path) && sidecar_path.is_file() {
            if let Ok(data) = std::fs::read_to_string(&sidecar_path) {
                if let Ok(c404) = serde_json::from_str::<Custom404>(&data) {
                    let status = c404.status.unwrap_or(404);
                    let ct = c404
                        .content_type
                        .or(c404.content_type_dash)
                        .or_else(|| Some("text/html".to_string()));
                    let body = c404
                        .body
                        .map(|s| s.into_bytes())
                        .unwrap_or_else(|| b"<h1>404 Not Found</h1>".to_vec());
                    return (status, ct, body);
                }
            }
        }

        (
            404,
            Some("text/html".to_string()),
            b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>".to_vec(),
        )
    }

    /// Percent-decode an ASCII path string, rejecting invalid escapes and NUL characters.
    fn percent_decode(input: &str) -> Option<String> {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let h1 = char::from(bytes[i + 1]).to_digit(16)?;
                let h2 = char::from(bytes[i + 2]).to_digit(16)?;
                let byte = ((h1 << 4) | h2) as u8;
                if byte == 0 {
                    return None; // NUL byte rejected
                }
                out.push(byte);
                i += 3;
            } else {
                if bytes[i] == 0 {
                    return None; // Literal NUL rejected
                }
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }

    /// Resolve authority and path_and_query to an on-disk file path, rejecting traversal attacks.
    fn resolve_path(&self, authority: &str, path_and_query: &str) -> Option<PathBuf> {
        if hermetic_common::validate_authority(authority.as_bytes()).is_err() {
            return None;
        }

        // Must start with '/'
        if !path_and_query.starts_with('/') {
            return None;
        }

        // Split into path and optional query
        let (path_part, query_part) = match path_and_query.find('?') {
            Some(idx) => (&path_and_query[..idx], Some(&path_and_query[idx + 1..])),
            None => (path_and_query, None),
        };

        // Reject raw // tricks before and after decoding
        if path_part.contains("//") {
            return None;
        }

        let decoded_path = Self::percent_decode(path_part)?;
        if decoded_path.contains("//") || !decoded_path.starts_with('/') {
            return None;
        }

        // Reject .. and . traversal segments
        for seg in decoded_path.split('/') {
            if seg == ".." || seg == "." {
                return None;
            }
        }

        if let Some(q) = query_part {
            if q.contains('\0') || q.contains('/') {
                return None;
            }
        }

        // Build path under <root>/<authority>
        let auth_dir = self.root.join(authority);

        // Normalize segments (strip leading/trailing empty segments)
        let raw_segs: Vec<&str> = decoded_path.split('/').filter(|s| !s.is_empty()).collect();

        // Construct file candidates
        // If there is a query string, the query selects `<path>?<query>` stored with `?` as `%3F`
        if let Some(q) = query_part {
            let mut candidate = auth_dir.clone();
            if raw_segs.is_empty() {
                // Root with query: %3F<query>
                candidate.push(format!("%3F{q}"));
                if is_inside_root(&self.root, &candidate) && candidate.is_file() {
                    return Some(candidate);
                }
                // Or index.html%3F<query>
                let mut alt = auth_dir.clone();
                alt.push(format!("index.html%3F{q}"));
                if is_inside_root(&self.root, &alt) && alt.is_file() {
                    return Some(alt);
                }
            } else {
                for seg in &raw_segs[..raw_segs.len() - 1] {
                    candidate.push(seg);
                }
                let last = raw_segs[raw_segs.len() - 1];
                let mut with_q = candidate.clone();
                with_q.push(format!("{last}%3F{q}"));
                if is_inside_root(&self.root, &with_q) && with_q.is_file() {
                    return Some(with_q);
                }
                // If trailing slash was requested, might be `<last>/index.html%3F<q>`
                let mut index_with_q = candidate.clone();
                index_with_q.push(last);
                index_with_q.push(format!("index.html%3F{q}"));
                if is_inside_root(&self.root, &index_with_q) && index_with_q.is_file() {
                    return Some(index_with_q);
                }
            }
            return None;
        }

        // No query string
        let mut candidate = auth_dir.clone();
        for seg in &raw_segs {
            candidate.push(seg);
        }

        if is_inside_root(&self.root, &candidate) && candidate.is_file() {
            return Some(candidate);
        }

        // If directory or trailing slash, look for index.html
        let index_candidate = candidate.join("index.html");
        if is_inside_root(&self.root, &index_candidate) && index_candidate.is_file() {
            return Some(index_candidate);
        }

        None
    }

    /// Read optional sidecar `<file>.headers.json`.
    fn read_sidecar(&self, file_path: &Path) -> (Option<String>, Vec<(String, String)>) {
        let sidecar_path = PathBuf::from(format!("{}.headers.json", file_path.display()));
        if is_inside_root(&self.root, &sidecar_path) && sidecar_path.is_file() {
            if let Ok(data) = std::fs::read_to_string(&sidecar_path) {
                if let Ok(sc) = serde_json::from_str::<SidecarHeaders>(&data) {
                    let ct = sc.content_type.or(sc.content_type_dash);
                    let mut extra = Vec::new();
                    if let Some(map) = sc.headers {
                        for (k, v) in map {
                            extra.push((k, v));
                        }
                    }
                    return (ct, extra);
                }
            }
        }

        // Infer basic content type from extension
        let ct = match file_path.extension().and_then(|s| s.to_str()) {
            Some("html") | Some("htm") => Some("text/html".to_string()),
            Some("json") => Some("application/json".to_string()),
            Some("txt") => Some("text/plain".to_string()),
            Some("whl") => Some("application/zip".to_string()),
            Some("gz") => Some("application/gzip".to_string()),
            Some("tar") => Some("application/x-tar".to_string()),
            _ => None,
        };

        (ct, Vec::new())
    }
}

impl Store for DirStore {
    fn get(&self, authority: &str, path_and_query: &str) -> Option<StoredObject> {
        let file_path = self.resolve_path(authority, path_and_query)?;
        if !is_inside_root(&self.root, &file_path) {
            return None;
        }
        let body = std::fs::read(&file_path).ok()?;
        let (content_type, extra_headers) = self.read_sidecar(&file_path);

        Some(StoredObject {
            body,
            content_type,
            extra_headers,
        })
    }
}
