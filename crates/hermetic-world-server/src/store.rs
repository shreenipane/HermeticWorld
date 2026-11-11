#![forbid(unsafe_code)]

use crate::safe_fs::Directory;
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub const MAX_SIDECAR_BYTES: u64 = 64 * 1024;
pub const MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_STORE_PATH_BYTES: usize = 8192;
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
    directory: Option<Directory>,
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
        let root = crate::safe_fs::normalize_path(root.as_ref());
        Self {
            directory: Directory::open(&root).ok(),
            root,
        }
    }

    pub(crate) fn try_new(root: &Path) -> std::io::Result<Self> {
        let root = crate::safe_fs::normalize_path(root);
        Ok(Self {
            directory: Some(Directory::open(&root)?),
            root,
        })
    }

    pub(crate) fn descriptor_path(&self) -> Option<PathBuf> {
        Some(self.directory.as_ref()?.descriptor_path())
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
        if let Some(data) = self.read_metadata(&sidecar_path) {
            if let Ok(c404) = serde_json::from_slice::<Custom404>(&data) {
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

        (
            404,
            Some("text/html".to_string()),
            b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>".to_vec(),
        )
    }

    /// Percent-decode an ASCII path string, rejecting invalid escapes and NUL characters.
    fn percent_decode(input: &str) -> Option<String> {
        let mut bytes = input.as_bytes().iter();
        let mut out = Vec::with_capacity(input.len());
        while let Some(&byte) = bytes.next() {
            let decoded = if byte == b'%' {
                let high = char::from(*bytes.next()?).to_digit(16)?;
                let low = char::from(*bytes.next()?).to_digit(16)?;
                ((high << 4) | low) as u8
            } else {
                byte
            };
            if decoded == 0 {
                return None;
            }
            out.push(decoded);
        }
        String::from_utf8(out).ok()
    }

    /// Resolve authority and path_and_query to an on-disk file path, rejecting traversal attacks.
    fn resolve_path(&self, authority: &str, path_and_query: &str) -> Option<PathBuf> {
        if path_and_query.len() > MAX_STORE_PATH_BYTES
            || hermetic_common::validate_authority(authority.as_bytes()).is_err()
        {
            return None;
        }

        // Must start with '/'
        if !path_and_query.starts_with('/') {
            return None;
        }

        // Split into path and optional query
        let (path_part, query_part) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
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
                if self.open_path(&candidate).is_some() {
                    return Some(candidate);
                }
                // Or index.html%3F<query>
                let mut alt = auth_dir.clone();
                alt.push(format!("index.html%3F{q}"));
                if self.open_path(&alt).is_some() {
                    return Some(alt);
                }
            } else {
                let (last, parents) = raw_segs.split_last()?;
                for seg in parents {
                    candidate.push(seg);
                }
                let mut with_q = candidate.clone();
                with_q.push(format!("{last}%3F{q}"));
                if self.open_path(&with_q).is_some() {
                    return Some(with_q);
                }
                // If trailing slash was requested, might be `<last>/index.html%3F<q>`
                let mut index_with_q = candidate.clone();
                index_with_q.push(last);
                index_with_q.push(format!("index.html%3F{q}"));
                if self.open_path(&index_with_q).is_some() {
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

        if self.open_path(&candidate).is_some() {
            return Some(candidate);
        }

        // If directory or trailing slash, look for index.html
        let index_candidate = candidate.join("index.html");
        if self.open_path(&index_candidate).is_some() {
            return Some(index_candidate);
        }

        None
    }

    /// Read optional sidecar `<file>.headers.json`.
    fn read_sidecar(&self, file_path: &Path) -> (Option<String>, Vec<(String, String)>) {
        let mut name = file_path.as_os_str().to_os_string();
        name.push(".headers.json");
        let sidecar_path = PathBuf::from(name);
        if let Some(data) = self.read_metadata(&sidecar_path) {
            if let Ok(sc) = serde_json::from_slice::<SidecarHeaders>(&data) {
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

impl DirStore {
    fn open_path(&self, path: &Path) -> Option<File> {
        self.directory
            .as_ref()?
            .open_file(path.strip_prefix(&self.root).ok()?, false, false)
            .ok()
    }

    fn read_metadata(&self, path: &Path) -> Option<Vec<u8>> {
        self.directory
            .as_ref()?
            .read(path.strip_prefix(&self.root).ok()?, MAX_SIDECAR_BYTES)
            .ok()
    }

    pub fn open(&self, authority: &str, path: &str) -> Option<OpenedObject> {
        let path = self.resolve_path(authority, path)?;
        let file = self.open_path(&path)?;
        let len = file.metadata().ok()?.len();
        let (content_type, extra_headers) = self.read_sidecar(&path);
        Some(OpenedObject {
            file,
            len,
            content_type,
            extra_headers,
        })
    }
}

pub struct OpenedObject {
    file: File,
    pub len: u64,
    pub content_type: Option<String>,
    pub extra_headers: Vec<(String, String)>,
}

impl OpenedObject {
    pub fn read_range(&mut self, start: u64, length: u64, cap: u64) -> std::io::Result<Vec<u8>> {
        if length > cap.min(MAX_BODY_BYTES)
            || start.checked_add(length).is_none_or(|end| end > self.len)
        {
            return Err(crate::safe_fs::invalid());
        }
        self.file.seek(SeekFrom::Start(start))?;
        let size = usize::try_from(length).map_err(|_| crate::safe_fs::invalid())?;
        let mut body = Vec::new();
        body.try_reserve_exact(size)
            .map_err(|_| crate::safe_fs::invalid())?;
        self.file.by_ref().take(length).read_to_end(&mut body)?;
        if body.len() != size {
            return Err(crate::safe_fs::invalid());
        }
        Ok(body)
    }
}

impl Store for DirStore {
    fn get(&self, authority: &str, path_and_query: &str) -> Option<StoredObject> {
        let mut object = self.open(authority, path_and_query)?;
        let body = object.read_range(0, object.len, MAX_BODY_BYTES).ok()?;
        Some(StoredObject {
            body,
            content_type: object.content_type,
            extra_headers: object.extra_headers,
        })
    }
}
