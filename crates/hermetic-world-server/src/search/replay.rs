#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::types::{
    SearchError, MAX_INDEX_RECIPE_BYTES, MAX_PAYLOAD_BYTES, MAX_TOTAL_PAYLOAD_BYTES,
};
use super::validation::{parse_timestamp_nanos, validate_digest, validate_source, validate_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCapture {
    pub url: String,
    pub captured: String,
    pub source: String,
    pub record_sha256: String,
    pub payload_sha256: String,
    pub size: usize,
    pub status: u16,
    pub content_type: String,
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayIndexDocument {
    pub schema: String,
    pub cutoff: String,
    pub captures: Vec<ReplayCapture>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResponse {
    pub status: u16,
    pub content_type: String,
    pub location: Option<String>,
    pub content_length: usize,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct ReplayIndex {
    cutoff: String,
    cutoff_nanos: i128,
    responses: HashMap<String, ReplayResponse>,
    index_sha256: String,
}

impl ReplayIndex {
    pub fn new(
        index_json: &[u8],
        blobs: &HashMap<String, Vec<u8>>,
        expected_cutoff: Option<&str>,
    ) -> Result<Self, SearchError> {
        if index_json.len() as u64 > MAX_INDEX_RECIPE_BYTES {
            return Err(SearchError::PayloadCapExceeded);
        }

        let doc: ReplayIndexDocument =
            serde_json::from_slice(index_json).map_err(|_| SearchError::UnsupportedSchema)?;
        if doc.schema != "hermetic-replay-index/v1" {
            return Err(SearchError::UnsupportedSchema);
        }

        if let Some(exp) = expected_cutoff {
            if doc.cutoff != exp {
                return Err(SearchError::PolicyMismatch(format!(
                    "cutoff mismatch: expected {}, got {}",
                    exp, doc.cutoff
                )));
            }
        }

        let cutoff_nanos = parse_timestamp_nanos(&doc.cutoff)?;
        let index_sha256 = hermetic_common::hash::sha256_hex(index_json);
        let mut responses: HashMap<String, (ReplayResponse, i128)> = HashMap::new();
        let mut total_bytes: u64 = 0;

        for cap in doc.captures {
            validate_url(&cap.url)?;
            validate_source(&cap.source)?;
            validate_digest(&cap.record_sha256)?;
            validate_digest(&cap.payload_sha256)?;

            let captured_nanos = parse_timestamp_nanos(&cap.captured)?;
            if captured_nanos >= cutoff_nanos {
                return Err(SearchError::PolicyMismatch(
                    "replay index contains capture at or after cutoff".to_string(),
                ));
            }

            if let Some(loc) = &cap.location {
                validate_url(loc)?;
            }

            let body = match blobs.get(&cap.payload_sha256) {
                Some(b) => b.clone(),
                None => {
                    return Err(SearchError::PolicyMismatch(format!(
                        "missing blob {}",
                        cap.payload_sha256
                    )));
                }
            };

            if body.len() != cap.size {
                return Err(SearchError::PayloadSizeMismatch);
            }
            if hermetic_common::hash::sha256_hex(&body) != cap.payload_sha256 {
                return Err(SearchError::PayloadDigestMismatch);
            }
            if body.len() as u64 > MAX_PAYLOAD_BYTES {
                return Err(SearchError::PayloadCapExceeded);
            }
            total_bytes = total_bytes
                .checked_add(body.len() as u64)
                .ok_or(SearchError::AggregatePayloadCapExceeded)?;
            if total_bytes > MAX_TOTAL_PAYLOAD_BYTES {
                return Err(SearchError::AggregatePayloadCapExceeded);
            }

            let resp = ReplayResponse {
                status: cap.status,
                content_type: cap.content_type,
                location: cap.location,
                content_length: cap.size,
                body,
            };

            match responses.get(&cap.url) {
                Some((_, prev_nanos)) => {
                    if captured_nanos == *prev_nanos {
                        return Err(SearchError::DuplicateCapture);
                    }
                    if captured_nanos > *prev_nanos {
                        responses.insert(cap.url, (resp, captured_nanos));
                    }
                }
                None => {
                    responses.insert(cap.url, (resp, captured_nanos));
                }
            }
        }

        let responses = responses
            .into_iter()
            .map(|(url, (resp, _))| (url, resp))
            .collect();

        Ok(Self {
            cutoff: doc.cutoff,
            cutoff_nanos,
            responses,
            index_sha256,
        })
    }

    pub fn load_from_files(
        index_path: &Path,
        blob_root: &Path,
        expected_cutoff: Option<&str>,
    ) -> Result<Self, SearchError> {
        let meta = index_path
            .symlink_metadata()
            .map_err(|e| SearchError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(SearchError::UnsafePath(
                "index path is a symlink or not a file".to_string(),
            ));
        }

        let blob_meta = blob_root
            .symlink_metadata()
            .map_err(|e| SearchError::Io(e.to_string()))?;
        if blob_meta.file_type().is_symlink() || !blob_meta.file_type().is_dir() {
            return Err(SearchError::UnsafePath(
                "blob root is a symlink or not a directory".to_string(),
            ));
        }

        let mut index_file = File::open(index_path).map_err(|e| SearchError::Io(e.to_string()))?;
        let mut index_bytes = Vec::new();
        index_file
            .by_ref()
            .take(MAX_INDEX_RECIPE_BYTES)
            .read_to_end(&mut index_bytes)
            .map_err(|e| SearchError::Io(e.to_string()))?;

        let doc: ReplayIndexDocument =
            serde_json::from_slice(&index_bytes).map_err(|_| SearchError::UnsupportedSchema)?;

        let mut blobs = HashMap::new();
        for cap in &doc.captures {
            validate_digest(&cap.payload_sha256)?;
            let blob_path = blob_root.join(&cap.payload_sha256);
            let b_meta = blob_path
                .symlink_metadata()
                .map_err(|e| SearchError::Io(e.to_string()))?;
            if b_meta.file_type().is_symlink() || !b_meta.file_type().is_file() {
                return Err(SearchError::UnsafePath(
                    "blob is a symlink or not a file".to_string(),
                ));
            }
            let mut b_file = File::open(&blob_path).map_err(|e| SearchError::Io(e.to_string()))?;
            let mut body = Vec::new();
            b_file
                .by_ref()
                .take(MAX_PAYLOAD_BYTES)
                .read_to_end(&mut body)
                .map_err(|e| SearchError::Io(e.to_string()))?;
            blobs.insert(cap.payload_sha256.clone(), body);
        }

        Self::new(&index_bytes, &blobs, expected_cutoff)
    }

    pub fn lookup(&self, url: &str, method: &str) -> Option<ReplayResponse> {
        if validate_url(url).is_err() {
            return None;
        }
        let resp = self.responses.get(url)?;
        if method == "HEAD" {
            Some(ReplayResponse {
                status: resp.status,
                content_type: resp.content_type.clone(),
                location: resp.location.clone(),
                content_length: resp.content_length,
                body: Vec::new(),
            })
        } else {
            Some(resp.clone())
        }
    }

    pub fn cutoff(&self) -> &str {
        &self.cutoff
    }

    pub fn cutoff_nanos(&self) -> i128 {
        self.cutoff_nanos
    }

    pub fn index_sha256(&self) -> &str {
        &self.index_sha256
    }
}
