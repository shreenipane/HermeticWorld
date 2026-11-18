#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use tantivy::{Index, TantivyDocument};

use super::schema::SearchSchema;
use super::types::{
    DocumentRecord, SearchError, SearchMeta, SearchRecipe, INDEX_WRITER_MEMORY_BUDGET,
    MAX_DOCUMENTS, MAX_INDEX_RECIPE_BYTES, SCHEMA_SEARCH_RECIPE_V1, SCHEMA_SEARCH_TANTIVY_V1,
};
use super::validation::{
    parse_month_boundary_nanos, parse_timestamp_nanos, validate_blobs_and_references,
    validate_digest, validate_source, validate_title, validate_url,
};

pub struct IndexBuildReport {
    pub month: String,
    pub first_day_cutoff: String,
    pub documents_indexed: usize,
    pub meta: SearchMeta,
}

pub fn build_month_index(
    raw_recipe: &[u8],
    blobs: &HashMap<String, Vec<u8>>,
    output_dir: &Path,
    explicit_month: Option<&str>,
) -> Result<IndexBuildReport, SearchError> {
    if raw_recipe.len() as u64 > MAX_INDEX_RECIPE_BYTES {
        return Err(SearchError::PayloadCapExceeded);
    }

    let recipe: SearchRecipe =
        serde_json::from_slice(raw_recipe).map_err(|_| SearchError::UnsupportedSchema)?;
    if recipe.schema != SCHEMA_SEARCH_RECIPE_V1 {
        return Err(SearchError::UnsupportedSchema);
    }

    let month = match explicit_month {
        Some(m) => {
            if m != recipe.month {
                return Err(SearchError::PolicyMismatch(
                    "explicit month does not match recipe month".to_string(),
                ));
            }
            m.to_string()
        }
        None => recipe.month,
    };

    let (boundary_nanos, first_day_rfc3339) = parse_month_boundary_nanos(&month)?;

    if recipe.documents.len() > MAX_DOCUMENTS {
        return Err(SearchError::RecordCapExceeded);
    }

    let mut seen_identities = HashSet::new();
    let mut references = HashSet::new();

    for doc in &recipe.documents {
        validate_url(&doc.url)?;
        validate_title(&doc.title)?;
        validate_source(&doc.source)?;
        validate_digest(&doc.record_sha256)?;
        validate_digest(&doc.text_sha256)?;

        let captured_nanos = parse_timestamp_nanos(&doc.captured)?;
        let identity = (doc.url.clone(), captured_nanos);
        if !seen_identities.insert(identity) {
            return Err(SearchError::DuplicateCapture);
        }
        references.insert(doc.text_sha256.clone());
    }

    validate_blobs_and_references(blobs, &references)?;

    // Select latest capture per URL strictly before the first day of the month
    let mut selected: BTreeMap<String, (DocumentRecord, i128)> = BTreeMap::new();
    for doc in recipe.documents {
        let captured_nanos = parse_timestamp_nanos(&doc.captured)?;
        if captured_nanos < boundary_nanos {
            match selected.get(&doc.url) {
                Some((_, prev_nanos)) => {
                    if captured_nanos > *prev_nanos {
                        selected.insert(doc.url.clone(), (doc, captured_nanos));
                    }
                }
                None => {
                    selected.insert(doc.url.clone(), (doc, captured_nanos));
                }
            }
        }
    }

    // Secure directory creation: 0700, verify no symlink
    if output_dir.exists() {
        let meta = output_dir
            .symlink_metadata()
            .map_err(|e| SearchError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(SearchError::UnsafePath(
                "output directory is a symlink or not a directory".to_string(),
            ));
        }
    } else {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(output_dir)
            .map_err(|e| SearchError::Io(e.to_string()))?;
    }

    let search_schema = SearchSchema::build();
    let index = Index::create_in_dir(output_dir, search_schema.schema.clone())
        .map_err(|e| SearchError::Tantivy(e.to_string()))?;

    let mut writer = index
        .writer_with_num_threads(1, INDEX_WRITER_MEMORY_BUDGET)
        .map_err(|e| SearchError::Tantivy(e.to_string()))?;

    // Sort documents deterministically by URL
    let sorted_entries: Vec<DocumentRecord> = selected.into_values().map(|(doc, _)| doc).collect();

    for doc in &sorted_entries {
        let body_bytes = blobs
            .get(&doc.text_sha256)
            .ok_or_else(|| SearchError::PolicyMismatch("missing blob".to_string()))?;
        let body_text = std::str::from_utf8(body_bytes)
            .map_err(|_| SearchError::PolicyMismatch("invalid utf8 text blob".to_string()))?;

        let mut tantivy_doc = TantivyDocument::default();
        tantivy_doc.add_text(search_schema.url, &doc.url);
        tantivy_doc.add_text(search_schema.title, &doc.title);
        tantivy_doc.add_text(search_schema.body, body_text);
        tantivy_doc.add_text(search_schema.captured, &doc.captured);
        tantivy_doc.add_text(search_schema.source, &doc.source);
        tantivy_doc.add_text(search_schema.record_sha256, &doc.record_sha256);
        tantivy_doc.add_text(search_schema.text_sha256, &doc.text_sha256);

        writer
            .add_document(tantivy_doc)
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;
    }

    writer
        .commit()
        .map_err(|e| SearchError::Tantivy(e.to_string()))?;

    // Write search-meta.json atomically with mode 0600
    let serialized_entries = serde_json::to_vec(&(&month, &sorted_entries))
        .map_err(|e| SearchError::PolicyMismatch(e.to_string()))?;
    let meta_obj = SearchMeta {
        schema: SCHEMA_SEARCH_TANTIVY_V1.to_string(),
        month: month.clone(),
        first_day_cutoff: first_day_rfc3339.clone(),
        document_count: sorted_entries.len(),
        index_sha256: hermetic_common::hash::sha256_hex(&serialized_entries),
    };

    let meta_json = serde_json::to_vec_pretty(&meta_obj)
        .map_err(|e| SearchError::PolicyMismatch(e.to_string()))?;
    let meta_path = output_dir.join("search-meta.json");

    let mut meta_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&meta_path)
        .map_err(|e| SearchError::Io(e.to_string()))?;
    meta_file
        .write_all(&meta_json)
        .map_err(|e| SearchError::Io(e.to_string()))?;
    meta_file
        .sync_all()
        .map_err(|e| SearchError::Io(e.to_string()))?;

    Ok(IndexBuildReport {
        month,
        first_day_cutoff: first_day_rfc3339,
        documents_indexed: sorted_entries.len(),
        meta: meta_obj,
    })
}

/// In-memory builder for testing without filesystem I/O
pub fn build_ram_index(
    raw_recipe: &[u8],
    blobs: &HashMap<String, Vec<u8>>,
    explicit_month: Option<&str>,
) -> Result<(Index, SearchSchema, SearchMeta), SearchError> {
    if raw_recipe.len() as u64 > MAX_INDEX_RECIPE_BYTES {
        return Err(SearchError::PayloadCapExceeded);
    }

    let recipe: SearchRecipe =
        serde_json::from_slice(raw_recipe).map_err(|_| SearchError::UnsupportedSchema)?;
    if recipe.schema != SCHEMA_SEARCH_RECIPE_V1 {
        return Err(SearchError::UnsupportedSchema);
    }

    let month = match explicit_month {
        Some(m) => {
            if m != recipe.month {
                return Err(SearchError::PolicyMismatch(
                    "explicit month does not match recipe month".to_string(),
                ));
            }
            m.to_string()
        }
        None => recipe.month,
    };

    let (boundary_nanos, first_day_rfc3339) = parse_month_boundary_nanos(&month)?;

    if recipe.documents.len() > MAX_DOCUMENTS {
        return Err(SearchError::RecordCapExceeded);
    }

    let mut seen_identities = HashSet::new();
    let mut references = HashSet::new();

    for doc in &recipe.documents {
        validate_url(&doc.url)?;
        validate_title(&doc.title)?;
        validate_source(&doc.source)?;
        validate_digest(&doc.record_sha256)?;
        validate_digest(&doc.text_sha256)?;

        let captured_nanos = parse_timestamp_nanos(&doc.captured)?;
        let identity = (doc.url.clone(), captured_nanos);
        if !seen_identities.insert(identity) {
            return Err(SearchError::DuplicateCapture);
        }
        references.insert(doc.text_sha256.clone());
    }

    validate_blobs_and_references(blobs, &references)?;

    let mut selected: BTreeMap<String, (DocumentRecord, i128)> = BTreeMap::new();
    for doc in recipe.documents {
        let captured_nanos = parse_timestamp_nanos(&doc.captured)?;
        if captured_nanos < boundary_nanos {
            match selected.get(&doc.url) {
                Some((_, prev_nanos)) => {
                    if captured_nanos > *prev_nanos {
                        selected.insert(doc.url.clone(), (doc, captured_nanos));
                    }
                }
                None => {
                    selected.insert(doc.url.clone(), (doc, captured_nanos));
                }
            }
        }
    }

    let search_schema = SearchSchema::build();
    let index = Index::create_in_ram(search_schema.schema.clone());

    let mut writer = index
        .writer_with_num_threads(1, INDEX_WRITER_MEMORY_BUDGET)
        .map_err(|e| SearchError::Tantivy(e.to_string()))?;

    let sorted_entries: Vec<DocumentRecord> = selected.into_values().map(|(doc, _)| doc).collect();

    for doc in &sorted_entries {
        let body_bytes = blobs
            .get(&doc.text_sha256)
            .ok_or_else(|| SearchError::PolicyMismatch("missing blob".to_string()))?;
        let body_text = std::str::from_utf8(body_bytes)
            .map_err(|_| SearchError::PolicyMismatch("invalid utf8 text blob".to_string()))?;

        let mut tantivy_doc = TantivyDocument::default();
        tantivy_doc.add_text(search_schema.url, &doc.url);
        tantivy_doc.add_text(search_schema.title, &doc.title);
        tantivy_doc.add_text(search_schema.body, body_text);
        tantivy_doc.add_text(search_schema.captured, &doc.captured);
        tantivy_doc.add_text(search_schema.source, &doc.source);
        tantivy_doc.add_text(search_schema.record_sha256, &doc.record_sha256);
        tantivy_doc.add_text(search_schema.text_sha256, &doc.text_sha256);

        writer
            .add_document(tantivy_doc)
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;
    }

    writer
        .commit()
        .map_err(|e| SearchError::Tantivy(e.to_string()))?;

    let serialized_entries = serde_json::to_vec(&(&month, &sorted_entries))
        .map_err(|e| SearchError::PolicyMismatch(e.to_string()))?;
    let meta_obj = SearchMeta {
        schema: SCHEMA_SEARCH_TANTIVY_V1.to_string(),
        month,
        first_day_cutoff: first_day_rfc3339,
        document_count: sorted_entries.len(),
        index_sha256: hermetic_common::hash::sha256_hex(&serialized_entries),
    };

    Ok((index, search_schema, meta_obj))
}
