#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::Value;
use tantivy::{Index, IndexReader, ReloadPolicy, TantivyDocument};
use time::OffsetDateTime;

use super::schema::SearchSchema;
use super::types::{
    SearchError, SearchHit, SearchMeta, SearchResponse, DEFAULT_RESULTS_LIMIT, MAX_QUERY_BYTES,
    MAX_QUERY_TERMS, MAX_RESULTS, MAX_SNIPPET_BYTES, SCHEMA_SEARCH_TANTIVY_V1,
};
use super::validation::parse_timestamp_nanos;

#[derive(Clone)]
pub struct SearchEngine {
    index: Index,
    reader: IndexReader,
    schema: SearchSchema,
    meta: SearchMeta,
}

impl SearchEngine {
    pub fn open(
        index_dir: &Path,
        expected_month: Option<&str>,
        t_clock: Option<OffsetDateTime>,
    ) -> Result<Self, SearchError> {
        let meta_stat = index_dir
            .symlink_metadata()
            .map_err(|e| SearchError::Io(e.to_string()))?;
        if meta_stat.file_type().is_symlink() || !meta_stat.file_type().is_dir() {
            return Err(SearchError::UnsafePath(
                "search index path is a symlink or not a directory".to_string(),
            ));
        }

        let meta_file_path = index_dir.join("search-meta.json");
        let mut meta_file =
            File::open(&meta_file_path).map_err(|e| SearchError::Io(e.to_string()))?;
        let mut meta_bytes = Vec::new();
        meta_file
            .by_ref()
            .take(64 * 1024)
            .read_to_end(&mut meta_bytes)
            .map_err(|e| SearchError::Io(e.to_string()))?;

        let meta: SearchMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| SearchError::PolicyMismatch(e.to_string()))?;

        if meta.schema != SCHEMA_SEARCH_TANTIVY_V1 {
            return Err(SearchError::PolicyMismatch(
                "unknown meta schema".to_string(),
            ));
        }

        if let Some(exp) = expected_month {
            if meta.month != exp {
                return Err(SearchError::PolicyMismatch(format!(
                    "search index month {} does not match expected {}",
                    meta.month, exp
                )));
            }
        }

        if let Some(clock) = t_clock {
            let cutoff_nanos = parse_timestamp_nanos(&meta.first_day_cutoff)?;
            if clock.unix_timestamp_nanos() < cutoff_nanos {
                return Err(SearchError::PolicyMismatch(
                    "clock is earlier than search index first-day cutoff".to_string(),
                ));
            }
        }

        let index =
            Index::open_in_dir(index_dir).map_err(|e| SearchError::Tantivy(e.to_string()))?;
        let schema = SearchSchema::from_schema(&index.schema()).ok_or_else(|| {
            SearchError::PolicyMismatch("index schema fields missing or incompatible".to_string())
        })?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        Ok(Self {
            index,
            reader,
            schema,
            meta,
        })
    }

    pub fn from_ram(
        index: Index,
        schema: SearchSchema,
        meta: SearchMeta,
    ) -> Result<Self, SearchError> {
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;
        Ok(Self {
            index,
            reader,
            schema,
            meta,
        })
    }

    pub fn month(&self) -> &str {
        &self.meta.month
    }

    pub fn meta(&self) -> &SearchMeta {
        &self.meta
    }

    pub fn query(
        &self,
        raw_query: &str,
        limit_opt: Option<usize>,
    ) -> Result<SearchResponse, SearchError> {
        if raw_query.len() > MAX_QUERY_BYTES {
            return Err(SearchError::QueryCapExceeded);
        }

        let limit = limit_opt.unwrap_or(DEFAULT_RESULTS_LIMIT).min(MAX_RESULTS);
        let trimmed = raw_query.trim();

        if trimmed.is_empty() || limit == 0 {
            return Ok(SearchResponse {
                query: trimmed.to_string(),
                month: self.meta.month.clone(),
                total_hits: 0,
                results: Vec::new(),
                hits: Vec::new(),
            });
        }

        let terms: Vec<&str> = trimmed.split_whitespace().collect();
        if terms.len() > MAX_QUERY_TERMS {
            return Err(SearchError::QueryCapExceeded);
        }

        let searcher = self.reader.searcher();
        let query_parser =
            QueryParser::for_index(&self.index, vec![self.schema.title, self.schema.body]);

        // Fallback-safe parsing: hostile punctuation falls back to plain term disjunction
        let parsed_query = match query_parser.parse_query(trimmed) {
            Ok(q) => q,
            Err(_) => {
                let sanitized: String = trimmed
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { ' ' })
                    .collect();
                let clean_terms: Vec<&str> = sanitized.split_whitespace().collect();
                if clean_terms.is_empty() {
                    return Ok(SearchResponse {
                        query: trimmed.to_string(),
                        month: self.meta.month.clone(),
                        total_hits: 0,
                        results: Vec::new(),
                        hits: Vec::new(),
                    });
                }
                let clean_query_str = clean_terms.join(" ");
                match query_parser.parse_query(&clean_query_str) {
                    Ok(q) => q,
                    Err(_) => {
                        return Ok(SearchResponse {
                            query: trimmed.to_string(),
                            month: self.meta.month.clone(),
                            total_hits: 0,
                            results: Vec::new(),
                            hits: Vec::new(),
                        });
                    }
                }
            }
        };

        // Query tantivy with BM25 scoring
        let top_docs = searcher
            .search(&parsed_query, &TopDocs::with_limit(limit))
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        let mut hits = Vec::new();
        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_address)
                .map_err(|e| SearchError::Tantivy(e.to_string()))?;

            let url = doc
                .get_first(self.schema.url)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let title = doc
                .get_first(self.schema.title)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let body = doc
                .get_first(self.schema.body)
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let snippet = if body.len() > MAX_SNIPPET_BYTES {
                let mut end = MAX_SNIPPET_BYTES;
                while end > 0 && !body.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &body[..end])
            } else {
                body.to_string()
            };

            let captured = doc
                .get_first(self.schema.captured)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let source = doc
                .get_first(self.schema.source)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            hits.push(SearchHit {
                url,
                title,
                snippet,
                score,
                captured,
                source,
            });
        }

        // Deterministic tie-breaking: score descending, then URL ascending
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.url.cmp(&b.url)));
        hits.truncate(limit);

        let url_hits = hits.iter().map(|h| h.url.clone()).collect();
        let total_hits = hits.len();

        Ok(SearchResponse {
            query: trimmed.to_string(),
            month: self.meta.month.clone(),
            total_hits,
            results: hits,
            hits: url_hits,
        })
    }

    /// Handle search HTTP request: parses query string, returns (status, content_type, body)
    pub fn format_error_response(e: &SearchError) -> (u16, Option<String>, Vec<u8>) {
        let err_obj = serde_json::json!({ "error": e.to_string() });
        let json = serde_json::to_vec(&err_obj)
            .unwrap_or_else(|_| b"{\"error\":\"search error\"}".to_vec());
        (400, Some("application/json".to_string()), json)
    }

    pub fn handle_http_request(&self, path_and_query: &str) -> (u16, Option<String>, Vec<u8>) {
        let query_str = match path_and_query.split_once('?') {
            Some((_, q)) => q,
            None => "",
        };

        let mut search_query = None;
        let mut limit = None;

        for pair in query_str.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            let decoded_k = percent_decode(k).unwrap_or_else(|| k.to_string());
            let decoded_v = percent_decode(v).unwrap_or_else(|| v.to_string());

            if decoded_k == "q" || decoded_k == "query" {
                search_query = Some(decoded_v);
            } else if decoded_k == "limit" || decoded_k == "n" {
                if let Ok(num) = decoded_v.parse::<usize>() {
                    limit = Some(num);
                }
            }
        }

        let q = match search_query {
            Some(q) => q,
            None => {
                // If path is like /search without ?q=, return empty result
                "".to_string()
            }
        };

        match self.query(&q, limit) {
            Ok(resp) => {
                let json = serde_json::to_vec(&resp).unwrap_or_default();
                (200, Some("application/json".to_string()), json)
            }
            Err(SearchError::QueryCapExceeded) => (
                400,
                Some("application/json".to_string()),
                b"{\"error\":\"search query exceeds size cap\"}".to_vec(),
            ),
            Err(e) => Self::format_error_response(&e),
        }
    }
}

fn percent_decode(input: &str) -> Option<String> {
    let mut bytes = input.as_bytes().iter();
    let mut out = Vec::with_capacity(input.len());
    while let Some(&byte) = bytes.next() {
        let decoded = if byte == b'%' {
            let high = char::from(*bytes.next()?).to_digit(16)?;
            let low = char::from(*bytes.next()?).to_digit(16)?;
            ((high << 4) | low) as u8
        } else if byte == b'+' {
            b' '
        } else {
            byte
        };
        out.push(decoded);
    }
    String::from_utf8(out).ok()
}
