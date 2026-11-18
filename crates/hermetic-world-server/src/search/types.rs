#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub const MAX_INDEX_RECIPE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_DOCUMENTS: usize = 4096;
pub const MAX_URL_BYTES: usize = 2048;
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_TOTAL_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DOCUMENT_TOKENS: usize = 32768;
pub const MAX_TOTAL_TOKENS: usize = 262144;
pub const MAX_TERMS: usize = 32768;
pub const MAX_QUERY_BYTES: usize = 1024;
pub const MAX_QUERY_TERMS: usize = 32;
pub const MAX_RESULTS: usize = 100;
pub const DEFAULT_RESULTS_LIMIT: usize = 10;
pub const MAX_SNIPPET_BYTES: usize = 256;
pub const INDEX_WRITER_MEMORY_BUDGET: usize = 15_000_000;
pub const SCHEMA_SEARCH_TANTIVY_V1: &str = "hermetic-search-tantivy/v1";
pub const SCHEMA_SEARCH_RECIPE_V1: &str = "hermetic-search-recipe/v1";
pub const SCHEMA_REPLAY_RECIPE_V1: &str = "hermetic-replay-recipe/v1";
pub const SCHEMA_REPLAY_INDEX_V1: &str = "hermetic-replay-index/v1";

pub const ALLOWED_SOURCES: &[&str] = &[
    "common-crawl",
    "wayback",
    "software-heritage",
    "stack-exchange",
];

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("invalid archive digest")]
    InvalidDigest,
    #[error("invalid archive timestamp")]
    InvalidTimestamp,
    #[error("invalid archive URL")]
    InvalidUrl,
    #[error("noncanonical archive URL")]
    NoncanonicalUrl,
    #[error("duplicate archive capture")]
    DuplicateCapture,
    #[error("invalid archive source")]
    InvalidSource,
    #[error("invalid search month")]
    InvalidMonth,
    #[error("invalid search title")]
    InvalidTitle,
    #[error("search token count or size cap exceeded")]
    TokenCapExceeded,
    #[error("archive payload digest mismatch")]
    PayloadDigestMismatch,
    #[error("archive payload size mismatch")]
    PayloadSizeMismatch,
    #[error("archive payload byte cap or type violation")]
    PayloadCapExceeded,
    #[error("archive aggregate payload cap exceeded")]
    AggregatePayloadCapExceeded,
    #[error("archive record count cap or type violation")]
    RecordCapExceeded,
    #[error("search query byte cap exceeded")]
    QueryCapExceeded,
    #[error("invalid search query or result cap")]
    InvalidQuery,
    #[error("invalid search index policy or cutoff mismatch: {0}")]
    PolicyMismatch(String),
    #[error("tantivy search error: {0}")]
    Tantivy(String),
    #[error("unsupported recipe schema")]
    UnsupportedSchema,
    #[error("unsafe filesystem path: {0}")]
    UnsafePath(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    pub url: String,
    pub title: String,
    pub snippet: String,
    pub score: f32,
    pub captured: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResponse {
    pub query: String,
    pub month: String,
    pub total_hits: usize,
    pub results: Vec<SearchHit>,
    pub hits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchMeta {
    pub schema: String,
    pub month: String,
    pub first_day_cutoff: String,
    pub document_count: usize,
    pub index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRecord {
    pub url: String,
    pub title: String,
    pub captured: String,
    pub source: String,
    pub record_sha256: String,
    pub text_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchRecipe {
    pub schema: String,
    pub month: String,
    pub documents: Vec<DocumentRecord>,
}
