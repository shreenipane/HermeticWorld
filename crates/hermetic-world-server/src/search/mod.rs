#![forbid(unsafe_code)]

pub mod build;
pub mod engine;
pub mod replay;
pub mod schema;
pub mod types;
pub mod validation;

pub use build::{build_month_index, build_ram_index, IndexBuildReport};
pub use engine::SearchEngine;
pub use replay::{ReplayCapture, ReplayIndex, ReplayIndexDocument, ReplayResponse};
pub use schema::SearchSchema;
pub use types::{
    DocumentRecord, SearchError, SearchHit, SearchMeta, SearchRecipe, SearchResponse,
    DEFAULT_RESULTS_LIMIT, INDEX_WRITER_MEMORY_BUDGET, MAX_DOCUMENTS, MAX_INDEX_RECIPE_BYTES,
    MAX_PAYLOAD_BYTES, MAX_QUERY_BYTES, MAX_QUERY_TERMS, MAX_RESULTS, MAX_SNIPPET_BYTES,
    MAX_TITLE_BYTES, MAX_TOTAL_PAYLOAD_BYTES, MAX_TOTAL_TOKENS, MAX_URL_BYTES,
    SCHEMA_REPLAY_INDEX_V1, SCHEMA_REPLAY_RECIPE_V1, SCHEMA_SEARCH_RECIPE_V1,
    SCHEMA_SEARCH_TANTIVY_V1,
};
pub use validation::{
    parse_month_boundary_nanos, parse_timestamp_nanos, validate_digest, validate_source,
    validate_title, validate_url,
};
