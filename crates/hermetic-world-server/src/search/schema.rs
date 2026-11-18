#![forbid(unsafe_code)]

use tantivy::schema::*;

#[derive(Clone)]
pub struct SearchSchema {
    pub schema: Schema,
    pub url: Field,
    pub title: Field,
    pub body: Field,
    pub captured: Field,
    pub source: Field,
    pub record_sha256: Field,
    pub text_sha256: Field,
}

impl SearchSchema {
    pub fn build() -> Self {
        let mut builder = Schema::builder();

        // Exact URL lookup and stored for retrieval
        let url = builder.add_text_field("url", STRING | STORED);

        // Title indexed for BM25 with positions/freqs and stored
        let title_options = TextOptions::default()
            .set_indexing_options(
                TextFieldIndexing::default()
                    .set_tokenizer("default")
                    .set_index_option(IndexRecordOption::WithFreqsAndPositions),
            )
            .set_stored();
        let title = builder.add_text_field("title", title_options);

        // Body indexed for BM25 with positions/freqs and stored for snippets
        let body_options = TextOptions::default()
            .set_indexing_options(
                TextFieldIndexing::default()
                    .set_tokenizer("default")
                    .set_index_option(IndexRecordOption::WithFreqsAndPositions),
            )
            .set_stored();
        let body = builder.add_text_field("body", body_options);

        // Stored metadata fields
        let captured = builder.add_text_field("captured", STRING | STORED);
        let source = builder.add_text_field("source", STRING | STORED);
        let record_sha256 = builder.add_text_field("record_sha256", STRING | STORED);
        let text_sha256 = builder.add_text_field("text_sha256", STRING | STORED);

        let schema = builder.build();
        Self {
            schema,
            url,
            title,
            body,
            captured,
            source,
            record_sha256,
            text_sha256,
        }
    }

    pub fn from_schema(schema: &Schema) -> Option<Self> {
        let url = schema.get_field("url").ok()?;
        let title = schema.get_field("title").ok()?;
        let body = schema.get_field("body").ok()?;
        let captured = schema.get_field("captured").ok()?;
        let source = schema.get_field("source").ok()?;
        let record_sha256 = schema.get_field("record_sha256").ok()?;
        let text_sha256 = schema.get_field("text_sha256").ok()?;

        Some(Self {
            schema: schema.clone(),
            url,
            title,
            body,
            captured,
            source,
            record_sha256,
            text_sha256,
        })
    }
}
