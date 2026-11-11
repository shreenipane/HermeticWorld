#![forbid(unsafe_code)]

pub mod benchmark;
pub mod binary;
pub mod bytecode;
pub mod containers;
pub mod d1;
pub mod d5a;
pub mod d6;
pub mod d8;
pub mod diff;
pub mod fingerprint;
pub mod gitstore;
pub mod index;
pub mod normalize;
pub mod sarif;
pub mod scan;
pub mod undated;
pub mod winnow;

use serde::{Deserialize, Serialize};

pub use benchmark::{BenchmarkSignatures, ExternalSignature};
pub use binary::{
    is_minified_bundle, parse_class, parse_elf, parse_minified, parse_wasm,
    scan_binary_if_recognized, scan_minified_bundle,
};
pub use bytecode::{check_pyc_bytecode, locate_pyc_source, pyc_header_len, pyc_magic};
pub use containers::{
    detect_container_type, extract_pyc_constants, is_tar, scan_container_or_unit,
    scan_container_or_unit_with_root_prefix, CountingReader,
};
pub use d1::scan_git_repo;
pub use d5a::{check_d5a_metadata, parse_pep440, parse_pkg_metadata, pep503_normalize};
pub use d6::{parse_oci_date, scan_oci, D6Error};
pub use d8::check_d8;
pub use diff::{
    parse_patch, DiffLine, DiffLineType, FilePatch, Hunk, HunkHeader, HunkRange, Patch,
};
pub use fingerprint::{FingerprintError, FingerprintSet, HunkFingerprints};
pub use gitstore::{
    apply_delta, compute_git_sha1, scan_stray_pack_slice, Commit, GitError, GitObject, GitStore,
    ObjectType, PackIndex, StrayPackResult, Tag, Tree, TreeEntry,
};
pub use index::{
    merge_continuations, query_index, write_index, write_index_with_threshold, IndexError,
    IndexReader, IndexRecord, IndexStats, MAX_UNIT_BYTES, NOT_COVERED,
};
pub const UNDATED_NOT_COVERED: &[&str] = &["D1", "D3", "D4", "D5a"];
pub use normalize::{clean_line, is_trivial, normalize_diff_line, normalize_line};
pub use sarif::{generate_sarif, generate_sarif_with_properties, SarifLog, SarifRunProperties};
pub use scan::{
    compute_unit_hashes, match_unit, match_unit_hashes, scan_problem_statement, scan_tree,
    walk_tree, Finding, ScanOptions, Severity, TreeSink, UnitHashes, Visibility,
};
pub use undated::{load_undated_task, UndatedTask};
pub use winnow::{
    hash_kgram, kgram_hashes, tokenize, winnow_hashes, winnow_tokens, Token, WinnowFingerprint,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSummary {
    pub lines: usize,
    pub windows: usize,
    pub removed_markers: usize,
    pub diff_shapes: usize,
    pub subtracted: usize,
    pub winnow: usize,
    pub winnow_subtracted: usize,
    pub binary_items: usize,
    pub binary_subtracted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealcheckReport {
    pub schema: String,
    pub instance_id: String,
    pub fingerprints: FingerprintSummary,
    pub findings: Vec<Finding>,
    pub gate: bool,
    /// `"query"` for a report answered from layer indexes; absent for a full scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Detectors a query report could not answer from its indexes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_covered: Vec<String>,
}
