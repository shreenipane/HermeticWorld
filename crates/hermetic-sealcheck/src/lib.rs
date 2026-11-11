#![forbid(unsafe_code)]

pub mod benchmark;
pub mod binary;
pub mod bytecode;
pub mod containers;
pub mod d1;
pub mod d5a;
pub mod d6;
pub mod diff;
pub mod fingerprint;
pub mod gitstore;
pub mod index;
pub mod normalize;
pub mod sarif;
pub mod scan;
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
pub use d5a::{
    check_d5a_metadata, check_d5a_name_and_version, parse_pep440, parse_pkg_metadata,
    pep503_normalize,
};
pub use d6::{parse_oci_date, scan_oci, D6Error};
pub use diff::{
    parse_patch, DiffLine, DiffLineType, FilePatch, Hunk, HunkHeader, HunkRange, Patch,
};
pub use fingerprint::{hex_to_u64, sha256_u64, FingerprintError, FingerprintSet, HunkFingerprints};
pub use gitstore::{
    apply_delta, compute_git_sha1, scan_stray_pack_slice, Commit, GitError, GitObject, GitStore,
    ObjectType, PackIndex, StrayPackResult, Tag, Tree, TreeEntry,
};
pub use index::{
    decode_record_payload, encode_record_payload, extract_token_hashes_from_runs,
    hash_exact_strings, index_tree, index_tree_to_file, match_binary_hashes, query_indexes,
    read_index, write_index, BinaryHashes, BuiltinD9Hits, IndexError, IndexHeader, IndexRecord,
    PkgMetadata, INDEX_FORMAT_VERSION, INDEX_MAGIC,
};
pub use normalize::{clean_line, is_trivial, normalize_diff_line, normalize_line};
pub use sarif::{generate_sarif, SarifLog};
pub use scan::{
    compute_unit_hashes, match_unit, match_unit_hashes, scan_problem_statement, scan_tree, Finding,
    ScanOptions, Severity, UnitHashes, Visibility,
};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_covered: Option<Vec<String>>,
    pub fingerprints: FingerprintSummary,
    pub findings: Vec<Finding>,
    pub gate: bool,
}
