#![forbid(unsafe_code)]

pub mod benchmark;
pub mod bytecode;
pub mod containers;
pub mod d1;
pub mod d6;
pub mod diff;
pub mod fingerprint;
pub mod gitstore;
pub mod normalize;
pub mod sarif;
pub mod scan;
pub mod winnow;

use serde::{Deserialize, Serialize};

pub use benchmark::{BenchmarkSignatures, ExternalSignature};
pub use bytecode::{check_pyc_bytecode, locate_pyc_source, pyc_header_len, pyc_magic};
pub use containers::{
    detect_container_type, extract_pyc_constants, is_tar, scan_container_or_unit,
    scan_container_or_unit_with_root_prefix, CountingReader,
};
pub use d1::scan_git_repo;
pub use d6::{parse_oci_date, scan_oci, D6Error};
pub use diff::{
    parse_patch, DiffLine, DiffLineType, FilePatch, Hunk, HunkHeader, HunkRange, Patch,
};
pub use fingerprint::{FingerprintError, FingerprintSet, HunkFingerprints};
pub use gitstore::{
    apply_delta, compute_git_sha1, Commit, GitError, GitObject, GitStore, ObjectType, PackIndex,
    Tag, Tree, TreeEntry,
};
pub use normalize::{clean_line, is_trivial, normalize_diff_line, normalize_line};
pub use sarif::{generate_sarif, SarifLog};
pub use scan::{scan_problem_statement, scan_tree, Finding, ScanOptions, Severity, Visibility};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealcheckReport {
    pub schema: String,
    pub instance_id: String,
    pub fingerprints: FingerprintSummary,
    pub findings: Vec<Finding>,
    pub gate: bool,
}
