#![forbid(unsafe_code)]

pub mod diff;
pub mod fingerprint;
pub mod normalize;
pub mod sarif;
pub mod scan;

use serde::{Deserialize, Serialize};

pub use diff::{
    parse_patch, DiffLine, DiffLineType, FilePatch, Hunk, HunkHeader, HunkRange, Patch,
};
pub use fingerprint::{FingerprintError, FingerprintSet, HunkFingerprints};
pub use normalize::{clean_line, is_trivial, normalize_diff_line, normalize_line};
pub use sarif::{generate_sarif, SarifLog};
pub use scan::{scan_problem_statement, scan_tree, Finding, ScanOptions, Severity, Visibility};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSummary {
    pub lines: usize,
    pub windows: usize,
    pub removed_markers: usize,
    pub diff_shapes: usize,
    pub subtracted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealcheckReport {
    pub schema: String,
    pub instance_id: String,
    pub fingerprints: FingerprintSummary,
    pub findings: Vec<Finding>,
    pub gate: bool,
}
