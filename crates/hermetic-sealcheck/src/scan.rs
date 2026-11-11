use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::benchmark::BenchmarkSignatures;
use crate::bytecode::check_pyc_bytecode;
use crate::containers::{
    detect_container_type, ContainerScanner, ContainerType, MatchSink, UnitSink,
};
use crate::diff::parse_patch;
use crate::fingerprint::{sha256_u64, FingerprintSet};
use crate::normalize::{clean_line, normalize_diff_line, normalize_line};
use crate::winnow::{tokenize, winnow_tokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    AgentVisible,
    ImageOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Gate,
    Review,
    Info,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    pub channel: String,
    pub path: String,
    pub visibility: Visibility,
    pub severity: Severity,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunk: Option<usize>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_bytes: u64,
    pub hunk_threshold: f64,
    pub winnow_threshold: f64,
    pub binary_threshold: f64,
    pub visibility: Visibility,
    pub max_depth: usize,
    pub max_member_bytes: u64,
    pub max_total_expanded_bytes: u64,
    pub max_ratio: f64,
    pub signatures: BenchmarkSignatures,
    /// Canonical directories never entered by `scan_tree`
    pub exclude_dirs: Vec<PathBuf>,
    pub base_commit: Option<String>,
    pub t_clock: Option<time::OffsetDateTime>,
    pub max_delta_depth: usize,
    pub target_packages: Vec<String>,
    pub task_version: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024, // 64 MiB
            hunk_threshold: 0.60,
            winnow_threshold: 0.60,
            binary_threshold: 0.60,
            visibility: Visibility::AgentVisible,
            max_depth: 4,
            max_member_bytes: 256 * 1024 * 1024, // 256 MiB
            max_total_expanded_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_ratio: 200.0,
            signatures: BenchmarkSignatures::new(None),
            exclude_dirs: Vec::new(),
            base_commit: None,
            t_clock: None,
            max_delta_depth: 4096,
            target_packages: Vec::new(),
            task_version: None,
        }
    }
}

/// Hashes extracted from a single scanned text unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UnitHashes {
    pub line_hashes: HashSet<u64>,
    pub window_hashes: HashSet<u64>,
    pub removed_marker_hashes: HashSet<u64>,
    pub diff_shape_hashes: HashSet<u64>,
    pub winnow_hashes: HashSet<u64>,
}

pub fn compute_unit_hashes(text: &str) -> UnitHashes {
    let mut line_hashes = HashSet::new();
    let mut window_hashes = HashSet::new();
    let mut removed_marker_hashes = HashSet::new();
    let mut diff_shape_hashes = HashSet::new();

    let lines: Vec<&str> = text.lines().collect();

    // 1. Regular lines and 2/3-line windows
    for line in &lines {
        if let Some(norm) = normalize_line(line) {
            line_hashes.insert(sha256_u64(norm.as_bytes()));
        }
    }

    for i in 0..lines.len() {
        if i + 1 < lines.len() {
            let w = [lines[i], lines[i + 1]];
            if !w.iter().all(|l| normalize_line(l).is_none()) {
                let norm_w = w
                    .iter()
                    .map(|l| clean_line(l, false))
                    .collect::<Vec<_>>()
                    .join("\n");
                window_hashes.insert(sha256_u64(norm_w.as_bytes()));
            }
        }
        if i + 2 < lines.len() {
            let w = [lines[i], lines[i + 1], lines[i + 2]];
            if !w.iter().all(|l| normalize_line(l).is_none()) {
                let norm_w = w
                    .iter()
                    .map(|l| clean_line(l, false))
                    .collect::<Vec<_>>()
                    .join("\n");
                window_hashes.insert(sha256_u64(norm_w.as_bytes()));
            }
        }
    }

    // 2. Diff-like lines handling: if any line starts with '+' or '-'
    let has_diff_lines = lines
        .iter()
        .any(|l| l.starts_with('+') || l.starts_with('-'));
    if has_diff_lines {
        for line in &lines {
            if line.starts_with('+') {
                if let Some(norm) = normalize_diff_line(line) {
                    line_hashes.insert(sha256_u64(norm.as_bytes()));
                }
            }
        }

        for line in &lines {
            if line.starts_with('-') {
                if let Some(norm) = normalize_diff_line(line) {
                    let marker = format!("-{}", norm);
                    removed_marker_hashes.insert(sha256_u64(marker.as_bytes()));
                }
            }
        }

        let after_change: Vec<String> = lines
            .iter()
            .filter(|l| !l.starts_with('-'))
            .map(|l| {
                if let Some(stripped) = l.strip_prefix('+') {
                    stripped.to_string()
                } else if let Some(stripped) = l.strip_prefix(' ') {
                    stripped.to_string()
                } else {
                    l.to_string()
                }
            })
            .collect();

        for i in 0..after_change.len() {
            if i + 1 < after_change.len() {
                let w = [&after_change[i], &after_change[i + 1]];
                if !w.iter().all(|l| normalize_line(l).is_none()) {
                    let norm_w = w
                        .iter()
                        .map(|l| clean_line(l, false))
                        .collect::<Vec<_>>()
                        .join("\n");
                    window_hashes.insert(sha256_u64(norm_w.as_bytes()));
                }
            }
            if i + 2 < after_change.len() {
                let w = [&after_change[i], &after_change[i + 1], &after_change[i + 2]];
                if !w.iter().all(|l| normalize_line(l).is_none()) {
                    let norm_w = w
                        .iter()
                        .map(|l| clean_line(l, false))
                        .collect::<Vec<_>>()
                        .join("\n");
                    window_hashes.insert(sha256_u64(norm_w.as_bytes()));
                }
            }
        }

        if let Ok(patch) = parse_patch(text) {
            for file in &patch.files {
                let file_path = file
                    .new_path
                    .as_deref()
                    .or(file.old_path.as_deref())
                    .unwrap_or("");

                let headers = file
                    .hunks
                    .iter()
                    .map(|h| h.raw_header.trim())
                    .collect::<Vec<_>>()
                    .join("\n");
                let shape_h = sha256_u64(format!("{}\n{}", file_path, headers).as_bytes());
                diff_shape_hashes.insert(shape_h);

                let mut diff_seq = Vec::new();
                for h in &file.hunks {
                    for l in &h.lines {
                        if l.line_type == crate::diff::DiffLineType::Added {
                            if let Some(norm) = normalize_line(&l.content) {
                                diff_seq.push(format!("+{}", norm));
                            }
                        } else if l.line_type == crate::diff::DiffLineType::Removed {
                            if let Some(norm) = normalize_line(&l.content) {
                                diff_seq.push(format!("-{}", norm));
                            }
                        }
                    }
                }
                let shape_s =
                    sha256_u64(format!("{}\n{}", file_path, diff_seq.join("\n")).as_bytes());
                diff_shape_hashes.insert(shape_s);
            }
        }
    }

    // 3. Tier 3 winnow hashes
    let tokens = tokenize(text);
    let token_texts: Vec<String> = tokens.into_iter().map(|t| t.text).collect();
    let winnow_fps = winnow_tokens(&token_texts);
    let winnow_hashes = winnow_fps.into_iter().map(|f| f.hash).collect();

    UnitHashes {
        line_hashes,
        window_hashes,
        removed_marker_hashes,
        diff_shape_hashes,
        winnow_hashes,
    }
}

pub fn match_unit_hashes(
    unit: &UnitHashes,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    detector: &str,
    channel: &str,
    path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Check diff shapes
    for (shape_u64, orig_hex) in &fp.diff_shape_u64 {
        if unit.diff_shape_hashes.contains(shape_u64) {
            let evidence_str = fp
                .hash_to_evidence
                .get(orig_hex)
                .cloned()
                .unwrap_or_else(|| "diff_shape".into());
            findings.push(Finding {
                detector: detector.to_string(),
                channel: "diff_shape".to_string(),
                path: path.to_string(),
                visibility: opts.visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![evidence_str],
            });
            break;
        }
    }

    // 2. Check each hunk's tier 1 fingerprints
    for hunk in &fp.hunks {
        let mut matched_line_weight = 0.0;
        let mut matched_window_weight = 0.0;
        let mut matched_removed_weight = 0.0;
        let mut matched_evidence = Vec::new();

        for (&hash_u64, (weight, orig_hex)) in &hunk.line_u64 {
            if unit.line_hashes.contains(&hash_u64) {
                matched_line_weight += weight;
                if matched_evidence.len() < 5 {
                    if let Some(ev) = fp.hash_to_evidence.get(orig_hex) {
                        let truncated: String = ev.chars().take(200).collect();
                        if !matched_evidence.contains(&truncated) {
                            matched_evidence.push(truncated);
                        }
                    }
                }
            }
        }

        for (&hash_u64, (weight, orig_hex)) in &hunk.window_u64 {
            if unit.window_hashes.contains(&hash_u64) {
                matched_window_weight += weight;
                if matched_evidence.len() < 5 {
                    if let Some(ev) = fp.hash_to_evidence.get(orig_hex) {
                        let truncated: String = ev.chars().take(200).collect();
                        if !matched_evidence.contains(&truncated) {
                            matched_evidence.push(truncated);
                        }
                    }
                }
            }
        }

        for (&hash_u64, (weight, orig_hex)) in &hunk.removed_u64 {
            if unit.removed_marker_hashes.contains(&hash_u64) {
                matched_removed_weight += weight;
                if matched_evidence.len() < 5 {
                    if let Some(ev) = fp.hash_to_evidence.get(orig_hex) {
                        let truncated: String = ev.chars().take(200).collect();
                        if !matched_evidence.contains(&truncated) {
                            matched_evidence.push(truncated);
                        }
                    }
                }
            }
        }

        let line_confidence = if hunk.total_line_weight > 0.0 {
            matched_line_weight / hunk.total_line_weight
        } else {
            0.0
        };

        let window_confidence = if hunk.total_window_weight > 0.0 {
            matched_window_weight / hunk.total_window_weight
        } else {
            0.0
        };

        let removed_confidence = if hunk.total_removed_weight > 0.0 {
            matched_removed_weight / hunk.total_removed_weight
        } else {
            0.0
        };

        let max_confidence = line_confidence
            .max(window_confidence)
            .max(removed_confidence);

        if max_confidence >= opts.hunk_threshold {
            findings.push(Finding {
                detector: detector.to_string(),
                channel: channel.to_string(),
                path: path.to_string(),
                visibility: opts.visibility,
                severity: Severity::Gate,
                confidence: (max_confidence * 100.0).round() / 100.0,
                hunk: Some(hunk.hunk_index),
                evidence: matched_evidence,
            });
        }

        // 3. Tier 3 winnowing check
        // "Hunks with fewer than 3 tier 3 fingerprints after subtraction are skipped on tier 3"
        if hunk.winnow_fingerprints.len() >= 3 {
            let mut winnow_matched_count = 0;
            let mut winnow_evidence = Vec::new();

            // Sorted, so the evidence kept is the same on every run.
            let mut winnow_sorted: Vec<u64> = hunk.winnow_fingerprints.iter().copied().collect();
            winnow_sorted.sort_unstable();
            for whash in winnow_sorted {
                if unit.winnow_hashes.contains(&whash) {
                    winnow_matched_count += 1;
                    if winnow_evidence.len() < 5 {
                        let hex_key = format!("{:016x}", whash);
                        if let Some(ev) = fp.hash_to_evidence.get(&hex_key) {
                            let truncated: String = ev.chars().take(200).collect();
                            if !winnow_evidence.contains(&truncated) {
                                winnow_evidence.push(truncated);
                            }
                        }
                    }
                }
            }

            let winnow_confidence =
                winnow_matched_count as f64 / hunk.winnow_fingerprints.len() as f64;
            if winnow_confidence >= opts.winnow_threshold {
                findings.push(Finding {
                    detector: "D2".to_string(),
                    channel: "winnow".to_string(),
                    path: path.to_string(),
                    visibility: opts.visibility,
                    severity: Severity::Gate,
                    confidence: (winnow_confidence * 100.0).round() / 100.0,
                    hunk: Some(hunk.hunk_index),
                    evidence: winnow_evidence,
                });
            }
        }
    }

    findings
}

pub fn match_unit(
    text: &str,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    detector: &str,
    channel: &str,
    path: &str,
) -> Vec<Finding> {
    match_unit_hashes(
        &compute_unit_hashes(text),
        fp,
        opts,
        detector,
        channel,
        path,
    )
}

/// Scan a problem statement for leaks (D0).
pub fn scan_problem_statement(text: &str, fp: &FingerprintSet, opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    let problem_path = "agent/problem_statement.md";

    findings.extend(match_unit(
        text,
        fp,
        opts,
        "D0",
        "problem_statement",
        problem_path,
    ));

    // Code blocks inside it (``` fences)
    let mut in_code_block = false;
    let mut current_block = Vec::new();

    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if in_code_block {
                let block_text = current_block.join("\n");
                findings.extend(match_unit(
                    &block_text,
                    fp,
                    opts,
                    "D0",
                    "problem_statement",
                    problem_path,
                ));
                current_block.clear();
                in_code_block = false;
            } else {
                in_code_block = true;
                current_block.clear();
            }
        } else if in_code_block {
            current_block.push(line);
        }
    }

    findings
}

/// What the tree walk reports besides units: the parts of `scan_tree` that need the live
/// tree or the task (D1 git stores, D3 `.pyc` headers) and each loose file's metadata.
pub trait TreeSink: UnitSink {
    /// A git directory found by the walk (D1).
    fn git_repo(&mut self, dir: &Path);
    /// A D1 finding made by the walk itself (a `.git` pointer file or symlink).
    fn d1_finding(&mut self, finding: Finding);
    /// A loose `.pyc`, before it is read, for its D3 header check.
    fn pyc_file(&mut self, path: &Path, display_path: &str);
    /// A loose file the walk is about to read, with its metadata.
    fn loose_file(&mut self, display_path: &str, metadata: &std::fs::Metadata);
    /// A directory reached by the walk, with its metadata.
    fn directory(&mut self, _display_path: &str, _metadata: &std::fs::Metadata) {}
    /// A symlink reached by the walk, with its metadata (via symlink_metadata).
    fn symlink(&mut self, _display_path: &str, _metadata: &std::fs::Metadata) {}
}

/// The sink `scan_tree` uses: `MatchSink` plus the D1 and D3 checks.
struct TreeMatchSink<'a> {
    inner: MatchSink<'a>,
    d4_paths: HashSet<String>,
}

impl UnitSink for TreeMatchSink<'_> {
    fn fixed(&mut self, finding: Finding) {
        self.inner.fixed(finding);
    }
    fn path(&mut self, match_path: &str, display_path: &str) {
        self.inner.path(match_path, display_path);
    }
    fn text(&mut self, path: &str, text: &str) {
        self.inner.text(path, text);
    }
    fn binary(&mut self, path: &str, channel: &str, strings: crate::binary::BinaryStrings) {
        self.inner.binary(path, channel, strings);
    }
    fn pkg_metadata(&mut self, path: &str, bytes: &[u8]) {
        self.inner.pkg_metadata(path, bytes);
    }
    fn member_time(&mut self, path: &str, unix_secs: i64) {
        self.inner.member_time(path, unix_secs);
    }
}

impl TreeSink for TreeMatchSink<'_> {
    fn git_repo(&mut self, dir: &Path) {
        let found = crate::d1::scan_git_repo(dir, self.inner.fp, self.inner.opts);
        self.inner.findings.extend(found);
    }
    fn d1_finding(&mut self, finding: Finding) {
        self.inner.findings.push(finding);
    }
    fn pyc_file(&mut self, path: &Path, display_path: &str) {
        match check_pyc_bytecode(path, self.inner.opts.visibility) {
            Ok(d3_findings) => self.inner.findings.extend(d3_findings),
            Err(e) => self.inner.findings.push(Finding {
                detector: "D2".into(),
                channel: "scan_error".into(),
                path: display_path.to_string(),
                visibility: self.inner.opts.visibility,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!("pyc check error: {e}")],
            }),
        }
    }
    fn loose_file(&mut self, display_path: &str, metadata: &std::fs::Metadata) {
        check_live_mtime(
            display_path,
            metadata,
            self.inner.opts.t_clock,
            self.inner.opts.visibility,
            &mut self.d4_paths,
            &mut self.inner.findings,
        );
    }
    fn directory(&mut self, display_path: &str, metadata: &std::fs::Metadata) {
        check_live_mtime(
            display_path,
            metadata,
            self.inner.opts.t_clock,
            self.inner.opts.visibility,
            &mut self.d4_paths,
            &mut self.inner.findings,
        );
    }
    fn symlink(&mut self, display_path: &str, metadata: &std::fs::Metadata) {
        check_live_mtime(
            display_path,
            metadata,
            self.inner.opts.t_clock,
            self.inner.opts.visibility,
            &mut self.d4_paths,
            &mut self.inner.findings,
        );
    }
}

pub fn format_rfc3339(dt: time::OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| dt.to_string())
}

pub fn format_mtime(secs: i64, nanos: u32) -> String {
    let total_nanos = (secs as i128) * 1_000_000_000 + (nanos as i128);
    match time::OffsetDateTime::from_unix_timestamp_nanos(total_nanos) {
        Ok(dt) => format_rfc3339(dt),
        Err(_) => format!("{secs}s"),
    }
}

/// Check loose file, directory, or symlink mtime against `T_clock` (D4).
///
/// Note: On a live tree, we do NOT check ctime or atime because the host sets
/// them on extraction or archive unpacking, so they always appear new.
fn check_live_mtime(
    display_path: &str,
    metadata: &std::fs::Metadata,
    t_clock: Option<time::OffsetDateTime>,
    visibility: Visibility,
    d4_paths: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let Some(tc) = t_clock else { return };
    if d4_paths.contains(display_path) {
        return;
    }
    let mtime = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return,
    };
    let (mtime_secs, mtime_nanos) = match mtime.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => (
            i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            d.subsec_nanos(),
        ),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            if d.subsec_nanos() == 0 {
                (-secs, 0)
            } else {
                (-secs - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    };
    let t_secs = tc.unix_timestamp();
    let t_nanos = tc.nanosecond();
    let is_later = (mtime_secs > t_secs) || (mtime_secs == t_secs && mtime_nanos > t_nanos);
    if is_later {
        let mtime_str = format_mtime(mtime_secs, mtime_nanos);
        let t_clock_str = format_rfc3339(tc);
        findings.push(Finding {
            detector: "D4".into(),
            channel: "mtime".into(),
            path: display_path.to_string(),
            visibility,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec![format!("mtime {mtime_str} > T_clock {t_clock_str}")],
        });
        d4_paths.insert(display_path.to_string());
    }
}

/// Scan a filesystem tree for leaks (D2, D3, D9, containers, tier 1, tier 3).
pub fn scan_tree(root: &Path, fp: &FingerprintSet, opts: &ScanOptions) -> Vec<Finding> {
    let sink = TreeMatchSink {
        inner: MatchSink::new(fp, &opts.signatures, opts),
        d4_paths: HashSet::new(),
    };
    walk_tree(root, opts, sink).inner.findings
}

/// Walk `root` as `scan_tree` does (pruning, symlinks, size limits, container recursion)
/// and report everything to `sink`. Returns the sink.
pub fn walk_tree<S: TreeSink>(root: &Path, opts: &ScanOptions, mut sink: S) -> S {
    let root_str = root.display().to_string();
    let root_prefix_len = root_str.len();

    let is_git_dir = |p: &Path| {
        p.join("HEAD").is_file() && p.join("objects").is_dir() && p.join("refs").is_dir()
    };

    if is_git_dir(root) {
        sink.git_repo(root);
    }

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        let path = e.path();
        if root == Path::new("/") {
            let path_str = path.to_string_lossy();
            if path_str == "/proc" || path_str == "/sys" || path_str == "/dev" {
                return false;
            }
        }
        if e.file_type().is_dir() {
            if e.file_name() == "objects" && path.parent().is_some_and(is_git_dir) {
                return false;
            }
            if !opts.exclude_dirs.is_empty() {
                if let Ok(canon) = path.canonicalize() {
                    return !opts.exclude_dirs.iter().any(|d| canon.starts_with(d));
                }
            }
        }
        true
    });

    let error_finding = |path: String, what: String| Finding {
        detector: "D2".into(),
        channel: "scan_error".into(),
        path,
        visibility: opts.visibility,
        severity: Severity::Info,
        confidence: 0.0,
        hunk: None,
        evidence: vec![what],
    };

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let path = e
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| root.display().to_string());
                sink.fixed(error_finding(path, format!("walk error: {e}")));
                continue;
            }
        };
        let file_path = entry.path();
        let display_path = file_path.display().to_string();

        if entry.path_is_symlink() {
            if let Ok(sym_meta) = std::fs::symlink_metadata(file_path) {
                sink.symlink(&display_path, &sym_meta);
            }
            if entry.file_name() == ".git" {
                sink.d1_finding(Finding {
                    detector: "D1".into(),
                    channel: "git_pointer".into(),
                    path: display_path.clone(),
                    visibility: opts.visibility,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec!["symlink named .git".into()],
                });
            }
        }

        let metadata = if entry.path_is_symlink() {
            match std::fs::metadata(file_path) {
                Ok(m) if m.is_file() => m,
                Ok(_) => {
                    sink.fixed(error_finding(
                        display_path,
                        "symlink to a non-file not followed".into(),
                    ));
                    continue;
                }
                Err(e) => {
                    sink.fixed(error_finding(display_path, format!("broken symlink: {e}")));
                    continue;
                }
            }
        } else if entry.file_type().is_file() {
            if entry.file_name() == ".git" {
                sink.d1_finding(Finding {
                    detector: "D1".into(),
                    channel: "git_pointer".into(),
                    path: display_path.clone(),
                    visibility: opts.visibility,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec!["git pointer file present".into()],
                });
            }
            match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    sink.fixed(error_finding(display_path, format!("metadata error: {e}")));
                    continue;
                }
            }
        } else if entry.file_type().is_dir() {
            if let Ok(dir_meta) = entry.metadata() {
                sink.directory(&display_path, &dir_meta);
            }
            if file_path != root && is_git_dir(file_path) {
                sink.git_repo(file_path);
            }
            continue;
        } else {
            continue;
        };

        sink.loose_file(&display_path, &metadata);

        // Size check for loose file
        if metadata.len() > opts.max_file_bytes {
            let is_large_archive = if metadata.len() <= opts.max_member_bytes {
                if let Ok(mut f) = File::open(file_path) {
                    let mut head = [0u8; 512];
                    if let Ok(n) = f.read(&mut head) {
                        matches!(
                            detect_container_type(&head[..n], &display_path),
                            Some(
                                ContainerType::Zip
                                    | ContainerType::Tar
                                    | ContainerType::Gzip
                                    | ContainerType::Bzip2
                                    | ContainerType::Xz
                                    | ContainerType::Zstd
                            )
                        )
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if !is_large_archive {
                sink.fixed(Finding {
                    detector: "D2".into(),
                    channel: "file".into(),
                    path: display_path,
                    visibility: opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!(
                        "skipped file exceeding max size ({} bytes > {} bytes)",
                        metadata.len(),
                        opts.max_file_bytes
                    )],
                });
                continue;
            }
        }

        // Loose .pyc check: PEP 552 bytecode check (D3)
        let is_pyc = file_path.extension().is_some_and(|ext| ext == "pyc");
        if is_pyc {
            sink.pyc_file(file_path, &display_path);
        }

        // Read file bytes
        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                sink.fixed(error_finding(display_path, format!("read error: {e}")));
                continue;
            }
        };

        let mut scanner = ContainerScanner::new(opts, sink, root_prefix_len);
        scanner.scan(&display_path, &bytes, 0);
        sink = scanner.sink;
    }

    sink
}
