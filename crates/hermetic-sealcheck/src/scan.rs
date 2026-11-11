use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;

use hermetic_common::hash::sha256_hex;

use crate::benchmark::BenchmarkSignatures;
use crate::bytecode::check_pyc_bytecode;
use crate::containers::scan_container_or_unit;
use crate::diff::parse_patch;
use crate::fingerprint::FingerprintSet;
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
    pub visibility: Visibility,
    pub max_depth: usize,
    pub max_member_bytes: u64,
    pub max_total_expanded_bytes: u64,
    pub max_ratio: f64,
    pub signatures: BenchmarkSignatures,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024, // 64 MiB
            hunk_threshold: 0.60,
            winnow_threshold: 0.60,
            visibility: Visibility::AgentVisible,
            max_depth: 4,
            max_member_bytes: 256 * 1024 * 1024, // 256 MiB
            max_total_expanded_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_ratio: 200.0,
            signatures: BenchmarkSignatures::new(None),
        }
    }
}

/// Hashes extracted from a single scanned text unit.
struct UnitHashes {
    line_hashes: HashSet<String>,
    window_hashes: HashSet<String>,
    removed_marker_hashes: HashSet<String>,
    diff_shape_hashes: HashSet<String>,
    winnow_hashes: HashSet<u64>,
}

fn compute_unit_hashes(text: &str) -> UnitHashes {
    let mut line_hashes = HashSet::new();
    let mut window_hashes = HashSet::new();
    let mut removed_marker_hashes = HashSet::new();
    let mut diff_shape_hashes = HashSet::new();

    let lines: Vec<&str> = text.lines().collect();

    // 1. Regular lines and 2/3-line windows
    for line in &lines {
        if let Some(norm) = normalize_line(line) {
            line_hashes.insert(sha256_hex(norm.as_bytes()));
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
                window_hashes.insert(sha256_hex(norm_w.as_bytes()));
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
                window_hashes.insert(sha256_hex(norm_w.as_bytes()));
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
                    line_hashes.insert(sha256_hex(norm.as_bytes()));
                }
            }
        }

        for line in &lines {
            if line.starts_with('-') {
                if let Some(norm) = normalize_diff_line(line) {
                    let marker = format!("-{}", norm);
                    removed_marker_hashes.insert(sha256_hex(marker.as_bytes()));
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
                    window_hashes.insert(sha256_hex(norm_w.as_bytes()));
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
                    window_hashes.insert(sha256_hex(norm_w.as_bytes()));
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
                let shape_h = sha256_hex(format!("{}\n{}", file_path, headers).as_bytes());
                diff_shape_hashes.insert(shape_h);

                let mut diff_seq = Vec::new();
                for h in &file.hunks {
                    for l in &h.lines {
                        if l.line_type == crate::diff::DiffLineType::Added {
                            if let Some(norm) = normalize_diff_line(&l.content) {
                                diff_seq.push(format!("+{}", norm));
                            }
                        } else if l.line_type == crate::diff::DiffLineType::Removed {
                            if let Some(norm) = normalize_diff_line(&l.content) {
                                diff_seq.push(format!("-{}", norm));
                            }
                        }
                    }
                }
                let shape_s =
                    sha256_hex(format!("{}\n{}", file_path, diff_seq.join("\n")).as_bytes());
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

pub fn match_unit(
    text: &str,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    detector: &str,
    channel: &str,
    path: &str,
) -> Vec<Finding> {
    let unit = compute_unit_hashes(text);
    let mut findings = Vec::new();

    // 1. Check diff shapes
    for shape in &unit.diff_shape_hashes {
        if fp.diff_shape_hashes.contains(shape) {
            let evidence_str = fp
                .hash_to_evidence
                .get(shape)
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

        for (hash, &weight) in &hunk.line_fingerprints {
            if unit.line_hashes.contains(hash) {
                matched_line_weight += weight;
                if matched_evidence.len() < 5 {
                    if let Some(ev) = fp.hash_to_evidence.get(hash) {
                        let truncated: String = ev.chars().take(200).collect();
                        if !matched_evidence.contains(&truncated) {
                            matched_evidence.push(truncated);
                        }
                    }
                }
            }
        }

        for (hash, &weight) in &hunk.window_fingerprints {
            if unit.window_hashes.contains(hash) {
                matched_window_weight += weight;
                if matched_evidence.len() < 5 {
                    if let Some(ev) = fp.hash_to_evidence.get(hash) {
                        let truncated: String = ev.chars().take(200).collect();
                        if !matched_evidence.contains(&truncated) {
                            matched_evidence.push(truncated);
                        }
                    }
                }
            }
        }

        for (hash, &weight) in &hunk.removed_markers {
            if unit.removed_marker_hashes.contains(hash) {
                matched_removed_weight += weight;
                if matched_evidence.len() < 5 {
                    if let Some(ev) = fp.hash_to_evidence.get(hash) {
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

            for &whash in &hunk.winnow_fingerprints {
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

/// Scan a filesystem tree for leaks (D2, D3, D9, containers, tier 1, tier 3).
pub fn scan_tree(root: &Path, fp: &FingerprintSet, opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        let path = e.path();
        if root == Path::new("/") {
            let path_str = path.to_string_lossy();
            if path_str == "/proc" || path_str == "/sys" || path_str == "/dev" {
                return false;
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
                findings.push(error_finding(path, format!("walk error: {e}")));
                continue;
            }
        };
        let file_path = entry.path();
        let display_path = file_path.display().to_string();

        let metadata = if entry.path_is_symlink() {
            match std::fs::metadata(file_path) {
                Ok(m) if m.is_file() => m,
                Ok(_) => {
                    findings.push(error_finding(
                        display_path,
                        "symlink to a non-file not followed".into(),
                    ));
                    continue;
                }
                Err(e) => {
                    findings.push(error_finding(display_path, format!("broken symlink: {e}")));
                    continue;
                }
            }
        } else if entry.file_type().is_file() {
            match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    findings.push(error_finding(display_path, format!("metadata error: {e}")));
                    continue;
                }
            }
        } else {
            continue;
        };

        // Size check for loose file
        if metadata.len() > opts.max_file_bytes {
            findings.push(Finding {
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

        // Loose .pyc check: PEP 552 bytecode check (D3)
        let is_pyc = file_path.extension().is_some_and(|ext| ext == "pyc");
        if is_pyc {
            match check_pyc_bytecode(file_path, opts.visibility) {
                Ok(d3_findings) => findings.extend(d3_findings),
                Err(e) => {
                    findings.push(error_finding(
                        display_path.clone(),
                        format!("pyc check error: {e}"),
                    ));
                }
            }
        }

        // Read file bytes
        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                findings.push(error_finding(display_path, format!("read error: {e}")));
                continue;
            }
        };

        let unit_findings =
            scan_container_or_unit(&display_path, &bytes, fp, &opts.signatures, opts);
        findings.extend(unit_findings);
    }

    findings
}
