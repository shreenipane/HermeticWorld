use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use hermetic_common::hash::sha256_hex;
use sha2::{Digest, Sha256};

use crate::diff::{parse_patch, DiffLineType, DiffParseError, FilePatch};
use crate::normalize::{clean_line, normalize_line};
use crate::winnow::{kgram_hashes, tokenize, winnow_tokens};

/// Convert the first 8 bytes of a byte slice's SHA-256 hash to a u64 in little-endian.
pub fn sha256_u64(bytes: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// Convert a 64-char sha256 hex string's first 8 bytes to a u64 in little-endian.
pub fn hex_to_u64(hex_str: &str) -> Option<u64> {
    if hex_str.len() < 16 {
        return None;
    }
    let mut bytes = [0u8; 8];
    hex::decode_to_slice(&hex_str[..16], &mut bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    #[error("Diff parse error: {0}")]
    Diff(#[from] DiffParseError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct HunkFingerprints {
    pub hunk_index: usize,
    pub file_path: String,
    /// Line fingerprint hashes and their raw weights
    pub line_fingerprints: HashMap<String, f64>,
    pub total_line_weight: f64,
    /// Window fingerprint hashes and their raw weights
    pub window_fingerprints: HashMap<String, f64>,
    pub total_window_weight: f64,
    /// Removed-line marker hashes ("-" + norm) and their raw weights
    pub removed_markers: HashMap<String, f64>,
    pub total_removed_weight: f64,
    /// Diff shape hashes and their raw weights
    pub diff_shapes: HashMap<String, f64>,
    /// Tier 3 winnow fingerprints
    pub winnow_fingerprints: HashSet<u64>,
    /// Binary tier items (identifiers and string literals)
    pub binary_items: Vec<String>,
    /// Preconverted 64-bit line fingerprints: hash -> (weight, orig_hex_hash). Ordered, so
    /// matching (and so the evidence a finding keeps) is the same on every run.
    pub line_u64: BTreeMap<u64, (f64, String)>,
    /// Preconverted 64-bit window fingerprints: hash -> (weight, orig_hex_hash)
    pub window_u64: BTreeMap<u64, (f64, String)>,
    /// Preconverted 64-bit removed marker fingerprints: hash -> (weight, orig_hex_hash)
    pub removed_u64: BTreeMap<u64, (f64, String)>,
}

#[derive(Debug, Clone)]
pub struct FingerprintSet {
    pub hunks: Vec<HunkFingerprints>,
    pub diff_shape_hashes: HashSet<String>,
    pub diff_shape_u64: BTreeMap<u64, String>,
    pub lines_count: usize,
    pub windows_count: usize,
    pub removed_markers_count: usize,
    pub diff_shapes_count: usize,
    pub subtracted_count: usize,
    pub winnow_count: usize,
    pub winnow_subtracted_count: usize,
    pub binary_items_count: usize,
    pub binary_subtracted_count: usize,
    /// Maps fingerprint hash to representative evidence text
    pub hash_to_evidence: HashMap<String, String>,
    pub skipped_files_count: usize,
}

struct CandidateHunk {
    hunk_index: usize,
    file_path: String,
    lines: Vec<(String, String)>,           // (hash, norm)
    windows: Vec<(String, Vec<String>)>,    // (hash, window_lines)
    removed_markers: Vec<(String, String)>, // (hash, norm)
    diff_shapes: Vec<(String, String)>,     // (hash, description)
    winnow_candidates: Vec<(u64, String)>,  // (hash, evidence)
    binary_items: Vec<String>,
}

fn apply_patch_to_base(
    file_patch: &FilePatch,
    base_tree_root: &Path,
) -> (Vec<String>, Vec<Vec<usize>>) {
    let rel_path = file_patch
        .old_path
        .as_deref()
        .or(file_patch.new_path.as_deref())
        .unwrap_or("");

    let base_file_path = base_tree_root.join(rel_path);
    let base_lines: Option<Vec<String>> = if base_file_path.exists() {
        read_text_like_scanner(&base_file_path).map(|s| s.lines().map(|l| l.to_string()).collect())
    } else {
        None
    };

    let mut post_fix = Vec::new();
    let mut hunk_changed_positions = Vec::new();

    if let Some(base) = base_lines {
        let mut base_idx = 0; // 0-based line index in base file

        for hunk in &file_patch.hunks {
            let mut changed = Vec::new();
            let hunk_start = if hunk.header.old_range.start > 0 {
                hunk.header.old_range.start - 1
            } else {
                0
            };

            // Copy base lines before this hunk
            while base_idx < hunk_start && base_idx < base.len() {
                post_fix.push(base[base_idx].clone());
                base_idx += 1;
            }

            let mut hunk_has_added = false;
            let mut deletion_pos = None;

            for diff_line in &hunk.lines {
                match diff_line.line_type {
                    DiffLineType::Context => {
                        post_fix.push(diff_line.content.clone());
                        if base_idx < base.len() {
                            base_idx += 1;
                        }
                    }
                    DiffLineType::Added => {
                        hunk_has_added = true;
                        changed.push(post_fix.len());
                        post_fix.push(diff_line.content.clone());
                    }
                    DiffLineType::Removed => {
                        if deletion_pos.is_none() {
                            deletion_pos = Some(if post_fix.is_empty() {
                                0
                            } else {
                                post_fix.len() - 1
                            });
                        }
                        if base_idx < base.len() {
                            base_idx += 1;
                        }
                    }
                }
            }

            // For deletion-only hunks, mark the deletion boundary
            if !hunk_has_added {
                if let Some(pos) = deletion_pos {
                    changed.push(pos);
                }
            }

            hunk_changed_positions.push(changed);
        }

        // Copy remaining base lines
        while base_idx < base.len() {
            post_fix.push(base[base_idx].clone());
            base_idx += 1;
        }
    } else {
        // Base file doesn't exist: for new file, gather all added lines
        for hunk in &file_patch.hunks {
            let mut changed = Vec::new();
            for diff_line in &hunk.lines {
                if diff_line.line_type == DiffLineType::Added {
                    changed.push(post_fix.len());
                    post_fix.push(diff_line.content.clone());
                }
            }
            hunk_changed_positions.push(changed);
        }
    }

    (post_fix, hunk_changed_positions)
}

/// Read a file as the tree scanner does: skip it if a NUL byte occurs in the first 8 KiB,
/// otherwise decode lossily as UTF-8.
fn read_text_like_scanner(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let head = &bytes[..bytes.len().min(8192)];
    if head.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

impl FingerprintSet {
    /// Build tier 1 and tier 3 fingerprints from gold patch, test patch, and base tree.
    pub fn from_task(
        gold_patch_str: &str,
        test_patch_str: &str,
        base_tree_root: &Path,
    ) -> Result<Self, FingerprintError> {
        let gold_patch = parse_patch(gold_patch_str)?;
        let test_patch = parse_patch(test_patch_str)?;

        let mut candidate_hunks: Vec<CandidateHunk> = Vec::new();
        let mut global_hunk_counter = 0;

        // 1. Process gold patch
        for file in &gold_patch.files {
            let file_path = file
                .new_path
                .as_deref()
                .or(file.old_path.as_deref())
                .unwrap_or("")
                .to_string();

            let (post_fix_lines, hunk_changed_positions) =
                apply_patch_to_base(file, base_tree_root);

            let post_fix_text = post_fix_lines.join("\n");
            let all_tokens = tokenize(&post_fix_text);

            // File-level diff shapes
            let headers = file
                .hunks
                .iter()
                .map(|h| h.raw_header.trim())
                .collect::<Vec<_>>()
                .join("\n");
            let diff_shape_headers = sha256_hex(format!("{}\n{}", file_path, headers).as_bytes());

            let mut diff_lines_seq = Vec::new();
            for h in &file.hunks {
                for l in &h.lines {
                    if l.line_type == DiffLineType::Added {
                        if let Some(norm) = normalize_line(&l.content) {
                            diff_lines_seq.push(format!("+{}", norm));
                        }
                    } else if l.line_type == DiffLineType::Removed {
                        if let Some(norm) = normalize_line(&l.content) {
                            diff_lines_seq.push(format!("-{}", norm));
                        }
                    }
                }
            }
            let diff_shape_seq =
                sha256_hex(format!("{}\n{}", file_path, diff_lines_seq.join("\n")).as_bytes());

            for (hunk_idx, hunk) in file.hunks.iter().enumerate() {
                let mut lines = Vec::new();
                let mut removed_markers = Vec::new();
                let mut windows = Vec::new();
                let mut diff_shapes = Vec::new();
                let mut winnow_candidates = Vec::new();

                // Diff shapes attached to first hunk
                if hunk_idx == 0 {
                    diff_shapes.push((
                        diff_shape_headers.clone(),
                        format!("diff-shape:headers:{}", file_path),
                    ));
                    diff_shapes.push((
                        diff_shape_seq.clone(),
                        format!("diff-shape:seq:{}", file_path),
                    ));
                }

                // Added and removed lines
                for diff_line in &hunk.lines {
                    match diff_line.line_type {
                        DiffLineType::Added => {
                            if let Some(norm) = normalize_line(&diff_line.content) {
                                let hash = sha256_hex(norm.as_bytes());
                                lines.push((hash, norm));
                            }
                        }
                        DiffLineType::Removed => {
                            if let Some(norm) = normalize_line(&diff_line.content) {
                                let marker = format!("-{}", norm);
                                let hash = sha256_hex(marker.as_bytes());
                                removed_markers.push((hash, marker));
                            }
                        }
                        DiffLineType::Context => {}
                    }
                }

                // Windows in post-fix file spanning changed positions
                if let Some(changed_pos) = hunk_changed_positions.get(hunk_idx) {
                    let mut seen_windows = HashSet::new();

                    for &pos in changed_pos {
                        // 2-line windows
                        if pos > 0 && pos < post_fix_lines.len() {
                            let w =
                                vec![post_fix_lines[pos - 1].clone(), post_fix_lines[pos].clone()];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let hash = sha256_hex(norm_w.as_bytes());
                                if seen_windows.insert(hash.clone()) {
                                    windows.push((hash, w));
                                }
                            }
                        }
                        if pos + 1 < post_fix_lines.len() {
                            let w =
                                vec![post_fix_lines[pos].clone(), post_fix_lines[pos + 1].clone()];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let hash = sha256_hex(norm_w.as_bytes());
                                if seen_windows.insert(hash.clone()) {
                                    windows.push((hash, w));
                                }
                            }
                        }

                        // 3-line windows
                        if pos >= 2 && pos < post_fix_lines.len() {
                            let w = vec![
                                post_fix_lines[pos - 2].clone(),
                                post_fix_lines[pos - 1].clone(),
                                post_fix_lines[pos].clone(),
                            ];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let hash = sha256_hex(norm_w.as_bytes());
                                if seen_windows.insert(hash.clone()) {
                                    windows.push((hash, w));
                                }
                            }
                        }
                        if pos >= 1 && pos + 1 < post_fix_lines.len() {
                            let w = vec![
                                post_fix_lines[pos - 1].clone(),
                                post_fix_lines[pos].clone(),
                                post_fix_lines[pos + 1].clone(),
                            ];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let hash = sha256_hex(norm_w.as_bytes());
                                if seen_windows.insert(hash.clone()) {
                                    windows.push((hash, w));
                                }
                            }
                        }
                        if pos + 2 < post_fix_lines.len() {
                            let w = vec![
                                post_fix_lines[pos].clone(),
                                post_fix_lines[pos + 1].clone(),
                                post_fix_lines[pos + 2].clone(),
                            ];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let hash = sha256_hex(norm_w.as_bytes());
                                if seen_windows.insert(hash.clone()) {
                                    windows.push((hash, w));
                                }
                            }
                        }
                    }

                    // Tier 3 winnowing: restricted to token range overlapping changed lines plus 15 tokens
                    let changed_line_set: HashSet<usize> = changed_pos.iter().copied().collect();
                    let matching_token_indices: Vec<usize> = all_tokens
                        .iter()
                        .enumerate()
                        .filter(|(_, tok)| changed_line_set.contains(&tok.line))
                        .map(|(idx, _)| idx)
                        .collect();

                    if !matching_token_indices.is_empty() {
                        let t_min = *matching_token_indices.iter().min().unwrap_or(&0);
                        let t_max = *matching_token_indices.iter().max().unwrap_or(&0);
                        let t_start = t_min.saturating_sub(15);
                        let t_end = (t_max + 15 + 1).min(all_tokens.len());

                        let slice = &all_tokens[t_start..t_end];
                        let token_texts: Vec<String> =
                            slice.iter().map(|t| t.text.clone()).collect();
                        let fps = winnow_tokens(&token_texts);

                        for fp in fps {
                            let ev_end = (fp.token_pos + 8).min(token_texts.len());
                            let ev = token_texts[fp.token_pos..ev_end].join(" ");
                            winnow_candidates.push((fp.hash, ev));
                        }
                    }
                }

                // Binary tier items from added lines only
                let mut added_lines = Vec::new();
                for diff_line in &hunk.lines {
                    if diff_line.line_type == DiffLineType::Added {
                        added_lines.push(diff_line.content.as_str());
                    }
                }
                let raw_items = crate::binary::extract_binary_items(&added_lines.join("\n"));
                let mut seen_items = HashSet::new();
                let mut binary_items = Vec::new();
                for it in raw_items {
                    if seen_items.insert(it.clone()) {
                        binary_items.push(it);
                    }
                }

                candidate_hunks.push(CandidateHunk {
                    hunk_index: global_hunk_counter,
                    file_path: file_path.clone(),
                    lines,
                    windows,
                    removed_markers,
                    diff_shapes,
                    winnow_candidates,
                    binary_items,
                });
                global_hunk_counter += 1;
            }
        }

        // 2. Process test patch (lines added by test patch)
        for file in &test_patch.files {
            let file_path = file
                .new_path
                .as_deref()
                .or(file.old_path.as_deref())
                .unwrap_or("")
                .to_string();

            for hunk in &file.hunks {
                let mut lines = Vec::new();
                for diff_line in &hunk.lines {
                    if diff_line.line_type == DiffLineType::Added {
                        if let Some(norm) = normalize_line(&diff_line.content) {
                            let hash = sha256_hex(norm.as_bytes());
                            lines.push((hash, norm));
                        }
                    }
                }
                if !lines.is_empty() {
                    candidate_hunks.push(CandidateHunk {
                        hunk_index: global_hunk_counter,
                        file_path: file_path.clone(),
                        lines,
                        windows: Vec::new(),
                        removed_markers: Vec::new(),
                        diff_shapes: Vec::new(),
                        winnow_candidates: Vec::new(),
                        binary_items: Vec::new(),
                    });
                    global_hunk_counter += 1;
                }
            }
        }

        Ok(finish_fingerprint_set(candidate_hunks, base_tree_root, 0))
    }

    /// Build tier 1, tier 3, and binary tier fingerprints from task files in undated mode (TR-SC-9).
    pub fn from_files(
        files: &[(String, String)],
        base_tree: &Path,
    ) -> Result<Self, FingerprintError> {
        const MAX_FILE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
        const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

        let mut total_bytes = 0usize;
        let mut skipped_files_count = 0usize;
        let mut candidate_hunks: Vec<CandidateHunk> = Vec::new();
        let mut global_hunk_counter = 0;

        for (file_path, text) in files {
            let file_bytes = text.len();
            if file_bytes > MAX_FILE_BYTES
                || total_bytes.saturating_add(file_bytes) > MAX_TOTAL_BYTES
            {
                skipped_files_count += 1;
                continue;
            }
            total_bytes += file_bytes;

            let bytes = text.as_bytes();
            let head = &bytes[..bytes.len().min(8192)];
            let is_binary = head.contains(&0);

            if is_binary {
                // Files that are binary (NUL in the first 8 KiB) contribute only binary-tier items
                // from their printable runs of 8+ characters.
                let runs = crate::binary::extract_printable_runs(bytes, 8);
                let mut seen_items = HashSet::new();
                let mut binary_items = Vec::new();
                for run in runs {
                    if !run.chars().any(char::is_control) && seen_items.insert(run.clone()) {
                        binary_items.push(run.clone());
                    }
                    for token in crate::binary::word_tokens(&run) {
                        if token.len() >= 8 && !token.chars().any(char::is_control) {
                            let token_str = token.to_string();
                            if seen_items.insert(token_str.clone()) {
                                binary_items.push(token_str);
                            }
                        }
                    }
                }
                candidate_hunks.push(CandidateHunk {
                    hunk_index: global_hunk_counter,
                    file_path: file_path.clone(),
                    lines: Vec::new(),
                    windows: Vec::new(),
                    removed_markers: Vec::new(),
                    diff_shapes: Vec::new(),
                    winnow_candidates: Vec::new(),
                    binary_items,
                });
                global_hunk_counter += 1;
            } else {
                let file_lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();

                let mut lines = Vec::new();
                for line in &file_lines {
                    if let Some(norm) = normalize_line(line) {
                        let hash = sha256_hex(norm.as_bytes());
                        lines.push((hash, norm));
                    }
                }

                let mut windows = Vec::new();
                let mut seen_windows = HashSet::new();
                for i in 0..file_lines.len() {
                    if i + 1 < file_lines.len() {
                        let w = vec![file_lines[i].clone(), file_lines[i + 1].clone()];
                        if !w.iter().all(|l| normalize_line(l).is_none()) {
                            let norm_w = w
                                .iter()
                                .map(|l| clean_line(l, false))
                                .collect::<Vec<_>>()
                                .join("\n");
                            let hash = sha256_hex(norm_w.as_bytes());
                            if seen_windows.insert(hash.clone()) {
                                windows.push((hash, w));
                            }
                        }
                    }
                    if i + 2 < file_lines.len() {
                        let w = vec![
                            file_lines[i].clone(),
                            file_lines[i + 1].clone(),
                            file_lines[i + 2].clone(),
                        ];
                        if !w.iter().all(|l| normalize_line(l).is_none()) {
                            let norm_w = w
                                .iter()
                                .map(|l| clean_line(l, false))
                                .collect::<Vec<_>>()
                                .join("\n");
                            let hash = sha256_hex(norm_w.as_bytes());
                            if seen_windows.insert(hash.clone()) {
                                windows.push((hash, w));
                            }
                        }
                    }
                }

                let mut diff_shapes = Vec::new();
                if !file_lines.is_empty() {
                    let raw_header = if file_lines.len() == 1 {
                        "@@ -0,0 +1 @@".to_string()
                    } else {
                        format!("@@ -0,0 +1,{} @@", file_lines.len())
                    };
                    let diff_shape_headers =
                        sha256_hex(format!("{}\n{}", file_path, raw_header).as_bytes());

                    let mut diff_lines_seq = Vec::new();
                    for line in &file_lines {
                        if let Some(norm) = normalize_line(line) {
                            diff_lines_seq.push(format!("+{}", norm));
                        }
                    }
                    let diff_shape_seq = sha256_hex(
                        format!("{}\n{}", file_path, diff_lines_seq.join("\n")).as_bytes(),
                    );

                    diff_shapes.push((
                        diff_shape_headers,
                        format!("diff-shape:headers:{}", file_path),
                    ));
                    diff_shapes.push((diff_shape_seq, format!("diff-shape:seq:{}", file_path)));
                }

                let all_tokens = tokenize(text);
                let token_texts: Vec<String> = all_tokens.iter().map(|t| t.text.clone()).collect();
                let fps = winnow_tokens(&token_texts);
                let mut winnow_candidates = Vec::new();
                for fp in fps {
                    let ev_end = (fp.token_pos + 8).min(token_texts.len());
                    let ev = token_texts[fp.token_pos..ev_end].join(" ");
                    winnow_candidates.push((fp.hash, ev));
                }

                let raw_items = crate::binary::extract_binary_items(text);
                let mut seen_items = HashSet::new();
                let mut binary_items = Vec::new();
                for it in raw_items {
                    if seen_items.insert(it.clone()) {
                        binary_items.push(it);
                    }
                }

                candidate_hunks.push(CandidateHunk {
                    hunk_index: global_hunk_counter,
                    file_path: file_path.clone(),
                    lines,
                    windows,
                    removed_markers: Vec::new(),
                    diff_shapes,
                    winnow_candidates,
                    binary_items,
                });
                global_hunk_counter += 1;
            }
        }

        Ok(finish_fingerprint_set(
            candidate_hunks,
            base_tree,
            skipped_files_count,
        ))
    }
}

fn finish_fingerprint_set(
    candidate_hunks: Vec<CandidateHunk>,
    base_tree_root: &Path,
    skipped_files_count: usize,
) -> FingerprintSet {
    // Baseline subtraction (TR-SC-1, TR-SC-4 & TR-SC-5): walk base_tree_root
    let mut base_line_counts: HashMap<String, usize> = HashMap::new();
    let mut base_line_hashes: HashSet<String> = HashSet::new();
    let mut base_window_hashes: HashSet<String> = HashSet::new();
    let mut base_winnow_hashes: HashSet<u64> = HashSet::new();
    let mut base_binary_tokens: HashSet<String> = HashSet::new();

    if base_tree_root.exists() {
        for entry in WalkDir::new(base_tree_root)
            .into_iter()
            .filter_entry(|e| e.file_name() != ".git")
            .flatten()
        {
            if entry.file_type().is_file() {
                // Decode the way the scanner does (lossy UTF-8, binary skipped), so every text unit the scanner can see at the base is also subtracted here.
                if let Some(content) = read_text_like_scanner(entry.path()) {
                    let file_lines: Vec<&str> = content.lines().collect();

                    // Line hashes & counts
                    for line in &file_lines {
                        if let Some(norm) = normalize_line(line) {
                            *base_line_counts.entry(norm.clone()).or_insert(0) += 1;
                            base_line_hashes.insert(sha256_hex(norm.as_bytes()));
                        }
                    }

                    // Window hashes
                    for i in 0..file_lines.len() {
                        if i + 1 < file_lines.len() {
                            let w = [file_lines[i], file_lines[i + 1]];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                base_window_hashes.insert(sha256_hex(norm_w.as_bytes()));
                            }
                        }
                        if i + 2 < file_lines.len() {
                            let w = [file_lines[i], file_lines[i + 1], file_lines[i + 2]];
                            if !w.iter().all(|l| normalize_line(l).is_none()) {
                                let norm_w = w
                                    .iter()
                                    .map(|l| clean_line(l, false))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                base_window_hashes.insert(sha256_hex(norm_w.as_bytes()));
                            }
                        }
                    }

                    // Winnow hashes and binary tokens for base tree
                    let base_tokens = tokenize(&content);
                    for tok in &base_tokens {
                        base_binary_tokens.insert(tok.text.clone());
                        if let Some(literal_content) =
                            crate::binary::extract_string_literal_content(&tok.text)
                        {
                            base_binary_tokens.insert(literal_content);
                        }
                    }
                    let base_token_texts: Vec<String> =
                        base_tokens.into_iter().map(|t| t.text).collect();
                    for hash in kgram_hashes(&base_token_texts) {
                        base_winnow_hashes.insert(hash);
                    }
                }
            }
        }
    }

    let mut subtracted_count = 0;
    let mut winnow_subtracted_count = 0;
    let mut binary_subtracted_count = 0;
    let mut final_hunks = Vec::new();
    let mut all_diff_shapes = HashSet::new();
    let mut hash_to_evidence = HashMap::new();

    let mut total_lines = 0;
    let mut total_windows = 0;
    let mut total_removed = 0;
    let mut total_shapes = 0;
    let mut total_winnow = 0;
    let mut total_binary_items = 0;

    for ch in candidate_hunks {
        let mut surviving_lines = Vec::new();
        for (hash, norm) in ch.lines {
            if base_line_hashes.contains(&hash) {
                subtracted_count += 1;
            } else {
                hash_to_evidence.insert(hash.clone(), norm.clone());
                surviving_lines.push((hash, norm));
            }
        }

        let mut surviving_windows = Vec::new();
        for (hash, w_lines) in ch.windows {
            if base_window_hashes.contains(&hash) {
                subtracted_count += 1;
            } else {
                let ev = w_lines
                    .iter()
                    .map(|l| clean_line(l, false))
                    .collect::<Vec<_>>()
                    .join(" / ");
                hash_to_evidence.insert(hash.clone(), ev);
                surviving_windows.push((hash, w_lines));
            }
        }

        for (hash, marker) in &ch.removed_markers {
            hash_to_evidence.insert(hash.clone(), marker.clone());
        }

        for (hash, desc) in &ch.diff_shapes {
            all_diff_shapes.insert(hash.clone());
            hash_to_evidence.insert(hash.clone(), desc.clone());
        }

        // Baseline subtraction for tier 3 winnow fingerprints
        let mut winnow_fingerprints = HashSet::new();
        for (hash, ev) in ch.winnow_candidates {
            if base_winnow_hashes.contains(&hash) {
                winnow_subtracted_count += 1;
            } else {
                winnow_fingerprints.insert(hash);
                hash_to_evidence.insert(format!("{:016x}", hash), ev);
            }
        }

        // Baseline subtraction for binary tier items
        let mut surviving_binary_items = Vec::new();
        for item in ch.binary_items {
            if base_binary_tokens.contains(&item) {
                binary_subtracted_count += 1;
            } else {
                surviving_binary_items.push(item);
            }
        }
        total_binary_items += surviving_binary_items.len();

        // Compute raw weights
        let mut line_fingerprints = HashMap::new();
        let mut total_line_weight = 0.0;
        for (hash, norm) in &surviving_lines {
            let count = base_line_counts.get(norm).copied().unwrap_or(0);
            // line: 1 / (1 + count)
            let w = 1.0 / (1.0 + count as f64);
            line_fingerprints.insert(hash.clone(), w);
            total_line_weight += w;
        }

        let mut window_fingerprints = HashMap::new();
        let mut total_window_weight = 0.0;
        for (hash, w_lines) in &surviving_windows {
            // window: minimum raw weight of its lines
            let min_w = w_lines
                .iter()
                .map(|l| {
                    let cleaned = clean_line(l, false);
                    let count = base_line_counts.get(&cleaned).copied().unwrap_or(0);
                    1.0 / (1.0 + count as f64)
                })
                .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or(1.0);
            window_fingerprints.insert(hash.clone(), min_w);
            total_window_weight += min_w;
        }

        let mut removed_map = HashMap::new();
        let mut total_removed_weight = 0.0;
        for (hash, marker) in &ch.removed_markers {
            let cleaned = marker.strip_prefix('-').unwrap_or(marker);
            let count = base_line_counts.get(cleaned).copied().unwrap_or(0);
            let w = 1.0 / (1.0 + count as f64);
            removed_map.insert(hash.clone(), w);
            total_removed_weight += w;
        }

        let mut diff_shapes_map = HashMap::new();
        for (hash, _) in &ch.diff_shapes {
            diff_shapes_map.insert(hash.clone(), 1.0);
        }

        total_lines += line_fingerprints.len();
        total_windows += window_fingerprints.len();
        total_removed += removed_map.len();
        total_shapes += diff_shapes_map.len();
        total_winnow += winnow_fingerprints.len();

        let mut line_u64 = BTreeMap::new();
        for (hash, &w) in &line_fingerprints {
            if let Some(u) = hex_to_u64(hash) {
                line_u64.insert(u, (w, hash.clone()));
            }
        }
        let mut window_u64 = BTreeMap::new();
        for (hash, &w) in &window_fingerprints {
            if let Some(u) = hex_to_u64(hash) {
                window_u64.insert(u, (w, hash.clone()));
            }
        }
        let mut removed_u64 = BTreeMap::new();
        for (hash, &w) in &removed_map {
            if let Some(u) = hex_to_u64(hash) {
                removed_u64.insert(u, (w, hash.clone()));
            }
        }

        final_hunks.push(HunkFingerprints {
            hunk_index: ch.hunk_index,
            file_path: ch.file_path,
            line_fingerprints,
            total_line_weight,
            window_fingerprints,
            total_window_weight,
            removed_markers: removed_map,
            total_removed_weight,
            diff_shapes: diff_shapes_map,
            winnow_fingerprints,
            binary_items: surviving_binary_items,
            line_u64,
            window_u64,
            removed_u64,
        });
    }

    let mut diff_shape_u64 = BTreeMap::new();
    for hash in &all_diff_shapes {
        if let Some(u) = hex_to_u64(hash) {
            diff_shape_u64.insert(u, hash.clone());
        }
    }

    FingerprintSet {
        hunks: final_hunks,
        diff_shape_hashes: all_diff_shapes,
        diff_shape_u64,
        lines_count: total_lines,
        windows_count: total_windows,
        removed_markers_count: total_removed,
        diff_shapes_count: total_shapes,
        subtracted_count,
        winnow_count: total_winnow,
        winnow_subtracted_count,
        binary_items_count: total_binary_items,
        binary_subtracted_count,
        hash_to_evidence,
        skipped_files_count,
    }
}
