use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
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
    #[error("Work budget exceeded")]
    WorkBudgetExceeded,
}

pub const DEFAULT_MAX_FINGERPRINT_WORK: usize = 1_000_000;

#[derive(Debug, Clone, Copy)]
pub struct WorkBudget {
    limit: usize,
    used: usize,
}

impl WorkBudget {
    pub fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    pub fn charge(&mut self, amount: usize) -> Result<(), FingerprintError> {
        self.used = self.used.saturating_add(amount);
        if self.used > self.limit {
            Err(FingerprintError::WorkBudgetExceeded)
        } else {
            Ok(())
        }
    }

    pub fn used(&self) -> usize {
        self.used
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PycFunctionFingerprint {
    pub function_name: String,
    pub added: HashSet<String>,
    pub removed: HashSet<String>,
    pub added_u64: Vec<u64>,
    pub removed_u64: Vec<u64>,
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
    /// .pyc function fingerprint (D3b)
    pub pyc_fingerprint: Option<PycFunctionFingerprint>,
    /// .pyc function fingerprints (D3b) for all functions changed by this hunk
    pub pyc_fingerprints: Vec<PycFunctionFingerprint>,
    /// Preconverted 64-bit line fingerprints: hash -> (weight, orig_hex_hash). Ordered, so
    /// matching (and so the evidence a finding keeps) is the same on every run.
    pub line_u64: BTreeMap<u64, (f64, String)>,
    /// Preconverted 64-bit window fingerprints: hash -> (weight, orig_hex_hash)
    pub window_u64: BTreeMap<u64, (f64, String)>,
    /// Preconverted 64-bit removed marker fingerprints: hash -> (weight, orig_hex_hash)
    pub removed_u64: BTreeMap<u64, (f64, String)>,
    /// Tier 2 anchors (file names, module path, enclosing functions/classes)
    pub tier2_anchors: Vec<String>,
    /// Tier 2 symbols and their IDF weights
    pub tier2_symbols: Vec<(String, f64)>,
    /// Tier 2 total symbol weight
    pub tier2_total_weight: f64,
}

impl HunkFingerprints {
    pub fn match_tier2(
        &self,
        text: &str,
        opts: &crate::scan::ScanOptions,
        detector: &str,
        path: &str,
    ) -> Option<crate::scan::Finding> {
        crate::tier2::match_tier2_for_unit(text, self, opts, detector, path)
    }

    pub fn match_tier2_with_context(
        &self,
        unit_symbols: &HashSet<String>,
        unit_anchor_tokens: &HashSet<String>,
        opts: &crate::scan::ScanOptions,
        detector: &str,
        path: &str,
    ) -> Option<crate::scan::Finding> {
        crate::tier2::match_tier2_with_context(
            unit_symbols,
            unit_anchor_tokens,
            self,
            opts,
            detector,
            path,
        )
    }
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
    pub baseline_incomplete: bool,
    pub baseline_skipped_bytes: u64,
    /// Whether base-tree scan was capped at 20,000 files or 200 MiB
    pub tier2_capped: bool,
    /// The base-tree Python files sampled for Tier 2 IDF
    pub tier2_chosen_files: Vec<PathBuf>,
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
    pyc_fingerprints: Vec<PycFunctionFingerprint>,
    tier2_anchors: Vec<String>,
    tier2_candidate_symbols: HashSet<String>,
}

fn apply_patch_to_base(
    file_patch: &FilePatch,
    base_tree_root: &Path,
) -> (Vec<String>, Vec<Vec<usize>>, Option<Vec<String>>) {
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

    if let Some(base) = &base_lines {
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

    (post_fix, hunk_changed_positions, base_lines)
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

const PYC_STOP_LIST: &[&str] = &["self", "cls", "None", "True", "False", "0", "1", ""];

fn get_line_indent(line: &str) -> Option<usize> {
    let mut count = 0;
    for c in line.chars() {
        if c == ' ' {
            count += 1;
        } else if c == '\t' {
            count += 8;
        } else if c == '#' {
            return None;
        } else {
            return Some(count);
        }
    }
    None
}

fn parse_def_or_class(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim_start();
    let (ident_part, is_class) = if let Some(rest) = trimmed.strip_prefix("def ") {
        (rest.trim_start(), false)
    } else if let Some(rest) = trimmed.strip_prefix("async def ") {
        (rest.trim_start(), false)
    } else {
        let rest = trimmed.strip_prefix("class ")?;
        (rest.trim_start(), true)
    };

    let mut end = 0;
    for (i, c) in ident_part.char_indices() {
        if i == 0 {
            if c.is_alphabetic() || c == '_' {
                end = c.len_utf8();
            } else {
                return None;
            }
        } else if c.is_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if end > 0 {
        Some((ident_part[..end].to_string(), is_class))
    } else {
        None
    }
}

fn is_py_keyword(s: &str) -> bool {
    matches!(
        s,
        "False"
            | "None"
            | "True"
            | "and"
            | "as"
            | "assert"
            | "async"
            | "await"
            | "break"
            | "class"
            | "continue"
            | "def"
            | "del"
            | "elif"
            | "else"
            | "except"
            | "finally"
            | "for"
            | "from"
            | "global"
            | "if"
            | "import"
            | "in"
            | "is"
            | "lambda"
            | "nonlocal"
            | "not"
            | "or"
            | "pass"
            | "raise"
            | "return"
            | "try"
            | "while"
            | "with"
            | "yield"
    )
}

fn is_statement_start(tokens: &[crate::winnow::Token], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let prev = &tokens[idx - 1];
    if prev.text == ";" || prev.text == ":" {
        return true;
    }
    if prev.line < tokens[idx].line {
        let mut depth = 0usize;
        for t in &tokens[..idx] {
            match t.text.as_str() {
                "(" | "[" | "{" => depth = depth.saturating_add(1),
                ")" | "]" | "}" => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if depth == 0 {
            return true;
        }
    }
    false
}

fn is_contextual_keyword(tokens: &[crate::winnow::Token], idx: usize) -> bool {
    let tok = &tokens[idx];
    if !is_statement_start(tokens, idx) {
        return false;
    }
    match tok.text.as_str() {
        "type" => {
            // PEP 695 type alias: `type Alias = ...` or `type Alias[T] = ...`
            let Some(next) = tokens.get(idx + 1) else {
                return false;
            };
            if !crate::binary::is_identifier(&next.text) || is_py_keyword(&next.text) {
                return false;
            }
            let mut depth = 0usize;
            for t in &tokens[idx + 2..] {
                if t.line > tok.line && depth == 0 {
                    break;
                }
                match t.text.as_str() {
                    "(" | "[" | "{" => depth = depth.saturating_add(1),
                    ")" | "]" | "}" => depth = depth.saturating_sub(1),
                    ";" if depth == 0 => break,
                    ":" if depth == 0 => break,
                    "=" if depth == 0 => return true,
                    _ => {}
                }
            }
            false
        }
        "match" => {
            let Some(next) = tokens.get(idx + 1) else {
                return false;
            };
            if next.text == "=" || next.text.ends_with('=') || next.text == "." {
                return false;
            }
            let mut depth = 0usize;
            for t in &tokens[idx + 1..] {
                if t.line > tok.line && depth == 0 {
                    break;
                }
                match t.text.as_str() {
                    "(" | "[" | "{" => depth = depth.saturating_add(1),
                    ")" | "]" | "}" => depth = depth.saturating_sub(1),
                    ":" if depth == 0 => return true,
                    ";" if depth == 0 => break,
                    _ => {}
                }
            }
            false
        }
        "case" => {
            let Some(next) = tokens.get(idx + 1) else {
                return false;
            };
            if next.text == "=" || next.text.ends_with('=') || next.text == "." {
                return false;
            }
            let mut depth = 0usize;
            for t in &tokens[idx + 1..] {
                if t.line > tok.line && depth == 0 {
                    break;
                }
                match t.text.as_str() {
                    "(" | "[" | "{" => depth = depth.saturating_add(1),
                    ")" | "]" | "}" => depth = depth.saturating_sub(1),
                    ":" if depth == 0 => return true,
                    ";" if depth == 0 => break,
                    _ => {}
                }
            }
            false
        }
        _ => false,
    }
}

fn decode_py_string_literal(tok_text: &str) -> Option<String> {
    let bytes = tok_text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut quote_start = 0;
    while quote_start < bytes.len() && bytes[quote_start].is_ascii_alphabetic() {
        quote_start += 1;
    }
    if quote_start >= bytes.len() {
        return None;
    }
    let quote_char = bytes[quote_start];
    if quote_char != b'\'' && quote_char != b'"' {
        return None;
    }
    let prefix = &tok_text[..quote_start];
    let is_raw = prefix.contains('r') || prefix.contains('R');

    let rest = &tok_text[quote_start..];
    let content = if rest.starts_with("\"\"\"") {
        let c = rest.strip_prefix("\"\"\"").unwrap_or(rest);
        c.strip_suffix("\"\"\"").unwrap_or(c)
    } else if rest.starts_with("'''") {
        let c = rest.strip_prefix("'''").unwrap_or(rest);
        c.strip_suffix("'''").unwrap_or(c)
    } else if rest.starts_with('"') {
        let c = rest.strip_prefix('"').unwrap_or(rest);
        c.strip_suffix('"').unwrap_or(c)
    } else if rest.starts_with('\'') {
        let c = rest.strip_prefix('\'').unwrap_or(rest);
        c.strip_suffix('\'').unwrap_or(c)
    } else {
        return None;
    };

    if is_raw {
        return Some(content.to_string());
    }

    // Decode escapes
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('"') => out.push('"'),
                Some('a') => out.push('\x07'),
                Some('b') => out.push('\x08'),
                Some('f') => out.push('\x0c'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('v') => out.push('\x0b'),
                Some('\n') => {} // Line continuation
                Some('\r') => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                }
                Some('x') => {
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if let Some(&h) = chars.peek() {
                            if h.is_ascii_hexdigit() {
                                hex.push(h);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if hex.len() == 2 {
                        if let Ok(b) = u8::from_str_radix(&hex, 16) {
                            out.push(b as char);
                        } else {
                            out.push_str("\\x");
                            out.push_str(&hex);
                        }
                    } else {
                        out.push_str("\\x");
                        out.push_str(&hex);
                    }
                }
                Some('u') => {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        if let Some(&h) = chars.peek() {
                            if h.is_ascii_hexdigit() {
                                hex.push(h);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if hex.len() == 4 {
                        if let Ok(u) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(u) {
                                out.push(ch);
                            } else {
                                out.push_str("\\u");
                                out.push_str(&hex);
                            }
                        } else {
                            out.push_str("\\u");
                            out.push_str(&hex);
                        }
                    } else {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
                Some('U') => {
                    let mut hex = String::new();
                    for _ in 0..8 {
                        if let Some(&h) = chars.peek() {
                            if h.is_ascii_hexdigit() {
                                hex.push(h);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if hex.len() == 8 {
                        if let Ok(u) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(u) {
                                out.push(ch);
                            } else {
                                out.push_str("\\U");
                                out.push_str(&hex);
                            }
                        } else {
                            out.push_str("\\U");
                            out.push_str(&hex);
                        }
                    } else {
                        out.push_str("\\U");
                        out.push_str(&hex);
                    }
                }
                Some(oct @ '0'..='7') => {
                    let mut octal = String::new();
                    octal.push(oct);
                    for _ in 0..2 {
                        if let Some(&d) = chars.peek() {
                            if ('0'..='7').contains(&d) {
                                octal.push(d);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if let Ok(u) = u32::from_str_radix(&octal, 8) {
                        if let Some(ch) = char::from_u32(u) {
                            out.push(ch);
                        } else {
                            out.push('\\');
                            out.push_str(&octal);
                        }
                    } else {
                        out.push('\\');
                        out.push_str(&octal);
                    }
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {
                    out.push('\\');
                }
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn pyc_literal_tokens(text: &str) -> Vec<crate::winnow::Token> {
    let tokens = crate::winnow::tokenize(text);
    let mut result: Vec<crate::winnow::Token> = Vec::new();
    let mut iter = tokens.into_iter().peekable();
    let mut source_end = 0usize;
    while let Some(mut token) = iter.next() {
        let start = text
            .get(source_end..)
            .and_then(|s| s.find(&token.text))
            .and_then(|offset| source_end.checked_add(offset))
            .unwrap_or(source_end);
        source_end = start.saturating_add(token.text.len());
        let prefix = token.text.to_ascii_lowercase();
        if matches!(prefix.as_str(), "r" | "b" | "u" | "br" | "rb") {
            if let Some(next) = iter.peek() {
                if next.text.starts_with(['\'', '"'])
                    && text
                        .get(source_end..)
                        .is_some_and(|s| s.starts_with(&next.text))
                {
                    if let Some(literal) = iter.next() {
                        source_end = source_end.saturating_add(literal.text.len());
                        token.text.push_str(&literal.text);
                    }
                }
            }
        } else if matches!(token.text.as_str(), "-" | "+") {
            let unary = result.last().is_none_or(|previous| {
                matches!(
                    previous.text.as_str(),
                    "return"
                        | "yield"
                        | "="
                        | "("
                        | "["
                        | "{"
                        | ","
                        | ":"
                        | "+"
                        | "-"
                        | "*"
                        | "/"
                        | "%"
                        | "**"
                )
            });
            if unary
                && iter
                    .peek()
                    .is_some_and(|next| next.text.starts_with(|c: char| c.is_ascii_digit()))
            {
                if let Some(number) = iter.next() {
                    if let Some(offset) = text.get(source_end..).and_then(|s| s.find(&number.text))
                    {
                        source_end = source_end
                            .saturating_add(offset)
                            .saturating_add(number.text.len());
                    }
                    let value = normalize_py_numeric_literal(&number.text);
                    token.text = if token.text == "-" {
                        format!("-{value}")
                    } else {
                        value
                    };
                }
            }
        }
        result.push(token);
    }
    result
}

fn is_pyc_number(text: &str) -> bool {
    text.strip_prefix('-')
        .unwrap_or(text)
        .starts_with(|c: char| c.is_ascii_digit())
}

fn normalize_py_numeric_literal(text: &str) -> String {
    let s = text.replace('_', "");
    if s.starts_with("0x") || s.starts_with("0X") {
        if let Ok(v) = i128::from_str_radix(&s[2..], 16) {
            return v.to_string();
        }
    } else if s.starts_with("0o") || s.starts_with("0O") {
        if let Ok(v) = i128::from_str_radix(&s[2..], 8) {
            return v.to_string();
        }
    } else if s.starts_with("0b") || s.starts_with("0B") {
        if let Ok(v) = i128::from_str_radix(&s[2..], 2) {
            return v.to_string();
        }
    } else if s.contains('.') || s.contains('e') || s.contains('E') {
        if let Ok(f) = s.parse::<f64>() {
            return f.to_string();
        }
    } else if let Ok(v) = s.parse::<i128>() {
        return v.to_string();
    }
    text.to_string()
}

fn collect_symbol_set(lines: &[&str]) -> HashSet<String> {
    let text = lines.join("\n");
    let tokens = pyc_literal_tokens(&text);
    let mut symbols = HashSet::new();
    let mut prev_is_dot = false;

    for (idx, tok) in tokens.iter().enumerate() {
        if let Some(content) = decode_py_string_literal(&tok.text) {
            symbols.insert(content);
            prev_is_dot = false;
        } else if is_pyc_number(&tok.text) {
            symbols.insert(normalize_py_numeric_literal(&tok.text));
            prev_is_dot = false;
        } else if crate::binary::is_identifier(&tok.text) {
            if prev_is_dot || (!is_py_keyword(&tok.text) && !is_contextual_keyword(&tokens, idx)) {
                symbols.insert(tok.text.clone());
            }
            prev_is_dot = false;
        } else {
            prev_is_dot = tok.text == ".";
        }
    }

    symbols
}

fn compute_line_continuation(lines: &[String]) -> Vec<bool> {
    let mut is_cont = vec![false; lines.len()];
    let mut paren_depth = 0usize;
    let mut backslash_cont = false;
    let mut in_triple_single = false;
    let mut in_triple_double = false;

    for (idx, line) in lines.iter().enumerate() {
        if paren_depth > 0 || backslash_cont || in_triple_single || in_triple_double {
            is_cont[idx] = true;
        }
        backslash_cont = false;

        let trimmed_end = line.trim_end();
        let bytes = line.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            if in_triple_single {
                if i + 2 < len
                    && bytes[i] == b'\''
                    && bytes[i + 1] == b'\''
                    && bytes[i + 2] == b'\''
                {
                    in_triple_single = false;
                    i += 3;
                    continue;
                }
                if bytes[i] == b'\\' && i + 1 < len {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if in_triple_double {
                if i + 2 < len && bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"' {
                    in_triple_double = false;
                    i += 3;
                    continue;
                }
                if bytes[i] == b'\\' && i + 1 < len {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }

            let b = bytes[i];
            if b == b'#' {
                break;
            }
            if b == b'\'' || b == b'"' {
                let quote = b;
                if i + 2 < len && bytes[i + 1] == quote && bytes[i + 2] == quote {
                    if quote == b'\'' {
                        in_triple_single = true;
                    } else {
                        in_triple_double = true;
                    }
                    i += 3;
                    continue;
                } else {
                    i += 1;
                    while i < len {
                        if bytes[i] == b'\\' && i + 1 < len {
                            i += 2;
                            continue;
                        }
                        if bytes[i] == quote {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
            }

            if b == b'(' || b == b'[' || b == b'{' {
                paren_depth += 1;
            } else if b == b')' || b == b']' || b == b'}' {
                paren_depth = paren_depth.saturating_sub(1);
            }
            i += 1;
        }

        if !in_triple_single && !in_triple_double && trimmed_end.ends_with('\\') {
            backslash_cont = true;
        }
    }

    is_cont
}

struct ParsedDefHeader {
    is_class: bool,
    func_symbols: HashSet<String>,
    enclosing_symbols: HashSet<String>,
    header_end: usize,
    inline_body: Option<String>,
}

fn parse_def_or_class_header(
    lines: &[String],
    def_line: usize,
    _is_cont: &[bool],
) -> Option<ParsedDefHeader> {
    if def_line >= lines.len() {
        return None;
    }
    let (name, is_class) = parse_def_or_class(&lines[def_line])?;

    let mut depth = 0usize;
    let mut header_end = def_line;
    let mut colon_byte_idx = None;

    for (idx, line) in lines.iter().enumerate().skip(def_line) {
        let bytes = line.as_bytes();
        let mut i = 0;
        let len = bytes.len();

        while i < len {
            let b = bytes[i];
            if b == b'#' {
                break;
            }
            if b == b'\'' || b == b'"' {
                let quote = b;
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' && i + 1 < len {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            if b == b'(' || b == b'[' || b == b'{' {
                depth += 1;
            } else if b == b')' || b == b']' || b == b'}' {
                depth = depth.saturating_sub(1);
            } else if b == b':' && depth == 0 {
                colon_byte_idx = Some(i);
                header_end = idx;
                break;
            }
            i += 1;
        }

        if colon_byte_idx.is_some() {
            break;
        }
    }

    let end_col = colon_byte_idx.unwrap_or_else(|| lines[header_end].len());
    let mut header_parts = Vec::new();
    for line in lines.iter().take(header_end).skip(def_line) {
        header_parts.push(line.as_str());
    }
    let last_slice = &lines[header_end][..end_col.min(lines[header_end].len())];
    header_parts.push(last_slice);
    let header_text = header_parts.join("\n");

    let inline_body = if end_col + 1 < lines[header_end].len() {
        let rest = lines[header_end][end_col + 1..].trim();
        if !rest.is_empty() {
            Some(rest.to_string())
        } else {
            None
        }
    } else {
        None
    };

    let mut func_symbols = HashSet::new();
    let mut enclosing_symbols = HashSet::new();
    enclosing_symbols.insert(name.clone());

    let tokens = pyc_literal_tokens(&header_text);

    if is_class {
        let mut in_parens = false;
        let mut prev_is_dot = false;
        for tok in &tokens {
            if tok.text == "(" {
                in_parens = true;
                continue;
            }
            if tok.text == ")" {
                in_parens = false;
                continue;
            }
            if in_parens {
                if let Some(content) = decode_py_string_literal(&tok.text) {
                    enclosing_symbols.insert(content);
                    prev_is_dot = false;
                } else if is_pyc_number(&tok.text) {
                    enclosing_symbols.insert(normalize_py_numeric_literal(&tok.text));
                    prev_is_dot = false;
                } else if crate::binary::is_identifier(&tok.text) {
                    if prev_is_dot || !is_py_keyword(&tok.text) {
                        enclosing_symbols.insert(tok.text.clone());
                    }
                    prev_is_dot = false;
                } else {
                    prev_is_dot = tok.text == ".";
                }
            }
        }
    } else {
        let mut paren_start = None;
        let mut paren_end = None;
        let mut p_depth = 0usize;

        for (idx, tok) in tokens.iter().enumerate() {
            if tok.text == "(" {
                if p_depth == 0 && paren_start.is_none() {
                    paren_start = Some(idx);
                }
                p_depth += 1;
            } else if tok.text == ")" {
                p_depth = p_depth.saturating_sub(1);
                if p_depth == 0 && paren_start.is_some() && paren_end.is_none() {
                    paren_end = Some(idx);
                    break;
                }
            }
        }

        if let (Some(start), Some(end)) = (paren_start, paren_end) {
            let param_tokens = &tokens[start + 1..end];
            let mut state_depth = 0usize;
            #[derive(PartialEq, Eq)]
            enum ParamState {
                ExpectingName,
                InParam,
                InAnnotation,
                InDefault,
            }
            let mut state = ParamState::ExpectingName;
            let mut prev_is_dot = false;

            for tok in param_tokens {
                if tok.text == "(" || tok.text == "[" || tok.text == "{" {
                    state_depth += 1;
                    continue;
                } else if tok.text == ")" || tok.text == "]" || tok.text == "}" {
                    state_depth = state_depth.saturating_sub(1);
                    continue;
                }

                if state_depth == 0 {
                    if tok.text == "," {
                        state = ParamState::ExpectingName;
                        prev_is_dot = false;
                        continue;
                    }
                    if state == ParamState::ExpectingName {
                        if tok.text == "*" || tok.text == "**" || tok.text == "/" {
                            continue;
                        }
                        if crate::binary::is_identifier(&tok.text) && !is_py_keyword(&tok.text) {
                            func_symbols.insert(tok.text.clone());
                            state = ParamState::InParam;
                            continue;
                        }
                    } else if state == ParamState::InParam {
                        if tok.text == ":" {
                            state = ParamState::InAnnotation;
                            prev_is_dot = false;
                            continue;
                        } else if tok.text == "=" {
                            state = ParamState::InDefault;
                            prev_is_dot = false;
                            continue;
                        }
                    } else if state == ParamState::InAnnotation && tok.text == "=" {
                        state = ParamState::InDefault;
                        prev_is_dot = false;
                        continue;
                    }
                }

                if state == ParamState::InAnnotation || state == ParamState::InDefault {
                    if let Some(content) = decode_py_string_literal(&tok.text) {
                        enclosing_symbols.insert(content);
                        prev_is_dot = false;
                    } else if is_pyc_number(&tok.text) {
                        enclosing_symbols.insert(normalize_py_numeric_literal(&tok.text));
                        prev_is_dot = false;
                    } else if crate::binary::is_identifier(&tok.text) {
                        if prev_is_dot || !is_py_keyword(&tok.text) {
                            enclosing_symbols.insert(tok.text.clone());
                        }
                        prev_is_dot = false;
                    } else {
                        prev_is_dot = tok.text == ".";
                    }
                }
            }

            let after_tokens = &tokens[end + 1..];
            let mut in_return_ann = false;
            let mut prev_is_dot = false;
            let mut prev_was_dash = false;
            for tok in after_tokens {
                if tok.text == "->" || (prev_was_dash && tok.text == ">") {
                    in_return_ann = true;
                    prev_was_dash = false;
                    continue;
                }
                prev_was_dash = tok.text == "-";
                if in_return_ann {
                    if let Some(content) = decode_py_string_literal(&tok.text) {
                        enclosing_symbols.insert(content);
                        prev_is_dot = false;
                    } else if is_pyc_number(&tok.text) {
                        enclosing_symbols.insert(normalize_py_numeric_literal(&tok.text));
                        prev_is_dot = false;
                    } else if crate::binary::is_identifier(&tok.text) {
                        if prev_is_dot || !is_py_keyword(&tok.text) {
                            enclosing_symbols.insert(tok.text.clone());
                        }
                        prev_is_dot = false;
                    } else {
                        prev_is_dot = tok.text == ".";
                    }
                }
            }
        }
    }

    Some(ParsedDefHeader {
        is_class,
        func_symbols,
        enclosing_symbols,
        header_end,
        inline_body,
    })
}

fn find_enclosing_function_for_pos(
    lines: &[String],
    pos: usize,
    is_cont: &[bool],
) -> (String, usize, usize) {
    if lines.is_empty() {
        return ("<module>".to_string(), 0, 0);
    }
    let target = pos.min(lines.len() - 1);
    if !is_cont.get(target).copied().unwrap_or(false) {
        if let Some(indent) = get_line_indent(&lines[target]) {
            if let Some((name, _)) = parse_def_or_class(&lines[target]) {
                return (name, indent, target);
            }
        }
    }

    let mut ref_indent = if !is_cont.get(target).copied().unwrap_or(false) {
        get_line_indent(&lines[target]).unwrap_or(usize::MAX)
    } else {
        usize::MAX
    };

    for i in (0..target).rev() {
        if is_cont.get(i).copied().unwrap_or(false) {
            continue;
        }
        if let Some(indent) = get_line_indent(&lines[i]) {
            if indent < ref_indent {
                if let Some((name, _)) = parse_def_or_class(&lines[i]) {
                    return (name, indent, i);
                }
                if indent == 0 {
                    break;
                }
                ref_indent = indent;
            }
        }
    }

    ("<module>".to_string(), 0, 0)
}

// Scope paths include the occurrence of each definition in source order, so
// repeated names in the same scope also have one-to-one identities.
struct PycDefinition {
    name: String,
    pos: usize,
    parent: Option<usize>,
    key: Vec<(String, usize)>,
}

fn pyc_definitions(lines: &[String], continuation: &[bool]) -> Vec<PycDefinition> {
    let mut definitions: Vec<PycDefinition> = Vec::new();
    let mut scopes: Vec<(usize, usize)> = Vec::new();
    let mut occurrences = HashMap::new();
    for (pos, line) in lines.iter().enumerate() {
        if continuation.get(pos).copied().unwrap_or(false) {
            continue;
        }
        let Some(indent) = get_line_indent(line) else {
            continue;
        };
        while scopes.last().is_some_and(|(level, _)| *level >= indent) {
            scopes.pop();
        }
        if let Some((name, _)) = parse_def_or_class(line) {
            let parent = scopes.last().and_then(|(_, index)| definitions.get(*index));
            let mut key = parent.map(|d| d.key.clone()).unwrap_or_default();
            let parent_pos = parent.map(|d| d.pos);
            let ordinal = occurrences
                .entry((key.clone(), name.clone()))
                .or_insert(0usize);
            key.push((name.clone(), *ordinal));
            *ordinal = ordinal.saturating_add(1);
            scopes.push((indent, definitions.len()));
            definitions.push(PycDefinition {
                name,
                pos,
                parent: parent_pos,
                key,
            });
        }
    }
    definitions
}

// Project positions through context and replacement blocks. An insertion or
// deletion with no opposite-side lines cannot supply a corresponding definition.
fn pyc_patch_position(hunk: &crate::diff::Hunk, pos: usize, from_fixed: bool) -> Option<usize> {
    let mut old = hunk.header.old_range.start.saturating_sub(1);
    let mut new = hunk.header.new_range.start.saturating_sub(1);
    let (source_start, destination_start) = if from_fixed { (new, old) } else { (old, new) };
    if pos < source_start {
        return Some(destination_start.saturating_sub(source_start.saturating_sub(pos)));
    }
    let mut lines = hunk.lines.iter().peekable();
    while let Some(line) = lines.next() {
        if line.line_type == DiffLineType::Context {
            let (source, destination) = if from_fixed { (new, old) } else { (old, new) };
            if pos == source {
                return Some(destination);
            }
            old = old.saturating_add(1);
            new = new.saturating_add(1);
            continue;
        }
        let old_start = old;
        let new_start = new;
        if line.line_type == DiffLineType::Removed {
            old = old.saturating_add(1);
        } else {
            new = new.saturating_add(1);
        }
        while lines
            .peek()
            .is_some_and(|line| line.line_type != DiffLineType::Context)
        {
            if let Some(line) = lines.next() {
                if line.line_type == DiffLineType::Removed {
                    old = old.saturating_add(1);
                } else {
                    new = new.saturating_add(1);
                }
            }
        }
        let (source, source_end, destination, destination_end) = if from_fixed {
            (new_start, new, old_start, old)
        } else {
            (old_start, old, new_start, new)
        };
        if pos >= source && pos < source_end {
            return if destination == destination_end {
                None
            } else {
                Some(
                    destination
                        .saturating_add(pos.saturating_sub(source))
                        .min(destination_end.saturating_sub(1)),
                )
            };
        }
    }
    let (source, destination) = if from_fixed { (new, old) } else { (old, new) };
    Some(destination.saturating_add(pos.saturating_sub(source)))
}

fn corresponding_pyc_definition(
    name: &str,
    pos: usize,
    hint: Option<usize>,
    source: &[PycDefinition],
    destination: &[PycDefinition],
    used: &HashSet<usize>,
) -> Option<usize> {
    if name == "<module>" {
        return Some(0);
    }
    let hint = hint?;
    let key = &source.iter().find(|d| d.pos == pos && d.name == name)?.key;
    let parent_key = key.get(..key.len().saturating_sub(1))?;
    destination
        .iter()
        .filter(|d| {
            d.name == name
                && !used.contains(&d.pos)
                && d.key.get(..d.key.len().saturating_sub(1)) == Some(parent_key)
        })
        .min_by_key(|d| (d.pos.abs_diff(hint), d.pos))
        .map(|d| d.pos)
}

struct PycFileAnalysis<'a> {
    lines: &'a [String],
    continuation: Vec<bool>,
    definitions: Vec<PycDefinition>,
    headers: HashMap<usize, Option<ParsedDefHeader>>,
    scope_membership: HashMap<usize, (String, usize)>,
    symbols: HashMap<(String, usize), HashSet<String>>,
}

impl<'a> PycFileAnalysis<'a> {
    fn new(lines: &'a [String]) -> Self {
        let continuation = compute_line_continuation(lines);
        let definitions = pyc_definitions(lines, &continuation);
        Self {
            lines,
            continuation,
            definitions,
            headers: HashMap::new(),
            scope_membership: HashMap::new(),
            symbols: HashMap::new(),
        }
    }

    fn get_or_parse_header(
        &mut self,
        def_pos: usize,
        budget: &mut WorkBudget,
    ) -> Result<Option<&ParsedDefHeader>, FingerprintError> {
        if !self.headers.contains_key(&def_pos) {
            budget.charge(1)?;
            let parsed = parse_def_or_class_header(self.lines, def_pos, &self.continuation);
            self.headers.insert(def_pos, parsed);
        }
        Ok(self.headers.get(&def_pos).and_then(|opt| opt.as_ref()))
    }

    fn get_scope_for_pos(
        &mut self,
        pos: usize,
        budget: &mut WorkBudget,
    ) -> Result<(String, usize), FingerprintError> {
        if let Some(scope) = self.scope_membership.get(&pos) {
            return Ok(scope.clone());
        }
        budget.charge(1)?;
        let (name, _, def_pos) =
            find_enclosing_function_for_pos(self.lines, pos, &self.continuation);
        let scope = (name, def_pos);
        self.scope_membership.insert(pos, scope.clone());
        Ok(scope)
    }

    fn changed_scopes(
        &mut self,
        positions: &[usize],
        budget: &mut WorkBudget,
    ) -> Result<Vec<(String, usize)>, FingerprintError> {
        let mut result = Vec::new();
        for &pos in positions {
            let enclosing = self.get_scope_for_pos(pos, budget)?;
            if !result.contains(&enclosing) {
                result.push(enclosing);
            }
            let idx = self.definitions.partition_point(|d| d.pos <= pos);
            if idx > 0 {
                let def = &self.definitions[idx - 1];
                let def_pos = def.pos;
                let parent_pos = def.parent;
                if let Some(header) = self.get_or_parse_header(def_pos, budget)? {
                    if pos <= header.header_end {
                        let parent =
                            parent_pos.and_then(|p| self.definitions.iter().find(|d| d.pos == p));
                        let enclosing_header_parent = parent
                            .map(|d| (d.name.clone(), d.pos))
                            .unwrap_or_else(|| ("<module>".to_string(), 0));
                        if !result.contains(&enclosing_header_parent) {
                            result.push(enclosing_header_parent);
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    fn get_or_extract_symbols(
        &mut self,
        function_name: &str,
        hint_pos: usize,
        budget: &mut WorkBudget,
    ) -> Result<HashSet<String>, FingerprintError> {
        let key = (function_name.to_string(), hint_pos);
        if let Some(syms) = self.symbols.get(&key) {
            return Ok(syms.clone());
        }
        let syms = self.extract_symbols(function_name, hint_pos, budget)?;
        self.symbols.insert(key, syms.clone());
        Ok(syms)
    }

    fn extract_symbols(
        &mut self,
        function_name: &str,
        hint_pos: usize,
        budget: &mut WorkBudget,
    ) -> Result<HashSet<String>, FingerprintError> {
        if self.lines.is_empty() {
            return Ok(HashSet::new());
        }

        if function_name == "<module>" {
            let mut module_symbols = HashSet::new();
            let mut skip_until_indent: Option<usize> = None;
            let mut line_idx = 0;

            while line_idx < self.lines.len() {
                let line = &self.lines[line_idx];

                if let Some(skip_indent) = skip_until_indent {
                    if self.continuation[line_idx] {
                        line_idx += 1;
                        continue;
                    }
                    if let Some(indent) = get_line_indent(line) {
                        if indent > skip_indent {
                            line_idx += 1;
                            continue;
                        } else {
                            skip_until_indent = None;
                        }
                    } else {
                        line_idx += 1;
                        continue;
                    }
                }

                if !self.continuation[line_idx] && parse_def_or_class(line).is_some() {
                    let def_indent = get_line_indent(line).unwrap_or(0);
                    if let Some(parsed) = self.get_or_parse_header(line_idx, budget)? {
                        let header_end = parsed.header_end;
                        let enclosing_syms = parsed.enclosing_symbols.clone();
                        module_symbols.extend(enclosing_syms);
                        skip_until_indent = Some(def_indent);
                        line_idx = header_end + 1;
                        continue;
                    }
                }

                let mut span_end = line_idx + 1;
                while span_end < self.lines.len() && self.continuation[span_end] {
                    span_end += 1;
                }
                let span_lines: Vec<&str> = self.lines[line_idx..span_end]
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                budget.charge(span_lines.len())?;
                let syms = collect_symbol_set(&span_lines);
                module_symbols.extend(syms);
                line_idx = span_end;
            }

            return Ok(module_symbols);
        }

        let candidate = self
            .definitions
            .iter()
            .filter(|d| d.name == function_name)
            .min_by_key(|d| d.pos.abs_diff(hint_pos));

        let Some(def) = candidate else {
            return Ok(HashSet::new());
        };
        let def_line = def.pos;
        let base_indent = get_line_indent(&self.lines[def_line]).unwrap_or(0);

        let mut end_line = self.lines.len();
        for (j, line) in self.lines.iter().enumerate().skip(def_line + 1) {
            if self.continuation[j] {
                continue;
            }
            if let Some(indent) = get_line_indent(line) {
                if indent <= base_indent {
                    end_line = j;
                    break;
                }
            }
        }

        let mut symbols = HashSet::new();
        let parsed_header = self.get_or_parse_header(def_line, budget)?;
        let (header_end, inline_body) = if let Some(parsed) = parsed_header {
            if !parsed.is_class {
                symbols.extend(parsed.func_symbols.clone());
            }
            (parsed.header_end, parsed.inline_body.clone())
        } else {
            (def_line, None)
        };

        if let Some(body_text) = inline_body {
            budget.charge(1)?;
            let syms = collect_symbol_set(&[&body_text]);
            symbols.extend(syms);
        }

        let mut skip_until_indent: Option<usize> = None;
        let mut line_idx = header_end + 1;
        while line_idx < end_line {
            let line = &self.lines[line_idx];

            if let Some(skip_indent) = skip_until_indent {
                if self.continuation[line_idx] {
                    line_idx += 1;
                    continue;
                }
                if let Some(indent) = get_line_indent(line) {
                    if indent > skip_indent {
                        line_idx += 1;
                        continue;
                    } else {
                        skip_until_indent = None;
                    }
                } else {
                    line_idx += 1;
                    continue;
                }
            }

            if !self.continuation[line_idx] && parse_def_or_class(line).is_some() {
                let nested_indent = get_line_indent(line).unwrap_or(base_indent + 1);
                if let Some(parsed) = self.get_or_parse_header(line_idx, budget)? {
                    let header_end = parsed.header_end;
                    let enclosing_syms = parsed.enclosing_symbols.clone();
                    symbols.extend(enclosing_syms);
                    skip_until_indent = Some(nested_indent);
                    line_idx = header_end + 1;
                    continue;
                }
            }

            let mut span_end = line_idx + 1;
            while span_end < end_line && self.continuation[span_end] {
                span_end += 1;
            }
            let span_lines: Vec<&str> = self.lines[line_idx..span_end]
                .iter()
                .map(|s| s.as_str())
                .collect();
            budget.charge(span_lines.len())?;
            let syms = collect_symbol_set(&span_lines);
            symbols.extend(syms);
            line_idx = span_end;
        }

        Ok(symbols)
    }
}

fn compute_pyc_function_fingerprints(
    hunk: &crate::diff::Hunk,
    fixed_analysis: &mut PycFileAnalysis,
    changed_pos: &[usize],
    mut base_analysis: Option<&mut PycFileAnalysis>,
    budget: &mut WorkBudget,
) -> Result<Vec<PycFunctionFingerprint>, FingerprintError> {
    let base_start = if hunk.header.old_range.start > 0 {
        hunk.header.old_range.start - 1
    } else {
        0
    };

    let mut base_hunk_lines = Vec::new();
    let mut cur = base_start;
    for line in &hunk.lines {
        match line.line_type {
            crate::diff::DiffLineType::Context => {
                cur += 1;
            }
            crate::diff::DiffLineType::Removed => {
                base_hunk_lines.push(cur);
                cur += 1;
            }
            crate::diff::DiffLineType::Added => {}
        }
    }
    if base_hunk_lines.is_empty() {
        base_hunk_lines.push(base_start);
    }

    let base_defs = if let Some(ref mut base_ana) = base_analysis {
        base_ana.changed_scopes(&base_hunk_lines, budget)?
    } else {
        Vec::new()
    };
    let fixed_defs = fixed_analysis.changed_scopes(changed_pos, budget)?;

    let mut targets: Vec<(String, Option<usize>, Option<usize>)> = Vec::new();
    let mut used_base = HashSet::new();
    let mut used_fixed = HashSet::new();
    for (name, pos) in fixed_defs {
        let base_pos = if let Some(ref base_ana) = base_analysis {
            corresponding_pyc_definition(
                &name,
                pos,
                pyc_patch_position(hunk, pos, true),
                &fixed_analysis.definitions,
                &base_ana.definitions,
                &used_base,
            )
        } else {
            None
        };
        if name != "<module>" {
            if let Some(base_pos) = base_pos {
                used_base.insert(base_pos);
            }
            used_fixed.insert(pos);
        }
        targets.push((name, Some(pos), base_pos));
    }
    for (name, pos) in base_defs {
        if targets
            .iter()
            .any(|(n, _, p)| n == &name && *p == Some(pos))
        {
            continue;
        }
        let fixed_pos = if let Some(ref base_ana) = base_analysis {
            corresponding_pyc_definition(
                &name,
                pos,
                pyc_patch_position(hunk, pos, false),
                &base_ana.definitions,
                &fixed_analysis.definitions,
                &used_fixed,
            )
        } else {
            None
        };
        if name != "<module>" {
            if let Some(fixed_pos) = fixed_pos {
                used_fixed.insert(fixed_pos);
            }
        }
        // A fixed definition can be paired only once, including removed definitions.
        if fixed_pos.is_some()
            && targets
                .iter()
                .any(|(n, p, _)| n == &name && *p == fixed_pos)
        {
            continue;
        }
        targets.push((name, fixed_pos, Some(pos)));
    }

    if targets.is_empty() {
        targets.push(("<module>".to_string(), Some(0), Some(0)));
    }

    let mut result = Vec::new();

    for (function_name, f_hint, b_hint) in targets {
        let fixed_symbols = if let Some(f_pos) = f_hint {
            fixed_analysis.get_or_extract_symbols(&function_name, f_pos, budget)?
        } else if function_name == "<module>" {
            fixed_analysis.get_or_extract_symbols("<module>", 0, budget)?
        } else {
            HashSet::new()
        };

        let base_symbols = if let Some(ref mut base_ana) = base_analysis {
            if let Some(b_pos) = b_hint {
                base_ana.get_or_extract_symbols(&function_name, b_pos, budget)?
            } else if function_name == "<module>" {
                base_ana.get_or_extract_symbols("<module>", 0, budget)?
            } else {
                HashSet::new()
            }
        } else {
            HashSet::new()
        };

        let mut added: HashSet<String> = fixed_symbols.difference(&base_symbols).cloned().collect();
        let mut removed: HashSet<String> =
            base_symbols.difference(&fixed_symbols).cloned().collect();

        for stop in PYC_STOP_LIST {
            added.remove(*stop);
            removed.remove(*stop);
        }

        if added.is_empty() && removed.is_empty() {
            continue;
        }

        let mut added_u64: Vec<u64> = added.iter().map(|s| sha256_u64(s.as_bytes())).collect();
        added_u64.sort_unstable();
        added_u64.dedup();

        let mut removed_u64: Vec<u64> = removed.iter().map(|s| sha256_u64(s.as_bytes())).collect();
        removed_u64.sort_unstable();
        removed_u64.dedup();

        result.push(PycFunctionFingerprint {
            function_name,
            added,
            removed,
            added_u64,
            removed_u64,
        });
    }

    Ok(result)
}

impl FingerprintSet {
    pub const DEFAULT_TIER2_MAX_FILES: usize = 20_000;
    pub const DEFAULT_TIER2_MAX_BYTES: u64 = 200 * 1024 * 1024;

    /// Build tier 1 and tier 3 fingerprints from gold patch, test patch, and base tree.
    pub fn from_task(
        gold_patch_str: &str,
        test_patch_str: &str,
        base_tree_root: &Path,
    ) -> Result<Self, FingerprintError> {
        Self::from_task_with_caps(
            gold_patch_str,
            test_patch_str,
            base_tree_root,
            Self::DEFAULT_TIER2_MAX_FILES,
            Self::DEFAULT_TIER2_MAX_BYTES,
        )
    }

    pub fn from_task_with_caps(
        gold_patch_str: &str,
        test_patch_str: &str,
        base_tree_root: &Path,
        tier2_max_files: usize,
        tier2_max_bytes: u64,
    ) -> Result<Self, FingerprintError> {
        Self::from_task_with_caps_and_budget(
            gold_patch_str,
            test_patch_str,
            base_tree_root,
            tier2_max_files,
            tier2_max_bytes,
            None,
        )
    }

    pub fn from_task_with_budget(
        gold_patch_str: &str,
        test_patch_str: &str,
        base_tree_root: &Path,
        work_budget: Option<usize>,
    ) -> Result<Self, FingerprintError> {
        Self::from_task_with_caps_and_budget(
            gold_patch_str,
            test_patch_str,
            base_tree_root,
            Self::DEFAULT_TIER2_MAX_FILES,
            Self::DEFAULT_TIER2_MAX_BYTES,
            work_budget,
        )
    }

    pub fn from_task_with_caps_and_budget(
        gold_patch_str: &str,
        test_patch_str: &str,
        base_tree_root: &Path,
        tier2_max_files: usize,
        tier2_max_bytes: u64,
        work_budget: Option<usize>,
    ) -> Result<Self, FingerprintError> {
        let budget_limit = work_budget
            .or_else(|| {
                std::env::var("HERMETIC_FINGERPRINT_WORK_BUDGET")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .unwrap_or(DEFAULT_MAX_FINGERPRINT_WORK);
        let mut budget = WorkBudget::new(budget_limit);
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

            let (post_fix_lines, hunk_changed_positions, base_lines) =
                apply_patch_to_base(file, base_tree_root);

            let mut fixed_analysis = if file_path.ends_with(".py") {
                Some(PycFileAnalysis::new(&post_fix_lines))
            } else {
                None
            };
            let mut base_analysis = if file_path.ends_with(".py") {
                base_lines.as_ref().map(|b| PycFileAnalysis::new(b))
            } else {
                None
            };

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

            // FIX 4: For renames, base file is at old_path
            let old_file_path = file.old_path.as_deref().unwrap_or(&file_path);
            let base_file_path = base_tree_root.join(old_file_path);
            let base_src = if base_file_path.exists() {
                read_text_like_scanner(&base_file_path)
            } else {
                None
            };

            for (hunk_idx, hunk) in file.hunks.iter().enumerate() {
                let mut lines = Vec::new();
                let mut removed_markers = Vec::new();
                let mut windows = Vec::new();
                let mut diff_shapes = Vec::new();
                let mut winnow_candidates = Vec::new();

                let mut removed_lines = Vec::new();
                let mut cur_old = hunk.header.old_range.start;
                for diff_line in &hunk.lines {
                    match diff_line.line_type {
                        DiffLineType::Context => {
                            cur_old += 1;
                        }
                        DiffLineType::Removed => {
                            if cur_old > 0 {
                                removed_lines.push(cur_old - 1);
                            }
                            cur_old += 1;
                        }
                        DiffLineType::Added => {}
                    }
                }

                // FIX 3: If hunk adds no lines, pass empty added-line list to Tier 2
                let hunk_has_added = hunk
                    .lines
                    .iter()
                    .any(|l| l.line_type == DiffLineType::Added);
                let added_lines = if hunk_has_added {
                    hunk_changed_positions
                        .get(hunk_idx)
                        .cloned()
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                let (tier2_candidate_symbols, mut tier2_anchors) =
                    crate::tier2::extract_hunk_symbols_and_anchors(
                        &file_path,
                        base_src.as_deref(),
                        &removed_lines,
                        &post_fix_text,
                        &added_lines,
                    );

                // FIX 4: Add old file's base name and module as additional anchors
                if let Some(old_p) = file.old_path.as_deref() {
                    if old_p != file_path {
                        for a in crate::tier2::extract_file_anchors(old_p) {
                            if !tier2_anchors.contains(&a) {
                                tier2_anchors.push(a);
                            }
                        }
                    }
                }

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
                let mut seen_lines = HashSet::new();
                let mut seen_removed = HashSet::new();
                for diff_line in &hunk.lines {
                    match diff_line.line_type {
                        DiffLineType::Added => {
                            if let Some(norm) = normalize_line(&diff_line.content) {
                                let hash = sha256_hex(norm.as_bytes());
                                if seen_lines.insert(hash.clone()) {
                                    lines.push((hash, norm));
                                }
                            }
                        }
                        DiffLineType::Removed => {
                            if let Some(norm) = normalize_line(&diff_line.content) {
                                let marker = format!("-{}", norm);
                                let hash = sha256_hex(marker.as_bytes());
                                if seen_removed.insert(hash.clone()) {
                                    removed_markers.push((hash, marker));
                                }
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

                let pyc_fingerprints = if let Some(ref mut fixed_ana) = fixed_analysis {
                    compute_pyc_function_fingerprints(
                        hunk,
                        fixed_ana,
                        hunk_changed_positions
                            .get(hunk_idx)
                            .map(|v| v.as_slice())
                            .unwrap_or(&[]),
                        base_analysis.as_mut(),
                        &mut budget,
                    )?
                } else {
                    Vec::new()
                };

                candidate_hunks.push(CandidateHunk {
                    hunk_index: global_hunk_counter,
                    file_path: file_path.clone(),
                    lines,
                    windows,
                    removed_markers,
                    diff_shapes,
                    winnow_candidates,
                    binary_items,
                    pyc_fingerprints,
                    tier2_anchors,
                    tier2_candidate_symbols,
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
                let mut seen_lines = HashSet::new();
                for diff_line in &hunk.lines {
                    if diff_line.line_type == DiffLineType::Added {
                        if let Some(norm) = normalize_line(&diff_line.content) {
                            let hash = sha256_hex(norm.as_bytes());
                            if seen_lines.insert(hash.clone()) {
                                lines.push((hash, norm));
                            }
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
                        pyc_fingerprints: Vec::new(),
                        tier2_anchors: Vec::new(),
                        tier2_candidate_symbols: HashSet::new(),
                    });
                    global_hunk_counter += 1;
                }
            }
        }

        let baseline_budget = std::env::var("HERMETIC_BASELINE_BUDGET")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64 * 1024 * 1024);
        Ok(finish_fingerprint_set(
            candidate_hunks,
            base_tree_root,
            0,
            baseline_budget,
            tier2_max_files,
            tier2_max_bytes,
        ))
    }

    /// Build tier 1, tier 3, and binary tier fingerprints from task files in undated mode (TR-SC-9).
    pub fn from_files(
        files: &[(String, Vec<u8>)],
        base_tree: &Path,
    ) -> Result<Self, FingerprintError> {
        Self::from_files_with_budget(files, base_tree, None)
    }

    pub fn from_files_with_budget(
        files: &[(String, Vec<u8>)],
        base_tree: &Path,
        budget: Option<usize>,
    ) -> Result<Self, FingerprintError> {
        const MAX_FILE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
        const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

        let mut total_bytes = 0usize;
        let mut skipped_files_count = 0usize;
        let mut candidate_hunks: Vec<CandidateHunk> = Vec::new();
        let mut global_hunk_counter = 0;

        for (file_path, bytes) in files {
            let file_bytes = bytes.len();
            if file_bytes > MAX_FILE_BYTES
                || total_bytes.saturating_add(file_bytes) > MAX_TOTAL_BYTES
            {
                skipped_files_count += 1;
                continue;
            }
            total_bytes += file_bytes;

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
                    pyc_fingerprints: Vec::new(),
                    tier2_anchors: Vec::new(),
                    tier2_candidate_symbols: HashSet::new(),
                });
                global_hunk_counter += 1;
            } else {
                let text = String::from_utf8_lossy(bytes);
                let file_lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();

                let mut lines = Vec::new();
                let mut seen_lines = HashSet::new();
                for line in &file_lines {
                    if let Some(norm) = normalize_line(line) {
                        let hash = sha256_hex(norm.as_bytes());
                        if seen_lines.insert(hash.clone()) {
                            lines.push((hash, norm));
                        }
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

                let all_tokens = tokenize(&text);
                let token_texts: Vec<String> = all_tokens.iter().map(|t| t.text.clone()).collect();
                let fps = winnow_tokens(&token_texts);
                let mut winnow_candidates = Vec::new();
                for fp in fps {
                    let ev_end = (fp.token_pos + 8).min(token_texts.len());
                    let ev = token_texts[fp.token_pos..ev_end].join(" ");
                    winnow_candidates.push((fp.hash, ev));
                }

                let raw_items = crate::binary::extract_binary_items(&text);
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
                    pyc_fingerprints: Vec::new(),
                    tier2_anchors: Vec::new(),
                    tier2_candidate_symbols: HashSet::new(),
                });
                global_hunk_counter += 1;
            }
        }

        let baseline_budget = budget
            .or_else(|| {
                std::env::var("HERMETIC_BASELINE_BUDGET")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .unwrap_or(64 * 1024 * 1024);

        Ok(finish_fingerprint_set(
            candidate_hunks,
            base_tree,
            skipped_files_count,
            baseline_budget,
            Self::DEFAULT_TIER2_MAX_FILES,
            Self::DEFAULT_TIER2_MAX_BYTES,
        ))
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line_buf: &mut Vec<u8>,
    max_line_len: usize,
) -> std::io::Result<Option<bool>> {
    line_buf.clear();
    let mut overlong = false;
    let mut total_read = 0;
    loop {
        let (done, used) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if total_read == 0 && !overlong {
                    return Ok(None);
                }
                return Ok(Some(!overlong));
            }
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let to_take = pos + 1;
                if !overlong && line_buf.len() + to_take <= max_line_len {
                    line_buf.extend_from_slice(&available[..to_take]);
                } else {
                    overlong = true;
                }
                (true, to_take)
            } else {
                let to_take = available.len();
                if !overlong && line_buf.len() + to_take <= max_line_len {
                    line_buf.extend_from_slice(&available[..to_take]);
                } else {
                    overlong = true;
                }
                (false, to_take)
            }
        };
        total_read += used;
        reader.consume(used);
        if done {
            return Ok(Some(!overlong));
        }
    }
}

fn finish_fingerprint_set(
    candidate_hunks: Vec<CandidateHunk>,
    base_tree_root: &Path,
    skipped_files_count: usize,
    baseline_budget: usize,
    tier2_max_files: usize,
    tier2_max_bytes: u64,
) -> FingerprintSet {
    let mut all_tier2_symbols = HashSet::new();
    for ch in &candidate_hunks {
        all_tier2_symbols.extend(ch.tier2_candidate_symbols.iter().cloned());
    }

    let (tier2_df_counts, tier2_py_count, tier2_capped, tier2_chosen_files) =
        sample_base_tree_for_idf(
            base_tree_root,
            &all_tier2_symbols,
            tier2_max_files,
            tier2_max_bytes,
        );

    // Baseline subtraction (TR-SC-1, TR-SC-4 & TR-SC-5): walk base_tree_root
    let mut base_line_counts: HashMap<String, usize> = HashMap::new();
    let mut base_line_hashes: HashSet<String> = HashSet::new();
    let mut base_window_hashes: HashSet<String> = HashSet::new();
    let mut base_winnow_hashes: HashSet<u64> = HashSet::new();
    let mut base_binary_tokens: HashSet<String> = HashSet::new();
    let mut baseline_bytes_used: usize = 0;
    let mut baseline_incomplete: bool = false;
    let mut baseline_skipped_bytes: u64 = 0;

    if base_tree_root.exists() {
        let mut base_entries: Vec<std::path::PathBuf> = Vec::new();
        for entry in WalkDir::new(base_tree_root)
            .into_iter()
            .filter_entry(|e| e.file_name() != ".git")
            .flatten()
        {
            if entry.file_type().is_file() {
                base_entries.push(entry.into_path());
            }
        }
        base_entries.sort();

        for file_path in base_entries {
            let Ok(meta) = fs::metadata(&file_path) else {
                continue;
            };
            let file_len = meta.len();

            if baseline_bytes_used >= baseline_budget {
                baseline_incomplete = true;
                baseline_skipped_bytes += file_len;
                continue;
            }

            let remaining_budget = (baseline_budget - baseline_bytes_used) as u64;
            let allowed_bytes = file_len.min(remaining_budget);
            if file_len > remaining_budget {
                baseline_incomplete = true;
                baseline_skipped_bytes += file_len - remaining_budget;
                baseline_bytes_used = baseline_budget;
            } else {
                baseline_bytes_used += file_len as usize;
            }

            let Ok(file) = fs::File::open(&file_path) else {
                continue;
            };

            const MAX_BASELINE_FILE_BYTES: u64 = 16 * 1024 * 1024;
            if file_len <= MAX_BASELINE_FILE_BYTES && file_len <= remaining_budget {
                let mut bytes = Vec::new();
                let mut handle = file.take(allowed_bytes + 1);
                if handle.read_to_end(&mut bytes).is_err() || bytes.len() as u64 > allowed_bytes {
                    continue;
                }

                let head = &bytes[..bytes.len().min(8192)];
                let is_binary = head.contains(&0);

                if is_binary {
                    let runs = crate::binary::extract_printable_runs(&bytes, 8);
                    for run in runs {
                        if !run.chars().any(char::is_control) {
                            base_binary_tokens.insert(run.clone());
                        }
                        for token in crate::binary::word_tokens(&run) {
                            if token.len() >= 8 && !token.chars().any(char::is_control) {
                                base_binary_tokens.insert(token.to_string());
                            }
                        }
                    }
                } else {
                    // Decode the way the scanner does (lossy UTF-8, binary skipped), so every text unit the scanner can see at the base is also subtracted here.
                    let content = String::from_utf8_lossy(&bytes);
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
            } else {
                let mut reader = std::io::BufReader::new(file.take(allowed_bytes));
                let is_binary = {
                    let available = match reader.fill_buf() {
                        Ok(buf) => buf,
                        Err(_) => continue,
                    };
                    let head = &available[..available.len().min(8192)];
                    head.contains(&0)
                };

                if is_binary {
                    continue;
                }

                const MAX_LINE_BYTES: usize = 1024 * 1024; // 1 MiB per line
                let mut line_buf = Vec::new();
                let mut window_lines: VecDeque<String> = VecDeque::new();
                let mut token_window: VecDeque<String> = VecDeque::new();

                while let Ok(Some(valid)) =
                    read_bounded_line(&mut reader, &mut line_buf, MAX_LINE_BYTES)
                {
                    if !valid {
                        window_lines.clear();
                        token_window.clear();
                        continue;
                    }

                    let text_line = String::from_utf8_lossy(&line_buf);
                    let clean = text_line.trim_end_matches(&['\r', '\n'][..]);

                    if let Some(norm) = normalize_line(clean) {
                        *base_line_counts.entry(norm.clone()).or_insert(0) += 1;
                        base_line_hashes.insert(sha256_hex(norm.as_bytes()));
                    }

                    if !window_lines.is_empty() {
                        let w = [&window_lines[window_lines.len() - 1], clean];
                        if !w.iter().all(|l| normalize_line(l).is_none()) {
                            let norm_w = w
                                .iter()
                                .map(|l| clean_line(l, false))
                                .collect::<Vec<_>>()
                                .join("\n");
                            base_window_hashes.insert(sha256_hex(norm_w.as_bytes()));
                        }
                    }
                    if window_lines.len() >= 2 {
                        let w = [
                            &window_lines[window_lines.len() - 2],
                            &window_lines[window_lines.len() - 1],
                            clean,
                        ];
                        if !w.iter().all(|l| normalize_line(l).is_none()) {
                            let norm_w = w
                                .iter()
                                .map(|l| clean_line(l, false))
                                .collect::<Vec<_>>()
                                .join("\n");
                            base_window_hashes.insert(sha256_hex(norm_w.as_bytes()));
                        }
                    }
                    window_lines.push_back(clean.to_string());
                    if window_lines.len() > 2 {
                        window_lines.pop_front();
                    }

                    let line_tokens = tokenize(clean);
                    for tok in line_tokens {
                        base_binary_tokens.insert(tok.text.clone());
                        if let Some(literal_content) =
                            crate::binary::extract_string_literal_content(&tok.text)
                        {
                            base_binary_tokens.insert(literal_content);
                        }
                        token_window.push_back(tok.text);
                        if token_window.len() == 8 {
                            let slice: Vec<String> = token_window.iter().cloned().collect();
                            base_winnow_hashes.insert(crate::winnow::hash_kgram(&slice));
                            token_window.pop_front();
                        }
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
        let mut seen_surviving_lines = HashSet::new();
        for (hash, norm) in ch.lines {
            if base_line_hashes.contains(&hash) {
                subtracted_count += 1;
            } else if seen_surviving_lines.insert(hash.clone()) {
                hash_to_evidence.insert(hash.clone(), norm.clone());
                surviving_lines.push((hash, norm));
            }
        }

        let mut surviving_windows = Vec::new();
        let mut seen_surviving_windows = HashSet::new();
        for (hash, w_lines) in ch.windows {
            if base_window_hashes.contains(&hash) {
                subtracted_count += 1;
            } else if seen_surviving_windows.insert(hash.clone()) {
                let ev = w_lines
                    .iter()
                    .map(|l| clean_line(l, false))
                    .collect::<Vec<_>>()
                    .join(" / ");
                hash_to_evidence.insert(hash.clone(), ev);
                surviving_windows.push((hash, w_lines));
            }
        }

        let mut surviving_removed_markers = Vec::new();
        let mut seen_surviving_removed = HashSet::new();
        for (hash, marker) in ch.removed_markers {
            if seen_surviving_removed.insert(hash.clone()) {
                hash_to_evidence.insert(hash.clone(), marker.clone());
                surviving_removed_markers.push((hash, marker));
            }
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
            if line_fingerprints.contains_key(hash) {
                continue;
            }
            let count = base_line_counts.get(norm).copied().unwrap_or(0);
            // line: 1 / (1 + count)
            let w = 1.0 / (1.0 + count as f64);
            line_fingerprints.insert(hash.clone(), w);
            total_line_weight += w;
        }

        let mut window_fingerprints = HashMap::new();
        let mut total_window_weight = 0.0;
        for (hash, w_lines) in &surviving_windows {
            if window_fingerprints.contains_key(hash) {
                continue;
            }
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
        for (hash, marker) in &surviving_removed_markers {
            if removed_map.contains_key(hash) {
                continue;
            }
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

        let n_py_files = tier2_py_count;
        let mut tier2_symbols = Vec::new();
        let mut tier2_total_weight = 0.0;
        for sym in &ch.tier2_candidate_symbols {
            let df = tier2_df_counts.get(sym).copied().unwrap_or(0);
            let weight = ((n_py_files as f64 + 1.0) / (df as f64 + 1.0)).ln() + 1.0;
            tier2_total_weight += weight;
            tier2_symbols.push((sym.clone(), weight));
        }

        tier2_symbols.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

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
            pyc_fingerprint: ch.pyc_fingerprints.first().cloned(),
            pyc_fingerprints: ch.pyc_fingerprints,
            tier2_anchors: ch.tier2_anchors,
            tier2_symbols,
            tier2_total_weight,
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
        baseline_incomplete,
        baseline_skipped_bytes,
        tier2_capped,
        tier2_chosen_files,
    }
}

/// Sample up to `max_files` (and `max_bytes`) Python files from `base_tree_root` in deterministic
/// lexicographical order to compute symbol document frequencies.
pub fn sample_base_tree_for_idf(
    base_tree_root: &Path,
    symbols: &HashSet<String>,
    max_files: usize,
    max_bytes: u64,
) -> (HashMap<String, usize>, usize, bool, Vec<PathBuf>) {
    let mut py_count = 0usize;
    let mut py_bytes = 0u64;
    let mut capped = false;
    let mut df_counts = HashMap::new();
    let mut chosen_files = Vec::new();

    if base_tree_root.exists() {
        for entry in WalkDir::new(base_tree_root)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| e.file_name() != ".git")
            .flatten()
        {
            if entry.file_type().is_file()
                && entry.path().extension().is_some_and(|e| e == "py")
                && !capped
            {
                if let Some(content) = read_text_like_scanner(entry.path()) {
                    let file_size = entry.metadata().map_or(0, |m| m.len());
                    if py_count >= max_files || py_bytes + file_size > max_bytes {
                        capped = true;
                    } else {
                        py_count += 1;
                        py_bytes += file_size;
                        chosen_files.push(entry.path().to_path_buf());
                        if !symbols.is_empty() {
                            let base_tokens = tokenize(&content);
                            let mut found_in_file = HashSet::new();
                            for tok in &base_tokens {
                                if symbols.contains(&tok.text) {
                                    found_in_file.insert(tok.text.clone());
                                } else if let Some(lit) =
                                    crate::binary::extract_string_literal_content(&tok.text)
                                {
                                    if symbols.contains(&lit) {
                                        found_in_file.insert(lit);
                                    }
                                }
                            }

                            let mut i = 0;
                            while i < base_tokens.len() {
                                let mut chain = base_tokens[i].text.clone();
                                let mut j = i + 1;
                                while j + 1 < base_tokens.len() && base_tokens[j].text == "." {
                                    chain.push('.');
                                    chain.push_str(&base_tokens[j + 1].text);
                                    if symbols.contains(&chain) {
                                        found_in_file.insert(chain.clone());
                                    }
                                    j += 2;
                                }
                                i += 1;
                            }

                            for sym in found_in_file {
                                *df_counts.entry(sym).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    (df_counts, py_count, capped, chosen_files)
}

/// Compute IDF weights for `symbols` sampled from `base_tree_root` with caps on files and bytes.
/// Returns the symbol weights and the chosen files in sorted order.
pub fn build_tier2_idf(
    base_tree_root: &Path,
    symbols: &HashSet<String>,
    max_files: usize,
    max_bytes: u64,
) -> (HashMap<String, f64>, Vec<PathBuf>) {
    let (df_counts, py_count, _capped, chosen_files) =
        sample_base_tree_for_idf(base_tree_root, symbols, max_files, max_bytes);
    let mut weights = HashMap::new();
    for sym in symbols {
        let df = df_counts.get(sym).copied().unwrap_or(0);
        let weight = ((py_count as f64 + 1.0) / (df as f64 + 1.0)).ln() + 1.0;
        weights.insert(sym.clone(), weight);
    }
    (weights, chosen_files)
}
