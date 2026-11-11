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
            | "match"
            | "case"
            | "type"
    )
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
    let tokens = crate::winnow::tokenize(&text);
    let mut symbols = HashSet::new();
    let mut prev_is_dot = false;

    for tok in &tokens {
        if let Some(content) = decode_py_string_literal(&tok.text) {
            symbols.insert(content);
            prev_is_dot = false;
        } else if tok.text.starts_with(|c: char| c.is_ascii_digit()) {
            symbols.insert(normalize_py_numeric_literal(&tok.text));
            prev_is_dot = false;
        } else if crate::binary::is_identifier(&tok.text) {
            if prev_is_dot || !is_py_keyword(&tok.text) {
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

    let tokens = crate::winnow::tokenize(&header_text);

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
                } else if tok.text.starts_with(|c: char| c.is_ascii_digit()) {
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
                    } else if tok.text.starts_with(|c: char| c.is_ascii_digit()) {
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
                    } else if tok.text.starts_with(|c: char| c.is_ascii_digit()) {
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

fn find_candidate_def(
    lines: &[String],
    function_name: &str,
    hint_pos: usize,
    is_cont: &[bool],
) -> Option<usize> {
    let mut candidates = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if !is_cont.get(idx).copied().unwrap_or(false) {
            if let Some((name, _)) = parse_def_or_class(line) {
                if name == function_name {
                    candidates.push(idx);
                }
            }
        }
    }
    candidates
        .into_iter()
        .min_by_key(|&idx| idx.abs_diff(hint_pos))
}

fn extract_symbols_for_function(
    lines: &[String],
    function_name: &str,
    hint_pos: usize,
) -> HashSet<String> {
    if lines.is_empty() {
        return HashSet::new();
    }
    let is_cont = compute_line_continuation(lines);

    if function_name == "<module>" {
        let mut module_symbols = HashSet::new();
        let mut skip_until_indent: Option<usize> = None;
        let mut line_idx = 0;

        while line_idx < lines.len() {
            let line = &lines[line_idx];

            if let Some(skip_indent) = skip_until_indent {
                if is_cont[line_idx] {
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

            if !is_cont[line_idx] && parse_def_or_class(line).is_some() {
                let def_indent = get_line_indent(line).unwrap_or(0);
                if let Some(parsed) = parse_def_or_class_header(lines, line_idx, &is_cont) {
                    module_symbols.extend(parsed.enclosing_symbols);
                    skip_until_indent = Some(def_indent);
                    line_idx = parsed.header_end + 1;
                    continue;
                }
            }

            let syms = collect_symbol_set(&[line.as_str()]);
            module_symbols.extend(syms);
            line_idx += 1;
        }

        return module_symbols;
    }

    let mut candidates = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if !is_cont[idx] {
            if let Some((name, _)) = parse_def_or_class(line) {
                if name == function_name {
                    if let Some(indent) = get_line_indent(line) {
                        candidates.push((idx, indent));
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        return HashSet::new();
    }

    let &(def_line, base_indent) = candidates
        .iter()
        .min_by_key(|(idx, _)| idx.abs_diff(hint_pos))
        .unwrap_or(&candidates[0]);

    let mut end_line = lines.len();
    for (j, line) in lines.iter().enumerate().skip(def_line + 1) {
        if is_cont[j] {
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
    let parsed_header = parse_def_or_class_header(lines, def_line, &is_cont);
    let (header_end, inline_body) = if let Some(parsed) = parsed_header {
        if !parsed.is_class {
            symbols.extend(parsed.func_symbols);
        }
        (parsed.header_end, parsed.inline_body)
    } else {
        (def_line, None)
    };

    if let Some(body_text) = inline_body {
        let syms = collect_symbol_set(&[&body_text]);
        symbols.extend(syms);
    }

    let mut skip_until_indent: Option<usize> = None;
    let mut line_idx = header_end + 1;
    while line_idx < end_line {
        let line = &lines[line_idx];

        if let Some(skip_indent) = skip_until_indent {
            if is_cont[line_idx] {
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

        if !is_cont[line_idx] && parse_def_or_class(line).is_some() {
            let nested_indent = get_line_indent(line).unwrap_or(base_indent + 1);
            if let Some(parsed) = parse_def_or_class_header(lines, line_idx, &is_cont) {
                symbols.extend(parsed.enclosing_symbols);
                skip_until_indent = Some(nested_indent);
                line_idx = parsed.header_end + 1;
                continue;
            }
        }

        let syms = collect_symbol_set(&[line.as_str()]);
        symbols.extend(syms);
        line_idx += 1;
    }

    symbols
}

fn compute_pyc_function_fingerprints(
    hunk: &crate::diff::Hunk,
    post_fix_lines: &[String],
    changed_pos: &[usize],
    base_lines: Option<&[String]>,
) -> Vec<PycFunctionFingerprint> {
    let post_fix_cont = compute_line_continuation(post_fix_lines);
    let base_cont = base_lines.map(compute_line_continuation);

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

    let base_defs: Vec<(String, usize)> = if let Some(base) = base_lines {
        let cont = base_cont.as_deref().unwrap_or(&[]);
        base_hunk_lines
            .iter()
            .map(|&b_pos| {
                let (b_name, _, b_def_pos) = find_enclosing_function_for_pos(base, b_pos, cont);
                (b_name, b_def_pos)
            })
            .collect()
    } else {
        Vec::new()
    };

    let fixed_defs: Vec<(String, usize)> = changed_pos
        .iter()
        .map(|&pos| {
            let (f_name, _, f_def_pos) =
                find_enclosing_function_for_pos(post_fix_lines, pos, &post_fix_cont);
            (f_name, f_def_pos)
        })
        .collect();

    let mut targets: Vec<(String, Option<usize>, Option<usize>)> = Vec::new();

    // 1. From fixed_defs
    for (f_name, f_def_pos) in fixed_defs {
        let b_hint = if let Some((_, b_pos)) = base_defs.iter().find(|(name, _)| *name == f_name) {
            Some(*b_pos)
        } else if let Some(base) = base_lines {
            if f_name == "<module>" {
                Some(0)
            } else {
                let cont = base_cont.as_deref().unwrap_or(&[]);
                find_candidate_def(base, &f_name, f_def_pos, cont)
            }
        } else {
            None
        };

        if !targets
            .iter()
            .any(|(name, f_h, _)| *name == f_name && *f_h == Some(f_def_pos))
        {
            targets.push((f_name, Some(f_def_pos), b_hint));
        }
    }

    // 2. From base_defs
    for (b_name, b_def_pos) in base_defs {
        if !targets
            .iter()
            .any(|(name, _, b_h)| *name == b_name && *b_h == Some(b_def_pos))
        {
            let f_hint = if b_name == "<module>" {
                Some(0)
            } else {
                find_candidate_def(post_fix_lines, &b_name, b_def_pos, &post_fix_cont)
            };
            targets.push((b_name, f_hint, Some(b_def_pos)));
        }
    }

    if targets.is_empty() {
        targets.push(("<module>".to_string(), Some(0), Some(0)));
    }

    let mut result = Vec::new();

    for (function_name, f_hint, b_hint) in targets {
        let fixed_symbols = if let Some(f_pos) = f_hint {
            extract_symbols_for_function(post_fix_lines, &function_name, f_pos)
        } else if function_name == "<module>" {
            extract_symbols_for_function(post_fix_lines, "<module>", 0)
        } else {
            HashSet::new()
        };

        let base_symbols = if let Some(base) = base_lines {
            if let Some(b_pos) = b_hint {
                extract_symbols_for_function(base, &function_name, b_pos)
            } else if function_name == "<module>" {
                extract_symbols_for_function(base, "<module>", 0)
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

    result
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

            let (post_fix_lines, hunk_changed_positions, base_lines) =
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

                let pyc_fingerprints = if file_path.ends_with(".py") {
                    compute_pyc_function_fingerprints(
                        hunk,
                        &post_fix_lines,
                        hunk_changed_positions
                            .get(hunk_idx)
                            .map(|v| v.as_slice())
                            .unwrap_or(&[]),
                        base_lines.as_deref(),
                    )
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
                        pyc_fingerprints: Vec::new(),
                    });
                    global_hunk_counter += 1;
                }
            }
        }

        // 3. Baseline subtraction (TR-SC-1, TR-SC-4 & TR-SC-5): walk base_tree_root
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
                pyc_fingerprint: ch.pyc_fingerprints.first().cloned(),
                pyc_fingerprints: ch.pyc_fingerprints,
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

        Ok(FingerprintSet {
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
        })
    }
}
