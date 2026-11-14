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
    /// `\N{...}` names (upper case, sorted, at most `MAX_UNRESOLVED_UNICODE_NAMES`) the
    /// Unicode name table did not know while fingerprinting `.pyc` scopes.
    pub unresolved_unicode_names: Vec<String>,
    /// Further distinct unresolved names beyond that bound, each counted once. Exact
    /// unless `unresolved_unicode_names_saturated`, when it is a lower bound.
    pub unresolved_unicode_names_omitted: usize,
    /// More than `MAX_OMITTED_UNICODE_NAME_DIGESTS` names were omitted, so
    /// `unresolved_unicode_names_omitted` is "at least".
    pub unresolved_unicode_names_saturated: bool,
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

/// The most passing fixes fingerprinted besides the gold patch (TR-SC-1).
pub const MAX_PASSING_FIXES: usize = 20;

/// Patch text with line endings and trailing whitespace normalised, for deduplication.
fn fix_dedup_key(patch: &str) -> String {
    let mut key = String::with_capacity(patch.len());
    for line in patch.lines() {
        key.push_str(line.trim_end());
        key.push('\n');
    }
    key.trim_end().to_string()
}

/// The first `MAX_PASSING_FIXES` fixes that differ from the gold patch and each other.
pub fn select_passing_fixes<'a>(gold_patch: &str, fixes: &'a [String]) -> Vec<&'a str> {
    let mut seen = HashSet::new();
    seen.insert(fix_dedup_key(gold_patch));
    let mut out = Vec::new();
    for fix in fixes {
        if out.len() >= MAX_PASSING_FIXES {
            break;
        }
        let key = fix_dedup_key(fix);
        if !key.is_empty() && seen.insert(key) {
            out.push(fix.as_str());
        }
    }
    out
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

/// Whitespace that separates Python tokens on one line (space, tab, form feed).
fn is_py_inline_space(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\x0c'
}

/// Strips the keyword `kw` from the start of `s` when it is a whole token followed by
/// inline whitespace, and returns the rest with that whitespace removed.
fn strip_py_keyword<'s>(s: &'s str, kw: &str) -> Option<&'s str> {
    let rest = s.strip_prefix(kw)?;
    if !rest.starts_with(is_py_inline_space) {
        return None;
    }
    Some(rest.trim_start_matches(is_py_inline_space))
}

fn parse_def_or_class(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim_start_matches(is_py_inline_space);
    let (ident_part, is_class) = if let Some(rest) = strip_py_keyword(trimmed, "def") {
        (rest, false)
    } else if let Some(rest) =
        strip_py_keyword(trimmed, "async").and_then(|r| strip_py_keyword(r, "def"))
    {
        (rest, false)
    } else {
        (strip_py_keyword(trimmed, "class")?, true)
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

/// Marks, in one pass, which tokens start a statement: the first token, a token after a
/// depth-0 `;` or `:`, or the first token of a new physical line at bracket depth 0.
///
/// Soft keywords (`type`, `match`, `case`) can only appear at a statement start, and a
/// statement start never lies inside brackets, so the bracket depth is tracked
/// incrementally and the whole computation is linear in the number of tokens.
fn statement_starts(tokens: &[crate::winnow::Token]) -> Vec<bool> {
    let mut starts = Vec::with_capacity(tokens.len());
    let mut depth = 0usize;
    let mut prev: Option<&crate::winnow::Token> = None;
    for tok in tokens {
        let start = match prev {
            None => true,
            Some(p) => depth == 0 && (p.text == ";" || p.text == ":" || p.line < tok.line),
        };
        starts.push(start);
        match tok.text.as_str() {
            "(" | "[" | "{" => depth = depth.saturating_add(1),
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            _ => {}
        }
        prev = Some(tok);
    }
    starts
}

/// Whether the identifier at `idx` is used as a soft keyword. `is_start` is the token's
/// entry from `statement_starts`. A forward scan runs only from a depth-0 statement start
/// and stops at the next depth-0 `;`, `:` or newline, so the scans of different starts
/// never overlap and their total cost is linear.
fn is_contextual_keyword(tokens: &[crate::winnow::Token], idx: usize, is_start: bool) -> bool {
    if !is_start {
        return false;
    }
    let Some(tok) = tokens.get(idx) else {
        return false;
    };
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

fn decode_py_string_literal(tok_text: &str, unresolved: &mut UnresolvedNames) -> Option<String> {
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
    Some(decode_py_escapes(content, unresolved))
}

/// Most distinct unresolved `\N{...}` names a fingerprint set records; more are counted.
pub const MAX_UNRESOLVED_UNICODE_NAMES: usize = 64;

/// Most digests of omitted (not retained) distinct unresolved names kept for counting.
pub const MAX_OMITTED_UNICODE_NAME_DIGESTS: usize = 4096;

/// A fixed-size digest of an omitted name: the first 16 bytes of its SHA-256.
type NameDigest = [u8; 16];

fn name_digest(name: &str) -> NameDigest {
    let full: [u8; 32] = Sha256::digest(name.as_bytes()).into();
    let mut d = [0u8; 16];
    d.copy_from_slice(full.get(..16).unwrap_or(&[0u8; 16]));
    d
}

/// The `\N{...}` names the Unicode name table did not know, recorded out of band where
/// the lookup fails. Distinct names are counted exactly while bounded:
///
/// - `names` keeps the `MAX_UNRESOLVED_UNICODE_NAMES` smallest names (in byte order), so
///   the retained set does not depend on the order of records and merges;
/// - `omitted` keeps digests of the other distinct names, at most
///   `MAX_OMITTED_UNICODE_NAME_DIGESTS` (the smallest digests, again order-independent);
/// - `saturated` is set once a digest had to be dropped, and the count is then only a
///   lower bound.
///
/// A name is counted once whether it is retained, omitted, or seen on both sides of a
/// merge. Omitted names are always larger than every retained name, because the largest
/// retained name only decreases over time.
#[derive(Debug, Default, Clone)]
pub(crate) struct UnresolvedNames {
    names: std::collections::BTreeSet<String>,
    omitted: std::collections::BTreeSet<NameDigest>,
    saturated: bool,
}

impl UnresolvedNames {
    fn record(&mut self, name: &str) {
        if self.names.contains(name) {
            return;
        }
        if self.names.len() < MAX_UNRESOLVED_UNICODE_NAMES {
            self.omitted.remove(&name_digest(name));
            self.names.insert(name.to_string());
            return;
        }
        let largest_is_larger = self
            .names
            .last()
            .is_some_and(|largest| largest.as_str() > name);
        if largest_is_larger {
            // Keep the smallest names: the largest retained one becomes omitted.
            if let Some(evicted) = self.names.pop_last() {
                self.insert_digest(name_digest(&evicted));
            }
            self.omitted.remove(&name_digest(name));
            self.names.insert(name.to_string());
        } else {
            self.insert_digest(name_digest(name));
        }
    }

    fn insert_digest(&mut self, digest: NameDigest) {
        if self.omitted.contains(&digest) {
            return;
        }
        // Never count a retained name again through its digest.
        if self.names.iter().any(|n| name_digest(n) == digest) {
            return;
        }
        if self.omitted.len() < MAX_OMITTED_UNICODE_NAME_DIGESTS {
            self.omitted.insert(digest);
            return;
        }
        self.saturated = true;
        // Keep the smallest digests so the kept set does not depend on order.
        if self.omitted.last().is_some_and(|largest| *largest > digest) {
            self.omitted.pop_last();
            self.omitted.insert(digest);
        }
    }

    fn merge(&mut self, other: &UnresolvedNames) {
        for name in &other.names {
            self.record(name);
        }
        for digest in &other.omitted {
            self.insert_digest(*digest);
        }
        self.saturated |= other.saturated;
    }

    /// The number of distinct names recorded (a lower bound when `saturated`).
    fn distinct_count(&self) -> usize {
        self.names.len().saturating_add(self.omitted.len())
    }
}

/// Prefix of the symbol for a string with an unresolved `\N{...}` name. The rest is a
/// length-prefixed encoding of its pieces: `L<bytes>:<text>` for decoded text and
/// `N<bytes>:<NAME>` for each unresolved name, so different names give different symbols
/// and the encoding is unambiguous. Names are reported from `UnresolvedNames`, never by
/// parsing symbols.
const UNRESOLVED_SYMBOL_PREFIX: &str = "\u{FFFF}pyc-unresolved-name:";

fn push_length_prefixed(out: &mut String, tag: char, text: &str) {
    out.push(tag);
    out.push_str(&text.len().to_string());
    out.push(':');
    out.push_str(text);
}

/// Decodes the backslash escapes of a non-raw string body as the compiler does. A string
/// with a `\N{...}` name missing from the Unicode name table becomes an
/// `UNRESOLVED_SYMBOL_PREFIX` symbol, and the name is recorded in `unresolved`.
fn decode_py_escapes(content: &str, unresolved: &mut UnresolvedNames) -> String {
    let mut encoded: Option<String> = None;
    let mut run_start = 0usize;
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
                Some('N') if chars.peek() == Some(&'{') => {
                    chars.next();
                    let mut name = String::new();
                    let mut overlong = false;
                    for n in chars.by_ref() {
                        if n == '}' {
                            break;
                        }
                        if name.len() < crate::unicode_names::MAX_UNICODE_NAME_LEN {
                            name.push(n);
                        } else {
                            overlong = true;
                        }
                    }
                    match crate::unicode_names::lookup(&name).filter(|_| !overlong) {
                        Some(ch) => out.push(ch),
                        None => {
                            let upper = name.to_uppercase();
                            unresolved.record(&upper);
                            let enc = encoded.get_or_insert_with(String::new);
                            push_length_prefixed(enc, 'L', out.get(run_start..).unwrap_or(""));
                            push_length_prefixed(enc, 'N', &upper);
                            run_start = out.len();
                        }
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
    match encoded {
        Some(mut enc) => {
            push_length_prefixed(&mut enc, 'L', out.get(run_start..).unwrap_or(""));
            format!("{UNRESOLVED_SYMBOL_PREFIX}{enc}")
        }
        None => out,
    }
}

/// Nesting limit for f-strings inside f-string replacement fields.
const MAX_FSTRING_DEPTH: usize = 4;

/// The symbols a string-literal token contributes to a code object: the decoded constant
/// for an ordinary string, or for an f-string its literal pieces (constants) plus the
/// symbols of its replacement-field expressions and format specs. `None` when the token
/// is not a string literal.
fn py_literal_symbols(tok_text: &str, unresolved: &mut UnresolvedNames) -> Option<Vec<String>> {
    py_literal_symbols_depth(tok_text, 0, unresolved)
}

fn py_literal_symbols_depth(
    tok_text: &str,
    depth: usize,
    unresolved: &mut UnresolvedNames,
) -> Option<Vec<String>> {
    let quote_start = tok_text
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(tok_text.len());
    let prefix = tok_text.get(..quote_start)?;
    if !prefix.contains(['f', 'F']) {
        return decode_py_string_literal(tok_text, unresolved).map(|c| vec![c]);
    }
    if prefix.len() > 2 || !prefix.chars().all(|c| "fFrR".contains(c)) {
        return None;
    }
    let is_raw = prefix.contains(['r', 'R']);
    let rest = tok_text.get(quote_start..)?;
    let quote = ["\"\"\"", "'''", "\"", "'"]
        .into_iter()
        .find(|q| rest.starts_with(q))?;
    let inner = rest.strip_prefix(quote).unwrap_or(rest);
    let body = inner.strip_suffix(quote).unwrap_or(inner);
    let mut out = Vec::new();
    fstring_body_symbols(body, is_raw, depth, &mut out, unresolved);
    Some(out)
}

fn push_fstring_literal(
    raw_piece: &str,
    is_raw: bool,
    literal: &mut String,
    unresolved: &mut UnresolvedNames,
) {
    if is_raw {
        literal.push_str(raw_piece);
    } else {
        literal.push_str(&decode_py_escapes(raw_piece, unresolved));
    }
}

/// Splits an f-string body into literal pieces (constants) and replacement fields, whose
/// expression symbols and format-spec pieces are added recursively.
fn fstring_body_symbols(
    body: &str,
    is_raw: bool,
    depth: usize,
    out: &mut Vec<String>,
    unresolved: &mut UnresolvedNames,
) {
    let bytes = body.as_bytes();
    let mut literal = String::new();
    let mut piece_start = 0usize;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if (b == b'{' || b == b'}') && bytes.get(i.saturating_add(1)) == Some(&b) {
            push_fstring_literal(
                body.get(piece_start..i).unwrap_or(""),
                is_raw,
                &mut literal,
                unresolved,
            );
            literal.push(char::from(b));
            i = i.saturating_add(2);
            piece_start = i;
            continue;
        }
        if b == b'{' {
            push_fstring_literal(
                body.get(piece_start..i).unwrap_or(""),
                is_raw,
                &mut literal,
                unresolved,
            );
            let field_start = i.saturating_add(1);
            let field_end = fstring_field_end(bytes, field_start);
            let field = body.get(field_start..field_end).unwrap_or("");
            let (expr, spec, self_doc) = split_fstring_field(field);
            if self_doc {
                // `{x=}` stores the expression text and `=` as a literal piece.
                literal.push_str(field.get(..expr.len().saturating_add(1)).unwrap_or(""));
            }
            if !literal.is_empty() {
                out.push(std::mem::take(&mut literal));
            }
            if depth < MAX_FSTRING_DEPTH {
                out.extend(collect_symbol_set_depth(
                    &[expr],
                    depth.saturating_add(1),
                    unresolved,
                ));
                if let Some(spec) = spec {
                    fstring_body_symbols(spec, is_raw, depth.saturating_add(1), out, unresolved);
                }
            }
            i = field_end.saturating_add(1);
            piece_start = i;
            continue;
        }
        i = i.saturating_add(1);
    }
    push_fstring_literal(
        body.get(piece_start..).unwrap_or(""),
        is_raw,
        &mut literal,
        unresolved,
    );
    if !literal.is_empty() {
        out.push(literal);
    }
}

/// Index of the `}` closing the replacement field that starts at `start` (or the body end).
fn fstring_field_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut i = start;
    while let Some(&b) = bytes.get(i) {
        if let Some(q) = quote {
            if b == b'\\' {
                i = i.saturating_add(1);
            } else if b == q {
                quote = None;
            }
        } else {
            match b {
                b'\'' | b'"' => quote = Some(b),
                b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
                b')' | b']' => depth = depth.saturating_sub(1),
                b'}' if depth == 0 => return i,
                b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        i = i.saturating_add(1);
    }
    bytes.len()
}

/// Splits a replacement field into its expression, optional format spec, and whether it
/// is a self-documenting `expr=` field.
fn split_fstring_field(field: &str) -> (&str, Option<&str>, bool) {
    let bytes = field.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut expr_end = bytes.len();
    let mut spec = None;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if let Some(q) = quote {
            if b == b'\\' {
                i = i.saturating_add(1);
            } else if b == q {
                quote = None;
            }
            i = i.saturating_add(1);
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'!' if depth == 0 && bytes.get(i.saturating_add(1)) != Some(&b'=') => {
                expr_end = i;
                spec = field
                    .get(i..)
                    .and_then(|r| r.find(':'))
                    .and_then(|colon| field.get(i.saturating_add(colon).saturating_add(1)..));
                break;
            }
            b':' if depth == 0 => {
                expr_end = i;
                spec = field.get(i.saturating_add(1)..);
                break;
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    let expr = field.get(..expr_end).unwrap_or("");
    let trimmed = expr.trim_end();
    let self_doc = trimmed.ends_with('=')
        && !trimmed.ends_with("==")
        && !trimmed.ends_with("!=")
        && !trimmed.ends_with("<=")
        && !trimmed.ends_with(">=");
    let expr = if self_doc {
        trimmed.strip_suffix('=').unwrap_or(trimmed)
    } else {
        expr
    };
    (expr, spec, self_doc)
}

/// Merges a `.` immediately followed (no whitespace) by a digit token into one float
/// token: Python's tokenizer reads `.3` and `.3e5` as numbers.
fn merge_leading_dot_floats(
    text: &str,
    tokens: Vec<crate::winnow::Token>,
) -> Vec<crate::winnow::Token> {
    let mut out: Vec<crate::winnow::Token> = Vec::with_capacity(tokens.len());
    let mut source_end = 0usize;
    let mut iter = tokens.into_iter().peekable();
    while let Some(mut token) = iter.next() {
        let start = text
            .get(source_end..)
            .and_then(|s| s.find(&token.text))
            .and_then(|offset| source_end.checked_add(offset))
            .unwrap_or(source_end);
        source_end = start.saturating_add(token.text.len());
        if token.text == "." {
            let adjacent_digit = iter.peek().is_some_and(|next| {
                next.text.starts_with(|c: char| c.is_ascii_digit())
                    && text
                        .get(source_end..)
                        .is_some_and(|s| s.starts_with(&next.text))
            });
            // `1..3`-style input and attribute access never put a digit right after `.`
            // in valid code, except a float literal.
            let after_number = out
                .last()
                .is_some_and(|p| p.text.starts_with(|c: char| c.is_ascii_digit()));
            if adjacent_digit && !after_number {
                if let Some(number) = iter.next() {
                    source_end = source_end.saturating_add(number.text.len());
                    token.text.push_str(&number.text);
                }
            }
        }
        out.push(token);
    }
    out
}

fn pyc_literal_tokens(text: &str) -> Vec<crate::winnow::Token> {
    let tokens = merge_leading_dot_floats(text, crate::winnow::tokenize(text));
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
        if matches!(
            prefix.as_str(),
            "r" | "b" | "u" | "br" | "rb" | "f" | "rf" | "fr"
        ) {
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
                        | "await"
                        | "assert"
                        | "if"
                        | "elif"
                        | "else"
                        | "while"
                        | "and"
                        | "or"
                        | "not"
                        | "in"
                        | "is"
                        | "case"
                        | "lambda"
                        | "="
                        | "<"
                        | ">"
                        | "!"
                        | "("
                        | "["
                        | "{"
                        | ","
                        | ":"
                        | ";"
                        | "+"
                        | "-"
                        | "*"
                        | "/"
                        | "%"
                        | "**"
                        | "//"
                        | "&"
                        | "|"
                        | "^"
                        | "~"
                        | "@"
                )
            });
            if unary && iter.peek().is_some_and(|next| is_pyc_number(&next.text)) {
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
    let t = text.strip_prefix('-').unwrap_or(text);
    let t = t.strip_prefix('.').unwrap_or(t);
    t.starts_with(|c: char| c.is_ascii_digit())
}

/// Most bits of an integer the marshal reader decodes (256 15-bit digits); a longer
/// literal can never match a marshalled constant and is left as source text. This also
/// bounds the conversion work per literal byte by a constant.
const MAX_BIG_INT_LITERAL_BITS: usize = 256 * 15;

/// Converts the digits of an integer literal in `radix` (2, 8, 10 or 16) to decimal text
/// without leading zeros, using base-1e9 limbs. `None` on a non-digit or an overlong input.
fn big_int_to_decimal(digits: &str, radix: u32) -> Option<String> {
    let bits_per_digit: usize = match radix {
        2 => 1,
        8 => 3,
        10 => 3, // log2(10) > 3: a slightly generous cap
        16 => 4,
        _ => return None,
    };
    let max_digits = MAX_BIG_INT_LITERAL_BITS / bits_per_digit + 1;
    if digits.is_empty() || digits.len() > max_digits {
        return None;
    }
    const LIMB: u64 = 1_000_000_000;
    // Little-endian base-1e9 limbs.
    let mut limbs: Vec<u64> = vec![0];
    for c in digits.chars() {
        let d = u64::from(c.to_digit(radix)?);
        let mut carry = d;
        for limb in limbs.iter_mut() {
            let v = limb.checked_mul(u64::from(radix))?.checked_add(carry)?;
            *limb = v % LIMB;
            carry = v / LIMB;
        }
        while carry > 0 {
            limbs.push(carry % LIMB);
            carry /= LIMB;
        }
    }
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
    let mut out = String::new();
    for (i, limb) in limbs.iter().rev().enumerate() {
        if i == 0 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{limb:09}"));
        }
    }
    Some(out)
}

fn normalize_py_numeric_literal(text: &str) -> String {
    let normalized = normalize_py_numeric_literal_small(text);
    if normalized != text {
        return normalized;
    }
    // Integers beyond i128, as the compiler stores them: decimal, no `_`, no leading zeros.
    let (sign, body) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text),
    };
    let s = body.replace('_', "");
    let lower = s.to_ascii_lowercase();
    let converted = if let Some(h) = lower.strip_prefix("0x") {
        big_int_to_decimal(h, 16)
    } else if let Some(o) = lower.strip_prefix("0o") {
        big_int_to_decimal(o, 8)
    } else if let Some(b) = lower.strip_prefix("0b") {
        big_int_to_decimal(b, 2)
    } else if lower.bytes().all(|b| b.is_ascii_digit()) {
        big_int_to_decimal(&lower, 10)
    } else {
        None
    };
    match converted {
        Some(v) if v == "0" => v,
        Some(v) => format!("{sign}{v}"),
        None => text.to_string(),
    }
}

fn normalize_py_numeric_literal_small(text: &str) -> String {
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

fn collect_symbol_set(lines: &[&str], unresolved: &mut UnresolvedNames) -> HashSet<String> {
    collect_symbol_set_depth(lines, 0, unresolved)
}

fn collect_symbol_set_depth(
    lines: &[&str],
    depth: usize,
    unresolved: &mut UnresolvedNames,
) -> HashSet<String> {
    let text = lines.join("\n");
    let tokens = pyc_literal_tokens(&text);
    let mut symbols = HashSet::new();
    let mut prev_is_dot = false;
    let starts = statement_starts(&tokens);

    for (idx, tok) in tokens.iter().enumerate() {
        if let Some(contents) = py_literal_symbols_depth(&tok.text, depth, unresolved) {
            symbols.extend(contents);
            prev_is_dot = false;
        } else if is_pyc_number(&tok.text) {
            symbols.insert(normalize_py_numeric_literal(&tok.text));
            prev_is_dot = false;
        } else if crate::binary::is_identifier(&tok.text) {
            let is_start = starts.get(idx).copied().unwrap_or(false);
            if prev_is_dot
                || (!is_py_keyword(&tok.text) && !is_contextual_keyword(&tokens, idx, is_start))
            {
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

/// Parses the `def`/`class` header starting at `def_line`.
///
/// The colon search covers only the header's logical line (`def_line` plus the following
/// lines `is_cont` marks as continuations), and every scanned line is charged to `budget`.
/// Logical lines never overlap and headers start only on non-continuation lines, so the
/// total scan over all headers of a file is linear in its length.
fn parse_def_or_class_header(
    lines: &[String],
    def_line: usize,
    is_cont: &[bool],
    budget: &mut WorkBudget,
    unresolved: &mut UnresolvedNames,
) -> Result<Option<ParsedDefHeader>, FingerprintError> {
    if def_line >= lines.len() {
        return Ok(None);
    }
    let Some((name, is_class)) = parse_def_or_class(&lines[def_line]) else {
        return Ok(None);
    };

    let mut depth = 0usize;
    let mut header_end = def_line;
    let mut colon_byte_idx = None;
    // Triple-quote state carries across the physical lines of the logical header.
    let mut in_triple: Option<u8> = None;

    for (idx, line) in lines.iter().enumerate().skip(def_line) {
        if idx > def_line && !is_cont.get(idx).copied().unwrap_or(false) {
            // The logical line ended without a depth-0 colon.
            break;
        }
        budget.charge(1)?;
        let bytes = line.as_bytes();
        let mut i = 0;
        let len = bytes.len();

        while i < len {
            let at = |k: usize| bytes.get(k).copied();
            let b = bytes[i];
            if let Some(q) = in_triple {
                // Inside a triple-quoted string, which may span lines of the header.
                if b == b'\\' {
                    i = i.saturating_add(2);
                } else if b == q && at(i + 1) == Some(q) && at(i + 2) == Some(q) {
                    in_triple = None;
                    i += 3;
                } else {
                    i += 1;
                }
                continue;
            }
            if b == b'#' {
                break;
            }
            if b == b'\'' || b == b'"' {
                let quote = b;
                if at(i + 1) == Some(quote) && at(i + 2) == Some(quote) {
                    in_triple = Some(quote);
                    i += 3;
                    continue;
                }
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
                if let Some(contents) = py_literal_symbols(&tok.text, unresolved) {
                    enclosing_symbols.extend(contents);
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
                    if let Some(contents) = py_literal_symbols(&tok.text, unresolved) {
                        enclosing_symbols.extend(contents);
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
                    if let Some(contents) = py_literal_symbols(&tok.text, unresolved) {
                        enclosing_symbols.extend(contents);
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

    Ok(Some(ParsedDefHeader {
        is_class,
        func_symbols,
        enclosing_symbols,
        header_end,
        inline_body,
    }))
}

// Scope paths include the occurrence of each definition in source order, so
// repeated names in the same scope also have one-to-one identities.
struct PycDefinition {
    name: String,
    pos: usize,
    end_line: usize,
    base_indent: usize,
    parent: Option<usize>,
    /// Fixed-size identity of the parent scope path (all zeros at module level).
    parent_path: ScopePathId,
    /// Fixed-size identity of this definition's scope path: the parent path, the name and
    /// the occurrence of that name in the parent. Two analyses (base and fixed) compare these
    /// without cloning whole paths.
    path: ScopePathId,
}

type ScopePathId = [u8; 32];

fn child_scope_path(parent: &ScopePathId, name: &str, ordinal: usize) -> ScopePathId {
    let mut h = Sha256::new();
    h.update(parent);
    h.update((name.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.update((ordinal as u64).to_le_bytes());
    h.finalize().into()
}

/// Discovers the `def`/`class` scopes of a file.
///
/// Work and memory are linear in the file: each definition stores only its own name and
/// fixed-size path identities, occurrences are counted per (parent path, name hash), and
/// the line-to-scope map is built in one pass. One budget unit is charged per line and per
/// 1 KiB of definition name.
fn pyc_definitions(
    lines: &[String],
    continuation: &[bool],
    budget: &mut WorkBudget,
) -> Result<(Vec<PycDefinition>, Vec<Option<usize>>), FingerprintError> {
    let mut definitions: Vec<PycDefinition> = Vec::new();
    let mut scopes: Vec<(usize, usize)> = Vec::new();
    let mut occurrences: HashMap<(ScopePathId, ScopePathId), usize> = HashMap::new();
    let mut active_stack: Vec<(usize, usize)> = Vec::new();

    for (pos, line) in lines.iter().enumerate() {
        budget.charge(1)?;
        if continuation.get(pos).copied().unwrap_or(false) {
            continue;
        }
        let Some(indent) = get_line_indent(line) else {
            continue;
        };
        while active_stack
            .last()
            .is_some_and(|(stack_indent, _)| indent <= *stack_indent)
        {
            if let Some((_, def_idx)) = active_stack.pop() {
                if let Some(d) = definitions.get_mut(def_idx) {
                    d.end_line = pos;
                }
            }
        }
        while scopes.last().is_some_and(|(level, _)| *level >= indent) {
            scopes.pop();
        }
        if let Some((name, _)) = parse_def_or_class(line) {
            budget.charge(name.len() / 1024)?;
            let parent = scopes.last().and_then(|(_, index)| definitions.get(*index));
            let parent_path = parent.map(|d| d.path).unwrap_or([0u8; 32]);
            let parent_pos = parent.map(|d| d.pos);
            let name_id: ScopePathId = Sha256::digest(name.as_bytes()).into();
            let ordinal = occurrences.entry((parent_path, name_id)).or_insert(0usize);
            let path = child_scope_path(&parent_path, &name, *ordinal);
            *ordinal = ordinal.saturating_add(1);
            let def_idx = definitions.len();
            scopes.push((indent, def_idx));
            active_stack.push((indent, def_idx));
            definitions.push(PycDefinition {
                name,
                pos,
                end_line: lines.len(),
                base_indent: indent,
                parent: parent_pos,
                parent_path,
                path,
            });
        }
    }

    // Innermost enclosing definition per line, in one pass: definitions are in source
    // order and properly nested, so a stack of open definitions suffices.
    let mut line_scopes = vec![None; lines.len()];
    let mut open: Vec<usize> = Vec::new();
    let mut next_def = 0usize;
    for (l, slot) in line_scopes.iter_mut().enumerate() {
        while open
            .last()
            .and_then(|&i| definitions.get(i))
            .is_some_and(|d| d.end_line <= l)
        {
            open.pop();
        }
        while definitions.get(next_def).is_some_and(|d| d.pos == l) {
            open.push(next_def);
            next_def = next_def.saturating_add(1);
        }
        *slot = open.last().copied();
    }

    Ok((definitions, line_scopes))
}

#[derive(Clone, Copy, Debug)]
enum HunkBlockKind {
    Context,
    Edit { dest_empty: bool },
}

#[derive(Clone, Copy, Debug)]
struct HunkBlock {
    source_start: usize,
    source_end: usize,
    dest_start: usize,
    dest_end: usize,
    kind: HunkBlockKind,
}

struct HunkPositionMapper {
    source_start: usize,
    destination_start: usize,
    source_end: usize,
    destination_end: usize,
    blocks: Vec<HunkBlock>,
}

impl HunkPositionMapper {
    fn new(hunk: &crate::diff::Hunk, from_fixed: bool) -> Self {
        let mut old = hunk.header.old_range.start.saturating_sub(1);
        let mut new = hunk.header.new_range.start.saturating_sub(1);
        let (source_start, destination_start) = if from_fixed { (new, old) } else { (old, new) };
        let mut blocks = Vec::new();
        let mut lines = hunk.lines.iter().peekable();

        while let Some(line) = lines.next() {
            if line.line_type == DiffLineType::Context {
                let old_ctx_start = old;
                let new_ctx_start = new;
                old = old.saturating_add(1);
                new = new.saturating_add(1);
                while lines
                    .peek()
                    .is_some_and(|l| l.line_type == DiffLineType::Context)
                {
                    lines.next();
                    old = old.saturating_add(1);
                    new = new.saturating_add(1);
                }
                let (s_start, s_end, d_start, d_end) = if from_fixed {
                    (new_ctx_start, new, old_ctx_start, old)
                } else {
                    (old_ctx_start, old, new_ctx_start, new)
                };
                blocks.push(HunkBlock {
                    source_start: s_start,
                    source_end: s_end,
                    dest_start: d_start,
                    dest_end: d_end,
                    kind: HunkBlockKind::Context,
                });
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
                .is_some_and(|l| l.line_type != DiffLineType::Context)
            {
                if let Some(l) = lines.next() {
                    if l.line_type == DiffLineType::Removed {
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
            if source < source_end {
                blocks.push(HunkBlock {
                    source_start: source,
                    source_end,
                    dest_start: destination,
                    dest_end: destination_end,
                    kind: HunkBlockKind::Edit {
                        dest_empty: destination == destination_end,
                    },
                });
            }
        }

        let (source_end, destination_end) = if from_fixed { (new, old) } else { (old, new) };
        Self {
            source_start,
            destination_start,
            source_end,
            destination_end,
            blocks,
        }
    }

    fn map(&self, pos: usize) -> Option<usize> {
        if pos < self.source_start {
            return Some(
                self.destination_start
                    .saturating_sub(self.source_start.saturating_sub(pos)),
            );
        }
        if pos >= self.source_end {
            return Some(
                self.destination_end
                    .saturating_add(pos.saturating_sub(self.source_end)),
            );
        }
        let idx = self.blocks.binary_search_by(|b| {
            if pos < b.source_start {
                std::cmp::Ordering::Greater
            } else if pos >= b.source_end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });
        match idx {
            Ok(i) => {
                let block = self.blocks.get(i)?;
                match block.kind {
                    HunkBlockKind::Context => Some(
                        block
                            .dest_start
                            .saturating_add(pos.saturating_sub(block.source_start)),
                    ),
                    HunkBlockKind::Edit { dest_empty } => {
                        if dest_empty {
                            None
                        } else {
                            Some(
                                block
                                    .dest_start
                                    .saturating_add(pos.saturating_sub(block.source_start))
                                    .min(block.dest_end.saturating_sub(1)),
                            )
                        }
                    }
                }
            }
            Err(_) => Some(
                self.destination_end
                    .saturating_add(pos.saturating_sub(self.source_end)),
            ),
        }
    }
}

fn corresponding_pyc_definition(
    name: &str,
    pos: usize,
    hint: Option<usize>,
    source: &PycFileAnalysis<'_>,
    destination: &PycFileAnalysis<'_>,
    used: &HashSet<usize>,
    budget: &mut WorkBudget,
) -> Result<Option<usize>, FingerprintError> {
    if name == "<module>" {
        return Ok(Some(0));
    }
    let Some(hint) = hint else {
        return Ok(None);
    };
    let source_def = source
        .definition_by_pos
        .get(&pos)
        .and_then(|&idx| source.definitions.get(idx))
        .filter(|d| d.name == name);
    let Some(source_def) = source_def else {
        return Ok(None);
    };
    let parent_key = source_def.parent_path;

    let candidates = match destination.definitions_by_name.get(name) {
        Some(c) => c,
        None => return Ok(None),
    };
    budget.charge(candidates.len())?;

    let best = candidates
        .iter()
        .filter_map(|&idx| destination.definitions.get(idx))
        .filter(|d| !used.contains(&d.pos) && d.parent_path == parent_key)
        .min_by_key(|d| (d.pos.abs_diff(hint), d.pos))
        .map(|d| d.pos);

    Ok(best)
}

struct PycFileAnalysis<'a> {
    lines: &'a [String],
    continuation: Vec<bool>,
    definitions: Vec<PycDefinition>,
    definition_by_pos: HashMap<usize, usize>,
    definitions_by_name: HashMap<String, Vec<usize>>,
    line_scopes: Vec<Option<usize>>,
    headers: HashMap<usize, Option<ParsedDefHeader>>,
    scope_membership: HashMap<usize, Option<usize>>,
    /// `\N{...}` names the Unicode table did not know, met while extracting symbols.
    unresolved: UnresolvedNames,
    symbols: HashMap<(String, usize), HashSet<String>>,
}

impl<'a> PycFileAnalysis<'a> {
    fn new(lines: &'a [String], budget: &mut WorkBudget) -> Result<Self, FingerprintError> {
        let continuation = compute_line_continuation(lines);
        let (definitions, line_scopes) = pyc_definitions(lines, &continuation, budget)?;
        let mut definition_by_pos = HashMap::with_capacity(definitions.len());
        let mut definitions_by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, def) in definitions.iter().enumerate() {
            definition_by_pos.insert(def.pos, idx);
            definitions_by_name
                .entry(def.name.clone())
                .or_default()
                .push(idx);
        }
        Ok(Self {
            lines,
            continuation,
            definitions,
            definition_by_pos,
            definitions_by_name,
            line_scopes,
            headers: HashMap::new(),
            scope_membership: HashMap::new(),
            unresolved: UnresolvedNames::default(),
            symbols: HashMap::new(),
        })
    }

    fn get_or_parse_header(
        &mut self,
        def_pos: usize,
        budget: &mut WorkBudget,
    ) -> Result<Option<&ParsedDefHeader>, FingerprintError> {
        if !self.headers.contains_key(&def_pos) {
            budget.charge(1)?;
            let parsed = parse_def_or_class_header(
                self.lines,
                def_pos,
                &self.continuation,
                budget,
                &mut self.unresolved,
            )?;
            self.headers.insert(def_pos, parsed);
        }
        Ok(self.headers.get(&def_pos).and_then(|opt| opt.as_ref()))
    }

    /// The innermost definition (by index) enclosing line `pos`, or `None` for module level.
    fn get_scope_for_pos(
        &mut self,
        pos: usize,
        budget: &mut WorkBudget,
    ) -> Result<Option<usize>, FingerprintError> {
        if let Some(scope) = self.scope_membership.get(&pos) {
            return Ok(*scope);
        }
        budget.charge(1)?;
        let scope = self
            .line_scopes
            .get(pos)
            .copied()
            .flatten()
            .filter(|&i| i < self.definitions.len());
        self.scope_membership.insert(pos, scope);
        Ok(scope)
    }

    /// The `(name, position)` of a scope; names are cloned once per distinct scope.
    fn scope_name(&self, scope: Option<usize>) -> (String, usize) {
        scope
            .and_then(|i| self.definitions.get(i))
            .map(|d| (d.name.clone(), d.pos))
            .unwrap_or_else(|| ("<module>".to_string(), 0))
    }

    fn changed_scopes(
        &mut self,
        positions: &[usize],
        budget: &mut WorkBudget,
    ) -> Result<Vec<(String, usize)>, FingerprintError> {
        let mut result = Vec::new();
        let mut seen: HashSet<Option<usize>> = HashSet::new();
        for &pos in positions {
            budget.charge(1)?;
            let enclosing = self.get_scope_for_pos(pos, budget)?;
            if seen.insert(enclosing) {
                result.push(self.scope_name(enclosing));
            }
            let idx = self.definitions.partition_point(|d| d.pos <= pos);
            if idx > 0 {
                if let Some(def) = self.definitions.get(idx - 1) {
                    let def_pos = def.pos;
                    let parent_pos = def.parent;
                    if let Some(header) = self.get_or_parse_header(def_pos, budget)? {
                        if pos <= header.header_end {
                            let parent_scope =
                                parent_pos.and_then(|p| self.definition_by_pos.get(&p).copied());
                            if seen.insert(parent_scope) {
                                result.push(self.scope_name(parent_scope));
                            }
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
                budget.charge(1)?;
                let Some(line) = self.lines.get(line_idx) else {
                    break;
                };

                if let Some(skip_indent) = skip_until_indent {
                    if self.continuation.get(line_idx).copied().unwrap_or(false) {
                        line_idx = line_idx.saturating_add(1);
                        continue;
                    }
                    if let Some(indent) = get_line_indent(line) {
                        if indent > skip_indent {
                            line_idx = line_idx.saturating_add(1);
                            continue;
                        } else {
                            skip_until_indent = None;
                        }
                    } else {
                        line_idx = line_idx.saturating_add(1);
                        continue;
                    }
                }

                if !self.continuation.get(line_idx).copied().unwrap_or(false)
                    && parse_def_or_class(line).is_some()
                {
                    let def_indent = get_line_indent(line).unwrap_or(0);
                    if let Some(parsed) = self.get_or_parse_header(line_idx, budget)? {
                        let header_end = parsed.header_end;
                        let enclosing_syms = parsed.enclosing_symbols.clone();
                        module_symbols.extend(enclosing_syms);
                        skip_until_indent = Some(def_indent);
                        line_idx = header_end.saturating_add(1);
                        continue;
                    }
                }

                let mut span_end = line_idx.saturating_add(1);
                while span_end < self.lines.len()
                    && self.continuation.get(span_end).copied().unwrap_or(false)
                {
                    span_end = span_end.saturating_add(1);
                }
                let mut span_lines: Vec<&str> =
                    Vec::with_capacity(span_end.saturating_sub(line_idx));
                if let Some(slice) = self.lines.get(line_idx..span_end) {
                    for s in slice {
                        span_lines.push(s.as_str());
                    }
                }
                budget.charge(span_lines.len())?;
                let syms = collect_symbol_set(&span_lines, &mut self.unresolved);
                module_symbols.extend(syms);
                line_idx = span_end;
            }

            return Ok(module_symbols);
        }

        let candidate_idx = if let Some(&idx) = self.definition_by_pos.get(&hint_pos) {
            if self.definitions.get(idx).map(|d| d.name.as_str()) == Some(function_name) {
                budget.charge(1)?;
                Some(idx)
            } else {
                None
            }
        } else {
            None
        };

        let candidate_idx = match candidate_idx {
            Some(idx) => Some(idx),
            None => {
                if let Some(indices) = self.definitions_by_name.get(function_name) {
                    budget.charge(indices.len())?;
                    indices.iter().copied().min_by_key(|&idx| {
                        self.definitions
                            .get(idx)
                            .map(|d| d.pos.abs_diff(hint_pos))
                            .unwrap_or(usize::MAX)
                    })
                } else {
                    None
                }
            }
        };

        let Some(def_idx) = candidate_idx else {
            return Ok(HashSet::new());
        };
        let Some(def) = self.definitions.get(def_idx) else {
            return Ok(HashSet::new());
        };
        let def_line = def.pos;
        let base_indent = def.base_indent;
        let end_line = def.end_line;

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

        let mut line_idx = header_end.saturating_add(1);
        if let Some(body_text) = inline_body {
            let mut span_end = line_idx;
            while span_end < end_line && self.continuation.get(span_end).copied().unwrap_or(false) {
                span_end = span_end.saturating_add(1);
            }
            let cont_count = span_end.saturating_sub(line_idx);
            let mut span_lines = Vec::with_capacity(cont_count.saturating_add(1));
            span_lines.push(body_text.as_str());
            if let Some(cont_slice) = self.lines.get(line_idx..span_end) {
                for line in cont_slice {
                    span_lines.push(line.as_str());
                }
            }
            budget.charge(span_lines.len())?;
            let syms = collect_symbol_set(&span_lines, &mut self.unresolved);
            symbols.extend(syms);
            line_idx = span_end;
        }

        let mut skip_until_indent: Option<usize> = None;
        while line_idx < end_line {
            budget.charge(1)?;
            let Some(line) = self.lines.get(line_idx) else {
                break;
            };

            if let Some(skip_indent) = skip_until_indent {
                if self.continuation.get(line_idx).copied().unwrap_or(false) {
                    line_idx = line_idx.saturating_add(1);
                    continue;
                }
                if let Some(indent) = get_line_indent(line) {
                    if indent > skip_indent {
                        line_idx = line_idx.saturating_add(1);
                        continue;
                    } else {
                        skip_until_indent = None;
                    }
                } else {
                    line_idx = line_idx.saturating_add(1);
                    continue;
                }
            }

            if !self.continuation.get(line_idx).copied().unwrap_or(false)
                && parse_def_or_class(line).is_some()
            {
                let nested_indent = get_line_indent(line).unwrap_or(base_indent.saturating_add(1));
                if let Some(parsed) = self.get_or_parse_header(line_idx, budget)? {
                    let header_end = parsed.header_end;
                    let enclosing_syms = parsed.enclosing_symbols.clone();
                    symbols.extend(enclosing_syms);
                    skip_until_indent = Some(nested_indent);
                    line_idx = header_end.saturating_add(1);
                    continue;
                }
            }

            let mut span_end = line_idx.saturating_add(1);
            while span_end < end_line && self.continuation.get(span_end).copied().unwrap_or(false) {
                span_end = span_end.saturating_add(1);
            }
            let mut span_lines: Vec<&str> = Vec::with_capacity(span_end.saturating_sub(line_idx));
            if let Some(slice) = self.lines.get(line_idx..span_end) {
                for s in slice {
                    span_lines.push(s.as_str());
                }
            }
            budget.charge(span_lines.len())?;
            let syms = collect_symbol_set(&span_lines, &mut self.unresolved);
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
    let mut seen_fixed_targets = HashSet::new();
    let mut seen_base_targets = HashSet::new();

    let fixed_mapper = HunkPositionMapper::new(hunk, true);
    let base_mapper = HunkPositionMapper::new(hunk, false);

    for (name, pos) in fixed_defs {
        let base_pos = if let Some(ref mut base_ana) = base_analysis {
            corresponding_pyc_definition(
                &name,
                pos,
                fixed_mapper.map(pos),
                fixed_analysis,
                base_ana,
                &used_base,
                budget,
            )?
        } else {
            None
        };
        if name != "<module>" {
            if let Some(base_pos) = base_pos {
                used_base.insert(base_pos);
            }
            used_fixed.insert(pos);
        }
        seen_fixed_targets.insert((name.clone(), pos));
        if let Some(bp) = base_pos {
            seen_base_targets.insert((name.clone(), bp));
        }
        targets.push((name, Some(pos), base_pos));
    }

    for (name, pos) in base_defs {
        if seen_base_targets.contains(&(name.clone(), pos)) {
            continue;
        }
        let fixed_pos = if let Some(ref mut base_ana) = base_analysis {
            corresponding_pyc_definition(
                &name,
                pos,
                base_mapper.map(pos),
                base_ana,
                fixed_analysis,
                &used_fixed,
                budget,
            )?
        } else {
            None
        };
        if name != "<module>" {
            if let Some(fixed_pos) = fixed_pos {
                used_fixed.insert(fixed_pos);
            }
        }
        if let Some(fp) = fixed_pos {
            if seen_fixed_targets.contains(&(name.clone(), fp)) {
                continue;
            }
            seen_fixed_targets.insert((name.clone(), fp));
        }
        seen_base_targets.insert((name.clone(), pos));
        targets.push((name, fixed_pos, Some(pos)));
    }

    if targets.is_empty() {
        targets.push(("<module>".to_string(), Some(0), Some(0)));
    }

    let mut result = Vec::new();

    for (function_name, f_hint, b_hint) in targets {
        budget.charge(1)?;
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
    /// Info findings for fingerprint coverage gaps found while fingerprinting. Today: a
    /// string literal in an analysed scope uses a `\N{...}` name missing from the Unicode
    /// name table (newer than Unicode 16.0), so its compiled constant cannot be reproduced
    /// and the `.pyc` function check cannot match that literal. `path` names the task.
    pub fn coverage_gap_findings(&self, path: &str) -> Vec<crate::scan::Finding> {
        if self.unresolved_unicode_names.is_empty() {
            return Vec::new();
        }
        let total = self
            .unresolved_unicode_names
            .len()
            .saturating_add(self.unresolved_unicode_names_omitted);
        let bound = if self.unresolved_unicode_names_saturated {
            "at least "
        } else {
            ""
        };
        let mut evidence = vec![format!(
            "{bound}{total} distinct \\N{{...}} name(s) unknown to the Unicode 16.0.0 name table; .pyc constants with them are not matched"
        )];
        evidence.extend(self.unresolved_unicode_names.iter().take(5).cloned());
        vec![crate::scan::Finding {
            detector: "D3b".into(),
            channel: "pyc_unknown_unicode_name".into(),
            path: path.to_string(),
            visibility: crate::scan::Visibility::AgentVisible,
            severity: crate::scan::Severity::Info,
            confidence: 0.0,
            hunk: None,
            evidence,
        }]
    }

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
        Self::from_task_with_fixes_caps_and_budget(
            gold_patch_str,
            test_patch_str,
            &[],
            base_tree_root,
            tier2_max_files,
            tier2_max_bytes,
            work_budget,
        )
    }

    /// Like `from_task`, but also fingerprints known passing fixes (TR-SC-1): up to
    /// `MAX_PASSING_FIXES` deduplicated patches, each treated like the gold patch. A fix
    /// identical to the gold patch or to an earlier fix is skipped; base-commit
    /// fingerprints are subtracted as for the gold patch.
    pub fn from_task_with_fixes(
        gold_patch_str: &str,
        test_patch_str: &str,
        passing_fixes: &[String],
        base_tree_root: &Path,
    ) -> Result<Self, FingerprintError> {
        Self::from_task_with_fixes_caps_and_budget(
            gold_patch_str,
            test_patch_str,
            passing_fixes,
            base_tree_root,
            Self::DEFAULT_TIER2_MAX_FILES,
            Self::DEFAULT_TIER2_MAX_BYTES,
            None,
        )
    }

    pub fn from_task_with_fixes_caps_and_budget(
        gold_patch_str: &str,
        test_patch_str: &str,
        passing_fixes: &[String],
        base_tree_root: &Path,
        tier2_max_files: usize,
        tier2_max_bytes: u64,
        work_budget: Option<usize>,
    ) -> Result<Self, FingerprintError> {
        let budget_limit = work_budget.unwrap_or(DEFAULT_MAX_FINGERPRINT_WORK);
        let mut budget = WorkBudget::new(budget_limit);
        let mut fix_patches = vec![parse_patch(gold_patch_str)?];
        for fix in select_passing_fixes(gold_patch_str, passing_fixes) {
            fix_patches.push(parse_patch(fix)?);
        }
        let test_patch = parse_patch(test_patch_str)?;
        let mut unresolved = UnresolvedNames::default();

        let mut candidate_hunks: Vec<CandidateHunk> = Vec::new();
        let mut global_hunk_counter = 0;

        // 1. Process the gold patch and the selected passing fixes
        for file in fix_patches.iter().flat_map(|p| p.files.iter()) {
            let file_path = file
                .new_path
                .as_deref()
                .or(file.old_path.as_deref())
                .unwrap_or("")
                .to_string();

            let (post_fix_lines, hunk_changed_positions, base_lines) =
                apply_patch_to_base(file, base_tree_root);

            let mut fixed_analysis = if file_path.ends_with(".py") {
                Some(PycFileAnalysis::new(&post_fix_lines, &mut budget)?)
            } else {
                None
            };
            let mut base_analysis = if file_path.ends_with(".py") {
                base_lines
                    .as_ref()
                    .map(|b| PycFileAnalysis::new(b, &mut budget))
                    .transpose()?
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

            // Parse once per file; per-hunk parsing was quadratic in hunk count.
            let tier2_parsed = crate::tier2::Tier2ParsedFile::parse(
                &file_path,
                base_src.as_deref(),
                Some(post_fix_text.as_str()),
            );
            let mut tier2_ctx = tier2_parsed.context();

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
                    tier2_ctx.extract_hunk(&removed_lines, &added_lines);

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
            if let Some(a) = &fixed_analysis {
                unresolved.merge(&a.unresolved);
            }
            if let Some(a) = &base_analysis {
                unresolved.merge(&a.unresolved);
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
        let mut set = finish_fingerprint_set(
            candidate_hunks,
            base_tree_root,
            0,
            baseline_budget,
            tier2_max_files,
            tier2_max_bytes,
        );
        set.unresolved_unicode_names_omitted = unresolved
            .distinct_count()
            .saturating_sub(unresolved.names.len());
        set.unresolved_unicode_names_saturated = unresolved.saturated;
        set.unresolved_unicode_names = unresolved.names.into_iter().collect();
        Ok(set)
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

fn add_text_to_baseline(
    content: &str,
    base_line_counts: &mut HashMap<String, usize>,
    base_line_hashes: &mut HashSet<String>,
    base_window_hashes: &mut HashSet<String>,
    base_binary_tokens: &mut HashSet<String>,
    base_winnow_hashes: &mut HashSet<u64>,
) {
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
    let base_tokens = tokenize(content);
    for tok in &base_tokens {
        base_binary_tokens.insert(tok.text.clone());
        if let Some(literal_content) = crate::binary::extract_string_literal_content(&tok.text) {
            base_binary_tokens.insert(literal_content);
        }
    }
    let base_token_texts: Vec<String> = base_tokens.into_iter().map(|t| t.text).collect();
    for hash in kgram_hashes(&base_token_texts) {
        base_winnow_hashes.insert(hash);
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

                    // Decode binary files the way the scanner does:
                    // 1) control-byte separated lossy UTF-8
                    // 2) both UTF-16 views
                    // so every text unit the scanner can see at the base is also subtracted here.
                    let separated: Vec<u8> = bytes
                        .iter()
                        .map(|&b| {
                            if b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r' {
                                b'\n'
                            } else {
                                b
                            }
                        })
                        .collect();
                    add_text_to_baseline(
                        &String::from_utf8_lossy(&separated),
                        &mut base_line_counts,
                        &mut base_line_hashes,
                        &mut base_window_hashes,
                        &mut base_binary_tokens,
                        &mut base_winnow_hashes,
                    );
                    for view in crate::binary::utf16_text_views(&bytes) {
                        for run in view.split('\n').filter(|run| run.chars().count() >= 6) {
                            base_binary_tokens.insert(run.to_string());
                        }
                        add_text_to_baseline(
                            &view,
                            &mut base_line_counts,
                            &mut base_line_hashes,
                            &mut base_window_hashes,
                            &mut base_binary_tokens,
                            &mut base_winnow_hashes,
                        );
                    }
                } else {
                    add_text_to_baseline(
                        &String::from_utf8_lossy(&bytes),
                        &mut base_line_counts,
                        &mut base_line_hashes,
                        &mut base_window_hashes,
                        &mut base_binary_tokens,
                        &mut base_winnow_hashes,
                    );
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
        unresolved_unicode_names: Vec::new(),
        unresolved_unicode_names_omitted: 0,
        unresolved_unicode_names_saturated: false,
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

#[cfg(test)]
mod t112_final_review_tests {
    use super::*;

    fn run_bounded<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
            Ok(v) => v,
            Err(e) => panic!("work did not finish within {secs}s: {e}"),
        }
    }

    /// Finding 2: with no colon, a `def` header used to be scanned to EOF for every header
    /// while charging one budget unit, so 100k colonless `def` lines took ~5e9 line scans.
    #[test]
    fn t112_final_finding2_colonless_def_headers_are_linear() {
        let n = 100_000usize;
        let mut lines: Vec<String> = (0..n).map(|i| format!("def f{i}()")).collect();
        lines.push("Y = 1".to_string());
        let (symbols, used) = run_bounded(60, move || {
            let mut budget = WorkBudget::new(DEFAULT_MAX_FINGERPRINT_WORK);
            let Ok(mut analysis) = PycFileAnalysis::new(&lines, &mut budget) else {
                return (Err(FingerprintError::WorkBudgetExceeded), budget.used());
            };
            let symbols = analysis.extract_symbols("<module>", 0, &mut budget);
            (symbols, budget.used())
        });
        let symbols = symbols.expect("within the default budget");
        assert!(symbols.contains("Y"));
        assert!(symbols.contains("f99999"));
        // Linear charging: a few units per line, never per header times file length.
        assert!(used <= 5 * (n + 1), "charged {used} units");
    }

    /// Finding 2: every scanned header line is charged, so a header spanning many lines
    /// costs its length.
    #[test]
    fn t112_final_finding2_header_scan_charges_per_line() {
        let mut lines = vec!["def f(".to_string()];
        lines.extend((0..1000).map(|i| format!("    a{i},")));
        lines.push("):".to_string());
        lines.push("    return 1".to_string());
        let cont = compute_line_continuation(&lines);
        let mut budget = WorkBudget::new(DEFAULT_MAX_FINGERPRINT_WORK);
        let parsed = parse_def_or_class_header(
            &lines,
            0,
            &cont,
            &mut budget,
            &mut UnresolvedNames::default(),
        )
        .expect("within budget")
        .expect("header");
        assert_eq!(parsed.header_end, 1001);
        assert!(budget.used() >= 1002, "charged {}", budget.used());
        let mut tiny = WorkBudget::new(10);
        assert!(matches!(
            parse_def_or_class_header(&lines, 0, &cont, &mut tiny, &mut UnresolvedNames::default()),
            Err(FingerprintError::WorkBudgetExceeded)
        ));
    }

    /// Finding 3: soft-keyword detection must be linear in a long bracketed span.
    #[test]
    fn t112_final_finding3_statement_starts_linear() {
        let mut lines = vec!["X = (".to_string()];
        lines.extend((0..200_000).map(|_| "    match,".to_string()));
        lines.push(")".to_string());
        let symbols = run_bounded(60, move || {
            let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
            collect_symbol_set(&refs, &mut UnresolvedNames::default())
        });
        assert!(symbols.contains("X"));
        assert!(symbols.contains("match"));
    }
}

#[cfg(test)]
mod unresolved_names_tests {
    use super::*;

    fn name(i: usize) -> String {
        format!("NAME {i:05}")
    }

    fn collect(names: impl IntoIterator<Item = String>) -> UnresolvedNames {
        let mut u = UnresolvedNames::default();
        for n in names {
            u.record(&n);
        }
        u
    }

    fn snapshot(u: &UnresolvedNames) -> (Vec<String>, usize, bool, Vec<NameDigest>) {
        (
            u.names.iter().cloned().collect(),
            u.distinct_count(),
            u.saturated,
            u.omitted.iter().copied().collect(),
        )
    }

    #[test]
    fn retained_names_sorted_deduplicated_and_bounded() {
        let u = collect(["B", "A", "B", "C", "A"].map(String::from));
        assert_eq!(
            u.names.iter().cloned().collect::<Vec<_>>(),
            vec!["A", "B", "C"]
        );
        assert_eq!(u.distinct_count(), 3);
        let u = collect((0..100).rev().map(name));
        assert_eq!(u.names.len(), MAX_UNRESOLVED_UNICODE_NAMES);
        // The retained names are the smallest, whatever the record order.
        assert_eq!(u.names.first(), Some(&name(0)));
        assert_eq!(u.names.last(), Some(&name(63)));
        assert_eq!(u.distinct_count(), 100);
        assert!(!u.saturated);
    }

    #[test]
    fn repeated_overflow_name_counted_once() {
        let mut u = collect((0..64).map(name));
        u.record(&name(64));
        u.record(&name(64));
        u.record(&name(3));
        assert_eq!(u.distinct_count(), 65);
    }

    #[test]
    fn overlapping_merges_count_each_name_once() {
        // The same omitted name on both sides.
        let a = collect((0..70).map(name));
        let b = collect((0..64).map(name).chain([name(65), name(99)]));
        let mut m = a.clone();
        m.merge(&b);
        assert_eq!(m.distinct_count(), 71); // 0..70 plus 99
                                            // A name retained on one side and omitted on the other.
        let small = collect([name(64)]); // retained here
        let full = collect((0..65).map(name)); // NAME 00064 omitted here
        for (x, y) in [(&small, &full), (&full, &small)] {
            let mut m = x.clone();
            m.merge(y);
            assert_eq!(m.distinct_count(), 65);
            assert_eq!(m.names.len(), 64);
        }
    }

    #[test]
    fn record_and_merge_order_independent() {
        let all: Vec<String> = (0..300).map(name).collect();
        let forward = collect(all.iter().cloned());
        let backward = collect(all.iter().rev().cloned());
        let interleaved = collect(
            all.iter()
                .step_by(2)
                .chain(all.iter().skip(1).step_by(2))
                .cloned(),
        );
        assert_eq!(snapshot(&forward), snapshot(&backward));
        assert_eq!(snapshot(&forward), snapshot(&interleaved));
        let left = collect(all.iter().take(200).cloned());
        let right = collect(all.iter().skip(100).cloned());
        let mut lr = left.clone();
        lr.merge(&right);
        let mut rl = right.clone();
        rl.merge(&left);
        assert_eq!(snapshot(&lr), snapshot(&forward));
        assert_eq!(snapshot(&rl), snapshot(&forward));
    }

    #[test]
    fn saturation_sets_flag_and_stays_bounded() {
        let below = collect((0..64 + MAX_OMITTED_UNICODE_NAME_DIGESTS).map(name));
        assert!(!below.saturated);
        assert_eq!(
            below.distinct_count(),
            64 + MAX_OMITTED_UNICODE_NAME_DIGESTS
        );
        let n = 64 + MAX_OMITTED_UNICODE_NAME_DIGESTS + 500;
        let a = collect((0..n).map(name));
        let b = collect((0..n).rev().map(name));
        assert!(a.saturated);
        assert_eq!(a.omitted.len(), MAX_OMITTED_UNICODE_NAME_DIGESTS);
        assert_eq!(snapshot(&a), snapshot(&b));
        let mut m = UnresolvedNames::default();
        m.merge(&a);
        assert!(m.saturated);

        let mut set = FingerprintSet::from_task("", "", Path::new("/nonexistent")).expect("fp");
        set.unresolved_unicode_names = a.names.iter().cloned().collect();
        set.unresolved_unicode_names_omitted = a.distinct_count() - a.names.len();
        set.unresolved_unicode_names_saturated = true;
        let gaps = set.coverage_gap_findings("task");
        assert!(gaps[0].evidence[0].starts_with("at least "), "{gaps:?}");
    }
}
