use std::collections::HashSet;
use std::path::Path;

use crate::binary::extract_string_literal_content;
use crate::fingerprint::HunkFingerprints;
use crate::scan::{Finding, ScanOptions, Severity};

/// Supported language for AST parsing in Tier 2.
/// Structured to allow additional language grammars to be added in the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedLanguage {
    Python,
}

impl SupportedLanguage {
    pub fn for_path(path: &str) -> Option<Self> {
        if path.ends_with(".py") {
            Some(Self::Python)
        } else {
            None
        }
    }

    pub fn make_parser(&self) -> Option<tree_sitter::Parser> {
        let mut parser = tree_sitter::Parser::new();
        match self {
            Self::Python => {
                if parser
                    .set_language(&tree_sitter_python::LANGUAGE.into())
                    .is_err()
                {
                    return None;
                }
            }
        }
        Some(parser)
    }
}

pub const PYTHON_KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "case", "class",
    "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if",
    "import", "in", "is", "lambda", "match", "nonlocal", "not", "or", "pass", "raise", "return",
    "try", "type", "while", "with", "yield",
];

pub const STOP_LIST: &[&str] = &["self", "cls", "None", "True", "False", "args", "kwargs"];

pub fn is_excluded(s: &str) -> bool {
    PYTHON_KEYWORDS.contains(&s) || STOP_LIST.contains(&s)
}

pub fn is_simple_statement(kind: &str) -> bool {
    matches!(
        kind,
        "expression_statement"
            | "assert_statement"
            | "return_statement"
            | "delete_statement"
            | "raise_statement"
            | "pass_statement"
            | "break_statement"
            | "continue_statement"
            | "import_statement"
            | "import_from_statement"
            | "future_import_statement"
            | "global_statement"
            | "nonlocal_statement"
            | "exec_statement"
            | "print_statement"
            | "type_alias_statement"
    )
}

pub fn is_compound_statement(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "class_definition"
            | "if_statement"
            | "for_statement"
            | "while_statement"
            | "try_statement"
            | "with_statement"
            | "match_statement"
            | "decorated_definition"
    )
}

pub fn is_clause(kind: &str) -> bool {
    matches!(
        kind,
        "elif_clause"
            | "else_clause"
            | "except_clause"
            | "except_group_clause"
            | "finally_clause"
            | "case_clause"
    )
}

fn find_block_child<'tree>(node: tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>> {
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            if child.kind() == "block" {
                return Some(child);
            }
        }
    }
    None
}

pub struct StatementTarget<'tree> {
    pub node: tree_sitter::Node<'tree>,
    pub is_header: bool,
    pub block_start_byte: Option<usize>,
}

fn find_statement_for_row<'tree>(
    node: tree_sitter::Node<'tree>,
    row: usize,
) -> Option<StatementTarget<'tree>> {
    if node.start_position().row > row || node.end_position().row < row {
        return None;
    }

    if is_simple_statement(node.kind()) {
        return Some(StatementTarget {
            node,
            is_header: false,
            block_start_byte: None,
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.start_position().row <= row && row <= child.end_position().row {
            if let Some(target) = find_statement_for_row(child, row) {
                return Some(target);
            }
        }
    }

    if is_compound_statement(node.kind()) || is_clause(node.kind()) {
        let block = find_block_child(node);
        let in_header = match block {
            Some(b) => {
                row < b.start_position().row
                    || (row == b.start_position().row && b.start_position().column > 0)
            }
            None => true,
        };
        if in_header {
            return Some(StatementTarget {
                node,
                is_header: true,
                block_start_byte: block.map(|b| b.start_byte()),
            });
        }
    }

    if node.kind() == "ERROR" {
        return Some(StatementTarget {
            node,
            is_header: false,
            block_start_byte: None,
        });
    }

    None
}

pub fn extract_symbols_from_statement(
    target: &StatementTarget,
    source: &[u8],
    symbols: &mut HashSet<String>,
) {
    let mut stack = vec![target.node];
    while let Some(curr) = stack.pop() {
        if target.is_header {
            if let Some(block_start) = target.block_start_byte {
                if curr.start_byte() >= block_start {
                    continue;
                }
            }
        }

        match curr.kind() {
            "identifier" => {
                if let Ok(text) = curr.utf8_text(source) {
                    if !is_excluded(text) && !text.is_empty() {
                        symbols.insert(text.to_string());
                    }
                }
            }
            "attribute" => {
                if curr.parent().is_none_or(|p| p.kind() != "attribute") {
                    if let Ok(full_text) = curr.utf8_text(source) {
                        let norm = full_text
                            .split('.')
                            .map(|s| s.trim())
                            .collect::<Vec<_>>()
                            .join(".");
                        if !is_excluded(&norm) && !norm.is_empty() {
                            symbols.insert(norm);
                        }
                    }
                }
            }
            "dotted_name" => {
                if let Ok(full_text) = curr.utf8_text(source) {
                    let norm = full_text
                        .split('.')
                        .map(|s| s.trim())
                        .collect::<Vec<_>>()
                        .join(".");
                    if !is_excluded(&norm) && !norm.is_empty() {
                        symbols.insert(norm);
                    }
                }
            }
            "keyword_argument" => {
                if let Some(name_node) = curr.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        if !is_excluded(name) && !name.is_empty() {
                            symbols.insert(name.to_string());
                        }
                    }
                }
            }
            "string" => {
                if let Ok(raw) = curr.utf8_text(source) {
                    if let Some(content) = extract_string_literal_content(raw) {
                        if content.chars().count() >= 3 && !is_excluded(&content) {
                            symbols.insert(content);
                        }
                    }
                }
            }
            "integer" | "float" => {
                if let Ok(text) = curr.utf8_text(source) {
                    if text != "0"
                        && text != "1"
                        && text != "0.0"
                        && text != "1.0"
                        && !is_excluded(text)
                    {
                        symbols.insert(text.to_string());
                    }
                }
            }
            _ => {}
        }

        let mut cursor = curr.walk();
        for child in curr.children(&mut cursor) {
            stack.push(child);
        }
    }
}

pub fn extract_enclosing_anchors(
    node: tree_sitter::Node,
    source: &[u8],
    anchors: &mut Vec<String>,
) {
    if node.kind() == "function_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                if !name.is_empty() && !anchors.contains(&name.to_string()) {
                    anchors.push(name.to_string());
                }
            }
        }
    }
    if node.kind() == "class_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                if !name.is_empty() && !anchors.contains(&name.to_string()) {
                    anchors.push(name.to_string());
                }
            }
        }
    }

    let mut curr = node.parent();
    while let Some(p) = curr {
        if p.kind() == "function_definition" {
            if let Some(name_node) = p.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source) {
                    if !name.is_empty() && !anchors.contains(&name.to_string()) {
                        anchors.push(name.to_string());
                    }
                }
            }
        }
        if p.kind() == "class_definition" {
            if let Some(name_node) = p.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source) {
                    if !name.is_empty() && !anchors.contains(&name.to_string()) {
                        anchors.push(name.to_string());
                    }
                }
            }
        }
        curr = p.parent();
    }
}

pub fn extract_file_anchors(file_path: &str) -> Vec<String> {
    let mut anchors = Vec::new();
    let p = Path::new(file_path);
    if let Some(file_name) = p.file_name().and_then(|s| s.to_str()) {
        if !file_name.is_empty() {
            anchors.push(file_name.to_string());
            if let Some(without_py) = file_name.strip_suffix(".py") {
                if !without_py.is_empty() && without_py != file_name {
                    anchors.push(without_py.to_string());
                }
            }
        }
    }

    let clean = file_path
        .strip_prefix("./")
        .unwrap_or(file_path)
        .strip_prefix('/')
        .unwrap_or(file_path);
    let mod_base = if let Some(stripped) = clean.strip_suffix(".py") {
        stripped
    } else {
        clean
    };
    let mod_base = if let Some(stripped) = mod_base.strip_suffix("/__init__") {
        stripped
    } else {
        mod_base
    };
    let mod_path = mod_base.replace('/', ".");
    if !mod_path.is_empty() && !anchors.contains(&mod_path) {
        anchors.push(mod_path.clone());
    }
    if let Some(stripped) = mod_path.strip_prefix("src.") {
        if !stripped.is_empty() && !anchors.contains(&stripped.to_string()) {
            anchors.push(stripped.to_string());
        }
    }
    if let Some(stripped) = mod_path.strip_prefix("lib.") {
        if !stripped.is_empty() && !anchors.contains(&stripped.to_string()) {
            anchors.push(stripped.to_string());
        }
    }
    anchors
}

pub fn extract_hunk_symbols_and_anchors(
    file_path: &str,
    base_src: Option<&str>,
    removed_lines: &[usize],
    fixed_src: &str,
    added_lines: &[usize],
) -> (HashSet<String>, Vec<String>) {
    let Some(lang) = SupportedLanguage::for_path(file_path) else {
        return (HashSet::new(), Vec::new());
    };

    let Some(mut parser) = lang.make_parser() else {
        return (HashSet::new(), Vec::new());
    };

    let mut anchors = extract_file_anchors(file_path);
    let mut symbols = HashSet::new();

    // 1. Base parse for removed lines
    if let Some(base) = base_src {
        if !removed_lines.is_empty() {
            if let Some(tree) = parser.parse(base.as_bytes(), None) {
                let root = tree.root_node();
                let mut seen_ranges = HashSet::new();
                for &row in removed_lines {
                    if let Some(target) = find_statement_for_row(root, row) {
                        let range = (
                            target.node.start_byte(),
                            target.node.end_byte(),
                            target.is_header,
                        );
                        if seen_ranges.insert(range) {
                            extract_symbols_from_statement(&target, base.as_bytes(), &mut symbols);
                            extract_enclosing_anchors(target.node, base.as_bytes(), &mut anchors);
                        }
                    }
                }
            }
        }
    }

    // 2. Fixed parse for added lines
    if !added_lines.is_empty() {
        if let Some(tree) = parser.parse(fixed_src.as_bytes(), None) {
            let root = tree.root_node();
            let mut seen_ranges = HashSet::new();
            for &row in added_lines {
                if let Some(target) = find_statement_for_row(root, row) {
                    let range = (
                        target.node.start_byte(),
                        target.node.end_byte(),
                        target.is_header,
                    );
                    if seen_ranges.insert(range) {
                        extract_symbols_from_statement(&target, fixed_src.as_bytes(), &mut symbols);
                        extract_enclosing_anchors(target.node, fixed_src.as_bytes(), &mut anchors);
                    }
                }
            }
        }
    }

    (symbols, anchors)
}

pub fn find_first_anchor<'a>(text: &str, anchors: &'a [String]) -> Option<&'a str> {
    for anchor in anchors {
        if anchor.is_empty() {
            continue;
        }
        let a_len = anchor.len();
        if a_len > text.len() {
            continue;
        }

        let mut start_idx = 0;
        while let Some(found_idx) = text[start_idx..].find(anchor.as_str()) {
            let idx = start_idx + found_idx;
            let end_idx = idx + a_len;

            let start_ok = match text[..idx].chars().next_back() {
                None => true,
                Some(c) => !c.is_alphanumeric() && c != '_',
            };

            let end_ok = match text[end_idx..].chars().next() {
                None => true,
                Some(c) => !c.is_alphanumeric() && c != '_',
            };

            if start_ok && end_ok {
                return Some(anchor.as_str());
            }

            let step = text[idx..].chars().next().map_or(1, |c| c.len_utf8());
            start_idx = idx + step;
        }
    }
    None
}

fn process_prose_token(
    raw_tok: &str,
    symbols: &mut HashSet<String>,
    anchor_tokens: &mut HashSet<String>,
) {
    let trimmed = raw_tok.trim_matches('.');
    if trimmed.is_empty() {
        return;
    }

    symbols.insert(trimmed.to_string());
    anchor_tokens.insert(trimmed.to_string());

    let parts: Vec<&str> = trimmed.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() > 1 {
        for part in &parts {
            symbols.insert((*part).to_string());
            anchor_tokens.insert((*part).to_string());
        }
        for (i, part) in parts.iter().enumerate() {
            let mut chain = (*part).to_string();
            for next_part in parts.iter().skip(i + 1) {
                chain.push('.');
                chain.push_str(next_part);
                symbols.insert(chain.clone());
                anchor_tokens.insert(chain.clone());
            }
        }
    }
}

fn extract_prose_tokens_into(
    text: &str,
    symbols: &mut HashSet<String>,
    anchor_tokens: &mut HashSet<String>,
) {
    let mut start_opt = None;
    for (idx, ch) in text.char_indices() {
        if ch.is_alphanumeric() || ch == '_' || ch == '.' {
            if start_opt.is_none() {
                start_opt = Some(idx);
            }
        } else if let Some(start) = start_opt.take() {
            process_prose_token(&text[start..idx], symbols, anchor_tokens);
        }
    }
    if let Some(start) = start_opt {
        process_prose_token(&text[start..], symbols, anchor_tokens);
    }
}

pub fn extract_unit_symbols_and_anchors(text: &str) -> (HashSet<String>, HashSet<String>) {
    let mut symbols = HashSet::new();
    let mut anchor_tokens = HashSet::new();

    extract_prose_tokens_into(text, &mut symbols, &mut anchor_tokens);

    extract_delimited_spans_into(text, '`', '`', &mut symbols, &mut anchor_tokens);
    extract_delimited_spans_into(text, '\'', '\'', &mut symbols, &mut anchor_tokens);
    extract_delimited_spans_into(text, '"', '"', &mut symbols, &mut anchor_tokens);

    (symbols, anchor_tokens)
}

pub fn extract_unit_candidate_symbols(text: &str) -> HashSet<String> {
    extract_unit_symbols_and_anchors(text).0
}

fn extract_delimited_spans_into(
    text: &str,
    open: char,
    close: char,
    symbols: &mut HashSet<String>,
    anchor_tokens: &mut HashSet<String>,
) {
    let mut start_idx = 0;
    while let Some(o_idx) = text[start_idx..].find(open) {
        let abs_open = start_idx + o_idx;
        let rest = &text[abs_open + open.len_utf8()..];
        if let Some(c_idx) = rest.find(close) {
            let span = rest[..c_idx].trim();
            if !span.is_empty() && span.len() <= 500 && !span.contains('\n') {
                symbols.insert(span.to_string());
                anchor_tokens.insert(span.to_string());
                extract_prose_tokens_into(span, symbols, anchor_tokens);
            }
            start_idx = abs_open + open.len_utf8() + c_idx + close.len_utf8();
        } else {
            break;
        }
    }
}

pub fn find_first_anchor_in_tokens<'a>(
    anchors: &'a [String],
    unit_anchor_tokens: &HashSet<String>,
) -> Option<&'a str> {
    for anchor in anchors {
        if unit_anchor_tokens.contains(anchor) {
            return Some(anchor.as_str());
        }
    }
    None
}

pub fn match_tier2_for_unit(
    unit_text: &str,
    hunk: &HunkFingerprints,
    opts: &ScanOptions,
    detector: &str,
    path: &str,
) -> Option<Finding> {
    if hunk.tier2_total_weight <= 0.0
        || hunk.tier2_symbols.len() < 2
        || hunk.tier2_anchors.is_empty()
    {
        return None;
    }

    let (unit_symbols, unit_anchor_tokens) = extract_unit_symbols_and_anchors(unit_text);
    match_tier2_with_context(
        &unit_symbols,
        &unit_anchor_tokens,
        hunk,
        opts,
        detector,
        path,
    )
}

pub fn match_tier2_with_context(
    unit_symbols: &HashSet<String>,
    unit_anchor_tokens: &HashSet<String>,
    hunk: &HunkFingerprints,
    opts: &ScanOptions,
    detector: &str,
    path: &str,
) -> Option<Finding> {
    match_tier2_by_membership(
        |symbol| unit_symbols.contains(symbol),
        |anchor| unit_anchor_tokens.contains(anchor),
        hunk,
        opts,
        detector,
        path,
    )
}

pub(crate) fn match_tier2_by_membership(
    contains_symbol: impl Fn(&str) -> bool,
    contains_anchor: impl Fn(&str) -> bool,
    hunk: &HunkFingerprints,
    opts: &ScanOptions,
    detector: &str,
    path: &str,
) -> Option<Finding> {
    if hunk.tier2_total_weight <= 0.0
        || hunk.tier2_symbols.len() < 2
        || hunk.tier2_anchors.is_empty()
    {
        return None;
    }

    let matched_anchor = hunk
        .tier2_anchors
        .iter()
        .find(|anchor| contains_anchor(anchor))?;

    let mut matched_symbols = Vec::new();
    let mut matched_weight = 0.0;

    for (sym, weight) in &hunk.tier2_symbols {
        if contains_symbol(sym) {
            matched_symbols.push((sym.clone(), *weight));
            matched_weight += weight;
        }
    }

    if matched_symbols.len() < 2 {
        return None;
    }

    let required_weight = opts.tier2_threshold * hunk.tier2_total_weight;
    if matched_weight < required_weight {
        return None;
    }

    let frac = (matched_weight / hunk.tier2_total_weight).min(1.0);
    let confidence = (frac * 100.0).round() / 100.0;

    matched_symbols.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    let mut evidence = vec![matched_anchor.to_string()];
    for (sym, _) in matched_symbols.iter().take(5) {
        evidence.push(sym.clone());
    }

    Some(Finding {
        detector: detector.to_string(),
        channel: "tier2".to_string(),
        path: path.to_string(),
        visibility: opts.visibility,
        severity: Severity::Review,
        confidence,
        hunk: Some(hunk.hunk_index),
        evidence,
    })
}
