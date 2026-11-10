/// Strip a trailing `#` comment if outside single or double string literals.
pub fn strip_trailing_comment(line: &str) -> &str {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;

    for (idx, c) in line.char_indices() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                in_quote = None;
            }
        } else if c == '\'' || c == '"' {
            in_quote = Some(c);
        } else if c == '#' {
            return &line[..idx];
        }
    }
    line
}

/// Clean a line by stripping diff marker (if `diff_mode`), stripping comments,
/// trimming, and collapsing whitespace to single spaces.
pub fn clean_line(line: &str, diff_mode: bool) -> String {
    let without_marker = if diff_mode {
        if let Some(stripped) = line
            .strip_prefix('+')
            .or_else(|| line.strip_prefix('-'))
            .or_else(|| line.strip_prefix(' '))
        {
            stripped
        } else {
            line
        }
    } else {
        line
    };

    let without_comment = strip_trailing_comment(without_marker);
    without_comment
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Return true if the cleaned string is a bare Python keyword or trivial control statement.
pub fn is_bare_keyword(s: &str) -> bool {
    const BARE_KEYWORDS: &[&str] = &[
        "pass",
        "return",
        "return None",
        "return True",
        "return False",
        "break",
        "continue",
        "raise",
        "yield",
        "else:",
        "try:",
        "finally:",
        "except:",
        "do:",
    ];

    BARE_KEYWORDS.contains(&s)
}

/// Return true if the line consists only of brackets and punctuation.
pub fn is_only_brackets_and_punctuation(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_punctuation()
                || c.is_whitespace()
                || "()[]{}<>,.:;+-*/%&|^~!=#`'\"".contains(c)
        })
}

/// Return true if the line is trivial per TR-SC-2:
/// - fewer than 12 characters after normalising
/// - bare Python keywords
/// - lines made only of brackets and punctuation
pub fn is_trivial(s: &str) -> bool {
    s.len() < 12 || is_bare_keyword(s) || is_only_brackets_and_punctuation(s)
}

/// Normalise a line.
///
/// In diff mode, strips a leading diff marker (`+`, `-`, or space).
/// Strips trailing comments, collapses whitespace, and returns `None` for trivial lines.
pub fn normalize_line_mode(line: &str, diff_mode: bool) -> Option<String> {
    let cleaned = clean_line(line, diff_mode);
    if is_trivial(&cleaned) {
        None
    } else {
        Some(cleaned)
    }
}

/// Normalise an ordinary source line.
pub fn normalize_line(line: &str) -> Option<String> {
    normalize_line_mode(line, false)
}

/// Normalise a line from a unified diff (strips leading `+`, `-`, or space).
pub fn normalize_diff_line(line: &str) -> Option<String> {
    normalize_line_mode(line, true)
}
