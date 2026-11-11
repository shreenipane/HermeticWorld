use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const K_GRAM_SIZE: usize = 8;
pub const WINNOW_WINDOW_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub line: usize,
}

/// Tokenise code into identifiers, numbers, string literals (quote-aware, kept as one token)
/// and single punctuation characters. Drops whitespace and `#` comments.
pub fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut line = 0;

    while i < len {
        let b = bytes[i];
        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'#' {
            // Drop comment to end of line
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // String literals: '...' or "..." or '''...''' or """..."""
        if b == b'\'' || b == b'"' {
            let quote = b;
            let start = i;
            let token_line = line;
            let is_triple = i + 2 < len && bytes[i + 1] == quote && bytes[i + 2] == quote;

            if is_triple {
                i += 3;
                let mut closed = false;
                while i + 2 < len {
                    if bytes[i] == b'\n' {
                        line += 1;
                    }
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote {
                        i += 3;
                        closed = true;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    // Unterminated triple quote, consume rest of string
                    while i < len {
                        if bytes[i] == b'\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            } else {
                i += 1;
                let mut escaped = false;
                while i < len {
                    let c = bytes[i];
                    if c == b'\n' {
                        // Unterminated single-line string literal at newline
                        break;
                    }
                    if escaped {
                        escaped = false;
                        i += 1;
                        continue;
                    }
                    if c == b'\\' {
                        escaped = true;
                        i += 1;
                        continue;
                    }
                    if c == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }

            tokens.push(Token {
                text: text[start..i.min(len)].to_string(),
                line: token_line,
            });
            continue;
        }

        // Numbers: starts with a digit
        if b.is_ascii_digit() {
            let start = i;
            let token_line = line;

            // Hex, binary, or octal prefix
            if b == b'0'
                && i + 1 < len
                && matches!(bytes[i + 1], b'x' | b'X' | b'o' | b'O' | b'b' | b'B')
            {
                i += 2;
                while i < len && (bytes[i].is_ascii_hexdigit() || bytes[i] == b'_') {
                    i += 1;
                }
            } else {
                while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
                    i += 1;
                }
                // Optional decimal fraction (only if followed by digit, not e.g. 1.foo())
                if i + 1 < len && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
                    i += 2;
                    while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
                        i += 1;
                    }
                }
                // Optional exponent
                if i < len && (bytes[i] == b'e' || bytes[i] == b'E') {
                    let mut exp_i = i + 1;
                    if exp_i < len && (bytes[exp_i] == b'+' || bytes[exp_i] == b'-') {
                        exp_i += 1;
                    }
                    if exp_i < len && bytes[exp_i].is_ascii_digit() {
                        i = exp_i + 1;
                        while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
                            i += 1;
                        }
                    }
                }
            }

            tokens.push(Token {
                text: text[start..i].to_string(),
                line: token_line,
            });
            continue;
        }

        // Identifiers: [a-zA-Z_][a-zA-Z0-9_]* or unicode alphabetic
        let is_ident_start = b.is_ascii_alphabetic()
            || b == b'_'
            || (!b.is_ascii()
                && text[i..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_'));

        if is_ident_start {
            let start = i;
            let token_line = line;
            while i < len {
                let cb = bytes[i];
                if cb.is_ascii_alphanumeric() || cb == b'_' {
                    i += 1;
                } else if !cb.is_ascii() {
                    if let Some(c) = text[i..].chars().next() {
                        if c.is_alphanumeric() || c == '_' {
                            i += c.len_utf8();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            tokens.push(Token {
                text: text[start..i].to_string(),
                line: token_line,
            });
            continue;
        }

        // Single punctuation character (any other character)
        let start = i;
        let token_line = line;
        if b.is_ascii() {
            i += 1;
        } else if let Some(c) = text[i..].chars().next() {
            i += c.len_utf8();
        } else {
            i += 1;
        }

        tokens.push(Token {
            text: text[start..i].to_string(),
            line: token_line,
        });
    }

    tokens
}

/// Hash a k-gram of tokens using the first 8 bytes of sha256.
pub fn hash_kgram(tokens: &[String]) -> u64 {
    let mut hasher = Sha256::new();
    for (idx, tok) in tokens.iter().enumerate() {
        if idx > 0 {
            hasher.update(b"\0");
        }
        hasher.update(tok.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WinnowFingerprint {
    pub hash: u64,
    pub token_pos: usize,
}

/// Compute winnow fingerprints for a token sequence.
pub fn winnow_tokens(tokens: &[String]) -> Vec<WinnowFingerprint> {
    if tokens.len() < K_GRAM_SIZE {
        return Vec::new();
    }
    let num_kgrams = tokens.len() - K_GRAM_SIZE + 1;
    let mut kgram_hashes = Vec::with_capacity(num_kgrams);
    for i in 0..num_kgrams {
        kgram_hashes.push(hash_kgram(&tokens[i..i + K_GRAM_SIZE]));
    }
    winnow_hashes(&kgram_hashes)
}

/// Winnow a sequence of k-gram hashes with window w = 8, robust winnowing
/// (minimum of each window, rightmost on ties, recording each selected hash once per position).
pub fn winnow_hashes(hashes: &[u64]) -> Vec<WinnowFingerprint> {
    if hashes.len() < WINNOW_WINDOW_SIZE {
        return Vec::new();
    }
    let mut selected = Vec::new();
    let mut last_min_pos: Option<usize> = None;

    let num_windows = hashes.len() - WINNOW_WINDOW_SIZE + 1;
    for i in 0..num_windows {
        let window = &hashes[i..i + WINNOW_WINDOW_SIZE];
        let mut min_val = u64::MAX;
        let mut min_idx = 0;
        // Rightmost on ties: <=
        for (offset, &h) in window.iter().enumerate() {
            if h <= min_val {
                min_val = h;
                min_idx = i + offset;
            }
        }
        if last_min_pos != Some(min_idx) {
            selected.push(WinnowFingerprint {
                hash: min_val,
                token_pos: min_idx,
            });
            last_min_pos = Some(min_idx);
        }
    }

    selected
}

/// Collect unique winnow hashes from text.
pub fn winnow_text(text: &str) -> HashSet<u64> {
    let tokens = tokenize(text);
    let token_texts: Vec<String> = tokens.into_iter().map(|t| t.text).collect();
    winnow_tokens(&token_texts)
        .into_iter()
        .map(|f| f.hash)
        .collect()
}
