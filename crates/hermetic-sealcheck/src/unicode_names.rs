//! Python `\N{...}` name lookup from a checked-in Unicode name table.
//!
//! `data/unicode_names.txt` is generated once by `data/gen_unicode_names.py` from the host
//! Python's `unicodedata` (Unicode 16.0.0) and the UCD `NameAliases.txt` of the same version;
//! the file header records the versions and the command. The build never runs Python.
//!
//! The table lists every character name and formal alias, sorted by bytes, except names
//! derived by rule: `@PREFIX\tFIRST\tLAST` rows give the ranges where the name is the prefix
//! followed by the code point in upper-case hex (CJK unified and compatibility ideographs,
//! Tangut, Khitan, Nushu, Egyptian hieroglyphs), and Hangul syllable names are composed
//! from their jamo as in the Unicode standard. Lookup is case-insensitive, as Python's is.

use std::sync::OnceLock;

static TABLE_TEXT: &str = include_str!("../data/unicode_names.txt");

/// Longer than any Unicode character name or alias; longer input is never a name.
pub const MAX_UNICODE_NAME_LEN: usize = 128;

struct Table {
    /// (name, code point), sorted by name bytes.
    names: Vec<(&'static str, u32)>,
    /// (prefix, first, last) ranges of hex-suffixed algorithmic names.
    rules: Vec<(&'static str, u32, u32)>,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut names = Vec::new();
        let mut rules = Vec::new();
        for line in TABLE_TEXT.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let mut fields = line.split('\t');
            let first = fields.next().unwrap_or("");
            let a = fields.next().and_then(|h| u32::from_str_radix(h, 16).ok());
            if let Some(prefix) = first.strip_prefix('@') {
                let b = fields.next().and_then(|h| u32::from_str_radix(h, 16).ok());
                if let (Some(a), Some(b)) = (a, b) {
                    rules.push((prefix, a, b));
                }
            } else if let Some(a) = a {
                names.push((first, a));
            }
        }
        // The file is sorted; sorting again keeps lookup correct even if it were not.
        names.sort_unstable_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()));
        Table { names, rules }
    })
}

const JAMO_L: &[&str] = &[
    "G", "GG", "N", "D", "DD", "R", "M", "B", "BB", "S", "SS", "", "J", "JJ", "C", "K", "T", "P",
    "H",
];
const JAMO_V: &[&str] = &[
    "A", "AE", "YA", "YAE", "EO", "E", "YEO", "YE", "O", "WA", "WAE", "OE", "YO", "U", "WEO", "WE",
    "WI", "YU", "EU", "YI", "I",
];
const JAMO_T: &[&str] = &[
    "", "G", "GG", "GS", "N", "NJ", "NH", "D", "L", "LG", "LM", "LB", "LS", "LT", "LP", "LH", "M",
    "B", "BS", "S", "SS", "NG", "J", "C", "K", "T", "P", "H",
];

/// The index of the longest entry of `list` that prefixes `s`, and its length.
fn longest_jamo(s: &str, list: &[&str]) -> Option<(usize, usize)> {
    list.iter()
        .enumerate()
        .filter(|(_, j)| s.starts_with(**j))
        .max_by_key(|(_, j)| j.len())
        .map(|(i, j)| (i, j.len()))
}

fn hangul_syllable(rest: &str) -> Option<char> {
    let (l, n) = longest_jamo(rest, JAMO_L)?;
    let rest = rest.get(n..)?;
    let (v, n) = longest_jamo(rest, JAMO_V)?;
    let rest = rest.get(n..)?;
    let (t, n) = longest_jamo(rest, JAMO_T)?;
    if n != rest.len() {
        return None;
    }
    let index = u32::try_from(
        l.checked_mul(21)?
            .checked_add(v)?
            .checked_mul(28)?
            .checked_add(t)?,
    )
    .ok()?;
    char::from_u32(0xAC00u32.checked_add(index)?)
}

/// The character Python's `\N{name}` produces, or `None` if the table does not know it.
pub fn lookup(name: &str) -> Option<char> {
    if name.is_empty() || name.len() > MAX_UNICODE_NAME_LEN || !name.is_ascii() {
        return None;
    }
    let upper = name.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix("HANGUL SYLLABLE ") {
        return hangul_syllable(rest);
    }
    let t = table();
    for &(prefix, first, last) in &t.rules {
        if let Some(hex) = upper.strip_prefix(prefix) {
            let Ok(cp) = u32::from_str_radix(hex, 16) else {
                continue;
            };
            // Only the canonical spelling (at least 4 digits, no extra leading zeros).
            if (first..=last).contains(&cp) && format!("{cp:04X}") == hex {
                return char::from_u32(cp);
            }
        }
    }
    t.names
        .binary_search_by(|(n, _)| n.as_bytes().cmp(upper.as_bytes()))
        .ok()
        .and_then(|i| t.names.get(i))
        .and_then(|&(_, cp)| char::from_u32(cp))
}

#[cfg(test)]
mod tests {
    use super::lookup;

    #[test]
    fn names_aliases_and_rules() {
        assert_eq!(lookup("HEAVY BLACK HEART"), Some('\u{2764}'));
        assert_eq!(lookup("black chess king"), Some('\u{265A}'));
        assert_eq!(lookup("BYTE ORDER MARK"), Some('\u{FEFF}'));
        assert_eq!(lookup("line feed"), Some('\n'));
        assert_eq!(lookup("cjk unified ideograph-4e00"), Some('\u{4E00}'));
        assert_eq!(lookup("CJK UNIFIED IDEOGRAPH-04E00"), None);
        assert_eq!(lookup("TANGUT IDEOGRAPH-17000"), Some('\u{17000}'));
        assert_eq!(lookup("HANGUL SYLLABLE GA"), Some('\u{AC00}'));
        assert_eq!(lookup("HANGUL SYLLABLE HIH"), Some('\u{D7A3}'));
        assert_eq!(lookup("hangul syllable gag"), Some('\u{AC01}'));
        assert_eq!(lookup("HANGUL SYLLABLE"), None);
        assert_eq!(lookup("NO SUCH CHARACTER NAME"), None);
        assert_eq!(lookup(""), None);
        assert_eq!(lookup(&"A".repeat(10_000)), None);
        assert_eq!(lookup(" BULLET"), None);
    }
}
