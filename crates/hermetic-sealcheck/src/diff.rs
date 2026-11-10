#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLineType {
    Context,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub line_type: DiffLineType,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HunkRange {
    pub start: usize,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HunkHeader {
    pub old_range: HunkRange,
    pub new_range: HunkRange,
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub header: HunkHeader,
    pub raw_header: String,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub files: Vec<FilePatch>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiffParseError {
    #[error("Invalid hunk header: {0}")]
    InvalidHunkHeader(String),
}

fn parse_range(s: &str) -> Option<HunkRange> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((start_s, count_s)) = s.split_once(',') {
        let start = start_s.parse::<usize>().ok()?;
        let count = count_s.parse::<usize>().ok()?;
        Some(HunkRange { start, count })
    } else {
        let start = s.parse::<usize>().ok()?;
        let count = if start == 0 { 0 } else { 1 };
        Some(HunkRange { start, count })
    }
}

pub fn parse_hunk_header(line: &str) -> Result<HunkHeader, DiffParseError> {
    let trimmed = line.trim();
    if !trimmed.starts_with("@@") {
        return Err(DiffParseError::InvalidHunkHeader(line.to_string()));
    }
    let rest = &trimmed[2..];
    let closing = rest
        .find("@@")
        .ok_or_else(|| DiffParseError::InvalidHunkHeader(line.to_string()))?;
    let header_body = rest[..closing].trim();
    let section = rest[closing + 2..].trim();
    let section = if section.is_empty() {
        None
    } else {
        Some(section.to_string())
    };

    let parts: Vec<&str> = header_body.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(DiffParseError::InvalidHunkHeader(line.to_string()));
    }

    let old_part = parts[0]
        .strip_prefix('-')
        .ok_or_else(|| DiffParseError::InvalidHunkHeader(line.to_string()))?;
    let new_part = parts[1]
        .strip_prefix('+')
        .ok_or_else(|| DiffParseError::InvalidHunkHeader(line.to_string()))?;

    let old_range =
        parse_range(old_part).ok_or_else(|| DiffParseError::InvalidHunkHeader(line.to_string()))?;
    let new_range =
        parse_range(new_part).ok_or_else(|| DiffParseError::InvalidHunkHeader(line.to_string()))?;

    Ok(HunkHeader {
        old_range,
        new_range,
        section,
    })
}

fn strip_git_prefix(path: &str) -> &str {
    if let Some(stripped) = path.strip_prefix("a/") {
        stripped
    } else if let Some(stripped) = path.strip_prefix("b/") {
        stripped
    } else {
        path
    }
}

fn parse_file_path(line: &str, prefix: &str) -> Option<String> {
    if let Some(path_part) = line.strip_prefix(prefix) {
        let p = path_part.trim();
        if p == "/dev/null" {
            None
        } else {
            // Strip timestamp if present (unified diff separator is often tab)
            let path_only = p.split('\t').next().unwrap_or(p);
            Some(strip_git_prefix(path_only).to_string())
        }
    } else {
        None
    }
}

/// Parse unified diff text into a `Patch` containing files and hunks.
pub fn parse_patch(diff_text: &str) -> Result<Patch, DiffParseError> {
    let mut files: Vec<FilePatch> = Vec::new();
    let mut current_file: Option<FilePatch> = None;
    let mut current_hunk: Option<Hunk> = None;

    let lines: Vec<&str> = diff_text.lines().collect();
    let mut idx = 0;
    // Lines still owed to the current hunk, from its header ranges. While either is
    // non-zero, `--- x` and `+++ x` are body lines (a removed `-- x`, an added `++ x`),
    // not file headers.
    let mut old_left: usize = 0;
    let mut new_left: usize = 0;

    while idx < lines.len() {
        let line = lines[idx];

        if (old_left > 0 || new_left > 0) && current_hunk.is_some() {
            let body = if let Some(content) = line.strip_prefix('-') {
                old_left = old_left.saturating_sub(1);
                Some((DiffLineType::Removed, content))
            } else if let Some(content) = line.strip_prefix('+') {
                new_left = new_left.saturating_sub(1);
                Some((DiffLineType::Added, content))
            } else if line.is_empty() || line.starts_with(' ') {
                old_left = old_left.saturating_sub(1);
                new_left = new_left.saturating_sub(1);
                Some((DiffLineType::Context, line.get(1..).unwrap_or("")))
            } else {
                None
            };
            if let Some((line_type, content)) = body {
                if let Some(ref mut hunk) = current_hunk {
                    hunk.lines.push(DiffLine {
                        line_type,
                        content: content.to_string(),
                    });
                }
                idx += 1;
                continue;
            }
            // `\ No newline at end of file` stays inside the body; anything else ends it.
            if !line.starts_with('\\') {
                old_left = 0;
                new_left = 0;
            }
        }

        if let Some(git_header) = line.strip_prefix("diff --git ") {
            if let Some(hunk) = current_hunk.take() {
                if let Some(ref mut file) = current_file {
                    file.hunks.push(hunk);
                }
            }
            if let Some(file) = current_file.take() {
                files.push(file);
            }

            // Extract default paths from `diff --git a/path b/path`
            let parts: Vec<&str> = git_header.split_whitespace().collect();
            let (old_p, new_p) = if parts.len() >= 2 {
                let op = strip_git_prefix(parts[0]).to_string();
                let np = strip_git_prefix(parts[1]).to_string();
                (Some(op), Some(np))
            } else {
                (None, None)
            };

            current_file = Some(FilePatch {
                old_path: old_p,
                new_path: new_p,
                hunks: Vec::new(),
            });
            idx += 1;
            continue;
        }

        if line.starts_with("--- ") {
            if let Some(ref mut file) = current_file {
                file.old_path = parse_file_path(line, "--- ");
            }
            idx += 1;
            continue;
        }

        if line.starts_with("+++ ") {
            if let Some(ref mut file) = current_file {
                file.new_path = parse_file_path(line, "+++ ");
            }
            idx += 1;
            continue;
        }

        if line.starts_with("@@") {
            if let Some(hunk) = current_hunk.take() {
                if let Some(ref mut file) = current_file {
                    file.hunks.push(hunk);
                }
            }
            let header = parse_hunk_header(line)?;
            old_left = header.old_range.count;
            new_left = header.new_range.count;
            current_hunk = Some(Hunk {
                header,
                raw_header: line.to_string(),
                lines: Vec::new(),
            });
            idx += 1;
            continue;
        }

        if line.starts_with(r"\ No newline at end of file") {
            idx += 1;
            continue;
        }

        if let Some(ref mut hunk) = current_hunk {
            if let Some(content) = line.strip_prefix('+') {
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Added,
                    content: content.to_string(),
                });
            } else if let Some(content) = line.strip_prefix('-') {
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Removed,
                    content: content.to_string(),
                });
            } else if let Some(content) = line.strip_prefix(' ') {
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Context,
                    content: content.to_string(),
                });
            } else if line.is_empty() {
                // An empty line in diff can be an empty context line
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Context,
                    content: String::new(),
                });
            }
        }

        idx += 1;
    }

    if let Some(hunk) = current_hunk.take() {
        if let Some(ref mut file) = current_file {
            file.hunks.push(hunk);
        }
    }
    if let Some(file) = current_file.take() {
        files.push(file);
    }

    Ok(Patch { files })
}
