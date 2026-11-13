#![forbid(unsafe_code)]

/// Check if a path corresponds to test infrastructure that must be dropped
/// as a whole file or directory and taken from the base tree.
pub fn is_whole_path_test_infra(path: &str, test_paths: &[String]) -> Option<&'static str> {
    // 1. Task's declared test paths
    if test_paths.iter().any(|t| {
        t == path
            || path
                .strip_prefix(t)
                .is_some_and(|rest| rest.starts_with('/'))
    }) {
        return Some("declared_test_path");
    }

    // 2. Check path segments and file name
    let filename = match path.rsplit('/').next() {
        Some(f) => f,
        None => path,
    };

    if filename == "conftest.py" {
        return Some("conftest");
    }
    if filename == "pytest.ini" {
        return Some("pytest_ini");
    }
    if filename == "tox.ini" {
        return Some("tox_ini");
    }
    if filename == "sitecustomize.py" {
        return Some("sitecustomize");
    }
    if filename == "usercustomize.py" {
        return Some("usercustomize");
    }
    if filename.ends_with(".pth") {
        return Some("pth_file");
    }

    // 3. In-tree *.egg-info and *.dist-info directories or files inside them
    for segment in path.split('/') {
        if segment.ends_with(".egg-info") {
            return Some("egg_info");
        }
        if segment.ends_with(".dist-info") {
            return Some("dist_info");
        }
    }

    None
}

/// Check if a file is subject to line-based section restoration
/// (such as setup.cfg, pyproject.toml, or tox.ini-style configuration files).
pub fn is_section_restored_file(path: &str) -> bool {
    let filename = match path.rsplit('/').next() {
        Some(f) => f,
        None => path,
    };

    filename == "setup.cfg"
        || filename == "pyproject.toml"
        || (filename.ends_with(".cfg") && filename != "setup.cfg")
}

#[derive(Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    Unmodified,
    SectionsRestored(String),
    FallbackWholeBaseRestored,
}

/// Restores test-runner sections and pytest11 entry points in `setup.cfg` or `pyproject.toml`.
/// Returns `RestoreOutcome::SectionsRestored(merged_content)` on successful merge,
/// or `RestoreOutcome::FallbackWholeBaseRestored` if the agent file cannot be safely parsed.
pub fn restore_file_sections(
    file_name: &str,
    base_content: Option<&str>,
    agent_content: &str,
) -> RestoreOutcome {
    if agent_content.chars().any(|c| {
        c == '\0' || c == '\u{feff}' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    }) {
        return RestoreOutcome::FallbackWholeBaseRestored;
    }
    if file_name.ends_with(".toml") {
        restore_toml_sections(base_content, agent_content)
    } else {
        // INI style (setup.cfg, *.cfg)
        restore_ini_sections(base_content, agent_content)
    }
}

// ---------------------------------------------------------------------------
// INI / setup.cfg section handling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct IniSection {
    header_line: String,
    name: String,
    body_lines: Vec<String>,
}

fn parse_ini_lines(content: &str) -> Result<(Vec<String>, Vec<IniSection>), ()> {
    let mut have_section = false;
    let mut option_indent = None;
    let mut options = std::collections::HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            have_section = true;
            option_indent = None;
            options.clear();
        } else if !trimmed.is_empty() && !trimmed.starts_with(['#', ';']) {
            if !have_section {
                return Err(());
            }
            let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
            if option_indent.is_some_and(|previous| indent > previous) {
                continue;
            }
            let (key, _) = trimmed.split_once(['=', ':']).ok_or(())?;
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() || !options.insert(key) {
                return Err(());
            }
            option_indent = Some(indent);
        }
    }
    let mut leading_comments = Vec::new();
    let mut sections = Vec::new();
    let mut current_section: Option<IniSection> = None;
    let mut names = std::collections::HashSet::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') || trimmed.len() < 2 {
                return Err(()); // unclosed bracket or invalid header
            }
            let name = trimmed[1..trimmed.len() - 1].trim().to_string();
            if name.is_empty()
                || name.contains(['[', ']'])
                || name == "DEFAULT"
                || line.starts_with([' ', '\t'])
                || !names.insert(name.clone())
            {
                return Err(());
            }

            if let Some(sec) = current_section.take() {
                sections.push(sec);
            }
            current_section = Some(IniSection {
                header_line: line.to_string(),
                name,
                body_lines: Vec::new(),
            });
        } else if let Some(ref mut sec) = current_section {
            sec.body_lines.push(line.to_string());
        } else {
            if !trimmed.is_empty() && !trimmed.starts_with(['#', ';']) {
                return Err(());
            }
            leading_comments.push(line.to_string());
        }
    }

    if let Some(sec) = current_section {
        sections.push(sec);
    }

    Ok((leading_comments, sections))
}

fn is_test_runner_ini_section(name: &str) -> bool {
    name == "tool:pytest"
        || name == "pytest"
        || name == "options.entry_points.pytest11"
        || name.starts_with("options.entry_points.pytest11.")
}

fn split_pytest11_lines(lines: &[String]) -> (Vec<String>, Vec<String>) {
    let mut other = Vec::new();
    let mut protected = Vec::new();
    let mut option_indent = None;
    let mut in_pytest11 = false;
    for line in lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with(['#', ';']) {
            let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
            if option_indent.is_none_or(|previous| indent <= previous) {
                in_pytest11 = trimmed
                    .split_once(['=', ':'])
                    .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("pytest11"));
                option_indent = Some(indent);
            }
        }
        if in_pytest11 {
            protected.push(line.clone());
        } else {
            other.push(line.clone());
        }
    }
    (other, protected)
}

fn restore_ini_sections(base_content: Option<&str>, agent_content: &str) -> RestoreOutcome {
    let (agent_leading, mut agent_sections) = match parse_ini_lines(agent_content) {
        Ok(res) => res,
        Err(_) => return RestoreOutcome::FallbackWholeBaseRestored,
    };

    let base_parsed = match base_content.map(parse_ini_lines).transpose() {
        Ok(parsed) => parsed,
        Err(_) => return RestoreOutcome::FallbackWholeBaseRestored,
    };

    // Extract test runner sections from base
    let mut base_test_sections = Vec::new();
    let mut base_pytest11_lines = Vec::new();

    if let Some((_, ref base_secs)) = base_parsed {
        for sec in base_secs {
            if is_test_runner_ini_section(&sec.name) {
                base_test_sections.push(sec.clone());
            } else if sec.name == "options.entry_points" {
                base_pytest11_lines.extend(split_pytest11_lines(&sec.body_lines).1);
            }
        }
    }

    // Filter agent sections: remove test runner sections and filter pytest11 in options.entry_points
    agent_sections.retain(|sec| !is_test_runner_ini_section(&sec.name));

    for sec in &mut agent_sections {
        if sec.name == "options.entry_points" {
            let mut new_body = split_pytest11_lines(&sec.body_lines).0;
            // Append base pytest11 lines
            new_body.extend(base_pytest11_lines.clone());
            sec.body_lines = new_body;
        }
    }

    if !base_pytest11_lines.is_empty()
        && !agent_sections
            .iter()
            .any(|s| s.name == "options.entry_points")
    {
        agent_sections.push(IniSection {
            header_line: "[options.entry_points]".into(),
            name: "options.entry_points".into(),
            body_lines: base_pytest11_lines,
        });
    }

    // Append base test runner sections
    agent_sections.extend(base_test_sections);

    // Reconstruct INI text
    let mut out = String::new();
    for line in agent_leading {
        out.push_str(&line);
        out.push('\n');
    }
    for sec in agent_sections {
        out.push_str(&sec.header_line);
        out.push('\n');
        for line in sec.body_lines {
            out.push_str(&line);
            out.push('\n');
        }
    }

    RestoreOutcome::SectionsRestored(out)
}

// ---------------------------------------------------------------------------
// TOML / pyproject.toml section handling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TomlTable {
    header_line: String,
    name: String,
    body_lines: Vec<String>,
}

fn parse_toml_tables(content: &str) -> Result<(Vec<String>, Vec<TomlTable>), ()> {
    // Conservative grammar: bare table names and bare, non-dotted assignment
    // keys only. Quoted/dotted keys, inline tables, multiline strings and array
    // tables can express protected settings outside the apparent section and
    // therefore restore the entire file. Single-line strings and multiline
    // arrays of scalar values are safe to retain.
    let mut names = std::collections::HashSet::new();
    let mut array_depth = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if array_depth == 0 && trimmed.starts_with('[') {
            let name = trimmed
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .ok_or(())?;
            if name.is_empty()
                || !name.split('.').all(|c| {
                    !c.is_empty()
                        && c.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
                || !names.insert(name)
            {
                return Err(());
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let value = if array_depth == 0 {
            let (key, value) = trimmed.split_once('=').ok_or(())?;
            let key = key.trim();
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(());
            }
            value
        } else {
            trimmed
        };
        let mut quote = None;
        let mut escape = false;
        for c in value.chars() {
            if escape {
                escape = false;
                continue;
            }
            if let Some(q) = quote {
                if c == '\\' && q == '"' {
                    escape = true;
                } else if c == q {
                    quote = None;
                }
            } else {
                match c {
                    '#' => break,
                    '\'' | '"' => quote = Some(c),
                    '{' | '}' => return Err(()),
                    '[' => {
                        array_depth = array_depth.checked_add(1).ok_or(())?;
                    }
                    ']' => {
                        array_depth = array_depth.checked_sub(1).ok_or(())?;
                    }
                    _ => {}
                }
            }
        }
        if quote.is_some() || value.contains("\"\"\"") || value.contains("'''") {
            return Err(());
        }
    }
    if array_depth != 0 {
        return Err(());
    }
    let mut leading = Vec::new();
    let mut tables = Vec::new();
    let mut current_table: Option<TomlTable> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            if !trimmed.ends_with(']') || trimmed.len() < 2 {
                return Err(());
            }
            let name = trimmed[1..trimmed.len() - 1].trim().to_string();
            if name.is_empty() {
                return Err(());
            }

            if let Some(tbl) = current_table.take() {
                tables.push(tbl);
            }
            current_table = Some(TomlTable {
                header_line: line.to_string(),
                name,
                body_lines: Vec::new(),
            });
        } else if trimmed.starts_with("[[") {
            // Array of tables
            if !trimmed.ends_with("]]") || trimmed.len() < 4 {
                return Err(());
            }
            let name = trimmed[2..trimmed.len() - 2].trim().to_string();
            if let Some(tbl) = current_table.take() {
                tables.push(tbl);
            }
            current_table = Some(TomlTable {
                header_line: line.to_string(),
                name,
                body_lines: Vec::new(),
            });
        } else if let Some(ref mut tbl) = current_table {
            tbl.body_lines.push(line.to_string());
        } else {
            leading.push(line.to_string());
        }
    }

    if let Some(tbl) = current_table {
        tables.push(tbl);
    }

    Ok((leading, tables))
}

fn is_test_runner_toml_table(name: &str) -> bool {
    name == "tool.pytest.ini_options"
        || name.starts_with("tool.pytest.")
        || name == "project.entry-points.pytest11"
        || name == "project.entry-points.\"pytest11\""
        || name == "tool.flit.entrypoints.pytest11"
        || name == "tool.flit.entrypoints.\"pytest11\""
        || name == "tool.poetry.plugins.pytest11"
        || name == "tool.poetry.plugins.\"pytest11\""
}

fn restore_toml_sections(base_content: Option<&str>, agent_content: &str) -> RestoreOutcome {
    let (agent_leading, mut agent_tables) = match parse_toml_tables(agent_content) {
        Ok(res) => res,
        Err(_) => return RestoreOutcome::FallbackWholeBaseRestored,
    };

    let base_parsed = match base_content.map(parse_toml_tables).transpose() {
        Ok(parsed) => parsed,
        Err(_) => return RestoreOutcome::FallbackWholeBaseRestored,
    };

    let mut base_test_tables = Vec::new();
    if let Some((_, ref base_tbls)) = base_parsed {
        for tbl in base_tbls {
            if is_test_runner_toml_table(&tbl.name) {
                base_test_tables.push(tbl.clone());
            }
        }
    }

    // Filter agent tables: remove any test runner tables
    agent_tables.retain(|tbl| !is_test_runner_toml_table(&tbl.name));

    // Append base test runner tables
    agent_tables.extend(base_test_tables);

    let mut out = String::new();
    for line in agent_leading {
        out.push_str(&line);
        out.push('\n');
    }
    for tbl in agent_tables {
        out.push_str(&tbl.header_line);
        out.push('\n');
        for line in tbl.body_lines {
            out.push_str(&line);
            out.push('\n');
        }
    }

    RestoreOutcome::SectionsRestored(out)
}
