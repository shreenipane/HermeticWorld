use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndatedTask {
    pub instance_id: String,
    pub instruction: String,
    pub files: Vec<(String, String)>,
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn strip_inline_comment(s: &str) -> &str {
    let mut in_quote = None;
    for (i, b) in s.bytes().enumerate() {
        match in_quote {
            Some(q) => {
                if b == q {
                    in_quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    in_quote = Some(b);
                } else if b == b'#' {
                    return s[..i].trim();
                }
            }
        }
    }
    s
}

fn extract_key_value(content: &str, keys: &[&str]) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        for key in keys {
            if let Some(rest) = trimmed.strip_prefix(key) {
                let rest = rest.trim_start();
                if let Some(after_sep) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
                    let val = strip_inline_comment(after_sep.trim());
                    let unquoted = strip_quotes(val);
                    if !unquoted.is_empty() {
                        return Some(unquoted.to_string());
                    }
                }
            }
        }
    }
    None
}

fn extract_id_from_metadata(task_dir: &Path) -> Option<String> {
    // 1. task.toml
    let toml_path = task_dir.join("task.toml");
    if let Ok(content) = fs::read_to_string(&toml_path) {
        if let Some(id) = extract_key_value(&content, &["instance_id", "id"]) {
            return Some(id);
        }
    }

    // 2. task.yaml
    let yaml_path = task_dir.join("task.yaml");
    if let Ok(content) = fs::read_to_string(&yaml_path) {
        if let Some(id) = extract_key_value(&content, &["instance_id", "id"]) {
            return Some(id);
        }
    }

    // 3. task.json
    let json_path = task_dir.join("task.json");
    if let Ok(content) = fs::read_to_string(&json_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(obj) = val.as_object() {
                if let Some(id) = obj
                    .get("instance_id")
                    .or_else(|| obj.get("id"))
                    .and_then(|v| v.as_str())
                {
                    if !id.trim().is_empty() {
                        return Some(id.trim().to_string());
                    }
                }
            }
        }
    }

    None
}

fn get_directory_name(task_dir: &Path) -> String {
    let canon = task_dir.canonicalize().ok();
    let p = canon.as_deref().unwrap_or(task_dir);
    p.file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("task")
        .to_string()
}

fn extract_yaml_instruction(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("instruction:") {
            let after_colon = rest.trim();
            if after_colon == "|"
                || after_colon == "|-"
                || after_colon == "|+"
                || after_colon == ">"
                || after_colon == ">-"
                || after_colon == ">+"
            {
                let mut block_lines = Vec::new();
                let mut block_indent = None;
                for next_line in &lines[i + 1..] {
                    if next_line.trim().is_empty() {
                        block_lines.push("");
                        continue;
                    }
                    let indent = next_line.len() - next_line.trim_start().len();
                    match block_indent {
                        None => {
                            if indent == 0 {
                                break;
                            }
                            block_indent = Some(indent);
                            block_lines.push(&next_line[indent..]);
                        }
                        Some(base_indent) => {
                            if indent < base_indent {
                                break;
                            }
                            let slice_idx = indent.min(base_indent);
                            block_lines.push(&next_line[slice_idx..]);
                        }
                    }
                }
                if !block_lines.is_empty() {
                    return Some(block_lines.join("\n"));
                }
            } else if !after_colon.is_empty() {
                let unquoted = strip_quotes(strip_inline_comment(after_colon));
                return Some(unquoted.to_string());
            }
        }
    }
    None
}

fn extract_instruction(task_dir: &Path) -> String {
    let md_path = task_dir.join("instruction.md");
    if let Ok(content) = fs::read_to_string(&md_path) {
        return content;
    }

    let yaml_path = task_dir.join("task.yaml");
    if let Ok(content) = fs::read_to_string(&yaml_path) {
        if let Some(inst) = extract_yaml_instruction(&content) {
            return inst;
        }
    }

    String::new()
}

fn gather_undated_files(task_dir: &Path) -> Result<Vec<(String, String)>, std::io::Error> {
    let mut files = Vec::new();
    for sub in &["solution", "tests"] {
        let sub_dir = task_dir.join(sub);
        if sub_dir.is_dir() {
            for entry in WalkDir::new(&sub_dir)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !e.path_is_symlink())
                .flatten()
            {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    let rel_path = match path.strip_prefix(task_dir) {
                        Ok(p) => p.to_string_lossy().replace('\\', "/"),
                        Err(_) => path.to_string_lossy().replace('\\', "/"),
                    };
                    let bytes = fs::read(path)?;
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    files.push((rel_path, text));
                }
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

pub fn load_undated_task(task_dir: &Path) -> Result<UndatedTask, std::io::Error> {
    if !task_dir.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "task directory '{}' does not exist or is not a directory",
                task_dir.display()
            ),
        ));
    }

    let instance_id =
        extract_id_from_metadata(task_dir).unwrap_or_else(|| get_directory_name(task_dir));
    let instruction = extract_instruction(task_dir);
    let files = gather_undated_files(task_dir)?;

    Ok(UndatedTask {
        instance_id,
        instruction,
        files,
    })
}
