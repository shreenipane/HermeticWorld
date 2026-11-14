use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

use crate::cutoff::{rfc3339_utc, DiscardedDate};

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing task file: {0}")]
    MissingFile(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffsRecord {
    #[serde(with = "rfc3339_utc")]
    pub t_world: OffsetDateTime,
    #[serde(with = "rfc3339_utc")]
    pub t_clock: OffsetDateTime,
    #[serde(default)]
    pub discarded: Vec<DiscardedDate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskJson {
    #[serde(default)]
    pub schema: Option<String>,
    pub instance_id: String,
    pub repo: String,
    pub base_commit: String,
    #[serde(default)]
    pub version: Option<String>,
    pub cutoffs: CutoffsRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskInput {
    pub instance_id: String,
    pub repo: String,
    pub base_commit: String,
    #[serde(default)]
    pub version: Option<String>,
    pub cutoffs: CutoffsRecord,
    pub gold_patch: String,
    pub test_patch: String,
    pub problem_statement: String,
    #[serde(default)]
    /// Known passing fixes (`staging/fixes/*.patch`, sorted by file name; TR-SC-1).
    /// Missing directory means none. Only regular files are read; symlinks are skipped.
    pub passing_fixes: Vec<String>,
}

/// The most fix files `TaskInput::load` reads from `staging/fixes/`.
pub const MAX_FIX_FILES: usize = 256;
/// The largest fix file `TaskInput::load` reads (16 MiB); larger files are an error.
pub const MAX_FIX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Bound directory traversal and aggregate fix bytes independently of file count.
pub const MAX_FIX_DIRECTORY_ENTRIES: usize = 4096;
pub const MAX_TOTAL_FIX_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn load_passing_fixes(dir: &Path) -> Result<Vec<String>, ManifestError> {
    use std::collections::BTreeSet;
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;
    const O_PATH: i32 = 0o10000000;
    const O_NOFOLLOW: i32 = 0o400000;
    const O_DIRECTORY: i32 = 0o200000;
    let refused = || ManifestError::MissingFile("passing fixes input refused".into());
    let child_path = |parent: &File, name: &std::ffi::OsStr| {
        Path::new(&format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name)
    };
    let mut held = File::open(if dir.is_absolute() { "/" } else { "." })?;
    // Hold every directory component. A missing/non-directory fixes leaf means
    // no optional fixes, preserving the intake contract.
    let components: Vec<_> = dir.components().collect();
    for (index, component) in components.iter().enumerate() {
        let name = match component {
            Component::Normal(name) => name,
            Component::RootDir | Component::CurDir => continue,
            _ => return Err(refused()),
        };
        let path = child_path(&held, name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) if index + 1 == components.len() => return Ok(Vec::new()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            _ => return Err(refused()),
        }
        held = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_DIRECTORY)
            .open(path)
            .map_err(|_| refused())?;
    }
    let entries =
        std::fs::read_dir(format!("/proc/self/fd/{}", held.as_raw_fd())).map_err(|_| refused())?;
    let mut names = BTreeSet::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_FIX_DIRECTORY_ENTRIES {
            return Err(refused());
        }
        let name = entry.map_err(|_| refused())?.file_name();
        if Path::new(&name).extension().and_then(|x| x.to_str()) == Some("patch") {
            let meta =
                std::fs::symlink_metadata(child_path(&held, &name)).map_err(|_| refused())?;
            if !meta.is_file() {
                continue;
            }
            if meta.len() > MAX_FIX_FILE_BYTES {
                return Err(refused());
            }
            names.insert(name);
            if names.len() > MAX_FIX_FILES {
                names.pop_last();
            }
        }
    }
    let mut total = 0u64;
    let mut fixes = Vec::new();
    for name in names {
        let path = child_path(&held, &name);
        let before = std::fs::symlink_metadata(&path).map_err(|_| refused())?;
        if !before.is_file() {
            continue;
        }
        let pinned = OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH | O_NOFOLLOW)
            .open(path)
            .map_err(|_| refused())?;
        let after = pinned.metadata().map_err(|_| refused())?;
        if (before.dev(), before.ino(), before.mode()) != (after.dev(), after.ino(), after.mode())
            || !after.is_file()
            || after.len() > MAX_FIX_FILE_BYTES
        {
            return Err(refused());
        }
        let file =
            File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd())).map_err(|_| refused())?;
        let cap = MAX_FIX_FILE_BYTES.min(MAX_TOTAL_FIX_BYTES.saturating_sub(total));
        let mut text = String::new();
        file.take(cap + 1)
            .read_to_string(&mut text)
            .map_err(|_| refused())?;
        if text.len() as u64 > cap {
            return Err(refused());
        }
        total += text.len() as u64;
        fixes.push(text);
    }
    Ok(fixes)
}

#[cfg(not(target_os = "linux"))]
fn load_passing_fixes(_dir: &Path) -> Result<Vec<String>, ManifestError> {
    Err(ManifestError::MissingFile(
        "safe passing fixes access requires Linux".into(),
    ))
}

impl TaskInput {
    /// Load task input from a task directory containing `task.json`,
    /// `staging/gold.patch`, `staging/test.patch`, and `agent/problem_statement.md`.
    pub fn load(task_dir: &Path) -> Result<Self, ManifestError> {
        let task_json_path = task_dir.join("task.json");
        let task_json_str = std::fs::read_to_string(&task_json_path).map_err(|e| {
            ManifestError::MissingFile(format!("{}: {}", task_json_path.display(), e))
        })?;
        let task_json: TaskJson = serde_json::from_str(&task_json_str)?;

        let gold_patch_path = task_dir.join("staging").join("gold.patch");
        let gold_patch = std::fs::read_to_string(&gold_patch_path).map_err(|e| {
            ManifestError::MissingFile(format!("{}: {}", gold_patch_path.display(), e))
        })?;

        let test_patch_path = task_dir.join("staging").join("test.patch");
        let test_patch = std::fs::read_to_string(&test_patch_path).map_err(|e| {
            ManifestError::MissingFile(format!("{}: {}", test_patch_path.display(), e))
        })?;

        let problem_statement_path = task_dir.join("agent").join("problem_statement.md");
        let problem_statement = std::fs::read_to_string(&problem_statement_path).map_err(|e| {
            ManifestError::MissingFile(format!("{}: {}", problem_statement_path.display(), e))
        })?;

        Ok(Self {
            instance_id: task_json.instance_id,
            repo: task_json.repo,
            base_commit: task_json.base_commit,
            version: task_json.version,
            cutoffs: task_json.cutoffs,
            gold_patch,
            test_patch,
            problem_statement,
            passing_fixes: load_passing_fixes(&task_dir.join("staging").join("fixes"))?,
        })
    }
}
