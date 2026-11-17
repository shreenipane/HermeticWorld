#![forbid(unsafe_code)]

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ExtractError;

pub const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Task class specifying extraction constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    Patch,
    Artifact,
    State,
}

/// Parsed benchmark task class specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskClassSpec {
    /// Extract changes within a repository directory (`""` denotes the tree root).
    Patch { repo_dir: String },
    /// Extract changes only for explicitly declared relative paths.
    Artifact { paths: Vec<String> },
    /// Extract nothing (produces a valid header + empty end record).
    State,
}

impl TaskClassSpec {
    pub fn class_kind(&self) -> TaskClass {
        match self {
            TaskClassSpec::Patch { .. } => TaskClass::Patch,
            TaskClassSpec::Artifact { .. } => TaskClass::Artifact,
            TaskClassSpec::State => TaskClass::State,
        }
    }
}

/// Validates a relative path for task class specifications.
fn validate_spec_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("path must not be empty".into());
    }
    if path.len() > 4096 {
        return Err("path exceeds maximum length of 4096 bytes".into());
    }
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("path contains whitespace or control characters".into());
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err("path must be relative without leading or trailing slash".into());
    }
    if path.contains('\0') || path.contains('\\') {
        return Err("path contains forbidden character".into());
    }
    let mut depth: usize = 0;
    for seg in path.split('/') {
        depth = depth.saturating_add(1);
        if depth > 32 {
            return Err("path depth exceeds limit of 32".into());
        }
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err("path contains empty, '.', or '..' segment".into());
        }
    }
    Ok(())
}

/// Parses and validates a task class specification string (`patch:REPO`, `patch:` for the tree root,
/// `artifact:P1,P2`, or `state`).
///
/// Refuses whitespace, control characters, leading/trailing slashes, and traversal sequences.
pub fn parse_task_class_spec(spec: &str) -> Result<TaskClassSpec, String> {
    if spec.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("task class must not contain whitespace or control characters".into());
    }
    if spec == "state" {
        return Ok(TaskClassSpec::State);
    }
    if let Some(repo) = spec.strip_prefix("patch:") {
        if repo == "." || repo == "./" || repo == "/" {
            return Err(
                "tree root must be spelled `patch:` (empty repo path), not '.' or '/'".into(),
            );
        }
        if !repo.is_empty() {
            validate_spec_relative_path(repo)?;
        }
        return Ok(TaskClassSpec::Patch {
            repo_dir: repo.to_string(),
        });
    }
    if let Some(list) = spec.strip_prefix("artifact:") {
        if list.is_empty() {
            return Err("artifact path list must not be empty".into());
        }
        let mut paths = Vec::new();
        for (idx, raw) in list.split(',').enumerate() {
            if idx >= 64 {
                return Err("too many declared artifact paths (limit 64)".into());
            }
            if raw.is_empty() {
                return Err("artifact path entry must not be empty".into());
            }
            validate_spec_relative_path(raw)?;
            paths.push(raw.to_string());
        }
        return Ok(TaskClassSpec::Artifact { paths });
    }
    Err(format!(
        "invalid task class specification '{spec}': expected 'patch:REPO', 'artifact:P1,P2', or 'state'"
    ))
}

impl FromStr for TaskClass {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "patch" => Ok(Self::Patch),
            "artifact" => Ok(Self::Artifact),
            "state" => Ok(Self::State),
            other => Err(format!(
                "invalid task class '{other}': expected 'patch', 'artifact', or 'state'"
            )),
        }
    }
}

impl fmt::Display for TaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Patch => write!(f, "patch"),
            Self::Artifact => write!(f, "artifact"),
            Self::State => write!(f, "state"),
        }
    }
}

/// Configuration and quotas for stream validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractConfig {
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,

    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: u64,

    #[serde(default = "default_max_file_count")]
    pub max_file_count: u64,

    #[serde(default = "default_max_dir_count")]
    pub max_dir_count: u64,

    #[serde(default = "default_max_path_bytes")]
    pub max_path_bytes: usize,

    #[serde(default = "default_max_path_depth")]
    pub max_path_depth: usize,

    #[serde(default)]
    pub repo_dir: Option<String>,

    #[serde(default)]
    pub artifact_paths: Vec<String>,

    #[serde(default)]
    pub test_paths: Vec<String>,

    #[serde(default)]
    pub installed_packages: Vec<String>,

    #[serde(default = "default_import_roots")]
    pub import_roots: Vec<String>,

    #[serde(default)]
    pub task_class: Option<TaskClass>,
}

fn default_max_file_bytes() -> u64 {
    64 * 1024 * 1024 // 64 MiB
}

fn default_max_total_bytes() -> u64 {
    256 * 1024 * 1024 // 256 MiB
}

fn default_max_file_count() -> u64 {
    10_000
}

fn default_max_dir_count() -> u64 {
    2_000
}

pub fn default_max_path_bytes() -> usize {
    4096
}

pub fn default_max_path_depth() -> usize {
    64
}

fn default_import_roots() -> Vec<String> {
    vec!["".to_string(), "src".to_string()]
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: default_max_file_bytes(),
            max_total_bytes: default_max_total_bytes(),
            max_file_count: default_max_file_count(),
            max_dir_count: default_max_dir_count(),
            max_path_bytes: default_max_path_bytes(),
            max_path_depth: default_max_path_depth(),
            repo_dir: None,
            artifact_paths: Vec::new(),
            test_paths: Vec::new(),
            installed_packages: Vec::new(),
            import_roots: default_import_roots(),
            task_class: None,
        }
    }
}

impl ExtractConfig {
    /// Configuration paths share stream path rules; an absent/empty repo root
    /// denotes the base tree root. Limit lists before building policy indexes.
    pub fn validate(&self) -> Result<(), ExtractError> {
        const MAX_CONFIG_ENTRIES: usize = 10_000;
        let mut bytes = 0usize;
        for list in [
            &self.artifact_paths,
            &self.test_paths,
            &self.import_roots,
            &self.installed_packages,
        ] {
            if list.len() > MAX_CONFIG_ENTRIES {
                return Err(ExtractError::Config(
                    "too many configuration entries".into(),
                ));
            }
            for value in list {
                bytes = bytes
                    .checked_add(value.len())
                    .filter(|n| *n <= MAX_CONFIG_FILE_BYTES as usize)
                    .ok_or_else(|| {
                        ExtractError::Config("configuration entries too large".into())
                    })?;
            }
        }
        // The tree root is spelled as the empty string (agent CLI `patch:`). Other root
        // spellings are refused explicitly rather than normalized.
        if let Some(repo) = &self.repo_dir {
            if repo == "." || repo == "./" || repo == "/" {
                return Err(ExtractError::Config(
                    "repo_dir must be \"\" for the tree root, not '.' or '/'".into(),
                ));
            }
        }
        for (path, allow_root) in self
            .repo_dir
            .iter()
            .map(|p| (p, true))
            .chain(self.artifact_paths.iter().map(|p| (p, false)))
            .chain(self.test_paths.iter().map(|p| (p, false)))
            .chain(self.import_roots.iter().map(|p| (p, true)))
        {
            if path.is_empty() && allow_root {
                continue;
            }
            if path.len() > crate::safe_fs::MAX_TREE_PATH_BYTES
                || path.contains(['\\', '\0'])
                || path.split('/').count() > crate::safe_fs::MAX_TREE_DEPTH
                || path
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == ".." || c.contains(':'))
            {
                return Err(ExtractError::Config("invalid configuration path".into()));
            }
        }
        Ok(())
    }

    /// Safely loads configuration from a regular JSON file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ExtractError> {
        let path = path.as_ref();
        let mut file = crate::safe_fs::open_regular_path(path)
            .map_err(|_| ExtractError::Config("unsafe config file".into()))?;
        let mut contents = Vec::new();
        file.by_ref()
            .take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut contents)
            .map_err(|_| ExtractError::Config("cannot read config".into()))?;

        if contents.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(ExtractError::Config("config exceeded maximum size".into()));
        }

        let s = std::str::from_utf8(&contents)
            .map_err(|_| ExtractError::Config("config is not UTF-8".into()))?;

        let config: ExtractConfig = serde_json::from_str(s)
            .map_err(|_| ExtractError::Config("invalid config JSON".into()))?;

        config.validate()?;
        Ok(config)
    }
}
