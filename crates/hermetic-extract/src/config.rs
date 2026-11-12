#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
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
    /// Safely loads configuration from a regular JSON file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ExtractError> {
        let path = path.as_ref();
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            ExtractError::Config(format!("cannot stat config file '{}': {e}", path.display()))
        })?;

        if meta.file_type().is_symlink() {
            return Err(ExtractError::Config(format!(
                "config file '{}' is a symlink",
                path.display()
            )));
        }

        if !meta.file_type().is_file() {
            return Err(ExtractError::Config(format!(
                "config file '{}' is not a regular file",
                path.display()
            )));
        }

        if meta.size() > MAX_CONFIG_FILE_BYTES {
            return Err(ExtractError::Config(format!(
                "config file '{}' size {} exceeds limit of {} bytes",
                path.display(),
                meta.size(),
                MAX_CONFIG_FILE_BYTES
            )));
        }

        let mut file = File::open(path).map_err(|e| {
            ExtractError::Config(format!("cannot open config file '{}': {e}", path.display()))
        })?;

        let mut contents = Vec::with_capacity(meta.size().min(MAX_CONFIG_FILE_BYTES) as usize);
        file.by_ref()
            .take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut contents)
            .map_err(|e| {
                ExtractError::Config(format!("cannot read config file '{}': {e}", path.display()))
            })?;

        if contents.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(ExtractError::Config(format!(
                "config file '{}' exceeded maximum size",
                path.display()
            )));
        }

        let s = std::str::from_utf8(&contents).map_err(|_| {
            ExtractError::Config(format!(
                "config file '{}' is not valid UTF-8",
                path.display()
            ))
        })?;

        let config: ExtractConfig = serde_json::from_str(s).map_err(|e| {
            ExtractError::Config(format!(
                "failed to parse config JSON '{}': {e}",
                path.display()
            ))
        })?;

        Ok(config)
    }
}
