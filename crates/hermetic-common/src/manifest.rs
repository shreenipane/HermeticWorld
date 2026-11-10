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
    pub cutoffs: CutoffsRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskInput {
    pub instance_id: String,
    pub repo: String,
    pub base_commit: String,
    pub cutoffs: CutoffsRecord,
    pub gold_patch: String,
    pub test_patch: String,
    pub problem_statement: String,
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
            cutoffs: task_json.cutoffs,
            gold_patch,
            test_patch,
            problem_statement,
        })
    }
}
