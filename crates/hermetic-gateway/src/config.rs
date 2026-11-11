#![forbid(unsafe_code)]

use crate::quota::QuotasConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfigFile {
    #[serde(default = "default_upstream_base_url")]
    pub upstream_base_url: String,

    pub anthropic_version: String,

    #[serde(default)]
    pub allowed_betas: Vec<String>,

    pub pinned_models: Vec<String>,

    #[serde(default)]
    pub quotas: QuotasConfig,

    pub log_dir: PathBuf,

    pub api_key_file: PathBuf,

    #[serde(default = "default_upstream_read_timeout_s")]
    pub upstream_read_timeout_s: u64,
}

fn default_upstream_base_url() -> String {
    "https://api.anthropic.com".to_string()
}

fn default_upstream_read_timeout_s() -> u64 {
    120
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub upstream_base_url: String,
    pub anthropic_version: String,
    pub allowed_betas: Vec<String>,
    pub pinned_models: Vec<String>,
    pub quotas: QuotasConfig,
    pub log_dir: PathBuf,
    pub api_key_file: PathBuf,
    pub upstream_read_timeout_s: u64,
    /// Loaded once into memory; never logged.
    api_key: String,
}

impl GatewayConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let file_contents = std::fs::read_to_string(path_ref)
            .map_err(|e| format!("Failed to read config file {}: {e}", path_ref.display()))?;
        let parsed: GatewayConfigFile = serde_json::from_str(&file_contents)
            .map_err(|e| format!("Failed to parse config JSON {}: {e}", path_ref.display()))?;

        let api_key = std::fs::read_to_string(&parsed.api_key_file)
            .map_err(|e| {
                format!(
                    "Failed to read API key file {}: {e}",
                    parsed.api_key_file.display()
                )
            })?
            .trim()
            .to_string();

        if api_key.is_empty() {
            return Err(format!(
                "API key file {} is empty",
                parsed.api_key_file.display()
            ));
        }

        Ok(Self {
            upstream_base_url: parsed.upstream_base_url,
            anthropic_version: parsed.anthropic_version,
            allowed_betas: parsed.allowed_betas,
            pinned_models: parsed.pinned_models,
            quotas: parsed.quotas,
            log_dir: parsed.log_dir,
            api_key_file: parsed.api_key_file,
            upstream_read_timeout_s: parsed.upstream_read_timeout_s,
            api_key,
        })
    }

    /// Construct directly (useful for tests).
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw(
        upstream_base_url: String,
        anthropic_version: String,
        allowed_betas: Vec<String>,
        pinned_models: Vec<String>,
        quotas: QuotasConfig,
        log_dir: PathBuf,
        api_key_file: PathBuf,
        api_key: String,
    ) -> Self {
        Self {
            upstream_base_url,
            anthropic_version,
            allowed_betas,
            pinned_models,
            quotas,
            log_dir,
            api_key_file,
            upstream_read_timeout_s: 120,
            api_key,
        }
    }

    pub fn with_upstream_read_timeout_s(mut self, timeout_s: u64) -> Self {
        self.upstream_read_timeout_s = timeout_s;
        self
    }

    /// Access the API key in memory only.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}
