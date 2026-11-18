#![forbid(unsafe_code)]

use crate::quota::QuotasConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    #[default]
    Anthropic,
    OpenaiChat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfigFile {
    #[serde(default)]
    pub upstream_protocol: Option<UpstreamProtocol>,
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

    /// Real-date sentinel (D12, TR-SEC-5) host data to look for. The real date itself is the
    /// host's current UTC date at gateway start.
    #[serde(default)]
    pub date_sentinel: DateSentinelConfig,
}

/// Host names and host paths the D12 sentinel looks for in gateway traffic. Never logged.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DateSentinelConfig {
    #[serde(default)]
    pub host_names: Vec<String>,
    #[serde(default)]
    pub host_paths: Vec<String>,
    #[serde(default = "default_tolerance_days")]
    pub tolerance_days: u32,
}

fn default_tolerance_days() -> u32 {
    1
}

impl std::fmt::Debug for DateSentinelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DateSentinelConfig")
            .field("host_names", &self.host_names.len())
            .field("host_paths", &self.host_paths.len())
            .field("tolerance_days", &self.tolerance_days)
            .finish()
    }
}

fn default_upstream_base_url() -> String {
    "https://api.anthropic.com".to_string()
}

fn default_upstream_read_timeout_s() -> u64 {
    120
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub upstream_protocol: UpstreamProtocol,
    pub upstream_base_url: String,
    pub anthropic_version: String,
    pub allowed_betas: Vec<String>,
    pub pinned_models: Vec<String>,
    pub quotas: QuotasConfig,
    pub log_dir: PathBuf,
    pub api_key_file: PathBuf,
    pub upstream_read_timeout_s: u64,
    pub date_sentinel: DateSentinelConfig,
    /// Loaded once into memory; never logged.
    api_key: String,
}

impl std::fmt::Debug for GatewayConfig {
    /// Same as a derived Debug, except that the API key is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("upstream_protocol", &self.upstream_protocol)
            .field("upstream_base_url", &self.upstream_base_url)
            .field("anthropic_version", &self.anthropic_version)
            .field("allowed_betas", &self.allowed_betas)
            .field("pinned_models", &self.pinned_models)
            .field("quotas", &self.quotas)
            .field("log_dir", &self.log_dir)
            .field("api_key_file", &self.api_key_file)
            .field("upstream_read_timeout_s", &self.upstream_read_timeout_s)
            .field("date_sentinel", &self.date_sentinel)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl GatewayConfig {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path_ref = path.as_ref();
        // Regular file only (no symlink, device or FIFO), at most MAX_CONFIG_FILE_BYTES.
        let raw =
            crate::fsutil::read_regular_file_capped(path_ref, crate::fsutil::MAX_CONFIG_FILE_BYTES)
                .map_err(|e| format!("Failed to read config file {}: {e}", path_ref.display()))?;
        let file_contents = String::from_utf8(raw)
            .map_err(|_| format!("Config file {} is not UTF-8", path_ref.display()))?;
        let parsed: GatewayConfigFile = serde_json::from_str(&file_contents)
            .map_err(|e| format!("Failed to parse config JSON {}: {e}", path_ref.display()))?;

        if parsed.upstream_read_timeout_s == 0 || parsed.upstream_read_timeout_s > 300 {
            return Err("Upstream timeout must be in 1..=300 seconds".into());
        }

        let upstream_base_url = if let Ok(env_url) = std::env::var("HERMETIC_UPSTREAM_URL") {
            let env_url = env_url.trim().to_string();
            if !env_url.is_empty() {
                env_url
            } else {
                parsed.upstream_base_url
            }
        } else {
            parsed.upstream_base_url
        };

        let mut pinned_models = parsed.pinned_models;
        if let Ok(env_model) = std::env::var("HERMETIC_UPSTREAM_MODEL") {
            let env_model = env_model.trim().to_string();
            if !env_model.is_empty() && !pinned_models.contains(&env_model) {
                pinned_models.push(env_model);
            }
        }

        let api_key_file = if let Ok(env_key) = std::env::var("HERMETIC_UPSTREAM_KEY_FILE") {
            let env_key = env_key.trim();
            if !env_key.is_empty() {
                PathBuf::from(env_key)
            } else {
                parsed.api_key_file
            }
        } else {
            parsed.api_key_file
        };

        let upstream_protocol = match parsed.upstream_protocol {
            Some(proto) => proto,
            None => {
                if upstream_base_url.contains("/v1")
                    || upstream_base_url.contains("nvidia")
                    || upstream_base_url.contains("openai")
                {
                    UpstreamProtocol::OpenaiChat
                } else {
                    UpstreamProtocol::Anthropic
                }
            }
        };

        if upstream_protocol == UpstreamProtocol::OpenaiChat {
            crate::openai::validate_base_url(&upstream_base_url)?;
        }
        // The key is opened once through pinned directory descriptors, mode 0600 only.
        let raw_key = crate::fsutil::read_secret_file_capped(
            &api_key_file,
            crate::fsutil::MAX_API_KEY_FILE_BYTES,
        )
        .map_err(|e| {
            format!(
                "Failed to read API key file {}: {e}",
                api_key_file.display()
            )
        })?;
        let api_key = String::from_utf8(raw_key)
            .map_err(|_| format!("API key file {} is not UTF-8", api_key_file.display()))?
            .trim()
            .to_string();

        if api_key.is_empty() {
            return Err(format!("API key file {} is empty", api_key_file.display()));
        }
        if !api_key.bytes().all(|byte| (33..=126).contains(&byte)) {
            return Err("API key contains invalid header bytes".into());
        }

        Ok(Self {
            upstream_protocol,
            upstream_base_url,
            anthropic_version: parsed.anthropic_version,
            allowed_betas: parsed.allowed_betas,
            pinned_models,
            quotas: parsed.quotas,
            log_dir: parsed.log_dir,
            api_key_file,
            upstream_read_timeout_s: parsed.upstream_read_timeout_s,
            date_sentinel: parsed.date_sentinel,
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
            upstream_protocol: UpstreamProtocol::Anthropic,
            upstream_base_url,
            anthropic_version,
            allowed_betas,
            pinned_models,
            quotas,
            log_dir,
            api_key_file,
            upstream_read_timeout_s: 120,
            date_sentinel: DateSentinelConfig::default(),
            api_key,
        }
    }

    pub fn with_upstream_read_timeout_s(mut self, timeout_s: u64) -> Self {
        self.upstream_read_timeout_s = timeout_s;
        self
    }

    pub fn with_date_sentinel(mut self, cfg: DateSentinelConfig) -> Self {
        self.date_sentinel = cfg;
        self
    }

    pub fn with_upstream_protocol(mut self, protocol: UpstreamProtocol) -> Self {
        self.upstream_protocol = protocol;
        self
    }

    /// Access the API key in memory only.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}
