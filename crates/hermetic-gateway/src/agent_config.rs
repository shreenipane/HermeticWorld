#![forbid(unsafe_code)]

//! Mode G guest agent configuration (TR-GW-9).
//!
//! Generates and validates the locked-down configuration for guest agents running
//! inside AgentVM under Mode G, ensuring:
//! - Base URL is redirected to the gateway.
//! - Network-bound domain preflight verification is disabled.
//! - Fast mode is disabled.
//! - Automatic updates and telemetry/diagnostics are completely disabled.
//! - WebFetch remains enabled (reaching the sealed guest network).
//! - WebSearch is disabled (provider-hosted tool rejected by gateway).
//! - Written safely to the guest overlay or toolchain volume by the host harness
//!   before guest execution (never by the untrusted guest agent).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Maximum byte length of the gateway base URL.
pub const MAX_GATEWAY_URL_BYTES: usize = 2048;

/// Maximum byte length of the generated configuration JSON.
pub const MAX_CONFIG_JSON_BYTES: usize = 64 * 1024;

/// Maximum number of path components when traversing directories.
pub const MAX_PATH_COMPONENTS: usize = 256;

/// Standard relative path for system-wide managed configuration.
pub const MANAGED_SETTINGS_REL_PATH: &str = "etc/claude-code/managed-settings.json";

/// Standard relative path for root user configuration.
pub const ROOT_SETTINGS_REL_PATH: &str = "root/.claude/settings.json";

/// Standard relative path within the toolchain volume.
pub const TOOLCHAIN_SETTINGS_REL_PATH: &str = "settings.json";

/// Typed error returned during configuration validation and filesystem deployment.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AgentConfigError {
    #[error("gateway URL is empty")]
    EmptyGatewayUrl,
    #[error("gateway URL exceeds byte limit: {0} > {1}")]
    OversizedGatewayUrl(usize, usize),
    #[error("invalid gateway URL scheme: must start with http:// or https://")]
    InvalidGatewayUrlScheme,
    #[error("gateway URL must point to local gateway, not external endpoint")]
    ExternalEndpointForbidden,
    #[error("skipWebFetchPreflight must be true")]
    PreflightNotSkipped,
    #[error("fast mode must be false (disabled)")]
    FastModeEnabled,
    #[error("auto-update must be false (disabled)")]
    AutoUpdateEnabled,
    #[error("telemetry must be false (disabled)")]
    TelemetryEnabled,
    #[error("WebFetch must remain enabled")]
    WebFetchDisabled,
    #[error("WebSearch must remain disabled")]
    WebSearchEnabled,
    #[error("environment variable missing or incorrect: {key}={expected}")]
    EnvironmentMismatch {
        key: &'static str,
        expected: &'static str,
    },
    #[error("target path contains symlinks or special files: {0}")]
    UnsafePath(String),
    #[error("JSON serialization error: {0}")]
    Serialization(String),
    #[error("filesystem I/O error: {0}")]
    Io(String),
}

impl From<io::Error> for AgentConfigError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Permissions allow/deny lists in the agent settings structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsPayload {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// JSON schema payload for agent settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPayload {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(rename = "skipWebFetchPreflight")]
    pub skip_web_fetch_preflight: bool,
    #[serde(rename = "fastMode")]
    pub fast_mode: bool,
    #[serde(rename = "autoUpdate")]
    pub auto_update: bool,
    #[serde(rename = "autoUpdatesChannel")]
    pub auto_updates_channel: String,
    pub telemetry: bool,
    pub env: BTreeMap<String, String>,
    pub permissions: PermissionsPayload,
}

/// High-level typed specification for Mode G agent configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub anthropic_base_url: String,
    pub skip_web_fetch_preflight: bool,
    pub fast_mode: bool,
    pub auto_update: bool,
    pub telemetry: bool,
    pub web_fetch: bool,
    pub web_search: bool,
}

fn validate_gateway_url(url: &str) -> Result<(), AgentConfigError> {
    if url.is_empty() {
        return Err(AgentConfigError::EmptyGatewayUrl);
    }
    if url.len() > MAX_GATEWAY_URL_BYTES {
        return Err(AgentConfigError::OversizedGatewayUrl(
            url.len(),
            MAX_GATEWAY_URL_BYTES,
        ));
    }
    let rest = if let Some(stripped) = url.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = url.strip_prefix("https://") {
        stripped
    } else {
        return Err(AgentConfigError::InvalidGatewayUrlScheme);
    };

    let authority = match rest.find(['/', '?', '#']) {
        Some(idx) => &rest[..idx],
        None => rest,
    };

    if authority.is_empty() || authority.contains('@') {
        return Err(AgentConfigError::ExternalEndpointForbidden);
    }

    let (host, port_str) = if authority.starts_with('[') {
        let end_bracket = authority
            .find(']')
            .ok_or(AgentConfigError::ExternalEndpointForbidden)?;
        let host = &authority[1..end_bracket];
        let rest_after_bracket = &authority[end_bracket + 1..];
        let port = if let Some(p) = rest_after_bracket.strip_prefix(':') {
            Some(p)
        } else if rest_after_bracket.is_empty() {
            None
        } else {
            return Err(AgentConfigError::ExternalEndpointForbidden);
        };
        (host, port)
    } else {
        match authority.rfind(':') {
            Some(colon_idx) => (&authority[..colon_idx], Some(&authority[colon_idx + 1..])),
            None => (authority, None),
        }
    };

    if host.is_empty() {
        return Err(AgentConfigError::ExternalEndpointForbidden);
    }

    if let Some(port) = port_str {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().map_or(true, |p| p == 0)
        {
            return Err(AgentConfigError::ExternalEndpointForbidden);
        }
    }

    let is_permitted_host = if host.eq_ignore_ascii_case("localhost") {
        true
    } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_loopback() || ipv4 == std::net::Ipv4Addr::new(10, 0, 2, 2)
            }
            std::net::IpAddr::V6(ipv6) => ipv6.is_loopback(),
        }
    } else {
        false
    };

    if !is_permitted_host {
        return Err(AgentConfigError::ExternalEndpointForbidden);
    }

    Ok(())
}

impl AgentConfig {
    /// Constructs the canonical Mode G configuration with the specified gateway URL.
    pub fn mode_g(gateway_url: impl Into<String>) -> Result<Self, AgentConfigError> {
        let config = Self {
            anthropic_base_url: gateway_url.into(),
            skip_web_fetch_preflight: true,
            fast_mode: false,
            auto_update: false,
            telemetry: false,
            web_fetch: true,
            web_search: false,
        };
        config.validate()?;
        Ok(config)
    }

    /// Strictly validates that every requirement of TR-GW-9 is satisfied.
    pub fn validate(&self) -> Result<(), AgentConfigError> {
        validate_gateway_url(&self.anthropic_base_url)?;
        if !self.skip_web_fetch_preflight {
            return Err(AgentConfigError::PreflightNotSkipped);
        }
        if self.fast_mode {
            return Err(AgentConfigError::FastModeEnabled);
        }
        if self.auto_update {
            return Err(AgentConfigError::AutoUpdateEnabled);
        }
        if self.telemetry {
            return Err(AgentConfigError::TelemetryEnabled);
        }
        if !self.web_fetch {
            return Err(AgentConfigError::WebFetchDisabled);
        }
        if self.web_search {
            return Err(AgentConfigError::WebSearchEnabled);
        }
        Ok(())
    }

    /// Returns the exact required environment variables for the guest agent run spec.
    pub fn env_vars(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(
            "ANTHROPIC_BASE_URL".to_string(),
            self.anthropic_base_url.clone(),
        );
        map.insert("DISABLE_AUTOUPDATER".to_string(), "1".to_string());
        map.insert("DISABLE_TELEMETRY".to_string(), "1".to_string());
        map.insert("DISABLE_ERROR_REPORTING".to_string(), "1".to_string());
        map.insert(
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_string(),
            "1".to_string(),
        );
        map
    }

    /// Constructs the canonical typed settings payload.
    pub fn to_settings_payload(&self) -> Result<SettingsPayload, AgentConfigError> {
        self.validate()?;
        Ok(SettingsPayload {
            schema: Some("https://json.schemastore.org/claude-code-settings.json".to_string()),
            skip_web_fetch_preflight: self.skip_web_fetch_preflight,
            fast_mode: self.fast_mode,
            auto_update: self.auto_update,
            auto_updates_channel: "disabled".to_string(),
            telemetry: self.telemetry,
            env: self.env_vars(),
            permissions: PermissionsPayload {
                allow: vec!["WebFetch".to_string()],
                deny: vec!["WebSearch".to_string()],
            },
        })
    }

    /// Serializes the settings to canonical formatted JSON string.
    pub fn to_settings_json(&self) -> Result<String, AgentConfigError> {
        let payload = self.to_settings_payload()?;
        let json_str = serde_json::to_string_pretty(&payload)
            .map_err(|e| AgentConfigError::Serialization(e.to_string()))?;
        if json_str.len() > MAX_CONFIG_JSON_BYTES {
            return Err(AgentConfigError::Serialization(
                "serialized config exceeds size limit".to_string(),
            ));
        }
        Ok(json_str)
    }

    /// Parses and validates a settings JSON payload string.
    pub fn from_settings_json(json_str: &str) -> Result<Self, AgentConfigError> {
        if json_str.len() > MAX_CONFIG_JSON_BYTES {
            return Err(AgentConfigError::Serialization(
                "config JSON exceeds size limit".to_string(),
            ));
        }
        let payload: SettingsPayload = serde_json::from_str(json_str)
            .map_err(|e| AgentConfigError::Serialization(e.to_string()))?;

        let url = payload
            .env
            .get("ANTHROPIC_BASE_URL")
            .cloned()
            .unwrap_or_default();
        if url.is_empty() {
            return Err(AgentConfigError::EmptyGatewayUrl);
        }
        if payload.env.get("DISABLE_AUTOUPDATER") != Some(&"1".to_string()) {
            return Err(AgentConfigError::EnvironmentMismatch {
                key: "DISABLE_AUTOUPDATER",
                expected: "1",
            });
        }
        if payload.env.get("DISABLE_TELEMETRY") != Some(&"1".to_string()) {
            return Err(AgentConfigError::EnvironmentMismatch {
                key: "DISABLE_TELEMETRY",
                expected: "1",
            });
        }
        if payload.env.get("DISABLE_ERROR_REPORTING") != Some(&"1".to_string()) {
            return Err(AgentConfigError::EnvironmentMismatch {
                key: "DISABLE_ERROR_REPORTING",
                expected: "1",
            });
        }
        if payload.env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC") != Some(&"1".to_string()) {
            return Err(AgentConfigError::EnvironmentMismatch {
                key: "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                expected: "1",
            });
        }
        if payload.permissions.deny.iter().any(|p| p == "WebFetch") {
            return Err(AgentConfigError::WebFetchDisabled);
        }
        let web_fetch = payload.permissions.allow.iter().any(|p| p == "WebFetch");
        let web_search = payload.permissions.deny.iter().any(|p| p == "WebSearch");

        let config = Self {
            anthropic_base_url: url,
            skip_web_fetch_preflight: payload.skip_web_fetch_preflight,
            fast_mode: payload.fast_mode,
            auto_update: payload.auto_update,
            telemetry: payload.telemetry,
            web_fetch,
            web_search: !web_search,
        };
        config.validate()?;
        Ok(config)
    }

    /// Deploys the configuration into the guest overlay filesystem tree.
    ///
    /// Writes:
    /// - `<overlay_upper_dir>/etc/claude-code/managed-settings.json`
    /// - `<overlay_upper_dir>/root/.claude/settings.json`
    ///
    /// Component-by-component traversal refuses symlinks and special files.
    /// Missing directories are created with mode 0700; files are written with mode 0600.
    pub fn write_to_overlay(&self, overlay_upper_dir: &Path) -> Result<(), AgentConfigError> {
        let json_bytes = self.to_settings_json()?.into_bytes();
        write_file_no_follow(
            overlay_upper_dir,
            Path::new(MANAGED_SETTINGS_REL_PATH),
            &json_bytes,
        )?;
        write_file_no_follow(
            overlay_upper_dir,
            Path::new(ROOT_SETTINGS_REL_PATH),
            &json_bytes,
        )?;
        Ok(())
    }

    /// Deploys the configuration into the `/opt/agent` toolchain volume tree.
    ///
    /// Writes:
    /// - `<volume_dir>/settings.json`
    /// - `<volume_dir>/managed-settings.json`
    ///
    /// Component-by-component traversal refuses symlinks and special files.
    /// Missing directories are created with mode 0700; files are written with mode 0600.
    pub fn write_to_agent_volume(&self, volume_dir: &Path) -> Result<(), AgentConfigError> {
        let json_bytes = self.to_settings_json()?.into_bytes();
        write_file_no_follow(
            volume_dir,
            Path::new(TOOLCHAIN_SETTINGS_REL_PATH),
            &json_bytes,
        )?;
        write_file_no_follow(volume_dir, Path::new("managed-settings.json"), &json_bytes)?;
        Ok(())
    }
}

/// Safely writes `bytes` to `<base_dir>/<rel_path>` without following symlinks.
///
/// Missing intermediate directories are created with mode 0700.
/// The leaf file is created atomically with mode 0600.
fn write_file_no_follow(
    base_dir: &Path,
    rel_path: &Path,
    bytes: &[u8],
) -> Result<PathBuf, AgentConfigError> {
    if rel_path.is_absolute() {
        return Err(AgentConfigError::UnsafePath(
            "relative path required".to_string(),
        ));
    }

    let mut parts: Vec<_> = rel_path.components().collect();
    if parts.is_empty() || parts.len() > MAX_PATH_COMPONENTS {
        return Err(AgentConfigError::UnsafePath(
            "invalid path depth".to_string(),
        ));
    }

    let filename = match parts.pop() {
        Some(Component::Normal(f)) => f
            .to_str()
            .ok_or_else(|| AgentConfigError::UnsafePath("non-UTF8 filename".to_string()))?,
        _ => {
            return Err(AgentConfigError::UnsafePath(
                "missing leaf filename".to_string(),
            ))
        }
    };

    // Construct intermediate directory path
    let mut dir_path = base_dir.to_path_buf();
    for part in parts {
        match part {
            Component::Normal(name) => dir_path.push(name),
            Component::CurDir => continue,
            _ => {
                return Err(AgentConfigError::UnsafePath(
                    "path contains parent reference".to_string(),
                ))
            }
        }
    }

    // Open/create intermediate directory with 0700, strictly verifying no symlinks
    let dir_file = crate::fsutil::open_dir_nofollow_create(&dir_path)
        .map_err(|e| AgentConfigError::Io(e.to_string()))?;

    // Write file atomically with mode 0600
    crate::fsutil::write_state_file(&dir_file, filename, bytes)
        .map_err(|e| AgentConfigError::Io(e.to_string()))?;

    Ok(dir_path.join(filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_valid_mode_g_config_matches_contract() {
        let config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        assert_eq!(config.anthropic_base_url, "http://127.0.0.1:5002");
        assert!(config.skip_web_fetch_preflight);
        assert!(!config.fast_mode);
        assert!(!config.auto_update);
        assert!(!config.telemetry);
        assert!(config.web_fetch);
        assert!(!config.web_search);

        let env = config.env_vars();
        assert_eq!(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:5002");
        assert_eq!(env["DISABLE_AUTOUPDATER"], "1");
        assert_eq!(env["DISABLE_TELEMETRY"], "1");
        assert_eq!(env["DISABLE_ERROR_REPORTING"], "1");
        assert_eq!(env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1");

        let json_str = config.to_settings_json().unwrap();
        assert!(json_str.contains("\"skipWebFetchPreflight\": true"));
        assert!(json_str.contains("\"fastMode\": false"));
        assert!(json_str.contains("\"autoUpdate\": false"));
        assert!(json_str.contains("\"telemetry\": false"));
        assert!(json_str.contains("\"allow\": [\n      \"WebFetch\"\n    ]"));
        assert!(json_str.contains("\"deny\": [\n      \"WebSearch\"\n    ]"));

        // Round-trip parse
        let parsed = AgentConfig::from_settings_json(&json_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_empty_gateway_url_rejected() {
        let err = AgentConfig::mode_g("").unwrap_err();
        assert_eq!(err, AgentConfigError::EmptyGatewayUrl);
    }

    #[test]
    fn test_invalid_scheme_rejected() {
        let err = AgentConfig::mode_g("ftp://127.0.0.1:5002").unwrap_err();
        assert_eq!(err, AgentConfigError::InvalidGatewayUrlScheme);
    }

    #[test]
    fn test_external_endpoint_rejected() {
        let err = AgentConfig::mode_g("https://api.anthropic.com").unwrap_err();
        assert_eq!(err, AgentConfigError::ExternalEndpointForbidden);
    }

    #[test]
    fn test_preflight_not_skipped_rejected() {
        let mut config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.skip_web_fetch_preflight = false;
        assert_eq!(
            config.validate().unwrap_err(),
            AgentConfigError::PreflightNotSkipped
        );
    }

    #[test]
    fn test_fast_mode_enabled_rejected() {
        let mut config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.fast_mode = true;
        assert_eq!(
            config.validate().unwrap_err(),
            AgentConfigError::FastModeEnabled
        );
    }

    #[test]
    fn test_auto_update_enabled_rejected() {
        let mut config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.auto_update = true;
        assert_eq!(
            config.validate().unwrap_err(),
            AgentConfigError::AutoUpdateEnabled
        );
    }

    #[test]
    fn test_telemetry_enabled_rejected() {
        let mut config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.telemetry = true;
        assert_eq!(
            config.validate().unwrap_err(),
            AgentConfigError::TelemetryEnabled
        );
    }

    #[test]
    fn test_web_fetch_disabled_rejected() {
        let mut config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.web_fetch = false;
        assert_eq!(
            config.validate().unwrap_err(),
            AgentConfigError::WebFetchDisabled
        );
    }

    #[test]
    fn test_web_search_enabled_rejected() {
        let mut config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.web_search = true;
        assert_eq!(
            config.validate().unwrap_err(),
            AgentConfigError::WebSearchEnabled
        );
    }

    #[test]
    fn test_write_to_overlay_creates_strict_files_and_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let overlay_upper = temp.path().join("upper");
        std::fs::create_dir_all(&overlay_upper).unwrap();

        let config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.write_to_overlay(&overlay_upper).unwrap();

        let managed_path = overlay_upper.join(MANAGED_SETTINGS_REL_PATH);
        let root_path = overlay_upper.join(ROOT_SETTINGS_REL_PATH);

        assert!(managed_path.is_file());
        assert!(root_path.is_file());

        // Verify mode 0600 on files
        assert_eq!(
            managed_path.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            root_path.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Verify mode 0700 on created directories
        let managed_dir = managed_path.parent().unwrap();
        let root_dir = root_path.parent().unwrap();
        assert_eq!(
            managed_dir.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            root_dir.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );

        // Verify content matches
        let content = std::fs::read_to_string(&managed_path).unwrap();
        let read_config = AgentConfig::from_settings_json(&content).unwrap();
        assert_eq!(config, read_config);
    }

    #[test]
    fn test_write_to_agent_volume_creates_strict_files_and_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let volume_dir = temp.path().join("opt_agent");
        std::fs::create_dir_all(&volume_dir).unwrap();

        let config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        config.write_to_agent_volume(&volume_dir).unwrap();

        let settings_path = volume_dir.join(TOOLCHAIN_SETTINGS_REL_PATH);
        let managed_path = volume_dir.join("managed-settings.json");

        assert!(settings_path.is_file());
        assert!(managed_path.is_file());

        assert_eq!(
            settings_path.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            managed_path.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let read_config = AgentConfig::from_settings_json(&content).unwrap();
        assert_eq!(config, read_config);
    }

    #[test]
    fn test_write_refuses_symlinked_components() {
        let temp = tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let overlay_upper = temp.path().join("upper");
        std::fs::create_dir_all(&overlay_upper).unwrap();

        // Create symlink etc -> outside
        std::os::unix::fs::symlink(&outside, overlay_upper.join("etc")).unwrap();

        let config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        let err = config.write_to_overlay(&overlay_upper);
        assert!(err.is_err());
    }

    #[test]
    fn test_external_and_malformed_gateway_urls_rejected() {
        assert_eq!(
            AgentConfig::mode_g("https://example.org").unwrap_err(),
            AgentConfigError::ExternalEndpointForbidden
        );
        assert_eq!(
            AgentConfig::mode_g("http://").unwrap_err(),
            AgentConfigError::ExternalEndpointForbidden
        );
        assert_eq!(
            AgentConfig::mode_g("http://127.0.0.1:0").unwrap_err(),
            AgentConfigError::ExternalEndpointForbidden
        );
        assert_eq!(
            AgentConfig::mode_g("http://user:pass@127.0.0.1:5002").unwrap_err(),
            AgentConfigError::ExternalEndpointForbidden
        );
        assert!(AgentConfig::mode_g("http://localhost:5002").is_ok());
        assert!(AgentConfig::mode_g("http://10.0.2.2:5002").is_ok());
    }

    #[test]
    fn test_settings_json_conflicting_web_fetch_deny_rejected() {
        let config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        let json_str = config.to_settings_json().unwrap();
        let mut val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        val["permissions"]["deny"] = serde_json::json!(["WebSearch", "WebFetch"]);
        let bad_json = serde_json::to_string(&val).unwrap();
        assert_eq!(
            AgentConfig::from_settings_json(&bad_json).unwrap_err(),
            AgentConfigError::WebFetchDisabled
        );
    }

    #[test]
    fn test_settings_json_missing_traffic_suppression_env_rejected() {
        let config = AgentConfig::mode_g("http://127.0.0.1:5002").unwrap();
        let json_str = config.to_settings_json().unwrap();

        let mut val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        val["env"]
            .as_object_mut()
            .unwrap()
            .remove("DISABLE_ERROR_REPORTING");
        let bad_json1 = serde_json::to_string(&val).unwrap();
        assert_eq!(
            AgentConfig::from_settings_json(&bad_json1).unwrap_err(),
            AgentConfigError::EnvironmentMismatch {
                key: "DISABLE_ERROR_REPORTING",
                expected: "1",
            }
        );

        let mut val2: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        val2["env"]
            .as_object_mut()
            .unwrap()
            .remove("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC");
        let bad_json2 = serde_json::to_string(&val2).unwrap();
        assert_eq!(
            AgentConfig::from_settings_json(&bad_json2).unwrap_err(),
            AgentConfigError::EnvironmentMismatch {
                key: "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                expected: "1",
            }
        );
    }
}
