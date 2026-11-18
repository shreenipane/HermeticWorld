#![forbid(unsafe_code)]

//! Escape probe configuration (TR-SEC-6).
//!
//! Loads gateway abuse probe settings, real-date sentinel criteria, and
//! install positive check targets. Strict, bounded, fail-closed parsing.
//! Never follows symlinks.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/hermetic/escape-probe.json";
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub const MAX_SENTINEL_ITEMS: usize = 256;
pub const MAX_SENTINEL_STRING_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NotFound,
    SymlinkOrSpecialFile,
    NotRegularFile,
    Oversized,
    Io(String),
    Json(String),
    InvalidDate(String),
    CapExceeded(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "config file not found"),
            Self::SymlinkOrSpecialFile => write!(f, "symlink or special file refused"),
            Self::NotRegularFile => write!(f, "not a regular file"),
            Self::Oversized => write!(f, "config file exceeds byte cap"),
            Self::Io(e) => write!(f, "i/o error reading config: {e}"),
            Self::Json(e) => write!(f, "malformed config JSON: {e}"),
            Self::InvalidDate(d) => write!(f, "invalid sentinel date format: {d}"),
            Self::CapExceeded(reason) => write!(f, "config cap exceeded: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EscapeConfig {
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
    #[serde(default)]
    pub install: Option<InstallConfig>,
    #[serde(default)]
    pub sentinel_output: Option<String>,
}

impl EscapeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(ref g) = self.gateway {
            g.validate()?;
        }
        if let Some(ref i) = self.install {
            i.validate()?;
        }
        if let Some(ref s) = self.sentinel_output {
            if s.len() > MAX_SENTINEL_STRING_BYTES {
                return Err(ConfigError::CapExceeded("sentinel_output path too long"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub base_url: String,
    pub pinned_model: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default)]
    pub allowed_beta: Option<String>,
    #[serde(default)]
    pub sentinel: Option<SentinelConfig>,
}

fn default_api_version() -> String {
    "2023-06-01".to_string()
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.base_url.len() > MAX_SENTINEL_STRING_BYTES {
            return Err(ConfigError::CapExceeded("base_url too long"));
        }
        if self.pinned_model.len() > MAX_SENTINEL_STRING_BYTES {
            return Err(ConfigError::CapExceeded("pinned_model too long"));
        }
        if let Some(ref s) = self.sentinel {
            s.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SentinelConfig {
    pub real_date: String,
    #[serde(default = "default_tolerance_days")]
    pub tolerance_days: u32,
    #[serde(default)]
    pub host_names: Vec<String>,
    #[serde(default)]
    pub host_paths: Vec<String>,
}

fn default_tolerance_days() -> u32 {
    1
}

impl SentinelConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.host_names.len() > MAX_SENTINEL_ITEMS {
            return Err(ConfigError::CapExceeded("too many host_names"));
        }
        if self.host_paths.len() > MAX_SENTINEL_ITEMS {
            return Err(ConfigError::CapExceeded("too many host_paths"));
        }
        for name in &self.host_names {
            if name.len() > MAX_SENTINEL_STRING_BYTES {
                return Err(ConfigError::CapExceeded("host_name too long"));
            }
        }
        for path in &self.host_paths {
            if path.len() > MAX_SENTINEL_STRING_BYTES {
                return Err(ConfigError::CapExceeded("host_path too long"));
            }
        }
        self.parse_date().map(|_| ())
    }

    pub fn parse_date(&self) -> Result<time::Date, ConfigError> {
        let parts: Vec<&str> = self.real_date.split('-').collect();
        if parts.len() != 3 {
            return Err(ConfigError::InvalidDate(self.real_date.clone()));
        }
        let year: i32 = parts[0]
            .parse()
            .map_err(|_| ConfigError::InvalidDate(self.real_date.clone()))?;
        let month_num: u8 = parts[1]
            .parse()
            .map_err(|_| ConfigError::InvalidDate(self.real_date.clone()))?;
        let day: u8 = parts[2]
            .parse()
            .map_err(|_| ConfigError::InvalidDate(self.real_date.clone()))?;
        let month = time::Month::try_from(month_num)
            .map_err(|_| ConfigError::InvalidDate(self.real_date.clone()))?;
        time::Date::from_calendar_date(year, month, day)
            .map_err(|_| ConfigError::InvalidDate(self.real_date.clone()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallConfig {
    #[serde(default)]
    pub pip_target: Option<String>,
    #[serde(default)]
    pub pip_command: Option<Vec<String>>,
    #[serde(default)]
    pub git_target: Option<String>,
    #[serde(default)]
    pub git_command: Option<Vec<String>>,
    #[serde(default)]
    pub curl_url: Option<String>,
    #[serde(default)]
    pub curl_command: Option<Vec<String>>,
}

impl InstallConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(ref p) = self.pip_target {
            if p.len() > MAX_SENTINEL_STRING_BYTES {
                return Err(ConfigError::CapExceeded("pip_target too long"));
            }
        }
        if let Some(ref pc) = self.pip_command {
            if pc.len() > MAX_SENTINEL_ITEMS {
                return Err(ConfigError::CapExceeded("too many pip_command arguments"));
            }
            for arg in pc {
                if arg.len() > MAX_SENTINEL_STRING_BYTES {
                    return Err(ConfigError::CapExceeded("pip_command argument too long"));
                }
            }
        }
        if let Some(ref g) = self.git_target {
            if g.len() > MAX_SENTINEL_STRING_BYTES {
                return Err(ConfigError::CapExceeded("git_target too long"));
            }
        }
        if let Some(ref gc) = self.git_command {
            if gc.len() > MAX_SENTINEL_ITEMS {
                return Err(ConfigError::CapExceeded("too many git_command arguments"));
            }
            for arg in gc {
                if arg.len() > MAX_SENTINEL_STRING_BYTES {
                    return Err(ConfigError::CapExceeded("git_command argument too long"));
                }
            }
        }
        if let Some(ref c) = self.curl_url {
            if c.len() > MAX_SENTINEL_STRING_BYTES {
                return Err(ConfigError::CapExceeded("curl_url too long"));
            }
        }
        if let Some(ref cc) = self.curl_command {
            if cc.len() > MAX_SENTINEL_ITEMS {
                return Err(ConfigError::CapExceeded("too many curl_command arguments"));
            }
            for arg in cc {
                if arg.len() > MAX_SENTINEL_STRING_BYTES {
                    return Err(ConfigError::CapExceeded("curl_command argument too long"));
                }
            }
        }
        Ok(())
    }
}

/// Safely reads file contents strictly without following symlinks.
pub fn read_config_file(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let sym_check = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ConfigError::NotFound
        } else {
            ConfigError::Io(e.to_string())
        }
    })?;
    if sym_check.file_type().is_symlink() {
        return Err(ConfigError::SymlinkOrSpecialFile);
    }
    if !sym_check.file_type().is_file() {
        return Err(ConfigError::NotRegularFile);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                ConfigError::SymlinkOrSpecialFile
            } else if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::NotFound
            } else {
                ConfigError::Io(e.to_string())
            }
        })?;

    let meta = file
        .metadata()
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(ConfigError::NotRegularFile);
    }

    let mut out = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| ConfigError::Io(e.to_string()))?;

    if out.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::Oversized);
    }

    Ok(out)
}

/// Parse configuration from byte slice.
pub fn parse_config(bytes: &[u8]) -> Result<EscapeConfig, ConfigError> {
    let cfg: EscapeConfig =
        serde_json::from_slice(bytes).map_err(|e| ConfigError::Json(e.to_string()))?;
    cfg.validate()?;
    Ok(cfg)
}

/// Discover and load configuration from explicit path, environment variable,
/// or default configuration path. Returns `Ok(None)` if no config is present.
pub fn load_config(path: Option<&Path>) -> Result<Option<EscapeConfig>, ConfigError> {
    if let Some(p) = path {
        let bytes = read_config_file(p)?;
        return Ok(Some(parse_config(&bytes)?));
    }

    if let Ok(env_path) = std::env::var("HERMETIC_ESCAPE_CONFIG") {
        if !env_path.is_empty() {
            let p = PathBuf::from(env_path);
            let bytes = read_config_file(&p)?;
            return Ok(Some(parse_config(&bytes)?));
        }
    }

    let default_path = Path::new(DEFAULT_CONFIG_PATH);
    match read_config_file(default_path) {
        Ok(bytes) => Ok(Some(parse_config(&bytes)?)),
        Err(ConfigError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}
