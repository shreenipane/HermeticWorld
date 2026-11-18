#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::symlink;

use hermetic_escapeprobe::config::{
    parse_config, read_config_file, ConfigError, EscapeConfig, MAX_CONFIG_BYTES,
};

#[test]
fn test_parse_valid_config() {
    let json = serde_json::json!({
        "gateway": {
            "base_url": "http://10.0.2.2:5002",
            "pinned_model": "test-model-pinned",
            "api_version": "2023-06-01",
            "allowed_beta": "prompt-caching-2024-07-31",
            "sentinel": {
                "real_date": "2024-10-22",
                "tolerance_days": 1,
                "host_names": ["host-1.local"],
                "host_paths": ["/home/user/hermetic"]
            }
        },
        "install": {
            "pip_target": "http://10.9.0.1/wheel.whl",
            "git_target": "http://10.9.0.1/repo.git",
            "curl_url": "http://10.9.0.1/hello.txt"
        },
        "sentinel_output": "/work/probe_sentinel.json"
    });

    let bytes = serde_json::to_vec(&json).unwrap();
    let cfg = parse_config(&bytes).expect("valid config parses");

    assert_eq!(
        cfg.gateway.as_ref().unwrap().base_url,
        "http://10.0.2.2:5002"
    );
    assert_eq!(
        cfg.gateway.as_ref().unwrap().pinned_model,
        "test-model-pinned"
    );
    assert_eq!(
        cfg.install.as_ref().unwrap().curl_url.as_deref(),
        Some("http://10.9.0.1/hello.txt")
    );
    assert_eq!(
        cfg.sentinel_output.as_deref(),
        Some("/work/probe_sentinel.json")
    );

    let sent = cfg.gateway.as_ref().unwrap().sentinel.as_ref().unwrap();
    assert_eq!(sent.real_date, "2024-10-22");
    assert_eq!(sent.tolerance_days, 1);
    assert_eq!(sent.host_names, vec!["host-1.local"]);
    assert_eq!(sent.host_paths, vec!["/home/user/hermetic"]);
    assert!(sent.parse_date().is_ok());
}

#[test]
fn test_parse_empty_config_defaults() {
    let json = serde_json::json!({});
    let bytes = serde_json::to_vec(&json).unwrap();
    let cfg = parse_config(&bytes).expect("empty config parses");
    assert_eq!(cfg, EscapeConfig::default());
    assert!(cfg.gateway.is_none());
    assert!(cfg.install.is_none());
}

#[test]
fn test_deny_unknown_fields() {
    let json = serde_json::json!({
        "unknown_extra_field": 123
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    assert!(matches!(parse_config(&bytes), Err(ConfigError::Json(_))));
}

#[test]
fn test_invalid_sentinel_date() {
    let json = serde_json::json!({
        "gateway": {
            "base_url": "http://10.0.2.2:5002",
            "pinned_model": "test-model",
            "sentinel": {
                "real_date": "not-a-date"
            }
        }
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    assert!(matches!(
        parse_config(&bytes),
        Err(ConfigError::InvalidDate(_))
    ));
}

#[test]
fn test_read_config_file_refuses_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let real_file = tmp.path().join("real_config.json");
    fs::write(&real_file, b"{}").unwrap();

    let sym_file = tmp.path().join("sym_config.json");
    symlink(&real_file, &sym_file).unwrap();

    assert_eq!(
        read_config_file(&sym_file),
        Err(ConfigError::SymlinkOrSpecialFile)
    );
    assert_eq!(read_config_file(&real_file), Ok(b"{}".to_vec()));
}

#[test]
fn test_read_config_file_refuses_oversized() {
    let tmp = tempfile::tempdir().unwrap();
    let big_file = tmp.path().join("big_config.json");
    let content = vec![b' '; (MAX_CONFIG_BYTES + 10) as usize];
    fs::write(&big_file, &content).unwrap();

    assert_eq!(read_config_file(&big_file), Err(ConfigError::Oversized));
}

#[test]
fn test_load_config_missing_file_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let non_existent = tmp.path().join("missing.json");
    assert_eq!(read_config_file(&non_existent), Err(ConfigError::NotFound));
}
