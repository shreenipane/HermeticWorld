#![forbid(unsafe_code)]

use hermetic_gateway::{config::GatewayConfig, openai};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn runtime_configurable_upstream_url_and_model_and_key() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HERMETIC_UPSTREAM_URL");
    std::env::remove_var("HERMETIC_UPSTREAM_MODEL");
    std::env::remove_var("HERMETIC_UPSTREAM_KEY_FILE");

    let custom_url = "https://custom-openai-compatible.example.com/v1";
    std::env::set_var("HERMETIC_UPSTREAM_URL", custom_url);
    assert!(openai::validate_base_url(custom_url).is_ok());
    assert!(openai::validate_base_url(&format!("{custom_url}/")).is_ok());

    // Still rejects credentials, query parameters, fragments, or mismatched host
    assert!(
        openai::validate_base_url("https://user:pass@custom-openai-compatible.example.com/v1")
            .is_err()
    );
    assert!(openai::validate_base_url("https://other-domain.example.com/v1").is_err());

    let dir = tempfile::tempdir().unwrap();
    let default_key = dir.path().join("default.key");
    std::fs::write(&default_key, "default-key-secret-12345").unwrap();
    std::fs::set_permissions(&default_key, std::fs::Permissions::from_mode(0o600)).unwrap();

    let runtime_key = dir.path().join("runtime.key");
    std::fs::write(&runtime_key, "runtime-key-secret-67890").unwrap();
    std::fs::set_permissions(&runtime_key, std::fs::Permissions::from_mode(0o600)).unwrap();

    let config_path = dir.path().join("gateway.json");
    std::fs::write(
        &config_path,
        json!({
            "upstream_protocol": "openai_chat",
            "upstream_base_url": "https://integrate.api.nvidia.com/v1",
            "anthropic_version": "2023-06-01",
            "pinned_models": ["default-model"],
            "api_key_file": default_key,
            "log_dir": dir.path().join("logs"),
            "quotas": {"max_output_tokens": 100}
        })
        .to_string(),
    )
    .unwrap();

    std::env::set_var("HERMETIC_UPSTREAM_MODEL", "gpt-oss-custom");
    std::env::set_var(
        "HERMETIC_UPSTREAM_KEY_FILE",
        runtime_key.display().to_string(),
    );

    let loaded = GatewayConfig::load_from_file(config_path).unwrap();
    assert_eq!(loaded.upstream_base_url, custom_url);
    assert!(loaded.pinned_models.contains(&"gpt-oss-custom".to_string()));
    assert_eq!(loaded.api_key_file, runtime_key);
    assert_eq!(loaded.api_key(), "runtime-key-secret-67890");

    // Clean up environment variables
    std::env::remove_var("HERMETIC_UPSTREAM_URL");
    std::env::remove_var("HERMETIC_UPSTREAM_MODEL");
    std::env::remove_var("HERMETIC_UPSTREAM_KEY_FILE");
}

#[test]
fn test_upstream_url_whitespace_trimmed_before_validation() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HERMETIC_UPSTREAM_URL");
    let custom_url = "https://custom-whitespace.example.com/v1";
    std::env::set_var("HERMETIC_UPSTREAM_URL", format!("  {custom_url}  "));
    let res = openai::validate_base_url(custom_url);
    std::env::remove_var("HERMETIC_UPSTREAM_URL");
    assert!(
        res.is_ok(),
        "whitespace in env url should be trimmed before comparison"
    );
}

#[test]
fn test_explicit_anthropic_protocol_preserved_with_v1_url() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HERMETIC_UPSTREAM_URL");
    std::env::remove_var("HERMETIC_UPSTREAM_MODEL");
    std::env::remove_var("HERMETIC_UPSTREAM_KEY_FILE");

    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("anthropic.key");
    std::fs::write(&key, "anthropic-key-secret-12345").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

    let config_path = dir.path().join("gateway.json");
    std::fs::write(
        &config_path,
        json!({
            "upstream_protocol": "anthropic",
            "upstream_base_url": "https://anthropic-proxy.example.com/v1",
            "anthropic_version": "2023-06-01",
            "pinned_models": ["claude-3-haiku-20240307"],
            "api_key_file": key,
            "log_dir": dir.path().join("logs"),
            "quotas": {"max_output_tokens": 100}
        })
        .to_string(),
    )
    .unwrap();

    let loaded = GatewayConfig::load_from_file(config_path)
        .expect("explicit anthropic protocol should not be overridden by /v1 in url");
    assert_eq!(
        loaded.upstream_protocol,
        hermetic_gateway::config::UpstreamProtocol::Anthropic
    );
    assert_eq!(
        loaded.upstream_base_url,
        "https://anthropic-proxy.example.com/v1"
    );
}
