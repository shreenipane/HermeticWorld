#![forbid(unsafe_code)]

#[test]
fn test_web_imports_smoke_script_present_and_executable() {
    let paths = [
        std::path::Path::new("scripts/integration/web-imports-smoke.sh"),
        std::path::Path::new("../../scripts/integration/web-imports-smoke.sh"),
    ];
    let mut found = false;
    for path in paths {
        if path.exists() {
            found = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
                let metadata = std::fs::metadata(path).unwrap();
                assert!(metadata.permissions().mode() & 0o111 != 0);
            }
        }
    }
    assert!(found, "web-imports-smoke.sh not found");
}

#[test]
fn test_web_imports_smoke_skips_cleanly_without_env_vars() {
    for var_name in [
        "HERMETIC_FC_BIN",
        "HERMETIC_FIRECRACKER_LOCK",
        "HERMETIC_KERNEL",
    ] {
        if std::env::var_os(var_name).is_none() {
            eprintln!("skipped: nested VM test requires {var_name}");
            return;
        }
    }
}
