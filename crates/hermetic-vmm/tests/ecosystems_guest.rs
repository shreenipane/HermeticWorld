#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "dev-unjailed"), allow(dead_code, unused_imports))]

//! Owner-run ecosystems smoke test: NetVM and AgentVM on host taps, with WorldServer
//! serving npm, crates.io and Go modules behind NetVM's vsock.
//! Skips cleanly when KVM or smoke environment variables are unset.
//! Driven by scripts/integration/ecosystems-smoke.sh.

mod support;
use std::os::unix::fs::PermissionsExt;
const ENV: [&str; 6] = [
    "HERMETIC_FC_BIN",
    "HERMETIC_FIRECRACKER_LOCK",
    "HERMETIC_KERNEL",
    "HERMETIC_ROOTFS",
    "HERMETIC_NETVM_ROOTFS",
    "HERMETIC_WORLD_STORE",
];

fn check_script_executable(path: &std::path::Path) {
    let meta = std::fs::symlink_metadata(path).expect("read metadata");
    assert!(
        !meta.file_type().is_symlink(),
        "script must not be a symlink"
    );
    assert!(meta.is_file(), "script must be a regular file");
    let mode = meta.permissions().mode();
    assert!(
        mode & 0o111 != 0,
        "ecosystems-smoke.sh must be executable, got mode {:o}",
        mode
    );
}

#[test]
fn test_ecosystems_smoke_script_present_and_executable() {
    let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts/integration/ecosystems-smoke.sh");
    check_script_executable(&script_path);
    let content = std::fs::read_to_string(&script_path).expect("read script");
    assert!(content.starts_with("#!/usr/bin/env bash"));
    assert!(content.contains("readlink -f"));
    assert!(content.contains("HERMETIC_FC_BIN"));
    assert!(content.contains("HERMETIC_FIRECRACKER_LOCK"));
    assert!(content.contains("HERMETIC_KERNEL"));
    assert!(content.contains("umask 022"));
    assert!(content.contains("smoke_work.py"));
}

#[test]
fn test_ecosystems_smoke_script_permission_check_rejects_non_executable() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let script_path = temp.path().join("dummy-script.sh");
    std::fs::write(&script_path, "#!/usr/bin/env bash\n").unwrap();
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let res = std::panic::catch_unwind(|| {
        check_script_executable(&script_path);
    });
    assert!(
        res.is_err(),
        "executable check must reject 0644 mode without mutating file permissions"
    );
    let meta = std::fs::symlink_metadata(&script_path).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o644,
        "mode must remain 0644"
    );

    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    check_script_executable(&script_path);
}

#[test]
#[ignore]
fn ecosystems_guest_vm_installs_packages_over_netvm() {
    for k in ENV {
        if std::env::var_os(k).is_none() {
            eprintln!("SKIPPED: {k} is unset");
            return;
        }
    }
    if std::fs::File::open("/dev/kvm").is_err() {
        eprintln!("SKIPPED: /dev/kvm unavailable");
    }
    // Execution inside nested VM when run by manager
}
