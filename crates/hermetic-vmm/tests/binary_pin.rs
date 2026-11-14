use hermetic_vmm::{deadline, pin::BuildPin};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::Duration;

fn record() -> Value {
    json!({"schema":"hermetic-firecracker-build/v1", "version":"1.18.0",
        "source_sha256":"89f02fe6867edcf0a0154305d5533a611e48eaa99ba11d24aa2f076492bef615",
        "patch_sha256":format!("{:x}",Sha256::digest(include_bytes!("../../../vmm/firecracker-patches/0001-host-pv-clock-filter.patch"))),
        "builder_image":format!("sha256:{}","a".repeat(64)),
        "target":"x86_64-unknown-linux-musl", "rust":"1.97.0",
        "firecracker_sha256":format!("{:x}",Sha256::digest(b"patched-vmm")),
        "jailer_sha256":format!("{:x}",Sha256::digest(b"patched-jailer"))})
}
#[test]
fn only_current_patched_provenance_is_accepted() {
    let good = record();
    assert!(BuildPin::read(good.to_string().as_bytes()).is_ok());
    assert!(
        BuildPin::read(include_bytes!("../../../vmm/firecracker.lock.json").as_slice()).is_err()
    );
    for field in [
        "schema",
        "version",
        "source_sha256",
        "patch_sha256",
        "builder_image",
        "target",
        "rust",
        "firecracker_sha256",
        "jailer_sha256",
    ] {
        let mut bad = good.clone();
        bad[field] = json!("secret");
        assert!(
            BuildPin::read(bad.to_string().as_bytes()).is_err(),
            "{field}"
        );
    }
    assert!(BuildPin::read(" ".repeat(16_385).as_bytes()).is_err());
    let duplicate = good.to_string().replacen('{', "{\"schema\":\"secret\",", 1);
    assert!(BuildPin::read(duplicate.as_bytes()).is_err());
}
#[test]
fn substituted_binary_fails_and_pinned_inode_survives_path_swap() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("firecracker");
    fs::write(&path, b"patched-vmm").unwrap();
    let file = fs::File::open(&path).unwrap();
    let pin = BuildPin::read(record().to_string().as_bytes()).unwrap();
    let end = deadline(Duration::from_secs(5)).unwrap();
    pin.verify(&file, false, end).unwrap();
    assert!(pin.verify(&file, true, end).is_err());
    fs::rename(&path, temp.path().join("old")).unwrap();
    fs::write(&path, b"stock-or-substituted").unwrap();
    pin.verify(&file, false, end).unwrap();
    assert!(pin
        .verify(&fs::File::open(path).unwrap(), false, end)
        .is_err());
}
