use hermetic_attest::{safe_atomic_write_file, safe_read_file};
use std::os::unix::fs::PermissionsExt;

// A separate test process gives the temporary-name counter its initial value.
#[test]
fn destination_may_use_the_temporary_name_prefix() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let target = dir.path().join(".attest-tmp-0");
    safe_atomic_write_file(&target, b"record").unwrap();
    assert_eq!(safe_read_file(&target, 100).unwrap(), b"record");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
