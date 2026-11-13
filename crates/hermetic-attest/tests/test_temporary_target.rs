use hermetic_attest::{safe_atomic_write_file, safe_read_file, FsError};
use std::os::unix::fs::PermissionsExt;

#[test]
fn destination_cannot_replace_an_entry_in_the_temporary_namespace() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let target = dir.path().join(".attest-tmp-0");
    std::fs::write(&target, b"record").unwrap();
    assert!(matches!(
        safe_atomic_write_file(&target, b"replacement"),
        Err(FsError::InvalidPath(_))
    ));
    assert_eq!(safe_read_file(&target, 100).unwrap(), b"record");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
