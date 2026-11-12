use hermetic_attest::{safe_atomic_write_file, safe_read_file, FsError};
use tempfile::tempdir;

#[test]
fn test_safe_read_and_atomic_write() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("record.json");

    let payload = b"{\"hello\":\"world\"}";
    safe_atomic_write_file(&file_path, payload).expect("atomic write");

    let read_back = safe_read_file(&file_path, 1024).expect("read file");
    assert_eq!(read_back, payload);
}

#[test]
fn test_safe_read_refuses_symlink() {
    let dir = tempdir().expect("tempdir");
    let target_path = dir.path().join("target.txt");
    let link_path = dir.path().join("link.txt");

    std::fs::write(&target_path, b"real content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

    #[cfg(unix)]
    {
        let err = safe_read_file(&link_path, 1024);
        assert!(matches!(err, Err(FsError::SymlinkForbidden(_))));
    }
}

#[test]
fn test_safe_read_refuses_directory() {
    let dir = tempdir().expect("tempdir");
    let err = safe_read_file(dir.path(), 1024);
    assert!(matches!(err, Err(FsError::NonRegularFile(_))));
}

#[test]
fn test_safe_read_enforces_size_cap() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("large.bin");
    std::fs::write(&file_path, vec![0u8; 200]).unwrap();

    let err = safe_read_file(&file_path, 100);
    assert!(matches!(err, Err(FsError::FileTooLarge { .. })));
}
