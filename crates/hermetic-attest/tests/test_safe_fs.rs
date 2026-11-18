use hermetic_attest::{safe_atomic_write_file, safe_read_file, safe_sha256_file, FsError};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn test_safe_read_and_atomic_write() {
    let dir = tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
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

#[test]
fn test_safe_sha256_file_matches_hash() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("content.bin");
    let data = b"deterministic test content for safe_sha256_file";
    std::fs::write(&file_path, data).unwrap();

    let expected = format!("{:x}", Sha256::digest(data));
    let actual = safe_sha256_file(&file_path, 1024).expect("safe_sha256_file");
    assert_eq!(actual, expected);
}

#[test]
fn test_safe_sha256_file_refuses_symlink() {
    let dir = tempdir().expect("tempdir");
    let target_path = dir.path().join("target.bin");
    let link_path = dir.path().join("link.bin");
    std::fs::write(&target_path, b"content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

    #[cfg(unix)]
    {
        let err = safe_sha256_file(&link_path, 1024);
        assert!(matches!(err, Err(FsError::SymlinkForbidden(_))));
    }
}

#[test]
fn test_safe_sha256_file_enforces_size_cap() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("oversized.bin");
    std::fs::write(&file_path, vec![0u8; 256]).unwrap();

    let err = safe_sha256_file(&file_path, 100);
    assert!(matches!(err, Err(FsError::FileTooLarge { .. })));
}

#[test]
fn test_safe_sha256_file_refuses_directory() {
    let dir = tempdir().expect("tempdir");
    let err = safe_sha256_file(dir.path(), 1024);
    assert!(matches!(err, Err(FsError::NonRegularFile(_))));
}
