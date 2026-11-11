use std::io::Write;
use std::path::Path;
use std::process::Command;

use hermetic_sealcheck::gitstore::scan_stray_pack_slice;
use hermetic_sealcheck::{
    apply_delta, compute_git_sha1, GitError, GitStore, PackIndex, ScanOptions,
};

fn run_git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Test Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_NAME", "Test Committer")
        .env("GIT_COMMITTER_EMAIL", "committer@example.com")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .env("HOME", dir.display().to_string())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git execution failed");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn test_gitstore_loose_and_packed_ofs_delta() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();

    run_git(repo_dir, &["init"]);
    run_git(repo_dir, &["config", "user.name", "Test Committer"]);
    run_git(repo_dir, &["config", "user.email", "committer@example.com"]);

    // Create a base file with several lines
    let file1 = repo_dir.join("file1.txt");
    let mut content = String::new();
    for i in 0..100 {
        content.push_str(&format!("Line number {}\n", i));
    }
    std::fs::write(&file1, &content).unwrap();
    run_git(repo_dir, &["add", "file1.txt"]);
    run_git(repo_dir, &["commit", "-m", "initial commit"]);

    // Create modified version to encourage delta compression
    let mut content_v2 = content.clone();
    content_v2.push_str("Appended line for delta\n");
    std::fs::write(&file1, &content_v2).unwrap();
    run_git(repo_dir, &["add", "file1.txt"]);
    run_git(repo_dir, &["commit", "-m", "second commit"]);

    // Create an annotated tag
    run_git(repo_dir, &["tag", "-a", "v1.0", "-m", "tag message"]);

    // Repack to create packed objects with OFS_DELTA
    run_git(repo_dir, &["repack", "-adf"]);

    // Also add a loose object that remains loose
    let loose_file = repo_dir.join("loose.txt");
    std::fs::write(&loose_file, "this is a loose object content\n").unwrap();
    run_git(repo_dir, &["add", "loose.txt"]);
    run_git(repo_dir, &["commit", "-m", "loose commit"]);

    let opts = ScanOptions::default();
    let git_dir = repo_dir.join(".git");
    let mut store = GitStore::open(&git_dir, &opts).expect("open git store");

    let git_objects_output = run_git(
        repo_dir,
        &[
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            "--batch-all-objects",
        ],
    );

    let mut expected_objects = Vec::new();
    for line in git_objects_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            expected_objects.push((parts[0].to_string(), parts[1].to_string()));
        }
    }
    assert!(
        !expected_objects.is_empty(),
        "expected objects from git cat-file"
    );

    let enumerated = store.enumerate_object_ids().expect("enumerate object ids");
    for (oid, _) in &expected_objects {
        assert!(
            enumerated.contains(oid),
            "enumerated ids missing object {}",
            oid
        );
    }
    assert_eq!(enumerated.len(), expected_objects.len());

    for (oid, expected_type) in expected_objects {
        let obj = store.read_object(&oid).expect("read object");
        assert_eq!(obj.obj_type.as_str(), expected_type);

        // Verify computed SHA-1
        let computed = compute_git_sha1(obj.obj_type, &obj.data);
        assert_eq!(computed, oid);

        // Compare raw bytes against git cat-file
        let git_raw = Command::new("git")
            .args(["cat-file", &expected_type, &oid])
            .current_dir(repo_dir)
            .output()
            .unwrap()
            .stdout;
        assert_eq!(obj.data, git_raw);
    }
}

#[test]
fn test_gitstore_ref_delta() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();

    run_git(repo_dir, &["init"]);
    run_git(repo_dir, &["config", "user.name", "Test Committer"]);
    run_git(repo_dir, &["config", "user.email", "committer@example.com"]);
    // Disable delta base offset to force REF_DELTA
    run_git(repo_dir, &["config", "pack.deltaBaseOffset", "false"]);

    let file1 = repo_dir.join("data.txt");
    let mut base_text = String::new();
    for i in 0..150 {
        base_text.push_str(&format!("REF_DELTA base line number {}\n", i));
    }
    std::fs::write(&file1, &base_text).unwrap();
    run_git(repo_dir, &["add", "data.txt"]);
    run_git(repo_dir, &["commit", "-m", "commit 1"]);

    let mut v2_text = base_text.clone();
    v2_text.push_str("extra modified line for ref delta\n");
    std::fs::write(&file1, &v2_text).unwrap();
    run_git(repo_dir, &["add", "data.txt"]);
    run_git(repo_dir, &["commit", "-m", "commit 2"]);

    // Pack objects using --no-delta-base-offset to produce REF_DELTA objects
    let pack_dir = repo_dir.join(".git/objects/pack");
    let pack_prefix = pack_dir.join("pack");
    let all_objects = run_git(repo_dir, &["rev-list", "--objects", "--all"]);
    let mut child = Command::new("git")
        .args([
            "pack-objects",
            "--no-delta-base-offset",
            pack_prefix.to_str().unwrap(),
        ])
        .current_dir(repo_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn pack-objects");
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in all_objects.lines() {
            if let Some(oid) = line.split_whitespace().next() {
                writeln!(stdin, "{}", oid).unwrap();
            }
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let opts = ScanOptions::default();
    let git_dir = repo_dir.join(".git");
    let mut store = GitStore::open(&git_dir, &opts).expect("open git store");

    let git_objects_output = run_git(
        repo_dir,
        &[
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            "--batch-all-objects",
        ],
    );

    for line in git_objects_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            let oid = parts[0];
            let expected_type = parts[1];
            let obj = store.read_object(oid).expect("read object");
            assert_eq!(obj.obj_type.as_str(), expected_type);
            assert_eq!(compute_git_sha1(obj.obj_type, &obj.data), oid);

            let git_raw = Command::new("git")
                .args(["cat-file", expected_type, oid])
                .current_dir(repo_dir)
                .output()
                .unwrap()
                .stdout;
            assert_eq!(obj.data, git_raw);
        }
    }
}

#[test]
fn test_hostile_truncated_pack() {
    let temp = tempfile::tempdir().unwrap();
    let idx_path = temp.path().join("test.idx");
    let pack_path = temp.path().join("test.pack");

    // Valid idx header
    let mut idx_data = Vec::new();
    idx_data.extend_from_slice(b"\xfftOc"); // magic
    idx_data.extend_from_slice(&2u32.to_be_bytes()); // v2
    for _ in 0..256 {
        idx_data.extend_from_slice(&1u32.to_be_bytes()); // 1 object
    }
    idx_data.extend_from_slice(&[0x11; 20]); // 1 oid
    idx_data.extend_from_slice(&[0x00; 4]); // crc32
    idx_data.extend_from_slice(&12u32.to_be_bytes()); // offset 12
    idx_data.extend_from_slice(&[0x00; 20]); // checksum
    idx_data.extend_from_slice(&[0x00; 20]); // checksum
    std::fs::write(&idx_path, &idx_data).unwrap();

    // Pack truncated to just 16 bytes (smaller than 32 bytes)
    let pack_data = b"PACK\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00";
    std::fs::write(&pack_path, pack_data).unwrap();

    let res = PackIndex::open(&idx_path);
    assert!(res.is_err(), "truncated pack should fail");
}

#[test]
fn test_hostile_idx_fanout_not_monotonic() {
    let temp = tempfile::tempdir().unwrap();
    let idx_path = temp.path().join("bad_fanout.idx");
    let pack_path = temp.path().join("bad_fanout.pack");
    std::fs::write(
        &pack_path,
        b"PACK\x00\x00\x00\x02\x00\x00\x00\x0012345678901234567890",
    )
    .unwrap();

    let mut idx_data = Vec::new();
    idx_data.extend_from_slice(b"\xfftOc");
    idx_data.extend_from_slice(&2u32.to_be_bytes());
    // Non-monotonic fanout: fanout[0] = 5, fanout[1] = 2
    idx_data.extend_from_slice(&5u32.to_be_bytes());
    idx_data.extend_from_slice(&2u32.to_be_bytes());
    for _ in 2..256 {
        idx_data.extend_from_slice(&5u32.to_be_bytes());
    }
    std::fs::write(&idx_path, idx_data).unwrap();

    let res = PackIndex::open(&idx_path);
    assert!(matches!(res, Err(GitError::Corrupt(msg)) if msg.contains("not monotonic")));
}

#[test]
fn test_hostile_idx_offset_beyond_pack() {
    let temp = tempfile::tempdir().unwrap();
    let idx_path = temp.path().join("beyond.idx");
    let pack_path = temp.path().join("beyond.pack");
    // Pack of 32 bytes
    std::fs::write(
        &pack_path,
        b"PACK\x00\x00\x00\x02\x00\x00\x00\x0112345678901234567890",
    )
    .unwrap();

    let mut idx_data = Vec::new();
    idx_data.extend_from_slice(b"\xfftOc");
    idx_data.extend_from_slice(&2u32.to_be_bytes());
    for _ in 0..256 {
        idx_data.extend_from_slice(&1u32.to_be_bytes());
    }
    idx_data.extend_from_slice(&[0xaa; 20]);
    idx_data.extend_from_slice(&[0x00; 4]);
    // Offset 999999 is beyond 32 bytes
    idx_data.extend_from_slice(&999999u32.to_be_bytes());
    idx_data.extend_from_slice(&[0x00; 20]);
    idx_data.extend_from_slice(&[0x00; 20]);
    std::fs::write(&idx_path, idx_data).unwrap();

    let res = PackIndex::open(&idx_path);
    assert!(matches!(res, Err(GitError::Corrupt(msg)) if msg.contains("beyond the pack")));
}

#[test]
fn test_hostile_delta_copy_beyond_base() {
    let base = b"short base";
    // Base size: 10, Result size: 20, Copy instruction: cmd = 0x80 | 0x01 | 0x10, offset 5, size 20
    let delta = vec![10, 20, 0x91, 5, 20];

    let res = apply_delta(base, &delta, 1024 * 1024);
    assert!(matches!(res, Err(GitError::Corrupt(msg)) if msg.contains("beyond the base")));
}

#[test]
fn test_hostile_delta_result_size_mismatch() {
    let base = b"base text";
    // Base size 9, Declared result size 50, Insert 5 bytes "hello"
    let mut delta = vec![9, 50, 5];
    delta.extend_from_slice(b"hello");

    let res = apply_delta(base, &delta, 1024 * 1024);
    assert!(matches!(res, Err(GitError::Corrupt(msg)) if msg.contains("result size mismatch")));
}

#[test]
fn test_hostile_ref_delta_cycle() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    run_git(repo_dir, &["init"]);
    run_git(repo_dir, &["config", "user.name", "Test"]);
    run_git(repo_dir, &["config", "user.email", "test@test.com"]);

    // Create a commit
    std::fs::write(repo_dir.join("f.txt"), "hello").unwrap();
    run_git(repo_dir, &["add", "f.txt"]);
    run_git(repo_dir, &["commit", "-m", "init"]);

    let pack_dir = repo_dir.join(".git/objects/pack");
    std::fs::create_dir_all(&pack_dir).unwrap();
    let pack_path = pack_dir.join("pack-cycle.pack");
    let idx_path = pack_dir.join("pack-cycle.idx");

    let oid_a = [0x11u8; 20];
    let oid_b = [0x22u8; 20];

    // Build pack with 2 REF_DELTA objects pointing to each other
    // Header
    let mut pack_bytes = Vec::new();
    pack_bytes.extend_from_slice(b"PACK\x00\x00\x00\x02\x00\x00\x00\x02");

    let offset_a = pack_bytes.len() as u64;
    // Object A: type 7 (REF_DELTA), size 15
    pack_bytes.push((7 << 4) | 15);
    pack_bytes.extend_from_slice(&oid_b); // base is B
                                          // Zlib-compressed delta
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    // delta: base_len 10, res_len 10, insert 10 'A's
    enc.write_all(&[10, 10, 10]).unwrap();
    enc.write_all(b"AAAAAAAAAA").unwrap();
    let comp_a = enc.finish().unwrap();
    pack_bytes.extend_from_slice(&comp_a);

    let offset_b = pack_bytes.len() as u64;
    // Object B: type 7 (REF_DELTA), size 15
    pack_bytes.push((7 << 4) | 15);
    pack_bytes.extend_from_slice(&oid_a); // base is A
    let mut enc_b = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc_b.write_all(&[10, 10, 10]).unwrap();
    enc_b.write_all(b"BBBBBBBBBB").unwrap();
    let comp_b = enc_b.finish().unwrap();
    pack_bytes.extend_from_slice(&comp_b);
    pack_bytes.extend_from_slice(&[0u8; 20]); // checksum
    std::fs::write(&pack_path, pack_bytes).unwrap();

    // Build idx file
    let mut idx_bytes = Vec::new();
    idx_bytes.extend_from_slice(b"\xfftOc\x00\x00\x00\x02");
    let mut fanout = [0u32; 256];
    fanout[0x11..].fill(1);
    fanout[0x22..].fill(2);
    for count in fanout {
        idx_bytes.extend_from_slice(&count.to_be_bytes());
    }
    idx_bytes.extend_from_slice(&oid_a);
    idx_bytes.extend_from_slice(&oid_b);
    idx_bytes.extend_from_slice(&[0u8; 8]); // crc32
    idx_bytes.extend_from_slice(&(offset_a as u32).to_be_bytes());
    idx_bytes.extend_from_slice(&(offset_b as u32).to_be_bytes());
    idx_bytes.extend_from_slice(&[0u8; 40]); // checksums
    std::fs::write(&idx_path, idx_bytes).unwrap();

    let opts = ScanOptions::default();
    let mut store = GitStore::open(&repo_dir.join(".git"), &opts).unwrap();
    let res = store.read_object(&hex::encode(oid_a));
    assert!(
        matches!(res, Err(GitError::Corrupt(ref msg)) if msg.contains("delta cycle")),
        "cycle detection expected, got {:?}",
        res
    );
}

fn stray_pack(count: u32, body: &[u8]) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&count.to_be_bytes());
    pack.extend_from_slice(body);
    pack.extend_from_slice(&[0u8; 20]); // trailer
    pack
}

#[test]
fn test_hostile_delta_copy_cannot_exceed_declared_result() {
    // base 4 bytes, declared result 4 bytes, then two copies of the whole base.
    let delta = vec![4, 4, 0x90, 4, 0x90, 4];
    let res = apply_delta(b"abcd", &delta, 1024 * 1024);
    assert!(matches!(res, Err(GitError::Corrupt(msg)) if msg.contains("result size mismatch")));
}

#[test]
fn test_hostile_delta_insert_cannot_exceed_declared_result() {
    // base 4 bytes, declared result 1 byte, then a 3-byte insert.
    let delta = vec![4, 1, 3, b'x', b'y', b'z'];
    let res = apply_delta(b"abcd", &delta, 1024 * 1024);
    assert!(matches!(res, Err(GitError::Corrupt(msg)) if msg.contains("result size mismatch")));
}

#[test]
fn test_hostile_stray_pack_huge_declared_size() {
    // A blob whose header declares 2^56 bytes: must be refused before allocating.
    let mut body = vec![0xb0u8];
    body.extend_from_slice(&[0x80; 7]);
    body.push(0x01);
    let opts = ScanOptions::default();
    let (_, _, err) = scan_stray_pack_slice(&stray_pack(1, &body), &opts, &mut 0);
    assert!(matches!(err, Some(GitError::LimitExceeded(_))));
}

#[test]
fn test_hostile_stray_pack_size_varint_overflow() {
    let body = vec![0xffu8; 16];
    let opts = ScanOptions::default();
    let (_, _, err) = scan_stray_pack_slice(&stray_pack(1, &body), &opts, &mut 0);
    assert!(matches!(err, Some(GitError::Corrupt(_))));
}

#[test]
fn test_hostile_stray_pack_zlib_bomb_stops_at_the_limit() {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![0u8; 5 * 1024 * 1024]).unwrap();
    let mut body = vec![0x35u8]; // blob, declared size 5
    body.extend_from_slice(&encoder.finish().unwrap());

    let opts = ScanOptions {
        max_member_bytes: 1024 * 1024,
        ..Default::default()
    };
    let (_, _, err) = scan_stray_pack_slice(&stray_pack(1, &body), &opts, &mut 0);
    assert!(matches!(err, Some(GitError::LimitExceeded(_))));
}

#[test]
fn test_hostile_stray_pack_shorter_than_its_count() {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"hello").unwrap();
    let mut body = vec![0x35u8];
    body.extend_from_slice(&encoder.finish().unwrap());

    let opts = ScanOptions::default();
    let (blobs, _, err) = scan_stray_pack_slice(&stray_pack(2, &body), &opts, &mut 0);
    assert!(matches!(err, Some(GitError::Corrupt(msg)) if msg.contains("last object")));
    // What was decoded before the error is still handed back for scanning.
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].1, b"hello");
}

#[test]
fn test_stray_pack_counts_against_container_total() {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"hello").unwrap();
    let mut body = vec![0x35u8];
    body.extend_from_slice(&encoder.finish().unwrap());

    let opts = ScanOptions::default();
    let mut total = 0u64;
    let (blobs, unresolved, err) = scan_stray_pack_slice(&stray_pack(1, &body), &opts, &mut total);
    assert!(err.is_none());
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].1, b"hello");
    assert!(!unresolved);
    assert_eq!(total, 5);
}

#[test]
fn test_hostile_declared_object_size_over_limit() {
    let base = b"base text";
    // base size 9, declared result size 2000 (0x90, 0x0f)
    let delta = vec![9, 0x90, 0x0f];

    // Limit is 100 bytes
    let res = apply_delta(base, &delta, 100);
    assert!(matches!(res, Err(GitError::LimitExceeded(msg)) if msg.contains("over the limit")));
}

#[test]
fn test_hostile_non_hex_oid_is_an_error_not_a_panic() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("objects")).unwrap();
    let mut store = GitStore::open(temp.path(), &ScanOptions::default()).unwrap();
    // 40 bytes long, with a multi-byte character across byte 2.
    let oid = format!("a\u{FFFD}{}", "b".repeat(36));
    assert_eq!(oid.len(), 40);
    assert!(matches!(store.read_object(&oid), Err(GitError::Corrupt(_))));
}

#[test]
fn test_hostile_idx_count_larger_than_file() {
    let temp = tempfile::tempdir().unwrap();
    let idx = temp.path().join("pack-x.idx");
    let mut bytes = b"\xfftOc\0\0\0\x02".to_vec();
    // Fanout claims u32::MAX objects, in a file with none.
    for _ in 0..256 {
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    }
    std::fs::write(&idx, bytes).unwrap();
    assert!(
        matches!(PackIndex::open(&idx), Err(GitError::Corrupt(msg)) if msg.contains("shorter"))
    );
}
