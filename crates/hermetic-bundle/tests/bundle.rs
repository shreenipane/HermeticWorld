#![forbid(unsafe_code)]

use hermetic_bundle::{
    compute_root, seal, validate_relative_path, verify, BundleError, EntryKind, EntryMode,
    Manifest, ManifestEntry, RefusedKind, Verdict, MANIFEST_FILENAME, MAX_COMPONENT_BYTES,
    MAX_DEPTH, MAX_PATH_BYTES,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn write_file(path: &Path, data: &[u8], mode: u32) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn create_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn known_answer_empty_and_fixed_tree() {
    // 1. Known-answer test for empty bundle:
    // SHA-256("") == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let empty_dir = TempDir::new().unwrap();
    let empty_manifest = seal(empty_dir.path()).unwrap();
    let expected_empty_root =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(empty_manifest.root, expected_empty_root);
    assert!(empty_manifest.entries.is_empty());

    let empty_on_disk = fs::read(empty_dir.path().join(MANIFEST_FILENAME)).unwrap();
    let expected_empty_manifest_bytes = br#"{"format":"hermetic-bundle/v1","entries":[],"root":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;
    assert_eq!(empty_on_disk, expected_empty_manifest_bytes);

    // 2. Known-answer test for a fixed tree with a file ("a.txt" = b"abc", mode 0644)
    // and a directory ("sub", mode 0755).
    // NIST SHA-256("abc") == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let tree = TempDir::new().unwrap();
    write_file(&tree.path().join("a.txt"), b"abc", 0o644);
    create_dir(&tree.path().join("sub"));

    let manifest = seal(tree.path()).unwrap();
    assert_eq!(manifest.entries.len(), 2);

    let canonical_a = br#"{"path":"a.txt","kind":"file","mode":"0644","size":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}"#;
    let canonical_sub = br#"{"path":"sub","kind":"dir","mode":"0755"}"#;

    assert_eq!(
        manifest.entries[0].to_canonical_json_bytes().unwrap(),
        canonical_a
    );
    assert_eq!(
        manifest.entries[1].to_canonical_json_bytes().unwrap(),
        canonical_sub
    );

    let mut outer = Sha256::new();
    outer.update(Sha256::digest(canonical_a));
    outer.update(Sha256::digest(canonical_sub));
    let expected_root = format!("sha256:{:x}", outer.finalize());
    let hardcoded_root = "sha256:3f4874b7911d5aaafcd47fb763d4ff38e7fc17abe8b6c4e8724a6b8b0bb9af53";
    assert_eq!(expected_root, hardcoded_root);
    assert_eq!(manifest.root, hardcoded_root);
    assert_eq!(compute_root(&manifest.entries).unwrap(), hardcoded_root);

    let report = verify(tree.path(), Some(hardcoded_root)).unwrap();
    assert_eq!(report.verdict, Verdict::Ok);
    assert!(report.manifest_root_matches);
    assert_eq!(report.expected_root_matches, Some(true));
}

#[test]
fn path_validation_rules_and_case_collisions() {
    // Invalid paths
    assert!(validate_relative_path("").is_err());
    assert!(validate_relative_path("/leading").is_err());
    assert!(validate_relative_path("trailing/").is_err());
    assert!(validate_relative_path("a//b").is_err());
    assert!(validate_relative_path(".").is_err());
    assert!(validate_relative_path("./a").is_err());
    assert!(validate_relative_path("a/.").is_err());
    assert!(validate_relative_path("..").is_err());
    assert!(validate_relative_path("../a").is_err());
    assert!(validate_relative_path("a/../b").is_err());
    assert!(validate_relative_path("a\0b").is_err());
    assert!(validate_relative_path("a\\b").is_err());
    assert!(validate_relative_path(MANIFEST_FILENAME).is_err());

    // Component length boundary: 255 allowed, 256 refused
    let max_comp = "x".repeat(MAX_COMPONENT_BYTES);
    assert!(validate_relative_path(&max_comp).is_ok());
    let over_comp = "x".repeat(MAX_COMPONENT_BYTES + 1);
    assert!(validate_relative_path(&over_comp).is_err());

    // Depth boundary: 128 allowed, 129 refused
    let depth_128 = vec!["a"; MAX_DEPTH].join("/");
    assert!(validate_relative_path(&depth_128).is_ok());
    let depth_129 = vec!["a"; MAX_DEPTH + 1].join("/");
    assert!(validate_relative_path(&depth_129).is_err());

    // Total path length boundary: 4096 allowed, 4097 refused
    let mut parts: Vec<String> = Vec::new();
    let mut total_len = 0usize;
    while total_len + 200 <= MAX_PATH_BYTES {
        if !parts.is_empty() {
            total_len += 1;
        }
        parts.push("p".repeat(199));
        total_len += 199;
    }
    let rem = MAX_PATH_BYTES - total_len - 1;
    parts.push("q".repeat(rem));
    let exact_4096 = parts.join("/");
    assert_eq!(exact_4096.len(), MAX_PATH_BYTES);
    assert!(validate_relative_path(&exact_4096).is_ok());

    let over_4096 = format!("{exact_4096}z");
    assert_eq!(over_4096.len(), MAX_PATH_BYTES + 1);
    assert!(validate_relative_path(&over_4096).is_err());

    // Non-ASCII UTF-8 paths are valid
    assert!(validate_relative_path("café/naïve-文件.txt").is_ok());

    // ASCII case collision in seal: file level
    let case_dir = TempDir::new().unwrap();
    write_file(&case_dir.path().join("Readme.md"), b"one", 0o644);
    write_file(&case_dir.path().join("README.md"), b"two", 0o644);
    match seal(case_dir.path()) {
        Err(BundleError::CaseCollision { .. }) => {}
        other => panic!("expected CaseCollision error, got {other:?}"),
    }

    // ASCII case collision in seal: directory level
    let dir_case = TempDir::new().unwrap();
    write_file(&dir_case.path().join("Sub/a.txt"), b"one", 0o644);
    write_file(&dir_case.path().join("sub/b.txt"), b"two", 0o644);
    match seal(dir_case.path()) {
        Err(BundleError::CaseCollision { .. }) => {}
        other => panic!("expected directory CaseCollision error, got {other:?}"),
    }
}

#[test]
fn refuses_symlinks_hardlinks_fifos_and_sockets() {
    // 1. Symlink refused in seal and reported in verify
    let sym_dir = TempDir::new().unwrap();
    write_file(&sym_dir.path().join("real.txt"), b"data", 0o644);
    symlink("real.txt", sym_dir.path().join("link.txt")).unwrap();

    match seal(sym_dir.path()) {
        Err(BundleError::RefusedObject { path, kind }) => {
            assert_eq!(path, "link.txt");
            assert_eq!(kind, RefusedKind::Symlink);
        }
        other => panic!("expected RefusedObject(Symlink), got {other:?}"),
    }

    // Seal clean directory, then add symlink and verify
    fs::remove_file(sym_dir.path().join("link.txt")).unwrap();
    seal(sym_dir.path()).unwrap();
    symlink("real.txt", sym_dir.path().join("link.txt")).unwrap();
    let rep_sym = verify(sym_dir.path(), None).unwrap();
    assert_eq!(rep_sym.verdict, Verdict::Mismatch);
    assert_eq!(rep_sym.refused_objects.len(), 1);
    assert_eq!(rep_sym.refused_objects[0].path, "link.txt");
    assert_eq!(rep_sym.refused_objects[0].kind, RefusedKind::Symlink);

    // 2. Hard link refused in seal and reported in verify
    let hl_dir = TempDir::new().unwrap();
    let orig = hl_dir.path().join("orig.txt");
    let twin = hl_dir.path().join("twin.txt");
    write_file(&orig, b"shared", 0o644);
    fs::hard_link(&orig, &twin).unwrap();

    match seal(hl_dir.path()) {
        Err(BundleError::RefusedObject { kind, .. }) => {
            assert_eq!(kind, RefusedKind::HardLink);
        }
        other => panic!("expected RefusedObject(HardLink), got {other:?}"),
    }

    fs::remove_file(&twin).unwrap();
    seal(hl_dir.path()).unwrap();
    fs::hard_link(&orig, &twin).unwrap();
    let rep_hl = verify(hl_dir.path(), None).unwrap();
    assert_eq!(rep_hl.verdict, Verdict::Mismatch);
    assert_eq!(rep_hl.refused_objects.len(), 2);
    assert_eq!(rep_hl.refused_objects[0].kind, RefusedKind::HardLink);

    // 3. FIFO refused in seal and reported in verify
    let fifo_dir = TempDir::new().unwrap();
    write_file(&fifo_dir.path().join("ok.txt"), b"ok", 0o644);
    seal(fifo_dir.path()).unwrap();

    let fifo_path = fifo_dir.path().join("pipe.fifo");
    match Command::new("mkfifo").arg(&fifo_path).status() {
        Ok(status) if status.success() => {
            let rep_fifo = verify(fifo_dir.path(), None).unwrap();
            assert_eq!(rep_fifo.verdict, Verdict::Mismatch);
            assert_eq!(rep_fifo.refused_objects.len(), 1);
            assert_eq!(rep_fifo.refused_objects[0].path, "pipe.fifo");
            assert_eq!(rep_fifo.refused_objects[0].kind, RefusedKind::Fifo);

            match seal(fifo_dir.path()) {
                Err(BundleError::RefusedObject { path, kind }) => {
                    assert_eq!(path, "pipe.fifo");
                    assert_eq!(kind, RefusedKind::Fifo);
                }
                other => panic!("expected RefusedObject(Fifo), got {other:?}"),
            }
        }
        _ => {
            eprintln!("skipping FIFO test: mkfifo unavailable or unsupported on test filesystem");
        }
    }

    // 4. Unix domain socket refused in seal and reported in verify
    let sock_dir = TempDir::new().unwrap();
    write_file(&sock_dir.path().join("base.txt"), b"base", 0o644);
    let sock_path = sock_dir.path().join("comm.sock");
    if let Ok(_listener) = UnixListener::bind(&sock_path) {
        match seal(sock_dir.path()) {
            Err(BundleError::RefusedObject { path, kind }) => {
                assert_eq!(path, "comm.sock");
                assert_eq!(kind, RefusedKind::Socket);
            }
            other => panic!("expected RefusedObject(Socket), got {other:?}"),
        }
    }
}

#[test]
fn detects_file_mutations_additions_removals_and_mode_changes() {
    let dir = TempDir::new().unwrap();
    write_file(&dir.path().join("data.bin"), b"hello world", 0o640);
    write_file(&dir.path().join("bin/tool"), b"#!/bin/sh\n", 0o750);
    write_file(&dir.path().join("keep.txt"), b"stay", 0o644);

    let manifest = seal(dir.path()).unwrap();
    // Non-execute bits are normalized: 0640 -> 0644, 0750 -> 0755
    assert_eq!(
        manifest
            .entries
            .iter()
            .find(|e| e.path == "data.bin")
            .unwrap()
            .mode,
        EntryMode::Mode0644
    );
    assert_eq!(
        manifest
            .entries
            .iter()
            .find(|e| e.path == "bin/tool")
            .unwrap()
            .mode,
        EntryMode::Mode0755
    );
    assert_eq!(verify(dir.path(), None).unwrap().verdict, Verdict::Ok);

    // 1. Modify file by one byte (same length) -> hash mismatch
    fs::write(dir.path().join("data.bin"), b"hello worlD").unwrap();
    let r1 = verify(dir.path(), None).unwrap();
    assert_eq!(r1.verdict, Verdict::Mismatch);
    assert!(r1.size_mismatches.is_empty());
    assert_eq!(r1.hash_mismatches.len(), 1);
    assert_eq!(r1.hash_mismatches[0].path, "data.bin");
    assert!(!r1.manifest_root_matches);
    fs::write(dir.path().join("data.bin"), b"hello world").unwrap();

    // 2. Append one byte -> size and hash mismatch
    fs::write(dir.path().join("data.bin"), b"hello world!").unwrap();
    let r2 = verify(dir.path(), None).unwrap();
    assert_eq!(r2.verdict, Verdict::Mismatch);
    assert_eq!(r2.size_mismatches.len(), 1);
    assert_eq!(r2.size_mismatches[0].expected, 11);
    assert_eq!(r2.size_mismatches[0].actual, 12);
    assert_eq!(r2.hash_mismatches.len(), 1);
    fs::write(dir.path().join("data.bin"), b"hello world").unwrap();

    // 3. Add extra file -> extra_entries
    write_file(&dir.path().join("untracked.txt"), b"extra", 0o644);
    let r3 = verify(dir.path(), None).unwrap();
    assert_eq!(r3.verdict, Verdict::Mismatch);
    assert_eq!(r3.extra_entries, vec!["untracked.txt".to_string()]);
    fs::remove_file(dir.path().join("untracked.txt")).unwrap();

    // 4. Remove tracked file -> missing_entries
    fs::remove_file(dir.path().join("keep.txt")).unwrap();
    let r4 = verify(dir.path(), None).unwrap();
    assert_eq!(r4.verdict, Verdict::Mismatch);
    assert_eq!(r4.missing_entries, vec!["keep.txt".to_string()]);
    write_file(&dir.path().join("keep.txt"), b"stay", 0o644);

    // 5. Mode change (execute bit toggled) -> mode_mismatches
    fs::set_permissions(
        dir.path().join("data.bin"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let r5 = verify(dir.path(), None).unwrap();
    assert_eq!(r5.verdict, Verdict::Mismatch);
    assert_eq!(r5.mode_mismatches.len(), 1);
    assert_eq!(r5.mode_mismatches[0].path, "data.bin");
    assert_eq!(r5.mode_mismatches[0].expected, EntryMode::Mode0644);
    assert_eq!(r5.mode_mismatches[0].actual, EntryMode::Mode0755);
}

#[test]
fn detects_tampered_manifest() {
    let dir = TempDir::new().unwrap();
    write_file(&dir.path().join("a.txt"), b"alpha", 0o644);
    write_file(&dir.path().join("b.txt"), b"beta", 0o644);
    let original = seal(dir.path()).unwrap();
    let manifest_path = dir.path().join(MANIFEST_FILENAME);
    let original_bytes = fs::read(&manifest_path).unwrap();

    // 1. Entry reordered
    let mut reordered = original.clone();
    reordered.entries.reverse();
    fs::write(&manifest_path, serde_json::to_vec(&reordered).unwrap()).unwrap();
    assert!(matches!(
        verify(dir.path(), None),
        Err(BundleError::ManifestInvalid { .. })
    ));

    // 2. Unknown field added
    let unknown_field = format!(
        r#"{{"format":"hermetic-bundle/v1","entries":[],"root":"{}","extra":1}}"#,
        original.root
    );
    fs::write(&manifest_path, unknown_field).unwrap();
    assert!(matches!(
        verify(dir.path(), None),
        Err(BundleError::ManifestInvalid { .. })
    ));

    // 3. Duplicate key added
    let dup_key = format!(
        r#"{{"format":"hermetic-bundle/v1","entries":[],"root":"{}","root":"{}"}}"#,
        original.root, original.root
    );
    fs::write(&manifest_path, dup_key).unwrap();
    assert!(matches!(
        verify(dir.path(), None),
        Err(BundleError::ManifestInvalid { .. })
    ));

    // 4. Root changed to different valid digest -> Verdict::Mismatch
    let mut bad_root = original.clone();
    bad_root.root =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    fs::write(&manifest_path, serde_json::to_vec(&bad_root).unwrap()).unwrap();
    let rep = verify(dir.path(), None).unwrap();
    assert_eq!(rep.verdict, Verdict::Mismatch);
    assert!(!rep.manifest_root_matches);

    // Restore original manifest and verify expected_root mismatch
    fs::write(&manifest_path, &original_bytes).unwrap();
    let rep_exp = verify(
        dir.path(),
        Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
    )
    .unwrap();
    assert_eq!(rep_exp.verdict, Verdict::Mismatch);
    assert!(rep_exp.manifest_root_matches);
    assert_eq!(rep_exp.expected_root_matches, Some(false));

    // Invalid expected root syntax -> error
    assert!(matches!(
        verify(dir.path(), Some("not-sha256")),
        Err(BundleError::InvalidExpectedRoot)
    ));
}

#[test]
fn determinism_and_verify_read_only_guarantee() {
    // Tree A created in forward order
    let tree_a = TempDir::new().unwrap();
    write_file(&tree_a.path().join("alpha/one.txt"), b"111", 0o644);
    write_file(&tree_a.path().join("beta/two.sh"), b"222", 0o755);
    create_dir(&tree_a.path().join("gamma"));

    let m_a1 = seal(tree_a.path()).unwrap();
    let bytes_a1 = fs::read(tree_a.path().join(MANIFEST_FILENAME)).unwrap();

    // Sealing the same tree twice yields identical manifest bytes
    let m_a2 = seal(tree_a.path()).unwrap();
    let bytes_a2 = fs::read(tree_a.path().join(MANIFEST_FILENAME)).unwrap();
    assert_eq!(m_a1, m_a2);
    assert_eq!(bytes_a1, bytes_a2);

    // Tree B created in reverse order yields byte-identical manifest
    let tree_b = TempDir::new().unwrap();
    create_dir(&tree_b.path().join("gamma"));
    write_file(&tree_b.path().join("beta/two.sh"), b"222", 0o755);
    write_file(&tree_b.path().join("alpha/one.txt"), b"111", 0o644);

    let m_b = seal(tree_b.path()).unwrap();
    let bytes_b = fs::read(tree_b.path().join(MANIFEST_FILENAME)).unwrap();
    assert_eq!(m_a1, m_b);
    assert_eq!(bytes_a1, bytes_b);

    // Snapshot entire tree_a state before verify
    fn snapshot(root: &Path) -> BTreeMap<String, (u32, Option<Vec<u8>>)> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let meta = fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    out.insert(rel, (meta.mode(), None));
                    stack.push(path);
                } else {
                    out.insert(rel, (meta.mode(), Some(fs::read(&path).unwrap())));
                }
            }
        }
        out
    }

    let before = snapshot(tree_a.path());
    let rep_ok = verify(tree_a.path(), Some(&m_a1.root)).unwrap();
    assert_eq!(rep_ok.verdict, Verdict::Ok);
    let after_ok = snapshot(tree_a.path());
    assert_eq!(before, after_ok);

    // Even when verify detects a mismatch, it does not modify the tree
    fs::write(tree_a.path().join("alpha/one.txt"), b"999").unwrap();
    let before_mismatch = snapshot(tree_a.path());
    let rep_bad = verify(tree_a.path(), None).unwrap();
    assert_eq!(rep_bad.verdict, Verdict::Mismatch);
    let after_mismatch = snapshot(tree_a.path());
    assert_eq!(before_mismatch, after_mismatch);
}

#[test]
fn cli_seal_and_verify_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_hermetic-bundle");
    let dir = TempDir::new().unwrap();
    write_file(&dir.path().join("hello.txt"), b"world\n", 0o644);

    let seal_out = Command::new(bin)
        .arg("seal")
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(seal_out.status.code(), Some(0));
    let root = String::from_utf8(seal_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(root.starts_with("sha256:"));
    assert_eq!(root.len(), 71);

    // Verify ok -> exit 0
    let verify_ok = Command::new(bin)
        .arg("verify")
        .arg(dir.path())
        .arg("--root")
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(verify_ok.status.code(), Some(0));
    let report_json: serde_json::Value = serde_json::from_slice(&verify_ok.stdout).unwrap();
    assert_eq!(report_json["verdict"], "ok");

    // Verify mismatch -> exit 2
    fs::write(dir.path().join("hello.txt"), b"tampered\n").unwrap();
    let verify_mismatch = Command::new(bin)
        .arg("verify")
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(verify_mismatch.status.code(), Some(2));
    let mismatch_json: serde_json::Value = serde_json::from_slice(&verify_mismatch.stdout).unwrap();
    assert_eq!(mismatch_json["verdict"], "mismatch");

    // Error (missing directory) -> exit 1
    let missing = dir.path().join("does-not-exist");
    let verify_err = Command::new(bin)
        .arg("verify")
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(verify_err.status.code(), Some(1));
}

#[test]
fn manual_manifest_construction_and_caps() {
    let entry = ManifestEntry {
        path: "script.sh".to_string(),
        kind: EntryKind::File,
        mode: EntryMode::Mode0755,
        size: Some(0),
        sha256: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    };
    let manifest = Manifest {
        format: "hermetic-bundle/v1".to_string(),
        root: compute_root(std::slice::from_ref(&entry)).unwrap(),
        entries: vec![entry],
    };
    assert!(manifest.validate().is_ok());

    // Directory entry cannot have mode 0644
    let bad_dir_mode = Manifest {
        format: "hermetic-bundle/v1".to_string(),
        root: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        entries: vec![ManifestEntry {
            path: "somedir".to_string(),
            kind: EntryKind::Dir,
            mode: EntryMode::Mode0644,
            size: None,
            sha256: None,
        }],
    };
    assert!(bad_dir_mode.validate().is_err());

    // File entry missing sha256 or size is rejected
    let missing_file_sha = Manifest {
        format: "hermetic-bundle/v1".to_string(),
        root: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        entries: vec![ManifestEntry {
            path: "file.txt".to_string(),
            kind: EntryKind::File,
            mode: EntryMode::Mode0644,
            size: Some(10),
            sha256: None,
        }],
    };
    assert!(missing_file_sha.validate().is_err());
}

#[test]
fn root_paths_reject_symlink_ancestors_and_trailing_slashes() {
    let tree = TempDir::new().unwrap();
    create_dir(&tree.path().join("real/bundle"));
    seal(tree.path().join("real/bundle")).unwrap();
    symlink("real", tree.path().join("alias")).unwrap();
    let through_ancestor = tree.path().join("alias/bundle");
    assert!(matches!(
        seal(&through_ancestor),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::Symlink,
            ..
        })
    ));
    assert!(matches!(
        verify(&through_ancestor, None),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::Symlink,
            ..
        })
    ));
    symlink("real/bundle", tree.path().join("link")).unwrap();
    let trailing = format!("{}/link/", tree.path().display());
    assert!(matches!(
        seal(Path::new(&trailing)),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::Symlink,
            ..
        })
    ));
    assert!(matches!(
        verify(Path::new(&trailing), None),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::Symlink,
            ..
        })
    ));
}

#[test]
fn seal_checks_excluded_manifest_objects_before_writing() {
    let tree = TempDir::new().unwrap();
    let manifest = tree.path().join(MANIFEST_FILENAME);
    write_file(&tree.path().join("target"), b"preserve", 0o600);
    symlink("target", &manifest).unwrap();
    assert!(matches!(
        seal(tree.path()),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::Symlink,
            ..
        })
    ));
    assert!(fs::symlink_metadata(&manifest).unwrap().is_symlink());
    assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"preserve");
    fs::remove_file(&manifest).unwrap();
    fs::hard_link(tree.path().join("target"), &manifest).unwrap();
    assert!(matches!(
        seal(tree.path()),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::HardLink,
            ..
        })
    ));
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(matches!(
        seal(tree.path()),
        Err(BundleError::RefusedObject { .. })
    ));
    fs::remove_dir(&manifest).unwrap();
    let listener = UnixListener::bind(&manifest).unwrap();
    assert!(matches!(
        seal(tree.path()),
        Err(BundleError::RefusedObject {
            kind: RefusedKind::Socket,
            ..
        })
    ));
    drop(listener);
    fs::remove_file(&manifest).unwrap();
    match Command::new("mkfifo").arg(&manifest).status() {
        Ok(status) if status.success() => {
            assert!(matches!(
                seal(tree.path()),
                Err(BundleError::RefusedObject {
                    kind: RefusedKind::Fifo,
                    ..
                })
            ));
        }
        _ => eprintln!("skipping excluded-manifest FIFO fixture: mkfifo unavailable"),
    }
}

#[test]
fn reserved_manifest_name_participates_in_portability_rules() {
    for path in [
        "BUNDLE.MANIFEST.JSON",
        "bundle.manifest.json/hidden",
        "Bundle.Manifest.Json/hidden",
    ] {
        assert!(validate_relative_path(path).is_err(), "{path}");
    }
    assert!(validate_relative_path("sub/bundle.manifest.json").is_ok());
    let tree = TempDir::new().unwrap();
    write_file(&tree.path().join("BUNDLE.MANIFEST.JSON"), b"data", 0o644);
    assert!(seal(tree.path()).is_err());
    assert!(!tree.path().join(MANIFEST_FILENAME).exists());
}

#[test]
fn canonical_manifest_rejects_alternate_encodings_and_null_fields() {
    let root = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let whitespace = format!(r#"{{ "format":"hermetic-bundle/v1","entries":[],"root":"{root}"}}"#);
    let order = format!(r#"{{"root":"{root}","entries":[],"format":"hermetic-bundle/v1"}}"#);
    let null_size = format!(
        r#"{{"format":"hermetic-bundle/v1","entries":[{{"path":"sub","kind":"dir","mode":"0755","size":null}}],"root":"{root}"}}"#
    );
    let null_hash = null_size.replace("size", "sha256");
    for json in [whitespace, order, null_size, null_hash] {
        assert!(
            Manifest::from_json_bytes(json.as_bytes()).is_err(),
            "{json}"
        );
    }
}

#[test]
fn manifest_rejects_impossible_parent_structure() {
    let tree = TempDir::new().unwrap();
    write_file(&tree.path().join("a/b"), b"data", 0o644);
    let mut manifest = seal(tree.path()).unwrap();
    manifest.entries.remove(0);
    assert!(manifest.validate().is_err());
    let mut file_parent = manifest.entries[0].clone();
    file_parent.path = "a".to_string();
    manifest.entries.insert(0, file_parent);
    assert!(manifest.validate().is_err());
}

#[test]
fn public_hash_and_serialization_apis_enforce_input_caps() {
    let mut entry = ManifestEntry {
        path: "x".repeat(MAX_PATH_BYTES + 1),
        kind: EntryKind::File,
        mode: EntryMode::Mode0644,
        size: Some(0),
        sha256: Some("0".repeat(64)),
    };
    assert!(matches!(
        entry.to_canonical_json_bytes(),
        Err(BundleError::LimitExceeded {
            limit: "MAX_PATH_BYTES",
            ..
        })
    ));
    assert!(matches!(
        compute_root(&[entry.clone()]),
        Err(BundleError::LimitExceeded {
            limit: "MAX_PATH_BYTES",
            ..
        })
    ));
    entry.path = "file".to_string();
    entry.size = Some(hermetic_bundle::MAX_TOTAL_FILE_BYTES + 1);
    assert!(compute_root(&[entry.clone()]).is_err());
    let manifest = Manifest {
        format: "hermetic-bundle/v1".to_string(),
        entries: vec![entry],
        root: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    };
    assert!(manifest.to_canonical_json_bytes().is_err());
}

#[test]
fn manifest_errors_do_not_echo_supplied_values() {
    let secret = "/private/host-identity-and-secret";
    let root = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for json in [
        format!(r#"{{"format":"{secret}","entries":[],"root":"{root}"}}"#),
        format!(
            r#"{{"format":"hermetic-bundle/v1","entries":[],"root":"{root}","{secret}":true}}"#
        ),
        format!(
            r#"{{"format":"hermetic-bundle/v1","entries":[{{"path":"file","kind":"{secret}","mode":"0644"}}],"root":"{root}"}}"#
        ),
    ] {
        let error = Manifest::from_json_bytes(json.as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(secret), "{error}");
        assert!(!format!("{error:?}").contains(secret));
    }
    assert!(!validate_relative_path(secret)
        .unwrap_err()
        .to_string()
        .contains(secret));
}

#[test]
fn cli_closed_output_streams_return_error_without_panicking() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    fn closed_stream() -> Stdio {
        let (writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        Stdio::from(OwnedFd::from(writer))
    }
    let bin = env!("CARGO_BIN_EXE_hermetic-bundle");
    let tree = TempDir::new().unwrap();
    for command in ["seal", "verify"] {
        let output = Command::new(bin)
            .arg(command)
            .arg(tree.path())
            .stdout(closed_stream())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
    let output = Command::new(bin)
        .arg("invalid-command")
        .stderr(closed_stream())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}
