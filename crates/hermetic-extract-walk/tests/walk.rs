use hermetic_extract_walk::{
    diff_trees, CapKind, Caps, Change, ChangeKind, EntryKind, RefusedEntry, RefusedKind, TaskClass,
    WalkError,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

fn write_file(root: &Path, rel: &str, bytes: &[u8]) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&full, bytes).unwrap();
}

#[cfg(unix)]
fn set_exec(root: &Path, rel: &str, exec: bool) {
    let full = root.join(rel);
    let mode = if exec { 0o755 } else { 0o644 };
    fs::set_permissions(&full, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn test_added_file_and_dir() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(work.path(), "new_dir/hello.txt", b"hello\n");
    #[cfg(unix)]
    set_exec(work.path(), "new_dir/hello.txt", true);

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    assert_eq!(res.changes.len(), 2);

    assert_eq!(
        res.changes[0],
        Change {
            change: ChangeKind::Added,
            kind: EntryKind::Dir,
            mode: None,
            path: "new_dir".to_string(),
            sha256: None,
            size: None,
        }
    );

    let expected_mode = if cfg!(unix) { "0755" } else { "0644" };
    assert_eq!(
        res.changes[1],
        Change {
            change: ChangeKind::Added,
            kind: EntryKind::File,
            mode: Some(expected_mode.to_string()),
            path: "new_dir/hello.txt".to_string(),
            sha256: Some(
                "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".to_string()
            ),
            size: Some(6),
        }
    );
}

#[test]
fn test_modified_content_and_unchanged_ignored() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(base.path(), "same.txt", b"unchanged");
    write_file(work.path(), "same.txt", b"unchanged");

    write_file(base.path(), "edit.txt", b"version 1");
    write_file(work.path(), "edit.txt", b"version 2!");

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    assert_eq!(res.changes.len(), 1);
    assert_eq!(res.changes[0].change, ChangeKind::Modified);
    assert_eq!(res.changes[0].kind, EntryKind::File);
    assert_eq!(res.changes[0].path, "edit.txt");
    assert_eq!(res.changes[0].size, Some(10));
    assert_eq!(res.changes[0].mode.as_deref(), Some("0644"));
    assert!(res.changes[0].sha256.is_some());
}

#[test]
#[cfg(unix)]
fn test_mode_only_change() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(base.path(), "script.sh", b"#!/bin/sh\necho hi\n");
    write_file(work.path(), "script.sh", b"#!/bin/sh\necho hi\n");
    set_exec(base.path(), "script.sh", false);
    set_exec(work.path(), "script.sh", true);

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    assert_eq!(res.changes.len(), 1);
    assert_eq!(res.changes[0].change, ChangeKind::Modified);
    assert_eq!(res.changes[0].path, "script.sh");
    assert_eq!(res.changes[0].mode.as_deref(), Some("0755"));
    assert_eq!(res.changes[0].size, Some(18));
}

#[test]
fn test_deleted_file_and_dir() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(base.path(), "obsolete/leaf.txt", b"gone");
    write_file(base.path(), "keep.txt", b"stay");
    write_file(work.path(), "keep.txt", b"stay");

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    assert_eq!(
        res.changes,
        vec![
            Change {
                change: ChangeKind::Deleted,
                kind: EntryKind::Dir,
                mode: None,
                path: "obsolete".to_string(),
                sha256: None,
                size: None,
            },
            Change {
                change: ChangeKind::Deleted,
                kind: EntryKind::File,
                mode: None,
                path: "obsolete/leaf.txt".to_string(),
                sha256: None,
                size: None,
            },
        ]
    );
}

#[test]
fn test_type_change_file_to_dir_and_dir_to_file() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    // File in base -> Dir in work
    write_file(base.path(), "was_file", b"flat");
    write_file(work.path(), "was_file/inside.txt", b"nested");

    // Dir in base -> File in work
    write_file(base.path(), "was_dir/old.txt", b"old");
    write_file(work.path(), "was_dir", b"now a file");

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    assert_eq!(res.changes.len(), 3);

    assert_eq!(
        res.changes[0],
        Change {
            change: ChangeKind::TypeChanged,
            kind: EntryKind::File,
            mode: Some("0644".to_string()),
            path: "was_dir".to_string(),
            sha256: Some(
                "92af885f330ed4b19948c1dd44dbed553840556063d5061346be12d7a06476d0".to_string()
            ),
            size: Some(10),
        }
    );

    assert_eq!(
        res.changes[1],
        Change {
            change: ChangeKind::TypeChanged,
            kind: EntryKind::Dir,
            mode: None,
            path: "was_file".to_string(),
            sha256: None,
            size: None,
        }
    );

    assert_eq!(res.changes[2].change, ChangeKind::Added);
    assert_eq!(res.changes[2].path, "was_file/inside.txt");
}

#[test]
fn test_git_ignored_dir_file_and_nested() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    // Base has a .git directory that gets removed in work, plus a nested .git file in work.
    write_file(base.path(), ".git/HEAD", b"ref: refs/heads/main\n");
    write_file(work.path(), ".git", b"gitdir: /host/secret/path");
    write_file(work.path(), "sub/.git/config", b"[core]\n");
    write_file(work.path(), "sub/nested/.git", b"gitfile");
    write_file(work.path(), "sub/real.txt", b"visible");

    // Even with a tiny max_file_size, oversized .git files are never opened or read.
    let caps = Caps {
        max_file_size: 10,
        ..Caps::default()
    };

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &caps,
    )
    .unwrap();

    assert!(res.refused.is_empty());
    let paths: Vec<&str> = res.changes.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(paths, vec!["sub", "sub/nested", "sub/real.txt"]);
}

#[test]
fn test_patch_scope_ignores_outside_repo_dir() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(base.path(), "repo/a.txt", b"old");
    write_file(work.path(), "repo/a.txt", b"new");
    write_file(work.path(), "outside/leak.txt", b"ignored");
    write_file(base.path(), "outside_deleted.txt", b"ignored");

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("repo"),
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    assert_eq!(res.changes.len(), 1);
    assert_eq!(res.changes[0].path, "repo/a.txt");
    assert_eq!(res.changes[0].change, ChangeKind::Modified);

    // Reject parent traversal and absolute scope paths.
    assert!(matches!(
        diff_trees(
            base.path(),
            work.path(),
            TaskClass::Patch {
                repo_dir: PathBuf::from("../escape"),
            },
            &Caps::default(),
        ),
        Err(WalkError::InvalidScopePath { .. })
    ));
}

#[test]
fn test_artifact_scope_extracts_only_declared_paths() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(work.path(), "artifacts/report.json", b"{\"ok\":true}");
    write_file(work.path(), "artifacts/logs/run.log", b"line1\n");
    write_file(work.path(), "untracked/noise.txt", b"ignore me");

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Artifact {
            paths: vec![
                PathBuf::from("artifacts/report.json"),
                PathBuf::from("artifacts/logs"),
                PathBuf::from("artifacts/missing.txt"),
            ],
        },
        &Caps::default(),
    )
    .unwrap();

    assert!(res.refused.is_empty());
    let paths: Vec<&str> = res.changes.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "artifacts/logs",
            "artifacts/logs/run.log",
            "artifacts/report.json"
        ]
    );
}

#[test]
fn test_state_class_returns_empty_set() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(work.path(), "added.txt", b"hello");

    let res = diff_trees(base.path(), work.path(), TaskClass::State, &Caps::default()).unwrap();
    assert!(res.changes.is_empty());
    assert!(res.refused.is_empty());
}

#[test]
#[cfg(unix)]
fn test_refused_symlink_and_hard_link_and_fifo() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();

    write_file(external.path(), "secret.txt", b"top secret");
    write_file(work.path(), "good.txt", b"clean");

    // 1. Symlink pointing outside work tree
    symlink(
        external.path().join("secret.txt"),
        work.path().join("bad_link"),
    )
    .unwrap();

    // 2. Hard link (st_nlink == 2)
    write_file(work.path(), "hl_a.txt", b"shared inode");
    fs::hard_link(work.path().join("hl_a.txt"), work.path().join("hl_b.txt")).unwrap();

    // 3. FIFO (named pipe) if platform supports mkfifo
    let fifo_path = work.path().join("pipe.fifo");
    let fifo_created = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !fifo_created {
        eprintln!("skipping FIFO assertion: mkfifo unavailable on this platform");
    }

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    // Valid file is still extracted.
    assert_eq!(res.changes.len(), 1);
    assert_eq!(res.changes[0].path, "good.txt");

    assert!(res.refused.contains(&RefusedEntry {
        kind: RefusedKind::Symlink,
        path: "bad_link".to_string(),
    }));
    assert!(res.refused.contains(&RefusedEntry {
        kind: RefusedKind::HardLink,
        path: "hl_a.txt".to_string(),
    }));
    assert!(res.refused.contains(&RefusedEntry {
        kind: RefusedKind::HardLink,
        path: "hl_b.txt".to_string(),
    }));
    if fifo_created {
        assert!(res.refused.contains(&RefusedEntry {
            kind: RefusedKind::Fifo,
            path: "pipe.fifo".to_string(),
        }));
    }
}

#[test]
#[cfg(unix)]
fn test_refused_non_utf8_path() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(work.path(), "valid.txt", b"ok");
    let bad_name = OsString::from_vec(vec![b'b', b'a', b'd', 0xff, b'f', b'i', b'l', b'e']);
    fs::write(work.path().join(&bad_name), b"non-utf8").unwrap();

    let res = diff_trees(
        base.path(),
        work.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    assert_eq!(res.changes.len(), 1);
    assert_eq!(res.changes[0].path, "valid.txt");
    assert_eq!(res.refused.len(), 1);
    assert_eq!(res.refused[0].kind, RefusedKind::NonUtf8Path);
    assert!(!res.refused[0].path.contains('\u{FFFD}'));
    assert!(res.refused[0].path.contains("626164ff66696c65"));
}

#[test]
fn test_caps_fail_closed_for_all_five_limits() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    write_file(work.path(), "a/b/c/deep_file.txt", b"0123456789");
    write_file(work.path(), "second_file.txt", b"abcdefghij");

    let scope = TaskClass::Patch {
        repo_dir: PathBuf::from("."),
    };

    // 1. max_entries_walked
    let err = diff_trees(
        base.path(),
        work.path(),
        scope.clone(),
        &Caps {
            max_entries_walked: 2,
            ..Caps::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        WalkError::CapExceeded {
            cap: CapKind::MaxEntriesWalked,
            ..
        }
    ));
    assert!(err.to_string().contains("max_entries_walked"));

    // 2. max_depth
    let err = diff_trees(
        base.path(),
        work.path(),
        scope.clone(),
        &Caps {
            max_depth: 2,
            ..Caps::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        WalkError::CapExceeded {
            cap: CapKind::MaxDepth,
            ..
        }
    ));
    assert!(err.to_string().contains("max_depth"));

    // 3. max_file_size
    let err = diff_trees(
        base.path(),
        work.path(),
        scope.clone(),
        &Caps {
            max_file_size: 5,
            ..Caps::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        WalkError::CapExceeded {
            cap: CapKind::MaxFileSize,
            ..
        }
    ));
    assert!(err.to_string().contains("max_file_size"));

    // 4. max_total_bytes_hashed
    let err = diff_trees(
        base.path(),
        work.path(),
        scope.clone(),
        &Caps {
            max_total_bytes_hashed: 15,
            ..Caps::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        WalkError::CapExceeded {
            cap: CapKind::MaxTotalBytesHashed,
            ..
        }
    ));
    assert!(err.to_string().contains("max_total_bytes_hashed"));

    // 5. max_path_length
    let err = diff_trees(
        base.path(),
        work.path(),
        scope,
        &Caps {
            max_path_length: 8,
            ..Caps::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        WalkError::CapExceeded {
            cap: CapKind::MaxPathLength,
            ..
        }
    ));
    assert!(err.to_string().contains("max_path_length"));
}

#[test]
fn test_known_answer_json_and_determinism() {
    let base1 = TempDir::new().unwrap();
    let work1 = TempDir::new().unwrap();
    write_file(base1.path(), "del.txt", b"old");
    write_file(work1.path(), "add.txt", b"hello\n");

    let base2 = TempDir::new().unwrap();
    let work2 = TempDir::new().unwrap();
    write_file(work2.path(), "add.txt", b"hello\n");
    write_file(base2.path(), "del.txt", b"old");

    let cs1 = diff_trees(
        base1.path(),
        work1.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();
    let cs2 = diff_trees(
        base2.path(),
        work2.path(),
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        },
        &Caps::default(),
    )
    .unwrap();

    let json1 = cs1.to_canonical_json().unwrap();
    let json2 = cs2.to_canonical_json().unwrap();
    assert_eq!(json1, json2);

    let expected = concat!(
        r#"{"changes":["#,
        r#"{"change":"added","kind":"file","mode":"0644","path":"add.txt","#,
        r#""sha256":"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03","size":6},"#,
        r#"{"change":"deleted","kind":"file","path":"del.txt"}"#,
        r#"],"refused":[]}"#
    );
    assert_eq!(json1, expected);

    // Ensure no host temporary paths leak into output.
    let base1_str = base1.path().to_string_lossy();
    let work1_str = work1.path().to_string_lossy();
    assert!(!json1.contains(base1_str.as_ref()));
    assert!(!json1.contains(work1_str.as_ref()));
}

#[test]
#[cfg(unix)]
fn test_cli_binary_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_hermetic-extract-walk");

    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    write_file(work.path(), "ok.txt", b"hello\n");

    // Exit 0: clean run with no refused entries
    let out_ok = Command::new(bin)
        .arg(base.path())
        .arg(work.path())
        .output()
        .unwrap();
    assert_eq!(out_ok.status.code(), Some(0));
    let stdout_ok = String::from_utf8(out_ok.stdout).unwrap();
    assert!(stdout_ok.trim().starts_with("{\"changes\":["));

    // Exit 2: refused entry present, ChangeSet still printed
    symlink("ok.txt", work.path().join("sym")).unwrap();
    let out_refused = Command::new(bin)
        .arg(base.path())
        .arg(work.path())
        .output()
        .unwrap();
    assert_eq!(out_refused.status.code(), Some(2));
    let stdout_refused = String::from_utf8(out_refused.stdout).unwrap();
    assert!(stdout_refused.contains("\"refused\":[{\"kind\":\"symlink\",\"path\":\"sym\"}]"));

    // Exit 1: cap exceeded (fail closed)
    let out_err = Command::new(bin)
        .arg("--max-file-size")
        .arg("2")
        .arg(base.path())
        .arg(work.path())
        .output()
        .unwrap();
    assert_eq!(out_err.status.code(), Some(1));
    assert!(out_err.stdout.is_empty());
}
