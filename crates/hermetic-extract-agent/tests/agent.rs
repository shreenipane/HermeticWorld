#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::process::Command;

use hermetic_extract_agent::{
    decode, decode_with_caps, extract, extract_with_hook, parse_task_class, CapName, Caps,
    DecodeError, ExtractError, ExtractReport, Record, SkippedEntry, SkippedKind, TaskClass,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

/// Builds one fixed 60-byte little-endian record header (flags and reserved bytes zero).
fn record_header(
    record_type: u8,
    path_len: u32,
    mode: u32,
    size: u64,
    record_count: u64,
    sha256: &[u8; 32],
) -> Vec<u8> {
    let mut h = vec![record_type, 0, 0, 0];
    h.extend_from_slice(&path_len.to_le_bytes());
    h.extend_from_slice(&mode.to_le_bytes());
    h.extend_from_slice(&size.to_le_bytes());
    h.extend_from_slice(&record_count.to_le_bytes());
    h.extend_from_slice(sha256);
    assert_eq!(h.len(), 60);
    h
}

fn write_file(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

#[cfg(unix)]
fn set_exec(path: &Path) {
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[test]
fn round_trip_and_each_change_kind() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    // Unchanged file (must NOT be emitted)
    write_file(&base.join("repo/unchanged.txt"), b"same content\n");
    write_file(&work.join("repo/unchanged.txt"), b"same content\n");

    // Modified file
    write_file(&base.join("repo/modified.txt"), b"before\n");
    write_file(&work.join("repo/modified.txt"), b"after\n");

    // Deleted file
    write_file(&base.join("repo/deleted.txt"), b"gone\n");

    // Deleted directory with nested file
    write_file(&base.join("repo/old_dir/nested.txt"), b"old\n");

    // Added directory + added regular file + added executable file
    write_file(&work.join("repo/new_dir/hello.txt"), b"hello\n");
    write_file(&work.join("repo/run.sh"), b"#!/bin/sh\necho hi\n");
    #[cfg(unix)]
    set_exec(&work.join("repo/run.sh"));

    // File replaced by directory
    write_file(&base.join("repo/morph_to_dir"), b"was file");
    write_file(&work.join("repo/morph_to_dir/inner.txt"), b"now dir");

    // Directory replaced by file
    write_file(&base.join("repo/morph_to_file/inner.txt"), b"was dir");
    write_file(&work.join("repo/morph_to_file"), b"now file");

    let mut stream = Vec::new();
    let report = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: "repo".to_string(),
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();

    assert!(report.skipped.is_empty());

    let records = decode(&stream[..]).unwrap();
    let expected_exec_mode = if cfg!(unix) { 0o755 } else { 0o644 };

    assert_eq!(records.len(), 12);
    assert_eq!(
        records[0],
        Record::Delete {
            path: "repo/deleted.txt".to_string()
        }
    );
    assert_eq!(
        records[1],
        Record::File {
            path: "repo/modified.txt".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"after\n").into(),
            data: b"after\n".to_vec(),
        }
    );
    assert_eq!(
        records[2],
        Record::Delete {
            path: "repo/morph_to_dir".to_string()
        }
    );
    assert_eq!(
        records[3],
        Record::Dir {
            path: "repo/morph_to_dir".to_string(),
            mode: 0o755,
        }
    );
    assert_eq!(
        records[4],
        Record::File {
            path: "repo/morph_to_dir/inner.txt".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"now dir").into(),
            data: b"now dir".to_vec(),
        }
    );
    assert_eq!(
        records[5],
        Record::Delete {
            path: "repo/morph_to_file".to_string()
        }
    );
    assert_eq!(
        records[6],
        Record::File {
            path: "repo/morph_to_file".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"now file").into(),
            data: b"now file".to_vec(),
        }
    );
    assert_eq!(
        records[7],
        Record::Dir {
            path: "repo/new_dir".to_string(),
            mode: 0o755,
        }
    );
    assert_eq!(
        records[8],
        Record::File {
            path: "repo/new_dir/hello.txt".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"hello\n").into(),
            data: b"hello\n".to_vec(),
        }
    );
    assert_eq!(
        records[9],
        Record::Delete {
            path: "repo/old_dir".to_string()
        }
    );
    assert_eq!(
        records[10],
        Record::File {
            path: "repo/run.sh".to_string(),
            mode: expected_exec_mode,
            sha256: Sha256::digest(b"#!/bin/sh\necho hi\n").into(),
            data: b"#!/bin/sh\necho hi\n".to_vec(),
        }
    );
    assert!(matches!(
        records[11],
        Record::End {
            record_count: 11,
            ..
        }
    ));
}

#[test]
fn round_trip_verifies_end_record_and_task_classes() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    write_file(&base.join("repo/a.txt"), b"v1");
    write_file(&work.join("repo/a.txt"), b"v2");
    write_file(&work.join("outside.txt"), b"ignored in patch");
    write_file(&work.join("artifacts/out.json"), b"{\"ok\":true}");

    // 1. Patch mode scoped to "repo" ignores "outside.txt" and "artifacts/out.json"
    let mut patch_stream = Vec::new();
    extract(
        &base,
        &work,
        &parse_task_class("patch:repo").unwrap(),
        &Caps::default(),
        &mut patch_stream,
    )
    .unwrap();
    let patch_records = decode(&patch_stream[..]).unwrap();
    assert_eq!(
        patch_records,
        vec![
            Record::File {
                path: "repo/a.txt".to_string(),
                mode: 0o644,
                sha256: Sha256::digest(b"v2").into(),
                data: b"v2".to_vec(),
            },
            Record::End {
                record_count: 1,
                total_bytes: 2,
            }
        ]
    );

    // 2. Artifact mode extracts only declared paths (and creates missing ancestor dir record)
    let mut art_stream = Vec::new();
    extract(
        &base,
        &work,
        &parse_task_class("artifact:artifacts/out.json").unwrap(),
        &Caps::default(),
        &mut art_stream,
    )
    .unwrap();
    let art_records = decode(&art_stream[..]).unwrap();
    assert_eq!(art_records.len(), 3);
    assert_eq!(
        art_records[0],
        Record::Dir {
            path: "artifacts".to_string(),
            mode: 0o755
        }
    );
    assert_eq!(
        art_records[1],
        Record::File {
            path: "artifacts/out.json".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"{\"ok\":true}").into(),
            data: b"{\"ok\":true}".to_vec(),
        }
    );
    assert!(matches!(
        art_records[2],
        Record::End {
            record_count: 2,
            ..
        }
    ));

    // 3. State mode emits nothing except header + end record with count 0
    let mut state_stream = Vec::new();
    extract(
        &base,
        &work,
        &parse_task_class("state").unwrap(),
        &Caps::default(),
        &mut state_stream,
    )
    .unwrap();
    let state_records = decode(&state_stream[..]).unwrap();
    assert_eq!(
        state_records,
        vec![Record::End {
            record_count: 0,
            total_bytes: 0,
        }]
    );
}

#[test]
fn git_ignored_at_any_depth() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    // .git at root, repo depth, and deeply nested submodule depth
    write_file(&base.join(".git/HEAD"), b"ref: refs/heads/old\n");
    write_file(&work.join(".git/HEAD"), b"ref: refs/heads/new\n");
    write_file(
        &work.join("repo/.git/objects/pack/huge.pack"),
        &vec![b'X'; 4096],
    );
    write_file(&base.join(".git/sub/.git/config"), b"[core]\n");
    write_file(&work.join("repo/kept.txt"), b"visible\n");

    // Set per_file_bytes cap smaller than huge.pack to prove .git is never even inspected
    let caps = Caps {
        max_file_bytes: 128,
        ..Caps::default()
    };

    let mut stream = Vec::new();
    let report = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &caps,
        &mut stream,
    )
    .unwrap();

    assert!(report.skipped.is_empty());
    let records = decode_with_caps(&stream[..], &caps).unwrap();
    assert_eq!(records.len(), 3); // Dir("repo"), File("repo/kept.txt"), End
    assert_eq!(
        records[0],
        Record::Dir {
            path: "repo".to_string(),
            mode: 0o755
        }
    );
    assert_eq!(
        records[1],
        Record::File {
            path: "repo/kept.txt".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"visible\n").into(),
            data: b"visible\n".to_vec(),
        }
    );
}

#[test]
fn skipped_kinds_listed_in_report_and_never_followed() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let outside = tmp.path().join("outside_secret");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&outside).unwrap();

    write_file(&outside.join("secret.txt"), b"DO NOT READ");
    write_file(&work.join("normal.txt"), b"ok");
    write_file(&work.join("hard_a.txt"), b"shared");
    fs::hard_link(work.join("hard_a.txt"), work.join("hard_b.txt")).unwrap();

    #[cfg(unix)]
    {
        symlink(outside.join("secret.txt"), work.join("sym_file")).unwrap();
        symlink(&outside, work.join("sym_dir")).unwrap();
    }

    let mut expected_skipped = vec![
        SkippedEntry {
            path: "hard_a.txt".to_string(),
            kind: SkippedKind::Hardlink,
        },
        SkippedEntry {
            path: "hard_b.txt".to_string(),
            kind: SkippedKind::Hardlink,
        },
    ];

    #[cfg(unix)]
    {
        expected_skipped.push(SkippedEntry {
            path: "sym_dir".to_string(),
            kind: SkippedKind::Symlink,
        });
        expected_skipped.push(SkippedEntry {
            path: "sym_file".to_string(),
            kind: SkippedKind::Symlink,
        });

        let fifo_path = work.join("my_fifo");
        if let Ok(status) = Command::new("mkfifo").arg(&fifo_path).status() {
            if status.success() {
                expected_skipped.push(SkippedEntry {
                    path: "my_fifo".to_string(),
                    kind: SkippedKind::Fifo,
                });
            }
        }
    }

    expected_skipped.sort();

    let mut stream = Vec::new();
    let report = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();

    assert_eq!(report.skipped, expected_skipped);

    let records = decode(&stream[..]).unwrap();
    assert_eq!(records.len(), 2); // Only File("normal.txt") and End
    assert_eq!(
        records[0],
        Record::File {
            path: "normal.txt".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"ok").into(),
            data: b"ok".to_vec(),
        }
    );
}

#[test]
fn file_changed_during_read_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let staging = tmp.path().join("staging");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&staging).unwrap();

    write_file(&work.join("target.txt"), b"initial content");
    write_file(&staging.join("swapped.txt"), b"tampered content!");

    let work_target = work.join("target.txt");
    let staged_swap = staging.join("swapped.txt");
    let swapped_once = RefCell::new(false);

    let mut hook = |rel_path: &str| -> std::io::Result<()> {
        if rel_path == "target.txt" && !*swapped_once.borrow() {
            *swapped_once.borrow_mut() = true;
            // Atomically replace target.txt between stat and read (changes dev/ino and size)
            fs::rename(&staged_swap, &work_target)?;
        }
        Ok(())
    };

    let mut stream = Vec::new();
    let err = extract_with_hook(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps::default(),
        &mut stream,
        Some(&mut hook),
    )
    .unwrap_err();

    assert_eq!(
        err,
        ExtractError::FileChangedDuringRead {
            path: "target.txt".to_string()
        }
    );
}

#[test]
fn every_cap_aborts_naming_cap_and_emits_nothing_further() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    write_file(&work.join("a.txt"), b"12345");
    write_file(&work.join("b.txt"), b"1234567890");
    write_file(&work.join("d1/d2/d3/deep_filename.txt"), b"x");

    // 1. Entries cap
    let mut out_entries = Vec::new();
    let err = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps {
            max_entries: 1,
            ..Caps::default()
        },
        &mut out_entries,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::CapExceeded {
            cap: CapName::Entries,
            ..
        }
    ));
    assert!(err.to_string().contains("entries"));
    // Directory collection exceeds the budget before emitting any records.
    assert_eq!(out_entries, b"HEXT\x01\x00\x00\x00");

    // 2. Depth cap
    let mut out_depth = Vec::new();
    let err = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps {
            max_depth: 2,
            ..Caps::default()
        },
        &mut out_depth,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::CapExceeded {
            cap: CapName::Depth,
            ..
        }
    ));
    assert!(err.to_string().contains("depth"));

    // 3. Path length cap
    let mut out_path_len = Vec::new();
    let err = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps {
            max_path_len: 8,
            ..Caps::default()
        },
        &mut out_path_len,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::CapExceeded {
            cap: CapName::PathLength,
            ..
        }
    ));
    assert!(err.to_string().contains("path_length"));

    // 4. Per-file bytes cap
    let mut out_file_bytes = Vec::new();
    let err = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps {
            max_file_bytes: 6,
            ..Caps::default()
        },
        &mut out_file_bytes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::CapExceeded {
            cap: CapName::PerFileBytes,
            ..
        }
    ));
    assert!(err.to_string().contains("per_file_bytes"));
    // "a.txt" (5 bytes) was emitted, then "b.txt" (10 bytes > 6) aborted before emitting anything further
    let len_after_a = out_file_bytes.len();
    assert_eq!(len_after_a, 8 + 60 + 5 + 5);

    // 5. Total bytes cap
    let mut out_total_bytes = Vec::new();
    let err = extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps {
            max_total_bytes: 12,
            ..Caps::default()
        },
        &mut out_total_bytes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::CapExceeded {
            cap: CapName::TotalBytes,
            ..
        }
    ));
    assert!(err.to_string().contains("total_bytes"));
    assert_eq!(out_total_bytes.len(), 8 + 60 + 5 + 5);

    // Decoder also enforces caps before allocating untrusted lengths
    let mut crafted = Vec::new();
    crafted.extend_from_slice(b"HEXT");
    crafted.extend_from_slice(&1u32.to_le_bytes());
    crafted.extend_from_slice(&record_header(1, 5, 0o644, u64::MAX, 0, &[0u8; 32]));
    crafted.extend_from_slice(b"x.txt");
    let dec_err = decode(&crafted[..]).unwrap_err();
    assert!(matches!(
        dec_err,
        DecodeError::CapExceeded {
            cap: CapName::PerFileBytes,
            ..
        }
    ));
}

#[test]
fn end_record_count_and_total_bytes_checked() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    write_file(&work.join("one.txt"), b"alpha");
    write_file(&work.join("two.txt"), b"beta");

    let mut stream = Vec::new();
    extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();

    let records = decode(&stream[..]).unwrap();
    let end_offset = stream.len() - 60;
    assert_eq!(
        records.last().unwrap(),
        &Record::End {
            record_count: 2,
            total_bytes: 9,
        }
    );

    // Corrupting the end-record total bytes fails with EndTotalBytesMismatch
    let mut bad_total = stream.clone();
    bad_total[end_offset + 12] = 99;
    assert_eq!(
        decode(&bad_total[..]).unwrap_err(),
        DecodeError::EndTotalBytesMismatch {
            expected: 9,
            actual: 99,
        }
    );

    // A nonzero end-record hash field is refused
    let mut bad_hash = stream.clone();
    let last_idx = bad_hash.len() - 1;
    bad_hash[last_idx] ^= 0xff;
    assert_eq!(
        decode(&bad_hash[..]).unwrap_err(),
        DecodeError::NonZeroHash { record_type: 4 }
    );

    // Corrupting the end-record count fails with EndRecordCountMismatch
    let mut bad_count = stream.clone();
    let count_offset = end_offset + 20;
    bad_count[count_offset] = 99;
    assert_eq!(
        decode(&bad_count[..]).unwrap_err(),
        DecodeError::EndRecordCountMismatch {
            expected: 2,
            actual: 99,
        }
    );
}

#[test]
fn truncated_stream_at_every_offset_fails_without_panic() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    write_file(&base.join("rm.txt"), b"bye");
    write_file(&work.join("dir/hello.txt"), b"world!");

    let mut stream = Vec::new();
    extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();

    assert!(decode(&stream[..]).is_ok());

    for offset in 0..stream.len() {
        let res = decode(&stream[..offset]);
        assert!(
            res.is_err(),
            "expected error for truncated stream at offset {}/{}",
            offset,
            stream.len()
        );
    }

    // Trailing bytes after end record must also fail
    let mut with_trailing = stream.clone();
    with_trailing.push(0x00);
    assert_eq!(
        decode(&with_trailing[..]).unwrap_err(),
        DecodeError::TrailingBytes
    );
}

#[test]
fn known_answer_stream_bytes_for_tiny_tree() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    write_file(&base.join("old.txt"), b"gone");
    write_file(&work.join("hi.txt"), b"hi\n");

    let mut actual_stream = Vec::new();
    extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps::default(),
        &mut actual_stream,
    )
    .unwrap();

    // Hand-construct exact wire format bytes:
    let mut expected = Vec::new();
    // Header: magic b"HEXT", version u32 = 1 LE
    expected.extend_from_slice(b"HEXT");
    expected.extend_from_slice(&1u32.to_le_bytes());

    // Record 0: File "hi.txt" (6 bytes), mode 0o644, size 3, sha256("hi\n"), bytes b"hi\n"
    let hi_sha: [u8; 32] = Sha256::digest(b"hi\n").into();
    expected.extend_from_slice(&record_header(1, 6, 0o644, 3, 0, &hi_sha));
    expected.extend_from_slice(b"hi.txt");
    expected.extend_from_slice(b"hi\n");

    // Record 1: Delete "old.txt" (7 bytes), mode 0, size 0, sha256 = [0; 32]
    expected.extend_from_slice(&record_header(3, 7, 0, 0, 0, &[0u8; 32]));
    expected.extend_from_slice(b"old.txt");

    // Record 2: End, path_len 0, mode 0, size = total file bytes (3), record_count = 2
    expected.extend_from_slice(&record_header(4, 0, 0, 3, 2, &[0u8; 32]));

    assert_eq!(actual_stream, expected);
}

#[test]
fn cli_binary_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let out_file = tmp.path().join("out.hext");
    let report_file = tmp.path().join("report.json");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();

    write_file(&base.join("repo/hello.txt"), b"old");
    write_file(&work.join("repo/hello.txt"), b"new");
    #[cfg(unix)]
    symlink("hello.txt", work.join("repo/link.txt")).unwrap();

    let bin = env!("CARGO_BIN_EXE_hermetic-extract-agent");
    let status = Command::new(bin)
        .arg("--base")
        .arg(&base)
        .arg("--work")
        .arg(&work)
        .arg("--class")
        .arg("patch:repo")
        .arg("--out")
        .arg(&out_file)
        .arg("--report")
        .arg(&report_file)
        .status()
        .unwrap();

    assert!(status.success());

    let stream_bytes = fs::read(&out_file).unwrap();
    let records = decode(&stream_bytes[..]).unwrap();
    assert_eq!(records.len(), 2);

    let report_json = fs::read_to_string(&report_file).unwrap();
    let host_tmp_str = tmp.path().to_str().unwrap();
    assert!(!report_json.contains(host_tmp_str));
    assert!(!stream_bytes
        .windows(host_tmp_str.len())
        .any(|w| w == host_tmp_str.as_bytes()));

    let report: ExtractReport = serde_json::from_str(&report_json).unwrap();
    #[cfg(unix)]
    assert_eq!(
        report.skipped,
        vec![SkippedEntry {
            path: "repo/link.txt".to_string(),
            kind: SkippedKind::Symlink,
        }]
    );
    #[cfg(not(unix))]
    assert!(report.skipped.is_empty());
}

#[cfg(unix)]
#[test]
fn regression_artifact_target_below_symlinked_ancestor_is_not_read() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();
    write_file(&outside.join("secret.txt"), b"OUTSIDE THE WORK TREE");
    symlink(&outside, work.join("link")).unwrap();

    let mut stream = Vec::new();
    let report = extract(
        &base,
        &work,
        &TaskClass::Artifact {
            paths: vec!["link/secret.txt".to_string(), "link/other".to_string()],
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();

    let records = decode(&stream[..]).unwrap();
    assert_eq!(records.len(), 1, "only the end record: {records:?}");
    assert!(matches!(records[0], Record::End { .. }));
    assert_eq!(
        report.skipped,
        vec![SkippedEntry {
            path: "link".to_string(),
            kind: SkippedKind::Symlink,
        }]
    );

    // Same for a patch repository directory below a symlinked ancestor.
    write_file(&outside.join("repo/leak.txt"), b"leak");
    let mut stream = Vec::new();
    extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: "link/repo".to_string(),
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();
    let records = decode(&stream[..]).unwrap();
    assert_eq!(records.len(), 1, "only the end record: {records:?}");
}

#[cfg(unix)]
#[test]
fn regression_base_symlink_replaced_by_real_dir_is_not_compared_through_symlink() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();
    write_file(&outside.join("f.txt"), b"same bytes");
    symlink(&outside, base.join("lib")).unwrap();
    write_file(&work.join("lib/f.txt"), b"same bytes");

    let mut stream = Vec::new();
    extract(
        &base,
        &work,
        &TaskClass::Patch {
            repo_dir: String::new(),
        },
        &Caps::default(),
        &mut stream,
    )
    .unwrap();

    let records = decode(&stream[..]).unwrap();
    assert!(
        records.contains(&Record::File {
            path: "lib/f.txt".to_string(),
            mode: 0o644,
            sha256: Sha256::digest(b"same bytes").into(),
            data: b"same bytes".to_vec(),
        }),
        "new file under a new real directory must be emitted: {records:?}"
    );
}

#[cfg(unix)]
#[test]
fn regression_fifo_swapped_in_after_stat_does_not_block() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();
    write_file(&work.join("target.txt"), b"");
    let target = work.join("target.txt");

    let (tx, rx) = std::sync::mpsc::channel();
    let base_t = base.clone();
    let work_t = work.clone();
    let target_t = target.clone();
    std::thread::spawn(move || {
        let mut hook = |rel_path: &str| -> std::io::Result<()> {
            if rel_path == "target.txt" {
                fs::remove_file(&target_t)?;
                let status = Command::new("mkfifo").arg(&target_t).status()?;
                if !status.success() {
                    return Err(std::io::Error::other("mkfifo failed"));
                }
            }
            Ok(())
        };
        let mut stream = Vec::new();
        let res = extract_with_hook(
            &base_t,
            &work_t,
            &TaskClass::Patch {
                repo_dir: String::new(),
            },
            &Caps::default(),
            &mut stream,
            Some(&mut hook),
        );
        let _ = tx.send(res.map(|_| ()));
    });

    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(res) => assert_eq!(
            res,
            Err(ExtractError::FileChangedDuringRead {
                path: "target.txt".to_string()
            })
        ),
        Err(_) => {
            // Unblock the reader so the test process can exit, then fail.
            let _ = fs::OpenOptions::new().write(true).open(&target);
            panic!("extraction blocked opening a FIFO swapped in after stat");
        }
    }
}

#[test]
fn regression_cli_failed_extraction_leaves_no_partial_output() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let out_file = tmp.path().join("out.hext");
    let report_file = tmp.path().join("report.json");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&work).unwrap();
    // A file over the default per-file cap makes extraction fail after the header was written.
    let big = fs::File::create(work.join("big.bin")).unwrap();
    big.set_len(Caps::default().max_file_bytes + 1).unwrap();
    drop(big);

    let bin = env!("CARGO_BIN_EXE_hermetic-extract-agent");
    let status = Command::new(bin)
        .arg("--base")
        .arg(&base)
        .arg("--work")
        .arg(&work)
        .arg("--class")
        .arg("patch:")
        .arg("--out")
        .arg(&out_file)
        .arg("--report")
        .arg(&report_file)
        .status()
        .unwrap();

    assert!(!status.success());
    assert!(!out_file.exists(), "no partial stream may be left behind");
    assert!(!report_file.exists());
    let leftovers: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        leftovers.len(),
        2,
        "only base and work remain: {leftovers:?}"
    );
}

#[test]
fn review_type_replacements_charge_each_record() {
    for kind in ["file_to_dir", "dir_to_file", "ancestor"] {
        let base = TempDir::new().unwrap();
        let work = TempDir::new().unwrap();
        if kind == "dir_to_file" {
            fs::create_dir(base.path().join("x")).unwrap();
            write_file(&work.path().join("x"), b"new");
        } else {
            write_file(&base.path().join("x"), b"old");
            fs::create_dir(work.path().join("x")).unwrap();
            if kind == "ancestor" {
                write_file(&work.path().join("x/child"), b"new");
            }
        }
        let required = if kind == "ancestor" { 3 } else { 2 };
        let class = TaskClass::Artifact {
            paths: vec![if kind == "ancestor" { "x/child" } else { "x" }.into()],
        };
        let mut caps = Caps {
            max_entries: required - 1,
            ..Caps::default()
        };
        let mut stream = Vec::new();
        assert!(
            matches!(
                extract(base.path(), work.path(), &class, &caps, &mut stream),
                Err(ExtractError::CapExceeded {
                    cap: CapName::Entries,
                    ..
                })
            ),
            "accepted {kind}"
        );
        caps.max_entries = required;
        stream.clear();
        extract(base.path(), work.path(), &class, &caps, &mut stream).unwrap();
        assert_eq!(
            decode_with_caps(stream.as_slice(), &caps).unwrap().len(),
            required + 1 // Includes the End record, which is not charged against the cap.
        );
    }
}

#[cfg(unix)]
#[test]
fn review_mode_change_between_probe_and_read_is_rejected() {
    let base = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    for root in [base.path(), work.path()] {
        write_file(&root.join("x"), b"same");
        fs::set_permissions(root.join("x"), fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut hook =
        |_: &str| fs::set_permissions(work.path().join("x"), fs::Permissions::from_mode(0o755));
    let mut stream = Vec::new();
    assert!(
        matches!(extract_with_hook(base.path(), work.path(), &TaskClass::Patch { repo_dir: String::new() }, &Caps::default(), &mut stream, Some(&mut hook)), Err(ExtractError::FileChangedDuringRead { path }) if path == "x")
    );
}
