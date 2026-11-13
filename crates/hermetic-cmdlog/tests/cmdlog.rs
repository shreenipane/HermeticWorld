#![forbid(unsafe_code)]

use std::fs;
use std::io::Cursor;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

use hermetic_cmdlog::{
    encode_sha256_prefixed, hash_output_bytes, hash_output_reader, verify, ChainError, CmdLog,
    Entry, EntryKind, EntryPayload, Head, EMPTY_SHA256, GENESIS_PREV, MAX_LINE_BYTES,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256_str(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out: [u8; 32] = h.finalize().into();
    encode_sha256_prefixed(&out)
}

fn write_log_file(path: &std::path::Path, content: impl AsRef<[u8]>) {
    fs::write(path, content).expect("write log file");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path).expect("meta").permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).expect("set permissions 0600");
    }
}

#[test]
fn req1_known_answer_head_for_fixed_3_entry_log() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("known.jsonl");

    let (stdout0_hash, stdout0_len) = hash_output_bytes(b"hello\n").expect("hash stdout");
    assert_eq!(stdout0_len, 6);
    assert_eq!(
        stdout0_hash,
        "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    );

    let mut log = CmdLog::open(&log_path).expect("open new log");
    assert_eq!(log.head(), (0, GENESIS_PREV.to_string()));

    let h0 = log
        .append(EntryPayload::exec(
            vec!["echo".to_string(), "hello".to_string()],
            Some(0),
            stdout0_hash,
            EMPTY_SHA256,
            stdout0_len,
            0,
            false,
        ))
        .expect("append entry 0");

    let expected_line_0 = r#"{"argv":["echo","hello"],"exit":0,"kind":"exec","prev":"sha256:0000000000000000000000000000000000000000000000000000000000000000","seq":0,"stderr_len":0,"stderr_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_len":6,"stdout_sha256":"sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03","truncated":false}"#;
    let expected_h0 = sha256_str(expected_line_0);
    assert_eq!(
        h0,
        Head {
            seq: 0,
            head: expected_h0.clone()
        }
    );
    assert_eq!(log.head(), (0, expected_h0.clone()));

    let h1 = log
        .append(EntryPayload::upload(
            "/workspace/main.rs",
            Some(0),
            EMPTY_SHA256,
            EMPTY_SHA256,
            0,
            0,
            false,
        ))
        .expect("append entry 1");

    let expected_line_1 = format!(
        r#"{{"exit":0,"kind":"upload","path":"/workspace/main.rs","prev":"{expected_h0}","seq":1,"stderr_len":0,"stderr_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_len":0,"stdout_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","truncated":false}}"#
    );
    let expected_h1 = sha256_str(&expected_line_1);
    assert_eq!(
        h1,
        Head {
            seq: 1,
            head: expected_h1.clone()
        }
    );

    let h2 = log
        .append(EntryPayload::status(
            None,
            EMPTY_SHA256,
            EMPTY_SHA256,
            0,
            0,
            false,
        ))
        .expect("append entry 2");

    let expected_line_2 = format!(
        r#"{{"exit":null,"kind":"status","prev":"{expected_h1}","seq":2,"stderr_len":0,"stderr_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_len":0,"stdout_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","truncated":false}}"#
    );
    let expected_h2 = sha256_str(&expected_line_2);
    assert_eq!(
        h2,
        Head {
            seq: 2,
            head: expected_h2.clone()
        }
    );
    assert_eq!(log.head(), (2, expected_h2.clone()));

    let raw = fs::read_to_string(&log_path).expect("read log file");
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(
        lines,
        vec![
            expected_line_0,
            expected_line_1.as_str(),
            expected_line_2.as_str()
        ]
    );

    let verified = verify(&log_path).expect("verify 3-entry log");
    assert_eq!(
        verified,
        Head {
            seq: 2,
            head: expected_h2
        }
    );
}

#[test]
fn req1_kind_specific_fields_enforced() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("invalid_kind.jsonl");
    let mut log = CmdLog::open(&log_path).expect("open log");

    // Exec without argv must fail.
    let bad_exec = EntryPayload {
        kind: EntryKind::Exec,
        argv: None,
        path: None,
        exit: Some(0),
        stdout_sha256: EMPTY_SHA256.to_string(),
        stderr_sha256: EMPTY_SHA256.to_string(),
        stdout_len: 0,
        stderr_len: 0,
        truncated: false,
    };
    assert!(matches!(
        log.append(bad_exec),
        Err(ChainError::InvalidField { .. })
    ));

    // Upload with argv must fail.
    let bad_upload = EntryPayload {
        kind: EntryKind::Upload,
        argv: Some(vec!["cp".to_string()]),
        path: Some("/tmp/x".to_string()),
        exit: Some(0),
        stdout_sha256: EMPTY_SHA256.to_string(),
        stderr_sha256: EMPTY_SHA256.to_string(),
        stdout_len: 0,
        stderr_len: 0,
        truncated: false,
    };
    assert!(matches!(
        log.append(bad_upload),
        Err(ChainError::InvalidField { .. })
    ));

    // Status with path on disk must fail verify at line 1.
    let raw_bad_status = r#"{"exit":null,"kind":"status","path":"/bad","prev":"sha256:0000000000000000000000000000000000000000000000000000000000000000","seq":0,"stderr_len":0,"stderr_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_len":0,"stdout_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","truncated":false}"#;
    fs::write(&log_path, format!("{raw_bad_status}\n")).expect("write bad status");
    let err = verify(&log_path).expect_err("must reject status with path");
    assert_eq!(err.line(), Some(1));
    assert!(matches!(
        err,
        ChainError::InvalidField { line: Some(1), .. }
    ));
}

#[test]
fn req2_chain_of_1000_entries_verifies() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("chain_1000.jsonl");
    let mut log = CmdLog::open(&log_path).expect("open log");

    let mut last_head = None;
    for i in 0..1000u64 {
        let payload = match i % 4 {
            0 => EntryPayload::exec(
                vec!["step".to_string(), i.to_string()],
                Some(0),
                EMPTY_SHA256,
                EMPTY_SHA256,
                0,
                0,
                false,
            ),
            1 => EntryPayload::upload(
                format!("/workspace/in_{i}.txt"),
                Some(0),
                EMPTY_SHA256,
                EMPTY_SHA256,
                0,
                0,
                false,
            ),
            2 => EntryPayload::download(
                format!("/workspace/out_{i}.txt"),
                Some(0),
                EMPTY_SHA256,
                EMPTY_SHA256,
                0,
                0,
                false,
            ),
            _ => EntryPayload::status(None, EMPTY_SHA256, EMPTY_SHA256, 0, 0, false),
        };
        last_head = Some(log.append(payload).expect("append entry"));
    }

    let expected = last_head.expect("1000 entries appended");
    assert_eq!(expected.seq, 999);
    assert_eq!(log.head(), (999, expected.head.clone()));

    let verified = verify(&log_path).expect("verify 1000-entry chain");
    assert_eq!(verified, expected);
}

#[test]
fn req2_reopening_existing_valid_log_continues_chain() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("reopen.jsonl");

    let mid_head = {
        let mut log = CmdLog::open(&log_path).expect("create log");
        let mut h = None;
        for i in 0..5 {
            h = Some(
                log.append(EntryPayload::exec(
                    vec!["cmd".to_string(), i.to_string()],
                    Some(0),
                    EMPTY_SHA256,
                    EMPTY_SHA256,
                    0,
                    0,
                    false,
                ))
                .expect("append initial"),
            );
        }
        h.expect("5 entries")
    };

    let final_head = {
        let mut reopened = CmdLog::open(&log_path).expect("reopen valid log");
        assert_eq!(reopened.head(), (mid_head.seq, mid_head.head));
        assert_eq!(reopened.next_seq(), 5);

        let mut h = None;
        for i in 5..10 {
            h = Some(
                reopened
                    .append(EntryPayload::status(
                        Some(i),
                        EMPTY_SHA256,
                        EMPTY_SHA256,
                        0,
                        0,
                        false,
                    ))
                    .expect("append resumed"),
            );
        }
        h.expect("10 entries")
    };

    assert_eq!(final_head.seq, 9);
    let verified = verify(&log_path).expect("verify reopened chain");
    assert_eq!(verified, final_head);
}

#[test]
fn req2_refuses_open_when_existing_chain_is_broken() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("corrupt_on_open.jsonl");

    {
        let mut log = CmdLog::open(&log_path).expect("create log");
        log.append(EntryPayload::status(
            Some(0),
            EMPTY_SHA256,
            EMPTY_SHA256,
            0,
            0,
            false,
        ))
        .expect("append 0");
    }

    fs::write(&log_path, "{\"not\":\"valid\"}\n").expect("overwrite corrupt line");
    let err = CmdLog::open(&log_path).expect_err("open must refuse broken existing log");
    assert_eq!(err.line(), Some(1));
}

#[cfg(unix)]
#[test]
fn req2_symlinked_and_group_writable_and_dir_refused() {
    let dir = tempdir().expect("create tempdir");
    let target_path = dir.path().join("real.jsonl");
    let symlink_path = dir.path().join("link.jsonl");
    let dangling_symlink_path = dir.path().join("dangling.jsonl");

    {
        let mut log = CmdLog::open(&target_path).expect("create target log");
        log.append(EntryPayload::status(
            Some(0),
            EMPTY_SHA256,
            EMPTY_SHA256,
            0,
            0,
            false,
        ))
        .expect("append entry");
    }

    // 1. Symlink to existing valid log refused on open and verify.
    symlink(&target_path, &symlink_path).expect("create symlink");
    assert!(matches!(
        CmdLog::open(&symlink_path),
        Err(ChainError::SymlinkNotAllowed { .. })
    ));
    assert!(matches!(
        verify(&symlink_path),
        Err(ChainError::SymlinkNotAllowed { .. })
    ));

    // 2. Dangling symlink refused on open.
    symlink(dir.path().join("nonexistent.jsonl"), &dangling_symlink_path)
        .expect("create dangling symlink");
    assert!(matches!(
        CmdLog::open(&dangling_symlink_path),
        Err(ChainError::SymlinkNotAllowed { .. })
    ));

    // 3. Directory (non-regular file) refused on open and verify.
    assert!(matches!(
        CmdLog::open(dir.path()),
        Err(ChainError::NotRegularFile { .. })
    ));
    assert!(matches!(
        verify(dir.path()),
        Err(ChainError::NotRegularFile { .. })
    ));

    // 4. Group-writable (0o660) and world-writable (0o602) files refused.
    fs::set_permissions(&target_path, fs::Permissions::from_mode(0o660)).expect("chmod 0660");
    assert!(matches!(
        CmdLog::open(&target_path),
        Err(ChainError::InsecurePermissions { .. })
    ));
    assert!(matches!(
        verify(&target_path),
        Err(ChainError::InsecurePermissions { .. })
    ));

    fs::set_permissions(&target_path, fs::Permissions::from_mode(0o602)).expect("chmod 0602");
    assert!(matches!(
        CmdLog::open(&target_path),
        Err(ChainError::InsecurePermissions { .. })
    ));
    assert!(matches!(
        verify(&target_path),
        Err(ChainError::InsecurePermissions { .. })
    ));
}

#[test]
fn req3_flipping_any_byte_of_any_line_detected() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("bitflip.jsonl");

    let original_head = {
        let mut log = CmdLog::open(&log_path).expect("open log");
        let mut h = None;
        for i in 0..4 {
            h = Some(
                log.append(EntryPayload::exec(
                    vec!["tool".to_string(), format!("arg-{i}")],
                    Some(i),
                    EMPTY_SHA256,
                    EMPTY_SHA256,
                    0,
                    0,
                    false,
                ))
                .expect("append"),
            );
        }
        h.expect("4 entries")
    };

    let original_bytes = fs::read(&log_path).expect("read original bytes");
    let line_ranges: Vec<(usize, usize)> = {
        let mut ranges = Vec::new();
        let mut start = 0;
        for (idx, &b) in original_bytes.iter().enumerate() {
            if b == b'\n' {
                ranges.push((start, idx));
                start = idx + 1;
            }
        }
        ranges
    };
    assert_eq!(line_ranges.len(), 4);

    let tampered_path = dir.path().join("tampered.jsonl");

    for (line_idx, &(start, end)) in line_ranges.iter().enumerate() {
        let one_based_line = line_idx + 1;
        let is_last_line = line_idx + 1 == line_ranges.len();

        for pos in start..end {
            let mut mutated = original_bytes.clone();
            // Flip bit 0; if that happens to produce '\n', flip bit 1 instead so line boundaries remain intact.
            let mut flipped = mutated[pos] ^ 0x01;
            if flipped == b'\n' {
                flipped = mutated[pos] ^ 0x02;
            }
            mutated[pos] = flipped;
            write_log_file(&tampered_path, &mutated);

            match verify(&tampered_path) {
                Err(err) => {
                    let reported = err.line().expect("error must report a line number");
                    assert!(
                        reported == one_based_line || reported == one_based_line + 1,
                        "byte flip at line {one_based_line} offset {pos} reported unexpected line {reported}: {err}"
                    );
                }
                Ok(new_head) => {
                    assert!(
                        is_last_line,
                        "interior line {one_based_line} byte flip at {pos} went undetected"
                    );
                    assert_ne!(
                        new_head.head, original_head.head,
                        "last-line byte flip at {pos} failed to alter head hash"
                    );
                }
            }
        }
    }
}

#[test]
fn req3_deleting_reordering_or_duplicating_line_detected() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("lines.jsonl");

    {
        let mut log = CmdLog::open(&log_path).expect("open log");
        for i in 0..4 {
            log.append(EntryPayload::status(
                Some(i),
                EMPTY_SHA256,
                EMPTY_SHA256,
                0,
                0,
                false,
            ))
            .expect("append");
        }
    }

    let raw = fs::read_to_string(&log_path).expect("read log");
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(lines.len(), 4);

    // 1. Deleting middle line (seq 1) -> detected at line 2 as SeqGap.
    let deleted = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]);
    let deleted_path = dir.path().join("deleted.jsonl");
    write_log_file(&deleted_path, deleted);
    let err = verify(&deleted_path).expect_err("deleted line must fail");
    assert_eq!(err.line(), Some(2));
    assert!(matches!(
        err,
        ChainError::SeqGap {
            line: 2,
            expected: 1,
            actual: 2
        }
    ));

    // 2. Reordering lines 2 and 3 (seq 0, seq 2, seq 1, seq 3) -> detected at line 2 as SeqGap.
    let reordered = format!("{}\n{}\n{}\n{}\n", lines[0], lines[2], lines[1], lines[3]);
    let reordered_path = dir.path().join("reordered.jsonl");
    write_log_file(&reordered_path, reordered);
    let err = verify(&reordered_path).expect_err("reordered lines must fail");
    assert_eq!(err.line(), Some(2));
    assert!(matches!(err, ChainError::SeqGap { line: 2, .. }));

    // 3. Duplicating line 2 (seq 0, seq 1, seq 1, seq 2, seq 3) -> detected at line 3 as SeqGap.
    let duplicated = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        lines[0], lines[1], lines[1], lines[2], lines[3]
    );
    let duplicated_path = dir.path().join("duplicated.jsonl");
    write_log_file(&duplicated_path, duplicated);
    let err = verify(&duplicated_path).expect_err("duplicated line must fail");
    assert_eq!(err.line(), Some(3));
    assert!(matches!(
        err,
        ChainError::SeqGap {
            line: 3,
            expected: 2,
            actual: 1
        }
    ));
}

#[test]
fn req3_truncated_last_line_detected() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("trunc.jsonl");

    {
        let mut log = CmdLog::open(&log_path).expect("open log");
        for i in 0..3 {
            log.append(EntryPayload::status(
                Some(i),
                EMPTY_SHA256,
                EMPTY_SHA256,
                0,
                0,
                false,
            ))
            .expect("append");
        }
    }

    let full = fs::read(&log_path).expect("read log");

    // Case A: strip trailing '\n' only -> TruncatedLine at line 3.
    let no_newline = &full[..full.len() - 1];
    let p_no_nl = dir.path().join("no_nl.jsonl");
    write_log_file(&p_no_nl, no_newline);
    let err = verify(&p_no_nl).expect_err("missing trailing newline must fail");
    assert_eq!(err.line(), Some(3));
    assert!(matches!(err, ChainError::TruncatedLine { line: 3 }));

    // Case B: cut mid-JSON on line 3 -> TruncatedLine at line 3.
    let mid_cut = &full[..full.len() - 15];
    let p_mid = dir.path().join("mid_cut.jsonl");
    write_log_file(&p_mid, mid_cut);
    let err = verify(&p_mid).expect_err("truncated last line must fail");
    assert_eq!(err.line(), Some(3));
    assert!(matches!(err, ChainError::TruncatedLine { line: 3 }));
}

#[test]
fn req3_bad_json_unknown_field_prev_mismatch_and_oversized_line_detected() {
    let dir = tempdir().expect("create tempdir");

    // 1. Bad JSON at line 1.
    let p_bad = dir.path().join("bad.jsonl");
    write_log_file(&p_bad, "{broken json\n");
    let err = verify(&p_bad).expect_err("bad json");
    assert_eq!(err.line(), Some(1));
    assert!(matches!(err, ChainError::BadJson { line: 1, .. }));

    // 2. Unknown field at line 1.
    let p_unk = dir.path().join("unknown.jsonl");
    let unk_line = r#"{"exit":0,"extra_field":123,"kind":"status","prev":"sha256:0000000000000000000000000000000000000000000000000000000000000000","seq":0,"stderr_len":0,"stderr_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stdout_len":0,"stdout_sha256":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","truncated":false}"#;
    write_log_file(&p_unk, format!("{unk_line}\n"));
    let err = verify(&p_unk).expect_err("unknown field");
    assert_eq!(err.line(), Some(1));
    assert!(matches!(err, ChainError::UnknownField { line: 1, .. }));

    // 3. Prev mismatch at line 2.
    let p_prev = dir.path().join("prev_mismatch.jsonl");
    let valid_0 = Entry {
        argv: None,
        exit: Some(0),
        kind: EntryKind::Status,
        path: None,
        prev: GENESIS_PREV.to_string(),
        seq: 0,
        stderr_len: 0,
        stderr_sha256: EMPTY_SHA256.to_string(),
        stdout_len: 0,
        stdout_sha256: EMPTY_SHA256.to_string(),
        truncated: false,
    };
    let bad_1 = Entry {
        argv: None,
        exit: Some(0),
        kind: EntryKind::Status,
        path: None,
        prev: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        seq: 1,
        stderr_len: 0,
        stderr_sha256: EMPTY_SHA256.to_string(),
        stdout_len: 0,
        stdout_sha256: EMPTY_SHA256.to_string(),
        truncated: false,
    };
    write_log_file(
        &p_prev,
        format!(
            "{}\n{}\n",
            valid_0.to_canonical_json().expect("json 0"),
            bad_1.to_canonical_json().expect("json 1")
        ),
    );
    let err = verify(&p_prev).expect_err("prev mismatch");
    assert_eq!(err.line(), Some(2));
    assert!(matches!(err, ChainError::PrevMismatch { line: 2, .. }));

    // 4. Oversized line (> MAX_LINE_BYTES) at line 1.
    let p_big = dir.path().join("oversized.jsonl");
    let huge = "a".repeat(MAX_LINE_BYTES + 10);
    write_log_file(&p_big, format!("{huge}\n"));
    let err = verify(&p_big).expect_err("oversized line");
    assert_eq!(err.line(), Some(1));
    assert!(matches!(err, ChainError::OversizedLine { line: 1, .. }));
}

#[test]
fn req4_output_bodies_never_stored_only_hashes_and_lengths() {
    let dir = tempdir().expect("create tempdir");
    let log_path = dir.path().join("no_leak.jsonl");

    let secret_stdout = b"TOP_SECRET_POST_CUTOFF_KNOWLEDGE_2026_CANARY_ALPHA";
    let secret_stderr = b"SECRET_HOST_INTERNAL_PATH_CANARY_BETA";

    let (out_hash, out_len) =
        hash_output_reader(Cursor::new(secret_stdout)).expect("stream hash stdout");
    let (err_hash, err_len) =
        hash_output_reader(Cursor::new(secret_stderr)).expect("stream hash stderr");

    assert_eq!(out_len, secret_stdout.len() as u64);
    assert_eq!(err_len, secret_stderr.len() as u64);

    let mut log = CmdLog::open(&log_path).expect("open log");
    log.append(EntryPayload::exec(
        vec!["run_benchmark".to_string()],
        Some(0),
        out_hash.clone(),
        err_hash.clone(),
        out_len,
        err_len,
        false,
    ))
    .expect("append entry");

    let raw_file = fs::read_to_string(&log_path).expect("read log file");
    assert!(!raw_file.contains("TOP_SECRET_POST_CUTOFF_KNOWLEDGE_2026_CANARY_ALPHA"));
    assert!(!raw_file.contains("SECRET_HOST_INTERNAL_PATH_CANARY_BETA"));
    assert!(raw_file.contains(&out_hash));
    assert!(raw_file.contains(&err_hash));
    assert!(raw_file.contains(&format!("\"stdout_len\":{}", secret_stdout.len())));
    assert!(raw_file.contains(&format!("\"stderr_len\":{}", secret_stderr.len())));
}

#[test]
fn req5_cli_verify_exit_codes_and_json_output() {
    let bin = env!("CARGO_BIN_EXE_hermetic-cmdlog");
    let dir = tempdir().expect("create tempdir");
    let valid_path = dir.path().join("cli_valid.jsonl");

    let expected_head = {
        let mut log = CmdLog::open(&valid_path).expect("open log");
        log.append(EntryPayload::exec(
            vec!["echo".to_string(), "ok".to_string()],
            Some(0),
            EMPTY_SHA256,
            EMPTY_SHA256,
            0,
            0,
            false,
        ))
        .expect("append")
    };

    // 1. Valid file -> exit 0 and prints {"seq":0,"head":"sha256:..."}.
    let ok_out = Command::new(bin)
        .args(["verify", valid_path.to_str().expect("utf8 path")])
        .output()
        .expect("run binary");
    assert_eq!(ok_out.status.code(), Some(0));
    let printed: Head = serde_json::from_slice(&ok_out.stdout).expect("parse stdout JSON");
    assert_eq!(printed, expected_head);

    // 2. Broken chain -> exit 2.
    let broken_path = dir.path().join("cli_broken.jsonl");
    write_log_file(&broken_path, "{\"seq\":99}\n");
    let broken_out = Command::new(bin)
        .args(["verify", broken_path.to_str().expect("utf8 path")])
        .output()
        .expect("run binary on broken");
    assert_eq!(broken_out.status.code(), Some(2));
    assert!(!broken_out.stderr.is_empty());

    // 3. Missing file -> exit 1.
    let missing_path = dir.path().join("does_not_exist.jsonl");
    let missing_out = Command::new(bin)
        .args(["verify", missing_path.to_str().expect("utf8 path")])
        .output()
        .expect("run binary on missing");
    assert_eq!(missing_out.status.code(), Some(1));

    // 4. Bad CLI usage -> exit 1.
    let usage_out = Command::new(bin).output().expect("run binary no args");
    assert_eq!(usage_out.status.code(), Some(1));
}
