use hermetic_cmdlog::{verify, CmdLog, EntryPayload, Head, EMPTY_SHA256};
use std::process::Command;

fn payload() -> EntryPayload {
    EntryPayload::status(Some(0), EMPTY_SHA256, EMPTY_SHA256, 0, 0, false)
}

#[test]
fn independent_writers_are_exclusive_until_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.jsonl");
    let mut first = CmdLog::open(&path).unwrap();
    assert!(CmdLog::open(&path).is_err(), "new log already has a writer");
    first.append(payload()).unwrap();
    assert!(CmdLog::open(&path).is_err(), "populated log has a writer");
    drop(first);
    let mut second = CmdLog::open(&path).unwrap();
    assert_eq!(second.next_seq(), 1);
    assert!(CmdLog::open(&path).is_err(), "reopened log has a writer");
    let head = second.append(payload()).unwrap();
    drop(second);
    assert_eq!(verify(&path).unwrap(), head);
}

#[cfg(unix)]
#[test]
fn cli_verifies_non_utf8_path_without_panicking() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join(OsString::from_vec(b"log-\xff.jsonl".to_vec()));
    let head = CmdLog::open(&path).unwrap().append(payload()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_hermetic-cmdlog"))
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    assert_eq!(serde_json::from_slice::<Head>(&out.stdout).unwrap(), head);
}

#[test]
fn cli_parser_diagnostics_do_not_echo_hostile_strings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.jsonl");
    drop(CmdLog::open(&path).unwrap());
    // Test unknown fields, enum variants and wrong value types.
    for input in [
        r#"{"\u001b[2J\nFORGED_SECRET":0}"#,
        r#"{"kind":"\u001b[2J\nFORGED_SECRET"}"#,
        r#"{"seq":"\u001b[2J\nFORGED_SECRET"}"#,
    ] {
        std::fs::write(&path, format!("{input}\n")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_hermetic-cmdlog"))
            .arg("verify")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!stderr.contains("FORGED_SECRET"), "{stderr:?}");
        assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
        assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
        assert!(stderr.contains("line 1"), "{stderr}");
    }
}
