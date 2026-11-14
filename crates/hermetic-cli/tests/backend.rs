//! End-to-end tests of the production backend through the CLI entry point.

#[path = "../../hermetic-attest/tests/common.rs"]
#[allow(unused_imports)]
mod attest_common;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use hermetic_cli::backend::{
    PROBE_NEEDS_INPUT, RUN_NOT_WIRED, SEAL_NOT_WIRED, VERIFY_SIGNATURE_NOT_WIRED,
};
use hermetic_cli::{run_with_args, ExitCode, RealBackend};

fn exec(args: &[&str]) -> (ExitCode, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_with_args(
        args.iter().map(OsString::from),
        &RealBackend,
        &mut out,
        &mut err,
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn mkfifo(path: &Path) {
    let status = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success());
}

const CANARY_PASS: &str = "\
boot noise\n\
hermetic-canary/v1 msr=00000011 rd=gp wr=gp page=unchanged\n\
hermetic-canary/v1 msr=00000012 rd=gp wr=gp page=unchanged\n\
hermetic-canary/v1 msr=4b564d00 rd=gp wr=gp page=unchanged\n\
hermetic-canary/v1 msr=4b564d01 rd=gp wr=gp page=unchanged\n\
hermetic-canary/v1 hypercall=9 ret=enosys page=unchanged\n\
hermetic-canary/v1 result=pass\n";

// ---- seal / run: fail closed ----

#[test]
fn seal_fails_closed_with_fixed_message_and_exit_70() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(dir.path()),
        "--out",
        p(&dir.path().join("out")),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "w1",
    ]);
    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
    assert!(out.is_empty());
    assert_eq!(err, format!("error: not available: {SEAL_NOT_WIRED}\n"));
    assert!(
        !dir.path().join("out").exists(),
        "seal must not write output"
    );
}

#[test]
fn run_fails_closed_with_fixed_message_and_exit_70() {
    let dir = tempfile::tempdir().unwrap();
    for json in [false, true] {
        let mut args = vec![
            "run",
            "--world",
            p(dir.path()),
            "--task",
            "t1",
            "--agent-mode",
            "H",
        ];
        if json {
            args.push("--json");
        }
        let (code, out, err) = exec(&args);
        assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
        assert!(out.is_empty());
        assert_eq!(err, format!("error: not available: {RUN_NOT_WIRED}\n"));
    }
    let (code, _, _) = exec(&[
        "run",
        "--world",
        p(dir.path()),
        "--task",
        "t1",
        "--agent-mode",
        "G",
        "--clock",
        "hidden",
    ]);
    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
}

// ---- verify-bundle ----

#[test]
fn verify_bundle_ok_mismatch_and_expected_root() {
    let dir = tempfile::tempdir().unwrap();
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    fs::write(b.join("a.txt"), b"hello").unwrap();
    let manifest = hermetic_bundle::seal(&b).unwrap();

    let (code, out, err) = exec(&["verify-bundle", p(&b)]);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, format!("verify-bundle: ok {}\n", manifest.root));

    let (code, _, _) = exec(&["verify-bundle", p(&b), "--root", &manifest.root]);
    assert_eq!(code, ExitCode::SUCCESS);

    let wrong = format!("sha256:{}", "0".repeat(64));
    let (code, out, _) = exec(&["verify-bundle", p(&b), "--root", &wrong]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(out.contains("expected root differs"), "{out}");

    fs::write(b.join("a.txt"), b"hellO").unwrap();
    let (code, out, _) = exec(&["verify-bundle", p(&b)]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(
        out.starts_with("verify-bundle: mismatch: 0 missing, 0 extra, 1 hash"),
        "{out}"
    );
}

#[test]
fn verify_bundle_missing_manifest_is_problem_found() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out, err) = exec(&["verify-bundle", p(dir.path())]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(out.is_empty());
    assert!(err.contains("bundle rejected"), "{err}");
}

#[test]
fn verify_bundle_refuses_symlinked_root_and_nondirectory() {
    let dir = tempfile::tempdir().unwrap();
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    hermetic_bundle::seal(&b).unwrap();
    let link = dir.path().join("link");
    symlink(&b, &link).unwrap();
    let (code, _, err) = exec(&["verify-bundle", p(&link)]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(err.contains("symlink"), "{err}");

    let f = dir.path().join("file");
    fs::write(&f, b"x").unwrap();
    let (code, _, _) = exec(&["verify-bundle", p(&f)]);
    assert_eq!(code, ExitCode::DATA_ERROR);

    let fifo = dir.path().join("fifo");
    mkfifo(&fifo);
    let (code, _, _) = exec(&["verify-bundle", p(&fifo)]);
    assert_eq!(code, ExitCode::DATA_ERROR);

    let (code, _, _) = exec(&["verify-bundle", p(&dir.path().join("absent"))]);
    assert_eq!(code, ExitCode::IO_ERROR);
}

#[test]
fn verify_bundle_with_symlink_inside_is_problem_found() {
    let dir = tempfile::tempdir().unwrap();
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    fs::write(b.join("a.txt"), b"x").unwrap();
    hermetic_bundle::seal(&b).unwrap();
    symlink("/etc/passwd", b.join("evil")).unwrap();
    let (code, _, _) = exec(&["verify-bundle", p(&b)]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
}

// ---- probe ----

#[test]
fn probe_without_input_fails_closed_and_never_probes_host() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out, err) = exec(&["probe", "--world", p(dir.path())]);
    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
    assert!(out.is_empty());
    assert_eq!(err, format!("error: not available: {PROBE_NEEDS_INPUT}\n"));
}

#[test]
fn probe_classifies_clockprobe_output_blocked_leak_error() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("probe.jsonl");
    fs::write(
        &f,
        "{\"probe\":\"rdtsc\",\"result\":\"blocked\",\"detail\":\"ok\"}\n\
         {\"probe\":\"hpet\",\"result\":\"unavailable\",\"detail\":\"none\"}\n",
    )
    .unwrap();
    let (code, out, err) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--clockprobe-output",
        p(&f),
        "--json",
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND, "{err}");
    assert_eq!(
        out,
        "{\"command\":\"probe\",\"details\":{\"records\":[{\"probe\":\"rdtsc\",\"result\":\"blocked\"},{\"probe\":\"hpet\",\"result\":\"unavailable\"}],\"verdict\":\"incomplete\"},\"ok\":false,\"summary\":\"probe coverage unavailable; result is incomplete\"}\n"
    );

    fs::write(
        &f,
        "{\"probe\":\"rtc\",\"result\":\"leak\",\"value\":\"2026\",\"detail\":\"d\"}\n",
    )
    .unwrap();
    let (code, out, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--clockprobe-output",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert_eq!(out, "probe: clock leak observed: rtc\n");

    fs::write(
        &f,
        "{\"probe\":\"rtc\",\"result\":\"error\",\"detail\":\"d\"}\n",
    )
    .unwrap();
    let (code, out, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--clockprobe-output",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(out.contains("inconclusive"));
}

#[test]
fn probe_unavailable_is_incomplete_and_never_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("probe.jsonl");
    for (result, expected_code, verdict) in [
        ("blocked", ExitCode::SUCCESS, "blocked"),
        ("unavailable", ExitCode::PROBLEM_FOUND, "incomplete"),
        ("leak", ExitCode::PROBLEM_FOUND, "leak"),
        ("error", ExitCode::PROBLEM_FOUND, "error"),
    ] {
        fs::write(
            &f,
            format!("{{\"probe\":\"hpet\",\"result\":\"{result}\",\"detail\":\"fixed reason\"}}\n"),
        )
        .unwrap();
        let (code, out, _) = exec(&[
            "probe",
            "--world",
            p(dir.path()),
            "--clockprobe-output",
            p(&f),
            "--json",
        ]);
        assert_eq!(code, expected_code);
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["details"]["verdict"], verdict);
    }
}

#[test]
fn probe_rejects_malformed_clockprobe_output_with_exit_65() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("probe.jsonl");
    for bad in [
        "",
        "\n\n",
        "not json\n",
        "{\"probe\":\"x\",\"result\":\"fine\",\"detail\":\"d\"}\n",
        "{\"probe\":\"x\",\"result\":\"blocked\",\"detail\":\"d\",\"extra\":1}\n",
        "{\"probe\":\"\",\"result\":\"blocked\",\"detail\":\"d\"}\n",
    ] {
        fs::write(&f, bad).unwrap();
        let (code, out, _) = exec(&[
            "probe",
            "--world",
            p(dir.path()),
            "--clockprobe-output",
            p(&f),
        ]);
        assert_eq!(code, ExitCode::DATA_ERROR, "input {bad:?}");
        assert!(out.is_empty());
    }
    fs::write(&f, [0xffu8, 0xfe]).unwrap();
    let (code, _, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--clockprobe-output",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);

    let line = "{\"probe\":\"x\",\"result\":\"blocked\",\"detail\":\"d\"}\n";
    fs::write(&f, line.repeat(513)).unwrap();
    let (code, _, err) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--clockprobe-output",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(err.contains("more than 512"), "{err}");
}

#[test]
fn probe_kernel_canary_serial_pass_leak_and_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("serial.log");
    fs::write(&f, CANARY_PASS).unwrap();
    let (code, out, err) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--kernel-canary-serial",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "probe: 1 probe records, no leak\n");

    fs::write(
        &f,
        CANARY_PASS.replace(
            "rd=gp wr=gp page=unchanged\nhermetic-canary/v1 msr=00000012",
            "rd=ok wr=gp page=unchanged\nhermetic-canary/v1 msr=00000012",
        ),
    )
    .unwrap();
    let (code, out, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--kernel-canary-serial",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert_eq!(out, "probe: clock leak observed: kernel_canary\n");

    fs::write(&f, "hermetic-canary/v1 result=pass\n").unwrap();
    let (code, out, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--kernel-canary-serial",
        p(&f),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(out.contains("inconclusive"));
}

#[test]
fn probe_combines_both_inputs_and_leak_wins() {
    let dir = tempfile::tempdir().unwrap();
    let s = dir.path().join("serial.log");
    fs::write(&s, CANARY_PASS).unwrap();
    let c = dir.path().join("probe.jsonl");
    fs::write(
        &c,
        "{\"probe\":\"rtc\",\"result\":\"leak\",\"detail\":\"d\"}\n",
    )
    .unwrap();
    let (code, out, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--clockprobe-output",
        p(&c),
        "--kernel-canary-serial",
        p(&s),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert_eq!(out, "probe: clock leak observed: rtc\n");
}

#[test]
fn probe_inputs_refuse_symlink_fifo_oversized_and_missing() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("serial.log");
    fs::write(&real, CANARY_PASS).unwrap();
    let link = dir.path().join("link");
    symlink(&real, &link).unwrap();
    let fifo = dir.path().join("fifo");
    mkfifo(&fifo);
    let big = dir.path().join("big");
    fs::write(&big, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    let big_serial = dir.path().join("big_serial");
    fs::write(&big_serial, vec![b'a'; 262_144 + 2]).unwrap();

    for flag in ["--clockprobe-output", "--kernel-canary-serial"] {
        for hostile in [&link, &fifo, &big] {
            let (code, out, err) = exec(&["probe", "--world", p(dir.path()), flag, p(hostile)]);
            assert_eq!(code, ExitCode::DATA_ERROR, "{flag} {hostile:?} {err}");
            assert!(out.is_empty());
        }
        let (code, _, _) = exec(&[
            "probe",
            "--world",
            p(dir.path()),
            flag,
            p(&dir.path().join("absent")),
        ]);
        assert_eq!(code, ExitCode::IO_ERROR);
    }
    let (code, _, _) = exec(&[
        "probe",
        "--world",
        p(dir.path()),
        "--kernel-canary-serial",
        p(&big_serial),
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
}

#[test]
fn probe_new_flags_parse_strictly() {
    let (code, _, _) = exec(&["probe", "--world", "/w", "--clockprobe-output"]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    let (code, _, _) = exec(&[
        "probe",
        "--world",
        "/w",
        "--clockprobe-output",
        "a",
        "--clockprobe-output",
        "b",
    ]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    let (code, _, _) = exec(&["probe", "--world", "/w", "--kernel-canary-serial="]);
    assert_eq!(code, ExitCode::DATA_ERROR);
}

// ---- verify ----

fn valid_record_json() -> String {
    serde_json::to_string(&attest_common::sample_run_record()).unwrap()
}

#[test]
fn verify_valid_record_fails_closed_on_signature_check() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path().join("record.json");
    fs::write(&r, valid_record_json()).unwrap();
    let (code, out, err) = exec(&["verify", "--record", p(&r)]);
    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED, "{err}");
    assert!(out.is_empty());
    assert_eq!(
        err,
        format!("error: not available: {VERIFY_SIGNATURE_NOT_WIRED}\n")
    );

    let (code, _, _) = exec(&["verify", "--record", p(&r), "--bundle", p(dir.path())]);
    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
}

#[test]
fn verify_invalid_record_is_problem_found() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path().join("record.json");
    for bad in [
        "{}".to_string(),
        "nope".to_string(),
        valid_record_json().replace("\"task_id\"", "\"task_idx\""),
    ] {
        fs::write(&r, &bad).unwrap();
        let (code, out, err) = exec(&["verify", "--record", p(&r)]);
        assert_eq!(code, ExitCode::PROBLEM_FOUND, "{bad}");
        assert!(out.is_empty());
        assert!(err.starts_with("error: record invalid"), "{err}");
    }
    fs::write(&r, [0xffu8]).unwrap();
    let (code, _, _) = exec(&["verify", "--record", p(&r)]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
}

#[test]
fn verify_refuses_hostile_record_and_bundle_paths() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path().join("record.json");
    fs::write(&r, valid_record_json()).unwrap();
    let link = dir.path().join("link");
    symlink(&r, &link).unwrap();
    let fifo = dir.path().join("fifo");
    mkfifo(&fifo);
    let big = dir.path().join("big");
    fs::write(&big, vec![b' '; 1024 * 1024 + 1]).unwrap();
    for hostile in [&link, &fifo, &big] {
        let (code, _, _) = exec(&["verify", "--record", p(hostile)]);
        assert_eq!(code, ExitCode::DATA_ERROR, "{hostile:?}");
    }
    let dlink = dir.path().join("dlink");
    symlink(dir.path(), &dlink).unwrap();
    let (code, _, _) = exec(&["verify", "--record", p(&r), "--bundle", p(&dlink)]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    let (code, _, _) = exec(&["verify", "--record", p(&dir.path().join("absent"))]);
    assert_eq!(code, ExitCode::IO_ERROR);
}
