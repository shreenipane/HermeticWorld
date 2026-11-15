//! End-to-end tests of the production backend through the CLI entry point.

#[path = "../../hermetic-attest/tests/common.rs"]
#[allow(unused_imports)]
mod attest_common;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use hermetic_cli::backend::{PROBE_NEEDS_INPUT, RUN_NOT_WIRED, SEAL_NOT_WIRED};
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

use hermetic_attest::canonical::compute_run_digest;
use hermetic_attest::dsse::{DsseEnvelope, Statement};
use hermetic_attest::offline_key::Ed25519Signer;
use hermetic_attest::{Digest, RunRecord};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

/// Throwaway signer generated in memory for one test.
fn signer() -> Ed25519Signer {
    let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519Signer::from_pkcs8(der.as_ref()).unwrap()
}

fn sign(record: RunRecord, signer: &Ed25519Signer) -> String {
    let st = Statement::new_run_statement(record).unwrap();
    serde_json::to_string(&DsseEnvelope::sign_statement(&st, signer).unwrap()).unwrap()
}

struct Fixture {
    dir: tempfile::TempDir,
    record: std::path::PathBuf,
    key: std::path::PathBuf,
    signer: Ed25519Signer,
}

fn fixture(record: RunRecord) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let signer = signer();
    let r = dir.path().join("record.json");
    fs::write(&r, sign(record, &signer)).unwrap();
    let k = dir.path().join("key.pub");
    fs::write(&k, signer.public_key()).unwrap();
    Fixture {
        record: r,
        key: k,
        dir,
        signer,
    }
}

fn classification(record: &RunRecord, flags: &[&str]) -> String {
    serde_json::json!({
        "schema": "hermetic-run-classification/v1",
        "run_digest": compute_run_digest(record).unwrap().to_string(),
        "clock": "hidden", "clock_reasons": [], "label": null, "confidence": null,
        "status": "resolved", "flags": flags,
    })
    .to_string()
}

#[test]
fn verify_accepts_a_signed_record_from_the_trusted_key() {
    let f = fixture(attest_common::sample_run_record());
    let (code, out, err) = exec(&["verify", "--record", p(&f.record), "--key", p(&f.key)]);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    let digest = compute_run_digest(&attest_common::sample_run_record()).unwrap();
    assert_eq!(out, format!("verify: verified run {digest}\n"));
}

#[test]
fn verify_rejects_tampering_wrong_key_and_unsigned_records() {
    let f = fixture(attest_common::sample_run_record());
    // A signature from another key, under the trusted key id or not, fails.
    let other = signer();
    let wrong_key = f.dir.path().join("other.pub");
    fs::write(&wrong_key, other.public_key()).unwrap();
    let (code, _, err) = exec(&["verify", "--record", p(&f.record), "--key", p(&wrong_key)]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(err.starts_with("error: record invalid"), "{err}");
    // Flip one payload byte of a valid envelope.
    let mut env: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&f.record).unwrap()).unwrap();
    let payload = env["payload"].as_str().unwrap().to_string();
    let flipped = if payload.starts_with('e') { "f" } else { "e" };
    env["payload"] = serde_json::Value::from(format!("{flipped}{}", &payload[1..]));
    let tampered = f.dir.path().join("tampered.json");
    fs::write(&tampered, env.to_string()).unwrap();
    // The old unsigned record format is not accepted either.
    let unsigned = f.dir.path().join("unsigned.json");
    fs::write(&unsigned, valid_record_json()).unwrap();
    for bad in [&tampered, &unsigned] {
        let (code, out, err) = exec(&["verify", "--record", p(bad), "--key", p(&f.key)]);
        assert_eq!(code, ExitCode::PROBLEM_FOUND, "{bad:?}");
        assert!(out.is_empty());
        assert!(err.starts_with("error: record invalid"), "{err}");
    }
    for bad in ["{}", "nope"] {
        fs::write(&tampered, bad).unwrap();
        let (code, _, _) = exec(&["verify", "--record", p(&tampered), "--key", p(&f.key)]);
        assert_eq!(code, ExitCode::PROBLEM_FOUND, "{bad}");
    }
    fs::write(&tampered, [0xffu8]).unwrap();
    let (code, _, _) = exec(&["verify", "--record", p(&tampered), "--key", p(&f.key)]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    drop(f.signer);
}

#[test]
fn verify_binds_the_record_to_the_bundle_root() {
    let dir = tempfile::tempdir().unwrap();
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    fs::write(b.join("a.txt"), b"hello").unwrap();
    let manifest = hermetic_bundle::seal(&b).unwrap();
    let root = Digest::parse(&manifest.root).unwrap();
    let mut matching = attest_common::sample_run_record();
    matching.world_root = root.clone();
    matching.version_tuple.world_version = root;
    let good = fixture(matching);
    let (code, _, err) = exec(&[
        "verify",
        "--record",
        p(&good.record),
        "--key",
        p(&good.key),
        "--bundle",
        p(&b),
    ]);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    // The sample record names a different world root.
    let other = fixture(attest_common::sample_run_record());
    let (code, _, err) = exec(&[
        "verify",
        "--record",
        p(&other.record),
        "--key",
        p(&other.key),
        "--bundle",
        p(&b),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(err.contains("world_root"), "{err}");
    // A modified bundle no longer matches its manifest.
    fs::write(b.join("a.txt"), b"changed").unwrap();
    let (code, _, err) = exec(&[
        "verify",
        "--record",
        p(&good.record),
        "--key",
        p(&good.key),
        "--bundle",
        p(&b),
    ]);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(err.contains("bundle rejected"), "{err}");
}

#[test]
fn verify_cross_checks_the_classifier() {
    let record = attest_common::sample_run_record();
    let f = fixture(record.clone());
    let c = f.dir.path().join("class.json");
    fs::write(&c, classification(&record, &[])).unwrap();
    let args = |c: &Path| {
        exec(&[
            "verify",
            "--record",
            p(&f.record),
            "--key",
            p(&f.key),
            "--classification",
            p(c),
        ])
    };
    let (code, _, err) = args(&c);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    // The classifier saw a date leak the record does not report.
    fs::write(&c, classification(&record, &["date_leak_observed"])).unwrap();
    let (code, _, err) = args(&c);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(err.contains("date_leak_observed"), "{err}");
    // Classification of another run.
    let mut other = record.clone();
    other.task_id = "other-task".into();
    fs::write(&c, classification(&other, &[])).unwrap();
    let (code, _, err) = args(&c);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(err.contains("run_digest"), "{err}");
    fs::write(&c, "{\"schema\":\"x\"}").unwrap();
    let (code, _, err) = args(&c);
    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(err.starts_with("error: classification invalid"), "{err}");
}

#[test]
fn verify_refuses_hostile_record_key_classification_and_bundle_paths() {
    let f = fixture(attest_common::sample_run_record());
    let dir = f.dir.path();
    let link = dir.join("link");
    symlink(&f.record, &link).unwrap();
    let klink = dir.join("klink");
    symlink(&f.key, &klink).unwrap();
    let fifo = dir.join("fifo");
    mkfifo(&fifo);
    let big = dir.join("big");
    fs::write(&big, vec![b' '; 1024 * 1024 + 1]).unwrap();
    for hostile in [&link, &fifo, &big] {
        let (code, _, _) = exec(&["verify", "--record", p(hostile), "--key", p(&f.key)]);
        assert_eq!(code, ExitCode::DATA_ERROR, "{hostile:?}");
        let (code, _, _) = exec(&[
            "verify",
            "--record",
            p(&f.record),
            "--key",
            p(&f.key),
            "--classification",
            p(hostile),
        ]);
        assert_eq!(code, ExitCode::DATA_ERROR, "classification {hostile:?}");
    }
    let short = dir.join("short.pub");
    fs::write(&short, [0u8; 31]).unwrap();
    for bad_key in [&klink, &fifo, &big, &short] {
        let (code, _, _) = exec(&["verify", "--record", p(&f.record), "--key", p(bad_key)]);
        assert_eq!(code, ExitCode::DATA_ERROR, "key {bad_key:?}");
    }
    let dlink = dir.join("dlink");
    symlink(dir, &dlink).unwrap();
    let (code, _, _) = exec(&[
        "verify",
        "--record",
        p(&f.record),
        "--key",
        p(&f.key),
        "--bundle",
        p(&dlink),
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    let (code, _, _) = exec(&[
        "verify",
        "--record",
        p(&dir.join("absent")),
        "--key",
        p(&f.key),
    ]);
    assert_eq!(code, ExitCode::IO_ERROR);
}

fn valid_record_json() -> String {
    serde_json::to_string(&attest_common::sample_run_record()).unwrap()
}
