#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::PathBuf;

use hermetic_cli::{
    parse_args, run_from_env_args, run_with_args, AgentMode, Backend, BackendError, ClockMode,
    ExitCode, NotImplementedBackend, Outcome, ParseErrorKind, ProbeRequest, RunRequest, SealLevel,
    SealRequest, SubcommandKind, VerifyBundleRequest, VerifyRequest,
};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordedCall {
    Seal(SealRequest),
    VerifyBundle(VerifyBundleRequest),
    Probe(ProbeRequest),
    Run(RunRequest),
    Verify(VerifyRequest),
}

struct RecordingBackend {
    calls: RefCell<Vec<RecordedCall>>,
    next_result: RefCell<Option<Result<Outcome, BackendError>>>,
}

impl RecordingBackend {
    fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            next_result: RefCell::new(None),
        }
    }

    fn with_result(result: Result<Outcome, BackendError>) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            next_result: RefCell::new(Some(result)),
        }
    }

    fn calls(&self) -> Vec<RecordedCall> {
        self.calls.borrow().clone()
    }

    fn take_or_default(&self, default_summary: &str) -> Result<Outcome, BackendError> {
        if let Some(res) = self.next_result.borrow_mut().take() {
            res
        } else {
            Ok(Outcome::success(default_summary))
        }
    }
}

impl Backend for RecordingBackend {
    fn seal(&self, req: SealRequest) -> Result<Outcome, BackendError> {
        self.calls.borrow_mut().push(RecordedCall::Seal(req));
        self.take_or_default("sealed world")
    }

    fn verify_bundle(&self, req: VerifyBundleRequest) -> Result<Outcome, BackendError> {
        self.calls
            .borrow_mut()
            .push(RecordedCall::VerifyBundle(req));
        self.take_or_default("bundle verified")
    }

    fn probe(&self, req: ProbeRequest) -> Result<Outcome, BackendError> {
        self.calls.borrow_mut().push(RecordedCall::Probe(req));
        self.take_or_default("probe complete")
    }

    fn run(&self, req: RunRequest) -> Result<Outcome, BackendError> {
        self.calls.borrow_mut().push(RecordedCall::Run(req));
        self.take_or_default("run complete")
    }

    fn verify(&self, req: VerifyRequest) -> Result<Outcome, BackendError> {
        self.calls.borrow_mut().push(RecordedCall::Verify(req));
        self.take_or_default("record verified")
    }
}

fn os_args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

fn exec(backend: &dyn Backend, args: &[&str]) -> (ExitCode, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_with_args(os_args(args), backend, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("stdout must be UTF-8"),
        String::from_utf8(stderr).expect("stderr must be UTF-8"),
    )
}

#[test]
fn happy_path_seal_default_and_explicit_level() {
    let backend = RecordingBackend::new();
    let (code, out, err) = exec(
        &backend,
        &[
            "seal",
            "--src",
            "/repos/app",
            "--out",
            "/worlds/out",
            "--t-clock",
            "2026-03-15T12:00:00Z",
            "--world-id",
            "bench-world-01",
        ],
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(out, "seal: sealed world\n");
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::Seal(SealRequest {
            src: PathBuf::from("/repos/app"),
            out: PathBuf::from("/worlds/out"),
            t_clock: "2026-03-15T12:00:00Z".to_string(),
            world_id: "bench-world-01".to_string(),
            seal_level: SealLevel::Strict,
        })]
    );

    let backend2 = RecordingBackend::new();
    let (code2, _, err2) = exec(
        &backend2,
        &[
            "seal",
            "--src",
            "/repos/app",
            "--out",
            "/worlds/out",
            "--t-clock",
            "2026-03-15T12:00:00.250Z",
            "--world-id",
            "w1",
            "--seal-level",
            "repo_only",
        ],
    );
    assert_eq!(code2, ExitCode::SUCCESS);
    assert!(err2.is_empty());
    assert_eq!(
        backend2.calls(),
        vec![RecordedCall::Seal(SealRequest {
            src: PathBuf::from("/repos/app"),
            out: PathBuf::from("/worlds/out"),
            t_clock: "2026-03-15T12:00:00.250Z".to_string(),
            world_id: "w1".to_string(),
            seal_level: SealLevel::RepoOnly,
        })]
    );
}

#[test]
fn happy_path_verify_bundle() {
    let root_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let root_arg = format!("sha256:{root_hex}");

    let backend = RecordingBackend::new();
    let (code, out, err) = exec(&backend, &["verify-bundle", "/bundles/b1"]);
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(out, "verify-bundle: bundle verified\n");
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::VerifyBundle(VerifyBundleRequest {
            dir: PathBuf::from("/bundles/b1"),
            root: None,
        })]
    );

    let backend2 = RecordingBackend::new();
    let (code2, _, err2) = exec(
        &backend2,
        &["verify-bundle", "--root", &root_arg, "/bundles/b1"],
    );
    assert_eq!(code2, ExitCode::SUCCESS);
    assert!(err2.is_empty());
    assert_eq!(
        backend2.calls(),
        vec![RecordedCall::VerifyBundle(VerifyBundleRequest {
            dir: PathBuf::from("/bundles/b1"),
            root: Some(root_arg),
        })]
    );
}

#[test]
fn happy_path_probe_human_and_canonical_json() {
    let backend = RecordingBackend::new();
    let (code, out, err) = exec(&backend, &["probe", "--world", "/worlds/w1"]);
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(out, "probe: probe complete\n");
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::Probe(ProbeRequest {
            world: PathBuf::from("/worlds/w1"),
            json: false,
            clockprobe_output: None,
            kernel_canary_serial: None,
        })]
    );

    let outcome = Outcome::success("sealed")
        .with_detail("z_field", Value::from(2))
        .with_detail("a_field", Value::from(1));
    let backend_json = RecordingBackend::with_result(Ok(outcome));
    let (code_j, out_j, err_j) = exec(&backend_json, &["probe", "--world", "/worlds/w1", "--json"]);
    assert_eq!(code_j, ExitCode::SUCCESS);
    assert!(err_j.is_empty());
    assert_eq!(out_j.lines().count(), 1);
    assert_eq!(
        out_j.trim_end(),
        r#"{"command":"probe","details":{"a_field":1,"z_field":2},"ok":true,"summary":"sealed"}"#
    );
    assert_eq!(
        backend_json.calls(),
        vec![RecordedCall::Probe(ProbeRequest {
            world: PathBuf::from("/worlds/w1"),
            json: true,
            clockprobe_output: None,
            kernel_canary_serial: None,
        })]
    );
}

#[test]
fn happy_path_run_human_and_json() {
    let backend = RecordingBackend::new();
    let (code, out, err) = exec(
        &backend,
        &[
            "run",
            "--world",
            "/worlds/w1",
            "--task",
            "SWE_bench.task-42",
            "--agent-mode",
            "H",
        ],
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(out, "run: run complete\n");
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::Run(RunRequest {
            world: PathBuf::from("/worlds/w1"),
            task: "SWE_bench.task-42".to_string(),
            agent_mode: AgentMode::H,
            clock: ClockMode::Faked,
            json: false,
            key: None,
            out: None,
            run_dir: None,
            entrypoint: None,
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        })]
    );

    let backend_g = RecordingBackend::new();
    let (code_g, out_g, err_g) = exec(
        &backend_g,
        &[
            "run",
            "--world",
            "/worlds/w1",
            "--task",
            "task_99",
            "--agent-mode",
            "G",
            "--clock",
            "faked",
            "--json",
        ],
    );
    assert_eq!(code_g, ExitCode::SUCCESS);
    assert!(err_g.is_empty());
    assert_eq!(
        out_g.trim_end(),
        r#"{"command":"run","ok":true,"summary":"run complete"}"#
    );
    assert_eq!(
        backend_g.calls(),
        vec![RecordedCall::Run(RunRequest {
            world: PathBuf::from("/worlds/w1"),
            task: "task_99".to_string(),
            agent_mode: AgentMode::G,
            clock: ClockMode::Faked,
            json: true,
            key: None,
            out: None,
            run_dir: None,
            entrypoint: None,
            model: None,
            upstream_url: None,
            upstream_key_file: None,
        })]
    );
}

#[test]
fn happy_path_verify_with_and_without_bundle() {
    let backend = RecordingBackend::new();
    let (code, out, err) = exec(
        &backend,
        &["verify", "--record", "/runs/rec.json", "--key", "/k"],
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(out, "verify: record verified\n");
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::Verify(VerifyRequest {
            record: PathBuf::from("/runs/rec.json"),
            key: PathBuf::from("/k"),
            bundle: None,
            classification: None,
        })]
    );

    let backend2 = RecordingBackend::new();
    let (code2, _, err2) = exec(
        &backend2,
        &[
            "verify",
            "--record",
            "/runs/rec.json",
            "--key",
            "/k",
            "--bundle",
            "/worlds/w1",
        ],
    );
    assert_eq!(code2, ExitCode::SUCCESS);
    assert!(err2.is_empty());
    assert_eq!(
        backend2.calls(),
        vec![RecordedCall::Verify(VerifyRequest {
            record: PathBuf::from("/runs/rec.json"),
            key: PathBuf::from("/k"),
            bundle: Some(PathBuf::from("/worlds/w1")),
            classification: None,
        })]
    );
}

#[test]
fn flag_equals_value_form_supported_everywhere() {
    let backend = RecordingBackend::new();
    let (code, _, err) = exec(
        &backend,
        &[
            "seal",
            "--src=/repos/dir=1",
            "--out=/worlds/dir=2",
            "--t-clock=2026-01-01T00:00:00Z",
            "--world-id=world-eq",
            "--seal-level=repo_only",
        ],
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::Seal(SealRequest {
            src: PathBuf::from("/repos/dir=1"),
            out: PathBuf::from("/worlds/dir=2"),
            t_clock: "2026-01-01T00:00:00Z".to_string(),
            world_id: "world-eq".to_string(),
            seal_level: SealLevel::RepoOnly,
        })]
    );
}

#[test]
fn double_dash_ends_options() {
    // Positional starting with '--' accepted after '--'
    let backend = RecordingBackend::new();
    let (code, _, err) = exec(&backend, &["verify-bundle", "--", "--weird-bundle-dir"]);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(err.is_empty());
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::VerifyBundle(VerifyBundleRequest {
            dir: PathBuf::from("--weird-bundle-dir"),
            root: None,
        })]
    );

    // Token after '--' on a subcommand with no positionals fails as stray positional (64)
    let backend2 = RecordingBackend::new();
    let (code2, out2, err2) = exec(
        &backend2,
        &["probe", "--world", "/worlds/w1", "--", "--json"],
    );
    assert_eq!(code2, ExitCode::USAGE_ERROR);
    assert!(out2.is_empty());
    assert!(err2.contains("unexpected positional argument '--json'"));
    assert!(err2.contains("USAGE:"));
    assert!(backend2.calls().is_empty());
}

#[test]
fn usage_error_classes_all_exit_64_with_usage_on_stderr() {
    let backend = RecordingBackend::new();

    // 1. Missing subcommand
    let (code, out, err) = exec(&backend, &[]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(out.is_empty());
    assert!(err.contains("missing subcommand"));
    assert!(err.contains("USAGE:"));

    // 2. Unknown subcommand
    let (code, _, err) = exec(&backend, &["deploy"]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(err.contains("unknown subcommand 'deploy'"));
    assert!(err.contains("USAGE:"));

    // 3. Unknown flag (including --json on commands that do not accept it)
    for cmd_args in [
        &["seal", "--unknown"][..],
        &["verify-bundle", "/b", "--json"][..],
        &["probe", "--world", "/w", "--bogus"][..],
        &[
            "run",
            "--world",
            "/w",
            "--task",
            "t",
            "--agent-mode",
            "H",
            "--bogus",
        ][..],
        &["verify", "--record", "/r", "--key", "/k", "--json"][..],
    ] {
        let (code, out, err) = exec(&backend, cmd_args);
        assert_eq!(code, ExitCode::USAGE_ERROR, "failed for {cmd_args:?}");
        assert!(out.is_empty());
        assert!(err.contains("unknown flag"));
        assert!(err.contains("USAGE:"));
    }

    // 4. Short flags rejected
    for short_args in [&["-v"][..], &["probe", "-w", "/w"][..], &["probe", "-"][..]] {
        let (code, _, err) = exec(&backend, short_args);
        assert_eq!(code, ExitCode::USAGE_ERROR, "failed for {short_args:?}");
        assert!(err.contains("short flags are not supported"));
        assert!(err.contains("USAGE:"));
    }

    // 5. Missing flag value (at end, before '--', and before next '--flag')
    for missing_val in [
        &["probe", "--world"][..],
        &["probe", "--world", "--"][..],
        &["probe", "--world", "--json"][..],
    ] {
        let (code, _, err) = exec(&backend, missing_val);
        assert_eq!(code, ExitCode::USAGE_ERROR, "failed for {missing_val:?}");
        assert!(err.contains("flag '--world' requires a value"));
        assert!(err.contains("USAGE:"));
    }

    // 6. Unexpected value on boolean flag
    let (code, _, err) = exec(&backend, &["probe", "--world", "/w", "--json=true"]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(err.contains("flag '--json' does not accept a value"));
    assert!(err.contains("USAGE:"));

    // 7. Repeated flags (value flags and boolean flags)
    for repeated in [
        &["probe", "--world", "/w1", "--world", "/w2"][..],
        &["probe", "--world", "/w1", "--json", "--json"][..],
        &[
            "verify-bundle",
            "/b",
            "--root",
            "sha256:00",
            "--root",
            "sha256:11",
        ][..],
    ] {
        let (code, _, err) = exec(&backend, repeated);
        assert_eq!(code, ExitCode::USAGE_ERROR, "failed for {repeated:?}");
        assert!(err.contains("cannot be specified more than once"));
        assert!(err.contains("USAGE:"));
    }

    // 8. Missing required flags & missing required positional
    let (code, _, err) = exec(
        &backend,
        &[
            "seal",
            "--src",
            "/s",
            "--out",
            "/o",
            "--t-clock",
            "2026-01-01T00:00:00Z",
        ],
    );
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(err.contains("missing required flag '--world-id'"));

    let (code, _, err) = exec(&backend, &["verify-bundle"]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(err.contains("missing required positional argument <DIR>"));

    // 9. Stray positional arguments
    for stray in [
        &[
            "seal",
            "--src",
            "/s",
            "--out",
            "/o",
            "--t-clock",
            "2026-01-01T00:00:00Z",
            "--world-id",
            "w",
            "extra",
        ][..],
        &["verify-bundle", "/b1", "/b2"][..],
        &["probe", "--world", "/w", "extra"][..],
        &[
            "run",
            "--world",
            "/w",
            "--task",
            "t",
            "--agent-mode",
            "H",
            "extra",
        ][..],
        &["verify", "--record", "/r", "--key", "/k", "extra"][..],
        &["--version", "extra"][..],
        &["help", "seal", "extra"][..],
    ] {
        let (code, _, err) = exec(&backend, stray);
        assert_eq!(code, ExitCode::USAGE_ERROR, "failed for {stray:?}");
        assert!(err.contains("unexpected positional argument"));
        assert!(err.contains("USAGE:"));
    }

    // 10. Invalid grammar enum choices
    let (code, _, err) = exec(
        &backend,
        &["run", "--world", "/w", "--task", "t", "--agent-mode", "X"],
    );
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(err.contains("invalid value 'X' for '--agent-mode'"));

    assert!(backend.calls().is_empty());
}

#[test]
fn non_utf8_argument_refused_without_lossy_conversion() {
    #[cfg(unix)]
    let bad_os: OsString = {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![0xff, 0xfe, 0xfd])
    };

    #[cfg(windows)]
    let bad_os: OsString = {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0xD800])
    };

    let err = parse_args(vec![
        OsString::from("probe"),
        OsString::from("--world"),
        bad_os.clone(),
    ])
    .expect_err("non-UTF-8 argument must be rejected");
    assert_eq!(err.kind, ParseErrorKind::NonUtf8Argument { position: 3 });

    let backend = RecordingBackend::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_from_env_args(
        vec![
            OsString::from("hermetic"),
            OsString::from("probe"),
            OsString::from("--world"),
            bad_os,
        ],
        &backend,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(stdout.is_empty());
    let err_str = String::from_utf8(stderr).expect("stderr must be UTF-8");
    assert!(err_str.contains("argument at position 3 is not valid UTF-8"));
    assert!(!err_str.contains('\u{FFFD}'));
    assert!(backend.calls().is_empty());
}

#[test]
fn validation_rejects_invalid_inputs_before_dispatch() {
    let backend = RecordingBackend::new();

    // Invalid timestamps (non-Z, lowercase z, bad calendar day, bad format)
    for bad_ts in [
        "2026-03-15T12:00:00+00:00",
        "2026-03-15T12:00:00-05:00",
        "2026-03-15T12:00:00z",
        "2026-03-15 12:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:00.Z",
        "",
    ] {
        let (code, out, err) = exec(
            &backend,
            &[
                "seal",
                "--src",
                "/s",
                "--out",
                "/o",
                "--t-clock",
                bad_ts,
                "--world-id",
                "w1",
            ],
        );
        assert_eq!(
            code,
            ExitCode::DATA_ERROR,
            "timestamp '{bad_ts}' must fail with 65"
        );
        assert!(out.is_empty());
        assert!(err.contains("RFC 3339 UTC timestamp"));
    }

    // Invalid world IDs: [a-z0-9-]{1,64}
    let too_long_world = "a".repeat(65);
    for bad_world in [
        "",
        "Upper",
        "has_underscore",
        "has.dot",
        "a/b",
        &too_long_world,
    ] {
        let (code, _, err) = exec(
            &backend,
            &[
                "seal",
                "--src",
                "/s",
                "--out",
                "/o",
                "--t-clock",
                "2026-01-01T00:00:00Z",
                "--world-id",
                bad_world,
            ],
        );
        assert_eq!(
            code,
            ExitCode::DATA_ERROR,
            "world-id '{bad_world}' must fail with 65"
        );
        assert!(err.contains("invalid world id"));
    }

    // Invalid task IDs: [A-Za-z0-9._-]{1,128}
    let too_long_task = "T".repeat(129);
    for bad_task in ["", "bad/slash", "bad space", "bad:colon", &too_long_task] {
        let (code, _, err) = exec(
            &backend,
            &[
                "run",
                "--world",
                "/w",
                "--task",
                bad_task,
                "--agent-mode",
                "H",
            ],
        );
        assert_eq!(
            code,
            ExitCode::DATA_ERROR,
            "task '{bad_task}' must fail with 65"
        );
        assert!(err.contains("invalid task id"));
    }

    // Invalid sha256 roots: "sha256:" + 64 lowercase hex
    let upper_hex = format!(
        "sha256:{}",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    );
    let short_hex = format!("sha256:{}", "a".repeat(63));
    let long_hex = format!("sha256:{}", "a".repeat(65));
    let non_hex = format!("sha256:{}", "g".repeat(64));
    for bad_root in [
        "",
        "0123456789abcdef",
        &upper_hex,
        &short_hex,
        &long_hex,
        &non_hex,
    ] {
        let (code, _, err) = exec(&backend, &["verify-bundle", "/b", "--root", bad_root]);
        assert_eq!(
            code,
            ExitCode::DATA_ERROR,
            "root '{bad_root}' must fail with 65"
        );
        assert!(err.contains("invalid sha256 root"));
    }

    // Invalid paths: empty or containing NUL
    for (cmd_args, field_label) in [
        (
            &[
                "seal",
                "--src",
                "",
                "--out",
                "/o",
                "--t-clock",
                "2026-01-01T00:00:00Z",
                "--world-id",
                "w",
            ][..],
            "--src",
        ),
        (
            &[
                "seal",
                "--src",
                "/s",
                "--out",
                "a\0b",
                "--t-clock",
                "2026-01-01T00:00:00Z",
                "--world-id",
                "w",
            ][..],
            "--out",
        ),
        (&["verify-bundle", ""][..], "DIR"),
        (&["probe", "--world", "w\0x"][..], "--world"),
        (&["verify", "--record", "", "--key", "/k"][..], "--record"),
        (
            &[
                "verify", "--record", "/r", "--key", "/k", "--bundle", "b\0c",
            ][..],
            "--bundle",
        ),
    ] {
        let (code, _, err) = exec(&backend, cmd_args);
        assert_eq!(
            code,
            ExitCode::DATA_ERROR,
            "path {cmd_args:?} must fail with 65"
        );
        assert!(err.contains(field_label));
    }

    assert!(backend.calls().is_empty());
}

#[test]
fn hidden_clock_parsed_but_refused_by_dispatch_with_exit_70() {
    let backend = RecordingBackend::new();
    let (code, out, err) = exec(
        &backend,
        &[
            "run",
            "--world",
            "/worlds/w1",
            "--task",
            "task-1",
            "--agent-mode",
            "H",
            "--clock",
            "hidden",
        ],
    );
    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
    assert!(out.is_empty());
    assert!(err.contains("hidden clock level is not available yet"));
    assert!(backend.calls().is_empty());
}

#[test]
fn exit_code_table_and_not_implemented_backend() {
    // 0: success
    let ok_backend = RecordingBackend::with_result(Ok(Outcome::success("all good")));
    let (c0, _, _) = exec(&ok_backend, &["verify", "--record", "/r", "--key", "/k"]);
    assert_eq!(c0, ExitCode(0));

    // 2: operation ran and found a problem (via Outcome.ok == false)
    let fail_outcome_backend =
        RecordingBackend::with_result(Ok(Outcome::problem("digest mismatch")));
    let (c2a, out2a, err2a) = exec(
        &fail_outcome_backend,
        &["verify", "--record", "/r", "--key", "/k"],
    );
    assert_eq!(c2a, ExitCode(2));
    assert_eq!(out2a, "verify: digest mismatch\n");
    assert!(err2a.is_empty());

    // 2: operation ran and found a problem (via BackendError::ProblemFound)
    let fail_err_backend = RecordingBackend::with_result(Err(BackendError::ProblemFound(
        "signature invalid".to_string(),
    )));
    let (c2b, out2b, err2b) = exec(
        &fail_err_backend,
        &["verify", "--record", "/r", "--key", "/k"],
    );
    assert_eq!(c2b, ExitCode(2));
    assert!(out2b.is_empty());
    assert_eq!(err2b, "error: signature invalid\n");

    // 64: usage error
    let (c64, _, _) = exec(&ok_backend, &["unknown-cmd"]);
    assert_eq!(c64, ExitCode(64));

    // 65: invalid input data
    let (c65, _, _) = exec(&ok_backend, &["verify-bundle", "/b", "--root", "bad"]);
    assert_eq!(c65, ExitCode(65));

    // 70: NotImplementedBackend on all subcommands
    let not_impl = NotImplementedBackend;
    for cmd in [
        &[
            "seal",
            "--src",
            "/s",
            "--out",
            "/o",
            "--t-clock",
            "2026-01-01T00:00:00Z",
            "--world-id",
            "w",
        ][..],
        &["verify-bundle", "/b"][..],
        &["probe", "--world", "/w"][..],
        &["run", "--world", "/w", "--task", "t", "--agent-mode", "H"][..],
        &["verify", "--record", "/r", "--key", "/k"][..],
    ] {
        let (c70, out70, err70) = exec(&not_impl, cmd);
        assert_eq!(
            c70,
            ExitCode(70),
            "NotImplementedBackend must exit 70 for {cmd:?}"
        );
        assert!(out70.is_empty());
        assert!(err70.contains("not yet wired"));
    }

    // 74: I/O error
    let io_backend =
        RecordingBackend::with_result(Err(BackendError::Io("permission denied".to_string())));
    let (c74, out74, err74) = exec(&io_backend, &["probe", "--world", "/w"]);
    assert_eq!(c74, ExitCode(74));
    assert!(out74.is_empty());
    assert_eq!(err74, "error: I/O error: permission denied\n");
}

#[test]
fn help_text_and_version_snapshots() {
    let backend = RecordingBackend::new();

    let (code_v, out_v, err_v) = exec(&backend, &["--version"]);
    assert_eq!(code_v, ExitCode::SUCCESS);
    assert_eq!(out_v, "hermetic 0.1.0\n");
    assert!(err_v.is_empty());

    let (code_h, out_h, err_h) = exec(&backend, &["help"]);
    assert_eq!(code_h, ExitCode::SUCCESS);
    assert!(err_h.is_empty());
    assert_eq!(
        out_h,
        "\
hermetic - Seal and evaluate Hermetic World software-engineering benchmarks

USAGE:
  hermetic seal --src DIR --out DIR --t-clock RFC3339 --world-id ID [--seal-level strict|repo_only]
  hermetic verify-bundle DIR [--root sha256:HEX]
  hermetic probe --world DIR [--clockprobe-output FILE] [--kernel-canary-serial FILE] [--json]
  hermetic run --world DIR --task ID --agent-mode H|G [--clock faked|hidden] [--json]
  hermetic verify --record FILE --key FILE [--bundle DIR] [--classification FILE]
  hermetic --version
  hermetic help [SUBCOMMAND]

SUBCOMMANDS:
  seal           Seal a source repository into a deterministic Hermetic World
  verify-bundle  Verify integrity and root digest of a sealed world bundle
  probe          Classify captured clock probe output (never probes the host)
  run            Execute a benchmark task inside a sealed world
  verify         Verify a recorded evaluation run against a bundle
  help           Show general or subcommand help

OPTIONS:
  Both --flag=value and --flag value forms are accepted.
  Use -- to terminate option parsing; short flags are not supported.

EXIT CODES:
  0   Success
  2   Operation completed and found a problem (for example, verification failed)
  64  Command-line usage error
  65  Invalid input data
  70  Internal error or feature not implemented
  74  I/O error
"
    );

    let (code_hs, out_hs, err_hs) = exec(&backend, &["help", "seal"]);
    assert_eq!(code_hs, ExitCode::SUCCESS);
    assert!(err_hs.is_empty());
    assert_eq!(
        out_hs,
        "\
USAGE:
  hermetic seal --src DIR --out DIR --t-clock RFC3339 --world-id ID [--seal-level strict|repo_only]

OPTIONS:
  --src DIR                      Source directory path (non-empty, no NUL bytes)
  --out DIR                      Output bundle directory path (non-empty, no NUL bytes)
  --t-clock RFC3339              Cutoff timestamp in UTC RFC 3339 format with 'Z' suffix
  --world-id ID                  World identifier matching [a-z0-9-]{1,64}
  --seal-level strict|repo_only  Sealing strictness level (default: strict)
"
    );

    let (code_hr, out_hr, err_hr) = exec(&backend, &["help", "run"]);
    assert_eq!(code_hr, ExitCode::SUCCESS);
    assert!(err_hr.is_empty());
    assert_eq!(
        out_hr,
        "\
USAGE:
  hermetic run --world DIR --task ID --agent-mode H|G [--clock faked|hidden] [--json]

OPTIONS:
  --world DIR            Sealed world directory path (non-empty, no NUL bytes)
  --task ID              Task identifier matching [A-Za-z0-9._-]{1,128}
  --agent-mode H|G       Agent evaluation mode ('H' or 'G')
  --clock faked|hidden   Clock isolation mode (default: faked)
  --json                 Emit a single canonical JSON object on stdout
"
    );

    assert_eq!(SubcommandKind::VerifyBundle.as_str(), "verify-bundle");
    assert!(backend.calls().is_empty());
}

#[test]
fn regression_argument_count_is_capped() {
    use hermetic_cli::MAX_ARGS;
    let mut args = vec!["probe".to_string(), "--world".to_string(), "w".to_string()];
    while args.len() <= MAX_ARGS {
        args.push("--json".to_string());
    }
    let os: Vec<OsString> = args.iter().map(OsString::from).collect();
    let err = parse_args(os).expect_err("must refuse");
    assert_eq!(
        err.kind,
        ParseErrorKind::TooManyArguments { limit: MAX_ARGS }
    );
    let backend = RecordingBackend::new();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _out, _err) = exec(&backend, &refs);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(backend.calls().is_empty());
}

#[test]
fn regression_argument_length_is_capped() {
    use hermetic_cli::MAX_ARG_BYTES;
    let long_world = "w".repeat(MAX_ARG_BYTES + 1);
    let err = parse_args(os_args(&["probe", "--world", &long_world])).expect_err("must refuse");
    assert_eq!(
        err.kind,
        ParseErrorKind::ArgumentTooLong {
            position: 3,
            limit: MAX_ARG_BYTES
        }
    );
    let exact = "w".repeat(MAX_ARG_BYTES);
    assert!(parse_args(os_args(&["probe", "--world", &exact])).is_ok());
}

#[test]
fn regression_timestamp_fraction_and_leap_years() {
    use hermetic_cli::args::validate_rfc3339_utc;
    assert!(validate_rfc3339_utc("2024-02-29T00:00:00Z").is_ok());
    assert!(validate_rfc3339_utc("2000-02-29T00:00:00Z").is_ok());
    assert!(validate_rfc3339_utc("1900-02-29T00:00:00Z").is_err());
    assert!(validate_rfc3339_utc("2023-02-29T00:00:00Z").is_err());
    assert!(validate_rfc3339_utc("2024-01-01T00:00:00.5Z").is_ok());
    assert!(validate_rfc3339_utc("2024-01-01T00:00:00.Z").is_err());
    assert!(validate_rfc3339_utc("2024-01-01T00:00:00xZ").is_err());
    // Multi-byte UTF-8 at a separator position must be refused, never panic.
    assert!(validate_rfc3339_utc("2024\u{e9}01-01T00:00:00Z").is_err());
    assert!(validate_rfc3339_utc("2024-01-01T00:00:00\u{e9}Z").is_err());
}

#[test]
fn verify_requires_a_trusted_key_and_parses_classification() {
    let backend = RecordingBackend::new();
    let (code, _, _) = exec(&backend, &["verify", "--record", "/r"]);
    assert_eq!(code, ExitCode::USAGE_ERROR);
    assert!(backend.calls().is_empty());
    let (code, _, err) = exec(
        &backend,
        &[
            "verify",
            "--record",
            "/r",
            "--key",
            "/k",
            "--classification",
            "/c",
        ],
    );
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(
        backend.calls(),
        vec![RecordedCall::Verify(VerifyRequest {
            record: PathBuf::from("/r"),
            key: PathBuf::from("/k"),
            bundle: None,
            classification: Some(PathBuf::from("/c")),
        })]
    );
    let (code, _, _) = exec(&backend, &["verify", "--record", "/r", "--key", ""]);
    assert_eq!(code, ExitCode::DATA_ERROR);
}
