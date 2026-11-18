#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use hermetic_bundle::Verdict;
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

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn create_mock_sealer(dir: &Path, exit_code: i32) -> std::path::PathBuf {
    let script_path = dir.join(format!("mock-sealer-{exit_code}.sh"));
    let content = format!(
        "#!/bin/sh\n\
         # parse args to find --out\n\
         out=\"\"\n\
         while [ $# -gt 0 ]; do\n\
           case \"$1\" in\n\
             --out) out=\"$2\"; shift 2 ;;\n\
             *) shift ;;\n\
           esac\n\
         done\n\
         if [ -n \"$out\" ] && [ {exit_code} -eq 0 ]; then\n\
           mkdir -p \"$out\"\n\
           echo 'dummy content' > \"$out/file.txt\"\n\
           echo '{{\"task_id\":\"mock\"}}' > \"$out/world_manifest.json\"\n\
         fi\n\
         exit {exit_code}\n"
    );
    fs::write(&script_path, content).unwrap();
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700)).unwrap();
    script_path
}

#[test]
fn seal_happy_path_with_sealer_subprocess() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("sample.txt"), b"sample").unwrap();

    let out_dir = temp.path().join("out");
    let sealer_bin = create_mock_sealer(temp.path(), 0);

    // Save and restore env var
    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&src_dir),
        "--out",
        p(&out_dir),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "happy-world",
        "--seal-level",
        "strict",
    ]);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert_eq!(code, ExitCode::SUCCESS, "stderr: {err}");
    assert!(err.is_empty(), "stderr should be empty, got: {err}");
    assert!(out.contains("seal: sealed world happy-world in bundle.manifest.json"));

    // Verify bundle manifest exists and is valid
    let manifest_path = out_dir.join(hermetic_bundle::MANIFEST_FILENAME);
    assert!(manifest_path.exists());
    let report = hermetic_bundle::verify(&out_dir, None).unwrap();
    assert_eq!(report.verdict, Verdict::Ok);

    // Verify world_manifest.json exists
    assert!(out_dir.join("world_manifest.json").exists());
}

#[test]
fn seal_gate_failure_exits_2() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let out_dir = temp.path().join("out");
    let sealer_bin = create_mock_sealer(temp.path(), 2);

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&src_dir),
        "--out",
        p(&out_dir),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "gate-fail",
    ]);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert_eq!(code, ExitCode::PROBLEM_FOUND);
    assert!(out.is_empty());
    assert_eq!(
        err,
        "error: sealcheck gate rejected sealed world: problem found\n"
    );
}

#[test]
fn seal_invalid_input_data_exits_65() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let real_dir = temp.path().join("real_src");
    fs::create_dir_all(&real_dir).unwrap();
    let sym_dir = temp.path().join("sym_src");
    symlink(&real_dir, &sym_dir).unwrap();

    let sealer_bin = create_mock_sealer(temp.path(), 0);
    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    // 1. Symlinked source directory refused
    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&sym_dir),
        "--out",
        p(&temp.path().join("out1")),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "w1",
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(out.is_empty());
    assert!(err.contains("invalid input: refused path: symlink encountered"));

    // 2. Invalid timestamp format
    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&real_dir),
        "--out",
        p(&temp.path().join("out2")),
        "--t-clock",
        "not-a-timestamp",
        "--world-id",
        "w1",
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(out.is_empty());
    assert!(err.contains("invalid RFC 3339 UTC timestamp"));

    // 3. Invalid world_id
    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&real_dir),
        "--out",
        p(&temp.path().join("out3")),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "invalid id with spaces",
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(out.is_empty());
    assert!(err.contains("invalid world id"));

    // 4. Output directory already exists and is non-empty
    let non_empty_out = temp.path().join("non_empty_out");
    fs::create_dir_all(&non_empty_out).unwrap();
    fs::write(non_empty_out.join("existing.txt"), b"already here").unwrap();

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&real_dir),
        "--out",
        p(&non_empty_out),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "w1",
    ]);
    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(out.is_empty());
    assert!(
        err.contains("invalid input: refused output directory: already exists and is not empty")
    );

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }
}

#[test]
fn seal_missing_source_exits_74() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let missing_src = temp.path().join("does_not_exist");
    let sealer_bin = create_mock_sealer(temp.path(), 0);

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&missing_src),
        "--out",
        p(&temp.path().join("out")),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "w1",
    ]);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert_eq!(code, ExitCode::IO_ERROR);
    assert!(out.is_empty());
    assert_eq!(err, "error: I/O error: input directory not found\n");
}

#[test]
fn seal_subprocess_failure_exits_70() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let sealer_bin = create_mock_sealer(temp.path(), 70);
    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&src_dir),
        "--out",
        p(&temp.path().join("out")),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "crash-world",
    ]);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
    assert!(out.is_empty());
    assert_eq!(err, "error: internal error: sealer subprocess failed\n");
}

#[test]
fn seal_refuses_symlinked_sealer_binary() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let real_sealer = create_mock_sealer(temp.path(), 0);
    let sym_sealer = temp.path().join("sym-sealer");
    symlink(&real_sealer, &sym_sealer).unwrap();

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sym_sealer);

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&src_dir),
        "--out",
        p(&temp.path().join("out")),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "sym-bin-world",
    ]);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert_eq!(code, ExitCode::DATA_ERROR);
    assert!(out.is_empty());
    assert!(err.contains("refused executable binary: symlink"));
}

#[test]
fn seal_fails_closed_when_sealer_does_not_produce_world_manifest() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let out_dir = temp.path().join("out");
    let script_path = temp.path().join("sealer-no-manifest.sh");
    let content = "#!/bin/sh\n\
         out=\"\"\n\
         while [ $# -gt 0 ]; do\n\
           case \"$1\" in\n\
             --out) out=\"$2\"; shift 2 ;;\n\
             *) shift ;;\n\
           esac\n\
         done\n\
         if [ -n \"$out\" ]; then\n\
           mkdir -p \"$out\"\n\
           echo 'dummy content' > \"$out/file.txt\"\n\
         fi\n\
         exit 0\n";
    fs::write(&script_path, content).unwrap();
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700)).unwrap();

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &script_path);

    let (code, out, err) = exec(&[
        "seal",
        "--src",
        p(&src_dir),
        "--out",
        p(&out_dir),
        "--t-clock",
        "2020-01-01T00:00:00Z",
        "--world-id",
        "no-manifest-world",
        "--seal-level",
        "strict",
    ]);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert_eq!(code, ExitCode::INTERNAL_OR_NOT_IMPLEMENTED);
    assert!(out.is_empty());
    assert!(err.contains("sealer did not produce world_manifest.json"));
}

#[test]
fn seal_validate_timestamp_rejects_malformed_and_leading_minus() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let sealer_bin = create_mock_sealer(temp.path(), 0);
    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    for (i, bad_ts) in ["T+", "--T+", "-100", "-2020-01-01T00:00:00Z"]
        .iter()
        .enumerate()
    {
        let out_dir = temp.path().join(format!("out-bad-{i}"));
        let req = hermetic_cli::args::SealRequest {
            src: src_dir.clone(),
            out: out_dir,
            t_clock: bad_ts.to_string(),
            world_id: "test-world".into(),
            seal_level: hermetic_cli::args::SealLevel::Strict,
        };
        let err = hermetic_cli::seal::execute_seal(req).unwrap_err();
        match err {
            hermetic_cli::dispatch::BackendError::Data(msg) => {
                assert!(
                    msg.contains("invalid t_clock format"),
                    "unexpected error msg: {msg}"
                );
            }
            other => panic!("expected BackendError::Data for '{bad_ts}', got {other:?}"),
        }
    }

    // Verify non-negative integer epoch is accepted by execute_seal
    let epoch_out = temp.path().join("epoch-out");
    let req = hermetic_cli::args::SealRequest {
        src: src_dir.clone(),
        out: epoch_out,
        t_clock: "1577836800".to_string(),
        world_id: "epoch-world".into(),
        seal_level: hermetic_cli::args::SealLevel::Strict,
    };
    let res = hermetic_cli::seal::execute_seal(req);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert!(res.is_ok(), "epoch should be accepted: {:?}", res.err());
}
