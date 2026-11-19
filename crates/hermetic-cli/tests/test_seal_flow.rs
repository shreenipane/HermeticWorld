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
            packages_record: None,
            substrate: None,
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
        packages_record: None,
        substrate: None,
    };
    let res = hermetic_cli::seal::execute_seal(req);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert!(res.is_ok(), "epoch should be accepted: {:?}", res.err());
}

#[test]
fn test_seal_passes_packages_record_and_substrate_to_sealer() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let out_dir = temp.path().join("out");

    let pkg_file = temp.path().join("packages.json");
    fs::write(&pkg_file, b"{\"closure_root\":\"test\"}").unwrap();
    fs::set_permissions(&pkg_file, fs::Permissions::from_mode(0o644)).unwrap();

    let sub_file = temp.path().join("substrate.json");
    fs::write(&sub_file, b"{\"substrate\":[]}").unwrap();
    fs::set_permissions(&sub_file, fs::Permissions::from_mode(0o644)).unwrap();

    let sealer_bin = temp.path().join("mock-sealer.sh");
    let script = r#"#!/bin/sh
out=""
has_pkg=0
has_sub=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --packages-record) has_pkg=1; shift 2 ;;
    --substrate) has_sub=1; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$has_pkg" -eq 1 ] && [ "$has_sub" -eq 1 ] && [ -n "$out" ]; then
  mkdir -p "$out"
  echo '{"task_id":"mock"}' > "$out/world_manifest.json"
  exit 0
else
  exit 65
fi
"#;
    fs::write(&sealer_bin, script).unwrap();
    fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o700)).unwrap();

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let req = hermetic_cli::args::SealRequest {
        src: src_dir,
        out: out_dir.clone(),
        t_clock: "2026-01-01T00:00:00Z".to_string(),
        world_id: "test-world".to_string(),
        seal_level: hermetic_cli::args::SealLevel::RepoOnly,
        packages_record: Some(pkg_file),
        substrate: Some(sub_file),
    };

    let res = hermetic_cli::seal::execute_seal(req);

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert!(res.is_ok(), "sealer should receive flags: {:?}", res.err());
    assert!(out_dir.join("bundle.manifest.json").exists());
}

#[test]
fn test_seal_refuses_symlinked_packages_record() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let out_dir = temp.path().join("out");

    let real_pkg = temp.path().join("real_pkg.json");
    fs::write(&real_pkg, b"{}").unwrap();
    let sym_pkg = temp.path().join("sym_pkg.json");
    std::os::unix::fs::symlink(&real_pkg, &sym_pkg).unwrap();

    let sealer_bin = temp.path().join("mock-sealer.sh");
    fs::write(&sealer_bin, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o700)).unwrap();

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let req = hermetic_cli::args::SealRequest {
        src: src_dir,
        out: out_dir,
        t_clock: "2026-01-01T00:00:00Z".to_string(),
        world_id: "test-world".to_string(),
        seal_level: hermetic_cli::args::SealLevel::RepoOnly,
        packages_record: Some(sym_pkg),
        substrate: None,
    };

    let err = hermetic_cli::seal::execute_seal(req).unwrap_err();

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    match err {
        hermetic_cli::dispatch::BackendError::Data(msg) => {
            assert!(msg.contains("symlink"), "unexpected error: {msg}");
        }
        other => panic!("expected BackendError::Data, got {other:?}"),
    }
}

#[test]
fn test_real_sealer_happy_path_end_to_end() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("calc.py"),
        b"def add(a, b):\n    return a + b\n",
    )
    .unwrap();

    let run_spec_file = src_dir.join("run_spec.json");
    fs::write(
        &run_spec_file,
        br#"{
  "env": {"PATH": "/usr/bin:/bin"},
  "workdir": "/testbed",
  "user": "root",
  "entrypoint": ["/bin/sh"],
  "resources": {
    "vcpus": 2,
    "memory_mib": 4096,
    "disk_mib": 8192,
    "wall_time_s": 1800
  }
}"#,
    )
    .unwrap();

    let dns_file = src_dir.join("dns.json");
    fs::write(
        &dns_file,
        br#"{"records": [{"name": "example.com", "a": ["10.9.0.1"], "aaaa": []}]}"#,
    )
    .unwrap();

    let out_dir = temp.path().join("out");

    let pkg_file = temp.path().join("packages.json");
    fs::write(
        &pkg_file,
        br#"{
  "closure_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "baseline_month": "2020-01",
  "baseline_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}"#,
    )
    .unwrap();

    let sub_file = temp.path().join("substrate.json");
    fs::write(
        &sub_file,
        br#"{
  "substrate": [],
  "substrate_at_t": "none",
  "exemptions": []
}"#,
    )
    .unwrap();

    let top = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sealer_bin = top.join("scripts").join("hermetic-sealer");
    let _ = fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o755));
    assert!(sealer_bin.is_file(), "scripts/hermetic-sealer must exist");
    // Ensure executable permissions
    let _ = fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o755));

    // Static stand-in guest binaries (copies of the host's static busybox): the
    // sealer only accepts static ELF guest binaries from HERMETIC_GUEST_BIN_DIR.
    let guest_bins = temp.path().join("guest-bin");
    fs::create_dir_all(&guest_bins).unwrap();
    for name in ["hermetic-init", "hermetic-execd", "hermetic-clockprobe"] {
        fs::copy("/usr/bin/busybox", guest_bins.join(name)).unwrap();
    }
    let original_guest = std::env::var_os("HERMETIC_GUEST_BIN_DIR");
    std::env::set_var("HERMETIC_GUEST_BIN_DIR", &guest_bins);

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let req = hermetic_cli::args::SealRequest {
        src: src_dir,
        out: out_dir.clone(),
        t_clock: "2020-01-01T00:00:00Z".to_string(),
        world_id: "test-real-world".to_string(),
        seal_level: hermetic_cli::args::SealLevel::RepoOnly,
        packages_record: Some(pkg_file),
        substrate: Some(sub_file),
    };

    let res = hermetic_cli::seal::execute_seal(req);

    match original_guest {
        Some(val) => std::env::set_var("HERMETIC_GUEST_BIN_DIR", val),
        None => std::env::remove_var("HERMETIC_GUEST_BIN_DIR"),
    }
    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    assert!(res.is_ok(), "real sealer failed: {:?}", res.err());
    assert!(out_dir.join("bundle.manifest.json").exists());
    assert!(out_dir.join("world_manifest.json").exists());

    // Verify canonical WorldManifest
    let manifest_bytes = fs::read(out_dir.join("world_manifest.json")).unwrap();
    let canonical = hermetic_common::world_manifest::WorldManifest::from_json_str(
        std::str::from_utf8(&manifest_bytes).unwrap(),
    )
    .expect("world_manifest.json must be valid canonical WorldManifest");

    assert_eq!(canonical.task_id, "test-real-world");
    assert_eq!(
        canonical.seal_level,
        hermetic_common::world_manifest::SealLevel::RepoOnly
    );
    assert!(canonical.repo_tree_digest.starts_with("sha1:"));
    assert!(canonical.rootfs_digest.starts_with("sha256:"));
    assert!(canonical.world_ca_cert_sha256.starts_with("sha256:"));
    assert_eq!(
        canonical.trust_store_paths,
        vec!["/etc/ssl/certs/ca-certificates.crt"]
    );
    assert_eq!(canonical.dns_table, vec!["example.com"]);

    let world_root = canonical.world_root().expect("world_root must compute");
    assert!(world_root.starts_with("blake3:"));
}

#[test]
fn test_real_sealer_refuses_missing_packages_record() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("calc.py"), b"calc").unwrap();
    let out_dir = temp.path().join("out");

    let sub_file = temp.path().join("substrate.json");
    fs::write(&sub_file, b"{\"substrate\":[]}").unwrap();

    let top = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sealer_bin = top.join("scripts").join("hermetic-sealer");
    let _ = fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o755));

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let req = hermetic_cli::args::SealRequest {
        src: src_dir,
        out: out_dir,
        t_clock: "2020-01-01T00:00:00Z".to_string(),
        world_id: "test-missing-pkg".to_string(),
        seal_level: hermetic_cli::args::SealLevel::RepoOnly,
        packages_record: None,
        substrate: Some(sub_file),
    };

    let err = hermetic_cli::seal::execute_seal(req).unwrap_err();

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    match err {
        hermetic_cli::dispatch::BackendError::Data(msg) => {
            assert!(
                msg.contains("sealer rejected invalid input data"),
                "got: {msg}"
            );
        }
        other => panic!("expected BackendError::Data, got {other:?}"),
    }
}

#[test]
fn test_real_sealer_refuses_missing_substrate() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("calc.py"), b"calc").unwrap();
    let out_dir = temp.path().join("out");

    let pkg_file = temp.path().join("packages.json");
    fs::write(&pkg_file, b"{\"closure_root\":\"test\"}").unwrap();

    let top = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sealer_bin = top.join("scripts").join("hermetic-sealer");
    let _ = fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o755));

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let req = hermetic_cli::args::SealRequest {
        src: src_dir,
        out: out_dir,
        t_clock: "2020-01-01T00:00:00Z".to_string(),
        world_id: "test-missing-sub".to_string(),
        seal_level: hermetic_cli::args::SealLevel::RepoOnly,
        packages_record: Some(pkg_file),
        substrate: None,
    };

    let err = hermetic_cli::seal::execute_seal(req).unwrap_err();

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    match err {
        hermetic_cli::dispatch::BackendError::Data(msg) => {
            assert!(
                msg.contains("sealer rejected invalid input data"),
                "got: {msg}"
            );
        }
        other => panic!("expected BackendError::Data, got {other:?}"),
    }
}

#[test]
fn test_real_sealer_refuses_strict_seal_level() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("calc.py"), b"calc").unwrap();
    let out_dir = temp.path().join("out");

    let pkg_file = temp.path().join("packages.json");
    fs::write(&pkg_file, b"{\"closure_root\":\"test\"}").unwrap();
    let sub_file = temp.path().join("substrate.json");
    fs::write(&sub_file, b"{\"substrate\":[]}").unwrap();

    let top = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sealer_bin = top.join("scripts").join("hermetic-sealer");
    let _ = fs::set_permissions(&sealer_bin, fs::Permissions::from_mode(0o755));

    let original = std::env::var_os("HERMETIC_SEALER_BIN");
    std::env::set_var("HERMETIC_SEALER_BIN", &sealer_bin);

    let req = hermetic_cli::args::SealRequest {
        src: src_dir,
        out: out_dir,
        t_clock: "2020-01-01T00:00:00Z".to_string(),
        world_id: "test-strict-level".to_string(),
        seal_level: hermetic_cli::args::SealLevel::Strict,
        packages_record: Some(pkg_file),
        substrate: Some(sub_file),
    };

    let err = hermetic_cli::seal::execute_seal(req).unwrap_err();

    if let Some(val) = original {
        std::env::set_var("HERMETIC_SEALER_BIN", val);
    } else {
        std::env::remove_var("HERMETIC_SEALER_BIN");
    }

    match err {
        hermetic_cli::dispatch::BackendError::Data(msg) => {
            assert!(
                msg.contains("sealer rejected invalid input data"),
                "got: {msg}"
            );
        }
        other => panic!("expected BackendError::Data, got {other:?}"),
    }
}

#[test]
fn test_verify_regular_file_relative_parent_path() {
    let rel_file = Path::new("src/seal.rs");
    assert!(rel_file.exists());
    assert!(!Path::new("seal.rs").exists());
    assert!(hermetic_cli::seal::verify_regular_file_no_symlinks(rel_file).is_ok());

    // Bare filename relative to current dir
    let bare_file = Path::new("Cargo.toml");
    assert!(bare_file.exists());
    assert!(hermetic_cli::seal::verify_regular_file_no_symlinks(bare_file).is_ok());

    // Relative symlink in a subdirectory must be rejected
    let temp = tempfile::tempdir().unwrap();
    let sub = temp.path().join("sub");
    fs::create_dir_all(&sub).unwrap();
    let target = sub.join("real.txt");
    fs::write(&target, b"content").unwrap();
    let link = sub.join("link.txt");
    std::os::unix::fs::symlink("real.txt", &link).unwrap();

    assert!(hermetic_cli::seal::verify_regular_file_no_symlinks(&target).is_ok());
    let err = hermetic_cli::seal::verify_regular_file_no_symlinks(&link).unwrap_err();
    match err {
        hermetic_cli::dispatch::BackendError::Data(msg) => {
            assert!(msg.contains("refused file: symlink"), "got: {msg}");
        }
        other => panic!("expected BackendError::Data, got {other:?}"),
    }
}
