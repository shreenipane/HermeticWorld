mod support;
use hermetic_vmm::spec::{Role, MAX_SPEC_BYTES};
use std::io::Write;
use std::process::{Command, Stdio};
fn plan(data: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .args(["plan", "-"])
        .env("HERMETIC_TSC_KHZ", "2000000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(data);
    child.wait_with_output().unwrap()
}
#[test]
fn plan_json_is_deterministic_and_never_opens_spec_image_paths() {
    let data = serde_json::to_vec(&support::spec(Role::Agent)).unwrap();
    let first = plan(&data);
    let second = plan(&data);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(value["api_requests"].as_array().unwrap().len(), 9);
    assert_eq!(value["jail_plan"]["uid"], 200000);
}
#[test]
fn validation_and_io_have_distinct_exit_codes_and_no_input_echo() {
    for input in [
        b"host-secret-date".to_vec(),
        vec![b' '; MAX_SPEC_BYTES as usize + 1],
    ] {
        let output = plan(&input);
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8(output.stderr)
            .unwrap()
            .contains("host-secret-date"));
        assert!(output.stdout.is_empty());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .args(["plan", "/does-not-exist/spec.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8(output.stderr)
        .unwrap()
        .contains("does-not-exist"));
}
#[test]
fn non_utf8_arguments_are_refused_without_a_panic() {
    use std::os::unix::ffi::OsStringExt;
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .arg("plan")
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stderr, b"refused: argument encoding\n");
    assert!(output.stdout.is_empty());
}

#[test]
fn cli_plan_and_direct_boot_args_share_calibration_and_reject_invalid_overrides() {
    let output = plan(&serde_json::to_vec(&support::spec(Role::Agent)).unwrap());
    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let args = v["api_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == "/boot-source")
        .unwrap()["body"]["boot_args"]
        .as_str()
        .unwrap();
    // The frequency reaches the guest only via the pinned CPUID leaf 0x15.
    assert_eq!(args.matches("tsc_early_khz").count(), 0);
    let base = support::spec(Role::Agent).boot_args;
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .args(["boot-args", &base])
        .env("HERMETIC_TSC_KHZ", "2000000")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim_end(), args);
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .args(["boot-args", &base])
        .env("HERMETIC_TSC_KHZ", "secret")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8(output.stderr).unwrap().contains("secret"));
}
