mod support;
use hermetic_vmm::spec::{Role, MAX_SPEC_BYTES};
use std::io::Write;
use std::process::{Command, Stdio};
fn plan(data: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .args(["plan", "-"])
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
