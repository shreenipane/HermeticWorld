use hermetic_clockprobe::{canary::*, classify::ProbeResult};
fn serial() -> String {
    EXPECTED
        .iter()
        .map(|s| format!("[    1.000] hermetic-canary/v1 {s}\n"))
        .collect()
}
#[test]
fn kernel_canary_requires_all_faults_and_untouched_pages() {
    let good = serial();
    assert_eq!(inspect(good.as_bytes()).result, ProbeResult::Blocked);
    for line in good.lines() {
        assert_eq!(
            inspect(good.replace(&format!("{line}\n"), "").as_bytes()).result,
            ProbeResult::Error
        );
    }
    assert_eq!(
        inspect(format!("{good}{good}").as_bytes()).result,
        ProbeResult::Error
    );
    for (from, to) in [
        ("wr=gp", "wr=accepted"),
        ("rd=gp", "rd=accepted"),
        ("page=unchanged", "page=changed"),
        ("ret=enosys", "ret=unexpected"),
        ("result=pass", "result=fail"),
    ] {
        assert_eq!(
            inspect(good.replace(from, to).as_bytes()).result,
            ProbeResult::Leak
        );
    }
    assert_eq!(
        inspect(&vec![b'x'; MAX_SERIAL_BYTES as usize + 1]).result,
        ProbeResult::Error
    );
    assert_eq!(inspect(b"\xff").result, ProbeResult::Error);
    assert!(!inspect(b"hermetic-canary/v1 secret-token")
        .to_json_line()
        .contains("secret-token"));
}
#[test]
fn explicit_cli_mode_validates_serial_without_executing_guest_probes() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_hermetic-clockprobe"))
        .arg("--kernel-canary-serial")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serial().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}\n", inspect(serial().as_bytes()).to_json_line())
    );
}
