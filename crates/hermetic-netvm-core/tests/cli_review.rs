use std::{os::unix::ffi::OsStringExt, process::Command};

#[test]
fn invalid_cli_is_bounded_and_never_panics_or_echoes_values() {
    for arg in [
        std::ffi::OsString::from_vec(vec![0xff]),
        "SECRET_HOST_IDENTITY".into(),
        "x".repeat(4097).into(),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hermetic-netvm"))
            .arg(arg)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stderr, b"netvm_start_failed: invalid_arguments\n");
        assert!(output.stdout.is_empty());
    }
}
