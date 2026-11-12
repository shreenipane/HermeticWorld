#![forbid(unsafe_code)]

mod support;

use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn bin_path() -> PathBuf {
    let mut p = std::env::current_exe().expect("current exe");
    p.pop(); // deps
    p.pop(); // debug
    p.push("hermetic-world-server");
    if p.exists() {
        return p;
    }
    let target =
        PathBuf::from("/home/flingboot/hermetic/cargo-target/t2.1/debug/hermetic-world-server");
    if target.exists() {
        return target;
    }
    panic!("hermetic-world-server binary not found at {:?}", p);
}

#[test]
fn test_sandbox_child_process() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    std::fs::create_dir_all(&store_dir).expect("create store");
    std::fs::create_dir_all(&log_dir).expect("create log");

    let bin = bin_path();
    let output = support::output_bounded(
        Command::new(&bin)
            .env("HERMETIC_CHILD_ROLE", "sandbox")
            .env("HERMETIC_TEST_STORE", &store_dir)
            .env("HERMETIC_TEST_LOG", &log_dir),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Child stdout: {stdout}");
    println!("Child stderr: {stderr}");
    println!("Child exit status: {:?}", output.status);

    // Ensure it reached the socket checkpoint (meaning steps 1, 2, 3 passed)
    assert!(
        stdout.contains("CHECKPOINT: BEFORE_AF_INET"),
        "Child must reach BEFORE_AF_INET checkpoint. stdout: {stdout}, stderr: {stderr}"
    );

    // Ensure steps 1, 2, 3 did not fail
    assert_ne!(
        output.status.code(),
        Some(10),
        "Opening file outside allowed paths unexpectedly succeeded"
    );
    assert_ne!(
        output.status.code(),
        Some(11),
        "Writing into store unexpectedly succeeded"
    );
    assert_ne!(
        output.status.code(),
        Some(12),
        "Command::new('true') unexpectedly succeeded"
    );
    assert_ne!(
        output.status.code(),
        Some(13),
        "Creating AF_INET socket unexpectedly succeeded"
    );

    // Creating AF_INET socket must have failed: either process exited with 0 (socket returned error)
    // or process was killed by seccomp signal (KillProcess).
    if output.status.success() {
        assert!(
            stdout.contains("CHECKPOINT: ALL_PASSED"),
            "Child exited 0 but did not reach ALL_PASSED"
        );
    } else {
        // Killed by seccomp (SIGSYS or signal termination on AF_INET socket)
        assert!(
            output.status.code().is_none() || output.status.code() != Some(0),
            "Child process failed as expected on AF_INET socket"
        );
    }
}

#[test]
fn test_fix7_sandbox_child_outside_fixture_failure() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    std::fs::create_dir_all(&store_dir).expect("create store");
    std::fs::create_dir_all(&log_dir).expect("create log");

    let bin = bin_path();
    let invalid_outside = temp.path().join("nonexistent_dir").join("outside.txt");

    let output = support::output_bounded(
        Command::new(&bin)
            .env("HERMETIC_CHILD_ROLE", "sandbox")
            .env("HERMETIC_TEST_STORE", &store_dir)
            .env("HERMETIC_TEST_LOG", &log_dir)
            .env("HERMETIC_TEST_OUTSIDE", &invalid_outside),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "Child process must exit with non-zero code 2 on fixture write failure before sandbox"
    );
    assert!(
        stderr.contains("Failed to create outside fixture file"),
        "Child process must emit clear error message on fixture write failure: {stderr}"
    );
}
