#![forbid(unsafe_code)]

mod support;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use support::private_tempdir as tempdir;

const CHILD_STORE: &str = "HERMETIC_SANDBOX_CHILD_STORE";
const CHILD_LOG: &str = "HERMETIC_SANDBOX_CHILD_LOG";
const CHILD_OUTSIDE: &str = "HERMETIC_SANDBOX_CHILD_OUTSIDE";

/// Create a fixture file exclusively: never through a planted entry.
fn create_fixture(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .expect("create fixture exclusively");
    file.write_all(contents).expect("write fixture");
}

/// Sandbox checks, run in a child copy of this test binary. All fixtures are
/// created by the parent test in its private temporary directory.
#[test]
fn sandbox_child() {
    let Some(store_path) = std::env::var_os(CHILD_STORE).map(PathBuf::from) else {
        return;
    };
    let log_path = PathBuf::from(std::env::var_os(CHILD_LOG).expect("child log"));
    let outside = PathBuf::from(std::env::var_os(CHILD_OUTSIDE).expect("child outside"));

    let status = match hermetic_world_server::apply_sandbox(&store_path, &log_path, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to apply sandbox: {e}");
            std::process::exit(1);
        }
    };

    if status == hermetic_world_server::SandboxLandlockStatus::NotEnforced {
        println!("Note: Landlock not supported by running kernel, checking only seccomp");
    } else {
        // 1. Opening a file outside allowed paths fails with PermissionDenied
        match fs::File::open(&outside) {
            Ok(_) => {
                eprintln!("Opening file outside allowed paths unexpectedly succeeded");
                std::process::exit(10);
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    eprintln!("Expected PermissionDenied opening outside file, got: {e}");
                    std::process::exit(10);
                }
            }
        }

        // 2. Writing into the store fails
        if fs::write(store_path.join("probe.txt"), b"bad").is_ok() {
            eprintln!("Writing into store unexpectedly succeeded");
            std::process::exit(11);
        }
    }

    // 3. Command::new("true").status() fails
    if let Ok(s) = Command::new("true").status() {
        if s.success() {
            eprintln!("Command::new('true') unexpectedly succeeded");
            std::process::exit(12);
        }
    }

    // 4. Creating an AF_INET socket fails
    println!("CHECKPOINT: BEFORE_AF_INET");
    if std::net::TcpListener::bind("127.0.0.1:0").is_ok() {
        eprintln!("Creating AF_INET socket unexpectedly succeeded");
        std::process::exit(13);
    }

    println!("CHECKPOINT: ALL_PASSED");
    std::process::exit(0);
}

#[test]
fn test_sandbox_child_process() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    support::create_private_dir(&store_dir).expect("create store");
    support::create_private_dir(&log_dir).expect("create log");
    create_fixture(&store_dir.join("test.txt"), b"read only content");
    let outside = temp.path().join("outside.txt");
    create_fixture(&outside, b"secret");

    let output = support::output_bounded(
        Command::new(std::env::current_exe().expect("current exe"))
            .args(["--exact", "sandbox_child", "--nocapture"])
            .env(CHILD_STORE, &store_dir)
            .env(CHILD_LOG, &log_dir)
            .env(CHILD_OUTSIDE, &outside),
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
    }
    assert_eq!(fs::read(&outside).expect("outside fixture"), b"secret");
    assert!(!store_dir.join("probe.txt").exists());
}

/// The production binary must not create test fixtures: a symlink or a
/// regular sentinel planted at the former fixed fixture location in its
/// temporary directory is left untouched, whatever the environment says.
#[test]
fn rereview_4_binary_never_writes_fixture_through_planted_entries() {
    for planted_symlink in [true, false] {
        let temp = tempdir().expect("tempdir");
        let tmpdir = temp.path().join("tmp");
        support::create_private_dir(&tmpdir).expect("create tmp");
        let sentinel = temp.path().join("sentinel");
        create_fixture(&sentinel, b"sentinel");
        let old_fixture = tmpdir.join("hw_test_outside.txt");
        if planted_symlink {
            symlink(&sentinel, &old_fixture).expect("plant symlink");
        } else {
            create_fixture(&old_fixture, b"regular sentinel");
        }

        let output = support::output_bounded(
            Command::new(env!("CARGO_BIN_EXE_hermetic-world-server"))
                .env("HERMETIC_CHILD_ROLE", "sandbox")
                .env("TMPDIR", &tmpdir)
                .env_remove("HERMETIC_TEST_STORE")
                .env_remove("HERMETIC_TEST_LOG")
                .env_remove("HERMETIC_TEST_OUTSIDE"),
        );
        assert!(
            !output.status.success(),
            "binary without server arguments must not succeed"
        );

        assert_eq!(fs::read(&sentinel).expect("sentinel"), b"sentinel");
        let meta = fs::symlink_metadata(&old_fixture).expect("planted entry");
        if planted_symlink {
            assert!(meta.file_type().is_symlink());
            assert_eq!(fs::read_link(&old_fixture).expect("link"), sentinel);
        } else {
            assert!(meta.file_type().is_file());
            assert_eq!(
                fs::read(&old_fixture).expect("regular sentinel"),
                b"regular sentinel"
            );
        }
        let mut names: Vec<_> = fs::read_dir(&tmpdir)
            .expect("read tmp")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort();
        assert_eq!(names, [std::ffi::OsString::from("hw_test_outside.txt")]);
    }
}
