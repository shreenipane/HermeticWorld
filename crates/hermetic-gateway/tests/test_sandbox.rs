#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;

const CHILD_LOG: &str = "HERMETIC_GW_CHILD_LOG";
const CHILD_KEY: &str = "HERMETIC_GW_CHILD_KEY";
const CHILD_SOCKET_DIR: &str = "HERMETIC_GW_CHILD_SOCKET_DIR";
const CHILD_WORLD: &str = "HERMETIC_GW_CHILD_WORLD";
const CHILD_AGENT_DISK: &str = "HERMETIC_GW_CHILD_AGENT_DISK";
const CHILD_HOST_SECRET: &str = "HERMETIC_GW_CHILD_HOST_SECRET";
const CHILD_OUTSIDE: &str = "HERMETIC_GW_CHILD_OUTSIDE";
const CHILD_OP: &str = "HERMETIC_GW_SECCOMP_OP";

fn create_private_dir(path: &Path) {
    fs::create_dir_all(path).expect("create dir");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
}

fn create_fixture_file(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .expect("create fixture exclusively");
    file.write_all(contents).expect("write fixture contents");
}

#[test]
fn sandbox_child() {
    let Some(log_path) = std::env::var_os(CHILD_LOG).map(PathBuf::from) else {
        return;
    };
    let key_path = PathBuf::from(std::env::var_os(CHILD_KEY).expect("child key"));
    let socket_dir = PathBuf::from(std::env::var_os(CHILD_SOCKET_DIR).expect("child socket dir"));
    let world_dir = PathBuf::from(std::env::var_os(CHILD_WORLD).expect("child world"));
    let agent_disk = PathBuf::from(std::env::var_os(CHILD_AGENT_DISK).expect("child agent disk"));
    let host_secret =
        PathBuf::from(std::env::var_os(CHILD_HOST_SECRET).expect("child host secret"));
    let outside = PathBuf::from(std::env::var_os(CHILD_OUTSIDE).expect("child outside"));

    let status =
        match hermetic_gateway::apply_sandbox(&log_path, &key_path, Some(&socket_dir), false) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to apply gateway sandbox: {e}");
                std::process::exit(1);
            }
        };

    if status == hermetic_gateway::SandboxLandlockStatus::NotEnforced {
        println!("Note: Landlock not enforced");
    } else {
        // 1. Reading key_file succeeds
        let key_data = fs::read(&key_path).expect("reading key_file must succeed");
        assert_eq!(key_data, b"test-upstream-key-material\n");

        // 2. Writing to log_dir succeeds
        let log_file = log_path.join("history.log");
        fs::write(&log_file, b"sample log record\n").expect("writing to log_dir must succeed");

        // 3. Reading from log_dir succeeds
        let read_log = fs::read(&log_file).expect("reading from log_dir must succeed");
        assert_eq!(read_log, b"sample log record\n");

        // 4. Reading world directory fails with PermissionDenied
        let world_file = world_dir.join("sealed_repo.txt");
        match fs::File::open(&world_file) {
            Ok(_) => {
                eprintln!("Opening world file unexpectedly succeeded");
                std::process::exit(10);
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    eprintln!("Expected PermissionDenied opening world file, got: {e}");
                    std::process::exit(10);
                }
            }
        }

        // 5. Reading agent disk fails with PermissionDenied
        let disk_file = agent_disk.join("agent_disk.img");
        match fs::File::open(&disk_file) {
            Ok(_) => {
                eprintln!("Opening agent disk unexpectedly succeeded");
                std::process::exit(11);
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    eprintln!("Expected PermissionDenied opening agent disk, got: {e}");
                    std::process::exit(11);
                }
            }
        }

        // 6. Reading host secret outside key file fails with PermissionDenied
        match fs::File::open(&host_secret) {
            Ok(_) => {
                eprintln!("Opening host secret unexpectedly succeeded");
                std::process::exit(12);
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    eprintln!("Expected PermissionDenied opening host secret, got: {e}");
                    std::process::exit(12);
                }
            }
        }

        // 7. Reading outside file fails with PermissionDenied
        match fs::File::open(&outside) {
            Ok(_) => {
                eprintln!("Opening outside file unexpectedly succeeded");
                std::process::exit(13);
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    eprintln!("Expected PermissionDenied opening outside file, got: {e}");
                    std::process::exit(13);
                }
            }
        }

        // 8. Writing into world directory fails
        if fs::write(world_dir.join("probe.txt"), b"tamper").is_ok() {
            eprintln!("Writing into world directory unexpectedly succeeded");
            std::process::exit(14);
        }

        // 9. Writing into agent disk directory fails
        if fs::write(agent_disk.join("probe.txt"), b"tamper").is_ok() {
            eprintln!("Writing into agent disk directory unexpectedly succeeded");
            std::process::exit(15);
        }

        // 10. Writing into key file fails (read-only beneath rule)
        if fs::write(&key_path, b"overwrite").is_ok() {
            eprintln!("Overwriting key file unexpectedly succeeded");
            std::process::exit(16);
        }

        // 11. Writing into outside directory fails
        if fs::write(outside.with_file_name("probe.txt"), b"tamper").is_ok() {
            eprintln!("Writing outside unexpectedly succeeded");
            std::process::exit(17);
        }
    }

    // 12. Command::new("true").status() fails (seccomp execve block)
    if let Ok(s) = Command::new("true").status() {
        if s.success() {
            eprintln!("Command::new('true') unexpectedly succeeded");
            std::process::exit(18);
        }
    }

    println!("CHECKPOINT: GATEWAY_ISOLATION_PASSED");
    std::process::exit(0);
}

#[test]
fn test_gateway_sandbox_child_cannot_read_outside_allowed_paths() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("logs");
    let key_dir = temp.path().join("keys");
    let socket_dir = temp.path().join("socket_dir");
    let world_dir = temp.path().join("world_store");
    let agent_disk_dir = temp.path().join("agent_disks");
    let host_secret_dir = temp.path().join("host_secrets");

    create_private_dir(&log_dir);
    create_private_dir(&key_dir);
    create_private_dir(&socket_dir);
    create_private_dir(&world_dir);
    create_private_dir(&agent_disk_dir);
    create_private_dir(&host_secret_dir);

    let key_file = key_dir.join("upstream_key.txt");
    create_fixture_file(&key_file, b"test-upstream-key-material\n");

    let world_file = world_dir.join("sealed_repo.txt");
    create_fixture_file(&world_file, b"sealed world contents\n");

    let agent_disk = agent_disk_dir.join("agent_disk.img");
    create_fixture_file(&agent_disk, b"agent disk contents\n");

    let host_secret = host_secret_dir.join("root_ca_key.pem");
    create_fixture_file(&host_secret, b"host ca private key\n");

    let outside = temp.path().join("outside.txt");
    create_fixture_file(&outside, b"general host content\n");

    let output = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "sandbox_child", "--nocapture"])
        .env(CHILD_LOG, &log_dir)
        .env(CHILD_KEY, &key_file)
        .env(CHILD_SOCKET_DIR, &socket_dir)
        .env(CHILD_WORLD, &world_dir)
        .env(CHILD_AGENT_DISK, &agent_disk_dir)
        .env(CHILD_HOST_SECRET, &host_secret)
        .env(CHILD_OUTSIDE, &outside)
        .output()
        .expect("run sandbox child");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Child stdout: {stdout}");
    println!("Child stderr: {stderr}");

    assert!(
        stdout.contains("CHECKPOINT: GATEWAY_ISOLATION_PASSED"),
        "Child must reach GATEWAY_ISOLATION_PASSED. code: {:?}, stdout: {stdout}, stderr: {stderr}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(0));

    // Confirm outside fixtures remained intact and unmodified
    assert_eq!(
        fs::read(&world_file).expect("world file intact"),
        b"sealed world contents\n"
    );
    assert_eq!(
        fs::read(&agent_disk).expect("agent disk intact"),
        b"agent disk contents\n"
    );
    assert_eq!(
        fs::read(&host_secret).expect("host secret intact"),
        b"host ca private key\n"
    );
    assert_eq!(
        fs::read(&outside).expect("outside intact"),
        b"general host content\n"
    );
    assert!(!world_dir.join("probe.txt").exists());
    assert!(!agent_disk_dir.join("probe.txt").exists());
}

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn seccomp_child() {
    let Ok(op) = std::env::var(CHILD_OP) else {
        return;
    };

    hermetic_gateway::apply_seccomp().expect("apply seccomp");

    match op.as_str() {
        "kill_other" => {
            let target_pid = std::env::var("TARGET_PID")
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(999999);
            let pid = rustix::process::Pid::from_raw(target_pid).unwrap();
            let _ = rustix::process::test_kill_process(pid);
        }
        "execve" => {
            use std::os::unix::process::CommandExt;
            let err = Command::new("true").exec();
            eprintln!("Command exec err: {err:?}");
            std::process::exit(99);
        }
        "setuid" => {
            let _ = rustix::thread::set_thread_uid(rustix::process::getuid());
        }
        "setgroups" => {
            let _ = rustix::thread::set_thread_groups(&[]);
        }
        "clock_settime" => {
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
            let _ = rustix::time::clock_settime(rustix::time::ClockId::Realtime, now);
        }
        "socket_netlink" => {
            let _ = rustix::net::socket(
                rustix::net::AddressFamily::NETLINK,
                rustix::net::SocketType::RAW,
                None,
            );
        }
        "kill_self" => {
            let me = rustix::process::getpid();
            let res = rustix::process::test_kill_process(me);
            assert!(res.is_ok(), "kill self signal must succeed");
            std::process::exit(0);
        }
        _ => {
            eprintln!("Unknown seccomp op: {op}");
            std::process::exit(1);
        }
    }

    std::process::exit(0);
}

#[test]
fn test_seccomp_denies_execve_foreign_signals_credentials_and_clock() {
    for op in [
        "kill_other",
        "execve",
        "setuid",
        "setgroups",
        "clock_settime",
        "socket_netlink",
    ] {
        let mut cmd = Command::new(std::env::current_exe().expect("current exe"));
        cmd.args(["--exact", "seccomp_child", "--nocapture"])
            .env(CHILD_OP, op);

        let _target_guard = if op == "kill_other" {
            let target = Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn foreign signal target");
            cmd.env("TARGET_PID", target.id().to_string());
            Some(ChildGuard(Some(target)))
        } else {
            None
        };

        let output = cmd.output().expect("spawn seccomp child");

        println!(
            "op: {op}, status: {:?}, stdout: {}, stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert_eq!(
            output.status.signal(),
            Some(libc::SIGSYS),
            "Operation {op} must be denied by seccomp (killed by SIGSYS), got: {:?}",
            output.status
        );
    }

    // Signal to self process must succeed
    let output = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "seccomp_child", "--nocapture"])
        .env(CHILD_OP, "kill_self")
        .output()
        .expect("spawn seccomp child for kill_self");

    assert!(
        output.status.success(),
        "kill_self must succeed, got status: {:?}",
        output.status
    );
}

#[test]
fn test_gateway_isolated_server_e2e_over_unix_socket() {
    let temp = tempdir().expect("tempdir");

    // 1. Mock upstream on loopback TCP port
    let mock_upstream = tiny_http::Server::http("127.0.0.1:0").expect("bind fake upstream");
    let upstream_addr = mock_upstream.server_addr().to_string();
    let upstream_thread = std::thread::spawn(move || {
        let req = mock_upstream.recv().expect("mock receives request");
        assert_eq!(req.url(), "/v1/messages");
        let body = r#"{"id":"msg_iso_1","type":"message","role":"assistant","content":[{"type":"text","text":"isolated reply"}],"model":"model-isolated","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let resp = tiny_http::Response::from_string(body)
            .with_status_code(200)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            );
        req.respond(resp).expect("respond from mock");
    });

    // 2. Gateway paths and config
    let log_dir = temp.path().join("gw_logs");
    create_private_dir(&log_dir);
    let key_file = temp.path().join("upstream_key.txt");
    create_fixture_file(&key_file, b"test-upstream-key-material\n");

    let sock_dir = temp.path().join("sock");
    create_private_dir(&sock_dir);
    let gw_socket = sock_dir.join("gateway.sock");
    let config_path = temp.path().join("gateway_config.json");
    let config_json = serde_json::json!({
        "upstream_protocol": "anthropic",
        "upstream_base_url": format!("http://{upstream_addr}"),
        "anthropic_version": "2023-06-01",
        "pinned_models": ["model-isolated"],
        "api_key_file": key_file,
        "log_dir": log_dir,
        "quotas": {}
    });
    fs::write(&config_path, config_json.to_string()).expect("write config");

    // 3. Spawn hermetic-gateway binary with sandbox enabled (default)
    let bin_path = env!("CARGO_BIN_EXE_hermetic-gateway");
    let stderr_file = temp.path().join("gw.stderr");
    let err_fd = fs::File::create(&stderr_file).unwrap();
    let child = Command::new(bin_path)
        .arg("--config")
        .arg(&config_path)
        .arg("--socket")
        .arg(&gw_socket)
        .args(["--t-clock", "2026-11-18T12:00:00Z"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err_fd)
        .spawn()
        .expect("spawn hermetic-gateway");
    let mut guard = ChildGuard(Some(child));

    // Wait for Unix domain socket with deadline
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gw_socket.exists() {
        if Instant::now() >= deadline {
            panic!("timed out waiting for gateway socket to bind");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // 4. NetVM connects to gateway over Unix domain socket
    let mut stream = UnixStream::connect(&gw_socket).expect("connect to gateway socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");

    let req_body = serde_json::json!({
        "model": "model-isolated",
        "max_tokens": 50,
        "messages": [{"role": "user", "content": "hello"}]
    })
    .to_string();

    let http_request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAnthropic-Version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        req_body.len(),
        req_body
    );

    stream
        .write_all(http_request.as_bytes())
        .expect("write to gateway UDS");
    stream.flush().expect("flush to gateway UDS");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .expect("read response from gateway UDS");
    let response_str = String::from_utf8_lossy(&response_bytes);

    let stderr_text = fs::read_to_string(&stderr_file).unwrap_or_default();
    assert!(
        response_str.starts_with("HTTP/1.1 200 OK\r\n"),
        "Expected 200 OK, got: {response_str}; stderr: {stderr_text}"
    );
    assert!(
        response_str.contains("isolated reply"),
        "Expected isolated reply in response: {response_str}"
    );
    assert!(
        response_str.contains("date: Wed, 18 Nov 2026 12:00:00 GMT")
            || response_str.contains("Date: Wed, 18 Nov 2026 12:00:00 GMT"),
        "Expected guest Date header in response: {response_str}"
    );

    upstream_thread.join().expect("join mock upstream thread");

    // Verify history log was created inside log_dir and updated with request-derived values
    let history_file = log_dir.join("gateway_history.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut history_written = false;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(&history_file) {
            if content.contains("gateway_log_head") {
                history_written = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        history_written,
        "Gateway history artifact must be written and contain gateway_log_head"
    );

    if let Some(mut child) = guard.0.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn test_gateway_isolation_kvm_smoke_skips_cleanly_without_env_vars() {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/integration/gateway-isolation-smoke.sh");
    assert!(
        script_path.exists(),
        "smoke script must exist at {}",
        script_path.display()
    );

    let temp = tempdir().expect("tempdir");
    let output = Command::new("bash")
        .arg(&script_path)
        .arg(temp.path())
        .env_remove("HERMETIC_FC_BIN")
        .env_remove("HERMETIC_FIRECRACKER_LOCK")
        .output()
        .expect("run gateway-isolation-smoke.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Smoke script must exit cleanly (status 0) on missing KVM inputs, got: {:?}, stdout: {stdout}, stderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("skipped"),
        "Expected skip message in smoke output, got: {stdout}"
    );
}

#[test]
fn test_persist_history_succeeds_under_landlock_without_ancestor_access() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("logs");
    create_private_dir(&log_dir);
    let key_file = temp.path().join("upstream_key.txt");
    create_fixture_file(&key_file, b"test-upstream-key\n");

    let config = hermetic_gateway::config::GatewayConfig::from_raw(
        "http://127.0.0.1:1234".to_string(),
        "2023-06-01".to_string(),
        vec![],
        vec!["model-isolated".to_string()],
        Default::default(),
        log_dir.clone(),
        key_file.clone(),
        "test-upstream-key\n".to_string(),
    );
    let clock = hermetic_gateway::GuestClock::frozen(
        time::OffsetDateTime::UNIX_EPOCH,
        Duration::from_secs(0),
    );
    let server =
        hermetic_gateway::GatewayServer::new_with_clock(config, clock).expect("create server");

    let status = hermetic_gateway::apply_landlock(&log_dir, &key_file, None, false);
    if matches!(
        status,
        Ok(hermetic_gateway::SandboxLandlockStatus::Enforced)
    ) {
        let ok = server.persist_history();
        assert!(
            ok,
            "persist_history must succeed through held dir handle under Landlock"
        );
        assert!(
            !server.history_persist_failed(),
            "history persist failure must not be latched"
        );
    }
}

#[test]
fn test_socket_dir_grant_does_not_permit_file_reads() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("logs");
    create_private_dir(&log_dir);
    let key_file = temp.path().join("upstream_key.txt");
    create_fixture_file(&key_file, b"test-key\n");
    let sock_dir = temp.path().join("sock");
    create_private_dir(&sock_dir);
    let target_file = sock_dir.join("secret_in_sock_dir.txt");
    create_fixture_file(&target_file, b"forbidden\n");

    let status = hermetic_gateway::apply_landlock(&log_dir, &key_file, Some(&sock_dir), false);
    if matches!(
        status,
        Ok(hermetic_gateway::SandboxLandlockStatus::Enforced)
    ) {
        let res = fs::read(&target_file);
        assert!(
            res.is_err(),
            "Reading regular files in socket_dir must be denied by Landlock"
        );
    }
}
