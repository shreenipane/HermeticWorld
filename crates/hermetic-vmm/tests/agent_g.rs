#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "dev-unjailed"), allow(dead_code, unused_imports))]

#[cfg(feature = "dev-unjailed")]
#[path = "support/agent_h.rs"]
#[allow(dead_code)]
mod diagnostics;
mod support;

use hermetic_vmm::spec::{project_mac, validate_run, Drive, Network, Role};
use hermetic_vmm::{api, deadline, Error, Result, Vmm};
use serde::Deserialize;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const T_CLOCK: u64 = 1_700_000_000;
const MAX_RPC_BYTES: u32 = 16 * 1024;
const MAX_REPLY_BYTES: u32 = 64 * 1024;
const MAX_HANDSHAKE_BYTES: usize = 64;
const GATEWAY_PORT: u32 = 5002;
const MAX_UPSTREAM_REQUEST_BYTES: usize = 16 * 1024;

const ENV: [&str; 5] = [
    "HERMETIC_FC_BIN",
    "HERMETIC_KERNEL",
    "HERMETIC_ROOTFS",
    "HERMETIC_NETVM_ROOTFS",
    "HERMETIC_MODE_G_WORK",
];

#[derive(Debug, Deserialize)]
struct GuestExec {
    code: Option<i32>,
    output: Vec<u8>,
    timed_out: bool,
}

#[cfg(feature = "dev-unjailed")]
fn call(socket: &str, request: &[u8], end: Instant) -> Result<serde_json::Value> {
    let mut stream = api::connect(socket, end)?;
    api::write_deadline(&mut stream, b"CONNECT 5000\n", end)?;
    let mut line = Vec::new();
    for _ in 0..MAX_HANDSHAKE_BYTES {
        let mut byte = [0];
        api::read_exact_deadline(&mut stream, &mut byte, end)?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if !line.starts_with(b"OK ") || !line.ends_with(b"\n") {
        return Err(Error::Protocol);
    }
    api::write_deadline(&mut stream, &(request.len() as u32).to_le_bytes(), end)?;
    api::write_deadline(&mut stream, request, end)?;
    let mut length = [0; 4];
    api::read_exact_deadline(&mut stream, &mut length, end)?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_RPC_BYTES {
        return Err(Error::Protocol);
    }
    let mut raw = vec![0; length as usize];
    api::read_exact_deadline(&mut stream, &mut raw, end)?;
    serde_json::from_slice(&raw).map_err(|_| Error::Protocol)
}

#[cfg(feature = "dev-unjailed")]
fn finish(child: &mut std::process::Child, timeout: Duration) {
    let end = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "smoke child failed");
            return;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("smoke child deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_read_only_probe_failure(reply: &serde_json::Value) {
    let code = reply.get("code").and_then(|c| c.as_i64());
    assert!(
        code.is_some() && code != Some(0),
        "/opt/agent write probe must complete with a nonzero exit code, got: {code:?}"
    );
    let output = reply
        .get("output")
        .and_then(|o| o.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|b| b as u8))
                .collect::<Vec<u8>>()
        })
        .unwrap_or_default();
    let msg = String::from_utf8_lossy(&output);
    assert!(
        msg.contains("Read-only file system") || msg.contains("EROFS"),
        "/opt/agent write probe must fail with read-only file system error, got code={code:?}, output: {msg}"
    );
}

fn guest_call(path: &str, request: &[u8], end: Instant) -> Result<Vec<u8>> {
    let mut stream = api::connect(path, end)?;
    api::write_deadline(&mut stream, b"CONNECT 5000\n", end)?;
    let mut handshake = Vec::new();
    loop {
        let mut byte = [0];
        match api::read_exact_deadline(&mut stream, &mut byte, end) {
            Err(Error::Protocol) if handshake.is_empty() => return Err(Error::Io),
            other => other?,
        }
        handshake.push(byte[0]);
        if handshake.len() > MAX_HANDSHAKE_BYTES {
            return Err(Error::Protocol);
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    if !handshake.starts_with(b"OK ") {
        return Err(Error::Protocol);
    }
    api::write_deadline(&mut stream, &(request.len() as u32).to_le_bytes(), end)?;
    api::write_deadline(&mut stream, request, end)?;
    let mut length = [0; 4];
    api::read_exact_deadline(&mut stream, &mut length, end)?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_REPLY_BYTES {
        return Err(Error::Protocol);
    }
    let mut body = vec![0; length as usize];
    api::read_exact_deadline(&mut stream, &mut body, end)?;
    Ok(body)
}

fn exec_until(socket: &str, argv: &[&str], end: Instant, timeout_ms: u64) -> Result<GuestExec> {
    let request = serde_json::to_vec(&serde_json::json!({
        "type": "exec", "argv": argv, "tty": false, "timeout_ms": timeout_ms
    }))
    .map_err(|_| Error::Protocol)?;
    loop {
        match guest_call(socket, &request, end) {
            Ok(body) => return serde_json::from_slice(&body).map_err(|_| Error::Protocol),
            Err(Error::Io) if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e),
        }
    }
}

fn exec(socket: &str, argv: &[&str]) -> GuestExec {
    let end = deadline(Duration::from_secs(30)).unwrap();
    exec_until(socket, argv, end, 10000).expect("execd call failed")
}

fn sh(socket: &str, script: &str) -> (Option<i32>, String) {
    let r = exec(socket, &["/bin/busybox", "sh", "-c", script]);
    assert!(!r.timed_out, "guest command timed out: {script}");
    let out = String::from_utf8_lossy(&r.output).into_owned();
    (r.code, out)
}

fn empty_overlay(path: &str) {
    let overlay = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    overlay.set_len(64 * 1024 * 1024).unwrap();
    let status = Command::new("/usr/sbin/mke2fs")
        .args(["-q", "-t", "ext4", "-F"])
        .arg(path)
        .env_clear()
        .env("E2FSPROGS_FAKE_TIME", T_CLOCK.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("mke2fs required");
    assert!(status.success());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn python_launcher(f: &support::Fixture) -> String {
    let source = std::fs::canonicalize("/usr/bin/python3").expect("Python 3 interpreter required");
    let path = f.temp.path().join("exec-python");
    std::fs::copy(source, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    path.to_str().unwrap().into()
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct FakeUpstream {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeUpstream {
    fn start() -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|_| Error::Io)?;
        let port = listener.local_addr().map_err(|_| Error::Io)?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        listener.set_nonblocking(true).map_err(|_| Error::Io)?;

        let handle = std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let mut buf = vec![0u8; MAX_UPSTREAM_REQUEST_BYTES];
                        let mut total = 0;
                        let read_deadline = Instant::now() + Duration::from_secs(5);
                        while total < buf.len() && Instant::now() < read_deadline {
                            match stream.read(&mut buf[total..]) {
                                Ok(0) => break,
                                Ok(n) => {
                                    total += n;
                                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        let body = r#"{"id":"msg_01","type":"message","role":"assistant","content":[{"type":"text","text":"deterministic mode-g answer"}],"model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDate: Tue, 15 Nov 2026 12:34:56 GMT\r\nx-request-id: req_fake_123\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            port,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn boots_agent_g_mounts_volume_read_only_and_collects_extraction() {
    #[cfg(feature = "dev-unjailed")]
    run_agent_volume_smoke();
    #[cfg(not(feature = "dev-unjailed"))]
    {
        eprintln!("skipped: Mode G KVM test requires --features dev-unjailed");
    }
}

#[cfg(feature = "dev-unjailed")]
fn run_agent_volume_smoke() {
    let required = |key| std::env::var(key).ok();
    let (Some(fc_bin), Some(kernel), Some(rootfs), Some(agent_volume)) = (
        required("HERMETIC_FC_BIN"),
        required("HERMETIC_KERNEL"),
        required("HERMETIC_ROOTFS"),
        required("HERMETIC_AGENT_VOLUME"),
    ) else {
        eprintln!("skipped: Mode G KVM test requires HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_ROOTFS, and HERMETIC_AGENT_VOLUME");
        return;
    };
    let clock: i64 = required("HERMETIC_AGENT_T_CLOCK")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_700_000_000);

    let mut fixture = support::Fixture::new();
    fixture.spec.jail.firecracker = fc_bin;
    fixture.spec.kernel_image = kernel;
    fixture.spec.root_drive.path = rootfs;
    fixture.spec.networks.clear();
    fixture.spec.boot_args = fixture
        .spec
        .boot_args
        .replace("hermetic.t=1700000000", &format!("hermetic.t={clock}"))
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-init")
        + " hermetic.agent_volume=/dev/vdc";

    // Overlay drive (vdb, writable)
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fixture.spec.drives[0].path)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    let mut mkfs = diagnostics::overlay_command(clock)
        .arg(&fixture.spec.drives[0].path)
        .spawn()
        .unwrap();
    finish(&mut mkfs, Duration::from_secs(30));

    // Agent volume drive (vdc, read_only: true)
    fixture.spec.drives.push(Drive {
        id: "agent".into(),
        path: agent_volume,
        read_only: true,
    });

    let launcher = fixture.temp.path().join("exec-python");
    std::fs::copy(
        std::fs::canonicalize("/usr/bin/python3").unwrap(),
        &launcher,
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o500)).unwrap();
    let runner = hermetic_vmm::runner::DevUnjailed::new(launcher.to_str().unwrap()).unwrap();
    let mut vm = Vmm::new(fixture.spec.clone().validate().unwrap(), runner);
    diagnostics::run(&mut vm, |vm| -> hermetic_vmm::Result<()> {
        vm.prepare(Duration::from_secs(120)).unwrap();
        vm.start(Duration::from_secs(10)).unwrap();
        vm.wait_ready(Duration::from_secs(30)).unwrap();
        let socket = vm.jail().unwrap().root.descriptor_path("vsock");
        let end = deadline(Duration::from_secs(30)).unwrap();
        loop {
            if let Ok(reply) = call(&socket, br#"{"type":"status"}"#, end) {
                diagnostics::status(&reply, clock)?;
                break;
            }
            assert!(Instant::now() < end, "execd readiness deadline");
            std::thread::sleep(Duration::from_millis(20));
        }

        // Test 1: Verify /opt/agent is read-only inside guest.
        // Executing touch /opt/agent/should_fail_ro must fail with EROFS (non-zero exit code).
        let end = deadline(Duration::from_secs(15)).unwrap();
        let ro_probe = call(
            &socket,
            br#"{"type":"exec","argv":["/bin/bash","-c","touch /opt/agent/should_fail_ro 2>&1"],"tty":false,"timeout_ms":5000}"#,
            end,
        )
        .unwrap();
        assert_read_only_probe_failure(&ro_probe);

        // Test 2: Verify /opt/agent is readable
        let end = deadline(Duration::from_secs(15)).unwrap();
        let list_probe = call(
            &socket,
            br#"{"type":"exec","argv":["/bin/bash","-c","test -r /opt/agent"],"tty":false,"timeout_ms":5000}"#,
            end,
        )
        .unwrap();
        assert_eq!(
            list_probe.get("code").and_then(|c| c.as_i64()),
            Some(0),
            "/opt/agent must be readable"
        );

        // Test 3: If an agent program exists at /opt/agent/run, execute it
        // and verify writes succeed on overlay (/testbed)
        let end = deadline(Duration::from_secs(30)).unwrap();
        let agent_run = call(
            &socket,
            br#"{"type":"exec","argv":["/bin/bash","-c","if [ -f /opt/agent/run ]; then /bin/bash /opt/agent/run; else sed -i 's/return a - b/return a + b/' /testbed/calc.py; fi"],"tty":false,"timeout_ms":10000}"#,
            end,
        )
        .unwrap();
        assert_eq!(
            agent_run.get("code").and_then(|c| c.as_i64()),
            Some(0),
            "agent execution failed"
        );

        // Test 4: Verify the edit was written to the overlay filesystem
        let end = deadline(Duration::from_secs(15)).unwrap();
        let verify_edit = call(
            &socket,
            br#"{"type":"exec","argv":["/bin/cat","/testbed/calc.py"],"tty":false,"timeout_ms":5000}"#,
            end,
        )
        .unwrap();
        let output = verify_edit
            .get("output")
            .and_then(|o| o.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|b| b as u8))
                    .collect::<Vec<u8>>()
            })
            .unwrap_or_default();
        assert!(
            String::from_utf8_lossy(&output).contains("return a + b"),
            "calc.py was not updated on overlay"
        );

        let end = deadline(Duration::from_secs(10)).unwrap();
        // Graceful shutdown freezes upper ext4
        let frozen = call(&socket, br#"{"type":"shutdown"}"#, end).unwrap();
        assert_eq!(frozen["type"], "frozen");
        vm.stop(Duration::from_secs(10)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
        Ok(())
    })
    .unwrap();

    std::io::stdout()
        .write_all(b"agent-g VM test: ok (read-only /opt/agent volume, overlay writes)\n")
        .unwrap();
}

#[test]
fn test_ro_probe_assertion_fails_unless_nonzero_code_and_ro_error() {
    // 1. Missing code (absent) must fail
    let missing_code = serde_json::json!({
        "type": "exec",
        "output": b"touch: cannot touch '/opt/agent/should_fail_ro': Read-only file system\n".to_vec()
    });
    let result = std::panic::catch_unwind(|| {
        assert_read_only_probe_failure(&missing_code);
    });
    assert!(result.is_err(), "missing exit code must fail");

    // 2. Success exit code (0) must fail
    let success = serde_json::json!({
        "type": "exec",
        "code": 0,
        "output": []
    });
    let result = std::panic::catch_unwind(|| {
        assert_read_only_probe_failure(&success);
    });
    assert!(result.is_err(), "exit code 0 must fail");

    // 3. Nonzero exit code with unrelated error (e.g. command not found) must fail
    let unrelated = serde_json::json!({
        "type": "exec",
        "code": 127,
        "output": b"touch: command not found\n".to_vec()
    });
    let result = std::panic::catch_unwind(|| {
        assert_read_only_probe_failure(&unrelated);
    });
    assert!(result.is_err(), "unrelated error must fail");

    // 4. Nonzero exit code with "Read-only file system" must pass
    let valid_ro_msg = serde_json::json!({
        "type": "exec",
        "code": 1,
        "output": b"touch: cannot touch '/opt/agent/should_fail_ro': Read-only file system\n".to_vec()
    });
    assert_read_only_probe_failure(&valid_ro_msg);

    // 5. Nonzero exit code with "EROFS" must pass
    let valid_erofs = serde_json::json!({
        "type": "exec",
        "code": 1,
        "output": b"touch: /opt/agent/should_fail_ro: EROFS\n".to_vec()
    });
    assert_read_only_probe_failure(&valid_erofs);
}

#[test]
#[ignore = "needs dev-unjailed, /dev/kvm, host taps, NetVM, agent rootfs; see scripts/integration/agent-g-smoke.sh"]
fn netvm_forwards_agent_model_calls_to_gateway_and_signs_record() {
    #[cfg(feature = "dev-unjailed")]
    run();
    #[cfg(not(feature = "dev-unjailed"))]
    panic!("build with --features dev-unjailed");
}

#[cfg(feature = "dev-unjailed")]
fn run() {
    use hermetic_vmm::runner::DevUnjailed;
    let mut v = Vec::new();
    for name in ENV {
        match std::env::var(name) {
            Ok(value) => v.push(value),
            Err(_) => {
                eprintln!("skipped: missing smoke prerequisites: {}", ENV.join(", "));
                return;
            }
        }
    }

    let work = std::path::Path::new(&v[4]);
    let agent_tap = std::env::var("HERMETIC_AGENT_TAP").unwrap_or_else(|_| "hwtap-agent".into());
    let net_tap = std::env::var("HERMETIC_NET_TAP").unwrap_or_else(|_| "hwtap-net".into());
    let gateway_bin = std::env::var("HERMETIC_GATEWAY_BIN").unwrap_or_else(|_| {
        let top = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());
        format!("{top}/release/hermetic-gateway")
    });

    let fake_upstream = FakeUpstream::start().expect("start fake upstream");

    let gw_dir = work.join("gateway");
    let gw_log_dir = gw_dir.join("logs");
    let _ = std::fs::create_dir_all(&gw_log_dir);
    let api_key_path = gw_dir.join("api_key.txt");
    std::fs::write(&api_key_path, b"fake-mode-g-key\n").expect("write api key");
    let _ = std::fs::set_permissions(&api_key_path, std::fs::Permissions::from_mode(0o600));

    let gw_config_path = gw_dir.join("gateway_config.json");
    let gw_config = serde_json::json!({
        "upstream_protocol": "anthropic",
        "upstream_base_url": format!("http://127.0.0.1:{}", fake_upstream.port),
        "anthropic_version": "2023-06-01",
        "allowed_betas": [],
        "pinned_models": ["claude-3-5-sonnet-20241022"],
        "quotas": {
            "max_requests": 100,
            "max_input_tokens": 10000,
            "max_output_tokens": 10000,
            "max_concurrency": 2,
            "wall_time_seconds": 600
        },
        "log_dir": gw_log_dir.to_str().unwrap(),
        "api_key_file": api_key_path.to_str().unwrap(),
        "upstream_read_timeout_s": 10,
        "date_sentinel": {
            "host_names": [],
            "host_paths": [],
            "tolerance_days": 1
        }
    });
    std::fs::write(
        &gw_config_path,
        serde_json::to_vec_pretty(&gw_config).unwrap(),
    )
    .expect("write gateway config");

    let mut agent = support::Fixture::new();
    agent.spec.id = "agent-0".into();
    agent.spec.jail.firecracker = v[0].clone();
    agent.spec.kernel_image = v[1].clone();
    agent.spec.root_drive.path = v[2].clone();
    agent.spec.boot_args = agent
        .spec
        .boot_args
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-init");
    agent.spec.networks = vec![Network {
        tap: agent_tap,
        guest_mac: project_mac(Role::Agent, 0),
        peer: Role::Net,
    }];
    empty_overlay(&agent.spec.drives[0].path);

    let mut net = support::Fixture::new();
    net.spec.id = "net-0".into();
    net.spec.role = Role::Net;
    net.spec.index = 1;
    net.spec.memory_mib = 128;
    net.spec.drives.clear();
    net.spec.jail.firecracker = v[0].clone();
    net.spec.kernel_image = v[1].clone();
    net.spec.root_drive.path = v[3].clone();
    net.spec.boot_args = net
        .spec
        .boot_args
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-netvm");
    if let Some(vsock) = net.spec.vsock.as_mut() {
        vsock.guest_cid = 4;
    }
    net.spec.networks = vec![Network {
        tap: net_tap,
        guest_mac: project_mac(Role::Net, 0),
        peer: Role::Agent,
    }];

    let launcher = python_launcher(&agent);
    let mut specs = validate_run(vec![agent.spec.clone(), net.spec.clone()])
        .unwrap()
        .into_iter();
    let mut agent_vm = Vmm::new(specs.next().unwrap(), DevUnjailed::new(&launcher).unwrap());
    let mut net_vm = Vmm::new(specs.next().unwrap(), DevUnjailed::new(&launcher).unwrap());

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        net_vm.prepare(Duration::from_secs(120)).unwrap();
        let gw_socket = net.temp.path().join(format!(
            "firecracker/{}/root/vsock_{GATEWAY_PORT}",
            net.spec.id
        ));
        assert!(gw_socket.parent().unwrap().is_dir(), "jail root layout");

        let _gateway = ChildGuard(
            Command::new(&gateway_bin)
                .arg("--config")
                .arg(&gw_config_path)
                .arg("--socket")
                .arg(&gw_socket)
                .args(["--t-clock", "2023-11-14T22:13:20Z"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(work.join("gateway.stderr")).unwrap())
                .spawn()
                .expect("start gateway"),
        );

        let end = Instant::now() + Duration::from_secs(10);
        while !gw_socket.exists() {
            assert!(Instant::now() < end, "gateway did not bind its socket");
            std::thread::sleep(Duration::from_millis(20));
        }

        let ca_path = work.join("ca.boot");
        let ca_thread = if ca_path.exists() {
            let ca_socket = gw_socket.with_file_name("vsock_5003");
            let ca_listener = std::os::unix::net::UnixListener::bind(&ca_socket).unwrap();
            ca_listener.set_nonblocking(true).unwrap();
            let material = {
                use std::io::Read;
                let file = hermetic_netvm_core::files::regular(
                    &ca_path,
                    (hermetic_netvm_core::tls::MAX_BOOT_BYTES + 4) as u64,
                )
                .unwrap();
                let mut bytes = Vec::new();
                file.take((hermetic_netvm_core::tls::MAX_BOOT_BYTES + 5) as u64)
                    .read_to_end(&mut bytes)
                    .unwrap();
                bytes
            };
            Some(std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(30);
                loop {
                    match ca_listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(true).unwrap();
                            api::write_deadline(&mut stream, &material, end).unwrap();
                            stream.shutdown(std::net::Shutdown::Write).unwrap();
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < end, "NetVM did not request CA material");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => panic!("CA transfer failed"),
                    }
                }
            }))
        } else {
            None
        };

        net_vm.start(Duration::from_secs(10)).unwrap();
        net_vm.wait_ready(Duration::from_secs(30)).unwrap();
        if let Some(th) = ca_thread {
            th.join().unwrap();
        }

        agent_vm.prepare(Duration::from_secs(120)).unwrap();
        agent_vm.start(Duration::from_secs(10)).unwrap();
        agent_vm.wait_ready(Duration::from_secs(30)).unwrap();
        let socket = agent_vm.jail().unwrap().root.descriptor_path("vsock");

        let ready = Instant::now() + Duration::from_secs(20);
        loop {
            let (_, out) = sh(
                &socket,
                "/bin/busybox nslookup api.anthropic.com 10.0.2.3 2>&1",
            );
            if out.contains("10.9.0.2") {
                break;
            }
            assert!(
                Instant::now() < ready,
                "allowed gateway name never resolved: {out}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }

        // 1. Positive model call: POST /v1/messages
        let post_req = concat!(
            "printf 'POST /v1/messages HTTP/1.1\\r\\n",
            "Host: api.anthropic.com\\r\\n",
            "Content-Type: application/json\\r\\n",
            "Content-Length: 102\\r\\n",
            "Connection: close\\r\\n\\r\\n",
            "{\"model\":\"claude-3-5-sonnet-20241022\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}' | /bin/busybox nc -w 5 10.9.0.2 80"
        );
        let (_, out) = sh(&socket, post_req);
        assert!(
            out.starts_with("HTTP/1.1 200"),
            "expected 200 OK, got: {out}"
        );
        assert!(
            out.contains("deterministic mode-g answer"),
            "missing expected answer in: {out}"
        );
        assert!(
            !out.contains("x-request-id"),
            "x-request-id should be stripped: {out}"
        );
        assert!(
            !out.contains("2026"),
            "real-date header should be rewritten: {out}"
        );

        // 2. Negative test: GET /v1/messages returns 405 Method Not Allowed
        let get_req = concat!(
            "printf 'GET /v1/messages HTTP/1.1\\r\\n",
            "Host: api.anthropic.com\\r\\n",
            "Connection: close\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.2 80"
        );
        let (_, out) = sh(&socket, get_req);
        assert!(
            out.starts_with("HTTP/1.1 405"),
            "expected 405 Method Not Allowed, got: {out}"
        );

        // 3. Negative test: Non-adapter endpoint rejected
        let bad_endpoint = concat!(
            "printf 'POST /v1/unknown HTTP/1.1\\r\\n",
            "Host: api.anthropic.com\\r\\n",
            "Content-Length: 2\\r\\n",
            "Connection: close\\r\\n\\r\\n{}' | /bin/busybox nc -w 5 10.9.0.2 80"
        );
        let (_, out) = sh(&socket, bad_endpoint);
        assert!(
            !out.contains("HTTP/1.1 200"),
            "unallowed endpoint must not succeed: {out}"
        );

        // 4. Negative test: Destination address mismatch rejected
        let mismatch_dest = concat!(
            "printf 'POST /v1/messages HTTP/1.1\\r\\n",
            "Host: api.anthropic.com\\r\\n",
            "Content-Length: 2\\r\\n\\r\\n{}' | /bin/busybox nc -w 5 10.0.2.2 80"
        );
        let (_, out) = sh(&socket, mismatch_dest);
        assert!(
            !out.contains("HTTP/1.1 2"),
            "mismatched destination must be rejected: {out}"
        );

        agent_vm.stop(Duration::from_secs(2)).unwrap();
        agent_vm.destroy(Duration::from_secs(10)).unwrap();
        net_vm.stop(Duration::from_secs(2)).unwrap();
        net_vm.destroy(Duration::from_secs(10)).unwrap();
    }));

    if let Err(payload) = outcome {
        let _ = agent_vm.stop(Duration::from_secs(2));
        let _ = net_vm.stop(Duration::from_secs(2));
        std::panic::resume_unwind(payload);
    }

    let head_path = gw_log_dir.join("gateway_head.json");
    assert!(head_path.exists(), "gateway_head.json must be persisted");
    let head_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&head_path).unwrap()).unwrap();
    let head_str = head_json["head"].as_str().expect("head hex string");
    assert_eq!(head_str.len(), 64, "valid 32-byte sha256 hex string");
    assert_eq!(head_json["history_rewrite_count"], 0);
    assert_eq!(head_json["adapter_version"], "2026-11-1");
    assert!(head_json["records_count"].as_u64().unwrap_or(0) >= 1);

    verify_mode_g_run_record(work, &head_path);
}

#[cfg(feature = "dev-unjailed")]
fn verify_mode_g_run_record(work: &std::path::Path, head_path: &std::path::Path) {
    use hermetic_attest::{
        verify_run_attestation, AgentMode, Ed25519Signer, Ed25519Verifier, ReplayGuard, RunBinding,
    };
    use hermetic_run::orchestrator::{assemble_run_record, sign_run_record};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    let run_dir = work.join("run_record_test");
    let _ = std::fs::create_dir_all(&run_dir);

    std::fs::copy(head_path, run_dir.join("gateway_head.json")).unwrap();

    let date_sentinel = serde_json::json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 1234
    });
    std::fs::write(
        run_dir.join("date_sentinel.json"),
        date_sentinel.to_string(),
    )
    .unwrap();

    let harness = serde_json::json!({
        "date_leak_observed": false,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 1234
    });
    std::fs::write(run_dir.join("harness_summary.json"), harness.to_string()).unwrap();

    let probe_lines = [
        r#"{"probe":"clock_pairing_hc","result":"unavailable","detail":"hypercall blocked"}"#,
        r#"{"probe":"clocksource_sysfs","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"cpuid","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"cpuinfo","result":"blocked","detail":"filtered"}"#,
        r#"{"probe":"dmesg_dates","result":"blocked","detail":"clear"}"#,
        r#"{"probe":"hpet","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"kernel_canary","result":"blocked","detail":"canary blocked"}"#,
        r#"{"probe":"kvmclock_msr","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"module_load","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"posix_clocks","result":"blocked","detail":"locked"}"#,
        r#"{"probe":"proc_driver_rtc","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"rdtsc","result":"blocked","detail":"trapped"}"#,
        r#"{"probe":"ring0_paths","result":"blocked","detail":"inaccessible"}"#,
        r#"{"probe":"rtc_sysfs_dev","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"vmclock","result":"blocked","detail":"disabled"}"#,
    ]
    .join("\n");
    std::fs::write(run_dir.join("probe_output.jsonl"), probe_lines).unwrap();

    let boot = serde_json::json!({
        "vm_id": "agent-vm-0",
        "boot_path": "trusted_initramfs",
        "initrd_sha256": "f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    });
    std::fs::write(run_dir.join("boot_record.json"), boot.to_string()).unwrap();

    let verdict = serde_json::json!({
        "run_status": "resolved",
        "r0_result": "passed",
        "r1_result": "passed",
        "r2_result": "passed",
        "r3_result": "passed",
        "r1_coverage": 850,
        "unclean_shutdown": false,
        "submitted_work_digest": "sha256:e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    });
    std::fs::write(run_dir.join("verdict.json"), verdict.to_string()).unwrap();

    let manifest = serde_json::json!({
        "task_id": "test-task-mode-g",
        "task_class": "patch",
        "seal_level": "strict",
        "agent_mode": "G",
        "host": {
            "patched_firecracker": true,
            "hypercall_block": true
        },
        "substrate": "microvm",
        "grader_isolation": "clean",
        "world_version": "1.0",
        "harness_command_log_head": null
    });
    std::fs::write(run_dir.join("world_manifest.json"), manifest.to_string()).unwrap();

    let record = assemble_run_record(&run_dir).expect("Mode G run record assembly must succeed");
    assert_eq!(record.agent_mode, AgentMode::G);
    assert!(
        record.gateway_log_head.is_some(),
        "gateway_log_head populated"
    );
    assert_eq!(record.history_rewrite_count, Some(0));
    assert_eq!(record.gateway_adapter_version.as_deref(), Some("2026-11-1"));
    assert_eq!(record.harness_command_log_head, None);

    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let signer = Ed25519Signer::from_pkcs8(doc.as_ref()).unwrap();
    let verifier = Ed25519Verifier::new(&[&signer.public_key()]).unwrap();

    let envelope = sign_run_record(&record, &signer).unwrap();
    let mut guard = ReplayGuard::new();
    let binding = RunBinding {
        task_id: Some("test-task-mode-g".to_string()),
        world_root: Some(record.world_root.clone()),
        world_bundle: Some(record.world_root.clone()),
        sealcheck_report_digest: Some(record.sealcheck_report_digest.clone()),
        grader_image_digest: Some(record.version_tuple.grader_image_digest.clone()),
        boot_record: record.boot_record.clone(),
    };
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    let (statement, _) = verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard)
        .expect("attestation verification must succeed");
    assert_eq!(statement.predicate.agent_mode, AgentMode::G);
    assert_eq!(
        statement.predicate.gateway_log_head,
        record.gateway_log_head
    );
    assert_eq!(
        statement.predicate.history_rewrite_count,
        record.history_rewrite_count
    );
    assert_eq!(
        statement.predicate.gateway_adapter_version,
        record.gateway_adapter_version
    );
}

#[test]
fn test_fake_upstream_stays_alive_until_dropped() {
    let upstream = FakeUpstream::start().expect("start fake upstream");
    let port = upstream.port;

    for _ in 0..2 {
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to fake upstream");
        stream
            .write_all(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 0\r\n\r\n")
            .expect("write request");
        stream.flush().expect("flush");

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read response");
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("deterministic mode-g answer"));
    }

    let start = Instant::now();
    drop(upstream);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn test_positive_smoke_post_request_content_length_matches_body() {
    let body = "{\"model\":\"claude-3-5-sonnet-20241022\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}";
    let body_bytes = body.as_bytes();
    assert_eq!(
        body_bytes.len(),
        102,
        "actual json body length is 102 bytes"
    );

    let mut incomplete_stream = std::io::Cursor::new(body_bytes);
    let mut receiver_buf_104 = vec![0u8; 104];
    let err = incomplete_stream
        .read_exact(&mut receiver_buf_104)
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

    let mut complete_stream = std::io::Cursor::new(body_bytes);
    let mut receiver_buf_102 = vec![0u8; 102];
    complete_stream
        .read_exact(&mut receiver_buf_102)
        .expect("reading exact 102 bytes succeeds");
    assert_eq!(&receiver_buf_102[..], body_bytes);
}

#[allow(dead_code)]
fn environment() -> Option<support::Fixture> {
    let mut vars = Vec::new();
    for name in ["HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_ROOTFS"] {
        match std::env::var(name) {
            Ok(value) => vars.push(value),
            Err(_) => {
                eprintln!("skipped: set HERMETIC_FC_BIN, HERMETIC_KERNEL and HERMETIC_ROOTFS");
                return None;
            }
        }
    }
    let mut f = support::Fixture::new();
    f.spec.jail.firecracker = vars[0].clone();
    f.spec.kernel_image = vars[1].clone();
    f.spec.root_drive.path = vars[2].clone();
    Some(f)
}

#[test]
fn test_agent_g_spec_validates_with_opt_agent_volume_and_netvm_network() {
    let mut fixture = support::Fixture::new();
    assert_eq!(fixture.spec.role, Role::Agent);

    // Add /opt/agent read-only drive
    let agent_disk = fixture.temp.path().join("agent.raw");
    std::fs::write(&agent_disk, b"fake-agent-volume").unwrap();
    std::fs::set_permissions(&agent_disk, std::fs::Permissions::from_mode(0o600)).unwrap();

    fixture.spec.drives.push(Drive {
        id: "agent".into(),
        path: agent_disk.to_str().unwrap().into(),
        read_only: true,
    });

    let validated = fixture
        .spec
        .validate()
        .expect("Mode G AgentVM spec must validate");
    assert_eq!(validated.spec().drives.len(), 2);
    assert_eq!(validated.spec().drives[0].id, "overlay");
    assert!(!validated.spec().drives[0].read_only);
    assert_eq!(validated.spec().drives[1].id, "agent");
    assert!(validated.spec().drives[1].read_only);
}

#[test]
fn test_agent_g_offline_skips_cleanly_when_unconfigured() {
    let Some(fixture) = environment() else {
        println!("test_agent_g_offline_skips_cleanly_when_unconfigured: cleanly skipped");
        return;
    };

    // If environment is set, verify execution setup
    assert_eq!(fixture.spec.role, Role::Agent);
    let agent_disk = fixture.temp.path().join("agent.raw");
    std::fs::write(&agent_disk, b"agent-content").unwrap();
    std::fs::set_permissions(&agent_disk, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut spec = fixture.spec;
    spec.drives.push(Drive {
        id: "agent".into(),
        path: agent_disk.to_str().unwrap().into(),
        read_only: true,
    });
    assert!(spec.validate().is_ok());
}
