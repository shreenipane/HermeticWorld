//! Owner-run two-VM network smoke: NetVM (hermetic-netvm as PID 1) and AgentVM
//! (execd as PID 1) on preconfigured host taps, with a host WorldServer behind the
//! NetVM's vsock. Driven by scripts/integration/net-smoke.sh; the default gate never
//! boots anything.
#![cfg_attr(not(feature = "dev-unjailed"), allow(dead_code, unused_imports))]
mod support;
use hermetic_vmm::spec::{project_mac, validate_run, Network, Role};
use hermetic_vmm::{api, deadline, Error, Result, Vmm};
use serde::Deserialize;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const T_CLOCK: u64 = 1_700_000_000;
const MAX_REPLY_BYTES: u32 = 64 * 1024;
const MAX_HANDSHAKE_BYTES: usize = 64;
const WORLD_PORT: u32 = 5001;
const DIAGNOSTIC_COMMAND_TIMEOUT_MS: u64 = 1000;
const DIAGNOSTIC_CALL_TIMEOUT: Duration = Duration::from_secs(2);
// Four capped console streams and four capped execd replies, allowing for UTF-8
// replacement expansion plus fixed headings.
const MAX_DIAGNOSTIC_BYTES: usize = 2 * 1024 * 1024;
const DIAGNOSTIC_COMMANDS: [&[&str]; 4] = [
    &["/bin/busybox", "ip", "addr"],
    &["/bin/busybox", "ip", "route"],
    &["/bin/busybox", "ip", "neigh"],
    &["/bin/busybox", "cat", "/etc/resolv.conf"],
];
const ENV: [&str; 7] = [
    "HERMETIC_FC_BIN",
    "HERMETIC_KERNEL",
    "HERMETIC_ROOTFS",
    "HERMETIC_NETVM_ROOTFS",
    "HERMETIC_WORLD_SERVER_BIN",
    "HERMETIC_WORLD_STORE",
    "HERMETIC_NET_WORK",
];

#[derive(Debug, Deserialize)]
struct GuestExec {
    code: Option<i32>,
    output: Vec<u8>,
    timed_out: bool,
}

/// One execd request over Firecracker's host-initiated vsock handshake.
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

fn exec(socket: &str, argv: &[&str]) -> GuestExec {
    let end = deadline(Duration::from_secs(30)).unwrap();
    exec_until(socket, argv, end, 10000).expect("execd call failed")
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

/// Called outside the unwinding closure, before either VM is dropped. A failed
/// diagnostic must not hide the smoke assertion or prevent the other probes.
fn diagnostic_report(
    agent: (Vec<u8>, Vec<u8>),
    net: (Vec<u8>, Vec<u8>),
    mut call: impl FnMut(&[&str]) -> Result<GuestExec>,
) -> String {
    use std::fmt::Write;
    let mut report = String::new();
    for (name, (serial, errors)) in [("AgentVM", agent), ("NetVM", net)] {
        let _ = writeln!(
            report,
            "=== {name} serial stdout ===\n{}",
            String::from_utf8_lossy(&serial)
        );
        let _ = writeln!(
            report,
            "=== {name} stderr ===\n{}",
            String::from_utf8_lossy(&errors)
        );
    }
    for argv in DIAGNOSTIC_COMMANDS {
        let _ = writeln!(report, "=== agent diagnostics: {} ===", argv.join(" "));
        match call(argv) {
            Ok(reply) => {
                let _ = writeln!(
                    report,
                    "code={:?} timed_out={}\n{}",
                    reply.code,
                    reply.timed_out,
                    String::from_utf8_lossy(&reply.output)
                );
            }
            Err(_) => {
                let _ = writeln!(report, "execd unavailable");
            }
        }
    }
    report
}

fn save_diagnostics(work: &std::path::Path, report: &str) -> Result<()> {
    use std::io::Write;
    if report.len() > MAX_DIAGNOSTIC_BYTES {
        return Err(Error::Protocol);
    }
    let dir = hermetic_vmm::fs::Directory::open(work.to_str().ok_or(Error::Io)?)?;
    dir.exclusive()?;
    let staged = dir.descriptor_path(".net-smoke-diagnostics.tmp");
    let published = dir.descriptor_path("net-smoke-diagnostics.log");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    // A no-replace hard link publishes only the complete, synced report. Every
    // operation stays in the held private directory, including cleanup.
    let result: Result<()> = (|| {
        file.write_all(report.as_bytes())?;
        file.sync_all()?;
        std::fs::hard_link(&staged, &published)?;
        std::fs::File::open(dir.descriptor_path(""))?.sync_all()?;
        Ok(())
    })();
    let cleanup = std::fs::remove_file(staged);
    result?;
    cleanup?;
    Ok(())
}

fn sh(socket: &str, script: &str) -> (Option<i32>, String) {
    let r = exec(socket, &["/bin/busybox", "sh", "-c", script]);
    assert!(!r.timed_out, "guest command timed out: {script}");
    let out = String::from_utf8_lossy(&r.output).into_owned();
    eprintln!("agent$ {script}\n  -> code={:?} {out:?}", r.code);
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

/// Kills and reaps the host WorldServer on every exit path.
struct World(std::process::Child);
impl Drop for World {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "needs dev-unjailed, /dev/kvm, host taps, NetVM and agent rootfs; see scripts/integration/net-smoke.sh"]
fn netvm_serves_world_to_agent_and_drops_everything_else() {
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
                panic!("missing smoke prerequisites: {}", ENV.join(", "));
            }
        }
    }
    let agent_tap = std::env::var("HERMETIC_AGENT_TAP").unwrap_or_else(|_| "hwtap-agent".into());
    let net_tap = std::env::var("HERMETIC_NET_TAP").unwrap_or_else(|_| "hwtap-net".into());

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

    let work = std::path::Path::new(&v[6]);
    let mut agent_socket = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        net_vm.prepare(Duration::from_secs(120)).unwrap();
        // Firecracker forwards a guest connect to CID 2 port P to "<uds_path>_P".
        let world_socket = net.temp.path().join(format!(
            "firecracker/{}/root/vsock_{WORLD_PORT}",
            net.spec.id
        ));
        assert!(world_socket.parent().unwrap().is_dir(), "jail root layout");
        let _world = World(
            Command::new(&v[4])
                .arg("--store")
                .arg(&v[5])
                .arg("--socket")
                .arg(&world_socket)
                .arg("--log")
                .arg(work.join("world-log"))
                .args(["--t-clock", "2023-11-14T22:13:20Z"])
                // A sandboxed WorldServer serves one connection per run; its per-frame
                // deadline also bounds idle time between frames, so the smoke widens it.
                .args(["--frame-deadline-ms", "600000"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(work.join("world-server.stderr")).unwrap())
                .spawn()
                .expect("start world server"),
        );
        // Never connect here: the single connection belongs to the NetVM.
        let end = Instant::now() + Duration::from_secs(10);
        while !world_socket.exists() {
            assert!(Instant::now() < end, "world server did not bind its socket");
            std::thread::sleep(Duration::from_millis(20));
        }
        // The host supplies only this world's CA material through the NetVM's
        // private UDS; the guest validates it against its sealed identity.
        let ca_socket = world_socket.with_file_name("vsock_5003");
        let ca_listener = std::os::unix::net::UnixListener::bind(&ca_socket).unwrap();
        ca_listener.set_nonblocking(true).unwrap();
        let material = {
            use std::io::Read;
            let file = hermetic_netvm_core::files::regular(
                &work.join("ca.boot"),
                (hermetic_netvm_core::tls::MAX_BOOT_BYTES + 4) as u64,
            )
            .unwrap();
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            let mut bytes = Vec::new();
            file.take((hermetic_netvm_core::tls::MAX_BOOT_BYTES + 5) as u64)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() <= hermetic_netvm_core::tls::MAX_BOOT_BYTES + 4);
            bytes
        };
        let ca_sender = std::thread::spawn(move || {
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
        });
        net_vm.start(Duration::from_secs(10)).unwrap();
        net_vm.wait_ready(Duration::from_secs(30)).unwrap();
        ca_sender.join().unwrap();

        agent_vm.prepare(Duration::from_secs(120)).unwrap();
        agent_socket = agent_vm.jail().map(|j| j.root.descriptor_path("vsock"));
        agent_vm.start(Duration::from_secs(10)).unwrap();
        agent_vm.wait_ready(Duration::from_secs(30)).unwrap();
        let socket = agent_vm.jail().unwrap().root.descriptor_path("vsock");

        // Readiness now requires execd to apply the run-spec network. These
        // probes only inspect it; no harness command repairs a missing setup.
        for (argv, expected) in [
            (
                &["/bin/busybox", "ip", "addr", "show", "dev", "eth0"][..],
                "10.0.2.15/32",
            ),
            (
                &["/bin/busybox", "ip", "link", "show", "dev", "eth0"][..],
                "mtu 1500",
            ),
            (
                &["/bin/busybox", "ip", "route", "show", "10.0.2.3/32"][..],
                "10.0.2.3 dev eth0",
            ),
            (
                &["/bin/busybox", "ip", "route", "show", "default"][..],
                "default via 10.0.2.3 dev eth0",
            ),
            (
                &["/bin/busybox", "sysctl", "net.ipv6.conf.all.disable_ipv6"][..],
                "net.ipv6.conf.all.disable_ipv6 = 1",
            ),
            (
                &[
                    "/bin/busybox",
                    "sysctl",
                    "net.ipv6.conf.default.disable_ipv6",
                ][..],
                "net.ipv6.conf.default.disable_ipv6 = 1",
            ),
        ] {
            let r = exec(&socket, argv);
            assert_eq!(
                r.code,
                Some(0),
                "{argv:?}: {:?}",
                String::from_utf8_lossy(&r.output)
            );
            assert!(String::from_utf8_lossy(&r.output).contains(expected));
        }
        // Let the NetVM finish its boot (it binds after eth0 is up).
        let ready = Instant::now() + Duration::from_secs(20);
        loop {
            let (_, out) = sh(&socket, "/bin/busybox nslookup files.example 10.0.2.3 2>&1");
            if out.contains("10.9.0.1") {
                break;
            }
            assert!(Instant::now() < ready, "allowed name never resolved: {out}");
            std::thread::sleep(Duration::from_millis(500));
        }

        // 1. Unknown name: NXDOMAIN.
        let (_, out) = sh(
            &socket,
            "/bin/busybox nslookup unknown.example 10.0.2.3 2>&1",
        );
        assert!(out.contains("NXDOMAIN") && !out.contains("10.9."), "{out}");

        // 2. GET through the filter returns the fixture body.
        let get = "printf 'GET /hello.txt HTTP/1.1\\r\\nHost: files.example\\r\\nConnection: close\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.1 80";
        let (_, out) = sh(&socket, get);
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.ends_with("hello from the frozen world\n"), "{out}");

        // Under TPROXY (TR-NET-3), requests to destination addresses that do not
        // match the host's DNS table address are refused (connection reset).
        for address in ["1.1.1.1", "192.168.0.1", "169.254.169.254", "10.0.2.2"] {
            let (_, out) = sh(&socket, &format!("printf 'GET /hello.txt HTTP/1.1\\r\\nHost: files.example\\r\\n\\r\\n' | /bin/busybox nc -w 5 {address} 80"));
            assert!(!out.contains("HTTP/1.1"), "{address}: {out}");
            let (_, out) = sh(&socket, &format!("printf 'GET / HTTP/1.1\\r\\nHost: unknown.example\\r\\n\\r\\n' | /bin/busybox nc -w 5 {address} 80"));
            assert!(!out.contains("HTTP/1.1"), "{address}: {out}");
        }

        // 3. POST: 405.
        let post = "printf 'POST /hello.txt HTTP/1.1\\r\\nHost: files.example\\r\\nContent-Length: 0\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.1 80";
        let (_, out) = sh(&socket, post);
        assert!(out.starts_with("HTTP/1.1 405"), "{out}");

        // 4. Unknown Host header on an owned world address: no response.
        let other = "printf 'GET / HTTP/1.1\\r\\nHost: elsewhere.example\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.1 80";
        let (_, out) = sh(&socket, other);
        assert!(!out.contains("HTTP/1.1 2"), "{out}");

        // 5. Other ports and unreachable neighbours remain blocked. Off-link
        //    port 80 destinations are tested above against the sealed fixture.
        for target in ["8.8.8.8 53", "10.0.2.1 22", "10.0.2.3 22", "10.0.2.3 5001"] {
            let (code, out) = sh(
                &socket,
                &format!("echo x | /bin/busybox nc -w 3 {target} && echo CONNECTED"),
            );
            assert!(
                code != Some(0) && !out.contains("CONNECTED"),
                "{target}: {out}"
            );
        }
        // Certificate verification uses only the injected world CA on the manifest
        // destination address (10.9.0.1). Mismatched destination addresses are refused.
        let address = "10.9.0.1";
        let (code, out) = sh(&socket, &format!("/bin/hermetic-https-fetch /etc/hermetic/ca.der {address} files.example /hello.txt GET 1700000000"));
        assert_eq!(code, Some(0), "{address}: {out}");
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.ends_with("hello from the frozen world\n"), "{out}");
        let (code, out) = sh(&socket, &format!("/bin/hermetic-https-fetch /etc/hermetic/unrelated.der {address} files.example /hello.txt GET 1700000000"));
        assert_ne!(code, Some(0), "unrelated CA accepted: {out}");
        assert!(!out.contains("hello from the frozen world"), "{out}");
        for address in ["1.1.1.1", "192.168.0.1", "169.254.169.254", "10.0.2.2"] {
            let (code, out) = sh(&socket, &format!("/bin/hermetic-https-fetch /etc/hermetic/ca.der {address} files.example /hello.txt GET 1700000000"));
            assert_ne!(
                code,
                Some(0),
                "mismatched address accepted: {address}: {out}"
            );
            assert!(
                !out.contains("hello from the frozen world"),
                "{address}: {out}"
            );
        }
        let (code, out) = sh(&socket, "/bin/hermetic-https-fetch /etc/hermetic/ca.der 10.9.0.1 files.example /hello.txt HEAD 1700000000");
        assert_eq!(code, Some(0), "{out}");
        assert!(!out.contains("hello from the frozen world"), "{out}");
        // ICMP addressed to NetVM itself must be dropped, independently of routing.
        for address in ["10.0.2.3", "10.9.0.1"] {
            let (code, _) = sh(&socket, &format!("/bin/busybox ping -c 1 -W 2 {address}"));
            assert_ne!(code, Some(0), "ICMP answered by {address}");
        }
        // The run-spec resolver must be a regular file installed by execd.
        let (code, out) = sh(&socket, "test -f /etc/resolv.conf && test ! -L /etc/resolv.conf && /bin/busybox cat /etc/resolv.conf");
        assert_eq!(code, Some(0));
        assert_eq!(out, "nameserver 10.0.2.3\noptions ndots:0\n");

        // DNS to a public resolver gets no answer.
        let (_, out) = sh(
            &socket,
            "/bin/busybox timeout 5 /bin/busybox nslookup files.example 8.8.8.8 2>&1",
        );
        assert!(!out.contains("10.9.0.1"), "{out}");

        agent_vm.stop(Duration::from_secs(2)).unwrap();
        agent_vm.destroy(Duration::from_secs(10)).unwrap();
        net_vm.stop(Duration::from_secs(2)).unwrap();
        net_vm.destroy(Duration::from_secs(10)).unwrap();
    }));
    if let Err(failure) = outcome {
        let report = diagnostic_report(
            agent_vm.runner().console_output(),
            net_vm.runner().console_output(),
            |argv| {
                let socket = agent_socket.as_deref().ok_or(Error::Io)?;
                exec_until(
                    socket,
                    argv,
                    deadline(DIAGNOSTIC_CALL_TIMEOUT)?,
                    DIAGNOSTIC_COMMAND_TIMEOUT_MS,
                )
            },
        );
        eprintln!("{report}");
        if save_diagnostics(work, &report).is_err() {
            eprintln!("could not save net-smoke-diagnostics.log");
        }
        std::panic::resume_unwind(failure);
    }
}

#[test]
fn failure_diagnostics_include_both_consoles_and_all_agent_probes() {
    let mut seen = Vec::new();
    let report = diagnostic_report(
        (b"agent serial".to_vec(), b"agent error".to_vec()),
        (b"netvm_ready".to_vec(), b"net error".to_vec()),
        |argv| {
            seen.push(argv.join(" "));
            if argv.contains(&"route") {
                return Err(Error::Io);
            }
            Ok(GuestExec {
                code: Some(0),
                output: b"probe output".to_vec(),
                timed_out: false,
            })
        },
    );
    assert_eq!(seen, DIAGNOSTIC_COMMANDS.map(|argv| argv.join(" ")));
    for expected in [
        "AgentVM serial",
        "agent serial",
        "agent error",
        "NetVM serial",
        "netvm_ready",
        "net error",
        "execd unavailable",
        "probe output",
    ] {
        assert!(report.contains(expected), "missing {expected}");
    }
}

#[test]
fn diagnostic_artifacts_are_private_and_never_replace_existing_files() {
    let report = "fixed diagnostic report";
    // Default tempdir permissions depend on umask and may permit group writes.
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    assert_eq!(
        std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    save_diagnostics(temp.path(), report).unwrap();
    let path = temp.path().join("net-smoke-diagnostics.log");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), report);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(save_diagnostics(temp.path(), "overwrite").is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), report);
    assert!(!temp.path().join(".net-smoke-diagnostics.tmp").exists());
}

#[test]
fn diagnostics_refuse_oversized_reports_before_file_access() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    assert_eq!(
        save_diagnostics(&missing, &"x".repeat(MAX_DIAGNOSTIC_BYTES + 1)),
        Err(Error::Protocol)
    );
    assert!(!missing.exists());
}

#[cfg(feature = "dev-unjailed")]
#[test]
fn development_console_survives_failure_cleanup_and_is_bounded() {
    use hermetic_vmm::runner::{DevUnjailed, MAX_CAPTURE_BYTES};
    // A stand-in executable writes serial and stderr then exits before any API
    // exists, exercising the real spawn -> wait_ready failure -> cleanup path.
    let mut fixture = support::Fixture::new();
    let launcher = python_launcher(&fixture);
    let executable = fixture.temp.path().join("console-fixture");
    std::fs::write(
        &executable,
        format!("#!{launcher}\nimport os\nos.write(1,b's'*262144)\nos.write(2,b'e'*262144)\n"),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
    fixture.spec.jail.firecracker = executable.to_str().unwrap().into();
    let mut vm = Vmm::new(
        fixture.spec.clone().validate().unwrap(),
        DevUnjailed::new(&launcher).unwrap(),
    );
    vm.prepare(Duration::from_secs(5)).unwrap();
    vm.start(Duration::from_secs(5)).unwrap();
    assert!(vm.wait_ready(Duration::from_secs(5)).is_err());
    assert_eq!(vm.state(), hermetic_vmm::State::Failed);
    assert!(vm.jail().is_none(), "failure cleanup must have run");
    let (serial, errors) = vm.runner().console_output();
    assert_eq!(serial, vec![b's'; MAX_CAPTURE_BYTES]);
    assert_eq!(errors, vec![b'e'; MAX_CAPTURE_BYTES]);
}
