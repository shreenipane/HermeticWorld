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
const MAX_CONSOLE_SCAN_BYTES: usize = 256 * 1024;
const ENV: [&str; 8] = [
    "HERMETIC_FC_BIN",
    "HERMETIC_FIRECRACKER_LOCK",
    "HERMETIC_KERNEL",
    "HERMETIC_ROOTFS",
    "HERMETIC_NETVM_ROOTFS",
    "HERMETIC_WORLD_SERVER_BIN",
    "HERMETIC_WORLD_STORE",
    "HERMETIC_NET_WORK",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetVmReady {
    pub interface: String,
    pub address: String,
    pub dns: String,
    pub http: String,
    pub path: String,
    pub destination_binding: String,
}

/// Parse and validate the sealed NetVM ready status line from console output.
pub fn parse_netvm_ready(output: &str) -> std::result::Result<NetVmReady, &'static str> {
    if output.len() > MAX_CONSOLE_SCAN_BYTES {
        return Err("oversized console output");
    }
    let mut found = None;

    for raw_line in output.lines() {
        let line = raw_line.trim_end_matches('\r').trim();
        let Some(pos) = line.find("netvm_ready") else {
            continue;
        };
        if pos > 0 {
            let prev = line.as_bytes()[pos - 1];
            if prev != b' ' && prev != b'\t' && prev != b':' && prev != b']' {
                continue;
            }
        }
        let remainder = &line[pos + "netvm_ready".len()..];
        if !remainder.is_empty() && !remainder.starts_with(' ') && !remainder.starts_with('\t') {
            continue;
        }

        let mut interface = None;
        let mut address = None;
        let mut dns = None;
        let mut http = None;
        let mut path = None;
        let mut destination_binding = None;

        let tokens = remainder.split_whitespace();
        for token in tokens {
            let Some((k, v)) = token.split_once('=') else {
                return Err("malformed token missing '=' in netvm_ready");
            };
            if k.is_empty() || v.is_empty() {
                return Err("empty key or value in netvm_ready");
            }
            match k {
                "interface" => {
                    if interface.is_some() {
                        return Err("duplicate interface in netvm_ready");
                    }
                    interface = Some(v.to_string());
                }
                "address" => {
                    if address.is_some() {
                        return Err("duplicate address in netvm_ready");
                    }
                    address = Some(v.to_string());
                }
                "dns" => {
                    if dns.is_some() {
                        return Err("duplicate dns in netvm_ready");
                    }
                    dns = Some(v.to_string());
                }
                "http" => {
                    if http.is_some() {
                        return Err("duplicate http in netvm_ready");
                    }
                    http = Some(v.to_string());
                }
                "path" => {
                    if path.is_some() {
                        return Err("duplicate path in netvm_ready");
                    }
                    path = Some(v.to_string());
                }
                "destination_binding" => {
                    if destination_binding.is_some() {
                        return Err("duplicate destination_binding in netvm_ready");
                    }
                    destination_binding = Some(v.to_string());
                }
                _ => return Err("unknown key in netvm_ready"),
            }
        }

        if interface.is_none()
            && address.is_none()
            && dns.is_none()
            && http.is_none()
            && path.is_none()
            && destination_binding.is_none()
        {
            continue;
        }

        let ready = NetVmReady {
            interface: interface.ok_or("missing interface in netvm_ready")?,
            address: address.ok_or("missing address in netvm_ready")?,
            dns: dns.ok_or("missing dns in netvm_ready")?,
            http: http.ok_or("missing http in netvm_ready")?,
            path: path.ok_or("missing path in netvm_ready")?,
            destination_binding: destination_binding
                .ok_or("missing destination_binding in netvm_ready")?,
        };

        if found.is_some() {
            return Err("multiple netvm_ready status lines");
        }
        found = Some(ready);
    }

    found.ok_or("missing netvm_ready status line")
}

/// Assert that the NetVM ready status line reports the expected path and coherent binding.
pub fn assert_netvm_ready_path(
    output: &str,
    expected_path: &str,
) -> std::result::Result<NetVmReady, &'static str> {
    let ready = parse_netvm_ready(output)?;
    if ready.path != expected_path {
        return Err("mismatched path in netvm_ready");
    }
    match ready.path.as_str() {
        "tproxy" => {
            if ready.destination_binding != "on" {
                return Err("inconsistent destination_binding for tproxy");
            }
        }
        "redirect" => {
            if ready.destination_binding != "off" {
                return Err("inconsistent destination_binding for redirect");
            }
        }
        _ => return Err("unsupported path value in netvm_ready"),
    }
    Ok(ready)
}

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
    eprintln!("skipped: build with --features dev-unjailed");
}

#[cfg(feature = "dev-unjailed")]
fn run() {
    use hermetic_vmm::runner::DevUnjailed;
    for name in ENV {
        if std::env::var(name).is_err() {
            eprintln!("skipped: missing smoke prerequisites: {}", ENV.join(", "));
            return;
        }
    }
    let fc_bin = std::env::var("HERMETIC_FC_BIN").unwrap();
    let kernel = std::env::var("HERMETIC_KERNEL").unwrap();
    let agent_rootfs = std::env::var("HERMETIC_ROOTFS").unwrap();
    let netvm_rootfs = std::env::var("HERMETIC_NETVM_ROOTFS").unwrap();
    let world_server_bin = std::env::var("HERMETIC_WORLD_SERVER_BIN").unwrap();
    let world_store = std::env::var("HERMETIC_WORLD_STORE").unwrap();
    let work_dir_str = std::env::var("HERMETIC_NET_WORK").unwrap();

    let agent_tap = std::env::var("HERMETIC_AGENT_TAP").unwrap_or_else(|_| "hwtap-agent".into());
    let net_tap = std::env::var("HERMETIC_NET_TAP").unwrap_or_else(|_| "hwtap-net".into());

    let mut agent = support::Fixture::new();
    agent.spec.id = "agent-0".into();
    agent.spec.jail.firecracker = fc_bin.clone();
    agent.spec.kernel_image = kernel.clone();
    agent.spec.root_drive.path = agent_rootfs;
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
    net.spec.jail.firecracker = fc_bin;
    net.spec.kernel_image = kernel;
    net.spec.root_drive.path = netvm_rootfs;
    net.spec.boot_args = net
        .spec
        .boot_args
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-netvm");
    if let Ok(verity_path) = std::env::var("HERMETIC_NETVM_VERITY") {
        let work = std::path::Path::new(&v[6]);
        let verity_meta = work.join("netvm-verity.json");
        let dm_create = if let Ok(data) = std::fs::read_to_string(&verity_meta) {
            let parsed: serde_json::Value =
                serde_json::from_str(&data).expect("invalid netvm-verity.json");
            parsed["dm_create"]
                .as_str()
                .expect("missing dm_create in netvm-verity.json")
                .to_string()
        } else {
            std::env::var("HERMETIC_NETVM_DM_CREATE")
                .expect("missing HERMETIC_NETVM_DM_CREATE or netvm-verity.json")
        };
        net.spec.drives = vec![hermetic_vmm::spec::Drive {
            id: "verity_hash".into(),
            path: verity_path,
            read_only: true,
        }];
        net.spec.boot_args = net
            .spec
            .boot_args
            .replace("root=/dev/vda", "root=/dev/dm-0");
        net.spec.boot_args.push(' ');
        net.spec.boot_args.push_str(&dm_create);
    }
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

    let work = std::path::Path::new(&work_dir_str);
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
            Command::new(&world_server_bin)
                .arg("--store")
                .arg(&world_store)
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

        // Assert the NetVM ready status reports path=tproxy (TR-NET-3).
        let (net_serial, net_stderr) = net_vm.runner().console_output();
        let mut console = String::from_utf8_lossy(&net_serial).into_owned();
        console.push('\n');
        console.push_str(&String::from_utf8_lossy(&net_stderr));
        let ready = assert_netvm_ready_path(&console, "tproxy")
            .expect("NetVM ready status must report path=tproxy");
        eprintln!(
            "netvm_ready interface={} address={} dns={} http={} path={} destination_binding={}",
            ready.interface,
            ready.address,
            ready.dns,
            ready.http,
            ready.path,
            ready.destination_binding
        );

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

#[test]
fn netvm_boots_with_dm_verity_and_corrupt_images_fail() {
    #[cfg(feature = "dev-unjailed")]
    {
        use hermetic_vmm::runner::DevUnjailed;
        use std::io::{Read, Seek, Write};
        let required_env = [
            "HERMETIC_FC_BIN",
            "HERMETIC_KERNEL",
            "HERMETIC_NETVM_ROOTFS",
            "HERMETIC_NETVM_VERITY",
        ];
        let mut vars = Vec::new();
        for name in required_env {
            match std::env::var(name) {
                Ok(val) => vars.push(val),
                Err(_) => {
                    eprintln!("skipped: {name} not set");
                    return;
                }
            }
        }
        let fc = &vars[0];
        let kernel = &vars[1];
        let rootfs = &vars[2];
        let verity_img = &vars[3];

        let dm_create = match std::env::var("HERMETIC_NETVM_DM_CREATE") {
            Ok(val) => val,
            Err(_) => {
                let p = std::path::Path::new(rootfs)
                    .parent()
                    .unwrap()
                    .join("netvm-verity.json");
                if let Ok(data) = std::fs::read_to_string(&p) {
                    let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
                    parsed["dm_create"].as_str().unwrap().to_string()
                } else {
                    eprintln!(
                        "skipped: HERMETIC_NETVM_DM_CREATE not set and netvm-verity.json missing"
                    );
                    return;
                }
            }
        };

        let fixture = support::Fixture::new();
        let launcher = python_launcher(&fixture);
        let base = fixture.temp.path();

        let mut net = support::Fixture::new();
        net.spec.id = "net-verity-0".into();
        net.spec.role = Role::Net;
        net.spec.index = 0;
        net.spec.memory_mib = 128;
        net.spec.jail.firecracker = fc.clone();
        net.spec.kernel_image = kernel.clone();
        net.spec.root_drive.path = rootfs.clone();
        net.spec.root_drive.read_only = true;
        net.spec.drives = vec![hermetic_vmm::spec::Drive {
            id: "verity_hash".into(),
            path: verity_img.clone(),
            read_only: true,
        }];
        net.spec.boot_args = format!(
            "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
        );
        net.spec.networks = vec![Network {
            tap: std::env::var("HERMETIC_NET_TAP").unwrap_or_else(|_| "hwtap-net".into()),
            guest_mac: project_mac(Role::Net, 0),
            peer: Role::Agent,
        }];

        // 1. Corrupt data image must fail (either on VMM prepare or guest dm-verity)
        let corrupt_data = base.join("corrupt-data.img");
        std::fs::copy(rootfs, &corrupt_data).unwrap();
        std::fs::set_permissions(&corrupt_data, std::fs::Permissions::from_mode(0o600)).unwrap();
        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&corrupt_data)
                .unwrap();
            f.seek(std::io::SeekFrom::Start(1024)).unwrap();
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).unwrap();
            byte[0] ^= 0x55;
            f.seek(std::io::SeekFrom::Start(1024)).unwrap();
            f.write_all(&byte).unwrap();
        }
        std::fs::set_permissions(&corrupt_data, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut bad_net_data = net.spec.clone();
        bad_net_data.id = "net-corrupt-data".into();
        bad_net_data.root_drive.path = corrupt_data.to_str().unwrap().into();
        let mut bad_data_vm = Vmm::new(
            bad_net_data.validate().unwrap(),
            DevUnjailed::new(&launcher).unwrap(),
        );
        let prep = bad_data_vm.prepare(Duration::from_secs(30));
        if prep.is_ok() {
            assert!(bad_data_vm.start(Duration::from_secs(10)).is_ok());
            let ready = bad_data_vm.wait_ready(Duration::from_secs(10));
            if ready.is_ok() {
                assert!(
                    bad_data_vm.wait_exit(Duration::from_secs(10)).is_ok(),
                    "corrupt data image reached ready without dm-verity exit"
                );
            }
        } else {
            assert!(matches!(prep.err(), Some(Error::Validation(_))));
        }

        // 2. Corrupt hash image root block must fail closed on VMM prepare (root hash mismatch)
        let corrupt_hash = base.join("corrupt-hash.img");
        std::fs::copy(verity_img, &corrupt_hash).unwrap();
        std::fs::set_permissions(&corrupt_hash, std::fs::Permissions::from_mode(0o600)).unwrap();
        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&corrupt_hash)
                .unwrap();
            f.seek(std::io::SeekFrom::Start(1024)).unwrap();
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).unwrap();
            byte[0] ^= 0xaa;
            f.seek(std::io::SeekFrom::Start(1024)).unwrap();
            f.write_all(&byte).unwrap();
        }
        std::fs::set_permissions(&corrupt_hash, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut bad_net_hash = net.spec.clone();
        bad_net_hash.id = "net-corrupt-hash".into();
        bad_net_hash.drives[0].path = corrupt_hash.to_str().unwrap().into();
        let mut bad_hash_vm = Vmm::new(
            bad_net_hash.validate().unwrap(),
            DevUnjailed::new(&launcher).unwrap(),
        );
        let prep_hash = bad_hash_vm.prepare(Duration::from_secs(30));
        assert_eq!(
            prep_hash.err(),
            Some(Error::Validation("verity root hash mismatch"))
        );

        // 3. Corrupt hash image tree block (beyond root block) must boot-fail in guest dm-verity
        let hash_len = std::fs::metadata(verity_img).unwrap().len();
        if hash_len > 4096 {
            let corrupt_tree = base.join("corrupt-tree.img");
            std::fs::copy(verity_img, &corrupt_tree).unwrap();
            std::fs::set_permissions(&corrupt_tree, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            {
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&corrupt_tree)
                    .unwrap();
                f.seek(std::io::SeekFrom::Start(4096 + 1024)).unwrap();
                let mut byte = [0u8; 1];
                f.read_exact(&mut byte).unwrap();
                byte[0] ^= 0x5a;
                f.seek(std::io::SeekFrom::Start(4096 + 1024)).unwrap();
                f.write_all(&byte).unwrap();
            }
            std::fs::set_permissions(&corrupt_tree, std::fs::Permissions::from_mode(0o400))
                .unwrap();
            let mut bad_net_tree = net.spec;
            bad_net_tree.id = "net-corrupt-tree".into();
            bad_net_tree.drives[0].path = corrupt_tree.to_str().unwrap().into();
            let mut bad_tree_vm = Vmm::new(
                bad_net_tree.validate().unwrap(),
                DevUnjailed::new(&launcher).unwrap(),
            );
            let prep_tree = bad_tree_vm.prepare(Duration::from_secs(30));
            if prep_tree.is_ok() {
                assert!(bad_tree_vm.start(Duration::from_secs(10)).is_ok());
                let ready = bad_tree_vm.wait_ready(Duration::from_secs(10));
                if ready.is_ok() {
                    assert!(
                        bad_tree_vm.wait_exit(Duration::from_secs(10)).is_ok(),
                        "corrupt hash tree block guest must boot-fail and exit"
                    );
                }
            } else {
                assert!(matches!(prep_tree.err(), Some(Error::Validation(_))));
            }
        }
    }
}

#[test]
fn test_netvm_ready_status_tproxy_known_answer() {
    let raw = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on\n";
    let status = assert_netvm_ready_path(raw, "tproxy").expect("known-answer tproxy status");
    assert_eq!(status.interface, "eth0");
    assert_eq!(status.address, "10.0.2.3/24");
    assert_eq!(status.dns, "10.0.2.3:53");
    assert_eq!(status.http, "0.0.0.0:80");
    assert_eq!(status.path, "tproxy");
    assert_eq!(status.destination_binding, "on");
}

#[test]
fn test_netvm_ready_status_rejects_redirect_fallback() {
    let raw = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=redirect destination_binding=off\n";
    let status = assert_netvm_ready_path(raw, "redirect").expect("valid redirect status");
    assert_eq!(status.path, "redirect");
    assert_eq!(status.destination_binding, "off");

    let err = assert_netvm_ready_path(raw, "tproxy").unwrap_err();
    assert_eq!(err, "mismatched path in netvm_ready");
}

#[test]
fn test_netvm_ready_status_embedded_in_console_stream() {
    let stream = concat!(
        "[    0.000000] Linux version 6.6.137\r\n",
        "[    0.051234] eth0: link up\r\n",
        "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on\r\n",
        "netvm: listening on 10.0.2.3:53\r\n"
    );
    let status = assert_netvm_ready_path(stream, "tproxy").expect("embedded tproxy status");
    assert_eq!(status.path, "tproxy");
    assert_eq!(status.destination_binding, "on");
}

#[test]
fn test_netvm_ready_status_hostile_and_malformed() {
    // Missing required path field
    let missing_path = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 destination_binding=on\n";
    assert_eq!(
        parse_netvm_ready(missing_path).unwrap_err(),
        "missing path in netvm_ready"
    );

    // Empty path value
    let empty_path = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path= destination_binding=on\n";
    assert_eq!(
        parse_netvm_ready(empty_path).unwrap_err(),
        "empty key or value in netvm_ready"
    );

    // Missing = in token
    let malformed_token = "netvm_ready interface=eth0 address=10.0.2.3/24 broken_token dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on\n";
    assert_eq!(
        parse_netvm_ready(malformed_token).unwrap_err(),
        "malformed token missing '=' in netvm_ready"
    );

    // Duplicate key
    let duplicate_key = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy path=redirect destination_binding=on\n";
    assert_eq!(
        parse_netvm_ready(duplicate_key).unwrap_err(),
        "duplicate path in netvm_ready"
    );

    // Inconsistent destination binding for tproxy
    let inconsistent_tproxy = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=off\n";
    assert_eq!(
        assert_netvm_ready_path(inconsistent_tproxy, "tproxy").unwrap_err(),
        "inconsistent destination_binding for tproxy"
    );

    // Inconsistent destination binding for redirect
    let inconsistent_redirect = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=redirect destination_binding=on\n";
    assert_eq!(
        assert_netvm_ready_path(inconsistent_redirect, "redirect").unwrap_err(),
        "inconsistent destination_binding for redirect"
    );

    // Unknown key
    let unknown_key = "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on evil=true\n";
    assert_eq!(
        parse_netvm_ready(unknown_key).unwrap_err(),
        "unknown key in netvm_ready"
    );

    // Missing status line completely
    assert_eq!(
        parse_netvm_ready("no status here\n").unwrap_err(),
        "missing netvm_ready status line"
    );

    // Substring tricks
    let fake_token = "fake_netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on\n";
    assert_eq!(
        parse_netvm_ready(fake_token).unwrap_err(),
        "missing netvm_ready status line"
    );

    // Conflicting multiple status lines
    let conflicting = concat!(
        "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on\n",
        "netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=redirect destination_binding=off\n"
    );
    assert_eq!(
        parse_netvm_ready(conflicting).unwrap_err(),
        "multiple netvm_ready status lines"
    );

    // Oversized console output
    let oversized = "x".repeat(MAX_CONSOLE_SCAN_BYTES + 1);
    assert_eq!(
        parse_netvm_ready(&oversized).unwrap_err(),
        "oversized console output"
    );
}
