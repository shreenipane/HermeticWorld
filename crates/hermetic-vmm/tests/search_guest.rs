#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "dev-unjailed"), allow(dead_code, unused_imports))]

//! Owner-run search and replay smoke: NetVM (hermetic-netvm as PID 1) and AgentVM
//! (execd as PID 1) on preconfigured host taps, with a host WorldServer serving
//! Tantivy BM25 search and replay archive behind NetVM's vsock.
//! Skips cleanly when KVM or smoke environment variables are unset.
//! Driven by scripts/integration/search-smoke.sh.

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
const MAX_DIAGNOSTIC_BYTES: usize = 2 * 1024 * 1024;
const DIAGNOSTIC_COMMANDS: [&[&str]; 4] = [
    &["/bin/busybox", "ip", "addr"],
    &["/bin/busybox", "ip", "route"],
    &["/bin/busybox", "ip", "neigh"],
    &["/bin/busybox", "cat", "/etc/resolv.conf"],
];
const ENV: [&str; 10] = [
    "HERMETIC_FC_BIN",
    "HERMETIC_FIRECRACKER_LOCK",
    "HERMETIC_KERNEL",
    "HERMETIC_ROOTFS",
    "HERMETIC_NETVM_ROOTFS",
    "HERMETIC_WORLD_SERVER_BIN",
    "HERMETIC_WORLD_STORE",
    "HERMETIC_SEARCH_INDEX",
    "HERMETIC_REPLAY_INDEX",
    "HERMETIC_NET_WORK",
];

#[derive(Debug, Deserialize)]
struct GuestExec {
    code: Option<i32>,
    output: Vec<u8>,
    timed_out: bool,
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
    let req_len = u32::try_from(request.len()).map_err(|_| Error::Protocol)?;
    api::write_deadline(&mut stream, &req_len.to_le_bytes(), end)?;
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
    let staged = dir.descriptor_path(".search-smoke-diagnostics.tmp");
    let published = dir.descriptor_path("search-smoke-diagnostics.log");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
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

struct World(std::process::Child);
impl Drop for World {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn search_guest_vm_serves_search_and_replay_to_agent() {
    #[cfg(feature = "dev-unjailed")]
    {
        for name in ENV {
            if std::env::var(name).is_err() {
                eprintln!("skipped: search guest test requires {}", name);
                return;
            }
        }
        if let Err(e) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
        {
            eprintln!("skipped: cannot open /dev/kvm: {e}");
            return;
        }
        let agent_tap =
            std::env::var("HERMETIC_AGENT_TAP").unwrap_or_else(|_| "hwtap-agent".into());
        let net_tap = std::env::var("HERMETIC_NET_TAP").unwrap_or_else(|_| "hwtap-net".into());
        for tap in [&agent_tap, &net_tap] {
            if !std::path::Path::new(&format!("/sys/class/net/{tap}")).exists() {
                eprintln!("skipped: missing host tap {tap}");
                return;
            }
        }
        run();
    }
    #[cfg(not(feature = "dev-unjailed"))]
    {
        eprintln!("skipped: build with --features dev-unjailed");
    }
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
    agent.spec.kernel_image = v[2].clone();
    agent.spec.root_drive.path = v[3].clone();
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
    net.spec.kernel_image = v[2].clone();
    net.spec.root_drive.path = v[4].clone();
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

    let work = std::path::Path::new(&v[9]);
    let mut agent_socket = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        net_vm.prepare(Duration::from_secs(120)).unwrap();
        let world_socket = net.temp.path().join(format!(
            "firecracker/{}/root/vsock_{WORLD_PORT}",
            net.spec.id
        ));
        assert!(world_socket.parent().unwrap().is_dir(), "jail root layout");
        let _world = World(
            Command::new(&v[5])
                .arg("--store")
                .arg(&v[6])
                .arg("--socket")
                .arg(&world_socket)
                .arg("--log")
                .arg(work.join("world-log"))
                .arg("--search-index")
                .arg(&v[7])
                .arg("--replay-index")
                .arg(&v[8])
                .args(["--t-clock", "2023-11-14T22:13:20Z"])
                .args(["--frame-deadline-ms", "600000"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(work.join("world-server.stderr")).unwrap())
                .spawn()
                .expect("start world server"),
        );

        let end = Instant::now() + Duration::from_secs(10);
        while !world_socket.exists() {
            assert!(Instant::now() < end, "world server did not bind its socket");
            std::thread::sleep(Duration::from_millis(20));
        }

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
        let _ca_sender = std::thread::spawn(move || {
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

        agent_vm.prepare(Duration::from_secs(120)).unwrap();
        agent_socket = Some(
            agent
                .temp
                .path()
                .join(format!("firecracker/{}/root/vsock", agent.spec.id))
                .to_str()
                .unwrap()
                .to_string(),
        );
        agent_vm.start(Duration::from_secs(10)).unwrap();
        agent_vm.wait_ready(Duration::from_secs(30)).unwrap();

        let socket = agent_socket.as_deref().unwrap();
        let ready = Instant::now() + Duration::from_secs(20);
        loop {
            let (_, out) = sh(socket, "/bin/busybox nslookup files.example 10.0.2.3 2>&1");
            if out.contains("10.9.0.1") {
                break;
            }
            assert!(Instant::now() < ready, "allowed name never resolved: {out}");
            std::thread::sleep(Duration::from_millis(500));
        }

        // 1. Tantivy BM25 search query from AgentVM through NetVM and WorldServer
        let search_req = "printf 'GET /search?q=requests HTTP/1.1\\r\\nHost: files.example\\r\\nConnection: close\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.1 80";
        let (_, out) = sh(socket, search_req);
        assert!(out.starts_with("HTTP/1.1 200"), "search response: {out}");
        assert!(
            out.contains("\"hits\"") && out.contains("https://files.example/requests"),
            "search results: {out}"
        );

        // 2. Exact-capture replay fetch from AgentVM through NetVM and WorldServer
        let replay_req = "printf 'GET /requests HTTP/1.1\\r\\nHost: files.example\\r\\nConnection: close\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.1 80";
        let (_, out) = sh(socket, replay_req);
        assert!(out.starts_with("HTTP/1.1 200"), "replay response: {out}");
        assert!(out.contains("Python Requests Page"), "replay body: {out}");

        // 3. Search query with nonexistent term returns 200 OK with total_hits: 0
        let empty_search_req = "printf 'GET /search?q=nonexistentword HTTP/1.1\\r\\nHost: files.example\\r\\nConnection: close\\r\\n\\r\\n' | /bin/busybox nc -w 5 10.9.0.1 80";
        let (_, out) = sh(socket, empty_search_req);
        assert!(
            out.starts_with("HTTP/1.1 200"),
            "empty search response: {out}"
        );
        assert!(out.contains("\"total_hits\":0"), "empty search body: {out}");

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
            eprintln!("could not save search-smoke-diagnostics.log");
        }
        std::panic::resume_unwind(failure);
    }
}

#[test]
fn search_diagnostics_include_both_consoles_and_all_agent_probes() {
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
fn search_diagnostic_artifacts_are_private_and_never_replace_existing_files() {
    let report = "fixed diagnostic report";
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    assert_eq!(
        std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    save_diagnostics(temp.path(), report).unwrap();
    let path = temp.path().join("search-smoke-diagnostics.log");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), report);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(save_diagnostics(temp.path(), "overwrite").is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), report);
    assert!(!temp.path().join(".search-smoke-diagnostics.tmp").exists());
}

fn check_script_executable(path: &std::path::Path) {
    let meta = std::fs::symlink_metadata(path).expect("read metadata");
    assert!(
        !meta.file_type().is_symlink(),
        "script must not be a symlink"
    );
    assert!(meta.is_file(), "script must be a regular file");
    let mode = meta.permissions().mode();
    assert!(
        mode & 0o111 != 0,
        "search-smoke.sh must be executable, got mode {:o}",
        mode
    );
}

#[test]
fn test_search_smoke_script_present_and_executable() {
    let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts/integration/search-smoke.sh");
    check_script_executable(&script_path);
    let content = std::fs::read_to_string(&script_path).expect("read script");
    assert!(content.starts_with("#!/usr/bin/env bash"));
    assert!(content.contains("readlink -f"));
    assert!(content.contains("HERMETIC_FC_BIN"));
    assert!(content.contains("HERMETIC_FIRECRACKER_LOCK"));
    assert!(content.contains("HERMETIC_KERNEL"));
}

#[test]
fn test_search_smoke_script_permission_check_rejects_non_executable() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let script_path = temp.path().join("dummy-script.sh");
    std::fs::write(&script_path, "#!/usr/bin/env bash\n").unwrap();
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let res = std::panic::catch_unwind(|| {
        check_script_executable(&script_path);
    });
    assert!(
        res.is_err(),
        "executable check must reject 0644 mode without mutating file permissions"
    );
    let meta = std::fs::symlink_metadata(&script_path).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o644,
        "mode must remain 0644 (not mutated)"
    );

    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    check_script_executable(&script_path);
}
