#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "dev-unjailed"), allow(dead_code, unused_imports))]

//! Owner-run package mirrors smoke: NetVM (hermetic-netvm as PID 1) and AgentVM
//! (execd as PID 1) on preconfigured host taps, with a host WorldServer serving
//! static package mirrors (PyPI, conda, Debian/Ubuntu, and git dumb HTTP) behind
//! NetVM's vsock.
//! Skips cleanly when KVM or smoke environment variables are unset.
//! Driven by scripts/integration/pkg-smoke.sh.

mod support;
use hermetic_vmm::spec::{project_mac, validate_run, Network, Role};
use hermetic_vmm::{api, deadline, Error, Result, Vmm};
use serde::Deserialize;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const T_CLOCK: u64 = 1_700_000_000;
const MAX_REPLY_BYTES: u32 = 64 * 1024;
const MAX_HANDSHAKE_BYTES: usize = 64;
const WORLD_PORT: u32 = 5001;

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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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
        "pkg-smoke.sh must be executable, got mode {:o}",
        mode
    );
}

#[test]
fn test_pkg_smoke_script_present_and_executable() {
    let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts/integration/pkg-smoke.sh");
    check_script_executable(&script_path);
    let content = std::fs::read_to_string(&script_path).expect("read script");
    assert!(content.starts_with("#!/usr/bin/env bash"));
    assert!(content.contains("readlink -f"));
    assert!(content.contains("HERMETIC_FC_BIN"));
    assert!(content.contains("HERMETIC_FIRECRACKER_LOCK"));
    assert!(content.contains("HERMETIC_KERNEL"));
}

#[test]
fn test_pkg_smoke_script_permission_check_rejects_non_executable() {
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

fn check_taps_with_mode(required: bool) -> std::result::Result<(), String> {
    let agent_tap = std::env::var("HERMETIC_AGENT_TAP").unwrap_or_else(|_| "hwtap-agent".into());
    let net_tap = std::env::var("HERMETIC_NET_TAP").unwrap_or_else(|_| "hwtap-net".into());
    for tap in [&agent_tap, &net_tap] {
        if !std::path::Path::new(&format!("/sys/class/net/{tap}")).exists() {
            if required {
                return Err(format!("missing host tap {tap}"));
            }
            eprintln!("skipped: missing host tap {tap}");
            return Ok(());
        }
    }
    Ok(())
}

fn check_prerequisites_with_mode(required: bool) -> std::result::Result<(), String> {
    for name in ENV {
        if std::env::var(name).is_err() {
            if required {
                return Err(format!("missing required prerequisite: {name}"));
            }
            eprintln!("skipped: pkg guest test requires {}", name);
            return Ok(());
        }
    }
    if let Err(e) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        if required {
            return Err(format!("cannot open /dev/kvm: {e}"));
        }
        eprintln!("skipped: cannot open /dev/kvm: {e}");
        return Ok(());
    }
    check_taps_with_mode(required)
}

#[test]
fn test_pkg_guest_required_mode_fails_on_missing_tap() {
    let tap_name = "hwtap-nonexistent-unit-test";
    std::env::set_var("HERMETIC_AGENT_TAP", tap_name);
    // When required is false, check succeeds with Ok(()) after printing skipped
    let res_skip = check_taps_with_mode(false);
    assert!(res_skip.is_ok());

    // When required is true, check fails closed with Err
    let res_req = check_taps_with_mode(true);
    assert!(res_req.is_err());
    assert!(res_req.unwrap_err().contains(tap_name));
    std::env::remove_var("HERMETIC_AGENT_TAP");
}

fn ca_bootstrap(
    listener: &std::os::unix::net::UnixListener,
    material: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "CA bootstrap accept timed out",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    };
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "CA bootstrap write timed out before sending material",
        ));
    }
    stream.set_write_timeout(Some(remaining))?;
    use std::io::Write;
    stream.write_all(material)?;
    stream.flush()?;
    Ok(())
}

fn agent_vsock_socket_path(jail_root: &std::path::Path, vm_id: &str) -> std::path::PathBuf {
    jail_root.join(format!("firecracker/{vm_id}/root/vsock"))
}

#[test]
fn test_agent_vsock_socket_path_uses_firecracker_host_vsock() {
    let root = std::path::Path::new("/tmp/test_jail");
    let sock = agent_vsock_socket_path(root, "agent-123");
    assert_eq!(
        sock,
        std::path::PathBuf::from("/tmp/test_jail/firecracker/agent-123/root/vsock")
    );
    assert_ne!(
        sock,
        std::path::PathBuf::from("/tmp/test_jail/firecracker/agent-123/root/vsock_5000")
    );
}

#[test]
fn test_ca_handoff_deadline_expires_on_unconnected_listener() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let ca_socket = temp.path().join("test_ca.sock");
    let ca_listener = std::os::unix::net::UnixListener::bind(&ca_socket).unwrap();
    ca_listener.set_nonblocking(true).unwrap();

    let res = ca_bootstrap(&ca_listener, b"dummy material", Duration::from_millis(50));
    assert!(
        res.is_err(),
        "CA handoff accept loop must time out when NetVM never connects"
    );
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn pkg_guest_vm_serves_pkg_mirrors_to_agent() {
    #[cfg(feature = "dev-unjailed")]
    {
        let required = std::env::var("HERMETIC_TEST_REQUIRED").is_ok()
            || std::env::var("HERMETIC_PKG_GUEST_REQUIRED").is_ok();
        if let Err(e) = check_prerequisites_with_mode(required) {
            panic!("{e}");
        }
        if std::env::var(ENV[0]).is_err() {
            return;
        }
        let agent_tap =
            std::env::var("HERMETIC_AGENT_TAP").unwrap_or_else(|_| "hwtap-agent".into());
        if !std::path::Path::new(&format!("/sys/class/net/{agent_tap}")).exists() {
            return;
        }
        run();
    }
    #[cfg(not(feature = "dev-unjailed"))]
    {
        let required = std::env::var("HERMETIC_TEST_REQUIRED").is_ok()
            || std::env::var("HERMETIC_PKG_GUEST_REQUIRED").is_ok();
        if required {
            panic!("dev-unjailed feature is required");
        }
        eprintln!("skipped: build with --features dev-unjailed");
    }
}

#[cfg(feature = "dev-unjailed")]
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

#[cfg(feature = "dev-unjailed")]
fn python_launcher(f: &support::Fixture) -> String {
    let source = std::fs::canonicalize("/usr/bin/python3").expect("Python 3 interpreter required");
    let path = f.temp.path().join("exec-python");
    std::fs::copy(source, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    path.to_str().unwrap().into()
}

#[cfg(feature = "dev-unjailed")]
struct World(std::process::Child);
#[cfg(feature = "dev-unjailed")]
impl Drop for World {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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

    let work = std::path::Path::new(&v[7]);
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
        let mut bytes = Vec::new();
        let mut reader = std::io::BufReader::new(file);
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    };

    net_vm.start(Duration::from_secs(10)).unwrap();
    ca_bootstrap(&ca_listener, &material, Duration::from_secs(30)).expect("CA bootstrap failed");

    agent_vm.prepare(Duration::from_secs(120)).unwrap();
    agent_vm.start(Duration::from_secs(10)).unwrap();
    let agent_socket_path = agent_vsock_socket_path(agent.temp.path(), &agent.spec.id);
    let sock = agent_socket_path.to_str().unwrap();

    let ready = exec(sock, &["/bin/busybox", "true"]);
    assert_eq!(ready.code, Some(0));

    // Verify fetches from package mirrors
    let res = exec(
        sock,
        &[
            "/bin/hermetic-https-fetch",
            "https://pypi.org/simple/pkg-demo/index.html",
        ],
    );
    assert_eq!(res.code, Some(0));
    assert!(String::from_utf8_lossy(&res.output).contains("pkg_demo"));

    let res = exec(
        sock,
        &[
            "/bin/hermetic-https-fetch",
            "https://conda.anaconda.org/channel/linux-64/repodata.json",
        ],
    );
    assert_eq!(res.code, Some(0));
    assert!(String::from_utf8_lossy(&res.output).contains("repodata_version"));

    let res = exec(
        sock,
        &[
            "/bin/hermetic-https-fetch",
            "https://snapshot.ubuntu.com/ubuntu/20230301T000000Z/dists/jammy/InRelease",
        ],
    );
    assert_eq!(res.code, Some(0));

    let res = exec(
        sock,
        &[
            "/bin/hermetic-https-fetch",
            "https://github.com/example/demo.git/HEAD",
        ],
    );
    assert_eq!(res.code, Some(0));
    assert!(String::from_utf8_lossy(&res.output).contains("refs/heads/main"));
}
