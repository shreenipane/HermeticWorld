#![cfg(feature = "dev-unjailed")]
//! Owner-run offline harness smoke. The ordinary gate never starts a VM.
#[path = "support/agent_h.rs"]
mod diagnostics;
mod support;
use hermetic_vmm::{api, deadline, Vmm};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_RPC_BYTES: u32 = 16 * 1024;
const MAX_HANDSHAKE_BYTES: usize = 64;

fn call(socket: &str, request: &[u8], end: Instant) -> hermetic_vmm::Result<serde_json::Value> {
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
        return Err(hermetic_vmm::Error::Protocol);
    }
    api::write_deadline(&mut stream, &(request.len() as u32).to_le_bytes(), end)?;
    api::write_deadline(&mut stream, request, end)?;
    let mut length = [0; 4];
    api::read_exact_deadline(&mut stream, &mut length, end)?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_RPC_BYTES {
        return Err(hermetic_vmm::Error::Protocol);
    }
    let mut raw = vec![0; length as usize];
    api::read_exact_deadline(&mut stream, &mut raw, end)?;
    serde_json::from_slice(&raw).map_err(|_| hermetic_vmm::Error::Protocol)
}

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

#[test]
#[ignore = "owner-run KVM smoke; see scripts/integration/agent-h-smoke.sh"]
fn boots_agent_runs_harness_and_collects_untrusted_extraction() {
    // Required inputs fail explicitly; an unconfigured smoke must never appear to pass.
    let required = |key| std::env::var(key).expect("missing smoke input");
    let work = required("HERMETIC_AGENT_WORK");
    let python = required("HERMETIC_AGENT_PYTHON");
    let manifest = required("HERMETIC_AGENT_MANIFEST");
    let top = required("HERMETIC_AGENT_TOP");
    let clock: i64 = required("HERMETIC_AGENT_T_CLOCK").parse().unwrap();
    let mut fixture = support::Fixture::new();
    fixture.spec.jail.firecracker = required("HERMETIC_FC_BIN");
    fixture.spec.kernel_image = required("HERMETIC_KERNEL");
    fixture.spec.root_drive.path = required("HERMETIC_ROOTFS");
    fixture.spec.networks.clear();
    fixture.spec.boot_args = fixture
        .spec
        .boot_args
        .replace("hermetic.t=1700000000", &format!("hermetic.t={clock}"))
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-init");
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
        // /proc/self/fd paths are meaningful only in the Vmm process. Keep its pinned directory
        // descriptor open and address it from the child through the parent's pid.
        let socket = socket.replacen("/proc/self/", &format!("/proc/{}/", std::process::id()), 1);
        let mut harness = Command::new(&python)
            .arg(format!("{top}/scripts/integration/agent_h_smoke.py"))
            .args(["--vsock", &socket, "--manifest", &manifest, "--work", &work])
            .env_clear()
            .env("PYTHONPATH", format!("{top}/python"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        finish(&mut harness, Duration::from_secs(240));
        let end = deadline(Duration::from_secs(10)).unwrap();
        // Graceful shutdown freezes the upper before power-off. Validation runs after teardown.
        let frozen = call(&socket, br#"{"type":"shutdown"}"#, end).unwrap();
        assert_eq!(frozen["type"], "frozen");
        vm.stop(Duration::from_secs(10)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
        Ok(())
    })
    .unwrap();
    let mut stream = std::fs::File::open(format!("{work}/changes.hext"))
        .unwrap()
        .take(1024 * 1024 + 1);
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    assert!(raw.len() <= 1024 * 1024 && raw.starts_with(b"HEXT"));
    std::io::stdout()
        .write_all(b"agent VM harness: ok\n")
        .unwrap();
}
