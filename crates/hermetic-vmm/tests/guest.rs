//! Owner-run KVM tests. The default gate never invokes privileged operations.
mod support;
use hermetic_vmm::{api, deadline, runner::Runner, Error, Result, Vmm};
use serde::Deserialize;
use std::io::Write;
#[cfg(feature = "dev-unjailed")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const T_CLOCK: u64 = 1_700_000_000;
const MAX_STATUS_BYTES: u32 = 16 * 1024;
const MAX_HANDSHAKE_BYTES: usize = 64;
const CLOCK_TOLERANCE_SECONDS: u64 = 15;
#[derive(Debug, Deserialize)]
struct GuestStatus {
    #[serde(rename = "type")]
    kind: String,
    guest_time_unix: u64,
}
#[derive(Debug, Deserialize)]
struct GuestExec {
    #[serde(rename = "type")]
    kind: String,
    code: Option<i32>,
    output: Vec<u8>,
    truncated: bool,
    timed_out: bool,
}
fn guest_status(path: &str, end: Instant) -> Result<GuestStatus> {
    let stream = api::connect(path, end)?;
    guest_status_stream(stream, end)
}
fn guest_status_stream(
    stream: std::os::unix::net::UnixStream,
    end: Instant,
) -> Result<GuestStatus> {
    let body = guest_call(stream, br#"{"type":"status"}"#, end)?;
    serde_json::from_slice(&body).map_err(|_| Error::Protocol)
}
fn guest_exec(path: &str, argv: &[&str], end: Instant) -> Result<GuestExec> {
    let stream = api::connect(path, end)?;
    let request = serde_json::to_vec(&serde_json::json!({
        "type": "exec", "argv": argv, "tty": false, "timeout_ms": 5000
    }))
    .map_err(|_| Error::Protocol)?;
    let body = guest_call(stream, &request, end)?;
    serde_json::from_slice(&body).map_err(|_| Error::Protocol)
}
/// One execd request over Firecracker's host-initiated vsock handshake.
fn guest_call(
    mut stream: std::os::unix::net::UnixStream,
    request: &[u8],
    end: Instant,
) -> Result<Vec<u8>> {
    api::write_deadline(&mut stream, b"CONNECT 5000\n", end)?;
    let mut handshake = Vec::new();
    loop {
        let mut byte = [0];
        match api::read_exact_deadline(&mut stream, &mut byte, end) {
            // Firecracker closes the connection without a reply while no guest
            // listener is bound yet (execd still booting): retryable, not a
            // protocol violation.
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
    let reply = std::str::from_utf8(&handshake).map_err(|_| Error::Protocol)?;
    if reply
        .strip_prefix("OK ")
        .and_then(|s| s.trim_end_matches('\n').parse::<u32>().ok())
        .is_none()
    {
        return Err(Error::Protocol);
    }
    api::write_deadline(&mut stream, &(request.len() as u32).to_le_bytes(), end)?;
    api::write_deadline(&mut stream, request, end)?;
    let mut length = [0; 4];
    api::read_exact_deadline(&mut stream, &mut length, end)?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_STATUS_BYTES {
        return Err(Error::Protocol);
    }
    let mut body = vec![0; length as usize];
    api::read_exact_deadline(&mut stream, &mut body, end)?;
    Ok(body)
}
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
    // First boot goes through the trusted early-proc shim, which execs execd as PID 1.
    f.spec.boot_args = f
        .spec
        .boot_args
        .replace("init=/sbin/hermetic-execd", "init=/sbin/hermetic-init");
    f.spec.networks.clear();
    // An empty ext4 upper disk, built without mounting anything on the host.
    // The host must provide the project's pinned e2fsprogs >=1.47.1.
    let overlay = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&f.spec.drives[0].path)
        .unwrap();
    overlay.set_len(64 * 1024 * 1024).unwrap();
    let mut child = Command::new("/usr/sbin/mke2fs")
        .args([
            "-q",
            "-t",
            "ext4",
            "-F",
            "-U",
            "00000000-0000-0000-0000-000000000001",
            "-E",
            "hash_seed=00000000-0000-0000-0000-000000000002,lazy_itable_init=0,lazy_journal_init=0",
        ])
        .arg(&f.spec.drives[0].path)
        .env_clear()
        .env("SOURCE_DATE_EPOCH", T_CLOCK.to_string())
        .env("E2FSPROGS_FAKE_TIME", T_CLOCK.to_string())
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("mke2fs required for empty overlay fixture");
    let end = deadline(Duration::from_secs(30)).unwrap();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "overlay fixture creation failed");
            break;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("overlay fixture deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::set_permissions(
        &f.spec.drives[0].path,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    Some(f)
}
fn python_launcher(f: &support::Fixture) -> String {
    let source = std::fs::canonicalize("/usr/bin/python3").expect("Python 3 interpreter required");
    let path = f.temp.path().join("exec-python");
    std::fs::copy(source, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    path.to_str().unwrap().into()
}
fn boot<R: Runner>(f: support::Fixture, runner: R) {
    let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), runner);
    vm.prepare(Duration::from_secs(120)).unwrap();
    vm.start(Duration::from_secs(10)).unwrap();
    vm.wait_ready(Duration::from_secs(30)).unwrap();
    let end = deadline(Duration::from_secs(30)).unwrap();
    let socket = vm.jail().unwrap().root.descriptor_path("vsock");
    let status = loop {
        match guest_status(&socket, end) {
            Ok(s) => break s,
            Err(Error::Io) => {
                assert!(Instant::now() < end, "execd readiness deadline");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("execd status failed: {e}"),
        }
    };
    assert_eq!(status.kind, "status");
    assert!(
        status.guest_time_unix.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS,
        "guest clock outside T_clock tolerance"
    );
    eprintln!("guest status: guest_time_unix={}", status.guest_time_unix);
    // One trivial command through execd; static busybox is in the smoke rootfs.
    let exec = guest_exec(&socket, &["/bin/busybox", "echo", "hermetic-ok"], end)
        .expect("execd exec failed");
    assert_eq!(exec.kind, "exec");
    assert_eq!(exec.code, Some(0));
    assert!(!exec.truncated && !exec.timed_out);
    assert_eq!(exec.output, b"hermetic-ok\n");
    // The command's view of the clock is the faked boot clock, not the host's.
    let date = guest_exec(&socket, &["/bin/busybox", "date", "-u", "+%s"], end)
        .expect("execd exec failed");
    let seconds: u64 = std::str::from_utf8(&date.output)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .expect("date output");
    assert!(seconds.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS);
    eprintln!(
        "guest exec: output={:?} date={seconds}",
        String::from_utf8_lossy(&exec.output)
    );
    // This intentionally verifies forced stop rather than execd's graceful
    // freeze protocol, which belongs to the caller/guest integration.
    vm.stop(Duration::from_secs(2)).unwrap();
    vm.destroy(Duration::from_secs(10)).unwrap();
}
#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and execd rootfs; see README"]
fn boots_guest_and_reads_guest_clock() {
    #[cfg(feature = "dev-unjailed")]
    {
        if let Some(f) = environment() {
            let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
            boot(f, runner);
        }
    }
    #[cfg(not(feature = "dev-unjailed"))]
    {
        eprintln!("skipped: build with --features dev-unjailed and set HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_ROOTFS");
    }
}

/// Boot once, poison disk PID 1 candidates and execd, freeze the upper, then
/// boot a copy with a trusted initrd. No touched executable may run before the
/// host explicitly authorizes the new PID 1.
#[cfg(feature = "dev-unjailed")]
#[test]
#[ignore = "needs /dev/kvm and pinned inputs; run scripts/integration/reboot-smoke.sh"]
fn reboots_touched_disk_with_trusted_initramfs() {
    use hermetic_vmm::spec::Initrd;
    use sha2::{Digest, Sha256};
    fn call(socket: &str, request: serde_json::Value, end: Instant) -> serde_json::Value {
        let bytes = serde_json::to_vec(&request).unwrap();
        let reply = guest_call(api::connect(socket, end).unwrap(), &bytes, end).unwrap();
        serde_json::from_slice(&reply).unwrap()
    }
    fn ready(vm: &Vmm<hermetic_vmm::runner::DevUnjailed>) -> (String, serde_json::Value) {
        let socket = vm.jail().unwrap().root.descriptor_path("vsock");
        let end = deadline(Duration::from_secs(30)).unwrap();
        loop {
            match guest_status(&socket, end) {
                Ok(status) => {
                    assert!(status.guest_time_unix.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS);
                    return (
                        socket.clone(),
                        call(&socket, serde_json::json!({"type":"status"}), end),
                    );
                }
                Err(Error::Io) => {
                    assert!(Instant::now() < end, "execd readiness deadline");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("execd readiness: {e}"),
            }
        }
    }
    let first = environment().expect("smoke requires pinned Firecracker, kernel and rootfs");
    let archive = std::env::var("HERMETIC_INITRD").expect("HERMETIC_INITRD");
    let pin = std::env::var("HERMETIC_INITRD_SHA256").expect("HERMETIC_INITRD_SHA256");
    let mut reboot = support::Fixture::new();
    reboot.spec.jail.firecracker = first.spec.jail.firecracker.clone();
    reboot.spec.kernel_image = first.spec.kernel_image.clone();
    reboot.spec.root_drive.path = first.spec.root_drive.path.clone();
    reboot.spec.networks.clear();
    reboot.spec.boot_args = first
        .spec
        .boot_args
        .replace("init=/sbin/hermetic-init", "hermetic.initramfs=1");
    reboot.spec.initrd = Some(Initrd {
        path: archive,
        sha256: pin,
    });
    let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&first)).unwrap();
    let mut vm = Vmm::new(first.spec.clone().validate().unwrap(), runner);
    vm.prepare(Duration::from_secs(120)).unwrap();
    vm.start(Duration::from_secs(10)).unwrap();
    vm.wait_ready(Duration::from_secs(30)).unwrap();
    let (socket, status) = ready(&vm);
    assert_eq!(status["locked"], false);
    let end = deadline(Duration::from_secs(30)).unwrap();
    for path in [
        "/sbin/hermetic-init",
        "/sbin/hermetic-execd",
        "/sbin/init",
        "/init",
        "/work/reboot-proof",
    ] {
        assert_eq!(
            call(
                &socket,
                serde_json::json!({"type":"upload","path":path,"data":b"touched-disk".to_vec()}),
                end
            )["type"],
            "ok"
        );
    }
    let spec = br#"{"env":{"PATH":"/bin","LANG":"C"},"workdir":"/work","uid":0,"gid":0,"entrypoint":["/bin/busybox","touch","/work/unauthorized"],"command":[],"hostname":"world","resolv_conf":"nameserver 10.0.0.1\n","resources":{"vcpus":1,"memory_mib":256,"disk_mib":64,"wall_time_s":60}}"#;
    assert_eq!(
        call(
            &socket,
            serde_json::json!({"type":"upload", "path":"/etc/hermetic/run-spec.json", "data":spec.to_vec()}),
            end
        )["type"],
        "ok"
    );
    assert_eq!(
        call(&socket, serde_json::json!({"type":"shutdown"}), end)["type"],
        "frozen"
    );
    vm.stop(Duration::from_secs(2)).unwrap();
    let touched = vm.jail().unwrap().root.descriptor_path("drive-overlay");
    std::fs::copy(touched, &reboot.spec.drives[0].path).unwrap();
    vm.destroy(Duration::from_secs(10)).unwrap();

    let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&reboot)).unwrap();
    let mut vm = Vmm::new(reboot.spec.clone().validate().unwrap(), runner);
    vm.prepare(Duration::from_secs(120)).unwrap();
    vm.start(Duration::from_secs(10)).unwrap();
    vm.wait_ready(Duration::from_secs(30)).unwrap();
    let (socket, status) = ready(&vm);
    assert_eq!(status["locked"], true);
    let end = deadline(Duration::from_secs(30)).unwrap();
    let denied = call(
        &socket,
        serde_json::json!({"type":"exec","argv":["/bin/busybox","true"],"tty":false,"timeout_ms":1000}),
        end,
    );
    assert_eq!(
        denied,
        serde_json::json!({"type":"error","reason":"locked"})
    );
    let marker = call(
        &socket,
        serde_json::json!({"type":"download","path":"/work/reboot-proof"}),
        end,
    );
    assert_eq!(marker["data"], serde_json::json!(b"touched-disk".to_vec()));
    assert_eq!(
        call(
            &socket,
            serde_json::json!({"type":"download","path":"/work/unauthorized"}),
            end
        )["type"],
        "error"
    );
    assert_eq!(
        call(&socket, serde_json::json!({"type":"authorize"}), end)["type"],
        "ok"
    );
    let exec = guest_exec(&socket, &["/bin/busybox", "echo", "trusted-reboot-ok"], end).unwrap();
    assert_eq!(exec.code, Some(0));
    assert_eq!(exec.output, b"trusted-reboot-ok\n");
    // This child helper must come from the initramfs: disk execd was poisoned.
    assert_eq!(
        call(
            &socket,
            serde_json::json!({"type":"download","path":"/sbin/hermetic-execd"}),
            end
        )["data"],
        serde_json::json!(b"touched-disk".to_vec())
    );
    let record = serde_json::to_vec(vm.boot_record().unwrap()).unwrap();
    assert_eq!(vm.boot_record().unwrap().boot_path, "trusted_initramfs");
    let output = std::env::var("HERMETIC_REBOOT_RECORD_OUT").expect("HERMETIC_REBOOT_RECORD_OUT");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .unwrap();
    file.write_all(&record).unwrap();
    file.sync_all().unwrap();
    // The pin recorded by the host is exactly the staged archive's digest.
    let staged = std::fs::read(vm.jail().unwrap().root.descriptor_path("initrd")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(staged)),
        vm.boot_record()
            .unwrap()
            .initrd_sha256
            .as_ref()
            .unwrap()
            .as_str()
    );
    assert_eq!(
        call(&socket, serde_json::json!({"type":"shutdown"}), end)["type"],
        "frozen"
    );
    vm.stop(Duration::from_secs(2)).unwrap();
    vm.destroy(Duration::from_secs(10)).unwrap();
    eprintln!("trusted reboot: touched disk, locked startup, authorization, trusted child helper, boot record passed");
}
/// The guest serial line `grader-init SECONDS clock`, printed right after the
/// grader PID 1 sets the clock.
fn grader_clock_line(serial: &[u8]) -> Option<u64> {
    String::from_utf8_lossy(serial).lines().find_map(|line| {
        let mut words = line.trim_end_matches('\r').split(' ');
        match (words.next(), words.next(), words.next(), words.next()) {
            (Some("grader-init"), Some(t), Some("clock"), None) => t.parse().ok(),
            _ => None,
        }
    })
}
#[test]
fn grader_clock_line_is_strict() {
    assert_eq!(
        grader_clock_line(b"[ 0.1] x\r\ngrader-init 1700000000 clock\r\n"),
        Some(T_CLOCK)
    );
    for bad in [
        &b"grader-init 1700000000 done\n"[..],
        b"x grader-init 1700000000 clock\n",
        b"grader-init 17x clock\n",
        b"grader-init 1700000000 clock extra\n",
    ] {
        assert_eq!(grader_clock_line(bad), None);
    }
}
/// Host-only HGRL v1 input, identical layout/size for every run. Never placed in
/// boot arguments, VM identity, rootfs or any sandbox-visible descriptor.
fn grader_run_input(run: &str) -> Option<Vec<u8>> {
    if !matches!(run, "R0" | "R1" | "R2" | "R3") {
        return None;
    }
    let mut image = b"HGRL\0\x01".to_vec();
    image.extend_from_slice(run.as_bytes());
    image.resize(1024 * 1024, 0);
    Some(image)
}

#[test]
fn grader_run_input_known_answer_and_strict_labels() {
    for run in ["R0", "R1", "R2", "R3"] {
        let image = grader_run_input(run).unwrap();
        assert_eq!(image.len() as u64, hermetic_vmm::spec::GRADER_RESULT_BYTES);
        assert_eq!(&image[..6], b"HGRL\0\x01");
        assert_eq!(&image[6..8], run.as_bytes());
        assert!(image[8..].iter().all(|b| *b == 0));
    }
    for bad in ["", "R4", "r0", "R0\n", "R0 secret", "R0\0"] {
        assert!(grader_run_input(bad).is_none());
    }
}

/// Preserve bounded development console diagnostics before reporting failure.
fn grader_exit_result(
    result: Result<()>,
    console: impl FnOnce() -> (Vec<u8>, Vec<u8>),
    report: &mut impl Write,
) -> Result<()> {
    if result.is_err() {
        // wait_exit kills the VM on failure. console_output retains both
        // bounded captures after cleanup, unlike serial().
        let (serial, errors) = console();
        for (name, bytes) in [("serial", serial), ("stderr", errors)] {
            let capped = bytes
                .get(..bytes.len().min(hermetic_vmm::runner::MAX_CAPTURE_BYTES))
                .unwrap_or_default();
            for line in String::from_utf8_lossy(capped).lines() {
                let _ = writeln!(report, "grader timeout: {name}: {line}");
            }
        }
    }
    result
}

/// Boots a grader image with `init=/sbin/hermetic-grader-init` (no vsock, no
/// network), waits for the guest to power off, checks the guest clock line and
/// copies the 1 MiB result drive to HERMETIC_GRADER_RESULT_OUT for the host verdict.
#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and a grader image; see README"]
fn boots_grader_and_collects_result_drive() {
    #[cfg(feature = "dev-unjailed")]
    {
        let mut vars = Vec::new();
        for name in [
            "HERMETIC_FC_BIN",
            "HERMETIC_KERNEL",
            "HERMETIC_GRADER_ROOTFS",
            "HERMETIC_GRADER_RESULT_OUT",
        ] {
            match std::env::var(name) {
                Ok(value) => vars.push(value),
                Err(_) => {
                    eprintln!("skipped: set HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_GRADER_ROOTFS and HERMETIC_GRADER_RESULT_OUT");
                    return;
                }
            }
        }
        let mut f = support::Fixture::grader();
        let run = std::env::var("HERMETIC_GRADER_RUN").expect("set HERMETIC_GRADER_RUN");
        let input = grader_run_input(&run).expect("invalid grader run label");
        std::fs::write(&f.spec.drives[0].path, input).unwrap();
        f.spec.jail.firecracker = vars[0].clone();
        f.spec.kernel_image = vars[1].clone();
        f.spec.root_drive.path = vars[2].clone();
        f.spec.reserved_drives.clear();
        f.spec.memory_mib = 1024;
        f.spec.boot_args = concat!(
            "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda ",
            "init=/sbin/hermetic-grader-init clocksource=tsc tsc=reliable ",
            "hermetic.t=1700000000 ro"
        )
        .into();
        let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
        let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), runner);
        vm.prepare(Duration::from_secs(120)).unwrap();
        vm.start(Duration::from_secs(10)).unwrap();
        vm.wait_ready(Duration::from_secs(30)).unwrap();
        grader_exit_result(
            vm.wait_exit(Duration::from_secs(300)),
            || vm.runner().console_output(),
            &mut std::io::stderr(),
        )
        .expect("grader VM did not power off");
        let serial = vm.runner().serial();
        let guest = grader_clock_line(&serial).expect("grader-init clock line on serial");
        eprintln!("grader serial: grader-init clock={guest}");
        assert!(
            guest >= T_CLOCK && guest - T_CLOCK <= CLOCK_TOLERANCE_SECONDS,
            "grader clock outside T_clock tolerance"
        );
        let drive = vm.jail().unwrap().root.descriptor_path("drive-result");
        let image = std::fs::read(drive).unwrap();
        assert_eq!(image.len(), 1024 * 1024);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&vars[3])
            .unwrap();
        out.write_all(&image).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
    }
    #[cfg(not(feature = "dev-unjailed"))]
    {
        eprintln!("skipped: build with --features dev-unjailed");
    }
}

#[test]
fn grader_exit_timeout_retains_bounded_serial_and_errors_after_cleanup() {
    let mut report = Vec::new();
    let serial = b"tsc: Unable to calibrate against PIT\ngrader-init 1700000000 clock\n";
    assert_eq!(
        grader_exit_result(
            Err(Error::Step("wait-exit")),
            || (serial.to_vec(), b"VMM failure\n".to_vec()),
            &mut report,
        ),
        Err(Error::Step("wait-exit"))
    );
    assert_eq!(
        report,
        b"grader timeout: serial: tsc: Unable to calibrate against PIT\ngrader timeout: serial: grader-init 1700000000 clock\ngrader timeout: stderr: VMM failure\n"
    );
    report.clear();
    assert!(grader_exit_result(
        Err(Error::Step("wait-exit")),
        || (
            vec![b'x'; hermetic_vmm::runner::MAX_CAPTURE_BYTES + 1],
            Vec::new()
        ),
        &mut report,
    )
    .is_err());
    assert_eq!(
        report.len(),
        b"grader timeout: serial: \n".len() + hermetic_vmm::runner::MAX_CAPTURE_BYTES
    );
    report.clear();
    assert_eq!(
        grader_exit_result(
            Ok(()),
            || panic!("successful exit needs no diagnostics"),
            &mut report
        ),
        Ok(())
    );
    assert!(report.is_empty());
}
#[test]
#[ignore = "owner only: root, cgroup v2 cpu/memory/pids delegation, preconfigured isolated netns/taps, /dev/kvm, and pinned jailer/Firecracker; see README"]
fn jailer_boots_in_isolated_namespace() {
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: jailer integration requires owner-provided root environment");
        return;
    }
    let Some(mut f) = environment() else {
        return;
    };
    let (Ok(jailer), Ok(netns)) = (
        std::env::var("HERMETIC_JAILER_BIN"),
        std::env::var("HERMETIC_NETNS"),
    ) else {
        eprintln!("skipped: set HERMETIC_JAILER_BIN and HERMETIC_NETNS");
        return;
    };
    f.spec.jail.jailer = jailer;
    f.spec.jail.netns = netns;
    let runner = hermetic_vmm::runner::JailerRunner::new(&python_launcher(&f)).unwrap();
    boot(f, runner);
}
#[test]
fn guest_status_frame_known_answer_and_cap() {
    // A fake vsock backend is a Unix listener; no guest or KVM is required.
    for oversized in [false, true] {
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let join = std::thread::spawn(move || {
            use std::io::Read;
            let mut s = std::fs::File::from(std::os::fd::OwnedFd::from(server));
            let mut hello = [0; 13];
            s.read_exact(&mut hello).unwrap();
            assert_eq!(&hello, b"CONNECT 5000\n");
            s.write_all(b"OK 5000\n").unwrap();
            let mut len = [0; 4];
            s.read_exact(&mut len).unwrap();
            assert_eq!(u32::from_le_bytes(len), 17);
            let mut body = [0; 17];
            s.read_exact(&mut body).unwrap();
            assert_eq!(&body, br#"{"type":"status"}"#);
            if oversized {
                s.write_all(&(MAX_STATUS_BYTES + 1).to_le_bytes()).unwrap();
            } else {
                let response = br#"{"type":"status","guest_time_unix":1700000000}"#;
                s.write_all(&(response.len() as u32).to_le_bytes()).unwrap();
                s.write_all(response).unwrap();
            }
        });
        let reply = guest_status_stream(client, deadline(Duration::from_secs(1)).unwrap());
        if oversized {
            assert!(reply.is_err());
        } else {
            assert_eq!(reply.unwrap().guest_time_unix, T_CLOCK);
        }
        join.join().unwrap();
    }
}
#[test]
fn guest_not_yet_listening_is_retryable() {
    // Regression: Firecracker answers CONNECT to an unbound guest port by closing
    // the stream. That must be retried by the readiness loop, not fail the boot.
    let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
    let join = std::thread::spawn(move || {
        use std::io::Read;
        let mut s = server;
        let mut hello = [0; 13];
        s.read_exact(&mut hello).unwrap();
        drop(s);
    });
    let reply = guest_status_stream(client, deadline(Duration::from_secs(1)).unwrap());
    assert!(matches!(reply, Err(Error::Io)));
    join.join().unwrap();
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LockdownRecord {
    probe: String,
    result: String,
    detail: String,
}
fn lockdown_reply_passes(reply: &GuestExec) -> bool {
    if reply.kind != "exec" || reply.code != Some(0) || reply.truncated || reply.timed_out {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&reply.output) else {
        return false;
    };
    let mut names = std::collections::BTreeSet::new();
    for line in text.lines().take(3) {
        let Ok(record) = serde_json::from_str::<LockdownRecord>(line) else {
            return false;
        };
        if record.result != "blocked"
            || record.detail.is_empty()
            || !matches!(record.probe.as_str(), "module_load" | "ring0_paths")
            || !names.insert(record.probe)
        {
            return false;
        }
    }
    names.len() == 2
}

#[test]
fn lockdown_vm_reply_requires_both_probes_blocked_and_complete() {
    let module = r#"{"probe":"module_load","result":"blocked","detail":"compiled out"}"#;
    let ring0 = r#"{"probe":"ring0_paths","result":"blocked","detail":"sealed"}"#;
    let good = format!("{module}\n{ring0}\n");
    let mut reply = GuestExec {
        kind: "exec".into(),
        code: Some(0),
        output: good.as_bytes().to_vec(),
        truncated: false,
        timed_out: false,
    };
    assert!(lockdown_reply_passes(&reply));
    for bad in [
        module.to_string(),
        format!("{module}\n{module}\n"),
        good.replace("blocked", "unavailable"),
        good.replace("blocked", "error"),
        good.replace("blocked", "leak"),
        format!("{good}{module}\n"),
        format!("{good}bad\n"),
    ] {
        reply.output = bad.into_bytes();
        assert!(!lockdown_reply_passes(&reply));
    }
    reply.output = good.into_bytes();
    reply.code = Some(2);
    assert!(!lockdown_reply_passes(&reply));
    reply.code = Some(0);
    reply.truncated = true;
    assert!(!lockdown_reply_passes(&reply));
    reply.truncated = false;
    reply.timed_out = true;
    assert!(!lockdown_reply_passes(&reply));
}

#[test]
#[ignore = "needs dev-unjailed, KVM and sealed probe/config in rootfs; use HERMETIC_LOCKDOWN_CONFIG with boot-smoke.sh"]
fn boots_guest_and_checks_root_lockdown() {
    #[cfg(feature = "dev-unjailed")]
    {
        let f = environment().expect("lockdown smoke requires pinned VM inputs");
        let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
        let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), runner);
        vm.prepare(Duration::from_secs(120)).unwrap();
        vm.start(Duration::from_secs(10)).unwrap();
        vm.wait_ready(Duration::from_secs(30)).unwrap();
        let end = deadline(Duration::from_secs(30)).unwrap();
        let socket = vm.jail().unwrap().root.descriptor_path("vsock");
        loop {
            match guest_status(&socket, end) {
                Ok(status) => {
                    assert_eq!(status.kind, "status");
                    break;
                }
                Err(Error::Io) => {
                    assert!(Instant::now() < end, "execd readiness deadline");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("execd readiness: {e}"),
            }
        }
        let mount = guest_exec(
            &socket,
            &[
                "/bin/busybox",
                "mount",
                "-t",
                "securityfs",
                "securityfs",
                "/sys/kernel/security",
            ],
            end,
        )
        .unwrap();
        assert_eq!(mount.code, Some(0), "securityfs mount failed");
        assert!(!mount.truncated && !mount.timed_out);
        let reply = guest_exec(
            &socket,
            &["/sbin/hermetic-clockprobe", "--lockdown-only"],
            end,
        )
        .unwrap();
        eprintln!(
            "clockprobe code={:?} truncated={} timed_out={} output:\n{}",
            reply.code,
            reply.truncated,
            reply.timed_out,
            String::from_utf8_lossy(&reply.output[..reply.output.len().min(4096)])
        );
        assert!(
            lockdown_reply_passes(&reply),
            "module_load and ring0_paths must both report blocked"
        );
        vm.stop(Duration::from_secs(2)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
    }
    #[cfg(not(feature = "dev-unjailed"))]
    panic!("lockdown smoke requires dev-unjailed feature");
}
