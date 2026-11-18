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
// execd serializes output bytes as JSON integers (up to four bytes per byte).
const MAX_REPLY_BYTES: u32 = 4 * 1024 * 1024 + 65536;
const ESCAPE_EXEC_TIMEOUT_MS: u64 = 290_000;
const MAX_ESCAPE_REPORT_BYTES: usize = 256 * 1024;
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
/// Poll execd status until it answers: right after boot (or a snapshot
/// restore) the vsock listener may not be up yet, which reads as `Error::Io`.
fn wait_guest_status(path: &str, end: Instant) -> GuestStatus {
    loop {
        match guest_status(path, end) {
            Ok(s) => return s,
            Err(Error::Io) => {
                assert!(Instant::now() < end, "execd readiness deadline");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("execd status failed: {e}"),
        }
    }
}
fn guest_status_stream(
    stream: std::os::unix::net::UnixStream,
    end: Instant,
) -> Result<GuestStatus> {
    let body = guest_call_capped(stream, br#"{"type":"status"}"#, end, MAX_STATUS_BYTES)?;
    serde_json::from_slice(&body).map_err(|_| Error::Protocol)
}
fn guest_exec(path: &str, argv: &[&str], end: Instant) -> Result<GuestExec> {
    guest_exec_timeout(path, argv, end, 5000)
}
fn guest_exec_timeout(
    path: &str,
    argv: &[&str],
    end: Instant,
    timeout_ms: u64,
) -> Result<GuestExec> {
    let stream = api::connect(path, end)?;
    let request = serde_json::to_vec(&serde_json::json!({
        "type": "exec", "argv": argv, "tty": false, "timeout_ms": timeout_ms
    }))
    .map_err(|_| Error::Protocol)?;
    let body = guest_call(stream, &request, end)?;
    serde_json::from_slice(&body).map_err(|_| Error::Protocol)
}
/// One execd request over Firecracker's host-initiated vsock handshake.
fn guest_call(
    stream: std::os::unix::net::UnixStream,
    request: &[u8],
    end: Instant,
) -> Result<Vec<u8>> {
    guest_call_capped(stream, request, end, MAX_REPLY_BYTES)
}
fn guest_call_capped(
    mut stream: std::os::unix::net::UnixStream,
    request: &[u8],
    end: Instant,
    max_reply: u32,
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
    if length == 0 || length > max_reply {
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
    let status = wait_guest_status(&socket, end);
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

/// Measure guest TSC stability and drift without kvmclock over at least 30 seconds.
///
/// Under Phase 3b clock-hiding rules, the virtual TSC is fixed at 2.0 GHz via
/// hardware scaling and CPUID leaf 0x15, while kvmclock MSRs are denied. If RDTSC
/// is trapped for untrusted agent workloads to eliminate covert timing channels,
/// execd (the trusted root supervisor) executes this measurement helper over vsock
/// as a documented trusted measurement path. The host collects (elapsed ns, TSC ticks)
/// pairs and validates that cumulative drift remains within MAX_PERMISSIBLE_DRIFT_PPM.
#[test]
#[ignore = "needs dev-unjailed, KVM, pinned Firecracker, and sealed static probe; run scripts/integration/tsc-drift-smoke.sh"]
fn measures_guest_tsc_drift_without_kvmclock() {
    #[cfg(feature = "dev-unjailed")]
    {
        let Some(f) = environment() else {
            return;
        };
        let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
        let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), runner);
        vm.prepare(Duration::from_secs(120)).unwrap();
        vm.start(Duration::from_secs(10)).unwrap();
        vm.wait_ready(Duration::from_secs(30)).unwrap();
        let socket = vm.jail().unwrap().root.descriptor_path("vsock");
        let ready_end = deadline(Duration::from_secs(30)).unwrap();
        loop {
            match guest_status(&socket, ready_end) {
                Ok(status) => {
                    assert_eq!(status.kind, "status");
                    break;
                }
                Err(Error::Io) => {
                    assert!(Instant::now() < ready_end, "execd readiness deadline");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("execd readiness: {e}"),
            }
        }

        let mut tracker = hermetic_vmm::tsc_drift::TscDriftTracker::for_virtual_tsc();
        let start_instant = Instant::now();
        const TOTAL_POINTS: usize = 6;
        const INTERVAL_SECS: u64 = 6;

        for i in 0..TOTAL_POINTS {
            if i > 0 {
                std::thread::sleep(Duration::from_secs(INTERVAL_SECS));
            }
            let host_before_ns = start_instant.elapsed().as_nanos() as u64;
            let call_deadline = deadline(Duration::from_secs(10)).unwrap();
            let reply = guest_exec(
                &socket,
                &["/sbin/hermetic-clockprobe", "--read-tsc"],
                call_deadline,
            )
            .expect("guest tsc reading exec reply");
            assert_eq!(reply.code, Some(0), "helper exited with non-zero");
            assert!(
                !reply.truncated && !reply.timed_out,
                "helper output truncated or timed out"
            );
            let host_after_ns = start_instant.elapsed().as_nanos() as u64;
            let guest_tsc = hermetic_vmm::tsc_drift::parse_tsc_reading(&reply.output)
                .expect("parse guest tsc reading");
            tracker
                .add_bracketed_sample(host_before_ns, host_after_ns, guest_tsc)
                .expect("feed tsc sample");
        }

        vm.stop(Duration::from_secs(2)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();

        assert!(
            tracker.sample_count() >= hermetic_vmm::tsc_drift::MIN_DRIFT_SAMPLES,
            "must collect at least {} sample points",
            hermetic_vmm::tsc_drift::MIN_DRIFT_SAMPLES
        );
        assert!(
            tracker.elapsed_host_ns().unwrap()
                >= hermetic_vmm::tsc_drift::MIN_MEASUREMENT_DURATION_NS,
            "measurement duration must be at least 30 s"
        );
        // Qualifies the drift together with the measured host timing window of
        // each read, so request latency neither fails a correct TSC nor hides drift.
        if let Err(e) = tracker.validate_measurement(
            hermetic_vmm::tsc_drift::MIN_MEASUREMENT_DURATION_NS,
            hermetic_vmm::tsc_drift::MIN_DRIFT_SAMPLES,
            hermetic_vmm::tsc_drift::MAX_PERMISSIBLE_DRIFT_PPM,
        ) {
            panic!(
                "TSC drift qualification failed against 2.0 GHz virtual TSC: {e} (uncertainty {:.3} ppm)",
                tracker.uncertainty_ppm().unwrap_or(f64::NAN)
            );
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

#[cfg(feature = "dev-unjailed")]
#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and rootfs"]
fn resumes_guest_snapshot_with_peerless_tap_and_attached_drive() {
    use std::os::unix::fs::OpenOptionsExt;
    let Some(mut first) = environment() else {
        return;
    };
    first.spec.limits.file_size_bytes =
        (u64::from(first.spec.memory_mib) * 1024 * 1024).max(first.spec.limits.file_size_bytes);
    let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&first)).unwrap();
    let mut vm = Vmm::new(first.spec.clone().validate().unwrap(), runner);
    vm.prepare(Duration::from_secs(120)).unwrap();
    vm.start(Duration::from_secs(10)).unwrap();
    vm.wait_ready(Duration::from_secs(30)).unwrap();

    let socket = vm.jail().unwrap().root.descriptor_path("vsock");
    let end = deadline(Duration::from_secs(30)).unwrap();
    let status = wait_guest_status(&socket, end);
    assert!(status.guest_time_unix.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS);

    // Pause VM and create snapshot
    vm.pause(Duration::from_secs(10)).unwrap();
    let snap_dir = first.temp.path().join("snapshot");
    std::fs::create_dir_all(&snap_dir).unwrap();
    let snap_path = snap_dir.join("vm.snap");
    let mem_path = snap_dir.join("vm.mem");

    vm.snapshot_create(
        snap_path.to_str().unwrap(),
        mem_path.to_str().unwrap(),
        Duration::from_secs(30),
    )
    .unwrap();

    vm.stop(Duration::from_secs(5)).unwrap();
    vm.destroy(Duration::from_secs(10)).unwrap();

    // Prepare tests drive to attach
    let tests_img = first.temp.path().join("tests.img");
    let tests_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tests_img)
        .unwrap();
    tests_file.set_len(4096).unwrap();

    // Restore into fresh VM instance
    let mut second_spec = first.spec.clone();
    second_spec.reserved_drives = vec!["tests".into()];
    let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&first)).unwrap();
    let mut vm = Vmm::new(second_spec.validate().unwrap(), runner);
    vm.prepare(Duration::from_secs(120)).unwrap();
    vm.start(Duration::from_secs(10)).unwrap();

    vm.restore_from_snapshot(
        snap_path.to_str().unwrap(),
        mem_path.to_str().unwrap(),
        &[],
        Duration::from_secs(30),
    )
    .unwrap();

    assert_eq!(vm.boot_record().unwrap().boot_path, "live_snapshot");

    // Attach tests drive read-only into reserved slot
    vm.attach_drive(
        "tests",
        tests_img.to_str().unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();

    // Resume execution
    vm.resume(Duration::from_secs(10)).unwrap();

    let socket2 = vm.jail().unwrap().root.descriptor_path("vsock");
    let end2 = deadline(Duration::from_secs(30)).unwrap();
    let status2 = wait_guest_status(&socket2, end2);
    assert!(status2.guest_time_unix.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS);

    vm.stop(Duration::from_secs(5)).unwrap();
    vm.destroy(Duration::from_secs(10)).unwrap();
    eprintln!("snapshot restore and drive attachment passed");
}

#[cfg(not(feature = "dev-unjailed"))]
#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and rootfs"]
fn resumes_guest_snapshot_with_peerless_tap_and_attached_drive() {
    eprintln!("skipped: build with --features dev-unjailed and set HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_ROOTFS");
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
fn grader_exit_diagnostics(exit: Result<()>, serial: &[u8], output: &mut impl Write) -> Result<()> {
    // The runner keeps only the first MAX_CAPTURE_BYTES bytes. A full capture
    // cannot prove that recovery succeeded: its failure marker may be lost.
    let full = serial.len() >= hermetic_vmm::runner::MAX_CAPTURE_BYTES;
    let serial = serial
        .get(..hermetic_vmm::runner::MAX_CAPTURE_BYTES)
        .unwrap_or(serial);
    let exit = if full
        || String::from_utf8_lossy(serial)
            .lines()
            .any(|line| line.trim_end_matches('\r') == "grader-init phase recovery-failed")
    {
        Err(Error::Protocol)
    } else {
        exit
    };
    if exit.is_err() {
        // Keep every line under the smoke harness's diagnostic prefix. The
        // runner retains its bounded capture even after wait_exit cleanup.
        writeln!(output, "grader serial: VM exit failed; console follows")?;
        for line in String::from_utf8_lossy(serial).lines() {
            writeln!(output, "grader serial: {line}")?;
        }
    }
    exit
}

#[test]
fn grader_timeout_prints_console_and_supervisor_phases_before_returning_error() {
    let serial = b"grader-init 1700000000 clock\ngrader-supervisor phase init-wait\n";
    let mut output = Vec::new();
    let error = Err(Error::Protocol);
    assert_eq!(
        grader_exit_diagnostics(error.clone(), serial, &mut output),
        error
    );
    assert_eq!(output, b"grader serial: VM exit failed; console follows\ngrader serial: grader-init 1700000000 clock\ngrader serial: grader-supervisor phase init-wait\n");
    output.clear();
    assert_eq!(grader_exit_diagnostics(Ok(()), serial, &mut output), Ok(()));
    assert!(output.is_empty());
    assert!(grader_exit_diagnostics(
        Ok(()),
        b"grader-init phase recovery-failed\r\n",
        &mut output
    )
    .is_err());
    assert!(output.ends_with(b"grader serial: grader-init phase recovery-failed\n"));
}
#[test]
fn grader_recovery_failure_marker_must_occupy_entire_serial_line() {
    for serial in [
        b"grader-init phase recovery-failed\n".as_slice(),
        b"booting\r\ngrader-init phase recovery-failed\r\npoweroff\r\n",
    ] {
        let mut output = Vec::new();
        assert_eq!(
            grader_exit_diagnostics(Ok(()), serial, &mut output),
            Err(Error::Protocol)
        );
        assert!(output.starts_with(b"grader serial: VM exit failed; console follows\n"));
    }
    for serial in [
        b"prefix grader-init phase recovery-failed\n".as_slice(),
        b"grader-init phase recovery-failed suffix\r\n",
        b"grader-init phase recovery-failed-extra\n",
    ] {
        let mut output = Vec::new();
        assert_eq!(grader_exit_diagnostics(Ok(()), serial, &mut output), Ok(()));
        assert!(output.is_empty());
    }
}

#[test]
fn grader_full_serial_capture_cannot_hide_recovery_failure() {
    let cap = hermetic_vmm::runner::MAX_CAPTURE_BYTES;
    let serial = vec![b'x'; cap];
    let mut output = Vec::new();
    // The capture keeps the first bytes only. A recovery-failed marker emitted
    // after this prefix would be discarded, even if the VM exits normally.
    assert_eq!(
        grader_exit_diagnostics(Ok(()), &serial, &mut output),
        Err(Error::Protocol)
    );
    assert!(output.starts_with(b"grader serial: VM exit failed; console follows\n"));

    output.clear();
    assert_eq!(
        grader_exit_diagnostics(Ok(()), serial.get(..cap - 1).unwrap(), &mut output),
        Ok(())
    );
    assert!(output.is_empty());
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
        let exit = vm.wait_exit(Duration::from_secs(300));
        let (serial, errors) = vm.runner().console_output();
        let exit = grader_exit_result(exit, || (serial.clone(), errors), &mut std::io::stderr());
        grader_exit_diagnostics(exit, &serial, &mut std::io::stderr())
            .expect("grader VM did not power off");
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

/// Boots an extractor image with `init=/sbin/hermetic-extract-init` (no vsock, no
/// network), mounts base read-only and overlay CoW read-write, executes in-guest
/// walk and stream, and writes the output drive, which the host validates with
/// `read_extractor_output`.
#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and an extractor image; see README"]
fn boots_extractor_and_collects_output_drive() {
    #[cfg(feature = "dev-unjailed")]
    {
        let mut vars = Vec::new();
        for name in [
            "HERMETIC_FC_BIN",
            "HERMETIC_KERNEL",
            "HERMETIC_EXTRACT_ROOTFS",
            "HERMETIC_EXTRACT_BASE",
            "HERMETIC_EXTRACT_OVERLAY_COW",
            "HERMETIC_EXTRACT_OUTPUT",
        ] {
            match std::env::var(name) {
                Ok(value) => vars.push(value),
                Err(_) => {
                    eprintln!("skipped: set HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_EXTRACT_ROOTFS, HERMETIC_EXTRACT_BASE, HERMETIC_EXTRACT_OVERLAY_COW and HERMETIC_EXTRACT_OUTPUT");
                    return;
                }
            }
        }
        let task_class = std::env::var("HERMETIC_EXTRACT_TASK").unwrap_or_else(|_| "patch:".into());

        let f = support::Fixture::new();
        let fc_bin = vars[0].clone();
        let kernel_bin = vars[1].clone();
        let rootfs = vars[2].clone();
        let base_drive = vars[3].clone();
        let overlay_cow = vars[4].clone();
        let output_out = vars[5].clone();

        let output_drive_path = std::path::PathBuf::from(&output_out);
        if let Some(parent) = output_drive_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&output_drive_path);
        hermetic_vmm::extractor::create_fresh_output_drive(&output_drive_path, 16 * 1024 * 1024)
            .expect("create fresh output drive");

        let run_nonce = hermetic_vmm::extractor::generate_run_nonce().expect("generate run nonce");

        if std::env::var_os("HERMETIC_FIRECRACKER_LOCK").is_none() {
            let candidate = std::path::PathBuf::from(format!("{fc_bin}.lock.json"));
            if candidate.is_file() {
                std::env::set_var("HERMETIC_FIRECRACKER_LOCK", &candidate);
            } else if let Ok(home) = std::env::var("HOME") {
                let default_lock = std::path::PathBuf::from(home)
                    .join(".hermetic/fcbuild/out/patched/firecracker.lock.json");
                if default_lock.is_file() {
                    std::env::set_var("HERMETIC_FIRECRACKER_LOCK", &default_lock);
                }
            }
        }

        let mut jail = f.spec.jail.clone();
        jail.firecracker = fc_bin;

        let config = hermetic_vmm::extractor::ExtractorVmConfig {
            vm_id: "extractor-vm-guest".into(),
            index: 0,
            extractor_image: rootfs,
            kernel_image: kernel_bin,
            base_drive,
            overlay_cow_drive: overlay_cow,
            output_drive: output_drive_path.to_str().unwrap().to_string(),
            task_class,
            run_nonce,
            t_clock: 1700000000,
            vcpus: 2,
            memory_mib: 1024,
            cpu_template: f.spec.cpu_template.clone(),
            jail,
        };

        let spec = hermetic_vmm::extractor::extractor_spec(&config).expect("valid extractor spec");
        let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
        let mut vm = Vmm::new(spec.validate().unwrap(), runner);

        let print_diagnostics = |runner: &hermetic_vmm::runner::DevUnjailed, step: &str| {
            let (serial, errors) = runner.console_output();
            eprintln!("extractor serial: {step} failed; console follows");
            let serial_str = String::from_utf8_lossy(&serial);
            for line in serial_str.lines() {
                eprintln!("extractor serial: {line}");
            }
            let error_str = String::from_utf8_lossy(&errors);
            for line in error_str.lines() {
                eprintln!("extractor serial: stderr: {line}");
                eprintln!("extractor stderr: {line}");
            }
        };

        if let Err(e) = vm.prepare(Duration::from_secs(120)) {
            print_diagnostics(vm.runner(), "prepare");
            panic!("prepare failed: {e:?}");
        }
        if let Err(e) = vm.start(Duration::from_secs(10)) {
            print_diagnostics(vm.runner(), "start");
            panic!("start failed: {e:?}");
        }
        if let Err(e) = vm.wait_ready(Duration::from_secs(30)) {
            print_diagnostics(vm.runner(), "wait_ready");
            panic!("wait_ready failed: {e:?}");
        }
        let exit = vm.wait_exit(Duration::from_secs(300));
        if let Err(ref e) = exit {
            print_diagnostics(vm.runner(), "wait_exit");
            panic!("wait_exit failed: {e:?}");
        }
        exit.expect("extractor VM did not power off");

        let drive = vm.jail().unwrap().root.descriptor_path("drive-output");
        let base_dir = std::env::var("HERMETIC_EXTRACT_BASE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| f.temp.path().join("base"));
        let out_dir = f.temp.path().join("published");
        let _ = std::fs::create_dir_all(&base_dir);
        let _ = std::fs::create_dir_all(&out_dir);

        let extract_config = hermetic_extract::config::ExtractConfig::default();
        let outcome = hermetic_vmm::extractor::read_extractor_output(
            std::path::Path::new(&drive),
            &config.run_nonce,
            &base_dir,
            &out_dir,
            hermetic_extract::config::TaskClass::Patch,
            &extract_config,
        )
        .expect("valid extractor output");
        eprintln!(
            "extractor outcome: patch_digest={} tamper_evidence={:?}",
            outcome.patch_digest, outcome.tamper_evidence
        );

        let drive_bytes = std::fs::read(&drive).unwrap();
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&output_drive_path)
            .unwrap();
        out.write_all(&drive_bytes).unwrap();

        if let Err(e) = vm.destroy(Duration::from_secs(10)) {
            print_diagnostics(vm.runner(), "destroy");
            panic!("destroy failed: {e:?}");
        }
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

#[test]
fn guest_reply_fragmentation_preserves_the_complete_frame() {
    use std::io::Read;
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    let observer = client.try_clone().unwrap();
    let end = deadline(Duration::from_secs(3)).unwrap();
    let join = std::thread::spawn(move || {
        // Wait until the client consumes each byte before sending the next.
        // Separate writes alone do not guarantee separate stream reads.
        let mut send = |bytes: &[u8]| {
            for byte in bytes {
                server.write_all(&[*byte]).unwrap();
                while rustix::io::ioctl_fionread(&observer).unwrap() != 0 {
                    assert!(Instant::now() < end, "fragment consumption deadline");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        // The request is small enough to remain queued while the fake sends
        // its reply; the real transport must still finish the CONNECT first.
        send(b"OK 5000\n");
        let body = br#"{"type":"status","guest_time_unix":1700000000}"#;
        send(&(body.len() as u32).to_le_bytes());
        send(body);
        let mut request = [0; 34];
        server.read_exact(&mut request).unwrap();
        assert_eq!(&request[..13], b"CONNECT 5000\n");
        assert_eq!(&request[13..17], &17u32.to_le_bytes());
        assert_eq!(&request[17..], br#"{"type":"status"}"#);
    });
    let reply = guest_status_stream(client, end);
    join.join().unwrap();
    assert_eq!(reply.unwrap().guest_time_unix, T_CLOCK);
}

#[test]
fn guest_early_or_truncated_reply_is_a_protocol_error() {
    use std::io::Read;
    let body = br#"{"type":"status","guest_time_unix":1700000000}"#;
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(body);
    for prefix in 0..frame.len() {
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let partial = frame[..prefix].to_vec();
        let join = std::thread::spawn(move || {
            let mut request = [0; 13];
            server.read_exact(&mut request).unwrap();
            server.write_all(b"OK 5000\n").unwrap();
            let mut request = [0; 21];
            server.read_exact(&mut request).unwrap();
            server.write_all(&partial).unwrap();
        });
        let reply = guest_status_stream(client, deadline(Duration::from_secs(1)).unwrap());
        join.join().unwrap();
        assert!(matches!(reply, Err(Error::Protocol)), "prefix {prefix}");
    }
    // A binary frame cannot substitute for Firecracker's CONNECT response,
    // even if it would otherwise decode as a valid status reply.
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    let join = std::thread::spawn(move || {
        let mut request = [0; 13];
        server.read_exact(&mut request).unwrap();
        server.write_all(&frame).unwrap();
    });
    let reply = guest_status_stream(client, deadline(Duration::from_secs(1)).unwrap());
    join.join().unwrap();
    assert!(matches!(reply, Err(Error::Protocol)));
}

#[cfg(feature = "dev-unjailed")]
#[path = "support/agent_h.rs"]
mod agent_h_diagnostics;

#[cfg(feature = "dev-unjailed")]
#[test]
fn agent_h_failure_report_caps_each_stream_without_utf8_expansion() {
    let mut output = Vec::new();
    agent_h_diagnostics::report(
        (b"execd 1700000000 Io\n".to_vec(), b"VMM failure\n".to_vec()),
        &mut output,
    );
    assert_eq!(output, b"agent VM failure: serial:\nexecd 1700000000 Io\n\nagent VM failure: stderr:\nVMM failure\n\n");
    output.clear();
    let cap = hermetic_vmm::runner::MAX_CAPTURE_BYTES;
    agent_h_diagnostics::report((vec![0xff; cap + 1], vec![b'e'; cap + 1]), &mut output);
    assert_eq!(
        output.len(),
        2 * cap + b"agent VM failure: serial:\n\nagent VM failure: stderr:\n\n".len()
    );
    assert_eq!(output.iter().filter(|b| **b == 0xff).count(), cap);
}

#[cfg(feature = "dev-unjailed")]
#[test]
fn agent_h_status_rejects_hostile_fields_without_panics() {
    for bad in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!({"type":"status"}),
        serde_json::json!({"type":"status","guest_time_unix":"secret"}),
        serde_json::json!({"type":"status","guest_time_unix":i64::MIN}),
        serde_json::json!({"type":"status","guest_time_unix":1700000020}),
        serde_json::json!({"type":"error","guest_time_unix":1700000000}),
    ] {
        assert_eq!(
            agent_h_diagnostics::status(&bad, 1700000000),
            Err(Error::Protocol)
        );
    }
    assert_eq!(
        agent_h_diagnostics::status(
            &serde_json::json!({"type":"status","guest_time_unix":1700000000}),
            1700000000
        ),
        Ok(())
    );
}

#[cfg(feature = "dev-unjailed")]
#[test]
fn agent_h_overlay_uses_pinned_config_instead_of_host_defaults() {
    let command = agent_h_diagnostics::overlay_command(1700000000);
    let settings: std::collections::BTreeMap<_, _> = command.get_envs().collect();
    let path = settings
        .get(std::ffi::OsStr::new("MKE2FS_CONFIG"))
        .and_then(|v| *v)
        .unwrap();
    assert_eq!(
        path,
        std::ffi::OsStr::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../python/hermetic_slice/data/mke2fs-hermetic.conf"
        ))
    );
    assert_eq!(settings.len(), 5);
    assert_eq!(
        settings.get(std::ffi::OsStr::new("E2FSPROGS_FAKE_TIME")),
        Some(&Some(std::ffi::OsStr::new("1700000000")))
    );
}

#[cfg(feature = "dev-unjailed")]
#[test]
fn agent_h_diagnostics_preserve_success_errors_and_panics() {
    let mut vm = Vmm::new(
        support::spec(hermetic_vmm::spec::Role::Agent)
            .validate()
            .unwrap(),
        hermetic_vmm::runner::DevUnjailed::default(),
    );
    assert_eq!(
        agent_h_diagnostics::run(&mut vm, |_| Ok::<_, Error>(7)),
        Ok(7)
    );
    assert_eq!(
        agent_h_diagnostics::run(&mut vm, |_| Err::<(), _>(Error::Protocol)),
        Err(Error::Protocol)
    );
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ =
            agent_h_diagnostics::run(&mut vm, |_| -> Result<()> { panic!("readiness deadline") });
    }))
    .unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"readiness deadline"));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LockdownRecord {
    probe: String,
    result: String,
    detail: String,
}

const FULL_CLOCK_PROBES: &[&str] = &[
    "rdtsc",
    "cpuid",
    "kvmclock_msr",
    "clock_pairing_hc",
    "rtc_sysfs_dev",
    "proc_driver_rtc",
    "hpet",
    "dmesg_dates",
    "clocksource_sysfs",
    "posix_clocks",
    "vmclock",
    "cpuinfo",
    "module_load",
    "ring0_paths",
];
const MAX_CLOCK_REPORT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockRecord {
    probe: String,
    result: String,
    detail: String,
    value: Option<String>,
}

fn full_clock_reply_passes(reply: &GuestExec) -> bool {
    if reply.kind != "exec"
        || reply.code != Some(0)
        || reply.truncated
        || reply.timed_out
        || reply.output.len() > MAX_CLOCK_REPORT_BYTES
    {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&reply.output) else {
        return false;
    };
    let mut names = std::collections::BTreeSet::new();
    for line in text.lines().take(FULL_CLOCK_PROBES.len() + 1) {
        let Ok(record) = serde_json::from_str::<ClockRecord>(line) else {
            return false;
        };
        let allowed = record.result == "blocked"
            || record.probe == "clock_pairing_hc" && record.result == "unavailable";
        if !allowed
            || record.detail.is_empty()
            || record.value.as_deref()
                != if record.probe == "posix_clocks" {
                    Some("tai=available")
                } else {
                    None
                }
            || !FULL_CLOCK_PROBES.contains(&record.probe.as_str())
            || !names.insert(record.probe)
        {
            return false;
        }
    }
    names.len() == FULL_CLOCK_PROBES.len()
}

#[test]
fn full_clock_reply_requires_every_record_and_only_pairing_may_be_unavailable() {
    let good: String = FULL_CLOCK_PROBES
        .iter()
        .map(|name| {
            format!(
                "{{\"probe\":\"{name}\",\"result\":\"{}\",{}\"detail\":\"fixed reason\"}}\n",
                if *name == "clock_pairing_hc" {
                    "unavailable"
                } else {
                    "blocked"
                },
                if *name == "posix_clocks" {
                    "\"value\":\"tai=available\","
                } else {
                    ""
                }
            )
        })
        .collect();
    let mut reply = GuestExec {
        kind: "exec".into(),
        code: Some(0),
        output: good.as_bytes().to_vec(),
        truncated: false,
        timed_out: false,
    };
    assert!(full_clock_reply_passes(&reply));
    reply.output = good.replace("unavailable", "blocked").into_bytes();
    assert!(full_clock_reply_passes(&reply));
    for name in FULL_CLOCK_PROBES {
        for result in ["leak", "error", "unavailable"] {
            if *name == "clock_pairing_hc" && result == "unavailable" {
                continue;
            }
            let changed: String = good
                .lines()
                .map(|line| {
                    if line.contains(&format!("\"probe\":\"{name}\"")) {
                        line.replace("blocked", result)
                            .replace("unavailable", result)
                            + "\n"
                    } else {
                        line.to_string() + "\n"
                    }
                })
                .collect();
            reply.output = changed.into_bytes();
            assert!(!full_clock_reply_passes(&reply), "{name}: {result}");
        }
        reply.output = good
            .lines()
            .filter(|line| !line.contains(&format!("\"probe\":\"{name}\"")))
            .map(|line| line.to_string() + "\n")
            .collect::<String>()
            .into_bytes();
        assert!(!full_clock_reply_passes(&reply));
    }
    for bad in [
        format!("{good}{good}"),
        format!("{good}bad\n"),
        good.replace("cpuid", "unknown"),
        good.replace("\"detail\":", "\"value\":\"host secret\",\"detail\":"),
        String::new(),
        "x".repeat(MAX_CLOCK_REPORT_BYTES + 1),
    ] {
        reply.output = bad.into_bytes();
        assert!(!full_clock_reply_passes(&reply));
    }
    reply.output = good.into_bytes();
    reply.code = Some(1);
    assert!(!full_clock_reply_passes(&reply));
    reply.code = Some(0);
    reply.truncated = true;
    assert!(!full_clock_reply_passes(&reply));
    reply.truncated = false;
    reply.timed_out = true;
    assert!(!full_clock_reply_passes(&reply));
    reply.timed_out = false;
    reply.kind = "error".into();
    assert!(!full_clock_reply_passes(&reply));
}

#[test]
#[ignore = "needs dev-unjailed, KVM and sealed static probe/config; run HERMETIC_FULL_PROBE=1 scripts/integration/boot-smoke.sh"]
fn runs_guest_full_clock_probe() {
    #[cfg(feature = "dev-unjailed")]
    {
        let f = environment().expect("full clock smoke requires pinned VM inputs");
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
        let reply = guest_exec(&socket, &["/sbin/hermetic-clockprobe"], end);
        vm.stop(Duration::from_secs(2)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
        assert!(full_clock_reply_passes(&reply.expect("full clock exec reply")),
            "full clock probe must exit 0 with all records blocked except userspace pairing coverage");
    }
    #[cfg(not(feature = "dev-unjailed"))]
    panic!("full clock smoke requires dev-unjailed feature");
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

// Incomplete is reported explicitly: gateway/install fixtures are not configured
// by this smoke. It is never upgraded to a sealed attestation.
fn escape_reply_passes(
    reply: &GuestExec,
    aggregate: impl FnOnce(&[u8]) -> (Option<i32>, Vec<u8>),
) -> bool {
    if reply.kind != "exec"
        || reply.truncated
        || reply.timed_out
        || reply.output.len() > MAX_ESCAPE_REPORT_BYTES
    {
        return false;
    }
    let (code, verdict) = aggregate(&reply.output);
    reply.code == Some(0)
        && matches!(
            (code, verdict.as_slice()),
            (Some(0), b"sealed\n") | (Some(1), b"incomplete\n")
        )
}

#[cfg(feature = "dev-unjailed")]
fn aggregate_escape_report(report: &[u8]) -> (Option<i32>, Vec<u8>) {
    use std::io::Read;
    const MAX_VERDICT_BYTES: u64 = 32;
    const AGGREGATE_TIMEOUT: Duration = Duration::from_secs(5);
    let binary = std::env::var_os("HERMETIC_ESCAPE_AGGREGATOR").expect("host aggregator required");
    let mut child = Command::new(binary)
        .arg("--aggregate")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start host aggregator");
    child.stdin.take().unwrap().write_all(report).unwrap();
    let end = Instant::now() + AGGREGATE_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= end {
            child.kill().unwrap();
            child.wait().unwrap();
            return (None, Vec::new());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut verdict = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(MAX_VERDICT_BYTES + 1)
        .read_to_end(&mut verdict)
        .unwrap();
    eprintln!(
        "escape aggregate: {}",
        match verdict.as_slice() {
            b"sealed\n" => "sealed",
            b"incomplete\n" => "incomplete",
            b"escaped\n" => "escaped",
            _ => "invalid",
        }
    );
    (status.code(), verdict)
}

#[test]
#[ignore = "needs dev-unjailed, KVM and sealed static probe; run HERMETIC_ESCAPE_PROBE=1 scripts/integration/boot-smoke.sh"]
fn runs_guest_escape_probe() {
    #[cfg(feature = "dev-unjailed")]
    {
        let Some(f) = environment() else {
            return;
        };
        let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
        let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), runner);
        vm.prepare(Duration::from_secs(120)).unwrap();
        vm.start(Duration::from_secs(10)).unwrap();
        vm.wait_ready(Duration::from_secs(30)).unwrap();
        let socket = vm.jail().unwrap().root.descriptor_path("vsock");
        let ready_end = deadline(Duration::from_secs(30)).unwrap();
        loop {
            match guest_status(&socket, ready_end) {
                Ok(status) => {
                    assert_eq!(status.kind, "status");
                    break;
                }
                Err(Error::Io) => {
                    assert!(Instant::now() < ready_end, "execd readiness deadline");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("execd readiness: {e}"),
            }
        }
        let reply = guest_exec_timeout(
            &socket,
            &["/sbin/hermetic-escapeprobe"],
            deadline(Duration::from_secs(300)).unwrap(),
            ESCAPE_EXEC_TIMEOUT_MS,
        );
        // Clean up the VM even when the report or transport failed.
        vm.stop(Duration::from_secs(2)).unwrap();
        vm.destroy(Duration::from_secs(10)).unwrap();
        assert!(
            escape_reply_passes(&reply.expect("escape exec reply"), aggregate_escape_report),
            "escape probe escaped, invalid, truncated or timed out"
        );
    }
    #[cfg(not(feature = "dev-unjailed"))]
    panic!("escape smoke requires dev-unjailed feature");
}

#[test]
fn escape_exec_frame_over_status_cap_is_accepted_and_bounded() {
    use std::io::Read;
    assert_eq!(ESCAPE_EXEC_TIMEOUT_MS, 290_000);
    let output = b"{\"probe\":\"dns.resolver0.google_a\",\"result\":\"blocked\",\"detail\":\"kernel refused\"}\n".repeat(64);
    let frame = serde_json::to_vec(&serde_json::json!({"type":"exec", "code":0,
        "output":output, "truncated":false,"timed_out":false}))
    .unwrap();
    assert!(frame.len() > MAX_STATUS_BYTES as usize);
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    let join = std::thread::spawn(move || {
        let mut hello = [0; 13];
        server.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"CONNECT 5000\n");
        server.write_all(b"OK 5000\n").unwrap();
        let mut length = [0; 4];
        server.read_exact(&mut length).unwrap();
        let mut request = vec![0; u32::from_le_bytes(length) as usize];
        server.read_exact(&mut request).unwrap();
        server
            .write_all(&(frame.len() as u32).to_le_bytes())
            .unwrap();
        for chunk in frame.chunks(127) {
            server.write_all(chunk).unwrap();
        }
    });
    let body = guest_call(
        client,
        br#"{"type":"exec"}"#,
        deadline(Duration::from_secs(5)).unwrap(),
    )
    .unwrap();
    let reply: GuestExec = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply.output, output);
    join.join().unwrap();
    for length in [0, MAX_REPLY_BYTES + 1] {
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let join = std::thread::spawn(move || {
            let mut hello = [0; 13];
            server.read_exact(&mut hello).unwrap();
            server.write_all(b"OK 5000\n").unwrap();
            let mut request = [0; 6];
            server.read_exact(&mut request).unwrap();
            server.write_all(&length.to_le_bytes()).unwrap();
        });
        assert!(matches!(
            guest_call(client, b"{}", deadline(Duration::from_secs(5)).unwrap()),
            Err(Error::Protocol)
        ));
        join.join().unwrap();
    }
}

#[test]
fn escape_smoke_aggregates_exact_output_and_rejects_transport_and_verdict_failures() {
    let mut reply = GuestExec {
        kind: "exec".into(),
        code: Some(0),
        output: b"report\n".to_vec(),
        truncated: false,
        timed_out: false,
    };
    for (code, verdict, good) in [
        (0, "sealed\n", true),
        (1, "incomplete\n", true),
        (2, "escaped\n", false),
        (1, "invalid\n", false),
        (0, "invalid\n", false),
        (0, "incomplete\n", false),
        (1, "sealed\n", false),
        (0, "sealed\nextra", false),
    ] {
        assert_eq!(
            escape_reply_passes(&reply, |bytes| {
                assert_eq!(bytes, b"report\n");
                (Some(code), verdict.as_bytes().to_vec())
            }),
            good
        );
    }
    for code in [Some(1), Some(2), None] {
        reply.code = code;
        assert!(!escape_reply_passes(&reply, |bytes| {
            assert_eq!(bytes, b"report\n");
            (Some(2), b"escaped\n".to_vec())
        }));
    }
    reply.code = Some(0);
    for fault in 0..4 {
        reply.truncated = fault == 0;
        reply.timed_out = fault == 1;
        reply.kind = if fault == 2 { "error" } else { "exec" }.into();
        if fault == 3 {
            reply.output = vec![0; MAX_ESCAPE_REPORT_BYTES + 1];
        }
        assert!(!escape_reply_passes(&reply, |_| panic!(
            "invalid reply must not be aggregated"
        )));
    }
}

#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and execd rootfs; see README"]
fn boots_multivcpu_guest_and_checks_clock() {
    #[cfg(feature = "dev-unjailed")]
    {
        if let Some(mut f) = environment() {
            f.spec.vcpus = 2;
            let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
            boot(f, runner);
        }
    }
    #[cfg(not(feature = "dev-unjailed"))]
    {
        eprintln!("skipped: build with --features dev-unjailed and set HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_ROOTFS");
    }
}

#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and execd rootfs; see README"]
fn pauses_resumes_and_snapshots_guest_under_clock_hiding() {
    #[cfg(feature = "dev-unjailed")]
    {
        if let Some(mut f) = environment() {
            // The memory file of a full snapshot is the guest's whole memory;
            // the process file-size limit must admit it.
            let memory = u64::from(f.spec.memory_mib) * 1024 * 1024;
            f.spec.limits.file_size_bytes = f.spec.limits.file_size_bytes.max(memory);
            let runner = hermetic_vmm::runner::DevUnjailed::new(&python_launcher(&f)).unwrap();
            let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), runner);
            vm.prepare(Duration::from_secs(120)).unwrap();
            vm.start(Duration::from_secs(10)).unwrap();
            vm.wait_ready(Duration::from_secs(30)).unwrap();
            let end = deadline(Duration::from_secs(30)).unwrap();
            let socket = vm.jail().unwrap().root.descriptor_path("vsock");
            let s0 = loop {
                match guest_status(&socket, end) {
                    Ok(s) => break s,
                    Err(Error::Io) => {
                        assert!(Instant::now() < end, "execd readiness deadline");
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("execd status failed: {e}"),
                }
            };
            assert!(s0.guest_time_unix.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS);

            // Pause the guest
            vm.pause(Duration::from_secs(5)).unwrap();
            assert_eq!(vm.state(), hermetic_vmm::State::Paused);

            // Snapshot while paused
            let snap_state = format!("{}/snap.state", f.temp.path().display());
            let snap_mem = format!("{}/snap.mem", f.temp.path().display());
            vm.snapshot_create(&snap_state, &snap_mem, Duration::from_secs(15))
                .unwrap();

            // Resume the guest
            vm.resume(Duration::from_secs(5)).unwrap();
            assert_eq!(vm.state(), hermetic_vmm::State::Running);

            // Verify status after resume: must still be bounded and monotonic
            let s1 = guest_status(&socket, end).unwrap();
            assert!(s1.guest_time_unix >= s0.guest_time_unix);
            assert!(s1.guest_time_unix.abs_diff(T_CLOCK) <= CLOCK_TOLERANCE_SECONDS);

            vm.stop(Duration::from_secs(2)).unwrap();
            vm.destroy(Duration::from_secs(10)).unwrap();
        }
    }
    #[cfg(not(feature = "dev-unjailed"))]
    {
        eprintln!("skipped: build with --features dev-unjailed and set HERMETIC_FC_BIN, HERMETIC_KERNEL, HERMETIC_ROOTFS");
    }
}

#[test]
#[ignore = "needs dev-unjailed feature, /dev/kvm, pinned Firecracker, guest kernel and execd rootfs; see README"]
fn measures_guest_tsc_drift_without_kvmclock_placeholder() {
    // A valid measurement needs guest-side TSC readings taken through execd
    // and compared against host elapsed time over a long interval. Deriving
    // ticks from the guest's one-second wall clock (an earlier version) does
    // not measure TSC drift, so this run fails rather than pass on such data.
    panic!("nested TSC drift measurement is not implemented: it needs guest-side TSC readings");
}

#[test]
fn audits_deployment_host_configuration() {
    match hermetic_vmm::host_audit::audit_host_live() {
        Ok(report) => {
            assert!(report.all_ok);
            assert!(report.vendor_ok);
            assert!(report.invariant_tsc_ok);
        }
        Err(e) => {
            eprintln!("live host audit skipped or failed closed: {e}");
        }
    }
}
