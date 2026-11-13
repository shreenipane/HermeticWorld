//! The separate experiment must remain valid x86 Firecracker v1.18.0 input.
//! These tests validate the artifact and mask behavior, not VMM/KVM denial.
#![forbid(unsafe_code)]
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Template {
    cpuid_modifiers: Vec<Leaf>,
    msr_modifiers: Vec<Msr>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Leaf {
    leaf: String,
    subleaf: String,
    flags: u32,
    modifiers: Vec<Register>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    register: String,
    bitmap: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Msr {
    addr: String,
    bitmap: String,
}

fn bitmap(text: &str, width: usize) -> (u64, u64) {
    let bits = text
        .strip_prefix("0b")
        .expect("Firecracker bitmap prefix")
        .replace('_', "");
    assert_eq!(bits.len(), width);
    bits.bytes().fold((0, 0), |(filter, value), b| {
        assert!(matches!(b, b'0' | b'1' | b'x'));
        (
            (filter << 1) | u64::from(b != b'x'),
            (value << 1) | u64::from(b == b'1'),
        )
    })
}
fn modifiers() -> BTreeMap<(u32, u32, String), (u32, u32)> {
    let t: Template =
        serde_json::from_str(include_str!("../../../vmm/clock-3b.cpu-template.json")).unwrap();
    // Initial MSR values cannot deny future MSR access. No unnecessary
    // TSC_ADJUST write may turn this proposal into a host-compatibility failure.
    assert!(t.msr_modifiers.is_empty());
    for msr in &t.msr_modifiers {
        let _ = u32::from_str_radix(msr.addr.trim_start_matches("0x"), 16).unwrap();
        bitmap(&msr.bitmap, 64);
    }
    let mut seen = BTreeSet::new();
    let mut regs = BTreeMap::new();
    for leaf in t.cpuid_modifiers {
        let l = u32::from_str_radix(leaf.leaf.trim_start_matches("0x"), 16).unwrap();
        let sub = u32::from_str_radix(leaf.subleaf.trim_start_matches("0x"), 16).unwrap();
        assert!(seen.insert((l, sub)), "duplicate CPUID key");
        assert_eq!(leaf.flags, if l == 7 { 1 } else { 0 });
        for reg in leaf.modifiers {
            assert!(["eax", "ebx", "ecx", "edx"].contains(&reg.register.as_str()));
            let (mask, value) = bitmap(&reg.bitmap, 32);
            assert!(regs
                .insert((l, sub, reg.register), (mask as u32, value as u32))
                .is_none());
        }
    }
    regs
}
fn apply(
    regs: &BTreeMap<(u32, u32, String), (u32, u32)>,
    leaf: u32,
    sub: u32,
    reg: &str,
    input: u32,
) -> u32 {
    let (mask, value) = regs
        .get(&(leaf, sub, reg.into()))
        .expect("required modifier");
    (input & !mask) | value
}
#[test]
fn proposal_schema_and_pv_mask_known_answer() {
    let regs = modifiers();
    assert_eq!(apply(&regs, 0x4000_0001, 0, "eax", u32::MAX), 0xfeff_ffd6);
    assert_eq!(apply(&regs, 0x4000_0001, 0, "eax", 0), 0);
}
#[test]
fn proposal_preserves_avx_consistency_and_removes_new_feature_subleaves() {
    let regs = modifiers();
    let ecx = apply(&regs, 1, 0, "ecx", u32::MAX);
    for bit in [12, 26, 27, 28, 29] {
        assert_ne!(ecx & (1 << bit), 0, "AVX/FMA/F16C/XSAVE dependency");
    }
    let ebx = apply(&regs, 7, 0, "ebx", u32::MAX);
    assert_ne!(ebx & (1 << 5), 0, "AVX2 remains paired with AVX");
    assert_eq!(
        ebx & ((1 << 16)
            | (1 << 17)
            | (1 << 21)
            | (1 << 26)
            | (1 << 27)
            | (1 << 28)
            | (1 << 30)
            | (1 << 31)),
        0
    );
    assert_eq!(apply(&regs, 7, 0, "eax", u32::MAX), 0);
    for r in ["ecx", "edx"] {
        assert_eq!(apply(&regs, 7, 0, r, u32::MAX), 0);
    }
    for r in ["eax", "ebx", "ecx", "edx"] {
        assert_eq!(apply(&regs, 7, 1, r, u32::MAX), 0);
        for leaf in [0xa, 0x15, 0x16] {
            assert_eq!(apply(&regs, leaf, 0, r, u32::MAX), 0);
        }
    }
    assert_eq!(
        apply(&regs, 7, 0, "ebx", 0),
        0,
        "cannot invent unsupported instructions"
    );
}
#[test]
fn desired_brand_encoding_is_exact_but_not_runtime_attestation() {
    let regs = modifiers();
    let mut bytes = Vec::new();
    for leaf in 0x8000_0002..=0x8000_0004 {
        for r in ["eax", "ebx", "ecx", "edx"] {
            bytes.extend(apply(&regs, leaf, 0, r, 0).to_le_bytes());
        }
    }
    let expected = b"Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz";
    assert_eq!(&bytes[..expected.len()], expected);
    assert!(bytes[expected.len()..].iter().all(|b| *b == 0));
    // Stock Firecracker normalizes this again; the documentation must retain
    // that limitation, and the manager must inspect actual guest CPUID.
}
#[test]
fn kernel_proposal_closes_root_interfaces_and_keeps_runtime_features() {
    let config = include_str!("../../../images/kernel/clock-3b.config");
    assert!(
        !config.contains("CONFIG_DEVKMEM"),
        "not a Linux 6.6.160 symbol"
    );
    let mut values = BTreeMap::new();
    for line in config.lines() {
        if let Some((key, value)) = line.strip_prefix("CONFIG_").and_then(|v| v.split_once('=')) {
            assert!(values.insert(key, value).is_none());
        } else if let Some(key) = line
            .strip_prefix("# CONFIG_")
            .and_then(|v| v.strip_suffix(" is not set"))
        {
            assert!(values.insert(key, "n").is_none());
        }
    }
    for key in [
        "KVM_GUEST",
        "PARAVIRT",
        "X86_MSR",
        "MODULES",
        "DEVMEM",
        "KEXEC",
        "KEXEC_FILE",
        "HIBERNATION",
        "PROC_KCORE",
        "PROC_PAGE_MONITOR",
        "X86_IOPL_IOPERM",
        "PERF_EVENTS",
        "PTP_1588_CLOCK",
        "RTC_CLASS",
    ] {
        assert_eq!(values.get(key), Some(&"n"), "root interface {key}");
    }
    for key in [
        "SECURITY",
        "SECURITY_LOCKDOWN_LSM",
        "SECURITY_LOCKDOWN_LSM_EARLY",
        "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY",
        "VIRTIO_BLK",
        "VIRTIO_NET",
        "VIRTIO_VSOCKETS",
        "HW_RANDOM_VIRTIO",
        "EXT4_FS",
        "OVERLAY_FS",
        "DEVTMPFS_MOUNT",
        "PROC_FS",
        "SYSFS",
        "UNIX98_PTYS",
        "CGROUPS",
        "CPUSETS",
        "MEMCG",
        "NAMESPACES",
        "NET_NS",
        "NF_TABLES",
        "IP_NF_IPTABLES",
        "BPF_SYSCALL",
        "CGROUP_BPF",
    ] {
        assert_eq!(values.get(key), Some(&"y"), "runtime dependency {key}");
    }
}

#[test]
fn documented_execd_baseline_transfers_large_static_binary_within_caps() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const MAX_FRAME: usize = 4 * 1024 * 1024 + 65536;
    const DEADLINE: Duration = Duration::from_secs(15);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vsock");
    let executable = temp.path().join("probe");
    // The actual GNU static probe is larger than the 1 MiB upload cap. A
    // compressible 2 MiB artifact regresses the documented transport path.
    std::fs::write(&executable, vec![0xa5; 2 * 1024 * 1024]).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let end = Instant::now() + DEADLINE;
        for call in 0..4 {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < end, "baseline client deadline");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("fake listener: {e}"),
                }
            };
            stream.set_read_timeout(Some(DEADLINE)).unwrap();
            stream.set_write_timeout(Some(DEADLINE)).unwrap();
            let mut hello = [0; 13];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(&hello, b"CONNECT 5000\n");
            stream.write_all(b"OK 5000\n").unwrap();
            let mut size = [0; 4];
            stream.read_exact(&mut size).unwrap();
            let size = u32::from_le_bytes(size) as usize;
            assert!((1..=MAX_FRAME).contains(&size));
            let mut body = vec![0; size];
            stream.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let response = match call {
                0 => {
                    assert_eq!(request["type"], "status");
                    serde_json::json!({"type":"status","locked":false})
                }
                1 => {
                    assert_eq!(request["type"], "upload");
                    assert_eq!(request["path"], "/work/hermetic-clockprobe.gz");
                    let data = request["data"].as_array().unwrap();
                    assert!(data.len() <= 1024 * 1024);
                    assert_eq!(data[0], 31);
                    assert_eq!(data[1], 139);
                    serde_json::json!({"type":"ok"})
                }
                2 => {
                    assert_eq!(request["argv"][0], "/bin/busybox");
                    assert_eq!(request["argv"][1], "sh");
                    assert_eq!(request["argv"][3],"/bin/busybox gzip -dc /work/hermetic-clockprobe.gz > /work/hermetic-clockprobe && /bin/busybox chmod 0700 /work/hermetic-clockprobe");
                    serde_json::json!({"type":"exec","code":0,"truncated":false,"timed_out":false,"output":[]})
                }
                _ => {
                    assert_eq!(
                        request["argv"],
                        serde_json::json!(["/work/hermetic-clockprobe"])
                    );
                    serde_json::json!({"type":"exec","code":2,"truncated":false,"timed_out":false,"output":b"fixture\n".to_vec()})
                }
            };
            let response = serde_json::to_vec(&response).unwrap();
            stream
                .write_all(&(response.len() as u32).to_le_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    let document = include_str!("../../../docs/clock-3b-config-and-test-plan.md");
    let source = document
        .split_once("<<'PY'\n")
        .unwrap()
        .1
        .split_once("\nPY\n")
        .unwrap()
        .0;
    let mut child = Command::new("/usr/bin/python3")
        .env_clear()
        .args(["-I", "-"])
        .arg(&path)
        .arg(&executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let end = Instant::now() + DEADLINE;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("baseline command deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"fixture\n");
    assert!(output.stderr.is_empty());
}
