#![forbid(unsafe_code)]

use hermetic_clockprobe::classify::{determine_exit_code, ProbeResult};
use hermetic_clockprobe::lockdown::{self, FORBIDDEN, REQUIRED};
use hermetic_clockprobe::read::Root;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn config() -> String {
    let mut text = String::from("# Linux/x86 6.6.160 Kernel Configuration\n");
    for name in REQUIRED {
        text.push_str(&format!("CONFIG_{name}=y\n"));
    }
    for name in FORBIDDEN {
        text.push_str(&format!("# CONFIG_{name} is not set\n"));
    }
    text
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let mut created = None;
        for _ in 0..100 {
            let path = base.join(format!(
                "clockprobe-lockdown-{}",
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    created = Some(path);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("fixture: {e}"),
            }
        }
        let f = Self(created.expect("fixture cap"));
        f.write(lockdown::CONFIG_PATH, &config());
        f.write(
            "sys/kernel/security/lockdown",
            "none integrity [confidentiality]\n",
        );
        f.write("proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
        f
    }
    fn write(&self, path: &str, text: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn inspect(&self) -> std::io::Result<hermetic_clockprobe::classify::ProbeRecord> {
        lockdown::inspect_ring0(
            &Root::new(&self.0)?,
            &Root::new(&self.0.join("proc"))?,
            &Root::new(&self.0.join("sys"))?,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn module_load_requires_absent_syscall_not_permissions_or_invalid_image() {
    let blocked = lockdown::classify_module_load(Some((-38, -38)));
    assert_eq!(blocked.to_json_line(), "{\"probe\":\"module_load\",\"result\":\"blocked\",\"detail\":\"Module insertion syscalls are not implemented by the running kernel\"}");
    assert_eq!(determine_exit_code(&[blocked]), 0);
    for raw in [-1, -13, -8, -14, -22, 0] {
        for results in [(raw, -38), (-38, raw), (raw, raw)] {
            let rec = lockdown::classify_module_load(Some(results));
            assert_eq!(rec.result, ProbeResult::Leak);
            assert_eq!(determine_exit_code(&[rec]), 2);
        }
    }
    assert_eq!(
        lockdown::classify_module_load(None).result,
        ProbeResult::Unavailable
    );
}

#[test]
fn every_root_interface_rule_fails_closed() {
    let good = config();
    assert!(lockdown::config_sealed(&good).unwrap());
    for name in REQUIRED {
        let line = format!("CONFIG_{name}=y\n");
        for value in ["m", "n"] {
            assert!(!lockdown::config_sealed(
                &good.replace(&line, &format!("CONFIG_{name}={value}\n"))
            )
            .unwrap());
        }
        assert!(!lockdown::config_sealed(&good.replace(&line, "")).unwrap());
    }
    for name in FORBIDDEN {
        for value in ["y", "m", "1", "\"n\""] {
            let wrong = good.replace(
                &format!("# CONFIG_{name} is not set"),
                &format!("CONFIG_{name}={value}"),
            );
            assert!(!lockdown::config_sealed(&wrong).unwrap());
        }
    }
}

#[test]
fn hostile_config_and_missing_evidence_never_pass() {
    for text in [
        "CONFIG_MODULES=n\nCONFIG_MODULES=y".into(),
        "CONFIG_MODULES=n\0".into(),
        "# CONFIG_MODULES is not unset".into(),
        "CONFIG_=n".into(),
        "x".repeat(lockdown::MAX_CONFIG_BYTES as usize + 1),
        format!("#{}", "x".repeat(lockdown::MAX_CONFIG_LINE_BYTES)),
    ] {
        assert!(lockdown::config_sealed(&text).is_err());
    }
    let f = Fixture::new();
    assert_eq!(f.inspect().unwrap().result, ProbeResult::Blocked);
    fs::remove_file(f.0.join(lockdown::CONFIG_PATH)).unwrap();
    assert!(f.inspect().is_err());
    f.write(lockdown::CONFIG_PATH, &config());
    fs::remove_file(f.0.join("sys/kernel/security/lockdown")).unwrap();
    assert!(f.inspect().is_err());
}

#[test]
fn running_state_and_registered_drivers_override_sealed_config() {
    let f = Fixture::new();
    let expected = f.inspect().unwrap().to_json_line();
    assert_eq!(expected, "{\"probe\":\"ring0_paths\",\"result\":\"blocked\",\"detail\":\"Verified build config and live kernel interfaces seal the enumerated root paths; kernel exploits and host hypercall filtering are outside this check\"}");
    for state in [
        "[none] integrity confidentiality",
        "none [integrity] confidentiality",
        "SECRET",
    ] {
        f.write("sys/kernel/security/lockdown", state);
        let rec = f.inspect().unwrap();
        assert_eq!(rec.result, ProbeResult::Leak);
        assert!(!rec.to_json_line().contains("SECRET"));
    }
    f.write(
        "sys/kernel/security/lockdown",
        "none integrity [confidentiality]\n",
    );
    for value in ["0", "bad", "3"] {
        f.write("proc/sys/kernel/unprivileged_bpf_disabled", value);
        assert_eq!(f.inspect().unwrap().result, ProbeResult::Leak);
    }
    f.write("proc/sys/kernel/unprivileged_bpf_disabled", "1");
    assert_eq!(f.inspect().unwrap().result, ProbeResult::Blocked);
    for path in [
        "proc/modules",
        "proc/sys/kernel/modules_disabled",
        "proc/kcore",
        "proc/sys/kernel/kexec_load_disabled",
        "sys/class/mem/mem",
        "sys/class/mem/kmem",
        "sys/class/msr",
        "sys/class/cpuid",
        "sys/kernel/kexec_loaded",
        "sys/power/resume",
    ] {
        f.write(path, "");
        assert_eq!(f.inspect().unwrap().result, ProbeResult::Leak, "{path}");
        fs::remove_file(f.0.join(path)).unwrap();
    }
}

#[test]
fn checked_in_policy_and_probe_agree() {
    let mut values = std::collections::BTreeMap::new();
    for text in [
        include_str!("../../../images/kernel/base-x86_64.config"),
        include_str!("../../../images/kernel/hermetic.config"),
    ] {
        for line in text.lines() {
            if let Some(line) = line.strip_prefix("CONFIG_") {
                let (name, value) = line.split_once('=').unwrap();
                values.insert(name, value);
            } else if let Some(name) = line
                .strip_prefix("# CONFIG_")
                .and_then(|s| s.strip_suffix(" is not set"))
            {
                values.insert(name, "n");
            }
        }
    }
    let text = values
        .into_iter()
        .map(|(name, value)| format!("CONFIG_{name}={value}\n"))
        .collect::<String>();
    assert!(lockdown::config_sealed(&text).unwrap());
}

// The probe's lists must match the build policy in python/hermetic_slice/guest_kernel.py.
// A drift (PERF_EVENTS, which x86 force-selects) made the real lockdown kernel
// report ring0_paths "leak" in the nested-VM smoke on 2026-11-14.
#[test]
fn lockdown_lists_match_kernel_build_policy() {
    let py = include_str!("../../../python/hermetic_slice/guest_kernel.py");
    let line = py
        .lines()
        .find(|l| l.contains("Phase 3b: deny guest root access") && l.contains("\"MODULES "))
        .expect("forbidden policy line");
    let policy: std::collections::BTreeSet<&str> = line
        .rsplit_once(", \"")
        .unwrap()
        .1
        .trim_end_matches("\"),")
        .split_ascii_whitespace()
        .collect();
    let probe: std::collections::BTreeSet<&str> =
        hermetic_clockprobe::lockdown::FORBIDDEN.iter().copied().collect();
    assert_eq!(probe, policy);
    assert!(!probe.contains("PERF_EVENTS"));
}
