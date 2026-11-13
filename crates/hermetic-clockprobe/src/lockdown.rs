//! Trusted pre-handoff checks, using the manager's verified final kernel config.
//! Device-node absence alone is never sufficient: root can recreate a node.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use crate::arch_x86;
use crate::classify::{ProbeRecord, ProbeResult};
use crate::read::Root;

pub const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_CONFIG_LINE_BYTES: usize = 4096;
pub const MAX_STATE_BYTES: u64 = 4096;
pub const CONFIG_PATH: &str = "etc/hermetic/guest-kernel.config";
pub const REQUIRED: &[&str] = &[
    "SECURITY",
    "SECURITYFS",
    "SECURITY_LOCKDOWN_LSM",
    "SECURITY_LOCKDOWN_LSM_EARLY",
    "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY",
    "BPF_UNPRIV_DEFAULT_OFF",
    "CGROUPS",
    "CGROUP_BPF",
    "BPF",
    "BPF_SYSCALL",
];
pub const FORBIDDEN: &[&str] = &[
    "MODULES",
    "DEVMEM",
    "DEVKMEM",
    "KEXEC",
    "KEXEC_FILE",
    "KEXEC_CORE",
    "X86_MSR",
    "X86_CPUID",
    "PROC_KCORE",
    "HIBERNATION",
    "X86_IOPL_IOPERM",
    "BPF_KPROBE_OVERRIDE",
    "KPROBES",
    "KPROBE_EVENTS",
    "UPROBE_EVENTS",
    "BPF_EVENTS",
    "ACPI_CUSTOM_METHOD",
    "ACPI_TABLE_UPGRADE",
    "PARAVIRT",
    "KVM_GUEST",
    "PARAVIRT_CLOCK",
];

fn record(name: &str, result: ProbeResult, detail: &str) -> ProbeRecord {
    ProbeRecord::new(name, result, None, detail)
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

/// Return no caller-controlled text, including when the config is malformed.
pub fn config_sealed(text: &str) -> io::Result<bool> {
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(invalid());
    }
    let mut values = BTreeMap::new();
    for line in text.split('\n') {
        if line.len() > MAX_CONFIG_LINE_BYTES || !line.bytes().all(|b| (32..=126).contains(&b)) {
            return Err(invalid());
        }
        let entry = if let Some(name) = line.strip_prefix("# CONFIG_") {
            Some((name.strip_suffix(" is not set").ok_or_else(invalid)?, "n"))
        } else if let Some(assignment) = line.strip_prefix("CONFIG_") {
            Some(assignment.split_once('=').ok_or_else(invalid)?)
        } else if line.is_empty() || line.starts_with('#') {
            None
        } else {
            return Err(invalid());
        };
        if let Some((name, value)) = entry {
            if name.is_empty()
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || value.is_empty()
                || values.insert(name, value).is_some()
            {
                return Err(invalid());
            }
        }
    }
    Ok(REQUIRED.iter().all(|name| values.get(name) == Some(&"y"))
        && FORBIDDEN
            .iter()
            .all(|name| matches!(values.get(name), None | Some(&"n"))))
}

/// Linux x86_64 returns raw -ENOSYS when module support is compiled out. An
/// empty module image cannot install code, even on an incorrectly built kernel.
pub fn classify_module_load(raw_result: Option<(i64, i64)>) -> ProbeRecord {
    match raw_result {
        Some((-38, -38)) => record(
            "module_load",
            ProbeResult::Blocked,
            "Module insertion syscalls are not implemented by the running kernel",
        ),
        Some(_) => record(
            "module_load",
            ProbeResult::Leak,
            "Module syscall exists; compiled-out module policy was not verified",
        ),
        None => record(
            "module_load",
            ProbeResult::Unavailable,
            "Module syscall inspection is supported only on Linux x86_64",
        ),
    }
}

pub fn inspect_ring0(root: &Root, proc: &Root, sys: &Root) -> io::Result<ProbeRecord> {
    if !config_sealed(&root.text(CONFIG_PATH, MAX_CONFIG_BYTES)?)? {
        return Ok(record(
            "ring0_paths",
            ProbeResult::Leak,
            "Verified build config does not seal root kernel interfaces",
        ));
    }
    let state = sys.text("kernel/security/lockdown", MAX_STATE_BYTES)?;
    if state.trim() != "none integrity [confidentiality]" {
        return Ok(record(
            "ring0_paths",
            ProbeResult::Leak,
            "Running kernel is not in confidentiality lockdown",
        ));
    }
    let bpf = proc.text("sys/kernel/unprivileged_bpf_disabled", MAX_STATE_BYTES)?;
    if !matches!(bpf.trim(), "1" | "2") {
        return Ok(record(
            "ring0_paths",
            ProbeResult::Leak,
            "Unprivileged BPF is not disabled",
        ));
    }
    for path in [
        "modules",
        "sys/kernel/modules_disabled",
        "kcore",
        "sys/kernel/kexec_load_disabled",
    ] {
        if proc.present(path)? {
            return Ok(record(
                "ring0_paths",
                ProbeResult::Leak,
                "Forbidden kernel interface remains registered",
            ));
        }
    }
    // Inspect driver registration too; deleting /dev nodes cannot hide drivers.
    for path in [
        "class/mem/mem",
        "class/mem/kmem",
        "class/msr",
        "class/cpuid",
        "kernel/kexec_loaded",
        "power/resume",
    ] {
        if sys.present(path)? {
            return Ok(record(
                "ring0_paths",
                ProbeResult::Leak,
                "Forbidden kernel driver remains registered",
            ));
        }
    }
    Ok(record("ring0_paths", ProbeResult::Blocked, "Verified build config and live kernel interfaces seal the enumerated root paths; kernel exploits and host hypercall filtering are outside this check"))
}

pub fn run() -> Vec<ProbeRecord> {
    let module = classify_module_load(arch_x86::empty_module_calls());
    let ring0 = (|| {
        let root = Root::new(Path::new("/"))?;
        let proc = Root::new(Path::new("/proc"))?;
        let sys = Root::new(Path::new("/sys"))?;
        inspect_ring0(&root, &proc, &sys)
    })()
    .unwrap_or_else(|_: io::Error| {
        record(
            "ring0_paths",
            ProbeResult::Error,
            "Kernel policy inspection failed; verified config and mounted securityfs are required",
        )
    });
    vec![module, ring0]
}
