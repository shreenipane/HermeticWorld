#![deny(unsafe_code)]

//! Deployment-host configuration audit for Phase 3b clock-hiding.
//!
//! Audits the deployment host's CPU vendor, invariant TSC, required CPU features,
//! host clocksource, KVM parameters, and KVM capabilities to verify the clock-hiding
//! security boundary without leaking host paths, usernames, or host times.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MAX_AUDIT_FILE_BYTES: u64 = 64 * 1024;
pub const MAX_CPUINFO_BYTES: u64 = 1024 * 1024;
pub const MAX_CPUINFO_LINES: usize = 65_536;

pub const REQUIRED_CPU_FLAGS: &[&str] = &[
    "constant_tsc",
    "nonstop_tsc",
    "pni",
    "ssse3",
    "cx16",
    "sse4_1",
    "sse4_2",
    "popcnt",
    "lm",
];

pub const REQUIRED_KVM_CAPS: &[&str] = &[
    "KVM_CAP_TSC_CONTROL",
    "KVM_CAP_X86_MSR_FILTER",
    "KVM_CAP_XEN_HVM",
    "KVM_CAP_ENFORCE_PV_FEATURE_CPUID",
];

pub const KVM_CAP_XEN_HVM: u32 = 38;
pub const KVM_CAP_TSC_CONTROL: u32 = 60;
pub const KVM_CAP_X86_MSR_FILTER: u32 = 189;
pub const KVM_CAP_ENFORCE_PV_FEATURE_CPUID: u32 = 190;
pub const KVM_XEN_HVM_CONFIG_INTERCEPT_HCALL: u32 = 1 << 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostAuditReport {
    pub vendor_ok: bool,
    pub invariant_tsc_ok: bool,
    pub cpu_features_ok: bool,
    pub host_clocksource_ok: bool,
    pub ignore_msrs_ok: bool,
    pub kvm_device_ok: bool,
    pub kvm_capabilities_ok: bool,
    pub all_ok: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HostAuditError {
    UnsupportedVendor,
    MissingInvariantTsc,
    MissingCpuFeature(&'static str),
    NonTscClocksource,
    IgnoreMsrsEnabled,
    KvmUnavailable,
    MissingKvmCapability(&'static str),
    Io,
    ResourceCapExceeded,
}

impl std::fmt::Display for HostAuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVendor => {
                f.write_str("host CPU vendor is not GenuineIntel (AMD and others fail closed)")
            }
            Self::MissingInvariantTsc => {
                f.write_str("host CPU lacks invariant TSC (constant_tsc / nonstop_tsc)")
            }
            Self::MissingCpuFeature(feat) => write!(f, "host CPU lacks required feature: {feat}"),
            Self::NonTscClocksource => f.write_str("host clocksource is not tsc"),
            Self::IgnoreMsrsEnabled => {
                f.write_str("KVM ignore_msrs parameter is enabled, compromising MSR filtering")
            }
            Self::KvmUnavailable => f.write_str("/dev/kvm is missing or inaccessible"),
            Self::MissingKvmCapability(cap) => write!(f, "KVM lacks required capability: {cap}"),
            Self::Io => f.write_str("host audit file I/O failed"),
            Self::ResourceCapExceeded => f.write_str("host audit file exceeded byte cap"),
        }
    }
}

impl std::error::Error for HostAuditError {}

fn read_bounded_file_with_cap(path: &Path, cap: u64) -> Result<String, HostAuditError> {
    let mut file = File::open(path).map_err(|_| HostAuditError::Io)?;
    let mut buf = Vec::new();
    let read_bytes = file
        .by_ref()
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|_| HostAuditError::Io)?;
    if read_bytes as u64 > cap {
        return Err(HostAuditError::ResourceCapExceeded);
    }
    String::from_utf8(buf).map_err(|_| HostAuditError::Io)
}

fn read_bounded_file(path: &Path) -> Result<String, HostAuditError> {
    read_bounded_file_with_cap(path, MAX_AUDIT_FILE_BYTES)
}

pub fn parse_cpuinfo(text: &str) -> Result<(), HostAuditError> {
    if text.len() as u64 > MAX_CPUINFO_BYTES {
        return Err(HostAuditError::ResourceCapExceeded);
    }

    let mut records_seen = 0usize;
    let mut current_vendor: Option<bool> = None;
    let mut current_flags = std::collections::HashSet::new();

    let validate_record = |vendor: Option<bool>,
                           flags: &std::collections::HashSet<&str>|
     -> Result<(), HostAuditError> {
        if vendor != Some(true) {
            return Err(HostAuditError::UnsupportedVendor);
        }
        if !flags.contains("constant_tsc") || !flags.contains("nonstop_tsc") {
            return Err(HostAuditError::MissingInvariantTsc);
        }
        for &required in REQUIRED_CPU_FLAGS {
            if !flags.contains(required) {
                return Err(HostAuditError::MissingCpuFeature(required));
            }
        }
        Ok(())
    };

    for line in text.lines().take(MAX_CPUINFO_LINES) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if current_vendor.is_some() || !current_flags.is_empty() {
                validate_record(current_vendor, &current_flags)?;
                records_seen += 1;
                current_vendor = None;
                current_flags.clear();
            }
            continue;
        }

        if let Some((k, v)) = trimmed.split_once(':') {
            match k.trim() {
                "processor" => {
                    if current_vendor.is_some() || !current_flags.is_empty() {
                        validate_record(current_vendor, &current_flags)?;
                        records_seen += 1;
                        current_vendor = None;
                        current_flags.clear();
                    }
                }
                "vendor_id" => {
                    let v_trim = v.trim();
                    current_vendor = Some(v_trim == "GenuineIntel");
                }
                "flags" => {
                    for flag in v.split_whitespace().take(256) {
                        current_flags.insert(flag);
                    }
                }
                _ => {}
            }
        }
    }

    if current_vendor.is_some() || !current_flags.is_empty() {
        validate_record(current_vendor, &current_flags)?;
        records_seen += 1;
    }

    if records_seen == 0 {
        return Err(HostAuditError::UnsupportedVendor);
    }

    Ok(())
}

pub fn parse_clocksource(text: &str) -> Result<(), HostAuditError> {
    let trimmed = text.trim();
    if trimmed == "tsc" {
        Ok(())
    } else {
        Err(HostAuditError::NonTscClocksource)
    }
}

pub fn parse_ignore_msrs(text: &str) -> Result<(), HostAuditError> {
    let trimmed = text.trim();
    if trimmed == "N" || trimmed == "0" {
        Ok(())
    } else {
        Err(HostAuditError::IgnoreMsrsEnabled)
    }
}

pub fn verify_kvm_caps(caps: &[(&str, bool)]) -> Result<(), HostAuditError> {
    for &required in REQUIRED_KVM_CAPS {
        let present = caps.iter().any(|(name, ok)| *name == required && *ok);
        if !present {
            return Err(HostAuditError::MissingKvmCapability(required));
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
struct KvmCheckExtension(usize);

#[allow(unsafe_code)]
unsafe impl rustix::ioctl::Ioctl for KvmCheckExtension {
    type Output = i32;
    const IS_MUTATING: bool = false;

    fn opcode(&self) -> rustix::ioctl::Opcode {
        0xAE03
    }

    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        self.0 as *mut core::ffi::c_void
    }

    unsafe fn output_from_ptr(
        output: rustix::ioctl::IoctlOutput,
        _: *mut core::ffi::c_void,
    ) -> rustix::io::Result<Self::Output> {
        Ok(output)
    }
}

#[allow(unsafe_code)]
fn probe_kvm_extension<F: rustix::fd::AsFd>(fd: F, cap: u32) -> Result<i32, HostAuditError> {
    // SAFETY: KVM_CHECK_EXTENSION (0xAE03) takes a numeric capability ID as argument
    // and returns an integer status/flag without mutating userspace pointers.
    unsafe { rustix::ioctl::ioctl(fd, KvmCheckExtension(cap as usize)) }
        .map_err(|_| HostAuditError::KvmUnavailable)
}

/// Offline audit using supplied contents.
pub fn audit_host_offline(
    cpuinfo_text: &str,
    clocksource_text: &str,
    ignore_msrs_text: Option<&str>,
    kvm_device_present: bool,
    kvm_caps: &[(&str, bool)],
) -> Result<HostAuditReport, HostAuditError> {
    parse_cpuinfo(cpuinfo_text)?;
    parse_clocksource(clocksource_text)?;
    let imsrs = ignore_msrs_text.ok_or(HostAuditError::IgnoreMsrsEnabled)?;
    parse_ignore_msrs(imsrs)?;
    if !kvm_device_present {
        return Err(HostAuditError::KvmUnavailable);
    }
    verify_kvm_caps(kvm_caps)?;

    Ok(HostAuditReport {
        vendor_ok: true,
        invariant_tsc_ok: true,
        cpu_features_ok: true,
        host_clocksource_ok: true,
        ignore_msrs_ok: true,
        kvm_device_ok: true,
        kvm_capabilities_ok: true,
        all_ok: true,
    })
}

/// Live host audit checking `/proc/cpuinfo`, sysfs clocksource, kvm parameters and `/dev/kvm`.
pub fn audit_host_live() -> Result<HostAuditReport, HostAuditError> {
    let cpuinfo = read_bounded_file_with_cap(Path::new("/proc/cpuinfo"), MAX_CPUINFO_BYTES)?;
    parse_cpuinfo(&cpuinfo)?;

    let clocksource = read_bounded_file(Path::new(
        "/sys/devices/system/clocksource/clocksource0/current_clocksource",
    ))?;
    parse_clocksource(&clocksource)?;

    let ignore_msrs = read_bounded_file(Path::new("/sys/module/kvm/parameters/ignore_msrs"))?;
    parse_ignore_msrs(&ignore_msrs)?;

    let kvm_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|_| HostAuditError::KvmUnavailable)?;

    let tsc_control = probe_kvm_extension(&kvm_file, KVM_CAP_TSC_CONTROL)?;
    if tsc_control <= 0 {
        return Err(HostAuditError::MissingKvmCapability("KVM_CAP_TSC_CONTROL"));
    }

    let msr_filter = probe_kvm_extension(&kvm_file, KVM_CAP_X86_MSR_FILTER)?;
    if msr_filter <= 0 {
        return Err(HostAuditError::MissingKvmCapability(
            "KVM_CAP_X86_MSR_FILTER",
        ));
    }

    let pv_feature = probe_kvm_extension(&kvm_file, KVM_CAP_ENFORCE_PV_FEATURE_CPUID)?;
    if pv_feature <= 0 {
        return Err(HostAuditError::MissingKvmCapability(
            "KVM_CAP_ENFORCE_PV_FEATURE_CPUID",
        ));
    }

    let xen_hvm = probe_kvm_extension(&kvm_file, KVM_CAP_XEN_HVM)?;
    if (xen_hvm as u32 & KVM_XEN_HVM_CONFIG_INTERCEPT_HCALL) == 0 {
        return Err(HostAuditError::MissingKvmCapability("KVM_CAP_XEN_HVM"));
    }

    Ok(HostAuditReport {
        vendor_ok: true,
        invariant_tsc_ok: true,
        cpu_features_ok: true,
        host_clocksource_ok: true,
        ignore_msrs_ok: true,
        kvm_device_ok: true,
        kvm_capabilities_ok: true,
        all_ok: true,
    })
}
