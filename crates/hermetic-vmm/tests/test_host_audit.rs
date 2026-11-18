#![forbid(unsafe_code)]

use hermetic_vmm::host_audit::{
    audit_host_offline, parse_clocksource, parse_cpuinfo, parse_ignore_msrs, verify_kvm_caps,
    HostAuditError, HostAuditReport, REQUIRED_CPU_FLAGS, REQUIRED_KVM_CAPS,
};

fn valid_cpuinfo() -> String {
    format!(
        "processor\t: 0\n\
         vendor_id\t: GenuineIntel\n\
         cpu family\t: 6\n\
         model\t\t: 26\n\
         model name\t: Intel(R) Core(TM) i7 CPU 920 @ 2.67GHz\n\
         flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm {} rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni dtes64 monitor ds_cpl vmx est tm2 ssse3 cx16 xtpr pdcm sse4_1 sse4_2 popcnt lahf_lm pti constant_tsc\n",
        REQUIRED_CPU_FLAGS.join(" ")
    )
}

fn valid_caps() -> Vec<(&'static str, bool)> {
    REQUIRED_KVM_CAPS.iter().map(|&cap| (cap, true)).collect()
}

#[test]
fn test_audit_host_offline_valid_intel_passes() {
    let cpuinfo = valid_cpuinfo();
    let caps = valid_caps();
    let report = audit_host_offline(&cpuinfo, "tsc\n", Some("0\n"), true, &caps).unwrap();
    assert_eq!(
        report,
        HostAuditReport {
            vendor_ok: true,
            invariant_tsc_ok: true,
            cpu_features_ok: true,
            host_clocksource_ok: true,
            ignore_msrs_ok: true,
            kvm_device_ok: true,
            kvm_capabilities_ok: true,
            all_ok: true,
        }
    );
}

#[test]
fn test_audit_host_offline_unsupported_vendor_amd_rejected() {
    let cpuinfo = valid_cpuinfo().replace("GenuineIntel", "AuthenticAMD");
    let caps = valid_caps();
    let err = audit_host_offline(&cpuinfo, "tsc", Some("0"), true, &caps).unwrap_err();
    assert_eq!(err, HostAuditError::UnsupportedVendor);
}

#[test]
fn test_audit_host_offline_missing_constant_tsc_rejected() {
    let cpuinfo = valid_cpuinfo().replace("constant_tsc", "variable_tsc");
    let caps = valid_caps();
    let err = audit_host_offline(&cpuinfo, "tsc", Some("0"), true, &caps).unwrap_err();
    assert_eq!(err, HostAuditError::MissingInvariantTsc);
}

#[test]
fn test_audit_host_offline_missing_nonstop_tsc_rejected() {
    let cpuinfo = valid_cpuinfo().replace("nonstop_tsc", "stopping_tsc");
    let caps = valid_caps();
    let err = audit_host_offline(&cpuinfo, "tsc", Some("0"), true, &caps).unwrap_err();
    assert_eq!(err, HostAuditError::MissingInvariantTsc);
}

#[test]
fn test_audit_host_offline_missing_cpu_feature_rejected() {
    let cpuinfo = valid_cpuinfo().replace("popcnt", "no_popcnt");
    let caps = valid_caps();
    let err = audit_host_offline(&cpuinfo, "tsc", Some("0"), true, &caps).unwrap_err();
    assert_eq!(err, HostAuditError::MissingCpuFeature("popcnt"));
}

#[test]
fn test_audit_host_offline_non_tsc_clocksource_rejected() {
    let cpuinfo = valid_cpuinfo();
    let caps = valid_caps();
    for bad_source in ["kvm-clock", "hpet", "acpi_pm", "jiffies", "tsc_bad"] {
        let err = audit_host_offline(&cpuinfo, bad_source, Some("0"), true, &caps).unwrap_err();
        assert_eq!(err, HostAuditError::NonTscClocksource);
    }
}

#[test]
fn test_audit_host_offline_ignore_msrs_enabled_rejected() {
    let cpuinfo = valid_cpuinfo();
    let caps = valid_caps();
    for bad_val in ["Y", "1", "y", "yes", "true"] {
        let err = audit_host_offline(&cpuinfo, "tsc", Some(bad_val), true, &caps).unwrap_err();
        assert_eq!(err, HostAuditError::IgnoreMsrsEnabled);
    }
}

#[test]
fn test_audit_host_offline_kvm_unavailable_rejected() {
    let cpuinfo = valid_cpuinfo();
    let caps = valid_caps();
    let err = audit_host_offline(&cpuinfo, "tsc", Some("0"), false, &caps).unwrap_err();
    assert_eq!(err, HostAuditError::KvmUnavailable);
}

#[test]
fn test_audit_host_offline_missing_kvm_cap_rejected() {
    let cpuinfo = valid_cpuinfo();
    for missing_cap in REQUIRED_KVM_CAPS {
        let caps: Vec<(&'static str, bool)> = REQUIRED_KVM_CAPS
            .iter()
            .map(|&c| (c, c != *missing_cap))
            .collect();
        let err = audit_host_offline(&cpuinfo, "tsc", Some("0"), true, &caps).unwrap_err();
        assert_eq!(err, HostAuditError::MissingKvmCapability(missing_cap));
    }
}

#[test]
fn test_host_audit_parsers_isolated() {
    assert!(parse_clocksource("tsc\n").is_ok());
    assert!(parse_clocksource("  tsc  ").is_ok());
    assert!(parse_clocksource("kvm-clock").is_err());

    assert!(parse_ignore_msrs("0\n").is_ok());
    assert!(parse_ignore_msrs("N").is_ok());
    assert!(parse_ignore_msrs("").is_err());
    assert!(parse_ignore_msrs("1").is_err());
    assert!(parse_ignore_msrs("Y").is_err());

    let caps = valid_caps();
    assert!(verify_kvm_caps(&caps).is_ok());
    assert!(verify_kvm_caps(&[]).is_err());
}

#[test]
fn test_host_audit_error_display_never_contains_host_paths_or_names() {
    let errors = [
        HostAuditError::UnsupportedVendor,
        HostAuditError::MissingInvariantTsc,
        HostAuditError::MissingCpuFeature("cx16"),
        HostAuditError::NonTscClocksource,
        HostAuditError::IgnoreMsrsEnabled,
        HostAuditError::KvmUnavailable,
        HostAuditError::MissingKvmCapability("KVM_CAP_TSC_CONTROL"),
        HostAuditError::Io,
        HostAuditError::ResourceCapExceeded,
    ];
    for err in &errors {
        let text = format!("{err}");
        assert!(!text.contains("/home/"));
        assert!(!text.contains("flingboot"));
        assert!(!text.contains("root"));
    }
}

#[test]
fn test_audit_host_oversized_cpuinfo_rejected() {
    let oversized = "processor : 0\nflags : tsc\n".repeat(45_000); // > 1 MiB
    let err = parse_cpuinfo(&oversized).unwrap_err();
    assert_eq!(err, HostAuditError::ResourceCapExceeded);
}

#[test]
fn test_audit_host_cpuinfo_128_cpus_accepted() {
    let single_cpu = valid_cpuinfo();
    let mut multi = String::new();
    for i in 0..128 {
        multi.push_str(&single_cpu.replace("processor\t: 0", &format!("processor\t: {i}")));
    }
    assert!(parse_cpuinfo(&multi).is_ok());
}

#[test]
fn test_audit_host_cpuinfo_heterogeneous_missing_flag_rejected() {
    let cpu0 = valid_cpuinfo();
    let cpu1 = valid_cpuinfo()
        .replace("processor\t: 0", "processor\t: 1")
        .replace("constant_tsc", "variable_tsc");
    let combined = format!("{cpu0}\n{cpu1}");
    let err = parse_cpuinfo(&combined).unwrap_err();
    assert_eq!(err, HostAuditError::MissingInvariantTsc);

    let cpu1_feature = valid_cpuinfo()
        .replace("processor\t: 0", "processor\t: 1")
        .replace("popcnt", "no_popcnt");
    let combined2 = format!("{cpu0}\n{cpu1_feature}");
    let err2 = parse_cpuinfo(&combined2).unwrap_err();
    assert_eq!(err2, HostAuditError::MissingCpuFeature("popcnt"));
}

#[test]
fn test_audit_host_offline_missing_ignore_msrs_rejected() {
    let cpuinfo = valid_cpuinfo();
    let caps = valid_caps();
    let err1 = audit_host_offline(&cpuinfo, "tsc", None, true, &caps).unwrap_err();
    assert_eq!(err1, HostAuditError::IgnoreMsrsEnabled);

    let err2 = audit_host_offline(&cpuinfo, "tsc", Some(""), true, &caps).unwrap_err();
    assert_eq!(err2, HostAuditError::IgnoreMsrsEnabled);

    let err3 = audit_host_offline(&cpuinfo, "tsc", Some("  \n"), true, &caps).unwrap_err();
    assert_eq!(err3, HostAuditError::IgnoreMsrsEnabled);
}

#[test]
fn test_audit_host_kvm_caps_xen_intercept_checked() {
    assert!(REQUIRED_KVM_CAPS.contains(&"KVM_CAP_X86_MSR_FILTER"));
    assert!(REQUIRED_KVM_CAPS.contains(&"KVM_CAP_XEN_HVM"));
    let caps = [
        ("KVM_CAP_TSC_CONTROL", true),
        ("KVM_CAP_X86_MSR_FILTER", true),
        ("KVM_CAP_ENFORCE_PV_FEATURE_CPUID", true),
        ("KVM_CAP_XEN_HVM", false),
    ];
    let err = verify_kvm_caps(&caps).unwrap_err();
    assert_eq!(err, HostAuditError::MissingKvmCapability("KVM_CAP_XEN_HVM"));
}
