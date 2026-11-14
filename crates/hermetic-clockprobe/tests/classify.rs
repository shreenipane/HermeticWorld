#![forbid(unsafe_code)]

use hermetic_clockprobe::classify::{
    classify_clock_pairing, classify_clocksource_sysfs, classify_cpuid, classify_cpuinfo,
    classify_dmesg_dates, classify_hpet, classify_kvmclock_msr, classify_posix_clocks,
    classify_proc_driver_rtc, classify_rdtsc, classify_rtc_sysfs_dev, classify_vmclock,
    compute_tsc_freq_from_cpuid, determine_exit_code, parse_hermetic_t_from_cmdline,
    parse_tsc_freq_from_cpuinfo, CpuidLeafDump, ProbeRecord, ProbeResult,
};

#[test]
fn test_cmdline_and_freq_parsers() {
    let cmdline = "console=ttyS0 clocksource=tsc tsc=reliable hermetic.t=1704067200 ro";
    assert_eq!(parse_hermetic_t_from_cmdline(cmdline), Some(1_704_067_200));
    assert_eq!(parse_hermetic_t_from_cmdline("ro quiet"), None);

    let l15 = Some(CpuidLeafDump {
        leaf: 0x15,
        subleaf: 0,
        eax: 2,
        ebx: 200,
        ecx: 25_000_000,
        edx: 0,
    });
    assert_eq!(compute_tsc_freq_from_cpuid(l15, None), Some(2_500_000_000));

    let cpuinfo = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5504 @ 2.00GHz\ncpu MHz\t\t: 2400.000\n";
    assert_eq!(parse_tsc_freq_from_cpuinfo(cpuinfo), Some(2_400_000_000));
}

#[test]
fn test_rdtsc_classification() {
    // Blocked: TSC offset active, matches guest uptime (12s)
    let ok = classify_rdtsc(Some(30_000_000_000), Some(2_500_000_000), Some(12.0));
    assert_eq!(ok.result, ProbeResult::Blocked);

    // Leak: TSC reflects 10-day host uptime (864_000s) while guest uptime is 5s
    let leak = classify_rdtsc(
        Some(2_500_000_000 * 864_000),
        Some(2_500_000_000),
        Some(5.0),
    );
    assert_eq!(leak.result, ProbeResult::Leak);

    // Unknown frequency cannot establish a safe counter origin
    let masked = classify_rdtsc(Some(123_456_789), None, Some(5.0));
    assert_eq!(masked.result, ProbeResult::Unavailable);
}

#[test]
fn test_cpuid_classification() {
    let clean_leaves = vec![
        CpuidLeafDump {
            leaf: 0x1,
            subleaf: 0,
            eax: 0x0001_06a5, // Nehalem baseline
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        CpuidLeafDump {
            leaf: 0x7,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        CpuidLeafDump {
            leaf: 0x15,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        CpuidLeafDump {
            leaf: 0x16,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        CpuidLeafDump {
            leaf: 0x4000_0001,
            subleaf: 0,
            eax: 0, // kvmclock and steal time cleared
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
    ];
    let clean = classify_cpuid(&clean_leaves, Some("Intel(R) Xeon(R) CPU E5504 @ 2.00GHz"));
    assert_eq!(clean.result, ProbeResult::Blocked);

    let leaky_leaves = vec![CpuidLeafDump {
        leaf: 0x4000_0001,
        subleaf: 0,
        eax: 1 << 3, // KVM_FEATURE_CLOCKSOURCE2
        ebx: 0,
        ecx: 0,
        edx: 0,
    }];
    let leak = classify_cpuid(&leaky_leaves, Some("Intel(R) Xeon(R) Platinum 8488C"));
    assert_eq!(leak.result, ProbeResult::Leak);
}

#[test]
fn test_kvmclock_msr_and_clock_pairing() {
    let absent = classify_kvmclock_msr(false, None, &[], None);
    assert_eq!(absent.result, ProbeResult::Blocked);

    let eio = classify_kvmclock_msr(true, None, &[], None);
    assert_eq!(eio.result, ProbeResult::Unavailable);

    let readable = classify_kvmclock_msr(true, None, &[0x4b56_4d00], None);
    assert_eq!(readable.result, ProbeResult::Unavailable);

    let unavail_hc = classify_clock_pairing(&[]);
    assert_eq!(unavail_hc.result, ProbeResult::Unavailable);

    let leak_hc = classify_clock_pairing(&["ptp0:kvm".to_string()]);
    assert_eq!(leak_hc.result, ProbeResult::Unavailable);
}

#[test]
fn test_rtc_hpet_and_clocksource() {
    let rtc_clean = classify_rtc_sysfs_dev(&[], None, None, false, Some(1_704_067_200), 10.0);
    assert_eq!(rtc_clean.result, ProbeResult::Blocked);

    let rtc_leak = classify_rtc_sysfs_dev(
        &["rtc0".to_string()],
        Some(1_794_600_000),
        Some("2026-11-13 17:00:00"),
        true,
        Some(1_704_067_200),
        10.0,
    );
    assert_eq!(rtc_leak.result, ProbeResult::Leak);

    let proc_rtc_none = classify_proc_driver_rtc(None, Some(1_704_067_200), 10.0);
    assert_eq!(proc_rtc_none.result, ProbeResult::Blocked);

    let proc_rtc_leak = classify_proc_driver_rtc(
        Some("rtc_time\t: 17:15:00\nrtc_date\t: 2026-11-13\n"),
        Some(1_704_067_200),
        10.0,
    );
    assert_eq!(proc_rtc_leak.result, ProbeResult::Leak);

    let hpet_clean = classify_hpet(false, Some("tsc"), &["lapic-deadline".to_string()]);
    assert_eq!(hpet_clean.result, ProbeResult::Blocked);

    let hpet_leak = classify_hpet(true, Some("tsc hpet"), &[]);
    assert_eq!(hpet_leak.result, ProbeResult::Unavailable);

    let cs_clean = classify_clocksource_sysfs(Some("tsc\n"), Some("tsc\n"));
    assert_eq!(cs_clean.result, ProbeResult::Blocked);

    let cs_leak = classify_clocksource_sysfs(Some("tsc\n"), Some("kvm-clock tsc\n"));
    assert_eq!(cs_leak.result, ProbeResult::Leak);
}

#[test]
fn test_dmesg_posix_vmclock_cpuinfo_and_exit_codes() {
    // 1704067200 = 2024-01-01 00:00:00 UTC
    let dmesg_ok = "\
6,0,0,-;Linux version 6.6.160 (builder@hermetic) #1 SMP PREEMPT_DYNAMIC Thu Jan 2 12:00:00 UTC 2025\n\
6,1,12000,-;clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x240937b9988, max_idle_ns: 440795218083 ns\n\
6,2,50000,-;hermetic-execd: setting clock to 2024-01-01\n";
    assert_eq!(
        classify_dmesg_dates(Some(dmesg_ok), false, Some(1_704_067_200)).result,
        ProbeResult::Leak
    );

    let dmesg_leak =
        "6,10,90000,-;rtc_cmos 00:01: setting system clock to 2026-11-13T17:00:00 UTC\n";
    assert_eq!(
        classify_dmesg_dates(Some(dmesg_leak), false, Some(1_704_067_200)).result,
        ProbeResult::Leak
    );

    let posix_ok = classify_posix_clocks(
        Some(1_704_067_210.0),
        Some(10.0),
        Some(10.0),
        Some(1_704_067_210.0),
        Some(1_704_067_200),
    );
    assert_eq!(posix_ok.result, ProbeResult::Blocked);

    let posix_tai_leak = classify_posix_clocks(
        Some(1_704_067_210.0),
        Some(10.0),
        Some(10.0),
        Some(1_704_067_247.0), // +37s TAI offset leaked
        Some(1_704_067_200),
    );
    assert_eq!(posix_tai_leak.result, ProbeResult::Leak);

    let vmclock_ok = classify_vmclock(&[], &[], &["AMZN0001:00".to_string()]);
    assert_eq!(vmclock_ok.result, ProbeResult::Blocked);

    let vmclock_leak = classify_vmclock(&["/dev/vmclock0".to_string()], &[], &[]);
    assert_eq!(vmclock_leak.result, ProbeResult::Unavailable);

    let cpu_ok = classify_cpuinfo(Some(
        "model name\t: Intel(R) Xeon(R) CPU E5504 @ 2.00GHz\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 sse4_2\n",
    ));
    assert_eq!(cpu_ok.result, ProbeResult::Blocked);

    let cpu_leak = classify_cpuinfo(Some(
        "model name\t: AMD EPYC 9R14 96-Core Processor\nflags\t\t: fpu tsc kvmclock avx512_fp16\n",
    ));
    assert_eq!(cpu_leak.result, ProbeResult::Leak);

    // JSON serialization & exit codes
    let json = posix_ok.to_json_line();
    assert!(json.starts_with("{\"probe\":\"posix_clocks\",\"result\":\"blocked\""));
    assert_eq!(determine_exit_code(&[posix_ok.clone(), unavail_rec()]), 0);
    assert_eq!(
        determine_exit_code(&[
            posix_ok,
            ProbeRecord::new("err", ProbeResult::Error, None, "io err"),
            posix_tai_leak,
        ]),
        2
    );
}

fn unavail_rec() -> ProbeRecord {
    ProbeRecord::new(
        "clock_pairing_hc",
        ProbeResult::Unavailable,
        None,
        "skipped",
    )
}
