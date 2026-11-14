use hermetic_clockprobe::{canary, classify::*};

#[test]
fn diagnostics_do_not_echo_clock_identity_or_filesystem_evidence() {
    let secret = "host-secret-token";
    let records = [
        classify_rdtsc(Some(987_654_321_123), Some(1), Some(0.0)),
        classify_cpuid(
            &[CpuidLeafDump {
                leaf: 1,
                subleaf: 0,
                eax: 0xabcdef12,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }],
            Some(secret),
        ),
        classify_cpuinfo(Some(&format!(
            "model name: {secret}\nflags: fpu {secret}\n"
        ))),
        classify_rtc_sysfs_dev(
            &["rtc0".into()],
            Some(1_794_600_000),
            None,
            true,
            Some(1),
            0.0,
        ),
        classify_proc_driver_rtc(
            Some("rtc_date: 2026-11-13\nrtc_time: 17:15:00\n"),
            Some(1),
            0.0,
        ),
        classify_posix_clocks(
            Some(1_794_600_000.0),
            Some(1.0),
            Some(1.0),
            Some(1_794_600_037.0),
            Some(1),
        ),
        classify_dmesg_dates(Some("2026-11-13"), false, Some(1)),
        classify_clocksource_sysfs(Some(secret), Some(secret)),
        classify_hpet(false, None, &[format!("hpet-{secret}")]),
        classify_vmclock(&[secret.into()], &[], &[]),
        classify_vmclock(&[], &[], &[secret.into()]),
    ];
    for record in records {
        let json = record.to_json_line();
        for forbidden in [
            secret,
            "987654321123",
            "abcdef12",
            "1794600000",
            "2026-11-13",
        ] {
            assert!(
                !json.contains(forbidden),
                "{} echoed evidence: {json}",
                record.probe
            );
        }
    }
}

#[test]
fn canary_rejects_truncated_final_payload() {
    let serial: String = canary::EXPECTED
        .iter()
        .map(|line| format!("hermetic-canary/v1 {line}\n"))
        .collect();
    assert_eq!(
        canary::inspect(serial.as_bytes()).result,
        ProbeResult::Blocked
    );
    assert_eq!(
        canary::inspect(serial.trim_end().as_bytes()).result,
        ProbeResult::Error
    );
}

#[test]
fn canary_rejects_incomplete_or_malformed_markers_after_valid_evidence() {
    let serial: String = canary::EXPECTED
        .iter()
        .map(|line| format!("hermetic-canary/v1 {line}\n"))
        .collect();
    for suffix in [
        "hermetic-canary/v1",
        "hermetic-canary/v1\n",
        "hermetic-canary/v1\tresult=fail\n",
    ] {
        assert_eq!(
            canary::inspect(format!("{serial}{suffix}").as_bytes()).result,
            ProbeResult::Error
        );
    }
}

#[test]
fn cpuinfo_rejects_duplicate_identity_fields_and_empty_flags() {
    for text in [
        format!("model name: {BASELINE_BRAND}\nflags: fpu\nmodel name: host-secret\n"),
        format!("model name: {BASELINE_BRAND}\nflags: fpu\nflags: avx\n"),
        format!("model name: {BASELINE_BRAND}\nflags: \n"),
    ] {
        let record = classify_cpuinfo(Some(&text));
        assert_eq!(record.result, ProbeResult::Error);
        assert!(!record.to_json_line().contains("host-secret"));
    }
}

#[test]
fn log_dates_before_message_semicolons_are_not_discarded() {
    for message in [
        "Linux version secret-host Fri Nov 13 12:00:00 UTC 2026; booting",
        "2026-11-13; booting",
        "6,42,1234,-;2026-11-13; booting",
    ] {
        let record = classify_dmesg_dates(Some(message), false, Some(1_704_067_200));
        assert_eq!(record.result, ProbeResult::Leak, "{message}");
        assert!(!record.to_json_line().contains("secret-host"));
        assert!(!record.to_json_line().contains("2026-11-13"));
    }
}

#[test]
fn monotonic_origin_cannot_predate_guest_boottime() {
    let epoch = 1_704_067_200;
    for tai in [None, Some(epoch as f64 + 10.0)] {
        let record = classify_posix_clocks(
            Some(epoch as f64 + 10.0),
            Some(864_000.0),
            Some(10.0),
            tai,
            Some(epoch),
        );
        assert_eq!(record.result, ProbeResult::Leak);
        assert!(!record.to_json_line().contains("864000"));
    }
    // Boottime includes suspend; monotonic may legitimately be smaller.
    for monotonic in [0.0, 10.0, 1000.0] {
        let record = classify_posix_clocks(
            Some(epoch as f64 + 1000.0),
            Some(monotonic),
            Some(1000.0),
            Some(epoch as f64 + 1000.0),
            Some(epoch),
        );
        assert_eq!(record.result, ProbeResult::Blocked);
    }
}

/// Values read inside the nested lockdown guest (patched Firecracker, no
/// tsc_early_khz, 2026-11-14): the kernel's jiffies sources and the KVM- and
/// template-determined `cpuid_fault`/`pti` flags carry no host evidence.
#[test]
fn nested_guest_clocksource_and_flags_are_the_fixed_profile() {
    let record = classify_clocksource_sysfs(Some("tsc\n"), Some("tsc refined-jiffies jiffies \n"));
    assert_eq!(record.result, ProbeResult::Blocked);
    for (current, available) in [
        ("tsc-early", "tsc-early refined-jiffies jiffies"),
        ("tsc", "tsc kvm-clock"),
        ("tsc", "tsc hpet"),
        ("tsc", "tsc acpi_pm"),
        ("tsc", "tsc jiffies2"),
    ] {
        assert_eq!(
            classify_clocksource_sysfs(Some(current), Some(available)).result,
            ProbeResult::Leak,
            "{current} / {available}"
        );
    }
    let flags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni ssse3 cx16 sse4_1 sse4_2 popcnt lahf_lm cpuid_fault pti";
    let cpuinfo = |flags: &str| {
        format!("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: {}\nflags\t\t: {flags}\n", hermetic_clockprobe::baseline::BRAND)
    };
    assert_eq!(classify_cpuinfo(Some(&cpuinfo(flags))).result, ProbeResult::Blocked);
    for extra in ["hypervisor", "avx", "md_clear", "arch_capabilities"] {
        assert_eq!(
            classify_cpuinfo(Some(&cpuinfo(&format!("{flags} {extra}")))).result,
            ProbeResult::Leak,
            "{extra}"
        );
    }
}

/// Kernel log lines read in the nested lockdown guest (2026-11-14). Only the
/// exact dates extracted from the kernel image are substrate; CodeRabbit's
/// counterexample (a real date older than the kernel) must stay a leak.
#[test]
fn only_exact_substrate_dates_are_listed_not_leaks() {
    let log = "Linux version 6.6.160 (hermetic@hermetic) (gcc (Debian 12.2.0-14+deb12u1) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Wed Oct 21 00:00:00 UTC 2026\n\
ACPI: XSDT 0x00000000000A0226 00003C (v01 FIRECK FCMVXSDT 00000000 FCAT 20240119)\n\
ACPI: Core revision 20230628\n\
device-mapper: ioctl: 4.48.0-ioctl (2023-03-01) initialised: dm-devel@redhat.com\n";
    let t = Some(1_700_000_000);
    let dates = parse_substrate_dates("2023-03-01\n2026-10-21\n").unwrap();
    assert_eq!(classify_dmesg_dates_with_substrate(Some(log), false, t, Some(&dates)).result, ProbeResult::Blocked);
    assert_eq!(classify_dmesg_dates(Some(log), false, t).result, ProbeResult::Leak);
    for other in ["wall time: 2026-10-31\n", "host boot 2025-01-02\n", "rtc: 2026-11-14 10:00:00\n", "built Wed Oct 22 00:00:00 UTC 2026\n"] {
        let text = format!("{log}{other}");
        let record = classify_dmesg_dates_with_substrate(Some(&text), false, Some(0), Some(&dates));
        assert_eq!(record.result, ProbeResult::Leak, "{other}");
        assert!(!record.to_json_line().contains("2026-11-14"));
    }
}

/// The list is extracted by the probe's own parser from the kernel image.
#[test]
fn substrate_dates_are_extracted_exactly_from_image_strings() {
    let mut image = b"\x7fELF\x00\x01Linux version 6.6.160 #1 SMP Wed Oct 21 00:00:00 UTC 2026\x00".to_vec();
    image.extend_from_slice(b"\x00\xffdevice-mapper: ioctl: 4.48.0-ioctl (2023-03-01) initialised\x00\x00short\x00");
    image.extend(std::iter::repeat_n(b'x', 1000));
    image.extend_from_slice(b" 2024-02-29\x00");
    assert_eq!(extract_substrate_dates(&image).unwrap(), "2023-03-01\n2024-02-29\n2026-10-21\n");
    assert_eq!(extract_substrate_dates(b"\x00no dates here at all\x00"), None);
    let list = extract_substrate_dates(&image).unwrap();
    assert_eq!(parse_substrate_dates(&list).unwrap().len(), 3);
}

/// Review findings (2026-11-14): malformed or impossible list entries are
/// configuration errors, and a clock sample spanning a long stop is refused.
#[test]
fn substrate_dates_reject_impossible_or_unordered_entries_and_stale_clock_samples_are_refused() {
    for bad in ["2026-02-30\n", "2026-02-29\n", "2026-04-31\n", "2026-11-31\n", "2026-01-00\n",
                "2026-10-21", "2026-10-21\n\n", "", "\n", "2026-13-01\n", "26-10-21\n", "2026/10/21\n",
                "2026-10-21\n2023-03-01\n", "2026-10-21\n2026-10-21\n", "+026-10-21\n"] {
        assert_eq!(parse_substrate_dates(bad), None, "{bad:?}");
    }
    assert!(parse_substrate_dates("2024-02-29\n").is_some());
    let many: String = (0..=MAX_SUBSTRATE_DATES).map(|i| format!("{:04}-01-01\n", 1970 + i)).collect();
    assert_eq!(parse_substrate_dates(&many), None);
    use hermetic_clockprobe::probes::posix_sample_is_coherent as ok;
    assert!(ok(Some(10.0), Some(10.2)));
    assert!(ok(Some(10.0), Some(11.0)));
    for (b, a) in [(Some(10.0), Some(71.0)), (Some(10.0), Some(11.01)), (Some(10.0), Some(9.0)), (None, Some(1.0)), (Some(1.0), None), (Some(f64::NAN), Some(1.0)), (Some(1.0), Some(f64::INFINITY))] {
        assert!(!ok(b, a), "{b:?} {a:?}");
    }
}
