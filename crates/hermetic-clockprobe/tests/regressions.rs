#![forbid(unsafe_code)]
use hermetic_clockprobe::classify::*;

#[test]
fn rtc_hostile_dates_never_panic_or_pass() {
    for date in [
        "0000-00-00 00:00:00",
        "2024-01-00 00:00:00",
        "2024-02-30 00:00:00",
        "2023-02-29 00:00:00",
        "2024-01-01 24:00:00",
        "2024-01-01 00:60:00",
        "2024-01-01 00:00:60",
        "2147483647-12-31 18446744073709551615:00:00",
        "2024-01-01 00:00:00:12",
        "é2024-01-01 00:00:00",
        "not a date",
    ] {
        assert_eq!(parse_iso_datetime_to_unix(date), None, "{date}");
        let (d, t) = date.split_once(' ').unwrap_or((date, "00:00:00"));
        let rtc = format!("rtc_date: {d}\nrtc_time: {t}\n");
        assert_eq!(
            classify_proc_driver_rtc(Some(&rtc), Some(1_704_067_200), 0.0).result,
            ProbeResult::Error
        );
    }
    assert_eq!(
        parse_iso_datetime_to_unix("2024-02-29 12:00:00"),
        Some(1_709_208_000)
    );
    assert_eq!(ymd_to_days(i32::MIN, 0, 0), 0);
}

#[test]
fn missing_references_nan_and_incomplete_inputs_fail_closed() {
    for epoch in [
        "hermetic.t=1 hermetic.t=2",
        "hermetic.t=+1",
        "hermetic.t=18446744073709551615",
        "hermetic.t=x",
        "hermetic.t=1 hermetic.t=x",
    ] {
        assert_eq!(parse_hermetic_t_from_cmdline(epoch), None);
    }
    assert_eq!(
        classify_posix_clocks(
            Some(1_794_600_000.0),
            Some(1.0),
            Some(1.0),
            Some(1_794_600_000.0),
            None
        )
        .result,
        ProbeResult::Error
    );
    for value in [f64::NAN, f64::INFINITY, -1.0] {
        assert_eq!(
            classify_posix_clocks(Some(value), Some(1.0), Some(1.0), Some(1.0), Some(1)).result,
            ProbeResult::Error
        );
    }
    assert_eq!(
        classify_clocksource_sysfs(Some("tsc"), None).result,
        ProbeResult::Error
    );
    assert_eq!(classify_cpuinfo(Some("")).result, ProbeResult::Error);
}

#[test]
fn readable_msrs_and_device_presence_are_not_clock_reads() {
    for msrs in [&[][..], &[0x11, 0x4b56_4d00][..]] {
        let rec = classify_kvmclock_msr(true, None, msrs, None);
        assert_eq!(rec.result, ProbeResult::Unavailable);
    }
    assert_eq!(
        classify_clock_pairing(&["ptp0:kvm".into()]).result,
        ProbeResult::Unavailable
    );
    assert_eq!(
        classify_hpet(true, Some("pit hpet"), &[]).result,
        ProbeResult::Unavailable
    );
    assert_eq!(
        classify_vmclock(&["vmclock0".into()], &[], &[]).result,
        ProbeResult::Unavailable
    );
    assert_eq!(
        classify_rtc_sysfs_dev(
            &["rtc0".into()],
            Some(1_704_067_210),
            Some("2024-01-01 00:00:10"),
            true,
            Some(1_704_067_200),
            10.0
        )
        .result,
        ProbeResult::Blocked
    );
    assert_eq!(
        classify_rdtsc(Some(1), Some(1), None).result,
        ProbeResult::Unavailable
    );
}

#[test]
fn small_rtc_divergence_and_hidden_cpu_brand_are_detected() {
    assert_eq!(
        classify_proc_driver_rtc(
            Some("rtc_date: 2024-01-01\nrtc_time: 01:00:00\n"),
            Some(1_704_067_200),
            0.0
        )
        .result,
        ProbeResult::Leak
    );
    assert_eq!(
        classify_cpuinfo(Some(
            "model name: Intel(R) Xeon(R) Processor @ 3.00GHz\nflags: fpu tsc\n"
        ))
        .result,
        ProbeResult::Leak
    );
    let leaf = CpuidLeafDump {
        leaf: 1,
        subleaf: 0,
        eax: 0x0001_06a5,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    assert_eq!(
        classify_cpuid(&[leaf], Some("Unrecognized CPU")).result,
        ProbeResult::Leak
    );
}

#[test]
fn all_log_dates_including_banners_are_checked_without_echoing_secrets() {
    for log in [
        "Linux version secret-token Wed Nov 13 12:00:00 UTC 2026",
        "é2024-01-01 good 2026-11-13 secret-token",
        "2026-11-13 secret-token",
    ] {
        let rec = classify_dmesg_dates(Some(log), false, Some(1_704_067_200));
        assert_eq!(rec.result, ProbeResult::Leak);
        assert!(!rec.to_json_line().contains("secret-token"));
    }
    assert_eq!(
        classify_dmesg_dates(Some(&"a".repeat(MAX_TEXT_BYTES + 1)), false, Some(1)).result,
        ProbeResult::Error
    );
}

#[test]
fn json_known_answer_and_exit_priority() {
    let record = ProbeRecord::new(
        "quote\"",
        ProbeResult::Error,
        Some("\\\n\r\t\0é".into()),
        "fixed",
    );
    assert_eq!(record.to_json_line(),"{\"probe\":\"quote\\\"\",\"result\":\"error\",\"value\":\"\\\\\\n\\r\\t\\u0000é\",\"detail\":\"fixed\"}");
    assert_eq!(determine_exit_code(std::slice::from_ref(&record)), 1);
    assert_eq!(
        determine_exit_code(&[
            record,
            ProbeRecord::new("leak", ProbeResult::Leak, None, "")
        ]),
        2
    );
}

#[test]
fn processor_base_mhz_is_not_an_architectural_tsc_ratio() {
    let leaf = CpuidLeafDump {
        leaf: 0x16,
        subleaf: 0,
        eax: 2400,
        ebx: 4000,
        ecx: 100,
        edx: 0,
    };
    assert_eq!(compute_tsc_freq_from_cpuid(None, Some(leaf)), None);
}

#[test]
fn unrecognized_features_duplicate_rtc_and_missing_samples_do_not_pass() {
    assert_eq!(
        classify_cpuinfo(Some(&format!(
            "model name: {BASELINE_BRAND}\nflags: fpu unknown_future_isa\n"
        )))
        .result,
        ProbeResult::Leak
    );
    let structured = CpuidLeafDump {
        leaf: 7,
        subleaf: 0,
        eax: 0,
        ebx: 0,
        ecx: 1,
        edx: 0,
    };
    assert_eq!(
        classify_cpuid(&[structured], Some(BASELINE_BRAND)).result,
        ProbeResult::Leak
    );
    assert_eq!(
        classify_proc_driver_rtc(
            Some("rtc_date: 2026-11-13\nrtc_date: 2024-01-01\nrtc_time: 00:00:00\n"),
            Some(1_704_067_200),
            0.0
        )
        .result,
        ProbeResult::Error
    );
    assert_eq!(
        classify_dmesg_dates(None, true, Some(1)).result,
        ProbeResult::Unavailable
    );
    let record = classify_posix_clocks(Some(11.0), Some(1.0), Some(1.0), None, Some(10));
    assert_eq!(record.result, ProbeResult::Unavailable);
    assert!(record.value.unwrap().contains("tai=unavailable"));
}

#[test]
fn rtc_sources_cannot_hide_a_divergent_clock() {
    let entries = vec!["rtc0".into()];
    assert_eq!(
        classify_rtc_sysfs_dev(
            &entries,
            Some(1_704_067_200),
            Some("2026-11-13 00:00:00"),
            true,
            Some(1_704_067_200),
            0.0
        )
        .result,
        ProbeResult::Leak
    );
    assert_eq!(
        classify_rtc_sysfs_dev(
            &entries,
            Some(1_704_067_200),
            Some("not a date"),
            true,
            Some(1_704_067_200),
            0.0
        )
        .result,
        ProbeResult::Error
    );
}

#[test]
fn unsupported_frequency_leaf_alias_is_dumped_but_not_interpreted() {
    let max = CpuidLeafDump {
        leaf: 0,
        subleaf: 0,
        eax: 0xd,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    let aliased = CpuidLeafDump {
        leaf: 0x15,
        subleaf: 0,
        eax: 0x4000,
        ebx: 1,
        ecx: 1,
        edx: 0,
    };
    let record = classify_cpuid(&[max, aliased], Some(BASELINE_BRAND));
    assert_eq!(record.result, ProbeResult::Blocked);
    assert!(record
        .value
        .unwrap()
        .contains("0x00000015:0x0=0x00004000:0x00000001:0x00000001:0x00000000"));
}

#[test]
fn nominal_frequency_parser_rejects_saturation_and_fractional_zero() {
    for text in [
        "cpu MHz: 1e308",
        "cpu MHz: 0.00000001",
        "model name: CPU @ 1e308GHz",
        "cpu MHz: NaN",
        "cpu MHz: inf",
    ] {
        assert_eq!(parse_tsc_freq_from_cpuinfo(text), None);
    }
}

#[test]
fn unknown_clocksource_and_hypervisor_advertisements_cannot_pass_profile() {
    assert_eq!(
        classify_clocksource_sysfs(Some("tsc"), Some("tsc new_host_clock")).result,
        ProbeResult::Leak
    );
    for (leaf, eax, ecx) in [
        (1, 0x000406f1, 1 << 31),
        (0x40000000, 0x40000001, 0),
        (0x40000001, 1 << 24, 0),
        (0x40000010, 1, 0),
    ] {
        let rec = classify_cpuid(
            &[CpuidLeafDump {
                leaf,
                subleaf: 0,
                eax,
                ebx: 0,
                ecx,
                edx: 0,
            }],
            Some(BASELINE_BRAND),
        );
        assert_eq!(rec.result, ProbeResult::Leak, "{leaf:x}");
    }
}

#[test]
fn later_cpu_identity_and_flags_cannot_hide_behind_cpu_zero() {
    let first = format!("processor: 0\nmodel name: {BASELINE_BRAND}\nflags: fpu tsc\n\n");
    for second in [
        "processor: 1\nmodel name: host-secret-sku\nflags: fpu tsc\n".to_string(),
        format!("processor: 1\nmodel name: {BASELINE_BRAND}\nflags: fpu tsc amx_tile\n"),
    ] {
        assert_eq!(
            classify_cpuinfo(Some(&(first.clone() + &second))).result,
            ProbeResult::Leak
        );
    }
}
