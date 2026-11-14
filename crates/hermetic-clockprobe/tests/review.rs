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
