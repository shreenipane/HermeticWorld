#![forbid(unsafe_code)]
use hermetic_clockprobe::classify::*;

#[test]
fn cpuinfo_checks_every_processor_and_requires_complete_records() {
    let baseline = format!("model name: {BASELINE_BRAND}\nflags: fpu tsc\n");
    for second in [
        "model name: future CPU\nflags: fpu tsc\n".to_string(),
        format!("model name: {BASELINE_BRAND}\nflags: fpu future_isa\n"),
    ] {
        let text = format!("processor: 0\n{baseline}\nprocessor: 1\n{second}");
        assert_eq!(classify_cpuinfo(Some(&text)).result, ProbeResult::Leak);
    }
    for second in [
        "model name: incomplete CPU\n".to_string(),
        "flags: fpu tsc\n".to_string(),
        format!("model name: {BASELINE_BRAND}\nflags: \n"),
    ] {
        let text = format!("processor: 0\n{baseline}\nprocessor: 1\n{second}");
        assert_ne!(classify_cpuinfo(Some(&text)).result, ProbeResult::Blocked);
    }
    let text = format!("processor: 0\n{baseline}\nprocessor: 1\n{baseline}");
    assert_eq!(classify_cpuinfo(Some(&text)).result, ProbeResult::Blocked);
    assert_eq!(
        classify_cpuinfo(Some(&format!("{baseline}\n").repeat(MAX_ITEMS + 1))).result,
        ProbeResult::Error
    );
}

#[test]
fn unexpected_available_clocksources_cannot_pass_the_tsc_profile() {
    for available in ["tsc xen", "tsc future_clock", "future_clock"] {
        assert_eq!(
            classify_clocksource_sysfs(Some("tsc"), Some(available)).result,
            ProbeResult::Leak
        );
    }
    assert_eq!(
        classify_clocksource_sysfs(Some("tsc"), Some("tsc")).result,
        ProbeResult::Blocked
    );
}

#[test]
fn log_date_check_requires_a_valid_cutoff_even_for_empty_logs() {
    for cutoff in [None, Some(MAX_EPOCH + 1)] {
        for log in ["", "6,0,0,-;booted", "6,0,0,-;1970-01-01"] {
            assert_eq!(
                classify_dmesg_dates(Some(log), false, cutoff).result,
                ProbeResult::Error
            );
        }
    }
    assert_eq!(
        classify_dmesg_dates(Some("6,0,0,-;2024-01-01"), false, Some(1_704_067_200)).result,
        ProbeResult::Blocked
    );
}

#[test]
fn cpuinfo_duplicate_and_empty_fields_cannot_pass() {
    for text in [
        format!("model name: {BASELINE_BRAND}\nflags: fpu\nflags: future_isa\n"),
        format!("model name: {BASELINE_BRAND}\nflags: fpu\nmodel name: future CPU\n"),
        format!("model name: {BASELINE_BRAND}\nflags: \n"),
    ] {
        assert_eq!(classify_cpuinfo(Some(&text)).result, ProbeResult::Error);
    }
}
