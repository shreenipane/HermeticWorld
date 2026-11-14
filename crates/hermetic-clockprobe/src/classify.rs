#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    Blocked,
    Leak,
    Unavailable,
    Error,
}

impl ProbeResult {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeResult::Blocked => "blocked",
            ProbeResult::Leak => "leak",
            ProbeResult::Unavailable => "unavailable",
            ProbeResult::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRecord {
    pub probe: String,
    pub result: ProbeResult,
    pub value: Option<String>,
    pub detail: String,
}

impl ProbeRecord {
    pub fn new(
        probe: impl Into<String>,
        result: ProbeResult,
        value: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            probe: probe.into(),
            result,
            value,
            detail: detail.into(),
        }
    }

    pub fn to_json_line(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push_str("{\"probe\":\"");
        escape_json_str(&self.probe, &mut out);
        out.push_str("\",\"result\":\"");
        out.push_str(self.result.as_str());
        out.push('"');
        if let Some(ref val) = self.value {
            out.push_str(",\"value\":\"");
            escape_json_str(val, &mut out);
            out.push('"');
        }
        out.push_str(",\"detail\":\"");
        escape_json_str(&self.detail, &mut out);
        out.push_str("\"}");
        out
    }
}

fn escape_json_str(input: &str, out: &mut String) {
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

pub fn determine_exit_code(records: &[ProbeRecord]) -> i32 {
    let mut has_error = false;
    for rec in records {
        match rec.result {
            ProbeResult::Leak => return 2,
            ProbeResult::Error => has_error = true,
            ProbeResult::Blocked | ProbeResult::Unavailable => {}
        }
    }
    if has_error {
        1
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidLeafDump {
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidLeafDump {
    pub fn format_hex(&self) -> String {
        format!(
            "0x{:08x}:0x{:x}=0x{:08x}:0x{:08x}:0x{:08x}:0x{:08x}",
            self.leaf, self.subleaf, self.eax, self.ebx, self.ecx, self.edx
        )
    }
}

pub const MAX_TEXT_BYTES: usize = 262_144;
pub const MAX_ITEMS: usize = 512;
pub const MAX_DATE_FINDINGS: usize = 5;
pub const MAX_EPOCH: u64 = 253_402_300_799;
pub const CLOCK_TOLERANCE_SECONDS: f64 = 60.0;
pub const BASELINE_BRAND: &str = crate::baseline::BRAND;

pub fn parse_hermetic_t_from_cmdline(cmdline: &str) -> Option<u64> {
    if cmdline.len() > MAX_TEXT_BYTES {
        return None;
    }
    let mut found = None;
    for token in cmdline.split_whitespace() {
        if let Some(raw) = token.strip_prefix("hermetic.t=") {
            if found.is_some() || raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let val = raw.parse::<u64>().ok()?;
            if val > MAX_EPOCH {
                return None;
            }
            found = Some(val);
        }
    }
    found
}

pub fn compute_tsc_freq_from_cpuid(
    leaf15: Option<CpuidLeafDump>,
    leaf16: Option<CpuidLeafDump>,
) -> Option<u64> {
    if let Some(l15) = leaf15 {
        if l15.eax > 0 && l15.ebx > 0 && l15.ecx > 0 {
            let num = (l15.ecx as u128).saturating_mul(l15.ebx as u128);
            let freq = num / (l15.eax as u128);
            if freq > 0 {
                return u64::try_from(freq).ok();
            }
        }
    }
    let _ = leaf16; // CPUID.16 is processor base frequency, not an architectural TSC ratio.

    None
}

/// Parse nominal processor MHz for fixture compatibility, not a guaranteed TSC rate.
/// Runtime TSC classification deliberately does not use this helper.
pub fn parse_tsc_freq_from_cpuinfo(cpuinfo: &str) -> Option<u64> {
    if cpuinfo.len() > MAX_TEXT_BYTES {
        return None;
    }
    for line in cpuinfo.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let k = key.trim();
            if k == "cpu MHz" {
                if let Ok(mhz) = val.trim().parse::<f64>() {
                    if mhz.is_finite() && mhz > 0.0 {
                        let hz = mhz * 1_000_000.0;
                        if hz.is_finite() && hz >= 1.0 && hz < u64::MAX as f64 {
                            return Some(hz as u64);
                        }
                    }
                }
            }
        }
    }
    for line in cpuinfo.lines() {
        if let Some((key, val)) = line.split_once(':') {
            if key.trim() == "model name" {
                if let Some((_, ghz_part)) = val.split_once('@') {
                    let trimmed = ghz_part.trim();
                    if let Some(num_str) = trimmed.strip_suffix("GHz") {
                        if let Ok(ghz) = num_str.trim().parse::<f64>() {
                            if ghz.is_finite() && ghz > 0.0 {
                                let hz = ghz * 1_000_000_000.0;
                                if hz.is_finite() && hz >= 1.0 && hz < u64::MAX as f64 {
                                    return Some(hz as u64);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Probe 1: RDTSC and estimated uptime vs guest boottime.
/// Flags a counter age exceeding known guest boottime by more than 60 seconds,
/// indicating a counter origin outside this guest; this alone does not prove host uptime.
pub fn classify_rdtsc(
    tsc: Option<u64>,
    freq_hz: Option<u64>,
    guest_boottime_sec: Option<f64>,
) -> ProbeRecord {
    let Some(tsc_val) = tsc else {
        return ProbeRecord::new(
            "rdtsc",
            ProbeResult::Unavailable,
            None,
            "RDTSC instruction unavailable on this architecture",
        );
    };

    let Some(hz) = freq_hz.filter(|&f| f > 0) else {
        return ProbeRecord::new(
            "rdtsc",
            ProbeResult::Unavailable,
            Some(format!("tsc={tsc_val}")),
            "TSC frequency unknown; masking does not establish an isolated counter origin",
        );
    };

    let est_uptime_sec = (tsc_val as f64) / (hz as f64);
    let val_str = format!("tsc={tsc_val},freq_hz={hz},est_uptime_sec={est_uptime_sec:.3}");

    if !guest_boottime_sec.is_some_and(|b| b.is_finite() && b >= 0.0) {
        return ProbeRecord::new(
            "rdtsc",
            ProbeResult::Unavailable,
            Some(val_str),
            "Guest uptime unavailable; cannot compare counter origins",
        );
    }
    let leaked = match guest_boottime_sec {
        Some(boot) if boot.is_finite() && boot >= 0.0 => (est_uptime_sec - boot) > 60.0,
        _ => est_uptime_sec > 86_400.0,
    };

    if leaked {
        ProbeRecord::new(
            "rdtsc",
            ProbeResult::Leak,
            Some(val_str),
            "TSC-estimated uptime exceeds guest VM uptime by >60s; counter origin may predate guest boot (not proof of host uptime)",
        )
    } else {
        ProbeRecord::new(
            "rdtsc",
            ProbeResult::Blocked,
            Some(val_str),
            "Sampled TSC counter age does not exceed guest uptime by the diagnostic tolerance",
        )
    }
}

/// Probe 2: CPUID leaves 0x0, 0x1, 0x7, 0x15, 0x16, 0x40000000..=0x40000010.
/// Leaks if kvmclock bits (0x40000001 EAX bit 0 or 3) are set, frequency leaves 0x15/0x16 are non-zero,
/// or leaf 0x1 EAX / brand string exposes unmasked host silicon SKU.
pub fn classify_cpuid(leaves: &[CpuidLeafDump], brand_string: Option<&str>) -> ProbeRecord {
    if leaves.len() > MAX_ITEMS {
        return ProbeRecord::new("cpuid", ProbeResult::Error, None, "CPUID item cap exceeded");
    }
    if leaves.is_empty() {
        return ProbeRecord::new(
            "cpuid",
            ProbeResult::Unavailable,
            None,
            "CPUID unavailable on this architecture",
        );
    }

    let mut leak_reasons: Vec<String> = Vec::new();
    let mut hex_entries: Vec<String> = Vec::with_capacity(leaves.len());

    let max_basic = leaves
        .iter()
        .find(|leaf| leaf.leaf == 0 && leaf.subleaf == 0)
        .map(|leaf| leaf.eax);
    for leaf in leaves {
        hex_entries.push(leaf.format_hex());
        if leaf.leaf < 0x4000_0000 && max_basic.is_some_and(|maximum| leaf.leaf > maximum) {
            continue;
        }
        match (leaf.leaf, leaf.subleaf) {
            (0x4000_0001, 0) => {
                if leaf.eax != 0 || leaf.ebx != 0 || leaf.ecx != 0 || leaf.edx != 0 {
                    leak_reasons.push("Hypervisor/PV CPUID state exposed".into());
                }
                if (leaf.eax & (1 << 0)) != 0 {
                    leak_reasons.push("0x40000001:EAX[0] KVM_FEATURE_CLOCKSOURCE set".to_string());
                }
                if (leaf.eax & (1 << 3)) != 0 {
                    leak_reasons.push("0x40000001:EAX[3] KVM_FEATURE_CLOCKSOURCE2 set".to_string());
                }
                if (leaf.eax & (1 << 5)) != 0 {
                    leak_reasons.push("0x40000001:EAX[5] KVM_FEATURE_STEAL_TIME set".to_string());
                }
            }
            (0x4000_0000..=0x4000_0010, _)
                if leaf.eax != 0 || leaf.ebx != 0 || leaf.ecx != 0 || leaf.edx != 0 =>
            {
                leak_reasons.push("Hypervisor/PV CPUID state exposed".into());
            }
            (0x15, 0) => {
                let actual = [leaf.eax, leaf.ebx, leaf.ecx, leaf.edx];
                if actual != [0; 4] && Some(actual) != crate::baseline::registers(0x15, 0, 0, 1) {
                    leak_reasons.push("0x15 differs from fixed guest TSC ratio".to_string());
                }
            }
            (0x16, 0) => {
                let actual = [leaf.eax, leaf.ebx, leaf.ecx, leaf.edx];
                if actual != [0; 4] && Some(actual) != crate::baseline::registers(0x16, 0, 0, 1) {
                    leak_reasons.push("0x16 differs from fixed guest frequency".to_string());
                }
            }
            (0x1, 0) => {
                if leaf.ecx & (1 << 31) != 0 {
                    leak_reasons.push("Hypervisor CPUID bit exposed".into());
                }
                // Family/model/stepping are fixed even on newer physical CPUs.
                let ext_model = (leaf.eax >> 16) & 0xF;
                let model = (leaf.eax >> 4) & 0xF;
                let full_model = (ext_model << 4) | model;
                if leaf.eax != crate::baseline::SIGNATURE {
                    leak_reasons.push(format!(
                        "0x1:EAX model 0x{:02x} differs from fixed baseline signature",
                        full_model
                    ));
                }
            }
            (0xa, 0) if leaf.eax != 0 || leaf.ebx != 0 || leaf.ecx != 0 || leaf.edx != 0 => {
                leak_reasons.push("PMU layout exposed".into());
            }
            (0x7, subleaf)
                if subleaf != 0
                    && (leaf.eax != 0 || leaf.ebx != 0 || leaf.ecx != 0 || leaf.edx != 0) =>
            {
                leak_reasons.push("post-baseline structured feature subleaf exposed".into());
            }
            (0x7, 0) => {
                if leaf.eax != 0 || leaf.ebx != 0 || leaf.ecx != 0 || leaf.edx != 0 {
                    leak_reasons.push("Structured features exceed the v2 profile".into());
                }
                if (leaf.ebx & (1 << 16)) != 0 {
                    leak_reasons.push("0x7:0:EBX[16] AVX512F exposed".to_string());
                }
                if (leaf.edx & ((1 << 22) | (1 << 24) | (1 << 25))) != 0 {
                    leak_reasons.push("0x7:0:EDX AMX exposed".to_string());
                }
            }
            _ => {}
        }
    }

    if brand_string.is_some_and(|brand| brand.trim() != BASELINE_BRAND) {
        leak_reasons.push("CPU brand differs from the fixed baseline".into());
    }

    let dump_str = hex_entries.join(";");
    if leak_reasons.is_empty() {
        ProbeRecord::new(
            "cpuid",
            if brand_string.is_some() { ProbeResult::Blocked } else { ProbeResult::Unavailable },
            Some(dump_str),
            "No profile violation found in the supplied CPUID subset; unqueried inputs remain untested",
        )
    } else {
        ProbeRecord::new(
            "cpuid",
            ProbeResult::Leak,
            Some(dump_str),
            leak_reasons.join("; "),
        )
    }
}

/// Probe 3: kvmclock MSRs (0x11, 0x12, 0x4b564d00, 0x4b564d01).
/// Readability alone is unavailable evidence for the write/page-content attack.
pub fn classify_kvmclock_msr(
    msr_dev_present: bool,
    msr_open_error: Option<&str>,
    readable_msrs: &[u32],
    wall_clock_sec: Option<u64>,
) -> ProbeRecord {
    if !msr_dev_present {
        return ProbeRecord::new(
            "kvmclock_msr",
            ProbeResult::Blocked,
            None,
            "/dev/cpu/0/msr not present; userspace MSR access blocked",
        );
    }

    if msr_open_error.is_some() {
        return ProbeRecord::new(
            "kvmclock_msr",
            ProbeResult::Unavailable,
            None,
            "MSR device could not be opened; no write test performed",
        );
    }

    if let Some(sec) = wall_clock_sec {
        if sec > 0 {
            return ProbeRecord::new(
                "kvmclock_msr",
                ProbeResult::Leak,
                Some(format!("wall_clock_sec={sec}")),
                "A caller-supplied wall-clock page epoch was observed; it is not an RDMSR value",
            );
        }
    }

    let _ = readable_msrs;
    ProbeRecord::new(
        "kvmclock_msr", ProbeResult::Unavailable, None,
        "MSR reads return guest addresses, not wall time; writes and pinned GPA pages were not tested",
    )
}

/// Probe 4: KVM_HC_CLOCK_PAIRING hypercall.
/// Uses safe documented PTP device check; raw VMCALL without ptp_kvm is reported as unavailable.
pub fn classify_clock_pairing(ptp_kvm_devices: &[String]) -> ProbeRecord {
    if !ptp_kvm_devices.is_empty() {
        return ProbeRecord::new(
            "clock_pairing_hc",
            ProbeResult::Unavailable,
            None,
            "PTP KVM device present; presence does not establish a successful clock-pairing read",
        );
    }
    ProbeRecord::new(
        "clock_pairing_hc",
        ProbeResult::Unavailable,
        None,
        "ptp_kvm driver absent; raw VMCALL hypercall skipped to avoid unsafe GPA memory writes",
    )
}

/// Probe 5: /sys/class/rtc and /dev/rtc0.
pub fn classify_rtc_sysfs_dev(
    sysfs_entries: &[String],
    since_epoch: Option<u64>,
    date_time_str: Option<&str>,
    dev_rtc0_exists: bool,
    expected_t_clock: Option<u64>,
    guest_uptime_sec: f64,
) -> ProbeRecord {
    if sysfs_entries.is_empty()
        && !dev_rtc0_exists
        && since_epoch.is_none()
        && date_time_str.is_none()
    {
        return ProbeRecord::new(
            "rtc_sysfs_dev",
            ProbeResult::Blocked,
            None,
            "RTC interfaces absent",
        );
    }
    let parsed = date_time_str.and_then(parse_iso_datetime_to_unix);
    if date_time_str.is_some() && parsed.is_none() {
        return ProbeRecord::new(
            "rtc_sysfs_dev",
            ProbeResult::Error,
            None,
            "Malformed RTC date",
        );
    }
    let epoch = since_epoch.or(parsed);
    let Some(epoch) = epoch else {
        return ProbeRecord::new("rtc_sysfs_dev", ProbeResult::Unavailable, None, "RTC present but no date read; /dev/rtc0 requires an approved safe RTC_RD_TIME ioctl wrapper");
    };
    let Some(t) = expected_t_clock.filter(|t| *t <= MAX_EPOCH) else {
        return ProbeRecord::new(
            "rtc_sysfs_dev",
            ProbeResult::Error,
            None,
            "Missing RTC reference epoch",
        );
    };
    if epoch > MAX_EPOCH || !guest_uptime_sec.is_finite() || guest_uptime_sec < 0.0 {
        return ProbeRecord::new(
            "rtc_sysfs_dev",
            ProbeResult::Error,
            None,
            "Invalid RTC or uptime value",
        );
    }
    let leaked = [since_epoch, parsed].into_iter().flatten().any(|observed| {
        (observed as f64 - t as f64 - guest_uptime_sec).abs() > CLOCK_TOLERANCE_SECONDS
    });
    ProbeRecord::new(
        "rtc_sysfs_dev",
        if leaked {
            ProbeResult::Leak
        } else {
            ProbeResult::Blocked
        },
        Some(format!("since_epoch={epoch}")),
        "RTC date compared with configured epoch and guest uptime",
    )
}

/// Probe 6: /proc/driver/rtc.
pub fn classify_proc_driver_rtc(
    content: Option<&str>,
    expected_t_clock: Option<u64>,
    guest_uptime_sec: f64,
) -> ProbeRecord {
    let Some(text) = content else {
        return ProbeRecord::new(
            "proc_driver_rtc",
            ProbeResult::Blocked,
            None,
            "/proc/driver/rtc does not exist",
        );
    };

    if text.len() > MAX_TEXT_BYTES {
        return ProbeRecord::new(
            "proc_driver_rtc",
            ProbeResult::Error,
            None,
            "Text cap exceeded",
        );
    }
    if !guest_uptime_sec.is_finite()
        || guest_uptime_sec < 0.0
        || !expected_t_clock.is_some_and(|t| t <= MAX_EPOCH)
    {
        return ProbeRecord::new(
            "proc_driver_rtc",
            ProbeResult::Error,
            None,
            "Invalid RTC reference or uptime",
        );
    }
    let mut rtc_date: Option<&str> = None;
    let mut rtc_time: Option<&str> = None;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let slot = match k.trim() {
                "rtc_date" => &mut rtc_date,
                "rtc_time" => &mut rtc_time,
                _ => continue,
            };
            if slot.replace(v.trim()).is_some() {
                return ProbeRecord::new(
                    "proc_driver_rtc",
                    ProbeResult::Error,
                    None,
                    "Duplicate RTC field",
                );
            }
        }
    }

    if let (Some(d), Some(t)) = (rtc_date, rtc_time) {
        let combined = format!("{d} {t}");
        if let Some(parsed_epoch) = parse_iso_datetime_to_unix(&combined) {
            let expected_now =
                expected_t_clock.map(|tc| tc.saturating_add(guest_uptime_sec as u64));
            let is_leak = match expected_now {
                Some(exp) => parsed_epoch.abs_diff(exp) > CLOCK_TOLERANCE_SECONDS as u64,
                None => parsed_epoch > 1_577_836_800,
            };
            if is_leak {
                return ProbeRecord::new(
                    "proc_driver_rtc",
                    ProbeResult::Leak,
                    Some(combined),
                    "RTC date diverges from the configured epoch and guest uptime",
                );
            }
        }
        return ProbeRecord::new(
            "proc_driver_rtc",
            if parse_iso_datetime_to_unix(&combined).is_some() && expected_t_clock.is_some() { ProbeResult::Blocked } else { ProbeResult::Error },
            None,
            "RTC date checked against the configured epoch; malformed or unreferenced dates fail closed",
        );
    }

    ProbeRecord::new(
        "proc_driver_rtc",
        ProbeResult::Error,
        None,
        "RTC content lacks a complete date and time",
    )
}

/// Probe 7: HPET and legacy hardware timers.
pub fn classify_hpet(
    dev_hpet_exists: bool,
    available_clocksources: Option<&str>,
    clockevent_devices: &[String],
) -> ProbeRecord {
    let mut leaks = Vec::new();
    if dev_hpet_exists {
        leaks.push("/dev/hpet exists".to_string());
    }
    if let Some(avail) = available_clocksources {
        for cs in avail.split_whitespace() {
            if matches!(cs, "hpet" | "acpi_pm" | "pit") {
                leaks.push(format!("available_clocksource contains {cs}"));
            }
        }
    }
    for dev in clockevent_devices {
        let lower = dev.trim().to_ascii_lowercase();
        if lower.contains("hpet") || lower.contains("pit") {
            leaks.push(format!("clockevent device {lower} present"));
        }
    }

    if leaks.is_empty() {
        ProbeRecord::new(
            "hpet",
            ProbeResult::Blocked,
            None,
            "No legacy timer interface found in the inspected paths; emulated timers may still exist",
        )
    } else {
        ProbeRecord::new(
            "hpet",
            ProbeResult::Unavailable,
            Some(leaks.join("; ")),
            "Legacy timer present; presence alone establishes neither wall time nor counter origin",
        )
    }
}

/// Probe 8: dmesg lines containing dates.
/// Flags recognized dates outside T_clock +/- one day, including build banners.
pub fn classify_dmesg_dates(
    dmesg_text: Option<&str>,
    access_denied: bool,
    expected_t_clock: Option<u64>,
) -> ProbeRecord {
    if access_denied {
        return ProbeRecord::new(
            "dmesg_dates",
            ProbeResult::Unavailable,
            None,
            "Kernel log access denied; not evidence of root isolation",
        );
    }

    let Some(text) = dmesg_text else {
        return ProbeRecord::new(
            "dmesg_dates",
            ProbeResult::Unavailable,
            None,
            "Kernel log unavailable",
        );
    };

    if text.len() > MAX_TEXT_BYTES {
        return ProbeRecord::new("dmesg_dates", ProbeResult::Error, None, "Text cap exceeded");
    }
    let expected_ymd = expected_t_clock
        .filter(|t| *t <= MAX_EPOCH)
        .map(unix_to_ymd);
    let mut suspicious_lines: Vec<String> = Vec::new();

    'lines: for raw_line in text.lines() {
        // Strip /dev/kmsg prefix ("prio,seq,timestamp,-;message") if present
        let msg = match raw_line.split_once(';') {
            Some((_, after)) => after,
            None => raw_line,
        };

        let Ok(dates) = find_dates_in_line(msg) else {
            return ProbeRecord::new(
                "dmesg_dates",
                ProbeResult::Error,
                None,
                "Date item cap exceeded",
            );
        };
        for (y, m, d) in dates {
            let allowed = match expected_ymd {
                Some((ey, em, ed)) => {
                    let found_days = ymd_to_days(y, m, d);
                    let exp_days = ymd_to_days(ey, em, ed);
                    found_days.abs_diff(exp_days) <= 1
                }
                None => y == 1970 && m == 1 && d == 1,
            };
            if !allowed {
                suspicious_lines.push(format!("date={y:04}-{m:02}-{d:02}"));
                if suspicious_lines.len() >= MAX_DATE_FINDINGS {
                    break 'lines;
                }
            }
        }
    }

    if suspicious_lines.is_empty() {
        ProbeRecord::new(
            "dmesg_dates",
            ProbeResult::Blocked,
            None,
            "No unpinned or real wall-clock dates found in kernel boot log",
        )
    } else {
        ProbeRecord::new(
            "dmesg_dates",
            ProbeResult::Leak,
            Some(suspicious_lines.join(" | ")),
            "Kernel boot log contains dates outside T_clock tolerance; build dates need substrate triage",
        )
    }
}

/// Probe 9: /sys/devices/system/clocksource/*/current_clocksource and available_clocksource.
pub fn classify_clocksource_sysfs(current: Option<&str>, available: Option<&str>) -> ProbeRecord {
    let Some(curr_raw) = current else {
        return ProbeRecord::new(
            "clocksource_sysfs",
            ProbeResult::Error,
            None,
            "Failed to read current_clocksource from sysfs",
        );
    };

    let curr = curr_raw.trim();
    let Some(avail) = available.map(str::trim).filter(|v| !v.is_empty()) else {
        return ProbeRecord::new(
            "clocksource_sysfs",
            ProbeResult::Error,
            None,
            "Available clocksources missing",
        );
    };
    let val = format!("current={curr},available={avail}");

    if curr != "tsc" {
        return ProbeRecord::new(
            "clocksource_sysfs",
            ProbeResult::Leak,
            Some(val),
            format!("Expected current_clocksource=tsc, got {curr}"),
        );
    }

    for cs in avail.split_whitespace() {
        if cs != "tsc" {
            return ProbeRecord::new(
                "clocksource_sysfs",
                ProbeResult::Leak,
                Some(val),
                format!("Forbidden clocksource '{cs}' listed in available_clocksource"),
            );
        }
    }

    ProbeRecord::new(
        "clocksource_sysfs",
        ProbeResult::Blocked,
        Some(val),
        "Current and available clocksource names match the inspected profile",
    )
}

/// Probe 10: POSIX clocks (CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_TAI).
pub fn classify_posix_clocks(
    realtime: Option<f64>,
    monotonic: Option<f64>,
    boottime: Option<f64>,
    tai: Option<f64>,
    expected_t_clock: Option<u64>,
) -> ProbeRecord {
    let (Some(rt), Some(mono), Some(boot)) = (realtime, monotonic, boottime) else {
        return ProbeRecord::new(
            "posix_clocks",
            ProbeResult::Error,
            None,
            "Failed to read core POSIX clocks via clock_gettime",
        );
    };

    if [rt, mono, boot].iter().any(|v| !v.is_finite() || *v < 0.0)
        || tai.is_some_and(|v| !v.is_finite() || v < 0.0)
    {
        return ProbeRecord::new(
            "posix_clocks",
            ProbeResult::Error,
            None,
            "Invalid clock value",
        );
    }
    let Some(t_clock) = expected_t_clock.filter(|t| *t <= MAX_EPOCH) else {
        return ProbeRecord::new(
            "posix_clocks",
            ProbeResult::Error,
            None,
            "Missing or invalid hermetic.t reference",
        );
    };
    let tai_text = tai
        .map(|v| format!("{v:.3}"))
        .unwrap_or_else(|| "unavailable".into());
    let summary = format!("realtime={rt:.3},monotonic={mono:.3},boottime={boot:.3},tai={tai_text}");

    let mut leaks = Vec::new();

    if let Some(tai_val) = tai.filter(|v| (*v - rt).abs() > 5.0) {
        leaks.push(format!(
            "CLOCK_TAI - CLOCK_REALTIME offset ({:.1}s) differs from the fixed guest TAI-offset policy",
            tai_val - rt
        ));
    }

    {
        let expected_rt = (t_clock as f64) + boot;
        if (rt - expected_rt).abs() > 60.0 {
            leaks.push(format!(
                "CLOCK_REALTIME ({rt:.1}s) differs from hermetic.t+boottime ({expected_rt:.1}s)"
            ));
        }
    }

    if leaks.is_empty() {
        ProbeRecord::new(
            "posix_clocks",
            if tai.is_some() { ProbeResult::Blocked } else { ProbeResult::Unavailable },
            Some(summary),
            "Sampled clocks checked against the configured epoch; missing TAI prevents full coverage",
        )
    } else {
        ProbeRecord::new(
            "posix_clocks",
            ProbeResult::Leak,
            Some(summary),
            leaks.join("; "),
        )
    }
}

/// Probe 11: VMClock device presence (/dev/vmclock*, ptp devices, ACPI VMCLOCK).
pub fn classify_vmclock(
    dev_vmclock_nodes: &[String],
    ptp_clocks: &[(String, String)], // (device_name, clock_name)
    acpi_vmclock_nodes: &[String],
) -> ProbeRecord {
    let mut leaks = Vec::new();
    if !dev_vmclock_nodes.is_empty() {
        leaks.push(format!("dev nodes: {}", dev_vmclock_nodes.join(",")));
    }
    for (dev, name) in ptp_clocks {
        let lower = name.trim().to_ascii_lowercase();
        if lower.contains("vmclock") || lower.contains("kvm") {
            leaks.push(format!("PTP device {dev} bound to {lower}"));
        }
    }

    if !leaks.is_empty() {
        return ProbeRecord::new(
            "vmclock",
            ProbeResult::Unavailable,
            Some(leaks.join("; ")),
            "VMClock or PTP interface present; no timestamp or ABI validity read was performed",
        );
    }

    let detail = if acpi_vmclock_nodes.is_empty() {
        "No /dev/vmclock*, PTP VMClock/KVM device, or VMClock ACPI node present".to_string()
    } else {
        format!(
            "ACPI firmware node(s) {:?} present without driver or /dev/vmclock* exposure",
            acpi_vmclock_nodes
        )
    };

    ProbeRecord::new("vmclock", ProbeResult::Blocked, None, detail)
}

/// Probe 12: /proc/cpuinfo model name and flags.
pub fn classify_cpuinfo(content: Option<&str>) -> ProbeRecord {
    let Some(text) = content.filter(|text| text.len() <= MAX_TEXT_BYTES) else {
        return ProbeRecord::new(
            "cpuinfo",
            ProbeResult::Error,
            None,
            "CPU information missing or over cap",
        );
    };
    let mut result = None;
    for section in text.split("\n\n").filter(|part| !part.trim().is_empty()) {
        let record = classify_cpuinfo_section(Some(section));
        if record.result == ProbeResult::Leak {
            return record;
        }
        if result
            .as_ref()
            .is_none_or(|r: &ProbeRecord| r.result != ProbeResult::Error)
        {
            result = Some(record);
        }
    }
    result.unwrap_or_else(|| {
        ProbeRecord::new("cpuinfo", ProbeResult::Error, None, "CPU information empty")
    })
}

fn classify_cpuinfo_section(content: Option<&str>) -> ProbeRecord {
    let Some(text) = content else {
        return ProbeRecord::new(
            "cpuinfo",
            ProbeResult::Error,
            None,
            "Failed to read /proc/cpuinfo",
        );
    };

    if text.len() > MAX_TEXT_BYTES {
        return ProbeRecord::new("cpuinfo", ProbeResult::Error, None, "Text cap exceeded");
    }
    let mut model_name: Option<String> = None;
    let mut flags: Option<String> = None;

    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim() {
                "model name" if model_name.is_none() => {
                    model_name = Some(v.trim().to_string());
                }
                "flags" if flags.is_none() => {
                    flags = Some(v.trim().to_string());
                }
                _ => {}
            }
        }
        if model_name.is_some() && flags.is_some() {
            break;
        }
    }

    if model_name.is_none() || flags.is_none() {
        return ProbeRecord::new(
            "cpuinfo",
            ProbeResult::Error,
            None,
            "CPU model or flags missing",
        );
    }
    let mut leaks = Vec::new();
    if let Some(ref model) = model_name {
        if model.trim() != BASELINE_BRAND {
            leaks.push(format!("unmasked host model name: {model}"));
        }
    }

    if let Some(ref fl) = flags {
        for flag in fl.split_whitespace() {
            const BASELINE_FLAGS: &[&str] = &[
                "fpu",
                "vme",
                "de",
                "pse",
                "tsc",
                "msr",
                "pae",
                "mce",
                "cx8",
                "apic",
                "sep",
                "mtrr",
                "pge",
                "mca",
                "cmov",
                "pat",
                "pse36",
                "clflush",
                "mmx",
                "fxsr",
                "sse",
                "sse2",
                "ht",
                "syscall",
                "nx",
                "lm",
                "constant_tsc",
                "nonstop_tsc",
                "tsc_reliable",
                "rep_good",
                "nopl",
                "xtopology",
                "cpuid",
                "tsc_known_freq",
                "pni",
                "ssse3",
                "cx16",
                "sse4_1",
                "sse4_2",
                "popcnt",
                "lahf_lm",
            ];
            if !BASELINE_FLAGS.contains(&flag) {
                leaks.push(format!("leaked flag: {flag}"));
            }
        }
    }

    let summary = format!(
        "model={},flags={}",
        model_name.as_deref().unwrap_or("<unknown>"),
        flags.as_deref().unwrap_or("<unknown>")
    );

    if leaks.is_empty() {
        ProbeRecord::new(
            "cpuinfo",
            ProbeResult::Blocked,
            Some(summary),
            "/proc/cpuinfo shows baseline CPU model and no kvmclock or post-cutoff ISA flags",
        )
    } else {
        ProbeRecord::new(
            "cpuinfo",
            ProbeResult::Leak,
            Some(summary),
            leaks.join("; "),
        )
    }
}

fn find_dates_in_line(line: &str) -> Result<Vec<(i32, u32, u32)>, ()> {
    let mut found = Vec::new();
    // Match YYYY-MM-DD
    for window in line.as_bytes().windows(10) {
        let candidate = std::str::from_utf8(window).ok();
        if let Some(text) = candidate {
            let mut parts = text.split('-');
            if let (Some(ys), Some(ms), Some(ds), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            {
                if ys.len() == 4 && ms.len() == 2 && ds.len() == 2 {
                    if let (Ok(y), Ok(m), Ok(d)) =
                        (ys.parse::<i32>(), ms.parse::<u32>(), ds.parse::<u32>())
                    {
                        if valid_date(y, m, d) {
                            if found.len() >= MAX_ITEMS {
                                return Err(());
                            }
                            found.push((y, m, d));
                        }
                    }
                }
            }
        }
    }

    // Match "Mon DD HH:MM:SS YYYY" or "Mon DD YYYY"
    let tokens: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
        .filter(|s| !s.is_empty())
        .collect();
    for idx in 0..tokens.len() {
        if let Some(month) = tokens.get(idx).and_then(|t| parse_month_abbrev(t)) {
            if idx + 2 < tokens.len() {
                if let Some(day) = tokens.get(idx + 1).and_then(|t| t.parse::<u32>().ok()) {
                    if (1..=31).contains(&day) {
                        for &cand in tokens.iter().skip(idx + 2).take(3) {
                            if cand.len() == 4 && cand.bytes().all(|b| b.is_ascii_digit()) {
                                if let Ok(year) = cand.parse::<i32>() {
                                    if valid_date(year, month, day) {
                                        if found.len() >= MAX_ITEMS {
                                            return Err(());
                                        }
                                        found.push((year, month, day));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(found)
}

fn parse_month_abbrev(tok: &str) -> Option<u32> {
    match tok {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

pub fn parse_iso_datetime_to_unix(dt: &str) -> Option<u64> {
    if dt.len() != 19 {
        return None;
    }
    let (date, time) = dt.split_once(' ')?;
    let mut d = date.split('-');
    let year = d.next()?.parse::<i32>().ok()?;
    let month = d.next()?.parse::<u32>().ok()?;
    let day = d.next()?.parse::<u32>().ok()?;
    if d.next().is_some() || !valid_date(year, month, day) {
        return None;
    }
    let mut t = time.split(':');
    let hour = t.next()?.parse::<u64>().ok()?;
    let minute = t.next()?.parse::<u64>().ok()?;
    let second = t.next()?.parse::<u64>().ok()?;
    if t.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    u64::try_from(ymd_to_days(year, month, day))
        .ok()?
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

fn valid_date(y: i32, m: u32, d: u32) -> bool {
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    (1970..=9999).contains(&y) && d >= 1 && d <= days
}

pub fn unix_to_ymd(unix_sec: u64) -> (i32, u32, u32) {
    // Civil-from-days algorithm (Howard Hinnant, public domain)
    let z = (unix_sec.min(MAX_EPOCH) / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

pub fn ymd_to_days(y: i32, m: u32, d: u32) -> i64 {
    if !valid_date(y, m, d) {
        return 0;
    }
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m_u = m as u64;
    let d_u = d as u64;
    let doy = (153 * (if m_u > 2 { m_u - 3 } else { m_u + 9 }) + 2) / 5 + d_u - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}
