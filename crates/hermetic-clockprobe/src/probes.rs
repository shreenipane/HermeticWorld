#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::arch_x86;
use crate::classify::{self, CpuidLeafDump, ProbeRecord, ProbeResult};
use crate::read::Root;

pub const MAX_SMALL_FILE_BYTES: u64 = 4096;
pub const MAX_CPUINFO_BYTES: u64 = 65_536;
pub const MAX_DMESG_BYTES: usize = 262_144;
pub const MAX_KMSG_RECORD_BYTES: usize = 8192;
pub const MAX_KMSG_RECORDS: usize = 512;
pub const TSC_SAMPLE_MILLIS: u64 = 20;
const KMSG_RDEV: u64 = (1 << 8) | 11;
const MSR_CPU0_RDEV: u64 = 202 << 8;

fn error(name: &str) -> ProbeRecord {
    ProbeRecord::new(
        name,
        ProbeResult::Error,
        None,
        "Inspection failed: invalid input, resource cap, or I/O failure",
    )
}
fn unavailable(name: &str, detail: &str) -> ProbeRecord {
    ProbeRecord::new(name, ProbeResult::Unavailable, None, detail)
}
fn optional<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn cpuid(leaf: u32, subleaf: u32) -> Option<CpuidLeafDump> {
    // CPUID outside a supported range can alias an unrelated leaf. Never
    // interpret such a result as a clock ratio or CPU frequency.
    let base = match leaf {
        0..=0x3fff_ffff => 0,
        0x4000_0000..=0x7fff_ffff => {
            if arch_x86::read_cpuid(1, 0)?.2 & (1 << 31) == 0 {
                return None;
            }
            0x4000_0000
        }
        _ => 0x8000_0000,
    };
    if leaf > arch_x86::read_cpuid(base, 0)?.0 {
        return None;
    }
    let (eax, ebx, ecx, edx) = arch_x86::read_cpuid(leaf, subleaf)?;
    Some(CpuidLeafDump {
        leaf,
        subleaf,
        eax,
        ebx,
        ecx,
        edx,
    })
}
fn brand() -> Option<String> {
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002..=0x8000_0004 {
        let r = cpuid(leaf, 0)?;
        for word in [r.eax, r.ebx, r.ecx, r.edx] {
            bytes.extend(word.to_le_bytes());
        }
    }
    let bytes: Vec<u8> = bytes.into_iter().take_while(|b| *b != 0).collect();
    String::from_utf8(bytes).ok()
}
fn probe_cpuid() -> ProbeRecord {
    arch_x86::with_pinned_cpu(sample_cpuid).unwrap_or_else(|_| error("cpuid"))
}
fn sample_cpuid() -> ProbeRecord {
    let mut leaves = Vec::new();
    for (leaf, subleaf) in crate::baseline::queries() {
        // Query the complete fixed profile, including zeroed PV leaves.
        if let Some((eax, ebx, ecx, edx)) = arch_x86::read_cpuid(leaf, subleaf) {
            leaves.push(CpuidLeafDump {
                leaf,
                subleaf,
                eax,
                ebx,
                ecx,
                edx,
            });
        }
    }
    crate::identity::inspect(&leaves, brand().as_deref())
}
fn probe_rdtsc(boot: Option<f64>) -> ProbeRecord {
    let start = Instant::now();
    let first = arch_x86::read_tsc();
    std::thread::sleep(Duration::from_millis(TSC_SAMPLE_MILLIS));
    let last = arch_x86::read_tsc();
    let elapsed = start.elapsed().as_secs_f64();
    let measured = first
        .zip(last)
        .and_then(|(a, b)| b.checked_sub(a))
        .and_then(|delta| {
            let hz = delta as f64 / elapsed;
            if hz.is_finite() && hz > 0.0 && hz <= u64::MAX as f64 {
                Some(hz as u64)
            } else {
                None
            }
        });
    let freq = classify::compute_tsc_freq_from_cpuid(cpuid(0x15, 0), None).or(measured);
    classify::classify_rdtsc(last, freq, boot)
}
fn probe_msr(dev: &Root) -> io::Result<ProbeRecord> {
    let Some(file) = optional(dev.device("cpu/0/msr", MSR_CPU0_RDEV))? else {
        return Ok(classify::classify_kvmclock_msr(false, None, &[], None));
    };
    let mut readable = Vec::new();
    for msr in [0x11, 0x12, 0x4b56_4d00, 0x4b56_4d01] {
        let mut bytes = [0u8; 8];
        match file.read_at(&mut bytes, u64::from(msr)) {
            Ok(8) => readable.push(msr),
            // Linux msr driver reports unsupported MSRs as EIO. This does
            // not prove WRMSR rejection. Do not turn other errors into passes.
            Err(e) if e.raw_os_error() == Some(5) => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
    Ok(classify::classify_kvmclock_msr(true, None, &readable, None))
}
fn ptp(sys: &Root) -> io::Result<Vec<(String, String)>> {
    let mut clocks = Vec::new();
    for ent in optional(sys.list("class/ptp"))?.unwrap_or_default() {
        let name = sys.text(&format!("class/ptp/{ent}/clock_name"), MAX_SMALL_FILE_BYTES)?;
        clocks.push((ent, name.trim().into()));
    }
    Ok(clocks)
}
/// Inspect every registered RTC; a hidden second RTC must not be skipped.
pub fn inspect_rtc(
    sys: &Root,
    dev: &Root,
    expected: Option<u64>,
    boot: f64,
) -> io::Result<ProbeRecord> {
    let entries = optional(sys.list("class/rtc"))?.unwrap_or_default();
    let unregistered_rtc0 = !entries.iter().any(|entry| entry == "rtc0") && dev.present("rtc0")?;
    let mut result =
        classify::classify_rtc_sysfs_dev(&[], None, None, unregistered_rtc0, expected, boot);
    for entry in entries {
        let epoch = optional(sys.text(
            &format!("class/rtc/{entry}/since_epoch"),
            MAX_SMALL_FILE_BYTES,
        ))?
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
        })
        .transpose()?;
        let date = optional(sys.text(&format!("class/rtc/{entry}/date"), MAX_SMALL_FILE_BYTES))?;
        let time = optional(sys.text(&format!("class/rtc/{entry}/time"), MAX_SMALL_FILE_BYTES))?;
        if date.is_some() != time.is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let dt = date
            .zip(time)
            .map(|(d, t)| format!("{} {}", d.trim(), t.trim()));
        let rec = classify::classify_rtc_sysfs_dev(
            std::slice::from_ref(&entry),
            epoch,
            dt.as_deref(),
            dev.present(&entry)?,
            expected,
            boot,
        );
        match rec.result {
            ProbeResult::Leak => return Ok(rec),
            ProbeResult::Error => result = rec,
            ProbeResult::Unavailable if result.result != ProbeResult::Error => result = rec,
            ProbeResult::Blocked | ProbeResult::Unavailable => {}
        }
    }
    Ok(result)
}
fn probe_hpet(sys: &Root, dev: &Root) -> io::Result<ProbeRecord> {
    let avail = sys.text(
        "devices/system/clocksource/clocksource0/available_clocksource",
        MAX_SMALL_FILE_BYTES,
    )?;
    let mut events = Vec::new();
    for ent in sys.list("devices/system/clockevents")? {
        if ent.starts_with("clockevent") {
            if let Some(value) = optional(sys.text(
                &format!("devices/system/clockevents/{ent}/current_device"),
                MAX_SMALL_FILE_BYTES,
            ))? {
                events.push(value);
            }
        }
    }
    Ok(classify::classify_hpet(
        dev.present("hpet")?,
        Some(&avail),
        &events,
    ))
}
fn probe_log(
    dev: &Root,
    expected: Option<u64>,
    bound: Option<(u32, u32, u32)>,
) -> io::Result<ProbeRecord> {
    let mut file = match dev.device("kmsg", KMSG_RDEV) {
        Ok(file) => file,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(unavailable(
                "dmesg_dates",
                "Kernel log cannot be inspected; root restrictions are not proof of isolation",
            ))
        }
        Err(e) => return Err(e),
    };
    let mut log = String::new();
    // /dev/kmsg requires a full record buffer, unlike a regular byte stream.
    let mut record = [0u8; MAX_KMSG_RECORD_BYTES];
    for _ in 0..MAX_KMSG_RECORDS {
        match file.read(&mut record) {
            Ok(0) => return Ok(classify::classify_dmesg_dates_with_substrate(Some(&log), false, expected, bound)),
            Ok(n) => {
                if log.len().saturating_add(n) > MAX_DMESG_BYTES {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let bytes = record.get(..n).ok_or(io::ErrorKind::InvalidData)?;
                log.push_str(std::str::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData)?);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(classify::classify_dmesg_dates_with_substrate(Some(&log), false, expected, bound))
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}
fn probe_vmclock(sys: &Root, dev: &Root) -> io::Result<ProbeRecord> {
    let nodes: Vec<String> = dev
        .list(".")?
        .into_iter()
        .filter(|n| n.starts_with("vmclock"))
        .collect();
    let acpi: Vec<String> = optional(sys.list("bus/acpi/devices"))?
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.starts_with("VMCLOCK") || n.starts_with("AMZNC10C"))
        .collect();
    Ok(classify::classify_vmclock(&nodes, &ptp(sys)?, &acpi))
}
/// Partial std-only clock read. std exposes realtime; /proc/uptime exposes
/// boottime. std cannot sample CLOCK_TAI or the absolute CLOCK_MONOTONIC value.
/// Never substitute one clock for another or claim complete clock coverage.
fn probe_posix(_proc: &Root, expected: Option<u64>) -> io::Result<ProbeRecord> {
    use arch_x86::{clock_seconds, CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_TAI};
    // Bracket the samples with BOOTTIME: a stop or scheduling delay between reads
    // would otherwise look like a clock offset. Retry a bounded number of times,
    // then report an inspection error rather than classify stale samples.
    for _ in 0..POSIX_SAMPLE_ATTEMPTS {
        let boot = clock_seconds(CLOCK_BOOTTIME);
        let mono = clock_seconds(CLOCK_MONOTONIC);
        let rt = clock_seconds(CLOCK_REALTIME);
        let tai = clock_seconds(CLOCK_TAI);
        let after = clock_seconds(CLOCK_BOOTTIME);
        if posix_sample_is_coherent(boot, after) {
            return Ok(classify::classify_posix_clocks(rt, mono, boot, tai, expected));
        }
    }
    Ok(error("posix_clocks"))
}
fn uptime(proc: &Root) -> io::Result<f64> {
    let text = proc.text("uptime", MAX_SMALL_FILE_BYTES)?;
    let boot = text
        .split_whitespace()
        .next()
        .and_then(|t| t.parse::<f64>().ok())
        .filter(|b| b.is_finite() && *b >= 0.0)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(boot)
}
fn checked(name: &str, result: io::Result<ProbeRecord>) -> ProbeRecord {
    result.unwrap_or_else(|_| error(name))
}

const POSIX_SAMPLE_ATTEMPTS: usize = 3;
/// Largest BOOTTIME span across one set of clock reads; far below the
/// classifier's tolerance, so a coherent sample cannot produce a false leak.
pub const MAX_POSIX_SAMPLE_SPAN_SECONDS: f64 = 1.0;

pub fn posix_sample_is_coherent(before: Option<f64>, after: Option<f64>) -> bool {
    matches!((before, after), (Some(b), Some(a))
        if b.is_finite() && a.is_finite() && a >= b && a - b <= MAX_POSIX_SAMPLE_SPAN_SECONDS)
}

/// Path, relative to /etc/hermetic, of the sealed newest substrate date.
pub const SUBSTRATE_BOUND_FILE: &str = "substrate-bound";

/// Absent: the strict rule applies (every date must be T_clock). Present but
/// malformed: an inspection error, never a silent fallback.
fn substrate_bound() -> io::Result<Option<(u32, u32, u32)>> {
    let root = match Root::new(Path::new("/etc/hermetic")) {
        Ok(root) => root,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match optional(root.text(SUBSTRATE_BOUND_FILE, 16))? {
        None => Ok(None),
        Some(text) => classify::parse_substrate_bound(&text)
            .map(Some)
            .ok_or_else(|| io::ErrorKind::InvalidData.into()),
    }
}

pub fn run_all_probes() -> Vec<ProbeRecord> {
    let (Ok(proc), Ok(sys), Ok(dev)) = (
        Root::new(Path::new("/proc")),
        Root::new(Path::new("/sys")),
        Root::new(Path::new("/dev")),
    ) else {
        return vec![error("inspection_roots")];
    };
    let cmdline = proc.text("cmdline", MAX_SMALL_FILE_BYTES);
    let expected = cmdline
        .as_deref()
        .ok()
        .and_then(classify::parse_hermetic_t_from_cmdline);
    let cpuinfo = proc.text("cpuinfo", MAX_CPUINFO_BYTES);
    let boot = uptime(&proc).ok();
    let ptp_names = ptp(&sys).map(|v| {
        v.into_iter()
            .filter(|(_, n)| n.to_ascii_lowercase().contains("kvm"))
            .map(|(d, n)| format!("{d}:{n}"))
            .collect::<Vec<_>>()
    });
    let mut records = vec![
        probe_rdtsc(boot),
        probe_cpuid(),
        checked("kvmclock_msr", probe_msr(&dev)),
        checked(
            "clock_pairing_hc",
            ptp_names.map(|v| classify::classify_clock_pairing(&v)),
        ),
        checked(
            "rtc_sysfs_dev",
            inspect_rtc(&sys, &dev, expected, boot.unwrap_or(f64::NAN)),
        ),
        checked(
            "proc_driver_rtc",
            optional(proc.text("driver/rtc", MAX_SMALL_FILE_BYTES)).map(|v| {
                classify::classify_proc_driver_rtc(v.as_deref(), expected, boot.unwrap_or(f64::NAN))
            }),
        ),
        checked("hpet", probe_hpet(&sys, &dev)),
        checked(
            "dmesg_dates",
            substrate_bound().and_then(|bound| probe_log(&dev, expected, bound)),
        ),
        checked(
            "clocksource_sysfs",
            (|| {
                let current = sys.text(
                    "devices/system/clocksource/clocksource0/current_clocksource",
                    MAX_SMALL_FILE_BYTES,
                )?;
                let avail = sys.text(
                    "devices/system/clocksource/clocksource0/available_clocksource",
                    MAX_SMALL_FILE_BYTES,
                )?;
                Ok(classify::classify_clocksource_sysfs(
                    Some(&current),
                    Some(&avail),
                ))
            })(),
        ),
        checked("posix_clocks", probe_posix(&proc, expected)),
        checked("vmclock", probe_vmclock(&sys, &dev)),
        checked(
            "cpuinfo",
            cpuinfo.map(|v| classify::classify_cpuinfo(Some(&v))),
        ),
    ];
    records.extend(crate::lockdown::run());
    records
}
