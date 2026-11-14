#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let mut leaves = Vec::new();
    for leaf in [0, 1, 7, 0xa, 0x15, 0x16]
        .into_iter()
        .chain(0x4000_0000..=0x4000_0010)
    {
        // Dump every requested query, including unadvertised hypervisor
        // leaves. Classification separately avoids interpreting unsupported
        // basic-leaf aliases as frequency data.
        if let Some((eax, ebx, ecx, edx)) = arch_x86::read_cpuid(leaf, 0) {
            leaves.push(CpuidLeafDump {
                leaf,
                subleaf: 0,
                eax,
                ebx,
                ecx,
                edx,
            });
        }
    }
    // All queried structured feature subleaves are bounded, independent of a
    // hostile maximum-subleaf value. The remaining leaves are explicitly
    // outside this diagnostic's identity-coverage claim.
    if cpuid(7, 0).is_some_and(|r| r.eax >= 1) {
        if let Some(r) = cpuid(7, 1) {
            leaves.push(r);
        }
    }
    classify::classify_cpuid(&leaves, brand().as_deref())
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
fn probe_rtc(sys: &Root, dev: &Root, expected: Option<u64>, boot: f64) -> io::Result<ProbeRecord> {
    let entries = optional(sys.list("class/rtc"))?.unwrap_or_default();
    let epoch = optional(sys.text("class/rtc/rtc0/since_epoch", MAX_SMALL_FILE_BYTES))?
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
        })
        .transpose()?;
    let date = optional(sys.text("class/rtc/rtc0/date", MAX_SMALL_FILE_BYTES))?;
    let time = optional(sys.text("class/rtc/rtc0/time", MAX_SMALL_FILE_BYTES))?;
    let dt = date
        .zip(time)
        .map(|(d, t)| format!("{} {}", d.trim(), t.trim()));
    Ok(classify::classify_rtc_sysfs_dev(
        &entries,
        epoch,
        dt.as_deref(),
        dev.present("rtc0")?,
        expected,
        boot,
    ))
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
fn probe_log(dev: &Root, expected: Option<u64>) -> io::Result<ProbeRecord> {
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
            Ok(0) => return Ok(classify::classify_dmesg_dates(Some(&log), false, expected)),
            Ok(n) => {
                if log.len().saturating_add(n) > MAX_DMESG_BYTES {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let bytes = record.get(..n).ok_or(io::ErrorKind::InvalidData)?;
                log.push_str(std::str::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData)?);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(classify::classify_dmesg_dates(Some(&log), false, expected))
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
fn probe_posix(proc: &Root, expected: Option<u64>) -> io::Result<ProbeRecord> {
    let rt = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::ErrorKind::InvalidData)?
        .as_secs_f64();
    let boot = uptime(proc)?;
    let Some(t) = expected else {
        return Ok(error("posix_clocks"));
    };
    let leaked = (rt - t as f64 - boot).abs() > classify::CLOCK_TOLERANCE_SECONDS;
    Ok(ProbeRecord::new("posix_clocks",if leaked { ProbeResult::Leak } else { ProbeResult::Unavailable },Some(format!("realtime={rt:.3},boottime={boot:.3}")),"Realtime checked against hermetic.t and guest boottime; CLOCK_MONOTONIC and CLOCK_TAI require an approved safe syscall wrapper"))
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
    vec![
        probe_rdtsc(boot),
        probe_cpuid(),
        checked("kvmclock_msr", probe_msr(&dev)),
        checked(
            "clock_pairing_hc",
            ptp_names.map(|v| classify::classify_clock_pairing(&v)),
        ),
        checked(
            "rtc_sysfs_dev",
            probe_rtc(&sys, &dev, expected, boot.unwrap_or(f64::NAN)),
        ),
        checked(
            "proc_driver_rtc",
            optional(proc.text("driver/rtc", MAX_SMALL_FILE_BYTES)).map(|v| {
                classify::classify_proc_driver_rtc(v.as_deref(), expected, boot.unwrap_or(f64::NAN))
            }),
        ),
        checked("hpet", probe_hpet(&sys, &dev)),
        checked("dmesg_dates", probe_log(&dev, expected)),
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
    ]
}
