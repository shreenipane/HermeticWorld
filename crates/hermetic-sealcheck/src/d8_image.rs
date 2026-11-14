//! D8 kernel-image build strings and CPU-template coherence.
//!
//! Kernel images under `boot/` are read without following links and scanned
//! with the clock probe's own substrate-date parser, so the sealer and the
//! guest agree on which dates an image carries. The guest CPU is the fixed
//! baseline identity; its model must have been sold by `T_clock`.

use std::path::Path;
use time::{Date, Month, OffsetDateTime};

use crate::scan::{Finding, Severity, Visibility};
use hermetic_clockprobe::{baseline, classify};

pub const MAX_KERNEL_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_KERNEL_IMAGES: usize = 16;
const MAX_DATES_REPORTED: usize = 16;
const IMAGE_PREFIXES: &[&str] = &["vmlinuz", "vmlinux", "bzImage", "Image"];

/// Historical CPU policy: brand, CPUID signature (eax of leaf 1) and the date
/// the model was first sold.
pub const CPU_MODELS: &[(&str, u32, (i32, u8, u8))] = &[(
    "Intel(R) Xeon(R) CPU E5504 @ 2.00GHz",
    0x0001_06a5,
    (2009, 3, 30),
)];

fn finding(
    path: &str,
    channel: &str,
    visibility: Visibility,
    confidence: f64,
    ev: Vec<String>,
) -> Finding {
    Finding {
        detector: "D8".into(),
        channel: channel.into(),
        path: path.into(),
        visibility,
        severity: Severity::Info,
        confidence,
        hunk: None,
        evidence: ev,
    }
}

fn day(t: OffsetDateTime) -> (i32, u32, u32) {
    (t.year(), u32::from(u8::from(t.month())), u32::from(t.day()))
}

/// Dated build strings in one kernel image after `T_clock`, or a fail-closed
/// note when no date can be recovered.
pub fn check_kernel_image_bytes(
    rel: &str,
    image: &[u8],
    t_clock: OffsetDateTime,
    visibility: Visibility,
) -> Vec<Finding> {
    let Some(list) = classify::extract_substrate_dates(image) else {
        return vec![finding(
            rel,
            "d8_error",
            visibility,
            0.0,
            vec!["kernel image: no build-string date recovered (compressed, stripped or over the date cap)".into()],
        )];
    };
    let limit = day(t_clock);
    let late: Vec<String> = list
        .lines()
        .filter(|line| {
            classify::parse_substrate_dates(&format!("{line}\n"))
                .and_then(|s| s.into_iter().next())
                .is_some_and(|d| d > limit)
        })
        .take(MAX_DATES_REPORTED)
        .map(|d| format!("build-string date: {d}"))
        .collect();
    if late.is_empty() {
        return Vec::new();
    }
    let mut ev = late;
    ev.push(format!(
        "T_clock: {:04}-{:02}-{:02}",
        limit.0, limit.1, limit.2
    ));
    vec![finding(rel, "kernel_image", visibility, 1.0, ev)]
}

pub fn check_kernel_images(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let boot = root.join("boot");
    if !crate::safe_fs::is_dir(&boot) {
        return;
    }
    let entries = match crate::safe_fs::read_dir(&boot) {
        Ok(entries) => entries,
        Err(_) => {
            findings.push(finding(
                "boot",
                "d8_error",
                visibility,
                0.0,
                vec!["cannot read dir".into()],
            ));
            return;
        }
    };
    let mut seen = 0;
    for path in entries {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !IMAGE_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let rel = format!("boot/{name}");
        seen += 1;
        if seen > MAX_KERNEL_IMAGES {
            findings.push(finding(
                "boot",
                "d8_error",
                visibility,
                0.0,
                vec!["inspection incomplete: kernel image count cap exceeded".into()],
            ));
            return;
        }
        match crate::safe_fs::read(&path, MAX_KERNEL_IMAGE_BYTES) {
            Ok(bytes) => {
                findings.extend(check_kernel_image_bytes(&rel, &bytes, t_clock, visibility))
            }
            Err(_) => findings.push(finding(
                &rel,
                "d8_error",
                visibility,
                0.0,
                vec!["kernel image unreadable (link, special file or over the byte cap)".into()],
            )),
        }
    }
}

/// Coherence of a guest CPU identity with `T_clock` under the historical policy.
pub fn check_cpu_identity(
    brand: &str,
    signature: u32,
    t_clock: OffsetDateTime,
    visibility: Visibility,
) -> Vec<Finding> {
    const PATH: &str = "<cpu-template>";
    let Some(&(_, sig, (y, m, d))) = CPU_MODELS.iter().find(|(b, _, _)| *b == brand) else {
        return vec![finding(
            PATH,
            "cpu_template",
            visibility,
            0.0,
            vec!["CPU brand not in the historical CPU policy".into()],
        )];
    };
    if sig != signature {
        return vec![finding(
            PATH,
            "cpu_template",
            visibility,
            1.0,
            vec![format!(
                "CPUID signature {signature:#010x} does not match the brand ({sig:#010x})"
            )],
        )];
    }
    let sold = Month::try_from(m)
        .ok()
        .and_then(|month| Date::from_calendar_date(y, month, d).ok());
    match sold {
        Some(sold) if sold <= t_clock.date() => Vec::new(),
        Some(sold) => vec![finding(
            PATH,
            "cpu_template",
            visibility,
            1.0,
            vec![
                format!("CPU model first sold {sold}"),
                format!("T_clock: {}", t_clock.date()),
            ],
        )],
        None => vec![finding(
            PATH,
            "d8_error",
            visibility,
            0.0,
            vec!["invalid CPU policy date".into()],
        )],
    }
}

/// The world's own guest CPU: the fixed baseline every VM runs with.
pub fn check_cpu_template(t_clock: OffsetDateTime, visibility: Visibility) -> Vec<Finding> {
    check_cpu_identity(baseline::BRAND, baseline::SIGNATURE, t_clock, visibility)
}
