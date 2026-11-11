use std::collections::HashSet;
use std::path::Path;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::scan::{Finding, ScanOptions, Severity};

/// PEP 503 normalisation: lowercase, with runs of `[-_.]` as a single `-`.
pub fn pep503_normalize(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !in_run {
                result.push('-');
                in_run = true;
            }
        } else {
            in_run = false;
            for lower in c.to_lowercase() {
                result.push(lower);
            }
        }
    }
    result
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pep440Version {
    pub release: Vec<u64>,
    pub dev: Option<String>,
}

/// Parse PEP 440 release segment and optional dev segment.
pub fn parse_pep440(version_str: &str) -> Option<Pep440Version> {
    let s = version_str.trim();
    if s.is_empty() {
        return None;
    }
    // Strip optional epoch (e.g. 1!2.3)
    let s = if let Some(idx) = s.find('!') {
        let epoch_part = &s[..idx];
        if !epoch_part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        &s[idx + 1..]
    } else {
        s
    };

    let mut release = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let num: u64 = s[start..i].parse().ok()?;
        release.push(num);

        if i < bytes.len() && bytes[i] == b'.' {
            if i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                i += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if release.is_empty() {
        return None;
    }

    let dev = if let Some(dev_idx) = s.find("dev") {
        let after_dev = &s[dev_idx + 3..];
        let mut dev_digits = String::new();
        for c in after_dev.chars() {
            if c.is_ascii_digit() {
                dev_digits.push(c);
            } else {
                break;
            }
        }
        if dev_digits.is_empty() {
            None
        } else {
            Some(dev_digits)
        }
    } else {
        None
    };

    Some(Pep440Version { release, dev })
}

fn parse_dev_date(dev: &str) -> Option<Date> {
    if dev.len() == 8 || dev.len() == 14 {
        let year: i32 = dev.get(0..4)?.parse().ok()?;
        let month_num: u8 = dev.get(4..6)?.parse().ok()?;
        let day: u8 = dev.get(6..8)?.parse().ok()?;
        let month = Month::try_from(month_num).ok()?;
        Date::from_calendar_date(year, month, day).ok()
    } else {
        None
    }
}

fn parse_dev_datetime(dev: &str) -> Option<OffsetDateTime> {
    if dev.len() == 14 {
        let year: i32 = dev.get(0..4)?.parse().ok()?;
        let month_num: u8 = dev.get(4..6)?.parse().ok()?;
        let day: u8 = dev.get(6..8)?.parse().ok()?;
        let hour: u8 = dev.get(8..10)?.parse().ok()?;
        let min: u8 = dev.get(10..12)?.parse().ok()?;
        let sec: u8 = dev.get(12..14)?.parse().ok()?;
        let month = Month::try_from(month_num).ok()?;
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let time = Time::from_hms(hour, min, sec).ok()?;
        Some(PrimitiveDateTime::new(date, time).assume_utc())
    } else {
        None
    }
}

/// Parse Name and Version headers from package metadata text.
pub fn parse_pkg_metadata(text: &str) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if line.is_empty() {
            // End of headers
            break;
        }
        if let Some(val) = line.strip_prefix("Name:") {
            name = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("name:") {
            name = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Version:") {
            version = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("version:") {
            version = Some(val.trim().to_string());
        }
    }
    (name, version)
}

/// Check if a path is a Python package metadata file:
/// `*.dist-info/METADATA`, `*.egg-info/PKG-INFO`, or any file named `PKG-INFO`.
pub fn is_pkg_metadata_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name == "METADATA" {
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|parent| parent.ends_with(".dist-info"))
    } else {
        file_name == "PKG-INFO"
    }
}

/// Check package metadata file for D5a target version leaks.
pub fn check_d5a_metadata(file_path: &Path, bytes: &[u8], opts: &ScanOptions) -> Vec<Finding> {
    if !is_pkg_metadata_file(file_path) {
        return Vec::new();
    }

    if opts.target_packages.is_empty() {
        return Vec::new();
    }

    let target_names: HashSet<String> = opts
        .target_packages
        .iter()
        .map(|n| pep503_normalize(n))
        .collect();

    let text = String::from_utf8_lossy(bytes);
    let (found_name, found_version) = parse_pkg_metadata(&text);

    let found_name = match found_name {
        Some(n) => n,
        None => return Vec::new(),
    };

    let norm_found = pep503_normalize(&found_name);
    if !target_names.contains(&norm_found) {
        return Vec::new();
    }

    let display_path = file_path.display().to_string();
    let found_v_str = match found_version {
        Some(v) => v,
        None => {
            return vec![Finding {
                detector: "D5a".into(),
                channel: "target_version_unknown".into(),
                path: display_path.clone(),
                visibility: opts.visibility,
                severity: Severity::Info,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "path: {}, found version: missing, task version: {}",
                    display_path,
                    opts.task_version.as_deref().unwrap_or("none")
                )],
            }];
        }
    };

    let task_v_str = match &opts.task_version {
        Some(tv) => tv.clone(),
        None => {
            // Task has no version: emit one info finding for each copy found
            return vec![Finding {
                detector: "D5a".into(),
                channel: "target_version_unknown".into(),
                path: display_path.clone(),
                visibility: opts.visibility,
                severity: Severity::Info,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "path: {}, found version: {}, task version: none",
                    display_path, found_v_str
                )],
            }];
        }
    };

    let found_pep = match parse_pep440(&found_v_str) {
        Some(p) => p,
        None => {
            return vec![Finding {
                detector: "D5a".into(),
                channel: "target_version_unknown".into(),
                path: display_path.clone(),
                visibility: opts.visibility,
                severity: Severity::Info,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "path: {}, found version: {}, task version: {}",
                    display_path, found_v_str, task_v_str
                )],
            }];
        }
    };

    let task_pep = match parse_pep440(&task_v_str) {
        Some(p) => p,
        None => {
            return vec![Finding {
                detector: "D5a".into(),
                channel: "target_version_unknown".into(),
                path: display_path.clone(),
                visibility: opts.visibility,
                severity: Severity::Info,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "path: {}, found version: {}, task version: {}",
                    display_path, found_v_str, task_v_str
                )],
            }];
        }
    };

    let k = task_pep.release.len();
    let mut found_prefix = found_pep.release[..k.min(found_pep.release.len())].to_vec();
    while found_prefix.len() < k {
        found_prefix.push(0);
    }

    if found_prefix > task_pep.release {
        return vec![Finding {
            detector: "D5a".into(),
            channel: "target_version".into(),
            path: display_path.clone(),
            visibility: opts.visibility,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec![format!(
                "path: {}, found version: {}, task version: {}",
                display_path, found_v_str, task_v_str
            )],
        }];
    }

    // Check .devN date against T_clock
    if let Some(ref dev_n) = found_pep.dev {
        if let Some(t_clock) = opts.t_clock {
            if dev_n.len() == 14 {
                if let Some(dt) = parse_dev_datetime(dev_n) {
                    if dt.date() > t_clock.date() || (dt.date() == t_clock.date() && dt > t_clock) {
                        return vec![Finding {
                            detector: "D5a".into(),
                            channel: "target_dev_date".into(),
                            path: display_path.clone(),
                            visibility: opts.visibility,
                            severity: Severity::Gate,
                            confidence: 1.0,
                            hunk: None,
                            evidence: vec![format!(
                                "path: {}, found version: {}, task version: {}",
                                display_path, found_v_str, task_v_str
                            )],
                        }];
                    }
                }
            } else if dev_n.len() == 8 {
                if let Some(d) = parse_dev_date(dev_n) {
                    if d > t_clock.date() {
                        return vec![Finding {
                            detector: "D5a".into(),
                            channel: "target_dev_date".into(),
                            path: display_path.clone(),
                            visibility: opts.visibility,
                            severity: Severity::Gate,
                            confidence: 1.0,
                            hunk: None,
                            evidence: vec![format!(
                                "path: {}, found version: {}, task version: {}",
                                display_path, found_v_str, task_v_str
                            )],
                        }];
                    }
                }
            }
        }
    }

    Vec::new()
}
