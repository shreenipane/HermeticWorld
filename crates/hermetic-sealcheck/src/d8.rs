use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::scan::{Finding, Severity, Visibility};

// ---------------------------------------------------------------------------
// Built-in tables: Distro releases
// ---------------------------------------------------------------------------

pub const UBUNTU_RELEASES: &[(&str, (i32, u8, u8))] = &[
    ("14.04", (2014, 4, 17)),
    ("14.10", (2014, 10, 23)),
    ("15.04", (2015, 4, 23)),
    ("15.10", (2015, 10, 22)),
    ("16.04", (2016, 4, 21)),
    ("16.10", (2016, 10, 13)),
    ("17.04", (2017, 4, 13)),
    ("17.10", (2017, 10, 19)),
    ("18.04", (2018, 4, 26)),
    ("18.10", (2018, 10, 18)),
    ("19.04", (2019, 4, 18)),
    ("19.10", (2019, 10, 17)),
    ("20.04", (2020, 4, 23)),
    ("20.10", (2020, 10, 22)),
    ("21.04", (2021, 4, 22)),
    ("21.10", (2021, 10, 14)),
    ("22.04", (2022, 4, 21)),
    ("22.10", (2022, 10, 20)),
    ("23.04", (2023, 4, 20)),
    ("23.10", (2023, 10, 12)),
    ("24.04", (2024, 4, 25)),
    ("24.10", (2024, 10, 10)),
    ("26.04", (2026, 4, 23)),
];

pub const DEBIAN_RELEASES: &[(&str, (i32, u8, u8))] = &[
    ("8", (2015, 4, 25)),
    ("9", (2017, 6, 17)),
    ("10", (2019, 7, 6)),
    ("11", (2021, 8, 14)),
    ("12", (2023, 6, 10)),
    ("13", (2025, 6, 1)),
];

pub const ALPINE_RELEASES: &[(&str, (i32, u8, u8))] = &[
    ("3.10", (2019, 6, 19)),
    ("3.11", (2019, 12, 19)),
    ("3.12", (2020, 5, 29)),
    ("3.13", (2021, 1, 14)),
    ("3.14", (2021, 6, 15)),
    ("3.15", (2021, 11, 24)),
    ("3.16", (2022, 5, 23)),
    ("3.17", (2022, 11, 22)),
    ("3.18", (2023, 5, 9)),
    ("3.19", (2023, 12, 7)),
    ("3.20", (2024, 5, 22)),
    ("3.21", (2024, 12, 5)),
];

pub const FEDORA_RELEASES: &[(&str, (i32, u8, u8))] = &[
    ("30", (2019, 4, 30)),
    ("31", (2019, 10, 29)),
    ("32", (2020, 4, 28)),
    ("33", (2020, 10, 27)),
    ("34", (2021, 4, 27)),
    ("35", (2021, 11, 2)),
    ("36", (2022, 5, 10)),
    ("37", (2022, 11, 15)),
    ("38", (2023, 4, 18)),
    ("39", (2023, 11, 7)),
    ("40", (2024, 4, 23)),
    ("41", (2024, 10, 29)),
];

pub const RHEL_FAMILY_RELEASES: &[(&str, (i32, u8, u8))] = &[
    ("7", (2014, 7, 7)),
    ("8", (2019, 5, 7)),
    ("9", (2022, 5, 17)),
    ("10", (2025, 5, 15)),
];

// ---------------------------------------------------------------------------
// Built-in tables: tzdata
// ---------------------------------------------------------------------------

pub const TZDATA_RELEASES: &[(&str, (i32, u8, u8))] = &[
    ("2014a", (2014, 3, 10)),
    ("2014b", (2014, 3, 24)),
    ("2014c", (2014, 5, 15)),
    ("2014d", (2014, 5, 28)),
    ("2014e", (2014, 6, 13)),
    ("2014f", (2014, 8, 8)),
    ("2014g", (2014, 8, 28)),
    ("2014h", (2014, 9, 25)),
    ("2014i", (2014, 10, 22)),
    ("2014j", (2014, 11, 10)),
    ("2015a", (2015, 1, 29)),
    ("2015b", (2015, 3, 20)),
    ("2015c", (2015, 4, 13)),
    ("2015d", (2015, 4, 24)),
    ("2015e", (2015, 6, 13)),
    ("2015f", (2015, 8, 10)),
    ("2015g", (2015, 10, 1)),
    ("2016a", (2016, 1, 27)),
    ("2016b", (2016, 3, 15)),
    ("2016c", (2016, 3, 23)),
    ("2016d", (2016, 4, 17)),
    ("2016e", (2016, 6, 14)),
    ("2016f", (2016, 7, 5)),
    ("2016g", (2016, 9, 28)),
    ("2016h", (2016, 10, 20)),
    ("2016i", (2016, 11, 1)),
    ("2016j", (2016, 11, 22)),
    ("2017a", (2017, 2, 28)),
    ("2017b", (2017, 3, 19)),
    ("2017c", (2017, 10, 20)),
    ("2018a", (2018, 1, 13)),
    ("2018b", (2018, 1, 18)),
    ("2018c", (2018, 1, 23)),
    ("2018d", (2018, 3, 22)),
    ("2018e", (2018, 5, 1)),
    ("2018f", (2018, 10, 18)),
    ("2018g", (2018, 10, 26)),
    ("2018h", (2018, 12, 23)),
    ("2018i", (2018, 12, 30)),
    ("2019a", (2019, 3, 25)),
    ("2019b", (2019, 7, 1)),
    ("2019c", (2019, 9, 11)),
    ("2020a", (2020, 4, 23)),
    ("2020b", (2020, 10, 6)),
    ("2020c", (2020, 10, 16)),
    ("2020d", (2020, 10, 21)),
    ("2020e", (2020, 12, 22)),
    ("2020f", (2020, 12, 29)),
    ("2021a", (2021, 1, 24)),
    ("2021b", (2021, 9, 24)),
    ("2021c", (2021, 10, 1)),
    ("2021d", (2021, 10, 15)),
    ("2021e", (2021, 10, 21)),
    ("2022a", (2022, 3, 15)),
    ("2022b", (2022, 8, 10)),
    ("2022c", (2022, 8, 15)),
    ("2022d", (2022, 9, 23)),
    ("2022e", (2022, 10, 11)),
    ("2022f", (2022, 10, 29)),
    ("2022g", (2022, 11, 29)),
    ("2023a", (2023, 3, 22)),
    ("2023b", (2023, 3, 24)),
    ("2023c", (2023, 3, 28)),
    ("2023d", (2023, 12, 22)),
    ("2024a", (2024, 2, 1)),
    ("2024b", (2024, 9, 4)),
    ("2025a", (2025, 1, 15)),
];

// ---------------------------------------------------------------------------
// Built-in tables: Linux mainline releases (4.0 onward)
// ---------------------------------------------------------------------------

pub type VersionPair = (u32, u32);
pub type ReleaseDate = (i32, u8, u8);

pub const KERNEL_RELEASES: &[(VersionPair, ReleaseDate)] = &[
    ((4, 0), (2015, 4, 12)),
    ((4, 1), (2015, 6, 22)),
    ((4, 2), (2015, 8, 30)),
    ((4, 3), (2015, 11, 1)),
    ((4, 4), (2016, 1, 10)),
    ((4, 5), (2016, 3, 13)),
    ((4, 6), (2016, 5, 15)),
    ((4, 7), (2016, 7, 24)),
    ((4, 8), (2016, 10, 2)),
    ((4, 9), (2016, 12, 11)),
    ((4, 10), (2017, 2, 19)),
    ((4, 11), (2017, 4, 30)),
    ((4, 12), (2017, 7, 2)),
    ((4, 13), (2017, 9, 3)),
    ((4, 14), (2017, 11, 12)),
    ((4, 15), (2018, 1, 28)),
    ((4, 16), (2018, 4, 1)),
    ((4, 17), (2018, 6, 3)),
    ((4, 18), (2018, 8, 12)),
    ((4, 19), (2018, 10, 22)),
    ((4, 20), (2018, 12, 23)),
    ((5, 0), (2019, 3, 3)),
    ((5, 1), (2019, 5, 5)),
    ((5, 2), (2019, 7, 7)),
    ((5, 3), (2019, 9, 15)),
    ((5, 4), (2019, 11, 24)),
    ((5, 5), (2020, 1, 26)),
    ((5, 6), (2020, 3, 29)),
    ((5, 7), (2020, 5, 31)),
    ((5, 8), (2020, 8, 2)),
    ((5, 9), (2020, 10, 11)),
    ((5, 10), (2020, 12, 13)),
    ((5, 11), (2021, 2, 14)),
    ((5, 12), (2021, 4, 25)),
    ((5, 13), (2021, 6, 27)),
    ((5, 14), (2021, 8, 29)),
    ((5, 15), (2021, 10, 31)),
    ((5, 16), (2022, 1, 9)),
    ((5, 17), (2022, 3, 20)),
    ((5, 18), (2022, 5, 22)),
    ((5, 19), (2022, 7, 31)),
    ((6, 0), (2022, 10, 2)),
    ((6, 1), (2022, 12, 11)),
    ((6, 2), (2023, 2, 19)),
    ((6, 3), (2023, 4, 23)),
    ((6, 4), (2023, 6, 25)),
    ((6, 5), (2023, 8, 27)),
    ((6, 6), (2023, 10, 29)),
    ((6, 7), (2024, 1, 7)),
    ((6, 8), (2024, 3, 17)),
    ((6, 9), (2024, 5, 12)),
    ((6, 10), (2024, 7, 14)),
    ((6, 11), (2024, 9, 15)),
    ((6, 12), (2024, 11, 17)),
    ((6, 13), (2025, 1, 19)),
];

// ---------------------------------------------------------------------------
// Built-in tables: CPython releases (3.6 onward)
// ---------------------------------------------------------------------------

pub const CPYTHON_RELEASES: &[(VersionPair, ReleaseDate)] = &[
    ((3, 6), (2016, 12, 23)),
    ((3, 7), (2018, 6, 27)),
    ((3, 8), (2019, 10, 14)),
    ((3, 9), (2020, 10, 5)),
    ((3, 10), (2021, 10, 4)),
    ((3, 11), (2022, 10, 24)),
    ((3, 12), (2023, 10, 2)),
    ((3, 13), (2024, 10, 7)),
    ((3, 14), (2025, 10, 1)),
];

// ---------------------------------------------------------------------------
// Date formatting helper
// ---------------------------------------------------------------------------

fn make_date(y: i32, m: u8, d: u8) -> Option<OffsetDateTime> {
    let month = Month::try_from(m).ok()?;
    let date = Date::from_calendar_date(y, month, d).ok()?;
    Some(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc())
}

fn format_dt(dt: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn truncate_200(s: &str) -> String {
    if s.chars().count() <= 200 {
        s.to_string()
    } else {
        s.chars().take(200).collect()
    }
}

fn read_file_capped(path: &Path, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    Read::take(&mut file, max_bytes).read_to_end(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Channel 1: os_release
// ---------------------------------------------------------------------------

pub fn lookup_distro_date(id: &str, version_id: &str) -> Option<OffsetDateTime> {
    let id_norm = id.trim().to_ascii_lowercase();
    let v_norm = version_id.trim();

    match id_norm.as_str() {
        "ubuntu" => {
            for (ver, (y, m, d)) in UBUNTU_RELEASES {
                if v_norm == *ver || v_norm.starts_with(&format!("{}.", ver)) {
                    return make_date(*y, *m, *d);
                }
            }
        }
        "debian" => {
            for (ver, (y, m, d)) in DEBIAN_RELEASES {
                if v_norm == *ver || v_norm.starts_with(&format!("{}.", ver)) {
                    return make_date(*y, *m, *d);
                }
            }
        }
        "alpine" => {
            for (ver, (y, m, d)) in ALPINE_RELEASES {
                if v_norm == *ver || v_norm.starts_with(&format!("{}.", ver)) {
                    return make_date(*y, *m, *d);
                }
            }
        }
        "fedora" => {
            for (ver, (y, m, d)) in FEDORA_RELEASES {
                if v_norm == *ver || v_norm.starts_with(&format!("{}.", ver)) {
                    return make_date(*y, *m, *d);
                }
            }
        }
        "centos" | "rhel" | "rocky" | "almalinux" | "alma" => {
            for (ver, (y, m, d)) in RHEL_FAMILY_RELEASES {
                if v_norm == *ver || v_norm.starts_with(&format!("{}.", ver)) {
                    return make_date(*y, *m, *d);
                }
            }
        }
        _ => {}
    }
    None
}

fn check_os_release(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let targets = ["etc/os-release", "usr/lib/os-release"];
    for rel_path in targets {
        let full_path = root.join(rel_path);
        let bytes = match read_file_capped(&full_path, 1024 * 1024) {
            Ok(b) => b,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "d8_error".into(),
                        path: full_path.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("cannot read file: {e}")],
                    });
                }
                continue;
            }
        };

        let content = String::from_utf8_lossy(&bytes);
        let mut id = None;
        let mut version_id = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim();
                let mut val = trimmed[eq_pos + 1..].trim();
                if val.len() >= 2
                    && ((val.starts_with('"') && val.ends_with('"'))
                        || (val.starts_with('\'') && val.ends_with('\'')))
                {
                    val = &val[1..val.len() - 1];
                }
                if key == "ID" {
                    id = Some(val.to_string());
                } else if key == "VERSION_ID" {
                    version_id = Some(val.to_string());
                }
            }
        }

        if let (Some(id_str), Some(v_str)) = (id, version_id) {
            if let Some(rel_dt) = lookup_distro_date(&id_str, &v_str) {
                if rel_dt > t_clock {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "os_release".into(),
                        path: full_path.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.5,
                        hunk: None,
                        evidence: vec![
                            format!("os-release: ID=\"{}\", VERSION_ID=\"{}\"", id_str, v_str),
                            format!("implied release date: {}", format_dt(rel_dt)),
                            format!("T_clock: {}", format_dt(t_clock)),
                        ],
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channel 2: tzdata
// ---------------------------------------------------------------------------

fn parse_tzdata_version(s: &str) -> Option<(u32, &str)> {
    let trimmed = s.trim();
    if trimmed.len() < 5 {
        return None;
    }
    let (year_str, suffix) = trimmed.split_at(4);
    let year: u32 = year_str.parse().ok()?;
    if !suffix.chars().all(|c| c.is_ascii_lowercase()) || suffix.is_empty() {
        return None;
    }
    Some((year, suffix))
}

fn check_tzdata(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let zi_path = root.join("usr/share/zoneinfo/tzdata.zi");
    let version_path = root.join("usr/share/zoneinfo/+VERSION");

    let targets = [(zi_path, true), (version_path, false)];

    for (full_path, is_zi) in targets {
        let bytes = match read_file_capped(&full_path, 64 * 1024) {
            Ok(b) => b,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "d8_error".into(),
                        path: full_path.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("cannot read file: {e}")],
                    });
                }
                continue;
            }
        };

        let content = String::from_utf8_lossy(&bytes);
        let first_line = content.lines().next().unwrap_or("").trim();
        let ver_str = if is_zi {
            if let Some(rest) = first_line.strip_prefix("# version ") {
                rest.trim()
            } else {
                continue;
            }
        } else {
            first_line
        };

        if let Some((year, suffix)) = parse_tzdata_version(ver_str) {
            // Check in table
            let mut found_in_table = false;
            for (table_ver, (y, m, d)) in TZDATA_RELEASES {
                if ver_str == *table_ver {
                    found_in_table = true;
                    if let Some(rel_dt) = make_date(*y, *m, *d) {
                        if rel_dt > t_clock {
                            findings.push(Finding {
                                detector: "D8".into(),
                                channel: "tzdata".into(),
                                path: full_path.display().to_string(),
                                visibility,
                                severity: Severity::Info,
                                confidence: 1.0,
                                hunk: None,
                                evidence: vec![
                                    format!("tzdata version {}", ver_str),
                                    format!("implied release date: {}", format_dt(rel_dt)),
                                    format!("T_clock: {}", format_dt(t_clock)),
                                ],
                            });
                        }
                    }
                    break;
                }
            }

            if !found_in_table {
                // Check if newer than every table entry
                // Newest entry in TZDATA_RELEASES is 2025a
                let newest = TZDATA_RELEASES.last();
                if let Some((newest_ver, (ny, _, _))) = newest {
                    let newest_suffix = &newest_ver[4..];
                    let is_newer =
                        year > (*ny as u32) || (year == (*ny as u32) && suffix > newest_suffix);
                    if is_newer {
                        findings.push(Finding {
                            detector: "D8".into(),
                            channel: "tzdata".into(),
                            path: full_path.display().to_string(),
                            visibility,
                            severity: Severity::Info,
                            confidence: 0.5,
                            hunk: None,
                            evidence: vec![
                                format!("tzdata version {}", ver_str),
                                "newer than the built-in table".to_string(),
                                format!("T_clock: {}", format_dt(t_clock)),
                            ],
                        });
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channel 3: ca_bundle (PEM & minimal DER parser)
// ---------------------------------------------------------------------------

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut clean = Vec::with_capacity(input.len());
    for &b in input {
        if !b.is_ascii_whitespace() {
            clean.push(b);
        }
    }
    if clean.is_empty() {
        return Some(Vec::new());
    }
    if clean.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.as_chunks::<4>().0 {
        let b0 = b64_val(chunk[0])?;
        let b1 = b64_val(chunk[1])?;
        if chunk[2] == b'=' {
            if chunk[3] != b'=' {
                return None;
            }
            out.push((b0 << 2) | (b1 >> 4));
        } else if chunk[3] == b'=' {
            let b2 = b64_val(chunk[2])?;
            out.push((b0 << 2) | (b1 >> 4));
            out.push((b1 << 4) | (b2 >> 2));
        } else {
            let b2 = b64_val(chunk[2])?;
            let b3 = b64_val(chunk[3])?;
            out.push((b0 << 2) | (b1 >> 4));
            out.push((b1 << 4) | (b2 >> 2));
            out.push((b2 << 6) | b3);
        }
    }
    Some(out)
}

struct Tlv<'a> {
    tag: u8,
    data: &'a [u8],
}

fn read_tlv(slice: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    if slice.is_empty() {
        return None;
    }
    let tag = slice[0];
    if slice.len() < 2 {
        return None;
    }
    let len_byte = slice[1];
    let (length, header_len) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else if len_byte == 0x80 {
        // Indefinite length is forbidden in DER
        return None;
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 || slice.len() < 2 + num_octets {
            return None;
        }
        let mut len = 0usize;
        for &b in &slice[2..2 + num_octets] {
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        (len, 2 + num_octets)
    };
    let total_len = header_len.checked_add(length)?;
    if slice.len() < total_len {
        return None;
    }
    Some((
        Tlv {
            tag,
            data: &slice[header_len..total_len],
        },
        &slice[total_len..],
    ))
}

fn parse_2digits(slice: &[u8]) -> Option<u8> {
    if slice.len() < 2 || !slice[0].is_ascii_digit() || !slice[1].is_ascii_digit() {
        return None;
    }
    Some((slice[0] - b'0') * 10 + (slice[1] - b'0'))
}

fn parse_4digits(slice: &[u8]) -> Option<i32> {
    if slice.len() < 4
        || !slice[0].is_ascii_digit()
        || !slice[1].is_ascii_digit()
        || !slice[2].is_ascii_digit()
        || !slice[3].is_ascii_digit()
    {
        return None;
    }
    let d0 = (slice[0] - b'0') as i32;
    let d1 = (slice[1] - b'0') as i32;
    let d2 = (slice[2] - b'0') as i32;
    let d3 = (slice[3] - b'0') as i32;
    Some(d0 * 1000 + d1 * 100 + d2 * 10 + d3)
}

fn parse_asn1_time(tlv: &Tlv) -> Option<OffsetDateTime> {
    match tlv.tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ or YYMMDDHHMMZ
            let d = tlv.data;
            if d.len() < 10 {
                return None;
            }
            let y_2d = parse_2digits(&d[0..2])?;
            let year = if y_2d >= 50 {
                1900 + y_2d as i32
            } else {
                2000 + y_2d as i32
            };
            let m_num = parse_2digits(&d[2..4])?;
            let day = parse_2digits(&d[4..6])?;
            let hour = parse_2digits(&d[6..8])?;
            let min = parse_2digits(&d[8..10])?;
            let sec = if d.len() >= 12 && d[10].is_ascii_digit() {
                parse_2digits(&d[10..12])?
            } else {
                0
            };
            let month = Month::try_from(m_num).ok()?;
            let date = Date::from_calendar_date(year, month, day).ok()?;
            let time = Time::from_hms(hour, min, sec).ok()?;
            Some(PrimitiveDateTime::new(date, time).assume_utc())
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            let d = tlv.data;
            if d.len() < 12 {
                return None;
            }
            let year = parse_4digits(&d[0..4])?;
            let m_num = parse_2digits(&d[4..6])?;
            let day = parse_2digits(&d[6..8])?;
            let hour = parse_2digits(&d[8..10])?;
            let min = parse_2digits(&d[10..12])?;
            let sec = if d.len() >= 14 && d[12].is_ascii_digit() {
                parse_2digits(&d[12..14])?
            } else {
                0
            };
            let month = Month::try_from(m_num).ok()?;
            let date = Date::from_calendar_date(year, month, day).ok()?;
            let time = Time::from_hms(hour, min, sec).ok()?;
            Some(PrimitiveDateTime::new(date, time).assume_utc())
        }
        _ => None,
    }
}

fn extract_subject_cn(subject_data: &[u8]) -> Option<String> {
    let mut rest = subject_data;
    while let Some((rdn_set, next_rdns)) = read_tlv(rest) {
        rest = next_rdns;
        let mut set_rest = rdn_set.data;
        while let Some((attr_seq, next_attrs)) = read_tlv(set_rest) {
            set_rest = next_attrs;
            if let Some((oid_tlv, val_rest)) = read_tlv(attr_seq.data) {
                // OID 2.5.4.3 for id-at-commonName is [0x55, 0x04, 0x03]
                if oid_tlv.tag == 0x06 && oid_tlv.data == [0x55, 0x04, 0x03] {
                    if let Some((val_tlv, _)) = read_tlv(val_rest) {
                        return Some(String::from_utf8_lossy(val_tlv.data).into_owned());
                    }
                }
            }
        }
    }
    None
}

pub fn parse_cert_der(der: &[u8]) -> Option<(OffsetDateTime, Option<String>)> {
    let (cert_seq, _) = read_tlv(der)?;
    if cert_seq.tag != 0x30 {
        return None;
    }
    let (tbs_seq, _) = read_tlv(cert_seq.data)?;
    if tbs_seq.tag != 0x30 {
        return None;
    }

    let mut tbs_rest = tbs_seq.data;
    let (first_elem, rest) = read_tlv(tbs_rest)?;
    tbs_rest = rest;

    // Optional version [0] EXPLICIT
    let (_serial_elem, rest) = if first_elem.tag == 0xA0 {
        read_tlv(tbs_rest)?
    } else {
        (first_elem, tbs_rest)
    };
    tbs_rest = rest;

    // signature: AlgorithmIdentifier (tag 0x30)
    let (_, rest) = read_tlv(tbs_rest)?;
    tbs_rest = rest;

    // issuer: Name (tag 0x30)
    let (_, rest) = read_tlv(tbs_rest)?;
    tbs_rest = rest;

    // validity: Validity (tag 0x30)
    let (validity, rest) = read_tlv(tbs_rest)?;
    tbs_rest = rest;
    if validity.tag != 0x30 {
        return None;
    }

    // subject: Name (tag 0x30)
    let subject = read_tlv(tbs_rest).map(|(s, _)| s);

    // Parse notBefore in validity
    let (not_before_tlv, _) = read_tlv(validity.data)?;
    let not_before = parse_asn1_time(&not_before_tlv)?;

    let cn = subject.and_then(|s| extract_subject_cn(s.data));

    Some((not_before, cn))
}

fn check_ca_bundle(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let mut cert_files: Vec<PathBuf> = Vec::new();

    let p1 = root.join("etc/ssl/certs/ca-certificates.crt");
    if p1.is_file() {
        cert_files.push(p1);
    }
    let p2 = root.join("etc/pki/tls/certs/ca-bundle.crt");
    if p2.is_file() {
        cert_files.push(p2);
    }

    let cert_dir = root.join("etc/ssl/certs");
    if cert_dir.is_dir() {
        match std::fs::read_dir(&cert_dir) {
            Ok(entries) => {
                let mut dir_files = Vec::new();
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                            if ext == "pem" || ext == "crt" {
                                dir_files.push(path);
                            }
                        }
                    }
                }
                dir_files.sort();
                for path in dir_files.into_iter().take(2000) {
                    if !cert_files.contains(&path) {
                        cert_files.push(path);
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "d8_error".into(),
                        path: cert_dir.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("cannot read dir: {e}")],
                    });
                }
            }
        }
    }

    let begin_marker = b"-----BEGIN ";
    let end_marker = b"-----END ";

    for file_path in cert_files {
        let bytes = match read_file_capped(&file_path, 16 * 1024 * 1024) {
            Ok(b) => b,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "d8_error".into(),
                        path: file_path.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("cannot read file: {e}")],
                    });
                }
                continue;
            }
        };

        let mut offset = 0;
        let mut block_idx = 0usize;

        while offset < bytes.len() && block_idx < 500 {
            let rem = &bytes[offset..];
            let begin_pos = match rem
                .windows(begin_marker.len())
                .position(|w| w == begin_marker)
            {
                Some(p) => offset + p,
                None => break,
            };

            // Find newline after -----BEGIN ...-----
            let line_end = match bytes[begin_pos..].iter().position(|&b| b == b'\n') {
                Some(p) => begin_pos + p + 1,
                None => break,
            };

            // Find -----END
            let end_pos = match bytes[line_end..]
                .windows(end_marker.len())
                .position(|w| w == end_marker)
            {
                Some(p) => line_end + p,
                None => break,
            };

            // Advance offset past the END marker line
            let next_offset = match bytes[end_pos..].iter().position(|&b| b == b'\n') {
                Some(p) => end_pos + p + 1,
                None => bytes.len(),
            };
            offset = next_offset;

            block_idx += 1;
            let b64_bytes = &bytes[line_end..end_pos];
            if let Some(der) = base64_decode(b64_bytes) {
                if let Some((not_before, maybe_cn)) = parse_cert_der(&der) {
                    if not_before > t_clock {
                        let mut ev = Vec::new();
                        if let Some(cn) = maybe_cn {
                            ev.push(format!("certificate CN: {}", cn));
                        } else {
                            ev.push(format!("certificate block #{}", block_idx));
                        }
                        ev.push(format!("notBefore: {}", format_dt(not_before)));
                        ev.push(format!("T_clock: {}", format_dt(t_clock)));

                        findings.push(Finding {
                            detector: "D8".into(),
                            channel: "ca_bundle".into(),
                            path: file_path.display().to_string(),
                            visibility,
                            severity: Severity::Info,
                            confidence: 1.0,
                            hunk: None,
                            evidence: ev,
                        });
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channel 4: kernel
// ---------------------------------------------------------------------------

pub fn parse_kernel_version(s: &str) -> Option<(u32, u32)> {
    for token in s.split_whitespace() {
        let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        if let Some(start) = trimmed.find(|c: char| c.is_ascii_digit()) {
            let rem = &trimmed[start..];
            if let Some(dot_idx) = rem.find('.') {
                if let Ok(major) = rem[..dot_idx].parse::<u32>() {
                    let rem2 = &rem[dot_idx + 1..];
                    let end_minor = rem2
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(rem2.len());
                    if end_minor > 0 {
                        if let Ok(minor) = rem2[..end_minor].parse::<u32>() {
                            return Some((major, minor));
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn lookup_kernel_date(major: u32, minor: u32) -> Option<OffsetDateTime> {
    for ((maj, min), (y, m, d)) in KERNEL_RELEASES {
        if *maj == major && *min == minor {
            return make_date(*y, *m, *d);
        }
    }
    None
}

fn check_kernel(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let module_dirs = ["lib/modules", "usr/lib/modules"];
    for m_dir_rel in module_dirs {
        let m_dir = root.join(m_dir_rel);
        if m_dir.is_dir() {
            match std::fs::read_dir(&m_dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                if let Some((maj, min)) = parse_kernel_version(name) {
                                    if let Some(rel_dt) = lookup_kernel_date(maj, min) {
                                        if rel_dt > t_clock {
                                            findings.push(Finding {
                                                detector: "D8".into(),
                                                channel: "kernel".into(),
                                                path: path.display().to_string(),
                                                visibility,
                                                severity: Severity::Info,
                                                confidence: 0.5,
                                                hunk: None,
                                                evidence: vec![
                                                    format!("kernel version {}.{}", maj, min),
                                                    format!(
                                                        "implied release date: {}",
                                                        format_dt(rel_dt)
                                                    ),
                                                    format!("T_clock: {}", format_dt(t_clock)),
                                                ],
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        findings.push(Finding {
                            detector: "D8".into(),
                            channel: "d8_error".into(),
                            path: m_dir.display().to_string(),
                            visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("cannot read dir: {e}")],
                        });
                    }
                }
            }
        }
    }

    let boot_dir = root.join("boot");
    if boot_dir.is_dir() {
        match std::fs::read_dir(&boot_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                            if fname.starts_with("config-") {
                                match read_file_capped(&path, 4 * 1024 * 1024) {
                                    Ok(bytes) => {
                                        let content = String::from_utf8_lossy(&bytes);
                                        let mut flagged_version = false;
                                        for line in content.lines() {
                                            let trimmed = line.trim();
                                            // Check header e.g. "# Linux/x86 6.8.0 Kernel Configuration"
                                            if !flagged_version
                                                && trimmed.starts_with("# Linux/")
                                                && trimmed.contains("Kernel Configuration")
                                            {
                                                if let Some((maj, min)) =
                                                    parse_kernel_version(trimmed)
                                                {
                                                    if let Some(rel_dt) =
                                                        lookup_kernel_date(maj, min)
                                                    {
                                                        if rel_dt > t_clock {
                                                            flagged_version = true;
                                                            findings.push(Finding {
                                                                detector: "D8".into(),
                                                                channel: "kernel".into(),
                                                                path: path.display().to_string(),
                                                                visibility,
                                                                severity: Severity::Info,
                                                                confidence: 0.5,
                                                                hunk: None,
                                                                evidence: vec![
                                                                    format!(
                                                                        "kernel version {}.{}",
                                                                        maj, min
                                                                    ),
                                                                    format!(
                                                                        "implied release date: {}",
                                                                        format_dt(rel_dt)
                                                                    ),
                                                                    format!(
                                                                        "T_clock: {}",
                                                                        format_dt(t_clock)
                                                                    ),
                                                                ],
                                                            });
                                                        }
                                                    }
                                                }
                                            }

                                            // Check Compiler: ... (date) or build-date lines
                                            if (trimmed.contains("Compiler:")
                                                || trimmed.contains("build date")
                                                || trimmed.contains("built on"))
                                                && (trimmed.contains('2') || trimmed.contains('1'))
                                            {
                                                if let Some(ts) =
                                                    find_timestamp_in_line(trimmed.as_bytes())
                                                {
                                                    if ts > t_clock {
                                                        findings.push(Finding {
                                                            detector: "D8".into(),
                                                            channel: "kernel".into(),
                                                            path: path.display().to_string(),
                                                            visibility,
                                                            severity: Severity::Info,
                                                            confidence: 1.0,
                                                            hunk: None,
                                                            evidence: vec![
                                                                format!(
                                                                    "kernel build timestamp: {}",
                                                                    format_dt(ts)
                                                                ),
                                                                format!(
                                                                    "line: {}",
                                                                    truncate_200(trimmed)
                                                                ),
                                                                format!(
                                                                    "T_clock: {}",
                                                                    format_dt(t_clock)
                                                                ),
                                                            ],
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if e.kind() != std::io::ErrorKind::NotFound {
                                            findings.push(Finding {
                                                detector: "D8".into(),
                                                channel: "d8_error".into(),
                                                path: path.display().to_string(),
                                                visibility,
                                                severity: Severity::Info,
                                                confidence: 0.0,
                                                hunk: None,
                                                evidence: vec![format!("cannot read file: {e}")],
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "d8_error".into(),
                        path: boot_dir.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("cannot read dir: {e}")],
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channel 5: dated_log
// ---------------------------------------------------------------------------

fn match_syslog_month(bytes: &[u8]) -> Option<(Month, usize)> {
    if bytes.len() < 3 {
        return None;
    }
    let m = match &bytes[..3] {
        b"Jan" => Month::January,
        b"Feb" => Month::February,
        b"Mar" => Month::March,
        b"Apr" => Month::April,
        b"May" => Month::May,
        b"Jun" => Month::June,
        b"Jul" => Month::July,
        b"Aug" => Month::August,
        b"Sep" => Month::September,
        b"Oct" => Month::October,
        b"Nov" => Month::November,
        b"Dec" => Month::December,
        _ => return None,
    };
    Some((m, 3))
}

fn find_4digit_year_on_line(bytes: &[u8], exclude_start: usize, exclude_end: usize) -> Option<i32> {
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if i >= exclude_start && i < exclude_end {
            i += 1;
            continue;
        }
        let prev_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
        let next_ok = i + 4 == bytes.len() || !bytes[i + 4].is_ascii_digit();
        if prev_ok && next_ok {
            if let Some(y) = parse_4digits(&bytes[i..i + 4]) {
                if (1970..=2100).contains(&y) {
                    return Some(y);
                }
            }
        }
        i += 1;
    }
    None
}

pub fn find_timestamp_in_line(bytes: &[u8]) -> Option<OffsetDateTime> {
    let mut best_ts: Option<OffsetDateTime> = None;

    let update = |best: &mut Option<OffsetDateTime>, candidate: OffsetDateTime| match best {
        Some(curr) => {
            if candidate > *curr {
                *best = Some(candidate);
            }
        }
        None => *best = Some(candidate),
    };

    let len = bytes.len();
    let mut i = 0;
    while i < len {
        // 1. Try ISO date or apt Start-Date/End-Date format: YYYY-MM-DD[ T ]HH:MM:SS
        if i + 10 <= len {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            if prev_ok {
                if let Some(year) = parse_4digits(&bytes[i..i + 4]) {
                    if (1970..=2100).contains(&year) && bytes[i + 4] == b'-' {
                        if let Some(m_num) = parse_2digits(&bytes[i + 5..i + 7]) {
                            if bytes[i + 7] == b'-' {
                                if let Some(day) = parse_2digits(&bytes[i + 8..i + 10]) {
                                    // Separator: '  ' (two spaces) or 'T' or ' ' (one space)
                                    let mut time_start = None;
                                    if i + 20 <= len
                                        && bytes[i + 10] == b' '
                                        && bytes[i + 11] == b' '
                                    {
                                        time_start = Some(i + 12);
                                    } else if i + 19 <= len
                                        && (bytes[i + 10] == b'T' || bytes[i + 10] == b' ')
                                    {
                                        time_start = Some(i + 11);
                                    }

                                    if let Some(ts_idx) = time_start {
                                        if ts_idx + 8 <= len {
                                            if let Some(hour) =
                                                parse_2digits(&bytes[ts_idx..ts_idx + 2])
                                            {
                                                if bytes[ts_idx + 2] == b':' {
                                                    if let Some(min) = parse_2digits(
                                                        &bytes[ts_idx + 3..ts_idx + 5],
                                                    ) {
                                                        if bytes[ts_idx + 5] == b':' {
                                                            if let Some(sec) = parse_2digits(
                                                                &bytes[ts_idx + 6..ts_idx + 8],
                                                            ) {
                                                                if let Ok(m) =
                                                                    Month::try_from(m_num)
                                                                {
                                                                    if let Ok(d) =
                                                                        Date::from_calendar_date(
                                                                            year, m, day,
                                                                        )
                                                                    {
                                                                        if let Ok(t) =
                                                                            Time::from_hms(
                                                                                hour, min, sec,
                                                                            )
                                                                        {
                                                                            let dt =
                                                                                PrimitiveDateTime::new(
                                                                                    d, t,
                                                                                )
                                                                                .assume_utc(
                                                                                );
                                                                            update(
                                                                                &mut best_ts,
                                                                                dt,
                                                                            );
                                                                            i = ts_idx + 8;
                                                                            continue;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Try Syslog format: "Nov 11 12:00:00" or "Nov  5 12:00:00"
        let word_start = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if word_start {
            if let Some((month, 3)) = match_syslog_month(&bytes[i..]) {
                if i + 3 < len && bytes[i + 3] == b' ' {
                    let mut day_idx = i + 4;
                    if day_idx < len && bytes[day_idx] == b' ' {
                        day_idx += 1;
                    }
                    if day_idx + 1 < len {
                        let day_opt = if day_idx + 2 <= len
                            && bytes[day_idx].is_ascii_digit()
                            && bytes[day_idx + 1].is_ascii_digit()
                        {
                            parse_2digits(&bytes[day_idx..day_idx + 2]).map(|d| (d, day_idx + 2))
                        } else if bytes[day_idx].is_ascii_digit() {
                            Some((bytes[day_idx] - b'0', day_idx + 1))
                        } else {
                            None
                        };

                        if let Some((day, after_day)) = day_opt {
                            if after_day < len && bytes[after_day] == b' ' {
                                let time_idx = after_day + 1;
                                if time_idx + 8 <= len {
                                    if let Some(hour) =
                                        parse_2digits(&bytes[time_idx..time_idx + 2])
                                    {
                                        if bytes[time_idx + 2] == b':' {
                                            if let Some(min) =
                                                parse_2digits(&bytes[time_idx + 3..time_idx + 5])
                                            {
                                                if bytes[time_idx + 5] == b':' {
                                                    if let Some(sec) = parse_2digits(
                                                        &bytes[time_idx + 6..time_idx + 8],
                                                    ) {
                                                        let syslog_end = time_idx + 8;
                                                        // Require 4-digit year on the same line
                                                        if let Some(year) = find_4digit_year_on_line(
                                                            bytes, i, syslog_end,
                                                        ) {
                                                            if let Ok(d) = Date::from_calendar_date(
                                                                year, month, day,
                                                            ) {
                                                                if let Ok(t) =
                                                                    Time::from_hms(hour, min, sec)
                                                                {
                                                                    let dt =
                                                                        PrimitiveDateTime::new(
                                                                            d, t,
                                                                        )
                                                                        .assume_utc();
                                                                    update(&mut best_ts, dt);
                                                                    i = syslog_end;
                                                                    continue;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        i += 1;
    }

    best_ts
}

fn check_dated_logs(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let log_dir = root.join("var/log");
    if !log_dir.is_dir() {
        return;
    }

    let mut log_files: Vec<PathBuf> = Vec::new();

    match std::fs::read_dir(&log_dir) {
        Ok(entries) => {
            let mut top_entries = Vec::new();
            for entry in entries.flatten() {
                top_entries.push(entry.path());
            }
            top_entries.sort();

            for path in top_entries {
                if log_files.len() >= 500 {
                    break;
                }
                if path.is_file() {
                    log_files.push(path);
                } else if path.is_dir() {
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        let mut sub_list = Vec::new();
                        for sub_entry in sub_entries.flatten() {
                            sub_list.push(sub_entry.path());
                        }
                        sub_list.sort();
                        for sub_path in sub_list {
                            if log_files.len() >= 500 {
                                break;
                            }
                            if sub_path.is_file() {
                                log_files.push(sub_path);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                findings.push(Finding {
                    detector: "D8".into(),
                    channel: "d8_error".into(),
                    path: log_dir.display().to_string(),
                    visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("cannot read dir: {e}")],
                });
            }
            return;
        }
    }

    for file_path in log_files {
        let bytes = match read_file_capped(&file_path, 4 * 1024 * 1024) {
            Ok(b) => b,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    findings.push(Finding {
                        detector: "D8".into(),
                        channel: "d8_error".into(),
                        path: file_path.display().to_string(),
                        visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("cannot read file: {e}")],
                    });
                }
                continue;
            }
        };

        let mut latest_in_file: Option<(OffsetDateTime, String)> = None;

        for line_slice in bytes.split(|&b| b == b'\n') {
            if let Some(ts) = find_timestamp_in_line(line_slice) {
                let is_newer = match &latest_in_file {
                    Some((curr_ts, _)) => ts > *curr_ts,
                    None => true,
                };
                if is_newer {
                    let line_str = String::from_utf8_lossy(line_slice).into_owned();
                    latest_in_file = Some((ts, line_str));
                }
            }
        }

        if let Some((latest_ts, line)) = latest_in_file {
            if latest_ts > t_clock {
                findings.push(Finding {
                    detector: "D8".into(),
                    channel: "dated_log".into(),
                    path: file_path.display().to_string(),
                    visibility,
                    severity: Severity::Info,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![
                        format!("latest timestamp: {}", format_dt(latest_ts)),
                        format!("line: {}", truncate_200(&line)),
                        format!("T_clock: {}", format_dt(t_clock)),
                    ],
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channel 6: python_build
// ---------------------------------------------------------------------------

pub fn parse_python_version(dir_name: &str) -> Option<(u32, u32)> {
    let rest = dir_name.strip_prefix("python")?;
    let dot_idx = rest.find('.')?;
    let major: u32 = rest[..dot_idx].parse().ok()?;
    let rest2 = &rest[dot_idx + 1..];
    let end_minor = rest2
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest2.len());
    if end_minor == 0 {
        return None;
    }
    let minor: u32 = rest2[..end_minor].parse().ok()?;
    Some((major, minor))
}

pub fn lookup_cpython_date(major: u32, minor: u32) -> Option<OffsetDateTime> {
    for ((maj, min), (y, m, d)) in CPYTHON_RELEASES {
        if *maj == major && *min == minor {
            return make_date(*y, *m, *d);
        }
    }
    None
}

fn check_python_build(
    root: &Path,
    t_clock: OffsetDateTime,
    visibility: Visibility,
    findings: &mut Vec<Finding>,
) {
    let py_dirs = ["usr/lib", "usr/local/lib"];
    for py_dir_rel in py_dirs {
        let py_dir = root.join(py_dir_rel);
        if py_dir.is_dir() {
            match std::fs::read_dir(&py_dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                if name.starts_with("python3") {
                                    if let Some((maj, min)) = parse_python_version(name) {
                                        if let Some(rel_dt) = lookup_cpython_date(maj, min) {
                                            if rel_dt > t_clock {
                                                findings.push(Finding {
                                                    detector: "D8".into(),
                                                    channel: "python_build".into(),
                                                    path: path.display().to_string(),
                                                    visibility,
                                                    severity: Severity::Info,
                                                    confidence: 0.5,
                                                    hunk: None,
                                                    evidence: vec![
                                                        format!("CPython directory: {}", name),
                                                        format!(
                                                            "implied release date: {}",
                                                            format_dt(rel_dt)
                                                        ),
                                                        format!("T_clock: {}", format_dt(t_clock)),
                                                    ],
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        findings.push(Finding {
                            detector: "D8".into(),
                            channel: "d8_error".into(),
                            path: py_dir.display().to_string(),
                            visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("cannot read dir: {e}")],
                        });
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub fn check_d8(root: &Path, t_clock: OffsetDateTime, visibility: Visibility) -> Vec<Finding> {
    let mut findings = Vec::new();
    check_os_release(root, t_clock, visibility, &mut findings);
    check_tzdata(root, t_clock, visibility, &mut findings);
    check_ca_bundle(root, t_clock, visibility, &mut findings);
    check_kernel(root, t_clock, visibility, &mut findings);
    check_dated_logs(root, t_clock, visibility, &mut findings);
    check_python_build(root, t_clock, visibility, &mut findings);
    findings
}
