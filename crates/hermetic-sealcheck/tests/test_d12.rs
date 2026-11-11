use hermetic_sealcheck::{check_d12, D12Options, Severity};
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use time::{Date, Month};

fn test_real_date() -> Date {
    Date::from_calendar_date(2026, Month::November, 11).expect("valid date")
}

#[test]
fn test_d12_every_listed_format_for_real_date() {
    let real_date = test_real_date();
    let epoch_secs = real_date.midnight().assume_utc().unix_timestamp();
    let epoch_millis = epoch_secs * 1000;

    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec![],
    };

    let epoch_secs_str = format!("timestamp {epoch_secs} recorded");
    let epoch_millis_str = format!("timestamp {epoch_millis} recorded");

    let formats = vec![
        ("ISO hyphen", "date: 2026-11-11 text"),
        ("ISO slash", "date: 2026/11/11 text"),
        ("ISO compact 8-digit", "prefix 20261111 suffix"),
        ("US slash", "US date 11/11/2026 here"),
        ("US hyphen", "US date 11-11-2026 here"),
        ("European dot", "Euro date 11.11.2026 here"),
        ("Month day year (Nov 11, 2026)", "On Nov 11, 2026 we met"),
        (
            "Day month year (11 November 2026)",
            "On 11 November 2026 event",
        ),
        (
            "Month day year no comma (November 11 2026)",
            "Dated November 11 2026 ok",
        ),
        (
            "Year month day (2026-Nov-11)",
            "Version 2026-Nov-11 released",
        ),
        (
            "RFC 2822 (Wed, 11 Nov 2026)",
            "Date: Wed, 11 Nov 2026 in email",
        ),
        (
            "HTTP RFC 1123",
            "Date: Wed, 11 Nov 2026 08:12:31 GMT header",
        ),
        (
            "HTTP RFC 850",
            "Date: Wednesday, 11-Nov-26 08:12:31 GMT header",
        ),
        ("HTTP asctime", "Log: Wed Nov 11 08:12:31 2026 started"),
        ("Unix epoch 10 digits", epoch_secs_str.as_str()),
        ("Unix epoch 13 digits", epoch_millis_str.as_str()),
    ];

    for (name, text) in formats {
        let findings = check_d12("test.log", text, &opts);
        assert_eq!(
            findings.len(),
            1,
            "Format '{name}' ({text}) should produce 1 finding, got {}",
            findings.len()
        );
        assert_eq!(findings[0].detector, "D12");
        assert_eq!(findings[0].channel, "real_date");
        assert_eq!(findings[0].severity, Severity::Review);
    }
}

#[test]
fn test_d12_date_3_days_away_not_flagged_with_tolerance_1() {
    let real_date = test_real_date(); // 2026-11-11
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec![],
    };

    // 2026-11-14 is 3 days away
    let text = "Past event on 2026-11-14 and 14/11/2026 and Nov 14, 2026";
    let findings = check_d12("test.log", text, &opts);
    assert!(
        findings.is_empty(),
        "Date 3 days away with tolerance 1 must not be flagged"
    );
}

#[test]
fn test_d12_invalid_dates_ignored() {
    let real_date = test_real_date();
    let opts = D12Options {
        real_date,
        tolerance_days: 100, // Even with large tolerance, invalid calendar dates must be ignored
        host_names: vec![],
        host_paths: vec![],
    };

    let text = "Invalid dates: 2026-02-30 and 13/45/2026 and 2026/02/30 and 31/02/2026";
    let findings = check_d12("test.log", text, &opts);
    assert!(
        findings.is_empty(),
        "Invalid calendar dates like 2026-02-30 or 13/45/2026 must be ignored"
    );
}

#[test]
fn test_d12_epochs_inside_and_outside_window() {
    let real_date = test_real_date(); // 2026-11-11
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec![],
    };

    let inside_10 = real_date.midnight().assume_utc().unix_timestamp();
    let inside_13 = inside_10 * 1000;

    // 2020-01-01 is way outside window
    let outside_10 = Date::from_calendar_date(2020, Month::January, 1)
        .expect("valid")
        .midnight()
        .assume_utc()
        .unix_timestamp();
    let outside_13 = outside_10 * 1000;

    let text =
        format!("inside: {inside_10} and {inside_13}; outside: {outside_10} and {outside_13}");
    let findings = check_d12("test.log", &text, &opts);
    assert_eq!(
        findings.len(),
        2,
        "Only epochs inside the window must be flagged"
    );
}

#[test]
fn test_d12_digits_embedded_in_longer_numbers_not_flagged() {
    let real_date = test_real_date();
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec![],
    };

    // 120261111 (9 digits), 202611110 (9 digits), 12026-11-11, 2026-11-110, 111/11/2026, 11/11/20261
    let text = "numbers: 120261111 202611110 11794355200 17943552000001 12026-11-11 2026-11-110 111/11/2026 11/11/20261";
    let findings = check_d12("test.log", text, &opts);
    assert!(
        findings.is_empty(),
        "Digits embedded in longer numbers must not be flagged: got {:?}",
        findings
    );
}

#[test]
fn test_d12_host_name_and_host_path_matching() {
    let opts = D12Options {
        real_date: test_real_date(),
        tolerance_days: 1,
        host_names: vec!["myhost".to_string()],
        host_paths: vec!["/home/flingboot".to_string()],
    };

    // "myhost2" should NOT match "myhost"
    // "MYHOST" should match "myhost" (case-insensitive)
    // "/home/flingboot" should match as substring
    let text = "myhost2 is not matching, but MYHOST is matching and path is /home/flingboot/repo";
    let findings = check_d12("test.log", text, &opts);

    assert_eq!(findings.len(), 2);
    let channels: Vec<&str> = findings.iter().map(|f| f.channel.as_str()).collect();
    assert!(channels.contains(&"host_name"));
    assert!(channels.contains(&"host_path"));
}

#[test]
fn test_d12_deduplication_and_50_cap() {
    let real_date = test_real_date();
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec!["myhost".to_string()],
        host_paths: vec![],
    };

    // De-duplication: "2026-11-11" repeated 10 times -> 1 finding; "myhost" repeated 5 times -> 1 finding
    let mut text_dup = String::new();
    for _ in 0..10 {
        text_dup.push_str("date 2026-11-11\n");
    }
    for _ in 0..5 {
        text_dup.push_str("host myhost\n");
    }
    let findings_dup = check_d12("test.log", &text_dup, &opts);
    assert_eq!(
        findings_dup.len(),
        2,
        "Duplicate matches within a file must be deduplicated"
    );

    // 50-cap test: generate 70 distinct host paths
    let host_paths: Vec<String> = (0..70).map(|i| format!("/path/to/item_{i}")).collect();
    let opts_cap = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: host_paths.clone(),
    };
    let mut text_cap = String::new();
    for p in &host_paths {
        text_cap.push_str(p);
        text_cap.push('\n');
    }
    let findings_cap = check_d12("test.log", &text_cap, &opts_cap);
    assert_eq!(
        findings_cap.len(),
        50,
        "Findings must be capped at 50 per file"
    );
}

#[test]
fn test_d12_directory_walk_and_nested_file() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let dir = tempdir().expect("tempdir");
    let nested_dir = dir.path().join("a/b/c");
    fs::create_dir_all(&nested_dir).expect("mkdir nested");

    let nested_file = nested_dir.join("sample.txt");
    fs::write(&nested_file, "Built on 2026-11-11 by host worker1").expect("write nested");

    let out_file = dir.path().join("report.json");

    let status = Command::new(bin_path)
        .arg("d12")
        .arg("--path")
        .arg(dir.path())
        .arg("--real-date")
        .arg("2026-11-11")
        .arg("--host-name")
        .arg("worker1")
        .arg("--format")
        .arg("json")
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run hermetic-sealcheck d12");

    assert_eq!(status.code(), Some(0));

    let report_str = fs::read_to_string(&out_file).expect("read report");
    let json: Value = serde_json::from_str(&report_str).expect("parse json");

    assert_eq!(json["schema"], "hermetic-sealcheck/v0");
    assert_eq!(json["mode"], "d12");
    assert_eq!(json["gate"], false);

    let findings = json["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 2);
}

#[test]
fn test_d12_fuzz_every_byte_and_random_input_never_panics() {
    let real_date = test_real_date();
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec!["host.internal".to_string()],
        host_paths: vec!["/root/data".to_string()],
    };

    // Feed all 256 byte values
    let all_bytes: Vec<u8> = (0..=255).collect();
    let lossy_text = String::from_utf8_lossy(&all_bytes);
    let findings = check_d12("fuzz_all_bytes.bin", &lossy_text, &opts);
    let _ = findings.len();

    // Feed long adversarial string with odd UTF-8 boundaries and repetitions
    let mut weird = String::new();
    for _ in 0..1000 {
        weird.push_str(
            "2026--11---11 /2026/11/11/ 11.11.2026.2026 202611110000000000 🚀 \0 \u{FFFF}",
        );
    }
    let findings2 = check_d12("fuzz_weird.txt", &weird, &opts);
    let _ = findings2.len();
}

#[test]
fn test_d12_utf8_char_boundary_safety_never_panics() {
    let opts = D12Options {
        real_date: test_real_date(),
        tolerance_days: 1,
        host_names: vec!["host".to_string()],
        host_paths: vec!["/path".to_string()],
    };

    // The exact bug report input: "11 Nov 2026 08:12:31 +000é"
    let buggy_input = "11 Nov 2026 08:12:31 +000é";
    let findings = check_d12("test.log", buggy_input, &opts);
    assert!(!findings.is_empty());

    // Several multibyte suffixes after every date format
    let multibyte_suffixes = ["é", "🚀", "\u{FFFF}", "\u{10FFFF}", "日本語", "€€€"];
    let base_formats = [
        "2026-11-11",
        "2026/11/11",
        "20261111",
        "11/11/2026",
        "11-11-2026",
        "11.11.2026",
        "Nov 11, 2026",
        "11 November 2026",
        "2026-Nov-11",
        "Wed, 11 Nov 2026",
        "Wed, 11 Nov 2026 08:12:31 GMT",
        "Wed, 11 Nov 2026 08:12:31 +0000",
        "Wednesday, 11-Nov-26 08:12:31 GMT",
        "Wed Nov 11 08:12:31 2026",
        "1794355200",
        "1794355200000",
    ];

    for base in base_formats {
        for suffix in multibyte_suffixes {
            let text = format!("{base}{suffix}");
            let _ = check_d12("test.log", &text, &opts);
            let text_space = format!("{base} {suffix}");
            let _ = check_d12("test.log", &text_space, &opts);
        }
    }
}

#[test]
fn test_d12_year_first_formats_not_ambiguous() {
    let real_date = test_real_date(); // 2026-11-11
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec![],
    };

    // 2026-12-11 and 20261211 are Dec 11 2026 (month 12, day 11).
    // They are 1 month away from 2026-11-11, so with tolerance 1 they must NOT be flagged.
    let text_ymd = "Dates: 2026-12-11 and 20261211 and 2026/12/11";
    let findings_ymd = check_d12("test.log", text_ymd, &opts);
    assert!(
        findings_ymd.is_empty(),
        "Year-first formats 2026-12-11 and 20261211 must NOT be flagged with real date 2026-11-11 tolerance 1: got {:?}",
        findings_ymd
    );

    // 12/11/2026 is ambiguous (could be 12 Nov 2026 or 11 Dec 2026).
    // 12 Nov 2026 is within 1 day of 2026-11-11, so 12/11/2026 STILL IS flagged!
    let text_ambiguous = "Ambiguous date: 12/11/2026";
    let findings_ambiguous = check_d12("test.log", text_ambiguous, &opts);
    assert_eq!(
        findings_ambiguous.len(),
        1,
        "Ambiguous date 12/11/2026 must still be flagged"
    );
    assert_eq!(findings_ambiguous[0].channel, "real_date");
}

#[test]
fn test_d12_host_paths_slash_on_8mib_and_1000_distinct_dates_cap() {
    let real_date = test_real_date(); // 2026-11-11
    let opts = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec!["/".to_string()],
    };

    // 1. host_paths ["/"] on 8 MiB of slashes
    let eight_mib_slashes = "/".repeat(8 * 1024 * 1024);
    let start_time = std::time::Instant::now();
    let findings_slashes = check_d12("slashes.txt", &eight_mib_slashes, &opts);
    let elapsed = start_time.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "8 MiB slashes took {:?}, expected well under 2s",
        elapsed
    );
    assert_eq!(
        findings_slashes.len(),
        1,
        "Expected exactly 1 host_path finding for slashes"
    );
    assert_eq!(findings_slashes[0].channel, "host_path");

    // 2. 1,000 distinct dates in the window give exactly 50 findings
    let mut thousand_dates = String::new();
    for sec in 0..1000 {
        let h = sec / 3600;
        let m = (sec % 3600) / 60;
        let s = sec % 60;
        thousand_dates.push_str(&format!(
            "Wed, 11 Nov 2026 {:02}:{:02}:{:02} GMT\n",
            h, m, s
        ));
    }
    let opts_dates = D12Options {
        real_date,
        tolerance_days: 1,
        host_names: vec![],
        host_paths: vec![],
    };
    let findings_1000 = check_d12("dates.txt", &thousand_dates, &opts_dates);
    assert_eq!(
        findings_1000.len(),
        50,
        "1,000 distinct dates in window must produce exactly 50 findings"
    );
}

#[test]
fn test_d12_4mib_words_scans_under_2s_without_quadratic_copying() {
    let opts = D12Options {
        real_date: test_real_date(),
        tolerance_days: 1,
        host_names: vec!["myhost".to_string()],
        host_paths: vec!["/var/data".to_string()],
    };

    // Create 4 MiB of space-separated words without dates
    let word = "banana apple cherry orange elephant computer keyboard window ";
    let repeats = (4 * 1024 * 1024) / word.len() + 1;
    let four_mib_text = word.repeat(repeats);

    let start_time = std::time::Instant::now();
    let findings = check_d12("corpus.txt", &four_mib_text, &opts);
    let elapsed = start_time.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "4 MiB words scan took {:?}, expected well under 2s",
        elapsed
    );
    assert!(findings.is_empty());
}

#[test]
#[cfg(unix)]
fn test_d12_directory_scan_skips_symlinks() {
    use std::os::unix::fs::symlink;

    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let dir = tempdir().expect("tempdir");

    let real_file = dir.path().join("real.txt");
    fs::write(&real_file, "clean content").expect("write real file");

    let symlink_file = dir.path().join("link_to_real.txt");
    symlink(&real_file, &symlink_file).expect("create symlink");

    let out_file = dir.path().join("report.json");

    let status = Command::new(bin_path)
        .arg("d12")
        .arg("--path")
        .arg(dir.path())
        .arg("--real-date")
        .arg("2026-11-11")
        .arg("--format")
        .arg("json")
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run hermetic-sealcheck d12");

    assert_eq!(status.code(), Some(0));

    let report_str = fs::read_to_string(&out_file).expect("read report");
    let json: Value = serde_json::from_str(&report_str).expect("parse json");

    let findings = json["findings"].as_array().expect("findings array");
    let symlink_findings: Vec<&Value> = findings
        .iter()
        .filter(|f| f["channel"] == "skipped_symlink")
        .collect();

    assert_eq!(
        symlink_findings.len(),
        1,
        "Expected exactly 1 skipped_symlink finding"
    );
    assert_eq!(symlink_findings[0]["detector"], "D12");
    assert_eq!(symlink_findings[0]["severity"], "info");
    assert_eq!(
        symlink_findings[0]["path"],
        symlink_file.display().to_string()
    );
    assert_eq!(symlink_findings[0]["evidence"][0], "symlink not followed");
}
