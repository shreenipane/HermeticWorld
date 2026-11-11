use std::fs;
use std::process::Command;
use tempfile::tempdir;
use time::macros::datetime;

use hermetic_sealcheck::d8::{
    check_d8, parse_kernel_version, parse_python_version, CPYTHON_RELEASES, KERNEL_RELEASES,
    TZDATA_RELEASES, UBUNTU_RELEASES,
};
use hermetic_sealcheck::{SealcheckReport, Visibility};

// ---------------------------------------------------------------------------
// Helpers for test certificates
// ---------------------------------------------------------------------------

fn der_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    if data.len() < 128 {
        out.push(data.len() as u8);
    } else if data.len() < 256 {
        out.push(0x81);
        out.push(data.len() as u8);
    } else {
        out.push(0x82);
        out.push((data.len() >> 8) as u8);
        out.push((data.len() & 0xFF) as u8);
    }
    out.extend_from_slice(data);
    out
}

fn b64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let idx0 = (b0 >> 2) as usize;
        let idx1 = (((b0 & 3) << 4) | (b1 >> 4)) as usize;
        let idx2 = (((b1 & 0xF) << 2) | (b2 >> 6)) as usize;
        let idx3 = (b2 & 0x3F) as usize;

        out.push(CHARS[idx0] as char);
        out.push(CHARS[idx1] as char);
        if chunk.len() > 1 {
            out.push(CHARS[idx2] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[idx3] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn make_test_cert_pem(
    not_before_utc: Option<&str>,
    not_before_gen: Option<&str>,
    cn: Option<&str>,
) -> String {
    let not_before = if let Some(utc) = not_before_utc {
        der_tlv(0x17, utc.as_bytes())
    } else if let Some(gen) = not_before_gen {
        der_tlv(0x18, gen.as_bytes())
    } else {
        der_tlv(0x17, b"200101000000Z")
    };
    let not_after = der_tlv(0x17, b"300101000000Z");
    let validity = der_tlv(0x30, &[not_before, not_after].concat());

    let subject = if let Some(cn_str) = cn {
        let oid = der_tlv(0x06, &[0x55, 0x04, 0x03]); // 2.5.4.3
        let val = der_tlv(0x0C, cn_str.as_bytes()); // UTF8String
        let attr_seq = der_tlv(0x30, &[oid, val].concat());
        let rdn_set = der_tlv(0x31, &attr_seq);
        der_tlv(0x30, &rdn_set)
    } else {
        der_tlv(0x30, &[])
    };

    let serial = der_tlv(0x02, &[1]);
    let sig_alg = der_tlv(0x30, &[]);
    let issuer = der_tlv(0x30, &[]);
    let tbs = der_tlv(
        0x30,
        &[serial, sig_alg.clone(), issuer, validity, subject].concat(),
    );
    let cert = der_tlv(0x30, &[tbs, sig_alg, der_tlv(0x03, &[0, 0])].concat());

    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64_encode(&cert)
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_os_release_flagged_and_not_flagged() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let etc = root.join("etc");
    fs::create_dir_all(&etc).expect("mkdir");

    // Case 1: Ubuntu 24.04 released in 2024-04-25.
    // T_clock = 2023-01-01 -> flagged!
    let os_rel = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n";
    fs::write(etc.join("os-release"), os_rel).expect("write");

    let t_clock_old = datetime!(2023-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock_old, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector, "D8");
    assert_eq!(findings[0].channel, "os_release");
    assert_eq!(findings[0].confidence, 0.5);

    // Case 2: T_clock = 2025-01-01 -> not flagged!
    let t_clock_new = datetime!(2025-01-01 00:00:00 UTC);
    let findings_clean = check_d8(root, t_clock_new, Visibility::AgentVisible);
    assert!(findings_clean.is_empty());
}

#[test]
fn test_os_release_quoted_and_point_releases() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let usr_lib = root.join("usr/lib");
    fs::create_dir_all(&usr_lib).expect("mkdir");

    // Single quotes and point release
    let os_rel = "ID='debian'\nVERSION_ID='12.4'\n";
    fs::write(usr_lib.join("os-release"), os_rel).expect("write");

    let t_clock = datetime!(2022-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "os_release");
}

#[test]
fn test_tzdata_flagged_and_not_flagged() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let zi_dir = root.join("usr/share/zoneinfo");
    fs::create_dir_all(&zi_dir).expect("mkdir");

    // tzdata 2024a (2024-02-01)
    fs::write(zi_dir.join("tzdata.zi"), "# version 2024a\nZone ...\n").expect("write");

    let t_clock_old = datetime!(2023-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock_old, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "tzdata");
    assert_eq!(findings[0].confidence, 1.0);

    let t_clock_new = datetime!(2025-01-01 00:00:00 UTC);
    let findings_clean = check_d8(root, t_clock_new, Visibility::AgentVisible);
    assert!(findings_clean.is_empty());
}

#[test]
fn test_tzdata_newer_than_table() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let zi_dir = root.join("usr/share/zoneinfo");
    fs::create_dir_all(&zi_dir).expect("mkdir");

    // 2026b is newer than every table entry
    fs::write(zi_dir.join("+VERSION"), "2026b\n").expect("write");

    let t_clock = datetime!(2024-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "tzdata");
    assert_eq!(findings[0].confidence, 0.5);
    assert!(findings[0].evidence[1].contains("newer than the built-in table"));
}

#[test]
fn test_ca_bundle_hand_encoded_der() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let cert_dir = root.join("etc/ssl/certs");
    fs::create_dir_all(&cert_dir).expect("mkdir");

    // Cert 1: UTCTime 2024-05-01 (after T_clock 2023-01-01) with Subject CN
    let pem_future = make_test_cert_pem(Some("240501000000Z"), None, Some("Future CA"));
    // Cert 2: GeneralizedTime 2020-01-01 (before T_clock 2023-01-01)
    let pem_past = make_test_cert_pem(None, Some("20200101000000Z"), Some("Past CA"));
    // Cert 3: Malformed PEM and truncated DER
    let pem_malformed =
        "-----BEGIN CERTIFICATE-----\nInvalidBase64!@#$\n-----END CERTIFICATE-----\n\
                         -----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n";

    let bundle = format!("{}{}{}", pem_future, pem_past, pem_malformed);
    fs::write(cert_dir.join("ca-certificates.crt"), bundle).expect("write");

    let t_clock = datetime!(2023-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);

    // Only the future cert should be flagged!
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "ca_bundle");
    assert_eq!(findings[0].confidence, 1.0);
    assert!(findings[0].evidence[0].contains("Future CA"));
}

#[test]
fn test_kernel_flagged_and_not_flagged() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Module directory: 6.8.0-40-generic (released 2024-03-17)
    let mod_dir = root.join("lib/modules/6.8.0-40-generic");
    fs::create_dir_all(&mod_dir).expect("mkdir");

    // Boot config: 5.15.0 (released 2021-10-31)
    let boot = root.join("boot");
    fs::create_dir_all(&boot).expect("mkdir");
    fs::write(
        boot.join("config-5.15.0"),
        "# Linux/x86 5.15.0 Kernel Configuration\nCONFIG_FOO=y\n",
    )
    .expect("write");

    // Case 1: T_clock = 2020-01-01 -> both 6.8 and 5.15 are newer
    let t_clock_2020 = datetime!(2020-01-01 00:00:00 UTC);
    let findings_2020 = check_d8(root, t_clock_2020, Visibility::AgentVisible);
    assert_eq!(findings_2020.len(), 2);
    assert!(findings_2020.iter().all(|f| f.channel == "kernel"));

    // Case 2: T_clock = 2022-01-01 -> only 6.8 is newer
    let t_clock_2022 = datetime!(2022-01-01 00:00:00 UTC);
    let findings_2022 = check_d8(root, t_clock_2022, Visibility::AgentVisible);
    assert_eq!(findings_2022.len(), 1);
    assert!(findings_2022[0].path.contains("6.8.0-40-generic"));

    // Case 3: T_clock = 2025-01-01 -> neither is newer
    let t_clock_2025 = datetime!(2025-01-01 00:00:00 UTC);
    let findings_2025 = check_d8(root, t_clock_2025, Visibility::AgentVisible);
    assert!(findings_2025.is_empty());
}

#[test]
fn test_kernel_build_date_in_config() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let boot = root.join("boot");
    fs::create_dir_all(&boot).expect("mkdir");

    // Config with ancient version 4.4 (2016) but compiler build date in 2024
    let config_content = "# Linux/x86 4.4.0 Kernel Configuration\n\
                          # Compiler: gcc 12.2.0 (built on 2024-06-15 10:00:00)\n";
    fs::write(boot.join("config-4.4.0"), config_content).expect("write");

    let t_clock = datetime!(2023-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "kernel");
    assert_eq!(findings[0].confidence, 1.0);
    assert!(findings[0].evidence[0].contains("2024-06-15"));
}

#[test]
fn test_dated_logs() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let log_dir = root.join("var/log");
    let apt_dir = log_dir.join("apt");
    fs::create_dir_all(&apt_dir).expect("mkdir");

    // 1. apt history log with Start-Date
    let apt_content = "Start-Date: 2026-11-11  12:00:00\nCommandline: apt-get install foo\n";
    fs::write(apt_dir.join("history.log"), apt_content).expect("write");

    // 2. Syslog file with standard syslog line without year -> NOT FLAGGED
    let syslog_no_year = "Nov 11 12:00:00 myhost systemd[1]: Started Foo Service.\n";
    fs::write(log_dir.join("syslog"), syslog_no_year).expect("write");

    // 3. dpkg log with ISO timestamp
    let dpkg_content = "2024-05-01 10:00:00 status installed bar:amd64 1.0\n";
    fs::write(log_dir.join("dpkg.log"), dpkg_content).expect("write");

    let t_clock = datetime!(2025-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);

    // Only history.log (2026) is flagged! dpkg.log is 2024 (< 2025), and syslog has no year.
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "dated_log");
    assert!(findings[0].path.contains("history.log"));
    assert_eq!(findings[0].confidence, 1.0);
    assert!(findings[0].evidence[1].contains("Start-Date: 2026-11-11  12:00:00"));
}

#[test]
fn test_syslog_with_year_flagged() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let log_dir = root.join("var/log");
    fs::create_dir_all(&log_dir).expect("mkdir");

    let syslog_with_year = "Nov 11 12:00:00 myhost app [2026]: service started\n";
    fs::write(log_dir.join("app.log"), syslog_with_year).expect("write");

    let t_clock = datetime!(2025-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "dated_log");
    assert!(findings[0].evidence[0].contains("2026-11-11"));
}

#[test]
fn test_python_build_flagged_and_not_flagged() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let usr_lib = root.join("usr/lib");
    let local_lib = root.join("usr/local/lib");
    fs::create_dir_all(&usr_lib).expect("mkdir");
    fs::create_dir_all(&local_lib).expect("mkdir");

    // python3.12 (released 2023-10-02)
    fs::create_dir_all(usr_lib.join("python3.12")).expect("mkdir");
    // python3.8 (released 2019-10-14)
    fs::create_dir_all(local_lib.join("python3.8")).expect("mkdir");

    // Case 1: T_clock = 2021-01-01 -> only python3.12 is flagged
    let t_clock = datetime!(2021-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "python_build");
    assert!(findings[0].path.contains("python3.12"));
    assert_eq!(findings[0].confidence, 0.5);

    // Case 2: T_clock = 2024-01-01 -> neither is flagged
    let t_clock_future = datetime!(2024-01-01 00:00:00 UTC);
    let findings_clean = check_d8(root, t_clock_future, Visibility::AgentVisible);
    assert!(findings_clean.is_empty());
}

#[test]
fn test_missing_files_give_no_findings() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let t_clock = datetime!(2020-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(findings.is_empty());
}

#[test]
fn test_version_tables_structure() {
    // Ubuntu
    assert!(UBUNTU_RELEASES.len() >= 22);
    assert_eq!(UBUNTU_RELEASES.first().unwrap().0, "14.04");
    assert_eq!(UBUNTU_RELEASES.last().unwrap().0, "26.04");

    // tzdata
    assert!(TZDATA_RELEASES.len() >= 50);
    assert_eq!(TZDATA_RELEASES.first().unwrap().0, "2014a");
    assert_eq!(TZDATA_RELEASES.last().unwrap().0, "2025a");

    // Kernel
    assert!(KERNEL_RELEASES.len() >= 40);
    assert_eq!(KERNEL_RELEASES.first().unwrap().0, (4, 0));
    assert_eq!(KERNEL_RELEASES.last().unwrap().0, (6, 13));

    // Python
    assert!(CPYTHON_RELEASES.len() >= 9);
    assert_eq!(CPYTHON_RELEASES.first().unwrap().0, (3, 6));
    assert_eq!(CPYTHON_RELEASES.last().unwrap().0, (3, 14));

    // Parsers
    assert_eq!(parse_kernel_version("6.8.0-40-generic"), Some((6, 8)));
    assert_eq!(parse_python_version("python3.11"), Some((3, 11)));
}

#[test]
fn test_fuzz_style_random_bytes_never_panic() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let etc = root.join("etc");
    let zi = root.join("usr/share/zoneinfo");
    let certs = root.join("etc/ssl/certs");
    let logs = root.join("var/log");
    fs::create_dir_all(&etc).expect("mkdir");
    fs::create_dir_all(&zi).expect("mkdir");
    fs::create_dir_all(&certs).expect("mkdir");
    fs::create_dir_all(&logs).expect("mkdir");

    // Pseudorandom generator (deterministic LCG)
    let mut state: u64 = 0xDEADBEEFCAFEBABE;
    let mut rand_bytes = |len: usize| -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            buf.push((state >> 33) as u8);
        }
        buf
    };

    let t_clock = datetime!(2024-01-01 00:00:00 UTC);

    for i in 0..20 {
        let len = (i * 257) % 5000 + 1;
        fs::write(etc.join("os-release"), rand_bytes(len)).expect("write");
        fs::write(zi.join("tzdata.zi"), rand_bytes(len)).expect("write");
        fs::write(certs.join("ca-certificates.crt"), rand_bytes(len)).expect("write");
        fs::write(logs.join("fuzz.log"), rand_bytes(len)).expect("write");

        // Must never panic
        let _ = check_d8(root, t_clock, Visibility::AgentVisible);
    }
}

#[test]
fn test_cli_d8_exit_codes_and_json_shape() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create a finding
    let etc = root.join("etc");
    fs::create_dir_all(&etc).expect("mkdir");
    fs::write(
        etc.join("os-release"),
        "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=24.04\n",
    )
    .expect("write");

    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // 1. Success exit code 0
    let out_file = dir.path().join("report.json");
    let status = Command::new(bin_path)
        .arg("d8")
        .arg("--root")
        .arg(root)
        .arg("--t-clock")
        .arg("2023-01-01T00:00:00Z")
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run d8");

    assert_eq!(status.code(), Some(0));
    assert!(out_file.exists());

    let content = fs::read_to_string(&out_file).expect("read report");
    let report: SealcheckReport = serde_json::from_str(&content).expect("parse report");
    assert_eq!(report.schema, "hermetic-sealcheck/v0");
    assert_eq!(report.instance_id, "");
    assert!(!report.gate);
    assert_eq!(report.mode, Some("d8".to_string()));
    assert_eq!(report.fingerprints.lines, 0);
    assert_eq!(report.fingerprints.windows, 0);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].detector, "D8");

    // 2. Bad RFC3339 timestamp -> exit 1
    let status_bad_date = Command::new(bin_path)
        .arg("d8")
        .arg("--root")
        .arg(root)
        .arg("--t-clock")
        .arg("not-a-date")
        .status()
        .expect("run d8 bad date");
    assert_eq!(status_bad_date.code(), Some(1));

    // 3. Bad argument -> exit 1
    let status_bad_arg = Command::new(bin_path)
        .arg("d8")
        .arg("--nonexistent-flag")
        .status()
        .expect("run d8 bad arg");
    assert_eq!(status_bad_arg.code(), Some(1));
}
