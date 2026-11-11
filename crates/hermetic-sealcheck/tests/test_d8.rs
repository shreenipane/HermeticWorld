use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use time::macros::datetime;

use hermetic_sealcheck::d8::{
    check_d8, parse_kernel_version, parse_python_version, resolve_in_root, CPYTHON_RELEASES,
    KERNEL_RELEASES, TZDATA_RELEASES, UBUNTU_RELEASES,
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

    let syslog_with_year = "Nov 11 12:00:00 2026 myhost app: service started\n";
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
    assert!(UBUNTU_RELEASES.len() >= 24);
    assert_eq!(UBUNTU_RELEASES.first().unwrap().0, "14.04");
    assert_eq!(UBUNTU_RELEASES.last().unwrap().0, "26.04");

    // tzdata
    assert!(TZDATA_RELEASES.len() >= 50);
    assert_eq!(TZDATA_RELEASES.first().unwrap().0, "2014a");
    assert_eq!(TZDATA_RELEASES.last().unwrap().0, "2025a");

    // Kernel
    assert!(KERNEL_RELEASES.len() >= 40);
    assert_eq!(KERNEL_RELEASES.first().unwrap().0, (4, 0));
    assert_eq!(KERNEL_RELEASES.last().unwrap().0, (6, 16));

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
    let boot = root.join("boot");
    fs::create_dir_all(&etc).expect("mkdir");
    fs::create_dir_all(&zi).expect("mkdir");
    fs::create_dir_all(&certs).expect("mkdir");
    fs::create_dir_all(&logs).expect("mkdir");
    fs::create_dir_all(&boot).expect("mkdir");

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
        fs::write(zi.join("+VERSION"), rand_bytes(len)).expect("write");
        fs::write(certs.join("ca-certificates.crt"), rand_bytes(len)).expect("write");
        fs::write(certs.join("cert.pem"), rand_bytes(len)).expect("write");
        fs::write(logs.join("fuzz.log"), rand_bytes(len)).expect("write");
        fs::write(boot.join("config-fuzz"), rand_bytes(len)).expect("write");

        // Must never panic
        let _ = check_d8(root, t_clock, Visibility::AgentVisible);
    }
}

#[test]
fn test_tzdata_multibyte_never_panics() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let zi_dir = root.join("usr/share/zoneinfo");
    fs::create_dir_all(&zi_dir).expect("mkdir");

    // +VERSION containing multibyte character €€
    fs::write(zi_dir.join("+VERSION"), "€€\n").expect("write");
    // tzdata.zi containing multibyte characters
    fs::write(zi_dir.join("tzdata.zi"), "# version €€\n").expect("write");

    let t_clock = datetime!(2024-01-01 00:00:00 UTC);
    // Must not panic on string slicing
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(findings.is_empty());

    // Also test with other multibyte sequences
    fs::write(zi_dir.join("+VERSION"), "2024€\n").expect("write");
    fs::write(zi_dir.join("tzdata.zi"), "# version 2024€\n").expect("write");
    let findings2 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(findings2.is_empty());
}

#[test]
fn test_syslog_adjacent_year_and_false_positives() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let log_dir = root.join("var/log");
    fs::create_dir_all(&log_dir).expect("mkdir");

    let t_clock = datetime!(2025-01-01 00:00:00 UTC);

    // Negative tests: false positive patterns must NOT produce findings
    // 1. PIDs in brackets (sshd[2099]:)
    let pids = "Nov 11 12:00:00 host sshd[2099]: x\n";
    fs::write(log_dir.join("pids.log"), pids).expect("write");

    // 2. Sizes (... 2048 MB)
    let sizes = "Nov 11 12:00:00 host kernel: Total Memory: 2048 MB available\n";
    fs::write(log_dir.join("sizes.log"), sizes).expect("write");

    // 3. Ports (... port 2049)
    let ports = "Nov 11 12:00:00 host daemon: listening on port 2049 for nfs\n";
    fs::write(log_dir.join("ports.log"), ports).expect("write");

    let findings_neg = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(
        findings_neg.is_empty(),
        "Expected no findings for false positive patterns, but got {:?}",
        findings_neg
    );

    // Clean up negative logs
    fs::remove_file(log_dir.join("pids.log")).expect("remove");
    fs::remove_file(log_dir.join("sizes.log")).expect("remove");
    fs::remove_file(log_dir.join("ports.log")).expect("remove");

    // Positive tests: each of the three recognised layouts is dated correctly
    // Layout 1: "Mon DD YYYY HH:MM:SS"
    let l1 = "Nov 11 2026 12:00:00 host service: started\n";
    fs::write(log_dir.join("layout1.log"), l1).expect("write");
    let f1 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(f1.len(), 1);
    assert_eq!(f1[0].channel, "dated_log");
    assert!(f1[0].evidence[0].contains("2026-11-11 12:00:00 UTC"));
    fs::remove_file(log_dir.join("layout1.log")).expect("remove");

    // Layout 2: "Mon DD HH:MM:SS YYYY"
    let l2 = "Nov 11 12:00:00 2026 host service: started\n";
    fs::write(log_dir.join("layout2.log"), l2).expect("write");
    let f2 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(f2.len(), 1);
    assert_eq!(f2[0].channel, "dated_log");
    assert!(f2[0].evidence[0].contains("2026-11-11 12:00:00 UTC"));
    fs::remove_file(log_dir.join("layout2.log")).expect("remove");

    // Layout 3: "Www Mon DD HH:MM:SS YYYY" (ctime)
    let l3 = "Wed Nov 11 12:00:00 2026 host service: started\n";
    fs::write(log_dir.join("layout3.log"), l3).expect("write");
    let f3 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(f3.len(), 1);
    assert_eq!(f3[0].channel, "dated_log");
    assert!(f3[0].evidence[0].contains("2026-11-11 12:00:00 UTC"));
}

#[cfg(unix)]
#[test]
fn test_symlink_root_isolation() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let cert_dir = root.join("etc/ssl/certs");
    let share_certs = root.join("usr/share/ca-certificates");
    fs::create_dir_all(&cert_dir).expect("mkdir");
    fs::create_dir_all(&share_certs).expect("mkdir");

    // Case 1: Absolute symlink inside rootfs
    // etc/ssl/certs/test.pem -> /usr/share/ca-certificates/x.crt
    let pem_content = make_test_cert_pem(Some("260101000000Z"), None, Some("Rootfs Test CA"));
    fs::write(share_certs.join("x.crt"), &pem_content).expect("write");
    symlink(
        "/usr/share/ca-certificates/x.crt",
        cert_dir.join("test.pem"),
    )
    .expect("symlink");

    let t_clock = datetime!(2025-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "ca_bundle");
    assert!(findings[0].evidence[0].contains("Rootfs Test CA"));

    // Case 2: When rootfs copy is missing, host path is never read!
    let missing_link = cert_dir.join("host_leak.pem");
    symlink("/etc/hostname", &missing_link).expect("symlink");
    fs::remove_file(cert_dir.join("test.pem")).expect("remove");
    fs::remove_file(share_certs.join("x.crt")).expect("remove");

    let findings_host = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(
        findings_host.is_empty(),
        "Host file /etc/hostname must not be read: got {:?}",
        findings_host
    );
    fs::remove_file(&missing_link).expect("remove");

    // Case 3: Link loop gives d8_error and no hang
    let loop_a = cert_dir.join("loop_a.pem");
    let loop_b = cert_dir.join("loop_b.pem");
    symlink("/etc/ssl/certs/loop_b.pem", &loop_a).expect("symlink");
    symlink("/etc/ssl/certs/loop_a.pem", &loop_b).expect("symlink");

    let findings_loop = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(
        findings_loop.iter().any(|f| f.channel == "d8_error"),
        "Expected d8_error for symlink loop"
    );
    fs::remove_file(&loop_a).expect("remove");
    fs::remove_file(&loop_b).expect("remove");

    // Case 4: ../../../ escape stays inside root
    let sub = root.join("a/b/c");
    fs::create_dir_all(&sub).expect("mkdir");
    let escape_link = sub.join("escaped.pem");
    symlink(
        "../../../../../../../../usr/share/ca-certificates/x.crt",
        &escape_link,
    )
    .expect("symlink");
    let resolved = resolve_in_root(root, Path::new("a/b/c/escaped.pem"));
    assert_eq!(resolved, Some(share_certs.join("x.crt")));
}

#[test]
fn test_cli_d8_invalid_root_error_and_exit_1() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // 1. Nonexistent directory
    let output_nonexistent = Command::new(bin_path)
        .arg("d8")
        .arg("--root")
        .arg("/nonexistent/directory/that/does/not/exist/d8_test")
        .arg("--t-clock")
        .arg("2023-01-01T00:00:00Z")
        .output()
        .expect("run d8");

    assert_eq!(output_nonexistent.status.code(), Some(1));
    let stderr_str = String::from_utf8_lossy(&output_nonexistent.stderr);
    assert!(
        stderr_str.contains("does not exist or is not a directory"),
        "Expected error message on stderr, got: {}",
        stderr_str
    );

    // 2. Path is a regular file, not a directory
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("regular_file.txt");
    fs::write(&file_path, "not a directory").expect("write");

    let output_file = Command::new(bin_path)
        .arg("d8")
        .arg("--root")
        .arg(&file_path)
        .arg("--t-clock")
        .arg("2023-01-01T00:00:00Z")
        .output()
        .expect("run d8 on file");

    assert_eq!(output_file.status.code(), Some(1));
    let stderr_file = String::from_utf8_lossy(&output_file.stderr);
    assert!(
        stderr_file.contains("does not exist or is not a directory"),
        "Expected error message on stderr, got: {}",
        stderr_file
    );
}

#[test]
fn test_large_log_reads_tail_post_t_clock() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let log_dir = root.join("var/log");
    fs::create_dir_all(&log_dir).expect("mkdir");

    let file_path = log_dir.join("large.log");
    let mut file = fs::File::create(&file_path).expect("create file");
    use std::io::Write;

    // Write ~4 MiB + 200 bytes
    // Early lines before T_clock (2024-01-01)
    let early_line = b"2024-01-01 10:00:00 past event line padding data to fill buffer\n";
    let target_size = 4 * 1024 * 1024 + 200;
    let mut written = 0;
    while written + early_line.len() + 100 < target_size {
        file.write_all(early_line).expect("write");
        written += early_line.len();
    }

    // Only post-T_clock line is at the end of the file
    let late_line = b"2026-11-11 12:00:00 post-cutoff event at log tail\n";
    file.write_all(late_line).expect("write");
    file.flush().expect("flush");

    let t_clock = datetime!(2025-01-01 00:00:00 UTC);
    let findings = check_d8(root, t_clock, Visibility::AgentVisible);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "dated_log");
    assert!(findings[0].evidence[0].contains("2026-11-11 12:00:00 UTC"));
    assert!(findings[0].evidence[1].contains("post-cutoff event at log tail"));
}

#[test]
fn test_format_dt_utc_conversion_with_nonzero_offset() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let etc = root.join("etc");
    fs::create_dir_all(&etc).expect("mkdir");

    // Ubuntu 24.04 released 2024-04-25
    fs::write(
        etc.join("os-release"),
        "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=24.04\n",
    )
    .expect("write");

    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // --t-clock 2023-01-01T00:00:00+05:00
    // UTC time is 2022-12-31 19:00:00 UTC
    let out_file = dir.path().join("report.json");
    let status = Command::new(bin_path)
        .arg("d8")
        .arg("--root")
        .arg(root)
        .arg("--t-clock")
        .arg("2023-01-01T00:00:00+05:00")
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run d8");

    assert_eq!(status.code(), Some(0));
    let content = fs::read_to_string(&out_file).expect("read report");
    let report: SealcheckReport = serde_json::from_str(&content).expect("parse report");
    assert_eq!(report.findings.len(), 1);
    let t_clock_evidence = &report.findings[0].evidence[2];
    assert!(
        t_clock_evidence.contains("2022-12-31 19:00:00 UTC"),
        "Expected '2022-12-31 19:00:00 UTC' in evidence, got: {}",
        t_clock_evidence
    );
}

#[test]
fn test_newer_than_table_distro_kernel_python() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let t_clock = datetime!(2025-01-01 00:00:00 UTC);

    // 1. Ubuntu 30.04 (newer than Ubuntu table ending at 26.04) -> finding!
    let etc = root.join("etc");
    fs::create_dir_all(&etc).expect("mkdir");
    fs::write(
        etc.join("os-release"),
        "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=30.04\n",
    )
    .expect("write");

    let f_u30 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(f_u30.len(), 1);
    assert_eq!(f_u30[0].channel, "os_release");
    assert_eq!(f_u30[0].confidence, 0.5);
    assert!(f_u30[0].evidence[1].contains("newer than the built-in table (release date unknown)"));

    // 2. Older unknown version: Ubuntu 5.04 (not in table, older than 26.04) -> gives NONE
    fs::write(
        etc.join("os-release"),
        "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=5.04\n",
    )
    .expect("write");
    let f_u5 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert!(
        f_u5.is_empty(),
        "Older unknown version must give no finding"
    );
    fs::remove_file(etc.join("os-release")).expect("remove");

    // 3. Kernel 9.1 (newer than Kernel table ending at 6.16) -> finding!
    let mod_dir = root.join("lib/modules/9.1.0-custom");
    fs::create_dir_all(&mod_dir).expect("mkdir");
    let f_k9 = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(f_k9.len(), 1);
    assert_eq!(f_k9[0].channel, "kernel");
    assert_eq!(f_k9[0].confidence, 0.5);
    assert!(f_k9[0].evidence[1].contains("newer than the built-in table (release date unknown)"));
    fs::remove_dir_all(root.join("lib")).expect("rmdir");

    // 4. CPython 3.99 (newer than CPython table ending at 3.14) -> finding!
    let py_dir = root.join("usr/lib/python3.99");
    fs::create_dir_all(&py_dir).expect("mkdir");
    let f_py = check_d8(root, t_clock, Visibility::AgentVisible);
    assert_eq!(f_py.len(), 1);
    assert_eq!(f_py[0].channel, "python_build");
    assert_eq!(f_py[0].confidence, 0.5);
    assert!(f_py[0].evidence[1].contains("newer than the built-in table (release date unknown)"));
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
