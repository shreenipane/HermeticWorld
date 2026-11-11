#![forbid(unsafe_code)]

use sha2::Digest;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use time::macros::datetime;

use hermetic_trust::{
    compute_ca_validity, compute_leaf_validity, create_empty_jks, install_ca, mint_ca, mint_leaf,
    parse_jks, read_seed_file, write_private_key_file, JksEntry, TrustError,
};

#[test]
fn test_determinism() {
    let seed1: [u8; 32] = [42u8; 32];
    let seed2: [u8; 32] = [43u8; 32];
    let world_id1 = "swe-bench-world-alpha";
    let world_id2 = "swe-bench-world-beta";
    let t_clock = datetime!(2024-03-15 12:00:00 UTC);

    // Same seed, world_id, t_clock -> identical cert and key
    let ca_a = mint_ca(world_id1, t_clock, &seed1).expect("mint ca_a");
    let ca_b = mint_ca(world_id1, t_clock, &seed1).expect("mint ca_b");

    assert_eq!(ca_a.cert_pem, ca_b.cert_pem);
    assert_eq!(ca_a.cert_der, ca_b.cert_der);
    assert_eq!(ca_a.key_pem, ca_b.key_pem);
    assert_eq!(ca_a.seed, ca_b.seed);

    // Different world_id -> different cert and key
    let ca_diff_world = mint_ca(world_id2, t_clock, &seed1).expect("mint diff world");
    assert_ne!(ca_a.cert_pem, ca_diff_world.cert_pem);
    assert_ne!(ca_a.key_pem, ca_diff_world.key_pem);

    // Different seed -> different cert and key
    let ca_diff_seed = mint_ca(world_id1, t_clock, &seed2).expect("mint diff seed");
    assert_ne!(ca_a.cert_pem, ca_diff_seed.cert_pem);
    assert_ne!(ca_a.key_pem, ca_diff_seed.key_pem);

    // Leaf determinism
    let hostnames = ["api.internal", "world.hermetic.local"];
    let leaf1 = mint_leaf(&ca_a, &hostnames, t_clock).expect("mint leaf1");
    let leaf2 = mint_leaf(&ca_a, &hostnames, t_clock).expect("mint leaf2");

    assert_eq!(leaf1.cert_pem, leaf2.cert_pem);
    assert_eq!(leaf1.cert_der, leaf2.cert_der);
    assert_eq!(leaf1.key_pem, leaf2.key_pem);
    assert_eq!(leaf1.key_der, leaf2.key_der);

    // Different hostnames -> different leaf
    let leaf3 = mint_leaf(&ca_a, &["other.internal"], t_clock).expect("mint leaf3");
    assert_ne!(leaf1.cert_pem, leaf3.cert_pem);
}

#[test]
fn test_validity_window() {
    // 2019 test: validity must be 2009 to 2029
    let t_2019 = datetime!(2019-07-20 15:30:45.123456 UTC);
    let (ca_start_2019, ca_end_2019) = compute_ca_validity(t_2019).expect("validity 2019");
    assert_eq!(ca_start_2019.year(), 2009);
    assert_eq!(ca_start_2019.month(), time::Month::July);
    assert_eq!(ca_start_2019.day(), 20);
    assert_eq!(ca_start_2019.hour(), 15);
    assert_eq!(ca_start_2019.minute(), 30);
    assert_eq!(ca_start_2019.second(), 45);
    assert_eq!(ca_start_2019.nanosecond(), 0);

    assert_eq!(ca_end_2019.year(), 2029);
    assert_eq!(ca_end_2019.month(), time::Month::July);
    assert_eq!(ca_end_2019.day(), 20);
    assert_eq!(ca_end_2019.hour(), 15);
    assert_eq!(ca_end_2019.minute(), 30);
    assert_eq!(ca_end_2019.second(), 45);
    assert_eq!(ca_end_2019.nanosecond(), 0);

    // 2023 test: validity must be 2013 to 2033
    let t_2023 = datetime!(2023-11-10 08:00:00 UTC);
    let (ca_start_2023, ca_end_2023) = compute_ca_validity(t_2023).expect("validity 2023");
    assert_eq!(ca_start_2023.year(), 2013);
    assert_eq!(ca_end_2023.year(), 2033);

    // Leaf validity: T_clock - 7 days to T_clock + 365 days
    let (leaf_start, leaf_end) = compute_leaf_validity(t_2023).expect("leaf validity");
    assert_eq!(leaf_start, datetime!(2023-11-03 08:00:00 UTC));
    assert_eq!(leaf_end, datetime!(2024-11-09 08:00:00 UTC)); // 365 days later (2024 is leap)
}

#[test]
fn test_openssl_verification() {
    let openssl_check = Command::new("openssl").arg("version").output();
    let openssl_available = match openssl_check {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !openssl_available {
        println!("note: openssl command not available, skipping openssl integration tests");
        return;
    }

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca_path = temp_dir.path().join("ca.pem");
    let leaf_path = temp_dir.path().join("leaf.pem");

    let seed: [u8; 32] = [0x5A; 32];
    let world_id = "test-openssl-world";
    let t_clock = datetime!(2024-06-01 12:00:00 UTC);

    let ca = mint_ca(world_id, t_clock, &seed).expect("mint ca");
    let leaf = mint_leaf(&ca, &["test.hermetic.internal"], t_clock).expect("mint leaf");

    fs::write(&ca_path, ca.cert_pem.as_bytes()).expect("write ca");
    fs::write(&leaf_path, leaf.cert_pem.as_bytes()).expect("write leaf");

    // 1. openssl x509 -noout -text parses CA and shows CA:TRUE
    let x509_out = Command::new("openssl")
        .args(["x509", "-noout", "-text", "-in"])
        .arg(&ca_path)
        .output()
        .expect("run openssl x509");

    assert!(
        x509_out.status.success(),
        "openssl x509 failed: {:?}",
        String::from_utf8_lossy(&x509_out.stderr)
    );
    let text = String::from_utf8_lossy(&x509_out.stdout);
    assert!(
        text.contains("CA:TRUE") || text.contains("CA: True") || text.contains("CA:true"),
        "x509 text must contain CA:TRUE. Output:\n{}",
        text
    );
    assert!(
        text.contains("Certificate Sign") || text.contains("keyCertSign"),
        "x509 text must contain keyCertSign. Output:\n{}",
        text
    );

    // 2. openssl verify -CAfile ca.pem leaf.pem succeeds at time inside window
    let t_inside = t_clock.unix_timestamp();
    let verify_inside = Command::new("openssl")
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().expect("ca_path"),
            "-attime",
            &t_inside.to_string(),
            leaf_path.to_str().expect("leaf_path"),
        ])
        .output()
        .expect("run openssl verify inside");

    assert!(
        verify_inside.status.success(),
        "openssl verify inside window failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify_inside.stdout),
        String::from_utf8_lossy(&verify_inside.stderr)
    );

    // 3. openssl verify fails outside window (e.g. before T_clock - 7 days)
    let t_before = (t_clock - time::Duration::days(10)).unix_timestamp();
    let verify_before = Command::new("openssl")
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().expect("ca_path"),
            "-attime",
            &t_before.to_string(),
            leaf_path.to_str().expect("leaf_path"),
        ])
        .output()
        .expect("run openssl verify before");

    assert!(
        !verify_before.status.success(),
        "openssl verify before window must fail but succeeded"
    );

    // 4. openssl verify fails after leaf expiration (e.g. T_clock + 400 days)
    let t_after = (t_clock + time::Duration::days(400)).unix_timestamp();
    let verify_after = Command::new("openssl")
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().expect("ca_path"),
            "-attime",
            &t_after.to_string(),
            leaf_path.to_str().expect("leaf_path"),
        ])
        .output()
        .expect("run openssl verify after");

    assert!(
        !verify_after.status.success(),
        "openssl verify after window must fail but succeeded"
    );
}

#[test]
fn test_fake_rootfs_install() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(&rootfs).expect("create rootfs");

    // 1. Debian bundle
    let debian_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&debian_dir).expect("create debian dir");
    let debian_bundle = debian_dir.join("ca-certificates.crt");
    fs::write(
        &debian_bundle,
        b"-----BEGIN CERTIFICATE-----\nMIIB...fake...debian\n-----END CERTIFICATE-----\n",
    )
    .expect("write debian bundle");

    // 2. RHEL bundle
    let rhel_dir = rootfs.join("etc/pki/tls/certs");
    fs::create_dir_all(&rhel_dir).expect("create rhel dir");
    let rhel_bundle = rhel_dir.join("ca-bundle.crt");
    fs::write(
        &rhel_bundle,
        b"-----BEGIN CERTIFICATE-----\nMIIB...fake...rhel\n-----END CERTIFICATE-----\n",
    )
    .expect("write rhel bundle");

    // 3. Anchor dirs
    let anchor1 = rootfs.join("usr/local/share/ca-certificates");
    fs::create_dir_all(&anchor1).expect("create anchor1");
    let anchor2 = rootfs.join("etc/pki/ca-trust/source/anchors");
    fs::create_dir_all(&anchor2).expect("create anchor2");

    // 4. certifi bundle 1 (regular file)
    let certifi_dir1 = rootfs.join("usr/local/lib/python3.10/site-packages/certifi");
    fs::create_dir_all(&certifi_dir1).expect("create certifi1");
    let certifi_file1 = certifi_dir1.join("cacert.pem");
    fs::write(
        &certifi_file1,
        b"-----BEGIN CERTIFICATE-----\nMIIB...fake...certifi\n-----END CERTIFICATE-----\n",
    )
    .expect("write certifi1");

    // 5. certifi bundle 2 (symlinked absolutely: /usr/lib/python3/dist-packages/certifi/cacert.pem -> /etc/ssl/certs/ca-certificates.crt)
    let certifi_dir2 = rootfs.join("usr/lib/python3/dist-packages/certifi");
    fs::create_dir_all(&certifi_dir2).expect("create certifi2");
    let certifi_symlink = certifi_dir2.join("cacert.pem");
    std::os::unix::fs::symlink("/etc/ssl/certs/ca-certificates.crt", &certifi_symlink)
        .expect("symlink certifi2");

    // 6. Conda bundle
    let conda_dir = rootfs.join("opt/miniconda3/ssl");
    fs::create_dir_all(&conda_dir).expect("create conda dir");
    let conda_bundle = conda_dir.join("cacert.pem");
    fs::write(
        &conda_bundle,
        b"-----BEGIN CERTIFICATE-----\nMIIB...fake...conda\n-----END CERTIFICATE-----\n",
    )
    .expect("write conda bundle");

    // 7. JKS cacerts
    let jks_dir = rootfs.join("usr/lib/jvm/java-17/lib/security");
    fs::create_dir_all(&jks_dir).expect("create jks dir");
    let jks_path = jks_dir.join("cacerts");
    let jks_initial = create_empty_jks("changeit");
    fs::write(&jks_path, &jks_initial).expect("write jks");

    // 8. PKCS#12 cacerts
    let p12_dir = rootfs.join("usr/lib/jvm/java-11/lib/security");
    fs::create_dir_all(&p12_dir).expect("create p12 dir");
    let p12_path = p12_dir.join("cacerts");
    // ASN.1 sequence mock PKCS#12
    let p12_initial = vec![0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00];
    fs::write(&p12_path, &p12_initial).expect("write p12");

    // Mint CA
    let seed: [u8; 32] = [1u8; 32];
    let ca = mint_ca(
        "test-rootfs-world",
        datetime!(2024-01-01 00:00:00 UTC),
        &seed,
    )
    .expect("mint ca");

    // Install CA
    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");

    // Verify report
    assert_eq!(
        report.ca_cert_sha256,
        hex::encode(sha2::Sha256::digest(&ca.cert_der))
    );
    assert!(!report.modified_paths.is_empty());

    // Verify Debian bundle was modified and contains ca.cert_pem
    let debian_content = fs::read_to_string(&debian_bundle).expect("read debian");
    assert!(debian_content.contains(&ca.cert_pem));

    // Verify RHEL bundle contains ca.cert_pem
    let rhel_content = fs::read_to_string(&rhel_bundle).expect("read rhel");
    assert!(rhel_content.contains(&ca.cert_pem));

    // Verify certifi bundle 1 contains ca.cert_pem
    let certifi1_content = fs::read_to_string(&certifi_file1).expect("read certifi1");
    assert!(certifi1_content.contains(&ca.cert_pem));

    // Verify conda bundle contains ca.cert_pem
    let conda_content = fs::read_to_string(&conda_bundle).expect("read conda");
    assert!(conda_content.contains(&ca.cert_pem));

    // Verify dropped PEM in anchor dirs
    let anchor_file1 = rootfs.join("usr/local/share/ca-certificates/hermetic-world-ca.crt");
    assert!(anchor_file1.exists());
    let anchor_file2 = rootfs.join("etc/pki/ca-trust/source/anchors/hermetic-world-ca.pem");
    assert!(anchor_file2.exists());

    // Verify JKS round-trip: parse back, check alias and integrity
    let jks_bytes = fs::read(&jks_path).expect("read updated jks");
    let (version, entries, _hash) = parse_jks(&jks_bytes).expect("parse jks back");
    assert_eq!(version, 2);
    let ca_entry = entries
        .iter()
        .find(|e| e.alias() == "hermetic-world-ca")
        .expect("hermetic-world-ca entry must exist");
    if let JksEntry::TrustedCert { cert_der, .. } = ca_entry {
        assert_eq!(cert_der, &ca.cert_der);
    } else {
        panic!("entry is not a TrustedCert");
    }

    // Verify PKCS#12 is untouched and reported unsupported
    let p12_bytes = fs::read(&p12_path).expect("read p12");
    assert_eq!(p12_bytes, p12_initial);
    let p12_skipped = report
        .skipped_paths
        .iter()
        .find(|s| s.reason == "unsupported_pkcs12");
    assert!(
        p12_skipped.is_some(),
        "PKCS#12 must be reported unsupported"
    );

    // Verify env defaults point to the existing system bundle
    assert_eq!(
        report.env_defaults.get("SSL_CERT_FILE").map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        report
            .env_defaults
            .get("REQUESTS_CA_BUNDLE")
            .map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        report
            .env_defaults
            .get("CURL_CA_BUNDLE")
            .map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        report.env_defaults.get("PIP_CERT").map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        report
            .env_defaults
            .get("NODE_EXTRA_CA_CERTS")
            .map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        report
            .env_defaults
            .get("GIT_SSL_CAINFO")
            .map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
    assert_eq!(
        report
            .env_defaults
            .get("CARGO_HTTP_CAINFO")
            .map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );

    // Snapshot files before second install
    let debian_before = fs::read(&debian_bundle).expect("read");
    let rhel_before = fs::read(&rhel_bundle).expect("read");
    let certifi1_before = fs::read(&certifi_file1).expect("read");
    let conda_before = fs::read(&conda_bundle).expect("read");
    let jks_before = fs::read(&jks_path).expect("read");

    // Second install must change NOTHING (idempotent)
    let report2 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca second run");
    assert!(
        report2.modified_paths.is_empty(),
        "Second install modified paths: {:?}",
        report2.modified_paths
    );

    assert_eq!(fs::read(&debian_bundle).expect("read"), debian_before);
    assert_eq!(fs::read(&rhel_bundle).expect("read"), rhel_before);
    assert_eq!(fs::read(&certifi_file1).expect("read"), certifi1_before);
    assert_eq!(fs::read(&conda_bundle).expect("read"), conda_before);
    assert_eq!(fs::read(&jks_path).expect("read"), jks_before);
}

#[test]
fn test_hostile_inputs() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(&rootfs).expect("create rootfs");

    // 1. Truncated JKS
    let jks_dir = rootfs.join("opt/java/lib/security");
    fs::create_dir_all(&jks_dir).expect("create jks_dir");
    let trunc_jks = jks_dir.join("cacerts");
    fs::write(&trunc_jks, b"\xFE\xED\xFE\xED\x00\x00\x00\x02").expect("write trunc");

    // 2. Huge entry count JKS
    let jks_dir2 = rootfs.join("opt/java2/lib/security");
    fs::create_dir_all(&jks_dir2).expect("create jks_dir2");
    let huge_jks = jks_dir2.join("cacerts");
    let mut huge_bytes = vec![0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02];
    huge_bytes.extend_from_slice(&0x7FFFFFFF_u32.to_be_bytes()); // huge entry count
    huge_bytes.extend_from_slice(&[0u8; 20]);
    fs::write(&huge_jks, &huge_bytes).expect("write huge");

    // 3. Bundle that is a directory
    let dir_bundle = rootfs.join("opt/ssl/certifi/cacert.pem");
    fs::create_dir_all(&dir_bundle).expect("create dir bundle");

    // 4. Symlink loop
    let loop_a = rootfs.join("opt/loop/ssl/cacert.pem");
    let loop_b = rootfs.join("opt/loop/ssl/loop_b.pem");
    fs::create_dir_all(loop_a.parent().unwrap()).expect("create loop dir");
    std::os::unix::fs::symlink("loop_b.pem", &loop_a).expect("symlink a");
    std::os::unix::fs::symlink("cacert.pem", &loop_b).expect("symlink b");

    // 5. Hostile symlink attempting escape: /../../../../etc/shadow
    let escape_bundle = rootfs.join("opt/escape/certifi/cacert.pem");
    fs::create_dir_all(escape_bundle.parent().unwrap()).expect("create escape dir");
    std::os::unix::fs::symlink("../../../../../../../../../etc/shadow", &escape_bundle)
        .expect("symlink escape");

    let seed: [u8; 32] = [7u8; 32];
    let ca = mint_ca("hostile-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // Must not panic!
    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca on hostile inputs");

    let skipped_reasons: Vec<&str> = report
        .skipped_paths
        .iter()
        .map(|s| s.reason.as_str())
        .collect();

    assert!(
        skipped_reasons
            .iter()
            .any(|r| r.contains("keystore shorter") || r.contains("truncated")),
        "Truncated JKS must be skipped"
    );
    assert!(
        skipped_reasons
            .iter()
            .any(|r| r.contains("hostile entry count")),
        "Huge entry count JKS must be skipped"
    );
    assert!(
        skipped_reasons.iter().any(|r| r == &"bundle_is_directory"),
        "Directory bundle must be skipped as bundle_is_directory"
    );
    assert!(
        skipped_reasons.iter().any(|r| r.contains("symlink loop")),
        "Symlink loop must be detected and skipped"
    );

    // Verify nothing outside rootfs was created or touched
    assert!(!temp_dir.path().join("etc/shadow").exists());
}

#[test]
fn test_seed_file_validation_and_private_key_permissions() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    // 1. Seed file not exactly 32 bytes (31 bytes) -> error
    let short_seed = temp_dir.path().join("short.seed");
    fs::write(&short_seed, [0u8; 31]).expect("write short");
    fs::set_permissions(&short_seed, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(
        read_seed_file(&short_seed),
        Err(TrustError::InvalidSeedFileLength(31))
    ));

    // 2. Seed file not exactly 32 bytes (33 bytes) -> error
    let long_seed = temp_dir.path().join("long.seed");
    fs::write(&long_seed, [0u8; 33]).expect("write long");
    fs::set_permissions(&long_seed, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(
        read_seed_file(&long_seed),
        Err(TrustError::InvalidSeedFileLength(33))
    ));

    // 3. Seed file group/world readable (0644) -> error
    let insecure_seed = temp_dir.path().join("insecure.seed");
    fs::write(&insecure_seed, [0u8; 32]).expect("write insecure");
    fs::set_permissions(&insecure_seed, fs::Permissions::from_mode(0o644)).expect("chmod");
    assert!(matches!(
        read_seed_file(&insecure_seed),
        Err(TrustError::InsecureSeedFilePermissions(_))
    ));

    // 4. Valid seed file (32 bytes, 0600) -> success
    let valid_seed = temp_dir.path().join("valid.seed");
    fs::write(&valid_seed, [9u8; 32]).expect("write valid");
    fs::set_permissions(&valid_seed, fs::Permissions::from_mode(0o600)).expect("chmod");
    let read_bytes = read_seed_file(&valid_seed).expect("read valid seed");
    assert_eq!(read_bytes, [9u8; 32]);

    // 5. Private key output must have mode 0600
    let key_out = temp_dir.path().join("ca.key");
    write_private_key_file(
        &key_out,
        "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n",
    )
    .expect("write private key");
    let meta = fs::metadata(&key_out).expect("metadata");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Private key file mode must be 0600");
}

fn assert_no_key_files(dir: &std::path::Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.ends_with(".key"),
                "key file found in rootfs: {}",
                path.display()
            );
            if path.is_dir() {
                assert_no_key_files(&path);
            }
        }
    }
}

#[test]
fn test_cli_mint_ca_and_install() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let seed_path = temp_dir.path().join("seed.bin");
    fs::write(&seed_path, [42u8; 32]).expect("write seed");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("chmod seed");

    let cert_out = temp_dir.path().join("CA.pem");
    let key_out = temp_dir.path().join("CA.key");

    let bin_path = env!("CARGO_BIN_EXE_hermetic-trust");

    // Test mint-ca
    let status = Command::new(bin_path)
        .args([
            "mint-ca",
            "--world-id",
            "cli-test-world",
            "--t-clock",
            "2024-05-01T10:00:00Z",
            "--ca-seed-file",
            seed_path.to_str().expect("seed_path"),
            "--cert-out",
            cert_out.to_str().expect("cert_out"),
            "--key-out",
            key_out.to_str().expect("key_out"),
        ])
        .status()
        .expect("run mint-ca CLI");

    assert!(status.success());
    assert!(cert_out.exists());
    assert!(key_out.exists());

    let key_meta = fs::metadata(&key_out).expect("key meta");
    assert_eq!(key_meta.permissions().mode() & 0o777, 0o600);

    // Test install CLI
    let rootfs = temp_dir.path().join("rootfs");
    let debian_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&debian_dir).expect("create debian dir");
    fs::write(debian_dir.join("ca-certificates.crt"), b"").expect("create bundle");

    let report_out = temp_dir.path().join("report.json");

    let install_status = Command::new(bin_path)
        .args([
            "install",
            "--rootfs",
            rootfs.to_str().expect("rootfs"),
            "--ca-cert",
            cert_out.to_str().expect("cert_out"),
            "--report",
            report_out.to_str().expect("report_out"),
        ])
        .status()
        .expect("run install CLI");

    assert!(install_status.success());
    assert!(report_out.exists());

    let report_content = fs::read_to_string(&report_out).expect("read report");
    assert!(report_content.contains("ca_cert_sha256"));
    assert!(report_content.contains("SSL_CERT_FILE"));

    // Verify key never appears under rootfs
    assert_no_key_files(&rootfs);
}

fn create_jks_with_private_key(alias: &str, password: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&hermetic_trust::JKS_MAGIC.to_be_bytes());
    data.extend_from_slice(&hermetic_trust::JKS_VERSION_2.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes()); // 1 entry

    // KeyEntry tag = 1
    data.extend_from_slice(&1u32.to_be_bytes());
    let alias_bytes = alias.as_bytes();
    data.extend_from_slice(&(alias_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(alias_bytes);
    data.extend_from_slice(&0i64.to_be_bytes()); // date_ms
    data.extend_from_slice(&4u32.to_be_bytes()); // key_len
    data.extend_from_slice(&[1, 2, 3, 4]); // dummy key bytes
    data.extend_from_slice(&0u32.to_be_bytes()); // chain_len = 0

    let hash = hermetic_trust::compute_jks_integrity_hash(password, &data);
    data.extend_from_slice(&hash);
    data
}

#[test]
fn test_fix1_private_key_leak_and_multiple_certs_rejected() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    let bundle_file = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_file, b"INITIAL_CONTENT\n").expect("write bundle");

    let seed: [u8; 32] = [101u8; 32];
    let ca = mint_ca("fix1-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // 1. Combined cert+key must be rejected and nothing in rootfs modified
    let combined_cert_key = format!("{}\n{}", ca.cert_pem, ca.key_pem);
    let res1 = install_ca(&rootfs, &combined_cert_key);
    assert!(res1.is_err(), "combined cert+key must return error");
    assert_eq!(
        fs::read(&bundle_file).expect("read bundle"),
        b"INITIAL_CONTENT\n"
    );

    // 2. Key first, then cert must also be rejected
    let key_first = format!("{}\n{}", ca.key_pem, ca.cert_pem);
    let res2 = install_ca(&rootfs, &key_first);
    assert!(res2.is_err(), "key-first must return error");
    assert_eq!(
        fs::read(&bundle_file).expect("read bundle"),
        b"INITIAL_CONTENT\n"
    );

    // 3. Two certificates must be rejected
    let two_certs = format!("{}\n{}", ca.cert_pem, ca.cert_pem);
    let res3 = install_ca(&rootfs, &two_certs);
    assert!(res3.is_err(), "two certs must return error");
    assert_eq!(
        fs::read(&bundle_file).expect("read bundle"),
        b"INITIAL_CONTENT\n"
    );
}

#[test]
fn test_fix2_leaf_basic_constraints_der_default() {
    let seed: [u8; 32] = [102u8; 32];
    let t_clock = datetime!(2024-06-01 12:00:00 UTC);
    let ca = mint_ca("fix2-world", t_clock, &seed).expect("mint ca");
    let leaf = mint_leaf(&ca, &["api.hermetic.local"], t_clock).expect("mint leaf");

    // BasicConstraints OID: 2.5.29.19 -> 06 03 55 1D 13
    // In DER: SEQUENCE containing OID and OCTET STRING
    // The OCTET STRING wrapping the empty SEQUENCE has length 2 and bytes 30 00: 04 02 30 00
    let target_seq = [0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00];
    let found = leaf
        .cert_der
        .windows(target_seq.len())
        .any(|w| w == target_seq);
    assert!(
        found,
        "Leaf BasicConstraints extension value bytes must be exactly 30 00 (empty SEQUENCE)"
    );
}

#[test]
fn test_fix3_jks_private_key_alias_collision_and_replace() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let jks_dir = rootfs.join("usr/lib/jvm/lib/security");
    fs::create_dir_all(&jks_dir).expect("create jks dir");
    let jks_path = jks_dir.join("cacerts");

    let seed: [u8; 32] = [103u8; 32];
    let ca = mint_ca("fix3-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // Case 1: PrivateKey entry with alias hermetic-world-ca -> skip without modifying
    let jks_with_pk = create_jks_with_private_key("hermetic-world-ca", "changeit");
    fs::write(&jks_path, &jks_with_pk).expect("write jks");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");
    assert_eq!(
        fs::read(&jks_path).expect("read jks"),
        jks_with_pk,
        "Keystore must be untouched on private key alias collision"
    );
    let skipped = report
        .skipped_paths
        .iter()
        .find(|s| s.reason == "alias collision with private key");
    assert!(
        skipped.is_some(),
        "Report must contain skipped reason 'alias collision with private key'"
    );

    // Case 2: TrustedCert entry with alias hermetic-world-ca -> replace cleanly
    let dummy_old_cert_der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let initial_jks = create_empty_jks("changeit");
    let jks_with_old_cert =
        hermetic_trust::inject_ca_into_jks(&initial_jks, &dummy_old_cert_der, 0)
            .expect("inject old")
            .expect("modified");
    fs::write(&jks_path, &jks_with_old_cert).expect("write old cert jks");

    let report2 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca second");
    assert!(
        report2
            .modified_paths
            .iter()
            .any(|p| p.ends_with("cacerts")),
        "Keystore must be modified when replacing TrustedCert"
    );

    let updated_bytes = fs::read(&jks_path).expect("read updated");
    let (_, entries, _) = parse_jks(&updated_bytes).expect("parse updated");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].alias(), "hermetic-world-ca");
    if let JksEntry::TrustedCert { cert_der, .. } = &entries[0] {
        assert_eq!(
            cert_der, &ca.cert_der,
            "TrustedCert must be updated to new CA cert"
        );
    } else {
        panic!("Entry should be a TrustedCert");
    }
}

#[test]
fn test_fix4_jks_unknown_keystore_password() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let jks_dir = rootfs.join("opt/java/lib/security");
    fs::create_dir_all(&jks_dir).expect("create jks dir");
    let jks_path = jks_dir.join("cacerts");

    let other_jks = create_empty_jks("other");
    fs::write(&jks_path, &other_jks).expect("write other jks");

    let seed: [u8; 32] = [104u8; 32];
    let ca = mint_ca("fix4-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");
    assert_eq!(
        fs::read(&jks_path).expect("read jks"),
        other_jks,
        "Keystore with other password must be left byte-identical"
    );

    let skipped = report
        .skipped_paths
        .iter()
        .find(|s| s.reason == "unknown keystore password");
    assert!(
        skipped.is_some(),
        "Must report skipped with reason 'unknown keystore password'"
    );
}

#[test]
fn test_fix5_fifo_hang_prevention() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    let fifo_path = certs_dir.join("ca-certificates.crt");

    let status = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo command");
    assert!(status.success());

    let seed: [u8; 32] = [105u8; 32];
    let ca = mint_ca("fix5-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca on fifo");
    let skipped = report
        .skipped_paths
        .iter()
        .find(|s| s.path.ends_with("ca-certificates.crt") && s.reason == "not a regular file");
    assert!(
        skipped.is_some(),
        "FIFO must be skipped with reason 'not a regular file'"
    );
}

#[test]
fn test_fix6_env_defaults_chosen_after_successful_append() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");

    // Candidate 1: etc/ssl/certs/ca-certificates.crt is a symlink loop (fails install)
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    let loop_path = certs_dir.join("ca-certificates.crt");
    std::os::unix::fs::symlink("ca-certificates.crt", &loop_path).expect("create loop");

    // Candidate 2: etc/pki/tls/certs/ca-bundle.crt is a normal bundle (succeeds)
    let rhel_dir = rootfs.join("etc/pki/tls/certs");
    fs::create_dir_all(&rhel_dir).expect("create rhel dir");
    let rhel_bundle = rhel_dir.join("ca-bundle.crt");
    fs::write(&rhel_bundle, b"INITIAL_RHEL\n").expect("write rhel");

    let seed: [u8; 32] = [106u8; 32];
    let ca = mint_ca("fix6-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");

    // Default must NOT be candidate 1 (which failed); it must be candidate 2!
    assert_eq!(
        report.env_defaults.get("SSL_CERT_FILE").map(|s| s.as_str()),
        Some("/etc/pki/tls/certs/ca-bundle.crt")
    );
}

#[test]
fn test_fix7_system_bundle_created_when_missing() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");

    // Rootfs has NO system bundle, only a certifi bundle
    let certifi_dir = rootfs.join("usr/local/lib/python3.10/site-packages/certifi");
    fs::create_dir_all(&certifi_dir).expect("create certifi dir");
    let certifi_bundle = certifi_dir.join("cacert.pem");
    fs::write(&certifi_bundle, b"INITIAL_CERTIFI\n").expect("write certifi");

    let seed: [u8; 32] = [107u8; 32];
    let ca = mint_ca("fix7-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");

    let created_bundle = rootfs.join("etc/ssl/certs/ca-certificates.crt");
    assert!(
        created_bundle.exists(),
        "System bundle etc/ssl/certs/ca-certificates.crt must be created"
    );
    let created_content = fs::read_to_string(&created_bundle).expect("read created bundle");
    assert_eq!(
        created_content.trim(),
        ca.cert_pem.trim(),
        "Created system bundle must contain only the CA"
    );

    assert!(
        report
            .modified_paths
            .contains(&"etc/ssl/certs/ca-certificates.crt".to_string()),
        "Report modified_paths must record the created system bundle"
    );

    assert_eq!(
        report.env_defaults.get("SSL_CERT_FILE").map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );
}

#[test]
fn test_fix8_seed_permissions_validation() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    // 0600 passes
    let seed_0600 = temp_dir.path().join("seed_0600.bin");
    fs::write(&seed_0600, [42u8; 32]).expect("write");
    fs::set_permissions(&seed_0600, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(read_seed_file(&seed_0600).is_ok());

    // 0640 fails
    let seed_0640 = temp_dir.path().join("seed_0640.bin");
    fs::write(&seed_0640, [42u8; 32]).expect("write");
    fs::set_permissions(&seed_0640, fs::Permissions::from_mode(0o640)).expect("chmod");
    assert!(matches!(
        read_seed_file(&seed_0640),
        Err(TrustError::InsecureSeedFilePermissions(_))
    ));

    // 0622 fails
    let seed_0622 = temp_dir.path().join("seed_0622.bin");
    fs::write(&seed_0622, [42u8; 32]).expect("write");
    fs::set_permissions(&seed_0622, fs::Permissions::from_mode(0o622)).expect("chmod");
    assert!(matches!(
        read_seed_file(&seed_0622),
        Err(TrustError::InsecureSeedFilePermissions(_))
    ));

    // 0604 fails
    let seed_0604 = temp_dir.path().join("seed_0604.bin");
    fs::write(&seed_0604, [42u8; 32]).expect("write");
    fs::set_permissions(&seed_0604, fs::Permissions::from_mode(0o604)).expect("chmod");
    assert!(matches!(
        read_seed_file(&seed_0604),
        Err(TrustError::InsecureSeedFilePermissions(_))
    ));
}

#[test]
fn test_fix9_host_modification_via_parent_symlinks_prevented() {
    let host_temp = tempfile::tempdir().expect("host tempdir");
    let host_dir = host_temp.path().join("host_ssl_certs");
    fs::create_dir_all(&host_dir).expect("create host dir");
    let host_bundle = host_dir.join("ca-certificates.crt");
    fs::write(&host_bundle, b"HOST_ORIGINAL_BUNDLE\n").expect("write host bundle");

    let rootfs_temp = tempfile::tempdir().expect("rootfs tempdir");
    let rootfs = rootfs_temp.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc/ssl")).expect("create etc/ssl");

    // rootfs etc/ssl/certs is a symlink to absolute path of tmp host dir
    std::os::unix::fs::symlink(&host_dir, rootfs.join("etc/ssl/certs")).expect("symlink to host");

    let seed: [u8; 32] = [109u8; 32];
    let ca = mint_ca("fix9-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // Case A: target absent in rootfs -> host bundle remains unchanged
    let _report1 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca absent target");
    assert_eq!(
        fs::read(&host_bundle).expect("read host"),
        b"HOST_ORIGINAL_BUNDLE\n",
        "Host bundle must be completely untouched!"
    );

    // Case B: target created inside rootfs under rootfs/<host_dir_path> -> updated inside rootfs
    let rootfs_target = rootfs
        .join(host_dir.strip_prefix("/").expect("strip"))
        .join("ca-certificates.crt");
    fs::create_dir_all(rootfs_target.parent().expect("parent")).expect("create dir in rootfs");
    fs::write(&rootfs_target, b"ROOTFS_INITIAL\n").expect("write rootfs initial");

    let _report2 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca present target");
    assert_eq!(
        fs::read(&host_bundle).expect("read host"),
        b"HOST_ORIGINAL_BUNDLE\n",
        "Host bundle must still be completely untouched!"
    );
    let rootfs_updated = fs::read_to_string(&rootfs_target).expect("read rootfs target");
    assert!(
        rootfs_updated.contains(&ca.cert_pem),
        "Rootfs-resolved target must be updated"
    );
}

#[test]
fn test_fix10_key_file_exposure_prevented() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let key_out = temp_dir.path().join("ca.key");

    // Create an existing key file with mode 0644
    fs::write(&key_out, b"old_unsecret_content").expect("write existing");
    fs::set_permissions(&key_out, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
    assert_eq!(
        fs::metadata(&key_out)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );

    let seed: [u8; 32] = [110u8; 32];
    let ca = mint_ca("fix10-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    write_private_key_file(&key_out, &ca.key_pem).expect("write_private_key_file");

    let final_mode = fs::metadata(&key_out)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(final_mode, 0o600, "Final mode must be 0600");
    assert_eq!(
        fs::read_to_string(&key_out).expect("read key"),
        ca.key_pem,
        "Key file content must match"
    );
}

#[test]
fn test_failed_bundle_not_selected_by_repeated_alias() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");

    // Target 1: etc/ssl/certs/ca-certificates.crt in an unwritable directory
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    let bundle_file = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_file, b"INITIAL_CANDIDATE_1\n").expect("write bundle");
    // Make directory non-writable so NamedTempFile::new_in fails during append
    fs::set_permissions(&certs_dir, fs::Permissions::from_mode(0o555)).expect("chmod certs dir");

    // Candidate 2: etc/pki/tls/certs/ca-bundle.crt is a symlink to candidate 1
    let rhel_dir = rootfs.join("etc/pki/tls/certs");
    fs::create_dir_all(&rhel_dir).expect("create rhel dir");
    let rhel_symlink = rhel_dir.join("ca-bundle.crt");
    std::os::unix::fs::symlink("../../ssl/certs/ca-certificates.crt", &rhel_symlink)
        .expect("symlink candidate 2 to candidate 1");

    // Candidate 3: etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem is a valid writable bundle
    let fedora_dir = rootfs.join("etc/pki/ca-trust/extracted/pem");
    fs::create_dir_all(&fedora_dir).expect("create fedora dir");
    let fedora_bundle = fedora_dir.join("tls-ca-bundle.pem");
    fs::write(&fedora_bundle, b"INITIAL_FEDORA_BUNDLE\n").expect("write fedora bundle");

    let seed: [u8; 32] = [111u8; 32];
    let ca = mint_ca("finding1-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");

    // Environment defaults must NOT select candidate 2 (alias of failed candidate 1).
    // Candidate 3 must be selected!
    assert_eq!(
        report.env_defaults.get("SSL_CERT_FILE").map(|s| s.as_str()),
        Some("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    );

    // Target 1 must be recorded in skipped_paths
    assert!(
        report
            .skipped_paths
            .iter()
            .any(|s| s.path.ends_with("ca-certificates.crt")),
        "Failed target 1 must be in skipped_paths"
    );

    // Candidate 3 must have received the CA cert
    let fedora_content = fs::read_to_string(&fedora_bundle).expect("read fedora bundle");
    assert!(fedora_content.contains("INITIAL_FEDORA_BUNDLE"));
    assert!(fedora_content.contains(&ca.cert_pem));

    // Restore permissions for clean temp_dir cleanup
    let _ = fs::set_permissions(&certs_dir, fs::Permissions::from_mode(0o755));
}

#[test]
fn test_preserve_existing_resolved_fallback_bundle() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");

    // rootfs/etc/ssl exists
    fs::create_dir_all(rootfs.join("etc/ssl")).expect("create etc/ssl");

    // rootfs/etc/ssl/certs is a symlink to /guest-certs (which does NOT exist on the host)
    std::os::unix::fs::symlink("/guest-certs", rootfs.join("etc/ssl/certs"))
        .expect("symlink to /guest-certs");

    // rootfs/guest-certs/ca-certificates.crt exists with existing trust anchors
    let guest_dir = rootfs.join("guest-certs");
    fs::create_dir_all(&guest_dir).expect("create guest-certs");
    let existing_bundle = guest_dir.join("ca-certificates.crt");
    let existing_content =
        "-----BEGIN CERTIFICATE-----\nEXISTING_TRUST_ANCHOR\n-----END CERTIFICATE-----\n";
    fs::write(&existing_bundle, existing_content).expect("write existing bundle");

    let seed: [u8; 32] = [112u8; 32];
    let ca = mint_ca("finding2-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");

    // The existing trust anchor MUST be preserved, and the new CA appended
    let updated_content = fs::read_to_string(&existing_bundle).expect("read updated bundle");
    assert!(
        updated_content.contains("EXISTING_TRUST_ANCHOR"),
        "Existing trust anchors must not be wiped out by fallback!"
    );
    assert!(
        updated_content.contains(&ca.cert_pem),
        "New CA must be present in the bundle!"
    );

    // The modified path must be recorded in report
    assert!(
        report
            .modified_paths
            .contains(&"guest-certs/ca-certificates.crt".to_string()),
        "Modified path must be recorded"
    );

    // Default env spec should point to standard guest path
    assert_eq!(
        report.env_defaults.get("SSL_CERT_FILE").map(|s| s.as_str()),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );

    // Idempotency: second run should not re-modify the bundle
    let report2 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca second run");
    assert!(
        !report2
            .modified_paths
            .contains(&"guest-certs/ca-certificates.crt".to_string()),
        "Second run must be idempotent (not re-modified)"
    );

    // Test non-regular file skip preservation in fallback
    let temp_dir2 = tempfile::tempdir().expect("tempdir2");
    let rootfs2 = temp_dir2.path().join("rootfs");
    fs::create_dir_all(rootfs2.join("etc/ssl")).expect("create etc/ssl 2");
    std::os::unix::fs::symlink("/guest-certs", rootfs2.join("etc/ssl/certs"))
        .expect("symlink to /guest-certs 2");
    // Target is a directory instead of a regular file
    fs::create_dir_all(rootfs2.join("guest-certs/ca-certificates.crt")).expect("create dir target");

    let report3 = install_ca(&rootfs2, &ca.cert_pem).expect("install_ca with dir fallback");
    assert!(
        report3
            .skipped_paths
            .iter()
            .any(|s| s.path == "guest-certs/ca-certificates.crt"
                && s.reason == "bundle_is_directory"),
        "Directory bundle in fallback must be skipped with bundle_is_directory"
    );
}
