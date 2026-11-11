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
