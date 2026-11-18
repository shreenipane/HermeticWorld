#![forbid(unsafe_code)]

use sha2::Digest;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;
use time::macros::datetime;

use hermetic_trust::{
    append_pem_bundle_in_root, atomic_write_file, atomic_write_in_root, check_not_alias,
    compute_ca_validity, compute_leaf_validity, create_empty_jks, install_ca_with_options, mint_ca,
    mint_leaf, open_dir_handle, parse_jks, read_cert_file_bounded, read_seed_file,
    validate_dns_name, validate_output_path, write_private_key_file, GuestOwner, InstallOptions,
    InstallReport, JksEntry, TrustError, MAX_CA_CERT_INPUT_BYTES, MAX_HOSTNAME_BYTES,
    MAX_LEAF_HOSTNAMES, NEW_DIR_MODE, NEW_FILE_MODE,
};

/// Owner (uid, gid) that files created by this test process receive.
fn current_owner() -> GuestOwner {
    let probe = tempfile::tempfile().expect("probe tempfile");
    let meta = probe.metadata().expect("probe metadata");
    GuestOwner {
        uid: meta.uid(),
        gid: meta.gid(),
    }
}

/// Install as the test process's own identity. New rootfs entries default to
/// guest root (0:0), which an unprivileged test process cannot assign; the
/// ownership rules themselves are covered by dedicated tests below.
fn install_ca(rootfs: &std::path::Path, ca_cert_pem: &str) -> Result<InstallReport, TrustError> {
    install_ca_with_options(
        rootfs,
        ca_cert_pem,
        &InstallOptions {
            owner: current_owner(),
            report_path: None,
        },
    )
}

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

    // Provide a valid bundle as well so install_ca can establish a usable bundle
    let valid_bundle = rootfs.join("etc/ssl/cert.pem");
    fs::write(&valid_bundle, b"").expect("write cert.pem");

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

    let res3 = install_ca(&rootfs2, &ca.cert_pem);
    assert!(
        res3.is_err(),
        "Directory bundle in fallback must cause install_ca to fail closed"
    );
}

// Defect 1: Unbounded reads
#[test]
fn test_unbounded_reads_sparse_file_capped() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let sparse_pem = temp_dir.path().join("sparse_bundle.pem");
    let f = fs::File::create(&sparse_pem).expect("create sparse pem");
    f.set_len(17 * 1024 * 1024).expect("set_len 17MiB"); // 17 MiB > 16 MiB cap
    drop(f);

    let seed: [u8; 32] = [1u8; 32];
    let ca = mint_ca("cap-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let temp_root = open_dir_handle(temp_dir.path()).expect("open temp root");
    let res = append_pem_bundle_in_root(
        &temp_root,
        std::path::Path::new("sparse_bundle.pem"),
        &ca.cert_pem,
        &ca.cert_der,
        current_owner(),
    );
    assert!(
        res.is_err(),
        "append_pem_bundle_in_root must reject files exceeding 16 MiB"
    );
    let err_str = res.err().unwrap().to_string();
    assert!(err_str.contains("exceeds size cap"));

    // Also test JKS > 8 MiB in rootfs install
    let rootfs = temp_dir.path().join("rootfs");
    let jks_dir = rootfs.join("usr/lib/jvm/default/lib/security");
    fs::create_dir_all(&jks_dir).expect("create jks dir");
    let sparse_jks = jks_dir.join("cacerts");
    let fj = fs::File::create(&sparse_jks).expect("create sparse jks");
    fj.set_len(9 * 1024 * 1024).expect("set_len 9MiB"); // 9 MiB > 8 MiB cap
    drop(fj);

    let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca with oversized jks");
    let skipped = report
        .skipped_paths
        .iter()
        .find(|s| s.path.ends_with("cacerts"));
    assert!(skipped.is_some(), "Oversized JKS must be skipped");
    assert!(skipped.unwrap().reason.contains("exceeds size cap"));

    // Also test anchor read > 16 MiB in rootfs install
    let rootfs_anchor = temp_dir.path().join("rootfs_anchor");
    let anchor_dir = rootfs_anchor.join("usr/local/share/ca-certificates");
    fs::create_dir_all(&anchor_dir).expect("create anchor dir");
    let sparse_anchor = anchor_dir.join("hermetic-world-ca.crt");
    let fa = fs::File::create(&sparse_anchor).expect("create sparse anchor");
    fa.set_len(17 * 1024 * 1024).expect("set_len 17MiB");
    drop(fa);

    let report_anchor =
        install_ca(&rootfs_anchor, &ca.cert_pem).expect("install_ca with oversized anchor");
    let skipped_anchor = report_anchor
        .skipped_paths
        .iter()
        .find(|s| s.path.ends_with("hermetic-world-ca.crt"));
    assert!(skipped_anchor.is_some(), "Oversized anchor must be skipped");
    assert!(skipped_anchor.unwrap().reason.contains("exceeds size cap"));
}

// Defect 2: Output depends on the host filesystem
#[test]
fn test_host_symlink_independence() {
    let host_temp = tempfile::tempdir().expect("host tempdir");
    let host_dir = host_temp.path().join("host_usr_local");
    fs::create_dir_all(host_dir.join("share/ca-certificates")).expect("create host share");

    let seed: [u8; 32] = [2u8; 32];
    let ca = mint_ca(
        "host-indep-world",
        datetime!(2024-01-01 00:00:00 UTC),
        &seed,
    )
    .expect("mint ca");

    // Case 1: host directory exists
    let rootfs_a_temp = tempfile::tempdir().expect("rootfs_a tempdir");
    let rootfs_a = rootfs_a_temp.path().join("rootfs");
    fs::create_dir_all(rootfs_a.join("usr")).expect("create usr");
    std::os::unix::fs::symlink(&host_dir, rootfs_a.join("usr/local")).expect("symlink usr/local");

    let report_a = install_ca(&rootfs_a, &ca.cert_pem).expect("install_ca case A");

    // Case 2: host directory does NOT exist
    let non_existent_host_dir = host_temp.path().join("non_existent_host_usr_local");
    assert!(!non_existent_host_dir.exists());

    let rootfs_b_temp = tempfile::tempdir().expect("rootfs_b tempdir");
    let rootfs_b = rootfs_b_temp.path().join("rootfs");
    fs::create_dir_all(rootfs_b.join("usr")).expect("create usr");
    std::os::unix::fs::symlink(&non_existent_host_dir, rootfs_b.join("usr/local"))
        .expect("symlink usr/local 2");

    let report_b = install_ca(&rootfs_b, &ca.cert_pem).expect("install_ca case B");

    // Both reports must have identical modified and skipped paths
    assert_eq!(report_a.modified_paths, report_b.modified_paths);
    assert_eq!(report_a.env_defaults, report_b.env_defaults);

    // No files created in host_dir
    let host_files: Vec<_> = fs::read_dir(host_dir.join("share/ca-certificates"))
        .expect("read host share")
        .collect();
    assert!(
        host_files.is_empty(),
        "No files may be written to host directory"
    );
}

// Defect 3: Refusal on symlink target
#[test]
fn test_check_then_use_symlink_refusal() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let outside_target = temp_dir.path().join("outside.txt");
    fs::write(&outside_target, b"ORIGINAL_OUTSIDE\n").expect("write outside");

    let symlink_path = temp_dir.path().join("symlink_target");
    std::os::unix::fs::symlink(&outside_target, &symlink_path).expect("create symlink");

    // atomic_write_in_root on a symlink must refuse
    let temp_root = open_dir_handle(temp_dir.path()).expect("open temp root");
    let res = atomic_write_in_root(
        &temp_root,
        std::path::Path::new("symlink_target"),
        b"NEW_DATA\n",
        NEW_FILE_MODE,
        current_owner(),
    );
    assert!(
        res.is_err(),
        "atomic_write_in_root must refuse symlink target"
    );
    assert!(matches!(res.unwrap_err(), TrustError::Symlink(_)));

    // Ensure outside target was not modified
    let content = fs::read(&outside_target).expect("read outside");
    assert_eq!(content, b"ORIGINAL_OUTSIDE\n");
}

// Defect 4: Seed file race & permissions
#[test]
fn test_seed_file_race_symlink_fifo_oversized() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    // 1. Valid seed
    let valid_seed = temp_dir.path().join("valid.seed");
    fs::write(&valid_seed, [7u8; 32]).expect("write valid");
    fs::set_permissions(&valid_seed, fs::Permissions::from_mode(0o600)).expect("chmod");

    // Symlink seed must be rejected
    let symlink_seed = temp_dir.path().join("symlink.seed");
    std::os::unix::fs::symlink(&valid_seed, &symlink_seed).expect("create symlink");
    assert!(
        read_seed_file(&symlink_seed).is_err(),
        "Symlink seed must be rejected"
    );

    // 2. Oversized seed (33 bytes and 100 bytes)
    let seed_33 = temp_dir.path().join("seed_33.bin");
    fs::write(&seed_33, [7u8; 33]).expect("write 33");
    fs::set_permissions(&seed_33, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(
        read_seed_file(&seed_33),
        Err(TrustError::InvalidSeedFileLength(33))
    ));

    let seed_100 = temp_dir.path().join("seed_100.bin");
    fs::write(&seed_100, [7u8; 100]).expect("write 100");
    fs::set_permissions(&seed_100, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(
        read_seed_file(&seed_100),
        Err(TrustError::InvalidSeedFileLength(33))
    ));

    // 3. FIFO seed rejected without blocking
    let fifo_seed = temp_dir.path().join("fifo.seed");
    let status = Command::new("mkfifo")
        .arg(&fifo_seed)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let res = read_seed_file(&fifo_seed);
    assert!(res.is_err(), "FIFO seed must be rejected");
}

// Defect 5: Known-answer test for CA
#[test]
fn test_ca_known_answer_test() {
    let seed: [u8; 32] = [42u8; 32];
    let world_id = "swe-bench-world-kat";
    let t_clock = datetime!(2024-01-01 00:00:00 UTC);

    let ca = mint_ca(world_id, t_clock, &seed).expect("mint ca");

    let cert_sha256 = hex::encode(sha2::Sha256::digest(&ca.cert_der));
    let spki_sha256 = hex::encode(sha2::Sha256::digest(&ca.spki_der));

    assert_eq!(
        cert_sha256,
        "10306bcd579e6dfe86faa01f9bc696c716af4164c7dcbfd3a0b543a86d781133"
    );
    assert_eq!(
        spki_sha256,
        "d7c00c72122e86f76b2c081fcafcb8884649591290db6bb1f59fa0217e120ec0"
    );

    // Verify SPKI is contained in cert_der
    assert!(ca
        .cert_der
        .windows(ca.spki_der.len())
        .any(|w| w == ca.spki_der));
}

// Defect 6: LeafCert Debug redaction
#[test]
fn test_leaf_cert_debug_redacted() {
    let seed: [u8; 32] = [77u8; 32];
    let ca = mint_ca("debug-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let leaf =
        mint_leaf(&ca, &["debug.internal"], datetime!(2024-01-01 00:00:00 UTC)).expect("mint leaf");

    let debug_output = format!("{:?}", leaf);

    assert!(debug_output.contains("[REDACTED]"));
    assert!(!debug_output.contains(&leaf.key_pem));
    assert!(!debug_output.contains("PRIVATE KEY"));

    let key_der_hex = hex::encode(&leaf.key_der);
    assert!(!debug_output.contains(&key_der_hex));

    let key_b64 = leaf
        .key_pem
        .lines()
        .filter(|l| !l.starts_with("---"))
        .collect::<Vec<_>>()
        .join("");
    assert!(!debug_output.contains(&key_b64));

    for line in leaf.key_pem.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("---") {
            assert!(!debug_output.contains(trimmed));
        }
    }
}

// =========================================================================
// Security Review Regression Tests (Defects 1 - 11)
// =========================================================================

// Defect 1: Synchronize final-component and ancestor swaps between validation and use;
// assert no outside reads, writes, chmods, or FIFO blocking.
#[test]
fn test_defect1_handle_anchoring_and_swap_race_protection() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir_all(&outside_dir).expect("create outside");
    let outside_victim = outside_dir.join("victim.txt");
    fs::write(&outside_victim, b"OUTSIDE_INITIAL").expect("write victim");
    let initial_victim_meta = fs::metadata(&outside_victim).expect("meta");

    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let bundle_path = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_path, b"INITIAL_BUNDLE\n").expect("write bundle");

    // Case 1: Final component swapped with symlink to outside file before use
    {
        let bundle_clone = bundle_path.clone();
        let victim_clone = outside_victim.clone();
        let hook_guard = hermetic_trust::set_before_use_hook_guard(move || {
            let _ = fs::remove_file(&bundle_clone);
            let _ = std::os::unix::fs::symlink(&victim_clone, &bundle_clone);
        });

        let root = open_dir_handle(&rootfs).expect("open rootfs");
        let res = atomic_write_in_root(
            &root,
            std::path::Path::new("etc/ssl/certs/ca-certificates.crt"),
            b"MALICIOUS_DATA",
            NEW_FILE_MODE,
            current_owner(),
        );
        drop(hook_guard);

        assert!(res.is_err(), "Must reject final-component symlink swap");
        let victim_content = fs::read(&outside_victim).expect("read victim");
        assert_eq!(
            victim_content, b"OUTSIDE_INITIAL",
            "Outside file must not be modified by final-component symlink race"
        );
        let curr_meta = fs::metadata(&outside_victim).expect("meta");
        assert_eq!(
            initial_victim_meta.permissions().mode(),
            curr_meta.permissions().mode(),
            "Outside file permissions must not be chmod'ed"
        );
    }

    // Case 2: Final component swapped with FIFO before use - must not block
    {
        let fifo_path = certs_dir.join("fifo_race.crt");
        let status = Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let fifo_clone = fifo_path.clone();
        let bundle_clone = certs_dir.join("ca-certificates2.crt");
        fs::write(&bundle_clone, b"BUNDLE2").expect("write");

        let bundle_hook = bundle_clone.clone();
        let hook_guard = hermetic_trust::set_before_use_hook_guard(move || {
            let _ = fs::remove_file(&bundle_hook);
            let _ = fs::rename(&fifo_clone, &bundle_hook);
        });

        let root = open_dir_handle(&rootfs).expect("open rootfs");
        let _ = atomic_write_in_root(
            &root,
            std::path::Path::new("etc/ssl/certs/ca-certificates2.crt"),
            b"NEW_DATA",
            NEW_FILE_MODE,
            current_owner(),
        );
        drop(hook_guard);
    }

    // Case 3: Ancestor swapped with symlink to outside before use
    {
        let rootfs2 = temp_dir.path().join("rootfs2");
        let ssl_dir = rootfs2.join("etc/ssl");
        let certs2_dir = ssl_dir.join("certs");
        fs::create_dir_all(&certs2_dir).expect("create certs2");
        let bundle2_path = certs2_dir.join("ca-certificates.crt");
        fs::write(&bundle2_path, b"INITIAL\n").expect("write");

        let outside_dir2 = temp_dir.path().join("outside2");
        fs::create_dir_all(&outside_dir2).expect("outside2");
        let canary_file = outside_dir2.join("canary.txt");
        fs::write(&canary_file, b"CANARY_INITIAL").expect("write canary");

        let ssl_clone = ssl_dir.clone();
        let ssl_moved = rootfs2.join("etc/ssl_old");
        let outside_clone = outside_dir2.clone();

        let hook_guard = hermetic_trust::set_before_use_hook_guard(move || {
            if fs::rename(&ssl_clone, &ssl_moved).is_ok() {
                let _ = std::os::unix::fs::symlink(&outside_clone, &ssl_clone);
            }
        });

        let root2 = open_dir_handle(&rootfs2).expect("open rootfs2");
        let _ = atomic_write_in_root(
            &root2,
            std::path::Path::new("etc/ssl/certs/ca-certificates.crt"),
            b"ANCHORED_DATA",
            NEW_FILE_MODE,
            current_owner(),
        );
        drop(hook_guard);

        let canary_content = fs::read(&canary_file).expect("read canary");
        assert_eq!(
            canary_content, b"CANARY_INITIAL",
            "Outside canary file must not be modified through ancestor swap"
        );
        assert!(
            !outside_dir2.join("ca-certificates.crt").exists(),
            "No file should have been written into outside directory through ancestor swap"
        );
    }

    // Case 4: Target swapped with outside symlink before read - must not read outside
    {
        let read_target = certs_dir.join("read_target.crt");
        fs::write(&read_target, b"TARGET_INITIAL\n").expect("write");
        let outside_secret = outside_dir.join("secret.txt");
        fs::write(&outside_secret, b"SECRET_OUTSIDE_DATA").expect("write secret");

        let target_clone = read_target.clone();
        let secret_clone = outside_secret.clone();
        let hook_guard = hermetic_trust::set_before_use_hook_guard(move || {
            let _ = fs::remove_file(&target_clone);
            let _ = std::os::unix::fs::symlink(&secret_clone, &target_clone);
        });

        let (parent_handle, file_name) = hermetic_trust::open_parent_dir_handle(
            &rootfs,
            std::path::Path::new("etc/ssl/certs/read_target.crt"),
        )
        .expect("parent");
        let read_res =
            hermetic_trust::read_file_capped_from_parent(&parent_handle, &file_name, 1024);
        drop(hook_guard);

        assert!(
            read_res.is_err(),
            "Must refuse reading through swapped symlink"
        );
    }
}

// Defect 2: --ca-cert size cap, regular file validation, non-blocking descriptor reads.
#[test]
fn test_defect2_ca_cert_input_validation_and_caps() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    // 1. Oversized sparse file
    let sparse_cert = temp_dir.path().join("sparse_cert.pem");
    let f = fs::File::create(&sparse_cert).expect("create sparse");
    f.set_len(MAX_CA_CERT_INPUT_BYTES + 1024).expect("set_len");
    drop(f);

    let res = read_cert_file_bounded(&sparse_cert);
    assert!(res.is_err(), "Oversized sparse file must be rejected");

    // Also verify library entry point install_ca rejects oversized cert string
    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc/ssl/certs")).expect("create certs");
    fs::write(rootfs.join("etc/ssl/certs/ca-certificates.crt"), b"").expect("write bundle");
    let huge_pem = "A".repeat(MAX_CA_CERT_INPUT_BYTES as usize + 10);
    let res_install = install_ca(&rootfs, &huge_pem);
    assert!(
        res_install.is_err(),
        "install_ca must reject oversized ca-cert string at entry point"
    );
    let bundle_content = fs::read(rootfs.join("etc/ssl/certs/ca-certificates.crt")).expect("read");
    assert_eq!(bundle_content, b"", "Rootfs must remain unmodified");

    // 2. FIFO ca-cert rejected promptly without blocking
    let fifo_cert = temp_dir.path().join("fifo_cert.pem");
    let status = Command::new("mkfifo")
        .arg(&fifo_cert)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let res_fifo = read_cert_file_bounded(&fifo_cert);
    assert!(res_fifo.is_err(), "FIFO ca-cert must be rejected");

    // 3. Device rejected
    let dev_null = std::path::Path::new("/dev/null");
    if dev_null.exists() {
        let res_dev = read_cert_file_bounded(dev_null);
        assert!(res_dev.is_err(), "Device /dev/null must be rejected");
    }

    // 4. Symlink rejected
    let valid_cert = temp_dir.path().join("valid_cert.pem");
    fs::write(&valid_cert, b"DUMMY_CERT").expect("write valid");
    let symlink_cert = temp_dir.path().join("symlink_cert.pem");
    std::os::unix::fs::symlink(&valid_cert, &symlink_cert).expect("symlink");
    let res_sym = read_cert_file_bounded(&symlink_cert);
    assert!(res_sym.is_err(), "Symlink ca-cert must be rejected");
}

// Defect 3: Validate complete X.509 CA certificate (CA constraints, signature) before mutation.
#[test]
fn test_defect3_ca_certificate_der_validation() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let bundle_path = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_path, b"ORIGINAL_BUNDLE\n").expect("write original");

    let seed: [u8; 32] = [42u8; 32];
    let ca = mint_ca("der-val-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let leaf =
        mint_leaf(&ca, &["leaf.local"], datetime!(2024-01-01 00:00:00 UTC)).expect("mint leaf");

    // 1. Arbitrary DER (AQID)
    let arbitrary_der = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let res1 = install_ca(&rootfs, arbitrary_der);
    assert!(res1.is_err(), "Arbitrary DER AQID must be rejected");
    assert_eq!(
        fs::read(&bundle_path).expect("read"),
        b"ORIGINAL_BUNDLE\n",
        "Rootfs must remain unchanged"
    );

    // 2. Relabeled PKCS#8 private key as CERTIFICATE
    let relabeled_key = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        ca.key_pem
            .lines()
            .filter(|l| !l.starts_with("---"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let res2 = install_ca(&rootfs, &relabeled_key);
    assert!(res2.is_err(), "Relabeled private key must be rejected");
    assert_eq!(
        fs::read(&bundle_path).expect("read"),
        b"ORIGINAL_BUNDLE\n",
        "Rootfs must remain unchanged"
    );

    // 3. Truncated certificate
    let truncated_der = &ca.cert_der[..ca.cert_der.len() / 2];
    let truncated_pem = pem::encode(&pem::Pem::new("CERTIFICATE", truncated_der.to_vec()));
    let res3 = install_ca(&rootfs, &truncated_pem);
    assert!(res3.is_err(), "Truncated certificate must be rejected");
    assert_eq!(
        fs::read(&bundle_path).expect("read"),
        b"ORIGINAL_BUNDLE\n",
        "Rootfs must remain unchanged"
    );

    // 4. Non-CA certificate (valid leaf cert without CA:true constraint)
    let res4 = install_ca(&rootfs, &leaf.cert_pem);
    assert!(res4.is_err(), "Non-CA leaf certificate must be rejected");
    assert_eq!(
        fs::read(&bundle_path).expect("read"),
        b"ORIGINAL_BUNDLE\n",
        "Rootfs must remain unchanged"
    );
}

// Defect 4: Checked date arithmetic for CA and leaf validity without panicking.
#[test]
fn test_defect4_validity_date_arithmetic_overflow() {
    let seed: [u8; 32] = [99u8; 32];
    let ca = mint_ca("valid-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // 1. Leaf validity checked arithmetic
    // Year 9999-12-31 overflows 365 days
    let max_year_dt = datetime!(9999-12-31 00:00:00 UTC);
    let res_leaf_9999 = compute_leaf_validity(max_year_dt);
    assert!(
        res_leaf_9999.is_err(),
        "Leaf validity on 9999-12-31 must return error"
    );

    // Year 0000-01-01 boundary
    let min_year_dt = datetime!(0000-01-01 00:00:00 UTC);
    let res_leaf_min = compute_leaf_validity(min_year_dt);
    let _ = res_leaf_min;

    // 2. CA validity checked arithmetic
    // 20 years from year 9990 exceeds 9999
    let high_year_dt = datetime!(9990-01-01 00:00:00 UTC);
    let res_ca_high = compute_ca_validity(high_year_dt);
    assert!(
        res_ca_high.is_err(),
        "CA validity on 9990-01-01 must return error"
    );

    // 3. mint_ca and mint_leaf return error without panicking or generating keys
    let res_mint_ca = mint_ca("overflow-world", high_year_dt, &seed);
    assert!(
        res_mint_ca.is_err(),
        "mint_ca on overflowing date must return error before generating keys"
    );

    let res_mint_leaf = mint_leaf(&ca, &["example.com"], max_year_dt);
    assert!(
        res_mint_leaf.is_err(),
        "mint_leaf on overflowing date must return error before generating keys"
    );
}

// Defect 5: Return failure unless a usable bundle containing CA was established.
#[test]
fn test_defect5_fallback_bundle_failure_requires_err() {
    let seed: [u8; 32] = [55u8; 32];
    let ca = mint_ca("fallback-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // Case 1: Fallback candidate is a directory and no other system bundle exists
    {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rootfs = temp_dir.path().join("rootfs");
        let fallback_dir = rootfs.join("etc/ssl/certs/ca-certificates.crt");
        fs::create_dir_all(&fallback_dir).expect("create fallback as dir");

        let res = install_ca(&rootfs, &ca.cert_pem);
        assert!(
            res.is_err(),
            "install_ca must fail when directory fallback cannot be used and no other bundle exists"
        );
    }

    // Case 2: Fallback candidate is a FIFO and no other system bundle exists
    {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rootfs = temp_dir.path().join("rootfs");
        let certs_dir = rootfs.join("etc/ssl/certs");
        fs::create_dir_all(&certs_dir).expect("create certs");
        let fallback_fifo = certs_dir.join("ca-certificates.crt");
        let status = Command::new("mkfifo")
            .arg(&fallback_fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let res = install_ca(&rootfs, &ca.cert_pem);
        assert!(
            res.is_err(),
            "install_ca must fail when FIFO fallback cannot be used and no other bundle exists"
        );
    }

    // Case 3: Fallback candidate is oversized and no other system bundle exists
    {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rootfs = temp_dir.path().join("rootfs");
        let certs_dir = rootfs.join("etc/ssl/certs");
        fs::create_dir_all(&certs_dir).expect("create certs");
        let fallback_huge = certs_dir.join("ca-certificates.crt");
        let f = fs::File::create(&fallback_huge).expect("create");
        f.set_len(20 * 1024 * 1024).expect("set_len"); // > 16 MB MAX_PEM_BUNDLE_BYTES
        drop(f);

        let res = install_ca(&rootfs, &ca.cert_pem);
        assert!(
            res.is_err(),
            "install_ca must fail when oversized fallback cannot be used and no other bundle exists"
        );
    }
}

// Defect 6: Enforce named limits during bounded discovery before writes begin.
#[test]
fn test_defect6_tree_walk_bounded_discovery_limits() {
    let seed: [u8; 32] = [66u8; 32];
    let ca = mint_ca(
        "tree-limits-world",
        datetime!(2024-01-01 00:00:00 UTC),
        &seed,
    )
    .expect("mint ca");

    // 1. Exceed depth limit (MAX_TREE_DEPTH = 64)
    {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rootfs = temp_dir.path().join("rootfs");
        let mut deep_path = rootfs.clone();
        for i in 0..70 {
            deep_path = deep_path.join(format!("level_{}", i));
        }
        fs::create_dir_all(&deep_path).expect("create deep dirs");
        fs::write(deep_path.join("ca-bundle.crt"), b"VALID_BUNDLE\n").expect("write bundle");

        let res = install_ca(&rootfs, &ca.cert_pem);
        assert!(
            matches!(res, Err(TrustError::Cert(_))),
            "Must return error when depth exceeds limit: {:?}",
            res
        );
    }

    // 2. Exceed aggregate bytes limit (MAX_AGGREGATE_BYTES = 64 MB) with individually valid files
    {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rootfs = temp_dir.path().join("rootfs");
        let certs_dir = rootfs.join("etc/ssl/certs");
        fs::create_dir_all(&certs_dir).expect("create certs");

        // Create 65 sparse files of 1 MB each (< 16 MB individual cap, but sum > 64 MB)
        for i in 0..65 {
            let p_dir = rootfs.join(format!("pkg_{}/certifi", i));
            fs::create_dir_all(&p_dir).expect("create pkg dir");
            let p = p_dir.join("cacert.pem");
            let f = fs::File::create(&p).expect("create");
            f.set_len(1024 * 1024 + 10).expect("set_len");
        }

        let res = install_ca(&rootfs, &ca.cert_pem);
        assert!(
            matches!(res, Err(TrustError::Cert(_))),
            "Must return error when aggregate bytes exceed limit: {:?}",
            res
        );

        // Verify no partial installation occurred
        for i in 0..65 {
            let p = rootfs.join(format!("pkg_{}/certifi/cacert.pem", i));
            let meta = fs::metadata(&p).expect("meta");
            assert_eq!(
                meta.len(),
                1024 * 1024 + 10,
                "Files must not be partially modified"
            );
        }
    }
}

// Defect 7: Deterministic candidate ordering, report sorting, and conflicting format rejection.
#[test]
fn test_defect7_deterministic_ordering_and_conflicts() {
    let seed: [u8; 32] = [77u8; 32];
    let ca = mint_ca("order-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    // 1. Conflicting target formats: PEM candidate targeting a JKS file (or vice versa)
    {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let rootfs = temp_dir.path().join("rootfs");
        let certs_dir = rootfs.join("etc/ssl/certs");
        fs::create_dir_all(&certs_dir).expect("create certs");
        let valid_bundle = certs_dir.join("ca-certificates.crt");
        fs::write(&valid_bundle, b"").expect("write valid bundle");

        // Create a JKS keystore at python certifi path (which is a PEM target)
        let certifi_dir = rootfs.join("usr/lib/python3.10/site-packages/certifi");
        fs::create_dir_all(&certifi_dir).expect("certifi dir");
        let conflicting_file = certifi_dir.join("cacert.pem");
        let jks_data = create_empty_jks("changeit");
        fs::write(&conflicting_file, &jks_data).expect("write jks at pem target");

        let report = install_ca(&rootfs, &ca.cert_pem).expect("install_ca");
        let skipped = report
            .skipped_paths
            .iter()
            .find(|s| s.path.ends_with("certifi/cacert.pem"));
        assert!(
            skipped.is_some(),
            "Conflicting PEM/JKS format must be skipped"
        );
        assert_eq!(
            skipped.unwrap().reason,
            "conflicting_target_format",
            "Reason must be stable code 'conflicting_target_format'"
        );

        // Conflicting file must not be corrupted
        let cur_bytes = fs::read(&conflicting_file).expect("read");
        assert_eq!(
            cur_bytes, jks_data,
            "Conflicting target must not be corrupted"
        );
    }

    // 2. Deterministic ordering: reverse candidate creation order, assert identical reports and bytes
    {
        let temp_dir1 = tempfile::tempdir().expect("tempdir1");
        let temp_dir2 = tempfile::tempdir().expect("tempdir2");
        let rootfs1 = temp_dir1.path().join("rootfs");
        let rootfs2 = temp_dir2.path().join("rootfs");

        let paths = [
            "etc/ssl/certs/ca-certificates.crt",
            "etc/pki/tls/certs/ca-bundle.crt",
            "etc/ssl/cert.pem",
        ];

        // Create in forward order in rootfs1
        for p in &paths {
            let full = rootfs1.join(p);
            fs::create_dir_all(full.parent().unwrap()).expect("mkdir");
            fs::write(&full, b"BUNDLE_DATA\n").expect("write");
        }

        // Create in reverse order in rootfs2
        for p in paths.iter().rev() {
            let full = rootfs2.join(p);
            fs::create_dir_all(full.parent().unwrap()).expect("mkdir");
            fs::write(&full, b"BUNDLE_DATA\n").expect("write");
        }

        let report1 = install_ca(&rootfs1, &ca.cert_pem).expect("install 1");
        let report2 = install_ca(&rootfs2, &ca.cert_pem).expect("install 2");

        let rep1_json = serde_json::to_string(&report1).expect("json 1");
        let rep2_json = serde_json::to_string(&report2).expect("json 2");
        assert_eq!(
            rep1_json, rep2_json,
            "Reports must be deterministically identical"
        );

        for p in &paths {
            let b1 = fs::read(rootfs1.join(p)).expect("read 1");
            let b2 = fs::read(rootfs2.join(p)).expect("read 2");
            assert_eq!(b1, b2, "File contents must be byte-for-byte identical");
        }
    }
}

// Defect 8: Output safety, alias/collision checks, and safe atomic replacement.
#[test]
fn test_defect8_output_safety_and_atomic_replacement() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    // 1. Output path is a symlink: validate_output_path and atomic_write_file reject it
    let victim = temp_dir.path().join("victim.txt");
    fs::write(&victim, b"PRESERVE_ME").expect("write victim");
    let symlink_out = temp_dir.path().join("out_symlink.pem");
    std::os::unix::fs::symlink(&victim, &symlink_out).expect("symlink");

    let val_res = validate_output_path(&symlink_out);
    assert!(
        val_res.is_err(),
        "validate_output_path must reject symlink output"
    );

    let write_res = atomic_write_file(&symlink_out, b"OVERWRITE", None);
    assert!(
        write_res.is_err(),
        "atomic_write_file must reject symlink output"
    );
    assert_eq!(
        fs::read(&victim).expect("read victim"),
        b"PRESERVE_ME",
        "Target of output symlink must not be truncated or overwritten"
    );

    // 2. Output aliasing seed file
    let seed_path = temp_dir.path().join("ca.seed");
    fs::write(&seed_path, [42u8; 32]).expect("write seed");
    let alias_res = check_not_alias(&seed_path, &seed_path, "cert_out", "ca_seed_file");
    assert!(alias_res.is_err(), "check_not_alias must reject same path");

    // Hard link alias to seed file
    let seed_hardlink = temp_dir.path().join("seed_link.seed");
    fs::hard_link(&seed_path, &seed_hardlink).expect("hardlink");
    let hardlink_res = check_not_alias(&seed_hardlink, &seed_path, "cert_out", "ca_seed_file");
    assert!(
        hardlink_res.is_err(),
        "check_not_alias must reject hardlink/inode alias"
    );

    // 3. Equal certificate and key output paths
    let cert_out = temp_dir.path().join("out.pem");
    let key_out = temp_dir.path().join("out.pem");
    let equal_res = check_not_alias(&cert_out, &key_out, "cert_out", "key_out");
    assert!(
        equal_res.is_err(),
        "check_not_alias must reject equal cert and key paths"
    );

    // 4. Safe atomic replacement preserves existing file if write fails
    let existing_file = temp_dir.path().join("existing.pem");
    fs::write(&existing_file, b"INITIAL_CONTENT").expect("write existing");
    let bad_path = temp_dir.path().join("existing.pem/cannot_create_dir");
    let fail_write = atomic_write_file(&bad_path, b"NEW", None);
    assert!(fail_write.is_err());
    assert_eq!(
        fs::read(&existing_file).expect("read"),
        b"INITIAL_CONTENT",
        "Existing file must be preserved"
    );
}

// Defect 9: Error strings in reports do not expose host staging paths; stable relative paths.
#[test]
fn test_defect9_host_path_disclosure_prevention() {
    let seed: [u8; 32] = [88u8; 32];
    let ca = mint_ca("prefix-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let staging_alice = temp_dir.path().join("alice_staging_prefix/rootfs");
    let staging_bob = temp_dir.path().join("bob_staging_prefix/rootfs");

    for root in [&staging_alice, &staging_bob] {
        let certs = root.join("etc/ssl/certs");
        fs::create_dir_all(&certs).expect("create certs");
        // Valid bundle so install succeeds
        fs::write(certs.join("ca-certificates.crt"), b"").expect("write bundle");

        // Oversized file that triggers a skip
        let oversized = certs.join("oversized.crt");
        let f = fs::File::create(&oversized).expect("create");
        f.set_len(17 * 1024 * 1024).expect("set_len"); // > 16 MB
    }

    let report_alice = install_ca(&staging_alice, &ca.cert_pem).expect("install alice");
    let report_bob = install_ca(&staging_bob, &ca.cert_pem).expect("install bob");

    let rep_alice_json = serde_json::to_string(&report_alice).expect("json alice");
    let rep_bob_json = serde_json::to_string(&report_bob).expect("json bob");

    // Assert reports are byte-for-byte identical
    assert_eq!(
        rep_alice_json, rep_bob_json,
        "Reports under different prefixes must be identical"
    );

    // Assert neither report contains host staging directory names
    assert!(
        !rep_alice_json.contains("alice_staging_prefix"),
        "Report must not expose alice host staging prefix"
    );
    assert!(
        !rep_bob_json.contains("bob_staging_prefix"),
        "Report must not expose bob host staging prefix"
    );
}

// Defect 10: Ownership-preservation failure propagation; original file preserved untouched.
#[test]
fn test_defect10_ownership_preservation_failure_propagation() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let target_file = temp_dir.path().join("target_bundle.crt");
    fs::write(&target_file, b"ORIGINAL_TARGET_BYTES\n").expect("write target");
    fs::set_permissions(&target_file, fs::Permissions::from_mode(0o644)).expect("chmod");

    let initial_meta = fs::metadata(&target_file).expect("meta");
    let initial_ino = initial_meta.ino();
    let initial_dev = initial_meta.dev();
    let initial_uid = initial_meta.uid();
    let initial_gid = initial_meta.gid();
    let initial_mode = initial_meta.permissions().mode();

    // Force ownership setting failure via the thread-local test hook
    let temp_root = open_dir_handle(temp_dir.path()).expect("open temp root");
    let guard = hermetic_trust::set_chown_failure_guard();
    let res = atomic_write_in_root(
        &temp_root,
        std::path::Path::new("target_bundle.crt"),
        b"NEW_DATA_SHOULD_FAIL",
        NEW_FILE_MODE,
        current_owner(),
    );
    drop(guard);

    assert!(res.is_err(), "Must propagate chown failure as an error");

    // Assert original target file is completely preserved
    let current_meta = fs::metadata(&target_file).expect("meta");
    assert_eq!(
        current_meta.ino(),
        initial_ino,
        "Inode must remain unchanged"
    );
    assert_eq!(current_meta.dev(), initial_dev, "Dev must remain unchanged");
    assert_eq!(current_meta.uid(), initial_uid, "UID must remain unchanged");
    assert_eq!(current_meta.gid(), initial_gid, "GID must remain unchanged");
    assert_eq!(
        current_meta.permissions().mode(),
        initial_mode,
        "Mode must remain unchanged"
    );
    assert_eq!(
        fs::read(&target_file).expect("read"),
        b"ORIGINAL_TARGET_BYTES\n",
        "Target contents must remain unchanged"
    );
}

// Defect 11: DNS SAN hostname validation, caps, and unambiguous derivation encoding.
#[test]
fn test_defect11_hostname_validation_and_derivation() {
    let seed: [u8; 32] = [11u8; 32];
    let ca = mint_ca("host-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let t_clock = datetime!(2024-01-01 00:00:00 UTC);

    // 1. Reject empty hostname
    assert!(
        validate_dns_name("").is_err(),
        "Empty hostname must be rejected"
    );
    assert!(
        mint_leaf(&ca, &[""], t_clock).is_err(),
        "mint_leaf with empty hostname must fail"
    );

    // 2. Reject non-ASCII hostname
    assert!(
        validate_dns_name("é.example").is_err(),
        "Non-ASCII hostname must be rejected"
    );
    assert!(mint_leaf(&ca, &["é.example"], t_clock).is_err());

    // 3. Reject NUL-containing hostname
    assert!(
        validate_dns_name("host\0.com").is_err(),
        "NUL byte must be rejected"
    );
    assert!(mint_leaf(&ca, &["host\0.com"], t_clock).is_err());

    // 4. Reject comma-containing hostname
    assert!(
        validate_dns_name("a,b.com").is_err(),
        "Comma must be rejected"
    );
    assert!(mint_leaf(&ca, &["a,b.com"], t_clock).is_err());

    // 5. Reject oversized hostname (> 253 bytes)
    let long_label = "a".repeat(60);
    let oversized = format!(
        "{}.{}.{}.{}.example.com",
        long_label, long_label, long_label, long_label
    );
    assert!(oversized.len() > MAX_HOSTNAME_BYTES);
    assert!(
        validate_dns_name(&oversized).is_err(),
        "Oversized hostname must be rejected"
    );
    assert!(mint_leaf(&ca, &[&oversized], t_clock).is_err());

    // 6. Reject excessive hostname count (> 100)
    let many_hosts: Vec<String> = (0..=MAX_LEAF_HOSTNAMES)
        .map(|i| format!("h{}.local", i))
        .collect();
    assert!(
        mint_leaf(&ca, &many_hosts, t_clock).is_err(),
        "Excessive hostname count must be rejected"
    );

    // 7. Unambiguous derivation encoding
    let leaf_pair = mint_leaf(&ca, &["a.local", "b.local"], t_clock).expect("mint pair");
    assert!(!leaf_pair.cert_der.is_empty());
}

fn sign_custom_tbs(tbs_der: &[u8], key: &rsa::RsaPrivateKey) -> String {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use sha2::Sha256;
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let sig = signing_key.sign(tbs_der);
    let sig_bit_str = hermetic_trust::asn1::encode_bit_string(0, &sig.to_vec());
    let sig_alg = hermetic_trust::asn1::encode_sha256_with_rsa_algorithm();
    let cert_der = hermetic_trust::asn1::encode_sequence(&[tbs_der, &sig_alg, &sig_bit_str]);
    pem::encode(&pem::Pem::new("CERTIFICATE", cert_der))
}

fn create_multi_entry_jks(entries: &[(&str, bool, &[u8])], password: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&hermetic_trust::JKS_MAGIC.to_be_bytes());
    data.extend_from_slice(&hermetic_trust::JKS_VERSION_2.to_be_bytes());
    data.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    for (alias, is_pk, bytes) in entries {
        if *is_pk {
            // KeyEntry tag = 1
            data.extend_from_slice(&1u32.to_be_bytes());
            let alias_bytes = alias.as_bytes();
            data.extend_from_slice(&(alias_bytes.len() as u16).to_be_bytes());
            data.extend_from_slice(alias_bytes);
            data.extend_from_slice(&0i64.to_be_bytes()); // date_ms
            data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(bytes);
            data.extend_from_slice(&0u32.to_be_bytes()); // chain_len = 0
        } else {
            // TrustedCertEntry tag = 2
            data.extend_from_slice(&2u32.to_be_bytes());
            let alias_bytes = alias.as_bytes();
            data.extend_from_slice(&(alias_bytes.len() as u16).to_be_bytes());
            data.extend_from_slice(alias_bytes);
            data.extend_from_slice(&0i64.to_be_bytes()); // date_ms
            let cert_type = "X.509".as_bytes();
            data.extend_from_slice(&(cert_type.len() as u16).to_be_bytes());
            data.extend_from_slice(cert_type);
            data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(bytes);
        }
    }

    let hash = hermetic_trust::compute_jks_integrity_hash(password, &data);
    data.extend_from_slice(&hash);
    data
}

// Regression test for item 1: malformed multibyte UTCTime and GeneralizedTime values
#[test]
fn test_regression_malformed_multibyte_asn1_time() {
    use hermetic_trust::asn1::*;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let bundle_path = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_path, b"ORIGINAL_BUNDLE\n").expect("write original");

    let seed: [u8; 32] = [42u8; 32];
    let ca = mint_ca("time-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let (_not_before, not_after) =
        compute_ca_validity(datetime!(2024-01-01 00:00:00 UTC)).expect("validity");

    let version_der = encode_explicit(0, &encode_integer(&[2]));
    let serial_der = encode_integer(&[1u8; 16]);
    let sig_alg_der = encode_sha256_with_rsa_algorithm();

    let bc_value = encode_sequence(&[&encode_boolean(true)]);
    let bc_extn = encode_sequence(&[
        &encode_oid(OID_BASIC_CONSTRAINTS),
        &encode_boolean(true),
        &encode_octet_string(&bc_value),
    ]);
    let ku_bits = encode_bit_string(1, &[0x06]);
    let ku_extn = encode_sequence(&[
        &encode_oid(OID_KEY_USAGE),
        &encode_boolean(true),
        &encode_octet_string(&ku_bits),
    ]);
    let extensions_seq = encode_sequence(&[&bc_extn, &ku_extn]);
    let extensions_der = encode_explicit(3, &extensions_seq);

    // 1. Malformed multibyte UTCTime: 13 bytes containing 3-byte euro sign: "€000000000Z"
    let malformed_utctime = "€000000000Z".as_bytes();
    assert_eq!(malformed_utctime.len(), 13);
    let validity_utctime = encode_sequence(&[
        &encode_tlv(0x17, malformed_utctime),
        &encode_der_time(not_after),
    ]);
    let tbs_utctime = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_utctime,
        &ca.subject_dn_der,
        &ca.spki_der,
        &extensions_der,
    ]);
    let cert_pem_utctime = sign_custom_tbs(&tbs_utctime, &ca.key);
    let res_utctime = install_ca(&rootfs, &cert_pem_utctime);
    assert!(
        res_utctime.is_err(),
        "install_ca must reject certificate containing multibyte UTCTime without panicking"
    );
    assert_eq!(
        fs::read(&bundle_path).expect("read"),
        b"ORIGINAL_BUNDLE\n",
        "Rootfs must remain unchanged after malformed UTCTime"
    );

    // 2. Malformed multibyte GeneralizedTime: 15 bytes containing 3-byte euro sign: "€00000000000Z"
    let malformed_gentime = "€00000000000Z".as_bytes();
    assert_eq!(malformed_gentime.len(), 15);
    let validity_gentime = encode_sequence(&[
        &encode_tlv(0x18, malformed_gentime),
        &encode_der_time(not_after),
    ]);
    let tbs_gentime = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_gentime,
        &ca.subject_dn_der,
        &ca.spki_der,
        &extensions_der,
    ]);
    let cert_pem_gentime = sign_custom_tbs(&tbs_gentime, &ca.key);
    let res_gentime = install_ca(&rootfs, &cert_pem_gentime);
    assert!(
        res_gentime.is_err(),
        "install_ca must reject certificate containing multibyte GeneralizedTime without panicking"
    );
    assert_eq!(
        fs::read(&bundle_path).expect("read"),
        b"ORIGINAL_BUNDLE\n",
        "Rootfs must remain unchanged after malformed GeneralizedTime"
    );
}

// Regression test for item 2: structural and constraint validation with re-signed certificates
#[test]
fn test_regression_ca_cert_structural_and_constraint_validation_resigned() {
    use hermetic_trust::asn1::*;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let bundle_path = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_path, b"ORIGINAL_BUNDLE\n").expect("write original");

    let seed: [u8; 32] = [43u8; 32];
    let ca = mint_ca("val-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let (not_before, not_after) =
        compute_ca_validity(datetime!(2024-01-01 00:00:00 UTC)).expect("validity");

    let version_der = encode_explicit(0, &encode_integer(&[2]));
    let serial_der = encode_integer(&[2u8; 16]);
    let sig_alg_der = encode_sha256_with_rsa_algorithm();
    let validity_der =
        encode_sequence(&[&encode_der_time(not_before), &encode_der_time(not_after)]);

    let bc_value = encode_sequence(&[&encode_boolean(true)]);
    let bc_extn = encode_sequence(&[
        &encode_oid(OID_BASIC_CONSTRAINTS),
        &encode_boolean(true),
        &encode_octet_string(&bc_value),
    ]);
    let ku_valid = encode_bit_string(1, &[0x06]);
    let ku_extn_valid = encode_sequence(&[
        &encode_oid(OID_KEY_USAGE),
        &encode_boolean(true),
        &encode_octet_string(&ku_valid),
    ]);

    // Subtest 1: Re-signed cert with critical keyUsage permitting ONLY digitalSignature (bit 0 = 0x80)
    let ku_digsig_only = encode_bit_string(7, &[0x80]);
    let ku_extn_digsig = encode_sequence(&[
        &encode_oid(OID_KEY_USAGE),
        &encode_boolean(true), // critical
        &encode_octet_string(&ku_digsig_only),
    ]);
    let exts_digsig = encode_explicit(3, &encode_sequence(&[&bc_extn, &ku_extn_digsig]));
    let tbs_digsig = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_digsig,
    ]);
    let pem_digsig = sign_custom_tbs(&tbs_digsig, &ca.key);
    let res1 = install_ca(&rootfs, &pem_digsig);
    assert!(
        res1.is_err(),
        "Critical keyUsage without keyCertSign must be rejected"
    );
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 2: Re-signed cert with unknown critical extension
    let unknown_extn = encode_sequence(&[
        &encode_oid(&[0x55, 0x1D, 0x99]), // unknown OID
        &encode_boolean(true),            // critical!
        &encode_octet_string(b"unknown_payload"),
    ]);
    let exts_unknown = encode_explicit(
        3,
        &encode_sequence(&[&bc_extn, &ku_extn_valid, &unknown_extn]),
    );
    let tbs_unknown = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_unknown,
    ]);
    let pem_unknown = sign_custom_tbs(&tbs_unknown, &ca.key);
    let res2 = install_ca(&rootfs, &pem_unknown);
    assert!(res2.is_err(), "Unknown critical extension must be rejected");
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 3: Re-signed cert with duplicate extensions
    let exts_dup = encode_explicit(3, &encode_sequence(&[&bc_extn, &bc_extn]));
    let tbs_dup = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_dup,
    ]);
    let pem_dup = sign_custom_tbs(&tbs_dup, &ca.key);
    let res3 = install_ca(&rootfs, &pem_dup);
    assert!(res3.is_err(), "Duplicate extensions must be rejected");
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 4: Re-signed cert with trailing fields in TBSCertificate
    let exts_valid = encode_explicit(3, &encode_sequence(&[&bc_extn, &ku_extn_valid]));
    let trailing_field = encode_integer(&[0x42]);
    let tbs_trailing = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_valid,
        &trailing_field, // Trailing item!
    ]);
    let pem_trailing = sign_custom_tbs(&tbs_trailing, &ca.key);
    let res4 = install_ca(&rootfs, &pem_trailing);
    assert!(
        res4.is_err(),
        "Trailing fields in TBSCertificate must be rejected"
    );
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 5: Re-signed cert with invalid version (v1 integer 0 instead of v3 integer 2)
    let version_v1 = encode_explicit(0, &encode_integer(&[0]));
    let tbs_v1 = encode_sequence(&[
        &version_v1,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_valid,
    ]);
    let pem_v1 = sign_custom_tbs(&tbs_v1, &ca.key);
    let res5 = install_ca(&rootfs, &pem_v1);
    assert!(res5.is_err(), "Version v1 with extensions must be rejected");
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 6: Re-signed cert with missing version (defaults to v1)
    let tbs_no_ver = encode_sequence(&[
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_valid,
    ]);
    let pem_no_ver = sign_custom_tbs(&tbs_no_ver, &ca.key);
    let res6 = install_ca(&rootfs, &pem_no_ver);
    assert!(
        res6.is_err(),
        "Missing version in TBSCertificate must be rejected"
    );
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 7: Re-signed cert with altered issuer (issuer != subject)
    let other_dn = hermetic_trust::cert::encode_dn("Different CA", Some("Different Org"));
    let tbs_diff_issuer = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &other_dn, // altered issuer
        &validity_der,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_valid,
    ]);
    let pem_diff_issuer = sign_custom_tbs(&tbs_diff_issuer, &ca.key);
    let res7 = install_ca(&rootfs, &pem_diff_issuer);
    assert!(res7.is_err(), "Altered issuer must be rejected");
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 8: Invalid signature (signature bits corrupted)
    let mut bad_sig_cert_der = ca.cert_der.clone();
    let last = bad_sig_cert_der.len() - 1;
    bad_sig_cert_der[last] ^= 0xFF;
    let pem_bad_sig = pem::encode(&pem::Pem::new("CERTIFICATE", bad_sig_cert_der));
    let res8 = install_ca(&rootfs, &pem_bad_sig);
    assert!(res8.is_err(), "Tampered signature must be rejected");
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");

    // Subtest 9: Malformed validity (notBefore after notAfter)
    let malformed_validity =
        encode_sequence(&[&encode_der_time(not_after), &encode_der_time(not_before)]);
    let tbs_bad_validity = encode_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &ca.subject_dn_der,
        &malformed_validity,
        &ca.subject_dn_der,
        &ca.spki_der,
        &exts_valid,
    ]);
    let pem_bad_validity = sign_custom_tbs(&tbs_bad_validity, &ca.key);
    let res9 = install_ca(&rootfs, &pem_bad_validity);
    assert!(res9.is_err(), "notBefore after notAfter must be rejected");
    assert_eq!(fs::read(&bundle_path).expect("read"), b"ORIGINAL_BUNDLE\n");
}

// Regression test for item 9: JKS duplicate alias and private key collision in both orders
#[test]
fn test_regression_jks_duplicate_alias_and_private_key_collision_both_orders() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let jks_dir = rootfs.join("usr/lib/jvm/lib/security");
    fs::create_dir_all(&jks_dir).expect("create jks dir");
    let jks_path = jks_dir.join("cacerts");

    let seed: [u8; 32] = [44u8; 32];
    let ca = mint_ca("jks-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let dummy_pk_bytes = [10u8, 20, 30, 40];

    // Order 1: Matching TrustedCert first, PrivateKey second (both with alias "hermetic-world-ca")
    let entries_order1: [(&str, bool, &[u8]); 2] = [
        ("hermetic-world-ca", false, &ca.cert_der),
        ("hermetic-world-ca", true, &dummy_pk_bytes),
    ];
    let jks_order1 = create_multi_entry_jks(&entries_order1, "changeit");
    fs::write(&jks_path, &jks_order1).expect("write order1");

    // Direct check on inject_ca_into_jks
    let direct_res1 = hermetic_trust::inject_ca_into_jks(&jks_order1, &ca.cert_der, 0);
    assert!(
        matches!(direct_res1, Err(TrustError::AliasCollisionWithPrivateKey)),
        "Order 1 must return AliasCollisionWithPrivateKey, got {:?}",
        direct_res1
    );

    // End-to-end check via install_ca
    let report1 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca order1");
    let skipped1 = report1
        .skipped_paths
        .iter()
        .find(|s| s.reason == "alias collision with private key");
    assert!(
        skipped1.is_some(),
        "Report must skip on alias collision with private key in order 1"
    );
    assert_eq!(
        fs::read(&jks_path).expect("read jks"),
        jks_order1,
        "Keystore bytes must remain unchanged in order 1"
    );

    // Order 2: PrivateKey first, Matching TrustedCert second (both with alias "hermetic-world-ca")
    let entries_order2: [(&str, bool, &[u8]); 2] = [
        ("hermetic-world-ca", true, &dummy_pk_bytes),
        ("hermetic-world-ca", false, &ca.cert_der),
    ];
    let jks_order2 = create_multi_entry_jks(&entries_order2, "changeit");
    fs::write(&jks_path, &jks_order2).expect("write order2");

    // Direct check on inject_ca_into_jks
    let direct_res2 = hermetic_trust::inject_ca_into_jks(&jks_order2, &ca.cert_der, 0);
    assert!(
        matches!(direct_res2, Err(TrustError::AliasCollisionWithPrivateKey)),
        "Order 2 must return AliasCollisionWithPrivateKey, got {:?}",
        direct_res2
    );

    // End-to-end check via install_ca
    let report2 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca order2");
    let skipped2 = report2
        .skipped_paths
        .iter()
        .find(|s| s.reason == "alias collision with private key");
    assert!(
        skipped2.is_some(),
        "Report must skip on alias collision with private key in order 2"
    );
    assert_eq!(
        fs::read(&jks_path).expect("read jks"),
        jks_order2,
        "Keystore bytes must remain unchanged in order 2"
    );

    // Order 3: Duplicate TrustedCert entries with the same alias
    let entries_order3: [(&str, bool, &[u8]); 2] = [
        ("hermetic-world-ca", false, &ca.cert_der),
        ("hermetic-world-ca", false, &ca.cert_der),
    ];
    let jks_order3 = create_multi_entry_jks(&entries_order3, "changeit");
    fs::write(&jks_path, &jks_order3).expect("write order3");

    let direct_res3 = hermetic_trust::inject_ca_into_jks(&jks_order3, &ca.cert_der, 0);
    assert!(
        direct_res3.is_err(),
        "Duplicate TrustedCert alias must be rejected"
    );
    let report3 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca order3");
    assert!(
        report3
            .skipped_paths
            .iter()
            .any(|s| s.path.ends_with("cacerts")),
        "Report must skip on duplicate alias in order 3"
    );
    assert_eq!(
        fs::read(&jks_path).expect("read jks"),
        jks_order3,
        "Keystore bytes must remain unchanged on duplicate alias"
    );

    // Order 4 (T2.5 review): a duplicate alias with control characters is reported
    // with a fixed code; no keystore alias text reaches the report.
    let hostile = "evil\u{1b}[31malias\n";
    let entries_order4: [(&str, bool, &[u8]); 2] = [
        (hostile, false, &ca.cert_der),
        (hostile, false, &ca.cert_der),
    ];
    let jks_order4 = create_multi_entry_jks(&entries_order4, "changeit");
    fs::write(&jks_path, &jks_order4).expect("write order4");
    let report4 = install_ca(&rootfs, &ca.cert_pem).expect("install_ca order4");
    let skipped4 = report4
        .skipped_paths
        .iter()
        .find(|s| s.path.ends_with("cacerts"))
        .expect("duplicate hostile alias skipped");
    assert!(
        skipped4.reason.contains("duplicate_alias"),
        "{:?}",
        skipped4.reason
    );
    assert!(!skipped4.reason.contains("evil"), "{:?}", skipped4.reason);
    assert!(
        !skipped4.reason.chars().any(char::is_control),
        "{:?}",
        skipped4.reason
    );
}

/// Wait for a child process with a deadline; kill it and panic on timeout.
fn wait_child_with_timeout(
    mut child: std::process::Child,
    timeout: std::time::Duration,
) -> std::process::Output {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait child") {
            Some(_) => return child.wait_with_output().expect("collect child output"),
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child process timed out after {:?}", timeout);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// Build a rootfs whose discovery would need far more descriptors than a small
/// RLIMIT_NOFILE allows if every pending directory held an open handle: a wide
/// level of sibling directories plus a deep certifi bundle visited last.
fn build_wide_deep_rootfs(rootfs: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let system_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&system_dir).expect("create system dir");
    let system_bundle = system_dir.join("ca-certificates.crt");
    fs::write(&system_bundle, b"").expect("write system bundle");

    let wide = rootfs.join("opt/app/node_modules");
    for i in 0..300 {
        fs::create_dir_all(wide.join(format!("pkg{:04}/lib", i))).expect("create pkg dir");
    }

    let mut deep = rootfs.join("opt/venv");
    for i in 0..40 {
        deep = deep.join(format!("d{:02}", i));
    }
    let certifi_dir = deep.join("site-packages/certifi");
    fs::create_dir_all(&certifi_dir).expect("create certifi dir");
    let certifi_bundle = certifi_dir.join("cacert.pem");
    fs::write(&certifi_bundle, b"").expect("write certifi bundle");
    (system_bundle, certifi_bundle)
}

#[test]
fn test_discovery_bounded_descriptors_under_low_nofile_limit() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_ca(
        "fd-budget-world",
        datetime!(2024-01-01 00:00:00 UTC),
        &[9u8; 32],
    )
    .expect("mint ca");
    let ca_path = temp_dir.path().join("CA.pem");
    fs::write(&ca_path, &ca.cert_pem).expect("write ca");

    let rootfs = temp_dir.path().join("rootfs");
    let (system_bundle, certifi_bundle) = build_wide_deep_rootfs(&rootfs);

    let bin_path = env!("CARGO_BIN_EXE_hermetic-trust");
    // Run the CLI with a tiny open-file limit (far below the 300+ pending dirs).
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("ulimit -n 32 && exec \"$0\" install --rootfs \"$1\" --ca-cert \"$2\"")
        .arg(bin_path)
        .arg(&rootfs)
        .arg(&ca_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn install under low nofile limit");
    let output = wait_child_with_timeout(child, std::time::Duration::from_secs(120));

    let system_after = fs::read(&system_bundle).expect("read system bundle");
    let certifi_after = fs::read(&certifi_bundle).expect("read certifi bundle");
    let ca_bytes = ca.cert_pem.as_bytes();
    let contains_ca = |b: &[u8]| b.windows(ca_bytes.len()).any(|w| w == ca_bytes);

    if output.status.success() {
        // Success must mean every bundle was processed.
        assert!(contains_ca(&system_after), "system bundle not updated");
        assert!(
            contains_ca(&certifi_after),
            "install succeeded but deep certifi bundle was silently skipped; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        // Failure must leave everything unmodified.
        assert!(
            system_after.is_empty(),
            "failed install modified system bundle"
        );
        assert!(
            certifi_after.is_empty(),
            "failed install modified certifi bundle"
        );
    }
    // With a bounded descriptor budget the install must actually succeed.
    assert!(
        output.status.success(),
        "install failed under a 32-descriptor limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The report must not depend on the descriptor limit.
    let rootfs2 = temp_dir.path().join("rootfs2");
    build_wide_deep_rootfs(&rootfs2);
    let report_low = String::from_utf8_lossy(&output.stdout).to_string();
    let child_high = Command::new(bin_path)
        .args(["install", "--rootfs"])
        .arg(&rootfs2)
        .arg("--ca-cert")
        .arg(&ca_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn install with default limit");
    let output_high = wait_child_with_timeout(child_high, std::time::Duration::from_secs(120));
    assert!(output_high.status.success());
    assert_eq!(report_low, String::from_utf8_lossy(&output_high.stdout));
}

#[test]
fn test_discovery_failure_aborts_install_without_modification() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_ca(
        "discovery-fail-world",
        datetime!(2024-01-01 00:00:00 UTC),
        &[10u8; 32],
    )
    .expect("mint ca");

    let rootfs = temp_dir.path().join("rootfs");
    let system_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&system_dir).expect("create system dir");
    let system_bundle = system_dir.join("ca-certificates.crt");
    fs::write(&system_bundle, b"").expect("write system bundle");
    let certifi_dir = rootfs.join("zzz/site-packages/certifi");
    fs::create_dir_all(&certifi_dir).expect("create certifi");
    fs::write(certifi_dir.join("cacert.pem"), b"").expect("write certifi");

    // Before a queued directory is visited, swap it for a symlink to a host
    // directory. Re-opening it with O_NOFOLLOW must fail, and that failure must
    // abort the whole install before anything is modified.
    let host_dir = temp_dir.path().join("host");
    fs::create_dir_all(&host_dir).expect("create host dir");
    let zzz = rootfs.join("zzz");
    let zzz_moved = temp_dir.path().join("zzz_moved");
    let calls = std::cell::Cell::new(0usize);
    let guard = hermetic_trust::set_before_dir_enum_hook_guard(move || {
        calls.set(calls.get() + 1);
        // Call 1 visits the root; call 2 visits "zzz" (last sorted entry, popped first).
        if calls.get() == 2 {
            fs::rename(&zzz, &zzz_moved).expect("move zzz");
            std::os::unix::fs::symlink(&host_dir, &zzz).expect("symlink zzz");
        }
    });
    let result = install_ca(&rootfs, &ca.cert_pem);
    drop(guard);

    assert!(result.is_err(), "install must fail when discovery fails");
    assert!(
        fs::read(&system_bundle)
            .expect("read system bundle")
            .is_empty(),
        "system bundle modified despite discovery failure"
    );
    assert_eq!(
        fs::read_dir(temp_dir.path().join("host"))
            .expect("read host dir")
            .count(),
        0,
        "host directory touched"
    );

    // Unreadable directory: enumeration failure must also abort (skipped when
    // running with privileges that bypass permission checks).
    let rootfs2 = temp_dir.path().join("rootfs2");
    let system_dir2 = rootfs2.join("etc/ssl/certs");
    fs::create_dir_all(&system_dir2).expect("create system dir2");
    let system_bundle2 = system_dir2.join("ca-certificates.crt");
    fs::write(&system_bundle2, b"").expect("write system bundle2");
    let locked = rootfs2.join("locked");
    fs::create_dir_all(&locked).expect("create locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod locked");
    let bypass = fs::read_dir(&locked).is_ok();
    let result2 = install_ca(&rootfs2, &ca.cert_pem);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("restore locked");
    if !bypass {
        assert!(
            result2.is_err(),
            "install must fail on unreadable directory"
        );
        assert!(
            fs::read(&system_bundle2)
                .expect("read system bundle2")
                .is_empty(),
            "system bundle modified despite enumeration failure"
        );
    }
}

// =========================================================================
// Re-review 2026-11-12 regressions (blocking items 1, 2, 3, 4 and 8)
// =========================================================================

fn mint_test_ca(world: &str, seed_byte: u8) -> hermetic_trust::Ca {
    mint_ca(world, datetime!(2024-01-01 00:00:00 UTC), &[seed_byte; 32]).expect("mint ca")
}

fn spawn_cli(args: &[&std::ffi::OsStr], cwd: Option<&std::path::Path>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hermetic-trust"));
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let child = cmd.spawn().expect("spawn hermetic-trust");
    wait_child_with_timeout(child, std::time::Duration::from_secs(120))
}

/// Item 1: after a missing component, `..` must not be normalised away and no
/// metadata may be read through a host symlink, so the outside file's existence
/// and size cannot change the report.
#[test]
fn test_missing_component_dotdot_results_independent_of_host_files() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("missing-dotdot-world", 31);
    let host_dir = temp_dir.path().join("host");
    fs::create_dir_all(&host_dir).expect("create host dir");
    let probe = host_dir.join("probe");

    let build = |name: &str| -> std::path::PathBuf {
        let rootfs = temp_dir.path().join(name);
        let certs = rootfs.join("etc/ssl/certs");
        fs::create_dir_all(&certs).expect("create certs");
        fs::write(certs.join("ca-certificates.crt"), b"").expect("write system bundle");
        let certifi = rootfs.join("opt/lib/certifi");
        fs::create_dir_all(&certifi).expect("create certifi");
        std::os::unix::fs::symlink("/missing/../escape/probe", certifi.join("cacert.pem"))
            .expect("symlink cacert.pem");
        std::os::unix::fs::symlink(&host_dir, rootfs.join("escape")).expect("symlink escape");
        rootfs
    };

    // Host probe absent.
    let report_absent = install_ca(&build("rootfs_absent"), &ca.cert_pem).expect("install absent");

    // Host probe present and small.
    fs::write(&probe, b"HOST_PROBE\n").expect("write probe");
    let report_small = install_ca(&build("rootfs_small"), &ca.cert_pem).expect("install small");
    assert_eq!(fs::read(&probe).expect("read probe"), b"HOST_PROBE\n");

    // Host probe present and above the bundle size cap.
    let f = fs::File::create(&probe).expect("create big probe");
    f.set_len(17 * 1024 * 1024).expect("set_len probe");
    drop(f);
    let report_big = install_ca(&build("rootfs_big"), &ca.cert_pem).expect("install big");

    let json = |r: &InstallReport| serde_json::to_string(r).expect("json");
    assert_eq!(
        json(&report_absent),
        json(&report_small),
        "report must not depend on whether a host file exists"
    );
    assert_eq!(
        json(&report_absent),
        json(&report_big),
        "report must not depend on the size of a host file"
    );
    assert!(
        report_absent
            .skipped_paths
            .iter()
            .any(|s| s.path == "opt/lib/certifi/cacert.pem" && s.reason == "cannot stat target"),
        "dangling '/missing/..' target must be reported as unresolvable: {:?}",
        report_absent.skipped_paths
    );
    assert!(!json(&report_absent).contains("escape"));

    // The host directory is untouched.
    assert_eq!(
        fs::metadata(&probe).expect("probe meta").len(),
        17 * 1024 * 1024
    );
    assert_eq!(fs::read_dir(&host_dir).expect("read host").count(), 1);
}

/// Item 1: a system bundle symlink through `/missing/..` names nothing in the
/// guest and must never become an environment default.
#[test]
fn test_missing_component_dotdot_cannot_become_env_default() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("missing-dotdot-default-world", 32);
    let rootfs = temp_dir.path().join("rootfs");
    let certs = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs).expect("create certs");
    std::os::unix::fs::symlink(
        "/missing/../existing-bundle.pem",
        certs.join("ca-certificates.crt"),
    )
    .expect("symlink system bundle");
    let existing = rootfs.join("existing-bundle.pem");
    fs::write(&existing, b"EXISTING\n").expect("write existing bundle");

    let result = install_ca(&rootfs, &ca.cert_pem);
    if let Ok(ref report) = result {
        assert!(
            !report
                .env_defaults
                .values()
                .any(|v| v == "/etc/ssl/certs/ca-certificates.crt"),
            "unresolvable bundle selected as env default: {:?}",
            report.env_defaults
        );
    }
    assert!(
        result.is_err(),
        "install must fail when the only system bundle path cannot be resolved"
    );
    assert_eq!(fs::read(&existing).expect("read existing"), b"EXISTING\n");
    assert!(fs::symlink_metadata(certs.join("ca-certificates.crt"))
        .expect("lstat bundle")
        .file_type()
        .is_symlink());
}

/// Item 2: `--report` naming an installed bundle must be rejected before any
/// mutation, both below depth 16 and in a wide tree under a low descriptor limit.
#[test]
fn test_report_collision_uses_complete_discovery_plan() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("report-collision-world", 33);
    let ca_path = temp_dir.path().join("CA.pem");
    fs::write(&ca_path, &ca.cert_pem).expect("write ca");

    // Case 1: certifi bundle at depth 23.
    let rootfs = temp_dir.path().join("rootfs_deep");
    let system_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&system_dir).expect("create system dir");
    let system_bundle = system_dir.join("ca-certificates.crt");
    fs::write(&system_bundle, b"").expect("write system bundle");
    let mut deep = rootfs.join("opt");
    for i in 0..20 {
        deep = deep.join(format!("d{:02}", i));
    }
    let certifi_dir = deep.join("site-packages/certifi");
    fs::create_dir_all(&certifi_dir).expect("create deep certifi");
    let deep_bundle = certifi_dir.join("cacert.pem");
    fs::write(&deep_bundle, b"ORIGINAL_DEEP\n").expect("write deep bundle");

    let output = spawn_cli(
        &[
            "install".as_ref(),
            "--rootfs".as_ref(),
            rootfs.as_os_str(),
            "--ca-cert".as_ref(),
            ca_path.as_os_str(),
            "--report".as_ref(),
            deep_bundle.as_os_str(),
        ],
        None,
    );
    assert!(
        !output.status.success(),
        "report colliding with a depth-23 bundle must be rejected"
    );
    assert_eq!(
        fs::read(&deep_bundle).expect("read deep"),
        b"ORIGINAL_DEEP\n"
    );
    assert!(fs::read(&system_bundle).expect("read system").is_empty());

    // Case 2: wide tree under a 32-descriptor limit; the colliding bundle is shallow.
    let rootfs2 = temp_dir.path().join("rootfs_wide");
    let (system2, deep2) = build_wide_deep_rootfs(&rootfs2);
    let wide_certifi = rootfs2.join("opt/app/node_modules/pkg0150/lib/certifi");
    fs::create_dir_all(&wide_certifi).expect("create wide certifi");
    let wide_bundle = wide_certifi.join("cacert.pem");
    fs::write(&wide_bundle, b"ORIGINAL_WIDE\n").expect("write wide bundle");

    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("ulimit -n 32 && exec \"$0\" install --rootfs \"$1\" --ca-cert \"$2\" --report \"$3\"")
        .arg(env!("CARGO_BIN_EXE_hermetic-trust"))
        .arg(&rootfs2)
        .arg(&ca_path)
        .arg(&wide_bundle)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn install under low nofile limit");
    let output2 = wait_child_with_timeout(child, std::time::Duration::from_secs(120));
    assert!(
        !output2.status.success(),
        "report colliding with a bundle in a wide tree must be rejected"
    );
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("report"),
        "failure must come from the report collision check: {}",
        stderr2
    );
    assert_eq!(
        fs::read(&wide_bundle).expect("read wide"),
        b"ORIGINAL_WIDE\n"
    );
    assert!(fs::read(&system2).expect("read system2").is_empty());
    assert!(fs::read(&deep2).expect("read deep2").is_empty());
}

fn write_test_seed(dir: &std::path::Path) -> std::path::PathBuf {
    let seed_path = dir.join("seed.bin");
    fs::write(&seed_path, [42u8; 32]).expect("write seed");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("chmod seed");
    seed_path
}

/// Item 3: relative/absolute spellings of the same new output, and an existing
/// certificate used as the parent of the key output, must be rejected before
/// writing anything.
#[test]
fn test_cli_mint_ca_output_alias_and_ancestor_conflicts() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let work = temp_dir.path().canonicalize().expect("canonical temp");
    let seed_path = write_test_seed(&work);

    // Scenario 1: `new/` absent; relative cert path and absolute key path alias.
    let abs_key = work.join("new/out.pem");
    let output = spawn_cli(
        &[
            "mint-ca".as_ref(),
            "--world-id".as_ref(),
            "alias-world".as_ref(),
            "--t-clock".as_ref(),
            "2024-05-01T10:00:00Z".as_ref(),
            "--ca-seed-file".as_ref(),
            seed_path.as_os_str(),
            "--cert-out".as_ref(),
            "new/out.pem".as_ref(),
            "--key-out".as_ref(),
            abs_key.as_os_str(),
        ],
        Some(&work),
    );
    assert!(
        !output.status.success(),
        "relative and absolute aliases of one new output must be rejected"
    );
    assert!(
        !work.join("new").exists(),
        "no directory may be created on rejection"
    );

    // Scenario 2: existing certificate file used as the key's parent directory.
    let existing_cert = work.join("o");
    fs::write(&existing_cert, b"EXISTING_CERT_BYTES\n").expect("write existing cert");
    let key_under_cert = work.join("o/k.pem");
    for (cert_arg, key_arg) in [
        (existing_cert.as_os_str(), key_under_cert.as_os_str()),
        (key_under_cert.as_os_str(), existing_cert.as_os_str()),
    ] {
        let output = spawn_cli(
            &[
                "mint-ca".as_ref(),
                "--world-id".as_ref(),
                "ancestor-world".as_ref(),
                "--t-clock".as_ref(),
                "2024-05-01T10:00:00Z".as_ref(),
                "--ca-seed-file".as_ref(),
                seed_path.as_os_str(),
                "--cert-out".as_ref(),
                cert_arg,
                "--key-out".as_ref(),
                key_arg,
            ],
            None,
        );
        assert!(
            !output.status.success(),
            "output used as the parent of the other output must be rejected"
        );
        assert_eq!(
            fs::read(&existing_cert).expect("read existing cert"),
            b"EXISTING_CERT_BYTES\n",
            "existing output bytes must be unchanged"
        );
    }

    // Library level: new nested outputs with ancestor relationship are rejected.
    let a = work.join("fresh/dir");
    let b = work.join("fresh/dir/key.pem");
    assert!(check_not_alias(&a, &b, "cert_out", "key_out").is_err());
    assert!(!work.join("fresh").exists());
}

/// Rootfs with both anchor directories present (anchor files missing) and no
/// system bundle, so the install creates anchors, `etc/ssl`, `etc/ssl/certs`
/// and the fallback bundle.
fn build_creation_rootfs(rootfs: &std::path::Path) {
    fs::create_dir_all(rootfs.join("usr/local/share/ca-certificates")).expect("anchor dir 1");
    fs::create_dir_all(rootfs.join("etc/pki/ca-trust/source/anchors")).expect("anchor dir 2");
}

const CREATED_ENTRIES: [&str; 5] = [
    "etc/ssl",
    "etc/ssl/certs",
    "etc/ssl/certs/ca-certificates.crt",
    "usr/local/share/ca-certificates/hermetic-world-ca.crt",
    "etc/pki/ca-trust/source/anchors/hermetic-world-ca.pem",
];

/// Item 4: created anchors, fallback bundle and parent directories get the
/// explicit guest owner and fixed modes, whatever the sealing process umask.
#[test]
fn test_created_entries_have_guest_owner_and_umask_independent_modes() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("ownership-world", 34);
    let ca_path = temp_dir.path().join("CA.pem");
    fs::write(&ca_path, &ca.cert_pem).expect("write ca");
    let owner = current_owner();

    let mut observed = Vec::new();
    for umask in ["022", "077"] {
        let rootfs = temp_dir.path().join(format!("rootfs_{}", umask));
        build_creation_rootfs(&rootfs);
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("umask \"$1\" && exec \"$0\" install --rootfs \"$2\" --ca-cert \"$3\" --guest-uid \"$4\" --guest-gid \"$5\"")
            .arg(env!("CARGO_BIN_EXE_hermetic-trust"))
            .arg(umask)
            .arg(&rootfs)
            .arg(&ca_path)
            .arg(owner.uid.to_string())
            .arg(owner.gid.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn install");
        let output = wait_child_with_timeout(child, std::time::Duration::from_secs(120));
        assert!(
            output.status.success(),
            "install under umask {} failed: {}",
            umask,
            String::from_utf8_lossy(&output.stderr)
        );

        let mut metas = Vec::new();
        for rel in CREATED_ENTRIES {
            let meta = fs::symlink_metadata(rootfs.join(rel)).expect("created entry");
            let expected_mode = if meta.is_dir() {
                NEW_DIR_MODE
            } else {
                NEW_FILE_MODE
            };
            assert_eq!(
                meta.mode() & 0o7777,
                expected_mode,
                "{} has mode {:o} under umask {}",
                rel,
                meta.mode() & 0o7777,
                umask
            );
            assert_eq!(
                (meta.uid(), meta.gid()),
                (owner.uid, owner.gid),
                "{} not owned by guest owner",
                rel
            );
            metas.push((rel, meta.uid(), meta.gid(), meta.mode() & 0o7777));
        }
        observed.push(metas);
    }
    assert_eq!(
        observed[0], observed[1],
        "metadata must not depend on umask"
    );
}

/// Item 4: with the default guest owner (root 0:0) an unprivileged process must
/// fail before creating anything; when ownership cannot be applied (injected
/// failure) nothing is created either.
#[test]
fn test_guest_ownership_failure_aborts_before_creating_entries() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("ownership-fail-world", 35);
    let owner = current_owner();

    let assert_nothing_created = |rootfs: &std::path::Path| {
        for rel in CREATED_ENTRIES {
            assert!(
                fs::symlink_metadata(rootfs.join(rel)).is_err(),
                "{} created despite ownership failure",
                rel
            );
        }
    };

    // Default guest owner 0:0.
    let rootfs = temp_dir.path().join("rootfs_default");
    build_creation_rootfs(&rootfs);
    let result = hermetic_trust::install_ca(&rootfs, &ca.cert_pem);
    if owner.uid == 0 {
        result.expect("install as root");
        for rel in CREATED_ENTRIES {
            let meta = fs::symlink_metadata(rootfs.join(rel)).expect("created entry");
            assert_eq!((meta.uid(), meta.gid()), (0, 0), "{} not owned by 0:0", rel);
        }
    } else {
        assert!(
            result.is_err(),
            "unprivileged install must not create entries owned by the sealing user"
        );
        assert_nothing_created(&rootfs);
    }

    // Injected ownership failure through the crate's ownership-failure path.
    let rootfs2 = temp_dir.path().join("rootfs_injected");
    build_creation_rootfs(&rootfs2);
    let guard = hermetic_trust::set_chown_failure_guard();
    let result2 = install_ca(&rootfs2, &ca.cert_pem);
    drop(guard);
    assert!(result2.is_err(), "ownership failure must abort the install");
    assert_nothing_created(&rootfs2);
}

/// Item 8: the supported root-anchored write API refuses intermediate symlinks
/// and `..`, leaves outside bytes and modes unchanged and creates nothing outside.
#[test]
fn test_root_anchored_write_refuses_intermediate_symlink() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("root-anchored-world", 36);
    let outside = temp_dir.path().join("outside");
    fs::create_dir_all(outside.join("sub")).expect("create outside/sub");
    let outside_bundle = outside.join("sub/bundle.pem");
    fs::write(&outside_bundle, b"OUTSIDE_BUNDLE\n").expect("write outside bundle");
    fs::set_permissions(&outside_bundle, fs::Permissions::from_mode(0o600)).expect("chmod");

    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("real/sub")).expect("create real/sub");
    std::os::unix::fs::symlink(&outside, rootfs.join("link")).expect("symlink link");
    let root = open_dir_handle(&rootfs).expect("open rootfs");
    let owner = current_owner();

    let hostile = [
        "link/sub/bundle.pem",
        "link/newdir/bundle.pem",
        "../outside/sub/bundle.pem",
        "real/../link/sub/bundle.pem",
        "/link/sub/bundle.pem",
    ];
    for rel in hostile {
        let rel = std::path::Path::new(rel);
        let write = atomic_write_in_root(&root, rel, b"REPLACED\n", NEW_FILE_MODE, owner);
        assert!(write.is_err(), "atomic_write_in_root accepted {:?}", rel);
        let append = append_pem_bundle_in_root(&root, rel, &ca.cert_pem, &ca.cert_der, owner);
        assert!(
            append.is_err(),
            "append_pem_bundle_in_root accepted {:?}",
            rel
        );
    }

    assert_eq!(
        fs::read(&outside_bundle).expect("read outside"),
        b"OUTSIDE_BUNDLE\n"
    );
    assert_eq!(
        fs::metadata(&outside_bundle)
            .expect("outside meta")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(
        !outside.join("newdir").exists(),
        "outside directory created"
    );
    let outside_entries: Vec<_> = fs::read_dir(outside.join("sub"))
        .expect("read outside/sub")
        .collect();
    assert_eq!(outside_entries.len(), 1, "outside directory gained entries");

    // The same API works for a real in-rootfs path.
    let real = std::path::Path::new("real/sub/bundle.pem");
    assert!(
        append_pem_bundle_in_root(&root, real, &ca.cert_pem, &ca.cert_der, owner)
            .expect("append to real path")
    );
    assert!(
        !append_pem_bundle_in_root(&root, real, &ca.cert_pem, &ca.cert_der, owner)
            .expect("idempotent append")
    );
}

// =========================================================================
// Prior-check 2026-11-12 regressions (items 8 and 4)
// =========================================================================

/// Item 8: the exported descriptor-relative helpers accept only one plain
/// file-name component, so a root descriptor plus "link/sub/bundle.pem" (link
/// pointing outside) can neither write nor read through the symlink.
#[test]
fn test_descriptor_helpers_refuse_multi_component_names() {
    use std::os::unix::io::AsRawFd;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let outside = temp_dir.path().join("outside");
    fs::create_dir_all(outside.join("sub")).expect("create outside/sub");
    let outside_bundle = outside.join("sub/bundle.pem");
    fs::write(&outside_bundle, b"OUTSIDE_BUNDLE\n").expect("write outside bundle");
    fs::set_permissions(&outside_bundle, fs::Permissions::from_mode(0o600)).expect("chmod");

    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("real")).expect("create real");
    std::os::unix::fs::symlink(&outside, rootfs.join("link")).expect("symlink link");
    let root = open_dir_handle(&rootfs).expect("open rootfs");
    let owner = current_owner();

    let names = [
        "link/sub/bundle.pem",
        "link/sub/new.pem",
        "real/../link/sub/bundle.pem",
        "/link/sub/bundle.pem",
        "link/",
        "..",
        ".",
        "",
    ];
    for name in names {
        let write = hermetic_trust::atomic_write_preserving_handle(
            &root,
            name,
            b"REPLACED\n",
            NEW_FILE_MODE,
            owner,
        );
        assert!(
            write.is_err(),
            "atomic_write_preserving_handle accepted {:?}",
            name
        );
        let read = hermetic_trust::read_file_capped_from_parent(&root, name, 1024);
        assert!(
            read.is_err(),
            "read_file_capped_from_parent accepted {:?}",
            name
        );
        assert!(
            hermetic_trust::open_child_dir(root.as_raw_fd(), name).is_err(),
            "open_child_dir accepted {:?}",
            name
        );
    }
    assert!(
        hermetic_trust::open_child_dir(root.as_raw_fd(), "link/sub").is_err(),
        "open_child_dir followed an intermediate symlink"
    );
    assert!(
        hermetic_trust::open_parent_dir_handle(
            &rootfs,
            std::path::Path::new("link/sub/bundle.pem")
        )
        .is_err(),
        "open_parent_dir_handle followed an intermediate symlink"
    );

    assert_eq!(
        fs::read(&outside_bundle).expect("read outside"),
        b"OUTSIDE_BUNDLE\n"
    );
    assert_eq!(
        fs::metadata(&outside_bundle)
            .expect("outside meta")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        fs::read_dir(outside.join("sub"))
            .expect("read outside/sub")
            .count(),
        1,
        "outside directory gained entries"
    );

    // A single plain name still works through a validated parent descriptor.
    let real = hermetic_trust::open_child_dir(root.as_raw_fd(), "real").expect("open real");
    hermetic_trust::atomic_write_preserving_handle(&real, "ok.pem", b"OK\n", NEW_FILE_MODE, owner)
        .expect("single component write");
    assert_eq!(
        hermetic_trust::read_file_capped_from_parent(&real, "ok.pem", 1024).expect("read ok"),
        b"OK\n"
    );
}

/// Item 4: with a fixed guest owner that differs from the sealing process, the
/// ownership step for every created directory, anchor and fallback bundle is
/// asked for exactly that owner and the fixed mode (recorded through the
/// thread-local ownership path instead of fchown, which needs privilege).
#[test]
fn test_ownership_steps_use_fixed_guest_owner_distinct_from_process() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("recorded-owner-world", 37);
    let process = current_owner();
    let guest = GuestOwner {
        uid: if process.uid == 4242 { 4243 } else { 4242 },
        gid: if process.gid == 4343 { 4344 } else { 4343 },
    };
    assert_ne!((guest.uid, guest.gid), (process.uid, process.gid));

    let rootfs = temp_dir.path().join("rootfs");
    build_creation_rootfs(&rootfs);
    let guard = hermetic_trust::record_ownership_guard();
    let report = install_ca_with_options(
        &rootfs,
        &ca.cert_pem,
        &InstallOptions {
            owner: guest,
            report_path: None,
        },
    )
    .expect("install with recorded ownership");
    let records = guard.records();
    drop(guard);

    use hermetic_trust::OwnershipTarget;
    let named = |target: OwnershipTarget| -> Vec<(String, u32, u32, Option<u32>)> {
        let mut v: Vec<_> = records
            .iter()
            .filter(|r| r.target == target)
            .map(|r| (r.name.to_string_lossy().to_string(), r.uid, r.gid, r.mode))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        named(OwnershipTarget::Probe),
        vec![(String::new(), guest.uid, guest.gid, None)],
        "guest owner must be probed once before mutation"
    );
    assert_eq!(
        named(OwnershipTarget::NewDirectory),
        vec![
            (
                "certs".to_string(),
                guest.uid,
                guest.gid,
                Some(NEW_DIR_MODE)
            ),
            ("ssl".to_string(), guest.uid, guest.gid, Some(NEW_DIR_MODE)),
        ],
        "created parent directories must get the guest owner and 0755"
    );
    assert_eq!(
        named(OwnershipTarget::NewFile),
        vec![
            (
                "ca-certificates.crt".to_string(),
                guest.uid,
                guest.gid,
                Some(NEW_FILE_MODE)
            ),
            (
                "hermetic-world-ca.crt".to_string(),
                guest.uid,
                guest.gid,
                Some(NEW_FILE_MODE)
            ),
            (
                "hermetic-world-ca.pem".to_string(),
                guest.uid,
                guest.gid,
                Some(NEW_FILE_MODE)
            ),
        ],
        "created anchors and fallback bundle must get the guest owner and 0644"
    );
    assert!(named(OwnershipTarget::ExistingFile).is_empty());
    assert!(records
        .iter()
        .all(|r| (r.uid, r.gid) != (process.uid, process.gid)));
    assert_eq!(
        report.env_defaults.get("SSL_CERT_FILE").map(String::as_str),
        Some("/etc/ssl/certs/ca-certificates.crt")
    );

    // Modes are still applied through descriptors.
    for rel in CREATED_ENTRIES {
        let meta = fs::symlink_metadata(rootfs.join(rel)).expect("created entry");
        let expected = if meta.is_dir() {
            NEW_DIR_MODE
        } else {
            NEW_FILE_MODE
        };
        assert_eq!(meta.mode() & 0o7777, expected, "{} mode", rel);
    }
}

/// Item 4: inside a user namespace with several mapped ids, the install runs as
/// namespace root and creates entries for guest owner 1:1, which differs from
/// the sealing identity; on-disk ownership and modes are checked under umask
/// 077. Skipped (with a message) when no such namespace can be created.
#[test]
fn test_created_entries_owned_by_guest_owner_in_user_namespace() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let probe_file = temp_dir.path().join("userns-probe");
    let variants: [&[&str]; 2] = [&["--user", "--map-root-user", "--map-auto"], &["-Ur"]];
    let mut chosen: Option<&[&str]> = None;
    for flags in variants {
        fs::write(&probe_file, b"").expect("write probe");
        let child = Command::new("unshare")
            .args(flags)
            .arg("/bin/sh")
            .arg("-c")
            .arg("chown 1:1 \"$0\" && id -u")
            .arg(&probe_file)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let Ok(child) = child else { break };
        let out = wait_child_with_timeout(child, std::time::Duration::from_secs(30));
        let inner_uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !inner_uid.is_empty() && inner_uid != "1" {
            chosen = Some(flags);
            break;
        }
    }
    let Some(flags) = chosen else {
        eprintln!(
            "SKIPPED test_created_entries_owned_by_guest_owner_in_user_namespace: \
             no user namespace with ids other than root mapped is available \
             (unshare/newuidmap missing or unprivileged user namespaces restricted)"
        );
        return;
    };

    let ca = mint_test_ca("userns-owner-world", 38);
    let ca_path = temp_dir.path().join("CA.pem");
    fs::write(&ca_path, &ca.cert_pem).expect("write ca");
    let rootfs = temp_dir.path().join("rootfs");
    build_creation_rootfs(&rootfs);

    let script = "umask 077 && \"$0\" install --rootfs \"$1\" --ca-cert \"$2\" \
                  --guest-uid 1 --guest-gid 1 >/dev/null && cd \"$1\" && \
                  stat -c '%u %g %a %n' \"$3\" \"$4\" \"$5\" \"$6\" \"$7\"";
    let child = Command::new("unshare")
        .args(flags)
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_hermetic-trust"))
        .arg(&rootfs)
        .arg(&ca_path)
        .args(CREATED_ENTRIES)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn install in user namespace");
    let out = wait_child_with_timeout(child, std::time::Duration::from_secs(120));
    assert!(
        out.status.success(),
        "install in user namespace failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        CREATED_ENTRIES.len(),
        "stat output: {}",
        stdout
    );
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(&parts[..2], &["1", "1"], "not owned by guest 1:1: {}", line);
        let is_dir = !parts[3].ends_with(".crt") && !parts[3].ends_with(".pem");
        let expected = if is_dir { "755" } else { "644" };
        assert_eq!(parts[2], expected, "mode under umask 077: {}", line);
    }
}

/// T2.5 review: test injection is per-thread only. A hook installed on one
/// thread never fires for an installer running on another thread.
#[test]
fn test_injection_hooks_never_cross_threads() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc/ssl/certs")).expect("create certs");
    let fired = Arc::new(AtomicUsize::new(0));
    let counter = fired.clone();
    let _hook = hermetic_trust::set_before_use_hook_guard(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let _chown = hermetic_trust::set_chown_failure_guard();
    let other = rootfs.clone();
    let result = std::thread::spawn(move || {
        let root = open_dir_handle(&other).expect("open rootfs");
        atomic_write_in_root(
            &root,
            std::path::Path::new("etc/ssl/certs/other-thread.crt"),
            b"DATA",
            NEW_FILE_MODE,
            current_owner(),
        )
    })
    .join()
    .expect("join");
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "hook fired on another thread"
    );
    // On the installing thread itself the hook does fire.
    let root = open_dir_handle(&rootfs).expect("open rootfs");
    let _ = atomic_write_in_root(
        &root,
        std::path::Path::new("etc/ssl/certs/same-thread.crt"),
        b"DATA",
        NEW_FILE_MODE,
        current_owner(),
    );
    assert!(
        fired.load(Ordering::SeqCst) > 0,
        "hook did not fire on its own thread"
    );
}

/// T2.5 review: the CA and leaf types own an explicit `Drop` that wipes the seed
/// and private-key buffers (a `Drop` bound only holds for an explicit impl).
#[test]
fn test_secret_holders_wipe_on_drop() {
    #[allow(drop_bounds)]
    fn explicit_drop<T: Drop>() {}
    explicit_drop::<hermetic_trust::Ca>();
    explicit_drop::<hermetic_trust::LeafCert>();
}

/// T2.5 review: strict DER for BOOLEANs, unique identifiers, pathLenConstraint
/// and the SAN/SKI/AKI payloads. Each bad certificate is otherwise a valid,
/// correctly self-signed CA; the baseline must still install.
#[test]
fn test_regression_strict_der_certificate_fields() {
    use hermetic_trust::asn1::*;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc/ssl/certs")).expect("create certs");
    let seed: [u8; 32] = [7u8; 32];
    let ca = mint_ca("der-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");
    let (not_before, not_after) =
        compute_ca_validity(datetime!(2024-01-01 00:00:00 UTC)).expect("validity");
    let validity = encode_sequence(&[&encode_der_time(not_before), &encode_der_time(not_after)]);

    let ext = |oid: &[u8], critical: Option<Vec<u8>>, value: Vec<u8>| -> Vec<u8> {
        match critical {
            Some(c) => encode_sequence(&[&encode_oid(oid), &c, &encode_octet_string(&value)]),
            None => encode_sequence(&[&encode_oid(oid), &encode_octet_string(&value)]),
        }
    };
    let ku = ext(
        OID_KEY_USAGE,
        Some(encode_boolean(true)),
        encode_bit_string(1, &[0x06]),
    );
    let bc = |inner: &[&[u8]]| {
        ext(
            OID_BASIC_CONSTRAINTS,
            Some(encode_boolean(true)),
            encode_sequence(inner),
        )
    };
    let good_bc = bc(&[&encode_boolean(true)]);

    let build = |unique: &[Vec<u8>], exts: &[Vec<u8>]| -> String {
        let ext_refs: Vec<&[u8]> = exts.iter().map(|e| e.as_slice()).collect();
        let exts_der = encode_explicit(3, &encode_sequence(&ext_refs));
        let version = encode_explicit(0, &encode_integer(&[2]));
        let serial = encode_integer(&[3u8; 16]);
        let alg = encode_sha256_with_rsa_algorithm();
        let mut items: Vec<&[u8]> = vec![
            &version,
            &serial,
            &alg,
            &ca.subject_dn_der,
            &validity,
            &ca.subject_dn_der,
            &ca.spki_der,
        ];
        for u in unique {
            items.push(u);
        }
        items.push(&exts_der);
        sign_custom_tbs(&encode_sequence(&items), &ca.key)
    };
    let installs = |pem: &str| install_ca(&rootfs, pem).is_ok();

    // Baseline and well-formed optional fields install.
    assert!(
        installs(&build(&[], &[good_bc.clone(), ku.clone()])),
        "baseline must install"
    );
    let good_san = ext(
        OID_SUBJECT_ALT_NAME,
        None,
        encode_sequence(&[&encode_tlv(0x82, b"ca.example")]),
    );
    let good_ski = ext(
        OID_SUBJECT_KEY_IDENTIFIER,
        None,
        encode_octet_string(&[1u8; 20]),
    );
    let good_aki = ext(
        OID_AUTHORITY_KEY_IDENTIFIER,
        None,
        encode_sequence(&[&encode_tlv(0x80, &[1u8; 20])]),
    );
    let good_path = bc(&[&encode_boolean(true), &encode_integer(&[0])]);
    assert!(
        installs(&build(
            &[encode_tlv(0x81, &[0, 0xAA])],
            &[good_path, ku.clone(), good_san, good_ski, good_aki]
        )),
        "well-formed optional fields must install"
    );

    let bad: Vec<(&str, String)> = vec![
        (
            "critical BOOLEAN 0x01",
            build(
                &[],
                &[
                    ext(
                        OID_BASIC_CONSTRAINTS,
                        Some(encode_tlv(0x01, &[0x01])),
                        encode_sequence(&[&encode_boolean(true)]),
                    ),
                    ku.clone(),
                ],
            ),
        ),
        (
            "explicit critical FALSE",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(
                        OID_SUBJECT_KEY_IDENTIFIER,
                        Some(encode_tlv(0x01, &[0x00])),
                        encode_octet_string(&[1u8; 20]),
                    ),
                ],
            ),
        ),
        (
            "two-byte BOOLEAN",
            build(&[], &[bc(&[&encode_tlv(0x01, &[0xFF, 0xFF])]), ku.clone()]),
        ),
        (
            "cA BOOLEAN 0x01",
            build(&[], &[bc(&[&encode_tlv(0x01, &[0x01])]), ku.clone()]),
        ),
        (
            "negative pathLen",
            build(
                &[],
                &[
                    bc(&[&encode_boolean(true), &encode_tlv(0x02, &[0xFF])]),
                    ku.clone(),
                ],
            ),
        ),
        (
            "non-minimal pathLen",
            build(
                &[],
                &[
                    bc(&[&encode_boolean(true), &encode_tlv(0x02, &[0x00, 0x01])]),
                    ku.clone(),
                ],
            ),
        ),
        (
            "empty pathLen",
            build(
                &[],
                &[
                    bc(&[&encode_boolean(true), &encode_tlv(0x02, &[])]),
                    ku.clone(),
                ],
            ),
        ),
        (
            "constructed unique id",
            build(
                &[encode_tlv(0xA1, &[0x03, 0x01, 0x00])],
                &[good_bc.clone(), ku.clone()],
            ),
        ),
        (
            "unique id bad unused bits",
            build(
                &[encode_tlv(0x81, &[9, 0xAA])],
                &[good_bc.clone(), ku.clone()],
            ),
        ),
        (
            "unique id non-zero padding",
            build(
                &[encode_tlv(0x81, &[1, 0x01])],
                &[good_bc.clone(), ku.clone()],
            ),
        ),
        (
            "unique ids out of order",
            build(
                &[encode_tlv(0x82, &[0]), encode_tlv(0x81, &[0])],
                &[good_bc.clone(), ku.clone()],
            ),
        ),
        (
            "empty SKI",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(OID_SUBJECT_KEY_IDENTIFIER, None, encode_octet_string(&[])),
                ],
            ),
        ),
        (
            "SKI not OCTET STRING",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(OID_SUBJECT_KEY_IDENTIFIER, None, encode_integer(&[1])),
                ],
            ),
        ),
        (
            "AKI unknown field",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(
                        OID_AUTHORITY_KEY_IDENTIFIER,
                        None,
                        encode_sequence(&[&encode_tlv(0x83, &[1])]),
                    ),
                ],
            ),
        ),
        (
            "AKI out of order",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(
                        OID_AUTHORITY_KEY_IDENTIFIER,
                        None,
                        encode_sequence(&[&encode_tlv(0x82, &[1]), &encode_tlv(0x80, &[1])]),
                    ),
                ],
            ),
        ),
        (
            "empty SAN",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(OID_SUBJECT_ALT_NAME, None, encode_sequence(&[])),
                ],
            ),
        ),
        (
            "SAN bad dNSName",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(
                        OID_SUBJECT_ALT_NAME,
                        None,
                        encode_sequence(&[&encode_tlv(0x82, b"bad name\n")]),
                    ),
                ],
            ),
        ),
        (
            "SAN bad iPAddress",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(
                        OID_SUBJECT_ALT_NAME,
                        None,
                        encode_sequence(&[&encode_tlv(0x87, &[1, 2, 3])]),
                    ),
                ],
            ),
        ),
        (
            "SAN unknown tag",
            build(
                &[],
                &[
                    good_bc.clone(),
                    ku.clone(),
                    ext(
                        OID_SUBJECT_ALT_NAME,
                        None,
                        encode_sequence(&[&encode_tlv(0x89, &[1])]),
                    ),
                ],
            ),
        ),
    ];
    for (what, pem) in bad {
        assert!(!installs(&pem), "{what} must be rejected");
    }
}

#[test]
fn test_installer_race_component_swapped_for_symlink_between_steps() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let bundle_path = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_path, b"INITIAL_BUNDLE\n").expect("write bundle");

    let outside_victim = temp_dir.path().join("victim_secret.txt");
    fs::write(&outside_victim, b"OUTSIDE_SECRET_DO_NOT_TOUCH\n").expect("write victim");

    let seed: [u8; 32] = [42u8; 32];
    let ca = mint_ca("race-world", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let bundle_clone = bundle_path.clone();
    let victim_clone = outside_victim.clone();

    let _hook = hermetic_trust::set_before_use_hook_guard(move || {
        let _ = fs::remove_file(&bundle_clone);
        let _ = std::os::unix::fs::symlink(&victim_clone, &bundle_clone);
    });

    let result = install_ca(&rootfs, &ca.cert_pem);
    drop(_hook);

    assert!(
        result.is_err(),
        "Installer must refuse when target component is swapped for symlink"
    );
    assert_eq!(
        fs::read(&outside_victim).expect("read victim"),
        b"OUTSIDE_SECRET_DO_NOT_TOUCH\n"
    );
}

#[test]
fn test_installer_race_intermediate_component_swapped_between_steps() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let ssl_dir = rootfs.join("etc/ssl");
    let certs_dir = ssl_dir.join("certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let bundle_path = certs_dir.join("ca-certificates.crt");
    fs::write(&bundle_path, b"INITIAL_BUNDLE\n").expect("write bundle");

    let outside_dir = temp_dir.path().join("outside_target_dir");
    fs::create_dir_all(&outside_dir).expect("create outside dir");
    let outside_canary = outside_dir.join("canary.txt");
    fs::write(&outside_canary, b"CANARY_INITIAL").expect("write canary");

    let seed: [u8; 32] = [43u8; 32];
    let ca = mint_ca("race-world-2", datetime!(2024-01-01 00:00:00 UTC), &seed).expect("mint ca");

    let ssl_clone = ssl_dir.clone();
    let ssl_staged = rootfs.join("etc/ssl_staged");
    let outside_clone = outside_dir.clone();

    let _hook = hermetic_trust::set_before_mutation_hook_guard(move || {
        if fs::rename(&ssl_clone, &ssl_staged).is_ok() {
            let _ = std::os::unix::fs::symlink(&outside_clone, &ssl_clone);
        }
    });

    let result = install_ca(&rootfs, &ca.cert_pem);
    drop(_hook);

    assert!(
        result.is_err(),
        "Installer must refuse when intermediate component is swapped for symlink"
    );
    assert_eq!(
        fs::read(&outside_canary).expect("read canary"),
        b"CANARY_INITIAL"
    );
    assert!(!outside_dir.join("ca-certificates.crt").exists());
}

#[test]
fn test_installer_race_swapping_component_during_atomic_write_refuses() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let rootfs = temp_dir.path().join("rootfs");
    let certs_dir = rootfs.join("etc/ssl/certs");
    fs::create_dir_all(&certs_dir).expect("create certs");
    let file_path = certs_dir.join("bundle.crt");
    fs::write(&file_path, b"ORIGINAL_DATA").expect("write file");

    let outside_file = temp_dir.path().join("outside_secret.txt");
    fs::write(&outside_file, b"OUTSIDE_SECRET").expect("write secret");

    let file_clone = file_path.clone();
    let outside_clone = outside_file.clone();

    let _hook = hermetic_trust::set_before_use_hook_guard(move || {
        let _ = fs::remove_file(&file_clone);
        let _ = std::os::unix::fs::symlink(&outside_clone, &file_clone);
    });

    let root_handle = open_dir_handle(&rootfs).expect("open rootfs");
    let result = atomic_write_in_root(
        &root_handle,
        std::path::Path::new("etc/ssl/certs/bundle.crt"),
        b"ATTACK_PAYLOAD",
        NEW_FILE_MODE,
        current_owner(),
    );
    drop(_hook);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TrustError::Symlink(_)));
    assert_eq!(
        fs::read(&outside_file).expect("read outside"),
        b"OUTSIDE_SECRET"
    );
}
