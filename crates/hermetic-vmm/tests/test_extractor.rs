#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::disk::{DiskError, ExtractDiskHeader, ExtractFailureCode};
use hermetic_extract::format::StreamEncoder;
use hermetic_vmm::extractor::{
    create_fresh_output_drive, create_overlay_cow_copy, extractor_spec, read_extractor_output,
    ExtractorError, ExtractorVmConfig,
};
use hermetic_vmm::spec::{JailConfig, Role};
use hermetic_vmm::Error;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TEST_NONCE: [u8; 32] = [0x5a; 32];

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn dummy_jail_config() -> JailConfig {
    JailConfig {
        base: "/jails".into(),
        uid_start: 200000,
        gid_start: 200000,
        count: 64,
        firecracker: "/bin/firecracker".into(),
        jailer: "/bin/jailer".into(),
        netns: "isolated-0".into(),
    }
}

#[test]
fn cow_copy_creates_mode_0600_copy_and_refuses_symlinks() {
    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("overlay.img");
    fs::write(&src_file, b"simulated-overlay-journal-and-ext4-data").unwrap();

    let dst_file = tmp.path().join("overlay_cow.img");
    create_overlay_cow_copy(&src_file, &dst_file).unwrap();

    // Verify content matches
    let content = fs::read(&dst_file).unwrap();
    assert_eq!(content, b"simulated-overlay-journal-and-ext4-data");

    // Verify mode is 0600
    let meta = fs::metadata(&dst_file).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    // Verify symlink source is refused
    let symlink_src = tmp.path().join("symlink_overlay");
    std::os::unix::fs::symlink(&src_file, &symlink_src).unwrap();
    let dst_sym_target = tmp.path().join("from_symlink.img");
    let err = create_overlay_cow_copy(&symlink_src, &dst_sym_target).unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));

    // Verify directory source is refused
    let dir_src = tmp.path().join("dir_overlay");
    fs::create_dir(&dir_src).unwrap();
    let err = create_overlay_cow_copy(&dir_src, &dst_sym_target).unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));
}

#[test]
fn cow_copy_refuses_existing_destination() {
    // Regression test for Defect F: O_EXCL must refuse an existing destination
    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("overlay.img");
    fs::write(&src_file, b"simulated-overlay").unwrap();

    let dst_file = tmp.path().join("overlay_cow.img");
    fs::write(&dst_file, b"pre-existing file").unwrap();

    let err = create_overlay_cow_copy(&src_file, &dst_file).unwrap_err();
    assert!(matches!(err, ExtractorError::Io { .. }));
}

#[test]
fn cow_copy_refuses_symlinked_destination_parent() {
    // Regression test for Defect F: destination parent must be checked without following symlinks
    let tmp = TempDir::new().unwrap();
    let real_parent = tmp.path().join("real_parent");
    fs::create_dir(&real_parent).unwrap();

    let sym_parent = tmp.path().join("sym_parent");
    std::os::unix::fs::symlink(&real_parent, &sym_parent).unwrap();

    let src_file = tmp.path().join("overlay.img");
    fs::write(&src_file, b"simulated-overlay").unwrap();

    let dst_file = sym_parent.join("dst_cow.img");
    let err = create_overlay_cow_copy(&src_file, &dst_file).unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));
}

#[test]
fn create_fresh_output_drive_contract() {
    // Regression test for Defect E(1): fresh output drive creation, O_EXCL, 0600, zero-filled
    let tmp = TempDir::new().unwrap();
    let out_file = tmp.path().join("output.img");

    create_fresh_output_drive(&out_file, 64 * 1024).unwrap();
    assert!(out_file.exists());

    // Verify file size and mode 0600
    let meta = fs::metadata(&out_file).unwrap();
    assert_eq!(meta.len(), 64 * 1024);
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    // Verify zero-filled
    let bytes = fs::read(&out_file).unwrap();
    assert_eq!(bytes, vec![0u8; 64 * 1024]);

    // Re-creating the same file must fail with O_EXCL
    let err = create_fresh_output_drive(&out_file, 64 * 1024).unwrap_err();
    assert!(matches!(err, ExtractorError::Io { .. }));

    // Recreating with symlinked parent must fail
    let sym_parent = tmp.path().join("sym_parent");
    std::os::unix::fs::symlink(tmp.path(), &sym_parent).unwrap();
    let err = create_fresh_output_drive(&sym_parent.join("new.img"), 1024).unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));

    // Zero size must fail
    let err = create_fresh_output_drive(&tmp.path().join("zero.img"), 0).unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));
}

#[test]
fn extractor_spec_validation_and_plan_contract() {
    let config = ExtractorVmConfig {
        vm_id: "extractor-vm-1".into(),
        index: 1,
        extractor_image: "/images/extractor.img".into(),
        kernel_image: "/images/kernel".into(),
        base_drive: "/images/base.img".into(),
        overlay_cow_drive: "/images/overlay_cow.img".into(),
        output_drive: "/images/output.img".into(),
        task_class: "patch:".into(),
        run_nonce: TEST_NONCE,
        t_clock: 1700000000,
        vcpus: 2,
        memory_mib: 512,
        cpu_template: "/images/cpu-template.json".into(),
        jail: dummy_jail_config(),
    };

    let spec = extractor_spec(&config).unwrap();
    assert_eq!(spec.role, Role::Extractor);
    assert_eq!(spec.drives.len(), 3);
    assert_eq!(spec.drives[0].id, "output");
    assert!(!spec.drives[0].read_only); // output drive is writable
    assert_eq!(spec.drives[1].id, "base");
    assert!(spec.drives[1].read_only); // base drive is read-only
    assert_eq!(spec.drives[2].id, "overlay");
    assert!(!spec.drives[2].read_only); // overlay CoW copy is writable
    assert!(spec.networks.is_empty()); // no network
    assert!(spec.vsock.is_none()); // no vsock exec

    // Verify cmdline parameters (items D and E(2))
    assert!(spec.boot_args.contains("hermetic.base=/dev/vdc"));
    assert!(spec.boot_args.contains("hermetic.overlay=/dev/vdd"));
    assert!(spec.boot_args.contains("hermetic.output=/dev/vdb"));
    let hex_nonce = TEST_NONCE
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    assert!(spec
        .boot_args
        .contains(&format!("hermetic.nonce={hex_nonce}")));

    // Validate spec passes hermetic-vmm validation
    let validated = spec.validate().unwrap();
    assert_eq!(validated.spec().role, Role::Extractor);
}

#[test]
fn extractor_spec_refuses_whitespace_or_control_in_task_class() {
    // Regression test for Defect F: spaces, tabs, newlines, control chars inject cmdline args
    let mut config = ExtractorVmConfig {
        vm_id: "extractor-vm-1".into(),
        index: 1,
        extractor_image: "/images/extractor.img".into(),
        kernel_image: "/images/kernel".into(),
        base_drive: "/images/base.img".into(),
        overlay_cow_drive: "/images/overlay_cow.img".into(),
        output_drive: "/images/output.img".into(),
        task_class: "patch: dir".into(), // contains space!
        run_nonce: TEST_NONCE,
        t_clock: 1700000000,
        vcpus: 2,
        memory_mib: 512,
        cpu_template: "/images/cpu-template.json".into(),
        jail: dummy_jail_config(),
    };
    assert!(extractor_spec(&config).is_err());

    config.task_class = "patch:dir\ninit=/evil".into();
    assert!(extractor_spec(&config).is_err());

    config.task_class = "patch:dir\tconsole=ttyS1".into();
    assert!(extractor_spec(&config).is_err());

    config.task_class = "patch:dir\x01".into();
    assert!(extractor_spec(&config).is_err());

    config.task_class = "invalid_class".into();
    assert!(extractor_spec(&config).is_err());
}

#[test]
fn extractor_spec_runs_vmspec_validation() {
    // Regression test for Defect F: extractor_spec must run VmSpec validation on result
    let config = ExtractorVmConfig {
        vm_id: "extractor-vm-1".into(),
        index: 1,
        extractor_image: "/images/extractor.img".into(),
        kernel_image: "/images/kernel".into(),
        base_drive: "/images/base.img".into(),
        overlay_cow_drive: "/images/overlay_cow.img".into(),
        output_drive: "/images/output.img".into(),
        task_class: "patch:".into(),
        run_nonce: TEST_NONCE,
        t_clock: 1700000000,
        vcpus: 0, // Invalid! VmSpec validation must reject this
        memory_mib: 512,
        cpu_template: "/images/cpu-template.json".into(),
        jail: dummy_jail_config(),
    };
    let err = extractor_spec(&config).unwrap_err();
    assert_eq!(err, Error::Validation("machine resource caps"));
}

/// Helper that creates a hand-made raw output drive with a valid HEXT stream.
fn create_handmade_output_drive(
    drive_path: &Path,
    stream_payload: &[u8],
    failure_code: Option<ExtractFailureCode>,
    nonce: [u8; 32],
) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(drive_path)
        .unwrap();

    let header = match failure_code {
        Some(code) => ExtractDiskHeader::new_failure(code, nonce),
        None => {
            let digest = compute_sha256(stream_payload);
            ExtractDiskHeader::new_success(nonce, stream_payload.len() as u64, digest)
        }
    };

    file.write_all(&header.encode()).unwrap();
    if failure_code.is_none() {
        file.write_all(stream_payload).unwrap();
    }
    // Pad to 1 MiB
    let current_pos = file.metadata().unwrap().len();
    if current_pos < 1024 * 1024 {
        file.set_len(1024 * 1024).unwrap();
    }
}

/// Generates a valid HEXT stream payload containing changes:
/// - modified `calc.py`
/// - new `fresh.txt`
fn make_hext_stream() -> Vec<u8> {
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    let calc_data = b"def add(a, b): return a + b\n";
    StreamEncoder::write_file(&mut stream, "calc.py", 0o644, calc_data).unwrap();
    let fresh_data = b"newly created file\n";
    StreamEncoder::write_file(&mut stream, "fresh.txt", 0o644, fresh_data).unwrap();
    StreamEncoder::write_end(&mut stream, 2, (calc_data.len() + fresh_data.len()) as u64).unwrap();
    stream
}

#[test]
fn read_extractor_output_valid_stream_produces_outcome() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    fs::write(base_dir.join("calc.py"), b"def add(a, b): return a\n").unwrap();

    let stream = make_hext_stream();
    let drive_path = tmp.path().join("output.img");
    create_handmade_output_drive(&drive_path, &stream, None, TEST_NONCE);

    let extract_config = ExtractConfig::default();
    let outcome = read_extractor_output(
        &drive_path,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &extract_config,
    )
    .unwrap();

    assert!(outcome.patch_digest.starts_with("sha256:"));
    assert!(outcome.tamper_evidence.is_none());

    // Verify published files in out_dir
    let published_calc = fs::read(out_dir.join("calc.py")).unwrap();
    assert_eq!(published_calc, b"def add(a, b): return a + b\n");
    let published_fresh = fs::read(out_dir.join("fresh.txt")).unwrap();
    assert_eq!(published_fresh, b"newly created file\n");
}

#[test]
fn read_extractor_output_refuses_nonce_mismatch() {
    // Regression test for Defect E(2): output drive nonce mismatch must be rejected
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let stream = make_hext_stream();
    let drive_path = tmp.path().join("output_bad_nonce.img");
    create_handmade_output_drive(&drive_path, &stream, None, TEST_NONCE);

    let different_nonce = [0x99; 32];
    let extract_config = ExtractConfig::default();
    let err = read_extractor_output(
        &drive_path,
        &different_nonce,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &extract_config,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ExtractorError::Disk(DiskError::NonceMismatch { .. })
    ));
}

#[test]
fn read_extractor_output_failure_codes_refused() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let drive_path = tmp.path().join("output_failed.img");
    create_handmade_output_drive(
        &drive_path,
        b"",
        Some(ExtractFailureCode::Timeout),
        TEST_NONCE,
    );

    let extract_config = ExtractConfig::default();
    let err = read_extractor_output(
        &drive_path,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &extract_config,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ExtractorError::Disk(DiskError::FailureCode(1))
    ));
}

#[test]
fn read_extractor_output_corrupted_hash_refused() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let stream = make_hext_stream();
    let drive_path = tmp.path().join("output_bad_hash.img");

    let mut file = File::create(&drive_path).unwrap();
    let mut bad_digest = compute_sha256(&stream);
    bad_digest[0] ^= 0xAA;
    let header = ExtractDiskHeader::new_success(TEST_NONCE, stream.len() as u64, bad_digest);
    file.write_all(&header.encode()).unwrap();
    file.write_all(&stream).unwrap();

    let extract_config = ExtractConfig::default();
    let err = read_extractor_output(
        &drive_path,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &extract_config,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ExtractorError::Disk(DiskError::Sha256Mismatch { .. })
    ));
}

#[test]
fn read_extractor_output_truncated_header_and_oversize_refused() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    // Truncated (less than 80 bytes)
    let tiny_drive = tmp.path().join("tiny.img");
    fs::write(&tiny_drive, [0u8; 30]).unwrap();
    let err = read_extractor_output(
        &tiny_drive,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractorError::Disk(DiskError::TruncatedHeader { .. })
    ));

    // Oversize (payload_len declared higher than quota)
    let oversize_drive = tmp.path().join("oversize.img");
    let mut file = File::create(&oversize_drive).unwrap();
    let header = ExtractDiskHeader::new_success(TEST_NONCE, 50_000_000, [0u8; 32]);
    file.write_all(&header.encode()).unwrap();
    file.set_len(1024 * 1024).unwrap();

    let strict_config = ExtractConfig {
        max_total_bytes: 1000,
        ..ExtractConfig::default()
    };
    let err = read_extractor_output(
        &oversize_drive,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &strict_config,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractorError::Disk(DiskError::PayloadTooLarge { .. })
    ));
}

#[test]
fn read_extractor_output_refuses_symlink_path() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let real_drive = tmp.path().join("real_output.img");
    fs::write(&real_drive, [0u8; 100]).unwrap();
    let sym_drive = tmp.path().join("symlink_output.img");
    std::os::unix::fs::symlink(&real_drive, &sym_drive).unwrap();

    let err = read_extractor_output(
        &sym_drive,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));
}

#[test]
fn read_extractor_output_restores_test_infra_and_records_tamper_evidence() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("base");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    fs::write(base_dir.join("conftest.py"), b"# original base conftest\n").unwrap();

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    let hostile_conftest = b"# agent hostile conftest\n";
    StreamEncoder::write_file(&mut stream, "conftest.py", 0o644, hostile_conftest).unwrap();
    StreamEncoder::write_end(&mut stream, 1, hostile_conftest.len() as u64).unwrap();

    let drive_path = tmp.path().join("output_tampered.img");
    create_handmade_output_drive(&drive_path, &stream, None, TEST_NONCE);

    let extract_config = ExtractConfig::default();
    let outcome = read_extractor_output(
        &drive_path,
        &TEST_NONCE,
        &base_dir,
        &out_dir,
        TaskClass::Patch,
        &extract_config,
    )
    .unwrap();

    assert!(outcome.patch_digest.starts_with("sha256:"));
    // Tamper evidence was recorded because conftest.py was restored from base
    assert!(outcome.tamper_evidence.is_some());
    assert!(outcome.tamper_evidence.unwrap().contains("restored:1"));

    // Verify conftest.py in out_dir has original base content, not hostile content!
    let published_conftest = fs::read(out_dir.join("conftest.py")).unwrap();
    assert_eq!(published_conftest, b"# original base conftest\n");
}

#[test]
fn smoke_script_exists_and_is_executable() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts/integration/extract-vm-smoke.sh");
    assert!(script.exists(), "smoke script must exist: {:?}", script);
    let perms = fs::metadata(&script).unwrap().permissions();
    assert_eq!(
        perms.mode() & 0o777,
        0o755,
        "smoke script must have mode 0755 without runtime modification"
    );
}

#[test]
fn cow_copy_source_truncation_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("empty_source.img");
    fs::write(&src_file, b"").unwrap();

    let dst_file = tmp.path().join("dst.img");
    fs::write(&dst_file, b"").unwrap();

    let src_fd = rustix::fs::open(
        &src_file,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let dst_fd = rustix::fs::open(
        &dst_file,
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();

    // Source file has 0 bytes, but file_len is expected to be 100 bytes.
    let err = hermetic_vmm::fallback_chunked_copy(&src_fd, &dst_fd, 100, 0).unwrap_err();
    assert!(matches!(
        err,
        ExtractorError::Validation("source overlay truncated during copy")
    ));
}

#[test]
fn destination_path_without_filename_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let src_file = tmp.path().join("overlay.img");
    fs::write(&src_file, b"overlay data").unwrap();

    // Destination path with no file name (e.g. root dir "/")
    let root_dst = Path::new("/");
    let err = create_overlay_cow_copy(&src_file, root_dst).unwrap_err();
    assert!(matches!(err, ExtractorError::Validation(_)));

    let err_drive = create_fresh_output_drive(root_dst, 4096).unwrap_err();
    assert!(matches!(err_drive, ExtractorError::Validation(_)));
}

#[test]
fn extractor_request_plan_invariants_and_comparison_with_working_specs() {
    use hermetic_vmm::jail_plan;
    use hermetic_vmm::plan::{calibrated_api_requests, cpu_template};
    use serde_json::json;

    let config = ExtractorVmConfig {
        vm_id: "extractor-vm-guest".into(),
        index: 0,
        extractor_image: "/images/extractor.img".into(),
        kernel_image: "/images/kernel".into(),
        base_drive: "/images/base.img".into(),
        overlay_cow_drive: "/images/overlay_cow.img".into(),
        output_drive: "/images/output.img".into(),
        task_class: "patch:".into(),
        run_nonce: TEST_NONCE,
        t_clock: 1700000000,
        vcpus: 2,
        memory_mib: 1024,
        cpu_template: "/images/cpu-template.json".into(),
        jail: dummy_jail_config(),
    };

    let spec = extractor_spec(&config).expect("valid extractor spec");
    let validated = spec.validate().expect("valid spec");
    let requests = calibrated_api_requests(&validated, 2_000_000).expect("calibrated requests");

    // 1. Structure and ordering: exactly 8 API requests in strict sequence
    assert_eq!(requests.len(), 8);
    assert_eq!(requests[0].path, "/machine-config");
    assert_eq!(requests[1].path, "/cpu-config");
    assert_eq!(requests[2].path, "/boot-source");
    assert_eq!(requests[3].path, "/drives/rootfs");
    assert_eq!(requests[4].path, "/drives/output");
    assert_eq!(requests[5].path, "/drives/base");
    assert_eq!(requests[6].path, "/drives/overlay");
    assert_eq!(requests[7].path, "/entropy");

    // 2. Machine config invariant: vcpu_count, mem_size_mib, smt=false
    assert_eq!(
        requests[0].body,
        json!({"vcpu_count": 2, "mem_size_mib": 1024, "smt": false})
    );

    // 3. CPU template invariant: exactly matches embedded clock-3b profile
    assert_eq!(requests[1].body, cpu_template());

    // 4. Boot source invariant: kernel path, required cmdline tokens, and no forbidden tokens
    assert_eq!(requests[2].body["kernel_image_path"], "/kernel");
    assert!(requests[2].body.get("initrd_path").is_none());
    let boot_args = requests[2].body["boot_args"].as_str().unwrap();
    assert!(boot_args.contains("console=ttyS0"));
    assert!(boot_args.contains("reboot=k"));
    assert!(boot_args.contains("panic=-1"));
    assert!(boot_args.contains("pci=off"));
    assert!(boot_args.contains("root=/dev/vda"));
    assert!(boot_args.contains("init=/sbin/hermetic-extract-init"));
    assert!(boot_args.contains("clocksource=tsc"));
    assert!(boot_args.contains("tsc=reliable"));
    assert!(boot_args.contains("hermetic.t=1700000000"));
    assert!(boot_args.contains("ro"));
    assert!(boot_args.contains("hermetic.class=patch:"));
    assert!(boot_args.contains("hermetic.base=/dev/vdc"));
    assert!(boot_args.contains("hermetic.overlay=/dev/vdd"));
    assert!(boot_args.contains("hermetic.output=/dev/vdb"));
    let hex_nonce = TEST_NONCE
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    assert!(boot_args.contains(&format!("hermetic.nonce={hex_nonce}")));
    assert!(!boot_args.contains("tsc_early_khz"));
    assert!(!boot_args.contains("rw"));
    assert!(!boot_args.contains("ip="));

    // 5. Drives invariants: order, ids, read_only flags, is_root_device
    // First drive is rootfs (read-only root device)
    assert_eq!(
        requests[3].body,
        json!({
            "drive_id": "rootfs",
            "path_on_host": "/drive-rootfs",
            "is_root_device": true,
            "is_read_only": true,
        })
    );
    // Output drive: writable, non-root (/dev/vdb in guest)
    assert_eq!(
        requests[4].body,
        json!({
            "drive_id": "output",
            "path_on_host": "/drive-output",
            "is_root_device": false,
            "is_read_only": false,
        })
    );
    // Base drive: read-only, non-root (/dev/vdc in guest)
    assert_eq!(
        requests[5].body,
        json!({
            "drive_id": "base",
            "path_on_host": "/drive-base",
            "is_root_device": false,
            "is_read_only": true,
        })
    );
    // Overlay drive: writable, non-root (/dev/vdd in guest)
    assert_eq!(
        requests[6].body,
        json!({
            "drive_id": "overlay",
            "path_on_host": "/drive-overlay",
            "is_root_device": false,
            "is_read_only": false,
        })
    );
    // Exactly one root device among all drives
    let root_count = requests
        .iter()
        .filter(|r| r.body.get("is_root_device").and_then(|v| v.as_bool()) == Some(true))
        .count();
    assert_eq!(root_count, 1);

    // 6. Device absence invariants: no vsock, no network, no mmds/balloon/logger/metrics
    assert!(requests.iter().all(|r| r.path != "/vsock"));
    assert!(requests
        .iter()
        .all(|r| !r.path.starts_with("/network-interfaces/")));
    assert!(requests.iter().all(|r| !r.path.starts_with("/mmds")
        && !r.path.starts_with("/balloon")
        && !r.path.starts_with("/logger")
        && !r.path.starts_with("/metrics")));

    // 7. Entropy invariant: final request is /entropy
    assert_eq!(requests[7].path, "/entropy");
    assert_eq!(requests[7].body, json!({}));

    // 8. Jail plan invariants
    let jp = jail_plan(&validated);
    assert_eq!(jp.files.len(), 6);
    assert_eq!(jp.files[0].destination, "kernel");
    assert!(!jp.files[0].writable);
    assert_eq!(jp.files[1].destination, "cpu-template.json");
    assert!(!jp.files[1].writable);
    assert_eq!(jp.files[2].destination, "drive-rootfs");
    assert!(!jp.files[2].writable);
    assert_eq!(jp.files[3].destination, "drive-output");
    assert!(jp.files[3].writable);
    assert_eq!(jp.files[4].destination, "drive-base");
    assert!(!jp.files[4].writable);
    assert_eq!(jp.files[5].destination, "drive-overlay");
    assert!(jp.files[5].writable);
    assert_eq!(jp.api_socket, format!("{}/api.socket", jp.root));
    assert_eq!((jp.uid, jp.gid), (200000, 200000));

    // 9. Field-by-field comparison with working specs:
    //    boots_guest_and_reads_guest_clock and reboots_touched_disk_with_trusted_initramfs
    use hermetic_vmm::spec::{Clock, Drive, Initrd, Limits, Role as VmRole, VmSpec, Vsock};

    let working_clock_spec = VmSpec {
        id: "vm-0".into(),
        role: VmRole::Agent,
        index: 0,
        vcpus: 2,
        memory_mib: 256,
        kernel_image: "/images/kernel".into(),
        initrd: None,
        boot_args: concat!(
            "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda ",
            "init=/sbin/hermetic-init clocksource=tsc tsc=reliable ",
            "hermetic.t=1700000000 ro"
        )
        .into(),
        root_drive: Drive {
            id: "rootfs".into(),
            path: "/images/rootfs".into(),
            read_only: true,
        },
        drives: vec![Drive {
            id: "overlay".into(),
            path: "/images/overlay".into(),
            read_only: false,
        }],
        reserved_drives: vec!["tests".into()],
        vsock: Some(Vsock {
            guest_cid: 3,
            socket_path: "/vsock".into(),
        }),
        networks: vec![],
        cpu_template: "/images/cpu-template.json".into(),
        clock: Clock::Faked,
        limits: Limits {
            pids: 128,
            file_size_bytes: 67108864,
            open_files: 128,
        },
        jail: dummy_jail_config(),
    };
    let working_clock_reqs =
        calibrated_api_requests(&working_clock_spec.validate().unwrap(), 2_000_000).unwrap();

    let working_reboot_spec = VmSpec {
        id: "vm-0".into(),
        role: VmRole::Agent,
        index: 0,
        vcpus: 2,
        memory_mib: 256,
        kernel_image: "/images/kernel".into(),
        initrd: Some(Initrd {
            path: "/images/trusted.cpio".into(),
            sha256: "a".repeat(64),
        }),
        boot_args: concat!(
            "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda ",
            "hermetic.initramfs=1 clocksource=tsc tsc=reliable ",
            "hermetic.t=1700000000 ro"
        )
        .into(),
        root_drive: Drive {
            id: "rootfs".into(),
            path: "/images/rootfs".into(),
            read_only: true,
        },
        drives: vec![Drive {
            id: "overlay".into(),
            path: "/images/overlay".into(),
            read_only: false,
        }],
        reserved_drives: vec![],
        vsock: Some(Vsock {
            guest_cid: 3,
            socket_path: "/vsock".into(),
        }),
        networks: vec![],
        cpu_template: "/images/cpu-template.json".into(),
        clock: Clock::Faked,
        limits: Limits {
            pids: 128,
            file_size_bytes: 67108864,
            open_files: 128,
        },
        jail: dummy_jail_config(),
    };
    let working_reboot_reqs =
        calibrated_api_requests(&working_reboot_spec.validate().unwrap(), 2_000_000).unwrap();

    // Field-by-field verification across extractor and working specs:
    // (a) vCPUs: All specs require vcpu_count == 2
    assert_eq!(
        requests[0].body["vcpu_count"],
        working_clock_reqs[0].body["vcpu_count"]
    );
    assert_eq!(
        requests[0].body["vcpu_count"],
        working_reboot_reqs[0].body["vcpu_count"]
    );
    assert_eq!(requests[0].body["vcpu_count"], 2);

    // (b) SMT: disabled across all specs
    assert_eq!(requests[0].body["smt"], false);
    assert_eq!(working_clock_reqs[0].body["smt"], false);
    assert_eq!(working_reboot_reqs[0].body["smt"], false);

    // (c) Memory: within supported range (64..=16384 MiB)
    assert_eq!(requests[0].body["mem_size_mib"], 1024);
    assert_eq!(working_clock_reqs[0].body["mem_size_mib"], 256);

    // (d) CPU template: identically matches the embedded clock-3b template
    assert_eq!(requests[1], working_clock_reqs[1]);
    assert_eq!(requests[1], working_reboot_reqs[1]);

    // (e) Kernel image path: all point to "/kernel"
    assert_eq!(requests[2].body["kernel_image_path"], "/kernel");
    assert_eq!(working_clock_reqs[2].body["kernel_image_path"], "/kernel");
    assert_eq!(working_reboot_reqs[2].body["kernel_image_path"], "/kernel");

    // (f) Boot arguments: all contain the mandatory core tokens
    for common in [
        "console=ttyS0",
        "reboot=k",
        "panic=-1",
        "pci=off",
        "root=/dev/vda",
        "clocksource=tsc",
        "tsc=reliable",
        "hermetic.t=1700000000",
        "ro",
    ] {
        assert!(boot_args.contains(common), "missing core token {common}");
        assert!(
            working_clock_reqs[2].body["boot_args"]
                .as_str()
                .unwrap()
                .contains(common),
            "working clock spec missing {common}"
        );
        assert!(
            working_reboot_reqs[2].body["boot_args"]
                .as_str()
                .unwrap()
                .contains(common),
            "working reboot spec missing {common}"
        );
    }

    // (g) Root drive: drive_id="rootfs", is_root_device=true, is_read_only=true across all
    assert_eq!(requests[3].body["drive_id"], "rootfs");
    assert_eq!(requests[3].body["is_root_device"], true);
    assert_eq!(requests[3].body["is_read_only"], true);
    assert_eq!(working_clock_reqs[3].body["drive_id"], "rootfs");
    assert_eq!(working_clock_reqs[3].body["is_root_device"], true);
    assert_eq!(working_clock_reqs[3].body["is_read_only"], true);
    assert_eq!(working_reboot_reqs[3].body["drive_id"], "rootfs");
    assert_eq!(working_reboot_reqs[3].body["is_root_device"], true);
    assert_eq!(working_reboot_reqs[3].body["is_read_only"], true);

    // (h) Isolation: Extractor has no vsock and no networks (unlike agent specs)
    assert!(requests.iter().all(|r| r.path != "/vsock"));
    assert!(working_clock_reqs.iter().any(|r| r.path == "/vsock"));
    assert!(working_reboot_reqs.iter().any(|r| r.path == "/vsock"));

    // (i) Entropy: identical final request
    assert_eq!(requests[7], *working_clock_reqs.last().unwrap());
    assert_eq!(requests[7], *working_reboot_reqs.last().unwrap());
}
