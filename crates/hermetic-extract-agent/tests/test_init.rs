#![forbid(unsafe_code)]

use std::cell::Cell;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hermetic_extract::disk::{
    ExtractDiskHeader, ExtractFailureCode, EXTRACT_DISK_MAGIC, EXTRACT_DISK_VERSION,
};
use hermetic_extract_agent::init::{
    overlayfs_options, run_extractor_init, ExtractorConfig, ExtractorSys, InitError, OutputWriter,
    OVERLAY_DATA_OPTIONS, OVERLAY_MOUNT_FLAGS,
};
use hermetic_extract_agent::TaskClass;
use rustix::mount::MountFlags;

// --- Config Tests ---

const VALID_CMDLINE_COMMON: &str = "hermetic.base=/dev/vdc hermetic.overlay=/dev/vdd hermetic.output=/dev/vdb hermetic.nonce=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn config_parse_cmdline_classes() {
    // patch: (tree root)
    let cmd = format!("console=ttyS0 hermetic.class=patch: {VALID_CMDLINE_COMMON} ro");
    let c = ExtractorConfig::parse_cmdline(cmd.as_bytes()).unwrap();
    assert_eq!(
        c.task_class,
        TaskClass::Patch {
            repo_dir: String::new()
        }
    );

    // patch:repo
    let cmd = format!("hermetic.class=patch:repo/sub {VALID_CMDLINE_COMMON} ro");
    let c = ExtractorConfig::parse_cmdline(cmd.as_bytes()).unwrap();
    assert_eq!(
        c.task_class,
        TaskClass::Patch {
            repo_dir: "repo/sub".to_string()
        }
    );

    // artifact:p1,p2
    let cmd = format!("hermetic.class=artifact:a.txt,dir/b.py {VALID_CMDLINE_COMMON}");
    let c = ExtractorConfig::parse_cmdline(cmd.as_bytes()).unwrap();
    assert_eq!(
        c.task_class,
        TaskClass::Artifact {
            paths: vec!["a.txt".to_string(), "dir/b.py".to_string()]
        }
    );

    // state
    let cmd = format!("hermetic.class=state {VALID_CMDLINE_COMMON}");
    let c = ExtractorConfig::parse_cmdline(cmd.as_bytes()).unwrap();
    assert_eq!(c.task_class, TaskClass::State);
}

#[test]
fn config_parse_cmdline_missing_class_refused() {
    // A missing task class must fail closed (defect D)
    let cmd = format!("console=ttyS0 root=/dev/vda {VALID_CMDLINE_COMMON} ro");
    assert!(ExtractorConfig::parse_cmdline(cmd.as_bytes()).is_err());
}

#[test]
fn config_parse_cmdline_invalid_classes_refused() {
    for bad in [
        format!("hermetic.class=patch:. {VALID_CMDLINE_COMMON}"),
        format!("hermetic.class=patch:/ {VALID_CMDLINE_COMMON}"),
        format!("hermetic.class=artifact: {VALID_CMDLINE_COMMON}"),
        format!("hermetic.class=artifact:a/../b {VALID_CMDLINE_COMMON}"),
        format!("hermetic.class=unknown {VALID_CMDLINE_COMMON}"),
        format!("hermetic.class=\"patch: bad\" {VALID_CMDLINE_COMMON}"),
    ] {
        assert!(ExtractorConfig::parse_cmdline(bad.as_bytes()).is_err());
    }
}

#[test]
fn config_parse_cmdline_refuses_unknown_or_duplicate_hermetic_keys() {
    // Unknown hermetic.* key
    let bad_key = format!("hermetic.class=patch: hermetic.unknown=1 {VALID_CMDLINE_COMMON}");
    assert!(ExtractorConfig::parse_cmdline(bad_key.as_bytes()).is_err());

    // Duplicate hermetic.class
    let dup_class = format!("hermetic.class=patch: hermetic.class=state {VALID_CMDLINE_COMMON}");
    assert!(ExtractorConfig::parse_cmdline(dup_class.as_bytes()).is_err());

    // Duplicate hermetic.base
    let dup_base = format!("hermetic.class=patch: hermetic.base=/dev/vdc {VALID_CMDLINE_COMMON}");
    assert!(ExtractorConfig::parse_cmdline(dup_base.as_bytes()).is_err());
}

#[test]
fn config_parse_cmdline_devices_and_caps() {
    let cmdline = concat!(
        "hermetic.class=patch: ",
        "hermetic.base=/dev/vdc ",
        "hermetic.overlay=/dev/vdd ",
        "hermetic.output=/dev/vdb ",
        "hermetic.nonce=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ",
        "hermetic.deadline_secs=300 ",
        "hermetic.max_file_bytes=1048576 ",
        "hermetic.max_total_bytes=10485760"
    );
    let c = ExtractorConfig::parse_cmdline(cmdline.as_bytes()).unwrap();
    assert_eq!(c.base_dev, "/dev/vdc");
    assert_eq!(c.overlay_dev, "/dev/vdd");
    assert_eq!(c.output_dev, "/dev/vdb");
    assert_eq!(c.overall_deadline, Duration::from_secs(300));
    assert_eq!(c.caps.max_file_bytes, 1048576);
    assert_eq!(c.caps.max_total_bytes, 10485760);
}

#[test]
fn config_parse_cmdline_refuses_unexpected_devices_or_missing_nonce() {
    // Unexpected base device
    let bad_base = "hermetic.class=patch: hermetic.base=/dev/vde hermetic.overlay=/dev/vdd hermetic.output=/dev/vdb hermetic.nonce=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(ExtractorConfig::parse_cmdline(bad_base.as_bytes()).is_err());

    // Missing nonce
    let no_nonce = "hermetic.class=patch: hermetic.base=/dev/vdc hermetic.overlay=/dev/vdd hermetic.output=/dev/vdb";
    assert!(ExtractorConfig::parse_cmdline(no_nonce.as_bytes()).is_err());
}

#[test]
fn config_parse_cmdline_nonce_non_ascii_utf8_refused_no_panic() {
    let bad_nonce = format!(
        "hermetic.class=patch: hermetic.base=/dev/vdc hermetic.overlay=/dev/vdd hermetic.output=/dev/vdb hermetic.nonce=aé{}",
        "a".repeat(61)
    );
    let err = ExtractorConfig::parse_cmdline(bad_nonce.as_bytes()).unwrap_err();
    assert!(matches!(err, InitError::Config(_)));
}

#[test]
fn config_parse_json() {
    let json = br#"{
        "task_class": "artifact:out.bin,report.txt",
        "base_dev": "/dev/vdc",
        "overlay_dev": "/dev/vdd",
        "output_dev": "/dev/vdb",
        "nonce": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "deadline_seconds": 60,
        "max_file_bytes": 2048,
        "max_total_bytes": 4096
    }"#;
    let c = ExtractorConfig::parse_json(json).unwrap();
    assert_eq!(
        c.task_class,
        TaskClass::Artifact {
            paths: vec!["out.bin".to_string(), "report.txt".to_string()]
        }
    );
    assert_eq!(c.base_dev, "/dev/vdc");
    assert_eq!(c.overall_deadline, Duration::from_secs(60));
    assert_eq!(c.caps.max_file_bytes, 2048);
    assert_eq!(c.caps.max_total_bytes, 4096);
}

#[test]
fn config_parse_json_denies_unknown_fields_and_missing_task_class() {
    // Unknown field in JSON config
    let bad_json = br#"{
        "task_class": "state",
        "base_dev": "/dev/vdc",
        "overlay_dev": "/dev/vdd",
        "output_dev": "/dev/vdb",
        "nonce": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "extra_unknown_field": "disallowed"
    }"#;
    assert!(ExtractorConfig::parse_json(bad_json).is_err());

    // Missing task_class in JSON config
    let no_class_json = br#"{
        "base_dev": "/dev/vdc",
        "overlay_dev": "/dev/vdd",
        "output_dev": "/dev/vdb",
        "nonce": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }"#;
    assert!(ExtractorConfig::parse_json(no_class_json).is_err());
}

#[test]
fn config_parse_json_nonce_non_ascii_utf8_refused_no_panic() {
    let bad_nonce = format!("aé{}", "a".repeat(61));
    let json = format!(
        r#"{{
        "task_class": "state",
        "base_dev": "/dev/vdc",
        "overlay_dev": "/dev/vdd",
        "output_dev": "/dev/vdb",
        "nonce": "{bad_nonce}"
    }}"#
    );
    let err = ExtractorConfig::parse_json(json.as_bytes()).unwrap_err();
    assert!(matches!(err, InitError::Config(_)));
}

// --- Mount Option Tests ---

#[test]
fn overlay_mount_options_exact() {
    // Assert exact mount flags
    let expected_flags =
        MountFlags::RDONLY | MountFlags::NODEV | MountFlags::NOSUID | MountFlags::NOEXEC;
    assert_eq!(OVERLAY_MOUNT_FLAGS, expected_flags);
    assert!(OVERLAY_MOUNT_FLAGS.contains(MountFlags::RDONLY));
    assert!(OVERLAY_MOUNT_FLAGS.contains(MountFlags::NODEV));
    assert!(OVERLAY_MOUNT_FLAGS.contains(MountFlags::NOSUID));
    assert!(OVERLAY_MOUNT_FLAGS.contains(MountFlags::NOEXEC));
    // Verify no unexpected flags are enabled
    assert!(!OVERLAY_MOUNT_FLAGS.contains(MountFlags::SYNCHRONOUS));

    // Assert exact data options string
    assert_eq!(
        OVERLAY_DATA_OPTIONS,
        "redirect_dir=nofollow,metacopy=off,index=off"
    );

    // Helper format
    let opts = overlayfs_options("/mnt/overlay/upper:/mnt/base");
    assert_eq!(
        opts,
        "lowerdir=/mnt/overlay/upper:/mnt/base,redirect_dir=nofollow,metacopy=off,index=off"
    );
}

// --- Mock Sys and Full Lifecycle Tests ---

#[derive(Clone)]
struct SharedBuffer {
    data: Arc<Mutex<Cursor<Vec<u8>>>>,
}

impl SharedBuffer {
    fn new(size: usize) -> Self {
        Self {
            data: Arc::new(Mutex::new(Cursor::new(vec![0u8; size]))),
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        self.data.lock().unwrap().get_ref().clone()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.data.lock().unwrap().flush()
    }
}

impl Seek for SharedBuffer {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.data.lock().unwrap().seek(pos)
    }
}

struct MockSys {
    pid1: bool,
    cmdline: Vec<u8>,
    config_file: Option<Vec<u8>>,
    alt_config_file: Option<Vec<u8>>,
    output_buffer: SharedBuffer,
    mount_calls: Vec<String>,
    sync_called: bool,
    poweroff_called: bool,
    fail_at_mount: Option<&'static str>,
    timeout_in_mount_dev: bool,
    step_timeout_in_mount_dev: bool,
    fail_config_read: bool,
    check_in_progress_in_mount_dev: bool,
    seen_in_progress_code: Cell<Option<u16>>,
    now_instant: Instant,
    time_offset: Cell<Duration>,
}

impl MockSys {
    fn new(output_size: usize) -> Self {
        Self {
            pid1: true,
            cmdline: format!("console=ttyS0 hermetic.class=patch: {VALID_CMDLINE_COMMON} ro")
                .into_bytes(),
            config_file: None,
            alt_config_file: None,
            output_buffer: SharedBuffer::new(output_size),
            mount_calls: Vec::new(),
            sync_called: false,
            poweroff_called: false,
            fail_at_mount: None,
            timeout_in_mount_dev: false,
            step_timeout_in_mount_dev: false,
            fail_config_read: false,
            check_in_progress_in_mount_dev: false,
            seen_in_progress_code: Cell::new(None),
            now_instant: Instant::now(),
            time_offset: Cell::new(Duration::ZERO),
        }
    }
}

impl ExtractorSys for MockSys {
    fn is_pid1(&self) -> bool {
        self.pid1
    }

    fn read_cmdline(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.cmdline.clone())
    }

    fn read_config_file(&mut self, path: &str) -> io::Result<Option<Vec<u8>>> {
        if self.fail_config_read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "config file read error",
            ));
        }
        if path == hermetic_extract_agent::init::ALT_CONFIG_FILE {
            return Ok(self.alt_config_file.clone());
        }
        Ok(self.config_file.clone())
    }

    fn mount_proc(&mut self) -> io::Result<()> {
        self.mount_calls.push("proc".into());
        if self.fail_at_mount == Some("proc") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proc mount fail",
            ));
        }
        Ok(())
    }

    fn mount_dev(&mut self) -> io::Result<()> {
        self.mount_calls.push("dev".into());
        if self.check_in_progress_in_mount_dev {
            let drive_data = self.output_buffer.to_vec();
            if let Ok(hdr) = ExtractDiskHeader::decode(&drive_data) {
                self.seen_in_progress_code.set(Some(hdr.failure_code));
            }
        }
        if self.timeout_in_mount_dev {
            self.time_offset.set(Duration::from_secs(10_000));
        }
        if self.step_timeout_in_mount_dev {
            self.time_offset.set(Duration::from_secs(35));
        }
        if self.fail_at_mount == Some("dev") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "dev mount fail",
            ));
        }
        Ok(())
    }

    fn mount_base(&mut self, source: &str, target: &str) -> io::Result<()> {
        self.mount_calls.push(format!("base:{source}->{target}"));
        if self.fail_at_mount == Some("base") {
            return Err(io::Error::new(io::ErrorKind::NotFound, "base mount fail"));
        }
        Ok(())
    }

    fn mount_overlay(&mut self, source: &str, target: &str) -> io::Result<()> {
        self.mount_calls.push(format!("overlay:{source}->{target}"));
        if self.fail_at_mount == Some("overlay") {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "overlay mount fail",
            ));
        }
        Ok(())
    }

    fn mount_overlayfs(&mut self, lowerdir: &str, target: &str) -> io::Result<()> {
        self.mount_calls
            .push(format!("overlayfs:{lowerdir}->{target}"));
        if self.fail_at_mount == Some("overlayfs") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlayfs mount fail",
            ));
        }
        Ok(())
    }

    fn open_output(&mut self, _path: &str) -> io::Result<Box<dyn OutputWriter>> {
        Ok(Box::new(self.output_buffer.clone()))
    }

    fn sync(&mut self) -> io::Result<()> {
        self.sync_called = true;
        Ok(())
    }

    fn power_off(&mut self) -> io::Result<()> {
        self.poweroff_called = true;
        Ok(())
    }

    fn now(&self) -> Instant {
        self.now_instant + self.time_offset.get()
    }
}

#[test]
fn not_pid1_is_rejected() {
    let mut sys = MockSys::new(1024 * 1024);
    sys.pid1 = false;
    let err = run_extractor_init(&mut sys, None).unwrap_err();
    assert!(matches!(err, InitError::NotPid1));
    assert_eq!(err.to_failure_code(), ExtractFailureCode::InternalError);
}

#[test]
fn mount_failure_writes_failure_code_to_drive_header() {
    let mut sys = MockSys::new(1024 * 1024);
    sys.fail_at_mount = Some("base");

    let err = run_extractor_init(&mut sys, None).unwrap_err();
    assert!(matches!(err, InitError::Mount { step: "base", .. }));
    assert!(sys.sync_called);
    assert!(sys.poweroff_called);

    // Verify output drive has failure header with MountError and run nonce
    let drive_data = sys.output_buffer.to_vec();
    let header = ExtractDiskHeader::decode(&drive_data).unwrap();
    assert_eq!(header.magic, *EXTRACT_DISK_MAGIC);
    assert_eq!(header.version, EXTRACT_DISK_VERSION);
    assert_eq!(header.failure_code, ExtractFailureCode::MountError.as_raw());
    assert_eq!(header.payload_len, 0);
    assert_eq!(header.sha256, [0u8; 32]);
    let expected_nonce: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    assert_eq!(header.nonce, expected_nonce);
}

#[test]
fn timeout_writes_timeout_failure_code_to_drive_header() {
    let mut sys = MockSys::new(1024 * 1024);
    sys.timeout_in_mount_dev = true;

    let config = ExtractorConfig {
        overall_deadline: Duration::from_secs(10),
        step_deadline: Duration::from_secs(10),
        nonce: [0x55; 32],
        ..ExtractorConfig::default()
    };

    let err = run_extractor_init(&mut sys, Some(config)).unwrap_err();
    assert!(matches!(err, InitError::Timeout(_)));
    assert!(sys.sync_called);
    assert!(sys.poweroff_called);

    let drive_data = sys.output_buffer.to_vec();
    let header = ExtractDiskHeader::decode(&drive_data).unwrap();
    assert_eq!(header.failure_code, ExtractFailureCode::Timeout.as_raw());
    assert_eq!(header.payload_len, 0);
    assert_eq!(header.nonce, [0x55; 32]);
}

#[test]
fn step_deadline_exceeded_in_mount_dev_is_detected() {
    let mut sys = MockSys::new(1024 * 1024);
    sys.step_timeout_in_mount_dev = true;

    let config = ExtractorConfig {
        overall_deadline: Duration::from_secs(300),
        step_deadline: Duration::from_secs(30),
        nonce: [0x55; 32],
        ..ExtractorConfig::default()
    };

    let err = run_extractor_init(&mut sys, Some(config)).unwrap_err();
    assert!(matches!(err, InitError::Timeout("mount_dev")));
    assert!(sys.sync_called);
    assert!(sys.poweroff_called);

    let drive_data = sys.output_buffer.to_vec();
    let header = ExtractDiskHeader::decode(&drive_data).unwrap();
    assert_eq!(header.failure_code, ExtractFailureCode::Timeout.as_raw());
    assert_eq!(header.payload_len, 0);
    assert_eq!(header.nonce, [0x55; 32]);
}

#[test]
fn config_read_failure_runs_shutdown_cleanup() {
    let mut sys = MockSys::new(1024 * 1024);
    sys.fail_config_read = true;

    let err = run_extractor_init(&mut sys, None).unwrap_err();
    assert!(matches!(
        err,
        InitError::Io {
            context: "read config file",
            ..
        }
    ));
    assert!(sys.sync_called);
    assert!(sys.poweroff_called);
}

#[test]
fn end_to_end_extractor_init_success() {
    let tmp = tempfile::tempdir().unwrap();
    let base_dir = tmp.path().join("base");
    let overlay_dir = tmp.path().join("overlay");
    let upper_dir = overlay_dir.join("upper");
    let work_dir = overlay_dir.join("work");
    let merged_dir = tmp.path().join("merged");

    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    std::fs::create_dir_all(&merged_dir).unwrap();

    std::fs::write(base_dir.join("unchanged.txt"), b"same content\n").unwrap();
    std::fs::write(base_dir.join("mod.py"), b"def f(): return 1\n").unwrap();

    std::fs::write(merged_dir.join("unchanged.txt"), b"same content\n").unwrap();
    std::fs::write(merged_dir.join("mod.py"), b"def f(): return 2\n").unwrap();
    std::fs::write(merged_dir.join("new.txt"), b"fresh new file\n").unwrap();

    let mut sys = MockSys::new(1024 * 1024);
    let test_nonce = [0x77; 32];
    let config = ExtractorConfig {
        base_mount: base_dir.to_str().unwrap().to_string(),
        merged_mount: merged_dir.to_str().unwrap().to_string(),
        overlay_mount: overlay_dir.to_str().unwrap().to_string(),
        nonce: test_nonce,
        ..ExtractorConfig::default()
    };

    let report = run_extractor_init(&mut sys, Some(config)).unwrap();
    assert!(sys.sync_called);
    assert!(sys.poweroff_called);
    assert!(report.skipped.is_empty());

    // Validate the drive output
    let drive_data = sys.output_buffer.to_vec();
    let (header, stream_payload) =
        hermetic_extract::disk::parse_and_validate_disk(&drive_data, &test_nonce, 10 * 1024 * 1024)
            .unwrap();
    assert_eq!(header.magic, *EXTRACT_DISK_MAGIC);
    assert_eq!(header.version, EXTRACT_DISK_VERSION);
    assert_eq!(header.failure_code, 0);
    assert_eq!(header.nonce, test_nonce);
    assert!(header.payload_len > 0);
    assert_eq!(header.payload_len as usize, stream_payload.len());

    // Validate that stream payload starts with HEXT v1 header
    assert!(stream_payload.starts_with(b"HEXT\x01\x00\x00\x00"));
}

#[test]
fn overlay_upper_symlink_refused() {
    // Regression test for Defect B: symlinked upper component must fail closed with MountError
    let tmp = tempfile::tempdir().unwrap();
    let base_dir = tmp.path().join("base");
    let overlay_dir = tmp.path().join("overlay");
    let fake_target = tmp.path().join("fake_upper");
    let work_dir = overlay_dir.join("work");
    let merged_dir = tmp.path().join("merged");

    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&overlay_dir).unwrap();
    std::fs::create_dir_all(&fake_target).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    std::fs::create_dir_all(&merged_dir).unwrap();

    // Create upper as symlink to fake_target
    std::os::unix::fs::symlink(&fake_target, overlay_dir.join("upper")).unwrap();

    let mut sys = MockSys::new(1024 * 1024);
    let config = ExtractorConfig {
        base_mount: base_dir.to_str().unwrap().to_string(),
        merged_mount: merged_dir.to_str().unwrap().to_string(),
        overlay_mount: overlay_dir.to_str().unwrap().to_string(),
        ..ExtractorConfig::default()
    };

    let err = run_extractor_init(&mut sys, Some(config)).unwrap_err();
    assert!(matches!(
        err,
        InitError::Mount {
            step: "overlay_layout",
            ..
        }
    ));
    assert_eq!(err.to_failure_code(), ExtractFailureCode::MountError);

    // Verify output drive recorded MountError header
    let drive_data = sys.output_buffer.to_vec();
    let header = ExtractDiskHeader::decode(&drive_data).unwrap();
    assert_eq!(header.failure_code, ExtractFailureCode::MountError.as_raw());
}

#[test]
fn overlay_work_symlink_refused() {
    // Regression test for Defect B: symlinked work component must fail closed with MountError
    let tmp = tempfile::tempdir().unwrap();
    let base_dir = tmp.path().join("base");
    let overlay_dir = tmp.path().join("overlay");
    let upper_dir = overlay_dir.join("upper");
    let fake_target = tmp.path().join("fake_work");
    let merged_dir = tmp.path().join("merged");

    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&fake_target).unwrap();
    std::fs::create_dir_all(&merged_dir).unwrap();

    // Create work as symlink to fake_target
    std::os::unix::fs::symlink(&fake_target, overlay_dir.join("work")).unwrap();

    let mut sys = MockSys::new(1024 * 1024);
    let config = ExtractorConfig {
        base_mount: base_dir.to_str().unwrap().to_string(),
        merged_mount: merged_dir.to_str().unwrap().to_string(),
        overlay_mount: overlay_dir.to_str().unwrap().to_string(),
        ..ExtractorConfig::default()
    };

    let err = run_extractor_init(&mut sys, Some(config)).unwrap_err();
    assert!(matches!(
        err,
        InitError::Mount {
            step: "overlay_layout",
            ..
        }
    ));
    assert_eq!(err.to_failure_code(), ExtractFailureCode::MountError);
}

#[test]
fn overlay_missing_upper_fails_closed() {
    // Regression test for Defect C: missing upper directory must fail closed with MountError,
    // NEVER falling back to using overlay root as lowerdir.
    let tmp = tempfile::tempdir().unwrap();
    let base_dir = tmp.path().join("base");
    let overlay_dir = tmp.path().join("overlay");
    let work_dir = overlay_dir.join("work");
    let merged_dir = tmp.path().join("merged");

    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&overlay_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    std::fs::create_dir_all(&merged_dir).unwrap();

    let mut sys = MockSys::new(1024 * 1024);
    let config = ExtractorConfig {
        base_mount: base_dir.to_str().unwrap().to_string(),
        merged_mount: merged_dir.to_str().unwrap().to_string(),
        overlay_mount: overlay_dir.to_str().unwrap().to_string(),
        ..ExtractorConfig::default()
    };

    let err = run_extractor_init(&mut sys, Some(config)).unwrap_err();
    assert!(matches!(
        err,
        InitError::Mount {
            step: "overlay_layout",
            ..
        }
    ));
    assert_eq!(err.to_failure_code(), ExtractFailureCode::MountError);
}

#[test]
fn config_file_read_error_other_than_not_found_fails_closed() {
    // Regression test for Defect D: config file read error other than NotFound must fail closed
    let mut sys = MockSys::new(1024 * 1024);
    sys.fail_config_read = true;

    let err = run_extractor_init(&mut sys, None).unwrap_err();
    assert!(matches!(
        err,
        InitError::Io {
            context: "read config file",
            ..
        }
    ));
    assert_eq!(err.to_failure_code(), ExtractFailureCode::IoError);
}

#[test]
fn initial_in_progress_failure_header_written_before_steps() {
    // Regression test for Defect E(3): in-progress header must be written to disk before any other step
    let mut sys = MockSys::new(1024 * 1024);
    sys.check_in_progress_in_mount_dev = true;

    let _ = run_extractor_init(&mut sys, None);
    assert_eq!(
        sys.seen_in_progress_code.get(),
        Some(ExtractFailureCode::InProgress.as_raw())
    );
}

#[test]
fn alt_config_file_loaded_if_default_not_found() {
    let mut sys = MockSys::new(1024 * 1024);
    sys.config_file = None;
    sys.alt_config_file = Some(
        br#"{
        "task_class": "patch:",
        "base_dev": "/dev/vdc",
        "overlay_dev": "/dev/vdd",
        "output_dev": "/dev/vdb",
        "nonce": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }"#
        .to_vec(),
    );
    sys.fail_at_mount = Some("base"); // stop after config read & mount attempt

    let err = run_extractor_init(&mut sys, None).unwrap_err();
    assert!(matches!(err, InitError::Mount { step: "base", .. }));
    // Verify it mounted base with the config loaded from alt_config_file
    assert!(sys
        .mount_calls
        .iter()
        .any(|c| c.starts_with("base:/dev/vdc")));
}
