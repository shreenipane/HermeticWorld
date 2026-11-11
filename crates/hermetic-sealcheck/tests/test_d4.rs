use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;

use hermetic_sealcheck::ext4::{scan_ext4_image, scan_ext4_slice};
use hermetic_sealcheck::index::{
    query_index, write_index, IndexReader, IndexRecord, FORMAT_VERSION,
};
use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity, Visibility};

const T_CLOCK_SECS: i64 = 1_704_153_600; // 2024-01-02T00:00:00Z
const FIXED_UUID: &str = "00000000-0000-0000-0000-000000000001";

fn t_clock() -> OffsetDateTime {
    datetime!(2024-01-02 00:00:00 UTC)
}

fn empty_fp(dir: &Path) -> FingerprintSet {
    FingerprintSet::from_task("", "", &dir.join("nonexistent")).expect("fp")
}

// =======================================================================================
// Part A: Live tree tests
// =======================================================================================

#[test]
fn test_live_tree_file_mtimes() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let clean_path = root.join("clean.txt");
    fs::write(&clean_path, "clean file\n").expect("write clean");
    let exact_time = SystemTime::UNIX_EPOCH + Duration::from_secs(T_CLOCK_SECS as u64);
    File::open(&clean_path)
        .expect("open clean")
        .set_modified(exact_time)
        .expect("set modified exact");

    let late_path = root.join("late.txt");
    fs::write(&late_path, "late file\n").expect("write late");
    let late_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 1) as u64);
    File::open(&late_path)
        .expect("open late")
        .set_modified(late_time)
        .expect("set modified late");

    // Backdate root directory so root itself does not gate
    if let Ok(f) = File::open(root) {
        let _ = f.set_modified(exact_time);
    }

    let fp = empty_fp(root);
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(root, &fp, &opts);
    let d4_findings: Vec<_> = findings.iter().filter(|f| f.detector == "D4").collect();

    assert_eq!(
        d4_findings.len(),
        1,
        "expected exactly 1 D4 finding for late file, got: {d4_findings:#?}"
    );
    let f = d4_findings[0];
    assert_eq!(f.channel, "mtime");
    assert_eq!(f.severity, Severity::Gate);
    assert!(f.path.ends_with("late.txt"));
    assert!(f.evidence[0].contains("mtime 2024-01-02T00:00:01Z > T_clock 2024-01-02T00:00:00Z"));
}

#[test]
fn test_live_tree_directory_late_mtime_gates() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let sub_dir = root.join("subfolder");
    fs::create_dir_all(&sub_dir).expect("mkdir");
    let f_path = sub_dir.join("file.txt");
    fs::write(&f_path, "sub file\n").expect("write file");

    let early_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS - 10) as u64);
    File::open(&f_path)
        .expect("open")
        .set_modified(early_time)
        .expect("set_modified");

    let late_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 5) as u64);
    // Setting modified on directory
    if let Ok(dir_f) = File::open(&sub_dir) {
        let _ = dir_f.set_modified(late_time);
    } else {
        println!("skipping directory set_modified on platform that cannot open dir as File");
        return;
    }

    // Backdate root
    if let Ok(f) = File::open(root) {
        let _ = f.set_modified(early_time);
    }

    let fp = empty_fp(root);
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(root, &fp, &opts);
    let d4_dir: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.path.ends_with("subfolder"))
        .collect();
    assert_eq!(
        d4_dir.len(),
        1,
        "directory with late mtime must gate: {findings:#?}"
    );
    assert_eq!(d4_dir[0].channel, "mtime");
    assert_eq!(d4_dir[0].severity, Severity::Gate);
}

#[test]
fn test_live_tree_symlink_late_mtime() {
    // Note: Rust std does not expose a way to set mtime directly on a symlink without
    // following it (File::open follows symlinks to the target).
    // However, when a symlink is freshly created at test time, its mtime is "now" (~2026),
    // which is later than T_clock (2024-01-02).
    // We backdate the target file to before T_clock, so only the symlink's own mtime
    // (inspected via symlink_metadata) is late.
    #[cfg(unix)]
    {
        let d = tempdir().expect("tempdir");
        let root = d.path();

        let target = root.join("target.txt");
        fs::write(&target, "target content\n").expect("write target");
        let early_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS - 10) as u64);
        File::open(&target)
            .expect("open")
            .set_modified(early_time)
            .expect("set modified target");

        let link = root.join("link_to_target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        // Backdate root directory
        if let Ok(f) = File::open(root) {
            let _ = f.set_modified(early_time);
        }

        let fp = empty_fp(root);
        let opts = ScanOptions {
            visibility: Visibility::AgentVisible,
            t_clock: Some(t_clock()),
            ..Default::default()
        };

        let findings = scan_tree(root, &fp, &opts);
        let link_d4: Vec<_> = findings
            .iter()
            .filter(|f| f.detector == "D4" && f.path.ends_with("link_to_target"))
            .collect();
        assert_eq!(
            link_d4.len(),
            1,
            "symlink with late mtime must gate via symlink_metadata: {findings:#?}"
        );
        assert_eq!(link_d4[0].channel, "mtime");
        assert_eq!(link_d4[0].severity, Severity::Gate);
    }
}

// =======================================================================================
// Archive member tests (tar and zip)
// =======================================================================================

#[test]
fn test_tar_archive_member_times() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let tar_path = root.join("test.tar");
    let file = File::create(&tar_path).expect("create tar");
    let mut tar = tar::Builder::new(file);

    // Early member: T_clock - 100s
    let early_content = b"early member";
    let mut h1 = tar::Header::new_gnu();
    h1.set_path("early.txt").expect("path");
    h1.set_size(early_content.len() as u64);
    h1.set_mode(0o644);
    h1.set_mtime((T_CLOCK_SECS - 100) as u64);
    h1.set_cksum();
    tar.append(&h1, &early_content[..]).expect("append early");

    // Late member: T_clock + 1s
    let late_content = b"late member";
    let mut h2 = tar::Header::new_gnu();
    h2.set_path("late.txt").expect("path");
    h2.set_size(late_content.len() as u64);
    h2.set_mode(0o644);
    h2.set_mtime((T_CLOCK_SECS + 1) as u64);
    h2.set_cksum();
    tar.append(&h2, &late_content[..]).expect("append late");

    tar.finish().expect("finish");

    // Backdate tar file itself and root
    let early_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS - 100) as u64);
    File::open(&tar_path)
        .expect("open")
        .set_modified(early_time)
        .expect("set modified");
    if let Ok(f) = File::open(root) {
        let _ = f.set_modified(early_time);
    }

    let fp = empty_fp(root);
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(root, &fp, &opts);
    let member_d4: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.channel == "member_mtime")
        .collect();

    assert_eq!(
        member_d4.len(),
        1,
        "tar late member must gate: {member_d4:#?}"
    );
    assert!(member_d4[0].path.ends_with("test.tar!/late.txt"));
    assert_eq!(member_d4[0].severity, Severity::Gate);
}

#[test]
fn test_zip_archive_member_times() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let zip_path = root.join("test.zip");
    let file = File::create(&zip_path).expect("create zip");
    let mut zip = zip::ZipWriter::new(file);

    // Early member: 2024-01-01 12:00:00 (treated as UTC)
    let early_dt = zip::DateTime::from_date_and_time(2024, 1, 1, 12, 0, 0).expect("dt");
    let opt_early = zip::write::SimpleFileOptions::default().last_modified_time(early_dt);
    zip.start_file("early.txt", opt_early).expect("start early");
    zip.write_all(b"early zip content").expect("write");

    // Late member: 2024-01-03 12:00:00 (treated as UTC)
    let late_dt = zip::DateTime::from_date_and_time(2024, 1, 3, 12, 0, 0).expect("dt");
    let opt_late = zip::write::SimpleFileOptions::default().last_modified_time(late_dt);
    zip.start_file("late.txt", opt_late).expect("start late");
    zip.write_all(b"late zip content").expect("write");

    zip.finish().expect("finish");

    // Backdate zip file itself and root
    let early_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS - 100) as u64);
    File::open(&zip_path)
        .expect("open")
        .set_modified(early_time)
        .expect("set modified");
    if let Ok(f) = File::open(root) {
        let _ = f.set_modified(early_time);
    }

    let fp = empty_fp(root);
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(root, &fp, &opts);
    let member_d4: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.channel == "member_mtime")
        .collect();

    assert_eq!(
        member_d4.len(),
        1,
        "zip late member must gate: {member_d4:#?}"
    );
    assert!(member_d4[0].path.ends_with("test.zip!/late.txt"));
    assert_eq!(member_d4[0].severity, Severity::Gate);
}

// =======================================================================================
// Part B: Index round-trip and query equivalence
// =======================================================================================

#[test]
fn test_index_round_trip_member_time_and_query_equivalence() {
    let d = tempdir().expect("tempdir");
    let root = d.path().join("tree");
    fs::create_dir_all(&root).expect("mkdir");

    // 1. Clean loose file
    let clean_path = root.join("clean.txt");
    fs::write(&clean_path, "clean\n").expect("write");
    let early_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS - 50) as u64);
    File::open(&clean_path)
        .expect("open")
        .set_modified(early_time)
        .expect("set_modified");

    // 2. Late loose file
    let late_path = root.join("late.txt");
    fs::write(&late_path, "late\n").expect("write");
    let late_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 2) as u64);
    File::open(&late_path)
        .expect("open")
        .set_modified(late_time)
        .expect("set_modified");

    // 3. Tar archive with early and late members
    let tar_path = root.join("archive.tar");
    {
        let file = File::create(&tar_path).expect("create tar");
        let mut tar = tar::Builder::new(file);

        let early_content = b"early member";
        let mut h1 = tar::Header::new_gnu();
        h1.set_path("early.txt").expect("path");
        h1.set_size(early_content.len() as u64);
        h1.set_mode(0o644);
        h1.set_mtime((T_CLOCK_SECS - 100) as u64);
        h1.set_cksum();
        tar.append(&h1, &early_content[..]).expect("append");

        let late_content = b"late member";
        let mut h2 = tar::Header::new_gnu();
        h2.set_path("late.txt").expect("path");
        h2.set_size(late_content.len() as u64);
        h2.set_mode(0o644);
        h2.set_mtime((T_CLOCK_SECS + 5) as u64);
        h2.set_cksum();
        tar.append(&h2, &late_content[..]).expect("append");
        tar.finish().expect("finish");
    }
    File::open(&tar_path)
        .expect("open")
        .set_modified(early_time)
        .expect("set_modified");

    // 4. Zip archive with early and late members
    let zip_path = root.join("archive.zip");
    {
        let file = File::create(&zip_path).expect("create zip");
        let mut zip = zip::ZipWriter::new(file);

        let early_dt = zip::DateTime::from_date_and_time(2024, 1, 1, 10, 0, 0).expect("dt");
        zip.start_file(
            "early.txt",
            zip::write::SimpleFileOptions::default().last_modified_time(early_dt),
        )
        .expect("start");
        zip.write_all(b"early zip").expect("write");

        let late_dt = zip::DateTime::from_date_and_time(2024, 1, 4, 10, 0, 0).expect("dt");
        zip.start_file(
            "late.txt",
            zip::write::SimpleFileOptions::default().last_modified_time(late_dt),
        )
        .expect("start");
        zip.write_all(b"late zip").expect("write");
        zip.finish().expect("finish");
    }
    File::open(&zip_path)
        .expect("open")
        .set_modified(early_time)
        .expect("set_modified");

    // Backdate root directory so directories do not emit D4 findings
    if let Ok(f) = File::open(&root) {
        let _ = f.set_modified(early_time);
    }

    // Build index
    let idx_path = d.path().join("tree.hwidx");
    let stats = write_index(&root, &idx_path).expect("write index");
    assert!(stats.files >= 4);

    // Verify format version and member-time records in reader
    let mut reader = IndexReader::open(&idx_path).expect("open index");
    assert_eq!(FORMAT_VERSION, 3);

    let mut found_member_times = Vec::new();
    let root_str = reader.root().to_string();
    while let Some(rec) = reader.next_record().expect("next_record") {
        if let IndexRecord::MemberTime { path, mtime_secs } = rec {
            found_member_times.push((path.display(&root_str), mtime_secs));
        }
    }
    assert!(
        found_member_times.len() >= 4,
        "expected member times for tar and zip members, got: {found_member_times:#?}"
    );

    // Test scan vs query equivalence
    let fp = empty_fp(&root);
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let scanned_findings = scan_tree(&root, &fp, &opts);
    let queried_findings = query_index(&idx_path, &fp, &opts).expect("query index");

    let mut scan_d4: Vec<String> = scanned_findings
        .into_iter()
        .filter(|f| f.detector == "D4")
        .map(|f| format!("{}:{}:{}", f.channel, f.path, f.evidence[0]))
        .collect();
    let mut query_d4: Vec<String> = queried_findings
        .into_iter()
        .filter(|f| f.detector == "D4")
        .map(|f| format!("{}:{}:{}", f.channel, f.path, f.evidence[0]))
        .collect();

    scan_d4.sort();
    query_d4.sort();

    assert_eq!(
        scan_d4, query_d4,
        "D4 findings from scan and query must match exactly"
    );
    assert_eq!(
        scan_d4.len(),
        3,
        "expected 3 gate findings (1 file + 2 archive members): {scan_d4:#?}"
    );
}

#[test]
fn test_version_2_index_still_reads() {
    let mut raw = Vec::new();
    raw.extend_from_slice(b"HWIDX1"); // magic
    raw.extend_from_slice(&2u32.to_le_bytes()); // version 2
    let root_str = "/test/root";
    raw.extend_from_slice(&(root_str.len() as u32).to_le_bytes());
    raw.extend_from_slice(root_str.as_bytes());
    let canon_root = "/test/root";
    raw.extend_from_slice(&(canon_root.len() as u32).to_le_bytes());
    raw.extend_from_slice(canon_root.as_bytes());
    raw.extend_from_slice(&1u64.to_le_bytes()); // count = 1

    let rec = IndexRecord::File {
        path: hermetic_sealcheck::index::IndexPath::Abs("/test/root/file.txt".to_string()),
        size: 100,
        mtime_secs: T_CLOCK_SECS,
        mtime_nanos: 0,
        mode: 0o644,
    };
    let mut payload = Vec::new();
    hermetic_sealcheck::index::encode_record(&rec, &mut payload);
    raw.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    raw.extend_from_slice(&payload);

    let cursor = std::io::Cursor::new(raw);
    let mut reader = IndexReader::new(cursor).expect("new reader");
    assert_eq!(reader.root(), "/test/root");
    let rec = reader.next_record().expect("next_record");
    assert!(matches!(rec, Some(IndexRecord::File { .. })));
}

// =======================================================================================
// Part C: ext4 image verification (mke2fs and hostile inputs)
// =======================================================================================

fn mke2fs_available() -> bool {
    Command::new("mke2fs").arg("-V").output().is_ok()
}

#[test]
fn test_ext4_mke2fs_suite() {
    if !mke2fs_available() {
        println!("skipping ext4 tests: mke2fs not found");
        return;
    }

    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let d = tempdir().expect("tempdir");

    // -----------------------------------------------------------------------------------
    // 1. Clean image: SOURCE_DATE_EPOCH=t, all files mtime <= t -> no gate, exit 0
    // -----------------------------------------------------------------------------------
    let clean_dir = d.path().join("clean_src");
    fs::create_dir_all(&clean_dir).expect("mkdir clean");
    let f1 = clean_dir.join("clean.txt");
    fs::write(&f1, "hello clean\n").expect("write");
    let t_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(T_CLOCK_SECS as u64);
    File::open(&f1)
        .expect("open")
        .set_modified(t_epoch)
        .expect("set_modified");
    if let Ok(f) = File::open(&clean_dir) {
        let _ = f.set_modified(t_epoch);
    }

    let clean_img = d.path().join("clean.ext4");
    let st = Command::new("mke2fs")
        .env("SOURCE_DATE_EPOCH", format!("{T_CLOCK_SECS}"))
        .arg("-q")
        .arg("-t")
        .arg("ext4")
        .arg("-d")
        .arg(&clean_dir)
        .arg("-U")
        .arg(FIXED_UUID)
        .arg("-E")
        .arg(format!("hash_seed={FIXED_UUID}"))
        .arg(&clean_img)
        .arg("4M")
        .status()
        .expect("mke2fs clean");
    assert!(st.success(), "mke2fs clean image creation failed");

    let clean_findings = scan_ext4_image(&clean_img, t_clock());
    let clean_gates: Vec<_> = clean_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        clean_gates.is_empty(),
        "clean image must have zero gate findings, got: {clean_gates:#?}"
    );

    // CLI d4-image clean -> exit code 0
    let clean_cli = Command::new(bin_path)
        .arg("d4-image")
        .arg("--image")
        .arg(&clean_img)
        .arg("--t-clock")
        .arg("2024-01-02T00:00:00Z")
        .status()
        .expect("run d4-image clean");
    assert_eq!(clean_cli.code(), Some(0), "clean d4-image CLI must exit 0");

    // -----------------------------------------------------------------------------------
    // 2. Late file: one file mtime > T_clock -> one inode gate, exit 2
    // -----------------------------------------------------------------------------------
    let late_dir = d.path().join("late_src");
    fs::create_dir_all(&late_dir).expect("mkdir late");
    let f_clean = late_dir.join("file_clean.txt");
    fs::write(&f_clean, "clean\n").expect("write");
    File::open(&f_clean)
        .expect("open")
        .set_modified(t_epoch)
        .expect("set_modified");

    let f_late = late_dir.join("file_late.txt");
    fs::write(&f_late, "late content\n").expect("write");
    let late_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 10) as u64);
    File::open(&f_late)
        .expect("open")
        .set_modified(late_epoch)
        .expect("set_modified");

    let late_img = d.path().join("late.ext4");
    let st_late = Command::new("mke2fs")
        .env("SOURCE_DATE_EPOCH", format!("{T_CLOCK_SECS}"))
        .arg("-q")
        .arg("-t")
        .arg("ext4")
        .arg("-d")
        .arg(&late_dir)
        .arg("-U")
        .arg(FIXED_UUID)
        .arg("-E")
        .arg(format!("hash_seed={FIXED_UUID}"))
        .arg(&late_img)
        .arg("4M")
        .status()
        .expect("mke2fs late");
    assert!(st_late.success(), "mke2fs late image creation failed");

    // mke2fs with SOURCE_DATE_EPOCH clamps file timestamps to SOURCE_DATE_EPOCH.
    // To test an ext4 image that contains a file whose mtime is after T_clock,
    // we patch that specific file's inode mtime in the image to T_CLOCK_SECS + 10.
    {
        let mut img_bytes = fs::read(&late_img).expect("read late img");
        let sb = &img_bytes[1024..2048];
        let block_size = 1024usize << u32::from_le_bytes([sb[0x18], sb[0x19], sb[0x1A], sb[0x1B]]);
        let inode_size = u16::from_le_bytes([sb[0x58], sb[0x59]]) as usize;
        let s_first_data_block =
            u32::from_le_bytes([sb[0x14], sb[0x15], sb[0x16], sb[0x17]]) as usize;
        let gdt_offset = (s_first_data_block + 1) * block_size;
        let itable_block = u32::from_le_bytes([
            img_bytes[gdt_offset + 8],
            img_bytes[gdt_offset + 9],
            img_bytes[gdt_offset + 10],
            img_bytes[gdt_offset + 11],
        ]) as usize;
        let itable_offset = itable_block * block_size;
        let inodes_per_group =
            u32::from_le_bytes([sb[0x28], sb[0x29], sb[0x2A], sb[0x2B]]) as usize;

        let mut patched = false;
        for i in 0..inodes_per_group {
            let in_off = itable_offset + i * inode_size;
            let size = u32::from_le_bytes([
                img_bytes[in_off + 4],
                img_bytes[in_off + 5],
                img_bytes[in_off + 6],
                img_bytes[in_off + 7],
            ]);
            if size == 13 {
                // file_late.txt has length 13 ("late content\n")
                let late_sec = (T_CLOCK_SECS + 10) as u32;
                img_bytes[in_off + 0x10..in_off + 0x14].copy_from_slice(&late_sec.to_le_bytes());
                if inode_size > 128 && img_bytes.len() >= in_off + 0x8C {
                    img_bytes[in_off + 0x88..in_off + 0x8C].copy_from_slice(&0u32.to_le_bytes());
                }
                patched = true;
                break;
            }
        }
        assert!(patched, "failed to locate late file inode in image");
        fs::write(&late_img, img_bytes).expect("write patched img");
    }

    let late_findings = scan_ext4_image(&late_img, t_clock());
    let inode_gates: Vec<_> = late_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.channel == "inode")
        .collect();
    assert_eq!(
        inode_gates.len(),
        1,
        "image with one late file must have exactly one inode gate: {late_findings:#?}"
    );
    assert!(inode_gates[0].path.contains("#inode/"));

    // CLI d4-image late -> exit code 2
    let late_cli = Command::new(bin_path)
        .arg("d4-image")
        .arg("--image")
        .arg(&late_img)
        .arg("--t-clock")
        .arg("2024-01-02T00:00:00Z")
        .output()
        .expect("run d4-image late");
    assert_eq!(
        late_cli.status.code(),
        Some(2),
        "late d4-image CLI must exit 2"
    );

    // SARIF format validation
    let sarif_cli = Command::new(bin_path)
        .arg("d4-image")
        .arg("--image")
        .arg(&late_img)
        .arg("--t-clock")
        .arg("2024-01-02T00:00:00Z")
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("run d4-image sarif");
    assert_eq!(sarif_cli.status.code(), Some(2));
    let sarif_val: serde_json::Value =
        serde_json::from_slice(&sarif_cli.stdout).expect("parse sarif json");
    assert_eq!(sarif_val["version"], "2.1.0");

    // -----------------------------------------------------------------------------------
    // 3. T_clock earlier than SOURCE_DATE_EPOCH -> superblock gates
    // -----------------------------------------------------------------------------------
    let early_t_clock = datetime!(2024-01-01 00:00:00 UTC); // 1 day before SOURCE_DATE_EPOCH
    let sb_findings = scan_ext4_image(&clean_img, early_t_clock);
    let sb_gates: Vec<_> = sb_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.channel == "superblock")
        .collect();
    assert!(
        !sb_gates.is_empty(),
        "T_clock earlier than SOURCE_DATE_EPOCH must trigger superblock gate: {sb_findings:#?}"
    );
    assert!(sb_gates.iter().any(|f| f.path.contains("#superblock/")));

    let early_cli = Command::new(bin_path)
        .arg("d4-image")
        .arg("--image")
        .arg(&clean_img)
        .arg("--t-clock")
        .arg("2024-01-01T00:00:00Z")
        .status()
        .expect("run d4-image early clock");
    assert_eq!(early_cli.code(), Some(2), "early clock CLI must exit 2");
}

// =======================================================================================
// Hostile images (6 specific tests)
// =======================================================================================

#[test]
fn test_ext4_hostile_truncated_superblock() {
    // Fewer than 2048 bytes (superblock starts at 1024 and needs 1024 bytes)
    let truncated = vec![0u8; 1500];
    let findings = scan_ext4_slice("truncated.img", &truncated, t_clock());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector, "D4");
    assert_eq!(findings[0].channel, "image_malformed");
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].evidence[0].contains("too small for superblock"));
}

#[test]
fn test_ext4_hostile_bad_magic() {
    let mut data = vec![0u8; 4096];
    // Offset 1024 + 0x38 = magic
    data[1024 + 0x38] = 0x34;
    data[1024 + 0x39] = 0x12; // 0x1234 instead of 0xEF53
    let findings = scan_ext4_slice("bad_magic.img", &data, t_clock());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "image_malformed");
    assert!(findings[0].evidence[0].contains("bad magic"));
}

#[test]
fn test_ext4_hostile_huge_inodes_per_group() {
    let mut data = vec![0u8; 8192];
    // Magic
    data[1024 + 0x38] = 0x53;
    data[1024 + 0x39] = 0xEF;
    // Log block size = 0 (1024)
    data[1024 + 0x18..1024 + 0x1C].copy_from_slice(&0u32.to_le_bytes());
    // Inode size = 256
    data[1024 + 0x58..1024 + 0x5A].copy_from_slice(&256u16.to_le_bytes());
    // Inodes count = 1000
    data[1024..1024 + 4].copy_from_slice(&1000u32.to_le_bytes());
    // Huge inodes per group: 0xFFFFFFFF
    data[1024 + 0x28..1024 + 0x2C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let findings = scan_ext4_slice("huge_inodes.img", &data, t_clock());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "image_malformed");
}

#[test]
fn test_ext4_hostile_group_count_past_file() {
    let mut data = vec![0u8; 4096];
    // Magic
    data[1024 + 0x38] = 0x53;
    data[1024 + 0x39] = 0xEF;
    // Log block size = 0 (1024)
    data[1024 + 0x18..1024 + 0x1C].copy_from_slice(&0u32.to_le_bytes());
    // Inode size = 128
    data[1024 + 0x58..1024 + 0x5A].copy_from_slice(&128u16.to_le_bytes());
    // Inodes count = 10, inodes per group = 10 -> group count = 1
    data[1024..1024 + 4].copy_from_slice(&10u32.to_le_bytes());
    data[1024 + 0x28..1024 + 0x2C].copy_from_slice(&10u32.to_le_bytes());
    // Blocks per group = 10, total blocks = 10 (10 * 1024 bytes > 4096)
    data[1024 + 0x20..1024 + 0x24].copy_from_slice(&10u32.to_le_bytes());
    data[1024 + 0x04..1024 + 0x08].copy_from_slice(&10u32.to_le_bytes());

    let findings = scan_ext4_slice("past_file.img", &data, t_clock());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "image_malformed");
    assert!(findings[0].evidence[0].contains("group count past the file"));
}

#[test]
fn test_ext4_hostile_descriptor_table_past_end() {
    let mut data = vec![0u8; 4096];
    // Magic
    data[1024 + 0x38] = 0x53;
    data[1024 + 0x39] = 0xEF;
    // Log block size = 0 (1024)
    data[1024 + 0x18..1024 + 0x1C].copy_from_slice(&0u32.to_le_bytes());
    // Inode size = 128
    data[1024 + 0x58..1024 + 0x5A].copy_from_slice(&128u16.to_le_bytes());
    // Inodes count = 10, inodes per group = 1 -> group count = 10
    data[1024..1024 + 4].copy_from_slice(&10u32.to_le_bytes());
    data[1024 + 0x28..1024 + 0x2C].copy_from_slice(&1u32.to_le_bytes());
    // Blocks count = 11, blocks per group = 1 -> group count = (11-1)/1 = 10
    data[1024 + 0x04..1024 + 0x08].copy_from_slice(&11u32.to_le_bytes());
    data[1024 + 0x20..1024 + 0x24].copy_from_slice(&1u32.to_le_bytes());
    // First data block = 1, so GDT is at block 2 (offset 2048)
    data[1024 + 0x14..1024 + 0x18].copy_from_slice(&1u32.to_le_bytes());
    // 64-bit feature enabled
    data[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x0080u32.to_le_bytes());
    // Descriptor size = 512 bytes (512 * 10 = 5120 bytes, offset 2048 + 5120 > 4096)
    data[1024 + 0xFE..1024 + 0x100].copy_from_slice(&512u16.to_le_bytes());

    let findings = scan_ext4_slice("desc_past_end.img", &data, t_clock());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "image_malformed");
    assert!(findings[0].evidence[0].contains("descriptor table past the end"));
}

#[test]
fn test_ext4_hostile_every_single_byte_flip_never_panics() {
    let mut baseline = vec![0u8; 8192];
    // Superblock
    baseline[1024 + 0x38] = 0x53;
    baseline[1024 + 0x39] = 0xEF; // magic
    baseline[1024 + 0x58] = 128; // inode size
    baseline[1024] = 10; // inodes count
    baseline[1024 + 0x28] = 10; // inodes per group
    baseline[1024 + 0x04] = 8; // blocks count
    baseline[1024 + 0x20] = 8; // blocks per group
    baseline[1024 + 0x14] = 1; // first data block

    let len = baseline.len().min(8192);
    for idx in 0..len {
        for flip in [0x01u8, 0x80u8, 0xFFu8] {
            baseline[idx] ^= flip;
            let _ = scan_ext4_slice("fuzz.img", &baseline, t_clock());
            baseline[idx] ^= flip; // restore
        }
    }
}
