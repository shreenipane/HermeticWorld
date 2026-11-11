use std::fs::{self, File};
use std::io::Write;
use std::time::Instant;
use tempfile::tempdir;

use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity, Visibility};

const LEAK_LINE: &str = "execute_critical_container_secret_check()";

fn setup_base_and_gold() -> (tempfile::TempDir, FingerprintSet) {
    let base_dir = tempdir().expect("tempdir");
    let base_code = "def process():\n    return 42\n";
    fs::write(base_dir.path().join("service.py"), base_code).expect("write base");

    let gold_patch = format!(
        "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,3 @@\n def process():\n+    {}\n     return 42\n",
        LEAK_LINE
    );

    let fp = FingerprintSet::from_task(&gold_patch, "", base_dir.path()).expect("fp");
    (base_dir, fp)
}

fn leaked_file_content() -> String {
    format!("def process():\n    {}\n    return 42\n", LEAK_LINE)
}

#[test]
fn test_containers_leaked_file_in_various_formats() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    let content = leaked_file_content();

    // 1. zip
    {
        let target_dir = tempdir().expect("tempdir");
        let zip_path = target_dir.path().join("archive.zip");
        let file = File::create(&zip_path).expect("create zip");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("leaked.py", zip::write::SimpleFileOptions::default())
            .expect("start_file");
        zip.write_all(content.as_bytes()).expect("write");
        zip.finish().expect("finish");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Gate && f.path.contains("archive.zip!/leaked.py"))
            .collect();
        assert!(
            !gates.is_empty(),
            "zip member must gate at archive.zip!/leaked.py"
        );
    }

    // 2. tar.gz
    {
        let target_dir = tempdir().expect("tempdir");
        let targz_path = target_dir.path().join("archive.tar.gz");
        let file = File::create(&targz_path).expect("create targz");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);

        let mut header = tar::Header::new_gnu();
        header.set_path("leaked.py").expect("path");
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, content.as_bytes()).expect("append");
        tar.finish().expect("finish");
        let gz = tar.into_inner().expect("into_inner");
        gz.finish().expect("finish gz");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.severity == Severity::Gate && f.path.contains("archive.tar.gz!/leaked.py")
            })
            .collect();
        assert!(
            !gates.is_empty(),
            "tar.gz member must gate at archive.tar.gz!/leaked.py"
        );
    }

    // 3. tar.xz
    {
        let target_dir = tempdir().expect("tempdir");
        let tarxz_path = target_dir.path().join("archive.tar.xz");
        let file = File::create(&tarxz_path).expect("create tarxz");
        let xz = xz2::write::XzEncoder::new(file, 6);
        let mut tar = tar::Builder::new(xz);

        let mut header = tar::Header::new_gnu();
        header.set_path("leaked.py").expect("path");
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, content.as_bytes()).expect("append");
        tar.finish().expect("finish");
        let xz = tar.into_inner().expect("into_inner");
        xz.finish().expect("finish xz");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.severity == Severity::Gate && f.path.contains("archive.tar.xz!/leaked.py")
            })
            .collect();
        assert!(
            !gates.is_empty(),
            "tar.xz member must gate at archive.tar.xz!/leaked.py"
        );
    }

    // 4. tar.bz2
    {
        let target_dir = tempdir().expect("tempdir");
        let tarbz2_path = target_dir.path().join("archive.tar.bz2");
        let file = File::create(&tarbz2_path).expect("create tarbz2");
        let bz = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
        let mut tar = tar::Builder::new(bz);

        let mut header = tar::Header::new_gnu();
        header.set_path("leaked.py").expect("path");
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, content.as_bytes()).expect("append");
        tar.finish().expect("finish");
        let bz = tar.into_inner().expect("into_inner");
        bz.finish().expect("finish bz");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.severity == Severity::Gate && f.path.contains("archive.tar.bz2!/leaked.py")
            })
            .collect();
        assert!(
            !gates.is_empty(),
            "tar.bz2 member must gate at archive.tar.bz2!/leaked.py"
        );
    }

    // 5. .zst
    {
        let target_dir = tempdir().expect("tempdir");
        let zst_path = target_dir.path().join("leaked.py.zst");
        let file = File::create(&zst_path).expect("create zst");
        let mut encoder = zstd::stream::write::Encoder::new(file, 0).expect("encoder");
        encoder.write_all(content.as_bytes()).expect("write");
        encoder.finish().expect("finish");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Gate && f.path.contains("leaked.py.zst!/leaked.py"))
            .collect();
        assert!(
            !gates.is_empty(),
            "zst member must gate at leaked.py.zst!/leaked.py"
        );
    }

    // 6. zip nested inside tar.gz at depth 2
    {
        let target_dir = tempdir().expect("tempdir");
        let mut zip_bytes = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            zip.start_file("nested.py", zip::write::SimpleFileOptions::default())
                .expect("start_file");
            zip.write_all(content.as_bytes()).expect("write");
            zip.finish().expect("finish");
        }

        let targz_path = target_dir.path().join("outer.tar.gz");
        let file = File::create(&targz_path).expect("create targz");
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);

        let mut header = tar::Header::new_gnu();
        header.set_path("inner.zip").expect("path");
        header.set_size(zip_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &zip_bytes[..]).expect("append");
        tar.finish().expect("finish");
        let gz = tar.into_inner().expect("into_inner");
        gz.finish().expect("finish gz");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.severity == Severity::Gate
                    && f.path.contains("outer.tar.gz!/inner.zip!/nested.py")
            })
            .collect();
        assert!(
            !gates.is_empty(),
            "nested zip inside tar.gz must gate at outer.tar.gz!/inner.zip!/nested.py"
        );
    }
}

#[test]
fn test_containers_depth_limit() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        max_depth: 4,
        ..Default::default()
    };
    let content = leaked_file_content();

    // Create 6 levels of nesting: level0 -> level1 -> level2 -> level3 -> level4 -> level5
    // Container at depth 5 must not be opened and give container_depth info finding
    let mut current_bytes = content.into_bytes();
    for d in (1..=6).rev() {
        let mut zip_bytes = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            zip.start_file(
                format!("level{}.zip", d),
                zip::write::SimpleFileOptions::default(),
            )
            .expect("start_file");
            zip.write_all(&current_bytes).expect("write");
            zip.finish().expect("finish");
        }
        current_bytes = zip_bytes;
    }

    let target_dir = tempdir().expect("tempdir");
    fs::write(target_dir.path().join("root.zip"), current_bytes).expect("write root.zip");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let depth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.channel == "container_depth" && f.severity == Severity::Info)
        .collect();

    assert!(
        !depth_findings.is_empty(),
        "depth 5 container must emit container_depth info finding"
    );
}

#[test]
fn test_containers_gzip_bomb_limit() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        max_member_bytes: 256 * 1024 * 1024, // 256 MiB
        ..Default::default()
    };

    let target_dir = tempdir().expect("tempdir");
    let bomb_path = target_dir.path().join("bomb.gz");
    let file = File::create(&bomb_path).expect("create bomb");
    let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::best());

    // Stream 300 MiB of zeros using a small 64 KiB buffer
    let zeros = [0u8; 64 * 1024];
    for _ in 0..4800 {
        gz.write_all(&zeros).expect("write zeros");
    }
    gz.finish().expect("finish bomb");

    let start = Instant::now();
    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "gzip bomb scan must finish in under 5 seconds, took {:?}",
        elapsed
    );

    let bomb_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.channel == "container_bomb" && f.severity == Severity::Review)
        .collect();

    assert!(
        !bomb_findings.is_empty(),
        "gzip bomb must produce container_bomb finding"
    );
}

#[test]
fn test_containers_corrupt_zip() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let target_dir = tempdir().expect("tempdir");
    fs::write(
        target_dir.path().join("corrupted.zip"),
        b"PK\x03\x04corrupted-archive-garbage-content",
    )
    .expect("write corrupt");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let corrupt_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.channel == "container_error" && f.severity == Severity::Info)
        .collect();

    assert!(
        !corrupt_findings.is_empty(),
        "corrupt zip must produce container_error info finding"
    );
}

#[test]
fn test_containers_sqlite_db_text_cell() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let target_dir = tempdir().expect("tempdir");
    let db_path = target_dir.path().join("data.db");

    let conn = rusqlite::Connection::open(&db_path).expect("open sqlite");
    conn.execute(
        "CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, details TEXT)",
        [],
    )
    .expect("create table");

    let content = leaked_file_content();
    conn.execute(
        "INSERT INTO audit_logs (id, details) VALUES (?1, ?2)",
        rusqlite::params![1, content],
    )
    .expect("insert leaked");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains("data.db::audit_logs#1"))
        .collect();

    assert!(
        !gates.is_empty(),
        "SQLite db row with leak must gate at <db>::<table>#<rowid>, got: {:?}",
        findings
    );
}
