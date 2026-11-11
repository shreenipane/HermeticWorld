use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
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

#[test]
fn test_h1_pack_text_file_is_scanned_gives_gate() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    let target_dir = tempdir().expect("tempdir");
    let file_path = target_dir.path().join("setup.py");
    let content = format!("PACKAGE_NAME = 1\n{}", leaked_file_content());
    fs::write(&file_path, content).expect("write file");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains("setup.py"))
        .collect();
    assert!(
        !gates.is_empty(),
        "file whose first line is PACKAGE_NAME = 1 containing leak must give a gate"
    );
}

#[test]
fn test_h2_fake_tar_and_targz_and_v7_tar() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    let content = leaked_file_content();
    let mut large_text = format!("# Padding line {}\n", 0).repeat(30);
    large_text.push_str(&content);
    assert!(large_text.len() > 512);

    // 1. Text file named x.tar (over 512 bytes) gives a gate
    {
        let target_dir = tempdir().expect("tempdir");
        let path = target_dir.path().join("x.tar");
        fs::write(&path, &large_text).expect("write x.tar");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Gate && f.path.ends_with("x.tar"))
            .collect();
        assert!(
            !gates.is_empty(),
            "leak in text file named x.tar must give a gate"
        );
    }

    // 2. Gzipped text leak named x.tar.gz gives a gate
    {
        let target_dir = tempdir().expect("tempdir");
        let path = target_dir.path().join("x.tar.gz");
        let file = File::create(&path).expect("create gz");
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        gz.write_all(large_text.as_bytes()).expect("write gz");
        gz.finish().expect("finish gz");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Gate && f.path.contains("x.tar.gz!/"))
            .collect();
        assert!(
            !gates.is_empty(),
            "gzipped text leak named x.tar.gz must give a gate"
        );
    }

    // 3. v7 tar with no ustar magic still gives a gate at its !/ member path
    {
        let target_dir = tempdir().expect("tempdir");
        let path = target_dir.path().join("v7.tar");
        let file = File::create(&path).expect("create v7.tar");
        let mut tar = tar::Builder::new(file);

        let mut header = tar::Header::new_old();
        header.set_path("leaked.py").expect("path");
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, content.as_bytes()).expect("append");
        tar.finish().expect("finish");

        // Verify v7 header has no "ustar" at offset 257
        let tar_bytes = fs::read(&path).expect("read v7.tar");
        assert_ne!(&tar_bytes[257..262], b"ustar");

        let findings = scan_tree(target_dir.path(), &fp, &opts);
        let gates: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Gate && f.path.contains("v7.tar!/leaked.py"))
            .collect();
        assert!(
            !gates.is_empty(),
            "v7 tar with no ustar magic must give a gate at its !/ member path"
        );
    }
}

#[test]
fn test_h3_pyc_check_crlf_text_gives_gate() {
    let base_dir = tempdir().expect("tempdir");
    let base_code = "def f():\n    return 1\n";
    fs::write(base_dir.path().join("service.py"), base_code).expect("write base");

    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,3 @@\n def f():\n+    execute_leak()\n     return 1\n";
    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let target_dir = tempdir().expect("tempdir");
    let file_path = target_dir.path().join("crlf_test.py");
    // "ab\r\n" is 4 bytes. "execute_leak()" starts at offset 4 (within first 16 bytes).
    let content = "ab\r\nexecute_leak()\r\ndef f():\r\n    return 1\r\n";
    fs::write(&file_path, content).expect("write crlf_test.py");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.ends_with("crlf_test.py"))
        .collect();
    assert!(
        !gates.is_empty(),
        "CRLF file starting with ab\\r\\n with short fixed line in first 16 bytes must give a gate"
    );
}

#[test]
fn test_h5_tar_contiguous_member_gives_gate() {
    let (_base_dir, fp) = setup_base_and_gold();
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    let content = leaked_file_content();

    let target_dir = tempdir().expect("tempdir");
    let path = target_dir.path().join("contiguous.tar");
    let file = File::create(&path).expect("create contiguous.tar");
    let mut tar = tar::Builder::new(file);

    let mut header = tar::Header::new_gnu();
    header.set_path("leaked.py").expect("path");
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::contiguous());
    header.set_cksum();
    tar.append(&header, content.as_bytes()).expect("append");
    tar.finish().expect("finish");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains("contiguous.tar!/leaked.py"))
        .collect();
    assert!(
        !gates.is_empty(),
        "contiguous tar member holding leak must give a gate"
    );
}

#[test]
fn test_h6_sqlite_escaping_and_multiline_and_sqliteleak() {
    let base_dir = tempdir().expect("tempdir");
    let base_code = "def process():\n    return 42\n";
    fs::write(base_dir.path().join("service.py"), base_code).expect("write base");

    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,4 @@\n def process():\n+    line_alpha_secret_token_123()\n+    line_beta_secret_token_456()\n     return 42\n";
    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let target_dir = tempdir().expect("tempdir");
    let db_path = target_dir.path().join("test.db");
    let conn = rusqlite::Connection::open(&db_path).expect("open sqlite");

    // Table 1: named we"ird with leak
    conn.execute(
        r#"CREATE TABLE "we""ird" (id INTEGER PRIMARY KEY, code TEXT)"#,
        [],
    )
    .expect("create we\"ird");
    let code_content =
        "def process():\n    line_alpha_secret_token_123()\n    line_beta_secret_token_456()\n    return 42\n";
    conn.execute(
        r#"INSERT INTO "we""ird" (id, code) VALUES (1, ?1)"#,
        [code_content],
    )
    .expect("insert we\"ird");

    // Table 2: named sqliteleak with leak
    conn.execute(
        r#"CREATE TABLE sqliteleak (id INTEGER PRIMARY KEY, code TEXT)"#,
        [],
    )
    .expect("create sqliteleak");
    conn.execute(
        r#"INSERT INTO sqliteleak (id, code) VALUES (1, ?1)"#,
        [code_content],
    )
    .expect("insert sqliteleak");

    // Table 3: row with fixed lines in two separate columns
    conn.execute(
        r#"CREATE TABLE multicol (id INTEGER PRIMARY KEY, col1 TEXT, col2 TEXT)"#,
        [],
    )
    .expect("create multicol");
    conn.execute(
        r#"INSERT INTO multicol (id, col1, col2) VALUES (1, ?1, ?2)"#,
        [
            &"line_alpha_secret_token_123()".to_string(),
            &"line_beta_secret_token_456()".to_string(),
        ],
    )
    .expect("insert multicol");

    let findings = scan_tree(target_dir.path(), &fp, &opts);

    // 1. Check table we"ird gate
    let weird_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains(r#"test.db::we"ird#1"#))
        .collect();
    assert!(
        !weird_gates.is_empty(),
        "table named we\"ird holding fixed lines must give gate at test.db::we\"ird#1"
    );

    // 2. Check table sqliteleak gate
    let sqliteleak_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains("test.db::sqliteleak#1"))
        .collect();
    assert!(
        !sqliteleak_gates.is_empty(),
        "table named sqliteleak holding fixed lines must give gate at test.db::sqliteleak#1"
    );

    // 3. Check multicol gate
    let multicol_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains("test.db::multicol#1"))
        .collect();
    assert!(
        !multicol_gates.is_empty(),
        "row with fixed lines across two separate columns joined by \\n must give gate"
    );
}

#[test]
fn test_h7_d9_path_checks_exclude_scan_root() {
    let fp = FingerprintSet::from_task("", "", Path::new("/tmp")).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // Tempdir whose name contains "swebench"
    let temp_root = tempfile::Builder::new()
        .prefix("swebench-eval-dir-")
        .tempdir()
        .expect("tempdir");

    // Clean file
    let clean_dir = temp_root.path().join("my_project");
    fs::create_dir_all(&clean_dir).expect("mkdir");
    let clean_file = clean_dir.join("clean.py");
    fs::write(&clean_file, "print('clean')\n").expect("write clean");

    let findings = scan_tree(temp_root.path(), &fp, &opts);
    let d9_findings: Vec<_> = findings.iter().filter(|f| f.detector == "D9").collect();
    assert!(
        d9_findings.is_empty(),
        "clean tree under tempdir containing swebench must give 0 D9 findings, got: {:?}",
        d9_findings
    );

    // Now add root/swebench_dump/a.txt
    let dump_dir = temp_root.path().join("swebench_dump");
    fs::create_dir_all(&dump_dir).expect("mkdir dump");
    let dump_file = dump_dir.join("a.txt");
    fs::write(&dump_file, "some normal content\n").expect("write dump file");

    let findings_after = scan_tree(temp_root.path(), &fp, &opts);
    let path_gates: Vec<_> = findings_after
        .iter()
        .filter(|f| {
            f.detector == "D9" && f.channel == "dataset_path" && f.severity == Severity::Gate
        })
        .collect();
    assert!(
        !path_gates.is_empty(),
        "root/swebench_dump/a.txt still gives a dataset_path gate"
    );
    assert_eq!(
        path_gates[0].path,
        dump_file.display().to_string(),
        "finding path must be absolute"
    );
}

#[test]
fn test_h7b_large_archive_scanned_plain_file_skipped() {
    let (_base_dir, fp) = setup_base_and_gold();
    // Set max_file_bytes to 200 bytes, so test files stay tiny.
    let opts = ScanOptions {
        max_file_bytes: 200,
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };
    let content = leaked_file_content();

    let target_dir = tempdir().expect("tempdir");

    // 1. Plain file over max_file_bytes containing leak
    let plain_path = target_dir.path().join("large_plain.py");
    let padding = "# comment padding\n".repeat(20);
    let large_plain_content = format!("{}\n{}", padding, content);
    assert!(large_plain_content.len() > 200);
    fs::write(&plain_path, large_plain_content).expect("write plain");

    // 2. Zip archive over max_file_bytes containing leak
    let zip_path = target_dir.path().join("large_archive.zip");
    {
        let file = File::create(&zip_path).expect("create zip");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("leaked.py", zip::write::SimpleFileOptions::default())
            .expect("start_file");
        zip.write_all(content.as_bytes()).expect("write");
        // Add padding file so zip exceeds 200 bytes
        zip.start_file("pad.txt", zip::write::SimpleFileOptions::default())
            .expect("start_file pad");
        zip.write_all(padding.as_bytes()).expect("write pad");
        zip.finish().expect("finish zip");
    }
    let zip_size = fs::metadata(&zip_path).expect("meta").len();
    assert!(
        zip_size > 200,
        "zip size {} must exceed max_file_bytes 200",
        zip_size
    );

    let findings = scan_tree(target_dir.path(), &fp, &opts);

    // Plain file must get info finding
    let plain_info: Vec<_> = findings
        .iter()
        .filter(|f| f.path.ends_with("large_plain.py") && f.severity == Severity::Info)
        .collect();
    assert!(
        !plain_info.is_empty(),
        "plain file over max_file_bytes must give info finding"
    );

    // Plain file must NOT give gate
    let plain_gate: Vec<_> = findings
        .iter()
        .filter(|f| f.path.ends_with("large_plain.py") && f.severity == Severity::Gate)
        .collect();
    assert!(
        plain_gate.is_empty(),
        "plain file over max_file_bytes must NOT give gate"
    );

    // Archive over max_file_bytes must give gate on leaked member
    let archive_gate: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.path.contains("large_archive.zip!/leaked.py"))
        .collect();
    assert!(
        !archive_gate.is_empty(),
        "archive over max_file_bytes holding leak must be opened and give gate"
    );
}

#[test]
fn test_h4_extract_pyc_constants_old_pyc_offset() {
    // 1. Python 3.6 pyc (magic 3379 -> 12-byte header)
    let mut pyc_12 = Vec::new();
    pyc_12.extend_from_slice(&3379u16.to_le_bytes());
    pyc_12.extend_from_slice(&[0x0d, 0x0a]);
    pyc_12.extend_from_slice(&1000u32.to_le_bytes()); // mtime (4..8)
    pyc_12.extend_from_slice(&500u32.to_le_bytes()); // size (8..12)
    pyc_12.extend_from_slice(b"secret_py36_constant"); // offset 12
    let extracted_12 = hermetic_sealcheck::extract_pyc_constants(&pyc_12);
    assert!(
        extracted_12.contains("secret_py36_constant"),
        "12-byte pyc must extract constants starting from offset 12, got: {}",
        extracted_12
    );

    // 2. Python 2.7 pyc (magic 62211 -> 8-byte header)
    let mut pyc_8 = Vec::new();
    pyc_8.extend_from_slice(&62211u16.to_le_bytes());
    pyc_8.extend_from_slice(&[0x0d, 0x0a]);
    pyc_8.extend_from_slice(&2000u32.to_le_bytes()); // mtime (4..8)
    pyc_8.extend_from_slice(b"secret_py27_constant"); // offset 8
    let extracted_8 = hermetic_sealcheck::extract_pyc_constants(&pyc_8);
    assert!(
        extracted_8.contains("secret_py27_constant"),
        "8-byte pyc must extract constants starting from offset 8, got: {}",
        extracted_8
    );

    // 3. Invalid magic .pyc extracts from offset 0
    let invalid_pyc = b"secret_from_offset_zero";
    let extracted_inv = hermetic_sealcheck::extract_pyc_constants(invalid_pyc);
    assert!(
        extracted_inv.contains("secret_from_offset_zero"),
        "invalid magic pyc must extract constants starting from offset 0, got: {}",
        extracted_inv
    );
}
