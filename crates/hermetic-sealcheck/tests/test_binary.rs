use std::fs;
use std::process::Command;
use tempfile::tempdir;

use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity};

/// Helper to write an unsigned LEB128 integer.
fn push_varuint(buf: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut b = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if val == 0 {
            break;
        }
    }
}

/// Helper to hand-build a minimal 64-bit LE ELF file with .shstrtab and .strtab sections.
fn build_elf64_le(symbols: &[&str]) -> Vec<u8> {
    let mut elf = Vec::new();

    // 1. ELF Header (64 bytes)
    elf.extend_from_slice(b"\x7fELF"); // e_ident[0..4]
    elf.push(2); // 64-bit
    elf.push(1); // little-endian
    elf.push(1); // EV_CURRENT
    elf.extend_from_slice(&[0u8; 9]); // padding
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    let e_shoff_pos = elf.len();
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (fill later)
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum (null, .shstrtab, .strtab)
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_shstrndx (section 1)

    assert_eq!(elf.len(), 64);

    // 2. Payload for section 1 (.shstrtab)
    let shstrtab_offset = elf.len();
    let mut shstrtab_data = Vec::new();
    shstrtab_data.push(0); // initial null
    let name_shstrtab_off = shstrtab_data.len();
    shstrtab_data.extend_from_slice(b".shstrtab\0");
    let name_strtab_off = shstrtab_data.len();
    shstrtab_data.extend_from_slice(b".strtab\0");
    let shstrtab_size = shstrtab_data.len();
    elf.extend_from_slice(&shstrtab_data);

    // 3. Payload for section 2 (.strtab)
    let strtab_offset = elf.len();
    let mut strtab_data = Vec::new();
    strtab_data.push(0);
    for sym in symbols {
        strtab_data.extend_from_slice(sym.as_bytes());
        strtab_data.push(0);
    }
    let strtab_size = strtab_data.len();
    elf.extend_from_slice(&strtab_data);

    // 4. Section header table (3 entries * 64 bytes)
    let sh_table_offset = elf.len();
    elf[e_shoff_pos..e_shoff_pos + 8].copy_from_slice(&(sh_table_offset as u64).to_le_bytes());

    // Section 0: Null section
    elf.extend_from_slice(&[0u8; 64]);

    // Section 1: .shstrtab
    let mut sec1 = vec![0u8; 64];
    sec1[0..4].copy_from_slice(&(name_shstrtab_off as u32).to_le_bytes()); // sh_name
    sec1[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    sec1[24..32].copy_from_slice(&(shstrtab_offset as u64).to_le_bytes()); // sh_offset
    sec1[32..40].copy_from_slice(&(shstrtab_size as u64).to_le_bytes()); // sh_size
    elf.extend_from_slice(&sec1);

    // Section 2: .strtab
    let mut sec2 = vec![0u8; 64];
    sec2[0..4].copy_from_slice(&(name_strtab_off as u32).to_le_bytes()); // sh_name
    sec2[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    sec2[24..32].copy_from_slice(&(strtab_offset as u64).to_le_bytes()); // sh_offset
    sec2[32..40].copy_from_slice(&(strtab_size as u64).to_le_bytes()); // sh_size
    elf.extend_from_slice(&sec2);

    elf
}

/// Helper to hand-build a minimal 32-bit BE ELF file with .shstrtab and .strtab sections.
fn build_elf32_be(symbols: &[&str]) -> Vec<u8> {
    let mut elf = Vec::new();

    // 1. ELF Header (52 bytes)
    elf.extend_from_slice(b"\x7fELF"); // e_ident[0..4]
    elf.push(1); // 32-bit
    elf.push(2); // big-endian
    elf.push(1); // EV_CURRENT
    elf.extend_from_slice(&[0u8; 9]); // padding
    elf.extend_from_slice(&2u16.to_be_bytes()); // ET_EXEC
    elf.extend_from_slice(&3u16.to_be_bytes()); // EM_386
    elf.extend_from_slice(&1u32.to_be_bytes()); // EV_CURRENT
    elf.extend_from_slice(&0u32.to_be_bytes()); // e_entry
    elf.extend_from_slice(&0u32.to_be_bytes()); // e_phoff
    let e_shoff_pos = elf.len();
    elf.extend_from_slice(&0u32.to_be_bytes()); // e_shoff (fill later)
    elf.extend_from_slice(&0u32.to_be_bytes()); // e_flags
    elf.extend_from_slice(&52u16.to_be_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_be_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_be_bytes()); // e_phnum
    elf.extend_from_slice(&40u16.to_be_bytes()); // e_shentsize
    elf.extend_from_slice(&3u16.to_be_bytes()); // e_shnum
    elf.extend_from_slice(&1u16.to_be_bytes()); // e_shstrndx

    assert_eq!(elf.len(), 52);

    // 2. .shstrtab
    let shstrtab_offset = elf.len();
    let mut shstrtab_data = Vec::new();
    shstrtab_data.push(0);
    let name_shstrtab_off = shstrtab_data.len();
    shstrtab_data.extend_from_slice(b".shstrtab\0");
    let name_strtab_off = shstrtab_data.len();
    shstrtab_data.extend_from_slice(b".strtab\0");
    let shstrtab_size = shstrtab_data.len();
    elf.extend_from_slice(&shstrtab_data);

    // 3. .strtab
    let strtab_offset = elf.len();
    let mut strtab_data = Vec::new();
    strtab_data.push(0);
    for sym in symbols {
        strtab_data.extend_from_slice(sym.as_bytes());
        strtab_data.push(0);
    }
    let strtab_size = strtab_data.len();
    elf.extend_from_slice(&strtab_data);

    // 4. Section header table (3 entries * 40 bytes)
    let sh_table_offset = elf.len();
    elf[e_shoff_pos..e_shoff_pos + 4].copy_from_slice(&(sh_table_offset as u32).to_be_bytes());

    // Section 0
    elf.extend_from_slice(&[0u8; 40]);

    // Section 1: .shstrtab
    let mut sec1 = vec![0u8; 40];
    sec1[0..4].copy_from_slice(&(name_shstrtab_off as u32).to_be_bytes());
    sec1[4..8].copy_from_slice(&3u32.to_be_bytes());
    sec1[16..20].copy_from_slice(&(shstrtab_offset as u32).to_be_bytes());
    sec1[20..24].copy_from_slice(&(shstrtab_size as u32).to_be_bytes());
    elf.extend_from_slice(&sec1);

    // Section 2: .strtab
    let mut sec2 = vec![0u8; 40];
    sec2[0..4].copy_from_slice(&(name_strtab_off as u32).to_be_bytes());
    sec2[4..8].copy_from_slice(&3u32.to_be_bytes());
    sec2[16..20].copy_from_slice(&(strtab_offset as u32).to_be_bytes());
    sec2[20..24].copy_from_slice(&(strtab_size as u32).to_be_bytes());
    elf.extend_from_slice(&sec2);

    elf
}

/// Helper to build a Java class file with a Long entry (tag 5, 2 slots) before matching UTF-8 entries.
fn build_class_with_long_and_utf8(utf8_entries: &[&str]) -> Vec<u8> {
    let mut class = Vec::new();
    class.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // magic
    class.extend_from_slice(&0u16.to_be_bytes()); // minor
    class.extend_from_slice(&52u16.to_be_bytes()); // major (Java 8)

    // Constant pool count:
    // Slot 1: Long (occupies 1 and 2)
    // Slot 3..: UTF-8 entries
    let cp_count = 1 + 2 + utf8_entries.len() as u16;
    class.extend_from_slice(&cp_count.to_be_bytes());

    // Slot 1: Long (tag 5, 8 bytes)
    class.push(5);
    class.extend_from_slice(&42u64.to_be_bytes());

    // Slot 3..: Utf8 entries
    for entry in utf8_entries {
        class.push(1); // CONSTANT_Utf8
        class.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        class.extend_from_slice(entry.as_bytes());
    }

    // Remaining class fields: access_flags, this_class, super_class, interfaces, fields, methods, attrs
    class.extend_from_slice(&[0u8; 14]);
    class
}

/// Helper to build a wasm module with export names.
fn build_wasm_with_exports(exports: &[&str]) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[1, 0, 0, 0]); // version 1

    // Export section: id = 7
    let mut payload = Vec::new();
    push_varuint(&mut payload, exports.len() as u32);
    for (idx, name) in exports.iter().enumerate() {
        push_varuint(&mut payload, name.len() as u32);
        payload.extend_from_slice(name.as_bytes());
        payload.push(0); // export kind: 0 = func
        push_varuint(&mut payload, idx as u32);
    }

    wasm.push(7); // section id
    push_varuint(&mut wasm, payload.len() as u32);
    wasm.extend_from_slice(&payload);

    wasm
}

#[test]
fn test_part_a_subtraction_short_id_and_skip_rule() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();
    fs::write(
        base_tree.join("base.py"),
        "def existing_base_identifier():\n    return \"existing_base_literal\"\n",
    )
    .expect("write base");

    // Gold patch adds:
    // 1. existing_base_identifier (should be subtracted)
    // 2. "existing_base_literal" (literal content in base, should be subtracted)
    // 3. short (short identifier < 8 chars, not an item)
    // 4. "shrt" (short literal content < 8 chars, not an item)
    // 5. hunk 1: novel_identifier_one and novel_identifier_two (2 items -> kept)
    // 6. hunk 2: only novel_isolated_item (1 item -> skipped)
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,6 @@
 def foo():
+    existing_base_identifier()
+    x = "existing_base_literal"
+    short = "shrt"
+    novel_identifier_one()
+    novel_identifier_two()
@@ -10,1 +15,2 @@
 def bar():
+    novel_isolated_item()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints");

    // Verify baseline subtraction occurred
    assert!(
        fp.binary_subtracted_count >= 2,
        "items existing in base must be subtracted, got {}",
        fp.binary_subtracted_count
    );

    // Hunk 0 has 2 novel items: novel_identifier_one, novel_identifier_two
    let hunk0 = &fp.hunks[0];
    assert_eq!(hunk0.binary_items.len(), 2);
    assert!(hunk0
        .binary_items
        .contains(&"novel_identifier_one".to_string()));
    assert!(hunk0
        .binary_items
        .contains(&"novel_identifier_two".to_string()));
    assert!(!hunk0.binary_items.contains(&"short".to_string()));
    assert!(!hunk0
        .binary_items
        .contains(&"existing_base_identifier".to_string()));

    // Hunk 1 has only 1 surviving item: novel_isolated_item
    let hunk1 = &fp.hunks[1];
    assert_eq!(hunk1.binary_items.len(), 1);

    // Scan an ELF containing only hunk 1's isolated item: should produce NO findings because hunk with < 2 items is skipped!
    let scan_dir = tempdir().expect("tempdir");
    let elf_bytes = build_elf64_le(&["novel_isolated_item"]);
    fs::write(scan_dir.path().join("skipped_hunk.elf"), &elf_bytes).expect("write elf");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    assert_eq!(
        findings.len(),
        0,
        "a hunk with only 1 item must be skipped on binary tier"
    );
}

#[test]
fn test_elf_64_le_and_32_be_matching_and_clean() {
    let base_dir = tempdir().expect("tempdir");
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,3 @@
 def foo():
+    elf_leaked_func_one()
+    elf_leaked_func_two()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    let scan_dir = tempdir().expect("tempdir");

    // 1. 64-bit LE matching ELF
    let elf64_match = build_elf64_le(&["elf_leaked_func_one", "elf_leaked_func_two"]);
    fs::write(scan_dir.path().join("match64.so"), &elf64_match).expect("write match64");

    // 2. 32-bit BE matching ELF
    let elf32_match = build_elf32_be(&["elf_leaked_func_one", "elf_leaked_func_two"]);
    fs::write(scan_dir.path().join("match32.so"), &elf32_match).expect("write match32");

    // 3. Clean ELF
    let elf_clean = build_elf64_le(&["completely_clean_symbol"]);
    fs::write(scan_dir.path().join("clean.so"), &elf_clean).expect("write clean");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);

    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 2);
    assert!(gates
        .iter()
        .any(|g| g.channel == "binary_elf" && g.path.ends_with("match64.so")));
    assert!(gates
        .iter()
        .any(|g| g.channel == "binary_elf" && g.path.ends_with("match32.so")));
    assert!(!gates.iter().any(|g| g.path.ends_with("clean.so")));
}

#[test]
fn test_class_file_long_two_slot_rule() {
    let base_dir = tempdir().expect("tempdir");
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,3 @@
 def foo():
+    java_class_symbol_one()
+    java_class_symbol_two()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    let scan_dir = tempdir().expect("tempdir");
    let class_bytes =
        build_class_with_long_and_utf8(&["java_class_symbol_one", "java_class_symbol_two"]);
    fs::write(scan_dir.path().join("TestClass.class"), &class_bytes).expect("write class");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);

    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].channel, "binary_class");
}

#[test]
fn test_wasm_matching_export() {
    let base_dir = tempdir().expect("tempdir");
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,3 @@
 def foo():
+    wasm_export_func_one()
+    wasm_export_func_two()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    let scan_dir = tempdir().expect("tempdir");
    let wasm_bytes = build_wasm_with_exports(&["wasm_export_func_one", "wasm_export_func_two"]);
    fs::write(scan_dir.path().join("module.wasm"), &wasm_bytes).expect("write wasm");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);

    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].channel, "binary_wasm");
}

#[test]
fn test_minified_js_bundle() {
    let base_dir = tempdir().expect("tempdir");
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,3 @@
 def foo():
+    minified_leak_identifier_one()
+    minified_leak_identifier_two()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    let scan_dir = tempdir().expect("tempdir");
    // Create a line with >= 5000 characters containing the identifiers
    let mut long_line = "var a=1;".repeat(600);
    long_line.push_str("minified_leak_identifier_one();minified_leak_identifier_two();");
    fs::write(scan_dir.path().join("app.bundle.js"), &long_line).expect("write bundle");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);

    let d3b_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(d3b_gates.len(), 1);
    assert_eq!(d3b_gates[0].channel, "binary_minified");
}

#[test]
fn test_nested_class_in_jar_in_tar_gz() {
    let base_dir = tempdir().expect("tempdir");
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,3 @@
 def foo():
+    nested_class_target_one()
+    nested_class_target_two()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    // Hand-build class file
    let class_bytes =
        build_class_with_long_and_utf8(&["nested_class_target_one", "nested_class_target_two"]);

    // Zip into .jar
    let mut jar_cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip_writer = zip::ZipWriter::new(&mut jar_cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip_writer
            .start_file("com/example/Nested.class", options)
            .expect("start file");
        use std::io::Write;
        zip_writer.write_all(&class_bytes).expect("write class");
        zip_writer.finish().expect("finish zip");
    }
    let jar_bytes = jar_cursor.into_inner();

    // Tar into .tar
    let mut tar_bytes = Vec::new();
    {
        let mut tar_builder = tar::Builder::new(&mut tar_bytes);
        let mut header = tar::Header::new_gnu();
        header.set_size(jar_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "inner.jar", jar_bytes.as_slice())
            .expect("append jar");
        tar_builder.finish().expect("finish tar");
    }

    // Gzip into .tar.gz
    let mut gz_bytes = Vec::new();
    {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(&mut gz_bytes, Compression::default());
        encoder.write_all(&tar_bytes).expect("write tar to gz");
        encoder.finish().expect("finish gz");
    }

    let scan_dir = tempdir().expect("tempdir");
    let archive_path = scan_dir.path().join("outer.tar.gz");
    fs::write(&archive_path, &gz_bytes).expect("write outer.tar.gz");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);

    let d3b_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(d3b_gates.len(), 1);
    assert_eq!(d3b_gates[0].channel, "binary_class");
    assert!(
        d3b_gates[0]
            .path
            .contains("outer.tar.gz!/inner.jar!/com/example/Nested.class"),
        "path must reflect nested '!/' nesting: got {}",
        d3b_gates[0].path
    );
}

#[test]
fn test_whole_token_rule_printable_runs() {
    let base_dir = tempdir().expect("tempdir");
    let gold_patch = r#"diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,3 @@
 def foo():
+    target_token_one()
+    target_token_two()
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    let scan_dir = tempdir().expect("tempdir");

    // 1. Construct a wasm where data section contains only substrings with adjacent alphanumeric/_
    // "pre_target_token_one_post" and "123target_token_two456"
    let mut wasm_bad_substring = Vec::new();
    wasm_bad_substring.extend_from_slice(b"\0asm\x01\0\0\0");
    // Section 11 (data section)
    let mut data_payload = Vec::new();
    push_varuint(&mut data_payload, 1); // 1 segment
    data_payload.push(0); // active mem 0
    data_payload.extend_from_slice(&[0x41, 0, 0x0b]); // i32.const 0, end
    let bad_bytes = b"pre_target_token_one_post 123target_token_two456";
    push_varuint(&mut data_payload, bad_bytes.len() as u32);
    data_payload.extend_from_slice(bad_bytes);

    wasm_bad_substring.push(11);
    push_varuint(&mut wasm_bad_substring, data_payload.len() as u32);
    wasm_bad_substring.extend_from_slice(&data_payload);

    fs::write(scan_dir.path().join("bad_sub.wasm"), &wasm_bad_substring).expect("write wasm");

    let opts = ScanOptions::default();
    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        gates.len(),
        0,
        "substring of longer identifier must NOT match whole-token rule"
    );

    // Now test whole-token match: surrounded by spaces or punctuation
    let mut wasm_good = Vec::new();
    wasm_good.extend_from_slice(b"\0asm\x01\0\0\0");
    let mut good_payload = Vec::new();
    push_varuint(&mut good_payload, 1);
    good_payload.push(0);
    good_payload.extend_from_slice(&[0x41, 0, 0x0b]);
    let good_bytes = b"hello target_token_one! and target_token_two; done";
    push_varuint(&mut good_payload, good_bytes.len() as u32);
    good_payload.extend_from_slice(good_bytes);

    wasm_good.push(11);
    push_varuint(&mut wasm_good, good_payload.len() as u32);
    wasm_good.extend_from_slice(&good_payload);

    fs::write(scan_dir.path().join("good_sub.wasm"), &wasm_good).expect("write wasm");

    let findings_good = scan_tree(scan_dir.path(), &fp, &opts);
    let gates_good: Vec<_> = findings_good
        .iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates_good.len(), 1, "whole-token match must gate");
}

#[test]
fn test_hostile_binaries_none_may_panic() {
    let base_dir = tempdir().expect("tempdir");
    let fp = FingerprintSet::from_task("", "", base_dir.path()).expect("fp");
    let scan_dir = tempdir().expect("tempdir");
    let opts = ScanOptions::default();

    // 1. ELF section offset past the end
    let mut elf_bad_offset = build_elf64_le(&["sym1"]);
    // Corrupt section 2 offset to point way past the end
    // In our 64-bit ELF, section 2 header starts at e_shoff + 2 * 64
    let e_shoff = u64::from_le_bytes([
        elf_bad_offset[40],
        elf_bad_offset[41],
        elf_bad_offset[42],
        elf_bad_offset[43],
        elf_bad_offset[44],
        elf_bad_offset[45],
        elf_bad_offset[46],
        elf_bad_offset[47],
    ]) as usize;
    let sec2_sh_start = e_shoff + 2 * 64;
    elf_bad_offset[sec2_sh_start + 24..sec2_sh_start + 32]
        .copy_from_slice(&999999u64.to_le_bytes());
    fs::write(scan_dir.path().join("bad_offset.elf"), &elf_bad_offset).expect("write");

    // 2. Section name index past .shstrtab
    let mut elf_bad_name = build_elf64_le(&["sym1"]);
    let sec2_sh_start = e_shoff + 2 * 64;
    elf_bad_name[sec2_sh_start..sec2_sh_start + 4].copy_from_slice(&99999u32.to_le_bytes());
    fs::write(scan_dir.path().join("bad_name.elf"), &elf_bad_name).expect("write");

    // 3. ELF with 0xFFFF sections declared
    let mut elf_huge_sections = build_elf64_le(&["sym1"]);
    elf_huge_sections[60..62].copy_from_slice(&0xffffu16.to_le_bytes());
    fs::write(scan_dir.path().join("huge_shnum.elf"), &elf_huge_sections).expect("write");

    // 4. Class file with constant-pool count larger than the file
    let mut class_large_cp = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
    class_large_cp.extend_from_slice(&50000u16.to_be_bytes()); // cp_count = 50000
    class_large_cp.extend_from_slice(&[0u8; 10]);
    fs::write(scan_dir.path().join("large_cp.class"), &class_large_cp).expect("write");

    // 5. Truncated class entry
    let mut class_truncated = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
    class_truncated.extend_from_slice(&3u16.to_be_bytes()); // cp_count = 3
    class_truncated.push(1); // CONSTANT_Utf8
    class_truncated.extend_from_slice(&1000u16.to_be_bytes()); // length 1000
    class_truncated.extend_from_slice(b"short"); // only 5 bytes
    fs::write(scan_dir.path().join("truncated.class"), &class_truncated).expect("write");

    // 6. wasm section length past the end
    let mut wasm_bad_len = vec![0, b'a', b's', b'm', 1, 0, 0, 0];
    wasm_bad_len.push(7); // export section
    push_varuint(&mut wasm_bad_len, 99999); // length 99999
    wasm_bad_len.extend_from_slice(b"truncated");
    fs::write(scan_dir.path().join("bad_len.wasm"), &wasm_bad_len).expect("write");

    // Run scan: none may panic!
    let findings = scan_tree(scan_dir.path(), &fp, &opts);

    // Each hostile file must give a binary_malformed info finding
    let malformed: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3b" && f.channel == "binary_malformed")
        .collect();
    assert_eq!(
        malformed.len(),
        6,
        "every malformed binary must give binary_malformed finding"
    );
    for m in &malformed {
        assert_eq!(m.severity, Severity::Info);
    }
}

#[test]
fn test_visibility_image_only_d3b_gate_exits_0() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let parent_dir = tempdir().expect("tempdir");
    let parent = parent_dir.path();

    let base_tree = parent.join("repo");
    fs::create_dir_all(&base_tree).expect("mkdir repo");
    fs::write(base_tree.join("main.py"), "def base(): pass\n").expect("write base");

    let task = parent.join("task");
    fs::create_dir_all(task.join("staging")).expect("mkdir staging");
    fs::create_dir_all(task.join("agent")).expect("mkdir agent");
    let task_json = r#"{
        "schema": "hermetic-slice-task/v1",
        "instance_id": "test__d3b-vis",
        "repo": "test/repo",
        "base_commit": "1234567890abcdef1234567890abcdef12345678",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z"
        }
    }"#;
    fs::write(task.join("task.json"), task_json).expect("write task.json");
    let gold_patch = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,1 +1,3 @@\n def base():\n+    d3b_image_only_leak_one()\n+    d3b_image_only_leak_two()\n";
    fs::write(task.join("staging/gold.patch"), gold_patch).expect("write gold");
    fs::write(task.join("staging/test.patch"), "").expect("write test");
    fs::write(task.join("agent/problem_statement.md"), "problem").expect("write problem");

    let scan_root = parent.join("root");
    fs::create_dir_all(&scan_root).expect("mkdir root");

    // Put a leaked ELF in scan_root
    let elf_bytes = build_elf64_le(&["d3b_image_only_leak_one", "d3b_image_only_leak_two"]);
    fs::write(scan_root.join("leak.so"), &elf_bytes).expect("write leak.so");

    // 1. With image_only visibility: exits 0
    let status_image_only = Command::new(bin_path)
        .arg("scan")
        .arg("--task")
        .arg(&task)
        .arg("--base-tree")
        .arg(&base_tree)
        .arg("--root")
        .arg(&scan_root)
        .arg("--root-visibility")
        .arg("image_only")
        .status()
        .expect("exec image_only");
    assert_eq!(
        status_image_only.code(),
        Some(0),
        "an image_only D3b gate must exit 0"
    );

    // 2. With agent_visible visibility: exits 2
    let status_agent_visible = Command::new(bin_path)
        .arg("scan")
        .arg("--task")
        .arg(&task)
        .arg("--base-tree")
        .arg(&base_tree)
        .arg("--root")
        .arg(&scan_root)
        .arg("--root-visibility")
        .arg("agent_visible")
        .status()
        .expect("exec agent_visible");
    assert_eq!(
        status_agent_visible.code(),
        Some(2),
        "an agent_visible D3b gate must exit 2"
    );
}

fn leak_fp(base: &std::path::Path) -> FingerprintSet {
    let gold_patch = "diff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,3 @@\n def foo():\n+    elf_leaked_func_one()\n+    elf_leaked_func_two()\n";
    FingerprintSet::from_task(gold_patch, "", base).expect("fp")
}

fn d3b_gates(dir: &std::path::Path, fp: &FingerprintSet) -> Vec<hermetic_sealcheck::Finding> {
    scan_tree(dir, fp, &ScanOptions::default())
        .into_iter()
        .filter(|f| f.detector == "D3b" && f.severity == Severity::Gate)
        .collect()
}

#[test]
fn test_elf_without_section_table_is_searched_whole() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let mut elf = build_elf64_le(&["elf_leaked_func_one", "elf_leaked_func_two"]);
    elf[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
    elf[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("stripped.so"), &elf).expect("write");
    assert!(!d3b_gates(dir.path(), &fp).is_empty());
}

#[test]
fn test_malformed_elf_still_gates_on_its_strings() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let mut elf = build_elf64_le(&["elf_leaked_func_one", "elf_leaked_func_two"]);
    // Point section 1's name past the end of .shstrtab.
    let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    elf[shoff + 64..shoff + 68].copy_from_slice(&0xffffu32.to_le_bytes());
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("bad.so"), &elf).expect("write");
    let findings = scan_tree(dir.path(), &fp, &ScanOptions::default());
    assert!(findings.iter().any(|f| f.channel == "binary_malformed"));
    assert!(findings
        .iter()
        .any(|f| f.detector == "D3b" && f.severity == Severity::Gate));
}

#[test]
fn test_elf_rodata_str_section_is_read() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let mut elf = build_elf64_le(&["elf_leaked_func_one", "elf_leaked_func_two"]);
    // Rename .strtab (8 bytes with its NUL) to .rodata.s, so only the run search sees it.
    let pos = elf.windows(8).position(|w| w == b".strtab\0").unwrap();
    elf[pos..pos + 8].copy_from_slice(b".rodata.");
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("lit.so"), &elf).expect("write");
    let gates = d3b_gates(dir.path(), &fp);
    assert!(!gates.is_empty(), "literals in .rodata.* must be searched");
}

#[test]
fn test_elf_extended_section_count() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let mut elf = build_elf64_le(&["elf_leaked_func_one", "elf_leaked_func_two"]);
    let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    elf[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0: real count in section 0
    elf[62..64].copy_from_slice(&0xffffu16.to_le_bytes()); // SHN_XINDEX
    elf[shoff + 32..shoff + 40].copy_from_slice(&3u64.to_le_bytes()); // sh_size = 3
    elf[shoff + 40..shoff + 44].copy_from_slice(&1u32.to_le_bytes()); // sh_link = 1
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("big.so"), &elf).expect("write");
    let findings = scan_tree(dir.path(), &fp, &ScanOptions::default());
    assert!(
        findings.iter().all(|f| f.channel != "binary_malformed"),
        "{findings:?}"
    );
    assert!(findings
        .iter()
        .any(|f| f.channel == "binary_elf" && f.severity == Severity::Gate));
}

#[test]
fn test_hostile_wasm_leb128_overflow_is_not_a_panic() {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.push(1); // type section
    wasm.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("x.wasm"), &wasm).expect("write");
    let findings = scan_tree(dir.path(), &fp, &ScanOptions::default());
    assert!(findings.iter().any(|f| f.channel == "binary_malformed"));
}

#[test]
fn test_multiline_literal_is_not_an_item() {
    let items = hermetic_sealcheck::binary::extract_binary_items(
        "x = \"\"\"first line\nsecond line\"\"\"\n",
    );
    assert!(items.is_empty(), "{items:?}");
}

#[test]
fn test_minified_bundle_after_a_hash_is_still_searched() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let dir = tempdir().expect("tempdir");
    let bundle = ".a{color:#fff}.b{x:1}function f(){elf_leaked_func_one();elf_leaked_func_two()}";
    fs::write(dir.path().join("app.min.js"), bundle).expect("write");
    let gates = d3b_gates(dir.path(), &fp);
    assert!(
        gates.iter().any(|g| g.channel == "binary_minified"),
        "{gates:?}"
    );
}

#[test]
fn test_macho_universal_binary_is_not_a_malformed_class() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
    fat.extend_from_slice(&[0u8; 40]);
    fat.extend_from_slice(b"\0elf_leaked_func_one\0elf_leaked_func_two\0");
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("libfat.dylib"), &fat).expect("write");
    let findings = scan_tree(dir.path(), &fp, &ScanOptions::default());
    assert!(
        findings.iter().all(|f| f.channel != "binary_malformed"),
        "{findings:?}"
    );
    assert!(findings
        .iter()
        .any(|f| f.channel == "binary_macho" && f.severity == Severity::Gate));
}

#[test]
fn test_hostile_nobits_shstrtab_is_not_a_panic() {
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let mut elf = build_elf64_le(&["elf_leaked_func_one"]);
    let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    let sec1 = shoff + 64;
    elf[sec1 + 4..sec1 + 8].copy_from_slice(&8u32.to_le_bytes()); // SHT_NOBITS
    elf[sec1 + 24..sec1 + 32].copy_from_slice(&u64::MAX.to_le_bytes()); // sh_offset
    elf[sec1 + 32..sec1 + 40].copy_from_slice(&u64::MAX.to_le_bytes()); // sh_size
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("evil.so"), &elf).expect("write");
    let findings = scan_tree(dir.path(), &fp, &ScanOptions::default());
    assert!(findings.iter().any(|f| f.channel == "binary_malformed"));
}

#[test]
fn test_real_pyc_of_the_fix_gates_on_the_binary_tier() {
    // Compile with the real interpreter: names in a .pyc run into the next marshal byte.
    let base = tempdir().expect("tempdir");
    let fp = leak_fp(base.path());
    let src_dir = tempdir().expect("tempdir");
    let src = src_dir.path().join("foo.py");
    fs::write(
        &src,
        "def foo():\n    elf_leaked_func_one()\n    elf_leaked_func_two()\n",
    )
    .unwrap();
    let dir = tempdir().expect("tempdir");
    let pyc = dir.path().join("foo.pyc");
    let status = Command::new("python3")
        .args(["-c", "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)"])
        .arg(&src)
        .arg(&pyc)
        .status()
        .expect("python3 runs");
    assert!(status.success());
    let gates = d3b_gates(dir.path(), &fp);
    assert!(gates.iter().any(|g| g.channel == "binary_pyc"), "{gates:?}");
}

#[test]
fn test_pyc_strings_read_length_prefixed_records() {
    // 'Z' | 0x80 (interned short ascii, ref flag), length, bytes, then an opcode byte 's'.
    let mut body = vec![0xda, 15];
    body.extend_from_slice(b"effective_hours");
    body.push(b's');
    let strings = hermetic_sealcheck::binary::extract_pyc_strings(&body);
    assert!(strings.contains("effective_hours"), "{strings:?}");
}
