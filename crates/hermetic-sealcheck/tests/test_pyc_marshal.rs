use std::fs;
use tempfile::tempdir;

use hermetic_sealcheck::fingerprint::FingerprintSet;
use hermetic_sealcheck::pyc_marshal::{parse_pyc_code_objects, PycCodeObject};
use hermetic_sealcheck::scan::{scan_tree, Finding, ScanOptions, Severity};

fn marshal_short_ascii(name: &str) -> Vec<u8> {
    let mut b = vec![b'z', name.len() as u8];
    b.extend_from_slice(name.as_bytes());
    b
}

fn marshal_int(val: i32) -> Vec<u8> {
    let mut b = vec![b'i'];
    b.extend_from_slice(&val.to_le_bytes());
    b
}

fn marshal_tuple(items: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![b')', items.len() as u8];
    for it in items {
        b.extend_from_slice(it);
    }
    b
}

fn marshal_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut b = vec![b's'];
    b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    b.extend_from_slice(bytes);
    b
}

pub fn build_pyc_38(name: &str, consts: &[Vec<u8>], names: &[&str], varnames: &[&str]) -> Vec<u8> {
    let mut pyc = Vec::new();
    // Header (16 bytes): magic 3413 (Python 3.8)
    pyc.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
    pyc.extend_from_slice(&[0u8; 12]);

    // Code object
    pyc.push(b'c');
    pyc.extend_from_slice(&0i32.to_le_bytes()); // argcount
    pyc.extend_from_slice(&0i32.to_le_bytes()); // posonlyargcount
    pyc.extend_from_slice(&0i32.to_le_bytes()); // kwonlyargcount
    pyc.extend_from_slice(&(varnames.len() as i32).to_le_bytes()); // nlocals
    pyc.extend_from_slice(&1i32.to_le_bytes()); // stacksize
    pyc.extend_from_slice(&0i32.to_le_bytes()); // flags
    pyc.extend_from_slice(&marshal_bytes(&[0])); // code
    pyc.extend_from_slice(&marshal_tuple(consts)); // consts
    let names_items: Vec<Vec<u8>> = names.iter().map(|n| marshal_short_ascii(n)).collect();
    pyc.extend_from_slice(&marshal_tuple(&names_items)); // names
    let var_items: Vec<Vec<u8>> = varnames.iter().map(|n| marshal_short_ascii(n)).collect();
    pyc.extend_from_slice(&marshal_tuple(&var_items)); // varnames
    pyc.extend_from_slice(&marshal_tuple(&[])); // freevars
    pyc.extend_from_slice(&marshal_tuple(&[])); // cellvars
    pyc.extend_from_slice(&marshal_short_ascii("test.py")); // filename
    pyc.extend_from_slice(&marshal_short_ascii(name)); // name
    pyc.extend_from_slice(&1i32.to_le_bytes()); // firstlineno
    pyc.extend_from_slice(&marshal_bytes(&[])); // lnotab

    pyc
}

pub fn build_pyc_311(
    name: &str,
    qualname: &str,
    consts: &[Vec<u8>],
    names: &[&str],
    localsplusnames: &[&str],
) -> Vec<u8> {
    let mut pyc = Vec::new();
    // Header (16 bytes): magic 3495 (Python 3.11)
    pyc.extend_from_slice(&[0xa7, 0x0d, 0x0d, 0x0a]);
    pyc.extend_from_slice(&[0u8; 12]);

    // Code object
    pyc.push(b'c');
    pyc.extend_from_slice(&0i32.to_le_bytes()); // argcount
    pyc.extend_from_slice(&0i32.to_le_bytes()); // posonlyargcount
    pyc.extend_from_slice(&0i32.to_le_bytes()); // kwonlyargcount
    pyc.extend_from_slice(&1i32.to_le_bytes()); // stacksize
    pyc.extend_from_slice(&0i32.to_le_bytes()); // flags
    pyc.extend_from_slice(&marshal_bytes(&[0])); // code
    pyc.extend_from_slice(&marshal_tuple(consts)); // consts
    let names_items: Vec<Vec<u8>> = names.iter().map(|n| marshal_short_ascii(n)).collect();
    pyc.extend_from_slice(&marshal_tuple(&names_items)); // names
    let locals_items: Vec<Vec<u8>> = localsplusnames
        .iter()
        .map(|n| marshal_short_ascii(n))
        .collect();
    pyc.extend_from_slice(&marshal_tuple(&locals_items)); // localsplusnames
    pyc.extend_from_slice(&marshal_bytes(&[])); // localspluskinds
    pyc.extend_from_slice(&marshal_short_ascii("test.py")); // filename
    pyc.extend_from_slice(&marshal_short_ascii(name)); // name
    pyc.extend_from_slice(&marshal_short_ascii(qualname)); // qualname
    pyc.extend_from_slice(&1i32.to_le_bytes()); // firstlineno
    pyc.extend_from_slice(&marshal_bytes(&[])); // linetable
    pyc.extend_from_slice(&marshal_bytes(&[])); // exceptiontable

    pyc
}

fn raw_code_38(name: &str, consts: &[Vec<u8>], names: &[&str], varnames: &[&str]) -> Vec<u8> {
    let mut pyc = Vec::new();
    pyc.push(b'c');
    pyc.extend_from_slice(&0i32.to_le_bytes());
    pyc.extend_from_slice(&0i32.to_le_bytes());
    pyc.extend_from_slice(&0i32.to_le_bytes());
    pyc.extend_from_slice(&(varnames.len() as i32).to_le_bytes());
    pyc.extend_from_slice(&1i32.to_le_bytes());
    pyc.extend_from_slice(&0i32.to_le_bytes());
    pyc.extend_from_slice(&marshal_bytes(&[0]));
    pyc.extend_from_slice(&marshal_tuple(consts));
    let names_items: Vec<Vec<u8>> = names.iter().map(|n| marshal_short_ascii(n)).collect();
    pyc.extend_from_slice(&marshal_tuple(&names_items));
    let var_items: Vec<Vec<u8>> = varnames.iter().map(|n| marshal_short_ascii(n)).collect();
    pyc.extend_from_slice(&marshal_tuple(&var_items));
    pyc.extend_from_slice(&marshal_tuple(&[]));
    pyc.extend_from_slice(&marshal_tuple(&[]));
    pyc.extend_from_slice(&marshal_short_ascii("test.py"));
    pyc.extend_from_slice(&marshal_short_ascii(name));
    pyc.extend_from_slice(&1i32.to_le_bytes());
    pyc.extend_from_slice(&marshal_bytes(&[]));
    pyc
}

#[test]
fn test_pyc_function_gates_on_added_short_name_and_constant_38_and_311() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("service.py"),
        "def process(x):\n    return x\n",
    )
    .expect("write base");

    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,2 @@\n-def process(x):\n-    return x\n+def process(x, strict=False):\n+    return x + 3\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprint
        .as_ref()
        .expect("pyc fingerprint");
    assert_eq!(pyc_fp.function_name, "process");
    assert!(pyc_fp.added.contains("strict"));
    assert!(pyc_fp.added.contains("3"));
    assert!(!pyc_fp.added.contains("False")); // in stop list

    // Test Python 3.8 layout
    let pyc_fixed_38 = build_pyc_38("process", &[marshal_int(3)], &[], &["x", "strict"]);
    let pyc_base_38 = build_pyc_38("process", &[], &[], &["x"]);

    let scan_dir = parent.path().join("scan_fixed_38");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("service.pyc"), &pyc_fixed_38).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let pyc_gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(pyc_gates.len(), 1, "3.8 fixed pyc must gate: {findings:?}");
    assert_eq!(pyc_gates[0].confidence, 1.0);
    assert_eq!(pyc_gates[0].evidence[0], "process");
    assert!(pyc_gates[0].evidence.contains(&"3".to_string()));
    assert!(pyc_gates[0].evidence.contains(&"strict".to_string()));

    // Base pyc must not gate
    let scan_base_dir = parent.path().join("scan_base_38");
    fs::create_dir_all(&scan_base_dir).expect("mkdir");
    fs::write(scan_base_dir.join("service.pyc"), &pyc_base_38).expect("write pyc");
    let base_findings = scan_tree(&scan_base_dir, &fp, &opts);
    let base_gates: Vec<&Finding> = base_findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        base_gates.len(),
        0,
        "base pyc must not gate: {base_findings:?}"
    );

    // Test Python 3.11 layout
    let pyc_fixed_311 = build_pyc_311(
        "process",
        "process",
        &[marshal_int(3)],
        &[],
        &["x", "strict"],
    );
    let pyc_base_311 = build_pyc_311("process", "process", &[], &[], &["x"]);

    let scan_dir_311 = parent.path().join("scan_fixed_311");
    fs::create_dir_all(&scan_dir_311).expect("mkdir");
    fs::write(scan_dir_311.join("service.pyc"), &pyc_fixed_311).expect("write pyc");
    let findings_311 = scan_tree(&scan_dir_311, &fp, &opts);
    let gates_311: Vec<&Finding> = findings_311
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        gates_311.len(),
        1,
        "3.11 fixed pyc must gate: {findings_311:?}"
    );

    let scan_base_311 = parent.path().join("scan_base_311");
    fs::create_dir_all(&scan_base_311).expect("mkdir");
    fs::write(scan_base_311.join("service.pyc"), &pyc_base_311).expect("write pyc");
    let base_findings_311 = scan_tree(&scan_base_311, &fp, &opts);
    let base_gates_311: Vec<&Finding> = base_findings_311
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(base_gates_311.len(), 0, "3.11 base pyc must not gate");
}

#[test]
fn test_pyc_deletion_only_fix_gives_review_not_gate() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("cache.py"),
        "def clean_cache(target, force=True):\n    return target + 42\n",
    )
    .expect("write base");

    let gold_patch = "diff --git a/cache.py b/cache.py\n--- a/cache.py\n+++ b/cache.py\n@@ -1,2 +1,2 @@\n-def clean_cache(target, force=True):\n-    return target + 42\n+def clean_cache(target):\n+    return target\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    let pyc_fp = fp.hunks[0]
        .pyc_fingerprint
        .as_ref()
        .expect("pyc fingerprint");
    assert_eq!(pyc_fp.function_name, "clean_cache");
    assert!(
        pyc_fp.added.is_empty(),
        "added must be empty for pure deletion"
    );
    assert!(pyc_fp.removed.contains("force"));
    assert!(pyc_fp.removed.contains("42"));

    // Fixed pyc lacks force and 42
    let pyc_fixed = build_pyc_38("clean_cache", &[], &[], &["target"]);
    let scan_dir = parent.path().join("scan_deletion");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("cache.pyc"), &pyc_fixed).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let reviews: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Review)
        .collect();
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();

    assert_eq!(gates.len(), 0, "pure deletion must NOT report Gate");
    assert_eq!(
        reviews.len(),
        1,
        "pure deletion must report Review: {findings:?}"
    );
    assert!(reviews[0]
        .evidence
        .contains(&"pure deletion: absence of names is weak evidence".to_string()));
    assert_eq!(reviews[0].evidence[0], "clean_cache");
}

#[test]
fn test_pyc_nested_function_and_method_inside_class_found_by_name() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("worker.py"),
        "class Worker:\n    def execute(self):\n        return 1\n\ndef outer():\n    def inner():\n        return 1\n",
    )
    .expect("write base");

    // Patch modifying both method inside class and nested function
    let gold_patch = "diff --git a/worker.py b/worker.py\n--- a/worker.py\n+++ b/worker.py\n@@ -2,2 +2,2 @@\n-    def execute(self):\n-        return 1\n+    def execute(self, strict=True):\n+        return 3\n@@ -6,2 +6,2 @@\n-    def inner():\n-        return 1\n+    def inner(strict=True):\n+        return 3\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 2);
    let fp_method = fp.hunks[0].pyc_fingerprint.as_ref().expect("method pyc fp");
    assert_eq!(fp_method.function_name, "execute");
    assert!(fp_method.added.contains("strict"));
    assert!(fp_method.added.contains("3"));

    let fp_nested = fp.hunks[1].pyc_fingerprint.as_ref().expect("nested pyc fp");
    assert_eq!(fp_nested.function_name, "inner");
    assert!(fp_nested.added.contains("strict"));
    assert!(fp_nested.added.contains("3"));

    // Build a pyc with a top-level module containing Worker and outer,
    // where Worker contains execute and outer contains inner.
    let co_execute = raw_code_38("execute", &[marshal_int(3)], &[], &["self", "strict"]);
    let co_worker = raw_code_38("Worker", &[co_execute], &["execute"], &[]);
    let co_inner = raw_code_38("inner", &[marshal_int(3)], &[], &["strict"]);
    let co_outer = raw_code_38("outer", &[co_inner], &["inner"], &[]);

    let top_pyc = build_pyc_38(
        "<module>",
        &[co_worker, co_outer],
        &["Worker", "outer"],
        &[],
    );

    let scan_dir = parent.path().join("scan_nested");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("worker.pyc"), &top_pyc).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();

    assert!(
        gates.iter().any(|g| g.evidence[0] == "execute"),
        "must gate on method execute: {gates:?}"
    );
    assert!(
        gates.iter().any(|g| g.evidence[0] == "inner"),
        "must gate on nested function inner: {gates:?}"
    );
}

#[test]
fn test_hostile_pyc_marshal_never_panics() {
    let valid_38 = build_pyc_38("f", &[marshal_int(42)], &["name1"], &["var1"]);
    let valid_311 = build_pyc_311("f", "f", &[marshal_int(42)], &["name1"], &["var1"]);

    // 1. Truncated marshal stream at every possible prefix
    for len in 0..valid_38.len() {
        let _ = parse_pyc_code_objects(&valid_38[..len]);
    }
    for len in 0..valid_311.len() {
        let _ = parse_pyc_code_objects(&valid_311[..len]);
    }

    // 2. Ref to a missing index
    let mut bad_ref = Vec::new();
    bad_ref.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]); // magic 3413
    bad_ref.extend_from_slice(&[0u8; 12]);
    bad_ref.push(b'r');
    bad_ref.extend_from_slice(&999u32.to_le_bytes()); // non-existent ref
    assert_eq!(
        parse_pyc_code_objects(&bad_ref),
        Vec::<PycCodeObject>::new()
    );

    // 3. Recursion bomb: 100 nested tuples
    let mut bomb = Vec::new();
    bomb.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
    bomb.extend_from_slice(&[0u8; 12]);
    for _ in 0..100 {
        bomb.push(b'(');
        bomb.extend_from_slice(&1u32.to_le_bytes()); // tuple with 1 element
    }
    bomb.push(b'N'); // None inside
    assert_eq!(parse_pyc_code_objects(&bomb), Vec::<PycCodeObject>::new());

    // 4. Huge declared lengths
    let mut huge_tuple = Vec::new();
    huge_tuple.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
    huge_tuple.extend_from_slice(&[0u8; 12]);
    huge_tuple.push(b'(');
    huge_tuple.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_pyc_code_objects(&huge_tuple),
        Vec::<PycCodeObject>::new()
    );

    let mut huge_str = Vec::new();
    huge_str.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
    huge_str.extend_from_slice(&[0u8; 12]);
    huge_str.push(b's');
    huge_str.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_pyc_code_objects(&huge_str),
        Vec::<PycCodeObject>::new()
    );

    // 5. Every single-byte flip of a small valid .pyc: no panic, no hang
    let mut fuzz_38 = valid_38.clone();
    for i in 0..fuzz_38.len() {
        for flip in [0x01u8, 0x80u8, 0xffu8] {
            fuzz_38[i] ^= flip;
            let _ = parse_pyc_code_objects(&fuzz_38);
            fuzz_38[i] ^= flip;
        }
    }

    let mut fuzz_311 = valid_311.clone();
    for i in 0..fuzz_311.len() {
        for flip in [0x01u8, 0x80u8, 0xffu8] {
            fuzz_311[i] ^= flip;
            let _ = parse_pyc_code_objects(&fuzz_311);
            fuzz_311[i] ^= flip;
        }
    }
}
