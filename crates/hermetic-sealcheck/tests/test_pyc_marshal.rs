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

fn marshal_long(n: i32, digits: &[u16]) -> Vec<u8> {
    let mut b = vec![b'l'];
    b.extend_from_slice(&n.to_le_bytes());
    for &d in digits {
        b.extend_from_slice(&d.to_le_bytes());
    }
    b
}

fn marshal_frozenset(items: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![b'>'];
    b.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for it in items {
        b.extend_from_slice(it);
    }
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

#[test]
fn test_regression_finding_1_multiline_signature_continuation_lines() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("multiline.py"),
        "def compute(\n    a,\n    b,\n):\n    return a + b\n",
    )
    .expect("write base");

    let gold_patch = "diff --git a/multiline.py b/multiline.py\n--- a/multiline.py\n+++ b/multiline.py\n@@ -5,1 +5,1 @@\n-    return a + b\n+    return a + b + 7\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprint
        .as_ref()
        .expect("pyc fingerprint");
    assert_eq!(pyc_fp.function_name, "compute");
    assert_eq!(pyc_fp.added, ["7".to_string()].into_iter().collect());
    assert!(
        pyc_fp.removed.is_empty(),
        "valid signature parameters survive"
    );
    assert!(
        pyc_fp.added.contains("7"),
        "added must contain 7: {:?}",
        pyc_fp.added
    );

    let pyc_fixed_38 = build_pyc_38("compute", &[marshal_int(7)], &[], &["a", "b"]);
    let scan_dir = parent.path().join("scan_fixed");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("multiline.pyc"), &pyc_fixed_38).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1, "multiline body fix must gate: {findings:?}");
    assert_eq!(gates[0].evidence[0], "compute");
    assert!(gates[0].evidence.contains(&"7".to_string()));
}

#[test]
fn test_regression_finding_2_same_named_methods_adjacent_classes() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("service.py"),
        "class A:\n    def run(self):\n        return 2\n\nclass B:\n    def run(self, force=True):\n        return 3\n",
    )
    .expect("write base");

    // Hunk context includes A.run returning 2, but the changed line removes force=True from B.run
    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -2,6 +2,6 @@\n     def run(self):\n         return 2\n \n class B:\n-    def run(self, force=True):\n+    def run(self):\n         return 3\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprint
        .as_ref()
        .expect("pyc fingerprint");
    assert_eq!(pyc_fp.function_name, "run");
    assert!(
        !pyc_fp.added.contains("3"),
        "must not have added 3: {:?}",
        pyc_fp.added
    );
    assert!(
        !pyc_fp.removed.contains("2"),
        "must not have removed 2: {:?}",
        pyc_fp.removed
    );
    assert!(
        pyc_fp.removed.contains("force"),
        "must have removed force: {:?}",
        pyc_fp.removed
    );

    // Unchanged B.run returning 3 in base pyc must NOT receive a Gate finding
    let pyc_unchanged_b = build_pyc_38("run", &[marshal_int(3)], &[], &["self", "force"]);
    let scan_dir = parent.path().join("scan_unchanged");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("service.pyc"), &pyc_unchanged_b).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        gates.len(),
        0,
        "unchanged B.run must NOT gate: {findings:?}"
    );
}

#[test]
fn test_regression_finding_3_literal_normalization() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("literals.py"),
        "def calc():\n    return 2\n\ndef greet():\n    return \"a\"\n",
    )
    .expect("write base");

    let gold_patch = "diff --git a/literals.py b/literals.py\n--- a/literals.py\n+++ b/literals.py\n@@ -1,5 +1,5 @@\n def calc():\n-    return 2\n+    return 0x3\n \n def greet():\n-    return \"a\"\n+    return \"hello\\nworld\"\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    // Fingerprints should normalize 0x3 to "3" and "hello\nworld" to "hello\nworld"
    let calc_fp = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .find(|f| f.function_name == "calc")
        .expect("calc fp");
    assert!(
        calc_fp.added.contains("3"),
        "calc added must contain 3: {:?}",
        calc_fp.added
    );
    assert!(!calc_fp.added.contains("0x3"));

    let greet_fp = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .find(|f| f.function_name == "greet")
        .expect("greet fp");
    assert!(
        greet_fp.added.contains("hello\nworld"),
        "greet added must contain hello\\nworld: {:?}",
        greet_fp.added
    );

    // Scan pyc containing 3 and "hello\nworld"
    let pyc_calc = build_pyc_38("calc", &[marshal_int(3)], &[], &[]);
    let pyc_greet = build_pyc_38("greet", &[marshal_short_ascii("hello\nworld")], &[], &[]);
    let scan_dir = parent.path().join("scan_literals");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("calc.pyc"), &pyc_calc).expect("write pyc");
    fs::write(scan_dir.join("greet.pyc"), &pyc_greet).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        gates.len(),
        2,
        "both normalized literals must gate: {findings:?}"
    );
}

#[test]
fn test_regression_finding_4_multiple_functions_per_hunk() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("multi.py"),
        "def f(x, unused=1):\n    return x\n\ndef g(y):\n    return y\n",
    )
    .expect("write base");

    // Single hunk changes both f (removes unused parameter) and g (adds constant 42)
    let gold_patch = "diff --git a/multi.py b/multi.py\n--- a/multi.py\n+++ b/multi.py\n@@ -1,5 +1,5 @@\n-def f(x, unused=1):\n+def f(x):\n     return x\n \n def g(y):\n-    return y\n+    return y + 42\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let fps = &fp.hunks[0].pyc_fingerprints;
    assert_eq!(fps.len(), 2, "hunk must produce 2 fingerprints: {fps:?}");

    let f_fp = fps.iter().find(|p| p.function_name == "f").expect("f fp");
    assert!(f_fp.added.is_empty(), "f is pure deletion");
    assert!(f_fp.removed.contains("unused"));

    let g_fp = fps.iter().find(|p| p.function_name == "g").expect("g fp");
    assert!(g_fp.added.contains("42"));

    // Fully fixed .pyc with f and g
    let co_f = raw_code_38("f", &[], &[], &["x"]);
    let co_g = raw_code_38("g", &[marshal_int(42)], &[], &["y"]);
    let top_pyc = build_pyc_38("<module>", &[co_f, co_g], &["f", "g"], &[]);

    let scan_dir = parent.path().join("scan_multi");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("multi.pyc"), &top_pyc).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);

    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    let reviews: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Review)
        .collect();

    assert_eq!(gates.len(), 1, "g must produce Gate: {findings:?}");
    assert_eq!(gates[0].evidence[0], "g");
    assert_eq!(reviews.len(), 1, "f must produce Review: {findings:?}");
    assert_eq!(reviews[0].evidence[0], "f");
}

#[test]
fn test_regression_finding_5_dos_reference_expansion_bounded() {
    let mut pyc = Vec::new();
    pyc.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]); // magic 3413
    pyc.extend_from_slice(&[0u8; 12]);

    // Define T0 = (1, 1) with FLAG_REF (0x80 | b')')
    pyc.push(0x80 | b')');
    pyc.push(2);
    pyc.extend_from_slice(&marshal_int(1));
    pyc.extend_from_slice(&marshal_int(1));

    // Define T1 = (r0, r0) through T25 = (r24, r24) with FLAG_REF
    for i in 0..25u32 {
        pyc.push(0x80 | b')');
        pyc.push(2);
        pyc.push(b'r');
        pyc.extend_from_slice(&i.to_le_bytes());
        pyc.push(b'r');
        pyc.extend_from_slice(&i.to_le_bytes());
    }

    // Parsing must terminate promptly without memory explosion or panic
    let start = std::time::Instant::now();
    let result = parse_pyc_code_objects(&pyc);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 500,
        "parsing bomb took too long: {elapsed:?}"
    );
    assert_eq!(result, Vec::<PycCodeObject>::new());
}

#[test]
fn test_regression_finding_6_definition_header_scope_ownership() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(base_dir.join("header.py"), "").expect("write base");

    let gold_patch = "diff --git a/header.py b/header.py\n--- a/header.py\n+++ b/header.py\n@@ -0,0 +1,5 @@\n+def f(x):\n+    return x\n+\n+def g(x: int = 100):\n+    return x\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    let fps = &fp.hunks[0].pyc_fingerprints;
    let f_fp = fps.iter().find(|p| p.function_name == "f").expect("f fp");
    assert!(
        !f_fp.added.contains("f"),
        "f must NOT be in f's symbol set: {:?}",
        f_fp.added
    );
    assert!(
        f_fp.added.contains("x"),
        "x must be in f's symbol set: {:?}",
        f_fp.added
    );

    let g_fp = fps.iter().find(|p| p.function_name == "g").expect("g fp");
    assert!(
        !g_fp.added.contains("g"),
        "g must NOT be in g's symbol set: {:?}",
        g_fp.added
    );
    assert!(
        !g_fp.added.contains("int"),
        "annotation int must NOT be in g's symbol set: {:?}",
        g_fp.added
    );
    assert!(
        !g_fp.added.contains("100"),
        "default 100 must NOT be in g's symbol set: {:?}",
        g_fp.added
    );
    assert!(
        g_fp.added.contains("x"),
        "x must be in g's symbol set: {:?}",
        g_fp.added
    );

    let mod_fp = fps
        .iter()
        .find(|p| p.function_name == "<module>")
        .expect("module fp");
    assert!(
        mod_fp.added.contains("f"),
        "module must have definition name f: {:?}",
        mod_fp.added
    );
    assert!(
        mod_fp.added.contains("g"),
        "module must have definition name g: {:?}",
        mod_fp.added
    );
    assert!(
        mod_fp.added.contains("int"),
        "module must have annotation int: {:?}",
        mod_fp.added
    );
    assert!(
        mod_fp.added.contains("100"),
        "module must have default 100: {:?}",
        mod_fp.added
    );
    assert!(
        !mod_fp.added.contains("x"),
        "module must NOT have parameter x: {:?}",
        mod_fp.added
    );

    // Code object for f has co_varnames=("x",), symbols={"x"}. Should score 1.0 confidence and gate!
    let pyc_f = build_pyc_38("f", &[], &[], &["x"]);
    let scan_dir = parent.path().join("scan_header");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("header.pyc"), &pyc_f).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1, "new def f(x) must gate: {findings:?}");
    assert_eq!(gates[0].confidence, 1.0);
}

#[test]
fn test_regression_finding_7_retain_module_indented_statements() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(base_dir.join("mod_block.py"), "if flag:\n    x = 2\n").expect("write base");

    let gold_patch = "diff --git a/mod_block.py b/mod_block.py\n--- a/mod_block.py\n+++ b/mod_block.py\n@@ -1,2 +1,2 @@\n if flag:\n-    x = 2\n+    x = 3\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprint
        .as_ref()
        .expect("module pyc fp must not be None");
    assert_eq!(pyc_fp.function_name, "<module>");
    assert!(
        pyc_fp.added.contains("3"),
        "added must contain 3: {:?}",
        pyc_fp.added
    );
    assert!(
        pyc_fp.removed.contains("2"),
        "removed must contain 2: {:?}",
        pyc_fp.removed
    );

    let pyc_mod = build_pyc_38("<module>", &[marshal_int(3)], &["flag", "x"], &[]);
    let scan_dir = parent.path().join("scan_mod");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("mod_block.pyc"), &pyc_mod).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        gates.len(),
        1,
        "module-level if body modification must gate: {findings:?}"
    );
}

#[test]
fn test_regression_finding_8_tuple_constant_scalar_symbols() {
    let parent = tempdir().expect("tempdir");
    let base_dir = parent.path().join("base");
    fs::create_dir_all(&base_dir).expect("mkdir");
    fs::write(
        base_dir.join("tuple_const.py"),
        "def get_pair():\n    return (2, 3)\n",
    )
    .expect("write base");

    let gold_patch = "diff --git a/tuple_const.py b/tuple_const.py\n--- a/tuple_const.py\n+++ b/tuple_const.py\n@@ -1,2 +1,2 @@\n def get_pair():\n-    return (2, 3)\n+    return (2, 4)\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let pyc_fp = fp.hunks[0].pyc_fingerprint.as_ref().expect("pyc fp");
    assert_eq!(pyc_fp.function_name, "get_pair");
    assert!(
        pyc_fp.added.contains("4"),
        "added must contain 4: {:?}",
        pyc_fp.added
    );

    // Build .pyc where co_consts contains folded tuple (2, 4)
    let folded_tuple = marshal_tuple(&[marshal_int(2), marshal_int(4)]);
    let pyc = build_pyc_38("get_pair", &[folded_tuple], &[], &[]);

    // Verify parser extracts 2 and 4 from inside the tuple constant
    let code_objs = parse_pyc_code_objects(&pyc);
    assert_eq!(code_objs.len(), 1);
    assert!(
        code_objs[0].symbols.contains("2"),
        "symbols must contain 2: {:?}",
        code_objs[0].symbols
    );
    assert!(
        code_objs[0].symbols.contains("4"),
        "symbols must contain 4: {:?}",
        code_objs[0].symbols
    );

    let scan_dir = parent.path().join("scan_tuple");
    fs::create_dir_all(&scan_dir).expect("mkdir");
    fs::write(scan_dir.join("tuple_const.pyc"), &pyc).expect("write pyc");

    let opts = ScanOptions::default();
    let findings = scan_tree(&scan_dir, &fp, &opts);
    let gates: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "binary_pyc_function" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1, "tuple constant fix must gate: {findings:?}");
    assert!(gates[0].evidence.contains(&"4".to_string()));
}

#[test]
fn reference_graph_drop_depth_is_bounded_in_subprocess() {
    const CHILD: &str = "HERMETIC_PYC_GRAPH_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        for truncated in [false, true] {
            let count = 150_000u32;
            let mut pyc = vec![0x55, 0x0d, 0x0d, 0x0a];
            pyc.extend_from_slice(&[0; 12]);
            pyc.push(b'[');
            pyc.extend_from_slice(&(count + 2).to_le_bytes());
            pyc.extend_from_slice(&raw_code_38("sentinel", &[], &[], &[]));
            pyc.extend_from_slice(&[0x80 | b')', 0]);
            for index in 0..count {
                pyc.extend_from_slice(&[0x80 | b')', 1, b'r']);
                pyc.extend_from_slice(&index.to_le_bytes());
            }
            if truncated {
                pyc.pop();
            }
            assert!(parse_pyc_code_objects(&pyc).is_empty());
        }
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "reference_graph_drop_depth_is_bounded_in_subprocess",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .status()
        .expect("subprocess");
    assert!(
        status.success(),
        "reference graph destruction must not overflow"
    );
}

fn assert_both_pyc_matchers(fp: &FingerprintSet, fixed: &[u8], base: &[u8]) {
    use hermetic_sealcheck::fingerprint::sha256_u64;
    use hermetic_sealcheck::pyc_marshal::{
        match_hashed_pyc_code_objects, match_pyc_code_objects, HashedPycCodeObject,
    };
    for (bytes, should_gate) in [(fixed, true), (base, false)] {
        let objects = parse_pyc_code_objects(bytes);
        assert!(!objects.is_empty());
        let hashed: Vec<_> = objects
            .iter()
            .map(|object| HashedPycCodeObject {
                name: object.name.clone(),
                symbols: object
                    .symbols
                    .iter()
                    .map(|s| sha256_u64(s.as_bytes()))
                    .collect(),
            })
            .collect();
        let opts = ScanOptions::default();
        for findings in [
            match_pyc_code_objects(&objects, fp, &opts, "fixture.pyc"),
            match_hashed_pyc_code_objects(&hashed, fp, &opts, "fixture.pyc"),
        ] {
            assert_eq!(
                findings.iter().any(|f| f.severity == Severity::Gate),
                should_gate,
                "{findings:?}"
            );
        }
    }
}

#[test]
fn changed_same_named_methods_pair_by_scope_and_position() {
    let parent = tempdir().expect("tempdir");
    let base = "class A:\n    def run(self, force=True):\n        return 2\nclass B:\n    def run(self, force=True):\n        return 3\n";
    fs::write(parent.path().join("service.py"), base).expect("base");
    let patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,6 +1,6 @@\n class A:\n-    def run(self, force=True):\n+    def run(self):\n         return 2\n class B:\n-    def run(self, force=True):\n+    def run(self):\n         return 3\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let methods: Vec<_> = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .filter(|f| f.function_name == "run")
        .collect();
    assert_eq!(methods.len(), 2);
    for method in methods {
        assert!(method.added.is_empty());
        assert_eq!(method.removed, ["force".to_string()].into_iter().collect());
    }
    use hermetic_sealcheck::pyc_marshal::{
        match_hashed_pyc_code_objects, match_pyc_code_objects, HashedPycCodeObject,
    };
    for constant in [2, 3] {
        let objects = parse_pyc_code_objects(&build_pyc_38(
            "run",
            &[marshal_int(constant)],
            &[],
            &["self", "force"],
        ));
        let hashed: Vec<_> = objects
            .iter()
            .map(|co| HashedPycCodeObject {
                name: co.name.clone(),
                symbols: co
                    .symbols
                    .iter()
                    .map(|s| hermetic_sealcheck::fingerprint::sha256_u64(s.as_bytes()))
                    .collect(),
            })
            .collect();
        for findings in [
            match_pyc_code_objects(&objects, &fp, &ScanOptions::default(), "fixture.pyc"),
            match_hashed_pyc_code_objects(&hashed, &fp, &ScanOptions::default(), "fixture.pyc"),
        ] {
            assert!(!findings.iter().any(|f| f.severity == Severity::Gate));
        }
    }
}

#[test]
fn header_only_changes_schedule_module_and_nested_enclosing_objects() {
    for nested in [false, true] {
        for annotation in [false, true] {
            let parent = tempdir().expect("tempdir");
            let indent = if nested { "    " } else { "" };
            let old_header = if annotation {
                "def f(x: OldType):"
            } else {
                "def f(x=2):"
            };
            let new_header = if annotation {
                "def f(x: NewType):"
            } else {
                "def f(x=3):"
            };
            let prefix = if nested { "def outer():\n" } else { "" };
            let base = format!("{prefix}{indent}{old_header}\n{indent}    return x\n");
            fs::write(parent.path().join("header.py"), base).expect("base");
            let line = if nested { 2 } else { 1 };
            let patch = format!("diff --git a/header.py b/header.py\n--- a/header.py\n+++ b/header.py\n@@ -{line},1 +{line},1 @@\n-{indent}{old_header}\n+{indent}{new_header}\n");
            let fp = FingerprintSet::from_task(&patch, "", parent.path()).expect("fingerprints");
            let name = if nested { "outer" } else { "<module>" };
            let scope = fp.hunks[0]
                .pyc_fingerprints
                .iter()
                .find(|f| f.function_name == name)
                .expect("enclosing fingerprint");
            let (old_symbol, new_symbol) = if annotation {
                ("OldType", "NewType")
            } else {
                ("2", "3")
            };
            assert!(scope.added.contains(new_symbol));
            assert!(scope.removed.contains(old_symbol));
            let fixed = if annotation {
                build_pyc_38(name, &[], &["f", "NewType"], &[])
            } else {
                build_pyc_38(name, &[marshal_int(3)], &["f"], &[])
            };
            let base = if annotation {
                build_pyc_38(name, &[], &["f", "OldType"], &[])
            } else {
                build_pyc_38(name, &[marshal_int(2)], &["f"], &[])
            };
            assert_both_pyc_matchers(&fp, &fixed, &base);
        }
    }
}

#[test]
fn signed_numbers_and_raw_strings_match_marshal_literals() {
    let mut float_base = vec![b'g'];
    float_base.extend_from_slice(&(-2.5f64).to_le_bytes());
    let mut float_fixed = vec![b'g'];
    float_fixed.extend_from_slice(&(-3.5f64).to_le_bytes());
    for (old, new, old_value, new_value, canonical) in [
        ("-2", "-3", marshal_int(-2), marshal_int(-3), "-3"),
        ("-2.5", "-3.5", float_base, float_fixed, "-3.5"),
        (
            r#"r"\t""#,
            r#"r"\n""#,
            marshal_short_ascii(r"\t"),
            marshal_short_ascii(r"\n"),
            r"\n",
        ),
    ] {
        let parent = tempdir().expect("tempdir");
        fs::write(
            parent.path().join("literal.py"),
            format!("def f():\n    return {old}\n"),
        )
        .expect("base");
        let patch = format!("diff --git a/literal.py b/literal.py\n--- a/literal.py\n+++ b/literal.py\n@@ -2,1 +2,1 @@\n-    return {old}\n+    return {new}\n");
        let fp = FingerprintSet::from_task(&patch, "", parent.path()).expect("fingerprints");
        assert_eq!(
            fp.hunks[0].pyc_fingerprints[0].added,
            [canonical.to_string()].into_iter().collect()
        );
        assert_both_pyc_matchers(
            &fp,
            &build_pyc_38("f", &[new_value], &[], &[]),
            &build_pyc_38("f", &[old_value], &[], &[]),
        );
    }
}

#[test]
fn inserted_same_named_definition_preserves_patch_position_pairing() {
    let parent = tempdir().expect("tempdir");
    let base = "class A:\n    def run(self, force=True):\n        return 2\n    def run(self, force=True):\n        return 3\n";
    fs::write(parent.path().join("service.py"), base).expect("base");
    let patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,5 +1,7 @@\n class A:\n+    def run(self):\n+        return 4\n     def run(self, force=True):\n         return 2\n-    def run(self, force=True):\n+    def run(self):\n         return 3\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let methods: Vec<_> = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .filter(|f| f.function_name == "run")
        .collect();
    assert_eq!(methods.len(), 2);
    assert!(methods
        .iter()
        .any(|f| f.added == ["4".to_string()].into_iter().collect()));
    assert!(methods
        .iter()
        .any(|f| f.added.is_empty() && f.removed == ["force".to_string()].into_iter().collect()));
    assert!(methods
        .iter()
        .all(|f| !f.added.contains("2") && !f.added.contains("3")));
}

#[test]
fn test_regression_defect1_large_patch_bounded_work_and_budget_error() {
    let parent = tempdir().expect("tempdir");
    let mut base = String::new();
    let n = 20_000;
    for i in 0..n {
        base.push_str(&format!("def f{i}():\n    return {i}\n"));
    }
    fs::write(parent.path().join("large.py"), &base).expect("base");

    let patch = "diff --git a/large.py b/large.py\n--- a/large.py\n+++ b/large.py\n@@ -1,4 +1,4 @@\n def f0():\n-    return 0\n+    return 99999\n@@ -39999,2 +39999,2 @@\n def f19999():\n-    return 19999\n+    return 88888\n";
    let start = std::time::Instant::now();
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "processing large file must complete within bounded work (took {elapsed:?})"
    );
    assert_eq!(fp.hunks.len(), 2);

    use hermetic_sealcheck::fingerprint::FingerprintError;
    let constrained = FingerprintSet::from_task_with_budget(patch, "", parent.path(), Some(10));
    assert!(
        matches!(constrained, Err(FingerprintError::WorkBudgetExceeded)),
        "must return deterministic budget error: {constrained:?}"
    );
}

#[test]
fn test_regression_defect2_contextual_keywords_as_identifiers() {
    let parent = tempdir().expect("tempdir");
    let base = "def f(x):\n    return x\n";
    fs::write(parent.path().join("service.py"), base).expect("base");

    let patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x\n+    return type(x)\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let f_fp = &fp.hunks[0].pyc_fingerprints[0];
    assert!(
        f_fp.added.contains("type"),
        "type as an identifier must enter added symbols: {:?}",
        f_fp.added
    );

    let fixed_pyc = build_pyc_38("f", &[], &["type"], &["x"]);
    let base_pyc = build_pyc_38("f", &[], &[], &["x"]);
    assert_both_pyc_matchers(&fp, &fixed_pyc, &base_pyc);

    let patch_match = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,4 @@\n def f(x):\n-    return x\n+    match = 1\n+    case = 2\n+    return match + case\n";
    let fp_match = FingerprintSet::from_task(patch_match, "", parent.path()).expect("fingerprints");
    let f_fp_match = &fp_match.hunks[0].pyc_fingerprints[0];
    assert!(f_fp_match.added.contains("match"));
    assert!(f_fp_match.added.contains("case"));
}

#[test]
fn test_regression_defect3_multiline_string_spans_in_functions_and_modules() {
    let parent = tempdir().expect("tempdir");

    // 1. Multiline string in a function body
    let fn_base = "def f():\n    return \"\"\"a\nb\"\"\"\n";
    fs::write(parent.path().join("fn_mod.py"), fn_base).expect("write fn_base");
    let fn_patch = "diff --git a/fn_mod.py b/fn_mod.py\n--- a/fn_mod.py\n+++ b/fn_mod.py\n@@ -1,3 +1,3 @@\n def f():\n-    return \"\"\"a\n+    return \"\"\"c\n b\"\"\"\n";
    let fp_fn = FingerprintSet::from_task(fn_patch, "", parent.path()).expect("fingerprints");
    let f_fp = &fp_fn.hunks[0].pyc_fingerprints[0];
    assert!(
        f_fp.added.contains("c\nb"),
        "added symbols must contain complete constant 'c\\nb': {:?}",
        f_fp.added
    );
    assert!(
        f_fp.removed.contains("a\nb"),
        "removed symbols must contain complete constant 'a\\nb': {:?}",
        f_fp.removed
    );
    assert!(
        !f_fp.added.contains("c"),
        "added symbols must not fragment multiline string into 'c'"
    );

    let fixed_fn_pyc = build_pyc_38("f", &[marshal_short_ascii("c\nb")], &[], &[]);
    let base_fn_pyc = build_pyc_38("f", &[marshal_short_ascii("a\nb")], &[], &[]);
    assert_both_pyc_matchers(&fp_fn, &fixed_fn_pyc, &base_fn_pyc);

    // 2. Multiline string at module level
    let mod_base = "DOC = \"\"\"hello\nworld\"\"\"\n";
    fs::write(parent.path().join("mod_doc.py"), mod_base).expect("write mod_base");
    let mod_patch = "diff --git a/mod_doc.py b/mod_doc.py\n--- a/mod_doc.py\n+++ b/mod_doc.py\n@@ -1,2 +1,2 @@\n DOC = \"\"\"hello\n-world\"\"\"\n+universe\"\"\"\n";
    let fp_mod = FingerprintSet::from_task(mod_patch, "", parent.path()).expect("fingerprints");
    let m_fp = &fp_mod.hunks[0].pyc_fingerprints[0];
    assert_eq!(m_fp.function_name, "<module>");
    assert!(
        m_fp.added.contains("hello\nuniverse"),
        "module added symbols must contain complete constant: {:?}",
        m_fp.added
    );
    assert!(
        m_fp.removed.contains("hello\nworld"),
        "module removed symbols must contain complete constant: {:?}",
        m_fp.removed
    );

    let fixed_mod_pyc = build_pyc_38(
        "<module>",
        &[marshal_short_ascii("hello\nuniverse")],
        &["DOC"],
        &[],
    );
    let base_mod_pyc = build_pyc_38(
        "<module>",
        &[marshal_short_ascii("hello\nworld")],
        &["DOC"],
        &[],
    );
    assert_both_pyc_matchers(&fp_mod, &fixed_mod_pyc, &base_mod_pyc);
}

#[test]
fn test_regression_defect4_five_digit_integers_positive_and_negative() {
    let parent = tempdir().expect("tempdir");

    // Positive five-digit integers
    // 1152921504606846976 is 2^60 (digits: [0, 0, 0, 0, 1])
    // 1152921504606846977 is 2^60 + 1 (digits: [1, 0, 0, 0, 1])
    let pos_base = "def f(x):\n    return 1152921504606846976\n";
    fs::write(parent.path().join("pos.py"), pos_base).expect("pos base");
    let pos_patch = "diff --git a/pos.py b/pos.py\n--- a/pos.py\n+++ b/pos.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return 1152921504606846976\n+    return 1152921504606846977\n";
    let fp_pos = FingerprintSet::from_task(pos_patch, "", parent.path()).expect("fingerprints");
    let f_pos = &fp_pos.hunks[0].pyc_fingerprints[0];
    assert!(
        f_pos.added.contains("1152921504606846977"),
        "source fingerprint must contain 5-digit int: {:?}",
        f_pos.added
    );
    assert!(
        f_pos.removed.contains("1152921504606846976"),
        "source fingerprint must contain removed 5-digit int: {:?}",
        f_pos.removed
    );

    let fixed_pos_pyc = build_pyc_38("f", &[marshal_long(5, &[1, 0, 0, 0, 1])], &[], &["x"]);
    let base_pos_pyc = build_pyc_38("f", &[marshal_long(5, &[0, 0, 0, 0, 1])], &[], &["x"]);
    assert_both_pyc_matchers(&fp_pos, &fixed_pos_pyc, &base_pos_pyc);

    // Negative five-digit integers
    let neg_base = "def f(x):\n    return -1152921504606846976\n";
    fs::write(parent.path().join("neg.py"), neg_base).expect("neg base");
    let neg_patch = "diff --git a/neg.py b/neg.py\n--- a/neg.py\n+++ b/neg.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return -1152921504606846976\n+    return -1152921504606846977\n";
    let fp_neg = FingerprintSet::from_task(neg_patch, "", parent.path()).expect("fingerprints");
    let f_neg = &fp_neg.hunks[0].pyc_fingerprints[0];
    assert!(
        f_neg.added.contains("-1152921504606846977"),
        "source fingerprint must contain negative 5-digit int: {:?}",
        f_neg.added
    );
    assert!(
        f_neg.removed.contains("-1152921504606846976"),
        "source fingerprint must contain negative removed 5-digit int: {:?}",
        f_neg.removed
    );

    let fixed_neg_pyc = build_pyc_38("f", &[marshal_long(-5, &[1, 0, 0, 0, 1])], &[], &["x"]);
    let base_neg_pyc = build_pyc_38("f", &[marshal_long(-5, &[0, 0, 0, 0, 1])], &[], &["x"]);
    assert_both_pyc_matchers(&fp_neg, &fixed_neg_pyc, &base_neg_pyc);
}

#[test]
fn test_regression_defect5_frozenset_constants_38_and_311() {
    let parent = tempdir().expect("tempdir");
    let base = "def f(x):\n    return x in {2, 3}\n";
    fs::write(parent.path().join("service.py"), base).expect("base");

    let patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x in {2, 3}\n+    return x in {2, 4}\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let f_fp = &fp.hunks[0].pyc_fingerprints[0];
    assert!(f_fp.added.contains("4"));
    assert!(f_fp.removed.contains("3"));

    // 1. Python 3.8 hand-marshalled frozenset constants
    let fs_fixed = marshal_frozenset(&[marshal_int(2), marshal_int(4)]);
    let fs_base = marshal_frozenset(&[marshal_int(2), marshal_int(3)]);
    let fixed_38 = build_pyc_38("f", std::slice::from_ref(&fs_fixed), &[], &["x"]);
    let base_38 = build_pyc_38("f", std::slice::from_ref(&fs_base), &[], &["x"]);

    let objs_38 = parse_pyc_code_objects(&fixed_38);
    assert_eq!(objs_38.len(), 1);
    assert!(
        objs_38[0].symbols.contains("4"),
        "Python 3.8 frozenset must expose scalar constant '4': {:?}",
        objs_38[0].symbols
    );
    assert!(objs_38[0].symbols.contains("2"));

    assert_both_pyc_matchers(&fp, &fixed_38, &base_38);

    // 2. Python 3.11 hand-marshalled frozenset constants
    let fixed_311 = build_pyc_311("f", "f", std::slice::from_ref(&fs_fixed), &[], &["x"]);
    let base_311 = build_pyc_311("f", "f", std::slice::from_ref(&fs_base), &[], &["x"]);

    let objs_311 = parse_pyc_code_objects(&fixed_311);
    assert_eq!(objs_311.len(), 1);
    assert!(
        objs_311[0].symbols.contains("4"),
        "Python 3.11 frozenset must expose scalar constant '4': {:?}",
        objs_311[0].symbols
    );
    assert!(objs_311[0].symbols.contains("2"));

    assert_both_pyc_matchers(&fp, &fixed_311, &base_311);
}

#[test]
fn test_regression_defect1_all_20000_functions_added_and_changed_bounded_ops() {
    let parent = tempdir().expect("tempdir");
    let mut base = String::new();
    let n = 20_000;
    for i in 0..n {
        base.push_str(&format!("def f{i}():\n    return {i}\n"));
    }
    fs::write(parent.path().join("large.py"), &base).expect("base");

    // 1. Change all 20,000 functions - assert deterministic budget rejection
    let mut change_patch = String::from(
        "diff --git a/large.py b/large.py\n--- a/large.py\n+++ b/large.py\n@@ -1,40000 +1,40000 @@\n",
    );
    for i in 0..n {
        change_patch.push_str(&format!(
            " def f{i}():\n-    return {i}\n+    return {}\n",
            i + 1_000_000
        ));
    }

    use hermetic_sealcheck::fingerprint::FingerprintError;
    let constrained_change =
        FingerprintSet::from_task_with_budget(&change_patch, "", parent.path(), Some(1_000));
    assert!(
        matches!(constrained_change, Err(FingerprintError::WorkBudgetExceeded)),
        "changing 20000 functions must yield deterministic budget rejection: {constrained_change:?}"
    );

    // 2. Add all 20,000 functions - assert deterministic budget rejection
    let mut add_patch = String::from(
        "diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,40000 @@\n",
    );
    for i in 0..n {
        add_patch.push_str(&format!("+def g{i}():\n+    return {i}\n"));
    }
    let constrained_add =
        FingerprintSet::from_task_with_budget(&add_patch, "", parent.path(), Some(1_000));
    assert!(
        matches!(constrained_add, Err(FingerprintError::WorkBudgetExceeded)),
        "adding 20000 functions must yield deterministic budget rejection: {constrained_add:?}"
    );
}

#[test]
fn test_regression_defect2_inline_multiline_string_complete_span() {
    let parent = tempdir().expect("tempdir");
    let base = "def f(): return \"\"\"a\nb\"\"\"\n";
    fs::write(parent.path().join("inline.py"), base).expect("base");

    let patch = "diff --git a/inline.py b/inline.py\n--- a/inline.py\n+++ b/inline.py\n@@ -1,2 +1,2 @@\n-def f(): return \"\"\"a\n+def f(): return \"\"\"c\n b\"\"\"\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let f_fp = &fp.hunks[0].pyc_fingerprints[0];
    assert_eq!(f_fp.function_name, "f");
    assert!(
        f_fp.added.contains("c\nb"),
        "added symbols must contain complete constant 'c\\nb': {:?}",
        f_fp.added
    );
    assert!(
        f_fp.removed.contains("a\nb"),
        "removed symbols must contain complete constant 'a\\nb': {:?}",
        f_fp.removed
    );
    assert!(
        !f_fp.added.contains("c"),
        "added symbols must not fragment inline multiline string into 'c': {:?}",
        f_fp.added
    );

    // Both Python 3.8 and Python 3.11 matchers gate on fixed and non-gate on base
    let fixed_38 = build_pyc_38("f", &[marshal_short_ascii("c\nb")], &[], &[]);
    let base_38 = build_pyc_38("f", &[marshal_short_ascii("a\nb")], &[], &[]);
    assert_both_pyc_matchers(&fp, &fixed_38, &base_38);

    let fixed_311 = build_pyc_311("f", "f", &[marshal_short_ascii("c\nb")], &[], &[]);
    let base_311 = build_pyc_311("f", "f", &[marshal_short_ascii("a\nb")], &[], &[]);
    assert_both_pyc_matchers(&fp, &fixed_311, &base_311);
}

#[test]
fn test_regression_defect3_unary_sign_comparison_operators_and_binary_subtraction() {
    let parent = tempdir().expect("tempdir");

    // 1. Comparison with negative constants
    let base = "def f(x):\n    return x < -3\n";
    fs::write(parent.path().join("cmp.py"), base).expect("base");

    let patch = "diff --git a/cmp.py b/cmp.py\n--- a/cmp.py\n+++ b/cmp.py\n@@ -1,2 +1,2 @@\n def f(x):\n-    return x < -3\n+    return x < -4\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let f_fp = &fp.hunks[0].pyc_fingerprints[0];
    assert!(
        f_fp.added.contains("-4"),
        "canonical signed fingerprint must contain '-4': {:?}",
        f_fp.added
    );
    assert!(
        f_fp.removed.contains("-3"),
        "canonical signed fingerprint must contain '-3': {:?}",
        f_fp.removed
    );
    assert!(
        !f_fp.added.contains("4"),
        "fingerprint must not drop unary sign on comparison operand: {:?}",
        f_fp.added
    );

    // Hand-marshal negative comparison constants for both supported test layouts (3.8 and 3.11)
    let fixed_38 = build_pyc_38("f", &[marshal_int(-4)], &[], &["x"]);
    let base_38 = build_pyc_38("f", &[marshal_int(-3)], &[], &["x"]);
    assert_both_pyc_matchers(&fp, &fixed_38, &base_38);

    let fixed_311 = build_pyc_311("f", "f", &[marshal_int(-4)], &[], &["x"]);
    let base_311 = build_pyc_311("f", "f", &[marshal_int(-3)], &[], &["x"]);
    assert_both_pyc_matchers(&fp, &fixed_311, &base_311);

    // 2. Binary subtraction preservation
    let sub_base = "def g(x):\n    return x - 3\n";
    fs::write(parent.path().join("sub.py"), sub_base).expect("sub base");
    let sub_patch = "diff --git a/sub.py b/sub.py\n--- a/sub.py\n+++ b/sub.py\n@@ -1,2 +1,2 @@\n def g(x):\n-    return x - 3\n+    return x - 4\n";
    let fp_sub = FingerprintSet::from_task(sub_patch, "", parent.path()).expect("fingerprints");
    let g_fp = &fp_sub.hunks[0].pyc_fingerprints[0];
    assert!(
        g_fp.added.contains("4"),
        "binary subtraction must produce positive constant 4: {:?}",
        g_fp.added
    );
    assert!(
        !g_fp.added.contains("-4"),
        "binary subtraction must not be converted into unary negative: {:?}",
        g_fp.added
    );
}

#[test]
fn test_regression_defect4_work_budget_env_var_ignored_in_default_construction() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let parent_dir = tempdir().expect("tempdir");
    let parent = parent_dir.path();

    let base_tree = parent.join("repo");
    fs::create_dir_all(&base_tree).expect("mkdir repo");
    fs::write(base_tree.join("main.py"), "def main():\n    return 1\n").expect("write base");

    let task = parent.join("task");
    fs::create_dir_all(task.join("staging")).expect("mkdir staging");
    fs::create_dir_all(task.join("agent")).expect("mkdir agent");
    let task_json = r#"{
        "schema": "hermetic-slice-task/v1",
        "instance_id": "test__budget_env-1",
        "repo": "test/repo",
        "base_commit": "1234567890abcdef1234567890abcdef12345678",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z"
        }
    }"#;
    fs::write(task.join("task.json"), task_json).expect("write task.json");
    let gold_patch = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,2 @@\n def main():\n-    return 1\n+    return 2\n";
    fs::write(task.join("staging/gold.patch"), gold_patch).expect("write gold.patch");
    fs::write(task.join("staging/test.patch"), "").expect("write test.patch");
    fs::write(
        task.join("agent/problem_statement.md"),
        "A statement of the problem.\n",
    )
    .expect("write problem");

    fn backdate_tree(root: &std::path::Path) {
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_704_067_200);
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    backdate_tree(&path);
                }
                if let Ok(f) = fs::File::open(&path) {
                    let _ = f.set_modified(t);
                }
            }
        }
        if let Ok(f) = fs::File::open(root) {
            let _ = f.set_modified(t);
        }
    }
    backdate_tree(parent);

    let run_scan = |env_val: Option<&str>| {
        let mut cmd = std::process::Command::new(bin_path);
        cmd.arg("scan")
            .arg("--task")
            .arg(&task)
            .arg("--base-tree")
            .arg(&base_tree)
            .arg("--root")
            .arg(&base_tree)
            .arg("--format")
            .arg("json");
        match env_val {
            Some(v) => {
                cmd.env("HERMETIC_FINGERPRINT_WORK_BUDGET", v);
            }
            None => {
                cmd.env_remove("HERMETIC_FINGERPRINT_WORK_BUDGET");
            }
        }
        cmd.output().expect("execute scan")
    };

    let out_unset = run_scan(None);
    let out_zero = run_scan(Some("0"));
    let out_large = run_scan(Some("100000000"));

    assert_eq!(out_unset.status.code(), Some(0));
    assert_eq!(
        out_unset.status.code(),
        out_zero.status.code(),
        "exit status with env unset must match env=0"
    );
    assert_eq!(
        out_unset.status.code(),
        out_large.status.code(),
        "exit status with env unset must match env=100000000"
    );
    assert_eq!(
        out_unset.stdout, out_zero.stdout,
        "stdout with env unset must match env=0"
    );
    assert_eq!(
        out_unset.stdout, out_large.stdout,
        "stdout with env unset must match env=100000000"
    );
    assert_eq!(
        out_unset.stderr, out_zero.stderr,
        "stderr with env unset must match env=0"
    );
    assert_eq!(
        out_unset.stderr, out_large.stderr,
        "stderr with env unset must match env=100000000"
    );

    // Also test CLI query command
    let index_file = parent.join("index.bin");
    let idx_status = std::process::Command::new(bin_path)
        .arg("index")
        .arg("--root")
        .arg(&base_tree)
        .arg("--out")
        .arg(&index_file)
        .status()
        .expect("execute index");
    assert!(idx_status.success(), "index creation must succeed");

    let run_query = |env_val: Option<&str>| {
        let mut cmd = std::process::Command::new(bin_path);
        cmd.arg("query")
            .arg("--task")
            .arg(&task)
            .arg("--base-tree")
            .arg(&base_tree)
            .arg("--index")
            .arg(&index_file)
            .arg("--format")
            .arg("json");
        match env_val {
            Some(v) => {
                cmd.env("HERMETIC_FINGERPRINT_WORK_BUDGET", v);
            }
            None => {
                cmd.env_remove("HERMETIC_FINGERPRINT_WORK_BUDGET");
            }
        }
        cmd.output().expect("execute query")
    };

    let q_unset = run_query(None);
    let q_zero = run_query(Some("0"));
    let q_large = run_query(Some("100000000"));

    assert_eq!(q_unset.status.code(), Some(0));
    assert_eq!(
        q_unset.status.code(),
        q_zero.status.code(),
        "query exit status with env unset must match env=0"
    );
    assert_eq!(
        q_unset.status.code(),
        q_large.status.code(),
        "query exit status with env unset must match env=100000000"
    );
    assert_eq!(
        q_unset.stdout, q_zero.stdout,
        "query stdout with env unset must match env=0"
    );
    assert_eq!(
        q_unset.stdout, q_large.stdout,
        "query stdout with env unset must match env=100000000"
    );
    assert_eq!(
        q_unset.stderr, q_zero.stderr,
        "query stderr with env unset must match env=0"
    );
    assert_eq!(
        q_unset.stderr, q_large.stderr,
        "query stderr with env unset must match env=100000000"
    );
}

// =========================================================================
// T1.12 final review fixes
// =========================================================================

/// Re-runs the test `name` of this binary in a child process with an address-space limit
/// (`ulimit -v`, in KiB) and a wall-clock timeout. The child runs the real work when
/// `env_key` is set. Returns true only when the child finished in time and passed, so a
/// regression that blows up memory or time fails the test instead of the host.
fn passes_in_limited_child(name: &str, env_key: &str, mem_kib: u64, timeout_secs: u64) -> bool {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let exe = std::env::current_exe().expect("test binary");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("ulimit -v \"$1\" || exit 99; exec \"$0\" --exact \"$2\" --test-threads=1 --nocapture")
        .arg(exe)
        .arg(mem_kib.to_string())
        .arg(name)
        .env(env_key, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn child");
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().expect("wait child") {
            Some(status) => return status.success(),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("{name}: child exceeded {timeout_secs}s");
                return false;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// 1.5 GiB of address space for a limited child.
const CHILD_MEM_KIB: u64 = 1536 * 1024;

const PYC_CHILD: &str = "HERMETIC_T112_PYC_CHILD";

/// Finding 3: soft-keyword detection must not rescan earlier tokens inside a long
/// bracketed expression.
#[test]
fn t112_final_finding3_long_bracketed_expression_symbols_are_linear() {
    if std::env::var_os(PYC_CHILD).is_none() {
        assert!(passes_in_limited_child(
            "t112_final_finding3_long_bracketed_expression_symbols_are_linear",
            PYC_CHILD,
            CHILD_MEM_KIB,
            120,
        ));
        return;
    }
    let parent = tempdir().expect("tempdir");
    let n = 100_000;
    let mut base = String::from("X = (\n");
    for _ in 0..n {
        base.push_str("    a,\n");
    }
    base.push_str(")\nY = 1\n");
    fs::write(parent.path().join("table.py"), &base).expect("base");
    let line = n + 3;
    let patch = format!(
        "diff --git a/table.py b/table.py\n--- a/table.py\n+++ b/table.py\n@@ -{line},1 +{line},1 @@\n-Y = 1\n+Y = 2\n"
    );
    let fp = FingerprintSet::from_task(&patch, "", parent.path()).expect("fingerprints");
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .find(|f| f.function_name == "<module>")
        .expect("module fingerprint");
    assert!(pyc_fp.added.contains("2"), "{pyc_fp:?}");
}

/// Finding 3 (semantics kept): soft keywords at a statement start are still skipped, and
/// the same names inside brackets are still symbols.
#[test]
fn t112_final_finding3_soft_keywords_only_at_statement_start() {
    let parent = tempdir().expect("tempdir");
    let base = "def f(command):\n    return 0\n";
    fs::write(parent.path().join("m.py"), base).expect("base");
    let patch = "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,5 @@\n def f(command):\n-    return 0\n+    match command:\n+        case 1:\n+            return {1: match_value(match), 2: [case]}\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .find(|f| f.function_name == "f")
        .expect("f fingerprint");
    assert!(pyc_fp.added.contains("match_value"), "{pyc_fp:?}");
    assert!(pyc_fp.added.contains("match"), "{pyc_fp:?}");
    assert!(pyc_fp.added.contains("case"), "{pyc_fp:?}");
}

fn raw_code_311(
    name: &str,
    consts: &[Vec<u8>],
    names: &[&str],
    localsplusnames: &[&str],
) -> Vec<u8> {
    build_pyc_311(name, name, consts, names, localsplusnames)[16..].to_vec()
}

/// Finding 4: a fix inside a comprehension lives in a nested `<listcomp>` code object on
/// CPython 3.8-3.11 and must still gate the enclosing function.
#[test]
fn t112_final_finding4_comprehension_fix_gates_through_nested_code_object() {
    let parent = tempdir().expect("tempdir");
    let base = "def keep(items):\n    return [x for x in items]\n";
    fs::write(parent.path().join("svc.py"), base).expect("base");
    let patch = "diff --git a/svc.py b/svc.py\n--- a/svc.py\n+++ b/svc.py\n@@ -1,2 +1,2 @@\n def keep(items):\n-    return [x for x in items]\n+    return [x for x in items if x.valid]\n";
    let fp = FingerprintSet::from_task(patch, "", parent.path()).expect("fingerprints");
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprints
        .iter()
        .find(|f| f.function_name == "keep")
        .expect("keep fingerprint");
    assert!(pyc_fp.added.contains("valid"), "{pyc_fp:?}");

    // 3.11 layout: `valid` is only in `<listcomp>.co_names`.
    let fixed_comp = raw_code_311("<listcomp>", &[], &["valid"], &[".0", "x"]);
    let base_comp = raw_code_311("<listcomp>", &[], &[], &[".0", "x"]);
    let fixed_311 = build_pyc_311("keep", "keep", &[fixed_comp], &[], &["items"]);
    let base_311 = build_pyc_311("keep", "keep", &[base_comp], &[], &["items"]);
    let keep = parse_pyc_code_objects(&fixed_311)
        .into_iter()
        .find(|c| c.name == "keep")
        .expect("keep code object");
    assert!(keep.symbols.contains("valid"), "{keep:?}");
    assert_both_pyc_matchers(&fp, &fixed_311, &base_311);

    // 3.8 layout, through a nested genexpr inside the listcomp.
    let fixed_gen = raw_code_38("<genexpr>", &[], &["valid"], &[".0"]);
    let fixed_comp_38 = raw_code_38("<listcomp>", &[fixed_gen], &[], &[".0", "x"]);
    let base_comp_38 = raw_code_38("<listcomp>", &[], &[], &[".0", "x"]);
    let fixed_38 = build_pyc_38("keep", &[fixed_comp_38], &[], &["items"]);
    let base_38 = build_pyc_38("keep", &[base_comp_38], &[], &["items"]);
    assert_both_pyc_matchers(&fp, &fixed_38, &base_38);
}

/// Finding 4 (scope kept): a nested named function is its own scope and is not folded
/// into the enclosing one.
#[test]
fn t112_final_finding4_nested_named_function_is_not_folded() {
    let inner = raw_code_311("helper", &[], &["valid"], &[]);
    let lam = raw_code_311("<lambda>", &[], &["checked"], &["y"]);
    let outer = build_pyc_311("keep", "keep", &[inner, lam], &[], &["items"]);
    let objects = parse_pyc_code_objects(&outer);
    let keep = objects
        .iter()
        .find(|c| c.name == "keep")
        .expect("keep code object");
    assert!(keep.symbols.contains("checked"), "{keep:?}");
    assert!(!keep.symbols.contains("valid"), "{keep:?}");
    assert!(objects.iter().any(|c| c.name == "helper"));
}

// =========================================================================
// T1.12 Codex re-review fixes (2026-11-12)
// =========================================================================

fn marshal_float(v: f64) -> Vec<u8> {
    let mut b = vec![b'g'];
    b.extend_from_slice(&v.to_le_bytes());
    b
}

fn marshal_unicode(s: &str) -> Vec<u8> {
    let mut b = vec![b'u'];
    b.extend_from_slice(&(s.len() as u32).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
    b
}

fn marshal_big_tuple(items: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![b'('];
    b.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for it in items {
        b.extend_from_slice(it);
    }
    b
}

/// A non-negative decimal integer as a marshal `l` object (15-bit digits).
fn marshal_long_decimal(decimal: &str) -> Vec<u8> {
    let mut digits: Vec<u32> = decimal.bytes().map(|b| u32::from(b - b'0')).collect();
    let mut out: Vec<u16> = Vec::new();
    while digits.iter().any(|&d| d != 0) {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + d;
            next.push(cur / 32768);
            rem = cur % 32768;
        }
        out.push(rem as u16);
        digits = next;
    }
    marshal_long(out.len() as i32, &out)
}

/// The fingerprint of a one-file task from `base` to `fixed` (whole-file replacement).
fn task_fp(file: &str, base: &str, fixed: &str) -> (tempfile::TempDir, FingerprintSet) {
    let parent = tempdir().expect("tempdir");
    fs::write(parent.path().join(file), base).expect("base");
    let old: Vec<&str> = base.lines().collect();
    let new: Vec<&str> = fixed.lines().collect();
    let mut patch = format!(
        "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -1,{} +1,{} @@\n",
        old.len(),
        new.len()
    );
    for l in &old {
        patch.push_str(&format!("-{l}\n"));
    }
    for l in &new {
        patch.push_str(&format!("+{l}\n"));
    }
    let fp = FingerprintSet::from_task(&patch, "", parent.path()).expect("fingerprints");
    (parent, fp)
}

fn fp_for<'a>(
    fp: &'a FingerprintSet,
    name: &str,
) -> &'a hermetic_sealcheck::fingerprint::PycFunctionFingerprint {
    fp.hunks
        .iter()
        .flat_map(|h| h.pyc_fingerprints.iter())
        .find(|f| f.function_name == name)
        .unwrap_or_else(|| panic!("no fingerprint for {name}: {:?}", fp.hunks))
}

/// Re-review 1: scope discovery must not clone a long parent path into every child.
#[test]
fn t112_rereview_finding1_long_class_name_many_methods_bounded() {
    const CHILD: &str = "HERMETIC_T112_RR1_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(passes_in_limited_child(
            "t112_rereview_finding1_long_class_name_many_methods_bounded",
            CHILD,
            CHILD_MEM_KIB,
            240,
        ));
        return;
    }
    let class_name = format!("C{}", "x".repeat(1024 * 1024));
    let mut base = format!("class {class_name}:\n");
    for i in 0..10_000 {
        base.push_str(&format!("    def m{i}(self):\n        return {i}\n"));
    }
    let parent = tempdir().expect("tempdir");
    fs::write(parent.path().join("big.py"), &base).expect("base");
    // Change the last method's return value.
    let line = 1 + 2 * 10_000;
    let patch = format!(
        "diff --git a/big.py b/big.py\n--- a/big.py\n+++ b/big.py\n@@ -{line},1 +{line},1 @@\n-        return 9999\n+        return 77777\n"
    );
    use hermetic_sealcheck::fingerprint::FingerprintError;
    match FingerprintSet::from_task(&patch, "", parent.path()) {
        Ok(fp) => assert!(fp_for(&fp, "m9999").added.contains("77777")),
        Err(FingerprintError::WorkBudgetExceeded) => {}
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

/// Re-review 2: `def`, `class` and `async def` separated by tabs are definitions.
#[test]
fn t112_rereview_finding2_tab_separated_definition_headers() {
    let cases = [
        (
            "def\tf():\n    return 2\n",
            "def\tf():\n    return 3\n",
            "f",
        ),
        (
            "class\tC:\n    def\tg(self):\n        return 2\n",
            "class\tC:\n    def\tg(self):\n        return 3\n",
            "g",
        ),
        (
            "async\tdef  \th():\n    return 2\n",
            "async\tdef  \th():\n    return 3\n",
            "h",
        ),
    ];
    for (base, fixed, name) in cases {
        let (_dir, fp) = task_fp("m.py", base, fixed);
        let f = fp_for(&fp, name);
        assert!(f.added.contains("3"), "{f:?}");
        assert!(
            !fp.hunks
                .iter()
                .flat_map(|h| h.pyc_fingerprints.iter())
                .any(|f| f.function_name == "<module>" && f.added.contains("3")),
            "the change must not be attributed to the module"
        );
        let fixed_38 = build_pyc_38(name, &[marshal_int(3)], &[], &[]);
        let base_38 = build_pyc_38(name, &[marshal_int(2)], &[], &[]);
        assert_both_pyc_matchers(&fp, &fixed_38, &base_38);
        let fixed_311 = build_pyc_311(name, name, &[marshal_int(3)], &[], &[]);
        let base_311 = build_pyc_311(name, name, &[marshal_int(2)], &[], &[]);
        assert_both_pyc_matchers(&fp, &fixed_311, &base_311);
    }
}

/// Re-review 3: a triple-quoted default spanning lines does not end the header early.
#[test]
fn t112_rereview_finding3_triple_quoted_default_in_header() {
    let base = "def f(x=\"\"\"a\n):\nb\"\"\"):\n    return x\n";
    let fixed = "def f(x=\"\"\"c\n):\nb\"\"\"):\n    return x\n";
    let (_dir, fp) = task_fp("m.py", base, fixed);
    let module = fp_for(&fp, "<module>");
    assert!(module.added.contains("c\n):\nb"), "{module:?}");
    assert!(module.removed.contains("a\n):\nb"), "{module:?}");
    let code_f = raw_code_38("f", &[], &[], &["x"]);
    let fixed_pyc = build_pyc_38(
        "<module>",
        &[marshal_short_ascii("c\n):\nb"), code_f.clone()],
        &["f"],
        &[],
    );
    let base_pyc = build_pyc_38(
        "<module>",
        &[marshal_short_ascii("a\n):\nb"), code_f],
        &["f"],
        &[],
    );
    assert_both_pyc_matchers(&fp, &fixed_pyc, &base_pyc);
}

/// (base source, fixed source, base consts, fixed consts, base names, fixed names)
type LiteralCase = (
    String,
    String,
    Vec<Vec<u8>>,
    Vec<Vec<u8>>,
    Vec<&'static str>,
    Vec<&'static str>,
);

/// Re-review 4: literals normalised to their compiled form.
#[test]
fn t112_rereview_finding4_literals_match_compiled_constants() {
    let big_base = "1000000000000000000000000000000000000000001";
    let big_fixed = "2000000000000000000000000000000000000000002";
    let underscored = |d: &str| {
        let mut s = String::new();
        for (i, c) in d.chars().enumerate() {
            if i > 0 && (d.len() - i).is_multiple_of(3) {
                s.push('_');
            }
            s.push(c);
        }
        s
    };
    // (base source, fixed source, base consts, fixed consts, base names, fixed names)
    let cases: Vec<LiteralCase> = vec![
        (
            "def f(x):\n    return .3\n".into(),
            "def f(x):\n    return .4\n".into(),
            vec![marshal_float(0.3)],
            vec![marshal_float(0.4)],
            vec![],
            vec![],
        ),
        (
            "def f(x):\n    return \"\\N{BULLET} \\N{em dash} one\"\n".into(),
            "def f(x):\n    return \"\\N{BULLET} \\N{em dash} two\"\n".into(),
            vec![marshal_unicode("\u{2022} \u{2014} one")],
            vec![marshal_unicode("\u{2022} \u{2014} two")],
            vec![],
            vec![],
        ),
        (
            // Decoded from the checked-in Unicode name table.
            "def f(x):\n    return \"\\N{HEAVY BLACK HEART} one\"\n".into(),
            "def f(x):\n    return \"\\N{HEAVY BLACK HEART} two\"\n".into(),
            vec![marshal_unicode("\u{2764} one")],
            vec![marshal_unicode("\u{2764} two")],
            vec![],
            vec![],
        ),
        (
            "def f(x):\n    return f\"v{x.a}\"\n".into(),
            "def f(x):\n    return f\"v{x.b}\"\n".into(),
            vec![marshal_short_ascii("v")],
            vec![marshal_short_ascii("v")],
            vec!["a"],
            vec!["b"],
        ),
        (
            format!("def f(x):\n    return {}\n", underscored(big_base)),
            format!("def f(x):\n    return {}\n", underscored(big_fixed)),
            vec![marshal_long_decimal(big_base)],
            vec![marshal_long_decimal(big_fixed)],
            vec![],
            vec![],
        ),
    ];
    for (base, fixed, base_consts, fixed_consts, base_names, fixed_names) in cases {
        let (_dir, fp) = task_fp("m.py", &base, &fixed);
        let f = fp_for(&fp, "f");
        assert!(!f.added.is_empty(), "{fixed}: {f:?}");
        let fixed_38 = build_pyc_38("f", &fixed_consts, &fixed_names, &["x"]);
        let base_38 = build_pyc_38("f", &base_consts, &base_names, &["x"]);
        assert_both_pyc_matchers(&fp, &fixed_38, &base_38);
        let fixed_311 = build_pyc_311("f", "f", &fixed_consts, &fixed_names, &["x"]);
        let base_311 = build_pyc_311("f", "f", &base_consts, &base_names, &["x"]);
        assert_both_pyc_matchers(&fp, &fixed_311, &base_311);
    }
    // The f-string expression symbols and literal piece are what the fingerprint holds.
    let (_dir, fp) = task_fp(
        "m.py",
        "def f(x):\n    return f\"v{x.a}\"\n",
        "def f(x):\n    return f\"v{x.b}\"\n",
    );
    let f = fp_for(&fp, "f");
    assert!(f.added.contains("b") && f.removed.contains("a"), "{f:?}");
    assert!(
        !f.added.contains("{x.b}") && !f.added.contains("f"),
        "{f:?}"
    );
}

/// Re-review 5: large legitimate constant tables stay within the marshal budgets, and
/// exceeding a real limit is reported as a coverage gap.
#[test]
fn t112_rereview_finding5_large_constant_tables_and_explicit_limit_gap() {
    use hermetic_sealcheck::{parse_pyc_code_objects_outcome, PycParseOutcome};
    let (_dir, fp) = task_fp(
        "m.py",
        "def f():\n    return 2\n",
        "def f():\n    return 3\n",
    );
    let ints: Vec<Vec<u8>> = (0..16_384).map(|i| marshal_int(1000 + i)).collect();
    let floats: Vec<Vec<u8>> = (0..16_384)
        .map(|i| marshal_float(f64::from(i) + 0.5))
        .collect();
    let strings: Vec<Vec<u8>> = (0..2_000)
        .map(|i| marshal_unicode(&format!("{i:05}{}", "s".repeat(1000))))
        .collect();
    let build = |ret: i32| {
        let code_f = raw_code_38("f", &[marshal_int(ret)], &[], &[]);
        build_pyc_38(
            "<module>",
            &[
                marshal_big_tuple(&ints),
                marshal_big_tuple(&floats),
                marshal_big_tuple(&strings),
                code_f,
            ],
            &["f", "TABLE"],
            &[],
        )
    };
    let fixed = build(3);
    let base = build(2);
    match parse_pyc_code_objects_outcome(&fixed) {
        PycParseOutcome::Parsed(objects) => assert!(objects.iter().any(|o| o.name == "f")),
        other => panic!("large legitimate tables must parse: {other:?}"),
    }
    assert_both_pyc_matchers(&fp, &fixed, &base);

    // Nesting past the reader's depth limit is a reported gap, not silence.
    let mut deep = vec![0x55, 0x0d, 0x0d, 0x0a];
    deep.extend_from_slice(&[0u8; 12]);
    for _ in 0..200 {
        deep.extend_from_slice(&[b')', 1]);
    }
    deep.extend_from_slice(&marshal_int(1));
    assert!(matches!(
        parse_pyc_code_objects_outcome(&deep),
        PycParseOutcome::LimitExceeded(_)
    ));
    // A truncated stream is malformed, which is not a coverage gap.
    let truncated = &fixed[..fixed.len() / 2];
    assert_eq!(
        parse_pyc_code_objects_outcome(truncated),
        PycParseOutcome::Malformed
    );

    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("deep.pyc"), &deep).expect("write");
    fs::write(dir.path().join("cut.pyc"), truncated).expect("write");
    let findings = scan_tree(dir.path(), &fp, &ScanOptions::default());
    let gaps: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.channel == "pyc_limit_exceeded")
        .collect();
    assert_eq!(gaps.len(), 1, "{findings:?}");
    assert!(gaps[0].path.ends_with("deep.pyc"));
    assert_eq!(gaps[0].severity, Severity::Info);
}

/// Prior-check 4: `\N{...}` names decode exactly, so a change of only the named character
/// is a fingerprint and the fixed bytecode gates.
#[test]
fn t112_priorcheck_finding4_named_escape_character_only_changes() {
    let cases = [
        // Reviewer's example: two names outside the old built-in table.
        (
            "HEAVY BLACK HEART",
            '\u{2764}',
            "BLACK CHESS KING",
            '\u{265A}',
        ),
        // Formal aliases (correction aliases for U+01A2 / U+01A3).
        (
            "LATIN CAPITAL LETTER GHA",
            '\u{01A2}',
            "latin small letter gha",
            '\u{01A3}',
        ),
        // Algorithmic names.
        (
            "HANGUL SYLLABLE GA",
            '\u{AC00}',
            "HANGUL SYLLABLE GAG",
            '\u{AC01}',
        ),
        (
            "TANGUT IDEOGRAPH-17000",
            '\u{17000}',
            "TANGUT IDEOGRAPH-17001",
            '\u{17001}',
        ),
    ];
    for (base_name, base_char, fixed_name, fixed_char) in cases {
        let base = format!("def f():\n    return \"\\N{{{base_name}}}\"\n");
        let fixed = format!("def f():\n    return \"\\N{{{fixed_name}}}\"\n");
        let (_dir, fp) = task_fp("m.py", &base, &fixed);
        let f = fp_for(&fp, "f");
        assert!(
            f.added.contains(&fixed_char.to_string()),
            "{fixed_name}: {f:?}"
        );
        assert!(
            f.removed.contains(&base_char.to_string()),
            "{base_name}: {f:?}"
        );
        assert!(fp.coverage_gap_findings("task").is_empty());
        let fixed_const = [marshal_unicode(&fixed_char.to_string())];
        let base_const = [marshal_unicode(&base_char.to_string())];
        assert_both_pyc_matchers(
            &fp,
            &build_pyc_38("f", &fixed_const, &[], &[]),
            &build_pyc_38("f", &base_const, &[], &[]),
        );
        assert_both_pyc_matchers(
            &fp,
            &build_pyc_311("f", "f", &fixed_const, &[], &[]),
            &build_pyc_311("f", "f", &base_const, &[], &[]),
        );
    }
}

/// Prior-check 4: a name the table does not know keeps base and fixed distinct and is
/// reported as a coverage gap instead of being silently collapsed.
#[test]
fn t112_priorcheck_finding4_unknown_name_is_a_reported_gap() {
    let (_dir, fp) = task_fp(
        "m.py",
        "def f():\n    return \"\\N{NOT A REAL CHARACTER NAME}\"\n",
        "def f():\n    return \"\\N{ANOTHER MADE UP NAME}\"\n",
    );
    let f = fp_for(&fp, "f");
    assert_eq!(f.added.len(), 1, "{f:?}");
    assert_eq!(f.removed.len(), 1, "{f:?}");
    assert_ne!(f.added, f.removed);
    let gaps = fp.coverage_gap_findings("task.json");
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert_eq!(gaps[0].channel, "pyc_unknown_unicode_name");
    assert_eq!(gaps[0].severity, Severity::Info);
    assert!(gaps[0].evidence.iter().any(|e| e == "ANOTHER MADE UP NAME"));
    assert!(gaps[0]
        .evidence
        .iter()
        .any(|e| e == "NOT A REAL CHARACTER NAME"));
}

/// Prior-check 2: unknown names are tracked out of band, so a literal holding a real
/// U+FFFF does not hide them from the coverage-gap finding.
#[test]
fn t112_priorcheck2_unknown_names_reported_despite_literal_u_ffff() {
    let (_dir, fp) = task_fp(
        "m.py",
        "def f():\n    return \"\u{FFFF}\\N{NOT A REAL CHARACTER NAME}\"\n",
        "def f():\n    return \"\u{FFFF}\\N{ANOTHER MADE UP NAME}\"\n",
    );
    let f = fp_for(&fp, "f");
    assert_eq!(f.added.len(), 1, "{f:?}");
    assert_eq!(f.removed.len(), 1, "{f:?}");
    assert_ne!(f.added, f.removed);
    let gaps = fp.coverage_gap_findings("task.json");
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert_eq!(gaps[0].channel, "pyc_unknown_unicode_name");
    for name in ["ANOTHER MADE UP NAME", "NOT A REAL CHARACTER NAME"] {
        assert!(gaps[0].evidence.iter().any(|e| e == name), "{gaps:?}");
    }
}

/// Prior-check 2: literal text that looks like an unresolved-name encoding is ordinary
/// content: no gap finding, and the change still gates as a plain constant.
#[test]
fn t112_priorcheck2_marker_lookalike_literal_is_not_a_gap() {
    let lookalikes = [
        (
            "\u{FFFF}pyc-unresolved-name:L0:N4:FAKEL0:",
            "\u{FFFF}pyc-unresolved-name:L0:N4:FAKKL0:",
        ),
        (
            "\u{FFFF}\\\\N{FAKE NAME}\u{FFFF}",
            "\u{FFFF}\\\\N{FAKE NAMF}\u{FFFF}",
        ),
    ];
    for (base_lit, fixed_lit) in lookalikes {
        let (_dir, fp) = task_fp(
            "m.py",
            &format!("def f():\n    return \"{base_lit}\"\n"),
            &format!("def f():\n    return \"{fixed_lit}\"\n"),
        );
        assert!(
            fp.coverage_gap_findings("task.json").is_empty(),
            "{base_lit:?}"
        );
        assert!(fp.unresolved_unicode_names.is_empty());
        // `\\` in the source is one backslash in the compiled constant.
        let compiled = |s: &str| s.replace("\\\\", "\\");
        let fixed_const = [marshal_unicode(&compiled(fixed_lit))];
        let base_const = [marshal_unicode(&compiled(base_lit))];
        assert_both_pyc_matchers(
            &fp,
            &build_pyc_38("f", &fixed_const, &[], &[]),
            &build_pyc_38("f", &base_const, &[], &[]),
        );
    }
}
