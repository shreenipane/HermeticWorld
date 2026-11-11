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

    let gold_patch = "diff --git a/multiline.py b/multiline.py\n--- a/multiline.py\n+++ b/multiline.py\n@@ -4,2 +4,2 @@\n-    return a + b\n+    return a + b + 7\n";
    let fp = FingerprintSet::from_task(gold_patch, "", &base_dir).expect("fingerprints");

    assert_eq!(fp.hunks.len(), 1);
    let pyc_fp = fp.hunks[0]
        .pyc_fingerprint
        .as_ref()
        .expect("pyc fingerprint");
    assert_eq!(pyc_fp.function_name, "compute");
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
