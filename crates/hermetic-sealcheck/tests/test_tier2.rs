use std::fs;
use std::time::Instant;
use tempfile::tempdir;

use hermetic_sealcheck::scan::{scan_problem_statement, ScanOptions, Severity};
use hermetic_sealcheck::{FingerprintSet, NOT_COVERED};

#[test]
fn test_spec_example_parse_cookie() {
    let base_dir = tempdir().expect("tempdir");
    let base_file = base_dir.path().join("cookies.py");
    fs::write(&base_file, "def parse_cookie(value):\n    return value\n").expect("write base");

    // Add extra common files so common symbols have high df
    for i in 0..10 {
        let f = base_dir.path().join(format!("common_{}.py", i));
        fs::write(&f, "def helper(value):\n    return value\n").expect("write common");
    }

    let gold_patch = "diff --git a/cookies.py b/cookies.py\n--- a/cookies.py\n+++ b/cookies.py\n@@ -1,2 +1,4 @@\n-def parse_cookie(value):\n+def parse_cookie(value, strict=False):\n+    if strict:\n+        return strict_parse(value)\n     return value\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions::default();

    // 1. Matches when anchor and fix symbols are present
    let leak_text = "pass `strict=False` to `parse_cookie` in cookies.py";
    let findings = scan_problem_statement(leak_text, &fp, &opts);
    let t2_findings: Vec<_> = findings.iter().filter(|f| f.channel == "tier2").collect();
    assert_eq!(
        t2_findings.len(),
        1,
        "Expected 1 tier2 finding, got: {findings:?}"
    );
    let f = t2_findings[0];
    assert_eq!(f.detector, "D0");
    assert_eq!(f.severity, Severity::Review);
    assert_eq!(f.hunk, Some(0));
    assert!(
        f.evidence.contains(&"cookies.py".to_string())
            || f.evidence.contains(&"parse_cookie".to_string()),
        "Evidence should contain anchor: {:?}",
        f.evidence
    );
    assert!(
        f.evidence.contains(&"strict".to_string()),
        "Evidence should contain matched symbol strict: {:?}",
        f.evidence
    );

    // 2. Same text without any anchor gives none
    let no_anchor_text = "pass `strict=False` to someone";
    let findings_no_anchor = scan_problem_statement(no_anchor_text, &fp, &opts);
    let t2_no_anchor: Vec<_> = findings_no_anchor
        .iter()
        .filter(|f| f.channel == "tier2")
        .collect();
    assert!(
        t2_no_anchor.is_empty(),
        "Expected no tier2 finding without anchor: {t2_no_anchor:?}"
    );

    // 3. Text with anchor but only common symbols gives none
    let common_only_text = "in cookies.py return value";
    let findings_common = scan_problem_statement(common_only_text, &fp, &opts);
    let t2_common: Vec<_> = findings_common
        .iter()
        .filter(|f| f.channel == "tier2")
        .collect();
    assert!(
        t2_common.is_empty(),
        "Expected no tier2 finding with only common symbols: {t2_common:?}"
    );
}

#[test]
fn test_idf_rare_vs_common_symbol_weights() {
    let base_dir = tempdir().expect("tempdir");

    // 10 base files, all containing common_symbol_name, none containing rare_symbol_name
    for i in 0..10 {
        let f = base_dir.path().join(format!("file_{}.py", i));
        fs::write(
            &f,
            "def worker():\n    common_symbol_name = 42\n    return common_symbol_name\n",
        )
        .expect("write base");
    }

    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,3 @@\n def run():\n+    rare_symbol_name = common_symbol_name\n     pass\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let hunk = &fp.hunks[0];

    let common_weight = hunk
        .tier2_symbols
        .iter()
        .find(|(s, _)| s == "common_symbol_name")
        .map(|(_, w)| *w)
        .expect("common_symbol_name present");

    let rare_weight = hunk
        .tier2_symbols
        .iter()
        .find(|(s, _)| s == "rare_symbol_name")
        .map(|(_, w)| *w)
        .expect("rare_symbol_name present");

    // With N=10, df(common)=10 -> ln(11/11)+1 = 1.0
    // df(rare)=0 -> ln(11/1)+1 ≈ 3.39789
    assert!(
        (common_weight - 1.0).abs() < 1e-4,
        "Common symbol weight should be ~1.0, got {common_weight}"
    );
    assert!(
        rare_weight > 3.0 * common_weight,
        "Rare symbol weight ({rare_weight}) should be > 3x common symbol weight ({common_weight})"
    );
}

#[test]
fn test_attribute_chain_matched_in_prose() {
    let base_dir = tempdir().expect("tempdir");
    let base_file = base_dir.path().join("auth.py");
    fs::write(&base_file, "def check_user(request):\n    return False\n").expect("write base");

    let gold_patch = "diff --git a/auth.py b/auth.py\n--- a/auth.py\n+++ b/auth.py\n@@ -1,2 +1,3 @@\n def check_user(request):\n+    if request.user.is_authenticated:\n     return False\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions::default();

    let prose = "In auth.py ensure that request.user.is_authenticated is checked before proceeding";
    let findings = scan_problem_statement(prose, &fp, &opts);
    let t2_findings: Vec<_> = findings.iter().filter(|f| f.channel == "tier2").collect();

    assert_eq!(
        t2_findings.len(),
        1,
        "Expected tier2 finding for attribute chain in prose: {findings:?}"
    );
    let f = t2_findings[0];
    assert_eq!(f.detector, "D0");
    assert_eq!(f.severity, Severity::Review);
    assert!(
        f.evidence
            .contains(&"request.user.is_authenticated".to_string()),
        "Evidence should contain full dotted attribute chain: {:?}",
        f.evidence
    );
}

#[test]
fn test_malformed_python_tolerated_no_panic() {
    let base_dir = tempdir().expect("tempdir");
    let base_file = base_dir.path().join("broken.py");
    fs::write(&base_file, "def valid():\n    pass\n").expect("write base");

    let gold_patch = "diff --git a/broken.py b/broken.py\n--- a/broken.py\n+++ b/broken.py\n@@ -1,2 +1,3 @@\n def valid():\n+    def (((( this is unparseable syntax +++\n     pass\n";

    // Tree-sitter error nodes are tolerated; must not panic
    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path());
    assert!(
        fp.is_ok(),
        "Malformed python must not cause an error or panic: {:?}",
        fp.err()
    );
}

#[test]
fn test_not_covered_includes_t2() {
    assert!(
        NOT_COVERED.contains(&"T2"),
        "NOT_COVERED must contain 'T2': {:?}",
        NOT_COVERED
    );
}

#[test]
fn test_no_change_to_existing_gate() {
    // Equivalence-style test: check that existing Gate findings are unchanged
    let base_dir = tempdir().expect("tempdir");
    let base_file = base_dir.path().join("core.py");
    fs::write(&base_file, "def compute(x):\n    return x * 2\n").expect("write base");

    let gold_patch = "diff --git a/core.py b/core.py\n--- a/core.py\n+++ b/core.py\n@@ -1,2 +1,3 @@\n def compute(x):\n+    validate_input_signature_completely(x)\n     return x * 2\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions::default();

    // Exact planted code leak triggers Gate finding (tier 1 or 3)
    let planted_code =
        "def compute(x):\n    validate_input_signature_completely(x)\n    return x * 2\n";
    let findings = scan_problem_statement(planted_code, &fp, &opts);

    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        !gates.is_empty(),
        "Gate finding must still trigger on planted code"
    );

    // Because a Gate finding exists for this hunk, no Tier 2 finding is emitted
    let t2: Vec<_> = findings.iter().filter(|f| f.channel == "tier2").collect();
    assert!(
        t2.is_empty(),
        "Tier 2 finding must not be emitted when Gate finding fired: {t2:?}"
    );
}

#[test]
#[ignore]
fn test_perf_building_tier2_2000_files() {
    let base_dir = tempdir().expect("tempdir");

    for i in 0..2000 {
        let p = base_dir.path().join(format!("module_{i}.py"));
        fs::write(
            &p,
            format!("def func_{i}(x):\n    val = x + {i}\n    return val\n"),
        )
        .expect("write synth");
    }

    let gold_patch = "diff --git a/module_0.py b/module_0.py\n--- a/module_0.py\n+++ b/module_0.py\n@@ -1,3 +1,4 @@\n def func_0(x):\n+    special_new_feature_flag(x)\n     val = x + 0\n     return val\n";

    let start = Instant::now();
    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let elapsed = start.elapsed();

    println!("Building Tier 2 for 2,000 files took: {elapsed:?}");
    assert!(
        elapsed.as_secs() < 5,
        "Building Tier 2 took {elapsed:?}, exceeding 5 s budget"
    );
    assert_eq!(fp.hunks.len(), 1);
}
