use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};
use tempfile::tempdir;

use hermetic_sealcheck::fingerprint::build_tier2_idf;
use hermetic_sealcheck::scan::{scan_problem_statement, ScanOptions, Severity};
use hermetic_sealcheck::tier2::{
    extract_unit_symbols_and_anchors, find_first_anchor, match_tier2_for_unit,
    match_tier2_with_context,
};
use hermetic_sealcheck::{FingerprintSet, HunkFingerprints, NOT_COVERED};

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

// =========================================================================
// FIX 1: Determinism & Lexicographical Capping for Base-Tree IDF Sample
// =========================================================================
#[test]
fn test_idf_sample_determinism_and_lexicographical_cap() {
    let base_dir = tempdir().expect("tempdir");

    // Create 5 files with names in non-sorted order: c.py, a.py, e.py, b.py, d.py
    fs::write(
        base_dir.path().join("c.py"),
        "def func_c():\n    return 'sym_c'\n",
    )
    .expect("write c");
    fs::write(
        base_dir.path().join("a.py"),
        "def func_a():\n    return 'sym_a'\n",
    )
    .expect("write a");
    fs::write(
        base_dir.path().join("e.py"),
        "def func_e():\n    return 'sym_e'\n",
    )
    .expect("write e");
    fs::write(
        base_dir.path().join("b.py"),
        "def func_b():\n    return 'sym_b'\n",
    )
    .expect("write b");
    fs::write(
        base_dir.path().join("d.py"),
        "def func_d():\n    return 'sym_d'\n",
    )
    .expect("write d");

    let mut symbols = HashSet::new();
    symbols.insert("func_a".to_string());
    symbols.insert("func_b".to_string());
    symbols.insert("func_c".to_string());
    symbols.insert("func_d".to_string());
    symbols.insert("func_e".to_string());

    // Small test cap: max 2 files
    let (weights1, files1) = build_tier2_idf(base_dir.path(), &symbols, 2, 1024 * 1024);
    let (weights2, files2) = build_tier2_idf(base_dir.path(), &symbols, 2, 1024 * 1024);

    // 1. Identical weights on both builds
    assert_eq!(
        weights1, weights2,
        "IDF weights built twice must be identical"
    );

    // 2. Chosen files must be the lexicographically first ones (a.py and b.py)
    assert_eq!(files1.len(), 2);
    assert_eq!(files2.len(), 2);
    let expected_files = vec![base_dir.path().join("a.py"), base_dir.path().join("b.py")];
    assert_eq!(
        files1, expected_files,
        "Chosen files must be lexicographically first"
    );
    assert_eq!(
        files2, expected_files,
        "Chosen files must be lexicographically first"
    );

    // Also test via FingerprintSet::from_task_with_caps
    let gold_patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n def func_a():\n+    return 'sym_a'\n";
    let fp1 = FingerprintSet::from_task_with_caps(gold_patch, "", base_dir.path(), 2, 1024 * 1024)
        .expect("fp1");
    let fp2 = FingerprintSet::from_task_with_caps(gold_patch, "", base_dir.path(), 2, 1024 * 1024)
        .expect("fp2");
    assert_eq!(fp1.hunks[0].tier2_symbols, fp2.hunks[0].tier2_symbols);
    assert_eq!(fp1.tier2_chosen_files, expected_files);
    assert_eq!(fp2.tier2_chosen_files, expected_files);
}

// =========================================================================
// FIX 2: Performance (4 MiB unit + 200 hunks < 2 s) & Unchanged Results
// =========================================================================
#[test]
#[ignore]
fn test_perf_tier2_4mb_unit_200_hunks_under_2s() {
    // 4 MiB unit
    let chunk =
        "The quick brown fox jumps over the lazy dog. In test_module.py we implement something. ";
    let repeat_count = (4 * 1024 * 1024) / chunk.len() + 1;
    let mut large_unit = chunk.repeat(repeat_count);
    large_unit
        .push_str("\nIn test_module.py we call special_rare_feature and finish_action_now.\n");

    let mut hunks = Vec::new();
    for i in 0..200 {
        hunks.push(HunkFingerprints {
            hunk_index: i,
            file_path: "test_module.py".to_string(),
            line_fingerprints: std::collections::HashMap::new(),
            total_line_weight: 0.0,
            window_fingerprints: std::collections::HashMap::new(),
            total_window_weight: 0.0,
            removed_markers: std::collections::HashMap::new(),
            total_removed_weight: 0.0,
            diff_shapes: std::collections::HashMap::new(),
            winnow_fingerprints: std::collections::HashSet::new(),
            binary_items: Vec::new(),
            pyc_fingerprint: None,
            pyc_fingerprints: Vec::new(),
            line_u64: std::collections::BTreeMap::new(),
            window_u64: std::collections::BTreeMap::new(),
            removed_u64: std::collections::BTreeMap::new(),
            tier2_anchors: vec!["test_module.py".to_string(), "test_module".to_string()],
            tier2_symbols: vec![
                ("special_rare_feature".to_string(), 10.0),
                ("finish_action_now".to_string(), 10.0),
            ],
            tier2_total_weight: 20.0,
        });
    }

    let fp = FingerprintSet {
        hunks,
        diff_shape_hashes: std::collections::HashSet::new(),
        diff_shape_u64: std::collections::BTreeMap::new(),
        lines_count: 0,
        windows_count: 0,
        removed_markers_count: 0,
        diff_shapes_count: 0,
        subtracted_count: 0,
        winnow_count: 0,
        winnow_subtracted_count: 0,
        binary_items_count: 0,
        binary_subtracted_count: 0,
        hash_to_evidence: std::collections::HashMap::new(),
        skipped_files_count: 0,
        baseline_incomplete: false,
        baseline_skipped_bytes: 0,
        tier2_capped: false,
        tier2_chosen_files: Vec::new(),
        unresolved_unicode_names: Vec::new(),
        unresolved_unicode_names_omitted: 0,
    };

    let opts = ScanOptions::default();
    let start = Instant::now();
    let (symbols, anchor_tokens) = extract_unit_symbols_and_anchors(&large_unit);
    let mut findings = Vec::new();
    for hunk in &fp.hunks {
        if let Some(f) = hunk.match_tier2_with_context(
            &symbols,
            &anchor_tokens,
            &opts,
            "D0",
            "problem_statement",
        ) {
            findings.push(f);
        }
    }
    let elapsed = start.elapsed();

    println!("Scanning 4 MiB unit with 200 hunks took: {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(2),
        "Perf test took {elapsed:?}, exceeding 2 s budget"
    );
    assert_eq!(findings.len(), 200);
}

#[test]
fn test_tier2_multi_hunk_results_unchanged_with_precomputed_context() {
    let base_dir = tempdir().expect("tempdir");
    let f1 = base_dir.path().join("mod1.py");
    fs::write(&f1, "def action1():\n    return 1\n").expect("write");
    let f2 = base_dir.path().join("mod2.py");
    fs::write(&f2, "def action2():\n    return 2\n").expect("write");

    let gold_patch = "\
diff --git a/mod1.py b/mod1.py
--- a/mod1.py
+++ b/mod1.py
@@ -1,2 +1,3 @@
 def action1():
+    first_rare_sym = other_rare_sym
     return 1
diff --git a/mod2.py b/mod2.py
--- a/mod2.py
+++ b/mod2.py
@@ -1,2 +1,3 @@
 def action2():
+    second_rare_sym = another_rare_sym
     return 2
";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions::default();

    // Unit mentioning mod1 anchor and symbols
    let unit_text = "In mod1.py we set first_rare_sym and other_rare_sym";
    let findings = scan_problem_statement(unit_text, &fp, &opts);
    let t2_findings: Vec<_> = findings.iter().filter(|f| f.channel == "tier2").collect();
    assert_eq!(t2_findings.len(), 1);
    assert_eq!(t2_findings[0].hunk, Some(0));

    // Direct comparison: match_tier2_for_unit vs match_tier2_with_context
    let (symbols, anchors) = extract_unit_symbols_and_anchors(unit_text);
    let f_direct = match_tier2_for_unit(unit_text, &fp.hunks[0], &opts, "D0", "test");
    let f_precomputed =
        match_tier2_with_context(&symbols, &anchors, &fp.hunks[0], &opts, "D0", "test");
    assert_eq!(f_direct, f_precomputed);
}

// =========================================================================
// FIX 3: Deletion Boundary
// =========================================================================
#[test]
fn test_deletion_only_hunk_does_not_treat_neighbor_as_added() {
    let base_dir = tempdir().expect("tempdir");
    let base_file = base_dir.path().join("service.py");
    fs::write(
        &base_file,
        "def cleanup():\n    deleted_symbol = 1\n    rare_neighbor_symbol = 2\n",
    )
    .expect("write base");

    // Patch only deletes the line `deleted_symbol = 1`
    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -2,1 +2,0 @@\n-    deleted_symbol = 1\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let hunk = &fp.hunks[0];

    // The deleted symbol should be in tier2_symbols (from removed lines)
    assert!(
        hunk.tier2_symbols
            .iter()
            .any(|(s, _)| s == "deleted_symbol"),
        "Deleted symbol should be present: {:?}",
        hunk.tier2_symbols
    );

    // The neighboring unchanged line's symbol should NOT be in tier2_symbols
    assert!(
        !hunk
            .tier2_symbols
            .iter()
            .any(|(s, _)| s == "rare_neighbor_symbol"),
        "Neighboring unchanged symbol must NOT be in tier2_symbols: {:?}",
        hunk.tier2_symbols
    );
}

// =========================================================================
// FIX 4: Renames & Base Source Reading
// =========================================================================
#[test]
fn test_rename_plus_edit_extracts_removed_side_symbols() {
    let base_dir = tempdir().expect("tempdir");
    let old_file = base_dir.path().join("old_service.py");
    fs::write(&old_file, "def old_function_to_remove():\n    return 42\n").expect("write base");

    // Patch renames old_service.py to new_service.py and replaces old_function_to_remove
    let gold_patch = "diff --git a/old_service.py b/new_service.py\n--- a/old_service.py\n+++ b/new_service.py\n@@ -1,2 +1,2 @@\n-def old_function_to_remove():\n+def new_function_added():\n     return 42\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let hunk = &fp.hunks[0];

    // Check that removed-side symbol is extracted
    assert!(
        hunk.tier2_symbols
            .iter()
            .any(|(s, _)| s == "old_function_to_remove"),
        "Removed-side symbol 'old_function_to_remove' must be extracted: {:?}",
        hunk.tier2_symbols
    );

    // Check that added-side symbol is extracted
    assert!(
        hunk.tier2_symbols
            .iter()
            .any(|(s, _)| s == "new_function_added"),
        "Added-side symbol 'new_function_added' must be extracted: {:?}",
        hunk.tier2_symbols
    );

    // Check that both new and old anchors are present
    assert!(
        hunk.tier2_anchors.contains(&"new_service.py".to_string())
            || hunk.tier2_anchors.contains(&"new_service".to_string()),
        "New file anchor must be present: {:?}",
        hunk.tier2_anchors
    );
    assert!(
        hunk.tier2_anchors.contains(&"old_service.py".to_string())
            || hunk.tier2_anchors.contains(&"old_service".to_string()),
        "Old file anchor must be present: {:?}",
        hunk.tier2_anchors
    );
}

// =========================================================================
// FIX 5: UTF-8 Panic Prevention & Fuzzing
// =========================================================================
#[test]
fn test_multibyte_anchors_and_units_never_panic() {
    // The review finding defect case: anchor "é", text "éx"
    let anchors = vec!["é".to_string()];
    let res = find_first_anchor("éx", &anchors);
    assert_eq!(res, None); // 'x' is alphanumeric, so not a word boundary

    let res = find_first_anchor("é ", &anchors);
    assert_eq!(res, Some("é"));

    // Multibyte Asian characters
    let anchors_jp = vec!["日本".to_string()];
    let res = find_first_anchor("日本語", &anchors_jp);
    assert_eq!(res, None); // '語' is alphanumeric
    let res = find_first_anchor(" 日本 ", &anchors_jp);
    assert_eq!(res, Some("日本"));

    // Emojis in anchors and text
    let anchors_emoji = vec!["🦀".to_string(), "🚀".to_string()];
    let res = find_first_anchor("Hello 🦀 World! 🚀", &anchors_emoji);
    assert_eq!(res, Some("🦀"));

    // Complex UTF-8 text with mixed multibyte characters
    let complex_text = "こんにちは世界！Café naïve résumé 🦀🔥🎉. Def fix_bug(): pass";
    let anchors_mixed = vec!["Café".to_string(), "世界".to_string()];
    let res = find_first_anchor(complex_text, &anchors_mixed);
    assert!(res.is_some());
}

#[test]
fn test_fuzz_anchor_and_unit_matching_never_panics() {
    let sample_chars: Vec<char> = vec![
        'a', 'Z', '0', '_', '.', '-', ' ', '\n', '\t', 'é', 'ü', 'ñ', 'ø', 'ç', '日', '本', '語',
        '中', '文', '한', '글', '🦀', '🔥', '🚀', '✨', '🎉', '\u{0000}', '\u{0080}', '\u{07FF}',
        '\u{FFFF}',
    ];

    // Deterministic pseudo-random number generator (LCG)
    let mut rng_state: u64 = 0xdeadbeef12345678;
    let mut next_u32 = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (rng_state >> 32) as u32
    };

    for _ in 0..1000 {
        let text_len = (next_u32() % 50) as usize + 1;
        let mut text = String::new();
        for _ in 0..text_len {
            let idx = (next_u32() as usize) % sample_chars.len();
            text.push(sample_chars[idx]);
        }

        let num_anchors = (next_u32() % 5) as usize + 1;
        let mut anchors = Vec::new();
        for _ in 0..num_anchors {
            let a_len = (next_u32() % 10) as usize;
            let mut anchor = String::new();
            for _ in 0..a_len {
                let idx = (next_u32() as usize) % sample_chars.len();
                anchor.push(sample_chars[idx]);
            }
            anchors.push(anchor);
        }

        // None of these must ever panic
        let _ = find_first_anchor(&text, &anchors);
        let _ = extract_unit_symbols_and_anchors(&text);
    }
}

// =========================================================================
// REVIEW 2 - FIX 1: Prose-Aware Anchor and Symbol Scanning
// =========================================================================
#[test]
fn test_markdown_heading_file_anchor_service_py() {
    let base_dir = tempdir().expect("tempdir");

    for i in 0..10 {
        let f = base_dir.path().join(format!("common_{}.py", i));
        fs::write(
            &f,
            "def worker():\n    common_sym = 1\n    return common_sym\n",
        )
        .expect("write common");
    }

    let gold_patch = "diff --git a/service.py b/service.py\n--- a/service.py\n+++ b/service.py\n@@ -1,2 +1,4 @@\n def run():\n+    rare_alpha = compute_rare()\n+    rare_beta = format_rare(rare_alpha)\n     pass\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions::default();

    // Problem statement whose only mention of the file is the heading "# service.py"
    // and whose body names the rare symbols
    let problem_statement = "# service.py\n\nPlease fix the bug by implementing rare_alpha and rare_beta in the service.";
    let findings = scan_problem_statement(problem_statement, &fp, &opts);
    let t2_findings: Vec<_> = findings.iter().filter(|f| f.channel == "tier2").collect();

    assert_eq!(
        t2_findings.len(),
        1,
        "Expected 1 tier2 finding for markdown heading '# service.py', got: {findings:?}"
    );
    let f = t2_findings[0];
    assert_eq!(f.detector, "D0");
    assert_eq!(f.severity, Severity::Review);
    assert_eq!(f.hunk, Some(0));
    assert!(
        f.evidence.contains(&"service.py".to_string())
            || f.evidence.contains(&"service".to_string()),
        "Evidence must contain file anchor 'service.py': {:?}",
        f.evidence
    );
    assert!(
        f.evidence.contains(&"rare_alpha".to_string())
            || f.evidence.contains(&"rare_beta".to_string()),
        "Evidence must contain rare symbols: {:?}",
        f.evidence
    );
}

#[test]
fn test_markdown_heading_function_anchor_parse_cookie() {
    let base_dir = tempdir().expect("tempdir");
    let base_file = base_dir.path().join("cookies.py");
    fs::write(&base_file, "def parse_cookie(value):\n    return value\n").expect("write base");

    for i in 0..10 {
        let f = base_dir.path().join(format!("common_{}.py", i));
        fs::write(
            &f,
            "def worker():\n    common_sym = 1\n    return common_sym\n",
        )
        .expect("write common");
    }

    let gold_patch = "diff --git a/cookies.py b/cookies.py\n--- a/cookies.py\n+++ b/cookies.py\n@@ -1,2 +1,4 @@\n def parse_cookie(value):\n+    rare_cookie_attr = compute_cookie_attr(value)\n+    validate_cookie_strict(rare_cookie_attr)\n     return value\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");
    let opts = ScanOptions::default();

    // 1. "## parse_cookie" works as a function anchor
    let problem_statement =
        "## parse_cookie\n\nFix with rare_cookie_attr and validate_cookie_strict.";
    let findings = scan_problem_statement(problem_statement, &fp, &opts);
    let t2_findings: Vec<_> = findings.iter().filter(|f| f.channel == "tier2").collect();

    assert_eq!(
        t2_findings.len(),
        1,
        "Expected 1 tier2 finding for markdown heading '## parse_cookie', got: {findings:?}"
    );
    let f = t2_findings[0];
    assert_eq!(f.detector, "D0");
    assert_eq!(f.severity, Severity::Review);
    assert!(
        f.evidence.contains(&"parse_cookie".to_string()),
        "Evidence must contain function anchor 'parse_cookie': {:?}",
        f.evidence
    );

    // 2. "## Fix in parse_cookie" also works as a function anchor
    let heading_with_prose =
        "## Fix in parse_cookie\n\nEnsure rare_cookie_attr and validate_cookie_strict are handled.";
    let findings_prose = scan_problem_statement(heading_with_prose, &fp, &opts);
    let t2_prose: Vec<_> = findings_prose
        .iter()
        .filter(|f| f.channel == "tier2")
        .collect();
    assert_eq!(
        t2_prose.len(),
        1,
        "Expected 1 tier2 finding for '## Fix in parse_cookie', got: {findings_prose:?}"
    );
    assert!(
        t2_prose[0].evidence.contains(&"parse_cookie".to_string()),
        "Evidence must contain function anchor 'parse_cookie': {:?}",
        t2_prose[0].evidence
    );
}

// =========================================================================
// REVIEW 2 - FIX 2: IDF Sample Excludes Binary and Unreadable Files
// =========================================================================
#[test]
fn test_idf_sample_excludes_binary_and_unreadable_files_and_both_paths_match() {
    let base_dir = tempdir().expect("tempdir");

    // 1. A valid readable .py file
    let valid_file = base_dir.path().join("valid.py");
    fs::write(
        &valid_file,
        "def valid_func():\n    rare_symbol = 123\n    return rare_symbol\n",
    )
    .expect("write valid");

    // 2. A binary .py file (contains NUL byte in first 8 KiB)
    let binary_file = base_dir.path().join("binary.py");
    fs::write(&binary_file, b"def broken():\x00\x01\x02pass\n").expect("write binary");

    // 3. An unreadable .py file (cfg(unix), chmod 000; skip if running as root)
    let mut has_unreadable = false;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unreadable_file = base_dir.path().join("unreadable.py");
        fs::write(&unreadable_file, "def secret(): pass\n").expect("write unreadable");
        let mut perms = fs::metadata(&unreadable_file)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&unreadable_file, perms.clone()).expect("set perms");

        // Skip the unreadable part when running as root (root ignores 000 permissions)
        if fs::read(&unreadable_file).is_ok() {
            perms.set_mode(0o644);
            let _ = fs::set_permissions(&unreadable_file, perms);
            let _ = fs::remove_file(&unreadable_file);
        } else {
            has_unreadable = true;
        }
    }

    let gold_patch = "diff --git a/valid.py b/valid.py\n--- a/valid.py\n+++ b/valid.py\n@@ -1,3 +1,4 @@\n def valid_func():\n+    rare_symbol = 123\n     return rare_symbol\n";

    // Path 1: FingerprintSet::from_task
    let fp = FingerprintSet::from_task(gold_patch, "", base_dir.path()).expect("fp");

    // Path 2: build_tier2_idf
    let mut symbols = HashSet::new();
    symbols.insert("valid_func".to_string());
    symbols.insert("rare_symbol".to_string());
    let (weights, chosen_files) = build_tier2_idf(
        base_dir.path(),
        &symbols,
        FingerprintSet::DEFAULT_TIER2_MAX_FILES,
        FingerprintSet::DEFAULT_TIER2_MAX_BYTES,
    );

    // Both paths must exclude binary.py and unreadable.py
    assert_eq!(
        fp.tier2_chosen_files,
        vec![valid_file.clone()],
        "Path 1 (from_task) should only contain valid.py"
    );
    assert_eq!(
        chosen_files,
        vec![valid_file.clone()],
        "Path 2 (build_tier2_idf) should only contain valid.py"
    );

    let n_path1 = fp.tier2_chosen_files.len();
    let n_path2 = chosen_files.len();
    assert_eq!(
        n_path1, 1,
        "N should be 1 (excluding binary and unreadable files)"
    );
    assert_eq!(
        n_path2, 1,
        "N should be 1 (excluding binary and unreadable files)"
    );

    // Weights via both paths must be identical
    for (sym, w1) in &fp.hunks[0].tier2_symbols {
        if let Some(w2) = weights.get(sym) {
            assert!(
                (w1 - w2).abs() < 1e-6,
                "Weights for symbol {sym} must match across both paths: {w1} vs {w2}"
            );
        }
    }

    // Clean up permissions on unix so tempdir can be deleted cleanly
    #[cfg(unix)]
    if has_unreadable {
        use std::os::unix::fs::PermissionsExt;
        let unreadable_file = base_dir.path().join("unreadable.py");
        if unreadable_file.exists() {
            let mut perms = fs::metadata(&unreadable_file)
                .expect("metadata")
                .permissions();
            perms.set_mode(0o644);
            let _ = fs::set_permissions(&unreadable_file, perms);
        }
    }
}

// =========================================================================
// T1.12 final review, finding 1: bounded tier-2 context extraction
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

fn dotted_chain(parts: usize) -> String {
    (0..parts)
        .map(|i| format!("p{i:04}"))
        .collect::<Vec<_>>()
        .join(".")
}

fn context_bytes(ctx: &hermetic_sealcheck::tier2::Tier2UnitContext) -> usize {
    ctx.symbols
        .iter()
        .chain(ctx.anchor_tokens.iter())
        .map(String::len)
        .sum()
}

const T2_CHILD: &str = "HERMETIC_T112_TIER2_CHILD";

#[test]
fn t112_final_finding1_long_dotted_chain_extraction_is_bounded() {
    if std::env::var_os(T2_CHILD).is_none() {
        assert!(passes_in_limited_child(
            "t112_final_finding1_long_dotted_chain_extraction_is_bounded",
            T2_CHILD,
            CHILD_MEM_KIB,
            120,
        ));
        return;
    }
    // A 12 KB `p0000.p0001.….p1999` unit used to produce ~2M sub-chains of ~4 KB each.
    let text = dotted_chain(2000);
    assert!(text.len() < 13 * 1024);
    let ctx = hermetic_sealcheck::tier2::extract_unit_tier2_context(&text);
    assert!(!ctx.truncated);
    let bytes = context_bytes(&ctx);
    assert!(
        bytes < 16 * 1024 * 1024,
        "12 KB unit must stay within a small memory bound, got {bytes} bytes"
    );
    // Short chains, single parts and the whole token are still recorded.
    assert!(ctx.symbols.contains("p0007"));
    assert!(ctx.symbols.contains("p0007.p0008.p0009"));
    assert!(ctx.anchor_tokens.contains(&text));
}

#[test]
fn t112_final_finding1_extraction_stops_at_budget_and_reports_truncation() {
    if std::env::var_os(T2_CHILD).is_none() {
        assert!(passes_in_limited_child(
            "t112_final_finding1_extraction_stops_at_budget_and_reports_truncation",
            T2_CHILD,
            CHILD_MEM_KIB,
            120,
        ));
        return;
    }
    let text = format!("{} trailing_symbol", dotted_chain(20_000));
    let ctx = hermetic_sealcheck::tier2::extract_unit_tier2_context_with_limit(&text, 1024 * 1024);
    assert!(
        ctx.truncated,
        "an oversized context must be reported as truncated"
    );
    let bytes = context_bytes(&ctx);
    assert!(bytes <= 1024 * 1024, "stored {bytes} bytes past the limit");

    let small = hermetic_sealcheck::tier2::extract_unit_tier2_context("call `obj.attr.method` now");
    assert!(!small.truncated);
    assert!(small.symbols.contains("obj.attr.method"));
    assert!(small.symbols.contains("attr.method"));
}
