use hermetic_sealcheck::{
    scan_problem_statement, scan_tree, FingerprintSet, ScanOptions, Severity, Visibility,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_no_false_positive_at_base_and_planted_findings() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();

    // Create base file
    fs::create_dir_all(base_tree.join("app")).expect("mkdir");
    let base_content = "def process_data(items):\n    total = 0\n    for item in items:\n        total += item.value\n    return total\n";
    fs::write(base_tree.join("app/core.py"), base_content).expect("write base");

    let gold_patch = "diff --git a/app/core.py b/app/core.py\n--- a/app/core.py\n+++ b/app/core.py\n@@ -2,3 +2,4 @@\n     total = 0\n     for item in items:\n+        validate_item_security_checks(item)\n         total += item.value\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints built");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // 1. No false positive at base
    let base_findings = scan_tree(base_tree, &fp, &opts);
    let base_gates: Vec<_> = base_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        base_gates.is_empty(),
        "base tree should have 0 gate findings, got: {:?}",
        base_gates
    );

    // 2. Planted copy of the fixed file gives D2 gate
    let target_dir = tempdir().expect("tempdir");
    let fixed_content = "def process_data(items):\n    total = 0\n    for item in items:\n        validate_item_security_checks(item)\n        total += item.value\n    return total\n";
    fs::write(target_dir.path().join("leaked.py"), fixed_content).expect("write fixed");

    let leak_findings = scan_tree(target_dir.path(), &fp, &opts);
    let leak_gates: Vec<_> = leak_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.detector == "D2")
        .collect();
    assert!(
        !leak_gates.is_empty(),
        "planted fixed file must produce a D2 gate"
    );

    // 3. Planted fix.patch gives D2 gate
    let patch_dir = tempdir().expect("tempdir");
    fs::write(patch_dir.path().join("fix.patch"), gold_patch).expect("write patch");
    let patch_findings = scan_tree(patch_dir.path(), &fp, &opts);
    let patch_gates: Vec<_> = patch_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate && f.detector == "D2")
        .collect();
    assert!(
        !patch_gates.is_empty(),
        "planted fix.patch must produce a D2 gate"
    );
}

#[test]
fn test_removed_markdown_bullet_does_not_gate_the_base_tree() {
    // Parsed diff content has already lost its marker; stripping again would turn the
    // removed bullet `- Fixed ...` into a marker that the unchanged base file also yields.
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();
    let base_content = "# Changes\n\n- Fixed issue in the configuration parser\n- Added a retry to the downloader\n";
    fs::write(base_tree.join("CHANGES.md"), base_content).expect("write base");

    let gold_patch = "diff --git a/CHANGES.md b/CHANGES.md\n--- a/CHANGES.md\n+++ b/CHANGES.md\n@@ -1,4 +1,3 @@\n # Changes\n \n-- Fixed issue in the configuration parser\n - Added a retry to the downloader\n";
    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints built");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let base_gates: Vec<_> = scan_tree(base_tree, &fp, &opts)
        .into_iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        base_gates.is_empty(),
        "base tree must not gate: {base_gates:?}"
    );

    // The leaked diff itself is still caught.
    let leaked_dir = tempdir().expect("tempdir");
    fs::write(leaked_dir.path().join("fix.diff"), gold_patch).expect("write leak");
    assert!(
        scan_tree(leaked_dir.path(), &fp, &opts)
            .iter()
            .any(|f| f.severity == Severity::Gate),
        "leaked diff must gate"
    );
}

#[test]
fn test_deletion_only_fix() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();

    let base_content = "def authenticate_user_access(user, token):\n    check_preconditions(user)\n    bypass_security_check_for_debug(user)\n    validate_jwt_token_signature(token)\n    return True\n";
    fs::write(base_tree.join("auth.py"), base_content).expect("write base");

    let gold_patch = "diff --git a/auth.py b/auth.py\n--- a/auth.py\n+++ b/auth.py\n@@ -1,5 +1,4 @@\n def authenticate_user_access(user, token):\n     check_preconditions(user)\n-    bypass_security_check_for_debug(user)\n     validate_jwt_token_signature(token)\n     return True\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints built");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // Base tree gives no gate
    let base_findings = scan_tree(base_tree, &fp, &opts);
    assert!(
        base_findings.iter().all(|f| f.severity != Severity::Gate),
        "base tree must not gate"
    );

    // Leaked diff with deleted line marker
    let leaked_dir = tempdir().expect("tempdir");
    let diff_leak = "diff --git a/auth.py b/auth.py\n-    bypass_security_check_for_debug(user)\n";
    fs::write(leaked_dir.path().join("leak.diff"), diff_leak).expect("write leak diff");

    let leak_findings = scan_tree(leaked_dir.path(), &fp, &opts);
    let gates: Vec<_> = leak_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        !gates.is_empty(),
        "leaked diff of deletion must produce gate finding"
    );

    // Same file content without deletion (plain base file in another dir) gives no gate
    let clean_dir = tempdir().expect("tempdir");
    fs::write(clean_dir.path().join("auth.py"), base_content).expect("write base");
    let clean_findings = scan_tree(clean_dir.path(), &fp, &opts);
    assert!(
        clean_findings.iter().all(|f| f.severity != Severity::Gate),
        "clean file without deletion must not gate"
    );
}

#[test]
fn test_one_character_fix_window_matching() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();

    let base_content = "def validate_positive_number(x):\n    if x > 0:\n        return execute_positive_number_handler(x)\n    return None\n";
    fs::write(base_tree.join("math_ops.py"), base_content).expect("write base");

    let gold_patch = "diff --git a/math_ops.py b/math_ops.py\n--- a/math_ops.py\n+++ b/math_ops.py\n@@ -1,4 +1,4 @@\n def validate_positive_number(x):\n-    if x > 0:\n+    if x >= 0:\n         return execute_positive_number_handler(x)\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints built");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // Base tree gives no gate
    let base_findings = scan_tree(base_tree, &fp, &opts);
    assert!(
        base_findings.iter().all(|f| f.severity != Severity::Gate),
        "base tree must not gate"
    );

    // Planted post-fix file gives gate through window
    let leak_dir = tempdir().expect("tempdir");
    let fixed_content = "def validate_positive_number(x):\n    if x >= 0:\n        return execute_positive_number_handler(x)\n    return None\n";
    fs::write(leak_dir.path().join("math_ops.py"), fixed_content).expect("write fixed");

    let leak_findings = scan_tree(leak_dir.path(), &fp, &opts);
    let gates: Vec<_> = leak_findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        !gates.is_empty(),
        "one-character fix in post-fix file must gate via window"
    );
}

#[test]
fn test_d0_problem_statement_scan() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();

    let base_content = "def helper():\n    pass\n";
    fs::write(base_tree.join("helper.py"), base_content).expect("write base");

    let gold_patch = "diff --git a/helper.py b/helper.py\n--- a/helper.py\n+++ b/helper.py\n@@ -1,2 +1,3 @@\n def helper():\n+    execute_critical_validation_routine()\n     pass\n";

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // Plain problem statement: no gate
    let plain_issue =
        "Users are reporting that the helper routine crashes on startup. Please investigate.\n";
    let plain_findings = scan_problem_statement(plain_issue, &fp, &opts);
    assert!(
        plain_findings.iter().all(|f| f.severity != Severity::Gate),
        "plain issue description must not gate"
    );

    // Problem statement with code fence containing the fixed line
    let leaking_issue = "Here is how to fix it:\n```python\nexecute_critical_validation_routine()\n```\nPlease apply.\n";
    let leak_findings = scan_problem_statement(leaking_issue, &fp, &opts);
    let d0_gates: Vec<_> = leak_findings
        .iter()
        .filter(|f| f.detector == "D0" && f.severity == Severity::Gate)
        .collect();
    assert!(
        !d0_gates.is_empty(),
        "code block with fixed line must produce D0 gate"
    );
}

#[test]
fn test_non_utf8_base_file_is_subtracted_like_the_scanner_reads_it() {
    // A Latin-1 base file already holding the gold line: the scanner decodes it lossily,
    // so the baseline must too, or the line survives subtraction and gates at the base.
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();
    fs::create_dir_all(base_tree.join("app")).expect("mkdir");
    fs::write(
        base_tree.join("app/core.py"),
        "def run():\n    return compute_the_answer()\n",
    )
    .expect("write base");
    let mut latin1 = b"# caf\xe9 notes\n".to_vec();
    latin1.extend_from_slice(b"    validate_item_security_checks(item)\n");
    fs::write(base_tree.join("app/notes_latin1.txt"), latin1).expect("write latin1");

    let gold_patch = "diff --git a/app/core.py b/app/core.py\n--- a/app/core.py\n+++ b/app/core.py\n@@ -1,2 +1,3 @@\n def run():\n+    validate_item_security_checks(item)\n     return compute_the_answer()\n";
    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints built");
    let findings = scan_tree(base_tree, &fp, &ScanOptions::default());
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(gates.is_empty(), "base tree must not gate: {gates:?}");
}

#[cfg(unix)]
#[test]
fn test_unreadable_file_is_reported_not_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempdir().expect("tempdir");
    let locked = root.path().join("locked.py");
    fs::write(&locked, "x = 1\n").expect("write");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(&locked).is_ok() {
        // Running as root: permissions are not enforced, nothing to test.
        return;
    }
    let fp = FingerprintSet::from_task("", "", root.path()).expect("fingerprints built");
    let findings = scan_tree(root.path(), &fp, &ScanOptions::default());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).expect("chmod back");
    assert!(
        findings.iter().any(|f| f.channel == "scan_error"
            && f.severity == Severity::Info
            && f.path.ends_with("locked.py")),
        "unreadable file must produce a scan_error info finding: {findings:?}"
    );
}

#[cfg(unix)]
#[test]
fn test_symlink_to_outside_leak_is_scanned() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();
    fs::write(
        base_tree.join("core.py"),
        "def run():\n    return compute_the_answer()\n",
    )
    .expect("write base");
    let gold_patch = "diff --git a/core.py b/core.py\n--- a/core.py\n+++ b/core.py\n@@ -1,2 +1,3 @@\n def run():\n+    validate_item_security_checks(item)\n     return compute_the_answer()\n";
    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fingerprints built");

    // The leak lives outside every scanned root; the root only holds links to it.
    let outside = tempdir().expect("tempdir");
    let leak = outside.path().join("gold.patch");
    fs::write(&leak, gold_patch).expect("write leak");
    let root = tempdir().expect("tempdir");
    std::os::unix::fs::symlink(&leak, root.path().join("innocent.txt")).expect("symlink");
    std::os::unix::fs::symlink(outside.path(), root.path().join("dirlink")).expect("symlink");
    std::os::unix::fs::symlink(root.path().join("missing"), root.path().join("broken"))
        .expect("symlink");

    let findings = scan_tree(root.path(), &fp, &ScanOptions::default());
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Gate && f.path.ends_with("innocent.txt")),
        "link to a leaked file must gate: {findings:?}"
    );
    for name in ["dirlink", "broken"] {
        assert!(
            findings
                .iter()
                .any(|f| f.channel == "scan_error" && f.path.ends_with(name)),
            "{name} must be reported: {findings:?}"
        );
    }
}

#[test]
fn test_regression_cr1_finding2_base_binary_subtracted_from_text_baseline() {
    let base_dir = tempdir().expect("tempdir");
    let mut binary_content = vec![0u8; 16];
    let lines = "distinctive_shared_line_one = 1001;\ndistinctive_shared_line_two = 2002;\ndistinctive_shared_line_three = 3003;\n";
    binary_content.extend_from_slice(lines.as_bytes());
    fs::write(base_dir.path().join("libsample.so"), &binary_content).expect("write binary");

    let patch = format!(
        "diff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,4 @@\n dummy_line = 0\n+{}\n+{}\n+{}\n",
        "distinctive_shared_line_one = 1001;",
        "distinctive_shared_line_two = 2002;",
        "distinctive_shared_line_three = 3003;"
    );

    let fp = FingerprintSet::from_task(&patch, "", base_dir.path()).expect("fingerprint set");

    let scan_dir = tempdir().expect("tempdir");
    fs::write(scan_dir.path().join("libsample.so"), &binary_content).expect("write scan binary");

    let findings = scan_tree(scan_dir.path(), &fp, &ScanOptions::default());
    let gate_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        gate_findings.is_empty(),
        "base tree binary lines must be subtracted by baseline, but got gate findings: {gate_findings:#?}"
    );

    // Also verify UTF-16 encoded lines in base tree binary file are subtracted
    let utf16_lines =
        "distinctive_utf16_base_line_one = 4004;\ndistinctive_utf16_base_line_two = 5005;\n";
    let mut utf16_binary = vec![0u8; 8];
    for u in utf16_lines.encode_utf16() {
        utf16_binary.extend_from_slice(&u.to_le_bytes());
    }
    fs::write(base_dir.path().join("libutf16.so"), &utf16_binary).expect("write utf16 binary");

    let patch2 = format!(
        "diff --git a/bar.py b/bar.py\n--- a/bar.py\n+++ b/bar.py\n@@ -1,1 +1,3 @@\n dummy_line = 0\n+{}\n+{}\n",
        "distinctive_utf16_base_line_one = 4004;",
        "distinctive_utf16_base_line_two = 5005;"
    );

    let fp2 = FingerprintSet::from_task(&patch2, "", base_dir.path()).expect("fingerprint set 2");
    fs::write(scan_dir.path().join("libutf16.so"), &utf16_binary).expect("write scan utf16 binary");
    let findings2 = scan_tree(scan_dir.path(), &fp2, &ScanOptions::default());
    let gate_findings2: Vec<_> = findings2
        .iter()
        .filter(|f| f.severity == Severity::Gate)
        .collect();
    assert!(
        gate_findings2.is_empty(),
        "base tree utf16 binary lines must be subtracted by baseline: {gate_findings2:#?}"
    );
}
