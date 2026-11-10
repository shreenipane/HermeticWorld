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
