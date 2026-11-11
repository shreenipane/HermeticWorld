use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity, Visibility};
use time::OffsetDateTime;

fn run_git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Test Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_AUTHOR_DATE", "2025-01-01T00:00:00Z")
        .env("GIT_COMMITTER_NAME", "Test Committer")
        .env("GIT_COMMITTER_EMAIL", "committer@example.com")
        .env("GIT_COMMITTER_DATE", "2025-01-01T00:00:00Z")
        .env("HOME", dir.display().to_string())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git execution failed");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn setup_base_repo(dir: &Path) -> (String, FingerprintSet, PathBuf) {
    run_git(dir, &["init", "-b", "main"]);
    run_git(dir, &["config", "user.name", "Test Committer"]);
    run_git(dir, &["config", "user.email", "committer@example.com"]);

    let file_path = dir.join("main.py");
    fs::write(&file_path, "def run():\n    pass\n").unwrap();
    run_git(dir, &["add", "main.py"]);
    run_git(dir, &["commit", "-m", "base commit"]);

    let base_commit = run_git(dir, &["rev-parse", "HEAD"]);
    let _ = fs::remove_dir_all(dir.join(".git/logs"));

    let gold_patch = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,3 @@\n def run():\n+    execute_critical_leak_line()\n     pass\n";
    let base_tree_dir = tempfile::tempdir().unwrap();
    fs::write(
        base_tree_dir.path().join("main.py"),
        "def run():\n    pass\n",
    )
    .unwrap();
    let fp = FingerprintSet::from_task(gold_patch, "", base_tree_dir.path()).unwrap();

    let base_tree_path = base_tree_dir.path().to_path_buf();
    let _ = base_tree_dir.keep();
    (base_commit, fp, base_tree_path)
}

fn t_clock() -> OffsetDateTime {
    time::macros::datetime!(2026-01-01 00:00:00 UTC)
}

fn scan_d1(
    repo_dir: &Path,
    base_commit: String,
    fp: &FingerprintSet,
) -> Vec<hermetic_sealcheck::Finding> {
    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };
    scan_tree(repo_dir, fp, &opts)
        .into_iter()
        .filter(|f| f.detector == "D1" && f.severity == Severity::Gate)
        .collect()
}

fn has_channel(findings: &[hermetic_sealcheck::Finding], channel: &str) -> bool {
    findings.iter().any(|f| f.channel == channel)
}

#[test]
fn test_d1_non_utf8_commit_keeps_history_reachable() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (_, fp, _base_tree) = setup_base_repo(repo_dir);

    // A Latin-1 commit in the middle of the history must not cut the walk off.
    fs::write(repo_dir.join("second.py"), "print('second')\n").unwrap();
    fs::write(repo_dir.join("msg.txt"), b"caf\xe9 commit\n").unwrap();
    run_git(repo_dir, &["add", "second.py"]);
    run_git(
        repo_dir,
        &[
            "-c",
            "i18n.commitEncoding=ISO-8859-1",
            "commit",
            "-F",
            "msg.txt",
        ],
    );
    fs::write(repo_dir.join("third.py"), "print('third')\n").unwrap();
    run_git(repo_dir, &["add", "third.py"]);
    run_git(repo_dir, &["commit", "-m", "top commit"]);
    let head = run_git(repo_dir, &["rev-parse", "HEAD"]);
    let _ = fs::remove_dir_all(repo_dir.join(".git/logs"));

    let gates = scan_d1(repo_dir, head, &fp);
    assert!(gates.is_empty(), "expected no D1 gates, got: {gates:?}");
}

#[cfg(unix)]
#[test]
fn test_d1_non_utf8_file_name_keeps_tree_reachable() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (_, fp, _base_tree) = setup_base_repo(repo_dir);

    fs::write(repo_dir.join(OsStr::from_bytes(b"caf\xe9.txt")), "x\n").unwrap();
    run_git(repo_dir, &["add", "-A"]);
    run_git(repo_dir, &["commit", "-m", "odd name"]);
    let head = run_git(repo_dir, &["rev-parse", "HEAD"]);
    let _ = fs::remove_dir_all(repo_dir.join(".git/logs"));

    let gates = scan_d1(repo_dir, head, &fp);
    assert!(gates.is_empty(), "expected no D1 gates, got: {gates:?}");
}

#[test]
fn test_d1_text_named_idx_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let pack_dir = repo_dir.join(".git/objects/pack");
    fs::create_dir_all(&pack_dir).unwrap();
    fs::write(
        pack_dir.join("notes.idx"),
        "def run():\n    execute_critical_leak_line()\n",
    )
    .unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_unknown_file"), "got: {gates:?}");
    assert!(has_channel(&gates, "git_unsupported"), "got: {gates:?}");
}

#[test]
fn test_d1_pack_without_idx_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let pack_dir = repo_dir.join(".git/objects/pack");
    fs::create_dir_all(&pack_dir).unwrap();
    let name = format!("pack-{}.pack", "a".repeat(40));
    fs::write(pack_dir.join(name), b"PACK\0\0\0\x02\0\0\0\0").unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_unknown_file"), "got: {gates:?}");
}

#[test]
fn test_d1_oddly_named_pack_file_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let pack_dir = repo_dir.join(".git/objects/pack");
    fs::create_dir_all(&pack_dir).unwrap();
    fs::write(pack_dir.join("leak.rev"), "execute_critical_leak_line()\n").unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_unknown_file"), "got: {gates:?}");
}

#[test]
fn test_d1_pack_count_differing_from_idx_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);
    run_git(repo_dir, &["repack", "-adq"]);

    let pack_dir = repo_dir.join(".git/objects/pack");
    let pack = fs::read_dir(&pack_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "pack"))
        .unwrap();
    let mut bytes = fs::read(&pack).unwrap();
    bytes[11] = bytes[11].wrapping_add(1);
    let mut perms = fs::metadata(&pack).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&pack, perms).unwrap();
    fs::write(&pack, bytes).unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_corrupt"), "got: {gates:?}");
}

#[test]
fn test_d1_symbolic_ref_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let dir = repo_dir.join(".git/refs/remotes/origin");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("HEAD"), "ref: refs/remotes/origin/main\n").unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_ref"), "got: {gates:?}");
}

#[test]
fn test_d1_inner_tag_of_a_chain_is_checked() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let leak = "def run():\n    execute_critical_leak_line()\n    pass\n";
    run_git(repo_dir, &["tag", "-a", "inner", "-m", leak, &base_commit]);
    run_git(repo_dir, &["tag", "-a", "outer", "-m", "harmless", "inner"]);
    run_git(repo_dir, &["tag", "-d", "inner"]);

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_tag"), "got: {gates:?}");
}

#[cfg(unix)]
#[test]
fn test_d1_symlinks_can_not_hide() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    std::os::unix::fs::symlink("/etc/hostname", repo_dir.join(".git/objects/stash")).unwrap();
    std::fs::create_dir_all(repo_dir.join("sub")).unwrap();
    std::os::unix::fs::symlink("/somewhere/else", repo_dir.join("sub/.git")).unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_unknown_file"), "got: {gates:?}");
    assert!(has_channel(&gates, "git_pointer"), "got: {gates:?}");
}

#[test]
fn test_d1_pass() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Old annotated tag before T_clock
    run_git(
        repo_dir,
        &["tag", "-a", "v1.0", "-m", "release v1.0", &base_commit],
    );
    let _ = fs::remove_dir_all(repo_dir.join(".git/logs"));

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    let d1_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D1" && f.severity == Severity::Gate)
        .collect();

    assert!(
        d1_gates.is_empty(),
        "expected 0 D1 gates for clean repo, got: {:?}",
        d1_gates
    );
}

#[test]
fn test_d1_commit_after_base() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Future commit
    fs::write(
        repo_dir.join("main.py"),
        "def run():\n    # future\n    pass\n",
    )
    .unwrap();
    run_git(repo_dir, &["add", "main.py"]);
    run_git(repo_dir, &["commit", "-m", "future commit"]);
    // Reset branch back to base so HEAD stays at base, leaving future commit dangling/unreachable
    run_git(repo_dir, &["reset", "--hard", &base_commit]);

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_unreachable_object"),
        "expected git_unreachable_object finding"
    );
}

#[test]
fn test_d1_dangling_blob_fixed_lines() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Write dangling blob with fixed lines
    let leaked_content = "def run():\n    execute_critical_leak_line()\n    pass\n";
    let mut child = Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(leaked_content.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let blob_oid = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_unreachable_object"),
        "expected git_unreachable_object"
    );

    let expected_path = format!("{}#{}", repo_dir.join(".git").display(), blob_oid);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D2" && f.severity == Severity::Gate && f.path == expected_path),
        "expected D2 gate finding at {}",
        expected_path
    );
}

#[test]
fn test_d1_dangling_blob_tar_gz_fixed_lines() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Build tar.gz holding fixed lines
    let mut tar_bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let leaked_content = b"def run():\n    execute_critical_leak_line()\n    pass\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(leaked_content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "leaked.py", &leaked_content[..])
            .unwrap();
        tar.finish().unwrap();
    }

    let mut child = Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&tar_bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    let blob_oid = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    let expected_subpath = format!(
        "{}#{}!/leaked.py",
        repo_dir.join(".git").display(),
        blob_oid
    );
    assert!(
        findings.iter().any(|f| f.detector == "D2"
            && f.severity == Severity::Gate
            && f.path == expected_subpath),
        "expected D2 gate finding inside archive member at {}",
        expected_subpath
    );
}

#[test]
fn test_d1_ref_pull() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let pull_ref = repo_dir.join(".git/refs/pull/1/head");
    fs::create_dir_all(pull_ref.parent().unwrap()).unwrap();
    fs::write(pull_ref, format!("{}\n", base_commit)).unwrap();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_ref"),
        "expected git_ref finding for refs/pull/1/head"
    );
}

#[test]
fn test_d1_ref_only_in_packed_refs() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Create a pull ref and pack it
    let pull_ref = repo_dir.join(".git/refs/pull/1/head");
    fs::create_dir_all(pull_ref.parent().unwrap()).unwrap();
    fs::write(&pull_ref, format!("{}\n", base_commit)).unwrap();
    run_git(repo_dir, &["pack-refs", "--all", "--prune"]);
    assert!(!pull_ref.exists(), "loose ref pruned");

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_ref"),
        "expected git_ref finding for ref only in packed-refs"
    );
}

#[test]
fn test_d1_reflog() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let logs_dir = repo_dir.join(".git/logs");
    fs::create_dir_all(&logs_dir).unwrap();
    fs::write(logs_dir.join("HEAD"), "reflog entry\n").unwrap();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_state_file"),
        "expected git_state_file for logs/"
    );
}

#[test]
fn test_d1_orig_head() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    fs::write(
        repo_dir.join(".git/ORIG_HEAD"),
        format!("{}\n", base_commit),
    )
    .unwrap();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_state_file"),
        "expected git_state_file for ORIG_HEAD"
    );
}

#[test]
fn test_d1_alternates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let info_dir = repo_dir.join(".git/objects/info");
    fs::create_dir_all(&info_dir).unwrap();
    fs::write(info_dir.join("alternates"), "/path/to/alt\n").unwrap();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_state_file"),
        "expected git_state_file for alternates"
    );
}

#[test]
fn test_d1_tag_after_t_clock() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Tag created with date after T_clock (2027-01-01)
    let output = Command::new("git")
        .args([
            "tag",
            "-a",
            "future-tag",
            "-m",
            "tag after T_clock",
            &base_commit,
        ])
        .current_dir(repo_dir)
        .env("GIT_COMMITTER_DATE", "2027-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(output.status.success());

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_tag"),
        "expected git_tag gate finding for tag after T_clock"
    );
}

#[test]
fn test_d1_tag_on_non_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Create an orphan commit
    run_git(repo_dir, &["checkout", "--orphan", "other"]);
    fs::write(repo_dir.join("other.txt"), "other").unwrap();
    run_git(repo_dir, &["add", "other.txt"]);
    run_git(repo_dir, &["commit", "-m", "other commit"]);
    let orphan_commit = run_git(repo_dir, &["rev-parse", "HEAD"]);

    // Tag the orphan commit
    run_git(
        repo_dir,
        &["tag", "-a", "orphan-tag", "-m", "msg", &orphan_commit],
    );

    // Switch back to main
    run_git(repo_dir, &["checkout", "main"]);

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_tag"),
        "expected git_tag gate finding for non-ancestor tag"
    );
}

#[test]
fn test_d1_stray_objects_file() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    fs::write(repo_dir.join(".git/objects/leak.txt"), "hidden text").unwrap();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_unknown_file"),
        "expected git_unknown_file gate finding for objects/leak.txt"
    );
}

#[test]
fn test_d1_pointer_file() {
    let temp = tempfile::tempdir().unwrap();
    let worktree_dir = temp.path();

    // A .git file pointing to gitdir
    fs::write(worktree_dir.join(".git"), "gitdir: /some/path/.git\n").unwrap();
    let base_tree = tempfile::tempdir().unwrap();
    let fp = FingerprintSet::from_task("", "", base_tree.path()).unwrap();

    let opts = ScanOptions::default();
    let findings = scan_tree(worktree_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_pointer"),
        "expected git_pointer gate finding for .git pointer file"
    );
}

#[test]
fn test_d1_head_not_at_base() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (_base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Commit again so HEAD advances past base commit
    fs::write(repo_dir.join("second.txt"), "second").unwrap();
    run_git(repo_dir, &["add", "second.txt"]);
    run_git(repo_dir, &["commit", "-m", "second commit"]);

    let original_base = run_git(repo_dir, &["rev-parse", "HEAD~1"]);

    let opts = ScanOptions {
        base_commit: Some(original_base),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_head"),
        "expected git_head gate finding when HEAD is not at base commit"
    );
}

#[test]
fn test_d1_remote_origin_section() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    run_git(
        repo_dir,
        &["remote", "add", "origin", "https://github.com/foo/bar.git"],
    );

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_config"),
        "expected git_config gate finding for remote section"
    );
}

#[test]
fn test_d1_base_commit_absent() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (_base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let absent_commit = "0123456789abcdef0123456789abcdef01234567".to_string();
    let opts = ScanOptions {
        base_commit: Some(absent_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_base_missing"),
        "expected git_base_missing gate finding"
    );
}

#[test]
fn test_commit_graph_reachable_passes() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Write commit-graph for reachable commits
    run_git(repo_dir, &["commit-graph", "write", "--reachable"]);

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        !findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_commit_graph"),
        "reachable commit-graph should produce 0 git_commit_graph findings"
    );
}

#[test]
fn test_commit_graph_future_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    // Add future commit
    fs::write(repo_dir.join("future.txt"), "future").unwrap();
    run_git(repo_dir, &["add", "future.txt"]);
    run_git(repo_dir, &["commit", "-m", "future commit"]);
    // Write commit graph that includes future commit
    run_git(repo_dir, &["commit-graph", "write", "--reachable"]);
    // Reset back to base commit so the future commit is unreachable from base
    run_git(repo_dir, &["reset", "--hard", &base_commit]);

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_tree(repo_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D1" && f.channel == "git_commit_graph"),
        "commit graph with future commit must gate"
    );
}

#[test]
fn test_stray_pack_outside_git() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    fs::create_dir_all(&repo_dir).unwrap();
    let (_base_commit, fp, _base_tree) = setup_base_repo(&repo_dir);

    // Write a blob containing fixed lines and repack into a packfile
    let leaked_content = "def run():\n    execute_critical_leak_line()\n    pass\n";
    fs::write(repo_dir.join("main.py"), leaked_content).unwrap();
    run_git(&repo_dir, &["add", "main.py"]);
    run_git(&repo_dir, &["commit", "-m", "leaked commit"]);
    run_git(&repo_dir, &["repack", "-adf"]);

    // Find the .pack file in objects/pack/
    let pack_dir = repo_dir.join(".git/objects/pack");
    let pack_entry = fs::read_dir(&pack_dir)
        .unwrap()
        .flatten()
        .find(|e| e.path().extension().is_some_and(|ext| ext == "pack"))
        .expect("pack file created");

    // Copy .pack file OUTSIDE any git directory
    let stray_dir = temp.path().join("outside");
    fs::create_dir_all(&stray_dir).unwrap();
    let stray_pack = stray_dir.join("stray.pack");
    fs::copy(pack_entry.path(), &stray_pack).unwrap();

    let opts = ScanOptions::default();
    let findings = scan_tree(&stray_dir, &fp, &opts);
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "D2" && f.severity == Severity::Gate && f.path.contains("stray.pack#")),
        "stray pack outside git directory must produce a gate finding at <file>#<offset>, got: {:?}",
        findings
    );
}

#[test]
fn test_stray_pack_in_tar_gz() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    fs::create_dir_all(&repo_dir).unwrap();
    let (_base_commit, fp, _base_tree) = setup_base_repo(&repo_dir);

    let leaked_content = "def run():\n    execute_critical_leak_line()\n    pass\n";
    fs::write(repo_dir.join("main.py"), leaked_content).unwrap();
    run_git(&repo_dir, &["add", "main.py"]);
    run_git(&repo_dir, &["commit", "-m", "leaked commit"]);
    run_git(&repo_dir, &["repack", "-adf"]);

    let pack_dir = repo_dir.join(".git/objects/pack");
    let pack_entry = fs::read_dir(&pack_dir)
        .unwrap()
        .flatten()
        .find(|e| e.path().extension().is_some_and(|ext| ext == "pack"))
        .expect("pack file created");
    let pack_bytes = fs::read(pack_entry.path()).unwrap();

    // Pack into tar.gz
    let outside_dir = temp.path().join("archive_outside");
    fs::create_dir_all(&outside_dir).unwrap();
    let tar_gz_path = outside_dir.join("archive.tar.gz");
    {
        let file = fs::File::create(&tar_gz_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(pack_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "inner.pack", &pack_bytes[..])
            .unwrap();
        tar.finish().unwrap();
    }

    let opts = ScanOptions::default();
    let findings = scan_tree(&outside_dir, &fp, &opts);
    assert!(
        findings.iter().any(|f| f.detector == "D2"
            && f.severity == Severity::Gate
            && f.path.contains("archive.tar.gz!/inner.pack#")),
        "stray pack in tar.gz must produce a gate finding, got: {:?}",
        findings
    );
}

#[test]
fn test_d1_visibility_image_only_exits_0() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    fs::create_dir_all(&repo_dir).unwrap();
    let (base_commit, _fp, base_tree) = setup_base_repo(&repo_dir);

    // Plant a D1 gate (e.g. ORIG_HEAD)
    fs::write(
        repo_dir.join(".git/ORIG_HEAD"),
        format!("{}\n", base_commit),
    )
    .unwrap();

    // Create a task directory with task.json, staging/, agent/
    let task_dir = temp.path().join("task");
    fs::create_dir_all(task_dir.join("staging")).unwrap();
    fs::create_dir_all(task_dir.join("agent")).unwrap();

    let gold_patch = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,3 @@\n def run():\n+    execute_critical_leak_line()\n     pass\n";
    fs::write(task_dir.join("staging/gold.patch"), gold_patch).unwrap();
    fs::write(task_dir.join("staging/test.patch"), "").unwrap();
    fs::write(
        task_dir.join("agent/problem_statement.md"),
        "problem description",
    )
    .unwrap();

    let task_json = format!(
        r#"{{
            "instance_id": "test__d1-vis",
            "repo": "test/repo",
            "base_commit": "{}",
            "cutoffs": {{
                "t_world": "2026-01-01T00:00:00Z",
                "t_clock": "2026-01-01T00:00:00Z"
            }}
        }}"#,
        base_commit
    );
    fs::write(task_dir.join("task.json"), task_json).unwrap();

    let exe = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let output = Command::new(exe)
        .args([
            "scan",
            "--task",
            task_dir.to_str().unwrap(),
            "--base-tree",
            base_tree.to_str().unwrap(),
            "--root",
            repo_dir.to_str().unwrap(),
            "--root-visibility",
            "image_only",
        ])
        .output()
        .expect("run hermetic-sealcheck binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "D1 finding under image_only root must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_d1_remote_section_case_insensitive() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);

    let cfg = repo_dir.join(".git/config");
    let mut text = fs::read_to_string(&cfg).unwrap();
    text.push_str("[REMOTE \"origin\"]\n\turl = https://example.com/x.git\n");
    fs::write(&cfg, text).unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_config"), "got: {gates:?}");
}

fn commit_lfs_pointer(repo_dir: &Path, oid: &str) -> String {
    fs::write(
        repo_dir.join("model.bin"),
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 3\n"),
    )
    .unwrap();
    run_git(repo_dir, &["add", "model.bin"]);
    run_git(repo_dir, &["commit", "-m", "lfs pointer"]);
    let _ = fs::remove_dir_all(repo_dir.join(".git/logs"));
    run_git(repo_dir, &["rev-parse", "HEAD"])
}

fn write_lfs_object(repo_dir: &Path, oid: &str) {
    let dir = repo_dir
        .join(".git/lfs/objects")
        .join(&oid[..2])
        .join(&oid[2..4]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(oid), "abc").unwrap();
}

#[test]
fn test_d1_lfs_object_referenced_by_base_passes() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (_, fp, _base_tree) = setup_base_repo(repo_dir);
    let oid = "a".repeat(64);
    let head = commit_lfs_pointer(repo_dir, &oid);
    write_lfs_object(repo_dir, &oid);

    let gates = scan_d1(repo_dir, head, &fp);
    assert!(gates.is_empty(), "got: {gates:?}");
}

#[test]
fn test_d1_lfs_object_not_referenced_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (_, fp, _base_tree) = setup_base_repo(repo_dir);
    let head = commit_lfs_pointer(repo_dir, &"a".repeat(64));
    write_lfs_object(repo_dir, &"b".repeat(64));

    let gates = scan_d1(repo_dir, head, &fp);
    assert!(has_channel(&gates, "git_state_file"), "got: {gates:?}");
}

#[test]
fn test_d1_split_commit_graph_passes_and_bad_chain_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);
    run_git(
        repo_dir,
        &["commit-graph", "write", "--split", "--reachable"],
    );

    let gates = scan_d1(repo_dir, base_commit.clone(), &fp);
    assert!(gates.is_empty(), "got: {gates:?}");

    let chain = repo_dir.join(".git/objects/info/commit-graphs/commit-graph-chain");
    fs::remove_file(&chain).unwrap();
    fs::write(&chain, "execute_critical_leak_line()\n").unwrap();
    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_commit_graph"), "got: {gates:?}");
}

#[test]
fn test_d1_info_packs_must_have_git_format() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);
    let info = repo_dir.join(".git/objects/info");
    fs::create_dir_all(&info).unwrap();

    fs::write(
        info.join("packs"),
        format!("P pack-{}.pack\n\n", "a".repeat(40)),
    )
    .unwrap();
    let gates = scan_d1(repo_dir, base_commit.clone(), &fp);
    assert!(!has_channel(&gates, "git_unknown_file"), "got: {gates:?}");

    fs::write(info.join("packs"), "execute_critical_leak_line()\n").unwrap();
    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_unknown_file"), "got: {gates:?}");
}

#[test]
fn test_d1_rev_file_with_appended_bytes_gates() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path();
    let (base_commit, fp, _base_tree) = setup_base_repo(repo_dir);
    run_git(
        repo_dir,
        &["-c", "pack.writeReverseIndex=true", "repack", "-adq"],
    );

    let gates = scan_d1(repo_dir, base_commit.clone(), &fp);
    assert!(gates.is_empty(), "got: {gates:?}");

    let pack_dir = repo_dir.join(".git/objects/pack");
    let rev = fs::read_dir(&pack_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "rev"))
        .unwrap();
    let mut bytes = fs::read(&rev).unwrap();
    bytes.extend_from_slice(b"execute_critical_leak_line()");
    let mut perms = fs::metadata(&rev).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&rev, perms).unwrap();
    fs::write(&rev, bytes).unwrap();

    let gates = scan_d1(repo_dir, base_commit, &fp);
    assert!(has_channel(&gates, "git_unknown_file"), "got: {gates:?}");
}
