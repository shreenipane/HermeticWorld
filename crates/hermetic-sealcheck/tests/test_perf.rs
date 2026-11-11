use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions};
use std::fs;
use std::time::Instant;
use tempfile::tempdir;

#[test]
#[ignore]
fn test_perf_synthetic_50mb_tree() {
    let tree_dir = tempdir().expect("tempdir");
    let tree_path = tree_dir.path();

    // 5000 small files (~10 KB each = ~50 MB total)
    let file_content =
        "def calculate_hash(x):\n    # Synthetic test code line\n    return x * 10 + 42\n"
            .repeat(150);
    assert!(file_content.len() >= 10_000);

    for dir_idx in 0..50 {
        let sub = tree_path.join(format!("dir_{}", dir_idx));
        fs::create_dir_all(&sub).expect("mkdir");
        for file_idx in 0..100 {
            fs::write(sub.join(format!("file_{}.py", file_idx)), &file_content).expect("write");
        }
    }

    let fp = FingerprintSet::from_task("", "", tree_path).expect("fp");
    let opts = ScanOptions::default();

    let start = Instant::now();
    let findings = scan_tree(tree_path, &fp, &opts);
    let elapsed = start.elapsed();

    println!(
        "Performance test: 5000 files (50 MB) scanned in {:.2?} ({} findings)",
        elapsed,
        findings.len()
    );

    assert!(
        elapsed.as_secs() < 10,
        "Tree scan must complete in under 10 s in release build, took {:?}",
        elapsed
    );
}

#[test]
#[ignore]
fn test_perf_d1_20k_commits() {
    use std::io::Write;
    use std::process::Command;

    let repo_temp = tempdir().expect("tempdir");
    let repo_dir = repo_temp.path();

    let init_out = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(repo_dir)
        .env("HOME", repo_dir.display().to_string())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git init");
    assert!(init_out.status.success());

    let mut child = Command::new("git")
        .args(["fast-import", "--quiet"])
        .current_dir(repo_dir)
        .stdin(std::process::Stdio::piped())
        .env("HOME", repo_dir.display().to_string())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .spawn()
        .expect("spawn fast-import");

    {
        let mut stdin = std::io::BufWriter::new(child.stdin.take().expect("stdin"));
        for i in 0..20_000 {
            writeln!(stdin, "commit refs/heads/main").unwrap();
            writeln!(
                stdin,
                "committer Test Committer <committer@example.com> {} +0000",
                1700000000 + i
            )
            .unwrap();
            let msg = format!("commit message for commit number {}", i);
            writeln!(stdin, "data {}", msg.len()).unwrap();
            write!(stdin, "{}", msg).unwrap();
            writeln!(stdin).unwrap();
            writeln!(stdin, "M 644 inline file.txt").unwrap();
            let content = format!("content version {}", i);
            writeln!(stdin, "data {}", content.len()).unwrap();
            write!(stdin, "{}", content).unwrap();
            writeln!(stdin).unwrap();
        }
        stdin.flush().unwrap();
    }

    let status = child.wait().expect("wait fast-import");
    assert!(status.success(), "fast-import failed");

    let rev_out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_dir)
        .env("HOME", repo_dir.display().to_string())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git rev-parse");
    assert!(rev_out.status.success());
    let base_commit = String::from_utf8(rev_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let _ = fs::remove_dir_all(repo_dir.join(".git/logs"));

    let base_tree = tempdir().expect("base_tree tempdir");
    fs::write(base_tree.path().join("file.txt"), "content version 19999").unwrap();
    let fp = FingerprintSet::from_task("", "", base_tree.path()).unwrap();

    let opts = ScanOptions {
        base_commit: Some(base_commit),
        t_clock: Some(time::macros::datetime!(2030-01-01 00:00:00 UTC)),
        ..Default::default()
    };

    let start = Instant::now();
    let findings = scan_tree(repo_dir, &fp, &opts);
    let elapsed = start.elapsed();

    println!(
        "D1 perf: 20,000 commits scanned in {:.2?} ({} findings)",
        elapsed,
        findings.len()
    );

    assert!(
        elapsed.as_secs() <= 30,
        "D1 time on 20,000 commits exceeded 30 s budget: took {:?}",
        elapsed
    );
}
