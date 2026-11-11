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
