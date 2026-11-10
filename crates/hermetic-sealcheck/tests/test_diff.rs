use hermetic_sealcheck::parse_patch;
use serde_json::Value;
use std::fs;
use std::path::Path;

fn count_diff_git_and_hunks(diff_text: &str) -> (usize, usize) {
    let mut files = 0;
    let mut hunks = 0;
    for line in diff_text.lines() {
        if line.starts_with("diff --git ") {
            files += 1;
        } else if line.starts_with("@@") {
            hunks += 1;
        }
    }
    (files, hunks)
}

#[test]
fn test_diff_parsing_real_grader_fixtures() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures_dir = manifest_dir.join("../../python/tests/fixtures/grader");
    assert!(
        fixtures_dir.exists(),
        "fixtures dir should exist at {}",
        fixtures_dir.display()
    );

    let mut tested_count = 0;
    for entry in fs::read_dir(&fixtures_dir).expect("read fixtures dir") {
        let entry = entry.expect("fixture entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json")
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".row.json"))
        {
            let content = fs::read_to_string(&path).expect("read row.json");
            let row: Value = serde_json::from_str(&content).expect("parse json");

            if let Some(patch_str) = row.get("patch").and_then(|v| v.as_str()) {
                if !patch_str.trim().is_empty() {
                    let (expected_files, expected_hunks) = count_diff_git_and_hunks(patch_str);
                    let parsed = parse_patch(patch_str).expect("patch parsed successfully");
                    let actual_hunks: usize = parsed.files.iter().map(|f| f.hunks.len()).sum();

                    assert_eq!(
                        parsed.files.len(),
                        expected_files,
                        "file count mismatch in {} for patch",
                        path.display()
                    );
                    assert_eq!(
                        actual_hunks,
                        expected_hunks,
                        "hunk count mismatch in {} for patch",
                        path.display()
                    );
                }
            }

            if let Some(test_patch_str) = row.get("test_patch").and_then(|v| v.as_str()) {
                if !test_patch_str.trim().is_empty() {
                    let (expected_files, expected_hunks) = count_diff_git_and_hunks(test_patch_str);
                    let parsed =
                        parse_patch(test_patch_str).expect("test_patch parsed successfully");
                    let actual_hunks: usize = parsed.files.iter().map(|f| f.hunks.len()).sum();

                    assert_eq!(
                        parsed.files.len(),
                        expected_files,
                        "file count mismatch in {} for test_patch",
                        path.display()
                    );
                    assert_eq!(
                        actual_hunks,
                        expected_hunks,
                        "hunk count mismatch in {} for test_patch",
                        path.display()
                    );
                }
            }

            tested_count += 1;
        }
    }

    assert!(
        tested_count > 0,
        "should have tested at least one fixture row.json"
    );
}
