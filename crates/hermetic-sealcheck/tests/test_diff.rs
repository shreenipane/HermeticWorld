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

#[test]
fn test_body_lines_that_look_like_file_headers() {
    // A removed SQL comment `-- x` serialises as `--- x`; an added `++ y` as `+++ y`.
    let diff = "diff --git a/q.sql b/q.sql\n--- a/q.sql\n+++ b/q.sql\n@@ -1,3 +1,3 @@\n SELECT 1;\n--- drop the old view\n+++ counter\n SELECT 2;\n";
    let patch = parse_patch(diff).expect("parses");
    assert_eq!(patch.files.len(), 1);
    let file = &patch.files[0];
    assert_eq!(file.old_path.as_deref(), Some("q.sql"));
    assert_eq!(file.new_path.as_deref(), Some("q.sql"));
    let lines = &file.hunks[0].lines;
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[1].content, "-- drop the old view");
    assert_eq!(lines[2].content, "++ counter");
}

#[test]
fn test_second_file_header_after_counted_hunk() {
    let diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old_value_line = 1\n+new_value_line = 2\n\\ No newline at end of file\ndiff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,2 @@\n keep_this_context_line()\n-b_removed_line_text = 3\n+b_added_line_text = 4\n";
    let patch = parse_patch(diff).expect("parses");
    assert_eq!(patch.files.len(), 2);
    assert_eq!(patch.files[0].hunks[0].lines.len(), 2);
    assert_eq!(patch.files[1].old_path.as_deref(), Some("b.py"));
    assert_eq!(patch.files[1].hunks[0].lines.len(), 3);
}
