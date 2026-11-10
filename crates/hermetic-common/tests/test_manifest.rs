use hermetic_common::cutoff::parse_utc_datetime;
use hermetic_common::manifest::TaskInput;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_task_input_load_and_forward_compatibility() {
    let dir = tempdir().expect("tempdir created");
    let task_dir = dir.path();

    // Create subdirs
    fs::create_dir_all(task_dir.join("staging")).expect("staging dir created");
    fs::create_dir_all(task_dir.join("agent")).expect("agent dir created");

    // task.json with extra unknown fields (forward compatible)
    let task_json_content = r#"{
        "schema": "hermetic-slice-task/v1",
        "instance_id": "test__task-1234",
        "repo": "test/repo",
        "base_commit": "abcdef0123456789abcdef0123456789abcdef01",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z",
            "discarded": [
                {
                    "commit": "c1",
                    "author_date": "2022-01-01T00:00:00Z",
                    "reason": "before_first_commit"
                }
            ]
        },
        "extra_future_field": "should be ignored",
        "another_nested_field": { "foo": 42 }
    }"#;

    fs::write(task_dir.join("task.json"), task_json_content).expect("wrote task.json");
    fs::write(
        task_dir.join("staging/gold.patch"),
        "diff --git a/foo b/foo\n",
    )
    .expect("wrote gold.patch");
    fs::write(
        task_dir.join("staging/test.patch"),
        "diff --git a/test b/test\n",
    )
    .expect("wrote test.patch");
    fs::write(
        task_dir.join("agent/problem_statement.md"),
        "Fix the bug please\n",
    )
    .expect("wrote problem_statement.md");

    let loaded = TaskInput::load(task_dir).expect("task input loaded");
    assert_eq!(loaded.instance_id, "test__task-1234");
    assert_eq!(loaded.repo, "test/repo");
    assert_eq!(
        loaded.base_commit,
        "abcdef0123456789abcdef0123456789abcdef01"
    );
    assert_eq!(
        loaded.cutoffs.t_world,
        parse_utc_datetime("2024-01-01T00:00:00Z").unwrap()
    );
    assert_eq!(
        loaded.cutoffs.t_clock,
        parse_utc_datetime("2024-01-02T00:00:00Z").unwrap()
    );
    assert_eq!(loaded.cutoffs.discarded.len(), 1);
    assert_eq!(loaded.gold_patch, "diff --git a/foo b/foo\n");
    assert_eq!(loaded.test_patch, "diff --git a/test b/test\n");
    assert_eq!(loaded.problem_statement, "Fix the bug please\n");
}

#[test]
fn test_task_input_missing_required_fields_fails() {
    let dir = tempdir().expect("tempdir created");
    let task_dir = dir.path();
    fs::create_dir_all(task_dir.join("staging")).expect("staging dir created");
    fs::create_dir_all(task_dir.join("agent")).expect("agent dir created");

    // Missing base_commit
    let invalid_json = r#"{
        "instance_id": "test__task-1234",
        "repo": "test/repo",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z"
        }
    }"#;

    fs::write(task_dir.join("task.json"), invalid_json).expect("wrote task.json");
    fs::write(task_dir.join("staging/gold.patch"), "").unwrap();
    fs::write(task_dir.join("staging/test.patch"), "").unwrap();
    fs::write(task_dir.join("agent/problem_statement.md"), "").unwrap();

    let err = TaskInput::load(task_dir).unwrap_err();
    assert!(matches!(
        err,
        hermetic_common::manifest::ManifestError::Json(_)
    ));
}

#[test]
fn test_task_input_missing_file_fails() {
    let dir = tempdir().expect("tempdir created");
    let task_dir = dir.path();

    let err = TaskInput::load(task_dir).unwrap_err();
    assert!(matches!(
        err,
        hermetic_common::manifest::ManifestError::MissingFile(_)
    ));
}
