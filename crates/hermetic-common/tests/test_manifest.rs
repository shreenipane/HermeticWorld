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

fn minimal_task_dir(task_dir: &std::path::Path) {
    fs::create_dir_all(task_dir.join("staging")).expect("staging");
    fs::create_dir_all(task_dir.join("agent")).expect("agent");
    let json = r#"{"instance_id":"a__b-1","repo":"a/b","base_commit":"abc",
        "cutoffs":{"t_world":"2024-01-01T00:00:00Z","t_clock":"2024-01-02T00:00:00Z","discarded":[]}}"#;
    fs::write(task_dir.join("task.json"), json).expect("task.json");
    fs::write(task_dir.join("staging/gold.patch"), "gold\n").expect("gold");
    fs::write(task_dir.join("staging/test.patch"), "test\n").expect("test");
    fs::write(task_dir.join("agent/problem_statement.md"), "p\n").expect("ps");
}

#[test]
fn test_task_input_passing_fixes_absent_is_empty() {
    let dir = tempdir().expect("tempdir");
    minimal_task_dir(dir.path());
    let loaded = TaskInput::load(dir.path()).expect("load");
    assert!(loaded.passing_fixes.is_empty());
}

#[test]
fn test_task_input_passing_fixes_sorted_regular_patch_files_only() {
    let dir = tempdir().expect("tempdir");
    let task_dir = dir.path();
    minimal_task_dir(task_dir);
    let fixes = task_dir.join("staging/fixes");
    fs::create_dir_all(&fixes).expect("fixes");
    fs::write(fixes.join("b.patch"), "fix b\n").expect("b");
    fs::write(fixes.join("a.patch"), "fix a\n").expect("a");
    fs::write(fixes.join("notes.txt"), "not a patch\n").expect("txt");
    fs::create_dir_all(fixes.join("dir.patch")).expect("dir");
    let outside = dir.path().join("outside.txt");
    fs::write(&outside, "outside\n").expect("outside");
    std::os::unix::fs::symlink(&outside, fixes.join("c.patch")).expect("symlink");
    let loaded = TaskInput::load(task_dir).expect("load");
    assert_eq!(
        loaded.passing_fixes,
        vec!["fix a\n".to_string(), "fix b\n".to_string()]
    );
}

#[test]
fn test_task_input_passing_fixes_symlinked_dir_is_not_followed() {
    let dir = tempdir().expect("tempdir");
    let task_dir = dir.path().join("task");
    minimal_task_dir(&task_dir);
    let real = dir.path().join("real_fixes");
    fs::create_dir_all(&real).expect("real");
    fs::write(real.join("a.patch"), "fix a\n").expect("a");
    std::os::unix::fs::symlink(&real, task_dir.join("staging/fixes")).expect("symlink");
    let loaded = TaskInput::load(&task_dir).expect("load");
    assert!(loaded.passing_fixes.is_empty());
}

#[test]
fn passing_fixes_directory_and_byte_caps_fail_closed() {
    use hermetic_common::manifest::{MAX_FIX_DIRECTORY_ENTRIES, MAX_FIX_FILE_BYTES};
    let dir = tempdir().unwrap();
    minimal_task_dir(dir.path());
    let fixes = dir.path().join("staging/fixes");
    fs::create_dir(&fixes).unwrap();
    let large = fs::File::create(fixes.join("a.patch")).unwrap();
    large.set_len(MAX_FIX_FILE_BYTES + 1).unwrap();
    assert!(TaskInput::load(dir.path()).is_err());
    fs::remove_file(fixes.join("a.patch")).unwrap();
    for i in 0..=MAX_FIX_DIRECTORY_ENTRIES {
        fs::File::create(fixes.join(format!("{i}.txt"))).unwrap();
    }
    assert!(TaskInput::load(dir.path()).is_err());
}

#[test]
fn passing_fixes_refuses_symlinked_ancestor() {
    let dir = tempdir().unwrap();
    let task = dir.path().join("task");
    minimal_task_dir(&task);
    let staging = task.join("staging");
    fs::create_dir(staging.join("fixes")).unwrap();
    fs::write(staging.join("fixes/a.patch"), "private").unwrap();
    let outside = dir.path().join("outside");
    fs::rename(&staging, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, &staging).unwrap();
    assert!(TaskInput::load(&task).is_err());
}
