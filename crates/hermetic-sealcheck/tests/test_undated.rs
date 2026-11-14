use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::{tempdir, TempDir};

use hermetic_sealcheck::{
    load_undated_task, match_unit, query_index, scan_tree, write_index, Finding, FingerprintSet,
    ScanOptions, Severity, Visibility,
};

const DISTINCTIVE_SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
distinctive_terminalbench_solution_variable="computed_special_value"
echo "$distinctive_terminalbench_solution_variable" > /tmp/solution_out.txt
run_custom_solution_engine --mode=production --output=/var/run/finished
"#;

const DISTINCTIVE_TESTS: &str = r#"import os

def test_distinctive_solution_output():
    distinctive_test_assertion_value = "computed_special_value"
    assert os.path.exists("/tmp/solution_out.txt")
    assert distinctive_test_assertion_value == "computed_special_value"
"#;

struct UndatedTaskFixture {
    _task_dir: TempDir,
    task_path: PathBuf,
    _base_dir: TempDir,
    base_path: PathBuf,
}

fn create_undated_fixture() -> UndatedTaskFixture {
    let task_dir = tempdir().expect("task tempdir");
    let base_dir = tempdir().expect("base tempdir");

    let task_path = task_dir.path().to_path_buf();
    let base_path = base_dir.path().to_path_buf();

    fs::write(
        task_path.join("task.yaml"),
        "id: tb-fake-task-001\ninstruction: Please process input_data.csv and produce required output.\n",
    )
    .expect("write task.yaml");

    fs::create_dir_all(task_path.join("solution")).expect("mkdir solution");
    fs::write(task_path.join("solution/solution.sh"), DISTINCTIVE_SCRIPT)
        .expect("write solution.sh");

    fs::create_dir_all(task_path.join("tests")).expect("mkdir tests");
    fs::write(task_path.join("tests/test_outputs.py"), DISTINCTIVE_TESTS)
        .expect("write test_outputs.py");

    UndatedTaskFixture {
        _task_dir: task_dir,
        task_path,
        _base_dir: base_dir,
        base_path,
    }
}

fn zip_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        for (name, data) in members {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start_file");
            zip.write_all(data).expect("write member");
        }
        zip.finish().expect("finish zip");
    }
    buf.into_inner()
}

fn covered_sorted(findings: Vec<Finding>) -> Vec<String> {
    let mut v: Vec<String> = findings
        .into_iter()
        .filter(|f| !matches!(f.detector.as_str(), "D1" | "D3" | "D6"))
        .filter(|f| !(f.detector == "D9" && f.channel == "instance_id"))
        .map(|f| serde_json::to_string(&f).expect("serialize finding"))
        .collect();
    v.sort();
    v
}

#[test]
fn test_fake_terminalbench_task_and_roots() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let fixture = create_undated_fixture();

    // 1. Clean root with only instruction-referenced input file
    let clean_dir = tempdir().expect("clean dir");
    fs::write(
        clean_dir.path().join("input_data.csv"),
        "id,value\n1,alpha\n2,beta\n",
    )
    .expect("write input_data.csv");

    let clean_status = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(clean_dir.path())
        .arg("--format")
        .arg("json")
        .status()
        .expect("run scan");
    assert_eq!(
        clean_status.code(),
        Some(0),
        "clean root with input files must not gate"
    );

    // 2. Root containing a copy of solution.sh gates (D2)
    let leak_sol_dir = tempdir().expect("leak sol dir");
    fs::write(leak_sol_dir.path().join("solution.sh"), DISTINCTIVE_SCRIPT)
        .expect("write leak solution.sh");

    let output_sol = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(leak_sol_dir.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("run scan");
    assert_eq!(
        output_sol.status.code(),
        Some(2),
        "root with copy of solution.sh must exit 2"
    );
    let json_sol: serde_json::Value =
        serde_json::from_slice(&output_sol.stdout).expect("parse json");
    assert_eq!(json_sol["gate"], true);
    assert_eq!(json_sol["mode"], "undated");
    assert_eq!(
        json_sol["not_covered"],
        serde_json::json!(["D1", "D3", "D4", "D5a"])
    );
    let findings = json_sol["findings"].as_array().expect("findings array");
    assert!(
        findings
            .iter()
            .any(|f| f["detector"] == "D2" && f["severity"] == "gate"),
        "must have D2 gate finding: {findings:#?}"
    );

    // 3. Root containing a zip of tests/ gates (D2)
    let leak_tests_dir = tempdir().expect("leak tests dir");
    let tests_zip = zip_bytes(&[("tests/test_outputs.py", DISTINCTIVE_TESTS.as_bytes())]);
    fs::write(leak_tests_dir.path().join("archive.zip"), tests_zip).expect("write zip");

    let output_zip = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(leak_tests_dir.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("run scan");
    assert_eq!(
        output_zip.status.code(),
        Some(2),
        "root with zip of tests/ must exit 2"
    );
    let json_zip: serde_json::Value =
        serde_json::from_slice(&output_zip.stdout).expect("parse json");
    assert_eq!(json_zip["gate"], true);
    let findings_zip = json_zip["findings"].as_array().expect("findings array");
    assert!(
        findings_zip
            .iter()
            .any(|f| f["detector"] == "D2" && f["severity"] == "gate"),
        "must have D2 gate finding from zip member: {findings_zip:#?}"
    );
}

#[test]
fn test_baseline_subtraction_line_in_base_does_not_gate() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    let base_dir = tempdir().expect("base dir");
    let base_path = base_dir.path();
    // Base tree contains a shared helper line
    fs::write(
        base_path.join("common.sh"),
        "shared_boilerplate_setup_variable = \"standard_infrastructure_path\"\n",
    )
    .expect("write base common.sh");

    let task_dir = tempdir().expect("task dir");
    let task_path = task_dir.path();
    fs::create_dir_all(task_path.join("solution")).expect("mkdir solution");

    // solution.sh includes that shared line plus its own novel lines
    let solution_content = r#"#!/usr/bin/env bash
shared_boilerplate_setup_variable = "standard_infrastructure_path"
unique_novel_action_step_one_computed_hash="11223344"
unique_novel_action_step_two_computed_hash="55667788"
"#;
    fs::write(task_path.join("solution/solution.sh"), solution_content).expect("write solution.sh");

    // Root contains ONLY the shared line from base tree
    let root_dir = tempdir().expect("root dir");
    fs::write(
        root_dir.path().join("used_common.sh"),
        "shared_boilerplate_setup_variable = \"standard_infrastructure_path\"\n",
    )
    .expect("write root used_common.sh");

    let status = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_path)
        .arg("--base-tree")
        .arg(base_path)
        .arg("--root")
        .arg(root_dir.path())
        .arg("--format")
        .arg("json")
        .status()
        .expect("run scan");
    assert_eq!(
        status.code(),
        Some(0),
        "a line in solution.sh that appears in the base tree must not by itself gate"
    );
}

#[test]
fn test_d0_instruction_quotes_solution_commands_gates() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let fixture = create_undated_fixture();

    // Overwrite instruction.md with text quoting solution's distinctive command
    let leaking_instruction = r#"# Task Instruction
Please solve the task. Specifically run:
run_custom_solution_engine --mode=production --output=/var/run/finished
distinctive_terminalbench_solution_variable="computed_special_value"
echo "$distinctive_terminalbench_solution_variable" > /tmp/solution_out.txt
"#;
    fs::write(
        fixture.task_path.join("instruction.md"),
        leaking_instruction,
    )
    .expect("write instruction.md");

    let clean_root = tempdir().expect("clean root");
    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(clean_root.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("run scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "quoting solution distinctive commands in instruction must gate D0"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse json");
    assert_eq!(json["gate"], true);
    let findings = json["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|f| f["detector"] == "D0"
            && f["channel"] == "problem_statement"
            && f["severity"] == "gate"
            && f["visibility"] == "agent_visible"),
        "expected D0 gate finding: {findings:#?}"
    );
}

#[test]
fn test_task_dir_inside_root_is_never_scanned() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    let root_dir = tempdir().expect("root dir");
    let root = root_dir.path();

    let base_dir = tempdir().expect("base dir");
    let base = base_dir.path();

    // Place the task directory INSIDE root
    let task_path = root.join("tb_tasks/my_task");
    fs::create_dir_all(task_path.join("solution")).expect("mkdir solution");
    fs::create_dir_all(task_path.join("tests")).expect("mkdir tests");

    fs::write(task_path.join("solution/solution.sh"), DISTINCTIVE_SCRIPT)
        .expect("write solution.sh");
    fs::write(task_path.join("tests/test_outputs.py"), DISTINCTIVE_TESTS)
        .expect("write test_outputs.py");

    let scan = || {
        Command::new(bin_path)
            .arg("scan")
            .arg("--undated")
            .arg("--task")
            .arg(&task_path)
            .arg("--base-tree")
            .arg(base)
            .arg("--root")
            .arg(root)
            .status()
            .expect("run scan")
            .code()
    };

    assert_eq!(
        scan(),
        Some(0),
        "the task directory inside the root must never be scanned"
    );

    // Placing a leak outside the task dir in the root DOES gate
    fs::write(root.join("leak_solution.sh"), DISTINCTIVE_SCRIPT).expect("write leak");
    assert_eq!(
        scan(),
        Some(2),
        "a leak beside the task directory inside root must gate"
    );
}

#[test]
fn test_scan_and_query_undated_equivalence() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let fixture = create_undated_fixture();

    let root_dir = tempdir().expect("root dir");
    let root = root_dir.path();

    // Plant leak in root
    fs::write(root.join("leaked_script.sh"), DISTINCTIVE_SCRIPT).expect("write leak");

    // Index the root
    let idx_dir = tempdir().expect("idx dir");
    let idx_path = idx_dir.path().join("layer.hwidx");
    let stats = write_index(root, &idx_path).expect("write index");
    assert!(stats.files > 0);

    // 1. Direct scan_tree vs query_index equivalence
    let undated_task = load_undated_task(&fixture.task_path).expect("load undated task");
    let fp = FingerprintSet::from_files(&undated_task.files, &fixture.base_path).expect("build fp");

    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        undated: true,
        ..Default::default()
    };

    let scanned = covered_sorted(scan_tree(root, &fp, &opts));
    let queried = covered_sorted(query_index(&idx_path, &fp, &opts).expect("query"));
    assert_eq!(
        scanned, queried,
        "scan and query covered findings must agree"
    );

    // 2. CLI scan --undated and query --undated
    let scan_out = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run scan");
    assert_eq!(scan_out.status.code(), Some(2));
    let scan_json: serde_json::Value =
        serde_json::from_slice(&scan_out.stdout).expect("parse json");

    let query_out = Command::new(bin_path)
        .arg("query")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--index")
        .arg(&idx_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run query");
    assert_eq!(query_out.status.code(), Some(2));
    let query_json: serde_json::Value =
        serde_json::from_slice(&query_out.stdout).expect("parse json");

    assert_eq!(scan_json["mode"], "undated");
    assert_eq!(query_json["mode"], "undated");
    assert_eq!(
        scan_json["not_covered"],
        serde_json::json!(["D1", "D3", "D4", "D5a"])
    );
    assert_eq!(
        query_json["not_covered"],
        serde_json::json!([
            "D1",
            "D3",
            "D6",
            "D9:instance_id",
            "D9:external",
            "D4",
            "D5a"
        ])
    );
}

#[test]
fn test_oversized_and_binary_solution_files_empty_and_missing() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    let base_dir = tempdir().expect("base dir");
    let base = base_dir.path();

    // 1. Oversized solution file (> 16 MiB)
    let task_dir_oversized = tempdir().expect("task dir");
    let task_ov = task_dir_oversized.path();
    fs::create_dir_all(task_ov.join("solution")).expect("mkdir solution");

    // Create 17 MiB file
    let big_content = vec![b'A'; 17 * 1024 * 1024];
    fs::write(task_ov.join("solution/big_solution.bin"), &big_content).expect("write big file");

    let undated_ov = load_undated_task(task_ov).expect("load task");
    let mut fp_ov = FingerprintSet::from_files(&undated_ov.files, base).expect("fp");
    fp_ov.skipped_files_count += undated_ov.skipped_files_count;
    assert_eq!(
        fp_ov.skipped_files_count, 1,
        "17 MiB file must be skipped by 16 MiB cap"
    );

    let clean_root = tempdir().expect("clean root");
    let out_ov = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_ov)
        .arg("--base-tree")
        .arg(base)
        .arg("--root")
        .arg(clean_root.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan");
    assert_eq!(out_ov.status.code(), Some(0));
    let json_ov: serde_json::Value = serde_json::from_slice(&out_ov.stdout).expect("json");
    let findings_ov = json_ov["findings"].as_array().expect("findings");
    assert!(
        findings_ov
            .iter()
            .any(|f| f["detector"] == "D2" && f["severity"] == "info"),
        "oversized file must produce an info finding: {findings_ov:#?}"
    );

    // 2. Binary solution file (NUL in first 8 KiB)
    let task_dir_bin = tempdir().expect("task dir bin");
    let task_bin = task_dir_bin.path();
    fs::create_dir_all(task_bin.join("solution")).expect("mkdir solution");

    let mut binary_content = Vec::new();
    binary_content.extend_from_slice(b"\x7fELF\x00\x00\x00\x00"); // NUL in first 8 KiB
    binary_content.extend_from_slice(b"some padding bytes to align header\n");
    binary_content.extend_from_slice(b"very_distinctive_binary_symbol_token_one\x00");
    binary_content.extend_from_slice(b"very_distinctive_binary_symbol_token_two\x00");

    fs::write(task_bin.join("solution/compiled_app"), &binary_content).expect("write binary");
    let undated_bin = load_undated_task(task_bin).expect("load task");
    let fp_bin = FingerprintSet::from_files(&undated_bin.files, base).expect("fp");

    // Contributes ONLY binary-tier items
    assert_eq!(
        fp_bin.lines_count, 0,
        "binary file must not contribute tier 1 lines"
    );
    assert_eq!(
        fp_bin.windows_count, 0,
        "binary file must not contribute tier 1 windows"
    );
    assert_eq!(
        fp_bin.winnow_count, 0,
        "binary file must not contribute tier 3 winnow"
    );
    assert!(
        fp_bin.binary_items_count >= 2,
        "binary file must contribute binary-tier items from printable runs of 8+"
    );

    // 3. Empty solution/ and missing tests/ (allowed)
    let task_dir_empty = tempdir().expect("task dir empty");
    let task_empty = task_dir_empty.path();
    fs::create_dir_all(task_empty.join("solution")).expect("mkdir solution");
    // tests/ is missing completely

    let undated_empty = load_undated_task(task_empty).expect("load task");
    assert!(undated_empty.files.is_empty());
    let fp_empty = FingerprintSet::from_files(&undated_empty.files, base).expect("fp");
    assert_eq!(fp_empty.lines_count, 0);
    assert_eq!(fp_empty.windows_count, 0);
    assert_eq!(fp_empty.winnow_count, 0);
    assert_eq!(fp_empty.binary_items_count, 0);

    let out_empty = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_empty)
        .arg("--base-tree")
        .arg(base)
        .arg("--root")
        .arg(clean_root.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan");
    assert_eq!(out_empty.status.code(), Some(0));
    let json_empty: serde_json::Value = serde_json::from_slice(&out_empty.stdout).expect("json");
    assert_eq!(json_empty["fingerprints"]["lines"], 0);
    assert_eq!(json_empty["fingerprints"]["windows"], 0);
    assert_eq!(json_empty["gate"], false);
}

#[test]
fn test_dated_scan_json_unchanged_no_mode() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    let base_dir = tempdir().expect("base dir");
    let base_tree = base_dir.path();
    fs::write(
        base_tree.join("main.py"),
        "def main():\n    do_base_work_initial()\n",
    )
    .expect("write base");

    let task_dir = tempdir().expect("task dir");
    let task = task_dir.path();
    fs::create_dir_all(task.join("staging")).expect("mkdir staging");
    fs::create_dir_all(task.join("agent")).expect("mkdir agent");
    let task_json = r#"{
        "schema": "hermetic-slice-task/v1",
        "instance_id": "test__cli-dated-mode",
        "repo": "test/repo",
        "base_commit": "1234567890abcdef1234567890abcdef12345678",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2030-01-01T00:00:00Z"
        }
    }"#;
    fs::write(task.join("task.json"), task_json).expect("write task.json");
    let gold_patch = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,3 @@\n def main():\n+    execute_critical_leak_line()\n     do_base_work_initial()\n";
    fs::write(task.join("staging/gold.patch"), gold_patch).expect("write gold.patch");
    fs::write(task.join("staging/test.patch"), "").expect("write test.patch");
    fs::write(
        task.join("agent/problem_statement.md"),
        "Please fix the bug.\n",
    )
    .expect("write problem_statement.md");

    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--task")
        .arg(task)
        .arg("--base-tree")
        .arg(base_tree)
        .arg("--root")
        .arg(base_tree)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run dated scan");
    assert_eq!(output.status.code(), Some(0));

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse json");
    assert!(
        json.get("mode").is_none(),
        "dated scan JSON must not have 'mode' field: {json:?}"
    );
    assert!(
        json.get("not_covered").is_none(),
        "dated scan JSON must not have 'not_covered' field: {json:?}"
    );
    assert_eq!(json["schema"], "hermetic-sealcheck/v0");
    assert_eq!(json["instance_id"], "test__cli-dated-mode");
    assert_eq!(json["gate"], false);
}

#[test]
fn test_total_size_cap_64mb() {
    let base_dir = tempdir().expect("base dir");
    let base = base_dir.path();

    // 5 files of 15 MiB each. Total = 75 MiB > 64 MiB cap.
    let files: Vec<(String, Vec<u8>)> = (0..5)
        .map(|i| {
            (
                format!("solution/chunk_{i}.txt"),
                vec![b'A'; 15 * 1024 * 1024],
            )
        })
        .collect();

    let fp = FingerprintSet::from_files(&files, base).expect("from_files");
    assert_eq!(
        fp.skipped_files_count, 1,
        "5th 15 MiB file should exceed the 64 MiB total cap and be skipped"
    );
}

#[test]
fn test_metadata_formats_toml_json_yaml_fallback() {
    // 1. task.toml
    let toml_dir = tempdir().expect("toml dir");
    fs::write(
        toml_dir.path().join("task.toml"),
        "instance_id = \"task-from-toml\"\n",
    )
    .expect("write toml");
    let task_toml = load_undated_task(toml_dir.path()).expect("load toml");
    assert_eq!(task_toml.instance_id, "task-from-toml");

    // 2. task.json
    let json_dir = tempdir().expect("json dir");
    fs::write(
        json_dir.path().join("task.json"),
        "{\"id\": \"task-from-json\"}\n",
    )
    .expect("write json");
    let task_json = load_undated_task(json_dir.path()).expect("load json");
    assert_eq!(task_json.instance_id, "task-from-json");

    // 3. task.yaml with block scalar instruction
    let yaml_dir = tempdir().expect("yaml dir");
    let yaml_content = r#"id: task-from-yaml
instruction: |
  Step 1: configure environment.
  Step 2: build project.
other: 123
"#;
    fs::write(yaml_dir.path().join("task.yaml"), yaml_content).expect("write yaml");
    let task_yaml = load_undated_task(yaml_dir.path()).expect("load yaml");
    assert_eq!(task_yaml.instance_id, "task-from-yaml");
    assert_eq!(
        task_yaml.instruction,
        "Step 1: configure environment.\nStep 2: build project."
    );

    // 4. No metadata file -> falls back to directory name
    let fallback_dir = tempdir().expect("fallback dir");
    let custom_named_dir = fallback_dir.path().join("unique-undated-dir-name");
    fs::create_dir_all(&custom_named_dir).expect("mkdir");
    let task_fallback = load_undated_task(&custom_named_dir).expect("load fallback");
    assert_eq!(task_fallback.instance_id, "unique-undated-dir-name");
    assert_eq!(task_fallback.instruction, "");
}

#[test]
fn test_undated_mode_oci_inspect_runs_d6() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let fixture = create_undated_fixture();

    // Inspect JSON containing leaking label or env
    let inspect_dir = tempdir().expect("inspect dir");
    let inspect_file = inspect_dir.path().join("inspect.json");
    let inspect_val = serde_json::json!([
        {
            "Created": "2024-01-01T00:00:00Z",
            "Config": {
                "Env": [
                    format!("LEAKED_SOLUTION={DISTINCTIVE_SCRIPT}")
                ]
            }
        }
    ]);
    fs::write(
        &inspect_file,
        serde_json::to_string(&inspect_val).expect("serialize inspect json"),
    )
    .expect("write inspect");

    let clean_root = tempdir().expect("clean root");
    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(clean_root.path())
        .arg("--oci-inspect")
        .arg(&inspect_file)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run scan with oci");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse json");
    let findings = json["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|f| f["detector"] == "D6"),
        "D6 findings must be reported when oci-inspect is provided: {findings:#?}"
    );
}

#[test]
fn test_undated_mode_sarif_output_has_properties() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let fixture = create_undated_fixture();

    let clean_root = tempdir().expect("clean root");
    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(&fixture.task_path)
        .arg("--base-tree")
        .arg(&fixture.base_path)
        .arg("--root")
        .arg(clean_root.path())
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("run scan with sarif");

    assert_eq!(output.status.code(), Some(0));
    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse sarif json");
    let runs = sarif["runs"].as_array().expect("runs array");
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    let props = &run["properties"];
    assert_eq!(props["mode"], "undated");
    assert_eq!(
        props["not_covered"],
        serde_json::json!(["D1", "D3", "D4", "D5a"])
    );
}

#[test]
fn test_fix1_yaml_block_scalar_headers_with_and_without_comments() {
    let headers = ["|", "|-", ">", ">+", "|2"];
    for header in headers {
        let expected = if header.starts_with('>') {
            "the block instruction line 1 the block instruction line 2"
        } else {
            "the block instruction line 1\nthe block instruction line 2"
        };

        // Without comment
        let yaml_no_comment = format!("id: test-task\ninstruction: {header}\n  the block instruction line 1\n  the block instruction line 2\n");
        let dir_no_comment = tempdir().expect("tempdir");
        fs::write(dir_no_comment.path().join("task.yaml"), &yaml_no_comment).expect("write yaml");
        let task = load_undated_task(dir_no_comment.path()).expect("load task");
        assert_eq!(
            task.instruction, expected,
            "failed for header without comment: {header}"
        );

        // With trailing comment
        let yaml_with_comment = format!("id: test-task\ninstruction: {header} # inline header comment\n  the block instruction line 1\n  the block instruction line 2\n");
        let dir_with_comment = tempdir().expect("tempdir");
        fs::write(
            dir_with_comment.path().join("task.yaml"),
            &yaml_with_comment,
        )
        .expect("write yaml");
        let task = load_undated_task(dir_with_comment.path()).expect("load task");
        assert_eq!(
            task.instruction, expected,
            "failed for header with comment: {header}"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_fix2_unreadable_subtree_in_solution_fails() {
    use std::os::unix::fs::PermissionsExt;
    let task_dir = tempdir().expect("task dir");
    let unreadable = task_dir.path().join("solution").join("forbidden_subdir");
    fs::create_dir_all(&unreadable).expect("mkdir");
    fs::write(unreadable.join("subfile.sh"), "echo hello\n").expect("write subfile");

    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read_dir(&unreadable).is_ok() {
        // Running as root: permissions ignored, skip assertion
        let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755));
        return;
    }

    let res = load_undated_task(task_dir.path());

    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let base_dir = tempdir().expect("base dir");
    let scan_root = tempdir().expect("scan root");
    let cli_out = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_dir.path())
        .arg("--base-tree")
        .arg(base_dir.path())
        .arg("--root")
        .arg(scan_root.path())
        .output();

    let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755));

    assert!(
        res.is_err(),
        "loading task with unreadable subtree must fail"
    );
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("forbidden_subdir") || err.contains(&unreadable.display().to_string()),
        "error must name unreadable path: {err}"
    );

    let cli_out = cli_out.expect("run scan");
    assert_eq!(
        cli_out.status.code(),
        Some(1),
        "CLI must exit 1 when traversal fails"
    );
}

#[test]
fn test_fix3_duplicate_line_weights_undated_and_dated() {
    // 1. Undated mode
    let task_dir = tempdir().expect("task dir");
    fs::create_dir_all(task_dir.path().join("solution")).expect("mkdir solution");
    fs::write(
        task_dir.path().join("solution/dup.py"),
        "unique_repeated_test_line_alpha = 1\nunique_repeated_test_line_alpha = 1\n",
    )
    .expect("write dup.py");
    let base_dir = tempdir().expect("base dir");
    let task = load_undated_task(task_dir.path()).expect("load task");
    let fp_undated = FingerprintSet::from_files(&task.files, base_dir.path()).expect("from_files");

    let unit_text = "unique_repeated_test_line_alpha = 1\n";
    let findings_undated = match_unit(
        unit_text,
        &fp_undated,
        &ScanOptions::default(),
        "D2",
        "file",
        "dup.py",
    );
    let f_undated = findings_undated
        .iter()
        .find(|f| f.detector == "D2" && f.channel == "file")
        .expect("finding for undated");
    assert_eq!(
        f_undated.confidence, 1.0,
        "undated confidence must be 1.0 when hunk's only distinctive line repeated twice appears once in unit"
    );

    // 2. Dated gold-patch path (from_task)
    let dated_base_dir = tempdir().expect("dated base dir");
    fs::write(
        dated_base_dir.path().join("dated.py"),
        "initial_context_line = 0\n",
    )
    .expect("write dated base");
    let gold_patch = "diff --git a/dated.py b/dated.py\n--- a/dated.py\n+++ b/dated.py\n@@ -1,1 +1,3 @@\n initial_context_line = 0\n+unique_repeated_test_line_beta = 2\n+unique_repeated_test_line_beta = 2\n";
    let fp_dated =
        FingerprintSet::from_task(gold_patch, "", dated_base_dir.path()).expect("from_task");

    let dated_unit_text = "unique_repeated_test_line_beta = 2\n";
    let findings_dated = match_unit(
        dated_unit_text,
        &fp_dated,
        &ScanOptions::default(),
        "D2",
        "file",
        "dated.py",
    );
    let f_dated = findings_dated
        .iter()
        .find(|f| f.detector == "D2" && f.channel == "file")
        .expect("finding for dated");
    assert_eq!(
        f_dated.confidence, 1.0,
        "dated confidence must be 1.0 when hunk's only distinctive line repeated twice appears once in unit"
    );

    // 3. Dated test-patch path (from_task)
    let test_patch = "diff --git a/test_dated.py b/test_dated.py\n--- /dev/null\n+++ b/test_dated.py\n@@ -0,0 +1,2 @@\n+unique_repeated_test_line_gamma = 3\n+unique_repeated_test_line_gamma = 3\n";
    let fp_test_patch =
        FingerprintSet::from_task("", test_patch, dated_base_dir.path()).expect("from_task");
    let test_unit_text = "unique_repeated_test_line_gamma = 3\n";
    let findings_tp = match_unit(
        test_unit_text,
        &fp_test_patch,
        &ScanOptions::default(),
        "D2",
        "file",
        "test_dated.py",
    );
    let f_tp = findings_tp
        .iter()
        .find(|f| f.detector == "D2" && f.channel == "file")
        .expect("finding for test patch");
    assert_eq!(
        f_tp.confidence, 1.0,
        "test patch confidence must be 1.0 when hunk's only distinctive line repeated twice appears once in unit"
    );
}

#[test]
fn test_fix4_sparse_large_file_and_budget_enforcement() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // Part 1: Sparse / large file over 16 MiB per-file cap is skipped without being read
    let task_dir_sparse = tempdir().expect("task dir sparse");
    fs::create_dir_all(task_dir_sparse.path().join("solution")).expect("mkdir solution");
    fs::write(
        task_dir_sparse.path().join("task.yaml"),
        "id: sparse-task\ninstruction: Do work.\n",
    )
    .expect("write yaml");

    let sparse_file_path = task_dir_sparse.path().join("solution/sparse_oversized.bin");
    let file = fs::File::create(&sparse_file_path).expect("create sparse file");
    file.set_len(20 * 1024 * 1024).expect("set_len to 20 MiB");
    drop(file);

    let task_sparse = load_undated_task(task_dir_sparse.path()).expect("load task sparse");
    assert_eq!(
        task_sparse.skipped_files_count, 1,
        "sparse 20 MiB file must be skipped during loading"
    );
    assert!(
        task_sparse.files.is_empty(),
        "sparse oversized file must not be loaded into memory"
    );

    let base_dir = tempdir().expect("base dir");
    let clean_root = tempdir().expect("clean root");
    let out_sparse = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_dir_sparse.path())
        .arg("--base-tree")
        .arg(base_dir.path())
        .arg("--root")
        .arg(clean_root.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan sparse");
    assert_eq!(out_sparse.status.code(), Some(0));
    let json_sparse: serde_json::Value =
        serde_json::from_slice(&out_sparse.stdout).expect("parse json");
    let findings_sparse = json_sparse["findings"].as_array().expect("findings");
    let info_finding = findings_sparse
        .iter()
        .find(|f| f["channel"] == "task_file_skipped" && f["severity"] == "info")
        .expect("must produce task_file_skipped info finding");
    assert!(
        info_finding["evidence"][0]
            .as_str()
            .unwrap()
            .contains("skipped 1 task files"),
        "evidence must indicate 1 skipped file: {info_finding:?}"
    );

    // Part 2: A set of files totalling over 64 MiB loads only up to it in sorted path order
    let task_dir_budget = tempdir().expect("task dir budget");
    fs::create_dir_all(task_dir_budget.path().join("solution")).expect("mkdir solution");
    let chunk_data = vec![b'B'; 15 * 1024 * 1024];
    fs::write(
        task_dir_budget.path().join("solution/file_a.bin"),
        &chunk_data,
    )
    .expect("write a");
    fs::write(
        task_dir_budget.path().join("solution/file_b.bin"),
        &chunk_data,
    )
    .expect("write b");
    fs::write(
        task_dir_budget.path().join("solution/file_c.bin"),
        &chunk_data,
    )
    .expect("write c");
    fs::write(
        task_dir_budget.path().join("solution/file_d.bin"),
        &chunk_data,
    )
    .expect("write d");
    fs::write(
        task_dir_budget.path().join("solution/file_e.bin"),
        &chunk_data,
    )
    .expect("write e");

    let task_budget = load_undated_task(task_dir_budget.path()).expect("load task budget");
    assert_eq!(
        task_budget.skipped_files_count, 1,
        "5th file must be skipped when 64 MiB budget is reached"
    );
    assert_eq!(
        task_budget.files.len(),
        4,
        "only first 4 files up to 64 MiB should be loaded"
    );
    assert_eq!(task_budget.files[0].0, "solution/file_a.bin");
    assert_eq!(task_budget.files[1].0, "solution/file_b.bin");
    assert_eq!(task_budget.files[2].0, "solution/file_c.bin");
    assert_eq!(task_budget.files[3].0, "solution/file_d.bin");
}

#[test]
fn test_fix5_nul_plus_6mib_ff_classified_binary_not_skipped_for_size() {
    let mut exact_input = Vec::with_capacity(1 + 6 * 1024 * 1024);
    exact_input.push(0x00);
    exact_input.resize(1 + 6 * 1024 * 1024, 0xFF);

    let task_dir = tempdir().expect("task dir");
    fs::create_dir_all(task_dir.path().join("solution")).expect("mkdir solution");
    fs::write(task_dir.path().join("solution/nul_ff.bin"), &exact_input).expect("write binary");

    let task = load_undated_task(task_dir.path()).expect("load task");
    assert_eq!(
        task.skipped_files_count, 0,
        "NUL + 6 MiB of 0xFF must not be skipped during loading (actual bytes <= 16 MiB)"
    );
    assert_eq!(task.files.len(), 1);

    let base_dir = tempdir().expect("base dir");
    let fp = FingerprintSet::from_files(&task.files, base_dir.path()).expect("from_files");
    assert_eq!(
        fp.skipped_files_count, 0,
        "from_files must not skip NUL + 6 MiB of 0xFF for size"
    );
    // Classified as binary, so tier 1 text lines/windows must be 0
    assert_eq!(fp.lines_count, 0, "binary file must have 0 lines");
    assert_eq!(fp.windows_count, 0, "binary file must have 0 windows");
    assert_eq!(fp.winnow_count, 0, "binary file must have 0 winnow");
}

#[test]
fn test_fix6_identical_base_and_solution_binary_subtracted_no_gate() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // Identical binary with NUL in first 8 KiB and printable runs of 8+ characters
    let mut binary_bytes = Vec::new();
    binary_bytes.extend_from_slice(b"\x7fELF\x00\x00\x00\x00header_padding_data_here\n");
    binary_bytes.extend_from_slice(b"identical_binary_symbol_token_one\x00");
    binary_bytes.extend_from_slice(b"identical_binary_symbol_token_two\x00");

    let base_dir = tempdir().expect("base dir");
    fs::write(base_dir.path().join("libcommon.so"), &binary_bytes).expect("write base binary");

    let task_dir = tempdir().expect("task dir");
    fs::create_dir_all(task_dir.path().join("solution")).expect("mkdir solution");
    fs::write(task_dir.path().join("solution/libcommon.so"), &binary_bytes)
        .expect("write solution binary");

    let task = load_undated_task(task_dir.path()).expect("load task");
    let fp = FingerprintSet::from_files(&task.files, base_dir.path()).expect("from_files");

    assert_eq!(
        fp.binary_items_count, 0,
        "identical solution binary to base-tree must yield 0 surviving binary items after subtraction"
    );
    assert!(
        fp.binary_subtracted_count >= 2,
        "binary items from identical base binary must be subtracted, got {}",
        fp.binary_subtracted_count
    );

    // Scan a root containing the same binary: must not gate!
    let scan_root = tempdir().expect("scan root");
    fs::write(scan_root.path().join("libcommon.so"), &binary_bytes).expect("write scan binary");

    let findings = scan_tree(
        scan_root.path(),
        &fp,
        &ScanOptions {
            undated: true,
            ..Default::default()
        },
    );
    assert!(
        findings.iter().all(|f| f.severity != Severity::Gate),
        "scanning root with unchanged base binary must not gate: {findings:?}"
    );

    // CLI test
    let out = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_dir.path())
        .arg("--base-tree")
        .arg(base_dir.path())
        .arg("--root")
        .arg(scan_root.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan");
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("parse json");
    assert_eq!(json["gate"], false);
    assert_eq!(json["fingerprints"]["binary_items"], 0);
    assert!(json["fingerprints"]["binary_subtracted"].as_u64().unwrap() >= 2);
}

#[test]
fn test_regression_fix1_folded_scalars_blank_lines_and_chomping() {
    // 1. Blank lines inside a folded block
    let dir_blank = tempdir().expect("tempdir");
    let yaml_blank = "id: task-blank\ninstruction: >\n  first para line 1\n  first para line 2\n\n  second para line 1\n  second para line 2\n";
    fs::write(dir_blank.path().join("task.yaml"), yaml_blank).expect("write yaml");
    let task_blank = load_undated_task(dir_blank.path()).expect("load task");
    assert_eq!(
        task_blank.instruction,
        "first para line 1 first para line 2\n\nsecond para line 1 second para line 2"
    );

    // 2. More-indented lines inside a folded block
    let dir_indented = tempdir().expect("tempdir");
    let yaml_indented = "id: task-indented\ninstruction: >\n  first line\n    more indented 1\n    more indented 2\n  second line\n";
    fs::write(dir_indented.path().join("task.yaml"), yaml_indented).expect("write yaml");
    let task_indented = load_undated_task(dir_indented.path()).expect("load task");
    assert_eq!(
        task_indented.instruction,
        "first line\n  more indented 1\n  more indented 2\nsecond line"
    );

    // 3. Chomping indicators for literal block (|): strip, clip, keep
    // Strip (-): no trailing newline
    let dir_strip = tempdir().expect("tempdir");
    let yaml_strip = "id: task-strip\ninstruction: |-\n  line 1\n  line 2\n\n";
    fs::write(dir_strip.path().join("task.yaml"), yaml_strip).expect("write yaml");
    let task_strip = load_undated_task(dir_strip.path()).expect("load task");
    assert_eq!(task_strip.instruction, "line 1\nline 2");

    // Clip (default): one trailing newline
    let dir_clip = tempdir().expect("tempdir");
    let yaml_clip = "id: task-clip\ninstruction: |\n  line 1\n  line 2\n\n";
    fs::write(dir_clip.path().join("task.yaml"), yaml_clip).expect("write yaml");
    let task_clip = load_undated_task(dir_clip.path()).expect("load task");
    assert_eq!(task_clip.instruction, "line 1\nline 2\n");

    // Keep (+): all trailing newlines (content line break + 1 blank line = 2 newlines)
    let dir_keep = tempdir().expect("tempdir");
    let yaml_keep = "id: task-keep\ninstruction: |+\n  line 1\n  line 2\n\n";
    fs::write(dir_keep.path().join("task.yaml"), yaml_keep).expect("write yaml");
    let task_keep = load_undated_task(dir_keep.path()).expect("load task");
    assert_eq!(task_keep.instruction, "line 1\nline 2\n\n");

    // 4. Chomping indicators for folded block (>): strip, clip, keep
    // Strip (-): folded, no trailing newline
    let dir_fstrip = tempdir().expect("tempdir");
    let yaml_fstrip = "id: task-fstrip\ninstruction: >-\n  line 1\n  line 2\n\n";
    fs::write(dir_fstrip.path().join("task.yaml"), yaml_fstrip).expect("write yaml");
    let task_fstrip = load_undated_task(dir_fstrip.path()).expect("load task");
    assert_eq!(task_fstrip.instruction, "line 1 line 2");

    // Clip (default): folded, one trailing newline
    let dir_fclip = tempdir().expect("tempdir");
    let yaml_fclip = "id: task-fclip\ninstruction: >\n  line 1\n  line 2\n\n";
    fs::write(dir_fclip.path().join("task.yaml"), yaml_fclip).expect("write yaml");
    let task_fclip = load_undated_task(dir_fclip.path()).expect("load task");
    assert_eq!(task_fclip.instruction, "line 1 line 2\n");

    // Keep (+): folded, all trailing newlines (content line break + 1 blank line = 2 newlines)
    let dir_fkeep = tempdir().expect("tempdir");
    let yaml_fkeep = "id: task-fkeep\ninstruction: >+\n  line 1\n  line 2\n\n";
    fs::write(dir_fkeep.path().join("task.yaml"), yaml_fkeep).expect("write yaml");
    let task_fkeep = load_undated_task(dir_fkeep.path()).expect("load task");
    assert_eq!(task_fkeep.instruction, "line 1 line 2\n\n");
}

#[test]
fn test_regression_fix2_hash_inside_values() {
    // 1. "C# support"
    let dir1 = tempdir().expect("tempdir");
    fs::write(
        dir1.path().join("task.yaml"),
        "id: task1\ninstruction: Implement C# support\n",
    )
    .expect("write");
    let t1 = load_undated_task(dir1.path()).expect("load");
    assert_eq!(t1.instruction, "Implement C# support");

    // 2. "issue#12"
    let dir2 = tempdir().expect("tempdir");
    fs::write(
        dir2.path().join("task.yaml"),
        "id: task2\ninstruction: Fix issue#12\n",
    )
    .expect("write");
    let t2 = load_undated_task(dir2.path()).expect("load");
    assert_eq!(t2.instruction, "Fix issue#12");

    // 3. quoted "a # b" value (double and single)
    let dir3 = tempdir().expect("tempdir");
    fs::write(
        dir3.path().join("task.yaml"),
        "id: task3\ninstruction: \"a # b\"\n",
    )
    .expect("write");
    let t3 = load_undated_task(dir3.path()).expect("load");
    assert_eq!(t3.instruction, "a # b");

    let dir3s = tempdir().expect("tempdir");
    fs::write(
        dir3s.path().join("task.yaml"),
        "id: task3s\ninstruction: 'a # b'\n",
    )
    .expect("write");
    let t3s = load_undated_task(dir3s.path()).expect("load");
    assert_eq!(t3s.instruction, "a # b");

    // 4. "value # real comment"
    let dir4 = tempdir().expect("tempdir");
    fs::write(
        dir4.path().join("task.yaml"),
        "id: task4\ninstruction: my_value # real comment\n",
    )
    .expect("write");
    let t4 = load_undated_task(dir4.path()).expect("load");
    assert_eq!(t4.instruction, "my_value");
}

#[test]
fn test_regression_fix3_indentation_indicator() {
    // 1. With indicator |2: content indentation is parent (0) + 2 = 2.
    // "    first" (4 spaces >= 2) keeps 2 extra spaces -> "  first".
    // "  second" (2 spaces >= 2) belongs to block -> "second".
    let dir_ind = tempdir().expect("tempdir");
    let yaml_ind = "id: task-ind\ninstruction: |2\n    first\n  second\nother: 123\n";
    fs::write(dir_ind.path().join("task.yaml"), yaml_ind).expect("write");
    let t_ind = load_undated_task(dir_ind.path()).expect("load");
    assert_eq!(t_ind.instruction, "  first\nsecond");

    // 2. Case without indicator: first line sets indentation to 4.
    // "    first" has 4 spaces -> "first".
    // "  second" has 2 spaces < 4 -> terminates block!
    let dir_no_ind = tempdir().expect("tempdir");
    let yaml_no_ind = "id: task-no-ind\ninstruction: |\n    first\n  second\nother: 123\n";
    fs::write(dir_no_ind.path().join("task.yaml"), yaml_no_ind).expect("write");
    let t_no_ind = load_undated_task(dir_no_ind.path()).expect("load");
    assert_eq!(t_no_ind.instruction, "first");

    // 3. Folded with indicator and chomping: >-2
    let dir_f2 = tempdir().expect("tempdir");
    let yaml_f2 = "id: task-f2\ninstruction: >-2\n    first\n    second\n  third\n";
    fs::write(dir_f2.path().join("task.yaml"), yaml_f2).expect("write");
    let t_f2 = load_undated_task(dir_f2.path()).expect("load");
    // "    first" and "    second" have extra indent (4 - 2 = 2 spaces).
    // In folded scalar, more-indented lines keep newlines:
    assert_eq!(t_f2.instruction, "  first\n  second\nthird");
}

#[test]
fn test_regression_fix4_oversized_baseline_subtraction_and_budget() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // Create a 17 MiB baseline text file containing a distinctive solution line
    let base_dir = tempdir().expect("base dir");
    let base_file = base_dir.path().join("large_baseline.txt");
    {
        use std::io::Write;
        let mut f = fs::File::create(&base_file).expect("create large baseline");
        let line = "normal baseline filler line repeated for size padding\n";
        let target_size = 17 * 1024 * 1024;
        let mut written = 0;
        // Write the distinctive solution line near the middle of the file (e.g. at ~10 MiB)
        while written < 10 * 1024 * 1024 {
            f.write_all(line.as_bytes()).expect("write");
            written += line.len();
        }
        let secret_line =
            "let distinctive_solution_line = \"unique_secret_baseline_token_12345\";\n";
        f.write_all(secret_line.as_bytes()).expect("write secret");
        written += secret_line.len();
        while written < target_size {
            f.write_all(line.as_bytes()).expect("write");
            written += line.len();
        }
    }

    // Solution containing the distinctive line
    let task_dir = tempdir().expect("task dir");
    fs::create_dir_all(task_dir.path().join("solution")).expect("mkdir solution");
    fs::write(
        task_dir.path().join("solution/sol.rs"),
        "let distinctive_solution_line = \"unique_secret_baseline_token_12345\";\n",
    )
    .expect("write solution");

    let task = load_undated_task(task_dir.path()).expect("load task");

    // Part A: With standard/default budget (64 MiB), the 17 MiB baseline file is fully processed.
    // The solution line is subtracted against the base tree!
    let fp = FingerprintSet::from_files(&task.files, base_dir.path()).expect("from_files");
    assert_eq!(
        fp.lines_count, 0,
        "solution line present in 17 MiB base file must be subtracted (surviving lines = 0)"
    );
    assert_eq!(
        fp.subtracted_count, 1,
        "solution line must be recorded as subtracted"
    );
    assert!(
        !fp.baseline_incomplete,
        "baseline must not be marked incomplete under standard budget"
    );

    // Clean scan root containing the same line: must NOT produce a Gate!
    let scan_root = tempdir().expect("scan root");
    fs::write(
        scan_root.path().join("sol.rs"),
        "let distinctive_solution_line = \"unique_secret_baseline_token_12345\";\n",
    )
    .expect("write scan file");

    let findings = scan_tree(
        scan_root.path(),
        &fp,
        &ScanOptions {
            undated: true,
            ..Default::default()
        },
    );
    assert!(
        findings.iter().all(|f| f.severity != Severity::Gate),
        "scanning root with subtracted baseline line must produce no Gate: {findings:?}"
    );

    // CLI test with default budget: exits 0, no Gate
    let out = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_dir.path())
        .arg("--base-tree")
        .arg(base_dir.path())
        .arg("--root")
        .arg(scan_root.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan");
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("parse json");
    assert_eq!(json["gate"], false);

    // Part B: With a tiny test budget (e.g. 1024 bytes), baseline is incomplete and emits Info finding
    let fp_tiny = FingerprintSet::from_files_with_budget(&task.files, base_dir.path(), Some(1024))
        .expect("from_files_with_budget");
    assert!(fp_tiny.baseline_incomplete);
    assert!(
        fp_tiny.baseline_skipped_bytes > 0,
        "skipped bytes must be recorded: {}",
        fp_tiny.baseline_skipped_bytes
    );

    // CLI test with tiny budget: emits Info finding "baseline incomplete: N bytes not subtracted"
    let clean_empty_root = tempdir().expect("clean empty root");
    let out_tiny = Command::new(bin_path)
        .arg("scan")
        .arg("--undated")
        .arg("--task")
        .arg(task_dir.path())
        .arg("--base-tree")
        .arg(base_dir.path())
        .arg("--root")
        .arg(clean_empty_root.path())
        .arg("--baseline-budget")
        .arg("1024")
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan tiny");
    assert_eq!(out_tiny.status.code(), Some(0));
    let json_tiny: serde_json::Value =
        serde_json::from_slice(&out_tiny.stdout).expect("parse json");
    let findings_tiny = json_tiny["findings"].as_array().expect("findings array");
    let incomplete_finding = findings_tiny
        .iter()
        .find(|f| f["channel"] == "baseline_incomplete" && f["severity"] == "info")
        .expect("must emit baseline_incomplete Info finding");
    assert!(
        incomplete_finding["evidence"][0]
            .as_str()
            .unwrap()
            .contains("baseline incomplete:"),
        "evidence must contain 'baseline incomplete:': {incomplete_finding:?}"
    );
    assert!(
        incomplete_finding["evidence"][0]
            .as_str()
            .unwrap()
            .contains("bytes not subtracted"),
        "evidence must contain 'bytes not subtracted': {incomplete_finding:?}"
    );
}
