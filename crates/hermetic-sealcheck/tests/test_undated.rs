use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::{tempdir, TempDir};

use hermetic_sealcheck::{
    load_undated_task, query_index, scan_tree, write_index, Finding, FingerprintSet, ScanOptions,
    Visibility,
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
    let fp_ov = FingerprintSet::from_files(&undated_ov.files, base).expect("fp");
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
            "t_clock": "2024-01-02T00:00:00Z"
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
    let files: Vec<(String, String)> = (0..5)
        .map(|i| {
            (
                format!("solution/chunk_{i}.txt"),
                "A".repeat(15 * 1024 * 1024),
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
