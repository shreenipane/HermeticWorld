"""Security review regressions using offline, hand-written task fixtures."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil

import pytest

from hermetic_slice import dispositions as d
from tests.disposition_fixtures import complete_manifest, complete_task, d0, report

LEAK = "execute_critical_leak_line()"
STATEMENT = (
    "The calculation module fails under concurrent requests. Please preserve the public interface.\n"
    + LEAK + "\n"
    "Fix the numerical handling and retain useful diagnostic context for the user.\n"
)
PATCH = (
    "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n"
    "@@ -1,2 +1,3 @@\n def main():\n+    " + LEAK + "\n     do_base_work_initial()\n"
)
STAMP = 1704067200


def backdate(root):
    for directory, _, files in os.walk(root, topdown=False):
        for name in files:
            os.utime(Path(directory) / name, (STAMP, STAMP))
        os.utime(directory, (STAMP, STAMP))


@pytest.fixture
def task_world(tmp_path):
    tasks = tmp_path / "tasks"
    task = tasks / "task_one"
    (task / "agent").mkdir(parents=True)
    (task / "staging").mkdir()
    (task / "agent/problem_statement.md").write_text(STATEMENT, encoding="utf-8")
    (task / "task.json").write_text(json.dumps(complete_task("task_one")), encoding="utf-8")
    (task / "manifest.json").write_text(json.dumps(complete_manifest("task_one")), encoding="utf-8")
    (task / "staging/gold.patch").write_text(PATCH, encoding="utf-8")
    (task / "staging/test.patch").write_text("", encoding="utf-8")
    base = tmp_path / "base"
    base.mkdir()
    (base / "main.py").write_text("def main():\n    do_base_work_initial()\n", encoding="utf-8")
    root = tmp_path / "world"
    root.mkdir()
    backdate(tmp_path)
    config = {"base_tree": str(base), "roots": [{"path": str(root), "visibility": "agent_visible"}]}
    binary = d.find_binary("hermetic-sealcheck")
    initial = d.run_real_sealcheck(task, binary, scan_config=config)
    assert initial["gate"]
    assert {f["detector"] for f in initial["findings"] if f["severity"] == "gate"} == {"D0"}
    initial["scan_config"] = config
    return tasks, task, root, initial, binary


def test_real_world_root_leak_forces_exclusion(task_world):
    tasks, task, root, initial, binary = task_world
    (root / "leak.py").write_text("def main():\n    " + LEAK + "\n    do_base_work_initial()\n", encoding="utf-8")
    backdate(root)
    entries, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries[0]["disposition"] == "excluded"
    assert "D2" in entries[0]["detectors"]
    assert (task / "agent/problem_statement.md").read_text(encoding="utf-8") == STATEMENT
    assert not (task / "problem_statement_redacted.json").exists()


def test_real_scan_requires_actual_trees_and_configuration(task_world):
    tasks, task, _, initial, binary = task_world
    for config in (None, {}, {"base_tree": "/missing", "roots": []}):
        invalid = copy.deepcopy(initial)
        invalid["scan_config"] = config
        with pytest.raises(d.DispositionsError):
            d.process_dispositions([invalid], tasks_dir=tasks, sealcheck_bin=binary)
    with pytest.raises(d.DispositionsError):
        d.run_real_sealcheck(task, binary)


def test_cli_without_tasks_dir_stages_complete_real_task(task_world, tmp_path, capsys):
    _, _, _, initial, binary = task_world
    initial.update(problem_statement=STATEMENT, task_json=complete_task("task_one"),
                   gold_patch=PATCH, test_patch="", manifest=complete_manifest("task_one"))
    source, out = tmp_path / "input.json", tmp_path / "output.json"
    source.write_text(json.dumps([initial]), encoding="utf-8")
    assert d.dispositions_cli(["--gate-output", str(source), "--out", str(out), "--sealcheck", binary]) == 0
    entry = json.loads(out.read_text(encoding="utf-8"))[0]
    assert entry["disposition"] == "repaired"
    assert entry["world_version"].startswith("blake3:")
    for key in ("task_json", "gold_patch", "test_patch"):
        invalid = copy.deepcopy(initial)
        del invalid[key]
        with pytest.raises(d.DispositionsError):
            d.process_dispositions([invalid], sealcheck_bin=binary)
    assert LEAK not in capsys.readouterr().err


def test_repaired_manifest_loads_and_root_recomputes(task_world, tmp_path):
    tasks, task, _, initial, binary = task_world
    original = json.loads((task / "manifest.json").read_text(encoding="utf-8"))
    old_root = d.compute_real_world_version(original)
    entries, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    saved = json.loads((task / "manifest.json").read_text(encoding="utf-8"))
    assert "world_root" not in saved
    assert "problem_statement_redacted" not in saved
    assert saved["dispositions"][-1]["kind"] == "repaired"
    assert d.compute_real_world_version(saved) == entries[0]["world_version"] != old_root
    detail = json.loads(saved["dispositions"][-1]["detail"])
    assert detail["problem_statement_redacted"]
    assert LEAK not in json.dumps(saved)
    assert (task / "agent/problem_statement.md").stat().st_mode & 0o777 == 0o600
    assert (task / "problem_statement_redacted.json").stat().st_mode & 0o777 == 0o600


def test_surviving_text_changes_world_version_and_missing_manifest_rejected():
    roots = []
    for suffix in ("First surviving description.", "Other surviving description."):
        result = d.decide_task_disposition("task_one", [d0()], problem_statement="LEAK_VALUE " + "context " * 12 + suffix,
            manifest=complete_manifest("task_one"), rescan_fn=lambda *_: report())
        roots.append(result.world_version)
    assert roots[0] != roots[1]
    with pytest.raises(d.DispositionsError, match="manifest"):
        d.decide_task_disposition("task_one", [d0()], problem_statement=STATEMENT + "LEAK_VALUE",
                                  rescan_fn=lambda *_: report())


BAD_REPORTS = [
    {}, {"gate": True, "findings": []}, {"findings": [None]},
    {"gate": False, "findings": [], "not_covered": ["D1"]},
    {"findings": []}, {"gate": False, "findings": [], "not_covered": ""},
    {"gate": False, "findings": [{}], "not_covered": []},
    {"gate": False, "findings": [d0()], "not_covered": []},
    {"gate": "false", "findings": [], "not_covered": []},
    {"gate": False, "findings": [{"detector": "D0"}], "not_covered": []},
]


@pytest.mark.parametrize("invalid", BAD_REPORTS)
def test_initial_and_rescan_reports_fail_closed(invalid):
    with pytest.raises(d.MalformedGateOutputError):
        d.process_dispositions([{**invalid, "task_id": "task_one"}])
    with pytest.raises(d.MalformedGateOutputError):
        d.decide_task_disposition("task_one", [d0()], problem_statement="LEAK_VALUE " + "useful context " * 12,
            manifest=complete_manifest("task_one"), rescan_fn=lambda *_: invalid)


def test_identical_original_report_rerun_is_verified_and_stable(task_world):
    tasks, task, _, initial, binary = task_world
    first, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    before = {name: (task / name).read_bytes() for name in ("agent/problem_statement.md", "manifest.json", "problem_statement_redacted.json")}
    second, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert first == second
    assert second[0]["disposition"] == "repaired"
    assert before == {name: (task / name).read_bytes() for name in before}
    (task / "agent/problem_statement.md").write_text("tampered content", encoding="utf-8")
    with pytest.raises(d.DispositionsError, match="mismatch"):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)


@pytest.mark.parametrize("invalid", BAD_REPORTS)
def test_existing_sidecar_does_not_bypass_report_validation(task_world, invalid):
    tasks, _, _, initial, binary = task_world
    d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    with pytest.raises(d.MalformedGateOutputError):
        d.process_dispositions([{**invalid, "task_id": "task_one"}], tasks_dir=tasks)
    with pytest.raises(d.MalformedGateOutputError):
        d.process_dispositions([initial], tasks_dir=tasks, rescan_fn=lambda *_: invalid)


def test_sidecar_rerun_still_scans_real_world(task_world):
    tasks, _, root, initial, binary = task_world
    d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    (root / "leak.py").write_text(LEAK, encoding="utf-8")
    backdate(root)
    entries, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries[0]["disposition"] == "excluded"


def test_empty_disk_inline_statement_and_late_invalid_report_are_atomic(task_world, tmp_path):
    tasks, task, _, initial, binary = task_world
    path = task / "agent/problem_statement.md"
    path.write_text("", encoding="utf-8")
    initial["problem_statement"] = STATEMENT
    second = tasks / "task_two"
    (second / "agent").mkdir(parents=True)
    (second / "agent/problem_statement.md").write_text("", encoding="utf-8")
    out = tmp_path / "out.json"
    before = (task / "manifest.json").read_bytes()
    with pytest.raises(d.MalformedGateOutputError):
        d.process_dispositions([initial, report("task_two", [None])], tasks_dir=tasks, out_path=out, sealcheck_bin=binary)
    assert path.read_bytes() == b""
    assert (task / "manifest.json").read_bytes() == before
    assert not out.exists()
    assert not (task / "problem_statement_redacted.json").exists()


def test_real_rescan_failure_never_mutates_empty_statement(task_world, tmp_path, monkeypatch):
    tasks, task, _, initial, binary = task_world
    statement = task / "agent/problem_statement.md"
    statement.write_text("", encoding="utf-8")
    initial["problem_statement"] = STATEMENT
    original = d.compute_real_world_version
    calls = 0
    def fail_after_scan(manifest, manifest_bin=None):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise d.DispositionsError("verification failed")
        return original(manifest, manifest_bin)
    monkeypatch.setattr(d, "compute_real_world_version", fail_after_scan)
    with pytest.raises(d.DispositionsError):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert statement.read_bytes() == b""
    assert not (task / "problem_statement_redacted.json").exists()


@pytest.mark.parametrize("attack", ["ancestor", "inline_symlink", "fifo"])
def test_task_destination_special_files_rejected(task_world, tmp_path, attack):
    tasks, task, _, initial, binary = task_world
    statement = task / "agent/problem_statement.md"
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "problem_statement.md"
    secret.write_text("PRIVATE_CONTENT", encoding="utf-8")
    if attack == "ancestor":
        statement.unlink()
        statement.parent.rmdir()
        statement.parent.symlink_to(outside, target_is_directory=True)
    elif attack == "inline_symlink":
        statement.unlink()
        statement.symlink_to(secret)
        initial["problem_statement"] = STATEMENT
    else:
        statement.unlink()
        os.mkfifo(statement)
        initial["problem_statement"] = STATEMENT
    with pytest.raises(d.DispositionsError):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert secret.read_text(encoding="utf-8") == "PRIVATE_CONTENT"


def test_open_replacement_race_is_rejected(task_world, tmp_path, monkeypatch):
    tasks, task, _, initial, binary = task_world
    statement = task / "agent/problem_statement.md"
    secret = tmp_path / "secret"
    secret.write_text("PRIVATE_CONTENT", encoding="utf-8")
    real_open = os.open
    replaced = False
    def racing_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if path == "problem_statement.md" and not replaced:
            replaced = True
            statement.unlink()
            statement.symlink_to(secret)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", racing_open)
    with pytest.raises(d.DispositionsError):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert replaced
    assert secret.read_text(encoding="utf-8") == "PRIVATE_CONTENT"


def test_directory_replacement_during_scan_cannot_redirect_write(task_world, tmp_path, monkeypatch):
    tasks, task, _, initial, binary = task_world
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "problem_statement.md"
    secret.write_text("PRIVATE_CONTENT", encoding="utf-8")
    scan = d.run_real_sealcheck
    def racing_scan(*args, **kwargs):
        task.joinpath("agent").rename(task / "original_agent")
        task.joinpath("agent").symlink_to(outside, target_is_directory=True)
        return scan(*args, **kwargs)
    monkeypatch.setattr(d, "run_real_sealcheck", racing_scan)
    entries, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries[0]["disposition"] == "repaired"
    assert secret.read_text(encoding="utf-8") == "PRIVATE_CONTENT"
    assert LEAK not in (task / "original_agent/problem_statement.md").read_text(encoding="utf-8")


def test_resource_caps_on_input_counts_nesting_and_statement(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "MAX_REPORT_BYTES", 128)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * 129)
    with pytest.raises(d.DispositionsError, match="cap"):
        d.load_gate_output(oversized)
    with pytest.raises(d.DispositionsError, match="cap"):
        d.parse_json("[" * (d.MAX_JSON_DEPTH + 1) + "]" * (d.MAX_JSON_DEPTH + 1))
    with pytest.raises(d.DispositionsError):
        d.process_dispositions([report(str(i)) for i in range(d.MAX_TASKS + 1)])
    with pytest.raises(d.DispositionsError):
        d.validate_findings([d0()] * (d.MAX_FINDINGS + 1))
    monkeypatch.setattr(d, "MAX_STATEMENT_BYTES", 32)
    with pytest.raises(d.DispositionsError):
        d.process_dispositions([report(problem_statement="x" * 33)])
    directory = tmp_path / "reports"
    directory.mkdir()
    monkeypatch.setattr(d, "MAX_TASKS", 2)
    for index in range(3):
        (directory / f"{index}.json").write_text("[]", encoding="utf-8")
    with pytest.raises(d.DispositionsError, match="cap"):
        d.load_gate_output(directory)


def executable(path, code):
    path.write_text("#!/usr/bin/python3\n" + code, encoding="utf-8")
    path.chmod(0o700)
    return path


@pytest.mark.parametrize("pipe", ["stdout", "stderr"])
def test_subprocess_output_is_bounded(tmp_path, monkeypatch, pipe):
    monkeypatch.setattr(d, "MAX_PROCESS_OUTPUT_BYTES", 1024)
    binary = executable(tmp_path / "manifest", f"import sys\nsys.{pipe}.write('SENSITIVE' * 10000)\n")
    with pytest.raises(d.DispositionsError, match="output cap") as error:
        d.compute_real_world_version(complete_manifest("task_one"), manifest_bin=binary)
    assert "SENSITIVE" not in str(error.value)


def test_manifest_process_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "PROCESS_TIMEOUT_SECONDS", 0.1)
    binary = executable(tmp_path / "manifest", "import time\ntime.sleep(0.5)\nprint('blake3:' + '0' * 64)\n")
    with pytest.raises(d.DispositionsError, match="time cap"):
        d.compute_real_world_version(complete_manifest("task_one"), manifest_bin=binary)


@pytest.mark.parametrize("field,value", [
    ("task_id", "../SECRET_TOKEN"),
    ("not_covered", ["SECRET_TOKEN"]),
    ("findings", [{"detector": "SECRET_TOKEN", "severity": "gate"}]),
])
def test_secret_bearing_invalid_fields_never_reach_errors_or_output(tmp_path, capsys, field, value):
    invalid = report()
    invalid[field] = value
    with pytest.raises(d.DispositionsError) as error:
        d.process_dispositions([invalid])
    assert "SECRET_TOKEN" not in str(error.value)
    source, out = tmp_path / "input.json", tmp_path / "output.json"
    source.write_text(json.dumps([invalid]), encoding="utf-8")
    assert d.dispositions_cli(["--gate-output", str(source), "--out", str(out)]) != 0
    captured = capsys.readouterr()
    assert "SECRET_TOKEN" not in captured.err + captured.out
    assert not out.exists()
    if field == "not_covered":
        with pytest.raises(d.DispositionsError) as error:
            d.decide_task_disposition("task_one", [], not_covered=value)
        assert "SECRET_TOKEN" not in str(error.value)


def test_mixed_dispositions_are_recorded_in_rust_loadable_manifests(task_world):
    tasks, task, _, initial, binary = task_world
    inputs = [initial]
    for tid, findings in (("task_clean", []), ("task_excluded", [{**d0(), "detector": "D2"}])):
        directory = tasks / tid
        (directory / "agent").mkdir(parents=True)
        (directory / "staging").mkdir()
        (directory / "agent/problem_statement.md").write_text("Ordinary issue description.", encoding="utf-8")
        (directory / "manifest.json").write_text(json.dumps(complete_manifest(tid)), encoding="utf-8")
        (directory / "task.json").write_text(json.dumps(complete_task(tid)), encoding="utf-8")
        (directory / "staging/gold.patch").write_text(PATCH, encoding="utf-8")
        (directory / "staging/test.patch").write_text("", encoding="utf-8")
        inputs.append(report(tid, findings, scan_config=initial["scan_config"]))
    entries, _ = d.process_dispositions(inputs, tasks_dir=tasks, sealcheck_bin=binary)
    assert {entry["disposition"] for entry in entries} == {"clean", "repaired", "excluded"}
    for entry in entries:
        manifest = json.loads((tasks / entry["task_id"] / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["dispositions"][-1]["kind"] == entry["disposition"]
        assert d.compute_real_world_version(manifest) == entry["world_version"]


@pytest.mark.parametrize("span", [(1, 1), (1, 2), (0, 1)])
def test_redaction_rejects_utf8_interior_boundaries(span):
    with pytest.raises(d.DispositionsError, match="UTF-8"):
        d.redact_problem_statement("é", [span])


@pytest.mark.parametrize("field", ["detector", "severity", "visibility", "channel", "path", "confidence", "evidence"])
def test_required_finding_fields_are_validated(field):
    finding = d0()
    del finding[field]
    with pytest.raises(d.MalformedGateOutputError):
        d.process_dispositions([report(findings=[finding])])
    with pytest.raises(d.MalformedGateOutputError):
        d.decide_task_disposition("task_one", [d0()], problem_statement="LEAK_VALUE " + "context " * 12,
            manifest=complete_manifest("task_one"), rescan_fn=lambda *_: report(findings=[finding]))


def test_identical_inline_statement_and_explicit_span_rerun(task_world):
    tasks, _, _, initial, binary = task_world
    start = STATEMENT.encode("utf-8").index(LEAK.encode("utf-8"))
    initial["problem_statement"] = STATEMENT
    initial["explicit_spans"] = [(start, start + len(LEAK))]
    first, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    second, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert first == second
    assert second[0]["disposition"] == "repaired"


def test_persisted_spans_must_match_actual_redaction_markers(task_world):
    tasks, task, _, initial, binary = task_world
    d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    sidecar = task / "problem_statement_redacted.json"
    metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    metadata["spans"][0]["start"] += 1
    metadata["spans"][0]["end"] += 1
    sidecar.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(d.DispositionsError, match="mismatch"):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)


def test_regression_defect1_oversized_leaking_file_refuses_repair(task_world):
    """Defect 1: real sealcheck with an oversized leaking file refuses repair."""
    tasks, task, root, initial, binary = task_world
    oversized = root / "large_leak.txt"
    with open(oversized, "wb") as f:
        f.seek(64 * 1024 * 1024 + 1024)
        f.write(b"def main():\n    " + LEAK.encode("utf-8") + b"\n")
    backdate(root)
    with pytest.raises((d.MalformedGateOutputError, d.DispositionsError)):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)


def test_regression_defect2_conflicting_inline_disk_patches_refused(task_world):
    """Defect 2: conflicting inline/disk patches cannot become repaired."""
    tasks, task, root, initial, binary = task_world
    conflicting = copy.deepcopy(initial)
    conflicting["gold_patch"] = ""
    conflicting["test_patch"] = ""
    start = STATEMENT.encode("utf-8").index(LEAK.encode("utf-8"))
    conflicting["explicit_spans"] = [(start, start + len(LEAK))]
    with pytest.raises(d.DispositionsError, match="Conflicting inline"):
        d.process_dispositions([conflicting], tasks_dir=tasks, sealcheck_bin=binary)


def test_regression_defect3_cli_without_tasks_dir_emits_durable_artifacts(task_world, tmp_path):
    """Defect 3: CLI without --tasks-dir emits durable repaired content, metadata, and manifest."""
    _, _, _, initial, binary = task_world
    initial.update(problem_statement=STATEMENT, task_json=complete_task("task_one"),
                   gold_patch=PATCH, test_patch="", manifest=complete_manifest("task_one"))
    source, out = tmp_path / "input.json", tmp_path / "output.json"
    source.write_text(json.dumps([initial]), encoding="utf-8")
    code = d.dispositions_cli(["--gate-output", str(source), "--out", str(out), "--sealcheck", binary])
    assert code == 0
    records = json.loads(out.read_text(encoding="utf-8"))
    assert len(records) == 1
    entry = records[0]
    assert entry["disposition"] == "repaired"
    assert "redacted_statement" in entry
    assert LEAK not in entry["redacted_statement"]
    assert "[REDACTED]" in entry["redacted_statement"]
    assert "problem_statement_redacted" in entry
    assert isinstance(entry["problem_statement_redacted"]["spans"], list)
    assert len(entry["problem_statement_redacted"]["spans"]) >= 1
    assert "manifest" in entry
    assert entry["manifest"]["dispositions"][-1]["kind"] == "repaired"


def test_regression_defect4_replace_config_and_root_ancestor_rejected(task_world, tmp_path):
    """Defect 4: replace configuration files and root ancestors between validation and subprocess access."""
    tasks, task, root, initial, binary = task_world
    sig_file = tmp_path / "signatures.json"
    sig_file.write_text(json.dumps({}), encoding="utf-8")
    initial["scan_config"]["signatures"] = str(sig_file)
    validated = d.validate_scan_config(initial["scan_config"])

    outside = tmp_path / "outside_secret"
    outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
    sig_file.unlink()
    sig_file.symlink_to(outside)
    with pytest.raises(d.DispositionsError):
        d.run_real_sealcheck(task, binary, scan_config=validated)

    sig_file.unlink()
    sig_file.write_text(json.dumps({}), encoding="utf-8")
    initial["scan_config"] = {"base_tree": initial["scan_config"]["base_tree"], "roots": [{"path": str(root), "visibility": "agent_visible"}]}
    validated = d.validate_scan_config(initial["scan_config"])
    nested_root = root / "sub" / "leaf"
    nested_root.mkdir(parents=True)
    validated["roots"] = [{"path": str(nested_root), "visibility": "agent_visible"}]

    shutil.rmtree(root / "sub")
    (root / "sub").symlink_to(outside, target_is_directory=True)
    with pytest.raises(d.DispositionsError):
        d.run_real_sealcheck(task, binary, scan_config=validated)


def test_regression_defect5_replace_agent_during_scan_ensures_verified_repair(task_world, monkeypatch):
    """Defect 5: replace agent during scanning requires verified repair at published task path."""
    tasks, task, _, initial, binary = task_world
    scan = d.run_real_sealcheck
    def racing_scan(*args, **kwargs):
        task.joinpath("agent").rename(task / "renamed_agent")
        replacement_agent = task / "agent"
        replacement_agent.mkdir(parents=True, exist_ok=True)
        (replacement_agent / "problem_statement.md").write_text(STATEMENT, encoding="utf-8")
        return scan(*args, **kwargs)
    monkeypatch.setattr(d, "run_real_sealcheck", racing_scan)
    entries, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries[0]["disposition"] == "repaired"
    published_statement = (task / "agent/problem_statement.md").read_text(encoding="utf-8")
    assert LEAK not in published_statement
    assert published_statement == entries[0]["redacted_statement"]


def test_regression_defect7_exclusion_without_rescan_inputs(tmp_path):
    """Defect 7: unsupported-detector and issue-text-is-the-fix reports without re-scan inputs."""
    reports = [
        {
            "task_id": "task__d2_unsupported",
            "gate": True,
            "not_covered": [],
            "findings": [
                {
                    "detector": "D2",
                    "channel": "file",
                    "path": "leaked.py",
                    "visibility": "agent_visible",
                    "severity": "gate",
                    "confidence": 1.0,
                    "evidence": ["some leak"],
                }
            ],
        },
        {
            "task_id": "task__issue_text_fix",
            "gate": True,
            "not_covered": [],
            "issue_text_is_the_fix": True,
            "findings": [
                {
                    "detector": "D0",
                    "channel": "problem_statement",
                    "path": "agent/problem_statement.md",
                    "visibility": "agent_visible",
                    "severity": "gate",
                    "confidence": 1.0,
                    "evidence": ["fix in text"],
                }
            ],
        },
    ]
    source, out = tmp_path / "input.json", tmp_path / "output.json"
    source.write_text(json.dumps(reports), encoding="utf-8")
    code = d.dispositions_cli(["--gate-output", str(source), "--out", str(out)])
    assert code == 0
    records = json.loads(out.read_text(encoding="utf-8"))
    assert len(records) == 2
    r_a = next(r for r in records if r["task_id"] == "task__d2_unsupported")
    assert r_a["disposition"] == "excluded"
    assert "D2" in r_a["detectors"]
    r_b = next(r for r in records if r["task_id"] == "task__issue_text_fix")
    assert r_b["disposition"] == "excluded"
    assert "D0" in r_b["detectors"]


def test_regression_defect8_clean_and_excluded_rerun_idempotent(tmp_path):
    """Defect 8: process clean and excluded tasks twice against their persisted manifests."""
    tasks = tmp_path / "tasks"
    tasks.mkdir(parents=True)
    reports = []
    for tid, findings in (("task_clean_8", []), ("task_excluded_8", [{**d0(), "detector": "D2"}])):
        t_dir = tasks / tid
        (t_dir / "agent").mkdir(parents=True)
        (t_dir / "agent/problem_statement.md").write_text("Issue statement text.", encoding="utf-8")
        manifest = complete_manifest(tid)
        (t_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (t_dir / "task.json").write_text(json.dumps(complete_task(tid)), encoding="utf-8")
        reports.append(report(tid, findings))
    out1 = tmp_path / "out1.json"
    entries1, _ = d.process_dispositions(reports, tasks_dir=tasks, out_path=out1)
    manifest_bytes_run1 = {
        tid: (tasks / tid / "manifest.json").read_bytes()
        for tid in ("task_clean_8", "task_excluded_8")
    }
    out2 = tmp_path / "out2.json"
    entries2, _ = d.process_dispositions(reports, tasks_dir=tasks, out_path=out2)
    manifest_bytes_run2 = {
        tid: (tasks / tid / "manifest.json").read_bytes()
        for tid in ("task_clean_8", "task_excluded_8")
    }
    assert manifest_bytes_run1 == manifest_bytes_run2
    assert entries1 == entries2
    assert [e["world_version"] for e in entries1] == [e["world_version"] for e in entries2]


def test_regression_defect9_secret_bearing_missing_paths_never_leak(tmp_path, capsys):
    """Defect 9: exercise both CLI entry points and API with secret-bearing missing paths."""
    from hermetic_slice.__main__ import main as cli_main
    secret_name = "SECRET_TOKEN_XYZ_12345"
    missing_gate_path = tmp_path / f"{secret_name}.json"
    with pytest.raises(d.DispositionsError) as exc_info:
        d.process_dispositions(missing_gate_path)
    assert secret_name not in str(exc_info.value)
    assert secret_name not in repr(exc_info.value)

    capsys.readouterr()
    code1 = d.dispositions_cli(["--gate-output", str(missing_gate_path)])
    assert code1 != 0
    cap1 = capsys.readouterr()
    assert secret_name not in cap1.err
    assert secret_name not in cap1.out

    code2 = cli_main(["dispositions", "--gate-output", str(missing_gate_path)])
    assert code2 != 0
    cap2 = capsys.readouterr()
    assert secret_name not in cap2.err
    assert secret_name not in cap2.out


def test_regression_defect1_nul_byte_leak_refuses_clean_and_repair(task_world, tmp_path):
    """Defect 1: unrecognized NUL-containing files must be rejected for both clean and repair paths."""
    tasks, task, root, initial, binary = task_world
    nul_file = root / "nul_leak.txt"
    nul_file.write_bytes(b"\x00" + LEAK.encode("utf-8"))
    os.utime(nul_file, (STAMP, STAMP))

    # Clean path: clean statement, real sealcheck / dispositions must reject incomplete scan
    clean_statement = "Clean problem statement without leak.\n"
    (task / "agent/problem_statement.md").write_text(clean_statement, encoding="utf-8")
    os.utime(task / "agent/problem_statement.md", (STAMP, STAMP))
    with pytest.raises((d.MalformedGateOutputError, d.DispositionsError)):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])

    # Repair path: D0 leak in statement, repair re-scan with NUL file must reject / refuse repair
    (task / "agent/problem_statement.md").write_text(STATEMENT, encoding="utf-8")
    os.utime(task / "agent/problem_statement.md", (STAMP, STAMP))
    with pytest.raises((d.MalformedGateOutputError, d.DispositionsError)):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)


def test_regression_defect2_replace_ancestor_at_subprocess_launch_no_outside_reads(task_world, monkeypatch, tmp_path):
    """Defect 2: replace root ancestor at subprocess launch and assert no outside reads."""
    tasks, task, root, initial, binary = task_world

    sub_dir = root / "ancestor" / "target"
    sub_dir.mkdir(parents=True)
    target_file = sub_dir / "target.py"
    target_file.write_text("safe_internal_code = 1\n", encoding="utf-8")
    backdate(root)

    outside = tmp_path / "outside_dir"
    outside.mkdir()
    outside_secret = outside / "secret.txt"
    outside_secret.write_text("CRITICAL_OUTSIDE_SECRET_LEAK\n", encoding="utf-8")
    backdate(outside)

    scan_config = {
        "base_tree": initial["scan_config"]["base_tree"],
        "roots": [{"path": str(sub_dir), "visibility": "agent_visible"}],
    }

    original_bounded_process = d.bounded_process
    replaced = False

    def hook_bounded_process(argv, timeout=d.PROCESS_TIMEOUT_SECONDS, **kwargs):
        nonlocal replaced
        if "scan" in argv:
            shutil.rmtree(root / "ancestor")
            (root / "ancestor").symlink_to(outside, target_is_directory=True)
            replaced = True
        return original_bounded_process(argv, timeout=timeout, **kwargs)

    monkeypatch.setattr(d, "bounded_process", hook_bounded_process)

    result = d.run_real_sealcheck(task, binary, scan_config=scan_config)
    assert replaced
    result_text = json.dumps(result)
    assert "CRITICAL_OUTSIDE_SECRET_LEAK" not in result_text
    assert str(outside) not in result_text


def test_regression_defect3_replace_entire_task_dir_during_scan_rejected(task_world, monkeypatch):
    """Defect 3: replace entire task directory during scanning requires rejection."""
    tasks, task, _, initial, binary = task_world
    scan = d.run_real_sealcheck

    def racing_scan(*args, **kwargs):
        stale_task = tasks / "task_one_stale"
        task.rename(stale_task)
        task.mkdir(parents=True, exist_ok=True)
        (task / "agent").mkdir(parents=True, exist_ok=True)
        (task / "agent/problem_statement.md").write_text(STATEMENT, encoding="utf-8")
        (task / "task.json").write_text(json.dumps(complete_task("task_one")), encoding="utf-8")
        (task / "manifest.json").write_text(json.dumps(complete_manifest("task_one")), encoding="utf-8")
        return scan(*args, **kwargs)

    monkeypatch.setattr(d, "run_real_sealcheck", racing_scan)
    with pytest.raises(d.DispositionsError, match="modified or replaced between validation and publication"):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)


def test_regression_defect4_cli_whole_statement_and_over_threshold_d0_no_scan_inputs(tmp_path):
    """Defect 4: CLI with whole-statement and over-threshold D0 findings, no scan inputs -> excluded records."""
    tasks = tmp_path / "tasks"
    tasks.mkdir(parents=True)

    tid1 = "task_whole_statement"
    t1_dir = tasks / tid1
    (t1_dir / "agent").mkdir(parents=True)
    text1 = "Short statement to redact fully."
    (t1_dir / "agent/problem_statement.md").write_text(text1, encoding="utf-8")
    (t1_dir / "task.json").write_text(json.dumps(complete_task(tid1)), encoding="utf-8")
    (t1_dir / "manifest.json").write_text(json.dumps(complete_manifest(tid1)), encoding="utf-8")
    rep1 = {
        "task_id": tid1,
        "gate": True,
        "not_covered": [],
        "findings": [
            {
                "detector": "D0",
                "channel": "problem_statement",
                "path": "agent/problem_statement.md",
                "visibility": "agent_visible",
                "severity": "gate",
                "confidence": 1.0,
                "evidence": [text1],
                "char_spans": [[0, len(text1)]],
            }
        ],
    }

    tid2 = "task_over_threshold"
    t2_dir = tasks / tid2
    (t2_dir / "agent").mkdir(parents=True)
    text2 = "12345678901234567890123456789012345678901234567890"
    (t2_dir / "agent/problem_statement.md").write_text(text2, encoding="utf-8")
    (t2_dir / "task.json").write_text(json.dumps(complete_task(tid2)), encoding="utf-8")
    (t2_dir / "manifest.json").write_text(json.dumps(complete_manifest(tid2)), encoding="utf-8")
    leak2 = "12345678901234567890"
    rep2 = {
        "task_id": tid2,
        "gate": True,
        "not_covered": [],
        "findings": [
            {
                "detector": "D0",
                "channel": "problem_statement",
                "path": "agent/problem_statement.md",
                "visibility": "agent_visible",
                "severity": "gate",
                "confidence": 1.0,
                "evidence": [leak2],
            }
        ],
    }

    source, out = tmp_path / "input.json", tmp_path / "output.json"
    source.write_text(json.dumps([rep1, rep2]), encoding="utf-8")
    code = d.dispositions_cli(["--gate-output", str(source), "--out", str(out), "--tasks-dir", str(tasks)])
    assert code == 0

    records = json.loads(out.read_text(encoding="utf-8"))
    assert len(records) == 2
    r1 = next(r for r in records if r["task_id"] == tid1)
    assert r1["disposition"] == "excluded"
    assert "D0" in r1["detectors"]
    assert "reason" in r1 and any("statement" in s.lower() or "threshold" in s.lower() or "issue text" in s.lower() for s in [r1["reason"]])

    r2 = next(r for r in records if r["task_id"] == tid2)
    assert r2["disposition"] == "excluded"
    assert "D0" in r2["detectors"]
    assert "reason" in r2 and any("statement" in s.lower() or "threshold" in s.lower() or "issue text" in s.lower() for s in [r2["reason"]])


def test_regression_defect5_previously_repaired_task_receives_d2_exclusion_without_scan_config(task_world, tmp_path):
    """Defect 5: previously repaired task receives D2 exclusion without scan configuration."""
    tasks, task, _, initial, binary = task_world

    entries1, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries1[0]["disposition"] == "repaired"
    assert (task / "problem_statement_redacted.json").is_file()

    d2_report = {
        "task_id": "task_one",
        "gate": True,
        "not_covered": [],
        "findings": [
            {
                "detector": "D2",
                "channel": "file",
                "path": "leaked.py",
                "visibility": "agent_visible",
                "severity": "gate",
                "confidence": 1.0,
                "evidence": ["leaked_solution_line()"],
            }
        ],
    }

    out = tmp_path / "d2_out.json"
    entries2, _ = d.process_dispositions([d2_report], tasks_dir=tasks, sealcheck_bin=binary, out_path=out)
    assert len(entries2) == 1
    assert entries2[0]["disposition"] == "excluded"
    assert "D2" in entries2[0]["detectors"]

    manifest = json.loads((task / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["dispositions"][-1]["kind"] == "excluded"
    assert manifest["dispositions"][-1]["detector"] == "D2"


@pytest.mark.parametrize(
    "artifact_rel",
    [
        "manifest.json",
        "agent/problem_statement.md",
        "problem_statement_redacted.json",
        "staging/gold.patch",
        "staging/test.patch",
        "task.json",
    ],
)
def test_regression_defect8_output_collisions_with_task_artifacts_rejected(task_world, artifact_rel):
    """Defect 8: parameterize output collisions with task inputs/artifacts; assert rejection and unchanged files."""
    tasks, task, _, initial, binary = task_world
    target_path = task / artifact_rel
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if not target_path.exists():
        target_path.write_text("initial sentinel content", encoding="utf-8")
    before_bytes = target_path.read_bytes()

    with pytest.raises(d.DispositionsError, match="Report destination overlaps task artifact"):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary, out_path=target_path)

    after_bytes = target_path.read_bytes()
    assert before_bytes == after_bytes


def test_regression_snapshot_escaping_symlinks_rejected_without_reading_canary(task_world, tmp_path):
    """Defect 1: absolute and relative escaping symlinks must be rejected without reading outside canary."""
    tasks, task, root, initial, binary = task_world

    # Outside canary file with 000 permissions: any host read attempt causes PermissionError
    canary = tmp_path / "outside_canary.txt"
    canary.write_text("CRITICAL_OUTSIDE_CANARY_SECRET_DATA\n", encoding="utf-8")
    os.chmod(canary, 0o000)

    # 1. Absolute symlink to outside canary
    abs_sym = root / "abs_link"
    abs_sym.symlink_to(canary)
    backdate(root)
    with pytest.raises(d.DispositionsError, match="Escaping symlink rejected"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])
    abs_sym.unlink()

    # 2. Relative escaping symlink to outside canary
    sub_dir = root / "subdir"
    sub_dir.mkdir(parents=True, exist_ok=True)
    rel_sym = sub_dir / "rel_link"
    # From root/subdir to outside canary: ../../outside_canary.txt
    rel_sym.symlink_to(os.path.relpath(canary, sub_dir))
    backdate(root)
    with pytest.raises(d.DispositionsError, match="Escaping symlink rejected"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])
    rel_sym.unlink()

    # 3. Permitted relative symlink staying inside root succeeds
    inside_target = root / "inside_target.txt"
    inside_target.write_text("def safe_inside():\n    return 42\n", encoding="utf-8")
    safe_sym = sub_dir / "safe_link"
    safe_sym.symlink_to("../inside_target.txt")
    backdate(root)
    dst_snap = tmp_path / "safe_snapshot"
    d.snapshot_tree_safely(root, dst_snap)
    assert (dst_snap / "subdir" / "safe_link").is_symlink()
    assert os.readlink(dst_snap / "subdir" / "safe_link") == "../inside_target.txt"


def test_regression_snapshot_unsupported_entries_and_failures_fail_closed(task_world, tmp_path, monkeypatch):
    """Defect 5: FIFO/socket entries and injected metadata/readlink failures fail closed; task artifacts unchanged."""
    import socket

    tasks, task, root, initial, binary = task_world
    task_json_before = (task / "task.json").read_bytes()
    statement_before = (task / "agent/problem_statement.md").read_bytes()
    manifest_before = (task / "manifest.json").read_bytes()

    def assert_artifacts_unchanged():
        assert (task / "task.json").read_bytes() == task_json_before
        assert (task / "agent/problem_statement.md").read_bytes() == statement_before
        assert (task / "manifest.json").read_bytes() == manifest_before

    # 1. FIFO entry in root
    fifo_path = root / "special_fifo"
    os.mkfifo(fifo_path)
    try:
        with pytest.raises(d.DispositionsError, match="Unsupported file system entry type"):
            d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])
        assert_artifacts_unchanged()
    finally:
        fifo_path.unlink()

    # 2. Socket entry in root
    sock_path = root / "special_sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sock_path))
        with pytest.raises(d.DispositionsError, match="Unsupported file system entry type"):
            d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])
        assert_artifacts_unchanged()
    finally:
        sock.close()
        if sock_path.exists():
            sock_path.unlink()

    # 3. Injected metadata (stat) failure during snapshot traversal
    orig_stat = os.stat

    def failing_stat(name, *args, **kwargs):
        if str(name) == "main.py" or (isinstance(name, Path) and name.name == "main.py"):
            raise OSError("Injected disk metadata I/O failure")
        return orig_stat(name, *args, **kwargs)

    monkeypatch.setattr(os, "stat", failing_stat)
    with pytest.raises(d.DispositionsError, match="Failed to stat directory entry"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])
    assert_artifacts_unchanged()
    monkeypatch.undo()

    # 4. Injected readlink failure
    inside_target = root / "readable_target.txt"
    inside_target.write_text("readable content\n", encoding="utf-8")
    test_link = root / "test_link"
    test_link.symlink_to("readable_target.txt")
    backdate(root)

    orig_readlink = os.readlink

    def failing_readlink(path, *args, **kwargs):
        if "test_link" in str(path):
            raise OSError("Injected readlink hardware fault")
        return orig_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", failing_readlink)
    with pytest.raises(d.DispositionsError, match="Failed to readlink"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])
    assert_artifacts_unchanged()
    monkeypatch.undo()


def test_regression_snapshot_descriptors_closed_and_bounded(tmp_path):
    """Defect 6: directory descriptors closed on success and failure; bounded under lowered limit."""
    import resource

    tree_root = tmp_path / "deep_tree"
    tree_root.mkdir()
    # Create 30 child directories each with subdirectories and files
    for i in range(30):
        sub = tree_root / f"dir_{i}" / "nested"
        sub.mkdir(parents=True)
        (sub / f"file_{i}.txt").write_text(f"content {i}\n", encoding="utf-8")

    dst_dir = tmp_path / "dst_tree"

    def count_open_fds():
        return len(os.listdir("/proc/self/fd"))

    # Verify no descriptor leaks across repeated successful snapshots
    initial_fds = count_open_fds()
    for _ in range(5):
        if dst_dir.exists():
            shutil.rmtree(dst_dir)
        d.snapshot_tree_safely(tree_root, dst_dir)
        assert count_open_fds() == initial_fds

    # Verify no descriptor leaks across repeated failing snapshots
    bad_root = tmp_path / "bad_tree"
    bad_root.mkdir()
    (bad_root / "bad_link").symlink_to("/outside/nonexistent")
    failing_dst = tmp_path / "failing_dst"
    for _ in range(5):
        if failing_dst.exists():
            shutil.rmtree(failing_dst)
        with pytest.raises(d.DispositionsError):
            d.snapshot_tree_safely(bad_root, failing_dst)
        assert count_open_fds() == initial_fds

    # Traversal under a lowered descriptor limit
    cur_soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    # Give just enough descriptors for Python and the bounded descriptor traversal (around 15 more than currently open)
    target_limit = initial_fds + 15
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
        low_dst = tmp_path / "low_limit_dst"
        d.snapshot_tree_safely(tree_root, low_dst)
        assert (low_dst / "dir_0" / "nested" / "file_0.txt").read_text(encoding="utf-8") == "content 0\n"
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (cur_soft, hard))


def test_regression_snapshot_entry_cap_separated_from_task_enumeration(tmp_path, monkeypatch):
    """Defect 7: snapshot directory traversal handles >128 files; rejects at snapshot entry cap."""
    base_dir = tmp_path / "base_tree_large"
    base_dir.mkdir()
    # 129 files in a single directory: exceeds MAX_TASKS (128)
    for i in range(129):
        (base_dir / f"module_{i:03d}.py").write_text(f"def fn_{i}(): pass\n", encoding="utf-8")

    dst_dir = tmp_path / "dst_tree_large"
    # Must succeed despite exceeding MAX_TASKS
    d.snapshot_tree_safely(base_dir, dst_dir)
    assert len(list(dst_dir.glob("module_*.py"))) == 129

    # Verify rejection at the actual snapshot entry cap
    monkeypatch.setattr(d, "MAX_SNAPSHOT_ENTRIES", 150)
    extra_dir = tmp_path / "over_cap_dir"
    extra_dir.mkdir()
    for i in range(151):
        (extra_dir / f"f_{i:03d}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(d.DispositionsError, match="Snapshot entry count cap exceeded"):
        d.snapshot_tree_safely(extra_dir, tmp_path / "over_cap_dst")


def test_regression_symlink_confinement_validated_against_completed_snapshot(task_world, tmp_path, monkeypatch):
    """Defect 1: validate symlinks against completed private snapshot; rejects concurrent link mutation before sealcheck."""
    tasks, task, root, initial, binary = task_world

    # Place canary in parent of root (tmp_path / "canary")
    canary = tmp_path / "canary"
    canary.write_text("CANARY_OUTSIDE_LEAK_SECRET\n", encoding="utf-8")

    deep_dir = root / "dir" / "deep"
    deep_dir.mkdir(parents=True, exist_ok=True)
    inside_canary = root / "canary"
    inside_canary.write_text("safe inside canary\n", encoding="utf-8")

    link_b = root / "b"
    link_b.symlink_to("dir/deep")

    link_a = root / "a"
    link_a.symlink_to("b/../../canary")
    backdate(root)

    task_json_before = (task / "task.json").read_bytes()
    statement_before = (task / "agent/problem_statement.md").read_bytes()
    manifest_before = (task / "manifest.json").read_bytes()

    canary_read = False
    orig_open = open

    def guarded_open(file, *args, **kwargs):
        nonlocal canary_read
        if str(canary) in str(file):
            canary_read = True
        return orig_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)

    sealcheck_ran = False
    orig_bounded_process = d.bounded_process

    def spy_process(cmd, *args, **kwargs):
        nonlocal sealcheck_ran
        sealcheck_ran = True
        return orig_bounded_process(cmd, *args, **kwargs)

    monkeypatch.setattr(d, "bounded_process", spy_process)

    # Deterministically change 'b' to 'dir' between validation and copying
    orig_symlink = os.symlink
    changed = False

    def race_symlink(src, dst, *args, **kwargs):
        nonlocal changed
        res = orig_symlink(src, dst, *args, **kwargs)
        if not changed and Path(dst).name == "a":
            link_b.unlink()
            link_b.symlink_to("dir")
            changed = True
        return res

    monkeypatch.setattr(os, "symlink", race_symlink)

    with pytest.raises(d.DispositionsError, match="Escaping symlink rejected"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])

    assert changed
    assert not sealcheck_ran
    assert not canary_read
    assert (task / "task.json").read_bytes() == task_json_before
    assert (task / "agent/problem_statement.md").read_bytes() == statement_before
    assert (task / "manifest.json").read_bytes() == manifest_before


def test_regression_queued_directory_substitution_rejected(task_world, monkeypatch):
    """Defect 2: queued directory substitution after enumeration is rejected; task artifacts unchanged; no fd leak."""
    tasks, task, root, initial, binary = task_world

    task_json_before = (task / "task.json").read_bytes()
    statement_before = (task / "agent/problem_statement.md").read_bytes()
    manifest_before = (task / "manifest.json").read_bytes()

    dir_a = root / "a"
    dir_a.mkdir()
    (dir_a / "leak.txt").write_text("LEAK_IN_A\n", encoding="utf-8")

    dir_z = root / "z"
    dir_z.mkdir()
    (dir_z / "child.txt").write_text("clean_z\n", encoding="utf-8")
    backdate(root)

    def count_open_fds():
        return len(os.listdir("/proc/self/fd"))

    initial_fds = count_open_fds()

    orig_open_descendant = d.open_safe_descendant
    replaced = False

    def hook_open_descendant(root_dir, rel_path, *args, **kwargs):
        nonlocal replaced
        if not replaced and rel_path == ("z",):
            shutil.rmtree(dir_a)
            dir_a.mkdir()
            (dir_a / "clean.txt").write_text("replacement\n", encoding="utf-8")
            backdate(root)
            replaced = True
        return orig_open_descendant(root_dir, rel_path, *args, **kwargs)

    monkeypatch.setattr(d, "open_safe_descendant", hook_open_descendant)

    with pytest.raises(d.DispositionsError, match="Directory substituted or changed during traversal"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])

    assert replaced
    assert (task / "task.json").read_bytes() == task_json_before
    assert (task / "agent/problem_statement.md").read_bytes() == statement_before
    assert (task / "manifest.json").read_bytes() == manifest_before
    assert count_open_fds() == initial_fds


def test_regression_destination_utime_failure_fails_closed(task_world, monkeypatch):
    """Defect 3: destination file utime failure fails closed with sanitized error; task artifacts unchanged."""
    tasks, task, root, initial, binary = task_world

    task_json_before = (task / "task.json").read_bytes()
    statement_before = (task / "agent/problem_statement.md").read_bytes()
    manifest_before = (task / "manifest.json").read_bytes()

    orig_utime = os.utime
    utime_failed = False

    def failing_utime(path, *args, **kwargs):
        nonlocal utime_failed
        p_str = str(path)
        if "disposition_config_" in p_str and (p_str.endswith(".py") or p_str.endswith(".txt") or p_str.endswith(".md")):
            utime_failed = True
            raise OSError("Injected destination file utime hardware fault")
        return orig_utime(path, *args, **kwargs)

    monkeypatch.setattr(os, "utime", failing_utime)

    subprocess_executed = False
    orig_bounded_process = d.bounded_process

    def spy_process(cmd, *args, **kwargs):
        nonlocal subprocess_executed
        subprocess_executed = True
        return orig_bounded_process(cmd, *args, **kwargs)

    monkeypatch.setattr(d, "bounded_process", spy_process)

    with pytest.raises(d.DispositionsError, match="Failed to preserve file timestamp in snapshot"):
        d.run_real_sealcheck(task, binary, scan_config=initial["scan_config"])

    assert utime_failed
    assert not subprocess_executed
    assert (task / "task.json").read_bytes() == task_json_before
    assert (task / "agent/problem_statement.md").read_bytes() == statement_before
    assert (task / "manifest.json").read_bytes() == manifest_before
