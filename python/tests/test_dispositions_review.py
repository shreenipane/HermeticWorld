"""Security review regressions using offline, hand-written task fixtures."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

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
