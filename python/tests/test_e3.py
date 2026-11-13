"""Tests for hermetic_slice.e3 corpus generation and accuracy harness."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
import zipfile

import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.e3 import (
    SYNTHETIC_MODULE_LINES,
    apply_patch_in_temp_dir,
    build_corpus,
    compute_dir_files_sha256,
    generate_synthetic_tasks,
    parse_patch_hunks,
    parse_patch_touched_files,
    run_e3,
    wilson_interval,
)
from hermetic_slice.gitutil import run_git


def _create_fake_task(tasks_dir: Path, base_trees_dir: Path, task_id: str = "fake_task_1") -> tuple[Path, Path]:
    """Create a tiny fake task with a 3-file repo and a real-format gold patch."""
    td = tasks_dir / task_id
    bd = base_trees_dir / task_id
    staging = td / "staging"
    agent = td / "agent"

    td.mkdir(parents=True, exist_ok=True)
    bd.mkdir(parents=True, exist_ok=True)
    staging.mkdir(parents=True, exist_ok=True)
    agent.mkdir(parents=True, exist_ok=True)

    # 3-file repo in base tree
    app_py_content = (
        "def get_version():\n"
        '    return "1.0.0"\n'
        "\n"
        "def calculate_discount(price: float) -> float:\n"
        "    # default discount rate\n"
        "    rate = 0.10\n"
        "    return price * rate\n"
        "\n"
        "def format_output(val: float) -> str:\n"
        '    return f"${val:.2f}"\n'
    )
    config_py_content = "DEBUG = False\nTIMEOUT = 30\nSERVICE_NAME = 'sample_service'\n"
    utils_py_content = (
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n"
        "\n"
        "def subtract(a: int, b: int) -> int:\n"
        "    return a - b\n"
    )

    (bd / "app.py").write_text(app_py_content, encoding="utf-8", newline="")
    (bd / "config.py").write_text(config_py_content, encoding="utf-8", newline="")
    (bd / "utils.py").write_text(utils_py_content, encoding="utf-8", newline="")

    # Real-format gold patch modifying app.py
    gold_patch = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -4,4 +4,4 @@\n"
        " def calculate_discount(price: float) -> float:\n"
        "-    # default discount rate\n"
        "-    rate = 0.10\n"
        "+    # improved discount rate\n"
        "+    rate = 0.15\n"
        "     return price * rate\n"
    )
    (staging / "gold.patch").write_text(gold_patch, encoding="utf-8", newline="")

    test_patch = (
        "diff --git a/test_app.py b/test_app.py\n"
        "--- a/test_app.py\n"
        "+++ b/test_app.py\n"
        "@@ -1,2 +1,4 @@\n"
        "+def test_discount():\n"
        "+    assert calculate_discount(100.0) == 15.0\n"
    )
    (staging / "test.patch").write_text(test_patch, encoding="utf-8", newline="")
    (staging / "hints.txt").write_text("Check discount rate calculation.\n", encoding="utf-8", newline="")
    (agent / "problem_statement.md").write_text("Discount calculation should be 15%.\n", encoding="utf-8", newline="")

    task_json = {
        "instance_id": task_id,
        "base_commit": "abcdef123456",
        "repo": "example/fake",
        "cutoffs": {
            "t_world": "2026-01-01T00:00:00Z",
            "t_clock": "2026-01-01T00:00:00Z",
            "discarded": [],
        },
    }
    (td / "task.json").write_text(json.dumps(task_json, indent=2) + "\n", encoding="utf-8")

    return td, bd


def test_wilson_interval_hand_computed() -> None:
    """Check Wilson interval against hand-computed values and boundary conditions."""
    # k=95, n=100
    low, high = wilson_interval(95, 100)
    assert abs(low - 0.8882) < 1e-3
    assert abs(high - 0.9785) < 1e-3

    # k=1, n=3
    low, high = wilson_interval(1, 3)
    assert abs(low - 0.0615) < 1e-3
    assert abs(high - 0.7923) < 1e-3

    # k=10, n=10
    low, high = wilson_interval(10, 10)
    assert abs(low - 0.7225) < 1e-3
    assert abs(high - 1.0) < 1e-4

    # k=0, n=10
    low, high = wilson_interval(0, 10)
    assert abs(low - 0.0) < 1e-4
    assert abs(high - 0.2775) < 1e-3

    # n=0
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_synthetic_tasks_properties(tmp_path: Path) -> None:
    """Check synthetic deletion-only and one-character tasks produce exact patch deltas."""
    synth_dir = tmp_path / "synthetic"
    task_ids = generate_synthetic_tasks(synth_dir)

    assert len(task_ids) == 6
    del_tasks = [t for t in task_ids if "del" in t]
    char_tasks = [t for t in task_ids if "char" in t]

    assert len(del_tasks) == 3
    assert len(char_tasks) == 3

    # Check realistic generated Python modules of about 300 lines
    assert 250 <= len(SYNTHETIC_MODULE_LINES) <= 350

    # Check deletion-only tasks
    for dtid in del_tasks:
        td = synth_dir / dtid
        gold_patch = (td / "staging" / "gold.patch").read_text(encoding="utf-8")
        removed_lines = [
            line for line in gold_patch.splitlines() if line.startswith("-") and not line.startswith("---")
        ]
        added_lines = [line for line in gold_patch.splitlines() if line.startswith("+") and not line.startswith("+++")]
        assert len(removed_lines) == 1, f"Task {dtid} must have exactly one removed line"
        assert len(added_lines) == 0, f"Task {dtid} must have 0 added lines"

    # Check one-character tasks
    for ctid in char_tasks:
        td = synth_dir / ctid
        gold_patch = (td / "staging" / "gold.patch").read_text(encoding="utf-8")
        removed_lines = [
            line for line in gold_patch.splitlines() if line.startswith("-") and not line.startswith("---")
        ]
        added_lines = [line for line in gold_patch.splitlines() if line.startswith("+") and not line.startswith("+++")]
        assert len(removed_lines) == 1, f"Task {ctid} must have exactly one removed line"
        assert len(added_lines) == 1, f"Task {ctid} must have exactly one added line"

        old_l = removed_lines[0][1:]
        new_l = added_lines[0][1:]
        assert len(old_l) == len(new_l), "One character fix must preserve line length"
        diff_count = sum(1 for c1, c2 in zip(old_l, new_l) if c1 != c2)
        assert diff_count == 1, f"Task {ctid} must differ by exactly 1 character"


def test_corpus_build_variants_and_determinism(tmp_path: Path) -> None:
    """Build corpus from tiny fake task and check variants, seed determinism, p01, p04."""
    tasks_dir = tmp_path / "tasks"
    base_trees_dir = tmp_path / "base_trees"
    out_dir_1 = tmp_path / "corpus_seed42_a"
    out_dir_2 = tmp_path / "corpus_seed42_b"
    out_dir_3 = tmp_path / "corpus_seed99"

    task_id = "fake_task_1"
    td, bd = _create_fake_task(tasks_dir, base_trees_dir, task_id)

    # 1. Build with seed 42 (run A)
    build_corpus(tasks_dir, base_trees_dir, out_dir_1, seed=42)

    # Check every variant exists with the right label
    expected_variants = {
        "p01_postfix_file": ("gate", "positive"),
        "p02_reformatted": ("gate", "positive"),
        "p03_patch_file": ("gate", "positive"),
        "p04_regenerated_diff": ("gate", "positive"),
        "p05_hunk_in_prose": ("gate", "positive"),
        "p06_zip": ("gate", "positive"),
        "p07_tar_gz": ("gate", "positive"),
        "p08_nested": ("gate", "positive"),
        "p09_sqlite": ("gate", "positive"),
        "p10_hidden_tests": ("gate", "positive"),
        "p11_pyc": ("gate", "positive"),
        "n01_prefix_files": ("clean", "negative"),
        "n02_base_sample": ("clean", "negative"),
        "n03_cross_task": ("clean", "negative"),
    }

    cases_dir_1 = out_dir_1 / "cases"
    for var_name, (exp_call, exp_kind) in expected_variants.items():
        case_id = f"{task_id}__{var_name}"
        case_path = cases_dir_1 / case_id
        assert case_path.is_dir(), f"Case directory for variant {var_name} missing"
        meta = json.loads((case_path / "case.json").read_text(encoding="utf-8"))
        assert meta["expected"] == exp_call, f"Variant {var_name} expected {exp_call}, got {meta['expected']}"
        assert meta["kind"] == exp_kind, f"Variant {var_name} kind {exp_kind}, got {meta['kind']}"
        assert (case_path / "root").is_dir()

    # 2. Check identical corpus with same seed
    build_corpus(tasks_dir, base_trees_dir, out_dir_2, seed=42)
    corpus_1_text = (out_dir_1 / "corpus.json").read_text(encoding="utf-8")
    corpus_2_text = (out_dir_2 / "corpus.json").read_text(encoding="utf-8")
    assert corpus_1_text == corpus_2_text, "Corpus json must be byte-identical for identical seed"

    # 3. Check different seed gives a different n02 sample
    build_corpus(tasks_dir, base_trees_dir, out_dir_3, seed=99)
    n02_case_1 = cases_dir_1 / f"{task_id}__n02_base_sample" / "root"
    n02_case_3 = (out_dir_3 / "cases") / f"{task_id}__n02_base_sample" / "root"
    files_1 = sorted([p.name for p in n02_case_1.iterdir()])
    files_3 = sorted([p.name for p in n02_case_3.iterdir()])
    assert files_1 != files_3, f"Different seed must yield different n02 sample (got {files_1} vs {files_3})"

    # 4. Check p01 equals patch applied
    p01_root = cases_dir_1 / f"{task_id}__p01_postfix_file" / "root"
    p01_app = (p01_root / "app.py").read_text(encoding="utf-8")
    assert "rate = 0.15" in p01_app
    assert "rate = 0.10" not in p01_app

    # 5. Check p04 is a valid diff that git apply --check accepts against the base
    p04_root = cases_dir_1 / f"{task_id}__p04_regenerated_diff" / "root"
    diff_file = p04_root / "fix.diff"
    assert diff_file.exists()
    diff_text = diff_file.read_text(encoding="utf-8")
    assert "--- a/app.py" in diff_text
    assert "+++ b/app.py" in diff_text

    # Test git apply --check in a copy of base tree
    with_base_copy = tmp_path / "base_copy"
    shutil.copytree(bd, with_base_copy)
    shutil.copy2(diff_file, with_base_copy / "fix.diff")
    proc = run_git(["apply", "--check", "fix.diff"], cwd=with_base_copy)
    assert proc == b""

    # Also check sqlite content in p09
    p09_db = cases_dir_1 / f"{task_id}__p09_sqlite" / "root" / "leak.db"
    assert p09_db.exists()
    conn = sqlite3.connect(str(p09_db))
    rows = conn.execute("SELECT path, content FROM leaks").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "app.py"
    assert "rate = 0.15" in rows[0][1]


def test_patch_application_with_worktree_local_tmpdir(tmp_path: Path, monkeypatch) -> None:
    """Patch copies even when temporary storage is inside an enclosing worktree."""
    _, base = _create_fake_task(tmp_path / "tasks", tmp_path / "base")
    patch = (tmp_path / "tasks/fake_task_1/staging/gold.patch").read_text()
    original = (base / "app.py").read_bytes()
    worktree = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix=".patch_regression_", dir=worktree) as storage:
        monkeypatch.setattr(tempfile, "tempdir", storage)
        patched = apply_patch_in_temp_dir(base, patch, ["app.py"])
    assert "rate = 0.15" in patched["app.py"]
    assert "rate = 0.10" not in patched["app.py"]
    assert (base / "app.py").read_bytes() == original


def test_e3_run_against_stub_sealcheck(tmp_path: Path) -> None:
    """Run e3-run against a stub sealcheck python script and verify TP, FP, TN, FN and Wilson intervals."""
    tasks_dir = tmp_path / "tasks"
    base_trees_dir = tmp_path / "base_trees"
    corpus_dir = tmp_path / "corpus"
    out_dir = tmp_path / "run_out"

    task_id = "eval_task"
    _create_fake_task(tasks_dir, base_trees_dir, task_id)
    build_corpus(tasks_dir, base_trees_dir, corpus_dir, seed=42)

    # Write a stub sealcheck script that produces canned JSON
    stub_sealcheck = tmp_path / "stub_sealcheck.py"
    stub_content = (
        "import argparse, json, sys\n"
        "from pathlib import Path\n"
        "\n"
        "parser = argparse.ArgumentParser()\n"
        "subparsers = parser.add_subparsers(dest='subcommand')\n"
        "scan_p = subparsers.add_parser('scan')\n"
        "scan_p.add_argument('--task')\n"
        "scan_p.add_argument('--base-tree')\n"
        "scan_p.add_argument('--root', required=True)\n"
        "scan_p.add_argument('--root-visibility')\n"
        "scan_p.add_argument('--format')\n"
        "args = parser.parse_args()\n"
        "\n"
        "case_name = Path(args.root).parent.name\n"
        "\n"
        "# Deterministic behavior by case pattern:\n"
        "if 'p01_postfix_file' in case_name:\n"
        "    # Gate detection (TP for positive)\n"
        "    findings = [{'detector': 'D2', 'severity': 'gate', 'visibility': 'agent_visible', 'channel': 'file'}]\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': findings}))\n"
        "    sys.exit(2)\n"
        "elif 'p03_patch_file' in case_name:\n"
        "    # Gate detection (TP for positive)\n"
        "    findings = [{'detector': 'D0', 'severity': 'gate', 'visibility': 'agent_visible', 'channel': 'diff'}]\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': findings}))\n"
        "    sys.exit(2)\n"
        "elif 'p04_regenerated_diff' in case_name:\n"
        "    # Clean call on positive -> False Negative\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': []}))\n"
        "    sys.exit(0)\n"
        "elif 'n01_prefix_files' in case_name:\n"
        "    # Clean call on negative -> True Negative\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': []}))\n"
        "    sys.exit(0)\n"
        "elif 'n02_base_sample' in case_name:\n"
        "    # Gate finding on negative -> False Positive\n"
        "    findings = [{'detector': 'D3b', 'severity': 'gate', 'visibility': 'agent_visible', 'channel': 'pkg'}]\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': findings}))\n"
        "    sys.exit(2)\n"
        "elif 'n03_cross_task' in case_name:\n"
        "    # Crash simulation on negative -> Counts as error against precision\n"
        "    sys.stderr.write('Fatal memory error in sealcheck!\\n')\n"
        "    sys.exit(1)\n"
        "elif 'p05_hunk_in_prose' in case_name:\n"
        "    # Crash simulation on positive -> Counts as error against recall\n"
        "    sys.stderr.write('Fatal crash!\\n')\n"
        "    sys.exit(1)\n"
        "else:\n"
        "    # Clean default\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': []}))\n"
        "    sys.exit(0)\n"
    )
    stub_sealcheck.write_text(stub_content, encoding="utf-8")

    # Run e3 harness
    run_e3(corpus_dir, tasks_dir, base_trees_dir, stub_sealcheck, out_dir)

    # Verify results.jsonl and metrics.json
    results_jsonl = out_dir / "results.jsonl"
    metrics_json = out_dir / "metrics.json"
    metrics_md = out_dir / "metrics.md"

    assert results_jsonl.exists()
    assert metrics_json.exists()
    assert metrics_md.exists()

    metrics = json.loads(metrics_json.read_text(encoding="utf-8"))
    assert "overall" in metrics
    assert "per_variant" in metrics
    assert "synthetic" in metrics
    assert "per_task" in metrics

    # Per variant assertions
    pv = metrics["per_variant"]
    assert pv["p01_postfix_file"]["tp"] > 0
    assert pv["n01_prefix_files"]["tn"] > 0
    assert pv["n02_base_sample"]["fp"] > 0
    assert pv["n03_cross_task"]["errors"] > 0
    assert pv["n03_cross_task"]["errors_negative"] > 0
    assert pv["p05_hunk_in_prose"]["errors"] > 0
    assert pv["p05_hunk_in_prose"]["errors_positive"] > 0
    # The stub reports only D0 for p03: D0 is not scored per case, so p03 is a miss,
    # and the task is listed once under d0_gate_tasks.
    assert pv["p03_patch_file"]["tp"] == 0
    assert metrics["d0_gate_tasks"]

    # Hand-computed Wilson interval verification
    ov = metrics["overall"]
    calc_prec_low, calc_prec_high = wilson_interval(ov["tp"], ov["tp"] + ov["fp"])
    calc_rec_low, calc_rec_high = wilson_interval(ov["tp"], ov["tp"] + ov["fn"])

    assert abs(ov["precision_ci"][0] - round(calc_prec_low, 4)) < 1e-4
    assert abs(ov["precision_ci"][1] - round(calc_prec_high, 4)) < 1e-4
    assert abs(ov["recall_ci"][0] - round(calc_rec_low, 4)) < 1e-4
    assert abs(ov["recall_ci"][1] - round(calc_rec_high, 4)) < 1e-4


def test_blind_labels_read_only_after_scanning(tmp_path: Path) -> None:
    """Verify that blind labels are read only after every blind case has been scanned."""
    tasks_dir = tmp_path / "tasks"
    base_trees_dir = tmp_path / "base_trees"
    corpus_dir = tmp_path / "corpus"
    blind_dir = tmp_path / "blind"
    out_dir = tmp_path / "out"

    task_id = "t_blind"
    _create_fake_task(tasks_dir, base_trees_dir, task_id)
    build_corpus(tasks_dir, base_trees_dir, corpus_dir, seed=42)

    # Set up blind cases
    blind_cases_dir = blind_dir / "cases"
    b_case_1 = blind_cases_dir / f"{task_id}__blind_case_1" / "root"
    b_case_2 = blind_cases_dir / f"{task_id}__blind_case_2" / "root"
    b_case_1.mkdir(parents=True, exist_ok=True)
    b_case_2.mkdir(parents=True, exist_ok=True)
    (b_case_1 / "leak.txt").write_text("leak 1", encoding="utf-8")
    (b_case_2 / "leak.txt").write_text("leak 2", encoding="utf-8")

    labels_file = blind_dir / "labels.json"
    labels_file.write_text(
        json.dumps(
            {
                f"{task_id}__blind_case_1": "gate",
                f"{task_id}__blind_case_2": "clean",
            }
        ),
        encoding="utf-8",
    )

    # Marker file: stub sealcheck will fail if labels.json was read before scanning finishes
    log_marker = tmp_path / "scan_events.log"

    stub_script = tmp_path / "stub_blind_sealcheck.py"
    stub_content = (
        "import argparse, json, sys\n"
        "from pathlib import Path\n"
        "parser = argparse.ArgumentParser()\n"
        "subparsers = parser.add_subparsers(dest='subcommand')\n"
        "scan_p = subparsers.add_parser('scan')\n"
        "scan_p.add_argument('--task')\n"
        "scan_p.add_argument('--base-tree')\n"
        "scan_p.add_argument('--root', required=True)\n"
        "scan_p.add_argument('--root-visibility')\n"
        "scan_p.add_argument('--format')\n"
        "args = parser.parse_args()\n"
        f"log_file = Path(r'{log_marker}')\n"
        "with log_file.open('a', encoding='utf-8') as f:\n"
        "    f.write(f'SCANNED:{Path(args.root).parent.name}\\n')\n"
        "findings = [{'detector': 'D2', 'severity': 'gate', 'visibility': 'agent_visible', 'channel': 'test'}]\n"
        "print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'findings': findings}))\n"
        "sys.exit(2)\n"
    )
    stub_script.write_text(stub_content, encoding="utf-8")

    run_e3(corpus_dir, tasks_dir, base_trees_dir, stub_script, out_dir, blind_dir=blind_dir)

    metrics = json.loads((out_dir / "metrics.json").read_text(encoding="utf-8"))
    assert "blind" in metrics
    blind_m = metrics["blind"]
    assert blind_m["total"] == 2
    # In blind_m: case 1 expected gate, called gate -> TP = 1. Case 2 expected clean, called gate -> FP = 1.
    assert blind_m["tp"] == 1
    assert blind_m["fp"] == 1

    # Check that events log recorded both blind scans
    log_lines = log_marker.read_text(encoding="utf-8").splitlines()
    assert any("blind_case_1" in line for line in log_lines)
    assert any("blind_case_2" in line for line in log_lines)


def test_cli_subcommands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test hermetic_slice CLI subcommands e3-build and e3-run."""
    tasks_dir = tmp_path / "cli_tasks"
    base_trees_dir = tmp_path / "cli_basetrees"
    corpus_dir = tmp_path / "cli_corpus"
    out_dir = tmp_path / "cli_out"

    _create_fake_task(tasks_dir, base_trees_dir, "cli_task")

    # Test e3-build CLI
    exit_code_build = main(
        [
            "e3-build",
            "--tasks-dir",
            str(tasks_dir),
            "--base-trees",
            str(base_trees_dir),
            "--out",
            str(corpus_dir),
            "--seed",
            "123",
        ]
    )
    assert exit_code_build == 0
    assert (corpus_dir / "corpus.json").exists()

    # Test e3-run CLI
    stub_script = tmp_path / "simple_stub.py"
    stub_script.write_text(
        "import sys, json\nprint(json.dumps({'findings': []}))\nsys.exit(0)\n",
        encoding="utf-8",
    )

    exit_code_run = main(
        [
            "e3-run",
            "--corpus",
            str(corpus_dir),
            "--tasks-dir",
            str(tasks_dir),
            "--base-trees",
            str(base_trees_dir),
            "--sealcheck",
            str(stub_script),
            "--out",
            str(out_dir),
        ]
    )
    assert exit_code_run == 0
    assert (out_dir / "results.jsonl").exists()
    assert (out_dir / "metrics.json").exists()
    assert (out_dir / "metrics.md").exists()


def test_e3_basetrees_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test extract_basetrees and e3-basetrees CLI with mocked docker."""
    tasks_dir = tmp_path / "bt_tasks"
    out_dir = tmp_path / "bt_out"

    # Create task directories
    (tasks_dir / "task_1").mkdir(parents=True, exist_ok=True)
    (tasks_dir / "task_1" / "task.json").write_text("{}", encoding="utf-8")
    (tasks_dir / "task_2").mkdir(parents=True, exist_ok=True)
    (tasks_dir / "task_2" / "task.json").write_text("{}", encoding="utf-8")

    # Pretend task_2 output already exists
    (out_dir / "task_2").mkdir(parents=True, exist_ok=True)
    (out_dir / "task_2" / "existing.py").write_text("print('existing')", encoding="utf-8")

    commands_run: list[list[str]] = []

    def mock_run_docker(args: list[str], **kwargs: Any) -> bytes:
        commands_run.append(list(args))
        if args[0] == "create":
            return b"container_id_123\n"
        elif args[0] == "cp":
            # args: ["cp", "container_id_123:/testbed", target_path]
            target_path = Path(args[2])
            target_path.mkdir(parents=True, exist_ok=True)
            (target_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
            git_dir = target_path / ".git"
            git_dir.mkdir(parents=True, exist_ok=True)
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            return b""
        elif args[0] == "rm":
            return b""
        return b""

    monkeypatch.setattr("hermetic_slice.e3.run_docker", mock_run_docker)

    # Run e3-basetrees
    from hermetic_slice.e3 import extract_basetrees

    extract_basetrees(tasks_dir, out_dir, only=["task_1"])

    # task_1 should have been extracted
    assert (out_dir / "task_1").is_dir()
    assert (out_dir / "task_1" / "mod.py").exists()
    # .git should have been removed
    assert not (out_dir / "task_1" / ".git").exists()

    # basetree.json should exist
    meta_path = out_dir / "task_1.basetree.json"
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["task_id"] == "task_1"
    assert meta["file_count"] == 1
    assert "sha256" in meta

    # Check commands sequence: create, cp, rm
    create_cmds = [c for c in commands_run if c[0] == "create"]
    cp_cmds = [c for c in commands_run if c[0] == "cp"]
    rm_cmds = [c for c in commands_run if c[0] == "rm"]
    assert len(create_cmds) == 1
    assert "hermetic/task_1:sealed" in create_cmds[0]
    assert len(cp_cmds) == 1
    assert len(rm_cmds) == 1

    # Check CLI subcommand e3-basetrees
    commands_run.clear()
    exit_code = main(
        [
            "e3-basetrees",
            "--tasks-dir",
            str(tasks_dir),
            "--out",
            str(out_dir),
            "--only",
            "task_2",
        ]
    )
    assert exit_code == 0
    # Because task_2 already existed, no docker command should have been run!
    assert len(commands_run) == 0


def test_p05_and_p10_are_skipped_when_they_add_nothing() -> None:
    from hermetic_slice.e3 import _build_variant_p05, _build_variant_p10

    deletion_only = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,1 @@\n keep\n-gone\n"
    assert _build_variant_p05(deletion_only) is None
    assert _build_variant_p10("").strip() == ""
