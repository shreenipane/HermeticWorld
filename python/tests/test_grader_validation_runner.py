"""Offline tests for the production grader validation runner and pipeline."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Mapping

import pytest

from hermetic_mutants.differential import RunResult, encode_disk
from hermetic_mutants.grader_runner import (
    GraderRunnerError,
    GraderValidationRunner,
    record_base_tree_in_repo,
    record_base_tree_with_cmd,
    run_e4_oracle,
    run_validation_pipeline,
)
from hermetic_oracle.analyse import OracleError, run_oracle_with_runner
from tests.mutants_fixture import (
    SOURCE,
    TEST_FILE,
    base_log,
    exec_runner,
    nodeid,
)


def _executable_script(path: Path, code: str) -> None:
    path.write_text("#!/usr/bin/env python3\n" + code, encoding="utf-8")
    path.chmod(0o700)


def test_grader_validation_runner_success(tmp_path: Path) -> None:
    base_disk = encode_disk(
        RunResult(
            run="R0",
            variant_set=hashlib.sha256(SOURCE.encode("utf-8")).hexdigest(),
            tests={
                "tests/test_calc.py::test_add": "failed",
                "tests/test_calc.py::test_double": "passed",
            },
            exit="clean",
            tests_started=2,
            tests_finished=2,
        )
    )
    gold_disk = encode_disk(
        RunResult(
            run="R0",
            variant_set=hashlib.sha256(SOURCE.encode("utf-8")).hexdigest(),
            tests={
                "tests/test_calc.py::test_add": "passed",
                "tests/test_calc.py::test_double": "passed",
            },
            exit="clean",
            tests_started=2,
            tests_finished=2,
        )
    )
    base_disk_path = tmp_path / "base.img"
    base_disk_path.write_bytes(base_disk)
    gold_disk_path = tmp_path / "gold.img"
    gold_disk_path.write_bytes(gold_disk)

    script = tmp_path / "mock_runner.py"
    _executable_script(
        script,
        f"""
import shutil, sys
tree, test_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
src = {str(base_disk_path)!r} if tree == "base" else {str(gold_disk_path)!r}
shutil.copyfile(src, out_path)
""",
    )
    runner = GraderValidationRunner((sys.executable, str(script)), timeout_s=30.0)
    outcomes_base = runner("base", SOURCE)
    assert outcomes_base["tests/test_calc.py::test_add"] == "failed"
    assert outcomes_base["tests/test_calc.py::test_double"] == "passed"

    outcomes_gold = runner("gold", SOURCE)
    assert outcomes_gold["tests/test_calc.py::test_add"] == "passed"
    assert outcomes_gold["tests/test_calc.py::test_double"] == "passed"


def test_grader_validation_runner_rejects_invalid_tree() -> None:
    runner = GraderValidationRunner((sys.executable, "dummy.py"))
    with pytest.raises(GraderRunnerError, match="invalid tree name"):
        runner("invalid", SOURCE)


def test_grader_validation_runner_rejects_invalid_text() -> None:
    runner = GraderValidationRunner((sys.executable, "dummy.py"))
    with pytest.raises(GraderRunnerError, match="must be a string"):
        runner("base", b"not a str")  # type: ignore[arg-type]

    with pytest.raises(GraderRunnerError, match="NUL"):
        runner("base", "hello\x00world")


def test_grader_validation_runner_tampered_disk(tmp_path: Path) -> None:
    script = tmp_path / "tamper_runner.py"
    _executable_script(
        script,
        """
import sys
tree, test_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(out_path, "wb") as f:
    f.write(b"NOT_A_VALID_HGRD_DISK" + bytes(1048576 - 21))
""",
    )
    runner = GraderValidationRunner((sys.executable, str(script)), timeout_s=30.0)
    with pytest.raises(GraderRunnerError, match="validation runner error on base"):
        runner("base", SOURCE)


def test_grader_validation_runner_wrong_variant_set(tmp_path: Path) -> None:
    bad_disk = encode_disk(
        RunResult(
            run="R0",
            variant_set="0" * 64,
            tests={"test": "passed"},
            exit="clean",
            tests_started=1,
            tests_finished=1,
        )
    )
    bad_disk_path = tmp_path / "bad.img"
    bad_disk_path.write_bytes(bad_disk)

    script = tmp_path / "wrong_vs_runner.py"
    _executable_script(
        script,
        f"""
import shutil, sys
tree, test_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.copyfile({str(bad_disk_path)!r}, out_path)
""",
    )
    runner = GraderValidationRunner((sys.executable, str(script)), timeout_s=30.0)
    with pytest.raises(GraderRunnerError, match="variant_set_mismatch"):
        runner("base", SOURCE)


def test_grader_validation_runner_subprocess_failure(tmp_path: Path) -> None:
    script = tmp_path / "failing_runner.py"
    _executable_script(script, "import sys; sys.exit(1)\n")
    runner = GraderValidationRunner((sys.executable, str(script)), timeout_s=30.0)
    with pytest.raises(GraderRunnerError, match="validation runner error"):
        runner("base", SOURCE)


def test_grader_validation_runner_refuses_symlink_out_disk(tmp_path: Path) -> None:
    target = tmp_path / "actual_target.img"
    target.write_bytes(bytes(1048576))
    script = tmp_path / "symlink_runner.py"
    _executable_script(
        script,
        f"""
import os, sys
tree, test_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
os.symlink({str(target)!r}, out_path)
""",
    )
    runner = GraderValidationRunner((sys.executable, str(script)), timeout_s=30.0)
    with pytest.raises(GraderRunnerError, match="validation runner error on base|target is not a regular file|symbolic link"):
        runner("base", SOURCE)


def test_record_base_tree_in_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\ndef double(x):\n    return x * 2\n")
    test_rel = "tests/test_calc.py"

    log_bytes = record_base_tree_in_repo(str(repo), test_rel, SOURCE.encode("utf-8"))
    assert log_bytes
    log_data = json.loads(log_bytes.decode("utf-8"))
    assert "tests" in log_data
    assert nodeid("test_add") in log_data["tests"]
    assert log_data["tests"][nodeid("test_add")]["outcome"] == "failed"
    assert nodeid("test_double") in log_data["tests"]
    assert log_data["tests"][nodeid("test_double")]["outcome"] == "passed"


def test_record_base_tree_in_repo_rejects_escaping_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(GraderRunnerError, match="escapes repository root|safe relative path"):
        record_base_tree_in_repo(str(repo), "../escape.py", b"# test")


def test_record_base_tree_in_repo_rejects_invalid_dir() -> None:
    with pytest.raises(GraderRunnerError, match="existing directory"):
        record_base_tree_in_repo("/nonexistent/dir", "test.py", b"# test")


def test_record_base_tree_with_cmd(tmp_path: Path) -> None:
    script = tmp_path / "recorder_cmd.py"
    _executable_script(
        script,
        """
import json, sys
test_path, log_path = sys.argv[1], sys.argv[2]
data = {
    "tests": {
        "tests/test_calc.py::test_add": {
            "file": "tests/test_calc.py",
            "outcome": "failed",
            "raising_line": 5,
            "reached": [{"line": 5, "index": 0, "site_id": "test_add#0", "passed": False}],
        }
    },
    "internal_errors": [],
}
with open(log_path, "w", encoding="utf-8") as f:
    json.dump(data, f)
""",
    )
    raw = record_base_tree_with_cmd((sys.executable, str(script)), TEST_FILE, SOURCE.encode("utf-8"))
    assert b"test_add" in raw


def test_run_oracle_with_runner_valid() -> None:
    report = run_oracle_with_runner(
        exec_runner,
        SOURCE,
        f2p=[nodeid("test_add"), nodeid("test_add_neg")],
        p2p=[nodeid("test_double")],
    )
    assert report["result"] == "valid"
    assert report["flaky"] == []
    assert report["violations"] == []


def test_run_oracle_with_runner_detects_flakiness() -> None:
    call_count = {"base": 0, "gold": 0}

    def flaky_runner(tree: str, text: str) -> Mapping[str, str]:
        call_count[tree] += 1
        res = exec_runner(tree, text)
        if tree == "gold" and call_count["gold"] == 2:
            # Flaky outcome on second gold run
            return {**res, nodeid("test_double"): "failed"}
        return res

    report = run_oracle_with_runner(
        flaky_runner,
        SOURCE,
        f2p=[nodeid("test_add")],
        p2p=[nodeid("test_double")],
    )
    assert nodeid("test_double") in report["flaky"]
    assert report["counts"]["flaky_total"] == 1


def test_run_oracle_with_runner_unusable() -> None:
    # If the only F2P test is flaky or missing, bad_f2p / total_f2p = 1000 permille > 200 permille -> unusable
    call_count = {"base": 0}

    def unstable_f2p_runner(tree: str, text: str) -> Mapping[str, str]:
        call_count["base"] += 1
        res = exec_runner(tree, text)
        if tree == "base" and call_count["base"] == 1:
            return {**res, nodeid("test_add"): "passed"}
        return res

    report = run_oracle_with_runner(
        unstable_f2p_runner,
        SOURCE,
        f2p=[nodeid("test_add")],
        p2p=[nodeid("test_double")],
    )
    assert report["result"] == "unusable"
    assert nodeid("test_add") in report["flaky"]


def test_run_oracle_with_runner_rejects_bad_args() -> None:
    with pytest.raises(OracleError, match="must be callable"):
        run_oracle_with_runner("not_callable", SOURCE, ["t1"], ["t2"])  # type: ignore[arg-type]

    with pytest.raises(OracleError, match="repeats must be 3"):
        run_oracle_with_runner(exec_runner, SOURCE, ["t1"], ["t2"], repeats=2)

    with pytest.raises(OracleError, match="f2p and p2p must be sequences"):
        run_oracle_with_runner(exec_runner, SOURCE, "not_seq", ["t2"])  # type: ignore[arg-type]


def test_run_e4_oracle_wrapper() -> None:
    report = run_e4_oracle(
        exec_runner,
        SOURCE,
        f2p=[nodeid("test_add"), nodeid("test_add_neg")],
        p2p=[nodeid("test_double")],
    )
    assert report["result"] == "valid"

    def broken_runner(tree: str, text: str) -> Mapping[str, str]:
        raise RuntimeError("boom")

    with pytest.raises(GraderRunnerError, match="E4 oracle failed"):
        run_e4_oracle(broken_runner, SOURCE, [nodeid("test_add")], [nodeid("test_double")])


def test_run_validation_pipeline_success() -> None:
    result = run_validation_pipeline(
        source=SOURCE.encode("utf-8"),
        test_file=TEST_FILE,
        hidden_lines=range(1, 14),
        seed="5eed",
        runner=exec_runner,
        f2p=[nodeid("test_add"), nodeid("test_add_neg")],
        p2p=[nodeid("test_double")],
        recorder_log=base_log(),
    )
    assert result.selection.r1_text is not None
    assert result.selection.r2_text is not None
    assert len(result.selection.r1_text) == len(result.selection.r2_text)
    assert result.oracle["result"] == "valid"
    assert len(result.plan.f2p) == 2
    assert len(result.plan.p2p) == 1
    assert result.base_log_sha256 == hashlib.sha256(base_log()).hexdigest()


def test_run_validation_pipeline_unusable_oracle_fails_closed() -> None:
    call_count = {"base": 0}

    def unstable_f2p_runner(tree: str, text: str) -> Mapping[str, str]:
        call_count["base"] += 1
        res = exec_runner(tree, text)
        if tree == "base" and call_count["base"] == 1:
            return {**res, nodeid("test_add"): "passed"}
        return res

    with pytest.raises(GraderRunnerError, match="E4 oracle judged tests unusable"):
        run_validation_pipeline(
            source=SOURCE.encode("utf-8"),
            test_file=TEST_FILE,
            hidden_lines=range(1, 14),
            seed="5eed",
            runner=unstable_f2p_runner,
            f2p=[nodeid("test_add")],
            p2p=[nodeid("test_double")],
            recorder_log=base_log(),
        )


def test_run_validation_pipeline_no_eligible_sites_fails_closed() -> None:
    with pytest.raises(GraderRunnerError, match="no eligible base-failing assertion sites found"):
        run_validation_pipeline(
            source=SOURCE.encode("utf-8"),
            test_file=TEST_FILE,
            hidden_lines=[999],  # No hidden lines match
            seed="5eed",
            runner=exec_runner,
            f2p=[nodeid("test_add"), nodeid("test_add_neg")],
            p2p=[nodeid("test_double")],
            recorder_log=base_log(),
        )


def test_run_validation_pipeline_with_base_repo_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\ndef double(x):\n    return x * 2\n")

    result = run_validation_pipeline(
        source=SOURCE.encode("utf-8"),
        test_file=TEST_FILE,
        hidden_lines=range(1, 14),
        seed="5eed",
        runner=exec_runner,
        f2p=[nodeid("test_add"), nodeid("test_add_neg")],
        p2p=[nodeid("test_double")],
        base_repo_dir=str(repo),
    )
    assert result.selection.r1_text is not None
    assert result.selection.r2_text is not None
    assert result.finder.eligible_sites


def test_run_validation_pipeline_invalid_oracle_fails_closed() -> None:
    def failing_p2p_runner(tree: str, text: str) -> Mapping[str, str]:
        res = exec_runner(tree, text)
        return {**res, nodeid("test_double"): "failed"}

    with pytest.raises(GraderRunnerError, match="E4 oracle judged tests invalid"):
        run_validation_pipeline(
            source=SOURCE.encode("utf-8"),
            test_file=TEST_FILE,
            hidden_lines=range(1, 14),
            seed="5eed",
            runner=failing_p2p_runner,
            f2p=[nodeid("test_add"), nodeid("test_add_neg")],
            p2p=[nodeid("test_double")],
            recorder_log=base_log(),
        )


def test_record_base_tree_in_repo_rejects_intermediate_symlink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\ndef double(x):\n    return x * 2\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_target = outside / "test_calc.py"
    outside_target.write_text("SENTINEL_OUTSIDE_CONTENT")

    (repo / "tests").symlink_to(outside)
    with pytest.raises(GraderRunnerError):
        record_base_tree_in_repo(str(repo), "tests/test_calc.py", SOURCE.encode("utf-8"))

    assert outside_target.read_text() == "SENTINEL_OUTSIDE_CONTENT"


def test_record_base_tree_in_repo_relative_dir_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "subrepo"
    repo.mkdir()
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\ndef double(x):\n    return x * 2\n")
    monkeypatch.chdir(tmp_path)
    log_bytes = record_base_tree_in_repo("subrepo", "tests/test_calc.py", SOURCE.encode("utf-8"))
    assert log_bytes

