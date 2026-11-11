"""Tests for hermetic_slice eval_spec: script preparation, row loading, and spec writing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hermetic_slice.eval_spec import (
    END_TEST_OUTPUT,
    START_TEST_OUTPUT,
    EvalSpecError,
    load_eval_rows,
    prepare_eval_script,
    write_eval_spec,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "grader"


def _read_row_fixture(instance_id: str) -> dict:
    path = FIXTURES_DIR / f"{instance_id}.row.json"
    return json.loads(path.read_text(encoding="utf-8"))


# =============================================================================
# prepare_eval_script Tests
# =============================================================================


@pytest.mark.parametrize(
    "instance_id",
    [
        "astropy__astropy-12907",
        "django__django-11099",
        "psf__requests-2317",
        "pytest-dev__pytest-6202",
        "sympy__sympy-20590",
    ],
)
def test_prepare_eval_script_real_fixtures(instance_id: str) -> None:
    """Verify prepare_eval_script removes install line and adds exit code recording."""
    row = _read_row_fixture(instance_id)
    eval_script = row["eval_script"]

    script_for_grader, removed_lines = prepare_eval_script(eval_script)

    # Exactly one install line removed
    assert len(removed_lines) == 1
    assert "pip" in removed_lines[0] and "install" in removed_lines[0]

    # Script for grader contains exit code marker lines around END_TEST_OUTPUT
    assert "SWEBENCH_TEST_EXIT_CODE=$?" in script_for_grader
    assert 'echo ">>>>> Test Exit Code: $SWEBENCH_TEST_EXIT_CODE"' in script_for_grader

    lines = script_for_grader.split("\n")
    end_idx = None
    for idx, line in enumerate(lines):
        if END_TEST_OUTPUT in line:
            end_idx = idx
            break

    assert end_idx is not None
    assert lines[end_idx - 1] == "SWEBENCH_TEST_EXIT_CODE=$?"
    assert lines[end_idx + 1] == 'echo ">>>>> Test Exit Code: $SWEBENCH_TEST_EXIT_CODE"'

    # Heredoc intact
    test_patch = row["test_patch"]
    assert test_patch in script_for_grader


def test_prepare_eval_script_missing_markers_raises() -> None:
    """Verify prepare_eval_script raises EvalSpecError when markers are missing."""
    with pytest.raises(EvalSpecError):
        prepare_eval_script("#!/bin/bash\necho hello\n")

    with pytest.raises(EvalSpecError):
        prepare_eval_script(f"#!/bin/bash\n: '{START_TEST_OUTPUT}'\npytest\n")

    with pytest.raises(EvalSpecError):
        prepare_eval_script(f"#!/bin/bash\n: '{END_TEST_OUTPUT}'\npytest\n")


# =============================================================================
# write_eval_spec Tests
# =============================================================================


def _setup_task_dir(tmp_path: Path, row: dict) -> Path:
    task_dir = tmp_path / row["instance_id"]
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    task_json_data = {
        "base_commit": row["base_commit"],
        "image": row["image"],
        "instance_id": row["instance_id"],
        "tests": {
            "FAIL_TO_PASS": row.get("FAIL_TO_PASS", []),
            "PASS_TO_PASS": row.get("PASS_TO_PASS", []),
        },
    }
    (task_dir / "task.json").write_text(json.dumps(task_json_data, indent=2), encoding="utf-8", newline="\n")
    (staging_dir / "gold.patch").write_text(row.get("patch", ""), encoding="utf-8", newline="")
    (staging_dir / "test.patch").write_text(row.get("test_patch", ""), encoding="utf-8", newline="")
    return task_dir


def test_write_eval_spec_keeps_crlf_in_gold_patch(tmp_path: Path) -> None:
    """A gold patch touching a CRLF file must still match the row byte for byte."""
    row = _read_row_fixture("pytest-dev__pytest-6202")
    row = {**row, "patch": row["patch"].replace("\n", "\r\n", 3)}
    task_dir = _setup_task_dir(tmp_path, row)

    spec = write_eval_spec(task_dir, row)
    assert spec["instance_id"] == row["instance_id"]


def test_write_eval_spec_success(tmp_path: Path) -> None:
    """Verify write_eval_spec cross-checks and outputs grader-only spec and eval.sh."""
    row = _read_row_fixture("pytest-dev__pytest-6202")
    task_dir = _setup_task_dir(tmp_path, row)

    spec = write_eval_spec(task_dir, row)

    assert spec["schema"] == "hermetic-slice-eval-spec/v1"
    assert spec["instance_id"] == row["instance_id"]
    assert spec["log_parser"] == row["log_parser"]
    assert spec["eval_type"] == row["eval_type"]

    eval_sh_path = task_dir / "staging" / "eval.sh"
    assert eval_sh_path.exists()
    eval_sh_bytes = eval_sh_path.read_bytes()
    expected_sha = hashlib.sha256(eval_sh_bytes).hexdigest()
    assert spec["eval_sh_sha256"] == expected_sha

    eval_spec_path = task_dir / "staging" / "eval_spec.json"
    assert eval_spec_path.exists()
    saved_spec = json.loads(eval_spec_path.read_text(encoding="utf-8"))
    assert saved_spec == spec


def test_write_eval_spec_mismatches(tmp_path: Path) -> None:
    """Verify write_eval_spec raises EvalSpecError on each field mismatch."""
    row = _read_row_fixture("pytest-dev__pytest-6202")

    # 1. base_commit mismatch
    task_dir1 = _setup_task_dir(tmp_path / "t1", row)
    bad_row1 = dict(row)
    bad_row1["base_commit"] = "badcommit12345"
    with pytest.raises(EvalSpecError, match="base_commit"):
        write_eval_spec(task_dir1, bad_row1)

    # 2. image mismatch
    task_dir2 = _setup_task_dir(tmp_path / "t2", row)
    bad_row2 = dict(row)
    bad_row2["image"] = "wrong/image:latest"
    with pytest.raises(EvalSpecError, match="image"):
        write_eval_spec(task_dir2, bad_row2)

    # 3. FAIL_TO_PASS mismatch
    task_dir3 = _setup_task_dir(tmp_path / "t3", row)
    bad_row3 = dict(row)
    bad_row3["FAIL_TO_PASS"] = ["unexpected_test"]
    with pytest.raises(EvalSpecError, match="FAIL_TO_PASS"):
        write_eval_spec(task_dir3, bad_row3)

    # 4. PASS_TO_PASS mismatch
    task_dir4 = _setup_task_dir(tmp_path / "t4", row)
    bad_row4 = dict(row)
    bad_row4["PASS_TO_PASS"] = ["unexpected_p2p"]
    with pytest.raises(EvalSpecError, match="PASS_TO_PASS"):
        write_eval_spec(task_dir4, bad_row4)

    # 5. patch mismatch
    task_dir5 = _setup_task_dir(tmp_path / "t5", row)
    bad_row5 = dict(row)
    bad_row5["patch"] = "diff --git a/foo b/foo\n"
    with pytest.raises(EvalSpecError, match="patch"):
        write_eval_spec(task_dir5, bad_row5)

    # 6. test_patch mismatch
    task_dir6 = _setup_task_dir(tmp_path / "t6", row)
    bad_row6 = dict(row)
    bad_row6["test_patch"] = "diff --git a/test b/test\n"
    with pytest.raises(EvalSpecError, match="test_patch"):
        write_eval_spec(task_dir6, bad_row6)

    # 7. test_patch not verbatim in eval_script
    task_dir7 = _setup_task_dir(tmp_path / "t7", row)
    bad_row7 = dict(row)
    bad_row7["eval_script"] = row["eval_script"].replace(row["test_patch"], "some_other_patch\n")
    with pytest.raises(EvalSpecError, match="verbatim"):
        write_eval_spec(task_dir7, bad_row7)


# =============================================================================
# load_eval_rows Strictness Tests
# =============================================================================


def test_load_eval_rows_success(tmp_path: Path) -> None:
    """Verify load_eval_rows fetches all pages, verifies rows, and caches them."""
    base_row = _read_row_fixture("pytest-dev__pytest-6202")

    def fake_http_get(url: str) -> bytes:
        # url contains offset and length
        offset = 0
        if "offset=" in url:
            offset = int(url.split("offset=")[1].split("&")[0])

        rows = []
        for i in range(100):
            idx = offset + i
            row_copy = dict(base_row)
            row_copy["instance_id"] = f"test-inst-{idx:03d}"
            rows.append({
                "row_idx": idx,
                "row": row_copy,
                "truncated_cells": [],
            })

        page = {
            "num_rows_total": 500,
            "rows": rows,
            "partial": False,
        }
        return json.dumps(page).encode("utf-8")

    cache_dir = tmp_path / "cache"
    rows = load_eval_rows(fake_http_get, cache_dir)
    assert len(rows) == 500
    assert (cache_dir / "swebench_verified_official.jsonl").exists()

    # Second call should load from cache without calling fake_http_get
    def failing_http_get(_: str) -> bytes:
        raise RuntimeError("Should not be called")

    cached_rows = load_eval_rows(failing_http_get, cache_dir)
    assert len(cached_rows) == 500


def test_load_eval_rows_short_page(tmp_path: Path) -> None:
    """Verify load_eval_rows raises EvalSpecError on a short page."""
    base_row = _read_row_fixture("pytest-dev__pytest-6202")

    def fake_http_get(url: str) -> bytes:
        page = {
            "num_rows_total": 500,
            "rows": [{"row_idx": 0, "row": base_row, "truncated_cells": []}],  # 1 row instead of 100
            "partial": False,
        }
        return json.dumps(page).encode("utf-8")

    with pytest.raises(EvalSpecError, match="Short page"):
        load_eval_rows(fake_http_get, tmp_path / "cache_short")


def test_load_eval_rows_truncated_cells(tmp_path: Path) -> None:
    """Verify load_eval_rows raises EvalSpecError on truncated cells."""
    base_row = _read_row_fixture("pytest-dev__pytest-6202")

    def fake_http_get(url: str) -> bytes:
        rows = []
        for i in range(100):
            row_copy = dict(base_row)
            row_copy["instance_id"] = f"inst-{i}"
            rows.append({
                "row_idx": i,
                "row": row_copy,
                "truncated_cells": ["eval_script"] if i == 5 else [],
            })
        page = {
            "num_rows_total": 500,
            "rows": rows,
            "partial": False,
        }
        return json.dumps(page).encode("utf-8")

    with pytest.raises(EvalSpecError, match="truncated_cells"):
        load_eval_rows(fake_http_get, tmp_path / "cache_trunc")


def test_load_eval_rows_missing_total_and_count_mismatch(tmp_path: Path) -> None:
    """Verify load_eval_rows checks num_rows_total presence and final row count."""
    base_row = _read_row_fixture("pytest-dev__pytest-6202")

    # Missing total
    def http_missing_total(url: str) -> bytes:
        page = {"rows": [{"row": base_row}], "partial": False}
        return json.dumps(page).encode("utf-8")

    with pytest.raises(EvalSpecError, match="num_rows_total"):
        load_eval_rows(http_missing_total, tmp_path / "cache_no_total")

    # Conflicting duplicate
    def http_conflicting(url: str) -> bytes:
        r1 = dict(base_row)
        r2 = dict(base_row)
        r2["base_commit"] = "diffcommit"
        rows = [
            {"row": r1, "truncated_cells": []},
            {"row": r2, "truncated_cells": []},
        ]
        page = {"num_rows_total": 2, "rows": rows, "partial": False}
        return json.dumps(page).encode("utf-8")

    with pytest.raises(EvalSpecError, match="conflicting"):
        load_eval_rows(http_conflicting, tmp_path / "cache_conflict")
