# Behaviour ported from SWE-bench (MIT License), swebench 5.0.2 harness.
"""Evaluation specification loading, verification, and script preparation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import TYPE_CHECKING

from .http import atomic_write_bytes

if TYPE_CHECKING:
    from .http import HttpGet


class EvalSpecError(Exception):
    """Raised when eval spec verification, loading, or preparation fails."""


START_TEST_OUTPUT = ">>>>> Start Test Output"
END_TEST_OUTPUT = ">>>>> End Test Output"
TEST_EXIT_CODE_VAR = "SWEBENCH_TEST_EXIT_CODE"
TEST_EXIT_CODE = ">>>>> Test Exit Code"


def load_eval_rows(http_get: HttpGet, cache_dir: Path) -> dict[str, dict]:
    """Load SWE-bench Verified official dataset rows with strict verification."""
    cache_file = cache_dir / "swebench_verified_official.jsonl"
    if cache_file.exists():
        rows: dict[str, dict] = {}
        with cache_file.open("r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                row = json.loads(line_str)
                rows[row["instance_id"]] = row
        return rows

    offset = 0
    length = 100
    rows_collected: dict[str, dict] = {}
    num_rows_total: int | None = None

    while True:
        url = (
            "https://datasets-server.huggingface.co/rows?"
            f"dataset=SWE-bench/SWE-bench_Verified&config=default&split=test&offset={offset}&length={length}"
        )
        page_bytes = http_get(url)
        page = json.loads(page_bytes.decode("utf-8"))

        if page.get("partial") is True:
            raise EvalSpecError(f"HuggingFace dataset returned partial page at offset {offset}")

        if offset == 0:
            page_total = page.get("num_rows_total")
            if not isinstance(page_total, int) or isinstance(page_total, bool):
                raise EvalSpecError(f"First page missing integer num_rows_total: {page_total!r}")
            num_rows_total = page_total
        else:
            page_total = page.get("num_rows_total")
            if page_total != num_rows_total:
                raise EvalSpecError(f"Inconsistent num_rows_total: {page_total} vs {num_rows_total}")

        page_rows = page.get("rows", [])
        if not page_rows and num_rows_total is not None and offset < num_rows_total:
            raise EvalSpecError(f"Empty rows at offset {offset} while expecting {num_rows_total}")
        if not page_rows:
            break

        expected_len = min(length, num_rows_total - offset) if num_rows_total is not None else length
        if len(page_rows) < expected_len:
            raise EvalSpecError(f"Short page at offset {offset}: expected {expected_len}, got {len(page_rows)}")

        for item in page_rows:
            truncated = item.get("truncated_cells")
            if truncated:
                inst = item.get("row", {}).get("instance_id", "unknown")
                raise EvalSpecError(f"Row {inst} has non-empty truncated_cells: {truncated}")

            row_data = dict(item["row"])
            if isinstance(row_data.get("FAIL_TO_PASS"), str):
                row_data["FAIL_TO_PASS"] = json.loads(row_data["FAIL_TO_PASS"])
            if isinstance(row_data.get("PASS_TO_PASS"), str):
                row_data["PASS_TO_PASS"] = json.loads(row_data["PASS_TO_PASS"])

            inst_id = row_data["instance_id"]
            if inst_id in rows_collected:
                if rows_collected[inst_id] != row_data:
                    raise EvalSpecError(f"Duplicate instance_id {inst_id} with conflicting content")
            else:
                rows_collected[inst_id] = row_data

        offset += len(page_rows)
        if num_rows_total is not None and offset >= num_rows_total:
            break

    if num_rows_total is not None and len(rows_collected) != num_rows_total:
        raise EvalSpecError(f"Unique row count ({len(rows_collected)}) != num_rows_total ({num_rows_total})")

    cache_dir.mkdir(parents=True, exist_ok=True)
    sorted_rows = sorted(rows_collected.values(), key=lambda r: r["instance_id"])
    content_bytes = "".join(json.dumps(r, sort_keys=True) + "\n" for r in sorted_rows).encode("utf-8")
    atomic_write_bytes(cache_file, content_bytes)

    return rows_collected


def write_eval_spec(task_dir: Path, row: dict) -> dict:
    """Cross-check official row against intake output and write grader-only eval spec and eval.sh."""
    task_dir = Path(task_dir)
    task_json_path = task_dir / "task.json"
    if not task_json_path.exists():
        raise EvalSpecError(f"task.json not found in {task_dir}")
    task_data = json.loads(task_json_path.read_text(encoding="utf-8"))

    # Cross-checks before writing anything
    if row.get("base_commit") != task_data.get("base_commit"):
        raise EvalSpecError(
            f"base_commit mismatch: row={row.get('base_commit')!r} vs task.json={task_data.get('base_commit')!r}"
        )
    if row.get("image") != task_data.get("image"):
        raise EvalSpecError(
            f"image mismatch: row={row.get('image')!r} vs task.json={task_data.get('image')!r}"
        )

    row_f2p = json.loads(row["FAIL_TO_PASS"]) if isinstance(row.get("FAIL_TO_PASS"), str) else row.get("FAIL_TO_PASS", [])
    row_p2p = json.loads(row["PASS_TO_PASS"]) if isinstance(row.get("PASS_TO_PASS"), str) else row.get("PASS_TO_PASS", [])
    task_tests = task_data.get("tests", {})
    task_f2p = task_tests.get("FAIL_TO_PASS", [])
    task_p2p = task_tests.get("PASS_TO_PASS", [])

    if row_f2p != task_f2p:
        raise EvalSpecError(f"FAIL_TO_PASS mismatch: row={row_f2p!r} vs task.json={task_f2p!r}")
    if row_p2p != task_p2p:
        raise EvalSpecError(f"PASS_TO_PASS mismatch: row={row_p2p!r} vs task.json={task_p2p!r}")

    gold_patch_path = task_dir / "staging" / "gold.patch"
    if not gold_patch_path.exists():
        raise EvalSpecError(f"staging/gold.patch not found in {task_dir}")
    # Bytes, not read_text: universal newlines would turn a CRLF file's \r\n into \n.
    gold_patch_text = gold_patch_path.read_bytes().decode("utf-8")
    if row.get("patch", "") != gold_patch_text:
        raise EvalSpecError("patch mismatch with staging/gold.patch")

    test_patch_path = task_dir / "staging" / "test.patch"
    if not test_patch_path.exists():
        raise EvalSpecError(f"staging/test.patch not found in {task_dir}")
    test_patch_bytes = test_patch_path.read_bytes()
    test_patch_text = test_patch_bytes.decode("utf-8")
    if row.get("test_patch", "") != test_patch_text:
        raise EvalSpecError("test_patch mismatch with staging/test.patch")

    eval_script = row.get("eval_script", "")
    if test_patch_text not in eval_script:
        raise EvalSpecError("test_patch text not found verbatim in eval_script")

    # Write staging/eval.sh with \n newlines
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    eval_sh_path = staging_dir / "eval.sh"
    eval_sh_normalized = eval_script.replace("\r\n", "\n")
    eval_sh_bytes = eval_sh_normalized.encode("utf-8")
    atomic_write_bytes(eval_sh_path, eval_sh_bytes)

    eval_sh_sha256 = hashlib.sha256(eval_sh_bytes).hexdigest()

    spec = {
        "eval_sh_sha256": eval_sh_sha256,
        "eval_type": row.get("eval_type", ""),
        "instance_id": row["instance_id"],
        "log_parser": row.get("log_parser", ""),
        "schema": "hermetic-slice-eval-spec/v1",
        "sha256": eval_sh_sha256,
    }

    spec_bytes = (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(staging_dir / "eval_spec.json", spec_bytes)

    return spec


def prepare_eval_script(script: str) -> tuple[str, list[str]]:
    """Remove offline pip install line and apply exit-code recording markers."""
    if START_TEST_OUTPUT not in script or END_TEST_OUTPUT not in script:
        raise EvalSpecError("eval_script missing required START_TEST_OUTPUT or END_TEST_OUTPUT marker")

    lines = script.replace("\r\n", "\n").split("\n")
    past_start_marker = False
    in_heredoc = False
    heredoc_delim: str | None = None
    removed_lines: list[str] = []
    output_lines: list[str] = []

    for line in lines:
        if not past_start_marker:
            if START_TEST_OUTPUT in line:
                past_start_marker = True
                output_lines.append(line)
                continue

            if in_heredoc:
                if line.strip() == heredoc_delim:
                    in_heredoc = False
                    heredoc_delim = None
                output_lines.append(line)
                continue

            m = re.search(r"<<\s*['\"]?([A-Za-z0-9_]+)['\"]?", line)
            if m:
                in_heredoc = True
                heredoc_delim = m.group(1)
                output_lines.append(line)
                continue

            stripped = line.strip()
            tokens = stripped.split()
            is_pip = False
            if tokens:
                if tokens[0] == "pip":
                    is_pip = True
                elif len(tokens) >= 3 and tokens[0].startswith("python") and tokens[1] == "-m" and tokens[2] == "pip":
                    is_pip = True

            if is_pip and "install" in tokens:
                removed_lines.append(line)
                continue

            output_lines.append(line)
        else:
            if END_TEST_OUTPUT in line:
                output_lines.append(f"{TEST_EXIT_CODE_VAR}=$?")
                output_lines.append(line)
                output_lines.append(f'echo "{TEST_EXIT_CODE}: ${TEST_EXIT_CODE_VAR}"')
            else:
                output_lines.append(line)

    return "\n".join(output_lines), removed_lines
