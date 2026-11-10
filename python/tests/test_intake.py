"""Tests for SWE-bench task intake, cutoffs, and staging."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.http import HttpError, HttpGet, make_http_get
from hermetic_slice.intake import (
    IntakeError,
    IssueRef,
    fetch_issue_created,
    intake_task,
    linked_refs,
    load_verified,
    repo_dates,
)
from tests.helpers import build_intake_synthetic_repo


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "intake"


def make_fake_http_get() -> HttpGet:
    """Return an HttpGet fake that routes URLs to recorded fixture files."""
    url_map = {
        "https://datasets-server.huggingface.co/rows?dataset=princeton-nlp/SWE-bench_Verified&config=default&split=test&offset=0&length=100": FIXTURES_DIR / "hf_rows_page.json",
        "https://api.github.com/repos/pytest-dev/pytest/pulls/6202": FIXTURES_DIR / "pytest-dev__pytest__pull_6202.json",
        "https://api.github.com/repos/pytest-dev/pytest/pulls/6202/commits?per_page=100": FIXTURES_DIR / "pytest-dev__pytest__pull_6202_commits.json",
        "https://api.github.com/repos/pytest-dev/pytest/issues/6189": FIXTURES_DIR / "pytest-dev__pytest__issue_6189.json",
        "https://api.github.com/repos/django/django/pulls/11099": FIXTURES_DIR / "django__django__pull_11099.json",
        "https://api.github.com/repos/django/django/pulls/11099/commits?per_page=100": FIXTURES_DIR / "django__django__pull_11099_commits.json",
        "https://code.djangoproject.com/ticket/30257": FIXTURES_DIR / "django_trac_ticket_30257.html",
    }

    def fake_get(url: str) -> bytes:
        if url in url_map:
            return url_map[url].read_bytes()
        raise HttpError(url, 404)

    return fake_get


# ---------------------------------------------------------------------------
# Required case 1: pytest-6202 end to end
# ---------------------------------------------------------------------------


def test_pytest_6202_end_to_end(tmp_path: Path) -> None:
    fake_http_get = make_fake_http_get()
    cache_dir = tmp_path / "cache"
    out_dir = tmp_path / "out"

    rows = load_verified(fake_http_get, cache_dir)
    assert "pytest-dev__pytest-6202" in rows

    synth_repo = build_intake_synthetic_repo(tmp_path, base_date="2019-11-15T00:00:00Z")

    modified_rows = dict(rows)
    row_copy = dict(rows["pytest-dev__pytest-6202"])
    row_copy["base_commit"] = synth_repo.base_sha
    modified_rows["pytest-dev__pytest-6202"] = row_copy

    task_dir = intake_task(
        "pytest-dev__pytest-6202",
        modified_rows,
        fake_http_get,
        cache_dir,
        out_dir,
        clone_url=str(synth_repo.path),
    )

    assert task_dir == out_dir / "pytest-dev__pytest-6202"
    assert task_dir.is_dir()

    # Exact layout check
    task_json_file = task_dir / "task.json"
    agent_dir = task_dir / "agent"
    staging_dir = task_dir / "staging"
    assert task_json_file.exists()
    assert agent_dir.exists()
    assert staging_dir.exists()

    agent_files = list(agent_dir.iterdir())
    assert agent_files == [agent_dir / "problem_statement.md"], "agent/ must contain only problem_statement.md"

    # Problem statement matches row
    assert (agent_dir / "problem_statement.md").read_text(encoding="utf-8", newline="") == row_copy["problem_statement"]

    # Patches are byte-equal
    assert (staging_dir / "gold.patch").read_bytes() == row_copy["patch"].encode("utf-8")
    assert (staging_dir / "test.patch").read_bytes() == row_copy["test_patch"].encode("utf-8")
    assert (staging_dir / "hints.txt").read_bytes() == row_copy["hints_text"].encode("utf-8")

    # task.json validation
    task_json_raw = task_json_file.read_text(encoding="utf-8")
    task_data = json.loads(task_json_raw)

    # Distinctive line from gold patch must NOT appear in task.json
    assert 'return s.replace(".[", "[")' not in task_json_raw
    assert "patch" not in task_data
    assert "test_patch" not in task_data
    assert "hints_text" not in task_data

    # Dates and cutoffs
    assert task_data["dates"]["issue_created"] == "2019-11-14T13:11:34Z"
    assert task_data["cutoffs"]["t_world"] == "2019-11-14T13:11:34Z"
    assert task_data["cutoffs"]["t_clock"] == "2019-11-15T00:00:00Z"

    # t_world earlier than PR date (2019-11-16) and fix commits
    assert task_data["cutoffs"]["t_world"] < task_data["dates"]["pr_opened"]
    for fc in task_data["dates"]["fix_commits"]:
        assert task_data["cutoffs"]["t_world"] < fc["author_date"]
        assert task_data["cutoffs"]["t_world"] < fc["committer_date"]

    # Image
    assert task_data["image"] == "swebench/sweb.eval.x86_64.pytest-dev_1776_pytest-6202:latest"

    # Warnings
    assert any("problem_statement taken as scraped" in w for w in task_data["warnings"])


# ---------------------------------------------------------------------------
# Required case 2: django-11099
# ---------------------------------------------------------------------------


def test_django_11099_trac_intake(tmp_path: Path) -> None:
    fake_http_get = make_fake_http_get()
    cache_dir = tmp_path / "cache"
    out_dir = tmp_path / "out"

    rows = load_verified(fake_http_get, cache_dir)
    assert "django__django-11099" in rows

    synth_repo = build_intake_synthetic_repo(tmp_path, base_date="2019-03-22T00:00:00Z")

    modified_rows = dict(rows)
    row_copy = dict(rows["django__django-11099"])
    row_copy["base_commit"] = synth_repo.base_sha
    modified_rows["django__django-11099"] = row_copy

    task_dir = intake_task(
        "django__django-11099",
        modified_rows,
        fake_http_get,
        cache_dir,
        out_dir,
        clone_url=str(synth_repo.path),
    )

    task_data = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
    assert task_data["dates"]["issue_created"] == "2019-03-15T22:50:34Z"
    assert task_data["cutoffs"]["t_world"] == "2019-03-15T22:50:34Z"
    assert task_data["cutoffs"]["t_clock"] == "2019-03-22T00:00:00Z"
    assert task_data["sources"]["issue_refs"] == [
        {"created_at": "2019-03-15T22:50:34Z", "kind": "trac", "number": 30257}
    ]


# ---------------------------------------------------------------------------
# Required case 3: linked_refs
# ---------------------------------------------------------------------------


def test_linked_refs() -> None:
    repo = "pytest-dev/pytest"

    # Keyword variants, colon, case
    text1 = "Closes #1, Closed #2, FIX #3, Fixes: #12, fixed #4, resolve #5, Resolves: #6, resolved #7"
    refs1 = linked_refs(repo, text1)
    assert refs1 == [
        IssueRef("github", 1),
        IssueRef("github", 2),
        IssueRef("github", 3),
        IssueRef("github", 12),
        IssueRef("github", 4),
        IssueRef("github", 5),
        IssueRef("github", 6),
        IssueRef("github", 7),
    ]

    # Full GitHub issue URL
    text_url = "Fixes https://github.com/pytest-dev/pytest/issues/9999 and closes https://github.com/other/other/issues/8888"
    refs_url = linked_refs(repo, text_url)
    assert refs_url == [IssueRef("github", 9999)]

    # Non-closing mentions
    text_non_closing = "see #5, related to #10, refs #15, #20"
    assert linked_refs(repo, text_non_closing) == []

    # Duplicates in first-seen order
    text_dupes = "Fixes #12 and closed #5 and resolves #12"
    refs_dupes = linked_refs(repo, text_dupes)
    assert refs_dupes == [IssueRef("github", 12), IssueRef("github", 5)]

    # Trac URL in Django repo vs non-Django repo
    trac_text = "Check out https://code.djangoproject.com/ticket/30257 for context"
    assert linked_refs("django/django", trac_text) == [IssueRef("trac", 30257)]
    assert linked_refs("pytest-dev/pytest", trac_text) == []


# ---------------------------------------------------------------------------
# Required case 4: load_verified
# ---------------------------------------------------------------------------


def test_load_verified(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"

    # Base valid page
    valid_page = {
        "num_rows_total": 2,
        "num_rows_per_page": 100,
        "partial": False,
        "rows": [
            {
                "row_idx": 1,
                "row": {
                    "instance_id": "repo__inst-1",
                    "repo": "owner/repo",
                    "FAIL_TO_PASS": '["test1"]',
                    "PASS_TO_PASS": '["test2"]',
                },
                "truncated_cells": [],
            },
            {
                "row_idx": 2,
                "row": {
                    "instance_id": "repo__inst-2",
                    "repo": "owner/repo",
                    "FAIL_TO_PASS": '["test3"]',
                    "PASS_TO_PASS": '["test4"]',
                },
                "truncated_cells": [],
            },
        ],
    }

    # 1. Normal load
    mock_get = MagicMock(return_value=json.dumps(valid_page).encode("utf-8"))
    res = load_verified(mock_get, cache_dir)
    assert len(res) == 2
    assert res["repo__inst-1"]["FAIL_TO_PASS"] == ["test1"]
    assert mock_get.call_count == 1

    # 2. Second call uses cache -> ZERO http_get calls
    res2 = load_verified(mock_get, cache_dir)
    assert len(res2) == 2
    assert mock_get.call_count == 1  # still 1, no new call

    # 3. Deduplication of identical duplicate
    cache_dir_dedupe = tmp_path / "cache_dedupe"
    page_with_dup = dict(valid_page)
    page_with_dup["rows"] = [valid_page["rows"][0], valid_page["rows"][0]]
    page_with_dup["num_rows_total"] = 1
    mock_get_dup = MagicMock(return_value=json.dumps(page_with_dup).encode("utf-8"))
    res_dup = load_verified(mock_get_dup, cache_dir_dedupe)
    assert len(res_dup) == 1

    # 4. Rejection: partial: true
    partial_page = dict(valid_page, partial=True)
    with pytest.raises(IntakeError, match="partial"):
        load_verified(lambda url: json.dumps(partial_page).encode("utf-8"), tmp_path / "c_part")

    # 5. Rejection: truncated_cells
    trunc_page = {
        "num_rows_total": 1,
        "partial": False,
        "rows": [
            {
                "row_idx": 1,
                "row": {"instance_id": "inst-1"},
                "truncated_cells": ["patch"],
            }
        ],
    }
    with pytest.raises(IntakeError, match="truncated_cells"):
        load_verified(lambda url: json.dumps(trunc_page).encode("utf-8"), tmp_path / "c_trunc")

    # 6. Rejection: conflicting duplicate
    conflicting_page = {
        "num_rows_total": 2,
        "partial": False,
        "rows": [
            {"row_idx": 1, "row": {"instance_id": "inst-1", "val": "A"}, "truncated_cells": []},
            {"row_idx": 2, "row": {"instance_id": "inst-1", "val": "B"}, "truncated_cells": []},
        ],
    }
    with pytest.raises(IntakeError, match="conflicting content"):
        load_verified(lambda url: json.dumps(conflicting_page).encode("utf-8"), tmp_path / "c_conflict")

    # 7. Rejection: count mismatch
    mismatch_page = dict(valid_page, num_rows_total=50)
    with pytest.raises(IntakeError, match="Unique row count"):
        load_verified(lambda url: json.dumps(mismatch_page).encode("utf-8"), tmp_path / "c_mismatch")


# ---------------------------------------------------------------------------
# Required case 6: A GitHub issue ref that is actually a PR
# ---------------------------------------------------------------------------


def test_github_issue_is_pr_ignored_with_warning() -> None:
    pr_issue_json = {
        "number": 500,
        "created_at": "2020-01-01T00:00:00Z",
        "pull_request": {"url": "https://api.github.com/repos/owner/repo/pulls/500"},
    }

    def fake_get(url: str) -> bytes:
        return json.dumps(pr_issue_json).encode("utf-8")

    warnings_list: list[str] = []
    with pytest.warns(UserWarning, match="actually a pull request"):
        dt = fetch_issue_created(
            IssueRef("github", 500),
            "owner/repo",
            fake_get,
            warnings_list=warnings_list,
        )

    assert dt is None
    assert len(warnings_list) == 1
    assert "actually a pull request" in warnings_list[0]


# ---------------------------------------------------------------------------
# Required case 7: N1 cleanup note test
# ---------------------------------------------------------------------------


def test_cleanup_incomplete_note(tmp_path: Path) -> None:
    from hermetic_slice.repo_sealer import VerificationError, seal_repo

    synth = build_intake_synthetic_repo(tmp_path)
    dest = tmp_path / "stubborn_dest"

    # Inject verification failure and patch _rmtree to fail to delete dest
    with patch("hermetic_slice.repo_sealer.verify_sealed_repo", return_value=["Injected failure"]):
        with patch("hermetic_slice.repo_sealer._rmtree", side_effect=lambda p: None):
            with pytest.raises(VerificationError) as exc_info:
                seal_repo(
                    src=synth.path,
                    base_commit=synth.base_sha,
                    dest=dest,
                    t_clock=synth.base_commit_time,
                )
            assert hasattr(exc_info.value, "__notes__")
            assert any("cleanup incomplete" in note for note in exc_info.value.__notes__)


# ---------------------------------------------------------------------------
# CLI end-to-end
# ---------------------------------------------------------------------------


def test_cli_intake_end_to_end(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    out_dir = tmp_path / "out"
    tasks_file = tmp_path / "tasks.txt"

    # Prepare cached swebench_verified.jsonl and synthetic repo
    synth = build_intake_synthetic_repo(tmp_path, base_date="2019-11-15T00:00:00Z")
    fake_http_get = make_fake_http_get()
    rows = load_verified(fake_http_get, cache_dir)

    row_copy = dict(rows["pytest-dev__pytest-6202"])
    row_copy["base_commit"] = synth.base_sha
    rows["pytest-dev__pytest-6202"] = row_copy

    # Overwrite cache with modified base commit
    cache_file = cache_dir / "swebench_verified.jsonl"
    with cache_file.open("w", encoding="utf-8") as f:
        for r in rows.values():
            f.write(json.dumps(r) + "\n")

    tasks_file.write_text(
        "# Comment line to skip\n\npytest-dev__pytest-6202\n",
        encoding="utf-8",
    )

    with patch("hermetic_slice.__main__.make_http_get", return_value=fake_http_get):
        with patch("hermetic_slice.intake.repo_dates") as mock_repo_dates:
            mock_repo_dates.return_value = (synth.base_commit_time, synth.repo_first_commit_time)
            code = main([
                "intake",
                "--tasks",
                str(tasks_file),
                "--out",
                str(out_dir),
                "--cache",
                str(cache_dir),
            ])
            assert code == 0

    assert (out_dir / "pytest-dev__pytest-6202" / "task.json").exists()


def test_cli_intake_unknown_task_failure(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    out_dir = tmp_path / "out"
    tasks_file = tmp_path / "tasks.txt"

    fake_http_get = make_fake_http_get()
    load_verified(fake_http_get, cache_dir)

    tasks_file.write_text("unknown-task-123\n", encoding="utf-8")

    with patch("hermetic_slice.__main__.make_http_get", return_value=fake_http_get):
        code = main([
            "intake",
            "--tasks",
            str(tasks_file),
            "--out",
            str(out_dir),
            "--cache",
            str(cache_dir),
        ])
        assert code == 1
