"""Offline tests for mutable-content revisioning and target-thread scrub list."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from hermetic_slice.cutoffs import Cutoffs, FixCommit, ensure_utc
from hermetic_slice.http import HttpError, HttpPostJson, make_http_post_json
from hermetic_slice.intake import intake_task, load_verified
from hermetic_slice.thread_scrub import (
    GITHUB_GRAPHQL_URL,
    GraphQLResponseError,
    ScrubEntry,
    ScrubResult,
    dedupe_and_sort_entries,
    get_solution_pr_scrub_entries,
    process_thread_scrub_and_revision,
    select_revision,
    split_title_and_body,
)
from tests.helpers import build_intake_synthetic_repo

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "thread_scrub"


def load_fixture_json(filename: str) -> dict:
    path = FIXTURES_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Test 1: Body edited after T_world (fix pasted in later)
# ---------------------------------------------------------------------------


def test_body_edited_after_t_world_uses_earlier_revision(tmp_path: Path) -> None:
    fixture_data = load_fixture_json("issue_edited_after_t_world.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected operation: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Parser bug\nBug: parser fails on unicode input. Fix: use utf-8 encoding."

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=100,
        target_issue_created=datetime.fromisoformat("2020-01-01T12:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Problem statement uses earlier revision (before fix was added)
    assert "Fix: use utf-8 encoding." not in result.problem_statement
    assert "Bug: parser fails on unicode input with special characters." in result.problem_statement
    assert result.problem_statement.startswith("Title: Parser bug\n")

    # Metadata
    assert result.problem_statement_revision == "revision_at_t_world"
    assert result.chosen_revision_edited_at == "2020-01-03T12:00:00Z"
    assert result.edits_ignored == 1
    assert result.hints_revisioned is True

    # No warning about problem_statement taken as scraped
    assert not any("problem_statement taken as scraped" in w for w in warnings_list)


# ---------------------------------------------------------------------------
# Test 2: T_world before issue creation
# ---------------------------------------------------------------------------


def test_t_world_before_issue_creation_uses_first_revision(tmp_path: Path) -> None:
    fixture_data = load_fixture_json("issue_created_after_t_world.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected operation: {op}")

    warnings_list: list[str] = []
    # T_world is 2020-01-15, but issue was created on 2020-02-01
    t_world = datetime.fromisoformat("2020-01-15T00:00:00+00:00")
    scraped_ps = "Title: New issue\nSecond revision with new details"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=101,
        target_issue_created=datetime.fromisoformat("2020-02-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # First revision (original body) is used
    assert "First revision original body" in result.problem_statement
    assert "Second revision with new details" not in result.problem_statement
    assert result.problem_statement_revision == "first_revision"
    assert result.chosen_revision_edited_at == "2020-02-01T10:00:00Z"
    assert result.edits_ignored == 1
    assert not any("problem_statement taken as scraped" in w for w in warnings_list)


# ---------------------------------------------------------------------------
# Test 3: Never-edited body
# ---------------------------------------------------------------------------


def test_never_edited_body_unchanged_no_warning(tmp_path: Path) -> None:
    fixture_data = load_fixture_json("issue_never_edited.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected operation: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-15T00:00:00+00:00")
    scraped_ps = "Title: Pristine issue\nNever edited issue body text."

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=102,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    assert result.problem_statement == scraped_ps
    assert result.problem_statement_revision == "as_scraped"
    assert result.chosen_revision_edited_at is None
    assert result.edits_ignored == 0
    assert not any("problem_statement taken as scraped" in w for w in warnings_list)


# ---------------------------------------------------------------------------
# Test 4: No token
# ---------------------------------------------------------------------------


def test_no_token_falls_back_to_as_scraped_with_warning(tmp_path: Path) -> None:
    mock_post = MagicMock()
    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-15T00:00:00+00:00")
    scraped_ps = "Title: Fallback issue\nScraped body text."
    scraped_hints = "Original scraped hints."

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=100,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints=scraped_hints,
        token=None,
        http_post_json=None,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # No GraphQL call made
    assert mock_post.call_count == 0

    # Content unchanged
    assert result.problem_statement == scraped_ps
    assert result.hints_text == scraped_hints
    assert result.problem_statement_revision == "as_scraped"
    assert result.chosen_revision_edited_at is None
    assert result.edits_ignored == 0
    assert result.hints_revisioned is False

    # Existing warning is present
    assert any("problem_statement taken as scraped" in w for w in warnings_list)

    # Static solution PR endpoints are still generated
    pr_urls = [e["url"] for e in result.scrub_entries]
    assert "https://github.com/test-org/test-repo/pull/50" in pr_urls
    assert "https://api.github.com/repos/test-org/test-repo/pulls/50" in pr_urls
    assert "https://github.com/test-org/test-repo/pull/50.diff" in pr_urls


# ---------------------------------------------------------------------------
# Test 5: Hints (drop late comment, earlier comment taken at earlier revision)
# ---------------------------------------------------------------------------


def test_hints_drop_late_comment_and_revision_earlier_comment(tmp_path: Path) -> None:
    fixture_data = load_fixture_json("issue_with_hints.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected operation: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Hints test\nIssue discussing bug and hints."

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=103,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="old hints",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Comment 1: earlier revision taken ("Comment 1: I reproduced the bug")
    # Fix text in comment 1 edit ("The fix is to add return True") is dropped
    assert "Comment 1: I reproduced the bug" in result.hints_text
    assert "The fix is to add return True" not in result.hints_text

    # Comment 2: created after T_world (2020-01-08) is dropped completely from hints
    assert "Comment 2" not in result.hints_text

    # But Comment 2 appears in thread scrub list!
    scrub_urls = [e["url"] for e in result.scrub_entries]
    assert "https://github.com/test-org/test-repo/issues/103#issuecomment-202" in scrub_urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/202" in scrub_urls
    late_comment_entry = next(
        e for e in result.scrub_entries
        if e["url"] == "https://github.com/test-org/test-repo/issues/103#issuecomment-202"
    )
    assert late_comment_entry["reason"] == "target issue comment created after T_world"
    assert late_comment_entry["kind"] == "comment"


# ---------------------------------------------------------------------------
# Test 6: Pagination of edits and comments (two pages)
# ---------------------------------------------------------------------------


def test_pagination_of_edits_and_comments(tmp_path: Path) -> None:
    initial_data = load_fixture_json("issue_pagination_initial.json")
    edits_p2 = load_fixture_json("issue_edits_page2.json")
    comments_p2 = load_fixture_json("issue_comments_page2.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    requested_operations: list[str] = []

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        requested_operations.append(op)
        if op == "TargetIssueData":
            return initial_data
        if op == "IssueEditsPage":
            assert payload.get("variables", {}).get("cursor") == "edits_cursor_p1"
            return edits_p2
        if op == "IssueCommentsPage":
            assert payload.get("variables", {}).get("cursor") == "comments_cursor_p1"
            return comments_p2
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected operation: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Pagination\nIssue requiring pagination."

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=104,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Both pagination queries were triggered
    assert "IssueEditsPage" in requested_operations
    assert "IssueCommentsPage" in requested_operations

    # Edit chosen is from page 2 (Page 2 Edit: pre-cutoff valid revision)
    assert "Page 2 Edit: pre-cutoff valid revision" in result.problem_statement
    assert result.problem_statement_revision == "revision_at_t_world"
    assert result.chosen_revision_edited_at == "2020-01-03T10:00:00Z"
    assert result.edits_ignored == 1

    # Comments from both page 1 and page 2 are collected into hints
    assert "Comment from page 1" in result.hints_text
    assert "Comment from page 2" in result.hints_text


# ---------------------------------------------------------------------------
# Test 7: Thread scrub list (PR, review comments, cross-references, late comment)
# ---------------------------------------------------------------------------


def test_thread_scrub_list_entries_and_determinism(tmp_path: Path) -> None:
    timeline_issue_data = load_fixture_json("issue_with_timeline.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return timeline_issue_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected operation: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-10T00:00:00+00:00")
    scraped_ps = "Title: Scrub test\nIssue with cross references and timeline events."

    result1 = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=105,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    entries = result1.scrub_entries

    # 1. The solution PR and all its endpoints appear
    pr_html = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50" and e["kind"] == "pull_request")
    assert pr_html["reason"] == "solution PR HTML URL"

    pr_api = next(e for e in entries if e["url"] == "https://api.github.com/repos/test-org/test-repo/pulls/50" and e["kind"] == "pull_request")
    assert pr_api["reason"] == "solution PR API URL"

    pr_diff = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50.diff")
    assert pr_diff["reason"] == "solution PR diff"

    pr_patch = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50.patch")
    assert pr_patch["reason"] == "solution PR patch"

    pr_files = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50/files")
    assert pr_files["reason"] == "solution PR files view"

    pr_commits = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50/commits")
    assert pr_commits["reason"] == "solution PR commits view"

    # 2. PR review comments appear with reasons
    rc_html = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50#discussion_r601")
    assert rc_html["kind"] == "review_comment"
    assert rc_html["reason"] == "solution PR review comment"

    rc_api = next(e for e in entries if e["url"] == "https://api.github.com/repos/test-org/test-repo/pulls/comments/601")
    assert rc_api["kind"] == "review_comment"
    assert rc_api["reason"] == "solution PR review comment"

    # PR reviews appear
    rev_html = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/50#pullrequestreview-501")
    assert rev_html["kind"] == "review"
    assert rev_html["reason"] == "solution PR review"

    # 3. Cross-referencing issue appears with reasons
    cross_ref = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/issues/120")
    assert cross_ref["kind"] == "cross_reference"
    assert cross_ref["reason"] == "cross-references target issue"

    cross_api = next(e for e in entries if e["url"] == "https://api.github.com/repos/test-org/test-repo/issues/120")
    assert cross_api["kind"] == "cross_reference"
    assert cross_api["reason"] == "cross-references target issue"

    # Connected event PR #55
    conn_pr = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/pull/55")
    assert conn_pr["kind"] == "cross_reference"
    assert conn_pr["reason"] == "connected to target issue"

    # 4. Late comment on target issue appears with reasons
    late_c = next(e for e in entries if e["url"] == "https://github.com/test-org/test-repo/issues/105#issuecomment-401")
    assert late_c["kind"] == "comment"
    assert late_c["reason"] == "target issue comment created after T_world"

    # 5. Output is sorted and stable across multiple runs
    result2 = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=105,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache2",
        warnings_list=[],
    )
    assert result1.scrub_entries == result2.scrub_entries

    urls = [e["url"] for e in entries]
    assert urls == sorted(urls)


# ---------------------------------------------------------------------------
# Test 8: Malformed or partial GraphQL responses (never crash, errors not cached)
# ---------------------------------------------------------------------------


def test_malformed_and_error_graphql_responses(tmp_path: Path) -> None:
    error_fixture = load_fixture_json("graphql_error_response.json")
    missing_repo_fixture = load_fixture_json("graphql_missing_repo.json")

    # Case A: GraphQL response with errors array
    warnings_list_a: list[str] = []
    result_a = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=100,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Problem statement unchanged",
        scraped_hints="Hints unchanged",
        token="test-token",
        http_post_json=lambda url, payload: error_fixture,
        cache_dir=tmp_path / "cache_a",
        warnings_list=warnings_list_a,
    )

    # Never crashed; fell back with warning
    assert result_a.problem_statement == "Problem statement unchanged"
    assert result_a.hints_text == "Hints unchanged"
    assert result_a.problem_statement_revision == "as_scraped"
    assert result_a.hints_revisioned is False
    assert any("GraphQL request for issue #100 failed" in w for w in warnings_list_a)
    assert any("problem_statement taken as scraped" in w for w in warnings_list_a)

    # Case B: GraphQL response with missing repository
    warnings_list_b: list[str] = []
    result_b = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=100,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Problem statement unchanged",
        scraped_hints="Hints unchanged",
        token="test-token",
        http_post_json=lambda url, payload: missing_repo_fixture,
        cache_dir=tmp_path / "cache_b",
        warnings_list=warnings_list_b,
    )
    assert result_b.problem_statement == "Problem statement unchanged"
    assert result_b.problem_statement_revision == "as_scraped"
    assert any("GraphQL repository not found" in w for w in warnings_list_b)

    # Case C: Network HttpError
    warnings_list_c: list[str] = []

    def failing_post(url: str, payload: dict) -> dict:
        raise HttpError(url, 500)

    result_c = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=100,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Problem statement unchanged",
        scraped_hints="Hints unchanged",
        token="test-token",
        http_post_json=failing_post,
        cache_dir=tmp_path / "cache_c",
        warnings_list=warnings_list_c,
    )
    assert result_c.problem_statement == "Problem statement unchanged"
    assert result_c.problem_statement_revision == "as_scraped"
    assert any("HTTP 500" in w for w in warnings_list_c)


# ---------------------------------------------------------------------------
# Test 9: End-to-end integration via intake_task
# ---------------------------------------------------------------------------


def test_intake_task_with_thread_scrub_and_revision(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    out_dir = tmp_path / "out"

    # Realistic SWE-bench row
    rows = {
        "pytest-dev__pytest-6202": {
            "instance_id": "pytest-dev__pytest-6202",
            "repo": "pytest-dev/pytest",
            "base_commit": "abc1234",
            "patch": "diff --git a/file.py\n--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n",
            "test_patch": "diff --git a/test_file.py\n",
            "problem_statement": "'.[' replaced with '[' in the headline shown of the test report\nScraped body with fix appended later.",
            "hints_text": "Old hints text",
            "created_at": "2019-11-14T13:11:34Z",
            "FAIL_TO_PASS": ["test_something"],
            "PASS_TO_PASS": [],
            "version": "5.2",
        }
    }

    # REST fake
    intake_fixtures = Path(__file__).parent / "fixtures" / "intake"
    url_map = {
        "https://api.github.com/repos/pytest-dev/pytest/pulls/6202": intake_fixtures / "pytest-dev__pytest__pull_6202.json",
        "https://api.github.com/repos/pytest-dev/pytest/pulls/6202/commits?per_page=100": intake_fixtures / "pytest-dev__pytest__pull_6202_commits.json",
        "https://api.github.com/repos/pytest-dev/pytest/issues/6189": intake_fixtures / "pytest-dev__pytest__issue_6189.json",
    }

    def fake_http_get(url: str) -> bytes:
        if url in url_map:
            return url_map[url].read_bytes()
        raise HttpError(url, 404)

    # GraphQL fake
    issue_fixture = load_fixture_json("pytest_issue_6189_edits.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_http_post_json(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return issue_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    synth_repo = build_intake_synthetic_repo(tmp_path, base_date="2019-11-15T00:00:00Z")
    rows["pytest-dev__pytest-6202"]["base_commit"] = synth_repo.base_sha

    task_dir = intake_task(
        "pytest-dev__pytest-6202",
        rows,
        fake_http_get,
        cache_dir,
        out_dir,
        clone_url=str(synth_repo.path),
        token="test-github-token",
        http_post_json=fake_http_post_json,
    )

    task_json = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
    assert task_json["problem_statement_revision"] == "revision_at_t_world"
    assert task_json["chosen_revision_edited_at"] == "2019-11-14T13:11:34Z"
    assert task_json["edits_ignored"] == 1
    assert task_json["hints_revisioned"] is True

    # problem_statement.md uses revision before the fix
    ps_content = (task_dir / "agent" / "problem_statement.md").read_text(encoding="utf-8")
    assert "Fix: change replace to return s" not in ps_content
    assert "Headline bug with pre-cutoff description" in ps_content
    assert ps_content.startswith("'.[' replaced with '[' in the headline shown of the test report\n")

    # staging/thread_scrub.json exists and contains solution PR and reviews
    scrub_file = task_dir / "staging" / "thread_scrub.json"
    assert scrub_file.exists()
    scrub_entries = json.loads(scrub_file.read_text(encoding="utf-8"))
    assert isinstance(scrub_entries, list)
    assert any(e["kind"] == "pull_request" for e in scrub_entries)
    assert any(e["kind"] == "review" for e in scrub_entries)
    assert any(e["kind"] == "review_comment" for e in scrub_entries)


# ===========================================================================
# Regression Tests for CodeRabbit Review Defects
# ===========================================================================


def test_regression_paginate_comment_edits_history(tmp_path: Path) -> None:
    """Finding 1: Paginate each retained comment's userContentEdits connection."""
    initial_fixture = load_fixture_json("comment_edits_pagination_initial.json")
    page2_fixture = load_fixture_json("comment_edits_page2.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    ops_called: list[str] = []

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        ops_called.append(op)
        if op == "TargetIssueData":
            return initial_fixture
        if op == "PullRequestData":
            return pr_fixture
        if op == "CommentEditsPage":
            assert payload.get("variables", {}).get("id") == "IC_kwDOtest_c999"
            assert payload.get("variables", {}).get("cursor") == "comment_edits_cursor_p1"
            return page2_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Comment pagination test\nScraped problem statement."

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=201,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="old hints",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    assert "CommentEditsPage" in ops_called
    assert "Pre-cutoff comment body text without fix" in result.hints_text
    assert "fix appended in later edit" not in result.hints_text


def test_regression_null_diff_not_substituted_with_scraped_body(tmp_path: Path) -> None:
    """Finding 2: Do not substitute scraped body when historical revision diff is null."""
    null_diff_fixture = load_fixture_json("issue_edit_null_diff.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return null_diff_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Null diff test\nCurrent scraped body with fix"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=202,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Must NOT certify as revision_at_t_world
    assert result.problem_statement_revision == "as_scraped"
    assert result.chosen_revision_edited_at is None
    assert any("historical revision diff is null" in w for w in warnings_list)
    assert any("problem_statement taken as scraped" in w for w in warnings_list)

    # Unit-level test on select_revision with null diff
    rev = select_revision(
        scraped_body="Current body",
        created_at=datetime.fromisoformat("2020-01-01T00:00:00+00:00"),
        last_edited_at=datetime.fromisoformat("2020-01-03T00:00:00+00:00"),
        user_content_edits=[{"editedAt": "2020-01-02T00:00:00Z", "diff": None}],
        t_world=t_world,
        is_target_issue=False,
    )
    assert rev.revision_type == "as_scraped"
    assert rev.warning is not None
    assert "historical revision diff is null" in rev.warning


def test_regression_null_connections_partial_graphql_response(tmp_path: Path) -> None:
    """Finding 3: Handle null edit connections without crashing."""
    null_conns_fixture = load_fixture_json("issue_null_connections.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return null_conns_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Null conns\nIssue with null GraphQL connections"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=203,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    assert result.problem_statement == scraped_ps
    assert result.problem_statement_revision == "as_scraped"


def test_regression_keep_collected_pr_entries_on_issue_failure(tmp_path: Path) -> None:
    """Finding 4: Retain collected PR review entries when target issue query fails."""
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "PullRequestData":
            return pr_fixture
        if op == "TargetIssueData":
            raise GraphQLResponseError("GraphQL error: target issue not found")
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Fallback issue\nScraped body text"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=999,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Problem statement falls back with warning
    assert result.problem_statement_revision == "as_scraped"
    assert any("GraphQL request for issue #999 failed" in w for w in warnings_list)

    # Collected PR review comments are preserved in scrub_entries
    urls = [e["url"] for e in result.scrub_entries]
    assert "https://api.github.com/repos/test-org/test-repo/pulls/comments/601" in urls
    assert "https://github.com/test-org/test-repo/pull/50#discussion_r601" in urls
    assert "https://github.com/test-org/test-repo/pull/50#pullrequestreview-501" in urls


def test_regression_edited_issue_empty_edits_not_certified_as_scraped(tmp_path: Path) -> None:
    """Finding 5: Do not certify scraped text when edited issue has empty userContentEdits."""
    empty_edits_fixture = load_fixture_json("issue_edited_empty_edits.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return empty_edits_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Empty edits\nEdited issue with empty userContentEdits"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=204,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    assert result.problem_statement_revision == "as_scraped"
    assert any("userContentEdits is missing or empty" in w for w in warnings_list)
    assert any("problem_statement taken as scraped" in w for w in warnings_list)


def test_regression_paginate_pr_thread_comments(tmp_path: Path) -> None:
    """Finding 6: Paginate comments inside each PR review thread."""
    pr_thread_p1 = load_fixture_json("pr_thread_pagination_initial.json")
    pr_thread_comments_p2 = load_fixture_json("pr_thread_comments_page2.json")
    issue_fixture = load_fixture_json("issue_never_edited.json")

    ops_called: list[str] = []

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        ops_called.append(op)
        if op == "PullRequestData":
            return pr_thread_p1
        if op == "PullRequestReviewThreadCommentsPage":
            assert payload.get("variables", {}).get("id") == "PRRT_kwDOthread1"
            assert payload.get("variables", {}).get("cursor") == "thread_comments_cursor_p1"
            return pr_thread_comments_p2
        if op == "TargetIssueData":
            return issue_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-15T00:00:00+00:00")

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=102,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement="Title: Thread\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    assert "PullRequestReviewThreadCommentsPage" in ops_called
    assert warnings_list == []
    urls = [e["url"] for e in result.scrub_entries]
    # Page 1 comment
    assert "https://github.com/test-org/test-repo/pull/50#discussion_r701" in urls
    assert "https://api.github.com/repos/test-org/test-repo/pulls/comments/701" in urls
    # Page 2 comment
    assert "https://github.com/test-org/test-repo/pull/50#discussion_r702" in urls
    assert "https://api.github.com/repos/test-org/test-repo/pulls/comments/702" in urls


def test_regression_connected_event_source_scrubbed(tmp_path: Path) -> None:
    """Finding 7: Query and process source of incoming ConnectedEvents."""
    connected_fixture = load_fixture_json("issue_connected_source.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return connected_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=205,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement="Title: Connected\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    urls = [e["url"] for e in result.scrub_entries]
    # Incoming connection source issue #350 is blocked
    assert "https://github.com/test-org/test-repo/issues/350" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/350" in urls

    # Target issue #205 itself is NOT blocked as a cross reference to itself
    assert not any(e["kind"] == "cross_reference" and "issues/205" in e["url"] for e in result.scrub_entries)


def test_regression_includes_created_edit_false_safe_fallback(tmp_path: Path) -> None:
    """Finding 8: Fall back safely when includesCreatedEdit is false."""
    inc_false_fixture = load_fixture_json("issue_includes_created_false.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return inc_false_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")
    scraped_ps = "Title: Inc False\nScraped body of issue without creation edit"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=206,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Post-cutoff edit must NOT be chosen as first_revision
    assert "Later edit text after cutoff" not in result.problem_statement
    assert result.problem_statement_revision == "as_scraped"
    assert any("includesCreatedEdit is false" in w for w in warnings_list)
    assert any("problem_statement taken as scraped" in w for w in warnings_list)


def test_regression_multi_issue_problem_statement_preserved(tmp_path: Path) -> None:
    """Finding 9: Preserve every issue in multi-issue problem statement."""
    cache_dir = tmp_path / "cache"
    out_dir = tmp_path / "out"

    multi_ps = "Issue 1 title and body\nFixes #6189 and also fixes #6190\nDetailed description of issue 2"
    rows = {
        "pytest-dev__pytest-6202": {
            "instance_id": "pytest-dev__pytest-6202",
            "repo": "pytest-dev/pytest",
            "base_commit": "abc1234",
            "patch": "diff --git a/file.py\n",
            "test_patch": "diff --git a/test.py\n",
            "problem_statement": multi_ps,
            "hints_text": "hints",
            "created_at": "2019-11-14T13:11:34Z",
            "FAIL_TO_PASS": [],
            "PASS_TO_PASS": [],
            "version": "5.2",
        }
    }

    # REST fake returning PR body that references two issues
    intake_fixtures = Path(__file__).parent / "fixtures" / "intake"
    pr_data = json.loads((intake_fixtures / "pytest-dev__pytest__pull_6202.json").read_text(encoding="utf-8"))
    pr_data["body"] = "Fixes #6189 and resolves #6190"

    url_map = {
        "https://api.github.com/repos/pytest-dev/pytest/pulls/6202": json.dumps(pr_data).encode("utf-8"),
        "https://api.github.com/repos/pytest-dev/pytest/pulls/6202/commits?per_page=100": (intake_fixtures / "pytest-dev__pytest__pull_6202_commits.json").read_bytes(),
        "https://api.github.com/repos/pytest-dev/pytest/issues/6189": (intake_fixtures / "pytest-dev__pytest__issue_6189.json").read_bytes(),
        "https://api.github.com/repos/pytest-dev/pytest/issues/6190": (intake_fixtures / "pytest-dev__pytest__issue_6189.json").read_bytes(),
    }

    def fake_http_get(url: str) -> bytes:
        if url in url_map:
            return url_map[url]
        raise HttpError(url, 404)

    synth_repo = build_intake_synthetic_repo(tmp_path, base_date="2019-11-15T00:00:00Z")
    rows["pytest-dev__pytest-6202"]["base_commit"] = synth_repo.base_sha

    task_dir = intake_task(
        "pytest-dev__pytest-6202",
        rows,
        fake_http_get,
        cache_dir,
        out_dir,
        clone_url=str(synth_repo.path),
    )

    task_json = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
    assert task_json["problem_statement_revision"] == "as_scraped"
    assert any("Multiple issue references resolved" in w for w in task_json["warnings"])

    # Problem statement is preserved in full without dropping issue 2
    ps_file_content = (task_dir / "agent" / "problem_statement.md").read_text(encoding="utf-8")
    assert ps_file_content == multi_ps


def test_regression_solution_pr_issues_api_representation_blocked() -> None:
    """Finding 10: Block solution PR's Issues API representation."""
    entries = get_solution_pr_scrub_entries("owner/repo", 123)
    issues_api_entry = next(
        (e for e in entries if e.url == "https://api.github.com/repos/owner/repo/issues/123"),
        None,
    )
    assert issues_api_entry is not None
    assert issues_api_entry.kind == "pull_request"
    assert issues_api_entry.reason == "solution PR Issues API URL"
