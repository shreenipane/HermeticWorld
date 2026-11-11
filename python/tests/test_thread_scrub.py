"""Offline tests for mutable-content revisioning and target-thread scrub list."""

from __future__ import annotations

from copy import deepcopy
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
    match_scrub_entry,
    matches_any_scrub_entry,
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

    # Unverifiable content excluded
    assert result.problem_statement == ""
    assert result.hints_text == ""
    assert result.problem_statement_revision == "excluded"
    assert result.chosen_revision_edited_at is None
    assert result.edits_ignored == 0
    assert result.hints_revisioned is False

    # Existing warning is present
    assert any("unverifiable_content_excluded" in w for w in warnings_list)

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
    assert result_a.problem_statement == ""
    assert result_a.hints_text == ""
    assert result_a.problem_statement_revision == "excluded"
    assert result_a.hints_revisioned is False
    assert any("pr_discovery_failed; repository_scope_denied" in w for w in warnings_list_a)
    assert any("unverifiable_content_excluded" in w for w in warnings_list_a)

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
    assert result_b.problem_statement == ""
    assert result_b.problem_statement_revision == "excluded"
    assert any("pr_discovery_failed; repository_scope_denied" in w for w in warnings_list_b)

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
    assert result_c.problem_statement == ""
    assert result_c.problem_statement_revision == "excluded"
    assert any("pr_discovery_failed; repository_scope_denied" in w for w in warnings_list_c)


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
    assert result.problem_statement_revision == "excluded"
    assert result.chosen_revision_edited_at is None
    assert any("invalid_revision" in w for w in warnings_list)
    assert any("unverifiable_content_excluded" in w for w in warnings_list)

    # Unit-level test on select_revision with null diff
    rev = select_revision(
        scraped_body="Current body",
        created_at=datetime.fromisoformat("2020-01-01T00:00:00+00:00"),
        last_edited_at=datetime.fromisoformat("2020-01-03T00:00:00+00:00"),
        user_content_edits=[{"editedAt": "2020-01-02T00:00:00Z", "diff": None}],
        t_world=t_world,
        is_target_issue=False,
    )
    assert rev.revision_type == "excluded"
    assert rev.warning is not None
    assert "invalid_revision" in rev.warning


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

    assert result.problem_statement == ""
    assert result.problem_statement_revision == "excluded"


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
    assert result.problem_statement_revision == "excluded"
    assert any("issue_discovery_failed; repository_scope_denied" in w for w in warnings_list)

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

    assert result.problem_statement_revision == "excluded"
    assert any("userContentEdits is missing or empty" in w for w in warnings_list)
    assert any("unverifiable_content_excluded" in w for w in warnings_list)


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
    assert result.problem_statement_revision == "excluded"
    assert any("includesCreatedEdit is false" in w for w in warnings_list)
    assert any("unverifiable_content_excluded" in w for w in warnings_list)


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
    assert task_json["problem_statement_revision"] == "excluded"
    assert any("Multiple issue references resolved" in w for w in task_json["warnings"])

    # Multi-issue statements cannot be verified and are excluded in full.
    ps_file_content = (task_dir / "agent" / "problem_statement.md").read_text(encoding="utf-8")
    assert ps_file_content == ""


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


# ---------------------------------------------------------------------------
# Offline Regression Tests for Defects 1 to 12
# ---------------------------------------------------------------------------


def test_defect1_comment_without_usable_history_dropped_and_counted(tmp_path: Path) -> None:
    """Defect 1: Comments without usable history are dropped, counted, warned without text, and hints_revisioned computed."""
    fixture_data = load_fixture_json("issue_comment_unusable_history.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-10T00:00:00+00:00")

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=301,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement="Title: Defect 1\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # 1. Comment 801 (never edited) is kept
    assert "Kept comment body: never edited" in result.hints_text

    # 2. Comments without usable history (802, 803, 804) are DROPPED
    assert "Dropped comment: empty edits" not in result.hints_text
    assert "Dropped comment: includesCreatedEdit false" not in result.hints_text
    assert "Dropped comment: null diff" not in result.hints_text

    # 3. Counted in metadata
    assert result.hints_excluded_no_history == 3
    # Every kept comment was never edited -> hints_revisioned is computed as True
    assert result.hints_revisioned is True

    # 4. Warnings name the comment ID, never its body/text
    warn_802 = next((w for w in warnings_list if "Comment 802" in w), None)
    assert warn_802 is not None
    assert "Dropped comment: empty edits" not in warn_802

    warn_803 = next((w for w in warnings_list if "Comment 803" in w), None)
    assert warn_803 is not None
    assert "Dropped comment: includesCreatedEdit false" not in warn_803

    warn_804 = next((w for w in warnings_list if "Comment 804" in w), None)
    assert warn_804 is not None
    assert "Dropped comment: null diff" not in warn_804


def test_defect2_truncated_history_raises_and_falls_back(tmp_path: Path) -> None:
    """Defect 2: Incomplete/truncated edit history raises GraphQLResponseError inside guarded path and excludes unverifiable content."""
    fixture_data = load_fixture_json("issue_truncated_history.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-10T00:00:00+00:00")
    scraped_ps = "Title: Truncated\nScraped body of issue with truncated history"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=302,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Must exclude unverifiable content, never first_revision / revision_at_t_world
    assert result.problem_statement_revision == "excluded"
    assert result.problem_statement == ""
    assert "Later revision that should never be certified" not in result.problem_statement
    assert any("issue_discovery_failed; repository_scope_denied" in w for w in warnings_list)
    assert any("unverifiable_content_excluded" in w for w in warnings_list)


def test_defect2_later_null_issue_node_response_falls_back(tmp_path: Path) -> None:
    """Defect 2 variant: Later null issue/node responses raise and exclude unverifiable content."""
    initial_issue = {
        "id": "iss-1", "body": "initial", "createdAt": "2020-01-01T00:00:00Z",
        "lastEditedAt": "2020-01-10T00:00:00Z", "includesCreatedEdit": True,
        "userContentEdits": {
            "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
            "nodes": [{"editedAt": "2020-01-10T00:00:00Z", "diff": "late revision"}],
        },
        "comments": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
        "timelineItems": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
    }
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    # Case A: Later issue response has null issue
    def post_null_issue(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return {"data": {"repository": {"issue": deepcopy(initial_issue)}}}
        if op == "PullRequestData":
            return pr_fixture
        if op == "IssueEditsPage":
            return {"data": {"repository": {"issue": None}}}
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=302,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Title: Truncated\nScraped body",
        scraped_hints="",
        token="test-token",
        http_post_json=post_null_issue,
        cache_dir=tmp_path / "cache_null_issue",
        warnings_list=warnings_list,
    )
    assert result.problem_statement_revision == "excluded"
    assert result.problem_statement == ""
    assert any("unverifiable_content_excluded" in w for w in warnings_list)

    # Case B: Later comment response has null node
    comment_node = {
        "id": "c-1", "databaseId": 501, "createdAt": "2020-01-02T00:00:00Z",
        "lastEditedAt": "2020-01-10T00:00:00Z", "includesCreatedEdit": True,
        "userContentEdits": {
            "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
            "nodes": [{"editedAt": "2020-01-10T00:00:00Z", "diff": "late comment revision"}],
        },
    }
    issue_with_comment = deepcopy(initial_issue)
    issue_with_comment["lastEditedAt"] = None
    issue_with_comment["userContentEdits"]["pageInfo"]["hasNextPage"] = False
    issue_with_comment["comments"]["nodes"] = [comment_node]

    def post_null_node(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return {"data": {"repository": {"issue": issue_with_comment}}}
        if op == "PullRequestData":
            return pr_fixture
        if op == "CommentEditsPage":
            return {"data": {"node": None}}
        raise ValueError(f"Unexpected op: {op}")

    warn_node: list[str] = []
    res_node = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=302,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Title: Comment Test\nScraped body",
        scraped_hints="Comment hint",
        token="test-token",
        http_post_json=post_null_node,
        cache_dir=tmp_path / "cache_null_node",
        warnings_list=warn_node,
    )
    assert res_node.hints_excluded_no_history == 1
    assert "late comment revision" not in res_node.hints_text
    assert res_node.hints_text == ""


def test_defect2_missing_later_page_info_falls_back(tmp_path: Path) -> None:
    """Defect 2 variant: Missing later pageInfo raises and excludes unverifiable content."""
    initial_issue = {
        "id": "iss-2", "body": "initial", "createdAt": "2020-01-01T00:00:00Z",
        "lastEditedAt": "2020-01-10T00:00:00Z", "includesCreatedEdit": True,
        "userContentEdits": {
            "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
            "nodes": [{"editedAt": "2020-01-10T00:00:00Z", "diff": "late revision"}],
        },
        "comments": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
        "timelineItems": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
    }
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def post_missing_page_info(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return {"data": {"repository": {"issue": deepcopy(initial_issue)}}}
        if op == "PullRequestData":
            return pr_fixture
        if op == "IssueEditsPage":
            return {"data": {"repository": {"issue": {"userContentEdits": {
                "nodes": [{"editedAt": "2020-01-01T00:00:00Z", "diff": "verified original"}],
            }}}}}
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=302,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Title: Truncated\nScraped body",
        scraped_hints="",
        token="test-token",
        http_post_json=post_missing_page_info,
        cache_dir=tmp_path / "cache_missing_page_info",
        warnings_list=warnings_list,
    )
    assert result.problem_statement_revision == "excluded"
    assert result.problem_statement == ""
    assert any("unverifiable_content_excluded" in w for w in warnings_list)


def test_defect2_paginated_comment_missing_id_falls_back(tmp_path: Path) -> None:
    """Defect 2 variant: A paginated comment missing its ID raises missing_pagination_id and excludes comment."""
    pr_fixture = load_fixture_json("pull_request_scrub.json")
    comment_without_id = {
        "databaseId": 502, "createdAt": "2020-01-02T00:00:00Z",
        "lastEditedAt": "2020-01-10T00:00:00Z", "includesCreatedEdit": True,
        "userContentEdits": {
            "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
            "nodes": [{"editedAt": "2020-01-10T00:00:00Z", "diff": "late comment revision"}],
        },
    }
    issue_data = {
        "id": "iss-3", "body": "initial", "createdAt": "2020-01-01T00:00:00Z",
        "lastEditedAt": None, "includesCreatedEdit": True,
        "userContentEdits": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
        "comments": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [comment_without_id]},
        "timelineItems": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
    }
    calls = []
    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        calls.append(op)
        if op == "TargetIssueData":
            return {"data": {"repository": {"issue": issue_data}}}
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=302,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-05T00:00:00+00:00"),
        scraped_problem_statement="Title: Safe\nScraped body",
        scraped_hints="Hint text",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache_missing_id",
        warnings_list=warnings_list,
    )
    assert result.hints_excluded_no_history == 1
    assert "late comment revision" not in result.hints_text
    assert result.hints_text == ""
    assert "CommentEditsPage" not in calls
    assert any("failed fetching or processing edit history" in w for w in warnings_list)


def test_defect3_missing_includes_created_edit_treated_as_not_including_creation(tmp_path: Path) -> None:
    """Defect 3: Missing includesCreatedEdit (omitted/null) is treated as not including creation edit."""
    fixture_data = load_fixture_json("issue_missing_includes_created_edit.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-10T00:00:00+00:00")
    scraped_ps = "Title: Missing IncludesCreated\nScraped body of issue with missing includesCreatedEdit"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=303,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Must not assume creation edit was included; excludes unverifiable content
    assert result.problem_statement_revision == "excluded"
    assert result.problem_statement == ""
    assert any("includesCreatedEdit is false / not true" in w for w in warnings_list)
    assert any("unverifiable_content_excluded" in w for w in warnings_list)


def test_defect4_comment_missing_or_unparseable_created_at_excluded(tmp_path: Path) -> None:
    """Defect 4: Comment with missing or unparseable createdAt is excluded from hints with warning and count."""
    fixture_data = load_fixture_json("issue_comment_missing_created_at.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    warnings_list: list[str] = []
    t_world = datetime.fromisoformat("2020-01-10T00:00:00+00:00")

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=304,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement="Title: Missing CreatedAt\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # Missing createdAt comment 805 is excluded
    assert "Comment with missing createdAt" not in result.hints_text
    # Valid comment 806 is kept
    assert "Valid comment body" in result.hints_text
    assert result.hints_excluded_no_created_at == 1
    assert any("Comment 805: missing or unparseable createdAt; excluded from hints" in w for w in warnings_list)


def test_defect5_comment_edit_pagination_errors_guarded_never_crash(tmp_path: Path) -> None:
    """Defect 5: Comment edit pagination errors (GraphQL error, HttpError, non-JSON) are guarded and do not crash."""
    fixture_data = load_fixture_json("issue_comment_edits_pagination_broken.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    # Test Case A: GraphQL error during comment edit pagination
    def fake_post_graphql_error(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        if op == "CommentEditsPage":
            return {"errors": [{"message": "Field 'userContentEdits' failed"}]}
        raise ValueError(f"Unexpected op: {op}")

    warnings_a: list[str] = []
    result_a = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=305,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Error guard\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post_graphql_error,
        cache_dir=tmp_path / "cache_a",
        warnings_list=warnings_a,
    )
    assert result_a.hints_excluded_no_history == 1
    assert "Comment with broken second page of edits" not in result_a.hints_text
    assert any("Comment 807: failed fetching or processing edit history" in w for w in warnings_a)

    # Test Case B: HttpError during comment edit pagination
    def fake_post_http_error(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        if op == "CommentEditsPage":
            raise HttpError("https://api.github.com/graphql", 502)
        raise ValueError(f"Unexpected op: {op}")

    warnings_b: list[str] = []
    result_b = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=305,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Error guard\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post_http_error,
        cache_dir=tmp_path / "cache_b",
        warnings_list=warnings_b,
    )
    assert result_b.hints_excluded_no_history == 1
    assert "Comment with broken second page of edits" not in result_b.hints_text
    assert any("Comment 807: failed fetching or processing edit history" in w for w in warnings_b)

    # Test Case C: Non-JSON bytes during comment edit pagination
    def fake_post_non_json(url: str, payload: dict) -> bytes:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        if op == "CommentEditsPage":
            return b"<html><body>502 Bad Gateway</body></html>"
        raise ValueError(f"Unexpected op: {op}")

    warnings_c: list[str] = []
    result_c = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=305,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Error guard\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post_non_json,
        cache_dir=tmp_path / "cache_c",
        warnings_list=warnings_c,
    )
    assert result_c.hints_excluded_no_history == 1
    assert "Comment with broken second page of edits" not in result_c.hints_text
    assert any("Comment 807: failed fetching or processing edit history" in w for w in warnings_c)


def test_defect6_cache_refresh_for_mutable_graphql_snapshot(tmp_path: Path) -> None:
    """Defect 6: Mutable GraphQL data uses per-run snapshots so a second run with newer fixture sees late comment."""
    cache_dir = tmp_path / "cache"
    run1_fixture = load_fixture_json("issue_snapshot_run1.json")
    run2_fixture = load_fixture_json("issue_snapshot_run2.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    t_world = datetime.fromisoformat("2020-01-05T00:00:00+00:00")

    # Run 1: Uses snapshot 1
    client_run1 = make_http_post_json(cache_dir, snapshot_id="snapshot_run_1")

    # Mock responses for run 1
    def mock_fetcher_run1(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return run1_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    result1 = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=306,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement="Title: Run 1\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=mock_fetcher_run1,
        cache_dir=cache_dir,
        warnings_list=[],
        snapshot_id="snapshot_run_1",
    )

    scrub_urls_run1 = [e["url"] for e in result1.scrub_entries]
    # In run 1, late comment 902 was not yet created
    assert "https://github.com/test-org/test-repo/issues/306#issuecomment-902" not in scrub_urls_run1

    # Run 2: A new intake run with newer fixture sees late comment in scrub list
    def mock_fetcher_run2(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return run2_fixture
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    result2 = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=306,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=t_world,
        scraped_problem_statement="Title: Run 2\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=mock_fetcher_run2,
        cache_dir=cache_dir,
        warnings_list=[],
        snapshot_id="snapshot_run_2",
    )

    scrub_urls_run2 = [e["url"] for e in result2.scrub_entries]
    # Run 2 sees the late comment in scrub list
    assert "https://github.com/test-org/test-repo/issues/306#issuecomment-902" in scrub_urls_run2
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/902" in scrub_urls_run2


def test_defect7_cross_repo_reference_derives_owner_repo_from_source_url(tmp_path: Path) -> None:
    """Defect 7: Derive owner/repo from source item's own URL, not the target repo."""
    fixture_data = load_fixture_json("issue_cross_repo_reference.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    result = process_thread_scrub_and_revision(
        repo="target-org/target-repo",
        pr_number=50,
        target_issue_number=307,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Cross Repo\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=[],
    )

    urls = [e["url"] for e in result.scrub_entries]

    # Derived from external-org/external-repo
    assert "https://api.github.com/repos/external-org/external-repo/pulls/77" in urls
    assert "https://github.com/external-org/external-repo/pull/77" in urls
    assert not any("repos/target-org/target-repo/pulls/77" in u for u in urls)

    # Derived from other-org/other-repo
    assert "https://api.github.com/repos/other-org/other-repo/issues/88" in urls
    assert "https://github.com/other-org/other-repo/issues/88" in urls
    assert not any("repos/target-org/target-repo/issues/88" in u for u in urls)


def test_defect8_referencing_prs_emitted_full_set(tmp_path: Path) -> None:
    """Defect 8: For every referencing PR, emit the same full set as solution PR."""
    fixture_data = load_fixture_json("issue_cross_repo_reference.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return fixture_data
        if op == "PullRequestData":
            return pr_fixture
        raise ValueError(f"Unexpected op: {op}")

    result = process_thread_scrub_and_revision(
        repo="target-org/target-repo",
        pr_number=50,
        target_issue_number=307,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Referencing PR full set\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=[],
    )

    urls = {e["url"] for e in result.scrub_entries}
    ref_pr = "https://github.com/external-org/external-repo/pull/77"
    ref_api = "https://api.github.com/repos/external-org/external-repo/pulls/77"
    ref_issues = "https://api.github.com/repos/external-org/external-repo/issues/77"

    assert ref_pr in urls
    assert f"{ref_pr}/" in urls
    assert ref_api in urls
    assert f"{ref_api}/" in urls
    assert ref_issues in urls
    assert f"{ref_issues}/" in urls
    assert "https://github.com/external-org/external-repo/issues/77" in urls
    assert f"{ref_pr}/files" in urls
    assert f"{ref_api}/files" in urls
    assert f"{ref_pr}/commits" in urls
    assert f"{ref_api}/commits" in urls
    assert f"{ref_pr}.diff" in urls
    assert f"{ref_pr}.patch" in urls


def test_defect9_solution_pr_entries_gaps_filled(tmp_path: Path) -> None:
    """Defect 9: Solution PR entries include issues prefix/exact URL, conversation comments, and fix/merge commits."""
    issue_fixture = load_fixture_json("issue_never_edited.json")
    pr_comments_fixture = load_fixture_json("pr_with_conversation_comments.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "TargetIssueData":
            return issue_fixture
        if op == "PullRequestData":
            return pr_comments_fixture
        raise ValueError(f"Unexpected op: {op}")

    commit_shas = ["fix_sha_1001", "merge_sha_2002"]
    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=102,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Solution PR gaps\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=[],
        commit_shas=commit_shas,
    )

    urls = {e["url"] for e in result.scrub_entries}

    # Issues API exact and prefix
    assert "https://api.github.com/repos/test-org/test-repo/issues/50" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/50/" in urls
    assert "https://github.com/test-org/test-repo/issues/50" in urls

    # Conversation comments on PR
    assert "https://github.com/test-org/test-repo/pull/50#issuecomment-901" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/901" in urls
    assert "https://github.com/test-org/test-repo/pull/50#issuecomment-902" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/902" in urls

    # Fix commit and merge commit endpoints
    for sha in commit_shas:
        assert f"https://github.com/test-org/test-repo/commit/{sha}" in urls
        assert f"https://github.com/test-org/test-repo/commit/{sha}.diff" in urls
        assert f"https://github.com/test-org/test-repo/commit/{sha}.patch" in urls
        assert f"https://api.github.com/repos/test-org/test-repo/commits/{sha}" in urls
        assert f"https://api.github.com/repos/test-org/test-repo/git/commits/{sha}" in urls


def test_defect9_solution_pr_conversation_comments_multi_page_pagination(tmp_path: Path) -> None:
    """Defect 9: Solution PR conversation comments are paginated across multiple pages and all scrubbed."""
    issue_fixture = load_fixture_json("issue_never_edited.json")
    pr_page1 = {
        "comments": {
            "pageInfo": {"hasNextPage": True, "endCursor": "cursor_pr_comments_p2"},
            "nodes": [
                {"databaseId": 901, "url": "https://github.com/test-org/test-repo/pull/50#issuecomment-901"},
            ],
        },
        "reviews": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
        "reviewThreads": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
    }
    pr_page2 = {
        "comments": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [
                {"databaseId": 902, "url": "https://github.com/test-org/test-repo/pull/50#issuecomment-902"},
            ],
        },
    }
    calls = []
    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        calls.append(op)
        if op == "TargetIssueData":
            return issue_fixture
        if op == "PullRequestData":
            return {"data": {"repository": {"pullRequest": deepcopy(pr_page1)}}}
        if op == "PullRequestCommentsPage":
            assert payload["variables"]["cursor"] == "cursor_pr_comments_p2"
            return {"data": {"repository": {"pullRequest": deepcopy(pr_page2)}}}
        raise ValueError(f"Unexpected op: {op}")

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=102,
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Title: Solution PR gaps\nBody",
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=[],
    )
    urls = [e["url"] for e in result.scrub_entries]
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/901" in urls
    assert "https://github.com/test-org/test-repo/pull/50#issuecomment-901" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/902" in urls
    assert "https://github.com/test-org/test-repo/pull/50#issuecomment-902" in urls
    assert calls.count("PullRequestCommentsPage") == 1


def test_defect10_prefixes_have_trailing_delimiter_and_match_field() -> None:
    """Defect 10: Prefixes end with trailing slash, exact entries do not, and match field is present."""
    entries = get_solution_pr_scrub_entries("test-org/test-repo", 12, commit_shas=["sha123"])
    entries_dict = dedupe_and_sort_entries(entries)

    for e in entries_dict:
        assert e["match"] in ("exact", "prefix")
        if e["match"] == "prefix":
            assert e["url"].endswith("/"), f"Prefix entry {e['url']} must end with trailing slash"
        elif e["match"] == "exact":
            if ".diff" in e["url"] or ".patch" in e["url"]:
                assert not e["url"].endswith("/")

    prefix_urls = [e["url"] for e in entries_dict if e["match"] == "prefix"]
    assert "https://github.com/test-org/test-repo/pull/12/" in prefix_urls
    assert "https://api.github.com/repos/test-org/test-repo/pulls/12/" in prefix_urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/12/" in prefix_urls

    # Verify no accidental prefix match between pull/12 and pull/120
    test_prefix = "https://github.com/test-org/test-repo/pull/12/"
    unrelated_pr = "https://github.com/test-org/test-repo/pull/120"
    assert not unrelated_pr.startswith(test_prefix)


def test_defect11_multi_issue_scrubs_every_referenced_issue(tmp_path: Path) -> None:
    """Defect 11: Multi-issue case scrubs every referenced issue and warns statement was left as scraped."""
    issue_6189 = load_fixture_json("multi_issue_6189.json")
    issue_6190 = load_fixture_json("multi_issue_6190.json")
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    def fake_post(url: str, payload: dict) -> dict:
        op = payload.get("operationName")
        if op == "PullRequestData":
            return pr_fixture
        if op == "TargetIssueData":
            num = payload.get("variables", {}).get("number")
            if num == 6189:
                return issue_6189
            if num == 6190:
                return issue_6190
        raise ValueError(f"Unexpected op: {op}, payload: {payload}")

    warnings_list: list[str] = []
    scraped_ps = "Title: Multi issue statement\nFixes #6189 and #6190"

    result = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_numbers=[6189, 6190],
        target_issue_created=datetime.fromisoformat("2020-01-01T10:00:00+00:00"),
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement=scraped_ps,
        scraped_hints="",
        token="test-token",
        http_post_json=fake_post,
        cache_dir=tmp_path / "cache",
        warnings_list=warnings_list,
    )

    # 1. Unverifiable statement excluded with explicit warning
    assert result.problem_statement_revision == "excluded"
    assert result.problem_statement == ""
    assert any("unverifiable_content_excluded" in w for w in warnings_list)

    # 2. Every referenced issue was scrubbed
    urls = {e["url"] for e in result.scrub_entries}
    # Issue 6189 post-T_world comment
    assert "https://github.com/test-org/test-repo/issues/6189#issuecomment-1111" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/1111" in urls
    # Issue 6189 timeline item
    assert "https://github.com/test-org/test-repo/issues/7777" in urls

    # Issue 6190 post-T_world comment
    assert "https://github.com/test-org/test-repo/issues/6190#issuecomment-2222" in urls
    assert "https://api.github.com/repos/test-org/test-repo/issues/comments/2222" in urls
    # Issue 6190 connected PR 8888 full set
    assert "https://github.com/test-org/test-repo/pull/8888" in urls
    assert "https://api.github.com/repos/test-org/test-repo/pulls/8888" in urls


def test_defect12_unrevisioned_warning_restored_on_all_paths(tmp_path: Path) -> None:
    """Defect 12: Warning restored for every path where problem statement is not revision-checked."""
    expected_warning = "unverifiable_content_excluded"
    pr_fixture = load_fixture_json("pull_request_scrub.json")

    # Path 1: No GitHub target issue (e.g. Trac or no issue reference)
    warn_p1: list[str] = []
    res_p1 = process_thread_scrub_and_revision(
        repo="django/django",
        pr_number=50,
        target_issue_number=None,
        target_issue_numbers=[],
        target_issue_created=None,
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Django problem statement",
        scraped_hints="",
        token="test-token",
        http_post_json=lambda u, p: pr_fixture,
        cache_dir=tmp_path / "cache_p1",
        warnings_list=warn_p1,
    )
    assert res_p1.problem_statement_revision == "excluded"
    assert expected_warning in warn_p1

    # Path 2: Multi-issue path
    warn_p2: list[str] = []
    res_p2 = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=None,
        target_issue_numbers=[100, 200],
        target_issue_created=None,
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="Multi-issue problem statement",
        scraped_hints="",
        token="test-token",
        http_post_json=lambda u, p: pr_fixture,
        cache_dir=tmp_path / "cache_p2",
        warnings_list=warn_p2,
    )
    assert res_p2.problem_statement_revision == "excluded"
    assert expected_warning in warn_p2

    # Path 3: Fallback due to missing token / failed GraphQL
    warn_p3: list[str] = []
    res_p3 = process_thread_scrub_and_revision(
        repo="test-org/test-repo",
        pr_number=50,
        target_issue_number=100,
        target_issue_numbers=[100],
        target_issue_created=None,
        t_world=datetime.fromisoformat("2020-01-10T00:00:00+00:00"),
        scraped_problem_statement="No token fallback statement",
        scraped_hints="",
        token=None,
        http_post_json=None,
        cache_dir=tmp_path / "cache_p3",
        warnings_list=warn_p3,
    )
    assert res_p3.problem_statement_revision == "excluded"
    assert expected_warning in warn_p3


def test_defect3_query_bearing_resource_matching() -> None:
    """Regression Defect 3: Evaluate generated entries against query-bearing PR, comment, and referencing-resource URLs; assert PR 50 does not block PR 500."""
    from hermetic_slice.thread_scrub import get_referencing_pr_scrub_entries

    repo = "test-org/test-repo"
    pr_entries = get_solution_pr_scrub_entries(repo, 50, commit_shas=["sha123"])

    # Add standalone comment entry
    pr_entries.append(ScrubEntry(
        kind="comment",
        match="exact",
        url=f"https://api.github.com/repos/{repo}/issues/comments/777",
        reason="late comment",
    ))
    pr_entries.append(ScrubEntry(
        kind="comment",
        match="exact",
        url=f"https://github.com/{repo}/issues/100#issuecomment-777",
        reason="late comment HTML",
    ))

    # Add referencing resource entries
    pr_entries.extend(get_referencing_pr_scrub_entries("other-org/other-repo", 80, base_reason="referencing PR"))

    # 1. Query-bearing solution PR URLs are blocked
    assert matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/pulls/50?x=1")
    assert matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/pulls/50/?x=1")
    assert matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/50?diff=split")
    assert matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/50/files?x=1&y=2")
    assert matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/50.diff?raw=true")
    assert matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/pulls/50/commits?per_page=100")

    # 2. Query-bearing comment URLs are blocked
    assert matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/issues/comments/777?view=simple")
    assert matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/issues/100?x=1#issuecomment-777")
    # Different comment id is not blocked
    assert not matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/issues/comments/7770?view=simple")
    assert not matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/issues/100?x=1#issuecomment-999")

    # 3. Query-bearing referencing resource URLs are blocked
    assert matches_any_scrub_entry(pr_entries, "https://github.com/other-org/other-repo/pull/80?x=1")
    assert matches_any_scrub_entry(pr_entries, "https://api.github.com/repos/other-org/other-repo/pulls/80?page=2")
    assert matches_any_scrub_entry(pr_entries, "https://github.com/other-org/other-repo/pull/80/files?utf8=1")

    # 4. Strict numeric path boundary: PR 50 does NOT block PR 500
    assert not matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/pulls/500")
    assert not matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/pulls/500?x=1")
    assert not matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/500")
    assert not matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/500?x=1")
    assert not matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/500/files")
    assert not matches_any_scrub_entry(pr_entries, f"https://github.com/{repo}/pull/500/files?x=1")
    assert not matches_any_scrub_entry(pr_entries, f"https://api.github.com/repos/{repo}/pulls/500/commits")

