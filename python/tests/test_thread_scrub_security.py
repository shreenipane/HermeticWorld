"""Offline regressions for response validation, exclusion, and artifact publication."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from hermetic_slice import http, thread_scrub
from hermetic_slice.intake import IntakeError, intake_task
from hermetic_slice.thread_scrub import process_thread_scrub_and_revision

LATE = "UNIQUE_LATE_FIX_73921"
SECRET = "UNIQUE_REMOTE_SECRET_84127"
WORLD = datetime(2020, 1, 5, tzinfo=timezone.utc)
REPO = "test-org/test-repo"


def connection(nodes=(), *, more=False, cursor=None):
    return {"nodes": list(nodes), "pageInfo": {"hasNextPage": more, "endCursor": cursor}}


def issue():
    return {
        "id": "issue1", "body": "verified original", "createdAt": "2020-01-01T00:00:00Z",
        "lastEditedAt": None, "includesCreatedEdit": True,
        "userContentEdits": connection(), "comments": connection(), "timelineItems": connection(),
    }


def comment():
    return {
        "id": "comment1", "databaseId": 101,
        "url": f"https://github.com/{REPO}/issues/1#issuecomment-101",
        "body": LATE, "createdAt": "2020-01-02T00:00:00Z",
        "lastEditedAt": "2020-01-10T00:00:00Z", "includesCreatedEdit": True,
        "userContentEdits": connection([{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}]),
    }


def pr():
    return {"comments": connection(), "reviews": connection(), "reviewThreads": connection()}


def response(kind, node):
    return {"data": {"repository": {kind: deepcopy(node)}}}


def run_scrub(tmp_path, node=None, *, post=None, targets=None, warnings=None, **kwargs):
    node = issue() if node is None else node
    if post is None:
        def post(url, payload):
            if payload["operationName"] == "PullRequestData":
                return response("pullRequest", pr())
            return response("issue", node)
    return process_thread_scrub_and_revision(
        repo=REPO, pr_number=50, target_issue_numbers=[1] if targets is None else targets,
        t_world=WORLD, scraped_problem_statement=f"Title\n{LATE}", scraped_hints=LATE,
        http_post_json=post, cache_dir=tmp_path / "cache",
        warnings_list=[] if warnings is None else warnings, **kwargs,
    )


def assert_denied(entries):
    # Unknown incoming references can be in another repository. Both services
    # must be denied in full when discovery could not determine that scope.
    for prefix in ("https://github.com/", "https://api.github.com/"):
        assert any(e["url"] == prefix and e["match"] == "prefix" for e in entries)


def publish(tmp_path, *, post=None, refs="Fixes #1", marker=LATE, **kwargs):
    row = {"repo": REPO, "base_commit": "abc", "problem_statement": marker,
           "hints_text": marker, "patch": "gold", "test_patch": "tests"}
    def get(url):
        if "/commits?" in url:
            return b"[]"
        if "/issues/" in url:
            return b'{"created_at":"2020-01-01T00:00:00Z"}'
        return json.dumps({"created_at": "2020-02-01T00:00:00Z", "body": refs}).encode()
    with patch("hermetic_slice.intake.repo_dates", return_value=(WORLD, WORLD)):
        return intake_task("test-org__test-repo-50", {"test-org__test-repo-50": row}, get,
                           tmp_path / "cache", tmp_path / "out", http_post_json=post, **kwargs)


@pytest.mark.parametrize("fallback", ["credentials", "query", "no_issue", "multi_issue", "empty", "null"])
def test_unverifiable_fallback_markers_never_reach_files(tmp_path, fallback):
    node = issue()
    node["lastEditedAt"] = "2020-01-10T00:00:00Z"
    node["body"] = LATE
    if fallback == "null":
        node["userContentEdits"] = connection([{"editedAt": "2020-01-01T00:00:00Z", "diff": None}])
    def post(url, payload):
        if fallback == "query":
            raise OSError(SECRET)
        return response("pullRequest", pr()) if payload["operationName"] == "PullRequestData" else response("issue", node)
    refs = "" if fallback == "no_issue" else "Fixes #1 and fixes #2" if fallback == "multi_issue" else "Fixes #1"
    task = publish(tmp_path, post=None if fallback == "credentials" else post, refs=refs)
    assert LATE not in (task / "agent/problem_statement.md").read_text()
    assert LATE not in (task / "staging/hints.txt").read_text()
    assert json.loads((task / "task.json").read_text())["problem_statement_revision"] == "excluded"


@pytest.mark.parametrize("status", ["omitted", "invalid", 123, {}, False])
@pytest.mark.parametrize("document", ["issue", "comment"])
def test_unknown_edit_status_excludes_markers(tmp_path, status, document):
    node = issue()
    target = node if document == "issue" else comment()
    target["body"] = LATE
    target["userContentEdits"] = connection()
    if status == "omitted":
        target.pop("lastEditedAt")
    else:
        target["lastEditedAt"] = status
    if document == "comment":
        node["comments"] = connection([target])
    result = run_scrub(tmp_path, node)
    assert LATE not in result.problem_statement + result.hints_text
    if document == "issue":
        assert result.problem_statement_revision == "excluded"
    else:
        assert result.hints_excluded_no_history == 1
        assert result.problem_statement_revision == "as_scraped"


@pytest.mark.parametrize("malformed", ["numeric_created", "null_edit", "object_body", "null_timeline", "object_timeline_source"])
def test_hostile_response_fields_are_controlled(tmp_path, malformed):
    node = issue()
    c = comment()
    c["lastEditedAt"] = None
    node["comments"] = connection([c])
    if malformed == "numeric_created":
        c["createdAt"] = 123
    elif malformed == "null_edit":
        node["lastEditedAt"] = "2020-01-10T00:00:00Z"
        node["userContentEdits"] = connection([None])
    elif malformed == "object_body":
        c["body"] = {"text": LATE}
    elif malformed == "null_timeline":
        node["timelineItems"] = connection([None])
    else:
        node["timelineItems"] = connection([{"__typename": "CrossReferencedEvent", "source": [LATE]}])
    warnings = []
    result = run_scrub(tmp_path, node, warnings=warnings)
    assert LATE not in result.problem_statement + result.hints_text + json.dumps(warnings)
    if malformed == "numeric_created":
        assert result.hints_excluded_no_created_at == 1
    else:
        assert result.problem_statement_revision == "excluded"
    assert_denied(result.scrub_entries)


@pytest.mark.parametrize("document", ["issue", "comment"])
@pytest.mark.parametrize("bad_page", ["initial_missing", "initial_empty", "initial_nonbool", "later_empty", "later_missing", "later_null_owner", "later_null_connection"])
def test_incomplete_revision_pages_never_certified(tmp_path, document, bad_page):
    node = issue()
    target = node if document == "issue" else comment()
    target.update(body=LATE, lastEditedAt="2020-01-10T00:00:00Z", includesCreatedEdit=True)
    history = connection([{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}])
    target["userContentEdits"] = history
    if document == "comment":
        node["comments"] = connection([target])
    later = connection([{"editedAt": "2020-01-01T00:00:00Z", "diff": "verified original"}])
    if bad_page == "initial_missing":
        history.pop("pageInfo")
    elif bad_page == "initial_empty":
        history["pageInfo"] = {}
    elif bad_page == "initial_nonbool":
        history["pageInfo"]["hasNextPage"] = 0
    else:
        history["pageInfo"] = {"hasNextPage": True, "endCursor": "page2"}
        if bad_page == "later_empty":
            later["pageInfo"] = {}
        elif bad_page == "later_missing":
            later.pop("pageInfo")
    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", node)
        owner = None if bad_page == "later_null_owner" else {"userContentEdits": None if bad_page == "later_null_connection" else later}
        return {"data": {"node": owner}} if document == "comment" else response("issue", owner)
    result = run_scrub(tmp_path, post=post)
    assert LATE not in result.problem_statement + result.hints_text
    if document == "issue":
        assert result.problem_statement_revision == "excluded"
    else:
        assert result.hints_excluded_no_history == 1


@pytest.mark.parametrize("document", ["issue", "comment"])
def test_repeated_cursor_terminates_without_certifying(tmp_path, document):
    node = issue()
    target = node if document == "issue" else comment()
    target.update(lastEditedAt="2020-01-10T00:00:00Z", includesCreatedEdit=True)
    history = connection([{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}], more=True, cursor="same")
    target["userContentEdits"] = history
    if document == "comment":
        node["comments"] = connection([target])
    calls = []
    def post(url, payload):
        calls.append(payload["operationName"])
        assert len(calls) <= 4, "pagination must detect its repeated cursor"
        if payload["operationName"] == "PullRequestData":
            return response("pullRequest", pr())
        if payload["operationName"] == "CommentEditsPage":
            return {"data": {"node": {"userContentEdits": history}}}
        return response("issue", node)
    result = run_scrub(tmp_path, post=post)
    assert len(calls) == 3
    assert LATE not in result.problem_statement + result.hints_text
    assert result.problem_statement_revision == "excluded" if document == "issue" else result.hints_excluded_no_history == 1


@pytest.mark.parametrize("cap", ["MAX_CONNECTION_PAGES", "MAX_CONNECTION_NODES", "MAX_GRAPHQL_PAGES", "MAX_GRAPHQL_NODES", "MAX_GRAPHQL_BYTES"])
def test_named_pagination_and_aggregate_caps_exclude(tmp_path, cap):
    node = issue()
    node["lastEditedAt"] = "2020-01-10T00:00:00Z"
    node["userContentEdits"] = connection([{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}], more=True, cursor="start")
    calls = []
    def post(url, payload):
        calls.append(payload["operationName"])
        assert len(calls) < 8
        if payload["operationName"] == "PullRequestData":
            return response("pullRequest", pr())
        result = response("issue", node)
        result["data"]["repository"]["issue"]["userContentEdits"]["pageInfo"]["endCursor"] = str(len(calls))
        return result
    with patch.object(thread_scrub, cap, 1):
        result = run_scrub(tmp_path, post=post)
    assert result.problem_statement_revision == "excluded"
    assert LATE not in result.problem_statement + result.hints_text
    assert_denied(result.scrub_entries)


def test_supplied_production_client_gets_run_snapshot(tmp_path):
    client = http.make_http_post_json(tmp_path / "cache", snapshot_id="initial")
    nodes = [issue(), issue()]
    late = comment()
    late["createdAt"] = "2020-01-20T00:00:00Z"
    nodes[1]["comments"] = connection([late])
    calls = []
    run = 0
    class Transport(io.BytesIO):
        status = 200
    def network(req, timeout):
        payload = json.loads(req.data)
        calls.append((run, payload["operationName"]))
        obj = response("pullRequest", pr()) if payload["operationName"] == "PullRequestData" else response("issue", nodes[run])
        return Transport(json.dumps(obj).encode())
    with patch("urllib.request.urlopen", side_effect=network):
        first = run_scrub(tmp_path, post=client, targets=[1, 1], snapshot_id="shared")
        run = 1
        second = run_scrub(tmp_path, post=client, targets=[1, 1], snapshot_id="shared", refresh=True)
    # Duplicate target lookups within each run share cached bytes; the second
    # run uses the very same supplied client and must fetch new mutable pages.
    assert calls == [(0, "PullRequestData"), (0, "TargetIssueData"),
                     (1, "PullRequestData"), (1, "TargetIssueData")]
    late_url = f"https://api.github.com/repos/{REPO}/issues/comments/101"
    assert late_url not in [e["url"] for e in first.scrub_entries]
    assert late_url in [e["url"] for e in second.scrub_entries]
    assert LATE not in second.hints_text
    assert not any(e["kind"] == "unresolved_scope" for e in second.scrub_entries)


@pytest.mark.parametrize("source", ["graphql", "transport"])
def test_remote_errors_never_disclose_in_metadata(tmp_path, source):
    def post(url, payload):
        if source == "transport":
            raise OSError(f"/host/private/{SECRET}/{LATE}")
        return {"errors": [{"message": SECRET + LATE}]}
    task = publish(tmp_path, post=post)
    for path in (task / "task.json", task / "agent/problem_statement.md", task / "staging/hints.txt", task / "staging/thread_scrub.json"):
        assert SECRET not in path.read_text()
        assert LATE not in path.read_text()
    assert_denied(json.loads((task / "staging/thread_scrub.json").read_text()))


@pytest.mark.parametrize("failure", ["pr", "second_issue_page"])
def test_incomplete_scrub_publication_requires_scope_denial(tmp_path, failure):
    node = issue()
    node["comments"] = connection(more=True, cursor="second")
    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            if failure == "pr":
                raise OSError(SECRET)
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", node if payload["variables"]["number"] == 2 else issue())
        raise OSError(SECRET)
    task = publish(tmp_path, post=post, refs="Fixes #1 and fixes #2")
    assert_denied(json.loads((task / "staging/thread_scrub.json").read_text()))
    assert (task / "agent/problem_statement.md").read_bytes() == b""
    assert (task / "staging/hints.txt").read_bytes() == b""


@pytest.mark.parametrize("existing", [False, True])
def test_scrub_write_failure_never_publishes_completion(tmp_path, existing):
    if existing:
        publish(tmp_path)
    original = os.replace
    def fail_scrub(src, dst, *args, **kwargs):
        if str(dst).endswith("thread_scrub.json"):
            raise OSError(SECRET)
        return original(src, dst, *args, **kwargs)
    with patch("os.replace", side_effect=fail_scrub):
        with pytest.raises(IntakeError) as exc:
            publish(tmp_path)
    assert SECRET not in str(exc.value)
    task = tmp_path / "out/test-org__test-repo-50"
    assert not (task / "task.json").exists()
    assert not (task / "staging/thread_scrub.json").exists()
    assert not list(task.rglob("*.tmp"))


@pytest.mark.parametrize("failure", ["missing_id", "non_json", "null_node"])
def test_comment_history_failure_variants_excluded(tmp_path, failure):
    node = issue()
    c = comment()
    c["userContentEdits"]["pageInfo"] = {"hasNextPage": True, "endCursor": "second"}
    if failure == "missing_id":
        c.pop("id")
    node["comments"] = connection([c])
    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", node)
        if failure == "non_json":
            return b"not json " + SECRET.encode()
        if failure == "null_node":
            return {"data": {"node": None}}
        return {"data": {"node": {"userContentEdits": connection([{"editedAt": "2020-01-01T00:00:00Z", "diff": "old comment"}])}}}
    warnings = []
    result = run_scrub(tmp_path, post=post, warnings=warnings)
    assert result.hints_text == ""
    assert result.hints_excluded_no_history == 1
    assert result.problem_statement_revision == "as_scraped"
    assert SECRET not in json.dumps(warnings)
    if failure == "missing_id":
        assert "CommentEditsPage" not in calls


def test_solution_pr_conversation_comments_all_pages_scrubbed(tmp_path):
    initial = pr()
    initial["comments"] = connection([{"databaseId": 201}], more=True, cursor="second")
    later = {"comments": connection([{"databaseId": 202, "url": f"https://github.com/{REPO}/pull/50#issuecomment-202"}])}
    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return response("pullRequest", initial)
        if op == "PullRequestCommentsPage":
            assert payload["variables"]["cursor"] == "second"
            return response("pullRequest", later)
        return response("issue", issue())
    result = run_scrub(tmp_path, post=post)
    urls = [e["url"] for e in result.scrub_entries]
    assert f"https://api.github.com/repos/{REPO}/issues/comments/201" in urls
    assert f"https://api.github.com/repos/{REPO}/issues/comments/202" in urls
    assert f"https://github.com/{REPO}/pull/50#issuecomment-202" in urls
    assert calls.count("PullRequestCommentsPage") == 1
    assert not any(e["kind"] == "unresolved_scope" for e in result.scrub_entries)


def test_reused_production_client_refreshes_intake_runs(tmp_path):
    client = http.make_http_post_json(tmp_path / "cache", snapshot_id="old")
    current = issue()
    calls = []
    class Transport(io.BytesIO):
        status = 200
    def network(req, timeout):
        op = json.loads(req.data)["operationName"]
        calls.append(op)
        obj = response("pullRequest", pr()) if op == "PullRequestData" else response("issue", current)
        return Transport(json.dumps(obj).encode())
    with patch("urllib.request.urlopen", side_effect=network):
        first = publish(tmp_path, post=client, snapshot_id="same")
        first_scrub = json.loads((first / "staging/thread_scrub.json").read_text())
        late = comment()
        late["createdAt"] = "2020-01-20T00:00:00Z"
        current["comments"] = connection([late])
        second = publish(tmp_path, post=client, snapshot_id="same", refresh=True)
    url = f"https://api.github.com/repos/{REPO}/issues/comments/101"
    assert url not in [e["url"] for e in first_scrub]
    entries = json.loads((second / "staging/thread_scrub.json").read_text())
    assert url in [e["url"] for e in entries]
    assert not any(e["kind"] == "unresolved_scope" for e in entries)
    assert calls == ["PullRequestData", "TargetIssueData", "PullRequestData", "TargetIssueData"]


def test_cached_cursor_cycle_is_bounded(tmp_path):
    real_client = http.make_http_post_json(tmp_path / "cache", snapshot_id="cycle")
    current = issue()
    current["body"] = LATE
    current["lastEditedAt"] = "2020-01-10T00:00:00Z"
    current["userContentEdits"] = connection(
        [{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}], more=True, cursor="cycle")
    requests = []
    calls = []
    class Transport(io.BytesIO):
        status = 200
    def network(req, timeout):
        op = json.loads(req.data)["operationName"]
        requests.append(op)
        obj = response("pullRequest", pr()) if op == "PullRequestData" else response("issue", current)
        return Transport(json.dumps(obj).encode())
    def guarded_client(url, payload):
        calls.append(payload["operationName"])
        assert len(calls) <= 4, "cached cursor repeated without termination"
        return real_client(url, payload)
    with patch("urllib.request.urlopen", side_effect=network):
        result = run_scrub(tmp_path, post=guarded_client)
    assert calls == requests == ["PullRequestData", "TargetIssueData", "IssueEditsPage"]
    assert result.problem_statement_revision == "excluded"
    assert LATE not in result.problem_statement + result.hints_text


@pytest.mark.parametrize("source", ["graphql", "transport"])
def test_surfaced_graphql_errors_are_structured(tmp_path, source):
    def post(url, payload):
        if source == "transport":
            raise OSError(SECRET + LATE)
        return {"errors": [{"message": SECRET + LATE}]}
    with pytest.raises(thread_scrub.GraphQLResponseError) as exc:
        thread_scrub._post_graphql(post, "query", {}, "Test")
    assert str(exc.value) == "graphql_request_failed"
    assert SECRET not in repr(exc.value)
    assert LATE not in repr(exc.value)


def test_output_directory_failure_has_no_host_path(tmp_path):
    with patch("hermetic_slice.intake.open_secure_directory", side_effect=OSError("/host/" + SECRET)):
        with pytest.raises(IntakeError) as exc:
            publish(tmp_path)
    assert str(exc.value) == "task_publication_failed"
    assert SECRET not in repr(exc.value)
    assert not (tmp_path / "out/test-org__test-repo-50/task.json").exists()


@pytest.mark.parametrize("unidentified_case", ["late_comment", "pr_comment", "null_source", "connected_null_source"])
def test_defect1_unidentified_resources_require_scope_denial(tmp_path, unidentified_case):
    """Regression Defect 1: Unidentified late comments, PR comments, and null reference sources either fail publication or include scope denial."""
    target_node = issue()
    pr_node = pr()

    if unidentified_case == "late_comment":
        target_node["comments"] = connection([{
            "id": "c_unidentified",
            "databaseId": None,
            "url": None,
            "body": LATE,
            "createdAt": "2020-01-10T00:00:00Z",
            "lastEditedAt": None,
        }])
    elif unidentified_case == "pr_comment":
        pr_node["comments"] = connection([{
            "id": "pr_c_unidentified",
            "databaseId": None,
            "url": None,
        }])
    elif unidentified_case == "null_source":
        target_node["timelineItems"] = connection([{
            "__typename": "CrossReferencedEvent",
            "url": None,
            "source": None,
        }])
    elif unidentified_case == "connected_null_source":
        target_node["timelineItems"] = connection([{
            "__typename": "ConnectedEvent",
            "source": None,
            "subject": {
                "__typename": "Issue",
                "number": 1,
                "url": f"https://github.com/{REPO}/issues/1",
            },
        }])

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr_node)
        if op == "TargetIssueData":
            return response("issue", target_node)
        raise OSError("unexpected op")

    try:
        task = publish(tmp_path, post=post, refs="Fixes #1")
        scrub = json.loads((task / "staging/thread_scrub.json").read_text())
        assert_denied(scrub)
        assert (task / "agent/problem_statement.md").read_bytes() == b""
        assert (task / "staging/hints.txt").read_bytes() == b""
    except IntakeError:
        pass


def test_defect1_connected_event_null_source_and_target_subject_denial(tmp_path):
    """Regression Defect 1: ConnectedEvent with source: null and target subject passes intake_task with mandatory scope denial or rejection."""
    target_node = issue()
    target_node["timelineItems"] = connection([{
        "__typename": "ConnectedEvent",
        "source": None,
        "subject": {
            "__typename": "Issue",
            "number": 1,
            "url": f"https://github.com/{REPO}/issues/1",
        },
    }])

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", target_node)
        raise OSError("unexpected op")

    try:
        task = publish(tmp_path, post=post, refs="Fixes #1")
        scrub = json.loads((task / "staging/thread_scrub.json").read_text())
        assert_denied(scrub)
        assert (task / "agent/problem_statement.md").read_bytes() == b""
        assert (task / "staging/hints.txt").read_bytes() == b""
    except IntakeError:
        pass


def test_defect2_unresolved_reference_lookup_denies_scope(tmp_path):
    """Regression Defect 2: 404/410 for one issue ref preserves unresolved target reference and emits scope denial despite GraphQL success on remaining issue."""
    def get(url):
        if "/commits?" in url:
            return b"[]"
        if "/issues/1" in url:
            return b'{"created_at":"2020-01-01T00:00:00Z"}'
        if "/issues/2" in url:
            raise http.HttpError(url, 404)
        return json.dumps({"created_at": "2020-02-01T00:00:00Z", "body": "Fixes #1 and fixes #2"}).encode()

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            assert payload["variables"]["number"] == 1
            return response("issue", issue())
        raise OSError(f"Unexpected op: {op}")

    row = {
        "repo": REPO,
        "base_commit": "abc",
        "problem_statement": "Statement",
        "hints_text": "Hints",
        "patch": "gold",
        "test_patch": "tests",
    }
    with patch("hermetic_slice.intake.repo_dates", return_value=(WORLD, WORLD)):
        task = intake_task(
            "test-org__test-repo-50",
            {"test-org__test-repo-50": row},
            get,
            tmp_path / "cache",
            tmp_path / "out",
            http_post_json=post,
        )

    scrub = json.loads((task / "staging/thread_scrub.json").read_text())
    assert_denied(scrub)
    assert (task / "agent/problem_statement.md").read_bytes() == b""
    assert (task / "staging/hints.txt").read_bytes() == b""
    urls = [e["url"] for e in scrub]
    assert f"https://github.com/{REPO}/issues/2" in urls


@pytest.mark.parametrize("location", ["issue_body", "comment_body"])
def test_defect4_oversized_numeric_reference_handled_gracefully(tmp_path, location):
    """Regression Defect 4: Hostile discussion text with 5,000-digit reference causes no uncaught exception and denies scope."""
    hostile_ref = "Fixes #" + "9" * 5000
    target_node = issue()

    if location == "issue_body":
        target_node["body"] = hostile_ref
    else:
        comm = comment()
        comm["body"] = hostile_ref
        target_node["comments"] = connection([comm])

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", target_node)
        raise OSError("unexpected op")

    warnings: list[str] = []
    res = run_scrub(tmp_path, node=target_node, post=post, warnings=warnings)
    assert_denied(res.scrub_entries)


def test_defect5_ancestor_symlink_swap_leaves_sentinel_untouched(tmp_path):
    """Regression Defect 5: Swapping task directory ancestor after validation leaves outside sentinels untouched and publishes no task.json."""
    outside_dir = tmp_path / "outside_dir"
    (outside_dir / "agent").mkdir(parents=True)
    (outside_dir / "staging").mkdir(parents=True)
    agent_sentinel = outside_dir / "agent" / "sentinel.txt"
    staging_sentinel = outside_dir / "staging" / "sentinel.txt"
    agent_sentinel.write_text("agent_sentinel_data", encoding="utf-8")
    staging_sentinel.write_text("staging_sentinel_data", encoding="utf-8")

    from hermetic_slice import intake
    real_open = intake.open_secure_directory
    swapped = False

    task_target = tmp_path / "out" / "test-org__test-repo-50"

    def hook_open_secure(p):
        nonlocal swapped
        fd = real_open(p)
        if Path(p) == task_target and not swapped:
            swapped = True
            backup = tmp_path / "out" / "temp_backup"
            os.rename(task_target, backup)
            os.symlink(outside_dir, task_target)
        return fd

    with patch("hermetic_slice.intake.open_secure_directory", side_effect=hook_open_secure):
        with pytest.raises(IntakeError):
            publish(tmp_path, refs="Fixes #1")

    assert agent_sentinel.exists()
    assert agent_sentinel.read_text(encoding="utf-8") == "agent_sentinel_data"
    assert staging_sentinel.exists()
    assert staging_sentinel.read_text(encoding="utf-8") == "staging_sentinel_data"
    assert not (outside_dir / "task.json").exists()
