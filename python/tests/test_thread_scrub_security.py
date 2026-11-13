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
    target_resp = response("issue", node)
    target_resp["data"]["repository"]["issue"]["userContentEdits"] = connection(
        [{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}],
        more=True,
        cursor="page2",
    )
    pr_resp = response("pullRequest", pr())
    edits_resp = {
        "data": {
            "repository": {
                "issue": {
                    "includesCreatedEdit": True,
                    "userContentEdits": connection(
                        [{"editedAt": "2020-01-01T00:00:00Z", "diff": "clean"}],
                        more=False,
                    ),
                }
            }
        }
    }

    n1, s1 = thread_scrub._measure_response(pr_resp)
    n2, s2 = thread_scrub._measure_response(target_resp)

    if cap == "MAX_GRAPHQL_NODES":
        cap_val = max(n1, n2)
        expected_calls = 2
    elif cap == "MAX_GRAPHQL_BYTES":
        cap_val = max(s1, s2)
        expected_calls = 2
    elif cap == "MAX_GRAPHQL_PAGES":
        cap_val = 2
        expected_calls = 2
    elif cap == "MAX_CONNECTION_PAGES":
        cap_val = 1
        expected_calls = 2
    elif cap == "MAX_CONNECTION_NODES":
        cap_val = 1
        expected_calls = 3

    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return deepcopy(pr_resp)
        if op == "TargetIssueData":
            return deepcopy(target_resp)
        if op == "IssueEditsPage":
            return deepcopy(edits_resp)
        return response("issue", issue())

    with patch.object(thread_scrub, cap, cap_val):
        result = run_scrub(tmp_path, post=post)
    assert len(calls) == expected_calls
    assert result.problem_statement_revision == "excluded"
    assert LATE not in result.problem_statement + result.hints_text
    assert_denied(result.scrub_entries)


@pytest.mark.parametrize("cap", ["MAX_CONNECTION_PAGES", "MAX_CONNECTION_NODES", "MAX_GRAPHQL_PAGES", "MAX_GRAPHQL_NODES", "MAX_GRAPHQL_BYTES"])
def test_named_caps_would_succeed_without_limit_check(tmp_path, cap):
    """Regression Defect 6: verify finite responses complete successfully when the limit check is not tripped, so the test fails if limit check is removed."""
    node = issue()
    node["lastEditedAt"] = "2020-01-10T00:00:00Z"
    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            result = response("issue", node)
            result["data"]["repository"]["issue"]["userContentEdits"] = connection(
                [{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}],
                more=True,
                cursor="page2",
            )
            return result
        if op == "IssueEditsPage":
            return {
                "data": {
                    "repository": {
                        "issue": {
                            "includesCreatedEdit": True,
                            "userContentEdits": connection(
                                [{"editedAt": "2020-01-01T00:00:00Z", "diff": "clean"}],
                                more=False,
                            ),
                        }
                    }
                }
            }
        return response("issue", issue())

    result = run_scrub(tmp_path, post=post)
    assert len(calls) == 3
    assert result.problem_statement_revision == "revision_at_t_world"
    assert "clean" in result.problem_statement
    assert not any(e["url"] == "https://github.com/" and e["match"] == "prefix" for e in result.scrub_entries)


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


def test_defect1_late_comment_blocks_containing_resources_and_query_variants(tmp_path):
    """Regression Defect 1: Late comment scrub list blocks containing fragmentless HTML page and comments collection, including query variants."""
    target_node = issue()
    late_c = comment()
    late_c["createdAt"] = "2020-01-20T00:00:00Z"
    target_node["comments"] = connection([late_c])
    result = run_scrub(tmp_path, node=target_node)
    entries = result.scrub_entries

    assert thread_scrub.matches_any_scrub_entry(entries, f"https://github.com/{REPO}/issues/1")
    assert thread_scrub.matches_any_scrub_entry(entries, f"https://github.com/{REPO}/issues/1?tab=comments")
    assert thread_scrub.matches_any_scrub_entry(entries, f"https://github.com/{REPO}/issues/1/?x=1")

    assert thread_scrub.matches_any_scrub_entry(entries, f"https://api.github.com/repos/{REPO}/issues/1/comments")
    assert thread_scrub.matches_any_scrub_entry(entries, f"https://api.github.com/repos/{REPO}/issues/1/comments?page=2")
    assert thread_scrub.matches_any_scrub_entry(entries, f"https://api.github.com/repos/{REPO}/issues/1/comments/?per_page=50")

    assert not thread_scrub.matches_any_scrub_entry(entries, f"https://github.com/{REPO}/issues/2")
    assert not thread_scrub.matches_any_scrub_entry(entries, f"https://api.github.com/repos/{REPO}/issues/2/comments")


def test_defect2_number_only_cross_reference_requires_rejection_or_scope_denial(tmp_path):
    """Regression Defect 2: Number-only CrossReferencedEvent source denies scope and never assumes target repository."""
    target_node = issue()
    target_node["timelineItems"] = connection([{
        "__typename": "CrossReferencedEvent",
        "url": None,
        "source": {
            "__typename": "Issue",
            "number": 88,
            "url": None,
        },
    }])
    result = run_scrub(tmp_path, node=target_node)
    assert_denied(result.scrub_entries)
    urls = [e["url"] for e in result.scrub_entries]
    assert f"https://github.com/{REPO}/issues/88" not in urls
    assert f"https://api.github.com/repos/{REPO}/issues/88" not in urls


def test_defect2_number_only_connected_event_requires_rejection_or_scope_denial(tmp_path):
    """Regression Defect 2: Number-only ConnectedEvent candidate denies scope and never assumes target repository."""
    target_node = issue()
    target_node["timelineItems"] = connection([{
        "__typename": "ConnectedEvent",
        "source": {
            "__typename": "Issue",
            "number": 88,
            "url": None,
        },
        "subject": {
            "__typename": "Issue",
            "number": 1,
            "url": f"https://github.com/{REPO}/issues/1",
        },
    }])
    result = run_scrub(tmp_path, node=target_node)
    assert_denied(result.scrub_entries)
    urls = [e["url"] for e in result.scrub_entries]
    assert f"https://github.com/{REPO}/issues/88" not in urls
    assert f"https://api.github.com/repos/{REPO}/issues/88" not in urls


@pytest.mark.parametrize("comment_type,url", [
    ("review_comment", f"https://github.com/{REPO}/pull/50"),
    ("review_comment", f"https://github.com/{REPO}/pull/50#discussion_r"),
    ("review_comment", f"https://github.com/{REPO}/pull/50#discussion_rnotanumber"),
    ("pr_comment", f"https://github.com/{REPO}/pull/50"),
    ("pr_comment", f"https://github.com/{REPO}/pull/50#issuecomment-bad"),
    ("issue_comment", f"https://github.com/{REPO}/issues/1"),
    ("issue_comment", f"https://github.com/{REPO}/issues/1#issuecomment-xyz"),
])
def test_defect3_url_only_comments_with_missing_or_malformed_fragments_denied(tmp_path, comment_type, url):
    """Regression Defect 3: Supply URL-only comments with missing or malformed fragments and assert mandatory scope denial."""
    pr_node = pr()
    issue_node = issue()
    if comment_type == "review_comment":
        pr_node["reviewThreads"] = connection([{
            "id": "thread1",
            "comments": connection([{"databaseId": None, "url": url}]),
        }])
    elif comment_type == "pr_comment":
        pr_node["comments"] = connection([{"databaseId": None, "url": url}])
    elif comment_type == "issue_comment":
        issue_node["comments"] = connection([{"databaseId": None, "url": url, "createdAt": "2020-01-02T00:00:00Z"}])

    def post(u, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr_node)
        if op == "TargetIssueData":
            return response("issue", issue_node)
        raise OSError(f"unexpected op {op}")

    result = run_scrub(tmp_path, node=issue_node, post=post)
    assert_denied(result.scrub_entries)


@pytest.mark.parametrize("bad_id", [
    ["bad"],
    {"bad": 1},
    "a" * 65,
    "not_hex_chars_123!",
])
@pytest.mark.parametrize("target_field", ["merge_commit_sha", "commit_sha"])
def test_defect4_malformed_commit_identifiers_fail_without_artifacts(tmp_path, bad_id, target_field):
    """Regression Defect 4: Exercise list-, object-, and oversized-string identifiers through intake_task; assert structured failure without artifacts."""
    row = {
        "repo": REPO,
        "base_commit": "abc",
        "problem_statement": "Statement",
        "hints_text": "Hints",
        "patch": "gold",
        "test_patch": "tests",
    }
    def get(url):
        if "/commits?" in url:
            if target_field == "commit_sha":
                return json.dumps([{
                    "sha": bad_id,
                    "commit": {
                        "author": {"date": "2020-01-01T00:00:00Z"},
                        "committer": {"date": "2020-01-01T00:00:00Z"},
                    },
                }]).encode()
            return b"[]"
        if "/issues/" in url:
            return b'{"created_at":"2020-01-01T00:00:00Z"}'
        data = {"created_at": "2020-02-01T00:00:00Z", "body": "Fixes #1"}
        if target_field == "merge_commit_sha":
            data["merge_commit_sha"] = bad_id
        return json.dumps(data).encode()

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", issue())
        raise OSError(f"unexpected op: {op}")

    out_dir = tmp_path / "out"
    with patch("hermetic_slice.intake.repo_dates", return_value=(WORLD, WORLD)):
        with pytest.raises(IntakeError):
            intake_task(
                "test-org__test-repo-50",
                {"test-org__test-repo-50": row},
                get,
                tmp_path / "cache",
                out_dir,
                http_post_json=post,
            )

    task_dir = out_dir / "test-org__test-repo-50"
    assert not (task_dir / "task.json").exists()
    assert not (task_dir / "staging/thread_scrub.json").exists()


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


def test_defect1_containing_comment_collections_blocked_when_forbidden_comments_exist(tmp_path):
    """Regression Defect 1: Successful discovery with forbidden comments denies containing collection endpoints and their query variants."""
    target_node = issue()
    late_c = {
        "id": "c_late",
        "databaseId": 101,
        "url": f"https://github.com/{REPO}/issues/1#issuecomment-101",
        "body": "late hint text",
        "createdAt": "2020-01-10T00:00:00Z",
        "lastEditedAt": None,
    }
    target_node["comments"] = connection([late_c])

    pr_node = pr()
    pr_rc = {
        "id": "pr_rc_1",
        "databaseId": 201,
        "url": f"https://github.com/{REPO}/pull/50#discussion_r201",
        "body": "review comment text",
    }
    pr_node["reviewThreads"] = connection([{
        "id": "thread_1",
        "comments": connection([pr_rc]),
    }])

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr_node)
        if op == "TargetIssueData":
            return response("issue", target_node)
        raise OSError("unexpected op")

    warnings: list[str] = []
    res = run_scrub(tmp_path, node=target_node, post=post, warnings=warnings)

    assert not any(e["kind"] == "unresolved_scope" for e in res.scrub_entries)

    issues_coll = f"https://api.github.com/repos/{REPO}/issues/comments"
    pulls_coll = f"https://api.github.com/repos/{REPO}/pulls/comments"

    for coll_url in (issues_coll, pulls_coll):
        assert thread_scrub.matches_any_scrub_entry(res.scrub_entries, coll_url)
        assert thread_scrub.matches_any_scrub_entry(res.scrub_entries, f"{coll_url}?page=1")
        assert thread_scrub.matches_any_scrub_entry(res.scrub_entries, f"{coll_url}?page=2&per_page=100")
        assert thread_scrub.matches_any_scrub_entry(res.scrub_entries, f"{coll_url}?since=2020-01-01T00:00:00Z")

    diff_issues = "https://api.github.com/repos/other-org/other-repo/issues/comments?page=1"
    diff_pulls = "https://api.github.com/repos/other-org/other-repo/pulls/comments?page=1"
    assert not thread_scrub.matches_any_scrub_entry(res.scrub_entries, diff_issues)
    assert not thread_scrub.matches_any_scrub_entry(res.scrub_entries, diff_pulls)


@pytest.mark.parametrize("kind,case", [
    ("review_comment", "conflicting_id"),
    ("review_comment", "foreign_repo"),
    ("pr_comment", "conflicting_id"),
    ("pr_comment", "foreign_repo"),
    ("issue_comment", "conflicting_id"),
    ("issue_comment", "foreign_repo"),
])
def test_defect2_comment_identity_validation_conflicting_ids_and_foreign_repos(tmp_path, kind, case):
    """Regression Defect 2: exercise conflicting IDs and foreign-repository URLs through top-level processing for review and conversation comments."""
    target_node = issue()
    pr_node = pr()

    if kind == "review_comment":
        if case == "conflicting_id":
            rc = {
                "id": "rc_bad",
                "databaseId": 101,
                "url": f"https://github.com/{REPO}/pull/50#discussion_r202",
            }
        else:
            rc = {
                "id": "rc_bad",
                "databaseId": 101,
                "url": "https://github.com/foreign-org/foreign-repo/pull/50#discussion_r101",
            }
        pr_node["reviewThreads"] = connection([{"id": "t1", "comments": connection([rc])}])

    elif kind == "pr_comment":
        if case == "conflicting_id":
            c = {
                "id": "c_bad",
                "databaseId": 101,
                "url": f"https://github.com/{REPO}/pull/50#issuecomment-202",
            }
        else:
            c = {
                "id": "c_bad",
                "databaseId": 101,
                "url": "https://github.com/foreign-org/foreign-repo/pull/50#issuecomment-101",
            }
        pr_node["comments"] = connection([c])

    elif kind == "issue_comment":
        if case == "conflicting_id":
            c = {
                "id": "c_bad",
                "databaseId": 101,
                "url": f"https://github.com/{REPO}/issues/1#issuecomment-202",
                "body": "some text",
                "createdAt": "2020-01-02T00:00:00Z",
                "lastEditedAt": None,
            }
        else:
            c = {
                "id": "c_bad",
                "databaseId": 101,
                "url": "https://github.com/foreign-org/foreign-repo/issues/1#issuecomment-101",
                "body": "some text",
                "createdAt": "2020-01-02T00:00:00Z",
                "lastEditedAt": None,
            }
        target_node["comments"] = connection([c])

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr_node)
        if op == "TargetIssueData":
            return response("issue", target_node)
        raise OSError("unexpected op")

    warnings: list[str] = []
    res = run_scrub(tmp_path, node=target_node, post=post, warnings=warnings)
    assert_denied(res.scrub_entries)


def test_defect3_mixed_case_repository_matching():
    """Regression Defect 3: Assert mixed-case repository variants are blocked for HTML, API and prefix entries while different repositories remain unmatched."""
    entries = [
        {"kind": "pull_request", "match": "exact", "url": "https://github.com/test-org/test-repo/pull/50", "reason": "PR HTML"},
        {"kind": "pull_request", "match": "exact", "url": "https://api.github.com/repos/test-org/test-repo/pulls/50", "reason": "PR API"},
        {"kind": "pull_request_prefix", "match": "prefix", "url": "https://api.github.com/repos/test-org/test-repo/pulls/50/", "reason": "PR API prefix"},
        {"kind": "pull_request_prefix", "match": "prefix", "url": "https://github.com/test-org/test-repo/pull/50/", "reason": "PR HTML prefix"},
    ]

    # HTML mixed-case matches
    assert thread_scrub.matches_any_scrub_entry(entries, "https://github.com/TEST-ORG/TEST-REPO/pull/50")
    assert thread_scrub.matches_any_scrub_entry(entries, "https://github.com/Test-Org/test-repo/pull/50")
    assert thread_scrub.matches_any_scrub_entry(entries, "https://github.com/TEST-org/test-REPO/pull/50")

    # API mixed-case matches
    assert thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/TEST-ORG/TEST-REPO/pulls/50")
    assert thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/Test-Org/test-repo/pulls/50")
    assert thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/TEST-org/test-REPO/pulls/50")

    # Prefix mixed-case matches
    assert thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/TEST-ORG/TEST-REPO/pulls/50/comments")
    assert thread_scrub.matches_any_scrub_entry(entries, "https://github.com/TEST-ORG/TEST-REPO/pull/50/files")

    # Different repositories remain unmatched
    assert not thread_scrub.matches_any_scrub_entry(entries, "https://github.com/other-org/other-repo/pull/50")
    assert not thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/other-org/other-repo/pulls/50")
    assert not thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/other-org/test-repo/pulls/50")
    assert not thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/test-org/other-repo/pulls/50")
    assert not thread_scrub.matches_any_scrub_entry(entries, "https://api.github.com/repos/other-org/other-repo/pulls/50/comments")
    assert not thread_scrub.matches_any_scrub_entry(entries, "https://github.com/other-org/other-repo/pull/50/files")


@pytest.mark.parametrize("secret_id", [
    "SECRET_CANARY_VALUE_SCALAR_12345",
    "abcdef" + "SECRET_CANARY_VALUE_SCALAR_12345" * 10,
    ["safe_token", "SECRET_CANARY_VALUE_LIST_12345"],
    {"token_key": "SECRET_CANARY_VALUE_OBJECT_12345"},
])
def test_defect4_secret_markers_never_in_exceptions_or_cli_output(tmp_path, secret_id, capsys):
    """Regression Defect 4: pass secret markers inside malformed scalar, list and object identifiers; assert their absence from exceptions and captured CLI output."""
    marker = "SECRET_CANARY_VALUE"

    with pytest.raises(IntakeError) as exc_info:
        from hermetic_slice.intake import validate_commit_sha
        validate_commit_sha(secret_id, "merge_commit")
    assert marker not in str(exc_info.value)
    assert marker not in repr(exc_info.value)

    with pytest.raises(thread_scrub.GraphQLResponseError) as exc_info2:
        thread_scrub.get_solution_pr_scrub_entries("test-org/test-repo", 50, commit_shas=[secret_id])
    assert marker not in str(exc_info2.value)
    assert marker not in repr(exc_info2.value)

    row = {
        "repo": REPO,
        "base_commit": "abc",
        "problem_statement": "Statement",
        "hints_text": "Hints",
        "patch": "gold",
        "test_patch": "tests",
    }
    def get(url):
        if "/commits?" in url:
            return b"[]"
        if "/issues/" in url:
            return b'{"created_at":"2020-01-01T00:00:00Z"}'
        data = {"created_at": "2020-02-01T00:00:00Z", "body": "Fixes #1", "merge_commit_sha": secret_id}
        return json.dumps(data).encode()

    def post(url, payload):
        op = payload["operationName"]
        if op == "PullRequestData":
            return response("pullRequest", pr())
        if op == "TargetIssueData":
            return response("issue", issue())
        raise OSError(f"unexpected op: {op}")

    out_dir = tmp_path / "out"
    with patch("hermetic_slice.intake.repo_dates", return_value=(WORLD, WORLD)):
        with pytest.raises(IntakeError) as exc_info3:
            intake_task(
                "test-org__test-repo-50",
                {"test-org__test-repo-50": row},
                get,
                tmp_path / "cache",
                out_dir,
                http_post_json=post,
            )
        assert marker not in str(exc_info3.value)
        assert marker not in repr(exc_info3.value)

    from hermetic_slice import __main__ as cli_main
    tasks_dir = tmp_path / "cli_tasks"
    tasks_dir.mkdir(parents=True)
    cache_dir = tmp_path / "cli_cache"
    cache_dir.mkdir(parents=True)
    verified_file = cache_dir / "swebench_verified.jsonl"
    verified_row = dict(row, instance_id="test-org__test-repo-50")
    verified_file.write_text(json.dumps(verified_row) + "\n", encoding="utf-8")

    capsys.readouterr()
    tasks_file = tmp_path / "tasks.txt"
    tasks_file.write_text("test-org__test-repo-50\n", encoding="utf-8")
    with patch("hermetic_slice.__main__.load_verified", return_value={"test-org__test-repo-50": verified_row}), patch("hermetic_slice.__main__.intake_task", side_effect=exc_info3.value) as mocked_intake:
        assert cli_main.main(["intake", "--tasks", str(tasks_file), "--out", str(tasks_dir), "--cache", str(cache_dir)]) == 1
    mocked_intake.assert_called_once()
    captured = capsys.readouterr()
    assert marker not in captured.err
    assert marker not in captured.out
    assert "Error processing test-org__test-repo-50:" in captured.err


def test_defect5_cumulative_nodes_enforcement_fails_if_cumulative_check_removed(tmp_path):
    """Regression Defect 5: finite responses that individually fit the node budget but collectively exceed it fail on cumulative enforcement."""
    node = issue()
    node["lastEditedAt"] = "2020-01-10T00:00:00Z"
    target_resp = response("issue", node)
    target_resp["data"]["repository"]["issue"]["userContentEdits"] = connection(
        [{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}],
        more=True,
        cursor="page2",
    )
    pr_resp = response("pullRequest", pr())

    n1, _ = thread_scrub._measure_response(pr_resp)
    n2, _ = thread_scrub._measure_response(target_resp)

    budget = max(n1, n2)
    assert n1 <= budget
    assert n2 <= budget
    assert n1 + n2 > budget

    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return deepcopy(pr_resp)
        if op == "TargetIssueData":
            return deepcopy(target_resp)
        if op == "IssueEditsPage":
            return {
                "data": {
                    "repository": {
                        "issue": {
                            "includesCreatedEdit": True,
                            "userContentEdits": connection(
                                [{"editedAt": "2020-01-10T00:00:00Z", "diff": "clean"}],
                                more=False,
                            ),
                        }
                    }
                }
            }
        return response("issue", issue())

    with patch.object(thread_scrub, "MAX_GRAPHQL_NODES", budget):
        result = run_scrub(tmp_path, post=post)

    assert len(calls) == 2
    assert result.problem_statement_revision == "excluded"
    assert LATE not in result.problem_statement + result.hints_text
    assert_denied(result.scrub_entries)


def test_defect5_cumulative_bytes_enforcement_fails_if_cumulative_check_removed(tmp_path):
    """Regression Defect 5: finite responses that individually fit the byte budget but collectively exceed it fail on cumulative enforcement."""
    node = issue()
    node["lastEditedAt"] = "2020-01-10T00:00:00Z"
    target_resp = response("issue", node)
    target_resp["data"]["repository"]["issue"]["userContentEdits"] = connection(
        [{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}],
        more=True,
        cursor="page2",
    )
    pr_resp = response("pullRequest", pr())

    _, s1 = thread_scrub._measure_response(pr_resp)
    _, s2 = thread_scrub._measure_response(target_resp)

    budget = max(s1, s2)
    assert s1 <= budget
    assert s2 <= budget
    assert s1 + s2 > budget

    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return deepcopy(pr_resp)
        if op == "TargetIssueData":
            return deepcopy(target_resp)
        if op == "IssueEditsPage":
            return {
                "data": {
                    "repository": {
                        "issue": {
                            "includesCreatedEdit": True,
                            "userContentEdits": connection(
                                [{"editedAt": "2020-01-10T00:00:00Z", "diff": "clean"}],
                                more=False,
                            ),
                        }
                    }
                }
            }
        return response("issue", issue())

    with patch.object(thread_scrub, "MAX_GRAPHQL_BYTES", budget):
        result = run_scrub(tmp_path, post=post)

    assert len(calls) == 2
    assert result.problem_statement_revision == "excluded"
    assert LATE not in result.problem_statement + result.hints_text
    assert_denied(result.scrub_entries)


def test_defect5_connection_pages_cap_enforces_across_paginated_responses(tmp_path):
    """Regression Defect 5: connection pagination enforces MAX_CONNECTION_PAGES across pages."""
    node = issue()
    node["lastEditedAt"] = "2020-01-10T00:00:00Z"
    target_resp = response("issue", node)
    target_resp["data"]["repository"]["issue"]["userContentEdits"] = connection(
        [{"editedAt": "2020-01-10T00:00:00Z", "diff": LATE}],
        more=True,
        cursor="page2",
    )
    pr_resp = response("pullRequest", pr())

    calls = []
    def post(url, payload):
        op = payload["operationName"]
        calls.append(op)
        if op == "PullRequestData":
            return deepcopy(pr_resp)
        if op == "TargetIssueData":
            return deepcopy(target_resp)
        if op == "IssueEditsPage":
            return {
                "data": {
                    "repository": {
                        "issue": {
                            "includesCreatedEdit": True,
                            "userContentEdits": connection(
                                [{"editedAt": "2020-01-05T00:00:00Z", "diff": "clean"}],
                                more=True,
                                cursor="page3",
                            ),
                        }
                    }
                }
            }
        return response("issue", issue())

    with patch.object(thread_scrub, "MAX_CONNECTION_PAGES", 2):
        result = run_scrub(tmp_path, post=post)

    assert len(calls) == 3
    assert result.problem_statement_revision == "excluded"
    assert LATE not in result.problem_statement + result.hints_text
    assert_denied(result.scrub_entries)



TIMELINE_SUFFIXES = ("timeline", "timeline?per_page=100", "timeline/", "events", "events?page=2&per_page=100", "events/")


@pytest.mark.parametrize("late", [True, False])
@pytest.mark.parametrize("targets", [[1], [1, 2]])
def test_target_issue_timeline_and_events_always_denied(tmp_path, late, targets):
    """Final review #1: the REST timeline/events of every target issue embed late comment
    bodies and cross-referenced PR bodies, so they are denied with or without a late comment."""
    node = issue()
    if late:
        late_c = comment()
        late_c["createdAt"] = "2020-01-20T00:00:00Z"
        node["comments"] = connection([late_c])
    result = run_scrub(tmp_path, node=node, targets=targets)
    entries = result.scrub_entries
    for number in targets:
        for suffix in TIMELINE_SUFFIXES:
            url = f"https://api.github.com/repos/{REPO}/issues/{number}/{suffix}"
            assert thread_scrub.matches_any_scrub_entry(entries, url), url
    # The target issue itself stays servable when nothing else forces denial.
    if not late and targets == [1]:
        assert not thread_scrub.matches_any_scrub_entry(entries, f"https://api.github.com/repos/{REPO}/issues/1")
        assert not thread_scrub.matches_any_scrub_entry(entries, f"https://api.github.com/repos/{REPO}/issues/3/timeline")


def test_cross_referenced_issue_and_pr_timelines_denied(tmp_path):
    """Final review #1: timeline/events of every referencing issue or PR are denied."""
    node = issue()
    node["timelineItems"] = connection([
        {"__typename": "CrossReferencedEvent", "url": None,
         "source": {"__typename": "PullRequest", "url": "https://github.com/other-org/other-repo/pull/77"}},
        {"__typename": "CrossReferencedEvent", "url": None,
         "source": {"__typename": "Issue", "url": f"https://github.com/{REPO}/issues/88"}},
    ])
    entries = run_scrub(tmp_path, node=node).scrub_entries
    for base in (f"https://api.github.com/repos/{REPO}/issues/1",
                 "https://api.github.com/repos/other-org/other-repo/issues/77",
                 f"https://api.github.com/repos/{REPO}/issues/88",
                 f"https://api.github.com/repos/{REPO}/issues/50"):
        for suffix in TIMELINE_SUFFIXES:
            assert thread_scrub.matches_any_scrub_entry(entries, f"{base}/{suffix}"), f"{base}/{suffix}"
    for helper, num in ((thread_scrub.get_referencing_pr_scrub_entries, 77),
                        (thread_scrub.get_referencing_issue_scrub_entries, 77),
                        (thread_scrub.get_solution_pr_scrub_entries, 77)):
        urls = {e.url for e in helper("o/r", num)}
        for kind in ("timeline", "events"):
            assert f"https://api.github.com/repos/o/r/issues/{num}/{kind}" in urls
            assert f"https://api.github.com/repos/o/r/issues/{num}/{kind}/" in urls


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/o/r/pulls/49/../50",
    "https://api.github.com/repos/o/r/pulls/%2E%2E/pulls/50",
    "https://api.github.com/repos/o/r/pulls/%2e%2E/pulls/50/files",
    "https://api.github.com/repos/o/r/pulls/./50",
    "https://api.github.com/repos/o/r/pulls/%2E/50/",
    "https://api.github.com/repos/o/r/x/y/../../pulls/50/comments",
    "https://api.github.com/repos/o/r/pulls/49/%2E%2E/50/reviews?per_page=1",
    "https://api.github.com/repos/x/y/../../o/r/issues/50",
    "https://github.com/o/r/pull/49/../50",
    "https://github.com/o/r/pull/%2E%2E/pull/50.diff",
    "https://github.com/o/r/pull/50/x/..",
    "https://api.github.com/repos/o/r/pulls/50/%2E%2E/50",
])
def test_dot_segments_are_removed_before_matching(url):
    """Final review #2: raw and encoded dot segments resolve before exact and prefix matching."""
    entries = thread_scrub.get_solution_pr_scrub_entries("o/r", 50)
    assert thread_scrub.matches_any_scrub_entry(entries, url)


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/o/r/pulls/%2E%2E/pulls/51",
    "https://api.github.com/repos/o/r/pulls/49/../51",
    "https://api.github.com/repos/o/r/x/../../r2/pulls/50",
])
def test_dot_segment_removal_does_not_overblock(url):
    entries = thread_scrub.get_solution_pr_scrub_entries("o/r", 50)
    assert not thread_scrub.matches_any_scrub_entry(entries, url)


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/o/r/pulls%2F50",
    "https://api.github.com/repos/o/r/pulls%2f50",
    "https://api.github.com/repos/o/r/pulls/51%2F..%2F50",
    "https://api.github.com/repos/o/r/pulls/51%5C..%5C50",
    "https://api.github.com/repos/unrelated%2Frepo/issues/9",
])
def test_encoded_slashes_are_rejected_consistently(url):
    """Encoded path separators cannot be canonicalised safely: controlled rejection (blocked)."""
    assert thread_scrub._canonicalize_url(url) is None
    assert thread_scrub.matches_any_scrub_entry(thread_scrub.get_solution_pr_scrub_entries("o/r", 50), url)


def test_dot_segment_helper_follows_rfc3986():
    rds = thread_scrub._remove_dot_segments
    assert rds("/a/b/c/./../../g") == "/a/g"
    assert rds("mid/content=5/../6") == "mid/6"
    assert rds("/../a") == "/a"
    assert rds("/a/..") == "/"
    assert rds("/a/.") == "/a/"
    assert rds("/a/b/") == "/a/b/"
