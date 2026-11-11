"""Mutable-content rule and target-thread scrub (TR-SEAL-9, spec §4).

This module implements:
1. Mutable-content revision rule:
   - Fetches edit histories for target issues and comments via GitHub GraphQL API.
   - Replaces scraped problem statement body with the newest revision dated at or before T_world.
   - Revisions hints: filters comments to those created at or before T_world, taking each
     at its revision as of T_world.
   - Records metadata: problem_statement_revision (as_scraped | revision_at_t_world | first_revision),
     the chosen revision's editedAt, number of edits ignored, and hints_revisioned.
2. Target-thread scrub list:
   - Discovers all resources that must not be served by the frozen world:
     * Target issue comments created after T_world (by ID and HTML URL)
     * Solution PR (HTML URL, API URL, /files, /commits, .diff, .patch, URL prefixes)
     * Solution PR reviews and review comments (IDs and URLs)
     * Any issue or PR that links to or references the target issue
   - Emits staging/thread_scrub.json sorted and de-duplicated.

Assumption note on userContentEdits:
In GitHub's GraphQL API, userContentEdits lists full revisions newest first. Although named diff,
the diff field in practice contains the complete snapshot of the body text for that revision, not an
incremental diff. This module treats diff as the full revision text.

Titles note:
Titles have their own edit history (TitleEdit). Per specification, titles are not revision-checked
and are kept as scraped.

Schema of staging/thread_scrub.json:
A JSON array of scrub entries sorted deterministically by (url, kind, reason):
[
  {
    "kind": "<kind>",
    "reason": "<reason>",
    "url": "<url>"
  },
  ...
]

Entry fields:
- kind (str): Category of scrubbed resource:
    * "pull_request": Solution PR HTML/API views (/files, /commits, .diff, .patch)
    * "pull_request_prefix": URL prefixes covering all sub-pages of the solution PR
    * "review": Solution PR review
    * "review_comment": Solution PR review comment
    * "comment": Target issue discussion comment created after T_world
    * "cross_reference": Issue, PR, or timeline event that links to the target issue
- reason (str): Human-readable explanation of why this resource must not be served.
- url (str): Exact URL or URL prefix blocked.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.http import HttpError, HttpPostJson, make_http_post_json

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


class GraphQLResponseError(Exception):
    """Raised when a GraphQL query returns errors or malformed data."""


@dataclass(frozen=True)
class ScrubEntry:
    kind: str
    url: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "reason": self.reason,
            "url": self.url,
        }


@dataclass(frozen=True)
class RevisionResult:
    body: str
    revision_type: str  # "as_scraped" | "revision_at_t_world" | "first_revision"
    edited_at: str | None
    edits_ignored: int


@dataclass
class ScrubResult:
    problem_statement: str
    hints_text: str
    problem_statement_revision: str
    chosen_revision_edited_at: str | None
    edits_ignored: int
    hints_revisioned: bool
    scrub_entries: list[dict[str, str]]


def iso_utc(dt: datetime) -> str:
    """Format datetime as UTC ISO 8601 string ending with Z."""
    utc_dt = ensure_utc(dt, "dt")
    if utc_dt.microsecond:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(dt_str: str | None) -> datetime | None:
    """Parse ISO 8601 string into a UTC timezone-aware datetime."""
    if not dt_str:
        return None
    s = dt_str
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return ensure_utc(dt, "parse_iso")
    except Exception:
        return None


def split_title_and_body(problem_statement: str) -> tuple[str, str]:
    """Split SWE-bench problem statement into title and body.
    
    Titles are not revision-checked per specification §4 and are kept as scraped.
    """
    if "\n" in problem_statement:
        title, body = problem_statement.split("\n", 1)
        return title, body
    return problem_statement, ""


def reconstruct_problem_statement(title: str, body: str) -> str:
    """Reconstruct problem statement from title and revised body."""
    if body:
        return f"{title}\n{body}"
    return title


def select_revision(
    scraped_body: str,
    created_at: datetime | None,
    last_edited_at: datetime | None,
    user_content_edits: list[dict[str, Any]],
    t_world: datetime,
    is_target_issue: bool = False,
) -> RevisionResult:
    """Select the appropriate revision of a mutable document as of T_world.

    Rules (§4):
    - If lastEditedAt is null, scraped content was never edited: unchanged.
    - If T_world is earlier than issue's creation (for target issue), take the first revision.
    - Otherwise, newest revision with editedAt <= T_world.
    - If none qualifies and created_at <= T_world, take the first revision (the oldest edit).
    """
    if last_edited_at is None or not user_content_edits:
        return RevisionResult(
            body=scraped_body,
            revision_type="as_scraped",
            edited_at=None,
            edits_ignored=0,
        )

    # userContentEdits is newest first
    if is_target_issue and created_at is not None and t_world < created_at:
        first_rev = user_content_edits[-1]
        chosen_body = first_rev.get("diff") if first_rev.get("diff") is not None else first_rev.get("body", scraped_body)
        rev_dt = parse_iso(first_rev.get("editedAt") or first_rev.get("createdAt"))
        return RevisionResult(
            body=chosen_body,
            revision_type="first_revision",
            edited_at=iso_utc(rev_dt) if rev_dt else None,
            edits_ignored=len(user_content_edits) - 1,
        )

    for idx, edit in enumerate(user_content_edits):
        edit_dt = parse_iso(edit.get("editedAt") or edit.get("createdAt"))
        if edit_dt and edit_dt <= t_world:
            chosen_body = edit.get("diff") if edit.get("diff") is not None else edit.get("body", scraped_body)
            return RevisionResult(
                body=chosen_body,
                revision_type="revision_at_t_world",
                edited_at=iso_utc(edit_dt),
                edits_ignored=idx,
            )

    # None qualified: take oldest revision (first revision)
    first_rev = user_content_edits[-1]
    chosen_body = first_rev.get("diff") if first_rev.get("diff") is not None else first_rev.get("body", scraped_body)
    rev_dt = parse_iso(first_rev.get("editedAt") or first_rev.get("createdAt"))
    return RevisionResult(
        body=chosen_body,
        revision_type="first_revision",
        edited_at=iso_utc(rev_dt) if rev_dt else None,
        edits_ignored=len(user_content_edits) - 1,
    )


# ---------------------------------------------------------------------------
# GraphQL Queries
# ---------------------------------------------------------------------------

TARGET_ISSUE_QUERY = """
query TargetIssueData(
  $owner: String!
  $repo: String!
  $number: Int!
  $editsCursor: String
  $commentsCursor: String
  $timelineCursor: String
) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      id
      databaseId
      url
      body
      createdAt
      lastEditedAt
      userContentEdits(first: 100, after: $editsCursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          createdAt
          editedAt
          diff
        }
      }
      comments(first: 100, after: $commentsCursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          databaseId
          url
          body
          createdAt
          lastEditedAt
          userContentEdits(first: 100) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              createdAt
              editedAt
              diff
            }
          }
        }
      }
      timelineItems(first: 100, after: $timelineCursor, itemTypes: [CROSS_REFERENCED_EVENT, CONNECTED_EVENT]) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          __typename
          ... on CrossReferencedEvent {
            url
            source {
              __typename
              ... on Issue {
                number
                url
              }
              ... on PullRequest {
                number
                url
              }
            }
          }
          ... on ConnectedEvent {
            subject {
              __typename
              ... on Issue {
                number
                url
              }
              ... on PullRequest {
                number
                url
              }
            }
          }
        }
      }
    }
  }
}
"""

ISSUE_EDITS_PAGE_QUERY = """
query IssueEditsPage($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      userContentEdits(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          createdAt
          editedAt
          diff
        }
      }
    }
  }
}
"""

ISSUE_COMMENTS_PAGE_QUERY = """
query IssueCommentsPage($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      comments(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          databaseId
          url
          body
          createdAt
          lastEditedAt
          userContentEdits(first: 100) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              createdAt
              editedAt
              diff
            }
          }
        }
      }
    }
  }
}
"""

ISSUE_TIMELINE_PAGE_QUERY = """
query IssueTimelinePage($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      timelineItems(first: 100, after: $cursor, itemTypes: [CROSS_REFERENCED_EVENT, CONNECTED_EVENT]) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          __typename
          ... on CrossReferencedEvent {
            url
            source {
              __typename
              ... on Issue {
                number
                url
              }
              ... on PullRequest {
                number
                url
              }
            }
          }
          ... on ConnectedEvent {
            subject {
              __typename
              ... on Issue {
                number
                url
              }
              ... on PullRequest {
                number
                url
              }
            }
          }
        }
      }
    }
  }
}
"""

PULL_REQUEST_QUERY = """
query PullRequestData($owner: String!, $repo: String!, $number: Int!, $reviewsCursor: String, $threadsCursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      id
      databaseId
      url
      reviews(first: 100, after: $reviewsCursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          databaseId
          url
        }
      }
      reviewThreads(first: 100, after: $threadsCursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          comments(first: 100) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              id
              databaseId
              url
            }
          }
        }
      }
    }
  }
}
"""

PR_REVIEWS_PAGE_QUERY = """
query PullRequestReviewsPage($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      reviews(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          databaseId
          url
        }
      }
    }
  }
}
"""

PR_THREADS_PAGE_QUERY = """
query PullRequestThreadsPage($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          comments(first: 100) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              id
              databaseId
              url
            }
          }
        }
      }
    }
  }
}
"""


def _post_graphql(http_post_json: HttpPostJson, query: str, variables: dict[str, Any], operation_name: str) -> dict[str, Any]:
    """Execute a GraphQL query, checking for errors array and malformed structure."""
    payload = {
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    }
    resp = http_post_json(GITHUB_GRAPHQL_URL, payload)
    if isinstance(resp, (bytes, bytearray)):
        resp = json.loads(resp.decode("utf-8"))

    if not isinstance(resp, dict):
        raise GraphQLResponseError(f"Expected dict response from GraphQL, got {type(resp).__name__}")

    errors = resp.get("errors")
    if errors:
        raise GraphQLResponseError(f"GraphQL errors: {errors}")

    data = resp.get("data")
    if data is None:
        raise GraphQLResponseError("GraphQL response missing 'data' field")

    repo_obj = data.get("repository")
    if repo_obj is None:
        raise GraphQLResponseError(f"GraphQL repository not found for variables: {variables}")

    return data


def fetch_target_issue_data(http_post_json: HttpPostJson, owner: str, name: str, issue_number: int) -> dict[str, Any]:
    """Fetch complete issue data with pagination for edits, comments, and timeline items."""
    vars_main = {"owner": owner, "repo": name, "number": issue_number}
    data = _post_graphql(http_post_json, TARGET_ISSUE_QUERY, vars_main, "TargetIssueData")
    issue = data["repository"].get("issue")
    if not issue:
        raise GraphQLResponseError(f"Issue #{issue_number} not found in {owner}/{name}")

    # Paginate issue userContentEdits if needed
    edits_field = issue.get("userContentEdits") or {}
    edits_nodes = list(edits_field.get("nodes") or [])
    page_info = edits_field.get("pageInfo") or {}
    while page_info.get("hasNextPage") and page_info.get("endCursor"):
        cursor = page_info["endCursor"]
        pdata = _post_graphql(
            http_post_json,
            ISSUE_EDITS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": issue_number, "cursor": cursor},
            "IssueEditsPage",
        )
        p_issue = pdata["repository"]["issue"]
        p_edits = p_issue.get("userContentEdits") or {}
        edits_nodes.extend(p_edits.get("nodes") or [])
        page_info = p_edits.get("pageInfo") or {}
    if "userContentEdits" in issue:
        issue["userContentEdits"]["nodes"] = edits_nodes

    # Paginate comments if needed
    comments_field = issue.get("comments") or {}
    comments_nodes = list(comments_field.get("nodes") or [])
    c_page_info = comments_field.get("pageInfo") or {}
    while c_page_info.get("hasNextPage") and c_page_info.get("endCursor"):
        cursor = c_page_info["endCursor"]
        pdata = _post_graphql(
            http_post_json,
            ISSUE_COMMENTS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": issue_number, "cursor": cursor},
            "IssueCommentsPage",
        )
        p_issue = pdata["repository"]["issue"]
        p_comments = p_issue.get("comments") or {}
        comments_nodes.extend(p_comments.get("nodes") or [])
        c_page_info = p_comments.get("pageInfo") or {}
    if "comments" in issue:
        issue["comments"]["nodes"] = comments_nodes

    # Paginate timeline items if needed
    timeline_field = issue.get("timelineItems") or {}
    timeline_nodes = list(timeline_field.get("nodes") or [])
    t_page_info = timeline_field.get("pageInfo") or {}
    while t_page_info.get("hasNextPage") and t_page_info.get("endCursor"):
        cursor = t_page_info["endCursor"]
        pdata = _post_graphql(
            http_post_json,
            ISSUE_TIMELINE_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": issue_number, "cursor": cursor},
            "IssueTimelinePage",
        )
        p_issue = pdata["repository"]["issue"]
        p_timeline = p_issue.get("timelineItems") or {}
        timeline_nodes.extend(p_timeline.get("nodes") or [])
        t_page_info = p_timeline.get("pageInfo") or {}
    if "timelineItems" in issue:
        issue["timelineItems"]["nodes"] = timeline_nodes

    return issue


def fetch_pull_request_data(http_post_json: HttpPostJson, owner: str, name: str, pr_number: int) -> dict[str, Any]:
    """Fetch pull request reviews and review comment threads with pagination."""
    vars_main = {"owner": owner, "repo": name, "number": pr_number}
    data = _post_graphql(http_post_json, PULL_REQUEST_QUERY, vars_main, "PullRequestData")
    pr = data["repository"].get("pullRequest")
    if not pr:
        raise GraphQLResponseError(f"Pull request #{pr_number} not found in {owner}/{name}")

    # Paginate reviews
    reviews_field = pr.get("reviews") or {}
    reviews_nodes = list(reviews_field.get("nodes") or [])
    r_page_info = reviews_field.get("pageInfo") or {}
    while r_page_info.get("hasNextPage") and r_page_info.get("endCursor"):
        cursor = r_page_info["endCursor"]
        pdata = _post_graphql(
            http_post_json,
            PR_REVIEWS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": pr_number, "cursor": cursor},
            "PullRequestReviewsPage",
        )
        p_pr = pdata["repository"]["pullRequest"]
        p_reviews = p_pr.get("reviews") or {}
        reviews_nodes.extend(p_reviews.get("nodes") or [])
        r_page_info = p_reviews.get("pageInfo") or {}
    if "reviews" in pr:
        pr["reviews"]["nodes"] = reviews_nodes

    # Paginate review threads
    threads_field = pr.get("reviewThreads") or {}
    threads_nodes = list(threads_field.get("nodes") or [])
    t_page_info = threads_field.get("pageInfo") or {}
    while t_page_info.get("hasNextPage") and t_page_info.get("endCursor"):
        cursor = t_page_info["endCursor"]
        pdata = _post_graphql(
            http_post_json,
            PR_THREADS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": pr_number, "cursor": cursor},
            "PullRequestThreadsPage",
        )
        p_pr = pdata["repository"]["pullRequest"]
        p_threads = p_pr.get("reviewThreads") or {}
        threads_nodes.extend(p_threads.get("nodes") or [])
        t_page_info = p_threads.get("pageInfo") or {}
    if "reviewThreads" in pr:
        pr["reviewThreads"]["nodes"] = threads_nodes

    return pr


def get_solution_pr_scrub_entries(repo: str, pr_number: int) -> list[ScrubEntry]:
    """Generate static scrub entries for the solution PR itself, its sub-views, and prefixes."""
    entries: list[ScrubEntry] = [
        ScrubEntry(kind="pull_request", url=f"https://github.com/{repo}/pull/{pr_number}", reason="solution PR HTML URL"),
        ScrubEntry(kind="pull_request", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}", reason="solution PR API URL"),
        ScrubEntry(kind="pull_request", url=f"https://github.com/{repo}/pull/{pr_number}/files", reason="solution PR files view"),
        ScrubEntry(kind="pull_request", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files", reason="solution PR files API"),
        ScrubEntry(kind="pull_request", url=f"https://github.com/{repo}/pull/{pr_number}/commits", reason="solution PR commits view"),
        ScrubEntry(kind="pull_request", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/commits", reason="solution PR commits API"),
        ScrubEntry(kind="pull_request", url=f"https://github.com/{repo}/pull/{pr_number}.diff", reason="solution PR diff"),
        ScrubEntry(kind="pull_request", url=f"https://github.com/{repo}/pull/{pr_number}.patch", reason="solution PR patch"),
        ScrubEntry(kind="pull_request_prefix", url=f"https://github.com/{repo}/pull/{pr_number}", reason="solution PR URL prefix"),
        ScrubEntry(kind="pull_request_prefix", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}", reason="solution PR API URL prefix"),
    ]
    return entries


def dedupe_and_sort_entries(entries: list[ScrubEntry]) -> list[dict[str, str]]:
    """Deduplicate entries and sort deterministically by (url, kind, reason)."""
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, str]] = []
    for entry in entries:
        if not entry.url:
            continue
        key = (entry.url, entry.kind, entry.reason)
        if key not in seen:
            seen.add(key)
            result.append(entry.to_dict())

    result.sort(key=lambda d: (d["url"], d["kind"], d["reason"]))
    return result


def process_thread_scrub_and_revision(
    *,
    repo: str,
    pr_number: int,
    target_issue_number: int | None,
    target_issue_created: datetime | None,
    t_world: datetime,
    scraped_problem_statement: str,
    scraped_hints: str,
    token: str | None,
    http_post_json: HttpPostJson | None,
    cache_dir: Path,
    warnings_list: list[str],
) -> ScrubResult:
    """Perform mutable-content revisioning and thread-scrub list generation.

    If token is not configured, or if GraphQL returns errors/malformed responses,
    falls back cleanly to scraped content and records warnings, never crashing.
    """
    owner, name = repo.split("/", 1)
    base_entries = get_solution_pr_scrub_entries(repo, pr_number)

    # Fallback state if token missing or query fails
    def make_fallback(warning_msg: str | None = None) -> ScrubResult:
        if warning_msg:
            warnings_list.append(warning_msg)
        warnings_list.append("problem_statement taken as scraped, not at its revision as of T_world (Phase 0 gap, spec section 4)")
        return ScrubResult(
            problem_statement=scraped_problem_statement,
            hints_text=scraped_hints,
            problem_statement_revision="as_scraped",
            chosen_revision_edited_at=None,
            edits_ignored=0,
            hints_revisioned=False,
            scrub_entries=dedupe_and_sort_entries(base_entries),
        )

    if not token and http_post_json is None:
        return make_fallback()

    post_client = http_post_json if http_post_json is not None else make_http_post_json(cache_dir, token=token)

    # 1. Fetch Pull Request scrub items (reviews, review comments)
    pr_entries: list[ScrubEntry] = list(base_entries)
    try:
        pr_data = fetch_pull_request_data(post_client, owner, name, pr_number)
        for review in pr_data.get("reviews", {}).get("nodes", []):
            rev_url = review.get("url")
            rev_id = review.get("databaseId")
            if not rev_id and rev_url:
                m = re.search(r"#pullrequestreview-(\d+)", rev_url)
                if m:
                    rev_id = m.group(1)
            if rev_url:
                pr_entries.append(ScrubEntry(kind="review", url=rev_url, reason="solution PR review"))
            if rev_id:
                pr_entries.append(ScrubEntry(
                    kind="review",
                    url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews/{rev_id}",
                    reason="solution PR review",
                ))

        for thread in pr_data.get("reviewThreads", {}).get("nodes", []):
            for rc in thread.get("comments", {}).get("nodes", []):
                rc_url = rc.get("url")
                rc_id = rc.get("databaseId")
                if not rc_id and rc_url:
                    m = re.search(r"#discussion_r(\d+)", rc_url)
                    if m:
                        rc_id = m.group(1)
                if rc_url:
                    pr_entries.append(ScrubEntry(kind="review_comment", url=rc_url, reason="solution PR review comment"))
                if rc_id:
                    pr_entries.append(ScrubEntry(
                        kind="review_comment",
                        url=f"https://api.github.com/repos/{repo}/pulls/comments/{rc_id}",
                        reason="solution PR review comment",
                    ))
    except Exception as exc:
        warnings_list.append(f"Failed fetching PR scrub details via GraphQL ({exc}); using static PR endpoints")

    if target_issue_number is None:
        # No target GitHub issue to revision
        return ScrubResult(
            problem_statement=scraped_problem_statement,
            hints_text=scraped_hints,
            problem_statement_revision="as_scraped",
            chosen_revision_edited_at=None,
            edits_ignored=0,
            hints_revisioned=False,
            scrub_entries=dedupe_and_sort_entries(pr_entries),
        )

    # 2. Fetch Target Issue data
    try:
        issue_data = fetch_target_issue_data(post_client, owner, name, target_issue_number)
    except Exception as exc:
        return make_fallback(f"GraphQL request for issue #{target_issue_number} failed ({exc}); falling back to scraped content")

    # 3. Revision target issue problem statement
    title, body_scraped = split_title_and_body(scraped_problem_statement)
    issue_created = parse_iso(issue_data.get("createdAt")) or target_issue_created
    last_edited = parse_iso(issue_data.get("lastEditedAt"))
    user_edits = list(issue_data.get("userContentEdits", {}).get("nodes") or [])

    rev_res = select_revision(
        scraped_body=body_scraped,
        created_at=issue_created,
        last_edited_at=last_edited,
        user_content_edits=user_edits,
        t_world=t_world,
        is_target_issue=True,
    )
    final_problem_statement = reconstruct_problem_statement(title, rev_res.body)

    # 4. Revision hints & target issue comments scrub
    comments_nodes = list(issue_data.get("comments", {}).get("nodes") or [])
    kept_comments_bodies: list[str] = []
    all_entries = list(pr_entries)

    for comment in comments_nodes:
        c_created = parse_iso(comment.get("createdAt"))
        c_last_edited = parse_iso(comment.get("lastEditedAt"))
        c_url = comment.get("url")
        c_db_id = comment.get("databaseId")
        if not c_db_id and c_url:
            m = re.search(r"#issuecomment-(\d+)", c_url)
            if m:
                c_db_id = m.group(1)

        if c_created and c_created > t_world:
            # Drop from hints; add to thread_scrub list
            if c_url:
                all_entries.append(ScrubEntry(kind="comment", url=c_url, reason="target issue comment created after T_world"))
            if c_db_id:
                all_entries.append(ScrubEntry(
                    kind="comment",
                    url=f"https://api.github.com/repos/{repo}/issues/comments/{c_db_id}",
                    reason="target issue comment created after T_world",
                ))
        else:
            # Kept comment: take at revision as of T_world
            c_edits = list(comment.get("userContentEdits", {}).get("nodes") or [])
            c_rev = select_revision(
                scraped_body=comment.get("body") or "",
                created_at=c_created,
                last_edited_at=c_last_edited,
                user_content_edits=c_edits,
                t_world=t_world,
                is_target_issue=False,
            )
            kept_comments_bodies.append(c_rev.body)

    final_hints = "\n".join(kept_comments_bodies) if kept_comments_bodies else ""

    # 5. Scrub timeline items linking to target issue
    for item in issue_data.get("timelineItems", {}).get("nodes") or []:
        typename = item.get("__typename")
        if typename == "CrossReferencedEvent":
            src = item.get("source") or {}
            src_url = src.get("url")
            src_num = src.get("number")
            src_type = src.get("__typename")
            if src_url:
                all_entries.append(ScrubEntry(kind="cross_reference", url=src_url, reason="cross-references target issue"))
            if src_num:
                sub = "pulls" if src_type == "PullRequest" else "issues"
                all_entries.append(ScrubEntry(
                    kind="cross_reference",
                    url=f"https://api.github.com/repos/{repo}/{sub}/{src_num}",
                    reason="cross-references target issue",
                ))
            if item.get("url"):
                all_entries.append(ScrubEntry(kind="cross_reference", url=item["url"], reason="cross-reference event on target issue"))
        elif typename == "ConnectedEvent":
            subj = item.get("subject") or {}
            subj_url = subj.get("url")
            subj_num = subj.get("number")
            subj_type = subj.get("__typename")
            if subj_url:
                all_entries.append(ScrubEntry(kind="cross_reference", url=subj_url, reason="connected to target issue"))
            if subj_num:
                sub = "pulls" if subj_type == "PullRequest" else "issues"
                all_entries.append(ScrubEntry(
                    kind="cross_reference",
                    url=f"https://api.github.com/repos/{repo}/{sub}/{subj_num}",
                    reason="connected to target issue",
                ))

    # 6. linked_refs parser applied the other way where cheap
    from hermetic_slice.intake import linked_refs

    text_corpus = [issue_data.get("body") or ""] + [c.get("body") or "" for c in comments_nodes]
    for text_sample in text_corpus:
        for ref in linked_refs(repo, "", text_sample):
            if ref.number != target_issue_number:
                if ref.kind == "github":
                    all_entries.append(ScrubEntry(
                        kind="cross_reference",
                        url=f"https://github.com/{repo}/issues/{ref.number}",
                        reason="referenced in target issue discussion",
                    ))
                    all_entries.append(ScrubEntry(
                        kind="cross_reference",
                        url=f"https://api.github.com/repos/{repo}/issues/{ref.number}",
                        reason="referenced in target issue discussion",
                    ))

    sorted_scrub_entries = dedupe_and_sort_entries(all_entries)

    return ScrubResult(
        problem_statement=final_problem_statement,
        hints_text=final_hints,
        problem_statement_revision=rev_res.revision_type,
        chosen_revision_edited_at=rev_res.edited_at,
        edits_ignored=rev_res.edits_ignored,
        hints_revisioned=True,
        scrub_entries=sorted_scrub_entries,
    )
