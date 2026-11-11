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
A JSON array of scrub entries sorted deterministically by (url, kind, match, reason):
[
  {
    "kind": "<kind>",
    "match": "<match>",
    "reason": "<reason>",
    "url": "<url>"
  },
  ...
]

Matching semantics:
- "exact": The requested URL must match `url` exactly.
- "prefix": The requested URL must start with `url` as a prefix. Every prefix entry ends with a
  trailing delimiter (e.g. '/') to prevent prefix collisions such as '/pull/12' matching '/pull/120'.
  Sub-paths like '.diff' and '.patch' are listed with explicit 'exact' match entries.

Entry fields:
- kind (str): Category of scrubbed resource:
    * "pull_request": Solution PR HTML/API views (/files, /commits, .diff, .patch)
    * "pull_request_prefix": URL prefixes covering all sub-pages of the solution PR
    * "commit": Solution PR commits or merge commit HTML/API/diff/patch
    * "review": Solution PR review
    * "review_comment": Solution PR review comment
    * "comment": Target issue discussion comment created after T_world or PR conversation comment
    * "cross_reference": Issue, PR, or timeline event that links to the target issue
    * "cross_reference_prefix": URL prefixes covering sub-pages of a referencing PR
- match (str): Matching semantics ("exact" or "prefix").
- reason (str): Human-readable explanation of why this resource must not be served.
- url (str): Exact URL or URL prefix blocked.
"""

from __future__ import annotations

from collections.abc import Sequence
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
    match: str = "exact"  # "exact" | "prefix"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "match": self.match,
            "reason": self.reason,
            "url": self.url,
        }


@dataclass(frozen=True)
class RevisionResult:
    body: str
    revision_type: str  # "as_scraped" | "revision_at_t_world" | "first_revision"
    edited_at: str | None
    edits_ignored: int
    warning: str | None = None


@dataclass
class ScrubResult:
    problem_statement: str
    hints_text: str
    problem_statement_revision: str
    chosen_revision_edited_at: str | None
    edits_ignored: int
    hints_revisioned: bool
    scrub_entries: list[dict[str, str]]
    hints_excluded_no_history: int = 0
    hints_excluded_no_created_at: int = 0


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
    includes_created_edit: bool | None = None,
) -> RevisionResult:
    """Select the appropriate revision of a mutable document as of T_world.

    Rules (§4):
    - If lastEditedAt is null, scraped content was never edited: unchanged.
    - If T_world is earlier than issue's creation (for target issue), take the first revision.
    - Otherwise, newest revision with editedAt <= T_world.
    - If none qualifies and created_at <= T_world, take the first revision (the oldest edit).
    - If history is missing or incomplete, fall back to scraped text with an explicit warning.
    """
    if last_edited_at is None:
        return RevisionResult(
            body=scraped_body,
            revision_type="as_scraped",
            edited_at=None,
            edits_ignored=0,
        )

    if not user_content_edits:
        return RevisionResult(
            body=scraped_body,
            revision_type="as_scraped",
            edited_at=None,
            edits_ignored=0,
            warning="document was edited but userContentEdits is missing or empty; fell back to scraped body",
        )

    # userContentEdits is newest first
    if is_target_issue and created_at is not None and t_world < created_at:
        if includes_created_edit is not True:
            return RevisionResult(
                body=scraped_body,
                revision_type="as_scraped",
                edited_at=None,
                edits_ignored=0,
                warning="edit history does not include creation edit (includesCreatedEdit is false / not true); fell back to scraped body",
            )
        first_rev = user_content_edits[-1]
        diff_val = first_rev.get("diff")
        body_val = first_rev.get("body")
        if diff_val is None and body_val is None:
            return RevisionResult(
                body=scraped_body,
                revision_type="as_scraped",
                edited_at=None,
                edits_ignored=0,
                warning="historical revision diff is null; fell back to scraped body",
            )
        chosen_body = diff_val if diff_val is not None else body_val
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
            diff_val = edit.get("diff")
            body_val = edit.get("body")
            if diff_val is None and body_val is None:
                return RevisionResult(
                    body=scraped_body,
                    revision_type="as_scraped",
                    edited_at=None,
                    edits_ignored=0,
                    warning="historical revision diff is null; fell back to scraped body",
                )
            chosen_body = diff_val if diff_val is not None else body_val
            return RevisionResult(
                body=chosen_body,
                revision_type="revision_at_t_world",
                edited_at=iso_utc(edit_dt),
                edits_ignored=idx,
            )

    # None qualified: take oldest revision (first revision) only if history confirms creation edit
    if includes_created_edit is not True:
        return RevisionResult(
            body=scraped_body,
            revision_type="as_scraped",
            edited_at=None,
            edits_ignored=0,
            warning="no qualifying edit before T_world and history does not include creation edit (includesCreatedEdit is false / not true); fell back to scraped body",
        )

    first_rev = user_content_edits[-1]
    diff_val = first_rev.get("diff")
    body_val = first_rev.get("body")
    if diff_val is None and body_val is None:
        return RevisionResult(
            body=scraped_body,
            revision_type="as_scraped",
            edited_at=None,
            edits_ignored=0,
            warning="historical revision diff is null; fell back to scraped body",
        )
    chosen_body = diff_val if diff_val is not None else body_val
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
      includesCreatedEdit
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
          includesCreatedEdit
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
      includesCreatedEdit
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
          includesCreatedEdit
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

COMMENT_EDITS_PAGE_QUERY = """
query CommentEditsPage($id: ID!, $cursor: String!) {
  node(id: $id) {
    ... on Comment {
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

PULL_REQUEST_QUERY = """
query PullRequestData($owner: String!, $repo: String!, $number: Int!, $reviewsCursor: String, $threadsCursor: String, $commentsCursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      id
      databaseId
      url
      comments(first: 100, after: $commentsCursor) {
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
          id
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

PR_COMMENTS_PAGE_QUERY = """
query PullRequestCommentsPage($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      comments(first: 100, after: $cursor) {
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
          id
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

PR_THREAD_COMMENTS_PAGE_QUERY = """
query PullRequestReviewThreadCommentsPage($id: ID!, $cursor: String!) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      comments(first: 100, after: $cursor) {
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

    return data


def fetch_target_issue_data(http_post_json: HttpPostJson, owner: str, name: str, issue_number: int) -> dict[str, Any]:
    """Fetch complete issue data with pagination for edits, comments, and timeline items."""
    vars_main = {"owner": owner, "repo": name, "number": issue_number}
    data = _post_graphql(http_post_json, TARGET_ISSUE_QUERY, vars_main, "TargetIssueData")
    repo = data.get("repository")
    if repo is None:
        raise GraphQLResponseError(f"GraphQL repository not found for variables: {vars_main}")
    issue = repo.get("issue")
    if not issue:
        raise GraphQLResponseError(f"Issue #{issue_number} not found in {owner}/{name}")

    # Normalize nullable connections
    for field in ("userContentEdits", "comments", "timelineItems"):
        if issue.get(field) is None:
            issue[field] = {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}

    # Paginate issue userContentEdits if needed
    edits_field = issue.get("userContentEdits") or {}
    edits_nodes = list(edits_field.get("nodes") or [])
    page_info = edits_field.get("pageInfo") or {}
    while page_info.get("hasNextPage"):
        cursor = page_info.get("endCursor")
        if not cursor:
            raise GraphQLResponseError(f"Issue #{issue_number} userContentEdits hasNextPage is true but endCursor is missing")
        pdata = _post_graphql(
            http_post_json,
            ISSUE_EDITS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": issue_number, "cursor": cursor},
            "IssueEditsPage",
        )
        repo_obj = pdata.get("repository")
        if not isinstance(repo_obj, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} userContentEdits page missing repository")
        p_issue = repo_obj.get("issue")
        if not isinstance(p_issue, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} userContentEdits page missing issue")
        p_edits = p_issue.get("userContentEdits")
        if not isinstance(p_edits, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} userContentEdits page missing userContentEdits")
        page_info = p_edits.get("pageInfo")
        if not isinstance(page_info, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} userContentEdits page missing pageInfo")
        edits_nodes.extend(p_edits.get("nodes") or [])
    if "userContentEdits" in issue and issue["userContentEdits"] is not None:
        issue["userContentEdits"]["nodes"] = edits_nodes

    # Paginate comments if needed
    comments_field = issue.get("comments") or {}
    comments_nodes = list(comments_field.get("nodes") or [])
    c_page_info = comments_field.get("pageInfo") or {}
    while c_page_info.get("hasNextPage"):
        cursor = c_page_info.get("endCursor")
        if not cursor:
            raise GraphQLResponseError(f"Issue #{issue_number} comments hasNextPage is true but endCursor is missing")
        pdata = _post_graphql(
            http_post_json,
            ISSUE_COMMENTS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": issue_number, "cursor": cursor},
            "IssueCommentsPage",
        )
        repo_obj = pdata.get("repository")
        if not isinstance(repo_obj, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} comments page missing repository")
        p_issue = repo_obj.get("issue")
        if not isinstance(p_issue, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} comments page missing issue")
        p_comments = p_issue.get("comments")
        if not isinstance(p_comments, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} comments page missing comments")
        c_page_info = p_comments.get("pageInfo")
        if not isinstance(c_page_info, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} comments page missing pageInfo")
        comments_nodes.extend(p_comments.get("nodes") or [])
    if "comments" in issue and issue["comments"] is not None:
        issue["comments"]["nodes"] = comments_nodes

    for comment in comments_nodes:
        if comment.get("userContentEdits") is None:
            comment["userContentEdits"] = {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}

    # Paginate timeline items if needed
    timeline_field = issue.get("timelineItems") or {}
    timeline_nodes = list(timeline_field.get("nodes") or [])
    t_page_info = timeline_field.get("pageInfo") or {}
    while t_page_info.get("hasNextPage"):
        cursor = t_page_info.get("endCursor")
        if not cursor:
            raise GraphQLResponseError(f"Issue #{issue_number} timelineItems hasNextPage is true but endCursor is missing")
        pdata = _post_graphql(
            http_post_json,
            ISSUE_TIMELINE_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": issue_number, "cursor": cursor},
            "IssueTimelinePage",
        )
        repo_obj = pdata.get("repository")
        if not isinstance(repo_obj, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} timeline page missing repository")
        p_issue = repo_obj.get("issue")
        if not isinstance(p_issue, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} timeline page missing issue")
        p_timeline = p_issue.get("timelineItems")
        if not isinstance(p_timeline, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} timeline page missing timelineItems")
        t_page_info = p_timeline.get("pageInfo")
        if not isinstance(t_page_info, dict):
            raise GraphQLResponseError(f"Issue #{issue_number} timeline page missing pageInfo")
        timeline_nodes.extend(p_timeline.get("nodes") or [])
    if "timelineItems" in issue and issue["timelineItems"] is not None:
        issue["timelineItems"]["nodes"] = timeline_nodes

    return issue


def fetch_pull_request_data(http_post_json: HttpPostJson, owner: str, name: str, pr_number: int) -> dict[str, Any]:
    """Fetch pull request reviews, review comment threads, and conversation comments with pagination."""
    vars_main = {"owner": owner, "repo": name, "number": pr_number}
    data = _post_graphql(http_post_json, PULL_REQUEST_QUERY, vars_main, "PullRequestData")
    repo = data.get("repository")
    if repo is None:
        raise GraphQLResponseError(f"GraphQL repository not found for variables: {vars_main}")
    pr = repo.get("pullRequest")
    if not pr:
        raise GraphQLResponseError(f"Pull request #{pr_number} not found in {owner}/{name}")

    # Normalize nullable connections
    for field in ("reviews", "reviewThreads", "comments"):
        if pr.get(field) is None:
            pr[field] = {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}

    # Paginate PR conversation comments (Defect 9)
    comments_field = pr.get("comments") or {}
    pr_comments_nodes = list(comments_field.get("nodes") or [])
    c_page_info = comments_field.get("pageInfo") or {}
    while c_page_info.get("hasNextPage"):
        cursor = c_page_info.get("endCursor")
        if not cursor:
            raise GraphQLResponseError(f"PR #{pr_number} comments hasNextPage is true but endCursor is missing")
        pdata = _post_graphql(
            http_post_json,
            PR_COMMENTS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": pr_number, "cursor": cursor},
            "PullRequestCommentsPage",
        )
        repo_obj = pdata.get("repository")
        if not isinstance(repo_obj, dict):
            raise GraphQLResponseError(f"PR #{pr_number} comments pagination missing repository")
        p_pr = repo_obj.get("pullRequest")
        if not isinstance(p_pr, dict):
            raise GraphQLResponseError(f"PR #{pr_number} comments pagination missing pullRequest")
        p_comments = p_pr.get("comments")
        if not isinstance(p_comments, dict):
            raise GraphQLResponseError(f"PR #{pr_number} comments pagination missing comments")
        c_page_info = p_comments.get("pageInfo")
        if not isinstance(c_page_info, dict):
            raise GraphQLResponseError(f"PR #{pr_number} comments pagination missing pageInfo")
        pr_comments_nodes.extend(p_comments.get("nodes") or [])
    if "comments" in pr and pr["comments"] is not None:
        pr["comments"]["nodes"] = pr_comments_nodes

    # Paginate reviews
    reviews_field = pr.get("reviews") or {}
    reviews_nodes = list(reviews_field.get("nodes") or [])
    r_page_info = reviews_field.get("pageInfo") or {}
    while r_page_info.get("hasNextPage"):
        cursor = r_page_info.get("endCursor")
        if not cursor:
            raise GraphQLResponseError(f"PR #{pr_number} reviews hasNextPage is true but endCursor is missing")
        pdata = _post_graphql(
            http_post_json,
            PR_REVIEWS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": pr_number, "cursor": cursor},
            "PullRequestReviewsPage",
        )
        repo_obj = pdata.get("repository")
        if not isinstance(repo_obj, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviews pagination missing repository")
        p_pr = repo_obj.get("pullRequest")
        if not isinstance(p_pr, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviews pagination missing pullRequest")
        p_reviews = p_pr.get("reviews")
        if not isinstance(p_reviews, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviews pagination missing reviews")
        r_page_info = p_reviews.get("pageInfo")
        if not isinstance(r_page_info, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviews pagination missing pageInfo")
        reviews_nodes.extend(p_reviews.get("nodes") or [])
    if "reviews" in pr and pr["reviews"] is not None:
        pr["reviews"]["nodes"] = reviews_nodes

    # Paginate review threads
    threads_field = pr.get("reviewThreads") or {}
    threads_nodes = list(threads_field.get("nodes") or [])
    t_page_info = threads_field.get("pageInfo") or {}
    while t_page_info.get("hasNextPage"):
        cursor = t_page_info.get("endCursor")
        if not cursor:
            raise GraphQLResponseError(f"PR #{pr_number} reviewThreads hasNextPage is true but endCursor is missing")
        pdata = _post_graphql(
            http_post_json,
            PR_THREADS_PAGE_QUERY,
            {"owner": owner, "repo": name, "number": pr_number, "cursor": cursor},
            "PullRequestThreadsPage",
        )
        repo_obj = pdata.get("repository")
        if not isinstance(repo_obj, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviewThreads pagination missing repository")
        p_pr = repo_obj.get("pullRequest")
        if not isinstance(p_pr, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviewThreads pagination missing pullRequest")
        p_threads = p_pr.get("reviewThreads")
        if not isinstance(p_threads, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviewThreads pagination missing reviewThreads")
        t_page_info = p_threads.get("pageInfo")
        if not isinstance(t_page_info, dict):
            raise GraphQLResponseError(f"PR #{pr_number} reviewThreads pagination missing pageInfo")
        threads_nodes.extend(p_threads.get("nodes") or [])

    # Paginate comments inside each review thread
    for thread in threads_nodes:
        if thread.get("comments") is None:
            thread["comments"] = {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}
        thread_id = thread.get("id")
        c_field = thread.get("comments") or {}
        c_nodes = list(c_field.get("nodes") or [])
        c_page_info = c_field.get("pageInfo") or {}
        while c_page_info.get("hasNextPage"):
            if not thread_id:
                raise GraphQLResponseError(f"PR #{pr_number} reviewThread has hasNextPage=True but id is missing")
            cursor = c_page_info.get("endCursor")
            if not cursor:
                raise GraphQLResponseError(f"PR #{pr_number} reviewThread {thread_id} comments hasNextPage is true but endCursor is missing")
            pdata = _post_graphql(
                http_post_json,
                PR_THREAD_COMMENTS_PAGE_QUERY,
                {"id": thread_id, "cursor": cursor},
                "PullRequestReviewThreadCommentsPage",
            )
            node_obj = pdata.get("node")
            if not isinstance(node_obj, dict):
                raise GraphQLResponseError(f"PR #{pr_number} reviewThread {thread_id} comments pagination missing node")
            p_comments = node_obj.get("comments")
            if not isinstance(p_comments, dict):
                raise GraphQLResponseError(f"PR #{pr_number} reviewThread {thread_id} comments pagination missing comments")
            c_page_info = p_comments.get("pageInfo")
            if not isinstance(c_page_info, dict):
                raise GraphQLResponseError(f"PR #{pr_number} reviewThread {thread_id} comments pagination missing pageInfo")
            c_nodes.extend(p_comments.get("nodes") or [])
        if "comments" in thread and thread["comments"] is not None:
            thread["comments"]["nodes"] = c_nodes

    if "reviewThreads" in pr and pr["reviewThreads"] is not None:
        pr["reviewThreads"]["nodes"] = threads_nodes

    return pr

def _parse_github_item_url(url: str | None) -> tuple[str, str, int] | None:
    """Extract (repo, kind, number) from a GitHub issue or pull request URL."""
    if not url:
        return None
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+)/(issues|pull|pulls)/(\d+)", url)
    if m:
        owner, repo_name, sub, num_str = m.groups()
        kind = "pull" if sub in ("pull", "pulls") else "issues"
        return f"{owner}/{repo_name}", kind, int(num_str)
    return None


def get_solution_pr_scrub_entries(
    repo: str,
    pr_number: int,
    commit_shas: Sequence[str] = (),
) -> list[ScrubEntry]:
    """Generate static scrub entries for the solution PR itself, its sub-views, prefixes, and commits."""
    entries: list[ScrubEntry] = [
        ScrubEntry(kind="pull_request", match="exact", url=f"https://github.com/{repo}/pull/{pr_number}", reason="solution PR HTML URL"),
        ScrubEntry(kind="pull_request_prefix", match="prefix", url=f"https://github.com/{repo}/pull/{pr_number}/", reason="solution PR URL prefix"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}", reason="solution PR API URL"),
        ScrubEntry(kind="pull_request_prefix", match="prefix", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/", reason="solution PR API URL prefix"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://api.github.com/repos/{repo}/issues/{pr_number}", reason="solution PR Issues API URL"),
        ScrubEntry(kind="pull_request_prefix", match="prefix", url=f"https://api.github.com/repos/{repo}/issues/{pr_number}/", reason="solution PR Issues API URL prefix"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://github.com/{repo}/issues/{pr_number}", reason="solution PR Issues HTML URL"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://github.com/{repo}/pull/{pr_number}/files", reason="solution PR files view"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files", reason="solution PR files API"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://github.com/{repo}/pull/{pr_number}/commits", reason="solution PR commits view"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/commits", reason="solution PR commits API"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://github.com/{repo}/pull/{pr_number}.diff", reason="solution PR diff"),
        ScrubEntry(kind="pull_request", match="exact", url=f"https://github.com/{repo}/pull/{pr_number}.patch", reason="solution PR patch"),
    ]
    seen_shas: set[str] = set()
    for sha in commit_shas:
        if not sha or sha in seen_shas:
            continue
        seen_shas.add(sha)
        entries.extend([
            ScrubEntry(kind="commit", match="exact", url=f"https://github.com/{repo}/commit/{sha}", reason="solution PR commit HTML URL"),
            ScrubEntry(kind="commit", match="exact", url=f"https://github.com/{repo}/commit/{sha}.diff", reason="solution PR commit diff"),
            ScrubEntry(kind="commit", match="exact", url=f"https://github.com/{repo}/commit/{sha}.patch", reason="solution PR commit patch"),
            ScrubEntry(kind="commit", match="exact", url=f"https://api.github.com/repos/{repo}/commits/{sha}", reason="solution PR commit API URL"),
            ScrubEntry(kind="commit", match="exact", url=f"https://api.github.com/repos/{repo}/git/commits/{sha}", reason="solution PR git commit API URL"),
        ])
    return entries


def get_referencing_pr_scrub_entries(
    pr_repo: str,
    pr_num: int,
    base_reason: str = "referencing PR",
) -> list[ScrubEntry]:
    """Generate the full scrub entry set for a referencing PR."""
    return [
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{pr_repo}/pull/{pr_num}", reason=base_reason),
        ScrubEntry(kind="cross_reference_prefix", match="prefix", url=f"https://github.com/{pr_repo}/pull/{pr_num}/", reason=f"{base_reason} URL prefix"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://api.github.com/repos/{pr_repo}/pulls/{pr_num}", reason=base_reason),
        ScrubEntry(kind="cross_reference_prefix", match="prefix", url=f"https://api.github.com/repos/{pr_repo}/pulls/{pr_num}/", reason=f"{base_reason} API URL prefix"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://api.github.com/repos/{pr_repo}/issues/{pr_num}", reason=base_reason),
        ScrubEntry(kind="cross_reference_prefix", match="prefix", url=f"https://api.github.com/repos/{pr_repo}/issues/{pr_num}/", reason=f"{base_reason} Issues API URL prefix"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{pr_repo}/issues/{pr_num}", reason=f"{base_reason} Issues HTML URL"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{pr_repo}/pull/{pr_num}/files", reason=f"{base_reason} files view"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://api.github.com/repos/{pr_repo}/pulls/{pr_num}/files", reason=f"{base_reason} files API"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{pr_repo}/pull/{pr_num}/commits", reason=f"{base_reason} commits view"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://api.github.com/repos/{pr_repo}/pulls/{pr_num}/commits", reason=f"{base_reason} commits API"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{pr_repo}/pull/{pr_num}.diff", reason=f"{base_reason} diff"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{pr_repo}/pull/{pr_num}.patch", reason=f"{base_reason} patch"),
    ]


def dedupe_and_sort_entries(entries: list[ScrubEntry]) -> list[dict[str, str]]:
    """Deduplicate entries and sort deterministically by (url, kind, match, reason)."""
    seen: set[tuple[str, str, str, str]] = set()
    result: list[dict[str, str]] = []
    for entry in entries:
        if not entry.url:
            continue
        key = (entry.url, entry.kind, entry.match, entry.reason)
        if key not in seen:
            seen.add(key)
            result.append(entry.to_dict())

    result.sort(key=lambda d: (d["url"], d["kind"], d.get("match", ""), d["reason"]))
    return result


def _add_timeline_scrub_entries(
    entries: list[ScrubEntry],
    issue_data: dict[str, Any],
    repo: str,
    target_issue_numbers: set[int],
) -> None:
    """Scrub timeline items (cross references and connected events) on an issue."""
    for item in (issue_data.get("timelineItems") or {}).get("nodes") or []:
        typename = item.get("__typename")
        if typename == "CrossReferencedEvent":
            src = item.get("source") or {}
            src_url = src.get("url") or ""
            src_num = src.get("number")
            src_type = src.get("__typename")
            parsed = _parse_github_item_url(src_url)
            src_repo = parsed[0] if parsed else repo
            src_kind = parsed[1] if parsed else ("pull" if src_type == "PullRequest" else "issues")
            src_number = parsed[2] if parsed else src_num

            if src_kind == "pull" or src_type == "PullRequest":
                if src_number:
                    entries.extend(get_referencing_pr_scrub_entries(src_repo, src_number, base_reason="cross-references target issue"))
                elif src_url:
                    entries.append(ScrubEntry(kind="cross_reference", match="exact", url=src_url, reason="cross-references target issue"))
            else:
                if src_url:
                    entries.append(ScrubEntry(kind="cross_reference", match="exact", url=src_url, reason="cross-references target issue"))
                if src_number:
                    entries.append(ScrubEntry(
                        kind="cross_reference",
                        match="exact",
                        url=f"https://api.github.com/repos/{src_repo}/issues/{src_number}",
                        reason="cross-references target issue",
                    ))
            if item.get("url"):
                entries.append(ScrubEntry(kind="cross_reference", match="exact", url=item["url"], reason="cross-reference event on target issue"))

        elif typename == "ConnectedEvent":
            for conn_item in (item.get("source"), item.get("subject")):
                if not conn_item:
                    continue
                c_url = conn_item.get("url") or ""
                c_num = conn_item.get("number")
                c_type = conn_item.get("__typename")
                parsed = _parse_github_item_url(c_url)
                c_repo = parsed[0] if parsed else repo
                c_kind = parsed[1] if parsed else ("pull" if c_type == "PullRequest" else "issues")
                c_number = parsed[2] if parsed else c_num

                if c_repo == repo and c_number in target_issue_numbers and c_kind == "issues":
                    continue

                if c_kind == "pull" or c_type == "PullRequest":
                    if c_number:
                        entries.extend(get_referencing_pr_scrub_entries(c_repo, c_number, base_reason="connected to target issue"))
                    elif c_url:
                        entries.append(ScrubEntry(kind="cross_reference", match="exact", url=c_url, reason="connected to target issue"))
                else:
                    if c_url:
                        entries.append(ScrubEntry(kind="cross_reference", match="exact", url=c_url, reason="connected to target issue"))
                    if c_number:
                        entries.append(ScrubEntry(
                            kind="cross_reference",
                            match="exact",
                            url=f"https://api.github.com/repos/{c_repo}/issues/{c_number}",
                            reason="connected to target issue",
                        ))


def _add_linked_refs_scrub_entries(
    entries: list[ScrubEntry],
    issue_data: dict[str, Any],
    repo: str,
    target_issue_numbers: set[int],
) -> None:
    """Scrub issue references discovered in the issue discussion corpus."""
    from hermetic_slice.intake import linked_refs

    comments_nodes = list((issue_data.get("comments") or {}).get("nodes") or [])
    text_corpus = [issue_data.get("body") or ""] + [c.get("body") or "" for c in comments_nodes]
    for text_sample in text_corpus:
        for ref in linked_refs(repo, "", text_sample):
            if ref.number not in target_issue_numbers:
                if ref.kind == "github":
                    entries.append(ScrubEntry(
                        kind="cross_reference",
                        match="exact",
                        url=f"https://github.com/{repo}/issues/{ref.number}",
                        reason="referenced in target issue discussion",
                    ))
                    entries.append(ScrubEntry(
                        kind="cross_reference",
                        match="exact",
                        url=f"https://api.github.com/repos/{repo}/issues/{ref.number}",
                        reason="referenced in target issue discussion",
                    ))


def process_thread_scrub_and_revision(
    *,
    repo: str,
    pr_number: int,
    target_issue_number: int | None = None,
    target_issue_numbers: list[int] | None = None,
    target_issue_created: datetime | None = None,
    t_world: datetime,
    scraped_problem_statement: str,
    scraped_hints: str,
    token: str | None = None,
    http_post_json: HttpPostJson | None = None,
    cache_dir: Path,
    warnings_list: list[str],
    commit_shas: Sequence[str] = (),
    snapshot_id: str | None = None,
    refresh: bool = False,
) -> ScrubResult:
    """Perform mutable-content revisioning and thread-scrub list generation.

    If token is not configured, or if GraphQL returns errors/malformed responses,
    falls back cleanly to scraped content and records warnings, never crashing.
    """
    owner, name = repo.split("/", 1)
    base_entries = get_solution_pr_scrub_entries(repo, pr_number, commit_shas=commit_shas)

    if target_issue_numbers is None:
        target_issue_numbers = [target_issue_number] if target_issue_number is not None else []

    unrev_warning = "problem_statement taken as scraped, not at its revision as of T_world (Phase 0 gap, spec section 4)"

    # Fallback state if token missing or query fails
    def make_fallback(warning_msg: str | None = None, entries: list[ScrubEntry] | None = None) -> ScrubResult:
        if warning_msg and warning_msg not in warnings_list:
            warnings_list.append(warning_msg)
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)
        return ScrubResult(
            problem_statement=scraped_problem_statement,
            hints_text=scraped_hints,
            problem_statement_revision="as_scraped",
            chosen_revision_edited_at=None,
            edits_ignored=0,
            hints_revisioned=False,
            scrub_entries=dedupe_and_sort_entries(entries if entries is not None else base_entries),
            hints_excluded_no_history=0,
            hints_excluded_no_created_at=0,
        )

    if not token and http_post_json is None:
        return make_fallback(entries=base_entries)

    post_client = http_post_json if http_post_json is not None else make_http_post_json(
        cache_dir, token=token, snapshot_id=snapshot_id, refresh=refresh
    )

    # 1. Fetch Pull Request scrub items (reviews, review comments, conversation comments)
    pr_entries: list[ScrubEntry] = list(base_entries)
    try:
        pr_data = fetch_pull_request_data(post_client, owner, name, pr_number)
        for review in (pr_data.get("reviews") or {}).get("nodes") or []:
            rev_url = review.get("url")
            rev_id = review.get("databaseId")
            if not rev_id and rev_url:
                m = re.search(r"#pullrequestreview-(\d+)", rev_url)
                if m:
                    rev_id = m.group(1)
            if rev_url:
                pr_entries.append(ScrubEntry(kind="review", match="exact", url=rev_url, reason="solution PR review"))
            if rev_id:
                pr_entries.append(ScrubEntry(
                    kind="review",
                    match="exact",
                    url=f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews/{rev_id}",
                    reason="solution PR review",
                ))

        for thread in (pr_data.get("reviewThreads") or {}).get("nodes") or []:
            for rc in (thread.get("comments") or {}).get("nodes") or []:
                rc_url = rc.get("url")
                rc_id = rc.get("databaseId")
                if not rc_id and rc_url:
                    m = re.search(r"#discussion_r(\d+)", rc_url)
                    if m:
                        rc_id = m.group(1)
                if rc_url:
                    pr_entries.append(ScrubEntry(kind="review_comment", match="exact", url=rc_url, reason="solution PR review comment"))
                if rc_id:
                    pr_entries.append(ScrubEntry(
                        kind="review_comment",
                        match="exact",
                        url=f"https://api.github.com/repos/{repo}/pulls/comments/{rc_id}",
                        reason="solution PR review comment",
                    ))

        # Defect 9: PR conversation comments (IssueComments on PR)
        for c in (pr_data.get("comments") or {}).get("nodes") or []:
            c_url = c.get("url")
            c_id = c.get("databaseId")
            if not c_id and c_url:
                m = re.search(r"#issuecomment-(\d+)", c_url)
                if m:
                    c_id = m.group(1)
            if c_url:
                pr_entries.append(ScrubEntry(kind="comment", match="exact", url=c_url, reason="solution PR conversation comment HTML URL"))
            if c_id:
                pr_entries.append(ScrubEntry(
                    kind="comment",
                    match="exact",
                    url=f"https://api.github.com/repos/{repo}/issues/comments/{c_id}",
                    reason="solution PR conversation comment API URL",
                ))
    except Exception as exc:
        warnings_list.append(f"Failed fetching PR scrub details via GraphQL ({exc}); using static PR endpoints")

    # Case A: No target GitHub issue to revision (Trac, Django, no issue reference)
    if len(target_issue_numbers) == 0:
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)
        return ScrubResult(
            problem_statement=scraped_problem_statement,
            hints_text=scraped_hints,
            problem_statement_revision="as_scraped",
            chosen_revision_edited_at=None,
            edits_ignored=0,
            hints_revisioned=False,
            scrub_entries=dedupe_and_sort_entries(pr_entries),
            hints_excluded_no_history=0,
            hints_excluded_no_created_at=0,
        )

    # Case B: Multi-issue case (Defect 11 & Defect 12)
    if len(target_issue_numbers) > 1:
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)

        all_entries = list(pr_entries)
        target_set = set(target_issue_numbers)
        for iss_num in target_issue_numbers:
            try:
                iss_data = fetch_target_issue_data(post_client, owner, name, iss_num)
            except Exception as exc:
                warnings_list.append(f"GraphQL request for issue #{iss_num} failed ({exc}); skipping scrub for issue #{iss_num}")
                continue

            # Scrub post-T_world comments on this issue
            for c in (iss_data.get("comments") or {}).get("nodes") or []:
                c_created = parse_iso(c.get("createdAt"))
                c_url = c.get("url")
                c_id = c.get("databaseId")
                if not c_id and c_url:
                    m = re.search(r"#issuecomment-(\d+)", c_url)
                    if m:
                        c_id = m.group(1)
                if c_created and c_created > t_world:
                    if c_url:
                        all_entries.append(ScrubEntry(kind="comment", match="exact", url=c_url, reason="target issue comment created after T_world"))
                    if c_id:
                        all_entries.append(ScrubEntry(
                            kind="comment",
                            match="exact",
                            url=f"https://api.github.com/repos/{repo}/issues/comments/{c_id}",
                            reason="target issue comment created after T_world",
                        ))

            _add_timeline_scrub_entries(all_entries, iss_data, repo, target_set)
            _add_linked_refs_scrub_entries(all_entries, iss_data, repo, target_set)

        return ScrubResult(
            problem_statement=scraped_problem_statement,
            hints_text=scraped_hints,
            problem_statement_revision="as_scraped",
            chosen_revision_edited_at=None,
            edits_ignored=0,
            hints_revisioned=False,
            scrub_entries=dedupe_and_sort_entries(all_entries),
            hints_excluded_no_history=0,
            hints_excluded_no_created_at=0,
        )

    # Case C: Exactly one target issue
    single_issue_number = target_issue_numbers[0]
    try:
        issue_data = fetch_target_issue_data(post_client, owner, name, single_issue_number)
    except Exception as exc:
        return make_fallback(
            f"GraphQL request for issue #{single_issue_number} failed ({exc}); falling back to scraped content",
            entries=pr_entries,
        )

    # 3. Revision target issue problem statement
    title, body_scraped = split_title_and_body(scraped_problem_statement)
    issue_created = parse_iso(issue_data.get("createdAt")) or target_issue_created
    last_edited = parse_iso(issue_data.get("lastEditedAt"))
    user_edits = list((issue_data.get("userContentEdits") or {}).get("nodes") or [])
    includes_created = issue_data.get("includesCreatedEdit")

    rev_res = select_revision(
        scraped_body=body_scraped,
        created_at=issue_created,
        last_edited_at=last_edited,
        user_content_edits=user_edits,
        t_world=t_world,
        is_target_issue=True,
        includes_created_edit=includes_created,
    )
    if rev_res.warning:
        warnings_list.append(rev_res.warning)
    if rev_res.revision_type == "as_scraped" and (last_edited is not None or rev_res.warning):
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)

    final_problem_statement = reconstruct_problem_statement(title, rev_res.body)

    # 4. Revision hints & target issue comments scrub
    comments_nodes = list((issue_data.get("comments") or {}).get("nodes") or [])
    kept_comments_bodies: list[str] = []
    kept_comments_verified: list[bool] = []
    hints_excluded_no_history = 0
    hints_excluded_no_created_at = 0
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
        c_comment_ident = str(c_db_id or comment.get("id") or c_url or "unknown")

        # Defect 4: Comment with missing or unparseable createdAt
        if c_created is None:
            hints_excluded_no_created_at += 1
            warnings_list.append(f"Comment {c_comment_ident}: missing or unparseable createdAt; excluded from hints")
            continue

        if c_created > t_world:
            # Drop from hints; add to thread_scrub list
            if c_url:
                all_entries.append(ScrubEntry(kind="comment", match="exact", url=c_url, reason="target issue comment created after T_world"))
            if c_db_id:
                all_entries.append(ScrubEntry(
                    kind="comment",
                    match="exact",
                    url=f"https://api.github.com/repos/{repo}/issues/comments/{c_db_id}",
                    reason="target issue comment created after T_world",
                ))
            continue

        # Comment was created at or before T_world
        if c_last_edited is None:
            # Never edited: verified revision as of T_world
            kept_comments_bodies.append(comment.get("body") or "")
            kept_comments_verified.append(True)
            continue

        # Comment has lastEditedAt set: must have usable history
        try:
            c_edits_obj = comment.get("userContentEdits") or {}
            c_edits = list(c_edits_obj.get("nodes") or [])
            c_page_info = c_edits_obj.get("pageInfo") or {}
            c_id = comment.get("id")

            # Defect 2: Paginate userContentEdits with incomplete checks
            while c_page_info.get("hasNextPage"):
                if not c_id:
                    raise GraphQLResponseError(f"Comment {c_comment_ident} has hasNextPage=True but id is missing")
                cursor = c_page_info.get("endCursor")
                if not cursor:
                    raise GraphQLResponseError(f"Comment {c_comment_ident} has hasNextPage=True but endCursor is missing")
                pdata = _post_graphql(
                    post_client,
                    COMMENT_EDITS_PAGE_QUERY,
                    {"id": c_id, "cursor": cursor},
                    "CommentEditsPage",
                )
                node_data = pdata.get("node")
                if not isinstance(node_data, dict):
                    raise GraphQLResponseError(f"Comment {c_comment_ident} pagination missing node")
                c_p_edits = node_data.get("userContentEdits")
                if not isinstance(c_p_edits, dict):
                    raise GraphQLResponseError(f"Comment {c_comment_ident} pagination missing userContentEdits")
                c_page_info = c_p_edits.get("pageInfo")
                if not isinstance(c_page_info, dict):
                    raise GraphQLResponseError(f"Comment {c_comment_ident} pagination missing pageInfo")
                c_edits.extend(c_p_edits.get("nodes") or [])

            # Defect 1: check empty userContentEdits
            if not c_edits:
                hints_excluded_no_history += 1
                warnings_list.append(f"Comment {c_comment_ident}: lastEditedAt set but userContentEdits is missing or empty; excluded from hints")
                continue

            c_includes_created = comment.get("includesCreatedEdit")
            c_rev = select_revision(
                scraped_body=comment.get("body") or "",
                created_at=c_created,
                last_edited_at=c_last_edited,
                user_content_edits=c_edits,
                t_world=t_world,
                is_target_issue=False,
                includes_created_edit=c_includes_created,
            )

            # Defect 1: If includesCreatedEdit is not true and no edit qualifies,
            # or chosen diff is null, select_revision returns as_scraped with warning
            if c_rev.revision_type == "as_scraped" or c_rev.warning:
                hints_excluded_no_history += 1
                warnings_list.append(f"Comment {c_comment_ident}: {c_rev.warning or 'no usable edit history'}; excluded from hints")
                continue

            kept_comments_bodies.append(c_rev.body)
            kept_comments_verified.append(True)

        except Exception as exc:
            # Defect 5: comment edit pagination failure cleanly caught
            hints_excluded_no_history += 1
            warnings_list.append(f"Comment {c_comment_ident}: failed fetching or processing edit history ({exc}); excluded from hints")
            continue

    final_hints = "\n".join(kept_comments_bodies) if kept_comments_bodies else ""
    # Defect 1: computed hints_revisioned
    hints_revisioned = bool(all(kept_comments_verified)) if kept_comments_bodies else True

    # 5. Scrub timeline items and linked refs for target issue
    _add_timeline_scrub_entries(all_entries, issue_data, repo, {single_issue_number})
    _add_linked_refs_scrub_entries(all_entries, issue_data, repo, {single_issue_number})

    sorted_scrub_entries = dedupe_and_sort_entries(all_entries)

    return ScrubResult(
        problem_statement=final_problem_statement,
        hints_text=final_hints,
        problem_statement_revision=rev_res.revision_type,
        chosen_revision_edited_at=rev_res.edited_at,
        edits_ignored=rev_res.edits_ignored,
        hints_revisioned=hints_revisioned,
        scrub_entries=sorted_scrub_entries,
        hints_excluded_no_history=hints_excluded_no_history,
        hints_excluded_no_created_at=hints_excluded_no_created_at,
    )
