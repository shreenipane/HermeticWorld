"""Mutable-content rule and target-thread scrub (TR-SEAL-9, spec §4).

This module implements:
1. Mutable-content revision rule:
   - Fetches edit histories for target issues and comments via GitHub GraphQL API.
   - Replaces scraped problem statement body with the newest revision dated at or before T_world.
   - Revisions hints: filters comments to those created at or before T_world, taking each
     at its revision as of T_world.
   - Records metadata: problem_statement_revision (as_scraped | revision_at_t_world | first_revision | excluded),
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
- "exact": The requested URL matches if its normalized resource URL (scheme, host, and path,
  with query parameters and fragment stripped unless the scrub entry explicitly specifies them)
  equals the entry's `url`. If the entry specifies a fragment (such as '#issuecomment-123'),
  the candidate URL must also match that exact fragment. Trailing slashes on non-root paths are
  normalized. This ensures query variants (e.g. '?x=1') of PRs, comments, and referencing
  resources are blocked while strictly preserving numeric path boundaries (e.g. PR 50 does
  not match PR 500).
- "prefix": The requested URL matches if its URL or normalized resource path begins with `url`.
  Every prefix entry ends with a trailing delimiter (e.g. '/') to prevent prefix collisions
  such as '/pull/50' matching '/pull/500'.
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
    * "unresolved_scope": Required prefix denial of GitHub services after incomplete discovery
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
from urllib.parse import urlsplit

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


MAX_RESOURCE_URL_LENGTH = 2048


def deny_unresolved_scope(entries: list[ScrubEntry]) -> None:
    """Append mandatory prefix denials for GitHub web and API scope."""
    for url in ("https://github.com/", "https://api.github.com/"):
        entries.append(ScrubEntry("unresolved_scope", url, "incomplete discovery; deny GitHub scope", "prefix"))


def _canonicalize_url(url: str) -> tuple[str, str, str, str, str] | None:
    """Validate, bound, and canonicalize URL components.

    Rejects malformed bracketed authorities, unsupported authority forms
    (e.g., userinfo, invalid ports), and URLs exceeding length bounds.
    Canonicalizes hostname case and strips default effective ports (443 for https, 80 for http).
    Returns (scheme, canonical_netloc, path, query, fragment) or None if invalid.
    """
    if not isinstance(url, str):
        return None
    if len(url) > MAX_RESOURCE_URL_LENGTH:
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    if scheme not in ("http", "https"):
        return None

    if not parsed.netloc:
        return None

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not hostname:
        return None

    hostname = hostname.lower()

    default_port = 443 if scheme == "https" else 80
    if port is not None and port == default_port:
        port = None

    if port is not None:
        if not (0 < port < 65536):
            return None
        canon_netloc = f"{hostname}:{port}"
    else:
        canon_netloc = hostname

    path = parsed.path or "/"

    return (scheme, canon_netloc, path, parsed.query, parsed.fragment)


def match_scrub_entry(entry: dict[str, str] | ScrubEntry, candidate_url: str) -> bool:
    """Evaluate whether candidate_url matches a scrub entry according to documented semantics."""
    if isinstance(entry, ScrubEntry):
        e_url = entry.url
        e_match = entry.match
    else:
        e_url = entry.get("url", "")
        e_match = entry.get("match", "exact")

    if not e_url:
        return False
    if not candidate_url:
        return False

    cand_canon = _canonicalize_url(candidate_url)
    if cand_canon is None:
        # Candidate URL is malformed, oversized, or unsupported authority: controlled rejection (cannot become allow)
        return True

    entry_canon = _canonicalize_url(e_url)
    if entry_canon is None:
        return False

    cand_scheme, cand_netloc, cand_path, cand_query, cand_frag = cand_canon
    entry_scheme, entry_netloc, entry_path, entry_query, entry_frag = entry_canon

    if cand_scheme != entry_scheme or cand_netloc != entry_netloc:
        return False

    if e_match == "exact":
        if entry_frag and cand_frag != entry_frag:
            return False
        if entry_query and cand_query != entry_query:
            return False
        c_path = cand_path.rstrip("/") if cand_path != "/" else "/"
        e_path = entry_path.rstrip("/") if entry_path != "/" else "/"
        return c_path == e_path

    if e_match == "prefix":
        cand_base = f"{cand_scheme}://{cand_netloc}{cand_path}"
        entry_base = f"{entry_scheme}://{entry_netloc}{entry_path}"
        if entry_query:
            entry_full = f"{entry_base}?{entry_query}"
            cand_full = f"{cand_base}?{cand_query}" if cand_query else cand_base
            return cand_full.startswith(entry_full)
        if cand_base.startswith(entry_base):
            return True
        if candidate_url.startswith(e_url):
            return True
        return False

    return False


def matches_any_scrub_entry(entries: Sequence[dict[str, str] | ScrubEntry], candidate_url: str) -> bool:
    """Evaluate whether candidate_url matches any scrub entry in the collection."""
    if not candidate_url:
        return False
    cand_canon = _canonicalize_url(candidate_url)
    if cand_canon is None:
        # Controlled rejection that cannot become an allow decision
        return True
    return any(match_scrub_entry(e, candidate_url) for e in entries)


match_resource = matches_any_scrub_entry
is_url_blocked = matches_any_scrub_entry


@dataclass(frozen=True)
class RevisionResult:
    body: str
    revision_type: str  # "as_scraped" | "revision_at_t_world" | "first_revision" | "excluded"
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
    if not isinstance(dt_str, str) or not dt_str or len(dt_str) > 128:
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
    - If history is missing or incomplete, exclude the content with an explicit warning.
    """
    if (not isinstance(scraped_body, str) or
            any(not isinstance(edit, dict) or
                parse_iso(edit.get("editedAt") or edit.get("createdAt")) is None or
                not isinstance(edit.get("diff") if edit.get("diff") is not None else edit.get("body"), str)
                for edit in user_content_edits)):
        return RevisionResult("", "excluded", None, 0, "invalid_revision; content excluded")
    if last_edited_at is None:
        return RevisionResult(
            body=scraped_body,
            revision_type="as_scraped",
            edited_at=None,
            edits_ignored=0,
        )

    if not user_content_edits:
        return RevisionResult(
            body="",
            revision_type="excluded",
            edited_at=None,
            edits_ignored=0,
            warning="document was edited but userContentEdits is missing or empty; content excluded",
        )

    # userContentEdits is newest first
    if is_target_issue and created_at is not None and t_world < created_at:
        if includes_created_edit is not True:
            return RevisionResult(
                body="",
                revision_type="excluded",
                edited_at=None,
                edits_ignored=0,
                warning="edit history does not include creation edit (includesCreatedEdit is false / not true); content excluded",
            )
        first_rev = user_content_edits[-1]
        diff_val = first_rev.get("diff")
        body_val = first_rev.get("body")
        if diff_val is None and body_val is None:
            return RevisionResult(
                body="",
                revision_type="excluded",
                edited_at=None,
                edits_ignored=0,
                warning="historical revision diff is null; content excluded",
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
                    body="",
                    revision_type="excluded",
                    edited_at=None,
                    edits_ignored=0,
                    warning="historical revision diff is null; content excluded",
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
            body="",
            revision_type="excluded",
            edited_at=None,
            edits_ignored=0,
            warning="no qualifying edit before T_world and history does not include creation edit (includesCreatedEdit is false / not true); content excluded",
        )

    first_rev = user_content_edits[-1]
    diff_val = first_rev.get("diff")
    body_val = first_rev.get("body")
    if diff_val is None and body_val is None:
        return RevisionResult(
            body="",
            revision_type="excluded",
            edited_at=None,
            edits_ignored=0,
            warning="historical revision diff is null; content excluded",
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


MAX_GRAPHQL_PAGES = 128
MAX_CONNECTION_PAGES = 32
MAX_CONNECTION_NODES = 10000
MAX_GRAPHQL_NODES = 100000
MAX_GRAPHQL_BYTES = 32 * 1024 * 1024
MAX_GRAPHQL_DEPTH = 32
MAX_GRAPHQL_CURSOR_LENGTH = 1024
MAX_RESOURCE_URL_LENGTH = 2048
MAX_RESOURCE_ID_LENGTH = 128
MAX_DATABASE_ID = (1 << 63) - 1


def _measure_response(value: Any, depth: int = 0) -> tuple[int, int]:
    if depth > MAX_GRAPHQL_DEPTH:
        raise GraphQLResponseError("response_depth_limit")
    nodes, size = 1, 0
    if isinstance(value, (bytes, bytearray)):
        size = len(value)
    elif isinstance(value, str):
        size = len(value.encode("utf-8"))
    elif isinstance(value, (dict, list)):
        values = value.items() if isinstance(value, dict) else enumerate(value)
        for key, child in values:
            count, length = _measure_response(child, depth + 1)
            nodes += count
            size += length + (len(key.encode("utf-8")) if isinstance(key, str) else 0)
            if nodes > MAX_GRAPHQL_NODES or size > MAX_GRAPHQL_BYTES:
                raise GraphQLResponseError("response_aggregate_limit")
    elif value is not None and type(value) not in (int, float, bool):
        raise GraphQLResponseError("invalid_response_type")
    if size > MAX_GRAPHQL_BYTES:
        raise GraphQLResponseError("response_aggregate_limit")
    return nodes, size


class _RunClient:
    def __init__(self, client: HttpPostJson) -> None:
        self.client = client
        self.pages = self.nodes = self.size = 0

    def __call__(self, url: str, payload: Any) -> Any:
        self.pages += 1
        if self.pages > MAX_GRAPHQL_PAGES:
            raise GraphQLResponseError("response_page_limit")
        response = self.client(url, payload)
        nodes, size = _measure_response(response)
        self.nodes += nodes
        self.size += size
        if self.nodes > MAX_GRAPHQL_NODES or self.size > MAX_GRAPHQL_BYTES:
            raise GraphQLResponseError("response_aggregate_limit")
        return response


def _post_graphql(http_post_json: HttpPostJson, query: str, variables: dict[str, Any], operation_name: str) -> dict[str, Any]:
    try:
        resp = http_post_json(GITHUB_GRAPHQL_URL, {
            "operationName": operation_name, "query": query, "variables": variables,
        })
        if isinstance(resp, (bytes, bytearray)):
            if len(resp) > MAX_GRAPHQL_BYTES:
                raise GraphQLResponseError("response_byte_limit")
            resp = json.loads(resp.decode("utf-8"))
        _measure_response(resp)
        if not isinstance(resp, dict) or resp.get("errors") or not isinstance(resp.get("data"), dict):
            raise GraphQLResponseError("invalid_graphql_response")
        return resp["data"]
    except Exception:
        raise GraphQLResponseError("graphql_request_failed") from None


def _object(parent: Any, field: str) -> dict[str, Any]:
    if not isinstance(parent, dict) or not isinstance(parent.get(field), dict):
        raise GraphQLResponseError("missing_response_object")
    return parent[field]


def _connection(connection: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(connection, dict):
        raise GraphQLResponseError("missing_connection")
    nodes, info = connection.get("nodes"), connection.get("pageInfo")
    if (not isinstance(nodes, list) or len(nodes) > MAX_CONNECTION_NODES or
            any(not isinstance(n, dict) for n in nodes) or
            not isinstance(info, dict) or type(info.get("hasNextPage")) is not bool):
        raise GraphQLResponseError("invalid_connection")
    if info["hasNextPage"] and (not isinstance(info.get("endCursor"), str) or
            not info["endCursor"] or len(info["endCursor"]) > MAX_GRAPHQL_CURSOR_LENGTH):
        raise GraphQLResponseError("invalid_connection_cursor")
    return list(nodes), info


def _paginate(client: HttpPostJson, initial: Any, query: str, variables: dict[str, Any],
              operation: str, path: tuple[str, ...]) -> list[dict[str, Any]]:
    nodes, info = _connection(initial)
    seen: set[str] = set()
    pages = 1
    while info["hasNextPage"]:
        cursor = info["endCursor"]
        if cursor in seen or pages >= MAX_CONNECTION_PAGES:
            raise GraphQLResponseError("pagination_limit_or_cycle")
        seen.add(cursor)
        if "id" in variables and (not isinstance(variables["id"], str) or not variables["id"]):
            raise GraphQLResponseError("missing_pagination_id")
        page: Any = _post_graphql(client, query, dict(variables, cursor=cursor), operation)
        for field in path:
            page = _object(page, field)
        more, info = _connection(page)
        if len(nodes) + len(more) > MAX_CONNECTION_NODES:
            raise GraphQLResponseError("connection_node_limit")
        nodes.extend(more)
        pages += 1
    return nodes


def _validate_fields(node: dict[str, Any]) -> None:
    for key in ("body", "diff", "id", "url", "__typename"):
        value = node.get(key)
        if value is not None and (not isinstance(value, str) or
                (key == "id" and len(value) > MAX_RESOURCE_ID_LENGTH)):
            raise GraphQLResponseError("invalid_content_field")
    for key in ("databaseId", "number"):
        value = node.get(key)
        if value is not None and (type(value) is not int or value <= 0 or value > MAX_DATABASE_ID):
            raise GraphQLResponseError("invalid_identifier")
    url = node.get("url")
    if url is not None and (len(url) > MAX_RESOURCE_URL_LENGTH or not re.fullmatch(r"https://(?:api\.)?github\.com/[A-Za-z0-9_./#?=&%-]+", url)):
        raise GraphQLResponseError("invalid_resource_url")


def _parse_github_item_url(url: str | None) -> tuple[str, str, int] | None:
    """Extract (repo, kind, number) from a GitHub issue or pull request URL."""
    if not url:
        return None
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+)/(issues|pull|pulls)/(\d+)", url)
    if m:
        owner, repo_name, sub, num_str = m.groups()
        if len(num_str) > 18:
            return None
        kind = "pull" if sub in ("pull", "pulls") else "issues"
        return f"{owner}/{repo_name}", kind, int(num_str)
    return None


def _is_target_issue_ref(item: Any, target_repo: str, target_numbers: set[int] | int) -> bool:
    """Check if an item dictionary references the target issue."""
    if not isinstance(item, dict):
        return False
    if isinstance(target_numbers, int):
        target_numbers = {target_numbers}
    t_type = item.get("__typename") if isinstance(item.get("__typename"), str) else None
    if t_type == "PullRequest":
        return False
    url = item.get("url") if isinstance(item.get("url"), str) else ""
    num = item.get("number") if type(item.get("number")) is int else None
    parsed = _parse_github_item_url(url)
    item_repo = parsed[0] if parsed else target_repo
    item_kind = parsed[1] if parsed else "issues"
    item_num = parsed[2] if parsed else num
    return item_repo == target_repo and item_kind == "issues" and item_num in target_numbers


def fetch_target_issue_data(http_post_json: HttpPostJson, owner: str, name: str, issue_number: int) -> dict[str, Any]:
    variables = {"owner": owner, "repo": name, "number": issue_number}
    data = _post_graphql(http_post_json, TARGET_ISSUE_QUERY, variables, "TargetIssueData")
    issue = _object(_object(data, "repository"), "issue")
    _validate_fields(issue)
    for field, query, operation in (
        ("userContentEdits", ISSUE_EDITS_PAGE_QUERY, "IssueEditsPage"),
        ("comments", ISSUE_COMMENTS_PAGE_QUERY, "IssueCommentsPage"),
        ("timelineItems", ISSUE_TIMELINE_PAGE_QUERY, "IssueTimelinePage"),
    ):
        nodes = _paginate(http_post_json, issue.get(field), query, variables,
                          operation, ("repository", "issue", field))
        for node in nodes:
            _validate_fields(node)
            if field == "comments":
                if not node.get("databaseId") and not node.get("url"):
                    raise GraphQLResponseError("missing_comment_identity")
            elif field == "timelineItems":
                if node.get("__typename") not in ("CrossReferencedEvent", "ConnectedEvent"):
                    raise GraphQLResponseError("invalid_timeline_node")
                if node.get("__typename") == "CrossReferencedEvent":
                    src = node.get("source")
                    if not isinstance(src, dict) or (not src.get("url") and not src.get("number")):
                        raise GraphQLResponseError("missing_cross_reference_source")
                    _validate_fields(src)
                elif node.get("__typename") == "ConnectedEvent":
                    src = node.get("source")
                    subj = node.get("subject")
                    has_src = isinstance(src, dict) and bool(src.get("url") or src.get("number"))
                    has_subj = isinstance(subj, dict) and bool(subj.get("url") or subj.get("number"))
                    target_repo_str = f"{owner}/{name}"
                    src_outside = has_src and not _is_target_issue_ref(src, target_repo_str, issue_number)
                    subj_outside = has_subj and not _is_target_issue_ref(subj, target_repo_str, issue_number)
                    if not src_outside and not subj_outside:
                        raise GraphQLResponseError("missing_connected_event_identity")
                    for key in ("source", "subject"):
                        if node.get(key) is not None:
                            _validate_fields(_object(node, key))
        issue[field]["nodes"] = nodes
    return issue


def fetch_pull_request_data(http_post_json: HttpPostJson, owner: str, name: str, pr_number: int) -> dict[str, Any]:
    variables = {"owner": owner, "repo": name, "number": pr_number}
    data = _post_graphql(http_post_json, PULL_REQUEST_QUERY, variables, "PullRequestData")
    pr = _object(_object(data, "repository"), "pullRequest")
    for field, query, operation in (
        ("comments", PR_COMMENTS_PAGE_QUERY, "PullRequestCommentsPage"),
        ("reviews", PR_REVIEWS_PAGE_QUERY, "PullRequestReviewsPage"),
        ("reviewThreads", PR_THREADS_PAGE_QUERY, "PullRequestThreadsPage"),
    ):
        nodes = _paginate(http_post_json, pr.get(field), query, variables,
                          operation, ("repository", "pullRequest", field))
        for node in nodes:
            _validate_fields(node)
            if field == "comments":
                if not node.get("databaseId") and not node.get("url"):
                    raise GraphQLResponseError("missing_pr_comment_identity")
            elif field == "reviews":
                if not node.get("databaseId") and not node.get("url"):
                    raise GraphQLResponseError("missing_review_identity")
            elif field == "reviewThreads":
                node["comments"]["nodes"] = _paginate(
                    http_post_json, node.get("comments"), PR_THREAD_COMMENTS_PAGE_QUERY,
                    {"id": node.get("id")}, "PullRequestReviewThreadCommentsPage", ("node", "comments"))
                for comment in node["comments"]["nodes"]:
                    _validate_fields(comment)
                    if not comment.get("databaseId") and not comment.get("url"):
                        raise GraphQLResponseError("missing_review_comment_identity")
        pr[field]["nodes"] = nodes
    return pr

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


def get_referencing_issue_scrub_entries(
    issue_repo: str,
    issue_num: int,
    base_reason: str = "referencing issue",
) -> list[ScrubEntry]:
    """Generate the full scrub entry set for a referencing issue with delimiter-bounded prefixes."""
    return [
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{issue_repo}/issues/{issue_num}", reason=base_reason),
        ScrubEntry(kind="cross_reference_prefix", match="prefix", url=f"https://github.com/{issue_repo}/issues/{issue_num}/", reason=f"{base_reason} URL prefix"),
        ScrubEntry(kind="cross_reference", match="exact", url=f"https://api.github.com/repos/{issue_repo}/issues/{issue_num}", reason=base_reason),
        ScrubEntry(kind="cross_reference_prefix", match="prefix", url=f"https://api.github.com/repos/{issue_repo}/issues/{issue_num}/", reason=f"{base_reason} API URL prefix"),
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
        if not isinstance(item, dict):
            continue
        typename = item.get("__typename")
        if typename == "CrossReferencedEvent":
            src = item.get("source") if isinstance(item.get("source"), dict) else None
            if src is None or (not src.get("url") and not src.get("number")):
                deny_unresolved_scope(entries)
                continue
            src_url = src.get("url") if isinstance(src.get("url"), str) else ""
            src_num = src.get("number") if type(src.get("number")) is int else None
            src_type = src.get("__typename") if isinstance(src.get("__typename"), str) else None
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
                if src_number:
                    entries.extend(get_referencing_issue_scrub_entries(src_repo, src_number, base_reason="cross-references target issue"))
                elif src_url:
                    entries.append(ScrubEntry(kind="cross_reference", match="exact", url=src_url, reason="cross-references target issue"))
            if item.get("url") and isinstance(item.get("url"), str):
                entries.append(ScrubEntry(kind="cross_reference", match="exact", url=item["url"], reason="cross-reference event on target issue"))

        elif typename == "ConnectedEvent":
            conn_candidates = [conn for conn in (item.get("source"), item.get("subject")) if isinstance(conn, dict)]
            outside_candidates = []
            for conn_item in conn_candidates:
                c_url = conn_item.get("url") if isinstance(conn_item.get("url"), str) else ""
                c_num = conn_item.get("number") if type(conn_item.get("number")) is int else None
                c_type = conn_item.get("__typename") if isinstance(conn_item.get("__typename"), str) else None
                parsed = _parse_github_item_url(c_url)
                c_repo = parsed[0] if parsed else repo
                c_kind = parsed[1] if parsed else ("pull" if c_type == "PullRequest" else "issues")
                c_number = parsed[2] if parsed else c_num

                if c_repo == repo and c_number in target_issue_numbers and c_kind == "issues":
                    continue

                if c_url or c_number:
                    outside_candidates.append((conn_item, c_repo, c_kind, c_number, c_url, c_type))

            if not outside_candidates:
                deny_unresolved_scope(entries)
                continue

            for conn_item, c_repo, c_kind, c_number, c_url, c_type in outside_candidates:
                if c_kind == "pull" or c_type == "PullRequest":
                    if c_number:
                        entries.extend(get_referencing_pr_scrub_entries(c_repo, c_number, base_reason="connected to target issue"))
                    elif c_url:
                        entries.append(ScrubEntry(kind="cross_reference", match="exact", url=c_url, reason="connected to target issue"))
                else:
                    if c_number:
                        entries.extend(get_referencing_issue_scrub_entries(c_repo, c_number, base_reason="connected to target issue"))
                    elif c_url:
                        entries.append(ScrubEntry(kind="cross_reference", match="exact", url=c_url, reason="connected to target issue"))


def _add_linked_refs_scrub_entries(
    entries: list[ScrubEntry],
    issue_data: dict[str, Any],
    repo: str,
    target_issue_numbers: set[int],
    warnings_list: list[str] | None = None,
) -> None:
    """Scrub issue references discovered in the issue discussion corpus."""
    from hermetic_slice.intake import linked_refs, InvalidReferenceError

    comments_nodes = list((issue_data.get("comments") or {}).get("nodes") or [])
    issue_body = issue_data.get("body")
    text_corpus = ([issue_body] if isinstance(issue_body, str) else []) + [
        c.get("body") for c in comments_nodes if isinstance(c, dict) and isinstance(c.get("body"), str)
    ]
    for text_sample in text_corpus:
        try:
            discovered = linked_refs(repo, "", text_sample)
        except (InvalidReferenceError, ValueError):
            deny_unresolved_scope(entries)
            if warnings_list is not None:
                if "unverifiable_content_excluded" not in warnings_list:
                    warnings_list.append("unverifiable_content_excluded")
                warnings_list.append("invalid_reference_number; repository_scope_denied")
            continue
        for ref in discovered:
            if ref.number not in target_issue_numbers:
                if ref.kind == "github":
                    entries.extend(get_referencing_issue_scrub_entries(
                        repo, ref.number, base_reason="referenced in target issue discussion"
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
    unresolved_target_refs: Sequence[Any] | None = None,
) -> ScrubResult:
    """Perform mutable-content revisioning and thread-scrub list generation.

    If token is not configured, or if GraphQL returns errors/malformed responses,
    excludes unverifiable content and denies unresolved repository resources.
    """
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repo):
        raise GraphQLResponseError("invalid_repository")
    owner, name = repo.split("/", 1)
    base_entries = get_solution_pr_scrub_entries(repo, pr_number, commit_shas=commit_shas)

    if unresolved_target_refs:
        for uref in unresolved_target_refs:
            num = getattr(uref, "number", None)
            kind = getattr(uref, "kind", "github")
            if kind == "github" and isinstance(num, int) and num > 0:
                base_entries.append(ScrubEntry(kind="cross_reference", match="exact", url=f"https://github.com/{repo}/issues/{num}", reason="unresolved target issue"))
                base_entries.append(ScrubEntry(kind="cross_reference", match="exact", url=f"https://api.github.com/repos/{repo}/issues/{num}", reason="unresolved target issue"))

    if target_issue_numbers is None:
        target_issue_numbers = [target_issue_number] if target_issue_number is not None else []

    unrev_warning = "unverifiable_content_excluded"

    # Fallback state if token missing or query fails
    def make_fallback(warning_msg: str | None = None, entries: list[ScrubEntry] | None = None) -> ScrubResult:
        if warning_msg and warning_msg not in warnings_list:
            warnings_list.append(warning_msg)
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)
        denied = list(entries if entries is not None else base_entries)
        deny_unresolved_scope(denied)
        return ScrubResult(
            problem_statement="",
            hints_text="",
            problem_statement_revision="excluded",
            chosen_revision_edited_at=None,
            edits_ignored=0,
            hints_revisioned=False,
            scrub_entries=dedupe_and_sort_entries(denied),
            hints_excluded_no_history=0,
            hints_excluded_no_created_at=0,
        )

    if not token and http_post_json is None:
        return make_fallback(entries=base_entries)

    post_client = http_post_json if http_post_json is not None else make_http_post_json(
        cache_dir, token=token, snapshot_id=snapshot_id, refresh=refresh
    )

    begin_snapshot = getattr(post_client, "begin_snapshot", None)
    if begin_snapshot is not None:
        post_client = begin_snapshot(snapshot_id=snapshot_id, refresh=refresh)
    post_client = _RunClient(post_client)

    # 1. Fetch Pull Request scrub items (reviews, review comments, conversation comments)
    pr_entries: list[ScrubEntry] = list(base_entries)
    try:
        pr_data = fetch_pull_request_data(post_client, owner, name, pr_number)
        for review in (pr_data.get("reviews") or {}).get("nodes") or []:
            rev_url = review.get("url")
            rev_id = review.get("databaseId")
            if not rev_id and rev_url:
                m = re.search(r"#pullrequestreview-(\d+)", rev_url)
                if m and len(m.group(1)) <= 18:
                    rev_id = int(m.group(1))
            if not rev_id and not rev_url:
                deny_unresolved_scope(pr_entries)
                if unrev_warning not in warnings_list:
                    warnings_list.append(unrev_warning)
                warnings_list.append("unidentified_pr_review; repository_scope_denied")
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
                    if m and len(m.group(1)) <= 18:
                        rc_id = int(m.group(1))
                if not rc_id and not rc_url:
                    deny_unresolved_scope(pr_entries)
                    if unrev_warning not in warnings_list:
                        warnings_list.append(unrev_warning)
                    warnings_list.append("unidentified_review_comment; repository_scope_denied")
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
                if m and len(m.group(1)) <= 18:
                    c_id = int(m.group(1))
            if not c_id and not c_url:
                deny_unresolved_scope(pr_entries)
                if unrev_warning not in warnings_list:
                    warnings_list.append(unrev_warning)
                warnings_list.append("unidentified_pr_comment; repository_scope_denied")
            if c_url:
                pr_entries.append(ScrubEntry(kind="comment", match="exact", url=c_url, reason="solution PR conversation comment HTML URL"))
            if c_id:
                pr_entries.append(ScrubEntry(
                    kind="comment",
                    match="exact",
                    url=f"https://api.github.com/repos/{repo}/issues/comments/{c_id}",
                    reason="solution PR conversation comment API URL",
                ))
    except Exception:
        return make_fallback("pr_discovery_failed; repository_scope_denied", pr_entries)

    # Case A: No target GitHub issue to revision (Trac, Django, no issue reference)
    if len(target_issue_numbers) == 0:
        if unresolved_target_refs:
            deny_unresolved_scope(pr_entries)
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)
        return ScrubResult(
            problem_statement="",
            hints_text="",
            problem_statement_revision="excluded",
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
            except Exception:
                return make_fallback("issue_discovery_failed; repository_scope_denied", all_entries)

            # Scrub post-T_world comments on this issue
            for c in (iss_data.get("comments") or {}).get("nodes") or []:
                if not isinstance(c, dict):
                    continue
                c_created = parse_iso(c.get("createdAt"))
                c_url = c.get("url") if isinstance(c.get("url"), str) else None
                c_id = c.get("databaseId") if type(c.get("databaseId")) is int else None
                if not c_id and c_url:
                    m = re.search(r"#issuecomment-(\d+)", c_url)
                    if m and len(m.group(1)) <= 18:
                        try:
                            c_id = int(m.group(1))
                        except ValueError:
                            c_id = None
                if not c_id and not c_url:
                    deny_unresolved_scope(all_entries)
                    if unrev_warning not in warnings_list:
                        warnings_list.append(unrev_warning)
                    warnings_list.append("unidentified_issue_comment; repository_scope_denied")
                if c_created is None:
                    deny_unresolved_scope(all_entries)
                if c_created and c_created > t_world:
                    if not c_url and not c_id:
                        deny_unresolved_scope(all_entries)
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
            _add_linked_refs_scrub_entries(all_entries, iss_data, repo, target_set, warnings_list)

        if unresolved_target_refs:
            deny_unresolved_scope(all_entries)
            if unrev_warning not in warnings_list:
                warnings_list.append(unrev_warning)

        return ScrubResult(
            problem_statement="",
            hints_text="",
            problem_statement_revision="excluded",
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
    except Exception:
        return make_fallback(
            "issue_discovery_failed; repository_scope_denied",
            entries=pr_entries,
        )

    # 3. Revision target issue problem statement
    title, _ = split_title_and_body(scraped_problem_statement)
    issue_created = parse_iso(issue_data.get("createdAt")) or target_issue_created
    last_edited = parse_iso(issue_data.get("lastEditedAt"))
    user_edits = list((issue_data.get("userContentEdits") or {}).get("nodes") or [])
    includes_created = issue_data.get("includesCreatedEdit")

    rev_res = select_revision(
        scraped_body=issue_data.get("body"),
        created_at=issue_created,
        last_edited_at=last_edited,
        user_content_edits=user_edits,
        t_world=t_world,
        is_target_issue=True,
        includes_created_edit=includes_created,
    )
    if ("lastEditedAt" not in issue_data or
            (issue_data["lastEditedAt"] is not None and last_edited is None) or
            issue_created is None):
        rev_res = RevisionResult("", "excluded", None, 0, "invalid_issue_edit_status; content excluded")
    if rev_res.warning:
        warnings_list.append(rev_res.warning)
    if rev_res.revision_type == "excluded":
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)

    final_problem_statement = reconstruct_problem_statement(title, rev_res.body) if rev_res.revision_type != "excluded" else ""

    # 4. Revision hints & target issue comments scrub
    comments_nodes = list((issue_data.get("comments") or {}).get("nodes") or [])
    kept_comments_bodies: list[str] = []
    kept_comments_verified: list[bool] = []
    hints_excluded_no_history = 0
    hints_excluded_no_created_at = 0
    all_entries = list(pr_entries)

    for comment in comments_nodes:
        if not isinstance(comment, dict):
            hints_excluded_no_history += 1
            continue
        c_created = parse_iso(comment.get("createdAt"))
        c_last_edited = parse_iso(comment.get("lastEditedAt"))
        c_url = comment.get("url") if isinstance(comment.get("url"), str) else None
        c_db_id = comment.get("databaseId") if type(comment.get("databaseId")) is int else None
        if not c_db_id and c_url:
            m = re.search(r"#issuecomment-(\d+)", c_url)
            if m and len(m.group(1)) <= 18:
                try:
                    c_db_id = int(m.group(1))
                except ValueError:
                    c_db_id = None
        c_comment_ident = str(c_db_id) if c_db_id is not None else "unknown"

        if not c_url and not c_db_id:
            deny_unresolved_scope(all_entries)
            if unrev_warning not in warnings_list:
                warnings_list.append(unrev_warning)
            warnings_list.append(f"Comment {c_comment_ident}: missing identity; repository_scope_denied")

        # Defect 4: Comment with missing or unparseable createdAt
        if c_created is None:
            deny_unresolved_scope(all_entries)
            hints_excluded_no_created_at += 1
            warnings_list.append(f"Comment {c_comment_ident}: missing or unparseable createdAt; excluded from hints")
            continue

        if c_created > t_world:
            # Drop from hints; add to thread_scrub list
            if not c_url and not c_db_id:
                deny_unresolved_scope(all_entries)
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
        if ("lastEditedAt" not in comment or
                (comment["lastEditedAt"] is not None and c_last_edited is None)):
            hints_excluded_no_history += 1
            warnings_list.append(f"Comment {c_comment_ident}: invalid_edit_status; excluded from hints")
            continue
        if c_last_edited is None:
            # Never edited: verified revision as of T_world
            c_body = comment.get("body")
            if not isinstance(c_body, str):
                hints_excluded_no_history += 1
                warnings_list.append(f"Comment {c_comment_ident}: invalid_comment_body; excluded from hints")
                continue
            kept_comments_bodies.append(c_body)
            kept_comments_verified.append(True)
            continue

        # Comment has lastEditedAt set: must have usable history
        try:
            c_edits = _paginate(post_client, comment.get("userContentEdits"),
                                 COMMENT_EDITS_PAGE_QUERY, {"id": comment.get("id")},
                                 "CommentEditsPage", ("node", "userContentEdits"))

            # Defect 1: check empty userContentEdits
            if not c_edits:
                hints_excluded_no_history += 1
                warnings_list.append(f"Comment {c_comment_ident}: lastEditedAt set but userContentEdits is missing or empty; excluded from hints")
                continue

            c_includes_created = comment.get("includesCreatedEdit")
            c_body = comment.get("body") if isinstance(comment.get("body"), str) else ""
            c_rev = select_revision(
                scraped_body=c_body,
                created_at=c_created,
                last_edited_at=c_last_edited,
                user_content_edits=c_edits,
                t_world=t_world,
                is_target_issue=False,
                includes_created_edit=c_includes_created,
            )

            # Defect 1: If includesCreatedEdit is not true and no edit qualifies,
            # or chosen diff is null, select_revision excludes the content with a warning
            if c_rev.revision_type in ("as_scraped", "excluded") or c_rev.warning:
                hints_excluded_no_history += 1
                warnings_list.append(f"Comment {c_comment_ident}: {c_rev.warning or 'no usable edit history'}; excluded from hints")
                continue

            kept_comments_bodies.append(c_rev.body)
            kept_comments_verified.append(True)

        except Exception:
            # Defect 5: comment edit pagination failure cleanly caught
            hints_excluded_no_history += 1
            warnings_list.append(f"Comment {c_comment_ident}: failed fetching or processing edit history; excluded from hints")
            continue

    final_hints = "\n".join(kept_comments_bodies) if kept_comments_bodies else ""
    # Defect 1: computed hints_revisioned
    hints_revisioned = bool(all(kept_comments_verified)) if kept_comments_bodies else True

    # 5. Scrub timeline items and linked refs for target issue
    _add_timeline_scrub_entries(all_entries, issue_data, repo, {single_issue_number})
    _add_linked_refs_scrub_entries(all_entries, issue_data, repo, {single_issue_number}, warnings_list)

    if unresolved_target_refs:
        final_problem_statement = ""
        final_hints = ""
        problem_statement_revision = "excluded"
        hints_revisioned = False
        deny_unresolved_scope(all_entries)
        if unrev_warning not in warnings_list:
            warnings_list.append(unrev_warning)
    else:
        problem_statement_revision = rev_res.revision_type

    sorted_scrub_entries = dedupe_and_sort_entries(all_entries)

    return ScrubResult(
        problem_statement=final_problem_statement,
        hints_text=final_hints,
        problem_statement_revision=problem_statement_revision,
        chosen_revision_edited_at=rev_res.edited_at,
        edits_ignored=rev_res.edits_ignored,
        hints_revisioned=hints_revisioned,
        scrub_entries=sorted_scrub_entries,
        hints_excluded_no_history=hints_excluded_no_history,
        hints_excluded_no_created_at=hints_excluded_no_created_at,
    )
