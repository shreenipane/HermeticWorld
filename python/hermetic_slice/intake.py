"""SWE-bench task intake: metadata fetching, cutoff computation, and staging."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import urllib.parse

from hermetic_slice.cutoffs import Cutoffs, FixCommit, compute_cutoffs, ensure_utc
from hermetic_slice.gitutil import GitError, run_git
from hermetic_slice.http import HttpError, HttpGet, _atomic_write_bytes


class IntakeError(Exception):
    """Raised when task intake fails verification or fetching."""


@dataclass(frozen=True)
class IssueRef:
    """A reference to an issue linked from a pull request."""

    kind: str  # "github" or "trac"
    number: int


def iso_utc(dt: datetime) -> str:
    """Format datetime as UTC ISO 8601 string ending with Z."""
    utc_dt = ensure_utc(dt, "dt")
    if utc_dt.microsecond:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_verified(http_get: HttpGet, cache_dir: Path) -> dict[str, dict]:
    """Load SWE-bench Verified dataset rows, using local cache or HF API."""
    cache_file = cache_dir / "swebench_verified.jsonl"
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
            f"dataset=princeton-nlp/SWE-bench_Verified&config=default&split=test&offset={offset}&length={length}"
        )
        page_bytes = http_get(url)
        page = json.loads(page_bytes.decode("utf-8"))

        if page.get("partial") is True:
            raise IntakeError(f"HuggingFace dataset returned partial page at offset {offset}")

        if offset == 0:
            page_total = page.get("num_rows_total")
            if not isinstance(page_total, int) or isinstance(page_total, bool):
                raise IntakeError(f"First page missing integer num_rows_total: {page_total!r}")
            num_rows_total = page_total
        else:
            page_total = page.get("num_rows_total")
            if page_total != num_rows_total:
                raise IntakeError(f"Inconsistent num_rows_total: {page_total} vs {num_rows_total}")

        page_rows = page.get("rows", [])
        if not page_rows:
            break

        for item in page_rows:
            truncated = item.get("truncated_cells")
            if truncated:
                inst = item.get("row", {}).get("instance_id", "unknown")
                raise IntakeError(f"Row {inst} has non-empty truncated_cells: {truncated}")

            row_data = dict(item["row"])
            if isinstance(row_data.get("FAIL_TO_PASS"), str):
                row_data["FAIL_TO_PASS"] = json.loads(row_data["FAIL_TO_PASS"])
            if isinstance(row_data.get("PASS_TO_PASS"), str):
                row_data["PASS_TO_PASS"] = json.loads(row_data["PASS_TO_PASS"])

            inst_id = row_data["instance_id"]
            if inst_id in rows_collected:
                if rows_collected[inst_id] != row_data:
                    raise IntakeError(f"Duplicate instance_id {inst_id} with conflicting content")
            else:
                rows_collected[inst_id] = row_data

        offset += len(page_rows)
        if num_rows_total is not None and offset >= num_rows_total:
            break

    if num_rows_total is not None and len(rows_collected) != num_rows_total:
        raise IntakeError(f"Unique row count ({len(rows_collected)}) != num_rows_total ({num_rows_total})")

    cache_dir.mkdir(parents=True, exist_ok=True)
    sorted_rows = sorted(rows_collected.values(), key=lambda r: r["instance_id"])
    content_bytes = "".join(json.dumps(r, sort_keys=True) + "\n" for r in sorted_rows).encode("utf-8")
    _atomic_write_bytes(cache_file, content_bytes)

    return rows_collected


def _strip_html_comments(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def linked_refs(repo: str, title: str, body: str) -> list[IssueRef]:
    """Extract linked issue references from a pull request title and body."""
    title_clean = _strip_html_comments(title or "")
    body_clean = _strip_html_comments(body or "")

    def _extract_from_text(text: str) -> list[IssueRef]:
        if not text:
            return []
        items: list[tuple[int, IssueRef]] = []

        if repo == "django/django":
            trac_url_pattern = re.compile(r"https://code\.djangoproject\.com/ticket/(\d+)\b")
            for m in trac_url_pattern.finditer(text):
                items.append((m.start(), IssueRef(kind="trac", number=int(m.group(1)))))

            django_ticket_pattern = re.compile(
                r"\b(?:close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved|refs?):?\s+#(\d+)\b",
                re.IGNORECASE,
            )
            for m in django_ticket_pattern.finditer(text):
                items.append((m.start(), IssueRef(kind="trac", number=int(m.group(1)))))
        else:
            gh_pattern = re.compile(
                rf"\b(?:close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved):?\s+(?:#(\d+)|https://github\.com/{re.escape(repo)}/issues/(\d+))\b",
                re.IGNORECASE,
            )
            for m in gh_pattern.finditer(text):
                num_str = m.group(1) or m.group(2)
                items.append((m.start(), IssueRef(kind="github", number=int(num_str))))

        items.sort(key=lambda x: x[0])
        return [ref for _, ref in items]

    title_refs = _extract_from_text(title_clean)
    body_refs = _extract_from_text(body_clean)

    deduped: list[IssueRef] = []
    seen: set[IssueRef] = set()
    for ref in title_refs + body_refs:
        if ref not in seen:
            seen.add(ref)
            deduped.append(ref)

    return deduped


def fetch_issue_created(
    ref: IssueRef,
    repo: str,
    http_get: HttpGet,
    warnings_list: list[str],
) -> datetime | None:
    """Fetch the creation datetime of an issue ref, ignoring PRs disguised as issues."""
    if ref.kind == "github":
        url = f"https://api.github.com/repos/{repo}/issues/{ref.number}"
        try:
            raw_data = http_get(url)
        except HttpError as exc:
            if exc.status in (404, 410):
                warnings_list.append(f"issue {ref.kind}#{ref.number} could not be fetched (HTTP {exc.status}); ignored")
                return None
            raise
        data = json.loads(raw_data.decode("utf-8"))
        if data.get("pull_request") is not None:
            msg = f"GitHub issue #{ref.number} in {repo} is actually a pull request; ignored"
            warnings_list.append(msg)
            return None
        created_str = data["created_at"]
        return ensure_utc(datetime.fromisoformat(created_str), f"github_issue_{ref.number}")

    if ref.kind == "trac":
        url = f"https://code.djangoproject.com/ticket/{ref.number}"
        try:
            raw_data = http_get(url)
        except HttpError as exc:
            if exc.status in (404, 410):
                warnings_list.append(f"issue {ref.kind}#{ref.number} could not be fetched (HTTP {exc.status}); ignored")
                return None
            raise
        html_text = raw_data.decode("utf-8", errors="replace")
        m = re.search(r'Opened\s+<a\s+class="timeline"\s+href="/timeline\?from=([^"&]+)', html_text)
        if not m:
            raise IntakeError(f"Could not parse opened date from Trac ticket {ref.number}")
        unquoted = urllib.parse.unquote(m.group(1))
        dt = datetime.fromisoformat(unquoted)
        return ensure_utc(dt, f"trac_ticket_{ref.number}")

    raise ValueError(f"Unsupported issue ref kind: {ref.kind}")


def repo_dates(
    repo: str,
    base_commit: str,
    cache_dir: Path,
    clone_url: str | None = None,
) -> tuple[datetime, datetime]:
    """Clone or fetch bare repo, returning (base_commit_time, repo_first_commit_time)."""
    owner, name = repo.split("/", 1)
    repos_dir = cache_dir / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = repos_dir / f"{owner}__{name}.git"

    url = clone_url if clone_url is not None else f"https://github.com/{repo}.git"
    is_https = (clone_url is None) or clone_url.startswith("https://")

    if not repo_dir.exists():
        cmd = ["clone", "--bare"]
        if is_https:
            cmd.append("--filter=blob:none")
        cmd.extend([url, str(repo_dir)])
        run_git(cmd, cwd=cache_dir)

    has_base = False
    try:
        run_git(["cat-file", "-e", f"{base_commit}^{{commit}}"], cwd=repo_dir)
        has_base = True
    except GitError:
        has_base = False

    if not has_base:
        run_git(
            ["fetch", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"],
            cwd=repo_dir,
        )
        try:
            run_git(["cat-file", "-e", f"{base_commit}^{{commit}}"], cwd=repo_dir)
        except GitError:
            raise IntakeError(f"Base commit {base_commit} not found in repository {repo}") from None

    base_out = run_git(["log", "-1", "--format=%cI", base_commit], cwd=repo_dir).decode("ascii").strip()
    base_commit_time = ensure_utc(datetime.fromisoformat(base_out), "base_commit_time")

    roots_out = run_git(["rev-list", "--max-parents=0", base_commit], cwd=repo_dir).decode("ascii")
    root_shas = [line.strip() for line in roots_out.splitlines() if line.strip()]
    if not root_shas:
        raise IntakeError(f"No root commits reachable from base commit {base_commit}")

    root_dates: list[datetime] = []
    for root_sha in root_shas:
        log_out = run_git(["log", "-1", "--format=%aI%x00%cI", root_sha], cwd=repo_dir).decode("ascii").strip()
        author_str, committer_str = log_out.split("\x00")
        author_dt = ensure_utc(datetime.fromisoformat(author_str), f"root_{root_sha}_author")
        committer_dt = ensure_utc(datetime.fromisoformat(committer_str), f"root_{root_sha}_committer")
        root_dates.append(min(author_dt, committer_dt))

    repo_first_commit_time = min(root_dates)
    return (base_commit_time, repo_first_commit_time)


def intake_task(
    instance_id: str,
    rows: dict[str, dict],
    http_get: HttpGet,
    cache_dir: Path,
    out_dir: Path,
    clone_url: str | None = None,
) -> Path:
    """Ingest a SWE-bench task, computing cutoffs and creating isolated staging/agent files."""
    if instance_id not in rows:
        raise IntakeError(f"Task instance ID {instance_id} not found in verified rows")

    row = rows[instance_id]
    repo = row["repo"]
    pr_number = int(instance_id.rsplit("-", 1)[-1])

    pr_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    pr_data = json.loads(http_get(pr_url).decode("utf-8"))
    pr_opened = ensure_utc(datetime.fromisoformat(pr_data["created_at"]), "pr_opened")
    pr_title = pr_data.get("title") or ""
    pr_body = pr_data.get("body") or ""

    fix_commits: list[FixCommit] = []
    page_num = 1
    while True:
        commits_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/commits?per_page=100"
        if page_num > 1:
            commits_url += f"&page={page_num}"
        commits_data = json.loads(http_get(commits_url).decode("utf-8"))
        if not commits_data:
            break
        for c in commits_data:
            sha = c["sha"]
            a_dt = ensure_utc(datetime.fromisoformat(c["commit"]["author"]["date"]), f"commit_{sha}_author")
            c_dt = ensure_utc(datetime.fromisoformat(c["commit"]["committer"]["date"]), f"commit_{sha}_committer")
            fix_commits.append(FixCommit(sha=sha, author_date=a_dt, committer_date=c_dt))
        if len(commits_data) < 100:
            break
        page_num += 1

    warnings_list: list[str] = []
    refs = linked_refs(repo, pr_title, pr_body)
    issue_refs_meta: list[dict] = []
    resolved_issue_refs: list[tuple[datetime, IssueRef]] = []

    for ref in refs:
        created_dt = fetch_issue_created(ref, repo, http_get, warnings_list)
        issue_refs_meta.append({
            "created_at": iso_utc(created_dt) if created_dt else None,
            "kind": ref.kind,
            "number": ref.number,
        })
        if created_dt is not None:
            resolved_issue_refs.append((created_dt, ref))

    if resolved_issue_refs:
        earliest_issue_created, earliest_ref = min(resolved_issue_refs, key=lambda pair: pair[0])
        issue_source = f"{earliest_ref.kind}#{earliest_ref.number}"
    else:
        earliest_issue_created = None
        issue_source = "none"

    if not refs:
        warnings_list.append(f"No issue reference found in PR {pr_number} body")
    elif not resolved_issue_refs:
        warnings_list.append(f"No valid issue reference resolved for PR {pr_number}")

    warnings_list.append("problem_statement taken as scraped, not at its revision as of T_world (Phase 0 gap, spec section 4)")

    base_commit_time, repo_first_commit_time = repo_dates(
        repo,
        row["base_commit"],
        cache_dir,
        clone_url=clone_url,
    )

    cutoffs = compute_cutoffs(
        issue_created=earliest_issue_created,
        pr_opened=pr_opened,
        fix_commits=fix_commits,
        base_commit_time=base_commit_time,
        repo_first_commit_time=repo_first_commit_time,
    )

    image = "swebench/sweb.eval.x86_64." + instance_id.lower().replace("__", "_1776_") + ":latest"

    task_json_data = {
        "base_commit": row["base_commit"],
        "cutoffs": {
            "discarded": [
                {
                    "author_date": iso_utc(d.author_date),
                    "commit": d.commit,
                    "reason": d.reason,
                }
                for d in cutoffs.discarded
            ],
            "t_clock": iso_utc(cutoffs.t_clock),
            "t_world": iso_utc(cutoffs.t_world),
        },
        "dataset_created_at": row.get("created_at", ""),
        "dates": {
            "base_commit_time": iso_utc(base_commit_time),
            "fix_commits": [
                {
                    "author_date": iso_utc(fc.author_date),
                    "committer_date": iso_utc(fc.committer_date),
                    "sha": fc.sha,
                }
                for fc in fix_commits
            ],
            "issue_created": iso_utc(earliest_issue_created) if earliest_issue_created else None,
            "pr_opened": iso_utc(pr_opened),
            "repo_first_commit_time": iso_utc(repo_first_commit_time),
        },
        "environment_setup_commit": row.get("environment_setup_commit", ""),
        "image": image,
        "instance_id": instance_id,
        "issue_source": issue_source,
        "pr_number": pr_number,
        "repo": repo,
        "schema": "hermetic-slice-task/v1",
        "sources": {
            "issue_refs": issue_refs_meta,
            "pr_url": pr_url,
        },
        "tests": {
            "FAIL_TO_PASS": row.get("FAIL_TO_PASS", []),
            "PASS_TO_PASS": row.get("PASS_TO_PASS", []),
        },
        "version": row.get("version", ""),
        "warnings": warnings_list,
    }

    task_dir = out_dir / instance_id
    agent_dir = task_dir / "agent"
    staging_dir = task_dir / "staging"
    if agent_dir.exists():
        shutil.rmtree(agent_dir)
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    agent_dir.mkdir(parents=True, exist_ok=True)
    staging_dir.mkdir(parents=True, exist_ok=True)

    (task_dir / "task.json").write_text(json.dumps(task_json_data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (agent_dir / "problem_statement.md").write_text(row.get("problem_statement", ""), encoding="utf-8", newline="")
    (staging_dir / "gold.patch").write_text(row.get("patch", ""), encoding="utf-8", newline="")
    (staging_dir / "test.patch").write_text(row.get("test_patch", ""), encoding="utf-8", newline="")
    (staging_dir / "hints.txt").write_text(row.get("hints_text", ""), encoding="utf-8", newline="")

    return task_dir
