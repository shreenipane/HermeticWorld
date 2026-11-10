"""Cutoff computation for Hermetic World evaluation environments."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence


@dataclass(frozen=True)
class DiscardedDate:
    """Record of an author date discarded during cutoff computation."""

    commit: str
    author_date: datetime
    reason: str


@dataclass(frozen=True)
class FixCommit:
    """A commit in the fix PR with author and committer dates."""

    sha: str
    author_date: datetime
    committer_date: datetime


@dataclass(frozen=True)
class Cutoffs:
    """The computed cutoffs for a task."""

    t_world: datetime
    t_clock: datetime
    discarded: tuple[DiscardedDate, ...]


def ensure_utc(dt: datetime, name: str) -> datetime:
    """Ensure a datetime is timezone-aware and convert it to UTC."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{name} must be timezone-aware, got naive datetime: {dt}")
    return dt.astimezone(timezone.utc)


def compute_cutoffs(
    *,
    issue_created: datetime | None,
    pr_opened: datetime | None,
    fix_commits: Sequence[FixCommit],
    base_commit_time: datetime,
    repo_first_commit_time: datetime,
) -> Cutoffs:
    """Compute t_world and t_clock following Hermetic World cutoff rules."""
    base_utc = ensure_utc(base_commit_time, "base_commit_time")
    repo_first_utc = ensure_utc(repo_first_commit_time, "repo_first_commit_time")

    permanent_candidates: list[datetime] = []
    if issue_created is not None:
        permanent_candidates.append(ensure_utc(issue_created, "issue_created"))
    if pr_opened is not None:
        permanent_candidates.append(ensure_utc(pr_opened, "pr_opened"))

    for fc in fix_commits:
        committer_utc = ensure_utc(fc.committer_date, f"fix_commit[{fc.sha}].committer_date")
        permanent_candidates.append(committer_utc)

    discarded: list[DiscardedDate] = []
    author_candidates: list[tuple[str, datetime]] = []

    for fc in fix_commits:
        author_utc = ensure_utc(fc.author_date, f"fix_commit[{fc.sha}].author_date")
        if author_utc < repo_first_utc:
            discarded.append(
                DiscardedDate(
                    commit=fc.sha,
                    author_date=author_utc,
                    reason="before_first_commit",
                )
            )
        else:
            author_candidates.append((fc.sha, author_utc))

    surviving_author_dates: list[datetime] = []
    for idx, (sha, author_utc) in enumerate(author_candidates):
        other_candidates = list(permanent_candidates) + [
            other_utc for i, (_, other_utc) in enumerate(author_candidates) if i != idx
        ]
        if other_candidates and (min(other_candidates) - author_utc > timedelta(days=90)):
            discarded.append(
                DiscardedDate(
                    commit=sha,
                    author_date=author_utc,
                    reason="outlier_gt_90d",
                )
            )
        else:
            surviving_author_dates.append(author_utc)

    surviving = permanent_candidates + surviving_author_dates
    if not surviving:
        raise ValueError("No candidates survive for t_world")

    t_world = min(surviving)
    t_clock = max(t_world, base_utc)

    return Cutoffs(
        t_world=t_world,
        t_clock=t_clock,
        discarded=tuple(discarded),
    )
