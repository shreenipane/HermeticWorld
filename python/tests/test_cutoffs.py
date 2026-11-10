"""Tests for cutoff computation rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hermetic_slice.cutoffs import (
    Cutoffs,
    DiscardedDate,
    FixCommit,
    compute_cutoffs,
    ensure_utc,
)


def _dt(iso_str: str) -> datetime:
    """Helper to construct UTC datetimes from ISO strings."""
    return datetime.fromisoformat(iso_str).astimezone(timezone.utc)


def test_earliest_candidate_wins() -> None:
    """The earliest candidate date determines t_world."""
    t1 = _dt("2024-01-01T00:00:00Z")
    t2 = _dt("2024-01-05T00:00:00Z")
    t3 = _dt("2024-01-10T00:00:00Z")
    t_base = _dt("2024-01-15T00:00:00Z")
    t_repo_first = _dt("2023-01-01T00:00:00Z")

    cutoffs = compute_cutoffs(
        issue_created=t1,
        pr_opened=t2,
        fix_commits=[FixCommit(sha="abc", author_date=t3, committer_date=t3)],
        base_commit_time=t_base,
        repo_first_commit_time=t_repo_first,
    )
    assert cutoffs.t_world == t1
    assert cutoffs.t_clock == t_base
    assert cutoffs.discarded == ()


def test_t_clock_uses_base_when_later() -> None:
    """t_clock is max(t_world, base_commit_time)."""
    t_world_candidate = _dt("2024-01-01T00:00:00Z")
    t_base = _dt("2024-02-01T00:00:00Z")
    t_first = _dt("2023-01-01T00:00:00Z")

    cutoffs = compute_cutoffs(
        issue_created=t_world_candidate,
        pr_opened=None,
        fix_commits=[],
        base_commit_time=t_base,
        repo_first_commit_time=t_first,
    )
    assert cutoffs.t_world == t_world_candidate
    assert cutoffs.t_clock == t_base

    # When t_world is later than base_commit_time
    t_base_early = _dt("2023-12-01T00:00:00Z")
    cutoffs2 = compute_cutoffs(
        issue_created=t_world_candidate,
        pr_opened=None,
        fix_commits=[],
        base_commit_time=t_base_early,
        repo_first_commit_time=t_first,
    )
    assert cutoffs2.t_world == t_world_candidate
    assert cutoffs2.t_clock == t_world_candidate


def test_discard_reason_before_first_commit() -> None:
    """An author date before repo_first_commit_time is discarded with reason before_first_commit."""
    t_first = _dt("2023-01-01T00:00:00Z")
    t_implausible = _dt("2022-06-01T00:00:00Z")
    t_valid = _dt("2024-01-01T00:00:00Z")

    cutoffs = compute_cutoffs(
        issue_created=t_valid,
        pr_opened=None,
        fix_commits=[FixCommit(sha="c1", author_date=t_implausible, committer_date=t_valid)],
        base_commit_time=t_valid,
        repo_first_commit_time=t_first,
    )
    assert cutoffs.t_world == t_valid
    assert len(cutoffs.discarded) == 1
    assert cutoffs.discarded[0].commit == "c1"
    assert cutoffs.discarded[0].author_date == t_implausible
    assert cutoffs.discarded[0].reason == "before_first_commit"


def test_discard_reason_outlier_gt_90d() -> None:
    """An author date more than 90 days before all other candidates is discarded as outlier_gt_90d."""
    t_first = _dt("2020-01-01T00:00:00Z")
    t_other = _dt("2024-05-01T00:00:00Z")
    t_outlier = t_other - timedelta(days=91)

    cutoffs = compute_cutoffs(
        issue_created=t_other,
        pr_opened=None,
        fix_commits=[FixCommit(sha="c1", author_date=t_outlier, committer_date=t_other)],
        base_commit_time=t_other,
        repo_first_commit_time=t_first,
    )
    assert cutoffs.t_world == t_other
    assert len(cutoffs.discarded) == 1
    assert cutoffs.discarded[0].commit == "c1"
    assert cutoffs.discarded[0].author_date == t_outlier
    assert cutoffs.discarded[0].reason == "outlier_gt_90d"


def test_author_date_not_discarded_within_90_days() -> None:
    """An author date within 90 days of another candidate is retained."""
    t_first = _dt("2020-01-01T00:00:00Z")
    t_committer = _dt("2024-05-01T00:00:00Z")
    t_author = t_committer - timedelta(days=89)

    cutoffs = compute_cutoffs(
        issue_created=None,
        pr_opened=None,
        fix_commits=[FixCommit(sha="c1", author_date=t_author, committer_date=t_committer)],
        base_commit_time=t_committer,
        repo_first_commit_time=t_first,
    )
    assert cutoffs.t_world == t_author
    assert cutoffs.discarded == ()


def test_naive_datetimes_are_rejected() -> None:
    """Naive datetimes in any argument cause ValueError."""
    aware = _dt("2024-01-01T00:00:00Z")
    naive = datetime(2024, 1, 1, 0, 0, 0)

    with pytest.raises(ValueError, match="base_commit_time must be timezone-aware"):
        compute_cutoffs(
            issue_created=aware,
            pr_opened=aware,
            fix_commits=[],
            base_commit_time=naive,
            repo_first_commit_time=aware,
        )

    with pytest.raises(ValueError, match="repo_first_commit_time must be timezone-aware"):
        compute_cutoffs(
            issue_created=aware,
            pr_opened=aware,
            fix_commits=[],
            base_commit_time=aware,
            repo_first_commit_time=naive,
        )

    with pytest.raises(ValueError, match="issue_created must be timezone-aware"):
        compute_cutoffs(
            issue_created=naive,
            pr_opened=aware,
            fix_commits=[],
            base_commit_time=aware,
            repo_first_commit_time=aware,
        )

    with pytest.raises(ValueError, match="author_date must be timezone-aware"):
        compute_cutoffs(
            issue_created=aware,
            pr_opened=aware,
            fix_commits=[FixCommit(sha="c1", author_date=naive, committer_date=aware)],
            base_commit_time=aware,
            repo_first_commit_time=aware,
        )


def test_no_candidates_raises_value_error() -> None:
    """ValueError is raised if no candidates exist or survive."""
    aware = _dt("2024-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="No candidates survive for t_world"):
        compute_cutoffs(
            issue_created=None,
            pr_opened=None,
            fix_commits=[],
            base_commit_time=aware,
            repo_first_commit_time=aware,
        )


def test_only_author_dates_ever_discarded() -> None:
    """Committer dates, issue_created, and pr_opened are never discarded."""
    t_first = _dt("2024-01-01T00:00:00Z")
    t_old = _dt("2020-01-01T00:00:00Z")  # well before first commit and > 90d
    t_base = _dt("2024-06-01T00:00:00Z")

    cutoffs = compute_cutoffs(
        issue_created=None,
        pr_opened=None,
        fix_commits=[
            FixCommit(
                sha="c1",
                author_date=_dt("2024-05-01T00:00:00Z"),
                committer_date=t_old,
            )
        ],
        base_commit_time=t_base,
        repo_first_commit_time=t_first,
    )
    # Even though committer date is older than repo_first_commit, it is NOT discarded
    assert cutoffs.t_world == t_old
    assert cutoffs.discarded == ()


def test_non_utc_datetimes_normalized() -> None:
    """Timezone-aware datetimes with non-UTC offsets are normalized to UTC."""
    tz_plus5 = timezone(timedelta(hours=5))
    dt_plus5 = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz_plus5)
    t_first = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t_base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    cutoffs = compute_cutoffs(
        issue_created=dt_plus5,
        pr_opened=None,
        fix_commits=[],
        base_commit_time=t_base,
        repo_first_commit_time=t_first,
    )
    assert cutoffs.t_world.tzinfo == timezone.utc
    assert cutoffs.t_world == datetime(2024, 1, 1, 5, 0, 0, tzinfo=timezone.utc)


def test_ensure_utc_validation() -> None:
    """ensure_utc validates timezone awareness and normalizes to UTC."""
    naive = datetime(2024, 1, 1, 12, 0, 0)
    with pytest.raises(ValueError, match="test_dt must be timezone-aware"):
        ensure_utc(naive, "test_dt")

    tz_plus2 = timezone(timedelta(hours=2))
    aware = datetime(2024, 1, 1, 14, 0, 0, tzinfo=tz_plus2)
    normalized = ensure_utc(aware, "test_dt")
    assert normalized.tzinfo == timezone.utc
    assert normalized == datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

