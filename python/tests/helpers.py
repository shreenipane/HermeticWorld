"""Test helpers and synthetic repository builders."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.gitutil import run_git


@dataclass(frozen=True)
class SyntheticRepo:
    """Synthetic repository fixture container."""

    path: Path
    c1: str
    c2: str
    c3_base: str
    c4_fix: str
    c_branch: str
    t_clock: datetime
    tag_light_c2: str
    tag_ann_c1: str
    tag_ann_c2_after: str
    tag_c4: str
    secret_string: str = "SECRET_FIX_7f3a"


def build_synthetic_repo(tmp_path: Path) -> SyntheticRepo:
    """Build a synthetic git repository meeting all task requirements."""
    src = tmp_path / "synthetic_src"
    run_git(["init", "-b", "main", str(src)], cwd=tmp_path)
    run_git(["config", "user.name", "Test User"], cwd=src)
    run_git(["config", "user.email", "test@example.com"], cwd=src)

    # Fixed timestamps
    d1 = "2024-01-01T12:00:00Z"
    d_tag_ann1 = "2024-01-02T12:00:00Z"
    d2 = "2024-01-05T12:00:00Z"
    d3 = "2024-01-10T12:00:00Z"
    d_tclock = datetime.fromisoformat("2024-01-10T12:00:00+00:00")
    d_branch = "2024-01-12T12:00:00Z"
    d4 = "2024-01-15T12:00:00Z"
    d_tag_ann2 = "2024-01-20T12:00:00Z"

    # Commit c1
    (src / "README.md").write_text("Repository root\n", encoding="utf-8")
    run_git(["add", "README.md"], cwd=src)
    run_git(["commit", "-m", "commit c1"], cwd=src, env={"GIT_AUTHOR_DATE": d1, "GIT_COMMITTER_DATE": d1})
    c1 = run_git(["rev-parse", "HEAD"], cwd=src).decode("ascii").strip()

    # Annotated tag on c1 dated before t_clock
    tag_ann_c1 = "v0.1-ann"
    run_git(["tag", "-a", tag_ann_c1, "-m", "tag c1 before t_clock", c1], cwd=src, env={"GIT_COMMITTER_DATE": d_tag_ann1})

    # Commit c2
    (src / "file2.txt").write_text("Second file content\n", encoding="utf-8")
    run_git(["add", "file2.txt"], cwd=src)
    run_git(["commit", "-m", "commit c2"], cwd=src, env={"GIT_AUTHOR_DATE": d2, "GIT_COMMITTER_DATE": d2})
    c2 = run_git(["rev-parse", "HEAD"], cwd=src).decode("ascii").strip()

    # Lightweight tag on c2
    tag_light_c2 = "v0.2-light"
    run_git(["tag", tag_light_c2, c2], cwd=src)

    # Annotated tag on c2 dated AFTER t_clock
    tag_ann_c2_after = "v0.2-ann-future"
    run_git(["tag", "-a", tag_ann_c2_after, "-m", "tag c2 after t_clock", c2], cwd=src, env={"GIT_COMMITTER_DATE": d_tag_ann2})

    # Commit c3 (the base commit)
    (src / "file3.txt").write_text("Base commit file\n", encoding="utf-8")
    run_git(["add", "file3.txt"], cwd=src)
    run_git(["commit", "-m", "commit c3 base"], cwd=src, env={"GIT_AUTHOR_DATE": d3, "GIT_COMMITTER_DATE": d3})
    c3_base = run_git(["rev-parse", "HEAD"], cwd=src).decode("ascii").strip()

    # Second branch with a commit after the base
    run_git(["checkout", "-b", "feature-post-base"], cwd=src)
    (src / "feature.txt").write_text("Branch feature content\n", encoding="utf-8")
    run_git(["add", "feature.txt"], cwd=src)
    run_git(["commit", "-m", "feature commit"], cwd=src, env={"GIT_AUTHOR_DATE": d_branch, "GIT_COMMITTER_DATE": d_branch})
    c_branch = run_git(["rev-parse", "HEAD"], cwd=src).decode("ascii").strip()

    # Back to main for c4 (fix)
    run_git(["checkout", "main"], cwd=src)
    (src / "fix.py").write_text("SECRET_FIX_7f3a\n", encoding="utf-8")
    run_git(["add", "fix.py"], cwd=src)
    run_git(["commit", "-m", "commit c4 fix"], cwd=src, env={"GIT_AUTHOR_DATE": d4, "GIT_COMMITTER_DATE": d4})
    c4_fix = run_git(["rev-parse", "HEAD"], cwd=src).decode("ascii").strip()

    # Tag on c4
    tag_c4 = "v0.4-fix"
    run_git(["tag", tag_c4, c4_fix], cwd=src)

    # Stash entry
    (src / "uncommitted.txt").write_text("Work in progress\n", encoding="utf-8")
    run_git(["add", "uncommitted.txt"], cwd=src)
    run_git(["stash", "push", "-m", "WIP stash"], cwd=src)

    # Extra refs: refs/pull/1/head and refs/original/refs/heads/main
    run_git(["update-ref", "refs/pull/1/head", c4_fix], cwd=src)
    run_git(["update-ref", "refs/original/refs/heads/main", c4_fix], cwd=src)

    return SyntheticRepo(
        path=src,
        c1=c1,
        c2=c2,
        c3_base=c3_base,
        c4_fix=c4_fix,
        c_branch=c_branch,
        t_clock=d_tclock,
        tag_light_c2=tag_light_c2,
        tag_ann_c1=tag_ann_c1,
        tag_ann_c2_after=tag_ann_c2_after,
        tag_c4=tag_c4,
    )


@dataclass(frozen=True)
class IntakeSyntheticRepo:
    """Synthetic repository fixture for intake tests with merged root histories."""

    path: Path
    base_sha: str
    root1_sha: str
    root2_sha: str
    base_commit_time: datetime
    repo_first_commit_time: datetime


def build_intake_synthetic_repo(tmp_path: Path, base_date: str = "2019-11-15T00:00:00Z") -> IntakeSyntheticRepo:
    """Build a synthetic git repo with two root commits and a base commit."""
    src = tmp_path / "intake_synthetic_src"
    run_git(["init", "-b", "main", str(src)], cwd=tmp_path)
    run_git(["config", "user.name", "Intake Tester"], cwd=src)
    run_git(["config", "user.email", "tester@example.com"], cwd=src)

    (src / "base_file.txt").write_text("Intake base file\n", encoding="utf-8")
    run_git(["add", "base_file.txt"], cwd=src)
    tree = run_git(["write-tree"], cwd=src).decode("ascii").strip()

    d_r1_a = "2015-01-01T00:00:00Z"
    d_r1_c = "2015-01-02T00:00:00Z"
    d_r2_a = "2015-03-01T00:00:00Z"
    d_r2_c = "2015-03-02T00:00:00Z"

    r1 = run_git(
        ["commit-tree", tree, "-m", "root 1"],
        cwd=src,
        env={"GIT_AUTHOR_DATE": d_r1_a, "GIT_COMMITTER_DATE": d_r1_c},
    ).decode("ascii").strip()

    r2 = run_git(
        ["commit-tree", tree, "-m", "root 2"],
        cwd=src,
        env={"GIT_AUTHOR_DATE": d_r2_a, "GIT_COMMITTER_DATE": d_r2_c},
    ).decode("ascii").strip()

    base_sha = run_git(
        ["commit-tree", tree, "-p", r1, "-p", r2, "-m", "base commit"],
        cwd=src,
        env={"GIT_AUTHOR_DATE": base_date, "GIT_COMMITTER_DATE": base_date},
    ).decode("ascii").strip()

    run_git(["update-ref", "refs/heads/main", base_sha], cwd=src)

    base_dt = ensure_utc(datetime.fromisoformat(base_date), "base_date")
    r1_dt = ensure_utc(datetime.fromisoformat(d_r1_a), "r1_dt")

    return IntakeSyntheticRepo(
        path=src,
        base_sha=base_sha,
        root1_sha=r1,
        root2_sha=r2,
        base_commit_time=base_dt,
        repo_first_commit_time=r1_dt,
    )

