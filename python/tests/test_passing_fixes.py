"""Collecting known passing fixes into staging/fixes (TR-SC-1)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermetic_slice.passing_fixes import (
    MAX_FIXES,
    FixCollectionError,
    collect,
    find_passing_fixes,
    normalise,
)

IID = "pytest-dev__pytest-6202"


def run(root: Path, split: str, name: str, patch: str | None, resolved, iid: str = IID) -> Path:
    d = root / "evaluation" / split / name / "logs" / iid
    d.mkdir(parents=True)
    if patch is not None:
        (d / "patch.diff").write_text(patch)
    if resolved is not None:
        (d / "report.json").write_text(json.dumps({iid: {"resolved": resolved}}))
    return d


def patch(n: int) -> str:
    return f"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new{n}\n"


def test_only_resolved_fixes_are_collected_deduplicated_and_ordered(tmp_path: Path) -> None:
    root = tmp_path / "exp"
    run(root, "lite", "a", patch(1), True)
    run(root, "lite", "b", patch(1).replace("\n", "\r\n") + "  \n", True)  # duplicate after normalising
    run(root, "verified", "c", patch(2), True)
    run(root, "lite", "d", patch(3), False)       # not resolved
    run(root, "lite", "e", patch(4), None)        # no report
    run(root, "lite", "f", None, True)            # no patch
    run(root, "lite", "g", patch(5), True, iid="other__repo-1")  # other task
    fixes = find_passing_fixes(root, IID)
    assert sorted(fixes) == sorted([normalise(patch(1)), normalise(patch(2))])
    assert fixes == sorted(fixes, key=lambda t: __import__("hashlib").sha256(t.encode()).hexdigest())


def test_collection_is_capped_and_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "exp"
    for i in range(MAX_FIXES + 5):
        run(root, "lite", f"r{i:02d}", patch(i), True)
    first = find_passing_fixes(root, IID)
    assert len(first) == MAX_FIXES
    assert find_passing_fixes(root, IID) == first


def test_written_fixes_are_read_back_in_order_and_replace_the_old_set(tmp_path: Path) -> None:
    root = tmp_path / "exp"
    run(root, "lite", "a", patch(1), True)
    run(root, "lite", "b", patch(2), True)
    task = tmp_path / "task"
    (task / "staging" / "fixes").mkdir(parents=True)
    (task / "staging" / "fixes" / "stale.patch").write_text("old fix")
    names = collect(root, task, IID)
    fixes_dir = task / "staging" / "fixes"
    assert sorted(os.listdir(fixes_dir)) == names
    assert [n[:4] for n in names] == ["001-", "002-"]
    assert [(fixes_dir / n).read_text() for n in names] == find_passing_fixes(root, IID)
    assert not any(p.name.startswith(".fixes") for p in (task / "staging").iterdir())


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    run(outside, "lite", "a", patch(9), True)
    root = tmp_path / "exp"
    (root / "evaluation" / "lite").mkdir(parents=True)
    # A symlinked run directory and a symlinked patch file are both skipped.
    (root / "evaluation" / "lite" / "linked").symlink_to(outside / "evaluation" / "lite" / "a")
    d = run(root, "lite", "real", None, True)
    (d / "patch.diff").symlink_to(outside / "evaluation" / "lite" / "a" / "logs" / IID / "patch.diff")
    assert find_passing_fixes(root, IID) == []
    link_root = tmp_path / "link-root"
    link_root.symlink_to(outside)
    with pytest.raises(FixCollectionError):
        find_passing_fixes(link_root, IID)
    task_link = tmp_path / "task-link"
    task_link.symlink_to(tmp_path)
    with pytest.raises(FixCollectionError):
        collect(root, task_link, IID)


@pytest.mark.parametrize("iid", ["", "../x", "a/b", "x" * 200, "a b"])
def test_invalid_instance_ids_are_refused(tmp_path: Path, iid: str) -> None:
    with pytest.raises(FixCollectionError):
        find_passing_fixes(tmp_path, iid)


def test_cli_collects_for_each_task(tmp_path: Path, capsys) -> None:
    from hermetic_slice.__main__ import main
    root = tmp_path / "exp"
    run(root, "lite", "a", patch(1), True)
    tasks = tmp_path / "tasks"
    (tasks / IID).mkdir(parents=True)
    (tasks / IID / "task.json").write_text("{}")
    assert main(["collect-fixes", "--tasks-dir", str(tasks), "--experiments", str(root)]) == 0
    assert capsys.readouterr().out.split() == [IID, "1"]
    assert len(list((tasks / IID / "staging" / "fixes").iterdir())) == 1
    assert main(["collect-fixes", "--tasks-dir", str(tasks), "--experiments", str(root),
                 "--only", "missing"]) == 1
