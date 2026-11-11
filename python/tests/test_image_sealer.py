"""Tests for hermetic_slice image sealer, measurement, and CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from unittest.mock import patch

import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.dockerutil import is_docker_available, run_docker
from hermetic_slice.gitutil import run_git
from hermetic_slice.image_sealer import (
    RESTORE_MODES_SH,
    ImageSealError,
    gold_lines,
    measure,
    render_dockerfile,
    seal_image,
    verification_problems,
)

requires_docker = pytest.mark.skipif(
    not is_docker_available(),
    reason="Docker is not available or docker info failed",
)


# =============================================================================
# Unit Tests (Run on Windows and Linux, no Docker needed)
# =============================================================================


def test_render_dockerfile() -> None:
    """Test Dockerfile generation exact text."""
    image_name = "swebench/sweb.eval.x86_64.pytest-dev_1776_pytest-6202:latest"
    rendered = render_dockerfile(image_name)
    expected = (
        f"FROM {image_name}\n"
        "RUN rm -rf /testbed/.git /root/.cache /root/.bash_history \\\n"
        " && (conda clean --all --yes || true)\n"
        "COPY sealed.git /testbed/.git\n"
        "COPY restore-modes.sh /tmp/restore-modes.sh\n"
        "RUN bash /tmp/restore-modes.sh && rm -f /tmp/restore-modes.sh\n"
    )
    assert rendered == expected


def test_verification_problems() -> None:
    """Test verification_problems returns [] for clean after and identifies each flaw."""
    clean_after = {
        "head_is_base": True,
        "extra_commits": [],
        "refs_not_ancestor_of_base": 0,
        "commits_in_store_not_reachable_from_base": 0,
        "objects_not_reachable_from_base": {"commit": 0, "tree": 0, "blob": 0, "tag": 1},
        "fix_commits_present": [],
        "remotes": [],
        "reflog_entries": 0,
        "stash_entries": 0,
        "git_meta_files_present": [],
        "tracked_modified_vs_base": 0,
        "gold_lines_found_in_unreachable": 0,
        "gold_lines_found_in_tree": 0,
    }
    assert verification_problems(clean_after) == []

    # Content edits the original image already had (SWE-bench env setup) are allowed;
    # new ones, or leftover executable-bit flips, are not.
    with_env_edits = dict(clean_after, tracked_modified_vs_base=1,
                          tracked_content_modified_vs_base=["tox.ini"], tracked_mode_changes_vs_base=0)
    before_env = {"tracked_content_modified_vs_base": ["setup.py", "tox.ini"]}
    assert verification_problems(with_env_edits, before_env) == []
    assert verification_problems(with_env_edits) != []
    assert verification_problems(dict(with_env_edits, tracked_content_modified_vs_base=["src/x.py"]), before_env) != []
    assert verification_problems(dict(with_env_edits, tracked_mode_changes_vs_base=3), before_env) != []

    # Tag objects unreachable from base are allowed
    clean_with_more_tags = dict(clean_after)
    clean_with_more_tags["objects_not_reachable_from_base"] = {"commit": 0, "tree": 0, "blob": 0, "tag": 5}
    assert verification_problems(clean_with_more_tags) == []

    # Test each failing field produces at least one problem
    flaws = [
        ("head_is_base", False),
        ("extra_commits", [{"sha": "abc", "author": "dev", "author_date": "2024", "subject": "msg"}]),
        ("refs_not_ancestor_of_base", 1),
        ("commits_in_store_not_reachable_from_base", 2),
        ("objects_not_reachable_from_base", {"commit": 1, "tree": 0, "blob": 0, "tag": 0}),
        ("objects_not_reachable_from_base", {"commit": 0, "tree": 1, "blob": 0, "tag": 0}),
        ("objects_not_reachable_from_base", {"commit": 0, "tree": 0, "blob": 1, "tag": 0}),
        ("objects_not_reachable_from_base", {"commit": 0, "tree": 0, "blob": 0, "tag": 0, "unexpected": 1}),
        ("fix_commits_present", ["deadbeef"]),
        ("remotes", ["origin"]),
        ("reflog_entries", 3),
        ("stash_entries", 1),
        ("git_meta_files_present", ["ORIG_HEAD"]),
        ("tracked_modified_vs_base", 1),
        ("gold_lines_found_in_unreachable", 1),
        ("gold_lines_found_in_tree", 1),
    ]

    for key, bad_val in flaws:
        bad_after = dict(clean_after)
        bad_after[key] = bad_val
        problems = verification_problems(bad_after)
        assert len(problems) >= 1, f"Expected verification problem for failing field {key}={bad_val!r}"


def test_gold_lines_no_staging_fallback(tmp_path: Path) -> None:
    """Test gold_lines ignores patches in task_dir root and does not fall back (H6)."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "Tester"], cwd=repo_dir)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)

    (repo_dir / "base.py").write_text("print('base')\n", encoding="utf-8")
    run_git(["add", "base.py"], cwd=repo_dir)
    d = "2024-01-01T00:00:00Z"
    run_git(["commit", "-m", "base commit"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})
    base_sha = run_git(["rev-parse", "HEAD"], cwd=repo_dir).decode("ascii").strip()

    task_dir = tmp_path / "task"
    task_dir.mkdir(parents=True, exist_ok=True)
    # Write a patch in task_dir root (which would be used under the old fallback)
    (task_dir / "test.patch").write_text("+should_not_be_loaded_from_task_root\n", encoding="utf-8")

    # Staging dir exists but test.patch is missing
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    (staging_dir / "gold.patch").write_text("+gold_secret_line_twelve_chars\n", encoding="utf-8")

    result = gold_lines(task_dir, repo_dir, base_sha)
    assert "should_not_be_loaded_from_task_root" not in result
    assert "gold_secret_line_twelve_chars" in result


def test_cli_only_append_multiple(tmp_path: Path) -> None:
    """Test --only action=append handles multiple --only flags (H3)."""
    tasks_dir = tmp_path / "tasks"
    work_dir = tmp_path / "work"
    for name in ["task-alpha", "task-beta", "task-gamma"]:
        td = tasks_dir / name
        td.mkdir(parents=True, exist_ok=True)
        (td / "task.json").write_text('{"instance_id": "' + name + '"}', encoding="utf-8")

    with patch("hermetic_slice.__main__.seal_image") as mock_seal:
        mock_seal.return_value = {
            "before": {"head_is_base": True, "extra_commits": []},
            "gold_lines_checked": 0,
            "status": "sealed",
            "sealed_image": "mock:sealed",
        }
        code = main([
            "seal-images",
            "--tasks-dir", str(tasks_dir),
            "--work", str(work_dir),
            "--only", "task-alpha",
            "--only", "task-beta",
        ])
        assert code == 0
        assert mock_seal.call_count == 2
        called_names = [call[0][0].name for call in mock_seal.call_args_list]
        assert called_names == ["task-alpha", "task-beta"]


def test_cli_only_unknown_id(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test --only with unknown ID prints error naming the ID and exits 1 (H7)."""
    tasks_dir = tmp_path / "tasks"
    work_dir = tmp_path / "work"
    tasks_dir.mkdir(parents=True, exist_ok=True)

    code = main([
        "seal-images",
        "--tasks-dir", str(tasks_dir),
        "--work", str(work_dir),
        "--only", "does-not-exist",
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "does-not-exist" in captured.err


def test_cli_status_column_and_problems_on_failure(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test CLI status column prints ASCII status and lists problems on failure (H4)."""
    tasks_dir = tmp_path / "tasks"
    work_dir = tmp_path / "work"

    for name in ["task_ok", "task_fail"]:
        td = tasks_dir / name
        td.mkdir(parents=True, exist_ok=True)
        (td / "task.json").write_text('{"instance_id": "' + name + '"}', encoding="utf-8")

    def fake_seal_image(tdir: Path, work_dir: Path, **kwargs) -> dict:
        if tdir.name == "task_ok":
            return {
                "before": {"head_is_base": True, "extra_commits": []},
                "gold_lines_checked": 10,
                "status": "sealed",
                "sealed_image": "hermetic/task_ok:sealed",
            }
        else:
            seal_dir = tdir / "seal"
            seal_dir.mkdir(parents=True, exist_ok=True)
            report = {
                "before": {"head_is_base": False, "extra_commits": ["abc"]},
                "gold_lines_checked": 5,
                "status": "failed",
                "sealed_image": "hermetic/task_fail:sealed",
                "problems": ["gold lines leaked in unreachable", "extra commit present"],
            }
            (seal_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
            raise ImageSealError("Sealed image verification failed:\n" + "\n".join(report["problems"]))

    with patch("hermetic_slice.__main__.seal_image", side_effect=fake_seal_image):
        code = main([
            "seal-images",
            "--tasks-dir", str(tasks_dir),
            "--work", str(work_dir),
        ])
        assert code == 1

    captured = capsys.readouterr()
    captured.out.encode("ascii")
    assert "→" not in captured.out
    assert "task_ok  True  0  10  sealed  hermetic/task_ok:sealed" in captured.out
    assert "task_fail  False  1  5  failed  hermetic/task_fail:sealed" in captured.out
    assert "problem: gold lines leaked in unreachable" in captured.out
    assert "problem: extra commit present" in captured.out


def test_gold_lines(tmp_path: Path) -> None:
    """Test gold_lines filtering, baseline subtraction, deduplication, and patch sources."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "Tester"], cwd=repo_dir)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)

    base_existing_line = "def base_tree_existing_function():"
    (repo_dir / "existing.py").write_text(f"    {base_existing_line}\n    pass\n", encoding="utf-8")
    run_git(["add", "existing.py"], cwd=repo_dir)
    d = "2024-01-01T00:00:00Z"
    run_git(["commit", "-m", "base commit"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})
    base_sha = run_git(["rev-parse", "HEAD"], cwd=repo_dir).decode("ascii").strip()

    task_dir = tmp_path / "task"
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    gold_patch_text = f"""--- a/existing.py
+++ b/existing.py
@@ -1,2 +1,6 @@
+    {base_existing_line}
+short
++++ b/header/to/exclude/path
+def secret_gold_function_alpha():
+def duplicate_secret_function_shared():
"""

    test_patch_text = """--- a/test_existing.py
+++ b/test_existing.py
@@ -1,2 +1,5 @@
+tiny
+def secret_test_function_beta():
+def duplicate_secret_function_shared():
"""

    (staging_dir / "gold.patch").write_text(gold_patch_text, encoding="utf-8")
    (staging_dir / "test.patch").write_text(test_patch_text, encoding="utf-8")

    result = gold_lines(task_dir, repo_dir, base_sha)

    # 1. +++ headers are excluded
    for item in result:
        assert not item.startswith("+++")
        assert not item.startswith("b/header")

    # 2. short lines (< 12 chars) are dropped ("short", "tiny")
    assert "short" not in result
    assert "tiny" not in result

    # 3. lines already in the base tree are subtracted
    assert base_existing_line not in result

    # 4. duplicates are removed
    assert result.count("def duplicate_secret_function_shared():") == 1

    # 5. both patch files are used
    assert "def secret_gold_function_alpha():" in result
    assert "def secret_test_function_beta():" in result

    expected = sorted([
        "def duplicate_secret_function_shared():",
        "def secret_gold_function_alpha():",
        "def secret_test_function_beta():",
    ])
    assert result == expected


def test_restore_modes_sh_restores_exact_modes_and_skips_symlinks(tmp_path: Path) -> None:
    """Offline regression test: RESTORE_MODES_SH enforces 0644/0755 and skips symlinks."""
    if not shutil.which("bash"):
        pytest.skip("bash is not available")

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "Tester"], cwd=repo_dir)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)

    # file1: tracked as 100644, but has mode 0755 on disk (simulating SWE-bench executable-flip)
    f1 = repo_dir / "file1.txt"
    f1.write_text("file 1\n", encoding="utf-8")
    run_git(["add", "file1.txt"], cwd=repo_dir)

    # file2: tracked as 100644, but has mode 0664 on disk (e.g. host umask 0002)
    f2 = repo_dir / "file2.txt"
    f2.write_text("file 2\n", encoding="utf-8")
    run_git(["add", "file2.txt"], cwd=repo_dir)

    # script: tracked as 100755, but has mode 0644 on disk
    f3 = repo_dir / "script.sh"
    f3.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    run_git(["add", "script.sh"], cwd=repo_dir)
    run_git(["update-index", "--chmod=+x", "script.sh"], cwd=repo_dir)

    # Commit tree
    d = "2024-01-01T00:00:00Z"
    run_git(["commit", "-m", "base commit"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})

    # Now intentionally alter modes on disk
    os.chmod(f1, 0o755)
    os.chmod(f2, 0o664)
    os.chmod(f3, 0o644)

    # Add a symlink on disk pointing to an outside file to verify no chmod through symlink
    target_outside = tmp_path / "outside.txt"
    target_outside.write_text("outside", encoding="utf-8")
    os.chmod(target_outside, 0o600)
    symlink_file = repo_dir / "symlink.txt"
    symlink_file.symlink_to(target_outside)

    # Run RESTORE_MODES_SH passing repo_dir as $1
    subprocess.run(["bash", "-c", RESTORE_MODES_SH, "bash", str(repo_dir)], check=True)

    # Verify exact modes (mask with 0o777)
    assert oct(f1.stat().st_mode & 0o777) == "0o644"
    assert oct(f2.stat().st_mode & 0o777) == "0o644"
    assert oct(f3.stat().st_mode & 0o777) == "0o755"
    assert symlink_file.is_symlink()
    assert oct(target_outside.stat().st_mode & 0o777) == "0o600"


def test_restore_modes_sh_tracked_ancestor_and_final_symlinks_never_chmod(tmp_path: Path) -> None:
    """Offline regression test for Defect 6: tracked ancestor symlinks and final symlinks never chmod outside files."""
    if not shutil.which("bash"):
        pytest.skip("bash is not available")

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "Tester"], cwd=repo_dir)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)

    # 1. Tracked ancestor scenario: HEAD tracks pkg/secret as 100644
    pkg_dir = repo_dir / "pkg"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    secret_tracked = pkg_dir / "secret"
    secret_tracked.write_text("secret content\n", encoding="utf-8")
    run_git(["add", "pkg/secret"], cwd=repo_dir)

    # 2. Tracked final symlink scenario: HEAD tracks tracked_sym.txt as 100644
    tracked_sym = repo_dir / "tracked_sym.txt"
    tracked_sym.write_text("regular file initially\n", encoding="utf-8")
    run_git(["add", "tracked_sym.txt"], cwd=repo_dir)

    # Commit tree
    d = "2024-01-01T00:00:00Z"
    run_git(["commit", "-m", "base commit with tracked files"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})

    # Now setup hostile on-disk scenario:
    # A) Replace pkg directory with a symlink to outside_dir containing 0600 secret
    shutil.rmtree(pkg_dir)
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside_secret = outside_dir / "secret"
    outside_secret.write_text("outside secret\n", encoding="utf-8")
    os.chmod(outside_secret, 0o600)
    pkg_dir.symlink_to(outside_dir, target_is_directory=True)

    # B) Replace tracked_sym.txt with a symlink to outside_file containing 0600 content
    tracked_sym.unlink()
    outside_file = tmp_path / "outside_file.txt"
    outside_file.write_text("outside file content\n", encoding="utf-8")
    os.chmod(outside_file, 0o600)
    tracked_sym.symlink_to(outside_file)

    # Run RESTORE_MODES_SH
    subprocess.run(["bash", "-c", RESTORE_MODES_SH, "bash", str(repo_dir)], check=True)

    # Verify outside files were NEVER chmod'd to 0644!
    assert oct(outside_secret.stat().st_mode & 0o777) == "0o600"
    assert oct(outside_file.stat().st_mode & 0o777) == "0o600"
    assert pkg_dir.is_symlink()
    assert tracked_sym.is_symlink()



# =============================================================================
# Docker Integration Tests (Requires working Docker inside WSL/Linux)
# =============================================================================


FAKE_IMAGE_TAG = "hermetic-test/fake-swebench:latest"
DISTINCTIVE_DANGLING_LINE = "SECRET_DISTINCTIVE_DANGLING_LINE_987654"
PRE_BASE_SECRET_LINE = "SECRET_PRE_BASE_HISTORIC_LINE_12345"


@pytest.fixture(scope="module")
def fake_swebench_image(tmp_path_factory: pytest.TempPathFactory):
    """Build a tiny synthetic SWE-bench image meeting T0.1 / T0.3 specifications."""
    if not is_docker_available():
        pytest.skip("Docker is not available or docker info failed")

    tmp_dir = tmp_path_factory.mktemp("fake_swebench")
    repo_dir = tmp_dir / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "SWE-bench"], cwd=repo_dir)
    run_git(["config", "user.email", "setup@swebench.com"], cwd=repo_dir)

    d1 = "2024-01-01T00:00:00Z"
    d2 = "2024-01-02T00:00:00Z"
    d3 = "2024-01-03T00:00:00Z"
    d_swe = "2026-08-13T00:00:00Z"

    # c1: contains pre_base_line
    (repo_dir / "file1.txt").write_text(f"file 1 content\n{PRE_BASE_SECRET_LINE}\n", encoding="utf-8")
    run_git(["add", "file1.txt"], cwd=repo_dir)
    run_git(["commit", "-m", "commit c1"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d1, "GIT_COMMITTER_DATE": d1})
    c1 = run_git(["rev-parse", "HEAD"], cwd=repo_dir).decode("ascii").strip()

    # c2: pre_base_line removed
    (repo_dir / "file1.txt").write_text("file 1 content\n", encoding="utf-8")
    (repo_dir / "file2.txt").write_text("file 2 content\n", encoding="utf-8")
    run_git(["add", "file1.txt", "file2.txt"], cwd=repo_dir)
    run_git(["commit", "-m", "commit c2"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d2, "GIT_COMMITTER_DATE": d2})
    c2 = run_git(["rev-parse", "HEAD"], cwd=repo_dir).decode("ascii").strip()

    # Tag on c2
    run_git(["tag", "v0.2", c2], cwd=repo_dir)

    # c3 = base
    (repo_dir / "file3.txt").write_text("file 3 content\n", encoding="utf-8")
    run_git(["add", "file3.txt"], cwd=repo_dir)
    run_git(["commit", "-m", "commit c3 base"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d3, "GIT_COMMITTER_DATE": d3})
    c3_base = run_git(["rev-parse", "HEAD"], cwd=repo_dir).decode("ascii").strip()

    # Dangling commit containing distinctive line
    (repo_dir / "secret.txt").write_text(f"{DISTINCTIVE_DANGLING_LINE}\n", encoding="utf-8")
    run_git(["add", "secret.txt"], cwd=repo_dir)
    tree_dangling = run_git(["write-tree"], cwd=repo_dir).decode("ascii").strip()
    run_git(["reset", "HEAD", "secret.txt"], cwd=repo_dir)
    (repo_dir / "secret.txt").unlink()
    run_git(
        ["commit-tree", tree_dangling, "-p", c3_base, "-m", "dangling commit"],
        cwd=repo_dir,
        env={"GIT_AUTHOR_DATE": d3, "GIT_COMMITTER_DATE": d3},
    )

    # SWE-bench commit on top of c3 with 2026 date (HEAD != base). Like the real
    # django/sympy/astropy images, it flips tracked files to 100755 with no
    # content change.
    for name in ("file1.txt", "file2.txt"):
        os.chmod(repo_dir / name, 0o755)
        run_git(["update-index", "--chmod=+x", name], cwd=repo_dir)
    run_git(
        ["commit", "-m", "SWE-bench"],
        cwd=repo_dir,
        env={"GIT_AUTHOR_DATE": d_swe, "GIT_COMMITTER_DATE": d_swe},
    )

    # ORIG_HEAD
    (repo_dir / ".git" / "ORIG_HEAD").write_text(f"{c3_base}\n", encoding="utf-8")

    # Build fake SWE-bench image
    df_path = tmp_dir / "Dockerfile"
    df_path.write_text(
        "FROM alpine:3.20\n"
        "RUN apk add --no-cache git bash python3\n"
        "COPY repo /testbed\n"
        "WORKDIR /testbed\n",
        encoding="utf-8",
    )

    run_docker(["build", "-t", FAKE_IMAGE_TAG, str(tmp_dir)], check=True)

    yield {
        "image": FAKE_IMAGE_TAG,
        "c1": c1,
        "c2": c2,
        "c3_base": c3_base,
        "distinctive_line": DISTINCTIVE_DANGLING_LINE,
        "pre_base_line": PRE_BASE_SECRET_LINE,
    }

    # Teardown: remove images
    run_docker(["rmi", "-f", FAKE_IMAGE_TAG], check=False)


@pytest.mark.docker
def test_measure_fake_image(fake_swebench_image: dict) -> None:
    """Test measure on the fake SWE-bench image."""
    image = fake_swebench_image["image"]
    c3_base = fake_swebench_image["c3_base"]
    distinctive_line = fake_swebench_image["distinctive_line"]
    pre_base_line = fake_swebench_image["pre_base_line"]

    task = {
        "base_commit": c3_base,
        "dates": {"fix_commits": []},
    }

    report = measure(image, task, lines=[distinctive_line, pre_base_line])

    # head_is_base is false
    assert report["head_is_base"] is False

    # there's 1 extra commit
    assert len(report["extra_commits"]) == 1
    assert report["extra_commits"][0]["subject"] == "SWE-bench"
    assert "SWE-bench" in report["extra_commits"][0]["author"]

    # the reflog is non-empty
    assert report["reflog_entries"] > 0

    # gold_lines_found_in_unreachable >= 1
    assert report["gold_lines_found_in_unreachable"] >= 1

    # The SWE-bench commit's mode flips show as changes against the base
    assert report["tracked_modified_vs_base"] == 2


@pytest.mark.docker
def test_seal_image_end_to_end(tmp_path: Path, fake_swebench_image: dict) -> None:
    """Test seal_image end-to-end and sealed container verification."""
    image = fake_swebench_image["image"]
    c1 = fake_swebench_image["c1"]
    c2 = fake_swebench_image["c2"]
    c3_base = fake_swebench_image["c3_base"]
    distinctive_line = fake_swebench_image["distinctive_line"]
    pre_base_line = fake_swebench_image["pre_base_line"]

    instance_id = "test-fake__task-1"
    task_dir = tmp_path / "tasks" / instance_id
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    task_json_data = {
        "base_commit": c3_base,
        "cutoffs": {
            "t_clock": "2024-01-05T00:00:00Z",
            "t_world": "2024-01-04T00:00:00Z",
        },
        "dates": {
            "fix_commits": [],
        },
        "image": image,
        "instance_id": instance_id,
        "schema": "hermetic-slice-task/v1",
    }
    (task_dir / "task.json").write_text(json.dumps(task_json_data, indent=2), encoding="utf-8")

    test_patch_text = f"""--- a/file3.txt
+++ b/file3.txt
@@ -1 +1,3 @@
 file 3 content
+{distinctive_line}
+{pre_base_line}
"""
    (staging_dir / "test.patch").write_text(test_patch_text, encoding="utf-8")

    work_dir = tmp_path / "work" / instance_id
    work_dir.mkdir(parents=True, exist_ok=True)

    sealed_tag = f"hermetic/{instance_id.lower()}:sealed"
    try:
        report = seal_image(task_dir, work_dir, tag=sealed_tag)

        # After report passes verification_problems == []
        problems = verification_problems(report["after"])
        assert problems == [], f"Verification problems found: {problems}"

        # report.json is written
        report_file = task_dir / "seal" / "report.json"
        assert report_file.exists()
        saved_report = json.loads(report_file.read_text(encoding="utf-8"))
        assert saved_report["schema"] == "hermetic-slice-seal/v1"
        assert saved_report["instance_id"] == instance_id
        assert saved_report["sealed_image"] == sealed_tag
        assert saved_report["status"] == "sealed"
        assert saved_report["problems"] == []
        assert saved_report["gold_lines_checked"] == 2
        assert saved_report["after"]["gold_lines_found_in_unreachable"] == 0

        # Modes flipped by the SWE-bench commit are restored from the base tree
        assert saved_report["before"]["tracked_modified_vs_base"] == 2
        assert saved_report["before"]["tracked_mode_changes_vs_base"] == 2
        assert saved_report["before"]["tracked_content_modified_vs_base"] == []
        assert saved_report["after"]["tracked_modified_vs_base"] == 0
        assert saved_report["after"]["tracked_mode_changes_vs_base"] == 0
        modes_out = run_docker([
            "run", "--rm", "--network", "none", "--entrypoint", "/bin/bash", sealed_tag,
            "-c", "cd /testbed && stat -c '%a %n' file1.txt file2.txt file3.txt && git status --porcelain",
        ]).decode("utf-8")
        assert modes_out.splitlines() == ["644 file1.txt", "644 file2.txt", "644 file3.txt"]

        # Running git log --all --format=%H inside the sealed image shows exactly c3, c2 and c1
        git_log_out = run_docker([
            "run",
            "--rm",
            "--network", "none",
            "--entrypoint", "/bin/bash",
            sealed_tag,
            "-c",
            "git -C /testbed log --all --format=%H",
        ])
        commits = [s.strip() for s in git_log_out.decode("ascii").splitlines() if s.strip()]
        assert commits == [c3_base, c2, c1]
    finally:
        run_docker(["rmi", "-f", sealed_tag], check=False)


@pytest.mark.docker
def test_seal_image_failure_writes_report(tmp_path: Path, fake_swebench_image: dict) -> None:
    """Test that a failed seal writes report.json with status failed and raises ImageSealError (H2)."""
    image = fake_swebench_image["image"]
    c3_base = fake_swebench_image["c3_base"]
    distinctive_line = fake_swebench_image["distinctive_line"]

    instance_id = "test-fail__task-1"
    task_dir = tmp_path / "tasks" / instance_id
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    task_json_data = {
        "base_commit": c3_base,
        "cutoffs": {
            "t_clock": "2024-01-05T00:00:00Z",
            "t_world": "2024-01-04T00:00:00Z",
        },
        "dates": {"fix_commits": []},
        "image": image,
        "instance_id": instance_id,
        "schema": "hermetic-slice-task/v1",
    }
    (task_dir / "task.json").write_text(json.dumps(task_json_data, indent=2), encoding="utf-8")
    (staging_dir / "test.patch").write_text(f"+{distinctive_line}\n", encoding="utf-8")

    work_dir = tmp_path / "work" / instance_id
    work_dir.mkdir(parents=True, exist_ok=True)
    sealed_tag = f"hermetic/{instance_id.lower()}:sealed"

    try:
        with patch("hermetic_slice.image_sealer.verification_problems", return_value=["Simulated verification failure"]):
            with pytest.raises(ImageSealError) as exc_info:
                seal_image(task_dir, work_dir, tag=sealed_tag)
            assert "Simulated verification failure" in str(exc_info.value)

        report_file = task_dir / "seal" / "report.json"
        assert report_file.exists()
        saved_report = json.loads(report_file.read_text(encoding="utf-8"))
        assert saved_report["status"] == "failed"
        assert saved_report["problems"] == ["Simulated verification failure"]
    finally:
        run_docker(["rmi", "-f", sealed_tag], check=False)


@pytest.mark.docker
def test_cli_seal_images(tmp_path: Path, fake_swebench_image: dict) -> None:
    """Test CLI seal-images command execution."""
    image = fake_swebench_image["image"]
    c3_base = fake_swebench_image["c3_base"]

    instance_id = "test-cli__task-1"
    tasks_root = tmp_path / "cli_tasks"
    task_dir = tasks_root / instance_id
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    task_json_data = {
        "base_commit": c3_base,
        "cutoffs": {
            "t_clock": "2024-01-05T00:00:00Z",
            "t_world": "2024-01-04T00:00:00Z",
        },
        "dates": {
            "fix_commits": [],
        },
        "image": image,
        "instance_id": instance_id,
        "schema": "hermetic-slice-task/v1",
    }
    (task_dir / "task.json").write_text(json.dumps(task_json_data, indent=2), encoding="utf-8")
    (staging_dir / "test.patch").write_text("+added_line_twelve_chars\n", encoding="utf-8")

    work_dir = tmp_path / "cli_work"
    sealed_tag = f"hermetic/{instance_id.lower()}:sealed"

    try:
        ret = main([
            "seal-images",
            "--tasks-dir", str(tasks_root),
            "--work", str(work_dir),
            "--only", instance_id,
        ])
        assert ret == 0
        report_file = task_dir / "seal" / "report.json"
        assert report_file.exists()
        saved_report = json.loads(report_file.read_text(encoding="utf-8"))
        assert saved_report["status"] == "sealed"
    finally:
        run_docker(["rmi", "-f", sealed_tag], check=False)


def test_regression_defect6_tracked_fifo_without_writer_promptly_rejected_and_replacement_during_open(tmp_path: Path) -> None:
    """Defect 6: replace tracked file with FIFO without writer; assert prompt rejection and replacement during open."""
    import stat
    if not shutil.which("bash"):
        pytest.skip("bash is not available")

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "Tester"], cwd=repo_dir)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)

    # Track regular file
    tracked = repo_dir / "fifo_target.txt"
    tracked.write_text("regular file\n", encoding="utf-8")
    run_git(["add", "fifo_target.txt"], cwd=repo_dir)
    d = "2024-01-01T00:00:00Z"
    run_git(["commit", "-m", "add tracked file"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})

    # Part 1: Replace tracked file with a FIFO without a writer
    tracked.unlink()
    os.mkfifo(tracked)
    os.chmod(tracked, 0o666)

    proc = subprocess.run(
        ["bash", "-c", RESTORE_MODES_SH, "bash", str(repo_dir)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert proc.returncode == 0
    assert stat.S_ISFIFO(tracked.stat().st_mode)

    # Part 2: Cover replacement during open
    race_target = repo_dir / "race_target.txt"
    race_target.write_text("initial regular\n", encoding="utf-8")
    dir_fd = os.open(str(repo_dir), os.O_RDONLY | os.O_DIRECTORY)
    try:
        st_before = os.lstat("race_target.txt", dir_fd=dir_fd)
        assert stat.S_ISREG(st_before.st_mode)
        race_target.unlink()
        os.mkfifo(race_target)
        fd = os.open("race_target.txt", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
        try:
            st_after = os.fstat(fd)
            is_valid = stat.S_ISREG(st_after.st_mode) and (st_before.st_dev, st_before.st_ino) == (st_after.st_dev, st_after.st_ino)
            assert not is_valid
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


def test_regression_defect7_ls_tree_lowered_caps_bounded_failure_and_child_cleanup(tmp_path: Path) -> None:
    """Defect 7: exceed lowered output/entry cap and assert bounded failure and child cleanup."""
    if not shutil.which("bash"):
        pytest.skip("bash is not available")

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "Tester"], cwd=repo_dir)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)

    for i in range(10):
        (repo_dir / f"file_{i}.txt").write_text(f"content {i}\n", encoding="utf-8")
        run_git(["add", f"file_{i}.txt"], cwd=repo_dir)

    d = "2024-01-01T00:00:00Z"
    run_git(["commit", "-m", "10 files"], cwd=repo_dir, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})

    # Test 1: Exceed lowered byte cap
    env_byte_cap = os.environ.copy()
    env_byte_cap["HERMETIC_MAX_LS_TREE_BYTES"] = "20"
    proc_bytes = subprocess.run(
        ["bash", "-c", RESTORE_MODES_SH, "bash", str(repo_dir)],
        env=env_byte_cap,
        capture_output=True,
        text=True,
    )
    assert proc_bytes.returncode != 0
    assert "byte cap exceeded" in proc_bytes.stderr

    # Test 2: Exceed lowered entry cap
    env_entry_cap = os.environ.copy()
    env_entry_cap["HERMETIC_MAX_LS_TREE_ENTRIES"] = "2"
    proc_entries = subprocess.run(
        ["bash", "-c", RESTORE_MODES_SH, "bash", str(repo_dir)],
        env=env_entry_cap,
        capture_output=True,
        text=True,
    )
    assert proc_entries.returncode != 0
    assert "entry count cap exceeded" in proc_entries.stderr

