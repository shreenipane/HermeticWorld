"""Tests for repo sealer and verification."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from unittest.mock import patch

import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.gitutil import GitError, run_git
from hermetic_slice.repo_sealer import (
    UnsupportedRepoError,
    VerificationError,
    _clean_directory,
    rmtree_force,
    seal_repo,
    verify_sealed_repo,
)
from tests.helpers import SyntheticRepo


def _hash_git_dir(git_dir: Path) -> dict[str, str]:
    """Compute sha256 for all files in .git directory."""
    hashes: dict[str, str] = {}
    for p in sorted(git_dir.rglob("*")):
        if p.is_file():
            hashes[str(p.relative_to(git_dir))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def test_seal_repo_completeness_and_isolation(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """Verify sealed repo secrecy, tag handling, commit history, and source isolation."""
    src = synthetic_repo.path
    dest = tmp_path / "sealed_dest"

    before_hashes = _hash_git_dir(src / ".git")

    report = seal_repo(
        src=src,
        base_commit=synthetic_repo.c3_base,
        dest=dest,
        t_clock=synthetic_repo.t_clock,
    )

    after_hashes = _hash_git_dir(src / ".git")
    assert before_hashes == after_hashes, "src/.git must be byte-identical before and after sealing"

    assert report.base_commit == synthetic_repo.c3_base
    assert report.kept_tags == {
        synthetic_repo.tag_light_c2: "ancestor",
        synthetic_repo.tag_ann_c1: "ancestor",
    }
    assert report.dropped_tags == {
        synthetic_repo.tag_ann_c2_after: "tagger_after_t_clock",
        synthetic_repo.tag_c4: "not_ancestor",
    }

    # Verify secret string SECRET_FIX_7f3a is absent from all objects in dest
    all_objects_content = run_git(["cat-file", "--batch-all-objects", "--batch"], cwd=dest)
    assert synthetic_repo.secret_string.encode("utf-8") not in all_objects_content

    # Verify secret string is absent from all files in dest working directory
    for p in dest.rglob("*"):
        if p.is_file() and ".git" not in p.parts:
            assert synthetic_repo.secret_string not in p.read_text(encoding="utf-8", errors="replace")

    # Verify c4 commit is absent from dest
    with pytest.raises(GitError):
        run_git(["cat-file", "-e", synthetic_repo.c4_fix], cwd=dest)

    # Verify git log in dest shows c1, c2, c3 only
    log_shas = run_git(["log", "--format=%H"], cwd=dest).decode("ascii").splitlines()
    assert log_shas == [synthetic_repo.c3_base, synthetic_repo.c2, synthetic_repo.c1]
    assert synthetic_repo.c4_fix not in log_shas
    assert synthetic_repo.c_branch not in log_shas

    # Verify verify_sealed_repo returns [] on sealed repo
    problems = verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags)
    assert problems == []


def test_verify_sealed_repo_fails_on_plain_clone(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """verify_sealed_repo returns a list of problems covering all key integrity checks on a plain clone."""
    clone_dir = tmp_path / "plain_clone"
    run_git(["clone", str(synthetic_repo.path), str(clone_dir)], cwd=tmp_path)

    allowed_tags = {
        synthetic_repo.tag_light_c2: "ancestor",
        synthetic_repo.tag_ann_c1: "ancestor",
    }
    problems = verify_sealed_repo(clone_dir, synthetic_repo.c3_base, allowed_tags)
    assert any("Unexpected objects" in p for p in problems), f"Expected unexpected objects problem, got {problems}"
    assert any("Forbidden ref present in repo: refs/remotes/" in p for p in problems), f"Expected forbidden remotes ref, got {problems}"
    assert any("Forbidden ref present in repo: refs/heads/main" in p for p in problems), f"Expected forbidden refs/heads/main, got {problems}"
    assert any("Remotes found in repo" in p and "origin" in p for p in problems), f"Expected remote origin problem, got {problems}"
    assert any("HEAD does not point to refs/heads/sealed" in p for p in problems), f"Expected HEAD problem, got {problems}"


def test_submodule_repo_raises_unsupported(tmp_path: Path) -> None:
    """Repositories with .gitmodules at base_commit raise UnsupportedRepoError and leave dest untouched."""
    repo = tmp_path / "repo_submodule"
    dest = tmp_path / "dest_submodule"
    run_git(["init", "-b", "main", str(repo)], cwd=tmp_path)
    run_git(["config", "user.name", "Tester"], cwd=repo)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo)

    (repo / ".gitmodules").write_text('[submodule "test"]\npath = test\nurl = https://example.com/sub.git\n', encoding="utf-8")
    run_git(["add", ".gitmodules"], cwd=repo)
    run_git(["commit", "-m", "add submodule"], cwd=repo)
    base_sha = run_git(["rev-parse", "HEAD"], cwd=repo).decode("ascii").strip()

    t_clock = datetime.now(timezone.utc)

    with pytest.raises(UnsupportedRepoError, match="Submodules are not supported"):
        seal_repo(src=repo, base_commit=base_sha, dest=dest, t_clock=t_clock)

    assert not dest.exists(), "dest must be left untouched when UnsupportedRepoError is raised"


def test_lfs_repo_raises_unsupported(tmp_path: Path) -> None:
    """Repositories with filter=lfs in .gitattributes raise UnsupportedRepoError and leave dest untouched."""
    repo = tmp_path / "repo_lfs"
    dest = tmp_path / "dest_lfs"
    run_git(["init", "-b", "main", str(repo)], cwd=tmp_path)
    run_git(["config", "user.name", "Tester"], cwd=repo)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo)

    (repo / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
    run_git(["add", ".gitattributes"], cwd=repo)
    run_git(["commit", "-m", "add lfs gitattributes"], cwd=repo)
    base_sha = run_git(["rev-parse", "HEAD"], cwd=repo).decode("ascii").strip()

    t_clock = datetime.now(timezone.utc)

    with pytest.raises(UnsupportedRepoError, match="Git LFS is not supported"):
        seal_repo(src=repo, base_commit=base_sha, dest=dest, t_clock=t_clock)

    assert not dest.exists(), "dest must be left untouched when UnsupportedRepoError is raised"


def test_non_commit_tag_dropped(tmp_path: Path) -> None:
    """Tags pointing to non-commit objects (like blobs) are dropped with reason not_commit."""
    repo = tmp_path / "repo_blob_tag"
    dest = tmp_path / "dest_blob_tag"
    run_git(["init", "-b", "main", str(repo)], cwd=tmp_path)
    run_git(["config", "user.name", "Tester"], cwd=repo)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo)

    (repo / "file.txt").write_text("Initial file\n", encoding="utf-8")
    run_git(["add", "file.txt"], cwd=repo)
    run_git(["commit", "-m", "init"], cwd=repo)
    base_sha = run_git(["rev-parse", "HEAD"], cwd=repo).decode("ascii").strip()

    # Create a blob and tag it directly
    blob_sha = run_git(["hash-object", "-w", "file.txt"], cwd=repo).decode("ascii").strip()
    run_git(["tag", "blob_tag", blob_sha], cwd=repo)

    t_clock = datetime.now(timezone.utc)
    report = seal_repo(src=repo, base_commit=base_sha, dest=dest, t_clock=t_clock)

    assert report.dropped_tags.get("blob_tag") == "not_commit"


def test_run_git_ignores_inherited_git_env(synthetic_repo: SyntheticRepo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """run_git drops caller GIT_* variables, preserving repo isolation."""
    other_repo = tmp_path / "other_repo"
    run_git(["init", str(other_repo)], cwd=tmp_path)
    monkeypatch.setenv("GIT_DIR", str(other_repo / ".git"))

    git_dir_out = run_git(["rev-parse", "--absolute-git-dir"], cwd=synthetic_repo.path).decode("utf-8").strip()
    assert Path(git_dir_out).resolve() == (synthetic_repo.path / ".git").resolve()

    dest = tmp_path / "sealed_env_test"
    report = seal_repo(
        src=synthetic_repo.path,
        base_commit=synthetic_repo.c3_base,
        dest=dest,
        t_clock=synthetic_repo.t_clock,
    )
    assert report.base_commit == synthetic_repo.c3_base
    assert verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags) == []


def test_annotated_tag_without_tagger_date_dropped(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """Annotated tags lacking a tagger date are dropped with reason no_tagger_date."""
    src = synthetic_repo.path
    tag_body = f"object {synthetic_repo.c1}\ntype commit\ntag tag_no_tagger\n\nNo tagger header\n".encode("utf-8")
    tag_sha = run_git(["mktag", "--no-strict"], cwd=src, input=tag_body).decode("ascii").strip()
    run_git(["update-ref", "refs/tags/tag_no_tagger", tag_sha], cwd=src)

    dest = tmp_path / "dest_no_tagger"
    report = seal_repo(
        src=src,
        base_commit=synthetic_repo.c3_base,
        dest=dest,
        t_clock=synthetic_repo.t_clock,
    )
    assert report.dropped_tags.get("tag_no_tagger") == "no_tagger_date"


def test_tag_with_same_name_as_branch_kept(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """Tags sharing a name with a branch are resolved without prefix ambiguity and kept."""
    src = synthetic_repo.path
    run_git(["branch", synthetic_repo.tag_light_c2, synthetic_repo.c2], cwd=src)

    dest = tmp_path / "dest_same_name"
    report = seal_repo(
        src=src,
        base_commit=synthetic_repo.c3_base,
        dest=dest,
        t_clock=synthetic_repo.t_clock,
    )
    assert synthetic_repo.tag_light_c2 in report.kept_tags
    assert report.kept_tags[synthetic_repo.tag_light_c2] == "ancestor"


def test_tag_dated_exactly_t_clock_kept(tmp_path: Path) -> None:
    """An annotated tag dated exactly t_clock is kept."""
    repo = tmp_path / "repo_exact_clock"
    dest = tmp_path / "dest_exact_clock"
    run_git(["init", "-b", "main", str(repo)], cwd=tmp_path)
    run_git(["config", "user.name", "Tester"], cwd=repo)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo)

    (repo / "f.txt").write_text("content\n", encoding="utf-8")
    run_git(["add", "f.txt"], cwd=repo)
    t_clock_str = "2024-05-01T12:00:00Z"
    run_git(["commit", "-m", "init"], cwd=repo, env={"GIT_AUTHOR_DATE": t_clock_str, "GIT_COMMITTER_DATE": t_clock_str})
    c1 = run_git(["rev-parse", "HEAD"], cwd=repo).decode("ascii").strip()

    run_git(["tag", "-a", "v1.0-exact", "-m", "exact tag", c1], cwd=repo, env={"GIT_COMMITTER_DATE": t_clock_str})

    t_clock = datetime.fromisoformat("2024-05-01T12:00:00+00:00")
    report = seal_repo(src=repo, base_commit=c1, dest=dest, t_clock=t_clock)
    assert report.kept_tags.get("v1.0-exact") == "ancestor"


def test_tag_on_base_commit_kept(tmp_path: Path) -> None:
    """A tag directly pointing to base_commit itself is kept."""
    repo = tmp_path / "repo_base_tag"
    dest = tmp_path / "dest_base_tag"
    run_git(["init", "-b", "main", str(repo)], cwd=tmp_path)
    run_git(["config", "user.name", "Tester"], cwd=repo)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo)

    (repo / "f.txt").write_text("base content\n", encoding="utf-8")
    run_git(["add", "f.txt"], cwd=repo)
    d = "2024-01-01T12:00:00Z"
    run_git(["commit", "-m", "base commit"], cwd=repo, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})
    c_base = run_git(["rev-parse", "HEAD"], cwd=repo).decode("ascii").strip()

    run_git(["tag", "tag-on-base", c_base], cwd=repo)

    t_clock = datetime.fromisoformat("2024-01-02T12:00:00+00:00")
    report = seal_repo(src=repo, base_commit=c_base, dest=dest, t_clock=t_clock)
    assert report.kept_tags.get("tag-on-base") == "ancestor"


def test_verify_sealed_repo_detects_forbidden_state(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """verify_sealed_repo detects worktrees, http-alternates, and core.logAllRefUpdates=always."""
    dest = tmp_path / "sealed_for_tampering"
    report = seal_repo(
        src=synthetic_repo.path,
        base_commit=synthetic_repo.c3_base,
        dest=dest,
        t_clock=synthetic_repo.t_clock,
    )
    assert verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags) == []

    # 1. Non-empty .git/worktrees
    wt_dir = dest / ".git" / "worktrees" / "wt1"
    wt_dir.mkdir(parents=True, exist_ok=True)
    (wt_dir / "gitdir").write_text("dummy", encoding="utf-8")
    probs = verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags)
    assert any(".git/worktrees" in p for p in probs)
    shutil.rmtree(dest / ".git" / "worktrees", ignore_errors=True)

    # 2. .git/objects/info/http-alternates
    http_alt = dest / ".git" / "objects" / "info" / "http-alternates"
    http_alt.write_text("https://example.com/objects\n", encoding="utf-8")
    probs = verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags)
    assert any("http-alternates" in p for p in probs)
    http_alt.unlink()

    # 3. core.logAllRefUpdates = always (and true)
    run_git(["config", "core.logAllRefUpdates", "always"], cwd=dest)
    probs = verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags)
    assert any("core.logAllRefUpdates is configured as always" in p for p in probs)

    run_git(["config", "core.logAllRefUpdates", "true"], cwd=dest)
    probs = verify_sealed_repo(dest, synthetic_repo.c3_base, report.kept_tags)
    assert any("core.logAllRefUpdates is configured as true" in p for p in probs)
    run_git(["config", "core.logAllRefUpdates", "false"], cwd=dest)


def test_unicode_tag_name_kept_and_verified(tmp_path: Path) -> None:
    """An ancestor tag with unicode characters in its name is kept and verified clean."""
    repo = tmp_path / "repo_unicode"
    dest = tmp_path / "dest_unicode"
    run_git(["init", "-b", "main", str(repo)], cwd=tmp_path)
    run_git(["config", "user.name", "Tester"], cwd=repo)
    run_git(["config", "user.email", "tester@example.com"], cwd=repo)

    (repo / "f.txt").write_text("hello unicode\n", encoding="utf-8")
    run_git(["add", "f.txt"], cwd=repo)
    d = "2024-01-01T12:00:00Z"
    run_git(["commit", "-m", "init"], cwd=repo, env={"GIT_AUTHOR_DATE": d, "GIT_COMMITTER_DATE": d})
    c1 = run_git(["rev-parse", "HEAD"], cwd=repo).decode("ascii").strip()

    unicode_tag = "v1.0-ünïcode"
    run_git(["tag", "-a", unicode_tag, "-m", "annotated unicode tag", c1], cwd=repo, env={"GIT_COMMITTER_DATE": d})

    t_clock = datetime.fromisoformat("2024-01-02T12:00:00+00:00")
    report = seal_repo(src=repo, base_commit=c1, dest=dest, t_clock=t_clock)
    assert unicode_tag in report.kept_tags
    assert report.kept_tags[unicode_tag] == "ancestor"
    assert verify_sealed_repo(dest, c1, report.kept_tags) == []


def test_failed_seal_cleans_up_dest(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """When sealing fails verification, dest is deleted if newly created, or emptied if pre-existing."""
    # Case 1: dest did not exist beforehand
    dest_new = tmp_path / "dest_new_cleanup"
    with patch("hermetic_slice.repo_sealer.verify_sealed_repo", return_value=["Injected flaw"]):
        with pytest.raises(VerificationError):
            seal_repo(
                src=synthetic_repo.path,
                base_commit=synthetic_repo.c3_base,
                dest=dest_new,
                t_clock=synthetic_repo.t_clock,
            )
    assert not dest_new.exists(), "dest must be deleted when it did not exist before failed seal"

    # Case 2: dest was a pre-existing empty directory
    dest_existing = tmp_path / "dest_existing_cleanup"
    dest_existing.mkdir()
    with patch("hermetic_slice.repo_sealer.verify_sealed_repo", return_value=["Injected flaw"]):
        with pytest.raises(VerificationError):
            seal_repo(
                src=synthetic_repo.path,
                base_commit=synthetic_repo.c3_base,
                dest=dest_existing,
                t_clock=synthetic_repo.t_clock,
            )
    assert dest_existing.exists(), "dest must remain existing when it existed before failed seal"
    assert list(dest_existing.iterdir()) == [], "dest must be emptied when it existed before failed seal"


def test_cli_end_to_end(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """End-to-end execution of seal-repo via CLI subcommand."""
    dest = tmp_path / "cli_sealed_dest"
    python_root = Path(__file__).resolve().parent.parent
    cmd = [
        sys.executable,
        "-m",
        "hermetic_slice",
        "seal-repo",
        "--src",
        str(synthetic_repo.path),
        "--base",
        synthetic_repo.c3_base,
        "--dest",
        str(dest),
        "--t-clock",
        synthetic_repo.t_clock.isoformat(),
    ]
    env = {**os.environ, "PYTHONPATH": str(python_root)}
    proc = subprocess.run(cmd, cwd=str(tmp_path), capture_output=True, text=True, env=env)
    assert proc.returncode == 0, f"CLI command failed with stderr: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert data["base_commit"] == synthetic_repo.c3_base
    assert data["kept_tags"] == {
        synthetic_repo.tag_light_c2: "ancestor",
        synthetic_repo.tag_ann_c1: "ancestor",
    }
    assert data["dropped_tags"] == {
        synthetic_repo.tag_ann_c2_after: "tagger_after_t_clock",
        synthetic_repo.tag_c4: "not_ancestor",
    }
    assert (dest / ".git").exists()


def test_cli_error_exit_codes(synthetic_repo: SyntheticRepo, tmp_path: Path) -> None:
    """CLI exits with 1 on general errors and 2 on verification errors."""
    python_root = Path(__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(python_root)}

    # Invalid commit SHA -> exit code 1
    bad_cmd = [
        sys.executable,
        "-m",
        "hermetic_slice",
        "seal-repo",
        "--src",
        str(synthetic_repo.path),
        "--base",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "--dest",
        str(tmp_path / "bad_dest"),
        "--t-clock",
        synthetic_repo.t_clock.isoformat(),
    ]
    proc_bad = subprocess.run(bad_cmd, capture_output=True, text=True, env=env)
    assert proc_bad.returncode == 1, f"Expected exit code 1 on error, got {proc_bad.returncode}"

    # Missing --src -> exit code 1 (argparse usage error mapped to 1)
    missing_src_cmd = [
        sys.executable,
        "-m",
        "hermetic_slice",
        "seal-repo",
        "--base",
        synthetic_repo.c3_base,
        "--dest",
        str(tmp_path / "missing_src_dest"),
        "--t-clock",
        synthetic_repo.t_clock.isoformat(),
    ]
    proc_missing = subprocess.run(missing_src_cmd, capture_output=True, text=True, env=env)
    assert proc_missing.returncode == 1, f"Expected exit code 1 on missing --src, got {proc_missing.returncode}"

    # --help -> exit code 0
    help_cmd = [sys.executable, "-m", "hermetic_slice", "--help"]
    proc_help = subprocess.run(help_cmd, capture_output=True, text=True, env=env)
    assert proc_help.returncode == 0, f"Expected exit code 0 on --help, got {proc_help.returncode}"

    # Verification failure -> exit code 2
    with patch("hermetic_slice.repo_sealer.verify_sealed_repo", return_value=["Mocked verification flaw"]):
        code = main([
            "seal-repo",
            "--src",
            str(synthetic_repo.path),
            "--base",
            synthetic_repo.c3_base,
            "--dest",
            str(tmp_path / "verify_fail_dest"),
            "--t-clock",
            synthetic_repo.t_clock.isoformat(),
        ])
        assert code == 2, f"Expected exit code 2 on verification failure, got {code}"


def test_rmtree_force_symlink_to_host_file_in_readonly_dir(tmp_path: Path) -> None:
    """(a) a directory containing a symlink to a 'host' file outside the tree,
    with the directory made read-only (chmod 0o555): rmtree_force removes the tree
    and the host file's mode is unchanged."""
    if os.geteuid() == 0:
        pytest.skip("Read-only directory test requires non-root user")

    host_file = tmp_path / "host_file.txt"
    host_file.write_text("host content\n")
    os.chmod(host_file, 0o644)
    orig_mode = stat.S_IMODE(os.lstat(host_file).st_mode)

    tree = tmp_path / "dir_to_remove"
    tree.mkdir()
    link = tree / "symlink_to_host"
    link.symlink_to(host_file)

    os.chmod(tree, 0o555)
    try:
        rmtree_force(tree)
    finally:
        if tree.exists():
            os.chmod(tree, 0o755)

    assert not tree.exists(), "Tree must be completely removed"
    assert host_file.exists(), "Host file must still exist"
    assert host_file.read_text() == "host content\n"
    current_mode = stat.S_IMODE(os.lstat(host_file).st_mode)
    assert current_mode == orig_mode, f"Host file mode changed from {oct(orig_mode)} to {oct(current_mode)}"


def test_clean_directory_symlink_to_host_directory(tmp_path: Path) -> None:
    """(b) _clean_directory on a directory containing a symlink to a host directory:
    the host directory and its contents are untouched and the link is gone."""
    host_dir = tmp_path / "host_dir"
    host_dir.mkdir()
    (host_dir / "file1.txt").write_text("precious file 1")
    (host_dir / "subdir").mkdir()
    (host_dir / "subdir" / "file2.txt").write_text("precious file 2")

    clean_dir = tmp_path / "dest_to_clean"
    clean_dir.mkdir()
    link = clean_dir / "link_to_host_dir"
    link.symlink_to(host_dir)

    _clean_directory(clean_dir)

    assert clean_dir.exists(), "clean_dir itself should remain existing"
    assert list(clean_dir.iterdir()) == [], "clean_dir should be empty"
    assert host_dir.exists(), "host directory must remain untouched"
    assert (host_dir / "file1.txt").read_text() == "precious file 1"
    assert (host_dir / "subdir" / "file2.txt").read_text() == "precious file 2"


def test_rootfs_clean_staging_readonly_dir_symlinked_history(tmp_path: Path) -> None:
    """(c) the rootfs builder test with a read-only staging directory holding a
    symlinked history file leaves the host target's mode unchanged."""
    if os.geteuid() == 0:
        pytest.skip("Read-only directory test requires non-root user")

    from hermetic_slice.rootfs import clean_rootfs_staging

    host_file = tmp_path / "host_bash_history"
    host_file.write_text("secret host commands\n")
    os.chmod(host_file, 0o600)
    orig_mode = stat.S_IMODE(os.lstat(host_file).st_mode)

    staging = tmp_path / "staging_ro"
    staging.mkdir()
    user_dir = staging / "home" / "user"
    user_dir.mkdir(parents=True)
    symlink_hist = user_dir / ".bash_history"
    symlink_hist.symlink_to(host_file.resolve())

    os.chmod(user_dir, 0o555)
    try:
        removed = clean_rootfs_staging(staging)
    finally:
        if user_dir.exists():
            os.chmod(user_dir, 0o755)

    assert "home/user/.bash_history" in removed
    assert not symlink_hist.exists()
    assert not symlink_hist.is_symlink()
    assert host_file.exists()
    assert host_file.read_text() == "secret host commands\n"
    current_mode = stat.S_IMODE(os.lstat(host_file).st_mode)
    assert current_mode == orig_mode, f"Host file mode changed from {oct(orig_mode)} to {oct(current_mode)}"
