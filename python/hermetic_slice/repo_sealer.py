"""Sealing git repositories to base commit reachable objects and cutoffs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Mapping

from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.gitutil import GitError, run_git


class UnsupportedRepoError(Exception):
    """Raised when repository uses unsupported features like submodules or LFS."""


class VerificationError(Exception):
    """Raised when sealed repository verification fails."""


@dataclass(frozen=True)
class SealReport:
    """Report detailing the results of repository sealing."""

    base_commit: str
    object_count: int
    kept_tags: dict[str, str]
    dropped_tags: dict[str, str]


def _rmtree(path: Path) -> None:
    """Remove a directory tree, clearing read-only flags and retrying on failure."""
    def _handle_onexc(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    def _handle_onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_handle_onexc)
    else:
        shutil.rmtree(path, onerror=_handle_onerror)


def _clean_directory(path: Path) -> None:
    """Remove all contents within a directory, handling read-only files."""
    if not path.exists():
        return
    for item in list(path.iterdir()):
        if item.is_dir():
            _rmtree(item)
        else:
            try:
                os.chmod(item, stat.S_IWRITE)
                item.unlink()
            except OSError:
                pass


def seal_repo(
    src: Path,
    base_commit: str,
    dest: Path,
    t_clock: datetime,
) -> SealReport:
    """Seal source repository to base commit reachability and copy into dest."""
    t_clock_utc = ensure_utc(t_clock, "t_clock")

    try:
        base_sha = run_git(["rev-parse", "--verify", f"{base_commit}^{{commit}}"], cwd=src).decode("ascii").strip()
    except GitError as exc:
        raise ValueError(f"Invalid base commit {base_commit}: {exc}") from exc

    obj_type = run_git(["cat-file", "-t", base_sha], cwd=src).decode("ascii").strip()
    if obj_type != "commit":
        raise ValueError(f"Base commit {base_commit} resolved to {obj_type}, not a commit")

    # Step 7: Submodules and LFS check before writing anything to dest
    submod_check = run_git(["ls-tree", base_sha, "--", ".gitmodules"], cwd=src).decode("utf-8", errors="replace").strip()
    if submod_check:
        raise UnsupportedRepoError("Submodules are not supported: .gitmodules exists at base_commit")

    attr_check = run_git(["ls-tree", base_sha, "--", ".gitattributes"], cwd=src).decode("utf-8", errors="replace").strip()
    if attr_check:
        attr_content = run_git(["show", f"{base_sha}:.gitattributes"], cwd=src).decode("utf-8", errors="replace")
        if "filter=lfs" in attr_content:
            raise UnsupportedRepoError("Git LFS is not supported: .gitattributes contains filter=lfs at base_commit")

    # Reachable commits from base commit computed once
    rev_list_out = run_git(["rev-list", base_sha], cwd=src).decode("ascii")
    reachable_commits = {line.strip() for line in rev_list_out.splitlines() if line.strip()}

    # Step 2: dest must not exist, or must be an empty directory
    dest_existed = dest.exists()
    if dest_existed:
        if not dest.is_dir() or any(dest.iterdir()):
            raise ValueError(f"Destination {dest} already exists and is not an empty directory")
    else:
        dest.mkdir(parents=True, exist_ok=True)

    # Step 4: Tags inspection in src
    kept_tags: dict[str, str] = {}
    dropped_tags: dict[str, str] = {}

    tags_out = run_git(
        [
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)%00%(*objecttype)%00%(taggerdate:unix)",
            "refs/tags",
        ],
        cwd=src,
    ).decode("utf-8", errors="replace")

    for line in tags_out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\0")
        if len(parts) < 6:
            continue
        ref_name, obj_sha, obj_type, peeled_sha, peeled_type, tagger_date_str = parts[:6]
        tag_name = ref_name.removeprefix("refs/tags/")

        if obj_type == "tag":
            if peeled_type != "commit" or not peeled_sha:
                dropped_tags[tag_name] = "not_commit"
                continue
            target_commit = peeled_sha
            if target_commit not in reachable_commits:
                dropped_tags[tag_name] = "not_ancestor"
                continue
            date_clean = tagger_date_str.strip()
            if not date_clean:
                dropped_tags[tag_name] = "no_tagger_date"
                continue
            try:
                tagger_dt = datetime.fromtimestamp(int(date_clean), tz=timezone.utc)
            except ValueError:
                dropped_tags[tag_name] = "no_tagger_date"
                continue
            if tagger_dt > t_clock_utc:
                dropped_tags[tag_name] = "tagger_after_t_clock"
                continue
            # TODO(phase1): D-tier check on tag message
            kept_tags[tag_name] = "ancestor"
        else:
            if obj_type != "commit":
                dropped_tags[tag_name] = "not_commit"
                continue
            target_commit = obj_sha
            if target_commit not in reachable_commits:
                dropped_tags[tag_name] = "not_ancestor"
                continue
            kept_tags[tag_name] = "ancestor"

    try:
        # Step 2 & 3: Create fresh repo with git init --template= and fetch reachable objects
        run_git(["init", "--template=", "-b", "sealed"], cwd=dest)
        run_git(["config", "core.logAllRefUpdates", "false"], cwd=dest)

        upload_pack_arg = "--upload-pack=git -c uploadpack.allowAnySHA1InWant=true upload-pack"
        src_abs = str(src.resolve())

        fetch_args = ["fetch", "--no-tags", upload_pack_arg, src_abs, base_sha]
        for tag_name in kept_tags:
            fetch_args.append(f"refs/tags/{tag_name}:refs/tags/{tag_name}")
        run_git(fetch_args, cwd=dest)

        # Step 5 & 6: Set refs, checkout base commit, clean forbidden paths
        run_git(["update-ref", "refs/heads/sealed", base_sha], cwd=dest)
        run_git(["symbolic-ref", "HEAD", "refs/heads/sealed"], cwd=dest)
        run_git(["checkout", "-f", "sealed"], cwd=dest)

        fetch_head = dest / ".git" / "FETCH_HEAD"
        if fetch_head.exists():
            fetch_head.unlink()

        orig_head = dest / ".git" / "ORIG_HEAD"
        if orig_head.exists():
            orig_head.unlink()

        logs_dir = dest / ".git" / "logs"
        if logs_dir.exists():
            shutil.rmtree(logs_dir, ignore_errors=True)

        hooks_dir = dest / ".git" / "hooks"
        if hooks_dir.exists():
            shutil.rmtree(hooks_dir, ignore_errors=True)

        worktrees_dir = dest / ".git" / "worktrees"
        if worktrees_dir.exists():
            shutil.rmtree(worktrees_dir, ignore_errors=True)

        alternates_file = dest / ".git" / "objects" / "info" / "alternates"
        if alternates_file.exists():
            alternates_file.unlink()

        http_alternates_file = dest / ".git" / "objects" / "info" / "http-alternates"
        if http_alternates_file.exists():
            http_alternates_file.unlink()

        remotes = run_git(["remote"], cwd=dest).decode("utf-8", errors="replace").splitlines()
        for remote in remotes:
            if remote.strip():
                run_git(["remote", "remove", remote.strip()], cwd=dest)

        for root, dirs, _ in os.walk(dest):
            if ".git" in dirs:
                dirs.remove(".git")
            for d in list(dirs):
                if d == "__pycache__":
                    shutil.rmtree(Path(root) / d, ignore_errors=True)
                    dirs.remove(d)

        # Step 8: Repack and prune
        run_git(["repack", "-a", "-d", "-f"], cwd=dest)
        run_git(["prune", "--expire=now"], cwd=dest)
        run_git(["commit-graph", "write", "--reachable"], cwd=dest)

        # Step 9: Verify sealed repo
        problems = verify_sealed_repo(dest, base_sha, kept_tags)
        if problems:
            raise VerificationError("Sealed repo verification failed:\n" + "\n".join(problems))

        obj_out = run_git(["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], cwd=dest).decode("ascii")
        object_count = len([line for line in obj_out.splitlines() if line.strip()])
    except BaseException as exc:
        if not dest_existed:
            if dest.exists():
                _rmtree(dest)
            if dest.exists():
                exc.add_note(f"cleanup incomplete: {dest}")
        else:
            if dest.exists():
                _clean_directory(dest)
                if any(dest.iterdir()):
                    exc.add_note(f"cleanup incomplete: {dest}")
        raise

    return SealReport(
        base_commit=base_sha,
        object_count=object_count,
        kept_tags=kept_tags,
        dropped_tags=dropped_tags,
    )


def verify_sealed_repo(
    repo: Path,
    base_commit: str,
    allowed_tags: Mapping[str, str],
) -> list[str]:
    """Verify that a repository adheres to sealed repository integrity rules."""
    problems: list[str] = []

    try:
        base_sha = run_git(["rev-parse", "--verify", f"{base_commit}^{{commit}}"], cwd=repo).decode("ascii").strip()
    except GitError:
        problems.append(f"base_commit {base_commit} cannot be resolved in repository")
        return problems

    try:
        reachable_out = run_git(["rev-list", "--objects", "--no-object-names", base_sha], cwd=repo).decode("ascii")
        expected_objects = {line.strip() for line in reachable_out.splitlines() if line.strip()}
    except GitError as exc:
        problems.append(f"Failed to list reachable objects from {base_sha}: {exc}")
        expected_objects = set()

    for tag in allowed_tags:
        tag_ref = tag if tag.startswith("refs/tags/") else f"refs/tags/{tag}"
        try:
            tag_sha = run_git(["rev-parse", "--verify", tag_ref], cwd=repo).decode("ascii").strip()
            obj_type = run_git(["cat-file", "-t", tag_sha], cwd=repo).decode("ascii").strip()
            if obj_type == "tag":
                expected_objects.add(tag_sha)
        except GitError:
            pass

    all_obj_out = run_git(["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], cwd=repo).decode("ascii")
    all_objects = {line.strip() for line in all_obj_out.splitlines() if line.strip()}

    unexpected = all_objects - expected_objects
    if unexpected:
        problems.append(f"Unexpected objects found in repo: {sorted(unexpected)}")

    missing = expected_objects - all_objects
    if missing:
        problems.append(f"Expected objects missing from repo: {sorted(missing)}")

    # Check refs
    allowed_ref_names = {"refs/heads/sealed"}
    for tag in allowed_tags:
        t_ref = tag if tag.startswith("refs/tags/") else f"refs/tags/{tag}"
        allowed_ref_names.add(t_ref)

    refs_out = run_git(["for-each-ref", "--format=%(refname) %(objectname)"], cwd=repo).decode("utf-8", errors="replace")
    existing_refs: dict[str, str] = {}
    for line in refs_out.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split()
        if len(parts) >= 2:
            existing_refs[parts[0]] = parts[1]

    for refname, refsha in existing_refs.items():
        if refname not in allowed_ref_names:
            problems.append(f"Forbidden ref present in repo: {refname}")
        elif refname == "refs/heads/sealed" and refsha != base_sha:
            problems.append(f"refs/heads/sealed points to {refsha}, expected {base_sha}")

    if "refs/heads/sealed" not in existing_refs:
        problems.append("Missing required ref: refs/heads/sealed")

    for t_ref in allowed_ref_names:
        if t_ref not in existing_refs:
            problems.append(f"Missing expected allowed tag ref: {t_ref}")

    # Check HEAD
    try:
        head_target = run_git(["symbolic-ref", "HEAD"], cwd=repo).decode("utf-8", errors="replace").strip()
        if head_target != "refs/heads/sealed":
            problems.append(f"HEAD does not point to refs/heads/sealed: {head_target}")
    except GitError:
        problems.append("HEAD is not a symbolic ref")

    # Check forbidden paths and configs
    if (repo / ".git" / "FETCH_HEAD").exists():
        problems.append("Forbidden path exists: .git/FETCH_HEAD")

    if (repo / ".git" / "ORIG_HEAD").exists():
        problems.append("Forbidden path exists: .git/ORIG_HEAD")

    logs_dir = repo / ".git" / "logs"
    if logs_dir.exists() and any(logs_dir.rglob("*")):
        problems.append("Forbidden directory .git/logs is present and not empty")

    hooks_dir = repo / ".git" / "hooks"
    if hooks_dir.exists() and any(hooks_dir.iterdir()):
        problems.append("Forbidden hooks directory is present and not empty")

    worktrees_dir = repo / ".git" / "worktrees"
    if worktrees_dir.exists() and any(worktrees_dir.iterdir()):
        problems.append("Forbidden directory .git/worktrees is present and not empty")

    if (repo / ".git" / "objects" / "info" / "alternates").exists():
        problems.append("Forbidden path exists: .git/objects/info/alternates")

    if (repo / ".git" / "objects" / "info" / "http-alternates").exists():
        problems.append("Forbidden path exists: .git/objects/info/http-alternates")

    remotes = run_git(["remote"], cwd=repo).decode("utf-8", errors="replace").splitlines()
    if any(r.strip() for r in remotes):
        problems.append(f"Remotes found in repo: {[r.strip() for r in remotes if r.strip()]}")

    try:
        log_ref = run_git(["config", "--get", "core.logAllRefUpdates"], cwd=repo).decode("utf-8", errors="replace").strip()
        if log_ref.lower() in ("true", "always"):
            problems.append(f"core.logAllRefUpdates is configured as {log_ref}")
    except GitError:
        pass

    for forbidden in ["pull", "original", "notes", "replace"]:
        if (repo / ".git" / "refs" / forbidden).exists():
            problems.append(f"Forbidden ref directory exists: .git/refs/{forbidden}")

    if (repo / ".git" / "refs" / "stash").exists():
        problems.append("Forbidden ref file exists: .git/refs/stash")

    return problems
