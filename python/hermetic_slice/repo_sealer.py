"""Sealing git repositories to base commit reachable objects and cutoffs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
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


_O_PATH = getattr(os, "O_PATH", 0)
_LOOKUP_FLAGS = (_O_PATH or os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_dir_anchored(dirpath) -> int:
    """Open a directory by walking its absolute path from "/" one component at a time with
    O_NOFOLLOW|O_DIRECTORY relative to the previous descriptor: a symlink anywhere in the path,
    an ancestor swapped for a symlink included, fails with ELOOP/ENOTDIR instead of being followed."""
    absolute = os.path.abspath(os.fspath(dirpath))
    fd = os.open("/", _LOOKUP_FLAGS)
    try:
        for part in absolute.split("/"):
            if part in ("", "."):
                continue
            next_fd = os.open(part, _LOOKUP_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_parent_anchored(path) -> tuple[int, str]:
    absolute = os.path.abspath(os.fspath(path))
    parent, name = os.path.split(absolute)
    if not name:
        raise OSError(errno.EINVAL, "path has no final component", absolute)
    return _open_dir_anchored(parent), name


def _fchmod_any(fd: int, mode: int) -> None:
    """chmod the inode behind fd (an O_PATH descriptor is changed through /proc/self/fd)."""
    try:
        os.fchmod(fd, mode)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        os.chmod(f"/proc/self/fd/{fd}", mode)


def _chmod_at(dir_fd: int, name: str, mode: int) -> bool:
    """chmod the entry name inside dir_fd itself; False (nothing changed) if it is a symlink."""
    flags = (_O_PATH or (os.O_RDONLY | os.O_NONBLOCK)) | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return False
        raise
    try:
        if stat.S_ISLNK(os.fstat(fd).st_mode):
            return False
        _fchmod_any(fd, mode)
        return True
    finally:
        os.close(fd)


def _add_owner_rwx(fd: int) -> None:
    _fchmod_any(fd, stat.S_IMODE(os.fstat(fd).st_mode) | stat.S_IRWXU)


def chmod_nofollow(path, mode: int) -> bool:
    """chmod path itself, never a symlink target and never through a symlinked ancestor.

    The parent directory is reached by anchored component-wise descriptor traversal from "/"
    (O_NOFOLLOW at each level) and the entry is opened relative to it with O_NOFOLLOW; the
    mode is changed on that descriptor. Returns False and changes nothing if the entry or any
    ancestor is a symlink.
    """
    try:
        parent_fd, name = _open_parent_anchored(path)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return False
        raise
    try:
        return _chmod_at(parent_fd, name, mode)
    finally:
        os.close(parent_fd)


def _remove_at(func, parent_fd: int, name: str) -> None:
    if func is os.rmdir:
        os.rmdir(name, dir_fd=parent_fd)
    elif func in (os.unlink, os.remove):
        os.unlink(name, dir_fd=parent_fd)
    # Other failing calls (open, scandir, lstat) need no retry here: making the entry
    # writable/searchable is the fix, and rmtree's own removal then proceeds or reports.


def _make_writable_and_retry(func, path, _exc):
    """shutil.rmtree error handler: every chmod, unlink and rmdir is relative to the parent's
    descriptor, reached without following any symlink (a swapped ancestor is refused)."""
    try:
        parent_fd, name = _open_parent_anchored(path)
    except OSError:
        return
    try:
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            _add_owner_rwx(parent_fd)
            os.unlink(name, dir_fd=parent_fd)
            return
        # S_IWRITE alone would strip r/x from directories on POSIX.
        if not _chmod_at(parent_fd, name, stat.S_IRWXU):
            os.unlink(name, dir_fd=parent_fd)  # swapped for a symlink: remove the link only
            return
        try:
            _remove_at(func, parent_fd, name)
        except OSError:
            _add_owner_rwx(parent_fd)
            _remove_at(func, parent_fd, name)
    except OSError:
        pass
    finally:
        os.close(parent_fd)


def _open_subdir_for_removal(parent_fd: int, name: str) -> int | None:
    """Open name inside parent_fd as a directory without following symlinks; None if it is
    not a directory (anymore). Grants owner rwx (on the opened inode) when needed."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return None
        if exc.errno != errno.EACCES or not _chmod_at(parent_fd, name, stat.S_IRWXU):
            raise
        fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        st = os.fstat(fd)
        if (st.st_mode & stat.S_IRWXU) != stat.S_IRWXU:
            _fchmod_any(fd, stat.S_IMODE(st.st_mode) | stat.S_IRWXU)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _unlink_at(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except PermissionError:
        _add_owner_rwx(dir_fd)
        os.unlink(name, dir_fd=dir_fd)


def _list_for_removal(fd: int) -> list[tuple[str, bool]]:
    with os.scandir(fd) as it:
        return [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in it]


def remove_tree_at(parent_fd: int, name: str) -> None:
    """Remove the entry name inside parent_fd, recursively, entirely through descriptors.

    Iterative; every directory is opened with O_NOFOLLOW|O_DIRECTORY relative to its parent's
    descriptor, entries are typed with lstat-equivalent checks (scandir without following),
    and unlink/rmdir/chmod are all relative to held descriptors. A symlink is removed as a
    link and never followed, so swapping any directory for a symlink mid-removal cannot reach
    outside the tree. Errors propagate (OSError).
    """
    st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode):
        _unlink_at(parent_fd, name)
        return
    top = _open_subdir_for_removal(parent_fd, name)
    if top is None:
        _unlink_at(parent_fd, name)
        return
    stack: list[tuple[int, str, list[tuple[str, bool]]]] = [(top, name, _list_for_removal(top))]
    try:
        while stack:
            fd, dir_name, entries = stack[-1]
            if entries:
                entry_name, is_dir = entries.pop()
                child = _open_subdir_for_removal(fd, entry_name) if is_dir else None
                if child is None:
                    _unlink_at(fd, entry_name)
                else:
                    try:
                        child_entries = _list_for_removal(child)
                    except BaseException:
                        os.close(child)
                        raise
                    stack.append((child, entry_name, child_entries))
                continue
            stack.pop()
            os.close(fd)
            holder = stack[-1][0] if stack else parent_fd
            try:
                os.rmdir(dir_name, dir_fd=holder)
            except PermissionError:
                _add_owner_rwx(holder)
                os.rmdir(dir_name, dir_fd=holder)
    finally:
        for fd, _, _ in stack:
            os.close(fd)


def rmtree_force(path: Path) -> None:
    """Remove a directory tree (or a single entry), clearing read-only flags as needed.

    The parent is reached by anchored descriptor traversal (no symlink followed anywhere in
    the path) and the removal is descriptor-relative (remove_tree_at). A path under a
    symlinked ancestor is left alone. Like shutil.rmtree with a swallowing error handler,
    this never raises; callers check whether the path still exists.
    """
    try:
        parent_fd, name = _open_parent_anchored(path)
    except OSError:
        return
    try:
        remove_tree_at(parent_fd, name)
    except OSError:
        pass
    finally:
        os.close(parent_fd)


def _clean_directory(path: Path) -> None:
    """Remove all contents within a directory, handling read-only files.

    The directory is opened by anchored descriptor traversal (no symlink followed anywhere in
    its path); entries are listed and removed relative to that descriptor (remove_tree_at).
    """
    path = Path(path)
    try:
        parent_fd, name = _open_parent_anchored(path)
    except OSError:
        return
    try:
        dir_fd = _open_subdir_for_removal(parent_fd, name)
    except OSError:
        dir_fd = None
    finally:
        os.close(parent_fd)
    if dir_fd is None:
        return
    try:
        for entry_name, _is_dir in _list_for_removal(dir_fd):
            try:
                remove_tree_at(dir_fd, entry_name)
            except OSError:
                pass
    finally:
        os.close(dir_fd)


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
                rmtree_force(dest)
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
