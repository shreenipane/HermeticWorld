"""Collect known passing fixes for one task into ``staging/fixes/`` (TR-SC-1).

Source layout (the public SWE-bench experiments repository)::

    <experiments>/evaluation/<split>/<run>/logs/<instance_id>/patch.diff
    <experiments>/evaluation/<split>/<run>/logs/<instance_id>/report.json

A run's patch is a passing fix only when its ``report.json`` names the
instance with ``"resolved": true``. Fixes are deduplicated by their normalised
text (line endings and trailing whitespace), capped at ``MAX_FIXES`` (the most
sealcheck fingerprints, TR-SC-1), and written deterministically as
``NNN-<sha12>.patch`` in ascending digest order, so the same experiments tree
always produces the same files.

Every directory is opened relative to its parent's descriptor with
``O_NOFOLLOW``; symlinks, FIFOs and devices are skipped, never followed.
Counts and sizes are capped. Nothing outside the task's ``staging/fixes`` is
written, and an existing fixes directory is replaced only as a whole.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

MAX_FIXES = 20
MAX_PATCH_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_RUNS = 10_000
MAX_SPLITS = 64
_INSTANCE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class FixCollectionError(Exception):
    """Invalid input or an unsafe tree; nothing was written."""


def _open_dir_at(parent: int, name: str) -> int | None:
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent)
    except OSError:
        return None  # missing, a symlink or not a directory: skipped


def _read_at(parent: int, name: str, cap: int) -> bytes | None:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        data = os.read(fd, cap + 1)
        return data if len(data) <= cap else None
    finally:
        os.close(fd)


def _subdirs(fd: int, cap: int) -> list[str]:
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= cap:
                raise FixCollectionError("directory entry cap exceeded")
            if entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
    return sorted(names)


def _resolved(report: bytes, instance_id: str) -> bool:
    try:
        doc = json.loads(report.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    entry = doc.get(instance_id) if isinstance(doc, dict) else None
    return isinstance(entry, dict) and entry.get("resolved") is True


def normalise(patch: str) -> str:
    """The text compared for deduplication: LF line ends, no trailing whitespace."""
    lines = patch.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n") + "\n"


def find_passing_fixes(experiments: str | os.PathLike[str], instance_id: str) -> list[str]:
    """Deduplicated passing fixes for one instance, in ascending digest order (capped)."""
    if not isinstance(instance_id, str) or not _INSTANCE.fullmatch(instance_id):
        raise FixCollectionError("invalid instance id")
    try:
        root = os.open(os.fspath(experiments), _DIR_FLAGS)
    except OSError:
        raise FixCollectionError("experiments root refused (missing or symlink)") from None
    fixes: dict[str, str] = {}
    try:
        evaluation = _open_dir_at(root, "evaluation")
        if evaluation is None:
            return []
        try:
            for split in _subdirs(evaluation, MAX_SPLITS):
                split_fd = _open_dir_at(evaluation, split)
                if split_fd is None:
                    continue
                try:
                    for run in _subdirs(split_fd, MAX_RUNS):
                        run_fd = _open_dir_at(split_fd, run)
                        if run_fd is None:
                            continue
                        try:
                            logs = _open_dir_at(run_fd, "logs")
                            if logs is None:
                                continue
                            try:
                                task = _open_dir_at(logs, instance_id)
                                if task is None:
                                    continue
                                try:
                                    report = _read_at(task, "report.json", MAX_REPORT_BYTES)
                                    patch = _read_at(task, "patch.diff", MAX_PATCH_BYTES)
                                finally:
                                    os.close(task)
                            finally:
                                os.close(logs)
                        finally:
                            os.close(run_fd)
                        if report is None or patch is None or not _resolved(report, instance_id):
                            continue
                        try:
                            text = normalise(patch.decode("utf-8"))
                        except UnicodeDecodeError:
                            continue
                        if not text.strip():
                            continue
                        fixes.setdefault(hashlib.sha256(text.encode()).hexdigest(), text)
                finally:
                    os.close(split_fd)
        finally:
            os.close(evaluation)
    finally:
        os.close(root)
    return [fixes[d] for d in sorted(fixes)][:MAX_FIXES]


def write_passing_fixes(task_dir: str | os.PathLike[str], fixes: list[str]) -> list[str]:
    """Replace ``<task_dir>/staging/fixes`` with ``fixes``; returns the file names."""
    from hermetic_safe_io import atomic_write_at

    if len(fixes) > MAX_FIXES:
        raise FixCollectionError("too many fixes")
    try:
        task = os.open(os.fspath(task_dir), _DIR_FLAGS)
    except OSError:
        raise FixCollectionError("task directory refused (missing or symlink)") from None
    try:
        try:
            os.mkdir("staging", 0o755, dir_fd=task)
        except FileExistsError:
            pass
        staging = _open_dir_at(task, "staging")
        if staging is None:
            raise FixCollectionError("staging is not a directory")
        try:
            new = f".fixes-{os.getpid()}"
            os.mkdir(new, 0o755, dir_fd=staging)
            new_fd = os.open(new, _DIR_FLAGS, dir_fd=staging)
            names = []
            try:
                for index, text in enumerate(fixes, 1):
                    digest = hashlib.sha256(text.encode()).hexdigest()
                    name = f"{index:03d}-{digest[:12]}.patch"
                    atomic_write_at(new_fd, name, text.encode())
                    names.append(name)
            finally:
                os.close(new_fd)
            _replace_dir(staging, new, "fixes")
            return names
        finally:
            os.close(staging)
    finally:
        os.close(task)


def _replace_dir(parent: int, new: str, name: str) -> None:
    """Swap ``new`` into place as ``name``; a previous directory is removed only
    after the swap, and only its regular files (no symlink is followed)."""
    old = None
    try:
        st = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISDIR(st.st_mode):
            raise FixCollectionError("staging/fixes is not a directory")
        old = f".fixes-old-{os.getpid()}"
        os.rename(name, old, src_dir_fd=parent, dst_dir_fd=parent)
    os.rename(new, name, src_dir_fd=parent, dst_dir_fd=parent)
    if old is not None:
        old_fd = os.open(old, _DIR_FLAGS, dir_fd=parent)
        try:
            with os.scandir(old_fd) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                        os.unlink(entry.name, dir_fd=old_fd)
        finally:
            os.close(old_fd)
        os.rmdir(old, dir_fd=parent)


def collect(experiments: str | os.PathLike[str], task_dir: str | os.PathLike[str],
            instance_id: str) -> list[str]:
    return write_passing_fixes(task_dir, find_passing_fixes(experiments, instance_id))
