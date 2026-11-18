"""Deterministic Mode G /opt/agent volume builder with D4 guard (TR-GW-*, §9.3).

Builds a reproducible, read-only ext4 filesystem image for the agent toolchain
mounted at /opt/agent by execd inside AgentVM.

The agent volume is class C (exempt from date gates, still scanned by D2 and D9,
and D4-verified with timestamps clamped to t_clock).
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime
import errno
import json
import os
from pathlib import Path
import stat
import sys

from hermetic_safe_io import open_parent, UnsafePathError
from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.guest_kernel import DEFAULT_KERNEL_DIR
from hermetic_slice.repo_sealer import remove_tree_at
from hermetic_slice.rootfs import (
    build_rootfs,
    open_dir_anchored,
    RootfsLimits,
    DEFAULT_MAX_LOGICAL_BYTES,
)

MAX_AGENT_FILES = 100_000
MAX_AGENT_VOLUME_BYTES = 512 * 1024 * 1024
MAX_DEPTH = 64
MAX_PATH_BYTES = 4096
MAX_TEMP_ATTEMPTS = 64
MIN_CLOCK = 315532800
MAX_CLOCK = 4102444799


def _publish_tree(parent: int, staged: str, leaf: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(staged), parent, os.fsencode(leaf), 1) != 0:
        raise OSError(ctypes.get_errno(), "cannot publish agent volume tree")
    os.fsync(parent)


def _validate_rel_path(path_str: str) -> list[str]:
    if not isinstance(path_str, str) or not path_str or len(path_str) > MAX_PATH_BYTES or "\0" in path_str:
        raise ValueError(f"Invalid path: {path_str!r}")
    if path_str.startswith("/") or path_str.endswith("/"):
        raise ValueError(f"Relative file path expected: {path_str!r}")
    parts = path_str.split("/")
    if any(p in ("", ".", "..") for p in parts) or len(parts) > MAX_DEPTH:
        raise ValueError(f"Invalid relative path components: {path_str!r}")
    return parts


def _collect_source_dir(source_dir: Path) -> dict[str, tuple[bytes, int]]:
    source_dir = Path(source_dir)
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source directory does not exist or is not a directory: {source_dir}")
    if source_dir.is_symlink():
        raise ValueError(f"Symlinks in agent volume are refused: {source_dir}")
    collected: dict[str, tuple[bytes, int]] = {}
    total_bytes = 0
    root_fd = open_dir_anchored(source_dir)
    stack: list[tuple[int, str, int]] = [(root_fd, "", 0)]
    try:
        while stack:
            curr_fd, prefix, depth = stack.pop()
            try:
                if depth > MAX_DEPTH:
                    raise ValueError(f"Source directory depth exceeds cap {MAX_DEPTH}")
                with os.scandir(curr_fd) as it:
                    entries = sorted(it, key=lambda e: e.name)
                for entry in entries:
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(st.st_mode):
                        raise ValueError(f"Symlinks in agent volume are refused: {prefix}{entry.name}")
                    if not stat.S_ISDIR(st.st_mode) and not stat.S_ISREG(st.st_mode):
                        raise ValueError(f"Special files in agent volume are refused: {prefix}{entry.name}")
                    rel_name = f"{prefix}{entry.name}" if not prefix else f"{prefix}/{entry.name}"
                    if stat.S_ISDIR(st.st_mode):
                        if depth + 1 > MAX_DEPTH:
                            raise ValueError(f"Source directory depth exceeds cap {MAX_DEPTH}")
                        try:
                            child_fd = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=curr_fd,
                            )
                        except OSError as exc:
                            if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
                                raise ValueError(f"Symlinks in agent volume are refused: {rel_name}") from exc
                            raise
                        try:
                            cur_st = os.fstat(child_fd)
                            if (cur_st.st_dev, cur_st.st_ino, cur_st.st_mode) != (st.st_dev, st.st_ino, st.st_mode):
                                raise RuntimeError(f"Directory {rel_name} changed during walk")
                        except BaseException:
                            os.close(child_fd)
                            raise
                        stack.append((child_fd, rel_name, depth + 1))
                    else:
                        if len(collected) >= MAX_AGENT_FILES:
                            raise ValueError(f"Source directory entries exceed cap {MAX_AGENT_FILES}")
                        if st.st_size > MAX_AGENT_VOLUME_BYTES:
                            raise ValueError(f"File {rel_name} exceeds byte cap")
                        try:
                            fd = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                dir_fd=curr_fd,
                            )
                        except OSError as exc:
                            if exc.errno in (errno.ELOOP, errno.ENOENT):
                                raise ValueError(f"Symlinks in agent volume are refused: {rel_name}") from exc
                            raise
                        try:
                            cur_st = os.fstat(fd)
                            if (cur_st.st_dev, cur_st.st_ino, cur_st.st_mode) != (st.st_dev, st.st_ino, st.st_mode):
                                raise RuntimeError(f"File {rel_name} changed during walk")
                            with os.fdopen(fd, "rb", closefd=False) as f:
                                data = f.read(MAX_AGENT_VOLUME_BYTES + 1)
                        finally:
                            os.close(fd)
                        if len(data) > MAX_AGENT_VOLUME_BYTES:
                            raise ValueError(f"File {rel_name} exceeds byte cap")
                        total_bytes += len(data)
                        if total_bytes > MAX_AGENT_VOLUME_BYTES:
                            raise ValueError(f"Total agent volume bytes exceed cap {MAX_AGENT_VOLUME_BYTES}")
                        mode = 0o755 if (st.st_mode & 0o111) else 0o644
                        collected[rel_name] = (data, mode)
            finally:
                os.close(curr_fd)
    finally:
        while stack:
            fd, _, _ = stack.pop()
            try:
                os.close(fd)
            except OSError:
                pass
    return collected


def build_agent_volume_tree(
    tree: Path,
    *,
    files: dict[str, bytes | tuple[bytes, int]] | None = None,
    source_dir: Path | None = None,
    t_clock: datetime,
) -> Path:
    """Create a fresh deterministic agent volume tree at ``tree`` (which must not exist)."""
    if files is None and source_dir is None:
        raise ValueError("Either files or source_dir must be provided")

    t_clock_utc = ensure_utc(t_clock, "t_clock")
    epoch = int(t_clock_utc.timestamp())
    if not MIN_CLOCK <= epoch <= MAX_CLOCK:
        raise ValueError(f"t_clock epoch {epoch} out of range [{MIN_CLOCK}, {MAX_CLOCK}]")

    all_files: dict[str, tuple[bytes, int]] = {}
    if source_dir is not None:
        all_files.update(_collect_source_dir(source_dir))

    if files is not None:
        total_bytes = sum(len(data) for data, _ in all_files.values())
        for path_str, val in files.items():
            _validate_rel_path(path_str)
            if isinstance(val, tuple):
                data, mode = val
            elif isinstance(val, (bytes, bytearray)):
                data = bytes(val)
                mode = 0o755 if (path_str.startswith("bin/") or path_str.endswith(".sh") or path_str == "run") else 0o644
            else:
                raise TypeError(f"Invalid file content for {path_str}: expected bytes or (bytes, mode)")
            if len(data) > MAX_AGENT_VOLUME_BYTES:
                raise ValueError(f"File {path_str} exceeds byte cap")
            if path_str not in all_files:
                if len(all_files) >= MAX_AGENT_FILES:
                    raise ValueError(f"Agent volume entries exceed cap {MAX_AGENT_FILES}")
                old_size = 0
            else:
                old_size = len(all_files[path_str][0])
            if total_bytes - old_size + len(data) > MAX_AGENT_VOLUME_BYTES:
                raise ValueError(f"Total agent volume bytes exceed cap {MAX_AGENT_VOLUME_BYTES}")
            total_bytes = total_bytes - old_size + len(data)
            all_files[path_str] = (data, mode)

    parent, leaf = open_parent(tree)
    staged = None
    directory = None
    try:
        try:
            os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"agent volume tree already exists: {leaf}")
        if os.fstat(parent).st_mode & 0o022:
            raise UnsafePathError("agent volume output parent must not be writable by other users")

        for attempt in range(MAX_TEMP_ATTEMPTS):
            candidate = f".agent-volume-tree.{attempt}"
            if candidate == leaf:
                continue
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            staged = candidate
            break
        if staged is None:
            raise OSError(errno.EEXIST, "agent volume temporary attempts exhausted")

        directory = os.open(staged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        anchor = Path(f"/proc/self/fd/{directory}")

        all_dirs: set[str] = set()
        for rel_path in all_files:
            parts = rel_path.split("/")
            for i in range(1, len(parts)):
                all_dirs.add("/".join(parts[:i]))
        sorted_dirs = sorted(all_dirs, key=lambda d: (d.count("/"), d))
        for d in sorted_dirs:
            target = anchor / d
            if not target.exists():
                os.mkdir(target, 0o700)

        for rel_path, (data, mode) in all_files.items():
            target = anchor / rel_path
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fchmod(f.fileno(), mode)
                os.utime(f.fileno(), (epoch, epoch))
                os.fsync(f.fileno())

        for d in sorted(sorted_dirs, key=lambda d: (-d.count("/"), d)):
            fd = os.open(anchor / d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fchmod(fd, 0o755)
                os.utime(fd, (epoch, epoch))
                os.fsync(fd)
            finally:
                os.close(fd)

        os.fchmod(directory, 0o755)
        os.utime(directory, (epoch, epoch))
        os.fsync(directory)

        _publish_tree(parent, staged, leaf)
        staged = None
    finally:
        if directory is not None:
            os.close(directory)
        if staged is not None:
            remove_tree_at(parent, staged)
        os.close(parent)

    return Path(tree)


def build_agent_volume_image(
    tree: Path,
    out_image: Path,
    *,
    files: dict[str, bytes | tuple[bytes, int]] | None = None,
    source_dir: Path | None = None,
    t_clock: datetime,
    world_id: str,
    sealcheck_bin: Path | None = None,
    work_dir: Path | None = None,
    size_mib: int | None = None,
    kernel_lock: Path = DEFAULT_KERNEL_DIR / "kernel.lock.json",
    kernel_image: Path | None = None,
    clockprobe_bin: Path | None = None,
) -> dict:
    """Build the agent volume tree and a D4-checked read-only ext4 image from it."""
    tree = Path(tree)
    if not tree.exists():
        build_agent_volume_tree(
            tree,
            files=files,
            source_dir=source_dir,
            t_clock=t_clock,
        )
    result = build_rootfs(
        tree,
        out_image,
        t_clock=t_clock,
        world_id=f"agent-volume:{world_id}",
        size_mib=size_mib,
        sealcheck_bin=sealcheck_bin,
        work_dir=work_dir,
        limits=RootfsLimits(
            max_bytes=MAX_AGENT_VOLUME_BYTES,
            max_entries=MAX_AGENT_FILES,
            max_depth=MAX_DEPTH,
            max_logical_bytes=DEFAULT_MAX_LOGICAL_BYTES,
        ),
        kernel_lock=kernel_lock,
        kernel_image=kernel_image,
        clockprobe_bin=clockprobe_bin,
        root_owned=True,
    )
    result["agent_volume_digest"] = f"sha256:{result['sha256']}"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic Mode G agent volume builder")
    parser.add_argument("--tree", required=True, type=Path, help="Directory for the staged tree")
    parser.add_argument("--out-image", required=True, type=Path, help="Output path for the ext4 image")
    parser.add_argument("--source-dir", type=Path, default=None, help="Source directory containing agent files")
    parser.add_argument("--t-clock", required=True, help="Clock cutoff timestamp (RFC 3339)")
    parser.add_argument("--world-id", required=True, help="World identifier")
    parser.add_argument("--sealcheck-bin", type=Path, default=None, help="Explicit path to hermetic-sealcheck")
    parser.add_argument("--work-dir", type=Path, default=None, help="Work directory for temporary files")
    parser.add_argument("--size-mib", type=int, default=None, help="Filesystem size in MiB")
    args = parser.parse_args(argv)

    t_clock = ensure_utc(datetime.fromisoformat(args.t_clock.replace("Z", "+00:00")), "t_clock")
    res = build_agent_volume_image(
        tree=args.tree,
        out_image=args.out_image,
        source_dir=args.source_dir,
        t_clock=t_clock,
        world_id=args.world_id,
        sealcheck_bin=args.sealcheck_bin,
        work_dir=args.work_dir,
        size_mib=args.size_mib,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
