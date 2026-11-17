"""ExtractorVM rootfs tree and clean read-only image builder.

The ExtractorVM image holds only the static extractor binary as
``/sbin/hermetic-extract-init`` (and ``/sbin/hermetic-extract-agent``), the mount
points for base, overlay, and merged filesystems, and the substrate bound files.
The image is a D4-checked, read-only ext4 built by
:func:`hermetic_slice.rootfs.build_rootfs`.
"""

from __future__ import annotations

import ctypes
from datetime import datetime
import errno
import json
import os
from pathlib import Path
import shutil

from hermetic_safe_io import open_parent, open_regular, UnsafePathError
from hermetic_slice.guest_kernel import DEFAULT_KERNEL_DIR
from hermetic_slice.substrate import substrate_files

EXTRACTOR_INIT = "/sbin/hermetic-extract-init"
EXTRACTOR_AGENT = "/sbin/hermetic-extract-agent"
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MIN_CLOCK = 315532800
MAX_CLOCK = 4102444799
MAX_TEMP_ATTEMPTS = 64

_TREE_DIRS = (
    "sbin",
    "dev",
    "proc",
    "mnt",
    "mnt/base",
    "mnt/overlay",
    "mnt/merged",
    "etc",
    "etc/hermetic",
)


def _read_regular(path: Path, cap: int, what: str) -> bytes:
    """Read a regular, non-symlink file of at most ``cap`` bytes."""
    fd = open_regular(path, cap)
    with os.fdopen(fd, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{what} exceeds byte cap")
    return data


def _publish_tree(parent: int, staged: str, leaf: str) -> None:
    """Linux renameat2(RENAME_NOREPLACE) publishes a complete tree atomically."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(staged), parent, os.fsencode(leaf), 1) != 0:
        raise OSError(ctypes.get_errno(), "cannot publish extractor tree")
    os.fsync(parent)


def build_extractor_tree(
    tree: Path,
    *,
    extractor_bin: Path,
    t_clock: datetime,
    agent_bin: Path | None = None,
    extract_config: dict | None = None,
    kernel_lock: Path = DEFAULT_KERNEL_DIR / "kernel.lock.json",
    kernel_image: Path | None = None,
    clockprobe_bin: Path | None = None,
) -> Path:
    """Create a fresh ExtractorVM rootfs tree at ``tree`` (which must not exist)."""
    if t_clock.tzinfo is None or t_clock.utcoffset() is None:
        raise ValueError("t_clock must be timezone-aware and in range")
    epoch = int(t_clock.timestamp())
    if not MIN_CLOCK <= epoch <= MAX_CLOCK:
        raise ValueError("t_clock must be timezone-aware and in range")

    extractor = _read_regular(extractor_bin, MAX_BINARY_BYTES, "extractor binary")
    if len(extractor) < 4 or not extractor.startswith(b"\x7fELF"):
        raise ValueError("extractor binary must be an ELF executable")

    if agent_bin is not None:
        agent = _read_regular(agent_bin, MAX_BINARY_BYTES, "agent binary")
        if len(agent) < 4 or not agent.startswith(b"\x7fELF"):
            raise ValueError("agent binary must be an ELF executable")
    else:
        agent = extractor

    files: dict[str, tuple[bytes, int]] = {
        "sbin/hermetic-extract-init": (extractor, 0o755),
        "sbin/hermetic-extract-agent": (agent, 0o755),
    }

    if extract_config is not None:
        raw_config = json.dumps(extract_config, sort_keys=True).encode("utf-8")
        if len(raw_config) > MAX_CONFIG_BYTES:
            raise ValueError("extract config exceeds byte cap")
        files["etc/hermetic/extract.json"] = (raw_config, 0o444)

    files.update({
        name: (data, 0o644)
        for name, data in substrate_files(
            kernel_lock, kernel_image=kernel_image, clockprobe_bin=clockprobe_bin
        ).items()
    })

    parent, leaf = open_parent(tree)
    staged = None
    directory = None
    try:
        try:
            os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("extractor tree already exists")

        if os.fstat(parent).st_mode & 0o022:
            raise UnsafePathError("extractor output parent must not be writable by other users")

        for attempt in range(MAX_TEMP_ATTEMPTS):
            candidate = f".extractor-tree.{attempt}"
            if candidate == leaf:
                continue
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            staged = candidate
            break

        if staged is None:
            raise OSError(errno.EEXIST, "extractor temporary attempts exhausted")

        directory = os.open(
            staged,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        anchor = Path(f"/proc/self/fd/{directory}")

        for rel in _TREE_DIRS:
            os.mkdir(anchor / rel, 0o700)

        for rel, (data, mode) in files.items():
            fd = os.open(
                anchor / rel,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fchmod(f.fileno(), mode)
                os.utime(f.fileno(), (epoch, epoch))
                os.fsync(f.fileno())

        for rel in reversed(_TREE_DIRS):
            fd = os.open(
                anchor / rel,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
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
            shutil.rmtree(Path(f"/proc/self/fd/{parent}") / staged)
        os.close(parent)

    return tree


def build_extractor_image(
    tree: Path,
    out_image: Path,
    *,
    extractor_bin: Path,
    t_clock: datetime,
    world_id: str,
    agent_bin: Path | None = None,
    extract_config: dict | None = None,
    sealcheck_bin: Path | None = None,
    work_dir: Path | None = None,
    kernel_lock: Path = DEFAULT_KERNEL_DIR / "kernel.lock.json",
    kernel_image: Path | None = None,
    clockprobe_bin: Path | None = None,
) -> dict:
    """Build the ExtractorVM rootfs tree and a D4-checked read-only ext4 image from it."""
    from hermetic_slice.rootfs import build_rootfs

    build_extractor_tree(
        tree,
        extractor_bin=extractor_bin,
        t_clock=t_clock,
        agent_bin=agent_bin,
        extract_config=extract_config,
        kernel_lock=kernel_lock,
        kernel_image=kernel_image,
        clockprobe_bin=clockprobe_bin,
    )
    return build_rootfs(
        tree,
        out_image,
        t_clock=t_clock,
        world_id=world_id,
        sealcheck_bin=sealcheck_bin,
        work_dir=work_dir,
        kernel_lock=kernel_lock,
        kernel_image=kernel_image,
        clockprobe_bin=clockprobe_bin,
    )
