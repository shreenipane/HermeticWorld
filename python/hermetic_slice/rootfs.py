"""Reproducible rootfs builder with D4 guard (TR-SEAL-7, TR-SEAL-8, TR-SEAL-12).

How the image is built
----------------------
The source tree is never copied into a staging directory. An iterative, descriptor-based
walker reads it exactly once and writes a deterministic PAX tar stream into a fresh private
work directory (``tempfile.mkdtemp`` under ``work_dir``, default the system temp dir);
``mke2fs -d <tar>`` (e2fsprogs >= 1.47.1 imports tar archives) then builds the ext4 image
from that stream. This route was chosen over a staging copy because:

* ownership and mode come from the SOURCE inodes (``uid``/``gid``/``mode`` from ``fstat``
  of the opened source entry, setuid/setgid/sticky bits included), never from whoever runs
  the builder: a staging copy made by a non-root builder is owned by the builder and
  ``chmod`` silently drops setgid when the builder is not in the file's group;
* no builder-side inode is ever imported, so a default ACL or LSM label on the work or
  output directory cannot reach the image. The stream carries no extended attributes at
  all: e2fsprogs 1.47.2's tar importer does not import them, so the image holds no
  ``system.posix_acl_*``, ``security.*`` or ``user.*`` xattrs (``"xattrs": "none"`` in the
  build result);
* hard links stay hard links (one data copy per source inode) and sparse files stay sparse
  (GNU sparse 1.0 members, holes found with ``SEEK_DATA``/``SEEK_HOLE``).

The stream is deterministic: entries are emitted parents first in byte-sorted name order,
user/group names are empty (numeric ids only), and every mtime is clamped to
``min(source mtime, T_clock)`` (never negative); mke2fs writes atime/ctime 0 for tar input.

Source trees are hostile: no path is ever resolved by name below ``src``. Directories are
opened with ``O_NOFOLLOW|O_DIRECTORY`` relative to their parent's descriptor and listed with
``os.scandir(fd)``; regular files are opened with ``O_NOFOLLOW|O_NONBLOCK`` and must still be
the same regular inode (``fstat``) that the listing saw; symlinks are recorded with
``readlink`` and never followed; FIFOs, devices and sockets are skipped and listed. The
caller must not modify the source tree during a build; if it changes anyway, the build
fails with :class:`SourceChangedError` rather than reading something else.

Resource use is capped while walking (:class:`RootfsLimits`: bytes, entries, depth; the
walk is iterative), free space is checked with ``statvfs`` before and while writing, and
every subprocess has a named, overridable timeout.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid

from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.intake import iso_utc
from hermetic_slice.repo_sealer import rmtree_force

HERMETIC_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "hermetic.world")
NAMESPACE = HERMETIC_NAMESPACE
MIN_E2FSPROGS_VERSION = (1, 47, 1)
# Exact e2fsprogs versions whose output has been checked to be reproducible with the pinned
# config and options below. To allow another version: build the reproducibility and D4
# tests with it, compare the image layout (dumpe2fs -h) against the pinned one, then add it.
ALLOWED_E2FSPROGS_VERSIONS: frozenset[tuple[int, int, int]] = frozenset({(1, 47, 2)})
SHELL_HISTORY_NAMES = {".bash_history", ".zsh_history", ".python_history", ".lesshst", ".viminfo"}

# Pinned image format (TR-SEAL-12): nothing below may come from the host.
MKE2FS_CONFIG_PATH = Path(__file__).resolve().parent / "data" / "mke2fs-hermetic.conf"
EXT4_FEATURES = (
    "none,has_journal,ext_attr,dir_index,filetype,extent,flex_bg,sparse_super,"
    "large_file,huge_file,dir_nlink,extra_isize,metadata_csum,64bit"
)
BLOCK_SIZE = 4096
INODE_SIZE = 256
RESERVED_BLOCKS_PERCENT = 5
FLEX_BG_SIZE = 16
USAGE_TYPE = "hermetic"
MKE2FS_EXTENDED_OPTIONS = "lazy_itable_init=0,lazy_journal_init=0,nodiscard,root_owner=0:0"

# Resource caps (overridable by argument or environment variable).
DEFAULT_MAX_BYTES = 64 * 1024**3
DEFAULT_MAX_ENTRIES = 5_000_000
DEFAULT_MAX_DEPTH = 256
ENV_MAX_BYTES = "HERMETIC_ROOTFS_MAX_BYTES"
ENV_MAX_ENTRIES = "HERMETIC_ROOTFS_MAX_ENTRIES"
ENV_MAX_DEPTH = "HERMETIC_ROOTFS_MAX_DEPTH"
FREE_SPACE_MARGIN_BYTES = 64 * 1024 * 1024
FREE_SPACE_CHECK_INTERVAL_BYTES = 64 * 1024 * 1024
MAX_SPARSE_SEGMENTS = 65536

# Subprocess timeouts in seconds; each can be overridden with HERMETIC_ROOTFS_TIMEOUT_<NAME>.
TIMEOUTS_S: dict[str, float] = {
    "MKE2FS_VERSION": 60.0,
    "MKE2FS_BUILD": 7200.0,
    "SEALCHECK_PROBE": 60.0,
    "SEALCHECK_D4": 7200.0,
}
SEALCHECK_ENV = "HERMETIC_SEALCHECK_BIN"

_MIB = 1024 * 1024
_DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY


class RootfsGateError(Exception):
    """Raised when rootfs image fails D4 guard verification."""

    def __init__(self, message: str, findings: list[dict] | None = None) -> None:
        super().__init__(message)
        self.findings = findings or []


class RootfsLimitError(RuntimeError):
    """Raised when the source tree exceeds a resource cap or the disk lacks free space."""


class RootfsTimeoutError(RuntimeError):
    """Raised when a subprocess exceeds its timeout (the child is killed)."""


class SourceChangedError(RuntimeError):
    """Raised when a source entry changes between listing and opening it."""


# -----------------------------------------------------------------------------
# e2fsprogs version and binaries
# -----------------------------------------------------------------------------


def parse_mke2fs_version(version_str: str) -> tuple[int, int, int]:
    """Parse (major, minor, patch) from mke2fs -V output string."""
    match = re.search(r"mke2fs\s+(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not match:
        raise ValueError(f"Could not parse mke2fs version from: {version_str!r}")
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def _fmt_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def check_e2fsprogs_version(version_str: str) -> tuple[int, int, int]:
    """Require e2fsprogs >= 1.47.1 AND an exact version from ALLOWED_E2FSPROGS_VERSIONS."""
    version = parse_mke2fs_version(version_str)
    if version < MIN_E2FSPROGS_VERSION:
        raise RuntimeError(
            f"e2fsprogs >= {_fmt_version(MIN_E2FSPROGS_VERSION)} required, "
            f"found {_fmt_version(version)} ({version_str.strip()})"
        )
    if version not in ALLOWED_E2FSPROGS_VERSIONS:
        allowed = ", ".join(_fmt_version(v) for v in sorted(ALLOWED_E2FSPROGS_VERSIONS))
        raise RuntimeError(
            f"e2fsprogs {_fmt_version(version)} is not a pinned version (allowed: {allowed}); "
            "a different mke2fs can lay out the image differently (TR-SEAL-12)"
        )
    return version


def resolve_mke2fs_bin() -> str:
    """Find mke2fs binary in PATH or standard system binary locations."""
    which_bin = shutil.which("mke2fs")
    if which_bin:
        return which_bin
    for candidate in ("/sbin/mke2fs", "/usr/sbin/mke2fs", "/usr/local/sbin/mke2fs"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("mke2fs binary not found in PATH or standard system directories")


def subprocess_timeout(name: str) -> float:
    """Timeout for the named subprocess step, from HERMETIC_ROOTFS_TIMEOUT_<NAME> or the default."""
    default = TIMEOUTS_S[name]
    raw = os.environ.get(f"HERMETIC_ROOTFS_TIMEOUT_{name}")
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"HERMETIC_ROOTFS_TIMEOUT_{name} must be a number of seconds: {raw!r}") from exc
    if not value > 0:
        raise ValueError(f"HERMETIC_ROOTFS_TIMEOUT_{name} must be positive: {raw!r}")
    return value


def _run(cmd: list[str], timeout_name: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """subprocess.run with the named timeout; a timeout kills the child and raises RootfsTimeoutError."""
    timeout = subprocess_timeout(timeout_name)
    try:
        return subprocess.run(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RootfsTimeoutError(
            f"{Path(str(cmd[0])).name} ({timeout_name.lower()}) timed out after {timeout:g} s "
            f"(override with HERMETIC_ROOTFS_TIMEOUT_{timeout_name})"
        ) from exc


def _binary_supports_d4(path: Path) -> bool:
    """Check if sealcheck binary supports the d4-image subcommand (bounded by a timeout)."""
    try:
        proc = _run([str(path), "d4-image", "--help"], "SEALCHECK_PROBE")
    except RootfsTimeoutError:
        raise
    except OSError:
        return False
    return proc.returncode == 0


def validate_sealcheck_bin(path: Path | str, origin: str) -> Path:
    """Check that a sealcheck binary is safe to execute; raise FileNotFoundError/PermissionError otherwise.

    Rules: absolute path; the final component is a regular file (not a symlink); owned by the
    current effective user or root; not group- or world-writable; executable; supports d4-image.
    """
    p = Path(path)
    if not p.is_absolute():
        raise FileNotFoundError(f"{origin} must be an absolute path: {p}")
    try:
        st = os.lstat(p)
    except OSError as exc:
        raise FileNotFoundError(f"{origin} not found: {p} ({exc})") from exc
    if not stat.S_ISREG(st.st_mode):
        raise PermissionError(f"{origin} is not a regular file (symlinks are refused): {p}")
    if st.st_uid not in (0, os.geteuid()):
        raise PermissionError(f"{origin} is owned by uid {st.st_uid}, not by the current user or root: {p}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"{origin} is group- or world-writable: {p}")
    if not os.access(p, os.X_OK):
        raise PermissionError(f"{origin} is not executable: {p}")
    if not _binary_supports_d4(p):
        raise FileNotFoundError(f"{origin} does not support the d4-image subcommand: {p}")
    return p


def find_sealcheck_bin(sealcheck_bin: Path | str | None = None) -> Path:
    """Return the sealcheck binary: the explicit argument, else $HERMETIC_SEALCHECK_BIN.

    There is no ambient search (home directories, cargo target dirs, $PATH): a binary found
    that way could be planted by another local user.
    """
    if sealcheck_bin is not None:
        return validate_sealcheck_bin(sealcheck_bin, "sealcheck_bin")
    env_bin = os.environ.get(SEALCHECK_ENV)
    if env_bin:
        return validate_sealcheck_bin(env_bin, f"${SEALCHECK_ENV}")
    raise FileNotFoundError(
        f"No hermetic-sealcheck binary given: pass sealcheck_bin (--sealcheck-bin) or set ${SEALCHECK_ENV} "
        "to the absolute path of a binary you built"
    )


# -----------------------------------------------------------------------------
# Resource limits and free space
# -----------------------------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer: {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive: {raw!r}")
    return value


@dataclass(frozen=True)
class RootfsLimits:
    """Caps enforced while walking the source tree."""

    max_bytes: int = DEFAULT_MAX_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_depth: int = DEFAULT_MAX_DEPTH

    @classmethod
    def from_env(cls) -> "RootfsLimits":
        return cls(
            max_bytes=_env_int(ENV_MAX_BYTES, DEFAULT_MAX_BYTES),
            max_entries=_env_int(ENV_MAX_ENTRIES, DEFAULT_MAX_ENTRIES),
            max_depth=_env_int(ENV_MAX_DEPTH, DEFAULT_MAX_DEPTH),
        )


def free_bytes(path: Path) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def require_free_space(path: Path, needed: int, what: str) -> None:
    """Fail early with a clear error if the filesystem holding path has less than needed bytes free."""
    available = free_bytes(path)
    if available < needed:
        raise RootfsLimitError(
            f"Not enough free space for the {what} in {path}: need {needed} bytes, {available} available"
        )


class _SpaceGuard:
    """Checks free space on the work filesystem before and while the tar stream grows."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.pending = 0

    def reserve(self, nbytes: int, *, force: bool = False) -> None:
        if force or self.pending + nbytes >= FREE_SPACE_CHECK_INTERVAL_BYTES:
            require_free_space(self.path, nbytes + self.pending + FREE_SPACE_MARGIN_BYTES, "rootfs tar stream")
            self.pending = 0
        else:
            self.pending += nbytes


# -----------------------------------------------------------------------------
# Clean-up rules (TR-SEAL-8), applied while walking
# -----------------------------------------------------------------------------


def is_cleanup_target(parts: tuple[str, ...]) -> bool:
    """True if the entry at relative path parts is removed by TR-SEAL-8.

    The walker only reaches a path through real directories (never through symlinks), so
    every ancestor of parts is a real directory of the source tree.

    - var/log/*, var/cache/* (the directories themselves are kept)
    - var/lib/apt/lists/*
    - root/.cache/pip, root/.cache/uv, home/*/.cache/pip, home/*/.cache/uv
    - opt/conda/pkgs/* and */miniconda3/pkgs/* except urls.txt
    - shell histories anywhere under root/ and home/
    """
    n = len(parts)
    if n == 3 and parts[0] == "var" and parts[1] in ("log", "cache"):
        return True
    if n == 5 and parts[:4] == ("var", "lib", "apt", "lists"):
        return True
    if n == 3 and parts[0] == "root" and parts[1] == ".cache" and parts[2] in ("pip", "uv"):
        return True
    if n == 4 and parts[0] == "home" and parts[2] == ".cache" and parts[3] in ("pip", "uv"):
        return True
    if n == 4 and parts[:3] == ("opt", "conda", "pkgs") and parts[3] != "urls.txt":
        return True
    if n >= 3 and parts[-3] == "miniconda3" and parts[-2] == "pkgs" and parts[-1] != "urls.txt":
        return True
    if n >= 2 and parts[0] in ("root", "home") and parts[-1] in SHELL_HISTORY_NAMES:
        return True
    return False


def _is_special_file(mode: int) -> bool:
    """Check if file mode represents device node, FIFO, or socket."""
    return stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


# -----------------------------------------------------------------------------
# Deterministic tar stream
# -----------------------------------------------------------------------------


@dataclass
class TreeScan:
    """What the walker emitted, and the block demand used to size the image."""

    removed: list[str]
    skipped_special: list[str]
    entries_seen: int = 0
    inodes: int = 1  # the root directory
    hardlinks: int = 0
    data_bytes: int = 0
    data_blocks: int = 0
    extent_blocks: int = 0
    symlink_blocks: int = 0
    dir_blocks: int = 0


def make_tarinfo(name: str, st: os.stat_result, mtime_ceiling: int) -> tarfile.TarInfo:
    """Tar header fields from the SOURCE inode: numeric uid/gid, full permission bits, clamped mtime."""
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(st.st_mode)
    info.uid = st.st_uid
    info.gid = st.st_gid
    info.uname = ""
    info.gname = ""
    info.mtime = max(0, min(int(st.st_mtime), mtime_ceiling))
    return info


def directory_blocks(entry_name_bytes: list[int] | int, entry_count: int | None = None) -> int:
    """Blocks a directory needs: ext4 dirents are 8 bytes + name rounded up to 4; . and .. take 24.

    Leaves are counted as if half full (hash-tree splits), plus one index block.
    """
    if isinstance(entry_name_bytes, int):
        total = 24 + (entry_count or 0) * 8 + entry_name_bytes
    else:
        total = 24 + sum(8 + ((n + 3) & ~3) for n in entry_name_bytes)
    leaves = max(1, math.ceil(total / (BLOCK_SIZE - 32)))
    return 1 if leaves == 1 else 2 * leaves + 1


def _file_blocks(data_bytes: int, segments: int) -> tuple[int, int]:
    """(data blocks, extent-tree blocks) for a file with data_bytes of data in segments runs."""
    data_blocks = math.ceil(data_bytes / BLOCK_SIZE)
    extents = max(segments, math.ceil(data_blocks / 32768))
    extent_blocks = 0 if extents <= 4 else math.ceil(extents / 340) + 1
    return data_blocks, extent_blocks


def data_segments(fd: int, size: int) -> list[tuple[int, int]]:
    """Data runs of an open regular file as (offset, length), holes omitted.

    Falls back to one dense run if the filesystem cannot report holes or the map is huge.
    """
    if size == 0:
        return []
    dense = [(0, size)]
    segments: list[tuple[int, int]] = []
    offset = 0
    try:
        while offset < size:
            try:
                data = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError as exc:
                if exc.errno == errno.ENXIO:
                    break
                raise
            if data >= size:
                break
            hole = min(os.lseek(fd, data, os.SEEK_HOLE), size)
            if hole <= data:
                return dense
            segments.append((data, hole - data))
            offset = hole
            if len(segments) > MAX_SPARSE_SEGMENTS:
                return dense
    except (OSError, AttributeError):
        return dense
    return segments


class _SegmentReader:
    """File-like reader producing prefix bytes then the given runs of fd, exactly; short reads raise."""

    def __init__(self, fd: int, segments: list[tuple[int, int]], prefix: bytes, rel: str) -> None:
        self.fd = fd
        self.segments = list(segments)
        self.prefix = prefix
        self.rel = rel
        self.index = 0
        self.done_in_segment = 0

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        if n < 0:
            n = len(self.prefix) + sum(length for _, length in self.segments)
        if self.prefix:
            take = self.prefix[:n]
            self.prefix = self.prefix[len(take):]
            out += take
        while len(out) < n and self.index < len(self.segments):
            offset, length = self.segments[self.index]
            want = min(n - len(out), length - self.done_in_segment)
            chunk = os.pread(self.fd, want, offset + self.done_in_segment)
            if not chunk:
                raise SourceChangedError(f"Source file shrank while reading: {self.rel}")
            out += chunk
            self.done_in_segment += len(chunk)
            if self.done_in_segment == length:
                self.index += 1
                self.done_in_segment = 0
        return bytes(out)


def _sparse_map(segments: list[tuple[int, int]], size: int) -> bytes:
    entries = list(segments)
    if not entries or entries[-1][0] + entries[-1][1] < size:
        entries.append((size, 0))
    text = f"{len(entries)}\n" + "".join(f"{off}\n{length}\n" for off, length in entries)
    raw = text.encode("ascii")
    return raw + b"\0" * (-len(raw) % tarfile.BLOCKSIZE)


@dataclass
class _Frame:
    fd: int
    parts: tuple[str, ...]
    entries: list[tuple[str, os.stat_result]]
    index: int = 0


def _list_directory(fd: int, rel: str, scan: TreeScan, limits: RootfsLimits) -> list[tuple[str, os.stat_result]]:
    """Entries of an open directory with their lstat, byte-sorted; counts towards max_entries."""
    entries: list[tuple[str, os.stat_result]] = []
    with os.scandir(fd) as it:
        for entry in it:
            scan.entries_seen += 1
            if scan.entries_seen > limits.max_entries:
                raise RootfsLimitError(
                    f"Source tree has more than {limits.max_entries} entries (at {rel or '.'}); "
                    f"raise {ENV_MAX_ENTRIES} if this is intended"
                )
            try:
                st = entry.stat(follow_symlinks=False)
            except FileNotFoundError as exc:
                raise SourceChangedError(f"Source entry vanished while listing: {rel}/{entry.name}") from exc
            entries.append((entry.name, st))
    entries.sort(key=lambda item: os.fsencode(item[0]))
    scan.dir_blocks += directory_blocks([len(os.fsencode(name)) for name, _ in entries])
    return entries


def _same_inode(listed: os.stat_result, opened: os.stat_result) -> bool:
    return listed.st_ino == opened.st_ino and listed.st_dev == opened.st_dev


def write_rootfs_tar(
    src: Path,
    tar_path: Path,
    *,
    mtime_ceiling: int,
    limits: RootfsLimits | None = None,
) -> TreeScan:
    """Walk src (never following symlinks) and write the cleaned tree as a deterministic tar.

    Returns a TreeScan with the TR-SEAL-8 removals, skipped special files and the block demand.
    The tar file is created exclusively with mode 0600; free space on its filesystem is checked
    before and while writing.
    """
    limits = limits or RootfsLimits.from_env()
    scan = TreeScan(removed=[], skipped_special=[])
    guard = _SpaceGuard(Path(tar_path).parent)
    guard.reserve(0, force=True)
    hardlink_first: dict[tuple[int, int], str] = {}

    root_fd = os.open(src, _DIR_OPEN_FLAGS)
    stack: list[_Frame] = []
    out_fd = os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(out_fd, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
                root_st = os.fstat(root_fd)
                root_info = make_tarinfo(".", root_st, mtime_ceiling)
                root_info.type = tarfile.DIRTYPE
                tf.addfile(root_info)
                stack.append(_Frame(root_fd, (), _list_directory(root_fd, "", scan, limits)))
                root_fd = -1

                while stack:
                    frame = stack[-1]
                    if frame.index >= len(frame.entries):
                        os.close(frame.fd)
                        stack.pop()
                        continue
                    name, listed = frame.entries[frame.index]
                    frame.index += 1
                    parts = frame.parts + (name,)
                    rel = "/".join(parts)
                    mode = listed.st_mode

                    if _is_special_file(mode):
                        scan.skipped_special.append(rel)
                        continue
                    if is_cleanup_target(parts):
                        scan.removed.append(rel)
                        continue

                    if stat.S_ISDIR(mode):
                        if len(parts) > limits.max_depth:
                            raise RootfsLimitError(
                                f"Source tree is deeper than {limits.max_depth} directories (at {rel}); "
                                f"raise {ENV_MAX_DEPTH} if this is intended"
                            )
                        try:
                            child_fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=frame.fd)
                        except OSError as exc:
                            if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
                                raise SourceChangedError(f"Source directory changed during build: {rel}") from exc
                            raise
                        try:
                            opened = os.fstat(child_fd)
                            if not stat.S_ISDIR(opened.st_mode) or not _same_inode(listed, opened):
                                raise SourceChangedError(f"Source directory changed during build: {rel}")
                            info = make_tarinfo(rel, opened, mtime_ceiling)
                            info.type = tarfile.DIRTYPE
                            guard.reserve(tarfile.BLOCKSIZE * 2)
                            tf.addfile(info)
                            scan.inodes += 1
                            entries = _list_directory(child_fd, rel, scan, limits)
                        except BaseException:
                            os.close(child_fd)
                            raise
                        stack.append(_Frame(child_fd, parts, entries))
                    elif stat.S_ISLNK(mode):
                        try:
                            target = os.readlink(name, dir_fd=frame.fd)
                        except OSError as exc:
                            raise SourceChangedError(f"Source symlink changed during build: {rel}") from exc
                        info = make_tarinfo(rel, listed, mtime_ceiling)
                        info.type = tarfile.SYMTYPE
                        info.linkname = target
                        guard.reserve(tarfile.BLOCKSIZE * 3)
                        tf.addfile(info)
                        scan.inodes += 1
                        if len(os.fsencode(target)) >= 60:
                            scan.symlink_blocks += 1
                    elif stat.S_ISREG(mode):
                        _add_regular(tf, frame.fd, name, rel, listed, mtime_ceiling, limits, scan, guard, hardlink_first)
                    else:
                        scan.skipped_special.append(rel)
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        for frame in stack:
            try:
                os.close(frame.fd)
            except OSError:
                pass
    scan.removed.sort()
    scan.skipped_special.sort()
    return scan


def _add_regular(
    tf: tarfile.TarFile,
    dir_fd: int,
    name: str,
    rel: str,
    listed: os.stat_result,
    mtime_ceiling: int,
    limits: RootfsLimits,
    scan: TreeScan,
    guard: _SpaceGuard,
    hardlink_first: dict[tuple[int, int], str],
) -> None:
    try:
        fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOENT, errno.ENXIO):
            raise SourceChangedError(f"Source file changed during build: {rel}") from exc
        raise
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(listed, opened):
            raise SourceChangedError(f"Source file changed during build: {rel}")
        key = (opened.st_dev, opened.st_ino)
        if opened.st_nlink > 1 and key in hardlink_first:
            info = make_tarinfo(rel, opened, mtime_ceiling)
            info.type = tarfile.LNKTYPE
            info.linkname = hardlink_first[key]
            guard.reserve(tarfile.BLOCKSIZE * 3)
            tf.addfile(info)
            scan.hardlinks += 1
            return

        size = opened.st_size
        segments = data_segments(fd, size)
        data_bytes = sum(length for _, length in segments)
        if scan.data_bytes + data_bytes > limits.max_bytes:
            raise RootfsLimitError(
                f"Source tree data exceeds {limits.max_bytes} bytes (at {rel}); "
                f"raise {ENV_MAX_BYTES} if this is intended"
            )
        info = make_tarinfo(rel, opened, mtime_ceiling)
        info.type = tarfile.REGTYPE
        if segments == [(0, size)] or size == 0:
            info.size = size
            prefix = b""
        else:
            prefix = _sparse_map(segments, size)
            parent, _, base = rel.rpartition("/")
            info.name = f"{parent + '/' if parent else ''}GNUSparseFile.0/{base}"
            info.size = len(prefix) + data_bytes
            info.pax_headers = {
                "GNU.sparse.major": "1",
                "GNU.sparse.minor": "0",
                "GNU.sparse.name": rel,
                "GNU.sparse.realsize": str(size),
            }
        guard.reserve(info.size + tarfile.BLOCKSIZE * 4)
        tf.addfile(info, _SegmentReader(fd, segments, prefix, rel))
        scan.data_bytes += data_bytes
        scan.inodes += 1
        blocks, extent_blocks = _file_blocks(data_bytes, len(segments))
        scan.data_blocks += blocks
        scan.extent_blocks += extent_blocks
        if opened.st_nlink > 1:
            hardlink_first[key] = rel
    finally:
        os.close(fd)


# -----------------------------------------------------------------------------
# Image sizing
# -----------------------------------------------------------------------------


def calculate_inode_count(entry_count: int) -> int:
    """Calculate requested inode count: entries * 1.25 + 1024."""
    return math.ceil(entry_count * 1.25 + 1024)


def journal_mib_for(size_mib: int) -> int:
    """Pinned journal size: 1/64 of the filesystem, at least 4 MiB, at most 1 GiB."""
    return min(1024, max(4, size_mib // 64))


@dataclass(frozen=True)
class ImagePlan:
    size_mib: int
    inode_count: int
    journal_mib: int
    required_bytes: int


def plan_image(scan: TreeScan, size_mib: int | None = None) -> ImagePlan:
    """Image size, inode count and journal size for the scanned tree.

    Counts every file's data rounded up to whole 4 KiB blocks (sparse files by their data
    runs), extent-tree blocks, long symlinks, directory blocks, the inode tables, per-group
    bitmaps and descriptors, a 10% safety factor, the journal and 16 MiB of headroom.
    """
    inode_count = calculate_inode_count(scan.inodes)
    inode_table_blocks = math.ceil(inode_count * INODE_SIZE / BLOCK_SIZE)
    content_blocks = scan.data_blocks + scan.extent_blocks + scan.symlink_blocks + scan.dir_blocks
    base_blocks = content_blocks + inode_table_blocks
    groups = math.ceil(base_blocks * 1.25 / 32768) + 1
    metadata_blocks = groups * 4 + math.ceil(groups * 64 / BLOCK_SIZE) * 32 + 256
    need_blocks = math.ceil((base_blocks + metadata_blocks) * 1.10)
    need_mib = math.ceil(need_blocks * BLOCK_SIZE / _MIB)
    if size_mib is not None:
        if size_mib <= 0:
            raise ValueError(f"size_mib must be positive: {size_mib}")
        journal = journal_mib_for(size_mib)
        return ImagePlan(size_mib, inode_count, journal, min(size_mib, need_mib + journal) * _MIB)
    journal = journal_mib_for(need_mib)
    final = max(64, need_mib + journal + 16)
    return ImagePlan(final, inode_count, journal, (need_mib + journal) * _MIB)


def pinned_mke2fs_config() -> tuple[Path, str]:
    """Path and sha256 of the in-repo mke2fs config (must be a regular file, not a symlink)."""
    st = os.lstat(MKE2FS_CONFIG_PATH)
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"Pinned mke2fs config is not a regular file: {MKE2FS_CONFIG_PATH}")
    digest = hashlib.sha256(MKE2FS_CONFIG_PATH.read_bytes()).hexdigest()
    return MKE2FS_CONFIG_PATH, digest


def mke2fs_command(
    mke2fs_bin: str, tar_path: Path, image_path: Path, plan: ImagePlan, rootfs_uuid: str, hash_seed: str
) -> list[str]:
    """The full mke2fs command line: every image-shaping option explicit (TR-SEAL-7, TR-SEAL-12)."""
    return [
        mke2fs_bin,
        "-q",
        "-t", "ext4",
        "-T", USAGE_TYPE,
        "-O", EXT4_FEATURES,
        "-b", str(BLOCK_SIZE),
        "-I", str(INODE_SIZE),
        "-N", str(plan.inode_count),
        "-J", f"size={plan.journal_mib}",
        "-m", str(RESERVED_BLOCKS_PERCENT),
        "-G", str(FLEX_BG_SIZE),
        "-e", "continue",
        "-d", str(tar_path),
        "-U", rootfs_uuid,
        "-E", f"hash_seed={hash_seed},{MKE2FS_EXTENDED_OPTIONS}",
        "-F",
        str(image_path),
        f"{plan.size_mib}M",
    ]


# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------


def build_rootfs(
    src: Path,
    out_image: Path,
    *,
    t_clock: datetime,
    world_id: str,
    size_mib: int | None = None,
    sealcheck_bin: Path | None = None,
    work_dir: Path | None = None,
    limits: RootfsLimits | None = None,
) -> dict:
    """Build a reproducible ext4 root filesystem image with D4 guard.

    Args:
        src: Path to source root filesystem tree (must not change during the build).
        out_image: Path to write the output ext4 filesystem image.
        t_clock: Clock cutoff timestamp (must be timezone-aware or UTC).
        world_id: Unique identifier for the world slice.
        size_mib: Optional filesystem image size in MiB.
        sealcheck_bin: Explicit path to hermetic-sealcheck (else $HERMETIC_SEALCHECK_BIN).
        work_dir: Directory in which a private work directory is created (default: system temp).
        limits: Resource caps (default: RootfsLimits.from_env()).

    Returns:
        dict containing build metadata and verification result.
    """
    src = Path(src)
    if not src.is_dir():
        raise FileNotFoundError(f"Source directory does not exist or is not a directory: {src}")

    out_image = Path(out_image)
    resolved_src = src.resolve()
    resolved_out = out_image.resolve()
    resolved_out_parent = out_image.parent.resolve()

    # Reject before creating anything if out_image, resolved symlink target, or its parent would be inside src
    if (
        resolved_out.is_relative_to(resolved_src)
        or resolved_out.parent.is_relative_to(resolved_src)
        or resolved_out_parent.is_relative_to(resolved_src)
    ):
        raise ValueError(
            f"Output image and staging directory cannot be inside source directory: "
            f"out_image={out_image} (resolved: {resolved_out}), src={src} (resolved: {resolved_src})"
        )
    work_parent = Path(work_dir) if work_dir is not None else Path(tempfile.gettempdir())
    if work_parent.resolve().is_relative_to(resolved_src):
        raise ValueError(f"Work directory cannot be inside source directory: work_dir={work_parent}, src={src}")

    t_clock_utc = ensure_utc(t_clock, "t_clock")
    t_clock_str = iso_utc(t_clock_utc)
    source_date_epoch = int(t_clock_utc.timestamp())

    # Find and vet the sealcheck binary BEFORE building (fail early if missing or unsafe)
    resolved_sealcheck = find_sealcheck_bin(sealcheck_bin)
    limits = limits or RootfsLimits.from_env()

    rootfs_uuid = str(uuid.uuid5(HERMETIC_NAMESPACE, f"hermetic-rootfs:{world_id}"))
    hash_seed = str(uuid.uuid5(HERMETIC_NAMESPACE, f"hermetic-hash-seed:{world_id}"))

    mke2fs_bin = resolve_mke2fs_bin()
    proc_ver = _run([mke2fs_bin, "-V"], "MKE2FS_VERSION")
    parsed_ver = check_e2fsprogs_version(f"{proc_ver.stdout}\n{proc_ver.stderr}")
    e2fsprogs_version_str = _fmt_version(parsed_ver)
    config_path, config_sha256 = pinned_mke2fs_config()

    work: Path | None = None
    tmp_image: Path | None = None

    try:
        out_image.parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="hermetic-rootfs-", dir=work_parent))
        tar_path = work / "rootfs.tar"

        # 1-2. Walk the source once: TR-SEAL-8 clean-up, special files skipped, caps enforced
        scan = write_rootfs_tar(resolved_src, tar_path, mtime_ceiling=source_date_epoch, limits=limits)

        # 3. Size calculation and inode demand
        plan = plan_image(scan, size_mib)

        fd, tmp_path_str = tempfile.mkstemp(dir=out_image.parent, prefix=f"{out_image.name}.", suffix=".tmp")
        os.close(fd)
        tmp_image = Path(tmp_path_str)
        require_free_space(out_image.parent, plan.required_bytes + FREE_SPACE_MARGIN_BYTES, "ext4 image")

        # 4. Build ext4 image (TR-SEAL-7) from the tar stream with a pinned config and options
        cmd = mke2fs_command(mke2fs_bin, tar_path, tmp_image, plan, rootfs_uuid, hash_seed)
        path_env = os.environ.get("PATH", "/bin:/usr/bin:/sbin:/usr/sbin")
        if "/sbin" not in path_env:
            path_env = f"{path_env}:/sbin:/usr/sbin"
        mke2fs_env = {
            "PATH": path_env,
            "LANG": "C",
            "TZ": "UTC",
            "MKE2FS_CONFIG": str(config_path),
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "E2FSPROGS_FAKE_TIME": str(source_date_epoch),
        }
        build_proc = _run(cmd, "MKE2FS_BUILD", env=mke2fs_env)
        if build_proc.returncode != 0:
            raise RuntimeError(
                f"mke2fs failed with exit code {build_proc.returncode}: {build_proc.stderr.strip()}"
            )

        # 5. Guard (D4) - run against temporary image BEFORE replacing out_image
        sc_cmd = [
            str(resolved_sealcheck),
            "d4-image",
            "--image", str(tmp_image),
            "--t-clock", t_clock_str,
            "--format", "json",
        ]
        sc_proc = _run(sc_cmd, "SEALCHECK_D4")

        if sc_proc.returncode == 2:
            findings = []
            try:
                findings = json.loads(sc_proc.stdout).get("findings", [])
            except Exception:
                pass
            raise RootfsGateError(
                f"D4 gate check failed for image {out_image}: {len(findings)} finding(s)",
                findings=findings,
            )
        if sc_proc.returncode != 0:
            err_msg = sc_proc.stderr.strip() or sc_proc.stdout.strip() or f"exit code {sc_proc.returncode}"
            raise RuntimeError(f"sealcheck d4-image failed ({sc_proc.returncode}): {err_msg}")

        # 6. Result metadata from tmp_image BEFORE publication to prevent concurrent overwrite races
        h = hashlib.sha256()
        with open(tmp_image, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        sha256_hex = h.hexdigest()
        size_bytes = tmp_image.stat().st_size

        os.replace(tmp_image, out_image)

        return {
            "image": str(out_image),
            "sha256": sha256_hex,
            "size_bytes": size_bytes,
            "uuid": rootfs_uuid,
            "hash_seed": hash_seed,
            "t_clock": t_clock_str,
            "source_date_epoch": source_date_epoch,
            "removed": scan.removed,
            "skipped_special": scan.skipped_special,
            "e2fsprogs_version": e2fsprogs_version_str,
            "mke2fs_config_sha256": config_sha256,
            "inode_count": plan.inode_count,
            "journal_mib": plan.journal_mib,
            "hardlinks": scan.hardlinks,
            "xattrs": "none",
            "d4": "pass",
        }
    finally:
        if tmp_image is not None:
            try:
                os.unlink(tmp_image)
            except OSError:
                pass
        if work is not None:
            rmtree_force(work)
