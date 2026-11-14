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
from hermetic_slice.repo_sealer import remove_tree_at

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
# Aggregate apparent (logical) size of all regular files. mke2fs's tar importer walks every
# file's whole logical length, holes included, so a tiny archive holding a huge all-hole file
# would otherwise cost hours inside mke2fs; this cap bounds that work before mke2fs starts.
DEFAULT_MAX_LOGICAL_BYTES = 128 * 1024**3
ENV_MAX_BYTES = "HERMETIC_ROOTFS_MAX_BYTES"
ENV_MAX_LOGICAL_BYTES = "HERMETIC_ROOTFS_MAX_LOGICAL_BYTES"
ENV_MAX_ENTRIES = "HERMETIC_ROOTFS_MAX_ENTRIES"
ENV_MAX_DEPTH = "HERMETIC_ROOTFS_MAX_DEPTH"
FREE_SPACE_MARGIN_BYTES = 64 * 1024 * 1024
FREE_SPACE_CHECK_INTERVAL_BYTES = 64 * 1024 * 1024
MAX_SPARSE_SEGMENTS = 65536
HOLE_SCAN_CHUNK_BYTES = 1024 * 1024
_ZERO_CHUNK = bytes(HOLE_SCAN_CHUNK_BYTES)

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


def _run(
    cmd: list[str],
    timeout_name: str,
    *,
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess:
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
            pass_fds=pass_fds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RootfsTimeoutError(
            f"{Path(str(cmd[0])).name} ({timeout_name.lower()}) timed out after {timeout:g} s "
            f"(override with HERMETIC_ROOTFS_TIMEOUT_{timeout_name})"
        ) from exc


class PinnedExecutable:
    """An executable opened once and run through its descriptor, never through its pathname again.

    The file is vetted with fstat on the held descriptor and executed as /proc/self/fd/<fd>
    (the descriptor is passed to the child with pass_fds), so replacing or renaming the
    pathname after vetting cannot change what runs.
    """

    def __init__(self, path: Path, fd: int) -> None:
        self.path = path
        self.fd = fd

    @property
    def exec_path(self) -> str:
        if self.fd < 0:
            raise RuntimeError(f"sealcheck descriptor already closed: {self.path}")
        return f"/proc/self/fd/{self.fd}"

    def run(self, args: list[str], timeout_name: str, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
        return _run([self.exec_path, *args], timeout_name, pass_fds=(self.fd, *pass_fds))

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            finally:
                self.fd = -1

    def __enter__(self) -> "PinnedExecutable":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"PinnedExecutable({str(self.path)!r}, fd={self.fd})"


def validate_sealcheck_bin(path: Path | str, origin: str) -> PinnedExecutable:
    """Open a sealcheck binary once and vet that descriptor; raise FileNotFoundError/PermissionError otherwise.

    Rules, all checked on the opened descriptor: absolute path; the final component is a
    regular file (opened with O_NOFOLLOW, so symlinks are refused); owned by the current
    effective user or root; not group- or world-writable; executable; supports d4-image (the
    probe runs the same descriptor that D4 runs later).
    """
    p = Path(path)
    if not p.is_absolute():
        raise FileNotFoundError(f"{origin} must be an absolute path: {p}")
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError(f"{origin} is not a regular file (symlinks are refused): {p}") from exc
        raise FileNotFoundError(f"{origin} not found: {p} ({exc})") from exc
    exe = PinnedExecutable(p, fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"{origin} is not a regular file (symlinks are refused): {p}")
        if st.st_uid not in (0, os.geteuid()):
            raise PermissionError(f"{origin} is owned by uid {st.st_uid}, not by the current user or root: {p}")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError(f"{origin} is group- or world-writable: {p}")
        if not os.access(exe.exec_path, os.X_OK):
            raise PermissionError(f"{origin} is not executable: {p}")
        try:
            probe = exe.run(["d4-image", "--help"], "SEALCHECK_PROBE")
        except OSError as exc:
            raise FileNotFoundError(f"{origin} could not be executed: {p} ({exc})") from exc
        if probe.returncode != 0:
            raise FileNotFoundError(f"{origin} does not support the d4-image subcommand: {p}")
        return exe
    except BaseException:
        exe.close()
        raise


def find_sealcheck_bin(sealcheck_bin: Path | str | None = None) -> PinnedExecutable:
    """Open and vet the sealcheck binary: the explicit argument, else $HERMETIC_SEALCHECK_BIN.

    The caller owns the returned PinnedExecutable and must close it.

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
    max_logical_bytes: int = DEFAULT_MAX_LOGICAL_BYTES

    @classmethod
    def from_env(cls) -> "RootfsLimits":
        return cls(
            max_bytes=_env_int(ENV_MAX_BYTES, DEFAULT_MAX_BYTES),
            max_entries=_env_int(ENV_MAX_ENTRIES, DEFAULT_MAX_ENTRIES),
            max_depth=_env_int(ENV_MAX_DEPTH, DEFAULT_MAX_DEPTH),
            max_logical_bytes=_env_int(ENV_MAX_LOGICAL_BYTES, DEFAULT_MAX_LOGICAL_BYTES),
        )


def free_bytes(path: Path | int) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def require_free_space(path: Path | int, needed: int, what: str) -> None:
    """Fail early with a clear error if the filesystem holding path has less than needed bytes free."""
    available = free_bytes(path)
    if available < needed:
        raise RootfsLimitError(
            f"Not enough free space for the {what} in {path}: need {needed} bytes, {available} available"
        )


class _SpaceGuard:
    """Checks free space on the work filesystem before and while the tar stream grows."""

    def __init__(self, path: Path | int) -> None:
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
    logical_bytes: int = 0
    data_blocks: int = 0
    extent_blocks: int = 0
    symlink_blocks: int = 0
    dir_blocks: int = 0


def make_tarinfo(name: str, st: os.stat_result, mtime_ceiling: int, *, root_owned: bool = False) -> tarfile.TarInfo:
    """Tar header fields from the SOURCE inode: numeric uid/gid, full permission bits, clamped mtime."""
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(st.st_mode)
    info.uid = 0 if root_owned else st.st_uid
    info.gid = 0 if root_owned else st.st_gid
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


def _host_data_hints(fd: int, size: int) -> list[tuple[int, int]]:
    """Regions the host reports as possibly holding data (SEEK_DATA/SEEK_HOLE); everything else
    is a hole and reads as zeros. Only an optimisation: one dense region when unsupported."""
    dense = [(0, size)]
    hints: list[tuple[int, int]] = []
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
            hints.append((data, hole - data))
            offset = hole
            if len(hints) > MAX_SPARSE_SEGMENTS:
                return dense
    except (OSError, AttributeError):
        return dense
    return hints


def data_segments(fd: int, size: int, rel: str = "") -> list[tuple[int, int]]:
    """Canonical data runs of an open regular file as (offset, length).

    A run is a maximal sequence of 4 KiB blocks (the last one clipped to the file size) that
    contain at least one non-zero byte; all-zero blocks are holes. The result depends only on
    the file's content, never on how the host stores it or whether it reports holes: host
    hole reports only let the scan skip regions that are known to read as zeros. Reads are
    streamed in bounded chunks; the caller caps the total logical size beforehand.
    """
    if size == 0:
        return []
    segments: list[tuple[int, int]] = []
    scanned_to = 0

    def add(offset: int, length: int) -> None:
        if segments and segments[-1][0] + segments[-1][1] == offset:
            segments[-1] = (segments[-1][0], segments[-1][1] + length)
        else:
            segments.append((offset, length))

    for hint_offset, hint_length in _host_data_hints(fd, size):
        start = max(scanned_to, hint_offset - hint_offset % BLOCK_SIZE)
        end = min(size, math.ceil((hint_offset + hint_length) / BLOCK_SIZE) * BLOCK_SIZE)
        pos = start
        while pos < end:
            want = min(HOLE_SCAN_CHUNK_BYTES, end - pos)
            chunk = os.pread(fd, want, pos)
            if len(chunk) != want:
                raise SourceChangedError(f"Source file shrank while reading: {rel}")
            if chunk != (_ZERO_CHUNK if want == HOLE_SCAN_CHUNK_BYTES else bytes(want)):
                view = memoryview(chunk)
                for block_start in range(0, want, BLOCK_SIZE):
                    block = view[block_start:block_start + BLOCK_SIZE]
                    if block != _ZERO_CHUNK[:len(block)]:
                        add(pos + block_start, len(block))
            pos += want
        scanned_to = max(scanned_to, end)
    if len(segments) > MAX_SPARSE_SEGMENTS:
        raise RootfsLimitError(
            f"Source file has more than {MAX_SPARSE_SEGMENTS} separate data runs: {rel}"
        )
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


_O_PATH = getattr(os, "O_PATH", 0)


def open_dir_anchored(path: Path | str) -> int:
    """Open a directory by walking its absolute path one component at a time from "/".

    Every component is opened with O_NOFOLLOW|O_DIRECTORY relative to the previous
    descriptor, so a symlink anywhere in the path (an ancestor swapped for a symlink included)
    is refused instead of followed. ".." is refused. Returns an O_RDONLY directory descriptor.
    """
    absolute = os.path.abspath(os.fspath(path))
    if any(part == ".." for part in os.fspath(path).split("/")):
        raise ValueError(f"Refusing path with '..' components: {path}")
    parts = [part for part in absolute.split("/") if part not in ("", ".")]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = (os.O_RDONLY if last or not _O_PATH else _O_PATH) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError(
                        f"Refusing path with a symlinked or non-directory component {part!r}: {path}"
                    ) from exc
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_rootfs_tar(
    src: Path | int,
    tar_path: Path,
    *,
    mtime_ceiling: int,
    limits: RootfsLimits | None = None,
    dir_fd: int | None = None,
    root_owned: bool = False,
) -> TreeScan:
    """Walk src (never following symlinks) and write the cleaned tree as a deterministic tar.

    Returns a TreeScan with the TR-SEAL-8 removals, skipped special files and the block demand.
    The tar file is created exclusively with mode 0600; free space on its filesystem is checked
    before and while writing.
    """
    if type(root_owned) is not bool:
        raise ValueError("root_owned must be boolean")
    limits = limits or RootfsLimits.from_env()
    scan = TreeScan(removed=[], skipped_special=[])
    guard = _SpaceGuard(dir_fd if dir_fd is not None else Path(tar_path).parent)
    guard.reserve(0, force=True)
    hardlink_first: dict[tuple[int, int], str] = {}

    # src is either a directory descriptor the caller opened with open_dir_anchored (kept
    # open by the caller) or a path, which is opened the same anchored way here.
    root_fd = os.dup(src) if isinstance(src, int) else open_dir_anchored(src)
    stack: list[_Frame] = []
    try:
        out_fd = os.open(
            tar_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd
        )
    except BaseException:
        os.close(root_fd)
        raise
    try:
        with os.fdopen(out_fd, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
                root_st = os.fstat(root_fd)
                root_info = make_tarinfo(".", root_st, mtime_ceiling, root_owned=root_owned)
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
                            info = make_tarinfo(rel, opened, mtime_ceiling, root_owned=root_owned)
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
                        info = make_tarinfo(rel, listed, mtime_ceiling, root_owned=root_owned)
                        info.type = tarfile.SYMTYPE
                        info.linkname = target
                        guard.reserve(tarfile.BLOCKSIZE * 3)
                        tf.addfile(info)
                        scan.inodes += 1
                        if len(os.fsencode(target)) >= 60:
                            scan.symlink_blocks += 1
                    elif stat.S_ISREG(mode):
                        _add_regular(tf, frame.fd, name, rel, listed, mtime_ceiling, limits, scan, guard, hardlink_first, root_owned)
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
    root_owned: bool = False,
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
            info = make_tarinfo(rel, opened, mtime_ceiling, root_owned=root_owned)
            info.type = tarfile.LNKTYPE
            info.linkname = hardlink_first[key]
            guard.reserve(tarfile.BLOCKSIZE * 3)
            tf.addfile(info)
            scan.hardlinks += 1
            return

        size = opened.st_size
        if scan.logical_bytes + size > limits.max_logical_bytes:
            raise RootfsLimitError(
                f"Source files' logical size exceeds {limits.max_logical_bytes} bytes (at {rel}); "
                f"raise {ENV_MAX_LOGICAL_BYTES} if this is intended"
            )
        scan.logical_bytes += size
        segments = data_segments(fd, size, rel)
        data_bytes = sum(length for _, length in segments)
        if scan.data_bytes + data_bytes > limits.max_bytes:
            raise RootfsLimitError(
                f"Source tree data exceeds {limits.max_bytes} bytes (at {rel}); "
                f"raise {ENV_MAX_BYTES} if this is intended"
            )
        info = make_tarinfo(rel, opened, mtime_ceiling, root_owned=root_owned)
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


def _is_inside(path: Path, anchor: os.stat_result) -> bool:
    """True if path (or its nearest existing ancestor chain) passes through the anchor directory."""
    current = Path(os.path.abspath(path))
    for candidate in (current, *current.parents):
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if (st.st_dev, st.st_ino) == (anchor.st_dev, anchor.st_ino):
            return True
    return False


def _make_output_dirs(directory: Path) -> None:
    """mkdir -p with mode 0755 for every created level (Path.mkdir(parents=True) ignores mode for parents)."""
    missing: list[Path] = []
    current = Path(os.path.abspath(directory))
    while not current.exists():
        missing.append(current)
        current = current.parent
    for level in reversed(missing):
        try:
            os.mkdir(level, 0o755)
        except FileExistsError:
            pass


def check_safe_dir_fd(fd: int, what: str, where: Path | str) -> None:
    """Refuse a directory (checked on its held descriptor) that another user could rearrange:
    it must be owned by the current user or root, and not group/other-writable unless sticky."""
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(f"{what} is not a directory: {where}")
    if st.st_uid not in (0, os.geteuid()):
        raise PermissionError(f"{what} {where} is owned by uid {st.st_uid}, not by the current user or root")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not st.st_mode & stat.S_ISVTX:
        raise PermissionError(
            f"{what} {where} is writable by group or others without the sticky bit; "
            "another user could substitute its entries"
        )


def check_private_dir_fd(fd: int, where: Path | str) -> None:
    """The work directory must be owned by the current user with no group/other access."""
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise PermissionError(f"Work directory {where} is not private to this user")


def check_output_dir(directory: Path) -> None:
    """Path-level form of check_safe_dir_fd for the output directory (opened anchored)."""
    fd = open_dir_anchored(directory)
    try:
        check_safe_dir_fd(fd, "Output directory", directory)
    finally:
        os.close(fd)


def _fd_path(fd: int) -> str:
    """Path a child process (given fd via pass_fds) uses to reach exactly the inode behind fd."""
    return f"/proc/self/fd/{fd}"


def _entry_is(dir_fd: int, name: str, fd: int) -> bool:
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return False
    held = os.fstat(fd)
    return stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == (held.st_dev, held.st_ino)


def _require_regular_fd(fd: int, when: str) -> None:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink < 1:
        raise RuntimeError(f"Temporary image is no longer a linked regular file {when}; refusing to continue")


def _sha256_fd(fd: int) -> str:
    h = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        h.update(chunk)
        offset += len(chunk)
    return h.hexdigest()


def _publish(image_fd: int, work_fd: int, image_name: str, out_dir_fd: int, out_name: str) -> None:
    """Publish the verified image to out_name inside the held output directory descriptor.

    Same filesystem: renameat from the private work directory descriptor to the output
    directory descriptor (the work entry is first checked against the held image descriptor;
    only this process can change entries of the 0700 work directory). Otherwise the held image
    descriptor is copied (holes kept) into an O_EXCL|O_NOFOLLOW temporary created relative to
    the output directory descriptor, fsynced, and renamed relative to that descriptor. In both
    cases the published entry is checked against the descriptor that was written.
    """
    if not _entry_is(work_fd, image_name, image_fd):
        raise RuntimeError("Temporary image entry in the work directory changed; refusing to publish")
    try:
        os.replace(image_name, out_name, src_dir_fd=work_fd, dst_dir_fd=out_dir_fd)
        published_fd = image_fd
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        tmp_name = f".{out_name}.{uuid.uuid4().hex}.tmp"
        tmp_fd = os.open(
            tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=out_dir_fd
        )
        try:
            size = os.fstat(image_fd).st_size
            offset = 0
            while offset < size:
                chunk = os.pread(image_fd, min(1024 * 1024, size - offset), offset)
                if not chunk:
                    raise RuntimeError("Temporary image shrank while publishing")
                if chunk.count(0) != len(chunk):
                    os.pwrite(tmp_fd, chunk, offset)
                offset += len(chunk)
            os.ftruncate(tmp_fd, size)
            os.fsync(tmp_fd)
            if not _entry_is(out_dir_fd, tmp_name, tmp_fd):
                raise RuntimeError("Temporary output entry changed before publication")
            os.replace(tmp_name, out_name, src_dir_fd=out_dir_fd, dst_dir_fd=out_dir_fd)
        except BaseException:
            try:
                if _entry_is(out_dir_fd, tmp_name, tmp_fd):
                    os.unlink(tmp_name, dir_fd=out_dir_fd)
            except OSError:
                pass
            os.close(tmp_fd)
            raise
        published_fd = tmp_fd
        try:
            if not _entry_is(out_dir_fd, out_name, published_fd):
                raise RuntimeError(f"Published image entry {out_name} does not match the verified image")
        finally:
            os.close(tmp_fd)
        return
    if not _entry_is(out_dir_fd, out_name, published_fd):
        raise RuntimeError(f"Published image entry {out_name} does not match the verified image")


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
    root_owned: bool = False,
) -> dict:
    """Build a reproducible ext4 root filesystem image with D4 guard.

    Args:
        src: Path to source root filesystem tree (must not change during the build). It is
            opened once, component by component without following symlinks, and that
            descriptor is used for every check and for the whole walk.
        out_image: Path to write the output ext4 filesystem image. Its directory must not be
            writable by group or others unless it has the sticky bit.
        t_clock: Clock cutoff timestamp (must be timezone-aware or UTC).
        world_id: Unique identifier for the world slice.
        size_mib: Optional filesystem image size in MiB.
        sealcheck_bin: Explicit path to hermetic-sealcheck (else $HERMETIC_SEALCHECK_BIN).
        work_dir: Directory in which a private work directory is created (default: system temp).
            The tar stream and the image are built there; the image is published only after D4.
        limits: Resource caps (default: RootfsLimits.from_env()).
        root_owned: Emit uid/gid 0 for trees staged by an unprivileged converter.

    Returns:
        dict containing build metadata and verification result.
    """
    if type(root_owned) is not bool:
        raise ValueError("root_owned must be boolean")
    src = Path(src)
    if not src.is_dir():
        raise FileNotFoundError(f"Source directory does not exist or is not a directory: {src}")
    src_fd = open_dir_anchored(src)
    sealcheck: PinnedExecutable | None = None
    work_parent_fd = out_dir_fd = work_fd = tar_fd = image_fd = -1
    work_name: str | None = None
    work_ident: tuple[int, int] | None = None
    try:
        src_st = os.fstat(src_fd)
        out_image = Path(out_image)
        resolved_src = Path(os.path.abspath(src))
        resolved_out = out_image.resolve()
        # Reject before creating anything if out_image, its resolved target, or its directory is inside src
        if (
            _is_inside(out_image.parent, src_st)
            or _is_inside(resolved_out.parent, src_st)
            or resolved_out.is_relative_to(resolved_src)
            or Path(os.path.abspath(out_image)).is_relative_to(resolved_src)
        ):
            raise ValueError(
                f"Output image and staging directory cannot be inside source directory: "
                f"out_image={out_image} (resolved: {resolved_out}), src={src}"
            )
        work_parent = Path(work_dir) if work_dir is not None else Path(tempfile.gettempdir())
        if _is_inside(work_parent, src_st):
            raise ValueError(f"Work directory cannot be inside source directory: work_dir={work_parent}, src={src}")

        t_clock_utc = ensure_utc(t_clock, "t_clock")
        t_clock_str = iso_utc(t_clock_utc)
        source_date_epoch = int(t_clock_utc.timestamp())

        # Open and vet the sealcheck binary BEFORE building (fail early if missing or unsafe)
        sealcheck = find_sealcheck_bin(sealcheck_bin)
        limits = limits or RootfsLimits.from_env()

        rootfs_uuid = str(uuid.uuid5(HERMETIC_NAMESPACE, f"hermetic-rootfs:{world_id}"))
        hash_seed = str(uuid.uuid5(HERMETIC_NAMESPACE, f"hermetic-hash-seed:{world_id}"))

        mke2fs_bin = resolve_mke2fs_bin()
        proc_ver = _run([mke2fs_bin, "-V"], "MKE2FS_VERSION")
        parsed_ver = check_e2fsprogs_version(f"{proc_ver.stdout}\n{proc_ver.stderr}")
        e2fsprogs_version_str = _fmt_version(parsed_ver)
        config_path, config_sha256 = pinned_mke2fs_config()

        # Storage is descriptor-anchored: the output directory and the work parent are opened
        # component by component without following symlinks and must not be rearrangeable by
        # other users; the private work directory is created and opened relative to its
        # parent's descriptor, and every file in it is reached through held descriptors.
        _make_output_dirs(out_image.parent)
        out_dir_fd = open_dir_anchored(out_image.parent)
        check_safe_dir_fd(out_dir_fd, "Output directory", out_image.parent)
        work_parent_fd = open_dir_anchored(work_parent)
        check_safe_dir_fd(work_parent_fd, "Work directory parent", work_parent)
        work_name = f"hermetic-rootfs-{uuid.uuid4().hex}"
        os.mkdir(work_name, 0o700, dir_fd=work_parent_fd)
        work_fd = os.open(work_name, _DIR_OPEN_FLAGS, dir_fd=work_parent_fd)
        work_st = os.fstat(work_fd)
        work_ident = (work_st.st_dev, work_st.st_ino)
        check_private_dir_fd(work_fd, work_parent / work_name)

        # 1-2. Walk the source once: TR-SEAL-8 clean-up, special files skipped, caps enforced
        scan = write_rootfs_tar(
            src_fd, "rootfs.tar", mtime_ceiling=source_date_epoch, limits=limits, dir_fd=work_fd,
            root_owned=root_owned
        )
        tar_fd = os.open("rootfs.tar", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=work_fd)

        # 3. Size calculation and inode demand
        plan = plan_image(scan, size_mib)
        require_free_space(work_fd, plan.required_bytes + FREE_SPACE_MARGIN_BYTES, "ext4 image")
        if work_st.st_dev != os.fstat(out_dir_fd).st_dev:
            require_free_space(out_dir_fd, plan.required_bytes + FREE_SPACE_MARGIN_BYTES, "published image")

        # The image is created in the private work directory; mke2fs and sealcheck reach it only
        # through the inherited descriptor (/proc/self/fd/N), never by a pathname that could be
        # redirected, and it is hashed and published from the same held descriptor.
        image_fd = os.open(
            "rootfs.img", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=work_fd
        )

        # 4. Build ext4 image (TR-SEAL-7) from the tar stream with a pinned config and options
        cmd = mke2fs_command(mke2fs_bin, _fd_path(tar_fd), _fd_path(image_fd), plan, rootfs_uuid, hash_seed)
        path_env = os.environ.get("PATH", "/bin:/usr/bin:/sbin:/usr/sbin")
        if "/sbin" not in path_env:
            path_env = f"{path_env}:/sbin:/usr/sbin"
        mke2fs_env = {
            "PATH": path_env,
            # UTF-8, not plain C: mke2fs reads the PAX tar through libarchive, which refuses
            # any non-ASCII name or link target under an ASCII locale (real images ship such
            # names, e.g. CA certificates). The image bytes do not depend on the locale.
            "LANG": "C.UTF-8",
            "TZ": "UTC",
            "MKE2FS_CONFIG": str(config_path),
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "E2FSPROGS_FAKE_TIME": str(source_date_epoch),
        }
        build_proc = _run(cmd, "MKE2FS_BUILD", env=mke2fs_env, pass_fds=(tar_fd, image_fd))
        if build_proc.returncode != 0:
            raise RuntimeError(
                f"mke2fs failed with exit code {build_proc.returncode}: {build_proc.stderr.strip()}"
            )
        _require_regular_fd(image_fd, "after mke2fs")

        # 5. Guard (D4) - run the pinned sealcheck descriptor against the image BEFORE publication
        sc_proc = sealcheck.run(
            ["d4-image", "--image", _fd_path(image_fd), "--t-clock", t_clock_str, "--format", "json"],
            "SEALCHECK_D4",
            pass_fds=(image_fd,),
        )
        _require_regular_fd(image_fd, "after the D4 check")

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

        # 6. Result metadata from the held descriptor, then publish that same inode
        sha256_hex = _sha256_fd(image_fd)
        size_bytes = os.fstat(image_fd).st_size
        _publish(image_fd, work_fd, "rootfs.img", out_dir_fd, out_image.name)

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
            "logical_bytes": scan.logical_bytes,
            "xattrs": "none",
            "d4": "pass",
        }
    finally:
        for fd in (image_fd, tar_fd):
            if fd >= 0:
                os.close(fd)
        if sealcheck is not None:
            sealcheck.close()
        os.close(src_fd)
        if work_fd >= 0:
            os.close(work_fd)
        if work_ident is not None and work_name is not None and work_parent_fd >= 0:
            # Remove only our own work directory: if the entry was substituted, leave it alone.
            try:
                entry = os.stat(work_name, dir_fd=work_parent_fd, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode) and (entry.st_dev, entry.st_ino) == work_ident:
                    remove_tree_at(work_parent_fd, work_name)
            except OSError:
                pass
        for fd in (work_parent_fd, out_dir_fd):
            if fd >= 0:
                os.close(fd)
