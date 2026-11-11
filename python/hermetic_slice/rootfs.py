"""Reproducible rootfs builder with D4 guard (TR-SEAL-7, TR-SEAL-8, TR-SEAL-12)."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.intake import iso_utc
from hermetic_slice.repo_sealer import rmtree_force

HERMETIC_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "hermetic.world")
NAMESPACE = HERMETIC_NAMESPACE
MIN_E2FSPROGS_VERSION = (1, 47, 1)
SHELL_HISTORY_NAMES = {".bash_history", ".zsh_history", ".python_history", ".lesshst", ".viminfo"}


class RootfsGateError(Exception):
    """Raised when rootfs image fails D4 guard verification."""

    def __init__(self, message: str, findings: list[dict] | None = None) -> None:
        super().__init__(message)
        self.findings = findings or []


def parse_mke2fs_version(version_str: str) -> tuple[int, int, int]:
    """Parse (major, minor, patch) from mke2fs -V output string."""
    match = re.search(r"mke2fs\s+(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not match:
        raise ValueError(f"Could not parse mke2fs version from: {version_str!r}")
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def check_e2fsprogs_version(version_str: str) -> tuple[int, int, int]:
    """Ensure mke2fs version satisfies minimum requirement >= 1.47.1."""
    version = parse_mke2fs_version(version_str)
    if version < MIN_E2FSPROGS_VERSION:
        found_ver = f"{version[0]}.{version[1]}.{version[2]}"
        min_ver = f"{MIN_E2FSPROGS_VERSION[0]}.{MIN_E2FSPROGS_VERSION[1]}.{MIN_E2FSPROGS_VERSION[2]}"
        raise RuntimeError(
            f"e2fsprogs >= {min_ver} required, found {found_ver} ({version_str.strip()})"
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


def _binary_supports_d4(path: Path) -> bool:
    """Check if sealcheck binary supports d4-image subcommand."""
    try:
        proc = subprocess.run(
            [str(path), "d4-image", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def find_sealcheck_bin(sealcheck_bin: Path | str | None = None) -> Path:
    """Locate hermetic-sealcheck binary following specification search order."""
    if sealcheck_bin is not None:
        p = Path(sealcheck_bin)
        if p.is_file() and os.access(p, os.X_OK):
            return p
        raise FileNotFoundError(f"Specified sealcheck binary not found or not executable: {p}")

    env_bin = os.environ.get("HERMETIC_SEALCHECK_BIN")
    if env_bin:
        p = Path(env_bin)
        if p.is_file() and os.access(p, os.X_OK):
            return p
        raise FileNotFoundError(f"HERMETIC_SEALCHECK_BIN binary not found or not executable: {p}")

    search_dirs = [
        Path.home() / "hermetic" / "cargo-target",
        Path.home().parent / "hermetic" / "cargo-target",
        Path("/home/flingboot/hermetic/cargo-target"),
    ]
    candidates: list[Path] = []
    for cargo_target_base in search_dirs:
        if cargo_target_base.is_dir():
            for mode in ("release", "debug"):
                for candidate in cargo_target_base.glob(f"*/{mode}/hermetic-sealcheck"):
                    if candidate.is_file() and os.access(candidate, os.X_OK) and candidate not in candidates:
                        candidates.append(candidate)
                for candidate in cargo_target_base.glob(f"*/target/{mode}/hermetic-sealcheck"):
                    if candidate.is_file() and os.access(candidate, os.X_OK) and candidate not in candidates:
                        candidates.append(candidate)

    # Sort candidates by mtime descending (newest first)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    # Prefer candidates that implement d4-image
    for candidate in candidates:
        if _binary_supports_d4(candidate):
            return candidate

    if candidates:
        return candidates[0]

    which_bin = shutil.which("hermetic-sealcheck")
    if which_bin:
        return Path(which_bin)

    raise FileNotFoundError(
        "No hermetic-sealcheck binary found. Provide sealcheck_bin, set $HERMETIC_SEALCHECK_BIN, "
        "or compile hermetic-sealcheck under ~/hermetic/cargo-target/*/"
    )


def _is_special_file(mode: int) -> bool:
    """Check if file mode represents device node, FIFO, or socket."""
    return (
        stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISFIFO(mode)
        or stat.S_ISSOCK(mode)
    )


def copy_to_staging(src: Path, staging_dir: Path) -> list[str]:
    """Copy src tree to staging_dir, skipping special files (device nodes, FIFOs, sockets).

    Returns:
        Sorted list of relative POSIX paths of skipped special files.
    """
    skipped_special: list[str] = []

    def _ignore_special(dir_path: str, names: list[str]) -> set[str]:
        ignored = set()
        for name in names:
            full_path = os.path.join(dir_path, name)
            try:
                st = os.lstat(full_path)
            except OSError:
                continue
            if _is_special_file(st.st_mode):
                ignored.add(name)
                rel_path = os.path.relpath(full_path, src)
                skipped_special.append(Path(rel_path).as_posix())
        return ignored

    shutil.copytree(src, staging_dir, symlinks=True, ignore=_ignore_special)
    return sorted(skipped_special)


def _safe_real_dir(staging_dir: Path, rel_path: Path | str) -> Path | None:
    """Resolve rel_path component by component from staging_dir using os.lstat.

    If any component (including ancestors) is a symlink, does not exist,
    or is not a directory, returns None (never descend through symlinks).
    Otherwise returns the Path.
    """
    rel = Path(rel_path)
    current = staging_dir
    try:
        st = os.lstat(current)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return None
    except OSError:
        return None

    for part in rel.parts:
        if part in (".", ""):
            continue
        if part == "..":
            return None
        current = current / part
        try:
            st = os.lstat(current)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return None

    return current


def _safe_walk(dir_path: Path):
    """Walk directory tree yielding (dirpath, dirnames, filenames), NEVER following symlinks."""
    try:
        with os.scandir(dir_path) as it:
            dirs = []
            files = []
            for entry in it:
                try:
                    if entry.is_symlink():
                        files.append(entry.name)
                    elif entry.is_dir(follow_symlinks=False):
                        dirs.append(entry.name)
                    else:
                        files.append(entry.name)
                except OSError:
                    continue
    except OSError:
        return

    yield dir_path, dirs, files

    for d in list(dirs):
        yield from _safe_walk(dir_path / d)


def _remove_path(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        os.unlink(path)
    else:
        rmtree_force(path)
        if path.exists() or path.is_symlink():
            raise OSError(f"Directory {path} could not be completely removed")


def _remove_entry(path: Path, staging_dir: Path | None = None) -> None:
    """Remove a file, symlink, or directory tree forcefully, failing if it cannot be removed."""
    try:
        _remove_path(path)
    except OSError:
        # First try making the parent directory writable (chmod u+w on the parent, inside staging only)
        parent = path.parent
        try:
            can_chmod = True
            if staging_dir is not None:
                resolved_staging = staging_dir.resolve()
                resolved_parent = parent.resolve()
                can_chmod = (
                    resolved_parent == resolved_staging
                    or resolved_parent.is_relative_to(resolved_staging)
                )
            if can_chmod:
                st = os.lstat(parent)
                if not stat.S_ISLNK(st.st_mode):
                    os.chmod(parent, st.st_mode | stat.S_IWUSR)
        except OSError:
            pass

        # Retry once
        try:
            _remove_path(path)
        except OSError as exc:
            raise RuntimeError(f"Failed to remove clean-up target {path}: {exc}") from exc


def clean_rootfs_staging(staging_dir: Path) -> list[str]:
    """Clean up staging directory according to TR-SEAL-8.

    Deletes:
    - var/log/*, var/cache/* (keeping the directories themselves)
    - var/lib/apt/lists/*
    - root/.cache/pip
    - every .cache/pip and .cache/uv under home/* and root
    - conda pkgs caches (opt/conda/pkgs/* and */miniconda3/pkgs/*, keeping urls.txt if present)
    - shell histories (.bash_history, .zsh_history, .python_history, .lesshst, .viminfo) anywhere under root/ and home/

    Returns:
        Sorted list of relative POSIX paths of removed entries.
    """
    removed: set[str] = set()

    # 1. var/log/* (keep var/log itself)
    log_dir = _safe_real_dir(staging_dir, "var/log")
    if log_dir is not None:
        with os.scandir(log_dir) as it:
            for entry in it:
                entry_path = Path(entry.path)
                rel = entry_path.relative_to(staging_dir).as_posix()
                _remove_entry(entry_path, staging_dir)
                removed.add(rel)

    # 2. var/cache/* (keep var/cache itself)
    cache_dir = _safe_real_dir(staging_dir, "var/cache")
    if cache_dir is not None:
        with os.scandir(cache_dir) as it:
            for entry in it:
                entry_path = Path(entry.path)
                rel = entry_path.relative_to(staging_dir).as_posix()
                _remove_entry(entry_path, staging_dir)
                removed.add(rel)

    # 3. var/lib/apt/lists/*
    apt_lists = _safe_real_dir(staging_dir, "var/lib/apt/lists")
    if apt_lists is not None:
        with os.scandir(apt_lists) as it:
            for entry in it:
                entry_path = Path(entry.path)
                rel = entry_path.relative_to(staging_dir).as_posix()
                _remove_entry(entry_path, staging_dir)
                removed.add(rel)

    # 4. root/.cache/pip, every .cache/pip and .cache/uv under home/* and root
    root_cache_dir = _safe_real_dir(staging_dir, "root/.cache")
    if root_cache_dir is not None:
        for cname in ("pip", "uv"):
            target = root_cache_dir / cname
            try:
                os.lstat(target)
                target_exists = True
            except OSError:
                target_exists = False
            if target_exists:
                rel = target.relative_to(staging_dir).as_posix()
                _remove_entry(target, staging_dir)
                removed.add(rel)

    home_dir = _safe_real_dir(staging_dir, "home")
    if home_dir is not None:
        with os.scandir(home_dir) as it:
            for u_entry in it:
                if u_entry.is_dir(follow_symlinks=False):
                    user_cache_dir = _safe_real_dir(staging_dir, f"home/{u_entry.name}/.cache")
                    if user_cache_dir is not None:
                        for cname in ("pip", "uv"):
                            target = user_cache_dir / cname
                            try:
                                os.lstat(target)
                                target_exists = True
                            except OSError:
                                target_exists = False
                            if target_exists:
                                rel = target.relative_to(staging_dir).as_posix()
                                _remove_entry(target, staging_dir)
                                removed.add(rel)

    # 5. conda pkgs caches (opt/conda/pkgs/* and */miniconda3/pkgs/*, keeping urls.txt if present)
    pkgs_dirs: list[Path] = []
    opt_conda_pkgs = _safe_real_dir(staging_dir, "opt/conda/pkgs")
    if opt_conda_pkgs is not None:
        pkgs_dirs.append(opt_conda_pkgs)

    for dirpath, dirs, files in _safe_walk(staging_dir):
        if opt_conda_pkgs is not None and dirpath == opt_conda_pkgs:
            dirs.clear()
            continue
        if dirpath.name == "pkgs" and dirpath.parent.name == "miniconda3":
            if dirpath not in pkgs_dirs:
                pkgs_dirs.append(dirpath)
            dirs.clear()

    # Prune any directory beneath another selected cleanup target
    filtered_pkgs_dirs: list[Path] = []
    for d in pkgs_dirs:
        if not any(d != other and d.is_relative_to(other) for other in pkgs_dirs):
            filtered_pkgs_dirs.append(d)
    pkgs_dirs = filtered_pkgs_dirs

    for pkgs_dir in pkgs_dirs:
        try:
            with os.scandir(pkgs_dir) as it:
                for entry in it:
                    if entry.name == "urls.txt":
                        continue
                    entry_path = Path(entry.path)
                    rel = entry_path.relative_to(staging_dir).as_posix()
                    _remove_entry(entry_path, staging_dir)
                    removed.add(rel)
        except OSError:
            continue

    # 6. shell histories anywhere under root/ and home/
    for base_name in ("root", "home"):
        base_dir = _safe_real_dir(staging_dir, base_name)
        if base_dir is not None:
            for dirpath, dirnames, filenames in _safe_walk(base_dir):
                for f in filenames:
                    if f in SHELL_HISTORY_NAMES:
                        p = dirpath / f
                        rel = p.relative_to(staging_dir).as_posix()
                        _remove_entry(p, staging_dir)
                        removed.add(rel)
                for d in list(dirnames):
                    if d in SHELL_HISTORY_NAMES:
                        p = dirpath / d
                        rel = p.relative_to(staging_dir).as_posix()
                        _remove_entry(p, staging_dir)
                        removed.add(rel)
                        dirnames.remove(d)

    return sorted(removed)


def compute_tree_stats(root: Path) -> tuple[int, int]:
    """Sum file sizes and count entries (files, dirs, symlinks) in directory tree."""
    total_bytes = 0
    entry_count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        entry_count += len(dirnames)
        for name in filenames:
            entry_count += 1
            p = Path(dirpath) / name
            try:
                st = p.lstat()
                total_bytes += st.st_size
            except OSError:
                pass
    return total_bytes, entry_count


def compute_tree_size_bytes(root: Path) -> int:
    """Sum file sizes in directory tree."""
    total_bytes, _ = compute_tree_stats(root)
    return total_bytes


def calculate_inode_count(entry_count: int) -> int:
    """Calculate requested inode count: entries * 1.25 + 1024."""
    return math.ceil(entry_count * 1.25 + 1024)


def calculate_image_size_mib(staging_dir: Path, size_mib: int | None = None) -> int:
    """Calculate target ext4 image size in MiB."""
    if size_mib is not None:
        if size_mib <= 0:
            raise ValueError(f"size_mib must be positive: {size_mib}")
        return size_mib
    staging_bytes, entry_count = compute_tree_stats(staging_dir)
    staging_mib = staging_bytes / (1024 * 1024)
    base_mib = math.ceil(staging_mib * 1.3 + 64)

    requested_inodes = calculate_inode_count(entry_count)
    # The base 64 MiB overhead covers filesystem metadata, directory entries, default
    # journal, and the initial baseline inodes (1024). Extra requested inodes require
    # 256 bytes each in addition to the base overhead and staging bytes.
    extra_inodes = max(0, requested_inodes - 1024)
    min_bytes = extra_inodes * 256 + staging_bytes + (64 * 1024 * 1024)
    min_mib = math.ceil(min_bytes / (1024 * 1024))

    return max(base_mib, min_mib)


def build_rootfs(
    src: Path,
    out_image: Path,
    *,
    t_clock: datetime,
    world_id: str,
    size_mib: int | None = None,
    sealcheck_bin: Path | None = None,
) -> dict:
    """Build a reproducible ext4 root filesystem image with D4 guard.

    Args:
        src: Path to source root filesystem tree.
        out_image: Path to write the output ext4 filesystem image.
        t_clock: Clock cutoff timestamp (must be timezone-aware or UTC).
        world_id: Unique identifier for the world slice.
        size_mib: Optional filesystem image size in MiB.
        sealcheck_bin: Optional explicit path to hermetic-sealcheck binary.

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

    # Reject before creating anything if out_image, resolved symlink target, or staging parent would be inside src
    if (
        resolved_out.is_relative_to(resolved_src)
        or resolved_out.parent.is_relative_to(resolved_src)
        or resolved_out_parent.is_relative_to(resolved_src)
    ):
        raise ValueError(
            f"Output image and staging directory cannot be inside source directory: "
            f"out_image={out_image} (resolved: {resolved_out}), src={src} (resolved: {resolved_src})"
        )

    # FIX 3: Find sealcheck binary BEFORE building (fail early if missing)
    resolved_sealcheck = find_sealcheck_bin(sealcheck_bin)

    t_clock_utc = ensure_utc(t_clock, "t_clock")
    t_clock_str = iso_utc(t_clock_utc)
    source_date_epoch = int(t_clock_utc.timestamp())

    rootfs_uuid = str(uuid.uuid5(HERMETIC_NAMESPACE, f"hermetic-rootfs:{world_id}"))
    hash_seed = str(uuid.uuid5(HERMETIC_NAMESPACE, f"hermetic-hash-seed:{world_id}"))

    mke2fs_bin = resolve_mke2fs_bin()
    proc_ver = subprocess.run(
        [mke2fs_bin, "-V"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    combined_ver_out = f"{proc_ver.stdout}\n{proc_ver.stderr}"
    parsed_ver = check_e2fsprogs_version(combined_ver_out)
    e2fsprogs_version_str = f"{parsed_ver[0]}.{parsed_ver[1]}.{parsed_ver[2]}"

    staging_dir: Path | None = None
    tmp_image: Path | None = None

    try:
        out_image.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = out_image.parent / f".staging-{out_image.name}-{uuid.uuid4().hex}"

        # FIX 4: Unique temporary file in the same directory
        fd, tmp_path_str = tempfile.mkstemp(
            dir=out_image.parent,
            prefix=f"{out_image.name}.",
            suffix=".tmp",
        )
        os.close(fd)
        tmp_image = Path(tmp_path_str)

        # 1. Staging copy (skipping special files)
        skipped_special = copy_to_staging(src, staging_dir)

        # 2. Clean-up (TR-SEAL-8)
        removed = clean_rootfs_staging(staging_dir)

        # 3. Size calculation and inode demand (FIX 6)
        staging_bytes, entry_count = compute_tree_stats(staging_dir)
        inode_count = calculate_inode_count(entry_count)
        final_size_mib = calculate_image_size_mib(staging_dir, size_mib)

        # 4. Build ext4 image (TR-SEAL-7)
        cmd = [
            mke2fs_bin,
            "-q",
            "-t", "ext4",
            "-N", str(inode_count),
            "-d", str(staging_dir),
            "-U", rootfs_uuid,
            "-E", f"hash_seed={hash_seed}",
            "-F",
            str(tmp_image),
            f"{final_size_mib}M",
        ]
        # Start from minimal env: PATH, LANG=C, plus TZ=UTC, SOURCE_DATE_EPOCH, E2FSPROGS_FAKE_TIME
        path_env = os.environ.get("PATH", "/bin:/usr/bin:/sbin:/usr/sbin")
        if "/sbin" not in path_env:
            path_env = f"{path_env}:/sbin:/usr/sbin"
        mke2fs_env = {
            "PATH": path_env,
            "LANG": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "E2FSPROGS_FAKE_TIME": str(source_date_epoch),
        }

        build_proc = subprocess.run(
            cmd,
            env=mke2fs_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if build_proc.returncode != 0:
            if tmp_image.exists():
                tmp_image.unlink()
            raise RuntimeError(
                f"mke2fs failed with exit code {build_proc.returncode}: {build_proc.stderr.strip()}"
            )

        # 5. Guard (D4) - run against temporary image BEFORE replacing out_image (FIX 3)
        sc_cmd = [
            str(resolved_sealcheck),
            "d4-image",
            "--image", str(tmp_image),
            "--t-clock", t_clock_str,
            "--format", "json",
        ]
        sc_proc = subprocess.run(
            sc_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if sc_proc.returncode == 0:
            pass
        elif sc_proc.returncode == 2:
            if tmp_image.exists():
                tmp_image.unlink()
            findings = []
            try:
                parsed_json = json.loads(sc_proc.stdout)
                findings = parsed_json.get("findings", [])
            except Exception:
                pass
            raise RootfsGateError(
                f"D4 gate check failed for image {out_image}: {len(findings)} finding(s)",
                findings=findings,
            )
        else:
            if tmp_image.exists():
                tmp_image.unlink()
            err_msg = sc_proc.stderr.strip() or sc_proc.stdout.strip() or f"exit code {sc_proc.returncode}"
            raise RuntimeError(f"sealcheck d4-image failed ({sc_proc.returncode}): {err_msg}")

        # 6. Result metadata from tmp_image BEFORE publication to prevent concurrent overwrite races
        h = hashlib.sha256()
        with open(tmp_image, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        sha256_hex = h.hexdigest()
        size_bytes = tmp_image.stat().st_size

        # Gate passed! Publish temporary image to out_image (FIX 3, FIX 4)
        os.replace(tmp_image, out_image)

        return {
            "image": str(out_image),
            "sha256": sha256_hex,
            "size_bytes": size_bytes,
            "uuid": rootfs_uuid,
            "hash_seed": hash_seed,
            "t_clock": t_clock_str,
            "source_date_epoch": source_date_epoch,
            "removed": removed,
            "skipped_special": skipped_special,
            "e2fsprogs_version": e2fsprogs_version_str,
            "d4": "pass",
        }
    finally:
        if tmp_image is not None and tmp_image.exists():
            try:
                tmp_image.unlink()
            except OSError:
                pass
        if staging_dir is not None and staging_dir.exists():
            rmtree_force(staging_dir)
