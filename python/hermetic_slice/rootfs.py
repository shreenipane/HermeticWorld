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


def _remove_entry(path: Path) -> None:
    """Remove a file, symlink, or directory tree forcefully."""
    if path.is_symlink() or not path.is_dir():
        try:
            path.unlink()
        except OSError:
            try:
                os.chmod(path, 0o700)
                path.unlink()
            except OSError:
                pass
    else:
        rmtree_force(path)


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
    log_dir = staging_dir / "var" / "log"
    if log_dir.is_dir():
        for entry in log_dir.iterdir():
            rel = entry.relative_to(staging_dir).as_posix()
            _remove_entry(entry)
            removed.add(rel)

    # 2. var/cache/* (keep var/cache itself)
    cache_dir = staging_dir / "var" / "cache"
    if cache_dir.is_dir():
        for entry in cache_dir.iterdir():
            rel = entry.relative_to(staging_dir).as_posix()
            _remove_entry(entry)
            removed.add(rel)

    # 3. var/lib/apt/lists/*
    apt_lists = staging_dir / "var" / "lib" / "apt" / "lists"
    if apt_lists.is_dir():
        for entry in apt_lists.iterdir():
            rel = entry.relative_to(staging_dir).as_posix()
            _remove_entry(entry)
            removed.add(rel)

    # 4. root/.cache/pip, every .cache/pip and .cache/uv under home/* and root
    user_caches: list[Path] = [
        staging_dir / "root" / ".cache" / "pip",
        staging_dir / "root" / ".cache" / "uv",
    ]
    home_dir = staging_dir / "home"
    if home_dir.is_dir():
        for child in home_dir.iterdir():
            if child.is_dir():
                user_caches.append(child / ".cache" / "pip")
                user_caches.append(child / ".cache" / "uv")
    for cache_target in user_caches:
        if cache_target.exists() or cache_target.is_symlink():
            rel = cache_target.relative_to(staging_dir).as_posix()
            _remove_entry(cache_target)
            removed.add(rel)

    # 5. conda pkgs caches (opt/conda/pkgs/* and */miniconda3/pkgs/*, keeping urls.txt if present)
    pkgs_dirs: list[Path] = []
    opt_conda_pkgs = staging_dir / "opt" / "conda" / "pkgs"
    if opt_conda_pkgs.is_dir():
        pkgs_dirs.append(opt_conda_pkgs)

    for p in staging_dir.rglob("miniconda3/pkgs"):
        if p.is_dir() and p not in pkgs_dirs:
            pkgs_dirs.append(p)

    for pkgs_dir in pkgs_dirs:
        for entry in pkgs_dir.iterdir():
            if entry.name == "urls.txt":
                continue
            rel = entry.relative_to(staging_dir).as_posix()
            _remove_entry(entry)
            removed.add(rel)

    # 6. shell histories anywhere under root/ and home/
    for base in (staging_dir / "root", staging_dir / "home"):
        if base.is_dir():
            for dirpath, dirnames, filenames in os.walk(base, topdown=True):
                for f in filenames:
                    if f in SHELL_HISTORY_NAMES:
                        p = Path(dirpath) / f
                        if p.exists() or p.is_symlink():
                            rel = p.relative_to(staging_dir).as_posix()
                            _remove_entry(p)
                            removed.add(rel)
                dirs_to_remove = [d for d in dirnames if d in SHELL_HISTORY_NAMES]
                for d in dirs_to_remove:
                    p = Path(dirpath) / d
                    if p.exists() or p.is_symlink():
                        rel = p.relative_to(staging_dir).as_posix()
                        _remove_entry(p)
                        removed.add(rel)
                    dirnames.remove(d)

    return sorted(removed)


def compute_tree_size_bytes(root: Path) -> int:
    """Sum file sizes in directory tree."""
    total = 0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                total += p.lstat().st_size
            except OSError:
                pass
    return total


def calculate_image_size_mib(staging_dir: Path, size_mib: int | None = None) -> int:
    """Calculate target ext4 image size in MiB."""
    if size_mib is not None:
        if size_mib <= 0:
            raise ValueError(f"size_mib must be positive: {size_mib}")
        return size_mib
    staging_bytes = compute_tree_size_bytes(staging_dir)
    staging_mib = staging_bytes / (1024 * 1024)
    return math.ceil(staging_mib * 1.3 + 64)


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

    out_image.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = out_image.parent / f".staging-{out_image.name}-{uuid.uuid4().hex}"
    tmp_image = out_image.parent / f"{out_image.name}.tmp"

    try:
        # 1. Staging copy (skipping special files)
        skipped_special = copy_to_staging(src, staging_dir)

        # 2. Clean-up (TR-SEAL-8)
        removed = clean_rootfs_staging(staging_dir)

        # 3. Size calculation
        final_size_mib = calculate_image_size_mib(staging_dir, size_mib)

        # 4. Build ext4 image (TR-SEAL-7)
        if tmp_image.exists():
            tmp_image.unlink()

        cmd = [
            mke2fs_bin,
            "-q",
            "-t", "ext4",
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

        tmp_image.replace(out_image)

        # 5. Guard (D4)
        resolved_sealcheck = find_sealcheck_bin(sealcheck_bin)
        sc_cmd = [
            str(resolved_sealcheck),
            "d4-image",
            "--image", str(out_image),
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
            if out_image.exists():
                out_image.unlink()
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
            if out_image.exists():
                out_image.unlink()
            err_msg = sc_proc.stderr.strip() or sc_proc.stdout.strip() or f"exit code {sc_proc.returncode}"
            raise RuntimeError(f"sealcheck d4-image failed ({sc_proc.returncode}): {err_msg}")

        # 6. Result
        h = hashlib.sha256()
        with open(out_image, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        sha256_hex = h.hexdigest()

        return {
            "image": str(out_image),
            "sha256": sha256_hex,
            "size_bytes": out_image.stat().st_size,
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
        if tmp_image.exists():
            try:
                tmp_image.unlink()
            except OSError:
                pass
        if staging_dir.exists():
            rmtree_force(staging_dir)
