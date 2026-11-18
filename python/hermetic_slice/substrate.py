"""Pinned kernel metadata for production world images; no live probes run here."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any
import zipfile
import zlib

from hermetic_safe_io import atomic_write, open_regular
from hermetic_slice import guest_kernel as kernel

MAX_SUBSTRATE_DATES = 4096
MAX_SUBSTRATE_DATES_BYTES = MAX_SUBSTRATE_DATES * 11
MAX_SUBSTRATE_IMAGE_BYTES = 512 * 1024 * 1024
EXTRACT_TIMEOUT_S = 60
BOUND_PATH = "etc/hermetic/substrate-bound"
DATES_PATH = "etc/hermetic/substrate-dates"


def _dates(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_SUBSTRATE_DATES_BYTES or not raw.endswith(b"\n"):
        raise ValueError("invalid substrate date list")
    previous = None
    for line in raw[:-1].split(b"\n"):
        if not re.fullmatch(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}", line):
            raise ValueError("invalid substrate date list")
        try:
            value = date.fromisoformat(line.decode("ascii"))
        except ValueError:
            raise ValueError("invalid substrate date list") from None
        if value.year < 1970 or previous is not None and value <= previous:
            raise ValueError("invalid substrate date list")
        previous = value
    return raw


def substrate_files(
    kernel_lock: Path = kernel.DEFAULT_KERNEL_DIR / "kernel.lock.json",
    *, kernel_image: Path | None = None, clockprobe_bin: Path | None = None,
) -> dict[str, bytes]:
    """Validate inputs before creating outputs. Optional image dates use the Rust parser.

    The release date is metadata only: it never authorizes a blanket date exemption.
    Image/extractor descriptors stay pinned through the bounded offline extraction.
    """
    if (kernel_image is None) != (clockprobe_bin is None):
        raise ValueError("kernel image and clockprobe binary must be supplied together")
    with os.fdopen(open_regular(kernel_lock, kernel.MAX_LOCK_BYTES), "rb") as stream:
        raw = stream.read(kernel.MAX_LOCK_BYTES + 1)
    try:
        if len(raw) > kernel.MAX_LOCK_BYTES:
            raise ValueError
        lock = kernel.validate_lock(json.loads(raw, object_pairs_hook=kernel._pairs), for_build=True)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid substrate kernel lock") from None
    release = kernel.release_datetime(lock)
    files = {BOUND_PATH: (release.date().isoformat() + "\n").encode("ascii")}
    if kernel_image is None:
        return files
    with ExitStack() as stack:
        image = stack.enter_context(os.fdopen(open_regular(kernel_image, MAX_SUBSTRATE_IMAGE_BYTES), "rb"))
        executable = stack.enter_context(os.fdopen(open_regular(clockprobe_bin, kernel.MAX_IMAGE_BYTES), "rb"))
        process = subprocess.Popen(
            [f"/proc/self/fd/{executable.fileno()}", "--extract-substrate-dates"],
            pass_fds=(executable.fileno(),), stdin=image, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={"LANG": "C", "TZ": "UTC"}, start_new_session=True,
        )
        complete = False
        try:
            output = bytearray()
            end = time.monotonic() + EXTRACT_TIMEOUT_S
            with selectors.DefaultSelector() as poll:
                poll.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = end - time.monotonic()
                    if remaining <= 0 or not poll.select(remaining):
                        raise ValueError("substrate extraction timed out")
                    chunk = os.read(process.stdout.fileno(), MAX_SUBSTRATE_DATES_BYTES + 1 - len(output))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_SUBSTRATE_DATES_BYTES:
                        raise ValueError("substrate extraction exceeds byte cap")
            if process.wait(timeout=max(0, end - time.monotonic())) != 0:
                raise ValueError("substrate extraction failed")
            files[DATES_PATH] = _dates(bytes(output))
            complete = True
        finally:
            if not complete:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=EXTRACT_TIMEOUT_S)
            if process.stdout is not None:
                process.stdout.close()
    return files


MAX_SUBSTRATE_FILES = 131072
MAX_SUBSTRATE_EXEMPTIONS = 1024
MAX_VERIFY_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB
MAX_DEPTH = 64
MAX_PATH_BYTES = 4096
MAX_DIR_ENTRIES = 10000
MAX_VERIFY_CHUNKS = (MAX_VERIFY_FILE_BYTES // 65536) + 1
FORBIDDEN_EXEMPTION_PREFIXES = (
    "testbed",
    "opt/miniconda3/envs",
    "opt/conda/envs",
)


def normalize_relative_path(path: str) -> str:
    """Normalize a path by stripping leading slashes and ./ prefixes."""
    s = path.strip()
    for _ in range(MAX_PATH_BYTES):
        if s.startswith("./"):
            s = s[2:]
        elif s.startswith("/"):
            s = s[1:]
        else:
            break
    return s


def is_repo_or_task_dep(
    rel_path: str,
    repo_path: str = "testbed",
    task_dep_prefixes: tuple[str, ...] = ("opt/miniconda3/envs", "opt/conda/envs"),
) -> bool:
    """Check if relative path points into repository or task dependency closure."""
    norm = normalize_relative_path(rel_path)
    if not norm:
        return False
    # Never inventory or exempt repository or git internals
    if norm in ("testbed", ".git") or norm.startswith(("testbed/", ".git/", f"{repo_path}/")):
        return True
    if norm == repo_path:
        return True
    if "/testbed/" in norm:
        return True
    # Never inventory or exempt task dependency closure
    for prefix in task_dep_prefixes:
        norm_prefix = normalize_relative_path(prefix)
        if norm == norm_prefix or norm.startswith(f"{norm_prefix}/"):
            return True
    return False


def validate_exemption_path(path_str: str) -> str:
    """Validate exemption path compliance with safety rules."""
    norm = normalize_relative_path(path_str)
    if not norm or len(norm.encode("utf-8")) > MAX_PATH_BYTES:
        raise ValueError(f"Invalid exemption path: '{path_str}'")
    if any(c in "*?[]" for c in norm) or path_str.endswith("/") or norm.endswith("/"):
        raise ValueError(f"Pattern or directory exemption is forbidden: '{path_str}'")
    parts = Path(norm).parts
    if any(part in ("..", ".") for part in parts):
        raise ValueError(f"Invalid exemption path containing relative components: '{path_str}'")
    if norm.startswith(("opt/miniconda3/envs/", "opt/conda/envs/")):
        raise ValueError(f"Forbidden exemption inside task dependency closure: '{path_str}'")
    if norm == ".git" or norm.startswith(".git/") or "/.git/" in norm or norm.endswith("/.git"):
        raise ValueError(f"Forbidden exemption inside repository metadata: '{path_str}'")
    if norm == "testbed" or norm.startswith("testbed/") or "/testbed/" in norm:
        raise ValueError(f"Forbidden exemption inside repository: '{path_str}'")
    return norm


def _safe_file_sha256(path: Path | str) -> str:
    """Hash regular file using open_regular with bounded read chunks."""
    h = hashlib.sha256()
    fd = open_regular(path, MAX_VERIFY_FILE_BYTES)
    try:
        with os.fdopen(fd, "rb") as stream:
            total = 0
            chunks = 0
            while chunks < MAX_VERIFY_CHUNKS:
                chunks += 1
                chunk = stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_VERIFY_FILE_BYTES:
                    raise ValueError(f"File {path} exceeds byte limit")
                h.update(chunk)
    except Exception:
        raise
    return h.hexdigest()


def _inventory_zip_members(
    zip_full_path: Path | str,
    archive_rel_path: str,
    entries: list[dict[str, str]],
) -> None:
    """Inventory zip/whl/jar members with uncompressed SHA-256."""
    try:
        with zipfile.ZipFile(zip_full_path, "r") as zf:
            for idx, info in enumerate(zf.infolist()):
                if idx >= MAX_SUBSTRATE_FILES:
                    raise ValueError(f"Substrate file count exceeds cap of {MAX_SUBSTRATE_FILES}")
                if info.is_dir() or info.filename.endswith("/"):
                    continue
                if info.file_size > MAX_VERIFY_FILE_BYTES:
                    continue
                if len(entries) >= MAX_SUBSTRATE_FILES:
                    raise ValueError(f"Substrate file count exceeds cap of {MAX_SUBSTRATE_FILES}")
                try:
                    member_bytes = zf.read(info)
                except (zipfile.BadZipFile, OSError, KeyError, RuntimeError, NotImplementedError, EOFError, zlib.error):
                    continue
                if len(member_bytes) > MAX_VERIFY_FILE_BYTES:
                    continue
                member_sha = hashlib.sha256(member_bytes).hexdigest()
                entries.append({
                    "path": f"{archive_rel_path}!/{info.filename}",
                    "sha256": member_sha,
                })
    except (zipfile.BadZipFile, OSError, KeyError, RuntimeError, NotImplementedError, EOFError, zlib.error):
        pass


def inventory_substrate(
    root: Path | str,
    *,
    repo_path: str = "testbed",
    task_dep_prefixes: tuple[str, ...] = ("opt/miniconda3/envs", "opt/conda/envs"),
) -> dict[str, Any]:
    """Inventory the substrate (base environment: interpreter, pip, OS packages).

    Separates repository (/testbed) and task dependencies (opt/.../envs/).
    Produces canonical substrate inventory with relative paths and sha256 digests.
    """
    root_path = Path(root).resolve()
    entries: list[dict[str, str]] = []

    def visit(current_dir: Path, rel_prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ValueError(f"Directory traversal exceeded depth limit of {MAX_DEPTH}")
        with os.scandir(current_dir) as scan:
            count = 0
            for entry in scan:
                count += 1
                if count > MAX_DIR_ENTRIES:
                    raise ValueError(f"Directory {current_dir} exceeds max entries cap of {MAX_DIR_ENTRIES}")
                # Never follow symlinks
                if entry.is_symlink():
                    continue
                name = entry.name
                rel_path = f"{rel_prefix}/{name}" if rel_prefix else name

                # Exclude repository and task dependency closure
                if is_repo_or_task_dep(rel_path, repo_path, task_dep_prefixes):
                    continue

                if entry.is_dir(follow_symlinks=False):
                    visit(Path(entry.path), rel_path, depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    if len(entries) >= MAX_SUBSTRATE_FILES:
                        raise ValueError(f"Substrate file count exceeds cap of {MAX_SUBSTRATE_FILES}")
                    file_sha = _safe_file_sha256(entry.path)
                    entries.append({"path": rel_path, "sha256": file_sha})

                    # If archive (.whl, .zip, .jar), inspect archive members
                    if rel_path.endswith((".whl", ".zip", ".jar")):
                        _inventory_zip_members(entry.path, rel_path, entries)

    visit(root_path, "", 0)
    entries.sort(key=lambda e: e["path"])
    canon_bytes = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    inventory_digest = hashlib.sha256(canon_bytes).hexdigest()
    return {
        "schema": "hermetic-substrate-inventory/v1",
        "entries": entries,
        "inventory_digest": inventory_digest,
        "total_entries": len(entries),
    }


def _parse_iso_or_oci_date(s: str) -> datetime:
    """Parse RFC 3339 or Docker UTC date string to UTC datetime."""
    s = s.strip()
    if s.endswith(" UTC"):
        s = s[:-4].strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    if len(s) > 10 and s[10] == " ":
        s = s[:10] + "T" + s[11:]
    s = re.sub(r"\s+([+-]\d{2}):?(\d{2})$", r"\1\2", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", s)
        if m:
            base, frac, rest = m.groups()
            s = f"{base}.{frac[:6]}{rest}"
            dt = datetime.fromisoformat(s)
        else:
            raise
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_exemptions(
    root: Path | str,
    inventory: dict[str, Any],
    t_clock: datetime,
    *,
    oci_inspect_path: Path | str | None = None,
    oci_history_path: Path | str | None = None,
    repo_path: str = "testbed",
    task_dep_prefixes: tuple[str, ...] = ("opt/miniconda3/envs", "opt/conda/envs"),
) -> dict[str, Any]:
    """Generate named exemptions for every substrate file that D4/D6 would flag.

    Each entry is (path, sha256, detector, reason). Exact match required.
    Never exempts anything inside repository or task dependencies.
    """
    root_path = Path(root).resolve()
    t_clock_utc = t_clock if t_clock.tzinfo else t_clock.replace(tzinfo=timezone.utc)
    t_clock_utc = t_clock_utc.astimezone(timezone.utc)
    t_clock_ts = t_clock_utc.timestamp()

    raw_exemptions: list[dict[str, str]] = []

    # 1. D4: Check substrate files and archive members against t_clock
    archive_members: dict[str, list[tuple[str, str, str]]] = {}
    for entry in inventory.get("entries", []):
        path_str = entry["path"]
        sha = entry["sha256"]

        # Security check: never exempt repository or dependency closure
        if is_repo_or_task_dep(path_str, repo_path, task_dep_prefixes):
            continue

        if "!/" in path_str:
            archive_rel, member_name = path_str.split("!/", 1)
            archive_members.setdefault(archive_rel, []).append((path_str, member_name, sha))
        else:
            full_path = root_path / path_str
            try:
                st = os.stat(full_path, follow_symlinks=False)
                if st.st_mtime > t_clock_ts:
                    raw_exemptions.append({
                        "detector": "D4",
                        "path": path_str,
                        "sha256": sha,
                        "reason": "post_cutoff_substrate_mtime",
                    })
            except OSError:
                pass

    for archive_rel, members in archive_members.items():
        archive_full = root_path / archive_rel
        if archive_full.is_file():
            try:
                with zipfile.ZipFile(archive_full, "r") as zf:
                    for path_str, member_name, sha in members:
                        try:
                            info = zf.getinfo(member_name)
                            dt = datetime(*info.date_time, tzinfo=timezone.utc)
                            if dt > t_clock_utc:
                                raw_exemptions.append({
                                    "detector": "D4",
                                    "path": path_str,
                                    "sha256": sha,
                                    "reason": "post_cutoff_archive_member_mtime",
                                })
                        except Exception:
                            pass
            except Exception:
                pass

    # 2. D6: Check oci_inspect_path
    if oci_inspect_path is not None:
        insp_p = Path(oci_inspect_path)
        if insp_p.is_file():
            try:
                data = json.loads(insp_p.read_text(encoding="utf-8"))
                images = data if isinstance(data, list) else [data]
                for img in images:
                    created_str = img.get("Created")
                    if created_str:
                        created_dt = _parse_iso_or_oci_date(created_str)
                        if created_dt > t_clock_utc:
                            raw_exemptions.append({
                                "detector": "D6",
                                "path": insp_p.name,
                                "sha256": hashlib.sha256(insp_p.read_bytes()).hexdigest(),
                                "reason": "post_cutoff_image_created",
                            })
                            break
            except Exception:
                pass

    # 3. D6: Check oci_history_path
    if oci_history_path is not None:
        hist_p = Path(oci_history_path)
        if hist_p.is_file():
            try:
                lines = hist_p.read_text(encoding="utf-8").splitlines()
                history_late = False
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    entry_json = json.loads(line)
                    created_at = entry_json.get("CreatedAt")
                    if created_at:
                        entry_dt = _parse_iso_or_oci_date(created_at)
                        if entry_dt > t_clock_utc:
                            history_late = True
                            break
                if history_late:
                    raw_exemptions.append({
                        "detector": "D6",
                        "path": hist_p.name,
                        "sha256": hashlib.sha256(hist_p.read_bytes()).hexdigest(),
                        "reason": "post_cutoff_image_history",
                    })
            except Exception:
                pass

    # Validate and cap exemptions
    if len(raw_exemptions) > MAX_SUBSTRATE_EXEMPTIONS:
        raise ValueError(f"Exemption count {len(raw_exemptions)} exceeds cap of {MAX_SUBSTRATE_EXEMPTIONS}")

    validated: list[dict[str, str]] = []
    seen_keys: set[tuple[str, str]] = set()
    for ex in raw_exemptions:
        valid_path = validate_exemption_path(ex["path"])
        key = (ex["detector"], valid_path)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        validated.append({
            "detector": ex["detector"],
            "path": valid_path,
            "sha256": ex["sha256"].lower(),
            "reason": ex["reason"],
        })

    # Strictly sort by detector then path
    validated.sort(key=lambda x: (x["detector"], x["path"]))

    # Exemption list for run record (strictly unique and sorted paths)
    exemption_list = sorted(list(set(x["path"] for x in validated)))

    canon_bytes = json.dumps({"exemptions": validated}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    exemption_list_digest = hashlib.sha256(canon_bytes).hexdigest()

    return {
        "schema": "hermetic-substrate-exemptions/v1",
        "exemptions": validated,
        "exemption_list": exemption_list,
        "exemption_list_digest": exemption_list_digest,
        "substrate_at_t": "partial" if validated else "full",
        "total_exemptions": len(validated),
    }


def write_substrate_outputs(
    work_dir: Path | str,
    inventory: dict[str, Any],
    exemptions: dict[str, Any],
) -> tuple[Path, Path]:
    """Write substrate inventory and exemptions deterministically."""
    work = Path(work_dir)
    inv_path = work / "substrate-inventory.json"
    ex_path = work / "exemptions.json"

    inv_bytes = json.dumps(inventory, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    ex_bytes = json.dumps(exemptions, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    atomic_write(inv_path, inv_bytes)
    atomic_write(ex_path, ex_bytes)
    return inv_path, ex_path
