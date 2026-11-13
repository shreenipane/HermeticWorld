import calendar
import datetime
import decimal
import json
import os
import re
import stat
import math
from typing import Any, Dict, List, Optional, Set, Tuple

MAX_PAGE_BYTES = 32 * 1024 * 1024
MAX_YANKS_BYTES = 8 * 1024 * 1024
MAX_FILES_COUNT = 100000
MAX_YANKS_COUNT = 200000
MAX_STRING_LEN = 16384
MAX_JSON_DEPTH = 16
READ_CHUNK_BYTES = 65536
MAX_TEMP_ATTEMPTS = 64
MAX_NUMBER_LITERAL_LEN = 64

# RFC 3339 date-time: "T"/"Z" case-insensitive, offset "Z" or +HH:MM / -HH:MM. ASCII digits
# only (no Unicode digits) and fullmatch (no trailing newline). More than 9 fractional digits
# is refused rather than truncated, because truncation could move a time to the cutoff.
_RFC3339_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)
_PEP503_RE = re.compile(r"[-_.]+")
_NS_PER_SEC = 1_000_000_000
_SDIST_EXTS = (".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz")


class YankError(Exception):
    """Typed error for PEP 691 simple index yank-date rewriting."""


def parse_rfc3339_ns(value: str) -> int:
    if not isinstance(value, str) or len(value) > 64:
        raise YankError("invalid RFC3339 timestamp")
    m = _RFC3339_RE.fullmatch(value)
    if not m:
        raise YankError("malformed RFC3339 UTC timestamp")
    year, month, day, hour, minute, second = (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3)),
        int(m.group(4)),
        int(m.group(5)),
        int(m.group(6)),
    )
    frac = m.group(7) or ""
    offset_sec = 0
    if m.group(8) is not None:
        off_h, off_m = int(m.group(9)), int(m.group(10))
        if off_h > 23 or off_m > 59:
            raise YankError("invalid UTC offset in timestamp")
        offset_sec = (off_h * 3600 + off_m * 60) * (1 if m.group(8) == "+" else -1)
    if year < 1970 or year > 9999:
        raise YankError("year out of range")
    try:
        dt = datetime.date(year, month, day)
    except ValueError as exc:
        raise YankError("invalid calendar date") from exc
    if hour > 23 or minute > 59 or second > 59:
        raise YankError("invalid time component")
    sec = calendar.timegm((dt.year, dt.month, dt.day, hour, minute, second, 0, 0, 0)) - offset_sec
    ns_frac = int(frac.ljust(9, "0")) if frac else 0
    return sec * _NS_PER_SEC + ns_frac


def safe_read_bytes(path: str, max_bytes: int) -> bytes:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise YankError("invalid file path")
    # lstat first: a symlink, FIFO, socket or device is refused before any open, so a
    # FIFO can never block the reader. O_NONBLOCK covers a swap between lstat and open,
    # and the dev/ino comparison after open proves the descriptor is the inspected file.
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise YankError("failed to open file safely") from exc
    if not stat.S_ISREG(before.st_mode):
        raise YankError("path is not a regular file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise YankError("failed to open file safely") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise YankError("path is not a regular file")
        if (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            raise YankError("input file changed while being opened")
        if st.st_size > max_bytes:
            raise YankError("file exceeds size cap")
        chunks: List[bytes] = []
        total = 0
        max_loops = (max_bytes // READ_CHUNK_BYTES) + 2
        for _ in range(max_loops):
            chunk = os.read(fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise YankError("file exceeded cap during read")
            chunks.append(chunk)
        else:
            raise YankError("read loop cap exceeded")
        return b"".join(chunks)
    except OSError as exc:
        raise YankError("failed reading file") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def check_output_path(path: str) -> Tuple[str, str]:
    """Validate an output path before anything is written.

    The parent directory must exist and be a real directory (not a symlink), and an
    existing target must be a regular file (not a symlink, FIFO, device or directory).
    Returns (directory, basename).
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        raise YankError("invalid output file path")
    norm_dir = os.path.dirname(path) or "."
    base_name = os.path.basename(path)
    if not base_name or base_name in (".", ".."):
        raise YankError("invalid output filename")
    try:
        dst = os.lstat(norm_dir)
    except OSError as exc:
        raise YankError("output directory does not exist") from exc
    if not stat.S_ISDIR(dst.st_mode):
        raise YankError("output directory is not a real directory")
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return norm_dir, base_name
    except OSError as exc:
        raise YankError("failed to stat output path") from exc
    if not stat.S_ISREG(lst.st_mode):
        raise YankError("refusing to overwrite symlink or non-regular file")
    return norm_dir, base_name


def atomic_write_bytes(path: str, data: bytes) -> None:
    norm_dir, base_name = check_output_path(path)

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    tmp_path: Optional[str] = None
    fd: Optional[int] = None
    for attempt in range(MAX_TEMP_ATTEMPTS):
        candidate = os.path.join(norm_dir, f".tmp.{base_name}.{attempt}")
        try:
            fd = os.open(candidate, flags, 0o600)
            tmp_path = candidate
            break
        except FileExistsError:
            continue
        except OSError as exc:
            raise YankError("failed to create temporary file") from exc
    if fd is None or tmp_path is None:
        raise YankError("exhausted temporary file creation attempts")

    try:
        total = 0
        view = memoryview(data)
        max_loops = (len(data) // READ_CHUNK_BYTES) + 2
        for _ in range(max_loops):
            if total >= len(data):
                break
            written = os.write(fd, view[total : total + READ_CHUNK_BYTES])
            if written <= 0:
                raise YankError("short write to temporary file")
            total += written
        if total != len(data):
            raise YankError("short write to temporary file")
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(tmp_path, path)
        tmp_path = None
        _fsync_dir(norm_dir)
    except OSError as exc:
        raise YankError("failed atomic write") from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _fsync_dir(dir_path: str) -> None:
    """Make the rename durable: fsync the directory that holds the renamed file."""
    dfd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _check_text(value: str) -> None:
    # A lone surrogate (from a JSON escape such as \ud800) cannot be written as UTF-8.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise YankError("JSON string is not encodable as UTF-8") from exc


def _reject_constant(name: str) -> Any:
    raise YankError(f"non-finite JSON number {name} is not allowed")


def _parse_float_exact(literal: str) -> float:
    # The rewritten page must keep every value equal; refuse non-finite floats and
    # literals that a binary float cannot represent exactly in value.
    if len(literal) > MAX_NUMBER_LITERAL_LEN:
        raise YankError("JSON number literal too long")
    value = float(literal)
    if not math.isfinite(value) or decimal.Decimal(literal) != decimal.Decimal(repr(value)):
        raise YankError("JSON number cannot be preserved exactly")
    return value


def _parse_int_bounded(literal: str) -> int:
    if len(literal) > MAX_NUMBER_LITERAL_LEN:
        raise YankError("JSON number literal too long")
    return int(literal)


def _no_dup_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if not isinstance(k, str) or len(k) > MAX_STRING_LEN or "\x00" in k:
            raise YankError("invalid JSON key")
        _check_text(k)
        if k in out:
            raise YankError(f"duplicate JSON key: {k}")
        out[k] = v
    return out


def _validate_json_tree(obj: Any, max_depth: int) -> None:
    stack: List[Tuple[Any, int]] = [(obj, 0)]
    while stack:
        curr, depth = stack.pop()
        if depth > max_depth:
            raise YankError("JSON nesting depth exceeded")
        if isinstance(curr, str):
            if len(curr) > MAX_STRING_LEN or "\x00" in curr:
                raise YankError("JSON string exceeds length cap or contains NUL")
            _check_text(curr)
        elif isinstance(curr, dict):
            for v in curr.values():
                stack.append((v, depth + 1))
        elif isinstance(curr, list):
            for item in curr:
                stack.append((item, depth + 1))


def load_json_bounded(raw: bytes, max_bytes: int) -> Any:
    if len(raw) > max_bytes:
        raise YankError("JSON payload exceeds size cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise YankError("invalid UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_no_dup_hook,
            parse_constant=_reject_constant,
            parse_float=_parse_float_exact,
            parse_int=_parse_int_bounded,
        )
    except YankError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, decimal.InvalidOperation) as exc:
        raise YankError("malformed JSON") from exc
    _validate_json_tree(parsed, MAX_JSON_DEPTH)
    return parsed


def _extract_version_from_file(file_entry: Dict[str, Any], project_name: str) -> Optional[str]:
    if "version" in file_entry and isinstance(file_entry["version"], str):
        return file_entry["version"]
    filename = file_entry["filename"]
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) >= 5:
            return parts[1]
    for ext in _SDIST_EXTS:
        if filename.endswith(ext):
            stem = filename[: -len(ext)]
            norm_stem = _PEP503_RE.sub("-", stem).lower()
            norm_proj = _PEP503_RE.sub("-", project_name).lower()
            prefix = norm_proj + "-"
            if norm_stem.startswith(prefix) and len(stem) > len(prefix):
                return stem[len(prefix) :]
            if "-" in stem:
                return stem.rsplit("-", 1)[1]
    return None


def _validate_file_entry(entry: Any) -> None:
    if not isinstance(entry, dict):
        raise YankError("file entry must be a JSON object")
    for req in ("filename", "url", "hashes"):
        if req not in entry:
            raise YankError(f"file entry missing required field {req}")
    if not isinstance(entry["filename"], str) or not entry["filename"]:
        raise YankError("invalid filename in file entry")
    if not isinstance(entry["url"], str) or not entry["url"]:
        raise YankError("invalid url in file entry")
    hashes = entry["hashes"]
    if not isinstance(hashes, dict):
        raise YankError("hashes must be a JSON object")
    for hk, hv in hashes.items():
        if not isinstance(hk, str) or not isinstance(hv, str):
            raise YankError("hash key and value must be strings")
    if "requires-python" in entry and entry["requires-python"] is not None:
        if not isinstance(entry["requires-python"], str):
            raise YankError("requires-python must be string or null")
    if "yanked" in entry:
        y = entry["yanked"]
        if not isinstance(y, (bool, str)):
            raise YankError("yanked field must be boolean or string")


def rewrite_simple_index(
    page_data: Any,
    yanks_data: Any,
    cutoff: str,
) -> Tuple[Dict[str, Any], Dict[str, List[str]]]:
    cutoff_ns = parse_rfc3339_ns(cutoff)
    if not isinstance(page_data, dict):
        raise YankError("page root must be a JSON object")
    if "meta" not in page_data or "name" not in page_data or "files" not in page_data:
        raise YankError("page missing required PEP 691 top-level keys")
    meta = page_data["meta"]
    if not isinstance(meta, dict) or not isinstance(meta.get("api-version"), str):
        raise YankError("invalid PEP 691 meta object")
    proj_name = page_data["name"]
    if not isinstance(proj_name, str) or not proj_name:
        raise YankError("invalid project name")
    files_list = page_data["files"]
    if not isinstance(files_list, list) or len(files_list) > MAX_FILES_COUNT:
        raise YankError("invalid or oversized files array")
    if "versions" in page_data:
        if not isinstance(page_data["versions"], list):
            raise YankError("versions field must be a list when present")
        for v in page_data["versions"]:
            if not isinstance(v, str):
                raise YankError("versions elements must be strings")

    if not isinstance(yanks_data, dict) or len(yanks_data) > MAX_YANKS_COUNT:
        raise YankError("yanks table must be a JSON object within size cap")
    parsed_yanks: Dict[str, int] = {}
    for fname, ytime in yanks_data.items():
        if not isinstance(fname, str) or not fname:
            raise YankError("invalid filename in yanks table")
        parsed_yanks[fname] = parse_rfc3339_ns(ytime)

    dropped_after_cutoff: List[str] = []
    unyanked_after_cutoff: List[str] = []
    unyanked_unknown_date: List[str] = []
    undated: List[str] = []
    kept_files: List[Dict[str, Any]] = []
    kept_versions: Set[str] = set()

    for idx in range(len(files_list)):
        fentry = files_list[idx]
        _validate_file_entry(fentry)
        fname = fentry["filename"]
        upload_time = fentry.get("upload-time")
        if upload_time is not None:
            upload_ns = parse_rfc3339_ns(upload_time)
            if upload_ns > cutoff_ns:
                dropped_after_cutoff.append(fname)
                continue
        else:
            undated.append(fname)

        new_entry = dict(fentry)
        yanked_val = new_entry.get("yanked", False)
        is_yanked = (yanked_val is True) or (isinstance(yanked_val, str) and yanked_val != "")
        if isinstance(yanked_val, str) and yanked_val == "":
            is_yanked = True

        if is_yanked:
            if fname in parsed_yanks:
                yank_ns = parsed_yanks[fname]
                if yank_ns <= cutoff_ns:
                    pass
                else:
                    new_entry["yanked"] = False
                    unyanked_after_cutoff.append(fname)
            else:
                new_entry["yanked"] = False
                unyanked_unknown_date.append(fname)

        kept_files.append(new_entry)
        ver = _extract_version_from_file(new_entry, proj_name)
        if ver is not None:
            kept_versions.add(ver)

    rewritten_page: Dict[str, Any] = {}
    for k, v in page_data.items():
        if k == "files":
            rewritten_page["files"] = kept_files
        elif k == "versions":
            # Rule 3: PEP 440 sort is not required; versions are sorted as plain strings.
            rewritten_page["versions"] = sorted(kept_versions)
        else:
            rewritten_page[k] = v

    report = {
        "dropped_after_cutoff": sorted(dropped_after_cutoff),
        "unyanked_after_cutoff": sorted(unyanked_after_cutoff),
        "unyanked_unknown_date": sorted(unyanked_unknown_date),
        "undated": sorted(undated),
    }
    return rewritten_page, report


def run_yank_rewrite_from_paths(
    page_path: str,
    yanks_path: str,
    cutoff: str,
    out_path: str,
    report_path: str,
) -> Tuple[Dict[str, Any], Dict[str, List[str]]]:
    page_raw = safe_read_bytes(page_path, MAX_PAGE_BYTES)
    yanks_raw = safe_read_bytes(yanks_path, MAX_YANKS_BYTES)
    page_json = load_json_bounded(page_raw, MAX_PAGE_BYTES)
    yanks_json = load_json_bounded(yanks_raw, MAX_YANKS_BYTES)
    rewritten_page, report = rewrite_simple_index(page_json, yanks_json, cutoff)

    try:
        page_bytes = json.dumps(
            rewritten_page, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        report_bytes = json.dumps(
            report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise YankError("rewritten page cannot be encoded as canonical JSON") from exc

    # Validate both output paths before writing either, so a bad --report never leaves a
    # freshly written --out behind, and refuse one file for both outputs.
    out_dir, out_base = check_output_path(out_path)
    rep_dir, rep_base = check_output_path(report_path)
    same_name = (os.path.abspath(out_dir), out_base) == (os.path.abspath(rep_dir), rep_base)
    try:
        same_file = os.path.samefile(out_path, report_path)
    except OSError:
        same_file = False
    if same_name or same_file:
        raise YankError("--out and --report must be different files")

    atomic_write_bytes(out_path, page_bytes)
    atomic_write_bytes(report_path, report_bytes)
    return rewritten_page, report
