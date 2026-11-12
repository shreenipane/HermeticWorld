
import calendar

import datetime

import json

import os

import re

import stat

from typing import Any, Dict, List, Optional, Tuple



from hermetic_d5b.model import (

    D5bError,

    ECOSYSTEMS,

    Exemption,

    InventoryPackage,

    MAX_EXEMPTIONS,

    MAX_EXEMPTIONS_BYTES,

    MAX_FILES_PER_VERSION,

    MAX_INVENTORY_BYTES,

    MAX_JSON_DEPTH,

    MAX_METADATA_BYTES,

    MAX_METADATA_PACKAGES_PER_ECOSYSTEM,

    MAX_PACKAGES,

    MAX_STRING_LEN,

    MAX_VERSIONS_PER_PACKAGE,

    MODES,

    PackageReportEntry,

    READ_CHUNK_BYTES,

)



_PEP503_RE = re.compile(r"[-_.]+")

_RFC3339_RE = re.compile(

    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"

)

_NS_PER_SEC = 1_000_000_000

_NS_PER_MS = 1_000_000

_MAX_TIMESTAMP_MS = 253402300799000





def normalize_pypi_name(name: str) -> str:

    if not isinstance(name, str) or not name or len(name) > MAX_STRING_LEN:

        raise D5bError("invalid package name")

    norm = _PEP503_RE.sub("-", name).lower()

    if not norm or norm == "-":

        raise D5bError("invalid pypi package name after normalisation")

    return norm





def parse_rfc3339_ns(value: str) -> int:

    if not isinstance(value, str) or len(value) > 64:

        raise D5bError("invalid RFC3339 timestamp type or length")

    m = _RFC3339_RE.match(value)

    if not m:

        raise D5bError("malformed RFC3339 UTC timestamp")

    year, month, day, hour, minute, second = (

        int(m.group(1)),

        int(m.group(2)),

        int(m.group(3)),

        int(m.group(4)),

        int(m.group(5)),

        int(m.group(6)),

    )

    frac = m.group(7) or ""

    if year < 1970 or year > 9999:

        raise D5bError("timestamp year out of range")

    try:

        dt = datetime.date(year, month, day)

    except ValueError as exc:

        raise D5bError("invalid calendar date in timestamp") from exc

    if hour > 23 or minute > 59 or second > 59:

        raise D5bError("invalid time component in timestamp")

    sec_epoch = calendar.timegm((dt.year, dt.month, dt.day, hour, minute, second, 0, 0, 0))

    ns_frac = int(frac.ljust(9, "0")) if frac else 0

    return sec_epoch * _NS_PER_SEC + ns_frac





def format_ns_as_rfc3339(ns: int) -> str:

    sec = ns // _NS_PER_SEC

    rem_ns = ns % _NS_PER_SEC

    tm = time_tuple_utc(sec)

    base = (

        f"{tm[0]:04d}-{tm[1]:02d}-{tm[2]:02d}T"

        f"{tm[3]:02d}:{tm[4]:02d}:{tm[5]:02d}"

    )

    if rem_ns == 0:

        return base + "Z"

    ms = rem_ns // _NS_PER_MS

    if rem_ns % _NS_PER_MS == 0:

        return f"{base}.{ms:03d}Z"

    return f"{base}.{rem_ns:09d}".rstrip("0") + "Z"





def time_tuple_utc(sec: int) -> Tuple[int, int, int, int, int, int]:

    dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)

    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)





def safe_read_bytes(path: str, max_bytes: int) -> bytes:

    if not isinstance(path, str) or not path or "\x00" in path:

        raise D5bError("invalid file path")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

    try:

        fd = os.open(path, flags)

    except OSError as exc:

        raise D5bError("failed to open input file safely") from exc

    try:

        st = os.fstat(fd)

        if not stat.S_ISREG(st.st_mode):

            raise D5bError("input path is not a regular file")

        if st.st_size > max_bytes:

            raise D5bError("input file exceeds size cap")

        chunks: List[bytes] = []

        total = 0

        max_loops = (max_bytes // READ_CHUNK_BYTES) + 2

        for _ in range(max_loops):

            chunk = os.read(fd, READ_CHUNK_BYTES)

            if not chunk:

                break

            total += len(chunk)

            if total > max_bytes:

                raise D5bError("input file grew beyond size cap during read")

            chunks.append(chunk)

        else:

            raise D5bError("read loop bound exceeded")

        return b"".join(chunks)

    except OSError as exc:

        raise D5bError("failed reading input file") from exc

    finally:

        try:

            os.close(fd)

        except OSError:

            pass





def _no_duplicate_keys_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:

    out: Dict[str, Any] = {}

    for k, v in pairs:

        if not isinstance(k, str) or len(k) > MAX_STRING_LEN:

            raise D5bError("invalid or oversized JSON object key")

        if k in out:

            raise D5bError(f"duplicate JSON key: {k}")

        out[k] = v

    return out





def _validate_json_depth_and_strings(obj: Any, max_depth: int) -> None:

    stack: List[Tuple[Any, int]] = [(obj, 0)]

    while stack:

        curr, depth = stack.pop()

        if depth > max_depth:

            raise D5bError("JSON nesting depth exceeds cap")

        if isinstance(curr, str):

            if len(curr) > MAX_STRING_LEN or "\x00" in curr:

                raise D5bError("JSON string exceeds length cap or contains NUL")

        elif isinstance(curr, dict):

            for k, v in curr.items():

                if not isinstance(k, str) or len(k) > MAX_STRING_LEN or "\x00" in k:

                    raise D5bError("invalid JSON key")

                stack.append((v, depth + 1))

        elif isinstance(curr, list):

            for item in curr:

                stack.append((item, depth + 1))





def load_json_bounded(raw: bytes, max_bytes: int, max_depth: int = MAX_JSON_DEPTH) -> Any:

    if len(raw) > max_bytes:

        raise D5bError("JSON payload exceeds size cap")

    try:

        text = raw.decode("utf-8")

    except UnicodeDecodeError as exc:

        raise D5bError("invalid UTF-8 in JSON input") from exc

    try:

        parsed = json.loads(text, object_pairs_hook=_no_duplicate_keys_hook)

    except D5bError:

        raise

    except (json.JSONDecodeError, RecursionError, ValueError) as exc:

        raise D5bError("malformed JSON input") from exc

    _validate_json_depth_and_strings(parsed, max_depth)

    return parsed





def parse_inventory(data: Any) -> List[InventoryPackage]:

    if not isinstance(data, dict):

        raise D5bError("inventory root must be a JSON object")

    if set(data.keys()) != {"packages"}:

        raise D5bError("inventory contains unknown or missing root fields")

    pkgs_raw = data["packages"]

    if not isinstance(pkgs_raw, list):

        raise D5bError("inventory 'packages' must be a list")

    if len(pkgs_raw) > MAX_PACKAGES:

        raise D5bError("inventory package count exceeds MAX_PACKAGES")

    allowed_fields = {"ecosystem", "name", "version", "file"}

    result: List[InventoryPackage] = []

    for idx in range(len(pkgs_raw)):

        entry = pkgs_raw[idx]

        if not isinstance(entry, dict):

            raise D5bError("package entry must be an object")

        if set(entry.keys()) != allowed_fields:

            raise D5bError("package entry has missing or unknown fields")

        eco = entry["ecosystem"]

        name = entry["name"]

        version = entry["version"]

        file_val = entry["file"]

        if eco not in ECOSYSTEMS:

            raise D5bError("unsupported ecosystem in inventory")

        if not isinstance(name, str) or not name:

            raise D5bError("invalid package name")

        if not isinstance(version, str) or not version:

            raise D5bError("invalid package version")

        if file_val is not None and (not isinstance(file_val, str) or not file_val):

            raise D5bError("invalid package file field")

        norm_name = normalize_pypi_name(name) if eco == "pypi" else name

        result.append(

            InventoryPackage(

                ecosystem=eco,

                name=norm_name,

                version=version,

                file=file_val,

            )

        )

    return result





def parse_exemptions(data: Any) -> Dict[Tuple[str, str, str], Exemption]:

    if data is None:

        return {}

    if isinstance(data, dict):

        if set(data.keys()) != {"exemptions"}:

            raise D5bError("exemptions object contains unknown fields")

        items = data["exemptions"]

    elif isinstance(data, list):

        items = data

    else:

        raise D5bError("exemptions must be a list or {'exemptions': [...]}")

    if not isinstance(items, list) or len(items) > MAX_EXEMPTIONS:

        raise D5bError("exemptions list invalid or exceeds cap")

    allowed = {"ecosystem", "name", "version", "reason"}

    out: Dict[Tuple[str, str, str], Exemption] = {}

    for idx in range(len(items)):

        item = items[idx]

        if not isinstance(item, dict) or set(item.keys()) != allowed:

            raise D5bError("invalid exemption entry fields")

        eco = item["ecosystem"]

        name = item["name"]

        version = item["version"]

        reason = item["reason"]

        if eco not in ECOSYSTEMS:

            raise D5bError("invalid ecosystem in exemption")

        if not isinstance(name, str) or not name:

            raise D5bError("invalid name in exemption")

        if not isinstance(version, str) or not version:

            raise D5bError("invalid version in exemption")

        if not isinstance(reason, str) or not reason:

            raise D5bError("invalid reason in exemption")

        norm_name = normalize_pypi_name(name) if eco == "pypi" else name

        key = (eco, norm_name, version)

        if key in out:

            raise D5bError("duplicate exemption entry")

        out[key] = Exemption(ecosystem=eco, name=norm_name, version=version, reason=reason)

    return out





def validate_metadata(data: Any) -> Dict[str, Any]:

    if not isinstance(data, dict):

        raise D5bError("metadata root must be an object")

    unknown_ecos = set(data.keys()) - set(ECOSYSTEMS)

    if unknown_ecos:

        raise D5bError("metadata contains unknown top-level ecosystem keys")

    validated: Dict[str, Any] = {eco: {} for eco in ECOSYSTEMS}



    if "pypi" in data:

        pypi_map = data["pypi"]

        if not isinstance(pypi_map, dict) or len(pypi_map) > MAX_METADATA_PACKAGES_PER_ECOSYSTEM:

            raise D5bError("invalid pypi metadata map")

        norm_pypi: Dict[str, Dict[str, Dict[str, Tuple[int, str]]]] = {}

        for pkg_name, ver_map in pypi_map.items():

            norm_pkg = normalize_pypi_name(pkg_name)

            if norm_pkg in norm_pypi:

                raise D5bError("colliding normalised pypi package names in metadata")

            if not isinstance(ver_map, dict) or len(ver_map) > MAX_VERSIONS_PER_PACKAGE:

                raise D5bError("invalid pypi version map")

            norm_pypi[norm_pkg] = {}

            for ver, file_map in ver_map.items():

                if not isinstance(ver, str) or not ver:

                    raise D5bError("invalid pypi version key")

                if not isinstance(file_map, dict) or len(file_map) > MAX_FILES_PER_VERSION:

                    raise D5bError("invalid pypi file map")

                parsed_files: Dict[str, Tuple[int, str]] = {}

                for fname, ts_str in file_map.items():

                    if not isinstance(fname, str) or not fname:

                        raise D5bError("invalid pypi filename")

                    ts_ns = parse_rfc3339_ns(ts_str)

                    parsed_files[fname] = (ts_ns, ts_str)

                norm_pypi[norm_pkg][ver] = parsed_files

        validated["pypi"] = norm_pypi



    if "conda" in data:

        conda_map = data["conda"]

        if not isinstance(conda_map, dict) or len(conda_map) > MAX_METADATA_PACKAGES_PER_ECOSYSTEM:

            raise D5bError("invalid conda metadata map")

        parsed_conda: Dict[str, Dict[str, Optional[Tuple[int, str]]]] = {}

        for pkg_name, ver_map in conda_map.items():

            if not isinstance(pkg_name, str) or not pkg_name:

                raise D5bError("invalid conda package name")

            if not isinstance(ver_map, dict) or len(ver_map) > MAX_VERSIONS_PER_PACKAGE:

                raise D5bError("invalid conda version map")

            parsed_conda[pkg_name] = {}

            for ver, ts_ms in ver_map.items():

                if not isinstance(ver, str) or not ver:

                    raise D5bError("invalid conda version")

                if ts_ms is None:

                    parsed_conda[pkg_name][ver] = None

                else:

                    if isinstance(ts_ms, bool) or not isinstance(ts_ms, int):

                        raise D5bError("conda timestamp must be integer milliseconds or null")

                    if ts_ms < 0 or ts_ms > _MAX_TIMESTAMP_MS:

                        raise D5bError("conda timestamp out of range")

                    ns = ts_ms * _NS_PER_MS

                    parsed_conda[pkg_name][ver] = (ns, format_ns_as_rfc3339(ns))

        validated["conda"] = parsed_conda



    for eco in ("npm", "crates"):

        if eco in data:

            eco_map = data[eco]

            if not isinstance(eco_map, dict) or len(eco_map) > MAX_METADATA_PACKAGES_PER_ECOSYSTEM:

                raise D5bError(f"invalid {eco} metadata map")

            parsed_eco: Dict[str, Dict[str, Tuple[int, str]]] = {}

            for pkg_name, ver_map in eco_map.items():

                if not isinstance(pkg_name, str) or not pkg_name:

                    raise D5bError(f"invalid {eco} package name")

                if not isinstance(ver_map, dict) or len(ver_map) > MAX_VERSIONS_PER_PACKAGE:

                    raise D5bError(f"invalid {eco} version map")

                parsed_eco[pkg_name] = {}

                for ver, ts_str in ver_map.items():

                    if not isinstance(ver, str) or not ver:

                        raise D5bError(f"invalid {eco} version")

                    ts_ns = parse_rfc3339_ns(ts_str)

                    parsed_eco[pkg_name][ver] = (ts_ns, ts_str)

            validated[eco] = parsed_eco



    return validated





def _lookup_release_time(

    pkg: InventoryPackage, metadata: Dict[str, Any]

) -> Optional[Tuple[int, str]]:

    eco = pkg.ecosystem

    if eco == "pypi":

        ver_map = metadata["pypi"].get(pkg.name)

        if not ver_map or pkg.version not in ver_map:

            return None

        file_map: Dict[str, Tuple[int, str]] = ver_map[pkg.version]

        if not file_map:

            return None

        if pkg.file is not None:

            return file_map.get(pkg.file)

        # Rule 1 rationale: When the inventory does not record which distribution

        # file was installed (file is null), we use the EARLIEST upload time among

        # all files for that version. If at least one artifact for that version was

        # published on or before the cutoff, the version itself existed in the world

        # at the cutoff; only if the earliest artifact was uploaded after the cutoff

        # could that version not possibly have existed at the cutoff.

        earliest_fname = min(file_map.keys(), key=lambda fn: (file_map[fn][0], fn))

        return file_map[earliest_fname]



    if eco == "conda":

        ver_map = metadata["conda"].get(pkg.name)

        if not ver_map or pkg.version not in ver_map:

            return None

        return ver_map[pkg.version]



    if eco in ("npm", "crates"):

        ver_map = metadata[eco].get(pkg.name)

        if not ver_map or pkg.version not in ver_map:

            return None

        return ver_map[pkg.version]



    return None





def evaluate_inventory(

    inventory_data: Any,

    metadata_data: Any,

    cutoff: str,

    mode: str,

    exemptions_data: Any = None,

) -> Dict[str, Any]:

    if mode not in MODES:

        raise D5bError("invalid mode; expected 'strict' or 'repo_only'")

    cutoff_ns = parse_rfc3339_ns(cutoff)

    packages = parse_inventory(inventory_data)

    metadata = validate_metadata(metadata_data)

    exemptions = parse_exemptions(exemptions_data)



    newer_entries: List[PackageReportEntry] = []

    unknown_entries: List[PackageReportEntry] = []

    exempt_entries: List[PackageReportEntry] = []

    ok_count = 0



    for idx in range(len(packages)):

        pkg = packages[idx]

        ex_key = (pkg.ecosystem, pkg.name, pkg.version)

        if ex_key in exemptions:

            ex = exemptions[ex_key]

            exempt_entries.append(

                PackageReportEntry(

                    ecosystem=pkg.ecosystem,

                    name=pkg.name,

                    version=pkg.version,

                    file=pkg.file,

                    release_time=None,

                    reason=ex.reason,

                )

            )

            continue



        rel = _lookup_release_time(pkg, metadata)

        if rel is None:

            unknown_entries.append(

                PackageReportEntry(

                    ecosystem=pkg.ecosystem,

                    name=pkg.name,

                    version=pkg.version,

                    file=pkg.file,

                    release_time=None,

                    reason=None,

                )

            )

            continue



        rel_ns, rel_str = rel

        if rel_ns > cutoff_ns:

            newer_entries.append(

                PackageReportEntry(

                    ecosystem=pkg.ecosystem,

                    name=pkg.name,

                    version=pkg.version,

                    file=pkg.file,

                    release_time=rel_str,

                    reason=None,

                )

            )

        else:

            ok_count += 1



    newer_entries.sort(key=lambda e: (e.ecosystem, e.name, e.version, e.file or ""))

    unknown_entries.sort(key=lambda e: (e.ecosystem, e.name, e.version, e.file or ""))

    exempt_entries.sort(key=lambda e: (e.ecosystem, e.name, e.version, e.file or ""))



    has_issues = bool(newer_entries or unknown_entries)

    if not has_issues:

        result_str = "pass"

    elif mode == "strict":

        result_str = "gate"

    else:

        result_str = "pass_with_warnings"



    return {

        "mode": mode,

        "cutoff": cutoff,

        "result": result_str,

        "newer": [e.to_dict(include_release_time=True) for e in newer_entries],

        "unknown": [e.to_dict() for e in unknown_entries],

        "exempt": [e.to_dict(include_reason=True) for e in exempt_entries],

        "counts": {

            "total": len(packages),

            "ok": ok_count,

            "newer": len(newer_entries),

            "unknown": len(unknown_entries),

            "exempt": len(exempt_entries),

        },

    }





def run_check_from_paths(

    inventory_path: str,

    metadata_path: str,

    cutoff: str,

    mode: str,

    exemptions_path: Optional[str] = None,

) -> Dict[str, Any]:

    inv_raw = safe_read_bytes(inventory_path, MAX_INVENTORY_BYTES)

    meta_raw = safe_read_bytes(metadata_path, MAX_METADATA_BYTES)

    inv_json = load_json_bounded(inv_raw, MAX_INVENTORY_BYTES)

    meta_json = load_json_bounded(meta_raw, MAX_METADATA_BYTES)

    ex_json = None

    if exemptions_path is not None:

        ex_raw = safe_read_bytes(exemptions_path, MAX_EXEMPTIONS_BYTES)

        ex_json = load_json_bounded(ex_raw, MAX_EXEMPTIONS_BYTES)

    return evaluate_inventory(inv_json, meta_json, cutoff, mode, ex_json)

