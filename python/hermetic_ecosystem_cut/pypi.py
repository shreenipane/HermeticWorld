"""Offline PyPI upload-time admission and deterministic simple index rendering.

Accept PEP 691/700 project JSON or the PyPI project JSON API. Both return a
minimal simple JSON page and PEP 503 HTML with identical artifact admission.
Source URLs, serials, descriptions, provenance and current yank reasons are not
historical evidence and never enter either page. Publication and digest checking
remain the caller's responsibility; no network or filesystem access occurs here.
"""

from dataclasses import dataclass
import html
import re

from hermetic_npm_cut.cut import HermeticNpmCutError, parse_json_bytes
from hermetic_pytest_env.scan import MAX_VERSION_BYTES, normalize_pep503, parse_pep440

from .cut import CutError, CutReport, _bytes, _encode, _time

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_FILE_RECORD_BYTES = 256 * 1024
MAX_FILES = 20_000
MAX_RELEASES = 20_000
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_NAME_BYTES = 128
MAX_FILENAME_BYTES = 255
MAX_REQUIRES_PYTHON_BYTES = 4096
MAX_ARTIFACT_BYTES = 1 << 40
_UPLOAD_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")


@dataclass(frozen=True)
class PyPIIndex:
    simple_json: bytes
    simple_html: bytes


def _text(value, cap: int) -> str:
    if (type(value) is not str or not value or len(value) > cap
            or not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CutError("invalid PyPI text field")
    return value


def _name(value) -> str:
    value = _text(value, MAX_NAME_BYTES)
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", value) is None:
        raise CutError("invalid PyPI project name")
    return normalize_pep503(value)


def _version(value):
    value = _text(value, MAX_VERSION_BYTES)
    parsed = parse_pep440(value)
    if parsed is None or any(char.isspace() for char in value):
        raise CutError("invalid PyPI version")
    return parsed.sort_key()


def _filename(value, project: str) -> tuple[str, str]:
    value = _text(value, MAX_FILENAME_BYTES)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]*", value) is None:
        raise CutError("unsafe PyPI filename")
    if value.endswith(".whl"):
        parts = value.removesuffix(".whl").split("-")
        if len(parts) not in (5, 6):
            raise CutError("invalid wheel filename")
        distribution, version, *tags = parts
        if (any(re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*", tag) is None
                for tag in tags[-3:])
                or (len(tags) == 4 and re.fullmatch(r"[0-9][A-Za-z0-9_]*", tags[0]) is None)):
            raise CutError("invalid wheel tags or build")
    else:
        suffix = next((ext for ext in (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz")
                       if value.endswith(ext)), None)
        if suffix is None:
            raise CutError("unsupported PyPI distribution file")
        stem = value.removesuffix(suffix)
        # Match the known project prefix, rather than splitting at the final
        # hyphen: legacy PEP 440 versions may contain hyphens themselves.
        prefix = "[-_.]+".join(re.escape(part) for part in project.split("-"))
        match = re.fullmatch(f"({prefix})-(.+)", stem, flags=re.IGNORECASE | re.ASCII)
        if match is None:
            raise CutError("invalid source distribution filename")
        distribution, version = match.groups()
    if _name(distribution) != project:
        raise CutError("distribution project mismatch")
    _version(version)
    return value, version


def _project(raw: bytes) -> dict:
    _bytes(raw, MAX_INPUT_BYTES)
    try:
        value = parse_json_bytes(raw, MAX_INPUT_BYTES)
    except HermeticNpmCutError:
        raise CutError("invalid PyPI JSON") from None
    if type(value) is not dict:
        raise CutError("PyPI project must be an object")
    return value


def _admit(project: str, files, boundary: int, *, legacy: bool) -> tuple[PyPIIndex, CutReport]:
    admitted = {}
    versions = set()
    seen = set()
    future = []
    unknown = []
    yank_unknown = []
    total_records = 0
    for entry, release in files:
        total_records += 1
        if total_records > MAX_FILES:
            raise CutError("PyPI file count cap exceeded")
        if type(entry) is not dict or len(_encode(entry)) > MAX_FILE_RECORD_BYTES:
            raise CutError("invalid or oversized PyPI file record")
        filename, version = _filename(entry.get("filename"), project)
        if release is not None and _version(release) != _version(version):
            raise CutError("release and filename version mismatch")
        if filename in seen:
            raise CutError("duplicate PyPI filename")
        seen.add(filename)
        hashes = entry.get("digests" if legacy else "hashes")
        digest = hashes.get("sha256") if type(hashes) is dict else None
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise CutError("invalid PyPI artifact digest")
        size = entry.get("size")
        if "size" in entry and (type(size) is not int or not 0 <= size <= MAX_ARTIFACT_BYTES):
            raise CutError("invalid PyPI artifact size")
        requires = entry.get("requires_python" if legacy else "requires-python")
        if requires not in (None, ""):
            _text(requires, MAX_REQUIRES_PYTHON_BYTES)
        yanked = entry.get("yanked", False)
        if type(yanked) not in (bool, str):
            raise CutError("invalid PyPI yank flag")
        date = entry.get("upload_time_iso_8601" if legacy else "upload-time")
        # No fallback to naive upload_time, filename, release date or host mtime.
        if date is None:
            unknown.append(filename)
            continue
        if type(date) is not str or len(date) > 32 or _UPLOAD_TIME.fullmatch(date) is None:
            raise CutError("invalid PyPI UTC upload timestamp")
        timestamp = _time(date)
        if timestamp > boundary:
            future.append(filename)
            continue
        if size is None:
            raise CutError("admitted PyPI file requires a size")
        kept = {"filename": filename, "url": f"/files/{digest}/{filename}",
                "hashes": {"sha256": digest}, "size": size,
                "upload-time": date, "yanked": False}
        if requires is not None:
            kept["requires-python"] = requires
        if yanked is not False:
            yank_unknown.append(filename)
        admitted[filename] = kept
        versions.add(version)
    ordered = [admitted[name] for name in sorted(admitted)]
    json_page = _encode({"meta": {"api-version": "1.1"}, "name": project,
                         "versions": sorted(versions), "files": ordered})
    if len(json_page) > MAX_OUTPUT_BYTES:
        raise CutError("PyPI output byte cap exceeded")
    chunks = ['<!DOCTYPE html>\n<html><head><meta name="pypi:repository-version" '
              'content="1.0"></head><body>\n']
    output_size = len(json_page) + len(chunks[0])
    for entry in ordered:
        url = entry["url"] + "#sha256=" + entry["hashes"]["sha256"]
        attrs = f'href="{html.escape(url, quote=True)}"'
        if "requires-python" in entry:
            attrs += f' data-requires-python="{html.escape(entry["requires-python"], quote=True)}"'
        line = f'<a {attrs}>{html.escape(entry["filename"])}</a>\n'
        output_size += len(line)
        if output_size > MAX_OUTPUT_BYTES:
            raise CutError("PyPI output byte cap exceeded")
        chunks.append(line)
    ending = '</body></html>\n'
    if output_size + len(ending) > MAX_OUTPUT_BYTES:
        raise CutError("PyPI output byte cap exceeded")
    chunks.append(ending)
    report = CutReport(tuple(sorted(admitted)), tuple(sorted(future)), tuple(sorted(unknown)),
                       tuple(sorted(yank_unknown)))
    return PyPIIndex(json_page, "".join(chunks).encode("ascii")), report


def cut_pypi_simple(raw: bytes, cutoff: str) -> tuple[PyPIIndex, CutReport]:
    """Admit PEP 691/700 project files at or before cutoff; omit undated files."""
    boundary = _time(cutoff)
    page = _project(raw)
    meta = page.get("meta")
    if (type(meta) is not dict or meta.get("api-version") not in
            ("1.0", "1.1", "1.2", "1.3", "1.4")):
        raise CutError("unsupported PyPI simple API version")
    project = _name(page.get("name"))
    files = page.get("files")
    if type(files) is not list or len(files) > MAX_FILES:
        raise CutError("invalid or oversized PyPI files array")
    if "versions" in page:
        versions = page["versions"]
        if type(versions) is not list or len(versions) > MAX_RELEASES:
            raise CutError("invalid or oversized PyPI version array")
        for version in versions:
            _version(version)
    return _admit(project, ((entry, None) for entry in files), boundary, legacy=False)


def cut_pypi_json(raw: bytes, cutoff: str) -> tuple[PyPIIndex, CutReport]:
    """Convert the project JSON API's releases to cutoff-filtered simple pages.

Current info/urls/vulnerabilities are deliberately not copied. Never substitute
those current-version files for the per-release inventory.
    """
    boundary = _time(cutoff)
    page = _project(raw)
    info = page.get("info")
    if type(info) is not dict:
        raise CutError("invalid PyPI project info")
    project = _name(info.get("name"))
    releases = page.get("releases")
    if type(releases) is not dict or len(releases) > MAX_RELEASES:
        raise CutError("invalid or oversized PyPI releases")
    count = 0
    for version, files in releases.items():
        _version(version)
        if type(files) is not list:
            raise CutError("invalid PyPI release file array")
        count += len(files)
        if count > MAX_FILES:
            raise CutError("PyPI file count cap exceeded")
    return _admit(project, ((entry, version) for version, files in releases.items()
                            for entry in files), boundary, legacy=True)
