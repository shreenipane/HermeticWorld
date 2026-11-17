"""Cutoff filtering, PEP 700 upload-time validation, and yank status rewriting."""

from __future__ import annotations

import calendar
import datetime
import html
from html.parser import HTMLParser
import json
import re
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from hermetic_pkgrec.constants import (
    MAX_FILENAME_BYTES,
    MAX_FILES_PER_PROJECT,
    MAX_INDEX_RESPONSE_BYTES,
    MAX_PROJECT_NAME_BYTES,
    SHA256_HEX_LEN,
)
from hermetic_pkgrec.errors import CutoffError, ProjectOverFileCapError, UpstreamError
from hermetic_pkgrec.models import (
    FilteredFileEntry,
    ProjectFilterResult,
    UpstreamFileEntry,
)
from hermetic_yank.simple_index import YankError, parse_rfc3339_ns

_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")
_PEP508_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}\Z")

# RFC 3339 date-time with optional nanosecond fraction and offset.
_RFC3339_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))$"
)
_NS_PER_SEC = 1_000_000_000


def parse_iso8601_ns(value: str) -> int:
    """Parse strict ISO 8601 / RFC 3339 timestamp string into UTC nanoseconds."""
    try:
        return parse_rfc3339_ns(value)
    except (YankError, ValueError, TypeError) as exc:
        raise CutoffError(str(exc)) from exc


def normalize_project_name(name: str) -> str:
    """Validate and normalize a project name according to PEP 503."""
    if not isinstance(name, str) or not name:
        raise CutoffError("Project name must be a non-empty string.")
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_PROJECT_NAME_BYTES:
        raise CutoffError("Project name exceeds maximum byte length.")
    if not _PEP508_NAME_RE.match(name):
        raise CutoffError(f"Invalid project name: {name!r}")
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


def validate_sha256(sha256: str) -> str:
    """Validate and normalize a lowercase 64-character hexadecimal SHA-256 digest."""
    if not isinstance(sha256, str) or not _SHA256_HEX_RE.fullmatch(sha256.lower()):
        raise CutoffError(f"Invalid SHA-256 digest: {sha256!r}")
    return sha256.lower()


def validate_filename(filename: str) -> str:
    """Validate a distribution filename segment."""
    if not isinstance(filename, str) or not filename:
        raise CutoffError("Filename must be a non-empty string.")
    if len(filename.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise CutoffError("Filename exceeds maximum byte length.")
    if filename in (".", "..") or "/" in filename or "\\" in filename or "\x00" in filename:
        raise CutoffError(f"Unsafe filename: {filename!r}")
    return filename


class _SimpleIndexHtmlParser(HTMLParser):
    """Safe streaming parser for PEP 503 HTML simple index pages."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.entries: list[UpstreamFileEntry] = []
        self._current_href: str | None = None
        self._current_upload_time: str | None = None
        self._current_yanked: bool | str = False
        self._current_requires_python: str | None = None
        self._text_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._current_href = None
            self._current_upload_time = None
            self._current_yanked = False
            self._current_requires_python = None
            self._text_chunks = []
            for k, v in attrs:
                key = k.lower()
                val = v if v is not None else ""
                if key == "href":
                    self._current_href = val
                elif key == "data-upload-time":
                    self._current_upload_time = val
                elif key == "data-yanked":
                    self._current_yanked = val if val else True
                elif key == "data-requires-python":
                    self._current_requires_python = val

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._text_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            filename = "".join(self._text_chunks).strip()
            href = self._current_href
            sha256: str | None = None
            parsed_url = urlsplit(href)
            if parsed_url.fragment.startswith("sha256="):
                sha256 = parsed_url.fragment[len("sha256=") :].strip().lower()

            if filename:
                self.entries.append(
                    UpstreamFileEntry(
                        filename=filename,
                        url=href,
                        sha256=sha256,
                        upload_time=self._current_upload_time,
                        yanked=self._current_yanked,
                        requires_python=self._current_requires_python,
                    )
                )
            self._current_href = None
            self._text_chunks = []


def parse_upstream_page(
    content_bytes: bytes,
    content_type: str,
) -> list[UpstreamFileEntry]:
    """Parse upstream simple index page from either PEP 691 JSON or PEP 503 HTML."""
    if len(content_bytes) > MAX_INDEX_RESPONSE_BYTES:
        raise UpstreamError("Upstream index page exceeds size cap.")

    ct_lower = content_type.lower()
    if "json" in ct_lower:
        try:
            payload = json.loads(content_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpstreamError("Corrupted JSON in upstream page.") from exc

        if not isinstance(payload, dict):
            raise UpstreamError("Upstream PEP 691 page must be a JSON object.")

        files_list = payload.get("files", [])
        if not isinstance(files_list, list):
            raise UpstreamError("Upstream PEP 691 'files' must be a list.")

        entries: list[UpstreamFileEntry] = []
        for item in files_list:
            if not isinstance(item, dict):
                continue
            fname = item.get("filename")
            url = item.get("url")
            if not isinstance(fname, str) or not isinstance(url, str):
                continue

            sha256: str | None = None
            hashes = item.get("hashes")
            if isinstance(hashes, dict) and isinstance(hashes.get("sha256"), str):
                sha256 = hashes["sha256"].lower()
            elif "#sha256=" in url:
                sha256 = url.split("#sha256=", 1)[1].partition("&")[0].lower()

            utime = item.get("upload-time") or item.get("upload_time")
            if not isinstance(utime, str):
                utime = None

            yanked = item.get("yanked", False)
            if not isinstance(yanked, (bool, str)):
                yanked = False

            yank_time = (
                item.get("yank-time")
                or item.get("yank_time")
                or item.get("yanked-time")
                or item.get("yanked_time")
            )
            if not isinstance(yank_time, str):
                yank_time = None

            req_py = item.get("requires-python")
            if not isinstance(req_py, str):
                req_py = None

            entries.append(
                UpstreamFileEntry(
                    filename=fname,
                    url=url,
                    sha256=sha256,
                    upload_time=utime,
                    yanked=yanked,
                    yank_time=yank_time,
                    requires_python=req_py,
                )
            )
        return entries

    # Fall back to HTML parsing.
    try:
        html_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UpstreamError("Upstream HTML page is not valid UTF-8.") from exc

    parser = _SimpleIndexHtmlParser()
    parser.feed(html_text)
    return parser.entries


def filter_project_files(
    raw_project: str,
    entries: list[UpstreamFileEntry],
    cutoff_ns: int,
    yank_table: dict[str, str] | None = None,
) -> ProjectFilterResult:
    """Filter project files against package cutoff T_pkg and rewrite yank status."""
    norm_project = normalize_project_name(raw_project)
    yank_lut = yank_table or {}

    if len(entries) > MAX_FILES_PER_PROJECT:
        raise ProjectOverFileCapError(
            f"Project {norm_project!r} file count ({len(entries)}) exceeds cap {MAX_FILES_PER_PROJECT}."
        )

    kept_files: list[FilteredFileEntry] = []
    missing_upload_time: list[dict[str, str]] = []
    unyanked_after_cutoff: list[dict[str, str]] = []
    unyanked_unknown_date: list[dict[str, str]] = []
    dropped_after_cutoff: list[dict[str, str]] = []
    missing_hash: list[dict[str, str]] = []
    invalid_hash: list[dict[str, str]] = []
    invalid_filename: list[dict[str, str]] = []

    entry_count = 0
    for entry in entries:
        entry_count += 1
        if entry_count > MAX_FILES_PER_PROJECT:
            raise ProjectOverFileCapError(
                f"Project {norm_project!r} file count exceeds cap {MAX_FILES_PER_PROJECT}."
            )

        fname = entry.filename
        try:
            fname = validate_filename(fname)
        except CutoffError:
            invalid_filename.append({"filename": str(entry.filename), "project": norm_project})
            continue

        # 1. PEP 700 upload-time check.
        if entry.upload_time is None or not entry.upload_time.strip():
            # Refused and listed!
            missing_upload_time.append({"filename": fname, "project": norm_project})
            continue

        try:
            upload_ns = parse_iso8601_ns(entry.upload_time)
        except CutoffError:
            missing_upload_time.append({"filename": fname, "project": norm_project})
            continue

        # Exact boundary second: upload_ns <= cutoff_ns is kept.
        if upload_ns > cutoff_ns:
            dropped_after_cutoff.append({"filename": fname, "project": norm_project})
            continue

        # 2. SHA-256 verification.
        if not entry.sha256:
            missing_hash.append({"filename": fname, "project": norm_project})
            continue
        try:
            sha256 = validate_sha256(entry.sha256)
        except CutoffError:
            invalid_hash.append({"filename": fname, "project": norm_project})
            continue

        # 3. Yank status rewriting per hermetic_yank.
        raw_yank = entry.yanked
        is_yanked = (raw_yank is True) or (isinstance(raw_yank, str) and raw_yank != "")

        final_yanked: bool = False
        yank_decision: str = "not_yanked"

        if is_yanked:
            yank_ts = entry.yank_time or yank_lut.get(fname)
            if yank_ts is not None:
                try:
                    yank_ns = parse_rfc3339_ns(yank_ts)
                    if yank_ns <= cutoff_ns:
                        # Yanked at or before cutoff: served with yanked=True and no reason text.
                        final_yanked = True
                        yank_decision = "yanked"
                    else:
                        # Yanked after cutoff: served as not yanked!
                        final_yanked = False
                        yank_decision = "unyanked_after_cutoff"
                        unyanked_after_cutoff.append({"filename": fname, "project": norm_project})
                except (CutoffError, YankError):
                    final_yanked = False
                    yank_decision = "unyanked_unknown_date"
                    unyanked_unknown_date.append({"filename": fname, "project": norm_project})
            else:
                # Unknown yank date: served as not yanked and listed!
                final_yanked = False
                yank_decision = "unyanked_unknown_date"
                unyanked_unknown_date.append({"filename": fname, "project": norm_project})

        kept_files.append(
            FilteredFileEntry(
                filename=fname,
                url=entry.url,
                sha256=sha256,
                upload_time=entry.upload_time,
                yanked=final_yanked,
                yank_decision=yank_decision,
                requires_python=entry.requires_python,
            )
        )

    # Sort deterministically.
    missing_upload_time.sort(key=lambda x: (x["project"], x["filename"]))
    unyanked_after_cutoff.sort(key=lambda x: (x["project"], x["filename"]))
    unyanked_unknown_date.sort(key=lambda x: (x["project"], x["filename"]))
    dropped_after_cutoff.sort(key=lambda x: (x["project"], x["filename"]))
    missing_hash.sort(key=lambda x: (x["project"], x["filename"]))
    invalid_hash.sort(key=lambda x: (x["project"], x["filename"]))
    invalid_filename.sort(key=lambda x: (x["project"], x["filename"]))
    kept_files.sort(key=lambda x: x.filename)

    return ProjectFilterResult(
        project=norm_project,
        files=kept_files,
        missing_upload_time=missing_upload_time,
        unyanked_after_cutoff=unyanked_after_cutoff,
        unyanked_unknown_date=unyanked_unknown_date,
        dropped_after_cutoff=dropped_after_cutoff,
        missing_hash=missing_hash,
        invalid_hash=invalid_hash,
        invalid_filename=invalid_filename,
    )


def render_project_json(
    project: str,
    files: list[FilteredFileEntry],
) -> bytes:
    """Render PEP 691 JSON for the filtered project page with local /files/ paths."""
    file_records: list[dict[str, Any]] = []
    for f in files:
        quoted_filename = quote(f.filename, safe="")
        rec: dict[str, Any] = {
            "filename": f.filename,
            "hashes": {"sha256": f.sha256},
            "upload-time": f.upload_time,
            "url": f"/files/{f.sha256}/{quoted_filename}",
        }
        if f.requires_python is not None:
            rec["requires-python"] = f.requires_python
        if f.yanked:
            rec["yanked"] = True
        file_records.append(rec)

    payload = {
        "meta": {"api-version": "1.0"},
        "name": project,
        "files": file_records,
    }
    return (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode("utf-8")


def render_project_html(
    project: str,
    files: list[FilteredFileEntry],
) -> bytes:
    """Render PEP 503 HTML for the filtered project page with local /files/ paths."""
    escaped_title = html.escape(project, quote=True)
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "  <head>",
        '    <meta name="pypi:repository-version" content="1.0">',
        f"    <title>Links for {escaped_title}</title>",
        "  </head>",
        "  <body>",
        f"    <h1>Links for {escaped_title}</h1>",
    ]

    for f in files:
        quoted_filename = quote(f.filename, safe="")
        href = f"/files/{f.sha256}/{quoted_filename}#sha256={f.sha256}"
        attrs = [f'href="{html.escape(href, quote=True)}"']
        attrs.append(f'data-upload-time="{html.escape(f.upload_time, quote=True)}"')

        if f.requires_python:
            attrs.append(f'data-requires-python="{html.escape(f.requires_python, quote=True)}"')

        if f.yanked:
            attrs.append('data-yanked=""')

        escaped_fn = html.escape(f.filename, quote=False)
        lines.append(f"    <a {' '.join(attrs)}>{escaped_fn}</a>")

    lines.extend(["  </body>", "</html>", ""])
    return "\n".join(lines).encode("utf-8")


def render_root_json(projects: list[str]) -> bytes:
    """Render PEP 691 JSON for the /simple/ project list."""
    payload = {
        "meta": {"api-version": "1.0"},
        "projects": [{"name": name} for name in sorted(projects)],
    }
    return (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode("utf-8")


def render_root_html(projects: list[str]) -> bytes:
    """Render PEP 503 HTML for the /simple/ project list."""
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "  <head>",
        '    <meta name="pypi:repository-version" content="1.0">',
        "    <title>Simple Index</title>",
        "  </head>",
        "  <body>",
    ]
    for name in sorted(projects):
        escaped = html.escape(name, quote=True)
        lines.append(f'    <a href="/simple/{escaped}/">{escaped}</a>')
    lines.extend(["  </body>", "</html>", ""])
    return "\n".join(lines).encode("utf-8")
