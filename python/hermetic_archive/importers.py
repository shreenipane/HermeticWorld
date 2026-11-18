"""Offline web archive importers for Common Crawl, Wayback, Software Heritage, and Stack Exchange.

Produces exact-capture records for the existing replay archive and BM25 index.
Enforces cutoff: only captures dated at or before the cutoff are admitted; anything
undated is listed in an uncertainty inventory, never guessed. Bounded parsers for
every format with strict limits and no host environment leakage.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import gzip
import hashlib
from html.parser import HTMLParser
import io
import json
import os
import re
import stat
from typing import Any
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

from hermetic_npm_cut.cut import (
    HermeticNpmCutError,
    parse_rfc3339_utc_nanos,
    read_regular_file_bounded,
)
from hermetic_safe_io import open_parent, validate_path

from . import formats as f

# Named bounds and safety limits
MAX_INPUT_BYTES = 64 * 1024 * 1024       # 64 MiB max input payload
MAX_RECORD_BYTES = 8 * 1024 * 1024      # 8 MiB max per record
MAX_RECORDS = 4096                      # Match f.MAX_RECORDS
MAX_LINE_BYTES = 65536                  # 64 KiB max line
MAX_HEADER_LINES = 1024                 # Max header lines per HTTP/WARC block
MAX_TEXT_BYTES = 8 * 1024 * 1024        # 8 MiB max text extraction
MAX_TITLE_BYTES = 512                   # Match search.MAX_TITLE_BYTES
MAX_XML_DEPTH = 32                      # Maximum XML element nesting
READ_CHUNK_SIZE = 65536                 # 64 KiB read chunk


@dataclass(frozen=True)
class ImportReport:
    """Deterministic result of importing web archive records."""
    source: str
    kept: tuple[dict, ...]
    search_documents: tuple[dict, ...]
    blobs: tuple[tuple[str, bytes], ...]
    after_cutoff: tuple[str, ...]
    undated: tuple[str, ...]
    replay_blobs: tuple[tuple[str, bytes], ...] = ()
    search_blobs: tuple[tuple[str, bytes], ...] = ()
    _search_recipe_builder: Any = field(default=None, compare=False, repr=False)

    def to_replay_recipe(self, cutoff: str) -> dict:
        f.timestamp(cutoff)
        return {
            "schema": "hermetic-replay-recipe/v1",
            "cutoff": cutoff,
            "captures": list(self.kept),
        }

    def to_search_recipe(self, month: str) -> dict:
        if type(month) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}", month) is None:
            raise f.ArchiveError("invalid search month")
        if self._search_recipe_builder is not None:
            docs, _ = self._search_recipe_builder(month)
            return {
                "schema": "hermetic-search-recipe/v1",
                "month": month,
                "documents": list(docs),
            }
        return {
            "schema": "hermetic-search-recipe/v1",
            "month": month,
            "documents": list(self.search_documents),
        }

    def to_blobs_dict(self) -> dict[str, bytes]:
        return dict(self.blobs)

    def to_replay_blobs_dict(self) -> dict[str, bytes]:
        if self.replay_blobs:
            return dict(self.replay_blobs)
        replay_keys = {entry["payload_sha256"] for entry in self.kept}
        return {k: v for k, v in self.blobs if k in replay_keys}

    def to_search_blobs_dict(self, month: str | None = None) -> dict[str, bytes]:
        if month is not None and self._search_recipe_builder is not None:
            _, blobs_map = self._search_recipe_builder(month)
            return blobs_map
        if self.search_blobs:
            return dict(self.search_blobs)
        search_keys = {entry["text_sha256"] for entry in self.search_documents}
        return {k: v for k, v in self.blobs if k in search_keys}


def _format_rfc3339_nanos(nanos: int) -> str:
    secs, sub_nanos = divmod(nanos, 1_000_000_000)
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=secs)
    if sub_nanos:
        sub_str = f"{sub_nanos:09d}".rstrip("0")
        return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{sub_str}Z"
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}Z"


def _parse_cutoff_nanos(cutoff: str | int) -> int:
    if isinstance(cutoff, int):
        return cutoff
    return f.timestamp(cutoff)


def _parse_iso_or_rfc3339_nanos(val: str | None) -> int | None:
    if not val or not isinstance(val, str) or len(val) > 64:
        return None
    val = val.strip()
    if not val:
        return None
    # If date has space instead of T, replace
    if " " in val:
        val = val.replace(" ", "T")
    # Check if there is an explicit offset at the end, e.g. +00:00, -05:00
    offset_match = re.search(r"([+-])(\d{2}):(\d{2})$", val)
    if offset_match:
        sign = 1 if offset_match.group(1) == "+" else -1
        try:
            hours = int(offset_match.group(2))
            minutes = int(offset_match.group(3))
            if hours > 23 or minutes > 59:
                return None
            offset_nanos = sign * (hours * 3600 + minutes * 60) * 1_000_000_000
            naive_str = val[:offset_match.start()] + "Z"
            base_nanos = parse_rfc3339_utc_nanos(naive_str)
            return base_nanos - offset_nanos
        except (HermeticNpmCutError, ValueError, OverflowError):
            return None
    # If no trailing Z and no timezone offset, assume UTC Z per SE archive spec
    if not val.endswith("Z") and not val.endswith("z"):
        val = val + "Z"
    elif val.endswith("z"):
        val = val[:-1] + "Z"
    try:
        return parse_rfc3339_utc_nanos(val)
    except (HermeticNpmCutError, ValueError, OverflowError):
        return None


def _parse_cdx_timestamp_nanos(val: str | None) -> int | None:
    if not val or not isinstance(val, str):
        return None
    val = val.strip()
    # CDX 14-digit format: YYYYMMDDhhmmss
    if re.fullmatch(r"\d{14}", val):
        try:
            year = int(val[0:4])
            month = int(val[4:6])
            day = int(val[6:8])
            hour = int(val[8:10])
            minute = int(val[10:12])
            second = int(val[12:14])
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            epoch_seconds = int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
            return epoch_seconds * 1_000_000_000
        except (ValueError, OverflowError):
            return None
    # Alternatively, RFC 3339 string
    return _parse_iso_or_rfc3339_nanos(val)


class _HtmlTitleAndTextExtractor(HTMLParser):
    def __init__(self, max_text_bytes: int = MAX_TEXT_BYTES, max_title_bytes: int = MAX_TITLE_BYTES):
        super().__init__(convert_charrefs=True)
        self.max_text_bytes = max_text_bytes
        self.max_title_bytes = max_title_bytes
        self.in_title = False
        self.in_ignored = False
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.total_text_len = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = True
        elif t in ("script", "style", "noscript", "svg", "template"):
            self.in_ignored = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t in ("script", "style", "noscript", "svg", "template"):
            self.in_ignored = False

    def handle_data(self, data: str) -> None:
        if self.in_title and sum(len(p) for p in self.title_parts) < self.max_title_bytes:
            self.title_parts.append(data)
        elif not self.in_ignored and not self.in_title:
            if self.total_text_len + len(data) <= self.max_text_bytes:
                self.text_parts.append(data)
                self.total_text_len += len(data)


def extract_html_title_and_text(body: bytes, fallback_title: str) -> tuple[str, bytes]:
    """Bounded, safe extraction of title and plain text from HTML or plain text."""
    if not body:
        cleaned_fallback = re.sub(r"[\x00-\x1f\x7f]", "", fallback_title).strip()[:MAX_TITLE_BYTES] or "Page"
        return cleaned_fallback, b""
    try:
        decoded = body.decode("utf-8", errors="replace")
    except Exception:
        decoded = ""

    parser = _HtmlTitleAndTextExtractor(MAX_TEXT_BYTES, MAX_TITLE_BYTES)
    try:
        parser.feed(decoded[:MAX_TEXT_BYTES])
        raw_title = "".join(parser.title_parts)
    except Exception:
        raw_title = ""

    raw_title = re.sub(r"\s+", " ", raw_title).strip()
    raw_title = re.sub(r"[\x00-\x1f\x7f]", "", raw_title)
    if not raw_title or len(raw_title) == 0:
        raw_title = re.sub(r"[\x00-\x1f\x7f]", "", fallback_title).strip() or "Page"
    title = raw_title.encode("utf-8")[:MAX_TITLE_BYTES].decode("utf-8", errors="ignore").strip()
    if not title:
        title = "Page"

    text = re.sub(r"\s+", " ", "".join(parser.text_parts)).strip()
    raw_text_bytes = text.encode("utf-8")
    if len(raw_text_bytes) > MAX_TEXT_BYTES:
        text_bytes = raw_text_bytes[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore").encode("utf-8")
    else:
        text_bytes = raw_text_bytes
    return title, text_bytes


def _bounded_decompress_gzip(data: bytes, cap: int = MAX_INPUT_BYTES) -> bytes:
    """Decompress gzip including multi-member streams within a strict byte cap."""
    if len(data) < 2 or data[:2] != b"\x1f\x8b":
        return data
    stream = io.BytesIO(data)
    out = io.BytesIO()
    total = 0
    try:
        with gzip.GzipFile(fileobj=stream, mode="rb") as gz:
            while True:
                chunk = gz.read(READ_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    raise f.ArchiveError("decompressed archive data exceeds byte cap")
                out.write(chunk)
    except (OSError, zlib.error) as exc:
        raise f.ArchiveError("malformed gzip compressed stream") from exc
    return out.getvalue()


def _bounded_decompress_deflate(data: bytes, cap: int = f.MAX_PAYLOAD_BYTES) -> bytes:
    """Decompress zlib or raw deflate stream within strict byte cap."""
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            decompressor = zlib.decompressobj(wbits)
            out = decompressor.decompress(data, cap + 1)
            if len(out) > cap:
                raise f.ArchiveError("decompressed archive data exceeds byte cap")
            remaining = decompressor.unconsumed_tail
            if remaining:
                more = decompressor.decompress(remaining, 1)
                if more or len(out) + len(more) > cap:
                    raise f.ArchiveError("decompressed archive data exceeds byte cap")
                out += more
            out += decompressor.flush()
            if len(out) > cap:
                raise f.ArchiveError("decompressed archive data exceeds byte cap")
            return out
        except zlib.error:
            continue
    raise f.ArchiveError("malformed deflate compressed body")


def _bounded_decompress_http_payload(body: bytes, encoding: str, cap: int = f.MAX_PAYLOAD_BYTES) -> bytes:
    """Decompress content-encoded HTTP bodies within payload cap."""
    encoding_lower = encoding.lower().strip()
    if encoding_lower in ("", "identity"):
        if len(body) > cap:
            raise f.ArchiveError("decompressed archive data exceeds byte cap")
        return body
    elif encoding_lower == "gzip":
        return _bounded_decompress_gzip(body, cap)
    elif encoding_lower == "deflate":
        return _bounded_decompress_deflate(body, cap)
    else:
        raise f.ArchiveError("unsupported content encoding")


# ---------------------------------------------------------------------------
# 1. Common Crawl WARC / CDX Importer
# ---------------------------------------------------------------------------

def _parse_http_response_block(http_bytes: bytes) -> tuple[int, str, str | None, bytes]:
    """Parse HTTP status line, headers and body from WARC response block."""
    header_end = http_bytes.find(b"\r\n\r\n")
    if header_end < 0:
        header_end = http_bytes.find(b"\n\n")
        delim_len = 2
    else:
        delim_len = 4

    if header_end < 0:
        raise f.ArchiveError("invalid or truncated HTTP response framing")

    header_block = http_bytes[:header_end]
    body = http_bytes[header_end + delim_len:]

    lines = [line.strip(b"\r") for line in header_block.split(b"\n")]
    if not lines or len(lines) > MAX_HEADER_LINES:
        raise f.ArchiveError("invalid HTTP response header count")

    # Status line: e.g. HTTP/1.1 200 OK
    status_parts = lines[0].split(None, 2)
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise f.ArchiveError("invalid HTTP status line in archive")
    status = int(status_parts[1])

    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if not line:
            continue
        key, sep, val = line.partition(b":")
        if not sep or not key:
            continue
        headers[key.strip().lower()] = val.strip()

    raw_ct = headers.get(b"content-type", b"text/html; charset=utf-8")
    try:
        content_type = raw_ct.decode("ascii", errors="replace").split(";")[0].strip().lower()
        if not content_type:
            content_type = "application/octet-stream"
        if ";" in raw_ct.decode("ascii", errors="replace"):
            charset_part = raw_ct.decode("ascii", errors="replace").split(";", 1)[1].strip()
            content_type = f"{content_type}; {charset_part}"
    except Exception:
        content_type = "text/html; charset=utf-8"

    if len(content_type) > f.MAX_CONTENT_TYPE_BYTES:
        content_type = content_type[:f.MAX_CONTENT_TYPE_BYTES]

    # Clean location if redirect
    location = None
    if status in (301, 302, 303, 307, 308):
        raw_loc = headers.get(b"location")
        if raw_loc:
            try:
                loc_str = raw_loc.decode("ascii", errors="replace").strip()
                location = f.url(loc_str)
            except Exception:
                location = None

    # Handle content-encoding
    content_encoding = headers.get(b"content-encoding", b"").decode("ascii", errors="replace").strip()
    if content_encoding:
        body = _bounded_decompress_http_payload(body, content_encoding)

    return status, content_type, location, body


def import_common_crawl_warc(raw_warc: bytes, cutoff: str) -> ImportReport:
    """Import Common Crawl WARC (1.0 or 1.1), plain or gzip-compressed.

    Admissions strictly <= cutoff; undated records listed in uncertainty report.
    """
    if type(raw_warc) is not bytes or len(raw_warc) > MAX_INPUT_BYTES:
        raise f.ArchiveError("warc input exceeds byte cap or invalid type")

    cutoff_nanos = _parse_cutoff_nanos(cutoff)
    decompressed = _bounded_decompress_gzip(raw_warc)

    offset = 0
    record_count = 0
    kept: list[dict] = []
    search_docs: list[dict] = []
    blobs: dict[str, bytes] = {}
    after_cutoff: list[str] = []
    undated: list[str] = []

    while offset < len(decompressed):
        # Each record starts with WARC/1.0 or WARC/1.1
        warc_start = decompressed.find(b"WARC/", offset)
        if warc_start < 0:
            break
        if record_count >= MAX_RECORDS:
            raise f.ArchiveError("WARC record cap exceeded")
        offset = warc_start
        header_end = decompressed.find(b"\r\n\r\n", offset, offset + MAX_LINE_BYTES * 16)
        if header_end < 0:
            header_end = decompressed.find(b"\n\n", offset, offset + MAX_LINE_BYTES * 16)
            delim_len = 2
        else:
            delim_len = 4
        if header_end < 0:
            raise f.ArchiveError("truncated WARC record header")

        header_bytes = decompressed[offset:header_end]
        lines = [line.strip(b"\r") for line in header_bytes.split(b"\n")]
        if not lines or not (lines[0].startswith(b"WARC/1.0") or lines[0].startswith(b"WARC/1.1")):
            raise f.ArchiveError("unsupported or invalid WARC version")

        warc_headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            if not line:
                continue
            key, sep, val = line.partition(b":")
            if not sep or not key:
                continue
            warc_headers[key.strip().lower()] = val.strip()

        warc_type = warc_headers.get(b"warc-type", b"").lower()
        content_len_str = warc_headers.get(b"content-length", b"")
        if not content_len_str.isdigit():
            raise f.ArchiveError("invalid WARC Content-Length")
        content_len = int(content_len_str)
        if content_len > MAX_RECORD_BYTES:
            raise f.ArchiveError("WARC record payload exceeds byte cap")

        body_start = header_end + delim_len
        body_end = body_start + content_len
        if body_end > len(decompressed):
            raise f.ArchiveError("truncated WARC payload")

        raw_record_bytes = decompressed[offset:body_end]
        offset = body_end
        # Advance over trailing newlines
        while offset < len(decompressed) and decompressed[offset:offset + 1] in (b"\r", b"\n"):
            offset += 1

        record_count += 1
        raw_uri = warc_headers.get(b"warc-target-uri", b"").decode("ascii", errors="replace").strip()
        raw_date = warc_headers.get(b"warc-date", b"").decode("ascii", errors="replace").strip()

        # If not a response record, skip to next
        if warc_type != b"response":
            continue

        try:
            canonical_url = f.url(raw_uri)
        except Exception:
            undated.append(raw_uri or f"record_{record_count}")
            continue

        date_nanos = _parse_iso_or_rfc3339_nanos(raw_date)
        if date_nanos is None:
            undated.append(canonical_url)
            continue

        if date_nanos > cutoff_nanos:
            after_cutoff.append(canonical_url)
            continue

        payload_bytes = decompressed[body_start:body_end]
        try:
            status, ct, loc, http_body = _parse_http_response_block(payload_bytes)
        except f.ArchiveError:
            raise
        except Exception:
            undated.append(canonical_url)
            continue

        if len(http_body) > f.MAX_PAYLOAD_BYTES:
            continue

        # Adjust status/location rules
        if status in (204, 205):
            http_body = b""
        if status in (301, 302, 303, 307, 308) and not loc:
            loc = canonical_url

        payload_hash = f.sha(http_body)
        rec_hash = f.sha(raw_record_bytes)
        captured_str = _format_rfc3339_nanos(date_nanos)

        replay_entry = {
            "url": canonical_url,
            "captured": captured_str,
            "source": "common-crawl",
            "record_sha256": rec_hash,
            "payload_sha256": payload_hash,
            "size": len(http_body),
            "status": status,
            "content_type": ct,
            "location": loc,
        }
        kept.append(replay_entry)
        blobs[payload_hash] = http_body

        # Search document
        title, text_bytes = extract_html_title_and_text(http_body, fallback_title=canonical_url)
        text_hash = f.sha(text_bytes)
        blobs[text_hash] = text_bytes
        search_entry = {
            "url": canonical_url,
            "captured": captured_str,
            "source": "common-crawl",
            "record_sha256": rec_hash,
            "text_sha256": text_hash,
            "title": title,
        }
        search_docs.append(search_entry)

    # Sort deterministically
    kept.sort(key=lambda x: (x["url"], x["captured"]))
    search_docs.sort(key=lambda x: (x["url"], x["captured"]))
    sorted_blobs = tuple(sorted(blobs.items(), key=lambda x: x[0]))
    replay_keys = {entry["payload_sha256"] for entry in kept}
    search_keys = {entry["text_sha256"] for entry in search_docs}
    replay_blobs = tuple(sorted(((k, v) for k, v in blobs.items() if k in replay_keys), key=lambda x: x[0]))
    search_blobs = tuple(sorted(((k, v) for k, v in blobs.items() if k in search_keys), key=lambda x: x[0]))
    return ImportReport(
        source="common-crawl",
        kept=tuple(kept),
        search_documents=tuple(search_docs),
        blobs=sorted_blobs,
        after_cutoff=tuple(sorted(set(after_cutoff))),
        undated=tuple(sorted(set(undated))),
        replay_blobs=replay_blobs,
        search_blobs=search_blobs,
    )


def import_common_crawl_cdx(raw_cdx: bytes, blobs: dict[str, bytes], cutoff: str) -> ImportReport:
    """Import Common Crawl CDX / CDXJ index lines paired with payload blobs."""
    return _import_cdx_lines(raw_cdx, blobs, cutoff, source="common-crawl")


# ---------------------------------------------------------------------------
# 2. Wayback CDX Captures Importer
# ---------------------------------------------------------------------------

def import_wayback_cdx(raw_cdx: bytes, blobs: dict[str, bytes], cutoff: str) -> ImportReport:
    """Import Wayback CDX (text lines or JSON array of arrays) paired with payload blobs."""
    return _import_cdx_lines(raw_cdx, blobs, cutoff, source="wayback")


def _import_cdx_lines(raw_cdx: bytes, blobs: dict[str, bytes], cutoff: str, source: str) -> ImportReport:
    if type(raw_cdx) is not bytes or len(raw_cdx) > MAX_INPUT_BYTES:
        raise f.ArchiveError("cdx input exceeds byte cap or invalid type")

    cutoff_nanos = _parse_cutoff_nanos(cutoff)
    blobs = f.payloads(blobs, set(blobs.keys()))

    # Build blob lookup map once in O(N) to avoid O(N^2) rehashing
    blob_lookup: dict[str, bytes] = {}
    for k, v in blobs.items():
        blob_lookup[k] = v
        s256 = f.sha(v)
        blob_lookup[s256] = v
        s1 = hashlib.sha1(v)
        s1_bytes = s1.digest()
        s1_hex = s1.hexdigest().lower()
        blob_lookup[s1_hex] = v
        blob_lookup[s1_hex.upper()] = v
        s1_b32 = base64.b32encode(s1_bytes).decode("ascii").upper()
        blob_lookup[s1_b32] = v
        blob_lookup[s1_b32.lower()] = v
        blob_lookup[s1_b32.rstrip("=")] = v
        blob_lookup[s1_b32.rstrip("=").lower()] = v

    kept: list[dict] = []
    search_docs: list[dict] = []
    result_blobs: dict[str, bytes] = {}
    after_cutoff: list[str] = []
    undated: list[str] = []

    # Check if raw_cdx is JSON (e.g. Wayback CDX JSON API array of arrays)
    is_json = False
    json_rows: list[list[str]] = []
    if raw_cdx.strip().startswith(b"["):
        try:
            parsed = json.loads(raw_cdx.decode("utf-8"))
            if isinstance(parsed, list) and all(isinstance(row, list) for row in parsed):
                is_json = True
                json_rows = parsed
        except Exception:
            is_json = False

    if is_json and len(json_rows) > 0:
        header = [str(col).lower() for col in json_rows[0]]
        data_rows = [row for row in json_rows[1:] if row]
        if len(data_rows) > MAX_RECORDS:
            raise f.ArchiveError("CDX record cap exceeded")
        for row in data_rows:
            row_dict = {header[i]: str(row[i]) for i in range(min(len(header), len(row)))}
            raw_url = row_dict.get("original") or row_dict.get("url") or ""
            raw_ts = row_dict.get("timestamp")
            status_str = row_dict.get("statuscode") or row_dict.get("status") or "200"
            mimetype = row_dict.get("mimetype") or row_dict.get("mime") or "text/html; charset=utf-8"
            digest = row_dict.get("digest") or ""
            redirect = row_dict.get("redirect")

            _process_cdx_entry(
                raw_url, raw_ts, status_str, mimetype, digest, redirect,
                cutoff_nanos, source, blob_lookup, kept, search_docs, result_blobs,
                after_cutoff, undated,
            )
    else:
        # Line-based CDX or CDXJ
        lines = raw_cdx.split(b"\n")
        header_mapping: list[str] | None = None
        data_lines: list[bytes] = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith(b"#"):
                continue
            if line.startswith(b"CDX ") or line.startswith(b" CDX "):
                # Header line
                header_mapping = [p.decode("ascii", errors="replace") for p in line.split()[1:]]
                continue
            data_lines.append(line)

        if len(data_lines) > MAX_RECORDS:
            raise f.ArchiveError("CDX record cap exceeded")

        for line in data_lines:
            decoded_line = line.decode("utf-8", errors="replace")
            # Check CDXJ: <urlkey> <timestamp> <json>
            if "{" in decoded_line and decoded_line.endswith("}"):
                parts = decoded_line.split(None, 2)
                if len(parts) == 3 and parts[2].startswith("{"):
                    raw_ts = parts[1]
                    try:
                        record_json = json.loads(parts[2])
                    except Exception:
                        undated.append(parts[0])
                        continue
                    raw_url = record_json.get("url") or parts[0]
                    status_str = str(record_json.get("status", "200"))
                    mimetype = str(record_json.get("mime", "text/html"))
                    digest = str(record_json.get("digest", ""))
                    redirect = record_json.get("redirect")

                    _process_cdx_entry(
                        raw_url, raw_ts, status_str, mimetype, digest, redirect,
                        cutoff_nanos, source, blob_lookup, kept, search_docs, result_blobs,
                        after_cutoff, undated,
                    )
                    continue

            # Standard CDX line (space-separated)
            parts = decoded_line.split()
            if len(parts) < 3:
                continue

            if header_mapping and len(parts) == len(header_mapping):
                entry = dict(zip(header_mapping, parts))
                raw_url = entry.get("a") or entry.get("original") or parts[2]
                raw_ts = entry.get("b") or entry.get("timestamp") or parts[1]
                mimetype = entry.get("m") or entry.get("mimetype") or (parts[3] if len(parts) > 3 else "text/html")
                status_str = entry.get("s") or entry.get("statuscode") or (parts[4] if len(parts) > 4 else "200")
                digest = entry.get("k") or entry.get("digest") or (parts[5] if len(parts) > 5 else "")
                redirect = entry.get("r") or entry.get("redirect") or (parts[6] if len(parts) > 6 else "-")
            else:
                # Default 9 or 11 field order: urlkey timestamp original mimetype statuscode digest redirect ...
                raw_ts = parts[1]
                raw_url = parts[2]
                mimetype = parts[3] if len(parts) > 3 else "text/html"
                status_str = parts[4] if len(parts) > 4 else "200"
                digest = parts[5] if len(parts) > 5 else ""
                redirect = parts[6] if len(parts) > 6 else "-"

            _process_cdx_entry(
                raw_url, raw_ts, status_str, mimetype, digest, redirect,
                cutoff_nanos, source, blob_lookup, kept, search_docs, result_blobs,
                after_cutoff, undated,
            )

    kept.sort(key=lambda x: (x["url"], x["captured"]))
    search_docs.sort(key=lambda x: (x["url"], x["captured"]))
    sorted_blobs = tuple(sorted(result_blobs.items(), key=lambda x: x[0]))
    replay_keys = {entry["payload_sha256"] for entry in kept}
    search_keys = {entry["text_sha256"] for entry in search_docs}
    replay_blobs = tuple(sorted(((k, v) for k, v in result_blobs.items() if k in replay_keys), key=lambda x: x[0]))
    search_blobs = tuple(sorted(((k, v) for k, v in result_blobs.items() if k in search_keys), key=lambda x: x[0]))
    return ImportReport(
        source=source,
        kept=tuple(kept),
        search_documents=tuple(search_docs),
        blobs=sorted_blobs,
        after_cutoff=tuple(sorted(set(after_cutoff))),
        undated=tuple(sorted(set(undated))),
        replay_blobs=replay_blobs,
        search_blobs=search_blobs,
    )


def _process_cdx_entry(
    raw_url: str,
    raw_ts: str | None,
    status_str: str,
    mimetype: str,
    digest: str,
    redirect: str | None,
    cutoff_nanos: int,
    source: str,
    blob_lookup: dict[str, bytes],
    kept: list[dict],
    search_docs: list[dict],
    result_blobs: dict[str, bytes],
    after_cutoff: list[str],
    undated: list[str],
) -> None:
    try:
        canonical_url = f.url(raw_url)
    except Exception:
        undated.append(raw_url or "unknown_url")
        return

    date_nanos = _parse_cdx_timestamp_nanos(raw_ts)
    if date_nanos is None:
        undated.append(canonical_url)
        return

    if date_nanos > cutoff_nanos:
        after_cutoff.append(canonical_url)
        return

    try:
        status = int(status_str)
        if not (200 <= status <= 599) or status == 304:
            status = 200
    except Exception:
        status = 200

    loc = None
    if status in (301, 302, 303, 307, 308):
        if redirect and redirect != "-":
            try:
                loc = f.url(redirect)
            except Exception:
                loc = canonical_url
        else:
            loc = canonical_url

    # Find body from precomputed lookup map (native SHA-1 base32/hex, SHA-256, or key)
    clean_digest = digest.strip()
    if clean_digest.lower().startswith("sha1:"):
        clean_digest = clean_digest[5:]
    elif clean_digest.lower().startswith("sha256:"):
        clean_digest = clean_digest[7:]

    body = blob_lookup.get(clean_digest)
    if body is None and digest:
        body = blob_lookup.get(digest)
    if body is None:
        body = blob_lookup.get(canonical_url) or blob_lookup.get(raw_url)
    if body is None:
        # Row with no matching supplied payload must be reported as undated, never fabricated empty body
        undated.append(canonical_url)
        return

    payload_hash = f.sha(body)
    rec_hash = f.sha(f"{canonical_url}|{date_nanos}|{status}|{digest}".encode("utf-8"))
    captured_str = _format_rfc3339_nanos(date_nanos)

    clean_ct = mimetype.split(";")[0].strip().lower()
    if not clean_ct or clean_ct == "-":
        clean_ct = "text/html; charset=utf-8"
    if len(clean_ct) > f.MAX_CONTENT_TYPE_BYTES:
        clean_ct = clean_ct[:f.MAX_CONTENT_TYPE_BYTES]

    replay_entry = {
        "url": canonical_url,
        "captured": captured_str,
        "source": source,
        "record_sha256": rec_hash,
        "payload_sha256": payload_hash,
        "size": len(body),
        "status": status,
        "content_type": clean_ct,
        "location": loc,
    }
    kept.append(replay_entry)
    result_blobs[payload_hash] = body

    title, text_bytes = extract_html_title_and_text(body, fallback_title=canonical_url)
    text_hash = f.sha(text_bytes)
    result_blobs[text_hash] = text_bytes
    search_entry = {
        "url": canonical_url,
        "captured": captured_str,
        "source": source,
        "record_sha256": rec_hash,
        "text_sha256": text_hash,
        "title": title,
    }
    search_docs.append(search_entry)


# ---------------------------------------------------------------------------
# 3. Software Heritage Snapshots Importer
# ---------------------------------------------------------------------------

def import_software_heritage(raw_snapshot: bytes, blobs: dict[str, bytes], cutoff: str) -> ImportReport:
    """Import Software Heritage snapshot JSON paired with payload blobs.

    Format schema: hermetic-swh-snapshot/v1 or hermetic-swh-directory/v1.
    """
    if type(raw_snapshot) is not bytes or len(raw_snapshot) > MAX_INPUT_BYTES:
        raise f.ArchiveError("swh input exceeds byte cap or invalid type")

    cutoff_nanos = _parse_cutoff_nanos(cutoff)
    blobs = f.payloads(blobs, set(blobs.keys()))

    try:
        doc = json.loads(raw_snapshot.decode("utf-8"))
    except Exception as exc:
        raise f.ArchiveError("invalid JSON in Software Heritage snapshot") from exc

    if not isinstance(doc, dict):
        raise f.ArchiveError("Software Heritage snapshot document must be a JSON object")

    origin = doc.get("origin")
    visit_date = doc.get("visit_date") or doc.get("date")
    entries = doc.get("entries") or doc.get("files") or []

    if not isinstance(entries, list) or len(entries) > MAX_RECORDS:
        raise f.ArchiveError("invalid or excessive Software Heritage entries")

    visit_nanos = _parse_iso_or_rfc3339_nanos(visit_date)
    kept: list[dict] = []
    search_docs: list[dict] = []
    result_blobs: dict[str, bytes] = {}
    after_cutoff: list[str] = []
    undated: list[str] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_url = entry.get("url")
        path = str(entry.get("path") or "")
        if not raw_url:
            if origin:
                raw_url = f"{origin.rstrip('/')}/raw/HEAD/{path.lstrip('/')}"
            else:
                raw_url = f"https://archive.softwareheritage.org/browse/content/{path}"

        try:
            canonical_url = f.url(raw_url)
        except Exception:
            undated.append(raw_url or path or "unknown_entry")
            continue

        entry_date = entry.get("captured") or entry.get("date")
        date_nanos = _parse_iso_or_rfc3339_nanos(entry_date) if entry_date else visit_nanos

        if date_nanos is None:
            undated.append(canonical_url)
            continue

        if date_nanos > cutoff_nanos:
            after_cutoff.append(canonical_url)
            continue

        sha256 = entry.get("sha256")
        body = blobs.get(sha256) if sha256 else None
        if body is None:
            undated.append(canonical_url)
            continue

        payload_hash = f.sha(body)
        rec_hash = f.sha(f"{canonical_url}|{date_nanos}|{payload_hash}".encode("utf-8"))
        captured_str = _format_rfc3339_nanos(date_nanos)

        ct = str(entry.get("content_type") or "text/plain")
        if len(ct) > f.MAX_CONTENT_TYPE_BYTES:
            ct = ct[:f.MAX_CONTENT_TYPE_BYTES]

        replay_entry = {
            "url": canonical_url,
            "captured": captured_str,
            "source": "software-heritage",
            "record_sha256": rec_hash,
            "payload_sha256": payload_hash,
            "size": len(body),
            "status": 200,
            "content_type": ct,
            "location": None,
        }
        kept.append(replay_entry)
        result_blobs[payload_hash] = body

        title = path or urllib.parse.urlsplit(canonical_url).path.split("/")[-1] or "Document"
        title = re.sub(r"[\x00-\x1f\x7f]", "", title).strip()[:MAX_TITLE_BYTES] or "Document"
        _, text_bytes = extract_html_title_and_text(body, fallback_title=title)
        text_hash = f.sha(text_bytes)
        result_blobs[text_hash] = text_bytes
        search_entry = {
            "url": canonical_url,
            "captured": captured_str,
            "source": "software-heritage",
            "record_sha256": rec_hash,
            "text_sha256": text_hash,
            "title": title,
        }
        search_docs.append(search_entry)

    kept.sort(key=lambda x: (x["url"], x["captured"]))
    search_docs.sort(key=lambda x: (x["url"], x["captured"]))
    sorted_blobs = tuple(sorted(result_blobs.items(), key=lambda x: x[0]))
    replay_keys = {entry["payload_sha256"] for entry in kept}
    search_keys = {entry["text_sha256"] for entry in search_docs}
    replay_blobs = tuple(sorted(((k, v) for k, v in result_blobs.items() if k in replay_keys), key=lambda x: x[0]))
    search_blobs = tuple(sorted(((k, v) for k, v in result_blobs.items() if k in search_keys), key=lambda x: x[0]))
    return ImportReport(
        source="software-heritage",
        kept=tuple(kept),
        search_documents=tuple(search_docs),
        blobs=sorted_blobs,
        after_cutoff=tuple(sorted(set(after_cutoff))),
        undated=tuple(sorted(set(undated))),
        replay_blobs=replay_blobs,
        search_blobs=search_blobs,
    )


# ---------------------------------------------------------------------------
# 4. Stack Exchange Rebuilder from Post History
# ---------------------------------------------------------------------------

@dataclass
class _SePostEvent:
    event_id: int
    event_type: int
    creation_date_nanos: int
    creation_date_str: str
    text: str | None


def import_stack_exchange(
    post_history_xml: bytes,
    cutoff: str,
    site_url: str = "https://stackoverflow.com",
    posts_xml: bytes | None = None,
) -> ImportReport:
    """Rebuild Stack Exchange posts from post history as of cutoff (mutable content rule §4).

    Edits after cutoff are rolled back to pre-cutoff revisions.
    Posts created after cutoff are excluded (after_cutoff).
    Undated posts or events are listed in undated, never guessed.
    """
    if type(post_history_xml) is not bytes or len(post_history_xml) > MAX_INPUT_BYTES:
        raise f.ArchiveError("post history input exceeds byte cap or invalid type")

    site_url_with_slash = site_url if site_url.endswith("/") else site_url + "/"
    f.url(site_url_with_slash)
    canonical_site_url = site_url_with_slash.rstrip("/")
    cutoff_nanos = _parse_cutoff_nanos(cutoff)

    # Posts metadata map if Posts.xml is provided: post_id -> dict(post_type, parent_id, score, ...)
    posts_meta: dict[int, dict] = {}
    if posts_xml is not None:
        if type(posts_xml) is not bytes or len(posts_xml) > MAX_INPUT_BYTES:
            raise f.ArchiveError("posts XML input exceeds byte cap")
        posts_meta = _parse_se_posts_metadata(posts_xml)

    # Parse PostHistory XML streaming
    post_events: dict[int, list[_SePostEvent]] = {}
    undated_post_ids: set[int] = set()
    undated_urls: set[str] = set()

    for row_attrib in _iter_xml_rows(post_history_xml):
        post_id_str = row_attrib.get("PostId")
        type_id_str = row_attrib.get("PostHistoryTypeId")
        date_str = row_attrib.get("CreationDate")
        if not post_id_str or not type_id_str or not post_id_str.isdigit() or not type_id_str.isdigit():
            continue
        post_id = int(post_id_str)
        type_id = int(type_id_str)

        date_nanos = _parse_iso_or_rfc3339_nanos(date_str)
        if date_nanos is None:
            # Withhold posts when an undated event can change its replay or search state
            if type_id in (1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13):
                undated_post_ids.add(post_id)
            continue

        event_id = int(row_attrib.get("Id", "0")) if row_attrib.get("Id", "0").isdigit() else 0
        text = row_attrib.get("Text")

        event = _SePostEvent(
            event_id=event_id,
            event_type=type_id,
            creation_date_nanos=date_nanos,
            creation_date_str=date_str or "",
            text=text,
        )
        post_events.setdefault(post_id, []).append(event)

    def _get_post_url(pid: int) -> str:
        ptype = posts_meta.get(pid, {}).get("PostTypeId")
        if ptype is None:
            evs = post_events.get(pid, [])
            has_title = any(ev.event_type in (1, 4, 7) for ev in evs)
            ptype = 1 if (has_title or not evs) else 2
        return f"{canonical_site_url}/questions/{pid}" if ptype == 1 else f"{canonical_site_url}/a/{pid}"

    for pid in undated_post_ids:
        undated_urls.add(_get_post_url(pid))

    def _reconstruct_post_state(events: list[_SePostEvent], boundary_nanos: int) -> tuple[int, str, str] | None:
        # Reconstruct strictly < boundary_nanos
        admitted = [ev for ev in events if ev.creation_date_nanos < boundary_nanos]
        if not admitted:
            return None
        title: str | None = None
        body: str | None = None
        is_deleted = False
        last_event_nanos = admitted[0].creation_date_nanos

        for ev in admitted:
            last_event_nanos = max(last_event_nanos, ev.creation_date_nanos)
            if ev.event_type in (1, 4, 7) and ev.text:
                title = ev.text
            elif ev.event_type in (2, 5, 8) and ev.text:
                body = ev.text
            elif ev.event_type == 12:
                is_deleted = True
            elif ev.event_type == 13:
                is_deleted = False

        if is_deleted or body is None:
            return None
        return last_event_nanos, title, body

    kept: list[dict] = []
    replay_blobs: dict[str, bytes] = {}
    after_cutoff: list[str] = []

    # Reconstruct each post for replay (strictly < cutoff_nanos)
    for post_id in sorted(post_events.keys()):
        events = post_events[post_id]
        events.sort(key=lambda ev: (ev.creation_date_nanos, ev.event_id))

        target_url = _get_post_url(post_id)

        if post_id in undated_post_ids:
            undated_urls.add(target_url)
            continue

        first_event = events[0]
        # Check if post was created at or after cutoff
        if first_event.creation_date_nanos >= cutoff_nanos:
            after_cutoff.append(target_url)
            continue

        state = _reconstruct_post_state(events, cutoff_nanos)
        if state is None:
            admitted_before_cutoff = [ev for ev in events if ev.creation_date_nanos < cutoff_nanos]
            is_del = False
            has_b = False
            for ev in admitted_before_cutoff:
                if ev.event_type in (2, 5, 8) and ev.text:
                    has_b = True
                elif ev.event_type == 12:
                    is_del = True
                elif ev.event_type == 13:
                    is_del = False
            if not is_del and not has_b:
                undated_urls.add(target_url)
            continue

        last_event_nanos, raw_title, body = state
        clean_title = (raw_title or f"Post {post_id}").strip()
        clean_title = re.sub(r"[\x00-\x1f\x7f]", "", clean_title)[:MAX_TITLE_BYTES] or f"Post {post_id}"

        # Rebuild HTML page
        html_page = (
            f"<!DOCTYPE html>\n<html>\n<head><title>{_escape_html(clean_title)}</title></head>\n"
            f"<body>\n<h1>{_escape_html(clean_title)}</h1>\n"
            f'<div class="post-text">{body}</div>\n'
            f"</body>\n</html>"
        ).encode("utf-8")

        payload_hash = f.sha(html_page)
        rec_hash = f.sha(f"{target_url}|{last_event_nanos}|{payload_hash}".encode("utf-8"))
        captured_str = _format_rfc3339_nanos(last_event_nanos)

        replay_entry = {
            "url": target_url,
            "captured": captured_str,
            "source": "stack-exchange",
            "record_sha256": rec_hash,
            "payload_sha256": payload_hash,
            "size": len(html_page),
            "status": 200,
            "content_type": "text/html; charset=utf-8",
            "location": None,
        }
        kept.append(replay_entry)
        replay_blobs[payload_hash] = html_page

    def _search_builder(month_str: str) -> tuple[tuple[dict, ...], dict[str, bytes]]:
        if type(month_str) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}", month_str) is None:
            raise f.ArchiveError("invalid search month")
        month_boundary_nanos = parse_rfc3339_utc_nanos(f"{month_str}-01T00:00:00Z")
        s_docs: list[dict] = []
        s_blobs: dict[str, bytes] = {}
        for pid in sorted(post_events.keys()):
            if pid in undated_post_ids:
                continue
            evs = post_events[pid]
            t_url = _get_post_url(pid)
            st = _reconstruct_post_state(evs, month_boundary_nanos)
            if st is None:
                continue
            last_ev_nanos, raw_t, b_body = st
            clean_t = (raw_t or f"Post {pid}").strip()
            clean_t = re.sub(r"[\x00-\x1f\x7f]", "", clean_t)[:MAX_TITLE_BYTES] or f"Post {pid}"
            html_p = (
                f"<!DOCTYPE html>\n<html>\n<head><title>{_escape_html(clean_t)}</title></head>\n"
                f"<body>\n<h1>{_escape_html(clean_t)}</h1>\n"
                f'<div class="post-text">{b_body}</div>\n'
                f"</body>\n</html>"
            ).encode("utf-8")
            p_hash = f.sha(html_p)
            r_hash = f.sha(f"{t_url}|{last_ev_nanos}|{p_hash}".encode("utf-8"))
            cap_str = _format_rfc3339_nanos(last_ev_nanos)

            _, txt_bytes = extract_html_title_and_text(html_p, fallback_title=clean_t)
            txt_hash = f.sha(txt_bytes)
            s_blobs[txt_hash] = txt_bytes
            s_docs.append({
                "url": t_url,
                "captured": cap_str,
                "source": "stack-exchange",
                "record_sha256": r_hash,
                "text_sha256": txt_hash,
                "title": clean_t,
            })
        s_docs.sort(key=lambda x: (x["url"], x["captured"]))
        return tuple(s_docs), s_blobs

    initial_month = cutoff[:7]
    initial_search_docs, initial_search_blobs = _search_builder(initial_month)

    all_blobs = dict(replay_blobs)
    all_blobs.update(initial_search_blobs)
    sorted_blobs = tuple(sorted(all_blobs.items(), key=lambda x: x[0]))
    replay_blobs_tuple = tuple(sorted(replay_blobs.items(), key=lambda x: x[0]))
    search_blobs_tuple = tuple(sorted(initial_search_blobs.items(), key=lambda x: x[0]))

    kept.sort(key=lambda x: (x["url"], x["captured"]))
    return ImportReport(
        source="stack-exchange",
        kept=tuple(kept),
        search_documents=initial_search_docs,
        blobs=sorted_blobs,
        after_cutoff=tuple(sorted(set(after_cutoff))),
        undated=tuple(sorted(undated_urls)),
        replay_blobs=replay_blobs_tuple,
        search_blobs=search_blobs_tuple,
        _search_recipe_builder=_search_builder,
    )


def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _iter_xml_rows(xml_bytes: bytes):
    """Safely and boundedly iterate over XML <row ... /> attributes."""
    if b"<!ENTITY" in xml_bytes or b"<!DOCTYPE" in xml_bytes:
        raise f.ArchiveError("XML external entities and DTD declarations forbidden")

    stream = io.BytesIO(xml_bytes)
    try:
        context = ET.iterparse(stream, events=("start", "end"))
        depth = 0
        row_count = 0
        for event, elem in context:
            if event == "start":
                depth += 1
                if depth > MAX_XML_DEPTH:
                    raise f.ArchiveError("XML nesting depth cap exceeded")
            elif event == "end":
                depth -= 1
                if elem.tag.lower() == "row":
                    row_count += 1
                    if row_count > MAX_RECORDS * 4:
                        raise f.ArchiveError("XML row cap exceeded")
                    yield elem.attrib
                    elem.clear()
    except ET.ParseError as exc:
        raise f.ArchiveError("malformed XML document") from exc


def _parse_se_posts_metadata(posts_xml: bytes) -> dict[int, dict]:
    meta: dict[int, dict] = {}
    for row in _iter_xml_rows(posts_xml):
        pid_str = row.get("Id")
        if not pid_str or not pid_str.isdigit():
            continue
        pid = int(pid_str)
        ptype = int(row.get("PostTypeId", "1")) if row.get("PostTypeId", "1").isdigit() else 1
        meta[pid] = {
            "PostTypeId": ptype,
            "ParentId": int(row.get("ParentId", "0")) if row.get("ParentId", "0").isdigit() else None,
            "Title": row.get("Title"),
        }
    return meta


# ---------------------------------------------------------------------------
# 5. Descriptor-Pinned Safe File Importers
# ---------------------------------------------------------------------------

def _read_blobs_dir_bounded(blob_root) -> dict[str, bytes]:
    """Read regular files in blob directory using descriptor pinning and O_NOFOLLOW."""
    directory = None
    try:
        probe = os.path.join(os.fspath(blob_root), ".probe")
        validate_path(probe)
        directory, _ = open_parent(probe)
        blobs: dict[str, bytes] = {}
        eligible_count = 0
        total = 0
        # Iterate over directory entries
        with os.scandir(directory) as it:
            for entry in it:
                if entry.name.startswith("."):
                    continue
                # Ensure regular file and not symlink
                st = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode):
                    continue
                eligible_count += 1
                if eligible_count > f.MAX_RECORDS:
                    raise f.ArchiveError("blob directory capacity exceeded")
                if total + st.st_size > f.MAX_TOTAL_PAYLOAD_BYTES:
                    raise f.ArchiveError("blob directory capacity exceeded")
                content = read_regular_file_bounded(
                    entry.name,
                    min(f.MAX_PAYLOAD_BYTES, f.MAX_TOTAL_PAYLOAD_BYTES - total),
                    directory=directory,
                )
                total += len(content)
                blobs[entry.name] = content
        return blobs
    except f.ArchiveError:
        raise
    except (OSError, ValueError, TypeError, HermeticNpmCutError):
        raise f.ArchiveError("blob directory load failed") from None
    finally:
        if directory is not None:
            os.close(directory)


def import_common_crawl_warc_file(path, cutoff: str) -> ImportReport:
    try:
        validate_path(path)
        raw = read_regular_file_bounded(path, MAX_INPUT_BYTES)
        return import_common_crawl_warc(raw, cutoff)
    except (OSError, ValueError, TypeError, HermeticNpmCutError) as exc:
        raise f.ArchiveError("failed to read warc file") from exc


def import_common_crawl_cdx_files(cdx_path, blob_dir, cutoff: str) -> ImportReport:
    try:
        validate_path(cdx_path)
        raw = read_regular_file_bounded(cdx_path, MAX_INPUT_BYTES)
        blobs = _read_blobs_dir_bounded(blob_dir)
        return import_common_crawl_cdx(raw, blobs, cutoff)
    except (OSError, ValueError, TypeError, HermeticNpmCutError) as exc:
        raise f.ArchiveError("failed to read cdx file or blobs") from exc


def import_wayback_cdx_files(cdx_path, blob_dir, cutoff: str) -> ImportReport:
    try:
        validate_path(cdx_path)
        raw = read_regular_file_bounded(cdx_path, MAX_INPUT_BYTES)
        blobs = _read_blobs_dir_bounded(blob_dir)
        return import_wayback_cdx(raw, blobs, cutoff)
    except (OSError, ValueError, TypeError, HermeticNpmCutError) as exc:
        raise f.ArchiveError("failed to read wayback cdx file or blobs") from exc


def import_software_heritage_files(snapshot_path, blob_dir, cutoff: str) -> ImportReport:
    try:
        validate_path(snapshot_path)
        raw = read_regular_file_bounded(snapshot_path, MAX_INPUT_BYTES)
        blobs = _read_blobs_dir_bounded(blob_dir)
        return import_software_heritage(raw, blobs, cutoff)
    except (OSError, ValueError, TypeError, HermeticNpmCutError) as exc:
        raise f.ArchiveError("failed to read swh snapshot file or blobs") from exc


def import_stack_exchange_files(
    post_history_path,
    cutoff: str,
    site_url: str = "https://stackoverflow.com",
    posts_path = None,
) -> ImportReport:
    try:
        validate_path(post_history_path)
        raw_history = read_regular_file_bounded(post_history_path, MAX_INPUT_BYTES)
        raw_posts = None
        if posts_path is not None:
            validate_path(posts_path)
            raw_posts = read_regular_file_bounded(posts_path, MAX_INPUT_BYTES)
        return import_stack_exchange(raw_history, cutoff, site_url, raw_posts)
    except (OSError, ValueError, TypeError, HermeticNpmCutError) as exc:
        raise f.ArchiveError("failed to read stack exchange files") from exc
