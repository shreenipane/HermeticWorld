"""Shared byte, schema and URL validation; no network or host metadata access."""

import hashlib
import json
import re
from urllib.parse import urlsplit

from hermetic_npm_cut.cut import HermeticNpmCutError, parse_json_bytes, parse_rfc3339_utc_nanos

MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 4096
MAX_URL_BYTES = 2048
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_TOTAL_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_CONTENT_TYPE_BYTES = 128
SOURCES = frozenset({"common-crawl", "wayback", "software-heritage", "stack-exchange"})


class ArchiveError(ValueError):
    """Fixed diagnostics never include input values, paths or parser errors."""


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ArchiveError("invalid archive digest")
    return value


def timestamp(value) -> int:
    try:
        return parse_rfc3339_utc_nanos(value)
    except HermeticNpmCutError:
        raise ArchiveError("invalid archive timestamp") from None


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def document(raw: bytes, fields: set[str]) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INDEX_BYTES:
        raise ArchiveError("archive index byte cap or type violation")
    try:
        value = parse_json_bytes(raw, MAX_INDEX_BYTES)
    except HermeticNpmCutError:
        raise ArchiveError("invalid archive JSON") from None
    if type(value) is not dict or set(value) != fields:
        raise ArchiveError("invalid archive document fields")
    return value


def authenticated(raw: bytes, expected_sha256: str, fields: set[str]) -> dict:
    digest(expected_sha256)
    # Check the byte cap before hashing attacker-controlled bytes.
    value = document(raw, fields)
    if sha(raw) != expected_sha256 or encode(value) != raw:
        raise ArchiveError("archive index authentication or canonical encoding failed")
    return value


def url(value) -> str:
    if (type(value) is not str or not 0 < len(value) <= MAX_URL_BYTES
            or not value.isascii() or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
            or "\\" in value or "#" in value):
        raise ArchiveError("invalid archive URL")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ArchiveError("invalid archive URL") from None
    # Strict canonical DNS authorities keep identity independent of resolver,
    # locale, percent decoding, credentials and default-port normalization.
    if (parts.scheme not in {"http", "https"} or not value.startswith(parts.scheme + "://")
            or not host or parts.netloc != host
            or port is not None or len(host) > 253
            or "." not in host or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                for label in host.split("."))
            or not parts.path.startswith("/")):
        raise ArchiveError("noncanonical archive URL")
    if (re.search(r"%(?![0-9A-F]{2})", value)
            or any(part in {".", ".."} for part in parts.path.split("/"))):
        raise ArchiveError("noncanonical archive URL path")
    return value


def captures(value, fields: set[str]) -> list[dict]:
    if type(value) is not list or len(value) > MAX_RECORDS:
        raise ArchiveError("archive record count cap or type violation")
    seen = set()
    for entry in value:
        if type(entry) is not dict or set(entry) != fields:
            raise ArchiveError("invalid archive record fields")
        url(entry.get("url"))
        date = timestamp(entry.get("captured"))
        # Nanosecond identity also rejects different spellings of one instant.
        identity = (entry["url"], date)
        if identity in seen:
            raise ArchiveError("duplicate archive capture")
        seen.add(identity)
    return value


def payloads(blobs, references: set[str]) -> dict[str, bytes]:
    if type(blobs) is not dict or len(blobs) > MAX_RECORDS:
        raise ArchiveError("archive payload count cap or type violation")
    # Hashing may release the interpreter lock. Keep the same immutable bodies
    # for validation and consumption if the caller changes its mapping.
    blobs = blobs.copy()
    if len(blobs) > MAX_RECORDS:
        raise ArchiveError("archive payload count cap or type violation")
    total = 0
    for key, body in blobs.items():
        digest(key)
        if type(body) is not bytes or len(body) > MAX_PAYLOAD_BYTES:
            raise ArchiveError("archive payload byte cap or type violation")
        total += len(body)
        if total > MAX_TOTAL_PAYLOAD_BYTES:
            raise ArchiveError("archive aggregate payload cap exceeded")
        if sha(body) != key:
            raise ArchiveError("archive payload digest mismatch")
    if set(blobs) != references:
        raise ArchiveError("archive payload inventory mismatch")
    return blobs


def bounded_encoding(value) -> bytes:
    raw = encode(value)
    if len(raw) > MAX_INDEX_BYTES:
        raise ArchiveError("archive output index byte cap exceeded")
    return raw
