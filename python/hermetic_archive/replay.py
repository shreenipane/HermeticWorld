"""Exact URL lookup over an authenticated, cutoff-bound offline capture index.

Only payload bytes and explicitly selected response fields are replayed. Raw
archive headers, archive URLs, cookies, clocks and source-server identity never
enter a response. Acquisition digests are evidence identifiers, not proof that
the capture date or the content's revision history is authentic.
"""

from dataclasses import dataclass
import os
import re

from hermetic_npm_cut.cut import HermeticNpmCutError, read_regular_file_bounded
from hermetic_safe_io import open_parent, validate_path

from . import formats as f

FIELDS = {"url", "captured", "source", "record_sha256", "payload_sha256", "size",
          "status", "content_type", "location"}
DOCUMENT_FIELDS = {"schema", "cutoff", "captures"}
SCHEMA = "hermetic-replay-index/v1"


@dataclass(frozen=True)
class ReplayBuild:
    index: bytes
    blobs: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class ReplayResponse:
    status: int
    content_type: str
    location: str | None
    content_length: int
    body: bytes


def _entries(value) -> list[dict]:
    entries = f.captures(value, FIELDS)
    for entry in entries:
        if type(entry["source"]) is not str or entry["source"] not in f.SOURCES:
            raise f.ArchiveError("invalid archive source")
        f.digest(entry["record_sha256"])
        f.digest(entry["payload_sha256"])
        if type(entry["size"]) is not int or not 0 <= entry["size"] <= f.MAX_PAYLOAD_BYTES:
            raise f.ArchiveError("invalid archive payload size")
        status = entry["status"]
        if type(status) is not int or not 200 <= status <= 599 or status == 304:
            raise f.ArchiveError("invalid archive response status")
        content_type = entry["content_type"]
        if (type(content_type) is not str or len(content_type) > f.MAX_CONTENT_TYPE_BYTES
                or re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+(?:; charset=[a-zA-Z0-9_-]+)?",
                                content_type) is None):
            raise f.ArchiveError("invalid archive content type")
        location = entry["location"]
        if location is not None:
            f.url(location)
        if (status in {301, 302, 303, 307, 308}) != (location is not None):
            raise f.ArchiveError("invalid archive redirect")
        if status in {204, 205} and entry["size"] != 0:
            raise f.ArchiveError("archive empty response has a payload")
    return entries


def build_replay_index(raw_recipe: bytes, blobs: dict[str, bytes]) -> ReplayBuild:
    """Select the latest exact capture per URL at or before the supplied cutoff.

    Recipe schema is hermetic-replay-recipe/v1. All records and payloads, even
    excluded records, are validated. Only selected blobs leave this function.
    This prepares private local bytes; it does not publish archived pages.
    """
    recipe = f.document(raw_recipe, DOCUMENT_FIELDS)
    if recipe["schema"] != "hermetic-replay-recipe/v1":
        raise f.ArchiveError("unsupported archive recipe schema")
    boundary = f.timestamp(recipe["cutoff"])
    entries = _entries(recipe["captures"])
    blobs = f.payloads(blobs, {entry["payload_sha256"] for entry in entries})
    selected = {}
    for entry in entries:
        if len(blobs[entry["payload_sha256"]]) != entry["size"]:
            raise f.ArchiveError("archive payload size mismatch")
        date = f.timestamp(entry["captured"])
        previous = selected.get(entry["url"])
        if date <= boundary and (previous is None or date > f.timestamp(previous["captured"])):
            selected[entry["url"]] = entry
    ordered = [selected[key] for key in sorted(selected)]
    raw = f.bounded_encoding({"schema": SCHEMA, "cutoff": recipe["cutoff"], "captures": ordered})
    references = {entry["payload_sha256"] for entry in ordered}
    return ReplayBuild(raw, tuple((key, blobs[key]) for key in sorted(references)))


def _parse(raw_index: bytes, expected_sha256: str, cutoff: str) -> list[dict]:
    boundary = f.timestamp(cutoff)
    value = f.authenticated(raw_index, expected_sha256, DOCUMENT_FIELDS)
    if value["schema"] != SCHEMA or value["cutoff"] != cutoff:
        raise f.ArchiveError("archive schema or cutoff mismatch")
    entries = _entries(value["captures"])
    urls = [entry["url"] for entry in entries]
    if urls != sorted(set(urls)) or any(f.timestamp(entry["captured"]) > boundary for entry in entries):
        raise f.ArchiveError("archive index order or admission violation")
    return entries


class ReplayIndex:
    def __init__(self, raw_index: bytes, blobs: dict[str, bytes], expected_sha256: str, cutoff: str):
        entries = _parse(raw_index, expected_sha256, cutoff)
        blobs = f.payloads(blobs, {entry["payload_sha256"] for entry in entries})
        self._responses = {}
        for entry in entries:
            body = blobs[entry["payload_sha256"]]
            if len(body) != entry["size"]:
                raise f.ArchiveError("archive payload size mismatch")
            self._responses[entry["url"]] = ReplayResponse(
                entry["status"], entry["content_type"], entry["location"], len(body), body)

    def lookup(self, url: str, method: str = "GET") -> ReplayResponse | None:
        f.url(url)
        if type(method) is not str or method not in {"GET", "HEAD"}:
            raise f.ArchiveError("unsupported archive request method")
        response = self._responses.get(url)
        if response is None or method == "GET":
            return response
        return ReplayResponse(response.status, response.content_type, response.location,
                              response.content_length, b"")


def load_replay_files(index_path, blob_root, expected_sha256: str, cutoff: str) -> ReplayIndex:
    """Read bounded regular files using a pinned blob-root directory descriptor."""
    directory = None
    try:
        f.digest(expected_sha256)
        f.timestamp(cutoff)
        validate_path(index_path)
        probe = os.path.join(os.fspath(blob_root), ".probe")
        validate_path(probe)
        raw = read_regular_file_bounded(index_path, f.MAX_INDEX_BYTES)
        entries = _parse(raw, expected_sha256, cutoff)
        references = {entry["payload_sha256"] for entry in entries}
        directory, _ = open_parent(probe)
        blobs = {}
        total = 0
        for key in sorted(references):
            body = read_regular_file_bounded(
                key, min(f.MAX_PAYLOAD_BYTES, f.MAX_TOTAL_PAYLOAD_BYTES - total), directory=directory)
            total += len(body)
            blobs[key] = body
        return ReplayIndex(raw, blobs, expected_sha256, cutoff)
    except (OSError, ValueError, TypeError, HermeticNpmCutError):
        raise f.ArchiveError("archive file load failed") from None
    finally:
        if directory is not None:
            os.close(directory)
