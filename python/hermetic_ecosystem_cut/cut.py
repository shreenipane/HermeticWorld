"""Bounded staging transforms implementing architecture §6.4.

Missing publication dates exclude the version and appear in the report. Invalid
metadata aborts the transform. Timestamps use strict RFC3339 UTC with nanoseconds.
Crate records retain Cargo's schema; Go .info output contains only Version/Time,
so current proxy Origin metadata cannot reach the sealed world.
"""

from dataclasses import dataclass
import json
import re

from hermetic_npm_cut.cut import (
    HermeticNpmCutError,
    canonical_json_bytes,
    parse_json_bytes,
    parse_rfc3339_utc_nanos,
    parse_semver,
)

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_RECORDS = 20_000
MAX_VERSION_BYTES = 256
MAX_NAME_BYTES = 64
MAX_OUTPUT_BYTES = MAX_INPUT_BYTES
CRATE_FIELDS = frozenset({"name", "vers", "deps", "cksum", "features", "yanked",
                          "links", "v", "features2", "rust_version", "pubtime"})


class CutError(ValueError):
    """Sanitized failure; input values and parser exception text are never rendered."""


@dataclass(frozen=True)
class CutReport:
    kept: tuple[str, ...]
    after_cutoff: tuple[str, ...]
    unknown: tuple[str, ...]
    yank_unknown: tuple[str, ...] = ()


def _bytes(raw: bytes, cap: int) -> None:
    if type(raw) is not bytes or len(raw) > cap:
        raise CutError("metadata byte cap or type violation")


def _json(raw: bytes) -> dict:
    _bytes(raw, MAX_RECORD_BYTES)
    try:
        value = parse_json_bytes(raw, MAX_RECORD_BYTES)
    except HermeticNpmCutError:
        raise CutError("invalid metadata JSON") from None
    if type(value) is not dict:
        raise CutError("metadata record must be an object")
    return value


def _time(value: str) -> int:
    try:
        return parse_rfc3339_utc_nanos(value)
    except HermeticNpmCutError:
        raise CutError("invalid UTC publication timestamp") from None


def _version(value: str, *, go: bool = False) -> str:
    if type(value) is not str or not 0 < len(value) <= MAX_VERSION_BYTES:
        raise CutError("invalid version")
    core = value.removeprefix("v") if go else value
    parsed = parse_semver(core)
    if ((go and not value.startswith("v")) or parsed is None
            or (go and parsed.build not in (None, ("incompatible",)))):
        raise CutError("invalid version")
    return value


def _encode(value: dict) -> bytes:
    # JSON accepts 1e999 as infinity; never emit a non-standard JSON number.
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError):
        raise CutError("unencodable metadata") from None


def _crate_schema(record: dict) -> None:
    """Validate nested Cargo fields before preserving them, even on excluded rows."""
    def text(value):
        return type(value) is str and bool(value) and "\0" not in value

    for field in ("features", "features2"):
        if field not in record and field == "features2":
            continue
        features = record.get(field)
        if type(features) is not dict or any(
                not text(key) or type(values) is not list
                or any(not text(value) for value in values)
                for key, values in features.items()):
            raise CutError("invalid crate features")
    if ("v" in record and (type(record["v"]) is not int or record["v"] not in (1, 2))):
        raise CutError("unsupported crate schema version")
    for field in ("links", "rust_version"):
        if record.get(field) is not None and not text(record[field]):
            raise CutError("invalid crate optional field")
    fields = {"name", "req", "features", "optional", "default_features", "target",
              "kind", "registry", "package"}
    for dep in record["deps"]:
        if (type(dep) is not dict or set(dep) - fields
                or not text(dep.get("name")) or not text(dep.get("req"))
                or type(dep.get("features")) is not list
                or any(not text(value) for value in dep["features"])
                or type(dep.get("optional")) is not bool
                or type(dep.get("default_features")) is not bool
                or dep.get("kind") not in (None, "normal", "build", "dev")):
            raise CutError("invalid crate dependency")
        for field in ("target", "registry", "package"):
            if dep.get(field) is not None and not text(dep[field]):
                raise CutError("invalid crate dependency field")


def cut_crates_index(raw: bytes, cutoff: str) -> tuple[bytes, CutReport]:
    """Filter one crate's newline-delimited sparse-index response by pubtime.

Unknown versions are omitted. Duplicate versions, mixed crate names, malformed
records and exceeded caps abort the whole transform without a partial result.
    As in TR-PKG-2, unknown yank dates mean serve as not yanked and list the
    uncertainty. Present-day yank flags are never published as historical truth.
    This accepts HTTP index JSON, not Cargo's cache.
"""
    boundary = _time(cutoff)
    _bytes(raw, MAX_INPUT_BYTES)
    kept: dict[str, bytes] = {}
    future: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    name: str | None = None
    total = 0
    # Byte cap bounds splitting as well as parsing; record cap bounds work further.
    lines = raw.splitlines()
    if len(lines) > MAX_RECORDS:
        raise CutError("metadata record cap exceeded")
    for line in lines:
        record = _json(line)
        if set(record) - CRATE_FIELDS:
            raise CutError("unsupported crate metadata field")
        current_name = record.get("name")
        if (type(current_name) is not str or len(current_name) > MAX_NAME_BYTES
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", current_name) is None):
            raise CutError("invalid crate name")
        if name is not None and name != current_name:
            raise CutError("mixed crate names")
        name = current_name
        version = _version(record.get("vers"))
        identity = version.split("+", 1)[0]
        if identity in seen:
            raise CutError("duplicate version")
        seen.add(identity)
        if (type(record.get("deps")) is not list
                or type(record.get("features")) is not dict
                or type(record.get("cksum")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", record["cksum"]) is None
                or type(record.get("yanked")) is not bool):
            raise CutError("invalid crate metadata schema")
        _crate_schema(record)
        # Validate even excluded records, including non-finite numeric extensions.
        _encode(record)
        date = record.get("pubtime")
        if date is None:
            unknown.append(version)
        elif _time(date) > boundary:
            future.append(version)
        else:
            record["yanked"] = False
            encoded = _encode(record)
            total += len(encoded) + 1
            if total > MAX_OUTPUT_BYTES:
                raise CutError("metadata output cap exceeded")
            kept[version] = encoded
    report = CutReport(tuple(sorted(kept)), tuple(sorted(future)), tuple(sorted(unknown)),
                       tuple(sorted(kept)))
    return b"".join(kept[version] + b"\n" for version in report.kept), report


def cut_go_versions(raw_list: bytes, infos: dict[str, bytes], cutoff: str
                    ) -> tuple[bytes, dict[str, bytes], CutReport]:
    """Filter /@v/list using exact matching /@v/<version>.info records.

Missing .info or Time is unknown and excluded. Never infer a date from a version,
file mtime or host clock. Callers must also deny excluded .mod/.zip/.info paths
and build any @latest response exclusively from admitted versions.
"""
    boundary = _time(cutoff)
    _bytes(raw_list, MAX_INPUT_BYTES)
    if type(infos) is not dict or len(infos) > MAX_RECORDS:
        raise CutError("info record cap or type violation")
    # Retain the immutable records covered by the aggregate budget while parsing.
    infos = infos.copy()
    if len(infos) > MAX_RECORDS:
        raise CutError("info record cap or type violation")
    total_input = len(raw_list)
    for key, data in infos.items():
        _version(key, go=True)
        _bytes(data, MAX_RECORD_BYTES)
        total_input += len(data)
        if total_input > MAX_INPUT_BYTES:
            raise CutError("metadata aggregate byte cap exceeded")
    try:
        lines = raw_list.decode("ascii").splitlines()
    except UnicodeError:
        raise CutError("invalid version list") from None
    if len(lines) > MAX_RECORDS:
        raise CutError("metadata record cap exceeded")
    seen: set[str] = set()
    kept: dict[str, bytes] = {}
    future: list[str] = []
    unknown: list[str] = []
    total_output = 0
    for line in lines:
        version = _version(line, go=True)
        if version in seen:
            raise CutError("duplicate version")
        seen.add(version)
        data = infos.get(version)
        if data is None:
            unknown.append(version)
            continue
        record = _json(data)
        if record.get("Version") != version:
            raise CutError("info version mismatch")
        _encode(record)
        date = record.get("Time")
        if date is None:
            unknown.append(version)
        elif _time(date) > boundary:
            future.append(version)
        else:
            kept[version] = canonical_json_bytes({"Version": version, "Time": date})
            total_output += len(kept[version]) + len(version) + 1
            if total_output > MAX_OUTPUT_BYTES:
                raise CutError("metadata output cap exceeded")
    if set(infos) - seen:
        raise CutError("unlisted info version")
    report = CutReport(tuple(sorted(kept)), tuple(sorted(future)), tuple(sorted(unknown)))
    return ("".join(version + "\n" for version in report.kept).encode("ascii"),
            {version: kept[version] for version in report.kept}, report)
