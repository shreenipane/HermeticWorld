"""Validated and capped baseline specification for Hermetic World Layer 2.

A baseline spec defines:
1. Cutoff month (YYYY-MM), governing the first second of that month.
2. Fixed tool list (pytest + plugins, hypothesis, mypy, tox, coverage, Cython,
   setuptools, wheel, ipdb, pip, uv; versions resolved at the cutoff).
3. Top-N packages per ecosystem (N capped), with PyPI top packages read
   from a local file (never fetched over network).

All reads and loops are bounded by named constants.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any

from .errors import CapExceededError, SpecValidationError
from .safe_io import safe_read_bytes

MAX_SPEC_BYTES: int = 1024 * 1024  # 1 MiB
MAX_FIXED_TOOLS: int = 256
MAX_TOP_N: int = 10_000
MAX_ECOSYSTEMS: int = 16
MAX_PACKAGE_NAME_BYTES: int = 256
MAX_FILENAME_BYTES: int = 255
MAX_FILE_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_TOP_PACKAGES_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MiB
MAX_TOP_PACKAGES_ENTRIES: int = 20_000
MAX_PARSE_LOOPS: int = 50_000

# Canonical developer and test tool list per TR-PKG-4 and architecture §6.3.
CANONICAL_FIXED_TOOLS: tuple[str, ...] = (
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "pytest-mock",
    "pytest-rerunfailures",
    "pytest-timeout",
    "pytest-xdist",
    "hypothesis",
    "mypy",
    "tox",
    "coverage",
    "cython",
    "setuptools",
    "wheel",
    "ipdb",
    "pip",
    "uv",
)

_PEP503_NORM_RE = re.compile(r"[-_.]+")
_PEP508_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_CUTOFF_MONTH_RE = re.compile(r"^([0-9]{4})-(0[1-9]|1[0-2])$")
_DIST_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def normalize_project_name(name: str) -> str:
    """Validate and normalize a project name according to PEP 503."""
    if not isinstance(name, str) or not name:
        raise SpecValidationError("Project name must be a non-empty string.")
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_PACKAGE_NAME_BYTES:
        raise SpecValidationError("Project name exceeds maximum byte length.")
    if not _PEP508_NAME_RE.fullmatch(name):
        raise SpecValidationError(f"Invalid project name: {name!r}")
    return _PEP503_NORM_RE.sub("-", name).lower()


def validate_distribution_filename(name: str) -> str:
    """Validate a distribution filename strictly according to conservative distribution rules.

    Must be a single component, conservative distribution-filename charset,
    no '/', '\\', NUL, '.', '..', leading dot, and bounded length.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("Distribution filename must be a non-empty string.")
    if len(name) > MAX_FILENAME_BYTES:
        raise ValueError(
            f"Filename exceeds maximum length of {MAX_FILENAME_BYTES} characters."
        )
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Filename contains non-UTF-8 characters.") from exc
    if len(encoded) > MAX_FILENAME_BYTES:
        raise ValueError(
            f"Filename exceeds maximum byte limit of {MAX_FILENAME_BYTES}."
        )
    if "/" in name or "\\" in name or "\0" in name:
        raise ValueError(f"Filename contains path separators or null bytes: {name!r}")
    if name == "." or name == ".." or name.startswith("."):
        raise ValueError(f"Filename has leading dot or invalid traversal name: {name!r}")
    if not _DIST_FILENAME_RE.fullmatch(name):
        raise ValueError(f"Filename contains illegal characters: {name!r}")
    return name


def parse_cutoff_month(month_str: str) -> tuple[int, int, str, int]:
    """Parse YYYY-MM and compute cutoff ISO timestamp and nanoseconds.

    The cutoff is the first second of the cutoff month (YYYY-MM-01T00:00:00Z).
    Returns (year, month, iso_timestamp, epoch_nanoseconds).
    """
    if not isinstance(month_str, str) or len(month_str) != 7:
        raise SpecValidationError(f"Invalid cutoff month string: {month_str!r}")
    match = _CUTOFF_MONTH_RE.fullmatch(month_str)
    if not match:
        raise SpecValidationError(
            f"Cutoff month must match YYYY-MM with month 01-12: {month_str!r}"
        )
    year = int(match.group(1))
    month = int(match.group(2))
    if year < 1970 or year > 9999:
        raise SpecValidationError(f"Year out of supported range: {year}")

    iso_timestamp = f"{year:04d}-{month:02d}-01T00:00:00Z"
    sec = calendar.timegm((year, month, 1, 0, 0, 0, 0, 0, 0))
    epoch_ns = sec * 1_000_000_000
    return year, month, iso_timestamp, epoch_ns


def parse_top_packages_file(
    file_path: str | Path,
    max_count: int,
    max_file_bytes: int = MAX_TOP_PACKAGES_FILE_BYTES,
) -> list[str]:
    """Parse a local top packages file without network access, bounded by caps.

    Supports JSON list of project names, JSON objects with 'rows'/'projects',
    or newline-separated project names (ignoring comments starting with '#').
    """
    if max_count <= 0:
        return []
    if max_count > MAX_TOP_N:
        raise CapExceededError(f"Requested count {max_count} exceeds MAX_TOP_N {MAX_TOP_N}")

    raw_bytes = safe_read_bytes(file_path, max_bytes=max_file_bytes)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecValidationError("Top packages file must be valid UTF-8.") from exc

    packages: list[str] = []
    seen: set[str] = set()

    # Attempt parsing as JSON first
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            candidate_list: list[Any] = []
            if isinstance(data, list):
                candidate_list = data
            elif isinstance(data, dict):
                if isinstance(data.get("rows"), list):
                    candidate_list = data["rows"]
                elif isinstance(data.get("projects"), list):
                    candidate_list = data["projects"]
                else:
                    raise SpecValidationError("JSON top packages object missing 'rows' or 'projects' list.")
            else:
                raise SpecValidationError("Invalid JSON top packages structure.")

            loop_count = 0
            for item in candidate_list:
                loop_count += 1
                if loop_count > MAX_TOP_PACKAGES_ENTRIES:
                    break
                name: str | None = None
                if isinstance(item, str):
                    name = item
                elif isinstance(item, dict):
                    name = item.get("project") or item.get("name")

                if name and isinstance(name, str):
                    norm = normalize_project_name(name)
                    if norm not in seen:
                        seen.add(norm)
                        packages.append(norm)
                        if len(packages) >= max_count:
                            break
            return packages
        except (json.JSONDecodeError, ValueError) as exc:
            # If JSON parse failed on JSON-like text, raise typed error
            if isinstance(exc, SpecValidationError):
                raise
            raise SpecValidationError("Failed to parse JSON top packages file.") from exc

    # Parse as line-delimited text
    loop_count = 0
    for line in text.splitlines():
        loop_count += 1
        if loop_count > MAX_TOP_PACKAGES_ENTRIES:
            break
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned:
            continue
        norm = normalize_project_name(cleaned)
        if norm not in seen:
            seen.add(norm)
            packages.append(norm)
            if len(packages) >= max_count:
                break

    return packages


@dataclass(frozen=True, slots=True)
class BaselineSpec:
    """Validated, capped specification for building a Layer 2 baseline."""

    cutoff_month: str
    year: int
    month: int
    cutoff_timestamp: str
    cutoff_epoch_ns: int
    fixed_tools: tuple[str, ...]
    top_n_per_ecosystem: dict[str, int]
    top_packages_files: dict[str, str]

    def get_seed_packages(self, ecosystem: str = "pypi") -> list[str]:
        """Return the combined seed packages (fixed tools + top-N) for an ecosystem."""
        if ecosystem != "pypi":
            return []

        seeds: list[str] = []
        seen: set[str] = set()

        for tool in self.fixed_tools:
            norm = normalize_project_name(tool)
            if norm not in seen:
                seen.add(norm)
                seeds.append(norm)

        top_n = self.top_n_per_ecosystem.get(ecosystem, 0)
        top_file = self.top_packages_files.get(ecosystem)

        if top_n > 0:
            if not top_file:
                raise SpecValidationError(
                    f"Ecosystem {ecosystem!r} has top_n={top_n} but no top packages file configured."
                )
            top_pkgs = parse_top_packages_file(top_file, max_count=top_n)
            for pkg in top_pkgs:
                if pkg not in seen:
                    seen.add(pkg)
                    seeds.append(pkg)

        return seeds

    def to_dict(self) -> dict[str, Any]:
        """Convert specification to a plain dictionary."""
        return {
            "cutoff_month": self.cutoff_month,
            "cutoff_timestamp": self.cutoff_timestamp,
            "fixed_tools": list(self.fixed_tools),
            "top_n_per_ecosystem": dict(self.top_n_per_ecosystem),
            "top_packages_files": dict(self.top_packages_files),
        }

    def to_canonical_json(self) -> str:
        """Render deterministic, canonical JSON representation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def parse_spec(data: str | bytes | dict[str, Any] | os.PathLike[str]) -> BaselineSpec:
    """Validate and parse a baseline specification dictionary, JSON string, or file.

    All bounds and caps are strictly enforced.
    """
    raw_dict: dict[str, Any]
    if isinstance(data, (str, bytes)):
        if isinstance(data, str) and not data.strip().startswith("{"):
            # Path to file
            content = safe_read_bytes(data, max_bytes=MAX_SPEC_BYTES)
            try:
                raw_dict = json.loads(content.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise SpecValidationError("Failed to parse spec JSON file.") from exc
        else:
            raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
            if len(raw_bytes) > MAX_SPEC_BYTES:
                raise CapExceededError(f"Spec exceeds maximum byte cap ({MAX_SPEC_BYTES}).")
            try:
                raw_dict = json.loads(raw_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise SpecValidationError("Invalid spec JSON string.") from exc
    elif isinstance(data, Path):
        content = safe_read_bytes(data, max_bytes=MAX_SPEC_BYTES)
        try:
            raw_dict = json.loads(content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SpecValidationError("Failed to parse spec JSON file.") from exc
    elif isinstance(data, dict):
        raw_dict = data
    else:
        raise SpecValidationError("Spec input must be a dict, JSON string/bytes, or Path.")

    if not isinstance(raw_dict, dict):
        raise SpecValidationError("Spec root must be a JSON object.")

    # Validate cutoff month
    raw_month = raw_dict.get("cutoff_month")
    if not isinstance(raw_month, str):
        raise SpecValidationError("Missing or non-string 'cutoff_month' in spec.")
    year, month, iso_ts, epoch_ns = parse_cutoff_month(raw_month)

    # Validate fixed tools
    tools_val = raw_dict.get("fixed_tools")
    fixed_tools_list: list[str] = []
    if tools_val is None:
        fixed_tools_list = list(CANONICAL_FIXED_TOOLS)
    elif isinstance(tools_val, list):
        if len(tools_val) > MAX_FIXED_TOOLS:
            raise CapExceededError(f"Fixed tools count exceeds cap {MAX_FIXED_TOOLS}")
        seen_tools: set[str] = set()
        for item in tools_val:
            if not isinstance(item, str):
                raise SpecValidationError("Each fixed tool must be a string.")
            norm = normalize_project_name(item)
            if norm not in seen_tools:
                seen_tools.add(norm)
                fixed_tools_list.append(norm)
    else:
        raise SpecValidationError("'fixed_tools' must be a list of project name strings.")

    # Validate top-N per ecosystem
    top_n_per_ecosystem: dict[str, int] = {}
    raw_top_n = raw_dict.get("top_n_per_ecosystem")
    if raw_top_n is not None:
        if not isinstance(raw_top_n, dict):
            raise SpecValidationError("'top_n_per_ecosystem' must be a dictionary.")
        if len(raw_top_n) > MAX_ECOSYSTEMS:
            raise CapExceededError(f"Ecosystem count exceeds cap {MAX_ECOSYSTEMS}")
        for eco, count in raw_top_n.items():
            if not isinstance(eco, str) or not eco:
                raise SpecValidationError("Ecosystem name must be a non-empty string.")
            if not isinstance(count, int) or count < 0:
                raise SpecValidationError(f"Top-N for ecosystem {eco!r} must be a non-negative integer.")
            if count > MAX_TOP_N:
                raise CapExceededError(f"Top-N for ecosystem {eco!r} exceeds cap {MAX_TOP_N}")
            top_n_per_ecosystem[eco] = count
    elif "top_n" in raw_dict:
        # Ergonomic alias: "top_n": 50 or "top_n": {"pypi": 50}
        val = raw_dict["top_n"]
        if isinstance(val, int):
            if val < 0:
                raise SpecValidationError("top_n must be a non-negative integer.")
            if val > MAX_TOP_N:
                raise CapExceededError(f"top_n exceeds cap {MAX_TOP_N}")
            top_n_per_ecosystem["pypi"] = val
        elif isinstance(val, dict):
            if len(val) > MAX_ECOSYSTEMS:
                raise CapExceededError(f"Ecosystem count exceeds cap {MAX_ECOSYSTEMS}")
            for eco, count in val.items():
                if not isinstance(eco, str) or not isinstance(count, int) or count < 0:
                    raise SpecValidationError("Invalid top_n ecosystem mapping.")
                if count > MAX_TOP_N:
                    raise CapExceededError(f"top_n for {eco} exceeds cap {MAX_TOP_N}")
                top_n_per_ecosystem[eco] = count
        else:
            raise SpecValidationError("'top_n' must be an integer or mapping.")

    # Validate top packages files
    top_packages_files: dict[str, str] = {}
    raw_files = raw_dict.get("top_packages_files")
    if raw_files is not None:
        if not isinstance(raw_files, dict):
            raise SpecValidationError("'top_packages_files' must be a dictionary.")
        if len(raw_files) > MAX_ECOSYSTEMS:
            raise CapExceededError(f"Top packages files count exceeds cap {MAX_ECOSYSTEMS}")
        for eco, fpath in raw_files.items():
            if not isinstance(eco, str) or not isinstance(fpath, str):
                raise SpecValidationError("Ecosystem and file path must be strings.")
            top_packages_files[eco] = fpath
    elif "top_packages_file" in raw_dict:
        fval = raw_dict["top_packages_file"]
        if not isinstance(fval, str):
            raise SpecValidationError("'top_packages_file' must be a string path.")
        top_packages_files["pypi"] = fval

    return BaselineSpec(
        cutoff_month=raw_month,
        year=year,
        month=month,
        cutoff_timestamp=iso_ts,
        cutoff_epoch_ns=epoch_ns,
        fixed_tools=tuple(fixed_tools_list),
        top_n_per_ecosystem=top_n_per_ecosystem,
        top_packages_files=top_packages_files,
    )
