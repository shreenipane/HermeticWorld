
"""Deterministic comparison engine and report builder for Detector D7."""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any

from hermetic_d7.normalise import (
    MAX_DIFF_INPUT_LINES,
    MAX_DIFF_LINES,
    MAX_TEXT_DIFF_BYTES,
    PYC_HEADER_SIZE,
    HermeticD7Error,
    NormalisedMember,
    ResourceLimitError,
    ResourceLimits,
    load_artifact,
)

AUDIT_POLICY_STATEMENT: str = (
    "Detector D7 is audit-only; a 'differs' verdict never gates by itself."
)

NORMALISATION_DOCUMENTATION: dict[str, Any] = {
    "line_endings": "not_normalised",
    "permissions": "executable_bit_only",
    "pkg_info_metadata": "trailing_blank_lines_dropped",
    "pyc_header_bytes_skipped": PYC_HEADER_SIZE,
    "timestamps": "ignored",
    "wheel_record": "sorted_lines_without_self_entry",
}


def build_unified_diff(
    member_path: str,
    data_shipped: bytes,
    data_rebuilt: bytes,
    *,
    max_text_bytes: int = MAX_TEXT_DIFF_BYTES,
    max_diff_lines: int = MAX_DIFF_LINES,
    max_input_lines: int = MAX_DIFF_INPUT_LINES,
) -> tuple[bool, str | None, bool]:
    """Build a bounded unified diff for UTF-8 text members under size caps.

    Returns (is_text, unified_diff_or_none, truncated).
    Binary members or members exceeding caps return (False, None, False).
    """
    if len(data_shipped) > max_text_bytes or len(data_rebuilt) > max_text_bytes:
        return False, None, False

    try:
        text_shipped = data_shipped.decode("utf-8")
        text_rebuilt = data_rebuilt.decode("utf-8")
    except UnicodeDecodeError:
        return False, None, False

    lines_shipped = text_shipped.splitlines(keepends=True)
    lines_rebuilt = text_rebuilt.splitlines(keepends=True)
    if len(lines_shipped) > max_input_lines or len(lines_rebuilt) > max_input_lines:
        return False, None, False

    diff_iter = difflib.unified_diff(
        lines_shipped,
        lines_rebuilt,
        fromfile=f"a/{member_path}",
        tofile=f"b/{member_path}",
        lineterm="\n",
    )

    bounded_limit = max(0, max_diff_lines)
    diff_lines: list[str] = []
    truncated = False

    for idx, raw_line in enumerate(diff_iter):
        if idx >= bounded_limit:
            truncated = True
            break
        diff_lines.append(raw_line.rstrip("\r\n"))

    return True, "\n".join(diff_lines), truncated


def _report_path(path: str | Path | None) -> str:
    """Name an input artifact by its final component only, never its host location."""
    if path is None:
        return ""
    return Path(path).name


def _scrub_host_paths(
    text: str,
    shipped_path: str | Path | None,
    rebuilt_path: str | Path | None,
) -> str:
    """Replace every spelling of the input locations in an error message."""
    replacements: list[tuple[str, str]] = []
    for label, path in (("<shipped>", shipped_path), ("<rebuilt>", rebuilt_path)):
        if path is None:
            continue
        # Only absolute spellings: a short relative name would match ordinary words.
        spellings = {os.path.abspath(str(path))}
        try:
            spellings.add(str(Path(path).resolve()))
        except (OSError, RuntimeError, ValueError):
            pass
        replacements.extend(
            (spelling, label) for spelling in spellings if spelling and spelling != "/"
        )
    # Longest first so a prefix never pre-empts a longer spelling.
    for spelling, label in sorted(replacements, key=lambda item: (-len(item[0]), item[0])):
        text = text.replace(spelling, label)
    return text


def build_error_report(
    shipped_path: str | Path | None,
    rebuilt_path: str | Path | None,
    error: Exception,
) -> dict[str, Any]:
    """Construct a deterministic JSON-serialisable error report."""
    return {
        "audit_only": True,
        "content_differences": [],
        "detector": "D7",
        "error": {
            "message": _scrub_host_paths(str(error), shipped_path, rebuilt_path),
            "type": type(error).__name__,
        },
        "gating": False,
        "normalisation": dict(NORMALISATION_DOCUMENTATION),
        "only_in_rebuilt": [],
        "only_in_shipped": [],
        "policy": AUDIT_POLICY_STATEMENT,
        "rebuilt_path": _report_path(rebuilt_path),
        "shipped_path": _report_path(shipped_path),
        "summary": {
            "content_differences_count": 0,
            "only_in_rebuilt_count": 0,
            "only_in_shipped_count": 0,
            "rebuilt_member_count": 0,
            "shipped_member_count": 0,
        },
        "verdict": "error",
    }


def _compare_member_pair(
    member_a: NormalisedMember,
    member_b: NormalisedMember,
    limits: ResourceLimits,
) -> dict[str, Any] | None:
    """Compare two normalised members present in both artifacts; return diff dict or None."""
    content_changed = member_a.sha256 != member_b.sha256
    executable_changed = member_a.executable != member_b.executable

    if not content_changed and not executable_changed:
        return None

    entry: dict[str, Any] = {
        "content_changed": content_changed,
        "executable_changed": executable_changed,
        "executable_rebuilt": member_b.executable,
        "executable_shipped": member_a.executable,
        "is_text": False,
        "path": member_a.path,
        "sha256_rebuilt": member_b.sha256,
        "sha256_shipped": member_a.sha256,
    }

    if content_changed and not member_a.is_pyc and not member_b.is_pyc:
        is_text, unified_diff, truncated = build_unified_diff(
            member_a.path,
            member_a.data,
            member_b.data,
            max_text_bytes=limits.max_text_diff_bytes,
            max_diff_lines=limits.max_diff_lines,
            max_input_lines=limits.max_diff_input_lines,
        )
        entry["is_text"] = is_text
        if is_text and unified_diff is not None:
            entry["diff_truncated"] = truncated
            entry["unified_diff"] = unified_diff

    return entry


def compare_artifacts(
    shipped_path: str | Path,
    rebuilt_path: str | Path,
    limits: ResourceLimits | None = None,
    *,
    generated_files: Sequence[str | Path] | set[str] | None = None,
) -> dict[str, Any]:
    """Compare a shipped artifact (A) against a rebuilt artifact (B).

    Never raises unhandled exceptions; returns a structured report with verdict
    'identical', 'differs', or 'error'.
    """
    active_limits = limits or ResourceLimits()

    try:
        members_shipped = load_artifact(shipped_path, limits=active_limits, generated_files=generated_files)
        members_rebuilt = load_artifact(rebuilt_path, limits=active_limits, generated_files=generated_files)

        keys_shipped = set(members_shipped.keys())
        keys_rebuilt = set(members_rebuilt.keys())

        only_in_shipped = sorted(keys_shipped - keys_rebuilt)
        only_in_rebuilt = sorted(keys_rebuilt - keys_shipped)
        common_paths = sorted(keys_shipped & keys_rebuilt)

        if len(common_paths) > active_limits.max_archive_members:
            raise ResourceLimitError(
                f"Common member count exceeds cap ({len(common_paths)} > {active_limits.max_archive_members})"
            )

        content_differences: list[dict[str, Any]] = []
        for idx, member_path in enumerate(common_paths, start=1):
            if idx > active_limits.max_archive_members:
                raise ResourceLimitError(
                    f"Comparison loop exceeded member cap ({active_limits.max_archive_members})"
                )
            diff_entry = _compare_member_pair(
                members_shipped[member_path],
                members_rebuilt[member_path],
                active_limits,
            )
            if diff_entry is not None:
                content_differences.append(diff_entry)

        verdict = (
            "identical"
            if (not only_in_shipped and not only_in_rebuilt and not content_differences)
            else "differs"
        )

        return {
            "audit_only": True,
            "content_differences": content_differences,
            "detector": "D7",
            "error": None,
            "gating": False,
            "normalisation": dict(NORMALISATION_DOCUMENTATION),
            "only_in_rebuilt": only_in_rebuilt,
            "only_in_shipped": only_in_shipped,
            "policy": AUDIT_POLICY_STATEMENT,
            "rebuilt_path": _report_path(rebuilt_path),
            "shipped_path": _report_path(shipped_path),
            "summary": {
                "content_differences_count": len(content_differences),
                "only_in_rebuilt_count": len(only_in_rebuilt),
                "only_in_shipped_count": len(only_in_shipped),
                "rebuilt_member_count": len(members_rebuilt),
                "shipped_member_count": len(members_shipped),
            },
            "verdict": verdict,
        }
    except HermeticD7Error as exc:
        return build_error_report(shipped_path, rebuilt_path, exc)
    except Exception as exc:  # Defensive boundary guaranteeing no unhandled exceptions
        wrapped = HermeticD7Error(f"Unexpected D7 failure: {exc}")
        return build_error_report(shipped_path, rebuilt_path, wrapped)


def format_report_json(report: dict[str, Any]) -> str:
    """Serialise a D7 report dictionary as deterministic formatted JSON."""
    return json.dumps(report, indent=2, sort_keys=True)


