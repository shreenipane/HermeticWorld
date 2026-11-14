"""`--deep-audit` orchestration for Detector D7.

The sealer records, for every shipped artifact it built, a build recipe
mapping (`d7-recipe.json`, schema `hermetic.d7.recipe/1`)::

    {"schema": "hermetic.d7.recipe/1",
     "entries": [{"id": "pkg-wheel",
                  "artifact": "dist/pkg-1.0-py3-none-any.whl",
                  "source": "src/pkg",
                  "builder": "python-wheel",
                  "args": ["--no-isolation"]}]}

`artifact` names the shipped artifact and `source` its build input, both
relative to the shipped world root. The orchestrator validates the mapping,
hands each entry to an injected isolated builder, and compares the shipped
artifact with what the builder produced. It never runs a build itself: the
default builder refuses, so untrusted build recipes can only run inside an
isolation boundary supplied by the caller (a disposable VM). Every path in
the report is the entry's relative name; host locations never appear.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from hermetic_d7.compare import AUDIT_POLICY_STATEMENT, compare_artifacts
from hermetic_d7.normalise import (
    HermeticD7Error,
    InvalidArtifactError,
    ResourceLimitError,
    ResourceLimits,
    SecurityViolationError,
    validate_member_path,
)

RECIPE_SCHEMA = "hermetic.d7.recipe/1"
MAX_RECIPE_BYTES = 1024 * 1024
MAX_RECIPE_ENTRIES = 256
MAX_ARGS = 64
MAX_ARG_BYTES = 1024
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_BUILDER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_ENTRY_KEYS = {"id", "artifact", "source", "builder", "args"}


@dataclass(frozen=True)
class RecipeEntry:
    """One validated build recipe entry; every path is relative to the world root."""

    id: str
    artifact: str
    source: str
    builder: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class BuildRequest:
    """What an isolated builder receives: the entry plus an open, pinned source tree.

    `source_fd` is a directory descriptor opened without following symlinks;
    `output_dir` is an empty directory the builder must write exactly one
    artifact into, named `artifact_name`.
    """

    entry: RecipeEntry
    source_fd: int
    output_dir: Path
    artifact_name: str


class IsolatedBuilder(Protocol):
    """A builder that runs the recipe inside an isolation boundary, never on the host."""

    def build(self, request: BuildRequest) -> None: ...


class BuildFailedError(HermeticD7Error):
    """The isolated builder could not produce the artifact."""


class RefusingBuilder:
    """Default builder: refuses, so a missing isolation boundary fails closed."""

    def build(self, request: BuildRequest) -> None:
        raise BuildFailedError("no isolated builder configured; deep audit refuses host builds")


def _read_no_follow(root_fd: int, rel: str, cap: int) -> bytes:
    fd = _open_no_follow(root_fd, rel, directory=False)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecurityViolationError(f"{rel!r} is not a regular file")
        if st.st_size > cap:
            raise ResourceLimitError(f"{rel!r} exceeds {cap} bytes")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ResourceLimitError(f"{rel!r} exceeds {cap} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _open_no_follow(root_fd: int, rel: str, *, directory: bool) -> int:
    """Open `rel` below `root_fd`, refusing a symlink at every component."""
    parts = rel.split("/") if rel else []
    current = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if not last or directory:
                flags |= os.O_DIRECTORY
            try:
                nxt = os.open(part, flags, dir_fd=current)
            except OSError as exc:
                raise SecurityViolationError(
                    f"cannot open {rel!r} without following links ({exc.strerror})"
                ) from None
            os.close(current)
            current = nxt
        return current
    except BaseException:
        os.close(current)
        raise


def _entry(raw: Any, index: int) -> RecipeEntry:
    if not isinstance(raw, dict) or set(raw) != _ENTRY_KEYS:
        raise InvalidArtifactError(f"recipe entry {index} must have exactly {sorted(_ENTRY_KEYS)}")
    ident, builder, args = raw["id"], raw["builder"], raw["args"]
    if not isinstance(ident, str) or not _ID_RE.fullmatch(ident):
        raise InvalidArtifactError(f"recipe entry {index} has an invalid id")
    if not isinstance(builder, str) or not _BUILDER_RE.fullmatch(builder):
        raise InvalidArtifactError(f"recipe entry {ident!r} has an invalid builder")
    if (
        not isinstance(args, list)
        or len(args) > MAX_ARGS
        or not all(
            isinstance(a, str) and "\x00" not in a and len(a.encode()) <= MAX_ARG_BYTES
            for a in args
        )
    ):
        raise InvalidArtifactError(f"recipe entry {ident!r} has invalid args")
    paths = []
    for key in ("artifact", "source"):
        value = raw[key]
        if not isinstance(value, str):
            raise InvalidArtifactError(f"recipe entry {ident!r} {key} must be a string")
        try:
            paths.append(validate_member_path(value, is_dir=False))
        except HermeticD7Error:
            raise SecurityViolationError(f"recipe entry {ident!r} {key} is not a safe relative path") from None
    return RecipeEntry(ident, paths[0], paths[1], builder, tuple(args))


def parse_recipe(data: bytes) -> list[RecipeEntry]:
    """Validate a recipe mapping strictly; any defect refuses the whole recipe."""
    if len(data) > MAX_RECIPE_BYTES:
        raise ResourceLimitError("recipe exceeds byte cap")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise InvalidArtifactError("recipe is not valid UTF-8 JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"schema", "entries"}:
        raise InvalidArtifactError("recipe must have exactly 'schema' and 'entries'")
    if doc["schema"] != RECIPE_SCHEMA:
        raise InvalidArtifactError("unsupported recipe schema")
    raw_entries = doc["entries"]
    if not isinstance(raw_entries, list) or not raw_entries:
        raise InvalidArtifactError("recipe entries must be a non-empty list")
    if len(raw_entries) > MAX_RECIPE_ENTRIES:
        raise ResourceLimitError("recipe entry cap exceeded")
    entries = [_entry(raw, i) for i, raw in enumerate(raw_entries)]
    for key in ("id", "artifact"):
        values = [getattr(e, key) for e in entries]
        if len(set(values)) != len(values):
            raise InvalidArtifactError(f"duplicate recipe {key}")
    return entries


def _audit_entry(
    root_fd: int,
    root: Path,
    entry: RecipeEntry,
    builder: IsolatedBuilder,
    limits: ResourceLimits,
) -> dict[str, Any]:
    result: dict[str, Any] = {"artifact": entry.artifact, "builder": entry.builder, "id": entry.id}
    try:
        # Pin both inputs without following links before anything is built.
        os.close(_open_no_follow(root_fd, entry.artifact, directory=False))
        source_fd = _open_no_follow(root_fd, entry.source, directory=True)
        try:
            with tempfile.TemporaryDirectory(prefix="d7-") as out:
                name = entry.artifact.rsplit("/", 1)[-1]
                try:
                    builder.build(BuildRequest(entry, source_fd, Path(out), name))
                except HermeticD7Error:
                    raise
                except Exception:
                    raise BuildFailedError("isolated builder failed") from None
                listing = sorted(os.listdir(out))
                if listing != [name]:
                    raise BuildFailedError("builder must produce exactly the named artifact")
                if stat.S_ISLNK(os.lstat(os.path.join(out, name)).st_mode):
                    raise SecurityViolationError("builder output is a symlink")
                report = compare_artifacts(root / entry.artifact, Path(out) / name, limits)
        finally:
            os.close(source_fd)
    except HermeticD7Error as exc:
        result.update(verdict="error", error={"type": type(exc).__name__, "message": str(exc)})
        return result
    for key in ("content_differences", "only_in_rebuilt", "only_in_shipped", "summary"):
        result[key] = report[key]
    result["verdict"] = report["verdict"]
    if report["error"] is not None:
        result["error"] = {"type": report["error"]["type"], "message": "comparison failed"}
    return result


def run_deep_audit(
    shipped_root: str | Path,
    recipe_rel: str,
    builder: IsolatedBuilder | None = None,
    limits: ResourceLimits | None = None,
) -> dict[str, Any]:
    """Rebuild every recipe entry with the isolated builder and diff it.

    Never raises for bad input: a refused recipe or root yields verdict
    'error'. Overall verdict is 'error' if any entry errored, else 'differs'
    if any differs, else 'identical'.
    """
    active_builder = builder or RefusingBuilder()
    active_limits = limits or ResourceLimits()
    root = Path(shipped_root)
    report: dict[str, Any] = {
        "audit_only": True,
        "detector": "D7",
        "entries": [],
        "error": None,
        "gating": False,
        "mode": "deep_audit",
        "policy": AUDIT_POLICY_STATEMENT,
        "recipe": "",
    }
    try:
        recipe = validate_member_path(recipe_rel, is_dir=False)
        report["recipe"] = recipe
        try:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise SecurityViolationError("shipped root is not a directory (links refused)") from None
        try:
            entries = parse_recipe(_read_no_follow(root_fd, recipe, MAX_RECIPE_BYTES))
            report["entries"] = [
                _audit_entry(root_fd, root, e, active_builder, active_limits) for e in entries
            ]
        finally:
            os.close(root_fd)
    except HermeticD7Error as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        report["verdict"] = "error"
        return report
    verdicts = {e["verdict"] for e in report["entries"]}
    report["verdict"] = (
        "error" if "error" in verdicts else "differs" if "differs" in verdicts else "identical"
    )
    return report


def run_deep_audit_cli(argv: Sequence[str]) -> dict[str, Any]:
    """CLI path: the command line can only reach the refusing builder."""
    if len(argv) != 2:
        return {
            "audit_only": True,
            "detector": "D7",
            "error": {"type": "CliUsageError", "message": "usage: --deep-audit ROOT RECIPE"},
            "verdict": "error",
        }
    return run_deep_audit(argv[0], argv[1])
