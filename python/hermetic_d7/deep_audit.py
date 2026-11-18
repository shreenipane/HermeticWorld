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

import hermetic_safe_io
from hermetic_d7.compare import AUDIT_POLICY_STATEMENT, compare_artifacts
from hermetic_d7.normalise import (
    HermeticD7Error,
    MAX_ARTIFACT_BYTES,
    READ_CHUNK_SIZE,
    InvalidArtifactError,
    ResourceLimitError,
    ResourceLimits,
    SecurityViolationError,
    validate_member_path,
)

RECIPE_SCHEMA = "hermetic.d7.recipe/1"
MAX_RECIPE_BYTES = 4 * 1024 * 1024
MAX_RECIPE_ENTRIES = 4096
MAX_ARGS = 64
MAX_ARG_BYTES = 1024
MAX_BUILDER_OUTPUT_ENTRIES = 2
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


class RecipeEntries(list[RecipeEntry]):
    """Recipe entries with optional unattributed artifacts attached."""

    unattributed: tuple[str, ...] = ()


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
    try:
        fd = _open_no_follow(root_fd, rel, directory=False)
    except FileNotFoundError:
        raise SecurityViolationError("recipe input does not exist")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecurityViolationError(f"{rel!r} is not a regular file")
        if st.st_size > cap:
            raise ResourceLimitError(f"{rel!r} exceeds {cap} bytes")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK_SIZE, cap - total + 1))
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
    """Pin each component, inspect it before opening, and refuse special files."""
    current = os.dup(root_fd)
    try:
        parts = rel.split("/")
        for index, part in enumerate(parts):
            is_dir = index < len(parts) - 1 or directory
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            if not (stat.S_ISDIR(before.st_mode) if is_dir else
                    stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
                raise SecurityViolationError("recipe input is a link or special file")
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if is_dir:
                flags |= os.O_DIRECTORY
            pinned = os.open(part, flags, dir_fd=current)
            try:
                after = os.fstat(pinned)
                if (before.st_dev, before.st_ino, before.st_mode) != (
                    after.st_dev, after.st_ino, after.st_mode
                ):
                    raise SecurityViolationError("recipe input changed during inspection")
                nxt = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            finally:
                os.close(pinned)
            os.close(current)
            current = nxt
        return current
    except FileNotFoundError:
        os.close(current)
        raise
    except OSError:
        os.close(current)
        raise SecurityViolationError("cannot open recipe input safely") from None
    except BaseException:
        os.close(current)
        raise


def _snapshot(fd: int, destination: Path, limits: ResourceLimits) -> None:
    """Copy a held artifact into private storage without reopening its pathname."""
    count = 0
    total = 0

    def copy(source: int, target: Path, depth: int) -> None:
        nonlocal count, total
        metadata = os.fstat(source)
        if stat.S_ISDIR(metadata.st_mode):
            if depth > limits.max_nesting_depth:
                raise ResourceLimitError("artifact directory depth cap exceeded")
            target.mkdir(mode=0o700)
            names = []
            with os.scandir(source) as entries:
                for entry in entries:
                    count += 1
                    if count > limits.max_archive_members:
                        raise ResourceLimitError("artifact member count cap exceeded")
                    names.append(entry.name)
            for name in sorted(names):
                child = _open_no_follow(source, name, directory=False)
                try:
                    copy(child, target / name, depth + 1)
                finally:
                    os.close(child)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            cap = MAX_ARTIFACT_BYTES if depth == 0 else limits.max_member_bytes
            if metadata.st_size > cap:
                raise ResourceLimitError("artifact byte cap exceeded")
            size = 0
            output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(output_fd, "wb") as output:
                while size <= cap:
                    chunk = os.read(source, min(READ_CHUNK_SIZE, cap - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    total += len(chunk)
                    if size > cap or total > limits.max_total_decompressed_bytes:
                        raise ResourceLimitError("artifact byte cap exceeded")
                    output.write(chunk)
                os.fchmod(output.fileno(), 0o700 if metadata.st_mode & 0o111 else 0o600)
        else:
            raise SecurityViolationError("artifact link or special file refused")

    try:
        copy(fd, destination, 0)
    except OSError:
        raise SecurityViolationError("artifact snapshot failed") from None


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
            isinstance(a, str) and "\x00" not in a and len(a.encode("utf-8", "surrogatepass")) <= MAX_ARG_BYTES
            and not any(0xD800 <= ord(c) <= 0xDFFF for c in a)
            for a in args
        )
    ):
        raise InvalidArtifactError(f"recipe entry {ident!r} has invalid args")
    paths = []
    for key in ("artifact", "source"):
        value = raw[key]
        if not isinstance(value, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise InvalidArtifactError(f"recipe entry {ident!r} {key} must be a valid string")
        try:
            paths.append(validate_member_path(value, is_dir=False))
        except HermeticD7Error:
            raise SecurityViolationError(f"recipe entry {ident!r} {key} is not a safe relative path") from None
    return RecipeEntry(ident, paths[0], paths[1], builder, tuple(args))


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise InvalidArtifactError("duplicate recipe key")
        out[key] = value
    return out


def parse_recipe(data: bytes) -> RecipeEntries:
    """Validate a recipe mapping strictly; any defect refuses the whole recipe."""
    if len(data) > MAX_RECIPE_BYTES:
        raise ResourceLimitError("recipe exceeds byte cap")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidArtifactError("recipe is not valid UTF-8 JSON") from None
    if not isinstance(doc, dict) or set(doc) not in (
        {"schema", "entries"},
        {"schema", "entries", "unattributed"},
    ):
        raise InvalidArtifactError("recipe must have exactly 'schema' and 'entries' (and optional 'unattributed')")
    if doc["schema"] != RECIPE_SCHEMA:
        raise InvalidArtifactError("unsupported recipe schema")
    raw_entries = doc["entries"]
    raw_unattributed = doc.get("unattributed")
    if not isinstance(raw_entries, list):
        raise InvalidArtifactError("recipe entries must be a list")
    if len(raw_entries) > MAX_RECIPE_ENTRIES:
        raise ResourceLimitError("recipe entry cap exceeded")
    unattributed_paths: list[str] = []
    if raw_unattributed is not None:
        if not isinstance(raw_unattributed, list):
            raise InvalidArtifactError("recipe unattributed must be a list")
        if len(raw_unattributed) > MAX_RECIPE_ENTRIES:
            raise ResourceLimitError("recipe unattributed cap exceeded")
        for idx, item in enumerate(raw_unattributed):
            if not isinstance(item, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise InvalidArtifactError(f"unattributed entry {idx} must be a valid string")
            try:
                unattributed_paths.append(validate_member_path(item, is_dir=False))
            except HermeticD7Error:
                raise SecurityViolationError(f"unattributed entry {idx} is not a safe relative path") from None
        if len(set(unattributed_paths)) != len(unattributed_paths):
            raise InvalidArtifactError("duplicate unattributed artifact")
    if not raw_entries and not unattributed_paths:
        raise InvalidArtifactError("recipe entries must be a non-empty list")
    entries = [_entry(raw, i) for i, raw in enumerate(raw_entries)]
    for key in ("id", "artifact"):
        values = [getattr(e, key) for e in entries]
        if len(set(values)) != len(values):
            raise InvalidArtifactError(f"duplicate recipe {key}")
    if raw_unattributed is not None:
        entry_artifacts = {e.artifact for e in entries}
        if entry_artifacts.intersection(unattributed_paths):
            raise InvalidArtifactError("artifact cannot be both attributed and unattributed")
    result = RecipeEntries(entries)
    result.unattributed = tuple(unattributed_paths)
    return result


def _audit_entry(
    root_fd: int,
    entry: RecipeEntry,
    builder: IsolatedBuilder,
    limits: ResourceLimits,
) -> dict[str, Any]:
    result: dict[str, Any] = {"artifact": entry.artifact, "builder": entry.builder, "id": entry.id}
    try:
        # Pin both inputs without following links before anything is built.
        artifact_fd = _open_no_follow(root_fd, entry.artifact, directory=False)
        try:
            source_fd = _open_no_follow(root_fd, entry.source, directory=True)
        except BaseException:
            os.close(artifact_fd)
            raise
        try:
            with tempfile.TemporaryDirectory(prefix="d7-") as work:
                name = entry.artifact.rsplit("/", 1)[-1]
                private = Path(work)
                shipped = private / "shipped" / name
                shipped.parent.mkdir(mode=0o700)
                _snapshot(artifact_fd, shipped, limits)
                out = private / "output"
                out.mkdir(mode=0o700)
                try:
                    builder.build(BuildRequest(entry, source_fd, Path(out), name))
                except Exception:
                    if type(builder) is RefusingBuilder:
                        raise BuildFailedError("no isolated builder configured; deep audit refuses host builds") from None
                    raise BuildFailedError("isolated builder failed") from None
                with os.scandir(out) as entries:
                    listing = [e.name for _, e in zip(range(MAX_BUILDER_OUTPUT_ENTRIES), entries)]
                if listing != [name]:
                    raise BuildFailedError("builder must produce exactly the named artifact")
                if stat.S_ISLNK(os.lstat(os.path.join(out, name)).st_mode):
                    raise SecurityViolationError("builder output is a symlink")
                report = compare_artifacts(shipped, Path(out) / name, limits, generated_files=[entry.artifact, name])
        finally:
            os.close(source_fd)
            os.close(artifact_fd)
    except OSError:
        result.update(verdict="error", error={"type": "SecurityViolationError", "message": "artifact access failed"})
        return result
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
    vm_config: Any | None = None,
) -> dict[str, Any]:
    """Rebuild every recipe entry with the isolated builder and diff it.

    Never raises for bad input: a refused recipe or root yields verdict
    'error'. Overall verdict is 'error' if any entry errored, else 'differs'
    if any differs, else 'identical'.
    """
    if builder is not None:
        active_builder = builder
    elif vm_config is not None:
        from hermetic_d7.vm_builder import VmIsolatedBuilder

        active_builder = VmIsolatedBuilder(vm_config)
    else:
        from hermetic_d7.vm_builder import VmBuilderConfig, VmIsolatedBuilder

        try:
            env_cfg = VmBuilderConfig.from_env()
        except HermeticD7Error as exc:
            # A bad environment config is an error report, not an uncaught exception.
            return {
                "audit_only": True,
                "detector": "D7",
                "error": {"type": type(exc).__name__, "message": str(exc)},
                "verdict": "error",
            }
        active_builder = VmIsolatedBuilder(env_cfg) if env_cfg is not None else RefusingBuilder()

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
        "unattributed": [],
    }
    try:
        recipe_str = str(recipe_rel)
        report["recipe"] = recipe_str
        try:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise SecurityViolationError("shipped root is not a directory (links refused)") from None
        try:
            recipe_path = Path(recipe_rel)
            if recipe_path.is_file() and (recipe_path.is_absolute() or "/" in recipe_str):
                try:
                    rec_fd = hermetic_safe_io.open_regular(recipe_path, MAX_RECIPE_BYTES)
                except (hermetic_safe_io.UnsafePathError, ValueError) as exc:
                    raise SecurityViolationError(f"recipe {recipe_str!r} is unsafe") from exc
                try:
                    recipe_bytes = os.read(rec_fd, MAX_RECIPE_BYTES + 1)
                finally:
                    os.close(rec_fd)
            else:
                recipe = validate_member_path(recipe_str, is_dir=False)
                recipe_bytes = _read_no_follow(root_fd, recipe, MAX_RECIPE_BYTES)
            entries = parse_recipe(recipe_bytes)
            report["unattributed"] = list(getattr(entries, "unattributed", ()))
            for unattr in getattr(entries, "unattributed", ()):
                try:
                    fd = _open_no_follow(root_fd, unattr, directory=False)
                    os.close(fd)
                except FileNotFoundError:
                    raise SecurityViolationError(f"unattributed artifact {unattr!r} does not exist") from None
            report["entries"] = [
                _audit_entry(root_fd, e, active_builder, active_limits) for e in entries
            ]
        finally:
            os.close(root_fd)
    except HermeticD7Error as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        report["verdict"] = "error"
        return report
    verdicts = {e["verdict"] for e in report["entries"]}
    if "error" in verdicts:
        report["verdict"] = "error"
    elif "differs" in verdicts:
        report["verdict"] = "differs"
    elif report["unattributed"]:
        report["verdict"] = "incomplete"
    else:
        report["verdict"] = "identical"
    return report


def run_deep_audit_cli(argv: Sequence[str]) -> dict[str, Any]:
    """CLI path: runs deep audit with the configured isolated builder or refuses."""
    args = list(argv)
    vm_config = None
    if "--vm-config" in args:
        idx = args.index("--vm-config")
        if idx + 1 >= len(args):
            return {
                "audit_only": True,
                "detector": "D7",
                "error": {
                    "type": "CliUsageError",
                    "message": "usage: --deep-audit ROOT RECIPE [--vm-config PATH]",
                },
                "verdict": "error",
            }
        config_path = args[idx + 1]
        args = args[:idx] + args[idx + 2 :]
        try:
            from hermetic_d7.vm_builder import VmBuilderConfig

            vm_config = VmBuilderConfig.from_json_file(config_path)
        except HermeticD7Error as exc:
            return {
                "audit_only": True,
                "detector": "D7",
                "error": {"type": type(exc).__name__, "message": str(exc)},
                "verdict": "error",
            }

    if len(args) != 2:
        return {
            "audit_only": True,
            "detector": "D7",
            "error": {
                "type": "CliUsageError",
                "message": "usage: --deep-audit ROOT RECIPE [--vm-config PATH]",
            },
            "verdict": "error",
        }
    return run_deep_audit(args[0], args[1], vm_config=vm_config)
