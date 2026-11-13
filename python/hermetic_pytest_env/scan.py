
from __future__ import annotations

import configparser
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
import re
import stat
from typing import Any

MAX_METADATA_BYTES: int = 1 * 1024 * 1024  # 1 MiB
MAX_ENTRY_POINTS_BYTES: int = 256 * 1024  # 256 KiB
MAX_DIR_ENTRIES: int = 50_000
MAX_SCAN_DIRS: int = 64
MAX_HEADER_LINES: int = 20_000
MAX_PEP440_SEGMENTS: int = 32
MAX_VERSION_BYTES: int = 128
MAX_PATH_BYTES: int = 4096
MAX_DISTRIBUTIONS: int = 4096
MAX_TOTAL_READ_BYTES: int = 64 * 1024 * 1024
MAX_TOTAL_PLUGINS: int = 4096
READ_CHUNK_BYTES: int = 65536

_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")
_PEP440_RE = re.compile(
    r"""
    ^
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|alpha|b|beta|rc|c|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)


class ScanError(Exception):
    """Typed error raised on invalid scanner inputs or fatal directory errors."""


class _AbsentFile(FileNotFoundError):
    """Only an absent initial directory entry, never a subsequent open failure."""


@dataclass(frozen=True)
class Pep440Version:
    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None

    local: tuple[str | int, ...] | None = None

    def sort_key(self) -> tuple[Any, ...]:
        rel = self.release
        while len(rel) > 1 and rel[-1] == 0:
            rel = rel[:-1]
        # Each component is compared independently, including post+dev on a prerelease.
        if self.pre is None and self.post is None and self.dev is not None:
            pre_key = (0,)
        elif self.pre is None:
            pre_key = (2,)
        else:
            pre_key = (1, {"a": 0, "b": 1, "rc": 2}[self.pre[0]], self.pre[1])
        post_key = (0,) if self.post is None else (1, self.post)
        dev_key = (1,) if self.dev is None else (0, self.dev)
        local_key = () if self.local is None else tuple(
            (1, part) if isinstance(part, int) else (0, part) for part in self.local
        )
        return (self.epoch, rel, pre_key, post_key, dev_key, local_key)


def parse_pep440(raw: str) -> Pep440Version | None:
    s = raw.strip()
    if not s or len(s) > MAX_VERSION_BYTES:
        return None
    m = _PEP440_RE.match(s)
    if not m:
        return None

    epoch_str = m.group("epoch")
    epoch = int(epoch_str) if epoch_str is not None else 0

    rel_parts = m.group("release").split(".")
    if len(rel_parts) > MAX_PEP440_SEGMENTS:
        return None
    release = tuple(int(p) for p in rel_parts)

    pre: tuple[str, int] | None = None
    if m.group("pre") is not None:
        raw_l = m.group("pre_l").lower()
        norm_l = {
            "a": "a",
            "alpha": "a",
            "b": "b",
            "beta": "b",
            "c": "rc",
            "rc": "rc",
            "pre": "rc",
            "preview": "rc",
        }[raw_l]
        pre_n = int(m.group("pre_n")) if m.group("pre_n") is not None else 0
        pre = (norm_l, pre_n)

    post: int | None = None
    if m.group("post") is not None:
        if m.group("post_n1") is not None:
            post = int(m.group("post_n1"))
        elif m.group("post_n2") is not None:
            post = int(m.group("post_n2"))
        else:
            post = 0

    dev: int | None = None
    if m.group("dev") is not None:
        dev = int(m.group("dev_n")) if m.group("dev_n") is not None else 0

    local_raw = m.group("local")
    local = None if local_raw is None else tuple(
        int(part) if part.isascii() and part.isdigit() else part.lower()
        for part in re.split(r"[-_.]", local_raw)
    )
    return Pep440Version(epoch=epoch, release=release, pre=pre, post=post, dev=dev, local=local)


def normalize_pep503(name: str) -> str:
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


@dataclass
class Inventory:
    pytest_version: str | None = None
    pytest_older_than_3_8: bool | None = None
    plugins: list[dict[str, str]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    refused: list[dict[str, str]] = field(default_factory=list)
    unparsable: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        # conftest.py declarations are outside static site-packages scanning.
        sorted_plugins = sorted(
            self.plugins,
            key=lambda p: (p["distribution"], p["name"], p["module"]),
        )
        sorted_conflicts = sorted(
            self.conflicts,
            key=lambda c: (c["dir_index"], c["normalized_name"], tuple(c["entries"])),
        )
        sorted_refused = sorted(
            self.refused,
            key=lambda r: (r["entry"], r["reason"]),
        )
        sorted_unparsable = sorted(
            self.unparsable,
            key=lambda u: (u["entry"], u["reason"], u.get("value", "")),
        )
        return {
            "conflicts": sorted_conflicts,
            "plugins": sorted_plugins,
            "pytest": {
                "older_than_3_8": self.pytest_older_than_3_8,
                "version": self.pytest_version,
            },
            "refused": sorted_refused,
            "unparsable": sorted_unparsable,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)


def _same_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return _same_file(before, after) and (
        before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)


@contextmanager
def _directory_at(name: str, parent_fd: int | None = None):
    before = os.lstat(name, dir_fd=parent_fd)
    if stat.S_ISLNK(before.st_mode):
        raise ValueError("symlink_refused")
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError("not_a_directory")
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=parent_fd)
    try:
        if not _same_file(before, os.fstat(fd)):
            raise ValueError("directory_changed")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _site_directory(path: str):
    # Walk every component relative to a held descriptor, including the initial root.
    with _directory_at("/" if os.path.isabs(path) else ".") as root_fd:
        fd = os.dup(root_fd)
        try:
            for part in path.split("/"):
                if part in ("", "."):
                    continue
                with _directory_at(part, fd) as next_fd:
                    os.close(fd)
                    fd = os.dup(next_fd)
            yield fd
        finally:
            os.close(fd)


def _read_regular_file_capped(path: str, cap: int, *, dir_fd: int, budget: _Budget) -> bytes:
    try:
        before = os.lstat(path, dir_fd=dir_fd)
    except FileNotFoundError:
        raise _AbsentFile from None
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("not_regular_file")
    if before.st_size > cap:
        raise ValueError("file_too_large")
    # O_PATH pins the inode without invoking a device driver or opening a FIFO.
    pinned_fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        pinned = os.fstat(pinned_fd)
        if not stat.S_ISREG(pinned.st_mode) or not _same_snapshot(before, pinned):
            raise ValueError("file_changed")
        # This kernel descriptor link reopens the pinned regular inode, not the input path.
        fd = os.open(f"/proc/self/fd/{pinned_fd}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not _same_snapshot(pinned, st):
                raise ValueError("file_changed")
            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = MAX_TOTAL_READ_BYTES - budget.read_bytes
                if remaining <= 0:
                    raise ScanError("total metadata byte limit exceeded")
                data = os.read(fd, min(READ_CHUNK_BYTES, cap + 1 - total, remaining))
                budget.read_bytes += len(data)
                if not data:
                    break
                total += len(data)
                if total > cap:
                    raise ValueError("file_too_large")
                chunks.append(data)
            if not _same_snapshot(st, os.fstat(fd)):
                raise ValueError("file_changed")
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(pinned_fd)


def _parse_rfc822_headers(raw_bytes: bytes) -> dict[str, list[str]]:
    """Parses RFC 822 style metadata headers up to the first blank line, handling folding."""
    text = raw_bytes.decode("utf-8", errors="strict")
    headers: dict[str, list[str]] = {}
    current_key: str | None = None
    current_val_parts: list[str] = []

    lines = text.replace("\r\n", "\n").split("\n")
    if len(lines) > MAX_HEADER_LINES:
        raise ValueError("too_many_metadata_lines")

    for line in lines:
        if line == "":
            # End of RFC 822 header block (body follows)
            break
        if any((ord(c) < 32 and c != "\t") or c in "\x7f\x85\u2028\u2029" for c in line):
            raise ValueError("invalid_metadata_header_character")
        if line[0] in (" ", "\t"):
            if current_key is None:
                raise ValueError("invalid_continuation_line")
            current_val_parts.append(line.strip())
            continue

        if current_key is not None:
            headers.setdefault(current_key, []).append(" ".join(current_val_parts).strip())
            current_key = None
            current_val_parts = []

        if ":" not in line:
            raise ValueError("malformed_metadata_header")
        k, v = line.split(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", k):
            raise ValueError("invalid_metadata_header_name")
        key = k.lower()
        current_key = key
        current_val_parts = [v.strip()]

    if current_key is not None:
        headers.setdefault(current_key, []).append(" ".join(current_val_parts).strip())

    return headers


def _parse_pytest11_entry_points(raw_bytes: bytes) -> list[tuple[str, str]]:
    text = raw_bytes.decode("utf-8", errors="strict")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and not re.fullmatch(r"\[[^\[\]]+\]", stripped):
            raise ValueError("invalid_entry_point_section")
    parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=("=",))
    # Preserve case of entry-point names
    parser.optionxform = lambda optionstr: optionstr  # type: ignore[method-assign]
    parser.read_string(text)

    if not parser.has_section("pytest11"):
        return []

    if parser.defaults():
        raise ValueError("entry_point_defaults_forbidden")
    results: list[tuple[str, str]] = []
    module = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    target_pattern = rf"({module}(?:\s*:\s*{module})?)(?:\s*\[\s*[A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*\s*\])?"
    for ep_name, ep_val in parser.items("pytest11"):
        clean_name = ep_name.strip()
        match = re.fullmatch(target_pattern, ep_val.strip(), flags=re.ASCII)
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", clean_name) or match is None:
            raise ValueError("invalid_pytest11_entry_point")
        results.append((clean_name, re.sub(r"\s+", "", match.group(1))))
    return results


@dataclass
class _Budget:
    distributions: int = 0
    read_bytes: int = 0
    plugins: int = 0

    def read(self, fd: int, name: str, cap: int) -> bytes:
        remaining = MAX_TOTAL_READ_BYTES - self.read_bytes
        if remaining <= 0:
            raise ScanError("total metadata byte limit exceeded")
        try:
            data = _read_regular_file_capped(name, min(cap, remaining), dir_fd=fd, budget=self)
        except ValueError as exc:
            if str(exc) == "file_too_large" and remaining < cap:
                raise ScanError("total metadata byte limit exceeded") from None
            raise
        return data


def scan(site_packages_dirs: list[str]) -> Inventory:
    """Scans site-packages directories statically without importing or executing target code."""
    if not isinstance(site_packages_dirs, list):
        raise ScanError("site_packages_dirs must be a list of paths")
    if len(site_packages_dirs) > MAX_SCAN_DIRS:
        raise ScanError("too many site_packages_dirs")
    # Validate the complete request before the first filesystem operation.
    for path in site_packages_dirs:
        if not isinstance(path, str) or not path or "\x00" in path or ".." in path.split("/"):
            raise ScanError("invalid site_packages directory path")
        try:
            encoded = os.fsencode(path)
        except UnicodeError:
            raise ScanError("invalid site_packages directory path") from None
        if len(encoded) > MAX_PATH_BYTES:
            raise ScanError("site_packages directory path too long")
    if not all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_PATH")):
        raise ScanError("safe filesystem operations unavailable")

    inv = Inventory()
    budget = _Budget()
    seen: dict[str, list[tuple[int, str]]] = {}
    pytest_candidates: list[tuple[Pep440Version | None, str]] = []
    for dir_idx, site_dir in enumerate(site_packages_dirs):
        try:
            with _site_directory(site_dir) as site_fd:
                _scan_directory(site_fd, dir_idx, inv, budget, seen, pytest_candidates)
        except (OSError, ValueError):
            # OS diagnostics can contain paths and depend on the host's locale.
            raise ScanError("cannot scan site_packages directory") from None

    for norm_name, entries in sorted(seen.items()):
        by_dir: dict[int, list[str]] = {}
        for idx, name in entries:
            by_dir.setdefault(idx, []).append(name)
        for idx, names in by_dir.items():
            if len(names) > 1:
                inv.conflicts.append({"dir_index": idx, "entries": sorted(names), "normalized_name": norm_name})
        if len(by_dir) > 1:
            inv.conflicts.append({"dir_index": min(by_dir), "dir_indices": sorted(by_dir),
                                  "entries": sorted(name for _, name in entries), "normalized_name": norm_name})

    # Multiple installations do not identify which pytest will be imported at runtime.
    if len(pytest_candidates) == 1:
        version, raw = pytest_candidates[0]
        if version is not None:
            inv.pytest_version = raw
            threshold = Pep440Version(0, (3, 8), None, None, None)
            inv.pytest_older_than_3_8 = version.sort_key() < threshold.sort_key()
    return inv


def _scan_directory(site_fd, dir_idx, inv, budget, seen, pytest_candidates):
    with os.scandir(site_fd) as it:
        names = []
        for idx, entry in enumerate(it):
            if idx >= MAX_DIR_ENTRIES:
                raise ScanError("site_packages directory exceeds entry limit")
            names.append(entry.name)
    for name in sorted(names):
        if not name.endswith((".dist-info", ".egg-info")):
            continue
        budget.distributions += 1
        if budget.distributions > MAX_DISTRIBUTIONS:
            raise ScanError("distribution limit exceeded")
        try:
            with _directory_at(name, site_fd) as dist_fd:
                _scan_distribution(dist_fd, dir_idx, name, inv, budget, seen, pytest_candidates)
        except UnicodeError:
            inv.refused.append({"entry": name, "reason": "metadata_decode_error"})
        except configparser.Error as exc:
            inv.refused.append({"entry": name, "reason": f"entry_points_parse_error:{type(exc).__name__}"})
        except ValueError as exc:
            # All ValueError messages here are fixed codes produced by this module.
            inv.refused.append({"entry": name, "reason": str(exc)})
        except OSError:
            inv.refused.append({"entry": name, "reason": "metadata_read_error"})


def _scan_distribution(fd, dir_idx, name, inv, budget, seen, pytest_candidates):
    meta_name = "METADATA" if name.endswith(".dist-info") else "PKG-INFO"
    headers = _parse_rfc822_headers(budget.read(fd, meta_name, MAX_METADATA_BYTES))
    names, versions = headers.get("name", []), headers.get("version", [])
    if len(names) != 1 or not names[0] or len(versions) != 1 or not versions[0]:
        raise ValueError("missing_or_duplicate_name_version")
    dist_name, raw_version = names[0], versions[0]
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", dist_name):
        raise ValueError("invalid_distribution_name")
    norm_name = normalize_pep503(dist_name)
    seen.setdefault(norm_name, []).append((dir_idx, name))
    version = parse_pep440(raw_version)
    if version is None:
        inv.unparsable.append({"entry": name, "reason": "unparsable_pep440_version", "value": raw_version})
    if norm_name == "pytest":
        pytest_candidates.append((version, raw_version))
    try:
        ep_bytes = budget.read(fd, "entry_points.txt", MAX_ENTRY_POINTS_BYTES)
    except _AbsentFile:
        return
    plugins = _parse_pytest11_entry_points(ep_bytes)
    budget.plugins += len(plugins)
    if budget.plugins > MAX_TOTAL_PLUGINS:
        raise ScanError("plugin limit exceeded")
    for ep_name, module_path in plugins:
        inv.plugins.append({"distribution": norm_name, "module": module_path,
                            "name": ep_name, "version": raw_version})
