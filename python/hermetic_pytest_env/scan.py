
from __future__ import annotations

import configparser
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
    re.VERBOSE | re.IGNORECASE,
)


class ScanError(Exception):
    """Typed error raised on invalid scanner inputs or fatal directory errors."""


@dataclass(frozen=True)
class Pep440Version:
    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None

    def sort_key(self) -> tuple[Any, ...]:
        # PEP 440 ordering:
        # dev-only < pre < pre+post < pre+dev < final < post
        rel = self.release
        # Strip trailing zeros for comparison
        while len(rel) > 1 and rel[-1] == 0:
            rel = rel[:-1]

        if self.pre is None and self.post is None and self.dev is not None:
            pre_key: tuple[Any, ...] = (0, self.dev)
        elif self.pre is not None:
            pre_order = {"a": 0, "b": 1, "rc": 2}[self.pre[0]]
            if self.dev is not None:
                sub = (0, self.dev)
            elif self.post is not None:
                sub = (2, self.post)
            else:
                sub = (1, 0)
            pre_key = (1, pre_order, self.pre[1], sub)
        elif self.post is not None:
            if self.dev is not None:
                pre_key = (3, self.post, 0, self.dev)
            else:
                pre_key = (3, self.post, 1, 0)
        else:
            pre_key = (2, 0)

        return (self.epoch, rel, pre_key)


def parse_pep440(raw: str) -> Pep440Version | None:
    s = raw.strip()
    if not s or len(s) > 128:
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

    return Pep440Version(epoch=epoch, release=release, pre=pre, post=post, dev=dev)


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
        # Note: conftest.py-style plugin declarations are out of scope for static
        # site-packages metadata scanning and are disabled at runtime via
        # PYTEST_DISABLE_PLUGIN_AUTOLOAD=1.
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


def _read_regular_file_capped(path: str, cap: int) -> bytes:
    """Opens and reads a regular file without following symlinks and enforces a hard size cap."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not_regular_file")
        if st.st_size > cap:
            raise ValueError("file_too_large")
        chunks: list[bytes] = []
        total = 0
        while True:
            to_read = min(65536, cap + 1 - total)
            if to_read <= 0:
                raise ValueError("file_too_large")
            data = os.read(fd, to_read)
            if not data:
                break
            total += len(data)
            if total > cap:
                raise ValueError("file_too_large")
            chunks.append(data)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_rfc822_headers(raw_bytes: bytes) -> dict[str, list[str]]:
    """Parses RFC 822 style metadata headers up to the first blank line, handling folding."""
    text = raw_bytes.decode("utf-8", errors="strict")
    headers: dict[str, list[str]] = {}
    current_key: str | None = None
    current_val_parts: list[str] = []

    lines = text.splitlines()
    if len(lines) > MAX_HEADER_LINES:
        raise ValueError("too_many_metadata_lines")

    for line in lines:
        if line == "":
            # End of RFC 822 header block (body follows)
            break
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
        key = k.strip().lower()
        if not key:
            raise ValueError("empty_metadata_header_name")
        current_key = key
        current_val_parts = [v.strip()]

    if current_key is not None:
        headers.setdefault(current_key, []).append(" ".join(current_val_parts).strip())

    return headers


def _parse_pytest11_entry_points(raw_bytes: bytes) -> list[tuple[str, str]]:
    text = raw_bytes.decode("utf-8", errors="strict")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    # Preserve case of entry-point names
    parser.optionxform = lambda optionstr: optionstr  # type: ignore[method-assign]
    parser.read_string(text)

    if not parser.has_section("pytest11"):
        return []

    results: list[tuple[str, str]] = []
    for ep_name, ep_val in parser.items("pytest11"):
        clean_name = ep_name.strip()
        # Strip optional extras marker `[extra]` from entry point target
        target = ep_val.split("[", 1)[0].strip()
        if not clean_name or not target:
            raise ValueError("invalid_pytest11_entry_point")
        results.append((clean_name, target))
    return results


def scan(site_packages_dirs: list[str]) -> Inventory:
    """Scans site-packages directories statically without importing or executing target code."""
    if not isinstance(site_packages_dirs, list):
        raise ScanError("site_packages_dirs must be a list of paths")
    if len(site_packages_dirs) > MAX_SCAN_DIRS:
        raise ScanError("too many site_packages_dirs")

    inv = Inventory()
    threshold_3_8 = parse_pep440("3.8.0")
    assert threshold_3_8 is not None

    pytest_candidates: list[tuple[Pep440Version, str]] = []

    for dir_idx, site_dir in enumerate(site_packages_dirs):
        if not isinstance(site_dir, str) or not site_dir or "\x00" in site_dir:
            raise ScanError("invalid site_packages directory path")

        try:
            dir_st = os.lstat(site_dir)
        except OSError as exc:
            raise ScanError(f"cannot access site_packages directory: {exc.strerror or 'error'}") from exc

        if stat.S_ISLNK(dir_st.st_mode) or not stat.S_ISDIR(dir_st.st_mode):
            raise ScanError("site_packages path must be a real directory, not a symlink")

        try:
            with os.scandir(site_dir) as it:
                entries = []
                for idx, entry in enumerate(it):
                    if idx >= MAX_DIR_ENTRIES:
                        raise ScanError("site_packages directory exceeds entry limit")
                    entries.append(entry)
        except OSError as exc:
            raise ScanError(f"failed to list site_packages directory: {exc.strerror or 'error'}") from exc

        # Deterministic traversal order
        entries.sort(key=lambda e: e.name)

        seen_in_dir: dict[str, list[str]] = {}

        for entry in entries:
            name = entry.name
            if not (name.endswith(".dist-info") or name.endswith(".egg-info")):
                continue

            entry_path = os.path.join(site_dir, name)
            try:
                is_link = entry.is_symlink()
                st = os.lstat(entry_path)
            except OSError:
                inv.refused.append({"entry": name, "reason": "lstat_failed"})
                continue

            if is_link or stat.S_ISLNK(st.st_mode):
                inv.refused.append({"entry": name, "reason": "symlink_refused"})
                continue

            if not stat.S_ISDIR(st.st_mode):
                inv.refused.append({"entry": name, "reason": "not_a_directory"})
                continue

            meta_filename = "METADATA" if name.endswith(".dist-info") else "PKG-INFO"
            meta_path = os.path.join(entry_path, meta_filename)

            try:
                meta_bytes = _read_regular_file_capped(meta_path, MAX_METADATA_BYTES)
                headers = _parse_rfc822_headers(meta_bytes)
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                reason = str(exc) if isinstance(exc, ValueError) else "metadata_read_error"
                inv.refused.append({"entry": name, "reason": reason})
                continue

            names = headers.get("name", [])
            versions = headers.get("version", [])
            if len(names) != 1 or not names[0] or len(versions) != 1 or not versions[0]:
                inv.refused.append({"entry": name, "reason": "missing_or_duplicate_name_version"})
                continue

            dist_name = names[0]
            dist_version_raw = versions[0]
            norm_name = normalize_pep503(dist_name)

            seen_in_dir.setdefault(norm_name, []).append(name)

            parsed_ver = parse_pep440(dist_version_raw)
            if parsed_ver is None:
                inv.unparsable.append(
                    {
                        "entry": name,
                        "reason": "unparsable_pep440_version",
                        "value": dist_version_raw,
                    }
                )
            elif norm_name == "pytest":
                pytest_candidates.append((parsed_ver, dist_version_raw))

            ep_path = os.path.join(entry_path, "entry_points.txt")
            try:
                ep_st = os.lstat(ep_path)
            except FileNotFoundError:
                ep_st = None
            except OSError:
                inv.refused.append({"entry": name, "reason": "entry_points_lstat_failed"})
                continue

            if ep_st is not None:
                if stat.S_ISLNK(ep_st.st_mode):
                    inv.refused.append({"entry": name, "reason": "entry_points_symlink_refused"})
                    continue
                try:
                    ep_bytes = _read_regular_file_capped(ep_path, MAX_ENTRY_POINTS_BYTES)
                    pytest11_eps = _parse_pytest11_entry_points(ep_bytes)
                except (
                    OSError,
                    UnicodeDecodeError,
                    ValueError,
                    configparser.Error,
                ) as exc:
                    reason = (
                        str(exc)
                        if isinstance(exc, ValueError)
                        else f"entry_points_parse_error:{type(exc).__name__}"
                    )
                    inv.refused.append({"entry": name, "reason": reason})
                    continue

                for ep_name, module_path in pytest11_eps:
                    inv.plugins.append(
                        {
                            "distribution": norm_name,
                            "module": module_path,
                            "name": ep_name,
                            "version": dist_version_raw,
                        }
                    )

        for norm_name, dist_entries in seen_in_dir.items():
            if len(dist_entries) > 1:
                inv.conflicts.append(
                    {
                        "dir_index": dir_idx,
                        "entries": sorted(dist_entries),
                        "normalized_name": norm_name,
                    }
                )

    if pytest_candidates:
        # Pick highest-precedence pytest version encountered across site_packages_dirs
        best_ver, best_raw = max(pytest_candidates, key=lambda item: item[0].sort_key())
        inv.pytest_version = best_raw
        inv.pytest_older_than_3_8 = best_ver.sort_key() < threshold_3_8.sort_key()

    return inv


