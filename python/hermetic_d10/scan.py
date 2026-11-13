
"""Filesystem traversal and single-file scanning for Detector D10."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path, PurePosixPath
import stat

from hermetic_d10.carriers import (
    CapExceededError,
    Finding,
    HermeticD10Error,
    Refusal,
    ScanCaps,
    UnsafeFileError,
    format_rfc3339_utc,
    inspect_payload_bytes,
    parse_rfc3339_utc,
)


@dataclass(frozen=True)
class ScanResult:
    """Deterministic result of scanning a root directory or single file."""

    t_clock: str
    verdict: str
    findings: list[Finding]
    refusals: list[Refusal]
    files_scanned: int
    bytes_read: int

    def has_cap_error(self) -> bool:
        return any(r.error_type == CapExceededError.__name__ for r in self.refusals)

    def to_dict(self) -> dict[str, object]:
        gate_count = sum(1 for f in self.findings if f.severity == "gate")
        info_count = sum(1 for f in self.findings if f.severity == "info")
        implausible_count = sum(1 for f in self.findings if f.implausible)
        return {
            "detector": "D10",
            "t_clock": self.t_clock,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "refusals": [r.to_dict() for r in self.refusals],
            "stats": {
                "files_scanned": self.files_scanned,
                "bytes_read": self.bytes_read,
                "findings_count": len(self.findings),
                "gate_count": gate_count,
                "info_count": info_count,
                "implausible_count": implausible_count,
                "refusals_count": len(self.refusals),
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def _normalize_t_clock(t_clock: datetime | str) -> datetime:
    if isinstance(t_clock, str):
        return parse_rfc3339_utc(t_clock)
    if t_clock.tzinfo is None:
        return parse_rfc3339_utc(t_clock.isoformat())
    return parse_rfc3339_utc(format_rfc3339_utc(t_clock))


def _read_regular_file_bounded(
    file_path: Path,
    caps: ScanCaps,
    remaining_total_bytes: int,
) -> bytes:
    """Safely open a regular file without following symlinks and read within byte caps."""
    try:
        st = os.lstat(file_path)
    except OSError as exc:
        raise UnsafeFileError(f"Unable to stat {file_path}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise UnsafeFileError(f"Refusing symlink: {file_path}")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeFileError(f"Refusing non-regular file (mode {oct(st.st_mode)}): {file_path}")

    effective_cap = min(caps.max_file_bytes, remaining_total_bytes)
    if st.st_size > effective_cap:
        raise CapExceededError(
            f"File size ({st.st_size} bytes) exceeds cap ({effective_cap} bytes)."
        )

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(file_path, open_flags)
    except OSError as exc:
        raise UnsafeFileError(f"Refusing file that could not be opened safely: {exc}") from exc

    try:
        f_st = os.fstat(fd)
        if not stat.S_ISREG(f_st.st_mode):
            raise UnsafeFileError(
                f"Refusing non-regular file descriptor (mode {oct(f_st.st_mode)}): {file_path}"
            )
        buf = bytearray()
        with os.fdopen(fd, "rb", closefd=True) as fp:
            fd = -1
            while True:
                remaining = effective_cap - len(buf)
                to_read = min(caps.read_chunk_size, remaining + 1)
                chunk = fp.read(to_read)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > effective_cap:
                    raise CapExceededError(
                        f"File read exceeded cap ({effective_cap} bytes)."
                    )
        return bytes(buf)
    finally:
        if fd != -1:
            os.close(fd)


def scan_file(
    file_path: str | os.PathLike[str],
    t_clock: datetime | str,
    *,
    rel_path: str | None = None,
    caps: ScanCaps | None = None,
) -> list[Finding]:
    """Scan a single regular file for date carriers. Raises typed errors on refusal/caps."""
    active_caps = caps or ScanCaps()
    clock_dt = _normalize_t_clock(t_clock)
    path_obj = Path(file_path)
    display_path = rel_path if rel_path is not None else PurePosixPath(path_obj.name).as_posix()

    raw = _read_regular_file_bounded(path_obj, active_caps, active_caps.max_total_bytes_read)
    findings = inspect_payload_bytes(
        rel_path=display_path,
        filename=path_obj.name,
        member_chain=[],
        data=raw,
        t_clock=clock_dt,
        caps=active_caps,
        depth=0,
    )
    return _sort_findings(findings)


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.path,
            tuple(f.member_chain),
            f.carrier,
            f.found_date,
            f.severity,
            f.note,
        ),
    )


def _sort_refusals(refusals: list[Refusal]) -> list[Refusal]:
    return sorted(
        refusals,
        key=lambda r: (
            r.path,
            tuple(r.member_chain),
            r.error_type,
            r.reason,
            r.detail,
        ),
    )


def scan_tree(
    root: str | os.PathLike[str],
    t_clock: datetime | str,
    *,
    caps: ScanCaps | None = None,
) -> ScanResult:
    """Walk a directory tree deterministically without following symlinks and scan date carriers."""
    active_caps = caps or ScanCaps()
    clock_dt = _normalize_t_clock(t_clock)
    root_path = Path(root)

    try:
        root_st = os.lstat(root_path)
    except OSError as exc:
        raise UnsafeFileError(f"Root path cannot be accessed: {exc}") from exc

    if stat.S_ISLNK(root_st.st_mode):
        raise UnsafeFileError(f"Refusing symlink root directory: {root_path}")
    if not stat.S_ISDIR(root_st.st_mode):
        raise UnsafeFileError(f"Root path is not a regular directory: {root_path}")

    findings: list[Finding] = []
    refusals: list[Refusal] = []
    files_scanned = 0
    bytes_read = 0

    # Iterative DFS stack: (absolute_dir_path, relative_posix_path, dir_depth)
    dir_stack: list[tuple[Path, str, int]] = [(root_path, "", 0)]
    cap_halted = False

    while dir_stack and not cap_halted:
        cur_dir, cur_rel, dir_depth = dir_stack.pop()
        if dir_depth > active_caps.max_dir_depth:
            refusals.append(
                Refusal(
                    path=cur_rel or ".",
                    member_chain=[],
                    error_type=CapExceededError.__name__,
                    reason="max_dir_depth_exceeded",
                    detail=f"Directory depth ({dir_depth}) exceeds cap ({active_caps.max_dir_depth}).",
                )
            )
            continue

        try:
            with os.scandir(cur_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            refusals.append(
                Refusal(
                    path=cur_rel or ".",
                    member_chain=[],
                    error_type=UnsafeFileError.__name__,
                    reason="directory_unreadable",
                    detail=str(exc),
                )
            )
            continue

        subdirs_to_push: list[tuple[Path, str, int]] = []
        for entry in entries:
            entry_rel = f"{cur_rel}/{entry.name}" if cur_rel else entry.name
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=UnsafeFileError.__name__,
                        reason="stat_failed",
                        detail=str(exc),
                    )
                )
                continue

            mode = st.st_mode
            if stat.S_ISLNK(mode):
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=UnsafeFileError.__name__,
                        reason="symlink_refused",
                        detail="Symlinks are never followed.",
                    )
                )
                continue

            if stat.S_ISDIR(mode):
                subdirs_to_push.append((Path(entry.path), entry_rel, dir_depth + 1))
                continue

            if not stat.S_ISREG(mode):
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=UnsafeFileError.__name__,
                        reason="non_regular_file_refused",
                        detail=f"Non-regular file mode {oct(mode)} refused.",
                    )
                )
                continue

            if files_scanned >= active_caps.max_files:
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=CapExceededError.__name__,
                        reason="max_files_exceeded",
                        detail=f"File count cap ({active_caps.max_files}) exceeded.",
                    )
                )
                cap_halted = True
                break

            files_scanned += 1
            remaining_total = active_caps.max_total_bytes_read - bytes_read
            if remaining_total <= 0:
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=CapExceededError.__name__,
                        reason="max_total_bytes_exceeded",
                        detail=f"Total bytes read cap ({active_caps.max_total_bytes_read}) exceeded.",
                    )
                )
                cap_halted = True
                break

            try:
                raw = _read_regular_file_bounded(
                    Path(entry.path),
                    active_caps,
                    remaining_total,
                )
                bytes_read += len(raw)
                file_findings = inspect_payload_bytes(
                    rel_path=entry_rel,
                    filename=entry.name,
                    member_chain=[],
                    data=raw,
                    t_clock=clock_dt,
                    caps=active_caps,
                    depth=0,
                )
                findings.extend(file_findings)
            except CapExceededError as exc:
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=CapExceededError.__name__,
                        reason="cap_exceeded",
                        detail=str(exc),
                    )
                )
            except HermeticD10Error as exc:
                refusals.append(
                    Refusal(
                        path=entry_rel,
                        member_chain=[],
                        error_type=type(exc).__name__,
                        reason="file_refused_or_malformed",
                        detail=str(exc),
                    )
                )

        # Reverse so lowest alphabetical directory is popped first
        for sub in reversed(subdirs_to_push):
            dir_stack.append(sub)

    sorted_findings = _sort_findings(findings)
    sorted_refusals = _sort_refusals(refusals)
    verdict = "gate" if any(f.severity == "gate" for f in sorted_findings) else "pass"

    return ScanResult(
        t_clock=format_rfc3339_utc(clock_dt),
        verdict=verdict,
        findings=sorted_findings,
        refusals=sorted_refusals,
        files_scanned=files_scanned,
        bytes_read=bytes_read,
    )


