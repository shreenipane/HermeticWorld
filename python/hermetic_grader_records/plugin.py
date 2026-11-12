"""Pytest plugin emitting authenticated per-test binary result records.

Outcome mapping policy (strict benchmark grading):
- Setup or teardown failure -> "error" (environment/fixture failure, not test assertion).
- Call pass -> "passed".
- Call failure -> "failed".
- Skip -> "skipped".
- xfail -> "failed": under strict grading, an expected failure still represents an
  unmet specification requirement and cannot be credited as passing.
- xpass -> "failed": under strict grading, an unexpectedly passing xfail test
  indicates an inaccurate test expectation rather than a verified pass.
"""

from __future__ import annotations

import errno
import fcntl
import os
import time
from typing import Any, BinaryIO, Generator

import pytest

from hermetic_grader_records.record import (
    HermeticGraderError,
    MAGIC,
    MAX_NODEID_LEN,
    StreamEncoder,
)

ENV_RESULT_FD: str = "HERMETIC_RESULT_FD"
MIN_HIGH_FD: int = 64
MAX_HIGH_FD: int = 4096
MAX_FD_ENV_LEN: int = 16


class PluginError(HermeticGraderError):
    """Typed error raised when the result plugin is misconfigured."""


def _validate_orig_fd(fd: int) -> int:
    if not isinstance(fd, int) or isinstance(fd, bool) or fd < 3 or fd >= MAX_HIGH_FD:
        raise PluginError("HERMETIC_RESULT_FD out of allowed range")
    return fd


def _parse_env_fd(raw_value: str) -> int:
    stripped = raw_value.strip()
    if len(stripped) == 0 or len(stripped) > MAX_FD_ENV_LEN or not stripped.isdigit():
        raise PluginError("Invalid HERMETIC_RESULT_FD value")
    return _validate_orig_fd(int(stripped, 10))


def _duplicate_to_high_fd(orig_fd: int) -> int:
    """Duplicate orig_fd onto a high close-on-exec fd >= MIN_HIGH_FD."""
    _validate_orig_fd(orig_fd)
    min_target = max(MIN_HIGH_FD, orig_fd + 1)
    if min_target >= MAX_HIGH_FD:
        raise PluginError("No high file descriptor range available")

    if hasattr(fcntl, "F_DUPFD_CLOEXEC"):
        try:
            high_fd = int(fcntl.fcntl(orig_fd, fcntl.F_DUPFD_CLOEXEC, min_target))
            if high_fd >= MAX_HIGH_FD:
                os.close(high_fd)
                raise PluginError("Duplicated file descriptor exceeds MAX_HIGH_FD")
            return high_fd
        except OSError as exc:
            raise PluginError("Failed to duplicate HERMETIC_RESULT_FD") from exc

    # Bounded fallback when F_DUPFD_CLOEXEC is unavailable
    for candidate in range(min_target, MAX_HIGH_FD):
        try:
            os.fstat(candidate)
            continue
        except OSError as exc:
            if exc.errno != errno.EBADF:
                continue
        try:
            os.dup2(orig_fd, candidate, inheritable=False)
            return candidate
        except OSError:
            continue

    raise PluginError("Failed to allocate high file descriptor")


def _classify_item_outcome(reports: dict[str, Any]) -> str:
    """Map pytest phase TestReports to a canonical outcome string."""
    setup_rep = reports.get("setup")
    call_rep = reports.get("call")
    teardown_rep = reports.get("teardown")

    if setup_rep is not None:
        if getattr(setup_rep, "wasxfail", None) is not None:
            return "failed"
        if setup_rep.outcome == "failed":
            return "error"
        if setup_rep.outcome == "skipped":
            return "skipped"

    if teardown_rep is not None:
        if getattr(teardown_rep, "wasxfail", None) is not None:
            return "failed"
        if teardown_rep.outcome == "failed":
            return "error"

    if call_rep is not None:
        if getattr(call_rep, "wasxfail", None) is not None:
            return "failed"
        if call_rep.outcome == "passed":
            return "passed"
        if call_rep.outcome == "failed":
            return "failed"
        if call_rep.outcome == "skipped":
            return "skipped"

    return "error"


def _sanitize_nodeid(nodeid: str) -> str:
    cleaned = nodeid.replace("\x00", "?")
    if len(cleaned) == 0:
        return "<unknown>"
    if len(cleaned) > MAX_NODEID_LEN:
        return cleaned[:MAX_NODEID_LEN]
    return cleaned


class HermeticResultPlugin:
    """Pytest plugin writing tamper-evident binary test records to a private fd."""

    def __init__(self, orig_fd: int) -> None:
        valid_orig_fd = _validate_orig_fd(orig_fd)
        high_fd = _duplicate_to_high_fd(valid_orig_fd)
        try:
            st = os.fstat(high_fd)
            expected_identity = (st.st_dev, st.st_ino)
            stream = os.fdopen(high_fd, "wb")
        except Exception as exc:
            try:
                os.close(high_fd)
            except OSError:
                pass
            raise PluginError("Failed to initialize result descriptor") from exc

        # Close the original fd and scrub environment so test code cannot easily reuse it.
        try:
            os.close(valid_orig_fd)
        except OSError:
            pass
        os.environ.pop(ENV_RESULT_FD, None)

        self._fd: int = high_fd
        self._expected_identity: tuple[int, int] = expected_identity
        self._stream: BinaryIO | None = stream
        self._encoder: StreamEncoder = StreamEncoder()
        self._disabled: bool = False
        self._phase_reports: dict[str, dict[str, Any]] = {}

        # Write stream magic once at plugin load
        self._write_checked(MAGIC)

    @property
    def fd(self) -> int:
        return self._fd

    @property
    def disabled(self) -> bool:
        return self._disabled

    def _verify_fd_identity(self) -> bool:
        if self._disabled or self._stream is None:
            return False
        try:
            st = os.fstat(self._fd)
        except OSError:
            self._disabled = True
            return False

        if (st.st_dev, st.st_ino) != self._expected_identity:
            self._disabled = True
            return False
        return True

    def _write_checked(self, data: bytes) -> bool:
        if not self._verify_fd_identity():
            return False
        assert self._stream is not None
        try:
            self._stream.write(data)
            self._stream.flush()
            return True
        except OSError:
            self._disabled = True
            return False

    def _close_stream(self) -> None:
        stream = self._stream
        self._stream = None
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(
        self, item: pytest.Item, nextitem: pytest.Item | None
    ) -> Generator[None, None, None]:
        nodeid = _sanitize_nodeid(item.nodeid)
        self._phase_reports[nodeid] = {}
        start_ns = time.monotonic_ns()

        try:
            start_bytes = self._encoder.start(nodeid)
        except HermeticGraderError:
            self._disabled = True
            start_bytes = b""

        if start_bytes:
            self._write_checked(start_bytes)

        yield

        elapsed_ns = max(0, time.monotonic_ns() - start_ns)
        duration_ms = elapsed_ns // 1_000_000
        reports = self._phase_reports.pop(nodeid, {})
        outcome = _classify_item_outcome(reports)

        try:
            finish_bytes = self._encoder.finish(nodeid, outcome, duration_ms)
        except HermeticGraderError:
            self._disabled = True
            finish_bytes = b""

        if finish_bytes:
            self._write_checked(finish_bytes)

    @pytest.hookimpl(trylast=True)
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        nodeid = _sanitize_nodeid(report.nodeid)
        if nodeid in self._phase_reports and report.when in ("setup", "call", "teardown"):
            self._phase_reports[nodeid][report.when] = report

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        if not self._disabled:
            try:
                end_bytes = self._encoder.end()
            except HermeticGraderError:
                self._disabled = True
                end_bytes = b""
            if end_bytes:
                self._write_checked(end_bytes)
        self._close_stream()

    def pytest_unconfigure(self, config: pytest.Config) -> None:
        self._close_stream()


def pytest_configure(config: pytest.Config) -> None:
    raw_fd = os.environ.get(ENV_RESULT_FD)
    if raw_fd is None:
        return
    orig_fd = _parse_env_fd(raw_fd)
    plugin = HermeticResultPlugin(orig_fd)
    config.pluginmanager.register(plugin, name="hermetic_result_recorder")
