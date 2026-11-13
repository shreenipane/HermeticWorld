
"""Pytest plugin recording reached assertion sites and failure lines deterministically.

Limitations & Requirements:
- Pytest must rewrite assertions for ``pytest_assertion_pass`` to fire on passing
  plain ``assert`` statements; test files must not disable assertion rewriting
  (such as via ``PYTEST_DONT_REWRITE`` or ``--assert=plain``).
- ``unittest``-style ``self.assertX(...)`` calls are ordinary method calls rather
  than ``assert`` statements, so pytest does not emit ``pytest_assertion_pass``
  for them when they succeed. They are recorded by line only when they fail
  with an ``AssertionError`` (with ``index`` and ``site_id`` set to ``None``).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import sys
import tempfile
from types import TracebackType
from typing import Any

import pytest

ENV_LOG_PATH: str = "HERMETIC_ASSERT_LOG"

MAX_TESTS: int = 10_000
MAX_REACHED_PER_TEST: int = 1_000
MAX_INTERNAL_ERRORS: int = 100
MAX_NODEID_LEN: int = 512
MAX_PATH_LEN: int = 512
MAX_QUALNAME_LEN: int = 256
MAX_OUTCOME_LEN: int = 32
MAX_ERROR_STR_LEN: int = 512
MAX_AST_FILE_BYTES: int = 2_000_000
MAX_AST_FUNCTIONS_PER_FILE: int = 2_000
MAX_ASSERTS_PER_FUNCTION: int = 1_000


def _cap_str(value: str, max_len: int) -> str:
    """Bound a string to ``max_len`` characters deterministically."""
    if len(value) <= max_len:
        return value
    return value[:max_len]


@dataclass(frozen=True)
class AssertSite:
    """Static metadata for a single plain ``assert`` statement in source order."""

    index: int
    line: int
    end_line: int
    qualname: str
    site_id: str


@dataclass(frozen=True)
class FunctionScope:
    """Static metadata for a function/method scope and its source-ordered assertions."""

    qualname: str
    def_line: int
    end_line: int
    asserts: tuple[AssertSite, ...]


@dataclass
class TestRecord:
    """Mutable per-test runtime record collected during a pytest session."""

    file: str
    outcome: str = "unknown"
    raising_line: int | None = None
    reached: list[dict[str, Any]] = field(default_factory=list)


def _collect_scope_asserts(stmts: list[ast.stmt]) -> list[ast.Assert]:
    """Collect ``ast.Assert`` nodes inside a function without entering nested scopes."""
    found: list[ast.Assert] = []

    def _visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(node, ast.Assert):
            found.append(node)
        for child in ast.iter_child_nodes(node):
            _visit(child)

    for stmt in stmts:
        _visit(stmt)

    found.sort(key=lambda n: (n.lineno, n.col_offset))
    return found[:MAX_ASSERTS_PER_FUNCTION]


def _index_file_ast(file_path: Path) -> tuple[FunctionScope, ...]:
    """Parse ``file_path`` without importing it and index all function assertion sites."""
    with file_path.open("rb") as handle:
        raw = handle.read(MAX_AST_FILE_BYTES + 1)
    if len(raw) > MAX_AST_FILE_BYTES:
        raise ValueError(f"Test file exceeds {MAX_AST_FILE_BYTES} bytes")

    tree = ast.parse(raw, filename=str(file_path))
    scopes: list[FunctionScope] = []
    try_types = (ast.Try, getattr(ast, "TryStar", ()))

    def _walk_statements(stmts: list[ast.stmt], prefix: str, in_function: bool) -> None:
        for stmt in stmts:
            if len(scopes) >= MAX_AST_FUNCTIONS_PER_FILE:
                return

            if isinstance(stmt, ast.ClassDef):
                if in_function:
                    class_qual = f"{prefix}.<locals>.{stmt.name}"
                else:
                    class_qual = f"{prefix}.{stmt.name}" if prefix else stmt.name
                _walk_statements(stmt.body, class_qual, in_function=False)

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if in_function:
                    raw_qual = f"{prefix}.<locals>.{stmt.name}"
                else:
                    raw_qual = f"{prefix}.{stmt.name}" if prefix else stmt.name
                func_qual = _cap_str(raw_qual, MAX_QUALNAME_LEN)

                assert_nodes = _collect_scope_asserts(stmt.body)
                sites = tuple(
                    AssertSite(
                        index=idx,
                        line=node.lineno,
                        end_line=node.end_lineno if node.end_lineno is not None else node.lineno,
                        qualname=func_qual,
                        site_id=_cap_str(f"{func_qual}#{idx}", MAX_QUALNAME_LEN),
                    )
                    for idx, node in enumerate(assert_nodes)
                )
                end_line = stmt.end_lineno if stmt.end_lineno is not None else stmt.lineno
                scopes.append(
                    FunctionScope(
                        qualname=func_qual,
                        def_line=stmt.lineno,
                        end_line=end_line,
                        asserts=sites,
                    )
                )
                _walk_statements(stmt.body, func_qual, in_function=True)

            elif isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                _walk_statements(stmt.body, prefix, in_function)
                _walk_statements(stmt.orelse, prefix, in_function)

            elif isinstance(stmt, try_types):
                _walk_statements(stmt.body, prefix, in_function)
                for handler in stmt.handlers:
                    _walk_statements(handler.body, prefix, in_function)
                _walk_statements(stmt.orelse, prefix, in_function)
                _walk_statements(stmt.finalbody, prefix, in_function)

            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    _walk_statements(case.body, prefix, in_function)

    _walk_statements(tree.body, prefix="", in_function=False)
    scopes.sort(key=lambda s: (s.def_line, s.end_line, s.qualname))
    return tuple(scopes)


class AssertRecorder:
    """Session-scoped recorder for reached assertions and failing test lines."""

    def __init__(self, config: pytest.Config) -> None:
        self._config = config
        self._rootpath = Path(str(config.rootpath)).resolve()
        self._tests: dict[str, TestRecord] = {}
        self._ast_cache: dict[Path, tuple[FunctionScope, ...]] = {}
        self._internal_errors: list[str] = []

    def _record_internal_error(self, context: str, exc: BaseException) -> None:
        try:
            if len(self._internal_errors) >= MAX_INTERNAL_ERRORS:
                return
            msg = _cap_str(f"{context}: {type(exc).__name__}: {exc}", MAX_ERROR_STR_LEN)
            self._internal_errors.append(msg)
        except Exception:
            pass

    def _relative_file(self, item_path: Path | None) -> str:
        if item_path is None:
            return ""
        try:
            rel = item_path.relative_to(self._rootpath).as_posix()
        except ValueError:
            rel = os.path.relpath(str(item_path), str(self._rootpath)).replace("\\", "/")
        return _cap_str(rel, MAX_PATH_LEN)

    def _resolve_item_file(self, item: pytest.Item) -> Path | None:
        raw_path = getattr(item, "path", None)
        if raw_path is None:
            fspath = getattr(item, "fspath", None)
            if fspath is not None:
                raw_path = Path(str(fspath))
        if raw_path is None:
            return None
        return Path(str(raw_path)).resolve()

    def _get_or_create_test_record(self, item: pytest.Item) -> TestRecord | None:
        nodeid = _cap_str(str(item.nodeid), MAX_NODEID_LEN)
        existing = self._tests.get(nodeid)
        if existing is not None:
            return existing
        if len(self._tests) >= MAX_TESTS:
            return None
        item_file = self._resolve_item_file(item)
        record = TestRecord(file=self._relative_file(item_file))
        self._tests[nodeid] = record
        return record

    def _get_file_scopes(self, file_path: Path) -> tuple[FunctionScope, ...]:
        cached = self._ast_cache.get(file_path)
        if cached is not None:
            return cached
        scopes = _index_file_ast(file_path)
        self._ast_cache[file_path] = scopes
        return scopes

    def _match_primary_scope(
        self,
        scopes: tuple[FunctionScope, ...],
        item: pytest.Item,
    ) -> FunctionScope | None:
        location = getattr(item, "location", None)
        target_def_line: int | None = None
        expected_qual: str | None = None

        if isinstance(location, tuple) and len(location) >= 3:
            if isinstance(location[1], int):
                target_def_line = location[1] + 1
            if isinstance(location[2], str):
                expected_qual = location[2].split("[", 1)[0]

        if target_def_line is not None:
            for scope in scopes:
                if scope.def_line == target_def_line:
                    return scope

        if expected_qual:
            for scope in scopes:
                if scope.qualname == expected_qual:
                    return scope

        return None

    def _resolve_assert_site(
        self,
        file_path: Path | None,
        item: pytest.Item,
        lineno: int,
    ) -> AssertSite | None:
        if file_path is None or not file_path.is_file():
            return None
        scopes = self._get_file_scopes(file_path)
        if not scopes:
            return None

        primary = self._match_primary_scope(scopes, item)
        if primary is not None:
            for site in primary.asserts:
                if site.line == lineno:
                    return site
            for site in primary.asserts:
                if site.line <= lineno <= site.end_line:
                    return site

        enclosing = [s for s in scopes if s.def_line <= lineno <= s.end_line]
        enclosing.sort(key=lambda s: (s.end_line - s.def_line, s.def_line))
        for scope in enclosing:
            for site in scope.asserts:
                if site.line == lineno:
                    return site
            for site in scope.asserts:
                if site.line <= lineno <= site.end_line:
                    return site

        return None

    def _find_caller_source_file(self) -> Path | None:
        try:
            frame = sys._getframe(1)
        except Exception:
            return None

        for _ in range(16):
            if frame is None:
                break
            filename = frame.f_code.co_filename
            if filename and not filename.startswith("<"):
                candidate = Path(filename)
                parts = candidate.parts
                if (
                    "_pytest" not in parts
                    and "pluggy" not in parts
                    and "hermetic_assert_recorder" not in parts
                ):
                    try:
                        return candidate.resolve()
                    except OSError:
                        return None
            frame = frame.f_back
        return None

    def _extract_last_test_file_line(
        self,
        excinfo: pytest.ExceptionInfo[BaseException] | None,
        item_file: Path | None,
    ) -> int | None:
        if excinfo is None or item_file is None:
            return None

        last_line: int | None = None
        tb: TracebackType | None = getattr(excinfo, "tb", None)
        while tb is not None:
            co_filename = tb.tb_frame.f_code.co_filename
            if co_filename and not co_filename.startswith("<"):
                try:
                    if Path(co_filename).resolve() == item_file:
                        last_line = int(tb.tb_lineno)
                except OSError:
                    pass
            tb = tb.tb_next

        if last_line is not None:
            return last_line

        for entry in getattr(excinfo, "traceback", ()):
            entry_path = getattr(entry, "path", None)
            entry_lineno = getattr(entry, "lineno", None)
            if entry_path is not None and isinstance(entry_lineno, int):
                try:
                    if Path(str(entry_path)).resolve() == item_file:
                        last_line = entry_lineno + 1
                except OSError:
                    pass

        return last_line

    def _append_reached(
        self,
        record: TestRecord,
        line: int,
        site: AssertSite | None,
        passed: bool,
    ) -> None:
        if len(record.reached) >= MAX_REACHED_PER_TEST:
            return
        record.reached.append(
            {
                "line": int(line),
                "index": site.index if site is not None else None,
                "site_id": site.site_id if site is not None else None,
                "passed": bool(passed),
            }
        )

    def pytest_assertion_pass(
        self,
        item: pytest.Item,
        lineno: int,
        orig: str,
        expl: str,
    ) -> None:
        try:
            record = self._get_or_create_test_record(item)
            if record is None:
                return

            item_file = self._resolve_item_file(item)
            caller_file = self._find_caller_source_file()
            if caller_file is not None and item_file is not None and caller_file != item_file:
                return

            site = self._resolve_assert_site(item_file, item, lineno)
            self._append_reached(record, line=lineno, site=site, passed=True)
        except Exception as exc:
            self._record_internal_error("pytest_assertion_pass", exc)

    def pytest_runtest_makereport(
        self,
        item: pytest.Item,
        call: pytest.CallInfo[Any],
    ) -> None:
        try:
            record = self._get_or_create_test_record(item)
            if record is None:
                return

            item_file = self._resolve_item_file(item)
            excinfo = call.excinfo
            exc_type = excinfo.type if excinfo is not None else None
            last_line = self._extract_last_test_file_line(excinfo, item_file)

            if call.when == "setup":
                if excinfo is not None:
                    if exc_type is not None and issubclass(exc_type, pytest.skip.Exception):
                        record.outcome = _cap_str("skipped", MAX_OUTCOME_LEN)
                    else:
                        record.outcome = _cap_str("error", MAX_OUTCOME_LEN)
                        record.raising_line = last_line

            elif call.when == "call":
                if excinfo is None:
                    record.outcome = _cap_str("passed", MAX_OUTCOME_LEN)
                    record.raising_line = None
                elif exc_type is not None and issubclass(exc_type, pytest.skip.Exception):
                    record.outcome = _cap_str("skipped", MAX_OUTCOME_LEN)
                    record.raising_line = None
                else:
                    record.outcome = _cap_str("failed", MAX_OUTCOME_LEN)
                    record.raising_line = last_line
                    if (
                        exc_type is not None
                        and issubclass(exc_type, AssertionError)
                        and last_line is not None
                    ):
                        site = self._resolve_assert_site(item_file, item, last_line)
                        self._append_reached(record, line=last_line, site=site, passed=False)

            elif call.when == "teardown":
                if excinfo is not None and record.outcome == "passed":
                    record.outcome = _cap_str("error", MAX_OUTCOME_LEN)
                    if record.raising_line is None:
                        record.raising_line = last_line
        except Exception as exc:
            self._record_internal_error("pytest_runtest_makereport", exc)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        try:
            if not hasattr(report, "wasxfail"):
                return
            nodeid = _cap_str(str(report.nodeid), MAX_NODEID_LEN)
            record = self._tests.get(nodeid)
            if record is None:
                return
            if report.skipped:
                record.outcome = _cap_str("xfailed", MAX_OUTCOME_LEN)
            elif report.passed:
                record.outcome = _cap_str("xpassed", MAX_OUTCOME_LEN)
        except Exception as exc:
            self._record_internal_error("pytest_runtest_logreport", exc)

    def build_payload(self) -> dict[str, Any]:
        """Construct the deterministic, sorted, bounded JSON payload."""
        sorted_tests: dict[str, Any] = {}
        for nodeid in sorted(self._tests.keys()):
            rec = self._tests[nodeid]
            sorted_tests[nodeid] = {
                "file": _cap_str(rec.file, MAX_PATH_LEN),
                "outcome": _cap_str(rec.outcome, MAX_OUTCOME_LEN),
                "raising_line": rec.raising_line,
                "reached": list(rec.reached[:MAX_REACHED_PER_TEST]),
            }
        return {
            "tests": sorted_tests,
            "internal_errors": list(self._internal_errors[:MAX_INTERNAL_ERRORS]),
        }

    def write_log(self, log_path_str: str) -> None:
        """Atomically serialize and replace ``log_path_str`` on disk."""
        payload = self.build_payload()
        serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

        target_path = Path(log_path_str)
        parent_dir = target_path.parent
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(parent_dir),
                prefix=".hermetic_assert_",
                suffix=".tmp",
                delete=False,
            ) as tmp_file:
                tmp_path = Path(tmp_file.name)
                tmp_file.write(serialized)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(str(tmp_path), str(target_path))
            tmp_path = None
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int | pytest.ExitCode) -> None:
        try:
            log_path_str = os.environ.get(ENV_LOG_PATH, "").strip()
            if not log_path_str:
                return
            self.write_log(log_path_str)
        except Exception as exc:
            self._record_internal_error("pytest_sessionfinish", exc)


_RECORDER_STASH_KEY: pytest.StashKey[AssertRecorder] = pytest.StashKey()


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """Enable pytest assertion pass hooks and register a session-isolated recorder."""
    try:
        if hasattr(config, "_inicache"):
            config._inicache["enable_assertion_pass_hook"] = True
        inicfg = getattr(config, "inicfg", None)
        if isinstance(inicfg, dict):
            inicfg["enable_assertion_pass_hook"] = "true"

        recorder = AssertRecorder(config)
        config.stash[_RECORDER_STASH_KEY] = recorder
        config.pluginmanager.register(recorder, name="hermetic_assert_recorder_session")
    except Exception:
        pass


def pytest_unconfigure(config: pytest.Config) -> None:
    """Unregister the session recorder cleanly so repeated in-process runs stay isolated."""
    try:
        recorder = config.stash.get(_RECORDER_STASH_KEY, None)
        if recorder is not None:
            config.pluginmanager.unregister(recorder)
            del config.stash[_RECORDER_STASH_KEY]
    except Exception:
        pass


