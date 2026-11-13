
"""Tests for the hermetic_assert_recorder pytest plugin using pytester."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermetic_assert_recorder.plugin import (
    ENV_LOG_PATH,
    MAX_REACHED_PER_TEST,
    AssertRecorder,
)

pytest_plugins = ["pytester"]

REPO_ROOT = str(Path(__file__).resolve().parents[1])


@pytest.fixture(autouse=True)
def _ensure_plugin_on_pythonpath(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure subprocesses spawned by pytester can import hermetic_assert_recorder."""
    existing = os.environ.get("PYTHONPATH", "")
    combined = f"{REPO_ROOT}{os.pathsep}{existing}" if existing else REPO_ROOT
    monkeypatch.setenv("PYTHONPATH", combined)


def test_req1_cli_flag_and_atomic_env_log_output(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 1: -p hermetic_assert_recorder.plugin writes valid JSON atomically to HERMETIC_ASSERT_LOG."""
    out_dir = pytester.path / "artifacts"
    out_dir.mkdir()
    log_path = out_dir / "assert_log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    pytester.makepyfile(
        test_req1="""
        def test_ok():
            assert 2 + 2 == 4
        """
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 0
    assert log_path.is_file()

    # Verify atomic rename left no temporary files behind.
    leftover_tmps = list(out_dir.glob(".hermetic_assert_*.tmp"))
    assert leftover_tmps == []

    data = json.loads(log_path.read_text(encoding="utf-8"))
    assert "tests" in data
    assert "internal_errors" in data
    assert data["internal_errors"] == []
    assert "test_req1.py::test_ok" in data["tests"]


def test_req2_passing_asserts_recorded_with_source_order_ast_indices(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 2: Passing asserts get exact lines, relative file paths, and AST source-order indices."""
    log_path = pytester.path / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    sub = pytester.mkpydir("pkg_tests")
    test_file = sub / "test_indices.py"
    test_file.write_text(
        "\n".join(
            [
                "def test_ordered_asserts():",
                "    x = 10",
                "    assert x == 10",  # line 3 -> index 0
                "    if x > 5:",
                "        assert (",  # line 5 -> index 1 (multiline)
                "            x * 2 == 20",
                "        )",
                "    assert x != 0",  # line 8 -> index 2
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 0

    data = json.loads(log_path.read_text(encoding="utf-8"))
    entry = data["tests"]["pkg_tests/test_indices.py::test_ordered_asserts"]
    assert entry["file"] == "pkg_tests/test_indices.py"
    assert entry["outcome"] == "passed"
    assert entry["raising_line"] is None
    assert entry["reached"] == [
        {"line": 3, "index": 0, "site_id": "test_ordered_asserts#0", "passed": True},
        {"line": 5, "index": 1, "site_id": "test_ordered_asserts#1", "passed": True},
        {"line": 8, "index": 2, "site_id": "test_ordered_asserts#2", "passed": True},
    ]


def test_req3_failing_assert_line_and_trailing_asserts_absent(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 3: Failing assert records its line and index; asserts after failure are absent."""
    log_path = pytester.path / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    pytester.makepyfile(
        test_fail_assert="\n".join(
            [
                "def test_stops_at_failure():",
                "    assert 1 == 1",  # line 2 -> index 0 (passed)
                "    assert 1 == 2",  # line 3 -> index 1 (failed)
                "    assert 3 == 3",  # line 4 -> index 2 (never reached)
            ]
        )
        + "\n"
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 1

    data = json.loads(log_path.read_text(encoding="utf-8"))
    entry = data["tests"]["test_fail_assert.py::test_stops_at_failure"]
    assert entry["outcome"] == "failed"
    assert entry["raising_line"] == 3
    assert entry["reached"] == [
        {"line": 2, "index": 0, "site_id": "test_stops_at_failure#0", "passed": True},
        {"line": 3, "index": 1, "site_id": "test_stops_at_failure#1", "passed": False},
    ]


def test_req3_non_assertion_exception_records_raising_line(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 3: Raising ValueError records raising_line without adding a failed assert."""
    log_path = pytester.path / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    pytester.makepyfile(
        test_val_err="\n".join(
            [
                "def test_raises_value_error():",
                "    assert 10 == 10",  # line 2 -> index 0 (passed)
                "    raise ValueError('boom')",  # line 3 -> raising_line
                "    assert 20 == 20",  # line 4 -> index 1 (never reached)
            ]
        )
        + "\n"
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 1

    data = json.loads(log_path.read_text(encoding="utf-8"))
    entry = data["tests"]["test_val_err.py::test_raises_value_error"]
    assert entry["outcome"] == "failed"
    assert entry["raising_line"] == 3
    assert entry["reached"] == [
        {"line": 2, "index": 0, "site_id": "test_raises_value_error#0", "passed": True},
    ]


def test_req4_unittest_self_assert_recorded_only_when_failing(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 4: unittest self.assertX calls are recorded by line only when they fail."""
    log_path = pytester.path / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    pytester.makepyfile(
        test_unittest_style="\n".join(
            [
                "import unittest",
                "",
                "class TestLegacyCase(unittest.TestCase):",
                "    def test_assert_methods(self):",
                "        self.assertEqual(1, 1)",  # line 5 -> passes, not recorded
                "        self.assertEqual(1, 2)",  # line 6 -> fails, recorded by line
                "        self.assertEqual(2, 2)",  # line 7 -> unreached
            ]
        )
        + "\n"
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 1

    data = json.loads(log_path.read_text(encoding="utf-8"))
    entry = data["tests"]["test_unittest_style.py::TestLegacyCase::test_assert_methods"]
    assert entry["outcome"] == "failed"
    assert entry["raising_line"] == 6
    assert entry["reached"] == [
        {"line": 6, "index": None, "site_id": None, "passed": False},
    ]


def test_req5_sorted_keys_per_test_cap_and_internal_errors_separated(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 5: Output tests are sorted, reached entries are capped, and internal errors are isolated."""
    log_path = pytester.path / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    pytester.makepyfile(
        test_caps_and_sort="\n".join(
            [
                "def test_zebra():",
                "    assert True",
                "",
                "def test_alpha_many():",
                f"    for i in range({MAX_REACHED_PER_TEST + 25}):",
                "        assert i >= 0",
            ]
        )
        + "\n"
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 0

    data = json.loads(log_path.read_text(encoding="utf-8"))
    assert list(data["tests"].keys()) == [
        "test_caps_and_sort.py::test_alpha_many",
        "test_caps_and_sort.py::test_zebra",
    ]
    alpha_entry = data["tests"]["test_caps_and_sort.py::test_alpha_many"]
    assert len(alpha_entry["reached"]) == MAX_REACHED_PER_TEST
    assert data["internal_errors"] == []


def test_req5_plugin_internal_error_does_not_change_test_outcomes(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 5: Unwritable log path or internal plugin error never changes test outcomes."""
    unwritable_path = pytester.path / "nonexistent_parent_dir" / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(unwritable_path))

    pytester.makepyfile(
        test_resilience="""
        def test_passes():
            assert 1 == 1

        def test_fails():
            assert 1 == 2
        """
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    # Exit code 1 reflects the single failing test, not an unhandled plugin crash.
    assert result.ret == 1
    result.stdout.fnmatch_lines(["*1 failed, 1 passed*"])
    assert not unwritable_path.exists()

    # Also verify directly that an unwritable target records into internal_errors cleanly.
    config = pytester.parseconfig()
    recorder = AssertRecorder(config)
    recorder.write_log_safely = None  # ensure no extra helper used
    try:
        recorder.write_log(str(unwritable_path))
    except Exception as exc:
        recorder._record_internal_error("write_log", exc)
    payload = recorder.build_payload()
    assert len(payload["internal_errors"]) == 1
    assert "FileNotFoundError" in payload["internal_errors"][0]


def test_req6_site_id_format_and_parametrised_separate_entries(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 6: site_id uses '<qualname>#<index>' and parametrised tests get separate entries."""
    log_path = pytester.path / "log.json"
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    pytester.makepyfile(
        test_sites="\n".join(
            [
                "import pytest",
                "",
                "@pytest.mark.parametrize('val', [1, 2])",
                "def test_param(val):",
                "    assert val > 0",  # line 5 -> index 0
                "    assert val < 10",  # line 6 -> index 1
                "",
                "class TestSuite:",
                "    def test_member(self):",
                "        assert 'a' in 'abc'",  # line 10 -> index 0
            ]
        )
        + "\n"
    )

    result = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")
    assert result.ret == 0

    data = json.loads(log_path.read_text(encoding="utf-8"))
    assert "test_sites.py::test_param[1]" in data["tests"]
    assert "test_sites.py::test_param[2]" in data["tests"]
    assert "test_sites.py::TestSuite::test_member" in data["tests"]

    p1 = data["tests"]["test_sites.py::test_param[1]"]
    p2 = data["tests"]["test_sites.py::test_param[2]"]
    assert p1["reached"] == [
        {"line": 5, "index": 0, "site_id": "test_param#0", "passed": True},
        {"line": 6, "index": 1, "site_id": "test_param#1", "passed": True},
    ]
    assert p2["reached"] == p1["reached"]

    member = data["tests"]["test_sites.py::TestSuite::test_member"]
    assert member["reached"] == [
        {"line": 10, "index": 0, "site_id": "TestSuite.test_member#0", "passed": True},
    ]


def test_deterministic_output_across_repeated_runs(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output JSON bytes are identical across repeated runs on the same test suite."""
    log1 = pytester.path / "run1.json"
    log2 = pytester.path / "run2.json"

    pytester.makepyfile(
        test_det="""
        import pytest

        @pytest.mark.parametrize("n", [10, 20])
        def test_det_param(n):
            assert n > 5
            if n == 20:
                assert n == 99

        def test_det_err():
            assert True
            raise RuntimeError("stop")
        """
    )

    monkeypatch.setenv(ENV_LOG_PATH, str(log1))
    res1 = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")

    monkeypatch.setenv(ENV_LOG_PATH, str(log2))
    res2 = pytester.runpytest("-p", "hermetic_assert_recorder.plugin")

    assert res1.ret == res2.ret == 1
    assert log1.read_text(encoding="utf-8") == log2.read_text(encoding="utf-8")


