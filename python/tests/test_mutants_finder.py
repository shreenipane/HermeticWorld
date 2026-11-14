"""Tests for the base-failing assertion finder (TR-GR-9)."""

from __future__ import annotations

import pytest

from hermetic_mutants.finder import (
    FinderError,
    find_base_failing_sites,
    nodeid_qualname,
    parse_recorder_log,
)
from tests.mutants_fixture import SOURCE, TEST_FILE, base_log, nodeid, recorder_log

ALL_LINES = range(1, 14)


def test_finder_selects_failing_hidden_sites_only() -> None:
    res = find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, ALL_LINES)
    assert res.eligible_sites == ("test_add:0", "test_add_neg:0")
    assert res.base_failing_tests == ("test_add", "test_add_neg")
    assert ("test_double", "not failing on base") in res.excluded


def test_finder_requires_every_assert_line_hidden() -> None:
    res = find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, [3, 4, 5, 11, 12])
    assert res.eligible_sites == ("test_add:0",)
    assert ("test_add_neg", "no mutable base-failing site in hidden lines") in res.excluded


def test_finder_unreached_site_needs_data_flow_dependency() -> None:
    src = (
        "def test_two():\n"
        "    r = boom()\n"
        "    assert r == 1\n"
        "    assert 3 == 3\n"
    ).encode()
    log = recorder_log(
        {f"{TEST_FILE}::test_two": {"file": TEST_FILE, "outcome": "failed",
                                     "raising_line": 2, "reached": []}}
    )
    res = find_base_failing_sites(src, log, TEST_FILE, range(1, 5))
    assert res.eligible_sites == ("test_two:0",)


def test_finder_site_passing_in_one_parametrisation_is_excluded() -> None:
    src = (
        "def test_p(x):\n"
        "    assert f(x) == 2\n"
    ).encode()
    fail = {"file": TEST_FILE, "outcome": "failed", "raising_line": 2,
            "reached": [{"line": 2, "index": 0, "site_id": "test_p#0", "passed": False}]}
    passed_but_failed_later = {
        "file": TEST_FILE, "outcome": "failed", "raising_line": 2,
        "reached": [{"line": 2, "index": 0, "site_id": "test_p#0", "passed": True}],
    }
    log = recorder_log({f"{TEST_FILE}::test_p[a]": fail, f"{TEST_FILE}::test_p[b]": passed_but_failed_later})
    res = find_base_failing_sites(src, log, TEST_FILE, [1, 2])
    assert res.eligible_sites == ()
    log2 = recorder_log({f"{TEST_FILE}::test_p[a]": fail,
                         f"{TEST_FILE}::test_p[b]": dict(fail, outcome="passed")})
    res2 = find_base_failing_sites(src, log2, TEST_FILE, [1, 2])
    assert res2.eligible_sites == ()
    assert res2.excluded == (("test_p", "not failing on base"),)


def test_finder_unittest_failure_recorded_by_line() -> None:
    src = (
        "class TestC:\n"
        "    def test_eq(self):\n"
        "        self.assertEqual(g(), 5)\n"
    ).encode()
    log = recorder_log({f"{TEST_FILE}::TestC::test_eq": {
        "file": TEST_FILE, "outcome": "failed", "raising_line": 3,
        "reached": [{"line": 3, "index": None, "site_id": None, "passed": False}]}})
    res = find_base_failing_sites(src, log, TEST_FILE, [1, 2, 3])
    assert res.eligible_sites == ("TestC.test_eq:0",)


@pytest.mark.parametrize(
    "entry,reason",
    [
        ("junk", "malformed test entry"),
        ({"outcome": "failed", "raising_line": None, "reached": []}, "no raising line"),
        ({"outcome": "failed", "raising_line": 3, "reached": "x"}, "malformed reached list"),
        ({"outcome": "failed", "raising_line": 3, "reached": [{"passed": 1}]},
         "malformed reached entry"),
        ({"outcome": "failed", "raising_line": 3,
          "reached": [{"site_id": "test_double#0", "passed": False}]},
         "reached site of another function"),
        ({"outcome": "failed", "raising_line": 3,
          "reached": [{"site_id": "test_add#7", "passed": False}]}, "flow analysis refused"),
    ],
)
def test_finder_malformed_entries_fail_closed(entry: object, reason: str) -> None:
    log = recorder_log({nodeid("test_add"): entry})
    res = find_base_failing_sites(SOURCE.encode(), log, TEST_FILE, ALL_LINES)
    assert res.eligible_sites == ()
    assert res.excluded == (("test_add", reason),)


def test_finder_internal_errors_give_nothing() -> None:
    log = recorder_log({}, internal_errors=[{"hook": "x"}])
    res = find_base_failing_sites(SOURCE.encode(), log, TEST_FILE, ALL_LINES)
    assert res.eligible_sites == ()


@pytest.mark.parametrize(
    "data",
    [
        b"not json",
        b"\xff\xfe",
        b'{"tests": {}, "tests": {}, "internal_errors": []}',
        b'{"tests": []}',
        b'{"tests": {}, "internal_errors": [], "x": 1}',
        b'{"tests": {}, "internal_errors": [NaN]}',
        b" " * (8 * 1024 * 1024 + 1),
    ],
)
def test_parse_recorder_log_rejects_hostile_input(data: bytes) -> None:
    with pytest.raises(FinderError):
        parse_recorder_log(data)


def test_finder_rejects_bad_arguments() -> None:
    with pytest.raises(FinderError):
        find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, [0])
    with pytest.raises(FinderError):
        find_base_failing_sites(SOURCE.encode(), base_log(), "a::b", ALL_LINES)


def test_nodeid_qualname_shapes() -> None:
    assert nodeid_qualname(f"{TEST_FILE}::test_a", TEST_FILE) == "test_a"
    assert nodeid_qualname(f"{TEST_FILE}::TestX::test_a[1-2]", TEST_FILE) == "TestX.test_a"
    assert nodeid_qualname("other.py::test_a", TEST_FILE) is None
    assert nodeid_qualname(f"{TEST_FILE}::test_a[x", TEST_FILE) is None
    assert nodeid_qualname(f"{TEST_FILE}::A::B::test_a", TEST_FILE) is None
    assert nodeid_qualname(f"{TEST_FILE}::helper", TEST_FILE) is None


def test_finder_is_deterministic() -> None:
    a = find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, ALL_LINES).to_json()
    b = find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, reversed(ALL_LINES)).to_json()
    assert a == b
