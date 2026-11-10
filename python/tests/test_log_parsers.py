"""Tests for hermetic_slice log parsers on real recorded SWE-bench fixtures."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from hermetic_slice.log_parsers import (
    get_log_parser,
    parse_log_astropy,
    parse_log_django,
    parse_log_matplotlib,
    parse_log_pylint,
    parse_log_pytest,
    parse_log_pytest_options,
    parse_log_pytest_v2,
    parse_log_requests,
    parse_log_scikit,
    parse_log_sphinx,
    parse_log_sympy,
    parse_log_xarray,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "grader"


def _read_log_fixture(name: str) -> str:
    path = FIXTURES_DIR / name
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        return f.read()


def test_parser_registry_and_aliases() -> None:
    """Verify registry lookup, aliases, and unknown parser error."""
    assert get_log_parser("parse_log_pytest") is parse_log_pytest
    assert get_log_parser("parse_log_xarray") is parse_log_xarray
    assert get_log_parser("parse_log_requests") is parse_log_requests
    assert get_log_parser("parse_log_pylint") is parse_log_pylint
    assert get_log_parser("parse_log_astropy") is parse_log_astropy
    assert get_log_parser("parse_log_scikit") is parse_log_scikit
    assert get_log_parser("parse_log_sphinx") is parse_log_sphinx
    assert get_log_parser("parse_log_django") is parse_log_django
    assert get_log_parser("parse_log_sympy") is parse_log_sympy
    assert get_log_parser("parse_log_matplotlib") is parse_log_matplotlib

    with pytest.raises(KeyError):
        get_log_parser("parse_log_nonexistent")


def test_parse_log_pytest_pytest6202_gold() -> None:
    """Verify pytest parser on pytest-6202 gold eval log."""
    log = _read_log_fixture("pytest-dev__pytest-6202.gold.log.gz")
    parsed = parse_log_pytest(log)

    # Assert what the data shows from reviewer notes: 73 passed, 1 xfailed
    passed = [k for k, v in parsed.items() if v == "PASSED"]
    xfailed = [k for k, v in parsed.items() if v == "XFAIL"]
    failed = [k for k, v in parsed.items() if v == "FAILED"]

    assert len(passed) == 73
    assert len(xfailed) == 1
    assert len(failed) == 0
    assert parsed["testing/test_collection.py::Test_genitems::test_example_items1"] == "PASSED"


def test_parse_log_pytest_pytest6202_empty() -> None:
    """Verify pytest parser on pytest-6202 empty eval log."""
    log = _read_log_fixture("pytest-dev__pytest-6202.empty.log.gz")
    parsed = parse_log_pytest(log)

    assert parsed["testing/test_collection.py::Test_genitems::test_example_items1"] == "FAILED"


def test_parse_log_django_django11099() -> None:
    """Verify django parser on django-11099 gold and empty eval logs."""
    gold_log = _read_log_fixture("django__django-11099.gold.log.gz")
    gold_parsed = parse_log_django(gold_log)

    f2p_test = "test_ascii_validator (auth_tests.test_validators.UsernameValidatorsTests)"
    assert gold_parsed.get(f2p_test) == "PASSED"
    assert sum(1 for v in gold_parsed.values() if v == "PASSED") > 10

    empty_log = _read_log_fixture("django__django-11099.empty.log.gz")
    empty_parsed = parse_log_django(empty_log)
    assert empty_parsed.get("test_ascii_validator") == "FAILED"


def test_parse_log_sympy_sympy20590() -> None:
    """Verify sympy parser on sympy-20590 gold eval log."""
    gold_log = _read_log_fixture("sympy__sympy-20590.gold.log.gz")
    parsed = parse_log_sympy(gold_log)

    f2p_test = "test_immutable"
    assert parsed.get(f2p_test) == "PASSED"
    assert sum(1 for v in parsed.values() if v == "PASSED") >= 1


def test_parse_log_astropy_astropy12907() -> None:
    """Verify pytest_v2 parser on astropy-12907 gold eval log."""
    gold_log = _read_log_fixture("astropy__astropy-12907.gold.log.gz")
    parsed = parse_log_astropy(gold_log)

    f2p_test = "astropy/modeling/tests/test_separable.py::test_separable[compound_model7-result7]"
    assert parsed.get(f2p_test) == "PASSED"
    assert sum(1 for v in parsed.values() if v == "PASSED") > 10


def test_parse_log_requests_requests2317() -> None:
    """Verify pytest_options parser on requests-2317 gold eval log (offline network failures)."""
    gold_log = _read_log_fixture("psf__requests-2317.gold.log.gz")
    parsed = parse_log_requests(gold_log)

    failed = [k for k, v in parsed.items() if v == "FAILED"]
    passed = [k for k, v in parsed.items() if v == "PASSED"]

    # Reviewer confirmed offline counts: 62 failed, 81 passed
    assert len(failed) == 62
    assert len(passed) == 81


def test_parse_log_matplotlib_buttons() -> None:
    """Verify matplotlib parser button translations."""
    sample_log = (
        "PASSED test_mouse[MouseButton.LEFT]\n"
        "FAILED test_mouse[MouseButton.RIGHT] - AssertionError\n"
    )
    parsed = parse_log_matplotlib(sample_log)
    assert parsed["test_mouse[1]"] == "PASSED"
    assert parsed["test_mouse[3]"] == "FAILED"
