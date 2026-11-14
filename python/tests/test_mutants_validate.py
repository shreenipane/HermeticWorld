"""Tests for variant validation and R1/R2 selection (TR-GR-5, TR-GR-7, TR-GR-8)."""

from __future__ import annotations

import ast
from collections import Counter

import pytest

from hermetic_mutants.validate import (
    PAD_LINE_PREFIX,
    ValidationError,
    check_outcomes,
    pad_equal,
    validate_and_select,
)
from tests.mutants_fixture import SOURCE, TEST_FILE, exec_runner, nodeid

SEED = "00c0ffee"
SITES = ["test_add:0", "test_add_neg:0"]


def _select(runner=exec_runner, sites=SITES, **kw):
    return validate_and_select(SOURCE.encode(), TEST_FILE, SEED, sites, runner, **kw)


def _strip_pad(text: str) -> str:
    return text.split(PAD_LINE_PREFIX)[0]


def _constants(text: str) -> list:
    return [n.value for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant)]


def test_selection_validates_and_mutates_base_failing_tests() -> None:
    sel = _select()
    assert sel.r1_text is not None and sel.r2_text is not None
    assert sel.mutated_sites == ("test_add:0", "test_add_neg:0")
    assert sel.mutated_tests == (nodeid("test_add"), nodeid("test_add_neg"))
    assert sel.compared_tests == tuple(nodeid(n) for n in ("test_add", "test_add_neg", "test_double"))
    assert sel.coverage_json() == {"covered_functions": 2, "eligible_functions": 2}
    # Every mutated test fails on both trees; untouched tests keep their outcome.
    for tree in ("base", "gold"):
        r1 = exec_runner(tree, sel.r1_text)
        assert r1[nodeid("test_add")] == "failed" and r1[nodeid("test_add_neg")] == "failed"
        assert r1[nodeid("test_double")] == "passed"
        assert exec_runner(tree, sel.r2_text) == exec_runner(tree, SOURCE)


def test_r1_differs_from_r2_only_in_mutated_literals_and_sizes_match() -> None:
    sel = _select()
    assert len(sel.r1_text.encode()) == len(sel.r2_text.encode())
    c1, c2 = _constants(_strip_pad(sel.r1_text)), _constants(_strip_pad(sel.r2_text))
    assert len(c1) == len(c2)
    assert sum(1 for a, b in zip(c1, c2) if a != b) == 2
    assert sel.r2_text != SOURCE


def test_selection_is_deterministic_and_seeded() -> None:
    assert _select().manifest_json() == _select().manifest_json()
    other = validate_and_select(SOURCE.encode(), TEST_FILE, "beef", SITES, exec_runner)
    assert other.r1_text != _select().r1_text


def test_flaky_baseline_test_is_dropped_from_comparisons() -> None:
    calls = Counter()

    def runner(tree, text):
        out = exec_runner(tree, text)
        calls[tree] += 1
        if calls[tree] % 2 == 0:
            out[nodeid("test_double")] = "failed"
        return out

    sel = _select(runner)
    assert sel.flaky_tests == (nodeid("test_double"),)
    assert nodeid("test_double") not in sel.compared_tests
    assert sel.r1_text is not None


def test_caller_flaky_ids_are_dropped() -> None:
    sel = _select(flaky=[nodeid("test_double")])
    assert nodeid("test_double") not in sel.compared_tests


@pytest.mark.parametrize(
    "bad",
    [None, [], {nodeid("test_add"): "PASS"}, {1: "passed"}, {"t\n": "passed"},
     {"x" * 2000: "passed"}],
)
def test_malformed_baseline_raises(bad) -> None:
    with pytest.raises(ValidationError):
        _select(lambda tree, text: bad)


def test_baseline_runner_exception_raises() -> None:
    def runner(tree, text):
        raise TimeoutError("vm timed out")

    with pytest.raises(ValidationError):
        _select(runner)


def test_variant_runner_failures_reject_variants_not_the_run() -> None:
    def runner(tree, text):
        if text != SOURCE:
            raise TimeoutError("vm timed out")
        return exec_runner(tree, text)

    sel = _select(runner)
    assert sel.r2_text is None and sel.r1_text is None
    assert ("r2", "no validated equivalent") in sel.rejected
    assert sel.coverage_json() == {"covered_functions": 0, "eligible_functions": 2}


def test_flaky_variant_is_rejected() -> None:
    seen = Counter()

    def runner(tree, text):
        out = exec_runner(tree, text)
        if text != SOURCE:
            seen[(tree, text)] += 1
            if seen[(tree, text)] == 2:
                out[nodeid("test_double")] = "error"
        return out

    sel = _select(runner)
    assert sel.r2_text is None
    assert all(reason.endswith("outcome mismatch") for k, reason in sel.rejected if k != "r2")


def test_mutant_passing_on_gold_is_not_used() -> None:
    def runner(tree, text):
        if tree == "gold" and text != SOURCE:
            # a gold tree whose result ignores the mutated literal
            return exec_runner("gold", SOURCE)
        return exec_runner(tree, text)

    sel = _select(runner)
    assert sel.r2_text is not None
    assert sel.r1_text is None
    assert sel.mutated_tests == ()
    assert ("r1", "no validated mutant") in sel.rejected
    assert sel.coverage_json()["covered_functions"] == 0


def test_combined_r1_failing_falls_back_to_single_mutant() -> None:
    combined = _strip_pad(_select().r1_text)

    def runner(tree, text):
        if text == combined:
            return {}
        return exec_runner(tree, text)

    sel = _select(runner)
    assert len(sel.mutated_sites) == 1
    assert ("r1_combined", "base: outcome mismatch") in sel.rejected
    assert sel.coverage_json() == {"covered_functions": 1, "eligible_functions": 2}


def test_ineligible_or_untested_sites_are_ignored() -> None:
    sel = _select(sites=["test_ghost:0"])
    assert sel.eligible_functions == ()
    assert sel.r1_text is None


def test_bad_arguments_raise() -> None:
    with pytest.raises(ValidationError):
        _select(repeats=0)
    with pytest.raises(ValidationError):
        _select(baseline_repeats=1)
    with pytest.raises(ValidationError):
        _select(sites="test_add:0")
    with pytest.raises(ValidationError):
        validate_and_select(b"\xff", TEST_FILE, SEED, [], exec_runner)


def test_check_outcomes_and_padding_helpers() -> None:
    assert check_outcomes({"a::t": "missing"}) == {"a::t": "missing"}
    a, b = pad_equal("x = 1\n", "x = 100\n")
    assert len(a) == len(b)
    assert ast.dump(ast.parse(a)) == ast.dump(ast.parse("x = 1\n"))
