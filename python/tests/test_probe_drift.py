"""Probe drift regression tests: ensure hermetic_classifier agrees with shared fixture."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from hermetic_classifier.run import (
    PROBE_RESULTS,
    REQUIRED_PROBES,
    RunEvidenceError,
    _probe_records,
    clock_level,
)


def test_probe_constants_match_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "probe_drift_fixture.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert set(REQUIRED_PROBES) == set(data["required_probes"])
    assert set(PROBE_RESULTS) == set(data["probe_results"])


def test_classifier_clock_level_matches_fixture_cases():
    fixture_path = Path(__file__).parent / "fixtures" / "probe_drift_fixture.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for case in data["test_cases"]:
        records = [(r["probe"], r["result"]) for r in case["records"]]
        level, reasons = clock_level(
            case["substrate"],
            case["host"],
            records,
            case["date_leak_observed"],
        )
        assert level == case["expected_clock_level"], f"Case {case['name']} level mismatch"
        assert sorted(reasons) == sorted(case["expected_clock_reasons"]), (
            f"Case {case['name']} reasons mismatch: got {reasons}, expected {case['expected_clock_reasons']}"
        )


def test_probe_records_rejects_vocabulary_outside_probe_results():
    for bad_result in ["ok", "passed", "clean", "tripped", "UNKNOWN"]:
        with pytest.raises(RunEvidenceError):
            _probe_records([{"probe": "rdtsc", "result": bad_result}])
