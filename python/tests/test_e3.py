
"""Comprehensive pytest suite for Hermetic World Experiment E3.

Every numbered requirement (1 through 6) has dedicated hand-written fixtures
and assertions that fail if that requirement is violated.
"""

from __future__ import annotations

import io
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import hermetic_e3
import hermetic_e3.match as match_mod
from hermetic_e3 import (
    CliArgumentError,
    DuplicateKeyError,
    FileSecurityError,
    Finding,
    HermeticE3Error,
    JsonFormatError,
    Leak,
    MAX_FILE_BYTES,
    RangeError,
    SchemaValidationError,
    SizeLimitError,
    bootstrap_confidence_interval,
    compute_all_metrics,
    evaluate,
    evaluate_exit_criterion,
    load_findings,
    load_ground_truth,
    match_findings,
    parse_findings,
    parse_ground_truth,
    ranges_overlap,
)
from hermetic_e3.__main__ import run_cli


def _assert_no_floats_anywhere(value: Any) -> None:
    """Recursively verify that no float appears anywhere in stored results."""
    assert not isinstance(value, float), f"Unexpected float found: {value!r}"
    if isinstance(value, dict):
        for k, v in value.items():
            _assert_no_floats_anywhere(k)
            _assert_no_floats_anywhere(v)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_no_floats_anywhere(item)


def _write_json(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Requirement 1: Inputs, caps, strict schema, duplicate keys, unknown fields,
#                symlink & non-regular file refusal
# ---------------------------------------------------------------------------


def test_req1_valid_ground_truth_and_findings_load(tmp_path: Path) -> None:
    truth_file = _write_json(
        tmp_path / "truth.json",
        {
            "leaks": [
                {
                    "id": "L-001",
                    "task": "task-alpha",
                    "path": "src/app.py",
                    "line_start": 10,
                    "line_end": 12,
                    "detector_hint": "git-history",
                    "kind": "seeded",
                },
                {
                    "id": "L-002",
                    "task": "task-alpha",
                    "path": "src/cfg.py",
                    "line_start": 5,
                    "line_end": 5,
                    "detector_hint": None,
                    "kind": "real",
                },
            ]
        },
    )
    findings_file = _write_json(
        tmp_path / "findings.json",
        {
            "findings": [
                {
                    "task": "task-alpha",
                    "detector": "git-history",
                    "path": "src/app.py",
                    "line_start": 12,
                    "line_end": 15,
                    "severity": "gate",
                }
            ]
        },
    )

    leaks = load_ground_truth(truth_file)
    findings = load_findings(findings_file)
    assert len(leaks) == 2
    assert leaks[0].id == "L-001"
    assert leaks[1].detector_hint is None
    assert len(findings) == 1
    assert findings[0].severity == "gate"


def test_req1_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    dup_top = tmp_path / "dup_top.json"
    dup_top.write_text('{"leaks": [], "leaks": []}', encoding="utf-8")
    with pytest.raises(DuplicateKeyError):
        load_ground_truth(dup_top)

    dup_nested = tmp_path / "dup_nested.json"
    dup_nested.write_text(
        '{"findings": [{"task": "t1", "task": "t2", "detector": "d", '
        '"path": "a.py", "line_start": 1, "line_end": 2, "severity": "gate"}]}',
        encoding="utf-8",
    )
    with pytest.raises(DuplicateKeyError):
        load_findings(dup_nested)


def test_req1_rejects_unknown_and_missing_fields(tmp_path: Path) -> None:
    unknown_top = _write_json(tmp_path / "u1.json", {"leaks": [], "extra": 1})
    with pytest.raises(SchemaValidationError):
        load_ground_truth(unknown_top)

    unknown_leak_field = _write_json(
        tmp_path / "u2.json",
        {
            "leaks": [
                {
                    "id": "L1",
                    "task": "t1",
                    "path": "a.py",
                    "line_start": 1,
                    "line_end": 2,
                    "detector_hint": None,
                    "kind": "real",
                    "unexpected": "nope",
                }
            ]
        },
    )
    with pytest.raises(SchemaValidationError):
        load_ground_truth(unknown_leak_field)

    missing_finding_field = _write_json(
        tmp_path / "m1.json",
        {
            "findings": [
                {
                    "task": "t1",
                    "detector": "d1",
                    "path": "a.py",
                    "line_start": 1,
                    "line_end": 2,
                }
            ]
        },
    )
    with pytest.raises(SchemaValidationError):
        load_findings(missing_finding_field)


def test_req1_rejects_invalid_types_and_bounds(tmp_path: Path) -> None:
    # Boolean instead of integer for line_start must be rejected.
    bool_line = _write_json(
        tmp_path / "bool_line.json",
        {
            "leaks": [
                {
                    "id": "L1",
                    "task": "t1",
                    "path": "a.py",
                    "line_start": True,
                    "line_end": 2,
                    "detector_hint": None,
                    "kind": "real",
                }
            ]
        },
    )
    with pytest.raises(SchemaValidationError):
        load_ground_truth(bool_line)

    # line_end < line_start must be rejected.
    inverted_range = _write_json(
        tmp_path / "inv.json",
        {
            "findings": [
                {
                    "task": "t1",
                    "detector": "d1",
                    "path": "a.py",
                    "line_start": 10,
                    "line_end": 9,
                    "severity": "gate",
                }
            ]
        },
    )
    with pytest.raises(SchemaValidationError):
        load_findings(inverted_range)

    # Duplicate leak ID must be rejected.
    dup_id = _write_json(
        tmp_path / "dup_id.json",
        {
            "leaks": [
                {
                    "id": "L1",
                    "task": "t1",
                    "path": "a.py",
                    "line_start": 1,
                    "line_end": 2,
                    "detector_hint": None,
                    "kind": "real",
                },
                {
                    "id": "L1",
                    "task": "t1",
                    "path": "b.py",
                    "line_start": 3,
                    "line_end": 4,
                    "detector_hint": None,
                    "kind": "seeded",
                },
            ]
        },
    )
    with pytest.raises(SchemaValidationError):
        load_ground_truth(dup_id)

    # NaN constant in JSON must be rejected.
    nan_file = tmp_path / "nan.json"
    nan_file.write_text(
        '{"findings": [{"task": "t1", "detector": "d1", "path": "a.py", '
        '"line_start": NaN, "line_end": 2, "severity": "gate"}]}',
        encoding="utf-8",
    )
    with pytest.raises(JsonFormatError):
        load_findings(nan_file)


def test_req1_refuses_symlinks_and_non_regular_files(tmp_path: Path) -> None:
    real_file = _write_json(tmp_path / "real.json", {"leaks": []})
    symlink_file = tmp_path / "link.json"
    symlink_file.symlink_to(real_file)

    with pytest.raises(FileSecurityError):
        load_ground_truth(symlink_file)

    # Directory is a non-regular file and must be refused.
    with pytest.raises(FileSecurityError):
        load_ground_truth(tmp_path)

    # FIFO (named pipe) is a non-regular file and must be refused without blocking.
    if hasattr(os, "mkfifo"):
        fifo_path = tmp_path / "pipe.json"
        os.mkfifo(fifo_path)
        with pytest.raises(FileSecurityError):
            load_findings(fifo_path)


def test_req1_enforces_file_size_and_entry_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # File exceeding MAX_FILE_BYTES (16 MiB) must fail with SizeLimitError.
    oversized = tmp_path / "big.json"
    with oversized.open("wb") as handle:
        handle.seek(MAX_FILE_BYTES)
        handle.write(b" ")
    with pytest.raises(SizeLimitError):
        load_ground_truth(oversized)

    # Entry count cap (200,000 in production; patched to 3 to verify exact enforcement).
    monkeypatch.setattr(match_mod, "MAX_ENTRIES", 3)
    too_many = {
        "findings": [
            {
                "task": "t1",
                "detector": "d1",
                "path": "a.py",
                "line_start": i + 1,
                "line_end": i + 1,
                "severity": "gate",
            }
            for i in range(4)
        ]
    }
    with pytest.raises(SizeLimitError):
        parse_findings(too_many)


# ---------------------------------------------------------------------------
# Requirement 2: Matching rules (overlap boundaries, info ignored,
#                no double counting, multi-leak match)
# ---------------------------------------------------------------------------


def test_req2_overlap_boundaries_touching_vs_adjacent() -> None:
    # Touching ranges overlap: [10, 15] and [15, 20] share line 15.
    assert ranges_overlap(10, 15, 15, 20) is True
    assert ranges_overlap(15, 20, 10, 15) is True
    # Adjacent ranges do not overlap: [10, 15] and [16, 20] share no lines.
    assert ranges_overlap(10, 15, 16, 20) is False
    assert ranges_overlap(16, 20, 10, 15) is False

    leaks = (
        Leak("L_touch", "t1", "f.py", 10, 15, None, "real"),
        Leak("L_adj", "t1", "f.py", 16, 20, None, "real"),
    )
    findings = (Finding("t1", "det1", "f.py", 5, 10, "gate"),)
    res = match_findings(leaks, findings)
    assert res.matched_leak_ids == ("L_touch",)
    assert res.unmatched_active_findings == ()


def test_req2_info_findings_ignored_completely() -> None:
    leaks = (Leak("L1", "t1", "f.py", 10, 20, None, "real"),)
    findings = (
        # Info overlapping L1 must NOT match L1.
        Finding("t1", "det1", "f.py", 10, 20, "info"),
        # Info nowhere near L1 must NOT become a false positive.
        Finding("t1", "det1", "other.py", 1, 5, "info"),
    )
    res = match_findings(leaks, findings)
    assert res.matched_leak_ids == ()
    assert res.unmatched_active_findings == ()
    assert res.active_finding_count == 0
    assert res.ignored_info_finding_count == 2


def test_req2_double_counting_prevented_and_one_finding_can_match_several_leaks() -> None:
    leaks = (
        Leak("L1", "t1", "f.py", 10, 12, None, "real"),
        Leak("L2", "t1", "f.py", 18, 20, None, "seeded"),
    )
    findings = (
        # Broad finding spans both L1 and L2 -> matches both leaks.
        Finding("t1", "det1", "f.py", 1, 25, "gate"),
        # Second finding also overlaps L1 -> L1 must still be counted only once.
        Finding("t1", "det2", "f.py", 11, 11, "warning"),
    )
    res = match_findings(leaks, findings)
    assert res.matched_leak_ids == ("L1", "L2")
    assert res.unmatched_active_findings == ()

    overall, _, _ = compute_all_metrics(leaks, findings, match_result=res)
    assert overall.tp == 2
    assert overall.fn == 0
    assert overall.fp == 0
    assert overall.recall_permille == 1000
    assert overall.precision_permille == 1000


# ---------------------------------------------------------------------------
# Requirement 3: Overall, per-detector, and per-kind metrics with integer
#                per-mille rounded down and FP deduplication
# ---------------------------------------------------------------------------


def test_req3_overall_per_detector_and_per_kind_metrics_and_fp_dedup() -> None:
    leaks = (
        Leak("R1", "t1", "a.py", 10, 12, "d1", "real"),
        Leak("R2", "t1", "b.py", 20, 22, "d2", "real"),
        Leak("R3", "t2", "c.py", 30, 32, None, "real"),
        Leak("S1", "t1", "d.py", 40, 42, "d1", "seeded"),
    )
    findings = (
        # d1 catches R1 and S1, and emits two duplicate FPs at the exact same location/range/detector.
        Finding("t1", "d1", "a.py", 10, 12, "gate"),
        Finding("t1", "d1", "d.py", 41, 41, "warning"),
        Finding("t1", "d1", "fp.py", 1, 3, "gate"),
        Finding("t1", "d1", "fp.py", 1, 3, "warning"),  # Deduplicated with above FP!
        # d2 catches R2 and emits one distinct FP at the same file/range (different detector).
        Finding("t1", "d2", "b.py", 20, 22, "gate"),
        Finding("t1", "d2", "fp.py", 1, 3, "gate"),
        # d3 emits only an info finding -> 0 TP, 0 FP, 4 FN.
        Finding("t2", "d3", "c.py", 30, 32, "info"),
    )

    overall, per_detector, per_kind = compute_all_metrics(leaks, findings)

    # Overall: 3 TP (R1, R2, S1), 1 FN (R3), 2 deduplicated FPs (d1 fp.py:1-3, d2 fp.py:1-3).
    # Precision = floor(3 * 1000 / 5) = 600; Recall = floor(3 * 1000 / 4) = 750.
    assert overall.tp == 3
    assert overall.fn == 1
    assert overall.fp == 2
    assert overall.precision_permille == 600
    assert overall.recall_permille == 750
    assert overall.missed_leak_ids == ("R3",)

    # Per detector:
    assert sorted(per_detector.keys()) == ["d1", "d2", "d3"]
    # d1: 2 TP (R1, S1), 2 FN (R2, R3), 1 FP -> precision = floor(2000/3) = 666, recall = 500.
    assert per_detector["d1"].tp == 2
    assert per_detector["d1"].fn == 2
    assert per_detector["d1"].fp == 1
    assert per_detector["d1"].precision_permille == 666
    assert per_detector["d1"].recall_permille == 500
    assert per_detector["d1"].missed_leak_ids == ("R2", "R3")

    # d2: 1 TP (R2), 3 FN (R1, R3, S1), 1 FP -> precision = 500, recall = 250.
    assert per_detector["d2"].tp == 1
    assert per_detector["d2"].fn == 3
    assert per_detector["d2"].fp == 1
    assert per_detector["d2"].precision_permille == 500
    assert per_detector["d2"].recall_permille == 250
    assert per_detector["d2"].missed_leak_ids == ("R1", "R3", "S1")

    # d3: 0 TP, 4 FN, 0 FP -> precision = 0, recall = 0.
    assert per_detector["d3"].tp == 0
    assert per_detector["d3"].fn == 4
    assert per_detector["d3"].fp == 0
    assert per_detector["d3"].precision_permille == 0
    assert per_detector["d3"].recall_permille == 0
    assert per_detector["d3"].missed_leak_ids == ("R1", "R2", "R3", "S1")

    # Per kind:
    # real: 2 TP (R1, R2), 1 FN (R3), 2 FP -> precision = floor(2000/4) = 500, recall = floor(2000/3) = 666.
    assert per_kind["real"].tp == 2
    assert per_kind["real"].fn == 1
    assert per_kind["real"].fp == 2
    assert per_kind["real"].precision_permille == 500
    assert per_kind["real"].recall_permille == 666
    assert per_kind["real"].missed_leak_ids == ("R3",)

    # seeded: 1 TP (S1), 0 FN, 2 FP -> precision = floor(1000/3) = 333, recall = 1000.
    assert per_kind["seeded"].tp == 1
    assert per_kind["seeded"].fn == 0
    assert per_kind["seeded"].fp == 2
    assert per_kind["seeded"].precision_permille == 333
    assert per_kind["seeded"].recall_permille == 1000
    assert per_kind["seeded"].missed_leak_ids == ()


# ---------------------------------------------------------------------------
# Requirement 4: Percentile bootstrap CI over tasks (determinism & known answer
#                with seed 7)
# ---------------------------------------------------------------------------


def test_req4_bootstrap_determinism_and_known_answer_seed_7() -> None:
    # Two tasks:
    # - task_1: 1 leak matched, 0 FPs -> (tp=1, fn=0, fp=0)
    # - task_2: 1 leak missed, 1 FP  -> (tp=0, fn=1, fp=1)
    leaks = (
        Leak("L1", "task_1", "a.py", 1, 2, None, "real"),
        Leak("L2", "task_2", "b.py", 1, 2, None, "real"),
    )
    findings = (
        Finding("task_1", "det", "a.py", 1, 2, "gate"),
        Finding("task_2", "det", "fp.py", 5, 6, "gate"),
    )

    ci_first = bootstrap_confidence_interval(leaks, findings, seed=7)
    ci_second = bootstrap_confidence_interval(leaks, findings, seed=7)
    assert ci_first == ci_second
    assert ci_first.bootstrap_iterations == 1000
    assert ci_first.seed == 7
    assert ci_first.task_count == 2

    # With 2 equally likely tasks (task_1 -> 1000, task_2 -> 0), each extreme occurs
    # with p = 0.25 (> 0.025), so for B=1000 the 2.5th percentile is 0 and 97.5th is 1000.
    assert ci_first.recall.low_permille == 0
    assert ci_first.recall.high_permille == 1000
    assert ci_first.precision.low_permille == 0
    assert ci_first.precision.high_permille == 1000

    # Hand-verified exact sequence for B=10 with seed=7:
    rng = random.Random(7)
    triples = [(1, 0, 0), (0, 1, 1)]
    expected_recalls = []
    expected_precisions = []
    for _ in range(10):
        tp = fn = fp = 0
        for _ in range(2):
            t_tp, t_fn, t_fp = triples[rng.randrange(2)]
            tp += t_tp
            fn += t_fn
            fp += t_fp
        expected_recalls.append((tp * 1000) // (tp + fn))
        expected_precisions.append((tp * 1000) // (tp + fp))
    expected_recalls.sort()
    expected_precisions.sort()

    ci_small = bootstrap_confidence_interval(leaks, findings, seed=7, bootstrap_iterations=10)
    assert ci_small.recall.low_permille == expected_recalls[0]
    assert ci_small.recall.high_permille == expected_recalls[9]
    assert ci_small.precision.low_permille == expected_precisions[0]
    assert ci_small.precision.high_permille == expected_precisions[9]


# ---------------------------------------------------------------------------
# Requirement 5: Exit-criterion check on 'real' kind
# ---------------------------------------------------------------------------


def test_req5_exit_criterion_checks_real_kind_thresholds() -> None:
    leaks = (
        Leak("R1", "t1", "a.py", 1, 2, None, "real"),
        Leak("R2", "t1", "b.py", 1, 2, None, "real"),
        Leak("S1", "t1", "c.py", 1, 2, None, "seeded"),
    )
    # Matches R1 and S1 (misses R2), plus 1 FP -> real recall = 500, real precision = 500.
    findings = (
        Finding("t1", "det", "a.py", 1, 2, "gate"),
        Finding("t1", "det", "c.py", 1, 2, "gate"),
        Finding("t1", "det", "fp.py", 9, 9, "gate"),
    )

    report_pass = evaluate(
        leaks, findings, seed=7, min_recall_permille=500, min_precision_permille=500
    )
    assert report_pass.exit_criterion.passed is True
    assert report_pass.exit_criterion.kind == "real"
    assert report_pass.exit_criterion.actual_recall_permille == 500
    assert report_pass.exit_criterion.actual_precision_permille == 500

    report_fail = evaluate(
        leaks, findings, seed=7, min_recall_permille=501, min_precision_permille=500
    )
    assert report_fail.exit_criterion.passed is False
    assert report_fail.exit_criterion.recall_passed is False
    assert report_fail.exit_criterion.precision_passed is True
    _assert_no_floats_anywhere(report_fail.to_dict())


# ---------------------------------------------------------------------------
# Requirement 6: CLI deterministic JSON and exit codes (0 pass, 2 fail, 1 error)
# ---------------------------------------------------------------------------


def test_req6_cli_exit_codes_0_2_1_and_deterministic_json(tmp_path: Path) -> None:
    truth_file = _write_json(
        tmp_path / "truth.json",
        {
            "leaks": [
                {
                    "id": "R1",
                    "task": "t1",
                    "path": "a.py",
                    "line_start": 1,
                    "line_end": 2,
                    "detector_hint": None,
                    "kind": "real",
                },
                {
                    "id": "R2",
                    "task": "t1",
                    "path": "b.py",
                    "line_start": 1,
                    "line_end": 2,
                    "detector_hint": None,
                    "kind": "real",
                },
            ]
        },
    )
    findings_file = _write_json(
        tmp_path / "findings.json",
        {
            "findings": [
                {
                    "task": "t1",
                    "detector": "d1",
                    "path": "a.py",
                    "line_start": 1,
                    "line_end": 2,
                    "severity": "gate",
                }
            ]
        },
    )

    # Exit 0 (pass): real recall is 500, real precision is 1000.
    out_pass_1 = io.StringIO()
    err_pass_1 = io.StringIO()
    rc_pass_1 = run_cli(
        [
            "--truth",
            str(truth_file),
            "--findings",
            str(findings_file),
            "--seed",
            "7",
            "--min-recall",
            "500",
            "--min-precision",
            "1000",
        ],
        stdout=out_pass_1,
        stderr=err_pass_1,
    )
    assert rc_pass_1 == 0
    assert err_pass_1.getvalue() == ""

    out_pass_2 = io.StringIO()
    err_pass_2 = io.StringIO()
    rc_pass_2 = run_cli(
        [
            "--truth",
            str(truth_file),
            "--findings",
            str(findings_file),
            "--seed",
            "7",
            "--min-recall",
            "500",
            "--min-precision",
            "1000",
        ],
        stdout=out_pass_2,
        stderr=err_pass_2,
    )
    assert rc_pass_2 == 0
    assert out_pass_1.getvalue() == out_pass_2.getvalue()
    parsed_pass = json.loads(out_pass_1.getvalue())
    _assert_no_floats_anywhere(parsed_pass)
    assert parsed_pass["exit_criterion"]["passed"] is True

    # Exit 2 (fail): require min-recall 600 when actual is 500.
    out_fail = io.StringIO()
    err_fail = io.StringIO()
    rc_fail = run_cli(
        [
            "--truth",
            str(truth_file),
            "--findings",
            str(findings_file),
            "--seed",
            "7",
            "--min-recall",
            "600",
            "--min-precision",
            "1000",
        ],
        stdout=out_fail,
        stderr=err_fail,
    )
    assert rc_fail == 2
    parsed_fail = json.loads(out_fail.getvalue())
    _assert_no_floats_anywhere(parsed_fail)
    assert parsed_fail["exit_criterion"]["passed"] is False

    # Exit 1 (error): bad CLI argument, out-of-range threshold, or missing file.
    out_err = io.StringIO()
    err_err = io.StringIO()
    rc_err = run_cli(
        ["--truth", str(truth_file), "--findings", str(findings_file)],  # missing --seed
        stdout=out_err,
        stderr=err_err,
    )
    assert rc_err == 1
    assert out_err.getvalue() == ""
    err_json = json.loads(err_err.getvalue())
    assert err_json["error"]["type"] == "CliArgumentError"

    # Subprocess smoke test verifying `python -m hermetic_e3` entrypoint.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermetic_e3",
            "--truth",
            str(truth_file),
            "--findings",
            str(findings_file),
            "--seed",
            "7",
            "--min-recall",
            "500",
            "--min-precision",
            "1000",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == out_pass_1.getvalue()


