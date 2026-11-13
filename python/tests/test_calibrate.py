
"""Tests for hermetic_calibrate covering every requirement and hostile edge cases."""

from __future__ import annotations

import json
import os
from pathlib import Path
import random
import subprocess
import sys
from typing import Any

import pytest

import hermetic_calibrate.calibrate as cal_mod
from hermetic_calibrate import (
    MAX_INPUT_BYTES,
    CalibrationConfig,
    ConfigError,
    InputFileError,
    Sample,
    SchemaValidationError,
    calibrate_file,
    calibrate_samples,
    format_result_json,
    parse_samples_bytes,
    parse_samples_json,
)
from hermetic_calibrate.__main__ import main


def _assert_no_floats(value: Any) -> None:
    """Recursively verify that no float instances exist anywhere in output data."""
    assert type(value) is not float, f"Found unexpected float: {value!r}"
    if isinstance(value, dict):
        for k, v in value.items():
            _assert_no_floats(k)
            _assert_no_floats(v)
    elif isinstance(value, list):
        for item in value:
            _assert_no_floats(item)


def _make_samples(
    detector: str,
    leak_scores: list[int],
    clean_scores: list[int],
    prefix: str = "task",
) -> list[dict[str, Any]]:
    """Build hand-written sample dicts with unique task names."""
    rows: list[dict[str, Any]] = []
    for idx, score in enumerate(leak_scores):
        rows.append(
            {
                "detector": detector,
                "task": f"{prefix}-leak-{idx:04d}",
                "score": score,
                "label": "leak",
            }
        )
    for idx, score in enumerate(clean_scores):
        rows.append(
            {
                "detector": detector,
                "task": f"{prefix}-clean-{idx:04d}",
                "score": score,
                "label": "clean",
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Requirement 1: Input JSON schema, size/sample caps, duplicate keys, uniqueness
# ---------------------------------------------------------------------------


def test_req1_rejects_oversized_file_above_32mib(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    with open(oversized, "wb") as handle:
        handle.seek(MAX_INPUT_BYTES)
        handle.write(b" ")

    with pytest.raises(InputFileError):
        calibrate_file(oversized)


def test_req1_rejects_sample_count_above_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cal_mod, "MAX_SAMPLES", 3)
    raw = json.dumps(
        {
            "samples": [
                {"detector": "d1", "task": f"t{i}", "score": i * 10, "label": "clean"}
                for i in range(4)
            ]
        }
    )
    with pytest.raises(SchemaValidationError):
        parse_samples_json(raw)


def test_req1_rejects_duplicate_json_keys() -> None:
    dup_root = '{"samples": [], "samples": []}'
    with pytest.raises(SchemaValidationError, match="Duplicate JSON key"):
        parse_samples_json(dup_root)

    dup_item = (
        '{"samples": [{"detector": "d1", "detector": "d2", '
        '"task": "t1", "score": 100, "label": "clean"}]}'
    )
    with pytest.raises(SchemaValidationError, match="Duplicate JSON key"):
        parse_samples_json(dup_item)


@pytest.mark.parametrize(
    "bad_json",
    [
        "[]",
        "{}",
        '{"samples": [], "extra": 1}',
        '{"samples": "not-a-list"}',
        '{"samples": [123]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": 10}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": 10, "label": "clean", "x": 1}]}',
        '{"samples": [{"detector": "", "task": "t1", "score": 10, "label": "clean"}]}',
        '{"samples": [{"detector": "   ", "task": "t1", "score": 10, "label": "clean"}]}',
        '{"samples": [{"detector": 123, "task": "t1", "score": 10, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "", "score": 10, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": true, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": 10.5, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": -1, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": 1000001, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": 10, "label": "LEAK"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": NaN, "label": "clean"}]}',
        '{"samples": [{"detector": "d1", "task": "t1", "score": Infinity, "label": "clean"}]}',
    ],
)
def test_req1_strict_schema_rejections(bad_json: str) -> None:
    with pytest.raises(SchemaValidationError):
        parse_samples_json(bad_json)


def test_req1_rejects_duplicate_detector_task_pair() -> None:
    dup_pair = json.dumps(
        {
            "samples": [
                {"detector": "detA", "task": "task1", "score": 100, "label": "clean"},
                {"detector": "detA", "task": "task1", "score": 200, "label": "leak"},
            ]
        }
    )
    with pytest.raises(SchemaValidationError, match="Duplicate"):
        parse_samples_json(dup_pair)

    # Same task across different detectors IS valid.
    cross_detector = json.dumps(
        {
            "samples": [
                {"detector": "detA", "task": "task1", "score": 100, "label": "clean"},
                {"detector": "detB", "task": "task1", "score": 200, "label": "leak"},
            ]
        }
    )
    parsed = parse_samples_json(cross_detector)
    assert len(parsed) == 2


# ---------------------------------------------------------------------------
# Requirement 2: Known-answer curves, floor per-mille rates, ties in scores
# ---------------------------------------------------------------------------


def test_req2_known_answer_curve_floor_rounding_and_no_floats() -> None:
    # 3 leaks at scores [200, 500, 800], 7 clean at scores [100, 100, 200, 300, 400, 600, 700].
    # Non-divisible denominators (3 and 7) verify floor division in per-mille:
    # 1/3 -> 333, 2/3 -> 666, 1/7 -> 142, 4/7 -> 571, 5/7 -> 714.
    rows = _make_samples("det_math", [200, 500, 800], [100, 100, 200, 300, 400, 600, 700])
    samples = parse_samples_json(json.dumps({"samples": rows}))
    cfg = CalibrationConfig(
        max_false_alarm=150,
        min_recall=600,
        min_leak_samples=1,
        min_clean_samples=1,
    )
    result = calibrate_samples(samples, cfg)
    _assert_no_floats(result)

    det = result["detectors"]["det_math"]
    expected_curve = [
        {"threshold": 100, "tp": 3, "fp": 7, "tn": 0, "fn": 0, "recall": 1000, "false_alarm_rate": 1000},
        {"threshold": 200, "tp": 3, "fp": 5, "tn": 2, "fn": 0, "recall": 1000, "false_alarm_rate": 714},
        {"threshold": 300, "tp": 2, "fp": 4, "tn": 3, "fn": 1, "recall": 666, "false_alarm_rate": 571},
        {"threshold": 400, "tp": 2, "fp": 3, "tn": 4, "fn": 1, "recall": 666, "false_alarm_rate": 428},
        {"threshold": 500, "tp": 2, "fp": 2, "tn": 5, "fn": 1, "recall": 666, "false_alarm_rate": 285},
        {"threshold": 600, "tp": 1, "fp": 2, "tn": 5, "fn": 2, "recall": 333, "false_alarm_rate": 285},
        {"threshold": 700, "tp": 1, "fp": 1, "tn": 6, "fn": 2, "recall": 333, "false_alarm_rate": 142},
        {"threshold": 800, "tp": 1, "fp": 0, "tn": 7, "fn": 2, "recall": 333, "false_alarm_rate": 0},
    ]
    assert det["curve"] == expected_curve
    assert det["status"] == "no_threshold"
    assert det["best_available"] == expected_curve[6]
    assert det["reason"] == "recall_below_min_recall"


def test_req2_ties_in_scores() -> None:
    # All leaks tied at 500; clean split between 100 (99 samples) and 500 (1 sample).
    rows = _make_samples("det_tie", [500] * 20, [100] * 99 + [500])
    samples = parse_samples_json(json.dumps({"samples": rows}))
    result = calibrate_samples(samples)
    _assert_no_floats(result)

    det = result["detectors"]["det_tie"]
    assert [pt["threshold"] for pt in det["curve"]] == [100, 500]
    assert det["curve"][1] == {
        "threshold": 500,
        "tp": 20,
        "fp": 1,
        "tn": 99,
        "fn": 0,
        "recall": 1000,
        "false_alarm_rate": 10,
    }
    assert det["threshold"] == 500


# ---------------------------------------------------------------------------
# Requirement 3: Exact boundary limits & no_threshold handling
# ---------------------------------------------------------------------------


def test_req3_exact_boundary_limits_and_lowest_threshold_choice() -> None:
    # 20 leaks: 18 at score 500, 2 at score 100 -> at t=500 recall = 18*1000//20 = 900 (exact min_recall).
    # 100 clean: 1 at score 500, 99 at score 100 -> at t=500 FAR = 1*1000//100 = 10 (exact max_false_alarm).
    # Add another leak at 700 so t=700 also qualifies (recall 19/20=950? Wait: keep 18 at 700 and 2 at 100,
    # and add 1 leak at 500 -> 19 leaks: 1 at 500, 18 at 700; let's use 20 leaks: 1 at 500, 18 at 700, 1 at 100).
    # At t=500: TP=19 (recall=950), FP=1 (FAR=10). At t=700: TP=18 (recall=900), FP=0 (FAR=0).
    # Both t=500 and t=700 qualify; lowest qualifying threshold t=500 must be chosen!
    rows = _make_samples(
        "det_boundary",
        leak_scores=[100, 500] + [700] * 18,
        clean_scores=[100] * 99 + [500],
    )
    samples = parse_samples_json(json.dumps({"samples": rows}))
    result = calibrate_samples(samples)
    det = result["detectors"]["det_boundary"]
    assert det["status"] == "calibrated"
    assert det["threshold"] == 500
    assert det["metrics"]["false_alarm_rate"] == 10

    # Now test exact recall=900 and exact FAR=10 at t=500:
    rows_exact = _make_samples(
        "det_exact",
        leak_scores=[100, 100] + [500] * 18,
        clean_scores=[100] * 99 + [500],
    )
    res_exact = calibrate_samples(parse_samples_json(json.dumps({"samples": rows_exact})))
    det_exact = res_exact["detectors"]["det_exact"]
    assert det_exact["status"] == "calibrated"
    assert det_exact["threshold"] == 500
    assert det_exact["metrics"]["recall"] == 900
    assert det_exact["metrics"]["false_alarm_rate"] == 10

    # One fewer leak above 500 drops recall to 17*1000//20 = 850 < 900 -> no_threshold.
    rows_below = _make_samples(
        "det_below",
        leak_scores=[100, 100, 100] + [500] * 17,
        clean_scores=[100] * 99 + [500],
    )
    res_below = calibrate_samples(parse_samples_json(json.dumps({"samples": rows_below})))
    det_below = res_below["detectors"]["det_below"]
    assert det_below["status"] == "no_threshold"
    assert det_below["threshold"] is None
    assert "no_threshold" in det_below["flags"]
    assert det_below["best_available"]["threshold"] == 500
    assert det_below["best_available"]["recall"] == 850
    assert det_below["reason"] == "recall_below_min_recall"


def test_req3_no_candidate_meets_false_alarm_limit() -> None:
    # All 50 clean samples have score 900, all 20 leaks have score 900 -> FAR is 1000 everywhere.
    rows = _make_samples("det_all_high", [900] * 20, [900] * 50)
    res = calibrate_samples(parse_samples_json(json.dumps({"samples": rows})))
    det = res["detectors"]["det_all_high"]
    assert det["status"] == "no_threshold"
    assert det["threshold"] is None
    assert det["best_available"] is None
    assert det["reason"] == "no_candidate_meets_max_false_alarm"
    assert "no_threshold" in det["flags"]


# ---------------------------------------------------------------------------
# Requirement 4: Minimum data -> insufficient_data
# ---------------------------------------------------------------------------


def test_req4_insufficient_data_boundaries() -> None:
    # 19 leaks + 50 clean -> insufficient_data
    low_leaks = _make_samples("d_low_leak", [800] * 19, [100] * 50)
    # 20 leaks + 49 clean -> insufficient_data
    low_clean = _make_samples("d_low_clean", [800] * 20, [100] * 49)
    # 20 leaks + 50 clean -> calibrated
    enough = _make_samples("d_enough", [800] * 20, [100] * 50)

    samples = parse_samples_json(
        json.dumps({"samples": low_leaks + low_clean + enough})
    )
    res = calibrate_samples(samples)

    assert res["detectors"]["d_low_leak"]["status"] == "insufficient_data"
    assert res["detectors"]["d_low_leak"]["threshold"] is None
    assert "insufficient_data" in res["detectors"]["d_low_leak"]["flags"]

    assert res["detectors"]["d_low_clean"]["status"] == "insufficient_data"
    assert res["detectors"]["d_low_clean"]["threshold"] is None
    assert "insufficient_data" in res["detectors"]["d_low_clean"]["flags"]

    assert res["detectors"]["d_enough"]["status"] == "calibrated"
    assert res["detectors"]["d_enough"]["threshold"] == 800


# ---------------------------------------------------------------------------
# Requirement 5: Leave-one-task-out stability & integer ratio check
# ---------------------------------------------------------------------------


def _naive_loo_thresholds(samples: list[Sample], cfg: CalibrationConfig) -> list[int | None]:
    """Reference brute-force LOO threshold recomputation for cross-checking."""
    results: list[int | None] = []
    for i in range(len(samples)):
        subset = samples[:i] + samples[i + 1 :]
        sub_cfg = CalibrationConfig(
            max_false_alarm=cfg.max_false_alarm,
            min_recall=cfg.min_recall,
            min_leak_samples=1,
            min_clean_samples=1,
            stability_numerator=cfg.stability_numerator,
            stability_denominator=cfg.stability_denominator,
        )
        sub_res = calibrate_samples(subset, sub_cfg)
        det_name = samples[0].detector
        results.append(sub_res["detectors"][det_name]["threshold"])
    return results


def test_req5_stability_boundary_and_unstable_detection() -> None:
    # Construct dataset where full threshold is 100, and removing a specific clean
    # outlier shifts threshold to 150 (stable: 150*100 == 100*150) vs 151 (unstable: 151*100 > 100*150).
    # With 100 clean samples and max_false_alarm=10 (allows 1 FP):
    # - 98 clean at score 50
    # - 1 clean at score 100
    # - 1 clean at score 120
    # Full data at t=100: FP=2 (FAR=20 > 10). At t=120: FP=1 (FAR=10 <= 10).
    # Wait: if we have 99 clean at 50, 1 clean at 100, and 1 clean at 150 (total 101 clean):
    # - Full data: at t=100, FP=2 -> 2000//101 = 19 > 10. At t=150, FP=1 -> 1000//101 = 9 <= 10 -> chosen=150.
    # - Remove the clean sample at 150 (100 clean left):
    #   at t=100, FP=1 -> 1000//100 = 10 <= 10 -> LOO chosen=100!
    # - Remove a clean sample at 50 (100 clean left):
    #   at t=100, FP=2 -> 2000//100 = 20 > 10; at t=150, FP=1 -> 1000//100 = 10 -> LOO chosen=150!
    # So LOO sees min_threshold=100 and max_threshold=150 -> 150 * 100 <= 100 * 150 -> STABLE!
    stable_rows = _make_samples(
        "det_stable",
        leak_scores=[200] * 20,
        clean_scores=[50] * 99 + [100, 150],
    )
    stable_samples = parse_samples_json(json.dumps({"samples": stable_rows}))
    stable_res = calibrate_samples(stable_samples)
    det_s = stable_res["detectors"]["det_stable"]
    assert det_s["threshold"] == 150
    assert det_s["stability"]["min_threshold"] == 100
    assert det_s["stability"]["max_threshold"] == 150
    assert det_s["stability"]["unstable"] is False
    assert "unstable" not in det_s["flags"]

    # Verify exact match with brute-force LOO reference:
    ref_thresholds = [
        t for t in _naive_loo_thresholds(stable_samples, CalibrationConfig()) if t is not None
    ]
    assert min(ref_thresholds) == det_s["stability"]["min_threshold"]
    assert max(ref_thresholds) == det_s["stability"]["max_threshold"]

    # Now change 150 -> 151: min=100, max=151 -> 151 * 100 > 100 * 150 -> UNSTABLE!
    unstable_rows = _make_samples(
        "det_unstable",
        leak_scores=[200] * 20,
        clean_scores=[50] * 99 + [100, 151],
    )
    unstable_samples = parse_samples_json(json.dumps({"samples": unstable_rows}))
    unstable_res = calibrate_samples(unstable_samples)
    det_u = unstable_res["detectors"]["det_unstable"]
    assert det_u["threshold"] == 151
    assert det_u["stability"]["min_threshold"] == 100
    assert det_u["stability"]["max_threshold"] == 151
    assert det_u["stability"]["unstable"] is True
    assert "unstable" in det_u["flags"]


def test_req5_loo_fold_dropping_below_min_recall_flags_unstable() -> None:
    # 20 leaks: 18 at 500, 2 at 100 -> full recall at 500 is 18*1000//20 = 900.
    # Removing any of the 18 leaks at 500 leaves 17 leaks at 500 out of 19 -> 17000//19 = 894 < 900,
    # so those 18 LOO folds fail to qualify and detector is flagged unstable.
    rows = _make_samples("det_fragile", [100, 100] + [500] * 18, [100] * 50)
    res = calibrate_samples(parse_samples_json(json.dumps({"samples": rows})))
    det = res["detectors"]["det_fragile"]
    assert det["status"] == "calibrated"
    assert det["stability"]["failed_folds"] == 18
    assert det["stability"]["unstable"] is True
    assert "unstable" in det["flags"]


# ---------------------------------------------------------------------------
# Requirement 6 & Rules: Symlinks, non-regular files, determinism, CLI exits
# ---------------------------------------------------------------------------


def test_rules_refuses_symlinks_and_non_regular_files(tmp_path: Path) -> None:
    real_file = tmp_path / "real.json"
    real_file.write_text('{"samples": []}', encoding="utf-8")

    symlink_file = tmp_path / "link.json"
    symlink_file.symlink_to(real_file)

    with pytest.raises(InputFileError, match="symlink"):
        calibrate_file(symlink_file)

    with pytest.raises(InputFileError, match="non-regular"):
        calibrate_file(tmp_path)

    with pytest.raises(InputFileError):
        calibrate_file(tmp_path / "does_not_exist.json")

    if hasattr(os, "mkfifo"):
        fifo_path = tmp_path / "pipe.json"
        os.mkfifo(fifo_path)
        with pytest.raises(InputFileError, match="non-regular"):
            calibrate_file(fifo_path)


def test_req6_determinism_regardless_of_input_order() -> None:
    rows = (
        _make_samples("zeta_det", [700] * 20, [100] * 50, prefix="z")
        + _make_samples("alpha_det", [600] * 20, [100] * 50, prefix="a")
        + _make_samples("mid_det", [500] * 5, [100] * 50, prefix="m")
    )
    rng = random.Random(42)
    shuffled = list(rows)
    rng.shuffle(shuffled)

    out_original = format_result_json(
        calibrate_samples(parse_samples_json(json.dumps({"samples": rows})))
    )
    out_shuffled = format_result_json(
        calibrate_samples(parse_samples_json(json.dumps({"samples": shuffled})))
    )

    assert out_original == out_shuffled
    parsed_out = json.loads(out_original)
    assert list(parsed_out["detectors"].keys()) == ["alpha_det", "mid_det", "zeta_det"]


def test_req6_cli_exit_codes_and_subprocess(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. All detectors calibrated -> exit 0
    ok_file = tmp_path / "ok.json"
    ok_rows = _make_samples("det_ok", [800] * 20, [100] * 50)
    ok_file.write_text(json.dumps({"samples": ok_rows}), encoding="utf-8")

    rc_ok = main(["--samples", str(ok_file)])
    captured_ok = capsys.readouterr()
    assert rc_ok == 0
    parsed_ok = json.loads(captured_ok.out)
    _assert_no_floats(parsed_ok)
    assert parsed_ok["detectors"]["det_ok"]["threshold"] == 800

    # 2. At least one detector fails to get a threshold -> exit 2, valid JSON still printed
    mixed_file = tmp_path / "mixed.json"
    mixed_rows = ok_rows + _make_samples("det_insuff", [800] * 5, [100] * 50, prefix="ins")
    mixed_file.write_text(json.dumps({"samples": mixed_rows}), encoding="utf-8")

    rc_mixed = main(["--samples", str(mixed_file)])
    captured_mixed = capsys.readouterr()
    assert rc_mixed == 2
    parsed_mixed = json.loads(captured_mixed.out)
    assert parsed_mixed["detectors"]["det_ok"]["threshold"] == 800
    assert parsed_mixed["detectors"]["det_insuff"]["threshold"] is None

    # 3. Error (invalid CLI arg, symlink, or invalid JSON) -> exit 1
    rc_bad_arg = main(["--samples", str(ok_file), "--max-false-alarm", "10.5"])
    captured_err = capsys.readouterr()
    assert rc_bad_arg == 1
    assert "error" in captured_err.err

    # 4. End-to-end python -m hermetic_calibrate invocation
    proc = subprocess.run(
        [sys.executable, "-m", "hermetic_calibrate", "--samples", str(ok_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["detectors"]["det_ok"]["threshold"] == 800


def test_hostile_inputs_never_raise_unhandled_exceptions() -> None:
    with pytest.raises(SchemaValidationError):
        parse_samples_bytes(b"\xff\xfe\xfd")

    with pytest.raises(SchemaValidationError):
        parse_samples_json("[" * 5000)

    with pytest.raises(ConfigError):
        CalibrationConfig(max_false_alarm=1001)

    with pytest.raises(ConfigError):
        CalibrationConfig(stability_numerator=90, stability_denominator=100)




def _call_with_deadline(func: Any, deadline_s: float = 10.0) -> BaseException | None:
    """Run func in a daemon thread; fail the test if it blocks past the deadline."""
    import threading

    outcome: list[BaseException | None] = []

    def _target() -> None:
        try:
            func()
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            outcome.append(exc)

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(deadline_s)
    assert not worker.is_alive(), "file read blocked (FIFO opened without O_NONBLOCK)"
    return outcome[0] if outcome else None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_regression_fifo_swapped_in_after_lstat_does_not_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = tmp_path / "decoy.json"
    decoy.write_text('{"samples": []}', encoding="utf-8")
    decoy_stat = os.lstat(decoy)
    fifo_path = tmp_path / "swapped.json"
    os.mkfifo(fifo_path)
    real_lstat = os.lstat

    def fake_lstat(p: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(p) == os.fspath(fifo_path):
            return decoy_stat
        return real_lstat(p, *args, **kwargs)

    monkeypatch.setattr(cal_mod.os, "lstat", fake_lstat)
    err = _call_with_deadline(lambda: calibrate_file(fifo_path))
    assert isinstance(err, InputFileError)


def test_regression_file_swapped_after_lstat_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = tmp_path / "decoy.json"
    decoy.write_text('{"samples": []}', encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text('{"samples": []}', encoding="utf-8")
    decoy_stat = os.lstat(decoy)
    real_lstat = os.lstat

    def fake_lstat(p: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(p) == os.fspath(target):
            return decoy_stat
        return real_lstat(p, *args, **kwargs)

    monkeypatch.setattr(cal_mod.os, "lstat", fake_lstat)
    with pytest.raises(InputFileError, match="changed between"):
        calibrate_file(target)
