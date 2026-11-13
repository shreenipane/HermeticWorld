
"""Core threshold calibration engine for sealcheck detectors."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import stat
from typing import Any, Sequence

# Named constant caps bounding every file read, allocation, and loop.
MAX_INPUT_BYTES: int = 32 * 1024 * 1024
READ_CHUNK_BYTES: int = 64 * 1024
MAX_READ_CHUNKS: int = (MAX_INPUT_BYTES // READ_CHUNK_BYTES) + 2

MAX_SAMPLES: int = 1_000_000
MAX_DETECTORS: int = 100_000
MAX_TASKS_PER_DETECTOR: int = 1_000_000
MAX_IDENTIFIER_LENGTH: int = 1_024
MAX_JSON_OBJECT_KEYS: int = 16
MAX_BINARY_SEARCH_STEPS: int = 32

MIN_SCORE: int = 0
MAX_SCORE: int = 1_000_000
PER_MILLE_SCALE: int = 1_000

DEFAULT_MAX_FALSE_ALARM: int = 10
DEFAULT_MIN_RECALL: int = 900
DEFAULT_MIN_LEAK_SAMPLES: int = 20
DEFAULT_MIN_CLEAN_SAMPLES: int = 50
DEFAULT_STABILITY_NUMERATOR: int = 150
DEFAULT_STABILITY_DENOMINATOR: int = 100

_EXPECTED_ROOT_KEYS: frozenset[str] = frozenset({"samples"})
_EXPECTED_SAMPLE_KEYS: frozenset[str] = frozenset({"detector", "task", "score", "label"})
_VALID_LABELS: frozenset[str] = frozenset({"leak", "clean"})


class CalibrationError(Exception):
    """Base typed error for all calibration failures."""

    code: str = "calibration_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class InputFileError(CalibrationError):
    """Raised when reading or opening the input file violates safety or size rules."""

    code: str = "input_file_error"


class SchemaValidationError(CalibrationError):
    """Raised when input JSON fails strict schema, type, or uniqueness validation."""

    code: str = "schema_validation_error"


class ConfigError(CalibrationError):
    """Raised when calibration parameters or CLI arguments are invalid."""

    code: str = "config_error"


def _is_strict_int(value: Any) -> bool:
    """Return True if value is an exact int and not a bool."""
    return type(value) is int


@dataclass(frozen=True)
class Sample:
    """Validated benchmark task score record for a single detector."""

    detector: str
    task: str
    score: int
    label: str

    def __post_init__(self) -> None:
        _validate_identifier(self.detector, "detector")
        _validate_identifier(self.task, "task")
        if not _is_strict_int(self.score):
            raise SchemaValidationError("Sample 'score' must be an integer")
        if self.score < MIN_SCORE or self.score > MAX_SCORE:
            raise SchemaValidationError(
                f"Sample 'score' {self.score} out of range [{MIN_SCORE}, {MAX_SCORE}]"
            )
        if type(self.label) is not str or self.label not in _VALID_LABELS:
            raise SchemaValidationError("Sample 'label' must be 'leak' or 'clean'")


@dataclass(frozen=True)
class CalibrationConfig:
    """Integer-only configuration for detector threshold calibration."""

    max_false_alarm: int = DEFAULT_MAX_FALSE_ALARM
    min_recall: int = DEFAULT_MIN_RECALL
    min_leak_samples: int = DEFAULT_MIN_LEAK_SAMPLES
    min_clean_samples: int = DEFAULT_MIN_CLEAN_SAMPLES
    stability_numerator: int = DEFAULT_STABILITY_NUMERATOR
    stability_denominator: int = DEFAULT_STABILITY_DENOMINATOR

    def __post_init__(self) -> None:
        for field_name, val in (
            ("max_false_alarm", self.max_false_alarm),
            ("min_recall", self.min_recall),
            ("min_leak_samples", self.min_leak_samples),
            ("min_clean_samples", self.min_clean_samples),
            ("stability_numerator", self.stability_numerator),
            ("stability_denominator", self.stability_denominator),
        ):
            if not _is_strict_int(val):
                raise ConfigError(f"Config '{field_name}' must be an integer")

        if self.max_false_alarm < 0 or self.max_false_alarm > PER_MILLE_SCALE:
            raise ConfigError(
                f"max_false_alarm must be between 0 and {PER_MILLE_SCALE}"
            )
        if self.min_recall < 0 or self.min_recall > PER_MILLE_SCALE:
            raise ConfigError(
                f"min_recall must be between 0 and {PER_MILLE_SCALE}"
            )
        if self.min_leak_samples < 1:
            raise ConfigError("min_leak_samples must be at least 1")
        if self.min_clean_samples < 1:
            raise ConfigError("min_clean_samples must be at least 1")
        if self.stability_denominator < 1:
            raise ConfigError("stability_denominator must be at least 1")
        if self.stability_numerator < self.stability_denominator:
            raise ConfigError(
                "stability_numerator must be >= stability_denominator"
            )


def _validate_identifier(value: Any, field_name: str) -> str:
    """Validate non-empty bounded identifier strings."""
    if type(value) is not str:
        raise SchemaValidationError(f"Field '{field_name}' must be a string")
    if len(value) == 0 or len(value) > MAX_IDENTIFIER_LENGTH:
        raise SchemaValidationError(
            f"Field '{field_name}' length must be in 1..{MAX_IDENTIFIER_LENGTH}"
        )
    if "\x00" in value or value.strip() == "":
        raise SchemaValidationError(
            f"Field '{field_name}' must not be blank or contain null bytes"
        )
    return value


def read_regular_file(path: str | os.PathLike[str]) -> bytes:
    """Read a regular file without following symlinks, enforcing MAX_INPUT_BYTES."""
    try:
        raw_path = os.fspath(path)
    except (TypeError, ValueError) as exc:
        raise InputFileError("Invalid file path") from exc

    if isinstance(raw_path, bytes):
        if not raw_path or b"\x00" in raw_path:
            raise InputFileError("Invalid file path")
    elif isinstance(raw_path, str):
        if not raw_path or "\x00" in raw_path:
            raise InputFileError("Invalid file path")
    else:
        raise InputFileError("Invalid file path type")

    try:
        lstat_res = os.lstat(raw_path)
    except OSError as exc:
        raise InputFileError(f"Cannot stat input file: {exc}") from exc

    if stat.S_ISLNK(lstat_res.st_mode):
        raise InputFileError("Refusing to follow symlink")
    if not stat.S_ISREG(lstat_res.st_mode):
        raise InputFileError("Refusing non-regular file")
    if lstat_res.st_size > MAX_INPUT_BYTES:
        raise InputFileError(
            f"Input file size {lstat_res.st_size} exceeds {MAX_INPUT_BYTES} bytes"
        )

    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(raw_path, open_flags)
    except OSError as exc:
        raise InputFileError(f"Cannot open input file: {exc}") from exc

    try:
        try:
            fstat_res = os.fstat(fd)
        except OSError as exc:
            raise InputFileError(f"Cannot fstat opened file: {exc}") from exc

        if not stat.S_ISREG(fstat_res.st_mode):
            raise InputFileError("Opened file descriptor is not a regular file")
        if fstat_res.st_size > MAX_INPUT_BYTES:
            raise InputFileError(
                f"Input file size {fstat_res.st_size} exceeds {MAX_INPUT_BYTES} bytes"
            )

        chunks: list[bytes] = []
        total_bytes = 0
        reached_eof = False

        for _ in range(MAX_READ_CHUNKS):
            try:
                chunk = os.read(fd, READ_CHUNK_BYTES)
            except OSError as exc:
                raise InputFileError(f"Error reading input file: {exc}") from exc

            if not chunk:
                reached_eof = True
                break

            total_bytes += len(chunk)
            if total_bytes > MAX_INPUT_BYTES:
                raise InputFileError(
                    f"Input file exceeds {MAX_INPUT_BYTES} bytes limit"
                )
            chunks.append(chunk)

        if not reached_eof:
            raise InputFileError("Input file exceeded maximum read chunk count")

        return b"".join(chunks)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _reject_duplicate_keys_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object_pairs_hook that rejects duplicate keys and caps key count."""
    if len(pairs) > MAX_JSON_OBJECT_KEYS:
        raise SchemaValidationError(
            f"JSON object has too many keys (max {MAX_JSON_OBJECT_KEYS})"
        )
    obj: dict[str, Any] = {}
    for idx, (key, value) in enumerate(pairs):
        if idx >= MAX_JSON_OBJECT_KEYS:
            raise SchemaValidationError(
                f"JSON object exceeded {MAX_JSON_OBJECT_KEYS} keys"
            )
        if key in obj:
            raise SchemaValidationError(f"Duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def _reject_json_float(token: str) -> Any:
    """Reject any floating-point literal in JSON input."""
    raise SchemaValidationError(f"Floating-point numbers are forbidden: {token!r}")


def _reject_json_constant(token: str) -> Any:
    """Reject non-standard JSON constants such as NaN and Infinity."""
    raise SchemaValidationError(f"Invalid JSON constant: {token!r}")


def parse_samples_bytes(raw_bytes: bytes) -> list[Sample]:
    """Decode UTF-8 bytes and parse strictly validated Sample records."""
    if type(raw_bytes) is not bytes:
        raise SchemaValidationError("Expected raw bytes input")
    if len(raw_bytes) > MAX_INPUT_BYTES:
        raise InputFileError(
            f"Input payload size {len(raw_bytes)} exceeds {MAX_INPUT_BYTES} bytes"
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SchemaValidationError(f"Invalid UTF-8 in input: {exc}") from exc
    return parse_samples_json(text)


def parse_samples_json(text: str) -> list[Sample]:
    """Parse JSON text into strictly validated Sample objects."""
    if type(text) is not str:
        raise SchemaValidationError("Expected JSON text string")
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise InputFileError(
            f"Input JSON exceeds {MAX_INPUT_BYTES} bytes limit"
        )
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys_hook,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except SchemaValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, TypeError) as exc:
        raise SchemaValidationError(f"Malformed JSON input: {exc}") from exc

    return _validate_payload(payload)


def _validate_payload(payload: Any) -> list[Sample]:
    """Validate root schema, item schemas, caps, and (detector, task) uniqueness."""
    if type(payload) is not dict:
        raise SchemaValidationError("Root JSON value must be an object")
    if set(payload.keys()) != _EXPECTED_ROOT_KEYS:
        raise SchemaValidationError(
            "Root JSON object must contain exact key 'samples'"
        )

    raw_samples = payload["samples"]
    if type(raw_samples) is not list:
        raise SchemaValidationError("'samples' must be a list")
    if len(raw_samples) > MAX_SAMPLES:
        raise SchemaValidationError(
            f"Sample count {len(raw_samples)} exceeds cap of {MAX_SAMPLES}"
        )

    samples: list[Sample] = []
    seen_pairs: set[tuple[str, str]] = set()

    for idx, entry in enumerate(raw_samples):
        if idx >= MAX_SAMPLES:
            raise SchemaValidationError(f"Sample count exceeded cap of {MAX_SAMPLES}")
        if type(entry) is not dict:
            raise SchemaValidationError(f"Sample at index {idx} must be an object")
        if set(entry.keys()) != _EXPECTED_SAMPLE_KEYS:
            raise SchemaValidationError(
                f"Sample at index {idx} must contain exact keys "
                "('detector', 'task', 'score', 'label')"
            )

        sample = Sample(
            detector=entry["detector"],
            task=entry["task"],
            score=entry["score"],
            label=entry["label"],
        )

        pair = (sample.detector, sample.task)
        if pair in seen_pairs:
            raise SchemaValidationError(
                f"Duplicate (detector, task) pair: ({sample.detector!r}, {sample.task!r})"
            )
        seen_pairs.add(pair)
        samples.append(sample)

    return samples


def _per_mille_floor(numerator: int, denominator: int) -> int:
    """Compute floor(numerator * 1000 / denominator) in pure integer arithmetic."""
    if denominator <= 0:
        return 0
    return (numerator * PER_MILLE_SCALE) // denominator


def _calibrate_single_detector(
    samples: list[Sample],
    config: CalibrationConfig,
) -> dict[str, Any]:
    """Compute full curve, chosen threshold, and LOO stability for one detector."""
    if len(samples) > MAX_TASKS_PER_DETECTOR:
        raise SchemaValidationError(
            f"Detector sample count {len(samples)} exceeds cap {MAX_TASKS_PER_DETECTOR}"
        )

    sorted_samples = sorted(samples, key=lambda s: (s.score, s.task))

    total_leaks = 0
    total_clean = 0
    distinct_scores: list[int] = []
    leak_counts_at_score: list[int] = []
    clean_counts_at_score: list[int] = []

    for idx, sample in enumerate(sorted_samples):
        if idx >= MAX_TASKS_PER_DETECTOR:
            raise SchemaValidationError(
                f"Detector sample count exceeded cap {MAX_TASKS_PER_DETECTOR}"
            )
        is_leak = sample.label == "leak"
        if is_leak:
            total_leaks += 1
        else:
            total_clean += 1

        if not distinct_scores or distinct_scores[-1] != sample.score:
            distinct_scores.append(sample.score)
            leak_counts_at_score.append(1 if is_leak else 0)
            clean_counts_at_score.append(0 if is_leak else 1)
        else:
            if is_leak:
                leak_counts_at_score[-1] += 1
            else:
                clean_counts_at_score[-1] += 1

    curve: list[dict[str, int]] = []
    tp_arr: list[int] = []
    fp_arr: list[int] = []
    freq_arr: list[int] = []
    score_to_idx: dict[int, int] = {}

    tp = total_leaks
    fp = total_clean
    fn = 0
    tn = 0

    for idx, threshold in enumerate(distinct_scores):
        if idx >= MAX_TASKS_PER_DETECTOR:
            raise SchemaValidationError(
                f"Distinct threshold count exceeded cap {MAX_TASKS_PER_DETECTOR}"
            )
        recall = _per_mille_floor(tp, total_leaks)
        false_alarm_rate = _per_mille_floor(fp, total_clean)

        curve.append(
            {
                "threshold": threshold,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "recall": recall,
                "false_alarm_rate": false_alarm_rate,
            }
        )
        tp_arr.append(tp)
        fp_arr.append(fp)
        leaks_here = leak_counts_at_score[idx]
        clean_here = clean_counts_at_score[idx]
        freq_arr.append(leaks_here + clean_here)
        score_to_idx[threshold] = idx

        tp -= leaks_here
        fn += leaks_here
        fp -= clean_here
        tn += clean_here

    sample_counts = {
        "total": total_leaks + total_clean,
        "leak": total_leaks,
        "clean": total_clean,
    }

    # Requirement 4: minimum sample count check.
    insufficient_leaks = total_leaks < config.min_leak_samples
    insufficient_clean = total_clean < config.min_clean_samples
    if insufficient_leaks or insufficient_clean:
        if insufficient_leaks and insufficient_clean:
            reason = "insufficient_leak_and_clean_samples"
        elif insufficient_leaks:
            reason = "insufficient_leak_samples"
        else:
            reason = "insufficient_clean_samples"
        return {
            "status": "insufficient_data",
            "threshold": None,
            "metrics": None,
            "best_available": None,
            "reason": reason,
            "sample_counts": sample_counts,
            "curve": curve,
            "stability": None,
            "flags": ["insufficient_data"],
        }

    # Requirement 3: threshold selection.
    # Because curve is sorted ascending by threshold, both recall and
    # false_alarm_rate are monotonically non-increasing. Thus the first
    # point meeting false_alarm_rate <= max_false_alarm also maximizes
    # recall among all points meeting max_false_alarm, and breaks ties
    # by lowest threshold.
    first_fa_ok: dict[str, int] | None = None
    for idx, point in enumerate(curve):
        if idx >= MAX_TASKS_PER_DETECTOR:
            raise SchemaValidationError(
                f"Curve length exceeded cap {MAX_TASKS_PER_DETECTOR}"
            )
        if point["false_alarm_rate"] <= config.max_false_alarm:
            first_fa_ok = point
            break

    if first_fa_ok is None:
        return {
            "status": "no_threshold",
            "threshold": None,
            "metrics": None,
            "best_available": None,
            "reason": "no_candidate_meets_max_false_alarm",
            "sample_counts": sample_counts,
            "curve": curve,
            "stability": None,
            "flags": ["no_threshold"],
        }

    if first_fa_ok["recall"] < config.min_recall:
        return {
            "status": "no_threshold",
            "threshold": None,
            "metrics": None,
            "best_available": dict(first_fa_ok),
            "reason": "recall_below_min_recall",
            "sample_counts": sample_counts,
            "curve": curve,
            "stability": None,
            "flags": ["no_threshold"],
        }

    chosen_metrics = dict(first_fa_ok)
    chosen_threshold = chosen_metrics["threshold"]

    # Requirement 5: leave-one-task-out stability check.
    stability = _compute_loo_stability(
        sorted_samples=sorted_samples,
        distinct_scores=distinct_scores,
        tp_arr=tp_arr,
        fp_arr=fp_arr,
        freq_arr=freq_arr,
        score_to_idx=score_to_idx,
        total_leaks=total_leaks,
        total_clean=total_clean,
        config=config,
    )

    flags: list[str] = []
    if stability["unstable"]:
        flags.append("unstable")

    return {
        "status": "calibrated",
        "threshold": chosen_threshold,
        "metrics": chosen_metrics,
        "best_available": None,
        "reason": None,
        "sample_counts": sample_counts,
        "curve": curve,
        "stability": stability,
        "flags": flags,
    }


def _compute_loo_stability(
    *,
    sorted_samples: list[Sample],
    distinct_scores: list[int],
    tp_arr: list[int],
    fp_arr: list[int],
    freq_arr: list[int],
    score_to_idx: dict[int, int],
    total_leaks: int,
    total_clean: int,
    config: CalibrationConfig,
) -> dict[str, Any]:
    """Recompute threshold with each task removed and evaluate integer stability ratio."""
    num_distinct = len(distinct_scores)
    folds_evaluated = 0
    failed_folds = 0
    loo_thresholds: list[int] = []

    for fold_idx, removed in enumerate(sorted_samples):
        if fold_idx >= MAX_TASKS_PER_DETECTOR:
            raise SchemaValidationError(
                f"LOO fold count exceeded cap {MAX_TASKS_PER_DETECTOR}"
            )
        folds_evaluated += 1
        removed_is_leak = removed.label == "leak"
        rem_leaks = total_leaks - (1 if removed_is_leak else 0)
        rem_clean = total_clean - (0 if removed_is_leak else 1)

        if rem_leaks <= 0 or rem_clean <= 0:
            failed_folds += 1
            continue

        v_idx = score_to_idx[removed.score]
        clean_delta = 0 if removed_is_leak else 1
        leak_delta = 1 if removed_is_leak else 0

        # Check whether even the highest threshold meets max_false_alarm.
        last_idx = num_distinct - 1
        last_fp = fp_arr[last_idx] - (clean_delta if last_idx <= v_idx else 0)
        if _per_mille_floor(last_fp, rem_clean) > config.max_false_alarm:
            failed_folds += 1
            continue

        lo = 0
        hi = last_idx
        converged = False
        for _ in range(MAX_BINARY_SEARCH_STEPS):
            if lo >= hi:
                converged = True
                break
            mid = lo + ((hi - lo) // 2)
            mid_fp = fp_arr[mid] - (clean_delta if mid <= v_idx else 0)
            if _per_mille_floor(mid_fp, rem_clean) <= config.max_false_alarm:
                hi = mid
            else:
                lo = mid + 1
        else:
            if lo >= hi:
                converged = True

        if not converged:
            raise CalibrationError("Binary search exceeded maximum step cap")

        star = lo
        # If the removed sample was the sole sample with score == distinct_scores[v_idx],
        # that score is no longer a candidate threshold in the remaining dataset.
        if star == v_idx and freq_arr[v_idx] == 1:
            star += 1

        if star >= num_distinct:
            failed_folds += 1
            continue

        star_tp = tp_arr[star] - (leak_delta if star <= v_idx else 0)
        star_recall = _per_mille_floor(star_tp, rem_leaks)
        if star_recall >= config.min_recall:
            loo_thresholds.append(distinct_scores[star])
        else:
            failed_folds += 1

    if loo_thresholds:
        min_t = min(loo_thresholds)
        max_t = max(loo_thresholds)
        ratio_exceeded = (
            max_t * config.stability_denominator
            > min_t * config.stability_numerator
        )
        unstable = ratio_exceeded or (failed_folds > 0)
    else:
        min_t = None
        max_t = None
        unstable = failed_folds > 0

    return {
        "min_threshold": min_t,
        "max_threshold": max_t,
        "unstable": unstable,
        "folds_evaluated": folds_evaluated,
        "failed_folds": failed_folds,
    }


def calibrate_samples(
    samples: Sequence[Sample],
    config: CalibrationConfig | None = None,
) -> dict[str, Any]:
    """Calibrate thresholds deterministically across all detectors in samples."""
    cfg = CalibrationConfig() if config is None else config
    if not isinstance(cfg, CalibrationConfig):
        raise ConfigError("config must be a CalibrationConfig instance")

    if len(samples) > MAX_SAMPLES:
        raise SchemaValidationError(
            f"Sample count {len(samples)} exceeds cap of {MAX_SAMPLES}"
        )

    grouped: dict[str, list[Sample]] = {}
    seen_pairs: set[tuple[str, str]] = set()

    for idx, sample in enumerate(samples):
        if idx >= MAX_SAMPLES:
            raise SchemaValidationError(f"Sample count exceeded cap of {MAX_SAMPLES}")
        if not isinstance(sample, Sample):
            raise SchemaValidationError(f"Item at index {idx} is not a Sample")

        pair = (sample.detector, sample.task)
        if pair in seen_pairs:
            raise SchemaValidationError(
                f"Duplicate (detector, task) pair: ({sample.detector!r}, {sample.task!r})"
            )
        seen_pairs.add(pair)

        if sample.detector not in grouped:
            if len(grouped) >= MAX_DETECTORS:
                raise SchemaValidationError(
                    f"Detector count exceeds cap of {MAX_DETECTORS}"
                )
            grouped[sample.detector] = []
        grouped[sample.detector].append(sample)

    detectors_output: dict[str, Any] = {}
    sorted_detector_names = sorted(grouped.keys())
    for det_idx, detector_name in enumerate(sorted_detector_names):
        if det_idx >= MAX_DETECTORS:
            raise SchemaValidationError(
                f"Detector count exceeded cap of {MAX_DETECTORS}"
            )
        detectors_output[detector_name] = _calibrate_single_detector(
            grouped[detector_name],
            cfg,
        )

    return {
        "config": {
            "max_false_alarm": cfg.max_false_alarm,
            "min_recall": cfg.min_recall,
            "min_leak_samples": cfg.min_leak_samples,
            "min_clean_samples": cfg.min_clean_samples,
            "stability_numerator": cfg.stability_numerator,
            "stability_denominator": cfg.stability_denominator,
        },
        "detectors": detectors_output,
    }


def calibrate_file(
    path: str | os.PathLike[str],
    config: CalibrationConfig | None = None,
) -> dict[str, Any]:
    """Read, validate, and calibrate samples from a regular JSON file."""
    cfg = CalibrationConfig() if config is None else config
    if not isinstance(cfg, CalibrationConfig):
        raise ConfigError("config must be a CalibrationConfig instance")
    raw_bytes = read_regular_file(path)
    samples = parse_samples_bytes(raw_bytes)
    return calibrate_samples(samples, cfg)


def format_result_json(result: dict[str, Any]) -> str:
    """Serialize calibration output deterministically to formatted JSON."""
    return json.dumps(result, indent=2, allow_nan=False)


