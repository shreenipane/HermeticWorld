
"""Deterministic integer per-mille metrics, task bootstrap CI, and exit checks."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Sequence

from hermetic_e3 import (
    DEFAULT_BOOTSTRAP_ITERATIONS,
    MAX_BOOTSTRAP_ITERATIONS,
    MAX_ENTRIES,
    PERMILLE_SCALE,
    RangeError,
    SizeLimitError,
)
from hermetic_e3.match import (
    ACTIVE_SEVERITIES,
    Finding,
    Leak,
    MatchResult,
    match_findings,
)

REPORTED_KINDS: tuple[str, ...] = ("real", "seeded")


@dataclass(frozen=True, slots=True)
class ScopeMetrics:
    """Integer counts and integer per-mille metrics for an evaluation scope."""

    tp: int
    fn: int
    fp: int
    precision_permille: int
    recall_permille: int
    missed_leak_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a pure-integer/string JSON-compatible dictionary."""
        return {
            "tp": int(self.tp),
            "fn": int(self.fn),
            "fp": int(self.fp),
            "precision_permille": int(self.precision_permille),
            "recall_permille": int(self.recall_permille),
            "missed_leak_ids": list(self.missed_leak_ids),
        }


@dataclass(frozen=True, slots=True)
class PercentileRange:
    """2.5th and 97.5th percentile bounds in integer per-mille (0..1000)."""

    low_permille: int
    high_permille: int

    def to_dict(self) -> dict[str, int]:
        """Serialize to a pure-integer dictionary."""
        return {
            "low_permille": int(self.low_permille),
            "high_permille": int(self.high_permille),
        }


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    """Task-resampled percentile bootstrap confidence intervals in per-mille."""

    seed: int
    bootstrap_iterations: int
    task_count: int
    recall: PercentileRange
    precision: PercentileRange

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a pure-integer dictionary."""
        return {
            "seed": int(self.seed),
            "bootstrap_iterations": int(self.bootstrap_iterations),
            "task_count": int(self.task_count),
            "recall": self.recall.to_dict(),
            "precision": self.precision.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ExitCriterionResult:
    """Result of checking 'real'-kind recall and precision against per-mille thresholds."""

    passed: bool
    kind: str
    actual_recall_permille: int
    actual_precision_permille: int
    min_recall_permille: int | None
    min_precision_permille: int | None
    recall_passed: bool
    precision_passed: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a pure-integer/bool/string dictionary."""
        return {
            "passed": bool(self.passed),
            "kind": str(self.kind),
            "actual_recall_permille": int(self.actual_recall_permille),
            "actual_precision_permille": int(self.actual_precision_permille),
            "min_recall_permille": (
                None if self.min_recall_permille is None else int(self.min_recall_permille)
            ),
            "min_precision_permille": (
                None
                if self.min_precision_permille is None
                else int(self.min_precision_permille)
            ),
            "recall_passed": bool(self.recall_passed),
            "precision_passed": bool(self.precision_passed),
        }


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Complete deterministic Experiment E3 evaluation report."""

    overall: ScopeMetrics
    per_detector: dict[str, ScopeMetrics]
    per_kind: dict[str, ScopeMetrics]
    confidence_interval: ConfidenceInterval
    exit_criterion: ExitCriterionResult

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete report with zero floats."""
        return {
            "overall": self.overall.to_dict(),
            "per_detector": {
                det: self.per_detector[det].to_dict()
                for det in sorted(self.per_detector.keys())
            },
            "per_kind": {
                kind: self.per_kind[kind].to_dict()
                for kind in sorted(self.per_kind.keys())
            },
            "confidence_interval": self.confidence_interval.to_dict(),
            "exit_criterion": self.exit_criterion.to_dict(),
        }


def to_permille_floor(numerator: int, denominator: int) -> int:
    """Compute floor(1000 * numerator / denominator) in exact integer arithmetic.

    Returns 0 when denominator <= 0.
    """
    if denominator <= 0 or numerator <= 0:
        return 0
    return (numerator * PERMILLE_SCALE) // denominator


def _deduplicated_fp_count(unmatched_findings: Sequence[Finding]) -> int:
    """Count unmatched active findings deduplicated by (task, path, line_start, line_end, detector)."""
    if len(unmatched_findings) > MAX_ENTRIES:
        raise SizeLimitError(
            f"Unmatched findings count ({len(unmatched_findings)}) exceeds cap {MAX_ENTRIES}"
        )
    dedup_keys: set[tuple[str, str, int, int, str]] = set()
    for fn in unmatched_findings[:MAX_ENTRIES]:
        if fn.severity not in ACTIVE_SEVERITIES:
            continue
        dedup_keys.add((fn.task, fn.path, fn.line_start, fn.line_end, fn.detector))
    return len(dedup_keys)


def _build_scope_metrics(
    scope_leaks: Sequence[Leak],
    matched_leak_ids: frozenset[str],
    fp_count: int,
) -> ScopeMetrics:
    """Construct ScopeMetrics from leaks in scope, matched leak IDs, and deduplicated FP count."""
    if len(scope_leaks) > MAX_ENTRIES:
        raise SizeLimitError(
            f"Scope leaks count ({len(scope_leaks)}) exceeds cap {MAX_ENTRIES}"
        )
    tp = 0
    missed: list[str] = []
    for leak in scope_leaks[:MAX_ENTRIES]:
        if leak.id in matched_leak_ids:
            tp += 1
        else:
            missed.append(leak.id)
    fn = len(missed)
    missed.sort()
    precision = to_permille_floor(tp, tp + fp_count)
    recall = to_permille_floor(tp, tp + fn)
    return ScopeMetrics(
        tp=tp,
        fn=fn,
        fp=fp_count,
        precision_permille=precision,
        recall_permille=recall,
        missed_leak_ids=tuple(missed),
    )


def compute_all_metrics(
    leaks: Sequence[Leak],
    findings: Sequence[Finding],
    match_result: MatchResult | None = None,
) -> tuple[ScopeMetrics, dict[str, ScopeMetrics], dict[str, ScopeMetrics]]:
    """Compute overall, per-detector, and per-kind ('real', 'seeded') metrics."""
    if len(leaks) > MAX_ENTRIES:
        raise SizeLimitError(f"Leaks count ({len(leaks)}) exceeds cap {MAX_ENTRIES}")
    if len(findings) > MAX_ENTRIES:
        raise SizeLimitError(f"Findings count ({len(findings)}) exceeds cap {MAX_ENTRIES}")

    resolved = match_result if match_result is not None else match_findings(leaks, findings)
    matched_overall_set = frozenset(resolved.matched_leak_ids)
    overall_fp = _deduplicated_fp_count(resolved.unmatched_active_findings)

    overall_metrics = _build_scope_metrics(leaks, matched_overall_set, overall_fp)

    # Group unmatched active findings by detector for per-detector FP counts.
    unmatched_by_detector: dict[str, list[Finding]] = {}
    all_detectors: set[str] = set()
    for fn in findings[:MAX_ENTRIES]:
        all_detectors.add(fn.detector)
    for fn in resolved.unmatched_active_findings[:MAX_ENTRIES]:
        unmatched_by_detector.setdefault(fn.detector, []).append(fn)

    if len(all_detectors) > MAX_ENTRIES:
        raise SizeLimitError(
            f"Detector count ({len(all_detectors)}) exceeds cap {MAX_ENTRIES}"
        )

    per_detector: dict[str, ScopeMetrics] = {}
    for detector in sorted(all_detectors)[:MAX_ENTRIES]:
        det_matched = frozenset(
            resolved.matched_leak_ids_by_detector.get(detector, ())
        )
        det_fp = _deduplicated_fp_count(unmatched_by_detector.get(detector, ()))
        per_detector[detector] = _build_scope_metrics(leaks, det_matched, det_fp)

    # Per kind ("real" and "seeded"): leaks filtered by kind; FPs are active findings
    # that match no ground-truth leak.
    leaks_by_kind: dict[str, list[Leak]] = {kind: [] for kind in REPORTED_KINDS}
    for leak in leaks[:MAX_ENTRIES]:
        leaks_by_kind[leak.kind].append(leak)

    per_kind: dict[str, ScopeMetrics] = {}
    for kind in REPORTED_KINDS:
        per_kind[kind] = _build_scope_metrics(
            leaks_by_kind[kind], matched_overall_set, overall_fp
        )

    return overall_metrics, per_detector, per_kind


def _validate_seed(seed: int) -> int:
    """Ensure seed is a strict integer (not a boolean)."""
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise RangeError("seed must be an integer")
    return seed


def _validate_bootstrap_iterations(bootstrap_iterations: int) -> int:
    """Validate bootstrap iteration count B within [1, MAX_BOOTSTRAP_ITERATIONS]."""
    if not isinstance(bootstrap_iterations, int) or isinstance(bootstrap_iterations, bool):
        raise RangeError("bootstrap_iterations must be an integer")
    if bootstrap_iterations < 1 or bootstrap_iterations > MAX_BOOTSTRAP_ITERATIONS:
        raise RangeError(
            f"bootstrap_iterations ({bootstrap_iterations}) must be between 1 and {MAX_BOOTSTRAP_ITERATIONS}"
        )
    return bootstrap_iterations


def bootstrap_confidence_interval(
    leaks: Sequence[Leak],
    findings: Sequence[Finding],
    *,
    seed: int,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    match_result: MatchResult | None = None,
) -> ConfidenceInterval:
    """Compute percentile bootstrap 95% CI (2.5th and 97.5th percentiles) over tasks.

    Tasks are resampled with replacement using an isolated ``random.Random(seed)``.
    Each replicate computes integer per-mille recall and precision (rounded down).
    """
    if len(leaks) > MAX_ENTRIES:
        raise SizeLimitError(f"Leaks count ({len(leaks)}) exceeds cap {MAX_ENTRIES}")
    if len(findings) > MAX_ENTRIES:
        raise SizeLimitError(f"Findings count ({len(findings)}) exceeds cap {MAX_ENTRIES}")

    valid_seed = _validate_seed(seed)
    valid_b = _validate_bootstrap_iterations(bootstrap_iterations)
    resolved = match_result if match_result is not None else match_findings(leaks, findings)
    matched_set = frozenset(resolved.matched_leak_ids)

    task_set: set[str] = set()
    tp_by_task: dict[str, int] = {}
    fn_by_task: dict[str, int] = {}
    fp_keys_by_task: dict[str, set[tuple[str, str, int, int, str]]] = {}

    for leak in leaks[:MAX_ENTRIES]:
        task_set.add(leak.task)
        if leak.id in matched_set:
            tp_by_task[leak.task] = tp_by_task.get(leak.task, 0) + 1
        else:
            fn_by_task[leak.task] = fn_by_task.get(leak.task, 0) + 1

    for fn in findings[:MAX_ENTRIES]:
        task_set.add(fn.task)

    for fn in resolved.unmatched_active_findings[:MAX_ENTRIES]:
        if fn.severity not in ACTIVE_SEVERITIES:
            continue
        fp_keys_by_task.setdefault(fn.task, set()).add(
            (fn.task, fn.path, fn.line_start, fn.line_end, fn.detector)
        )

    if len(task_set) > MAX_ENTRIES:
        raise SizeLimitError(f"Task count ({len(task_set)}) exceeds cap {MAX_ENTRIES}")

    tasks = sorted(task_set)
    task_count = len(tasks)
    if task_count == 0:
        zero_range = PercentileRange(low_permille=0, high_permille=0)
        return ConfidenceInterval(
            seed=valid_seed,
            bootstrap_iterations=valid_b,
            task_count=0,
            recall=zero_range,
            precision=zero_range,
        )

    task_triples: tuple[tuple[int, int, int], ...] = tuple(
        (
            tp_by_task.get(t, 0),
            fn_by_task.get(t, 0),
            len(fp_keys_by_task.get(t, ())),
        )
        for t in tasks[:MAX_ENTRIES]
    )

    rng = random.Random(valid_seed)
    recall_samples: list[int] = []
    precision_samples: list[int] = []

    for _ in range(valid_b):
        rep_tp = 0
        rep_fn = 0
        rep_fp = 0
        for _ in range(task_count):
            t_tp, t_fn, t_fp = task_triples[rng.randrange(task_count)]
            rep_tp += t_tp
            rep_fn += t_fn
            rep_fp += t_fp
        recall_samples.append(to_permille_floor(rep_tp, rep_tp + rep_fn))
        precision_samples.append(to_permille_floor(rep_tp, rep_tp + rep_fp))

    recall_samples.sort()
    precision_samples.sort()

    low_idx = (25 * valid_b) // PERMILLE_SCALE
    high_idx = min(valid_b - 1, (975 * valid_b) // PERMILLE_SCALE)

    return ConfidenceInterval(
        seed=valid_seed,
        bootstrap_iterations=valid_b,
        task_count=task_count,
        recall=PercentileRange(
            low_permille=recall_samples[low_idx],
            high_permille=recall_samples[high_idx],
        ),
        precision=PercentileRange(
            low_permille=precision_samples[low_idx],
            high_permille=precision_samples[high_idx],
        ),
    )


def _validate_threshold(value: int | None, name: str) -> int | None:
    """Validate an optional per-mille threshold in [0, 1000]."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise RangeError(f"{name} must be an integer")
    if value < 0 or value > PERMILLE_SCALE:
        raise RangeError(
            f"{name} ({value}) must be between 0 and {PERMILLE_SCALE}"
        )
    return value


def evaluate_exit_criterion(
    real_metrics: ScopeMetrics,
    *,
    min_recall_permille: int | None = None,
    min_precision_permille: int | None = None,
) -> ExitCriterionResult:
    """Evaluate pass/fail against per-mille recall and precision thresholds for 'real' leaks."""
    valid_min_rec = _validate_threshold(min_recall_permille, "min_recall_permille")
    valid_min_prec = _validate_threshold(min_precision_permille, "min_precision_permille")

    recall_passed = (
        True
        if valid_min_rec is None
        else real_metrics.recall_permille >= valid_min_rec
    )
    precision_passed = (
        True
        if valid_min_prec is None
        else real_metrics.precision_permille >= valid_min_prec
    )
    return ExitCriterionResult(
        passed=(recall_passed and precision_passed),
        kind="real",
        actual_recall_permille=real_metrics.recall_permille,
        actual_precision_permille=real_metrics.precision_permille,
        min_recall_permille=valid_min_rec,
        min_precision_permille=valid_min_prec,
        recall_passed=recall_passed,
        precision_passed=precision_passed,
    )


def evaluate(
    leaks: Sequence[Leak],
    findings: Sequence[Finding],
    *,
    seed: int,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    min_recall_permille: int | None = None,
    min_precision_permille: int | None = None,
) -> EvaluationReport:
    """Run the full Experiment E3 evaluation pipeline and return a deterministic report."""
    match_result = match_findings(leaks, findings)
    overall, per_detector, per_kind = compute_all_metrics(
        leaks, findings, match_result=match_result
    )
    ci = bootstrap_confidence_interval(
        leaks,
        findings,
        seed=seed,
        bootstrap_iterations=bootstrap_iterations,
        match_result=match_result,
    )
    exit_check = evaluate_exit_criterion(
        per_kind["real"],
        min_recall_permille=min_recall_permille,
        min_precision_permille=min_precision_permille,
    )
    return EvaluationReport(
        overall=overall,
        per_detector=per_detector,
        per_kind=per_kind,
        confidence_interval=ci,
        exit_criterion=exit_check,
    )


