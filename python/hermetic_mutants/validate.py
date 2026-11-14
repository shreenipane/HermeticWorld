"""Variant validation and R1/R2 test-set selection (TR-GR-5, TR-GR-7, TR-GR-8).

Host-side and VM-agnostic: every test execution goes through an injected
``runner(tree, text)`` where ``tree`` is ``"base"`` or ``"gold"`` and ``text`` is
the hidden test file to run. It returns a mapping ``node id -> outcome`` with
outcomes ``passed``, ``failed``, ``skipped``, ``error`` or ``missing``. In
production the runner boots a GraderVM per call; tests use fakes.

Procedure (all choices derive from SHA-256 of the seed, never from time or
hash randomisation):

1. **Baseline.** The original file runs ``baseline_repeats`` times on each
   tree. A test whose outcome is not identical in every run on a tree, or that
   is missing from any run, is flaky and dropped from every comparison
   (TR-GR-5), as are caller-supplied flaky ids. The comparison set is the
   remaining node ids of the hidden test file. Malformed baseline output, a
   runner exception or an empty comparison set raise ``ValidationError``.
2. **Equivalents.** Each pool equivalent runs ``repeats`` times on each tree.
   It is valid iff in every run its outcome equals the baseline outcome for
   every test of the comparison set.
3. **R2 set.** The valid equivalent ranked first by
   ``sha256(seed ":r2:" variant_sha)`` is the R2 test set.
4. **Mutants.** Every eligible site (from the base-failing finder) is mutated,
   alone, in the R2 text. A single mutant is valid iff in every run on both
   trees every comparison test of the site's function is ``failed`` and every
   other comparison test equals the baseline.
5. **R1 set.** One valid site per test function (ranked by
   ``sha256(seed ":r1:" site_id)``) is mutated in the R2 text, all at once. The
   combined text is validated the same way. If it does not validate, R1 falls
   back to the single best-ranked valid mutant (already validated as is).
6. **Padding.** R1 and R2 texts are padded with a trailing comment to the same
   byte length (TR-GR-7: identical file sizes).
7. **Coverage.** Eligible functions (functions of eligible sites with at least
   one comparison test) versus functions mutated in R1.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from hermetic_mutants.finder import nodeid_qualname, site_function
from hermetic_mutants.pool import build_pool
from hermetic_mutants.rewrite import MutantError, apply_mutant_rewrite

OUTCOMES: frozenset[str] = frozenset({"passed", "failed", "skipped", "error", "missing"})
TREES: tuple[str, str] = ("base", "gold")
MAX_RESULT_TESTS: int = 100_000
MAX_NODEID_BYTES: int = 1_024
MAX_REPEATS: int = 5
MAX_SITE_CANDIDATES: int = 64
MAX_EQUIVALENTS: int = 16
PAD_LINE_PREFIX: str = "\n# hermetic-pad "

Runner = Callable[[str, str], Mapping[str, str]]


class ValidationError(MutantError):
    """Raised when validation cannot proceed (bad baseline, bad arguments)."""


class _BadRun(Exception):
    """A single run gave unusable output; the candidate is rejected."""


@dataclass(frozen=True)
class Selection:
    """Result of validation: the R1/R2 texts, the plan sets and coverage."""

    r2_text: str | None
    r1_text: str | None
    r2_sha256: str | None
    r1_sha256: str | None
    mutated_sites: tuple[str, ...]
    mutated_tests: tuple[str, ...]
    compared_tests: tuple[str, ...]
    flaky_tests: tuple[str, ...]
    eligible_functions: tuple[str, ...]
    covered_functions: tuple[str, ...]
    valid_equivalents: int
    rejected: tuple[tuple[str, str], ...]

    def coverage_json(self) -> dict[str, Any]:
        return {
            "covered_functions": len(self.covered_functions),
            "eligible_functions": len(self.eligible_functions),
        }

    def manifest_json(self) -> str:
        return json.dumps(
            {
                "compared_tests": list(self.compared_tests),
                "coverage": self.coverage_json(),
                "covered_functions": list(self.covered_functions),
                "eligible_functions": list(self.eligible_functions),
                "flaky_tests": list(self.flaky_tests),
                "mutated_sites": list(self.mutated_sites),
                "mutated_tests": list(self.mutated_tests),
                "r1_sha256": self.r1_sha256,
                "r2_sha256": self.r2_sha256,
                "rejected": [[k, r] for k, r in self.rejected],
                "valid_equivalents": self.valid_equivalents,
            },
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rank(seed: str, tag: str, key: str) -> str:
    return hashlib.sha256(f"{seed}:{tag}:{key}".encode("utf-8")).hexdigest()


def check_outcomes(raw: Any) -> dict[str, str]:
    """Validate one runner result strictly; raise _BadRun on anything unexpected."""
    if not isinstance(raw, Mapping) or len(raw) > MAX_RESULT_TESTS:
        raise _BadRun("malformed result")
    out: dict[str, str] = {}
    for key, value in raw.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8", "replace")) > MAX_NODEID_BYTES
            or not all(0x20 <= ord(c) <= 0x7E for c in key)
        ):
            raise _BadRun("malformed node id")
        if not isinstance(value, str) or value not in OUTCOMES:
            raise _BadRun("malformed outcome")
        out[key] = value
    return out


def _run(runner: Runner, tree: str, text: str) -> dict[str, str]:
    try:
        raw = runner(tree, text)
    except Exception as exc:  # the runner is a VM boundary; any failure rejects
        raise _BadRun("runner error") from exc
    return check_outcomes(raw)


def pad_equal(a: str, b: str) -> tuple[str, str]:
    """Pad two test texts with a trailing comment line to one common byte length."""
    la, lb = len(a.encode("utf-8")), len(b.encode("utf-8"))
    target = max(la, lb) + len(PAD_LINE_PREFIX) + 1

    def pad(text: str, length: int) -> str:
        fill = target - length - len(PAD_LINE_PREFIX) - 1
        return text + PAD_LINE_PREFIX + ("x" * fill) + "\n"

    return pad(a, la), pad(b, lb)


def _matches(
    results: Mapping[str, str],
    baseline: Mapping[str, str],
    compared: Iterable[str],
    must_fail: frozenset[str],
) -> bool:
    for nodeid in compared:
        got = results.get(nodeid)
        if nodeid in must_fail:
            if got != "failed":
                return False
        elif got != baseline[nodeid]:
            return False
    return True


def _validate_candidate(
    runner: Runner,
    text: str,
    baselines: Mapping[str, Mapping[str, str]],
    compared: Sequence[str],
    must_fail: frozenset[str],
    repeats: int,
) -> str | None:
    """Return None when valid, else a short reason."""
    for tree in TREES:
        for _ in range(repeats):
            try:
                results = _run(runner, tree, text)
            except _BadRun as exc:
                return f"{tree}: {exc}"
            if not _matches(results, baselines[tree], compared, must_fail):
                return f"{tree}: outcome mismatch"
    return None


def _baseline(
    runner: Runner,
    original: str,
    test_file: str,
    repeats: int,
    extra_flaky: frozenset[str],
) -> tuple[dict[str, dict[str, str]], list[str], list[str]]:
    per_tree: dict[str, dict[str, str]] = {}
    flaky: set[str] = set(extra_flaky)
    seen: set[str] = set()
    for tree in TREES:
        runs: list[dict[str, str]] = []
        for _ in range(repeats):
            try:
                runs.append(_run(runner, tree, original))
            except _BadRun as exc:
                raise ValidationError(f"baseline on {tree}: {exc}") from None
        ids = set().union(*runs)
        seen |= ids
        stable: dict[str, str] = {}
        for nodeid in ids:
            values = {r.get(nodeid) for r in runs}
            if len(values) != 1 or None in values:
                flaky.add(nodeid)
            else:
                stable[nodeid] = runs[0][nodeid]
        per_tree[tree] = stable
    prefix = test_file + "::"
    compared = sorted(
        nodeid
        for nodeid in seen
        if nodeid.startswith(prefix)
        and nodeid not in flaky
        and all(nodeid in per_tree[t] for t in TREES)
        and nodeid_qualname(nodeid, test_file) is not None
    )
    if not compared:
        raise ValidationError("no stable test of the hidden file to compare")
    return per_tree, compared, sorted(f for f in flaky if f.startswith(prefix))


def _function_tests(compared: Sequence[str], test_file: str, qual: str) -> frozenset[str]:
    return frozenset(n for n in compared if nodeid_qualname(n, test_file) == qual)


def _mutate_all(text: str, site_ids: Sequence[str], seed: str) -> str:
    tree = ast.parse(text)
    for site_id in site_ids:
        tree, _ = apply_mutant_rewrite(tree, site_id, seed=seed, in_place=True)
    ast.fix_missing_locations(tree)
    out = ast.unparse(tree)
    ast.parse(out)
    return out


def validate_and_select(
    source: bytes,
    test_file: str,
    seed: str,
    eligible_sites: Sequence[str],
    runner: Runner,
    *,
    n_equivalents: int = 4,
    repeats: int = 2,
    baseline_repeats: int = 3,
    flaky: Iterable[str] = (),
) -> Selection:
    """Validate a variant pool and select the R1 and R2 test texts (module docstring)."""
    if not isinstance(source, bytes):
        raise ValidationError("source must be bytes")
    for name, value, low in (
        ("repeats", repeats, 1),
        ("baseline_repeats", baseline_repeats, 2),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= MAX_REPEATS:
            raise ValidationError(f"{name} must be between {low} and {MAX_REPEATS}")
    if isinstance(n_equivalents, bool) or not isinstance(n_equivalents, int):
        raise ValidationError("n_equivalents must be an integer")
    if not 1 <= n_equivalents <= MAX_EQUIVALENTS:
        raise ValidationError(f"n_equivalents must be between 1 and {MAX_EQUIVALENTS}")
    if isinstance(eligible_sites, (str, bytes)):
        raise ValidationError("eligible_sites must be a sequence of site ids")
    try:
        original = source.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError("source is not UTF-8") from None

    pool = build_pool(source, seed, n_equivalents=n_equivalents, n_mutants=0)
    baselines, compared, flaky_ids = _baseline(
        runner, original, test_file, baseline_repeats, frozenset(flaky)
    )
    rejected: dict[str, str] = {}

    valid_eq = []
    for variant in pool.variants:
        if variant.kind != "equivalent":
            continue
        reason = _validate_candidate(
            runner, variant.source, baselines, compared, frozenset(), repeats
        )
        if reason is None:
            valid_eq.append(variant)
        else:
            rejected[variant.name] = reason

    sites = sorted(set(eligible_sites))[:MAX_SITE_CANDIDATES]
    eligible_functions = sorted(
        {site_function(s) for s in sites if _function_tests(compared, test_file, site_function(s))}
    )

    if not valid_eq:
        return Selection(
            None, None, None, None, (), (), tuple(compared), tuple(flaky_ids),
            tuple(eligible_functions), (), 0,
            tuple(sorted({**rejected, "r2": "no validated equivalent"}.items())),
        )

    r2 = min(valid_eq, key=lambda v: _rank(seed, "r2", v.sha256))
    r2_text = r2.source

    valid_sites: list[str] = []
    for site_id in sites:
        qual = site_function(site_id)
        targets = _function_tests(compared, test_file, qual)
        if not targets:
            rejected[site_id] = "no compared test"
            continue
        try:
            mutant_text = _mutate_all(r2_text, [site_id], seed)
        except (MutantError, SyntaxError, ValueError, RecursionError):
            rejected[site_id] = "not mutable in R2 text"
            continue
        reason = _validate_candidate(runner, mutant_text, baselines, compared, targets, repeats)
        if reason is None:
            valid_sites.append(site_id)
        else:
            rejected[site_id] = reason

    best: dict[str, str] = {}
    for site_id in sorted(valid_sites, key=lambda s: _rank(seed, "r1", s)):
        best.setdefault(site_function(site_id), site_id)
    chosen = sorted(best.values(), key=lambda s: _rank(seed, "r1", s))

    r1_sites: list[str] = []
    r1_text: str | None = None
    if chosen:
        combined = sorted(chosen)
        combined_text = _mutate_all(r2_text, combined, seed)
        must_fail = frozenset().union(
            *(_function_tests(compared, test_file, site_function(s)) for s in combined)
        )
        reason = None
        if len(combined) > 1:
            reason = _validate_candidate(
                runner, combined_text, baselines, compared, must_fail, repeats
            )
        if reason is None:
            r1_sites, r1_text = combined, combined_text
        else:
            rejected["r1_combined"] = reason
            r1_sites = [chosen[0]]
            r1_text = _mutate_all(r2_text, r1_sites, seed)

    covered = sorted({site_function(s) for s in r1_sites})
    mutated_tests = sorted(
        frozenset().union(*(_function_tests(compared, test_file, q) for q in covered))
    )
    if r1_text is None:
        rejected.setdefault("r1", "no validated mutant")
        r2_out, r1_out = r2_text, None
    else:
        r2_out, r1_out = pad_equal(r2_text, r1_text)
    return Selection(
        r2_text=r2_out,
        r1_text=r1_out,
        r2_sha256=sha256_text(r2_out),
        r1_sha256=sha256_text(r1_out) if r1_out is not None else None,
        mutated_sites=tuple(r1_sites),
        mutated_tests=tuple(mutated_tests),
        compared_tests=tuple(compared),
        flaky_tests=tuple(flaky_ids),
        eligible_functions=tuple(eligible_functions),
        covered_functions=tuple(covered),
        valid_equivalents=len(valid_eq),
        rejected=tuple(sorted(rejected.items())),
    )


__all__ = [
    "OUTCOMES",
    "Selection",
    "ValidationError",
    "check_outcomes",
    "pad_equal",
    "sha256_text",
    "validate_and_select",
]
