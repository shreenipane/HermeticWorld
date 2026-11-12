"""Variant pool builder for Hermetic World differential grading (TR-GR-8, TR-GR-7).

Builds deterministic equivalent and mutant test variants from syntax-tree rewriting:
- Equivalents preserve semantics while altering syntax (TR-GR-8).
- Mutants alter exactly one assertion site's expected value to a third, failing value.
- Mutants and equivalents are paired: each mutant is derived from its paired equivalent
  so they differ ONLY at the mutated site (TR-GR-7 groundwork).
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

from hermetic_mutants.rewrite import (
    AssertionSite,
    apply_assert_eq_to_not_ne,
    apply_insert_noop,
    apply_mutant_rewrite,
    apply_rename_local,
    apply_swap_assert_equal,
    apply_swap_compare_operands,
    can_assert_eq_to_not_ne,
    can_mutate_site,
    can_swap_assert_equal,
    can_swap_compare_operands,
    find_assertion_sites,
    find_test_functions,
    get_renamable_locals,
    parse_test_bytes,
    parse_test_source,
)


@dataclass(frozen=True)
class Variant:
    """A generated test file variant."""

    name: str
    kind: str  # "equivalent" or "mutant"
    source: str
    sha256: str
    site_ids: tuple[str, ...]
    rewrites: tuple[str, ...]


@dataclass(frozen=True)
class VariantPair:
    """A paired equivalent and mutant variant sharing the same rewritten base."""

    equivalent: Variant
    mutant: Variant | None


@dataclass(frozen=True)
class Pool:
    """A collection of generated test variants and their pairings."""

    variants: tuple[Variant, ...]
    pairs: tuple[VariantPair, ...]
    shortfalls: dict[str, int]
    shortfall_reason: str | None = None


def _compute_sha256(text: str) -> str:
    """Compute deterministic SHA-256 hex digest of string text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _generate_candidate_combos(
    ops: list[tuple[Any, ...]], seed: str, max_needed: int
) -> list[list[tuple[Any, ...]]]:
    """Generate deterministic combinations of rewrite operations ordered by seed hash."""
    combos: list[list[tuple[Any, ...]]] = []

    # 1-op combinations
    for op in ops:
        combos.append([op])

    # 2-op combinations (pairs of distinct operations)
    if len(ops) >= 2:
        for i in range(len(ops)):
            for j in range(i + 1, len(ops)):
                combos.append([ops[i], ops[j]])

    # 3-op combinations
    if len(ops) >= 3 and len(combos) < max_needed * 3:
        for i in range(len(ops)):
            for j in range(i + 1, len(ops)):
                for k in range(j + 1, len(ops)):
                    combos.append([ops[i], ops[j], ops[k]])

    # Deterministic sorting keyed by (size, sha256(seed:size:repr(combo)))
    def sort_key(combo: list[tuple[Any, ...]]) -> tuple[int, str]:
        size = len(combo)
        rep = repr(combo)
        h = hashlib.sha256(f"{seed}:{size}:{rep}".encode("utf-8")).hexdigest()
        return size, h

    combos.sort(key=sort_key)
    return combos


def build_pool(
    source: str | bytes,
    seed: str,
    n_equivalents: int = 4,
    n_mutants: int = 4,
    eligible_sites: Sequence[str] | set[str] | None = None,
) -> Pool:
    """Build a deterministic variant pool of equivalents and paired mutants.

    Args:
        source: Python source code as string or UTF-8 bytes.
        seed: Deterministic seed string (typically hex).
        n_equivalents: Target count of equivalent variants.
        n_mutants: Target count of mutant variants.
        eligible_sites: Optional subset of site IDs eligible for mutation.

    Returns:
        Pool containing variants, pairings, and shortfall metadata.
    """
    if isinstance(source, bytes):
        base_tree = parse_test_bytes(source)
    else:
        base_tree = parse_test_source(source)

    orig_text = ast.unparse(base_tree)
    orig_sha256 = _compute_sha256(orig_text)

    # Convert eligible_sites to a frozen set if provided
    allowed_mutant_sites: frozenset[str] | None = None
    if eligible_sites is not None:
        allowed_mutant_sites = frozenset(eligible_sites)

    # Discover atomic rewrite opportunities
    sites = find_assertion_sites(base_tree)
    test_funcs = find_test_functions(base_tree)

    raw_ops: list[tuple[Any, ...]] = []

    for s in sites:
        if can_swap_compare_operands(s):
            raw_ops.append(("swap_compare", s.site_id))
        if can_assert_eq_to_not_ne(s):
            raw_ops.append(("assert_eq_to_not_ne", s.site_id))
        if can_swap_assert_equal(s):
            raw_ops.append(("swap_assert_equal", s.site_id))

    for f in test_funcs:
        renamable = get_renamable_locals(f.func_node, base_tree)
        for var in renamable:
            raw_ops.append(("rename_local", f.qualname, var))
        raw_ops.append(("insert_noop", f.qualname))

    # Deterministic sorting of candidate atomic operations
    raw_ops.sort(key=lambda op: (op[0], op[1], op[2] if len(op) > 2 else ""))

    candidate_combos = _generate_candidate_combos(raw_ops, seed, n_equivalents)

    seen_variant_hashes: set[str] = {orig_sha256}
    equivalents: list[Variant] = []

    for combo in candidate_combos:
        if len(equivalents) >= n_equivalents:
            break

        cur_tree = parse_test_source(orig_text)
        applied_sites: list[str] = []
        applied_rewrites: list[str] = []
        valid = True

        for op in combo:
            op_kind = op[0]
            try:
                if op_kind == "swap_compare":
                    site_id = op[1]
                    cur_tree = apply_swap_compare_operands(cur_tree, site_id)
                    applied_sites.append(site_id)
                    applied_rewrites.append("swap_compare")
                elif op_kind == "assert_eq_to_not_ne":
                    site_id = op[1]
                    cur_tree = apply_assert_eq_to_not_ne(cur_tree, site_id)
                    applied_sites.append(site_id)
                    applied_rewrites.append("assert_eq_to_not_ne")
                elif op_kind == "swap_assert_equal":
                    site_id = op[1]
                    cur_tree = apply_swap_assert_equal(cur_tree, site_id)
                    applied_sites.append(site_id)
                    applied_rewrites.append("swap_assert_equal")
                elif op_kind == "rename_local":
                    qualname, var = op[1], op[2]
                    h_val = hashlib.sha256(
                        f"{seed}:{qualname}:{var}".encode("utf-8")
                    ).hexdigest()[:6]
                    new_var = f"_hw_{var}_{h_val}"
                    cur_tree = apply_rename_local(cur_tree, qualname, var, new_var)
                    applied_rewrites.append(f"rename_local:{var}")
                elif op_kind == "insert_noop":
                    qualname = op[1]
                    h_val = hashlib.sha256(
                        f"{seed}:{qualname}:noop:{len(applied_rewrites)}".encode("utf-8")
                    ).hexdigest()[:6]
                    noop_name = f"_hw_noop_{h_val}"
                    cur_tree = apply_insert_noop(cur_tree, qualname, noop_name)
                    applied_rewrites.append("insert_noop")
            except Exception:
                valid = False
                break

        if not valid:
            continue

        try:
            ast.fix_missing_locations(cur_tree)
            candidate_text = ast.unparse(cur_tree)
            # Verify clean re-parsing
            ast.parse(candidate_text)
        except Exception:
            continue

        candidate_sha = _compute_sha256(candidate_text)
        if candidate_sha in seen_variant_hashes:
            continue

        seen_variant_hashes.add(candidate_sha)
        eq_name = f"variant_eq_{len(equivalents)}.py"
        equivalents.append(
            Variant(
                name=eq_name,
                kind="equivalent",
                source=candidate_text,
                sha256=candidate_sha,
                site_ids=tuple(sorted(set(applied_sites))),
                rewrites=tuple(applied_rewrites),
            )
        )

    # Build paired mutants from the same rewritten base text as each equivalent
    pairs: list[VariantPair] = []
    target_pair_count = min(n_mutants, len(equivalents))

    for i in range(target_pair_count):
        eq_variant = equivalents[i]
        eq_tree = parse_test_source(eq_variant.source)
        eq_sites = find_assertion_sites(eq_tree)

        # Filter candidate assertion sites for mutation
        eligible_for_mutant = [s for s in eq_sites if can_mutate_site(s)]
        if allowed_mutant_sites is not None:
            eligible_for_mutant = [
                s for s in eligible_for_mutant if s.site_id in allowed_mutant_sites
            ]

        eligible_for_mutant.sort(key=lambda s: s.site_id)

        if not eligible_for_mutant:
            pairs.append(VariantPair(equivalent=eq_variant, mutant=None))
            continue

        # Deterministically choose which site to mutate
        site_choice = (
            int.from_bytes(
                hashlib.sha256(f"{seed}:mutant_choice:{i}".encode("utf-8")).digest()[:4],
                "big",
            )
            % len(eligible_for_mutant)
        )
        target_site = eligible_for_mutant[site_choice]

        mutant_tree, rewrite_desc = apply_mutant_rewrite(
            eq_tree, target_site.site_id, seed=seed
        )
        mutant_text = ast.unparse(mutant_tree)
        # Verify clean re-parsing
        ast.parse(mutant_text)
        mutant_sha = _compute_sha256(mutant_text)

        # Ensure mutant is distinct from equivalent and not previously seen
        salt = 0
        while mutant_sha in seen_variant_hashes and salt < 10:
            salt += 1
            salted_seed = f"{seed}_salt_{salt}"
            mutant_tree, rewrite_desc = apply_mutant_rewrite(
                eq_tree, target_site.site_id, seed=salted_seed
            )
            mutant_text = ast.unparse(mutant_tree)
            ast.parse(mutant_text)
            mutant_sha = _compute_sha256(mutant_text)

        seen_variant_hashes.add(mutant_sha)
        mut_name = f"variant_mut_{i}.py"
        mutant_variant = Variant(
            name=mut_name,
            kind="mutant",
            source=mutant_text,
            sha256=mutant_sha,
            site_ids=(target_site.site_id,),
            rewrites=(rewrite_desc,),
        )
        pairs.append(VariantPair(equivalent=eq_variant, mutant=mutant_variant))

    # Any remaining equivalents without mutant requests
    for i in range(target_pair_count, len(equivalents)):
        pairs.append(VariantPair(equivalent=equivalents[i], mutant=None))

    mutants = [p.mutant for p in pairs if p.mutant is not None]
    all_variants = tuple(equivalents + mutants)

    shortfalls = {
        "requested_equivalents": n_equivalents,
        "actual_equivalents": len(equivalents),
        "requested_mutants": n_mutants,
        "actual_mutants": len(mutants),
    }

    shortfall_reason: str | None = None
    if (
        len(equivalents) < n_equivalents
        or len(mutants) < n_mutants
    ):
        shortfall_reason = (
            f"Requested {n_equivalents} equivalents and {n_mutants} mutants; "
            f"generated {len(equivalents)} equivalents and {len(mutants)} mutants."
        )

    return Pool(
        variants=all_variants,
        pairs=tuple(pairs),
        shortfalls=shortfalls,
        shortfall_reason=shortfall_reason,
    )
