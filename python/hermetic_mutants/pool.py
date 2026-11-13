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
    MutantError,
    can_insert_noop,
    collect_identifiers,
    module_level_names,
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

# Upper bound on requested equivalents and on requested mutants per pool
MAX_VARIANTS_PER_KIND: int = 64
# Upper bound on atomic rewrite operations considered per pool (seed-selected)
MAX_REWRITE_OPS: int = 64
# Upper bound on candidate rewrite combinations generated per pool
MAX_CANDIDATE_COMBOS: int = 4096
# Upper bound on candidate combinations actually applied per pool
MAX_COMBO_ATTEMPTS: int = 512
# Upper bound on re-derivations tried when a mutant text collides with another variant
MAX_MUTANT_SALTS: int = 10


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


def _op_key(seed: str, op: tuple[Any, ...]) -> str:
    return hashlib.sha256(f"{seed}:op:{op!r}".encode("utf-8")).hexdigest()


def _generate_candidate_combos(
    ops: list[tuple[Any, ...]], seed: str, max_needed: int
) -> list[list[tuple[Any, ...]]]:
    """Generate deterministic combinations of rewrite operations ordered by seed hash.

    At most MAX_REWRITE_OPS operations (chosen by seed hash) and at most
    MAX_CANDIDATE_COMBOS combinations are built. Larger combinations are built
    only while smaller ones cannot fill three times the request.
    """
    if len(ops) > MAX_REWRITE_OPS:
        ops = sorted(ops, key=lambda op: _op_key(seed, op))[:MAX_REWRITE_OPS]
        ops.sort()
    combos: list[list[tuple[Any, ...]]] = []

    # 1-op combinations
    for op in ops:
        combos.append([op])

    # 2-op combinations (pairs of distinct operations)
    if len(ops) >= 2 and len(combos) < max_needed * 3:
        for i in range(len(ops)):
            for j in range(i + 1, len(ops)):
                if len(combos) >= MAX_CANDIDATE_COMBOS:
                    break
                combos.append([ops[i], ops[j]])

    # 3-op combinations
    if len(ops) >= 3 and len(combos) < max_needed * 3:
        for i in range(len(ops)):
            for j in range(i + 1, len(ops)):
                for k in range(j + 1, len(ops)):
                    if len(combos) >= MAX_CANDIDATE_COMBOS:
                        break
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

    Each mutant is built from one equivalent's text and paired with it; when
    more mutants than equivalents are requested, equivalents are reused in
    order. Requests above MAX_VARIANTS_PER_KIND or below 0 raise MutantError.

    Returns:
        Pool containing variants, pairings, and shortfall metadata.
    """
    if isinstance(n_equivalents, bool) or not isinstance(n_equivalents, int):
        raise MutantError("n_equivalents must be an integer")
    if isinstance(n_mutants, bool) or not isinstance(n_mutants, int):
        raise MutantError("n_mutants must be an integer")
    if not 0 <= n_equivalents <= MAX_VARIANTS_PER_KIND:
        raise MutantError(f"n_equivalents must be between 0 and {MAX_VARIANTS_PER_KIND}")
    if not 0 <= n_mutants <= MAX_VARIANTS_PER_KIND:
        raise MutantError(f"n_mutants must be between 0 and {MAX_VARIANTS_PER_KIND}")
    if not isinstance(seed, str) or not seed:
        raise MutantError("seed must be a non-empty string")
    if isinstance(eligible_sites, (str, bytes)):
        raise MutantError("eligible_sites must be a collection of site ids, not a string")

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

    module_names = module_level_names(base_tree)
    base_identifiers = frozenset(collect_identifiers(base_tree))
    for f in test_funcs:
        renamable = get_renamable_locals(f.func_node, base_tree, module_names)
        for var in renamable:
            raw_ops.append(("rename_local", f.qualname, var))
        if can_insert_noop(f.func_node):
            raw_ops.append(("insert_noop", f.qualname))

    # Deterministic sorting of candidate atomic operations
    raw_ops.sort(key=lambda op: (op[0], op[1], op[2] if len(op) > 2 else ""))

    candidate_combos = _generate_candidate_combos(raw_ops, seed, n_equivalents)

    seen_variant_hashes: set[str] = {orig_sha256}
    equivalents: list[Variant] = []

    for combo in candidate_combos[:MAX_COMBO_ATTEMPTS]:
        if len(equivalents) >= n_equivalents:
            break

        applied_sites: list[str] = []
        applied_rewrites: list[str] = []
        taken_names: set[str] = set(base_identifiers)

        try:
            # A fresh tree per combination; every rewrite below edits it in place
            cur_tree: ast.AST = ast.parse(orig_text)
            for op in combo:
                op_kind = op[0]
                if op_kind == "swap_compare":
                    cur_tree = apply_swap_compare_operands(cur_tree, op[1], in_place=True)
                    applied_sites.append(op[1])
                    applied_rewrites.append("swap_compare")
                elif op_kind == "assert_eq_to_not_ne":
                    cur_tree = apply_assert_eq_to_not_ne(cur_tree, op[1], in_place=True)
                    applied_sites.append(op[1])
                    applied_rewrites.append("assert_eq_to_not_ne")
                elif op_kind == "swap_assert_equal":
                    cur_tree = apply_swap_assert_equal(cur_tree, op[1], in_place=True)
                    applied_sites.append(op[1])
                    applied_rewrites.append("swap_assert_equal")
                elif op_kind == "rename_local":
                    qualname, var = op[1], op[2]
                    h_val = hashlib.sha256(
                        f"{seed}:{qualname}:{var}".encode("utf-8")
                    ).hexdigest()[:6]
                    new_var = f"_hw_{var}_{h_val}"
                    cur_tree = apply_rename_local(
                        cur_tree, qualname, var, new_var, in_place=True, taken_names=taken_names
                    )
                    taken_names.add(new_var)
                    applied_rewrites.append(f"rename_local:{var}")
                elif op_kind == "insert_noop":
                    qualname = op[1]
                    h_val = hashlib.sha256(
                        f"{seed}:{qualname}:noop:{len(applied_rewrites)}".encode("utf-8")
                    ).hexdigest()[:6]
                    noop_name = f"_hw_noop_{h_val}"
                    cur_tree = apply_insert_noop(
                        cur_tree, qualname, noop_name, in_place=True, taken_names=taken_names
                    )
                    taken_names.add(noop_name)
                    applied_rewrites.append("insert_noop")
                else:
                    raise MutantError(f"Unknown rewrite {op_kind}")
            ast.fix_missing_locations(cur_tree)
            candidate_text = ast.unparse(cur_tree)
            # Verify clean re-parsing
            ast.parse(candidate_text)
        except (MutantError, SyntaxError, ValueError, RecursionError, MemoryError):
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

    # Build mutants from the same rewritten base text as their paired equivalent.
    # Mutant i is paired with equivalent i modulo the number of equivalents.
    pairs: list[VariantPair] = []
    mutants: list[Variant] = []
    paired_eq_names: set[str] = set()
    eq_sites_cache: dict[int, list[AssertionSite]] = {}
    mutant_request = n_mutants if equivalents else 0

    for i in range(mutant_request):
        eq_index = i % len(equivalents)
        eq_variant = equivalents[eq_index]
        if eq_index not in eq_sites_cache:
            try:
                eq_tree = ast.parse(eq_variant.source)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                eq_sites_cache[eq_index] = []
                continue
            eligible = [s for s in find_assertion_sites(eq_tree) if can_mutate_site(s)]
            if allowed_mutant_sites is not None:
                eligible = [s for s in eligible if s.site_id in allowed_mutant_sites]
            eligible.sort(key=lambda s: s.site_id)
            eq_sites_cache[eq_index] = eligible
        eligible_for_mutant = eq_sites_cache[eq_index]
        if not eligible_for_mutant:
            continue

        # Deterministically choose a starting site; try the others in order if
        # a site yields no mutant distinct from every other variant
        start = (
            int.from_bytes(
                hashlib.sha256(f"{seed}:mutant_choice:{i}".encode("utf-8")).digest()[:4],
                "big",
            )
            % len(eligible_for_mutant)
        )
        mutant_variant: Variant | None = None
        for offset in range(len(eligible_for_mutant)):
            target_site = eligible_for_mutant[(start + offset) % len(eligible_for_mutant)]
            for salt in range(MAX_MUTANT_SALTS + 1):
                salted_seed = seed if salt == 0 else f"{seed}_salt_{salt}"
                try:
                    # A fresh tree from the equivalent's text, mutated in place
                    mutant_tree, rewrite_desc = apply_mutant_rewrite(
                        ast.parse(eq_variant.source),
                        target_site.site_id,
                        seed=salted_seed,
                        in_place=True,
                    )
                    ast.fix_missing_locations(mutant_tree)
                    mutant_text = ast.unparse(mutant_tree)
                    ast.parse(mutant_text)
                except (MutantError, SyntaxError, ValueError, RecursionError, MemoryError):
                    break
                mutant_sha = _compute_sha256(mutant_text)
                if mutant_sha not in seen_variant_hashes:
                    mutant_variant = Variant(
                        name=f"variant_mut_{len(mutants)}.py",
                        kind="mutant",
                        source=mutant_text,
                        sha256=mutant_sha,
                        site_ids=(target_site.site_id,),
                        rewrites=(rewrite_desc,),
                    )
                    break
            if mutant_variant is not None:
                break
        if mutant_variant is None:
            continue

        seen_variant_hashes.add(mutant_variant.sha256)
        mutants.append(mutant_variant)
        paired_eq_names.add(eq_variant.name)
        pairs.append(VariantPair(equivalent=eq_variant, mutant=mutant_variant))

    # Equivalents that received no mutant
    for eq_variant in equivalents:
        if eq_variant.name not in paired_eq_names:
            pairs.append(VariantPair(equivalent=eq_variant, mutant=None))

    all_variants = tuple(equivalents + mutants)

    shortfalls = {
        "requested_equivalents": n_equivalents,
        "actual_equivalents": len(equivalents),
        "requested_mutants": n_mutants,
        "actual_mutants": len(mutants),
    }

    shortfall_reason: str | None = None
    if len(equivalents) < n_equivalents or len(mutants) < n_mutants:
        shortfall_reason = (
            f"Requested {n_equivalents} equivalents and {n_mutants} mutants; "
            f"generated {len(equivalents)} equivalents and {len(mutants)} mutants."
        )
        if n_mutants and not equivalents:
            shortfall_reason += " Mutants need a paired equivalent and none was generated."

    return Pool(
        variants=all_variants,
        pairs=tuple(pairs),
        shortfalls=shortfalls,
        shortfall_reason=shortfall_reason,
    )
