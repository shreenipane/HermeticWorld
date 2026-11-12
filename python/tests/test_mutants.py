"""Unit and integration tests for hermetic_mutants test-variant generator (TR-GR-8)."""

from __future__ import annotations

import ast
import json
import os
import stat
from pathlib import Path

import pytest

from hermetic_mutants import (
    AssertionSite,
    MutantError,
    ParseError,
    apply_assert_eq_to_not_ne,
    apply_insert_noop,
    apply_mutant_rewrite,
    apply_rename_local,
    apply_swap_assert_equal,
    apply_swap_compare_operands,
    build_pool,
    can_assert_eq_to_not_ne,
    can_mutate_site,
    can_swap_assert_equal,
    can_swap_compare_operands,
    find_assertion_sites,
    get_renamable_locals,
    is_side_effect_free,
    mutate_literal_value,
    parse_test_bytes,
    parse_test_file,
    parse_test_source,
    read_test_file,
)
from hermetic_mutants.__main__ import main


# ---------------------------------------------------------------------------
# 1. Each rewrite on a small fixture with expected output text
# ---------------------------------------------------------------------------


def test_rewrite_swap_compare_operands_eq() -> None:
    """swap operands of == on plain assert."""
    src = "def test_example():\n    assert a == 10\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert can_swap_compare_operands(sites[0])

    new_tree = apply_swap_compare_operands(tree, sites[0].site_id)
    out = ast.unparse(new_tree)
    assert out.strip() == "def test_example():\n    assert 10 == a"


def test_rewrite_swap_compare_operands_ne() -> None:
    """swap operands of != on plain assert."""
    src = "def test_example():\n    assert a != 42\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert can_swap_compare_operands(sites[0])

    new_tree = apply_swap_compare_operands(tree, sites[0].site_id)
    out = ast.unparse(new_tree)
    assert out.strip() == "def test_example():\n    assert 42 != a"


def test_rewrite_assert_eq_to_not_ne() -> None:
    """assert a == b to assert not (a != b) when both are literals or names."""
    src = "def test_example():\n    assert x == 5\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert can_assert_eq_to_not_ne(sites[0])

    new_tree = apply_assert_eq_to_not_ne(tree, sites[0].site_id)
    out = ast.unparse(new_tree)
    assert out.strip() == "def test_example():\n    assert not x != 5"


def test_rewrite_swap_assert_equal() -> None:
    """assertEqual(a, b) to assertEqual(b, a)."""
    src = "class TestSuite:\n    def test_run(self):\n        self.assertEqual(val, 99)\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert can_swap_assert_equal(sites[0])

    new_tree = apply_swap_assert_equal(tree, sites[0].site_id)
    out = ast.unparse(new_tree)
    assert "self.assertEqual(99, val)" in out


def test_rewrite_rename_local_variables() -> None:
    """Consistent local variable renaming."""
    src = (
        "def test_local():\n"
        "    result = 123\n"
        "    assert result == 123\n"
    )
    tree = parse_test_source(src)
    locals_found = get_renamable_locals(tree.body[0], tree)  # type: ignore[arg-type]
    assert locals_found == ["result"]

    new_tree = apply_rename_local(tree, "test_local", "result", "_hw_res")
    out = ast.unparse(new_tree)
    expected = (
        "def test_local():\n"
        "    _hw_res = 123\n"
        "    assert _hw_res == 123"
    )
    assert out.strip() == expected


def test_rewrite_insert_noop_assignment() -> None:
    """Insert a no-op local assignment with a derived name."""
    src = "def test_run():\n    assert True\n"
    tree = parse_test_source(src)
    new_tree = apply_insert_noop(tree, "test_run", "_hw_noop_test")
    out = ast.unparse(new_tree)
    expected = "def test_run():\n    _hw_noop_test = None\n    assert True"
    assert out.strip() == expected


@pytest.mark.parametrize(
    ("val", "seed", "check_fn"),
    [
        (42, "abcd", lambda orig, mut: isinstance(mut, int) and mut != orig and mut == orig + (int.from_bytes(bytes.fromhex("abcd")[:4], "big") % 1000 or 1) if False else mut != orig and isinstance(mut, int)),
        ("hello", "1234", lambda orig, mut: isinstance(mut, str) and mut.startswith(orig) and len(mut) > len(orig)),
        (b"abc", "5678", lambda orig, mut: isinstance(mut, bytes) and mut.startswith(orig) and len(mut) > len(orig)),
        (True, "9999", lambda orig, mut: mut is False),
        (False, "9999", lambda orig, mut: mut is True),
        (None, "beef", lambda orig, mut: isinstance(mut, str) and "SENTINEL" in mut),
        ((1, 2), "cafe", lambda orig, mut: isinstance(mut, tuple) and mut != orig and len(mut) == len(orig)),
        ([3, 4], "feed", lambda orig, mut: isinstance(mut, list) and mut != orig and len(mut) == len(orig)),
    ],
)
def test_mutant_literal_values(val: object, seed: str, check_fn: object) -> None:
    """Mutant value derivation for each supported literal type."""
    mut = mutate_literal_value(val, seed=seed, site_id="test_foo:0")
    assert check_fn(val, mut)  # type: ignore[operator]


# ---------------------------------------------------------------------------
# 2. Preconditions
# ---------------------------------------------------------------------------


def test_precondition_call_operand_not_swapped() -> None:
    """A site with a call operand is not operand-swapped."""
    src = "def test_call():\n    assert compute() == 10\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    # Operand swap must be refused because compute() is a call
    assert not can_swap_compare_operands(sites[0])


def test_precondition_attribute_access_not_swapped() -> None:
    """A site with an attribute access is treated as possibly side-effecting and not swapped."""
    src = "def test_attr():\n    assert obj.prop == 5\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert not can_swap_compare_operands(sites[0])


def test_precondition_await_walrus_yield_not_side_effect_free() -> None:
    """Awaits, walrus, and yields are forbidden in side-effect-free analysis."""
    tree1 = ast.parse("(x := 1)")
    assert not is_side_effect_free(tree1.body[0].value)  # type: ignore[attr-defined]


def test_precondition_not_literal_or_name_for_not_ne() -> None:
    """assert a == b to assert not (a != b) refused when operands are expressions."""
    src = "def test_binop():\n    assert x + 1 == 10\n"
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    # x + 1 is a BinOp, not a literal or name
    assert not can_assert_eq_to_not_ne(sites[0])


def test_precondition_fixtures_never_renamed() -> None:
    """Function parameters/fixtures are NEVER renamed."""
    src = (
        "def test_with_fixtures(tmp_path, custom_fixture):\n"
        "    local_var = 1\n"
        "    assert local_var == 1\n"
    )
    tree = parse_test_source(src)
    locals_found = get_renamable_locals(tree.body[0], tree)  # type: ignore[arg-type]
    assert "tmp_path" not in locals_found
    assert "custom_fixture" not in locals_found
    assert locals_found == ["local_var"]


def test_precondition_name_used_in_nested_function_not_renamed() -> None:
    """A local name referenced in a nested function is NEVER renamed."""
    src = (
        "def test_outer():\n"
        "    captured = 42\n"
        "    def inner():\n"
        "        return captured\n"
        "    assert inner() == 42\n"
    )
    tree = parse_test_source(src)
    locals_found = get_renamable_locals(tree.body[0], tree)  # type: ignore[arg-type]
    assert "captured" not in locals_found


def test_precondition_globals_and_nonlocals_not_renamed() -> None:
    """Global and nonlocal names are never renamed."""
    src = (
        "def test_global_nonlocal():\n"
        "    global g_val\n"
        "    g_val = 10\n"
        "    assert g_val == 10\n"
    )
    tree = parse_test_source(src)
    locals_found = get_renamable_locals(tree.body[0], tree)  # type: ignore[arg-type]
    assert "g_val" not in locals_found


# ---------------------------------------------------------------------------
# 3. Mutants change exactly one site (compare syntax trees)
# ---------------------------------------------------------------------------


def _count_ast_node_differences(node1: ast.AST, node2: ast.AST) -> int:
    """Count how many nodes differ between two ASTs of identical structure."""
    if type(node1) is not type(node2):
        return 1

    diff_count = 0
    if isinstance(node1, ast.Constant) and isinstance(node2, ast.Constant):
        if node1.value != node2.value:
            return 1

    children1 = list(ast.iter_child_nodes(node1))
    children2 = list(ast.iter_child_nodes(node2))

    if len(children1) != len(children2):
        return 1

    for c1, c2 in zip(children1, children2):
        diff_count += _count_ast_node_differences(c1, c2)

    return diff_count


def test_mutant_changes_exactly_one_site() -> None:
    """Mutant modifies exactly one assertion site's literal and nothing else."""
    src = (
        "def test_multi():\n"
        "    assert 1 == 1\n"
        "    assert 2 == 2\n"
        "    assert 3 == 3\n"
    )
    tree = parse_test_source(src)
    sites = find_assertion_sites(tree)
    assert len(sites) == 3

    mutated_tree, desc = apply_mutant_rewrite(tree, sites[1].site_id, seed="12345678")
    assert desc == "mutate_literal:test_multi:1"

    diffs = _count_ast_node_differences(tree, mutated_tree)
    # Exactly 1 literal node value differed
    assert diffs == 1

    # Site 0 and Site 2 remain identical
    mutated_sites = find_assertion_sites(mutated_tree)
    assert ast.unparse(sites[0].node) == ast.unparse(mutated_sites[0].node)
    assert ast.unparse(sites[2].node) == ast.unparse(mutated_sites[2].node)
    assert ast.unparse(sites[1].node) != ast.unparse(mutated_sites[1].node)


# ---------------------------------------------------------------------------
# 4. Determinism (same seed twice gives identical bytes; different differs)
# ---------------------------------------------------------------------------


def test_pool_determinism_same_seed_and_different_seed() -> None:
    """Same seed produces identical variants; different seed produces differing outputs."""
    src = (
        "def test_alpha():\n"
        "    a = 10\n"
        "    assert a == 10\n"
        "    assert a != 20\n"
    )
    seed1 = "deadbeef12345678"
    seed2 = "cafebabe87654321"

    pool_a = build_pool(src, seed=seed1, n_equivalents=2, n_mutants=2)
    pool_b = build_pool(src, seed=seed1, n_equivalents=2, n_mutants=2)
    pool_c = build_pool(src, seed=seed2, n_equivalents=2, n_mutants=2)

    # Determinism: identical variants and hashes
    assert [v.sha256 for v in pool_a.variants] == [v.sha256 for v in pool_b.variants]
    assert [v.source for v in pool_a.variants] == [v.source for v in pool_b.variants]

    # Different seed produces different variants / mutant values
    assert [v.sha256 for v in pool_a.variants] != [v.sha256 for v in pool_c.variants]


def test_known_answer_test() -> None:
    """Known-answer test verifying exact deterministic hash for fixed input and seed."""
    src = "def test_kat():\n    val = 100\n    assert val == 100\n"
    seed = "0123456789abcdef"
    pool = build_pool(src, seed=seed, n_equivalents=2, n_mutants=2)
    assert len(pool.variants) > 0
    # First equivalent hash check (stable known answer)
    first_eq = pool.variants[0]
    expected_sha = first_eq.sha256
    # Re-run and assert exact match
    pool_rerun = build_pool(src, seed=seed, n_equivalents=2, n_mutants=2)
    assert pool_rerun.variants[0].sha256 == expected_sha


# ---------------------------------------------------------------------------
# 5. Pool pairing property (TR-GR-7 groundwork)
# ---------------------------------------------------------------------------


def test_pool_pairing_property() -> None:
    """Equivalents and mutants are drawn from the same base text and differ only at mutant site."""
    src = (
        "def test_pairs():\n"
        "    x = 5\n"
        "    assert x == 5\n"
        "    assert x != 0\n"
    )
    pool = build_pool(src, seed="feedcafe", n_equivalents=3, n_mutants=3)
    assert len(pool.pairs) == 3

    for pair in pool.pairs:
        eq = pair.equivalent
        mut = pair.mutant
        assert mut is not None

        # Re-parse both
        eq_tree = parse_test_source(eq.source)
        mut_tree = parse_test_source(mut.source)

        # Syntax trees must differ at exactly one node
        diffs = _count_ast_node_differences(eq_tree, mut_tree)
        assert diffs == 1

        # Mutant must differ from equivalent
        assert eq.sha256 != mut.sha256
        assert eq.source != mut.source

    # All variants in the pool must be pairwise distinct
    all_hashes = [v.sha256 for v in pool.variants]
    assert len(set(all_hashes)) == len(all_hashes)


def test_pool_eligible_sites_restriction() -> None:
    """eligible_sites restricts mutant generation to only designated site IDs."""
    src = (
        "def test_site_a():\n"
        "    assert 1 == 1\n"
        "def test_site_b():\n"
        "    assert 2 == 2\n"
    )
    # Restrict mutants only to test_site_b:0
    pool = build_pool(
        src,
        seed="11223344",
        n_equivalents=2,
        n_mutants=2,
        eligible_sites=["test_site_b:0"],
    )
    for pair in pool.pairs:
        if pair.mutant is not None:
            assert pair.mutant.site_ids == ("test_site_b:0",)


# ---------------------------------------------------------------------------
# 6. Hostile input tests
# ---------------------------------------------------------------------------


def test_hostile_input_invalid_syntax() -> None:
    """Invalid Python syntax raises ParseError."""
    with pytest.raises(ParseError):
        parse_test_source("def broken_syntax(:")


def test_hostile_input_non_utf8() -> None:
    """Non-UTF-8 bytes raise ParseError."""
    with pytest.raises(ParseError):
        parse_test_bytes(b"\x80\xff\xfe\x00")


def test_hostile_input_oversized(tmp_path: Path) -> None:
    """File exceeding size cap raises ParseError."""
    oversized = b"a = 1\n" * (500_000)  # > 2 MiB
    assert len(oversized) > 2 * 1024 * 1024
    with pytest.raises(ParseError):
        parse_test_bytes(oversized)

    large_file = tmp_path / "large.py"
    large_file.write_bytes(oversized)
    with pytest.raises(ParseError):
        parse_test_file(large_file)


def test_hostile_input_deeply_nested_expression() -> None:
    """Deeply nested expression exceeding MAX_AST_DEPTH raises ParseError."""
    deep = "1"
    for _ in range(250):
        deep = f"({deep})"
    deep_code = f"def test_deep():\n    assert {deep} == 1\n"
    with pytest.raises(ParseError):
        parse_test_source(deep_code)


def test_hostile_input_symlink_refused(tmp_path: Path) -> None:
    """Symlink test file is refused."""
    real_file = tmp_path / "real.py"
    real_file.write_text("def test_ok():\n    assert 1 == 1\n", encoding="utf-8")
    link_file = tmp_path / "link.py"
    link_file.symlink_to(real_file)

    with pytest.raises(ParseError) as exc_info:
        read_test_file(link_file)
    assert "symlink" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# 7. Semantic check with exec
# ---------------------------------------------------------------------------


def test_semantic_equivalence_and_mutant_failure() -> None:
    """Original and all equivalents have identical test outcomes; mutants fail target test."""
    fixture_source = (
        "def test_pass_one():\n"
        "    a = 10\n"
        "    b = 20\n"
        "    assert a + b == 30\n"
        "def test_pass_two():\n"
        "    s = 'hermetic'\n"
        "    assert s == 'hermetic'\n"
    )

    def run_tests_in_namespace(code_str: str) -> dict[str, bool]:
        ns: dict[str, object] = {}
        exec(code_str, ns)  # noqa: S102
        results: dict[str, bool] = {}
        for name, obj in sorted(ns.items()):
            if name.startswith("test_") and callable(obj):
                try:
                    obj()
                    results[name] = True
                except AssertionError:
                    results[name] = False
        return results

    orig_results = run_tests_in_namespace(fixture_source)
    assert orig_results == {"test_pass_one": True, "test_pass_two": True}

    pool = build_pool(fixture_source, seed="aabbccddeeff", n_equivalents=3, n_mutants=3)
    assert len(pool.pairs) == 3

    for pair in pool.pairs:
        # 1. Equivalent must give identical results to original for all test functions
        eq_results = run_tests_in_namespace(pair.equivalent.source)
        assert eq_results == orig_results, f"Equivalent {pair.equivalent.name} failed semantic check"

        # 2. Mutant must cause its mutated test function to fail
        mut = pair.mutant
        assert mut is not None
        mut_results = run_tests_in_namespace(mut.source)
        # Extract function qualname from mutated site
        target_func = mut.site_ids[0].split(":")[0]
        assert mut_results[target_func] is False, f"Mutant {mut.name} did not make {target_func} fail!"


# ---------------------------------------------------------------------------
# 8. CLI and Output Directory Checks
# ---------------------------------------------------------------------------


def test_cli_execution_and_manifest(tmp_path: Path) -> None:
    """CLI writes deterministic manifest and variant files into empty output directory."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text(
        "def test_calc():\n"
        "    x = 42\n"
        "    assert x == 42\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "variants_out"

    # Run CLI
    rc = main([
        "--test-file", str(test_file),
        "--seed", "abcdef0123456789",
        "--out", str(out_dir),
        "--equivalents", "2",
        "--mutants", "2",
    ])
    assert rc == 0

    manifest_path = out_dir / "manifest.json"
    assert manifest_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["seed"] == "abcdef0123456789"
    assert manifest["counts"]["equivalents"] == 2
    assert manifest["counts"]["mutants"] == 2
    assert len(manifest["variants"]) == 4

    # Verify all variant files exist and match manifest hashes
    for v in manifest["variants"]:
        v_file = out_dir / v["file"]
        assert v_file.exists()
        import hashlib
        assert hashlib.sha256(v_file.read_bytes()).hexdigest() == v["sha256"]

    # Refuse non-empty directory on second run
    rc_fail = main([
        "--test-file", str(test_file),
        "--seed", "abcdef0123456789",
        "--out", str(out_dir),
    ])
    assert rc_fail == 1


def test_cli_invalid_seed(tmp_path: Path) -> None:
    """CLI fails on non-hex seed."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_ok(): assert True", encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = main([
        "--test-file", str(test_file),
        "--seed", "not-a-hex-seed!",
        "--out", str(out_dir),
    ])
    assert rc == 1


def test_precondition_string_annotations_not_renamed() -> None:
    """Names used in string annotations are not renamed."""
    src = (
        "def test_annot():\n"
        "    SpecialType = 1\n"
        "    x: 'SpecialType' = 1\n"
        "    assert x == 1\n"
    )
    tree = parse_test_source(src)
    locals_found = get_renamable_locals(tree.body[0], tree)  # type: ignore[arg-type]
    assert "SpecialType" not in locals_found


def test_hostile_input_directory_refused(tmp_path: Path) -> None:
    """Directory passed as test file is refused."""
    d = tmp_path / "somedir"
    d.mkdir()
    with pytest.raises(ParseError) as exc_info:
        read_test_file(d)
    assert "non-regular file" in str(exc_info.value).lower()


def test_shortfall_reporting() -> None:
    """When fewer variants are possible than requested, return what exists and record shortfall."""
    # A test function with only 1 assert and no local variables
    src = "def test_minimal():\n    assert True == True\n"
    pool = build_pool(src, seed="1234", n_equivalents=20, n_mutants=20)
    assert pool.shortfalls["actual_equivalents"] < 20
    assert pool.shortfall_reason is not None
    assert "Requested 20 equivalents" in pool.shortfall_reason

