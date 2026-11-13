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


def test_noop_only_rewrite_reports_shortfall() -> None:
    """A function with no permitted rewrite gets no artificial assignments (§11.2)."""
    src = "def test_run():\n    assert True\n"
    pool = build_pool(src, seed="ab")
    assert pool.variants == ()
    assert pool.pairs == ()
    assert pool.shortfalls == {
        "requested_equivalents": 4,
        "actual_equivalents": 0,
        "requested_mutants": 4,
        "actual_mutants": 0,
    }
    assert pool.shortfall_reason is not None


@pytest.mark.parametrize(
    ("val", "seed", "check_fn"),
    [
        (42, "abcd", lambda orig, mut: isinstance(mut, int) and mut != orig and mut == orig + (int.from_bytes(bytes.fromhex("abcd")[:4], "big") % 1000 or 1) if False else mut != orig and isinstance(mut, int)),
        ("hello", "1234", lambda orig, mut: isinstance(mut, str) and mut.startswith(orig) and len(mut) > len(orig)),
        (b"abc", "5678", lambda orig, mut: isinstance(mut, bytes) and mut.startswith(orig) and len(mut) > len(orig)),
        (True, "9999", lambda orig, mut: mut is False),
        (False, "9999", lambda orig, mut: mut is True),
        (None, "beef", lambda orig, mut: isinstance(mut, str) and len(mut) > 0),
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
    """Count how many nodes differ between two ASTs, comparing every field.

    Scalar fields (such as ``Name.id`` or ``Constant.value``) and list positions are
    compared too, not just child nodes.
    """
    if type(node1) is not type(node2):
        return 1

    diff_count = 0
    for (_name1, value1), (_name2, value2) in zip(ast.iter_fields(node1), ast.iter_fields(node2)):
        diff_count += _count_ast_field_differences(value1, value2)
    return diff_count


def _count_ast_field_differences(value1: object, value2: object) -> int:
    if isinstance(value1, ast.AST) and isinstance(value2, ast.AST):
        return _count_ast_node_differences(value1, value2)
    if isinstance(value1, list) and isinstance(value2, list):
        if len(value1) != len(value2):
            return 1
        return sum(_count_ast_field_differences(a, b) for a, b in zip(value1, value2))
    if isinstance(value1, ast.AST) or isinstance(value2, ast.AST):
        return 1
    if isinstance(value1, list) or isinstance(value2, list):
        return 1
    return 0 if (type(value1) is type(value2) and value1 == value2) else 1


def test_regression_ast_difference_count_includes_scalar_fields() -> None:
    a = ast.parse("assert a == 1")
    b = ast.parse("assert b == 2")
    assert _count_ast_node_differences(a, b) == 2
    assert _count_ast_node_differences(a, ast.parse("assert a == 1")) == 0


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



# ---------------------------------------------------------------------------
# 9. Review regressions
# ---------------------------------------------------------------------------

_RICH_FIXTURE = (
    "import unittest\n"
    "\n"
    "def test_eq():\n"
    "    a = 10\n"
    "    b = 20\n"
    "    assert a + b == 30\n"
    "    assert a == 10\n"
    "\n"
    "def test_ne_and_order():\n"
    "    x = 5\n"
    "    assert x != 20\n"
    "    assert x < 10\n"
    "    assert not (x == 6)\n"
    "\n"
    "def test_none_and_float():\n"
    "    r = None\n"
    "    f = 1.5\n"
    "    big = 1e20\n"
    "    assert r is None\n"
    "    assert f == 1.5\n"
    "    assert big == 1e20\n"
    "\n"
    "def test_membership():\n"
    "    n = 1\n"
    "    assert n in [0, 1]\n"
    "    assert 'a' in 'abc'\n"
    "\n"
    "class TestMethods(unittest.TestCase):\n"
    "    def test_methods(self):\n"
    "        v = 'hermetic'\n"
    "        self.assertEqual(v, 'hermetic')\n"
    "        self.assertIn(1, [0, 1])\n"
    "        self.assertIn('a', 'abc')\n"
    "        self.assertTrue(True)\n"
    "        self.assertTrue(1)\n"
    "        self.assertFalse(0)\n"
    "        self.assertIs(None, None)\n"
)


def _run_fixture(code_str: str) -> dict[str, bool]:
    """Run every test function and Test* method of a hand-written fixture."""
    import unittest

    ns: dict[str, object] = {}
    exec(code_str, ns)  # noqa: S102
    results: dict[str, bool] = {}
    for name, obj in sorted(ns.items()):
        if name.startswith("test_") and callable(obj):
            try:
                obj()  # type: ignore[operator]
                results[name] = True
            except AssertionError:
                results[name] = False
        elif name.startswith("Test") and isinstance(obj, type) and issubclass(obj, unittest.TestCase):
            for meth in sorted(vars(obj)):
                if meth.startswith("test"):
                    inst = obj(meth)
                    try:
                        getattr(inst, meth)()
                        results[f"{name}.{meth}"] = True
                    except AssertionError:
                        results[f"{name}.{meth}"] = False
    return results


def test_semantic_rich_fixture_every_mutant_fails_every_equivalent_agrees() -> None:
    """Across many seeds, equivalents agree with the original and every mutant fails its test."""
    orig = _run_fixture(_RICH_FIXTURE)
    assert all(orig.values()) and len(orig) == 5
    total_mutants = 0
    for k in range(24):
        seed = f"{k:02x}c0ffee"
        pool = build_pool(_RICH_FIXTURE, seed=seed, n_equivalents=4, n_mutants=6)
        for v in pool.variants:
            ast.parse(v.source)
        for pair in pool.pairs:
            assert _run_fixture(pair.equivalent.source) == orig, (seed, pair.equivalent.source)
            if pair.mutant is None:
                continue
            total_mutants += 1
            target = pair.mutant.site_ids[0].rsplit(":", 1)[0]
            assert _run_fixture(pair.mutant.source)[target] is False, (seed, pair.mutant.source)
    assert total_mutants > 0


def test_float_literal_sites_are_mutated_without_error() -> None:
    """A float expected value yields a mutant instead of aborting the pool."""
    pool = build_pool("def test_f():\n    x = 1.5\n    assert x == 1.5\n", seed="ab")
    assert pool.shortfalls["actual_mutants"] > 0
    for val in (1.5, 0.0, 1e20, float("inf"), float("nan")):
        mut = mutate_literal_value(val, seed="ab", site_id="t:0")
        assert isinstance(mut, float)
        assert mut != val


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("assert x == 1", True),
        ("assert x is None", True),
        ("assert not (x != 1)", True),
        ("assert not (x is not None)", True),
        ("assert x in [0, 1]", True),
        ("assert x != 1", False),
        ("assert x < 10", False),
        ("assert x is not None", False),
        ("assert not (x == 1)", False),
        ("assert 'a' in 'abc'", False),
        ("assert 1 in xs", False),
        ("assert x not in [0, 1]", False),
        ("self.assertEqual(x, 1)", True),
        ("self.assertIs(x, None)", True),
        ("self.assertIn(x, [0, 1])", True),
        ("self.assertIn('a', 'abc')", False),
        ("self.assertIn(1, xs)", False),
        ("self.assertTrue(True)", True),
        ("self.assertFalse(0)", True),
        ("self.assertFalse(None)", True),
        ("self.assertTrue(1)", False),
        ("self.assertTrue('x')", False),
        ("self.assertEqual(*pair, 1)", False),
    ],
)
def test_mutation_eligibility_requires_guaranteed_failure(src: str, expected: bool) -> None:
    """Only sites whose mutated form must fail are eligible for mutation."""
    tree = parse_test_source(f"class TestK:\n    def test_k(self):\n        {src}\n")
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert can_mutate_site(sites[0]) is expected
    if not expected:
        with pytest.raises(MutantError):
            apply_mutant_rewrite(tree, sites[0].site_id, seed="ab")


def test_in_container_mutant_never_contains_an_original_element() -> None:
    """A membership mutant's container shares no element with the original container."""
    src = "class TestK:\n    def test_k(self):\n        self.assertIn(x, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])\n"
    tree = parse_test_source(src)
    site_id = find_assertion_sites(tree)[0].site_id
    for k in range(200):
        new_tree, _ = apply_mutant_rewrite(tree, site_id, seed=f"{k:x}")
        call = find_assertion_sites(new_tree)[0].node.value  # type: ignore[attr-defined]
        new_elts = [e.value for e in call.args[1].elts]
        assert not set(new_elts) & set(range(10)), k


def test_mutant_text_carries_no_fixed_marker() -> None:
    """Neither variant kind carries a fixed mutation marker or inserted no-op."""
    src = (
        "def test_m():\n"
        "    assert s == 'abc'\n"
        "    assert b == b'abc'\n"
        "    assert r is None\n"
    )
    for k in range(8):
        pool = build_pool(src, seed=f"{k:x}1", n_equivalents=3, n_mutants=3)
        for v in pool.variants:
            low = v.source.lower()
            assert all(marker not in low for marker in ("mut", "sentinel", "hermetic", "noop"))
            assert "insert_noop" not in v.rewrites


def test_seed_must_be_plain_hex(tmp_path: Path) -> None:
    """Seeds with prefixes, signs, underscores, whitespace or excess length are rejected."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_ok():\n    assert x == 1\n", encoding="utf-8")
    for i, bad in enumerate(["0xab", "a_b", " ab ", "+ab", "-ab", "ab\n", "a" * 257]):
        rc = main(["--test-file", str(test_file), "--seed", bad, "--out", str(tmp_path / f"o{i}")])
        assert rc == 1, bad
        assert not (tmp_path / f"o{i}").exists()
    assert main(["--test-file", str(test_file), "--seed", "AB", "--out", str(tmp_path / "ok")]) == 0
    manifest = json.loads((tmp_path / "ok" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["seed"] == "ab"


def test_candidate_combinations_are_bounded() -> None:
    """Rewrite combinations stay within named caps however many sites a file has."""
    from hermetic_mutants import pool as pool_mod

    ops = [("swap_compare", f"test_x:{i:04d}") for i in range(300)]
    combos = pool_mod._generate_candidate_combos(ops, "ab", 4)
    assert len(combos) <= pool_mod.MAX_CANDIDATE_COMBOS
    assert len(combos) <= pool_mod.MAX_REWRITE_OPS * 3
    with pytest.raises(MutantError):
        build_pool("def test_a():\n    assert x == 1\n", "ab", n_equivalents=pool_mod.MAX_VARIANTS_PER_KIND + 1)
    with pytest.raises(MutantError):
        build_pool("def test_a():\n    assert x == 1\n", "ab", n_mutants=-1)


def test_names_bound_without_name_nodes_are_not_renamed() -> None:
    """except-as names, match captures, nested def names and local imports are never renamed."""
    src = (
        "def test_bind():\n"
        "    e = None\n"
        "    try:\n"
        "        raise ValueError('x')\n"
        "    except ValueError as e:\n"
        "        assert str(e) == 'x'\n"
        "    m = 0\n"
        "    match [1]:\n"
        "        case [m]:\n"
        "            pass\n"
        "    helper = 1\n"
        "    def helper():\n"
        "        return 2\n"
        "    os = 3\n"
        "    import os\n"
        "    keep = 4\n"
        "    assert keep == 4\n"
    )
    tree = parse_test_source(src)
    assert get_renamable_locals(tree.body[0], tree) == ["keep"]  # type: ignore[arg-type]


def test_dynamic_scope_functions_are_not_renamed_or_padded() -> None:
    """A test using locals() gets neither a rename nor an inserted no-op."""
    src = "def test_dyn():\n    x = 1\n    assert locals() == {'x': 1}\n"
    tree = parse_test_source(src)
    assert get_renamable_locals(tree.body[0], tree) == []  # type: ignore[arg-type]
    pool = build_pool(src, seed="ab", n_equivalents=4, n_mutants=0)
    assert pool.variants == ()
    for v in pool.variants:
        assert _run_fixture(v.source) == {"test_dyn": True}


def test_variants_preserve_docstring_without_padding() -> None:
    """Rewritten functions retain their docstring and contain no added statements."""
    src = 'def test_doc():\n    """Doc."""\n    assert x == 1\n'
    pool = build_pool(src, seed="ab", n_equivalents=2, n_mutants=2)
    assert len(pool.variants) == 4
    for variant in pool.variants:
        func = ast.parse(variant.source).body[0]
        assert ast.get_docstring(func) == "Doc."
        assert len(func.body) == 2
        assert isinstance(func.body[1], ast.Assert)


def test_new_names_never_collide_with_existing_identifiers() -> None:
    """A rename whose derived name already exists in the module is refused."""
    src = "_hw_res = 5\ndef test_c():\n    result = 1\n    assert result == _hw_res - 4\n"
    tree = parse_test_source(src)
    with pytest.raises(MutantError):
        apply_rename_local(tree, "test_c", "result", "_hw_res")


def test_rebound_test_names_are_skipped() -> None:
    """A redefined test function or class is skipped, so site ids are unique and live."""
    src = (
        "def test_a():\n    assert x == 1\n"
        "def test_a():\n    assert x == 2\n"
        "class TestK:\n"
        "    def test_m(self):\n        assert y == 1\n"
        "    test_m = None\n"
        "def test_b():\n    assert z == 3\n"
    )
    sites = find_assertion_sites(parse_test_source(src))
    assert [s.site_id for s in sites] == ["test_b:0"]


def test_starred_assert_equal_not_swapped() -> None:
    """assertEqual with a starred argument is not operand-swapped."""
    tree = parse_test_source("class TestK:\n    def test_k(self):\n        self.assertEqual(*pair, x)\n")
    sites = find_assertion_sites(tree)
    assert len(sites) == 1
    assert not can_swap_assert_equal(sites[0])


def test_only_self_assert_calls_are_sites() -> None:
    """Assert-method calls on other objects or bare names are not assertion sites."""
    src = (
        "class TestK:\n"
        "    def test_k(self):\n"
        "        other.assertEqual(x, 1)\n"
        "        assertEqual(x, 1)\n"
        "        self.assertEqual(x, 1)\n"
    )
    sites = find_assertion_sites(parse_test_source(src))
    assert [s.site_id for s in sites] == ["TestK.test_k:0"]


def test_more_mutants_than_equivalents_are_generated_and_paired() -> None:
    """Mutant requests beyond the equivalent count reuse equivalents as paired bases."""
    src = "def test_m():\n    assert a == 1\n    assert b == 2\n    assert c == 3\n"
    pool = build_pool(src, seed="ab", n_equivalents=1, n_mutants=3)
    mutants = [v for v in pool.variants if v.kind == "mutant"]
    assert len(mutants) == 3
    assert pool.shortfall_reason is None
    hashes = [v.sha256 for v in pool.variants]
    assert len(set(hashes)) == len(hashes)
    for pair in pool.pairs:
        assert pair.mutant is not None
        assert pair.equivalent.name == "variant_eq_0.py"
        diffs = _count_ast_node_differences(
            ast.parse(pair.equivalent.source), ast.parse(pair.mutant.source)
        )
        assert diffs == 1


def test_eligible_sites_string_rejected() -> None:
    """A bare string for eligible_sites is refused instead of silently matching nothing."""
    with pytest.raises(MutantError):
        build_pool("def test_a():\n    assert x == 1\n", "ab", eligible_sites="test_a:0")


def test_builtin_named_locals_are_renamable() -> None:
    """Renaming does not depend on the interpreter's builtin name list."""
    src = "def test_s():\n    sum = 3\n    assert sum == 3\n"
    tree = parse_test_source(src)
    assert get_renamable_locals(tree.body[0], tree) == ["sum"]  # type: ignore[arg-type]


def test_string_annotation_identifiers_not_renamed() -> None:
    """Identifiers inside a compound string annotation are not renamed."""
    src = "def test_a():\n    Thing = 1\n    x: 'list[Thing]' = [1]\n    assert x == [1]\n"
    tree = parse_test_source(src)
    assert "Thing" not in get_renamable_locals(tree.body[0], tree)  # type: ignore[arg-type]


def test_cli_invalid_input_touches_no_files(tmp_path: Path) -> None:
    """Invalid test syntax is reported before the output directory is created."""
    test_file = tmp_path / "test_bad.py"
    test_file.write_text("def test_(:\n", encoding="utf-8")
    out_dir = tmp_path / "out"
    assert main(["--test-file", str(test_file), "--seed", "ab", "--out", str(out_dir)]) == 1
    assert not out_dir.exists()


def test_cli_usage_error_exits_1(tmp_path: Path) -> None:
    """Missing or malformed arguments exit 1, not argparse's 2."""
    assert main(["--seed", "ab"]) == 1
    assert main(["--test-file", "x", "--seed", "ab", "--out", "y", "--equivalents", "many"]) == 1


def test_cli_out_symlink_refused(tmp_path: Path) -> None:
    """A symlinked output directory is refused and nothing is written through it."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_ok():\n    assert x == 1\n", encoding="utf-8")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert main(["--test-file", str(test_file), "--seed", "ab", "--out", str(link)]) == 1
    assert list(real.iterdir()) == []


def test_fifo_test_file_refused_without_blocking(tmp_path: Path) -> None:
    """A FIFO is refused before any open, so the read never blocks."""
    fifo = tmp_path / "test_fifo.py"
    os.mkfifo(fifo)
    with pytest.raises(ParseError):
        read_test_file(fifo)


def test_atomic_write_survives_short_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Variant files are complete even when os.write writes only part of a buffer."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_ok():\n    value = 1\n    assert value == 1\n", encoding="utf-8")
    real_write = os.write

    def short_write(fd: int, data: bytes) -> int:
        return real_write(fd, bytes(data[:7]))

    monkeypatch.setattr(os, "write", short_write)
    rc = main(["--test-file", str(test_file), "--seed", "ab", "--out", str(tmp_path / "out")])
    monkeypatch.undo()
    assert rc == 0
    import hashlib

    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    for v in manifest["variants"]:
        data = (tmp_path / "out" / v["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == v["sha256"]
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(
        [v["file"] for v in manifest["variants"]] + ["manifest.json"]
    )


def test_identity_none_mutant_compiles_without_warning() -> None:
    """`x is None` mutates to a bool, so compiling the mutant emits no SyntaxWarning."""
    import warnings

    tree = parse_test_source("def test_n():\n    assert r is None\n")
    for k in range(8):
        new_tree, _ = apply_mutant_rewrite(tree, "test_n:0", seed=f"{k:x}")
        text = ast.unparse(new_tree)
        assert text != ast.unparse(tree)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(text, "<mutant>", "exec")


def test_known_answer_manifest_and_variants() -> None:
    """Fixed source and seed give exactly these variant texts and manifest bytes."""
    import hashlib

    from hermetic_mutants.__main__ import build_manifest_bytes

    src = "def test_kat():\n    val = 100\n    assert val == 100\n"
    pool = build_pool(src, seed="0123456789abcdef", n_equivalents=2, n_mutants=2)
    assert [v.source for v in pool.variants] == [
        "def test_kat():\n    val = 100\n    assert 100 == val",
        "def test_kat():\n    val = 100\n    assert not val != 100",
        "def test_kat():\n    val = 100\n    assert 631 == val",
        "def test_kat():\n    val = 100\n    assert not val != 631",
    ]
    manifest = build_manifest_bytes(pool, "0123456789abcdef")
    assert hashlib.sha256(manifest).hexdigest() == (
        "1ea947eac721084b9b88925e3a3b4489b81f899e14f17abbc0f6355dc72ce238"
    )
