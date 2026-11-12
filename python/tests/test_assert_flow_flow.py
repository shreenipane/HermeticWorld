"""Tests for hermetic_assert_flow.flow covering every data-flow, give-up, and determinism rule."""

from __future__ import annotations

import pytest

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.flow import analyze_flow, eligible_sites


def test_direct_dependency() -> None:
    src = b"""
def test_direct():
    clean = 10
    val = failing_op()
    assert clean == 10
    assert val == 20
"""
    # line 4: `val = failing_op()`
    result = eligible_sites(src, "test_direct", raising_line=4, reached_site_ids=[])
    assert result == ["test_direct#1"]


def test_transitive_chain() -> None:
    src = b"""
def test_chain():
    a = failing_op()
    b = a + 5
    c = b * 2
    unrelated = 99
    assert unrelated == 99
    assert c == 30
"""
    # line 3: `a = failing_op()`
    result = eligible_sites(src, "test_chain", raising_line=3, reached_site_ids=[])
    assert result == ["test_chain#1"]


def test_untaint_by_reassignment() -> None:
    src = b"""
def test_untaint():
    x = failing_op()
    assert x == 1
    x = 42
    assert x == 42
"""
    # line 3: `x = failing_op()`
    # site #0 (line 4) sees tainted x -> eligible
    # line 5: `x = 42` untaints x
    # site #1 (line 6) sees untainted x -> not eligible
    result = eligible_sites(src, "test_untaint", raising_line=3, reached_site_ids=[])
    assert result == ["test_untaint#0"]


def test_branch_may_taint_and_full_overwrite_untaint() -> None:
    src = b"""
def test_branches(cond):
    x = failing_op()
    y = 0
    if cond:
        y = x + 1
        x = 10
    else:
        x = 20
    assert y > 0
    assert x >= 10
"""
    # line 3: `x = failing_op()`
    # In `if`: y becomes tainted, x becomes untainted.
    # In `else`: y stays untainted, x becomes untainted.
    # Join after `if/else`: y is tainted on `if` path (may-taint -> eligible),
    # x is untainted on ALL paths (not eligible).
    result = eligible_sites(src, "test_branches", raising_line=3, reached_site_ids=[])
    assert result == ["test_branches#0"]


def test_branch_partial_overwrite_preserves_may_taint() -> None:
    src = b"""
def test_partial_overwrite(cond):
    x = failing_op()
    if cond:
        x = 10
    assert x == 10
"""
    # On the implicit else path, x is still tainted -> may-taint -> eligible.
    result = eligible_sites(src, "test_partial_overwrite", raising_line=3, reached_site_ids=[])
    assert result == ["test_partial_overwrite#0"]


def test_loop_target_and_body_fixpoint() -> None:
    src = b"""
def test_loop():
    items = failing_items()
    total = 0
    for item in items:
        total = total + item
    assert total > 0
"""
    # line 3: `items = failing_items()` -> items tainted -> item tainted -> total tainted
    result = eligible_sites(src, "test_loop", raising_line=3, reached_site_ids=[])
    assert result == ["test_loop#0"]


def test_tuple_unpacking() -> None:
    src = b"""
def test_unpack():
    pair = failing_pair()
    left, right = pair
    a, b = left, 100
    assert a == 1
    assert b == 100
    assert right == 2
"""
    # line 3: `pair = failing_pair()`
    # left and right both tainted from `pair`; then `a, b = left, 100` taints `a` and untaints `b`.
    result = eligible_sites(src, "test_unpack", raising_line=3, reached_site_ids=[])
    assert result == ["test_unpack#0", "test_unpack#2"]


def test_call_propagation() -> None:
    src = b"""
def test_call_prop():
    raw = failing_input()
    transformed = normalize(raw, mode="strict")
    clean = normalize("constant", mode="strict")
    assert clean == "CONSTANT"
    assert transformed == "EXPECTED"
"""
    result = eligible_sites(src, "test_call_prop", raising_line=3, reached_site_ids=[])
    assert result == ["test_call_prop#1"]


def test_attribute_and_subscript_stores_taint_base_name() -> None:
    src = b"""
def test_stores(self):
    bad = failing_value()
    cfg = make_config()
    arr = [1, 2, 3]
    cfg.endpoint = bad
    arr[0] = bad
    self.assertEqual(cfg.port, 8080)
    self.assertIn(2, arr)
"""
    # line 3: `bad = failing_value()`
    # `cfg.endpoint = bad` taints base `cfg`; `arr[0] = bad` taints base `arr`.
    result = eligible_sites(src, "test_stores", raising_line=3, reached_site_ids=[])
    assert result == ["test_stores#0", "test_stores#1"]


def test_augmented_assignment_with_as_and_walrus() -> None:
    src = b"""
def test_extra_forms():
    seed = failing_seed()
    acc = 1
    acc += seed
    with open_ctx(seed) as handle:
        data = handle.read()
    if (captured := data):
        assert captured == "ok"
    assert acc > 1
"""
    result = eligible_sites(src, "test_extra_forms", raising_line=3, reached_site_ids=[])
    assert result == ["test_extra_forms#0", "test_extra_forms#1"]


def test_reached_sites_always_eligible_and_pre_raising_unreached_excluded() -> None:
    src = b"""
def test_reached():
    x = 1
    assert x == 1
    assert x == 2
    y = failing_call()
    assert x == 1
    assert y == 3
"""
    # line 6: `y = failing_call()`
    # site #0 (line 4): before raising_line, not reached -> NOT eligible
    # site #1 (line 5): before raising_line, listed in reached_site_ids -> ELIGIBLE
    # site #2 (line 7): after raising_line, reads untainted x -> NOT eligible
    # site #3 (line 8): after raising_line, reads tainted y -> ELIGIBLE
    result = eligible_sites(
        src,
        "test_reached",
        raising_line=6,
        reached_site_ids=["test_reached#1"],
    )
    assert result == ["test_reached#1", "test_reached#3"]


@pytest.mark.parametrize(
    ("snippet", "expected_reason_fragment"),
    [
        (
            b"""
def test_nested_fn():
    x = failing()
    assert x == 1
    def inner():
        return x
    assert x == 2
""",
            "nested function",
        ),
        (
            b"""
def test_lambda():
    x = failing()
    assert x == 1
    fn = lambda v: v + x
    assert x == 2
""",
            "lambda",
        ),
        (
            b"""
G = 0
def test_global():
    global G
    x = failing()
    assert x == 1
    G = x
    assert x == 2
""",
            "global",
        ),
        (
            b"""
def outer():
    z = 0
    def test_nonlocal():
        nonlocal z
        x = failing()
        assert x == 1
        z = x
        assert x == 2
""",
            "nonlocal",
        ),
    ],
)
def test_give_up_cases_return_only_reached_sites(
    snippet: bytes,
    expected_reason_fragment: str,
) -> None:
    if b"outer" in snippet:
        # Verify module-level test_* with nonlocal inside a helper isn't needed; test valid module-level give-up too.
        with pytest.raises(FlowError):
            analyze_flow(snippet, "test_nonlocal", raising_line=6, reached_site_ids=[])
        return

    res = analyze_flow(
        snippet,
        function=snippet.splitlines()[1].split(b"(")[0].split()[1].decode("utf-8"),
        raising_line=3,
        reached_site_ids=[
            f"{snippet.splitlines()[1].split(b'(')[0].split()[1].decode('utf-8')}#0"
        ],
    )
    assert res.gave_up is True
    assert res.reason is not None
    assert expected_reason_fragment in res.reason
    assert len(res.eligible) == 1
    assert res.eligible[0].endswith("#0")


def test_give_up_on_nonlocal_in_valid_test_method() -> None:
    # A Test* class method containing a nonlocal statement (even invalid semantically at runtime,
    # AST-valid in Python!) must trigger give-up cleanly without crashing.
    src = b"""
class TestNonlocal:
    def test_nl(self):
        nonlocal outside
        x = failing()
        assert x == 1
        assert x == 2
"""
    res = analyze_flow(
        src,
        function="TestNonlocal.test_nl",
        raising_line=5,
        reached_site_ids=["TestNonlocal.test_nl#0"],
    )
    assert res.gave_up is True
    assert res.reason is not None
    assert "nonlocal" in res.reason
    assert res.eligible == ["TestNonlocal.test_nl#0"]


def test_determinism_repeated_calls_identical() -> None:
    src = b"""
def test_det(a, b, c):
    v0 = failing()
    if a:
        v1 = v0
        v2 = v1
    elif b:
        v3 = v0
        v4 = v3
    else:
        v5 = v0
    assert v0 == 1
    assert v1 == 1
    assert v2 == 1
    assert v3 == 1
    assert v4 == 1
    assert v5 == 1
"""
    first = analyze_flow(src, "test_det", raising_line=3, reached_site_ids=["test_det#0"])
    for _ in range(20):
        again = analyze_flow(src, "test_det", raising_line=3, reached_site_ids=["test_det#0"])
        assert again == first
