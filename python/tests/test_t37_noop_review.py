"""Regressions for the §11.2 rewrite decision and Unicode data attribution."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

from hermetic_mutants import build_pool


@pytest.mark.parametrize(
    "source",
    [
        "def test_value():\n    value = 1\n    assert value == 1\n",
        'def test_doc():\n    """Doc."""\n    assert value == 1\n',
        "class TestValue:\n    def test_value(self):\n        self.assertEqual(value, 1)\n",
        "async def test_value():\n    assert value == 1\n",
        "def test_existing():\n    unused = None\n    assert value == 1\n",
    ],
)
def test_no_variant_contains_inserted_statements(source: str) -> None:
    """Every equivalent and paired mutant has exactly the original statements."""
    original_statements = Counter(
        type(node) for node in ast.walk(ast.parse(source)) if isinstance(node, ast.stmt)
    )
    for seed in ("ab", "cd", "0123456789abcdef"):
        pool = build_pool(source, seed=seed, n_equivalents=64, n_mutants=64)
        assert {variant.kind for variant in pool.variants} == {"equivalent", "mutant"}
        for variant in pool.variants:
            statements = Counter(
                type(node)
                for node in ast.walk(ast.parse(variant.source))
                if isinstance(node, ast.stmt)
            )
            assert statements == original_statements
            assert "insert_noop" not in variant.rewrites


def test_unicode_names_license_notice() -> None:
    """The distributed Unicode 16.0.0 table carries its source and licence notice."""
    root = Path(__file__).resolve().parents[2]
    data = root / "crates/hermetic-sealcheck/data"
    with (data / "unicode_names.txt").open(encoding="utf-8") as table:
        header = "".join(next(table) for _ in range(4))
    assert "Unicode 16.0.0" in header
    assert "Unicode License v3" in header
    assert "LICENSE-UNICODE" in header
    assert "https://www.unicode.org/license.txt" in header
    notice = (data / "LICENSE-UNICODE").read_text(encoding="utf-8")
    assert "unicode_names.txt" in notice
    assert "Unicode 16.0.0" in notice
    assert "UNICODE LICENSE V3" in notice
    assert "Unicode, Inc." in notice
    assert "Permission is hereby granted, free of charge" in notice
    assert "this copyright and permission notice appear with all copies" in notice
    assert 'THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS"' in notice
    assert "IN NO EVENT SHALL THE COPYRIGHT HOLDER" in notice
    assert notice.endswith("authorization of the copyright holder.\n")
