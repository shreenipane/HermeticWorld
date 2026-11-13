"""Tests for hermetic_assert_flow.parse."""

from __future__ import annotations

import ast

import pytest

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.limits import MAX_AST_DEPTH, MAX_AST_NODES, MAX_SOURCE_BYTES
from hermetic_assert_flow.parse import parse_source


def test_parse_valid_source() -> None:
    src = b"def test_ok():\n    x = 1\n    assert x == 1\n"
    tree = parse_source(src)
    assert isinstance(tree, ast.Module)
    assert len(tree.body) == 1


def test_parse_rejects_oversized_source_above_1mib() -> None:
    oversized = b"x = 1\n" * ((MAX_SOURCE_BYTES // 6) + 10)
    assert len(oversized) > MAX_SOURCE_BYTES
    with pytest.raises(FlowError) as exc_info:
        parse_source(oversized)
    assert exc_info.value.code == "SOURCE_TOO_LARGE"


def test_parse_rejects_non_utf8_bytes() -> None:
    bad_utf8 = b"def test_bad():\n    s = '\xff\xfe'\n"
    with pytest.raises(FlowError) as exc_info:
        parse_source(bad_utf8)
    assert exc_info.value.code == "INVALID_UTF8"


def test_parse_rejects_latin1_coding_cookie_with_non_utf8() -> None:
    latin1_bytes = b"# -*- coding: latin-1 -*-\ndef test_latin1():\n    s = '\xe9'\n"
    with pytest.raises(FlowError) as exc_info:
        parse_source(latin1_bytes)
    assert exc_info.value.code == "INVALID_UTF8"


def test_parse_rejects_syntax_error_as_flow_error() -> None:
    invalid_syntax = b"def test_broken(:\n    assert True\n"
    with pytest.raises(FlowError) as exc_info:
        parse_source(invalid_syntax)
    assert exc_info.value.code == "PARSE_ERROR"


def test_parse_rejects_null_byte_as_flow_error() -> None:
    with_null = b"def test_null():\n    x = '\x00'\n"
    with pytest.raises(FlowError) as exc_info:
        parse_source(with_null)
    assert exc_info.value.code == "PARSE_ERROR"


def test_parse_rejects_deeply_nested_expression() -> None:
    depth = MAX_AST_DEPTH + 20
    deep_expr = ("(" * depth) + "1" + (")" * depth)
    # Parentheses alone collapse in Python's AST; chain binary ops to force AST depth.
    deep_binop = "1" + (" + 1" * (MAX_AST_DEPTH + 20))
    src = f"def test_deep():\n    x = {deep_binop}\n".encode("utf-8")
    assert len(src) < MAX_SOURCE_BYTES
    with pytest.raises(FlowError) as exc_info:
        parse_source(src)
    assert exc_info.value.code in {"AST_TOO_DEEP", "PARSE_ERROR"}
    assert deep_expr  # keep variable referenced


def test_parse_rejects_excessive_ast_nodes() -> None:
    # Each `a = 1; ` is 3 AST nodes (Assign, Name, Constant); 20,000 statements > 50,000 nodes.
    stmt = "a = 1\n"
    count = (MAX_AST_NODES // 2) + 500
    src = ("def test_huge_ast():\n" + ("    " + stmt) * count).encode("utf-8")
    assert len(src) < MAX_SOURCE_BYTES
    with pytest.raises(FlowError) as exc_info:
        parse_source(src)
    assert exc_info.value.code == "AST_TOO_MANY_NODES"


def test_parse_never_executes_module_code() -> None:
    src = (
        b"raise RuntimeError('MUST_NOT_EXECUTE')\n"
        b"def test_never_run():\n"
        b"    assert 1 == 1\n"
    )
    tree = parse_source(src)
    assert isinstance(tree, ast.Module)
