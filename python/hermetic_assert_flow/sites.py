"""Discovery of assertion sites inside a target test function in source order."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.limits import (
    MAX_EXPR_DEPTH,
    MAX_IDENTIFIER_LENGTH,
    MAX_SITES_PER_FUNCTION,
    MAX_STATEMENTS_PER_FUNCTION,
)
from hermetic_assert_flow.parse import parse_source

# Supported unittest assertion methods and their checked positional/keyword argument counts (excluding msg).
SUPPORTED_ASSERT_METHODS: dict[str, tuple[int, tuple[str, ...]]] = {
    "assertEqual": (2, ("first", "second")),
    "assertNotEqual": (2, ("first", "second")),
    "assertTrue": (1, ("expr",)),
    "assertFalse": (1, ("expr",)),
    "assertIs": (2, ("expr1", "expr2")),
    "assertIsNone": (1, ("obj",)),
    "assertIn": (2, ("member", "container")),
}


@dataclass(frozen=True)
class AssertionSite:
    """A single assertion site inside a test function."""

    site_id: str
    qualified_name: str
    index: int
    lineno: int
    end_lineno: int
    col_offset: int
    kind: str
    checked_exprs: tuple[ast.expr, ...]


def validate_test_function_name(function: str) -> tuple[str | None, str]:
    """Validate and split a qualified test function name into (class_name_or_None, func_name)."""
    if not isinstance(function, str) or not function or len(function) > MAX_IDENTIFIER_LENGTH:
        raise FlowError("Invalid target test function name", code="INVALID_FUNCTION_NAME")

    if "." in function:
        parts = function.split(".")
        if len(parts) != 2:
            raise FlowError(
                "Qualified function name must be 'test_*' or 'Test*.test_*'",
                code="INVALID_FUNCTION_NAME",
            )
        cls_name, fn_name = parts
        if not (cls_name.startswith("Test") and cls_name.isidentifier()):
            raise FlowError(
                "Test class name must match 'Test*'",
                code="INVALID_FUNCTION_NAME",
            )
        if not (fn_name.startswith("test_") and fn_name.isidentifier()):
            raise FlowError(
                "Test method name must match 'test_*'",
                code="INVALID_FUNCTION_NAME",
            )
        return cls_name, fn_name

    if not (function.startswith("test_") and function.isidentifier()):
        raise FlowError(
            "Module-level test function name must match 'test_*'",
            code="INVALID_FUNCTION_NAME",
        )
    return None, function


def find_test_function_node(
    tree: ast.Module,
    function: str,
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]:
    """Locate the target module-level test_* function or Test*.test_* method in an AST module."""
    cls_name, fn_name = validate_test_function_name(function)
    matches: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    if cls_name is None:
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == fn_name:
                matches.append(stmt)
    else:
        for stmt in tree.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == cls_name:
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == fn_name:
                        matches.append(item)

    if not matches:
        raise FlowError("Target test function not found", code="FUNCTION_NOT_FOUND")
    if len(matches) > 1:
        raise FlowError("Duplicate test function definitions found", code="DUPLICATE_FUNCTION")

    return matches[0], function


def is_supported_self_assert_call(node: ast.AST) -> str | None:
    """Return the method name if node is self.<supported_assert>(...), else None."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    if not isinstance(func.value, ast.Name) or func.value.id != "self":
        return None
    if func.attr in SUPPORTED_ASSERT_METHODS:
        return func.attr
    return None


def extract_checked_exprs_from_call(call: ast.Call, method_name: str) -> tuple[ast.expr, ...]:
    """Return the checked value expressions for a supported self.assert* call (excluding msg)."""
    arity, kw_names = SUPPORTED_ASSERT_METHODS[method_name]
    checked: list[ast.expr] = []

    for arg in call.args[:arity]:
        checked.append(arg)

    for kw in call.keywords:
        if kw.arg is None:
            # **kwargs could supply checked parameters
            checked.append(kw.value)
        elif kw.arg in kw_names:
            checked.append(kw.value)

    return tuple(checked)


def _iter_expr_calls_in_source_order(root_expr: ast.expr) -> list[ast.Call]:
    """Iteratively collect all Call nodes inside root_expr in deterministic source order."""
    calls: list[ast.Call] = []
    stack: list[tuple[ast.AST, int]] = [(root_expr, 1)]

    while stack:
        node, depth = stack.pop()
        if depth > MAX_EXPR_DEPTH:
            raise FlowError(
                f"Expression depth exceeds cap of {MAX_EXPR_DEPTH}",
                code="EXPR_TOO_DEEP",
            )
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Do not descend into nested function/class scopes.
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        children = list(ast.iter_child_nodes(node))
        for child in reversed(children):
            stack.append((child, depth + 1))

    calls.sort(key=lambda c: (getattr(c, "lineno", 0), getattr(c, "col_offset", 0)))
    return calls


def extract_sites_from_function(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    qualified_name: str,
) -> list[AssertionSite]:
    """Extract all assertion sites within fn_node in deterministic source order."""
    raw_sites: list[tuple[int, int, int, str, tuple[ast.expr, ...]]] = []
    stmt_count = 0

    def record_site(node: ast.AST, kind: str, checked_exprs: tuple[ast.expr, ...]) -> None:
        if len(raw_sites) >= MAX_SITES_PER_FUNCTION:
            raise FlowError(
                f"Assertion site count exceeds cap of {MAX_SITES_PER_FUNCTION}",
                code="TOO_MANY_SITES",
            )
        lineno = getattr(node, "lineno", 0)
        end_lineno = getattr(node, "end_lineno", lineno) or lineno
        col_offset = getattr(node, "col_offset", 0)
        raw_sites.append((lineno, col_offset, end_lineno, kind, checked_exprs))

    def scan_expr(expr: ast.expr | None) -> None:
        if expr is None:
            return
        for call in _iter_expr_calls_in_source_order(expr):
            method = is_supported_self_assert_call(call)
            if method is not None:
                record_site(call, method, extract_checked_exprs_from_call(call, method))

    def walk_stmts(stmts: list[ast.stmt]) -> None:
        nonlocal stmt_count
        for stmt in stmts:
            stmt_count += 1
            if stmt_count > MAX_STATEMENTS_PER_FUNCTION:
                raise FlowError(
                    f"Statement count in function exceeds cap of {MAX_STATEMENTS_PER_FUNCTION}",
                    code="TOO_MANY_STATEMENTS",
                )

            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Nested scopes are not traversed for sites; flow analysis handles give-up.
                continue

            if isinstance(stmt, ast.Assert):
                record_site(stmt, "assert", (stmt.test,))
                scan_expr(stmt.test)
                scan_expr(stmt.msg)
            elif isinstance(stmt, ast.Expr):
                scan_expr(stmt.value)
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    scan_expr(target)
                scan_expr(stmt.value)
            elif isinstance(stmt, ast.AnnAssign):
                scan_expr(stmt.target)
                scan_expr(stmt.annotation)
                scan_expr(stmt.value)
            elif isinstance(stmt, ast.AugAssign):
                scan_expr(stmt.target)
                scan_expr(stmt.value)
            elif isinstance(stmt, ast.If):
                scan_expr(stmt.test)
                walk_stmts(stmt.body)
                walk_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                scan_expr(stmt.target)
                scan_expr(stmt.iter)
                walk_stmts(stmt.body)
                walk_stmts(stmt.orelse)
            elif isinstance(stmt, ast.While):
                scan_expr(stmt.test)
                walk_stmts(stmt.body)
                walk_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    scan_expr(item.context_expr)
                    scan_expr(item.optional_vars)
                walk_stmts(stmt.body)
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                walk_stmts(stmt.body)
                for handler in stmt.handlers:
                    scan_expr(handler.type)
                    walk_stmts(handler.body)
                walk_stmts(stmt.orelse)
                walk_stmts(stmt.finalbody)
            elif isinstance(stmt, ast.Match):
                scan_expr(stmt.subject)
                for case in stmt.cases:
                    scan_expr(case.guard)
                    walk_stmts(case.body)
            elif isinstance(stmt, ast.Return):
                scan_expr(stmt.value)
            elif isinstance(stmt, ast.Raise):
                scan_expr(stmt.exc)
                scan_expr(stmt.cause)
            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    scan_expr(target)

    walk_stmts(fn_node.body)

    # Sort strictly by source position (lineno, col_offset) for deterministic indexing.
    raw_sites.sort(key=lambda item: (item[0], item[1]))

    sites: list[AssertionSite] = []
    for idx, (lineno, col_offset, end_lineno, kind, checked_exprs) in enumerate(raw_sites):
        sites.append(
            AssertionSite(
                site_id=f"{qualified_name}#{idx}",
                qualified_name=qualified_name,
                index=idx,
                lineno=lineno,
                end_lineno=end_lineno,
                col_offset=col_offset,
                kind=kind,
                checked_exprs=checked_exprs,
            )
        )
    return sites


def list_assertion_sites(source: bytes, function: str) -> list[AssertionSite]:
    """Parse source bytes and return all assertion sites in the named test function."""
    tree = parse_source(source)
    fn_node, qualified_name = find_test_function_node(tree, function)
    return extract_sites_from_function(fn_node, qualified_name)
