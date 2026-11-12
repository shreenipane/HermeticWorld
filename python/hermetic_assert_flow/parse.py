"""Safe, bounded Python AST parsing from raw bytes without code execution."""

from __future__ import annotations

import ast

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.limits import (
    MAX_AST_DEPTH,
    MAX_AST_NODES,
    MAX_SOURCE_BYTES,
)


def parse_source(
    source: bytes,
    *,
    max_bytes: int = MAX_SOURCE_BYTES,
    max_depth: int = MAX_AST_DEPTH,
    max_nodes: int = MAX_AST_NODES,
) -> ast.Module:
    """Parse Python source bytes into an ast.Module under strict size, UTF-8, depth, and node caps.

    Never imports, compiles bytecode, or executes the parsed source.
    """
    if not isinstance(source, bytes):
        raise FlowError("Source must be bytes", code="INVALID_SOURCE_TYPE")

    if len(source) > max_bytes:
        raise FlowError(
            f"Source size exceeds cap of {max_bytes} bytes",
            code="SOURCE_TOO_LARGE",
        )

    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FlowError("Source is not valid UTF-8", code="INVALID_UTF8") from exc

    try:
        tree = ast.parse(text, filename="<hermetic>", mode="exec", type_comments=False)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise FlowError(
            f"Unable to parse Python source ({type(exc).__name__})",
            code="PARSE_ERROR",
        ) from exc

    _enforce_ast_caps(tree, max_depth=max_depth, max_nodes=max_nodes)
    return tree


def _enforce_ast_caps(tree: ast.AST, *, max_depth: int, max_nodes: int) -> None:
    """Iteratively validate AST depth and total node count without recursion."""
    node_count = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]

    while stack:
        current, depth = stack.pop()
        node_count += 1
        if node_count > max_nodes:
            raise FlowError(
                f"AST node count exceeds cap of {max_nodes}",
                code="AST_TOO_MANY_NODES",
            )
        if depth > max_depth:
            raise FlowError(
                f"AST depth exceeds cap of {max_depth}",
                code="AST_TOO_DEEP",
            )
        for child in ast.iter_child_nodes(current):
            stack.append((child, depth + 1))
