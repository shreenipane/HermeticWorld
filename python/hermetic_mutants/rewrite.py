"""AST parsing and rewriting for Hermetic World test variant generation (TR-GR-8).

This module implements syntax-tree rewriting to produce:
1. Equivalent rewrites: test code with identical meaning and side-effect-free operands.
2. Mutant rewrites: test code where exactly one assertion site's expected literal is
   replaced with a third, differing value built deterministically from the seed.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# Resource bounds to protect against hostile or runaway inputs
MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2 MiB
MAX_AST_DEPTH: int = 200
MAX_AST_NODES: int = 50_000

# Standard assertion methods in unittest.TestCase
ASSERT_METHODS: frozenset[str] = frozenset(
    {"assertEqual", "assertTrue", "assertFalse", "assertIs", "assertIn"}
)

# Node types treated as possibly side-effecting
# Operands containing calls, awaits, yields, walrus, comprehension side effects
# or attribute access on unknown objects are strictly forbidden for operand swap.
FORBIDDEN_SIDE_EFFECT_TYPES: tuple[type[ast.AST], ...] = (
    ast.Call,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
    ast.NamedExpr,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
    ast.Attribute,
    ast.Lambda,
)


class MutantError(Exception):
    """Base exception for all hermetic_mutants errors."""


class ParseError(MutantError):
    """Raised when parsing or validating Python test syntax fails."""


@dataclass(frozen=True)
class TestFunctionInfo:
    """Metadata for a test function inside a module or test class."""

    qualname: str
    func_node: ast.FunctionDef | ast.AsyncFunctionDef
    class_name: str | None = None


@dataclass(frozen=True)
class AssertionSite:
    """An assertion site within a test function."""

    site_id: str
    func_qualname: str
    index_in_func: int
    node: ast.AST
    kind: str  # "assert_compare" or "call_assert"


def read_test_file(path: str | Path) -> bytes:
    """Read a test file securely as raw bytes.

    Applies strict checks:
    - Path must not be a symlink (lstat).
    - Path must refer to a regular file (refuses FIFOs, devices, sockets, directories).
    - File size must not exceed MAX_FILE_SIZE_BYTES.
    - Uses O_NOFOLLOW to prevent symlink following races.
    """
    resolved_str = os.fspath(path)
    try:
        st = os.lstat(resolved_str)
    except OSError as exc:
        raise ParseError(f"Cannot access file {resolved_str}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise ParseError(f"Refusing to read symlink: {resolved_str}")
    if not stat.S_ISREG(st.st_mode):
        raise ParseError(f"Refusing to read non-regular file: {resolved_str}")
    if st.st_size > MAX_FILE_SIZE_BYTES:
        raise ParseError(
            f"File size {st.st_size} exceeds cap of {MAX_FILE_SIZE_BYTES} bytes"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(resolved_str, flags)
    except OSError as exc:
        raise ParseError(f"Cannot open file {resolved_str}: {exc}") from exc

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ParseError(f"File descriptor is not a regular file: {resolved_str}")

        data = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_FILE_SIZE_BYTES:
                raise ParseError(
                    f"File content exceeds cap of {MAX_FILE_SIZE_BYTES} bytes"
                )
        return bytes(data)
    finally:
        os.close(fd)


def validate_ast_bounds(tree: ast.AST) -> None:
    """Ensure AST node count and tree depth do not exceed bounded resource caps."""
    node_count = 0
    max_depth = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]

    while stack:
        node, depth = stack.pop()
        node_count += 1
        if node_count > MAX_AST_NODES:
            raise ParseError(f"AST node count exceeds cap of {MAX_AST_NODES}")
        if depth > max_depth:
            max_depth = depth
            if max_depth > MAX_AST_DEPTH:
                raise ParseError(
                    f"AST depth {max_depth} exceeds cap of {MAX_AST_DEPTH}"
                )
        for child in ast.iter_child_nodes(node):
            stack.append((child, depth + 1))


def parse_test_bytes(data: bytes, filename: str = "<test>") -> ast.AST:
    """Parse raw bytes of a Python test file into an AST, checking bounds and UTF-8."""
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise ParseError(
            f"Data size {len(data)} exceeds cap of {MAX_FILE_SIZE_BYTES} bytes"
        )
    try:
        source_text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Source file is not valid UTF-8: {exc}") from exc
    return parse_test_source(source_text, filename=filename)


def parse_test_source(source: str, filename: str = "<test>") -> ast.AST:
    """Parse Python source text into an AST, checking bounds and syntax."""
    encoded_len = len(source.encode("utf-8"))
    if encoded_len > MAX_FILE_SIZE_BYTES:
        raise ParseError(
            f"Source text size {encoded_len} exceeds cap of {MAX_FILE_SIZE_BYTES} bytes"
        )
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, RecursionError, MemoryError) as exc:
        raise ParseError(f"Failed to parse Python syntax: {exc}") from exc

    validate_ast_bounds(tree)
    return tree


def parse_test_file(path: str | Path) -> ast.AST:
    """Read and parse a test file from disk securely."""
    data = read_test_file(path)
    return parse_test_bytes(data, filename=str(path))


def find_test_functions(tree: ast.AST) -> list[TestFunctionInfo]:
    """Find test functions at module level (def test_*) or inside class Test*."""
    test_funcs: list[TestFunctionInfo] = []

    for stmt in getattr(tree, "body", []):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name.startswith("test"):
                test_funcs.append(
                    TestFunctionInfo(qualname=stmt.name, func_node=stmt, class_name=None)
                )
        elif isinstance(stmt, ast.ClassDef) and stmt.name.startswith("Test"):
            for class_stmt in stmt.body:
                if isinstance(class_stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if class_stmt.name.startswith("test"):
                        qualname = f"{stmt.name}.{class_stmt.name}"
                        test_funcs.append(
                            TestFunctionInfo(
                                qualname=qualname,
                                func_node=class_stmt,
                                class_name=stmt.name,
                            )
                        )

    return test_funcs


def find_assertion_sites(tree: ast.AST) -> list[AssertionSite]:
    """Find all assertion sites inside test functions.

    Each assertion site receives a stable id: function qualified name plus the
    0-based index of the site within that function (e.g. 'test_foo:0').
    """
    test_funcs = find_test_functions(tree)
    sites: list[AssertionSite] = []

    for tfunc in test_funcs:
        site_idx = 0
        # Walk statements in lexical order, without descending into nested functions or classes
        stack: list[ast.AST] = list(reversed(tfunc.func_node.body))
        while stack:
            node = stack.pop()

            is_site = False
            kind = ""

            if isinstance(node, ast.Assert):
                if isinstance(node.test, ast.Compare):
                    is_site = True
                    kind = "assert_compare"
                elif (
                    isinstance(node.test, ast.UnaryOp)
                    and isinstance(node.test.op, ast.Not)
                    and isinstance(node.test.operand, ast.Compare)
                ):
                    is_site = True
                    kind = "assert_not_compare"
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute):
                    if call.func.attr in ASSERT_METHODS:
                        is_site = True
                        kind = "call_assert"
                elif isinstance(call.func, ast.Name):
                    if call.func.id in ASSERT_METHODS:
                        is_site = True
                        kind = "call_assert"

            if is_site:
                site_id = f"{tfunc.qualname}:{site_idx}"
                # Attach site_id to node for quick reference
                setattr(node, "_hermetic_site_id", site_id)
                sites.append(
                    AssertionSite(
                        site_id=site_id,
                        func_qualname=tfunc.qualname,
                        index_in_func=site_idx,
                        node=node,
                        kind=kind,
                    )
                )
                site_idx += 1
                # Do not descend into subnodes of the assertion site itself
                continue

            # Do not descend into nested scopes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            # Descend child nodes in order
            children = list(ast.iter_child_nodes(node))
            for child in reversed(children):
                stack.append(child)

    return sites


def is_side_effect_free(node: ast.AST) -> bool:
    """Determine whether an AST expression is side-effect-free (pure).

    Rule:
    Operands containing calls, awaits, yields, walrus expressions, comprehension
    side effects or attribute access on unknown objects are treated as possibly
    side-effecting and return False.

    Only literals (ast.Constant), identifiers (ast.Name in Load context), pure
    unary/binary operations, pure comparisons, pure subscripts, and container
    literals (tuples/lists/dicts/sets) composed exclusively of side-effect-free
    sub-expressions are considered side-effect-free.
    """
    for subnode in ast.walk(node):
        if isinstance(subnode, FORBIDDEN_SIDE_EFFECT_TYPES):
            return False
        # Disallow variable assignments or non-load expressions
        if isinstance(subnode, ast.Name) and not isinstance(subnode.ctx, ast.Load):
            return False

    return True


def is_literal_or_name(node: ast.AST) -> bool:
    """Check if an AST node is a literal constant or identifier name."""
    return isinstance(node, (ast.Constant, ast.Name))


def is_supported_literal(node: ast.AST) -> bool:
    """Check if an AST node is a supported literal value for mutation.

    Supported: int, float, str, bytes, bool, None, or tuple/list composed of them.
    """
    if isinstance(node, ast.Constant):
        return type(node.value) in (int, float, str, bytes, bool, type(None))
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(is_supported_literal(elt) for elt in node.elts)
    return False


def extract_literal_value(node: ast.AST) -> Any:
    """Extract Python literal value from a supported literal AST node."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Tuple):
        return tuple(extract_literal_value(elt) for elt in node.elts)
    if isinstance(node, ast.List):
        return [extract_literal_value(elt) for elt in node.elts]
    raise MutantError(f"Unsupported AST node for literal extraction: {ast.dump(node)}")


def value_to_literal_node(val: Any) -> ast.AST:
    """Convert a Python literal value into an AST node."""
    if isinstance(val, (int, float, str, bytes, bool, type(None))):
        return ast.Constant(value=val)
    if isinstance(val, tuple):
        return ast.Tuple(elts=[value_to_literal_node(x) for x in val], ctx=ast.Load())
    if isinstance(val, list):
        return ast.List(elts=[value_to_literal_node(x) for x in val], ctx=ast.Load())
    raise MutantError(f"Cannot convert value of type {type(val)} to literal AST node")


# --- Equivalent Rewrite Checks & Applications ---


def can_swap_compare_operands(site: AssertionSite) -> bool:
    """Check precondition for swapping operands of == and != in assert."""
    if site.kind != "assert_compare":
        return False
    assert_node = site.node
    if not isinstance(assert_node, ast.Assert):
        return False
    comp = assert_node.test
    if not isinstance(comp, ast.Compare):
        return False
    if len(comp.ops) != 1 or len(comp.comparators) != 1:
        return False
    op = comp.ops[0]
    if not isinstance(op, (ast.Eq, ast.NotEq)):
        return False
    return is_side_effect_free(comp.left) and is_side_effect_free(comp.comparators[0])


def apply_swap_compare_operands(tree: ast.AST, site_id: str) -> ast.AST:
    """Swap left and right operands of == or != in plain assert."""
    new_tree = copy.deepcopy(tree)
    sites = find_assertion_sites(new_tree)
    target = next((s for s in sites if s.site_id == site_id), None)
    if target is None:
        raise MutantError(f"Assertion site {site_id} not found")
    comp = target.node.test if isinstance(target.node.test, ast.Compare) else target.node.test.operand  # type: ignore[attr-defined]
    left = comp.left
    right = comp.comparators[0]
    comp.left = right
    comp.comparators[0] = left
    ast.fix_missing_locations(new_tree)
    return new_tree


def can_assert_eq_to_not_ne(site: AssertionSite) -> bool:
    """Check precondition: assert a == b to assert not (a != b).

    Applied ONLY when both operands are literals or names.
    """
    if site.kind != "assert_compare":
        return False
    assert_node = site.node
    if not isinstance(assert_node, ast.Assert):
        return False
    comp = assert_node.test
    if not isinstance(comp, ast.Compare):
        return False
    if len(comp.ops) != 1 or len(comp.comparators) != 1:
        return False
    if not isinstance(comp.ops[0], ast.Eq):
        return False
    return is_literal_or_name(comp.left) and is_literal_or_name(comp.comparators[0])


def apply_assert_eq_to_not_ne(tree: ast.AST, site_id: str) -> ast.AST:
    """Rewrite 'assert a == b' to 'assert not (a != b)'."""
    new_tree = copy.deepcopy(tree)
    sites = find_assertion_sites(new_tree)
    target = next((s for s in sites if s.site_id == site_id), None)
    if target is None:
        raise MutantError(f"Assertion site {site_id} not found")
    assert_node = target.node
    comp = assert_node.test  # type: ignore[attr-defined]
    new_test = ast.UnaryOp(
        op=ast.Not(),
        operand=ast.Compare(
            left=comp.left,
            ops=[ast.NotEq()],
            comparators=[comp.comparators[0]],
        ),
    )
    assert_node.test = new_test  # type: ignore[attr-defined]
    ast.fix_missing_locations(new_tree)
    return new_tree


def can_swap_assert_equal(site: AssertionSite) -> bool:
    """Check precondition for swapping operands of assertEqual(a, b)."""
    if site.kind != "call_assert":
        return False
    expr_node = site.node
    call = expr_node.value if isinstance(expr_node, ast.Expr) else expr_node
    if not isinstance(call, ast.Call):
        return False
    method_name = ""
    if isinstance(call.func, ast.Attribute):
        method_name = call.func.attr
    elif isinstance(call.func, ast.Name):
        method_name = call.func.id
    if method_name != "assertEqual":
        return False
    if len(call.args) < 2:
        return False
    return is_side_effect_free(call.args[0]) and is_side_effect_free(call.args[1])


def apply_swap_assert_equal(tree: ast.AST, site_id: str) -> ast.AST:
    """Rewrite self.assertEqual(a, b) to self.assertEqual(b, a)."""
    new_tree = copy.deepcopy(tree)
    sites = find_assertion_sites(new_tree)
    target = next((s for s in sites if s.site_id == site_id), None)
    if target is None:
        raise MutantError(f"Assertion site {site_id} not found")
    expr_node = target.node
    call = expr_node.value if isinstance(expr_node, ast.Expr) else expr_node
    arg0 = call.args[0]  # type: ignore[attr-defined]
    arg1 = call.args[1]  # type: ignore[attr-defined]
    call.args[0] = arg1  # type: ignore[attr-defined]
    call.args[1] = arg0  # type: ignore[attr-defined]
    ast.fix_missing_locations(new_tree)
    return new_tree


def get_renamable_locals(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.AST
) -> list[str]:
    """Find local variable names eligible for consistent renaming.

    Strict exclusions:
    - Parameters and fixtures of the test function.
    - 'self' and 'cls'.
    - Names declared global or nonlocal.
    - Names used in nested scopes (inner functions, classes, lambdas, comprehensions).
    - Names used in string annotations or type annotations.
    - Names used as attributes (x.attr).
    - Python standard built-in names.
    - Module-level defined or imported names.
    """
    excluded: set[str] = {"self", "cls"}

    # Exclude function parameters (fixtures)
    for arg in (
        func_node.args.posonlyargs
        + func_node.args.args
        + func_node.args.kwonlyargs
    ):
        excluded.add(arg.arg)
    if func_node.args.vararg:
        excluded.add(func_node.args.vararg.arg)
    if func_node.args.kwarg:
        excluded.add(func_node.args.kwarg.arg)

    # Builtins
    import builtins

    excluded.update(dir(builtins))

    # Module-level imports, functions, classes
    for stmt in getattr(tree, "body", []):
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                excluded.add(alias.asname or alias.name)
        elif isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                excluded.add(alias.asname or alias.name)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            excluded.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    excluded.add(t.id)

    # Scan inside the function for global, nonlocal, attributes, annotations, and nested scopes
    for node in ast.walk(func_node):
        if isinstance(node, ast.Global):
            excluded.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            excluded.update(node.names)
        elif isinstance(node, ast.Attribute):
            excluded.add(node.attr)
        elif isinstance(node, ast.AnnAssign):
            # Exclude names in type annotations (including string annotations)
            for sub in ast.walk(node.annotation):
                if isinstance(sub, ast.Name):
                    excluded.add(sub.id)
                elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    excluded.add(sub.value)

    # Exclude any name used in nested scopes
    for child in ast.walk(func_node):
        if child is func_node:
            continue
        if isinstance(
            child,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            for inner in ast.walk(child):
                if isinstance(inner, ast.Name):
                    excluded.add(inner.id)

    # Collect assigned local variables at function level
    candidate_locals: set[str] = set()
    for stmt in func_node.body:
        for node in ast.walk(stmt):
            if isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                # Don't inspect inside nested scopes
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                if node.id not in excluded:
                    candidate_locals.add(node.id)

    return sorted(candidate_locals)


def apply_rename_local(
    tree: ast.AST, func_qualname: str, old_name: str, new_name: str
) -> ast.AST:
    """Rename a local variable consistently throughout a test function."""
    new_tree = copy.deepcopy(tree)
    tfuncs = find_test_functions(new_tree)
    target_func = next((f for f in tfuncs if f.qualname == func_qualname), None)
    if target_func is None:
        raise MutantError(f"Test function {func_qualname} not found")

    class LocalRenamer(ast.NodeTransformer):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            return node

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
            return node

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
            return node

        def visit_Lambda(self, node: ast.Lambda) -> ast.AST:
            return node

        def visit_ListComp(self, node: ast.ListComp) -> ast.AST:
            return node

        def visit_SetComp(self, node: ast.SetComp) -> ast.AST:
            return node

        def visit_DictComp(self, node: ast.DictComp) -> ast.AST:
            return node

        def visit_GeneratorExp(self, node: ast.GeneratorExp) -> ast.AST:
            return node

        def visit_Name(self, node: ast.Name) -> ast.AST:
            if node.id == old_name:
                node.id = new_name
            return node

    renamer = LocalRenamer()
    target_func.func_node.body = [
        renamer.visit(stmt) for stmt in target_func.func_node.body
    ]
    ast.fix_missing_locations(new_tree)
    return new_tree


def apply_insert_noop(
    tree: ast.AST, func_qualname: str, noop_name: str
) -> ast.AST:
    """Insert a no-op local assignment with a derived name at the start of a test function."""
    new_tree = copy.deepcopy(tree)
    tfuncs = find_test_functions(new_tree)
    target_func = next((f for f in tfuncs if f.qualname == func_qualname), None)
    if target_func is None:
        raise MutantError(f"Test function {func_qualname} not found")

    noop_stmt = ast.Assign(
        targets=[ast.Name(id=noop_name, ctx=ast.Store())],
        value=ast.Constant(value=None),
    )
    if target_func.func_node.body:
        ast.copy_location(noop_stmt, target_func.func_node.body[0])
    else:
        ast.copy_location(noop_stmt, target_func.func_node)
    ast.fix_missing_locations(noop_stmt)
    target_func.func_node.body.insert(0, noop_stmt)
    ast.fix_missing_locations(new_tree)
    return new_tree


# --- Mutant Rewrites ---


def can_mutate_site(site: AssertionSite) -> bool:
    """Check if an assertion site has a literal expected operand eligible for mutation."""
    node = site.node
    if site.kind in ("assert_compare", "assert_not_compare") and isinstance(node, ast.Assert):
        comp = (
            node.test
            if isinstance(node.test, ast.Compare)
            else node.test.operand  # type: ignore[attr-defined]
        )
        if isinstance(comp, ast.Compare) and len(comp.ops) == 1 and len(comp.comparators) == 1:
            return is_supported_literal(comp.comparators[0]) or is_supported_literal(
                comp.left
            )
    elif site.kind == "call_assert":
        call = node.value if isinstance(node, ast.Expr) else node
        if isinstance(call, ast.Call):
            attr_name = ""
            if isinstance(call.func, ast.Attribute):
                attr_name = call.func.attr
            elif isinstance(call.func, ast.Name):
                attr_name = call.func.id

            if attr_name in ("assertEqual", "assertIs"):
                return (
                    len(call.args) >= 2
                    and (
                        is_supported_literal(call.args[1])
                        or is_supported_literal(call.args[0])
                    )
                )
            if attr_name in ("assertTrue", "assertFalse"):
                return len(call.args) >= 1 and is_supported_literal(call.args[0])
            if attr_name == "assertIn":
                return (
                    len(call.args) >= 2
                    and (
                        is_supported_literal(call.args[1])
                        or is_supported_literal(call.args[0])
                    )
                )

    return False


def mutate_literal_value(val: Any, seed: str, site_id: str) -> Any:
    """Replace a literal value with a deterministic third value differing from the original."""
    h = hashlib.sha256(f"{seed}:{site_id}:{val!r}".encode("utf-8")).digest()

    if isinstance(val, bool):
        # bool is an int subclass; check bool first: assertion negated
        return not val
    if isinstance(val, int):
        # ints: original + nonzero offset
        offset = (int.from_bytes(h[:4], "big") % 1000) + 1
        return val + offset
    if isinstance(val, str):
        # str: original with derived suffix
        suffix = f"_mut_{h[:4].hex()}"
        return val + suffix
    if isinstance(val, bytes):
        # bytes: original with derived suffix
        suffix = f"_mut_{h[:4].hex()}".encode("ascii")
        return val + suffix
    if val is None:
        # None: a sentinel string
        return f"__HERMETIC_SENTINEL_{h[:4].hex()}__"
    if isinstance(val, tuple):
        if not val:
            return ((int.from_bytes(h[:4], "big") % 1000) + 1,)
        return tuple(
            mutate_literal_value(x, seed, f"{site_id}:{idx}")
            for idx, x in enumerate(val)
        )
    if isinstance(val, list):
        if not val:
            return [(int.from_bytes(h[:4], "big") % 1000) + 1]
        return [
            mutate_literal_value(x, seed, f"{site_id}:{idx}")
            for idx, x in enumerate(val)
        ]

    raise MutantError(f"Unsupported literal type for mutation: {type(val)}")


def apply_mutant_rewrite(
    tree: ast.AST, site_id: str, seed: str
) -> tuple[ast.AST, str]:
    """Mutate exactly one assertion site's expected literal value.

    Returns the new mutated AST and the rewrite description.
    """
    new_tree = copy.deepcopy(tree)
    sites = find_assertion_sites(new_tree)
    target = next((s for s in sites if s.site_id == site_id), None)
    if target is None:
        raise MutantError(f"Assertion site {site_id} not found")

    node = target.node
    if target.kind in ("assert_compare", "assert_not_compare") and isinstance(node, ast.Assert):
        comp = (
            node.test
            if isinstance(node.test, ast.Compare)
            else node.test.operand  # type: ignore[attr-defined]
        )
        if not isinstance(comp, ast.Compare):
            raise MutantError(f"Site {site_id} is not an assert compare")
        # Standard convention: right side is expected
        if is_supported_literal(comp.comparators[0]):
            orig_val = extract_literal_value(comp.comparators[0])
            new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
            comp.comparators[0] = value_to_literal_node(new_val)
        elif is_supported_literal(comp.left):
            orig_val = extract_literal_value(comp.left)
            new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
            comp.left = value_to_literal_node(new_val)
        else:
            raise MutantError(f"Site {site_id} has no literal expected operand")

    elif target.kind == "call_assert":
        expr_node = node
        call = expr_node.value if isinstance(expr_node, ast.Expr) else expr_node
        if not isinstance(call, ast.Call):
            raise MutantError(f"Site {site_id} is not a call")
        attr_name = ""
        if isinstance(call.func, ast.Attribute):
            attr_name = call.func.attr
        elif isinstance(call.func, ast.Name):
            attr_name = call.func.id

        if attr_name in ("assertEqual", "assertIs"):
            if len(call.args) >= 2 and is_supported_literal(call.args[1]):
                orig_val = extract_literal_value(call.args[1])
                new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
                call.args[1] = value_to_literal_node(new_val)
            elif len(call.args) >= 1 and is_supported_literal(call.args[0]):
                orig_val = extract_literal_value(call.args[0])
                new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
                call.args[0] = value_to_literal_node(new_val)
            else:
                raise MutantError(f"Site {site_id} has no literal operand")
        elif attr_name in ("assertTrue", "assertFalse"):
            if len(call.args) >= 1 and is_supported_literal(call.args[0]):
                orig_val = extract_literal_value(call.args[0])
                new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
                call.args[0] = value_to_literal_node(new_val)
            else:
                raise MutantError(f"Site {site_id} has no literal operand")
        elif attr_name == "assertIn":
            if len(call.args) >= 2 and is_supported_literal(call.args[1]):
                orig_val = extract_literal_value(call.args[1])
                new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
                call.args[1] = value_to_literal_node(new_val)
            elif len(call.args) >= 1 and is_supported_literal(call.args[0]):
                orig_val = extract_literal_value(call.args[0])
                new_val = mutate_literal_value(orig_val, seed=seed, site_id=site_id)
                call.args[0] = value_to_literal_node(new_val)
            else:
                raise MutantError(f"Site {site_id} has no literal operand")
        else:
            raise MutantError(f"Unsupported assertion method: {attr_name}")
    else:
        raise MutantError(f"Unsupported site kind: {target.kind}")

    ast.fix_missing_locations(new_tree)
    return new_tree, f"mutate_literal:{site_id}"
