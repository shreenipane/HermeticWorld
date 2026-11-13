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
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# Resource bounds to protect against hostile or runaway inputs
MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2 MiB
MAX_AST_DEPTH: int = 200
MAX_AST_NODES: int = 50_000
# Read chunk size for test files
READ_CHUNK_BYTES: int = 65536
# Bounded number of re-derivations tried for an in-container mutant whose new
# elements must not collide with any original element
MAX_MUTATION_SALTS: int = 16

# Calls that expose or evaluate a function's local namespace by name. A test
# function that uses any of them is never renamed and gets no inserted no-op,
# because either rewrite would change what the call observes.
DYNAMIC_SCOPE_CALLS: frozenset[str] = frozenset(
    {"locals", "vars", "dir", "eval", "exec"}
)
DYNAMIC_SCOPE_ATTRS: frozenset[str] = frozenset({"f_locals"})

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

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
    # Regular-file check before any open, so a FIFO or device is never opened
    if not stat.S_ISREG(st.st_mode):
        raise ParseError(f"Refusing to read non-regular file: {resolved_str}")
    if st.st_size > MAX_FILE_SIZE_BYTES:
        raise ParseError(
            f"File size {st.st_size} exceeds cap of {MAX_FILE_SIZE_BYTES} bytes"
        )

    # O_NONBLOCK: if the path is swapped for a FIFO after lstat, open must not block
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
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
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise ParseError(f"File changed between check and open: {resolved_str}")

        data = bytearray()
        while True:
            chunk = os.read(fd, READ_CHUNK_BYTES)
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
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise ParseError(f"Failed to parse Python syntax: {exc}") from exc

    validate_ast_bounds(tree)
    return tree


def parse_test_file(path: str | Path) -> ast.AST:
    """Read and parse a test file from disk securely."""
    data = read_test_file(path)
    return parse_test_bytes(data, filename=str(path))


_SCOPE_NODES: tuple[type[ast.AST], ...] = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
)


def _binding_names(node: ast.AST) -> list[str]:
    """Names a single node binds in its scope (not counting nested scopes' bodies)."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return [node.id]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.alias):
        return [(node.asname or node.name).split(".")[0]]
    if isinstance(node, ast.ExceptHandler) and node.name:
        return [node.name]
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        return [node.name]
    if isinstance(node, ast.MatchMapping) and node.rest:
        return [node.rest]
    return []


def _scope_binding_counts(body: Sequence[ast.stmt]) -> dict[str, int]:
    """Count how often each name is bound directly in a scope body.

    Nested function, class and lambda bodies are not entered (their own name is
    counted). A test whose name is bound more than once is shadowed or replaced
    at run time, so a rewrite of it could target dead code.
    """
    counts: dict[str, int] = {}
    stack: list[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        for name in _binding_names(node):
            counts[name] = counts.get(name, 0) + 1
        if isinstance(node, _SCOPE_NODES):
            continue
        stack.extend(ast.iter_child_nodes(node))
    return counts


def find_test_functions(tree: ast.AST) -> list[TestFunctionInfo]:
    """Find test functions at module level (def test_*) or inside class Test*.

    A function or class whose name is bound more than once in its scope
    (redefinition, reassignment, deletion) is skipped entirely: its site ids
    would be ambiguous and the definition that runs is not knowable statically.
    """
    test_funcs: list[TestFunctionInfo] = []
    module_body = getattr(tree, "body", [])
    module_counts = _scope_binding_counts(module_body)

    for stmt in module_body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name.startswith("test") and module_counts.get(stmt.name) == 1:
                test_funcs.append(
                    TestFunctionInfo(qualname=stmt.name, func_node=stmt, class_name=None)
                )
        elif (
            isinstance(stmt, ast.ClassDef)
            and stmt.name.startswith("Test")
            and module_counts.get(stmt.name) == 1
        ):
            class_counts = _scope_binding_counts(stmt.body)
            for class_stmt in stmt.body:
                if isinstance(class_stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if (
                        class_stmt.name.startswith("test")
                        and class_counts.get(class_stmt.name) == 1
                    ):
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
                # Only self.<assertMethod>(...): an unknown object's or bare
                # function's assert method has unknown meaning
                call = node.value
                if (
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "self"
                    and call.func.attr in ASSERT_METHODS
                ):
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


def apply_swap_compare_operands(
    tree: ast.AST, site_id: str, *, in_place: bool = False
) -> ast.AST:
    """Swap left and right operands of == or != in plain assert."""
    # in_place: the caller owns tree, and calls ast.fix_missing_locations itself
    new_tree = tree if in_place else copy.deepcopy(tree)
    sites = find_assertion_sites(new_tree)
    target = next((s for s in sites if s.site_id == site_id), None)
    if target is None:
        raise MutantError(f"Assertion site {site_id} not found")
    comp = target.node.test if isinstance(target.node.test, ast.Compare) else target.node.test.operand  # type: ignore[attr-defined]
    left = comp.left
    right = comp.comparators[0]
    comp.left = right
    comp.comparators[0] = left
    if not in_place:
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


def apply_assert_eq_to_not_ne(
    tree: ast.AST, site_id: str, *, in_place: bool = False
) -> ast.AST:
    """Rewrite 'assert a == b' to 'assert not (a != b)'."""
    # in_place: the caller owns tree, and calls ast.fix_missing_locations itself
    new_tree = tree if in_place else copy.deepcopy(tree)
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
    if not in_place:
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
    # A starred argument hides which positions hold first, second and msg
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return False
    return is_side_effect_free(call.args[0]) and is_side_effect_free(call.args[1])


def apply_swap_assert_equal(
    tree: ast.AST, site_id: str, *, in_place: bool = False
) -> ast.AST:
    """Rewrite self.assertEqual(a, b) to self.assertEqual(b, a)."""
    # in_place: the caller owns tree, and calls ast.fix_missing_locations itself
    new_tree = tree if in_place else copy.deepcopy(tree)
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
    if not in_place:
        ast.fix_missing_locations(new_tree)
    return new_tree


def uses_dynamic_scope(func_node: ast.AST) -> bool:
    """True if the function may observe its locals by name.

    Detected: calls to locals(), vars(), dir(), eval(), exec() by bare name,
    and any access to an attribute named f_locals (frame inspection).
    """
    for node in ast.walk(func_node):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in DYNAMIC_SCOPE_CALLS
        ):
            return True
        if isinstance(node, ast.Attribute) and node.attr in DYNAMIC_SCOPE_ATTRS:
            return True
    return False


def collect_identifiers(tree: ast.AST) -> set[str]:
    """Every identifier spelled anywhere in the tree (names, args, attributes, aliases)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        names.update(_binding_names(node))
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
    return names


def can_insert_noop(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A no-op local is safe unless the function observes its locals by name."""
    return not uses_dynamic_scope(func_node)


def module_level_names(tree: ast.AST) -> frozenset[str]:
    """Names imported, defined or assigned by plain assignment at module level."""
    names: set[str] = set()
    for stmt in getattr(tree, "body", []):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                names.add(alias.asname or alias.name)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return frozenset(names)


def get_renamable_locals(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.AST,
    module_names: frozenset[str] | None = None,
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

    # A function that inspects or evaluates its local namespace by name is never renamed
    if uses_dynamic_scope(func_node):
        return []

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

    # Builtin names are not excluded: a name assigned in the function is local
    # throughout it, so renaming every occurrence is consistent. Excluding them
    # would make the output depend on the interpreter version.

    # Module-level imports, functions, classes (module_names: precomputed cache)
    excluded.update(module_level_names(tree) if module_names is None else module_names)

    # Scan inside the function for global, nonlocal, attributes, annotations, and nested scopes
    for node in ast.walk(func_node):
        if isinstance(node, ast.Global):
            excluded.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            excluded.update(node.names)
        elif isinstance(node, ast.Attribute):
            excluded.add(node.attr)
        elif isinstance(node, ast.AnnAssign):
            # Exclude names in type annotations (including every identifier
            # inside string annotations such as 'list[Thing]')
            for sub in ast.walk(node.annotation):
                if isinstance(sub, ast.Name):
                    excluded.add(sub.id)
                elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    excluded.update(_IDENTIFIER_RE.findall(sub.value))
        elif not isinstance(node, ast.Name) and node is not func_node:
            # Names bound without an ast.Name node (except ... as e, match
            # captures, imports, nested def/class names) are never renamed,
            # since the rename only rewrites ast.Name nodes
            excluded.update(_binding_names(node))

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
    tree: ast.AST,
    func_qualname: str,
    old_name: str,
    new_name: str,
    *,
    in_place: bool = False,
    taken_names: set[str] | None = None,
) -> ast.AST:
    """Rename a local variable consistently throughout a test function."""
    # in_place: the caller owns tree, and calls ast.fix_missing_locations itself
    new_tree = tree if in_place else copy.deepcopy(tree)
    tfuncs = find_test_functions(new_tree)
    target_func = next((f for f in tfuncs if f.qualname == func_qualname), None)
    if target_func is None:
        raise MutantError(f"Test function {func_qualname} not found")
    taken = collect_identifiers(new_tree) if taken_names is None else taken_names
    if new_name in taken:
        raise MutantError(f"Rename target {new_name} already used in module")
    if old_name not in get_renamable_locals(target_func.func_node, new_tree):
        raise MutantError(f"Name {old_name} is not renamable in {func_qualname}")

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
    if not in_place:
        ast.fix_missing_locations(new_tree)
    return new_tree


def apply_insert_noop(
    tree: ast.AST,
    func_qualname: str,
    noop_name: str,
    *,
    in_place: bool = False,
    taken_names: set[str] | None = None,
) -> ast.AST:
    """Insert a no-op local assignment with a derived name at the start of a test function.

    The assignment goes after the docstring, if any, so __doc__ is unchanged.
    """
    # in_place: the caller owns tree, and calls ast.fix_missing_locations itself
    new_tree = tree if in_place else copy.deepcopy(tree)
    tfuncs = find_test_functions(new_tree)
    target_func = next((f for f in tfuncs if f.qualname == func_qualname), None)
    if target_func is None:
        raise MutantError(f"Test function {func_qualname} not found")
    if not can_insert_noop(target_func.func_node):
        raise MutantError(f"Test function {func_qualname} observes its locals")
    taken = collect_identifiers(new_tree) if taken_names is None else taken_names
    if noop_name in taken:
        raise MutantError(f"No-op name {noop_name} already used in module")

    noop_stmt = ast.Assign(
        targets=[ast.Name(id=noop_name, ctx=ast.Store())],
        value=ast.Constant(value=None),
    )
    if target_func.func_node.body:
        ast.copy_location(noop_stmt, target_func.func_node.body[0])
    else:
        ast.copy_location(noop_stmt, target_func.func_node)
    ast.fix_missing_locations(noop_stmt)
    body = target_func.func_node.body
    insert_at = 0
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        insert_at = 1
    body.insert(insert_at, noop_stmt)
    if not in_place:
        ast.fix_missing_locations(new_tree)
    return new_tree


# --- Mutant Rewrites ---
#
# A mutant must make its assertion fail whenever the original passes. Rules:
# - compare sites: `a == L`, `a is L`, `not (a != L)`, `not (a is not L)` mutate
#   the literal L (right side preferred); for `is`, None becomes a bool. Given a == L, a cannot equal a value
#   L' != L, and given a is L, a cannot be a distinct object L'.
# - membership sites: `a in C`, `not (a not in C)`, `assertIn(a, C)` only when C
#   is a tuple/list literal; every element is mutated and no new element may
#   equal any original element (a equals some original element, so it then
#   equals no new one).
# - assertEqual/assertIs: like == and is.
# - assertTrue/assertFalse: only a literal whose truth value the mutation flips
#   (a bool, or a falsy literal, which always mutates to a truthy value).
# - anything else (!=, <, `in` on strings, starred arguments, ...) is ineligible,
#   because the mutated assertion could still pass.


def _call_method_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def _compare_mutation_mode(node: ast.Assert) -> tuple[ast.Compare, str] | None:
    """Return the compare node and its mutation mode ('eq', 'is' or 'in'), or None."""
    test = node.test
    negated = False
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        test = test.operand
        negated = True
    if not isinstance(test, ast.Compare):
        return None
    if len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    op = test.ops[0]
    if negated:
        modes = {ast.NotEq: "eq", ast.IsNot: "is", ast.NotIn: "in"}
    else:
        modes = {ast.Eq: "eq", ast.Is: "is", ast.In: "in"}
    mode = modes.get(type(op))
    if mode is None:
        return None
    return test, mode


def _is_literal_container(node: ast.AST) -> bool:
    return isinstance(node, (ast.Tuple, ast.List)) and is_supported_literal(node)


def _is_flippable_truth_literal(node: ast.AST) -> bool:
    if not is_supported_literal(node):
        return False
    val = extract_literal_value(node)
    return isinstance(val, bool) or not val


def can_mutate_site(site: AssertionSite) -> bool:
    """Check if a site has a literal operand whose mutation must make it fail."""
    node = site.node
    if site.kind in ("assert_compare", "assert_not_compare") and isinstance(node, ast.Assert):
        found = _compare_mutation_mode(node)
        if found is None:
            return False
        comp, mode = found
        if mode == "in":
            return _is_literal_container(comp.comparators[0])
        return is_supported_literal(comp.comparators[0]) or is_supported_literal(comp.left)
    if site.kind == "call_assert":
        call = node.value if isinstance(node, ast.Expr) else node
        if not isinstance(call, ast.Call):
            return False
        if any(isinstance(arg, ast.Starred) for arg in call.args):
            return False
        attr_name = _call_method_name(call)
        if attr_name in ("assertEqual", "assertIs"):
            return len(call.args) >= 2 and (
                is_supported_literal(call.args[1]) or is_supported_literal(call.args[0])
            )
        if attr_name in ("assertTrue", "assertFalse"):
            return len(call.args) >= 1 and _is_flippable_truth_literal(call.args[0])
        if attr_name == "assertIn":
            return len(call.args) >= 2 and _is_literal_container(call.args[1])
    return False


def mutate_literal_value(val: Any, seed: str, site_id: str) -> Any:
    """Replace a literal value with a deterministic third value differing from the original.

    Derived values carry no fixed marker text, so a mutant cannot be told
    apart from an equivalent by searching for a constant token.
    """
    h = hashlib.sha256(f"{seed}:{site_id}:{val!r}".encode("utf-8")).digest()
    offset = (int.from_bytes(h[:4], "big") % 1000) + 1

    if isinstance(val, bool):
        # bool is an int subclass; check bool first: assertion negated
        return not val
    if isinstance(val, int):
        # ints: original + nonzero offset
        return val + offset
    if isinstance(val, float):
        # floats: original + nonzero offset, unless that leaves the value
        # unchanged (inf, nan, or magnitudes where the offset is below precision)
        candidate = val + float(offset)
        if not math.isfinite(val) or candidate == val:
            candidate = float(offset)
        return candidate
    if isinstance(val, str):
        # str: original with derived suffix
        return val + h[4:8].hex()
    if isinstance(val, bytes):
        # bytes: original with derived suffix
        return val + h[4:8].hex().encode("ascii")
    if val is None:
        # None: a derived sentinel string
        return h[4:10].hex()
    if isinstance(val, tuple):
        if not val:
            return (offset,)
        return tuple(
            mutate_literal_value(x, seed, f"{site_id}:{idx}")
            for idx, x in enumerate(val)
        )
    if isinstance(val, list):
        if not val:
            return [offset]
        return [
            mutate_literal_value(x, seed, f"{site_id}:{idx}")
            for idx, x in enumerate(val)
        ]

    raise MutantError(f"Unsupported literal type for mutation: {type(val)}")


def _mutate_node(node: ast.AST, seed: str, site_id: str) -> ast.AST:
    orig_val = extract_literal_value(node)
    return value_to_literal_node(mutate_literal_value(orig_val, seed=seed, site_id=site_id))


def _mutate_identity_node(node: ast.AST, seed: str, site_id: str) -> ast.AST:
    """Mutate the literal of an `is` compare.

    `x is None` becomes `x is True` or `x is False` (derived from the seed)
    rather than `x is '<str>'`: comparing identity with a str, bytes or number
    literal makes the compiler warn, and that warning would mark the mutant.
    """
    if isinstance(node, ast.Constant) and node.value is None:
        h = hashlib.sha256(f"{seed}:{site_id}:is-none".encode("utf-8")).digest()
        return ast.Constant(value=bool(h[0] & 1))
    return _mutate_node(node, seed, site_id)


def _mutate_container_node(node: ast.AST, seed: str, site_id: str) -> ast.AST:
    """Mutate a membership container so that no new element equals an original one."""
    orig_val = extract_literal_value(node)
    for salt in range(MAX_MUTATION_SALTS):
        salted = seed if salt == 0 else f"{seed}:in:{salt}"
        new_val = mutate_literal_value(orig_val, seed=salted, site_id=site_id)
        if not any(new == old for new in new_val for old in orig_val):
            return value_to_literal_node(new_val)
    raise MutantError(f"Site {site_id}: no collision-free container mutation")


def apply_mutant_rewrite(
    tree: ast.AST, site_id: str, seed: str, *, in_place: bool = False
) -> tuple[ast.AST, str]:
    """Mutate exactly one assertion site's expected literal value.

    Returns the new mutated AST and the rewrite description. Raises MutantError
    for a site that can_mutate_site rejects.
    """
    # in_place: the caller owns tree, and calls ast.fix_missing_locations itself
    new_tree = tree if in_place else copy.deepcopy(tree)
    sites = find_assertion_sites(new_tree)
    target = next((s for s in sites if s.site_id == site_id), None)
    if target is None:
        raise MutantError(f"Assertion site {site_id} not found")
    if not can_mutate_site(target):
        raise MutantError(f"Site {site_id} is not eligible for mutation")

    node = target.node
    if target.kind in ("assert_compare", "assert_not_compare") and isinstance(node, ast.Assert):
        found = _compare_mutation_mode(node)
        if found is None:
            raise MutantError(f"Site {site_id} is not a mutable compare")
        comp, mode = found
        mutate = _mutate_identity_node if mode == "is" else _mutate_node
        if mode == "in":
            comp.comparators[0] = _mutate_container_node(comp.comparators[0], seed, site_id)
        elif is_supported_literal(comp.comparators[0]):
            # Standard convention: right side is expected
            comp.comparators[0] = mutate(comp.comparators[0], seed, site_id)
        else:
            comp.left = mutate(comp.left, seed, site_id)
    elif target.kind == "call_assert":
        call = node.value if isinstance(node, ast.Expr) else node
        if not isinstance(call, ast.Call):
            raise MutantError(f"Site {site_id} is not a call")
        attr_name = _call_method_name(call)
        if attr_name in ("assertEqual", "assertIs"):
            if is_supported_literal(call.args[1]):
                call.args[1] = _mutate_node(call.args[1], seed, site_id)
            else:
                call.args[0] = _mutate_node(call.args[0], seed, site_id)
        elif attr_name in ("assertTrue", "assertFalse"):
            call.args[0] = _mutate_node(call.args[0], seed, site_id)
        elif attr_name == "assertIn":
            call.args[1] = _mutate_container_node(call.args[1], seed, site_id)
        else:
            raise MutantError(f"Unsupported assertion method: {attr_name}")
    else:
        raise MutantError(f"Unsupported site kind: {target.kind}")

    if not in_place:
        ast.fix_missing_locations(new_tree)
    return new_tree, f"mutate_literal:{site_id}"
