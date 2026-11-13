"""Flow-sensitive proven-dependency data-flow analysis for base-failing assertion eligibility."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.limits import (
    MAX_EXPR_DEPTH,
    MAX_IDENTIFIER_LENGTH,
    MAX_LINE_NUMBER,
    MAX_LOOP_FIXPOINT_ITERATIONS,
    MAX_REACHED_ARGS,
    MAX_STATEMENTS_PER_FUNCTION,
    MAX_TAINTED_NAMES,
)
from hermetic_assert_flow.parse import parse_source
from hermetic_assert_flow.sites import (
    AssertionSite,
    extract_checked_exprs_from_call,
    extract_sites_from_function,
    find_test_function_node,
    is_supported_self_assert_call,
)


@dataclass(frozen=True)
class FlowResult:
    """Result of eligibility analysis for a single test function."""

    eligible: list[str]
    gave_up: bool
    reason: str | None


@dataclass
class _PathState:
    """Mutable per-path taint state during statement traversal."""

    tainted: set[str]
    started: bool
    terminated: bool = False
    control: str | None = None

    def clone(self) -> _PathState:
        return _PathState(
            tainted=set(self.tainted),
            started=self.started,
            terminated=self.terminated,
            control=self.control,
        )


def _check_give_up(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return a deterministic give-up reason if fn_node contains unsupported scope constructs."""
    stack: list[ast.AST] = list(reversed(fn_node.body))
    visited = 0

    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_STATEMENTS_PER_FUNCTION * 50:
            return "function AST complexity limit exceeded"

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return "nested function definition is unsupported"
        if isinstance(node, ast.ClassDef):
            return "nested class definition is unsupported"
        if isinstance(node, ast.Lambda):
            return "lambda expression is unsupported"
        if isinstance(node, ast.Global):
            return "global statement is unsupported"
        if isinstance(node, ast.Nonlocal):
            return "nonlocal statement is unsupported"

        children = list(ast.iter_child_nodes(node))
        for child in reversed(children):
            stack.append(child)

    return None


def _find_raising_statement(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    raising_line: int,
) -> ast.stmt | None:
    """Find the innermost statement inside fn_node covering raising_line."""
    fn_start = fn_node.lineno
    fn_end = fn_node.end_lineno or fn_start
    if raising_line < fn_start or raising_line > fn_end:
        raise FlowError(
            "raising_line is outside the target test function",
            code="INVALID_RAISING_LINE",
        )

    candidates: list[ast.stmt] = []
    stmt_count = 0

    def visit(stmts: list[ast.stmt]) -> None:
        nonlocal stmt_count
        for stmt in stmts:
            stmt_count += 1
            if stmt_count > MAX_STATEMENTS_PER_FUNCTION:
                raise FlowError(
                    f"Statement count exceeds cap of {MAX_STATEMENTS_PER_FUNCTION}",
                    code="TOO_MANY_STATEMENTS",
                )
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            start = stmt.lineno
            end = stmt.end_lineno or start
            if start <= raising_line <= end:
                candidates.append(stmt)

            if isinstance(stmt, ast.If):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, ast.While):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                visit(stmt.body)
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                visit(stmt.body)
                for handler in stmt.handlers:
                    visit(handler.body)
                visit(stmt.orelse)
                visit(stmt.finalbody)
            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    visit(case.body)

    visit(fn_node.body)

    if not candidates:
        raise FlowError(
            "No statement found at raising_line inside target function",
            code="RAISING_STATEMENT_NOT_FOUND",
        )

    # Prefer the innermost (smallest line span) matching statement.
    candidates.sort(
        key=lambda s: (
            (s.end_lineno or s.lineno) - s.lineno,
            -s.lineno,
            -s.col_offset,
        )
    )
    first = candidates[0]
    # Line-only traceback data cannot distinguish adjacent statements on one line.
    peers = [item for item in candidates if item.lineno == first.lineno
             and (item.end_lineno or item.lineno) == (first.end_lineno or first.lineno)]
    if len(peers) != 1:
        return None
    return first


def _field_key(expr: ast.expr) -> str | None:
    """Identify only exact named attributes and constant-index fields."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _field_key(expr.value)
        return None if base is None else base + "." + expr.attr
    if isinstance(expr, ast.Subscript):
        value = expr.slice
        if isinstance(value, ast.Constant):
            constant = value.value
        elif (isinstance(value, ast.UnaryOp) and isinstance(value.operand, ast.Constant)
              and isinstance(value.operand.value, (int, float, complex))
              and isinstance(value.op, (ast.USub, ast.UAdd))):
            constant = -value.operand.value if isinstance(value.op, ast.USub) else +value.operand.value
        else:
            return None
        # Python dictionary keys with equal numeric values name the same field.
        if isinstance(constant, complex) and constant.imag == 0:
            constant = constant.real
        if isinstance(constant, bool) or (isinstance(constant, float) and constant.is_integer()):
            constant = int(constant)
        base = _field_key(expr.value)
        suffix = repr(constant)
        if base is not None and len(suffix) <= MAX_IDENTIFIER_LENGTH:
            return base + "[" + suffix + "]"
    return None


def _truth(expr: ast.expr) -> bool | None:
    if isinstance(expr, ast.Constant):
        return bool(expr.value)
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        return None if any(isinstance(item, ast.Starred) for item in expr.elts) else bool(expr.elts)
    if isinstance(expr, ast.Dict):
        return bool(expr.keys)
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        value = _truth(expr.operand)
        return None if value is None else not value
    return None


def _forget_fields(tainted: set[str], expr: ast.expr) -> None:
    names = {node.id for node in ast.walk(expr) if isinstance(node, ast.Name)}
    tainted.difference_update({item for item in tainted
                               if any(item.startswith(name + ".") or item.startswith(name + "[")
                                      for name in names)})


def _clear_target(tainted: set[str], name: str) -> None:
    tainted.difference_update({item for item in tainted
                               if item == name or item.startswith(name + ".")
                               or item.startswith(name + "[")})


def _add_taint(tainted: set[str], name: str) -> None:
    if name not in tainted and len(tainted) >= MAX_TAINTED_NAMES:
        raise FlowError(
            f"Tainted name count exceeds cap of {MAX_TAINTED_NAMES}",
            code="TOO_MANY_TAINTED_NAMES",
        )
    tainted.add(name)


def _eval_expr_taint(
    expr: ast.expr | None,
    tainted: set[str],
    *,
    active: bool,
    depth: int = 1,
) -> bool:
    """Evaluate whether expr reads/propagates a tainted value, updating tainted for walrus targets."""
    if expr is None:
        return False
    if depth > MAX_EXPR_DEPTH:
        raise FlowError(
            f"Expression depth exceeds cap of {MAX_EXPR_DEPTH}",
            code="EXPR_TOO_DEEP",
        )

    if isinstance(expr, ast.Name):
        return active and isinstance(expr.ctx, ast.Load) and (expr.id in tainted)

    if isinstance(expr, ast.Constant):
        return False

    if isinstance(expr, ast.NamedExpr):
        val_tainted = _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)
        if active:
            _clear_target(tainted, expr.target.id)
            if val_tainted:
                _add_taint(tainted, expr.target.id)
            else:
                tainted.discard(expr.target.id)
        return val_tainted

    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        key = _field_key(expr)
        # A dependency of a container does not prove a dependency of each field.
        return active and key is not None and key in tainted

    if isinstance(expr, ast.Slice):
        low_t = _eval_expr_taint(expr.lower, tainted, active=active, depth=depth + 1)
        up_t = _eval_expr_taint(expr.upper, tainted, active=active, depth=depth + 1)
        step_t = _eval_expr_taint(expr.step, tainted, active=active, depth=depth + 1)
        return low_t or up_t or step_t

    if isinstance(expr, ast.Call):
        func_t = _eval_expr_taint(expr.func, tainted, active=active, depth=depth + 1)
        if isinstance(expr.func, ast.Attribute):
            func_t |= _eval_expr_taint(expr.func.value, tainted, active=active, depth=depth + 1)
        args_t = False
        for arg in expr.args:
            if _eval_expr_taint(arg, tainted, active=active, depth=depth + 1):
                args_t = True
        for kw in expr.keywords:
            if _eval_expr_taint(kw.value, tainted, active=active, depth=depth + 1):
                args_t = True
        # An opaque call can mutate referenced objects. Field dependencies cannot
        # survive it unless a later explicit store establishes them again.
        if is_supported_self_assert_call(expr) is not None:
            return False  # Supported unittest assertions return None on success.
        _forget_fields(tainted, expr)
        return func_t or args_t

    if isinstance(expr, ast.UnaryOp):
        return _eval_expr_taint(expr.operand, tainted, active=active, depth=depth + 1)

    if isinstance(expr, ast.BinOp):
        left_t = _eval_expr_taint(expr.left, tainted, active=active, depth=depth + 1)
        right_t = _eval_expr_taint(expr.right, tainted, active=active, depth=depth + 1)
        return left_t or right_t

    if isinstance(expr, ast.BoolOp):
        possible: list[bool] = []
        incoming = set(tainted)
        optional = False
        for index, val in enumerate(expr.values):
            value_t = _eval_expr_taint(val, tainted, active=active, depth=depth + 1)
            truth = _truth(val)
            stops = truth is not None and (truth != isinstance(expr.op, ast.And))
            if index == len(expr.values) - 1 or stops:
                possible.append(value_t)
                break
            if truth is None:
                possible.append(value_t)
                optional = True
        if optional:
            tainted.intersection_update(incoming)
        return bool(possible) and all(possible)

    if isinstance(expr, ast.Compare):
        # Only the first comparison is guaranteed to execute in a chain.
        left_t = _eval_expr_taint(expr.left, tainted, active=active, depth=depth + 1)
        right_t = _eval_expr_taint(expr.comparators[0], tainted, active=active, depth=depth + 1)
        return left_t or right_t

    if isinstance(expr, ast.IfExp):
        _eval_expr_taint(expr.test, tainted, active=active, depth=depth + 1)
        truth = _truth(expr.test)
        if truth is not None:
            return _eval_expr_taint(expr.body if truth else expr.orelse, tainted,
                                    active=active, depth=depth + 1)
        body_state = set(tainted)
        else_state = set(tainted)
        body_t = _eval_expr_taint(expr.body, body_state, active=active, depth=depth + 1)
        else_t = _eval_expr_taint(expr.orelse, else_state, active=active, depth=depth + 1)
        tainted.clear()
        tainted.update(body_state & else_state)
        return body_t and else_t

    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        result = False
        for elt in expr.elts:
            if _eval_expr_taint(elt, tainted, active=active, depth=depth + 1):
                result = True
        return result

    if isinstance(expr, ast.Dict):
        result = False
        for k, v in zip(expr.keys, expr.values):
            if _eval_expr_taint(k, tainted, active=active, depth=depth + 1):
                result = True
            if _eval_expr_taint(v, tainted, active=active, depth=depth + 1):
                result = True
        return result

    if isinstance(expr, ast.Starred):
        return _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)

    if isinstance(expr, ast.JoinedStr):
        result = False
        for val in expr.values:
            if _eval_expr_taint(val, tainted, active=active, depth=depth + 1):
                result = True
        return result

    if isinstance(expr, ast.FormattedValue):
        val_t = _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)
        fmt_t = _eval_expr_taint(expr.format_spec, tainted, active=active, depth=depth + 1)
        return val_t or fmt_t

    if isinstance(expr, ast.Await):
        return _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)

    if isinstance(expr, (ast.Yield, ast.YieldFrom)):
        return _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)

    if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        comp_tainted = set(tainted)
        any_gen_tainted = False
        for gen in expr.generators:
            iter_t = _eval_expr_taint(gen.iter, comp_tainted, active=active, depth=depth + 1)
            if _truth(gen.iter) is False:
                return False
            if active:
                _assign_target(gen.target, iter_t, comp_tainted, rhs_expr=None, depth=depth + 1)
            for cond in gen.ifs:
                if _truth(cond) is False:
                    return False
                if _eval_expr_taint(cond, comp_tainted, active=active, depth=depth + 1):
                    any_gen_tainted = True
        elt_t = _eval_expr_taint(expr.elt, comp_tainted, active=active, depth=depth + 1)
        return elt_t or any_gen_tainted

    if isinstance(expr, ast.DictComp):
        comp_tainted = set(tainted)
        any_gen_tainted = False
        for gen in expr.generators:
            iter_t = _eval_expr_taint(gen.iter, comp_tainted, active=active, depth=depth + 1)
            if _truth(gen.iter) is False:
                return False
            if active:
                _assign_target(gen.target, iter_t, comp_tainted, rhs_expr=None, depth=depth + 1)
            for cond in gen.ifs:
                if _truth(cond) is False:
                    return False
                if _eval_expr_taint(cond, comp_tainted, active=active, depth=depth + 1):
                    any_gen_tainted = True
        key_t = _eval_expr_taint(expr.key, comp_tainted, active=active, depth=depth + 1)
        val_t = _eval_expr_taint(expr.value, comp_tainted, active=active, depth=depth + 1)
        return key_t or val_t or any_gen_tainted

    # Fallback for any other expression node: inspect children in source order.
    result = False
    for child in ast.iter_child_nodes(expr):
        if isinstance(child, ast.expr):
            if _eval_expr_taint(child, tainted, active=active, depth=depth + 1):
                result = True
    return result


def _rhs_dependencies(expr: ast.expr, tainted: set[str], active: bool) -> dict[int, bool]:
    values: dict[int, bool] = {}
    def evaluate(node: ast.expr) -> bool:
        if isinstance(node, (ast.Tuple, ast.List)):
            dependencies = [evaluate(item) for item in node.elts]
            dependency = any(dependencies)
        else:
            dependency = _eval_expr_taint(node, tainted, active=active)
        values[id(node)] = dependency
        return dependency
    evaluate(expr)
    return values


def _assign_target(
    target: ast.expr,
    rhs_tainted: bool,
    tainted: set[str],
    *,
    rhs_expr: ast.expr | None = None,
    depth: int = 1,
    rhs_state: set[str] | None = None,
    rhs_values: dict[int, bool] | None = None,
) -> None:
    """Apply assignment taint semantics to a store target."""
    if depth > MAX_EXPR_DEPTH:
        raise FlowError(
            f"Assignment target depth exceeds cap of {MAX_EXPR_DEPTH}",
            code="EXPR_TOO_DEEP",
        )

    if rhs_state is None:
        rhs_state = set(tainted)

    if isinstance(target, ast.Name):
        _clear_target(tainted, target.id)
        if rhs_tainted:
            _add_taint(tainted, target.id)
        else:
            tainted.discard(target.id)
        return

    if isinstance(target, ast.Starred):
        _assign_target(target.value, rhs_tainted, tainted, rhs_expr=None, depth=depth + 1)
        return

    if isinstance(target, (ast.Tuple, ast.List)):
        # Element-wise propagation when rhs_expr is a matching literal Tuple/List without Starred.
        if (
            isinstance(rhs_expr, (ast.Tuple, ast.List))
            and len(rhs_expr.elts) == len(target.elts)
            and not any(isinstance(t, ast.Starred) for t in target.elts)
            and not any(isinstance(e, ast.Starred) for e in rhs_expr.elts)
        ):
            for sub_target, sub_rhs in zip(target.elts, rhs_expr.elts):
                sub_tainted = (rhs_values.get(id(sub_rhs), False) if rhs_values is not None
                               else _eval_expr_taint(sub_rhs, set(rhs_state), active=True, depth=depth + 1))
                _assign_target(
                    sub_target,
                    sub_tainted,
                    tainted,
                    rhs_expr=sub_rhs,
                    depth=depth + 1,
                    rhs_state=rhs_state,
                    rhs_values=rhs_values,
                )
            return

        for sub_target in target.elts:
            _assign_target(sub_target, rhs_tainted, tainted, rhs_expr=None, depth=depth + 1)
        return

    if isinstance(target, (ast.Attribute, ast.Subscript)):
        key = _field_key(target)
        if key is not None:
            _clear_target(tainted, key)
            if rhs_tainted:
                _add_taint(tainted, key)
        else:
            _forget_fields(tainted, target)
        return


def _apply_aug_assign(target: ast.expr, rhs_tainted: bool, tainted: set[str]) -> None:
    key = _field_key(target)
    if key is not None:
        _assign_target(target, rhs_tainted or key in tainted, tainted)
    else:
        _forget_fields(tainted, target)


def _bind_match_pattern(
    pattern: ast.pattern,
    subject_tainted: bool,
    tainted: set[str],
    depth: int = 1,
) -> None:
    """Bind pattern capture variables from a match/case statement."""
    if depth > MAX_EXPR_DEPTH:
        raise FlowError(
            f"Match pattern depth exceeds cap of {MAX_EXPR_DEPTH}",
            code="EXPR_TOO_DEEP",
        )

    if isinstance(pattern, ast.MatchAs):
        if pattern.pattern is not None:
            _bind_match_pattern(pattern.pattern, subject_tainted, tainted, depth + 1)
        if pattern.name is not None:
            _clear_target(tainted, pattern.name)
            if subject_tainted:
                _add_taint(tainted, pattern.name)
            else:
                tainted.discard(pattern.name)
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
            _clear_target(tainted, pattern.name)
            if subject_tainted:
                _add_taint(tainted, pattern.name)
            else:
                tainted.discard(pattern.name)
    elif isinstance(pattern, ast.MatchSequence):
        for p in pattern.patterns:
            _bind_match_pattern(p, subject_tainted, tainted, depth + 1)
    elif isinstance(pattern, ast.MatchMapping):
        for p in pattern.patterns:
            _bind_match_pattern(p, subject_tainted, tainted, depth + 1)
        if pattern.rest is not None:
            _clear_target(tainted, pattern.rest)
            if subject_tainted:
                _add_taint(tainted, pattern.rest)
            else:
                tainted.discard(pattern.rest)
    elif isinstance(pattern, ast.MatchClass):
        for p in pattern.patterns:
            _bind_match_pattern(p, subject_tainted, tainted, depth + 1)
        for p in pattern.kwd_patterns:
            _bind_match_pattern(p, subject_tainted, tainted, depth + 1)
    elif isinstance(pattern, ast.MatchOr):
        for p in pattern.patterns:
            _bind_match_pattern(p, subject_tainted, tainted, depth + 1)


def analyze_flow(
    source: bytes,
    function: str,
    raising_line: int,
    reached_site_ids: Sequence[str] = (),
) -> FlowResult:
    """Run flow-sensitive proven-dependency analysis for a test function starting at raising_line."""
    if isinstance(raising_line, bool) or not isinstance(raising_line, int):
        raise FlowError("raising_line must be an integer", code="INVALID_RAISING_LINE")
    if raising_line < 1 or raising_line > MAX_LINE_NUMBER:
        raise FlowError(
            f"raising_line must be between 1 and {MAX_LINE_NUMBER}",
            code="INVALID_RAISING_LINE",
        )

    if not isinstance(reached_site_ids, Sequence) or isinstance(reached_site_ids, (str, bytes)):
        raise FlowError("Invalid reached site sequence", code="INVALID_SITE_ID")
    if len(reached_site_ids) > MAX_REACHED_ARGS:
        raise FlowError(
            f"Number of reached site IDs exceeds cap of {MAX_REACHED_ARGS}",
            code="TOO_MANY_REACHED_SITES",
        )

    reached_list: list[str] = []
    for item in reached_site_ids:
        if not isinstance(item, str) or not item or len(item) > MAX_IDENTIFIER_LENGTH:
            raise FlowError("Invalid reached site ID", code="INVALID_SITE_ID")
        reached_list.append(item)

    tree = parse_source(source)
    fn_node, qualified_name = find_test_function_node(tree, function)
    sites: list[AssertionSite] = extract_sites_from_function(fn_node, qualified_name)
    known_site_ids = {s.site_id for s in sites}

    for site_id in reached_list:
        if site_id not in known_site_ids:
            raise FlowError(
                "Reached site ID does not match any assertion site in target function",
                code="UNKNOWN_SITE_ID",
            )

    reached_set = set(reached_list)
    raising_stmt = _find_raising_statement(fn_node, raising_line)
    if raising_stmt is None:
        return FlowResult([s.site_id for s in sites if s.site_id in reached_set], True,
                          "ambiguous raising statement position")
    raising_pos = (raising_stmt.lineno, raising_stmt.col_offset)
    if (isinstance(raising_stmt, (ast.Assign, ast.AnnAssign))
            and isinstance(raising_stmt.value, (ast.Tuple, ast.List, ast.Dict, ast.Set))):
        return FlowResult([site.site_id for site in sites if site.site_id in reached_set], True,
                          "raising aggregate requires an exact expression position")
    raising_expressions = [node for node in ast.iter_child_nodes(raising_stmt) if isinstance(node, ast.expr)]
    raising_walruses = [node for expr in raising_expressions for node in ast.walk(expr)
                       if isinstance(node, ast.NamedExpr)]
    if raising_walruses and (len(raising_walruses) != 1
                            or raising_walruses[0] not in raising_expressions):
        return FlowResult([site.site_id for site in sites if site.site_id in reached_set], True,
                          "ambiguous raising assignment expression")

    # Check give-up conditions (nested functions, classes, lambdas, global, nonlocal).
    give_up_reason = _check_give_up(fn_node)
    if give_up_reason is not None:
        reached_eligible = [s.site_id for s in sites if s.site_id in reached_set]
        return FlowResult(eligible=reached_eligible, gave_up=True, reason=give_up_reason)

    eligible_set: set[str] = {s.site_id for s in sites if s.site_id in reached_set}
    independent_sites: set[str] = set()
    site_by_pos: dict[tuple[int, int, str], AssertionSite] = {
        (s.lineno, s.col_offset, s.kind): s for s in sites
    }

    stmt_count = 0
    loop_stack: list[tuple[list[_PathState], list[_PathState]]] = []

    def merge_states(state: _PathState, branches: list[_PathState]) -> None:
        live = [branch for branch in branches if not branch.terminated]
        selected = live or branches
        # Paths which never reached the supplied raising statement cannot explain
        # that traceback and must not contribute a speculative dependency.
        started = [branch for branch in selected if branch.started]
        selected = started or selected
        if not selected:
            state.terminated = True
            return
        state.tainted = set.intersection(*(branch.tainted for branch in selected))
        state.started = all(branch.started for branch in selected)
        state.terminated = not live
        state.control = selected[0].control if state.terminated else None

    def check_site_node(node: ast.AST, kind: str, state: _PathState) -> None:
        key = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0), kind)
        site = site_by_pos.get(key)
        if site is None:
            return
        if site.site_id in reached_set:
            eligible_set.add(site.site_id)
            return
        # Unreached site: must be located after raising_line / raising statement.
        is_after = (site.lineno > raising_line) or (
            site.lineno == raising_line and (site.lineno, site.col_offset) > raising_pos
        )
        if not (state.started and is_after):
            return
        checked_state = set(state.tainted)
        dependencies = [_eval_expr_taint(expr, checked_state, active=True)
                        for expr in site.checked_exprs]
        dependent = any(dependencies)
        if dependent:
            eligible_set.add(site.site_id)
        else:
            independent_sites.add(site.site_id)

    def scan_expr_for_assert_calls(expr: ast.expr | None, state: _PathState) -> None:
        if expr is None:
            return
        stack: list[tuple[ast.AST, int]] = [(expr, 1)]
        calls: list[tuple[int, int, ast.Call, str]] = []
        while stack:
            node, depth = stack.pop()
            if depth > MAX_EXPR_DEPTH:
                raise FlowError(
                    f"Expression depth exceeds cap of {MAX_EXPR_DEPTH}",
                    code="EXPR_TOO_DEEP",
                )
            method = is_supported_self_assert_call(node)
            if method is not None and isinstance(node, ast.Call):
                calls.append(
                    (getattr(node, "lineno", 0), getattr(node, "col_offset", 0), node, method)
                )
            children = list(ast.iter_child_nodes(node))
            if isinstance(node, ast.BoolOp):
                children = []
                for value in node.values:
                    children.append(value)
                    truth = _truth(value)
                    if truth is not None and truth != isinstance(node.op, ast.And):
                        break
            elif isinstance(node, ast.IfExp):
                truth = _truth(node.test)
                children = [node.test]
                if truth is not False:
                    children.append(node.body)
                if truth is not True:
                    children.append(node.orelse)
            elif isinstance(node, ast.GeneratorExp):
                children = [node.generators[0].iter]
            for child in reversed(children):
                stack.append((child, depth + 1))

        calls.sort(key=lambda item: (item[0], item[1]))
        for _, _, call_node, method_name in calls:
            key = (
                getattr(call_node, "lineno", 0),
                getattr(call_node, "col_offset", 0),
                method_name,
            )
            site = site_by_pos.get(key)
            if site is None:
                continue
            if site.site_id in reached_set:
                eligible_set.add(site.site_id)
                continue
            is_after = (site.lineno > raising_line) or (
                site.lineno == raising_line and (site.lineno, site.col_offset) > raising_pos
            )
            if not (state.started and is_after):
                continue
            checked_exprs = extract_checked_exprs_from_call(call_node, method_name)
            checked_state = set(state.tainted)
            dependencies = [_eval_expr_taint(expr, checked_state, active=True)
                            for expr in checked_exprs]
            dependent = any(dependencies)
            if dependent:
                eligible_set.add(site.site_id)
            else:
                independent_sites.add(site.site_id)

    def exec_stmts(stmts: list[ast.stmt], state: _PathState) -> None:
        nonlocal stmt_count
        for stmt in stmts:
            if state.terminated:
                break
            stmt_count += 1
            if stmt_count > MAX_STATEMENTS_PER_FUNCTION:
                raise FlowError(
                    f"Statement execution count exceeds cap of {MAX_STATEMENTS_PER_FUNCTION}",
                    code="TOO_MANY_STATEMENTS",
                )
            exec_stmt(stmt, state)

    def exec_stmt(stmt: ast.stmt, state: _PathState) -> None:
        is_raising = stmt is raising_stmt
        if is_raising:
            state.started = True

        active = state.started
        walruses: list[ast.NamedExpr] = []
        if is_raising:
            expressions = [node for node in ast.iter_child_nodes(stmt) if isinstance(node, ast.expr)]
            walruses = [node for expr in expressions for node in ast.walk(expr)
                        if isinstance(node, ast.NamedExpr)]
            if len(walruses) == 1:
                _add_taint(state.tainted, walruses[0].target.id)

        if isinstance(stmt, ast.Assign):
            rhs_values = _rhs_dependencies(stmt.value, state.tainted, active)
            rhs_t = rhs_values[id(stmt.value)]
            if isinstance(stmt.value, (ast.Name, ast.Attribute, ast.Subscript)):
                _forget_fields(state.tainted, stmt.value)
            if len(walruses) == 1:
                _add_taint(state.tainted, walruses[0].target.id)
            if is_raising:
                rhs_t = True
            rhs_state = set(state.tainted)
            for target in stmt.targets:
                scan_expr_for_assert_calls(target, state)
                if active:
                    use_literal_rhs = (
                        stmt.value
                        if (
                            not is_raising
                            and isinstance(target, (ast.Tuple, ast.List))
                            and isinstance(stmt.value, (ast.Tuple, ast.List))
                        )
                        else None
                    )
                    _assign_target(target, rhs_t, state.tainted, rhs_expr=use_literal_rhs, rhs_state=rhs_state, rhs_values=rhs_values)
            scan_expr_for_assert_calls(stmt.value, state)

        elif isinstance(stmt, ast.AnnAssign):
            scan_expr_for_assert_calls(stmt.target, state)
            scan_expr_for_assert_calls(stmt.annotation, state)
            if stmt.value is not None:
                rhs_t = _eval_expr_taint(stmt.value, state.tainted, active=active)
                if len(walruses) == 1:
                    _add_taint(state.tainted, walruses[0].target.id)
                if is_raising:
                    rhs_t = True
                if active:
                    use_literal_rhs = (
                        stmt.value
                        if (
                            not is_raising
                            and isinstance(stmt.target, (ast.Tuple, ast.List))
                            and isinstance(stmt.value, (ast.Tuple, ast.List))
                        )
                        else None
                    )
                    _assign_target(
                        stmt.target,
                        rhs_t,
                        state.tainted,
                        rhs_expr=use_literal_rhs,
                    )
                scan_expr_for_assert_calls(stmt.value, state)

        elif isinstance(stmt, ast.AugAssign):
            scan_expr_for_assert_calls(stmt.target, state)
            rhs_t = _eval_expr_taint(stmt.value, state.tainted, active=active)
            if is_raising:
                rhs_t = True
            if active:
                _apply_aug_assign(stmt.target, rhs_t, state.tainted)
            scan_expr_for_assert_calls(stmt.value, state)

        elif isinstance(stmt, ast.Assert):
            check_site_node(stmt, "assert", state)
            _eval_expr_taint(stmt.test, state.tainted, active=active)
            _eval_expr_taint(stmt.msg, state.tainted, active=active)
            scan_expr_for_assert_calls(stmt.test, state)
            scan_expr_for_assert_calls(stmt.msg, state)

        elif isinstance(stmt, ast.Expr):
            scan_expr_for_assert_calls(stmt.value, state)
            _eval_expr_taint(stmt.value, state.tainted, active=active)
            if len(walruses) == 1:
                _add_taint(state.tainted, walruses[0].target.id)

        elif isinstance(stmt, ast.If):
            _eval_expr_taint(stmt.test, state.tainted, active=active)
            if len(walruses) == 1:
                _add_taint(state.tainted, walruses[0].target.id)
            scan_expr_for_assert_calls(stmt.test, state)
            truth = _truth(stmt.test)
            branches = []
            for feasible, body in ((truth is not False, stmt.body), (truth is not True, stmt.orelse)):
                if feasible:
                    branch = state.clone()
                    exec_stmts(body, branch)
                    branches.append(branch)
            merge_states(state, branches)

        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            loop_entry = state.clone()
            breaks: list[_PathState] = []
            continues: list[_PathState] = []
            loop_stack.append((breaks, continues))
            try:
                if isinstance(stmt, ast.While):
                    iterable = None
                    truth = _truth(stmt.test)
                else:
                    iterable = stmt.iter
                    truth = _truth(iterable)
                    scan_expr_for_assert_calls(iterable, state)
                # Literal finite loops have an exact iteration count. Otherwise include
                # the zero-iteration path and intersect dependencies at the fixed point.
                exact_count = (len(iterable.elts) if isinstance(iterable, (ast.Tuple, ast.List))
                               and not any(isinstance(item, ast.Starred) for item in iterable.elts) else None)
                if exact_count is not None and exact_count > MAX_LOOP_FIXPOINT_ITERATIONS:
                    exact_count = None
                entry = state.clone()
                iterations = exact_count if exact_count is not None else MAX_LOOP_FIXPOINT_ITERATIONS
                if truth is False:
                    iterations = 0
                normal_exit = True
                for index in range(iterations):
                    body_state = entry.clone()
                    if isinstance(stmt, ast.While):
                        _eval_expr_taint(stmt.test, body_state.tainted, active=body_state.started)
                        scan_expr_for_assert_calls(stmt.test, body_state)
                    else:
                        value = (iterable.elts[index] if exact_count is not None else iterable)
                        iter_t = _eval_expr_taint(value, body_state.tainted, active=body_state.started)
                        if is_raising:
                            iter_t = True
                        if body_state.started:
                            _assign_target(stmt.target, iter_t, body_state.tainted)
                    exec_stmts(stmt.body, body_state)
                    outgoing = [] if body_state.terminated else [body_state]
                    outgoing.extend(item for item in continues if item.control == "continue")
                    continues.clear()
                    for item in outgoing:
                        item.terminated = False
                        item.control = None
                    if not outgoing:
                        normal_exit = False
                        break
                    if exact_count is None:
                        outgoing.append(loop_entry.clone())
                    updated = entry.clone()
                    merge_states(updated, outgoing)
                    stable = (updated.tainted, updated.started) == (entry.tainted, entry.started)
                    entry = updated
                    if exact_count is None and stable:
                        break
                exits = []
                if isinstance(stmt, ast.While) and truth is True:
                    normal_exit = False
                if normal_exit:
                    exec_stmts(stmt.orelse, entry)
                    exits.append(entry)
                elif exact_count is None and truth is not True:
                    exits.append(loop_entry)
                for item in breaks:
                    if item.control != "break":
                        continue
                    item.terminated = False
                    item.control = None
                    exits.append(item)
                merge_states(state, exits)
            finally:
                loop_stack.pop()

        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                scan_expr_for_assert_calls(item.context_expr, state)
                ctx_t = _eval_expr_taint(item.context_expr, state.tainted, active=active)
                if is_raising:
                    ctx_t = True
                if item.optional_vars is not None:
                    scan_expr_for_assert_calls(item.optional_vars, state)
                    if active:
                        _assign_target(item.optional_vars, ctx_t, state.tainted)
            exec_stmts(stmt.body, state)

        elif isinstance(stmt, (ast.Try, ast.TryStar)):
            exit_lists = [(items, len(items)) for pair in loop_stack for items in pair]
            body_state = state.clone()
            exec_stmts(stmt.body, body_state)
            if not body_state.terminated:
                exec_stmts(stmt.orelse, body_state)
            branches = [body_state]
            for handler in stmt.handlers:
                handler_state = state.clone()
                # A handler may run before any body statement; only shared
                # dependencies can be proven without exception-site information.
                handler_state.tainted.intersection_update(body_state.tainted)
                handler_state.started = state.started and body_state.started
                if handler.name is not None:
                    _clear_target(handler_state.tainted, handler.name)
                exec_stmts(handler.body, handler_state)
                branches.append(handler_state)
            if stmt.finalbody:
                # Loop transfers also execute finally, even when another branch
                # falls through the try body. Keep their exit states separate.
                final_states = list(branches)
                for items, previous_count in exit_lists:
                    for pending_state in items[previous_count:]:
                        if not any(pending_state is item for item in final_states):
                            final_states.append(pending_state)
                for branch in final_states:
                    pending = branch.terminated
                    control = branch.control
                    branch.terminated = False
                    branch.control = None
                    exec_stmts(stmt.finalbody, branch)
                    if not branch.terminated:
                        branch.terminated = pending
                        branch.control = control
            merge_states(state, branches)

        elif isinstance(stmt, ast.Match):
            scan_expr_for_assert_calls(stmt.subject, state)
            subj_t = _eval_expr_taint(stmt.subject, state.tainted, active=active) or is_raising
            branches = []
            exhaustive = False
            for case in stmt.cases:
                if (isinstance(stmt.subject, ast.Constant) and isinstance(case.pattern, ast.MatchValue)
                        and isinstance(case.pattern.value, ast.Constant)
                        and stmt.subject.value != case.pattern.value.value):
                    continue
                case_state = state.clone()
                if case_state.started:
                    _bind_match_pattern(case.pattern, subj_t, case_state.tainted)
                guard_truth = True if case.guard is None else _truth(case.guard)
                if guard_truth is False:
                    continue
                if case.guard is not None:
                    _eval_expr_taint(case.guard, case_state.tainted, active=case_state.started)
                    scan_expr_for_assert_calls(case.guard, case_state)
                exec_stmts(case.body, case_state)
                branches.append(case_state)
                if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and guard_truth is True:
                    exhaustive = True
                    break
            if not exhaustive:
                branches.append(state.clone())
            merge_states(state, branches)

        elif isinstance(stmt, (ast.Break, ast.Continue)):
            state.terminated = True
            state.control = "break" if isinstance(stmt, ast.Break) else "continue"
            if loop_stack:
                target = loop_stack[-1][0 if isinstance(stmt, ast.Break) else 1]
                target.append(state)

        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                scan_expr_for_assert_calls(target, state)
                if active:
                    key = _field_key(target)
                    if key is not None:
                        _clear_target(state.tainted, key)
                    else:
                        _forget_fields(state.tainted, target)

        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            if active:
                for alias in stmt.names:
                    bound = alias.asname if alias.asname else alias.name.split(".")[0]
                    _clear_target(state.tainted, bound)

        elif isinstance(stmt, ast.Return):
            scan_expr_for_assert_calls(stmt.value, state)
            _eval_expr_taint(stmt.value, state.tainted, active=active)
            state.terminated = True

        elif isinstance(stmt, ast.Raise):
            scan_expr_for_assert_calls(stmt.exc, state)
            scan_expr_for_assert_calls(stmt.cause, state)
            _eval_expr_taint(stmt.exc, state.tainted, active=active)
            _eval_expr_taint(stmt.cause, state.tainted, active=active)
            state.terminated = True

    initial_state = _PathState(tainted=set(), started=False, terminated=False)
    exec_stmts(fn_node.body, initial_state)

    # Return eligible site IDs in deterministic source order.
    ordered_eligible = [s.site_id for s in sites if s.site_id in reached_set
                        or (s.site_id in eligible_set and s.site_id not in independent_sites)]
    return FlowResult(eligible=ordered_eligible, gave_up=False, reason=None)


def eligible_sites(
    source: bytes,
    function: str,
    raising_line: int,
    reached_site_ids: list[str],
) -> list[str]:
    """Return deterministic list of eligible assertion site IDs for the given test function."""
    result = analyze_flow(
        source=source,
        function=function,
        raising_line=raising_line,
        reached_site_ids=reached_site_ids,
    )
    return result.eligible
