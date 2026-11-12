"""Flow-sensitive may-taint data-flow analysis for base-failing assertion eligibility."""

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

    def clone(self) -> _PathState:
        return _PathState(
            tainted=set(self.tainted),
            started=self.started,
            terminated=self.terminated,
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
) -> ast.stmt:
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
    return candidates[0]


def _extract_base_name(target: ast.expr) -> str | None:
    """Resolve the root variable Name for Attribute/Subscript chains, or None if non-name root."""
    cur: ast.expr = target
    depth = 0
    while isinstance(cur, (ast.Attribute, ast.Subscript)):
        depth += 1
        if depth > MAX_EXPR_DEPTH:
            raise FlowError(
                f"Target expression depth exceeds cap of {MAX_EXPR_DEPTH}",
                code="EXPR_TOO_DEEP",
            )
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    return None


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
            if val_tainted:
                _add_taint(tainted, expr.target.id)
            else:
                tainted.discard(expr.target.id)
        return val_tainted

    if isinstance(expr, ast.Attribute):
        return _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)

    if isinstance(expr, ast.Subscript):
        val_t = _eval_expr_taint(expr.value, tainted, active=active, depth=depth + 1)
        slc_t = _eval_expr_taint(expr.slice, tainted, active=active, depth=depth + 1)
        return val_t or slc_t

    if isinstance(expr, ast.Slice):
        low_t = _eval_expr_taint(expr.lower, tainted, active=active, depth=depth + 1)
        up_t = _eval_expr_taint(expr.upper, tainted, active=active, depth=depth + 1)
        step_t = _eval_expr_taint(expr.step, tainted, active=active, depth=depth + 1)
        return low_t or up_t or step_t

    if isinstance(expr, ast.Call):
        func_t = _eval_expr_taint(expr.func, tainted, active=active, depth=depth + 1)
        args_t = False
        for arg in expr.args:
            if _eval_expr_taint(arg, tainted, active=active, depth=depth + 1):
                args_t = True
        for kw in expr.keywords:
            if _eval_expr_taint(kw.value, tainted, active=active, depth=depth + 1):
                args_t = True
        return func_t or args_t

    if isinstance(expr, ast.UnaryOp):
        return _eval_expr_taint(expr.operand, tainted, active=active, depth=depth + 1)

    if isinstance(expr, ast.BinOp):
        left_t = _eval_expr_taint(expr.left, tainted, active=active, depth=depth + 1)
        right_t = _eval_expr_taint(expr.right, tainted, active=active, depth=depth + 1)
        return left_t or right_t

    if isinstance(expr, ast.BoolOp):
        result = False
        for val in expr.values:
            if _eval_expr_taint(val, tainted, active=active, depth=depth + 1):
                result = True
        return result

    if isinstance(expr, ast.Compare):
        result = _eval_expr_taint(expr.left, tainted, active=active, depth=depth + 1)
        for comp in expr.comparators:
            if _eval_expr_taint(comp, tainted, active=active, depth=depth + 1):
                result = True
        return result

    if isinstance(expr, ast.IfExp):
        test_t = _eval_expr_taint(expr.test, tainted, active=active, depth=depth + 1)
        body_t = _eval_expr_taint(expr.body, tainted, active=active, depth=depth + 1)
        else_t = _eval_expr_taint(expr.orelse, tainted, active=active, depth=depth + 1)
        return test_t or body_t or else_t

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
            if active:
                _assign_target(gen.target, iter_t, comp_tainted, rhs_expr=None, depth=depth + 1)
            for cond in gen.ifs:
                if _eval_expr_taint(cond, comp_tainted, active=active, depth=depth + 1):
                    any_gen_tainted = True
        elt_t = _eval_expr_taint(expr.elt, comp_tainted, active=active, depth=depth + 1)
        return elt_t or any_gen_tainted

    if isinstance(expr, ast.DictComp):
        comp_tainted = set(tainted)
        any_gen_tainted = False
        for gen in expr.generators:
            iter_t = _eval_expr_taint(gen.iter, comp_tainted, active=active, depth=depth + 1)
            if active:
                _assign_target(gen.target, iter_t, comp_tainted, rhs_expr=None, depth=depth + 1)
            for cond in gen.ifs:
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


def _assign_target(
    target: ast.expr,
    rhs_tainted: bool,
    tainted: set[str],
    *,
    rhs_expr: ast.expr | None = None,
    depth: int = 1,
) -> None:
    """Apply assignment taint semantics to a store target."""
    if depth > MAX_EXPR_DEPTH:
        raise FlowError(
            f"Assignment target depth exceeds cap of {MAX_EXPR_DEPTH}",
            code="EXPR_TOO_DEEP",
        )

    if isinstance(target, ast.Name):
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
                sub_tainted = _eval_expr_taint(sub_rhs, tainted, active=True, depth=depth + 1)
                _assign_target(
                    sub_target,
                    sub_tainted,
                    tainted,
                    rhs_expr=sub_rhs,
                    depth=depth + 1,
                )
            return

        for sub_target in target.elts:
            _assign_target(sub_target, rhs_tainted, tainted, rhs_expr=None, depth=depth + 1)
        return

    if isinstance(target, ast.Attribute):
        _eval_expr_taint(target.value, tainted, active=True, depth=depth + 1)
        if rhs_tainted:
            base = _extract_base_name(target)
            if base is not None:
                _add_taint(tainted, base)
        return

    if isinstance(target, ast.Subscript):
        _eval_expr_taint(target.value, tainted, active=True, depth=depth + 1)
        slice_tainted = _eval_expr_taint(target.slice, tainted, active=True, depth=depth + 1)
        if rhs_tainted or slice_tainted:
            base = _extract_base_name(target)
            if base is not None:
                _add_taint(tainted, base)
        return


def _apply_aug_assign(
    target: ast.expr,
    rhs_tainted: bool,
    tainted: set[str],
) -> None:
    """Apply augmented assignment (x += rhs, obj.attr += rhs, arr[i] += rhs) taint semantics."""
    if isinstance(target, ast.Name):
        if rhs_tainted or (target.id in tainted):
            _add_taint(tainted, target.id)
        return

    if isinstance(target, ast.Attribute):
        base_t = _eval_expr_taint(target.value, tainted, active=True)
        if rhs_tainted or base_t:
            base = _extract_base_name(target)
            if base is not None:
                _add_taint(tainted, base)
        return

    if isinstance(target, ast.Subscript):
        base_t = _eval_expr_taint(target.value, tainted, active=True)
        slice_t = _eval_expr_taint(target.slice, tainted, active=True)
        if rhs_tainted or base_t or slice_t:
            base = _extract_base_name(target)
            if base is not None:
                _add_taint(tainted, base)
        return


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
            if subject_tainted:
                _add_taint(tainted, pattern.name)
            else:
                tainted.discard(pattern.name)
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
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
    """Run flow-sensitive may-taint analysis for a test function starting at raising_line."""
    if isinstance(raising_line, bool) or not isinstance(raising_line, int):
        raise FlowError("raising_line must be an integer", code="INVALID_RAISING_LINE")
    if raising_line < 1 or raising_line > MAX_LINE_NUMBER:
        raise FlowError(
            f"raising_line must be between 1 and {MAX_LINE_NUMBER}",
            code="INVALID_RAISING_LINE",
        )

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
    raising_pos = (raising_stmt.lineno, raising_stmt.col_offset)

    # Check give-up conditions (nested functions, classes, lambdas, global, nonlocal).
    give_up_reason = _check_give_up(fn_node)
    if give_up_reason is not None:
        reached_eligible = [s.site_id for s in sites if s.site_id in reached_set]
        return FlowResult(eligible=reached_eligible, gave_up=True, reason=give_up_reason)

    eligible_set: set[str] = {s.site_id for s in sites if s.site_id in reached_set}
    site_by_pos: dict[tuple[int, int, str], AssertionSite] = {
        (s.lineno, s.col_offset, s.kind): s for s in sites
    }

    stmt_count = 0

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
        for checked_expr in site.checked_exprs:
            if _eval_expr_taint(checked_expr, state.tainted, active=True):
                eligible_set.add(site.site_id)
                break

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
            for child in reversed(list(ast.iter_child_nodes(node))):
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
            for checked_expr in checked_exprs:
                if _eval_expr_taint(checked_expr, state.tainted, active=True):
                    eligible_set.add(site.site_id)
                    break

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

        if isinstance(stmt, ast.Assign):
            rhs_t = _eval_expr_taint(stmt.value, state.tainted, active=active)
            if is_raising:
                rhs_t = True
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
                    _assign_target(target, rhs_t, state.tainted, rhs_expr=use_literal_rhs)
            scan_expr_for_assert_calls(stmt.value, state)

        elif isinstance(stmt, ast.AnnAssign):
            scan_expr_for_assert_calls(stmt.target, state)
            scan_expr_for_assert_calls(stmt.annotation, state)
            if stmt.value is not None:
                rhs_t = _eval_expr_taint(stmt.value, state.tainted, active=active)
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

        elif isinstance(stmt, ast.If):
            _eval_expr_taint(stmt.test, state.tainted, active=active)
            scan_expr_for_assert_calls(stmt.test, state)

            then_state = state.clone()
            else_state = state.clone()
            exec_stmts(stmt.body, then_state)
            exec_stmts(stmt.orelse, else_state)

            state.started = then_state.started or else_state.started
            if then_state.terminated and else_state.terminated:
                state.terminated = True
                state.tainted = then_state.tainted | else_state.tainted
            elif then_state.terminated:
                state.terminated = False
                state.tainted = else_state.tainted
            elif else_state.terminated:
                state.terminated = False
                state.tainted = then_state.tainted
            else:
                state.terminated = False
                state.tainted = then_state.tainted | else_state.tainted

        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            scan_expr_for_assert_calls(stmt.target, state)
            scan_expr_for_assert_calls(stmt.iter, state)

            entry = state.clone()
            for _ in range(MAX_LOOP_FIXPOINT_ITERATIONS):
                iter_state = entry.clone()
                iter_t = _eval_expr_taint(stmt.iter, iter_state.tainted, active=iter_state.started)
                if is_raising:
                    iter_t = True
                if iter_state.started:
                    _assign_target(stmt.target, iter_t, iter_state.tainted)
                exec_stmts(stmt.body, iter_state)

                next_tainted = entry.tainted | iter_state.tainted
                next_started = entry.started or iter_state.started
                if next_tainted == entry.tainted and next_started == entry.started:
                    break
                entry.tainted = next_tainted
                entry.started = next_started
            else:
                raise FlowError(
                    f"Loop fixpoint exceeded {MAX_LOOP_FIXPOINT_ITERATIONS} iterations",
                    code="LOOP_FIXPOINT_EXCEEDED",
                )

            if stmt.orelse:
                else_state = entry.clone()
                exec_stmts(stmt.orelse, else_state)
                state.tainted = entry.tainted | else_state.tainted
                state.started = entry.started or else_state.started
            else:
                state.tainted = entry.tainted
                state.started = entry.started

        elif isinstance(stmt, ast.While):
            entry = state.clone()
            for _ in range(MAX_LOOP_FIXPOINT_ITERATIONS):
                iter_state = entry.clone()
                _eval_expr_taint(stmt.test, iter_state.tainted, active=iter_state.started)
                scan_expr_for_assert_calls(stmt.test, iter_state)
                exec_stmts(stmt.body, iter_state)

                next_tainted = entry.tainted | iter_state.tainted
                next_started = entry.started or iter_state.started
                if next_tainted == entry.tainted and next_started == entry.started:
                    break
                entry.tainted = next_tainted
                entry.started = next_started
            else:
                raise FlowError(
                    f"Loop fixpoint exceeded {MAX_LOOP_FIXPOINT_ITERATIONS} iterations",
                    code="LOOP_FIXPOINT_EXCEEDED",
                )

            if stmt.orelse:
                else_state = entry.clone()
                _eval_expr_taint(stmt.test, else_state.tainted, active=else_state.started)
                exec_stmts(stmt.orelse, else_state)
                state.tainted = entry.tainted | else_state.tainted
                state.started = entry.started or else_state.started
            else:
                state.tainted = entry.tainted
                state.started = entry.started

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
            body_state = state.clone()
            exec_stmts(stmt.body, body_state)

            merged_tainted = set(body_state.tainted)
            merged_started = body_state.started
            all_terminated = body_state.terminated

            for handler in stmt.handlers:
                h_state = body_state.clone()
                h_state.terminated = False
                type_t = False
                if handler.type is not None:
                    scan_expr_for_assert_calls(handler.type, h_state)
                    type_t = _eval_expr_taint(
                        handler.type,
                        h_state.tainted,
                        active=h_state.started,
                    )
                if handler.name is not None and h_state.started:
                    if type_t:
                        _add_taint(h_state.tainted, handler.name)
                    else:
                        h_state.tainted.discard(handler.name)
                exec_stmts(handler.body, h_state)
                merged_tainted |= h_state.tainted
                merged_started = merged_started or h_state.started
                all_terminated = all_terminated and h_state.terminated

            if stmt.orelse:
                else_state = body_state.clone()
                exec_stmts(stmt.orelse, else_state)
                merged_tainted |= else_state.tainted
                merged_started = merged_started or else_state.started

            state.tainted = merged_tainted
            state.started = merged_started
            state.terminated = all_terminated if stmt.handlers else body_state.terminated

            if stmt.finalbody:
                exec_stmts(stmt.finalbody, state)

        elif isinstance(stmt, ast.Match):
            scan_expr_for_assert_calls(stmt.subject, state)
            subj_t = _eval_expr_taint(stmt.subject, state.tainted, active=active)
            if is_raising:
                subj_t = True

            merged_tainted = set(state.tainted)
            merged_started = state.started
            for case in stmt.cases:
                c_state = state.clone()
                if c_state.started:
                    _bind_match_pattern(case.pattern, subj_t, c_state.tainted)
                if case.guard is not None:
                    scan_expr_for_assert_calls(case.guard, c_state)
                    _eval_expr_taint(case.guard, c_state.tainted, active=c_state.started)
                exec_stmts(case.body, c_state)
                merged_tainted |= c_state.tainted
                merged_started = merged_started or c_state.started

            state.tainted = merged_tainted
            state.started = merged_started

        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                scan_expr_for_assert_calls(target, state)
                if active and isinstance(target, ast.Name):
                    state.tainted.discard(target.id)

        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            if active:
                for alias in stmt.names:
                    bound = alias.asname if alias.asname else alias.name.split(".")[0]
                    state.tainted.discard(bound)

        elif isinstance(stmt, ast.Return):
            scan_expr_for_assert_calls(stmt.value, state)
            _eval_expr_taint(stmt.value, state.tainted, active=active)
            if active:
                state.terminated = True

        elif isinstance(stmt, ast.Raise):
            scan_expr_for_assert_calls(stmt.exc, state)
            scan_expr_for_assert_calls(stmt.cause, state)
            _eval_expr_taint(stmt.exc, state.tainted, active=active)
            _eval_expr_taint(stmt.cause, state.tainted, active=active)
            if active:
                state.terminated = True

    initial_state = _PathState(tainted=set(), started=False, terminated=False)
    exec_stmts(fn_node.body, initial_state)

    # Return eligible site IDs in deterministic source order.
    ordered_eligible = [s.site_id for s in sites if s.site_id in eligible_set]
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
