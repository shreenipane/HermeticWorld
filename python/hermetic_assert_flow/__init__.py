"""Hermetic static data-flow analysis for base-failing test assertion eligibility."""

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.flow import FlowResult, analyze_flow, eligible_sites
from hermetic_assert_flow.limits import (
    MAX_AST_DEPTH,
    MAX_AST_NODES,
    MAX_EXPR_DEPTH,
    MAX_IDENTIFIER_LENGTH,
    MAX_LINE_NUMBER,
    MAX_LOOP_FIXPOINT_ITERATIONS,
    MAX_REACHED_ARGS,
    MAX_READ_CHUNK_BYTES,
    MAX_SITES_PER_FUNCTION,
    MAX_SOURCE_BYTES,
    MAX_STATEMENTS_PER_FUNCTION,
    MAX_TAINTED_NAMES,
)
from hermetic_assert_flow.parse import parse_source
from hermetic_assert_flow.sites import AssertionSite, list_assertion_sites

__all__ = [
    "AssertionSite",
    "FlowError",
    "FlowResult",
    "MAX_AST_DEPTH",
    "MAX_AST_NODES",
    "MAX_EXPR_DEPTH",
    "MAX_IDENTIFIER_LENGTH",
    "MAX_LINE_NUMBER",
    "MAX_LOOP_FIXPOINT_ITERATIONS",
    "MAX_REACHED_ARGS",
    "MAX_READ_CHUNK_BYTES",
    "MAX_SITES_PER_FUNCTION",
    "MAX_SOURCE_BYTES",
    "MAX_STATEMENTS_PER_FUNCTION",
    "MAX_TAINTED_NAMES",
    "analyze_flow",
    "eligible_sites",
    "list_assertion_sites",
    "parse_source",
]
