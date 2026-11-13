
"""Hermetic assertion recorder pytest plugin package.

Note: Pytest must rewrite assertions in test files for passing plain ``assert``
statements to invoke ``pytest_assertion_pass``. Test files must not disable
assertion rewriting (e.g., via ``PYTEST_DONT_REWRITE`` or ``--assert=plain``).
"""

from __future__ import annotations

from hermetic_assert_recorder.plugin import (
    ENV_LOG_PATH,
    MAX_ASSERTS_PER_FUNCTION,
    MAX_AST_FILE_BYTES,
    MAX_AST_FUNCTIONS_PER_FILE,
    MAX_ERROR_STR_LEN,
    MAX_INTERNAL_ERRORS,
    MAX_NODEID_LEN,
    MAX_OUTCOME_LEN,
    MAX_PATH_LEN,
    MAX_QUALNAME_LEN,
    MAX_REACHED_PER_TEST,
    MAX_TESTS,
    AssertRecorder,
)

__all__ = [
    "AssertRecorder",
    "ENV_LOG_PATH",
    "MAX_ASSERTS_PER_FUNCTION",
    "MAX_AST_FILE_BYTES",
    "MAX_AST_FUNCTIONS_PER_FILE",
    "MAX_ERROR_STR_LEN",
    "MAX_INTERNAL_ERRORS",
    "MAX_NODEID_LEN",
    "MAX_OUTCOME_LEN",
    "MAX_PATH_LEN",
    "MAX_QUALNAME_LEN",
    "MAX_REACHED_PER_TEST",
    "MAX_TESTS",
]


