"""Hermetic slice package for cutoff computation and repository sealing."""

from hermetic_slice.cutoffs import (
    Cutoffs,
    DiscardedDate,
    FixCommit,
    compute_cutoffs,
    ensure_utc,
)
from hermetic_slice.dispositions import (
    DispositionsError,
    MalformedGateOutputError,
    MissingDispositionError,
    RedactedSpan,
    TaskDispositionResult,
    decide_task_disposition,
    find_spans_in_text,
    process_dispositions,
    redact_problem_statement,
    MAX_REDACTION_FRACTION,
    MIN_REMAINING_CHARS,
)
from hermetic_slice.eval_spec import (
    EvalSpecError,
    load_eval_rows,
    prepare_eval_script,
    write_eval_spec,
)
from hermetic_slice.gitutil import GitError, run_git
from hermetic_slice.grader import (
    FilePatch,
    GraderError,
    PatchRejected,
    grade,
    oracle_check,
    split_patch,
    validate_patch,
)
from hermetic_slice.log_parsers import get_log_parser
from hermetic_slice.repo_sealer import (
    SealReport,
    UnsupportedRepoError,
    VerificationError,
    seal_repo,
    verify_sealed_repo,
)

__all__ = [
    "Cutoffs",
    "DiscardedDate",
    "EvalSpecError",
    "FilePatch",
    "FixCommit",
    "GitError",
    "GraderError",
    "PatchRejected",
    "SealReport",
    "UnsupportedRepoError",
    "VerificationError",
    "compute_cutoffs",
    "ensure_utc",
    "get_log_parser",
    "grade",
    "load_eval_rows",
    "oracle_check",
    "prepare_eval_script",
    "run_git",
    "seal_repo",
    "split_patch",
    "validate_patch",
    "verify_sealed_repo",
    "write_eval_spec",
    "DispositionsError",
    "MalformedGateOutputError",
    "MissingDispositionError",
    "RedactedSpan",
    "TaskDispositionResult",
    "decide_task_disposition",
    "find_spans_in_text",
    "process_dispositions",
    "redact_problem_statement",
    "MAX_REDACTION_FRACTION",
    "MIN_REMAINING_CHARS",
]
