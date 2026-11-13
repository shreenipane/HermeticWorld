"""Command-line interface for hermetic_classifier."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .baseline import (
    ClassifierError,
    audit_predicate_to_json,
    build_audit_predicate,
    classify,
    run_status_hint,
    safe_read_file,
    validate_run_digest,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="hermetic_classifier",
        description="Hermetic World retrieval classifier (derived vs retrieved).",
    )
    parser.add_argument(
        "--agent-patch",
        type=Path,
        required=True,
        help="Path to agent's final diff file.",
    )
    parser.add_argument(
        "--gold-patch",
        type=Path,
        required=True,
        help="Path to gold reference diff file.",
    )
    parser.add_argument(
        "--run-digest",
        type=str,
        required=True,
        help="Run digest string ('sha256:' followed by 64 hex characters).",
    )
    parser.add_argument(
        "--sealed",
        action="store_true",
        default=False,
        help="Whether the evaluation world was sealed.",
    )
    parser.add_argument(
        "--gate-leak",
        action="store_true",
        default=False,
        help="Whether sealcheck gate reported a leak.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint. Returns 0 on success, 1 on error."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as err:
        return 1 if err.code != 0 else 0

    try:
        # Validate run digest format
        validate_run_digest(args.run_digest)

        # Safely read patch files without following symlinks
        agent_patch_text = safe_read_file(args.agent_patch)
        gold_patch_text = safe_read_file(args.gold_patch)

        # Classify patches
        result = classify(agent_patch_text, gold_patch_text)

        # Build audit predicate
        predicate = build_audit_predicate(
            run_digest=args.run_digest,
            label=result.label,
            confidence=result.confidence,
            evidence=result.evidence,
        )

        # Evaluate status hint rule (TR-CLS-2)
        hint = run_status_hint(
            label=result.label,
            world_sealed=args.sealed,
            gate_says_leak=args.gate_leak,
        )

        # Print outputs
        print(audit_predicate_to_json(predicate, indent=2))
        print(f"status_hint: {hint}")
        return 0

    except ClassifierError as err:
        sys.stderr.write(f"Classifier error: {err}\n")
        return 1
    except Exception as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
