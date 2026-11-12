"""Command-line interface for hermetic_mutants (TR-GR-8).

Usage:
    python -m hermetic_mutants --test-file FILE --seed HEX --out DIR [--equivalents N] [--mutants N]

Outputs a deterministic manifest.json and atomically written variant files.
Exits 0 on success, or 1 on error.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from hermetic_mutants.pool import Pool, build_pool
from hermetic_mutants.rewrite import MutantError, read_test_file


def _validate_hex_seed(seed_str: str) -> str:
    """Validate that the seed is a non-empty hexadecimal string."""
    if not seed_str:
        raise MutantError("Seed cannot be empty")
    try:
        int(seed_str, 16)
    except ValueError as exc:
        raise MutantError(f"Seed must be a valid hex string, got: {seed_str!r}") from exc
    return seed_str.lower()


def _prepare_empty_out_dir(out_dir_path: Path) -> None:
    """Ensure the output directory exists, is not a symlink, and is empty."""
    resolved_str = os.fspath(out_dir_path)

    if out_dir_path.exists():
        st = os.lstat(resolved_str)
        if stat.S_ISLNK(st.st_mode):
            raise MutantError(f"Output directory is a symlink: {resolved_str}")
        if not stat.S_ISDIR(st.st_mode):
            raise MutantError(f"Output path is not a directory: {resolved_str}")

        # Check if directory is empty
        with os.scandir(resolved_str) as entries:
            for entry in entries:
                raise MutantError(f"Output directory is not empty: {resolved_str}")
    else:
        out_dir_path.mkdir(parents=True, exist_ok=True)
        st = os.lstat(resolved_str)
        if stat.S_ISLNK(st.st_mode):
            raise MutantError(f"Created output directory is a symlink: {resolved_str}")


def _atomic_write_file(target_path: Path, data: bytes) -> None:
    """Write data to a file atomically via a temporary file in the same directory."""
    dir_path = target_path.parent
    token = secrets.token_hex(4)
    tmp_path = dir_path / f".tmp_{target_path.name}_{os.getpid()}_{token}"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(os.fspath(tmp_path), flags, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

    os.replace(tmp_path, target_path)


def write_pool_output(pool: Pool, seed: str, out_dir: Path) -> None:
    """Write variants and manifest.json atomically to the empty out_dir."""
    # Write variant files
    for variant in pool.variants:
        variant_path = out_dir / variant.name
        _atomic_write_file(variant_path, variant.source.encode("utf-8"))

    # Construct deterministic manifest (no host time, no host identity, no host paths)
    manifest_data = {
        "counts": {
            "equivalents": pool.shortfalls["actual_equivalents"],
            "mutants": pool.shortfalls["actual_mutants"],
            "pairs": len(pool.pairs),
            "total_variants": len(pool.variants),
        },
        "pairs": [
            {
                "equivalent": p.equivalent.name,
                "mutant": p.mutant.name if p.mutant is not None else None,
            }
            for p in pool.pairs
        ],
        "seed": seed,
        "shortfalls": pool.shortfalls,
        "variants": [
            {
                "file": v.name,
                "kind": v.kind,
                "rewrites": list(v.rewrites),
                "sha256": v.sha256,
                "site_ids": list(v.site_ids),
            }
            for v in pool.variants
        ],
    }

    manifest_bytes = (
        json.dumps(manifest_data, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    manifest_path = out_dir / "manifest.json"
    _atomic_write_file(manifest_path, manifest_bytes)


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="hermetic_mutants",
        description="Generate deterministic test-variants by syntax-tree rewriting.",
    )
    parser.add_argument(
        "--test-file",
        required=True,
        type=Path,
        help="Path to Python test file to rewrite.",
    )
    parser.add_argument(
        "--seed",
        required=True,
        type=str,
        help="Deterministic hexadecimal seed string.",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Path to output directory (must be empty).",
    )
    parser.add_argument(
        "--equivalents",
        default=4,
        type=int,
        help="Target number of equivalent variants (default: 4).",
    )
    parser.add_argument(
        "--mutants",
        default=4,
        type=int,
        help="Target number of mutant variants (default: 4).",
    )

    try:
        args = parser.parse_args(argv)

        if args.equivalents < 0:
            raise MutantError("--equivalents must be non-negative")
        if args.mutants < 0:
            raise MutantError("--mutants must be non-negative")

        valid_seed = _validate_hex_seed(args.seed)

        # Securely read test file
        source_bytes = read_test_file(args.test_file)

        # Prepare empty output directory
        _prepare_empty_out_dir(args.out)

        # Build variants
        pool = build_pool(
            source=source_bytes,
            seed=valid_seed,
            n_equivalents=args.equivalents,
            n_mutants=args.mutants,
        )

        # Write output files and manifest atomically
        write_pool_output(pool, seed=valid_seed, out_dir=args.out)

        return 0
    except MutantError as exc:
        sys.stderr.write(f"hermetic_mutants error: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"hermetic_mutants unexpected error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
