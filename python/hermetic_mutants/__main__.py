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
import re
import secrets
import stat
import sys
from pathlib import Path

from hermetic_mutants.pool import Pool, build_pool
from hermetic_mutants.rewrite import MutantError, read_test_file

# Longest accepted seed, in hex digits
MAX_SEED_HEX_CHARS: int = 256
_HEX_SEED_RE = re.compile(r"[0-9A-Fa-f]+")


def _validate_hex_seed(seed_str: str) -> str:
    """Validate that the seed is a non-empty string of plain hexadecimal digits.

    Prefixes (0x), signs, underscores and whitespace are rejected, so each seed
    value has exactly one accepted spelling up to letter case.
    """
    if not seed_str:
        raise MutantError("Seed cannot be empty")
    if len(seed_str) > MAX_SEED_HEX_CHARS:
        raise MutantError(f"Seed longer than {MAX_SEED_HEX_CHARS} hex digits")
    if _HEX_SEED_RE.fullmatch(seed_str) is None:
        raise MutantError("Seed must contain only hexadecimal digits")
    return seed_str.lower()


def _open_empty_out_dir(out_dir_path: Path) -> int:
    """Create or check the output directory and return an fd for it.

    The directory must not be a symlink and must be empty. The returned fd is
    opened with O_NOFOLLOW and checked against the lstat result (device and
    inode), and every later write goes through it.
    """
    path_str = os.fspath(out_dir_path)
    try:
        st = os.lstat(path_str)
    except FileNotFoundError:
        out_dir_path.parent.mkdir(parents=True, exist_ok=True)
        os.mkdir(path_str, 0o755)
        st = os.lstat(path_str)

    if stat.S_ISLNK(st.st_mode):
        raise MutantError(f"Output directory is a symlink: {path_str}")
    if not stat.S_ISDIR(st.st_mode):
        raise MutantError(f"Output path is not a directory: {path_str}")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(path_str, flags)
    try:
        fst = os.fstat(dir_fd)
        if not stat.S_ISDIR(fst.st_mode) or (fst.st_dev, fst.st_ino) != (
            st.st_dev,
            st.st_ino,
        ):
            raise MutantError(f"Output directory changed during check: {path_str}")
        with os.scandir(dir_fd) as entries:
            for _entry in entries:
                raise MutantError(f"Output directory is not empty: {path_str}")
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd


def _atomic_write_file(dir_fd: int, name: str, data: bytes) -> None:
    """Write data to name inside dir_fd atomically via a temporary file and rename."""
    tmp_name = f".tmp_{name}_{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)

    fd = os.open(tmp_name, flags, 0o644, dir_fd=dir_fd)
    try:
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise MutantError(f"Short write for {name}")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def build_manifest_bytes(pool: Pool, seed: str) -> bytes:
    """Deterministic manifest (no host time, no host identity, no host paths)."""
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
        "shortfall_reason": pool.shortfall_reason,
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
    return (json.dumps(manifest_data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_pool_output(pool: Pool, seed: str, out_dir: Path) -> None:
    """Write variants, then manifest.json last, atomically into the empty out_dir."""
    manifest_bytes = build_manifest_bytes(pool, seed)
    dir_fd = _open_empty_out_dir(out_dir)
    try:
        for variant in pool.variants:
            _atomic_write_file(dir_fd, variant.name, variant.source.encode("utf-8"))
        _atomic_write_file(dir_fd, "manifest.json", manifest_bytes)
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class _ArgumentParser(argparse.ArgumentParser):
    """Argument parser that reports usage errors as MutantError (exit 1, not 2)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise MutantError(f"invalid arguments: {message}")


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = _ArgumentParser(
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

        # Build variants (all input is validated here, before any file is touched)
        pool = build_pool(
            source=source_bytes,
            seed=valid_seed,
            n_equivalents=args.equivalents,
            n_mutants=args.mutants,
        )

        # Check the empty output directory, then write files and manifest atomically
        write_pool_output(pool, seed=valid_seed, out_dir=args.out)

        return 0
    except MutantError as exc:
        sys.stderr.write(f"hermetic_mutants error: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"hermetic_mutants unexpected error: {type(exc).__name__}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
