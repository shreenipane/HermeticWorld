# hermetic_pkgbase

Layer 2 ecosystem baseline construction and planning for Hermetic World (TR-PKG-4).

## Overview

Hermetic World evaluates software engineering tasks in sealed worlds frozen at a cutoff date. Layer 2 provides a task-independent baseline of common developer and test tools (pytest, plugins, hypothesis, mypy, tox, coverage, Cython, setuptools, wheel, ipdb, pip, uv) and the transitive closure of top packages per ecosystem at the cutoff month.

The baseline is shared across all tasks sharing that cutoff month, covers installations initiated during evaluation, and is immutable once frozen.

## Components

1. **Baseline Spec (`hermetic_pkgbase.spec`)**:
   - Validated JSON specification format bounded by named caps.
   - Parses cutoff month (`YYYY-MM`) and establishes the cutoff boundary at the first second of that month (`YYYY-MM-01T00:00:00Z`).
   - Fixed tools list (canonical defaults or explicitly specified).
   - Top-N per ecosystem (N capped) from a local input file (never fetched over network).

2. **Transitive Closure Planner (`hermetic_pkgbase.planner`)**:
   - Takes a `BaselineSpec` and a `Resolver` interface.
   - Computes transitive closure at the cutoff (only files uploaded strictly before the first second of the cutoff month are admitted).
   - Handles dependency cycles safely without infinite recursion.
   - Enforces named caps on resolution depth, package count, and total artifact bytes.
   - Emits a canonical-JSON plan with deterministic ordering, listing all admitted files (`project`, `filename`, `sha256`, `upload-time`) and unresolvable packages (listed, not guessed).

3. **Storage Measurement (`hermetic_pkgbase.storage`)**:
   - Measures and reports total storage footprint, bytes per ecosystem, and bytes per package.

4. **Content-Addressed Store Builder (`hermetic_pkgbase.builder`)**:
   - Consumes a `Plan` and a `Fetcher` interface.
   - Builds a content-addressed directory structure compatible with `hermetic_pkgindex.store.FrozenStore`:
     - `STORE/simple/<normalized-project>/index.json` (PEP 691 JSON index)
     - `STORE/files/<sha256>/<filename>` (verified distribution artifacts)
     - `STORE/.frozen` (immutability marker)
     - `STORE/baseline-manifest.json` (Layer 2 manifest)
   - Verifies SHA-256 for each fetched artifact and refuses mismatches.
   - Freezes the store (read-only permissions 0400/0500) and refuses any subsequent modification or rebuild.

5. **Safe I/O (`hermetic_pkgbase.safe_io`)**:
   - Opens files without following symlinks (`O_NOFOLLOW`).
   - Creates directories and files with private permissions (`0700` and `0600`).
   - Safe atomic writes and bounded chunked reads.
