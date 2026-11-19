# hermetic_pkgworld

Package evidence generator and verifier for Hermetic World (`PackagesRecord`).

## Overview

Hermetic World evaluates agent benchmark tasks in sealed environments frozen at a cutoff date $T_{\text{pkg}}$. The canonical World Manifest (`WorldManifest`, TR-SEAL-11, TR-SEAL-12) requires package evidence:

```rust
pub struct PackagesRecord {
    pub closure_root: String,
    pub baseline_month: String,
    pub baseline_root: String,
}
```

`hermetic_pkgworld`:
1. Validates the task's frozen Layer-1 closure (produced by `hermetic_pkgrec freeze`) against its canonical manifest (`project`, `filename`, `sha256`, `upload-time`, `yank_decision`), checks every distribution artifact and index page on disk, and computes `closure_root` as a deterministic Merkle digest.
2. Validates the Layer-2 baseline plan and store (produced by `hermetic_pkgbase`), verifies store immutability (`.frozen`), checks distribution artifacts against declared checksums, extracts `baseline_month` (`YYYY-MM`), and computes `baseline_root` the exact same way.
3. Explicitly and verifiably represents tasks with zero third-party packages (signed off by `pkgrec` with zero files), producing a deterministic cryptographic root and never an empty string or fabricated placeholder.
4. Fails closed with precise typed diagnostics on any missing artifact, hash mismatch, un-frozen baseline, or cutoff discrepancy.

---

## The Exact Hashing Scheme

Both `closure_root` and `baseline_root` are computed using a deterministic, domain-separated binary Merkle tree over canonical JSON leaves.

### 1. Domain Tags

To prevent second-preimage and cross-context collision attacks:
- Leaf tag: `b"hw-pkg-leaf\0"` (12 bytes)
- Node tag: `b"hw-pkg-node\0"` (12 bytes)
- Empty tree tag: `b"hw-pkg-empty\0"` (13 bytes)

### 2. Canonical Leaves

Each leaf is a pair `(path, value)` where:
- `path`: ASCII/UTF-8 path string identifying the leaf.
- `value`: Canonical JSON byte encoding (UTF-8) with sorted keys, compact separators (`,`, `:`), and no trailing whitespace except a single final `\n`.

#### For Layer-1 Closure (`closure_root`):
1. **Manifest Metadata Leaf**:
   - `path`: `"/manifest"`
   - `value`:
     ```json
     {"cutoff":"<cutoff_timestamp>","files_count":<N>,"schema":"hermetic.pkgrec.manifest/1"}
     ```
2. **Per-File Leaves** (for each distribution file in `manifest.files`):
   - `path`: `f"/files/{normalized_project}/{filename}/{sha256}"`
   - `value`:
     ```json
     {"filename":"<filename>","project":"<normalized_project>","sha256":"<64_hex_sha256>","upload-time":"<upload_time>","yank_decision":"<yank_decision>"}
     ```

#### For Layer-2 Baseline (`baseline_root`):
1. **Manifest Metadata Leaf**:
   - `path`: `"/manifest"`
   - `value`:
     ```json
     {"cutoff_month":"<YYYY-MM>","cutoff_timestamp":"<cutoff_timestamp>","files_count":<N>,"schema":"hermetic.pkgbase.baseline/1"}
     ```
2. **Per-File Leaves** (for each distribution file in `baseline_plan.files`):
   - `path`: `f"/files/{normalized_project}/{filename}/{sha256}"`
   - `value`:
     ```json
     {"filename":"<filename>","project":"<normalized_project>","sha256":"<64_hex_sha256>","upload-time":"<upload_time>","yank_decision":"<yank_decision>"}
     ```

### 3. Leaf Hash Computation

For each leaf `(path, value)`:
$$\text{leaf\_hash} = \text{SHA-256}(\text{PKG\_LEAF\_TAG} \mathbin{\Vert} \text{len}(path)_{\text{u32 LE}} \mathbin{\Vert} path \mathbin{\Vert} \text{len}(value)_{\text{u32 LE}} \mathbin{\Vert} value)$$

### 4. Binary Merkle Tree Reduction

Leaves are sorted strictly by `path` in byte order (ASCII/UTF-8).
Let $L = [h_0, h_1, \dots, h_{N-1}]$ be the list of leaf hashes:
- If $N = 0$: $\text{root} = \text{SHA-256}(\text{PKG\_EMPTY\_TAG})$.
- While $|L| > 1$:
  - Pair consecutive nodes $(L_{2i}, L_{2i+1})$:
    $$\text{parent} = \text{SHA-256}(\text{PKG\_NODE\_TAG} \mathbin{\Vert} L_{2i} \mathbin{\Vert} L_{2i+1})$$
  - If $|L|$ is odd, the last node $L_{|L|-1}$ is promoted unchanged to the next level.
  - $L \leftarrow \text{next level}$.
- Format: `sha256:<64 lowercase hex characters>`.

---

## Tasks with Zero Third-Party Packages

Per TRD §13 and TR-PKG-1, an environment that uses only standard library packages must be represented explicitly and verifiably:
- `pkgrec` produces a canonical manifest with `schema = "hermetic.pkgrec.manifest/1"`, `cutoff = "<T_pkg>"`, and `files = []`.
- When frozen, the directory contains `manifest.json` signed off by `pkgrec` with zero files.
- `hermetic_pkgworld` verifies that `files/` and `simple/` contain no rogue files.
- The Merkle tree evaluates over the single canonical `/manifest` leaf with `files_count: 0`.
- The resulting `closure_root` is a deterministic, non-empty 64-hex SHA-256 digest (e.g. `sha256:...`), **never an empty string**.
- An arbitrary empty directory lacking `manifest.json` signed off by `pkgrec` fails closed immediately.

---

## CLI Usage

Compute package evidence from a frozen closure and baseline store:

```bash
python -m hermetic_pkgworld \
  --pkg-closure /path/to/frozen_closure \
  --pkg-baseline /path/to/baseline_store \
  --cutoff 2024-05-01T00:00:00Z
```

Outputs canonical JSON to stdout:

```json
{
  "baseline_month": "2024-05",
  "baseline_root": "sha256:7b3c...",
  "closure_root": "sha256:1a2b..."
}
```

Exit code:
- `0`: All verifications passed, valid JSON printed to stdout.
- `1`: Validation or integrity failure, error printed to stderr.

---

## Integration with Stage-One Sealing (`e2e_seal.py`)

`scripts/integration/e2e_seal.py` accepts:
```bash
python scripts/integration/e2e_seal.py <instance> \
  --pkg-closure /path/to/closure \
  --pkg-baseline /path/to/baseline
```
- When both are supplied, `e2e_seal.py` verifies both directories, writes `packages.json`, adds `packages` evidence to `bundle-evidence.json`, and omits `"package_closure_and_baseline"` from the missing prerequisites list in step `world_manifest`.
- When omitted, the step retains `"package_closure_and_baseline"` as open.
- When only one is supplied or an input fails verification, sealing fails closed immediately.
