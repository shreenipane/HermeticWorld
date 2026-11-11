# Hermetic World: Build Log

A dated, append-only record of what was built, measured and decided. Newest entries go at the top. Phase checklists live in [PHASES.md](PHASES.md). This log records what actually happened.

## Entry template

```markdown
## YYYY-MM-DD: <short title>

- **Phase:** 0 | 1 | 2 | 3 | 3b | 4
- **Type:** build | measurement | decision | incident | docs
- **Requirements:** TR-... (from TRD.md)

### Done
- ...

### Results / measurements
- Experiment (E#), metric, value, sample size

### Decisions
- What was decided, the alternatives considered, and why. Note any spec section that must change.

### Problems / open questions
- ...

### Next
- ...
```

---

## 2026-11-11: T1.6 layer index and per-task query (Phase 1)

- **Phase:** 1
- **Type:** build + measurement
- **Requirements:** TR-SC-10
- **Briefs:** `agy-tasks/T1.6-layer-index.md`
- **Merge commits:** `edfe238`

### Done
- Built layer indexing and caching in `crates/hermetic-sealcheck`:
  - `src/index.rs`: layer index format (format version 2) storing inode times, package manifests with dates, line/window/winnow hashes, and D9 benchmark presence indicators; bounded unit merge, exclusion paths, canonical root support, record limits, and SARIF output mode.
  - Per-task query: matches tasks against pre-computed layer index records without re-traversing layer filesystem trees.
  - CLI subcommands in `src/main.rs`: `index-layer` and `query-index`.
- Modules involved: `crates/hermetic-sealcheck` (`src/index.rs`, `src/main.rs`, `src/lib.rs`, `src/scan.rs`, `src/benchmark.rs`, `src/binary.rs`, `src/containers.rs`, `src/d5a.rs`, `src/fingerprint.rs`, `src/sarif.rs`).
- Tests: `crates/hermetic-sealcheck/tests/test_index.rs`.

### Results / measurements
- Query time: 0.11 s on a 50 MB, 5,000-file tree (target budget < 5 s).

---

## 2026-11-11: T1.7 detector D4 inode and superblock times (Phase 1)

- **Phase:** 1
- **Type:** build
- **Requirements:** TR-SC-7 (D4), TR-SEAL-8
- **Briefs:** `agy-tasks/T1.7-d4-times.md`
- **Merge commits:** `a89c697`

### Done
- Built detector D4 checking inode and superblock times against `T_clock`:
  - Live tree scan: loose files, directories, and symlinks with mtime after `T_clock` trigger a gate finding (`channel: mtime`). Tar and zip members with mtimes newer than `T_clock` trigger gate findings (`channel: member_mtime`).
  - Index integration: member times stored in record tag 9 (format version 3, backward compatible with version 2), allowing `query-index` to evaluate D4 findings.
  - Direct ext4 image inspection in `src/ext4.rs`: CLI subcommand `d4-image` parses ext4 structures directly without mounting, checking superblock times and in-use inode times (including extra-epoch bits) against `T_clock`; malformed images fail closed or record info findings.
- Modules involved: `crates/hermetic-sealcheck` (`src/ext4.rs`, `src/scan.rs`, `src/index.rs`, `src/containers.rs`, `src/main.rs`, `src/lib.rs`).
- Tests: `crates/hermetic-sealcheck/tests/test_d4.rs` (live trees, archive members, index round-trip/query equivalence, mke2fs ext4 clean/late images, corrupted and boundary-case images), with updates in `tests/test_cli.rs`, `tests/test_d5a.rs`, `tests/test_d6.rs`, `tests/test_index.rs`.

---

## 2026-11-11: T1.8 detectors D11 and D12 (Phase 1)

- **Phase:** 1
- **Type:** build
- **Requirements:** TR-SC-7 (D11, D12), TR-SEC-5
- **Merge commits:** `057ef23`

### Done
- Built detectors D11 (test-infrastructure changes) and D12 (real-date sentinel):
  - D11 (`hermetic-sealcheck d11 --patch FILE`): inspects unified diff patches for modifications to test infrastructure: `conftest.py`, `pytest.ini`, `tox.ini`, `sitecustomize`, `usercustomize`, `.pth`, `egg-info` / `dist-info` metadata files, benchmark test files, pytest and coverage sections and `pytest11` entry points in `setup.cfg`, `pyproject.toml`, and `setup.py`, monkey-patching of test frameworks or interpreter internals, and modules shadowing the standard library or installed packages. Advisory severity (`review`), exit code 0.
  - D12 (`hermetic-sealcheck d12 --path ... --real-date YYYY-MM-DD`): scans text leaving the VM for real execution date across formats (ISO, US, European, English month names, RFC 2822, HTTP-date, epoch seconds and milliseconds), host names, and host paths. Advisory severity (`review`), exit code 0.
  - Added SARIF reporting rules and CLI dispatch for D11 and D12.
- Modules involved: `crates/hermetic-sealcheck` (`src/d11.rs`, `src/d12.rs`, `src/main.rs`, `src/sarif.rs`, `src/lib.rs`).
- Tests: `crates/hermetic-sealcheck/tests/test_d11.rs`, `crates/hermetic-sealcheck/tests/test_d12.rs`.

---

## 2026-11-11: T1.9 undated mode (Phase 1)

- **Phase:** 1
- **Type:** build
- **Requirements:** TR-SC-9
- **Briefs:** `agy-tasks/T1.9-undated-mode.md`
- **Merge commits:** `958fabe`

### Done
- Built undated mode for benchmark tasks lacking commit history and cutoff dates (`scan --undated` and `query --undated`):
  - Fingerprints all files under `solution/` and `tests/` as added lines (`FingerprintSet::from_files`), subtracting base-tree baselines.
  - Streaming baseline subtraction for large base-tree files over size caps with bounded lines; incomplete baselines are recorded when overall budgets are exhausted.
  - Executes D0 on task instructions, D2, D3b, and D9 on roots, and D6 when OCI files are provided; cutoff-dependent detectors D1, D3, D4, and D5a are skipped and reported in `not_covered`.
  - Fixes for YAML block scalars (folded and literal), indentation indicators, inline `#` comments, and duplicate-line weighting across both dated and undated paths.
- Modules involved: `crates/hermetic-sealcheck` (`src/undated.rs`, `src/fingerprint.rs`, `src/main.rs`, `src/scan.rs`, `src/index.rs`, `src/lib.rs`).
- Tests: `crates/hermetic-sealcheck/tests/test_undated.rs`, `crates/hermetic-sealcheck/tests/test_tier2.rs`.

---

## 2026-11-11: T1.10 detector D8 coherence tells (Phase 1)

- **Phase:** 1
- **Type:** build
- **Requirements:** TR-SC-7 (D8)
- **Merge commits:** `c6a57a1`

### Done
- Built detector D8 (`hermetic-sealcheck d8 --root DIR --t-clock RFC3339`):
  - Inspects rootfs details that indicate a date later than `T_clock`. Advisory `info` severity only, never gates.
  - Inspects channels: `os_release` (built-in Linux distribution release-date tables; versions newer than tables flagged), `tzdata`, `ca_bundle` (handwritten PEM and DER certificate parser checking `notBefore` validity), `kernel` modules, `dated_log` (syslog and journal logs read from tail for recent entries, parsing years adjacent to timestamps), and `python_build` (sysconfig timestamps).
  - Path safety and boundaries: `resolve_in_root` chroot-style symlink resolution preventing host filesystem escapes, root-relative path resolution, and bounded reads using `take()` to prevent unbounded log consumption.
- Modules involved: `crates/hermetic-sealcheck` (`src/d8.rs`, `src/main.rs`, `src/lib.rs`).
- Tests: `crates/hermetic-sealcheck/tests/test_d8.rs`.

---

## 2026-11-11: T1.11 Tier 2 tree-sitter IDF symbols (Phase 1)

- **Phase:** 1
- **Type:** build
- **Requirements:** TR-SC-3
- **Briefs:** `agy-tasks/T1.11-tier2.md`
- **Merge commits:** `16639ae`

### Done
- Built Tier 2 statement symbol fingerprinting:
  - Tree-sitter integration for Python (pinned `tree-sitter = 0.25.0`, `tree-sitter-python = 0.25.0`) collecting identifiers, attribute chains, keyword arguments, and literals from modified statements in the patch.
  - Symbols weighted by inverse document frequency (IDF) over a deterministic sorted sample of the base tree.
  - File, module, function, and class names serve as anchors. A text unit containing an anchor plus at least 2 symbols carrying >= `tier2_threshold` (default 0.35) of a hunk's weight flags a `review` finding under D0 or D2 (suppressed if a Tier 1 or Tier 3 gate already covers the hunk). Never gates.
  - Prose-aware scanner preserving markdown heading anchors, safe UTF-8 character boundary stepping, handling of renames and deletion-only hunks, and single tokenization pass per text unit.
  - `query-index` reports Tier 2 as not covered.
- Modules involved: `crates/hermetic-sealcheck` (`src/tier2.rs`, `src/fingerprint.rs`, `src/scan.rs`, `src/containers.rs`, `src/index.rs`, `src/lib.rs`, `Cargo.toml`).
- Tests: `crates/hermetic-sealcheck/tests/test_tier2.rs`, `crates/hermetic-sealcheck/tests/test_index.rs`.

---

## 2026-11-11: T2.6 world manifest and world_root (Phase 2)

- **Phase:** 2
- **Type:** build
- **Requirements:** TR-SEAL-11, TR-SEAL-12; §13.1
- **Briefs:** `agy-tasks/T2.6-world-manifest.md`
- **Merge commits:** `b684b58`

### Done
- Built the world manifest and `world_root` Merkle tree verification:
  - `WorldManifest` struct in `crates/hermetic-common/src/world_manifest.rs` covering all §13.1 field groups (Identity, Cutoffs, Content, Substrate, Network, Run spec, Evidence), `deny_unknown_fields`, and validation reporting all schema, format, calendar date, and timestamp constraint errors.
  - `world_root`: BLAKE3 binary Merkle root over canonical sorted `(field path, JSON scalar)` leaves with domain separation (`hw-leaf\0`, `hw-node\0`, `hw-empty\0`). Generates and verifies cryptographic inclusion proofs (`inclusion_proof`, `verify_inclusion`). Schema and tree pinned with a fixed known-answer test.
  - Deterministic tree digest (`digest_tree`, `digest_file`): raw-byte path and symlink target hashing on Unix, entry kind, owner-executable bit (ignoring timestamps and ownership), BLAKE3 content stream, domain tag `hw-tree\0`.
  - CLI binary `hermetic-manifest` (`crates/hermetic-common/src/bin/hermetic_manifest.rs`) providing subcommands: `root`, `verify`, `prove`, `check-proof`, `digest-tree`, and `digest-file`.
- Modules involved: `crates/hermetic-common` (`src/world_manifest.rs`, `src/bin/hermetic_manifest.rs`, `src/lib.rs`, `Cargo.toml`).
- Tests: `crates/hermetic-common/tests/test_world_manifest.rs`.

---

## 2026-11-11: T1.4 binary tier, D3b and D5a; T1.5 E3 harness; first E3 numbers (Phase 1)

- **Phase:** 1
- **Type:** build + measurement
- **Requirements:** TR-SC-5, TR-SC-7 (D3b, D5a); E3
- **Briefs:** `agy-tasks/T1.4-binary-tier-d3b-d5a.md`, `agy-tasks/T1.5-e3-corpus.md`

### Done
- **T1.4:** binary-tier items, and D3b over ELF, Java class, wasm, Mach-O universal, minified bundles and `.pyc`. D5a reads package metadata on disk and inside wheels and eggs.
- **T1.5:** the `e3-basetrees`, `e3-build` and `e3-run` commands. The corpus has 11 leak variants and 3 clean variants per task, plus 6 synthetic tasks (3 deletion-only, 3 one-character). Metrics come with Wilson 95% intervals.
- **Review:**
  - T1.4: 12 bugs fixed.
  - T1.5: 4 fixes, including scoring D0 per task. The problem statement is the same for every case of a task, so per case it would have scored them all alike.

### Results / measurements
- **E3, seeded set:** 175 cases over 10 real and 6 synthetic tasks, seed 20261111, scanned with sealcheck at `c3449b5`.

| Metric | Value | 95% interval |
|---|---|---|
| Precision | 100% (114 / 114) | 96.7–100% |
| Recall | 89.8% (114 / 127) | 83.3–93.9% |

  - **Clean cases:** 0 false gates out of 48, covering pre-fix files, 200 sampled base files per task, and another task's fix.
  - **Detected every time:** post-fix files, the patch, a regenerated diff, zip, tar.gz, nested archives, SQLite, hidden-test lines, and every synthetic deletion-only and one-character fix.
  - **Misses:**
    - 10 of 10 `.pyc` cases;
    - 2 of 10 reformatted hunks (scikit-learn, sympy);
    - 1 of 9 hunks pasted into prose (sphinx).
- **Why `.pyc` misses:** a `.pyc` holds names and constants, not source lines, so tiers 1 and 3 can't match it. The binary tier only scores identifiers or literals of 8+ characters that the fix adds and the base tree lacks. Most real fixes add none (0 items for scikit-learn, matplotlib, astropy), and django's fix has one per hunk, below the 2-item rule. The thresholds were **not** loosened to fit this corpus.
- **D3b and D5a on real environments:** 0 D3b gates across 2,920 compiled libraries in four images. Two D5a false gates were found and fixed: matplotlib and astropy editable installs report the next release as a `.dev` version at the base commit.

### Problems / open questions
- E3's 90% recall target is defined on the **blind** and **real** sets. The blind set needs leaks seeded by someone other than us. The real set (pytest-6202 history, SWE-Bench+ cases, the Cybench config) isn't built yet.
- `.pyc` recall needs another technique, for example fingerprints over each code object's name and constant sequence. Tier 2 (tree-sitter symbols) would help reformatted and prose leaks.
- D3 still reports conda's rewritten sysconfig files as stale, a calibration decision for later.

### Next
- The E3 real set, then the layer index (TR-SC-10) and tier 2.

## 2026-11-11: Phase 0 exit, T1.2 and T1.3 sealcheck, OpenRouter client

- **Phase:** 0 and 1
- **Type:** build + measurement + decision + incident
- **Requirements:** TR-SC-4, TR-SC-6, TR-SC-7 (D1, D3, D6, D9), TR-SC-8
- **Briefs:** `agy-tasks/T0.5`, `T0.6`, `T1.1`, `T1.2`, `T1.2a`, `T1.3`

### Done
- **T0.5, T0.6:** clean grader, oracle, Gemma agent loop, extractor and run record.
- **T1.1:** Rust workspace, `hermetic-common`, sealcheck tier 1, D0, D2, JSON and SARIF.
- **T1.2:** tier 3 winnowing, zip/tar/gz/bz2/xz/zstd/SQLite/`.pyc` scanning with bomb limits, D3, D9.
- **T1.3:** a git object store read with no `git` process, D1 and D6.
- **OpenRouter client** on `t0.7-openrouter`: `run-agent --provider openrouter`, refusing any model without a `:free` suffix.

### Results / measurements
- **Phase 0 exit met.** `django__django-11099` on Gemma 4 31B: `RESOLVED_FULL`, 3/3 `FAIL_TO_PASS`, 19/19 `PASS_TO_PASS`, 9 steps, 1134 s. The oracle passes on 10 of 10 tasks.
- **Agent runs so far:**

| Task | Model | Outcome | Steps | Wall |
|---|---|---|---|---|
| django-11099 | Gemma 4 31B | `RESOLVED_FULL` | 9 | 1134 s |
| sympy-20590 | Gemma 4 31B | `RESOLVED_FULL` | 12 | 912 s |
| pylint-7080 | Gemma 4 31B | `model_error` (HTTP 503), no model reply | 0 | 1342 s |
| scikit-learn-13142 | Gemma 4 31B | `model_error`, no model reply | 0 | 1565 s |
| pylint-7080 | Nemotron 3 Ultra free | `RESOLVED_NO`, hit a 30-step cap | 30 | 141 s |

  A `model_error` with zero steps is an API outage, not a model failure, and isn't a score. Astropy, flask, pytest, sphinx and xarray have cut-off partial runs with no record.
- **sealcheck on real images (T1.3):** all 10 sealed images pass D1, each in under 15 s and about 290 MB. Django's unsealed image is caught by `git_head`, `git_ref`, `git_state_file` and `git_unreachable_object`.
- **Python 3.6 `.pyc`:** after the T1.2a header fix, 7 of 2,375 files in django-11099 are flagged stale.
- **Performance:** a 50 MB synthetic tree scans in 4.23 s (budget 10 s).
- **Tests:** 123 Rust tests pass on `t1.3`; fmt and clippy are clean.

### Decisions
- **Fast track (user):** two tracks at most, and scope sequenced so the leak report comes first. D7, D8, D10, D11, D12 and tier 2 move later. None are cut.
- **Model change (user):** agent runs move to OpenRouter free models. Scores across models must not be combined. Run records name the model.
- **Pylint reran at a 30-step cap**, against 60 for Gemma, to protect the free daily quota. It isn't a like-for-like result.
- **An unsupported pack format gates** instead of being flagged for review, because D1 can't prove anything about a store it can't read. SHA-256 repositories remain `review`, as the brief says.
- **Reviewer-written code:** the T1.3 review fixes and the OpenRouter client were written directly by the reviewer rather than agy, to save time.

### Problems / open questions
- **Memory kills.** Claude Code's safeguard killed background jobs repeatedly near 3–4 GB free, costing about 2.5 h on T1.3. The cause was Rust builds using all 16 threads. Builds are now capped at 4 jobs with debug info off, and T1.3 then built without a kill.
- **D3 calibration:** the 7 stale `.pyc` files in django are conda build and sysconfig files rewritten at install time. They are correctly stale but aren't an answer leak. Decide how to treat them before E3.
- **D6 on sealed images** reports 2026 image dates as `image_only` gates, as expected until Phase 2 flattens the image.
- **Review bugs T1.2 and T1.3 tests missed:** 13 in T1.2 and 21 in T1.3 (12 from reading the code, 9 from CodeRabbit). The largest were every Python 3.6 `.pyc` being misparsed, a text file named `*.idx` stopping D1, and non-UTF-8 commits breaking the reachability walk.

### Next
- T1.4: binary tier, D3b, D5a. Then the E3 corpus and threshold calibration.
- The E3 blind set needs leaks seeded by a second person. Disclosure of a leak report is the user's decision.

## 2026-11-11: T0.3a image sealer accepted, T0.4 frozen index and offline world merged, task swap (Phase 0)

- **Phase:** 0
- **Type:** build + measurement + decision
- **Requirements:** TR-SEAL-1 to TR-SEAL-3 applied to real images; §6.3 package world; §9.6 mini escape probe
- **Briefs:** `agy-tasks/T0.3a-review-fixes.md`, `agy-tasks/T0.4-frozen-index-and-world.md`. agy ran in parallel git worktrees: T0.3a, T0.4 and T0.5 at once; T0.6 later.

### Done
- **T0.3a** (commit 732f960): agy's fixes H1–H7, plus reviewer fixes after the live run.
  - The leak scan covers only objects unreachable from the base, streamed.
  - The report is always written.
  - Executable bits are restored from the base tree.
  - SWE-bench's env-setup edits are allowed only when the original image already had them, and are listed.
- **T0.4** (commit 3299e18, merged in b22878d):
  - `pkg_index.py` builds a PEP 503 index from PyPI files uploaded on or before `T_world`. It excludes the target project and lists packages newer than `T_world` (class B).
  - `world.py` runs the index and the agent container on a `--internal` Docker network, with a probe.
  - Reviewer fixes:
    - `world_exec` enforces timeouts inside the container (process-group kill);
    - the agent container runs with `--init`;
    - PyPI 404s are recorded as `on_pypi: false` instead of aborting.

### Results / measurements
- **All 10 slice images seal and verify.**
  - Sealing: pytest-6202 took 8 s and 320 MB RSS (it ran out of memory before H1). The 8 other images took 3–5 min in total, at about 1.1 GB peak RSS.
  - Before sealing, every image has HEAD on an extra "SWE-bench" commit dated 2026-08, plus a reflog, ORIG_HEAD and COMMIT_EDITMSG. All are gone after sealing.
  - **Leftover future history removed:** sympy-20590 had 59 commits and 33 blobs unreachable from the base; matplotlib-24149 had 89 commits and 20 blobs. No gold line was found in them.
  - **SWE-bench's HEAD commit flips every tracked file to 100755** in 8 of the 9 images it was measured on, with identical content: django 6061 files, matplotlib 4349, pylint 3315, astropy 1861, sympy 1758, sphinx 1470, sklearn 1201, xarray 254. pytest-6202's SWE-bench commit is empty. Without the restore, the agent's `git status` would list thousands of changes.
  - **SWE-bench env-setup edits kept:**
    - astropy: `pyproject.toml` pins `setuptools==68.0.0`;
    - sphinx: `setup.py` pins sphinxcontrib-*, Jinja2 and markupsafe, and `tox.ini` adds `-rA`, which the log parser needs.
- **Official eval scripts offline:** the SWE-bench 5.x dataset `SWE-bench/SWE-bench_Verified` ships each task's `eval_script`, `log_parser` and `eval_type`.
  - Every script's `pip install` line fails offline: build isolation fetches setuptools.
  - The tests still run against the existing editable install: pytest-6202 gold gives 73 passed, 1 xfailed.

### Decisions
- **Replaced `psf__requests-2317` with `pallets__flask-5014`** (user choice). requests' tests call httpbin.org: offline, the gold patch gives 62 failed, 81 passed. flask-5014 passes offline (gold 60 passed; empty patch fails only the `FAIL_TO_PASS` test), and adds a 2023 task. The slice now spans 2019–2023.
- **The grader drops the eval script's reinstall line** (§10: "the grader doesn't reinstall the target package"), and records that it did. Specified in T0.5.
- The agent runs are on **Gemma 4 31B** (`gemma-4-31b-it`) through the Gemini API, 1 run per task (user choice). The key is kept in a user-only file outside the repo.

### Problems / open questions
- The sealed image still has the original layers underneath (Phase 2 flattens it), and file mtimes are 2026 (`clock: real`).
- **Class B:** the env packages are far newer than `T_world` (pytest-6202: attrs 23.1.0, packaging 23.1 and more). They are reported, not rebuilt, because Phase 0 is `repo_only`.

### Next
- Live `build-index` and `world-probe` on all 10 tasks.
- Merge T0.5 (grader and oracle) and run the oracle on every sealed task.
- Merge T0.6 (agent loop) and do one Gemma run per task.

## 2026-11-10: T0.2 task intake (Phase 0)

- **Phase:** 0
- **Type:** build + measurement
- **Requirements:** TR-CUT-1 to TR-CUT-3 fed with real data; §4 thread scrub (the agent never sees `hints_text`)
- **Briefs:** `agy-tasks/T0.2-task-intake.md`; fixes queued in `agy-tasks/T0.2a-review-fixes.md`

### Done
- `http.py`: fetching with a disk cache, retries (2/4/8/16 s on 429, 5xx and timeouts), and a GitHub token sent to `api.github.com` only.
- `intake.py`: loads SWE-bench Verified from the Hugging Face datasets-server, rejecting partial pages and truncated cells. It resolves PR, commit and issue dates from the GitHub API and Django Trac dates from `/ticket/N` (allowed by robots.txt), and reads repo dates from blobless bare clones. It writes `task.json`, `agent/problem_statement.md` and `staging/{gold.patch,test.patch,hints.txt}`.
- CLI: `python -m hermetic_slice intake --tasks phase0/tasks.txt --out … --cache …`.
- `phase0/tasks.txt`: 10 Verified tasks, one per repository, 2014–2022.
- Real-API fixtures recorded by the reviewer in `python/tests/fixtures/intake/`.

### Results
- Tests: **37 passed** on Windows and Linux.
- **Live intake of all 10 tasks: exit 0 in 252 s.** It made about 35 HTTP requests unauthenticated, and the blobless clones total 314 MB. Output is in `~/hermetic/out` (WSL).
- In 9 of 10 tasks, `T_world` is the linked issue's creation date, earlier than the PR in every case. Examples: pytest-6202, issue 11-14 vs PR 11-16; django-11099, Trac ticket 03-15 vs PR 03-20.
- Every `agent/` folder holds only `problem_statement.md`, and no gold-patch line appears in any `task.json`.

### Found by the live run (not catchable by the offline tests)
- **SymPy PR template comment:** `Fixes #1234` sits inside an HTML comment in the PR template. It was harmless only because #1234 is a 2012 PR; had it been an issue, `T_world` would have been 8 years early. This is fix G11.
- **Sphinx links in the title only:** `Fix #8720: …` appears in the PR title, so today the task gets `issue_source: none` and a cutoff 11 minutes late. This is part of G1.
- **Django:** `#N` means a Trac ticket, not a GitHub issue. This is latent for 309 of the 500 Verified tasks (G1).

### T0.2a review fixes (accepted)
- agy fixed G1–G11:
  - Django `#N` and `Refs #N` now map to Trac;
  - PR titles are parsed for every repo;
  - HTML comments are stripped before matching;
  - a 404 or 410 on an issue gives a warning instead of a failure;
  - cache writes are atomic;
  - a missing `num_rows_total` is rejected;
  - existing clones aren't re-fetched;
  - `agent/` and `staging/` are recreated on every run;
  - `issue_source` is written to `task.json`.
- Tests: **46 passed** on Windows and Linux. CodeRabbit: **0 findings**.
- **Live re-run:** exit 0 in **2 s**, since the clones and HTTP cache are reused.
  - All 10 tasks now resolve an issue date, up from 9 of 10.
  - Sphinx-8721 now resolves `github#8720`, moving `T_world` 11 minutes earlier.
  - SymPy-20590 no longer picks up the template's `#1234`.

---

## 2026-11-10: T0.1 cutoffs and repo sealer (Phase 0)

- **Phase:** 0
- **Type:** build
- **Requirements:** TR-CUT-1 to TR-CUT-3, TR-SEAL-1 to TR-SEAL-6 (Python slice versions)
- **Briefs:** `agy-tasks/T0.1-cutoffs-and-repo-sealer.md`, `agy-tasks/T0.1a-review-fixes.md`

### Done
- `python/hermetic_slice/` is a standard-library Python package:
  - `cutoffs.py`: `compute_cutoffs`, implementing the §4 rules including the discard rules for implausible author dates;
  - `gitutil.py`: `run_git`, isolated from the system and global git config and from inherited `GIT_*` variables;
  - `repo_sealer.py`: `seal_repo` (copies only objects reachable from the base commit, filters tags, strips refs, logs, hooks and alternates, repacks) and `verify_sealed_repo` (a mini D1);
  - CLI: `python -m hermetic_slice seal-repo`. Exit codes: 0 on success, 2 on verification failure, 1 on other errors.
- Process: agy wrote T0.1, then Claude reviewed it (10 findings) and CodeRabbit reviewed it (5 findings: 2 new, 3 duplicates). agy fixed all 12 in T0.1a.

### Results
- Tests: **25 passed**, on Windows (Python 3.15, 24 s) and on Linux in WSL (Python 3.14, 2 s).
- The leak test confirms a planted fix string (`SECRET_FIX_7f3a`) is in no object and no file of the sealed repo, and that `src/.git` is byte-identical before and after.

### Decisions
- Phase 0 is written in Python. The spec allows "stock tools" here; the Rust crates start in Phase 1.
- `requires-python >= 3.11`.
- Tagger dates are read as unix timestamps, and annotated tags without a tagger date are dropped (fail closed, reason `no_tagger_date`).
- Submodules and LFS are rejected in Phase 0 (`UnsupportedRepoError`).

### Known gaps (carried forward)
- Tag messages are not yet fingerprint-checked (Phase 1, D-tier).
- Checkout mtimes and `.git/index` stat data carry the real date. That's acceptable at `clock: real` in Phase 0; D4 and the rootfs build fix it later.
- `verify_sealed_repo` runs `git` on the repo it inspects. Phase 1's D1 should parse stored data instead (§5: "inspect stored data, not commands").
- Nitpick for the next task: replace the hand-written `_clean_directory` with `shutil.rmtree` and a permission-fixing error handler.

### Environment
- WSL2 Ubuntu 26.04.1 has 16 CPUs, 10 GB RAM and `/dev/kvm`. Docker 29.1.3 and uv 0.13.7 are installed. WSL auto-updated mid-install once, and the retry succeeded.
- CodeRabbit CLI 0.9.4 and its Claude Code plugin are installed. There is no official CodeRabbit MCP.

---

## 2026-11-10: Project documentation set created

- **Phase:** pre-0
- **Type:** docs

### Done
- Read the full design spec, `HERMETIC_WORLD_ARCHITECTURE.md` (16 sections and 3 appendices).
- Created the derived documents:
  - `README.md`: overview and document map
  - `PRD.md`: problem, users, goals G1–G6, product requirements PR-1 to PR-26, success metrics E1–E10
  - `TRD.md`: stack, enums, per-component requirements (TR-*), formats, security, performance
  - `ARCHITECTURE.md`: rings, lifecycle, subsystems, interfaces, 12 design invariants, decision table
  - `PHASES.md`: phases 0–4 with deliverable checklists and exit criteria
  - `BUILD_LOG.md`: this file

### State
- No code, images or supporting files exist yet. The spec's Appendix A files (`firecracker-enforce-pv-cpuid.patch`, `hide-kvmclock.cpu-template.json`, `clock-leak-probe.md`) are described as written, but they aren't in this directory.
- Not a git repository yet.

### Open questions
- Where are the Appendix A supporting files? Bring them into `vmm/` and `tests/`.
- Phases 0–1 are specced to run on "the MacBook". Confirm the dev machine for those phases.
- Phase 3+ needs Linux x86_64 with KVM. Choose between bare metal and EC2 with nested virtualization.

### Next
- Start Phase 0: choose the 5–10 SWE-bench Verified slice tasks.
