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
