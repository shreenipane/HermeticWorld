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
