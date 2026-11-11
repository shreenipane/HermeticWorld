# Hermetic World: Handoff

Written 2026-11-11 before the laptop moves from Windows (WSL2) to native **Ubuntu 26.04 LTS**. Read this first in any new session, then `BUILD_LOG.md` (newest first) and `PHASES.md`.

## Where things stand

- **Overall:** about 20 of 100 by effort.
  - Phase 0 (vertical slice) is done.
  - Phase 1 (sealcheck) is roughly half done.
  - Phases 2, 3, 3b and 4 haven't started.
- **Repository:** `https://github.com/shreenipane/HermeticWorld` (private). `main` holds everything reviewed.
- **sealcheck:** 158 Rust tests, plus 56+ Python tests.
  - Detectors done: D0, D1, D2, D3, D3b, D5a, D6, D9.
  - Tiers done: tier 1, tier 3 and the binary tier; archive, SQLite, git-pack and `.pyc` reading.
- **E3, first run on 175 seeded cases:** precision 100% (95% interval 96.7–100%), recall 89.8% (83.3–93.9%). The `.pyc` gap and its cause are in `BUILD_LOG.md`.
- **Agent runs:** two `RESOLVED_FULL`, both on Gemma 4 31B (django-11099, sympy-20590). Most others failed on API errors or quota. See the table in `BUILD_LOG.md`.

### Branches

| Branch | State |
|---|---|
| `main` | Reviewed and merged work |
| `t1.6` | **In progress:** layer index and per-task query (TR-SC-10). Its WIP commit is unreviewed and may not compile. The brief is `agy-tasks/T1.6-layer-index.md` |
| `t0.6`, `t0.7-openrouter`, `t1.1` … `t1.5` | Merged; kept for history |

## Rules for this project (the user's standing instructions)

1. **Never credit Claude in commits or PRs.** No `Co-Authored-By` or `Claude-Session` lines. GitHub must show the user as the only contributor.
2. **Publish everything to GitHub as it lands.** No force-pushes. Scan for API keys before every push. Keys never enter the repository.
3. **Lossless:** never cut scope. Deferred items stay in `PHASES.md`.
4. **Workflow:** agy (Antigravity CLI) writes code from a brief in `agy-tasks/`. Claude reviews every line, CodeRabbit (`coderabbit review --agent`) reviews after, and fixes come with regression tests.
5. **Merge reviewed branches to `main` without asking.** The user granted this on 2026-11-11.
6. **Free-tier models only** for agent runs. Never spend money.
7. **The user decides:** any disclosure of a leak report to benchmark maintainers.

## Rebuilding on native Linux

### Toolchain
```bash
sudo apt install -y build-essential git curl python3 python3-venv docker.io e2fsprogs
sudo usermod -aG docker $USER            # log out and back in
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
curl -LsSf https://astral.sh/uv/install.sh | sh
mke2fs -V                                 # the spec needs e2fsprogs >= 1.47.1
git clone https://github.com/shreenipane/HermeticWorld.git
cd HermeticWorld && bash scripts/test-rust.sh
cd python && python3 -m venv .venv && .venv/bin/pip install pytest && .venv/bin/python -m pytest -q
```
Also install CodeRabbit CLI and agy. agy on Linux is **unverified**. If it isn't available, Claude writes the code and CodeRabbit still reviews.

### Secrets (never in Git)
Create these with mode 600:
- `~/.hermetic/secrets/gemini_api_key`
- `~/.hermetic/secrets/openrouter_api_key`

The keys are on the user's backup drive, or re-issue them. Both were pasted in chat, so **rotate them when the project ends**. The key-file environment variables are `HERMETIC_GEMINI_KEY_FILE` and `HERMETIC_OPENROUTER_KEY_FILE`.

### Data (it lived in WSL under `~/hermetic/out`; rebuild if no backup)
Output root: `~/hermetic/out`. About 60 GB of Docker images plus about 14 GB of data.
```bash
cd python
O=~/hermetic/out
python3 -m hermetic_slice intake --tasks ../phase0/tasks.txt --out $O/tasks --cache $O/cache
python3 -m hermetic_slice seal-images --tasks-dir $O/tasks --work $O/seal-work
python3 -m hermetic_slice fetch-eval-specs --tasks-dir $O/tasks --cache $O/cache
python3 -m hermetic_slice build-index --tasks-dir $O/tasks --cache $O/cache
python3 -m hermetic_slice world-probe --tasks-dir $O/tasks
python3 -m hermetic_slice oracle --tasks-dir $O/tasks        # expect 10/10 oracle_ok
python3 -m hermetic_slice e3-basetrees --tasks-dir $O/tasks --out $O/e3/basetrees
python3 -m hermetic_slice e3-build --tasks-dir $O/tasks --base-trees $O/e3/basetrees --out $O/e3/corpus --seed 20261111
```
If `seal-images` doesn't pull the source images itself, pull them first: `docker pull swebench/sweb.eval.x86_64.<repo>_1776_<id>:latest`.

### Agent runs
```bash
HERMETIC_OPENROUTER_KEY_FILE=~/.hermetic/secrets/openrouter_api_key python3 -m hermetic_slice run-agent \
  --provider openrouter --model nvidia/nemotron-3-ultra-550b-a55b:free --max-steps 30 \
  --tasks-dir ~/hermetic/out/tasks --runs-dir ~/hermetic/out/runs --only <id>
```
The free daily quota allows about one 30-step run. Waiting for the 00:00 UTC reset is better than starting a run that will die halfway.
- Still owed one run each: xarray-4094, flask-5014, pytest-6202, sphinx-8721, astropy-12907, matplotlib-24149.
- Scikit-learn's run died on the quota mid-run. Retry it.

## Lessons from the Windows period
- **Rust builds drained memory** at the default of 16 parallel jobs. Use `CARGO_BUILD_JOBS=4`, `CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0`. Give each worktree its own `CARGO_TARGET_DIR`: a shared one linked tests against another branch's build.
- **agy reported success on code that didn't compile** in the shared-target case. Always run the gate yourself.
- **Real-image scans find what tests don't:** a Python 3.6 `.pyc` header bug, non-UTF-8 commits, and D5a on setuptools_scm versions. Re-check each new detector against sealed and unsealed images.

## Next, in order
1. Finish, review and merge T1.6 (layer index; a query must take under 5 s).
2. The E3 real set: pytest-6202 history, SWE-Bench+ cases, the Cybench config.
3. Tier 2 (tree-sitter IDF symbols, review flag). Then D4, D5b, D7, D8, D10, D11, D12.
4. `.pyc` recall: fingerprints over each code object's name and constant sequences.
5. D3 calibration: conda rewrites sysconfig files, which then read as stale.
6. Phase 2 needs a reliable model endpoint for the 50–100 task ablation. Free tiers are too small.
7. Phase 3: Firecracker with KVM now runs natively. Phase 3b (clock hiding) needs the host kernel, which native Linux now allows.

## Needs the user
- Blind-seeded E3 leaks from a second person.
- The decision on disclosing a leak report.
- Rotating the API keys at the end.
