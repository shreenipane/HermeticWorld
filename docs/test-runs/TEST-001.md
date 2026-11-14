# Test #1: first agent run on a real sealed task

**Status: RESOLVED.** Designated the official Test #1 by the project owner on 2026-11-14.

| Field | Value |
|---|---|
| Date | 2026-11-14, about 01:05 to 01:45 IST |
| Task | `pytest-dev__pytest-6202` (SWE-bench Verified) |
| Problem statement | GitHub issue #6189, revision `as_scraped`: the edit history was verified, there were no edits after the cutoff, 2,156 bytes, no warnings |
| World date | Cutoffs from intake: issue created 2019-11-14T13:11:34Z |
| Image | `hermetic/pytest-dev__pytest-6202:sealed`, built by `hermetic_slice seal-images` from `swebench/sweb.eval.x86_64.pytest-dev_1776_pytest-6202:latest` |
| Oracle (E4) | Passed: the gold patch passed with 0 FAIL_TO_PASS and 0 PASS_TO_PASS failures; the empty patch failed FAIL_TO_PASS |
| Execution | Docker container from the sealed image, `--network none --init`, working directory `/testbed` |
| Calls | 27, then the agent submitted |
| Patch | `TEST-001.patch` (sha256 `0e1188c6885ceaf77a5242a6d65629d9a3bff7ea0725d222bbb966b760ddbf48`) |
| Grade | `hermetic_slice.grader.grade` in a fresh container with no network: **resolved**. FAIL_TO_PASS 1/1 passed; PASS_TO_PASS 72/72 passed, no regressions |
| Cost | $0 |

## What the agent did
It explored pytest's collection code, found that `PyobjMixin.getmodpath` in `src/_pytest/python.py` replaced `".["` with `"["` and so corrupted test IDs such as `test_boo[..[]`, and removed the replacement. This is the same change as the upstream fix. It also added a long explanatory comment, one line of which is mis-indented; that is harmless because it is a comment.

## What this run does and does not show
- **Shows:** the chain works end to end on real data. Intake verifies the statement, the image is sealed, the oracle passes, an agent works in a no-network sealed world, and an independent grader gives the verdict.
- **Does not show:** that the world is leak-free.
  - The Phase 0 container shares the host's real clock.
  - Provider calls bypassed `hermetic-gateway`.
  - The VM-based Mode H run and the exit measurements (E1, E8, E9) are the leak tests.
- **Contamination caveat:** training postdates 2019 and may include this fix. Sealing hides the environment; it does not erase memorised solutions.

## Earlier attempts (not counted)
1. The problem statement was empty because intake excluded the unverifiable statement when no GitHub token was configured. This found a bug: agents must refuse an empty statement (fix in progress).
2. A free daily request cap was reached.
3. A free-tier limit of 8,000 tokens per minute was too small for an agent run.
4. Free-tier limits of 5 requests per minute and 20 requests per day were too small for a full run.
