# Hermetic World: Phases

- **Status:** derived from §15 of [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md). Requirement IDs refer to [TRD.md](TRD.md).
- **Last updated:** 2026-11-14

Tick items off here as they land, and log each one in [BUILD_LOG.md](BUILD_LOG.md).

## Verified checklist counts

Counts include nested checklist items. Checked items cite merged tests or named historical manager smokes; historical smoke evidence is not a new run. Unchecked items state what remains. Component tests do not certify whole-phase exit criteria.

| Phase | Verified checklist |
|---|---|
| 0: Vertical slice | done 10 of 10 |
| 1: sealcheck | done 30 of 43 |
| 2: World | done 4 of 43 |
| 3: VMs | done 10 of 35 |
| 3b: Clock hiding | done 13 of 16 |
| 4: Extensions | done 0 of 9 |

## Overview

| Phase | Name | Runs on | Exit criterion | Status |
|---|---|---|---|---|
| 0 | Vertical slice | WSL2 Ubuntu + Docker | Oracle passes on every slice task; one agent run graded | **Done** 2026-11-11 |
| 1 | sealcheck | Laptop (no KVM) | E3 targets met; leak report on one public benchmark, disclosed privately | In progress |
| 2 | World | Any Linux box | E4 ≥ 99%; E2 Track A on the paired subset; E10 | In progress |
| 3 | VMs | Linux x86 + KVM | E1, E8, E9 | In progress |
| 3b | Clock hiding (host filter required in v1) | Linux x86 + KVM | Probe passes → `clock: hidden` (else ship `faked`) | **Probe passes** in the nested VM 2026-11-14 (all records blocked; hypercall covered by the ring-0 canary); integration pending |
| 4 | Extensions | Linux x86 + KVM | E2 Track B; E5 | Not started |

```
0 ──▶ 1 ──▶ 2 ──▶ 3 ──▶ 3b
                   └───▶ 4
```

**Cut list.** If time runs out, drop in this order: Phase 4 → Mode G → R3 → R2. Phase 3b host filtering is required in v1 (owner decision 2026-11-14).

**Smallest publishable result:** the Phase 1 leak report plus the Phase 2 ablation (E2 Track A).

---

## Phase 0: Vertical slice

**Goal.** Run 5–10 SWE-bench Verified tasks end to end with stock tools, to prove the pipeline shape before building any component properly.

**Runs on.** A laptop, in containers, with `clock: real`.

### Deliverables
- [x] Pick 5–10 SWE-bench Verified tasks, spread across repositories and years: 10 tasks in `phase0/tasks.txt`, one per repo, 2019–2023. On 2026-11-11 requests-2317 was replaced by flask-5014, because its tests need httpbin.org. Proof: `phase0/tasks.txt` intake smoke (BUILD_LOG.md, Phase 0 exit).
- [x] Image sealer (T0.3/T0.3a): all 10 real images sealed and verified. It removes the extra SWE-bench commit, the reflog and future history, and restores file modes. Proof: `test_seal_image_end_to_end` (`python/tests/test_image_sealer.py`); all-image sealing smoke recorded in BUILD_LOG.md.
- [x] Minimal cutoff computation (`T_world`, base commit, `T_clock`): done; T0.2 intake feeds it real GitHub, Trac and git dates for all 10 tasks. Proof: `test_pytest_6202_end_to_end`, `test_django_11099_trac_intake` (`python/tests/test_intake.py`).
- [x] Repo sealer: reachable-objects copy, tag filter, strip refs and reflog (TR-SEAL-1 to TR-SEAL-3, TR-SEAL-6), done in T0.1, 25 tests. Proof: `test_seal_repo_completeness_and_isolation` (`python/tests/test_repo_sealer.py`).
- [x] Local frozen pip index at the cutoff (T0.4; PEP 503 index of PyPI files uploaded at or before `T_world`, up to 5 versions per installed package, target project excluded; all 10 tasks, 25 MB to 1.5 GB each, 4.4 GB total). Proof: `test_build_index_with_py_fixture` (`python/tests/test_pkg_index.py`); ten-task index build smoke in BUILD_LOG.md.
- [x] Docker network with no outside route; the agent container reaches only the index (T0.4; `world-probe` all_ok: positive install, newer version blocked, target blocked, egress blocked). Proof: `test_world_lifecycle_and_probe` (`python/tests/test_world.py`).
- [x] Clean container as grader: apply the extracted diff, run `FAIL_TO_PASS` and `PASS_TO_PASS` (T0.5; official SWE-bench eval scripts minus the pip line, swebench 5.0.2 grading rules). Proof: `test_docker_grade_and_oracle_integration` (`python/tests/test_grader.py`).
- [x] Unsigned JSON run record (T0.6; `hermetic-slice-run/v0-unsigned`). Proof: `test_extract_failure_still_writes_run_record`, `test_grade_failure_still_writes_run_record` (`python/tests/test_runner.py`).
- [x] Oracle run: the gold patch passes in the sealed world for every slice task (10/10 on 2026-11-11; django-11099 lists one FAIL_TO_PASS test that already passes without the fix, recorded as `f2p_pass_without_fix`). Proof: ten-task oracle smoke, 10/10 (BUILD_LOG.md, Phase 0 exit).
- [x] One real agent run, graded: django-11099 on Gemma 4 31B, `RESOLVED_FULL`. Proof: django-11099 graded-run smoke, 3/3 FAIL_TO_PASS and 19/19 PASS_TO_PASS (BUILD_LOG.md, Phase 0 exit).

### Exit
The oracle passes on every slice task, and one agent run is graded.

### Learn and record
- Which slice tasks needed a `pkg_cutoff` raise
- Install misses against the frozen index
- Rough timings, as a baseline for E6

---

## Phase 1: sealcheck

**Goal.** A standalone leak scanner good enough to publish a leak report on its own.

**Runs on.** A laptop.

### Deliverables
- [x] `hermetic-common`: manifest types, cutoff logic (TR-CUT-*), hash chain (T1.1). Proof: `test_earliest_candidate_wins`, `test_hash_chain_vectors_and_tamper` (`crates/hermetic-common/tests/`).
- [x] Both modes: dated and undated (TR-SC-9). Proof: `test_scan_and_query_undated_equivalence`, `test_dated_scan_json_unchanged_no_mode` (`crates/hermetic-sealcheck/tests/test_undated.rs`).
- [ ] remaining: Fingerprints with baseline subtraction (TR-SC-1)
  - [x] Tier 1: lines, windows, diff shape, diff-like text (TR-SC-2) (T1.1). Proof: `test_no_false_positive_at_base_and_planted_findings` (`crates/hermetic-sealcheck/tests/test_fingerprint_and_scan.rs`).
  - [x] Tier 2: tree-sitter IDF symbols, as review (TR-SC-3). Proof: `test_tier2_multi_hunk_results_unchanged_with_precomputed_context` (`crates/hermetic-sealcheck/tests/test_tier2.rs`).
  - [x] Tier 3: winnowing, k=8, w=8 (TR-SC-4) (T1.2). Proof: `test_winnow_baseline_subtraction_gives_zero_gates`, `test_winnow_planted_reformatted_copy_gives_tier3_gate` (`crates/hermetic-sealcheck/tests/test_winnow.rs`).
  - [x] Binary tier (TR-SC-5) (T1.4; `.pyc` code-object fingerprints T1.12). Proof: `test_real_pyc_of_the_fix_gates_on_the_binary_tier`, `test_hostile_binaries_none_may_panic` (`crates/hermetic-sealcheck/tests/test_binary.rs`).
    - [ ] remaining: Deferred (T1.12 review): both 20,000-function budget tests exhaust a budget of 1,000 during changed-scope discovery; add a sufficiently budgeted test that completes extraction for every changed or added function
    - [ ] remaining: Deferred (T1.12 review): reports still declare `"T2"` uncovered for fresh version-5 indexes, which do store and query tier-2 context; report coverage by index version, and correct the documentation
    - [ ] remaining: Deferred (T1.12 review): `extract_hunk_symbols_and_anchors` in `tier2.rs` is quadratic in hunk count
    - [ ] remaining: Deferred (T1.12): add a licence note for `crates/hermetic-sealcheck/data/unicode_names.txt` (Unicode 16.0.0 name data, generated by `data/gen_unicode_names.py`; Unicode licence applies)
- [x] Container recursion with bomb limits, including git packs (TR-SC-6) (T1.2, T1.3). Proof: `test_containers` and `test_gitstore` suites (`crates/hermetic-sealcheck/tests/`).
- [ ] remaining: Detectors D0–D12 (TR-SC-7): implemented D0, D1, D2, D3, D3b, D4, D5a, D5b (`python/hermetic_d5b`), D6, D9, D11. Detector audit (2026-11-13):
  - [x] D4: live file/directory/symlink mtimes, tar/zip member times, index equivalence, ext4 inode/superblock times; bounded no-follow image reads; dirty journals refused; malformed images report Info and exit 1. Proof: `test_ext4_mke2fs_suite`, `test_live_tree_symlink_late_mtime` (`crates/hermetic-sealcheck/tests/test_d4.rs`).
  - [ ] remaining: D7: `python/hermetic_d7` compares supplied shipped/rebuilt artifacts with bounded ingestion. Open: no `--deep-audit` rebuild orchestration; requires the sealer's build recipe/artifact mapping and isolation contract (TR-SC-7).
  - [ ] remaining: D8: os-release, tzdata, certificates, kernel/config dates, dated logs, Python versions implemented; bounded no-follow I/O and stable relative findings. Open: kernel-image build-string extraction and CPU-template coherence checks require specified artifact paths/formats and a historical CPU policy (architecture detector table); the current kernel checks read module directory versions and config headers.
  - [ ] remaining: D10: `python/hermetic_d10` implements archive/metadata times and bounded WARC-Date checks for every record, including gzip/nested captures; malformed captures fail closed. Open: per-record payload fingerprints and verification of thread scrub/revision provenance require integration with the fingerprint scanner and archive provenance contract (architecture detector table, §4).
  - [x] D11: advisory patch inspection, test-infrastructure paths, runner sections, monkeypatching and shadowing; standard unified diffs and quoted paths supported; bounded CLI/library inputs. Proof: `test_d11_cli_execution_and_json_shape`, `test_d11_monkeypatch_rules` (`crates/hermetic-sealcheck/tests/test_d11.rs`).
  - [ ] remaining: D12: advisory text/file scanner implemented with bounded no-follow traversal. Open: host run/probe/gateway integration scanning every guest egress and prompts, and recording `date_leak_observed`, is not wired (TR-SEC-5). `python/hermetic_slice/runner.py` still emits null; the attestation field alone does not implement the sentinel.
  - [ ] remaining: Shared path policy: decide whether to reject non-UTF-8 roots/paths or encode their bytes losslessly across scan, index and SARIF. D4/D8 currently normalize rendered strings against the original root; a non-UTF-8 root can retain its host prefix, and lossy path identities can collide.
  - [x] Prior gate findings: queued-directory checks include ctime, and E3 patch application stops enclosing-repository discovery. Proof: `test_queued_directory_reused_inode_rejected` (`python/tests/test_dispositions_review.py`), `test_patch_application_with_worktree_local_tmpdir` (`python/tests/test_e3.py`).
- [x] Thread scrub and mutable-content revision rule (TR-SEAL-9) (T1.13). Proof: `test_intake_task_with_thread_scrub_and_revision` (`python/tests/test_thread_scrub.py`).
  - [x] Deferred (T1.13 review, non-blocking): scrub URL matching misses aliases of the same resource (`www.github.com`, `http://`, trailing-dot host, empty path segments, `/repositories/{id}/...`); canonicalise or deny them before a WorldServer maps aliases to stored content — aliases canonicalised; unverifiable repository-ID routes denied; regression cases added. Proof: `test_scrub_resource_aliases_denied` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Deferred (T1.13 review): the CLI secret-safety test calls `intake` with arguments the parser rejects, so the exception path is never exercised; use valid arguments and assert the mock ran — valid CLI arguments, mocked dataset, call and error-output assertions. Proof: `test_defect4_secret_markers_never_in_exceptions_or_cli_output` (`python/tests/test_thread_scrub_security.py`).
  - [x] Deferred (T1.13 review): `open_secure_directory` refuses operator-supplied roots that traverse symlinks; decide whether a trusted prefix may be resolved (no-follow stays for everything beneath it) — fail closed: physical paths required throughout; documented and tested. Proof: `test_secure_root_symlink_policy` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Deferred (T1.13 review): task publication wraps every failure as `task_publication_failed` and drops the cause; pass `IntakeError` through and keep the error class — typed intake failures preserved; unexpected exceptions remain sanitised; stale-tree cleanup now has entry/depth caps and checks opened directory identity. Proof: `test_publication_preserves_intake_error`, `test_publication_cleanup_has_named_caps`, `test_cleanup_directory_replacement_is_rejected` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Deferred (T1.13 review): decide whether the scrub fallback paths should return the as-scraped statement with `problem_statement_revision = as_scraped` and a warning (today they exclude content) — retain exclusion per §4: no verified history means no content; tested with GitHub alias denial. Proof: `test_unverifiable_fallback_markers_never_reach_files` (`python/tests/test_thread_scrub_security.py`).
  - [x] Deferred (T1.13 review): fixture `pytest_issue_6189_edits.json` has a creation edit dated before the issue's creation; the cache case in `test_http.py` can pass before the bounded-read check — impossible edit removed; cache-growth case now asserts bounded_read executed. Proof: `test_creation_revision_fixture_is_chronological`, `test_cache_read_reaches_bounded_read` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Docker fixture names isolated per run. Proof: `test_fake_swebench_runs_build_and_remove_only_owned_tags`, `test_sealer_runs_use_distinct_output_tags_and_owned_cleanup` (`python/tests/test_sealer_test_isolation.py`), `test_world_probe_name_unique_per_run` (`python/tests/test_world.py`).
- [x] Dispositions: `repaired` / `excluded`, never silent (§5.5) (T1.14). Proof: `test_cli_end_to_end_real_rescan_repaired_and_excluded` (`python/tests/test_dispositions.py`).
  - [x] Deferred (T1.14 review, non-blocking): a report with an inline manifest is rejected on rerun after publication changed the disk manifest, so an interrupted repair cannot finish in that case; reconcile the inline manifest with verified repair metadata — only the verified repair transition is reconciled; interrupted and complete reruns tested. Proof: `test_inline_manifest_repair_rerun` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Deferred (T1.14 review): Python checks UTF-8 span boundaries after merging spans (`redact_problem_statement("é", [(0,1),(1,2)])` succeeds; Rust rejects); validate every supplied boundary first — all original boundaries checked, including adjacent and nested spans. Proof: `test_redaction_rejects_utf8_interior_boundaries` (`python/tests/test_dispositions_review.py`).
  - [x] Deferred (T1.14 review): Python and Rust count surviving characters differently (literal `[REDACTED]` in the original, whitespace definition incl. U+001C–U+001F); specify one rule and add cross-language cases — count original surviving Unicode scalars outside explicit Unicode White_Space; matching known cases in both languages. Proof: `test_surviving_characters_shared_with_python` (`crates/hermetic-common/tests/test_dispositions.rs`).
  - [x] Deferred (T1.14 review): empty spans are accepted during repair but rejected by persisted-metadata validation, so every later rerun fails; reject them before publication — empty spans rejected before merging in both languages. Proof: `test_empty_spans_rejected_before_merging` (`crates/hermetic-common/tests/test_dispositions.rs`).
  - [x] Deferred (T1.14 review): every replaced file becomes mode 0600, including an originally 0644 problem statement, so a runner under another uid cannot read it; preserve statement permissions — checked descriptor supplies statement permissions; private metadata stays 0600; reruns tested. Proof: `test_repair_preserves_statement_permissions` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Deferred (T1.14 review): an unusable explicit `--sealcheck` path silently falls back to PATH and developer locations; fail instead — explicit executable failure stops resolution; no fallback call. Proof: `test_explicit_binary_path_never_falls_back` (`python/tests/test_deferred_t113_t114.py`).
  - [x] Deferred (T1.14 review): clean tasks get a manifest `clean` disposition although TRD §2 allows only `repaired` and `excluded`, which also changes an unchanged world's root; keep `clean` in the per-run report only — manifest enum rejects clean; clean processing preserves the root. Proof: `test_clean_disposition_rejected_in_manifest` (`crates/hermetic-common/tests/test_dispositions.rs`).
  - [x] Deferred (T1.14 review): excluding a previously repaired task appends to the manifest, leaving both statuses; separate repair history from the current disposition — only current status in dispositions; root-bound repair_history in exclusion detail; repeated exclusion and re-verification tested. Proof: `test_regression_defect5_previously_repaired_task_receives_d2_exclusion_without_scan_config` (`python/tests/test_dispositions_review.py`).
  - [x] Deferred (T1.14 review): missing tests for the merged mode-restore script (`RESTORE_MODES_SH`): replacement between stat and open, fstat hard-link rejection, stalled `git ls-tree` with child termination, ancestor swap, and a FIFO-replacement test that runs the real script with an outside sentinel (the current race section tests its own `os.open` flags) — real shell-script race tests cover all cases, unchanged sentinel modes/content, and killed/reaped child. Proof: `test_restore_script_replacement_races_preserve_outside_sentinel`, `test_restore_script_stalled_ls_tree_kills_and_reaps_child` (`python/tests/test_restore_modes_deferred.py`).
- [x] JSON and SARIF output; exit code 2 on an agent-visible gate finding (TR-SC-8) (T1.1). Proof: `test_cli_execution`, `cli_sarif_query_and_scan_properties` (`crates/hermetic-sealcheck/tests/`).
- [x] Layer index plus per-task query, under 5 s (TR-SC-10). Proof: `perf_query_50mb_5000_files_under_5s` (`crates/hermetic-sealcheck/tests/test_index.rs`).
- [ ] remaining: E3 corpus: seeded leaks (done, T1.5: precision 100%, recall 89.8% on 175 cases), blind-seeded leaks from a second person, and real leaks (pytest-6202, SWE-Bench+ cases, the Cybench config), including deletion-only and one-character fixes, patch files, archives and SQLite
- [ ] remaining: Calibrate the tier-1 and tier-2 thresholds against E3

### Exit
- E3: gate precision ≥ 95% and recall ≥ 90% on the blind and real sets.
- A leak report on one public benchmark, disclosed privately to its maintainers.

---

## Phase 2: World

**Goal.** Full world construction with a real WorldServer and gateway, still on containers. Produces the headline ablation.

**Runs on.** Any Linux box.

### Deliverables
- [x] Rootfs build with `SOURCE_DATE_EPOCH` mke2fs (e2fsprogs ≥ 1.47.1) and a D4 guard (TR-SEAL-7, TR-SEAL-8) (T2.4; tar stream into `mke2fs -d`, pinned e2fsprogs 1.47.2 and `data/mke2fs-hermetic.conf`). Proof: `test_synthetic_tree_mtimes_clamped_passes_d4`, `test_reproducibility_tr_seal_12` (`python/tests/test_rootfs.py`).
  - [ ] remaining: Decision to confirm (T2.4): the image keeps no extended attributes; mtimes are clamped to min(source, T_clock); source paths with symlinked ancestors are refused
  - [ ] remaining: Deferred (T2.4): `_make_output_dirs` still creates missing output directories by path (the directory is then opened anchored and checked before any write)
  - [ ] remaining: Deferred (T2.4): `_make_writable_and_retry` in `repo_sealer.py` is no longer used by production code; remove it together with the tests that call it directly
  - [ ] remaining: Deferred (T2.4): the simulated-other-uid test stubs the storage ownership checks
- [ ] remaining: Open, postponed by the owner on 2026-11-12 (T2.2): gateway deadline handling. `test_8_stalled_clients_are_dropped_at_the_deadline_and_service_recovers` failed once in a full workspace run; investigation found no slot leak (load timing, inferred, not reproduced) but a real defect: the next request's head deadline is armed at hand-off and overwrites the current request's body deadline (body deadline cut to the head deadline; kept-alive connections closed after any request longer than the head deadline). A first fix is on branch `t2.2` (`b0c7867`, not merged) and was rejected in review: its wait for request completion is unbounded (a retained writer plus a client disconnect parks the connection thread forever), two loosened timing tests no longer prove their deadline, and the two new regressions are not deterministic. Review: `t2.2-codex-deadline-rearm-20261112`
  - [ ] remaining: Also found by CodeRabbit on main (2026-11-12): keep the body deadline active until the body reader finishes (`crates/vendor/tiny_http/src/client.rs:162`); do not release a successor before its predecessor finishes (`util/sequential.rs:172`); do not block while dropping a waiting reader (`util/sequential.rs:159`). Details: `cr-main-crates-20261112.log`
- [ ] remaining: Package world (TR-PKG-*)
  - [ ] remaining: Layer 1: recording index for the task closure (pip, uv, conda via pixi)
  - [ ] remaining: Yanked-release handling (simple-index yank rewriting in `python/hermetic_yank`, merged 2026-11-13; wiring into the package mirror still open)
  - [ ] remaining: Layer 2: ecosystem baseline per cutoff month; measure its storage
  - [ ] remaining: apt snapshots where available
- [ ] remaining: Ecosystems: PyPI, conda, Debian/Ubuntu, git dependencies (static mirrors)
- [ ] remaining: `strict` class B rebuild, with `repo_only` fallback and labelling
- [x] WorldServer: read-only store, Landlock, seccomp, frames, limits, hash log, dedupe index (TR-WS-*) (T2.1). Proof: `test_store_and_responses`, `test_sandbox`, `test_limits`, `test_log_and_dedupe` suites (`crates/hermetic-world-server/tests/`).
  - [ ] remaining: Deferred (T2.1 review, non-blocking): endpoint probes use a blocking `UnixStream::connect` against a lock listener that never accepts; repeated recovery attempts on one endpoint can fill the backlog and block startup; use non-blocking exclusive ownership
  - [ ] remaining: Deferred (T2.1 review): the live-endpoint test passes `--recover` without `--resume-log`, so it is rejected before endpoint ownership is checked; give it valid recovery inputs and assert the original listener still serves
  - [ ] remaining: Deferred (T2.1 review): the seccomp allow-list still permits arbitrary Unix-socket connects, signalling other same-uid processes, credential-changing syscalls and `clock_settime`; remove them and test denial
  - [ ] remaining: Deferred (T2.1 review): the Landlock failure-injection test sets a process-global flag while other tests start sandboxed servers; isolate it in a child process
  - [ ] remaining: Deferred (T2.1 review): no test stalls a child, thread or socket to prove the bounded test helpers actually time out
  - [ ] remaining: Deferred (T2.1): publication and endpoint reclaim trust same-uid processes and root (directories must be owned by the server uid and not group/other writable); `renameat2(RENAME_NOREPLACE)` is not used because the crate forbids unsafe code
- [x] Trust injection: per-world CA, every trust store, environment defaults (TR-SEAL-10) (T2.5). Proof: `test_fake_rootfs_install`, `test_seed_file_validation_and_private_key_permissions` (`crates/hermetic-trust/tests/test_trust.rs`).
  - [ ] remaining: Deferred (T2.5 review, non-blocking): a duplicate-alias error copies keystore alias text (incl. control characters) into `skipped_paths.reason` and reports; return a fixed code
  - [ ] remaining: Deferred (T2.5 review): certificate validation gaps: unique-ID fields skipped unvalidated, BOOLEAN accepts any non-zero byte, `pathLenConstraint` checked by tag only, critical SAN/SKI/AKI payloads not validated
  - [ ] remaining: Deferred (T2.5 review): the process-global test hooks `FORCE_CHOWN_FAILURE` and `BEFORE_USE_HOOK` are public and consulted in production paths; move injection to test-only, per-thread code
  - [ ] remaining: Deferred (T2.5 review): CA seed and plaintext key PEM buffers are not zeroised; two guarded `unwrap()` calls remain; no compile-failure check for unsupported targets
  - [ ] remaining: Deferred (T2.5): on-disk ownership with a guest owner different from the sealing user is tested only by recording the ownership step, because this host cannot create user namespaces; run `test_created_entries_owned_by_guest_owner_in_user_namespace` where `unshare -Ur` works
  - [ ] remaining: Deferred (T2.5, owner decision): the installer's check-then-use protection assumes exclusive access to the rootfs; the full fix needs `openat2`/`cap-std` (new dependency)
- [ ] remaining: Gateway with the Anthropic adapter (TR-GW-*)
  - [ ] remaining: Policy core: default-deny adapter, request and response rewriting, quotas, history, streaming (TR-GW-2 to TR-GW-8) (T2.2). Proof: `test_sse_streaming_timestamp_rewrite_and_token_counting` plus request/response/quota suites (`crates/hermetic-gateway/tests/`). Current full Rust gate exposed a test synchronization race: `test_sse_streaming_timestamp_rewrite_and_token_counting` reads finalized quota totals immediately after response EOF, before `record_and_release` runs (`server.rs:973-974`); observed 0 instead of 25 input tokens. Requires gateway-component test synchronization; existing assertions retained.
  - [ ] remaining: Gateway isolation (TR-GW-1)
  - [ ] remaining: Deferred (T2.2 review): operator config and API-key paths are opened without refusing symlinked ancestor directories
  - [ ] remaining: Deferred (T2.2 review): quota errors expose internal reasons and configured limits instead of standard messages
  - [ ] remaining: Deferred (T2.2 review): source validation traverses arbitrary tool inputs and schemas, so a legitimate tool argument shaped like a URL image source is refused
  - [ ] remaining: Deferred (T2.2 review): every read failure on a successful upstream response is classified as a timeout (e.g. invalid UTF-8)
  - [ ] remaining: Deferred (T2.2 review): original SSE error bodies are never logged (`original_error_body` is always `None` for streams)
  - [ ] remaining: Deferred (T2.2 review): an unrecognised upstream error type falls back to the HTTP-status-derived type instead of `api_error`
  - [ ] remaining: Note (T2.2): `tiny_http` 0.12.0 is vendored with local patches at `crates/vendor/tiny_http` (see `VENDORED.md`); a half-closed client never frees its slot before the upstream ends, and a waiting request gets a bounded 529
- [ ] remaining: Container isolation of the agent, with the run spec applied
- [x] Manifest with `world_root`. Proof: `test_known_answer_root`, `test_inclusion_proofs_for_every_leaf` (`crates/hermetic-common/tests/test_world_manifest.rs`).
- [ ] remaining: Reproducibility check (E7)
- [ ] remaining: E4 oracle harness: gold passes, `FAIL_TO_PASS` fails on base, per-test parity with the official harness, flaky-test detection (3×), pytest plugin list (oracle result analysis in `python/hermetic_oracle`, merged 2026-11-13; harness run still open)
- [ ] remaining: E2 design: a paired subset of 50–100 tasks stratified by repo and year, ≥ 2 seeds, bootstrap intervals, McNemar, drift control

### Exit
- E4 ≥ 99%.
- E2 Track A run on the paired subset.
- E10 gateway conformance: < 1% wrongly blocked and 0 real dates.

---

## Phase 3: VMs

**Goal.** Replace containers with the ring architecture, and add differential grading and signed records.

**Runs on.** Linux x86 with KVM (bare metal, or EC2 with nested virtualization).

### Deliverables
- [ ] remaining: `hermetic-vmm`: Firecracker + jailer orchestration (TR-VMM-1) (T3.3 merged: spec validation, request plan with the kvmclock-hiding CPU template, jail plan, lifecycle, API client, dev-unjailed mode; Firecracker v1.18.0 pinned)
  - [ ] remaining: Open (T3.3): run the jailer tests as root (owner runs `sudo -v` first) and the in-VM boot test once a guest kernel and rootfs exist
  - [x] T3.3 status schema: confirm the status-frame format against `hermetic-execd` (T3.1): execd now emits the guest clock the vmm decoder expects; full jailer validation remains above Proof: `status_frame_supplies_vmm_guest_clock_schema` (`crates/hermetic-execd/tests/contract.rs`); transport schema only.
- [x] Guest kernel build: config, boot args, pinned build timestamp (TR-VMM-4, TR-VMM-5) (T3.2 build tooling merged; deployment smokes remain separate). Proof: `test_container_pipeline_checks_before_compile_and_records_inputs`, `test_reproducible_hook_builds_twice_and_compares_all_outputs` (`python/tests/test_guest_kernel.py`); manager kernel/canary compilation smoke (docs/clock-3b-host-filter.md, 2026-11-14).
- [x] `hermetic-execd`: clock-first boot, run spec, vsock RPC, shutdown freeze (TR-EXD-*) (T3.1, merged 2026-11-13 after review+fix; status frame now carries the guest clock for the vmm decoder). Proof: `boot_known_answer_no_tmp_or_run_tmpfs`, `shutdown_exact_order_retained_handle_and_disconnected_reply` (`crates/hermetic-execd/tests/contract.rs`).
  - [x] Early proc handoff: `init=/sbin/hermetic-init` shim mounts read-only procfs then execs execd (clock-first kept); guest kernel moved to 6.6.160 with devtmpfs automount and initrd support; dev-unjailed boot smoke in `scripts/integration/boot-smoke.sh`. Proof: `boots_guest_and_reads_guest_clock` manager boot smoke recorded in docs/guest-lockdown.md (2026-11-14).
  - [x] TR-EXD-6 trusted-reboot initramfs: reproducible `newc` builder with known-answer hash, `hermetic.initramfs=1` clock-first devtmpfs/base assembly, pinned and bounded hermetic-vmm initrd snapshot, and host boot record; first boot uses the base-resident `init=/sbin/hermetic-init` shim Proof: `test_initramfs_known_answer_contents_and_metadata` (`python/tests/test_initramfs.py`), `trusted_reboot_clock_dev_base_order_and_every_failure_stops_boot` (`crates/hermetic-execd/tests/contract.rs`).
  - [ ] remaining: Open: run `bash scripts/integration/reboot-smoke.sh /tmp/hermetic-reboot-smoke` on a KVM-capable host to verify the touched-disk reboot; this sandbox has no `/dev/kvm`
  - [ ] remaining: Open: propagate the VMM host boot record into the signed `hermetic-attest::RunRecord`; that component's schema has no boot-path/initrd field and requires a separate record-schema change
  - [ ] remaining: Open: upload publication can be raced by a guest process replacing the temporary entry before rename; needs a writer-quiescence or owned-inode publication design
  - [ ] remaining: Open: synchronous filesystem I/O can stall the single RPC loop; needs isolated filesystem workers
- [ ] remaining: NetVM: dm-verity image, DNS table, TPROXY + TLS, drop everything else (TR-NET-*)
  - [x] First-cut runtime: PID 1 clock setup, fixed eth0 addresses, table DNS, HTTP filter to persistent serialized WorldServer frames (CID 2 port 5001), ingress/egress service-port filter, forwarding and IPv6 off; offline transport/policy tests. Proof: `test_dns_round_trip_via_fake`, `test_http_get_forwarded_with_header_filtering` (`crates/hermetic-netvm-core/tests/netvm.rs`).
  - [x] NetVM tree/image builder through existing D4-checked rootfs tooling; AgentVM resolver and network in run spec Proof: `test_netvm_image` suite (`python/tests/test_netvm_image.py`).
  - [x] Automatic eth0 initialization from the AgentVM run spec: validated IPv4 address/prefix, on-link NetVM gateway and MTU; fixed, bounded trusted busybox commands after clock/root setup and before entrypoint/vsock; fail closed; offline validation/order/failure tests. Network smoke inspects setup instead of supplying harness commands; VM verification remains below. Proof: `network_validates_before_commands_and_rejects_failure_signal_and_timeout`, `network_argv_uses_declared_address_prefix_gateway_and_mtu` (`crates/hermetic-execd/tests/contract.rs`).
  - [ ] remaining: Open: TLS termination, world-CA private-key delivery at boot and leaf minting (TR-NET-1/3/4); 443 currently dropped
  - [ ] remaining: Open: TPROXY (TR-NET-3); first cut owns manifest world addresses as /32s and listens directly on port 80
  - [ ] remaining: Open: dm-verity for NetVM (TR-NET-1); first cut uses a D4-checked read-only ext4 image
  - [ ] remaining: Open: two-VM boot/network verification; this environment has no /dev/kvm. Run `scripts/integration/net-smoke.sh "$HOME/hermetic-netvm-smoke"` on the prepared host with a policy-checked kernel including built-in legacy IPv4 filtering (see BOOT_NOTES.md, Network VM).
- [ ] remaining: AgentVM on a CoW world; Mode H through vsock 5000
- [ ] remaining: Mode G: `/opt/agent` volume, model path NetVM → gateway (cut list: optional)
- [ ] remaining: ExtractorVM plus host validator (TR-EXT-*)
- [ ] remaining: GraderVM supervisor and isolation (TR-GR-1 to TR-GR-5)
- [ ] remaining: `hermetic_mutants`: variant pool, base-failing assertion finder, validation (TR-GR-8, TR-GR-9)
- [ ] remaining: Differential runs R0, R1 and R2 in parallel; R3 advisory (cut list: R3, then R2)
- [ ] remaining: Escape probe (TR-SEC-6)
- [ ] remaining: Real-date sentinel D12 (TR-SEC-5): scanner exists; runtime/probe/gateway wiring and `date_leak_observed` aggregation remain open (see detector audit above).
- [x] Classifier (TR-CLS-1, TR-CLS-2): baseline exact-match/overlap label (`python/hermetic_classifier/baseline.py`) plus run classifier `python -m hermetic_classifier.run EVIDENCE` (`run.py`) combining sealcheck, R0-R3, patches, clock probe and D12 into label, status (attest precedence) and flags; strict bounded JSON, fail closed. Proof: `test_retrieved_in_sealed_world_gives_review`, `test_gate_leak_but_derived_is_disagreement_review`, `test_success_without_patches_is_unclassified_review`, `test_status_precedence`, `test_malformed_fields_raise`, `test_parse_evidence_rejects_hostile_json` (`python/tests/test_run_classifier.py`), `python/tests/test_classifier.py`.
  - [ ] remaining: evidence producer (runner writing `hermetic-run-evidence/v1` from real runs) and D12 runtime wiring; until then `date_leak_observed` absent is flagged `date_sentinel_not_run`.
- [ ] remaining: Attestations: `hermetic-run/v1`, `hermetic-transcript-audit/v1`, score card (TR-ATT-*)
- [ ] remaining: Harbor backend (TR-HB-1); prototype registration early, since it's a known risk
- [ ] remaining: `hermetic-cli`: `seal`, `verify-bundle`, `probe`, `run`, `verify`
  - [x] Strict argument parser and exit-code contract (0/2/64/65/70/74) for all five subcommands. Proof: `usage_error_classes_all_exit_64_with_usage_on_stderr`, `validation_rejects_invalid_inputs_before_dispatch`, `exit_code_table_and_not_implemented_backend` (`crates/hermetic-cli/tests/cli.rs`).
  - [x] `verify-bundle` over `hermetic-bundle::verify`: ok/mismatch/expected-root, symlinked or non-directory root refused (65), inner symlink rejected (2). Proof: `verify_bundle_ok_mismatch_and_expected_root`, `verify_bundle_refuses_symlinked_root_and_nondirectory`, `verify_bundle_with_symlink_inside_is_problem_found` (`crates/hermetic-cli/tests/backend.rs`).
  - [x] `probe` classifies supplied `--clockprobe-output` JSON lines and/or `--kernel-canary-serial` transcripts (never probes the host; no input fails closed, 70); symlink, FIFO and oversized inputs refused. Proof: `probe_classifies_clockprobe_output_blocked_leak_error`, `probe_kernel_canary_serial_pass_leak_and_malformed`, `probe_inputs_refuse_symlink_fifo_oversized_and_missing`, `probe_without_input_fails_closed_and_never_probes_host`.
  - [ ] remaining: `verify`: run-record schema validation is wired (invalid record exits 2), but DSSE signature check and bundle cross-check are not, so a valid record fails closed with exit 70. Proof of fail-closed: `verify_valid_record_fails_closed_on_signature_check`, `verify_invalid_record_is_problem_found`, `verify_refuses_hostile_record_and_bundle_paths`.
  - [ ] remaining: `seal` (cutoff computation, world build, sealcheck gate) and `run` (microVM orchestration) fail closed with fixed messages, exit 70. Proof: `seal_fails_closed_with_fixed_message_and_exit_70`, `run_fails_closed_with_fixed_message_and_exit_70`.
- [x] `clock: faked`: microVM runs are `faked` unless patched Firecracker, host hypercall block, a complete probe (every required record exactly once) with every record blocked (clock pairing `unavailable` only with a blocked ring-0 canary) and no D12 hit all hold; container runs are `real`. Proof: `test_full_blocked_probe_with_host_filter_is_hidden`, `test_missing_host_filter_gives_faked`, `test_missing_probe_gives_faked`, `test_incomplete_probe_gives_faked`, `test_any_record_not_blocked_gives_faked`, `test_clock_pairing_unavailable_needs_blocked_canary`, `test_duplicate_probe_record_gives_faked_even_if_both_blocked`, `test_date_leak_observed_gives_faked_and_review`, `test_container_substrate_is_real` (`python/tests/test_run_classifier.py`).

### Exit
- E1: zero canary recovery per channel.
- E8: every forger caught or blocked, with < 1% false alarms.
- E9: Docker vs microVM compatibility reported, with causes.

---

### Integration findings, 2026-11-13 (grader path)
- [x] Grader PID 1: static unsafe-free binary; read-only proc, /tmp, devpts; clock from `hermetic.t` first (reuse execd clock code); run the supervisor with fixed config and result drive; sync and power off; no vsock or network. Plus the vmm grader drive layout (1 MiB result drive) and VM-exit detection. Unblocks the grader VM boot and its clock check (TR-GR-1/2). Proof: `clock_is_set_before_anything_writable_then_supervisor_then_poweroff` (`crates/hermetic-execd/src/grader.rs`); `grader_drive_layout_requires_writable_result_first_and_read_only_others` (`crates/hermetic-vmm/tests/spec_plan.rs`).
- [ ] remaining: Supervisor isolation: apply the `hermetic-grader-sandbox` plan (pid/mount/ipc/uts/net namespaces, capability drop, no_new_privs, device list, cgroup v2 block-device deny); record pipe on fd 3 or higher; process-group kill.
- [x] Extraction format: the validator's HEXT v1 format is canonical; `hermetic-extract-agent` emits it byte for byte. Tree root is `patch:` / `repo_dir: ""` on both sides; `.` is refused. Cross-crate test `crates/hermetic-extract-agent/tests/validator_compat.rs`; grader smoke now runs agent then validator (done 2026-11-13). Proof: `validator_compat` suite (`crates/hermetic-extract-agent/tests/validator_compat.rs`).

---

## Phase 3b: Clock hiding

**Goal.** Reach `clock: hidden` with guest lockdown, host clock filtering, fixed
CPU identity and a fixed guest TSC rate. All are v1 requirements; retain `faked`
until deployment validation passes.

### Deliverables
- [x] Guest root lockdown: modules, kernel memory/MSR devices, kexec, raw I/O and tracing disabled; forced early confidentiality lockdown; cgroup-device BPF retained. Owner reported nested-VM boot with module_load/ring0_paths blocked on 2026-11-14. Proof: `every_root_interface_rule_fails_closed`, `running_state_and_registered_drivers_override_sealed_config` (`crates/hermetic-clockprobe/tests/lockdown.rs`); manager `boots_guest_and_checks_root_lockdown` smoke (2026-11-14).
- [x] Owner-approved kernel builder digest pinned and required by validation; Docker uses the approved local image ID. Proof: `test_kernel_builder_requires_the_approved_digest`, `test_unapproved_local_builder_is_refused_before_kernel_build` (`python/tests/test_cpu_identity_task.py`).
- [x] Fixed 2 GHz guest TSC on lifecycle, CLI and direct Python paths; no host-rate calibration enters guest arguments. The patched VMM requires TSC-control capability, sets and verifies each vCPU rate on cold boot/restore, and rejects incompatible snapshots/hosts. Proof: `all_launch_roles_have_exactly_one_calibrated_boot_source` (`crates/hermetic-vmm/tests/lockdown_followup.rs`), `test_direct_boot_arguments_route_through_vmm` (`python/tests/test_guest_kernel.py`); patched `scaled_tsc_errors_and_mismatched_readback_fail_closed` build test.
- [x] Fixed 2009 Nehalem CPU identity with x86-64-v2 feature ceiling, complete cache/topology/extended-leaf policy and zero PV/PMU/XSAVE state. The pinned patch replaces host normalization output; clockprobe checks every profile register. AMD and unsupported nested hosts fail closed. Proof: `exact_profile_all_cpus_and_each_register_mutation` (`crates/hermetic-clockprobe/tests/identity.rs`), `test_cpu_identity_is_replaced_after_normalization_on_boot_and_restore` (`python/tests/test_host_filter_patch.py`).
- [x] Document PERF_EVENTS forced by x86, inert no-kvmclock with PARAVIRT disabled, and substrate timing limits in docs/clock-3b-analysis.md and docs/guest-lockdown.md. Proof: `test_policy_does_not_forbid_options_x86_force_selects` (`python/tests/test_guest_kernel.py`), `documented_cpu_register_baseline_matches_guest_checker` (`crates/hermetic-clockprobe/tests/identity.rs`).
- [x] Host filtering is v1: pinned Firecracker 1.18 patch denies both directions of all clock MSRs, enables PV CPUID enforcement on boot/restore and intercepts pairing through Xen; unsupported hosts fail closed. Source research: docs/clock-3b-host-filter.md. Proof: `test_patch_applies_once_and_preserves_seccomp_rules` (`python/tests/test_host_filter_patch.py`); manager nested ring-0 canary/control smoke (docs/clock-3b-host-filter.md, 2026-11-14).
- [x] Offline double-build wrapper, measured build-lock and real-runner executable verification; source/patch pins and failure regressions. Proof: `test_double_build_and_pinned_lock_are_published_privately` (`python/tests/test_firecracker_build.py`), `substituted_binary_fails_and_pinned_inode_survives_path_swap` (`crates/hermetic-vmm/tests/binary_pin.rs`).
- [x] Opt-in built-in ring-0 canary patch/config and bounded serial validator; no VM run during review. Proof: `kernel_canary_requires_all_faults_and_untouched_pages` (`crates/hermetic-clockprobe/tests/canary.rs`), `test_clock_canary` suite (`python/tests/test_clock_canary.py`).
- [x] Owner: immutable Rust 1.97.0/vendor builder, full Firecracker and canary compilation, reproducible patched hashes, and nested Xen interception verified on 2026-11-14; base recipe and measurements in docs/clock-3b-host-filter.md. Proof: manager double-build and canary compilation smoke (docs/clock-3b-host-filter.md, measured artifacts, 2026-11-14).
- [x] Owner: nested ring-0 canary faults on all four MSRs on reads/writes, hypercall 9 returns ENOSYS, pages unchanged, result=pass; stock control accepts all four MSRs, changes page, result=fail. Proof: manager nested ring-0 canary/control smoke (docs/clock-3b-host-filter.md, expected six records and stock rejection, 2026-11-14).
- [ ] remaining: Owner: multiple vCPUs, pause/resume, snapshot restore and deployment-host configuration audit; the completed nested test does not certify these paths.
- [ ] remaining: Check TSC stability without kvmclock (partial 2026-11-14: guest TSC fixed at 2000 MHz via KVM scaling and CPUID 0x15, `tsc` clocksource with `tsc_known_freq`, rdtsc probe blocked across 9 reboots; no long-running drift measurement yet)
- [x] Eighth check, the hypercall from guest ring 0: module loading is compiled out of the lockdown kernel, so the check is the built-in ring-0 canary (hypercall 9 → ENOSYS, page unchanged). Proof: nested canary 2026-11-14, `kernel_canary_requires_all_faults_and_untouched_pages`.
- [x] Full probe (`/sbin/hermetic-clockprobe`, no arguments) in the nested lockdown guest on patched Firecracker `9826f474…` (2026-11-14, commit `52d7be6`): exit 0, every record blocked except `clock_pairing_hc`, which the probe never issues and the ring-0 canary covers (hypercall 9 returns ENOSYS). Control on unpatched Firecracker: the canary's stock control accepts all four MSRs and changes the page (result=fail). Fixes found by the probe: no `tsc_early_khz` (frequency only via pinned CPUID 0x15, so `tsc` registers at once with `tsc_known_freq`), KVM's recomputed 0xD.0 EBX and the KVM/template flags `cpuid_fault`/`pti` in the expected profile, jiffies clocksources allowed, kernel-log dates exempt only when exactly in the sealed `substrate-dates` list extracted from the kernel image, `/dev` enumeration cap for legacy PTYs, real POSIX clock sampling. Proof: `nested_guest_dump_with_kvm_xsave_size_is_the_fixed_profile`, `nested_guest_clocksource_and_flags_are_the_fixed_profile`, `only_exact_substrate_dates_are_listed_not_leaks`, `lockdown_dev_with_legacy_ptys_fits_the_enumeration_cap`, `all_launch_roles_boot_without_a_tsc_frequency_argument`; nested boot, reboot ×3, grader-VM and net smokes.
- [x] CodeRabbit review of the whole 3b branch (2026-11-14): four findings, all fixed: exact substrate-date list instead of a date cutoff; snapshot restore accepts exactly KVM's recomputed CPUID 0xD.0 EBX (Firecracker rebuilt, canary re-verified); kernel builder used by approved image ID from the store or a saved archive, never rebuilt; host-filter remedy documentation. Proof: `substrate_dates_are_extracted_exactly_from_image_strings`, `test_builder_archive_is_loaded_only_when_the_approved_id_is_missing`, the patch's `fixed_identity_rejects_incompatible_hosts_and_snapshot_mutations`.
- [ ] remaining (follow-ups): production rootfs/world builders install `/etc/hermetic/substrate-dates`; `CONFIG_LEGACY_PTYS=n` in the lockdown policy; `HERMETIC_FULL_PROBE=1` boot-smoke mode; docs that still describe `tsc_early_khz`.

### Exit
The probe passes, giving `clock: hidden`. Otherwise, record why and ship `faked`.

---

## Phase 4: Extensions

**Goal.** Broaden coverage. Every item is independent and can be cut.

### Deliverables
- [ ] remaining: Web archive and search: a tantivy BM25 index per month, exact-capture replay, Common Crawl, Wayback, Software Heritage, and Stack Exchange rebuilt from post history
- [ ] remaining: Other ecosystems: npm, crates.io, Go modules; research Maven
- [ ] remaining: Other provider adapters for the gateway
- [ ] remaining: Smart git protocol terminated in NetVM (for shallow clones)
- [ ] remaining: State-task live grading from a snapshot (TR-VMM-6, §11.4)
- [ ] remaining: Split mode for Mode G (agent in a second VM)
- [ ] remaining: TEE quotes (SEV-SNP, TDX, Nitro)
- [ ] remaining: aarch64 (pl031 RTC offset patch)
- [ ] remaining: Resolve whether archived pages can be redistributed

### Exit
- E2 Track B: start fully sealed and open one channel at a time.
- E5: date evidence at each clock level; 0 outside the substrate at `hidden`.
