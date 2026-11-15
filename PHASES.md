# Hermetic World: Phases

- **Status:** derived from §15 of [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md). Requirement IDs refer to [TRD.md](TRD.md).
- **Last updated:** 2026-11-15

Tick items off here as they land, and log each one in [BUILD_LOG.md](BUILD_LOG.md).

## Verified checklist counts

Counts include nested checklist items. Checked items cite merged tests or named historical manager smokes; historical smoke evidence is not a new run. Unchecked items state what remains. Component tests do not certify whole-phase exit criteria.

| Phase | Verified checklist |
|---|---|
| 0: Vertical slice | done 10 of 10 |
| 1: sealcheck | done 40 of 48 |
| 2: World | done 16 of 43 |
| 3: VMs | done 23 of 48 |
| 3b: Clock hiding | done 18 of 20 |
| 4: Extensions | done 27 of 39 |

## Overview

| Phase | Name | Runs on | Exit criterion | Status |
|---|---|---|---|---|
| 0 | Vertical slice | WSL2 Ubuntu + Docker | Oracle passes on every slice task; one agent run graded | **Done** 2026-11-11 |
| 1 | sealcheck | Laptop (no KVM) | E3 targets met; leak report on one public benchmark, disclosed privately | In progress |
| 2 | World | Any Linux box | E4 ≥ 99%; E2 Track A on the paired subset; E10 | In progress |
| 3 | VMs | Linux x86 + KVM | E1, E8, E9 | In progress |
| 3b | Clock hiding (host filter required in v1) | Linux x86 + KVM | Probe passes → `clock: hidden` (else ship `faked`) | **Nested probe passes** 2026-11-14 (pairing covered by the ring-0 canary); full-smoke automation and builder metadata wired; deployment validation pending |
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
- [x] Fingerprints with baseline subtraction (TR-SC-1): gold patch, test-patch added lines, and up to 20 deduplicated passing fixes (`staging/fixes/*.patch`), base-commit fingerprints subtracted. Proof: `test_passing_fix_is_fingerprinted_and_base_subtracted`, `test_passing_fixes_deduplicated_and_capped_at_20` (`crates/hermetic-sealcheck/tests/test_fingerprint_and_scan.rs`), `test_cli_scan_gates_on_a_passing_fix_from_staging_fixes` (`tests/test_cli.rs`), `test_task_input_passing_fixes_sorted_regular_patch_files_only`, `test_task_input_passing_fixes_symlinked_dir_is_not_followed` (`crates/hermetic-common/tests/test_manifest.rs`).
  - [ ] remaining: collecting the SWE-bench/experiments passing fixes into `staging/fixes/` belongs to slice packaging and is not built
  - [x] Tier 1: lines, windows, diff shape, diff-like text (TR-SC-2) (T1.1). Proof: `test_no_false_positive_at_base_and_planted_findings` (`crates/hermetic-sealcheck/tests/test_fingerprint_and_scan.rs`).
  - [x] Tier 2: tree-sitter IDF symbols, as review (TR-SC-3). Proof: `test_tier2_multi_hunk_results_unchanged_with_precomputed_context` (`crates/hermetic-sealcheck/tests/test_tier2.rs`).
  - [x] Tier 3: winnowing, k=8, w=8 (TR-SC-4) (T1.2). Proof: `test_winnow_baseline_subtraction_gives_zero_gates`, `test_winnow_planted_reformatted_copy_gives_tier3_gate` (`crates/hermetic-sealcheck/tests/test_winnow.rs`).
  - [x] Binary tier (TR-SC-5) (T1.4; `.pyc` code-object fingerprints T1.12). Proof: `test_real_pyc_of_the_fix_gates_on_the_binary_tier`, `test_hostile_binaries_none_may_panic` (`crates/hermetic-sealcheck/tests/test_binary.rs`).
    - [x] T1.12 review: with a sufficient budget, extraction completes for every one of 20,000 changed and 20,000 added functions, in a child limited to 2 GiB. Proof: `test_all_20000_functions_changed_and_added_complete_with_sufficient_budget` (`crates/hermetic-sealcheck/tests/test_pyc_marshal.rs`).
    - [x] T1.12 review: `"T2"` is reported uncovered only for indexes older than version 5; docs in `index.rs` corrected. Proof: `test_t2_coverage_follows_index_version` (`tests/test_tier2.rs`), `query_older_version_index_reports_not_covered`, `cli_index_and_query_match_scan` (`tests/test_index.rs`), `test_scan_and_query_undated_equivalence` (`tests/test_undated.rs`).
    - [x] T1.12 review: tier-2 extraction parses each file once (not once per hunk), looks rows up by binary search over cached children, and deduplicates anchors with a set. Proof: `test_tier2_many_hunks_one_file_is_not_quadratic` (4,000 hunks; under 60 s in a memory-limited child, about 15 s; the old code exceeds 60 s) and `test_tier2_per_file_parse_matches_per_hunk_extraction` (`tests/test_tier2.rs`).
    - [x] T1.12: licence note `crates/hermetic-sealcheck/data/LICENSE-UNICODE` (Unicode License v3) for `data/unicode_names.txt`. Proof: `test_unicode_names_data_has_licence_note` (`tests/test_tier2.rs`).
- [x] Container recursion with bomb limits, including git packs (TR-SC-6) (T1.2, T1.3). Proof: `test_containers` and `test_gitstore` suites (`crates/hermetic-sealcheck/tests/`).
- [ ] remaining: Detectors D0–D12 (TR-SC-7): implemented D0, D1, D2, D3, D3b, D4, D5a, D5b (`python/hermetic_d5b`), D6, D9, D11. Detector audit (2026-11-13):
  - [x] D4: live file/directory/symlink mtimes, tar/zip member times, index equivalence, ext4 inode/superblock times; bounded no-follow image reads; dirty journals refused; malformed images report Info and exit 1. Proof: `test_ext4_mke2fs_suite`, `test_live_tree_symlink_late_mtime` (`crates/hermetic-sealcheck/tests/test_d4.rs`).
  - [ ] remaining: D7: `python/hermetic_d7` compares supplied shipped/rebuilt artifacts with bounded ingestion. Done (2026-11-14): `--deep-audit` orchestration (`hermetic_d7/deep_audit.py`) over a strict recipe mapping (`hermetic.d7.recipe/1`: id, artifact, source, builder, args), no-follow pinning of root, recipe, artifact and source, an injectable isolated builder, and a refusing default so the host never builds; misbehaving builders fail closed and reports carry only relative names. Proof: `test_deep_audit_identical_rebuild`, `test_deep_audit_default_builder_refuses_host_builds`, `test_hostile_recipe_entries_refuse_the_recipe`, `test_symlinked_recipe_source_artifact_and_root_are_refused`, `test_misbehaving_builder_fails_closed` (`python/tests/test_d7_deep_audit.py`). Remaining: the real VM-isolated builder, and the sealer emitting `d7-recipe.json`.
  - [x] D8: os-release, tzdata, certificates, kernel/config dates, dated logs, Python versions; kernel-image build-string dates (`boot/vmlinuz*`, `vmlinux*`, `bzImage*`, `Image*`, no-follow, 64 MiB and 16-image caps, parsed with the clock probe's `extract_substrate_dates`; no recoverable date fails closed as Info); CPU-template coherence of the fixed `vmm/cpu-baseline.rs` identity against a historical CPU policy (brand, CPUID signature, first-sale date). Bounded no-follow I/O and stable relative findings. Proof: `kernel_image_build_string_after_t_clock_is_reported`, `kernel_image_date_flood_fails_closed`, `check_d8_scans_boot_images_relative_and_no_follow`, `oversized_and_excess_kernel_images_are_capped`, `cpu_template_baseline_is_coherent_after_its_sale_date`, `unknown_or_mismatched_cpu_identity_is_reported` (`crates/hermetic-sealcheck/tests/test_d8_image.rs`). Note: compressed images expose dates only through their uncompressed version string.
  - [ ] remaining: D10: `python/hermetic_d10` implements archive/metadata times and bounded WARC-Date checks for every record, including gzip/nested captures; malformed captures fail closed. Done (2026-11-14): per-record payload fingerprints (`payload_sha256` on every WARC finding) and strict verification against a sealer provenance manifest (`hermetic_d10/provenance.py`, `hermetic.d10.provenance/1`): every record needs exactly one entry with a matching fingerprint, revision at or before T_clock, scrub state, and no scrubbed payload present; incomplete scans never verify. Proof: `test_every_warc_record_carries_a_payload_fingerprint`, `test_matching_provenance_verifies_plain_and_gzip`, `test_provenance_mismatches_gate_with_relative_names`, `test_incomplete_scan_never_verifies`, `test_hostile_provenance_manifests_are_refused` (`python/tests/test_d10_provenance.py`). Done (2026-11-15): the sealer writes the manifest (`build_provenance`, validated by the parser before it is written; a repo_only seal ships no archive, so its manifest is empty and any WARC record in the tree gates) and D10 verifies it (`--provenance`); a D10 report without verified provenance cannot be seal evidence. Proof: `test_cli_provenance_gates_unlisted_records_and_verifies_listed_ones`, `test_cli_refuses_hostile_provenance_files`, `test_build_provenance_is_canonical_and_refuses_invalid_records`, `test_d10_report_without_verified_provenance_is_refused`, `test_d10_provenance_gate_gates_the_seal`. Remaining: hunk-fingerprint (line/window) matching of record payloads via the sealcheck fingerprint scanner.
  - [x] D11: advisory patch inspection, test-infrastructure paths, runner sections, monkeypatching and shadowing; standard unified diffs and quoted paths supported; bounded CLI/library inputs. Proof: `test_d11_cli_execution_and_json_shape`, `test_d11_monkeypatch_rules` (`crates/hermetic-sealcheck/tests/test_d11.rs`).
  - [x] D12 advisory text/file scanner with bounded no-follow traversal. Proof: `crates/hermetic-sealcheck/tests/test_d12.rs`.
  - [x] D12 run-time sentinel library (`hermetic_sealcheck::d12_runtime`): count-only summaries keyed `source:channel` (no matched text kept), raw plus decoded views (`\uXXXX`, `%XX`, `&#..;`, full-width digits, UTF-16), chunk tails, SSE delta joining, fail closed on byte/line/option caps. Proof: 15 tests in `crates/hermetic-sealcheck/tests/test_d12_runtime.rs` (e.g. `rt_sse_date_split_across_deltas_and_byte_chunks`, `rt_text_stream_date_split_across_chunks`, `rt_encoded_dates_are_decoded`, `rt_sse_line_cap_fails_closed`, `rt_run_byte_cap_fails_closed`, `rt_real_date_host_name_and_path_counted_without_echo`).
  - [x] D12 gateway wiring (Mode G): every agent request body (also refused and non-UTF-8 ones), every forwarded upstream JSON/error body and every forwarded SSE stream is scanned; the summary is written to `date_sentinel.json` in the gateway log dir after each request (a write failure marks the scan incomplete). Config: optional `date_sentinel` {`host_names`, `host_paths`, `tolerance_days`}; real date = host UTC date at start. Proof: 11 tests in `crates/hermetic-gateway/tests/test_date_sentinel.rs` (e.g. `gw_d12_sse_date_split_across_deltas_detected`, `gw_d12_json_escaped_date_in_prompt_detected`, `gw_d12_refused_non_utf8_request_still_scanned`, `gw_d12_byte_cap_fails_closed`, `gw_d12_agent_prompt_with_real_date_is_recorded_without_echo`).
  - [x] D12 Mode H harness wiring: `python/hermetic_slice/date_sentinel.py` (mirror of the Rust sentinel); `run_agent(..., sentinel=)` scans system/task prompts, format-error turns and every command output before truncation; `run_task` writes `date_leak_observed` (bool) and the merged `date_sentinel` summary into `run.json`, merging `extra_sentinel_summaries` (e.g. the gateway file) and failing closed on a missing/malformed part. Proof: 41 tests in `python/tests/test_date_sentinel.py` (e.g. `test_agent_loop_scans_observations_before_truncation`, `test_run_record_date_leak_observed`, `test_merge_fails_closed_on_missing_or_malformed`). (The `python/hermetic_agent/environment.py` Mode H environment is not on this branch; when it lands, call `sentinel.scan_text("observation", ...)` on each observation it returns and `scan_text("prompt", ...)` on each prompt, as `agent_loop.py` does.)
  - [ ] remaining: D12 escape-probe integration (the guest probe and host aggregator exist; real model-call date scanning remains unavailable) and the Rust run orchestrator: nothing in `crates/` builds `RunRecord` yet, so `date_leak_observed` there must be set from `SentinelSummary::merge` over the gateway `date_sentinel.json`, the harness summary and the probe once that orchestrator exists; VM command-log egress in the Firecracker path is not yet routed through the sentinel.
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
  - [x] `_make_output_dirs` creates missing output directories relative to held descriptors with `O_NOFOLLOW`; a symlinked or file component is refused (2026-11-15). Proof: `test_output_dirs_are_created_without_following_symlinks`
  - [x] The unused `_make_writable_and_retry` rmtree handler (and `_remove_at`) removed with the test that called it directly; the swapped-ancestor chmod coverage stays (2026-11-15). Proof: `test_unused_rmtree_retry_handler_is_removed`, `test_ancestor_swapped_for_symlink_is_never_followed`
  - [x] The simulated-other-uid image test no longer stubs the storage ownership checks: they run on every held descriptor against the real owning identity, and the test asserts they ran (2026-11-15). Proof: `test_finding1_image_independent_of_builder_identity`
- [x] Gateway deadline handling (T2.2). Each request has its own read-deadline cell, armed for the next head only when the stream is handed on, so a successor never cuts a body deadline (`ae2e6ef`). Two further causes of the `test_8_stalled_clients_are_dropped_at_the_deadline_and_service_recovers` flake fixed 2026-11-15: the body deadline is re-read from the server configuration after the head (deadlines installed while a head was pending were ignored), and the test harnesses create the server with its deadlines before the first accept, as the gateway binary does. test_8 passed 50 of 50 runs after the fix (5 of 15 failed before). Proof: `body_deadline_installed_while_head_is_pending_still_applies` (fails before the fix).
  - [x] CodeRabbit (2026-11-12): body deadline kept until the body reader finishes (`ae2e6ef`); the sequential hand-off no longer panics when a predecessor writer or reader disappears without handing on, and a failed writer stays failed. Proof: `writer_whose_predecessor_vanished_fails_without_panicking_and_stays_failed`, `dropping_a_waiting_reader_whose_predecessor_vanished_does_not_panic`, `dropping_a_waiting_reader_forwards_the_stream_once_it_arrives`.
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
  - [x] Seccomp allow-list tightened (2026-11-15): `connect` removed (the server connects only before the sandbox), every credential-changing call (`set*id`, `setgroups`, `setfs*id`, `capset`) and `clock_settime` removed, and `kill`/`tgkill`/`rt_sigqueueinfo` allowed only for the server's own pid (`tkill` removed). Denial is tested in child processes (killed by SIGSYS) and self-signalling still works. Proof: `seccomp_denies_connect_foreign_signals_credentials_and_clock_setting`
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
  - [x] Operator config and API-key paths: every component is opened with `O_NOFOLLOW` through pinned directory descriptors, so symlinked ancestors are refused (fixed earlier; recorded 2026-11-15). Proof: `secret_file_permissions_and_all_symlink_components_are_refused`
  - [x] Quota errors reply with the standard `rate_limit_error` message; the reason and limits go only to the host log (2026-11-15). Proof: `quota_breach_replies_with_the_standard_message_and_logs_the_reason`
  - [x] Source validation checks only protocol content-block locations, so a tool argument or schema shaped like a URL image source is accepted (fixed in `a4dbcd2`; recorded 2026-11-15). Proof: `test_tool_use_and_schema_with_image_like_source_not_rejected`
  - [x] Only a real timeout on an upstream body read is reported as a timeout; other read failures are upstream errors (2026-11-15). Proof: `only_real_timeouts_are_reported_as_timeouts`
  - [x] The first original upstream SSE `error` event (bounded to 64 KiB) is kept for the host log; the agent still receives only the sanitised event (2026-11-15). Proof: `upstream_sse_error_body_is_logged_but_never_forwarded`
  - [x] An explicit unrecognised upstream error type becomes `api_error`; only a body without a type maps from the status (2026-11-15). Proof: `unrecognised_upstream_error_type_becomes_api_error`
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
  - [ ] remaining: Open (T3.3): run the jailer tests as root on the prepared host; the dev-unjailed nested boot already passed on 2026-11-14
  - [x] T3.3 status schema: confirm the status-frame format against `hermetic-execd` (T3.1): execd now emits the guest clock the vmm decoder expects; full jailer validation remains above Proof: `status_frame_supplies_vmm_guest_clock_schema` (`crates/hermetic-execd/tests/contract.rs`); transport schema only.
- [x] Guest kernel build: config, boot args, pinned build timestamp (TR-VMM-4, TR-VMM-5) (T3.2 build tooling merged; deployment smokes remain separate). Proof: `test_container_pipeline_checks_before_compile_and_records_inputs`, `test_reproducible_hook_builds_twice_and_compares_all_outputs` (`python/tests/test_guest_kernel.py`); manager kernel/canary compilation smoke (docs/clock-3b-host-filter.md, 2026-11-14).
- [x] `hermetic-execd`: clock-first boot, run spec, vsock RPC, shutdown freeze (TR-EXD-*) (T3.1, merged 2026-11-13 after review+fix; status frame now carries the guest clock for the vmm decoder). Proof: `boot_known_answer_no_tmp_or_run_tmpfs`, `shutdown_exact_order_retained_handle_and_disconnected_reply` (`crates/hermetic-execd/tests/contract.rs`).
  - [x] Early proc handoff: `init=/sbin/hermetic-init` shim mounts read-only procfs then execs execd (clock-first kept); guest kernel moved to 6.6.160 with devtmpfs automount and initrd support; dev-unjailed boot smoke in `scripts/integration/boot-smoke.sh`. Proof: `boots_guest_and_reads_guest_clock` manager boot smoke recorded in docs/guest-lockdown.md (2026-11-14).
  - [x] TR-EXD-6 trusted-reboot initramfs: reproducible `newc` builder with known-answer hash, `hermetic.initramfs=1` clock-first devtmpfs/base assembly, pinned and bounded hermetic-vmm initrd snapshot, and host boot record; first boot uses the base-resident `init=/sbin/hermetic-init` shim Proof: `test_initramfs_known_answer_contents_and_metadata` (`python/tests/test_initramfs.py`), `trusted_reboot_clock_dev_base_order_and_every_failure_stops_boot` (`crates/hermetic-execd/tests/contract.rs`).
  - [x] Manager nested trusted-reboot smoke passed ×3 on 2026-11-14: touched-disk reboot, locked startup, authorization and trusted helper. Proof: `reboots_touched_disk_with_trusted_initramfs` (`crates/hermetic-vmm/tests/guest.rs`), `scripts/integration/reboot-smoke.sh`; historical manager smoke, not rerun in this review.
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
  - [x] Manager nested two-VM boot/network smoke passed on 2026-11-14 using the policy-checked kernel and patched Firecracker. Proof: `scripts/integration/net-smoke.sh`, `crates/hermetic-vmm/tests/net_guest.rs`; historical manager smoke, not rerun in this review.
- [ ] remaining: AgentVM on a CoW world; Mode H through vsock 5000
- [ ] remaining: Mode G: `/opt/agent` volume, model path NetVM → gateway (cut list: optional)
- [ ] remaining: ExtractorVM plus host validator (TR-EXT-*)
- [ ] remaining: GraderVM supervisor and isolation (TR-GR-1 to TR-GR-5)
- [x] `hermetic_mutants`: variant pool, base-failing assertion finder, validation (TR-GR-8, TR-GR-9). Finder (`finder.py`) combines the base-tree assertion log with `hermetic_assert_flow` and hidden lines, fail closed; validation (`validate.py`) runs baseline three times (flaky tests dropped), keeps equivalents matching on base and gold, single mutants failing on both, builds the R1 set from the R2 text with one mutant per test function, pads R1/R2 to equal size and records coverage; runner injected. Proof: `test_finder_selects_failing_hidden_sites_only`, `test_finder_unreached_site_needs_data_flow_dependency`, `test_finder_site_passing_in_one_parametrisation_is_excluded`, `test_finder_malformed_entries_fail_closed` (`python/tests/test_mutants_finder.py`); `test_selection_validates_and_mutates_base_failing_tests`, `test_r1_differs_from_r2_only_in_mutated_literals_and_sizes_match`, `test_flaky_baseline_test_is_dropped_from_comparisons`, `test_flaky_variant_is_rejected`, `test_mutant_passing_on_gold_is_not_used`, `test_combined_r1_failing_falls_back_to_single_mutant` (`python/tests/test_mutants_validate.py`).
  - [ ] remaining: Open: production validation runner (GraderVM per base/gold call) and E4 wiring; the recorder log must come from a real base-tree run.
- [x] Differential runs R0, R1 and R2 in parallel; R3 advisory (cut list: R3, then R2): host orchestration `python/hermetic_mutants/differential.py` with injected disk runner, strict result-disk decoding (same rules as `hermetic-grader-result`), verdict with the same precedence and reasons plus `variant_set_mismatch`, `runner_error`, `run_timeout`; `CommandRunner` for an external VM command. Proof: `test_run_differential_runs_in_parallel`, `test_run_differential_timeout_and_bad_returns`, `test_decode_disk_hostile_images`, `test_aggregate_slot_and_digest_mismatch_are_tampered`, `test_aggregate_r3_advisory_review_including_empty_f2p`, `test_end_to_end_blanket_forger_caught_by_r1`, `test_end_to_end_source_hash_keyed_forger_caught_by_r2` (`python/tests/test_mutants_differential.py`).
  - [ ] remaining: Open: VM run. `HERMETIC_DIFFERENTIAL_VM_RUNNER=<cmd RUN_ID TEST_FILE OUT_DISK>` then `py-gate tests/test_mutants_differential_vm.py` on a KVM host (the runner command for the grader smoke task still has to be written around `scripts/integration/grader-vm-smoke.sh`); R3 fix-removal work preparation (stubbing gold-touched functions) is not built.
- [ ] remaining: Escape probe (TR-SEC-6)
  - [x] Guest probe `hermetic-escapeprobe` (DNS real names + delegation, raw IP, ICMP, IPv6, QUIC, vsock CID 0/2 scans, device nodes, host-share mounts, module loading, getrandom positive check) and fail-closed host aggregator; offline classification and hostile-report tests. Proof: `attempt_reached_is_leak_timeout_and_refusals_blocked_other_error`, `mountinfo_host_shares_leak_clean_blocks_hostile_errors`, `netvm_table_resolver_blocks_every_real_name_and_delegation`, `hostile_reports_fail_closed` (`crates/hermetic-escapeprobe/tests/`).
  - [ ] remaining: Open: run in a nested-VM AgentVM: `HERMETIC_ESCAPE_PROBE=1 HERMETIC_LOCKDOWN_CONFIG=<verified-config> scripts/integration/boot-smoke.sh <fresh-work-dir>` (static probe through execd, then fail-closed host aggregation); no /dev/kvm here.
  - [ ] remaining: Open: gateway abuse probes, real model-call date scan, pip/git/curl install positive checks (report `unavailable`, verdict `incomplete`); attestation wiring of the verdict.
- [ ] remaining: Real-date sentinel D12 (TR-SEC-5): scanner, run-time library, gateway wiring and Mode H harness wiring with `date_leak_observed` in `run.json` are done and tested (see detector audit above); probe integration and the Rust run-record orchestrator remain.
- [x] Classifier (TR-CLS-1, TR-CLS-2): baseline exact-match/overlap label (`python/hermetic_classifier/baseline.py`) plus run classifier `python -m hermetic_classifier.run EVIDENCE` (`run.py`) combining sealcheck, R0-R3, patches, clock probe and D12 into label, status (attest precedence) and flags; strict bounded JSON, fail closed. Proof: `test_retrieved_in_sealed_world_gives_review`, `test_gate_leak_but_derived_is_disagreement_review`, `test_success_without_patches_is_unclassified_review`, `test_status_precedence`, `test_malformed_fields_raise`, `test_parse_evidence_rejects_hostile_json` (`python/tests/test_run_classifier.py`), `python/tests/test_classifier.py`.
  - [x] Evidence producer (`python/hermetic_classifier/evidence.py`, `python -m hermetic_classifier.evidence`): builds `hermetic-run-evidence/v1` from files, not flags. Host facts hold only when the Firecracker binary hashes to a `hermetic-firecracker-build/v1` record whose patch and source equal the pinned lock and differ from the release (checked on the real patched build: true; stock release: false); guest probe JSON lines and the canary record are parsed strictly; D12 comes from `run.json` and a missing value is refused; the result is checked by the classifier before output. Proof: `python/tests/test_run_evidence_producer.py` (11 tests).
  - [ ] remaining: run the producer from the Mode H harness after each real run (needs the full probe run in the AgentVM before the agent starts).
- [x] Attestations: `hermetic-run/v1`, `hermetic-transcript-audit/v1`, score card (TR-ATT-*) in `crates/hermetic-attest`: canonical JSON and run digest, in-toto v1 statement in a DSSE envelope (PAE known-answer), Ed25519 offline-key signing (key by path or descriptor), verification refusing tampering, missing fields, wrong types, unknown/missing key ids, replay and mismatched world root / world bundle / sealcheck / grader / task bindings; record cross-checked with the classifier for clock level, D12 `date_leak_observed` and status; score card refusing mixed tuples. Proof: `ed25519_rejects_tampered_payload_and_signature`, `ed25519_rejects_wrong_missing_and_unknown_key_ids`, `signer_loads_key_by_path_and_fd_and_refuses_hostile_files`, `signed_payload_with_missing_field_or_wrong_type_is_rejected`, `replay_of_a_verified_record_is_rejected`, `mismatched_world_root_bundle_and_other_bindings_are_rejected`, `audit_requires_a_verified_run_and_matching_digest`, `record_must_match_classifier_clock_date_leak_and_status`, `hostile_classification_documents_are_rejected`, `hidden_clock_with_date_leak_is_an_invalid_record` (`crates/hermetic-attest/tests/test_offline_key_and_policy.rs`), plus `test_dsse_envelope.rs`, `test_canonical_and_digest.rs`, `test_run_record.rs`, `test_score_card.rs`, `test_run_status.rs`.
  - [ ] remaining: Sigstore keyless signing; TEE quote verification; wiring into `hermetic-cli run`/`verify` (the run-record orchestrator that fills the record from real runs).
- [ ] remaining: Harbor backend (TR-HB-1); prototype registration early, since it's a known risk
- [ ] remaining: `hermetic-cli`: `seal`, `verify-bundle`, `probe`, `run`, `verify`
  - [x] Strict argument parser and exit-code contract (0/2/64/65/70/74) for all five subcommands. Proof: `usage_error_classes_all_exit_64_with_usage_on_stderr`, `validation_rejects_invalid_inputs_before_dispatch`, `exit_code_table_and_not_implemented_backend` (`crates/hermetic-cli/tests/cli.rs`).
  - [x] `verify-bundle` over `hermetic-bundle::verify`: ok/mismatch/expected-root, symlinked or non-directory root refused (65), inner symlink rejected (2). Proof: `verify_bundle_ok_mismatch_and_expected_root`, `verify_bundle_refuses_symlinked_root_and_nondirectory`, `verify_bundle_with_symlink_inside_is_problem_found` (`crates/hermetic-cli/tests/backend.rs`).
  - [x] `probe` classifies supplied `--clockprobe-output` JSON lines and/or `--kernel-canary-serial` transcripts (never probes the host; no input fails closed, 70); symlink, FIFO and oversized inputs refused. Proof: `probe_classifies_clockprobe_output_blocked_leak_error`, `probe_kernel_canary_serial_pass_leak_and_malformed`, `probe_inputs_refuse_symlink_fifo_oversized_and_missing`, `probe_without_input_fails_closed_and_never_probes_host`.
  - [x] `verify`: Ed25519 DSSE signature check against a trusted key, bundle root binding to `world_root`, and classifier cross-check (clock, `date_leak_observed`, status, run digest). Proof: `verify_accepts_a_signed_record_from_the_trusted_key`, `verify_rejects_tampering_wrong_key_and_unsigned_records`, `verify_binds_the_record_to_the_bundle_root`, `verify_cross_checks_the_classifier`, `verify_refuses_hostile_record_key_classification_and_bundle_paths`, `verify_requires_a_trusted_key_and_parses_classification`.
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
- [x] Fixed 2 GHz guest TSC on lifecycle, CLI and direct Python paths; no host-rate calibration enters guest arguments. The patched VMM requires TSC-control capability, sets and verifies each vCPU rate on cold boot/restore, and rejects incompatible snapshots/hosts. Proof: `all_launch_roles_boot_without_a_tsc_frequency_argument` (`crates/hermetic-vmm/tests/lockdown_followup.rs`), `test_direct_boot_arguments_route_through_vmm` (`python/tests/test_guest_kernel.py`); patched `scaled_tsc_errors_and_mismatched_readback_fail_closed` build test.
- [x] Fixed 2009 Nehalem CPU identity with x86-64-v2 feature ceiling, complete cache/topology/extended-leaf policy and zero PV/PMU state and no advertised XSAVE (KVM runtime leaf 0xD.0 EBX is exactly `0x240`). The pinned patch replaces host normalization output; clockprobe checks every profile register. AMD and unsupported nested hosts fail closed. Proof: `exact_profile_all_cpus_and_each_register_mutation` (`crates/hermetic-clockprobe/tests/identity.rs`), `test_cpu_identity_is_replaced_after_normalization_on_boot_and_restore` (`python/tests/test_host_filter_patch.py`).
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
- [x] Adversarial review of the whole 3b branch (2026-11-14): four findings, all fixed: exact substrate-date list instead of a date cutoff; snapshot restore accepts exactly KVM's recomputed CPUID 0xD.0 EBX (Firecracker rebuilt, canary re-verified); kernel builder used by approved image ID from the store or a saved archive, never rebuilt; host-filter remedy documentation. Proof: `substrate_dates_are_extracted_exactly_from_image_strings`, `test_builder_archive_is_loaded_only_when_the_approved_id_is_missing`, the patch's `fixed_identity_rejects_incompatible_hosts_and_snapshot_mutations`.
- [x] Production rootfs and NetVM world builders install `/etc/hermetic/substrate-bound` from the validated kernel lock release date; matching image/extractor inputs install exact `/etc/hermetic/substrate-dates` with bounded offline extraction. No general date-cutoff exemption. Files are deterministic and source trees remain untouched. Proof: `test_production_rootfs_installs_kernel_metadata_without_mutating_source`, `test_rootfs_defaults_to_the_pinned_release_date`, `test_netvm_world_tree_installs_same_kernel_metadata`, `test_generated_substrate_counts_toward_resource_caps` (`python/tests/test_lockdown_completion.py`).
- [x] `CONFIG_LEGACY_PTYS=n` in the kernel fragment, Python rules and guest forbidden list; UNIX98 PTYs retained. Proof: `test_legacy_ptys_are_disabled_and_unix98_ptys_are_retained`, `every_root_interface_rule_fails_closed`. Manager kernel rebuild remains required; the earlier nested smoke used the previous kernel.
- [x] `HERMETIC_FULL_PROBE=1` boot-smoke mode runs `/sbin/hermetic-clockprobe` without arguments, requires exit 0 and every expected record exactly once and blocked except pairing may be unavailable. Proof: `test_full_clock_smoke_installs_probe_config_and_selects_complete_validator`, `full_clock_reply_requires_every_record_and_only_pairing_may_be_unavailable`. No live VM run during this review.
- [x] Clock analysis, host-filter guide, guest-lockdown guide and clockprobe README describe CPUID-only frequency discovery, runtime XSAVE/flags/jiffies, real POSIX sampling, 4096-entry device cap and exact sealed date exemptions. Proof: implementation and offline regression suites cited above.
- [x] CLI probe reports unavailable coverage as incomplete with exit 2 instead of a blocked verdict. Proof: `probe_unavailable_is_incomplete_and_never_blocked` (`crates/hermetic-cli/tests/backend.rs`).

### Exit
The probe passes, giving `clock: hidden`. Otherwise, record why and ship `faked`.

---

## Phase 4: Extensions

**Goal.** Broaden coverage. Every item is independent and can be cut.

### Deliverables
- [ ] Web archive and search: a tantivy BM25 index per month, exact-capture replay, Common Crawl, Wayback, Software Heritage, and Stack Exchange rebuilt from post history
  - [x] Offline replay interchange format and authenticated reader (`python/hermetic_archive`): exact URL and nanosecond cutoff lookup, latest capture strictly before the cutoff per URL, payload hashes/sizes, selected response fields, GET/HEAD and redirects without following them. Digest-bound bounded file readers pin regular inodes and blob directories; hostile records, symlinks/FIFOs, substitution, authentication and known-answer tests. No page redistribution or live WorldServer routing is enabled.
  - [x] Deterministic monthly search preparation format and authenticated reader: only captures strictly before the first day contribute documents, term frequencies or lengths; stable document IDs and ordered postings, explicit ASCII tokenization, named resource/query caps and hostile posting-reference tests. URL-ordered conjunctive candidate lookup supports inspecting the format; tantivy BM25 and the search service remain open.
- [ ] Other ecosystems: npm, crates.io, Go modules; research Maven
  - [x] Offline cutoff filters (`docs/phase4-plan.md`): npm filter reviewed and public input boundary bounded; `python/hermetic_ecosystem_cut` adds crates.io sparse-index `pubtime` and Go proxy `.info` `Time` filtering, exact nanosecond boundaries, deterministic output, unknown-date reports, duplicate/version validation and named input/output caps. Unknown crate yank dates use TR-PKG-2's not-yanked-and-listed rule; no current yank state is presented as historical truth.
  - [x] Offline continuation: PyPI simple/JSON upload-time filtering and deterministic HTML rendering, with file-level cutoff boundaries, exclusion/reporting of unknown dates, strict bounded parsers and hostile-input tests. Reviewed preparation defects fixed: nested Cargo schema validation, canonical Go versions and output cap, npm direct-input NUL keys and descriptor-pinned publication preflight. No dependencies added or existing tests changed.
  - [x] Offline frozen-store build (`python/hermetic_ecosystem_cut/mirror.py`): integrate crates/Go/PyPI/npm filters with digest-checked acquisition blobs; publish admitted metadata and downloads, local URLs, Cargo config, Go version case escaping and admitted-only `@latest`, deterministic hash manifests and separate operator reports. Private descriptor-pinned staging and complete-tree rename, named resource caps, hostile-input/publication tests and a production WorldServer `DirStore` integration test. Unverifiable retained npm non-latest tags fail closed in this builder; the existing filter contract remains open below. See `docs/phase4-plan.md` for recipe and CLI.
  - [x] Offline publication manifest verification (`verify_mirror`): require the trusted world digest and cutoff, authenticate all served bytes and uncertainty reports, reject malformed inventories/order/paths/types and enforce the builder's named caps before returning immutable bytes. Blob acquisition now retains its root directory descriptor across all reads; directory and symlink substitution regressions failed before repair. No rootfs or WorldServer startup integration is claimed.
  - [x] Offline payload identity review: replay/search consumers and mirror build/verification retain bounded input inventories and consume the exact immutable byte objects whose digests were checked. Five regressions failed before repair when entries changed during hashing; the repaired targeted suite passed 258 tests. Existing tests and dependencies are preserved; final gate results are in `docs/phase4-plan.md`.
  - [x] Go info inventory review: retain a private copy before aggregate input validation so later caller substitutions cannot bypass `MAX_INPUT_BYTES` or change admission. Replacement and removal regressions both failed before repair; the targeted ecosystem/mirror suite passes 149 tests. Full Python gate: 2285 passed, 1 skipped, exit 0. Full Rust gate remains blocked by the same four VMM ancestor-ownership failures (exit 101). Existing tests and dependencies are preserved; exact gate results and remaining blockers are in `docs/phase4-plan.md`.
  - [x] Direct npm tree identity review: capture containers during bounded validation and filter only the retained tree. Four regressions failed before repair when later caller changes injected oversized/cyclic metadata, removed a version or replaced its date. Two companion cases check typed refusal of dictionary resizing during validation. The targeted suite passes 174 tests; full Python gate: 2291 passed, 1 skipped, exit 0. Full Rust gate remains blocked by the same four VMM ancestor-ownership failures, exit 101. Existing tests and dependencies are preserved; exact gates and open prerequisites are recorded in `docs/phase4-plan.md`.
  - [x] Offline npm resolver fixture: real deterministic tarballs, a scoped package and transitive dependency installed by a real npm client from exact frozen builder bytes with an empty cache/config. Assert admitted versions, lockfile integrity and requested downloads; refuse external sockets and disable lifecycle scripts. Local npm/Node are required; Cargo/Go fixtures remain open.
  - [x] Offline guest install configurations for pip/npm/Cargo/Go (`hermetic_ecosystem_cut.install`): fixed frozen-store authorities intercepted by NetVM, no Go direct/VCS/toolchain fallback, no npm audit or lifecycle scripts, hash manifest and strict bundle verification before rootfs installation. Host environment independence and hostile path/content/manifest/cap tests. Rootfs installation and clean client environment/cache assembly remain integration work.
  - [x] Real Cargo offline resolver fixture uses exact frozen index and deterministic archive bytes in Cargo's local-registry layout; asserts the admitted dependency executes, lockfile version/checksum match and corrupted archive bytes fail. A matching real Go file-proxy fixture is implemented but skipped here because no local Go executable is available; no Go validation is claimed.
  - [x] Real pip offline wheel fixture installs an admitted root package and transitive dependency from exact frozen artifact bytes, with empty private home/cache and the delivered pip configuration. Future/undated wheels are absent; installed metadata and imported versions are checked. HTTP/NetVM resolver validation remains open.
  - [x] Additional parser review: npm's shared byte parser rejects non-byte inputs and invalid or unbounded cap values before parsing, using fixed typed errors. Reproduced uncontrolled TypeError/AttributeError failures; regression tests added without changing existing tests.
  - [x] I/O diagnostic review: npm's bounded reader and atomic writer suppress private OS exception causes as well as using fixed messages. Five regressions reproduce private paths/details in ordinary exception-chain logging before repair; existing tests are preserved.
  - [x] Offline publisher review: fix npm's preflight-to-read path substitution using the retained parent and expected inode (two regressions); omit metadata routes for packages without admitted releases, preventing post-cutoff package-existence leaks (twelve regressions). All regressions were observed failing before repair. Keep excluded inventories in operator-only reports and retain full validation even for an empty admitted inventory.
  - [ ] Deferred integration: source acquisition and dated immutable-manifest provenance, npm tag history, Go h1/sumdb provenance, cutoff-aware recording/resolver builds including build dependencies, HTTP/NetVM Cargo/Go install validation, execution of the Go fixture, rootfs client setup, E4 and monthly baseline sizing. The offline store establishes integrity of recipe-bound bytes; it does not establish source provenance or complete ecosystem support.
  - [x] Initial Maven research: release-list metadata has no per-release publication time; snapshot metadata retains current entries. Supporting Maven requires dated, digest-bound artifact provenance or a historical snapshot, including POMs/plugins/parents/classifiers. Primary sources and remaining work are in `docs/phase4-plan.md`; no Maven support is claimed.
  - [x] Resolved 2026-11-14 (owner decision: drop post-cutoff npm tags): with no tag history in a packument, `cut_packument` drops every `dist-tags` entry except `latest`, which is recomputed from admitted versions; the mirror serves only that. Proof: `test_tags_pointing_at_admitted_versions_are_still_dropped`, `test_mirror_npm_mutable_tags_are_dropped_and_never_published`.
- [ ] Other provider adapters for the gateway
- [ ] Smart git protocol terminated in NetVM (for shallow clones)
  - [ ] Review 2026-11-15: the branch's three commits contain no smart Git implementation. NetVM still rejects POST; sealed reachable-object repository binding, upload-pack v2 shallow/deepen, a bounded pkt-line parser and hostile protocol tests remain open. Implementing them requires the NetVM transport and repository-serving components outside this preparation change set; see `docs/phase4-plan.md`.
- [ ] State-task live grading from a snapshot (TR-VMM-6, §11.4)
  - [x] Review 2026-11-15: retain the snapshot payload inventory before validating keys and collecting bytes. Two regressions reproduce missing-artifact acceptance and unchecked unknown-role `KeyError` before the fix; the targeted suite passes 120 tests. Full Python gate: 2294 passed, 1 skipped, exit 0. Rust gate: exit 101 at the four existing VMM ancestor-ownership failures; host mapping remains open. Details are in `docs/phase4-plan.md`.
  - [x] Offline handoff and grading-path formats (`python/hermetic_state_snapshot.py`): canonical bounded manifests bind memory/state/base/overlay artifacts, run identity and CPU-model/Firecracker/kernel/initramfs/template digests; authenticated readers require independent destination-runtime pins. Records retain `shared` isolation and distinguish live grading from trusted-initramfs reboot with an explicit fallback reason. Hostile-input, compatibility, exact-byte, cap and environment-independence tests; no VM or filesystem access.
  - [x] In-memory snapshot artifact verification: authenticate the handoff, validate the complete payload inventory and all size caps before hashing, then return the exact immutable verified bytes. Mapping substitution during hashing cannot replace returned payloads. Combined snapshot/error review tests pass (118 cases); full Python gate includes them.
  - [x] Offline immutable snapshot-byte verification (`verify_snapshot_artifacts`): authenticate the handoff against independent pins, require exactly four bounded byte payloads, check all sizes before hashing any payload, and verify every digest. Return the exact verified bytes in stable role order, independent of later input-mapping changes. Hostile inventories, corrupt/truncated/growing bodies, wrong pins, named caps and ordering tests; streaming file acquisition and VM restore remain open.
  - [ ] Trusted harness integration: close model/network access, pause and consistently snapshot memory plus disk, verify artifact bytes in isolation, match reserved drive/interface topology, redirect every interface to a tap without a peer before resume, attach/mount tests read-only, supervise grading, perform trusted-initramfs fallback, and embed the selected path in the signed run record. VM/KVM validation remains open.
- [ ] Split mode for Mode G (agent in a second VM)
- [ ] TEE quotes (SEV-SNP, TDX, Nitro)
- [ ] aarch64 (pl031 RTC offset patch)
- [x] Resolve whether archived pages can be redistributed: owner decision 2026-11-14, archived pages stay local-only and are never redistributed or published.

### Preparation and remaining prerequisites (2026-11-14)

- [x] Final branch/preparation review: the requested three-dot diff and branch-only
  log remain empty at `9fa9070`; reviewed the uncommitted offline Phase 4 code,
  tests and specifications as well. An offline 1,027-case field-mutation sweep
  found no unexpected exception, and no additional verified defect was found.
  No code, existing test, dependency or git state was changed. The npm history,
  gateway startup and host UID-mapping findings below remain open; exact gate
  results are recorded in `docs/phase4-plan.md`. Rust gate: exit 101 at the same
  four VMM ancestor-ownership failures, after formatting/clippy and gateway
  tests passed. Subsequent Python gate: 2291 passed, 1 skipped, 12 warnings,
  exit 0. No full Rust gate success is claimed.

- [x] Resolved 2026-11-14: `Server::http_with_deadlines` / `from_listener_with_deadlines` install the read deadlines before the accept thread starts, and the gateway binary uses them (proof: `deadlines_given_at_construction_bound_the_first_connection`). Original finding, gateway startup deadline race: `Server::http` begins accepting
  before `GatewayServer::run_loop` installs request deadlines. A request queued
  in that window caches unlimited body reads; installing deadlines later does
  not bound it. Independently reproduced with an incomplete local request that
  remained blocked after a subsequently installed 50 ms deadline. Requires
  gateway/HTTP acceptance lifecycle work outside this preparation scope; see
  `docs/phase4-plan.md`. No existing test or deadline policy was weakened.

The branch started with no commits or diff relative to `main`; the preparation
plan and interface details are in [docs/phase4-plan.md](docs/phase4-plan.md).
No deliverable above is removed or reduced:

- Web/search remains open: production WorldServer replay/search routing, source acquisition for
  Common Crawl/Wayback/Software Heritage, Stack Exchange reconstruction, and D10
  fingerprint/thread/revision provenance integration. BM25 requires tantivy,
  which is not in the existing dependencies; adding it needs owner authorization
  under the no-new-dependencies constraint. The new offline interchange formats
  and readers do not replace that engine or its integration requirements.
- Owner decisions: archived-page redistribution, the additional provider/endpoint
  and pin set, and the TEE platform. Until redistribution is resolved, publish
  recipes and manifests only, as architecture §6.5 requires.
- Smart git termination in NetVM and the remote file layer for split Mode G
  remain implementation work; end-to-end validation needs the NetVM/VM path.
- State-task snapshot orchestration/grading, TEE quote verification, the aarch64 RTC patch,
  E2 Track B and E5 remain open and need the matching VM/KVM or platform access.
- Gate environment blocker: rust-gate's VMM filesystem/process fixtures refuse
  `unsafe ancestor ownership` because this sandbox maps host root-owned `/` and
  ancestors to unmapped UID 65534 (`/proc/self/uid_map`: `1000 0 1`). The production
  ownership check is preserved. Full VMM gate validation needs a host with normal
  UID mappings; changing that host/sandbox mapping is outside this branch.
  The continuation reproduced the same four failures (`rust-gate` exit 101);
  `py-gate` then passed with 1854 tests and exit 0. Details are in the plan.
  The offline-store continuation reproduced them again in both Rust runs
  (formatting/clippy passed, gate exit 101). Its final `py-gate` passed with
  1920 tests and exit 0; all 66 new builder/cleanup cases pass, and the separate
  production `DirStore` integration test passes. Source-provenance work and the
  host mapping remain open; no full-gate success is claimed.
  The input-identity/package-existence review and npm install continuation ran
  both full gates twice more: Rust runs 5 and 6 each exited 101 with the same
  four ownership failures after formatting/clippy passed. Python run 5 passed
  1923 tests; the final run 6, including both repairs, passed 1939 tests with
  exit 0. All 14 newly reproduced regression cases now pass; no existing tests
  were changed. Exact results and remaining blockers are in the plan.
  The client-config/replay/search continuation's Rust run 7 again exited 101
  with those four ownership failures; Python run 7 passed 2127 tests with one
  new Go-toolchain skip, 12 existing warnings and exit 0. The separate production
  `DirStore` test passed. All new parser regressions and offline preparation
  tests passed; no dependency, git state mutation or original test change was
  made. The full Rust gate and historical npm tag policy remain OPEN.
  The publication-authentication continuation's Rust run 8 exited 101 at the
  same four VMM ownership failures after formatting/clippy passed. Python run 8
  passed 2160 tests with one unavailable-Go skip, 12 existing warnings and exit
  0; all 33 new publication tests pass. The separate production `DirStore`
  integration passed. The two blob-root substitution regressions failed before
  repair; no existing test was changed. The host mapping and npm history/policy
  remain OPEN, with exact results in the plan.
  The snapshot continuation's Rust run 9 exited 101 in the existing gateway
  stalled-body test; a focused rerun passed, and an independent bounded
  reproduction established the startup deadline race recorded above. Rust run
  10 passed that test and exited 101 at the same four VMM ownership failures.
  Python runs 9 and 10 passed with 2231 and 2278 tests respectively, one
  unavailable-Go skip, 12 existing warnings and exit 0. Concurrent npm I/O error
  disclosure repairs and artifact verification were reviewed and preserved;
  five exception-chain regressions now pass without leaking private OS details.
  No original test or production ownership check was weakened. Exact results
  and the unresolved component/host prerequisites are in the plan.
  The artifact-verification/diagnostic review's distinct-log final Rust gate
  exited 101 at those same four VMM ownership failures after formatting, clippy
  and gateway tests passed. Its subsequent full Python gate exited 0 with
  2278 passed, one unavailable-Go skip and 12 existing warnings, including all
  42 snapshot-byte cases and five diagnostic regressions. Logs and exact results
  are in the plan; npm history, gateway startup integration and host UID mapping
  remain OPEN. Git state and existing tests are preserved.
  The retained-payload inventory review reproduced five archive/search/mirror
  substitution failures and repaired all five. Its full Rust gate exited 101
  at the same four VMM ancestor-ownership failures after formatting/clippy and
  gateway tests passed; the subsequent full Python gate exited 0 with 2283
  passed, one unavailable-Go skip and 12 existing warnings. No existing test,
  dependency or production ownership check was changed. Exact results and logs
  are in the plan; npm history, gateway startup and host UID mapping remain OPEN.

### Exit
- E2 Track B: start fully sealed and open one channel at a time.
- E5: date evidence at each clock level; 0 outside the substrate at `hidden`.

### Integration findings, 2026-11-13 (grader path)
- [x] Grader PID 1: static unsafe-free binary; read-only proc, /tmp, devpts; clock from `hermetic.t` first (reuse execd clock code); run the supervisor with fixed config and result drive; sync and power off; no vsock or network. Plus the vmm grader drive layout (1 MiB result drive) and VM-exit detection. Unblocks the grader VM boot and its clock check (TR-GR-1/2).
- [ ] Supervisor isolation: apply the `hermetic-grader-sandbox` plan (pid/mount/ipc/uts/net namespaces, capability drop, no_new_privs, device list, cgroup v2 block-device deny); record pipe on fd 3 or higher; process-group kill.
- [x] Extraction format: the validator's HEXT v1 format is canonical; `hermetic-extract-agent` emits it byte for byte. Tree root is `patch:` / `repo_dir: ""` on both sides; `.` is refused. Cross-crate test `crates/hermetic-extract-agent/tests/validator_compat.rs`; grader smoke now runs agent then validator (done 2026-11-13).
