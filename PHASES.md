# Hermetic World: Phases

- **Status:** derived from §15 of [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md). Requirement IDs refer to [TRD.md](TRD.md).
- **Last updated:** 2026-11-14

Tick items off here as they land, and log each one in [BUILD_LOG.md](BUILD_LOG.md).

## Overview

| Phase | Name | Runs on | Exit criterion | Status |
|---|---|---|---|---|
| 0 | Vertical slice | WSL2 Ubuntu + Docker | Oracle passes on every slice task; one agent run graded | **Done** 2026-11-11 |
| 1 | sealcheck | Laptop (no KVM) | E3 targets met; leak report on one public benchmark, disclosed privately | In progress |
| 2 | World | Any Linux box | E4 ≥ 99%; E2 Track A on the paired subset; E10 | In progress; construction and oracle integration open |
| 3 | VMs | Linux x86 + KVM | E1, E8, E9 | In progress; runtime components merged, VM acceptance open |
| 3b | Clock hiding | Linux x86 + KVM | Probe passes → `clock: hidden` (else ship `faked`) | Source audit/proposal; nested tests open |
| 4 | Extensions | Linux x86 + KVM | E2 Track B; E5 | Not started |

```
0 ──▶ 1 ──▶ 2 ──▶ 3 ──▶ 3b
                   └───▶ 4
```

**Cut list.** If time runs out, drop in this order: Phase 4 → Phase 3b → Mode G → R3 → R2.

**Smallest publishable result:** the Phase 1 leak report plus the Phase 2 ablation (E2 Track A).

### Integration status, 2026-11-13/14

Recorded from `git log --all --since=2026-11-13`; a merge into `int-night`
does not mean a merge into `main` or completed VM acceptance. No phase exit
criterion is removed by an open dependency.

| Branch | State at this review | Delivered work and remaining acceptance |
|---|---|---|
| `int-night` | Head `2f0856c`; not merged into `main` | Includes the five topic merges below and `77e4eae`: destination-independent service-port interception, AgentVM /32 routing and fragment-watermark boot fix. Review and prepared-host VM reruns remain necessary. |
| `agent-h` | Separate branch `e1f7457`, pending review | Optional host harness over execd vsock, deterministic wire vectors, command evidence, Chat Completions gateway adapter and owner-run smoke. No end-to-end VM acceptance recorded by these commits. |
| `guest-lockdown` | Separate branch `155dfae` (after `038272f`, `8096b58`), pending integration | Forced confidentiality lockdown, removal of root kernel/memory interfaces and paravirtual clock hooks, lockdown probes, VMM-owned `tsc_early_khz`. x86 force-selects PERF_EVENTS; lockdown restricts its kernel-reading uses. Kernel rebuild and all VM smoke checks remain open. |
| `clock-3b` | `10d8f5c`, merged into `int-night` by `2f0856c` | Source audit, bounded read-only diagnostic, separate kernel/CPU proposals and nested test plan. Host denial, complete probes and nested acceptance remain open; retain `clock: faked`. |
| `empty-stmt` | Points to `main` at `9fa9070`; no separate branch changes | No empty-statement implementation is present on this branch. The head records the main-fix merge for direct/initramfs execd boot ordering. |
| `httpbin-world` | `aca4738`, merged into `int-night` by `a10f64a` | Bounded local httpbin profile, task/manifest declaration and container-grader lifecycle. Historical requests oracle, AgentVM dispatch and GraderVM lifecycle remain open. |
| `netvm-tls` | `31dd4b3`, merged into `int-night` by `ccfc5ab` | Sealed CA-material boot transfer, TLS termination and verified offline HTTPS tests; prepared-host two-VM verification and dm-verity remain open. |
| `e2e-1` | `62a29e7`, merged into `int-night` by `39173b3` | Real-task export/intake/repository/rootfs/scanning orchestration and private oracle inputs. Deliberately exits 1 before world publication until package, substrate, trust and run-spec evidence is supplied. |
| `t37-noop` | `b7d8a51`, merged into `int-night` by `2de8b60` | Removes generated no-op assignments under the recorded architecture §11.2 decision; other equivalent/mutant rewrites and shortfall reporting remain. |

Main's 2026-11-13 merges also include component review fixes, the detector audit,
HEXT alignment (`d74a79b`), grader PID 1 (`7deae2d`), offline grader-chain
integration (`64143d6`), supervisor isolation (`f9bf272`), NetVM PID 1
(`553d5b3`), AgentVM eth0 setup (`559fe3a`), run-label isolation (`6097c74`),
trusted reboot initramfs (`2bad653`) and boot-order repair (`4b6549b`). These
deliver implementations and smoke entrypoints; the phase exits still require
their specified measurements and VM runs.

Deferred work retained in full:

- [ ] Host-side hypercall/MSR filtering: root with kernel execution can still
  invoke KVM CLOCK_PAIRING or wall/system MSRs; guest lockdown and CPUID masks
  do not establish host denial. Requires host/VMM changes and canary tests.
- [ ] AMD hosts (and nested hosts without usable CPUID.15) need an accurate
  operator-supplied `HERMETIC_TSC_KHZ` with `guest-lockdown`; the resolver fails
  closed without it. No guessed frequency or hidden-clock claim.
- [ ] Httpbin wire-protocol methods/bodies: versioned protocol decision pending
  for request headers/bodies, per-authority method policy, dynamic dispatch and
  auditing. Keep the requests oracle and AgentVM/GraderVM service integration open.
- [ ] CPU identity template: select a cutoff-specific policy and address stock
  Firecracker host-vendor/Intel-brand normalization plus other identity leaves.
  The experimental JSON alone does not implement this policy.

---

## Phase 0: Vertical slice

**Goal.** Run 5–10 SWE-bench Verified tasks end to end with stock tools, to prove the pipeline shape before building any component properly.

**Runs on.** A laptop, in containers, with `clock: real`.

### Deliverables
- [x] Pick 5–10 SWE-bench Verified tasks, spread across repositories and years: 10 tasks in `phase0/tasks.txt`, one per repo, 2019–2023. On 2026-11-11 requests-2317 was replaced by flask-5014, because its tests need httpbin.org.
- [x] Image sealer (T0.3/T0.3a): all 10 real images sealed and verified. It removes the extra SWE-bench commit, the reflog and future history, and restores file modes.
- [x] Minimal cutoff computation (`T_world`, base commit, `T_clock`): done; T0.2 intake feeds it real GitHub, Trac and git dates for all 10 tasks
- [x] Repo sealer: reachable-objects copy, tag filter, strip refs and reflog (TR-SEAL-1 to TR-SEAL-3, TR-SEAL-6), done in T0.1, 25 tests
- [x] Local frozen pip index at the cutoff (T0.4; PEP 503 index of PyPI files uploaded at or before `T_world`, up to 5 versions per installed package, target project excluded; all 10 tasks, 25 MB to 1.5 GB each, 4.4 GB total)
- [x] Docker network with no outside route; the agent container reaches only the index (T0.4; `world-probe` all_ok: positive install, newer version blocked, target blocked, egress blocked)
- [x] Clean container as grader: apply the extracted diff, run `FAIL_TO_PASS` and `PASS_TO_PASS` (T0.5; official SWE-bench eval scripts minus the pip line, swebench 5.0.2 grading rules)
- [x] Unsigned JSON run record (T0.6; `hermetic-slice-run/v0-unsigned`)
- [x] Oracle run: the gold patch passes in the sealed world for every slice task (10/10 on 2026-11-11; django-11099 lists one FAIL_TO_PASS test that already passes without the fix, recorded as `f2p_pass_without_fix`)
- [x] One real agent run, graded: django-11099 on Gemma 4 31B, `RESOLVED_FULL`

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
- [x] `hermetic-common`: manifest types, cutoff logic (TR-CUT-*), hash chain (T1.1)
- [x] Both modes: dated and undated (TR-SC-9)
- [ ] Fingerprints with baseline subtraction (TR-SC-1)
  - [x] Tier 1: lines, windows, diff shape, diff-like text (TR-SC-2) (T1.1)
  - [x] Tier 2: tree-sitter IDF symbols, as review (TR-SC-3)
  - [x] Tier 3: winnowing, k=8, w=8 (TR-SC-4) (T1.2)
  - [x] Binary tier (TR-SC-5) (T1.4; `.pyc` code-object fingerprints T1.12)
    - [ ] Deferred (T1.12 review): both 20,000-function budget tests exhaust a budget of 1,000 during changed-scope discovery; add a sufficiently budgeted test that completes extraction for every changed or added function
    - [ ] Deferred (T1.12 review): reports still declare `"T2"` uncovered for fresh version-5 indexes, which do store and query tier-2 context; report coverage by index version, and correct the documentation
    - [ ] Deferred (T1.12 review): `extract_hunk_symbols_and_anchors` in `tier2.rs` is quadratic in hunk count
    - [x] T1.12 licence note: `crates/hermetic-sealcheck/data/unicode_names.txt` identifies its Unicode 16.0.0 source and links to `data/LICENSE-UNICODE`, containing the Unicode License v3 notice from https://www.unicode.org/license.txt. The root `LICENSE` already contains the full Apache License 2.0 text (owner decision, 2026-11-13).
- [x] Container recursion with bomb limits, including git packs (TR-SC-6) (T1.2, T1.3)
- [ ] Detectors D0–D12 (TR-SC-7): implemented D0, D1, D2, D3, D3b, D4, D5a, D5b (`python/hermetic_d5b`), D6, D9, D11. Detector audit (2026-11-13):
  - [x] D4: live file/directory/symlink mtimes, tar/zip member times, index equivalence, ext4 inode/superblock times; bounded no-follow image reads; dirty journals refused; malformed images report Info and exit 1.
  - [ ] D7: `python/hermetic_d7` compares supplied shipped/rebuilt artifacts with bounded ingestion. Open: no `--deep-audit` rebuild orchestration; requires the sealer's build recipe/artifact mapping and isolation contract (TR-SC-7).
  - [ ] D8: os-release, tzdata, certificates, kernel/config dates, dated logs, Python versions implemented; bounded no-follow I/O and stable relative findings. Open: kernel-image build-string extraction and CPU-template coherence checks require specified artifact paths/formats and a historical CPU policy (architecture detector table); the current kernel checks read module directory versions and config headers.
  - [ ] D10: `python/hermetic_d10` implements archive/metadata times and bounded WARC-Date checks for every record, including gzip/nested captures; malformed captures fail closed. Open: per-record payload fingerprints and verification of thread scrub/revision provenance require integration with the fingerprint scanner and archive provenance contract (architecture detector table, §4).
  - [x] D11: advisory patch inspection, test-infrastructure paths, runner sections, monkeypatching and shadowing; standard unified diffs and quoted paths supported; bounded CLI/library inputs.
  - [ ] D12: advisory text/file scanner implemented with bounded no-follow traversal. Open: host run/probe/gateway integration scanning every guest egress and prompts, and recording `date_leak_observed`, is not wired (TR-SEC-5). `python/hermetic_slice/runner.py` still emits null; the attestation field alone does not implement the sentinel.
  - [ ] Shared path policy: decide whether to reject non-UTF-8 roots/paths or encode their bytes losslessly across scan, index and SARIF. D4/D8 currently normalize rendered strings against the original root; a non-UTF-8 root can retain its host prefix, and lossy path identities can collide.
  - [x] Gate findings outside this detector task: dispositions directory identity under inode reuse and E3 temporary patches inside a repository fixed on `ws-bugs` (`297b00b`), merged into main on 2026-11-13; the same change bounds long socket paths.
- [x] Thread scrub and mutable-content revision rule (TR-SEAL-9) (T1.13)
  - [x] Deferred (T1.13 review, non-blocking): scrub URL matching misses aliases of the same resource (`www.github.com`, `http://`, trailing-dot host, empty path segments, `/repositories/{id}/...`); canonicalise or deny them before a WorldServer maps aliases to stored content — aliases canonicalised; unverifiable repository-ID routes denied; regression cases added.
  - [x] Deferred (T1.13 review): the CLI secret-safety test calls `intake` with arguments the parser rejects, so the exception path is never exercised; use valid arguments and assert the mock ran — valid CLI arguments, mocked dataset, call and error-output assertions.
  - [x] Deferred (T1.13 review): `open_secure_directory` refuses operator-supplied roots that traverse symlinks; decide whether a trusted prefix may be resolved (no-follow stays for everything beneath it) — fail closed: physical paths required throughout; documented and tested.
  - [x] Deferred (T1.13 review): task publication wraps every failure as `task_publication_failed` and drops the cause; pass `IntakeError` through and keep the error class — typed intake failures preserved; unexpected exceptions remain sanitised; stale-tree cleanup now has entry/depth caps and checks opened directory identity.
  - [x] Deferred (T1.13 review): decide whether the scrub fallback paths should return the as-scraped statement with `problem_statement_revision = as_scraped` and a warning (today they exclude content) — retain exclusion per §4: no verified history means no content; tested with GitHub alias denial.
  - [x] Deferred (T1.13 review): fixture `pytest_issue_6189_edits.json` has a creation edit dated before the issue's creation; the cache case in `test_http.py` can pass before the bounded-read check — impossible edit removed; cache-growth case now asserts bounded_read executed.
  - [x] Deferred (gates): fixed Docker image/network names replaced with per-run names on `flaky-fix` (`513f4e9`) and `sealer-test-iso` (`a158e9a`), merged into main on 2026-11-13.
- [x] Dispositions: `repaired` / `excluded`, never silent (§5.5) (T1.14)
  - [x] Deferred (T1.14 review, non-blocking): a report with an inline manifest is rejected on rerun after publication changed the disk manifest, so an interrupted repair cannot finish in that case; reconcile the inline manifest with verified repair metadata — only the verified repair transition is reconciled; interrupted and complete reruns tested.
  - [x] Deferred (T1.14 review): Python checks UTF-8 span boundaries after merging spans (`redact_problem_statement("é", [(0,1),(1,2)])` succeeds; Rust rejects); validate every supplied boundary first — all original boundaries checked, including adjacent and nested spans.
  - [x] Deferred (T1.14 review): Python and Rust count surviving characters differently (literal `[REDACTED]` in the original, whitespace definition incl. U+001C–U+001F); specify one rule and add cross-language cases — count original surviving Unicode scalars outside explicit Unicode White_Space; matching known cases in both languages.
  - [x] Deferred (T1.14 review): empty spans are accepted during repair but rejected by persisted-metadata validation, so every later rerun fails; reject them before publication — empty spans rejected before merging in both languages.
  - [x] Deferred (T1.14 review): every replaced file becomes mode 0600, including an originally 0644 problem statement, so a runner under another uid cannot read it; preserve statement permissions — checked descriptor supplies statement permissions; private metadata stays 0600; reruns tested.
  - [x] Deferred (T1.14 review): an unusable explicit `--sealcheck` path silently falls back to PATH and developer locations; fail instead — explicit executable failure stops resolution; no fallback call.
  - [x] Deferred (T1.14 review): clean tasks get a manifest `clean` disposition although TRD §2 allows only `repaired` and `excluded`, which also changes an unchanged world's root; keep `clean` in the per-run report only — manifest enum rejects clean; clean processing preserves the root.
  - [x] Deferred (T1.14 review): excluding a previously repaired task appends to the manifest, leaving both statuses; separate repair history from the current disposition — only current status in dispositions; root-bound repair_history in exclusion detail; repeated exclusion and re-verification tested.
  - [x] Deferred (T1.14 review): missing tests for the merged mode-restore script (`RESTORE_MODES_SH`): replacement between stat and open, fstat hard-link rejection, stalled `git ls-tree` with child termination, ancestor swap, and a FIFO-replacement test that runs the real script with an outside sentinel (the current race section tests its own `os.open` flags) — real shell-script race tests cover all cases, unchanged sentinel modes/content, and killed/reaped child.
- [x] JSON and SARIF output; exit code 2 on an agent-visible gate finding (TR-SC-8) (T1.1)
- [x] Layer index plus per-task query, under 5 s (TR-SC-10)
- [ ] E3 corpus: seeded leaks (done, T1.5: precision 100%, recall 89.8% on 175 cases), blind-seeded leaks from a second person, and real leaks (pytest-6202, SWE-Bench+ cases, the Cybench config), including deletion-only and one-character fixes, patch files, archives and SQLite
- [ ] Calibrate the tier-1 and tier-2 thresholds against E3

### Exit
- E3: gate precision ≥ 95% and recall ≥ 90% on the blind and real sets.
- A leak report on one public benchmark, disclosed privately to its maintainers.

---

## Phase 2: World

**Goal.** Full world construction with a real WorldServer and gateway, still on containers. Produces the headline ablation.

**Runs on.** Any Linux box.

### Deliverables
- [x] Rootfs build with `SOURCE_DATE_EPOCH` mke2fs (e2fsprogs ≥ 1.47.1) and a D4 guard (TR-SEAL-7, TR-SEAL-8) (T2.4; tar stream into `mke2fs -d`, pinned e2fsprogs 1.47.2 and `data/mke2fs-hermetic.conf`)
  - [ ] Decision to confirm (T2.4): the image keeps no extended attributes; mtimes are clamped to min(source, T_clock); source paths with symlinked ancestors are refused
  - [ ] Deferred (T2.4): `_make_output_dirs` still creates missing output directories by path (the directory is then opened anchored and checked before any write)
  - [ ] Deferred (T2.4): `_make_writable_and_retry` in `repo_sealer.py` is no longer used by production code; remove it together with the tests that call it directly
  - [ ] Deferred (T2.4): the simulated-other-uid test stubs the storage ownership checks
- [x] T2.2 deadline repair, merged into main on 2026-11-13 (`ae2e6ef`): each header reader gets its own deadline cell, armed only after body-reader handoff; completed requests cannot clear a successor's deadline. This supersedes the rejected `t2.2` attempt (`b0c7867`).
  - [x] Body-reader deadline lifetime and connection-slot lifetime fixes are included in `ae2e6ef`, with regression tests. This records the implementation; it does not assert that every previously observed load-dependent timeout has been reproduced or resolved.
  - [ ] Remaining sequential-stream concerns: do not release a successor before its predecessor finishes; do not block while dropping a waiting reader (`crates/vendor/tiny_http/src/util/sequential.rs`). The latter still calls blocking `recv().unwrap()`; these items are not closed by the deadline-cell repair.
- [ ] Package world (TR-PKG-*)
  - [ ] Layer 1: recording index for the task closure (pip, uv, conda via pixi)
  - [ ] Yanked-release handling (simple-index yank rewriting in `python/hermetic_yank`, merged 2026-11-13; wiring into the package mirror still open)
  - [ ] Layer 2: ecosystem baseline per cutoff month; measure its storage
  - [ ] apt snapshots where available
- [ ] Ecosystems: PyPI, conda, Debian/Ubuntu, git dependencies (static mirrors)
- [ ] `strict` class B rebuild, with `repo_only` fallback and labelling
- [x] WorldServer: read-only store, Landlock, seccomp, frames, limits, hash log, dedupe index (TR-WS-*) (T2.1)
  - [ ] Deferred (T2.1 review, non-blocking): endpoint probes use a blocking `UnixStream::connect` against a lock listener that never accepts; repeated recovery attempts on one endpoint can fill the backlog and block startup; use non-blocking exclusive ownership
  - [ ] Deferred (T2.1 review): the live-endpoint test passes `--recover` without `--resume-log`, so it is rejected before endpoint ownership is checked; give it valid recovery inputs and assert the original listener still serves
  - [ ] Deferred (T2.1 review): the seccomp allow-list still permits arbitrary Unix-socket connects, signalling other same-uid processes, credential-changing syscalls and `clock_settime`; remove them and test denial
  - [ ] Deferred (T2.1 review): the Landlock failure-injection test sets a process-global flag while other tests start sandboxed servers; isolate it in a child process
  - [ ] Deferred (T2.1 review): no test stalls a child, thread or socket to prove the bounded test helpers actually time out
  - [ ] Deferred (T2.1): publication and endpoint reclaim trust same-uid processes and root (directories must be owned by the server uid and not group/other writable); `renameat2(RENAME_NOREPLACE)` is not used because the crate forbids unsafe code
- [x] Trust injection: per-world CA, every trust store, environment defaults (TR-SEAL-10) (T2.5)
  - [ ] Deferred (T2.5 review, non-blocking): a duplicate-alias error copies keystore alias text (incl. control characters) into `skipped_paths.reason` and reports; return a fixed code
  - [ ] Deferred (T2.5 review): certificate validation gaps: unique-ID fields skipped unvalidated, BOOLEAN accepts any non-zero byte, `pathLenConstraint` checked by tag only, critical SAN/SKI/AKI payloads not validated
  - [ ] Deferred (T2.5 review): the process-global test hooks `FORCE_CHOWN_FAILURE` and `BEFORE_USE_HOOK` are public and consulted in production paths; move injection to test-only, per-thread code
  - [ ] Deferred (T2.5 review): CA seed and plaintext key PEM buffers are not zeroised; two guarded `unwrap()` calls remain; no compile-failure check for unsupported targets
  - [ ] Deferred (T2.5): on-disk ownership with a guest owner different from the sealing user is tested only by recording the ownership step, because this host cannot create user namespaces; run `test_created_entries_owned_by_guest_owner_in_user_namespace` where `unshare -Ur` works
  - [ ] Deferred (T2.5, owner decision): the installer's check-then-use protection assumes exclusive access to the rootfs; the full fix needs `openat2`/`cap-std` (new dependency)
- [ ] Gateway with the Anthropic adapter (TR-GW-*)
  - [x] Policy core: default-deny adapter, request and response rewriting, quotas, history, streaming (TR-GW-2 to TR-GW-8) (T2.2)
  - [ ] Gateway isolation (TR-GW-1)
  - [ ] Deferred (T2.2 review): operator config and API-key paths are opened without refusing symlinked ancestor directories
  - [ ] Deferred (T2.2 review): quota errors expose internal reasons and configured limits instead of standard messages
  - [ ] Deferred (T2.2 review): source validation traverses arbitrary tool inputs and schemas, so a legitimate tool argument shaped like a URL image source is refused
  - [ ] Deferred (T2.2 review): every read failure on a successful upstream response is classified as a timeout (e.g. invalid UTF-8)
  - [ ] Deferred (T2.2 review): original SSE error bodies are never logged (`original_error_body` is always `None` for streams)
  - [ ] Deferred (T2.2 review): an unrecognised upstream error type falls back to the HTTP-status-derived type instead of `api_error`
  - [ ] Note (T2.2): `tiny_http` 0.12.0 is vendored with local patches at `crates/vendor/tiny_http` (see `VENDORED.md`); a half-closed client never frees its slot before the upstream ends, and a waiting request gets a bounded 529
- [ ] Container isolation of the agent, with the run spec applied
- [x] Manifest with `world_root`
- [ ] Reproducibility check (E7)
- [ ] E4 oracle harness: gold passes, `FAIL_TO_PASS` fails on base, per-test parity with the official harness, flaky-test detection (3×), pytest plugin list (oracle result analysis in `python/hermetic_oracle`, merged 2026-11-13; harness run still open)
  - [x] On `int-night`: `httpbin-v1` local profile with bounded deterministic endpoints, manifest/task registration and container-grader startup/cleanup (`aca4738`).
  - [ ] Historical requests oracle still needs HTTPS/hardcoded-host routing and timeout semantics; AgentVM needs the versioned WorldServer protocol decision, and GraderVM needs service lifecycle/loopback/interpreter/result-fd isolation. See [HTTPBIN.md](python/hermetic_slice/HTTPBIN.md).
  - [x] On `int-night`: stage-one real-task sealing (`62a29e7`) retains bounded private artifacts and prepares exact oracle inputs without executing them on the host.
  - [ ] Stage-one completion: supply D5b inventory/release metadata, package closure/baseline roots, substrate inventory/exemptions, installed trust and run spec before manifest publication. Current runner exits 1 with an open verdict; oracle execution remains separate. See [E2E_SEAL.md](scripts/integration/E2E_SEAL.md).
- [ ] E2 design: a paired subset of 50–100 tasks stratified by repo and year, ≥ 2 seeds, bootstrap intervals, McNemar, drift control

### Exit
- E4 ≥ 99%.
- E2 Track A run on the paired subset.
- E10 gateway conformance: < 1% wrongly blocked and 0 real dates.

---

## Phase 3: VMs

**Goal.** Replace containers with the ring architecture, and add differential grading and signed records.

**Runs on.** Linux x86 with KVM (bare metal, or EC2 with nested virtualization).

### Deliverables
- [ ] `hermetic-vmm`: Firecracker + jailer orchestration (TR-VMM-1) (T3.3 merged: spec validation, request plan with the kvmclock-hiding CPU template, jail plan, lifecycle, API client, dev-unjailed mode; Firecracker v1.18.0 pinned)
  - [ ] Open (T3.3): run the jailer tests as root (owner runs `sudo -v` first) and the in-VM boot test once a guest kernel and rootfs exist
  - [x] Open (T3.3): confirm the status-frame format against `hermetic-execd` (T3.1): execd now emits the guest clock the vmm decoder expects; to be proven end to end at the first VM boot
- [ ] Guest kernel build: config, boot args, pinned build timestamp (TR-VMM-4, TR-VMM-5) (T3.2 tooling and first builds merged; Linux 6.6.160 integration in `870c859`; lockdown branch rebuild/acceptance still open)
- [x] `hermetic-execd`: clock-first boot, run spec, vsock RPC, shutdown freeze (TR-EXD-*) (T3.1, merged 2026-11-13 after review+fix; status frame now carries the guest clock for the vmm decoder)
  - [x] Early proc handoff: `init=/sbin/hermetic-init` shim mounts read-only procfs then execs execd (clock-first kept); guest kernel moved to 6.6.160 with devtmpfs automount and initrd support; dev-unjailed boot smoke in `scripts/integration/boot-smoke.sh`
  - [x] TR-EXD-6 trusted-reboot initramfs: reproducible `newc` builder with known-answer hash, `hermetic.initramfs=1` clock-first devtmpfs/base assembly, pinned and bounded hermetic-vmm initrd snapshot, and host boot record; first boot uses the base-resident `init=/sbin/hermetic-init` shim
  - [ ] Open: run `bash scripts/integration/reboot-smoke.sh /tmp/hermetic-reboot-smoke` on a KVM-capable host to verify the touched-disk reboot; this sandbox has no `/dev/kvm`
  - [ ] Open: propagate the VMM host boot record into the signed `hermetic-attest::RunRecord`; that component's schema has no boot-path/initrd field and requires a separate record-schema change
  - [ ] Open: upload publication can be raced by a guest process replacing the temporary entry before rename; needs a writer-quiescence or owned-inode publication design
  - [ ] Open: synchronous filesystem I/O can stall the single RPC loop; needs isolated filesystem workers
- [ ] NetVM: dm-verity image, DNS table, TPROXY + TLS, drop everything else (TR-NET-*)
  - [x] First-cut runtime: PID 1 clock setup, fixed eth0 addresses, table DNS, HTTP filter to persistent serialized WorldServer frames (CID 2 port 5001), ingress/egress service-port filter, forwarding and IPv6 off; offline transport/policy tests
  - [x] NetVM tree/image builder through existing D4-checked rootfs tooling; AgentVM resolver and network in run spec
  - [x] Automatic eth0 initialization from the AgentVM run spec: validated IPv4 address/prefix, NetVM gateway and MTU; /32 mode adds an explicit peer route; fixed, bounded trusted busybox commands after clock/root setup and before entrypoint/vsock; fail closed; offline validation/order/failure tests. Network smoke inspects setup instead of supplying harness commands; VM verification remains below.
  - [x] TLS termination, per-world CA-key/issuance-seed boot delivery on private vsock 5003, sealed world/clock/DNS/CA/material binding, deterministic bounded leaf minting, ECH/SNI/Host rejection and public CA trust injection. Offline verified GET/HEAD and rejection tests pass; smoke now requires successful verified HTTPS and unrelated-trust failure. Owner-run VM verification remains open below.
  - [x] TR-NET-3 interception fallback: fixed eth0 PREROUTING REDIRECT for TCP 80/443 independent of destination IP, bounded conntrack/fragment state, deny filter installed first. AgentVM /32 plus an explicit peer route sends other link addresses through the filter. TLS on 443 uses the same sealed policy; offline rule/route/failure tests pass, VM verification remains open.
  - [ ] Open: dm-verity for NetVM (TR-NET-1). No veritysetup tool is installed; pinned kernel has DM_INIT disabled; guest-kernel boot policy requires root=/dev/vda and rejects dm setup arguments. Requires authenticated root-hash metadata and VMM boot wiring; precise plan and corruption checks in BOOT_NOTES.md. Current image is D4-checked read-only ext4.
  - [ ] Open: two-VM boot/network verification; this environment has no /dev/kvm. Run `scripts/integration/net-smoke.sh "$HOME/hermetic-netvm-smoke"` on the prepared host with a policy-checked kernel including built-in legacy IPv4 filtering, NAT, conntrack and REDIRECT (see BOOT_NOTES.md, Network VM).
- [ ] AgentVM on a CoW world; Mode H through vsock 5000
  - [ ] Separate `agent-h` branch (`e1f7457`): host harness and Chat Completions adapter implemented, pending review/integration and prepared-host `agent-h-smoke.sh`. Exact count_tokens and inline-document mappings remain a provider-policy decision; unsupported requests fail closed.
- [ ] Mode G: `/opt/agent` volume, model path NetVM → gateway (cut list: optional)
- [ ] ExtractorVM plus host validator (TR-EXT-*)
  - [x] Components, canonical HEXT compatibility and offline chain merged on 2026-11-13; prepared-host VM extraction/validation acceptance remains open.
- [ ] GraderVM supervisor and isolation (TR-GR-1 to TR-GR-5)
  - [x] Grader PID 1, supervisor sandbox-plan application, deadline/diagnostic handling and offline chain merged on 2026-11-13 (`7deae2d`, `f9bf272`, `f872ad1`, `64143d6`); complete VM and forgery acceptance remains open.
- [ ] `hermetic_mutants`: variant pool, base-failing assertion finder, validation (TR-GR-8, TR-GR-9)
  - [x] Owner decision (2026-11-13): HERMETIC_WORLD_ARCHITECTURE.md §11.2 takes precedence over the T3.7 brief's no-op insertion requirement. Removed no-op assignments from equivalent and paired mutant generation; kept the other rewrites and shortfall reporting. Regression tests cover all generated variants, marker strings, docstrings and deterministic known answers.
- [ ] Differential runs R0, R1 and R2 in parallel; R3 advisory (cut list: R3, then R2)
- [ ] Escape probe (TR-SEC-6)
- [ ] Real-date sentinel D12 (TR-SEC-5): scanner exists; runtime/probe/gateway wiring and `date_leak_observed` aggregation remain open (see detector audit above).
- [ ] Classifier (TR-CLS-*)
- [ ] Attestations: `hermetic-run/v1`, `hermetic-transcript-audit/v1`, score card (TR-ATT-*)
- [ ] Harbor backend (TR-HB-1); prototype registration early, since it's a known risk
- [ ] `hermetic-cli`: `seal`, `verify-bundle`, `probe`, `run`, `verify`
- [ ] `clock: faked`

### Exit
- E1: zero canary recovery per channel.
- E8: every forger caught or blocked, with < 1% false alarms.
- E9: Docker vs microVM compatibility reported, with causes.

---

## Phase 3b: Clock hiding

**Goal.** Reach `clock: hidden`, or record the remaining channels and ship `faked`.

- [x] Import and audit the clock analysis against Linux 6.6.160 and Firecracker
  v1.18.0; [source evidence and corrected claims](docs/clock-3b-analysis.md).
- [x] Add the std-only, read-only `hermetic-clockprobe` workspace crate with
  bounded descriptor-based inspection and offline classification/regression fixtures.
  `unavailable` is incomplete coverage, even with exit 0.
  - [x] Integration review: inspect every supplied CPU record, reject unexpected
    available clocksources, and require a valid log cutoff; offline regressions
    demonstrate the former false negatives.
- [x] Keep the kernel/CPU proposals separate in `images/kernel/clock-3b.config`
  and `vmm/clock-3b.cpu-template.json`; active settings are unchanged.
  - [ ] Reconcile the old clock proposal's `PERF_EVENTS=n` request and matching
    artifact test with the kernel policy on `guest-lockdown`: pinned Linux
    6.6.160 `arch/x86/Kconfig` unconditionally selects PERF_EVENTS. The proposed
    fragment cannot retain every requested value after olddefconfig, so its
    current artifact test does not establish a buildable policy. Kernel-policy
    integration and acceptance remain open.
- [x] Document the exact [execd baseline command and nested test matrix](docs/clock-3b-config-and-test-plan.md).
- [ ] Manager: run today's AgentVM baseline and the nested kernel/VMM tests.
- [ ] Close root clock channels: CPUID clearing alone does not deny the wall/system
  MSRs with stock Firecracker. Per-vCPU PV enforcement gates these MSRs, but in
  the inspected KVM it does **not** gate CLOCK_PAIRING. Hypercall 9 rejects CPL3
  and exposes real UTC to a CPL0 caller when the host clocksource supports it.
  EXIT_HYPERCALL cannot filter number 9 in this kernel. Host/VMM denial and the
  proposed guest restriction policy require an owner decision and runtime tests.
- [ ] Resolve CPU identity: stock Firecracker normalization restores host vendor
  and overwrites Intel brand modifiers, potentially retaining a host frequency.
  Full cutoff-specific CPUID normalization is not established by the proposal.
- [ ] Resolve reported PIT/TSC boot stall: `tsc=reliable` supplies no frequency;
  zeroing .15/.16 can remove calibration routes. Test accurate `tsc_early_khz`
  (frequency exposed, so `faked`); a fixed hidden rate needs actual KVM TSC scaling
  and consistent calibration, not an invented number. Firecracker does create a PIT.
- [ ] Complete safe CLOCK_TAI/absolute CLOCK_MONOTONIC/RTC ioctl sampling; the
  std-only and CPUID/RDTSC-only unsafe constraints need a wrapper/design decision.
- [ ] Decide residual timing/identity risks; validate device ABIs, payloads,
  images, boot/serial strings, all vCPUs and snapshot history before `hidden`.

**Exit.** Retain `clock: faked` until the missing denial tests and complete
channel coverage pass. This source audit and diagnostic do not attest `hidden`.

---

## Phase 4: Extensions

**Goal.** Broaden coverage. Every item is independent and can be cut.

### Deliverables
- [ ] Web archive and search: a tantivy BM25 index per month, exact-capture replay, Common Crawl, Wayback, Software Heritage, and Stack Exchange rebuilt from post history
- [ ] Other ecosystems: npm, crates.io, Go modules; research Maven
- [ ] Other provider adapters for the gateway
- [ ] Smart git protocol terminated in NetVM (for shallow clones)
- [ ] State-task live grading from a snapshot (TR-VMM-6, §11.4)
- [ ] Split mode for Mode G (agent in a second VM)
- [ ] TEE quotes (SEV-SNP, TDX, Nitro)
- [ ] aarch64 (pl031 RTC offset patch)
- [ ] Resolve whether archived pages can be redistributed

### Exit
- E2 Track B: start fully sealed and open one channel at a time.
- E5: date evidence at each clock level; 0 outside the substrate at `hidden`.

### Integration findings, 2026-11-13 (grader path)
- [x] Grader PID 1: static unsafe-free binary; read-only proc, /tmp, devpts; clock from `hermetic.t` first (reuse execd clock code); run the supervisor with fixed config and result drive; sync and power off; no vsock or network. Plus the vmm grader drive layout (1 MiB result drive) and VM-exit detection. Unblocks the grader VM boot and its clock check (TR-GR-1/2).
- [x] Supervisor isolation: `sup-isolation` (`f9bf272`), merged into main on 2026-11-13, applies the sandbox plan (pid/mount/ipc/uts/net namespaces, capability drop, no_new_privs, devices and cgroup v2 policy), isolated result descriptor and process-group teardown. Prepared-host VM acceptance remains part of Phase 3.
- [x] Extraction format: the validator's HEXT v1 format is canonical; `hermetic-extract-agent` emits it byte for byte. Tree root is `patch:` / `repo_dir: ""` on both sides; `.` is refused. Cross-crate test `crates/hermetic-extract-agent/tests/validator_compat.rs`; grader smoke now runs agent then validator (done 2026-11-13).
