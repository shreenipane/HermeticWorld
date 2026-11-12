# Hermetic World: Phases

- **Status:** derived from §15 of [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md). Requirement IDs refer to [TRD.md](TRD.md).
- **Last updated:** 2026-11-11

Tick items off here as they land, and log each one in [BUILD_LOG.md](BUILD_LOG.md).

## Overview

| Phase | Name | Runs on | Exit criterion | Status |
|---|---|---|---|---|
| 0 | Vertical slice | WSL2 Ubuntu + Docker | Oracle passes on every slice task; one agent run graded | **Done** 2026-11-11 |
| 1 | sealcheck | Laptop (no KVM) | E3 targets met; leak report on one public benchmark, disclosed privately | In progress |
| 2 | World | Any Linux box | E4 ≥ 99%; E2 Track A on the paired subset; E10 | Not started |
| 3 | VMs | Linux x86 + KVM | E1, E8, E9 | Not started |
| 3b | Clock hiding | Linux x86 + KVM | Probe passes → `clock: hidden` (else ship `faked`) | Not started |
| 4 | Extensions | Linux x86 + KVM | E2 Track B; E5 | Not started |

```
0 ──▶ 1 ──▶ 2 ──▶ 3 ──▶ 3b
                   └───▶ 4
```

**Cut list.** If time runs out, drop in this order: Phase 4 → Phase 3b → Mode G → R3 → R2.

**Smallest publishable result:** the Phase 1 leak report plus the Phase 2 ablation (E2 Track A).

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
  - [x] Binary tier (TR-SC-5) (T1.4; `.pyc` coverage is weak, see BUILD_LOG)
- [x] Container recursion with bomb limits, including git packs (TR-SC-6) (T1.2, T1.3)
- [ ] Detectors D0–D12 (TR-SC-7): done D0, D1, D2, D3, D3b, D5a, D6, D9. Remaining, in order: D4, D5b, D7, D8, D10, D11, D12
- [x] Thread scrub and mutable-content revision rule (TR-SEAL-9) (T1.13)
  - [ ] Deferred (T1.13 review, non-blocking): scrub URL matching misses aliases of the same resource (`www.github.com`, `http://`, trailing-dot host, empty path segments, `/repositories/{id}/...`); canonicalise or deny them before a WorldServer maps aliases to stored content
  - [ ] Deferred (T1.13 review): the CLI secret-safety test calls `intake` with arguments the parser rejects, so the exception path is never exercised; use valid arguments and assert the mock ran
  - [ ] Deferred (T1.13 review): `open_secure_directory` refuses operator-supplied roots that traverse symlinks; decide whether a trusted prefix may be resolved (no-follow stays for everything beneath it)
  - [ ] Deferred (T1.13 review): task publication wraps every failure as `task_publication_failed` and drops the cause; pass `IntakeError` through and keep the error class
  - [ ] Deferred (T1.13 review): decide whether the scrub fallback paths should return the as-scraped statement with `problem_statement_revision = as_scraped` and a warning (today they exclude content)
  - [ ] Deferred (T1.13 review): fixture `pytest_issue_6189_edits.json` has a creation edit dated before the issue's creation; the cache case in `test_http.py` can pass before the bounded-read check
  - [ ] Deferred (gates): Docker tests use fixed image and network names (`hermetic-test/fake-swebench`, `hermetic-world-test-inst-1-net`), so two py-gate runs at once make `test_cli_seal_images` and `test_world_probe_cli` fail; use per-run names
- [ ] Dispositions: `repaired` / `excluded`, never silent (§5.5)
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
- [ ] Rootfs build with `SOURCE_DATE_EPOCH` mke2fs (e2fsprogs ≥ 1.47.1) and a D4 guard (TR-SEAL-7, TR-SEAL-8)
- [ ] Package world (TR-PKG-*)
  - [ ] Layer 1: recording index for the task closure (pip, uv, conda via pixi)
  - [ ] Yanked-release handling
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
- [ ] Trust injection: per-world CA, every trust store, environment defaults (TR-SEAL-10)
- [ ] Gateway with the Anthropic adapter (TR-GW-*)
- [ ] Container isolation of the agent, with the run spec applied
- [x] Manifest with `world_root`
- [ ] Reproducibility check (E7)
- [ ] E4 oracle harness: gold passes, `FAIL_TO_PASS` fails on base, per-test parity with the official harness, flaky-test detection (3×), pytest plugin list
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
- [ ] `hermetic-vmm`: Firecracker + jailer orchestration (TR-VMM-1)
- [ ] Guest kernel build: config, boot args, pinned build timestamp (TR-VMM-4, TR-VMM-5)
- [ ] `hermetic-execd`: clock-first boot, run spec, vsock RPC, shutdown freeze (TR-EXD-*)
- [ ] NetVM: dm-verity image, DNS table, TPROXY + TLS, drop everything else (TR-NET-*)
- [ ] AgentVM on a CoW world; Mode H through vsock 5000
- [ ] Mode G: `/opt/agent` volume, model path NetVM → gateway (cut list: optional)
- [ ] ExtractorVM plus host validator (TR-EXT-*)
- [ ] GraderVM supervisor and isolation (TR-GR-1 to TR-GR-5)
- [ ] `hermetic_mutants`: variant pool, base-failing assertion finder, validation (TR-GR-8, TR-GR-9)
- [ ] Differential runs R0, R1 and R2 in parallel; R3 advisory (cut list: R3, then R2)
- [ ] Escape probe (TR-SEC-6)
- [x] Real-date sentinel D12 (TR-SEC-5)
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

**Goal.** Reach `clock: hidden`, or prove it can't be done here and ship `faked`.

### Deliverables
- [ ] Compile and apply `firecracker-enforce-pv-cpuid.patch`; confirm #GP on the masked MSRs
- [ ] Apply the `hide-kvmclock.cpu-template.json` CPU template
- [ ] Block the clock-pairing hypercall on the host. Try in order:
  1. a non-TSC host clocksource (`hpet` / `acpi_pm`)
  2. Xen hypercall interception (a second patch plus `CONFIG_KVM_XEN`)
  3. a host kernel patch (only on hardware you control)
- [ ] Check TSC stability without kvmclock
- [ ] Add the eighth check to `clock-leak-probe.md`: the hypercall from a guest kernel module
- [ ] Run the probe, plus a control run on unpatched Firecracker

### Exit
The probe passes, giving `clock: hidden`. Otherwise, record why and ship `faked`.

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
