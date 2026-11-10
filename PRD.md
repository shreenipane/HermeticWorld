# Hermetic World: Product Requirements

- **Status:** Draft, derived from [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md) (the spec). Section references (§) point there.
- **Last updated:** 2026-11-10

---

## 1. Problem

Agent benchmarks are built from past events: a GitHub issue and its fix, or a task with a known answer. Agents are evaluated in today's world, where that answer already exists. An agent can therefore *retrieve* the answer instead of *deriving* it. It can walk git history past the base commit, install a later version of the library, find the merged PR online, or read the benchmark itself from a cache.

Evidence (§1.1, §2):

- 63% of Opus 4.8 Max's successful SWE-bench Pro fixes were retrieved rather than derived (Cursor).
- Sealing git history and the internet dropped its score from 87.1% to 73.0%.
- 57% of its trajectories found the merged PR online.
- Real escapes have happened: DNS delegation out of an "offline" sandbox, answers left in task configs, and `conftest.py` hooks that force every test to pass.

Existing work seals single channels (git history, the live network). Nobody offers an open, checkable, cross-benchmark guarantee that **no** post-cutoff information was reachable, and that the score wasn't forged.

## 2. Users

| User | Need |
|---|---|
| **Benchmark maintainers** | Find leaks in their tasks (leak report), repair or exclude them, and publish scores that mean "derived" |
| **Evaluation researchers** | Measure how much of a model's score is retrieval (ablation, E2) and compare models on a sealed footing |
| **Labs and model developers** | Publish benchmark numbers with a signed, third-party-checkable claim about the seal and the grading |
| **Readers of published scores** | Check what a number does and doesn't prove (score card, §12.4–12.5) |

## 3. Goals

| ID | Goal | Measured by |
|---|---|---|
| G1 | **Answer seal (P1).** No information created after `T_world` is reachable: repo beyond the base commit, later project versions, the issue thread, the web, benchmark data, and (in `strict`) third-party library code. | E1 canary recovery = 0; E3 scanner accuracy |
| G2 | **Date seal (P2).** Nothing the agent can read states a date later than the guest clock, at a recorded level (`hidden` / `faked` / `real`). | E5; real-date sentinel (D12) |
| G3 | **Score integrity (P3).** The score depends only on the submitted work, graded in a clean environment, and forgery is detected. | E8 forger suite |
| G4 | **Checkable claims.** Every run produces a signed record that someone else can verify. | `hermetic verify`; E7 reproducibility |
| G5 | **Fidelity.** Sealing doesn't break honest solutions. | E4 ≥ 99%; E9; E10 |
| G6 | **Practical cost.** Fast enough to run whole benchmarks. | E6: cached gate < 5 s; end to end < 1.5× Docker |

## 4. Non-goals

- **Undetectability.** An agent with root can always find signs of a sandbox.
- **Contamination in the model's weights.** Reported, not solved.
- **Timing side channels.** Measured, not closed.
- **Hiding the cutoff itself.** The newest item in the world, and the clock, show where it is.
- **Hiding the physical CPU's generation.** It gives only a lower bound on the date.
- **Not in the first release:** multi-container (compose) tasks, nested Docker, GPU tasks, and live-internet tasks. E9 measures how many tasks this excludes.

## 5. Product requirements

### 5.1 Sealing and verification

| ID | Requirement | Spec |
|---|---|---|
| PR-1 | Compute three cutoffs per task (`T_world`, repo boundary, `T_clock`) and record any `pkg_cutoff` override and every discarded author date. | §4 |
| PR-2 | Build a sealed world bundle with a manifest whose `world_root` is a Merkle root over everything it names. | §6, §13.1 |
| PR-3 | Offer two seal levels: `strict` for published scores, and `repo_only` for images that don't rebuild at the cutoff and for quick experiments. | §1.3 |
| PR-4 | Scan both the raw task image (to produce the leak report) and the bundle (as the gate), with detectors D0–D12. | §5 |
| PR-5 | Output findings as JSON and SARIF, each with a channel, an evidence path, visibility, severity and confidence. An agent-visible gate finding stops the task (exit code 2). | §5.4 |
| PR-6 | Never drop a task silently. Every gate failure is either `repaired` (new world version) or `excluded` (listed with its detector). | §5.5 |
| PR-7 | Scrub the target issue's thread after the problem statement, the solution PR, and anything linking to it, independent of dates. | §4 |
| PR-8 | Take mutable content (issue bodies, comments, forum posts) at its revision as of `T_world`. Exclude content with no capture or edit history. | §4 |
| PR-9 | Support both dated tasks (SWE-bench style) and undated tasks (Terminal-Bench style). | §5.1 |

### 5.2 Running agents

| ID | Requirement | Spec |
|---|---|---|
| PR-10 | Run the agent as root in an isolated VM with no internet route. Its only network is the frozen world. | §3, §7 |
| PR-11 | Support Mode H (the harness runs outside the VM; every command is recorded on the host) and Mode G (shipped agents such as Claude Code and Codex run inside the VM). | §9.1 |
| PR-12 | Route model traffic through a default-deny gateway that rejects provider-hosted tools, remote sources and server-side state, and strips dates from responses. | §9.2 |
| PR-13 | Ensure ordinary installs (pip, conda, git, curl) work against the sealed world, with TLS trusted. | §6.3, §7.2 |
| PR-14 | Run an escape probe before each batch. Every way out must fail, and the result goes into the record. | §9.6 |
| PR-15 | Set the guest clock to `T_clock` and record the clock level achieved. | §8 |

### 5.3 Grading

| ID | Requirement | Spec |
|---|---|---|
| PR-16 | Extract the agent's work without the host ever mounting the agent's disk. | §10 |
| PR-17 | Grade in a clean VM with no network, where results come from a supervisor and not from the test runner's output. | §11.1 |
| PR-18 | Detect forgery with differential grading: R0 normal, R1 mutant, R2 equivalence, and R3 fix removal (advisory). | §11.2 |
| PR-19 | One shot: grader output never reaches an agent. A retry is a new run, and attempts are counted. | §11.1 |
| PR-20 | Grade state tasks live from a paused snapshot, with reduced isolation, and report them separately. | §11.4 |
| PR-21 | Label each success as derived or retrieved using host-side logs only. In a sealed world, a "retrieved" label is a seal failure to investigate. | §5.6 |

### 5.4 Records and reporting

| ID | Requirement | Spec |
|---|---|---|
| PR-22 | Sign a run record (`hermetic-run/v1`) and a separate audit record (`hermetic-transcript-audit/v1`) as in-toto DSSE envelopes. | §12.1–12.2 |
| PR-23 | Give every run one of seven statuses: `resolved`, `unresolved`, `tampered`, `limit_exceeded`, `review`, `infra_error`, `gate_blocked`. | §12.3 |
| PR-24 | Publish a score card with every number: benchmark version, version tuple, seal, clock and agent mode, counts per status and per class, excluded and repaired lists, and the `substrate_at_T` spread. | §12.4 |
| PR-25 | Treat scores as comparable only within the same version tuple. | §12.4 |
| PR-26 | State plainly what the records do **not** prove. | §12.5 |

## 6. Success metrics

| # | Metric | Target |
|---|---|---|
| E1 | Canary recovery per channel in a seeded-leak red team | 0 (every later escape is logged publicly) |
| E2 | Pass-rate change per channel (ablation tracks A and B) | Reported, against Cursor's 14.1- and 20.7-point gaps |
| E3 | Gate precision and recall on blind and real leak sets | Precision ≥ 95%, recall ≥ 90% |
| E4 | Oracle fidelity per world version | ≥ 99% of tasks |
| E5 | Cited date evidence after `T_clock`, outside the substrate, at `hidden` | 0 |
| E6 | Overhead | Cached gate < 5 s; end to end < 1.5× Docker |
| E7 | World root when the same task is sealed twice | Identical |
| E8 | Forgers caught or blocked; false alarms on honest fixes | All caught; < 1% false alarms |
| E9 | Tasks that pass in Docker and in the microVM | Reported, with causes |
| E10 | Legitimate gateway requests wrongly blocked; real dates reaching the guest | < 1%; 0 |

**Minimum publishable result:** the Phase 1 leak report plus the Phase 2 ablation (§15.1).

## 7. Release plan

See [PHASES.md](PHASES.md). In summary: 0 vertical slice → 1 sealcheck → 2 world → 3 VMs → 3b clock hiding → 4 extensions. If time runs out, cut in this order: Phase 4, Phase 3b, Mode G, R3, R2.

## 8. Risks

These are product-level risks. The technical risks are in [TRD.md § Open technical risks](TRD.md#10-open-technical-risks).

- **Budget.** The E2 ablation needs many paired runs on frontier models. API cost, not engineering, limits it.
- **Sources.** Several incident details come from secondhand write-ups. Replace them with primary sources before publishing.
- **Redistribution.** It's unresolved whether world bundles with archived pages can be shared. Until it is, publish manifests and build recipes only.
- **Disclosure.** Findings about public benchmarks go to maintainers privately first.
- **Coverage.** Tasks that fall back to `repo_only`, fail in the VM, or can't get R1 mutants reduce how much a score can claim. All of these are reported, never hidden.
