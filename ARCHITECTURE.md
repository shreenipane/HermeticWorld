# Hermetic World: Architecture Overview

This is a condensed, navigable view of the system. The full design, with rationale and sources, is in [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md) (the spec). Section references (§) point there.

---

## 1. Threat model in one line

The agent has **root inside AgentVM and can run its own kernel code**. No boundary may depend on anything inside AgentVM. NetVM is assumed compromisable because it parses hostile traffic. The gateway is the only component with both hostile input and internet egress, so it is a ring of its own. (§2)

Assets: post-cutoff information (the fix, the tests, later code and pages), the real date, and the integrity of the score. The spec enumerates 26 leak channels in §2, each mapped to what closes it.

## 2. Rings and components

```
 STAGING HOST (online)
   seal ─▶ sealcheck ─▶ oracle check ─▶ world bundle ──────────▶ run host
                 └─▶ leak report (private)   grader images ────▶ grading host

 RUN HOST (no internet route)
   harness ──▶ gateway ──▶ model provider       (own netns; the only egress)
      │ vsock 5000 (Mode H)     ▲ vsock (Mode G: model host name only)
      ▼                         │
   Ring 1 AgentVM ──tap──▶ Ring 2 NetVM ──frames──▶ Ring 3 WorldServer
      │ overlay, read-only, after shutdown
      ▼
   ExtractorVM ──framed stream──▶ host validator ──▶ validated work

 GRADING HOST (no network)
   validated work ──▶ Ring 4 GraderVM: normal + mutant + equivalence runs
                                   └──▶ signed records
```

| Component | Ring | Trust | Role |
|---|---|---|---|
| **Sealer** | Staging | Trusted | Builds the sealed repo, rootfs, package world and manifest (§6) |
| **sealcheck** | Staging | Trusted | Proves nothing post-cutoff is reachable; produces the leak report and the gate (§5) |
| **AgentVM** | 1 | Fully compromised | Firecracker VM where the agent works as root |
| **NetVM** | 2 | Compromisable | Answers all AgentVM network traffic from the frozen world; dm-verity image, single static binary, no shell (§7.1) |
| **WorldServer** | 3 | Trusted, locked down | Host process serving the frozen store read-only under Landlock and seccomp (§7.3) |
| **Gateway** | Own ring | Hostile input + egress | The only path to the model provider; default deny (§9.2) |
| **execd** | Inside VMs | Untrusted in AgentVM | PID 1: clock-first boot, run spec, command server, shutdown freeze (§8.3, §9.4) |
| **ExtractorVM** | Throwaway | Disposable | Parses the agent's untrusted disk in its own kernel and streams out the work (§10) |
| **Host validator** | Host | Trusted | Rust validator for the extraction stream (§10) |
| **GraderVM** | 4 | Clean per run | Runs R0–R3 with a supervisor as PID 1; no network, no vsock (§11) |
| **Classifier** | Grading host | Trusted | Labels each success derived or retrieved from host-side logs (§5.6) |
| **Attest** | Host | Trusted | Signs `hermetic-run/v1` and `hermetic-transcript-audit/v1` (§12) |

## 3. Deployment roles (§3.2)

| Role | Network | Holds | Never holds |
|---|---|---|---|
| Staging host | Online | Raw images, gold patches, hidden tests, sealer, sealcheck + fingerprints | n/a |
| Run host | No internet route | World bundles, NetVM image, agent VMs | Gold patches, hidden tests, fingerprints, grader images, API keys |
| Gateway + harness | Provider egress only | API key, request logs | World, tests |
| Grading host | None | Grader images with tests, test variants, classifier + fingerprints | API keys |

On one machine (`deployment: single_host`), the roles are separate Unix users and network namespaces. Grader files sit outside every jailer chroot and can't be read by the user that runs the agent-phase Firecracker.

## 4. Run lifecycle (§3.4)

| # | Step | Where | Notes |
|---|---|---|---|
| 1 | **Seal** | Staging | Cutoffs → world bundle + manifest → freeze the world root |
| 2 | **Verify** | Staging | sealcheck gate; repair or exclude |
| 3 | **Oracle check (E4)** | Staging | Gold patch passes in the sealed world; variants validate. Once per world version. |
| 4 | **Ship** | → run / grading host | Bundle by digest; grader images separately |
| 5 | **Probe** | Run host | Rooted throwaway AgentVM tries every way out |
| 6 | **Boot** | Run host | NetVM, then AgentVM on a copy-on-write copy of the world |
| 7 | **Work** | Run host | Model traffic through the gateway; all other traffic AgentVM → NetVM → WorldServer |
| 8 | **Stop** | Run host | Kill processes, freeze ext4, destroy VMs. State tasks: pause and snapshot instead. |
| 9 | **Extract** | Run host | ExtractorVM → framed stream → host validator |
| 10 | **Grade** | Grading host | R0, R1, R2 in parallel, each in a fresh GraderVM; R3 advisory |
| 11 | **Classify** | Grading host | Derived vs retrieved from host-side logs |
| 12 | **Sign** | Host | Run record + audit record |

## 5. Subsystems at a glance

### 5.1 Cutoffs (§4)
- `T_world` is the earliest of: issue created, first commit in the fix PR, fix PR opened. It governs web, search, packages and the thread.
- The repo boundary is the base commit, by reachability.
- `T_clock` = max(`T_world`, base commit time). It governs the guest clock, `SOURCE_DATE_EPOCH`, certificates and HTTP `Date`.

### 5.2 sealcheck (§5)
- Fingerprints come from the gold patch, the hidden tests and up to 20 other passing fixes, with fingerprints already in the base tree subtracted out.
- Four tiers:
  - weighted lines and windows, plus diff shape (the gate);
  - IDF-weighted statement symbols (review);
  - winnowing with k=8, w=8;
  - binary symbols and strings.
- It looks inside containers up to four levels deep, with bomb limits.
- Detectors D0–D12 (see [TRD.md](TRD.md#42-hermetic-sealcheck)).
- Performance split: a **layer index** once per layer digest, and a **task query** per task in under 5 s.

### 5.3 World construction (§6)
- **Repo:** copy only objects reachable from the base commit. Keep tags that point at ancestors. Strip remotes, reflog, stash, `refs/pull` and hooks. Rebuild the commit-graph.
- **Rootfs:** `SOURCE_DATE_EPOCH=T_clock mke2fs` (e2fsprogs ≥ 1.47.1), then D4 as a guard. Strip dated logs and caches.
- **Packages:**
  - Layer 1 is the recorded task closure, built with `uv --exclude-newer`, pip `--uploaded-prior-to` and pixi `exclude-newer`.
  - Layer 2 is the ecosystem baseline for the cutoff month.
  - apt comes from a snapshot.
- **Web (Phase 4):** a BM25 index per month, and exact-capture page replay.

### 5.4 Network (§7)
- NetVM DNS answers only manifest names from a fixed table; everything else gets NXDOMAIN.
- TCP 80/443 with a known host name is intercepted with TPROXY, TLS is terminated with a per-world CA leaf, and GET/HEAD become fixed frames to WorldServer.
- Everything else is dropped or reset.
- The world CA is valid from `T_clock` and installed into every trust store. Its key is delivered over vsock at boot.
- WorldServer: Landlock, seccomp, size-capped frames, rate shaping, a volume cap, a BLAKE3 hash-chained log and a dedupe index.

### 5.5 Time (§8)
- `faked` = the guest clock set to `T_clock`.
- `hidden` also closes all three host-time paths:
  - kvmclock MSRs, through the CPUID mask plus a Firecracker patch that enforces it;
  - the clock-pairing hypercall, through a host-side block;
  - the RTC, which isn't emulated on x86.
- The execd boot sets the clock **before** anything writable is mounted.

### 5.6 Execution (§9)
- **Mode H:** the harness sends commands over vsock 5000, and the host records each one.
- **Mode G:** the agent runs in the VM from a self-contained read-only `/opt/agent` volume.
- Gateway: per-provider default-deny adapters, typed reconstruction of each request, response and error sanitising, a 128-bit cache nonce, hard quotas, and a history-consistency log.

### 5.7 Extraction (§10)
- The host never mounts the agent's disk.
- ExtractorVM mounts overlayfs read-only with `redirect_dir=nofollow,metacopy=off,index=off` and compares the merged view with the base in its own binary. It never runs `git`.
- It emits length-prefixed records, not tar.
- The host validator accepts only regular files, directories and deletions. It enforces no path escapes and quotas, keeps only the executable bit, restores test infrastructure to its base version, and flags shadowing modules.

### 5.8 Grading (§11)
- A clean image with tests baked in.
- The supervisor is PID 1 and reads per-test start and finish records over a pipe.
- Tests run in their own PID and mount namespace, without `CAP_MKNOD`, under a cgroup device rule.
- Python runs with `-s`, and pytest with plugin autoload off.
- Differential runs R0–R3. **R1 and R2 must be indistinguishable.** Only base-failing assertions in hidden lines are mutated.

## 6. Interfaces (§13.2)

| Interface | Direction | Trust | Format |
|---|---|---|---|
| execd RPC (vsock 5000) | Host → AgentVM | Replies untrusted | Length-prefixed frames: exec, upload, download, status |
| NetVM → WorldServer (vsock) | NetVM → host | Requests untrusted | Fixed binary frames: authority, path+query, method |
| Model path, Mode G | AgentVM → NetVM → gateway | Untrusted | HTTP, checked by the adapter |
| Model path, Mode H | Harness → gateway | Semi-trusted | Same adapter |
| Extractor stream | ExtractorVM → host | Untrusted | Length-prefixed records |
| Grader result | GraderVM → grading host | Untrusted | Fixed-schema record on an output disk |

## 7. Design invariants

These are the rules that make the guarantees hold. A change that breaks one of them needs a spec change first.

1. **No boundary depends on anything inside AgentVM.** (§2)
2. **The host never listens for a connection that AgentVM starts.** (§13.2)
3. **The host never mounts AgentVM's disk.** (§10)
4. **Nothing forwards to the live internet.** The world is built ahead of time, and NetVM has no upstream. (§2 ch. 12, §7.1)
5. **The world is frozen before evaluation.** Misses only go into the next world version. (§6.3)
6. **The run host never holds the answers:** no gold patches, hidden tests, fingerprints, grader images or keys. (§3.2)
7. **No guest bytes or headers are forwarded verbatim upstream.** The gateway rebuilds each request from typed fields. (§9.2)
8. **No grader output ever reaches an agent.** (§11.1)
9. **Only host-side logs count as evidence.** (§2 ch. 24)
10. **No task is dropped silently.** (§5.5)
11. **Every date the guest can see is derived from `T_clock`, never from the host clock.** (§7.2, §8)
12. **The run record contains only deterministic or digest values.** (§12.1)

## 8. Key decisions and rejected alternatives

| Decision | Rejected alternative | Why |
|---|---|---|
| Firecracker microVMs + jailer | Containers | The agent has root and kernel code; a VM boundary is needed (§2) |
| Pre-built frozen world | Filtering proxy to live registries | Live forwarding is attack surface (ch. 12) |
| Index lookup in WorldServer | pywb on the trusted side | Smaller parser surface (§6.5) |
| One CA per world version | Per-run CA; disguised real-looking CAs | Stable rootfs digest; undetectability is a non-goal (§7.1–7.2) |
| ExtractorVM with the kernel's ext4 | User-space ext4 reader on the host | A rooted agent can enable features the reader lacks (§10) |
| Length-prefixed records | tar | Too many extensions to parse safely (§10) |
| ext4 freeze at shutdown | Read-only remount | Remount fails with files open for writing (§9.5) |
| Overlay disk for `/tmp` | tmpfs `/tmp` | Artifacts would vanish; large builds held in memory (§8.3) |
| Differential grading (R1/R2) | Tests in memory; signed results; parent-side verdict; forced external pytest config | All sit inside the process the agent's code runs in (§11.5) |
| Agent volume readable by root | Private mount namespace | Root reaches any namespace through `/proc` (§9.3) |
| Month-floor BM25 index | Exact-date ranking | No ranking statistic can postdate the cutoff (§6.5) |
| Count history rewrites | Reject them | Agents legitimately compact and run sub-agents (§9.2) |

## Code layout

| Path | Owns | Ring |
|---|---|---|
| `crates/hermetic-common` | Manifest, wire frames, hash chain, cutoff logic | Shared |
| `crates/hermetic-sealcheck` | D0–D12, fingerprints, IDF index, layer index, SARIF | Staging |
| `crates/hermetic-sealer` | Repo rebuild, rootfs build + D4 verify, thread scrub, trust injection | Staging |
| `crates/hermetic-world-server` | Store, month index, limits, dedupe index, hash log | 3 |
| `crates/hermetic-netvm` | Ring 2 daemon (static musl) | 2 |
| `crates/hermetic-execd` | PID 1: clock-first boot, run spec, shutdown freeze, vsock runner | 1 / 4 |
| `crates/hermetic-extract` | ExtractorVM agent + host-side validator | Throwaway / host |
| `crates/hermetic-grader` | GraderVM supervisor: R0–R3 | 4 |
| `crates/hermetic-vmm` | Firecracker orchestration, CPU template, patched build, snapshots | Host |
| `crates/hermetic-gateway` | Default-deny adapters, sanitising, nonce, quotas | Own |
| `crates/hermetic-attest` | Run and audit records, score card | Host |
| `crates/hermetic-cli` | `seal`, `verify-bundle`, `probe`, `run`, `verify` | Host |
| `python/hermetic_harbor` | Harbor environment backend | Harness |
| `python/hermetic_pkg_resolver` | Recording index, ecosystem baseline, snapshots | Staging |
| `python/hermetic_mutants` | Test-variant pool generation and validation | Staging |
| `python/hermetic_classifier` | Derived vs retrieved | Grading |
| `images/` | Guest kernel config, NetVM and extractor root filesystems | n/a |
| `vmm/` | `firecracker-enforce-pv-cpuid.patch`, `hide-kvmclock.cpu-template.json` | n/a |

The crates may start as modules of one crate (§15.2).
