# Hermetic World: Technical Requirements

- **Status:** Draft, derived from [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md) (the spec). Section references (§) point there.
- **Last updated:** 2026-11-10
- **Companion docs:** [PRD.md](PRD.md) (what and why), [ARCHITECTURE.md](ARCHITECTURE.md) (shape), [PHASES.md](PHASES.md) (order).

Requirement IDs use the form `TR-<area>-<n>`. "Must" is a gate for the phase that delivers the component. "Should" is best effort, and its outcome must be recorded.

---

## 1. Platform and stack

| Item | Requirement |
|---|---|
| Host OS | Linux x86_64 with KVM (Phase 3+). aarch64 later; it needs a pl031 RTC offset patch (§8.2). |
| Virtualization | Firecracker + jailer. A patched build for `clock: hidden` (§8.2). |
| Core language | Rust. NetVM and execd are static (musl) binaries. |
| Python components | Harbor bridge, package resolvers, test rewriting (mutants), classifier |
| Filesystem build | **e2fsprogs ≥ 1.47.1**, pinned (Debian bookworm's 1.47.0 is not enough) |
| Package resolvers | `uv --exclude-newer`; pip 26 `--uploaded-prior-to`; pixi / rattler `exclude-newer` for conda; npm `--before` (Phase 4) |
| Search | tantivy (BM25) |
| Parsing | tree-sitter (tier-2 symbols, test rewriting) |
| Hashing | BLAKE3 (log chain); Merkle root for `world_root` |
| Host sandboxing | Landlock, seccomp, separate Unix users and network namespaces |
| NetVM image | dm-verity, read-only, no shell |
| Traffic interception | TPROXY |
| Signing | in-toto DSSE envelopes; Sigstore keyless or an offline key |
| Optional attestation | TEE quote: AMD SEV-SNP, Intel TDX or AWS Nitro |

## 2. Configuration enums

These values appear in manifests and records, and must be spelled exactly as below.

| Field | Values |
|---|---|
| `seal_level` | `strict`, `repo_only` |
| `clock` | `hidden`, `faked`, `real` |
| `agent_mode` | `H`, `G` |
| `task_class` | `patch`, `artifact`, `state` |
| `grader_isolation` | `clean`, `shared` |
| `deployment` | `split`, `single_host` |
| `substrate_at_T` | `full`, `partial`, `none` |
| Run status | `resolved`, `unresolved`, `tampered`, `limit_exceeded`, `review`, `infra_error`, `gate_blocked` |
| Disposition | `repaired`, `excluded` |

## 3. Cutoff logic (`hermetic-common`)

- **TR-CUT-1** Must compute `T_world` as the earliest of: issue created, the earliest author or committer date in the fix PR, fix PR opened. Use whichever exist.
- **TR-CUT-2** Must discard an author date only if it is before the repo's first commit, or more than 90 days before every other candidate. Must record each discard. Must not tie dates to the PR's merge-base.
- **TR-CUT-3** Must compute `T_clock` = max(`T_world`, base commit time).
- **TR-CUT-4** Packages use `T_world`. Must allow a per-task `pkg_cutoff` raise to at most the base commit's time, only when E4 shows it is needed, and must record it.
- **TR-CUT-5** For undated tasks, `T_world` is the task's first commit in the benchmark repo, and the world holds only that month's package layers, with no web.

## 4. Component requirements

### 4.1 `hermetic-sealer`
- **TR-SEAL-1** Copy only objects reachable from the base commit into a fresh repo.
- **TR-SEAL-2** Keep a tag only if it points at an ancestor of the base commit. An annotated tag must also be dated ≤ `T_clock` and its message must pass the fingerprint tiers.
- **TR-SEAL-3** Delete remotes, reflog, stash, `FETCH_HEAD`, `ORIG_HEAD`, `refs/pull`, `refs/original`, alternates, hooks, config credentials and `__pycache__`.
- **TR-SEAL-4** Seal submodules at their recorded commits. Keep only the LFS objects the base tree references.
- **TR-SEAL-5** Delete native build outputs and rebuild them where the build is reproducible. Otherwise D3b must pass.
- **TR-SEAL-6** Rebuild the commit-graph and repack. `git log`, `blame` and `bisect` must still work on pre-base history.
- **TR-SEAL-7** Build the rootfs with `SOURCE_DATE_EPOCH=T_clock mke2fs -t ext4 -d <src> -U <fixed uuid> -E hash_seed=<fixed>`. Fail the build if D4 finds any time > `T_clock`.
- **TR-SEAL-8** Delete `/var/log`, `/var/cache`, apt lists, pip and conda caches, and shell history.
- **TR-SEAL-9** Apply the target-thread scrub and the mutable-content revision rule (§4).
- **TR-SEAL-10** Generate one CA per world version, with validity `T_clock` ± 10 years. Install it into the system bundle, every `certifi/cacert.pem`, conda `ssl/cacert.pem` and Java keystores. Record the paths in the manifest.
- **TR-SEAL-11** Write the run spec (§9.4) into the manifest.
- **TR-SEAL-12** Sealing the same task twice must produce an identical `world_root` (E7).

### 4.2 `hermetic-sealcheck`
- **TR-SC-1** Fingerprint the gold patch's added and changed lines, the hidden tests' added lines, and up to 20 deduplicated passing fixes from SWE-bench/experiments. Subtract fingerprints already present at the base commit.
- **TR-SC-2** Tier 1:
  - normalised lines (drop anything < 12 characters, bare keywords and brackets), weighted by rarity in the base tree;
  - 2- and 3-line windows around every changed position;
  - diff shape, with and without hunk ranges;
  - for diff-like text, after-change windows and `-`-marked removed lines.
  - A unit matches at ≥ 60% of a hunk's weight. The threshold is calibrated in E3.
- **TR-SC-3** Tier 2: tree-sitter identifiers, attribute chains and literals in modified statements, IDF-weighted, co-occurring with the file or function name. This is a review flag, not a gate.
- **TR-SC-4** Tier 3: winnowing over code tokens with k = 8, w = 8, which guarantees a match on any shared run of 15 or more tokens.
- **TR-SC-5** Binary tier: identifiers and string literals the fix adds, searched in symbol and string tables.
- **TR-SC-6** Look inside zip, tar, gz, bz2, xz, zstd, git packs, SQLite text cells and `.pyc` constants, up to 4 levels deep, with expansion-ratio and size limits. A bomb ends that container's scan with a finding.
- **TR-SC-7** Implement these detectors:

| ID | Detector | `strict` | `repo_only` |
|---|---|---|---|
| D0 | Problem-statement leak | Gate (T1, T3); review (T2) | same |
| D1 | Git state beyond the base commit | Gate | Gate |
| D2 | Files and archives (tiers 1–3, all classes) | Gate | Gate |
| D3 | Stale bytecode (PEP 552 vs source; orphan `.pyc`) | Gate | Gate |
| D3b | Compiled and derived artifacts | Gate | Gate |
| D4 | Inode and superblock times ≤ `T_clock` | Gate | Gate |
| D5a | Target project at a post-fix version | Gate | Gate |
| D5b | Third-party packages newer than the cutoff | Gate | Warning |
| D6 | OCI and VM metadata | Gate | Gate |
| D7 | Rebuild and diff (`--deep-audit`) | Audit | Audit |
| D8 | Coherence tells | Info | Info |
| D9 | Benchmark presence | Gate | Gate |
| D10 | Dated archive records | Gate | Gate |
| D11 | Test-infrastructure changes (post-run) | Advisory | Advisory |
| D12 | Real-date sentinel | Advisory (P1); counts against P2 | same |

- **TR-SC-8** Output JSON and SARIF. Each finding has a channel, an evidence path, visibility (agent-visible / image-only), severity and confidence. Any agent-visible gate finding exits with code 2.
- **TR-SC-9** Undated mode runs D0, D2, D3b, D9 and D6 against `solution/` and `tests/`.
- **TR-SC-10** Build a layer index once per unique layer digest: inode times, package manifests with dates, and line, window and winnow hashes. A task query must take **< 5 s**, even uncached for that task.

### 4.3 Package world (`hermetic_pkg_resolver`)
- **TR-PKG-1** Layer 1: record the task closure by running setup and the oracle build through a recording index at the package cutoff. Build environments must honour the cutoff too.
- **TR-PKG-2** Serve releases that were yanked after the cutoff as not yanked. If the yank date is unknown, serve the file as not yanked and list it.
- **TR-PKG-3** Cut conda packages by their repodata `timestamp`. A package with no timestamp is unknown: listed, and it fails D5b in `strict` unless exempted by hand.
- **TR-PKG-4** Layer 2: a task-independent baseline per cutoff month (common dev and test tools plus the top-N closure per ecosystem).
- **TR-PKG-5** apt from a snapshot at the cutoff where one exists (Ubuntu only after 2023-03-01).
- **TR-PKG-6** Freeze the world root before evaluation. Misses logged during runs go only into the next world version.

### 4.4 `hermetic-world-server` (Ring 3)
- **TR-WS-1** One process per run over a shared read-only store. Open the store and the month index read-only, then apply Landlock (read the store, write only the log) and seccomp (no internet sockets, `exec`, `ptrace` or `mount`).
- **TR-WS-2** Accept only fixed-format, size-capped binary frames from NetVM. A malformed frame ends the run with status `tampered`.
- **TR-WS-3** Serve package indexes, metadata sidecar files and byte ranges, apt snapshot indexes, static git mirrors (dumb HTTP), search, and archived pages.
- **TR-WS-4** Strip `Memento-*`, `X-Archive-*` and `Server: pywb`. Set `Date` = `T_clock` + elapsed. Answer misses with the kind of 404 the real site would send.
- **TR-WS-5** Shape the rate with a token bucket that delays and never kills. Enforce a per-run total request and byte cap, set from the oracle's usage with a margin. Exceeding it gives status `limit_exceeded`.
- **TR-WS-6** Keep a BLAKE3 hash-chained append-only log, plus a dedupe index `(authority, path_and_query, status) → count, first_seen, last_seen`.

### 4.5 `hermetic-netvm` (Ring 2)
- **TR-NET-1** Boot from a read-only dm-verity image: one static binary as PID 1, no shell, no writable filesystem. It holds only the world CA key, received over vsock at boot.
- **TR-NET-2** DNS: answer from the manifest's fixed table, and NXDOMAIN for everything else. No upstream.
- **TR-NET-3** TCP 80/443 with a known host name: intercept with TPROXY and terminate TLS with a leaf valid from `T_clock` − 7 days to `T_clock` + 365 days. Forward GET/HEAD as frames. Other methods get 405.
- **TR-NET-4** Unknown or missing SNI or Host, ECH, or non-TLS on 443: reset and log.
- **TR-NET-5** Drop QUIC, DoH, DoT, NTP, ICMP, IPv6, `git://`, SSH and all other traffic.
- **TR-NET-6** Mode G only: forward the model host name's adapter POST endpoints over a second vsock port to the gateway.

### 4.6 `hermetic-execd` (PID 1)
- **TR-EXD-1** Boot order (§8.3):
  1. the rootfs is mounted read-only;
  2. `clock_settime(T_clock)` from `hermetic.t=` is the very first action;
  3. then mount the overlay disk read-write, assemble overlayfs, move devtmpfs and switch root;
  4. mount `/proc`, `/sys`, `/dev/pts` and `/dev/shm`;
  5. re-stamp `/dev`;
  6. apply the run spec;
  7. start the vsock server.
- **TR-EXD-2** `/tmp` and `/run` are overlay directories, not tmpfs.
- **TR-EXD-3** Reap zombies, forward signals, allocate a TTY on request, apply the run spec to every command, and optionally start the image's entry point as a child.
- **TR-EXD-4** RPC over vsock 5000 with length-prefixed frames (exec, upload, download, status). Cap output per command and per run. Re-stamp uploads to guest time.
- **TR-EXD-5** Shutdown: end all other processes, sync, and freeze the upper ext4 through a handle kept since boot. If execd doesn't answer, record `unclean_shutdown`.
- **TR-EXD-6** When a touched disk is rebooted, PID 1 comes from a trusted initramfs.

### 4.7 `hermetic-vmm`
- **TR-VMM-1** Orchestrate Firecracker + jailer for AgentVM, NetVM, ExtractorVM and GraderVM.
- **TR-VMM-2** Apply the CPU template `hide-kvmclock.cpu-template.json`, which clears bits 0 and 3 of leaf `0x40000001` eax, together with a CPU model sold before the cutoff (best effort).
- **TR-VMM-3** `clock: hidden` requires all of:
  - the `firecracker-enforce-pv-cpuid.patch` build, which enables `KVM_CAP_ENFORCE_PV_FEATURE_CPUID` after every `set_cpuid2`, including on restore;
  - a host-side block on `KVM_HC_CLOCK_PAIRING`, using one of: a non-TSC host clocksource, Xen hypercall interception, or a host kernel patch;
  - a passing probe from a guest kernel module.

  Otherwise the level is `faked`.
- **TR-VMM-4** Guest kernel: version 5.10 or newer, without `CONFIG_PTP_1588_CLOCK_KVM`. Enable cgroup v2, namespaces, overlayfs, netfilter, BPF and cgroup BPF. Boot args `clocksource=tsc tsc=reliable`. Pin `KBUILD_BUILD_TIMESTAMP` to the kernel version's release date, and fix `KBUILD_BUILD_USER` and `KBUILD_BUILD_HOST`.
- **TR-VMM-5** Attach virtio-rng. Don't configure MMDS. Re-check VMClock on every Firecracker upgrade.
- **TR-VMM-6** State tasks: pause and snapshot, then resume with `network_overrides` pointing at a tap with no peer, and attach the tests disk with `PATCH /drives` into a slot reserved at boot.

### 4.8 `hermetic-gateway`
- **TR-GW-1** Run as its own user in its own network namespace, under seccomp and Landlock. Egress only to the provider's host names, with TLS verified and redirects refused. The API key lives only in memory.
- **TR-GW-2** One default-deny adapter per provider, listing the allowed endpoints, fields, headers and beta flags. Parse each request into typed fields and rebuild it upstream. Record the adapter version.
- **TR-GW-3** Allow message creation, token counting, the pinned models, text, client-side tools and inline base64 images and documents. Reject provider-hosted tools, URL and file-ID sources, server-side state, background and batch modes, and unlisted beta flags.
- **TR-GW-4** Responses, streaming included:
  - pass only content-type, length and encoding headers, plus `retry-after` in seconds;
  - replace `Date` with guest time;
  - drop rate-limit, request-ID and CDN headers, keeping them in the host log;
  - rewrite body timestamps to guest time.
- **TR-GW-5** Replace a non-success body with a standard error for that status, keeping only the recognised error type. Treat stream error events the same way.
- **TR-GW-6** Prepend a 128-bit random nonce to the system prompt, creating one if absent. Never use a time-based ID.
- **TR-GW-7** Enforce hard quotas per run: requests, input and output tokens, concurrency and wall time. Breaching one gives status `limit_exceeded`.
- **TR-GW-8** Mode G: keep a history-consistency hash log, counting rewrites without rejecting them.
- **TR-GW-9** Claude Code in Mode G: `ANTHROPIC_BASE_URL` = gateway, `skipWebFetchPreflight`, fast mode off, auto-update and telemetry off. WebFetch stays on.

### 4.9 `hermetic-extract`
- **TR-EXT-1** Never mount the agent's disk on the host.
- **TR-EXT-2** ExtractorVM boots a clean read-only image with the base read-only and a CoW copy of the agent overlay, so the journal can replay. Mount overlayfs read-only with `nodev,nosuid,noexec,redirect_dir=nofollow,metacopy=off,index=off`. Time-limit everything.
- **TR-EXT-3** Compare with the extractor's own static binary. Never run `git`, and ignore the agent's `.git`.
- **TR-EXT-4** Extract by task class:
  - patch: changes inside the repo directory only;
  - artifact: the declared paths;
  - state: nothing.
- **TR-EXT-5** Stream length-prefixed records (type, path, mode, size, hash, bytes).
- **TR-EXT-6** The host validator (Rust):
  - accepts regular files, directories and deletions only;
  - rejects absolute paths and `..`;
  - enforces per-file, total-byte and file-count quotas;
  - keeps only the executable bit;
  - restores test infrastructure (test files, `conftest.py`, `pytest.ini`, `tox.ini`, `sitecustomize.py`, `usercustomize.py`, `*.pth`, in-tree `*.egg-info` and `*.dist-info`, test-runner sections and `pytest11` entry points);
  - flags new top-level modules that shadow the stdlib or an installed package.

### 4.10 `hermetic-grader` and `hermetic_mutants`
- **TR-GR-1** GraderVM: a clean image with tests and runner baked in. No network, no vsock, nothing downloaded. Results go on an output disk as a fixed-schema, size-capped record.
- **TR-GR-2** The supervisor is PID 1, never imports the repo, and reads per-test start and finish records over a pipe. A missing finish record counts as a fail. Ignore printed summaries and exit codes.
- **TR-GR-3** Tests run:
  - in their own PID and mount namespaces with no-new-privileges;
  - with Docker's default capability set minus `CAP_MKNOD` and the administrative capabilities;
  - with only the usual character devices in `/dev`;
  - under a cgroup v2 program that denies every block device.

  Write the result disk only after the whole process tree has ended.
- **TR-GR-4** Runner settings: Python `-s`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` with the required `-p` plugins (from E4), and the clock at `T_clock`. Record pytest versions older than 3.8.
- **TR-GR-5** Exclude flaky tests: E4 runs three times on base and gold, and tests with unstable results are dropped from every comparison.
- **TR-GR-6** Differential runs, each in a fresh GraderVM on the same work. R0 normal, R1 mutant and R2 equivalence run in parallel. R3 fix removal is advisory.
- **TR-GR-7** R1 and R2 must be indistinguishable:
  - both draw the same rewritten test set;
  - R1 mutates only base-failing assertions in hidden lines, to a third value that fails on both trees;
  - the kernel command line, environment, host name, disk layout and file sizes are identical or padded.
- **TR-GR-8** Variant pool: about 8 per task, generated by syntax-tree rewriting on staging. Each equivalent must match its original on base and gold, and each mutant must fail on both. Record R1 coverage.
- **TR-GR-9** Find base-failing assertions with all assertions recorded on the base tree. An unreached assertion is eligible only if its checked value depends, by data flow, on the statement that raised.
- **TR-GR-10** No grader output reaches an agent.

### 4.11 `hermetic_classifier`
- **TR-CLS-1** Label each success derived or retrieved, using host-side logs and the final work only. SWE-bench exact-match is the baseline.
- **TR-CLS-2** A "retrieved" label in a sealed world, or a disagreement between the gate and the classifier, gives status `review`.

### 4.12 `hermetic-attest`
- **TR-ATT-1** `hermetic-run/v1` holds only deterministic or digest values, with the fields listed in §12.1.
- **TR-ATT-2** `hermetic-transcript-audit/v1` names the run digest and holds the label, confidence and evidence spans. It is kept separate so that `hermetic verify` stays deterministic.
- **TR-ATT-3** Produce the score card with the version tuple (`spec_version`, `world_version`, `sealcheck_version`, grader image digest).

### 4.13 `hermetic_harbor`
- **TR-HB-1** A Harbor environment backend. The separate-verifier copy maps to ExtractorVM, and the verifier session maps to GraderVM. Whether it can be registered cleanly hasn't been prototyped yet.

## 5. Data formats

| Format | Owner | Notes |
|---|---|---|
| World manifest | common | Identity, cutoffs, content digests, substrate list, DNS table, CA digest, trust-store paths, run spec, evidence. `world_root` = Merkle root. (§13.1) |
| execd frames | common / execd | Length-prefixed; exec, upload, download, status |
| NetVM → WorldServer frames | common | Fixed binary: authority, path+query, method; size-capped |
| Extractor stream | extract | Length-prefixed records: type, path, mode, size, hash, bytes |
| Grader result | grader | Fixed schema, size-capped, strict parser |
| Hash-chained log | common | BLAKE3, append-only |
| sealcheck report | sealcheck | JSON + SARIF |
| Run and audit records | attest | in-toto DSSE |

## 6. Security requirements (cross-cutting)

- **TR-SEC-1** The host never listens for a connection that AgentVM starts.
- **TR-SEC-2** The run host holds no gold patches, hidden tests, fingerprints, grader images or API keys. In `single_host`, enforce this with Unix users, network namespaces and jailer chroots.
- **TR-SEC-3** Every parser of guest-originated data (frames, the extract stream, the grader record, gateway requests) must be size-capped and strict. It fails closed with status `tampered` where the spec says so.
- **TR-SEC-4** Every date shown to a guest is derived from `T_clock`.
- **TR-SEC-5** The real-date sentinel (D12) scans everything that leaves the VM and everything sent to the model, looking for the real date in common formats, host names and host paths.
- **TR-SEC-6** The escape probe runs before each batch and covers:
  - DNS lookups and delegation;
  - raw IP, ICMP, IPv6 and QUIC;
  - vsock to host ports;
  - the kvmclock MSRs and the clock-pairing hypercall from a guest kernel module;
  - gateway abuse;
  - a real model call scanned for the date;
  - positive checks: a pip, git and curl install, and a `getrandom()` that doesn't block.

## 7. Performance requirements

| Metric | Target | Source |
|---|---|---|
| sealcheck task query (cached layers) | < 5 s | E6, §5.4 |
| Layer index | Minutes per multi-GB layer, once per digest | §5.4 |
| End-to-end run overhead | < 1.5× Docker | E6 |
| Also measured | Boot time, NetVM round trip, extraction time, R0–R2 grading time, storage | E6 |

## 8. Verification

| Experiment | Verifies |
|---|---|
| E1 | P1: every closable channel, against a scripted root probe and against frontier agents |
| E3 | sealcheck precision ≥ 95% and recall ≥ 90% |
| E4 | Oracle fidelity ≥ 99%; variant validation; flaky tests; pytest plugin list |
| E5 | P2 at each clock level |
| E6 | Performance targets |
| E7 | Reproducible `world_root` |
| E8 | P3 against the forger suite; < 1% false alarms |
| E9 | Docker vs microVM compatibility |
| E10 | Gateway conformance: < 1% wrongly blocked; 0 real dates |

## 9. Supporting files (Appendix A)

| File | State |
|---|---|
| `vmm/firecracker-enforce-pv-cpuid.patch` | Written, not compiled |
| `vmm/hide-kvmclock.cpu-template.json` | Written |
| `tests/clock-leak-probe.md` | Needs an eighth check: the clock-pairing hypercall from a guest kernel module |

None of these files are in this directory yet.

## 10. Open technical risks

1. Clock hiding is unproven: the patch hasn't been compiled, TSC stability without kvmclock is untested, and no hypercall block has been tried (Phase 3b).
2. R1 coverage may be low, and honest fixes may trip R2 on tests that depend on source text.
3. `strict` rebuilds of old environments may fail, in which case the task falls back to `repo_only`, labelled.
4. MicroVM fidelity relative to Docker is unknown (E9).
5. Harbor backend registration hasn't been prototyped.
6. The tier-1 and tier-2 thresholds need calibrating (E3).
7. Storage for the per-month baseline is unmeasured.
8. Clients that ignore the system trust store and the environment variables will fail.
9. Only the Anthropic API adapter has been researched.
10. It's unknown whether PyPI publishes yank dates.
