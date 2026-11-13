# Hermetic World — Architecture

Hermetic World is a time-sealed evaluation environment for AI agents. Each task runs in a world frozen at the moment the task was created, so an agent can only solve it by working it out, not by looking the answer up. Its first component, **sealcheck**, verifies that nothing from after that moment is reachable.

- **Status:** design specification. Nothing has been built or run yet.
- **Platform:** Linux x86_64 with KVM and Firecracker microVMs. The core is in Rust; the Harbor bridge, package resolvers, test rewriting and classifier are in Python. aarch64 comes later.
- **Terms:** see the glossary in Appendix C.

---

# Part I — Foundations

## 1. Problem and goals

### 1.1 Problem

Agent benchmarks are built from past events, but agents run in today's world, so they can look up an answer instead of deriving it. Cursor found that 63% of Opus 4.8 Max's successful SWE-bench Pro fixes were retrieved rather than derived. Sealing git history and the internet dropped its score from 87.1% to 73.0%.

### 1.2 Three properties

Each run records the level it reached on each property.

| Property | Claim | Strength | Checked by |
|---|---|---|---|
| **P1 Answer seal** | No information created after the world cutoff is reachable by the agent: the repo beyond the base commit, later versions of the project, the issue thread, the web, benchmark data, and (in `strict`) third-party library code | Hard guarantee, gated | sealcheck gates, escape probe, E1 |
| **P2 Date seal** | Nothing the agent can read states a date later than the guest clock | Best effort, three levels (§8.1), measured | Clock probe, real-date sentinel, E5 |
| **P3 Score integrity** | The score depends only on the submitted work, graded in an environment the agent never touched; forgery is detected | Full for patch and artifact tasks, reduced for state tasks | Differential grading, E8 |

P1 is the product. It doesn't depend on P2: if nothing newer than the cutoff exists in the world, an agent that learns the real date still has nothing to look up.

### 1.3 Content classes and seal levels

| Class | What it covers | `strict` | `repo_only` |
|---|---|---|---|
| **A. Task-relevant** | Target repo, the target project's own packages, issue thread, web and search, benchmark data | Sealed, gated | Sealed, gated |
| **B. Third-party library code** | Language-ecosystem packages (PyPI, conda, npm, crates and so on), installed or installable | Dated at or before the world cutoff, gated (D5b) | Listed as a warning |
| **C. Substrate** | Base OS userland, language runtime, guest kernel, agent toolchain (Mode G), Hermetic's own guest tools | Taken from a snapshot at the cutoff where one exists; otherwise exempt and listed by digest | Exempt and listed |

Class C can't be gated honestly:

- SWE-bench images are built on Ubuntu 22.04 with a 2023 Miniconda, whatever the task's date. Their Dockerfiles mostly don't pin versions, so packages were resolved at image build time.
- Ubuntu's snapshot service only covers dates after 1 March 2023.
- Firecracker needs a guest kernel of 5.10 or newer.
- In Mode G the agent's own binary is newer than every task.

The substrate can reveal a lower bound on today's date. It can't reveal anything about the task, as long as the fingerprint detectors (D2, D9), which scan all three classes, are clean. Each run records `substrate_at_T` (full, partial or none) and the exemption list.

Use `strict` for published scores. Use `repo_only` for images that don't rebuild at the cutoff, and for quick experiments.

### 1.4 Task classes

| Class | Graded from | Examples | `grader_isolation` |
|---|---|---|---|
| **patch** | A diff against the base commit | SWE-bench family | `clean` |
| **artifact** | Output files the task declares | Harbor tasks with a separate verifier | `clean` |
| **state** | The state of the agent's own environment: services, installed software, files anywhere | Most Terminal-Bench tasks (Harbor's default shared verifier) | `shared` (reduced, §11.4) |

### 1.5 Scope and non-goals

- **Undetectability.** An agent with root can always find signs of a sandbox.
- **Knowledge in the model's weights** (training contamination). Reported, not solved.
- **Timing side channels.** Measured, not closed.
- **Hiding the cutoff itself.** The newest item in the world shows where the cutoff is, and so does the clock. Only information from after the cutoff is hidden.
- **Hiding the physical CPU's generation.** A guest can probe for instructions and time the caches, whatever CPUID says. Hardware virtualization can't prevent that. Like the rest of the substrate, it gives only a lower bound on the date.
- **Not supported in the first release:** multi-container (compose) tasks, nested Docker, GPU tasks, and tasks that need the live internet by design. E9 measures how many tasks this excludes.

### 1.6 Contribution

Earlier work showed the problem and sealed single channels (git history, the live network). This project adds four things:

1. An open verifier that produces leak reports across benchmarks.
2. Seal levels stated as signed claims that someone else can check.
3. An adversary with root, which makes the VM clock and the model API channels to close.
4. Grading integrity recorded in the same signed record as the seal.

## 2. Threat model

**Adversary.** The agent has root inside AgentVM and can run its own kernel code from the start. No boundary may depend on anything inside AgentVM. NetVM is also assumed compromisable, because it parses hostile traffic. The gateway is the only component with both hostile input and internet egress, so it is treated as a ring of its own (§9.2).

**Assets.** Information created after the world cutoff (the fix, the tests, later code and pages), the real date, and the integrity of the score.

| # | Channel | Example | Closed by |
|---|---|---|---|
| 1 | Repo history beyond the base commit (refs, tags, reflog, packed or dangling objects, submodules, LFS) | `git log --all` on pytest-6202; MiMo parsing pack files itself | Repo sealer + D1 (§6.1) |
| 2 | Leftover files (configs, caches, archives, `.pyc`) | Cybench answer in a task config | D2, D3 |
| 3 | Compiled or derived artifacts built from post-fix source | A `.so` or bundle containing the fix in binary form | Rebuild from the base tree + D3b |
| 4 | The target project at a post-fix version | o3 installing the latest library; `pip download astropy==4.3` | Frozen mirror + D5a |
| 5 | Third-party packages newer than the cutoff | Sibling packages' changelogs and compatibility shims | `strict`: rebuilt at the cutoff + D5b gate. `repo_only`: listed. |
| 6 | Live web and upstream lookup | 57% of Opus 4.8 Max trajectories found the merged PR online | No route anywhere; NetVM serves only the world |
| 7 | The target issue's own thread | SWE-bench `hints_text` holds comments made before the first fix commit | Thread scrub, independent of date (§4) |
| 8 | Mutable content edited after the cutoff | An issue body or forum post edited later to add the fix | Revision-at-cutoff rule (§4) |
| 9 | The benchmark itself in an archive or cache | BrowseComp in OpenAI's offline cache | D9 |
| 10 | Wrong date metadata, or a retriever trained on the future | Brave date filters leaking (FutureSim) | Date by capture time; month-floor index; BM25 or pre-cutoff embeddings |
| 11 | Network tunnels (DNS, ICMP, IPv6, QUIC, DoH) | OpenAI's September 20 DNS-delegation escape | NetVM: drop by default, static DNS, no upstream |
| 12 | Live forwarding services as attack surface | Zero-day in a package-registry cache proxy (July 2026) | Nothing forwards; the world is built ahead of time |
| 13 | VM or container escape | SandboxEscapeBench | Firecracker + jailer; no internet route; answers aren't on the run host (§3.2) |
| 14 | Wall clock (kvmclock MSRs, the clock-pairing hypercall, RTC) | Real date read by a rooted guest | §8 (`clock: hidden`) |
| 15 | Filesystem timestamps | `statx` birth time, superblock times | mke2fs with `SOURCE_DATE_EPOCH` + D4; `/dev` re-stamp |
| 16 | Model API responses (Mode G) | `Date` header; rate-limit reset timestamps; `created` fields | Gateway response sanitising (§9.2) |
| 17 | Context injected by the harness | Today's date in a system prompt; uploads with host timestamps | Real-date sentinel (§8.4); execd re-stamps uploads |
| 18 | Hardware and OS tells; the substrate | A CPU model released after the cutoff; instruction probing; the kernel's build date; the agent's own version string | CPU template; pinned kernel build date; exemption list (best effort) |
| 19 | Cross-run state | Shared stores; the provider's prompt cache; stored conversations | Fresh copy-on-write world per run; cache nonce; server-side state rejected |
| 20 | The model API as a side door | Provider-hosted tools; URL image and document sources | Default-deny gateway in both modes (§9.2) |
| 21 | Grader tampering | `conftest.py` hook forcing every test to pass; a planted module that shadows one of the test runner's imports; trojaned `uv` at verify time | ExtractorVM, clean GraderVM, differential grading (§10, §11) |
| 22 | Hidden tests or gold patches reachable after an escape | Answers stored on the same host as the agent | Role separation (§3.2) |
| 23 | Grader feedback across attempts | A retry loop that learns from test output | One-shot rule (§11.1) |
| 24 | Forged or flooded evidence | Rooted guest faking its own logs; compromised NetVM flooding the log | Only host-side logs count; WorldServer limits and dedupe (§7.3) |
| 25 | Timing side channels | Deterland | Measured, not closed |
| 26 | Knowledge in weights | SWE-Bench Illusion | Out of scope; reported |

---

# Part II — System

## 3. System overview

### 3.1 Components

| Component | Ring | Role |
|---|---|---|
| **sealcheck** | Staging | Proves before a run that nothing post-cutoff is reachable (§5) |
| **Sealer** | Staging | Builds the sealed repo, root filesystem, package world and manifest (§6) |
| **AgentVM** | 1 | Firecracker VM where the agent works. Assumed fully compromised. |
| **NetVM** | 2 | Firecracker VM that answers all of AgentVM's network traffic from the world (§7.1) |
| **WorldServer** | 3 | Locked-down host process that serves the frozen world to NetVM (§7.3) |
| **Gateway** | Own ring | The only path to the model provider (§9.2) |
| **ExtractorVM** | Throwaway | Reads the agent's disk and streams out its work (§10) |
| **GraderVM** | 4 | Clean VM that runs the tests on the extracted work (§11) |
| **execd** | Inside VMs | PID 1 and command server in AgentVM and GraderVM (§8.3, §9.4) |

### 3.2 Deployment roles

| Role | Network | Holds | Never holds |
|---|---|---|---|
| **Staging host** | Online | Raw task images, gold patches, hidden tests, the sealer, sealcheck with its fingerprints | n/a |
| **Run host** | No internet route | World bundles (checked by digest), NetVM image, agent VMs | Gold patches, hidden tests, fingerprints, grader images, API keys |
| **Gateway + harness** | Egress to the model provider only | API key, request logs | World, tests |
| **Grading host** | No network | Grader images with tests baked in, test variants, the classifier with fingerprints | API keys |

On one machine, which is the realistic setup for this project, the roles are separate Unix users and network namespaces. Grader files sit outside every jailer chroot and aren't readable by the user that runs agent-phase Firecracker. The run records `deployment` as `split` or `single_host`.

### 3.3 Diagram

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

### 3.4 Lifecycle of a run

1. **Seal** (staging). `hermetic seal --task <id>` computes the cutoffs (§4), builds the world bundle and its manifest (§13.1), and freezes the world root.
2. **Verify** (staging). sealcheck scans the task image and the bundle. A gate finding at the chosen seal level is repaired or the task is excluded (§5.5).
3. **Oracle check** (E4, once per world version, before any agent). The reference fix must pass in the sealed world, and the test variants must behave as specified (§11.3).
4. **Ship.** The bundle goes to the run host; grader images go to the grading host.
5. **Probe.** A throwaway AgentVM, as root, confirms every way out fails (§9.6).
6. **Boot.** NetVM starts, then AgentVM with a copy-on-write copy of the world. PID 1 runs the boot sequence (§8.3).
7. **Work.** The agent works. Model traffic goes through the gateway in both modes. All other traffic goes AgentVM → NetVM → WorldServer. The host records logs.
8. **Stop.** AgentVM is shut down so its disk is complete and consistent (§9.5). State tasks are paused instead (§11.4).
9. **Extract.** A throwaway ExtractorVM reads the agent's disk and streams out the diff or the declared files. The host validates the stream (§10).
10. **Grade** (grading host). GraderVM runs the normal, mutant and equivalence runs (§11.2). State tasks skip steps 8 and 9 and are graded in their resumed VM (§11.4).
11. **Classify.** The classifier labels the run from host-side logs (§5.6).
12. **Sign.** The host signs `hermetic-run/v1` and `hermetic-transcript-audit/v1` (§12).

## 4. Cutoffs

Every part of the system works from three values.

| Name | Definition | Governs |
|---|---|---|
| **World cutoff** `T_world` | The earliest of: issue created, earliest commit in the fix PR (author or committer date), fix PR opened. Use whichever exist; implausible author dates are discarded (below). | Web, search, packages, the issue thread |
| **Repo boundary** | The base commit, by reachability, not by date | Repo contents |
| **Clock time** `T_clock` | The later of `T_world` and the base commit's time | Guest clock, `SOURCE_DATE_EPOCH`, certificate dates, HTTP `Date`, D4 |

- **Why three values.** The base commit is usually later than the issue, so the repo legitimately holds commits newer than `T_world`. `T_clock` stops those commits appearing to come from the future. A clock later than the world cutoff leaks nothing; it is only a number.
- **Package cutoff.** Packages use `T_world`. If E4 shows the base tree needs a dependency released between `T_world` and the base commit, that task may raise `pkg_cutoff` to at most the base commit's time. The override is recorded.
- **Implausible author dates.** Git author dates are set by the author's machine and nobody checks them. An earlier cutoff hides more, so a wrong early date can't leak anything; it only makes the world older than it should be.
  - Only clear outliers are discarded: an author date before the repository's first commit, or more than 90 days before every other candidate date. Each discard is recorded, and E4 catches the remaining cases as a fidelity failure.
  - Dates are not tied to the PR's merge-base, because rebasing keeps author dates, so a legitimate fix commit can predate the merge-base.
- **Target-thread scrub, independent of dates.** Remove from the world everything after the problem statement in the target issue's discussion, the solution PR and its review comments, and any issue or PR that links to the target. SWE-bench's `hints_text` is defined as comments made before the solution PR's first commit, so such comments can predate the fix and still contain it.
- **Mutable-content rule.** Content that can be edited after it is created (issue and PR bodies, comments, forum posts, wiki pages) is taken at its revision as of `T_world`, not as of scrape time.
  - Sources: a capture dated at or before `T_world`, or an edit history (GitHub's `userContentEdits`, Stack Exchange post history). Content with neither is excluded.
  - Dataset fields such as the problem statement were scraped later than the task's date, so they get the same treatment.
  - **The target issue itself** is taken at its first revision whenever `T_world` is earlier than the issue's creation (a fix commit can predate the issue). Otherwise the problem statement would have no revision at the cutoff.
- **Undated tasks.** `T_world` is the task's authoring date (its first commit in the benchmark's repository). The world holds only the package layers (§6.3) for that month; there is no web layer.

## 5. sealcheck

**Job.** Prove before a run that nothing the agent mustn't see is reachable. It runs on the staging host, on the raw task image (to produce the leak report) and on the world bundle (as the gate). Principle: inspect stored data, not commands.

### 5.1 Modes

- **Dated tasks** (SWE-bench style): inputs are the cutoffs, the base commit, the reference fix, the hidden tests and the problem statement. Every detector runs.
- **Undated tasks** (Terminal-Bench style): the fingerprint detectors (D0, D2, D3b, D9) and metadata (D6) run against `solution/` and `tests/`.

### 5.2 Fingerprints

**What is fingerprinted.** The lines the reference fix adds or changes, the lines the hidden tests add, and up to 20 other passing fixes per task from SWE-bench/experiments, deduplicated.

**Baseline subtraction.** Any fingerprint that already occurs in the tree at the base commit is removed. Without this, a fix that reuses an existing line flags every file containing that line.

1. **Tier 1, weighted lines and windows.** Normalise each line (strip comments, whitespace and diff markers).
   - *Lines.* Drop trivial lines: under 12 characters, bare keywords, brackets. Weight the rest by rarity in the base tree.
   - *Windows.* For every changed position, also hash the two-line and three-line windows of the fixed file that span it. A deletion leaves two lines newly adjacent, and a one-character edit sits between its neighbours, so both get fingerprints even though they add no long line.
   - *Diff shape.* The file path plus the hunk ranges of the reference fix, to catch a leaked `.patch` file, plus a variant without hunk ranges, so a diff made with a different amount of context still matches.
   - *Diff-like text.* In a leaked diff of a deletion-only fix, every line already exists in the base tree, and the deletion's new adjacency never appears. So any text block with lines starting `+` or `-` also gets:
     - windows computed over its after-change view (removed lines skipped), which reproduces the fixed file's new adjacencies;
     - fingerprints of the fix's removed lines with the `-` marker kept. Ordinary source at the base commit has no such lines, so baseline subtraction leaves them in place.
   - *Match rule.* A scanned unit (a file, git object, archive member, WARC record, or text block) matches when it holds fingerprints carrying at least 60% of a hunk's weight. The threshold is calibrated in E3.
2. **Tier 2, IDF-weighted statement symbols (review flag, not gate).** Use tree-sitter to collect all identifiers, attribute chains (`request.user.is_authenticated`) and literals in the modified statements, both removed and added. Weight each by inverse document frequency across the base tree. Flag text where the changed file's name, or the enclosing function's name, co-occurs with symbols whose summed weight exceeds a threshold. This catches prose leaks such as "pass `strict=False` to `parse_cookie`".
3. **Tier 3, winnowing.** Over code tokens with k = 8 and w = 8, so any shared run of 15 or more tokens is guaranteed to be caught. Shorter fixes rely on tiers 1 and 2.
4. **Binary tier (for D3b).** Identifiers and string literals that the reference fix adds, searched in symbol tables and string tables.

**Containers.** Every tier looks inside archives (zip, tar, gz, bz2, xz, zstd), git packs, SQLite text cells and `.pyc` constants, up to four levels deep. Each container has an expansion-ratio limit and a size limit. A decompression bomb ends that container's scan with a finding; it doesn't exhaust the scanner.

### 5.3 Detectors

| ID | Detector | `strict` | `repo_only` | Notes |
|---|---|---|---|---|
| D0 | Problem-statement leak | Gate (T1, T3); review (T2) | same | Issue text, hints, `instruction.md` |
| D1 | Git state beyond the base commit | Gate | Gate | All loose and packed objects, refs (including `refs/pull` and `refs/original`), reflogs, stash, worktrees, notes, commit-graph, `FETCH_HEAD`, `ORIG_HEAD`, alternates, submodule repos, LFS objects. Allowed: objects reachable from the base commit, plus tags that point at one of its ancestors (§6.1). |
| D2 | Files and archives | Gate | Gate | Tiers 1–3 over the whole rootfs, all content classes |
| D3 | Stale bytecode | Gate | Gate | PEP 552 header vs source; `.pyc` without source |
| D3b | Compiled and derived artifacts | Gate | Gate | Binary tier over ELF objects, `.class` and `.jar` files, wasm, minified bundles |
| D4 | Inode and superblock times | Gate | Gate | Every time at or before `T_clock`. Also verifies the sealer's output. |
| D5a | Target project at a post-fix version | Gate | Gate | Installed or vendored copies newer than the base commit |
| D5b | Third-party packages newer than the cutoff | **Gate** | Warning | Class B only: PEP 700 upload time, conda `timestamp`, npm `time`, crates `pubtime` |
| D6 | OCI and VM metadata | Gate | Gate | Config, history, labels, environment |
| D7 | Rebuild and diff | Audit only (`--deep-audit`) | same | Slow, and affected by build nondeterminism |
| D8 | Coherence tells | Info | Info | Kernel build string, os-release, tzdata, CA bundle, CPU template, dated logs |
| D9 | Benchmark presence | Gate | Gate | Canaries, datasets, benchmark hosts, in the rootfs and the WARCs, all content classes |
| D10 | Dated archive records | Gate | Gate | Capture times at or before the cutoff; fingerprints over payloads; thread scrub and revision rule verified |
| D11 | Test-infrastructure changes in the agent's work (post-run) | Advisory | Advisory | `conftest.py`, pytest, tox or setup config, `sitecustomize`, `.pth`, monkey-patching. It can be obfuscated. |
| D12 | Real-date sentinel (post-run and in the probe) | Advisory for P1; counts against P2 | same | §8.4 |

### 5.4 Output and performance

- **Output.** Each finding has a channel, an evidence path, visibility (agent-visible or image-only), severity and confidence. Formats are JSON and SARIF. Any agent-visible gate finding stops the task with exit code 2.
- **Performance.** Fingerprints and cutoffs differ per task, so caching a task's verdict per layer never hits. The scan is split in two.
  - *Layer index, once per unique layer digest.* Unpack the layer and record its facts: inode times, package manifests with release dates, and a compact index of line hashes, window hashes and winnowing fingerprints. This takes minutes for a multi-GB layer.
  - *Task query, per task.* Look the task's fingerprints and cutoffs up in the indexes of its layers. This should take under 5 s even the first time a task is checked, because benchmark images share most of their layers.

### 5.5 Tasks that fail the gate

A task is never dropped silently, because that changes the denominator of the score.

| Disposition | When | Recorded as |
|---|---|---|
| `repaired` | The sealer can remove the leak without changing the task, and a re-scan is clean. For a D0 leak, the leaking span is redacted from the problem statement. | New world version; `problem_statement_redacted` where it applies |
| `excluded` | The leak is the task (for example, the issue text is the fix) | Listed in the score card with the detector that fired (§12.4) |

The per-run report also lists passing tasks as `clean`; this is not a manifest disposition
and does not change the world root. Manifest dispositions describe the current status.
If a repaired task is later excluded, its former repair entries are retained as
`repair_history` in the exclusion entry's JSON `detail`, separate from the current status
and still bound to the world root. The repair sidecar must match that evidence on rerun.

D0 repair excludes a task if it removes more than 50% of the original UTF-8 bytes or
leaves fewer than 20 original Unicode scalar values outside Unicode White_Space
(U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A,
U+2028–U+2029, U+202F, U+205F, U+3000). Count only unredacted original text:
inserted `[REDACTED]` markers contribute nothing; literal markers in the original count
normally. U+001C–U+001F are not whitespace under this rule. All supplied spans must be
nonempty and every original endpoint must be a UTF-8 boundary before merging.

### 5.6 Retrieval classifier

After a run, the classifier (on the grading host) labels each success as derived or retrieved, using host-side logs and the final work only.

- In a sealed world retrieval should be impossible, so any "retrieved" label is a seal failure to investigate.
- In the unsealed arms of E2 it measures the retrieval rate.
- SWE-bench's own exact-match check (6.7% average on Verified submissions) is the baseline.
- If the gate and the classifier disagree, the run goes to `review`.

## 6. World construction

### 6.1 Repository sealer

- Copy only the objects reachable from the base commit into a fresh repo.
- **Tags.** Keep a tag, lightweight or annotated, only if it points at an ancestor of the base commit. An annotated tag must also be dated at or before `T_clock`, and its message must pass the fingerprint tiers. Version tools such as setuptools_scm read tags with `git describe --tags`, so deleting them would change the package's version and break the oracle.
- Delete remotes, the reflog, the stash, `FETCH_HEAD`, `ORIG_HEAD`, `refs/pull`, `refs/original`, alternates, hooks, and credentials in the config.
- Delete the target repo's `__pycache__` directories. Python rebuilds them from the sealed source.
- Seal each submodule the same way, at the commit the base tree records. Keep only the LFS objects the base tree references.
- Delete native build outputs and rebuild them from the base tree where the build is reproducible. Otherwise D3b must pass.
- Rebuild the commit-graph and repack. Pre-base history is kept, so `git log`, `blame` and `bisect` still work. Verify with D1.

### 6.2 Root filesystem and substrate

- Extract the layers. In `strict` mode, rebuild the class B environment with the cutoff resolver (§6.3).
- **Substrate.** Where a distro snapshot at `T_world` exists, `strict` may rebuild the OS layer from it (`substrate_at_T: full`). Ubuntu snapshots start on 1 March 2023; Debian's archive reaches back further. Otherwise the benchmark's own base image is kept and listed (§1.3).
- **Clean-up.** Delete dated logs, caches and histories that add nothing to the task: `/var/log`, `/var/cache`, apt lists, pip and conda caches, shell history. D8 reports what remains.
- **Build.** `SOURCE_DATE_EPOCH=T_clock mke2fs -t ext4 -d <rootdir or tar> -U <fixed uuid> -E hash_seed=<fixed>`, using **e2fsprogs ≥ 1.47.1** (pinned; Debian bookworm ships 1.47.0).
  - In e2fsprogs (`misc/create_inode.c`, `lib/ext2fs/initialize.c`), `SOURCE_DATE_EPOCH` enables `EXT2_FLAG2_USE_FAKE_TIME`, and `set_inode_extra()` clamps atime, ctime and mtime with `clamped_time()`. New inodes get `i_crtime` from the faked "now".
- **Guard.** Run D4 on the finished image anyway, and fail the build on any time later than `T_clock`.
- Clamping timestamps doesn't make a newer file's contents older. That is what D5b and the exemption list are for.

### 6.3 Package world

Two frozen layers, plus apt.

1. **Layer 1, task closure.** Recorded by doing the install. On the staging host, run the task's setup and the oracle build with `uv --exclude-newer` (or pip 26 `--uploaded-prior-to`) at the package cutoff, through a recording index that saves every file fetched.
   - uv passes `exclude_newer` to the resolver for build environments (`crates/uv-dispatch`), and pip passes `--uploaded-prior-to` to the subprocess that installs build dependencies (`build_env/installer.py`). Source builds therefore can't pull a newer setuptools.
   - **Yanked releases.** A release that existed at the cutoff but was yanked later is marked yanked on today's index, and resolvers skip yanked files. The recording index serves such files as not yanked. Where the yank date can't be established, the file is served as not yanked and listed.
   - **conda.** SWE-bench environments are conda plus pip. Conda packages are cut with the `timestamp` in repodata (pixi's `exclude-newer` covers conda and PyPI). A package with no timestamp is treated as unknown: `strict` lists it and fails D5b unless it is exempted by hand.
2. **Layer 2, ecosystem baseline at the cutoff month.** A task-independent mirror of common developer and test tools (pytest and plugins, hypothesis, mypy, tox, coverage, Cython, setuptools, wheel, ipdb and so on), plus the transitive closure of the top N packages per ecosystem. It is shared by every task with the same cutoff month, and covers installs the agent starts itself.
3. **apt** from a snapshot at the cutoff, where one exists.
4. **Freeze.** The world root is fixed before evaluation. Misses logged during agent runs may go into the next world version, with its oracle re-run. They never change the world mid-benchmark.

### 6.4 Ecosystem coverage

| Ecosystem | Date source | Cutoff mechanism | Phase | Known gap |
|---|---|---|---|---|
| PyPI | Upload time per file (PEP 700) | uv `--exclude-newer`; pip `--uploaded-prior-to` | 2 | Files deleted upstream since the cutoff |
| conda | `timestamp` in repodata | pixi / rattler `exclude-newer` | 2 | Old packages without a timestamp |
| Debian, Ubuntu | Snapshot services | Snapshot ID | 2 | Ubuntu only after 1 March 2023 |
| git dependencies | Reachability at the cutoff | Static mirrors (§7.1) | 2 | No shallow clone |
| npm | `time` map in package metadata | npm `--before`; filter in WorldServer | 4 | Unpublished packages |
| crates.io | `pubtime` in the index (added January 2026) | Filter the sparse index in WorldServer | 4 | Coverage of older versions unchecked |
| Go modules | `Time` in the proxy's `.info` file | Filter the version list in WorldServer | 4 | none known |
| Maven and others | Not yet researched | n/a | 4 | n/a |

Python comes first because SWE-bench is Python. The others matter for SWE-bench Pro and Multi-SWE-bench.

### 6.5 Search and web archive (Phase 4)

- **Search.** One tantivy BM25 index per cutoff month, holding only documents captured before the first day of that month. Up to a month of content is lost; in return no document or ranking statistic can postdate the cutoff.
- **Page replay.** Captures dated at or before `T_world`, exactly, served by index lookup inside WorldServer (no pywb on the trusted side).
- **Sources.** Common Crawl, Wayback, Software Heritage, and Stack Exchange data dumps rebuilt to their state at `T_world` from post history (the mutable-content rule, §4).
- **Synthetic GitHub REST API.** Deferred: GH Archive records events, not full API state.
- **Redistribution.** Whether a world bundle containing archived pages may be redistributed is unresolved. Until it is, publish the manifest and the build recipe, not the pages.

## 7. Network

### 7.1 NetVM (Ring 2)

- **Image.** A Firecracker VM booted from a read-only `dm-verity` image. It runs one static Rust binary as PID 1, with no shell and no writable filesystem. It holds the world CA key and nothing else.
- **No disguise.** Undetectability features (cloned real CA names, synthetic CT stamps, realistic public IPs) are deliberately left out.

| Traffic | Handling |
|---|---|
| DNS | Names in the manifest are answered from a fixed table; everything else gets NXDOMAIN; no upstream |
| TCP 80 and 443 with a known host name | Intercepted with TPROXY; TLS terminated with a leaf from the world CA; GET and HEAD forwarded to WorldServer as fixed frames over its own vsock port |
| Unknown or missing SNI or Host, encrypted client hello, non-TLS on 443 | Connection reset, logged |
| Other HTTP methods | 405 |
| git over HTTPS | Static mirrors served with git's "dumb" HTTP protocol, which needs only GET. Shallow clones aren't available over it. If agents need them, the smart protocol (a POST to `git-upload-pack`) is terminated inside NetVM in Phase 4, so WorldServer never has to parse it. |
| QUIC, DoH, DoT, NTP, ICMP, IPv6, `git://`, SSH, everything else | Dropped |
| The model host name (Mode G only) | The adapter's POST endpoints only, forwarded over a second vsock port to the gateway; nothing else uses that path |

### 7.2 TLS and trust stores

Intercepting HTTPS only works if every client trusts the intercepting CA.

- **One CA per world version,** created at seal time.
  - The private key is in no image. NetVM receives it over vsock at boot and mints leaf certificates on demand.
  - Every validity date is computed from `T_clock`, never from the host clock: the CA from `T_clock` minus 10 years to `T_clock` plus 10 years; leaves from `T_clock` minus 7 days to `T_clock` plus 365 days.
  - One CA per world keeps the rootfs digest stable and needs no work at boot.
  - It is safe because only sealed AgentVMs of this world trust the CA. An agent that steals the key can only fool itself.
- **The sealer installs the CA certificate** into every trust store in the rootfs and records the paths in the manifest:
  - the system bundle;
  - every `certifi/cacert.pem` and conda `ssl/cacert.pem`;
  - Java keystores.
- **The run spec sets defaults** for clients that take a path from the environment: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`.
- **Known gap.** A package the agent installs later may bring its own bundle and ignore both. Such a client fails with a TLS error; it never reaches anything unsealed.
- **Test.** E4 includes one install each through pip, conda, git and curl from the sealed world.

### 7.3 WorldServer (Ring 3)

- **Host process, locked down.** One process per run over a shared read-only store. It opens the store and the month index read-only, then applies Landlock (read those directories, write only the log) and seccomp (no internet sockets, no `exec`, `ptrace` or `mount`).
- **Input.** It accepts only fixed-format binary frames from NetVM, size-capped.
- **What it serves.** Package indexes, apt snapshot indexes, static git mirrors, search, and archived pages.
  - It answers byte-range requests and serves the package index's metadata sidecar files, so resolvers don't download whole wheels to read their metadata.
  - It strips `Memento-*`, `X-Archive-*` and `Server: pywb` headers, and sets `Date` to `T_clock` plus elapsed time.
  - Misses get the kind of 404 the real site would send.
- **Limits.** They protect against a compromised NetVM without punishing honest installs.
  - *Rate:* a token bucket that delays requests above the rate. It never ends the run; uv alone opens 50 downloads at once by default.
  - *Total volume:* a per-run cap on requests and bytes, set from the oracle's own usage with a wide margin. Exceeding it ends the run with status `limit_exceeded`.
  - *Malformed frames:* a frame that breaks the format ends the run with status `tampered`, because only a compromised NetVM sends one.
- **Logs.**
  - A BLAKE3 hash-chained append-only log.
  - A deduplicated index of `(authority, path_and_query, status) → count, first_seen, last_seen`. The classifier reads the index, so flooding can't bury a real request.
- **What the log means.** It records content that left WorldServer. A compromised NetVM can serve a cached copy again without logging it, but everything WorldServer can serve predates the cutoff anyway.

## 8. Time

**Goal.** Nothing the agent can read states a date later than `T_clock` (P2). This layer is optional for P1 (§1.2).

### 8.1 Clock levels

| `clock` | Mechanism | Can a rooted agent read the real date? | Needs |
|---|---|---|---|
| `hidden` | Guest clock set to `T_clock`; all three host clock paths closed (§8.2) | No known path | Patched Firecracker, plus a host-side block on the clock-pairing hypercall. Unproven until the probe passes. |
| `faked` | Guest clock set to `T_clock` only | Yes, through the kvmclock MSRs or the clock-pairing hypercall | Stock Firecracker |
| `real` | Nothing | Yes | Container mode (Phases 0–2) |

`hidden` matters for date-sensitive benchmarks such as forecasting, and for E5. The project ships with `faked` if either the patch or the hypercall block doesn't work out.

### 8.2 Hiding the host clock

The host's real time can reach a guest by three paths: the kvmclock wall-clock MSRs, the clock-pairing hypercall, and an emulated RTC.

- **kvmclock.**
  - *Shifting it doesn't help.* KVM gives the guest a wall-clock epoch equal to host real time minus kvmclock, so `KVM_SET_CLOCK` doesn't change the date.
  - *Mask.* A Firecracker custom CPU template clears bits 0 and 3 (`KVM_FEATURE_CLOCKSOURCE`, `KVM_FEATURE_CLOCKSOURCE2`) of CPUID leaf `0x40000001` eax (`hide-kvmclock.cpu-template.json`). These are the only bits of that leaf that expose a date.
  - *Enforce.* Without `KVM_CAP_ENFORCE_PV_FEATURE_CPUID`, KVM still serves the wall-clock MSRs to a guest that writes them anyway. Firecracker never enables this capability, so it needs a patch of about 20 lines (`firecracker-enforce-pv-cpuid.patch`). It enables the capability after every `set_cpuid2`, including on snapshot restore. KVM's selftest expects #GP on the masked MSRs. The patch hasn't been compiled yet.
- **The clock-pairing hypercall.** In `arch/x86/kvm/x86.c`, `KVM_HC_CLOCK_PAIRING` copies the host's `CLOCK_REALTIME` into guest memory for any caller in guest ring 0. No CPUID bit gates it, so the mask and enforcement above don't touch it. Leaving the `ptp_kvm` driver out of the guest kernel isn't a boundary either, because a rooted agent can load its own module and make the call. It has to be blocked on the host. Candidates, in order of preference:
  1. **A host clocksource that isn't based on the TSC** (`hpet` or `acpi_pm`). KVM then answers "not supported". It needs no code, but host timekeeping gets slower, and a cloud instance may not offer a clocksource that works.
  2. **Xen hypercall interception.** With it enabled, KVM sends every guest hypercall down its Xen path, which hands unhandled calls to the VMM and never reaches the KVM handlers. This needs a second Firecracker patch and a host kernel built with `CONFIG_KVM_XEN`, and the other paravirtual features that use hypercalls must be masked. Untested.
  3. **A host kernel patch** of a few lines. Only possible on hardware you control.

  The probe must show the call failing from a kernel module inside the guest. Until it does, the level is `faked`.
- **RTC.** On x86, Firecracker emulates no CMOS RTC, and port reads it doesn't handle return 0, so the kernel's CMOS fallback reads a fixed, meaningless date. On aarch64, the pl031 reads host time and needs an offset patch.
- **Other settings.**
  - *Guest kernel config.* Built without `CONFIG_PTP_1588_CLOCK_KVM`, so an unmodified guest doesn't use the clock-pairing call by accident.
  - *TSC.* KVM starts each vCPU's TSC at zero, so it shows the VM's uptime and nothing about the host. Firecracker writes the TSC only when it restores a snapshot.
  - *Clock source.* Boot args `clocksource=tsc tsc=reliable` stop the watchdog from demoting an invariant TSC.
  - *Kernel build date.* `uname -v` prints when the kernel was built. Build the guest kernel with `KBUILD_BUILD_TIMESTAMP` set to that kernel version's release date, and with fixed `KBUILD_BUILD_USER` and `KBUILD_BUILD_HOST`. The version number itself stays a substrate tell.
  - *Entropy.* Attach Firecracker's virtio-rng device. Without kvmclock the guest still has the TSC and the CPU's own random-number instruction, so the kernel's generator should be ready at boot. The probe checks that `getrandom()` doesn't block.
  - *VMClock* (attached on every x86 VM) writes only a disruption counter and a generation counter, so it carries no date. Re-check on Firecracker upgrades.
  - *MMDS* (Firecracker's metadata service) is not configured.

### 8.3 Boot sequence (`hermetic-execd` as PID 1)

Before PID 1 runs, the kernel's clock holds the fixed CMOS-fallback date. Anything written before the clock is set carries that date, and ZIP-based tooling rejects timestamps before 1980. So nothing writable may be mounted until the clock is right. PID 1 reads `T_clock` from the kernel command line (`hermetic.t=`; it isn't secret).

1. The kernel mounts the base rootfs **read-only**, so it writes nothing to that superblock.
2. PID 1 calls `clock_settime(CLOCK_REALTIME, T_clock)` as its very first action.
3. Only then does it mount the per-run overlay disk read-write and assemble overlayfs over the read-only base. It moves the kernel's `/dev` (devtmpfs) into the new root, then switches root into it. The overlay disk was itself built with `SOURCE_DATE_EPOCH=T_clock`.
4. Mount `/proc`, `/sys`, `/dev/pts` and `/dev/shm`, as Docker does. `/tmp` and `/run` stay ordinary directories on the overlay, already stamped at `T_clock`. A memory-backed `/tmp` would vanish with the VM, taking any artifacts written there, and would hold large unpacked builds in VM memory.
5. Walk `/dev` without crossing mount points and re-stamp every node the kernel created before step 2. Because `/dev` is devtmpfs, this touches memory only and nothing is copied into the overlay.
6. Apply the run spec (§9.4): environment, working directory, user, the image's entry point if the task needs it.
7. Start the vsock command server.

Whenever a disk the agent has touched is booted again (the fallback for state tasks, §11.4), PID 1 comes from a trusted initramfs, not from that disk.

### 8.4 Other date carriers and the real-date sentinel

| Carrier | Fix |
|---|---|
| Rootfs timestamps | mke2fs with `SOURCE_DATE_EPOCH` + D4 (§6.2) |
| Dated logs and caches in the image | Deleted by the sealer (§6.2) |
| Files the harness uploads | execd re-stamps them to the guest's current time |
| Model API responses | Gateway response sanitising (§9.2) |
| HTTP `Date`, certificates | WorldServer `Date` = `T_clock` plus elapsed; world CA valid at `T_clock` (§7.2) |
| CPU model and features | CPU template matching a CPU sold before the cutoff (best effort). Instruction probing and cache timing still show the real generation (§1.5). |
| Kernel build date in `uname -v` | Pinned at build time (§8.2) |
| os-release, tzdata, kernel version, agent version | Substrate: listed, not hidden (§1.3) |

**Real-date sentinel (D12).** The host scans everything that leaves the VM (command output in Mode H, model requests in Mode G) and everything sent to the model, for the run day's real date in common formats and for host names and host paths. A hit sets `date_leak_observed` and is reviewed. It is a cheap run-time check of P2, and it also catches a harness that writes today's date into a prompt.

## 9. Agent execution

### 9.1 Agent modes

| Mode | How it works | Evidence of commands | Use for |
|---|---|---|---|
| **H (default)** | The harness runs outside the VMs and sends each command to `hermetic-execd` (vsock 5000). AgentVM never sees the key. | **Host-recorded:** every command the agent issued. Anything that ran later was started by one of them. | Agents built on remote execution (e.g. terminus-2) |
| **G (gateway)** | The agent (Claude Code, Codex) runs inside AgentVM and reaches the model through NetVM and the gateway. | **None trustworthy:** a rooted guest can rewrite the message history it sends, so the gateway log proves only what was sent to the model | Testing agents as shipped |

- In both modes, model traffic goes through `hermetic-gateway`. The harness's only egress is the gateway.
- execd caps output per command and per run. Downloads from the VM pass the same validator as extraction (§10).

### 9.2 Model gateway

**Placement.** The gateway is the one component that takes hostile input and has internet egress. It runs as its own user in its own network namespace, under seccomp and Landlock. Its egress is limited to the provider's host names, with TLS verified and redirects refused. The API key lives only in its memory.

1. **Default deny, one adapter per provider.** An adapter lists the endpoints, fields, headers and beta flags that are allowed. Anything not listed is rejected, so a new API feature fails closed.
   - The gateway parses each request into typed fields and builds the upstream request from those fields. No bytes or headers from the guest are forwarded as they arrived.
   - Adapters are built from the provider's current API reference, and the adapter version goes into the attestation. Phase 2 ships the Anthropic adapter; others follow in Phase 4.
2. **Requests.**
   - *Allowed:* message creation and token counting; a pinned model set (the main model, plus a second model if the agent declares one for internal calls); text; client-side tool calls and results; images and documents sent inline as base64.
   - *Rejected:*
     - provider-hosted tools (search, fetch, code execution, hosted MCP, file search);
     - remote sources (a URL or a file ID, which the provider fetches server-side);
     - server-side state (stored conversations, previous-response IDs, provider memory, containers);
     - background and batch modes;
     - beta flags that aren't listed.
3. **Responses.** Applied to streaming events as well.
   - Only content type, length and encoding headers pass. `retry-after` passes as a number of seconds.
   - `Date` is replaced with guest time.
   - Rate-limit headers, request IDs and CDN headers are dropped (and kept in the host log). The Claude API's rate-limit reset headers are full RFC 3339 timestamps.
   - Timestamp fields in the body (`created`, `created_at` and the like, per adapter) are rewritten to guest time.
   - **Error responses.** Provider and CDN error bodies are free text and may contain timestamps. For any status that isn't success, the body is replaced with a standard error for that status, keeping only the error type the adapter recognises (rate limit, overloaded, invalid request and so on), because agents use it to decide whether to retry. Error events in a stream are treated the same way. The original is kept in the host log.
4. **Cross-run cache isolation.** Put a per-run nonce at the very start of the system prompt, creating a system prompt if the request has none, so no prefix can match another run's cache.
   - The nonce is 128 random bits; a time-based ID such as UUIDv7 would carry today's date.
   - Caching within a run still works.
   - Claude API caches are already isolated per workspace; one workspace per benchmark campaign adds a second layer.
5. **Hard quotas per run.** Requests, input tokens, output tokens, concurrency and wall time. Breaching one ends the run with status `limit_exceeded`.
6. **Logging.** Requests and responses are logged on the host and scanned by the real-date sentinel (§8.4).
7. **History-consistency log (Mode G).** The gateway hashes each conversation as it grows. A request that neither extends a conversation it has seen nor starts a new one is recorded as a history rewrite. Rewrites are counted, not rejected, because agents legitimately compact their context and run sub-agents. A high count is a reason to review the run. It can't reveal commands the agent never showed the model.

**Claude Code in Mode G:** `ANTHROPIC_BASE_URL` = gateway; `skipWebFetchPreflight`; fast mode off; auto-update and telemetry off. WebFetch stays on, because it fetches from inside the VM and so reaches the sealed world. WebSearch is a provider-hosted tool and is rejected.

### 9.3 Agent toolchain volume (Mode G)

The agent itself is newer than every task and can't be installed from the sealed world.

- It is built on the staging host from a pinned release, as a read-only disk mounted at `/opt/agent`.
- **Self-contained.** It brings its own runtime, loader and C library, so it also runs on task images with old system libraries.
- It is class C: listed in the attestation by digest, exempt from the date gates, still scanned by D2 and D9.
- **A rooted agent can read it.** Hiding it in a private mount namespace doesn't work, because root can reach any mount namespace through `/proc`. Its version string therefore reveals a lower bound on the date. The model already knows it exists, so this adds little; E5 measures it.
- **Split mode (Phase 4 option).** Run the shipped agent in a second VM and forward its shell and file operations to execd in AgentVM. AgentVM then holds no agent files, and the host sees every command, as in Mode H. It needs a remote file layer for the agent's file tools, which is why it isn't the default.

### 9.4 From OCI image to microVM

Benchmarks ship Docker images. A VM isn't a container, so the sealer writes a **run spec** into the manifest and execd applies it.

- **Run spec.** Environment variables, working directory, user and group, entry point and command, declared resources (vCPUs, memory, disk), host name, and a `resolv.conf` pointing at NetVM.
- **execd as PID 1.** It reaps zombies, forwards signals, allocates a TTY when asked, applies the run spec to every command, and starts the image's entry point as a child when the task needs a long-running service.
- **Guest kernel.** One kernel for all tasks, with cgroup v2, namespaces, overlayfs and netfilter enabled, so ordinary tooling works. BPF and cgroup BPF are enabled too, because cgroup v2 enforces device rules with a small BPF program (§11.1).
- **Fidelity risk.** A task whose oracle passes in Docker may fail in the VM. E9 measures this, by cause.

### 9.5 Shutdown

For patch and artifact tasks, the agent's disk must be complete and consistent before extraction.

1. execd ends every other process in the VM and waits for them to exit.
2. It flushes pending writes and freezes the upper ext4 filesystem, through a handle it keeps on that filesystem from boot. Freezing writes out all dirty data and empties the journal. A read-only remount isn't used: it fails while any file is open for writing.
3. AgentVM and NetVM are destroyed. The host never mounts AgentVM's disk.

If execd doesn't answer (only an agent that killed it causes this), the VM is stopped anyway and the run is marked `unclean_shutdown`. What gets graded is whatever reached the disk; ExtractorVM's journal replay recovers what it can.

State tasks are paused instead of stopped (§11.4).

### 9.6 Escape probe

Before each batch, from a rooted throwaway AgentVM, try every way out. Every attempt must fail, and the result goes into the attestation.

- DNS lookups of real names, and DNS delegation;
- raw IP connections, ICMP, IPv6 and QUIC;
- vsock connections to host ports;
- the kvmclock MSRs and the clock-pairing hypercall, from a kernel module (expected to fail only at `clock: hidden`);
- gateway abuse: remote sources, provider-hosted tools, other endpoints, other models, unlisted beta flags, and exceeding quotas;
- a real model call, checked for the real date anywhere in what reaches the guest.

The probe also runs two positive checks: an install through pip, git and curl from the sealed world succeeds, and `getrandom()` returns without blocking at boot.

## 10. Extraction

**Rule.** Never mount AgentVM's disk on the host kernel. A rooted guest can craft a malicious ext4 image aimed at the host's filesystem driver.

**ExtractorVM.** A throwaway Firecracker VM boots from a clean read-only image. Its guest kernel parses the untrusted filesystem; if that kernel is compromised, it holds nothing and is destroyed.

- **Disks.** The pristine base image, read-only, and a throwaway copy-on-write copy of the agent's overlay disk. The copy is writable so the kernel can replay the ext4 journal of a disk that wasn't unmounted cleanly; the original is never written.
- **Merged view.** It mounts overlayfs read-only (`nodev,nosuid,noexec`) over the base and the agent's upper layer, so the kernel itself interprets deletions (stored as special device entries) and opaque directories.
  - The agent had root, so it may have written overlay control attributes onto its disk. The mount turns off redirects, metacopy and the index (`redirect_dir=nofollow,metacopy=off,index=off`), so those attributes can't point the view at other files.
  - Everything has a time limit, in case the disk is crafted to loop.
- **Comparison.** The extractor's own static binary compares the merged view with the base. It never runs `git` and ignores the agent's `.git`, whose config, hooks, filters and replace refs could otherwise run code or falsify the comparison. Deletions become deletion records.
- **What is extracted.**
  - *Patch tasks:* changed, added and deleted files **inside the repo directory only**. Everything else on the disk (caches, installed packages, `/tmp`) is ignored, so nothing the agent changed outside the repo reaches the grader.
  - *Artifact tasks:* the paths the task declares.
  - *State tasks:* nothing (§11.4).
- **Stream format.** Length-prefixed records (type, path, mode, size, hash, bytes), not tar. Tar has too many extensions to parse safely.
- **Alternative.** A user-space ext4 reader in a jailed host process would avoid booting a VM. It isn't the default: a rooted agent can turn on filesystem features the reader doesn't support, and the kernel driver inside a throwaway VM handles them all.

**Host-side validation**, in Rust, before anything reaches the grader:

- **Regular files, directories and deletions only.** Symlinks, hardlinks, FIFOs, sockets and device nodes are rejected.
- **No path escapes.** Absolute paths and `..` components are rejected.
- **Quotas.** Per-file and total byte quotas, and a file-count cap.
- **Modes.** Only the executable bit is kept.
- **Test infrastructure is restored to its base version,** and the change is recorded (D11).
  - *Whole files, at any depth in the tree:* the test files the benchmark supplies, `conftest.py`, `pytest.ini`, `tox.ini`, `sitecustomize.py`, `usercustomize.py`, `*.pth`. New files with these names are dropped.
  - *Whole directories:* `*.egg-info` and `*.dist-info` inside the tree. An editable install keeps its metadata, including entry points, in the working tree rather than in `site-packages`.
  - *Sections only:* the test-runner sections of `setup.cfg` and `pyproject.toml`, and any entry-point section that registers a pytest plugin (`pytest11`) in `pyproject.toml`, `setup.cfg` or `setup.py`. The rest of those files keeps the agent's edits, because a real fix may change dependencies or build settings there.
  - The grader doesn't reinstall the target package, so its installed metadata stays as in the clean image. A task that has to reinstall is rebuilt in E4 with the restored sections.
- **Shadowing check.** A new top-level module or package whose name matches a standard-library module, or a package installed in the grader image, is flagged for review. Python would import it in place of the real one.

**Harbor mapping.** Harbor's separate-verifier mode copies only the declared artifacts into a verifier sandbox whose image already contains `/tests`. Our backend implements that copy with ExtractorVM and the verifier session with GraderVM.

## 11. Grading

### 11.1 Grader environment

- **Clean image.** GraderVM boots from its own clean image: the task image plus baked-in tests, the test runner and its dependencies. Nothing is downloaded at grading time.
- **No channels.** It has no network and no vsock. Results go to a small output disk; the host parses a fixed-schema record with a size cap.
- **Supervisor.** Results come from a supervisor, not from the runner's output.
  - A supervisor process that never imports the repo starts the tests in a child, and reads one start record and one finish record per test over a pipe. A test with no finish record has failed.
  - Printed summaries and exit codes are ignored, so fake output followed by an early exit gains nothing.
  - The pipe is reachable from the agent's code, like everything else in the test process. Forged records are the in-process limit below, and R1 is what catches them.
- **Isolation of the test process.** Benchmark images usually run as root, so the supervisor doesn't rely on the image's user.
  - The supervisor is PID 1 of GraderVM and holds the only handle to the result disk.
  - The tests run in their own PID and mount namespaces with no-new-privileges, so the supervisor isn't visible from inside.
  - *Capabilities:* Docker's default set minus `CAP_MKNOD`, so tests behave as they do under Docker (E9). Administrative capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_TIME`, `CAP_NET_ADMIN` and the like) are dropped too.
  - *No device node.* The tests' `/dev` holds only the usual character devices, and without `CAP_MKNOD` a test can't create a device node. The kernel checks that capability only for device nodes, so FIFOs and sockets still work.
  - *Device rule.* A cgroup v2 device program denies every block device, as Docker does for host devices.
  - *Cost:* a test that creates device nodes would pass under Docker and fail here. E9 counts such tests.
  - The result disk is written only after the tests' whole process tree has ended. A run that doesn't end within its time limit is killed, and its unfinished tests count as failed.
- **Fixed runner settings.**
  - Python runs with the user site disabled (`-s`), so `usercustomize` never loads.
  - pytest runs with plugin autoload off (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`), and the plugins the base environment's test command needs are loaded explicitly with `-p`. That list is worked out once in E4 from the clean image.
  - pytest supports that switch from version 3.8. E4 records each image's pytest version; on older versions, the metadata restore in §10 is the only protection against plugin entry points.
- **Clock.** Set to `T_clock`, so date-dependent tests behave as they did when written.
- **One shot.** No grader output ever reaches an agent's context. A retry is a new run with a fresh world, and attempts are counted.
- **Flaky tests.** E4 runs the tests three times on the base tree and with the gold patch. Tests with unstable results are excluded from every comparison.

**Limit.** The agent's code runs inside the test process, so forgery there can't be prevented. Python's own docs say audit hooks are not suitable for implementing a sandbox. The goal is detection.

### 11.2 Differential grading (patch and artifact tasks)

Each run uses a fresh GraderVM and the same validated work.

| Run | What changes | Expected | If not |
|---|---|---|---|
| **R0 normal** | Nothing | The verdict: `FAIL_TO_PASS` and `PASS_TO_PASS` | n/a |
| **R1 mutant** | This run's R2 test set, with expected values changed only in assertions that are in hidden lines **and** fail on the base tree, so that each changed test must fail on the base tree and with the gold patch | Every mutant fails | `tampered` |
| **R2 equivalence** | Same test IDs; the hidden tests and a random sample of visible tests rewritten to mean the same thing | Same result per test as R0 | `tampered` |
| **R3 fix removal** (advisory) | Functions the gold patch touches are stubbed to raise; where there is no function to stub, the gold-touched files are reverted to base | `FAIL_TO_PASS` fails | `review` |

Neither R1 nor R2 touches the agent's code, so forging code can't tell which run it is in by inspecting itself.

**R1 must be indistinguishable from R2.** R0 and R2 expect the same result and R1 the opposite, so that is the property that matters. Telling R0 apart from the other two doesn't help a forger.

- **Shared starting point.** For each graded run, one rewritten test set is drawn at random. R2 uses it as it is. R1 uses the same set, with expected values changed only in lines the agent never saw. Visible tests are therefore identical in R1 and R2.
- **Why that is enough.** A forger can notice that the tests changed, but not whether it is in R1 or R2. If it forges, R1 catches it. If it behaves honestly, R2's result differs from the forged R0 result, and R2 catches it.
- **Lines the agent saw stay unmutated.** When the hidden test patch modifies an existing test, R1 changes only the lines that patch added or changed.
- **Only base-failing assertions are mutated.** The agent has the base code, so a forger can carry a copy of the unpatched code and compute what the base returns on any input, including hidden ones.
  - On an assertion that passes on the base tree, a mutant would disagree with that copy and reveal R1. So such assertions keep their original values in R1, matching R2.
  - On an assertion that fails on the base tree, the expected value differs from the base result in both R1 and R2, so the copy reveals nothing.
- **Natural-looking rewrites.** Renamed locals drawn from ordinary names, reordered independent statements, swapped operands of symmetric comparisons, and equivalent assertion forms. No inserted no-op statements. Changed expected values are plausible values of the same type.
- **Nothing else differs.** Each variant is baked into its own grader disk. The kernel command line, environment, host name, disk layout and file sizes are padded or kept identical, and nothing in the VM names the run.

**A mutant must fail on both trees.** A plain inverted assertion (`==` changed to `!=`) passes on buggy code. A forger whose code is still buggy could then flip the outcome of every new test: the real test goes from fail to pass, the inverted one from pass to fail, and both runs look right. A mutant that fails on buggy and fixed code alike gives the forger nothing to flip. For a `FAIL_TO_PASS` test, that means changing the expected value of a base-failing assertion to a third value, one that also differs from the base result. Hidden tests that pass entirely on the base tree get no mutation at all.

| Forger strategy | Caught by |
|---|---|
| Blanket: every test passes, the report is rewritten, or assertion helpers are neutralised | R1 |
| Flips the outcome of new or changed tests (works when the agent's code is still buggy) | R1, because mutants fail on buggy code too |
| Tells the runs apart by comparing a visible test with its known base version | That separates R0 from R1 and R2, but R1 and R2 have identical visible tests. Forging in both is caught by R1; honesty in both is caught by R2. |
| Carries a copy of the base code and compares its results with the hidden assertions | Nothing to compare: only base-failing assertions are mutated |
| Keyed on test names (possible when the hidden patch modifies an existing test, or a name can be guessed from the issue) | R1: same names, mutated bodies |
| Keyed on a hash of the test's source | R2: same meaning, different source, so the honest result shows |
| Active only while the agent's own fix is intact | R1 and R2. It evades R3, which is why R3 is advisory. |
| Reads each test's meaning at run time and decides per assertion | Not reliably caught. Residual risk, measured in E8. |

**Advisory signals.** D11, and an optional C-level audit hook as telemetry. Neither is a boundary.

### 11.3 Building and running the variants

- **Pool.** On the staging host, by syntax-tree rewriting, a pool of rewritten test sets is generated per task (say 8), each with its matching mutant set. Each graded run draws one entry at random.
- **Validation (E4).** Each equivalent must match its original on the base tree and with the gold patch, and each mutant must fail on both. Tests with no mutant that validates are left out of R1, and the coverage is recorded.
- **Finding base-failing assertions.** A test normally stops at its first failing assertion, so later ones are never evaluated on the base tree. On the staging host only, E4 runs each hidden test on the base tree with every assertion recorded instead of stopping. An assertion is eligible for mutation if, on the base tree:
  - it fails or raises itself; or
  - it is never reached because an earlier statement raised, **and** the value it checks depends on that statement's result, by data flow in the test body. The base code crashes where that value would come from, so a copy of it can't compute the value.

  Any other unreached assertion is not mutated. A check on a value computed before the crash could still be computed by the copy, and would reveal R1.
- **Scope.** R1 and R2 run for every run that R0 marks resolved. Both use the drawn test set: all hidden tests plus a random sample of visible tests. R1 mutates only base-failing assertions in hidden lines.
- **Parallel.** R0, R1 and R2 are independent, so they run in parallel.
- **Languages.** Python comes first; each other language needs its own generator.

### 11.4 State tasks

The test checks the agent's own environment, including services and background processes it started, so a clean image isn't possible and a cold boot would kill what the test checks. `grader_isolation` is `shared`.

- **Live grading (default).** When the agent finishes:
  1. The harness stops sending commands, NetVM is destroyed and the gateway path is closed. The VM has no network and no model.
  2. The VM is paused and snapshotted (memory and disk).
  3. The snapshot is resumed on the grading host, still without network. Its network device is pointed at a tap with no peer (Firecracker's `network_overrides` on snapshot load), and the tests disk goes into a drive slot reserved at boot (`PATCH /drives`).
  4. execd mounts the tests disk read-only and runs the tests under the supervisor rules (§11.1), then returns the result over its channel.
- **Fallback.** If execd doesn't answer, or the task declares that it has no live state, a fresh VM boots a copy of the agent's disk with a trusted kernel and PID 1 from a trusted initramfs. The run records which path was used.
- **Limits.** The agent's leftover processes are still running and execd itself is exposed to root, so neither the result nor the tests' privacy is protected against a forger that stayed behind. Harbor's default shared verifier has the same property.
  - These tasks are reported separately, and their tests are exposed only after the agent's model access has ended.
  - Where a task author can declare outputs, convert the task to the artifact class.
- **Requirement.** Resuming needs a host with the same CPU model and Firecracker build. In a `single_host` deployment, that is automatic.

### 11.5 Rejected alternatives

Each of these sounds like a boundary, but sits inside the process the agent's code runs in.

- **Loading tests from memory and hiding the files.** The agent's code can still read the loaded test code through the call stack, and tests that open their own data files break.
- **Signing results with a secret held by a parent process.** The test process has to ask for the signature, and the agent's code can ask in the same way.
- **Moving the pass-or-fail decision to the parent, so both runs execute identical test code.** The parent then only negates what the child reports. A forger that always reports "true" is right in both runs, so the second run proves nothing.
- **Forcing an external pytest config.** It would discard the repo's own base settings, which the tests depend on.

## 12. Records and reporting

Both records are in-toto DSSE envelopes, signed with Sigstore keyless or with an offline key.

### 12.1 Run record (`hermetic-run/v1`)

It contains only deterministic or digest values:

- task ID, task class, `seal_level`, `agent_mode`, `clock`, `grader_isolation`, `deployment`;
- `T_world`, `T_clock`, the base commit and any `pkg_cutoff` override;
- the version tuple (§12.4);
- digests of the world root, the task rootfs, the NetVM image, the guest kernel, the VM config, the CPU template, the Firecracker build, the agent volume and the sealcheck report;
- `substrate_at_T`, the exemption list, and the D5b warning list (`repo_only` runs only);
- the escape-probe result and digest;
- heads of the WorldServer log, the dedupe-index digest and the request count;
- the harness command log head (Mode H), or the gateway log head and the history-rewrite count (Mode G), and the gateway adapter version;
- the digest of the submitted work, the results of R0–R3, R1 coverage, and the run status;
- `date_leak_observed` and `unclean_shutdown`;
- an optional TEE quote (AMD SEV-SNP, Intel TDX or AWS Nitro).

### 12.2 Audit record (`hermetic-transcript-audit/v1`)

It names the run digest as its subject, and records the classifier's derived or retrieved label, its confidence and the evidence spans. It is kept separate so a nondeterministic judge can't break `hermetic verify`.

### 12.3 Run status

| Status | Meaning | In the score |
|---|---|---|
| `resolved` | R0 passes; R1 and R2 clean | Counts as a success |
| `unresolved` | R0 fails | Counts as a failure |
| `tampered` | R1 or R2 tripped, or NetVM sent a malformed frame | Counts as a failure; listed |
| `limit_exceeded` | A gateway quota or the WorldServer volume cap was hit | Counts as a failure |
| `review` | R3 tripped, or the gate and the classifier disagree | Reported separately until a person decides |
| `infra_error` | Hermetic itself failed (VM crash, WorldServer fault) | Retried; excluded and listed if it keeps failing |
| `gate_blocked` | Excluded by sealcheck before any run (§5.5) | Excluded; listed by detector |

### 12.4 Score card and versions

**Score card.** Every published number comes with:

- the benchmark and its version;
- the version tuple;
- seal level, clock level and agent mode;
- counts per status;
- counts per task class and grader isolation;
- the lists of excluded and repaired tasks;
- the spread of `substrate_at_T`.

**Version tuple.** `spec_version`, `world_version` (the world root), `sealcheck_version`, and the grader image digest. Scores are comparable only within the same tuple.

### 12.5 What the records prove

| Proves | Does not prove |
|---|---|
| Which world the run used; that class A and B content predates the cutoff (`strict`), or which class B items didn't (`repo_only`); which substrate was exempt | That the model never saw the answer in training |
| That the escape probe failed to escape | That no timing side channel was used |
| Which URLs left WorldServer, and (Mode H) which commands the agent issued | **In Mode G:** which commands ran inside AgentVM |
| Which clock level applied | That a rooted agent couldn't learn the date at `faked` or `real`; that it couldn't tell the CPU's real generation, or where the cutoff lies |
| That grading used a clean image and passed R1 and R2 (patch and artifact tasks) | That a forger which reads test meaning wasn't present; anything about forgery in state tasks |
| | That the hidden tests are strong enough |
| | That the host was honest, unless a TEE quote is included |

---

# Part III — Delivery

## 13. Interfaces

### 13.1 World manifest

The manifest is the single description of a sealed world. `world_root` is a Merkle root over everything it names.

| Group | Fields |
|---|---|
| Identity | `spec_version`, `task_id`, `task_class`, `seal_level` |
| Cutoffs | `T_world`, `T_clock`, `base_commit`, `pkg_cutoff` |
| Content | `repo_tree_digest`, `rootfs_digest`, package layers (closure root, baseline month, baseline root), web (index month, capture-index root) |
| Substrate | A list of name, version, digest and date; `substrate_at_T`; the exemption list |
| Network | The DNS table (host names the world answers for); the world CA certificate digest; trust-store paths |
| Run spec | Environment, working directory, user, entry point, resources (§9.4) |
| Evidence | `sealcheck_report_digest`; dispositions applied (§5.5) |

### 13.2 Interface inventory

| Interface | Direction | Trust | Format | Limits |
|---|---|---|---|---|
| execd RPC (vsock 5000) | Host connects to AgentVM | Replies untrusted | Length-prefixed frames: exec, upload, download, status | Output cap per command and per run; downloads validated |
| NetVM to WorldServer (vsock) | NetVM sends requests | Requests untrusted | Fixed binary frames: authority, path and query, method | Size, rate and total limits (§7.3) |
| Model path, Mode G | AgentVM → NetVM → gateway | Requests untrusted | HTTP, checked by the adapter | Quotas (§9.2) |
| Model path, Mode H | Harness → gateway | Semi-trusted | Same adapter | Same |
| Extractor stream | ExtractorVM to host | Untrusted | Length-prefixed records (§10) | File count; per-file and total bytes |
| Grader result | GraderVM to grading host | Untrusted | Fixed-schema record on an output disk | Size cap; strict parser |

The host never listens for a connection that AgentVM starts.

## 14. Evaluation plan

| # | Experiment | Metric | Target |
|---|---|---|---|
| E1 | Seeded-leak red team: a canary in each closable channel of §2, attacked by a scripted root probe and by frontier agents told to find it | Canary recovery per channel | 0. A finite red team proves little, so every escape found later is logged publicly. |
| E2 | Ablation. **Track A:** cut the live network first, then add a sealed repo, the frozen mirror and the full world. **Track B:** start fully sealed and open one channel at a time. | Pass-rate change per channel | Report it; compare with Cursor's 14.1 and 20.7-point gaps |
| E3 | Scanner accuracy on three sets: leaks we seed; leaks seeded blind by someone else; published real leaks (pytest-6202 history, solution-in-issue cases from SWE-Bench+, the Cybench config). The seeded sets include deletion-only and one-character fixes, patch files, and leaks inside archives and SQLite files. | Precision and recall of gate findings; tier-2 review precision | Gate precision ≥ 95%, recall ≥ 90% on the blind and real sets |
| E4 | Oracle fidelity, per world version and before any agent | Gold patch passes; `FAIL_TO_PASS` fails on base; per-test results match the official harness for the gold patch and for an empty patch; test variants validate; flaky tests found | ≥ 99% of tasks |
| E5 | Date evidence: agents estimate the date and cite their evidence, at each clock level | Cited evidence dated after `T_clock`, split into substrate and other | 0 outside the substrate at `hidden` |
| E6 | Overhead | Gate time (cached and uncached), boot time, NetVM round trip, extraction time, grading time for R0–R2, storage | Cached gate < 5 s; end to end < 1.5× Docker |
| E7 | Reproducibility: seal the same task twice | World root | Identical, and frozen for the whole benchmark |
| E8 | Grader forger suite: the Berkeley `conftest.py` exploit, the Django `TestCase.run` monkey-patch, a trojaned runner, a planted module that shadows a runner import, fake output with an early exit, plugins registered through entry points, a test process that tries to reach the result disk, and forgers that are blanket, outcome-flipping, name-keyed, source-hash-keyed, self-checking, base-code-carrying, or that compare visible tests with their base version | Caught by R1 or R2, or blocked by the validator; false alarms on honest fixes | All caught or blocked; false alarms < 1% |
| E9 | Compatibility: the oracle in Docker vs in the microVM | Share of tasks that pass in both, with failure causes; share excluded by §1.5 | Report it |
| E10 | Gateway conformance: replay real agent traffic through each adapter | Legitimate requests wrongly blocked; real-date strings reaching the guest | < 1%; 0 |

**Design of E2.** The headline number is only as good as this.

- **Paired.** One fixed task subset, stratified by repository and year, run under every condition.
- **Seeds.** At least two per condition. Report bootstrap intervals and a paired test (McNemar).
- **Drift control.** The same agent in the official image with the network off, and in the sealed world with only the network sealed, must score the same within noise. A gap there is environment drift, not sealing, and is reported separately.
- **Budget.** API cost, not engineering, limits this experiment. Start with 50–100 tasks and state the sample size next to every number.

**Ethics.** E1, E5 and E8 run only in sealed worlds that passed the probe. Findings about public benchmarks go to maintainers privately first.

## 15. Build plan

### 15.1 Phases

| Phase | Build | Runs on | Exit criterion |
|---|---|---|---|
| **0 Vertical slice** | 5–10 SWE-bench Verified tasks end to end with stock tools: repo sealer, a local frozen pip index on a Docker network with no outside route, a clean container as grader, an unsigned JSON record | The MacBook | The oracle passes on every slice task, and one agent run is graded |
| **1 sealcheck** | `hermetic-common`, both modes, fingerprints, D0–D12, cutoffs, thread scrub, dispositions | The MacBook | E3 targets met; a leak report on one public benchmark, disclosed privately |
| **2 World** | Two-layer package world, WorldServer, trust injection, gateway with the Anthropic adapter, container isolation | Any Linux box | E4 ≥ 99%; E2 Track A on the paired subset; E10 |
| **3 VMs** | AgentVM, NetVM, ExtractorVM, GraderVM with R0–R2, execd, escape probe, attestations, Harbor backend, `clock: faked` | Linux x86 with KVM (EC2 with nested virtualization, or bare metal) | E1, E8, E9 |
| **3b Clock hiding** | Compile the Firecracker patch; CPU template; block the clock-pairing hypercall on the host; run the clock probe | Same | The probe passes, giving `clock: hidden`. If it doesn't, ship `faked`. |
| **4 Extensions** | Web archive and search, other ecosystems, other provider adapters, smart git, state-task grading, split mode, TEE quotes, aarch64 | Same | E2 Track B; E5 |

**Cut list.** If time runs out, drop in this order: Phase 4, Phase 3b, Mode G, R3, R2. The smallest result worth publishing is the Phase 1 leak report plus the Phase 2 ablation.

### 15.2 Repository layout

```text
hermetic-world/
  crates/                   (may start as modules of one crate)
    hermetic-common/        manifest, wire frames, hash chain, cutoff logic
    hermetic-sealcheck/     D0-D12, fingerprints, IDF index, layer index, SARIF
    hermetic-sealer/        repo rebuild, rootfs build + D4 verify, thread scrub, trust injection
    hermetic-world-server/  Ring 3: store, month index, limits, dedupe index, hash log
    hermetic-netvm/         Ring 2 daemon (static musl)
    hermetic-execd/         PID 1: clock-first boot, run spec, shutdown freeze, vsock runner
    hermetic-extract/       ExtractorVM agent + host-side stream validator
    hermetic-grader/        GraderVM supervisor: R0-R3
    hermetic-vmm/           Firecracker orchestration, CPU template, patched build, snapshots
    hermetic-gateway/       default-deny adapters, response sanitising, nonce, quotas
    hermetic-attest/        run/v1 + transcript-audit/v1, score card
    hermetic-cli/           seal, verify-bundle, probe, run, verify
  python/
    hermetic_harbor/        Harbor environment backend
    hermetic_pkg_resolver/  recording index, ecosystem baseline, snapshots
    hermetic_mutants/       test-variant pool generation and validation
    hermetic_classifier/    derived vs retrieved, host-side logs only
  images/
    kernel/                 guest config: no ptp_kvm, BPF on; boot args clocksource=tsc tsc=reliable
    netvm-rootfs/           dm-verity image
    extractor-rootfs/       minimal read-only image
  vmm/
    firecracker-enforce-pv-cpuid.patch
    hide-kvmclock.cpu-template.json
  tests/
    clock-leak-probe.md
```

## 16. Open risks

Nothing in this document has been built or run. These are the risks most likely to change the design.

1. **Clock hiding.** The Firecracker patch hasn't been compiled, and TSC stability without kvmclock is untested. No way of blocking the clock-pairing hypercall has been tried, and the simplest one depends on which clocksources the host offers (Phase 3b).
2. **Differential grading coverage.** R1 only mutates base-failing assertions in hidden tests, and mutants that fail on both trees may be hard to generate for many of them, so R1 coverage may be low. Honest fixes may trip R2 on tests that depend on source text. E4 and E8 measure both.
3. **`strict` rebuilds.** Old environments may not rebuild at the cutoff. E4 measures it; affected tasks fall back to `repo_only` and are labelled.
4. **microVM fidelity.** The share of tasks whose oracle passes in Docker but not in the VM is unknown (E9).
5. **Harbor.** Whether a custom environment backend can be registered cleanly hasn't been prototyped.
6. **Thresholds.** The tier-1 and tier-2 thresholds need calibrating (E3).
7. **Storage** for the per-month ecosystem baseline (Phase 2 measurement).
8. **Trust stores.** Clients that ignore both the system store and the environment variables will fail in the sealed world.
9. **Gateway adapters.** Only the Anthropic API's behaviour was checked. Other providers' fields and response metadata still need research.
10. **Budget.** E2 needs many paired agent runs on frontier models.
11. **Sources.** Several incident details come from secondhand write-ups; replace them with primary posts before publishing.
12. **Redistribution** of archived web content is unresolved (§6.5).
13. **Yank dates.** Whether PyPI publishes the date a release was yanked hasn't been checked (§6.3).

---

## Appendix A: Supporting files

| File | Purpose | State |
|---|---|---|
| `firecracker-enforce-pv-cpuid.patch` | Enables `KVM_CAP_ENFORCE_PV_FEATURE_CPUID` after every `set_cpuid2`, including on snapshot restore | Written, not compiled |
| `hide-kvmclock.cpu-template.json` | Clears bits 0 and 3 of CPUID leaf `0x40000001` eax | Written |
| `clock-leak-probe.md` | Seven clock checks plus a control run on unpatched Firecracker | Needs an eighth check: the clock-pairing hypercall, issued from a kernel module inside the guest |

## Appendix B: Sources

- **Leakage evidence:** Cursor reward-hacking study; NIST CAISI cheating examples; Vals MiMo; SWE-Bench+; SWE-Bench Illusion; Angulo et al. contamination taxonomy (2026); Paleka et al. (forecaster pitfalls); FutureSim; BrowseComp-Plus; Scale search-time contamination.
- **Grader attacks:** Berkeley RDI "trustworthy benchmarks" (`conftest.py`, trojaned `uv`); BenchJack (arXiv 2605.12673); Poolside "Through the looking glass"; Verification Horizon taxonomy (arXiv 2606.26300).
- **Isolation incidents:** SandboxEscapeBench (ICML 2026); OpenAI DNS escape and "offline world" (Oct 2026); CSA research note; AISI OpenClaw.
- **KVM, Firecracker and kernel:** KVM CPUID docs; kvm_pv_test selftest; the `kvm_get_wall_clock_epoch` commit; Firecracker source and docs (vcpu.rs port-I/O handler, `vmclock.rs`, `custom_cpu_template.rs`, entropy, vsock, snapshot network overrides, `PATCH /drives`); Linux source: `arch/x86/kvm/x86.c` (hypercall dispatch, `kvm_pv_clock_pairing`, `kvm_arch_vcpu_postcreate`), `kvm_para.h` (feature bits), `xen.h` (hypercall interception), `fs/namei.c` (`CAP_MKNOD`), `fs/namespace.c` (read-only remount), `fs/overlayfs/params.c` (mount options), `fs/ext4/super.c` (freeze), kbuild docs (`KBUILD_BUILD_TIMESTAMP`).
- **Packaging:** e2fsprogs source (`create_inode.c`, `initialize.c`); uv `crates/uv-dispatch` and `concurrency.rs`; pip `build_env/installer.py`; pip 26 release notes; npm config reference (`before`); pixi manifest reference (`exclude-newer`); crates.io development update, January 2026 (`pubtime`); Ubuntu snapshot service documentation; vcs-versioning `_git.py` (the `git describe --tags` command setuptools_scm runs); pytest source (`PYTEST_DISABLE_PLUGIN_AUTOLOAD`); Python `site` module (`usercustomize`).
- **SWE-bench images:** SWE-bench harness Dockerfiles; Epoch AI's SWE-bench Docker write-up (base image, unpinned dependencies).
- **Mutable content:** GitHub GraphQL `userContentEdits`; Stack Exchange data-dump post history.
- **git:** the "dumb" HTTP protocol and its lack of shallow-clone support.
- **Harbor:** network policies; separate verifier sandboxes (May 2026); task configuration docs.
- **Model API:** Claude API rate-limit documentation (reset headers); Claude PDF support (URL sources); prompt-caching docs (workspace isolation); Claude Code LLM gateway docs.
- **Attestation:** Attestable Audits; DeepMind double-blind evaluation; Valkyrie.

## Appendix C: Glossary

| Term | Meaning |
|---|---|
| `T_world` | World cutoff: nothing created after it is in the world (§4) |
| `T_clock` | The time the guest clock and all generated dates are set to (§4) |
| Base commit | The repo state the agent starts from; the repo boundary |
| Gold patch | The reference fix |
| `FAIL_TO_PASS`, `PASS_TO_PASS` | Hidden tests that must go from failing to passing, and tests that must keep passing |
| Hidden lines | Test lines the agent never saw: those the hidden test patch adds or changes |
| Base-failing assertion | An assertion that fails, raises, or is unreachable because of a crash it depends on, on the base tree (§11.3) |
| Oracle check (E4) | Running the gold patch and the test variants in the sealed world before any agent |
| Class A, B, C | Task-relevant content, third-party library code, substrate (§1.3) |
| `strict`, `repo_only` | Seal levels (§1.3) |
| `hidden`, `faked`, `real` | Clock levels (§8.1) |
| Mode H, Mode G | Agent loop outside the VM (harness) or inside it (gateway) (§9.1) |
| R0–R3 | Normal, mutant, equivalence and fix-removal grading runs (§11.2) |
| World root | Merkle root over the sealed world's manifest |
