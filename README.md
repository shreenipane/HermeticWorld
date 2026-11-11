# Hermetic World

A time-sealed evaluation environment for AI agents. Each task runs in a world frozen at the moment the task was created. That way an agent can only solve the task by working it out, not by looking the answer up.

The first component, **sealcheck**, proves before a run that nothing created after that moment is reachable.

> **Status:** Phase 0 (vertical slice) is complete and Phase 1 (sealcheck) is in progress. See [PHASES.md](PHASES.md) and [BUILD_LOG.md](BUILD_LOG.md).

## Why

Agent benchmarks are built from past events, but agents run in today's world. Cursor found that 63% of Opus 4.8 Max's successful SWE-bench Pro fixes were retrieved rather than derived. Sealing git history and the internet dropped its score from 87.1% to 73.0%.

Hermetic World closes those channels and records, in a signed record, how well each one was closed.

## The three properties

| Property | Claim | Strength |
|---|---|---|
| **P1 Answer seal** | No information created after the world cutoff is reachable by the agent | Hard guarantee, gated |
| **P2 Date seal** | Nothing the agent can read states a date later than the guest clock | Best effort, three levels, measured |
| **P3 Score integrity** | The score depends only on the submitted work, graded in an environment the agent never touched | Full for patch and artifact tasks, reduced for state tasks |

P1 is the product. It doesn't depend on P2.

## How it works, in one paragraph

On an online **staging host**, the sealer builds a frozen world for a task: the repo cut at the base commit, a root filesystem stamped at the cutoff, and a package mirror and web archive dated at or before the cutoff. sealcheck then scans it for anything newer. On an offline **run host**, the agent works as root inside a Firecracker **AgentVM**. All of its network traffic goes to a **NetVM** that answers only from the frozen world, and model traffic goes through a default-deny **gateway**. When the agent stops, a throwaway **ExtractorVM** pulls out its work. A clean **GraderVM** then runs the tests three ways (normal, mutant and equivalence) to detect forged results. The host signs a record of everything.

## Documents

| File | What it holds |
|---|---|
| [HERMETIC_WORLD_ARCHITECTURE.md](HERMETIC_WORLD_ARCHITECTURE.md) | **The full design specification. Source of truth.** |
| [PRD.md](PRD.md) | Product requirements: problem, users, goals, requirements, success metrics |
| [TRD.md](TRD.md) | Technical requirements: stack, per-component requirements, formats, security, performance |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture overview: rings, components, data flow, invariants, key decisions |
| [PHASES.md](PHASES.md) | Build plan: phases, deliverables checklists, exit criteria, cut list |
| [BUILD_LOG.md](BUILD_LOG.md) | Dated log of what was built, measured and decided |

If a derived document disagrees with the specification, the specification wins. Fix the derived document.

## Platform

- Linux x86_64 with KVM and Firecracker microVMs (aarch64 later).
- Core in **Rust**. The Harbor bridge, package resolvers, test rewriting and classifier are in **Python**.
- Phases 0–1 need no VMs and run in containers. Phase 3 onwards needs KVM, either bare metal or EC2 with nested virtualization.

## Planned CLI

```text
hermetic seal --task <id>     # compute cutoffs, build the world bundle and manifest
hermetic verify-bundle        # run sealcheck against a bundle
hermetic probe                # escape probe from a rooted throwaway AgentVM
hermetic run                  # boot, work, stop, extract, grade, sign
hermetic verify               # check a signed run record
```

Only `seal --task <id>` has its arguments fixed by the spec. Arguments for the other commands are still to be designed.

## Planned repository layout

```text
crates/    Rust: common, sealcheck, sealer, world-server, netvm, execd,
           extract, grader, vmm, gateway, attest, cli
python/    harbor backend, package resolver, mutants, classifier
images/    guest kernel config, NetVM and extractor root filesystems
vmm/       Firecracker patch and CPU template
tests/     clock-leak probe
```

See [ARCHITECTURE.md § Code layout](ARCHITECTURE.md#code-layout) for what each crate owns.

## Scope

Not goals: undetectability, contamination in the model's weights, closing timing side channels, hiding the cutoff itself, and hiding the CPU generation. Not in the first release: multi-container tasks, nested Docker, GPU tasks, and tasks that need the live internet by design.
