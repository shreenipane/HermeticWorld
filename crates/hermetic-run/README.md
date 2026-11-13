
# hermetic-run

Deterministic evaluation runner for Hermetic World software-engineering benchmarks.

## Modules

- **`infra`**: Defines the `Infra` trait, `Clock` trait, `NamedDeadline`, `DeadlineSchedule`, `CleanupLog`, and `VmGuard` (an RAII guard whose `Drop` implementation destroys started VMs and records cleanup across error and panic unwind paths).
- **`machine`**: Implements the explicit `StateMachine` (`Initial -> Prepared -> NetUp -> AgentUp -> AgentDone -> Extracted -> Graded -> Finished`, plus `Failed(step, reason)`), rejecting invalid transitions and enforcing VM existence invariants.
- **`verdict`**: Evaluates grader outputs (`R0`..`R3`) via `verdict()` and resolves overall run status under strict precedence: `tampered > infra_error > limit_exceeded > unresolved > review > resolved`.
- **`lib`**: Orchestrates the end-to-end evaluation lifecycle (`run_evaluation` and `run_evaluation_with_log`) and serializes deterministic `RunSummary` JSON containing only step names/outcomes, status, reasons, and `unclean_shutdown`.

## Running Tests

cargo test -p hermetic-run


