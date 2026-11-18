# Hermetic Harbor Backend (TR-HB-1)

`hermetic_harbor` provides an execution environment backend for the Harbor
agent-evaluation framework, running agent tasks through the sealed Hermetic World.

## Approved Dependency

- Package: `harbor` (Python)
- Pinned Version: **`0.25.0`** (Released: **2026-10-25**, > 2 weeks prior to cutoff)
- Staged install target: `pip install './python/hermetic_harbor[harbor]'`

The sealing pipeline and offline test suite do not require this dependency
to be installed in order to validate backend safety, bounds, and interfaces.

## Architecture Mapping

- **Separate Verifier Mode (`environment_mode = "separate"`):**
  - Harbor copies declared task artifacts from the agent environment into an
    isolated verifier container.
  - In Hermetic World, this copy maps to **ExtractorVM** (`hermetic-extract-validate`),
    which enforces regular-file policy, checks against declared `artifact_paths`,
    and drops or rejects unauthorized filesystem modifications outside declared paths.
  - The verifier session maps to **GraderVM** (`hermetic-grader-supervisor`), running
    tests against clean task images under supervisor isolation (sealed clock `T_clock`,
    no network, process isolation, result disk).
  - Rewards are emitted to `/logs/verifier/reward.txt` and `/logs/verifier/reward.json`.

- **Shared Verifier Mode (`environment_mode = "shared"`):**
  - When a task does not declare a separate verifier, tests run in the agent's
    environment under shared isolation, recording `grader_isolation: "shared"`
    per architecture §11.4.

## Registration Prototype

Harbor uses a closed `EnvironmentType` enum and an internal dictionary registry
(`_ENVIRONMENT_REGISTRY`) in `harbor.environments.factory`.

`hermetic_harbor.registration`:
- Validates the pinned `harbor==0.25.0` version.
- Dynamically registers `HERMETIC = "hermetic"` in `EnvironmentType`.
- Injects `HermeticEnvironment` into `_ENVIRONMENT_REGISTRY`.
- Provides `unregister_hermetic()` for test cleanup and isolation.
- Refuses hostile, malformed, or invalid inputs.

## Security and Safety

- **Safe I/O:** Every host-side file operation uses descriptor-pinned handles
  (`hermetic_safe_io`), opens with `O_NOFOLLOW`, refuses symlinks, FIFOs, and
  device nodes, and writes atomically with mode 0600.
- **Bounds:** Every buffer, directory traversal, command execution, and transfer
  is bounded by named constants (`MAX_COMMAND_BYTES`, `MAX_TRANSFER_BYTES`,
  `MAX_TIMEOUT_SECONDS`, `MAX_DIR_ENTRIES`).
- **Sanitization:** Diagnostics contain fixed strings and never echo host paths,
  host timestamps, usernames, or host network identifiers.
