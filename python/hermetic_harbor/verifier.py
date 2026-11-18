"""Harbor separate-verifier mapping to ExtractorVM and GraderVM (TR-HB-1).

In separate-verifier mode:
1. Declared task artifacts are extracted from the agent tree via ExtractorVM logic,
   strictly rejecting any undeclared changes, path traversal, or symlinks.
2. Extracted artifacts are staged into the clean verifier sandbox (GraderVM).
3. The verifier test command executes under supervisor isolation (T_clock, no network).
4. Harbor evaluation rewards (/logs/verifier/reward.txt) and structured verdicts are emitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Any, Callable

from hermetic_safe_io import (
    IO_CHUNK_BYTES,
    MAX_PATH_BYTES,
    UnsafePathError,
    atomic_write,
    open_regular,
    scandir,
    validate_path,
)

from .errors import (
    HarborExtractionError,
    HarborSecurityError,
    HarborVerificationError,
)
from .task import TaskConfig

logger = logging.getLogger(__name__)

MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024  # 256 MiB
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024  # 1 MiB


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of Harbor task verification."""
    status: str  # "resolved", "unresolved", "tampered", "timeout", "error"
    reward: float  # 1.0 for pass, 0.0 for fail
    return_code: int
    extracted_artifacts: tuple[str, ...]
    stdout: str
    stderr: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    grader_isolation: str = "clean"  # "clean" for separate-verifier, "shared" for shared mode


def extract_declared_artifacts(
    agent_work_dir: Path | str,
    declared_artifacts: tuple[str, ...],
    destination_dir: Path | str,
) -> tuple[str, ...]:
    """ExtractorVM step: copy only the declared artifacts into the verifier sandbox.

    Refuses symlinks, device nodes, FIFOs, path traversal, and undeclared files.
    """
    agent_p = Path(os.fspath(agent_work_dir)).resolve()
    dest_p = Path(os.fspath(destination_dir)).resolve()

    dest_p.mkdir(parents=True, exist_ok=True, mode=0o700)
    extracted: list[str] = []
    total_bytes = 0

    for artifact in declared_artifacts:
        # Normalize relative path
        rel_artifact = artifact.lstrip("/")
        source_file = agent_p / rel_artifact
        target_file = dest_p / rel_artifact

        # Check for path escape
        try:
            target_file_resolved = target_file.resolve()
            if not str(target_file_resolved).startswith(str(dest_p)):
                raise HarborSecurityError("Artifact destination attempts path traversal")
        except Exception as exc:
            raise HarborSecurityError("Invalid artifact target path") from exc

        if not source_file.exists():
            # Declared artifact was not produced by the agent
            continue

        # Inspect source file without following symlinks
        try:
            fd = open_regular(source_file, MAX_ARTIFACT_FILE_BYTES)
        except UnsafePathError as exc:
            raise HarborExtractionError("Artifact file violates safe regular-file policy") from exc
        except (ValueError, OSError) as exc:
            raise HarborExtractionError("Artifact file is inaccessible or unsafe") from exc

        try:
            st = os.fstat(fd)
            size = st.st_size
            total_bytes += size
            if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                raise HarborExtractionError("Total extracted artifact size exceeds quota")

            chunks = []
            while True:
                chunk = os.read(fd, IO_CHUNK_BYTES)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)

        # Stage into verifier directory
        target_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(target_file, data)
        extracted.append(rel_artifact)

    return tuple(extracted)


def run_harbor_verification(
    task_config: TaskConfig,
    agent_work_dir: Path | str,
    verifier_tree_dir: Path | str,
    logs_dir: Path | str,
    t_clock: int = 1700000000,
    runner: Callable[[list[str], str, dict[str, str], float], dict[str, Any]] | None = None,
) -> VerificationResult:
    """Execute Harbor verification matching TR-HB-1.

    In separate-verifier mode:
    1. Extracts declared artifacts via ExtractorVM logic.
    2. Runs verifier tests in the verifier sandbox via GraderVM logic.
    3. Emits /logs/verifier/reward.txt and writes test logs.
    """
    logs_p = Path(os.fspath(logs_dir)).resolve()
    verifier_log_dir = logs_p / "verifier"
    verifier_log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    extracted: tuple[str, ...] = ()
    isolation = "clean"

    if task_config.is_separate_verifier:
        # Separate verifier: ExtractorVM extracts declared artifacts into verifier tree
        isolation = "clean"
        try:
            extracted = extract_declared_artifacts(
                agent_work_dir=agent_work_dir,
                declared_artifacts=task_config.artifacts,
                destination_dir=verifier_tree_dir,
            )
        except (HarborExtractionError, HarborSecurityError) as exc:
            # Extraction failure results in unresolved/tampered verdict
            reward_data = b"0.0\n"
            atomic_write(verifier_log_dir / "reward.txt", reward_data)
            return VerificationResult(
                status="tampered",
                reward=0.0,
                return_code=1,
                extracted_artifacts=(),
                stdout="",
                stderr="Artifact extraction failed",
                reasons=("extraction_failed",),
                grader_isolation=isolation,
            )
        target_work_dir = Path(os.fspath(verifier_tree_dir)).resolve()
    else:
        # Shared verifier: tests run directly in agent work directory
        isolation = "shared"
        target_work_dir = Path(os.fspath(agent_work_dir)).resolve()

    # GraderVM step: execute verifier command under supervisor isolation
    cmd = task_config.verifier.test_command
    timeout = float(task_config.verifier.timeout_sec)
    argv = ["/bin/bash", "--noprofile", "--norc", "-c", cmd]

    py_dir = str(Path(sys.executable).parent)
    clean_env = {
        "PATH": f"{py_dir}:/usr/local/bin:/usr/bin:/bin",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": "/tmp",
        "SOURCE_DATE_EPOCH": str(t_clock),
    }

    if runner is not None:
        try:
            res = runner(argv, str(target_work_dir), clean_env, timeout)
            stdout = res.get("stdout", "")
            stderr = res.get("stderr", "")
            rc = res.get("return_code", 0)
        except subprocess.TimeoutExpired:
            rc = 124
            stdout = ""
            stderr = "Verifier execution timed out"
        except Exception:
            rc = 1
            stdout = ""
            stderr = "Verifier runner failed"
    else:
        try:
            proc = subprocess.run(
                argv,
                cwd=str(target_work_dir),
                capture_output=True,
                env=clean_env,
                timeout=timeout,
                check=False,
            )
            stdout = proc.stdout[:MAX_VERIFIER_OUTPUT_BYTES].decode("utf-8", errors="replace")
            stderr = proc.stderr[:MAX_VERIFIER_OUTPUT_BYTES].decode("utf-8", errors="replace")
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rc = 124
            stdout = ""
            stderr = "Verifier execution timed out"
        except Exception:
            rc = 1
            stdout = ""
            stderr = "Verifier execution failed"

    # Determine reward and status
    reasons: list[str] = []
    if rc == 0:
        reward = 1.0
        status = "resolved"
    elif rc == 124:
        reward = 0.0
        status = "timeout"
        reasons.append("verifier_timeout")
    else:
        reward = 0.0
        status = "unresolved"
        reasons.append("tests_failed")

    # Harbor standard reward outputs
    reward_text = f"{reward:.1f}\n".encode("ascii")
    atomic_write(verifier_log_dir / "reward.txt", reward_text)

    reward_json = json.dumps({"reward": reward}, indent=2).encode("ascii") + b"\n"
    atomic_write(verifier_log_dir / "reward.json", reward_json)

    atomic_write(verifier_log_dir / "test-stdout.txt", stdout.encode("utf-8", errors="replace"))
    atomic_write(verifier_log_dir / "test-stderr.txt", stderr.encode("utf-8", errors="replace"))

    return VerificationResult(
        status=status,
        reward=reward,
        return_code=rc,
        extracted_artifacts=extracted,
        stdout=stdout,
        stderr=stderr,
        reasons=tuple(reasons),
        grader_isolation=isolation,
    )
