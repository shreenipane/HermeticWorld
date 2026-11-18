"""Harbor task configuration parser and validator (TR-HB-1).

Parses task.toml definitions under strict size, count, and path constraints.
Validates declared artifact paths and verifier configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from typing import Any

from hermetic_safe_io import MAX_PATH_BYTES, MAX_PATH_COMPONENTS, open_regular

from .errors import HarborConfigError, HarborSecurityError

MAX_TASK_FILE_BYTES = 64 * 1024  # 64 KiB
MAX_TASK_NAME_BYTES = 256
MAX_ARTIFACTS_COUNT = 256
MAX_COMMAND_LEN = 4096
MAX_VERIFIER_TIMEOUT = 3600


@dataclass(frozen=True)
class VerifierConfig:
    """Verifier configuration within a Harbor task."""
    environment_mode: str = "separate"  # "separate" or "shared"
    test_command: str = "bash tests/test.sh"
    timeout_sec: int = 120
    docker_image: str | None = None


@dataclass(frozen=True)
class TaskConfig:
    """Parsed and validated Harbor task configuration."""
    name: str
    artifacts: tuple[str, ...] = field(default_factory=tuple)
    verifier: VerifierConfig = field(default_factory=VerifierConfig)

    @property
    def is_separate_verifier(self) -> bool:
        return self.verifier.environment_mode == "separate"


def validate_artifact_path(path: str) -> str:
    """Validate a declared artifact path: no traversal, no nulls, reasonable length."""
    if not isinstance(path, str) or not path or "\0" in path:
        raise HarborConfigError("Artifact path contains null byte or is empty")
    encoded = path.encode("utf-8")
    if len(encoded) > MAX_PATH_BYTES:
        raise HarborConfigError("Artifact path exceeds byte limit")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if len(parts) > MAX_PATH_COMPONENTS or ".." in parts:
        raise HarborConfigError("Artifact path contains traversal components or exceeds depth")
    return path


def parse_task_toml(raw_bytes: bytes) -> TaskConfig:
    """Parse task.toml bytes into a validated TaskConfig."""
    if not isinstance(raw_bytes, bytes):
        raise HarborConfigError("task.toml data must be bytes")
    if len(raw_bytes) > MAX_TASK_FILE_BYTES:
        raise HarborConfigError("task.toml exceeds size limit")

    try:
        text = raw_bytes.decode("utf-8")
        data: dict[str, Any] = tomllib.loads(text)
    except Exception as exc:
        raise HarborConfigError("Failed to parse task.toml syntax") from exc

    if not isinstance(data, dict):
        raise HarborConfigError("task.toml root must be a table")

    task_table = data.get("task", {})
    if not isinstance(task_table, dict):
        raise HarborConfigError("[task] section must be a table")

    name = task_table.get("name", "unnamed-task")
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > MAX_TASK_NAME_BYTES:
        raise HarborConfigError("Invalid task name")

    raw_artifacts = task_table.get("artifacts", [])
    if not isinstance(raw_artifacts, list):
        raise HarborConfigError("artifacts must be a list")
    if len(raw_artifacts) > MAX_ARTIFACTS_COUNT:
        raise HarborConfigError("artifacts count exceeds maximum limit")

    validated_artifacts = []
    for art in raw_artifacts:
        validated_artifacts.append(validate_artifact_path(art))

    verifier_table = data.get("verifier", {})
    if not isinstance(verifier_table, dict):
        raise HarborConfigError("[verifier] section must be a table")

    mode = verifier_table.get("environment_mode", "separate")
    if mode not in ("separate", "shared"):
        raise HarborConfigError(f"Unsupported verifier environment_mode: {mode}")

    test_cmd = verifier_table.get("test_command", verifier_table.get("command", "bash tests/test.sh"))
    if not isinstance(test_cmd, str) or not test_cmd or len(test_cmd) > MAX_COMMAND_LEN:
        raise HarborConfigError("Invalid verifier test_command")

    timeout = verifier_table.get("timeout_sec", 120)
    if type(timeout) is not int or not (1 <= timeout <= MAX_VERIFIER_TIMEOUT):
        raise HarborConfigError("Invalid verifier timeout_sec")

    v_env = verifier_table.get("environment", {})
    docker_img = v_env.get("docker_image") if isinstance(v_env, dict) else None
    if docker_img is not None and (not isinstance(docker_img, str) or len(docker_img) > 1024):
        raise HarborConfigError("Invalid verifier docker_image")

    verifier_config = VerifierConfig(
        environment_mode=mode,
        test_command=test_cmd,
        timeout_sec=timeout,
        docker_image=docker_img,
    )

    return TaskConfig(
        name=name,
        artifacts=tuple(validated_artifacts),
        verifier=verifier_config,
    )


def load_task_config(task_path: Path | str) -> TaskConfig:
    """Load and validate task.toml from a file path using safe regular-file I/O."""
    p = Path(os.fspath(task_path))
    if p.is_dir():
        p = p / "task.toml"

    fd = open_regular(p, MAX_TASK_FILE_BYTES)
    try:
        data = os.read(fd, MAX_TASK_FILE_BYTES)
    finally:
        os.close(fd)

    return parse_task_toml(data)
