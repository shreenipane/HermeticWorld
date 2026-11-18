"""Hermetic Environment backend for Harbor (TR-HB-1).

Subclasses Harbor's `BaseEnvironment` (or a protocol-compatible base if Harbor
is uninstalled), executing agent actions through the sealed world and enforcing
strict resource, deadline, and safe-I/O bounds without host information leakage.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import math
import os
from pathlib import Path
import shlex
import stat
import subprocess
import time
from typing import Any, Callable

from hermetic_safe_io import (
    IO_CHUNK_BYTES,
    MAX_PATH_BYTES,
    MAX_PATH_COMPONENTS,
    UnsafePathError,
    atomic_write,
    open_parent,
    open_regular,
    scandir,
    validate_path,
)

from .errors import (
    HarborConfigError,
    HarborExecutionError,
    HarborSecurityError,
)

logger = logging.getLogger(__name__)

# Strict named bounds
MAX_COMMAND_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RUN_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300
MAX_TRANSFER_BYTES = 1024 * 1024  # 1 MiB (matches execd MAX_TRANSFER)
MAX_DIR_ENTRIES = 1000
MAX_DIR_TOTAL_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64

# Try importing from harbor; define robust fallbacks if not installed
try:
    from harbor.environments.base import BaseEnvironment as _HarborBaseEnvironment  # type: ignore[import-untyped]
    from harbor.environments.base import ExecResult as _HarborExecResult  # type: ignore[import-untyped]
except ImportError:
    _HarborBaseEnvironment = None  # type: ignore[assignment,misc]
    _HarborExecResult = None  # type: ignore[assignment,misc]

try:
    from harbor.environments.capabilities import EnvironmentCapabilities as _HarborCapabilities  # type: ignore[import-untyped]
except ImportError:
    _HarborCapabilities = None  # type: ignore[assignment,misc]


@dataclass
class ExecResult:
    """Execution result matching Harbor's ExecResult schema."""
    stdout: str | None = None
    stderr: str | None = None
    return_code: int = 0


@dataclass
class EnvironmentCapabilities:
    """Capabilities descriptor matching Harbor's capability schema."""
    supports_exec: bool = True
    supports_file_transfers: bool = True
    supports_ssh: bool = False
    isolated_network: bool = True
    sealed_clock: bool = True


if _HarborBaseEnvironment is not None:
    _Base = _HarborBaseEnvironment
else:
    class _Base:  # type: ignore[no-redef]
        """Fallback base class when harbor is not installed."""
        def __init__(
            self,
            environment_name: str,
            session_id: str,
            trial_paths: Any = None,
            task_env_config: Any = None,
            logger: logging.Logger | None = None,
            **kwargs: Any,
        ):
            self.environment_name = environment_name
            self.session_id = session_id
            self.trial_paths = trial_paths
            self.task_env_config = task_env_config
            self.logger = logger or logging.getLogger(__name__)


def validate_guest_path(path: str) -> str:
    """Validate a guest filesystem path for sanity and boundary preservation."""
    if not isinstance(path, str) or not path or "\0" in path:
        raise HarborSecurityError("Invalid guest path: contains null or is empty")
    encoded = path.encode("utf-8")
    if len(encoded) > MAX_PATH_BYTES:
        raise HarborSecurityError("Guest path exceeds byte cap")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if len(parts) > MAX_PATH_COMPONENTS or ".." in parts:
        raise HarborSecurityError("Guest path attempts traversal or exceeds depth")
    return path


class HermeticEnvironment(_Base):
    """Hermetic World execution environment backend for Harbor."""

    def __init__(
        self,
        environment_name: str,
        session_id: str,
        trial_paths: Any = None,
        task_env_config: Any = None,
        logger: logging.Logger | None = None,
        manifest_path: str | Path | None = None,
        vsock_path: str | None = None,
        runner: Callable[[list[str], str, dict[str, str], float], dict[str, Any]] | None = None,
        t_clock: int = 1700000000,
        **kwargs: Any,
    ):
        super().__init__(
            environment_name=environment_name,
            session_id=session_id,
            trial_paths=trial_paths,
            task_env_config=task_env_config,
            logger=logger,
            **kwargs,
        )
        self.manifest_path = manifest_path
        self.vsock_path = vsock_path
        self._runner = runner
        self.t_clock = t_clock
        self._is_running = False
        self._output_bytes = 0
        self._client: Any = None

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def capabilities(self) -> Any:
        if _HarborCapabilities is not None:
            try:
                return _HarborCapabilities()
            except Exception:
                pass
        return EnvironmentCapabilities()

    @classmethod
    def connect_ssh(cls, handle: Any) -> Any:
        raise NotImplementedError("HermeticEnvironment does not provide SSH access")

    async def start(self, force_build: bool = False) -> None:
        """Start the sealed environment."""
        if self._is_running:
            return
        if self.vsock_path is not None:
            # Wire execd client if vsock endpoint supplied
            from hermetic_agent.protocol import ExecdClient
            self._client = ExecdClient(self.vsock_path)
        self._output_bytes = 0
        self._is_running = True

    async def stop(self, delete: bool = False) -> None:
        """Stop and tear down the sealed environment."""
        self._is_running = False
        self._client = None

    async def exec(
        self,
        command: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_sec: int | None = None,
        user: str | int | None = None,
    ) -> Any:
        """Execute a shell command inside the sealed environment."""
        if not self._is_running:
            raise HarborExecutionError("Environment is not running")

        if not isinstance(command, str) or not command.strip() or "\0" in command:
            raise HarborExecutionError("Invalid command string")
        if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
            raise HarborExecutionError("Command exceeds size limit")

        guest_cwd = validate_guest_path(cwd if cwd else "/testbed")
        timeout = float(timeout_sec if timeout_sec is not None else 60)
        if not (0 < timeout <= MAX_TIMEOUT_SECONDS) or not math.isfinite(timeout):
            raise HarborExecutionError("Invalid execution timeout")

        if self._output_bytes >= MAX_RUN_OUTPUT_BYTES:
            raise HarborExecutionError("Environment cumulative output byte limit exceeded")

        cmd_env: dict[str, str] = {}
        if env is not None:
            if not isinstance(env, dict):
                raise HarborConfigError("Environment variables must be a dictionary")
            for k, v in env.items():
                if not isinstance(k, str) or not isinstance(v, str) or "\0" in k or "\0" in v:
                    raise HarborConfigError("Invalid environment variable key/value")
                cmd_env[k] = v

        full_command = f"cd -- {shlex.quote(guest_cwd)} && {command}"
        argv = ["/bin/bash", "--noprofile", "--norc", "-c", full_command]

        result_cls = _HarborExecResult if _HarborExecResult is not None else ExecResult

        # 1. Injected runner (used for offline deterministic unit testing)
        if self._runner is not None:
            try:
                res = self._runner(argv, guest_cwd, cmd_env, timeout)
            except subprocess.TimeoutExpired:
                raise HarborExecutionError("Command execution timed out") from None
            except Exception as exc:
                raise HarborExecutionError("Injected runner execution failed") from exc

            stdout_text = res.get("stdout", "")
            stderr_text = res.get("stderr", "")
            code = res.get("return_code", 0)

            out_len = len(stdout_text.encode("utf-8")) + len(stderr_text.encode("utf-8"))
            self._output_bytes += out_len
            if self._output_bytes > MAX_RUN_OUTPUT_BYTES:
                raise HarborExecutionError("Environment cumulative output byte limit exceeded")

            return result_cls(stdout=stdout_text, stderr=stderr_text, return_code=code)

        # 2. Vsock execd client (Mode H in AgentVM)
        if self._client is not None:
            req = {
                "type": "exec",
                "argv": argv,
                "tty": False,
                "timeout_ms": max(1, int(timeout * 1000)),
            }
            try:
                reply = self._client.call(req, timeout=timeout + 5)
            except Exception as exc:
                raise HarborExecutionError("Vsock execution RPC failed") from exc

            if reply.get("timed_out", False):
                raise HarborExecutionError("Command execution timed out")

            raw_output = bytes(reply.get("output", []))
            self._output_bytes += len(raw_output)
            if self._output_bytes > MAX_RUN_OUTPUT_BYTES:
                raise HarborExecutionError("Environment cumulative output byte limit exceeded")

            text = raw_output[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            code = reply.get("code")
            return result_cls(stdout=text, stderr="", return_code=code if code is not None else 128)

        # 3. Fail closed: host execution of agent commands is prohibited
        raise HarborExecutionError("Isolated runner is required; host execution is prohibited")

    async def upload_file(self, source_path: Path | str, target_path: str) -> None:
        """Upload a local file from the host into the environment using safe I/O."""
        if not self._is_running:
            raise HarborExecutionError("Environment is not running")

        validate_guest_path(target_path)

        # Open and inspect the local regular file without following symlinks
        try:
            fd = open_regular(source_path, MAX_TRANSFER_BYTES)
        except UnsafePathError as exc:
            raise HarborSecurityError("Source file violates safe regular-file policy") from exc
        except (ValueError, OSError) as exc:
            raise HarborSecurityError("Invalid source path or file inaccessible") from exc

        try:
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, IO_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TRANSFER_BYTES:
                    raise HarborSecurityError("Upload exceeds transfer byte cap")
                chunks.append(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)

        # Upload through vsock client or write to local guest tree
        if self._client is not None:
            req = {"type": "upload", "path": target_path, "data": list(data)}
            try:
                self._client.call(req)
            except Exception as exc:
                raise HarborExecutionError("Vsock file upload failed") from exc
        else:
            # Local filesystem staging (e.g., in offline testbed directory)
            # Create parent directories if needed
            target_p = Path(target_path)
            if target_p.is_absolute():
                target_p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                atomic_write(target_p, data)

    async def download_file(self, source_path: str, target_path: Path | str) -> None:
        """Download a file from the environment to a host path using safe I/O."""
        if not self._is_running:
            raise HarborExecutionError("Environment is not running")

        validate_guest_path(source_path)

        data: bytes
        if self._client is not None:
            req = {"type": "download", "path": source_path}
            try:
                reply = self._client.call(req)
            except Exception as exc:
                raise HarborExecutionError("Vsock file download failed") from exc
            raw = reply.get("data", [])
            if not isinstance(raw, list) or len(raw) > MAX_TRANSFER_BYTES:
                raise HarborSecurityError("Downloaded data violates size bounds")
            data = bytes(raw)
        else:
            source_p = Path(source_path)
            if not source_p.exists():
                raise HarborExecutionError("Source file does not exist in environment")
            try:
                fd = open_regular(source_p, MAX_TRANSFER_BYTES)
            except Exception as exc:
                raise HarborSecurityError("Guest source file unsafe or unreadable") from exc
            try:
                data = os.read(fd, MAX_TRANSFER_BYTES)
            finally:
                os.close(fd)

        # Write to host using descriptor-pinned atomic write (mode 0600, no symlinks)
        try:
            atomic_write(target_path, data)
        except Exception as exc:
            raise HarborSecurityError("Host download destination write failed") from exc

    async def upload_dir(self, source_dir: Path | str, target_dir: str) -> None:
        """Upload a host directory into the environment, refusing symlinks and FIFOs."""
        if not self._is_running:
            raise HarborExecutionError("Environment is not running")

        validate_guest_path(target_dir)

        # Verify source directory parent descriptor and attributes
        source_p = Path(os.fspath(source_dir)).resolve()
        if not source_p.is_dir():
            raise HarborSecurityError("Source directory must exist and be a directory")

        entries_count = 0
        total_bytes = 0

        # Walk safely using scandir
        for root, dirs, files in os.walk(str(source_p), followlinks=False):
            rel_root = os.path.relpath(root, str(source_p))
            # Refuse symlinks in directory hierarchy
            for d in dirs:
                full_d = os.path.join(root, d)
                st = os.lstat(full_d)
                if stat.S_ISLNK(st.st_mode):
                    raise HarborSecurityError("Symlinked directory rejected in upload_dir")
                entries_count += 1
                if entries_count > MAX_DIR_ENTRIES:
                    raise HarborSecurityError("upload_dir exceeds maximum entry cap")

            for f in files:
                full_f = os.path.join(root, f)
                st = os.lstat(full_f)
                if stat.S_ISLNK(st.st_mode):
                    raise HarborSecurityError("Symlink rejected in upload_dir")
                if not stat.S_ISREG(st.st_mode):
                    raise HarborSecurityError("Non-regular file rejected in upload_dir")

                file_size = st.st_size
                if file_size > MAX_TRANSFER_BYTES:
                    raise HarborSecurityError("File in upload_dir exceeds per-file cap")
                total_bytes += file_size
                if total_bytes > MAX_DIR_TOTAL_BYTES:
                    raise HarborSecurityError("upload_dir exceeds cumulative byte cap")
                entries_count += 1
                if entries_count > MAX_DIR_ENTRIES:
                    raise HarborSecurityError("upload_dir exceeds maximum entry cap")

                rel_file = os.path.join(rel_root, f) if rel_root != "." else f
                dest_file = os.path.join(target_dir, rel_file)
                await self.upload_file(full_f, dest_file)

    async def download_dir(self, source_dir: str, target_dir: Path | str) -> None:
        """Download a directory from the environment to host."""
        if not self._is_running:
            raise HarborExecutionError("Environment is not running")

        validate_guest_path(source_dir)
        target_p = Path(os.fspath(target_dir))
        target_p.mkdir(parents=True, exist_ok=True, mode=0o700)

        # In offline/local mode: scan and download
        source_p = Path(source_dir)
        if not source_p.is_dir():
            raise HarborExecutionError("Source directory does not exist")

        entries_count = 0
        total_bytes = 0
        for root, dirs, files in os.walk(str(source_p), followlinks=False):
            rel_root = os.path.relpath(root, str(source_p))
            for f in files:
                full_f = os.path.join(root, f)
                st = os.lstat(full_f)
                if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                    continue
                entries_count += 1
                if entries_count > MAX_DIR_ENTRIES:
                    raise HarborSecurityError("download_dir exceeds maximum entry cap")
                total_bytes += st.st_size
                if total_bytes > MAX_DIR_TOTAL_BYTES:
                    raise HarborSecurityError("download_dir exceeds cumulative byte cap")

                rel_file = os.path.join(rel_root, f) if rel_root != "." else f
                dest_file = target_p / rel_file
                dest_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                await self.download_file(full_f, dest_file)
