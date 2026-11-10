"""Git invocation wrapper isolated from host environment configuration."""

from __future__ import annotations

import atexit
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


class GitError(Exception):
    """Raised when a git command exits with non-zero status."""

    def __init__(self, args: list[str], returncode: int, stderr: str, stdout: bytes = b"") -> None:
        self.args_list = list(args)
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        super().__init__(f"git command failed (exit {returncode}): {' '.join(args)}\n{stderr}")


_TEMP_DIR = tempfile.mkdtemp(prefix="hermetic_git_")
_EMPTY_GLOBAL_CONFIG = Path(_TEMP_DIR) / "empty_gitconfig"
_EMPTY_GLOBAL_CONFIG.touch(exist_ok=True)


@atexit.register
def _cleanup_temp_dir() -> None:
    """Clean up process-level temporary git config directory."""
    shutil.rmtree(_TEMP_DIR, ignore_errors=True)


def _git_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Return an isolated environment dictionary for running git."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    if extra_env:
        env.update(extra_env)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = str(_EMPTY_GLOBAL_CONFIG)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    return env


def run_git(
    args: list[str],
    *,
    cwd: Path,
    input: bytes | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> bytes:
    """Execute git with isolated environment and return stdout bytes."""
    cmd = ["git", *args]
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_env(env),
        shell=False,
    )
    if check and proc.returncode != 0:
        stderr_str = proc.stderr.decode("utf-8", errors="replace")
        raise GitError(cmd, proc.returncode, stderr_str, stdout=proc.stdout)
    return proc.stdout
