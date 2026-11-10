"""Docker invocation wrapper isolated and controlled."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess


class DockerError(Exception):
    """Raised when a docker command exits with non-zero status."""

    def __init__(self, args: list[str], returncode: int, stderr: str, stdout: bytes = b"") -> None:
        self.args_list = list(args)
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        super().__init__(f"docker command failed (exit {returncode}): {' '.join(args)}\n{stderr}")


def is_docker_available() -> bool:
    """Return True if docker binary is found and docker info succeeds."""
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def run_docker(
    args: list[str],
    *,
    input: bytes | None = None,
    check: bool = True,
    timeout: float | None = None,
    combine_output: bool = False,
    stdout_path: Path | None = None,
) -> bytes:
    """Execute docker CLI and return stdout bytes."""
    cmd = ["docker", *args]
    stderr_dest = subprocess.STDOUT if combine_output else subprocess.PIPE
    if stdout_path is not None:
        with open(stdout_path, "wb") as out_f:
            proc = subprocess.run(
                cmd,
                input=input,
                stdout=out_f,
                stderr=stderr_dest,
                shell=False,
                timeout=timeout,
            )
        if check and proc.returncode != 0:
            stderr_str = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            raise DockerError(cmd, proc.returncode, stderr_str)
        return b""

    proc = subprocess.run(
        cmd,
        input=input,
        stdout=subprocess.PIPE,
        stderr=stderr_dest,
        shell=False,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        if proc.stderr:
            stderr_str = proc.stderr.decode("utf-8", errors="replace")
        elif proc.stdout:
            stderr_str = proc.stdout.decode("utf-8", errors="replace")
        else:
            stderr_str = ""
        raise DockerError(cmd, proc.returncode, stderr_str, stdout=proc.stdout)
    return proc.stdout
