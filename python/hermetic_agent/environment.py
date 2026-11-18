"""A remote-only single-bash execution environment."""

from dataclasses import dataclass, asdict
import json
import shlex
import time

from .errors import ExecutionTimeout, LimitError, ProtocolError
from .protocol import (ExecdClient, MAX_COMMAND_BYTES, MAX_OUTPUT_BYTES,
                       MAX_RUN_OUTPUT_BYTES, timeout_seconds)


@dataclass(frozen=True)
class EnvironmentConfig:
    cwd: str
    timeout: float = 60


def guest_directory(cwd):
    if (not isinstance(cwd, str) or not cwd.startswith("/") or "\0" in cwd
            or len(cwd.encode("utf-8")) > 4096):
        raise ProtocolError("Invalid guest directory")
    return cwd


class ExecdEnvironment:
    def __init__(self, vsock_path: str, *, cwd: str, timeout: float = 60, journal=None, sentinel=None):
        self.config = EnvironmentConfig(guest_directory(cwd), timeout_seconds(timeout))
        self._client = ExecdClient(vsock_path)
        self._output_bytes = 0
        self._journal = journal
        self._sentinel = sentinel
        self._run_deadline = None

    def set_run_deadline(self, deadline):
        self._run_deadline = deadline

    def get_template_vars(self):
        return asdict(self.config)

    def execute(self, action: str, cwd: str = "", *, timeout: float | None = None):
        timeout = timeout_seconds(self.config.timeout if timeout is None else timeout)
        call_timeout = timeout + 5
        if self._run_deadline is not None:
            remaining = self._run_deadline - time.monotonic()
            if remaining <= 0:
                raise LimitError("Run deadline exceeded")
            timeout = min(timeout, remaining)
            call_timeout = min(call_timeout, remaining)
        directory = guest_directory(cwd or self.config.cwd)
        if not isinstance(action, str) or not action or "\0" in action:
            raise ProtocolError("Invalid action")
        command = f"cd -- {shlex.quote(directory)} && {action}"
        argv = ["/bin/bash", "--noprofile", "--norc", "-c", command]
        if (any(len(arg.encode()) > 4096 for arg in argv)
                or len(json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_COMMAND_BYTES):
            raise LimitError("Command byte limit")
        if self._output_bytes >= MAX_RUN_OUTPUT_BYTES:
            raise LimitError("Run output limit")
        if self._journal is not None:
            self._journal.record({"type": "command", "action": action, "cwd": directory})
        result = self._client.call({"type": "exec", "argv": argv, "tty": False,
                                    "timeout_ms": max(1, int(timeout * 1000))}, timeout=call_timeout)
        if (set(result) != {"type", "code", "output", "truncated", "timed_out"}
                or result.get("type") != "exec"
                or type(result.get("truncated")) is not bool
                or type(result.get("timed_out")) is not bool):
            raise ProtocolError("Invalid execution reply")
        code = result.get("code")
        output = result.get("output")
        if code is not None and (type(code) is not int or not -(2**31) <= code < 2**31):
            raise ProtocolError("Invalid return code")
        if (not isinstance(output, list) or len(output) > 1024 * 1024
                or any(type(byte) is not int or not 0 <= byte <= 255 for byte in output)):
            raise ProtocolError("Invalid command output")
        self._output_bytes += len(output)
        if self._output_bytes > MAX_RUN_OUTPUT_BYTES:
            raise LimitError("Run output limit")
        raw_output = bytes(output)
        if self._sentinel is not None:
            self._sentinel.scan_text("observation", raw_output)
        encoded = bytes(output[:MAX_OUTPUT_BYTES]).decode("utf-8", errors="replace").encode("utf-8")
        marker = b"\n[output truncated]"
        if result["truncated"] or len(output) > MAX_OUTPUT_BYTES or len(encoded) > MAX_OUTPUT_BYTES:
            text = encoded[:MAX_OUTPUT_BYTES - len(marker)].decode("utf-8", errors="ignore") + marker.decode()
        else:
            text = encoded.decode("utf-8")
        if self._journal is not None:
            self._journal.record({"type": "result", "code": code, "output": text,
                                  "timed_out": result["timed_out"], "truncated": result["truncated"]})
        if result["timed_out"]:
            raise ExecutionTimeout(text)
        return {"returncode": code if code is not None else 128, "output": text}
