"""Trusted test-service declarations shared by intake and container grading."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from hermetic_safe_io import open_regular
from . import httpbin_service

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SERVICE_SOURCE_BYTES = 64 * 1024
MAX_TEST_SERVICES = 1
HTTPBIN_PROFILE = "httpbin-v1"
REQUESTS_BASE = "091991be0da19de9108dbe5e3752917fea3d7fdc"
GUEST_LOADER = (
    "import sys\n"
    f"source=sys.stdin.buffer.read({MAX_SERVICE_SOURCE_BYTES + 1})\n"
    f"if len(source)>{MAX_SERVICE_SOURCE_BYTES}:\n    raise SystemExit(1)\n"
    "exec(compile(source, '<hermetic-test-service>', 'exec'))"
)


def declared_services(repo: str, base_commit: str) -> list[str]:
    """Only the reviewed historical requests suite receives the built-in profile."""
    return [HTTPBIN_PROFILE] if repo == "psf/requests" and base_commit == REQUESTS_BASE else []


def _validate(value):
    if not isinstance(value, list) or len(value) > MAX_TEST_SERVICES:
        raise ValueError("invalid test services")
    if any(type(item) is not str or item != HTTPBIN_PROFILE for item in value):
        raise ValueError("unknown test service")
    return value


def read_regular(path: Path, cap: int) -> bytes:
    with os.fdopen(open_regular(path, cap), "rb") as stream:
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise ValueError("test-service file exceeds cap")
    return data


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest field")
        result[key] = value
    return result


@dataclass(frozen=True)
class TestServicePlan:
    names: tuple[str, ...]
    t_clock: int | None

    def command(self, container: str) -> list[str]:
        if not self.names:
            return ["exec", container, "/bin/bash", "/eval.sh"]
        # Activate the image's test interpreter before starting the service. -I
        # keeps repository files and interpreter environment out of its imports.
        launcher = (
            "set -e\n"
            "if [ -f /opt/miniconda3/etc/profile.d/conda.sh ]; then\n"
            "  . /opt/miniconda3/etc/profile.d/conda.sh\n"
            "  conda activate testbed\n"
            "fi\n"
            f'exec python -I -c "{GUEST_LOADER}" --t-clock {self.t_clock} --run /bin/bash /eval.sh\n'
        )
        return ["exec", "-i", container, "/bin/bash", "-c", launcher]


def load_test_services(task_dir: Path, task: dict) -> TestServicePlan:
    """Prefer the sealed manifest; reject conflicting or unsupported declarations.

    Older intake artifacts predate this field. Only the exact reviewed requests
    base has a migration default, so the existing oracle command can use it.
    No task artifact is changed during grading.
    """
    names = _validate(task["test_services"]) if "test_services" in task else None
    try:
        raw = read_regular(task_dir / "manifest.json", MAX_MANIFEST_BYTES)
    except FileNotFoundError:
        manifest = None
    else:
        try:
            manifest = json.loads(raw, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("invalid test-service manifest") from None
        if not isinstance(manifest, dict):
            raise ValueError("invalid test-service manifest")
    if manifest is not None:
        sealed = _validate(manifest.get("test_services", []))
        if names is not None and names != sealed:
            raise ValueError("conflicting test-service declarations")
        names = sealed
    if names is None:
        names = declared_services(task.get("repo"), task.get("base_commit"))
    names = _validate(names)
    if not names:
        return TestServicePlan((), None)
    try:
        value = task["cutoffs"]["t_clock"]
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError()
        clock = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if clock.tzinfo is None or clock.utcoffset() is None or clock.microsecond:
            raise ValueError()
        epoch = int(clock.astimezone(timezone.utc).timestamp())
        httpbin_service.fixed_date(epoch)
        if manifest is not None and "cutoffs" in manifest and manifest["cutoffs"]["t_clock"] != value:
            raise ValueError()
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("invalid test-service clock") from None
    return TestServicePlan(tuple(names), epoch)


def service_source() -> bytes:
    return read_regular(Path(httpbin_service.__file__), MAX_SERVICE_SOURCE_BYTES)
