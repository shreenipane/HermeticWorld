"""Offline evaluation world management, execution, and probes."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import time
from typing import Any

from hermetic_slice.dockerutil import DockerError, run_docker


@dataclass(frozen=True)
class World:
    """Represents an isolated evaluation world with index and agent containers."""

    name: str
    network: str
    index_container: str
    agent_container: str


ENV_ACTIVATE = (
    "if [ -f /opt/miniconda3/etc/profile.d/conda.sh ]; then\n"
    "    . /opt/miniconda3/etc/profile.d/conda.sh\n"
    "    conda activate testbed 2>/dev/null || true\n"
    "fi\n"
)


def start_world(
    task: dict,
    image: str,
    index_dir: Path,
    *,
    name: str,
    timeout: float = 30.0,
) -> World:
    """Start index and agent containers on an internal network."""
    network = f"{name}-net"
    index_container = f"{name}-index"
    agent_container = f"{name}-agent"
    world = World(
        name=name,
        network=network,
        index_container=index_container,
        agent_container=agent_container,
    )

    try:
        run_docker(["network", "create", "--internal", network], check=True)

        abs_index_dir = Path(index_dir).resolve()
        run_docker([
            "run",
            "-d",
            "--name", index_container,
            "--network", network,
            "-v", f"{abs_index_dir}:/srv:ro",
            "python:3.12-alpine",
            "python", "-m", "http.server", "8080", "--directory", "/srv",
        ], check=True)

        deadline = time.time() + timeout
        server_ready = False
        while time.time() < deadline:
            try:
                run_docker([
                    "exec",
                    index_container,
                    "python", "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=1)",
                ], check=True)
                server_ready = True
                break
            except DockerError:
                time.sleep(0.2)

        if not server_ready:
            raise RuntimeError(f"Index container {index_container} did not respond within {timeout}s")

        run_docker([
            "run",
            "-d",
            # --init: PID 1 reaps orphans, so killed or backgrounded agent
            # processes don't pile up as zombies.
            "--init",
            "--name", agent_container,
            "--network", network,
            "-e", f"PIP_INDEX_URL=http://{index_container}:8080/simple/",
            "-e", f"PIP_TRUSTED_HOST={index_container}",
            "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",
            "--entrypoint", "/bin/bash",
            image,
            "-c", "sleep infinity",
        ], check=True)

        return world
    except Exception:
        stop_world(world)
        raise


TIMEOUT_EXIT_CODE = 124


def world_exec(world: World, script: str, *, timeout: int = 600) -> tuple[int, str]:
    """Execute a bash script inside the agent container.

    The time limit is enforced inside the container by coreutils `timeout`, which
    signals the script's whole process group, so nothing keeps running after a
    timeout. Killing only the host-side `docker exec` client would leave it running.
    A timeout returns exit code 124 (137 if the group needed SIGKILL).
    """
    args = [
        "exec", world.agent_container,
        "timeout", "-k", "5", str(timeout), "/bin/bash", "-lc", script,
    ]
    try:
        stdout_bytes = run_docker(args, check=True, timeout=timeout + 30, combine_output=True)
        return (0, stdout_bytes.decode("utf-8", errors="replace"))
    except DockerError as exc:
        out = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else exc.stderr
        return (exc.returncode, out)
    except subprocess.TimeoutExpired as exc:
        # Backstop only: the in-container timeout should have fired first.
        partial = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        return (TIMEOUT_EXIT_CODE, partial + "\n[hermetic: command timed out]")


def stop_world(world: World) -> None:
    """Tear down index and agent containers and network idempotently."""
    run_docker(["rm", "-f", world.agent_container], check=False)
    run_docker(["rm", "-f", world.index_container], check=False)
    run_docker(["network", "rm", world.network], check=False)


def probe(world: World, task: dict, report: dict) -> dict[str, Any]:
    """Verify isolation, positive and negative installs, and name reachability."""
    results: dict[str, dict[str, Any]] = {}

    # 1. positive: pip download --no-deps --dest /tmp/p <pkg>==<v> succeeds (first served package)
    target_pkg = None
    target_ver = None
    for p in report.get("packages", []):
        if p.get("served_versions"):
            target_pkg = p["name"]
            target_ver = p["served_versions"][0]
            break

    if target_pkg and target_ver:
        cmd = f"{ENV_ACTIVATE}mkdir -p /tmp/p && pip download --no-deps --dest /tmp/p {target_pkg}=={target_ver}"
        code, out = world_exec(world, cmd)
        results["positive"] = {
            "ok": (code == 0),
            "detail": out.strip() if code == 0 else f"pip download failed (code {code}): {out.strip()}",
        }
    else:
        results["positive"] = {
            "ok": False,
            "detail": "No served package found in report",
        }

    # 2. negative, newer: pip download --no-deps <pkg>==<installed_version> fails
    newer_pkg = None
    newer_ver = None
    for p in report.get("packages", []):
        if p.get("installed_newer_than_t_world"):
            newer_pkg = p["name"]
            newer_ver = p["installed_version"]
            break

    if newer_pkg and newer_ver:
        cmd = f"{ENV_ACTIVATE}pip download --no-deps {newer_pkg}=={newer_ver}"
        code, out = world_exec(world, cmd)
        results["negative_newer"] = {
            "ok": (code != 0),
            "detail": f"Failed as expected (code {code}): {out.strip()}" if code != 0 else f"Unexpectedly succeeded: {out.strip()}",
        }
    else:
        results["negative_newer"] = {
            "ok": True,
            "detail": "No newer packages in report to test",
        }

    # 3. negative, target: pip download --no-deps <target project> fails
    target_project = None
    if report.get("excluded"):
        target_project = report["excluded"][0]
    elif task.get("repo"):
        target_project = task["repo"].split("/")[-1]

    if target_project:
        cmd = f"{ENV_ACTIVATE}pip download --no-deps {target_project}"
        code, out = world_exec(world, cmd)
        results["negative_target"] = {
            "ok": (code != 0),
            "detail": f"Failed as expected (code {code}): {out.strip()}" if code != 0 else f"Unexpectedly succeeded: {out.strip()}",
        }
    else:
        results["negative_target"] = {
            "ok": False,
            "detail": "No target project identified",
        }

    # 4. egress: pypi.org and 1.1.1.1 unreachable
    egress_script = (
        f"{ENV_ACTIVATE}"
        r'''python -c "
import urllib.request, socket, sys

errors = []

try:
    socket.getaddrinfo('pypi.org', 443)
    errors.append('DNS for pypi.org resolved')
except Exception:
    pass

try:
    with urllib.request.urlopen('https://pypi.org/simple/', timeout=5) as resp:
        errors.append('https://pypi.org/simple/ reached')
except Exception:
    pass

try:
    with urllib.request.urlopen('http://1.1.1.1/', timeout=5) as resp:
        errors.append('http://1.1.1.1/ reached')
except Exception:
    pass

if errors:
    print('; '.join(errors))
    sys.exit(1)
else:
    print('Egress blocked')
    sys.exit(0)
"'''
    )
    code, out = world_exec(world, egress_script)
    results["egress"] = {
        "ok": (code == 0),
        "detail": out.strip() if code == 0 else f"Egress leak: {out.strip()}",
    }

    # 5. name isolation: index container reachable by name
    index_url = f"http://{world.index_container}:8080/simple/"
    isolation_script = (
        f"{ENV_ACTIVATE}"
        rf'''python -c "
import urllib.request, sys
try:
    with urllib.request.urlopen('{index_url}', timeout=5) as resp:
        if resp.status == 200:
            print('Reachable')
            sys.exit(0)
        else:
            print(f'Status {{resp.status}}')
            sys.exit(1)
except Exception as e:
    print(f'Unreachable: {{e}}')
    sys.exit(1)
"'''
    )
    code, out = world_exec(world, isolation_script)
    results["name_isolation"] = {
        "ok": (code == 0),
        "detail": out.strip() if code == 0 else f"Isolation failed: {out.strip()}",
    }

    all_ok = all(v["ok"] for v in results.values())
    return {
        **results,
        "all_ok": all_ok,
    }
