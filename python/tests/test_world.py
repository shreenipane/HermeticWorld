"""Docker integration tests for offline world and probe."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import zipfile

import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.dockerutil import is_docker_available, run_docker
from hermetic_slice.world import probe, start_world, stop_world, world_exec

requires_docker = pytest.mark.skipif(
    not is_docker_available(),
    reason="Docker is not available or docker info failed",
)


def _build_wheel(dest_dir: Path, name: str, version: str) -> tuple[str, str]:
    """Create a valid pure-python wheel and return (filename, sha256)."""
    norm_name = name.replace("-", "_")
    filename = f"{norm_name}-{version}-py2.py3-none-any.whl"
    dist_info = f"{norm_name}-{version}.dist-info"
    wheel_path = dest_dir / filename

    entries: list[tuple[str, bytes]] = [
        (
            f"{norm_name}/__init__.py",
            f'__version__ = "{version}"\n'.encode("utf-8"),
        ),
        (
            f"{dist_info}/METADATA",
            (
                "Metadata-Version: 2.1\n"
                f"Name: {name}\n"
                f"Version: {version}\n"
                "Summary: Synthetic demo wheel for testing\n"
            ).encode("utf-8"),
        ),
        (
            f"{dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: hermetic-test\n"
                "Root-Is-Purelib: true\n"
                "Tag: py2.py3-none-any\n"
            ).encode("utf-8"),
        ),
    ]

    record_lines: list[str] = []
    for path, data in entries:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
        record_lines.append(f"{path},sha256={digest},{len(data)}")
    record_lines.append(f"{dist_info}/RECORD,,")
    record_bytes = "\n".join(record_lines).encode("utf-8") + b"\n"
    entries.append((f"{dist_info}/RECORD", record_bytes))

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries:
            zf.writestr(path, data)

    sha256 = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    return filename, sha256


@pytest.fixture(scope="module")
def fake_agent_image():
    """Build a fake agent image from python:3.9-slim once for the module."""
    if not is_docker_available():
        pytest.skip("Docker is not available")

    tag = f"hermetic-t04-test-agent-{secrets.token_hex(4)}"
    df_content = (
        "FROM python:3.9-slim\n"
        "RUN mkdir -p /testbed\n"
        "WORKDIR /testbed\n"
    )
    with tempfile.TemporaryDirectory() as td:
        df_path = Path(td) / "Dockerfile"
        df_path.write_text(df_content, encoding="utf-8")
        run_docker(["build", "-t", tag, td], check=True)

    yield tag

    run_docker(["rmi", "-f", tag], check=False)


@pytest.mark.docker
def test_world_lifecycle_and_probe(tmp_path: Path, fake_agent_image: str) -> None:
    """Test start_world, probe, and stop_world with hand-made wheel index."""
    index_dir = tmp_path / "index"
    files_dir = index_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    wheel_filename, wheel_sha = _build_wheel(files_dir, "hermetic-demo", "1.0")

    simple_demo_dir = index_dir / "simple" / "hermetic-demo"
    simple_demo_dir.mkdir(parents=True, exist_ok=True)
    demo_html = (
        "<!DOCTYPE html>\n<html><body>\n"
        f'<a href="../../files/{wheel_filename}#sha256={wheel_sha}">{wheel_filename}</a>\n'
        "</body></html>\n"
    )
    (simple_demo_dir / "index.html").write_text(demo_html, encoding="utf-8")

    root_simple = index_dir / "simple" / "index.html"
    root_simple.write_text(
        '<!DOCTYPE html>\n<html><body><a href="hermetic-demo/">hermetic-demo</a></body></html>\n',
        encoding="utf-8",
    )

    report = {
        "t_world": "2024-01-01T00:00:00Z",
        "packages": [
            {
                "name": "hermetic-demo",
                "installed_version": "2.0",
                "installed_version_uploaded": "2024-06-01T00:00:00Z",
                "installed_newer_than_t_world": True,
                "served_versions": ["1.0"],
                "served_files": [wheel_filename],
                "yanked_served": [],
            }
        ],
        "excluded": ["target-pkg"],
        "totals": {
            "installed_packages": 1,
            "served_packages": 1,
            "served_versions": 1,
            "served_files": 1,
            "yanked_served": 0,
            "newer_than_t_world": 1,
        },
    }
    (index_dir / "index-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    task = {
        "instance_id": "test-task-1",
        "repo": "test-org/target-pkg",
        "image": fake_agent_image,
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-01T00:00:00Z",
        },
    }

    world_name = f"hermetic-t04-test-w-{secrets.token_hex(4)}"
    world = start_world(task, fake_agent_image, index_dir, name=world_name)

    try:
        # Inside world: hermetic-demo 1.0 succeeds
        code, out = world_exec(world, "mkdir -p /tmp/p && pip download --no-deps --dest /tmp/p hermetic-demo==1.0")
        assert code == 0, f"pip download hermetic-demo==1.0 failed: {out}"

        # Inside world: hermetic-demo 2.0 fails
        code, out = world_exec(world, "pip download --no-deps hermetic-demo==2.0")
        assert code != 0, "pip download hermetic-demo==2.0 succeeded unexpectedly"

        # Probe execution
        probe_res = probe(world, task, report)
        assert probe_res["all_ok"] is True, f"Probe failed: {probe_res}"
        assert probe_res["positive"]["ok"] is True
        assert probe_res["negative_newer"]["ok"] is True
        assert probe_res["negative_target"]["ok"] is True
        assert probe_res["egress"]["ok"] is True
        assert probe_res["name_isolation"]["ok"] is True

        # A timed-out command is killed inside the container, children included
        code, out = world_exec(
            world, "touch /tmp/started; (sleep 37; touch /tmp/child-survived) & sleep 37", timeout=2
        )
        assert code in (124, 137), f"expected a timeout exit code, got {code}: {out}"
        # Live processes only: a zombie's cmdline is empty, and --init reaps them anyway.
        code, out = world_exec(
            world,
            'test -e /tmp/started || exit 3; sleep 1; n=0; '
            'for d in /proc/[0-9]*; do [ "$(tr "\\0" " " < "$d/cmdline" 2>/dev/null)" = "sleep 37 " ] && n=$((n+1)); done; '
            'echo "alive=$n"',
        )
        assert (code, out.strip()) == (0, "alive=0"), f"processes survived the timeout: {code} {out}"
    finally:
        stop_world(world)

    # Verify stop_world leaves no containers or networks behind
    containers_out = run_docker(["ps", "-a", "--filter", f"name={world_name}", "--format", "{{.Names}}"])
    leftover_containers = [c.strip() for c in containers_out.decode("utf-8").splitlines() if c.strip()]
    assert leftover_containers == []

    networks_out = run_docker(["network", "ls", "--filter", f"name={world_name}", "--format", "{{.Name}}"])
    leftover_networks = [n.strip() for n in networks_out.decode("utf-8").splitlines() if n.strip()]
    assert leftover_networks == []


@pytest.mark.docker
def test_world_probe_cli(tmp_path: Path, fake_agent_image: str) -> None:
    """Test world-probe CLI subcommand end to end."""
    tasks_dir = tmp_path / "tasks"
    task_dir = tasks_dir / "test-inst-1"
    index_dir = task_dir / "index"
    files_dir = index_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    wheel_filename, wheel_sha = _build_wheel(files_dir, "hermetic-demo", "1.0")

    simple_demo_dir = index_dir / "simple" / "hermetic-demo"
    simple_demo_dir.mkdir(parents=True, exist_ok=True)
    demo_html = (
        "<!DOCTYPE html>\n<html><body>\n"
        f'<a href="../../files/{wheel_filename}#sha256={wheel_sha}">{wheel_filename}</a>\n'
        "</body></html>\n"
    )
    (simple_demo_dir / "index.html").write_text(demo_html, encoding="utf-8")
    (index_dir / "simple" / "index.html").write_text(
        '<!DOCTYPE html>\n<html><body><a href="hermetic-demo/">hermetic-demo</a></body></html>\n',
        encoding="utf-8",
    )

    report = {
        "t_world": "2024-01-01T00:00:00Z",
        "packages": [
            {
                "name": "hermetic-demo",
                "installed_version": "2.0",
                "installed_version_uploaded": "2024-06-01T00:00:00Z",
                "installed_newer_than_t_world": True,
                "served_versions": ["1.0"],
                "served_files": [wheel_filename],
                "yanked_served": [],
            }
        ],
        "excluded": ["target-pkg"],
        "totals": {
            "installed_packages": 1,
            "served_packages": 1,
            "served_versions": 1,
            "served_files": 1,
            "yanked_served": 0,
            "newer_than_t_world": 1,
        },
    }
    (index_dir / "index-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    task = {
        "instance_id": "test-inst-1",
        "repo": "test-org/target-pkg",
        "image": fake_agent_image,
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-01T00:00:00Z",
        },
    }
    (task_dir / "task.json").write_text(json.dumps(task, indent=2), encoding="utf-8")

    # Run world-probe with image-tag-format pointing to fake_agent_image
    exit_code = main([
        "world-probe",
        "--tasks-dir", str(tasks_dir),
        "--only", "test-inst-1",
        "--image-tag-format", fake_agent_image,
    ])
    assert exit_code == 0
    probe_json = task_dir / "world" / "probe.json"
    assert probe_json.exists()
    probe_data = json.loads(probe_json.read_text(encoding="utf-8"))
    assert probe_data["all_ok"] is True
