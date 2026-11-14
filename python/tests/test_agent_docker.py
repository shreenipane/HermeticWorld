"""Docker integration tests for extract_patch and run_task."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import tempfile
from typing import Any

import pytest

from hermetic_slice.agent_loop import Limits
from hermetic_slice.dockerutil import is_docker_available, run_docker
from hermetic_slice.extract import extract_patch
from hermetic_slice.model_client import ModelReply
from hermetic_slice.runner import run_task

requires_docker = pytest.mark.skipif(
    not is_docker_available(),
    reason="Docker is not available",
)


class _RecordingSecrets:
    """Stands in for a module's ``secrets`` and records every token it hands out."""

    def __init__(self) -> None:
        self.tokens: list[str] = []

    def token_hex(self, nbytes: int | None = None) -> str:
        token = secrets.token_hex(nbytes)
        self.tokens.append(token)
        return token


def _owned_containers_left(prefix: str, tokens: list[str]) -> list[str]:
    """Containers named ``prefix...<token>...`` for this test's tokens (others are ignored)."""
    names = run_docker(["ps", "-a", "--format", "{{.Names}}"]).decode("utf-8").split()
    return [n for n in names if n.startswith(prefix) and any(t in n for t in tokens)]


@pytest.fixture(scope="module")
def fake_sealed_image():
    """Build a fake sealed image hermetic-t06-test-img-<random> with git repo at /testbed."""
    if not is_docker_available():
        pytest.skip("Docker is not available")

    rand_tag = secrets.token_hex(4)
    tag = f"hermetic-t06-test-img-{rand_tag}"

    dockerfile_content = (
        "FROM python:3.9-slim\n"
        "RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*\n"
        "RUN git config --global user.name 'Hermetic Tester' && git config --global user.email 'tester@localhost'\n"
        "RUN mkdir -p /testbed/pkg /testbed/tests /testbed/build\n"
        "WORKDIR /testbed\n"
        "RUN echo 'def mod_func(): return 1' > pkg/mod.py && \\\n"
        "    echo 'def test_func(): assert True' > tests/test_mod.py && \\\n"
        "    echo '[metadata]\\nname = testpkg\\nversion = 0.1\\n' > setup.cfg && \\\n"
        "    echo 'build/' > .gitignore && \\\n"
        "    git init -b main . && \\\n"
        "    git add . && \\\n"
        "    git commit -m 'base commit' && \\\n"
        "    echo '# env edit' >> setup.cfg && \\\n"
        "    echo 'binary_artifact_data' > build/artifact.bin\n"
    )

    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "Dockerfile").write_text(dockerfile_content, encoding="utf-8")
        run_docker(["build", "-t", tag, td], check=True)

    yield tag

    run_docker(["rmi", "-f", tag], check=False)


@pytest.mark.docker
def test_extract_patch_docker(
    tmp_path: Path, fake_sealed_image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hermetic_slice.extract as extract_mod

    recorder = _RecordingSecrets()
    monkeypatch.setattr(extract_mod, "secrets", recorder)
    rand_name = secrets.token_hex(4)
    agent_container = f"hermetic-t06-test-agent-{rand_name}"

    try:
        run_docker([
            "run",
            "-d",
            "--name", agent_container,
            fake_sealed_image,
            "sleep", "infinity",
        ], check=True)

        # In container:
        # 1. modify pkg/mod.py
        # 2. add pkg/new.py
        # 3. delete tests/test_mod.py
        # 4. add symlink pkg/link -> /etc/passwd
        # 5. write build/other.bin
        # 6. edit .git/config
        mutations = (
            "set -euo pipefail\n"
            "echo 'def mod_func(): return 42' > /testbed/pkg/mod.py\n"
            "echo 'def new_feature(): pass' > /testbed/pkg/new.py\n"
            "rm -f /testbed/tests/test_mod.py\n"
            "ln -s /etc/passwd /testbed/pkg/link\n"
            "echo 'other_binary' > /testbed/build/other.bin\n"
            "echo '# untrusted edit' >> /testbed/.git/config\n"
        )
        run_docker(["exec", agent_container, "/bin/bash", "-c", mutations], check=True)

        patch_text, report = extract_patch(agent_container, fake_sealed_image, tmp_path)

        # Assert diff contents
        assert "diff --git a/pkg/mod.py b/pkg/mod.py" in patch_text
        assert "return 42" in patch_text
        assert "diff --git a/pkg/new.py b/pkg/new.py" in patch_text
        assert "new file mode" in patch_text
        assert "diff --git a/tests/test_mod.py b/tests/test_mod.py" in patch_text
        assert "deleted file mode" in patch_text
        assert "diff --git a/pkg/link b/pkg/link" in patch_text
        assert "120000" in patch_text
        assert "/etc/passwd" in patch_text

        # Must NOT contain setup.cfg, build/, or .git
        assert "setup.cfg" not in patch_text
        assert "build" not in patch_text
        assert "artifact.bin" not in patch_text
        assert "other.bin" not in patch_text
        assert ".git" not in patch_text

        # Report counts
        assert report["files_changed"] == 1
        assert report["files_added"] == 2
        assert report["files_deleted"] == 1
        assert report["patch_bytes"] == len(patch_text.encode("utf-8"))
        assert report["tar_bytes"] > 0
        assert report["sha256"] == hashlib.sha256(patch_text.encode("utf-8")).hexdigest()

        # Extractor container must be gone
        # Only this test's extractor is checked, so concurrent runs cannot cause false failures.
        assert recorder.tokens
        assert _owned_containers_left("hermetic-extract-", recorder.tokens) == []

    finally:
        run_docker(["rm", "-f", agent_container], check=False)


class FakeDockerModel:
    def __init__(self, key: str = "fake-secret-model-key") -> None:
        self.model = "gemma-4-31b-it"
        self.api_key = key
        self.turn = 0

    def generate(self, system: str, messages: list[dict[str, str]]) -> ModelReply:
        self.turn += 1
        if self.turn == 1:
            cmd = "sed -i 's/return 1/return 99/' /testbed/pkg/mod.py"
            text = f"Fixing function:\n```bash\n{cmd}\n```"
        else:
            text = "Done:\n```bash\necho HERMETIC_SUBMIT\n```"

        return ModelReply(
            text=text,
            finish_reason="STOP",
            usage={
                "promptTokenCount": 20,
                "candidatesTokenCount": 10,
                "totalTokenCount": 30,
                "thoughtsTokenCount": 0,
            },
            latency_s=0.2,
            attempts=1,
        )


@pytest.mark.docker
def test_run_task_docker_end_to_end(
    tmp_path: Path, fake_sealed_image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hermetic_slice.runner as runner_mod

    recorder = _RecordingSecrets()
    monkeypatch.setattr(runner_mod, "secrets", recorder)
    task_dir = tmp_path / "task"
    (task_dir / "agent").mkdir(parents=True, exist_ok=True)
    (task_dir / "index").mkdir(parents=True, exist_ok=True)
    (task_dir / "world").mkdir(parents=True, exist_ok=True)
    (task_dir / "seal").mkdir(parents=True, exist_ok=True)

    task_json = {
        "instance_id": "test-instance-e2e",
        "repo": "test/repo",
        "base_commit": "abcdef1234567890",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-01T00:00:00Z",
        },
    }
    (task_dir / "task.json").write_text(json.dumps(task_json), encoding="utf-8")
    (task_dir / "agent" / "problem_statement.md").write_text("Fix return value of mod_func", encoding="utf-8")

    index_report = {
        "packages": [],
        "totals": {"served_packages": 0, "served_files": 0, "newer_than_t_world": 0},
    }
    (task_dir / "index" / "index-report.json").write_text(json.dumps(index_report), encoding="utf-8")
    (task_dir / "index" / "index.html").write_text("<html></html>", encoding="utf-8")

    probe_report = {"all_ok": True}
    (task_dir / "world" / "probe.json").write_text(json.dumps(probe_report), encoding="utf-8")

    seal_report = {"status": "sealed"}
    (task_dir / "seal" / "report.json").write_text(json.dumps(seal_report), encoding="utf-8")

    fake_key = "fake-secret-gemini-key-t06"
    model = FakeDockerModel(key=fake_key)

    grade_calls: list[dict[str, Any]] = []

    def fake_grade(td: Path, patch: str, *, image: str, out_dir: Path) -> dict[str, Any]:
        grade_calls.append({
            "task_dir": td,
            "patch": patch,
            "image": image,
            "out_dir": out_dir,
        })
        return {
            "status": "graded",
            "resolution": "RESOLVED_FULL",
            "resolved": True,
            "f2p": {"success": ["test_a"], "failure": []},
            "p2p": {"success": ["test_b", "test_c"], "failure": []},
            "findings": [],
        }

    run_dir = tmp_path / "run_dir"
    limits = Limits(max_steps=5, command_timeout_s=30)

    record = run_task(
        task_dir,
        model=model,
        grade_fn=fake_grade,
        run_dir=run_dir,
        image_tag_format=fake_sealed_image,
        limits=limits,
    )

    # 1. run.json is written with schema and every field
    run_json_path = run_dir / "run.json"
    assert run_json_path.exists()
    saved_record = json.loads(run_json_path.read_text(encoding="utf-8"))
    assert saved_record["schema"] == "hermetic-slice-run/v0-unsigned"
    assert saved_record["instance_id"] == "test-instance-e2e"
    assert saved_record["seal_level"] == "repo_only"
    assert saved_record["agent_mode"] == "H"
    assert saved_record["clock"] == "real"
    assert saved_record["grader_isolation"] == "clean_container"
    assert saved_record["deployment"] == "single_host"
    assert "task" in saved_record
    assert saved_record["task"]["t_world"] == "2024-01-01T00:00:00Z"
    assert saved_record["task"]["base_commit"] == "abcdef1234567890"
    assert "model" in saved_record
    assert "agent" in saved_record
    assert saved_record["agent"]["agent_status"] == "submitted"
    assert saved_record["agent"]["steps"] == 2
    assert "images" in saved_record
    assert saved_record["images"]["sealed_image"] == fake_sealed_image
    assert len(saved_record["images"]["sealed_image_id"]) > 0
    assert "extract" in saved_record
    assert saved_record["extract"]["files_changed"] == 1
    assert "grade" in saved_record
    assert saved_record["grade"]["resolution"] == "RESOLVED_FULL"
    assert saved_record["grade"]["f2p_success"] == 1
    assert saved_record["grade"]["p2p_success"] == 2
    assert saved_record["grade"]["p2p_failure"] == 0
    assert saved_record["status"] == "completed"
    assert isinstance(saved_record["date_leak_observed"], bool)
    assert saved_record["date_sentinel"]["date_leak_observed"] == saved_record["date_leak_observed"]
    assert "Phase 0: unsigned; transcript audit not run" in saved_record["notes"]

    # 2. Digests match the files
    digests = saved_record["digests"]
    assert digests["seal/report.json"] == hashlib.sha256((task_dir / "seal" / "report.json").read_bytes()).hexdigest()
    assert digests["index/index-report.json"] == hashlib.sha256((task_dir / "index" / "index-report.json").read_bytes()).hexdigest()
    assert digests["world/probe.json"] == hashlib.sha256((task_dir / "world" / "probe.json").read_bytes()).hexdigest()
    assert digests["trajectory.jsonl"] == hashlib.sha256((run_dir / "trajectory.jsonl").read_bytes()).hexdigest()
    assert digests["patch.diff"] == hashlib.sha256((run_dir / "patch.diff").read_bytes()).hexdigest()

    # 3. grade_fn received the extracted patch
    assert len(grade_calls) == 1
    patch_text = (run_dir / "patch.diff").read_text(encoding="utf-8")
    assert grade_calls[0]["patch"] == patch_text
    assert "return 99" in patch_text

    # 4. The world is torn down
    # Only this test's world is checked, so concurrent runs cannot cause false failures.
    assert recorder.tokens
    assert _owned_containers_left("hermetic-run-", recorder.tokens) == []

    # 5. Fake key appears in no file under run_dir
    for fpath in run_dir.rglob("*"):
        if fpath.is_file():
            content = fpath.read_bytes()
            assert fake_key.encode("utf-8") not in content, f"Key leaked in {fpath}"
