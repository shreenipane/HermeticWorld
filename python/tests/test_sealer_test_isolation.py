"""Offline regressions for concurrent sealer integration test runs."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from tests import test_image_sealer as sealer_tests


def test_fake_swebench_runs_build_and_remove_only_owned_tags(tmp_path_factory, monkeypatch):
    live_images: set[str] = set()
    removed: list[str] = []

    def docker(args, **kwargs):
        if args[0] == "build":
            tag = args[args.index("-t") + 1]
            assert tag not in live_images, "concurrent fixture overwrote another run's image"
            live_images.add(tag)
        else:
            assert args[:2] == ["rmi", "-f"]
            live_images.remove(args[2])
            removed.append(args[2])
        return b""

    monkeypatch.setattr(sealer_tests, "is_docker_available", lambda: True)
    monkeypatch.setattr(sealer_tests, "run_docker", docker)
    first = sealer_tests.fake_swebench_image.__wrapped__(tmp_path_factory)
    second = sealer_tests.fake_swebench_image.__wrapped__(tmp_path_factory)
    try:
        first_image = next(first)["image"]
        second_image = next(second)["image"]
        assert first_image != second_image
        first.close()
        assert live_images == {second_image}
        assert removed == [first_image]
        second.close()
        assert live_images == set()
        assert removed == [first_image, second_image]
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize("test_name", [
    "test_seal_image_end_to_end",
    "test_seal_image_failure_writes_report",
    "test_cli_seal_images",
])
def test_sealer_runs_use_distinct_output_tags_and_owned_cleanup(tmp_path, monkeypatch, test_name):
    # Stop at the build boundary; the original integration tests still choose
    # their task IDs and output tags and execute their real cleanup blocks.
    class BuildBoundary(BaseException):
        pass

    builds: list[tuple[str, str | None]] = []
    removed: list[str] = []

    def seal(task_dir: Path, work_dir: Path, *, tag=None):
        task = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
        builds.append((task["instance_id"], tag))
        raise BuildBoundary

    def docker(args, **kwargs):
        assert args[:2] == ["rmi", "-f"]
        removed.append(args[2])
        return b""

    monkeypatch.setattr(sealer_tests, "seal_image", seal)
    monkeypatch.setattr(importlib.import_module("hermetic_slice.__main__"), "seal_image", seal)
    monkeypatch.setattr(sealer_tests, "run_docker", docker)
    fake_image = {
        "image": "unused-offline-input",
        "c1": "1" * 40,
        "c2": "2" * 40,
        "c3_base": "3" * 40,
        "distinctive_line": "distinctive dangling test line",
        "pre_base_line": "historic test line",
    }
    for run in ("first", "second"):
        with pytest.raises(BuildBoundary):
            getattr(sealer_tests, test_name)(tmp_path / run, fake_image)

    assert len(builds) == len(removed) == 2
    assert builds[0][0] != builds[1][0], "concurrent tests reused the task's default output tag"
    assert removed[0] != removed[1], "cleanup can remove the other run's image"
    for (instance_id, tag), removed_tag in zip(builds, removed):
        assert removed_tag == (tag or f"hermetic/{instance_id.lower()}:sealed")
