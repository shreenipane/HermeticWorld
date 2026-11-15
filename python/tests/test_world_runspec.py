"""The derived run spec is applied to the container-mode agent (Phase 2)."""

from __future__ import annotations

import copy

import pytest

import hermetic_slice.world as world_mod
from hermetic_slice.world import runspec_docker_args

SPEC = {
    "env": [["HOME", "/home/agent"], ["PATH", "/usr/bin:/bin"]],
    "cwd": "/testbed",
    "uid": 1000,
    "gid": 1000,
    "supplementary_gids": [27, 4, 27],
    "entrypoint": [],
    "cmd": ["/bin/bash"],
    "resources": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 8192},
    "hostname": "sandbox",
    "resolv_conf": "nameserver 10.0.0.53\noptions ndots:0\n",
}


def test_run_spec_maps_to_hardened_docker_flags() -> None:
    args = runspec_docker_args(SPEC)
    pairs = {args[i]: args[i + 1] for i in range(0, len(args) - 1) if args[i].startswith("--")}
    assert pairs["--user"] == "1000:1000"
    assert pairs["--workdir"] == "/testbed"
    assert pairs["--hostname"] == "sandbox"
    assert pairs["--dns"] == "10.0.0.53"
    assert pairs["--cpus"] == "2" and pairs["--memory"] == "4096m"
    assert pairs["--cap-drop"] == "ALL" and pairs["--security-opt"] == "no-new-privileges"
    assert [args[i + 1] for i, a in enumerate(args) if a == "--group-add"] == ["4", "27"]
    assert [args[i + 1] for i, a in enumerate(args) if a == "-e"] == ["HOME=/home/agent", "PATH=/usr/bin:/bin"]
    assert runspec_docker_args(copy.deepcopy(SPEC)) == args  # deterministic


@pytest.mark.parametrize("change", [
    {"uid": -1}, {"uid": "0"}, {"gid": 2**32}, {"cwd": "relative"}, {"cwd": "/a\0b"},
    {"hostname": "bad host"}, {"hostname": "-x"}, {"resolv_conf": "nameserver evil\n"},
    {"resources": {"vcpus": 0, "memory_mib": 4096, "disk_mib": 1}},
    {"resources": {"vcpus": 2, "memory_mib": 4096}},
    {"env": [["PIP_INDEX_URL", "http://attacker/"]]}, {"env": [["BAD NAME", "x"]]},
    {"env": [["A", "b\0c"]]}, {"supplementary_gids": ["x"]}, {"extra": 1},
])
def test_invalid_run_specs_are_refused(change: dict) -> None:
    spec = dict(copy.deepcopy(SPEC), **change)
    with pytest.raises(ValueError):
        runspec_docker_args(spec)


def test_start_world_applies_the_run_spec_to_the_agent_only(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_run_docker(args, check=True, **kwargs):
        calls.append(list(args))

        class Result:
            stdout = ""
            returncode = 0
        return Result()

    monkeypatch.setattr(world_mod, "run_docker", fake_run_docker)
    world_mod.start_world({}, "img", tmp_path, name="w", runspec=SPEC)
    runs = [c for c in calls if c[:1] == ["run"]]
    index_run, agent_run = runs
    assert "--user" not in index_run
    flags = runspec_docker_args(SPEC)
    start = agent_run.index(flags[0])
    assert agent_run[start:start + len(flags)] == flags
    assert agent_run[agent_run.index("--entrypoint") + 1] == "/bin/bash"

    calls.clear()
    world_mod.start_world({}, "img", tmp_path, name="w2")
    assert "--user" not in [c for c in calls if c[:1] == ["run"]][1]
