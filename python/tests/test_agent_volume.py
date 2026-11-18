"""Tests for deterministic Mode G /opt/agent volume builder (TR-GW-*, §9.3)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import pytest

from hermetic_slice import agent_volume
from tests.test_rootfs import (
    SEALCHECK_BIN,
    requires_sealcheck,
)

T = datetime.fromtimestamp(1700000000, timezone.utc)


@pytest.fixture(autouse=True)
def _sealcheck_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    if SEALCHECK_BIN is not None:
        tools = tmp_path / "sealcheck-tools"
        tools.mkdir(mode=0o700)
        binary = tools / "hermetic-sealcheck"
        shutil.copyfile(SEALCHECK_BIN, binary)
        binary.chmod(0o755)
        monkeypatch.setenv("HERMETIC_SEALCHECK_BIN", str(binary))
    else:
        monkeypatch.delenv("HERMETIC_SEALCHECK_BIN", raising=False)


def test_build_agent_volume_tree_from_files(tmp_path: Path) -> None:
    tree_dir = tmp_path / "tree"
    files = {
        "run": b"#!/bin/bash\necho ok\n",
        "bin/agent": (b"\x7fELFagent", 0o755),
        "data/config.json": b'{"mode": "g"}',
    }
    tree = agent_volume.build_agent_volume_tree(tree_dir, files=files, t_clock=T)
    assert tree == tree_dir
    assert tree.is_dir()

    run_file = tree / "run"
    assert run_file.read_bytes() == b"#!/bin/bash\necho ok\n"
    assert oct(run_file.stat().st_mode & 0o777) == "0o755"
    assert run_file.stat().st_mtime == 1700000000

    agent_bin = tree / "bin/agent"
    assert agent_bin.read_bytes() == b"\x7fELFagent"
    assert oct(agent_bin.stat().st_mode & 0o777) == "0o755"
    assert agent_bin.stat().st_mtime == 1700000000

    cfg = tree / "data/config.json"
    assert cfg.read_bytes() == b'{"mode": "g"}'
    assert oct(cfg.stat().st_mode & 0o777) == "0o644"
    assert cfg.stat().st_mtime == 1700000000

    assert oct((tree / "bin").stat().st_mode & 0o777) == "0o755"
    assert (tree / "bin").stat().st_mtime == 1700000000
    assert oct((tree / "data").stat().st_mode & 0o777) == "0o755"
    assert (tree / "data").stat().st_mtime == 1700000000


def test_build_agent_volume_tree_from_source_dir(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "bin").mkdir()
    script = src_dir / "bin/runner.sh"
    script.write_bytes(b"#!/bin/sh\nexit 0\n")
    os.chmod(script, 0o755)

    data = src_dir / "weights.bin"
    data.write_bytes(b"DATA123")
    os.chmod(data, 0o644)

    tree_dir = tmp_path / "tree"
    tree = agent_volume.build_agent_volume_tree(tree_dir, source_dir=src_dir, t_clock=T)
    assert (tree / "bin/runner.sh").read_bytes() == b"#!/bin/sh\nexit 0\n"
    assert oct((tree / "bin/runner.sh").stat().st_mode & 0o777) == "0o755"
    assert (tree / "bin/runner.sh").stat().st_mtime == 1700000000

    assert (tree / "weights.bin").read_bytes() == b"DATA123"
    assert oct((tree / "weights.bin").stat().st_mode & 0o777) == "0o644"
    assert (tree / "weights.bin").stat().st_mtime == 1700000000


def test_symlinks_in_source_dir_refused(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    target = src_dir / "file.txt"
    target.write_bytes(b"secret")
    os.symlink(target, src_dir / "symlink.txt")

    with pytest.raises(ValueError, match="Symlinks in agent volume are refused"):
        agent_volume.build_agent_volume_tree(tmp_path / "tree", source_dir=src_dir, t_clock=T)
    assert not (tmp_path / "tree").exists()


def test_special_files_in_source_dir_refused(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    fifo = src_dir / "fifo"
    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="Special files in agent volume are refused"):
        agent_volume.build_agent_volume_tree(tmp_path / "tree", source_dir=src_dir, t_clock=T)
    assert not (tmp_path / "tree").exists()


@pytest.mark.parametrize("bad_path", ["/abs/path", "../escape", "a/../../b", "a/\0/b", "", "dir/"])
def test_invalid_relative_paths_refused(tmp_path: Path, bad_path: str) -> None:
    with pytest.raises(ValueError):
        agent_volume.build_agent_volume_tree(tmp_path / "tree", files={bad_path: b"payload"}, t_clock=T)
    assert not (tmp_path / "tree").exists()


def test_existing_tree_destination_refused(tmp_path: Path) -> None:
    tree_dir = tmp_path / "tree"
    tree_dir.mkdir()
    with pytest.raises(FileExistsError):
        agent_volume.build_agent_volume_tree(tree_dir, files={"run": b"echo ok"}, t_clock=T)


def test_naive_or_out_of_range_clock_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        agent_volume.build_agent_volume_tree(tmp_path / "tree", files={"run": b"echo ok"}, t_clock=datetime(2023, 1, 1))

    with pytest.raises(ValueError):
        agent_volume.build_agent_volume_tree(
            tmp_path / "tree", files={"run": b"echo ok"}, t_clock=datetime.fromtimestamp(100, timezone.utc)
        )


@requires_sealcheck
def test_agent_volume_image_reproducibility_and_d4(tmp_path: Path) -> None:
    files = {
        "run": b"#!/bin/bash\nsed -i 's/a - b/a + b/' /testbed/calc.py\n",
        "bin/helper": (b"#!/bin/sh\nexit 0\n", 0o755),
    }

    tree1 = tmp_path / "tree1"
    img1 = tmp_path / "agent1.img"
    res1 = agent_volume.build_agent_volume_image(
        tree=tree1,
        out_image=img1,
        files=files,
        t_clock=T,
        world_id="test-world-g",
        size_mib=16,
    )

    tree2 = tmp_path / "tree2"
    img2 = tmp_path / "agent2.img"
    res2 = agent_volume.build_agent_volume_image(
        tree=tree2,
        out_image=img2,
        files=files,
        t_clock=T,
        world_id="test-world-g",
        size_mib=16,
    )

    assert res1["d4"] == "pass"
    assert res2["d4"] == "pass"
    assert res1["sha256"] == res2["sha256"]
    assert res1["agent_volume_digest"] == res2["agent_volume_digest"]
    assert res1["agent_volume_digest"].startswith("sha256:")
    assert img1.read_bytes() == img2.read_bytes()


def test_replace_existing_file_accounts_for_volume_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_volume, "MAX_AGENT_FILES", 2)
    monkeypatch.setattr(agent_volume, "MAX_AGENT_VOLUME_BYTES", 100)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "weights.bin").write_bytes(b"A" * 60)
    (src_dir / "config.json").write_bytes(b"B" * 20)

    tree_dir = tmp_path / "tree"
    # Replacing weights.bin with 70 bytes:
    # Net bytes: 20 + 70 = 90 <= 100.
    # Total files: 2 <= 2 (at cap).
    # Replacement must succeed.
    tree = agent_volume.build_agent_volume_tree(
        tree_dir,
        source_dir=src_dir,
        files={"weights.bin": b"C" * 70},
        t_clock=T,
    )
    assert (tree / "weights.bin").read_bytes() == b"C" * 70

    # A new entry when already at MAX_AGENT_FILES must be rejected
    tree_dir2 = tmp_path / "tree2"
    with pytest.raises(ValueError, match="Agent volume entries exceed cap"):
        agent_volume.build_agent_volume_tree(
            tree_dir2,
            source_dir=src_dir,
            files={"extra.txt": b"D"},
            t_clock=T,
        )

    # Replacing with a payload that exceeds volume cap after subtraction must be rejected
    tree_dir3 = tmp_path / "tree3"
    with pytest.raises(ValueError, match="Total agent volume bytes exceed cap"):
        agent_volume.build_agent_volume_tree(
            tree_dir3,
            source_dir=src_dir,
            files={"weights.bin": b"E" * 85},  # 20 + 85 = 105 > 100
            t_clock=T,
        )


def test_collect_source_dir_pins_subdirectories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    sub_dir = src_dir / "sub"
    sub_dir.mkdir()
    (sub_dir / "inside.txt").write_bytes(b"inside data")

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_sub = outside_dir / "sub"
    outside_sub.mkdir()
    (outside_sub / "secret.txt").write_bytes(b"host secret")

    real_scandir = os.scandir
    call_count = [0]
    in_hook = [False]

    def swapping_scandir(arg, *args, **kwargs):
        if in_hook[0]:
            return real_scandir(arg, *args, **kwargs)
        call_count[0] += 1
        if call_count[0] == 2:
            in_hook[0] = True
            try:
                os.rename(sub_dir, tmp_path / "sub_saved")
                os.symlink(outside_sub, sub_dir)
            finally:
                in_hook[0] = False
        return real_scandir(arg, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", swapping_scandir)
    collected = agent_volume._collect_source_dir(src_dir)
    monkeypatch.undo()

    assert call_count[0] == 2, f"expected 2 scandir calls, got {call_count[0]}"
    assert "sub/inside.txt" in collected
    assert collected["sub/inside.txt"][0] == b"inside data"
    assert "sub/secret.txt" not in collected

