"""Tests for ExtractorVM rootfs tree and image builder."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path

import pytest

from hermetic_slice import extractor

T = datetime.fromtimestamp(1700000000, timezone.utc)


def _inputs(tmp: Path) -> dict:
    (tmp / "extractor").write_bytes(b"\x7fELFextractor")
    return {"extractor_bin": tmp / "extractor", "t_clock": T}


def test_tree_layout_modes_and_mounts(tmp_path: Path) -> None:
    tree = extractor.build_extractor_tree(tmp_path / "tree", **_inputs(tmp_path))
    files = sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file())
    assert files == [
        "etc/hermetic/substrate-bound",
        "sbin/hermetic-extract-agent",
        "sbin/hermetic-extract-init",
    ]
    dirs = sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_dir())
    assert "mnt/base" in dirs
    assert "mnt/overlay" in dirs
    assert "mnt/merged" in dirs
    assert "proc" in dirs
    assert "dev" in dirs

    assert oct((tree / "sbin/hermetic-extract-init").stat().st_mode & 0o777) == "0o755"
    assert oct((tree / "sbin/hermetic-extract-agent").stat().st_mode & 0o777) == "0o755"
    assert oct((tree / "mnt/merged").stat().st_mode & 0o777) == "0o755"
    assert all(p.lstat().st_mtime == 1700000000 for p in tree.rglob("*"))
    assert not any(p.is_symlink() for p in tree.rglob("*"))


def test_optional_config_file(tmp_path: Path) -> None:
    cfg = {"task": "patch", "caps": {"max_patch_bytes": 1000}}
    tree = extractor.build_extractor_tree(
        tmp_path / "tree_cfg", **_inputs(tmp_path), extract_config=cfg
    )
    cfg_file = tree / "etc/hermetic/extract.json"
    assert cfg_file.is_file()
    assert oct(cfg_file.stat().st_mode & 0o777) == "0o444"
    assert json.loads(cfg_file.read_text()) == cfg


def test_symlinked_input_is_refused(tmp_path: Path) -> None:
    args = _inputs(tmp_path)
    os.symlink(tmp_path / "extractor", tmp_path / "link")
    args["extractor_bin"] = tmp_path / "link"
    with pytest.raises(OSError):
        extractor.build_extractor_tree(tmp_path / "tree", **args)
    assert not (tmp_path / "tree").exists()


def test_naive_or_out_of_range_clock_is_refused(tmp_path: Path) -> None:
    args = _inputs(tmp_path)
    args["t_clock"] = datetime(2023, 1, 1)
    with pytest.raises(ValueError):
        extractor.build_extractor_tree(tmp_path / "tree", **args)


def test_non_elf_binary_is_refused(tmp_path: Path) -> None:
    (tmp_path / "bad_bin").write_bytes(b"NOT_AN_ELF_BINARY")
    args = {"extractor_bin": tmp_path / "bad_bin", "t_clock": T}
    with pytest.raises(ValueError, match="ELF"):
        extractor.build_extractor_tree(tmp_path / "tree", **args)
