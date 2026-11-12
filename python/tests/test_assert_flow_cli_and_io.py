"""Tests for CLI output, determinism, host-leak prevention, symlink/FIFO refusal, and atomic writes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hermetic_assert_flow.cli import run_cli
from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.io_utils import atomic_write_bytes, read_regular_file_bounded


def test_cli_outputs_deterministic_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    test_file = tmp_path / "sample_test.py"
    test_file.write_bytes(
        b"""
def test_cli_case():
    x = boom()
    assert x == 1
    y = x + 2
    assert y == 3
    assert 10 == 10
"""
    )

    rc = run_cli(
        [
            "--file",
            str(test_file),
            "--function",
            "test_cli_case",
            "--raising-line",
            "3",
            "--reached",
            "test_cli_case#0",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    data = json.loads(captured.out)
    assert data == {
        "eligible": ["test_cli_case#0", "test_cli_case#1"],
        "gave_up": False,
        "reason": None,
    }
    # Verify exact key ordering and no host path leakage.
    assert captured.out.strip() == (
        '{"eligible": ["test_cli_case#0", "test_cli_case#1"], "gave_up": false, "reason": null}'
    )
    assert str(tmp_path) not in captured.out


def test_cli_subprocess_determinism_across_hash_seeds(tmp_path: Path) -> None:
    test_file = tmp_path / "det_test.py"
    test_file.write_bytes(
        b"""
def test_seed(flag):
    a = boom()
    if flag:
        b = a
    else:
        c = a
    assert a == 1
    assert b == 1
    assert c == 1
"""
    )

    outputs: list[bytes] = []
    for seed in ("0", "1", "42", "999999"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "hermetic_assert_flow",
                "--file",
                str(test_file),
                "--function",
                "test_seed",
                "--raising-line",
                "3",
                "--reached",
                "test_seed#0",
            ],
            capture_output=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 0
        assert proc.stderr == b""
        outputs.append(proc.stdout)

    assert len(set(outputs)) == 1


def test_refuses_symlinks_when_opening_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real_file = tmp_path / "real.py"
    real_file.write_bytes(b"def test_x():\n    assert True\n")
    link_file = tmp_path / "link.py"
    os.symlink(real_file, link_file)

    with pytest.raises(FlowError) as exc_info:
        read_regular_file_bounded(link_file)
    assert exc_info.value.code == "OPEN_ERROR"

    rc = run_cli(
        [
            "--file",
            str(link_file),
            "--function",
            "test_x",
            "--raising-line",
            "2",
        ]
    )
    assert rc == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    # Ensure host path is never leaked in stderr error output.
    assert str(link_file) not in captured.stderr
    assert str(real_file) not in captured.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO not supported on this platform")
def test_refuses_fifo_special_file(tmp_path: Path) -> None:
    fifo_path = tmp_path / "named_pipe.py"
    os.mkfifo(fifo_path)

    with pytest.raises(FlowError) as exc_info:
        read_regular_file_bounded(fifo_path)
    assert exc_info.value.code in {"NOT_REGULAR_FILE", "OPEN_ERROR"}


def test_atomic_write_bytes_creates_file_and_refuses_symlink_target(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    payload = b'{"eligible":[],"gave_up":false,"reason":null}\n'
    atomic_write_bytes(target, payload)
    assert target.read_bytes() == payload
    # Ensure no leftover temp files remain in the directory.
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]

    link_target = tmp_path / "out_link.json"
    os.symlink(target, link_target)
    with pytest.raises(FlowError) as exc_info:
        atomic_write_bytes(link_target, payload)
    assert exc_info.value.code == "UNSAFE_DESTINATION"
