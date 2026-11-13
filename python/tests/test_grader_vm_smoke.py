"""Offline shell regressions for the development grader VM smoke harness."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/integration/grader-vm-smoke.sh"


def executable(path, body):
    path.write_text("#!/usr/bin/python3\n" + body)
    path.chmod(0o700)


@pytest.fixture
def smoke_environment(tmp_path):
    """Replace external builders and the VM, while running the complete script."""
    top = tmp_path / "repo"
    top.mkdir()
    fixture = top / "scripts/integration/fixtures/grader-task"
    shutil.copytree(ROOT / "scripts/integration/fixtures/grader-task", fixture)
    python = top / "python"
    python.mkdir()
    (python / "hermetic_safe_io.py").touch()
    records = python / "hermetic_grader_records"
    records.mkdir()
    for name in ("__init__", "plugin", "record", "supervisor"):
        (records / f"{name}.py").touch()
    package = python / "hermetic_slice"
    package.mkdir()
    (package / "__init__.py").touch()
    (package / "rootfs.py").write_text(
        "def build_rootfs(tree, image, **kwargs):\n"
        "    image.write_bytes(b'fixture image')\n"
        "    return {'d4': 'pass'}\n"
    )
    venv = tmp_path / "venv"
    site = venv / "lib/python3.12/site-packages"
    site.mkdir(parents=True)
    for name in ("_pytest", "pytest", "pluggy", "iniconfig", "packaging", "pygments"):
        (site / name).mkdir()
        (site / f"{name}-1.dist-info").mkdir()
    (site / "py.py").touch()
    base = tmp_path / "base"
    (base / "sbin").mkdir(parents=True)
    (base / "usr/local/lib/python3.12/site-packages").mkdir(parents=True)
    archive = tmp_path / "base.tar"
    with tarfile.open(archive, "w") as tar:
        tar.add(base, arcname=".")
    commands = tmp_path / "commands"
    commands.mkdir()
    executable(commands / "git", f"print({str(top)!r})\n")
    executable(
        commands / "docker",
        "import sys\n"
        f"from pathlib import Path\narchive = Path({str(archive)!r})\n"
        "if sys.argv[1] == 'create': print('fixture')\n"
        "elif sys.argv[1] == 'export': sys.stdout.buffer.write(archive.read_bytes())\n",
    )
    verdict_script = (
        "#!/usr/bin/python3\nimport json, sys\n"
        "empty = any('/empty/' in arg for arg in sys.argv)\n"
        "print(json.dumps({'status': 'unresolved' if empty else 'resolved', "
        "'reasons': ['f2p_failed'] if empty else []}, separators=(',', ':')))\n"
        "sys.exit(2 if empty else 0)\n"
    )
    executable(
        commands / "cargo",
        "import os, sys\nfrom pathlib import Path\n"
        "if sys.argv[1] == 'build':\n"
        "    out = Path(os.environ['CARGO_TARGET_DIR']) / 'x86_64-unknown-linux-gnu/release'\n"
        "    out.mkdir(parents=True)\n"
        "    for name in ('hermetic-sealcheck', 'hermetic-grader-supervisor', 'hermetic-grader-init'):\n"
        "        (out / name).write_text('#!/bin/sh\\nexit 0\\n')\n"
        "    verdict = out / 'hermetic-grader-verdict'\n"
        f"    verdict.write_text({verdict_script!r})\n"
        "    verdict.chmod(0o700)\n"
        "elif '--no-run' not in sys.argv:\n"
        "    Path(os.environ['HERMETIC_GRADER_RESULT_OUT']).write_bytes(bytes(1048576))\n"
        "    code = int(os.environ['FIXTURE_VM_EXIT'])\n"
        "    print('test result: FAILED' if code else 'test result: ok')\n"
        "    sys.exit(code)\n",
    )
    env = dict(os.environ, HOME=str(tmp_path), HERMETIC_VENV=str(venv),
               PATH=f"{commands}:{os.environ['PATH']}", FIXTURE_VM_EXIT="0")
    return env


def test_vm_test_failure_is_fatal_even_after_writing_result(tmp_path, smoke_environment):
    smoke_environment["FIXTURE_VM_EXIT"] = "1"
    work = tmp_path / "work"
    result = subprocess.run(["bash", str(SCRIPT), str(work)], env=smoke_environment,
                            capture_output=True, text=True, timeout=30)
    assert (work / "empty/host/R0.img").stat().st_size == 1048576
    assert result.returncode != 0, result.stdout + result.stderr
    assert "grader VM smoke: ok" not in result.stdout


def test_successful_vm_smoke_checks_both_verdicts(tmp_path, smoke_environment):
    work = tmp_path / "work"
    result = subprocess.run(["bash", str(SCRIPT), str(work)], env=smoke_environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "empty: verdict rc=2" in result.stdout
    assert "gold: verdict rc=0" in result.stdout
    assert "grader VM smoke: ok" in result.stdout
    assert stat.S_IMODE(work.stat().st_mode) == 0o700


def test_work_directory_symlink_is_refused_without_chmod(tmp_path, smoke_environment):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    work = tmp_path / "work"
    work.symlink_to(target, target_is_directory=True)
    result = subprocess.run(["bash", str(SCRIPT), str(work)], env=smoke_environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert not list(target.iterdir())
