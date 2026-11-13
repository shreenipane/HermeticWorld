"""Offline shell regressions for the development grader VM smoke harness."""

import json
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
    shutil.copyfile(SCRIPT, top / "scripts/integration/grader-vm-smoke.sh")
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
        "    image.with_suffix('.run.json').write_bytes((tree / 'etc/hermetic/grader/run.json').read_bytes())\n"
        "    image.with_suffix('.calc.py').write_bytes((tree / 'work/repo/calc.py').read_bytes())\n"
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
    extraction_script = (
        "#!/usr/bin/python3\nimport sys, shutil\nfrom pathlib import Path\n"
        "args = dict(zip(sys.argv[1::2], sys.argv[2::2]))\n"
        "if '--work' in args:\n"
        "    Path(args['--out']).write_text(args['--work'])\n"
        "    Path(args['--report']).write_text('{}')\n"
        "else:\n"
        "    shutil.copytree(Path(args['--stream']).read_text(), args['--out'])\n"
    )
    executable(
        commands / "cargo",
        "import os, sys\nfrom pathlib import Path\n"
        "if sys.argv[1] == 'build':\n"
        "    out = Path(os.environ['CARGO_TARGET_DIR']) / 'x86_64-unknown-linux-gnu/release'\n"
        "    out.mkdir(parents=True, exist_ok=True)\n"
        "    if 'hermetic-extract-agent' in sys.argv:\n"
        "        host = Path(os.environ['CARGO_TARGET_DIR']) / 'release'\n"
        "        host.mkdir(parents=True, exist_ok=True)\n"
        "        for name in ('hermetic-extract-agent', 'hermetic-extract-validate'):\n"
        f"            (host / name).write_text({extraction_script!r})\n"
        "            (host / name).chmod(0o700)\n"
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


def test_vm_configs_apply_the_sealed_runner_without_a_shell_bridge(tmp_path, smoke_environment):
    work = tmp_path / "work"
    result = subprocess.run(["bash", str(SCRIPT), str(work)], env=smoke_environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    for variant in ("empty", "gold"):
        for run in ("R0", "R1", "R2"):
            config = json.loads((work / variant / run / "img/grader.run.json").read_text())
            assert config["argv"] == ["/usr/local/bin/python3.12", "-s", "-m", "pytest",
                                      "-p", "no:cacheprovider", "-q",
                                      "tests/test_calc.py::test_add", "tests/test_calc.py::test_double"]
            assert config["env"] == {}
            assert config["sandbox"] == {"t_clock": 1700000000, "required_pytest_plugins": []}
            assert config["run"] == run


def test_full_smoke_keeps_validated_extraction_and_uses_vm_clock(tmp_path, smoke_environment):
    work = tmp_path / "full"
    result = subprocess.run(["bash", str(ROOT / "scripts/integration/grader-smoke.sh"), str(work)],
                            env=smoke_environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "validated extraction" in result.stdout
    for variant in ("empty", "gold"):
        published = (work / "published" / variant / "calc.py").read_bytes()
        assert published == (work / variant / "work/calc.py").read_bytes()
        assert (work / variant / "changes.hext").is_file()
        for run in ("R0", "R1", "R2"):
            assert (work / "vm" / variant / run / "img/grader.calc.py").read_bytes() == published
            config = json.loads((work / "vm" / variant / run / "img/grader.run.json").read_text())
            assert config["sandbox"]["t_clock"] == 1700000000
    assert (work / "published/empty/calc.py").read_bytes() != (work / "published/gold/calc.py").read_bytes()


def test_boot_notes_describe_the_booted_grader_and_current_fd_transport():
    notes = (ROOT / "scripts/integration/BOOT_NOTES.md").read_text()
    assert "Why the grader VM is not booted" not in notes
    assert "There is no grader-mode PID 1" not in notes
    assert "dedicated fd 3" in notes
    assert "bash scripts/integration/grader-vm-smoke.sh" in notes
