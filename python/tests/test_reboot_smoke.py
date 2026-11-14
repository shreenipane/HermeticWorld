"""Offline lifetime regression for the nested first-boot smoke artifacts."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("boot_exit", [0, 17])
def test_reboot_keeps_first_boot_image_until_reboot_finishes(tmp_path, boot_exit):
    top = tmp_path / "repo"
    scripts = top / "scripts/integration"
    scripts.mkdir(parents=True)
    for name in ("reboot-smoke.sh", "smoke_work.py"):
        shutil.copyfile(ROOT / "scripts/integration" / name, scripts / name)
    python = top / "python"
    python.mkdir()
    shutil.copyfile(ROOT / "python/hermetic_safe_io.py", python / "hermetic_safe_io.py")
    package = python / "hermetic_slice"
    package.mkdir()
    (package / "__init__.py").touch()
    (package / "initramfs.py").write_text(
        "from pathlib import Path\n"
        "def build_initramfs(execd, early, output, clock):\n"
        "    assert Path(output).with_name('first').joinpath('rootfs.img').read_bytes() == b'sealed'\n"
        "    Path(output).write_bytes(b'trusted')\n"
        "    return '0' * 64\n"
    )
    # Exercise the real cleanup wrapper used by boot-smoke, replacing only its
    # expensive build/VM body. Standalone success must still remove its image.
    boot = scripts / "boot-smoke.sh"
    boot.write_text(
        'smoke_main() {\n'
        '  printf sealed > "$HERMETIC_SMOKE_WORK/rootfs.img"\n'
        f'  return {boot_exit}\n'
        '}\n'
        'if [ "${BASH_SOURCE[0]}" = "$0" ]; then\n'
        '  exec /usr/bin/python3 -I "$(dirname "$0")/smoke_work.py" "$0" "$@"\n'
        'fi\n'
    )
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "git").write_text(f'#!/bin/sh\nprintf "%s\\n" "{top}"\n')
    (commands / "cargo").write_text(
        '#!/usr/bin/python3\n'
        'import os\nfrom pathlib import Path\n'
        "assert Path(os.environ['HERMETIC_ROOTFS']).read_bytes() == b'sealed'\n"
        "assert Path(os.environ['HERMETIC_INITRD']).read_bytes() == b'trusted'\n"
        "Path(os.environ['HERMETIC_REBOOT_RECORD_OUT']).write_text('reboot complete')\n"
    )
    for command in commands.iterdir():
        command.chmod(0o700)
    env = dict(os.environ, HOME=str(tmp_path),
               PATH=f"{commands}:{os.environ['PATH']}", PYTHONDONTWRITEBYTECODE="1")
    standalone = tmp_path / "standalone"
    result = subprocess.run(["bash", str(boot), str(standalone)], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == boot_exit, result.stderr
    assert standalone.exists() == bool(boot_exit)
    work = tmp_path / "reboot"
    result = subprocess.run(["bash", str(scripts / "reboot-smoke.sh"), str(work)],
                            cwd=top, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == boot_exit, result.stdout + result.stderr
    if boot_exit:
        assert not (work / "trusted.cpio").exists()
        assert not (work / "reboot-record.json").exists()
    else:
        assert (work / "first/rootfs.img").read_bytes() == b"sealed"
        assert (work / "reboot-record.json").read_text() == "reboot complete"
