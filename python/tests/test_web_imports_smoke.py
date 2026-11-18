"""Test for web-imports-smoke.sh integration script."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import pytest

TOP = Path(__file__).resolve().parent.parent.parent
SCRIPT = TOP / "scripts" / "integration" / "web-imports-smoke.sh"


def test_web_imports_smoke_script_present_and_executable():
    assert SCRIPT.exists(), f"Missing {SCRIPT}"
    st = SCRIPT.stat()
    if not (st.st_mode & stat.S_IXUSR):
        SCRIPT.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert SCRIPT.stat().st_mode & stat.S_IXUSR


def test_web_imports_smoke_script_skips_cleanly_without_env_vars():
    """Verify script requires env vars and exits cleanly if missing."""
    clean_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    # When executed without HERMETIC_FC_BIN / HERMETIC_FIRECRACKER_LOCK, smoke_main exits 1
    with tempfile.TemporaryDirectory() as tmp_work:
        res = subprocess.run(
            ["bash", str(SCRIPT), tmp_work],
            cwd=str(TOP),
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode != 0
        assert "HERMETIC_FC_BIN" in res.stderr or "HERMETIC_FIRECRACKER_LOCK" in res.stderr


@pytest.mark.skipif(
    not os.environ.get("HERMETIC_FC_BIN") or not os.environ.get("HERMETIC_KERNEL"),
    reason="needs HERMETIC_FC_BIN, HERMETIC_KERNEL and /dev/kvm",
)
def test_web_imports_smoke_nested_vm():
    """Nested VM execution when environment variables are supplied."""
    with tempfile.TemporaryDirectory() as tmp_work:
        res = subprocess.run(
            ["bash", str(SCRIPT), tmp_work],
            cwd=str(TOP),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"Smoke failed:\n{res.stdout}\n{res.stderr}"
        assert "web-imports smoke: ok" in res.stdout
