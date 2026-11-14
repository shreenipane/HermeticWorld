"""Exercise smoke input selection without building or starting any VM."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('name', ['boot-smoke', 'net-smoke'])
def test_smoke_preserves_patched_binary_and_requires_measured_lock(tmp_path, name):
    script = ROOT / 'scripts/integration' / (name + '.sh')
    # Stop at the first builder, before any filesystem effects. Stub only tap
    # availability so the network harness can reach the same input check.
    body = '''
source "$SCRIPT"
[() {
    if [[ $1 == -e && $2 == /sys/class/net/* ]]; then return 0; fi
    builtin [ "$@"
}
cargo() {
    test "$FC" = "$HERMETIC_FC_BIN" || exit 43
    printf '%s' reached-builder
    exit 42
}
smoke_main
'''
    env = dict(os.environ, SCRIPT=str(script), HERMETIC_SMOKE_WORK=str(tmp_path / 'work'),
               HERMETIC_FC_BIN=str(tmp_path / 'patched/firecracker'),
               HERMETIC_FIRECRACKER_LOCK=str(tmp_path / 'patched/firecracker.lock.json'))
    good = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, timeout=10)
    assert good.returncode == 42, good.stderr
    assert good.stdout == 'reached-builder'
    for missing in ['HERMETIC_FC_BIN', 'HERMETIC_FIRECRACKER_LOCK']:
        incomplete = {key: value for key, value in env.items() if key != missing}
        result = subprocess.run(['bash', '-c', body], env=incomplete,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode != 42
        assert 'reached-builder' not in result.stdout
        assert not (tmp_path / 'work').exists()
