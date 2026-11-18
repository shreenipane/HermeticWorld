"""Exercise smoke input selection without building or starting any VM."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('name', ['boot-smoke', 'net-smoke', 'multivcpu-smoke', 'snapshot-smoke', 'tsc-drift-smoke'])
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


def test_escape_smoke_builds_installs_and_runs_static_probe(tmp_path):
    script = ROOT / 'scripts/integration/boot-smoke.sh'
    home = tmp_path / 'home'
    gate = home / '.hermetic/bin/rust-gate'
    gate.parent.mkdir(parents=True)
    gate.write_text('''#!/bin/bash
set -eu
[[ $HERMETIC_ESCAPE_AGGREGATOR == */x86_64-unknown-linux-gnu/release/hermetic-escapeprobe ]]
[[ $HERMETIC_ROOTFS == "$HERMETIC_SMOKE_WORK/rootfs.img" ]]
printf 'gate %s\\n' "$*" >> "$RECORD"
''')
    gate.chmod(0o700)
    work = tmp_path / 'work'
    work.mkdir()
    record = tmp_path / 'record'
    body = '''
source "$SCRIPT"
cargo() { [[ $RUSTFLAGS == '-C target-feature=+crt-static' ]] || exit 44; printf 'cargo %s\\n' "$*" >> "$RECORD"; }
bash() { :; }
install() { printf 'install %s\\n' "$*" >> "$RECORD"; }
chmod() { :; }
find() { :; }
ls() { :; }
/usr/bin/python3() { cat >/dev/null; }
smoke_main
'''
    env = dict(os.environ, SCRIPT=str(script), HOME=str(home), RECORD=str(record),
               HERMETIC_SMOKE_WORK=str(work), HERMETIC_ESCAPE_PROBE='1',
               HERMETIC_FC_BIN='/fixed/firecracker', HERMETIC_FIRECRACKER_LOCK='/fixed/lock')
    env.pop('HERMETIC_LOCKDOWN_CONFIG', None)
    result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    calls = record.read_text().splitlines()
    assert any('cargo build' in c and '-p hermetic-escapeprobe' in c for c in calls)
    assert any('install -m 0755' in c and 'tree/sbin/hermetic-escapeprobe' in c for c in calls)
    assert any('--test guest runs_guest_escape_probe -- --ignored --nocapture' in c for c in calls)


def test_full_clock_smoke_installs_probe_config_and_selects_complete_validator(tmp_path):
    home = tmp_path / 'home'
    gate = home / '.hermetic/bin/rust-gate'
    gate.parent.mkdir(parents=True)
    gate.write_text('#!/bin/bash\nprintf "gate %s\\n" "$*" >> "$RECORD"\n')
    gate.chmod(0o700)
    work = tmp_path / 'work'
    work.mkdir()
    record = tmp_path / 'record'
    body = '''
source "$SCRIPT"
cargo() { printf 'cargo %s\\n' "$*" >> "$RECORD"; }
bash() { :; }
python3() { printf 'config %s\\n' "$*" >> "$RECORD"; }
install() { printf 'install %s\\n' "$*" >> "$RECORD"; }
chmod() { :; }
find() { :; }
ls() { :; }
/usr/bin/python3() { printf 'image %s\\n' "$*" >> "$RECORD"; cat > "$BUILD_BODY"; }
smoke_main
'''
    env = dict(os.environ, SCRIPT=str(ROOT / 'scripts/integration/boot-smoke.sh'), HOME=str(home),
        RECORD=str(record), BUILD_BODY=str(tmp_path / 'builder.py'), HERMETIC_SMOKE_WORK=str(work),
        HERMETIC_FULL_PROBE='1', HERMETIC_ESCAPE_PROBE='0', HERMETIC_LOCKDOWN_CONFIG='/sealed/.config',
        HERMETIC_KERNEL='/sealed/vmlinux', HERMETIC_FC_BIN='/fixed/firecracker', HERMETIC_FIRECRACKER_LOCK='/fixed/lock')
    result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    calls = record.read_text().splitlines()
    assert any('kernel-check-config --config /sealed/.config' in c for c in calls)
    assert any('install -m 0755' in c and 'tree/sbin/hermetic-clockprobe' in c for c in calls)
    assert any('install -m 0600 /sealed/.config' in c for c in calls)
    assert any('--test guest runs_guest_full_clock_probe -- --ignored --nocapture' in c for c in calls)
    assert any(c.startswith('image ') and '/sealed/.config /sealed/vmlinux ' in c for c in calls)
    build = (tmp_path / 'builder.py').read_text()
    assert 'kernel_lock=Path(sys.argv[6]).parent / "kernel.lock.json"' in build
    assert 'kernel_image=Path(sys.argv[7]), clockprobe_bin=Path(sys.argv[8])' in build
    for change in ({'HERMETIC_FULL_PROBE': 'bad'}, {'HERMETIC_LOCKDOWN_CONFIG': ''}, {'HERMETIC_ESCAPE_PROBE': '1'}):
        record.unlink(missing_ok=True)
        result = subprocess.run(['bash', '-c', body], env={**env, **change},
                                capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert not record.exists(), 'invalid selection must fail before building'
