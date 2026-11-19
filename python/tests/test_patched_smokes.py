"""Exercise smoke input selection without building or starting any VM."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('name', ['boot-smoke', 'net-smoke', 'multivcpu-smoke', 'snapshot-smoke', 'tsc-drift-smoke', 'd7-smoke'])
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


def test_cli_run_smoke_builds_trust_and_exports_hermetic_trust_bin(tmp_path):
    script = ROOT / 'scripts/integration/cli-run-smoke.sh'
    content = script.read_text()
    assert '-p hermetic-trust' in content
    assert 'HERMETIC_TRUST_BIN' in content
    work = tmp_path / 'work'
    work.mkdir()
    record = tmp_path / 'record'
    body = '''
set -e
cargo() { printf 'cargo %s\\n' "$*" >> "$RECORD"; }
install() { printf 'install %s\\n' "$*" >> "$RECORD"; }
mkdir() { :; }
cat() { :; }
chmod() { :; }
readlink() { printf '%s' "$1"; }
bash() { printf 'bash %s\\n' "$*" >> "$RECORD"; }
export -f cargo install readlink bash
eval "$(sed -n '/# 2\\. Build release/,/export HERMETIC_TRUST_BIN/p' "$SCRIPT")"
printf 'TRUST_BIN=%s\\n' "$HERMETIC_TRUST_BIN" >> "$RECORD"
'''
    env = dict(os.environ, SCRIPT=str(script), RECORD=str(record), WORK=str(work),
               HOME=str(tmp_path / 'home'), top=str(ROOT))
    result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    calls = record.read_text().splitlines()
    assert any('cargo build' in c and '-p hermetic-trust' in c for c in calls)
    assert any('install -m 0700' in c and 'release/hermetic-trust' in c and f'{work}/trust' in c for c in calls)
    assert any('bash scripts/build-trusted-execd.sh' in c for c in calls)
    assert any(c == f'TRUST_BIN={work}/trust' for c in calls)


def test_cli_run_smoke_eval_failure_terminates_shell(tmp_path):
    work = tmp_path / 'work'
    work.mkdir()
    record = tmp_path / 'record'
    script = ROOT / 'scripts/integration/cli-run-smoke.sh'
    # Fail during cargo build inside the extracted fragment; ensure subsequent
    # fragment commands (bash, install, export) and trailing printf do not run under errexit.
    body = '''
set -e
cargo() { printf 'cargo failed\\n' >> "$RECORD"; return 1; }
install() { printf 'install %s\\n' "$*" >> "$RECORD"; }
mkdir() { :; }
cat() { :; }
chmod() { :; }
readlink() { printf '%s' "$1"; }
bash() { printf 'bash %s\\n' "$*" >> "$RECORD"; }
export -f cargo install readlink bash
eval "$(sed -n '/# 2\\. Build release/,/export HERMETIC_TRUST_BIN/p' "$SCRIPT")"
printf 'UNREACHED\\n' >> "$RECORD"
'''
    env = dict(os.environ, SCRIPT=str(script), RECORD=str(record), WORK=str(work),
               HOME=str(tmp_path / 'home'), top=str(ROOT))
    result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    lines = record.read_text().splitlines()
    assert 'cargo failed' in lines
    assert 'UNREACHED' not in lines
    assert not any('install' in line for line in lines)
    assert not any('bash' in line for line in lines)


def test_cli_run_smoke_structure_and_no_fabricated_artifacts():
    script = ROOT / 'scripts/integration/cli-run-smoke.sh'
    content = script.read_text()

    # 1. No fabricated run artifacts written by smoke script before run
    assert 'gold.patch" "$RUN_DIR/submitted_work.patch"' not in content
    assert 'cat > "$RUN_DIR/date_sentinel.json"' not in content
    assert 'cat > "$RUN_DIR/harness_summary.json"' not in content
    assert 'cat > "$RUN_DIR/boot_record.json"' not in content
    assert 'cat > "$RUN_DIR/probe_output.jsonl"' not in content

    # 2. Uses HERMETIC_RUN_DIR directly
    assert 'HERMETIC_RUN_DIR="$RUN_DIR"' in content

    # 3. Real package record and substrate fixtures from existing components
    assert 'from hermetic_pkgrec.freeze import freeze_world' in content
    assert 'hermetic-sealer-substrate-request/v1' in content  # sealer inventories its own staged rootfs
    assert '--packages-record "$PACKAGES_RECORD"' in content
    assert '--substrate "$SUBSTRATE_FILE"' in content

    # 4. Mode H fixture agent volume
    assert 'from hermetic_slice.agent_volume import build_agent_volume_image' in content
    assert 'export HERMETIC_AGENT_VOLUME=' in content
    assert '--agent-mode H' in content

    # 5. Asserts VM-produced evidence
    assert '$CLI" verify' in content
    assert 'submitted_work_digest' in content
    assert 'agent_volume_digest' in content
    assert 'probe_output.jsonl' in content
    assert 'date_sentinel.json' in content

