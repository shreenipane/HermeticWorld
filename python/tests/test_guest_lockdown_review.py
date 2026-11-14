"""Security boundary regressions from the guest lockdown review."""
import io
from pathlib import Path
import subprocess

import pytest

from hermetic_slice import firecracker_build as f
from hermetic_slice import guest_kernel as k


def test_invalid_deflate_is_a_controlled_archive_error():
    # Valid gzip header followed by a reserved DEFLATE block type.
    archive = bytes.fromhex('1f8b080000000000000306000000000000000000')
    with pytest.raises(k.KernelError, match='invalid source archive'):
        f.source_files(archive)


@pytest.mark.parametrize('failure', ['timeout', 'read_error'])
def test_resolver_cleanup_never_enters_unbounded_context_wait(tmp_path, monkeypatch, failure):
    resolver = tmp_path / 'resolver'
    resolver.write_bytes(b'fixture')
    resolver.chmod(0o700)
    waits = []
    kills = []
    pipe = io.BytesIO()

    class Process:
        pid = 1234
        stdout = pipe

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pytest.fail('Popen context cleanup waits without a deadline')

        def wait(self, timeout):
            waits.append(timeout)
            raise subprocess.TimeoutExpired('resolver', timeout)

    class Selector:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def register(self, *args):
            pass

        def select(self, timeout):
            if failure == 'read_error':
                raise OSError('secret-host')
            return []

    monkeypatch.setattr(k.subprocess, 'Popen', lambda *args, **kwargs: Process())
    monkeypatch.setattr(k.selectors, 'DefaultSelector', Selector)
    monkeypatch.setattr(k.os, 'killpg', lambda pid, sig: kills.append(pid))
    with pytest.raises(k.KernelError) as error:
        k.boot_arguments(0, vmm=resolver)
    assert 'secret-host' not in str(error.value)
    assert kills == [1234]
    assert waits == [k.TSC_RESOLVE_TIMEOUT_S]
    assert pipe.closed


def test_gate_logs_are_absent_and_all_log_names_are_ignored():
    root = Path(__file__).resolve().parents[2]
    for name in ['.continuation-mutation.log', '.rust-gate.log']:
        assert not (root / name).exists()
    result = subprocess.run(
        ['git', 'check-ignore', '--no-index', '--stdin'], cwd=root,
        input='review.log\n.rust-gate.log\nsubdir/gate.log\n',
        capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0
    assert result.stdout.splitlines() == ['review.log', '.rust-gate.log', 'subdir/gate.log']
