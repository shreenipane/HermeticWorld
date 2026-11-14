"""Offline archive, reproducibility, publication and build-policy regressions."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile

import pytest
from hermetic_slice import firecracker_build as f
from hermetic_slice import guest_kernel as k


def tar_bytes(extra=None):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz', format=tarfile.USTAR_FORMAT) as tar:
        for name, content in [('Cargo.lock', b'pinned'), ('rust-toolchain.toml', b'1.97.0')]:
            member = tarfile.TarInfo('firecracker-1.18.0/' + name)
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
        if extra is not None:
            tar.addfile(extra, io.BytesIO(b'x' * extra.size))
    return data.getvalue()


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    patches = root / 'vmm/firecracker-patches'
    patches.mkdir(parents=True)
    patch = b'pinned patch\n'
    (patches / f.PATCH).write_bytes(patch)
    archive = tar_bytes()
    tarball = tmp_path / 'source.tar.gz'
    tarball.write_bytes(archive)
    (root / 'vmm/firecracker.lock.json').write_text(json.dumps(dict(
        version='1.18.0', source_sha256=hashlib.sha256(archive).hexdigest(),
        patch_sha256=hashlib.sha256(patch).hexdigest())))
    monkeypatch.setattr(f, 'ROOT', root)
    return tarball, 'sha256:' + 'a' * 64, tmp_path / 'result'


def fake_runner(argv):
    output = Path(next(arg for arg in argv if arg.endswith(':/outputs:rw')).removesuffix(':/outputs:rw'))
    (output / 'firecracker').write_bytes(b'patched-vmm')
    (output / 'jailer').write_bytes(b'patched-jailer')


def test_double_build_and_pinned_lock_are_published_privately(inputs):
    f.build(*inputs, runner=fake_runner)
    result = inputs[2]
    assert sorted(p.name for p in result.iterdir()) == ['firecracker', 'firecracker.lock.json', 'jailer']
    record = json.loads((result / 'firecracker.lock.json').read_bytes())
    assert record['firecracker_sha256'] == hashlib.sha256(b'patched-vmm').hexdigest()
    assert record['jailer_sha256'] == hashlib.sha256(b'patched-jailer').hexdigest()
    assert record['schema'] == 'hermetic-firecracker-build/v1'
    assert (result / 'firecracker').stat().st_mode & 0o777 == 0o500
    assert (result / 'firecracker.lock.json').stat().st_mode & 0o777 == 0o600
    with pytest.raises(k.KernelError):
        f.build(*inputs, runner=lambda _: pytest.fail('existing output touched'))


def test_hash_and_builder_validation_precede_artifacts(inputs):
    tarball, image, output = inputs
    for args in [(tarball, 'mutable:latest', output)]:
        with pytest.raises(k.KernelError):
            f.build(*args, runner=lambda _: pytest.fail('invalid build started'))
    tarball.write_bytes(b'hostile tar')
    with pytest.raises(k.KernelError):
        f.build(*inputs, runner=lambda _: pytest.fail('bad hash build started'))
    assert not output.exists()
    assert not list(output.parent.glob('.fc-build-*'))


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'device', 'escape', 'duplicate', 'parent'])
def test_archive_rejects_special_files_and_escaping_or_ambiguous_paths(kind):
    member = tarfile.TarInfo('firecracker-1.18.0/extra')
    if kind == 'symlink':
        member.type = tarfile.SYMTYPE
        member.linkname = '/host/secret'
    elif kind == 'fifo':
        member.type = tarfile.FIFOTYPE
    elif kind == 'device':
        member.type = tarfile.CHRTYPE
    elif kind == 'escape':
        member.name = 'firecracker-1.18.0/../../escape'
    elif kind == 'duplicate':
        member.name = 'firecracker-1.18.0/Cargo.lock'
    else:
        member.name = 'firecracker-1.18.0/Cargo.lock/child'
    with pytest.raises(k.KernelError):
        f.source_files(tar_bytes(member))


def test_nonreproducible_or_symlink_outputs_are_never_published(inputs):
    count = 0
    def changing(argv):
        nonlocal count
        count += 1
        fake_runner(argv)
        output = Path(next(arg for arg in argv if arg.endswith(':/outputs:rw')).removesuffix(':/outputs:rw'))
        (output / 'firecracker').write_bytes(str(count).encode())
    with pytest.raises(k.KernelError):
        f.build(*inputs, runner=changing)
    assert not inputs[2].exists()
    def symlink(argv):
        fake_runner(argv)
        output = Path(next(arg for arg in argv if arg.endswith(':/outputs:rw')).removesuffix(':/outputs:rw'))
        (output / 'firecracker').unlink()
        (output / 'firecracker').symlink_to('/etc/passwd')
    with pytest.raises(k.KernelError):
        f.build(*inputs, runner=symlink)
    assert not inputs[2].exists()


def test_build_commands_are_offline_pinned_bounded_and_test_the_filter():
    args = f.docker_arguments('sha256:' + 'a' * 64, Path('/work'))
    for arg in ['--pull=never', '--network=none', '--read-only', '--memory=4g', '--pids-limit=512']:
        assert arg in args
    assert '--locked --offline' in args[-1]
    assert 'test --locked --offline -p vmm --lib clock_filter::tests' in args[-1]
    assert 'patch --batch --fuzz=0 -p1' in args[-1]
    assert 'SOURCE_DATE_EPOCH=1794182400' in args


def test_source_and_entry_caps_are_enforced(monkeypatch):
    monkeypatch.setattr(f, 'MAX_SOURCE_ENTRIES', 1)
    with pytest.raises(k.KernelError):
        f.source_files(tar_bytes())
    monkeypatch.setattr(f, 'MAX_SOURCE_ENTRIES', 20_000)
    monkeypatch.setattr(f, 'MAX_SOURCE_BYTES', 16)
    with pytest.raises(k.KernelError):
        f.source_files(tar_bytes())


def test_publishes_whole_directory_without_partial_output(inputs, monkeypatch):
    # Per-artifact moves expose an incomplete final directory if interrupted.
    original = os.rename
    def no_partial(src, dst, **kwargs):
        assert not inputs[2].exists(), 'final directory exposed before publication completed'
        return original(src, dst, **kwargs)
    monkeypatch.setattr(os, 'rename', no_partial)
    f.build(*inputs, runner=fake_runner)
    assert len(list(inputs[2].iterdir())) == 3


def test_concurrent_output_insertion_is_not_replaced(inputs):
    calls = 0
    def insert(argv):
        nonlocal calls
        calls += 1
        fake_runner(argv)
        if calls == 2:
            inputs[2].mkdir()
            (inputs[2] / 'owner').write_text('keep')
    with pytest.raises(OSError):
        f.build(*inputs, runner=insert)
    assert sorted(p.name for p in inputs[2].iterdir()) == ['owner']


@pytest.mark.parametrize('value', [[], None, {'version': '1.18.0'},
    {'version': '1.18.0', 'source_sha256': [], 'patch_sha256': 'a' * 64}])
def test_malformed_build_locks_fail_closed_before_build(inputs, monkeypatch, value):
    (f.ROOT / 'vmm/firecracker.lock.json').write_text(json.dumps(value))
    with pytest.raises(k.KernelError):
        f.build(*inputs, runner=lambda _: pytest.fail('invalid lock started build'))
    assert not inputs[2].exists()


@pytest.mark.parametrize('raw', ['[' * 2000 + ']' * 2000,
    '{"version":"1.18.0","version":"1.18.0"}'])
def test_duplicate_or_deep_build_lock_is_a_static_cli_error(inputs, monkeypatch, capsys, raw):
    import sys
    (f.ROOT / 'vmm/firecracker.lock.json').write_text(raw)
    monkeypatch.setattr(sys, 'argv', ['build'] + [str(v) for v in inputs])
    assert f.main() == 1
    assert capsys.readouterr().err == 'Firecracker build refused: invalid input, failed build or resource cap\n'


def test_builder_ignores_ambient_docker_configuration(inputs):
    def runner(argv):
        assert argv[:2] == ['/usr/bin/docker', '--config']
        config = Path(argv[2])
        assert config.is_dir() and not list(config.iterdir())
        assert '--name' in argv
        fake_runner(argv)
    f.build(*inputs, runner=runner)


def test_build_timeout_removes_daemon_container_before_return(monkeypatch):
    import subprocess
    calls = []
    class Process:
        pid = 1234
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def wait(self, timeout):
            if not calls:
                calls.append('timed out')
                raise subprocess.TimeoutExpired('docker', timeout)
            return -9
    monkeypatch.setattr(f.subprocess, 'Popen', lambda *a, **kw: Process())
    monkeypatch.setattr(f.os, 'killpg', lambda pid, sig: calls.append(('kill', pid)))
    monkeypatch.setattr(f.subprocess, 'run', lambda argv, **kw: calls.append(('remove', argv, kw)))
    argv = f.docker_arguments('sha256:' + 'a' * 64, Path('/work/build/0'))
    with pytest.raises(k.KernelError, match='timed out'):
        f.run(argv)
    assert calls[-1][0] == 'remove'
    assert calls[-1][1] == argv[:3] + ['rm', '--force', argv[argv.index('--name') + 1]]
    assert calls[-1][2]['timeout'] <= 30
    assert calls[-1][2]['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
