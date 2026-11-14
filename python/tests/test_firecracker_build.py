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
    def launch(argv, **kwargs):
        if argv[3] != 'rm':
            return Process()
        class Cleanup:
            def wait(self, timeout):
                calls.append(('remove', argv, {**kwargs, 'timeout': timeout}))
                return 0
        return Cleanup()
    monkeypatch.setattr(f.subprocess, 'Popen', launch)
    monkeypatch.setattr(f.os, 'killpg', lambda pid, sig: calls.append(('kill', pid)))
    argv = f.docker_arguments('sha256:' + 'a' * 64, Path('/work/build/0'))
    with pytest.raises(k.KernelError, match='timed out'):
        f.run(argv)
    assert calls[-1][0] == 'remove'
    assert calls[-1][1] == argv[:3] + ['rm', '--force', argv[argv.index('--name') + 1]]
    assert calls[-1][2]['timeout'] <= 30
    assert calls[-1][2]['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}


@pytest.mark.parametrize('removal_stalls', [False, True])
def test_reap_timeout_still_removes_container_without_unbounded_context_wait(monkeypatch, removal_stalls):
    import subprocess
    calls = []
    class Process:
        pid = 1234
        def __enter__(self): return self
        def __exit__(self, *args):
            pytest.fail('Popen context cleanup can wait without a deadline')
        def wait(self, timeout):
            calls.append(('wait', timeout))
            raise subprocess.TimeoutExpired('docker', timeout)
    def launch(argv, **kwargs):
        if argv[3] != 'rm':
            return Process()
        class Cleanup(Process):
            def wait(self, timeout):
                calls.append(('remove', argv, {**kwargs, 'timeout': timeout}))
                if removal_stalls:
                    raise subprocess.TimeoutExpired('docker rm', timeout)
                return 0
        return Cleanup()
    monkeypatch.setattr(f.subprocess, 'Popen', launch)
    monkeypatch.setattr(f.os, 'killpg', lambda pid, sig: calls.append(('kill', pid)))
    argv = f.docker_arguments('sha256:' + 'a' * 64, Path('/work/build/0'))
    with pytest.raises((k.KernelError, subprocess.TimeoutExpired)):
        f.run(argv)
    removal = next(call for call in calls if call[0] == 'remove')
    assert removal[1] == argv[:3] + ['rm', '--force', argv[argv.index('--name') + 1]]
    assert removal[2]['timeout'] == f.BUILD_CLEANUP_TIMEOUT_SECONDS
    assert [call[1] for call in calls if call[0] == 'wait'] == [
        f.BUILD_TIMEOUT_SECONDS, f.BUILD_CLEANUP_TIMEOUT_SECONDS]
    assert sum(call[0] == 'remove' for call in calls) == (2 if removal_stalls else 1)


def test_failed_client_removes_daemon_container(monkeypatch):
    calls = []
    def client(argv, timeout):
        calls.append((argv, timeout))
        return 1 if len(calls) == 1 else 0
    monkeypatch.setattr(f, '_run_process', client)
    argv = f.docker_arguments('sha256:' + 'a' * 64, Path('/work/build/0'))
    with pytest.raises(k.KernelError, match='build failed'):
        f.run(argv)
    assert calls == [
        (argv, f.BUILD_TIMEOUT_SECONDS),
        (argv[:3] + ['rm', '--force', argv[argv.index('--name') + 1]],
         f.BUILD_CLEANUP_TIMEOUT_SECONDS)]


def test_target_tmpfs_allows_build_scripts_to_execute():
    # Docker mounts --tmpfs noexec by default; cargo build scripts compiled into
    # /target then fail with EACCES (manager build, 2026-11-14).
    from pathlib import Path
    from hermetic_slice import firecracker_build as fb
    args = fb.docker_arguments("sha256:" + "0" * 64, Path("/attempt"))
    target = [a for a in args if a.startswith("--tmpfs=/target:")]
    assert len(target) == 1
    options = target[0].split(":", 1)[1].split(",")
    assert "exec" in options and "noexec" not in options
    assert "nosuid" in options and "nodev" in options
    tmp = [a for a in args if a.startswith("--tmpfs=/tmp:")]
    assert len(tmp) == 1 and "exec" not in tmp[0].split(":", 1)[1].split(",")


def test_held_parent_resolves_to_real_path_not_proc_magic_link(tmp_path):
    # runc rejects bind mounts from /proc/PID/fd paths with EINVAL (manager build, 2026-11-14).
    import os
    import pytest
    from hermetic_slice import firecracker_build as fb
    d = tmp_path / "parent"
    d.mkdir(mode=0o700)
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        resolved = fb.held_directory_path(fd)
        assert str(resolved) == os.path.realpath(d) and not str(resolved).startswith("/proc/")
        os.rename(d, tmp_path / "moved")
        (tmp_path / "parent").mkdir(mode=0o700)
        assert fb.held_directory_path(fd) == tmp_path / "moved"
        os.rmdir(tmp_path / "moved")
        with pytest.raises((fb.k.KernelError, OSError)):
            fb.held_directory_path(fd)
    finally:
        os.close(fd)


def test_output_ancestry_must_prevent_untrusted_rename(inputs):
    tarball, image, output = inputs
    shared = output.parent / 'shared'
    shared.mkdir()
    shared.chmod(0o777)
    private = shared / 'private'
    private.mkdir(mode=0o700)
    with pytest.raises(k.KernelError):
        f.build(tarball, image, private / 'result', runner=fake_runner)
    assert list(private.iterdir()) == []


def test_archive_rejects_directory_under_regular_file_before_staging():
    member = tarfile.TarInfo('firecracker-1.18.0/Cargo.lock/child')
    member.type = tarfile.DIRTYPE
    with pytest.raises(k.KernelError):
        f.source_files(tar_bytes(member))


def test_verified_base_recipe_pins_toolchain_packages_and_musl_headers():
    recipe = (Path(__file__).resolve().parents[2] / 'vmm/firecracker-base.Dockerfile').read_text()
    lines = recipe.replace('\\\n', ' ').splitlines()
    assert 'FROM rust@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073' in lines
    install = next(line for line in lines if line.startswith('RUN apt-get'))
    packages = install.split('apt-get install -y --no-install-recommends', 1)[1].split('&&', 1)[0].split()
    assert packages == ['musl-tools', 'cmake', 'patch', 'clang', 'libclang-dev', 'linux-libc-dev', 'libseccomp-dev']
    for name, source in [('linux', '/usr/include/linux'), ('asm', '/usr/include/x86_64-linux-gnu/asm'),
                         ('asm-generic', '/usr/include/asm-generic')]:
        assert f'ln -s {source} /usr/include/x86_64-linux-musl/{name}' in install
    toolchain = next(line for line in lines if line.startswith('RUN rustup'))
    assert 'rustup toolchain install 1.97.0 --profile minimal --component rustfmt' in toolchain
    assert '--target x86_64-unknown-linux-musl' in toolchain
    assert 'rustup default 1.97.0' in toolchain
