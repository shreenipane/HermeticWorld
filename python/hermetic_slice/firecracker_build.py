"""Pinned, offline, double-build wrapper for the host clock filter."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import gzip
import stat
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import tarfile
import tempfile

from . import guest_kernel as k

ROOT = Path(__file__).absolute().parents[2]
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_ENTRIES = 20_000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
BUILD_TIMEOUT_SECONDS = 7200
BUILD_CLEANUP_TIMEOUT_SECONDS = 30
PATCH = '0001-host-pv-clock-filter.patch'
TARGET = 'x86_64-unknown-linux-musl'
RUST = '1.97.0'


def inputs(tarball: Path, image: str) -> tuple[dict, bytes, bytes]:
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise k.KernelError('builder must be an immutable local image ID')
    try:
        lock = json.loads(k.read_file(ROOT / 'vmm/firecracker.lock.json', k.MAX_LOCK_BYTES),
                          object_pairs_hook=k._pairs)
    except (ValueError, RecursionError):
        raise k.KernelError('invalid Firecracker source lock') from None
    if (not isinstance(lock, dict) or lock.get('version') != '1.18.0'
            or any(not isinstance(lock.get(field), str)
                   or not re.fullmatch(r'[0-9a-f]{64}', lock[field])
                   for field in ('source_sha256', 'patch_sha256'))):
        raise k.KernelError('invalid Firecracker source lock')
    patch = k.read_file(ROOT / 'vmm/firecracker-patches' / PATCH, k.MAX_CONFIG_BYTES)
    archive = k.read_file(tarball, MAX_ARCHIVE_BYTES)
    if hashlib.sha256(archive).hexdigest() != lock['source_sha256']:
        raise k.KernelError('Firecracker source hash mismatch')
    if hashlib.sha256(patch).hexdigest() != lock['patch_sha256']:
        raise k.KernelError('Firecracker patch hash mismatch')
    return lock, archive, patch


def source_files(archive: bytes) -> dict[str, bytes]:
    """Validate the complete bounded archive before creating any output."""
    files = {}
    seen = set()
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(archive)) as compressed:
            unpacked = compressed.read(MAX_SOURCE_BYTES + 1)
        if len(unpacked) > MAX_SOURCE_BYTES:
            raise k.KernelError('unpacked source byte cap')
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r|') as tar:
            for index, member in enumerate(tar):
                if index >= MAX_SOURCE_ENTRIES:
                    raise k.KernelError('source entry cap')
                path = PurePosixPath(member.name)
                if (len(member.name) > k.MAX_PATH_BYTES or len(path.parts) > k.MAX_PATH_DEPTH
                        or path.is_absolute() or '..' in path.parts
                        or not path.parts or path.parts[0] != 'firecracker-1.18.0'
                        or str(path) in seen or not (member.isfile() or member.isdir())
                        or any(key != 'comment' or value != 'eaf83bb718a559d324613d566eaf776b31a62340'
                               for key, value in member.pax_headers.items()) or member.size < 0 or member.size > MAX_MEMBER_BYTES):
                    raise k.KernelError('unsafe source archive entry')
                seen.add(str(path))
                total += member.size
                if total > MAX_SOURCE_BYTES:
                    raise k.KernelError('source byte cap')
                if member.isfile():
                    stream = tar.extractfile(member)
                    if stream is None:
                        raise k.KernelError('missing archive member')
                    data = stream.read(MAX_MEMBER_BYTES + 1)
                    if len(data) != member.size:
                        raise k.KernelError('truncated archive member')
                    files[str(PurePosixPath(*path.parts[1:]))] = data
        if 'Cargo.lock' not in files or 'rust-toolchain.toml' not in files:
            raise k.KernelError('missing source build inputs')
        for name in files:
            if any(str(parent) in files for parent in PurePosixPath(name).parents):
                raise k.KernelError('source file used as a directory')
    except (tarfile.TarError, EOFError, OSError):
        raise k.KernelError('invalid source archive') from None
    return files


@contextmanager
def directory_at(parent: int, parts: tuple[str, ...]):
    fd = os.dup(parent)
    try:
        for part in parts:
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise k.KernelError('internal directory changed')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(child)
                raise k.KernelError('internal directory changed')
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def artifact(parent: int, name: str) -> bytes:
    with k._regular_at(parent, name, MAX_BINARY_BYTES) as fd:
        return k._read_bytes(fd, MAX_BINARY_BYTES)


BUILD_COMMAND = '''set -eu
[ "$(rustc --version | cut -d ' ' -f 2)" = 1.97.0 ]
cd /build
patch --batch --fuzz=0 -p1 < /inputs/filter.patch
cargo --config /vendor/config.toml test --locked --offline -p vmm --lib clock_filter::tests --target x86_64-unknown-linux-musl
cargo --config /vendor/config.toml build --locked --offline --release --target x86_64-unknown-linux-musl -p firecracker -p jailer
cp /target/x86_64-unknown-linux-musl/release/firecracker /outputs/firecracker
cp /target/x86_64-unknown-linux-musl/release/jailer /outputs/jailer
'''


def docker_arguments(image: str, work: Path) -> list[str]:
    return ['/usr/bin/docker', '--config', str(work / 'inputs/docker-config'),
            'run', '--name', 'hermetic-fc-' + work.parent.name + '-' + work.name,
            '--rm', '--pull=never', '--network=none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--hostname=hermetic-build',
            '--pids-limit=512', '--memory=4g', '--cpus=4',
            '--ulimit=fsize=2147483648:2147483648',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
            '--tmpfs=/target:rw,exec,nosuid,nodev,size=4g',
            '-v', f'{work}/source:/build:rw', '-v', f'{work}/inputs:/inputs:ro',
            '-v', f'{work}/outputs:/outputs:rw', '--workdir=/build',
            '-e', 'CARGO_TARGET_DIR=/target', '-e', 'CARGO_HOME=/tmp/cargo',
            '-e', 'RUSTUP_TOOLCHAIN=1.97.0', '-e', 'HOME=/tmp',
            '-e', 'SOURCE_DATE_EPOCH=1794182400', '-e', 'TZ=UTC', '-e', 'LC_ALL=C',
            '-e', 'RUSTFLAGS=--remap-path-prefix=/build=/src -Ccodegen-units=1',
            '--entrypoint=/bin/sh', image, '-c', BUILD_COMMAND]


def run(argv: list[str]) -> None:
    try:
        with subprocess.Popen(argv, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True) as process:
            try:
                status = process.wait(timeout=BUILD_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=BUILD_CLEANUP_TIMEOUT_SECONDS)
                # The daemon owns the container; killing its client alone does
                # not stop a build or release its mounts.
                name = argv[argv.index('--name') + 1]
                subprocess.run(argv[:3] + ['rm', '--force', name],
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=BUILD_CLEANUP_TIMEOUT_SECONDS, check=True)
                raise k.KernelError('Firecracker build timed out') from None
    except OSError:
        raise k.KernelError('Firecracker build unavailable') from None
    if status:
        raise k.KernelError('Firecracker build failed')


def held_directory_path(fd: int) -> Path:
    """Real path of a held private directory, for Docker bind mounts.

    runc cannot bind-mount /proc/PID/fd magic links (EINVAL), so resolve the
    descriptor and require the resolved path to be the same directory inode.
    The caller has already required the directory to be private.
    """
    real = os.readlink(f'/proc/self/fd/{fd}')
    held = os.fstat(fd)
    seen = os.stat(real, follow_symlinks=False)
    if not real.startswith('/') or (seen.st_dev, seen.st_ino) != (held.st_dev, held.st_ino):
        raise k.KernelError('held output parent moved')
    return Path(real)


def build(tarball: Path, image: str, output: Path, *, runner=run) -> None:
    lock, archive, patch = inputs(tarball, image)
    files = source_files(archive)
    if output.name in ('', '.', '..') or not output.is_absolute():
        raise k.KernelError('absolute fresh output path required')
    # Hold the parent throughout staging and publication. The private directory
    # prevents pathname replacement by another guest or local user.
    with k.directory(output.parent) as parent:
        if os.stat(parent).st_mode & 0o022:
            raise k.KernelError('output parent must be private')
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise k.KernelError('output must be fresh')
        held_parent = held_directory_path(parent)
        with tempfile.TemporaryDirectory(prefix='.fc-build-', dir=held_parent) as temporary:
            work = Path(temporary)
            artifacts = []
            for index in range(2):
                attempt = work / str(index)
                for directory in ('source', 'inputs', 'outputs'):
                    (attempt / directory).mkdir(parents=True)
                (attempt / 'inputs/docker-config').mkdir(mode=0o700)
                for name, data in files.items():
                    dest = attempt / 'source' / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                (attempt / 'inputs/filter.patch').write_bytes(patch)
                runner(docker_arguments(image, attempt))
                with directory_at(parent, (work.name, str(index), 'outputs')) as result:
                    artifacts.append({name: artifact(result, name) for name in ('firecracker', 'jailer')})
            if artifacts[0] != artifacts[1] or any(not v for v in artifacts[0].values()):
                raise k.KernelError('Firecracker build is not reproducible')
            record = dict(schema='hermetic-firecracker-build/v1', version=lock['version'],
                          source_sha256=lock['source_sha256'], patch_sha256=lock['patch_sha256'],
                          builder_image=image, target=TARGET, rust=RUST,
                          **{name + '_sha256': hashlib.sha256(data).hexdigest()
                             for name, data in artifacts[0].items()})
            publish = work / 'publish'
            publish.mkdir(mode=0o700)
            with directory_at(parent, (work.name, 'publish')) as dest:
                for name, data in artifacts[0].items():
                    k._atomic_bytes(dest, name, data)
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dest)
                    try:
                        os.fchmod(fd, 0o500)
                    finally:
                        os.close(fd)
                k._atomic_bytes(dest, 'firecracker.lock.json', k._json_bytes(record))
                os.fsync(dest)
            # Publish the complete set in one operation, refusing concurrent
            # insertions (even empty directories) without a pathname recheck.
            with directory_at(parent, (work.name,)) as staged:
                libc = ctypes.CDLL(None, use_errno=True)
                rename = libc.renameat2
                rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                   ctypes.c_char_p, ctypes.c_uint]
                rename.restype = ctypes.c_int
                if rename(staged, b'publish', parent, os.fsencode(output.name), 1) != 0:
                    raise OSError(ctypes.get_errno(), 'cannot publish Firecracker build')
            os.fsync(parent)


def main() -> int:
    import sys
    try:
        if len(sys.argv) != 4:
            raise k.KernelError('usage: build-firecracker.sh SOURCE.tar.gz sha256:BUILDER_ID /ABS/FRESH_OUTPUT')
        build(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
    except (k.KernelError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('Firecracker build refused: invalid input, failed build or resource cap', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
