"""Private work-directory lifecycle for development smoke scripts (stdlib only)."""

import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys

MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 256
MAX_CREATE_ATTEMPTS = 128
MAX_CLEANUP_ENTRIES = 1_000_000
MAX_CLEANUP_DEPTH = 128
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def path_parts(path):
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_BYTES or len(os.fsencode(path)) > MAX_PATH_BYTES:
        raise ValueError("invalid work path")
    if any(c in path for c in ("\0", "\n", "\r")):
        raise ValueError("invalid work path")
    parts = path.split("/")
    if ".." in parts or len(parts) > MAX_PATH_COMPONENTS:
        raise ValueError("invalid work path")
    return [part for part in parts if part not in ("", ".")]


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


def open_child(parent, name):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError("work path contains a non-directory")
    child = os.open(name, DIR_FLAGS, dir_fd=parent)
    if identity(before) != identity(os.fstat(child)):
        os.close(child)
        raise ValueError("work directory changed")
    return child


def private_mkdir(parent, name):
    previous = os.umask(0o077)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    finally:
        os.umask(previous)


def open_directory(path, *, create=False):
    parts = path_parts(path)
    directory = os.open("/" if path.startswith("/") else ".", DIR_FLAGS)
    try:
        for part in parts:
            if create:
                try:
                    private_mkdir(directory, part)
                except FileExistsError:
                    pass
            child = open_child(directory, part)
            os.close(directory)
            directory = child
        metadata = os.fstat(directory)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
            raise ValueError("work parent must be owned by the caller and not writable by others")
        return directory
    except BaseException:
        os.close(directory)
        raise


def create_work(script, requested):
    # Validate the complete input before creating even a cache ancestor.
    if requested is not None:
        parts = path_parts(requested)
        if not parts or requested.endswith("/") or requested.split("/")[-1] == ".":
            raise ValueError("work directory must be new")
        path = Path(requested).absolute()
        parent = open_directory(str(path.parent))
        leaf = path.name
    else:
        root = os.environ.get("HERMETIC_SMOKE_DIR") or os.path.join(
            os.environ["HOME"], ".cache", "hermetic-smoke"
        )
        path_parts(root)
        parent = open_directory(root, create=True)
        path = Path(root).absolute()
        leaf = None
    try:
        for _ in range(MAX_CREATE_ATTEMPTS):
            name = leaf if leaf is not None else f"{Path(script).stem}-{secrets.token_hex(12)}"
            try:
                private_mkdir(parent, name)
            except FileExistsError:
                if leaf is not None:
                    raise
                continue
            child = open_child(parent, name)
            work = path if leaf is not None else path / name
            return parent, name, child, str(work)
        raise ValueError("work directory creation attempts exhausted")
    except BaseException:
        os.close(parent)
        raise


def remove_contents(directory, device, budget, depth=0):
    if depth > MAX_CLEANUP_DEPTH:
        raise ValueError("smoke cleanup depth cap exceeded")
    with os.scandir(directory) as entries:
        for entry in entries:
            budget[0] -= 1
            if budget[0] < 0:
                raise ValueError("smoke cleanup entry cap exceeded")
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = open_child(directory, entry.name)
                try:
                    if identity(metadata) != identity(os.fstat(child)) or metadata.st_dev != device:
                        raise ValueError("smoke cleanup directory changed or crossed a filesystem")
                    remove_contents(child, device, budget, depth + 1)
                    current = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                    if identity(current) != identity(metadata):
                        raise ValueError("smoke cleanup directory changed")
                    os.rmdir(entry.name, dir_fd=directory)
                finally:
                    os.close(child)
            else:
                # Unlink the entry itself, including links, sockets and special files.
                os.unlink(entry.name, dir_fd=directory)


def cleanup(parent, name, directory):
    original = os.fstat(directory)
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(current.st_mode) or identity(current) != identity(original):
        raise ValueError("smoke work directory was replaced; refusing cleanup")
    remove_contents(directory, original.st_dev, [MAX_CLEANUP_ENTRIES])
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if identity(current) != identity(original):
        raise ValueError("smoke work directory was replaced; refusing cleanup")
    os.rmdir(name, dir_fd=parent)


def run(script, requested=None):
    parent, name, directory, work = create_work(script, requested)
    process = None
    received_signal = None
    previous = {}

    def forward(signum, _frame):
        nonlocal received_signal
        received_signal = signum
        if process is not None:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    result = 1
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, forward)
        env = dict(os.environ, HERMETIC_SMOKE_WORK=work)
        process = subprocess.Popen(
            ["bash", "-c", 'set -euo pipefail; source "$1"; smoke_main', "smoke", script],
            env=env, start_new_session=True,
        )
        if received_signal is not None:
            forward(received_signal, None)
        result = process.wait()
        if received_signal is not None:
            result = 128 + received_signal
        elif result < 0:
            result = 128 - result
        if result == 0:
            cleanup(parent, name, directory)
    except (OSError, ValueError):
        result = 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        os.close(directory)
        os.close(parent)
        if result != 0:
            print(f"Smoke failed; work directory retained: {work}", file=sys.stderr)
    return result


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: smoke-script [NEW_WORK_DIR]", file=sys.stderr)
        return 2
    try:
        return run(os.path.abspath(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else None)
    except (OSError, ValueError, KeyError):
        print("Cannot create a fresh private smoke work directory", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
