"""Build development Mode H inputs without running code from a task image."""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys

TOP = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(TOP / "python"))
sys.path.insert(0, str(TOP / "scripts/integration"))

from hermetic_agent.task import clock_value, read_input
from hermetic_agent.protocol import parse_json
from hermetic_safe_io import atomic_write, open_parent, open_regular, validate_path
from hermetic_slice.rootfs import build_rootfs, RootfsLimits
from e2e_seal import command, encoded, unpack_export, normalise_tree, MAX_EXPORT_BYTES
from smoke_work import create_work, open_child

MAX_BINARY_BYTES = 128 * 1024**2
MAX_RUNTIME_BYTES = 512 * 1024**2
MAX_RUNTIME_FILES = 128
MAX_ELF_HEADERS = 4096
MAX_DYNAMIC_ENTRIES = 65536
MAX_ELF_STRING_BYTES = 4096
MAX_LINKS = 40
MAX_COMPONENTS = 128
MAX_METADATA_BYTES = 1024**2
MAX_BUILD_SECONDS = 1800
MIN_GUEST_CLOCK = 315532800
MAX_GUEST_CLOCK = 4102444799
FIXTURE_CLOCK = "2023-11-14T22:13:20Z"
INSTANCE = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[0-9]{1,12}", re.ASCII)
LIBRARY_DIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
                "/lib64", "/usr/lib64", "/lib", "/usr/lib")
GUEST_DIRS = ("sbin", "bin", "dev/pts", "dev/shm", "proc", "sys", "tmp", "run",
              "etc/hermetic", "root", "mnt/hermetic-overlay", "mnt/hermetic-root")


def refused():
    raise ValueError("Agent image input refused")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        refused()


def read_binary(path):
    fd = open_regular(path, MAX_BINARY_BYTES)
    with os.fdopen(fd, "rb") as source:
        data = source.read(MAX_BINARY_BYTES + 1)
    if len(data) > MAX_BINARY_BYTES:
        refused()
    return data


def elf_dependencies(data):
    """Read x86_64 ELF dynamic dependencies as data, with no loader execution."""
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            refused()
        return struct.unpack_from(fmt, data, offset)

    if data[:6] != b"\x7fELF\x02\x01" or unpack("<H", 18) != (62,):
        refused()
    phoff, = unpack("<Q", 32)
    size, count = unpack("<HH", 54)
    if size != 56 or not 0 < count <= MAX_ELF_HEADERS:
        refused()
    segments = []
    interpreter = None
    for number in range(count):
        kind, _, offset, address, _, length, _, _ = unpack("<IIQQQQQQ", phoff + number * size)
        if offset + length > len(data):
            refused()
        segments.append((kind, offset, address, length))
        if kind == 3:
            if interpreter is not None or not 1 < length <= MAX_ELF_STRING_BYTES:
                refused()
            raw = data[offset:offset + length]
            if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                refused()
            interpreter = raw[:-1].decode("ascii")
            if not interpreter.startswith("/"):
                refused()
            validate_path(interpreter)
    needed = []
    table_address = table_size = None
    for kind, offset, _, length in segments:
        if kind != 2:
            continue
        if length % 16 or length // 16 > MAX_DYNAMIC_ENTRIES:
            refused()
        for index in range(length // 16):
            tag, value = unpack("<QQ", offset + index * 16)
            if tag == 0:
                break
            if tag == 1:
                needed.append(value)
                if len(needed) > MAX_RUNTIME_FILES:
                    refused()
            elif tag == 5:
                table_address = value
            elif tag == 10:
                table_size = value
    if not needed:
        return interpreter, []
    if table_address is None or table_size is None:
        refused()
    table = None
    for kind, offset, address, length in segments:
        if kind == 1 and address <= table_address and table_address + table_size <= address + length:
            table = offset + table_address - address
            break
    if table is None:
        refused()
    names = []
    for value in needed:
        if value >= table_size:
            refused()
        start = table + value
        end = data.find(b"\0", start, min(table + table_size, start + MAX_ELF_STRING_BYTES))
        if end < 0:
            refused()
        name = data[start:end].decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_+.-]{1,255}", name) or name in (".", ".."):
            refused()
        names.append(name)
    return interpreter, names


class Tree:
    """Guest-rooted symlink resolution; host syscalls never follow image links."""

    def __init__(self, path):
        self.fd, _ = open_parent(Path(path) / ".probe")

    def close(self):
        os.close(self.fd)

    def directory(self, path, *, create=False, regular=False):
        validate_path(path + "/.probe")
        pending = deque(path.split("/"))
        parents = [os.dup(self.fd)]
        links = steps = 0
        try:
            while pending:
                steps += 1
                if steps > MAX_COMPONENTS * (MAX_LINKS + 1) or len(pending) > MAX_COMPONENTS:
                    refused()
                name = pending.popleft()
                if name in ("", "."):
                    continue
                if name == "..":
                    if len(parents) <= 1:
                        refused()
                    os.close(parents.pop())
                    continue
                try:
                    before = os.stat(name, dir_fd=parents[-1], follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(name, 0o755, dir_fd=parents[-1])
                    before = os.stat(name, dir_fd=parents[-1], follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode):
                    links += 1
                    if links > MAX_LINKS:
                        refused()
                    target = os.readlink(name, dir_fd=parents[-1])
                    after = os.stat(name, dir_fd=parents[-1], follow_symlinks=False)
                    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                        refused()
                    if len(os.fsencode(target)) > MAX_ELF_STRING_BYTES:
                        refused()
                    if target.startswith("/"):
                        while len(parents) > 1:
                            os.close(parents.pop())
                    pending.extendleft(reversed(target.split("/")))
                else:
                    if regular and not pending:
                        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BINARY_BYTES:
                            refused()
                        pinned = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         dir_fd=parents[-1])
                        try:
                            after = os.fstat(pinned)
                            if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode):
                                refused()
                            return os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                        finally:
                            os.close(pinned)
                    if len(parents) > MAX_COMPONENTS:
                        refused()
                    parents.append(open_child(parents[-1], name))
            if regular:
                refused()
            return os.dup(parents[-1])
        finally:
            for fd in parents:
                os.close(fd)

    def write(self, path, data, mode=0o644):
        validate_path(path)
        parent, _, leaf = path.rpartition("/")
        directory = self.directory(parent, create=True)
        fd = None
        temporary = ".agent-image-new"
        try:
            # Replace an existing symlink itself; never open or chmod its target.
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "wb", closefd=False) as out:
                out.write(data)
                out.flush()
                os.fchmod(fd, mode)
                os.fsync(fd)
            os.replace(temporary, leaf, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            os.fsync(directory)
        finally:
            if fd is not None:
                os.close(fd)
                if temporary is not None:
                    os.unlink(temporary, dir_fd=directory)
            os.close(directory)

    def read(self, path, *, executable=False):
        fd = self.directory(path, regular=True)
        with os.fdopen(fd, "rb") as source:
            if executable and not os.fstat(source.fileno()).st_mode & 0o111:
                refused()
            data = source.read(MAX_BINARY_BYTES + 1)
        if len(data) > MAX_BINARY_BYTES:
            refused()
        return data


def check_guest_runtime(tree):
    pending = deque((path, True) for path in ("/bin/bash", "/bin/cat", "/bin/sed"))
    seen = set()
    total = 0
    while pending:
        path, executable = pending.popleft()
        if (path, executable) in seen:
            continue
        if len(seen) >= MAX_RUNTIME_FILES:
            refused()
        seen.add((path, executable))
        data = tree.read(path, executable=executable)
        total += len(data)
        if total > MAX_RUNTIME_BYTES:
            refused()
        interpreter, needed = elf_dependencies(data)
        if interpreter:
            pending.append((interpreter, True))
        for name in needed:
            for directory in LIBRARY_DIRS:
                candidate = directory + "/" + name
                try:
                    fd = tree.directory(candidate, regular=True)
                except FileNotFoundError:
                    continue
                os.close(fd)
                pending.append((candidate, False))
                break
            else:
                refused()


def host_runtime():
    """Only fixture inputs from the trusted staging OS; never used for real tasks."""
    pending = deque(("/bin/bash", "/bin/cat", "/bin/sed"))
    files = {}
    total = 0
    while pending:
        path = pending.popleft()
        if path in files:
            continue
        if len(files) >= MAX_RUNTIME_FILES:
            refused()
        # Merged-/usr and library SONAME links belong to the trusted host runtime.
        # Canonicalize those fixed inputs, then read the regular inode without links.
        data = read_binary(Path(path).resolve(strict=True))
        total += len(data)
        if total > MAX_RUNTIME_BYTES:
            refused()
        interpreter, needed = elf_dependencies(data)
        files[path] = data
        if interpreter:
            pending.append(interpreter)
        for name in needed:
            for directory in LIBRARY_DIRS:
                candidate = Path(directory) / name
                try:
                    candidate.resolve(strict=True)
                except FileNotFoundError:
                    continue
                pending.append(str(candidate))
                break
            else:
                refused()
    return files


def run_spec():
    return {"env": {"HOME": "/root", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                    "PATH": "/opt/miniconda3/envs/testbed/bin:/opt/conda/envs/testbed/bin:/usr/local/bin:/usr/bin:/bin:/sbin"},
            "workdir": "/testbed", "uid": 0, "gid": 0, "entrypoint": [], "command": [],
            "hostname": "world", "resolv_conf": "nameserver 10.0.0.1\n",
            "resources": {"vcpus": 1, "memory_mib": 2048, "disk_mib": 32768, "wall_time_s": 5400}}


def install_guest(tree, binaries):
    for name in GUEST_DIRS:
        fd = tree.directory(name, create=True)
        os.close(fd)
    for name, data in sorted(binaries.items()):
        tree.write("sbin/" + name, data, 0o755)
    for name, data in {"hostname": b"world\n", "hosts": b"127.0.0.1 localhost\n::1 localhost\n",
                       "resolv.conf": b"nameserver 10.0.0.1\n", "machine-id": b""}.items():
        tree.write("etc/" + name, data)
    tree.write("var/lib/dbus/machine-id", b"")
    tree.write("etc/hermetic/run-spec.json", encoded(run_spec()))


def build_tools(work):
    env = dict(os.environ)
    env.pop("RUSTFLAGS", None)
    cargo_home = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve(strict=True)
    env["CARGO_TARGET_DIR"] = str(work / "cargo-target")
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(("-C", "target-feature=+crt-static",
        "--remap-path-prefix=" + str(TOP) + "=/src",
        "--remap-path-prefix=" + str(cargo_home) + "=/cargo",
        "--remap-path-prefix=" + str(work) + "=/build"))
    command(["cargo", "build", "--offline", "--locked", "--release", "--target",
             "x86_64-unknown-linux-gnu", "-p", "hermetic-execd", "-p", "hermetic-extract-agent",
             "-p", "hermetic-sealcheck"], env=env, timeout=MAX_BUILD_SECONDS)
    output = work / "cargo-target/x86_64-unknown-linux-gnu/release"
    binaries = {}
    for name in ("hermetic-execd", "hermetic-init", "hermetic-extract-agent", "hermetic-sealcheck"):
        data = read_binary(output / name)
        if elf_dependencies(data) != (None, []):
            refused()
        binaries[name] = data
    atomic_write(work / "sealcheck", binaries.pop("hermetic-sealcheck"))
    fd = open_regular(work / "sealcheck", MAX_BINARY_BYTES)
    try:
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return binaries


def task_inputs(root, instance):
    if not isinstance(instance, str) or len(instance) > 200 or not INSTANCE.fullmatch(instance):
        refused()
    task_dir = Path(root) / "tasks" / instance
    task = parse_json(read_input(task_dir / "task.json", MAX_METADATA_BYTES))
    if not isinstance(task, dict) or task.get("instance_id") != instance or not isinstance(task.get("cutoffs"), dict):
        refused()
    cutoffs = {key: task["cutoffs"].get(key) for key in ("t_world", "t_clock")}
    epoch = clock_value(cutoffs["t_clock"])
    if not MIN_GUEST_CLOCK <= epoch <= MAX_GUEST_CLOCK or clock_value(cutoffs["t_world"]) > epoch:
        refused()
    base = task.get("base_commit")
    if not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base):
        refused()
    issue = read_input(task_dir / "agent/problem_statement.md")
    if not issue or b"\0" in issue:
        refused()
    issue.decode("utf-8")
    return cutoffs, base, issue


def export_image(image, work):
    # Ignore container config/Env/entrypoints. Only filesystem bytes are imported.
    info = parse_json(command(["docker", "image", "inspect", "--format", "{{json .Id}}", image]))
    if not isinstance(info, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", info):
        refused()
    container = command(["docker", "create", "--pull", "never", "--network", "none",
                         "--hostname", "world", "--entrypoint", "/bin/true", info]).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        refused()
    try:
        command(["docker", "export", container], cap=MAX_EXPORT_BYTES, output=work / "source.tar")
    finally:
        command(["docker", "rm", "-f", container])
    unpack_export(work / "source.tar", work / "tree")
    return info


def finish(work, instance, cutoffs, source):
    epoch = clock_value(cutoffs["t_clock"])
    if not MIN_GUEST_CLOCK <= epoch <= MAX_GUEST_CLOCK:
        refused()
    normalise_tree(work / "tree", epoch)
    result = build_rootfs(work / "tree", work / "rootfs.img",
                          t_clock=datetime.fromtimestamp(epoch, timezone.utc), world_id=instance,
                          sealcheck_bin=work / "sealcheck", work_dir=work,
                          limits=RootfsLimits(max_bytes=24 * 1024**3, max_entries=500_000,
                                              max_depth=128, max_logical_bytes=24 * 1024**3),
                          root_owned=True)
    if result.get("d4") != "pass" or result.get("skipped_special"):
        refused()
    # This harness input deliberately makes no complete WorldManifest certification claim.
    manifest = {"schema": "hermetic-agent-input/v1", "task_id": instance,
                "cutoffs": cutoffs, "rootfs_digest": "sha256:" + result["sha256"],
                "run_spec": run_spec(), "source": source, "checks": {"D4": "pass"},
                "certified_world_bundle": False}
    atomic_write(work / "world.json", encoded(manifest))


def run(argv=None):
    parser = Parser(prog="agent-h-image", description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="mode", required=True)
    fixture = sub.add_parser("fixture", allow_abbrev=False)
    fixture.add_argument("work")
    sealed = sub.add_parser("sealed", allow_abbrev=False)
    sealed.add_argument("sealed_run")
    sealed.add_argument("instance")
    sealed.add_argument("work")
    args = parser.parse_args(argv)
    validate_path(args.work)
    # Validate all supplied metadata and stage fixture runtime before creating output.
    if args.mode == "sealed":
        cutoffs, base, issue = task_inputs(args.sealed_run, args.instance)
        instance = args.instance
        runtime = None
    else:
        instance = "agent-h-fixture"
        cutoffs = {"t_world": FIXTURE_CLOCK, "t_clock": FIXTURE_CLOCK}
        base = None
        issue = b"Fix add(a, b) so that it adds its arguments.\n"
        runtime = host_runtime()
    parent, _, directory, path = create_work(str(__file__), args.work)
    work = Path(path)
    try:
        os.umask(0o077)
        binaries = build_tools(work)
        if runtime is None:
            source = {"image_id": export_image("hermetic/" + instance + ":sealed", work), "base_commit": base}
        else:
            os.mkdir(work / "tree", 0o700)
            source = {"fixture": "grader-task/repo", "runtime_sha256": {
                name: hashlib.sha256(data).hexdigest() for name, data in sorted(runtime.items())}}
        tree = Tree(work / "tree")
        try:
            if runtime is not None:
                for name, data in sorted(runtime.items()):
                    tree.write(name, data, 0o755)
                repo = TOP / "scripts/integration/fixtures/grader-task/repo"
                # The fixture has only these reviewed files; never import host caches.
                for name in ("calc.py", "tests/test_calc.py"):
                    data = read_input(repo / name)
                    for destination in ("testbed/", "smoke/base/"):
                        tree.write(destination + name, data)
            install_guest(tree, binaries)
            check_guest_runtime(tree)
            fd = tree.directory("testbed")
            os.close(fd)
        finally:
            tree.close()
        atomic_write(work / "issue.txt", issue)
        finish(work, instance, cutoffs, source)
        print('Agent image ready: rootfs.img, world.json, issue.txt (D4 pass)')
        return 0
    finally:
        os.close(directory)
        os.close(parent)


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except Exception:
        raise SystemExit("Agent image build refused") from None
