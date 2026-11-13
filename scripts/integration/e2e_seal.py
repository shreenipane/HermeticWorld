"""Stage-one sealing integration. All inputs and outputs stay on the staging host."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time

TOP = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(TOP / "python"))
sys.path.insert(0, str(TOP / "scripts/integration"))

from hermetic_safe_io import atomic_write, open_parent, open_regular, validate_path
from hermetic_runspec.derive import parse_json_bytes, read_regular_file_bounded
from smoke_work import create_work, open_child

MAX_RECORD_BYTES = 8 * 1024**2
MAX_REPORT_BYTES = 32 * 1024**2
MAX_TOOL_BYTES = 128 * 1024**2
MAX_EXPORT_BYTES = 32 * 1024**3
MAX_TREE_BYTES = 24 * 1024**3
MAX_FILE_BYTES = 2 * 1024**3
MAX_MEMBERS = 500_000
MAX_DEPTH = 128
MAX_HEADER_READ = 1024**2
MAX_STEP_SECONDS = 1800
MAX_WORKER_MEMORY = 4 * 1024**3
IO_CHUNK_BYTES = 65536
MAX_TESTS = 100_000
MAX_TEST_ID_BYTES = 4096
MAX_ARCHIVE_PATH_BYTES = 4096


class SealError(Exception):
    """A public, fixed diagnostic without input contents."""


class CommandFailure(SealError):
    def __init__(self, code, output):
        super().__init__("step_exit_" + str(code if code >= 0 else 1))
        self.output = output


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def read_json(path, cap=MAX_REPORT_BYTES):
    return parse_json_bytes(read_regular_file_bounded(path, cap), cap)


def validate_record(row, instance):
    if not isinstance(row, dict) or row.get("instance_id") != instance:
        raise SealError("record_identity_mismatch")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", str(row.get("repo", ""))):
        raise SealError("invalid_record_repository")
    if not re.fullmatch(r"[0-9a-f]{40}", str(row.get("base_commit", ""))):
        raise SealError("invalid_base_commit")
    for field in ("problem_statement", "patch", "test_patch"):
        value = row.get(field)
        if not isinstance(value, str) or not value or "\0" in value:
            raise SealError("invalid_record_text")
        try:
            if len(value.encode("utf-8")) > MAX_RECORD_BYTES:
                raise SealError("record_text_cap")
        except UnicodeError:
            raise SealError("invalid_record_text") from None
    for field in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        tests = row.get(field)
        if isinstance(tests, str):
            tests = parse_json_bytes(tests.encode("utf-8"), MAX_RECORD_BYTES)
        if not isinstance(tests, list) or not tests or len(tests) > MAX_TESTS:
            raise SealError("invalid_test_list")
        if any(not isinstance(t, str) or not t or "\0" in t or
               len(t.encode("utf-8")) > MAX_TEST_ID_BYTES for t in tests):
            raise SealError("invalid_test_id")
        if len(set(tests)) != len(tests):
            raise SealError("duplicate_test_id")
        row[field] = tests
    if set(row["FAIL_TO_PASS"]) & set(row["PASS_TO_PASS"]):
        raise SealError("overlapping_test_lists")
    return row


def load_record(path, instance, source=None):
    raw = read_regular_file_bounded(path, MAX_RECORD_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    if source is not None:
        provenance = read_json(source, MAX_RECORD_BYTES)
        if not isinstance(provenance, dict) or provenance.get("sha256") != digest:
            raise SealError("record_digest_mismatch")
    row = validate_record(parse_json_bytes(raw, MAX_RECORD_BYTES), instance)
    return raw, row, digest


def emit(step, verdict, **detail):
    sys.stdout.buffer.write(encoded({"step": step, "verdict": verdict, **detail}))
    sys.stdout.buffer.flush()


def command(argv, *, cap=MAX_REPORT_BYTES, timeout=MAX_STEP_SECONDS, output=None, env=None):
    """Bound both streams together; never print subprocess data or exception text."""
    parent = descriptor = None
    temporary = None
    process = None
    result = bytearray()
    total = 0
    try:
        if output is not None:
            parent, leaf = open_parent(output)
            candidate = leaf + ".partial"
            descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            temporary = candidate
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, start_new_session=True, env=env)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, True)
            selector.register(process.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SealError("step_timeout")
                ready = selector.select(min(remaining, 1))
                for key, _ in ready:
                    data = os.read(key.fd, IO_CHUNK_BYTES)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > cap:
                        raise SealError("step_output_cap")
                    if key.data:
                        if descriptor is None:
                            result.extend(data)
                        else:
                            with os.fdopen(os.dup(descriptor), "wb", closefd=True) as stream:
                                stream.write(data)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SealError("step_timeout")
            code = process.wait(timeout=remaining)
        if code != 0:
            raise CommandFailure(code, bytes(result))
        if descriptor is not None:
            os.fsync(descriptor)
            os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
            temporary = None
            os.fsync(parent)
        return bytes(result)
    finally:
        if process is not None:
            # Descendants can survive their parent or hold pipes open after it exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        if parent is not None:
            os.close(parent)


class HeaderReader:
    """Refuse oversized GNU/PAX extensions before tarfile allocates their payload."""

    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        if size < 0 or size > MAX_HEADER_READ:
            raise SealError("archive_header_cap")
        return self.stream.read(size)

    def seek(self, *args):
        return self.stream.seek(*args)

    def tell(self):
        return self.stream.tell()


def member_parts(name):
    if not isinstance(name, str) or name.startswith("/") or "\0" in name:
        raise SealError("archive_path_refused")
    # Docker's root entry and leading ./ are conventional tar spellings.
    parts = tuple(p for p in name.split("/") if p not in ("", "."))
    if ".." in parts or len(parts) > MAX_DEPTH or len(name.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES:
        raise SealError("archive_path_refused")
    return parts


@contextmanager
def directory_at(root, parts):
    current = os.dup(root)
    try:
        for part in parts:
            child = open_child(current, part)
            os.close(current)
            current = child
        yield current
    finally:
        os.close(current)


def unpack_export(archive, destination):
    """Validate the complete export before writing; never use tar extract/extractall."""
    descriptor = open_regular(archive, MAX_EXPORT_BYTES)
    try:
        archive_size = os.fstat(descriptor).st_size
        with os.fdopen(descriptor, "rb", closefd=False) as stream, tarfile.open(
            fileobj=HeaderReader(stream), mode="r:"
        ) as tar:
            members = {}
            total = 0
            for number, member in enumerate(tar):
                if number >= MAX_MEMBERS:
                    raise SealError("archive_entry_cap")
                parts = member_parts(member.name)
                if not parts and member.isdir():
                    continue
                if not parts or parts in members:
                    raise SealError("archive_duplicate_path")
                if not (member.isdir() or member.isreg() or member.issym() or member.islnk()):
                    raise SealError("archive_special_file")
                if member.sparse is not None or member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise SealError("archive_file_cap")
                if member.offset_data + member.size > archive_size:
                    raise SealError("archive_file_truncated")
                total += member.size
                if total > MAX_TREE_BYTES:
                    raise SealError("archive_byte_cap")
                if member.issym() and (len(member.linkname.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES or "\0" in member.linkname):
                    raise SealError("archive_link_refused")
                members[parts] = member
            for parts, member in members.items():
                for depth in range(1, len(parts)):
                    ancestor = members.get(parts[:depth])
                    if ancestor is not None and not ancestor.isdir():
                        raise SealError("archive_non_directory_ancestor")
                if member.islnk():
                    target = members.get(member_parts(member.linkname))
                    if target is None or not target.isreg():
                        raise SealError("archive_hardlink_refused")
                    total += target.size
                    if total > MAX_TREE_BYTES:
                        raise SealError("archive_byte_cap")
            dirs = set()
            for parts, member in members.items():
                for depth in range(1, len(parts) + int(member.isdir())):
                    dirs.add(parts[:depth])
                    if len(dirs) > MAX_MEMBERS:
                        raise SealError("archive_directory_cap")
            # All ancestors are fresh directories in a private work area. Hard links
            # become independent files, so chmod and later cleanup cannot affect aliases.
            os.mkdir(destination, 0o700)
            root, _ = open_parent(Path(destination) / ".probe")
            try:
                for parts in sorted(dirs, key=lambda p: (len(p), p)):
                    with directory_at(root, parts[:-1]) as parent:
                        os.mkdir(parts[-1], 0o700, dir_fd=parent)
                for parts, member in sorted(members.items()):
                    if member.isdir():
                        continue
                    with directory_at(root, parts[:-1]) as parent:
                        if member.issym():
                            os.symlink(member.linkname, parts[-1], dir_fd=parent)
                            continue
                        source = members[member_parts(member.linkname)] if member.islnk() else member
                        content = tar.extractfile(source)
                        if content is None:
                            raise SealError("archive_file_unreadable")
                        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW, 0o600, dir_fd=parent)
                        with os.fdopen(fd, "wb") as out, content:
                            remaining = source.size
                            while remaining:
                                chunk = content.read(min(IO_CHUNK_BYTES, remaining))
                                if not chunk:
                                    raise SealError("archive_file_truncated")
                                out.write(chunk)
                                remaining -= len(chunk)
                            os.fchmod(out.fileno(), source.mode & 0o777)
                # Apply directory modes last, through held descriptors, never a link.
                for parts in sorted(dirs, key=lambda p: (-len(p), p)):
                    with directory_at(root, parts) as directory:
                        member = members.get(parts)
                        os.fchmod(directory, (member.mode & 0o777) if member else 0o755)
            finally:
                os.close(root)
    finally:
        os.close(descriptor)


def check_git_tree(root):
    """Git must never interpret image-provided links or external object stores on the host."""
    parent, _ = open_parent(Path(root) / ".probe")
    count = [0]
    def visit(directory, depth):
        if depth > MAX_DEPTH:
            raise SealError("git_tree_depth_cap")
        with os.scandir(directory) as entries:
            for entry in entries:
                count[0] += 1
                if count[0] > MAX_MEMBERS:
                    raise SealError("git_tree_entry_cap")
                mode = entry.stat(follow_symlinks=False).st_mode
                if entry.name in ("alternates", "http-alternates", "commondir", "gitdir"):
                    raise SealError("git_external_store_refused")
                if stat.S_ISDIR(mode):
                    child = open_child(directory, entry.name)
                    try:
                        visit(child, depth + 1)
                    finally:
                        os.close(child)
                elif not stat.S_ISREG(mode):
                    raise SealError("git_link_or_special_refused")
    try:
        visit(parent, 0)
    finally:
        os.close(parent)
    # Discard image-provided includes, hooks, helpers and external worktree
    # settings before any host-side Git command reads the repository.
    atomic_write(Path(root) / "config", b"[core]\nrepositoryformatversion = 0\nbare = false\n")


def prepare_oracle(row, task_dir, output):
    """Prepare data only: never run the benchmark's eval script on the staging host."""
    artifacts = {
        "gold.patch": row["patch"].encode("utf-8"),
        "test.patch": row["test_patch"].encode("utf-8"),
        "FAIL_TO_PASS.json": encoded(row["FAIL_TO_PASS"]),
        "PASS_TO_PASS.json": encoded(row["PASS_TO_PASS"]),
    }
    cutoffs = read_json(Path(task_dir) / "task.json")["cutoffs"]
    os.mkdir(output, 0o700)
    for name, data in sorted(artifacts.items()):
        atomic_write(Path(output) / name, data)
    atomic_write(Path(output) / "inputs.json", encoded({
        "schema": "hermetic-oracle-inputs/v1", "instance_id": row["instance_id"],
        "base_commit": row["base_commit"], "cutoffs": cutoffs,
        "files": {name: "sha256:" + hashlib.sha256(data).hexdigest()
                  for name, data in sorted(artifacts.items())},
        "executed": False,
    }))


def normalise_tree(root, epoch):
    """Clamp live mtimes for the static scans as well as the eventual ext4 build."""
    parent, _ = open_parent(Path(root) / ".probe")
    count = [0]
    def visit(directory, depth):
        if depth > MAX_DEPTH:
            raise SealError("tree_depth_cap")
        with os.scandir(directory) as entries:
            for entry in entries:
                count[0] += 1
                if count[0] > MAX_MEMBERS:
                    raise SealError("tree_entry_cap")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    child = open_child(directory, entry.name)
                    try:
                        visit(child, depth + 1)
                    finally:
                        os.close(child)
                elif not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
                    raise SealError("tree_special_file")
                os.utime(entry.name, (epoch, epoch), dir_fd=directory, follow_symlinks=False)
        os.utime(directory, (epoch, epoch))
    try:
        visit(parent, 0)
    finally:
        os.close(parent)


def worker(action, work, instance):
    """Existing modules run in a process with resource limits and a private HOME/TMPDIR."""
    resource.setrlimit(resource.RLIMIT_AS, (MAX_WORKER_MEMORY, MAX_WORKER_MEMORY))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_EXPORT_BYTES, MAX_EXPORT_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_STEP_SECONDS, MAX_STEP_SECONDS))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    work = Path(work)
    row = validate_record(read_json(work / "record.json", MAX_RECORD_BYTES), instance)
    tree = work / "source-tree"
    task_dir = work / "tasks" / instance
    if action == "unpack":
        unpack_export(work / "source.tar", tree)
        check_git_tree(tree / "testbed/.git")
    elif action == "intake":
        from hermetic_slice.http import make_http_get, make_http_post_json
        from hermetic_slice.intake import intake_task
        token = os.environ.get("GITHUB_TOKEN")
        cache = work / "cache"
        intake_task(instance, {instance: row}, make_http_get(cache, token=token), cache,
                    work / "tasks", clone_url=str(tree / "testbed"), token=token,
                    http_post_json=make_http_post_json(cache, token=token) if token else None)
        prepare_oracle(row, task_dir, work / "oracle-inputs")
    elif action == "repository":
        from hermetic_slice.repo_sealer import seal_repo, remove_tree_at
        import shutil
        task = read_json(task_dir / "task.json")
        seal_repo(tree / "testbed", row["base_commit"], work / "base-tree",
                  datetime.fromisoformat(task["cutoffs"]["t_clock"]))
        directory, _ = open_parent(tree / "testbed/.probe")
        try:
            remove_tree_at(directory, ".git")
        finally:
            os.close(directory)
        shutil.copytree(work / "base-tree/.git", tree / "testbed/.git", symlinks=True)
        # Container creation can supply resolver and identity files from the
        # staging machine. Replace them before anything is made guest-visible.
        for name, data in {
            "hostname": b"world\n",
            "hosts": b"127.0.0.1 localhost\n::1 localhost\n",
            "resolv.conf": b"nameserver 10.0.0.1\noptions ndots:0\n",
        }.items():
            atomic_write(tree / "etc" / name, data)
        # Remove target bytecode and the same caches omitted by build_rootfs, so
        # sealcheck scans the tree that is actually made reachable in the image.
        from hermetic_slice.rootfs import is_cleanup_target
        remaining = [MAX_MEMBERS]
        def cleanup(directory, parts=()):
            if len(parts) > MAX_DEPTH:
                raise SealError("tree_depth_cap")
            with os.scandir(directory) as entries:
                for entry in entries:
                    remaining[0] -= 1
                    if remaining[0] < 0:
                        raise SealError("tree_entry_cap")
                    path = parts + (entry.name,)
                    if is_cleanup_target(path) or (path[:1] == ("testbed",) and entry.name == "__pycache__"):
                        remove_tree_at(directory, entry.name)
                    elif entry.is_dir(follow_symlinks=False):
                        child = open_child(directory, entry.name)
                        try:
                            cleanup(child, path)
                        finally:
                            os.close(child)
        directory, _ = open_parent(tree / ".probe")
        try:
            cleanup(directory)
        finally:
            os.close(directory)
        epoch = int(datetime.fromisoformat(task["cutoffs"]["t_clock"]).timestamp())
        normalise_tree(tree, epoch)
        normalise_tree(work / "base-tree", epoch)
    elif action == "rootfs":
        from hermetic_slice.rootfs import build_rootfs
        task = read_json(task_dir / "task.json")
        result = build_rootfs(tree, work / "rootfs.img", world_id=instance,
                              t_clock=datetime.fromisoformat(task["cutoffs"]["t_clock"]),
                              sealcheck_bin=work / "sealcheck", work_dir=work)
        atomic_write(work / "rootfs-report.json", encoded(result))
    else:
        raise SealError("unknown_worker_step")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SealError("invalid_arguments")


def run(argv=None):
    parser = Parser(prog="e2e-seal", allow_abbrev=False)
    parser.add_argument("instance")
    parser.add_argument("work", nargs="?")
    parser.add_argument("--sealcheck", default=os.environ.get("HERMETIC_SEALCHECK_BIN"))
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.]+__[A-Za-z0-9_.-]+-[0-9]{1,12}", args.instance) or len(args.instance) > 200:
        raise SealError("invalid_instance_id")
    fixture = TOP / "scripts/integration/fixtures/swebench" / (args.instance + ".json")
    raw, row, digest = load_record(fixture, args.instance, fixture.with_suffix(".source.json"))
    if not args.sealcheck:
        raise SealError("sealcheck_binary_required")
    tool = read_regular_file_bounded(args.sealcheck, MAX_TOOL_BYTES)
    if args.work is not None:
        validate_path(args.work)
    parent, name, directory, work_path = create_work(str(__file__), args.work)
    work = Path(work_path)
    step = "record"
    try:
        os.umask(0o077)
        atomic_write(work / "record.json", encoded(row))
        atomic_write(work / "record-source.json", encoded({
            "source": "scripts/integration/fixtures/swebench/" + fixture.name,
            "source_sha256": digest, "staged_sha256": hashlib.sha256(encoded(row)).hexdigest(),
        }))
        atomic_write(work / "sealcheck", tool)
        fd = open_regular(work / "sealcheck", MAX_TOOL_BYTES)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        emit(step, "pass", sha256=digest, seal_level="repo_only", substrate_at_t="none")
        os.mkdir(work / "home", 0o700)
        os.mkdir(work / "tmp", 0o700)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "TZ": "UTC",
               "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "PYTHONDONTWRITEBYTECODE": "1"}
        if os.environ.get("GITHUB_TOKEN"):
            env["GITHUB_TOKEN"] = os.environ["GITHUB_TOKEN"]
        image = "swebench/sweb.eval.x86_64." + args.instance.lower().replace("__", "_1776_") + ":latest"
        step = "image_export"
        # Pin the local image ID first; never pull or execute benchmark code.
        inspection = command(["docker", "image", "inspect", image], env=env)
        info = parse_json_bytes(inspection, MAX_REPORT_BYTES)
        if not isinstance(info, list) or len(info) != 1 or not isinstance(info[0], dict):
            raise SealError("invalid_image_inspection")
        image_id = info[0].get("Id")
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise SealError("invalid_image_id")
        atomic_write(work / "source-inspect.json", inspection)
        container = command(["docker", "create", "--pull", "never", "--network", "none",
                             "--hostname", "world", "--entrypoint", "/bin/true", image_id], env=env).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise SealError("invalid_container_id")
        try:
            command(["docker", "export", container], cap=MAX_EXPORT_BYTES, output=work / "source.tar", env=env)
        finally:
            command(["docker", "rm", "-f", container], env=env)
        emit(step, "pass", image_id=image_id)
        for action in ("unpack", "intake", "repository", "rootfs"):
            step = action
            command([sys.executable, "-I", "-B", str(Path(__file__).absolute()), "--worker", action,
                     str(work), args.instance], env=env)
            emit(step, "pass", **({"d4": "pass"} if action == "rootfs" else {}))
        task_dir = work / "tasks" / args.instance
        task = read_json(task_dir / "task.json")
        clock = task["cutoffs"]["t_clock"]
        scans = [
            ("sealcheck_tiers", [str(work / "sealcheck"), "scan", "--task", str(task_dir),
                                 "--base-tree", str(work / "base-tree"), "--root", str(work / "source-tree"),
                                 "--oci-inspect", str(work / "source-inspect.json")]),
            ("D8", [str(work / "sealcheck"), "d8", "--root", str(work / "source-tree"), "--t-clock", clock]),
            ("D10", [sys.executable, "-I", "-B", "-c",
                      "import sys; sys.path.insert(0, sys.argv.pop(1)); from hermetic_d10.__main__ import main; raise SystemExit(main())",
                      str(TOP / "python"), "--root", str(work / "source-tree"), "--t-clock", clock]),
        ]
        for step, argv in scans:
            report = command(argv, env=env)
            value = parse_json_bytes(report, MAX_REPORT_BYTES)
            if not isinstance(value, dict):
                raise SealError("invalid_scan_report")
            if value.get("gate") is True or value.get("verdict") == "gate":
                raise SealError("detector_gate")
            atomic_write(work / (step + ".json"), report)
            emit(step, "pass", findings=len(value.get("findings", [])))
        step = "world_manifest"
        # These inputs must come from the package-world and trust construction
        # components. Empty roots or arbitrary exemption lists would certify a
        # different world. Do not publish a manifest or success in their absence.
        emit(step, "open", reason="package_world_and_trust_evidence_unavailable",
             missing=["D5b_inventory_and_release_metadata", "package_closure_and_baseline",
                      "substrate_inventory_and_exemptions", "installed_world_trust_and_run_spec"],
             detectors={"D7": "not_applicable_without_deep_audit", "D11": "post_run_only",
                        "D12": "requires_runtime_probe"},
             oracle_inputs="prepared_host_only_not_executed")
        return 1
    except SealError as exc:
        detail = {}
        if isinstance(exc, CommandFailure) and exc.output:
            filename = step + ".failed-output"
            atomic_write(work / filename, exc.output)
            detail["private_report"] = filename
        emit(step, "fail", reason=str(exc), **detail)
        return 1
    except Exception:
        emit(step, "fail", reason="staging_operation_failed")
        return 1
    finally:
        # Retain successful and failed artifacts for the host fix round.
        os.close(directory)
        os.close(parent)


def main():
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "--worker":
            worker(sys.argv[2], sys.argv[3], sys.argv[4])
            return 0
        return run()
    except Exception:
        emit("preflight", "fail", reason="invalid_or_unavailable_input")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
