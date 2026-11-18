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
from hermetic_d7.normalise import HermeticD7Error
from hermetic_d7.recipe import RecipeError, RecipeSecurityError
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
MAX_ROOTFS_BYTES = 64 * 1024**3


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


def new_directory(path):
    """Create and pin a directory after checking every ancestor without following links."""
    parent, leaf = open_parent(path)
    try:
        os.mkdir(leaf, 0o700, dir_fd=parent)
        return open_child(parent, leaf)
    finally:
        os.close(parent)


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
            root = new_directory(destination)
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
    os.close(new_directory(output))
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


def sealed_provenance():
    """D10 provenance manifest for the archived records this seal ships (none)."""
    from hermetic_d10.provenance import build_provenance
    return build_provenance([], [])


def sealed_recipe(tree=None, build_record=None):
    """D7 build recipe for artifacts built from source in the world."""
    from hermetic_d7.recipe import build_recipe
    if tree is not None and os.path.isdir(tree):
        return build_recipe(tree, build_manifest=build_record)
    if build_record is not None:
        return build_recipe(None, build_manifest=build_record)
    return None


def validate_scan_report(step, value):
    """Exit zero alone cannot certify coverage of every stored payload."""
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        raise SealError("invalid_scan_report")
    findings = value["findings"]
    if any(not isinstance(f, dict) or f.get("severity") not in ("gate", "review", "info")
           or f.get("visibility", "agent_visible") not in ("agent_visible", "image_only")
           for f in findings):
        raise SealError("invalid_scan_report")
    if step == "D10":
        if value.get("detector") != "D10" or value.get("verdict") not in ("pass", "gate"):
            raise SealError("invalid_scan_report")
        if value.get("complete") is not True:
            raise SealError("detector_incomplete")
        provenance = value.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("verdict") not in ("verified", "gate"):
            raise SealError("d10_provenance_unverified")
        gated = value["verdict"] == "gate" or provenance["verdict"] == "gate"
    else:
        if value.get("schema") != "hermetic-sealcheck/v0" or type(value.get("gate")) is not bool:
            raise SealError("invalid_scan_report")
        if not isinstance(value.get("not_covered", []), list):
            raise SealError("invalid_scan_report")
        if value.get("not_covered") or any(f.get("channel") == "d8_error" for f in findings):
            raise SealError("detector_incomplete")
        gated = value["gate"]
    if gated or any(f.get("severity") == "gate" and
                    f.get("visibility", "agent_visible") == "agent_visible" for f in findings):
        raise SealError("detector_gate")
    return len(findings)


def file_evidence(path, cap):
    """Stream a pinned artifact, rejecting growth and returning no host metadata."""
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(open_regular(path, cap), "rb") as stream:
        while True:
            chunk = stream.read(min(IO_CHUNK_BYTES, cap - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                raise SealError("artifact_byte_cap")
            digest.update(chunk)
    return {"digest": "sha256:" + digest.hexdigest(), "size_bytes": size}


def prepare_bundle_evidence(work, instance):
    """Retain verified construction outputs without inventing missing world inputs.

    Oracle patches, raw OCI metadata, source exports and credentials are deliberately
    outside this handoff. This record is staging evidence, not a shippable bundle.
    """
    work = Path(work)
    task_path = work / "tasks" / instance / "task.json"
    task_raw = read_regular_file_bounded(task_path, MAX_REPORT_BYTES)
    task = parse_json_bytes(task_raw, MAX_REPORT_BYTES)
    if not isinstance(task, dict) or task.get("instance_id") != instance:
        raise SealError("task_identity_mismatch")
    services = task.get("test_services", [])
    if services not in ([], ["httpbin-v1"]):
        raise SealError("invalid_test_services")
    reports = {}
    for step in ("sealcheck_tiers", "D8", "D10"):
        raw = read_regular_file_bounded(work / (step + ".json"), MAX_REPORT_BYTES)
        report = parse_json_bytes(raw, MAX_REPORT_BYTES)
        validate_scan_report(step, report)
        reports[step] = {"digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                         "size_bytes": len(raw)}
    rootfs = file_evidence(work / "rootfs.img", MAX_ROOTFS_BYTES)
    build = read_json(work / "rootfs-report.json")
    if (not isinstance(build, dict) or build.get("d4") != "pass" or build.get("sha256") != rootfs["digest"][7:]
            or type(build.get("size_bytes")) is not int or build["size_bytes"] != rootfs["size_bytes"]):
        raise SealError("rootfs_evidence_mismatch")
    evidence = {
        "schema": "hermetic-bundle-evidence/v1", "task_id": instance,
        "seal_level": "repo_only", "substrate_at_t": "none", "complete": False,
        "rootfs": rootfs, "scans": reports,
        "task": {"digest": "sha256:" + hashlib.sha256(task_raw).hexdigest(),
                 "size_bytes": len(task_raw)},
        "test_services": services,
    }
    if (work / "substrate-inventory.json").exists():
        inv_raw = read_regular_file_bounded(work / "substrate-inventory.json", MAX_REPORT_BYTES)
        inv_data = parse_json_bytes(inv_raw, MAX_REPORT_BYTES)
        evidence["substrate_inventory"] = {
            "digest": "sha256:" + hashlib.sha256(inv_raw).hexdigest(),
            "size_bytes": len(inv_raw),
            "entries_count": len(inv_data.get("entries", [])),
        }
    exemption_substrate_at_t = None
    if (work / "exemptions.json").exists():
        ex_raw = read_regular_file_bounded(work / "exemptions.json", MAX_REPORT_BYTES)
        ex_data = parse_json_bytes(ex_raw, MAX_REPORT_BYTES)
        ex_list = ex_data.get("exemption_list", [])
        evidence["exemption_list"] = ex_list
        evidence["exemption_list_digest"] = "sha256:" + hashlib.sha256(ex_raw).hexdigest()
        exemption_substrate_at_t = "partial" if ex_list else "full"
        evidence["substrate_at_t"] = exemption_substrate_at_t
    if (work / "d5b-inventory.json").exists():
        d5b_raw = read_regular_file_bounded(work / "d5b-inventory.json", MAX_REPORT_BYTES)
        d5b_data = parse_json_bytes(d5b_raw, MAX_REPORT_BYTES)
        pkgs = d5b_data.get("inventory", {}).get("packages", d5b_data.get("packages", []))
        evidence["d5b_inventory"] = {
            "digest": "sha256:" + hashlib.sha256(d5b_raw).hexdigest(),
            "size_bytes": len(d5b_raw),
            "packages_count": len(pkgs),
            "substrate_entries_count": len(d5b_data.get("substrate", [])),
        }
        if "substrate_at_t" in d5b_data:
            d5b_sub = d5b_data["substrate_at_t"]
            order = {"none": 0, "partial": 1, "full": 2}
            if d5b_sub in order:
                if exemption_substrate_at_t is not None and exemption_substrate_at_t in order:
                    if order[d5b_sub] < order[exemption_substrate_at_t]:
                        evidence["substrate_at_t"] = d5b_sub
                    else:
                        evidence["substrate_at_t"] = exemption_substrate_at_t
                else:
                    evidence["substrate_at_t"] = d5b_sub
            else:
                evidence["substrate_at_t"] = d5b_sub
    atomic_write(work / "bundle-evidence.json", encoded(evidence))
    return evidence


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
        from hermetic_slice.netvm import RESOLV_CONF
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
            "resolv.conf": RESOLV_CONF.encode("ascii"),
        }.items():
            atomic_write(tree / "etc" / name, data)
        # Remove bytecode caches and the same caches omitted by build_rootfs, so
        # sealcheck scans the tree that is actually made reachable in the image.
        # TR-SEAL-3 removes __pycache__ from the repository; outside it, clamping
        # mtimes to T_clock (normalise_tree) leaves every timestamp-based cache
        # stale (D3), and Python would only recompile it, so caches are removed
        # everywhere and rebuilt in the agent's overlay.
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
                    if is_cleanup_target(path) or (entry.name == "__pycache__" and entry.is_dir(follow_symlinks=False)):
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
    elif action == "evidence":
        prepare_bundle_evidence(work, instance)
    else:
        raise SealError("unknown_worker_step")


def validate_d5b_inventory_data(data):
    if not isinstance(data, dict):
        raise SealError("invalid_d5b_inventory_format")
    inv = data.get("inventory")
    if inv is not None:
        if not isinstance(inv, dict) or not isinstance(inv.get("packages"), list):
            raise SealError("invalid_d5b_inventory_packages")
    elif not isinstance(data.get("packages"), list):
        raise SealError("invalid_d5b_inventory_packages")
    substrate = data.get("substrate")
    if substrate is not None:
        if not isinstance(substrate, list):
            raise SealError("invalid_d5b_substrate_format")
        for entry in substrate:
            if not isinstance(entry, dict):
                raise SealError("invalid_d5b_substrate_entry")
            if not isinstance(entry.get("name"), str) or not entry["name"]:
                raise SealError("invalid_d5b_substrate_entry_name")
            if not isinstance(entry.get("version"), str) or not entry["version"]:
                raise SealError("invalid_d5b_substrate_entry_version")
            digest = entry.get("digest")
            if not isinstance(digest, str) or not re.fullmatch(r"^(sha256|blake3):[0-9a-f]{64}$", digest):
                raise SealError("invalid_d5b_substrate_entry_digest")
            date_val = entry.get("date")
            if not isinstance(date_val, str) or not re.fullmatch(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})?)?$", date_val):
                raise SealError("invalid_d5b_substrate_entry_date")
    sub_at_t = data.get("substrate_at_t")
    if sub_at_t is not None and sub_at_t not in ("full", "partial", "none"):
        raise SealError("invalid_d5b_substrate_at_t")
    d5b_report = data.get("d5b_report")
    if d5b_report is not None and isinstance(d5b_report, dict):
        if data.get("mode") == "strict" and d5b_report.get("result") == "gate":
            raise SealError("d5b_inventory_gate")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SealError("invalid_arguments")


def run(argv=None):
    parser = Parser(prog="e2e-seal", allow_abbrev=False)
    parser.add_argument("instance")
    parser.add_argument("work", nargs="?")
    parser.add_argument("--sealcheck", default=os.environ.get("HERMETIC_SEALCHECK_BIN"))
    parser.add_argument("--d5b-inventory", dest="d5b_inventory", default=None)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[0-9]{1,12}", args.instance) or len(args.instance) > 200:
        raise SealError("invalid_instance_id")
    fixture = TOP / "scripts/integration/fixtures/swebench" / (args.instance + ".json")
    raw, row, digest = load_record(fixture, args.instance, fixture.with_suffix(".source.json"))
    if not args.sealcheck:
        raise SealError("sealcheck_binary_required")
    tool = read_regular_file_bounded(args.sealcheck, MAX_TOOL_BYTES)
    d5b_raw = None
    if args.d5b_inventory is not None:
        validate_path(args.d5b_inventory)
        d5b_raw = read_regular_file_bounded(args.d5b_inventory, MAX_REPORT_BYTES)
        d5b_json = parse_json_bytes(d5b_raw, MAX_REPORT_BYTES)
        validate_d5b_inventory_data(d5b_json)
    if args.work is not None:
        validate_path(args.work)
    parent, name, directory, work_path = create_work(str(__file__), args.work)
    work = Path(work_path)
    step = "record"
    try:
        os.umask(0o077)
        if d5b_raw is not None:
            atomic_write(work / "d5b-inventory.json", d5b_raw)
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
        # A repo_only seal ships no sealer-built web archive, so its provenance
        # manifest is empty: any WARC record found in the tree gates the seal.
        atomic_write(work / "d10-provenance.json", sealed_provenance())
        # Emit d7-recipe.json for the sealed world root (outside the world tree).
        step = "d7_recipe"
        build_rec_path = work / "build-record.json"
        try:
            build_rec = None
            try:
                st = os.lstat(build_rec_path)
                if stat.S_ISLNK(st.st_mode):
                    raise RecipeSecurityError(f"build manifest {build_rec_path!r} is a symlink")
                if not stat.S_ISREG(st.st_mode):
                    raise RecipeSecurityError(f"build manifest {build_rec_path!r} is not a regular file")
                build_rec = build_rec_path
            except FileNotFoundError:
                build_rec = None
            recipe_data = sealed_recipe(work / "source-tree", build_record=build_rec)
        except (RecipeError, HermeticD7Error) as exc:
            raise SealError(f"d7_recipe_{type(exc).__name__}") from exc
        if recipe_data is not None:
            atomic_write(work / "d7-recipe.json", recipe_data)

        # Inventory substrate and generate named exemptions for post-cutoff base environment files
        ex_path = None
        if (work / "source-tree").is_dir():
            from hermetic_slice.substrate import (
                inventory_substrate,
                generate_exemptions,
                write_substrate_outputs,
            )
            clock_iso = clock.replace("Z", "+00:00") if clock.endswith("Z") else clock
            t_clock_dt = datetime.fromisoformat(clock_iso)
            substrate_inv = inventory_substrate(work / "source-tree")
            exemptions_doc = generate_exemptions(
                work / "source-tree",
                substrate_inv,
                t_clock_dt,
                oci_inspect_path=work / "source-inspect.json",
            )
            _, ex_path = write_substrate_outputs(work, substrate_inv, exemptions_doc)

        scans = [
            ("sealcheck_tiers", [str(work / "sealcheck"), "scan", "--task", str(task_dir),
                                 "--base-tree", str(work / "base-tree"), "--root", str(work / "source-tree"),
                                 "--oci-inspect", str(work / "source-inspect.json"),
                                 *([ "--exemptions", str(ex_path)] if ex_path else [])]),
            ("D8", [str(work / "sealcheck"), "d8", "--root", str(work / "source-tree"), "--t-clock", clock]),
            ("D10", [sys.executable, "-I", "-B", "-c",
                      "import sys; sys.path.insert(0, sys.argv.pop(1)); from hermetic_d10.__main__ import main; raise SystemExit(main())",
                      str(TOP / "python"), "--root", str(work / "source-tree"), "--t-clock", clock,
                      "--provenance", str(work / "d10-provenance.json")]),
        ]
        for step, argv in scans:
            report = command(argv, env=env)
            value = parse_json_bytes(report, MAX_REPORT_BYTES)
            findings = validate_scan_report(step, value)
            atomic_write(work / (step + ".json"), report)
            emit(step, "pass", findings=findings)
        step = "bundle_evidence"
        command([sys.executable, "-I", "-B", str(Path(__file__).absolute()), "--worker", "evidence",
                 str(work), args.instance], env=env)
        emit(step, "pass", artifact="bundle-evidence.json", complete=False)
        step = "world_manifest"
        # These inputs must come from the package-world and trust construction
        # components. Empty roots or arbitrary exemption lists would certify a
        # different world. Do not publish a manifest or success in their absence.
        missing = [
            "canonical_repository_tree_digest",
            "D5b_inventory_and_release_metadata",
            "package_closure_and_baseline",
            "installed_world_trust_and_run_spec",
        ]
        if (work / "d5b-inventory.json").exists():
            missing.remove("D5b_inventory_and_release_metadata")
        emit(step, "open", reason="package_world_and_trust_evidence_unavailable",
             missing=missing,
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
