"""Offline stage-one integration regressions; no Docker daemon or VM required."""

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import zlib

import pytest

ROOT = Path(__file__).absolute().parents[2]
HELPER = ROOT / "scripts/integration/e2e_seal.py"
spec = importlib.util.spec_from_file_location("e2e_seal", HELPER)
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)
INSTANCE = "psf__requests-2317"
FIXTURE = ROOT / "scripts/integration/fixtures/swebench" / (INSTANCE + ".json")


def test_offline_record_known_answer_and_provenance():
    raw, row, digest = e2e.load_record(FIXTURE, INSTANCE, FIXTURE.with_suffix(".source.json"))
    assert digest == "4069e71d0cb3d5927ca1ed005a9ee2f6f73fef9ea7136e6115436089980b368e"
    assert raw == (ROOT / "python/tests/fixtures/grader" / (INSTANCE + ".row.json")).read_bytes()
    assert row["base_commit"] == "091991be0da19de9108dbe5e3752917fea3d7fdc"
    assert "to_native_string(method)" in row["patch"]
    assert len(row["FAIL_TO_PASS"]) == 8
    assert "test_requests.py::TestTimeout::test_encoded_methods" in row["FAIL_TO_PASS"]
    assert len(row["PASS_TO_PASS"]) > 100


@pytest.mark.parametrize("field,value", [
    ("instance_id", "../secret"), ("repo", "../.."), ("base_commit", "--upload-pack=secret"),
    ("problem_statement", None), ("patch", "\ud800"), ("test_patch", ""),
    ("FAIL_TO_PASS", []), ("PASS_TO_PASS", [None]),
    ("FAIL_TO_PASS", ["same", "same"]),
])
def test_hostile_record_refused(field, value):
    row = json.loads(FIXTURE.read_bytes())
    row[field] = value
    with pytest.raises(Exception):
        e2e.validate_record(row, INSTANCE)


def test_string_test_lists_and_disjointness():
    row = json.loads(FIXTURE.read_bytes())
    row["FAIL_TO_PASS"] = '["test_a"]'
    assert e2e.validate_record(row, INSTANCE)["FAIL_TO_PASS"] == ["test_a"]
    row["PASS_TO_PASS"] = ["test_a"]
    with pytest.raises(e2e.SealError, match="overlapping"):
        e2e.validate_record(row, INSTANCE)


@pytest.mark.parametrize("kind", ["symlink", "ancestor", "fifo", "oversize", "digest"])
def test_record_io_fails_closed(tmp_path, monkeypatch, kind):
    record = tmp_path / "row.json"
    record.write_bytes(FIXTURE.read_bytes())
    source = tmp_path / "source.json"
    source.write_text('{"sha256":"wrong"}')
    if kind == "symlink":
        record = tmp_path / "link"
        record.symlink_to(FIXTURE)
    elif kind == "ancestor":
        link = tmp_path / "linked"
        link.symlink_to(tmp_path, target_is_directory=True)
        record = link / "row.json"
    elif kind == "fifo":
        record.unlink()
        os.mkfifo(record)
    elif kind == "oversize":
        monkeypatch.setattr(e2e, "MAX_RECORD_BYTES", 1)
    with pytest.raises(Exception):
        e2e.load_record(record, INSTANCE, source if kind == "digest" else None)


def make_tar(path, entries):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, value in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if kind == "dir" else 0o644
            if kind == "dir":
                member.type = tarfile.DIRTYPE
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = value
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = value
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
            elif kind == "device":
                member.type = tarfile.CHRTYPE
            else:
                member.size = len(value)
            archive.addfile(member, io.BytesIO(value) if kind == "file" else None)


@pytest.mark.parametrize("entries", [
    [("../escaped", "file", b"secret")], [("/escaped", "file", b"secret")],
    [("a", "symlink", "/"), ("a/escaped", "file", b"secret")],
    [("fifo", "fifo", None)], [("dev", "device", None)],
    [("a", "file", b"a"), ("./a", "file", b"b")],
    [("a", "hardlink", "../../host")],
    [("a", "symlink", "/host"), ("b", "hardlink", "a")],
])
def test_export_rejected_before_writes(tmp_path, entries):
    archive = tmp_path / "source.tar"
    destination = tmp_path / "tree"
    make_tar(archive, entries)
    with pytest.raises(e2e.SealError):
        e2e.unpack_export(archive, destination)
    assert not destination.exists()
    assert not (tmp_path / "escaped").exists()


def test_export_import_keeps_guest_links_and_breaks_hardlinks(tmp_path):
    archive = tmp_path / "source.tar"
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    destination = tmp_path / "tree"
    make_tar(archive, [(".", "dir", None), ("usr", "dir", None),
                       ("usr/file", "file", b"payload"),
                       ("bin", "symlink", str(outside)),
                       ("copy", "hardlink", "usr/file")])
    e2e.unpack_export(archive, destination)
    assert (destination / "usr/file").read_bytes() == b"payload"
    assert (destination / "copy").read_bytes() == b"payload"
    assert (destination / "usr/file").stat().st_ino != (destination / "copy").stat().st_ino
    assert os.readlink(destination / "bin") == str(outside)
    e2e.normalise_tree(destination, 1700000000)
    assert int((destination / "usr/file").stat().st_mtime) == 1700000000
    assert outside.read_bytes() == b"untouched"
    assert int(outside.stat().st_mtime) != 1700000000


@pytest.mark.parametrize("operation", ["unpack", "oracle"])
def test_output_symlink_ancestor_is_rejected_before_mkdir(tmp_path, operation):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    destination = link / "output"
    archive = tmp_path / "source.tar"
    make_tar(archive, [("file", "file", b"payload")])
    _, row, _ = e2e.load_record(FIXTURE, INSTANCE)
    task = tmp_path / "task"
    task.mkdir()
    (task / "task.json").write_text('{"cutoffs":{"t_clock":"2014-01-01T00:00:00Z"}}')
    with pytest.raises(OSError):
        if operation == "unpack":
            e2e.unpack_export(archive, destination)
        else:
            e2e.prepare_oracle(row, task, destination)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("cap,value", [("MAX_FILE_BYTES", 1), ("MAX_TREE_BYTES", 1), ("MAX_MEMBERS", 1)])
def test_export_resource_caps(tmp_path, monkeypatch, cap, value):
    archive = tmp_path / "source.tar"
    make_tar(archive, [("a", "file", b"xx"), ("b", "file", b"yy")])
    monkeypatch.setattr(e2e, cap, value)
    with pytest.raises(e2e.SealError, match="cap"):
        e2e.unpack_export(archive, tmp_path / "tree")
    assert not (tmp_path / "tree").exists()


def test_pax_header_allocation_is_capped(tmp_path, monkeypatch):
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
        entry = tarfile.TarInfo("a")
        entry.pax_headers = {"comment": "x" * 8192}
        tar.addfile(entry, io.BytesIO())
    monkeypatch.setattr(e2e, "MAX_HEADER_READ", 4096)
    with pytest.raises(e2e.SealError, match="header_cap"):
        e2e.unpack_export(archive, tmp_path / "tree")
    assert not (tmp_path / "tree").exists()


@pytest.mark.parametrize("entry", ["alternates", "http-alternates", "commondir", "gitdir", "link"])
def test_git_cannot_reach_host_files(tmp_path, entry):
    git = tmp_path / ".git"
    git.mkdir()
    if entry == "link":
        (git / entry).symlink_to("/etc/passwd")
    else:
        (git / entry).write_text("/host/path")
    with pytest.raises(e2e.SealError):
        e2e.check_git_tree(git)


def test_git_local_configuration_cannot_load_host_config(tmp_path):
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text('[include]\npath=/host/secret\n[core]\nfsmonitor=/host/execute\n')
    e2e.check_git_tree(git)
    assert (git / "config").read_bytes() == b"[core]\nrepositoryformatversion = 0\nbare = false\n"
    assert stat.S_IMODE((git / "config").stat().st_mode) == 0o600


def test_repository_worker_seals_real_objects_and_preserves_source_edits(tmp_path):
    work = tmp_path / "work"
    repo = work / "source-tree/testbed"
    git = repo / ".git"
    (git / "objects").mkdir(parents=True)
    (git / "refs/heads").mkdir(parents=True)
    def object_id(kind, data):
        raw = kind.encode() + b" " + str(len(data)).encode() + b"\0" + data
        oid = hashlib.sha1(raw).hexdigest()
        location = git / "objects" / oid[:2] / oid[2:]
        location.parent.mkdir(exist_ok=True)
        location.write_bytes(zlib.compress(raw))
        return oid
    blob = object_id("blob", b"base source\n")
    tree = object_id("tree", b"100644 source.py\0" + bytes.fromhex(blob))
    def commit(tree_id, parent=""):
        data = f"tree {tree_id}\n{parent}author Fixture <fixture@example.invalid> 1388534400 +0000\ncommitter Fixture <fixture@example.invalid> 1388534400 +0000\n\nfixture\n"
        return object_id("commit", data.encode())
    base = commit(tree)
    secret = object_id("blob", b"post-cutoff secret\n")
    fix_tree = object_id("tree", b"100644 source.py\0" + bytes.fromhex(secret))
    fix = commit(fix_tree, f"parent {base}\n")
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "refs/heads/main").write_text(fix + "\n")
    (git / "config").write_text("[core]\nbare=false\n")
    (repo / "source.py").write_bytes(b"image environment setup edit\n")
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__/stale.pyc").write_bytes(b"stale")
    log = work / "source-tree/var/log"
    log.mkdir(parents=True)
    (log / "dated.log").write_text("host date")
    etc = work / "source-tree/etc"
    etc.mkdir()
    for name in ("hostname", "hosts", "resolv.conf"):
        (etc / name).write_text("staging-host-identity")
    outside = work / "outside"
    outside.write_bytes(b"untouched")
    original_mtime = outside.stat().st_mtime_ns
    (repo / "link").symlink_to(outside)
    row = json.loads(FIXTURE.read_bytes())
    instance = "fixture__repo-1"
    row.update(instance_id=instance, repo="fixture/repo", base_commit=base)
    (work / "record.json").write_bytes(e2e.encoded(row))
    task = work / "tasks" / instance
    task.mkdir(parents=True)
    (task / "task.json").write_text('{"cutoffs":{"t_clock":"2014-01-01T00:00:00Z"}}')
    for name in ("home", "tmp"):
        (work / name).mkdir()
    result = subprocess.run([sys.executable, "-I", "-B", str(HELPER), "--worker", "repository", str(work), instance],
                            env={"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "TMPDIR": str(work / "tmp")},
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout
    assert (work / "base-tree/source.py").read_bytes() == b"base source\n"
    assert (repo / "source.py").read_bytes() == b"image environment setup edit\n"
    assert not (repo / "__pycache__").exists()
    assert not (log / "dated.log").exists()
    assert outside.read_bytes() == b"untouched"
    assert outside.stat().st_mtime_ns == original_mtime
    assert int((repo / "source.py").stat().st_mtime) == 1388534400
    assert (etc / "hostname").read_bytes() == b"world\n"
    assert (etc / "hosts").read_bytes() == b"127.0.0.1 localhost\n::1 localhost\n"
    assert (etc / "resolv.conf").read_bytes() == b"nameserver 10.0.2.3\noptions ndots:0\n"
    objects = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
                             env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
                             capture_output=True, timeout=10, check=True)
    assert set(objects.stdout.decode().splitlines()) == {base, tree, blob}


def test_oracle_secrets_private_and_exact(tmp_path):
    _, row, _ = e2e.load_record(FIXTURE, INSTANCE)
    task = tmp_path / "task"
    task.mkdir()
    (task / "task.json").write_text('{"cutoffs":{"t_clock":"2014-01-01T00:00:00Z"}}')
    output = tmp_path / "oracle"
    e2e.prepare_oracle(row, task, output)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for entry in output.iterdir():
        assert stat.S_IMODE(entry.stat().st_mode) == 0o600
    assert (output / "gold.patch").read_bytes() == row["patch"].encode()
    assert (output / "test.patch").read_bytes() == row["test_patch"].encode()
    assert json.loads((output / "FAIL_TO_PASS.json").read_bytes()) == row["FAIL_TO_PASS"]
    assert json.loads((output / "inputs.json").read_bytes())["executed"] is False


def test_bounded_command_retains_private_failure_without_printing(capsys):
    with pytest.raises(e2e.CommandFailure) as error:
        e2e.command([sys.executable, "-I", "-c", "print('secret-host-clock'); raise SystemExit(2)"])
    assert error.value.output == b"secret-host-clock\n"
    assert str(error.value) == "step_exit_2"
    assert not capsys.readouterr().out


@pytest.mark.parametrize("scenario", ["cap", "timeout"])
def test_bounded_command_removes_partial_artifact(tmp_path, scenario):
    output = tmp_path / "export.tar"
    if scenario == "cap":
        code = "import sys; sys.stdout.buffer.write(b'x'*8192)"
        kwargs = {"cap": 100}
    else:
        code = "import time; print('partial', flush=True); time.sleep(30)"
        kwargs = {"timeout": 0.1}
    with pytest.raises(e2e.SealError, match=scenario):
        e2e.command([sys.executable, "-I", "-c", code], output=output, **kwargs)
    assert not output.exists()
    assert not output.with_suffix(".tar.partial").exists()


def test_bounded_command_publishes_only_after_success(tmp_path):
    output = tmp_path / "export.tar"
    e2e.command([sys.executable, "-I", "-c", "print('complete')"], output=output)
    assert output.read_bytes() == b"complete\n"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_bounded_command_never_deletes_preexisting_partial(tmp_path):
    output = tmp_path / "export.tar"
    partial = tmp_path / "export.tar.partial"
    partial.write_bytes(b"caller-owned")
    with pytest.raises(FileExistsError):
        e2e.command([sys.executable, "-I", "-c", "print('new')"], output=output)
    assert partial.read_bytes() == b"caller-owned"
    assert not output.exists()


def test_shell_invalid_input_is_json_and_creates_nothing(tmp_path):
    work = tmp_path / "new"
    result = subprocess.run(["bash", str(ROOT / "scripts/integration/e2e-seal.sh"), "../secret", str(work)],
                            capture_output=True, timeout=10)
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"step": "preflight", "verdict": "fail",
                                        "reason": "invalid_or_unavailable_input"}
    assert result.stderr == b""
    assert b"secret" not in result.stdout
    assert not work.exists()


@pytest.mark.parametrize("failure", [None, "intake", "sealcheck_tiers"])
def test_orchestration_is_ordered_and_stops_without_false_world(tmp_path, monkeypatch, capsys, failure):
    work = tmp_path / "work"
    tool = tmp_path / "sealcheck"
    tool.write_bytes(b"unused-in-this-orchestration-test")
    calls = []
    def fake_command(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return e2e.encoded([{"Id": "sha256:" + "a" * 64}])
        if argv[:2] == ["docker", "create"]:
            assert "--pull" in argv and "never" in argv and argv[-1] == "sha256:" + "a" * 64
            return ("b" * 64 + "\n").encode()
        if "--worker" in argv:
            action = argv[argv.index("--worker") + 1]
            if action == failure:
                raise e2e.CommandFailure(1, b"private reason")
            if action == "intake":
                task = work / "tasks" / INSTANCE
                task.mkdir(parents=True)
                (task / "task.json").write_text('{"cutoffs":{"t_clock":"2014-01-01T00:00:00Z"}}')
        if "scan" in argv:
            if failure == "sealcheck_tiers":
                raise e2e.CommandFailure(2, b'{"gate":true}')
            return b'{"schema":"hermetic-sealcheck/v0","gate":false,"findings":[],"not_covered":[]}'
        if "d8" in argv:
            return b'{"schema":"hermetic-sealcheck/v0","gate":false,"findings":[]}'
        if "--root" in argv:
            return b'{"detector":"D10","findings":[],"verdict":"pass","complete":true}'
        return b""
    monkeypatch.setattr(e2e, "command", fake_command)
    original_umask = os.umask(0o077)
    try:
        assert e2e.run([INSTANCE, str(work), "--sealcheck", str(tool)]) == 1
    finally:
        os.umask(original_umask)
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["seal_level"] == "repo_only"
    assert [c[1] for c in calls if c[0] == "docker"] == ["image", "create", "export", "rm"]
    assert not (work / "world-manifest.json").exists()
    if failure:
        assert events[-1]["step"] == failure
        assert events[-1]["verdict"] == "fail"
        assert (work / (failure + ".failed-output")).is_file()
    else:
        assert [e["step"] for e in events] == ["record", "image_export", "unpack", "intake", "repository",
                                                 "rootfs", "sealcheck_tiers", "D8", "D10", "bundle_evidence", "world_manifest"]
        assert events[-1]["verdict"] == "open"
        assert "D5b_inventory_and_release_metadata" in events[-1]["missing"]
        assert events[-1]["detectors"]["D11"] == "post_run_only"
    assert "private reason" not in json.dumps(events)
