"""Offline image preparation, hostile filesystem and handoff regressions."""

import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile

import pytest

from hermetic_slice.rootfs import make_tarinfo, write_rootfs_tar

INTEGRATION = Path(__file__).parents[2] / "scripts/integration"
sys.path.insert(0, str(INTEGRATION))
import agent_h_image as image


@pytest.mark.parametrize("script", ["build-agent-h-fixture.sh", "convert-agent-h-task.sh"])
def test_isolated_shell_entrypoints_load_their_modules(script):
    result = subprocess.run(["bash", str(INTEGRATION / script), "--help"],
                            capture_output=True, timeout=10)
    assert result.returncode == 0
    assert b"usage:" in result.stdout and not result.stderr


def test_builder_argument_errors_do_not_reflect_input():
    result = subprocess.run(["bash", str(INTEGRATION / "build-agent-h-fixture.sh"), "--private-value"],
                            capture_output=True, timeout=10)
    assert result.returncode != 0
    assert result.stderr == b"Agent image build refused: input\n"
    assert not result.stdout


def static_elf():
    raw = bytearray(120)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", raw, 18, 62)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 0, 0, 0, 0, len(raw), len(raw), 4096)
    return bytes(raw)


def task(tmp_path, **changes):
    root = tmp_path / "sealed"
    directory = root / "tasks/pytest-dev__pytest-6202"
    (directory / "agent").mkdir(parents=True)
    value = {"instance_id": "pytest-dev__pytest-6202", "base_commit": "a" * 40,
             "cutoffs": {"t_world": "2019-11-14T13:11:34Z", "t_clock": "2019-11-15T22:57:08Z"}}
    value.update(changes)
    (directory / "task.json").write_text(json.dumps(value))
    (directory / "agent/problem_statement.md").write_text("Fix collection.\n")
    return root


def test_elf_dependencies_and_host_runtime_are_read_without_execution():
    assert image.elf_dependencies(static_elf()) == (None, [])
    files = image.host_runtime()
    assert {"/bin/bash", "/bin/cat", "/bin/sed"} <= files.keys()
    assert image.elf_dependencies(files["/bin/bash"])[0] in files


@pytest.mark.parametrize("raw", [b"", b"not ELF", static_elf()[:100],
    static_elf()[:54] + b"\xff\xff\xff\xff" + static_elf()[58:]])
def test_elf_hostile_offsets_and_counts_fail_closed(raw):
    with pytest.raises(ValueError):
        image.elf_dependencies(raw)


def test_trusted_tools_build_offline_static_with_remapped_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("CARGO_HOME", str(tmp_path))
    monkeypatch.setenv("RUSTFLAGS", "private-host-value")
    seen = []
    def command(argv, **kwargs):
        seen.append(argv)
        assert "--offline" in argv and "--locked" in argv
        assert "RUSTFLAGS" not in kwargs["env"]
        flags = kwargs["env"]["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        assert flags[:2] == ["-C", "target-feature=+crt-static"]
        assert "--remap-path-prefix=" + str(image.TOP) + "=/src" in flags
        assert "--remap-path-prefix=" + str(tmp_path) + "=/build" in flags
        output = tmp_path / "cargo-target/x86_64-unknown-linux-gnu/release"
        output.mkdir(parents=True)
        for name in ("hermetic-execd", "hermetic-init", "hermetic-extract-agent", "hermetic-sealcheck"):
            (output / name).write_bytes(static_elf())
    monkeypatch.setattr(image, "command", command)
    binaries = image.build_tools(tmp_path)
    assert len(seen) == 1
    assert sorted(binaries) == ["hermetic-execd", "hermetic-extract-agent", "hermetic-init"]
    assert (tmp_path / "sealcheck").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "sealcheck").read_bytes() == static_elf()


def test_guest_links_resolve_inside_root_and_leaf_is_replaced(tmp_path):
    root = tmp_path / "tree"
    (root / "usr/sbin").mkdir(parents=True)
    (root / "sbin").symlink_to("/usr/sbin")
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    (root / "usr/sbin/hermetic-init").symlink_to(outside)
    tree = image.Tree(root)
    try:
        tree.write("sbin/hermetic-init", b"static", 0o755)
        assert tree.read("sbin/hermetic-init") == b"static"
        assert (root / "usr/sbin/hermetic-init").stat().st_mode & 0o777 == 0o755
        (root / "escape").symlink_to("../../outside")
        with pytest.raises(ValueError):
            tree.write("escape/should-not-exist", b"bad")
    finally:
        tree.close()
    assert outside.read_bytes() == b"secret"
    assert outside.stat().st_mode & 0o777 != 0o755


def test_guest_fifo_and_symlink_loop_are_bounded(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    (tmp_path / "loop").symlink_to("loop")
    tree = image.Tree(tmp_path)
    try:
        for path in ("fifo", "loop"):
            with pytest.raises(ValueError):
                tree.read(path)
    finally:
        tree.close()


def test_root_owned_tar_never_imports_staging_identity(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file").write_bytes(b"payload")
    (root / "link").symlink_to("file")
    os.link(root / "file", root / "hardlink")
    archive = tmp_path / "root.tar"
    write_rootfs_tar(root, archive, mtime_ceiling=1700000000, root_owned=True)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
    assert {m.name for m in members} == {".", "file", "hardlink", "link"}
    assert all((m.uid, m.gid, m.uname, m.gname) == (0, 0, "", "") for m in members)
    # The old/default ownership-preserving contract is unchanged.
    metadata = (root / "file").stat()
    assert make_tarinfo("file", metadata, 1700000000).uid == metadata.st_uid
    synthetic = os.stat_result((stat.S_IFREG | 0o644, 1, 1, 1, 12345, 54321, 7, 0, 9, 0))
    info = make_tarinfo("file", synthetic, 5, root_owned=True)
    assert (info.uid, info.gid, info.mode, info.mtime) == (0, 0, 0o644, 5)


def test_root_owned_override_validated_before_output_creation(tmp_path):
    with pytest.raises(ValueError):
        write_rootfs_tar(tmp_path, tmp_path / "never.tar", mtime_ceiling=0, root_owned=1)
    assert not (tmp_path / "never.tar").exists()


@pytest.mark.parametrize("changes", [{"instance_id": "other"}, {"base_commit": "secret"},
    {"cutoffs": {"t_world": "2023-11-14T22:13:20Z", "t_clock": "2019-11-15T22:57:08Z"}}])
def test_sealed_metadata_rejected_before_creating_work(tmp_path, changes):
    root = task(tmp_path, **changes)
    destination = tmp_path / "new"
    with pytest.raises(ValueError):
        image.run(["sealed", str(root), "pytest-dev__pytest-6202", str(destination)])
    assert not destination.exists()


def test_sealed_metadata_uses_only_issue_and_cutoffs(tmp_path):
    root = task(tmp_path)
    cutoffs, base, issue = image.task_inputs(root, "pytest-dev__pytest-6202")
    assert cutoffs == {"t_world": "2019-11-14T13:11:34Z", "t_clock": "2019-11-15T22:57:08Z"}
    assert base == "a" * 40 and issue == b"Fix collection.\n"
    with pytest.raises(ValueError):
        image.task_inputs(root, "../../host")


def test_export_pins_image_without_start_or_pull_and_cleans_up(tmp_path, monkeypatch):
    seen = []
    def command(argv, **kwargs):
        seen.append(argv)
        if argv[1:3] == ["image", "inspect"]:
            return json.dumps("sha256:" + "a" * 64).encode()
        if argv[1] == "create":
            assert argv[-1] == "sha256:" + "a" * 64
            return b"b" * 64
        if argv[1] == "export":
            raise ValueError("export failed")
        return b""
    monkeypatch.setattr(image, "command", command)
    with pytest.raises(ValueError):
        image.export_image("hermetic/pytest-dev__pytest-6202:sealed", tmp_path)
    assert seen[-1] == ["docker", "rm", "-f", "b" * 64]
    assert not any("start" in row or "run" in row or "pull" in row for row in seen)
    assert "--pull" in seen[1] and "never" in seen[1] and "none" in seen[1]


def test_fixture_pipeline_stages_exact_repo_and_publishes_after_d4(tmp_path, monkeypatch):
    monkeypatch.setattr(image, "host_runtime", lambda: {"/bin/" + n: static_elf() for n in ("bash", "cat", "sed")})
    monkeypatch.setattr(image, "build_tools", lambda work: {n: static_elf() for n in
        ("hermetic-execd", "hermetic-init", "hermetic-extract-agent")})
    builds = []
    def build(src, output, **kwargs):
        assert not (output.parent / "world.json").exists()
        assert kwargs["root_owned"] is True
        assert kwargs["t_clock"].isoformat() == "2023-11-14T22:13:20+00:00"
        builds.append(kwargs)
        output.write_bytes(b"D4-checked fixture")
        return {"sha256": "a" * 64, "d4": "pass", "skipped_special": []}
    monkeypatch.setattr(image, "build_rootfs", build)
    work = tmp_path / "new"
    previous = os.umask(0o022)
    try:
        assert image.run(["fixture", str(work)]) == 0
    finally:
        os.umask(previous)
    manifest = json.loads((work / "world.json").read_bytes())
    assert manifest["rootfs_digest"] == "sha256:" + "a" * 64
    assert manifest["checks"] == {"D4": "pass"}
    assert manifest["certified_world_bundle"] is False
    assert str(tmp_path) not in json.dumps(manifest)
    for directory in ("testbed", "smoke/base"):
        actual = work / "tree" / directory
        expected = INTEGRATION / "fixtures/grader-task/repo"
        assert sorted(p.relative_to(actual) for p in actual.rglob("*") if p.is_file()) == sorted(
            p.relative_to(expected) for p in expected.rglob("*") if p.is_file())
        for name in ("calc.py", "tests/test_calc.py"):
            assert (actual / name).read_bytes() == (expected / name).read_bytes()
    for name in ("world.json", "issue.txt"):
        assert (work / name).stat().st_mode & 0o777 == 0o600
    assert json.loads((work / "tree/etc/hermetic/run-spec.json").read_bytes()) == manifest["run_spec"]
    with pytest.raises(FileExistsError):
        image.run(["fixture", str(work)])


def test_failed_d4_never_publishes_manifest(tmp_path, monkeypatch):
    (tmp_path / "tree").mkdir()
    monkeypatch.setattr(image, "build_rootfs", lambda *a, **kw: {"d4": "fail"})
    with pytest.raises(ValueError):
        image.finish(tmp_path, "fixture", {"t_clock": image.FIXTURE_CLOCK}, {})
    assert not (tmp_path / "world.json").exists()


def test_sealed_pipeline_keeps_runtime_and_discards_container_identity(tmp_path, monkeypatch):
    root = task(tmp_path)
    instance = "pytest-dev__pytest-6202"
    def tools(work):
        return {"hermetic-execd": static_elf(), "hermetic-init": static_elf(),
                "hermetic-extract-agent": static_elf()}
    monkeypatch.setattr(image, "build_tools", tools)
    def command(argv, **kwargs):
        if argv[1:3] == ["image", "inspect"]:
            assert argv[-1] == "hermetic/" + instance + ":sealed"
            return json.dumps("sha256:" + "a" * 64).encode()
        if argv[1] == "create":
            return b"b" * 64
        if argv[1] == "export":
            with tarfile.open(kwargs["output"], "w") as tar:
                for name in ("etc/hostname", "etc/hosts", "etc/resolv.conf", "etc/machine-id",
                             "var/lib/dbus/machine-id", "testbed/source.py"):
                    data = b"container-secret"
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    tar.addfile(info, io.BytesIO(data))
                for name in ("bash", "cat", "sed"):
                    data = static_elf()
                    info = tarfile.TarInfo("usr/bin/" + name)
                    info.size = len(data)
                    info.mode = 0o755
                    tar.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo("bin")
                info.type, info.linkname = tarfile.SYMTYPE, "/usr/bin"
                tar.addfile(info)
        return b""
    monkeypatch.setattr(image, "command", command)
    def build(src, output, **kwargs):
        assert (src / "testbed/source.py").read_bytes() == b"container-secret"
        assert not (src / "task.json").exists()
        assert (src / "etc/hostname").read_bytes() == b"world\n"
        assert (src / "etc/machine-id").read_bytes() == b""
        assert (src / "var/lib/dbus/machine-id").read_bytes() == b""
        assert kwargs["t_clock"].isoformat() == "2019-11-15T22:57:08+00:00"
        return {"sha256": "c" * 64, "d4": "pass", "skipped_special": []}
    monkeypatch.setattr(image, "build_rootfs", build)
    work = tmp_path / "converted"
    previous = os.umask(0o022)
    try:
        assert image.run(["sealed", str(root), instance, str(work)]) == 0
    finally:
        os.umask(previous)
    manifest = json.loads((work / "world.json").read_bytes())
    assert manifest["source"] == {"base_commit": "a" * 40, "image_id": "sha256:" + "a" * 64}
    assert manifest["rootfs_digest"] == "sha256:" + "c" * 64
    assert manifest["run_spec"]["entrypoint"] == []
    assert "network" not in manifest["run_spec"]
    assert "container-secret" not in json.dumps(manifest)
    assert (work / "issue.txt").read_bytes() == b"Fix collection.\n"


def test_missing_guest_shell_and_oversize_binary_fail_closed(tmp_path, monkeypatch):
    tree = image.Tree(tmp_path)
    try:
        with pytest.raises(FileNotFoundError):
            image.check_guest_runtime(tree)
        tree.write("bin/bash", b"oversize")
        monkeypatch.setattr(image, "MAX_BINARY_BYTES", 4)
        with pytest.raises(ValueError):
            tree.read("bin/bash")
    finally:
        tree.close()


def test_task_runner_preflight_creates_no_directory(tmp_path, monkeypatch):
    import agent_h_run
    for name in tuple(os.environ):
        if name.startswith("HERMETIC_"):
            monkeypatch.delenv(name)
    work = tmp_path / "new"
    with pytest.raises(ValueError):
        agent_h_run.run([str(work)])
    assert not work.exists()


def test_task_runner_retains_private_evidence_directory(tmp_path, monkeypatch):
    import agent_h_run
    manifest = tmp_path / "world.json"
    manifest.write_text(json.dumps({"cutoffs": {"t_clock": image.FIXTURE_CLOCK}}))
    issue = tmp_path / "issue.txt"
    issue.write_text("fix")
    for key in ("HERMETIC_ROOTFS", "HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_AGENT_PYTHON"):
        monkeypatch.setenv(key, "/not-executed")
    monkeypatch.setenv("HERMETIC_AGENT_MANIFEST", str(manifest))
    monkeypatch.setenv("HERMETIC_AGENT_TASK", str(issue))
    monkeypatch.setenv("HERMETIC_AGENT_GATEWAY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HERMETIC_AGENT_MODEL", "pinned")
    seen = []
    def command(argv, **kwargs):
        seen.append((argv, kwargs))
        work = Path(kwargs["env"]["HERMETIC_AGENT_WORK"])
        assert (work / "config").stat().st_mode & 0o777 == 0o700
    monkeypatch.setattr(agent_h_run, "command", command)
    work = tmp_path / "new"
    assert agent_h_run.run([str(work)]) == 0
    assert work.stat().st_mode & 0o777 == 0o700
    assert len(seen) == 2 and "--no-run" in seen[0][0]
    assert seen[1][1]["timeout"] == agent_h_run.MAX_SESSION_SECONDS
    assert seen[1][1]["env"]["HERMETIC_AGENT_T_CLOCK"] == "1700000000"
    assert "--ignored" in seen[1][0] and "--exact" in seen[1][0]


@pytest.mark.parametrize("clock", ["1601-01-01T00:00:00Z", "1979-12-31T23:59:59Z",
                                  "2100-01-01T00:00:00Z", "9999-12-31T23:59:59Z"])
def test_converter_refuses_clocks_execd_cannot_boot_before_creating_work(tmp_path, clock):
    root = task(tmp_path, cutoffs={"t_world": clock, "t_clock": clock})
    work = tmp_path / "never"
    with pytest.raises(ValueError):
        image.run(["sealed", str(root), "pytest-dev__pytest-6202", str(work)])
    assert not work.exists()


@pytest.mark.parametrize("clock", ["1980-01-01T00:00:00Z", "2099-12-31T23:59:59Z"])
def test_converter_guest_clock_boundaries_match_execd(tmp_path, clock):
    root = task(tmp_path, cutoffs={"t_world": clock, "t_clock": clock})
    cutoffs, _, _ = image.task_inputs(root, "pytest-dev__pytest-6202")
    assert cutoffs["t_clock"] == clock


@pytest.mark.parametrize("non_executable", ["bash", "cat", "sed", "loader"])
def test_converter_refuses_runtime_without_execute_permission(tmp_path, non_executable):
    # A minimal ELF with PT_INTERP exercises the loader's mode as well as the
    # three required command modes, without executing any image-provided code.
    raw = bytearray(static_elf())
    raw.extend(bytes(56))
    interpreter = b"/lib/loader\0"
    struct.pack_into("<HH", raw, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", raw, 120, 3, 0, len(raw), 0, 0,
                     len(interpreter), len(interpreter), 1)
    raw.extend(interpreter)
    tree = image.Tree(tmp_path)
    try:
        for name in ("bash", "cat", "sed"):
            tree.write("bin/" + name, bytes(raw), 0o755)
        tree.write("lib/loader", static_elf(), 0o755)
        image.check_guest_runtime(tree)
        path = "lib/loader" if non_executable == "loader" else "bin/" + non_executable
        (tmp_path / path).chmod(0o644)
        with pytest.raises(ValueError, match="Agent image input refused"):
            image.check_guest_runtime(tree)
    finally:
        tree.close()


@pytest.mark.parametrize("clock", ["1601-01-01T00:00:00Z", "1979-12-31T23:59:59Z",
                                  "2100-01-01T00:00:00Z", "9999-12-31T23:59:59Z"])
def test_task_runner_refuses_unbootable_clock_before_creating_work(tmp_path, monkeypatch, clock):
    import agent_h_run
    manifest = tmp_path / "world.json"
    manifest.write_text(json.dumps({"cutoffs": {"t_clock": clock}}))
    issue = tmp_path / "issue.txt"
    issue.write_text("fix")
    for key in ("HERMETIC_ROOTFS", "HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_AGENT_PYTHON"):
        monkeypatch.setenv(key, "/not-executed")
    monkeypatch.setenv("HERMETIC_AGENT_MANIFEST", str(manifest))
    monkeypatch.setenv("HERMETIC_AGENT_TASK", str(issue))
    monkeypatch.setenv("HERMETIC_AGENT_GATEWAY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HERMETIC_AGENT_MODEL", "pinned")
    calls = []
    monkeypatch.setattr(agent_h_run, "command", lambda *args, **kwargs: calls.append(args))
    work = tmp_path / "never"
    with pytest.raises(ValueError):
        agent_h_run.run([str(work)])
    assert not work.exists()
    assert not calls


def test_converter_excludes_only_root_installer_before_d4(tmp_path, monkeypatch):
    root = task(tmp_path)
    monkeypatch.setattr(image, "build_tools", lambda work: {})
    cap = 64 * 1024**2
    def export(name, work):
        tree = work / "tree"
        (tree / "bin").mkdir(parents=True)
        (tree / "testbed").mkdir()
        for program in ("bash", "cat", "sed"):
            (tree / "bin" / program).write_bytes(static_elf())
            (tree / "bin" / program).chmod(0o755)
        # Sparse staging file represents the 141 MB image installer without
        # allocating its contents in this offline regression.
        with (tree / "miniconda.sh").open("wb") as out:
            out.truncate(141_000_000)
        (tree / "testbed/miniconda.sh").write_bytes(b"keep nested names")
        (tree / "miniconda.sh.keep").write_bytes(b"keep similar names")
        return "sha256:" + "a" * 64
    monkeypatch.setattr(image, "export_image", export)
    calls = []
    def build(src, output, **kwargs):
        assert not os.path.lexists(src / "miniconda.sh")
        assert (src / "testbed/miniconda.sh").read_bytes() == b"keep nested names"
        assert (src / "miniconda.sh.keep").read_bytes() == b"keep similar names"
        assert max(p.stat().st_size for p in src.rglob("*") if p.is_file()) <= cap
        assert kwargs["sealcheck_bin"] == output.parent / "sealcheck"
        calls.append(src)
        return {"d4": "pass", "sha256": "c" * 64, "skipped_special": []}
    monkeypatch.setattr(image, "build_rootfs", build)
    previous = os.umask(0o022)
    try:
        assert image.run(["sealed", str(root), "pytest-dev__pytest-6202", str(tmp_path / "work")]) == 0
    finally:
        os.umask(previous)
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "absent"])
def test_image_exclusion_never_follows_links_or_recurses(tmp_path, kind):
    root = tmp_path / "tree"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"private sentinel")
    excluded = root / "miniconda.sh"
    if kind == "symlink":
        excluded.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(excluded)
    elif kind == "directory":
        excluded.mkdir()
        (excluded / "keep").write_bytes(b"keep")
    tree = image.Tree(root)
    try:
        if kind in ("fifo", "directory"):
            with pytest.raises(ValueError):
                image.exclude_image_leftovers(tree)
        else:
            image.exclude_image_leftovers(tree)
            assert not os.path.lexists(excluded)
    finally:
        tree.close()
    assert outside.read_bytes() == b"private sentinel"


@pytest.mark.parametrize("script", ["build-agent-h-fixture.sh", "convert-agent-h-task.sh"])
def test_image_usage_explains_group_writable_parent_refusal(script):
    result = subprocess.run(["bash", str(INTEGRATION / script), "--help"],
                            capture_output=True, timeout=10)
    assert result.returncode == 0
    assert b"group-writable" in result.stdout
    assert b"caller" in result.stdout


@pytest.mark.parametrize("stage", ["work-directory", "image-export", "rootfs-d4",
                                   "rootfs-d4-file-byte-cap"])
def test_image_cli_reports_safe_failure_category_only(tmp_path, monkeypatch, capsys, stage):
    root = task(tmp_path)
    work = tmp_path / "new"
    if stage == "work-directory":
        tmp_path.chmod(0o770)
    else:
        def fail(*args, **kwargs):
            detail = "private-path secret-token hostname 2026-11-14"
            if stage == "rootfs-d4-file-byte-cap":
                detail = "sealcheck d4-image failed (1): file byte cap exceeded " + detail
            raise RuntimeError(detail)
        monkeypatch.setattr(image, "build_tools", lambda work: {})
        if stage == "image-export":
            monkeypatch.setattr(image, "export_image", fail)
        else:
            def export(name, work):
                (work / "tree/testbed").mkdir(parents=True)
                return "sha256:" + "a" * 64
            monkeypatch.setattr(image, "export_image", export)
            monkeypatch.setattr(image, "check_guest_runtime", lambda tree: None)
            monkeypatch.setattr(image, "build_rootfs", fail)
    previous = os.umask(0o022)
    try:
        assert image.main(["sealed", str(root), "pytest-dev__pytest-6202", str(work)]) == 1
    finally:
        os.umask(previous)
        tmp_path.chmod(0o700)
    captured = capsys.readouterr()
    assert captured.err == "Agent image build refused: " + stage + "\n"
    assert not captured.out
    assert not (work / "world.json").exists()
    if stage == "work-directory":
        assert not work.exists()
