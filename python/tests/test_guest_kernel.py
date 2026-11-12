"""Offline policy and synthetic build fixtures for T3.2."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

import pytest

from hermetic_slice import guest_kernel as k
from hermetic_slice.__main__ import main

ROOT = Path(__file__).absolute().parents[2] / "images/kernel"
HEADER = "# Linux/x86 6.1.128 Kernel Configuration\n"


def config(values=None):
    values = values if values is not None else {name: rule.value for name, rule in k.RULES.items()}
    return HEADER + "\n".join(f"{name}={value}" for name, value in sorted(values.items())) + "\n"


@pytest.fixture
def lock():
    value = k.load_lock(ROOT / "kernel.lock.json")
    value.update(sha256=hashlib.sha256(b"source").hexdigest(), release_date="2025-02-01T00:00:00Z",
                 builder_image="hermetic/kernel-builder:6.1-v1@sha256:" + "a" * 64)
    return value


@pytest.mark.parametrize("name,rule", k.RULES.items())
def test_every_required_missing_wrong_and_forbidden_module(name, rule):
    values = {key: item.value for key, item in k.RULES.items()}
    assert k.check_config(config(values)) == []
    values.pop(name)
    missing = k.check_config(config(values))
    assert bool(missing) == (rule.value != "n")
    for wrong in ("m", "y" if rule.value != "y" else "n", '"bad"'):
        values[name] = wrong
        assert [f.option for f in k.check_config(config(values))] == [name]


@pytest.mark.parametrize("text", [b"\xff", b"\0", "CONFIG_X=y\0", "a" * (k.MAX_CONFIG_BYTES + 1),
                                    "#" + "x" * k.MAX_LINE_BYTES, "CONFIG_X=$(id)", "CONFIG_X=y\nCONFIG_X=n",
                                    "# CONFIG_X is not unset", "export CONFIG_X=y", "CONFIG_X=y\r"])
def test_hostile_config(text):
    with pytest.raises(k.KernelError):
        k.check_config(text)


@pytest.mark.parametrize("header", ["", "# Linux/x86 5.9.1 Kernel Configuration\n", HEADER + HEADER])
def test_kernel_version_minimum(header):
    assert k.check_config(config().replace(HEADER, header))[0].option == "kernel.version"


def test_merged_fragments_and_generated_readme_table():
    merged = {}
    for filename in ("base-x86_64.config", "hermetic.config"):
        merged.update(k.parse_config((ROOT / filename).read_bytes()))
    assert k.check_config(config(merged)) == []
    readme = (ROOT / "README.md").read_text()
    assert readme.split("<!-- BEGIN POLICY -->\n")[1].split("\n<!-- END POLICY -->")[0] == k.documentation_table()


def test_boot_known_answer():
    expected = ("console=ttyS0,115200n8 reboot=k panic=-1 pci=off root=/dev/vda rootfstype=ext4 ro "
                "init=/sbin/hermetic-execd clocksource=tsc tsc=reliable no-kvmclock hermetic.t=1704067200")
    assert k.boot_arguments(1704067200) == expected
    assert k.check_boot_arguments(expected) == []


@pytest.mark.parametrize("value", [-1, True, 1.1, "1", k.MAX_CLOCK + 1])
def test_boot_clock_bounds(value):
    with pytest.raises(k.KernelError):
        k.boot_arguments(value)


@pytest.mark.parametrize("token", k.BOOT_FIXED.split() + ["hermetic.t=0"])
def test_each_boot_argument_required(token):
    assert k.check_boot_arguments(" ".join(t for t in k.boot_arguments(0).split() if t != token))


@pytest.mark.parametrize("suffix", [" rw", " ip=dhcp", " clocksource=kvm-clock", " hostname=host", " hermetic.t=1",
                                    " no-kvmclock=0", " quiet", " hermetic.t=-1", " hermetic.t=0001",
                                    " hermetic.t=253402300800", " hermetic.t=99999999999999999999", "\t"])
def test_boot_rejections(suffix):
    assert k.check_boot_arguments(k.boot_arguments(0) + suffix)


def test_lock_shape_identity_and_dates(lock):
    assert k.validate_lock(lock, for_build=True) == lock
    for key, value in [("version", "5.9.1"), ("version", "6.1.1;id"), ("source_url", "https://other.invalid/"),
                       ("sha256", "0"), ("release_date", "2025-02-30T00:00:00Z"),
                       ("release_date", "2025-01-01T00:00:00+01:00"), ("build_user", "host"),
                       ("build_host", "host"), ("builder_image", "debian:latest"), ("boot_args", "rw"),
                       ("sha256", 1)]:
        with pytest.raises(k.KernelError):
            k.validate_lock({**lock, key: value})
    with pytest.raises(k.KernelError):
        k.validate_lock({**lock, "extra": "unknown"})
    with pytest.raises(k.KernelError):
        k.validate_lock([])


@pytest.mark.parametrize("field", ["sha256", "release_date", "builder_image"])
def test_placeholder_field_named(lock, field):
    lock[field] = ("hermetic/builder@sha256:" if field == "builder_image" else "") + k.PLACEHOLDER
    k.validate_lock(lock)
    with pytest.raises(k.KernelError, match=field):
        k.validate_lock(lock, for_build=True)


def test_lock_bad_json_and_caps(tmp_path):
    path = tmp_path / "lock"
    for raw in (b'{"version":"6.1.1","version":"6.1.2"}', b"[" * 5000, b"\xff", b"x" * (k.MAX_LOCK_BYTES + 1)):
        path.write_bytes(raw)
        with pytest.raises(k.KernelError):
            k.load_lock(path)


def test_docker_known_answer(lock):
    assert k.docker_arguments(lock, Path("/private/in"), Path("/private/out")) == [
        "/usr/bin/docker", "--config", "/private/in/docker-config", "run", "--rm", "--name", "hermetic-kernel-build", "--pull=never", "--network=none",
        "--hostname=hermetic", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=512", "--memory=4g", "--cpus=2", "--user", "1000:1000",
        "--mount", "type=bind,src=/private/in,dst=/inputs,readonly",
        "--mount", "type=bind,src=/private/out,dst=/output",
        "--tmpfs", "/build:rw,exec,nosuid,nodev,size=8g,mode=1777", "--workdir=/build",
        "--entrypoint=/bin/bash", "hermetic/kernel-builder:6.1-v1@sha256:" + "a" * 64, "/inputs/build.sh"]


@pytest.mark.parametrize("path", ["relative", "/tmp/a,readonly", "/tmp/a\n", "/tmp/../a"])
def test_docker_rejects_bad_mounts(lock, path):
    with pytest.raises(k.KernelError):
        k.docker_arguments(lock, Path(path), Path("/out"))


def banner(lock):
    return (f'Linux version {lock["version"]} (hermetic@hermetic) (gcc (Debian) 12.2.0, GNU ld 2.40) '
            '#1 SMP Sat Feb 01 00:00:00 UTC 2025\n').encode()


@pytest.mark.parametrize("change,option", [(lambda b: b, None),
    (lambda b: b.replace(b"6.1.128", b"6.1.127"), "banner.identity"),
    (lambda b: b.replace(b"hermetic@hermetic", b"alice@host"), "banner.identity"),
    (lambda b: b.replace(b"2025", b"2026"), "banner.date"),
    (lambda b: b"no banner", "banner"), (lambda b: b * 2, "banner"),
    (lambda b: b"Linux version " + b"x" * 1200 + b"\0", "banner")])
def test_banner_verifier(tmp_path, lock, change, option):
    path = tmp_path / "kernel"
    path.write_bytes(b"ELF\0" + change(banner(lock)) + b"\0")
    findings = k.verify_vmlinux(path, lock)
    assert [f.option for f in findings] == ([option] if option else [])


def test_banner_chunk_boundary(tmp_path, lock):
    path = tmp_path / "kernel"
    path.write_bytes(b"x" * (k.CHUNK_BYTES - 5) + banner(lock) + b"\0")
    assert k.verify_vmlinux(path, lock) == []


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "ancestor"])
def test_file_types_never_followed(tmp_path, kind):
    secret = tmp_path / "secret"
    secret.write_bytes(b"SECRET")
    victim = tmp_path / "victim"
    if kind == "symlink":
        victim.symlink_to(secret)
    elif kind == "fifo":
        os.mkfifo(victim)
    elif kind == "directory":
        victim.mkdir()
    else:
        victim.symlink_to(tmp_path, target_is_directory=True)
        victim = victim / "secret"
    with pytest.raises((k.KernelError, OSError)):
        k.read_file(victim, 100)
    assert secret.read_bytes() == b"SECRET"


def test_inode_swap_is_rejected(tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.write_bytes(b"ordinary")
    real_open = os.open

    def swap(path, flags, *args, **kwargs):
        if path == "victim":
            victim.unlink()
            os.mkfifo(victim)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(k.KernelError):
        k.read_file(victim, 100)


@pytest.fixture
def build_inputs(tmp_path, lock):
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock))
    archive = tmp_path / "source.tar.xz"
    archive.write_bytes(b"source")
    output = tmp_path / "out"
    output.mkdir(mode=0o700)
    return path, archive, output


def fake_builder(lock, incoming, output):
    (output / "vmlinux").write_bytes(banner(lock))
    (output / ".config").write_text(config())
    (output / "build-record.json").write_text('{"version":"6.1.128"}\n')


def test_reproducible_hook_builds_twice_and_compares_all_outputs(build_inputs):
    calls = []

    def builder(lock, incoming, output):
        calls.append(output)
        assert k.hash_file(incoming / "source.tar.xz") == lock["sha256"]
        fake_builder(lock, incoming, output)

    result = k.build_kernel(*build_inputs, verify_reproducible=True, builder=builder)
    assert len(calls) == 2 and calls[0] != calls[1]
    assert result["reproducible"]
    assert set(result["sha256"]) == set(k.ARTIFACTS)
    assert sorted(p.name for p in build_inputs[2].iterdir()) == sorted(k.ARTIFACTS)


@pytest.mark.parametrize("artifact", k.ARTIFACTS)
def test_reproducibility_mismatch_preserves_old_output(build_inputs, artifact):
    calls = 0
    old = build_inputs[2] / "vmlinux"
    old.write_bytes(b"old")

    def builder(lock, incoming, output):
        nonlocal calls
        fake_builder(lock, incoming, output)
        if calls:
            with (output / artifact).open("ab") as handle:
                handle.write(b"\n")
        calls += 1

    with pytest.raises(k.KernelError, match="not reproducible"):
        k.build_kernel(*build_inputs, verify_reproducible=True, builder=builder)
    assert old.read_bytes() == b"old"


def test_hash_mismatch_no_builder_or_publication(build_inputs):
    build_inputs[1].write_bytes(b"mismatch")
    with pytest.raises(k.KernelError, match="sha256 mismatch"):
        k.build_kernel(*build_inputs, builder=lambda *_: pytest.fail("builder must not run"))
    assert list(build_inputs[2].iterdir()) == []


def test_failed_build_verification_preserves_output(build_inputs):
    def builder(lock, incoming, output):
        fake_builder(lock, incoming, output)
        (output / ".config").write_text(HEADER)
    with pytest.raises(k.KernelError, match="verification"):
        k.build_kernel(*build_inputs, builder=builder)
    assert list(build_inputs[2].iterdir()) == []


def test_cli_status_json_and_errors(tmp_path, capsys):
    path = tmp_path / "config"
    path.write_text(config())
    assert main(["kernel-check-config", "--config", str(path)]) == 0
    assert capsys.readouterr().out == '{"findings": []}\n'
    path.write_text(HEADER)
    assert main(["kernel-check-config", "--config", str(path)]) == 2
    data = json.loads(capsys.readouterr().out)
    assert [f["option"] for f in data["findings"]] == sorted(f["option"] for f in data["findings"])
    path.write_text("SECRET$(id)")
    assert main(["kernel-check-config", "--config", str(path)]) == 1
    assert "SECRET" not in capsys.readouterr().out
    assert main(["kernel-build", "--tarball", str(path), "--out", str(tmp_path)]) == 1
    assert "placeholder" in capsys.readouterr().out


def test_cli_build_wired(build_inputs, monkeypatch, capsys):
    calls = []
    def build(*args, **kwargs):
        calls.append((args, kwargs))
        return {"reproducible": True}
    monkeypatch.setattr(k, "build_kernel", build)
    path, source, output = build_inputs
    assert main(["kernel-build", "--lock", str(path), "--tarball", str(source), "--out", str(output),
                 "--verify-reproducible"]) == 0
    assert calls == [((path, source, output), {"verify_reproducible": True})]
    assert json.loads(capsys.readouterr().out) == {"reproducible": True}


def test_subprocess_environment_and_failure_redaction(monkeypatch):
    calls = []
    class Process:
        def __init__(self, argv, **kwargs):
            calls.append((argv, kwargs))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def wait(self, **kwargs):
            assert kwargs["timeout"] == k.BUILD_TIMEOUT_S
            return 1
    monkeypatch.setattr(k.subprocess, "Popen", Process)
    with pytest.raises(k.KernelError) as exc:
        k._run(["/usr/bin/make"], env={"LC_ALL": "C"})
    assert str(exc.value) == "kernel build subprocess failed"
    assert calls[0][1]["env"] == {"LC_ALL": "C"}
    assert calls[0][1]["stdout"] == subprocess.DEVNULL


def test_atomic_output_fsync_and_rename(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"new")
    target = tmp_path / "target"
    target.write_bytes(b"old")
    events = []
    real_sync, real_replace = os.fsync, os.replace
    def sync(fd):
        events.append("fsync")
        real_sync(fd)
    def replace(src, dst, **kwargs):
        events.append("rename")
        assert target.read_bytes() == b"old"
        real_replace(src, dst, **kwargs)
    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", replace)
    with k.directory(tmp_path) as fd:
        k._atomic_copy(source, fd, "target", 100)
    assert target.read_bytes() == b"new"
    assert events == ["fsync", "rename", "fsync"]


def archive_fixture(path, members):
    with tarfile.open(path, "w:xz") as archive:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "link":
                info.type = tarfile.SYMTYPE
                info.linkname = content
                archive.addfile(info)
            else:
                info.size = len(content)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(content))


def test_source_extraction(tmp_path):
    archive = tmp_path / "source.tar.xz"
    archive_fixture(archive, [("linux-6.1.128/Makefile", b"source", "file"),
                              ("linux-6.1.128/scripts/link", "../Makefile", "link")])
    output = tmp_path / "source"
    output.mkdir()
    root = k._extract_source(archive, output, "6.1.128", k.hash_file(archive))
    assert (root / "Makefile").read_bytes() == b"source"
    assert (root / "scripts/link").is_symlink()


@pytest.mark.parametrize("members", [[("../escape", b"x", "file")], [("/escape", b"x", "file")],
    [("linux-6.1.128/link", "../../escape", "link")], [("linux-6.1.128/link", "/escape", "link")],
    [("linux-6.1.128/link", "Makefile", "link"), ("linux-6.1.128/link/evil", b"x", "file")]])
def test_source_archive_rejects_unsafe_paths(tmp_path, members):
    archive = tmp_path / "source.tar.xz"
    archive_fixture(archive, members)
    with pytest.raises((k.KernelError, OSError)):
        k._extract_source(archive, tmp_path, "6.1.128", k.hash_file(archive))


def test_container_pipeline_checks_before_compile_and_records_inputs(tmp_path, lock, monkeypatch):
    incoming, output, work = (tmp_path / name for name in ("inputs", "output", "build"))
    for path in (incoming, output, work):
        path.mkdir()
    for filename in ("build.sh", "Dockerfile", "base-x86_64.config", "hermetic.config"):
        (incoming / filename).write_bytes((ROOT / filename).read_bytes())
    (incoming / "guest_kernel.py").write_bytes(Path(k.__file__).read_bytes())
    archive_fixture(incoming / "source.tar.xz", [("linux-6.1.128/Makefile", b"kernel source", "file")])
    lock["sha256"] = k.hash_file(incoming / "source.tar.xz")
    (incoming / "kernel.lock.json").write_text(json.dumps(lock))
    calls = []
    monkeypatch.setattr(k.resource, "setrlimit", lambda *args: None)

    def run(argv, *, env, cwd=None):
        calls.append((argv, env, cwd))
        if "olddefconfig" in argv:
            (work / "objects/.config").write_text(config())
        if "vmlinux" in argv:
            assert k.check_config((work / "objects/.config").read_bytes()) == []
            (work / "objects/vmlinux").write_bytes(banner(lock))

    monkeypatch.setattr(k, "_run", run)
    k.container_build(incoming=incoming, output=output, work=work)
    assert [argv[-1] for argv, _, _ in calls] == [str(incoming / "hermetic.config"), "olddefconfig", "vmlinux"]
    assert calls[0][0] == ["/bin/bash", str(work / "linux-6.1.128/scripts/kconfig/merge_config.sh"),
                           "-m", "-O", str(work / "objects"), str(incoming / "base-x86_64.config"),
                           str(incoming / "hermetic.config")]
    for argv, env, cwd in calls:
        assert env == {
            "PATH": "/usr/bin:/bin", "HOME": "/build", "ARCH": "x86_64", "LC_ALL": "C", "TZ": "UTC",
            "KBUILD_BUILD_TIMESTAMP": "Sat Feb 01 00:00:00 UTC 2025", "KBUILD_BUILD_USER": "hermetic",
            "KBUILD_BUILD_HOST": "hermetic", "KBUILD_BUILD_VERSION": "1", "SOURCE_DATE_EPOCH": "1738368000",
            "KCONFIG_NOTIMESTAMP": "1", "KCONFIG_CONFIG": str(work / "objects/.config")}
    record = json.loads((output / "build-record.json").read_text())
    assert record["inputs"] == {name: k.hash_file(incoming / name) for name in (
        "source.tar.xz", "kernel.lock.json", "base-x86_64.config", "hermetic.config", "build.sh", "Dockerfile", "guest_kernel.py")}
    assert record["outputs"] == {name: k.hash_file(output / name) for name in ("vmlinux", ".config")}
    assert "2026" not in json.dumps(record)
    assert str(tmp_path) not in json.dumps(record)
    # Repeat with olddefconfig silently dropping required options: compile is never reached.
    def broken(argv, *, env, cwd=None):
        assert "vmlinux" not in argv
        if "olddefconfig" in argv:
            (work / "objects/.config").write_text(HEADER)
    monkeypatch.setattr(k, "_run", broken)
    second_work = tmp_path / "second-build"
    second_work.mkdir()
    # Repoint the synthetic olddefconfig writer for this fresh build.
    work = second_work
    with pytest.raises(k.KernelError, match="config failed"):
        k.container_build(incoming=incoming, output=output, work=second_work)


def test_container_hash_mismatch_before_unpack(tmp_path, lock, monkeypatch):
    incoming = tmp_path / "inputs"
    incoming.mkdir()
    (incoming / "kernel.lock.json").write_text(json.dumps(lock))
    (incoming / "source.tar.xz").write_bytes(b"bad")
    monkeypatch.setattr(k.resource, "setrlimit", lambda *args: None)
    monkeypatch.setattr(k, "_extract_source", lambda *a: pytest.fail("unpack before verification"))
    with pytest.raises(k.KernelError, match="sha256 mismatch"):
        k.container_build(incoming=incoming, output=tmp_path, work=tmp_path)


def test_build_uses_exact_docker_argv_and_clean_environment(build_inputs, monkeypatch):
    calls = []
    def run(argv, *, env, cwd=None):
        calls.append((argv, env))
        incoming = Path(argv[argv.index("--mount") + 1].split("src=", 1)[1].split(",dst=", 1)[0])
        output = Path(next(value for value in argv if "dst=/output" in value).split("src=", 1)[1].split(",dst=", 1)[0])
        fake_builder(k.load_lock(incoming / "kernel.lock.json", for_build=True), incoming, output)
    monkeypatch.setattr(k, "_run", run)
    k.build_kernel(*build_inputs)
    assert len(calls) == 1
    argv, env = calls[0]
    assert "--network=none" in argv and "--pull=never" in argv
    assert env == {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "TZ": "UTC"}


def test_build_client_failure_removes_daemon_container(build_inputs, monkeypatch):
    calls = []
    def fail(*a, **kw):
        raise k.KernelError("failed")
    def cleanup(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(k, "_run", fail)
    monkeypatch.setattr(k.subprocess, "run", cleanup)
    with pytest.raises(k.KernelError, match="failed"):
        k.build_kernel(*build_inputs)
    assert calls[0][0][-3:-1] == ["rm", "--force"]
    assert calls[0][0][-1].startswith("hermetic-kernel-")
    assert calls[0][1]["timeout"] == k.CLEANUP_TIMEOUT_S


def test_subprocess_timeout_kills_process_group(monkeypatch):
    events = []
    class Process:
        pid = 123
        def __init__(self, *a, **kw):
            assert kw["start_new_session"]
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
        def wait(self, *, timeout):
            events.append(("wait", timeout))
            if timeout == k.BUILD_TIMEOUT_S:
                raise subprocess.TimeoutExpired("test", timeout)
            return 0
    monkeypatch.setattr(k.subprocess, "Popen", Process)
    monkeypatch.setattr(k.os, "killpg", lambda pid, signal: events.append(("kill", pid)))
    with pytest.raises(k.KernelError, match="timed out"):
        k._run(["/usr/bin/make"], env={})
    assert events == [("wait", k.BUILD_TIMEOUT_S), ("kill", 123), ("wait", 10)]


def test_bounded_source_entry_bytes_and_xz_limits(tmp_path, monkeypatch):
    archive = tmp_path / "source.tar.xz"
    archive_fixture(archive, [("linux-6.1.128/file", b"a" * 4096, "file")])
    for cap, value in (("MAX_SOURCE_ENTRIES", 0), ("MAX_SOURCE_BYTES", 1), ("MAX_UNPACKED_BYTES", 1),
                       ("MAX_XZ_MEMORY_BYTES", 1)):
        with monkeypatch.context() as patch:
            patch.setattr(k, cap, value)
            output = tmp_path / cap
            output.mkdir()
            with pytest.raises(k.KernelError):
                k._extract_source(archive, output, "6.1.128", k.hash_file(archive))


def test_size_caps_and_growth_after_open(tmp_path, monkeypatch):
    path = tmp_path / "file"
    path.write_bytes(b"12345")
    with pytest.raises(k.KernelError, match="byte cap"):
        k.read_file(path, 4)
    with pytest.raises(k.KernelError, match="byte cap"):
        k.hash_file(path, 4)
    real_read = os.read
    def read(fd, count):
        # Simulate a regular inode growing after fstat.
        with path.open("ab") as out:
            out.write(b"x")
        return real_read(fd, count)
    monkeypatch.setattr(os, "read", read)
    with pytest.raises(k.KernelError, match="byte cap"):
        k.read_file(path, 5)


def test_unsafe_output_directory_and_placeholder_create_nothing(build_inputs, monkeypatch):
    lock, source, out = build_inputs
    out.chmod(0o777)
    with pytest.raises(k.KernelError, match="output directory"):
        k.build_kernel(lock, source, out)
    out.chmod(0o700)
    assert list(out.iterdir()) == []
    lock.write_text((ROOT / "kernel.lock.json").read_text())
    with pytest.raises(k.KernelError, match="placeholder"):
        k.build_kernel(lock, source, out)
    assert list(out.iterdir()) == []


def test_unterminated_second_banner_rejected(tmp_path, lock):
    path = tmp_path / "kernel"
    path.write_bytes(banner(lock) + b"Linux version secret")
    assert k.verify_vmlinux(path, lock)[0].option == "banner"


def test_entrypoint_environment_and_builder_prerequisites():
    script = (ROOT / "build.sh").read_text()
    assert "set -euo pipefail" in script
    assert "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC HOME=/build" in script
    assert "/usr/bin/python3 -I -B /inputs/guest_kernel.py" in script
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}" in dockerfile
    for tool in ("bison", "flex", "build-essential", "python3", "libelf-dev", "libssl-dev"):
        assert tool in dockerfile


def test_source_sha256_mismatch_never_unpacks(tmp_path):
    archive = tmp_path / "source.tar.xz"
    archive_fixture(archive, [("linux-6.1.128/file", b"source", "file")])
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(k.KernelError, match="sha256 mismatch"):
        k._extract_source(archive, output, "6.1.128", "0" * 64)
    assert list(output.iterdir()) == []


def test_archive_metadata_and_special_members_are_bounded(tmp_path):
    for kind in (tarfile.FIFOTYPE, tarfile.LNKTYPE, tarfile.GNUTYPE_SPARSE):
        path = tmp_path / ("archive-" + kind.decode("ascii"))
        with tarfile.open(path, "w:xz") as archive:
            info = tarfile.TarInfo("linux-6.1.128/special")
            info.type = kind
            info.linkname = "linux-6.1.128/file"
            archive.addfile(info)
        with pytest.raises(k.KernelError):
            k._extract_source(path, tmp_path, "6.1.128", k.hash_file(path))
    path = tmp_path / "metadata.tar.xz"
    with tarfile.open(path, "w:xz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("linux-6.1.128/file")
        info.pax_headers = {"comment": "x" * (k.MAX_TAR_METADATA_BYTES + 1)}
        archive.addfile(info)
    with pytest.raises(k.KernelError, match="metadata exceeds"):
        k._extract_source(path, tmp_path, "6.1.128", k.hash_file(path))


def test_clock_and_identity_do_not_depend_on_host_locale(lock, monkeypatch):
    monkeypatch.setenv("LC_ALL", "invalid_locale")
    monkeypatch.setenv("TZ", "Pacific/Honolulu")
    monkeypatch.setenv("KBUILD_BUILD_HOST", "SECRET-HOST")
    assert k._banner_date(lock) == "Sat Feb 01 00:00:00 UTC 2025"
    assert k.boot_arguments(0).endswith(" hermetic.t=0")
    assert k.boot_arguments(k.MAX_CLOCK).endswith(" hermetic.t=253402300799")


def test_output_ancestor_replacement_uses_open_directory(build_inputs, tmp_path):
    path, source, output = build_inputs
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "vmlinux"
    sentinel.write_bytes(b"OUTSIDE")
    moved = tmp_path / "moved-output"
    def builder(lock, incoming, run_dir):
        fake_builder(lock, incoming, run_dir)
        output.rename(moved)
        output.symlink_to(outside, target_is_directory=True)
    k.build_kernel(path, source, output, builder=builder)
    assert sentinel.read_bytes() == b"OUTSIDE"
    assert (moved / "vmlinux").read_bytes().startswith(b"Linux version ")


def test_config_signed_integer_grammar():
    assert k.parse_config("CONFIG_UNKNOWN=-1\n") == {"CONFIG_UNKNOWN": "-1"}


def test_failed_atomic_copy_leaves_old_artifact_and_no_temporary(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"too large")
    target.write_bytes(b"old")
    with k.directory(tmp_path) as parent:
        with pytest.raises(k.KernelError):
            k._atomic_copy(source, parent, "target", 1)
    assert target.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["source", "target"]
