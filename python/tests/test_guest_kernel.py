"""Offline policy and synthetic build fixtures for T3.2."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

from hermetic_slice import guest_kernel as k
from hermetic_slice.__main__ import main

ROOT = Path(__file__).absolute().parents[2] / "images/kernel"
HEADER = "# Linux/x86 6.6.160 Kernel Configuration\n"


def config(values=None):
    values = values if values is not None else {name: rule.value for name, rule in k.RULES.items()}
    return HEADER + "\n".join(f"{name}={value}" for name, value in sorted(values.items())) + "\n"


@pytest.fixture
def lock():
    value = k.load_lock(ROOT / "kernel.lock.json")
    value.update(sha256=hashlib.sha256(b"source").hexdigest(),
                 builder_image="hermetic/kernel-builder:6.6-v1@sha256:" + "a" * 64)
    return value


def test_checked_in_lock_real_pins():
    raw = json.loads((ROOT / "kernel.lock.json").read_text())
    assert raw["sha256"] == "b24c40a9e2188695803358567edda51c4080176424a57dbefca45e5ac44ec225"
    assert raw["release_date"] == "2026-10-21T00:00:00Z"
    assert raw["builder_image"] == "hermetic/kernel-builder:6.6-v1@sha256:TO-BE-FILLED-BY-OWNER"
    assert raw["version"] == "6.6.160"
    assert raw["source_url"] == "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.160.tar.xz"
    assert raw["build_user"] == "hermetic"
    assert raw["build_host"] == "hermetic"


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
                "init=/sbin/hermetic-init clocksource=tsc tsc=reliable no-kvmclock hermetic.t=1704067200")
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
        "--entrypoint=/bin/bash", "hermetic/kernel-builder:6.6-v1@sha256:" + "a" * 64, "/inputs/build.sh"]


@pytest.mark.parametrize("path", ["relative", "/tmp/a,readonly", "/tmp/a\n", "/tmp/../a"])
def test_docker_rejects_bad_mounts(lock, path):
    with pytest.raises(k.KernelError):
        k.docker_arguments(lock, Path(path), Path("/out"))


def banner(lock):
    return (f'Linux version {lock["version"]} (hermetic@hermetic) (gcc (Debian) 12.2.0, GNU ld 2.40) '
            '#1 SMP Wed Oct 21 00:00:00 UTC 2026\n').encode()


@pytest.mark.parametrize("change,option", [(lambda b: b, None),
    (lambda b: b.replace(b"6.6.160", b"6.1.127"), "banner.identity"),
    (lambda b: b.replace(b"hermetic@hermetic", b"alice@host"), "banner.identity"),
    (lambda b: b.replace(b"2026", b"2027"), "banner.date"),
    (lambda b: b"no banner", "banner"), (lambda b: b + b.replace(b"2026", b"2027"), "banner"),
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
    (output / "build-record.json").write_text('{"version":"6.6.160"}\n')


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
    # Test placeholder refusal using an explicit fixture copy
    placeholder_lock = tmp_path / "placeholder_lock.json"
    placeholder_lock.write_text(json.dumps({**k.load_lock(ROOT / "kernel.lock.json"), "sha256": k.PLACEHOLDER}))
    assert main(["kernel-build", "--lock", str(placeholder_lock), "--tarball", str(path), "--out", str(tmp_path)]) == 1
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
    archive_fixture(archive, [("linux-6.6.160/Makefile", b"source", "file"),
                              ("linux-6.6.160/scripts/link", "../Makefile", "link")])
    output = tmp_path / "source"
    output.mkdir()
    root = k._extract_source(archive, output, "6.6.160", k.hash_file(archive))
    assert (root / "Makefile").read_bytes() == b"source"
    assert (root / "scripts/link").is_symlink()


@pytest.mark.parametrize("members", [[("../escape", b"x", "file")], [("/escape", b"x", "file")],
    [("linux-6.6.160/link", "../../escape", "link")], [("linux-6.6.160/link", "/escape", "link")],
    [("linux-6.6.160/link", "Makefile", "link"), ("linux-6.6.160/link/evil", b"x", "file")]])
def test_source_archive_rejects_unsafe_paths(tmp_path, members):
    archive = tmp_path / "source.tar.xz"
    archive_fixture(archive, members)
    with pytest.raises((k.KernelError, OSError)):
        k._extract_source(archive, tmp_path, "6.6.160", k.hash_file(archive))


def test_container_pipeline_checks_before_compile_and_records_inputs(tmp_path, lock, monkeypatch):
    incoming, output, work = (tmp_path / name for name in ("inputs", "output", "build"))
    for path in (incoming, output, work):
        path.mkdir()
    for filename in ("build.sh", "Dockerfile", "base-x86_64.config", "hermetic.config"):
        (incoming / filename).write_bytes((ROOT / filename).read_bytes())
    (incoming / "guest_kernel.py").write_bytes(Path(k.__file__).read_bytes())
    archive_fixture(incoming / "source.tar.xz", [("linux-6.6.160/Makefile", b"kernel source", "file")])
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
    assert calls[0][0] == ["/bin/bash", str(work / "linux-6.6.160/scripts/kconfig/merge_config.sh"),
                           "-m", "-O", str(work / "objects"), str(incoming / "base-x86_64.config"),
                           str(incoming / "hermetic.config")]
    for argv, env, cwd in calls:
        assert env == {
            "PATH": "/usr/bin:/bin", "HOME": "/build", "ARCH": "x86_64", "LC_ALL": "C", "TZ": "UTC",
            "KBUILD_BUILD_TIMESTAMP": "Wed Oct 21 00:00:00 UTC 2026", "KBUILD_BUILD_USER": "hermetic",
            "KBUILD_BUILD_HOST": "hermetic", "KBUILD_BUILD_VERSION": "1", "SOURCE_DATE_EPOCH": "1792540800",
            "KCONFIG_NOTIMESTAMP": "1", "KCONFIG_CONFIG": str(work / "objects/.config"),
            "TMPDIR": str(work / "tmp")}
    # Regression: the container's /tmp is read-only and 6.6 gen_initramfs.sh calls mktemp.
    assert (work / "tmp").is_dir() and (work / "tmp").stat().st_mode & 0o777 == 0o700
    record = json.loads((output / "build-record.json").read_text())
    assert record["inputs"] == {name: k.hash_file(incoming / name) for name in (
        "source.tar.xz", "kernel.lock.json", "base-x86_64.config", "hermetic.config", "build.sh", "Dockerfile", "guest_kernel.py")}
    assert record["outputs"] == {name: k.hash_file(output / name) for name in ("vmlinux", ".config")}
    # No host build date: the lock's release date is the only date in the record.
    assert record["release_date"] == "2026-10-21T00:00:00Z"
    assert "2026-" not in json.dumps({key: value for key, value in record.items() if key != "release_date"})
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
    def run(argv, *, env, cwd=None, stderr_parent=None):
        assert stderr_parent is not None
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
    archive_fixture(archive, [("linux-6.6.160/file", b"a" * 4096, "file")])
    for cap, value in (("MAX_SOURCE_ENTRIES", 0), ("MAX_SOURCE_BYTES", 1), ("MAX_UNPACKED_BYTES", 1),
                       ("MAX_XZ_MEMORY_BYTES", 1)):
        with monkeypatch.context() as patch:
            patch.setattr(k, cap, value)
            output = tmp_path / cap
            output.mkdir()
            with pytest.raises(k.KernelError):
                k._extract_source(archive, output, "6.6.160", k.hash_file(archive))


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
    placeholder_copy = dict(k.load_lock(ROOT / "kernel.lock.json"))
    placeholder_copy["sha256"] = k.PLACEHOLDER
    lock.write_text(json.dumps(placeholder_copy))
    with pytest.raises(k.KernelError, match="placeholder"):
        k.build_kernel(lock, source, out)
    assert list(out.iterdir()) == []


def test_integration_kernel_build_script():
    script_path = Path(__file__).absolute().parents[2] / "scripts/integration/kernel-build.sh"
    assert script_path.is_file()
    content = script_path.read_text()
    assert "set -euo pipefail" in content
    assert "sudo" not in content
    assert "debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc" in content
    assert "hermetic/kernel-builder:6.6-v1" in content
    assert "kernel-build" in content
    assert "build-record.json" in content


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
    archive_fixture(archive, [("linux-6.6.160/file", b"source", "file")])
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(k.KernelError, match="sha256 mismatch"):
        k._extract_source(archive, output, "6.6.160", "0" * 64)
    assert list(output.iterdir()) == []


def test_archive_metadata_and_special_members_are_bounded(tmp_path):
    for kind in (tarfile.FIFOTYPE, tarfile.LNKTYPE, tarfile.GNUTYPE_SPARSE):
        path = tmp_path / ("archive-" + kind.decode("ascii"))
        with tarfile.open(path, "w:xz") as archive:
            info = tarfile.TarInfo("linux-6.6.160/special")
            info.type = kind
            info.linkname = "linux-6.6.160/file"
            archive.addfile(info)
        with pytest.raises(k.KernelError):
            k._extract_source(path, tmp_path, "6.6.160", k.hash_file(path))
    path = tmp_path / "metadata.tar.xz"
    with tarfile.open(path, "w:xz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("linux-6.6.160/file")
        info.pax_headers = {"comment": "x" * (k.MAX_TAR_METADATA_BYTES + 1)}
        archive.addfile(info)
    with pytest.raises(k.KernelError, match="metadata exceeds"):
        k._extract_source(path, tmp_path, "6.6.160", k.hash_file(path))


def test_clock_and_identity_do_not_depend_on_host_locale(lock, monkeypatch):
    monkeypatch.setenv("LC_ALL", "invalid_locale")
    monkeypatch.setenv("TZ", "Pacific/Honolulu")
    monkeypatch.setenv("KBUILD_BUILD_HOST", "SECRET-HOST")
    assert k._banner_date(lock) == "Wed Oct 21 00:00:00 UTC 2026"
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


@pytest.mark.parametrize("entrypoint", [False, True])
def test_standalone_module_at_shallow_staging_path(entrypoint):
    # Compile with the container's filename: reproducing /inputs needs no root
    # privileges or files outside the test directory.
    code = '''
import sys, types
source = open(sys.argv[1], 'rb').read()
name = '__main__' if sys.argv[2] == 'True' else 'staged'
module = types.ModuleType(name)
module.__file__ = '/inputs/guest_kernel.py'
sys.modules[name] = module
exec(compile(source, module.__file__, 'exec'), module.__dict__)
assert module.boot_arguments(0).endswith(' hermetic.t=0')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, k.__file__, str(entrypoint)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    if entrypoint:
        assert result.returncode == 1
        assert result.stderr == b'kernel container build failed\n'
    else:
        assert result.returncode == 0, result.stderr
        assert result.stderr == b''
    assert b'IndexError' not in result.stderr


@pytest.mark.parametrize("status", [0, 1])
def test_run_saves_bounded_stderr_tail_atomically(tmp_path, status):
    outside = tmp_path / 'outside'
    outside.write_bytes(b'unchanged')
    log = tmp_path / k.STDERR_LOG
    log.symlink_to(outside)
    code = 'import os, sys; os.write(2, b"x" * 300000); os.write(2, b"last diagnostic\\n"); sys.exit(int(sys.argv[1]))'
    with k.directory(tmp_path) as parent:
        if status:
            with pytest.raises(k.KernelError, match='^kernel build subprocess failed$'):
                k._run([sys.executable, '-I', '-B', '-c', code, str(status)], env={}, stderr_parent=parent)
        else:
            k._run([sys.executable, '-I', '-B', '-c', code, str(status)], env={}, stderr_parent=parent)
    assert outside.read_bytes() == b'unchanged'
    assert not log.is_symlink()
    assert log.stat().st_mode & 0o777 == 0o600
    expected = (b'x' * k.MAX_STDERR_BYTES + b'last diagnostic\n')[-k.MAX_STDERR_BYTES:]
    assert log.read_bytes() == expected
    assert sorted(p.name for p in tmp_path.iterdir()) == [k.STDERR_LOG, 'outside']


def test_inner_build_stderr_reaches_outer_log(tmp_path):
    code = '''
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from hermetic_slice.guest_kernel import _run
_run([sys.executable, '-I', '-B', '-c', 'import os; os.write(2, b"compiler failure\\n"); raise SystemExit(1)'], env={})
'''
    with k.directory(tmp_path) as parent:
        with pytest.raises(k.KernelError, match='subprocess failed'):
            k._run([sys.executable, '-I', '-B', '-c', code, str(Path(k.__file__).parent.parent)],
                   env={}, stderr_parent=parent)
    assert b'compiler failure\n' in (tmp_path / k.STDERR_LOG).read_bytes()


def test_run_timeout_keeps_stderr_tail(tmp_path, monkeypatch):
    monkeypatch.setattr(k, 'BUILD_TIMEOUT_S', 0.5)
    code = 'import os, time; os.write(2, b"before timeout\\n"); time.sleep(30)'
    with k.directory(tmp_path) as parent:
        with pytest.raises(k.KernelError, match='timed out'):
            k._run([sys.executable, '-I', '-B', '-c', code], env={}, stderr_parent=parent)
    assert (tmp_path / k.STDERR_LOG).read_bytes() == b'before timeout\n'


def test_local_builder_image_id_is_not_a_registry_digest(lock):
    lock['builder_image'] = 'sha256:' + 'b' * 64
    assert k.validate_lock(lock, for_build=True) == lock
    argv = k.docker_arguments(lock, Path('/in'), Path('/out'))
    assert argv[-2] == 'sha256:' + 'b' * 64
    assert '--pull=never' in argv


@pytest.fixture
def integration_inputs(tmp_path, lock, monkeypatch):
    kernel = tmp_path / 'kernel'
    kernel.mkdir()
    for name in ('Dockerfile', 'build.sh', 'base-x86_64.config', 'hermetic.config'):
        (kernel / name).write_bytes((ROOT / name).read_bytes())
    lock['builder_image'] = 'hermetic/kernel-builder:6.6-v1@sha256:' + k.PLACEHOLDER
    (kernel / 'kernel.lock.json').write_text(json.dumps(lock))
    source = tmp_path / 'source.tar.xz'
    source.write_bytes(b'source')
    monkeypatch.setattr(k, 'DEFAULT_KERNEL_DIR', kernel)
    return source, tmp_path / 'out'


def test_integration_resolves_local_id_and_uses_private_output(integration_inputs, monkeypatch):
    source, output = integration_inputs
    output.mkdir(mode=0o700)
    outside = output.parent / 'outside-lock'
    outside.write_bytes(b'unchanged')
    (output / 'kernel.lock.json').symlink_to(outside)
    calls = []

    def run(argv, *, env, stderr_parent):
        assert env == {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C', 'TZ': 'UTC'}
        assert os.fstat(stderr_parent).st_ino == output.stat().st_ino
        assert argv[:5] == ['/usr/bin/docker', '--config', argv[2], 'build', '--build-arg']
        assert argv[5] == 'BASE_IMAGE=debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc'
        image_file = Path(argv[argv.index('--iidfile') + 1])
        assert image_file.is_relative_to(output)
        image_file.write_text('sha256:' + 'c' * 64 + '\n')
        calls.append('image')

    def build(lock_path, tarball, out, *, work_dir, output_identity, kernel_dir):
        assert calls == ['image']
        assert tarball == source and out == output
        assert work_dir.is_relative_to(output)
        assert kernel_dir == k.DEFAULT_KERNEL_DIR
        info = output.stat()
        assert output_identity == (info.st_dev, info.st_ino)
        effective = k.load_lock(lock_path, for_build=True)
        assert effective['builder_image'] == 'sha256:' + 'c' * 64
        (out / 'build-record.json').write_bytes(b'{"verified": true}\n')
        calls.append('kernel')

    monkeypatch.setattr(k, '_run', run)
    monkeypatch.setattr(k, 'build_kernel', build)
    assert k.integration_build(source, output) == b'{"verified": true}\n'
    assert calls == ['image', 'kernel']
    assert outside.read_bytes() == b'unchanged'
    assert k.load_lock(output / 'kernel.lock.json', for_build=True)['builder_image'] == 'sha256:' + 'c' * 64
    assert (output / 'kernel.lock.json').stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in output.iterdir()) == ['build-record.json', 'kernel.lock.json']


@pytest.mark.parametrize('kind', ['symlink', 'ancestor-symlink', 'shared', 'fifo'])
def test_integration_rejects_unsafe_output_before_docker(integration_inputs, monkeypatch, kind):
    source, output = integration_inputs
    outside = output.parent / 'outside'
    outside.mkdir(mode=0o755)
    if kind == 'symlink':
        output.symlink_to(outside, target_is_directory=True)
    elif kind == 'ancestor-symlink':
        output.symlink_to(outside, target_is_directory=True)
        output = output / 'child'
    elif kind == 'shared':
        output.mkdir(mode=0o755)
    else:
        os.mkfifo(output)
    monkeypatch.setattr(k, '_run', lambda *a, **kw: pytest.fail('Docker before validation'))
    with pytest.raises((k.KernelError, OSError)):
        k.integration_build(source, output)
    assert outside.stat().st_mode & 0o777 == 0o755
    assert list(outside.iterdir()) == []


def test_integration_hash_mismatch_creates_nothing(integration_inputs, monkeypatch):
    source, output = integration_inputs
    source.write_bytes(b'wrong')
    monkeypatch.setattr(k, '_run', lambda *a, **kw: pytest.fail('Docker before validation'))
    with pytest.raises(k.KernelError, match='sha256 mismatch'):
        k.integration_build(source, output)
    assert not output.exists()


def test_source_symlink_composition_cannot_escape_root(tmp_path):
    archive = tmp_path / 'source.tar.xz'
    archive_fixture(archive, [('linux-6.6.160/a', '.', 'link'),
                              ('linux-6.6.160/b', 'a/..', 'link')])
    destination = tmp_path / 'build'
    destination.mkdir()
    with pytest.raises(k.KernelError, match='source link escapes tree'):
        k._extract_source(archive, destination, '6.6.160', k.hash_file(archive))
    assert not (destination / 'linux-6.6.160/a').is_symlink()
    assert not (destination / 'linux-6.6.160/b').is_symlink()


def test_source_symlink_cycles_are_bounded(tmp_path):
    archive = tmp_path / 'source.tar.xz'
    archive_fixture(archive, [('linux-6.6.160/a', 'b', 'link'),
                              ('linux-6.6.160/b', 'a', 'link')])
    with pytest.raises(k.KernelError, match='hop cap'):
        k._extract_source(archive, tmp_path, '6.6.160', k.hash_file(archive))


@pytest.mark.parametrize('ancestor', [False, True])
def test_source_extraction_refuses_preexisting_symlinks(tmp_path, ancestor):
    archive = tmp_path / 'source.tar.xz'
    archive_fixture(archive, [('linux-6.6.160/sub/file', b'must stay inside', 'file')])
    destination = tmp_path / 'build'
    destination.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    root = destination / 'linux-6.6.160'
    if ancestor:
        root.mkdir()
        (root / 'sub').symlink_to(outside, target_is_directory=True)
    else:
        root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(k.KernelError, match='source directory must not contain symlinks'):
        k._extract_source(archive, destination, '6.6.160', k.hash_file(archive))
    assert list(outside.iterdir()) == []


def test_cli_defaults_work_in_shallow_package(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'config'
    path.write_text(config())
    monkeypatch.setitem(main.__globals__, '__file__', '/hermetic_slice/__main__.py')
    assert main(['kernel-check-config', '--config', str(path)]) == 0
    assert capsys.readouterr().out == '{"findings": []}\n'


@pytest.mark.parametrize('field', ['path', 'linkpath'])
def test_source_pax_nul_paths_are_rejected_before_filesystem_use(tmp_path, field):
    archive = tmp_path / 'source.tar.xz'
    with tarfile.open(archive, 'w:xz', format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo('linux-6.6.160/link')
        info.type = tarfile.SYMTYPE
        info.linkname = 'internal'
        info.pax_headers = {field: 'linux-6.6.160/a\0b' if field == 'path' else 'a\0b'}
        tar.addfile(info)
    with pytest.raises(k.KernelError, match='NUL'):
        k._extract_source(archive, tmp_path, '6.6.160', k.hash_file(archive))
    assert not (tmp_path / 'linux-6.6.160').exists()


@pytest.mark.parametrize('bad_input', ['config', 'shell-symlink', 'source-pin'])
def test_integration_validates_inputs_before_output_or_docker(integration_inputs, monkeypatch, bad_input):
    source, output = integration_inputs
    if bad_input == 'config':
        (k.DEFAULT_KERNEL_DIR / 'hermetic.config').write_text('CONFIG_UNSAFE=$(command)\n')
    elif bad_input == 'shell-symlink':
        script = k.DEFAULT_KERNEL_DIR / 'build.sh'
        script.unlink()
        script.symlink_to(ROOT / 'build.sh')
    else:
        path = k.DEFAULT_KERNEL_DIR / 'kernel.lock.json'
        lock = k.load_lock(path)
        lock['sha256'] = k.PLACEHOLDER
        path.write_text(json.dumps(lock))
    monkeypatch.setattr(k, '_run', lambda *a, **kw: pytest.fail('Docker before validation'))
    with pytest.raises(k.KernelError):
        k.integration_build(source, output)
    assert not output.exists()


def test_integration_output_identity_change_prevents_build(build_inputs):
    lock, tarball, output = build_inputs
    info = output.stat()
    with pytest.raises(k.KernelError, match='output directory changed'):
        k.build_kernel(lock, tarball, output, output_identity=(info.st_dev, info.st_ino + 1),
                       builder=lambda *args: pytest.fail('build into substituted directory'))
    assert list(output.iterdir()) == []


def test_source_root_cannot_be_a_symlink_to_destination(tmp_path):
    archive = tmp_path / 'source.tar.xz'
    archive_fixture(archive, [('linux-6.6.160', '.', 'link')])
    with pytest.raises(k.KernelError, match='unsafe paths'):
        k._extract_source(archive, tmp_path, '6.6.160', k.hash_file(archive))
    assert not (tmp_path / 'linux-6.6.160').exists()


def test_config_accepts_real_kconfig_symbols_with_lowercase_letters():
    # Linux 6.1 olddefconfig emits symbols such as CONFIG_CRYPTO_DEV_QAT_DH895xCC.
    parsed = k.parse_config(
        "# CONFIG_CRYPTO_DEV_QAT_DH895xCC is not set\n"
        "# CONFIG_CRYPTO_DEV_QAT_DH895xCCVF is not set\n"
        "CONFIG_EXAMPLE_x86=y\n"
    )
    assert parsed["CONFIG_CRYPTO_DEV_QAT_DH895xCC"] == "n"
    assert parsed["CONFIG_CRYPTO_DEV_QAT_DH895xCCVF"] == "n"
    assert parsed["CONFIG_EXAMPLE_x86"] == "y"
    with pytest.raises(k.KernelError):
        k.parse_config("# CONFIG_BAD-NAME is not set\n")


def test_base_config_enables_paravirt_for_required_kvm_guest():
    # KVM_GUEST depends on PARAVIRT; without it olddefconfig silently drops KVM_GUEST
    # and the final-config policy fails (seen in the first real 6.6.160 build).
    base = k.parse_config((Path(__file__).resolve().parents[2] / "images/kernel/base-x86_64.config").read_text())
    assert base.get("CONFIG_KVM_GUEST") == "y"
    assert base.get("CONFIG_PARAVIRT") == "y"


def test_identical_banner_copies_accepted_but_capped(tmp_path, lock):
    # A real 6.6.160 vmlinux carries two identical linux_banner copies.
    path = tmp_path / "kernel"
    path.write_bytes(b"ELF\0" + banner(lock) + b"\0" + banner(lock) + b"\0")
    assert k.verify_vmlinux(path, lock) == []
    path.write_bytes(b"ELF\0" + (banner(lock) + b"\0") * (k.MAX_BANNER_COPIES + 1))
    assert [f.option for f in k.verify_vmlinux(path, lock)] == ["banner"]


def _policy(**changes):
    return {**{name: rule.value for name, rule in k.RULES.items()}, **changes}


def test_execd_boot_contract_kernel_policy():
    # Regression: the 6.1 lock had no initramfs support and no devtmpfs automount, so
    # execd's documented boot contract (kernel-mounted /dev) could not be met.
    assert k.RULES["CONFIG_DEVTMPFS_MOUNT"].value == "y"
    assert k.RULES["CONFIG_BLK_DEV_INITRD"].value == "y"
    assert k.RULES["CONFIG_RD_GZIP"].value == "y"
    assert k.RULES["CONFIG_INITRAMFS_SOURCE"].value == '""'
    for name in ("RD_BZIP2", "RD_LZMA", "RD_XZ", "RD_LZO", "RD_LZ4", "RD_ZSTD"):
        assert k.RULES["CONFIG_" + name].value == "n"
        assert [f.option for f in k.check_config(config(_policy(**{"CONFIG_" + name: "y"})))] == ["CONFIG_" + name]
    assert [f.option for f in k.check_config(config(_policy(CONFIG_DEVTMPFS_MOUNT="n")))] == ["CONFIG_DEVTMPFS_MOUNT"]
    # Clock hiding stays: PTP KVM clock is still forbidden and no-kvmclock is still a boot argument.
    assert k.RULES["CONFIG_PTP_1588_CLOCK_KVM"].value == "n"
    assert "no-kvmclock" in k.BOOT_FIXED.split()
    assert "init=/sbin/hermetic-init" in k.BOOT_FIXED.split()


def test_lock_requires_6_6_series():
    good = json.loads((ROOT / "kernel.lock.json").read_text())
    k.validate_lock(good)
    for version in ("6.1.128", "6.12.1"):
        bad = dict(good, version=version, source_url=f"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-{version}.tar.xz")
        with pytest.raises(k.KernelError):
            k.validate_lock(bad)


def test_policy_has_no_symbols_removed_before_6_6():
    # Regression: CONFIG_RANDOM_TRUST_CPU was removed in Linux 6.2 (CPU RNG trust is now
    # the default, random.trust_cpu); requiring it made every 6.6 build fail the policy.
    assert "CONFIG_RANDOM_TRUST_CPU" not in k.RULES
    for filename in ("base-x86_64.config", "hermetic.config"):
        assert "CONFIG_RANDOM_TRUST_CPU" not in k.parse_config((ROOT / filename).read_bytes())


def test_policy_requires_proc_children_for_execd_reaper():
    # Regression: without /proc/<pid>/task/<tid>/children execd's reaper fails and the
    # guest powers off before serving any vsock request.
    assert k.RULES["CONFIG_PROC_CHILDREN"].value == "y"
    assert k.parse_config((ROOT / "hermetic.config").read_bytes())["CONFIG_PROC_CHILDREN"] == "y"
    assert [f.option for f in k.check_config(config(_policy(CONFIG_PROC_CHILDREN="n")))] == ["CONFIG_PROC_CHILDREN"]


def test_netvm_filter_requires_builtin_legacy_tables():
    for option in ("CONFIG_NETFILTER_XTABLES", "CONFIG_IP_NF_IPTABLES", "CONFIG_IP_NF_FILTER"):
        assert k.RULES[option].value == "y"
        assert k.parse_config((ROOT / "hermetic.config").read_bytes())[option] == "y"
        assert [f.option for f in k.check_config(config(_policy(**{option: "n"})))] == [option]


# Root must not be able to replace or inspect the trusted kernel even when it
# creates its own device nodes or supplies arbitrary modules and BPF programs.
LOCKDOWN_REQUIRED = (
    "SECURITY SECURITYFS SECURITY_LOCKDOWN_LSM SECURITY_LOCKDOWN_LSM_EARLY "
    "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY BPF_UNPRIV_DEFAULT_OFF"
).split()
LOCKDOWN_FORBIDDEN = (
    "MODULES DEVMEM DEVKMEM KEXEC KEXEC_FILE KEXEC_CORE X86_MSR X86_CPUID "
    "PROC_KCORE HIBERNATION X86_IOPL_IOPERM BPF_KPROBE_OVERRIDE KPROBES "
    "KPROBE_EVENTS UPROBE_EVENTS BPF_EVENTS ACPI_CUSTOM_METHOD "
    "ACPI_TABLE_UPGRADE PARAVIRT KVM_GUEST PARAVIRT_CLOCK"
).split()


@pytest.mark.parametrize("symbol", LOCKDOWN_REQUIRED + LOCKDOWN_FORBIDDEN)
def test_root_ring0_policy_is_enforced(symbol):
    name = "CONFIG_" + symbol
    wanted = "y" if symbol in LOCKDOWN_REQUIRED else "n"
    assert k.RULES.get(name) == k.Rule(wanted, "Phase 3b: deny guest root access to kernel code and memory")
    values = {key: rule.value for key, rule in k.RULES.items()}
    for wrong in ("m", "n" if wanted == "y" else "y"):
        values[name] = wrong
        assert name in {finding.option for finding in k.check_config(config(values))}


def test_lockdown_retains_builtin_vm_and_grader_support():
    merged = {}
    for filename in ("base-x86_64.config", "hermetic.config"):
        merged.update(k.parse_config((ROOT / filename).read_bytes()))
    for symbol in LOCKDOWN_REQUIRED:
        assert merged.get("CONFIG_" + symbol) == "y"
    for symbol in LOCKDOWN_FORBIDDEN:
        assert merged.get("CONFIG_" + symbol) == "n"
    for name, rule in k.RULES.items():
        if rule.value == "y":
            assert merged.get(name) == "y", name
    for symbol in ("VIRTIO_BLK VIRTIO_NET VIRTIO_VSOCKETS HW_RANDOM_VIRTIO "
                   "EXT4_FS OVERLAY_FS DEVTMPFS CGROUP_BPF BPF_SYSCALL "
                   "NETFILTER_XTABLES NF_TABLES NFT_TPROXY").split():
        assert merged["CONFIG_" + symbol] == "y"


def test_policy_does_not_forbid_options_x86_force_selects():
    # x86 selects PERF_EVENTS unconditionally; forbidding it made every
    # integration build fail after olddefconfig. Lockdown confidentiality mode
    # covers its kernel-reading paths instead.
    assert k.RULES.get("CONFIG_PERF_EVENTS") is None or k.RULES["CONFIG_PERF_EVENTS"].value != "n"
