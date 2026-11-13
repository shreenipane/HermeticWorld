import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess

import pytest

from hermetic_slice import initramfs as mod

MAX_STATIC_BUILD_SECONDS = 300


def test_trusted_static_build_has_no_host_source_paths(tmp_path):
    root = Path(__file__).resolve().parents[2]
    target = tmp_path / "static target"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="4")
    result = subprocess.run(
        ["bash", str(root / "scripts/build-trusted-execd.sh")],
        cwd=root, env=env, capture_output=True,
        timeout=MAX_STATIC_BUILD_SECONDS, check=False,
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""
    directory = target / "x86_64-unknown-linux-gnu/release"
    binaries = [mod._read_binary(str(directory / name))
                for name in ("hermetic-execd", "hermetic-init")]
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    for binary in binaries:
        mod.validate_static_elf(binary)
        for prefix in (root, cargo_home, Path.home()):
            assert os.fsencode(str(prefix)) not in binary
    assert mod.build_archive(*binaries, 1700000000).startswith(b"070701")


def test_trusted_static_build_errors_are_static(tmp_path):
    root = Path(__file__).resolve().parents[2]
    commands = tmp_path / "commands"
    commands.mkdir()
    cargo = commands / "cargo"
    cargo.write_text("#!/bin/sh\nprintf 'secret-host-path' >&2\nexit 1\n")
    cargo.chmod(0o700)
    env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}")
    for cargo_home in (os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
                       str(tmp_path / "secret-host-missing")):
        env["CARGO_HOME"] = cargo_home
        result = subprocess.run(
            ["bash", str(root / "scripts/build-trusted-execd.sh")],
            cwd=root, env=env, capture_output=True, timeout=MAX_STATIC_BUILD_SECONDS,
            check=False,
        )
        assert result.returncode == 2
        assert result.stdout == b"" and result.stderr == b"Trusted executable build refused\n"


def elf(payload=b"trusted"):
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                         2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    return header + struct.pack("<IIQQQQQQ", 1, 5, 120, 0x400078, 0,
                                len(payload), len(payload), 1) + payload


def entries(data):
    pos = 0
    result = []
    while data[pos:pos + 6] == b"070701":
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        name = data[pos + 110:pos + 110 + fields[11] - 1].decode("ascii")
        pos += 110 + fields[11]
        pos += -pos % 4
        payload = data[pos:pos + fields[6]]
        pos += fields[6]
        pos += -pos % 4
        result.append((name, fields, payload))
        if name == "TRAILER!!!":
            assert data[pos:] == b"\0" * (len(data) - pos)
            break
    return result


def test_initramfs_known_answer_contents_and_metadata():
    data = mod.build_archive(elf(), elf(b"shim"), 1700000000)
    assert hashlib.sha256(data).hexdigest() == "a7d9a32e7602de912d24e8a03ae2ce3c4547ad6c6866c6ce80f230cc0766f3ab"
    parsed = entries(data)
    names = [name for name, _, _ in parsed[:-1]]
    assert names == sorted(names)
    assert set(names) == {".", "dev", "dev/console", "init", "mnt", "mnt/hermetic-base",
                          "mnt/hermetic-overlay", "mnt/hermetic-root", "proc",
                          "sbin", "sbin/hermetic-execd"}
    assert len(data) % 512 == 0
    for inode, (name, f, payload) in enumerate(parsed, 1):
        assert f[0] == inode and f[2:4] == [0, 0]
        assert f[5] == 1700000000 and f[7:9] == [0, 0] and f[12] == 0
        if name == "dev/console":
            assert f[1] == stat.S_IFCHR | 0o600 and f[9:11] == [5, 1]
        elif name == "init":
            assert payload == elf(b"shim") and f[1] == stat.S_IFREG | 0o755
        elif name == "sbin/hermetic-execd":
            assert payload == elf() and f[1] == stat.S_IFREG | 0o755
        elif name != "TRAILER!!!":
            assert f[1] == stat.S_IFDIR | 0o755 and not payload


def test_initramfs_reproducible_private_atomic_and_independent_of_host_metadata(tmp_path, monkeypatch):
    exe, shim, out = (tmp_path / n for n in ("execd", "shim", "archive"))
    exe.write_bytes(elf())
    shim.write_bytes(elf(b"shim"))
    digest = mod.build_initramfs(str(exe), str(shim), str(out), 1700000000)
    first = out.read_bytes()
    os.utime(exe, (123, 456))
    os.chmod(exe, 0o700)
    monkeypatch.setenv("HOSTNAME", "secret-host")
    monkeypatch.setenv("TZ", "Pacific/Honolulu")
    monkeypatch.setenv("LANG", "secret-locale")
    out.write_bytes(b"old")
    assert mod.build_initramfs(str(exe), str(shim), str(out), 1700000000) == digest
    assert out.read_bytes() == first
    assert out.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".tmp.hermetic.*"))
    assert mod.build_archive(elf(), elf(b"shim"), 1700000001) != first


def test_initramfs_rejects_all_truncations_dynamic_and_malformed_elf():
    good = elf()
    for end in range(len(good)):
        with pytest.raises(ValueError):
            mod.validate_static_elf(good[:end])
    for offset, fmt, value in [(0, "B", 0), (4, "B", 1), (18, "H", 3),
                                (32, "Q", 2**64 - 1), (56, "H", 129),
                                (54, "H", 1), (64, "I", 3), (96, "Q", 2**64 - 1)]:
        bad = bytearray(good)
        struct.pack_into("<" + fmt, bad, offset, value)
        with pytest.raises(ValueError):
            mod.validate_static_elf(bad)
    dynamic = bytearray(elf(b"\0" * 16))
    struct.pack_into("<I", dynamic, 64, 2)
    struct.pack_into("<Q", dynamic, 120, 1)  # DT_NEEDED
    with pytest.raises(ValueError):
        mod.validate_static_elf(dynamic)


def test_static_elf_rejects_interpreter_and_dependencies_with_valid_load_segment():
    def with_segment(tag, content):
        header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                             3, 62, 1, 0x4000B0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        load = struct.pack("<IIQQQQQQ", 1, 5, 176, 0x4000B0, 0,
                           1 + len(content), 1 + len(content), 1)
        extra = struct.pack("<IIQQQQQQ", tag, 4, 177, 0x4000B1, 0,
                            len(content), len(content), 1)
        return header + load + extra + b"\xc3" + content

    # Static PIE can have PT_DYNAMIC without any DT_NEEDED. Keep the executable
    # load segment valid in every case so each dependency check is exercised.
    mod.validate_static_elf(with_segment(2, struct.pack("<QQ", 0, 0)))
    for bad in (with_segment(3, b"/lib/ld.so\0"),
                with_segment(2, struct.pack("<QQQQ", 1, 0, 0, 0)),
                with_segment(2, struct.pack("<QQ", 2, 0)),
                with_segment(2, b"x")):
        with pytest.raises(ValueError):
            mod.validate_static_elf(bad)


def test_initramfs_invalid_inputs_never_publish_and_do_not_follow_links(tmp_path, monkeypatch):
    exe, shim, out = (tmp_path / n for n in ("execd", "shim", "archive"))
    exe.write_bytes(elf())
    shim.write_bytes(elf())
    out.write_bytes(b"protected")
    for clock in (True, -1, 0, mod.MIN_CLOCK - 1, mod.MAX_CLOCK + 1, "1700000000"):
        with pytest.raises(ValueError):
            mod.build_initramfs("/absent", "/absent", str(out), clock)
        assert out.read_bytes() == b"protected"
    link = tmp_path / "link"
    link.symlink_to(exe)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    for source in (link, fifo, tmp_path, alias / "execd"):
        with pytest.raises((OSError, ValueError)):
            mod.build_initramfs(str(source), str(shim), str(out), 1700000000)
        assert out.read_bytes() == b"protected"
    for dest in (link, fifo, tmp_path, alias / "archive"):
        with pytest.raises((OSError, ValueError)):
            mod.build_initramfs(str(exe), str(shim), str(dest), 1700000000)
        assert exe.read_bytes() == elf() and out.read_bytes() == b"protected"
    monkeypatch.setattr(mod, "MAX_BINARY_BYTES", len(elf()) - 1)
    with pytest.raises((OSError, ValueError)):
        mod.build_initramfs(str(exe), str(shim), str(out), 1700000000)
    assert out.read_bytes() == b"protected"


def test_initramfs_archive_cap_and_clock_bounds(monkeypatch):
    for clock in (mod.MIN_CLOCK, mod.MAX_CLOCK):
        assert entries(mod.build_archive(elf(), elf(), clock))[0][1][5] == clock
    monkeypatch.setattr(mod, "MAX_INITRD_BYTES", 1)
    with pytest.raises(ValueError, match="size cap"):
        mod.build_archive(elf(), elf(), 1700000000)


def test_initramfs_atomic_failure_exclusive_parent_and_bounded_temporary_names(tmp_path, monkeypatch):
    out = tmp_path / "archive"
    out.write_bytes(b"old")
    os.chmod(tmp_path, 0o777)
    with pytest.raises(ValueError, match="Unsafe output directory"):
        mod._publish(str(out), b"new")
    os.chmod(tmp_path, 0o700)
    with monkeypatch.context() as patch:
        patch.setattr(os, "write", lambda *a: 0)
        with pytest.raises(OSError):
            mod._publish(str(out), b"new")
    assert out.read_bytes() == b"old" and not list(tmp_path.glob(".initramfs.*"))
    for index in range(mod.MAX_PUBLICATION_ATTEMPTS):
        (tmp_path / f".initramfs.{index}").symlink_to(out)
    with pytest.raises(ValueError, match="attempts exhausted"):
        mod._publish(str(out), b"new")
    assert out.read_bytes() == b"old"


def test_initramfs_cli_errors_are_static_without_input_echo(monkeypatch, capsys):
    for args in (["--t-clock", "secret-host"], ["--unknown-secret"],
                 ["x"] * (mod.MAX_ARGUMENTS + 1)):
        monkeypatch.setattr("sys.argv", ["initramfs"] + args)
        assert mod.main() == 2
        output = capsys.readouterr()
        assert output.out == "" and output.err == "Initramfs build refused\n"
