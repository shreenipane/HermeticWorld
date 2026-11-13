"""Reproducible TR-EXD-6 newc archive from two trusted static executables.

Build the inputs with bash scripts/build-trusted-execd.sh, which also remaps
host source paths in the executables. No host file
metadata, directory contents, environment, or clock enters the archive.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import struct
import sys

from hermetic_safe_io import open_parent, open_regular, validate_path

MIN_CLOCK = 315532800
MAX_CLOCK = 4102444799
MAX_BINARY_BYTES = 24 * 1024 * 1024
MAX_INITRD_BYTES = 64 * 1024 * 1024
MAX_PROGRAM_HEADERS = 128
MAX_DYNAMIC_ENTRIES = 4096
IO_CHUNK_BYTES = 65536
MAX_PUBLICATION_ATTEMPTS = 16
MAX_ARGUMENTS = 9
MAX_ARGUMENT_BYTES = 4096


def validate_static_elf(data: bytes) -> None:
    """Accept bounded ELF64 LE x86-64 executables with no runtime dependencies."""
    if not 64 <= len(data) <= MAX_BINARY_BYTES:
        raise ValueError("Invalid static executable")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, kind, machine, version, entry, phoff = header[:6]
    ehsize, phsize, phnum = header[8:11]
    if (ident[:7] != b"\x7fELF\x02\x01\x01" or kind not in (2, 3)
            or machine != 62 or version != 1 or ehsize != 64 or phsize != 56
            or not 1 <= phnum <= MAX_PROGRAM_HEADERS
            or phoff < 64 or phoff + phnum * phsize > len(data)):
        raise ValueError("Invalid static executable")
    executable_entry = False
    for index in range(phnum):
        tag, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize,
        )
        if offset + filesz > len(data) or (tag == 1 and filesz > memsz) or tag == 3:
            raise ValueError("Invalid static executable")
        if tag == 1 and flags & 1 and vaddr <= entry < vaddr + memsz:
            executable_entry = True
        if tag == 2:
            if filesz % 16 or not 1 <= filesz // 16 <= MAX_DYNAMIC_ENTRIES:
                raise ValueError("Invalid static executable")
            terminated = False
            for pos in range(offset, offset + filesz, 16):
                dynamic_tag, _ = struct.unpack_from("<QQ", data, pos)
                if dynamic_tag == 1:  # DT_NEEDED
                    raise ValueError("Invalid static executable")
                if dynamic_tag == 0:
                    terminated = True
                    break
            if not terminated:
                raise ValueError("Invalid static executable")
    if not executable_entry:
        raise ValueError("Invalid static executable")


def build_archive(execd: bytes, early_init: bytes, t_clock: int) -> bytes:
    if type(t_clock) is not int or not MIN_CLOCK <= t_clock <= MAX_CLOCK:
        raise ValueError("Invalid T_clock")
    validate_static_elf(execd)
    validate_static_elf(early_init)
    directories = (".", "dev", "mnt", "mnt/hermetic-base", "mnt/hermetic-overlay",
                   "mnt/hermetic-root", "proc", "sbin")
    entries = {name: (stat.S_IFDIR | 0o755, b"", 0, 0) for name in directories}
    entries.update({
        # Kernel console handoff before PID 1. This is a generated archive node,
        # never a device opened or copied from the build host.
        "dev/console": (stat.S_IFCHR | 0o600, b"", 5, 1),
        "init": (stat.S_IFREG | 0o755, early_init, 0, 0),
        "sbin/hermetic-execd": (stat.S_IFREG | 0o755, execd, 0, 0),
    })
    output = bytearray()
    ordered = [(name, entries[name]) for name in sorted(entries)]
    ordered.append(("TRAILER!!!", (0, b"", 0, 0)))
    for inode, (name, (mode, payload, major, minor)) in enumerate(ordered, 1):
        encoded = name.encode("ascii") + b"\0"
        fields = (inode, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1,
                  t_clock, len(payload), 0, 0, major, minor, len(encoded), 0)
        output.extend(b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields))
        output.extend(encoded)
        output.extend(b"\0" * (-len(output) % 4))
        output.extend(payload)
        output.extend(b"\0" * (-len(output) % 4))
    output.extend(b"\0" * (-len(output) % 512))
    if len(output) > MAX_INITRD_BYTES:
        raise ValueError("Initramfs size cap")
    return bytes(output)


def _read_binary(path: str) -> bytes:
    fd = open_regular(path, MAX_BINARY_BYTES)
    try:
        output = bytearray()
        # Byte count and call count are both capped, including a growing inode.
        for _ in range(MAX_BINARY_BYTES + 1):
            chunk = os.read(fd, min(IO_CHUNK_BYTES, MAX_BINARY_BYTES + 1 - len(output)))
            if not chunk:
                return bytes(output)
            output.extend(chunk)
            if len(output) > MAX_BINARY_BYTES:
                break
        raise ValueError("Executable size cap")
    finally:
        os.close(fd)


def _publish(path: str, data: bytes) -> None:
    if len(data) > MAX_INITRD_BYTES:
        raise ValueError("Initramfs size cap")
    directory, leaf = open_parent(path)
    temporary = None
    try:
        meta = os.fstat(directory)
        # A hostile peer must not be able to replace the temporary name before
        # publication. Keep this inspected directory descriptor through rename.
        if meta.st_uid not in (0, os.geteuid()) or meta.st_mode & 0o022:
            raise ValueError("Unsafe output directory")
        try:
            existing = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValueError("Unsafe output destination")
        for attempt in range(MAX_PUBLICATION_ATTEMPTS):
            candidate = f".initramfs.{attempt}"
            if candidate == leaf:
                continue
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            except FileExistsError:
                continue
            temporary = candidate
            break
        else:
            raise ValueError("Output temporary attempts exhausted")
        try:
            view = memoryview(data)
            offset = 0
            for _ in range(MAX_INITRD_BYTES + 1):
                if offset == len(data):
                    break
                count = os.write(fd, view[offset:offset + IO_CHUNK_BYTES])
                if count <= 0:
                    raise OSError("Write made no progress")
                offset += count
            if offset != len(data):
                raise ValueError("Initramfs write cap")
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, leaf, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    finally:
        try:
            if temporary is not None:
                os.unlink(temporary, dir_fd=directory)
        finally:
            os.close(directory)


def build_initramfs(execd: str, early_init: str, output: str, t_clock: int) -> str:
    # Validate all scalar inputs before any filesystem access.
    if type(t_clock) is not int or not MIN_CLOCK <= t_clock <= MAX_CLOCK:
        raise ValueError("Invalid T_clock")
    for path in (execd, early_init, output):
        validate_path(path)
    archive = build_archive(_read_binary(execd), _read_binary(early_init), t_clock)
    _publish(output, archive)
    return hashlib.sha256(archive).hexdigest()


def main() -> int:
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError("Invalid build arguments")

    try:
        if len(sys.argv) > MAX_ARGUMENTS or any(len(a) > MAX_ARGUMENT_BYTES for a in sys.argv):
            raise ValueError("Build argument cap")
        parser = Parser(description=__doc__)
        parser.add_argument("--execd", required=True)
        parser.add_argument("--early-init", required=True)
        parser.add_argument("--output", required=True)
        parser.add_argument("--t-clock", required=True, type=int)
        args = parser.parse_args()
        digest = build_initramfs(args.execd, args.early_init, args.output, args.t_clock)
    except (OSError, ValueError, struct.error):
        print("Initramfs build refused", file=sys.stderr)
        return 2
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
