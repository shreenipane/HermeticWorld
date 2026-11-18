"""Throwaway microVM-isolated rebuild builder for Detector D7.

Runs rebuild recipes inside an ephemeral, disposable microVM (never on the
host), enforcing bounded execution time, bounded output, and strict filesystem
isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
from typing import Any, Protocol, Sequence

from hermetic_d7.deep_audit import (
    BuildFailedError,
    BuildRequest,
    IsolatedBuilder,
    RecipeEntry,
)
from hermetic_d7.normalise import (
    HermeticD7Error,
    InvalidArtifactError,
    MAX_ARTIFACT_BYTES,
    READ_CHUNK_SIZE,
    ResourceLimitError,
    SecurityViolationError,
    validate_member_path,
)
from hermetic_safe_io import (
    UnsafePathError,
    open_parent,
    open_regular,
    open_regular_at,
    validate_path,
)

DEFAULT_BUILD_TIMEOUT_S: float = 120.0
MIN_BUILD_TIMEOUT_S: float = 1.0
MAX_BUILD_TIMEOUT_S: float = 600.0

DEFAULT_VCPUS: int = 1
MIN_VCPUS: int = 1
MAX_VCPUS: int = 32

DEFAULT_MEMORY_MIB: int = 256
MIN_MEMORY_MIB: int = 64
MAX_MEMORY_MIB: int = 4096

DEFAULT_T_CLOCK: int = 1700000000
MIN_T_CLOCK: int = 315532800
MAX_T_CLOCK: int = 4102444799

DEFAULT_MAX_OUTPUT_BYTES: int = 16 * 1024 * 1024
MAX_OUTPUT_BYTES: int = 64 * 1024 * 1024

MAX_TRANSFER_CHUNK_BYTES: int = 1024 * 1024
MAX_TRANSFER_CHUNKS: int = 64
MAX_LOCK_BYTES: int = 64 * 1024
MAX_CONFIG_BYTES: int = 64 * 1024

MAX_SOURCE_ENTRIES: int = 10000
MAX_SOURCE_DEPTH: int = 32
MAX_SOURCE_BYTES: int = 64 * 1024 * 1024
MAX_OUTPUT_PARTS: int = 64

MAX_PATH_BYTES: int = 4096
MAX_PATH_COMPONENTS: int = 128
MAX_EXEC_OUTPUT_BYTES: int = 1024 * 1024
MAX_HANDSHAKE_BYTES: int = 64
MAX_FRAME_BYTES: int = 4 * 1024 * 1024 + 65536
MAX_JSON_DEPTH: int = 64

CONNECT_TIMEOUT_S: float = 30.0
API_TIMEOUT_S: float = 10.0
SHUTDOWN_TIMEOUT_S: float = 5.0
POLL_INTERVAL_S: float = 0.02

OVERLAY_SIZE_BYTES: int = 64 * 1024 * 1024


def _same_object(before: os.stat_result, after: os.stat_result) -> bool:
    return (before.st_dev, before.st_ino, before.st_mode) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
    )


def _check_safe_host_file(
    path: Path | str,
    max_bytes: int,
    *,
    check_executable: bool = False,
) -> None:
    """Validate a host file component-by-component without following symlinks."""
    raw = str(path)
    if not raw.startswith("/"):
        raise SecurityViolationError("file path must be absolute")
    if "\0" in raw or len(raw.encode("utf-8", "surrogatepass")) > MAX_PATH_BYTES:
        raise SecurityViolationError("invalid file path")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if ".." in parts or len(parts) > MAX_PATH_COMPONENTS:
        raise SecurityViolationError("invalid path components")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open("/", flags)
    try:
        caller_uid = os.getuid()
        for idx, part in enumerate(parts):
            is_last = idx == len(parts) - 1
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            if is_last:
                if not stat.S_ISREG(before.st_mode):
                    raise SecurityViolationError("target is not a regular file")
                if before.st_mode & 0o022:
                    raise SecurityViolationError("target file is writable by others")
                if before.st_uid not in (0, caller_uid):
                    raise SecurityViolationError("target file not owned by caller or root")
                if before.st_size > max_bytes:
                    raise ResourceLimitError("target file exceeds byte cap")
                if check_executable and not (before.st_mode & 0o111):
                    raise SecurityViolationError("target file is not executable")
                # Open with O_PATH to verify no race changed the inode
                pinned = os.open(part, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
                try:
                    after = os.fstat(pinned)
                    if not _same_object(before, after):
                        raise SecurityViolationError("file changed during inspection")
                finally:
                    os.close(pinned)
            else:
                if not stat.S_ISDIR(before.st_mode):
                    raise SecurityViolationError("path component is not a directory")
                child = os.open(part, flags, dir_fd=current)
                try:
                    after = os.fstat(child)
                    if not _same_object(before, after):
                        raise SecurityViolationError("directory changed during inspection")
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
    except OSError:
        raise SecurityViolationError("cannot inspect host file safely") from None
    finally:
        os.close(current)


def _verify_firecracker_lock(fc_path: Path, lock_path: Path) -> None:
    """Check that the Firecracker binary matches the measured lock SHA-256."""
    _check_safe_host_file(lock_path, MAX_LOCK_BYTES)
    fd_lock = open_regular(lock_path, MAX_LOCK_BYTES)
    try:
        raw_lock = _read_all_bounded(fd_lock, MAX_LOCK_BYTES)
        doc = json.loads(raw_lock.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise InvalidArtifactError("invalid Firecracker lock JSON") from None
    finally:
        os.close(fd_lock)

    if not isinstance(doc, dict):
        raise InvalidArtifactError("Firecracker lock must be an object")

    expected_sha = doc.get("firecracker_sha256")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        raise InvalidArtifactError("invalid firecracker_sha256 in lock")

    hasher = hashlib.sha256()
    fd_fc = open_regular(fc_path, MAX_OUTPUT_BYTES * 4)
    try:
        total = 0
        cap = MAX_OUTPUT_BYTES * 4
        while total <= cap:
            chunk = os.read(fd_fc, min(READ_CHUNK_SIZE, cap - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ResourceLimitError("firecracker binary exceeds byte cap")
            hasher.update(chunk)
    finally:
        os.close(fd_fc)
    actual_sha = hasher.hexdigest()
    if actual_sha.lower() != expected_sha.lower():
        raise SecurityViolationError("Firecracker binary does not match measured lock")


@dataclass(frozen=True)
class VmBuilderConfig:
    """Validated configuration for the throwaway microVM rebuild builder."""

    firecracker_bin: Path
    kernel_image: Path
    rootfs_image: Path
    firecracker_lock: Path | None = None
    cpu_template: Path | None = None
    t_clock: int = DEFAULT_T_CLOCK
    vcpus: int = DEFAULT_VCPUS
    memory_mib: int = DEFAULT_MEMORY_MIB
    build_timeout_s: float = DEFAULT_BUILD_TIMEOUT_S
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES

    def validate(self) -> None:
        """Validate all parameters, paths, and limits strictly."""
        if not (MIN_T_CLOCK <= self.t_clock <= MAX_T_CLOCK):
            raise InvalidArtifactError("t_clock out of range")
        if not (MIN_VCPUS <= self.vcpus <= MAX_VCPUS):
            raise InvalidArtifactError("vcpus out of range")
        if not (MIN_MEMORY_MIB <= self.memory_mib <= MAX_MEMORY_MIB):
            raise InvalidArtifactError("memory_mib out of range")
        if (
            not isinstance(self.build_timeout_s, (int, float))
            or not math.isfinite(self.build_timeout_s)
            or not (MIN_BUILD_TIMEOUT_S <= self.build_timeout_s <= MAX_BUILD_TIMEOUT_S)
        ):
            raise InvalidArtifactError("build_timeout_s out of range")
        if not (1024 <= self.max_output_bytes <= MAX_OUTPUT_BYTES):
            raise InvalidArtifactError("max_output_bytes out of range")

        _check_safe_host_file(self.firecracker_bin, MAX_OUTPUT_BYTES * 4, check_executable=True)
        _check_safe_host_file(self.kernel_image, MAX_OUTPUT_BYTES * 4)
        _check_safe_host_file(self.rootfs_image, MAX_OUTPUT_BYTES * 64)

        if self.firecracker_lock is not None:
            _verify_firecracker_lock(self.firecracker_bin, self.firecracker_lock)

        if self.cpu_template is not None:
            _check_safe_host_file(self.cpu_template, MAX_CONFIG_BYTES)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VmBuilderConfig:
        if not isinstance(data, dict):
            raise InvalidArtifactError("VM builder config must be a JSON object")

        required = {"firecracker_bin", "kernel_image", "rootfs_image"}
        missing = required - set(data)
        if missing:
            raise InvalidArtifactError(f"missing required config keys: {sorted(missing)}")

        for key in ("firecracker_bin", "kernel_image", "rootfs_image"):
            if not isinstance(data[key], str) or not data[key]:
                raise InvalidArtifactError(f"{key} must be a non-empty string path")
        for key in ("firecracker_lock", "cpu_template"):
            if key in data and (not isinstance(data[key], str) or not data[key]):
                raise InvalidArtifactError(f"{key} must be a non-empty string path when given")

        fc_bin = Path(data["firecracker_bin"])
        kernel = Path(data["kernel_image"])
        rootfs = Path(data["rootfs_image"])

        lock = Path(data["firecracker_lock"]) if "firecracker_lock" in data else None
        cpu = Path(data["cpu_template"]) if "cpu_template" in data else None

        t_clock = data.get("t_clock", DEFAULT_T_CLOCK)
        if not isinstance(t_clock, int):
            raise InvalidArtifactError("t_clock must be an integer")

        vcpus = data.get("vcpus", DEFAULT_VCPUS)
        if not isinstance(vcpus, int):
            raise InvalidArtifactError("vcpus must be an integer")

        memory_mib = data.get("memory_mib", DEFAULT_MEMORY_MIB)
        if not isinstance(memory_mib, int):
            raise InvalidArtifactError("memory_mib must be an integer")

        timeout_s = data.get("build_timeout_s", DEFAULT_BUILD_TIMEOUT_S)
        if not isinstance(timeout_s, (int, float)):
            raise InvalidArtifactError("build_timeout_s must be a number")

        max_out = data.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)
        if not isinstance(max_out, int):
            raise InvalidArtifactError("max_output_bytes must be an integer")

        config = cls(
            firecracker_bin=fc_bin,
            kernel_image=kernel,
            rootfs_image=rootfs,
            firecracker_lock=lock,
            cpu_template=cpu,
            t_clock=t_clock,
            vcpus=vcpus,
            memory_mib=memory_mib,
            build_timeout_s=float(timeout_s),
            max_output_bytes=max_out,
        )
        config.validate()
        return config

    @classmethod
    def from_json_file(cls, path: str | Path) -> VmBuilderConfig:
        _check_safe_host_file(path, MAX_CONFIG_BYTES)
        fd = open_regular(path, MAX_CONFIG_BYTES)
        try:
            raw = _read_all_bounded(fd, MAX_CONFIG_BYTES)
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            raise InvalidArtifactError("invalid VM builder config JSON") from None
        finally:
            os.close(fd)
        return cls.from_dict(data)

    @classmethod
    def from_env(cls) -> VmBuilderConfig | None:
        fc = os.environ.get("HERMETIC_FC_BIN")
        kernel = os.environ.get("HERMETIC_KERNEL")
        rootfs = os.environ.get("HERMETIC_D7_ROOTFS") or os.environ.get("HERMETIC_ROOTFS")
        if not (fc and kernel and rootfs):
            return None

        lock = os.environ.get("HERMETIC_FIRECRACKER_LOCK")
        clock_str = os.environ.get("HERMETIC_T_CLOCK")
        if clock_str is None:
            t_clock = DEFAULT_T_CLOCK
        else:
            try:
                t_clock = int(clock_str, 10)
            except ValueError:
                raise InvalidArtifactError("HERMETIC_T_CLOCK must be an integer") from None

        config = cls(
            firecracker_bin=Path(os.path.realpath(fc)),
            kernel_image=Path(os.path.realpath(kernel)),
            rootfs_image=Path(os.path.realpath(rootfs)),
            firecracker_lock=Path(os.path.realpath(lock)) if lock else None,
            t_clock=t_clock,
        )
        config.validate()
        return config


def build_source_tar(source_fd: int, t_clock: int) -> bytes:
    """Iteratively package the pinned source directory into a deterministic tar stream."""
    count = 0
    total_bytes = 0
    buf = io.BytesIO()

    with tarfile.open(mode="w", fileobj=buf, format=tarfile.PAX_FORMAT) as tar:

        def walk(current_fd: int, prefix: str, depth: int) -> None:
            nonlocal count, total_bytes
            if depth > MAX_SOURCE_DEPTH:
                raise ResourceLimitError("source directory nesting depth cap exceeded")

            names = []
            with os.scandir(current_fd) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_SOURCE_ENTRIES:
                        raise ResourceLimitError("source member count cap exceeded")
                    names.append(entry.name)

            for name in sorted(names):
                rel_name = f"{prefix}/{name}" if prefix else name
                st = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    ti = tarfile.TarInfo(rel_name)
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o755
                    ti.mtime = min(int(st.st_mtime), t_clock)
                    ti.uid = 0
                    ti.gid = 0
                    ti.uname = ""
                    ti.gname = ""
                    tar.addfile(ti)

                    child_fd = _open_dir_no_follow(current_fd, name)
                    try:
                        walk(child_fd, rel_name, depth + 1)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(st.st_mode):
                    if st.st_size > MAX_SOURCE_BYTES:
                        raise ResourceLimitError("source file exceeds byte cap")
                    file_fd = _open_file_no_follow(current_fd, name)
                    try:
                        file_data = _read_all_bounded(file_fd, MAX_SOURCE_BYTES)
                    finally:
                        os.close(file_fd)

                    total_bytes += len(file_data)
                    if total_bytes > MAX_SOURCE_BYTES:
                        raise ResourceLimitError("source archive total byte cap exceeded")

                    ti = tarfile.TarInfo(rel_name)
                    ti.type = tarfile.REGTYPE
                    ti.size = len(file_data)
                    ti.mode = 0o755 if (st.st_mode & 0o111) else 0o644
                    ti.mtime = min(int(st.st_mtime), t_clock)
                    ti.uid = 0
                    ti.gid = 0
                    ti.uname = ""
                    ti.gname = ""
                    tar.addfile(ti, io.BytesIO(file_data))
                elif stat.S_ISLNK(st.st_mode):
                    target = os.readlink(name, dir_fd=current_fd)
                    if target.startswith("/") or "\0" in target:
                        raise SecurityViolationError("unsafe symlink in source tree")
                    # Check symlink relative traversal does not escape root
                    parts = target.split("/")
                    check_depth = depth
                    for p in parts:
                        check_depth += -1 if p == ".." else (0 if p in ("", ".") else 1)
                        if check_depth < 0:
                            raise SecurityViolationError("source link escapes root")

                    ti = tarfile.TarInfo(rel_name)
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = target
                    ti.mode = 0o777
                    ti.mtime = min(int(st.st_mtime), t_clock)
                    ti.uid = 0
                    ti.gid = 0
                    ti.uname = ""
                    ti.gname = ""
                    tar.addfile(ti)
                else:
                    raise SecurityViolationError("unsupported special file in source tree")

        walk(source_fd, "", 0)

    tar_bytes = buf.getvalue()
    if len(tar_bytes) > MAX_SOURCE_BYTES:
        raise ResourceLimitError("source archive exceeds byte cap")
    return tar_bytes


def _open_dir_no_follow(parent_fd: int, name: str) -> int:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise SecurityViolationError("expected directory")
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        after = os.fstat(child)
        if not _same_object(before, after):
            raise SecurityViolationError("directory changed during open")
        return child
    except BaseException:
        os.close(child)
        raise


def _open_file_no_follow(parent_fd: int, name: str) -> int:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise SecurityViolationError("expected regular file")
    child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        after = os.fstat(child)
        if not _same_object(before, after):
            raise SecurityViolationError("file changed during open")
        return child
    except BaseException:
        os.close(child)
        raise


def _read_all_bounded(fd: int, cap: int) -> bytes:
    chunks = []
    total = 0
    while total <= cap:
        chunk = os.read(fd, min(READ_CHUNK_SIZE, cap - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise ResourceLimitError("file exceeds byte cap")
        chunks.append(chunk)
    return b"".join(chunks)


def unpack_artifact_tar(
    tar_bytes: bytes,
    output_dir: Path,
    expected_name: str,
    max_bytes: int,
) -> None:
    """Safely unpack artifact tar bytes into output_dir without following symlinks."""
    if len(tar_bytes) > max_bytes:
        raise ResourceLimitError("artifact tar exceeds byte cap")

    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            members = tar.getmembers()
            if len(members) > MAX_SOURCE_ENTRIES:
                raise ResourceLimitError("artifact member count cap exceeded")

            total_unpacked = 0
            for member in members:
                norm_name = member.name.lstrip("/").replace("\\", "/")
                parts = [p for p in norm_name.split("/") if p not in ("", ".")]
                if ".." in parts or not parts:
                    raise SecurityViolationError("invalid member path in artifact")
                if parts[0] != expected_name:
                    raise BuildFailedError("artifact member path does not match expected name")

                target_path = output_dir.joinpath(*parts)
                # Ensure target stays strictly inside output_dir
                try:
                    target_path.relative_to(output_dir)
                except ValueError:
                    raise SecurityViolationError("artifact path escapes output directory") from None

                if member.isdir():
                    target_path.mkdir(mode=0o700, parents=True, exist_ok=True)
                elif member.isreg():
                    if member.size > max_bytes:
                        raise ResourceLimitError("artifact file member exceeds byte cap")
                    target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    fd = os.open(
                        target_path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o700 if (member.mode & 0o111) else 0o600,
                    )
                    try:
                        reader = tar.extractfile(member)
                        if reader is None:
                            raise BuildFailedError("cannot read member from artifact tar")
                        written = 0
                        while written < member.size:
                            chunk = reader.read(min(READ_CHUNK_SIZE, member.size - written))
                            if not chunk:
                                break
                            written += len(chunk)
                            total_unpacked += len(chunk)
                            if total_unpacked > max_bytes:
                                raise ResourceLimitError("total artifact bytes exceeded cap")
                            os.write(fd, chunk)
                    finally:
                        os.close(fd)
                elif member.issym():
                    raise SecurityViolationError("builder output is a symlink")
                else:
                    raise SecurityViolationError("unsupported special file in artifact tar")
    except (tarfile.TarError, UnicodeDecodeError):
        raise BuildFailedError("artifact tar archive is corrupt or malformed") from None

    expected_path = output_dir / expected_name
    if not expected_path.exists():
        raise BuildFailedError("builder must produce exactly the named artifact")


class ExecdClient:
    """Bounded, deadline-enforcing RPC client for hermetic-execd over Firecracker vsock."""

    def __init__(self, vsock_path: str | Path) -> None:
        self.vsock_path = str(vsock_path)

    def call(self, request: dict[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("execd call deadline exceeded")
            return left

        req_bytes = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(req_bytes) > MAX_FRAME_BYTES:
            raise ResourceLimitError("RPC frame limit exceeded")

        frame = struct.pack("<I", len(req_bytes)) + req_bytes

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(remaining())
            stream.connect(self.vsock_path)
            stream.settimeout(remaining())
            stream.sendall(b"CONNECT 5000\n")

            handshake = bytearray()
            for _ in range(MAX_HANDSHAKE_BYTES):
                stream.settimeout(remaining())
                byte = stream.recv(1)
                if not byte:
                    raise BuildFailedError("vsock handshake truncated")
                handshake.extend(byte)
                if byte == b"\n":
                    break

            prefix, sep, port = bytes(handshake).partition(b" ")
            digits = port.removesuffix(b"\n")
            if (
                prefix != b"OK"
                or not sep
                or not port.endswith(b"\n")
                or not digits
                or not digits.isdigit()
            ):
                raise BuildFailedError("invalid vsock handshake")

            stream.settimeout(remaining())
            stream.sendall(frame)

            # Read 4-byte little-endian length
            len_bytes = bytearray()
            while len(len_bytes) < 4:
                stream.settimeout(remaining())
                part = stream.recv(4 - len(len_bytes))
                if not part:
                    raise BuildFailedError("truncated response frame length")
                len_bytes.extend(part)

            (resp_len,) = struct.unpack("<I", len_bytes)
            if not (0 < resp_len <= MAX_FRAME_BYTES):
                raise ResourceLimitError("RPC response frame size invalid")

            # Read response body
            body = bytearray()
            while len(body) < resp_len:
                stream.settimeout(remaining())
                chunk = stream.recv(min(65536, resp_len - len(body)))
                if not chunk:
                    raise BuildFailedError("truncated response body")
                body.extend(chunk)

            try:
                resp = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise BuildFailedError("invalid JSON from execd") from None

            if not isinstance(resp, dict):
                raise BuildFailedError("execd reply must be an object")

            if resp.get("type") == "error":
                raise BuildFailedError("execd returned error")

            return resp


class FirecrackerApiClient:
    """Minimal, strict HTTP/1.1 client over Firecracker API Unix domain socket."""

    def __init__(self, socket_path: str | Path, timeout: float = API_TIMEOUT_S) -> None:
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, bytes]:
        deadline = time.monotonic() + self.timeout

        payload = json.dumps(body).encode("utf-8") if body is not None else b""
        req = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Accept: application/json\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + payload

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            left = max(0.1, deadline - time.monotonic())
            stream.settimeout(left)
            stream.connect(self.socket_path)
            stream.sendall(req)

            resp_buf = bytearray()
            while True:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError("Firecracker API call timed out")
                header_end = resp_buf.find(b"\r\n\r\n")
                if header_end >= 0:
                    headers = resp_buf[:header_end].decode("latin1")
                    content_length = None
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            _, _, cl_val = line.partition(":")
                            if cl_val.strip().isdigit():
                                content_length = int(cl_val.strip())
                    if content_length is not None:
                        body_len = len(resp_buf) - (header_end + 4)
                        if body_len >= content_length:
                            break
                    elif headers.startswith("HTTP/1.1 204") or headers.startswith("HTTP/1.0 204"):
                        break

                stream.settimeout(rem)
                chunk = stream.recv(4096)
                if not chunk:
                    break
                resp_buf.extend(chunk)
                if len(resp_buf) > 65536:
                    raise ResourceLimitError("Firecracker API response too large")

        header_end = resp_buf.find(b"\r\n\r\n")
        if header_end < 0:
            raise BuildFailedError("malformed Firecracker API response")

        headers = resp_buf[:header_end].decode("latin1")
        resp_body = bytes(resp_buf[header_end + 4 :])

        lines = headers.split("\r\n")
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            raise BuildFailedError("malformed HTTP status line")

        status_code = int(status_parts[1])
        return status_code, resp_body

    def put(self, path: str, body: dict[str, Any] | None = None) -> None:
        status, resp_body = self.request("PUT", path, body)
        if not (200 <= status < 300):
            raise BuildFailedError("Firecracker API configuration rejected")


class MicroVmRunner(Protocol):
    """Protocol for launching and executing a build inside a microVM."""

    def run_build(
        self,
        request: BuildRequest,
        source_tar: bytes,
        work_dir: Path,
    ) -> bytes:
        """Run the build inside the microVM and return the output artifact tar bytes."""
        ...


class FirecrackerRunner:
    """Orchestrates an ephemeral Firecracker microVM with KVM and hermetic-execd."""

    def __init__(self, config: VmBuilderConfig) -> None:
        self.config = config

    def _create_overlay(self, overlay_path: Path) -> None:
        """Create a private, sparse 64 MiB ext4 overlay disk."""
        fd = os.open(
            overlay_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.ftruncate(fd, OVERLAY_SIZE_BYTES)
        finally:
            os.close(fd)

        mke2fs = shutil.which("mke2fs") or "/usr/sbin/mke2fs"
        if not os.path.exists(mke2fs):
            raise BuildFailedError("mke2fs required for microVM overlay disk")

        proc = subprocess.run(
            [
                mke2fs,
                "-q",
                "-t",
                "ext4",
                "-F",
                "-U",
                "00000000-0000-0000-0000-000000000001",
                "-E",
                "hash_seed=00000000-0000-0000-0000-000000000002,lazy_itable_init=0,lazy_journal_init=0",
                str(overlay_path),
            ],
            env={
                "SOURCE_DATE_EPOCH": str(self.config.t_clock),
                "E2FSPROGS_FAKE_TIME": str(self.config.t_clock),
                "LC_ALL": "C",
                "TZ": "UTC",
                "PATH": "/usr/sbin:/sbin:/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise BuildFailedError("failed to create microVM overlay disk")

    def run_build(
        self,
        request: BuildRequest,
        source_tar: bytes,
        work_dir: Path,
    ) -> bytes:
        api_sock = work_dir / "fc-api.sock"
        vsock_sock = work_dir / "vsock.sock"
        overlay_img = work_dir / "overlay.img"

        self._create_overlay(overlay_img)

        # Start Firecracker child process
        fc_proc = subprocess.Popen(
            [str(self.config.firecracker_bin), "--api-sock", str(api_sock)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        try:
            # Wait for Firecracker API socket
            api_client = FirecrackerApiClient(api_sock)
            start_wait = time.monotonic()
            while True:
                if fc_proc.poll() is not None:
                    raise BuildFailedError("Firecracker exited unexpectedly on startup")
                if api_sock.exists():
                    try:
                        # Probe API socket
                        status, _ = api_client.request("GET", "/")
                        break
                    except (OSError, TimeoutError):
                        pass
                if time.monotonic() - start_wait > API_TIMEOUT_S:
                    raise BuildFailedError("Firecracker API readiness timed out")
                time.sleep(POLL_INTERVAL_S)

            # Configure VM via Firecracker API
            boot_args = (
                f"console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda "
                f"init=/sbin/hermetic-init clocksource=tsc tsc=reliable "
                f"hermetic.t={self.config.t_clock} ro"
            )
            api_client.put(
                "/boot-source",
                {
                    "kernel_image_path": str(self.config.kernel_image),
                    "boot_args": boot_args,
                },
            )
            api_client.put(
                "/drives/rootfs",
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(self.config.rootfs_image),
                    "is_root_device": True,
                    "is_read_only": True,
                },
            )
            api_client.put(
                "/drives/overlay",
                {
                    "drive_id": "overlay",
                    "path_on_host": str(overlay_img),
                    "is_root_device": False,
                    "is_read_only": False,
                },
            )
            api_client.put(
                "/vsock",
                {
                    "vsock_id": "vsock",
                    "guest_cid": 3,
                    "uds_path": str(vsock_sock),
                },
            )
            api_client.put(
                "/machine-config",
                {
                    "vcpu_count": self.config.vcpus,
                    "mem_size_mib": self.config.memory_mib,
                    "smt": False,
                },
            )
            if self.config.cpu_template is not None:
                fd_cpu = open_regular(self.config.cpu_template, MAX_CONFIG_BYTES)
                try:
                    raw_cpu = _read_all_bounded(fd_cpu, MAX_CONFIG_BYTES)
                    tmpl_data = json.loads(raw_cpu.decode("utf-8"))
                except (OSError, UnicodeDecodeError, ValueError):
                    raise BuildFailedError("invalid CPU template JSON") from None
                finally:
                    os.close(fd_cpu)
                api_client.put("/cpu-config", tmpl_data)

            # Start MicroVM
            api_client.put("/actions", {"action_type": "InstanceStart"})

            # Wait for execd on vsock
            execd = ExecdClient(vsock_sock)
            start_vsock = time.monotonic()
            while True:
                if fc_proc.poll() is not None:
                    raise BuildFailedError("Firecracker exited during VM boot")
                if vsock_sock.exists():
                    try:
                        status_rep = execd.call({"type": "status"}, timeout=1.0)
                        if status_rep.get("locked"):
                            execd.call({"type": "authorize"}, timeout=1.0)
                        break
                    except (BuildFailedError, OSError, TimeoutError):
                        pass
                if time.monotonic() - start_vsock > CONNECT_TIMEOUT_S:
                    raise BuildFailedError("execd vsock connection timed out")
                time.sleep(POLL_INTERVAL_S)

            # Upload source archive in chunks
            num_chunks = (len(source_tar) + MAX_TRANSFER_CHUNK_BYTES - 1) // MAX_TRANSFER_CHUNK_BYTES
            if num_chunks > MAX_TRANSFER_CHUNKS:
                raise ResourceLimitError("source archive exceeds chunk count limit")

            for i in range(num_chunks):
                chunk = source_tar[i * MAX_TRANSFER_CHUNK_BYTES : (i + 1) * MAX_TRANSFER_CHUNK_BYTES]
                execd.call(
                    {
                        "type": "upload",
                        "path": f"/tmp/source.tar.{i:04d}",
                        "data": list(chunk),
                    },
                    timeout=10.0,
                )

            # Unpack source archive in guest
            unpack_res = execd.call(
                {
                    "type": "exec",
                    "argv": [
                        "/bin/sh",
                        "-c",
                        "cat /tmp/source.tar.* > /tmp/source.tar && "
                        "rm -f /tmp/source.tar.* && "
                        "mkdir -p /work/source /work/output && "
                        "tar -xf /tmp/source.tar -C /work/source && "
                        "rm -f /tmp/source.tar",
                    ],
                    "tty": False,
                    "timeout_ms": 15000,
                },
                timeout=20.0,
            )
            if unpack_res.get("code") != 0 or unpack_res.get("timed_out"):
                raise BuildFailedError("failed to unpack source tree inside microVM")

            # Execute builder command in guest
            builder_name = request.entry.builder
            timeout_ms = int(self.config.build_timeout_s * 1000)

            if builder_name == "copy":
                guest_cmd = [
                    "/bin/sh",
                    "-c",
                    'mkdir -p /work/output/"$1" && cp -a /work/source/. /work/output/"$1"/',
                    "copy-builder",
                    request.artifact_name,
                ]
            elif builder_name == "python-wheel":
                guest_cmd = [
                    "/bin/sh",
                    "-c",
                    'python3 -m pip wheel --no-deps -w /work/output /work/source "$@"',
                    "wheel-builder",
                    *request.entry.args,
                ]
            elif builder_name == "python-sdist":
                guest_cmd = [
                    "/bin/sh",
                    "-c",
                    'python3 -m build --sdist --outdir /work/output /work/source "$@"',
                    "sdist-builder",
                    *request.entry.args,
                ]
            else:
                guest_cmd = [
                    "/bin/sh",
                    "-c",
                    'export SOURCE=/work/source OUTPUT=/work/output ARTIFACT_NAME="$1"; shift; exec "$@"',
                    "generic-builder",
                    request.artifact_name,
                    builder_name,
                    *request.entry.args,
                ]

            build_res = execd.call(
                {
                    "type": "exec",
                    "argv": guest_cmd,
                    "tty": False,
                    "timeout_ms": timeout_ms,
                },
                timeout=self.config.build_timeout_s + 5.0,
            )
            if build_res.get("timed_out") or build_res.get("code") != 0:
                raise BuildFailedError("build command failed inside microVM")

            # Check that output artifact exists and pack it into tar
            pack_res = execd.call(
                {
                    "type": "exec",
                    "argv": [
                        "/bin/sh",
                        "-c",
                        'test -e /work/output/"$1" && '
                        'tar -cf /tmp/out.tar -C /work/output "$1" && '
                        "split -b 1048576 -d /tmp/out.tar /tmp/out.part. && "
                        "ls -1 /tmp/out.part.*",
                        "pack-artifact",
                        request.artifact_name,
                    ],
                    "tty": False,
                    "timeout_ms": 30000,
                },
                timeout=35.0,
            )
            if pack_res.get("code") != 0 or pack_res.get("timed_out"):
                raise BuildFailedError("failed to pack build output in microVM")

            raw_part_list = bytes(pack_res.get("output", [])).decode("utf-8", "ignore").strip().splitlines()
            if not raw_part_list:
                raise BuildFailedError("builder produced no output parts")
            if len(raw_part_list) > MAX_OUTPUT_PARTS:
                raise ResourceLimitError("output part count exceeded limit")

            tar_parts = []
            total_dl = 0
            for part in raw_part_list:
                part_name = part.strip()
                if not part_name:
                    continue
                dl_res = execd.call({"type": "download", "path": part_name}, timeout=10.0)
                part_data = bytes(dl_res.get("data", []))
                total_dl += len(part_data)
                if total_dl > self.config.max_output_bytes:
                    raise ResourceLimitError("artifact output exceeded byte cap")
                tar_parts.append(part_data)

            # Freeze disk and shut down guest
            try:
                execd.call({"type": "shutdown"}, timeout=SHUTDOWN_TIMEOUT_S)
            except Exception:
                pass

            return b"".join(tar_parts)

        finally:
            if fc_proc.poll() is None:
                try:
                    fc_proc.terminate()
                    fc_proc.wait(timeout=2.0)
                except Exception:
                    try:
                        fc_proc.kill()
                        fc_proc.wait(timeout=2.0)
                    except Exception:
                        pass


class VmIsolatedBuilder:
    """Isolated builder running rebuild recipes in a throwaway microVM."""

    def __init__(
        self,
        config: VmBuilderConfig,
        runner: MicroVmRunner | None = None,
    ) -> None:
        self.config = config
        self.runner = runner if runner is not None else FirecrackerRunner(config)

    def build(self, request: BuildRequest) -> None:
        """Run the build recipe inside an isolated throwaway microVM."""
        if request.source_fd < 0:
            raise BuildFailedError("invalid source descriptor")

        work_dir = None
        try:
            work_dir = Path(tempfile.mkdtemp(prefix="d7-vm-"))
            os.chmod(work_dir, 0o700)

            # 1. Package source tree from held descriptor
            source_tar = build_source_tar(request.source_fd, self.config.t_clock)

            # 2. Execute build inside throwaway microVM
            artifact_tar_bytes = self.runner.run_build(request, source_tar, work_dir)

            # 3. Unpack artifact tar into request.output_dir
            unpack_artifact_tar(
                artifact_tar_bytes,
                request.output_dir,
                request.artifact_name,
                self.config.max_output_bytes,
            )

        except HermeticD7Error:
            raise
        except (TimeoutError, subprocess.TimeoutExpired):
            raise BuildFailedError("isolated builder timed out") from None
        except Exception as exc:
            raise BuildFailedError("isolated builder failed") from exc
        finally:
            if work_dir is not None and work_dir.exists():
                try:
                    shutil.rmtree(work_dir, ignore_errors=True)
                except Exception:
                    pass
