"""Comprehensive offline and hostile-input tests for the D7 VM-isolated rebuild builder."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import tarfile
import threading
import time

import pytest

from hermetic_d7.__main__ import main
from hermetic_d7.deep_audit import (
    BuildFailedError,
    BuildRequest,
    RecipeEntry,
    RefusingBuilder,
    parse_recipe,
    run_deep_audit,
    run_deep_audit_cli,
)
from hermetic_d7.normalise import (
    HermeticD7Error,
    InvalidArtifactError,
    ResourceLimitError,
    SecurityViolationError,
)
from hermetic_d7.vm_builder import (
    DEFAULT_BUILD_TIMEOUT_S,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MEMORY_MIB,
    DEFAULT_T_CLOCK,
    DEFAULT_VCPUS,
    ExecdClient,
    FirecrackerApiClient,
    MicroVmRunner,
    VmBuilderConfig,
    VmIsolatedBuilder,
    build_source_tar,
    unpack_artifact_tar,
)


def _make_dummy_file(path: Path, mode: int = 0o600, content: bytes = b"binary-data") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return path


def _dummy_config_files(tmp_path: Path) -> dict[str, Path]:
    base = tmp_path / "vm_env"
    base.mkdir(mode=0o700)
    fc = _make_dummy_file(base / "firecracker", mode=0o700, content=b"patched-fc-binary")
    kernel = _make_dummy_file(base / "vmlinux", mode=0o600, content=b"kernel-image")
    rootfs = _make_dummy_file(base / "rootfs.img", mode=0o600, content=b"rootfs-image")

    import hashlib
    fc_sha = hashlib.sha256(b"patched-fc-binary").hexdigest()
    lock = _make_dummy_file(
        base / "firecracker.lock.json",
        mode=0o600,
        content=json.dumps({"version": "1.18.0", "firecracker_sha256": fc_sha}).encode(),
    )
    return {"fc": fc, "kernel": kernel, "rootfs": rootfs, "lock": lock, "dir": base}


def _dummy_world(tmp_path: Path, entries: list[dict] | None = None) -> Path:
    root = tmp_path / "world"
    (root / "src" / "pkg").mkdir(parents=True, mode=0o700)
    (root / "src" / "pkg" / "mod.py").write_text("x = 1\n")
    (root / "dist" / "pkg").mkdir(parents=True, mode=0o700)
    (root / "dist" / "pkg" / "mod.py").write_text("x = 1\n")
    if entries is None:
        entries = [
            {"id": "pkg", "artifact": "dist/pkg", "source": "src/pkg", "builder": "copy", "args": []}
        ]
    (root / "d7-recipe.json").write_text(
        json.dumps({"schema": "hermetic.d7.recipe/1", "entries": entries})
    )
    return root


# 1. Config validation and known answers
def test_vm_builder_config_validation_and_known_answers(tmp_path: Path) -> None:
    files = _dummy_config_files(tmp_path)
    config = VmBuilderConfig(
        firecracker_bin=files["fc"],
        kernel_image=files["kernel"],
        rootfs_image=files["rootfs"],
        firecracker_lock=files["lock"],
        t_clock=1700000000,
        vcpus=2,
        memory_mib=512,
        build_timeout_s=60.0,
        max_output_bytes=8 * 1024 * 1024,
    )
    config.validate()
    assert config.vcpus == 2
    assert config.memory_mib == 512
    assert config.build_timeout_s == 60.0
    assert config.max_output_bytes == 8 * 1024 * 1024


@pytest.mark.parametrize(
    "bad_param",
    [
        {"t_clock": 100},
        {"t_clock": 5000000000},
        {"vcpus": 0},
        {"vcpus": 33},
        {"memory_mib": 32},
        {"memory_mib": 8192},
        {"build_timeout_s": 0.5},
        {"build_timeout_s": 1000.0},
        {"build_timeout_s": float("nan")},
        {"build_timeout_s": float("inf")},
        {"max_output_bytes": 500},
        {"max_output_bytes": 128 * 1024 * 1024},
    ],
)
def test_vm_builder_config_bounds_and_invalid_parameters(tmp_path: Path, bad_param: dict) -> None:
    files = _dummy_config_files(tmp_path)
    kwargs = {
        "firecracker_bin": files["fc"],
        "kernel_image": files["kernel"],
        "rootfs_image": files["rootfs"],
    }
    kwargs.update(bad_param)
    with pytest.raises(InvalidArtifactError):
        VmBuilderConfig(**kwargs).validate()


def test_vm_builder_config_security_violations(tmp_path: Path) -> None:
    files = _dummy_config_files(tmp_path)

    # Relative path rejected
    with pytest.raises(SecurityViolationError, match="absolute"):
        VmBuilderConfig(
            firecracker_bin=Path("relative/fc"),
            kernel_image=files["kernel"],
            rootfs_image=files["rootfs"],
        ).validate()

    # Non-existent file rejected
    with pytest.raises(SecurityViolationError):
        VmBuilderConfig(
            firecracker_bin=tmp_path / "nonexistent",
            kernel_image=files["kernel"],
            rootfs_image=files["rootfs"],
        ).validate()

    # Symlinked component rejected
    symlink_fc = files["dir"] / "symlink_fc"
    symlink_fc.symlink_to(files["fc"])
    with pytest.raises(SecurityViolationError):
        VmBuilderConfig(
            firecracker_bin=symlink_fc,
            kernel_image=files["kernel"],
            rootfs_image=files["rootfs"],
        ).validate()

    # Group/other-writable file rejected
    writable_kernel = _make_dummy_file(files["dir"] / "vmlinux_writable", mode=0o666)
    with pytest.raises(SecurityViolationError, match="writable"):
        VmBuilderConfig(
            firecracker_bin=files["fc"],
            kernel_image=writable_kernel,
            rootfs_image=files["rootfs"],
        ).validate()

    # Non-executable firecracker rejected
    non_exec_fc = _make_dummy_file(files["dir"] / "fc_nonexec", mode=0o600)
    with pytest.raises(SecurityViolationError, match="executable"):
        VmBuilderConfig(
            firecracker_bin=non_exec_fc,
            kernel_image=files["kernel"],
            rootfs_image=files["rootfs"],
        ).validate()


def test_vm_builder_config_lock_verification(tmp_path: Path) -> None:
    files = _dummy_config_files(tmp_path)

    # Lock mismatch raises SecurityViolationError
    bad_lock = _make_dummy_file(
        files["dir"] / "bad_lock.json",
        content=json.dumps({"firecracker_sha256": "0" * 64}).encode(),
    )
    with pytest.raises(SecurityViolationError, match="lock"):
        VmBuilderConfig(
            firecracker_bin=files["fc"],
            kernel_image=files["kernel"],
            rootfs_image=files["rootfs"],
            firecracker_lock=bad_lock,
        ).validate()

    # Corrupt lock JSON raises InvalidArtifactError
    corrupt_lock = _make_dummy_file(files["dir"] / "corrupt.json", content=b"{not json")
    with pytest.raises(InvalidArtifactError):
        VmBuilderConfig(
            firecracker_bin=files["fc"],
            kernel_image=files["kernel"],
            rootfs_image=files["rootfs"],
            firecracker_lock=corrupt_lock,
        ).validate()


def test_vm_builder_config_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Absent env returns None
    for k in ["HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_D7_ROOTFS", "HERMETIC_ROOTFS"]:
        monkeypatch.delenv(k, raising=False)
    assert VmBuilderConfig.from_env() is None

    # Present env returns valid config
    files = _dummy_config_files(tmp_path)
    monkeypatch.setenv("HERMETIC_FC_BIN", str(files["fc"]))
    monkeypatch.setenv("HERMETIC_KERNEL", str(files["kernel"]))
    monkeypatch.setenv("HERMETIC_ROOTFS", str(files["rootfs"]))
    monkeypatch.setenv("HERMETIC_FIRECRACKER_LOCK", str(files["lock"]))

    cfg = VmBuilderConfig.from_env()
    assert cfg is not None
    assert cfg.firecracker_bin == files["fc"].resolve()
    assert cfg.kernel_image == files["kernel"].resolve()


def test_vm_builder_config_from_json_file(tmp_path: Path) -> None:
    files = _dummy_config_files(tmp_path)
    data = {
        "firecracker_bin": str(files["fc"]),
        "kernel_image": str(files["kernel"]),
        "rootfs_image": str(files["rootfs"]),
        "firecracker_lock": str(files["lock"]),
        "vcpus": 1,
        "memory_mib": 256,
        "build_timeout_s": 90.0,
    }
    cfg_file = _make_dummy_file(files["dir"] / "config.json", content=json.dumps(data).encode())
    loaded = VmBuilderConfig.from_json_file(cfg_file)
    assert loaded.build_timeout_s == 90.0
    assert loaded.vcpus == 1


# 2. Source tar packaging and artifact unpacking tests
def test_build_source_tar_determinism_and_bounds(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir(mode=0o700)
    (src_dir / "b.txt").write_bytes(b"hello")
    (src_dir / "a.txt").write_bytes(b"world")
    sub = src_dir / "sub"
    sub.mkdir(mode=0o700)
    (sub / "c.txt").write_bytes(b"subfile")

    fd1 = os.open(src_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tar1 = build_source_tar(fd1, 1700000000)
    finally:
        os.close(fd1)

    fd2 = os.open(src_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tar2 = build_source_tar(fd2, 1700000000)
    finally:
        os.close(fd2)

    # Identical runs produce identical tar bytes
    assert tar1 == tar2
    assert len(tar1) > 0

    # Verify tar contents: parents first, sorted order
    with tarfile.open(fileobj=io.BytesIO(tar1), mode="r") as tf:
        names = [m.name for m in tf.getmembers()]
        assert names == ["a.txt", "b.txt", "sub", "sub/c.txt"]


def test_build_source_tar_symlink_escape_rejected(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir(mode=0o700)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    (src_dir / "bad_link").symlink_to("../outside.txt")

    fd = os.open(src_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(SecurityViolationError, match="escapes"):
            build_source_tar(fd, 1700000000)
    finally:
        os.close(fd)


def test_unpack_artifact_tar_safety(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir(mode=0o700)

    # Valid tar unpacking
    buf = io.BytesIO()
    with tarfile.open(mode="w", fileobj=buf) as tf:
        ti_dir = tarfile.TarInfo("pkg")
        ti_dir.type = tarfile.DIRTYPE
        ti_dir.mode = 0o700
        tf.addfile(ti_dir)

        ti_file = tarfile.TarInfo("pkg/mod.py")
        ti_file.type = tarfile.REGTYPE
        ti_file.size = 6
        ti_file.mode = 0o600
        tf.addfile(ti_file, io.BytesIO(b"x = 1\n"))

    tar_bytes = buf.getvalue()
    unpack_artifact_tar(tar_bytes, out_dir, "pkg", 1024 * 1024)
    assert (out_dir / "pkg" / "mod.py").read_text() == "x = 1\n"

    # Tar containing escaping path rejected
    buf_bad = io.BytesIO()
    with tarfile.open(mode="w", fileobj=buf_bad) as tf:
        ti = tarfile.TarInfo("pkg/../../escape.txt")
        ti.size = 4
        tf.addfile(ti, io.BytesIO(b"evil"))
    with pytest.raises(SecurityViolationError):
        unpack_artifact_tar(buf_bad.getvalue(), out_dir, "pkg", 1024 * 1024)

    # Tar containing symlink rejected
    buf_sym = io.BytesIO()
    with tarfile.open(mode="w", fileobj=buf_sym) as tf:
        ti = tarfile.TarInfo("pkg")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)
    with pytest.raises(SecurityViolationError):
        unpack_artifact_tar(buf_sym.getvalue(), out_dir, "pkg", 1024 * 1024)


# 3. MicroVmRunner mock tests and end-to-end VmIsolatedBuilder
class MockMicroVmRunner:
    def __init__(self, mode: str = "ok", alter_bytes: bytes | None = None) -> None:
        self.mode = mode
        self.alter_bytes = alter_bytes
        self.requests: list[BuildRequest] = []

    def run_build(
        self,
        request: BuildRequest,
        source_tar: bytes,
        work_dir: Path,
    ) -> bytes:
        self.requests.append(request)
        if self.mode == "timeout":
            raise TimeoutError("simulated microVM timeout")
        if self.mode == "fail_cmd":
            raise BuildFailedError("simulated build failure in guest")
        if self.mode == "oversized":
            return b"X" * (DEFAULT_MAX_OUTPUT_BYTES + 1024)
        if self.mode == "corrupt":
            return b"not a valid tar archive"
        if self.mode == "symlink":
            buf = io.BytesIO()
            with tarfile.open(mode="w", fileobj=buf) as tf:
                ti = tarfile.TarInfo(request.artifact_name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = "/etc/shadow"
                tf.addfile(ti)
            return buf.getvalue()

        # "ok" mode: unpack source_tar in memory, pack it under artifact_name
        buf = io.BytesIO()
        with tarfile.open(mode="w", fileobj=buf) as tf:
            ti_dir = tarfile.TarInfo(request.artifact_name)
            ti_dir.type = tarfile.DIRTYPE
            ti_dir.mode = 0o700
            tf.addfile(ti_dir)

            with tarfile.open(fileobj=io.BytesIO(source_tar), mode="r") as in_tf:
                for member in in_tf.getmembers():
                    if member.isfile():
                        content = in_tf.extractfile(member).read()
                        if self.alter_bytes is not None:
                            content = self.alter_bytes
                        ti = tarfile.TarInfo(f"{request.artifact_name}/{member.name}")
                        ti.size = len(content)
                        ti.mode = 0o600
                        tf.addfile(ti, io.BytesIO(content))
        return buf.getvalue()


def test_vm_isolated_builder_identical_rebuild_with_mock_runner(tmp_path: Path) -> None:
    files = _dummy_config_files(tmp_path)
    config = VmBuilderConfig(
        firecracker_bin=files["fc"],
        kernel_image=files["kernel"],
        rootfs_image=files["rootfs"],
    )
    runner = MockMicroVmRunner(mode="ok")
    builder = VmIsolatedBuilder(config, runner=runner)

    root = _dummy_world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json", builder=builder)
    assert report["verdict"] == "identical"
    assert len(runner.requests) == 1
    assert runner.requests[0].artifact_name == "pkg"
    # Verify no host paths in report JSON
    rep_str = json.dumps(report)
    assert str(tmp_path) not in rep_str
    assert "/tmp" not in rep_str


def test_vm_isolated_builder_differs_rebuild_with_mock_runner(tmp_path: Path) -> None:
    files = _dummy_config_files(tmp_path)
    config = VmBuilderConfig(
        firecracker_bin=files["fc"],
        kernel_image=files["kernel"],
        rootfs_image=files["rootfs"],
    )
    runner = MockMicroVmRunner(mode="ok", alter_bytes=b"x = 99\n")
    builder = VmIsolatedBuilder(config, runner=runner)

    root = _dummy_world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json", builder=builder)
    assert report["verdict"] == "differs"
    assert report["entries"][0]["content_differences"][0]["path"] == "mod.py"
    rep_str = json.dumps(report)
    assert str(tmp_path) not in rep_str


@pytest.mark.parametrize("mode", ["timeout", "fail_cmd", "oversized", "corrupt", "symlink"])
def test_vm_isolated_builder_hostile_outcomes_fail_closed(tmp_path: Path, mode: str) -> None:
    files = _dummy_config_files(tmp_path)
    config = VmBuilderConfig(
        firecracker_bin=files["fc"],
        kernel_image=files["kernel"],
        rootfs_image=files["rootfs"],
    )
    runner = MockMicroVmRunner(mode=mode)
    builder = VmIsolatedBuilder(config, runner=runner)

    root = _dummy_world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json", builder=builder)
    assert report["verdict"] == "error"
    err = report["entries"][0]["error"]
    assert err["type"] in {"BuildFailedError", "SecurityViolationError", "ResourceLimitError"}
    rep_str = json.dumps(report)
    assert str(tmp_path) not in rep_str
    assert "/tmp" not in rep_str


# 4. Replacement of default refusing builder only when configured
def test_replacing_refusing_builder_only_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for k in ["HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_D7_ROOTFS", "HERMETIC_ROOTFS"]:
        monkeypatch.delenv(k, raising=False)

    root = _dummy_world(tmp_path)

    # 1. Without configuration: default RefusingBuilder refuses host builds
    report_unconf = run_deep_audit(root, "d7-recipe.json")
    assert report_unconf["verdict"] == "error"
    assert report_unconf["entries"][0]["error"]["type"] == "BuildFailedError"
    assert "no isolated builder configured" in report_unconf["entries"][0]["error"]["message"]

    # 2. CLI without configuration: exits 1 and reports no builder
    ret = main(["--deep-audit", str(root), "d7-recipe.json"])
    assert ret == 1
    out = capsys.readouterr().out
    assert "no isolated builder configured" in out

    # 3. With CLI --vm-config pointing to valid config
    files = _dummy_config_files(tmp_path)
    cfg_data = {
        "firecracker_bin": str(files["fc"]),
        "kernel_image": str(files["kernel"]),
        "rootfs_image": str(files["rootfs"]),
    }
    cfg_path = _make_dummy_file(files["dir"] / "cfg.json", content=json.dumps(cfg_data).encode())

    # Mock runner inside VmIsolatedBuilder to avoid needing KVM during CLI test
    orig_init = VmIsolatedBuilder.__init__

    def mock_init(self, config, runner=None):
        orig_init(self, config, runner=MockMicroVmRunner(mode="ok"))

    monkeypatch.setattr(VmIsolatedBuilder, "__init__", mock_init)

    ret_cli = main(["--deep-audit", str(root), "d7-recipe.json", "--vm-config", str(cfg_path)])
    out_cli = capsys.readouterr().out
    assert ret_cli == 0
    assert '"verdict": "identical"' in out_cli


# 5. FirecrackerApiClient and ExecdClient protocol tests with mock sockets
def test_firecracker_api_client_protocol(tmp_path: Path) -> None:
    sock_path = tmp_path / "fc_api.sock"
    ready = threading.Event()

    def server_thread():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.bind(str(sock_path))
            s.listen(1)
            ready.set()
            try:
                conn, _ = s.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5.0)
                req = conn.recv(4096)
                assert b"PUT /boot-source HTTP/1.1" in req
                conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")

    th = threading.Thread(target=server_thread, daemon=True)
    th.start()
    assert ready.wait(timeout=5.0), "mock server failed to start"
    try:
        client = FirecrackerApiClient(sock_path, timeout=5.0)
        client.put("/boot-source", {"kernel": "vmlinux"})
    finally:
        th.join(timeout=5.0)


def test_execd_client_protocol(tmp_path: Path) -> None:
    sock_path = tmp_path / "execd.sock"
    ready = threading.Event()

    def server_thread():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.bind(str(sock_path))
            s.listen(1)
            ready.set()
            try:
                conn, _ = s.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5.0)
                hs = conn.recv(64)
                assert hs == b"CONNECT 5000\n"
                conn.sendall(b"OK 5000\n")

                len_bytes = bytearray()
                while len(len_bytes) < 4:
                    chunk = conn.recv(4 - len(len_bytes))
                    if not chunk:
                        break
                    len_bytes.extend(chunk)
                if len(len_bytes) == 4:
                    (flen,) = struct.unpack("<I", len_bytes)
                    body = conn.recv(flen)
                    req = json.loads(body.decode())
                    assert req.get("type") == "status"

                    rep = json.dumps({"type": "status", "locked": False, "guest_time_unix": 1700000000}).encode()
                    conn.sendall(struct.pack("<I", len(rep)) + rep)

    th = threading.Thread(target=server_thread, daemon=True)
    th.start()
    assert ready.wait(timeout=5.0), "mock server failed to start"
    try:
        client = ExecdClient(sock_path)
        resp = client.call({"type": "status"}, timeout=5.0)
        assert resp["guest_time_unix"] == 1700000000
    finally:
        th.join(timeout=5.0)


# 6. Real KVM integration test (skips cleanly when env vars or /dev/kvm unset)
def test_kvm_microvm_builder_rebuild(tmp_path: Path) -> None:
    fc = os.environ.get("HERMETIC_FC_BIN")
    kernel = os.environ.get("HERMETIC_KERNEL")
    rootfs = os.environ.get("HERMETIC_D7_ROOTFS") or os.environ.get("HERMETIC_ROOTFS")
    lock = os.environ.get("HERMETIC_FIRECRACKER_LOCK")

    if not (fc and kernel and rootfs and os.path.exists("/dev/kvm")):
        pytest.skip(
            "skipped: set HERMETIC_FC_BIN, HERMETIC_FIRECRACKER_LOCK, HERMETIC_KERNEL and HERMETIC_ROOTFS with /dev/kvm"
        )

    config = VmBuilderConfig(
        firecracker_bin=Path(os.path.realpath(fc)),
        kernel_image=Path(os.path.realpath(kernel)),
        rootfs_image=Path(os.path.realpath(rootfs)),
        firecracker_lock=Path(os.path.realpath(lock)) if lock else None,
        build_timeout_s=120.0,
    )
    builder = VmIsolatedBuilder(config)
    root = _dummy_world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json", builder=builder)
    assert report["verdict"] == "identical"
