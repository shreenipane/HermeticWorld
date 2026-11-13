"""Tests for reproducible ext4 rootfs builder with D4 guard (T2.4)."""

from __future__ import annotations

import atexit
from datetime import datetime, timezone
import errno
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid

import pytest

from hermetic_slice import rootfs
from hermetic_slice.__main__ import main
from hermetic_slice.rootfs import (
    ALLOWED_E2FSPROGS_VERSIONS,
    BLOCK_SIZE,
    EXT4_FEATURES,
    HERMETIC_NAMESPACE,
    INODE_SIZE,
    MIN_E2FSPROGS_VERSION,
    MKE2FS_CONFIG_PATH,
    PinnedExecutable,
    RootfsGateError,
    RootfsLimitError,
    RootfsLimits,
    RootfsTimeoutError,
    SourceChangedError,
    TreeScan,
    build_rootfs,
    calculate_inode_count,
    check_e2fsprogs_version,
    directory_blocks,
    find_sealcheck_bin,
    is_cleanup_target,
    make_tarinfo,
    parse_mke2fs_version,
    plan_image,
    resolve_mke2fs_bin,
    write_rootfs_tar,
)

SUBPROCESS_TIMEOUT_S = 60
T_EPOCH = int(datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp())


def _check_mke2fs_usable() -> tuple[bool, str]:
    try:
        bin_path = resolve_mke2fs_bin()
    except FileNotFoundError:
        return False, "mke2fs binary not found in PATH or standard locations"
    try:
        proc = subprocess.run(
            [bin_path, "-V"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=SUBPROCESS_TIMEOUT_S,
        )
        check_e2fsprogs_version(f"{proc.stdout}\n{proc.stderr}")
        return True, ""
    except Exception as exc:
        return False, f"mke2fs not usable (need a pinned e2fsprogs version): {exc}"


def _locate_test_sealcheck() -> tuple[Path | None, str]:
    """Test-only discovery of a hermetic-sealcheck build that supports d4-image.

    The builder itself never searches (review finding 5); the tests look in this worktree's
    cargo target dirs (and $HERMETIC_SEALCHECK_BIN), then in the owner's other cargo target
    dirs, and copy the binary into a private 0700 directory with mode 0755 so it passes the
    builder's owner/mode checks (cargo leaves binaries group-writable under umask 002).
    """
    candidates: list[Path] = []
    env_bin = os.environ.get("HERMETIC_SEALCHECK_BIN")
    if env_bin:
        candidates.append(Path(env_bin))
    repo_root = Path(__file__).resolve().parents[2]
    cargo_root = Path.home() / "hermetic" / "cargo-target"
    own = [repo_root / "target", cargo_root / repo_root.name]
    others: list[Path] = []
    if cargo_root.is_dir():
        others = [p for p in cargo_root.iterdir() if p.is_dir() and not p.is_symlink() and p not in own]
    found_own: list[Path] = []
    found_other: list[Path] = []
    for bucket, bases in ((found_own, own), (found_other, others)):
        for base in bases:
            for mode in ("debug", "release"):
                cand = base / mode / "hermetic-sealcheck"
                if cand.is_file() and not cand.is_symlink():
                    bucket.append(cand)
    found_other.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    candidates += found_own + found_other

    private = Path(tempfile.mkdtemp(prefix="hermetic-sealcheck-test-"))
    atexit.register(shutil.rmtree, private, True)
    for cand in candidates:
        try:
            proc = subprocess.run(
                [str(cand), "d4-image", "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            dest = private / "hermetic-sealcheck"
            shutil.copyfile(cand, dest)
            os.chmod(dest, 0o755)
            return dest, ""
    return None, "no hermetic-sealcheck build with d4-image found (run rust-gate or set HERMETIC_SEALCHECK_BIN)"


MKE2FS_AVAILABLE, MKE2FS_REASON = _check_mke2fs_usable()
SEALCHECK_BIN, SEALCHECK_REASON = _locate_test_sealcheck()
SEALCHECK_AVAILABLE = SEALCHECK_BIN is not None
DEBUGFS = shutil.which("debugfs") or next(
    (p for p in ("/sbin/debugfs", "/usr/sbin/debugfs") if os.path.isfile(p)), None
)

requires_mke2fs = pytest.mark.skipif(not MKE2FS_AVAILABLE, reason=MKE2FS_REASON)
requires_sealcheck = pytest.mark.skipif(not SEALCHECK_AVAILABLE, reason=SEALCHECK_REASON)
requires_debugfs = pytest.mark.skipif(DEBUGFS is None, reason="debugfs not found")


@pytest.fixture(autouse=True)
def _sealcheck_env(monkeypatch: pytest.MonkeyPatch) -> None:
    if SEALCHECK_BIN is not None:
        monkeypatch.setenv("HERMETIC_SEALCHECK_BIN", str(SEALCHECK_BIN))
    else:
        monkeypatch.delenv("HERMETIC_SEALCHECK_BIN", raising=False)


def hash_directory_tree(root: Path) -> str:
    """Compute deterministic SHA256 over all relative paths, modes and contents in a directory."""
    hasher = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for f in sorted(filenames):
            p = Path(dirpath) / f
            rel = p.relative_to(root).as_posix()
            hasher.update(rel.encode("utf-8"))
            if p.is_symlink():
                hasher.update(b"symlink:" + os.readlink(p).encode("utf-8"))
            elif p.is_file():
                hasher.update(p.read_bytes())
    return hasher.hexdigest()


def _norm(name: str) -> str:
    name = name.rstrip("/")
    if name in ("", "."):
        return "."
    return name[2:] if name.startswith("./") else name


def _tar_tree(src: Path, tmp_path: Path, **limit_kwargs) -> tuple[TreeScan, dict[str, tarfile.TarInfo], Path]:
    """Run the walker on src; return the scan, the tar members by normalised name and the tar path."""
    tar_path = tmp_path / f"stream-{uuid.uuid4().hex}.tar"
    scan = write_rootfs_tar(src, tar_path, mtime_ceiling=T_EPOCH, limits=RootfsLimits(**limit_kwargs))
    with tarfile.open(tar_path) as tf:
        members = {_norm(m.name): m for m in tf.getmembers()}
    return scan, members, tar_path


def _debugfs(image: Path, request: str) -> str:
    proc = subprocess.run(
        [DEBUGFS, "-R", request, str(image)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=SUBPROCESS_TIMEOUT_S,
        check=False,
    )
    return proc.stdout


def _fake_sealcheck() -> PinnedExecutable:
    """A pinned descriptor for tests that mock subprocess.run (the descriptor is never executed)."""
    return PinnedExecutable(Path("/bin/hermetic-sealcheck"), os.open("/bin/sh", os.O_RDONLY | os.O_CLOEXEC))


def _fake_tool(path: Path, body: str, mode: int = 0o755) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n")
    os.chmod(path, mode)
    return path


# -----------------------------------------------------------------------------
# Unit Tests (no subprocess needed)
# -----------------------------------------------------------------------------


def test_version_check_rejects_and_accepts() -> None:
    """Version check: below the minimum and outside the pinned allow-list are rejected."""
    assert (1, 47, 2) in ALLOWED_E2FSPROGS_VERSIONS
    v1 = check_e2fsprogs_version("mke2fs 1.47.2 (1-Jan-2025)\n\tUsing EXT2FS Library version 1.47.2")
    assert v1 == (1, 47, 2)

    with pytest.raises(RuntimeError) as excinfo:
        check_e2fsprogs_version("mke2fs 1.47.0 (5-Feb-2023)")
    assert "1.47.0" in str(excinfo.value)
    assert "1.47.1" in str(excinfo.value)

    # Review finding 2: newer than the minimum but not pinned -> refused
    for other in ("mke2fs 1.47.1 (20-May-2024)", "mke2fs 1.47.3 (1-Jan-2026)", "mke2fs 1.48.0 (1-Jan-2027)"):
        with pytest.raises(RuntimeError, match="not a pinned version"):
            check_e2fsprogs_version(other)

    with pytest.raises(ValueError):
        parse_mke2fs_version("invalid version string")


def test_plan_image_explicit_and_minimum() -> None:
    """Explicit size_mib is used as is; an empty tree gets the 64 MiB floor; size_mib <= 0 is refused."""
    empty = TreeScan(removed=[], skipped_special=[])
    assert plan_image(empty).size_mib == 64
    assert plan_image(empty, 128).size_mib == 128
    assert plan_image(empty, 128).journal_mib == 4
    with pytest.raises(ValueError):
        plan_image(empty, 0)


def test_special_files_skipped(tmp_path: Path) -> None:
    """Special files (FIFOs) are skipped and listed in skipped_special; the walk never opens them."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "file.txt").write_text("hello")
    sub = src / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("world")
    os.mkfifo(src / "dev_fifo")
    os.mkfifo(sub / "nested_fifo")

    scan, members, _ = _tar_tree(src, tmp_path)

    assert scan.skipped_special == ["dev_fifo", "sub/nested_fifo"]
    assert "dev_fifo" not in members
    assert "sub/nested_fifo" not in members
    assert members["file.txt"].isfile()
    assert members["sub/nested.txt"].isfile()


def test_cleanup_targets_and_src_untouched(tmp_path: Path) -> None:
    """Clean-up removes exactly the listed caches and histories, keeps var/log and var/cache, preserves src."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "var" / "log" / "nginx").mkdir(parents=True)
    (src / "var" / "log" / "syslog").write_text("logs")
    (src / "var" / "log" / "nginx" / "access.log").write_text("access")
    (src / "var" / "cache" / "apt").mkdir(parents=True)
    (src / "var" / "cache" / "apt" / "pkg.deb").write_bytes(b"deb")
    (src / "var" / "lib" / "apt" / "lists").mkdir(parents=True)
    (src / "var" / "lib" / "apt" / "lists" / "deb.debian.org_Packages").write_text("packages")
    (src / "root" / ".cache" / "pip" / "wheels").mkdir(parents=True)
    (src / "root" / ".cache" / "pip" / "wheels" / "pkg.whl").write_bytes(b"whl")
    (src / "root" / ".cache" / "uv").mkdir(parents=True)
    (src / "root" / ".cache" / "uv" / "cache.db").write_text("uvcache")
    (src / "home" / "user1" / ".cache" / "pip").mkdir(parents=True)
    (src / "home" / "user1" / ".cache" / "pip" / "p.whl").write_bytes(b"whl")
    (src / "home" / "user1" / ".cache" / "uv").mkdir(parents=True)
    (src / "home" / "user1" / ".cache" / "uv" / "u.db").write_text("uv")
    (src / "opt" / "conda" / "pkgs").mkdir(parents=True)
    (src / "opt" / "conda" / "pkgs" / "pkg1.tar.bz2").write_bytes(b"pkg1")
    (src / "opt" / "conda" / "pkgs" / "urls.txt").write_text("https://conda.anaconda.org/main\n")
    (src / "home" / "user1" / "miniconda3" / "pkgs").mkdir(parents=True)
    (src / "home" / "user1" / "miniconda3" / "pkgs" / "pkg2.tar.bz2").write_bytes(b"pkg2")
    (src / "home" / "user1" / "miniconda3" / "pkgs" / "urls.txt").write_text("https://conda.anaconda.org/r\n")
    (src / "root" / ".bash_history").write_text("ls\n")
    (src / "home" / "user1" / ".bash_history").write_text("cd\n")
    (src / "home" / "user1" / ".zsh_history").write_text(": 1234:0;echo hi\n")
    (src / "home" / "user1" / ".python_history").write_text("import os\n")
    (src / "home" / "user1" / ".lesshst").write_text(".search\n")
    (src / "root" / ".viminfo").write_text("'0  1  0\n")
    (src / "etc").mkdir()
    (src / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    (src / "home" / "user1" / "project").mkdir()
    (src / "home" / "user1" / "project" / "main.py").write_text("print('hello')\n")

    src_hash_before = hash_directory_tree(src)
    scan, members, _ = _tar_tree(src, tmp_path)
    assert hash_directory_tree(src) == src_hash_before, "Clean-up modified src directory!"

    for kept_dir in ("var/log", "var/cache", "var/lib/apt/lists", "opt/conda/pkgs"):
        assert members[kept_dir].isdir()
    for kept_file in (
        "opt/conda/pkgs/urls.txt",
        "home/user1/miniconda3/pkgs/urls.txt",
        "etc/passwd",
        "home/user1/project/main.py",
    ):
        assert members[kept_file].isfile()

    expected_removed = sorted([
        "var/log/syslog",
        "var/log/nginx",
        "var/cache/apt",
        "var/lib/apt/lists/deb.debian.org_Packages",
        "root/.cache/pip",
        "root/.cache/uv",
        "home/user1/.cache/pip",
        "home/user1/.cache/uv",
        "opt/conda/pkgs/pkg1.tar.bz2",
        "home/user1/miniconda3/pkgs/pkg2.tar.bz2",
        "root/.bash_history",
        "home/user1/.bash_history",
        "home/user1/.zsh_history",
        "home/user1/.python_history",
        "home/user1/.lesshst",
        "root/.viminfo",
    ])
    assert scan.removed == expected_removed
    for gone in expected_removed:
        assert gone not in members
        assert not any(name.startswith(gone + "/") for name in members)


def test_cleanup_rule_table() -> None:
    """The TR-SEAL-8 predicate on relative paths."""
    assert is_cleanup_target(("var", "log", "x"))
    assert not is_cleanup_target(("var", "log"))
    assert is_cleanup_target(("miniconda3", "pkgs", "a"))
    assert not is_cleanup_target(("miniconda3", "pkgs", "urls.txt"))
    assert is_cleanup_target(("home", "u", "deep", ".viminfo"))
    assert not is_cleanup_target(("etc", ".bash_history"))
    assert not is_cleanup_target((".bash_history",))


def test_naive_t_clock_rejected(tmp_path: Path) -> None:
    """Naive t_clock without timezone is rejected."""
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out.img"
    with pytest.raises(ValueError, match="timezone-aware"):
        build_rootfs(
            src=src,
            out_image=out,
            t_clock=datetime(2024, 1, 1, 0, 0, 0),  # naive!
            world_id="test",
        )


def test_guard_failure_exit_2_and_exit_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Monkeypatch sealcheck call: exit 2 deletes image and raises RootfsGateError; exit 1 raises error."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "file.txt").write_text("hello")
    out = tmp_path / "out.img"
    t_clock = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Mock mke2fs version check to pass
    monkeypatch.setattr(
        "hermetic_slice.rootfs.resolve_mke2fs_bin",
        lambda: "/bin/mke2fs",
    )
    # Mock find_sealcheck_bin
    monkeypatch.setattr(
        "hermetic_slice.rootfs.find_sealcheck_bin",
        lambda _bin=None: _fake_sealcheck(),
    )

    findings = [
        {
            "rule": "D4",
            "severity": "gate",
            "message": "Timestamp 2025-01-01T00:00:00Z is after T_clock",
        }
    ]

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "-V" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="mke2fs 1.47.2 (1-Jan-2025)\n", stderr="")
        if "-t" in cmd and "ext4" in cmd:
            # Create dummy output file
            out_idx = cmd.index("-F") + 1
            out_path = Path(cmd[out_idx])
            out_path.write_bytes(b"dummy ext4 data" * 1024)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "d4-image" in cmd:
            if monkeypatch_exit == 2:
                return subprocess.CompletedProcess(
                    cmd, 2, stdout=json.dumps({"schema": "hermetic-sealcheck/v0", "findings": findings}), stderr=""
                )
            elif monkeypatch_exit == 1:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Fatal error scanning ext4 image\n")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    # Test Exit 2 (Gate failure)
    monkeypatch_exit = 2
    with pytest.raises(RootfsGateError) as excinfo:
        build_rootfs(src=src, out_image=out, t_clock=t_clock, world_id="test-gate")

    assert not out.exists(), "Image file was not deleted upon gate failure!"
    assert len(excinfo.value.findings) == 1
    assert excinfo.value.findings[0]["rule"] == "D4"

    # Test Exit 1 (Fatal execution error)
    monkeypatch_exit = 1
    with pytest.raises(RuntimeError) as excinfo_err:
        build_rootfs(src=src, out_image=out, t_clock=t_clock, world_id="test-err")

    assert not out.exists(), "Image file was not deleted upon sealcheck error!"
    assert "Fatal error scanning ext4 image" in str(excinfo_err.value)


def test_cli_help_and_missing_src() -> None:
    """CLI: build-rootfs --help returns 0, missing --src returns error (non-zero)."""
    assert main(["build-rootfs", "--help"]) == 0
    assert main(["build-rootfs", "--out", "/tmp/out.img"]) != 0


# -----------------------------------------------------------------------------
# End-to-End Integration Tests (requires mke2fs >= 1.47.1 and sealcheck binary)
# -----------------------------------------------------------------------------


@requires_mke2fs
@requires_sealcheck
def test_synthetic_tree_mtimes_clamped_passes_d4(tmp_path: Path) -> None:
    """A synthetic tree whose files have mtimes after T_clock builds an image passing D4."""
    src = tmp_path / "src"
    src.mkdir()
    f1 = src / "file1.txt"
    f1.write_text("content 1")
    f2 = src / "file2.txt"
    f2.write_text("content 2")

    t_clock = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    t_clock_epoch = int(t_clock.timestamp())

    # Set mtime to 1 year in the future (after T_clock)
    future_epoch = t_clock_epoch + 365 * 86400
    os.utime(f1, (future_epoch, future_epoch))
    os.utime(f2, (future_epoch, future_epoch))

    out_image = tmp_path / "rootfs.ext4"
    res = build_rootfs(
        src=src,
        out_image=out_image,
        t_clock=t_clock,
        world_id="world-clamping-test",
        size_mib=64,
    )

    assert res["d4"] == "pass"
    assert out_image.exists()
    assert len(res["sha256"]) == 64
    assert res["size_bytes"] == out_image.stat().st_size
    assert res["t_clock"] == "2024-01-01T12:00:00Z"
    assert res["source_date_epoch"] == t_clock_epoch
    assert res["skipped_special"] == []


def test_regression_mke2fs_runs_under_utf8_locale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """mke2fs must get a UTF-8 locale; under LANG=C libarchive rejects non-ASCII PAX names."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    calls, _ = _mock_toolchain(monkeypatch)
    build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                 world_id="w", work_dir=tmp_path)
    _, build_kwargs = next((c, k) for c, k in calls if "-d" in c)
    assert build_kwargs["env"]["LANG"] == "C.UTF-8"


@requires_mke2fs
@requires_sealcheck
def test_regression_non_ascii_names_and_link_targets_build(tmp_path: Path) -> None:
    """A tree with a non-ASCII file name and symlink target (as in Alpine's CA store) builds."""
    src = tmp_path / "src"
    (src / "certs").mkdir(parents=True)
    (src / "certs" / "Főtanúsítvány.crt").write_text("cert\n")
    os.symlink("../certs/Főtanúsítvány.crt", src / "certs" / "link-to-cert.pem")
    os.symlink("Főtanúsítvány.crt", src / "certs" / "ca-cert-Főtanúsítvány.pem")
    res = build_rootfs(src=src, out_image=tmp_path / "out" / "r.ext4",
                       t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc), world_id="w-utf8", size_mib=64)
    assert res["d4"] == "pass"


@requires_mke2fs
@requires_sealcheck
def test_reproducibility_tr_seal_12(tmp_path: Path) -> None:
    """Building the same tree twice gives byte-identical images (TR-SEAL-12)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("file A")
    (src / "b.txt").write_text("file B")
    sub = src / "sub"
    sub.mkdir()
    (sub / "c.txt").write_text("file C")

    t_clock = datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    world_id = "repro-world-42"

    out1 = tmp_path / "run1" / "rootfs.ext4"
    out2 = tmp_path / "run2" / "rootfs.ext4"

    res1 = build_rootfs(src=src, out_image=out1, t_clock=t_clock, world_id=world_id, size_mib=64)

    # Slight pause to ensure wall-clock moments differ
    time.sleep(0.05)

    res2 = build_rootfs(src=src, out_image=out2, t_clock=t_clock, world_id=world_id, size_mib=64)

    assert res1["sha256"] == res2["sha256"]
    assert res1["uuid"] == res2["uuid"]
    assert res1["hash_seed"] == res2["hash_seed"]
    assert out1.read_bytes() == out2.read_bytes()


@requires_mke2fs
@requires_sealcheck
def test_different_world_id_gives_different_uuid_and_image(tmp_path: Path) -> None:
    """A different world_id gives a different uuid and a different image."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "common.txt").write_text("common content")

    t_clock = datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    out1 = tmp_path / "world1.ext4"
    out2 = tmp_path / "world2.ext4"

    res1 = build_rootfs(src=src, out_image=out1, t_clock=t_clock, world_id="world-alpha", size_mib=64)
    res2 = build_rootfs(src=src, out_image=out2, t_clock=t_clock, world_id="world-beta", size_mib=64)

    assert res1["uuid"] != res2["uuid"]
    assert res1["hash_seed"] != res2["hash_seed"]
    assert res1["sha256"] != res2["sha256"]


@requires_mke2fs
@requires_sealcheck
def test_cli_full_execution(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Full CLI invocation outputs valid JSON matching build_rootfs result."""
    src = tmp_path / "cli_src"
    src.mkdir()
    (src / "test.txt").write_text("cli test")

    out_image = tmp_path / "cli_out.ext4"
    rc = main([
        "build-rootfs",
        "--src", str(src),
        "--out", str(out_image),
        "--t-clock", "2024-05-01T00:00:00Z",
        "--world-id", "cli-world",
        "--size-mib", "64",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["d4"] == "pass"
    assert data["image"] == str(out_image)
    assert out_image.exists()


@requires_mke2fs
@requires_sealcheck
def test_measured_build_time_20mib(tmp_path: Path) -> None:
    """Measure build time for a 20 MiB synthetic tree."""
    src = tmp_path / "src_20mib"
    src.mkdir()

    # Create 20 files of 1 MiB each
    chunk = b"A" * (1024 * 1024)
    for i in range(20):
        (src / f"file_{i:02d}.bin").write_bytes(chunk)

    out_image = tmp_path / "rootfs_20mib.ext4"
    t_clock = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

    t0 = time.perf_counter()
    res = build_rootfs(
        src=src,
        out_image=out_image,
        t_clock=t_clock,
        world_id="bench-20mib",
    )
    t1 = time.perf_counter()
    elapsed = t1 - t0

    assert res["d4"] == "pass"
    assert out_image.exists()
    print(f"\n[MEASURED_BUILD_TIME_20MIB] Elapsed: {elapsed:.3f} s, image sha256: {res['sha256']}, size_bytes: {res['size_bytes']}")




# -----------------------------------------------------------------------------
# Symlinks and read-only directories in the source (earlier review rounds)
# -----------------------------------------------------------------------------


def test_fix1_symlinks_in_cleanup_a_var_log_absolute_host_dir(tmp_path: Path) -> None:
    """var/log -> an absolute host directory: it is shipped as a symlink, never entered or cleaned."""
    host_dir = tmp_path / "host_log"
    host_dir.mkdir()
    host_file = host_dir / "syslog.host"
    host_file.write_text("critical host log content")

    src = tmp_path / "src_a"
    (src / "var").mkdir(parents=True)
    (src / "var" / "log").symlink_to(host_dir.resolve())

    scan, members, tar_path = _tar_tree(src, tmp_path)

    assert host_file.read_text() == "critical host log content"
    assert members["var/log"].issym()
    assert members["var/log"].linkname == str(host_dir.resolve())
    assert "var/log/syslog.host" not in scan.removed
    assert b"critical host log content" not in tar_path.read_bytes()


def test_fix1_symlinks_in_cleanup_b_home_u_host_dir_with_history(tmp_path: Path) -> None:
    """home/u -> a host dir containing .bash_history: nothing behind the link is read or removed."""
    host_dir = tmp_path / "host_user"
    host_dir.mkdir()
    host_hist = host_dir / ".bash_history"
    host_hist.write_text("secret host history")

    src = tmp_path / "src_b"
    (src / "home").mkdir(parents=True)
    (src / "home" / "u").symlink_to(host_dir.resolve())

    scan, members, tar_path = _tar_tree(src, tmp_path)

    assert host_hist.read_text() == "secret host history"
    assert members["home/u"].issym()
    assert "home/u/.bash_history" not in scan.removed
    assert b"secret host history" not in tar_path.read_bytes()


def test_fix1_symlinks_in_cleanup_c_var_points_outside(tmp_path: Path) -> None:
    """var -> ../outside: nothing outside src is read or touched."""
    outside_dir = tmp_path / "outside"
    (outside_dir / "log").mkdir(parents=True)
    (outside_dir / "untouchable.txt").write_text("outside data")
    (outside_dir / "log" / "app.log").write_text("outside log")

    src = tmp_path / "src_c"
    src.mkdir()
    (src / "var").symlink_to(Path("..") / "outside")

    scan, members, tar_path = _tar_tree(src, tmp_path)

    assert (outside_dir / "untouchable.txt").read_text() == "outside data"
    assert (outside_dir / "log" / "app.log").read_text() == "outside log"
    assert not any(r.startswith("var/") for r in scan.removed)
    assert members["var"].issym()
    assert b"outside data" not in tar_path.read_bytes()


def test_fix1_symlinks_in_cleanup_d_history_symlink_to_host_file(tmp_path: Path) -> None:
    """A .bash_history that is a symlink to a host file: the link is dropped, the host file stays."""
    host_file = tmp_path / "host_bash_history"
    host_file.write_text("precious history")

    src = tmp_path / "src_d"
    (src / "home" / "user").mkdir(parents=True)
    (src / "home" / "user" / ".bash_history").symlink_to(host_file.resolve())

    scan, members, _ = _tar_tree(src, tmp_path)

    assert host_file.read_text() == "precious history"
    assert "home/user/.bash_history" in scan.removed
    assert "home/user/.bash_history" not in members
    assert (src / "home" / "user" / ".bash_history").is_symlink(), "src must never be modified"


def test_readonly_source_dir_history_dropped_src_untouched(tmp_path: Path) -> None:
    """A history file in a read-only source directory is dropped without making anything writable."""
    if os.geteuid() == 0:
        pytest.skip("Read-only directory test requires non-root user")

    src = tmp_path / "src_ro"
    user_dir = src / "home" / "user"
    user_dir.mkdir(parents=True)
    (user_dir / ".bash_history").write_text("history")
    os.chmod(user_dir, 0o555)
    try:
        scan, members, _ = _tar_tree(src, tmp_path)
        assert "home/user/.bash_history" in scan.removed
        assert "home/user/.bash_history" not in members
        assert stat.S_IMODE(members["home/user"].mode) == 0o555, "the image keeps the source mode"
        assert (user_dir.stat().st_mode & stat.S_IWUSR) == 0
        assert (user_dir / ".bash_history").exists()
    finally:
        os.chmod(user_dir, 0o755)


def test_readonly_source_dir_with_symlinked_history_leaves_host_mode_unchanged(tmp_path: Path) -> None:
    """A read-only source directory holding a symlinked history leaves the host target's mode unchanged."""
    if os.geteuid() == 0:
        pytest.skip("Read-only directory test requires non-root user")

    host_file = tmp_path / "host_bash_history"
    host_file.write_text("precious history")
    os.chmod(host_file, 0o644)

    src = tmp_path / "src_ro_symlink"
    user_dir = src / "home" / "user"
    user_dir.mkdir(parents=True)
    (user_dir / ".bash_history").symlink_to(host_file.resolve())
    os.chmod(user_dir, 0o555)
    try:
        scan, _, _ = _tar_tree(src, tmp_path)
        assert "home/user/.bash_history" in scan.removed
        assert stat.S_IMODE(os.lstat(host_file).st_mode) == 0o644
        assert host_file.read_text() == "precious history"
    finally:
        os.chmod(user_dir, 0o755)


def test_cleanup_nested_pkgs_cache_directories(tmp_path: Path) -> None:
    """Cache directories nested beneath other clean-up targets are dropped once, urls.txt kept."""
    src = tmp_path / "src_nested_pkgs"
    outer_pkgs = src / "miniconda3" / "pkgs"
    inner_pkgs = outer_pkgs / "nested_pkg" / "miniconda3" / "pkgs"
    inner_pkgs.mkdir(parents=True)
    (outer_pkgs / "outer.tar.bz2").write_text("outer package")
    (inner_pkgs / "inner.tar.bz2").write_text("inner package")
    opt_pkgs = src / "opt" / "conda" / "pkgs"
    opt_inner = opt_pkgs / "nested_pkg" / "miniconda3" / "pkgs"
    opt_inner.mkdir(parents=True)
    (opt_pkgs / "opt_pkg.tar.bz2").write_text("opt package")
    (opt_inner / "nested_opt.tar.bz2").write_text("nested opt package")
    (outer_pkgs / "urls.txt").write_text("https://example.com/repo\n")

    scan, members, _ = _tar_tree(src, tmp_path)

    assert "miniconda3/pkgs/outer.tar.bz2" in scan.removed
    assert "miniconda3/pkgs/nested_pkg" in scan.removed
    assert "opt/conda/pkgs/opt_pkg.tar.bz2" in scan.removed
    assert "opt/conda/pkgs/nested_pkg" in scan.removed
    assert members["miniconda3/pkgs/urls.txt"].isfile()
    assert not any("nested_pkg" in name for name in members)


def test_plan_image_inode_overhead_for_many_entries() -> None:
    """300,000 empty files: the inode tables (~92 MiB) are covered on top of the floor."""
    scan = TreeScan(removed=[], skipped_special=[], inodes=300_001, dir_blocks=directory_blocks(300_000 * 8, 300_000))
    plan = plan_image(scan)
    inode_table_mib = calculate_inode_count(300_001) * INODE_SIZE / (1024 * 1024)
    assert plan.inode_count == calculate_inode_count(300_001)
    assert plan.size_mib >= math.ceil(inode_table_mib) + plan.journal_mib + 16


def test_fix3_existing_out_image_survives_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FIX 3: An existing good out_image survives a gate failure (exit 2), a gate error (exit 1),
    and a missing sealcheck binary."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.txt").write_text("app data")

    out_image = tmp_path / "existing.img"
    original_data = b"PRE-EXISTING-GOOD-IMAGE-DATA\x00\x01\x02\x03"
    out_image.write_bytes(original_data)

    t_clock = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Missing sealcheck binary fails BEFORE building and leaves existing image untouched
    monkeypatch.setattr(
        "hermetic_slice.rootfs.resolve_mke2fs_bin",
        lambda: "/bin/mke2fs",
    )
    monkeypatch.setattr(
        "hermetic_slice.rootfs.find_sealcheck_bin",
        lambda _bin=None: (_ for _ in ()).throw(FileNotFoundError("no hermetic-sealcheck")),
    )
    with pytest.raises(FileNotFoundError, match="no hermetic-sealcheck"):
        build_rootfs(src=src, out_image=out_image, t_clock=t_clock, world_id="test-world")

    assert out_image.exists()
    assert out_image.read_bytes() == original_data

    # Setup mock subprocess for exit 2 and exit 1
    monkeypatch.setattr(
        "hermetic_slice.rootfs.find_sealcheck_bin",
        lambda _bin=None: _fake_sealcheck(),
    )

    sc_exit = 2

    def mock_subprocess_run(cmd, *args, **kwargs):
        if "-V" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="mke2fs 1.47.2\n", stderr="")
        if "-t" in cmd and "ext4" in cmd:
            out_idx = cmd.index("-F") + 1
            Path(cmd[out_idx]).write_bytes(b"temporary ext4 data")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "d4-image" in cmd:
            if sc_exit == 2:
                findings = [{"rule": "D4", "severity": "gate", "message": "bad timestamp"}]
                return subprocess.CompletedProcess(
                    cmd, 2, stdout=json.dumps({"findings": findings}), stderr=""
                )
            elif sc_exit == 1:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Corrupted ext4")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    # 2. Gate failure (exit 2) leaves existing out_image untouched
    sc_exit = 2
    with pytest.raises(RootfsGateError):
        build_rootfs(src=src, out_image=out_image, t_clock=t_clock, world_id="test-world")

    assert out_image.exists()
    assert out_image.read_bytes() == original_data

    # 3. Gate error (exit 1) leaves existing out_image untouched
    sc_exit = 1
    with pytest.raises(RuntimeError, match="sealcheck d4-image failed"):
        build_rootfs(src=src, out_image=out_image, t_clock=t_clock, world_id="test-world")

    assert out_image.exists()
    assert out_image.read_bytes() == original_data


@requires_mke2fs
@requires_sealcheck
def test_fix4_concurrent_builds_to_same_out_image(tmp_path: Path) -> None:
    """FIX 4: Two builds to the same out_image run in threads both succeed,
    the result is one valid image, and no .tmp files remain."""
    import concurrent.futures

    src = tmp_path / "src"
    src.mkdir()
    (src / "hello.txt").write_text("concurrent content")

    out_image = tmp_path / "concurrent.ext4"
    t_clock = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def run_worker(wid: str):
        return build_rootfs(
            src=src,
            out_image=out_image,
            t_clock=t_clock,
            world_id=wid,
            size_mib=64,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(run_worker, "w1")
        f2 = pool.submit(run_worker, "w2")
        r1 = f1.result()
        r2 = f2.result()

    assert r1["d4"] == "pass"
    assert r2["d4"] == "pass"
    assert out_image.exists()
    assert out_image.stat().st_size > 0
    # No .tmp files remain
    tmp_files = list(out_image.parent.glob("*.tmp"))
    assert tmp_files == [], f"Found leftover .tmp files: {tmp_files}"


def test_fix5_out_inside_src_exits_with_error_and_creates_nothing(tmp_path: Path) -> None:
    """FIX 5: --out inside --src exits with error and creates nothing."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "data.txt").write_text("important")

    nested_out = src / "nested" / "out.img"
    rc = main([
        "build-rootfs",
        "--src", str(src),
        "--out", str(nested_out),
        "--t-clock", "2024-01-01T00:00:00Z",
        "--world-id", "test-inside",
    ])
    assert rc != 0
    # Creates nothing!
    assert not (src / "nested").exists()
    assert not nested_out.exists()
    assert list(src.iterdir()) == [src / "data.txt"]

    # Direct build_rootfs call also raises ValueError
    with pytest.raises(ValueError, match="cannot be inside source directory"):
        build_rootfs(
            src=src,
            out_image=src / "out.img",
            t_clock=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            world_id="test-inside",
        )


@requires_mke2fs
@requires_sealcheck
def test_fix6_many_empty_files_automatic_sizing(tmp_path: Path) -> None:
    """FIX 6: A tree of 20,000 empty files builds successfully with automatic sizing."""
    src = tmp_path / "src_20000"
    src.mkdir()
    # Create 20,000 empty files
    for i in range(20000):
        (src / f"f_{i:05d}").touch()

    out_image = tmp_path / "rootfs_20000.ext4"
    t_clock = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    t0 = time.perf_counter()
    res = build_rootfs(
        src=src,
        out_image=out_image,
        t_clock=t_clock,
        world_id="world-20000",
        size_mib=None,  # automatic sizing!
    )
    t1 = time.perf_counter()
    elapsed = t1 - t0

    assert res["d4"] == "pass"
    assert out_image.exists()
    assert out_image.stat().st_size > 0
    print(f"\n[20000_FILES_BUILD_TIME] Elapsed: {elapsed:.3f} s")


@requires_mke2fs
@requires_sealcheck
def test_build_rootfs_metadata_computed_from_tmp_image_under_concurrent_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test (Finding 4): result metadata is computed from tmp_image before os.replace,
    so concurrent image replacement after publication does not corrupt returned sha256/size."""
    src1 = tmp_path / "src1"
    src1.mkdir()
    (src1 / "file1.txt").write_text("build 1 data")

    src2 = tmp_path / "src2"
    src2.mkdir()
    (src2 / "file2.txt").write_text("build 2 data with different content and size")

    out_image = tmp_path / "out.img"
    t_clock = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Build image 2 first as an independent file to get its content
    img2_standalone = tmp_path / "standalone2.img"
    res2 = build_rootfs(
        src=src2,
        out_image=img2_standalone,
        t_clock=t_clock,
        world_id="world-2",
        size_mib=64,
    )
    img2_bytes = img2_standalone.read_bytes()

    real_replace = os.replace

    def replace_interleaving(src_path, dst_path, **kwargs):
        # Perform the real (descriptor-relative) replace of the work image -> out_image
        real_replace(src_path, dst_path, **kwargs)
        # Simulate another build immediately overwriting out_image with img2
        if Path(dst_path).name == out_image.name:
            with open(out_image, "wb") as f:
                f.write(img2_bytes)

    monkeypatch.setattr(os, "replace", replace_interleaving)

    res1 = build_rootfs(
        src=src1,
        out_image=out_image,
        t_clock=t_clock,
        world_id="world-1",
        size_mib=64,
    )

    # res1 must report build 1's sha256 and size, NOT build 2's sha256 or size
    assert res1["sha256"] != res2["sha256"]
    assert res1["size_bytes"] == 64 * 1024 * 1024
    assert out_image.read_bytes() == img2_bytes


def test_build_rootfs_rejects_out_image_symlink_inside_src(tmp_path: Path) -> None:
    """Regression test (Finding 5): out_image inside src is rejected even if out_image is a symlink
    pointing outside src."""
    src = tmp_path / "src_symlink_parent"
    src.mkdir()
    (src / "data.txt").write_text("original data")
    nested_dir = src / "nested"
    nested_dir.mkdir()

    outside_target = tmp_path / "outside_target.img"
    symlink_out = nested_dir / "out.img"
    symlink_out.symlink_to(outside_target)

    t_clock = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="Output image and staging directory cannot be inside source directory"):
        build_rootfs(
            src=src,
            out_image=symlink_out,
            t_clock=t_clock,
            world_id="world-symlink-check",
            size_mib=64,
        )

    # Verify no staging directory or files were created inside src/nested
    assert list(nested_dir.iterdir()) == [symlink_out]
    assert not outside_target.exists()


# -----------------------------------------------------------------------------
# Regression tests for the final review (t2.4-claude-final-20261112), one block per finding
# -----------------------------------------------------------------------------


def _mock_toolchain(monkeypatch: pytest.MonkeyPatch, version: str = "mke2fs 1.47.2 (1-Jan-2025)\n"):
    """Mock mke2fs and sealcheck; record every subprocess.run call (cmd, kwargs)."""
    calls: list[tuple[list[str], dict]] = []
    monkeypatch.setattr("hermetic_slice.rootfs.resolve_mke2fs_bin", lambda: "/bin/mke2fs")
    monkeypatch.setattr("hermetic_slice.rootfs.find_sealcheck_bin", lambda _bin=None: _fake_sealcheck())
    behaviour: dict[str, object] = {"build": "ok"}

    def fake_run(cmd, *args, **kwargs):
        calls.append((list(cmd), kwargs))
        if "-V" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=version, stderr="")
        if "d4-image" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout='{"findings": []}', stderr="")
        if behaviour["build"] == "timeout":
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        Path(cmd[cmd.index("-F") + 1]).write_bytes(b"fake ext4")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls, behaviour


# Finding 1: builder identity ------------------------------------------------


def test_finding1_tarinfo_uses_source_owner_mode_and_clamped_mtime() -> None:
    """Tar headers carry the source uid/gid and every permission bit (setgid included), no names."""
    fake = os.stat_result((stat.S_IFREG | 0o2755, 1, 1, 1, 0, 50, 6, 0, T_EPOCH + 999, 0))
    info = make_tarinfo("usr/bin/tool", fake, T_EPOCH)
    assert (info.uid, info.gid) == (0, 50)
    assert info.mode == 0o2755
    assert info.uname == "" and info.gname == ""
    assert info.mtime == T_EPOCH, "mtime is clamped to T_clock"
    old = os.stat_result((stat.S_IFREG | 0o644, 1, 1, 1, 7, 8, 0, 0, 1000, 0))
    assert make_tarinfo("a", old, T_EPOCH).mtime == 1000


def test_finding1_stream_carries_source_ownership_and_setgid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The stream reflects the source inodes, not the (simulated) builder identity."""
    src = tmp_path / "src"
    (src / "usr" / "bin").mkdir(parents=True)
    tool = src / "usr" / "bin" / "tool"
    tool.write_text("#!/bin/sh\n")
    os.chmod(tool, 0o2755)
    st = os.lstat(tool)

    _, members_a, tar_a = _tar_tree(src, tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    monkeypatch.setattr(os, "getegid", lambda: 4343)
    monkeypatch.setattr(os, "getuid", lambda: 4242)
    monkeypatch.setattr(os, "getgid", lambda: 4343)
    _, _, tar_b = _tar_tree(src, tmp_path)

    member = members_a["usr/bin/tool"]
    assert (member.uid, member.gid) == (st.st_uid, st.st_gid)
    assert stat.S_IMODE(member.mode) == stat.S_IMODE(st.st_mode)
    assert tar_a.read_bytes() == tar_b.read_bytes()


@requires_mke2fs
@requires_sealcheck
def test_finding1_image_independent_of_builder_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two builds of the same tree with different (simulated) effective uids give the same sha256,
    and the image keeps the source owner and the setgid bit."""
    src = tmp_path / "src"
    (src / "usr" / "bin").mkdir(parents=True)
    tool = src / "usr" / "bin" / "tool"
    tool.write_text("#!/bin/sh\necho hi\n")
    os.chmod(tool, 0o2755)
    t_clock = datetime(2024, 1, 1, tzinfo=timezone.utc)

    res1 = build_rootfs(src=src, out_image=tmp_path / "a" / "r.ext4", t_clock=t_clock, world_id="w", size_mib=64)
    sealcheck = find_sealcheck_bin()
    monkeypatch.setattr("hermetic_slice.rootfs.find_sealcheck_bin", lambda _bin=None: sealcheck)
    # The simulated builder does not own the real test directories; the ownership checks on
    # storage directories are covered by the B4 tests, this test is about the image bytes.
    monkeypatch.setattr("hermetic_slice.rootfs.check_safe_dir_fd", lambda *_args: None)
    monkeypatch.setattr("hermetic_slice.rootfs.check_private_dir_fd", lambda *_args: None)
    for fn, value in (("geteuid", 4242), ("getuid", 4242), ("getegid", 4343), ("getgid", 4343)):
        monkeypatch.setattr(os, fn, lambda value=value: value)
    res2 = build_rootfs(
        src=src, out_image=tmp_path / "b" / "r.ext4", t_clock=t_clock, world_id="w", size_mib=64,
        work_dir=tmp_path,
    )
    monkeypatch.undo()
    assert res1["sha256"] == res2["sha256"]

    if DEBUGFS is not None:
        out = _debugfs(tmp_path / "a" / "r.ext4", "stat /usr/bin/tool")
        assert "Mode:  02755" in out
        assert f"User: {os.lstat(tool).st_uid:>5}" in out


# Finding 2: pinned mke2fs config, options and version ----------------------


def test_finding2_mke2fs_gets_pinned_config_and_explicit_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    calls, _ = _mock_toolchain(monkeypatch)

    res = build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                       world_id="w", work_dir=tmp_path)

    build_cmd, build_kwargs = next((c, k) for c, k in calls if "-d" in c)
    env = build_kwargs["env"]
    assert env["MKE2FS_CONFIG"] == str(MKE2FS_CONFIG_PATH)
    assert MKE2FS_CONFIG_PATH.is_file() and not MKE2FS_CONFIG_PATH.is_symlink()
    assert set(env) == {"PATH", "LANG", "TZ", "MKE2FS_CONFIG", "SOURCE_DATE_EPOCH", "E2FSPROGS_FAKE_TIME"}
    assert env["LANG"] == "C.UTF-8"

    def opt(flag: str) -> str:
        return build_cmd[build_cmd.index(flag) + 1]

    assert opt("-O") == EXT4_FEATURES and opt("-O").startswith("none,")
    assert opt("-b") == str(BLOCK_SIZE)
    assert opt("-I") == str(INODE_SIZE)
    assert opt("-N") == str(res["inode_count"])
    assert opt("-J") == f"size={res['journal_mib']}"
    assert opt("-t") == "ext4"
    assert opt("-m") == "5"
    assert "lazy_itable_init=0" in opt("-E") and "root_owner=0:0" in opt("-E")
    assert opt("-d").startswith("/proc/self/fd/"), "mke2fs reads the held tar descriptor"
    assert build_cmd[build_cmd.index("-F") + 1].startswith("/proc/self/fd/"), "and writes the held image descriptor"
    assert set(build_kwargs["pass_fds"]) == {int(opt("-d").rsplit("/", 1)[1]),
                                             int(build_cmd[build_cmd.index("-F") + 1].rsplit("/", 1)[1])}
    assert res["e2fsprogs_version"] == "1.47.2"
    assert res["mke2fs_config_sha256"] == hashlib.sha256(MKE2FS_CONFIG_PATH.read_bytes()).hexdigest()


def test_finding2_unpinned_mke2fs_version_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _mock_toolchain(monkeypatch, version="mke2fs 1.47.3 (1-Jan-2026)\n")
    with pytest.raises(RuntimeError, match="not a pinned version"):
        build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                     world_id="w", work_dir=tmp_path)
    assert not (tmp_path / "o.img").exists()


# Finding 3: copy TOCTOU ------------------------------------------------------


def _run_walker_bounded(src: Path, tar_path: Path, timeout_s: float = 20.0):
    outcome: dict[str, object] = {}

    def target() -> None:
        try:
            outcome["scan"] = write_rootfs_tar(src, tar_path, mtime_ceiling=T_EPOCH, limits=RootfsLimits())
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            outcome["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout=timeout_s)
    assert not worker.is_alive(), "walker blocked"
    return outcome


def _swap_on_open(monkeypatch: pytest.MonkeyPatch, victim: Path, replace) -> None:
    real_open = os.open

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None and path == victim.name and victim.exists() and not victim.is_symlink():
            victim.unlink()
            replace(victim)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swapping_open)


def test_finding3_file_swapped_for_symlink_is_not_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "host_secret"
    secret.write_text("HOST-SECRET-CONTENT")
    src = tmp_path / "src"
    src.mkdir()
    victim = src / "victim"
    victim.write_text("ordinary file")

    _swap_on_open(monkeypatch, victim, lambda p: p.symlink_to(secret))
    tar_path = tmp_path / "s.tar"
    outcome = _run_walker_bounded(src, tar_path)

    assert isinstance(outcome.get("error"), SourceChangedError)
    assert b"HOST-SECRET-CONTENT" not in tar_path.read_bytes()


def test_finding3_file_swapped_for_fifo_does_not_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    victim = src / "victim"
    victim.write_text("ordinary file")

    _swap_on_open(monkeypatch, victim, lambda p: os.mkfifo(p))
    outcome = _run_walker_bounded(src, tmp_path / "s.tar")
    assert isinstance(outcome.get("error"), SourceChangedError)


def test_finding3_symlinks_recorded_never_followed(tmp_path: Path) -> None:
    secret = tmp_path / "host_secret"
    secret.write_text("HOST-SECRET-CONTENT")
    src = tmp_path / "src"
    src.mkdir()
    (src / "link").symlink_to(secret)
    (src / "dirlink").symlink_to(tmp_path)

    _, members, tar_path = _tar_tree(src, tmp_path)
    assert members["link"].issym() and members["link"].linkname == str(secret)
    assert members["dirlink"].issym()
    assert b"HOST-SECRET-CONTENT" not in tar_path.read_bytes()


# Finding 4: resource caps, hard links, sparse files, depth -------------------


def test_finding4_hard_links_not_amplified(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    first = src / "big"
    first.write_bytes(os.urandom(1024 * 1024))
    for i in range(49):
        os.link(first, src / f"link{i:02d}")

    scan, members, tar_path = _tar_tree(src, tmp_path)
    assert scan.hardlinks == 49
    assert scan.data_bytes == 1024 * 1024
    assert tar_path.stat().st_size < 2 * 1024 * 1024
    assert members["link00"].islnk() and members["link00"].linkname == "big"


def test_finding4_sparse_file_streamed_sparsely(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    fd = os.open(src / "sparse", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.pwrite(fd, b"D" * 4096, 512 * 1024 * 1024)
        os.ftruncate(fd, 1024 * 1024 * 1024)
    finally:
        os.close(fd)
    if os.lstat(src / "sparse").st_blocks * 512 >= 1024 * 1024:
        pytest.skip("temporary filesystem does not keep holes")

    scan, members, tar_path = _tar_tree(src, tmp_path)
    assert scan.data_bytes == 4096
    assert scan.data_blocks == 1
    assert tar_path.stat().st_size < 1024 * 1024
    assert members["sparse"].size == 1024 * 1024 * 1024
    assert plan_image(scan).size_mib < 128, "sizing uses data runs, not st_size"


def test_finding4_entry_cap_trips_early(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(50):
        (src / f"f{i}").write_bytes(b"x")
    with pytest.raises(RootfsLimitError, match="more than 10 entries"):
        _tar_tree(src, tmp_path, max_entries=10)


def test_finding4_byte_cap_trips_early(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"f{i}").write_bytes(b"y" * 65536)
    tar_path_dir = tmp_path / "out"
    tar_path_dir.mkdir()
    with pytest.raises(RootfsLimitError, match="exceeds 100000 bytes"):
        _tar_tree(src, tar_path_dir, max_bytes=100_000)
    written = sum(p.stat().st_size for p in tar_path_dir.iterdir())
    assert written < 3 * 65536, "the walk stopped at the cap instead of reading everything"


def test_finding4_depth_cap_and_iterative_walk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    deep = src.joinpath(*(["d"] * 300))
    deep.mkdir(parents=True)
    (deep / "leaf").write_text("leaf")

    with pytest.raises(RootfsLimitError, match="deeper than 20"):
        _tar_tree(src, tmp_path, max_depth=20)

    # A recursive walker needs one Python frame per level; this one needs none.
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(len(inspect.stack()) + 120)
    try:
        _, members, _ = _tar_tree(src, tmp_path, max_depth=400)
    finally:
        sys.setrecursionlimit(old_limit)
    assert "/".join(["d"] * 300) + "/leaf" in members


def test_finding4_free_space_checked_before_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    monkeypatch.setattr(os, "statvfs", lambda _p: os.statvfs_result((4096, 4096, 100, 10, 10, 100, 10, 10, 0, 255)))
    with pytest.raises(RootfsLimitError, match="Not enough free space"):
        write_rootfs_tar(src, tmp_path / "s.tar", mtime_ceiling=T_EPOCH, limits=RootfsLimits())
    assert not (tmp_path / "s.tar").exists()


def test_finding4_limits_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMETIC_ROOTFS_MAX_BYTES", "123")
    monkeypatch.setenv("HERMETIC_ROOTFS_MAX_ENTRIES", "45")
    monkeypatch.setenv("HERMETIC_ROOTFS_MAX_DEPTH", "6")
    assert RootfsLimits.from_env() == RootfsLimits(max_bytes=123, max_entries=45, max_depth=6)
    monkeypatch.setenv("HERMETIC_ROOTFS_MAX_DEPTH", "0")
    with pytest.raises(ValueError):
        RootfsLimits.from_env()


# Finding 5: sealcheck discovery ----------------------------------------------


def test_finding5_no_ambient_sealcheck_search(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A binary planted under ~/hermetic/cargo-target, /home/hermetic-style dirs or $PATH is never used."""
    fake_home = tmp_path / "home" / "me"
    planted_dir = fake_home / "hermetic" / "cargo-target" / "x" / "release"
    planted_dir.mkdir(parents=True)
    marker = tmp_path / "executed"
    _fake_tool(planted_dir / "hermetic-sealcheck", f"touch {marker}; exit 0")
    other = tmp_path / "home" / "hermetic" / "cargo-target" / "y" / "release"
    other.mkdir(parents=True)
    _fake_tool(other / "hermetic-sealcheck", f"touch {marker}; exit 0")
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PATH", f"{planted_dir}:{os.environ.get('PATH', '')}")
    monkeypatch.delenv("HERMETIC_SEALCHECK_BIN", raising=False)

    with pytest.raises(FileNotFoundError, match="No hermetic-sealcheck binary given"):
        find_sealcheck_bin()
    assert not marker.exists(), "a planted binary was executed"


def test_finding5_sealcheck_path_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good = _fake_tool(tmp_path / "good", "exit 0")
    with find_sealcheck_bin(good) as pinned:
        assert pinned.path == good
    monkeypatch.setenv("HERMETIC_SEALCHECK_BIN", str(good))
    with find_sealcheck_bin() as pinned:
        assert pinned.path == good

    with pytest.raises(FileNotFoundError, match="absolute"):
        find_sealcheck_bin(Path("relative/hermetic-sealcheck"))
    link = tmp_path / "link"
    link.symlink_to(good)
    with pytest.raises(PermissionError, match="regular file"):
        find_sealcheck_bin(link)
    writable = _fake_tool(tmp_path / "writable", "exit 0", mode=0o775)
    with pytest.raises(PermissionError, match="writable"):
        find_sealcheck_bin(writable)
    monkeypatch.setenv("HERMETIC_SEALCHECK_BIN", str(writable))
    with pytest.raises(PermissionError, match="writable"):
        find_sealcheck_bin()
    no_d4 = _fake_tool(tmp_path / "no_d4", "exit 1")
    with pytest.raises(FileNotFoundError, match="does not support the d4-image"):
        find_sealcheck_bin(no_d4)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    with pytest.raises(PermissionError, match="owned by uid"):
        find_sealcheck_bin(good)


# Finding 6: subprocess timeouts ----------------------------------------------


def test_finding6_every_subprocess_call_has_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    calls, _ = _mock_toolchain(monkeypatch)
    build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                 world_id="w", work_dir=tmp_path)
    assert len(calls) == 3
    for _cmd, kwargs in calls:
        assert kwargs.get("timeout") and kwargs["timeout"] > 0


def test_finding6_mke2fs_timeout_is_clear_error_and_cleans_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    _, behaviour = _mock_toolchain(monkeypatch)
    behaviour["build"] = "timeout"
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    out_dir = tmp_path / "out"

    with pytest.raises(RootfsTimeoutError, match="timed out"):
        build_rootfs(src=src, out_image=out_dir / "o.img", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                     world_id="w", work_dir=work)
    assert list(work.iterdir()) == [], "work directory left behind"
    assert list(out_dir.iterdir()) == [], "temporary image left behind"


def test_finding6_sealcheck_probe_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hang = _fake_tool(tmp_path / "hang", "exec sleep 30")
    monkeypatch.setenv("HERMETIC_ROOTFS_TIMEOUT_SEALCHECK_PROBE", "1")
    t0 = time.monotonic()
    with pytest.raises(RootfsTimeoutError, match="timed out after 1 s"):
        find_sealcheck_bin(hang)
    assert time.monotonic() - t0 < 15


# Finding 7: host ACL / xattr leakage -----------------------------------------


def test_finding7_stream_has_no_xattrs_and_work_dir_is_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    f = src / "f"
    f.write_text("x")
    try:
        os.setxattr(f, "user.origin", b"host")
    except OSError:
        pass  # filesystem without user xattrs: the header check below still applies

    _, members, _ = _tar_tree(src, tmp_path)
    for member in members.values():
        assert not any("xattr" in key or "acl" in key.lower() for key in member.pax_headers)

    seen_work: list[str] = []
    calls, _ = _mock_toolchain(monkeypatch)
    real_run = subprocess.run

    def recording_run(cmd, *args, **kwargs):
        seen_work.extend(p.name for p in work.iterdir())
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", recording_run)
    out_dir = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    res = build_rootfs(src=src, out_image=out_dir / "o.img", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                       world_id="w", work_dir=work)
    assert res["xattrs"] == "none"
    assert seen_work and all(name.startswith("hermetic-rootfs-") for name in seen_work), "staging under work_dir"
    assert list(work.iterdir()) == [], "the private work directory is removed"
    assert sorted(p.name for p in out_dir.iterdir()) == ["o.img"], "nothing staged next to the output"


@requires_mke2fs
@requires_sealcheck
@requires_debugfs
def test_finding7_image_has_no_xattrs(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    f = src / "f"
    f.write_text("x")
    try:
        os.setxattr(f, "user.origin", b"host")
    except OSError:
        pytest.skip("temporary filesystem has no user xattrs")
    out = tmp_path / "r.ext4"
    build_rootfs(src=src, out_image=out, t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc), world_id="w", size_mib=64)
    for path in ("/", "/f"):
        assert "user." not in _debugfs(out, f"ea_list {path}")
        assert "security." not in _debugfs(out, f"ea_list {path}")


# Finding 8: sizing --------------------------------------------------------------


def test_finding8_100k_small_files_get_enough_space() -> None:
    """100,000 files of 100 bytes need 100,000 data blocks (~391 MiB), not 10 MB."""
    n = 100_000
    names = n * len("f_000000")
    scan = TreeScan(
        removed=[],
        skipped_special=[],
        inodes=n + 1,
        data_bytes=n * 100,
        data_blocks=n,
        dir_blocks=directory_blocks(names + n * 4, n),
    )
    plan = plan_image(scan)
    needed_blocks = n + scan.dir_blocks + math.ceil(plan.inode_count * INODE_SIZE / BLOCK_SIZE)
    assert plan.size_mib * 1024 * 1024 >= needed_blocks * BLOCK_SIZE + plan.journal_mib * 1024 * 1024
    assert plan.size_mib >= 391 + 31


def test_finding8_scan_counts_whole_blocks(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(300):
        (src / f"f_{i:03d}").write_bytes(b"z" * 100)
    (src / "long_link").symlink_to("x" * 80)
    scan, _, _ = _tar_tree(src, tmp_path)
    assert scan.data_blocks == 300, "each 100-byte file takes a whole 4 KiB block"
    assert scan.symlink_blocks == 1
    assert scan.dir_blocks >= 2, "301 dirents (~4.8 KiB) do not fit one directory block"
    assert scan.inodes == 302


@requires_mke2fs
@requires_sealcheck
def test_finding8_many_small_files_automatic_sizing(tmp_path: Path) -> None:
    """20,000 files of 100 bytes (~78 MiB of blocks) build with automatic sizing."""
    src = tmp_path / "src_small"
    src.mkdir()
    payload = b"s" * 100
    for i in range(20000):
        (src / f"f_{i:05d}").write_bytes(payload)
    res = build_rootfs(src=src, out_image=tmp_path / "r.ext4", t_clock=datetime(2024, 1, 1, tzinfo=timezone.utc),
                       world_id="small-files", size_mib=None)
    assert res["d4"] == "pass"


# -----------------------------------------------------------------------------
# Regression tests for the prior-defects check (t2.4-codex-priorcheck-20261112)
# -----------------------------------------------------------------------------

T_CLOCK = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _hooked_toolchain(monkeypatch: pytest.MonkeyPatch, *, on_build=None, on_d4=None, real_sealcheck: bool = False):
    """Mock mke2fs (and sealcheck unless real_sealcheck); hooks run inside the mocked steps."""
    calls: list[list[str]] = []
    real_run = subprocess.run
    monkeypatch.setattr("hermetic_slice.rootfs.resolve_mke2fs_bin", lambda: "/bin/mke2fs")
    if not real_sealcheck:
        monkeypatch.setattr("hermetic_slice.rootfs.find_sealcheck_bin", lambda _bin=None: _fake_sealcheck())

    def fake_run(cmd, *args, **kwargs):
        cmd = [str(c) for c in cmd]
        calls.append(cmd)
        if real_sealcheck and cmd[0].startswith("/proc/self/fd/"):
            return real_run(cmd, *args, **kwargs)
        if "-V" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="mke2fs 1.47.2 (1-Jan-2025)\n", stderr="")
        if "d4-image" in cmd:
            if on_d4 is not None:
                on_d4(Path(cmd[cmd.index("--image") + 1]))
            return subprocess.CompletedProcess(cmd, 0, stdout='{"findings": []}', stderr="")
        image = Path(cmd[cmd.index("-F") + 1])
        if on_build is not None:
            on_build(image, Path(cmd[cmd.index("-d") + 1]))
        with open(image, "r+b") as handle:  # like mke2fs: write into the existing file
            handle.write(b"GOOD-IMAGE")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _write_sparse_fixture(path: Path) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.ftruncate(fd, 16 * 1024 * 1024)
        os.pwrite(fd, b"A" * 5000, 1024 * 1024 + 100)        # data crossing a block boundary
        os.pwrite(fd, bytes(64 * 1024), 4 * 1024 * 1024)     # allocated, but all zeros
        os.pwrite(fd, b"Z" * 10, 16 * 1024 * 1024 - 10)      # data at the very end
    finally:
        os.close(fd)


def _no_hole_reporting(monkeypatch: pytest.MonkeyPatch) -> None:
    real_lseek = os.lseek

    def lseek(fd, pos, whence):
        if whence in (os.SEEK_DATA, os.SEEK_HOLE):
            raise OSError(errno.EINVAL, "hole reporting unsupported")
        return real_lseek(fd, pos, whence)

    monkeypatch.setattr(os, "lseek", lseek)


def test_b1_hole_layout_independent_of_host_hole_reporting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B1: the same content gives the same stream and image plan whether or not the host reports holes."""
    src = tmp_path / "src"
    src.mkdir()
    _write_sparse_fixture(src / "sparse.bin")

    scan_native, _, tar_native = _tar_tree(src, tmp_path)
    _no_hole_reporting(monkeypatch)
    scan_fallback, members, tar_fallback = _tar_tree(src, tmp_path)
    monkeypatch.undo()

    assert tar_native.read_bytes() == tar_fallback.read_bytes()
    assert plan_image(scan_native) == plan_image(scan_fallback)
    assert scan_native.data_blocks == scan_fallback.data_blocks == 3, "the all-zero region is a hole"
    assert members["sparse.bin"].size == 16 * 1024 * 1024


@requires_mke2fs
@requires_sealcheck
def test_b1_image_hash_independent_of_host_hole_reporting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _write_sparse_fixture(src / "sparse.bin")
    res1 = build_rootfs(src=src, out_image=tmp_path / "a" / "r.ext4", t_clock=T_CLOCK, world_id="b1")
    _no_hole_reporting(monkeypatch)
    res2 = build_rootfs(src=src, out_image=tmp_path / "b" / "r.ext4", t_clock=T_CLOCK, world_id="b1")
    assert res1["sha256"] == res2["sha256"]
    assert res1["size_bytes"] == res2["size_bytes"]


def test_b2_huge_all_hole_file_trips_logical_cap_before_mke2fs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B2: a 2 TiB all-hole file costs no stored bytes but must hit the logical-size cap before mke2fs."""
    src = tmp_path / "src"
    src.mkdir()
    fd = os.open(src / "huge", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.ftruncate(fd, 2 * 1024**4)
    except OSError:
        pytest.skip("temporary filesystem cannot hold a 2 TiB sparse file")
    finally:
        os.close(fd)
    calls = _hooked_toolchain(monkeypatch)

    t0 = time.monotonic()
    with pytest.raises(RootfsLimitError, match="logical size exceeds"):
        build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=T_CLOCK, world_id="b2", work_dir=tmp_path)
    assert time.monotonic() - t0 < 30
    assert not any("-d" in cmd for cmd in calls), "mke2fs must not start"
    assert not (tmp_path / "o.img").exists()


def test_b3_swapped_source_ancestor_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B3: an ancestor of src replaced by a symlink after the caller chose the path is refused;
    nothing from the symlink's target enters the stream."""
    shared = tmp_path / "shared"
    (shared / "input" / "root").mkdir(parents=True)
    (shared / "input" / "root" / "f").write_text("inside")
    outside = tmp_path / "outside"
    (outside / "root").mkdir(parents=True)
    (outside / "root" / "secret").write_text("OUTSIDE-SENTINEL")
    src = shared / "input" / "root"

    shutil.rmtree(shared / "input")
    (shared / "input").symlink_to(outside)

    seen: list[bytes] = []
    calls = _hooked_toolchain(monkeypatch, on_build=lambda _img, tar: seen.append(tar.read_bytes()))
    with pytest.raises(ValueError, match="symlinked"):
        build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=T_CLOCK, world_id="b3", work_dir=tmp_path)
    assert not any("-d" in cmd for cmd in calls)
    assert not any(b"OUTSIDE-SENTINEL" in data for data in seen)
    with pytest.raises(ValueError, match="symlinked"):
        write_rootfs_tar(src, tmp_path / "s.tar", mtime_ceiling=T_EPOCH)


def test_finding5_sealcheck_replaced_after_probe_does_not_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """5: the vetted descriptor runs for D4 even if the pathname is replaced after the probe."""
    bindir = tmp_path / "bin"
    bindir.mkdir(mode=0o755)
    good = _fake_tool(
        bindir / "hermetic-sealcheck",
        'if [ "$2" = "--help" ]; then exit 0; fi\n'
        'echo \'{"findings": [{"rule": "D4", "message": "checked by the vetted binary"}]}\'\nexit 2',
    )
    evil_marker = tmp_path / "evil-ran"
    evil = _fake_tool(tmp_path / "evil", f"touch {evil_marker}; exit 0")
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")

    _hooked_toolchain(monkeypatch, real_sealcheck=True, on_build=lambda _img, _tar: os.replace(evil, good))
    with pytest.raises(RootfsGateError) as excinfo:
        build_rootfs(src=src, out_image=tmp_path / "o.img", t_clock=T_CLOCK, world_id="w5",
                     sealcheck_bin=good, work_dir=tmp_path)
    assert excinfo.value.findings[0]["message"] == "checked by the vetted binary"
    assert not evil_marker.exists(), "the replacement binary ran"
    assert not (tmp_path / "o.img").exists()


def _out_dir_with_original(tmp_path: Path) -> tuple[Path, Path]:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    os.chmod(out_dir, 0o755)
    out = out_dir / "r.img"
    out.write_bytes(b"ORIGINAL")
    return out_dir, out


def test_b4_output_dir_substitutions_cannot_redirect_or_replace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B4: an attacker in the output directory swaps every other entry for a symlink before mke2fs
    and rewrites it after D4: the outside sentinel is untouched and only the verified image is published."""
    out_dir, out = _out_dir_with_original(tmp_path)
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("SENTINEL")
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")

    def before_mke2fs(image: Path, _tar: Path) -> None:
        for entry in list(out_dir.iterdir()):
            if entry.name != out.name:
                entry.unlink()
                entry.symlink_to(sentinel)

    def after_d4(_image: Path) -> None:
        for entry in list(out_dir.iterdir()):
            if entry.name != out.name:
                entry.unlink()
                entry.write_bytes(b"EVIL")

    _hooked_toolchain(monkeypatch, on_build=before_mke2fs, on_d4=after_d4)
    res = build_rootfs(src=src, out_image=out, t_clock=T_CLOCK, world_id="b4", work_dir=tmp_path)

    assert sentinel.read_text() == "SENTINEL"
    assert out.read_bytes() == b"GOOD-IMAGE"
    assert res["sha256"] == hashlib.sha256(b"GOOD-IMAGE").hexdigest()


def _only_work_dir(parent: Path) -> Path:
    entries = [p for p in parent.iterdir() if p.name.startswith("hermetic-rootfs-")]
    assert len(entries) == 1, entries
    return entries[0]


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=False)
    os.chmod(path, 0o700)
    return path


def test_b4_image_entry_replaced_after_d4_is_not_published(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The work entry is checked against the held descriptor right before the descriptor-relative rename."""
    out_dir, out = _out_dir_with_original(tmp_path)
    work_parent = _private_dir(tmp_path / "wp")
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")

    def swap(_image: Path) -> None:
        work = _only_work_dir(work_parent)
        (work / "evil").write_bytes(b"EVIL")
        os.replace(work / "evil", work / "rootfs.img")

    _hooked_toolchain(monkeypatch, on_d4=swap)
    with pytest.raises(RuntimeError, match="refusing to"):
        build_rootfs(src=src, out_image=out, t_clock=T_CLOCK, world_id="b4", work_dir=work_parent)
    assert out.read_bytes() == b"ORIGINAL"
    assert sorted(p.name for p in out_dir.iterdir()) == ["r.img"]


def _substitute_work_dir(work_parent: Path, sentinel: Path, *, as_symlink_entry: bool) -> Path:
    """Attacker: move the build's work directory away and put a look-alike at its name whose
    rootfs.img is a symlink to the sentinel (or a file with EVIL content)."""
    work = _only_work_dir(work_parent)
    moved = work_parent / "moved-away"
    os.rename(work, moved)
    fake = work_parent / work.name
    fake.mkdir(mode=0o700)
    if as_symlink_entry:
        (fake / "rootfs.img").symlink_to(sentinel)
        (fake / "rootfs.tar").symlink_to(sentinel)
    else:
        (fake / "rootfs.img").write_bytes(b"EVIL")
    return moved


def _substitute_ancestor(anchor: Path, sentinel: Path, *, as_symlink_entry: bool) -> None:
    """Attacker: replace an ancestor of the work directory with a symlink to a look-alike tree."""
    wp = anchor / "wp"
    work = _only_work_dir(wp)
    os.rename(anchor, anchor.with_name(anchor.name + "-real"))
    evil_root = anchor.with_name(anchor.name + "-evil")
    fake_work = evil_root / "wp" / work.name
    fake_work.mkdir(parents=True, mode=0o700)
    if as_symlink_entry:
        (fake_work / "rootfs.img").symlink_to(sentinel)
    else:
        (fake_work / "rootfs.img").write_bytes(b"EVIL")
    anchor.symlink_to(evil_root)


@pytest.mark.parametrize("stage", ["before_mke2fs", "before_publication"])
@pytest.mark.parametrize("target", ["work_dir", "ancestor"])
def test_b4_work_storage_substitution_never_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, target: str
) -> None:
    """B4: the work directory (or an ancestor of it) is substituted before mke2fs runs or just
    before publication. The build never writes through the substitute, never publishes its
    content, and the outside sentinel and the existing output stay intact unless the verified
    image replaces the output."""
    out_dir, out = _out_dir_with_original(tmp_path)
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"SENTINEL")
    os.chmod(sentinel, 0o600)
    anchor = _private_dir(tmp_path / "anc")
    work_parent = _private_dir(anchor / "wp")
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")

    def attack() -> None:
        if target == "work_dir":
            _substitute_work_dir(work_parent, sentinel, as_symlink_entry=(stage == "before_mke2fs"))
        else:
            _substitute_ancestor(anchor, sentinel, as_symlink_entry=(stage == "before_mke2fs"))

    hooks = {"on_build": (lambda _img, _tar: attack())} if stage == "before_mke2fs" else {"on_d4": (lambda _img: attack())}
    _hooked_toolchain(monkeypatch, **hooks)
    res = build_rootfs(src=src, out_image=out, t_clock=T_CLOCK, world_id="b4", work_dir=work_parent)

    assert sentinel.read_bytes() == b"SENTINEL", "wrote through the substituted work storage"
    assert stat.S_IMODE(os.lstat(sentinel).st_mode) == 0o600
    assert out.read_bytes() == b"GOOD-IMAGE", "published something other than the verified image"
    assert res["sha256"] == hashlib.sha256(b"GOOD-IMAGE").hexdigest()


def test_b4_shared_output_dir_needs_sticky_bit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir, out = _out_dir_with_original(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    _hooked_toolchain(monkeypatch)
    os.chmod(out_dir, 0o777)
    with pytest.raises(PermissionError, match="sticky"):
        build_rootfs(src=src, out_image=out, t_clock=T_CLOCK, world_id="b4", work_dir=tmp_path)
    assert out.read_bytes() == b"ORIGINAL"
    os.chmod(out_dir, 0o1777)
    try:
        build_rootfs(src=src, out_image=out, t_clock=T_CLOCK, world_id="b4", work_dir=tmp_path)
    finally:
        os.chmod(out_dir, 0o755)
    assert out.read_bytes() == b"GOOD-IMAGE"


def test_b4_cross_filesystem_publish_copies_held_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir, out = _out_dir_with_original(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x")
    _hooked_toolchain(monkeypatch)
    real_replace = os.replace

    def replace(a, b, *args, **kwargs):
        if kwargs.get("src_dir_fd") is not None and kwargs.get("src_dir_fd") != kwargs.get("dst_dir_fd"):
            raise OSError(errno.EXDEV, "cross-device link")
        return real_replace(a, b, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    res = build_rootfs(src=src, out_image=out, t_clock=T_CLOCK, world_id="b4", work_dir=tmp_path)
    assert out.read_bytes() == b"GOOD-IMAGE"
    assert res["sha256"] == hashlib.sha256(b"GOOD-IMAGE").hexdigest()
    assert sorted(p.name for p in out_dir.iterdir()) == ["r.img"]
