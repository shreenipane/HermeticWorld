"""Tests for reproducible ext4 rootfs builder with D4 guard (T2.4)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import uuid

import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.rootfs import (
    HERMETIC_NAMESPACE,
    MIN_E2FSPROGS_VERSION,
    RootfsGateError,
    build_rootfs,
    calculate_image_size_mib,
    calculate_inode_count,
    check_e2fsprogs_version,
    clean_rootfs_staging,
    compute_tree_size_bytes,
    compute_tree_stats,
    copy_to_staging,
    find_sealcheck_bin,
    parse_mke2fs_version,
    resolve_mke2fs_bin,
)


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
        )
        ver = parse_mke2fs_version(f"{proc.stdout}\n{proc.stderr}")
        if ver < MIN_E2FSPROGS_VERSION:
            return False, f"mke2fs version {ver} is older than required 1.47.1"
        return True, ""
    except Exception as exc:
        return False, f"mke2fs version check failed: {exc}"


def _check_sealcheck_usable() -> tuple[bool, str]:
    try:
        find_sealcheck_bin()
        return True, ""
    except Exception as exc:
        return False, f"hermetic-sealcheck binary not found: {exc}"


MKE2FS_AVAILABLE, MKE2FS_REASON = _check_mke2fs_usable()
SEALCHECK_AVAILABLE, SEALCHECK_REASON = _check_sealcheck_usable()

requires_mke2fs = pytest.mark.skipif(not MKE2FS_AVAILABLE, reason=MKE2FS_REASON)
requires_sealcheck = pytest.mark.skipif(not SEALCHECK_AVAILABLE, reason=SEALCHECK_REASON)


def hash_directory_tree(root: Path) -> str:
    """Compute deterministic SHA256 over all relative paths and contents in a directory."""
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


# -----------------------------------------------------------------------------
# Unit Tests (no subprocess needed)
# -----------------------------------------------------------------------------


def test_version_check_rejects_and_accepts() -> None:
    """Version check rejects 1.47.0 and accepts 1.47.2 (unit test, no subprocess)."""
    # Accept 1.47.2
    v1 = check_e2fsprogs_version("mke2fs 1.47.2 (1-Jan-2025)")
    assert v1 == (1, 47, 2)

    # Accept 1.47.1
    v2 = check_e2fsprogs_version("mke2fs 1.47.1 (20-May-2024)\n\tUsing EXT2FS Library version 1.47.1")
    assert v2 == (1, 47, 1)

    # Reject 1.47.0
    with pytest.raises(RuntimeError) as excinfo:
        check_e2fsprogs_version("mke2fs 1.47.0 (5-Feb-2023)")
    assert "1.47.0" in str(excinfo.value)
    assert "1.47.1" in str(excinfo.value)

    # Invalid version string
    with pytest.raises(ValueError):
        parse_mke2fs_version("invalid version string")


def test_calculate_image_size_mib(tmp_path: Path) -> None:
    """Size calculation computes staging * 1.3 + 64 MiB or uses explicit size_mib."""
    staging = tmp_path / "staging"
    staging.mkdir()

    # Empty staging: 0 MiB * 1.3 + 64 = 64 MiB
    assert calculate_image_size_mib(staging) == 64

    # 10 MiB in staging: 10 * 1.3 + 64 = 77 MiB
    (staging / "test.bin").write_bytes(b"\x00" * (10 * 1024 * 1024))
    assert calculate_image_size_mib(staging) == 77

    # Explicit size_mib overrides calculation
    assert calculate_image_size_mib(staging, size_mib=128) == 128

    # Negative / zero size_mib raises ValueError
    with pytest.raises(ValueError):
        calculate_image_size_mib(staging, size_mib=0)


def test_special_files_skipped(tmp_path: Path) -> None:
    """Special files (FIFOs, device nodes) are skipped and listed in skipped_special."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "file.txt").write_text("hello")
    sub = src / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("world")

    fifo_path = src / "dev_fifo"
    os.mkfifo(fifo_path)

    nested_fifo = sub / "nested_fifo"
    os.mkfifo(nested_fifo)

    staging = tmp_path / "staging"
    skipped = copy_to_staging(src, staging)

    assert skipped == ["dev_fifo", "sub/nested_fifo"]
    assert not (staging / "dev_fifo").exists()
    assert not (staging / "sub" / "nested_fifo").exists()
    assert (staging / "file.txt").read_text() == "hello"
    assert (staging / "sub" / "nested_txt" if False else (staging / "sub" / "nested.txt")).read_text() == "world"


def test_cleanup_targets_and_src_untouched(tmp_path: Path) -> None:
    """Clean-up removes exactly listed caches and histories, keeps var/log and var/cache, and preserves src."""
    src = tmp_path / "src"
    src.mkdir()

    # 1. var/log
    (src / "var" / "log" / "nginx").mkdir(parents=True)
    (src / "var" / "log" / "syslog").write_text("logs")
    (src / "var" / "log" / "nginx" / "access.log").write_text("access")

    # 2. var/cache
    (src / "var" / "cache" / "apt").mkdir(parents=True)
    (src / "var" / "cache" / "apt" / "pkg.deb").write_bytes(b"deb")

    # 3. var/lib/apt/lists
    (src / "var" / "lib" / "apt" / "lists").mkdir(parents=True)
    (src / "var" / "lib" / "apt" / "lists" / "deb.debian.org_Packages").write_text("packages")

    # 4. pip and uv caches
    (src / "root" / ".cache" / "pip" / "wheels").mkdir(parents=True)
    (src / "root" / ".cache" / "pip" / "wheels" / "pkg.whl").write_bytes(b"whl")
    (src / "root" / ".cache" / "uv").mkdir(parents=True)
    (src / "root" / ".cache" / "uv" / "cache.db").write_text("uvcache")

    (src / "home" / "user1" / ".cache" / "pip").mkdir(parents=True)
    (src / "home" / "user1" / ".cache" / "pip" / "p.whl").write_bytes(b"whl")
    (src / "home" / "user1" / ".cache" / "uv").mkdir(parents=True)
    (src / "home" / "user1" / ".cache" / "uv" / "u.db").write_text("uv")

    # 5. conda pkgs
    (src / "opt" / "conda" / "pkgs").mkdir(parents=True)
    (src / "opt" / "conda" / "pkgs" / "pkg1.tar.bz2").write_bytes(b"pkg1")
    (src / "opt" / "conda" / "pkgs" / "urls.txt").write_text("https://conda.anaconda.org/main\n")

    (src / "home" / "user1" / "miniconda3" / "pkgs").mkdir(parents=True)
    (src / "home" / "user1" / "miniconda3" / "pkgs" / "pkg2.tar.bz2").write_bytes(b"pkg2")
    (src / "home" / "user1" / "miniconda3" / "pkgs" / "urls.txt").write_text("https://conda.anaconda.org/r\n")

    # 6. shell histories
    (src / "root" / ".bash_history").write_text("ls\n")
    (src / "home" / "user1" / ".bash_history").write_text("cd\n")
    (src / "home" / "user1" / ".zsh_history").write_text(": 1234:0;echo hi\n")
    (src / "home" / "user1" / ".python_history").write_text("import os\n")
    (src / "home" / "user1" / ".lesshst").write_text(".search\n")
    (src / "root" / ".viminfo").write_text("'0  1  0\n")

    # 7. Non-cache files that MUST be preserved
    (src / "etc").mkdir()
    (src / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    (src / "home" / "user1" / "project").mkdir()
    (src / "home" / "user1" / "project" / "main.py").write_text("print('hello')\n")

    src_hash_before = hash_directory_tree(src)

    staging = tmp_path / "staging"
    copy_to_staging(src, staging)
    removed = clean_rootfs_staging(staging)

    # Verify src is untouched
    src_hash_after = hash_directory_tree(src)
    assert src_hash_before == src_hash_after, "Clean-up modified src directory!"

    # Verify kept directories
    assert (staging / "var" / "log").is_dir()
    assert (staging / "var" / "cache").is_dir()
    assert (staging / "var" / "lib" / "apt" / "lists").is_dir()
    assert (staging / "opt" / "conda" / "pkgs").is_dir()
    assert (staging / "opt" / "conda" / "pkgs" / "urls.txt").is_file()
    assert (staging / "home" / "user1" / "miniconda3" / "pkgs" / "urls.txt").is_file()

    # Verify kept regular files
    assert (staging / "etc" / "passwd").is_file()
    assert (staging / "home" / "user1" / "project" / "main.py").is_file()

    # Verify deleted paths
    assert not (staging / "var" / "log" / "syslog").exists()
    assert not (staging / "var" / "log" / "nginx").exists()
    assert not (staging / "var" / "cache" / "apt").exists()
    assert not (staging / "var" / "lib" / "apt" / "lists" / "deb.debian.org_Packages").exists()
    assert not (staging / "root" / ".cache" / "pip").exists()
    assert not (staging / "root" / ".cache" / "uv").exists()
    assert not (staging / "home" / "user1" / ".cache" / "pip").exists()
    assert not (staging / "home" / "user1" / ".cache" / "uv").exists()
    assert not (staging / "opt" / "conda" / "pkgs" / "pkg1.tar.bz2").exists()
    assert not (staging / "home" / "user1" / "miniconda3" / "pkgs" / "pkg2.tar.bz2").exists()
    assert not (staging / "root" / ".bash_history").exists()
    assert not (staging / "home" / "user1" / ".bash_history").exists()
    assert not (staging / "home" / "user1" / ".zsh_history").exists()
    assert not (staging / "home" / "user1" / ".python_history").exists()
    assert not (staging / "home" / "user1" / ".lesshst").exists()
    assert not (staging / "root" / ".viminfo").exists()

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
    assert removed == expected_removed


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
        lambda _bin=None: Path("/bin/hermetic-sealcheck"),
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
# Regression Tests for Security Review Fixes 1-6
# -----------------------------------------------------------------------------


def test_fix1_symlinks_in_cleanup_a_staging_var_log_absolute_host_dir(tmp_path: Path) -> None:
    """FIX 1 (a): staging var/log -> absolute path of a tmp host directory containing files:
    after the build those host files still exist."""
    host_dir = tmp_path / "host_log"
    host_dir.mkdir()
    host_file = host_dir / "syslog.host"
    host_file.write_text("critical host log content")

    src = tmp_path / "src_a"
    src.mkdir()
    (src / "var").mkdir()
    (src / "var" / "log").symlink_to(host_dir.resolve())

    staging = tmp_path / "staging_a"
    copy_to_staging(src, staging)
    removed = clean_rootfs_staging(staging)

    assert host_file.exists(), "Host file was deleted by clean-up following symlink!"
    assert host_file.read_text() == "critical host log content"
    assert "var/log/syslog.host" not in removed


def test_fix1_symlinks_in_cleanup_b_home_u_host_dir_with_history(tmp_path: Path) -> None:
    """FIX 1 (b): home/u -> a host dir containing .bash_history: the host file still exists."""
    host_dir = tmp_path / "host_user"
    host_dir.mkdir()
    host_hist = host_dir / ".bash_history"
    host_hist.write_text("secret host history")

    src = tmp_path / "src_b"
    src.mkdir()
    (src / "home").mkdir()
    (src / "home" / "u").symlink_to(host_dir.resolve())

    staging = tmp_path / "staging_b"
    copy_to_staging(src, staging)
    removed = clean_rootfs_staging(staging)

    assert host_hist.exists(), "Host history was deleted by clean-up following symlink!"
    assert host_hist.read_text() == "secret host history"
    assert "home/u/.bash_history" not in removed


def test_fix1_symlinks_in_cleanup_c_var_points_outside(tmp_path: Path) -> None:
    """FIX 1 (c): var -> ../outside: nothing outside staging is touched."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "untouchable.txt"
    outside_file.write_text("outside data")
    outside_log = outside_dir / "log"
    outside_log.mkdir()
    outside_log_file = outside_log / "app.log"
    outside_log_file.write_text("outside log")

    src = tmp_path / "src_c"
    src.mkdir()
    (src / "var").symlink_to(Path("..") / "outside")

    staging = tmp_path / "staging_c"
    copy_to_staging(src, staging)
    removed = clean_rootfs_staging(staging)

    assert outside_file.exists()
    assert outside_file.read_text() == "outside data"
    assert outside_log_file.exists()
    assert outside_log_file.read_text() == "outside log"
    assert not any(r.startswith("var/") for r in removed)


def test_fix1_symlinks_in_cleanup_d_history_symlink_to_host_file(tmp_path: Path) -> None:
    """FIX 1 (d): a .bash_history that is itself a symlink to a host file:
    the link is removed, the host file stays."""
    host_file = tmp_path / "host_bash_history"
    host_file.write_text("precious history")

    src = tmp_path / "src_d"
    src.mkdir()
    (src / "home" / "user").mkdir(parents=True)
    (src / "home" / "user" / ".bash_history").symlink_to(host_file.resolve())

    staging = tmp_path / "staging_d"
    copy_to_staging(src, staging)
    removed = clean_rootfs_staging(staging)

    # Host file stays!
    assert host_file.exists()
    assert host_file.read_text() == "precious history"
    # The symlink in staging was unlinked!
    assert not (staging / "home" / "user" / ".bash_history").exists()
    assert not (staging / "home" / "user" / ".bash_history").is_symlink()
    assert "home/user/.bash_history" in removed


def test_fix2_readonly_parent_made_writable_in_staging_never_in_src(tmp_path: Path) -> None:
    """FIX 2: A history file in a read-only directory inside source is still removed
    (parent made writable in staging, never in src)."""
    src = tmp_path / "src_ro"
    src.mkdir()
    user_dir = src / "home" / "user"
    user_dir.mkdir(parents=True)
    hist = user_dir / ".bash_history"
    hist.write_text("history")

    # Make parent directory in src read-only (no user write: 0o555)
    os.chmod(user_dir, 0o555)
    try:
        staging = tmp_path / "staging_ro"
        copy_to_staging(src, staging)

        staging_user = staging / "home" / "user"
        # Verify staging started read-only like src
        assert (staging_user.stat().st_mode & stat.S_IWUSR) == 0

        removed = clean_rootfs_staging(staging)

        # Removed from staging
        assert "home/user/.bash_history" in removed
        assert not (staging / "home" / "user" / ".bash_history").exists()

        # Parent in staging made writable
        assert (staging_user.stat().st_mode & stat.S_IWUSR) != 0

        # Parent in src NEVER made writable!
        assert (user_dir.stat().st_mode & stat.S_IWUSR) == 0
    finally:
        # Restore src permissions for clean tmp_path teardown
        os.chmod(user_dir, 0o755)


def test_readonly_staging_dir_with_symlinked_history_leaves_host_mode_unchanged(tmp_path: Path) -> None:
    """The rootfs builder test with a read-only staging directory holding a
    symlinked history file leaves the host target's mode unchanged."""
    if os.geteuid() == 0:
        pytest.skip("Read-only directory test requires non-root user")

    host_file = tmp_path / "host_bash_history"
    host_file.write_text("precious history")
    os.chmod(host_file, 0o644)
    orig_mode = stat.S_IMODE(os.lstat(host_file).st_mode)

    src = tmp_path / "src_ro_symlink"
    src.mkdir()
    user_dir = src / "home" / "user"
    user_dir.mkdir(parents=True)
    (user_dir / ".bash_history").symlink_to(host_file.resolve())

    os.chmod(user_dir, 0o555)
    try:
        staging = tmp_path / "staging_ro_symlink"
        copy_to_staging(src, staging)

        staging_user = staging / "home" / "user"
        assert (staging_user.stat().st_mode & stat.S_IWUSR) == 0

        removed = clean_rootfs_staging(staging)

        assert "home/user/.bash_history" in removed
        assert not (staging / "home" / "user" / ".bash_history").exists()
        assert not (staging / "home" / "user" / ".bash_history").is_symlink()

        assert host_file.exists()
        assert host_file.read_text() == "precious history"
        assert stat.S_IMODE(os.lstat(host_file).st_mode) == orig_mode
        assert (user_dir.stat().st_mode & stat.S_IWUSR) == 0
    finally:
        os.chmod(user_dir, 0o755)


def test_fix2_unremovable_file_raises_error_naming_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FIX 2: A case that cannot be removed (monkeypatch on os.unlink raising PermissionError twice) raises."""
    src = tmp_path / "src_fail"
    src.mkdir()
    (src / "home" / "user").mkdir(parents=True)
    (src / "home" / "user" / ".bash_history").write_text("history")

    staging = tmp_path / "staging_fail"
    copy_to_staging(src, staging)

    unlink_calls = 0

    def mock_unlink(path, *args, **kwargs):
        nonlocal unlink_calls
        unlink_calls += 1
        raise PermissionError(f"Permission denied on {path}")

    monkeypatch.setattr(os, "unlink", mock_unlink)

    with pytest.raises(RuntimeError) as excinfo:
        clean_rootfs_staging(staging)

    assert ".bash_history" in str(excinfo.value)
    assert unlink_calls >= 2


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
        lambda _bin=None: Path("/bin/hermetic-sealcheck"),
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
