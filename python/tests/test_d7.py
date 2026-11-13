
"""Comprehensive test suite for Hermetic World Detector D7."""

from __future__ import annotations

import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from hermetic_d7 import (
    MAX_DIFF_LINES,
    PYC_HEADER_SIZE,
    ResourceLimits,
    compare_artifacts,
    format_report_json,
)


def _write_zip(
    path: Path,
    entries: list[tuple[str, bytes, tuple[int, int, int, int, int, int], int]],
) -> Path:
    """Create a deterministic zip/wheel archive with explicit timestamps and POSIX modes."""
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, payload, dt, mode in entries:
            info = zipfile.ZipInfo(filename=arcname, date_time=dt)
            info.create_system = 3
            info.external_attr = (mode & 0xFFFF) << 16
            zf.writestr(info, payload)
    return path


def _write_tar(
    path: Path,
    entries: list[tuple[str, bytes, int, int]],
    *,
    gzipped: bool = False,
) -> Path:
    """Create a tar or tar.gz archive with explicit mtimes and modes."""
    mode = "w:gz" if gzipped else "w"
    with tarfile.open(path, mode=mode) as tf:
        for arcname, payload, mtime, perm in entries:
            ti = tarfile.TarInfo(name=arcname)
            ti.size = len(payload)
            ti.mtime = mtime
            ti.mode = perm
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(payload))
    return path


def _make_pyc(header_bytes: bytes, bytecode_payload: bytes) -> bytes:
    """Construct a synthetic .pyc binary with a 16-byte header + payload."""
    assert len(header_bytes) == PYC_HEADER_SIZE
    return header_bytes + bytecode_payload


def test_identical_artifacts_different_timestamps(tmp_path: Path) -> None:
    """Requirement 1 & 2: identical contents with different timestamps yield 'identical'."""
    py_code = b"def add(a: int, b: int) -> int:\n    return a + b\n"
    init_code = b"__version__ = '1.0.0'\n"

    whl_a = _write_zip(
        tmp_path / "demo-1.0.0-py3-none-any-a.whl",
        [
            ("demo/__init__.py", init_code, (2020, 1, 1, 0, 0, 0), 0o100644),
            ("demo/math_ops.py", py_code, (2020, 1, 1, 0, 0, 0), 0o100644),
        ],
    )
    whl_b = _write_zip(
        tmp_path / "demo-1.0.0-py3-none-any-b.whl",
        [
            ("demo/__init__.py", init_code, (2026, 6, 15, 12, 30, 0), 0o100644),
            ("demo/math_ops.py", py_code, (2026, 6, 15, 12, 30, 0), 0o100644),
        ],
    )

    rep_whl = compare_artifacts(whl_a, whl_b)
    assert rep_whl["verdict"] == "identical"
    assert rep_whl["only_in_shipped"] == []
    assert rep_whl["only_in_rebuilt"] == []
    assert rep_whl["content_differences"] == []

    tar_a = _write_tar(
        tmp_path / "demo-a.tar.gz",
        [
            ("demo/__init__.py", init_code, 1_577_836_800, 0o644),
            ("demo/math_ops.py", py_code, 1_577_836_800, 0o644),
        ],
        gzipped=True,
    )
    tar_b = _write_tar(
        tmp_path / "demo-b.tar.gz",
        [
            ("demo/__init__.py", init_code, 1_780_000_000, 0o644),
            ("demo/math_ops.py", py_code, 1_780_000_000, 0o644),
        ],
        gzipped=True,
    )

    rep_tar = compare_artifacts(tar_a, tar_b)
    assert rep_tar["verdict"] == "identical"

    # Cross-format comparison: unpacked directory tree vs .tar
    dir_a = tmp_path / "unpacked"
    (dir_a / "demo").mkdir(parents=True)
    (dir_a / "demo" / "__init__.py").write_bytes(init_code)
    (dir_a / "demo" / "math_ops.py").write_bytes(py_code)

    rep_cross = compare_artifacts(dir_a, tar_b)
    assert rep_cross["verdict"] == "identical"


def test_pyc_header_only_difference_vs_bytecode_difference(tmp_path: Path) -> None:
    """Requirement 2 & 3: .pyc 16-byte header differences ignored; body differences hashed only."""
    header_a = struct.pack("<IIII", 0x0A0DF303, 0, 1_600_000_000, 42)
    header_b = struct.pack("<IIII", 0x0A0DF303, 1, 1_750_000_000, 42)
    payload_same = b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00bytecode_body_v1\xff"
    payload_diff = b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00bytecode_body_v2\xff"

    zip_a = _write_zip(
        tmp_path / "pyc_a.zip",
        [("pkg/__pycache__/mod.cpython-311.pyc", _make_pyc(header_a, payload_same), (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    zip_b = _write_zip(
        tmp_path / "pyc_b.zip",
        [("pkg/__pycache__/mod.cpython-311.pyc", _make_pyc(header_b, payload_same), (2025, 1, 1, 0, 0, 0), 0o100644)],
    )

    rep_same = compare_artifacts(zip_a, zip_b)
    assert rep_same["verdict"] == "identical"

    zip_c = _write_zip(
        tmp_path / "pyc_c.zip",
        [("pkg/__pycache__/mod.cpython-311.pyc", _make_pyc(header_b, payload_diff), (2025, 1, 1, 0, 0, 0), 0o100644)],
    )
    rep_diff = compare_artifacts(zip_a, zip_c)
    assert rep_diff["verdict"] == "differs"
    assert len(rep_diff["content_differences"]) == 1
    diff_item = rep_diff["content_differences"][0]
    assert diff_item["is_text"] is False
    assert "unified_diff" not in diff_item
    assert len(diff_item["sha256_shipped"]) == 64
    assert len(diff_item["sha256_rebuilt"]) == 64
    assert diff_item["sha256_shipped"] != diff_item["sha256_rebuilt"]


def test_record_ordering_and_self_entry_normalised(tmp_path: Path) -> None:
    """Requirement 2: wheel RECORD compared as sorted lines with RECORD's own line removed."""
    rec_path = "demo-1.0.0.dist-info/RECORD"
    record_a = (
        "demo/b.py,sha256=bbbb,20\n"
        "demo-1.0.0.dist-info/RECORD,,\n"
        "demo/a.py,sha256=aaaa,10\n"
    ).encode("utf-8")
    record_b = (
        "demo/a.py,sha256=aaaa,10\n"
        "demo/b.py,sha256=bbbb,20\n"
        "demo-1.0.0.dist-info/RECORD,sha256=selfhash,123\n"
    ).encode("utf-8")

    whl_a = _write_zip(
        tmp_path / "rec_a.whl",
        [(rec_path, record_a, (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    whl_b = _write_zip(
        tmp_path / "rec_b.whl",
        [(rec_path, record_b, (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    assert compare_artifacts(whl_a, whl_b)["verdict"] == "identical"

    record_tampered = (
        "demo/a.py,sha256=TAMPERED,10\n"
        "demo/b.py,sha256=bbbb,20\n"
        "demo-1.0.0.dist-info/RECORD,,\n"
    ).encode("utf-8")
    whl_c = _write_zip(
        tmp_path / "rec_c.whl",
        [(rec_path, record_tampered, (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    assert compare_artifacts(whl_a, whl_c)["verdict"] == "differs"


def test_pkg_info_metadata_trailing_blank_lines_and_line_endings_policy(tmp_path: Path) -> None:
    """Requirement 2: trailing blank lines dropped in PKG-INFO/METADATA; line endings not normalised."""
    meta_a = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n\nBody text.\n"
    meta_b = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n\nBody text.\n\n   \n\t\n"

    whl_a = _write_zip(
        tmp_path / "meta_a.whl",
        [
            ("demo-1.0.0.dist-info/METADATA", meta_a, (2024, 1, 1, 0, 0, 0), 0o100644),
            ("PKG-INFO", meta_a, (2024, 1, 1, 0, 0, 0), 0o100644),
        ],
    )
    whl_b = _write_zip(
        tmp_path / "meta_b.whl",
        [
            ("demo-1.0.0.dist-info/METADATA", meta_b, (2024, 1, 1, 0, 0, 0), 0o100644),
            ("PKG-INFO", meta_b, (2024, 1, 1, 0, 0, 0), 0o100644),
        ],
    )
    rep_meta = compare_artifacts(whl_a, whl_b)
    assert rep_meta["verdict"] == "identical"
    assert rep_meta["normalisation"]["line_endings"] == "not_normalised"

    # Line endings are NOT normalised: CRLF vs LF must produce 'differs'
    lf_zip = _write_zip(
        tmp_path / "lf.zip",
        [("pkg/text.py", b"x = 1\ny = 2\n", (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    crlf_zip = _write_zip(
        tmp_path / "crlf.zip",
        [("pkg/text.py", b"x = 1\r\ny = 2\r\n", (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    rep_eol = compare_artifacts(lf_zip, crlf_zip)
    assert rep_eol["verdict"] == "differs"
    assert rep_eol["content_differences"][0]["is_text"] is True


def test_permissions_compared_only_for_executable_bit(tmp_path: Path) -> None:
    """Requirement 2: non-executable mode variations ignored; executable bit toggle detected."""
    payload = b"#!/usr/bin/env python3\nprint('hi')\n"

    tar_644 = _write_tar(tmp_path / "p644.tar", [("bin/tool.py", payload, 1_700_000_000, 0o644)])
    tar_664 = _write_tar(tmp_path / "p664.tar", [("bin/tool.py", payload, 1_700_000_000, 0o664)])
    tar_755 = _write_tar(tmp_path / "p755.tar", [("bin/tool.py", payload, 1_700_000_000, 0o755)])
    tar_775 = _write_tar(tmp_path / "p775.tar", [("bin/tool.py", payload, 1_700_000_000, 0o775)])

    assert compare_artifacts(tar_644, tar_664)["verdict"] == "identical"
    assert compare_artifacts(tar_755, tar_775)["verdict"] == "identical"

    rep_exec = compare_artifacts(tar_644, tar_755)
    assert rep_exec["verdict"] == "differs"
    diff = rep_exec["content_differences"][0]
    assert diff["content_changed"] is False
    assert diff["executable_changed"] is True
    assert diff["executable_shipped"] is False
    assert diff["executable_rebuilt"] is True


def test_changed_function_in_py_member_detected_with_bounded_diff(tmp_path: Path) -> None:
    """Requirement 3 & 4: function change in .py gets hashes + bounded unified diff + audit-only policy."""
    shipped_py = (
        "def compute(x: int) -> int:\n"
        "    # subtle backdoor in shipped artifact\n"
        "    if x == 1337:\n"
        "        return 9999\n"
        "    return x * 2\n"
    ).encode("utf-8")
    rebuilt_py = (
        "def compute(x: int) -> int:\n"
        "    return x * 2\n"
    ).encode("utf-8")

    whl_shipped = _write_zip(
        tmp_path / "shipped.whl",
        [("pkg/core.py", shipped_py, (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    whl_rebuilt = _write_zip(
        tmp_path / "rebuilt.whl",
        [("pkg/core.py", rebuilt_py, (2024, 1, 1, 0, 0, 0), 0o100644)],
    )

    report = compare_artifacts(whl_shipped, whl_rebuilt)
    assert report["verdict"] == "differs"
    assert report["audit_only"] is True
    assert report["gating"] is False
    assert "audit-only" in report["policy"]
    assert "never gates" in report["policy"]

    assert len(report["content_differences"]) == 1
    item = report["content_differences"][0]
    assert item["path"] == "pkg/core.py"
    assert item["is_text"] is True
    assert item["sha256_shipped"] != item["sha256_rebuilt"]
    assert "-    if x == 1337:" in item["unified_diff"]
    assert len(item["unified_diff"].splitlines()) <= MAX_DIFF_LINES

    # Verify unified diff line bound is enforced on large text diffs
    big_a = "\n".join(f"line_a_{i}" for i in range(600)).encode("utf-8")
    big_b = "\n".join(f"line_b_{i}" for i in range(600)).encode("utf-8")
    zip_big_a = _write_zip(tmp_path / "big_a.zip", [("big.txt", big_a, (2024, 1, 1, 0, 0, 0), 0o100644)])
    zip_big_b = _write_zip(tmp_path / "big_b.zip", [("big.txt", big_b, (2024, 1, 1, 0, 0, 0), 0o100644)])
    tight_limits = ResourceLimits(max_diff_lines=15)
    rep_big = compare_artifacts(zip_big_a, zip_big_b, limits=tight_limits)
    big_item = rep_big["content_differences"][0]
    assert big_item["diff_truncated"] is True
    assert len(big_item["unified_diff"].splitlines()) <= 15


def test_member_only_on_one_side(tmp_path: Path) -> None:
    """Requirement 3: members only in A and only in B reported accurately."""
    shared = b"SHARED = True\n"
    zip_a = _write_zip(
        tmp_path / "side_a.zip",
        [
            ("pkg/shared.py", shared, (2024, 1, 1, 0, 0, 0), 0o100644),
            ("pkg/extra_shipped.py", b"A = 1\n", (2024, 1, 1, 0, 0, 0), 0o100644),
        ],
    )
    zip_b = _write_zip(
        tmp_path / "side_b.zip",
        [
            ("pkg/shared.py", shared, (2024, 1, 1, 0, 0, 0), 0o100644),
            ("pkg/extra_rebuilt.py", b"B = 2\n", (2024, 1, 1, 0, 0, 0), 0o100644),
        ],
    )

    report = compare_artifacts(zip_a, zip_b)
    assert report["verdict"] == "differs"
    assert report["only_in_shipped"] == ["pkg/extra_shipped.py"]
    assert report["only_in_rebuilt"] == ["pkg/extra_rebuilt.py"]
    assert report["content_differences"] == []


def test_zip_bomb_and_member_caps_refused(tmp_path: Path) -> None:
    """Requirement 1: zip bombs (declared or actual decompressed size) and member caps refused."""
    # High-compression payload (~1000:1 deflate ratio) exceeding a bounded cap
    bomb_payload = b"\x00" * (2 * 1024 * 1024)  # 2 MiB of zeros compresses to ~2 KiB
    bomb_zip = _write_zip(
        tmp_path / "bomb.zip",
        [("pkg/zeros.bin", bomb_payload, (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    clean_zip = _write_zip(
        tmp_path / "clean.zip",
        [("pkg/zeros.bin", b"ok", (2024, 1, 1, 0, 0, 0), 0o100644)],
    )

    tight_byte_limits = ResourceLimits(
        max_member_bytes=256 * 1024,
        max_total_decompressed_bytes=512 * 1024,
    )
    rep_bomb = compare_artifacts(bomb_zip, clean_zip, limits=tight_byte_limits)
    assert rep_bomb["verdict"] == "error"
    assert rep_bomb["error"]["type"] == "ResourceLimitError"

    # Also test spoofed small ZipInfo.file_size header where actual stream exceeds cap
    spoofed_path = tmp_path / "spoofed_bomb.zip"
    with zipfile.ZipFile(spoofed_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/spoof.bin", bomb_payload)
    raw_zip_bytes = bytearray(spoofed_path.read_bytes())
    # Patch uncompressed size field in local file header (offset 22..26) to 10 bytes
    struct.pack_into("<I", raw_zip_bytes, 22, 10)
    spoofed_path.write_bytes(bytes(raw_zip_bytes))

    rep_spoof = compare_artifacts(spoofed_path, clean_zip, limits=tight_byte_limits)
    assert rep_spoof["verdict"] == "error"
    assert rep_spoof["error"]["type"] == "ResourceLimitError"

    # Member count cap
    many_zip = _write_zip(
        tmp_path / "many.zip",
        [(f"pkg/f_{i}.py", b"x=1\n", (2024, 1, 1, 0, 0, 0), 0o100644) for i in range(10)],
    )
    rep_many = compare_artifacts(many_zip, clean_zip, limits=ResourceLimits(max_archive_members=5))
    assert rep_many["verdict"] == "error"
    assert rep_many["error"]["type"] == "ResourceLimitError"


def test_path_traversal_members_refused(tmp_path: Path) -> None:
    """Requirement 1: path traversal ('..') and absolute paths in archives refused."""
    clean_zip = _write_zip(
        tmp_path / "clean.zip",
        [("pkg/ok.py", b"x = 1\n", (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    dotdot_zip = _write_zip(
        tmp_path / "dotdot.zip",
        [("../escape.py", b"evil = 1\n", (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    abs_zip = _write_zip(
        tmp_path / "abs.zip",
        [("/etc/passwd", b"root:x:0:0\n", (2024, 1, 1, 0, 0, 0), 0o100644)],
    )
    dotdot_tar = _write_tar(
        tmp_path / "dotdot.tar",
        [("pkg/../../escape.py", b"evil = 1\n", 1_700_000_000, 0o644)],
    )

    for bad_artifact in (dotdot_zip, abs_zip, dotdot_tar):
        rep = compare_artifacts(bad_artifact, clean_zip)
        assert rep["verdict"] == "error"
        assert rep["error"]["type"] == "SecurityViolationError"


def test_tar_symlink_and_non_regular_files_refused(tmp_path: Path) -> None:
    """Requirement 1: tar symlinks, hardlinks, FIFOs, and directory symlinks are refused."""
    clean_tar = _write_tar(
        tmp_path / "clean.tar",
        [("pkg/ok.py", b"x = 1\n", 1_700_000_000, 0o644)],
    )

    # Tar symlink member
    sym_tar = tmp_path / "symlink.tar"
    with tarfile.open(sym_tar, mode="w") as tf:
        ti = tarfile.TarInfo(name="pkg/link.py")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)

    rep_sym = compare_artifacts(sym_tar, clean_tar)
    assert rep_sym["verdict"] == "error"
    assert rep_sym["error"]["type"] == "SecurityViolationError"

    # Tar hardlink member
    hard_tar = tmp_path / "hardlink.tar"
    with tarfile.open(hard_tar, mode="w") as tf:
        ti = tarfile.TarInfo(name="pkg/hard.py")
        ti.type = tarfile.LNKTYPE
        ti.linkname = "pkg/ok.py"
        tf.addfile(ti)

    rep_hard = compare_artifacts(hard_tar, clean_tar)
    assert rep_hard["verdict"] == "error"
    assert rep_hard["error"]["type"] == "SecurityViolationError"

    # Tar FIFO non-regular member
    fifo_tar = tmp_path / "fifo.tar"
    with tarfile.open(fifo_tar, mode="w") as tf:
        ti = tarfile.TarInfo(name="pkg/pipe")
        ti.type = tarfile.FIFOTYPE
        tf.addfile(ti)

    rep_fifo = compare_artifacts(fifo_tar, clean_tar)
    assert rep_fifo["verdict"] == "error"
    assert rep_fifo["error"]["type"] == "SecurityViolationError"

    # Directory containing a symlink
    dir_with_sym = tmp_path / "dir_sym"
    dir_with_sym.mkdir()
    target_file = tmp_path / "outside.txt"
    target_file.write_text("secret", encoding="utf-8")
    os.symlink(target_file, dir_with_sym / "leak.txt")

    rep_dir_sym = compare_artifacts(dir_with_sym, clean_tar)
    assert rep_dir_sym["verdict"] == "error"
    assert rep_dir_sym["error"]["type"] == "SecurityViolationError"


def test_cli_exit_codes_and_determinism(tmp_path: Path) -> None:
    """Requirement 5 & Determinism: CLI exit codes 0/2/1 and byte-for-byte deterministic JSON."""
    whl_1 = _write_zip(
        tmp_path / "a.whl",
        [
            ("pkg/z.py", b"z = 26\n", (2024, 1, 1, 0, 0, 0), 0o100644),
            ("pkg/a.py", b"a = 1\n", (2024, 1, 1, 0, 0, 0), 0o100644),
        ],
    )
    # Reverse member insertion order in archive B
    whl_2 = _write_zip(
        tmp_path / "b.whl",
        [
            ("pkg/a.py", b"a = 1\n", (2025, 5, 5, 5, 5, 5), 0o100644),
            ("pkg/z.py", b"z = 26\n", (2025, 5, 5, 5, 5, 5), 0o100644),
        ],
    )
    whl_diff = _write_zip(
        tmp_path / "diff.whl",
        [
            ("pkg/a.py", b"a = 2\n", (2025, 5, 5, 5, 5, 5), 0o100644),
            ("pkg/only_b.py", b"b = 2\n", (2025, 5, 5, 5, 5, 5), 0o100644),
        ],
    )

    # Exit 0 on identical
    res_ok = subprocess.run(
        [sys.executable, "-m", "hermetic_d7", "--shipped", str(whl_1), "--rebuilt", str(whl_2)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_ok.returncode == 0
    parsed_ok = json.loads(res_ok.stdout)
    assert parsed_ok["verdict"] == "identical"

    # Exit 2 on differs, and repeated runs produce byte-identical JSON
    res_diff_1 = subprocess.run(
        [sys.executable, "-m", "hermetic_d7", "--shipped", str(whl_1), "--rebuilt", str(whl_diff)],
        capture_output=True,
        text=True,
        check=False,
    )
    res_diff_2 = subprocess.run(
        [sys.executable, "-m", "hermetic_d7", "--shipped", str(whl_1), "--rebuilt", str(whl_diff)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_diff_1.returncode == 2
    assert res_diff_2.returncode == 2
    assert res_diff_1.stdout == res_diff_2.stdout
    assert res_diff_1.stdout.strip() == format_report_json(json.loads(res_diff_1.stdout))

    # Exit 1 on error (missing artifact & invalid CLI flags)
    res_missing = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermetic_d7",
            "--shipped",
            str(tmp_path / "nonexistent.whl"),
            "--rebuilt",
            str(whl_1),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_missing.returncode == 1
    assert json.loads(res_missing.stdout)["verdict"] == "error"

    res_bad_cli = subprocess.run(
        [sys.executable, "-m", "hermetic_d7", "--shipped", str(whl_1)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_bad_cli.returncode == 1
    assert json.loads(res_bad_cli.stdout)["verdict"] == "error"




def test_oversized_tar_extended_header_refused(tmp_path: Path) -> None:
    """A pax header larger than the cap is refused before tarfile buffers it."""
    clean_tar = _write_tar(
        tmp_path / "clean.tar",
        [("pkg/ok.py", b"x = 1\n", 1_700_000_000, 0o644)],
    )
    pax_tar = tmp_path / "pax.tar"
    with tarfile.open(pax_tar, mode="w", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo(name="pkg/ok.py")
        ti.size = len(b"x = 1\n")
        ti.mtime = 1_700_000_000
        ti.mode = 0o644
        ti.pax_headers = {"comment": "c" * (2 * 1024 * 1024)}
        tf.addfile(ti, io.BytesIO(b"x = 1\n"))

    report = compare_artifacts(pax_tar, clean_tar)
    assert report["verdict"] == "error"
    assert report["error"]["type"] == "InvalidArtifactError"
    from hermetic_d7.normalise import MAX_TAR_EXTENDED_HEADER_BYTES

    assert MAX_TAR_EXTENDED_HEADER_BYTES < 2 * 1024 * 1024


def test_directory_hardlink_refused(tmp_path: Path) -> None:
    """Hardlinked files in a directory artifact are refused, as documented."""
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("secret\n", encoding="utf-8")
    shipped = tmp_path / "shipped"
    shipped.mkdir()
    os.link(outside, shipped / "leak.txt")
    rebuilt = tmp_path / "rebuilt"
    rebuilt.mkdir()
    (rebuilt / "leak.txt").write_text("other\n", encoding="utf-8")

    report = compare_artifacts(shipped, rebuilt)
    assert report["verdict"] == "error"
    assert report["error"]["type"] == "SecurityViolationError"
    assert "secret" not in format_report_json(report)


def test_directory_member_cap_applies_while_listing(tmp_path: Path) -> None:
    """One directory with more entries than the member cap is refused."""
    shipped = tmp_path / "wide"
    shipped.mkdir()
    for i in range(6):
        (shipped / f"f{i}.txt").write_text("x", encoding="utf-8")
    report = compare_artifacts(shipped, shipped, limits=ResourceLimits(max_archive_members=5))
    assert report["verdict"] == "error"
    assert report["error"]["type"] == "ResourceLimitError"


def test_reports_never_contain_absolute_host_paths(tmp_path: Path) -> None:
    """Reports name inputs by final component and scrub host locations from errors."""
    shipped = tmp_path / "shipped_dir"
    shipped.mkdir()
    os.symlink(tmp_path / "nowhere", shipped / "dangling")
    rebuilt = tmp_path / "rebuilt_dir"
    rebuilt.mkdir()

    error_report = compare_artifacts(shipped, rebuilt)
    assert error_report["verdict"] == "error"
    text = format_report_json(error_report)
    assert str(tmp_path) not in text
    assert error_report["shipped_path"] == "shipped_dir"

    (shipped / "dangling").unlink()
    ok_report = compare_artifacts(shipped, rebuilt)
    assert ok_report["verdict"] == "identical"
    assert str(tmp_path) not in format_report_json(ok_report)
    assert ok_report["rebuilt_path"] == "rebuilt_dir"
