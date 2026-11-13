
"""Comprehensive pytest suite for Hermetic World Detector D10."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import zipfile

import pytest

from hermetic_d10 import (
    MAX_DECOMPRESSED_BYTES,
    MAX_NESTING_DEPTH,
    CapExceededError,
    ScanCaps,
    UnsafeFileError,
    scan_file,
    scan_tree,
)
from hermetic_d10.__main__ import main as cli_main

T_CLOCK = datetime(2025, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
T_CLOCK_STR = "2025-05-01T12:00:00Z"


def _make_zip_bytes(
    members: list[tuple[str, bytes, tuple[int, int, int, int, int, int], bytes]],
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    """Build an in-memory ZIP archive with explicit DOS date_time and extra fields."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=compression) as zf:
        for name, payload, dt_tuple, extra in members:
            info = zipfile.ZipInfo(filename=name, date_time=dt_tuple)
            info.extra = extra
            info.compress_type = compression
            zf.writestr(info, payload)
    return buf.getvalue()


def _make_0x5455_extra(mtime_unix: int) -> bytes:
    """Encode an Info-ZIP 0x5455 extended-timestamp extra field with mtime."""
    return struct.pack("<HHBI", 0x5455, 5, 1, mtime_unix)


def _make_tar_bytes(members: list[tuple[str, bytes, int]]) -> bytes:
    """Build an in-memory TAR archive with explicit member mtimes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, payload, mtime in members:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(payload)
            ti.mtime = mtime
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


def _make_gzip_bytes(payload: bytes, mtime_unix: int, fname: bytes | None = None) -> bytes:
    """Build an RFC 1952 GZIP stream with explicit 4-byte header MTIME."""
    raw_gz = gzip.compress(payload, mtime=mtime_unix)
    if fname is None:
        return raw_gz
    # Inject FNAME flag (0x08) and null-terminated filename after the 10-byte header
    header = bytearray(raw_gz[:10])
    header[3] |= 0x08
    return bytes(header) + fname + b"\x00" + raw_gz[10:]


def _make_pyc_bytes(flags: int, ts_or_low32: int, size_or_high32: int = 42) -> bytes:
    """Build a 16-byte PEP 552 .pyc header."""
    magic = b"\xa7\x0d\r\n"
    return magic + struct.pack("<III", flags, ts_or_low32, size_or_high32)


def _dt_to_dos(dt: datetime) -> tuple[int, int, int, int, int, int]:
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


# ---------------------------------------------------------------------------
# Requirement 1 & 4: Every carrier at T_clock (respecting DOS +14h slack) vs +1s
# ---------------------------------------------------------------------------


def test_carrier_zip_dos_timestamp_slack_and_gate(tmp_path: Path) -> None:
    # Exactly at T_clock -> info (pass)
    z_at = tmp_path / "at.zip"
    z_at.write_bytes(
        _make_zip_bytes([("a.txt", b"hi", _dt_to_dos(T_CLOCK), b"")])
    )
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    dos_findings = [f for f in res_at.findings if f.carrier == "zip_dos_timestamp"]
    assert len(dos_findings) == 1
    assert dos_findings[0].severity == "info"
    assert "14h" in dos_findings[0].note

    # Exactly at T_clock + 14h -> still within conservative UTC+14 slack -> info (pass)
    z_at.unlink()
    z_slack = tmp_path / "slack.zip"
    dos_at_slack = T_CLOCK + timedelta(hours=14)
    z_slack.write_bytes(
        _make_zip_bytes([("a.txt", b"hi", _dt_to_dos(dos_at_slack), b"")])
    )
    res_slack = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_slack.verdict == "pass"
    assert res_slack.findings[0].severity == "info"

    # Past T_clock + 14h (DOS has 2-second granularity, so +14h + 2s is the next tick) -> gate
    z_slack.unlink()
    z_gate = tmp_path / "gate.zip"
    dos_over_slack = T_CLOCK + timedelta(hours=14, seconds=2)
    z_gate.write_bytes(
        _make_zip_bytes([("a.txt", b"hi", _dt_to_dos(dos_over_slack), b"")])
    )
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    assert res_gate.findings[0].severity == "gate"
    assert "14h" in res_gate.findings[0].note


def test_carrier_zip_extended_timestamp_0x5455(tmp_path: Path) -> None:
    base_dos = (2020, 1, 1, 0, 0, 0)
    ts_at = int(T_CLOCK.timestamp())

    # At T_clock -> info
    whl_at = tmp_path / "pkg-1.0-py3-none-any.whl"
    whl_at.write_bytes(
        _make_zip_bytes([("mod.py", b"x = 1", base_dos, _make_0x5455_extra(ts_at))])
    )
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    ext_at = [f for f in res_at.findings if f.carrier == "zip_ext_timestamp"]
    assert len(ext_at) == 1
    assert ext_at[0].severity == "info"
    assert ext_at[0].found_date == T_CLOCK_STR

    # 1 second after T_clock -> gate (no +14h slack for UTC Unix timestamps)
    whl_at.write_bytes(
        _make_zip_bytes([("mod.py", b"x = 1", base_dos, _make_0x5455_extra(ts_at + 1))])
    )
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    ext_gate = [f for f in res_gate.findings if f.carrier == "zip_ext_timestamp"]
    assert len(ext_gate) == 1
    assert ext_gate[0].severity == "gate"
    assert ext_gate[0].found_date == "2025-05-01T12:00:01Z"


def test_carrier_tar_mtime(tmp_path: Path) -> None:
    ts_at = int(T_CLOCK.timestamp())
    tar_path = tmp_path / "archive.tar"

    tar_path.write_bytes(_make_tar_bytes([("file.txt", b"hello", ts_at)]))
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    assert len(res_at.findings) == 1
    assert res_at.findings[0].carrier == "tar_mtime"
    assert res_at.findings[0].severity == "info"

    tar_path.write_bytes(_make_tar_bytes([("file.txt", b"hello", ts_at + 1)]))
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    assert res_gate.findings[0].severity == "gate"
    assert res_gate.findings[0].found_date == "2025-05-01T12:00:01Z"


def test_carrier_gzip_mtime(tmp_path: Path) -> None:
    ts_at = int(T_CLOCK.timestamp())
    gz_path = tmp_path / "blob.txt.gz"

    gz_path.write_bytes(_make_gzip_bytes(b"plain text", ts_at))
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    assert len(res_at.findings) == 1
    assert res_at.findings[0].carrier == "gzip_mtime"
    assert res_at.findings[0].severity == "info"

    gz_path.write_bytes(_make_gzip_bytes(b"plain text", ts_at + 1))
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    assert res_gate.findings[0].severity == "gate"
    assert res_gate.findings[0].found_date == "2025-05-01T12:00:01Z"


def test_carrier_wheel_and_egg_metadata_pkg_info(tmp_path: Path) -> None:
    base_dos = (2020, 1, 1, 0, 0, 0)

    # Wheel METADATA at T_clock -> info; description body date ignored
    meta_at = (
        b"Metadata-Version: 2.1\n"
        b"Name: demo-pkg\n"
        b"Version: 1.0.0\n"
        b"Build-Date: 2025-05-01T12:00:00Z\n"
        b"\n"
        b"Release-Date: 2099-01-01T00:00:00Z inside long description body must be ignored.\n"
    )
    whl_path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    whl_path.write_bytes(
        _make_zip_bytes([("demo_pkg-1.0.0.dist-info/METADATA", meta_at, base_dos, b"")])
    )
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    meta_findings = [f for f in res_at.findings if f.carrier == "pkg_metadata"]
    assert len(meta_findings) == 1
    assert meta_findings[0].severity == "info"

    # Egg PKG-INFO 1 second after T_clock -> gate
    pkg_info_gate = (
        b"Metadata-Version: 1.1\n"
        b"Name: egg-pkg\n"
        b"Version: 0.2.0\n"
        b"Date: Thu, 01 May 2025 12:00:01 +0000\n"
    )
    egg_path = tmp_path / "egg_pkg-0.2.0-py3.11.egg"
    egg_path.write_bytes(
        _make_zip_bytes([("EGG-INFO/PKG-INFO", pkg_info_gate, base_dos, b"")])
    )
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    gate_meta = [
        f for f in res_gate.findings if f.carrier == "pkg_metadata" and f.severity == "gate"
    ]
    assert len(gate_meta) == 1
    assert gate_meta[0].found_date == "2025-05-01T12:00:01Z"


def test_carrier_jar_manifest(tmp_path: Path) -> None:
    base_dos = (2020, 1, 1, 0, 0, 0)
    jar_path = tmp_path / "app.jar"

    # At T_clock -> info, plus non-date Created-By ignored
    manifest_at = (
        b"Manifest-Version: 1.0\r\n"
        b"Created-By: 17.0.9 (Oracle Corporation)\r\n"
        b"Build-Date: 2025-05-01T12:00:00Z\r\n"
    )
    jar_path.write_bytes(
        _make_zip_bytes([("META-INF/MANIFEST.MF", manifest_at, base_dos, b"")])
    )
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    mf_findings = [f for f in res_at.findings if f.carrier == "jar_manifest"]
    assert len(mf_findings) == 1
    assert mf_findings[0].severity == "info"

    # Created-By with embedded date 1 second after T_clock -> gate
    manifest_gate = (
        b"Manifest-Version: 1.0\r\n"
        b"Created-By: Apache Maven 3.9.6 (2025-05-01T12:00:01Z)\r\n"
    )
    jar_path.write_bytes(
        _make_zip_bytes([("META-INF/MANIFEST.MF", manifest_gate, base_dos, b"")])
    )
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    mf_gate = [f for f in res_gate.findings if f.carrier == "jar_manifest"]
    assert len(mf_gate) == 1
    assert mf_gate[0].severity == "gate"
    assert mf_gate[0].found_date == "2025-05-01T12:00:01Z"


def test_npm_package_json_out_of_scope(tmp_path: Path) -> None:
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps(
            {
                "name": "left-pad",
                "version": "1.3.0",
                "time": {
                    "created": "2025-05-01T12:00:01Z",
                    "modified": "2026-01-01T00:00:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "pass"
    assert res.findings == []


def test_carrier_pyc_pep552_timestamp_and_hash_modes(tmp_path: Path) -> None:
    ts_at = int(T_CLOCK.timestamp())

    # Timestamp mode (flags == 0) at T_clock -> info
    pyc_at = tmp_path / "mod_at.pyc"
    pyc_at.write_bytes(_make_pyc_bytes(flags=0, ts_or_low32=ts_at))
    res_at = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_at.verdict == "pass"
    assert len(res_at.findings) == 1
    assert res_at.findings[0].carrier == "pyc_timestamp"
    assert res_at.findings[0].severity == "info"

    # Hash mode (flags == 1) with post-cutoff bytes in 8..12 -> MUST be ignored
    pyc_at.unlink()
    pyc_hash = tmp_path / "mod_hash.pyc"
    pyc_hash.write_bytes(_make_pyc_bytes(flags=1, ts_or_low32=ts_at + 9999))
    res_hash = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_hash.verdict == "pass"
    assert res_hash.findings == []

    # Timestamp mode (flags == 0) 1 second after T_clock -> gate
    pyc_hash.unlink()
    pyc_gate = tmp_path / "mod_gate.pyc"
    pyc_gate.write_bytes(_make_pyc_bytes(flags=0, ts_or_low32=ts_at + 1))
    res_gate = scan_tree(tmp_path, T_CLOCK_STR)
    assert res_gate.verdict == "gate"
    assert len(res_gate.findings) == 1
    assert res_gate.findings[0].carrier == "pyc_timestamp"
    assert res_gate.findings[0].severity == "gate"
    assert res_gate.findings[0].found_date == "2025-05-01T12:00:01Z"


# ---------------------------------------------------------------------------
# Requirement 2: Nested archives (zip in tar in gzip) & nesting depth cap
# ---------------------------------------------------------------------------


def test_nested_zip_in_tar_in_gzip(tmp_path: Path) -> None:
    base_ts = int(datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
    post_ts = int((T_CLOCK + timedelta(seconds=1)).timestamp())

    inner_zip = _make_zip_bytes(
        [("deep/payload.txt", b"secret", (2024, 1, 1, 0, 0, 0), _make_0x5455_extra(post_ts))]
    )
    middle_tar = _make_tar_bytes([("sub/inner.zip", inner_zip, base_ts)])
    outer_gz = _make_gzip_bytes(middle_tar, base_ts, fname=b"middle.tar")

    bundle = tmp_path / "bundle.tar.gz"
    bundle.write_bytes(outer_gz)

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "gate"
    gate_findings = [f for f in res.findings if f.severity == "gate"]
    assert len(gate_findings) == 1
    assert gate_findings[0].path == "bundle.tar.gz"
    assert gate_findings[0].member_chain == ["middle.tar", "sub/inner.zip", "deep/payload.txt"]
    assert gate_findings[0].carrier == "zip_ext_timestamp"
    assert gate_findings[0].found_date == "2025-05-01T12:00:01Z"


def test_nesting_depth_cap_refused(tmp_path: Path) -> None:
    assert MAX_NESTING_DEPTH == 3
    # 4 nested zip layers exceeds MAX_NESTING_DEPTH = 3
    layer = b"leaf"
    for idx in range(4):
        layer = _make_zip_bytes([(f"layer{idx}.zip", layer, (2024, 1, 1, 0, 0, 0), b"")])
    deep_zip = tmp_path / "too_deep.zip"
    deep_zip.write_bytes(layer)

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "pass"
    assert any(
        r.error_type == CapExceededError.__name__ and "nesting depth" in r.detail.lower()
        for r in res.refusals
    )


# ---------------------------------------------------------------------------
# Requirement 3: Implausible dates (< 1980-01-01 or > 2100) reported as info
# ---------------------------------------------------------------------------


def test_implausible_dates_not_gated(tmp_path: Path) -> None:
    ts_pre_1980 = int(datetime(1975, 6, 15, 0, 0, 0, tzinfo=timezone.utc).timestamp())
    ts_post_2100 = int(datetime(2105, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())

    tar_bytes = _make_tar_bytes(
        [
            ("ancient.txt", b"old", ts_pre_1980),
            ("future.txt", b"far", ts_post_2100),
        ]
    )
    (tmp_path / "dates.tar").write_bytes(tar_bytes)

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "pass"
    assert len(res.findings) == 2
    for finding in res.findings:
        assert finding.severity == "info"
        assert finding.implausible is True
        assert "implausible" in finding.note.lower()


# ---------------------------------------------------------------------------
# Caps, Symlinks Refused, Zip Bomb Refused, Determinism, and CLI Exit Codes
# ---------------------------------------------------------------------------


def test_symlinks_and_non_regular_files_refused(tmp_path: Path) -> None:
    # Create an outside file with a post-cutoff date that must never be followed
    outside = tmp_path / "outside"
    outside.mkdir()
    post_ts = int((T_CLOCK + timedelta(hours=5)).timestamp())
    secret_tar = outside / "secret.tar"
    secret_tar.write_bytes(_make_tar_bytes([("leak.txt", b"leak", post_ts)]))

    scan_root = tmp_path / "world"
    scan_root.mkdir()
    os.symlink(secret_tar, scan_root / "link_to_secret.tar")

    res = scan_tree(scan_root, T_CLOCK_STR)
    assert res.verdict == "pass"
    assert res.findings == []
    assert any(
        r.path == "link_to_secret.tar"
        and r.error_type == UnsafeFileError.__name__
        and r.reason == "symlink_refused"
        for r in res.refusals
    )

    # Calling scan_file directly on a symlink must raise UnsafeFileError
    with pytest.raises(UnsafeFileError):
        scan_file(scan_root / "link_to_secret.tar", T_CLOCK_STR)


def test_zip_bomb_refused(tmp_path: Path) -> None:
    # 33 MiB of zeros compresses down to ~33 KiB, exceeding default MAX_DECOMPRESSED_BYTES (32 MiB)
    uncompressed_size = MAX_DECOMPRESSED_BYTES + (1024 * 1024)
    bomb_payload = b"\x00" * uncompressed_size
    bomb_zip = _make_zip_bytes(
        [("bomb.bin", bomb_payload, (2024, 1, 1, 0, 0, 0), b"")],
        compression=zipfile.ZIP_DEFLATED,
    )
    assert len(bomb_zip) < 100_000  # Small compressed size on disk
    bomb_path = tmp_path / "bomb.zip"
    bomb_path.write_bytes(bomb_zip)

    with pytest.raises(CapExceededError):
        scan_file(bomb_path, T_CLOCK_STR)

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.has_cap_error() is True
    assert any(
        r.path == "bomb.zip" and r.error_type == CapExceededError.__name__
        for r in res.refusals
    )

    # CLI exits 1 on zip bomb cap violation
    exit_code = cli_main(["--root", str(tmp_path), "--t-clock", T_CLOCK_STR])
    assert exit_code == 1


def test_file_and_member_caps(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.pyc").write_bytes(_make_pyc_bytes(0, int(T_CLOCK.timestamp())))

    res = scan_tree(tmp_path, T_CLOCK_STR, caps=ScanCaps(max_files=2))
    assert res.has_cap_error() is True
    assert res.files_scanned == 2
    assert any(r.reason == "max_files_exceeded" for r in res.refusals)


def test_deterministic_output_and_sorting(tmp_path: Path) -> None:
    ts_at = int(T_CLOCK.timestamp())
    (tmp_path / "z_last.tar").write_bytes(_make_tar_bytes([("b.txt", b"1", ts_at), ("a.txt", b"2", ts_at)]))
    (tmp_path / "a_first.gz").write_bytes(_make_gzip_bytes(b"hello", ts_at))

    out1 = scan_tree(tmp_path, T_CLOCK_STR).to_json()
    out2 = scan_tree(tmp_path, T_CLOCK_STR).to_json()
    assert out1 == out2

    parsed = json.loads(out1)
    keys = [(f["path"], f["member_chain"], f["carrier"]) for f in parsed["findings"]]
    assert keys == sorted(keys)


def test_cli_exit_codes_pass_gate_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ts_at = int(T_CLOCK.timestamp())
    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "ok.pyc").write_bytes(_make_pyc_bytes(0, ts_at))

    # Exit 0 on pass
    rc_pass = cli_main(["--root", str(clean_dir), "--t-clock", T_CLOCK_STR])
    assert rc_pass == 0
    payload_pass = json.loads(capsys.readouterr().out)
    assert payload_pass["verdict"] == "pass"

    # Exit 2 on gate
    gate_dir = tmp_path / "gated"
    gate_dir.mkdir()
    (gate_dir / "post.pyc").write_bytes(_make_pyc_bytes(0, ts_at + 1))
    rc_gate = cli_main(["--root", str(gate_dir), "--t-clock", T_CLOCK_STR])
    assert rc_gate == 2
    payload_gate = json.loads(capsys.readouterr().out)
    assert payload_gate["verdict"] == "gate"

    # Exit 1 on invalid --t-clock or missing --root
    rc_bad_clock = cli_main(["--root", str(clean_dir), "--t-clock", "not-a-timestamp"])
    assert rc_bad_clock == 1
    capsys.readouterr()

    rc_missing_root = cli_main(["--root", str(tmp_path / "does_not_exist"), "--t-clock", T_CLOCK_STR])
    assert rc_missing_root == 1
    capsys.readouterr()

    # Subprocess smoke test of `python -m hermetic_d10`
    proc = subprocess.run(
        [sys.executable, "-m", "hermetic_d10", "--root", str(gate_dir), "--t-clock", T_CLOCK_STR],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["verdict"] == "gate"




# ---------------------------------------------------------------------------
# Review regressions: hostile inputs, fail-closed CLI, and carrier coverage
# ---------------------------------------------------------------------------


def test_tar_with_unrepresentable_pax_mtime_is_refused_not_crash(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo(name="a.txt")
        ti.size = 1
        ti.pax_headers = {"mtime": "1e300"}
        tf.addfile(ti, io.BytesIO(b"x"))
    (tmp_path / "huge.tar").write_bytes(buf.getvalue())

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert not res.is_complete()
    assert any(r.path == "huge.tar" for r in res.refusals)
    assert cli_main(["--root", str(tmp_path), "--t-clock", T_CLOCK_STR]) == 1


@pytest.mark.parametrize(
    "date_value",
    ["Fri, 31 Dec 9999 23:59:59 -1400", "9999-12-31T23:59:59-14:00"],
)
def test_metadata_date_overflow_does_not_crash(tmp_path: Path, date_value: str) -> None:
    (tmp_path / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: x\nBuild-Date: {date_value}\n\n", encoding="utf-8"
    )
    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.refusals == []


def test_unsupported_zip_compression_is_refusal_and_cli_fails_closed(tmp_path: Path) -> None:
    data = bytearray(
        _make_zip_bytes([("a.txt", b"hi", (2020, 1, 1, 0, 0, 0), b"")], zipfile.ZIP_STORED)
    )
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, local + 8, 99)
    struct.pack_into("<H", data, central + 10, 99)
    (tmp_path / "odd.zip").write_bytes(bytes(data))

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert any(r.path == "odd.zip" for r in res.refusals)
    assert not res.is_complete()
    assert cli_main(["--root", str(tmp_path), "--t-clock", T_CLOCK_STR]) == 1


def test_malformed_archive_makes_cli_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "broken.zip").write_bytes(b"this is not a zip archive at all")
    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "pass"
    assert res.to_dict()["complete"] is False
    assert cli_main(["--root", str(tmp_path), "--t-clock", T_CLOCK_STR]) == 1


def test_zip_local_header_dos_time_differing_from_central_is_gated(tmp_path: Path) -> None:
    data = bytearray(_make_zip_bytes([("a.txt", b"hi", (2020, 1, 1, 0, 0, 0), b"")]))
    local = data.find(b"PK\x03\x04")
    post = T_CLOCK + timedelta(days=30)
    dos_time = (post.hour << 11) | (post.minute << 5) | (post.second // 2)
    dos_date = ((post.year - 1980) << 9) | (post.month << 5) | post.day
    struct.pack_into("<HH", data, local + 10, dos_time, dos_date)
    (tmp_path / "local.zip").write_bytes(bytes(data))

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "gate"
    assert any(f.carrier == "zip_local_dos_timestamp" and f.severity == "gate" for f in res.findings)


def test_zip_local_only_extended_atime_is_gated(tmp_path: Path) -> None:
    at = int(T_CLOCK.timestamp())
    post = at + 86_400
    local_extra = struct.pack("<HHBII", 0x5455, 9, 0x03, at, post)
    data = bytearray(_make_zip_bytes([("a.txt", b"hi", (2020, 1, 1, 0, 0, 0), local_extra)]))
    central = data.find(b"PK\x01\x02")
    central_extra_at = data.find(local_extra, central)
    assert central_extra_at > central
    # Central copy keeps only an at-cutoff atime: the post-cutoff value lives in the local header.
    struct.pack_into("<I", data, central_extra_at + 9, at)
    (tmp_path / "ut.zip").write_bytes(bytes(data))

    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "gate"
    assert any(
        f.carrier == "zip_ext_timestamp_atime" and f.severity == "gate" for f in res.findings
    )


def test_zip_ntfs_extra_timestamp_is_gated(tmp_path: Path) -> None:
    post = T_CLOCK + timedelta(days=2)
    filetime = (int(post.timestamp()) + 11_644_473_600) * 10_000_000
    ntfs = struct.pack("<HHIHHQQQ", 0x000A, 32, 0, 0x0001, 24, filetime, filetime, filetime)
    (tmp_path / "ntfs.zip").write_bytes(
        _make_zip_bytes([("a.txt", b"hi", (2020, 1, 1, 0, 0, 0), ntfs)])
    )
    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "gate"
    assert any(f.carrier == "zip_ntfs_mtime" and f.severity == "gate" for f in res.findings)


def test_prefixed_zip_such_as_zipapp_is_inspected(tmp_path: Path) -> None:
    post = T_CLOCK + timedelta(days=3)
    payload = b"#!/usr/bin/env python3\n" + _make_zip_bytes(
        [("__main__.py", b"print(1)", _dt_to_dos(post), b"")]
    )
    (tmp_path / "tool.pyz").write_bytes(payload)
    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "gate"


def test_concatenated_bz2_streams_are_all_scanned(tmp_path: Path) -> None:
    import bz2

    post_ts = int((T_CLOCK + timedelta(days=5)).timestamp())
    at_ts = int(T_CLOCK.timestamp())
    tar_bytes = _make_tar_bytes([("first.txt", b"a" * 600, at_ts), ("second.txt", b"b", post_ts)])
    split = 512 + 1024  # header + padded data of the first member
    assert tar_bytes[split + 257 : split + 262] == b"ustar"
    (tmp_path / "multi.tar.bz2").write_bytes(
        bz2.compress(tar_bytes[:split]) + bz2.compress(tar_bytes[split:])
    )
    res = scan_tree(tmp_path, T_CLOCK_STR)
    assert res.verdict == "gate"
    assert any(f.member_chain[-1] == "second.txt" for f in res.findings if f.severity == "gate")


def test_directory_entry_cap_is_a_refusal(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x", encoding="utf-8")
    res = scan_tree(tmp_path, T_CLOCK_STR, caps=ScanCaps(max_dir_entries=3))
    assert any(r.reason == "max_dir_entries_exceeded" for r in res.refusals)
    assert res.has_cap_error()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_refusal_details_never_contain_host_paths(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(locked, 0)
    try:
        res = scan_tree(tmp_path, T_CLOCK_STR)
    finally:
        os.chmod(locked, 0o755)
    assert any(r.reason == "directory_unreadable" for r in res.refusals)
    assert str(tmp_path) not in res.to_json()


def test_regression_multistream_bz2_beyond_first_chunk_is_fully_decompressed() -> None:
    import bz2

    from hermetic_d10.carriers import _decompress_bz2_bounded

    first = bz2.compress(b"A" * 100)
    second = bz2.compress(os.urandom(4096))
    third = bz2.compress(b"third-stream")
    data = first + second + third
    caps = ScanCaps(read_chunk_size=64)
    out = _decompress_bz2_bounded(data, caps)
    assert out == bz2.decompress(data)


def test_regression_multistream_xz_stream_ending_at_chunk_boundary_is_not_skipped() -> None:
    import lzma

    from hermetic_d10.carriers import _decompress_xz_bounded

    first = lzma.compress(b"first")
    second = lzma.compress(b"second-stream")
    caps = ScanCaps(read_chunk_size=len(first))
    out = _decompress_xz_bounded(first + second, caps)
    assert out == b"firstsecond-stream"


def test_regression_gzip_decompression_cap_is_archive_wide() -> None:
    from hermetic_d10.carriers import CapExceededError, inspect_gzip_bytes

    stream = gzip.compress(b"\x00" * 600, mtime=0)
    caps = ScanCaps(max_decompressed_bytes=1000)
    clock = datetime(2025, 5, 1, tzinfo=timezone.utc)
    # One stream fits within the cap; two streams together exceed it.
    inspect_gzip_bytes("a.gz", "a.gz", [], stream, clock, caps, 0)
    with pytest.raises(CapExceededError):
        inspect_gzip_bytes("a.gz", "a.gz", [], stream + stream, clock, caps, 0)
