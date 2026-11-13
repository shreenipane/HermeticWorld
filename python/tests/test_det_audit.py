"""Regression coverage for detector audit boundaries and WARC capture times."""

import gzip
import json
import os
from pathlib import Path
import zipfile

import pytest

from hermetic_d10 import CapExceededError, MalformedArchiveError, ScanCaps, scan_file, scan_tree
from hermetic_d10.__main__ import main
from hermetic_d10 import InvalidTimestampError, parse_rfc3339_utc
from hermetic_d7 import compare_artifacts
from hermetic_d7.normalise import ResourceLimitError, ResourceLimits
import hermetic_d7.normalise as d7
import hermetic_safe_io

CLOCK = "2025-05-01T00:00:00Z"


def warc(date: bytes = b"2025-05-01T00:00:01Z", payload: bytes = b"body", extra: bytes = b"") -> bytes:
    return (b"WARC/1.1\r\nWARC-Type: response\r\nWARC-Date: " + date
            + b"\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n"
            + extra + b"\r\n" + payload + b"\r\n\r\n")


def test_warc_capture_known_answer_all_records_and_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "capture.warc"
    path.write_bytes(warc(b"2025-05-01T00:00:00Z") + warc())
    result = scan_tree(tmp_path, CLOCK)
    assert result.is_complete() and result.verdict == "gate"
    assert [f.to_dict() for f in result.findings] == [
        {"path": "capture.warc", "member_chain": ["<warc:1>"], "carrier": "warc_date",
         "found_date": CLOCK, "severity": "info", "implausible": False, "note": ""},
        {"path": "capture.warc", "member_chain": ["<warc:2>"], "carrier": "warc_date",
         "found_date": "2025-05-01T00:00:01Z", "severity": "gate", "implausible": False, "note": ""},
    ]
    assert result.to_json() == scan_tree(tmp_path, CLOCK).to_json()


@pytest.mark.parametrize("date", [b"2025-05-01T00:00:00.000001Z", b"2200-01-01T00:00:00Z"])
def test_warc_late_dates_always_gate(tmp_path: Path, date: bytes) -> None:
    path = tmp_path / "capture.warc"
    path.write_bytes(warc(date))
    assert scan_file(path, CLOCK)[0].severity == "gate"


def test_warc_content_length_with_leading_zeros_is_framed(tmp_path: Path) -> None:
    path = tmp_path / "capture.warc"
    path.write_bytes(warc().replace(b"Content-Length: 4", b"Content-Length: 000004"))
    assert scan_file(path, CLOCK)[0].severity == "gate"


def test_warc_nested_gzip_and_opaque_payload(tmp_path: Path) -> None:
    path = tmp_path / "capture.warc.gz"
    # A header-looking string in a payload is not a record header.
    path.write_bytes(gzip.compress(warc(b"2024-01-01T00:00:00Z", warc()), mtime=0))
    findings = scan_file(path, CLOCK)
    assert len(findings) == 1 and findings[0].severity == "info"
    path.write_bytes(gzip.compress(warc(), mtime=0))
    assert scan_file(path, CLOCK)[0].severity == "gate"


@pytest.mark.parametrize("data", [
    b"", b"WARC/1.1\r\n", warc()[:-1], warc() + b"junk",
    warc(b"invalid SECRET"), warc(b"2025-05-01"), warc(b"2025-05-01T00:00:00"),
    warc(extra=b"warc-date: 2024-01-01T00:00:00Z\r\n"),
    warc(extra=b"Content-Length: 0\r\n"),
    warc().replace(b"Content-Length: 4", b"Content-Length: 999999999999999999999999"),
    warc().replace(b"WARC-Date:", b"Missing-Date:"),
    warc().replace(b"WARC-Date:", b" WARC-Date:"),
])
def test_warc_malformed_fails_closed_without_payload_in_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], data: bytes,
) -> None:
    path = tmp_path / "capture.warc"
    path.write_bytes(data)
    with pytest.raises(MalformedArchiveError):
        scan_file(path, CLOCK)
    assert main(["--root", str(tmp_path), "--t-clock", CLOCK]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["complete"] is False
    assert "SECRET" not in json.dumps(result)


def test_warc_caps_are_shared_and_exact(tmp_path: Path) -> None:
    path = tmp_path / "capture.warc"
    path.write_bytes(warc() + warc())
    with pytest.raises(CapExceededError):
        scan_file(path, CLOCK, caps=ScanCaps(max_archive_members=1))
    assert len(scan_file(path, CLOCK, caps=ScanCaps(max_archive_members=2))) == 2
    for caps in [ScanCaps(max_metadata_bytes=16), ScanCaps(max_metadata_lines=2)]:
        with pytest.raises(CapExceededError):
            scan_file(path, CLOCK, caps=caps)


@pytest.mark.parametrize("caps_type,error", [(ScanCaps, CapExceededError), (ResourceLimits, ResourceLimitError)])
def test_invalid_read_caps_rejected(caps_type, error) -> None:
    for value in (0, -1, False, "100"):
        with pytest.raises(error):
            caps_type(read_chunk_size=value)


def test_d10_overflowing_cutoff_is_a_typed_error() -> None:
    with pytest.raises(InvalidTimestampError):
        parse_rfc3339_utc("9999-12-31T23:59:59-01:00")


@pytest.mark.parametrize("detector", ["d7", "d10"])
def test_detector_directory_swap_never_lists_external_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, detector: str,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child"
    child.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SECRET.warc").write_bytes(warc())
    original = hermetic_safe_io.scandir
    swapped = False

    def swap(path):
        nonlocal swapped
        if Path(path) == child and not swapped:
            swapped = True
            child.rmdir()
            child.symlink_to(outside, target_is_directory=True)
        return original(path)

    monkeypatch.setattr(hermetic_safe_io, "scandir", swap)
    if detector == "d7":
        result = compare_artifacts(root, root)
        assert result["verdict"] == "error"
    else:
        result = scan_tree(root, CLOCK).to_dict()
        assert result["complete"] is False
    assert swapped
    assert "SECRET" not in json.dumps(result)


def test_d7_archive_swap_is_refused_before_parser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "input.zip"
    external = tmp_path / "external.zip"
    for path in (archive, external):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("payload", b"content")
    original = hermetic_safe_io.open_regular

    def swap(path, cap):
        if Path(path) == archive:
            archive.unlink()
            archive.symlink_to(external)
        return original(path, cap)

    monkeypatch.setattr(hermetic_safe_io, "open_regular", swap)
    assert compare_artifacts(archive, external)["verdict"] == "error"
    assert archive.is_symlink()


def test_d7_archive_input_cap_and_expanded_tar_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(d7, "MAX_ARTIFACT_BYTES", 1024)
    path = tmp_path / "input.tar.gz"
    path.write_bytes(gzip.compress(b"\0" * 2048, mtime=0))
    assert compare_artifacts(path, path)["verdict"] == "error"
    path = tmp_path / "input.zip"
    path.write_bytes(b"A" * 1025)
    assert compare_artifacts(path, path)["verdict"] == "error"


def test_d7_hardlinked_archive_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "input.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("payload", b"content")
    os.link(path, tmp_path / "alias.zip")
    assert compare_artifacts(path, path)["verdict"] == "error"


def test_d10_failed_growing_reads_consume_total_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("a", "b", "c"):
        (tmp_path / name).write_bytes(b"A")
    original = hermetic_safe_io.open_regular
    opened = []

    def grow(path, cap):
        fd = original(path, cap)
        opened.append(Path(path).name)
        with Path(path).open("ab") as stream:
            stream.write(b"BCDE")
        return fd

    monkeypatch.setattr(hermetic_safe_io, "open_regular", grow)
    result = scan_tree(tmp_path, CLOCK, caps=ScanCaps(max_file_bytes=4, max_total_bytes_read=4))
    assert not result.is_complete()
    assert result.has_cap_error()
    assert opened == ["a"]
    assert result.bytes_read == 5  # four allowed bytes plus the bounded overflow probe
