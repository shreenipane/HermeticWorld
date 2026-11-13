"""Aggregate resource limits for one D10 input, including nested carriers."""

import bz2
from datetime import datetime, timezone
import gzip
import io
import json
import lzma
from pathlib import Path
import tarfile
import zipfile
import zlib

import pytest

from hermetic_d10 import CapExceededError, ScanCaps, scan_file, scan_tree
from hermetic_d10.__main__ import main
from hermetic_d10.carriers import inspect_payload_bytes


CLOCK = datetime(2025, 5, 1, tzinfo=timezone.utc)
KINDS = ("zip", "tar", "gzip", "bz2", "xz")


def _wrap(kind: str, payload: bytes) -> bytes:
    if kind == "gzip":
        return gzip.compress(payload, mtime=0)
    if kind == "bz2":
        return bz2.compress(payload)
    if kind == "xz":
        return lzma.compress(payload)
    buf = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo("payload", date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    else:
        assert kind == "tar"
        with tarfile.open(fileobj=buf, mode="w") as archive:
            info = tarfile.TarInfo("payload")
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _inspect(data: bytes, caps: ScanCaps) -> list:
    return inspect_payload_bytes("input", "input", [], data, CLOCK, caps, 0)


@pytest.mark.parametrize("outer", KINDS)
@pytest.mark.parametrize("inner", KINDS)
def test_nested_carriers_share_byte_budget(outer: str, inner: str) -> None:
    leaf = b"A" * 12_000
    nested = _wrap(inner, leaf)
    data = _wrap(outer, nested)
    total = len(nested) + len(leaf)
    # Every layer fits independently, but their aggregate output exceeds the cap.
    assert max(len(nested), len(leaf)) < total - 1
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_decompressed_bytes=total - 1))
    # An exact aggregate budget remains usable and is fresh for each top-level call.
    caps = ScanCaps(max_decompressed_bytes=total)
    assert _inspect(data, caps) == _inspect(data, caps)


def test_gzip_in_tar_in_gzip_bomb_is_an_incomplete_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    leaf = b"A" * 12_000
    inner = _wrap("gzip", leaf)
    middle = _wrap("tar", inner)
    path = tmp_path / "bomb.gz"
    path.write_bytes(_wrap("gzip", middle))
    cap = len(middle) + len(inner) + len(leaf) - 1
    assert max(len(middle), len(inner), len(leaf)) < cap
    caps = ScanCaps(max_decompressed_bytes=cap)
    with pytest.raises(CapExceededError):
        scan_file(path, CLOCK, caps=caps)
    result = scan_tree(tmp_path, CLOCK, caps=caps)
    assert result.has_cap_error()
    assert not result.is_complete()
    assert main([
        "--root", str(tmp_path), "--t-clock", "2025-05-01T00:00:00Z",
        "--max-decompressed-bytes", str(cap),
    ]) == 1
    assert json.loads(capsys.readouterr().out)["complete"] is False


@pytest.mark.parametrize("outer", KINDS)
@pytest.mark.parametrize("inner", KINDS)
def test_nested_carriers_share_member_and_stream_budget(outer: str, inner: str) -> None:
    data = _wrap(outer, _wrap(inner, b""))
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_archive_members=1))
    _inspect(data, ScanCaps(max_archive_members=2))


@pytest.mark.parametrize("kind", ("gzip", "bz2", "xz"))
def test_concatenated_streams_share_member_budget(kind: str) -> None:
    data = _wrap(kind, b"") + _wrap(kind, b"")
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_archive_members=1))
    _inspect(data, ScanCaps(max_archive_members=2))


@pytest.mark.parametrize("kind", ("gzip", "bz2", "xz"))
@pytest.mark.parametrize("chunk_size", (1, 65_536))
def test_exact_byte_limit_allows_trailers_and_empty_streams(kind: str, chunk_size: int) -> None:
    data = _wrap(kind, b"leaf") + _wrap(kind, b"")
    assert _inspect(data, ScanCaps(max_decompressed_bytes=4, read_chunk_size=chunk_size)) == []
    assert _inspect(_wrap(kind, b""), ScanCaps(max_decompressed_bytes=0)) == []
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_decompressed_bytes=3, read_chunk_size=chunk_size))


@pytest.mark.parametrize("kind", ("gzip", "bz2", "xz"))
def test_stream_siblings_and_their_children_share_budget(kind: str) -> None:
    leaf = b"A" * 1000
    nested = _wrap("gzip", leaf)
    data = _wrap(kind, nested) + _wrap(kind, nested)
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_archive_members=3))
    total = 2 * (len(nested) + len(leaf))
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_decompressed_bytes=total - 1))
    assert _inspect(data, ScanCaps(max_archive_members=4, max_decompressed_bytes=total)) == []


def test_prefixed_nested_zip_shares_budget() -> None:
    leaf = b"A" * 1000
    nested = b"#!/usr/bin/env python3\n" + _wrap("zip", leaf)
    data = _wrap("gzip", nested)
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_decompressed_bytes=len(nested) + len(leaf) - 1))
    with pytest.raises(CapExceededError):
        _inspect(data, ScanCaps(max_archive_members=1))


def test_budget_is_fresh_for_each_file_in_a_tree(tmp_path: Path) -> None:
    leaf = b"leaf"
    inner = _wrap("gzip", leaf)
    data = _wrap("gzip", inner)
    (tmp_path / "a.gz").write_bytes(data)
    (tmp_path / "b.gz").write_bytes(data)
    caps = ScanCaps(max_archive_members=2, max_decompressed_bytes=len(inner) + len(leaf))
    result = scan_tree(tmp_path, CLOCK, caps=caps)
    assert result.is_complete()
    assert result.files_scanned == 2
    assert result.to_json() == scan_tree(tmp_path, CLOCK, caps=caps).to_json()


@pytest.mark.parametrize("kind", KINDS)
def test_deep_nesting_refused_before_opening_excess_layer(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = b"leaf"
    for _ in range(5):
        data = _wrap(kind, data)
    module, name = {
        "zip": (zipfile, "ZipFile"),
        "tar": (tarfile, "open"),
        "gzip": (zlib, "decompressobj"),
        "bz2": (bz2, "BZ2Decompressor"),
        "xz": (lzma, "LZMADecompressor"),
    }[kind]
    original = getattr(module, name)
    opened = []

    def counted(*args, **kwargs):
        opened.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, counted)
    with pytest.raises(CapExceededError, match="nesting depth"):
        _inspect(data, ScanCaps(max_nesting_depth=3))
    assert len(opened) == 3
