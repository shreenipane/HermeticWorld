"""Retained input inventories must satisfy their count caps before processing."""

import builtins
import hashlib

import pytest

from hermetic_archive import formats
from hermetic_ecosystem_cut import cut, mirror
from tests.test_ecosystem_cut import CUTOFF, info
from tests.test_phase4_mirror import encoded


def grow_after_count(monkeypatch, module, mapping, extra):
    changed = []

    def count(value):
        result = builtins.len(value)
        if value is mapping and not changed:
            # Schedule a caller between the initial guard and its private copy.
            changed.append(True)
            mapping.update(extra)
        return result

    monkeypatch.setattr(module, "len", count, raising=False)
    return changed


def test_archive_retained_payload_count_is_capped_before_hashing(monkeypatch):
    bodies = (b"first", b"second")
    extra = {hashlib.sha256(body).hexdigest(): body for body in bodies}
    blobs = {}
    changed = grow_after_count(monkeypatch, formats, blobs, extra)
    monkeypatch.setattr(formats, "MAX_RECORDS", 1)
    hashed = []
    digest = formats.sha

    def observe(body):
        hashed.append(body)
        return digest(body)

    monkeypatch.setattr(formats, "sha", observe)
    with pytest.raises(formats.ArchiveError):
        formats.payloads(blobs, set(extra))
    assert changed and not hashed


def test_mirror_retained_blob_count_is_capped_before_hashing(monkeypatch):
    extra = {hashlib.sha256(body).hexdigest(): body for body in (b"first", b"second")}
    blobs = {}
    changed = grow_after_count(monkeypatch, mirror, blobs, extra)
    monkeypatch.setattr(mirror, "MAX_BLOBS", 1)
    hashed = []
    digest = mirror._sha

    def observe(body):
        hashed.append(body)
        return digest(body)

    monkeypatch.setattr(mirror, "_sha", observe)
    with pytest.raises(cut.CutError):
        mirror.build_mirror(encoded(dict(cutoff=CUTOFF, packages=[])), blobs)
    assert changed and not hashed


def test_go_retained_info_count_is_capped_before_validation(monkeypatch):
    infos = {}
    extra = {version: info(version) for version in ("v1.0.0", "v1.1.0")}
    changed = grow_after_count(monkeypatch, cut, infos, extra)
    monkeypatch.setattr(cut, "MAX_RECORDS", 1)
    validated = []
    version = cut._version

    def observe(value, **kwargs):
        validated.append(value)
        return version(value, **kwargs)

    monkeypatch.setattr(cut, "_version", observe)
    with pytest.raises(cut.CutError):
        cut.cut_go_versions(b"", infos, CUTOFF)
    assert changed and not validated
