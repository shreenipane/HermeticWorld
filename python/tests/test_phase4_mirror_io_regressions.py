"""Descriptor and staging cleanup on filesystem inspection failures."""

import os

import pytest

from hermetic_ecosystem_cut import CutError, mirror
from tests.test_phase4_mirror import disk_inputs


def test_mirror_directory_inspection_failure_closes_descriptor(tmp_path, monkeypatch):
    (tmp_path / "child").mkdir()
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_open, real_stat = os.open, os.fstat
    opened = []
    def capture(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor
    def fail(descriptor):
        raise OSError("host-secret")
    try:
        with monkeypatch.context() as context:
            context.setattr(mirror.os, "open", capture)
            context.setattr(mirror.os, "fstat", fail)
            with pytest.raises(OSError):
                mirror._directory(parent, "child")
        assert len(opened) == 1
        descriptor = next(iter(opened))
        with pytest.raises(OSError):
            real_stat(descriptor)
    finally:
        for descriptor in opened:
            try:
                real_stat(descriptor)
            except OSError:
                pass
            else:
                os.close(descriptor)
        os.close(parent)


def test_mirror_root_inspection_failure_removes_stage(tmp_path, monkeypatch):
    source, blobs, output = disk_inputs(tmp_path)
    def fail(*args, **kwargs):
        raise OSError("host-secret")
    monkeypatch.setattr(mirror, "_directory", fail)
    with pytest.raises(CutError) as caught:
        mirror.build_mirror_files(source, blobs, output)
    assert "host-secret" not in str(caught.value)
    assert not output.exists()
    assert not list(tmp_path.glob(".mirror-stage-*"))
