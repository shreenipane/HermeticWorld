"""The authenticated mirror must cover the exact returned file inventory."""

import builtins

import pytest

from hermetic_ecosystem_cut import CutError, mirror
from tests.test_phase4_publication_review import bundle, verify


@pytest.mark.parametrize("path", ["unlisted", "../outside"])
def test_mirror_inventory_growth_before_capture_is_refused(monkeypatch, path):
    build = bundle()
    files = dict(build.files)
    changed = False

    def grow_after_inventory_count(value):
        nonlocal changed
        count = builtins.len(value)
        if value is files and not changed:
            # Schedule a caller mutation after the count used for validation,
            # before the verifier captures its private mapping.
            changed = True
            files[path] = b"unverified"
        return count

    monkeypatch.setattr(mirror, "len", grow_after_inventory_count, raising=False)
    with pytest.raises(CutError, match="inventory"):
        verify(build, files=files)
    assert changed
