"""Consumers must use the immutable bytes whose digests they actually checked."""

import pytest

from hermetic_archive import ReplayIndex, build_replay_index, build_search_index
from hermetic_archive import formats as f
from hermetic_ecosystem_cut import mirror
from tests.test_phase4_archive import CUTOFF, URL, capture, recipe as replay_recipe
from tests.test_phase4_mirror import BODY, CUTOFF as MIRROR_CUTOFF, encoded, fixture, go_only
from tests.test_phase4_search import document, recipe as search_recipe


@pytest.mark.parametrize("consumer", ["replay-build", "replay-read", "search-build"])
def test_archive_consumes_verified_payloads_when_source_mapping_changes(monkeypatch, consumer):
    body = b"admitted"
    key = f.sha(body)
    blobs = {key: body}
    if consumer == "search-build":
        raw = search_recipe([document(body, title="")])
        expected = build_search_index(raw, blobs)
    else:
        raw = replay_recipe([capture(body)])
        expected = build_replay_index(raw, blobs)
    digest = f.sha
    changed = False

    def substitute_after_hash(content):
        nonlocal changed
        result = digest(content)
        if content is body and not changed:
            changed = True
            blobs[key] = b"injected"
        return result

    monkeypatch.setattr(f, "sha", substitute_after_hash)
    if consumer == "replay-build":
        assert build_replay_index(raw, blobs) == expected
    elif consumer == "replay-read":
        index = ReplayIndex(expected.index, blobs, digest(expected.index), CUTOFF)
        assert index.lookup(URL).body is body
    else:
        assert build_search_index(raw, blobs) == expected
    assert changed and blobs[key] == b"injected"


def test_mirror_build_consumes_verified_blobs_when_source_mapping_changes(monkeypatch):
    recipe, blobs = go_only([("v1.0.0", MIRROR_CUTOFF)])
    raw = encoded(recipe)
    expected = mirror.build_mirror(raw, blobs)
    digest = mirror._sha
    changed = False

    def substitute_after_hash(content):
        nonlocal changed
        result = digest(content)
        if content is BODY and not changed:
            changed = True
            blobs[result] = b"unverified artifact"
        return result

    monkeypatch.setattr(mirror, "_sha", substitute_after_hash)
    assert mirror.build_mirror(raw, blobs) == expected
    assert changed and blobs[digest(BODY)] == b"unverified artifact"


def test_mirror_verifier_returns_verified_files_when_source_mapping_changes(monkeypatch):
    recipe, blobs = fixture()
    expected = mirror.build_mirror(encoded(recipe), blobs)
    files = dict(expected.files)
    path, body = next(iter(expected.files))
    digest = mirror._sha
    changed = False

    def substitute_after_hash(content):
        nonlocal changed
        result = digest(content)
        if content is body and not changed:
            changed = True
            files[path] = b"!" * len(body)
        return result

    monkeypatch.setattr(mirror, "_sha", substitute_after_hash)
    verified = mirror.verify_mirror(expected.manifest, files, expected.reports,
                                    digest(expected.manifest), MIRROR_CUTOFF)
    assert verified == expected
    assert changed and files[path] != body
