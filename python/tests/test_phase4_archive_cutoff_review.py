"""Replay capture admission must be strictly before the world cutoff."""

import pytest

from hermetic_archive import ArchiveError, ReplayIndex, build_replay_index, load_replay_files
from hermetic_archive import formats as f, replay
from tests.test_phase4_archive import URL, capture, recipe


@pytest.mark.parametrize("cutoff,date", [
    ("2023-04-01T00:00:00.000000001Z", "2023-04-01T00:00:00.000000001Z"),
    ("2023-04-01T00:00:00Z", "2023-04-01T00:00:00.000000000Z"),
])
def test_replay_builder_excludes_exact_cutoff_and_timestamp_alias(cutoff, date):
    older = capture(b"older", date="2023-03-31T23:59:59.999999999Z")
    boundary = capture(b"boundary-secret", date=date)
    new_url = capture(b"new-page", date=date, url="https://example.org/new")
    blobs = {f.sha(body): body for body in (b"older", b"boundary-secret", b"new-page")}
    build = build_replay_index(recipe([boundary, new_url, older], cutoff), blobs)
    expected = f.encode(dict(schema=replay.SCHEMA, cutoff=cutoff, captures=[older]))
    assert build.index == expected
    assert build.blobs == ((f.sha(b"older"), b"older"),)
    index = ReplayIndex(build.index, dict(build.blobs), f.sha(build.index), cutoff)
    assert index.lookup(URL).body == b"older"
    assert index.lookup(new_url["url"]) is None


@pytest.mark.parametrize("cutoff,date", [
    ("2023-04-01T00:00:00.000000001Z", "2023-04-01T00:00:00.000000001Z"),
    ("2023-04-01T00:00:00Z", "2023-04-01T00:00:00.000000000Z"),
])
def test_replay_reader_refuses_authenticated_capture_at_cutoff(cutoff, date):
    body = b"boundary-secret"
    raw = f.encode(dict(schema=replay.SCHEMA, cutoff=cutoff,
                        captures=[capture(body, date=date)]))
    with pytest.raises(ArchiveError, match="admission"):
        ReplayIndex(raw, {f.sha(body): body}, f.sha(raw), cutoff)


def test_replay_file_reader_refuses_cutoff_capture_before_reading_payloads(tmp_path, monkeypatch):
    cutoff = "2023-04-01T00:00:00Z"
    raw = f.encode(dict(schema=replay.SCHEMA, cutoff=cutoff,
                        captures=[capture(date=cutoff)]))
    source = tmp_path / "index.json"
    source.write_bytes(raw)
    root = tmp_path / "blobs"
    root.mkdir()
    (root / f.sha(b"admitted")).write_bytes(b"admitted")
    read = replay.read_regular_file_bounded
    calls = []

    def observe(path, cap, **kwargs):
        calls.append(path)
        return read(path, cap, **kwargs)

    monkeypatch.setattr(replay, "read_regular_file_bounded", observe)
    with pytest.raises(ArchiveError):
        load_replay_files(source, root, f.sha(raw), cutoff)
    assert calls == [source]
