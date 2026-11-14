"""Offline replay admission, exact lookup, authentication and hostile I/O."""

import json
import os

import pytest

from hermetic_archive import ArchiveError, ReplayIndex, build_replay_index, load_replay_files
from hermetic_archive import formats as f, replay

CUTOFF = "2023-04-01T00:00:00.000000001Z"
URL = "https://example.org/article?a=1"


def capture(body=b"admitted", date=CUTOFF, url=URL, **updates):
    entry = dict(url=url, captured=date, source="wayback", record_sha256="a" * 64,
                 payload_sha256=f.sha(body), size=len(body), status=200,
                 content_type="text/html; charset=utf-8", location=None)
    entry.update(updates)
    return entry


def recipe(entries, cutoff=CUTOFF):
    return f.encode(dict(schema="hermetic-replay-recipe/v1", cutoff=cutoff, captures=entries))


def fixture():
    entries = [capture(b"older", "2023-03-01T00:00:00Z"), capture(),
               capture(b"future-secret", "2023-04-01T00:00:00.000000002Z"),
               capture(b"future-page", "2024-01-01T00:00:00Z", "https://example.org/future")]
    bodies = {f.sha(body): body for body in (b"older", b"admitted", b"future-secret", b"future-page")}
    return recipe(entries), bodies


def reader(build):
    return ReplayIndex(build.index, dict(build.blobs), f.sha(build.index), CUTOFF)


def test_replay_exact_cutoff_and_latest_capture_without_future_inventory():
    raw, blobs = fixture()
    build = build_replay_index(raw, blobs)
    assert build.blobs == ((f.sha(b"admitted"), b"admitted"),)
    assert json.loads(build.index)["captures"] == [capture()]
    index = reader(build)
    response = index.lookup(URL)
    assert response == replay.ReplayResponse(200, "text/html; charset=utf-8", None, 8, b"admitted")
    assert index.lookup(URL, "HEAD") == replay.ReplayResponse(
        200, "text/html; charset=utf-8", None, 8, b"")
    assert index.lookup("https://example.org/article?a=2") is None
    assert index.lookup("http://example.org/article?a=1") is None
    assert index.lookup("https://example.org/future") is None
    assert b"future" not in build.index


def test_replay_redirect_is_replayed_without_following_it():
    entry = capture(b"", status=302, location="https://example.org/destination")
    build = build_replay_index(recipe([entry]), {f.sha(b""): b""})
    response = reader(build).lookup(URL)
    assert response.status == 302 and response.location == "https://example.org/destination"
    assert response.body == b"" and reader(build).lookup(response.location) is None


def test_replay_empty_known_answer():
    build = build_replay_index(recipe([]), {})
    assert build.index == (b'{"captures":[],"cutoff":"2023-04-01T00:00:00.000000001Z",'
                           b'"schema":"hermetic-replay-index/v1"}')
    assert build.blobs == ()
    assert reader(build).lookup(URL) is None


def test_replay_order_and_host_settings_do_not_change_bytes(monkeypatch):
    raw, blobs = fixture()
    expected = build_replay_index(raw, blobs)
    value = json.loads(raw)
    value["captures"].reverse()
    for key in ("TZ", "LANG", "LC_ALL", "HOSTNAME", "HOME", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(key, "host-secret")
    assert build_replay_index(json.dumps(value, indent=2).encode(),
                              dict(reversed(list(blobs.items())))) == expected


@pytest.mark.parametrize("updates", [
    {"status": True}, {"status": 199}, {"status": 600}, {"status": 304}, {"status": 204},
    {"status": 302}, {"content_type": "text/html\r\nSet-Cookie: secret"},
    {"content_type": []}, {"location": "https://example.org/a"},
    {"payload_sha256": "../host-secret"}, {"record_sha256": None}, {"source": []},
    {"source": "host-secret"}, {"size": True}, {"size": -1}, {"size": 1},
    {"captured": None}, {"captured": "2023-02-29T00:00:00Z"},
    {"headers": {"X-Archive-Orig-Date": "host-secret"}},
])
def test_replay_invalid_records_fail_closed_even_when_excluded(updates):
    for date in (CUTOFF, "2024-01-01T00:00:00Z"):
        with pytest.raises(ArchiveError) as error:
            build_replay_index(recipe([capture(**dict({"captured": date}, **updates))]),
                               {f.sha(b"admitted"): b"admitted"})
        assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("url", [None, [], "https://user:host-secret@example.org/a", "file:///etc/passwd",
    "HTTPS://example.org/a", "https://EXAMPLE.org/a", "https://example.org:443/a", "https://example.org", "https://example.org/a#b",
    "https://example.org/a\nb", "https://example.org/../secret", "https://example.org/%zz",
    "https://example.org/%2f", "https://[invalid/a", "https://example.org/\\secret",
    "https://-invalid.org/a", "https://example.org./a", "https://example.org/é"])
def test_replay_hostile_urls_have_typed_errors(url):
    with pytest.raises(ArchiveError) as error:
        build_replay_index(recipe([capture(url=url)]), {f.sha(b"admitted"): b"admitted"})
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("raw", [None, [], "{}", b"\xff", b"null", b"[]", b"NaN", b"{",
    b'{"schema":1,"schema":2}', b'{"x":"\\ud800"}', b'{"x":1e999}',
    b'{"x":' * 30 + b'0' + b'}' * 30])
def test_replay_hostile_documents(raw):
    with pytest.raises(ArchiveError):
        build_replay_index(raw, {})


def test_replay_duplicate_timestamp_alias_fails_closed():
    for entries in ([capture(), capture()],
                    [capture(date="2023-03-01T00:00:00Z"),
                     capture(date="2023-03-01T00:00:00.000Z")]):
        with pytest.raises(ArchiveError):
            build_replay_index(recipe(entries), {f.sha(b"admitted"): b"admitted"})


@pytest.mark.parametrize("mutation", ["hash", "cutoff", "payload", "missing", "extra", "type",
                                      "future", "order", "duplicate", "size", "encoding"])
def test_replay_reader_refuses_forged_index_or_blobs(mutation):
    raw, blobs = fixture()
    build = build_replay_index(raw, blobs)
    index, bodies, digest, cutoff = build.index, dict(build.blobs), f.sha(build.index), CUTOFF
    if mutation == "hash":
        digest = "0" * 64
    elif mutation == "cutoff":
        cutoff = "2025-01-01T00:00:00Z"
    elif mutation in {"payload", "missing", "extra", "type"}:
        key = next(iter(bodies))
        if mutation == "payload":
            bodies[key] = b"host-secret"
        elif mutation == "missing":
            del bodies[key]
        elif mutation == "extra":
            bodies[f.sha(b"extra")] = b"extra"
        else:
            bodies[key] = None
    elif mutation == "encoding":
        index = json.dumps(json.loads(index), indent=2).encode()
        digest = f.sha(index)
    else:
        value = json.loads(index)
        entry = next(iter(value["captures"]))
        if mutation == "future":
            entry["captured"] = "2024-01-01T00:00:00Z"
        elif mutation == "order":
            value["captures"].append(dict(entry, url="https://example.org/a"))
        elif mutation == "duplicate":
            value["captures"].append(dict(entry, captured="2023-01-01T00:00:00Z"))
        else:
            entry["size"] = 1
        index = f.encode(value)
        digest = f.sha(index)
    with pytest.raises(ArchiveError) as error:
        ReplayIndex(index, bodies, digest, cutoff)
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("cap", ["MAX_INDEX_BYTES", "MAX_RECORDS", "MAX_URL_BYTES", "MAX_PAYLOAD_BYTES",
                                  "MAX_TOTAL_PAYLOAD_BYTES", "MAX_CONTENT_TYPE_BYTES"])
def test_replay_named_caps(monkeypatch, cap):
    raw, blobs = fixture()
    monkeypatch.setattr(f, cap, 1)
    with pytest.raises(ArchiveError):
        build_replay_index(raw, blobs)


def disk_inputs(tmp_path):
    build = build_replay_index(*fixture())
    source = tmp_path / "replay.json"
    source.write_bytes(build.index)
    root = tmp_path / "blobs"
    root.mkdir()
    for key, body in build.blobs:
        (root / key).write_bytes(body)
    return build, source, root


def test_replay_file_reader_loads_exact_verified_bytes(tmp_path):
    build, source, root = disk_inputs(tmp_path)
    index = load_replay_files(source, root, f.sha(build.index), CUTOFF)
    assert index.lookup(URL).body == b"admitted"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "parent-symlink", "index-symlink"])
def test_replay_file_reader_refuses_unsafe_files_without_blocking(tmp_path, kind):
    build, source, root = disk_inputs(tmp_path)
    payload = root / next(iter(dict(build.blobs)))
    if kind == "index-symlink":
        source.unlink()
        source.symlink_to(payload)
    elif kind == "parent-symlink":
        root.rename(tmp_path / "moved")
        root.symlink_to(tmp_path / "moved", target_is_directory=True)
    else:
        payload.unlink()
        if kind == "symlink":
            payload.symlink_to(source)
        elif kind == "fifo":
            os.mkfifo(payload)
        else:
            payload.mkdir()
    with pytest.raises(ArchiveError):
        load_replay_files(source, root, f.sha(build.index), CUTOFF)


def test_replay_file_reader_retains_blob_directory_across_path_substitution(tmp_path, monkeypatch):
    build, source, root = disk_inputs(tmp_path)
    real_read = replay.read_regular_file_bounded
    moved = tmp_path / "moved"
    def swap(path, cap, **kwargs):
        if "directory" in kwargs:
            root.rename(moved)
            root.mkdir()
            (root / path).write_bytes(b"host-secret")
        return real_read(path, cap, **kwargs)
    monkeypatch.setattr(replay, "read_regular_file_bounded", swap)
    assert load_replay_files(source, root, f.sha(build.index), CUTOFF).lookup(URL).body == b"admitted"


@pytest.mark.parametrize("method", [None, [], "POST", "host-secret"])
def test_replay_refuses_unsupported_request_methods(method):
    index = reader(build_replay_index(*fixture()))
    with pytest.raises(ArchiveError):
        index.lookup(URL, method)
