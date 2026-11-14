"""Monthly deterministic term-index format and hostile reader regressions."""

import json
import os

import pytest

from hermetic_archive import ArchiveError, SearchIndex, build_search_index, load_search_file
from hermetic_archive import formats as f, search

MONTH = "2023-04"


def document(body=b"Beta alpha", url="https://example.org/a", title="Alpha",
             date="2023-03-31T23:59:59.999999999Z", **updates):
    entry = dict(url=url, title=title, captured=date, source="common-crawl",
                 record_sha256="a" * 64, text_sha256=f.sha(body))
    entry.update(updates)
    return entry


def recipe(entries, month=MONTH):
    return f.encode(dict(schema="hermetic-search-recipe/v1", month=month, documents=entries))


def fixture():
    bodies = (b"Beta alpha", b"gamma", b"oldword", b"futureword", b"secretword")
    entries = [document(), document(b"gamma", "https://example.org/b", "Beta"),
               document(b"oldword", title="Old", date="2023-03-01T00:00:00Z"),
               document(b"futureword", date="2023-04-01T00:00:00Z"),
               document(b"secretword", "https://example.org/future", "Future", "2024-01-01T00:00:00Z")]
    return recipe(entries), {f.sha(body): body for body in bodies}


def reader(raw):
    return SearchIndex(raw, f.sha(raw), MONTH)


def test_search_known_answer_and_month_boundary_excludes_future_statistics():
    raw = build_search_index(*fixture())
    assert json.loads(raw) == dict(
        schema="hermetic-search-index/v1", month=MONTH, tokenizer="ascii-alnum-lower/v1",
        documents=[dict(document(), length=3), dict(document(b"gamma", "https://example.org/b", "Beta"), length=2)],
        terms=[["alpha", [[0, 2]]], ["beta", [[0, 1], [1, 1]]], ["gamma", [[1, 1]]]])
    # Exact independently specified wire prefix/suffix, including term ordering.
    assert raw.startswith(b'{"documents":[{"captured":"2023-03-31T23:59:59.999999999Z","length":3,')
    assert raw.endswith(b'"terms":[["alpha",[[0,2]]],["beta",[[0,1],[1,1]]],["gamma",[[1,1]]]],'
                        b'"tokenizer":"ascii-alnum-lower/v1"}')
    index = reader(raw)
    assert index.lookup_terms("BETA") == ("https://example.org/a", "https://example.org/b")
    assert index.lookup_terms("beta ALPHA") == ("https://example.org/a",)
    assert index.lookup_terms("beta", limit=1) == ("https://example.org/a",)
    assert index.lookup_terms("gamma") == ("https://example.org/b",)
    for query in ("oldword", "futureword", "secretword", "", "---", "β", "unseen alpha"):
        assert index.lookup_terms(query) == ()
    assert index.lookup_terms("beta", limit=0) == ()
    assert all(word not in raw for word in (b"oldword", b"futureword", b"secretword", b"/future"))


def test_search_empty_known_answer():
    raw = build_search_index(recipe([]), {})
    assert raw == (b'{"documents":[],"month":"2023-04","schema":"hermetic-search-index/v1",'
                   b'"terms":[],"tokenizer":"ascii-alnum-lower/v1"}')
    assert reader(raw).lookup_terms("alpha") == ()


def test_search_future_document_cannot_change_existing_index_bytes():
    raw, blobs = fixture()
    first = build_search_index(raw, blobs)
    value = json.loads(raw)
    admitted = [entry for entry in value["documents"] if entry["captured"] < "2023-04"]
    admitted_blobs = {entry["text_sha256"]: blobs[entry["text_sha256"]] for entry in admitted}
    assert build_search_index(recipe(admitted), admitted_blobs) == first


def test_search_order_and_host_environment_do_not_change_index(monkeypatch):
    raw, blobs = fixture()
    expected = build_search_index(raw, blobs)
    value = json.loads(raw)
    value["documents"].reverse()
    for key in ("HOME", "HOSTNAME", "TZ", "LANG", "LC_ALL", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(key, "host-secret")
    assert build_search_index(json.dumps(value, indent=2).encode(),
                              dict(reversed(list(blobs.items())))) == expected


@pytest.mark.parametrize("month", [None, [], "2023-4", "0000-04", "2023-13", "host-secret", "2023-04-01"])
def test_search_invalid_month_has_typed_error(month):
    with pytest.raises(ArchiveError):
        build_search_index(recipe([], month), {})


@pytest.mark.parametrize("updates", [{"title": []}, {"title": "host-secret\n"}, {"title": "\ud800"},
    {"url": "https://user:host-secret@example.org/a"}, {"captured": None}, {"source": []},
    {"source": "host-secret"}, {"record_sha256": "wrong"}, {"text_sha256": "../host-secret"},
    {"extra": "host-secret"}])
def test_search_hostile_document_schema_even_after_month(updates):
    entry = document(date="2024-01-01T00:00:00Z")
    entry.update(updates)
    # ensure_ascii permits a deliberately invalid surrogate to reach the parser.
    raw = json.dumps(dict(schema="hermetic-search-recipe/v1", month=MONTH, documents=[entry])).encode()
    with pytest.raises(ArchiveError) as error:
        build_search_index(raw, {f.sha(b"Beta alpha"): b"Beta alpha"})
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("body", [b"\xff", b"a" * (search.MAX_TERM_BYTES + 1)])
def test_search_hostile_text_fails_closed(body):
    with pytest.raises(ArchiveError):
        build_search_index(recipe([document(body)]), {f.sha(body): body})


@pytest.mark.parametrize("mutation", ["missing", "extra", "corrupt", "type", "count"])
def test_search_payload_inventory_is_verified(mutation):
    raw, blobs = fixture()
    key = next(iter(blobs))
    if mutation == "missing":
        del blobs[key]
    elif mutation == "extra":
        blobs[f.sha(b"extra")] = b"extra"
    elif mutation == "corrupt":
        blobs[key] = b"host-secret"
    elif mutation == "type":
        blobs[key] = None
    else:
        blobs = []
    with pytest.raises(ArchiveError):
        build_search_index(raw, blobs)


def mutate_terms(value, rows):
    value["terms"][0][1] = rows


@pytest.mark.parametrize("mutate", [
    lambda v: mutate_terms(v, [[-1, 1]]), lambda v: mutate_terms(v, [[2, 1]]),
    lambda v: mutate_terms(v, [[True, 1]]), lambda v: mutate_terms(v, [[0, True]]),
    lambda v: mutate_terms(v, [[0, 0]]), lambda v: mutate_terms(v, [[0, -1]]),
    lambda v: mutate_terms(v, [[0, search.MAX_DOCUMENT_TOKENS + 1]]),
    lambda v: mutate_terms(v, [[0, 1], [0, 1]]), lambda v: mutate_terms(v, [[1, 1], [0, 1]]),
    lambda v: mutate_terms(v, [None]), lambda v: mutate_terms(v, []),
    lambda v: v["terms"].reverse(), lambda v: v["terms"].append(v["terms"][0]),
    lambda v: v["terms"].append(None), lambda v: v["terms"][0].__setitem__(0, "ALPHA"),
    lambda v: v["terms"][0].__setitem__(0, []),
    lambda v: v["documents"][0].__setitem__("length", True),
    lambda v: v["documents"][0].__setitem__("length", 4),
    lambda v: v["documents"][0].__setitem__("captured", "2023-04-01T00:00:00Z"),
    lambda v: v["documents"].reverse(), lambda v: v.__setitem__("tokenizer", "host-secret"),
    lambda v: v.__setitem__("month", "2024-01"),
])
def test_search_reader_rejects_forged_postings_and_statistics(mutate):
    value = json.loads(build_search_index(*fixture()))
    mutate(value)
    raw = f.encode(value)
    with pytest.raises(ArchiveError) as error:
        reader(raw)
    assert "host-secret" not in str(error.value)


def test_search_authentication_and_canonical_encoding_required():
    raw = build_search_index(*fixture())
    with pytest.raises(ArchiveError):
        SearchIndex(raw, "0" * 64, MONTH)
    noncanonical = json.dumps(json.loads(raw), indent=2).encode()
    with pytest.raises(ArchiveError):
        reader(noncanonical)


@pytest.mark.parametrize("query,limit", [(None, 1), ([], 1), ("alpha", True), ("alpha", -1),
    ("alpha", search.MAX_RESULTS + 1), ("x" * (search.MAX_QUERY_BYTES + 1), 1),
    ("a " * (search.MAX_QUERY_TERMS + 1), 1), ("\ud800", 1),
    ("é" * (search.MAX_QUERY_BYTES // 2 + 1), 1)])
def test_search_hostile_query_never_escapes_typed_error(query, limit):
    with pytest.raises(ArchiveError):
        reader(build_search_index(*fixture())).lookup_terms(query, limit)


@pytest.mark.parametrize("cap", ["MAX_TITLE_BYTES", "MAX_TERM_BYTES", "MAX_DOCUMENT_TOKENS",
                                  "MAX_TOTAL_TOKENS", "MAX_TERMS"])
def test_search_named_build_and_read_caps(monkeypatch, cap):
    raw, blobs = fixture()
    valid = build_search_index(raw, blobs)
    monkeypatch.setattr(search, cap, 1)
    with pytest.raises(ArchiveError):
        build_search_index(raw, blobs)
    with pytest.raises(ArchiveError):
        reader(valid)


def test_archive_readers_arbitrary_short_bytes_are_typed():
    for byte in range(256):
        raw = bytes([byte])
        for run in (lambda: build_search_index(raw, {}),
                    lambda: SearchIndex(raw, f.sha(raw), MONTH)):
            with pytest.raises(ArchiveError):
                run()


def test_search_file_reader_loads_authenticated_index(tmp_path):
    raw = build_search_index(*fixture())
    source = tmp_path / "search.json"
    source.write_bytes(raw)
    assert load_search_file(source, f.sha(raw), MONTH).lookup_terms("alpha") == ("https://example.org/a",)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "parent-symlink", "oversized"])
def test_search_file_reader_refuses_hostile_files(tmp_path, kind):
    raw = build_search_index(*fixture())
    parent = tmp_path / "parent"
    parent.mkdir()
    source = parent / "search.json"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(raw)
        source.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(source)
    elif kind == "directory":
        source.mkdir()
    elif kind == "parent-symlink":
        parent.rename(tmp_path / "moved")
        parent.symlink_to(tmp_path / "moved", target_is_directory=True)
        source.write_bytes(raw)
    else:
        with source.open("wb") as output:
            output.truncate(f.MAX_INDEX_BYTES + 1)
    with pytest.raises(ArchiveError):
        load_search_file(source, f.sha(raw), MONTH)


@pytest.mark.parametrize("digest,month", [("host-secret", MONTH), ("a" * 64, "host-secret")])
def test_search_file_reader_validates_options_before_file_access(monkeypatch, digest, month):
    def refuse(*args, **kwargs):
        pytest.fail("invalid load configuration reached file access")
    monkeypatch.setattr(search, "read_regular_file_bounded", refuse)
    with pytest.raises(ArchiveError):
        load_search_file("index.json", digest, month)
