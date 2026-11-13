
import json

import pytest



from hermetic_yank.simple_index import (

    YankError,

    load_json_bounded,

    rewrite_simple_index,

)

from hermetic_yank.__main__ import main as cli_main





CUTOFF = "2023-04-01T00:00:00Z"





def _fixture_page():

    return {

        "meta": {"api-version": "1.1"},

        "name": "demo-pkg",

        "versions": ["0.9.0", "1.0.0", "1.1.0", "1.2.0", "2.0.0"],

        "files": [

            {

                "filename": "demo_pkg-0.9.0.tar.gz",

                "url": "https://files.pythonhosted.org/demo_pkg-0.9.0.tar.gz",

                "hashes": {"sha256": "aaaa"},

                "yanked": False,

            },

            {

                "filename": "demo_pkg-1.0.0-py3-none-any.whl",

                "url": "https://files.pythonhosted.org/demo_pkg-1.0.0-py3-none-any.whl",

                "hashes": {"sha256": "bbbb"},

                "upload-time": "2023-04-01T00:00:00Z",

                "yanked": "critical bug",

                "data-dist-info-metadata": {"sha256": "meta1"},

                "x-custom-ext": "keep-me",

            },

            {

                "filename": "demo_pkg-1.1.0-py3-none-any.whl",

                "url": "https://files.pythonhosted.org/demo_pkg-1.1.0-py3-none-any.whl",

                "hashes": {"sha256": "cccc"},

                "upload-time": "2023-03-15T00:00:00Z",

                "yanked": "yanked later",

            },

            {

                "filename": "demo_pkg-1.2.0-py3-none-any.whl",

                "url": "https://files.pythonhosted.org/demo_pkg-1.2.0-py3-none-any.whl",

                "hashes": {"sha256": "dddd"},

                "upload-time": "2023-03-20T00:00:00Z",

                "yanked": True,

            },

            {

                "filename": "demo_pkg-2.0.0-py3-none-any.whl",

                "url": "https://files.pythonhosted.org/demo_pkg-2.0.0-py3-none-any.whl",

                "hashes": {"sha256": "eeee"},

                "upload-time": "2023-04-01T00:00:01Z",

                "yanked": False,

                "data-dist-info-metadata": {"sha256": "dropped-meta"},

            },

        ],

    }





def test_rules_1_to_4_and_cutoff_boundaries():

    page = _fixture_page()

    yanks = {

        "demo_pkg-1.0.0-py3-none-any.whl": "2023-04-01T00:00:00Z",

        "demo_pkg-1.1.0-py3-none-any.whl": "2023-04-01T00:00:01Z",

    }

    rewritten, report = rewrite_simple_index(page, yanks, CUTOFF)



    assert report["dropped_after_cutoff"] == ["demo_pkg-2.0.0-py3-none-any.whl"]

    assert report["unyanked_after_cutoff"] == ["demo_pkg-1.1.0-py3-none-any.whl"]

    assert report["unyanked_unknown_date"] == ["demo_pkg-1.2.0-py3-none-any.whl"]

    assert report["undated"] == ["demo_pkg-0.9.0.tar.gz"]



    by_name = {f["filename"]: f for f in rewritten["files"]}

    assert "demo_pkg-2.0.0-py3-none-any.whl" not in by_name

    assert by_name["demo_pkg-1.0.0-py3-none-any.whl"]["yanked"] == "critical bug"

    assert by_name["demo_pkg-1.0.0-py3-none-any.whl"]["x-custom-ext"] == "keep-me"

    assert by_name["demo_pkg-1.0.0-py3-none-any.whl"]["data-dist-info-metadata"] == {"sha256": "meta1"}

    assert by_name["demo_pkg-1.1.0-py3-none-any.whl"]["yanked"] is False

    assert by_name["demo_pkg-1.2.0-py3-none-any.whl"]["yanked"] is False

    assert rewritten["versions"] == ["0.9.0", "1.0.0", "1.1.0", "1.2.0"]





def test_hostile_pages_rejected():

    with pytest.raises(YankError):

        load_json_bounded(b'{"a":1,"a":2}', 1024)



    bad_page = _fixture_page()

    bad_page["files"][0]["hashes"] = "not-a-dict"

    with pytest.raises(YankError):

        rewrite_simple_index(bad_page, {}, CUTOFF)



    huge_str_page = _fixture_page()

    huge_str_page["name"] = "a" * 20000

    raw = json.dumps(huge_str_page).encode("utf-8")

    with pytest.raises(YankError):

        load_json_bounded(raw, 1024 * 1024)





def test_cli_atomic_write_and_determinism(tmp_path):

    page_path = tmp_path / "page.json"

    yanks_path = tmp_path / "yanks.json"

    out1 = tmp_path / "out1.json"

    rep1 = tmp_path / "rep1.json"

    out2 = tmp_path / "out2.json"

    rep2 = tmp_path / "rep2.json"



    page_path.write_text(json.dumps(_fixture_page()), encoding="utf-8")

    yanks_path.write_text(

        json.dumps({"demo_pkg-1.0.0-py3-none-any.whl": "2023-03-30T00:00:00Z"}),

        encoding="utf-8",

    )



    rc1 = cli_main([

        "--page", str(page_path),

        "--yanks", str(yanks_path),

        "--cutoff", CUTOFF,

        "--out", str(out1),

        "--report", str(rep1),

    ])

    rc2 = cli_main([

        "--page", str(page_path),

        "--yanks", str(yanks_path),

        "--cutoff", CUTOFF,

        "--out", str(out2),

        "--report", str(rep2),

    ])

    assert rc1 == 0

    assert rc2 == 0

    assert out1.read_bytes() == out2.read_bytes()

    assert rep1.read_bytes() == rep2.read_bytes()



# ---------------------------------------------------------------------------
# Requirement coverage added in review.
# ---------------------------------------------------------------------------

import copy
import os
import threading

import hermetic_yank.simple_index as simple_index
from hermetic_yank.simple_index import (
    MAX_FILES_COUNT,
    atomic_write_bytes,
    parse_rfc3339_ns,
    run_yank_rewrite_from_paths,
    safe_read_bytes,
)


def _file(name, upload=None, yanked=None, **extra):
    entry = {"filename": name, "url": "https://files.example/" + name, "hashes": {"sha256": "00"}}
    if upload is not None:
        entry["upload-time"] = upload
    if yanked is not None:
        entry["yanked"] = yanked
    entry.update(extra)
    return entry


def _page(files, versions=None, **extra):
    page = {"meta": {"api-version": "1.1"}, "name": "demo-pkg", "files": files}
    if versions is not None:
        page["versions"] = versions
    page.update(extra)
    return page


def _run_cli(tmp_path, page, yanks, out="out.json", report="rep.json", raw_page=None):
    page_path = tmp_path / "page.json"
    yanks_path = tmp_path / "yanks.json"
    if raw_page is not None:
        page_path.write_bytes(raw_page)
    else:
        page_path.write_text(json.dumps(page), encoding="utf-8")
    yanks_path.write_text(json.dumps(yanks), encoding="utf-8")
    return cli_main([
        "--page", str(page_path), "--yanks", str(yanks_path), "--cutoff", CUTOFF,
        "--out", str(tmp_path / out), "--report", str(tmp_path / report),
    ])


def test_fifo_input_refused_without_blocking(tmp_path):
    fifo = tmp_path / "page.fifo"
    os.mkfifo(fifo)
    box = {}

    def runner():
        try:
            safe_read_bytes(str(fifo), 1024)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            box["exc"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(5)
    finished = not t.is_alive()
    if not finished:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        t.join(5)
    assert finished, "reading a FIFO blocked"
    assert isinstance(box.get("exc"), YankError)


def test_symlinked_inputs_and_outputs_refused(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    os.symlink(real, link)
    with pytest.raises(YankError):
        safe_read_bytes(str(link), 1024)
    with pytest.raises(YankError):
        atomic_write_bytes(str(link), b"x")
    assert real.read_text(encoding="utf-8") == "{}"
    linkdir = tmp_path / "linkdir"
    os.symlink(tmp_path, linkdir)
    with pytest.raises(YankError):
        atomic_write_bytes(str(linkdir / "new.json"), b"x")
    assert not (tmp_path / "new.json").exists()


def test_rule1_drop_after_cutoff_boundary_and_undated_kept():
    files = [
        _file("demo_pkg-1.0.tar.gz", "2023-04-01T00:00:00Z"),
        _file("demo_pkg-1.1.tar.gz", "2023-04-01T00:00:00.000001Z"),
        _file("demo_pkg-0.1.tar.gz"),
        _file("demo_pkg-0.2.tar.gz", None, None, **{"upload-time": None}),
    ]
    out, rep = rewrite_simple_index(_page(files), {}, CUTOFF)
    assert [f["filename"] for f in out["files"]] == ["demo_pkg-1.0.tar.gz", "demo_pkg-0.1.tar.gz", "demo_pkg-0.2.tar.gz"]
    assert rep["dropped_after_cutoff"] == ["demo_pkg-1.1.tar.gz"]
    assert rep["undated"] == ["demo_pkg-0.1.tar.gz", "demo_pkg-0.2.tar.gz"]


def test_rule1_bad_upload_time_rejected():
    for bad in (5, "2023-04-01", "yesterday", "2023-04-01T00:00:00Z\n"):
        with pytest.raises(YankError):
            rewrite_simple_index(_page([_file("a-1.tar.gz", bad)]), {}, CUTOFF)


def test_rfc3339_offsets_in_upload_and_yank_times():
    assert parse_rfc3339_ns("2023-03-31T20:00:00-04:00") == parse_rfc3339_ns(CUTOFF)
    files = [
        _file("demo_pkg-1.0.tar.gz", "2023-04-01T01:00:00+01:00", "r"),
        _file("demo_pkg-1.1.tar.gz", "2023-03-31T20:00:01-04:00"),
    ]
    out, rep = rewrite_simple_index(_page(files), {"demo_pkg-1.0.tar.gz": "2023-04-01T02:00:01+02:00"}, CUTOFF)
    assert rep["dropped_after_cutoff"] == ["demo_pkg-1.1.tar.gz"]
    assert rep["unyanked_after_cutoff"] == ["demo_pkg-1.0.tar.gz"]
    assert out["files"][0]["yanked"] is False


def test_rule2_yank_boundary_reason_true_and_unknown():
    files = [
        _file("demo_pkg-1.0.tar.gz", "2023-01-01T00:00:00Z", "reason at cutoff"),
        _file("demo_pkg-1.1.tar.gz", "2023-01-01T00:00:00Z", True),
        _file("demo_pkg-1.2.tar.gz", "2023-01-01T00:00:00Z", "later"),
        _file("demo_pkg-1.3.tar.gz", "2023-01-01T00:00:00Z", "no date"),
        _file("demo_pkg-1.4.tar.gz", "2023-01-01T00:00:00Z", False),
        _file("demo_pkg-1.5.tar.gz", "2023-01-01T00:00:00Z"),
    ]
    yanks = {
        "demo_pkg-1.0.tar.gz": CUTOFF,
        "demo_pkg-1.1.tar.gz": "2023-03-01T00:00:00Z",
        "demo_pkg-1.2.tar.gz": "2023-04-01T00:00:00.000000001Z",
        "demo_pkg-1.4.tar.gz": "2023-05-01T00:00:00Z",
    }
    out, rep = rewrite_simple_index(_page(files), yanks, CUTOFF)
    y = {f["filename"]: f.get("yanked", "absent") for f in out["files"]}
    assert y == {
        "demo_pkg-1.0.tar.gz": "reason at cutoff",
        "demo_pkg-1.1.tar.gz": True,
        "demo_pkg-1.2.tar.gz": False,
        "demo_pkg-1.3.tar.gz": False,
        "demo_pkg-1.4.tar.gz": False,
        "demo_pkg-1.5.tar.gz": "absent",
    }
    assert rep["unyanked_after_cutoff"] == ["demo_pkg-1.2.tar.gz"]
    assert rep["unyanked_unknown_date"] == ["demo_pkg-1.3.tar.gz"]


def test_rule2_bad_yank_values_rejected():
    for bad_yank in (1, None, ["r"], {"r": 1}):
        with pytest.raises(YankError):
            rewrite_simple_index(_page([dict(_file("a-1.tar.gz"), yanked=bad_yank)]), {}, CUTOFF)
    for table in ([], {"a-1.tar.gz": 5}, {"a-1.tar.gz": "soon"}, {"": CUTOFF}):
        with pytest.raises(YankError):
            rewrite_simple_index(_page([_file("a-1.tar.gz")]), table, CUTOFF)


def test_rule3_versions_recomputed_sorted_as_strings_and_absent_stays_absent():
    files = [
        _file("demo_pkg-10.0-py3-none-any.whl", "2023-01-01T00:00:00Z"),
        _file("demo_pkg-9.0.tar.gz", "2023-01-01T00:00:00Z"),
        _file("demo_pkg-2.0.tar.gz", "2023-01-01T00:00:00Z"),
        _file("demo_pkg-11.0.tar.gz", "2024-01-01T00:00:00Z"),
    ]
    out, _ = rewrite_simple_index(_page(files, versions=["2.0", "9.0", "10.0", "11.0", "12.0"]), {}, CUTOFF)
    # Plain string sort, not PEP 440: "10.0" < "2.0" < "9.0".
    assert out["versions"] == ["10.0", "2.0", "9.0"]
    out, _ = rewrite_simple_index(_page(files), {}, CUTOFF)
    assert "versions" not in out


def test_rule3_other_fields_and_extension_keys_preserved_exactly():
    kept = _file(
        "demo_pkg-1.0-py3-none-any.whl",
        "2023-01-01T00:00:00Z",
        False,
        **{
            "requires-python": ">=3.8",
            "data-dist-info-metadata": {"sha256": "m"},
            "core-metadata": True,
            "dist-info-metadata": False,
            "gpg-sig": False,
            "x-ext": {"nested": [1, 2.5, None, "sé"]},
            "size": 12345678901234567890,
        },
    )
    dropped = _file("demo_pkg-2.0-py3-none-any.whl", "2024-01-01T00:00:00Z", **{"data-dist-info-metadata": True})
    page = _page([kept, dropped], versions=["1.0", "2.0"], **{"project-status": {"status": "active"}, "x-top": [1]})
    page["meta"]["_last-serial"] = 42
    snapshot = copy.deepcopy(page)
    out, _ = rewrite_simple_index(page, {}, CUTOFF)
    assert page == snapshot, "input must not be mutated"
    assert out["files"] == [kept]
    assert out["meta"] == {"api-version": "1.1", "_last-serial": 42}
    assert out["project-status"] == {"status": "active"}
    assert out["x-top"] == [1]
    assert out["name"] == "demo-pkg"
    assert set(out) == {"meta", "name", "files", "versions", "project-status", "x-top"}


def test_rule4_canonical_output_and_report(tmp_path):
    files = [
        _file("demo_pkg-b.tar.gz", "2024-01-01T00:00:00Z"),
        _file("demo_pkg-a.tar.gz", "2024-01-01T00:00:00Z"),
        _file("demo_pkg-1.0.tar.gz", None, "r", **{"x-u": "é"}),
    ]
    assert _run_cli(tmp_path, _page(files, versions=[]), {}) == 0
    raw = (tmp_path / "out.json").read_bytes()
    parsed = json.loads(raw.decode("utf-8"))
    assert raw == json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert "é".encode("utf-8") in raw
    rep = json.loads((tmp_path / "rep.json").read_bytes())
    assert rep == {
        "dropped_after_cutoff": ["demo_pkg-a.tar.gz", "demo_pkg-b.tar.gz"],
        "unyanked_after_cutoff": [],
        "unyanked_unknown_date": ["demo_pkg-1.0.tar.gz"],
        "undated": ["demo_pkg-1.0.tar.gz"],
    }
    assert sorted(os.listdir(tmp_path)) == ["out.json", "page.json", "rep.json", "yanks.json"]


def test_hostile_page_shapes_rejected():
    good = _file("a-1.tar.gz")
    bad_pages = [
        [],
        {"meta": {"api-version": "1.1"}, "name": "a"},
        {"meta": {}, "name": "a", "files": []},
        {"meta": {"api-version": 1}, "name": "a", "files": []},
        {"meta": {"api-version": "1.1"}, "name": "", "files": []},
        {"meta": {"api-version": "1.1"}, "name": "a", "files": {}},
        _page([good], versions="1"),
        _page([good], versions=[1]),
        _page(["a-1.tar.gz"]),
        _page([{"filename": "a-1.tar.gz", "url": "u"}]),
        _page([dict(good, filename=5)]),
        _page([dict(good, url="")]),
        _page([dict(good, hashes={"sha256": 1})]),
        _page([dict(good, **{"requires-python": 3})]),
        _page([good] * (MAX_FILES_COUNT + 1)),
    ]
    for page in bad_pages:
        with pytest.raises(YankError):
            rewrite_simple_index(page, {}, CUTOFF)


def test_hostile_page_bytes_rejected():
    for raw in (
        b'{"files": [{"filename": "a", "filename": "b"}]}',
        b'{"a": "' + b"x" * 20000 + b'"}',
        b"[" * 100000 + b"]" * 100000,
        b"\xff",
        b'{"a": "\\ud800"}',
        b'{"\\udfff": 1}',
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": 1e400}',
        b'{"a": 0.10000000000000000000001}',
        b'{"a": ' + b"1" * 100 + b"}",
        b'{"a\\u0000": 1}',
    ):
        with pytest.raises(YankError):
            load_json_bounded(raw, 1024 * 1024)
    assert load_json_bounded(b'{"a": 2.5, "b": 1e2, "c": -0.0}', 1024) == {"a": 2.5, "b": 100.0, "c": -0.0}


def test_cli_lone_surrogate_and_non_finite_number_exit_one(tmp_path):
    raw = json.dumps(_page([_file("a-1.tar.gz")])).encode("utf-8")
    surrogate = raw.replace(b'"name": "demo-pkg"', b'"name": "demo\\ud800"')
    assert surrogate != raw
    assert _run_cli(tmp_path, None, {}, raw_page=surrogate) == 1
    infinite = raw.replace(b'"name": "demo-pkg"', b'"name": "demo-pkg", "x": 1e400')
    assert _run_cli(tmp_path, None, {}, raw_page=infinite) == 1
    assert not (tmp_path / "out.json").exists()
    assert not (tmp_path / "rep.json").exists()


def test_cli_bad_report_path_writes_nothing(tmp_path):
    page = _page([_file("a-1.tar.gz")])
    rc = _run_cli(tmp_path, page, {}, report="missing-dir/rep.json")
    assert rc == 1
    assert not (tmp_path / "out.json").exists()
    rc = _run_cli(tmp_path, page, {}, out="same.json", report="same.json")
    assert rc == 1
    assert not (tmp_path / "same.json").exists()
    (tmp_path / "adir").mkdir()
    assert _run_cli(tmp_path, page, {}, out="adir") == 1
    assert _run_cli(tmp_path, page, {}, out="o.json", report="./o.json") == 1
    assert not (tmp_path / "o.json").exists()


def test_cli_overwrites_existing_output_atomically(tmp_path):
    (tmp_path / "out.json").write_text("old", encoding="utf-8")
    assert _run_cli(tmp_path, _page([_file("a-1.tar.gz")]), {}) == 0
    assert json.loads((tmp_path / "out.json").read_bytes())["name"] == "demo-pkg"
    assert not [n for n in os.listdir(tmp_path) if n.startswith(".tmp.")]


def test_atomic_write_detects_short_write(tmp_path, monkeypatch):
    real_write = os.write

    def one_byte_write(fd, data):
        return real_write(fd, bytes(data[:1]))

    monkeypatch.setattr(simple_index.os, "write", one_byte_write)
    target = tmp_path / "out.json"
    with pytest.raises(YankError):
        atomic_write_bytes(str(target), b"x" * 1000)
    monkeypatch.undo()
    assert not target.exists()
    assert os.listdir(tmp_path) == []


def test_cli_error_exit_one_without_host_paths(tmp_path, capsys):
    rc = cli_main(["--page", str(tmp_path / "nope.json"), "--yanks", "y", "--cutoff", CUTOFF, "--out", "o", "--report", "r"])
    assert rc == 1
    assert cli_main(["--page", "p"]) == 1
    err = capsys.readouterr().err
    assert str(tmp_path) not in err


def test_run_from_paths_rejects_oversized_page(tmp_path):
    page = tmp_path / "page.json"
    page.write_bytes(b" " * (32 * 1024 * 1024 + 1))
    yanks = tmp_path / "yanks.json"
    yanks.write_text("{}", encoding="utf-8")
    with pytest.raises(YankError):
        run_yank_rewrite_from_paths(str(page), str(yanks), CUTOFF, str(tmp_path / "o"), str(tmp_path / "r"))


def test_regression_out_and_report_same_file_via_symlinked_ancestor(tmp_path):
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    os.symlink(real, tmp_path / "alias")
    page = tmp_path / "page.json"
    page.write_text(json.dumps(_page([_file("demo_pkg-1.0.tar.gz", upload="2023-01-01T00:00:00Z")])), encoding="utf-8")
    yanks = tmp_path / "yanks.json"
    yanks.write_text("{}", encoding="utf-8")
    with pytest.raises(YankError):
        run_yank_rewrite_from_paths(
            str(page), str(yanks), CUTOFF,
            str(real / "sub" / "x.json"), str(tmp_path / "alias" / "sub" / "x.json"),
        )
    assert not (real / "sub" / "x.json").exists()
