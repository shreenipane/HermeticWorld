
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

