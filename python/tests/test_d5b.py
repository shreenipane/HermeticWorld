
import json

import os

import pytest



from hermetic_d5b.check import (

    evaluate_inventory,

    load_json_bounded,

    normalize_pypi_name,

    run_check_from_paths,

)

from hermetic_d5b.model import D5bError, MAX_INVENTORY_BYTES

from hermetic_d5b.__main__ import main as cli_main





CUTOFF = "2023-04-01T00:00:00Z"





def _sample_metadata():

    return {

        "pypi": {

            "my-cool-pkg": {

                "1.0.0": {

                    "my_cool_pkg-1.0.0.tar.gz": "2023-04-01T00:00:00Z",

                    "my_cool_pkg-1.0.0-py3-none-any.whl": "2023-04-01T00:00:01Z",

                },

                "2.0.0": {

                    "my_cool_pkg-2.0.0.tar.gz": "2023-04-01T00:00:01Z",

                },

            }

        },

        "conda": {

            "numpy": {

                "1.24.0": 1680307200000,

                "1.25.0": 1680307200001,

                "1.26.0": None,

            }

        },

        "npm": {

            "left-pad": {

                "1.3.0": "2023-03-31T23:59:59Z",

                "1.4.0": "2023-04-01T00:00:01Z",

            }

        },

        "crates": {

            "serde": {

                "1.0.159": "2023-04-01T00:00:00Z",

                "1.0.160": "2023-04-01T00:00:01Z",

            }

        },

    }





def test_pep503_normalisation():

    assert normalize_pypi_name("My_Cool..Pkg---Name") == "my-cool-pkg-name"

    with pytest.raises(D5bError):

        normalize_pypi_name("")

    with pytest.raises(D5bError):

        normalize_pypi_name("___")





def test_all_ecosystems_and_exact_cutoff_boundary():

    meta = _sample_metadata()

    inv = {

        "packages": [

            {"ecosystem": "pypi", "name": "My_Cool.Pkg", "version": "1.0.0", "file": "my_cool_pkg-1.0.0.tar.gz"},

            {"ecosystem": "conda", "name": "numpy", "version": "1.24.0", "file": None},

            {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0", "file": None},

            {"ecosystem": "crates", "name": "serde", "version": "1.0.159", "file": None},

        ]

    }

    res = evaluate_inventory(inv, meta, CUTOFF, "strict")

    assert res["result"] == "pass"

    assert res["newer"] == []

    assert res["unknown"] == []

    assert res["counts"]["ok"] == 4





def test_one_second_and_one_millisecond_after_cutoff_is_newer():

    meta = _sample_metadata()

    inv = {

        "packages": [

            {"ecosystem": "pypi", "name": "my-cool-pkg", "version": "2.0.0", "file": None},

            {"ecosystem": "conda", "name": "numpy", "version": "1.25.0", "file": None},

            {"ecosystem": "npm", "name": "left-pad", "version": "1.4.0", "file": None},

            {"ecosystem": "crates", "name": "serde", "version": "1.0.160", "file": None},

        ]

    }

    res = evaluate_inventory(inv, meta, CUTOFF, "strict")

    assert res["result"] == "gate"

    assert len(res["newer"]) == 4

    assert [x["ecosystem"] for x in res["newer"]] == ["conda", "crates", "npm", "pypi"]





def test_pypi_per_file_vs_earliest_file_rule():

    meta = _sample_metadata()

    inv_earliest = {

        "packages": [

            {"ecosystem": "pypi", "name": "My.Cool_Pkg", "version": "1.0.0", "file": None}

        ]

    }

    res_earliest = evaluate_inventory(inv_earliest, meta, CUTOFF, "strict")

    assert res_earliest["result"] == "pass"



    inv_specific_wheel = {

        "packages": [

            {

                "ecosystem": "pypi",

                "name": "My.Cool_Pkg",

                "version": "1.0.0",

                "file": "my_cool_pkg-1.0.0-py3-none-any.whl",

            }

        ]

    }

    res_wheel = evaluate_inventory(inv_specific_wheel, meta, CUTOFF, "strict")

    assert res_wheel["result"] == "gate"

    assert len(res_wheel["newer"]) == 1





def test_unknown_handling_and_modes():

    meta = _sample_metadata()

    inv = {

        "packages": [

            {"ecosystem": "conda", "name": "numpy", "version": "1.26.0", "file": None},

            {"ecosystem": "npm", "name": "missing-pkg", "version": "0.1.0", "file": None},

        ]

    }

    strict_res = evaluate_inventory(inv, meta, CUTOFF, "strict")

    assert strict_res["result"] == "gate"

    assert len(strict_res["unknown"]) == 2



    repo_res = evaluate_inventory(inv, meta, CUTOFF, "repo_only")

    assert repo_res["result"] == "pass_with_warnings"

    assert len(repo_res["unknown"]) == 2





def test_exemptions_prevent_gate():

    meta = _sample_metadata()

    inv = {

        "packages": [

            {"ecosystem": "pypi", "name": "My_Cool_Pkg", "version": "2.0.0", "file": None},

            {"ecosystem": "conda", "name": "numpy", "version": "1.26.0", "file": None},

        ]

    }

    exemptions = [

        {"ecosystem": "pypi", "name": "my.cool.pkg", "version": "2.0.0", "reason": "backported"},

        {"ecosystem": "conda", "name": "numpy", "version": "1.26.0", "reason": "vendor-pinned"},

    ]

    res = evaluate_inventory(inv, meta, CUTOFF, "strict", exemptions)

    assert res["result"] == "pass"

    assert res["newer"] == []

    assert res["unknown"] == []

    assert len(res["exempt"]) == 2





def test_hostile_json_and_unknown_fields(tmp_path):

    with pytest.raises(D5bError):

        load_json_bounded(b'{"a": 1, "a": 2}', 1024)



    nested = b"[" * 25 + b"]" * 25

    with pytest.raises(D5bError):

        load_json_bounded(nested, 1024)



    with pytest.raises(D5bError):

        load_json_bounded(b"x" * (MAX_INVENTORY_BYTES + 10), MAX_INVENTORY_BYTES)



    with pytest.raises(D5bError):

        evaluate_inventory(

            {"packages": [{"ecosystem": "pypi", "name": "a", "version": "1", "file": None, "extra": 1}]},

            _sample_metadata(),

            CUTOFF,

            "strict",

        )



    target = tmp_path / "real.json"

    target.write_text("{}", encoding="utf-8")

    link = tmp_path / "link.json"

    os.symlink(target, link)

    with pytest.raises(D5bError):

        run_check_from_paths(str(link), str(target), CUTOFF, "strict")





def test_cli_exit_codes_and_determinism(tmp_path, capsys):

    inv_path = tmp_path / "inv.json"

    meta_path = tmp_path / "meta.json"

    meta_path.write_text(json.dumps(_sample_metadata()), encoding="utf-8")



    inv_gate = {

        "packages": [

            {"ecosystem": "npm", "name": "left-pad", "version": "1.4.0", "file": None},

            {"ecosystem": "pypi", "name": "My_Cool_Pkg", "version": "1.0.0", "file": None},

        ]

    }

    inv_path.write_text(json.dumps(inv_gate), encoding="utf-8")



    code_strict = cli_main([

        "--inventory", str(inv_path),

        "--metadata", str(meta_path),

        "--cutoff", CUTOFF,

        "--mode", "strict",

    ])

    out1 = capsys.readouterr().out

    assert code_strict == 2



    code_repo = cli_main([

        "--inventory", str(inv_path),

        "--metadata", str(meta_path),

        "--cutoff", CUTOFF,

        "--mode", "repo_only",

    ])

    out2 = capsys.readouterr().out

    assert code_repo == 0



    code_strict_again = cli_main([

        "--inventory", str(inv_path),

        "--metadata", str(meta_path),

        "--cutoff", CUTOFF,

        "--mode", "strict",

    ])

    out3 = capsys.readouterr().out

    assert code_strict_again == 2

    assert out1 == out3

