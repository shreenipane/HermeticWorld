
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



# ---------------------------------------------------------------------------
# Requirement coverage added in review.
# ---------------------------------------------------------------------------

import threading

from hermetic_d5b.check import parse_rfc3339_ns, safe_read_bytes
from hermetic_d5b.model import MAX_PACKAGES


def _pkg(eco, name, version, file=None):
    return {"ecosystem": eco, "name": name, "version": version, "file": file}


def _call_with_deadline(fn, seconds=5.0):
    """Run fn in a thread; return (finished, exception)."""
    box = {}

    def runner():
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            box["exc"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), box.get("exc"), t


def test_fifo_input_refused_without_blocking(tmp_path):
    fifo = tmp_path / "inv.fifo"
    os.mkfifo(fifo)
    finished, exc, thread = _call_with_deadline(lambda: safe_read_bytes(str(fifo), 1024))
    if not finished:
        # Unblock the stuck reader so the test process can exit.
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        thread.join(5)
    assert finished, "reading a FIFO blocked"
    assert isinstance(exc, D5bError)


def test_device_and_directory_inputs_refused(tmp_path):
    with pytest.raises(D5bError):
        safe_read_bytes("/dev/null", 1024)
    with pytest.raises(D5bError):
        safe_read_bytes(str(tmp_path), 1024)


def test_oversized_inventory_file_refused(tmp_path):
    inv = tmp_path / "inv.json"
    inv.write_bytes(b" " * (MAX_INVENTORY_BYTES + 1))
    meta = tmp_path / "meta.json"
    meta.write_text("{}", encoding="utf-8")
    with pytest.raises(D5bError):
        run_check_from_paths(str(inv), str(meta), CUTOFF, "strict")


def test_rfc3339_numeric_offsets_compare_in_utc():
    assert parse_rfc3339_ns("2023-04-01T01:00:00+01:00") == parse_rfc3339_ns(CUTOFF)
    assert parse_rfc3339_ns("2023-03-31T20:00:01-04:00") == parse_rfc3339_ns(CUTOFF) + 1_000_000_000
    assert parse_rfc3339_ns("2023-04-01t00:00:00z") == parse_rfc3339_ns(CUTOFF)
    meta = {"npm": {"a": {"1": "2023-03-31T20:00:01-04:00", "2": "2023-04-01T02:00:00+02:00"}}}
    res = evaluate_inventory({"packages": [_pkg("npm", "a", "1"), _pkg("npm", "a", "2")]}, meta, CUTOFF, "strict")
    assert [e["version"] for e in res["newer"]] == ["1"]
    assert res["counts"]["ok"] == 1


@pytest.mark.parametrize(
    "bad",
    [
        "2023-04-01T00:00:00Z\n",
        "٢023-04-01T00:00:00Z",
        "2023-04-01T00:00:00.0000000001Z",
        "2023-04-01T00:00:00",
        "2023-04-01T00:00:00+24:00",
        "2023-02-30T00:00:00Z",
        "2023-04-01T24:00:00Z",
        123,
    ],
)
def test_malformed_timestamps_rejected(bad):
    with pytest.raises(D5bError):
        parse_rfc3339_ns(bad)
    with pytest.raises(D5bError):
        evaluate_inventory({"packages": []}, {}, bad, "strict")


def test_metadata_keys_are_pep503_normalised_and_collisions_rejected():
    meta = {"pypi": {"Zope.Interface": {"5.0": {"f.whl": "2023-03-01T00:00:00Z"}}}}
    res = evaluate_inventory({"packages": [_pkg("pypi", "zope_interface", "5.0")]}, meta, CUTOFF, "strict")
    assert res["result"] == "pass"
    assert res["counts"]["ok"] == 1
    clash = {"pypi": {"a_b": {}, "A.B": {}}}
    with pytest.raises(D5bError):
        evaluate_inventory({"packages": []}, clash, CUTOFF, "strict")


def test_pypi_named_file_absent_from_metadata_is_unknown():
    meta = _sample_metadata()
    inv = {"packages": [_pkg("pypi", "my-cool-pkg", "1.0.0", "my_cool_pkg-1.0.0-cp311-manylinux.whl")]}
    res = evaluate_inventory(inv, meta, CUTOFF, "strict")
    assert res["result"] == "gate"
    assert [e["file"] for e in res["unknown"]] == ["my_cool_pkg-1.0.0-cp311-manylinux.whl"]


def test_pypi_named_file_before_cutoff_passes_even_if_other_file_newer():
    meta = _sample_metadata()
    inv = {"packages": [_pkg("pypi", "my-cool-pkg", "1.0.0", "my_cool_pkg-1.0.0.tar.gz")]}
    res = evaluate_inventory(inv, meta, CUTOFF, "strict")
    assert res["result"] == "pass"


def test_unknown_version_and_unknown_ecosystem_entry_each_ecosystem():
    meta = _sample_metadata()
    inv = {
        "packages": [
            _pkg("pypi", "my-cool-pkg", "9.9"),
            _pkg("conda", "numpy", "9.9"),
            _pkg("npm", "left-pad", "9.9"),
            _pkg("crates", "serde", "9.9"),
            _pkg("crates", "no-such-crate", "1.0"),
        ]
    }
    res = evaluate_inventory(inv, meta, CUTOFF, "strict")
    assert res["result"] == "gate"
    assert res["counts"]["unknown"] == 5
    assert res["newer"] == []


def test_conda_milliseconds_conversion_exact():
    meta = {"conda": {"x": {"1": 1680307200000, "2": 1680307200001, "3": 1680307199999}}}
    inv = {"packages": [_pkg("conda", "x", "1"), _pkg("conda", "x", "2"), _pkg("conda", "x", "3")]}
    res = evaluate_inventory(inv, meta, CUTOFF, "strict")
    assert [e["version"] for e in res["newer"]] == ["2"]
    assert res["newer"][0]["release_time"] == "2023-04-01T00:00:00.001Z"
    for bad in (1680307200000.0, "1680307200000", True, -1):
        with pytest.raises(D5bError):
            evaluate_inventory({"packages": []}, {"conda": {"x": {"1": bad}}}, CUTOFF, "strict")


def test_repo_only_with_only_newer_warns_and_clean_inventory_passes():
    meta = _sample_metadata()
    res = evaluate_inventory({"packages": [_pkg("npm", "left-pad", "1.4.0")]}, meta, CUTOFF, "repo_only")
    assert res["result"] == "pass_with_warnings"
    assert len(res["newer"]) == 1
    res = evaluate_inventory({"packages": [_pkg("npm", "left-pad", "1.3.0")]}, meta, CUTOFF, "repo_only")
    assert res["result"] == "pass"
    with pytest.raises(D5bError):
        evaluate_inventory({"packages": []}, meta, CUTOFF, "lenient")


def test_exempt_packages_never_gate_and_are_reported_with_reason():
    meta = _sample_metadata()
    inv = {"packages": [_pkg("npm", "left-pad", "1.4.0"), _pkg("crates", "serde", "1.0.160")]}
    ex = {"exemptions": [{"ecosystem": "npm", "name": "left-pad", "version": "1.4.0", "reason": "vetted"}]}
    res = evaluate_inventory(inv, meta, CUTOFF, "strict", ex)
    assert res["result"] == "gate"
    assert [e["name"] for e in res["newer"]] == ["serde"]
    assert res["exempt"] == [
        {"ecosystem": "npm", "name": "left-pad", "version": "1.4.0", "file": None, "reason": "vetted"}
    ]
    dup = [ex["exemptions"][0], dict(ex["exemptions"][0])]
    with pytest.raises(D5bError):
        evaluate_inventory(inv, meta, CUTOFF, "strict", dup)
    with pytest.raises(D5bError):
        evaluate_inventory(inv, meta, CUTOFF, "strict", [{"ecosystem": "npm", "name": "x", "version": "1"}])


def test_report_shape_and_sort_order_independent_of_input_order():
    meta = _sample_metadata()
    pkgs = [
        _pkg("pypi", "my-cool-pkg", "2.0.0"),
        _pkg("npm", "left-pad", "1.4.0"),
        _pkg("crates", "serde", "1.0.160"),
        _pkg("conda", "numpy", "1.25.0"),
        _pkg("npm", "zzz", "1"),
        _pkg("npm", "aaa", "1"),
    ]
    a = evaluate_inventory({"packages": pkgs}, meta, CUTOFF, "strict")
    b = evaluate_inventory({"packages": list(reversed(pkgs))}, meta, CUTOFF, "strict")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert set(a) == {"mode", "cutoff", "result", "newer", "unknown", "exempt", "counts"}
    keys = [(e["ecosystem"], e["name"], e["version"]) for e in a["newer"]]
    assert keys == sorted(keys)
    assert [e["name"] for e in a["unknown"]] == ["aaa", "zzz"]
    assert a["counts"] == {"total": 6, "ok": 0, "newer": 4, "unknown": 2, "exempt": 0}


def test_hostile_inventory_shapes_rejected():
    meta = _sample_metadata()
    bad_inventories = [
        [],
        {"packages": {}},
        {"packages": [], "extra": 1},
        {"packages": [_pkg("gem", "a", "1")]},
        {"packages": [_pkg("npm", 1, "1")]},
        {"packages": [_pkg("npm", "a", "")]},
        {"packages": [_pkg("npm", "a", "1", 5)]},
        {"packages": [{"ecosystem": "npm", "name": "a", "version": "1"}]},
        {"packages": ["npm:a@1"]},
        {"packages": [_pkg("npm", "a", "1")] * (MAX_PACKAGES + 1)},
    ]
    for inv in bad_inventories:
        with pytest.raises(D5bError):
            evaluate_inventory(inv, meta, CUTOFF, "strict")
    bad_metadata = [
        [],
        {"rubygems": {}},
        {"npm": {"a": {"1": 5}}},
        {"npm": {"a": ["1"]}},
        {"pypi": {"a": {"1": {"f": None}}}},
        {"crates": {"a": {"1": "yesterday"}}},
    ]
    for m in bad_metadata:
        with pytest.raises(D5bError):
            evaluate_inventory({"packages": []}, m, CUTOFF, "strict")


def test_hostile_json_bytes_rejected():
    for raw in (
        b"\xff\xfe",
        b'{"packages": [}',
        b"[" * 100000 + b"]" * 100000,
        b'{"a": "' + b"x" * 5000 + b'"}',
        b'{"a\\u0000": 1}',
        b'{"packages": [{"name": "a", "name": "b"}]}',
    ):
        with pytest.raises(D5bError):
            load_json_bounded(raw, 4 * 1024 * 1024)


def _write_cli_inputs(tmp_path, inv):
    inv_path = tmp_path / "inv.json"
    meta_path = tmp_path / "meta.json"
    inv_path.write_text(json.dumps(inv), encoding="utf-8")
    meta_path.write_text(json.dumps(_sample_metadata()), encoding="utf-8")
    return str(inv_path), str(meta_path)


def test_cli_exit_zero_on_pass_and_one_on_error(tmp_path, capsys):
    inv_path, meta_path = _write_cli_inputs(tmp_path, {"packages": [_pkg("npm", "left-pad", "1.3.0")]})
    rc = cli_main(["--inventory", inv_path, "--metadata", meta_path, "--cutoff", CUTOFF, "--mode", "strict"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["result"] == "pass"
    rc = cli_main(["--inventory", inv_path, "--metadata", meta_path, "--cutoff", "bad", "--mode", "strict"])
    assert rc == 1
    rc = cli_main(["--inventory", inv_path, "--metadata", meta_path, "--cutoff", CUTOFF, "--mode", "x"])
    assert rc == 1
    rc = cli_main(["--inventory", inv_path, "--cutoff", CUTOFF, "--mode", "strict"])
    assert rc == 1
    rc = cli_main(["--inventory", str(tmp_path / "missing.json"), "--metadata", meta_path, "--cutoff", CUTOFF, "--mode", "strict"])
    err = capsys.readouterr().err
    assert rc == 1
    assert str(tmp_path) not in err


def test_cli_exemptions_file_and_pass_with_warnings_exit_zero(tmp_path, capsys):
    inv_path, meta_path = _write_cli_inputs(
        tmp_path, {"packages": [_pkg("npm", "left-pad", "1.4.0"), _pkg("npm", "nope", "1")]}
    )
    ex_path = tmp_path / "ex.json"
    ex_path.write_text(
        json.dumps([{"ecosystem": "npm", "name": "left-pad", "version": "1.4.0", "reason": "ok"}]), encoding="utf-8"
    )
    base = ["--inventory", inv_path, "--metadata", meta_path, "--cutoff", CUTOFF]
    rc = cli_main(base + ["--mode", "repo_only", "--exemptions", str(ex_path)])
    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert report["result"] == "pass_with_warnings"
    assert [e["name"] for e in report["exempt"]] == ["left-pad"]
    rc = cli_main(base + ["--mode", "strict", "--exemptions", str(ex_path)])
    assert rc == 2
