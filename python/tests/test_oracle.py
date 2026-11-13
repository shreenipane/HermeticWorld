
import json

import pytest



from hermetic_oracle.analyse import OracleError, analyse_oracle_runs

from hermetic_oracle.__main__ import main as cli_main





def _make_runs(base_runs, gold_runs):

    out = []

    for idx, res in enumerate(base_runs, start=1):

        out.append({"tree": "base", "run": idx, "results": dict(res)})

    for idx, res in enumerate(gold_runs, start=1):

        out.append({"tree": "gold", "run": idx, "results": dict(res)})

    return out





def test_valid_oracle_and_error_missing_treated_as_failed():

    # t1 has failed, error, missing on base -> all normalize to "failed", so NOT flaky

    base = [

        {"t1": "failed", "t2": "passed"},

        {"t1": "error", "t2": "passed"},

        {"t1": "missing", "t2": "passed"},

    ]

    gold = [

        {"t1": "passed", "t2": "passed"},

        {"t1": "passed", "t2": "passed"},

        {"t1": "passed", "t2": "passed"},

    ]

    report = analyse_oracle_runs(_make_runs(base, gold), ["t1"], ["t2"])

    assert report["result"] == "valid"

    assert report["flaky"] == []

    assert report["violations"] == []





def test_flaky_detection_in_both_directions():

    # t_flaky_b flips on base; t_flaky_g flips on gold; 5 total f2p so 1 flaky is 200 permille (valid)

    base = [

        {"f1": "failed", "f2": "failed", "f3": "failed", "f4": "failed", "f5": "failed", "p1": "passed"},

        {"f1": "passed", "f2": "failed", "f3": "failed", "f4": "failed", "f5": "failed", "p1": "passed"},

        {"f1": "failed", "f2": "failed", "f3": "failed", "f4": "failed", "f5": "failed", "p1": "passed"},

    ]

    gold = [

        {"f1": "passed", "f2": "passed", "f3": "passed", "f4": "passed", "f5": "passed", "p1": "passed"},

        {"f1": "passed", "f2": "passed", "f3": "passed", "f4": "passed", "f5": "passed", "p1": "failed"},

        {"f1": "passed", "f2": "passed", "f3": "passed", "f4": "passed", "f5": "passed", "p1": "passed"},

    ]

    report = analyse_oracle_runs(

        _make_runs(base, gold),

        ["f1", "f2", "f3", "f4", "f5"],

        ["p1"],

    )

    assert report["result"] == "valid"

    assert report["flaky_base"] == ["f1"]

    assert report["flaky_gold"] == ["p1"]

    assert report["flaky"] == ["f1", "p1"]





def test_all_five_violation_kinds():

    base = [

        {

            "f_ok": "failed",

            "f_pass_base": "passed",

            "f_fail_gold": "failed",

            "p_fail_base": "failed",

            "p_fail_gold": "passed",

        }

    ] * 3

    gold = [

        {

            "f_ok": "passed",

            "f_pass_base": "passed",

            "f_fail_gold": "failed",

            "p_fail_base": "passed",

            "p_fail_gold": "failed",

        }

    ] * 3

    report = analyse_oracle_runs(

        _make_runs(base, gold),

        ["f_ok", "f_pass_base", "f_fail_gold"],

        ["p_fail_base", "p_fail_gold", "p_missing"],

    )

    assert report["result"] == "invalid"

    kinds = {v["test"]: v["kind"] for v in report["violations"]}

    assert kinds == {

        "f_pass_base": "f2p_passes_on_base",

        "f_fail_gold": "f2p_fails_on_gold",

        "p_fail_base": "p2p_fails_on_base",

        "p_fail_gold": "p2p_fails_on_gold",

        "p_missing": "declared_test_missing",

    }





def test_threshold_boundary_exact_vs_one_above():

    # 5 F2P tests: 1 flaky = 200 permille (exact boundary -> valid)

    # 4 F2P tests: 1 flaky = 250 permille (above 200 permille -> unusable)

    f_ids_5 = ["f1", "f2", "f3", "f4", "f5"]

    base_5 = [

        {"f1": "failed", "f2": "failed", "f3": "failed", "f4": "failed", "f5": "failed"},

        {"f1": "passed", "f2": "failed", "f3": "failed", "f4": "failed", "f5": "failed"},

        {"f1": "failed", "f2": "failed", "f3": "failed", "f4": "failed", "f5": "failed"},

    ]

    gold_5 = [

        {"f1": "passed", "f2": "passed", "f3": "passed", "f4": "passed", "f5": "passed"}

    ] * 3

    res_at = analyse_oracle_runs(_make_runs(base_5, gold_5), f_ids_5, [])

    assert res_at["result"] == "valid"



    res_above = analyse_oracle_runs(_make_runs(base_5, gold_5), ["f1", "f2", "f3", "f4"], [])

    assert res_above["result"] == "unusable"

    assert res_above["deciding_rule"] == "rule_3_f2p_flaky_or_missing_exceeds_threshold"





def test_malformed_run_sets_and_hostile_inputs():

    base = [{"f1": "failed"}] * 3

    gold = [{"f1": "passed"}] * 3

    runs = _make_runs(base, gold)

    runs[5]["run"] = 2

    with pytest.raises(OracleError):

        analyse_oracle_runs(runs, ["f1"], [])



    with pytest.raises(OracleError):

        analyse_oracle_runs(_make_runs(base, gold)[:5], ["f1"], [])



    with pytest.raises(OracleError):

        analyse_oracle_runs(_make_runs(base, gold), ["f1"], ["f1"])





def test_cli_and_determinism(tmp_path, capsys):

    base = [{"f1": "failed", "p1": "passed"}] * 3

    gold = [{"f1": "passed", "p1": "passed"}] * 3

    runs = _make_runs(base, gold)

    run_files = []

    for idx, r in enumerate(runs):

        p = tmp_path / f"run_{idx}.json"

        p.write_text(json.dumps(r), encoding="utf-8")

        run_files.append(str(p))

    f2p_file = tmp_path / "f2p.json"

    p2p_file = tmp_path / "p2p.json"

    f2p_file.write_text(json.dumps(["f1"]), encoding="utf-8")

    p2p_file.write_text(json.dumps(["p1"]), encoding="utf-8")



    rc1 = cli_main(["--runs", *run_files, "--f2p", str(f2p_file), "--p2p", str(p2p_file)])

    out1 = capsys.readouterr().out

    rc2 = cli_main(["--runs", *reversed(run_files), "--f2p", str(f2p_file), "--p2p", str(p2p_file)])

    out2 = capsys.readouterr().out

    assert rc1 == 0

    assert rc2 == 0

    assert out1 == out2



# ---------------------------------------------------------------------------
# Requirement coverage added in review.
# ---------------------------------------------------------------------------

import os
import threading

from hermetic_oracle.analyse import (
    MAX_DECLARED_TESTS,
    MAX_TESTS_PER_RUN,
    load_json_bounded,
    run_oracle_from_paths,
    safe_read_bytes,
)


def _const_runs(base_res, gold_res):
    return _make_runs([base_res] * 3, [gold_res] * 3)


def test_fifo_input_refused_without_blocking(tmp_path):
    fifo = tmp_path / "run.fifo"
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
    assert isinstance(box.get("exc"), OracleError)


def test_symlink_and_device_inputs_refused(tmp_path):
    real = tmp_path / "f2p.json"
    real.write_text('["t"]', encoding="utf-8")
    link = tmp_path / "link.json"
    os.symlink(real, link)
    with pytest.raises(OracleError):
        safe_read_bytes(str(link), 1024)
    with pytest.raises(OracleError):
        safe_read_bytes("/dev/null", 1024)


def test_flaky_on_base_from_pass_to_fail_and_on_gold_from_fail_to_pass():
    base = [{"a": "failed", "b": "failed", "c": "failed", "d": "failed", "e": "failed"}] * 3
    gold = [
        {"a": "passed", "b": "passed", "c": "passed", "d": "passed", "e": "failed"},
        {"a": "passed", "b": "passed", "c": "passed", "d": "passed", "e": "passed"},
        {"a": "passed", "b": "passed", "c": "passed", "d": "passed", "e": "passed"},
    ]
    rep = analyse_oracle_runs(_make_runs(base, gold), ["a", "b", "c", "d", "e"], [])
    assert rep["flaky_gold"] == ["e"]
    assert rep["flaky_base"] == []
    # The flaky test is excluded from comparisons: no violation for "e".
    assert rep["violations"] == []
    assert rep["result"] == "valid"


def test_skipped_versus_passed_is_flaky_but_error_versus_missing_is_not():
    base = [
        {"f": "failed", "p": "passed", "q": "error"},
        {"f": "failed", "p": "skipped", "q": "missing"},
        {"f": "failed", "p": "passed", "q": "failed"},
    ]
    gold = [{"f": "passed", "p": "passed", "q": "passed"}] * 3
    rep = analyse_oracle_runs(_make_runs(base, gold), ["f", "q"], ["p"])
    assert rep["flaky"] == ["p"]
    assert rep["result"] == "valid"


def test_flaky_p2p_violation_is_suppressed():
    base = [{"f": "failed", "p": "failed"}, {"f": "failed", "p": "passed"}, {"f": "failed", "p": "failed"}]
    gold = [{"f": "passed", "p": "passed"}] * 3
    rep = analyse_oracle_runs(_make_runs(base, gold), ["f"], ["p"])
    assert rep["flaky"] == ["p"]
    assert rep["violations"] == []


def test_skipped_f2p_and_p2p_count_as_violations():
    rep = analyse_oracle_runs(
        _const_runs({"f1": "skipped", "f2": "failed", "p": "skipped"}, {"f1": "passed", "f2": "skipped", "p": "passed"}),
        ["f1", "f2"],
        ["p"],
    )
    assert rep["result"] == "invalid"
    assert rep["deciding_rule"] == "rule_2_oracle_validity_violation"
    assert rep["violations"] == [
        {"test": "f1", "kind": "f2p_passes_on_base"},
        {"test": "f2", "kind": "f2p_fails_on_gold"},
        {"test": "p", "kind": "p2p_fails_on_base"},
    ]


def test_declared_test_missing_on_gold_only_and_f2p_missing_counts_toward_threshold():
    rep = analyse_oracle_runs(
        _const_runs({"f1": "failed", "f2": "failed"}, {"f1": "passed"}),
        ["f1", "f2"],
        [],
    )
    assert rep["missing_declared"] == ["f2"]
    assert {"test": "f2", "kind": "declared_test_missing"} in rep["violations"]
    # 1 of 2 F2P missing = 500 permille > 200 permille.
    assert rep["result"] == "unusable"
    assert rep["counts"]["f2p_flaky_or_missing"] == 1


def test_threshold_uses_integer_permille_at_custom_boundary():
    ids = [f"f{i}" for i in range(7)]
    base = {t: "failed" for t in ids}
    gold = {t: "passed" for t in ids}
    del gold["f0"]
    runs = _const_runs(base, gold)
    # 1/7 = 142.857 permille: exactly-at is impossible; 142 is below it, 143 above.
    assert analyse_oracle_runs(runs, ids, [], max_bad_f2p_permille=142)["result"] == "unusable"
    assert analyse_oracle_runs(runs, ids, [], max_bad_f2p_permille=143)["result"] == "invalid"
    # 1/5 = 200 permille exactly: at the threshold is not "more than".
    ids5 = ids[:5]
    runs5 = _const_runs({t: "failed" for t in ids5}, {t: "passed" for t in ids5 if t != "f0"})
    assert analyse_oracle_runs(runs5, ids5, [], max_bad_f2p_permille=200)["result"] == "invalid"
    assert analyse_oracle_runs(runs5, ids5, [], max_bad_f2p_permille=199)["result"] == "unusable"
    for bad in (0.2, True, -1, 1001, "200"):
        with pytest.raises(OracleError):
            analyse_oracle_runs(runs5, ids5, [], max_bad_f2p_permille=bad)


def test_report_has_sorted_lists_counts_and_rule():
    rep = analyse_oracle_runs(
        _const_runs({"z": "passed", "a": "passed", "f": "failed"}, {"z": "failed", "a": "failed", "f": "passed"}),
        ["f"],
        ["z", "a"],
    )
    assert [v["test"] for v in rep["violations"]] == ["a", "z"]
    assert rep["counts"] == {
        "f2p_total": 1,
        "p2p_total": 2,
        "flaky_total": 0,
        "f2p_flaky_or_missing": 0,
        "violations_total": 2,
        "threshold_permille": 200,
    }
    assert rep["deciding_rule"] == "rule_2_oracle_validity_violation"
    ok = analyse_oracle_runs(_const_runs({"f": "failed"}, {"f": "passed"}), ["f"], [])
    assert ok["deciding_rule"] == "rule_2_all_non_flaky_declared_tests_valid"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.__setitem__(0, dict(r[0], tree="head")),
        lambda r: r.__setitem__(0, dict(r[0], run=4)),
        lambda r: r.__setitem__(0, dict(r[0], run=0)),
        lambda r: r.__setitem__(0, dict(r[0], run="1")),
        lambda r: r.__setitem__(0, dict(r[0], run=True)),
        lambda r: r.__setitem__(0, dict(r[0], run=1.0)),
        lambda r: r.__setitem__(3, dict(r[3], tree="base")),
        lambda r: r.__setitem__(0, dict(r[0], extra=1)),
        lambda r: r.__setitem__(0, {"tree": "base", "run": 1}),
        lambda r: r.__setitem__(0, dict(r[0], results=[])),
        lambda r: r.__setitem__(0, dict(r[0], results={"f": "xfail"})),
        lambda r: r.__setitem__(0, dict(r[0], results={"f": None})),
        lambda r: r.__setitem__(0, dict(r[0], results={"": "passed"})),
        lambda r: r.append(dict(r[0])),
        lambda r: r.__setitem__(0, "base-run-1"),
    ],
)
def test_malformed_run_sets_rejected(mutate):
    runs = _const_runs({"f": "failed"}, {"f": "passed"})
    mutate(runs)
    with pytest.raises(OracleError):
        analyse_oracle_runs(runs, ["f"], [])


def test_malformed_declared_lists_rejected():
    runs = _const_runs({"f": "failed"}, {"f": "passed"})
    for f2p, p2p in (
        ({"f": 1}, []),
        (["f", "f"], []),
        (["f", 3], []),
        (["f", ""], []),
        ([], []),
        (["f"], "p"),
        (["f"] + [f"x{i}" for i in range(MAX_DECLARED_TESTS)], []),
    ):
        with pytest.raises(OracleError):
            analyse_oracle_runs(runs, f2p, p2p)


def test_oversized_results_map_rejected():
    big = {f"t{i}": "passed" for i in range(MAX_TESTS_PER_RUN + 1)}
    runs = _const_runs({"f": "failed"}, {"f": "passed"})
    runs[0]["results"] = big
    with pytest.raises(OracleError):
        analyse_oracle_runs(runs, ["f"], [])


def test_hostile_json_bytes_rejected():
    for raw in (
        b'{"tree": "base", "tree": "gold", "run": 1, "results": {}}',
        b'{"results": {"t": "passed", "t": "failed"}}',
        b"[" * 100000 + b"]" * 100000,
        b"\xc3\x28",
        b'{"run": 1',
        b'["' + b"x" * 5000 + b'"]',
    ):
        with pytest.raises(OracleError):
            load_json_bounded(raw, 1024 * 1024)
    with pytest.raises(OracleError):
        load_json_bounded(b"[]" + b" " * 100, 10)


def test_run_files_from_paths_oversized_and_wrong_count(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    lst = tmp_path / "l.json"
    lst.write_text('["f"]', encoding="utf-8")
    with pytest.raises(OracleError):
        run_oracle_from_paths([str(big)] * 6, str(lst), str(lst))
    with pytest.raises(OracleError):
        run_oracle_from_paths([str(lst)] * 5, str(lst), str(lst))


def _write_run_files(tmp_path, runs):
    paths = []
    for idx, r in enumerate(runs):
        p = tmp_path / f"r{idx}.json"
        p.write_text(json.dumps(r), encoding="utf-8")
        paths.append(str(p))
    return paths


def test_cli_exit_two_for_invalid_and_unusable_one_for_error(tmp_path, capsys):
    f2p = tmp_path / "f2p.json"
    p2p = tmp_path / "p2p.json"
    f2p.write_text('["f"]', encoding="utf-8")
    p2p.write_text("[]", encoding="utf-8")
    invalid = _write_run_files(tmp_path, _const_runs({"f": "passed"}, {"f": "passed"}))
    rc = cli_main(["--runs", *invalid, "--f2p", str(f2p), "--p2p", str(p2p)])
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["result"] == "invalid"
    unusable = _write_run_files(tmp_path, _make_runs([{"f": "failed"}] * 3, [{"f": "passed"}, {"f": "failed"}, {"f": "passed"}]))
    rc = cli_main(["--runs", *unusable, "--f2p", str(f2p), "--p2p", str(p2p)])
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["result"] == "unusable"
    dup = _write_run_files(tmp_path, _const_runs({"f": "failed"}, {"f": "passed"}))
    rc = cli_main(["--runs", dup[0], dup[0], *dup[2:], "--f2p", str(f2p), "--p2p", str(p2p)])
    assert rc == 1
    rc = cli_main(["--runs", *dup[:5], "--f2p", str(f2p), "--p2p", str(p2p)])
    assert rc == 1
    err = capsys.readouterr().err
    assert str(tmp_path) not in err
