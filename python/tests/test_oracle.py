
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

