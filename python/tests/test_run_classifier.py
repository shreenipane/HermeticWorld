"""Tests for the run classifier and clock level (TR-CLS-1, TR-CLS-2, TR-VMM-3)."""

from __future__ import annotations

import copy
import json
import os

import pytest

from hermetic_classifier.run import (
    MAX_INPUT_BYTES,
    MAX_PROBE_RECORDS,
    REQUIRED_PROBES,
    RunEvidenceError,
    classification_to_json,
    classify_run,
    main,
    parse_evidence,
)

DIGEST = "sha256:" + "ab" * 32

GOLD = """\
diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,2 +1,4 @@
 def f(x):
-    return x
+    value = compute_the_answer(x)
+    return normalise_result(value, strict=True)
+    # trailing comment line
"""
DERIVED = """\
diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,2 +1,2 @@
 def f(x):
-    return x
+    return totally_different_approach(x) or fallback_value
"""


def probes(**override: str) -> list[dict]:
    recs = [{"probe": name, "result": "blocked", "detail": "d"} for name in sorted(REQUIRED_PROBES)]
    for rec in recs:
        if rec["probe"] == "clock_pairing_hc":
            rec["result"] = "unavailable"
    for rec in recs:
        if rec["probe"] in override:
            rec["result"] = override[rec["probe"]]
    return recs


def hidden_evidence(**changes) -> dict:
    ev = {
        "schema": "hermetic-run-evidence/v1",
        "run_digest": DIGEST,
        "substrate": "microvm",
        "world_sealed": True,
        "host": {"patched_firecracker": True, "hypercall_block": True},
        "clockprobe": probes(),
        "date_leak_observed": False,
        "sealcheck": {"blocked": False, "leak": False},
        "grader": {"r0": "pass", "r1": "clean", "r2": "clean", "r3": "clean"},
        "patches": {"agent": DERIVED, "gold": GOLD},
    }
    ev.update(changes)
    return ev


# --- clock levels ---------------------------------------------------------


def test_full_blocked_probe_with_host_filter_is_hidden():
    out = classify_run(hidden_evidence())
    assert out["clock"] == "hidden"
    assert out["clock_reasons"] == []
    assert out["status"] == "resolved"
    assert out["label"] == "derived"


def test_container_substrate_is_real():
    ev = hidden_evidence(substrate="container")
    del ev["host"], ev["clockprobe"]
    out = classify_run(ev)
    assert out["clock"] == "real"
    assert out["clock_reasons"] == ["container_substrate"]


@pytest.mark.parametrize(
    "host,reason",
    [
        ({"patched_firecracker": False, "hypercall_block": True}, "no_patched_firecracker"),
        ({"patched_firecracker": True, "hypercall_block": False}, "no_hypercall_block"),
        ({"patched_firecracker": True}, "no_hypercall_block"),
        (None, "no_patched_firecracker"),
    ],
)
def test_missing_host_filter_gives_faked(host, reason):
    ev = hidden_evidence(host=host)
    out = classify_run(ev)
    assert out["clock"] == "faked"
    assert reason in out["clock_reasons"]


def test_missing_probe_gives_faked():
    out = classify_run(hidden_evidence(clockprobe=None))
    assert out["clock"] == "faked"
    assert out["clock_reasons"] == ["probe_missing"]


@pytest.mark.parametrize("dropped", sorted(REQUIRED_PROBES))
def test_incomplete_probe_gives_faked(dropped):
    recs = [r for r in probes() if r["probe"] != dropped]
    out = classify_run(hidden_evidence(clockprobe=recs))
    assert out["clock"] == "faked"
    assert "probe_incomplete" in out["clock_reasons"]


@pytest.mark.parametrize("result", ["leak", "unavailable", "error"])
@pytest.mark.parametrize("name", sorted(REQUIRED_PROBES - {"clock_pairing_hc"}))
def test_any_record_not_blocked_gives_faked(name, result):
    out = classify_run(hidden_evidence(clockprobe=probes(**{name: result})))
    assert out["clock"] == "faked"
    want = "probe_leak" if result == "leak" else "probe_not_blocked"
    assert want in out["clock_reasons"]


def test_clock_pairing_unavailable_needs_blocked_canary():
    out = classify_run(hidden_evidence(clockprobe=probes(kernel_canary="error")))
    assert out["clock"] == "faked"
    assert out["clock_reasons"] == ["probe_not_blocked"]


@pytest.mark.parametrize("result", ["leak", "error"])
def test_clock_pairing_leak_or_error_gives_faked(result):
    out = classify_run(hidden_evidence(clockprobe=probes(clock_pairing_hc=result)))
    assert out["clock"] == "faked"


def test_duplicate_probe_record_gives_faked_even_if_both_blocked():
    recs = probes() + [{"probe": "rdtsc", "result": "blocked"}]
    out = classify_run(hidden_evidence(clockprobe=recs))
    assert out["clock"] == "faked"
    assert "probe_duplicate" in out["clock_reasons"]


def test_contradictory_duplicate_probe_record_gives_faked():
    recs = [{"probe": "rdtsc", "result": "leak"}] + probes()
    out = classify_run(hidden_evidence(clockprobe=recs))
    assert out["clock"] == "faked"
    assert {"probe_duplicate", "probe_leak"} <= set(out["clock_reasons"])


def test_unknown_probe_record_gives_faked():
    recs = probes() + [{"probe": "new_probe", "result": "blocked"}]
    out = classify_run(hidden_evidence(clockprobe=recs))
    assert out["clock"] == "faked"
    assert "probe_unknown_record" in out["clock_reasons"]


def test_date_leak_observed_gives_faked_and_review():
    out = classify_run(hidden_evidence(date_leak_observed=True))
    assert out["clock"] == "faked"
    assert out["clock_reasons"] == ["date_leak_observed"]
    assert out["status"] == "review"
    assert "date_leak_observed" in out["flags"]


def test_date_sentinel_absent_is_flagged_not_lowered():
    ev = hidden_evidence()
    del ev["date_leak_observed"]
    out = classify_run(ev)
    assert out["clock"] == "hidden"
    assert "date_sentinel_not_run" in out["flags"]


def test_container_with_microvm_evidence_is_contradictory():
    with pytest.raises(RunEvidenceError):
        classify_run(hidden_evidence(substrate="container"))


# --- labels and status ----------------------------------------------------


def test_retrieved_in_sealed_world_gives_review():
    out = classify_run(hidden_evidence(patches={"agent": GOLD, "gold": GOLD}))
    assert out["label"] == "retrieved"
    assert out["status"] == "review"
    assert {"retrieved_in_sealed_world", "gate_classifier_disagreement"} <= set(out["flags"])


def test_retrieved_in_unsealed_world_agreeing_gate_is_resolved():
    ev = hidden_evidence(
        world_sealed=False,
        patches={"agent": GOLD, "gold": GOLD},
        sealcheck={"blocked": False, "leak": True},
    )
    out = classify_run(ev)
    assert out["label"] == "retrieved"
    assert out["status"] == "resolved"


def test_gate_leak_but_derived_is_disagreement_review():
    out = classify_run(hidden_evidence(sealcheck={"blocked": False, "leak": True}))
    assert out["status"] == "review"
    assert out["flags"] == ["gate_classifier_disagreement"]


def test_success_without_patches_is_unclassified_review():
    ev = hidden_evidence()
    del ev["patches"]
    out = classify_run(ev)
    assert out["label"] is None
    assert out["status"] == "review"
    assert "unclassified_success" in out["flags"]


def test_failure_is_not_labelled():
    out = classify_run(hidden_evidence(grader={"r0": "fail", "r1": "clean", "r2": "clean", "r3": "clean"}))
    assert out["label"] is None
    assert out["status"] == "unresolved"


def test_missing_r0_is_never_resolved():
    out = classify_run(hidden_evidence(grader={}))
    assert out["status"] == "unresolved"
    assert "r0_missing" in out["flags"]


@pytest.mark.parametrize(
    "changes,status",
    [
        ({"sealcheck": {"blocked": True}, "grader": {}, "infra_error": True}, "gate_blocked"),
        ({"infra_error": True, "netvm_malformed_frame": True}, "infra_error"),
        ({"netvm_malformed_frame": True, "limit_exceeded": True}, "tampered"),
        ({"grader": {"r0": "pass", "r1": "tripped"}}, "tampered"),
        ({"grader": {"r0": "pass", "r1": "clean", "r2": "tripped"}}, "tampered"),
        ({"limit_exceeded": True, "date_leak_observed": True}, "limit_exceeded"),
        ({"grader": {"r0": "pass", "r1": "clean", "r2": "clean", "r3": "tripped"}}, "review"),
    ],
)
def test_status_precedence(changes, status):
    assert classify_run(hidden_evidence(**changes))["status"] == status


def test_unrun_checks_are_flagged():
    out = classify_run(hidden_evidence(grader={"r0": "pass"}))
    assert {"r1_not_run", "r2_not_run", "r3_not_run"} <= set(out["flags"])


def test_gate_blocked_with_grader_verdict_is_contradictory():
    with pytest.raises(RunEvidenceError):
        classify_run(hidden_evidence(sealcheck={"blocked": True}))


# --- determinism ----------------------------------------------------------


def test_known_answer_json():
    out = classification_to_json(classify_run(hidden_evidence(clockprobe=None)))
    assert out == (
        '{"clock":"faked","clock_reasons":["probe_missing"],"confidence":'
        + str(classify_run(hidden_evidence())["confidence"])
        + ',"flags":[],"label":"derived","run_digest":"'
        + DIGEST
        + '","schema":"hermetic-run-classification/v1","status":"resolved"}'
    )


def test_record_order_does_not_change_output():
    ev = hidden_evidence(clockprobe=list(reversed(probes(rdtsc="leak"))))
    assert classify_run(ev) == classify_run(hidden_evidence(clockprobe=probes(rdtsc="leak")))


def test_input_is_not_mutated():
    ev = hidden_evidence()
    before = copy.deepcopy(ev)
    classify_run(ev)
    assert ev == before


# --- hostile input --------------------------------------------------------


@pytest.mark.parametrize("key", ["schema", "run_digest", "substrate", "world_sealed"])
def test_missing_required_field_raises(key):
    ev = hidden_evidence()
    del ev[key]
    with pytest.raises(RunEvidenceError):
        classify_run(ev)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": "hermetic-run-evidence/v2"},
        {"run_digest": "sha256:xyz"},
        {"substrate": "docker"},
        {"world_sealed": "yes"},
        {"world_sealed": 1},
        {"host": {"patched_firecracker": "true", "hypercall_block": True}},
        {"host": {"patched_firecracker": True, "extra": True}},
        {"clockprobe": {"rdtsc": "blocked"}},
        {"clockprobe": [{"probe": "rdtsc"}]},
        {"clockprobe": [{"probe": "rdtsc", "result": "BLOCKED"}]},
        {"clockprobe": [{"probe": "rdtsc", "result": "blocked", "x": 1}]},
        {"clockprobe": [{"probe": "r" * 65, "result": "blocked"}]},
        {"clockprobe": [{"probe": "rdtsc", "result": "blocked", "detail": "d" * 5000}]},
        {"clockprobe": [{"probe": "rdtsc", "result": "blocked"}] * (MAX_PROBE_RECORDS + 1)},
        {"date_leak_observed": "no"},
        {"grader": {"r0": "passed"}},
        {"grader": {"r0": "pass", "r4": "clean"}},
        {"patches": {"agent": DERIVED}},
        {"patches": {"agent": 1, "gold": GOLD}},
        {"unknown": True},
    ],
)
def test_malformed_fields_raise(changes):
    with pytest.raises(RunEvidenceError):
        classify_run(hidden_evidence(**changes))


def test_malformed_patch_raises_classifier_error():
    from hermetic_classifier import ClassifierError

    with pytest.raises(ClassifierError):
        classify_run(hidden_evidence(patches={"agent": "\x00garbage", "gold": GOLD}))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a": 1, "a": 2}',
        b'{"x": 1.5}',
        b'{"x": NaN}',
        b"[1, 2]",
        b"not json",
        b"\xff\xfe",
        b"[" * 100000 + b"]" * 100000,
        b'{"a":' * 20 + b"1" + b"}" * 20,
    ],
)
def test_parse_evidence_rejects_hostile_json(raw):
    with pytest.raises(RunEvidenceError):
        parse_evidence(raw)


def test_parse_evidence_rejects_oversized():
    with pytest.raises(RunEvidenceError):
        parse_evidence(b" " * (MAX_INPUT_BYTES + 1))


def test_duplicate_key_in_nested_record_raises():
    raw = json.dumps(hidden_evidence()).replace(
        '"probe": "cpuid"', '"probe": "cpuid", "probe": "rdtsc"', 1
    )
    with pytest.raises(RunEvidenceError):
        parse_evidence(raw)


# --- CLI ------------------------------------------------------------------


def test_cli_prints_classification(tmp_path, capsys):
    path = tmp_path / "ev.json"
    path.write_text(json.dumps(hidden_evidence()))
    assert main([str(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["clock"] == "hidden"


def test_cli_errors(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema": 1}')
    link = tmp_path / "link.json"
    good = tmp_path / "good.json"
    good.write_text(json.dumps(hidden_evidence()))
    os.symlink(good, link)
    assert main([]) == 1
    assert main([str(bad)]) == 1
    assert main([str(link)]) == 1
    assert main([str(tmp_path / "missing.json")]) == 1
    assert main([str(tmp_path)]) == 1
    capsys.readouterr()
