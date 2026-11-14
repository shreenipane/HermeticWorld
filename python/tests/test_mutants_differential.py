"""Tests for the differential grading orchestration (TR-GR-6, TR-GR-7)."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path

import pytest

from hermetic_mutants.differential import (
    DISK_BYTES,
    CommandRunner,
    DifferentialError,
    DiskTamper,
    GradingPlan,
    RunRequest,
    RunResult,
    aggregate,
    build_plan,
    build_requests,
    decode_disk,
    encode_disk,
    run_differential,
)
from hermetic_mutants.finder import find_base_failing_sites
from hermetic_mutants.validate import validate_and_select
from tests.mutants_fixture import (
    SOURCE, TEST_FILE, base_log, exec_runner, exec_tests, nodeid, work,
)

VS = "a" * 64
T = "tests/t.py::test_a"


def _res(run="R0", tests=None, exit="clean", vs=VS):
    tests = {T: "passed"} if tests is None else tests
    n = len(tests)
    return RunResult(run, vs, tests, exit, n, n)


def test_disk_known_answer_layout() -> None:
    img = encode_disk(_res())
    payload = (
        '{"run":"R0","variant_set":"' + VS + '","tests":{"tests/t.py::test_a":"passed"},'
        '"supervisor":{"exit":"clean","tests_started":1,"tests_finished":1}}'
    ).encode()
    assert len(img) == DISK_BYTES
    assert img[:12] == b"HGRD\x00\x01\x00\x00" + len(payload).to_bytes(4, "big")
    assert img[12:44] == hashlib.sha256(payload).digest()
    assert img[44:44 + len(payload)] == payload
    assert decode_disk(img) == _res()


def _with_payload(payload: bytes, digest: bytes | None = None) -> bytes:
    d = hashlib.sha256(payload).digest() if digest is None else digest
    head = b"HGRD\x00\x01\x00\x00" + len(payload).to_bytes(4, "big") + d
    return head + payload + bytes(DISK_BYTES - 44 - len(payload))


def _payload(**over) -> bytes:
    obj = {"run": "R0", "variant_set": VS, "tests": {T: "passed"},
           "supervisor": {"exit": "clean", "tests_started": 1, "tests_finished": 1}}
    obj.update(over)
    return json.dumps(obj, separators=(",", ":")).encode()


GOOD = encode_disk(_res())


@pytest.mark.parametrize(
    "image,reason",
    [
        (GOOD[:-1], "invalid_disk_size"),
        (b"XGRD" + GOOD[4:], "bad_magic"),
        (GOOD[:4] + b"\x00\x02" + GOOD[6:], "unsupported_version"),
        (GOOD[:6] + b"\x00\x01" + GOOD[8:], "non_zero_flags"),
        (GOOD[:8] + (DISK_BYTES).to_bytes(4, "big") + GOOD[12:], "payload_length_exceeds_cap"),
        (GOOD[:12] + bytes(32) + GOOD[44:], "payload_hash_mismatch"),
        (GOOD[:-1] + b"\x01", "non_zero_padding"),
        (_with_payload(b"\xff\xfe"), "invalid_utf8"),
        (_with_payload(b"{not json"), "invalid_json"),
        (_with_payload(b'{"run":"R0","run":"R0"}'), "duplicate_json_key"),
        (_with_payload(_payload(extra=1)), "invalid_json"),
        (_with_payload(_payload(run="R9")), "invalid_json"),
        (_with_payload(_payload(variant_set="A" * 64)), "invalid_variant_set"),
        (_with_payload(_payload(tests={"bad\nid": "passed"})), "invalid_node_id"),
        (_with_payload(_payload(tests={T: "PASSED"})), "invalid_json"),
        (_with_payload(_payload(supervisor={"exit": "clean", "tests_started": 0,
                                            "tests_finished": 1})), "inconsistent_counts"),
        (_with_payload(_payload(supervisor={"exit": "clean", "tests_started": True,
                                            "tests_finished": 1})), "invalid_json"),
        (_with_payload(_payload(supervisor={"exit": "clean", "tests_started": 1,
                                            "tests_finished": 1.0})), "invalid_json"),
        (_with_payload(json.dumps(json.loads(_payload())).encode()), "non_canonical_json"),
        (_with_payload(b'{"tests":{},"run":"R0","variant_set":"' + VS.encode()
                       + b'","supervisor":{"exit":"clean","tests_started":0,'
                       b'"tests_finished":0}}'), "non_canonical_json"),
    ],
)
def test_decode_disk_hostile_images(image: bytes, reason: str) -> None:
    with pytest.raises(DiskTamper) as err:
        decode_disk(image)
    assert err.value.reason == reason


F2P = nodeid("test_add")
P2P = nodeid("test_double")


def _plan(**over):
    base = dict(f2p=frozenset({F2P}), p2p=frozenset({P2P}), mutated=frozenset({F2P}),
                equivalents={F2P: F2P, P2P: P2P})
    base.update(over)
    return GradingPlan(**base)


def _reqs(with_r3=False):
    return {r.run_id: r for r in build_requests("o", "m", "e", with_r3=with_r3)}


def _ok(run_id, tests, reqs, exit="clean"):
    n = len(tests)
    return RunResult(run_id, reqs[run_id].variant_set, tests, exit, n, n)


def _honest(reqs, r3=None):
    out = {
        "R0": _ok("R0", {F2P: "passed", P2P: "passed"}, reqs),
        "R1": _ok("R1", {F2P: "failed", P2P: "passed"}, reqs),
        "R2": _ok("R2", {F2P: "passed", P2P: "passed"}, reqs),
    }
    if r3 is not None:
        out["R3"] = _ok("R3", r3, reqs)
    return out


def test_aggregate_resolved_and_classifier_fields() -> None:
    reqs = _reqs(with_r3=True)
    v = aggregate(_honest(reqs, r3={F2P: "failed", P2P: "passed"}), reqs, _plan())
    assert (v.status, v.reasons) == ("resolved", ())
    assert json.loads(v.to_json())["grader"] == {"r0": "pass", "r1": "clean", "r2": "clean",
                                                 "r3": "clean"}


def test_aggregate_mutant_passed_is_tampered() -> None:
    reqs = _reqs()
    out = _honest(reqs)
    out["R1"] = _ok("R1", {F2P: "passed", P2P: "passed"}, reqs)
    v = aggregate(out, reqs, _plan())
    assert v.status == "tampered" and v.reasons == ("mutant_passed",) and v.r1 == "tripped"


@pytest.mark.parametrize("r2_tests", [{F2P: "failed", P2P: "passed"}, {P2P: "passed"}])
def test_aggregate_equivalence_mismatch_or_missing_is_tampered(r2_tests) -> None:
    reqs = _reqs()
    out = _honest(reqs)
    out["R2"] = _ok("R2", r2_tests, reqs)
    v = aggregate(out, reqs, _plan())
    assert v.status == "tampered" and "equivalence_mismatch" in v.reasons


def test_aggregate_unresolved_and_precedence() -> None:
    reqs = _reqs()
    out = _honest(reqs)
    out["R0"] = _ok("R0", {F2P: "failed", P2P: "error"}, reqs)
    out["R2"] = _ok("R2", {F2P: "failed", P2P: "error"}, reqs)
    v = aggregate(out, reqs, _plan())
    assert (v.status, v.reasons, v.r0) == ("unresolved", ("f2p_failed", "p2p_failed"), "fail")
    out["R1"] = _ok("R1", {F2P: "passed"}, reqs)
    assert aggregate(out, reqs, _plan()).status == "tampered"


@pytest.mark.parametrize("exit,reason", [("timeout", "supervisor_timeout"),
                                         ("crash", "supervisor_crash")])
def test_aggregate_r0_supervisor_failure_is_infra(exit, reason) -> None:
    reqs = _reqs()
    out = _honest(reqs)
    out["R0"] = _ok("R0", {F2P: "passed", P2P: "passed"}, reqs, exit=exit)
    v = aggregate(out, reqs, _plan())
    assert v.status == "infra_error" and reason in v.reasons


def test_aggregate_r3_advisory_review_including_empty_f2p() -> None:
    reqs = _reqs(with_r3=True)
    v = aggregate(_honest(reqs, r3={F2P: "passed", P2P: "passed"}), reqs, _plan())
    assert (v.status, v.reasons, v.r3) == ("review", ("fix_removal_passed",), "tripped")
    v2 = aggregate(_honest(reqs, r3={}), reqs, _plan(f2p=frozenset()))
    assert v2.status == "review"
    no_r3 = _reqs()
    assert aggregate(_honest(no_r3), no_r3, _plan()).r3 is None


def test_aggregate_slot_and_digest_mismatch_are_tampered() -> None:
    reqs = _reqs()
    out = _honest(reqs)
    out["R2"] = _ok("R1", {F2P: "passed", P2P: "passed"}, {"R1": reqs["R2"]})
    v = aggregate(out, reqs, _plan())
    assert v.status == "tampered" and v.reasons == ("run_id_mismatch",)
    out = _honest(reqs)
    out["R1"] = RunResult("R1", reqs["R2"].variant_set, {F2P: "failed"}, "clean", 1, 1)
    v = aggregate(out, reqs, _plan())
    assert v.runs["R1"] == "tamper:variant_set_mismatch" and v.status == "tampered"


def test_aggregate_runner_error_timeout_tamper_and_invalid_plan() -> None:
    reqs = _reqs()
    out = _honest(reqs)
    out["R1"] = "runner_error"
    out["R2"] = "timeout"
    v = aggregate(out, reqs, _plan())
    assert v.status == "infra_error" and v.reasons == ("run_timeout", "runner_error")
    assert v.r1 is None and v.r2 is None
    out["R2"] = DiskTamper("bad_magic")
    v = aggregate(out, reqs, _plan())
    assert v.status == "tampered" and v.runs["R2"] == "tamper:bad_magic"
    v = aggregate(_honest(reqs), reqs, _plan(f2p=frozenset({"bad\nid"})))
    assert v.status == "infra_error" and "invalid_plan" in v.reasons


def test_run_differential_runs_in_parallel() -> None:
    barrier = threading.Barrier(3, timeout=10)
    reqs = _reqs()
    honest = _honest(reqs)

    def runner(req):
        barrier.wait()  # breaks (runner_error) unless all three run at once
        return encode_disk(honest[req.run_id])

    v = run_differential(list(reqs.values()), _plan(), runner, timeout_s=30)
    assert v.status == "resolved"


def test_run_differential_timeout_and_bad_returns() -> None:
    release = threading.Event()
    reqs = _reqs()
    honest = _honest(reqs)

    def runner(req):
        if req.run_id == "R1":
            release.wait(30)
        if req.run_id == "R2":
            return "not bytes"
        return encode_disk(honest[req.run_id])

    try:
        v = run_differential(list(reqs.values()), _plan(), runner, timeout_s=0.5)
    finally:
        release.set()
    assert v.runs == {"R0": "ok", "R1": "timeout", "R2": "runner_error"}
    assert v.status == "infra_error"


def test_run_differential_rejects_bad_requests() -> None:
    reqs = build_requests("o", "m", "e", with_r3=False)
    with pytest.raises(DifferentialError):
        run_differential(reqs[:2], _plan(), lambda r: b"", timeout_s=1)
    with pytest.raises(DifferentialError):
        run_differential(reqs + [reqs[0]], _plan(), lambda r: b"", timeout_s=1)
    with pytest.raises(DifferentialError):
        run_differential(reqs, _plan(), lambda r: b"", timeout_s=0)


# --- end to end with fakes: finder -> validation -> R0/R1/R2 ----------------


def _selection():
    found = find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, range(1, 14))
    return validate_and_select(SOURCE.encode(), TEST_FILE, "5eed", found.eligible_sites,
                               exec_runner)


def _grade(agent):
    """``agent(req, honest_tests)`` returns the tests map the forged run reports."""
    sel = _selection()
    reqs = build_requests(SOURCE, sel.r1_text, sel.r2_text, with_r3=False)
    plan = build_plan([nodeid("test_add"), nodeid("test_add_neg")], [nodeid("test_double")],
                      sel.mutated_tests, sel.compared_tests)

    def runner(req):
        tests = agent(req, exec_tests(req.test_text, work("gold") if req.run_id != "R3"
                                      else work("base")))
        n = len(tests)
        return encode_disk(RunResult(req.run_id, req.variant_set, tests, "clean", n, n))

    return run_differential(reqs, plan, runner, timeout_s=30)


def test_end_to_end_honest_fix_is_resolved() -> None:
    v = _grade(lambda req, honest: honest)
    assert v.status == "resolved", v


def test_end_to_end_blanket_forger_caught_by_r1() -> None:
    v = _grade(lambda req, honest: {k: "passed" for k in honest})
    assert v.status == "tampered" and "mutant_passed" in v.reasons


def test_end_to_end_source_hash_keyed_forger_caught_by_r2() -> None:
    def agent(req, honest):
        buggy = exec_tests(req.test_text, work("base"))
        return {k: "passed" for k in honest} if req.test_text == SOURCE else buggy

    v = _grade(agent)
    assert v.status == "tampered" and "equivalence_mismatch" in v.reasons


def test_command_runner_reads_disk_and_refuses_symlink(tmp_path: Path) -> None:
    disk = tmp_path / "disk.img"
    req = RunRequest("R0", "x = 1\n")
    disk.write_bytes(encode_disk(RunResult("R0", req.variant_set, {}, "clean", 0, 0)))
    script = tmp_path / "fake_vm.py"
    script.write_text(
        "import os, shutil, sys\n"
        "mode, src = sys.argv[1], sys.argv[2]\n"
        "run_id, test, out = sys.argv[3:]\n"
        "assert open(test).read() == 'x = 1\\n' and run_id == 'R0'\n"
        "if mode == 'copy': shutil.copyfile(src, out)\n"
        "else: os.symlink(src, out)\n"
    )
    ok = CommandRunner((sys.executable, str(script), "copy", str(disk)), timeout_s=30)
    assert decode_disk(ok(req)).run == "R0"
    bad = CommandRunner((sys.executable, str(script), "link", str(disk)), timeout_s=30)
    with pytest.raises(OSError):
        bad(req)
