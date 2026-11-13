"""Offline pytest suite for Component G12 (hermetic_probe_eval)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from hermetic_probe_eval.__main__ import main as cli_main
from hermetic_probe_eval.evaluate import (
    MAX_CHECKS,
    MAX_EVIDENCE_INPUT_LEN,
    NEGATIVE_CHECK_IDS,
    POSITIVE_CHECK_IDS,
    CapExceededError,
    FileSafetyError,
    JsonParseError,
    ValidationError,
    evaluate_probe_file,
    evaluate_probe_results,
)


def _passing_checks() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    for cid in sorted(NEGATIVE_CHECK_IDS):
        checks.append({"id": cid, "outcome": "blocked", "evidence": f"SECRET_PASS_EVIDENCE_{cid}"})
    for cid in sorted(POSITIVE_CHECK_IDS):
        checks.append({"id": cid, "outcome": "passed", "evidence": f"SECRET_PASS_EVIDENCE_{cid}"})
    return checks


def test_rule1_pass_and_rule3_passing_evidence_excluded() -> None:
    """Test Rule 1 pass verdict and Rule 3 exclusion of passing evidence."""
    payload = {"probe_version": "1.0.0", "checks": _passing_checks()}
    report = evaluate_probe_results(payload)
    assert report.verdict == "pass"
    assert report.failed == []
    assert report.escaped == []
    assert report.missing == []
    assert report.unknown == []
    assert report.digest.startswith("sha256:")

    # Rule 3: Output must not contain the evidence text of passing checks at all
    serialised = json.dumps(report.to_dict())
    assert "SECRET_PASS_EVIDENCE" not in serialised


def test_rule2_escape_verdict_and_rule3_sanitisation() -> None:
    """Test Rule 2 escape verdict and Rule 3 truncation to 256 and printable ASCII replacement."""
    checks = _passing_checks()
    # Mutate raw_ip to escaped with non-printable ASCII and > 256 chars
    raw_bad_evidence = "LINE1\nLINE2\t\x00\x1b[31m\u2603" + ("X" * 400)
    for c in checks:
        if c["id"] == "raw_ip":
            c["outcome"] = "escaped"
            c["evidence"] = raw_bad_evidence
        elif c["id"] == "pip_install":
            c["outcome"] = "failed"
            c["evidence"] = "pip failed cleanly"

    report = evaluate_probe_results({"probe_version": "1.0.0", "checks": checks})
    # Rule 2: Any negative check with escaped yields verdict escape
    assert report.verdict == "escape"
    assert report.escaped == ["raw_ip"]
    assert len(report.failed) == 2

    raw_ip_fail = [f for f in report.failed if f["id"] == "raw_ip"][0]
    # Rule 3: At most first 256 characters with non-printable replaced by ?
    assert len(raw_ip_fail["evidence"]) == 256
    assert raw_ip_fail["evidence"].startswith("LINE1?LINE2???[31m?XXXX")
    assert all(0x20 <= ord(ch) <= 0x7E for ch in raw_ip_fail["evidence"])


def test_rule1_missing_duplicate_unknown_and_error_fail() -> None:
    """Test Rule 1 fail closed on missing, duplicated, unknown-id, or error checks."""
    checks = [c for c in _passing_checks() if c["id"] != "icmp"]
    # Duplicate ipv6
    checks.append({"id": "ipv6", "outcome": "blocked", "evidence": "dup"})
    # Unknown check even with "blocked" outcome fails closed
    checks.append({"id": "mystery_probe", "outcome": "blocked", "evidence": "unknown_ev"})
    # Error on positive check
    for c in checks:
        if c["id"] == "git_clone":
            c["outcome"] = "error"
            c["evidence"] = "git crashed"

    report = evaluate_probe_results({"probe_version": "1.0.0", "checks": checks})
    assert report.verdict == "fail"
    assert report.missing == ["icmp"]
    assert report.unknown == ["mystery_probe"]
    reasons = {(f["id"], f["reason"]) for f in report.failed}
    assert ("ipv6", "duplicate_check_id") in reasons
    assert ("mystery_probe", "unknown_check_id") in reasons
    assert ("git_clone", "check_error") in reasons


def test_rule4_digest_stability_and_determinism() -> None:
    """Test Rule 4 digest stability under check reordering and deterministic JSON."""
    checks_fwd = _passing_checks()
    checks_rev = list(reversed(checks_fwd))
    rep1 = evaluate_probe_results({"probe_version": "1.0.0", "checks": checks_fwd})
    rep2 = evaluate_probe_results({"probe_version": "1.0.0", "checks": checks_rev})
    assert rep1.digest == rep2.digest
    assert rep1.to_dict() == rep2.to_dict()


def test_rule5_cli_exit_codes_and_hostile_inputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test Rule 5 CLI exit codes (0 pass, 2 fail/escape, 1 error) and hostile inputs."""
    # Evidence > 4096 chars rejected
    too_long_ev = _passing_checks()
    too_long_ev[0]["evidence"] = "A" * (MAX_EVIDENCE_INPUT_LEN + 1)
    with pytest.raises(CapExceededError):
        evaluate_probe_results({"probe_version": "1.0.0", "checks": too_long_ev})

    # Too many checks rejected
    with pytest.raises(CapExceededError):
        evaluate_probe_results(
            {
                "probe_version": "1.0.0",
                "checks": [{"id": "raw_ip", "outcome": "blocked", "evidence": ""}] * (MAX_CHECKS + 1),
            }
        )

    # Extra root fields rejected
    with pytest.raises(ValidationError):
        evaluate_probe_results({"probe_version": "1.0.0", "checks": [], "extra": 1})

    # Duplicate JSON keys rejected
    dup_f = tmp_path / "dup.json"
    dup_f.write_text('{"probe_version": "1.0", "probe_version": "2.0", "checks": []}', encoding="utf-8")
    with pytest.raises(JsonParseError):
        evaluate_probe_file(dup_f)

    # Symlink rejected
    pass_f = tmp_path / "pass.json"
    pass_f.write_text(json.dumps({"probe_version": "1.0.0", "checks": _passing_checks()}), encoding="utf-8")
    sym_f = tmp_path / "sym.json"
    os.symlink(pass_f, sym_f)
    with pytest.raises(FileSafetyError):
        evaluate_probe_file(sym_f)

    # CLI exit codes: 0 for pass, 2 for fail/escape, 1 for error
    rc_pass = cli_main(["--results", str(pass_f)])
    capsys.readouterr()
    assert rc_pass == 0

    fail_f = tmp_path / "fail.json"
    fail_f.write_text(json.dumps({"probe_version": "1.0.0", "checks": []}), encoding="utf-8")
    rc_fail = cli_main(["--results", str(fail_f)])
    capsys.readouterr()
    assert rc_fail == 2

    rc_err = cli_main(["--results", str(dup_f)])
    err_out = capsys.readouterr().err
    assert rc_err == 1
    # Check no host path in error output
    assert str(tmp_path) not in err_out


# ---------------------------------------------------------------------------
# Review regressions
# ---------------------------------------------------------------------------

import threading  # noqa: E402

from hermetic_probe_eval.evaluate import read_regular_file_bounded  # noqa: E402


def _call_with_deadline(fn, seconds: float = 5.0):  # type: ignore[no-untyped-def]
    box: dict[str, BaseException] = {}

    def runner() -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            box["exc"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), box.get("exc"), t


def test_review_fifo_results_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "results.fifo"
    os.mkfifo(fifo)
    finished, exc, thread = _call_with_deadline(lambda: evaluate_probe_file(fifo))
    if not finished:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        thread.join(5)
    assert finished, "opening a FIFO results file blocked"
    assert isinstance(exc, FileSafetyError)


def test_review_device_and_symlinked_parent_refused(tmp_path: Path) -> None:
    with pytest.raises(FileSafetyError):
        read_regular_file_bounded("/dev/null", 1024)
    real = tmp_path / "real"
    real.mkdir()
    (real / "r.json").write_text(json.dumps({"probe_version": "1", "checks": _passing_checks()}), encoding="utf-8")
    os.symlink(real, tmp_path / "link")
    with pytest.raises(FileSafetyError):
        evaluate_probe_file(tmp_path / "link" / "r.json")


def test_review_lone_surrogate_is_typed_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    checks = _passing_checks()
    checks.append({"id": "mystery", "outcome": "error", "evidence": "\ud800"})
    with pytest.raises(ValidationError):
        evaluate_probe_results({"probe_version": "1", "checks": checks})
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"probe_version": "1", "checks": checks}), encoding="ascii")
    assert cli_main(["--results", str(f)]) == 1
    assert "INTERNAL_ERROR" not in capsys.readouterr().err


def test_review_unknown_ids_echoed_only_as_printable_ascii() -> None:
    checks = _passing_checks()
    hostile_id = "evil‮\x1b[2Jid" + "Z" * 200
    checks.append({"id": hostile_id[:128], "outcome": "blocked", "evidence": ""})
    report = evaluate_probe_results({"probe_version": "1", "checks": checks})
    assert report.verdict == "fail"
    assert report.unknown == ["evil??[2Jid" + "Z" * 117]
    out = json.dumps(report.to_dict(), ensure_ascii=False)
    assert all(0x20 <= ord(ch) <= 0x7E for ch in out)


def test_review_rule1_unknown_id_alone_fails_closed() -> None:
    checks = _passing_checks()
    checks.append({"id": "extra_check", "outcome": "passed", "evidence": "fine"})
    report = evaluate_probe_results({"probe_version": "1", "checks": checks})
    assert report.verdict == "fail"
    assert report.missing == []
    assert report.unknown == ["extra_check"]


@pytest.mark.parametrize(
    "cid,outcome",
    [("raw_ip", "passed"), ("raw_ip", "failed"), ("raw_ip", "error"),
     ("curl_fetch", "blocked"), ("curl_fetch", "escaped"), ("curl_fetch", "failed"), ("curl_fetch", "error")],
)
def test_review_rule1_wrong_outcome_fails(cid: str, outcome: str) -> None:
    checks = _passing_checks()
    for c in checks:
        if c["id"] == cid:
            c["outcome"] = outcome
    report = evaluate_probe_results({"probe_version": "1", "checks": checks})
    assert report.verdict == "fail"
    assert report.escaped == []
    assert [f["id"] for f in report.failed] == [cid]


def test_review_rule2_duplicate_escape_is_escape_and_cli_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checks = _passing_checks()
    checks.append({"id": "quic", "outcome": "escaped", "evidence": "reached host"})
    report = evaluate_probe_results({"probe_version": "1", "checks": checks})
    assert report.verdict == "escape"
    assert report.escaped == ["quic"]
    f = tmp_path / "e.json"
    f.write_text(json.dumps({"probe_version": "1", "checks": checks}), encoding="utf-8")
    assert cli_main(["--results", str(f)]) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "escape"


def test_review_rule3_evidence_boundary_and_rule4_digest_content() -> None:
    import hashlib

    checks = _passing_checks()
    for c in checks:
        if c["id"] == "icmp":
            c["outcome"] = "error"
            c["evidence"] = "A" * 256 + "TAIL"
    report = evaluate_probe_results({"probe_version": "1", "checks": checks})
    ev = [f for f in report.failed if f["id"] == "icmp"][0]["evidence"]
    assert ev == "A" * 256
    assert "TAIL" not in json.dumps(report.to_dict())
    canonical = json.dumps(
        sorted(checks, key=lambda c: (c["id"], c["outcome"], c["evidence"])),
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    assert report.digest == "sha256:" + hashlib.sha256(canonical).hexdigest()
    changed = [dict(c) for c in checks]
    changed[0]["evidence"] += "x"
    assert evaluate_probe_results({"probe_version": "1", "checks": changed}).digest != report.digest
