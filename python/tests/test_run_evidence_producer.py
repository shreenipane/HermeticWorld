"""Run evidence producer: host facts, probe records and D12 derived from files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hermetic_classifier.evidence import (
    build_run_evidence,
    date_leak_from_run_json,
    host_facts,
    main,
    parse_probe_lines,
)
from hermetic_classifier.run import REQUIRED_PROBES, RunEvidenceError, classify_run

DIGEST = "sha256:" + "a" * 64
PATCH = "b" * 64
SOURCE = "c" * 64
RELEASE = "d" * 64


def probe_lines(**override: str) -> bytes:
    lines = []
    for name in sorted(REQUIRED_PROBES - {"kernel_canary"}):
        result = override.get(name, "unavailable" if name == "clock_pairing_hc" else "blocked")
        lines.append(json.dumps({"probe": name, "result": result, "value": None, "detail": "d"}))
    return ("\n".join(lines) + "\n").encode()


CANARY = b'{"probe":"kernel_canary","result":"blocked","detail":"ring-0 canary"}\n'


@pytest.fixture
def host(tmp_path: Path) -> dict[str, Path]:
    fc = tmp_path / "firecracker"
    fc.write_bytes(b"patched firecracker build")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({
        "schema": "hermetic-firecracker-build/v1", "version": "1.18.0",
        "firecracker_sha256": hashlib.sha256(fc.read_bytes()).hexdigest(),
        "patch_sha256": PATCH, "source_sha256": SOURCE}))
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"version": "1.18.0", "firecracker_sha256": RELEASE,
                                "patch_sha256": PATCH, "source_sha256": SOURCE}))
    run_json = tmp_path / "run.json"
    run_json.write_text(json.dumps({"date_leak_observed": False}))
    probe = tmp_path / "probe.jsonl"
    probe.write_bytes(probe_lines())
    canary = tmp_path / "canary.jsonl"
    canary.write_bytes(CANARY)
    return {"fc": fc, "build": build, "lock": lock, "run": run_json, "probe": probe, "canary": canary}


def test_verified_patched_build_with_full_probe_classifies_hidden(host: dict[str, Path], capsys) -> None:
    argv = ["--run-digest", DIGEST, "--world-sealed", "true", "--firecracker", str(host["fc"]),
            "--firecracker-build", str(host["build"]), "--pinned-lock", str(host["lock"]),
            "--clockprobe", str(host["probe"]), "--canary", str(host["canary"]),
            "--run-json", str(host["run"])]
    assert main(argv) == 0
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["host"] == {"patched_firecracker": True, "hypercall_block": True}
    assert classify_run(evidence)["clock"] == "hidden"


def test_host_facts_are_false_unless_the_binary_matches_the_pinned_patched_build(
        host: dict[str, Path], tmp_path: Path) -> None:
    assert host_facts(host["fc"], host["build"], host["lock"])["patched_firecracker"] is True
    other = tmp_path / "other"
    other.write_bytes(b"some other binary")
    assert host_facts(other, host["build"], host["lock"]) == {
        "patched_firecracker": False, "hypercall_block": False}
    build = json.loads(host["build"].read_text())
    for key, value in [("patch_sha256", "e" * 64), ("source_sha256", "e" * 64)]:
        changed = tmp_path / f"build-{key}.json"
        changed.write_text(json.dumps(dict(build, **{key: value})))
        assert host_facts(host["fc"], changed, host["lock"])["patched_firecracker"] is False
    # A build record claiming the unpatched release hash is not a patched build.
    release = tmp_path / "release.json"
    lock = json.loads(host["lock"].read_text())
    lock["firecracker_sha256"] = build["firecracker_sha256"]
    release.write_text(json.dumps(lock))
    assert host_facts(host["fc"], host["build"], release)["patched_firecracker"] is False


def test_hostile_or_malformed_host_inputs_are_refused(host: dict[str, Path], tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(host["fc"])
    with pytest.raises(RunEvidenceError):
        host_facts(link, host["build"], host["lock"])
    for bad in [b"{", b"[]", b'{"schema":"other"}',
                json.dumps({"schema": "hermetic-firecracker-build/v1", "firecracker_sha256": "x"}).encode(),
                b'{"schema":"hermetic-firecracker-build/v1","schema":"x"}']:
        path = tmp_path / "bad.json"
        path.write_bytes(bad)
        with pytest.raises(RunEvidenceError):
            host_facts(host["fc"], path, host["lock"])
    with pytest.raises(RunEvidenceError):
        host_facts(host["fc"], host["build"], tmp_path / "absent")


def test_probe_lines_are_strict() -> None:
    assert len(parse_probe_lines(probe_lines())) == len(REQUIRED_PROBES) - 1
    for bad in [b"", b"\n", b"{", b'{"probe":"x"}', b'{"probe":"x","result":"maybe"}',
                b'{"probe":"x","result":"blocked","extra":"1"}', b'{"probe":1,"result":"blocked"}',
                b"\xff", (CANARY * 65)]:
        with pytest.raises(RunEvidenceError):
            parse_probe_lines(bad)


def test_leaks_and_d12_lower_the_clock_level(host: dict[str, Path], tmp_path: Path) -> None:
    facts = host_facts(host["fc"], host["build"], host["lock"])
    leak = parse_probe_lines(probe_lines(rdtsc="leak")) + parse_probe_lines(CANARY)
    evidence = build_run_evidence(run_digest=DIGEST, world_sealed=True, host=facts,
                                  clockprobe=leak, date_leak_observed=False)
    assert classify_run(evidence)["clock"] == "faked"
    clean = parse_probe_lines(probe_lines()) + parse_probe_lines(CANARY)
    run = tmp_path / "leak-run.json"
    run.write_text(json.dumps({"date_leak_observed": True}))
    evidence = build_run_evidence(run_digest=DIGEST, world_sealed=True, host=facts, clockprobe=clean,
                                  date_leak_observed=date_leak_from_run_json(run))
    result = classify_run(evidence)
    assert result["clock"] == "faked" and "date_leak_observed" in result["flags"]


@pytest.mark.parametrize("doc", [{}, {"date_leak_observed": None}, {"date_leak_observed": "false"},
                                 {"date_leak_observed": 0}])
def test_run_json_without_a_boolean_d12_result_is_refused(tmp_path: Path, doc: dict) -> None:
    run = tmp_path / "run.json"
    run.write_text(json.dumps(doc))
    with pytest.raises(RunEvidenceError):
        date_leak_from_run_json(run)


def test_extra_evidence_cannot_replace_derived_facts(host: dict[str, Path]) -> None:
    facts = host_facts(host["fc"], host["build"], host["lock"])
    for key in ("host", "clockprobe", "substrate", "run_digest"):
        with pytest.raises(RunEvidenceError):
            build_run_evidence(run_digest=DIGEST, world_sealed=True, host=facts, clockprobe=[],
                               date_leak_observed=False, extra={key: None})
    evidence = build_run_evidence(run_digest=DIGEST, world_sealed=True, host=facts,
                                  clockprobe=parse_probe_lines(probe_lines()), date_leak_observed=False,
                                  extra={"grader": {"r0": "pass"}})
    assert evidence["grader"] == {"r0": "pass"}


def test_cli_reports_errors_without_output(host: dict[str, Path], tmp_path: Path, capsys) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(b"{")
    argv = ["--run-digest", DIGEST, "--world-sealed", "true", "--firecracker", str(host["fc"]),
            "--firecracker-build", str(host["build"]), "--pinned-lock", str(host["lock"]),
            "--clockprobe", str(bad), "--run-json", str(host["run"])]
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "error" in captured.err


@pytest.mark.parametrize("key", ["host", "clockprobe", "date_leak_observed", "schema", "world_sealed"])
def test_absent_derived_facts_cannot_be_asserted_through_extra(key: str) -> None:
    asserted = {"host": {"patched_firecracker": True, "hypercall_block": True},
                "clockprobe": [], "date_leak_observed": False, "schema": "x", "world_sealed": True}
    with pytest.raises(RunEvidenceError):
        build_run_evidence(run_digest=DIGEST, world_sealed=True, host=None, clockprobe=None,
                           date_leak_observed=None, extra={key: asserted[key]})
