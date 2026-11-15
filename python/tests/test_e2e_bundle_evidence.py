"""Offline coverage validation and deterministic staging-evidence handoff."""

import hashlib
import json
import os
import stat

import pytest

from hermetic_runspec.derive import FileSafetyError
from test_e2e_seal import e2e, INSTANCE


def clean_report(step):
    if step == "D10":
        return {"detector": "D10", "verdict": "pass", "complete": True, "findings": [],
                "provenance": {"verdict": "verified", "issues": []}}
    return {"schema": "hermetic-sealcheck/v0", "gate": False,
            "not_covered": [], "findings": []}


@pytest.mark.parametrize("step", ["sealcheck_tiers", "D8", "D10"])
@pytest.mark.parametrize("bad", [{}, {"findings": []}, {"findings": "none"},
                                 {"findings": [None]}])
def test_scan_reports_require_explicit_success(step, bad):
    with pytest.raises(e2e.SealError, match="invalid_scan_report"):
        e2e.validate_scan_report(step, bad)


@pytest.mark.parametrize("step", ["sealcheck_tiers", "D8", "D10"])
@pytest.mark.parametrize("finding", [{}, {"severity": "error"},
                                     {"severity": "gate", "visibility": "unknown"}])
def test_scan_findings_require_known_severity_and_visibility(step, finding):
    report = dict(clean_report(step), findings=[finding])
    with pytest.raises(e2e.SealError, match="invalid_scan_report"):
        e2e.validate_scan_report(step, report)


@pytest.mark.parametrize("step,changes", [
    ("sealcheck_tiers", {"not_covered": ["D3b"]}),
    ("D8", {"findings": [{"channel": "d8_error", "severity": "info"}]}),
    ("D10", {"complete": False}),
    ("D10", {"complete": None}),
])
def test_incomplete_scans_cannot_be_passing_evidence(step, changes):
    with pytest.raises(e2e.SealError, match="detector_incomplete"):
        e2e.validate_scan_report(step, dict(clean_report(step), **changes))


@pytest.mark.parametrize("step", ["sealcheck_tiers", "D8", "D10"])
def test_gate_findings_cannot_hide_behind_a_pass_summary(step):
    report = clean_report(step)
    report["findings"] = [{"severity": "gate", "visibility": "agent_visible"}]
    with pytest.raises(e2e.SealError, match="detector_gate"):
        e2e.validate_scan_report(step, report)
    # Image-only findings retain the scanner's visibility policy.
    report["findings"][0]["visibility"] = "image_only"
    assert e2e.validate_scan_report(step, report) == 1


@pytest.mark.parametrize("step", ["sealcheck_tiers", "D8", "D10"])
def test_orchestration_stops_at_incomplete_scan(tmp_path, monkeypatch, capsys, step):
    work = tmp_path / "work"
    tool = tmp_path / "sealcheck"
    tool.write_bytes(b"fixture tool")
    def command(argv, **kwargs):
        if argv[:3] == ["docker", "image", "inspect"]:
            return e2e.encoded([{"Id": "sha256:" + "a" * 64}])
        if argv[:2] == ["docker", "create"]:
            return ("b" * 64 + "\n").encode()
        if "--worker" in argv and argv[argv.index("--worker") + 1] == "intake":
            task = work / "tasks" / INSTANCE
            task.mkdir(parents=True)
            (task / "task.json").write_bytes(b'{"cutoffs":{"t_clock":"2014-01-01T00:00:00Z"}}')
        current = "sealcheck_tiers" if "scan" in argv else "D8" if "d8" in argv else "D10" if "--root" in argv else None
        if current is not None:
            report = clean_report(current)
            if current == step:
                if current == "D10":
                    report["complete"] = False
                elif current == "D8":
                    report["findings"] = [{"channel": "d8_error", "severity": "info"}]
                else:
                    report["not_covered"] = ["D3b"]
            return e2e.encoded(report)
        return b""
    monkeypatch.setattr(e2e, "command", command)
    previous = os.umask(0o077)
    try:
        assert e2e.run([INSTANCE, str(work), "--sealcheck", str(tool)]) == 1
    finally:
        os.umask(previous)
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[-1] == {"step": step, "verdict": "fail", "reason": "detector_incomplete"}
    assert not (work / "bundle-evidence.json").exists()
    assert not (work / "world-manifest.json").exists()


def inputs(work):
    task = work / "tasks" / INSTANCE
    task.mkdir(parents=True)
    (task / "task.json").write_bytes(e2e.encoded({
        "instance_id": INSTANCE, "test_services": ["httpbin-v1"],
    }))
    (work / "rootfs.img").write_bytes(b"sealed filesystem fixture\n")
    (work / "rootfs-report.json").write_bytes(e2e.encoded({
        "sha256": hashlib.sha256((work / "rootfs.img").read_bytes()).hexdigest(),
        "size_bytes": (work / "rootfs.img").stat().st_size, "d4": "pass",
        "image": "/private/host/path/rootfs.img",
    }))
    for step in ("sealcheck_tiers", "D8", "D10"):
        (work / (step + ".json")).write_bytes(e2e.encoded(clean_report(step)))


def test_bundle_evidence_is_deterministic_private_and_bound_to_actual_bytes(tmp_path):
    outputs = []
    for name in ("first", "second"):
        work = tmp_path / name
        inputs(work)
        (work / "gold.patch").write_bytes(b"private oracle data")
        evidence = e2e.prepare_bundle_evidence(work, INSTANCE)
        path = work / "bundle-evidence.json"
        outputs.append(path.read_bytes())
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert evidence["complete"] is False
        assert evidence["test_services"] == ["httpbin-v1"]
        assert evidence["rootfs"] == {
            "digest": "sha256:" + hashlib.sha256(b"sealed filesystem fixture\n").hexdigest(),
            "size_bytes": len(b"sealed filesystem fixture\n"),
        }
        assert set(evidence["scans"]) == {"sealcheck_tiers", "D8", "D10"}
        assert not (work / "world-manifest.json").exists()
        assert b"/private/host" not in outputs[-1]
        assert b"private oracle data" not in outputs[-1]
        os.utime(work / "rootfs.img", (100, 100))
        e2e.prepare_bundle_evidence(work, INSTANCE)
        assert path.read_bytes() == outputs[-1]
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("bad", ["digest", "size", "d4", "scan", "identity", "services", "missing"])
def test_bundle_evidence_rejects_unverified_inputs_before_publication(tmp_path, bad):
    work = tmp_path / "work"
    inputs(work)
    if bad in ("digest", "size", "d4"):
        path = work / "rootfs-report.json"
        report = json.loads(path.read_bytes())
        report[{"digest": "sha256", "size": "size_bytes", "d4": "d4"}[bad]] = "wrong"
        path.write_bytes(e2e.encoded(report))
    elif bad == "scan":
        (work / "D10.json").write_bytes(e2e.encoded(dict(clean_report("D10"), complete=False)))
    elif bad == "identity":
        (work / "tasks" / INSTANCE / "task.json").write_bytes(b'{"instance_id":"other"}')
    elif bad == "services":
        (work / "tasks" / INSTANCE / "task.json").write_bytes(e2e.encoded({
            "instance_id": INSTANCE, "test_services": ["private-command"],
        }))
    else:
        (work / "D8.json").unlink()
    with pytest.raises((e2e.SealError, OSError, FileSafetyError)):
        e2e.prepare_bundle_evidence(work, INSTANCE)
    assert not (work / "bundle-evidence.json").exists()


@pytest.mark.parametrize("kind", ["link", "ancestor", "fifo", "cap"])
def test_evidence_hash_refuses_unsafe_artifacts(tmp_path, kind):
    path = tmp_path / "input"
    path.write_bytes(b"payload")
    if kind == "link":
        link = tmp_path / "link"
        link.symlink_to(path)
        path = link
    elif kind == "ancestor":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        path = link / "input"
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path)
    with pytest.raises(OSError):
        e2e.file_evidence(path, 1 if kind == "cap" else 1024)


def test_artifact_hash_known_answer_and_growth_cap(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"abc")
    assert e2e.file_evidence(path, 3) == {
        "digest": "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "size_bytes": 3,
    }
    original = e2e.open_regular
    def growing(path, cap):
        descriptor = original(path, cap)
        with open(path, "ab") as stream:
            stream.write(b"d")
        return descriptor
    monkeypatch.setattr(e2e, "open_regular", growing)
    with pytest.raises(e2e.SealError, match="artifact_byte_cap"):
        e2e.file_evidence(path, 3)


@pytest.mark.parametrize("provenance", [None, {}, {"verdict": "error"}, {"verdict": "pass"}, "verified"])
def test_d10_report_without_verified_provenance_is_refused(provenance):
    report = clean_report("D10")
    if provenance is None:
        del report["provenance"]
    else:
        report["provenance"] = provenance
    with pytest.raises(e2e.SealError, match="d10_provenance_unverified"):
        e2e.validate_scan_report("D10", report)


def test_d10_provenance_gate_gates_the_seal():
    report = dict(clean_report("D10"), provenance={"verdict": "gate", "issues": [{"issue": "x"}]})
    with pytest.raises(e2e.SealError, match="detector_gate"):
        e2e.validate_scan_report("D10", report)
