"""Regression cases for the public npm filter's hostile input boundary."""

import pytest
import json

from hermetic_npm_cut import cut
from hermetic_npm_cut.__main__ import main
from hermetic_npm_cut.cut import (
    HermeticNpmCutError, MAX_JSON_DEPTH, cut_packument, parse_json_bytes,
)

CUTOFF = "2023-04-01T00:00:00Z"


def packument(value):
    return {"name": "demo", "versions": {"1.0.0": {"extension": value}},
            "time": {"1.0.0": CUTOFF}}


def test_npm_direct_filter_bounds_nested_manifests():
    value = "leaf"
    for _ in range(MAX_JSON_DEPTH + 1):
        value = [value]
    with pytest.raises(HermeticNpmCutError):
        cut_packument(packument(value), CUTOFF)


def test_npm_direct_filter_rejects_cycles():
    value = []
    value.append(value)
    with pytest.raises(HermeticNpmCutError):
        cut_packument(packument(value), CUTOFF)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_npm_direct_filter_rejects_nonfinite_numbers(value):
    with pytest.raises(HermeticNpmCutError):
        cut_packument(packument(value), CUTOFF)


def test_npm_byte_parser_rejects_numeric_overflow():
    with pytest.raises(HermeticNpmCutError):
        parse_json_bytes(b'{"number":1e999}', 1024)


@pytest.mark.parametrize("value", [{1: "bad key"}, {"bad": object()}, "\ud800"])
def test_npm_direct_filter_rejects_non_json_values(value):
    with pytest.raises(HermeticNpmCutError):
        cut_packument(packument(value), CUTOFF)


def test_npm_invalid_configuration_is_rejected_before_reading(monkeypatch):
    reads = []
    def read(*args, **kwargs):
        reads.append(True)
        return json.dumps(packument("valid")).encode()
    monkeypatch.setattr(cut, "read_regular_file_bounded", read)
    for kwargs in ({"cutoff": "invalid"}, {"packument_cap_bytes": -1},
                   {"report_path": "bad\x00path"}):
        arguments = dict(packument_path="in.json", cutoff=CUTOFF,
                         out_path="out.json", report_path="report.json")
        arguments.update(kwargs)
        with pytest.raises(HermeticNpmCutError):
            cut.cut_packument_files(**arguments)
    assert reads == []


def test_npm_report_cannot_overwrite_packument(tmp_path):
    source = tmp_path / "in.json"
    output = tmp_path / "out.json"
    source.write_text(json.dumps(packument("valid")))
    for report in (output, source):
        with pytest.raises(HermeticNpmCutError):
            cut.cut_packument_files(source, CUTOFF, output, report)
        assert not output.exists()
        assert json.loads(source.read_text()) == packument("valid")


def test_npm_direct_tree_obeys_named_caps(monkeypatch):
    with monkeypatch.context() as context:
        context.setattr(cut, "DEFAULT_PACKUMENT_CAP_BYTES", 16)
        with pytest.raises(HermeticNpmCutError):
            cut_packument(packument("valid"), CUTOFF)
    with monkeypatch.context() as context:
        context.setattr(cut, "MAX_JSON_TOKENS", 4)
        with pytest.raises(HermeticNpmCutError):
            cut_packument(packument("valid"), CUTOFF)


def test_npm_cli_does_not_echo_untrusted_version(tmp_path, capsys):
    source = tmp_path / "in.json"
    source.write_text(json.dumps({"name": "demo", "versions": {"secret-marker": []}, "time": {}}))
    assert main(["--packument", str(source), "--cutoff", CUTOFF,
                 "--out", str(tmp_path / "out.json"),
                 "--report", str(tmp_path / "report.json")]) == 1
    captured = capsys.readouterr()
    assert "VALIDATION_ERROR" in captured.err
    assert "secret-marker" not in captured.err + captured.out
