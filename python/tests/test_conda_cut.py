"""Offline pytest suite for Component G9 (hermetic_conda_cut)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from hermetic_conda_cut.__main__ import main as cli_main
from hermetic_conda_cut.cut import (
    CapExceededError,
    FileSafetyError,
    JsonParseError,
    ValidationError,
    cut_repodata,
    cut_repodata_files,
)


def _sample_repodata() -> dict:
    # 2023-04-01T00:00:00Z == 1680307200000 ms
    return {
        "info": {"subdir": "linux-64"},
        "removed": ["legacy-pkg-0.1.0-0.tar.bz2"],
        "packages": {
            "at-cutoff-1.0.0-0.tar.bz2": {
                "name": "at-cutoff",
                "version": "1.0.0",
                "build": "0",
                "timestamp": 1680307200000,
                "sha256": "aa" * 32,
            },
            "after-cutoff-1.0.1-0.tar.bz2": {
                "name": "after-cutoff",
                "version": "1.0.1",
                "build": "0",
                "timestamp": 1680307200001,
            },
            "no-ts-1.0.0-0.tar.bz2": {
                "name": "no-ts",
                "version": "1.0.0",
                "build": "0",
            },
        },
        "packages.conda": {
            "before-cutoff-2.0.0-py311_0.conda": {
                "name": "before-cutoff",
                "version": "2.0.0",
                "build": "py311_0",
                "timestamp": 1680307199999,
                "md5": "bb" * 16,
            },
            "null-ts-2.0.0-py311_0.conda": {
                "name": "null-ts",
                "version": "2.0.0",
                "build": "py311_0",
                "timestamp": None,
            },
            "newer-conda-2.1.0-py311_0.conda": {
                "name": "newer-conda",
                "version": "2.1.0",
                "build": "py311_0",
                "timestamp": 1680393600000,
            },
        },
    }


def test_rule1_cutoff_boundary_integer_arithmetic_and_unknowns() -> None:
    """Rule 1: Timestamp <= cutoff integer arithmetic filtering, and dropping of missing/null timestamps as unknown."""
    cut_out, report = cut_repodata(_sample_repodata(), cutoff="2023-04-01T00:00:00Z")

    assert report.kept == 2
    assert report.dropped_after_cutoff == 2
    assert report.unknown == ["no-ts-1.0.0-0.tar.bz2", "null-ts-2.0.0-py311_0.conda"]

    # Exactly at cutoff kept
    assert "at-cutoff-1.0.0-0.tar.bz2" in cut_out["packages"]
    # After cutoff dropped
    assert "after-cutoff-1.0.1-0.tar.bz2" not in cut_out["packages"]
    # Missing timestamp dropped
    assert "no-ts-1.0.0-0.tar.bz2" not in cut_out["packages"]

    # Before cutoff kept in packages.conda
    assert "before-cutoff-2.0.0-py311_0.conda" in cut_out["packages.conda"]
    assert "newer-conda-2.1.0-py311_0.conda" not in cut_out["packages.conda"]
    assert "null-ts-2.0.0-py311_0.conda" not in cut_out["packages.conda"]


def test_rule1_seconds_vs_milliseconds_confusion_rejected() -> None:
    """Rule 1: Timestamps < 10**11 (which look like seconds) must be rejected with ValidationError."""
    bad_repodata = {
        "info": {"subdir": "linux-64"},
        "packages": {
            "seconds-pkg-1.0.0-0.tar.bz2": {
                "name": "seconds-pkg",
                "version": "1.0.0",
                "build": "0",
                "timestamp": 1680307200,  # in seconds (< 10**11)
            }
        },
        "packages.conda": {},
    }
    with pytest.raises(ValidationError):
        cut_repodata(bad_repodata, cutoff="2023-04-01T00:00:00Z")


def test_rule2_unchanged_keys_and_removed_preserved() -> None:
    """Rule 2: Keep every other key of kept records unchanged; info and removed unchanged."""
    cut_out, _ = cut_repodata(_sample_repodata(), cutoff="2023-04-01T00:00:00Z")

    # Extra keys on kept records preserved intact
    assert cut_out["packages"]["at-cutoff-1.0.0-0.tar.bz2"]["sha256"] == "aa" * 32
    assert cut_out["packages.conda"]["before-cutoff-2.0.0-py311_0.conda"]["md5"] == "bb" * 16

    # info preserved
    assert cut_out["info"] == {"subdir": "linux-64"}

    # removed list preserved
    assert cut_out["removed"] == ["legacy-pkg-0.1.0-0.tar.bz2"]


def test_rule3_rule4_atomic_output_canonical_json_and_cli(tmp_path: Path) -> None:
    """Rule 3 and Rule 4: Atomic canonical JSON writing, CLI execution, determinism, and safety."""
    valid_f = tmp_path / "repodata.json"
    valid_f.write_text(json.dumps(_sample_repodata()), encoding="utf-8")

    out1 = tmp_path / "out1.json"
    rep1 = tmp_path / "rep1.json"
    out2 = tmp_path / "out2.json"
    rep2 = tmp_path / "rep2.json"

    rc1 = cli_main(
        ["--repodata", str(valid_f), "--cutoff", "2023-04-01T00:00:00Z", "--out", str(out1), "--report", str(rep1)]
    )
    rc2 = cli_main(
        ["--repodata", str(valid_f), "--cutoff", "2023-04-01T00:00:00Z", "--out", str(out2), "--report", str(rep2)]
    )
    assert rc1 == 0 and rc2 == 0

    # Deterministic byte-for-byte identical output
    assert out1.read_bytes() == out2.read_bytes()
    assert rep1.read_bytes() == rep2.read_bytes()

    # Canonical compact JSON without embedded newlines
    assert b"\n" not in out1.read_bytes()
    assert b"\n" not in rep1.read_bytes()

    # Hostile inputs: duplicate JSON keys rejected
    dup_f = tmp_path / "dup.json"
    dup_f.write_text('{"info": {}, "info": {}, "packages": {}, "packages.conda": {}}', encoding="utf-8")
    with pytest.raises(JsonParseError):
        cut_repodata_files(dup_f, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json")

    # Hostile inputs: symlink rejected
    sym_f = tmp_path / "sym.json"
    os.symlink(valid_f, sym_f)
    with pytest.raises(FileSafetyError):
        cut_repodata_files(sym_f, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json")

    # Hostile inputs: byte cap enforced
    with pytest.raises(CapExceededError):
        cut_repodata_files(
            valid_f, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json", repodata_cap_bytes=16
        )

    # CLI exit code 1 on error
    rc_err = cli_main(
        ["--repodata", str(sym_f), "--cutoff", "2023-04-01T00:00:00Z", "--out", str(out1), "--report", str(rep1)]
    )
    assert rc_err == 1


# ---------------------------------------------------------------------------
# Review regressions
# ---------------------------------------------------------------------------

import subprocess
import sys

_PKG_ROOT = str(Path(__file__).resolve().parent.parent)


def test_fifo_repodata_refused_without_blocking(tmp_path: Path) -> None:
    """A FIFO named as repodata is refused immediately instead of blocking on open."""
    fifo = tmp_path / "repodata.fifo"
    os.mkfifo(fifo)
    proc = subprocess.run(
        [sys.executable, "-I", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]);"
         "from hermetic_conda_cut.__main__ import main; raise SystemExit(main(sys.argv[2:]))",
         _PKG_ROOT, "--repodata", str(fifo), "--cutoff", "2023-04-01T00:00:00Z",
         "--out", str(tmp_path / "o.json"), "--report", str(tmp_path / "r.json")],
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 1
    assert not (tmp_path / "o.json").exists()
    with pytest.raises(FileSafetyError):
        cut_repodata_files(fifo, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json")


def test_unknown_top_level_fields_refused() -> None:
    """A 'signatures' map (or any unknown key) could name post-cutoff files; refuse it."""
    data = _sample_repodata()
    data["signatures"] = {"after-cutoff-1.0.1-0.tar.bz2": {"k": "v"}}
    with pytest.raises(ValidationError):
        cut_repodata(data, cutoff="2023-04-01T00:00:00Z")
    data = _sample_repodata()
    data["repodata_version"] = 1
    out, _ = cut_repodata(data, cutoff="2023-04-01T00:00:00Z")
    assert out["repodata_version"] == 1
    for bad in ("1", True, -1, 1.0):
        data["repodata_version"] = bad
        with pytest.raises(ValidationError):
            cut_repodata(data, cutoff="2023-04-01T00:00:00Z")


def test_lone_surrogate_is_validation_error(tmp_path: Path) -> None:
    """Hostile text without a UTF-8 encoding raises a typed error and writes nothing."""
    src = tmp_path / "repodata.json"
    src.write_text(
        '{"info": {"x": "\\ud800"}, "packages": {}, "packages.conda": {}}', encoding="utf-8"
    )
    with pytest.raises(ValidationError):
        cut_repodata_files(src, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json")
    assert not (tmp_path / "o.json").exists()


def test_out_and_report_must_differ(tmp_path: Path) -> None:
    """Rule 3: the report must never overwrite the cut repodata."""
    src = tmp_path / "repodata.json"
    src.write_text(json.dumps(_sample_repodata()), encoding="utf-8")
    same = tmp_path / "same.json"
    with pytest.raises(ValidationError):
        cut_repodata_files(src, "2023-04-01T00:00:00Z", same, same)
    assert not same.exists()


def test_output_through_symlinked_directory_refused(tmp_path: Path) -> None:
    """Rule 3: atomic writes never follow a symlinked parent directory."""
    src = tmp_path / "repodata.json"
    src.write_text(json.dumps(_sample_repodata()), encoding="utf-8")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(FileSafetyError):
        cut_repodata_files(src, "2023-04-01T00:00:00Z", link / "o.json", tmp_path / "r.json")
    assert list(real.iterdir()) == []


def test_bad_cutoff_touches_no_files(tmp_path: Path) -> None:
    """Rule 4: arguments are validated before any file is written."""
    src = tmp_path / "repodata.json"
    src.write_text(json.dumps(_sample_repodata()), encoding="utf-8")
    for bad in ("2023-04-01", "2023-04-01T00:00:00+00:00", "2023-04-01t00:00:00z", "1680307200"):
        assert cli_main(["--repodata", str(src), "--cutoff", bad, "--out", str(tmp_path / "o.json"),
                         "--report", str(tmp_path / "r.json")]) == 1
    assert not (tmp_path / "o.json").exists()
    assert not (tmp_path / "r.json").exists()


def test_report_shape_and_canonical_output(tmp_path: Path) -> None:
    """Rule 3: exact report shape and canonical sorted-key output."""
    src = tmp_path / "repodata.json"
    src.write_text(json.dumps(_sample_repodata()), encoding="utf-8")
    out = tmp_path / "o.json"
    rep = tmp_path / "r.json"
    cut_repodata_files(src, "2023-04-01T00:00:00Z", out, rep)
    assert json.loads(rep.read_bytes()) == {
        "kept": 2,
        "dropped_after_cutoff": 2,
        "unknown": ["no-ts-1.0.0-0.tar.bz2", "null-ts-2.0.0-py311_0.conda"],
    }
    parsed = json.loads(out.read_bytes())
    assert out.read_bytes() == json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert "no-ts-1.0.0-0.tar.bz2" not in out.read_text(encoding="utf-8")
    assert "after-cutoff" not in out.read_text(encoding="utf-8")
