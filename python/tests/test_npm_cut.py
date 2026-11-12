"""Offline pytest suite for Component G10 (hermetic_npm_cut)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from hermetic_npm_cut.__main__ import main as cli_main
from hermetic_npm_cut.cut import (
    CapExceededError,
    DateParseError,
    FileSafetyError,
    JsonParseError,
    ValidationError,
    compare_semver,
    cut_packument,
    cut_packument_files,
    parse_semver,
)


def test_rule3_semver_2_0_0_precedence_rules() -> None:
    """Test Rule 3 semver precedence: prereleases, build metadata, numeric vs alphanumeric."""
    # SemVer 2.0.0 section 11 canonical precedence chain:
    # 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2
    # < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0 < 1.0.1 < 1.2.0 < 2.0.0
    ordered_versions = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.2.0",
        "2.0.0",
    ]
    parsed = [parse_semver(v) for v in ordered_versions]
    assert all(p is not None for p in parsed)
    for i in range(len(parsed) - 1):
        assert compare_semver(parsed[i], parsed[i + 1]) == -1  # type: ignore[arg-type]
        assert compare_semver(parsed[i + 1], parsed[i]) == 1  # type: ignore[arg-type]
        assert compare_semver(parsed[i], parsed[i]) == 0  # type: ignore[arg-type]

    # Build metadata ignored in precedence
    sv_b1 = parse_semver("1.0.0+build.1")
    sv_b2 = parse_semver("1.0.0+build.2026")
    assert sv_b1 is not None and sv_b2 is not None
    assert compare_semver(sv_b1, sv_b2) == 0

    # Numeric identifier has lower precedence than alphanumeric identifier
    sv_num = parse_semver("1.0.0-99")
    sv_alpha = parse_semver("1.0.0-a")
    assert sv_num is not None and sv_alpha is not None
    assert compare_semver(sv_num, sv_alpha) == -1

    # Invalid semver forms rejected (leading zeros, v-prefix, missing patch)
    for bad in ("v1.0.0", "01.0.0", "1.0", "1.0.0-01", "1.0.0+", "", "   ", "1.0.0-"):
        assert parse_semver(bad) is None


def test_rules_1_2_3_4_5_packument_cut() -> None:
    """Test Rules 1, 2, 3, 4, 5 for packument cutting, time, tags, leak-key removal, and report."""
    packument = {
        "_id": "demo-lib",
        "_rev": "99-postcutoffrev",
        "name": "demo-lib",
        "users": {"future_user": True},
        "readme": "Post-cutoff README leaking 3.0.0 features",
        "readmeFilename": "README.md",
        "dist-tags": {
            "latest": "3.0.0",
            "next": "2.0.0-beta.1",
            "legacy": "1.0.0",
            "future-tag": "3.0.0",
        },
        "time": {
            "created": "2022-01-01T00:00:00Z",
            "modified": "2023-05-01T00:00:00Z",
            "1.0.0": "2022-01-01T00:00:00Z",
            "1.2.0": "2023-04-01T00:00:00Z",
            "2.0.0-beta.1": "2023-04-01T00:00:00Z",
            "3.0.0": "2023-04-01T00:00:01Z",
        },
        "versions": {
            "1.0.0": {"name": "demo-lib", "version": "1.0.0", "readme": "Old readme"},
            "1.2.0": {
                "name": "demo-lib",
                "version": "1.2.0",
                "readme": "Cutoff 1.2.0 readme",
                "readmeFilename": "README.rst",
            },
            "2.0.0-beta.1": {"name": "demo-lib", "version": "2.0.0-beta.1"},
            "3.0.0": {"name": "demo-lib", "version": "3.0.0", "readme": "Future readme"},
            "9.9.9-notime": {"name": "demo-lib", "version": "9.9.9-notime"},
        },
    }

    out, report = cut_packument(packument, cutoff="2023-04-01T00:00:00Z")

    # Rule 1: Kept versions <= cutoff, dropped after cutoff, dropped without time listed as unknown
    assert report.kept == 3
    assert report.dropped_after_cutoff == 1
    assert report.unknown == ["9.9.9-notime"]
    assert set(out["versions"].keys()) == {"1.0.0", "1.2.0", "2.0.0-beta.1"}

    # Rule 2: Recompute time (created earliest, modified latest)
    assert out["time"] == {
        "created": "2022-01-01T00:00:00Z",
        "modified": "2023-04-01T00:00:00Z",
        "1.0.0": "2022-01-01T00:00:00Z",
        "1.2.0": "2023-04-01T00:00:00Z",
        "2.0.0-beta.1": "2023-04-01T00:00:00Z",
    }

    # Rule 3: Recompute dist-tags (tag survives only if pointing at kept version; latest re-pointed to highest stable version)
    assert report.tags_dropped == ["future-tag"]
    assert report.latest == "1.2.0"
    assert out["dist-tags"] == {
        "latest": "1.2.0",
        "legacy": "1.0.0",
        "next": "2.0.0-beta.1",
    }

    # Rule 4: Leak keys removal
    assert "users" not in out
    assert "_rev" not in out
    assert out["_id"] == "demo-lib"
    assert out["name"] == "demo-lib"
    assert out["readme"] == "Cutoff 1.2.0 readme"
    assert out["readmeFilename"] == "README.rst"

    # Rule 5: Report fields
    rep_dict = report.to_dict()
    assert set(rep_dict.keys()) == {"kept", "dropped_after_cutoff", "unknown", "tags_dropped", "latest"}


def test_rule2_rule3_empty_and_prerelease_only() -> None:
    """Test Rule 2 and 3 when nothing kept, or only prereleases kept."""
    # Only prereleases kept: latest is dropped
    packument_pre = {
        "name": "pre-only",
        "readme": "Leaked readme",
        "readmeFilename": "README.md",
        "dist-tags": {"latest": "1.0.0", "alpha": "0.1.0-alpha.1"},
        "time": {
            "created": "2023-01-01T00:00:00Z",
            "modified": "2023-06-01T00:00:00Z",
            "0.1.0-alpha.1": "2023-01-01T00:00:00Z",
            "1.0.0": "2023-06-01T00:00:00Z",
        },
        "versions": {
            "0.1.0-alpha.1": {"name": "pre-only", "version": "0.1.0-alpha.1"},
            "1.0.0": {"name": "pre-only", "version": "1.0.0"},
        },
    }
    out_pre, report_pre = cut_packument(packument_pre, cutoff="2023-04-01T00:00:00Z")
    assert report_pre.latest is None
    assert report_pre.tags_dropped == ["latest"]
    assert out_pre["dist-tags"] == {"alpha": "0.1.0-alpha.1"}
    assert "readme" not in out_pre
    assert "readmeFilename" not in out_pre

    # Nothing kept: drop both created and modified
    packument_none = {
        "name": "all-future",
        "dist-tags": {"latest": "2.0.0"},
        "time": {
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "2.0.0": "2024-01-01T00:00:00Z",
        },
        "versions": {
            "2.0.0": {"name": "all-future", "version": "2.0.0"},
        },
    }
    out_none, report_none = cut_packument(packument_none, cutoff="2023-04-01T00:00:00Z")
    assert report_none.kept == 0
    assert report_none.dropped_after_cutoff == 1
    assert report_none.latest is None
    assert report_none.tags_dropped == ["latest"]
    assert out_none["time"] == {}
    assert out_none["dist-tags"] == {}


def test_rule6_cli_and_safety(tmp_path: Path) -> None:
    """Test Rule 6 CLI execution, exit codes, and hostile input handling."""
    # Duplicate JSON keys rejected
    dup_f = tmp_path / "dup.json"
    dup_f.write_text('{"name": "x", "name": "y", "versions": {}, "time": {}}', encoding="utf-8")
    with pytest.raises(JsonParseError):
        cut_packument_files(dup_f, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json")

    # Invalid timestamp rejected
    with pytest.raises(DateParseError):
        cut_packument({"name": "x", "versions": {}, "time": {}}, "invalid-date")

    # Wrong type rejected
    with pytest.raises(ValidationError):
        cut_packument({"name": "x", "versions": [], "time": {}}, "2023-04-01T00:00:00Z")

    # Symlink rejected
    valid_f = tmp_path / "pkg.json"
    valid_f.write_text(
        json.dumps(
            {
                "name": "x",
                "versions": {"1.0.0": {"name": "x", "version": "1.0.0"}},
                "time": {
                    "created": "2023-01-01T00:00:00Z",
                    "modified": "2023-01-01T00:00:00Z",
                    "1.0.0": "2023-01-01T00:00:00Z",
                },
                "dist-tags": {"latest": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    sym_f = tmp_path / "sym.json"
    os.symlink(valid_f, sym_f)
    with pytest.raises(FileSafetyError):
        cut_packument_files(sym_f, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json")

    # Byte cap exceeded
    with pytest.raises(CapExceededError):
        cut_packument_files(
            valid_f, "2023-04-01T00:00:00Z", tmp_path / "o.json", tmp_path / "r.json", packument_cap_bytes=8
        )

    # CLI exit codes and deterministic output
    out1 = tmp_path / "out1.json"
    rep1 = tmp_path / "rep1.json"
    out2 = tmp_path / "out2.json"
    rep2 = tmp_path / "rep2.json"
    rc1 = cli_main(["--packument", str(valid_f), "--cutoff", "2023-04-01T00:00:00Z", "--out", str(out1), "--report", str(rep1)])
    rc2 = cli_main(["--packument", str(valid_f), "--cutoff", "2023-04-01T00:00:00Z", "--out", str(out2), "--report", str(rep2)])
    assert rc1 == 0 and rc2 == 0
    assert out1.read_bytes() == out2.read_bytes()
    assert rep1.read_bytes() == rep2.read_bytes()

    # CLI failure exit code 1
    rc_err = cli_main(["--packument", str(sym_f), "--cutoff", "2023-04-01T00:00:00Z", "--out", str(out1), "--report", str(rep1)])
    assert rc_err == 1
