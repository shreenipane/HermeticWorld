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

    # Rule 3: only "latest" survives, re-pointed to the highest admitted stable
    # version; every other tag may have been created after the cutoff.
    assert report.tags_dropped == ["future-tag", "legacy", "next"]
    assert report.latest == "1.2.0"
    assert out["dist-tags"] == {"latest": "1.2.0"}

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
    assert report_pre.tags_dropped == ["alpha", "latest"]
    assert out_pre["dist-tags"] == {}
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


# ---------------------------------------------------------------------------
# Review regressions
# ---------------------------------------------------------------------------

import threading  # noqa: E402

from hermetic_npm_cut.cut import read_regular_file_bounded, write_file_atomic  # noqa: E402

_CUTOFF = "2023-04-01T00:00:00Z"


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


def _small_packument() -> dict:  # type: ignore[type-arg]
    return {
        "name": "x",
        "versions": {"1.0.0": {"name": "x", "version": "1.0.0"}},
        "time": {"1.0.0": "2023-01-01T00:00:00Z"},
        "dist-tags": {"latest": "1.0.0"},
    }


def test_review_fifo_packument_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pkg.fifo"
    os.mkfifo(fifo)
    finished, exc, thread = _call_with_deadline(lambda: read_regular_file_bounded(fifo, 1024))
    if not finished:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        thread.join(5)
    assert finished, "opening a FIFO packument blocked"
    assert isinstance(exc, FileSafetyError)


def test_review_device_and_symlinked_parent_refused(tmp_path: Path) -> None:
    with pytest.raises(FileSafetyError):
        read_regular_file_bounded("/dev/null", 1024)
    real = tmp_path / "real"
    real.mkdir()
    (real / "pkg.json").write_text(json.dumps(_small_packument()), encoding="utf-8")
    os.symlink(real, tmp_path / "link")
    with pytest.raises(FileSafetyError):
        read_regular_file_bounded(tmp_path / "link" / "pkg.json", 1 << 20)
    # Output through a symlinked parent directory is refused as well.
    with pytest.raises(FileSafetyError):
        write_file_atomic(tmp_path / "link" / "out.json", b"{}")
    assert not (real / "out.json").exists()


def test_review_atomic_write_fsyncs_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import stat as stat_mod

    synced_dirs: list[bool] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        synced_dirs.append(stat_mod.S_ISDIR(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    write_file_atomic(tmp_path / "out.json", b"{}")
    assert (tmp_path / "out.json").read_bytes() == b"{}"
    assert True in synced_dirs, "destination directory was not fsynced after rename"
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


def test_review_lone_surrogate_is_typed_error(tmp_path: Path) -> None:
    src = tmp_path / "pkg.json"
    doc = json.dumps(_small_packument())
    src.write_text(doc.replace('"version": "1.0.0"}', '"version": "1.0.0", "description": "\\ud800"}', 1), encoding="utf-8")
    assert "\\ud800" in src.read_text(encoding="utf-8")
    with pytest.raises(ValidationError):
        cut_packument_files(src, _CUTOFF, tmp_path / "o.json", tmp_path / "r.json")
    assert cli_main(
        ["--packument", str(src), "--cutoff", _CUTOFF, "--out", str(tmp_path / "o.json"),
         "--report", str(tmp_path / "r.json")]
    ) == 1
    assert not (tmp_path / "o.json").exists()


def test_review_rule4_latest_derived_and_unknown_top_level_keys_removed() -> None:
    packument = _small_packument()
    packument["versions"]["2.0.0"] = {
        "name": "x", "version": "2.0.0", "description": "future", "keywords": ["future"],
    }
    packument["versions"]["1.0.0"]["description"] = "old description"
    packument["time"]["2.0.0"] = "2024-01-01T00:00:00Z"
    packument.update(
        {
            "_id": "x",
            "description": "future description of 2.0.0",
            "keywords": ["future"],
            "maintainers": [{"name": "joined-2024"}],
            "homepage": "https://example.invalid/2024",
            "_attachments": {"x-2.0.0.tgz": {}},
            "x-registry-extra": "2024 state",
        }
    )
    out, report = cut_packument(packument, _CUTOFF)
    assert report.latest == "1.0.0"
    assert out["description"] == "old description"
    for key in ("keywords", "maintainers", "homepage", "_attachments", "x-registry-extra"):
        assert key not in out, key
    assert set(out) == {"_id", "name", "versions", "time", "dist-tags", "description"}
    assert "future" not in json.dumps(out) and "2024" not in json.dumps(out)


def test_review_deprecated_field_stripped_from_kept_manifests() -> None:
    packument = _small_packument()
    packument["versions"]["1.0.0"]["deprecated"] = "Use 2.0.0 released in 2024"
    out, _ = cut_packument(packument, _CUTOFF)
    assert "deprecated" not in out["versions"]["1.0.0"]
    assert out["versions"]["1.0.0"] == {"name": "x", "version": "1.0.0"}


def test_review_reserved_time_key_as_version_is_unknown() -> None:
    packument = _small_packument()
    packument["versions"]["created"] = {"name": "x", "version": "created"}
    packument["time"]["created"] = "2022-01-01T00:00:00Z"
    out, report = cut_packument(packument, _CUTOFF)
    assert report.unknown == ["created"]
    assert "created" not in out["versions"]
    assert out["time"] == {
        "created": "2023-01-01T00:00:00Z",
        "modified": "2023-01-01T00:00:00Z",
        "1.0.0": "2023-01-01T00:00:00Z",
    }


def test_review_rule1_boundary_and_fractional_cutoff() -> None:
    packument = _small_packument()
    packument["versions"]["1.0.1"] = {"name": "x", "version": "1.0.1"}
    packument["versions"]["1.0.2"] = {"name": "x", "version": "1.0.2"}
    packument["time"]["1.0.1"] = "2023-04-01T00:00:00.000Z"
    packument["time"]["1.0.2"] = "2023-04-01T00:00:00.001Z"
    out, report = cut_packument(packument, _CUTOFF)
    assert sorted(out["versions"]) == ["1.0.0", "1.0.1"]
    assert report.dropped_after_cutoff == 1
    assert report.latest == "1.0.1"


def test_review_rule3_latest_ignores_invalid_semver_and_build_metadata() -> None:
    packument = _small_packument()
    for ver in ("9.0", "v9.0.0", "1.5.0+build.7", "1.5.0-rc.1"):
        packument["versions"][ver] = {"name": "x", "version": ver}
        packument["time"][ver] = "2023-02-01T00:00:00Z"
    out, report = cut_packument(packument, _CUTOFF)
    assert report.latest == "1.5.0+build.7"
    assert out["dist-tags"]["latest"] == "1.5.0+build.7"


def test_review_cut_is_deterministic_under_key_order(tmp_path: Path) -> None:
    packument = _small_packument()
    packument["versions"]["0.9.0"] = {"name": "x", "version": "0.9.0"}
    packument["time"]["0.9.0"] = "2022-12-01T00:00:00Z"
    reordered = json.loads(json.dumps(packument, sort_keys=True))
    reordered["versions"] = dict(reversed(list(reordered["versions"].items())))
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps(packument), encoding="utf-8")
    b.write_text(json.dumps(reordered, indent=2), encoding="utf-8")
    cut_packument_files(a, _CUTOFF, tmp_path / "oa.json", tmp_path / "ra.json")
    cut_packument_files(b, _CUTOFF, tmp_path / "ob.json", tmp_path / "rb.json")
    assert (tmp_path / "oa.json").read_bytes() == (tmp_path / "ob.json").read_bytes()
    assert (tmp_path / "ra.json").read_bytes() == (tmp_path / "rb.json").read_bytes()


def test_review_hostile_packuments_raise_typed_errors() -> None:
    from hermetic_npm_cut.cut import HermeticNpmCutError, parse_json_bytes

    hostile_docs = [
        b"[" * 100 + b"]" * 100,
        b'{"a": NaN}',
        b"\xff\xfe",
        b'{"name": "x"',
    ]
    for raw in hostile_docs:
        with pytest.raises(HermeticNpmCutError):
            parse_json_bytes(raw, 1 << 20)
    hostile_values = [
        {"name": "x", "versions": {"1.0.0": "notobj"}, "time": {}},
        {"name": "x", "versions": {}, "time": {}, "dist-tags": {"latest": 5}},
        {"name": "x", "versions": {"1.0.0": {}}, "time": {"1.0.0": 1680307200}},
        {"name": "x", "versions": {}, "time": {}, "_id": ["x"]},
        {"name": 5, "versions": {}, "time": {}},
    ]
    for doc in hostile_values:
        with pytest.raises(HermeticNpmCutError):
            cut_packument(doc, _CUTOFF)


def test_tags_pointing_at_admitted_versions_are_still_dropped():
    """Review finding: without tag history, a tag created after the cutoff can
    point at an admitted release and would reveal post-cutoff activity."""
    packument = {
        "name": "tagged",
        "dist-tags": {"latest": "2.0.0", "added-after-cutoff-2026": "1.0.0", "lts": "1.0.0"},
        "time": {"created": "2020-01-01T00:00:00Z", "modified": "2026-05-01T00:00:00Z",
                 "1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-05-01T00:00:00Z"},
        "versions": {"1.0.0": {"name": "tagged", "version": "1.0.0"},
                     "2.0.0": {"name": "tagged", "version": "2.0.0"}},
    }
    out, report = cut_packument(packument, cutoff="2020-06-01T00:00:00Z")
    assert out["dist-tags"] == {"latest": "1.0.0"}
    assert report.tags_dropped == ["added-after-cutoff-2026", "lts"]
    assert "added-after-cutoff-2026" not in json.dumps(out)
