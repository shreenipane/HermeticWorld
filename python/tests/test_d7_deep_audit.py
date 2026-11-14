"""Deep-audit orchestration tests for D7 with fake isolated builders."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from hermetic_d7.__main__ import main
from hermetic_d7.deep_audit import (
    MAX_RECIPE_ENTRIES,
    RECIPE_SCHEMA,
    BuildRequest,
    parse_recipe,
    run_deep_audit,
)
from hermetic_d7.normalise import HermeticD7Error


def _world(tmp_path: Path, entries: list[dict] | None = None) -> Path:
    root = tmp_path / "world"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "mod.py").write_text("x = 1\n")
    (root / "dist" / "pkg").mkdir(parents=True)
    (root / "dist" / "pkg" / "mod.py").write_text("x = 1\n")
    if entries is None:
        entries = [_entry()]
    (root / "d7-recipe.json").write_text(json.dumps({"schema": RECIPE_SCHEMA, "entries": entries}))
    return root


def _entry(**over: object) -> dict:
    e = {"id": "pkg", "artifact": "dist/pkg", "source": "src/pkg", "builder": "copy", "args": []}
    e.update(over)
    return e


class CopyBuilder:
    """Fake isolated builder: copies the pinned source tree, optionally altered."""

    def __init__(self, alter: bytes | None = None) -> None:
        self.alter = alter
        self.requests: list[BuildRequest] = []

    def build(self, request: BuildRequest) -> None:
        self.requests.append(request)
        out = request.output_dir / request.artifact_name
        out.mkdir()
        for name in os.listdir(request.source_fd):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=request.source_fd)
            with os.fdopen(fd, "rb") as fh:
                data = fh.read()
            (out / name).write_bytes(self.alter if self.alter is not None else data)


def _text(report: dict) -> str:
    return json.dumps(report)


def test_deep_audit_identical_rebuild(tmp_path: Path) -> None:
    root = _world(tmp_path)
    builder = CopyBuilder()
    report = run_deep_audit(root, "d7-recipe.json", builder)
    assert report["verdict"] == "identical"
    assert report["audit_only"] is True and report["gating"] is False
    assert [e["id"] for e in report["entries"]] == ["pkg"]
    assert builder.requests[0].artifact_name == "pkg"
    assert str(tmp_path) not in _text(report)


def test_deep_audit_reports_rebuild_difference_without_host_paths(tmp_path: Path) -> None:
    root = _world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json", CopyBuilder(alter=b"x = 2\n"))
    assert report["verdict"] == "differs"
    diff = report["entries"][0]["content_differences"][0]
    assert diff["path"] == "mod.py"
    assert str(tmp_path) not in _text(report)


def test_deep_audit_default_builder_refuses_host_builds(tmp_path: Path) -> None:
    root = _world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json")
    assert report["verdict"] == "error"
    assert report["entries"][0]["error"]["type"] == "BuildFailedError"


def test_deep_audit_cli_never_runs_a_build(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _world(tmp_path)
    assert main(["--deep-audit", str(root), "d7-recipe.json"]) == 1
    out = capsys.readouterr().out
    assert "no isolated builder configured" in out and str(tmp_path) not in out
    assert main(["--deep-audit", str(root)]) == 1


@pytest.mark.parametrize(
    "bad",
    [
        _entry(artifact="../outside"),
        _entry(source="/etc"),
        _entry(source="a/../../b"),
        _entry(id="Bad ID"),
        _entry(builder="sh -c"),
        _entry(args=["a\x00b"]),
        _entry(args="--x"),
        {**_entry(), "extra": 1},
    ],
)
def test_hostile_recipe_entries_refuse_the_recipe(tmp_path: Path, bad: dict) -> None:
    root = _world(tmp_path, [bad])
    builder = CopyBuilder()
    report = run_deep_audit(root, "d7-recipe.json", builder)
    assert report["verdict"] == "error" and report["entries"] == []
    assert builder.requests == []
    assert str(tmp_path) not in _text(report)


def test_recipe_structure_and_caps() -> None:
    with pytest.raises(HermeticD7Error):
        parse_recipe(b"\xff")
    with pytest.raises(HermeticD7Error):
        parse_recipe(json.dumps({"schema": "other", "entries": [_entry()]}).encode())
    with pytest.raises(HermeticD7Error):
        parse_recipe(json.dumps({"schema": RECIPE_SCHEMA, "entries": []}).encode())
    dup = [_entry(), _entry(id="other")]
    with pytest.raises(HermeticD7Error, match="duplicate"):
        parse_recipe(json.dumps({"schema": RECIPE_SCHEMA, "entries": dup}).encode())
    many = [_entry(id=f"e{i}", artifact=f"d/{i}") for i in range(MAX_RECIPE_ENTRIES + 1)]
    with pytest.raises(HermeticD7Error, match="cap"):
        parse_recipe(json.dumps({"schema": RECIPE_SCHEMA, "entries": many}).encode())
    with pytest.raises(HermeticD7Error):
        parse_recipe(b"[" * 100000)


def test_symlinked_recipe_source_artifact_and_root_are_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mod.py").write_text("secret\n")
    root = _world(tmp_path)
    builder = CopyBuilder()

    shutil.rmtree(root / "src" / "pkg")
    (root / "src" / "pkg").symlink_to(outside)
    report = run_deep_audit(root, "d7-recipe.json", builder)
    assert report["entries"][0]["verdict"] == "error" and builder.requests == []

    (root / "src" / "pkg").unlink()
    (root / "src" / "pkg").mkdir()
    shutil.rmtree(root / "dist")
    (root / "dist").symlink_to(outside)
    assert run_deep_audit(root, "d7-recipe.json", builder)["verdict"] == "error"
    assert builder.requests == []

    real = root / "d7-recipe.json"
    moved = tmp_path / "recipe.json"
    real.rename(moved)
    real.symlink_to(moved)
    assert run_deep_audit(root, "d7-recipe.json", builder)["entries"] == []

    link_root = tmp_path / "rootlink"
    link_root.symlink_to(root)
    report = run_deep_audit(link_root, "d7-recipe.json", builder)
    assert report["verdict"] == "error" and str(tmp_path) not in _text(report)


class _BadBuilder:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    def build(self, request: BuildRequest) -> None:
        out = request.output_dir
        if self.mode == "raise":
            raise RuntimeError(f"boom at {out}")
        if self.mode == "extra":
            (out / request.artifact_name).mkdir()
            (out / "stray").write_text("x")
        if self.mode == "symlink":
            (out / request.artifact_name).symlink_to("/")
        # "nothing": produce no artifact


@pytest.mark.parametrize("mode", ["raise", "extra", "symlink", "nothing"])
def test_misbehaving_builder_fails_closed(tmp_path: Path, mode: str) -> None:
    root = _world(tmp_path)
    report = run_deep_audit(root, "d7-recipe.json", _BadBuilder(mode))
    assert report["verdict"] == "error"
    assert report["entries"][0]["error"]["type"] in {"BuildFailedError", "SecurityViolationError"}
    assert str(tmp_path) not in _text(report) and "/tmp" not in _text(report)


def test_one_entry_error_makes_overall_error(tmp_path: Path) -> None:
    root = _world(tmp_path, [_entry(), _entry(id="missing", artifact="dist/none")])
    report = run_deep_audit(root, "d7-recipe.json", CopyBuilder())
    assert [e["verdict"] for e in report["entries"]] == ["identical", "error"]
    assert report["verdict"] == "error"


def test_deep_audit_compares_pinned_artifact_after_builder_replaces_path(tmp_path: Path) -> None:
    root = _world(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mod.py").write_text("host secret\n")

    class ReplacingBuilder(CopyBuilder):
        def build(self, request: BuildRequest) -> None:
            super().build(request)
            (root / "dist").rename(root / "old-dist")
            (root / "dist").symlink_to(outside)

    report = run_deep_audit(root, "d7-recipe.json", ReplacingBuilder())
    assert report["verdict"] == "identical", report
    assert "host secret" not in _text(report)
    assert str(tmp_path) not in _text(report)


@pytest.mark.parametrize("kind", ["fifo", "device"])
def test_deep_audit_refuses_special_artifact_before_open(tmp_path: Path, monkeypatch, kind: str) -> None:
    root = _world(tmp_path, [_entry(artifact="dist/special")])
    path = root / "dist" / "special"
    if kind == "fifo":
        os.mkfifo(path)
    else:
        # Simulate device metadata at the lstat boundary without requiring root.
        path.write_bytes(b"")
        original_stat = os.stat
        import stat

        def device_stat(name, *args, **kwargs):
            st = original_stat(name, *args, **kwargs)
            if name == "special":
                return os.stat_result((stat.S_IFCHR | 0o600, *st[1:]))
            return st
        monkeypatch.setattr(os, "stat", device_stat)
    original_open = os.open

    def guarded_open(name, *args, **kwargs):
        assert name != "special", "special artifact must be refused before open"
        return original_open(name, *args, **kwargs)
    monkeypatch.setattr(os, "open", guarded_open)
    builder = CopyBuilder()
    assert run_deep_audit(root, "d7-recipe.json", builder)["verdict"] == "error"
    assert builder.requests == []


@pytest.mark.parametrize("data", [
    json.dumps({"schema": RECIPE_SCHEMA, "entries": [_entry(args=["\ud800"])]}).encode(),
    json.dumps({"schema": RECIPE_SCHEMA, "entries": [_entry(source="\ud800")]}).encode(),
    ('{"schema":"' + RECIPE_SCHEMA + '","entries":[],"entries":[]}').encode(),
])
def test_recipe_hostile_json_fails_closed(data: bytes) -> None:
    with pytest.raises(HermeticD7Error):
        parse_recipe(data)


def test_builder_typed_errors_do_not_disclose_host_paths(tmp_path: Path) -> None:
    root = _world(tmp_path)

    class TypedFailure:
        def build(self, request: BuildRequest) -> None:
            raise HermeticD7Error(f"private builder location {request.output_dir}")

    report = run_deep_audit(root, "d7-recipe.json", TypedFailure())
    assert report["verdict"] == "error"
    assert report["entries"][0]["error"]["message"] == "isolated builder failed"
    assert "/tmp" not in _text(report) and str(tmp_path) not in _text(report)


def test_builder_output_listing_stops_at_named_cap(tmp_path: Path, monkeypatch) -> None:
    from contextlib import contextmanager
    from hermetic_d7.deep_audit import MAX_BUILDER_OUTPUT_ENTRIES

    root = _world(tmp_path)
    output = None
    reads = 0
    real_scandir, real_listdir = os.scandir, os.listdir

    class FloodBuilder:
        def build(self, request: BuildRequest) -> None:
            nonlocal output
            output = request.output_dir
            for i in range(MAX_BUILDER_OUTPUT_ENTRIES + 1):
                (output / str(i)).write_bytes(b"")

    def is_output(path):
        return output is not None and not isinstance(path, int) and Path(path) == output

    @contextmanager
    def capped_scandir(path):
        nonlocal reads
        with real_scandir(path) as entries:
            if not is_output(path):
                yield entries
                return

            def counted():
                nonlocal reads
                for entry in entries:
                    reads += 1
                    assert reads <= MAX_BUILDER_OUTPUT_ENTRIES, "unbounded output directory read"
                    yield entry
            yield counted()

    def capped_listdir(path):
        if is_output(path):
            with capped_scandir(path) as entries:
                return [entry.name for entry in entries]
        return real_listdir(path)

    monkeypatch.setattr(os, "scandir", capped_scandir)
    monkeypatch.setattr(os, "listdir", capped_listdir)
    report = run_deep_audit(root, "d7-recipe.json", FloodBuilder())
    assert report["verdict"] == "error"
    assert report["entries"][0]["error"]["type"] == "BuildFailedError"
    assert reads == MAX_BUILDER_OUTPUT_ENTRIES
