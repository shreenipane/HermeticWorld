"""Offline regressions for the deferred thread-scrub and disposition review."""

import copy
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from hermetic_slice import dispositions as d, http, thread_scrub as scrub
from hermetic_slice.intake import IntakeError
from tests.disposition_fixtures import complete_manifest, d0, report
from tests.test_dispositions_review import published_under, task_world  # noqa: F401
from tests.test_thread_scrub_security import WORLD, publish


@pytest.mark.parametrize("url", [
    "https://www.github.com/Org/Repo/pull/50/files",
    "http://github.com/org/repo/pull/50/files",
    "https://github.com./org/repo/pull/50/files",
    "https://api.github.com./repos/org/repo/pulls/50/files",
    "https://github.com//org///repo/pull/50/files",
    "https://api.github.com/repositories/123/pulls/50/files",
    "https://github.com/repositories/123/pull/50/files",
])
def test_scrub_resource_aliases_denied(url):
    entries = scrub.get_solution_pr_scrub_entries("org/repo", 50)
    assert scrub.matches_any_scrub_entry(entries, url)
    assert not scrub.matches_any_scrub_entry(entries, "https://github.com/org/repo/pull/500/files")


def test_secure_root_symlink_policy(tmp_path):
    root = tmp_path / "real"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="invalid_cache_directory"):
        http.open_secure_directory(alias / "new")
    assert list(root.iterdir()) == []


def test_unverifiable_revision_fails_closed(tmp_path):
    warnings = []
    result = scrub.process_thread_scrub_and_revision(
        repo="org/repo", pr_number=50, target_issue_number=1,
        target_issue_created=WORLD, t_world=WORLD,
        scraped_problem_statement="POST_CUTOFF_SECRET", scraped_hints="POST_CUTOFF_HINT",
        token=None, http_post_json=None, cache_dir=tmp_path, warnings_list=warnings,
    )
    assert result.problem_statement == result.hints_text == ""
    assert result.problem_statement_revision == "excluded"
    assert "unverifiable_content_excluded" in warnings
    assert scrub.matches_any_scrub_entry(result.scrub_entries, "http://www.github.com./org/repo/issues/1")


def test_publication_preserves_intake_error(tmp_path):
    with patch("hermetic_slice.intake.atomic_write_bytes_at", side_effect=IntakeError("publication_cap_exceeded")):
        with pytest.raises(IntakeError, match="^publication_cap_exceeded$"):
            publish(tmp_path)


@pytest.mark.parametrize("cap,error", [("MAX_TASK_CLEANUP_ENTRIES", "entry"), ("MAX_TASK_CLEANUP_DEPTH", "depth")])
def test_publication_cleanup_has_named_caps(tmp_path, monkeypatch, cap, error):
    from hermetic_slice import intake as module
    task = publish(tmp_path)
    stale = task / "agent" / "nested" / "deeper" / "deepest"
    stale.mkdir(parents=True)
    for index in range(4):
        (stale / str(index)).write_text("stale")
    monkeypatch.setattr(module, cap, 2)
    with pytest.raises(IntakeError, match=f"^task_cleanup_{error}_limit$"):
        publish(tmp_path)
    assert not (task / "task.json").exists()


def test_cleanup_directory_replacement_is_rejected(tmp_path):
    from hermetic_slice.intake import _secure_rmdir_contents_at
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    outside = tmp_path / "sentinel"
    outside.write_text("outside")
    real_open = os.open
    def replace(path, flags, *args, **kwargs):
        if path == "child":
            child.rename(root / "original")
            child.mkdir()
            (child / "sentinel").symlink_to(outside)
        return real_open(path, flags, *args, **kwargs)
    fd = real_open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with patch("os.open", side_effect=replace), pytest.raises(IntakeError, match="task_cleanup_directory_swapped"):
            _secure_rmdir_contents_at(fd)
    finally:
        os.close(fd)
    assert outside.read_text() == "outside"
    assert (child / "sentinel").is_symlink()


def test_creation_revision_fixture_is_chronological():
    path = Path(__file__).parent / "fixtures/thread_scrub/pytest_issue_6189_edits.json"
    issue = json.loads(path.read_text())["data"]["repository"]["issue"]
    revisions = issue["userContentEdits"]["nodes"]
    assert all(edit["editedAt"] >= issue["createdAt"] for edit in revisions)
    assert revisions[-1]["editedAt"] == issue["createdAt"]


@pytest.mark.parametrize("spans", [[(0, 1), (1, 2)], [(0, 2), (1, 2)]])
def test_every_utf8_span_boundary_validated_before_merge(spans):
    with pytest.raises(d.DispositionsError, match="UTF-8"):
        d.redact_problem_statement("é", spans)
    assert d.is_exclusion_only(report(findings=[d0()], explicit_spans=spans), "é" + "context" * 20)
    with pytest.raises(d.DispositionsError, match="UTF-8"):
        d.decide_task_disposition("task_one", [d0()], explicit_spans=spans,
            problem_statement="é" + "context" * 20,
            manifest=complete_manifest("task_one"), rescan_fn=lambda *_: report())


@pytest.mark.parametrize("spans", [[(0, 0)], [(0, 1), (1, 1)]])
def test_empty_redaction_spans_rejected(spans):
    with pytest.raises(d.DispositionsError, match="span|Span"):
        d.redact_problem_statement("x" * 100, spans)


@pytest.mark.parametrize("survivors,excluded", [
    ("[REDACTED]abcdefghij", False),
    ("a" * 19 + "\x1c\x1d\x1e\x1f", False),
    ("a" * 19 + "\u0085\u00a0\u2028\u2029", True),
    ("a" * 20, False),
])
def test_surviving_character_rule_matches_rust(survivors, excluded):
    text = "LEAK " + survivors
    result = d.decide_task_disposition("task_one", [d0("LEAK")],
        problem_statement=text, explicit_spans=[(0, 4)],
        manifest=complete_manifest("task_one"), rescan_fn=lambda *_: report())
    assert (result.disposition == "excluded") == excluded
    assert d.is_exclusion_only(report(findings=[d0("LEAK")], explicit_spans=[(0, 4)]), text) == excluded


def test_explicit_binary_path_never_falls_back(tmp_path):
    binary = tmp_path / "not-executable"
    binary.write_text("invalid")
    with patch.object(d.shutil, "which", return_value="/some/other/sealcheck") as fallback:
        for path in (binary, tmp_path / "absent"):
            with pytest.raises(d.DispositionsError, match="Explicit executable unavailable"):
                d.find_binary("hermetic-sealcheck", custom_path=path)
    fallback.assert_not_called()


def test_clean_task_preserves_manifest_and_world_root():
    manifest = complete_manifest("task_one")
    original = copy.deepcopy(manifest)
    root = d.compute_real_world_version(manifest)
    entries, _ = d.process_dispositions([report(manifest=manifest)])
    assert entries[0]["disposition"] == "clean"
    assert manifest == original
    assert entries[0]["world_version"] == root


@pytest.mark.parametrize("step", ["manifest.json", "problem_statement.md", None])
def test_inline_manifest_repair_rerun(task_world, monkeypatch, step):
    tasks, task, _, initial, binary = task_world
    initial["manifest"] = json.loads((task / "manifest.json").read_text())
    initial["problem_statement"] = (task / "agent/problem_statement.md").read_text()
    original_write = d.SafeDirectory.write
    def interrupt(self, name, content):
        if name == step and published_under(self, tasks.parent):
            raise OSError("interrupted")
        original_write(self, name, content)
    if step:
        with monkeypatch.context() as context:
            context.setattr(d.SafeDirectory, "write", interrupt)
            with pytest.raises(OSError, match="interrupted"):
                d.process_dispositions([copy.deepcopy(initial)], tasks_dir=tasks, sealcheck_bin=binary)
    else:
        d.process_dispositions([copy.deepcopy(initial)], tasks_dir=tasks, sealcheck_bin=binary)
    entries, _ = d.process_dispositions([copy.deepcopy(initial)], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries[0]["disposition"] == "repaired"
    assert (task / "agent/problem_statement.md").read_text() == entries[0]["redacted_statement"]
    tampered = copy.deepcopy(initial)
    tampered["manifest"]["rootfs_digest"] = "sha256:" + "f" * 64
    before = (task / "manifest.json").read_bytes()
    with pytest.raises(d.DispositionsError, match="Conflicting inline manifest"):
        d.process_dispositions([tampered], tasks_dir=tasks, sealcheck_bin=binary)
    assert (task / "manifest.json").read_bytes() == before


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o600])
def test_repair_preserves_statement_permissions(task_world, mode):
    tasks, task, _, initial, binary = task_world
    statement = task / "agent/problem_statement.md"
    statement.chmod(mode)
    for _ in range(2):
        d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
        assert statement.stat().st_mode & 0o777 == mode
        assert (task / "problem_statement_redacted.json").stat().st_mode & 0o777 == 0o600


def test_exclusion_replaces_current_repair_and_keeps_verified_history(task_world):
    tasks, task, _, initial, binary = task_world
    d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    previous = json.loads((task / "manifest.json").read_text())["dispositions"]
    dirty = report(findings=[{**d0(), "detector": "D2"}])
    for _ in range(2):
        entries, _ = d.process_dispositions([dirty], tasks_dir=tasks, sealcheck_bin=binary)
        assert entries[0]["disposition"] == "excluded"
        saved = json.loads((task / "manifest.json").read_text())
        assert {entry["kind"] for entry in saved["dispositions"]} == {"excluded"}
        history = json.loads(saved["dispositions"][0]["detail"])["repair_history"]
        assert history == previous
    # History must remain verifiable for a subsequent real scan.
    entries, _ = d.process_dispositions([initial], tasks_dir=tasks, sealcheck_bin=binary)
    assert entries[0]["disposition"] == "repaired"


@pytest.mark.parametrize("method", ["get", "post"])
def test_cache_read_reaches_bounded_read(tmp_path, method):
    client = http.make_http_get(tmp_path) if method == "get" else http.make_http_post_json(tmp_path, snapshot_id="bounded")
    class Transport(io.BytesIO):
        status = 200
    def call():
        return client("https://api.github.com/graphql") if method == "get" else client("https://api.github.com/graphql", {})
    with patch("urllib.request.urlopen", return_value=Transport(b'{"data":{}}')):
        call()
    with patch.object(http, "bounded_read", side_effect=ValueError("bounded-read-reached")) as read, patch("urllib.request.urlopen") as network:
        with pytest.raises(ValueError, match="bounded-read-reached"):
            call()
    read.assert_called_once()
    network.assert_not_called()
