"""Offline regressions for smoke storage and cleanup, without images or KVM."""

import importlib.util
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/integration/smoke_work.py"
spec = importlib.util.spec_from_file_location("smoke_work", HELPER)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def fixture_script(tmp_path, body):
    script = tmp_path / "fixture-smoke.sh"
    script.write_text('smoke_main() {\nWORK=$HERMETIC_SMOKE_WORK\n' + body + '\n}\n')
    return script


def invoke(script, env, *args, **kwargs):
    return subprocess.run([sys.executable, "-I", str(HELPER), str(script), *map(str, args)],
                          env=env, capture_output=True, text=True, timeout=15, **kwargs)


@pytest.mark.parametrize("override", [False, True])
def test_default_work_is_private_fresh_and_removed_on_success(tmp_path, override):
    root = tmp_path / ("override" if override else ".cache/hermetic-smoke")
    env = dict(os.environ, HOME=str(tmp_path))
    env.pop("HERMETIC_SMOKE_DIR", None)
    if override:
        env["HERMETIC_SMOKE_DIR"] = str(root)
    script = fixture_script(tmp_path, 'stat -c "%a" "$WORK"\nprintf "%s\\n" "$WORK"\n'
                            'mkdir "$WORK/tree"; echo fixture > "$WORK/tree/image"\n'
                            'ln -s "$HOME/sentinel" "$WORK/link"')
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "keep").write_text("untouched")
    paths = []
    for _ in range(2):
        result = invoke(script, env)
        assert result.returncode == 0, result.stderr
        mode, path = result.stdout.splitlines()
        assert mode == "700"
        assert Path(path).parent == root
        assert not Path(path).exists()
        paths.append(path)
    assert paths[0] != paths[1]
    assert list(root.iterdir()) == []
    assert (sentinel / "keep").read_text() == "untouched"


@pytest.mark.parametrize("exit_code", [1, 17])
def test_failure_retains_and_reports_work(tmp_path, exit_code):
    script = fixture_script(tmp_path, f'echo diagnostic > "$WORK/log"; exit {exit_code}')
    work = tmp_path / "work with spaces"
    result = invoke(script, dict(os.environ), work)
    assert result.returncode == exit_code
    assert (work / "log").read_text() == "diagnostic\n"
    assert str(work) in result.stderr
    assert stat.S_IMODE(work.stat().st_mode) == 0o700


def test_explicit_fresh_work_is_removed_on_success(tmp_path):
    script = fixture_script(tmp_path, 'echo fixture > "$WORK/image"')
    work = tmp_path / "new"
    result = invoke(script, dict(os.environ), work)
    assert result.returncode == 0, result.stderr
    assert not work.exists()


@pytest.mark.parametrize("kind", ["existing", "symlink", "ancestor-link", "fifo", "file"])
def test_caller_owned_paths_are_never_chmodded_or_deleted(tmp_path, kind):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    (target / "sentinel").write_text("untouched")
    work = tmp_path / "work"
    if kind == "existing":
        work = target
    elif kind == "symlink":
        work.symlink_to(target, target_is_directory=True)
    elif kind == "ancestor-link":
        work.symlink_to(target, target_is_directory=True)
        work = work / "new"
    elif kind == "fifo":
        os.mkfifo(work)
    else:
        work.write_text("caller file")
    script = fixture_script(tmp_path, 'exit 0')
    result = invoke(script, dict(os.environ), work)
    assert result.returncode != 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert sorted(p.name for p in target.iterdir()) == ["sentinel"]
    assert (target / "sentinel").read_text() == "untouched"
    assert os.path.lexists(work if kind != "ancestor-link" else work.parent)


@pytest.mark.parametrize("ancestor", [False, True])
def test_default_root_symlinks_are_refused(tmp_path, ancestor):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    root = tmp_path / "cache"
    root.symlink_to(target, target_is_directory=True)
    if ancestor:
        root = root / "smoke"
    result = invoke(fixture_script(tmp_path, 'exit 0'),
                    dict(os.environ, HERMETIC_SMOKE_DIR=str(root)))
    assert result.returncode != 0
    assert list(target.iterdir()) == []
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_cleanup_refuses_replaced_work_directory(tmp_path):
    script = fixture_script(tmp_path, 'mv "$WORK" "$WORK-original"; mkdir "$WORK"; '
                            'echo caller > "$WORK/sentinel"')
    work = tmp_path / "work"
    result = invoke(script, dict(os.environ), work)
    assert result.returncode != 0
    assert (work / "sentinel").read_text() == "caller\n"
    assert work.with_name("work-original").is_dir()
    assert str(work) in result.stderr


def test_cleanup_uses_pinned_parent_after_ancestor_exchange(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    moved = tmp_path / "moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    work = parent / "work"
    script = fixture_script(tmp_path,
                            f'mv "{parent}" "{moved}"; ln -s "{outside}" "{parent}"')
    result = invoke(script, dict(os.environ), work)
    assert result.returncode == 0, result.stderr
    assert not (moved / "work").exists()
    assert list(outside.iterdir()) == []


def test_signal_retains_and_reports_work(tmp_path):
    script = fixture_script(tmp_path, 'echo diagnostic > "$WORK/log"; kill -TERM "$PPID"; sleep 5')
    work = tmp_path / "work"
    result = invoke(script, dict(os.environ), work)
    assert result.returncode == 128 + signal.SIGTERM
    assert (work / "log").is_file()
    assert str(work) in result.stderr


@pytest.mark.parametrize("invalid", ["../escape", "bad\npath", "x" * (smoke.MAX_PATH_BYTES + 1)])
def test_invalid_work_path_has_no_filesystem_effects(tmp_path, invalid):
    script = fixture_script(tmp_path, 'exit 0')
    before = sorted(tmp_path.iterdir())
    result = invoke(script, dict(os.environ), tmp_path / invalid)
    assert result.returncode != 0
    assert sorted(tmp_path.iterdir()) == before


def test_cleanup_limits_fail_closed(tmp_path, monkeypatch):
    parent, name, directory, work = smoke.create_work("fixture-smoke.sh", str(tmp_path / "work"))
    try:
        (Path(work) / "image").touch()
        monkeypatch.setattr(smoke, "MAX_CLEANUP_ENTRIES", 0)
        with pytest.raises(ValueError, match="entry cap"):
            smoke.cleanup(parent, name, directory)
        assert (Path(work) / "image").exists()
    finally:
        os.close(directory)
        os.close(parent)


def test_work_is_0700_even_under_restrictive_umask(tmp_path):
    script = fixture_script(tmp_path, 'stat -c "%a" "$WORK"; exit 17')
    result = invoke(script, dict(os.environ, HOME=str(tmp_path), HERMETIC_SMOKE_DIR=""), umask=0o777)
    assert result.returncode == 17, result.stderr
    assert result.stdout.strip() == "700"
    root = tmp_path / ".cache/hermetic-smoke"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


@pytest.mark.parametrize("script_name", ["boot-smoke", "grader-smoke", "grader-vm-smoke"])
@pytest.mark.parametrize("kind", ["existing", "ancestor-link"])
def test_smoke_entrypoints_refuse_unsafe_supplied_paths(tmp_path, script_name, kind):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    (target / "sentinel").write_text("untouched")
    work = target
    if kind == "ancestor-link":
        link = tmp_path / "link"
        link.symlink_to(target, target_is_directory=True)
        work = link / "new"
    commands = tmp_path / "commands"
    commands.mkdir()
    # If an entrypoint fails to reject the path, stop before any real build or install.
    for command in ("sha256sum", "cargo"):
        path = commands / command
        path.write_text("#!/bin/sh\nexit 17\n")
        path.chmod(0o700)
    env = dict(os.environ, HOME=str(tmp_path), PATH=f"{commands}:{os.environ['PATH']}")
    result = subprocess.run(["bash", str(ROOT / f"scripts/integration/{script_name}.sh"), str(work)],
                            cwd=ROOT, env=env, capture_output=True, timeout=15)
    assert result.returncode != 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert sorted(p.name for p in target.iterdir()) == ["sentinel"]
    assert (target / "sentinel").read_text() == "untouched"


def test_rootfs_image_fixture_discards_images_after_assertions(tmp_path):
    basetemp = tmp_path / "child-run"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp", str(basetemp),
         "tests/test_rootfs.py::test_finding2_mke2fs_gets_pinned_config_and_explicit_options"],
        cwd=ROOT / "python", env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not list(basetemp.rglob("*.img"))
    assert not list(basetemp.glob("test_finding2*"))


def test_replaceable_ancestor_is_refused_but_sticky_shared_ancestor_is_allowed(tmp_path):
    """Review finding (2026-11-14): only the final parent was checked, so a
    non-sticky, other-writable ancestor could be renamed and replaced by a
    symlink the shell would later follow."""
    shared = tmp_path / "shared"
    shared.mkdir()
    private = shared / "alice"
    private.mkdir(mode=0o700)
    shared.chmod(0o777)  # writable by others, not sticky
    try:
        with pytest.raises(ValueError, match="ancestor another user can replace"):
            smoke.create_work("x-smoke.sh", str(private / "job"))
        assert not (private / "job").exists()
        shared.chmod(0o1777)  # sticky: entries can only be renamed by their owners
        parent, name, child, path = smoke.create_work("x-smoke.sh", str(private / "job"))
        os.close(child)
        os.close(parent)
        assert path == str(private / "job")
    finally:
        shared.chmod(0o755)
    with pytest.raises(ValueError, match="absolute"):
        smoke.open_directory("relative/dir")


def test_signal_during_cleanup_stops_deletion_and_retains_artifacts(tmp_path):
    """Review finding (2026-11-14): a signal recorded during cleanup must stop
    deletion and fail the run instead of removing everything and returning 0."""
    parent, name, child, path = smoke.create_work("x-smoke.sh", str(tmp_path / "w"))
    try:
        for i in range(5):
            (Path(path) / f"f{i}").write_text("x")
        calls = []
        def cancelled():
            calls.append(1)
            return len(calls) > 2
        with pytest.raises(smoke.Cancelled):
            smoke.cleanup(parent, name, child, cancelled=cancelled)
        assert (tmp_path / "w").is_dir()
        assert 0 < len(list((tmp_path / "w").iterdir())) < 5
    finally:
        os.close(child)
        os.close(parent)
