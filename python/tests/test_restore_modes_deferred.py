"""Run the mode-restoration shell script across adversarial filesystem races."""

import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import textwrap

import pytest

from hermetic_slice.image_sealer import RESTORE_MODES_SH


def executable(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def restore_environment(tmp_path, listing, harness=None, stalled=False):
    """Use a deterministic git listing; execute the actual script and its interpreter."""
    repo = tmp_path / "repo"
    repo.mkdir()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    git_code = tmp_path / "git.py"
    pid_file = tmp_path / "child.pid"
    git_code.write_text(
        "import os, sys, time\n"
        "if sys.argv[1] == 'ls-tree':\n"
        + (f"    open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n    time.sleep(60)\n" if stalled else f"    sys.stdout.buffer.write({listing!r})\n"),
        encoding="utf-8",
    )
    executable(binaries / "git", f"#!/bin/bash\nexec {shlex.quote(sys.executable)} -I -S {shlex.quote(str(git_code))} \"$@\"\n")
    if harness:
        runner = tmp_path / "runner.py"
        runner.write_text(harness, encoding="utf-8")
        executable(binaries / "python3", f"#!/bin/bash\nexec {shlex.quote(sys.executable)} -I -S {shlex.quote(str(runner))} \"$@\"\n")
    env = {**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"]}
    return repo, env, pid_file


@pytest.mark.parametrize("race,reason", [
    ("regular", "a tracked file changed during traversal"),
    ("hardlink", "a tracked file is multiply linked"),
    ("fifo", "a tracked path is not a regular file"),
    ("ancestor", "a tracked directory changed during traversal"),
])
def test_restore_script_replacement_races_preserve_outside_sentinel(tmp_path, race, reason):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("outside secret\n")
    sentinel.chmod(0o600)
    before = sentinel.stat()
    hook = textwrap.dedent(f"""
        import os, sys
        from pathlib import Path
        race = {race!r}
        sentinel = {str(sentinel)!r}
        original_open = os.open
        fired = False
        def hooked_open(path, flags, *args, **kwargs):
            global fired
            directory = kwargs.get('dir_fd')
            target = b'dir' if race == 'ancestor' else b'victim'
            if not fired and directory is not None and path == target:
                fired = True
                os.rename(path, b'saved', src_dir_fd=directory, dst_dir_fd=directory)
                if race == 'ancestor':
                    os.mkdir(path, dir_fd=directory)
                    # If traversal follows the replacement it reaches an outside hard link.
                    os.link(sentinel, b'dir/victim', dst_dir_fd=directory)
                elif race == 'fifo':
                    os.mkfifo(path, dir_fd=directory)
                elif race == 'hardlink':
                    os.link(sentinel, path, dst_dir_fd=directory)
                else:
                    fd = original_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
                    os.close(fd)
            return original_open(path, flags, *args, **kwargs)
        os.open = hooked_open
        source = sys.stdin.read(65536)
        sys.argv = ['-', sys.argv[-1]]
        exec(compile(source, '<restore-modes>', 'exec'))
        assert fired, 'the race hook must execute'
    """)
    path = b"dir/victim" if race == "ancestor" else b"victim"
    listing = b"100644 blob " + b"a" * 40 + b"\t" + path + b"\0"
    repo, env, _ = restore_environment(tmp_path, listing, hook)
    tracked = repo / os.fsdecode(path)
    tracked.parent.mkdir(exist_ok=True)
    tracked.write_text("tracked\n")
    tracked.chmod(0o600)
    result = subprocess.run(["bash", "-c", RESTORE_MODES_SH, "bash", str(repo)],
                            env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert reason in result.stderr
    assert sentinel.read_text() == "outside secret\n"
    after = sentinel.stat()
    assert (after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode)) == (before.st_dev, before.st_ino, 0o600)
    original = repo / "saved/victim" if race == "ancestor" else tracked.parent / "saved"
    assert original.stat().st_mode & 0o777 == 0o600


def test_restore_script_stalled_ls_tree_kills_and_reaps_child(tmp_path):
    repo, env, pid_file = restore_environment(tmp_path, b"", stalled=True)
    tracked = repo / "victim"
    tracked.write_text("unchanged")
    tracked.chmod(0o600)
    env["HERMETIC_LS_TREE_TIMEOUT"] = "0.2"
    result = subprocess.run(["bash", "-c", RESTORE_MODES_SH, "bash", str(repo)],
                            env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "git ls-tree timeout exceeded" in result.stderr
    assert tracked.stat().st_mode & 0o777 == 0o600
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
