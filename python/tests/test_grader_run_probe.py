"""Exercise the smoke probe with real descriptors and injected kernel views.

Actual PID/mount isolation is asserted separately by the KVM smoke itself.
"""

import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "scripts/integration/fixtures/grader-task/hermetic_run_probe.py"


@pytest.mark.parametrize("leak", ["none", "config", "environment", "argv", "cmdline", "device", "process", "fd", "readable_pipe", "config_cap", "cmdline_cap", "entries_cap"])
def test_run_probe_checks_each_label_channel(tmp_path, leak):
    config = tmp_path / "config"
    config.write_bytes(b'{"run":"R1"}' if leak == "config" else b'{}')
    cmdline = tmp_path / "cmdline"
    cmdline.write_bytes(b'ro hermetic.t=1700000000' + (b' hermetic.run=R1' if leak == 'cmdline' else b''))
    if leak == 'config_cap':
        config.write_bytes(b' ' * (1024 * 1024 + 1))
    if leak == 'cmdline_cap':
        cmdline.write_bytes(b' ' * 4097)
    reader, writer = os.pipe()
    try:
        # Keep real safe file opens, byte caps, fstat and fcntl. Only VM-specific
        # kernel views and paths to the image files are injected.
        script = r'''
import contextlib, os, runpy, sys, types
probe, leak, writer, config, cmdline, modules = sys.argv[1:]
writer = int(writer)
sys.path.insert(0, modules)
import hermetic_safe_io
safe_open = hermetic_safe_io.open_regular
hermetic_safe_io.open_regular = lambda path, cap: safe_open(config if path == '/etc/hermetic/grader/run.json' else cmdline, cap)
os.dup2(writer, 3)
if writer != 3: os.close(writer)
null = os.open('/dev/null', os.O_RDWR)
for fd in (0, 1, 2): os.dup2(null, fd)
os.close(null)
os.getpid = lambda: 1
os.getppid = lambda: 0
os.environ.clear()
if leak == 'environment': os.environ['HERMETIC_GRADER_RUN'] = 'R1'
sys.orig_argv = ['python', '-s', '-m', 'pytest'] + (['R1'] if leak == 'argv' else [])
if leak == 'fd': extra = open('/dev/null')
if leak == 'readable_pipe':
    r, w = os.pipe()
    os.dup2(r, 3)
    if r != 3: os.close(r)
    os.close(w)
original_scandir = os.scandir
@contextlib.contextmanager
def view(path):
    if path == '/proc':
        names = ['1'] + (['2'] if leak == 'process' else [])
        if leak == 'entries_cap': names = ['x'] * 4097
        yield iter(types.SimpleNamespace(name=name) for name in names)
    elif path == '/dev': yield iter([])
    else:
        with original_scandir(path) as entries: yield entries
os.scandir = view
os.path.lexists = lambda path: leak == 'device'
try: runpy.run_path(probe)
except (AssertionError, hermetic_safe_io.UnsafePathError): sys.exit(42)
'''
        result = subprocess.run([sys.executable, "-s", "-c", script, str(PROBE), leak,
                                 str(writer), str(config), str(cmdline), str(ROOT / 'python')],
                                pass_fds=(writer,), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10)
    finally:
        os.close(reader)
        os.close(writer)
    assert result.returncode == (0 if leak == 'none' else 42), result.stderr
