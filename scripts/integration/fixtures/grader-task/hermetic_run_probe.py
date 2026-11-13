"""Trusted sandbox assertions, run by every grader VM smoke boot."""

import fcntl
from itertools import islice
import json
import os
import stat
import sys

from hermetic_safe_io import open_regular

MAX_CONFIG_BYTES = 1024 * 1024
MAX_CMDLINE_BYTES = 4096
MAX_VIEW_ENTRIES = 4096


def read_capped(path, cap):
    with os.fdopen(open_regular(path, cap), 'rb') as stream:
        data = stream.read(cap + 1)
    assert len(data) <= cap
    return data


def names_capped(path):
    with os.scandir(path) as entries:
        names = [entry.name for entry in islice(entries, MAX_VIEW_ENTRIES + 1)]
    assert len(names) <= MAX_VIEW_ENTRIES
    return names


def verify_isolation():
    config = json.loads(read_capped('/etc/hermetic/grader/run.json', MAX_CONFIG_BYTES))
    assert 'run' not in config and 'run_name' not in config
    assert not any('RUN' in key or 'NONCE' in key for key in os.environ)
    assert not any(arg in ('R0', 'R1', 'R2', 'R3') for arg in sys.orig_argv)
    cmdline = read_capped('/proc/cmdline', MAX_CMDLINE_BYTES)
    assert b'hermetic.run' not in cmdline and b'nonce' not in cmdline.lower()
    assert not any(label in cmdline.split() for label in (b'R0', b'R1', b'R2', b'R3'))
    assert os.getpid() == 1 and os.getppid() == 0
    assert not os.path.lexists('/dev/vdb')
    assert not any(name.startswith('vd') for name in names_capped('/dev'))
    # The proc mount belongs to this PID namespace. There is no route through a
    # supervisor's root, memory, argv, environment or descriptor table.
    assert {name for name in names_capped('/proc') if name.isdigit()} == {'1'}
    fds = {int(name) for name in names_capped('/proc/self/fd')}
    # scandir itself briefly owns one descriptor, closed before this check.
    live = set()
    for fd in fds:
        try:
            os.fstat(fd)
        except OSError:
            continue
        live.add(fd)
    assert live == {0, 1, 2, 3}
    for fd in (0, 1, 2):
        assert os.fstat(fd).st_rdev == os.stat('/dev/null').st_rdev
    assert stat.S_ISFIFO(os.fstat(3).st_mode)
    assert fcntl.fcntl(3, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY


# Plugin import precedes pytest capture descriptors and repository imports.
verify_isolation()
