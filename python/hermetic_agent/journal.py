"""Atomically publish bounded host evidence before each remote command."""

import json
from hermetic_safe_io import atomic_write, open_parent
import os
import stat
from .errors import LimitError, ProtocolError
from .task import clock_value

MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_RECORDS = 1000


def validate_output(path):
    directory, leaf = open_parent(path)
    try:
        try:
            entry = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            entry = None
        if entry is not None and not stat.S_ISREG(entry.st_mode):
            raise ProtocolError("Output must be a regular file")
        parent = os.fstat(directory)
        return parent.st_dev, parent.st_ino, leaf
    finally:
        os.close(directory)


class CommandJournal:
    def __init__(self, path, *, t_clock):
        validate_output(path)
        self._path = path
        self._timestamp = clock_value(t_clock)
        self._records = []
        self._bytes = 0

    def record(self, record):
        raw = json.dumps(record | {"timestamp": self._timestamp}, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(self._records) >= MAX_JOURNAL_RECORDS or self._bytes + len(raw) > MAX_JOURNAL_BYTES:
            raise LimitError("Command journal limit")
        records = self._records + [raw]
        atomic_write(self._path, b"".join(records))
        self._records = records
        self._bytes += len(raw)
