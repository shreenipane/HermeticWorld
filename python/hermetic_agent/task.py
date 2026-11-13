"""Read bounded task inputs through pinned file descriptors."""

from datetime import datetime, timezone
import os
import re

from hermetic_safe_io import open_regular
from .errors import ProtocolError, LimitError
from .protocol import parse_json

MAX_TASK_BYTES = 1024 * 1024


def read_input(path, cap=MAX_TASK_BYTES):
    try:
        descriptor = open_regular(path, cap)
        with os.fdopen(descriptor, "rb") as source:
            raw = source.read(cap + 1)
        if len(raw) > cap:
            raise LimitError("Input byte limit")
        return raw
    except (OSError, ValueError):
        raise ProtocolError("Task input refused") from None


def clock_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ProtocolError("Invalid world clock")
    try:
        clock = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if clock.year < 1601:
            raise ValueError()
        return int((clock - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
    except (ValueError, OverflowError):
        raise ProtocolError("Invalid world clock") from None


def task_clock(manifest):
    value = parse_json(read_input(manifest))
    if not isinstance(value, dict) or not isinstance(value.get("cutoffs"), dict):
        raise ProtocolError("Missing world clock")
    result = value["cutoffs"].get("t_clock")
    clock_value(result)
    return result
