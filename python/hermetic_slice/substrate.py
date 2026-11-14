"""Pinned kernel metadata for production world images; no live probes run here."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import date
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from hermetic_safe_io import open_regular
from hermetic_slice import guest_kernel as kernel

MAX_SUBSTRATE_DATES = 4096
MAX_SUBSTRATE_DATES_BYTES = MAX_SUBSTRATE_DATES * 11
MAX_SUBSTRATE_IMAGE_BYTES = 512 * 1024 * 1024
EXTRACT_TIMEOUT_S = 60
BOUND_PATH = "etc/hermetic/substrate-bound"
DATES_PATH = "etc/hermetic/substrate-dates"


def _dates(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_SUBSTRATE_DATES_BYTES or not raw.endswith(b"\n"):
        raise ValueError("invalid substrate date list")
    previous = None
    for line in raw[:-1].split(b"\n"):
        if not re.fullmatch(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}", line):
            raise ValueError("invalid substrate date list")
        try:
            value = date.fromisoformat(line.decode("ascii"))
        except ValueError:
            raise ValueError("invalid substrate date list") from None
        if value.year < 1970 or previous is not None and value <= previous:
            raise ValueError("invalid substrate date list")
        previous = value
    return raw


def substrate_files(
    kernel_lock: Path = kernel.DEFAULT_KERNEL_DIR / "kernel.lock.json",
    *, kernel_image: Path | None = None, clockprobe_bin: Path | None = None,
) -> dict[str, bytes]:
    """Validate inputs before creating outputs. Optional image dates use the Rust parser.

    The release date is metadata only: it never authorizes a blanket date exemption.
    Image/extractor descriptors stay pinned through the bounded offline extraction.
    """
    if (kernel_image is None) != (clockprobe_bin is None):
        raise ValueError("kernel image and clockprobe binary must be supplied together")
    with os.fdopen(open_regular(kernel_lock, kernel.MAX_LOCK_BYTES), "rb") as stream:
        raw = stream.read(kernel.MAX_LOCK_BYTES + 1)
    try:
        if len(raw) > kernel.MAX_LOCK_BYTES:
            raise ValueError
        lock = kernel.validate_lock(json.loads(raw, object_pairs_hook=kernel._pairs), for_build=True)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid substrate kernel lock") from None
    release = kernel.release_datetime(lock)
    files = {BOUND_PATH: (release.date().isoformat() + "\n").encode("ascii")}
    if kernel_image is None:
        return files
    with ExitStack() as stack:
        image = stack.enter_context(os.fdopen(open_regular(kernel_image, MAX_SUBSTRATE_IMAGE_BYTES), "rb"))
        executable = stack.enter_context(os.fdopen(open_regular(clockprobe_bin, kernel.MAX_IMAGE_BYTES), "rb"))
        process = subprocess.Popen(
            [f"/proc/self/fd/{executable.fileno()}", "--extract-substrate-dates"],
            pass_fds=(executable.fileno(),), stdin=image, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={"LANG": "C", "TZ": "UTC"}, start_new_session=True,
        )
        complete = False
        try:
            output = bytearray()
            end = time.monotonic() + EXTRACT_TIMEOUT_S
            with selectors.DefaultSelector() as poll:
                poll.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = end - time.monotonic()
                    if remaining <= 0 or not poll.select(remaining):
                        raise ValueError("substrate extraction timed out")
                    chunk = os.read(process.stdout.fileno(), MAX_SUBSTRATE_DATES_BYTES + 1 - len(output))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_SUBSTRATE_DATES_BYTES:
                        raise ValueError("substrate extraction exceeds byte cap")
            if process.wait(timeout=max(0, end - time.monotonic())) != 0:
                raise ValueError("substrate extraction failed")
            files[DATES_PATH] = _dates(bytes(output))
            complete = True
        finally:
            if not complete:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=EXTRACT_TIMEOUT_S)
            if process.stdout is not None:
                process.stdout.close()
    return files
