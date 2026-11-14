"""Run-time real-date sentinel (D12, TR-SEC-5) for the Mode H harness.

Scans everything the harness sends to the model (system prompt, task prompt, every user
turn) and every observation returned from the world (command output), for the real run
date in common formats, host names and host paths. It mirrors the Rust sentinel
(``hermetic_sealcheck::d12_runtime``), which the gateway uses for Mode G traffic:

- only counts are kept, keyed ``source:channel``; no matched text, so the summary never
  echoes host data;
- text is scanned raw and after decoding common escapes (``\\uXXXX``, ``\\/``, ``%XX``,
  ``&#NN;``, ``&#xHH;``, full-width digits and separators);
- streams keep a tail of the previous chunk so a date split across chunks is seen;
- fail closed: once the byte cap is passed the scan is incomplete and
  ``date_leak_observed`` is true.

``merge_summaries`` combines this summary with the gateway's ``date_sentinel.json`` into the
run record's ``date_leak_observed``.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

MAX_RUN_SCAN_CHARS = 1 << 30
MAX_OPTION_ITEMS = 10_000
MAX_OPTION_LEN = 4096
STREAM_TAIL_CHARS = 256
MAX_HIT_KEYS = 256

_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}
_MON = r"(?P<mon>" + "|".join(sorted(_MONTHS, key=len, reverse=True)) + r")"
_SEP = r"[-/.]"
_RE_YMD = re.compile(r"(?<![0-9])(?P<y>\d{4})(?P<s>" + _SEP + r")(?P<a>\d{1,2})(?P=s)(?P<b>\d{1,2})(?![0-9])")
_RE_DMY = re.compile(r"(?<![0-9])(?P<a>\d{1,2})(?P<s>" + _SEP + r")(?P<b>\d{1,2})(?P=s)(?P<y>\d{4})(?![0-9])")
_RE_COMPACT = re.compile(r"(?<![0-9])(?P<y>\d{4})(?P<a>\d{2})(?P<b>\d{2})(?![0-9])")
_RE_MON_D_Y = re.compile(
    r"(?<![A-Za-z])" + _MON + r"\.?\s+(?P<d>\d{1,2})(?:st|nd|rd|th)?,?\s+(?P<y>\d{4})(?![0-9])",
    re.IGNORECASE,
)
_RE_D_MON_Y = re.compile(
    r"(?<![0-9])(?P<d>\d{1,2})(?:st|nd|rd|th)?[\s-]+" + _MON + r"\.?[\s,-]+(?P<y>\d{4})(?![0-9])",
    re.IGNORECASE,
)
_RE_EPOCH = re.compile(r"(?<![0-9])(\d{10}|\d{13})(?![0-9])")

_FOLD = {chr(0xFF10 + i): str(i) for i in range(10)}
_FOLD.update({
    "－": "-", "‐": "-", "‑": "-", "‒": "-", "–": "-", "−": "-",
    "／": "/", "．": ".", "：": ":", "　": " ", " ": " ",
})
_RE_ESC = re.compile(r"\\u([0-9a-fA-F]{4})|\\/|%([0-7][0-9a-fA-F])|&#[xX]([0-9a-fA-F]{1,6});|&#([0-9]{1,7});")


def decode_escapes(text: str) -> str | None:
    """Decode common escape forms; ``None`` if nothing changed."""

    def sub(m: re.Match[str]) -> str:
        if m.group(1):
            return chr(int(m.group(1), 16))
        if m.group(0) == "\\/":
            return "/"
        if m.group(2):
            return chr(int(m.group(2), 16))
        cp = int(m.group(3), 16) if m.group(3) else int(m.group(4))
        return chr(cp) if cp <= 0x10FFFF else m.group(0)

    out = _RE_ESC.sub(sub, text)
    out = "".join(_FOLD.get(c, c) for c in out)
    return None if out == text else out


@dataclass
class SentinelSummary:
    date_leak_observed: bool = False
    scan_incomplete: bool = False
    hits: dict[str, int] = field(default_factory=dict)
    incomplete: dict[str, int] = field(default_factory=dict)
    bytes_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "date_leak_observed": self.date_leak_observed,
            "scan_incomplete": self.scan_incomplete,
            "hits": dict(sorted(self.hits.items())),
            "incomplete": dict(sorted(self.incomplete.items())),
            "bytes_scanned": self.bytes_scanned,
        }


def _bump(d: dict[str, int], key: str, n: int) -> None:
    if key in d or len(d) < MAX_HIT_KEYS:
        d[key] = d.get(key, 0) + n
    else:
        d["overflow:other"] = d.get("overflow:other", 0) + n


class DateSentinel:
    """Count-only D12 sentinel. Host names and paths are never echoed."""

    def __init__(
        self,
        real_date: _dt.date,
        *,
        tolerance_days: int = 1,
        host_names: Iterable[str] = (),
        host_paths: Iterable[str] = (),
        max_chars: int = MAX_RUN_SCAN_CHARS,
    ) -> None:
        names = [n for n in host_names if n]
        paths = [p for p in host_paths if p]
        if (
            len(names) > MAX_OPTION_ITEMS
            or len(paths) > MAX_OPTION_ITEMS
            or any(len(x) > MAX_OPTION_LEN for x in names + paths)
            or not 0 <= tolerance_days <= 366
        ):
            raise ValueError("D12 option cap exceeded")
        self._lo = real_date - _dt.timedelta(days=tolerance_days)
        self._hi = real_date + _dt.timedelta(days=tolerance_days)
        lo_ts = _dt.datetime.combine(self._lo, _dt.time(), _dt.timezone.utc).timestamp()
        self._epoch = (int(lo_ts), int(lo_ts) + 86400 * (2 * tolerance_days + 1))
        self._names = [
            re.compile(r"(?<![A-Za-z0-9.-])" + re.escape(n) + r"(?![A-Za-z0-9.-])", re.IGNORECASE)
            for n in names
        ]
        self._paths = paths
        self._max = max_chars
        self._s = SentinelSummary()

    def __repr__(self) -> str:
        return "DateSentinel(<redacted>)"

    # -- detection -------------------------------------------------------------------
    def _in_window(self, y: int, m: int, d: int) -> bool:
        try:
            return self._lo <= _dt.date(y, m, d) <= self._hi
        except ValueError:
            return False

    def _pair(self, y: int, a: int, b: int) -> bool:
        return self._in_window(y, a, b) or self._in_window(y, b, a)

    def _count_view(self, text: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        dates = 0
        for rx in (_RE_YMD, _RE_DMY, _RE_COMPACT):
            for m in rx.finditer(text):
                if self._pair(int(m["y"]), int(m["a"]), int(m["b"])):
                    dates += 1
        for rx in (_RE_MON_D_Y, _RE_D_MON_Y):
            for m in rx.finditer(text):
                if self._in_window(int(m["y"]), _MONTHS[m["mon"].lower()], int(m["d"])):
                    dates += 1
        lo, hi = self._epoch
        for m in _RE_EPOCH.finditer(text):
            v = int(m.group(1))
            if len(m.group(1)) == 13:
                v //= 1000
            if lo <= v < hi:
                dates += 1
        if dates:
            counts["real_date"] = dates
        names = sum(1 for rx in self._names if rx.search(text))
        if names:
            counts["host_name"] = names
        paths = sum(1 for p in self._paths if p in text)
        if paths:
            counts["host_path"] = paths
        return counts

    def _count(self, text: str) -> dict[str, int]:
        best = self._count_view(text)
        decoded = decode_escapes(text)
        if decoded is not None:
            for k, v in self._count_view(decoded).items():
                best[k] = max(best.get(k, 0), v)
        return best

    # -- recording -------------------------------------------------------------------
    def mark_incomplete(self, source: str, reason: str) -> None:
        self._s.scan_incomplete = True
        self._s.date_leak_observed = True
        _bump(self._s.incomplete, f"{source}:{reason}", 1)

    def _reserve(self, source: str, n: int) -> bool:
        self._s.bytes_scanned += n
        if self._s.bytes_scanned > self._max:
            self.mark_incomplete(source, "run_byte_cap")
            return False
        return True

    def _record(self, source: str, counts: dict[str, int]) -> None:
        for ch, n in counts.items():
            if n > 0:
                _bump(self._s.hits, f"{source}:{ch}", n)
                self._s.date_leak_observed = True

    def scan_text(self, source: str, text: str | bytes) -> None:
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        if not self._reserve(source, len(text)):
            return
        self._record(source, self._count(text))

    def stream(self, source: str) -> "TextStream":
        return TextStream(self, source)

    def summary(self) -> SentinelSummary:
        s = self._s
        return SentinelSummary(
            s.date_leak_observed, s.scan_incomplete, dict(s.hits), dict(s.incomplete), s.bytes_scanned
        )


class TextStream:
    """Chunked text: each chunk is scanned with the tail of the previous one."""

    def __init__(self, sentinel: DateSentinel, source: str) -> None:
        self._s = sentinel
        self._source = source
        self._tail = ""

    def feed(self, chunk: str) -> None:
        if not chunk or not self._s._reserve(self._source, len(chunk)):
            return
        window = self._tail + chunk
        total = self._s._count(window)
        old = self._s._count(self._tail)
        self._s._record(self._source, {k: max(0, v - old.get(k, 0)) for k, v in total.items()})
        self._tail = window[-STREAM_TAIL_CHARS:]


def merge_summaries(parts: Iterable[dict[str, Any] | SentinelSummary | None]) -> dict[str, Any]:
    """Combine sentinel summaries into one; a missing or malformed part fails closed."""
    out = SentinelSummary()
    for p in parts:
        if isinstance(p, SentinelSummary):
            p = p.to_dict()
        if not isinstance(p, dict) or not isinstance(p.get("date_leak_observed"), bool):
            out.scan_incomplete = True
            _bump(out.incomplete, "merge:missing_or_malformed", 1)
            continue
        out.scan_incomplete |= bool(p.get("scan_incomplete"))
        out.date_leak_observed |= p["date_leak_observed"]
        out.bytes_scanned += int(p.get("bytes_scanned") or 0)
        for key, src in (("hits", out.hits), ("incomplete", out.incomplete)):
            for k, v in (p.get(key) or {}).items():
                _bump(src, str(k), int(v))
    out.date_leak_observed = out.date_leak_observed or out.scan_incomplete or bool(out.hits)
    return out.to_dict()
