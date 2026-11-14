"""Base-failing assertion finder (TR-GR-9, TR-GR-7).

Input: the hidden test file as bytes, the assertion log that
``hermetic_assert_recorder`` wrote while the tests ran on the base tree, and the
set of line numbers the hidden test patch added or changed ("hidden lines").

Output: the mutant site ids (``hermetic_mutants.rewrite`` numbering,
``<qualname>:<index>``) that R1 may mutate. A site is eligible only when all of
these hold:

1. Its test function ran on the base tree and every recorded node of that
   function (every parametrisation) has outcome ``failed``.
2. In every node of that function the site either failed when reached (the
   raising assertion) or was not reached and its checked value depends, by data
   flow, on the statement that raised (``hermetic_assert_flow``). A site that
   was recorded passing in any node is never eligible, whatever the flow says.
3. Every line of the assertion statement is a hidden line.
4. ``hermetic_mutants.rewrite.can_mutate_site`` accepts it.

Anything the finder cannot interpret (unknown node ids, recorder internal
errors, malformed entries) fails closed: the affected function contributes no
sites and the reason is recorded. Malformed top-level input raises
``FinderError``. The result is deterministic: sorted ids, sorted reasons.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.flow import analyze_flow
from hermetic_assert_flow.sites import list_assertion_sites
from hermetic_mutants.rewrite import (
    MutantError,
    can_mutate_site,
    find_assertion_sites,
    parse_test_bytes,
)

MAX_LOG_BYTES: int = 8 * 1024 * 1024
MAX_LOG_TESTS: int = 10_000
MAX_REACHED_ENTRIES: int = 1_000
MAX_HIDDEN_LINES: int = 1_000_000
MAX_NODEID_LEN: int = 512
MAX_LINE: int = 1_000_000

FAILED = "failed"


class FinderError(MutantError):
    """Raised when finder input is malformed at the top level."""


@dataclass(frozen=True)
class FinderResult:
    """Eligible mutant site ids plus the per-function reasons for exclusions."""

    eligible_sites: tuple[str, ...]
    base_failing_tests: tuple[str, ...]
    excluded: tuple[tuple[str, str], ...]

    def to_json(self) -> str:
        return json.dumps(
            {
                "base_failing_tests": list(self.base_failing_tests),
                "eligible_sites": list(self.eligible_sites),
                "excluded": [[q, r] for q, r in self.excluded],
            },
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise FinderError("duplicate key in assertion log")
        out[key] = value
    return out


def _reject_constant(_: str) -> Any:
    raise FinderError("non-finite number in assertion log")


def parse_recorder_log(data: bytes) -> dict[str, Any]:
    """Parse the recorder log bytes strictly (size cap, UTF-8, no duplicate keys)."""
    if not isinstance(data, bytes):
        raise FinderError("assertion log must be bytes")
    if len(data) > MAX_LOG_BYTES:
        raise FinderError("assertion log exceeds size cap")
    try:
        text = data.decode("utf-8")
        obj = json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except FinderError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise FinderError("assertion log is not valid JSON") from exc
    if not isinstance(obj, dict) or set(obj) != {"tests", "internal_errors"}:
        raise FinderError("assertion log has an unexpected shape")
    if not isinstance(obj["tests"], dict) or not isinstance(obj["internal_errors"], list):
        raise FinderError("assertion log has an unexpected shape")
    if len(obj["tests"]) > MAX_LOG_TESTS:
        raise FinderError("assertion log has too many tests")
    return obj


def nodeid_qualname(nodeid: str, test_file: str) -> str | None:
    """Map ``<test_file>::[Class::]test_name[params]`` to ``[Class.]test_name``.

    Returns None for node ids of other files or of any other shape.
    """
    prefix = test_file + "::"
    if not nodeid.startswith(prefix):
        return None
    rest = nodeid[len(prefix):]
    bracket = rest.find("[")
    if bracket != -1:
        if not rest.endswith("]"):
            return None
        rest = rest[:bracket]
    parts = rest.split("::")
    if len(parts) == 1 and parts[0].startswith("test") and parts[0].isidentifier():
        return parts[0]
    if (
        len(parts) == 2
        and parts[0].startswith("Test")
        and parts[0].isidentifier()
        and parts[1].startswith("test")
        and parts[1].isidentifier()
    ):
        return f"{parts[0]}.{parts[1]}"
    return None


def _is_line(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_LINE


def _node_eligible_flow_ids(
    source: bytes,
    qualname: str,
    entry: Any,
    flow_by_line: Mapping[int, list[str]],
) -> tuple[set[str], set[str]] | str:
    """Return (eligible flow ids, passed flow ids) for one recorded node, or a reason."""
    if not isinstance(entry, dict):
        return "malformed test entry"
    if entry.get("outcome") != FAILED:
        return "not failing on base"
    raising_line = entry.get("raising_line")
    if not _is_line(raising_line):
        return "no raising line"
    reached = entry.get("reached")
    if not isinstance(reached, list) or len(reached) > MAX_REACHED_ENTRIES:
        return "malformed reached list"
    failed_ids: set[str] = set()
    passed_ids: set[str] = set()
    for item in reached:
        if not isinstance(item, dict) or not isinstance(item.get("passed"), bool):
            return "malformed reached entry"
        site_id = item.get("site_id")
        if site_id is None:
            line = item.get("line")
            if not _is_line(line):
                return "malformed reached entry"
            candidates = flow_by_line.get(line, [])
            if len(candidates) != 1:
                return "reached line does not name one site"
            site_id = candidates[0]
        if not isinstance(site_id, str) or not site_id.startswith(qualname + "#"):
            return "reached site of another function"
        (passed_ids if item["passed"] else failed_ids).add(site_id)
    try:
        result = analyze_flow(
            source=source,
            function=qualname,
            raising_line=raising_line,
            reached_site_ids=sorted(failed_ids),
        )
    except FlowError:
        return "flow analysis refused"
    return set(result.eligible) - passed_ids, passed_ids


def find_base_failing_sites(
    source: bytes,
    recorder_log: bytes,
    test_file: str,
    hidden_lines: Iterable[int],
) -> FinderResult:
    """Return the mutant site ids R1 may mutate (see module docstring)."""
    if not isinstance(source, bytes):
        raise FinderError("source must be bytes")
    if not isinstance(test_file, str) or not test_file or "::" in test_file:
        raise FinderError("test_file must be a non-empty relative node id path")
    hidden: set[int] = set()
    for line in hidden_lines:
        if not _is_line(line):
            raise FinderError("hidden line out of range")
        hidden.add(line)
        if len(hidden) > MAX_HIDDEN_LINES:
            raise FinderError("too many hidden lines")
    log = parse_recorder_log(recorder_log)
    tree = parse_test_bytes(source)

    mutant_by_pos: dict[tuple[int, int], Any] = {}
    for site in find_assertion_sites(tree):
        node = site.node
        mutant_by_pos[(node.lineno, node.col_offset)] = site

    excluded: dict[str, str] = {}
    if log["internal_errors"]:
        return FinderResult((), (), (("*", "recorder internal errors"),))

    nodes_by_qual: dict[str, list[Any]] = {}
    for nodeid in sorted(log["tests"]):
        if not isinstance(nodeid, str) or len(nodeid) > MAX_NODEID_LEN:
            raise FinderError("invalid node id in assertion log")
        qual = nodeid_qualname(nodeid, test_file)
        if qual is None:
            continue
        nodes_by_qual.setdefault(qual, []).append(log["tests"][nodeid])

    eligible: set[str] = set()
    failing_tests: list[str] = []
    for qual in sorted(nodes_by_qual):
        try:
            flow_sites = list_assertion_sites(source, qual)
        except FlowError:
            excluded[qual] = "function not found"
            continue
        flow_by_line: dict[int, list[str]] = {}
        flow_pos: dict[str, tuple[int, int, int]] = {}
        for fs in flow_sites:
            flow_by_line.setdefault(fs.lineno, []).append(fs.site_id)
            flow_pos[fs.site_id] = (fs.lineno, fs.end_lineno, fs.col_offset)
        common: set[str] | None = None
        passed_any: set[str] = set()
        reason: str | None = None
        for entry in nodes_by_qual[qual]:
            got = _node_eligible_flow_ids(source, qual, entry, flow_by_line)
            if isinstance(got, str):
                reason = got
                break
            ids, passed = got
            passed_any |= passed
            common = ids if common is None else common & ids
        if reason is not None:
            excluded[qual] = reason
            continue
        failing_tests.append(qual)
        chosen = sorted((common or set()) - passed_any)
        kept = 0
        for flow_id in chosen:
            pos = flow_pos.get(flow_id)
            if pos is None:
                continue
            lineno, end_lineno, col = pos
            if any(line not in hidden for line in range(lineno, end_lineno + 1)):
                continue
            msite = mutant_by_pos.get((lineno, col))
            if msite is None or msite.func_qualname != qual or not can_mutate_site(msite):
                continue
            eligible.add(msite.site_id)
            kept += 1
        if kept == 0:
            excluded[qual] = "no mutable base-failing site in hidden lines"

    return FinderResult(
        eligible_sites=tuple(sorted(eligible)),
        base_failing_tests=tuple(failing_tests),
        excluded=tuple(sorted(excluded.items())),
    )


def site_function(site_id: str) -> str:
    """Return the qualified test function name of a mutant site id."""
    qual, sep, _ = site_id.rpartition(":")
    if not sep or not qual:
        raise FinderError("malformed site id")
    return qual


__all__ = [
    "FinderError",
    "FinderResult",
    "find_base_failing_sites",
    "nodeid_qualname",
    "parse_recorder_log",
    "site_function",
]
