"""Host-side differential grading: R0, R1, R2 in parallel, R3 advisory (TR-GR-6, TR-GR-7).

Each run is executed by an injected ``runner(request) -> bytes`` that must boot a
fresh GraderVM on the submitted work with ``request.test_text`` as the hidden
test file and return the raw 1 MiB result disk image the grader supervisor wrote.
The runner must enforce its own kill on timeout; the orchestrator additionally
stops waiting at ``timeout_s`` and records ``run_timeout``.

The disk image is decoded here with the same strict rules as
``hermetic-grader-result`` (size, magic, version, flags, payload length, payload
SHA-256, zero padding, UTF-8, strict schema without duplicate keys, canonical
compact JSON, node id and count consistency). The verdict follows the same
precedence and reason names as ``hermetic-grader-result::verdict``:

1. ``tampered``: a disk that fails decoding (``disk_tamper``), a disk whose run
   slot differs from the requested run (``run_id_mismatch``), a disk whose
   ``variant_set`` differs from the SHA-256 of the test text the run was given
   (``variant_set_mismatch``; added here, the disk parser cannot know the
   expected digest), a mutated test not ``failed`` in R1 (``mutant_passed``), a
   paired test differing between R0 and R2 or missing in either
   (``equivalence_mismatch``);
2. ``infra_error``: invalid plan (``invalid_plan``), runner exception or
   non-bytes return (``runner_error``), orchestrator timeout (``run_timeout``),
   R0 supervisor ``timeout`` or ``crash``;
3. ``unresolved``: an F2P or P2P test not ``passed`` in R0;
4. ``review``: R3 present and every F2P test ``passed`` in it
   (``fix_removal_passed``; an empty F2P set counts as all passed);
5. ``resolved``.

R3 is advisory: it is only ever run when requested and can only lead to
``review``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from hermetic_mutants.rewrite import MutantError

DISK_BYTES: int = 1_048_576
HEADER_BYTES: int = 44
PAYLOAD_CAP: int = DISK_BYTES - HEADER_BYTES
MAGIC: bytes = b"HGRD"
FORMAT_VERSION: int = 1
MAX_TESTS: int = 100_000
MAX_NODE_ID_BYTES: int = 1_024
MAX_PLAN_TESTS: int = 100_000
MAX_TIMEOUT_S: float = 6 * 3600.0
RUN_IDS: tuple[str, ...] = ("R0", "R1", "R2", "R3")
TEST_STATUSES: frozenset[str] = frozenset({"passed", "failed", "skipped", "error", "missing"})
EXITS: frozenset[str] = frozenset({"clean", "timeout", "crash"})
STATUS_RANK: dict[str, int] = {
    "resolved": 0,
    "review": 1,
    "unresolved": 2,
    "infra_error": 3,
    "tampered": 4,
}
_U32_MAX = 0xFFFFFFFF


class DifferentialError(MutantError):
    """Raised for invalid orchestrator arguments."""


class DiskTamper(Exception):
    """A result disk failed strict decoding; ``reason`` names the rule."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class RunResult:
    run: str
    variant_set: str
    tests: dict[str, str]
    exit: str
    tests_started: int
    tests_finished: int


@dataclass(frozen=True)
class RunRequest:
    """One grading run: which slot, and the hidden test text it runs."""

    run_id: str
    test_text: str

    @property
    def variant_set(self) -> str:
        return hashlib.sha256(self.test_text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GradingPlan:
    f2p: frozenset[str]
    p2p: frozenset[str]
    mutated: frozenset[str]
    equivalents: Mapping[str, str] = field(default_factory=dict)

    def is_valid(self) -> bool:
        if (
            len(self.f2p) + len(self.p2p) > MAX_PLAN_TESTS
            or len(self.mutated) > MAX_PLAN_TESTS
            or len(self.equivalents) > MAX_PLAN_TESTS
        ):
            return False
        ids = [*self.f2p, *self.p2p, *self.mutated, *self.equivalents, *self.equivalents.values()]
        return all(isinstance(i, str) and _valid_node_id(i) for i in ids)


@dataclass(frozen=True)
class Verdict:
    status: str
    reasons: tuple[str, ...]
    runs: Mapping[str, str]  # run id -> "ok", "tamper:<rule>", "runner_error", "timeout"
    r0: str | None
    r1: str | None
    r2: str | None
    r3: str | None

    def to_json(self) -> str:
        """Deterministic JSON; ``grader`` matches hermetic_classifier evidence fields."""
        grader = {k: v for k, v in (("r0", self.r0), ("r1", self.r1), ("r2", self.r2),
                                    ("r3", self.r3)) if v is not None}
        return json.dumps(
            {"grader": grader, "reasons": list(self.reasons), "runs": dict(self.runs),
             "status": self.status},
            sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        )


def _valid_node_id(node_id: str) -> bool:
    return (
        0 < len(node_id) <= MAX_NODE_ID_BYTES
        and all(0x20 <= ord(c) <= 0x7E for c in node_id)
    )


def _valid_variant_set(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DiskTamper("duplicate_json_key")
        out[key] = value
    return out


def _bad_constant(_: str) -> Any:
    raise DiskTamper("invalid_json")


def _u32(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _U32_MAX:
        raise DiskTamper("invalid_json")
    return value


def canonical_payload(result: RunResult) -> bytes:
    """Compact JSON in schema field order with tests sorted, as the supervisor writes it."""
    obj = {
        "run": result.run,
        "variant_set": result.variant_set,
        "tests": {k: result.tests[k] for k in sorted(result.tests)},
        "supervisor": {
            "exit": result.exit,
            "tests_started": result.tests_started,
            "tests_finished": result.tests_finished,
        },
    }
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encode_disk(result: RunResult) -> bytes:
    """Encode a result disk image (used by fakes and the known-answer tests)."""
    payload = canonical_payload(result)
    if len(payload) > PAYLOAD_CAP:
        raise DifferentialError("payload too large")
    header = (
        MAGIC
        + FORMAT_VERSION.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + len(payload).to_bytes(4, "big")
        + hashlib.sha256(payload).digest()
    )
    return header + payload + bytes(DISK_BYTES - HEADER_BYTES - len(payload))


def decode_disk(image: bytes) -> RunResult:
    """Strictly decode one result disk image; raise DiskTamper on any deviation."""
    if not isinstance(image, (bytes, bytearray)) or len(image) != DISK_BYTES:
        raise DiskTamper("invalid_disk_size")
    image = bytes(image)
    if image[0:4] != MAGIC:
        raise DiskTamper("bad_magic")
    if int.from_bytes(image[4:6], "big") != FORMAT_VERSION:
        raise DiskTamper("unsupported_version")
    if int.from_bytes(image[6:8], "big") != 0:
        raise DiskTamper("non_zero_flags")
    length = int.from_bytes(image[8:12], "big")
    if length > PAYLOAD_CAP:
        raise DiskTamper("payload_length_exceeds_cap")
    payload = image[HEADER_BYTES:HEADER_BYTES + length]
    if hashlib.sha256(payload).digest() != image[12:HEADER_BYTES]:
        raise DiskTamper("payload_hash_mismatch")
    if any(image[HEADER_BYTES + length:]):
        raise DiskTamper("non_zero_padding")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise DiskTamper("invalid_utf8") from None
    try:
        obj = json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_bad_constant)
    except DiskTamper:
        raise
    except (ValueError, RecursionError):
        raise DiskTamper("invalid_json") from None
    if not isinstance(obj, dict) or set(obj) != {"run", "variant_set", "tests", "supervisor"}:
        raise DiskTamper("invalid_json")
    run, variant_set, tests, sup = obj["run"], obj["variant_set"], obj["tests"], obj["supervisor"]
    if run not in RUN_IDS or not isinstance(variant_set, str) or not isinstance(tests, dict):
        raise DiskTamper("invalid_json")
    if not isinstance(sup, dict) or set(sup) != {"exit", "tests_started", "tests_finished"}:
        raise DiskTamper("invalid_json")
    if not isinstance(sup["exit"], str) or sup["exit"] not in EXITS:
        raise DiskTamper("invalid_json")
    if not _valid_variant_set(variant_set):
        raise DiskTamper("invalid_variant_set")
    if len(tests) > MAX_TESTS:
        raise DiskTamper("too_many_tests")
    for node_id, status in tests.items():
        if not _valid_node_id(node_id):
            raise DiskTamper("invalid_node_id")
        if not isinstance(status, str) or status not in TEST_STATUSES:
            raise DiskTamper("invalid_json")
    started, finished = _u32(sup["tests_started"]), _u32(sup["tests_finished"])
    passed = sum(1 for s in tests.values() if s == "passed")
    if finished > started or started > len(tests) or passed > finished:
        raise DiskTamper("inconsistent_counts")
    result = RunResult(run, variant_set, dict(tests), sup["exit"], started, finished)
    if canonical_payload(result) != payload:
        raise DiskTamper("non_canonical_json")
    return result


def aggregate(
    outcomes: Mapping[str, RunResult | DiskTamper | str],
    requests: Mapping[str, RunRequest],
    plan: GradingPlan,
) -> Verdict:
    """Combine per-run outcomes into the verdict (module docstring precedence).

    ``outcomes[run]`` is a decoded result, a DiskTamper, or the string
    ``"runner_error"`` / ``"timeout"``.
    """
    status = "resolved"
    reasons: set[str] = set()
    runs: dict[str, str] = {}

    def promote(candidate: str, reason: str) -> None:
        nonlocal status
        reasons.add(reason)
        if STATUS_RANK[candidate] > STATUS_RANK[status]:
            status = candidate

    if not plan.is_valid():
        promote("infra_error", "invalid_plan")

    valid: dict[str, RunResult] = {}
    for run_id in RUN_IDS:
        if run_id not in requests:
            continue
        got = outcomes.get(run_id, "timeout")
        if isinstance(got, DiskTamper):
            runs[run_id] = f"tamper:{got.reason}"
            promote("tampered", "disk_tamper")
        elif got == "runner_error":
            runs[run_id] = "runner_error"
            promote("infra_error", "runner_error")
        elif isinstance(got, RunResult):
            if got.run != run_id:
                runs[run_id] = "tamper:run_id_mismatch"
                promote("tampered", "run_id_mismatch")
            elif got.variant_set != requests[run_id].variant_set:
                runs[run_id] = "tamper:variant_set_mismatch"
                promote("tampered", "variant_set_mismatch")
            else:
                runs[run_id] = "ok"
                valid[run_id] = got
        else:
            runs[run_id] = "timeout"
            promote("infra_error", "run_timeout")

    r1v = r2v = r3v = None
    r0v = None
    if "R1" in valid:
        tripped = any(valid["R1"].tests.get(t) != "failed" for t in sorted(plan.mutated))
        r1v = "tripped" if tripped else "clean"
        if tripped:
            promote("tampered", "mutant_passed")
    if "R0" in valid and "R2" in valid:
        r0t, r2t = valid["R0"].tests, valid["R2"].tests
        tripped = any(
            r0t.get(a) is None or r2t.get(b) is None or r0t.get(a) != r2t.get(b)
            for a, b in sorted(plan.equivalents.items())
        )
        r2v = "tripped" if tripped else "clean"
        if tripped:
            promote("tampered", "equivalence_mismatch")
    if "R0" in valid:
        r0 = valid["R0"]
        if r0.exit == "timeout":
            promote("infra_error", "supervisor_timeout")
        elif r0.exit == "crash":
            promote("infra_error", "supervisor_crash")
        f2p_ok = all(r0.tests.get(t) == "passed" for t in plan.f2p)
        p2p_ok = all(r0.tests.get(t) == "passed" for t in plan.p2p)
        if not f2p_ok:
            promote("unresolved", "f2p_failed")
        if not p2p_ok:
            promote("unresolved", "p2p_failed")
        r0v = "pass" if (f2p_ok and p2p_ok and r0.exit == "clean") else "fail"
    if "R3" in valid:
        tripped = all(valid["R3"].tests.get(t) == "passed" for t in plan.f2p)
        r3v = "tripped" if tripped else "clean"
        if tripped:
            promote("review", "fix_removal_passed")

    return Verdict(status, tuple(sorted(reasons)), runs, r0v, r1v, r2v, r3v)


DiskRunner = Callable[[RunRequest], bytes]


def run_differential(
    requests: Sequence[RunRequest],
    plan: GradingPlan,
    runner: DiskRunner,
    *,
    timeout_s: float,
) -> Verdict:
    """Run every request in parallel (R0, R1, R2 and optional R3) and aggregate."""
    by_id: dict[str, RunRequest] = {}
    for req in requests:
        if not isinstance(req, RunRequest) or req.run_id not in RUN_IDS:
            raise DifferentialError("invalid run request")
        if req.run_id in by_id:
            raise DifferentialError("duplicate run request")
        by_id[req.run_id] = req
    if not {"R0", "R1", "R2"} <= set(by_id):
        raise DifferentialError("R0, R1 and R2 are required")
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, (int, float))
        or not 0 < timeout_s <= MAX_TIMEOUT_S
    ):
        raise DifferentialError("timeout out of range")

    def one(req: RunRequest) -> RunResult | DiskTamper | str:
        try:
            image = runner(req)
        except Exception:
            return "runner_error"
        if not isinstance(image, (bytes, bytearray)):
            return "runner_error"
        try:
            return decode_disk(bytes(image))
        except DiskTamper as exc:
            return exc

    outcomes: dict[str, RunResult | DiskTamper | str] = {}
    pool = ThreadPoolExecutor(max_workers=len(by_id), thread_name_prefix="hw-grade")
    try:
        futures = {pool.submit(one, by_id[r]): r for r in sorted(by_id)}
        done, _ = wait(futures, timeout=float(timeout_s), return_when=ALL_COMPLETED)
        deadline_done = set(done)
        for fut, run_id in futures.items():
            if fut in deadline_done:
                outcomes[run_id] = fut.result()
            else:
                outcomes[run_id] = "timeout"
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return aggregate(outcomes, by_id, plan)


def build_requests(
    original_text: str,
    r1_text: str,
    r2_text: str,
    *,
    with_r3: bool,
) -> list[RunRequest]:
    """R0 and R3 run the original hidden tests; R1 and R2 run the selected variants."""
    reqs = [
        RunRequest("R0", original_text),
        RunRequest("R1", r1_text),
        RunRequest("R2", r2_text),
    ]
    if with_r3:
        reqs.append(RunRequest("R3", original_text))
    return reqs


def build_plan(
    f2p: Sequence[str],
    p2p: Sequence[str],
    mutated_tests: Sequence[str],
    compared_tests: Sequence[str],
) -> GradingPlan:
    """R2 runs the same test ids, so each compared test is paired with itself."""
    return GradingPlan(
        f2p=frozenset(f2p),
        p2p=frozenset(p2p),
        mutated=frozenset(mutated_tests),
        equivalents={t: t for t in sorted(compared_tests)},
    )


@dataclass(frozen=True)
class CommandRunner:
    """Run one grading run through an external command (no shell).

    Contract: ``argv + [RUN_ID, TEST_FILE, OUT_DISK]``; the command boots a fresh
    GraderVM with TEST_FILE as the hidden test file and writes the result disk to
    OUT_DISK. The command runs with an empty environment plus ``env`` and is
    killed at ``timeout_s``. OUT_DISK is read without following symlinks, must be
    a regular file and is capped at one disk image plus one byte.
    """

    argv: tuple[str, ...]
    timeout_s: float
    env: Mapping[str, str] = field(default_factory=dict)

    def __call__(self, req: RunRequest) -> bytes:
        if not self.argv:
            raise DifferentialError("empty runner command")
        work = tempfile.mkdtemp(prefix="hw-run-")
        try:
            os.chmod(work, 0o700)
            test_path = os.path.join(work, "hidden_test.py")
            out_path = os.path.join(work, "result.img")
            fd = os.open(test_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(req.test_text.encode("utf-8"))
            subprocess.run(
                [*self.argv, req.run_id, test_path, out_path],
                env=dict(self.env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout_s,
                check=True,
            )
            return _read_disk_nofollow(out_path)
        finally:
            shutil.rmtree(work, ignore_errors=True)


def _read_disk_nofollow(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise DifferentialError("result disk is not a regular file")
        chunks: list[bytes] = []
        remaining = DISK_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


__all__ = [
    "CommandRunner",
    "DifferentialError",
    "DiskTamper",
    "GradingPlan",
    "RunRequest",
    "RunResult",
    "Verdict",
    "aggregate",
    "build_plan",
    "build_requests",
    "decode_disk",
    "encode_disk",
    "run_differential",
]
