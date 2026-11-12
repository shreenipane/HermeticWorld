"""Binary record format encoder and bounded streaming decoder for grader results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import json
import struct
from typing import Any, BinaryIO, Iterator

MAGIC: bytes = b"HGR1"
MAGIC_LEN: int = 4
HEADER_LEN: int = 5
HEADER_STRUCT: struct.Struct = struct.Struct("<BI")

MAX_RECORD: int = 64 * 1024  # 64 KiB maximum payload length per record
READ_CHUNK_SIZE: int = 4096  # Maximum bytes read per single fileobj.read() call
MAX_RECORDS: int = 100_000  # Maximum records allowed in a single stream
MAX_NODEID_LEN: int = 4096  # Maximum UTF-8 character length of a pytest nodeid
MAX_CHUNK_READS_PER_ITEM: int = (MAX_RECORD // READ_CHUNK_SIZE) + 16

VALID_OUTCOMES: frozenset[str] = frozenset({"passed", "failed", "skipped", "error"})

START_KEYS: frozenset[str] = frozenset({"seq", "nodeid"})
FINISH_KEYS: frozenset[str] = frozenset({"seq", "nodeid", "outcome", "duration_ms"})
END_KEYS: frozenset[str] = frozenset({"count"})


class HermeticGraderError(Exception):
    """Base typed error for all hermetic grader record operations."""


class RecordError(HermeticGraderError):
    """Typed error raised when encoding or decoding an invalid binary record stream."""


class PrematureEOFError(RecordError):
    """Typed error raised when a stream reaches EOF at a record boundary before END."""


class RecordType(IntEnum):
    """Wire type identifiers for binary records."""

    START = 1
    FINISH = 2
    END = 3


@dataclass(frozen=True, slots=True)
class StartRecord:
    """Record emitted immediately before a test's setup phase."""

    seq: int
    nodeid: str


@dataclass(frozen=True, slots=True)
class FinishRecord:
    """Record emitted immediately after a test's teardown phase."""

    seq: int
    nodeid: str
    outcome: str
    duration_ms: int


@dataclass(frozen=True, slots=True)
class EndRecord:
    """Record emitted at session completion with total preceding record count."""

    count: int


Record = StartRecord | FinishRecord | EndRecord


def _is_non_bool_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_nodeid(nodeid: Any) -> str:
    if not isinstance(nodeid, str):
        raise RecordError("Field 'nodeid' must be a string")
    if len(nodeid) == 0:
        raise RecordError("Field 'nodeid' must not be empty")
    if len(nodeid) > MAX_NODEID_LEN:
        raise RecordError("Field 'nodeid' exceeds MAX_NODEID_LEN")
    if "\x00" in nodeid:
        raise RecordError("Field 'nodeid' must not contain NUL bytes")
    return nodeid


def _validate_seq(seq: Any) -> int:
    if not _is_non_bool_int(seq):
        raise RecordError("Field 'seq' must be an integer")
    if seq < 0:
        raise RecordError("Field 'seq' must be non-negative")
    return seq


def _validate_outcome(outcome: Any) -> str:
    if not isinstance(outcome, str) or outcome not in VALID_OUTCOMES:
        raise RecordError("Field 'outcome' must be one of passed, failed, skipped, error")
    return outcome


def _validate_duration_ms(duration_ms: Any) -> int:
    if not _is_non_bool_int(duration_ms):
        raise RecordError("Field 'duration_ms' must be an integer")
    if duration_ms < 0:
        raise RecordError("Field 'duration_ms' must be non-negative")
    return duration_ms


def _validate_count(count: Any) -> int:
    if not _is_non_bool_int(count):
        raise RecordError("Field 'count' must be an integer")
    if count < 0:
        raise RecordError("Field 'count' must be non-negative")
    if count > MAX_RECORDS:
        raise RecordError("Field 'count' exceeds MAX_RECORDS")
    return count


def _serialize_payload(payload_obj: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            payload_obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RecordError("Failed to serialize JSON payload") from exc

    if len(raw) > MAX_RECORD:
        raise RecordError("Encoded payload exceeds MAX_RECORD")
    return raw


def encode_record(record_type: RecordType | int, payload_bytes: bytes) -> bytes:
    """Frame a validated record type and UTF-8 JSON payload bytes."""
    try:
        rtype = RecordType(record_type)
    except ValueError as exc:
        raise RecordError("Unknown record type") from exc

    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise RecordError("Payload must be bytes")
    if len(payload_bytes) > MAX_RECORD:
        raise RecordError("Payload length exceeds MAX_RECORD")

    header = HEADER_STRUCT.pack(int(rtype), len(payload_bytes))
    return header + bytes(payload_bytes)


def encode_start(seq: int, nodeid: str) -> bytes:
    """Encode a START binary record."""
    valid_seq = _validate_seq(seq)
    valid_nodeid = _validate_nodeid(nodeid)
    payload = _serialize_payload({"seq": valid_seq, "nodeid": valid_nodeid})
    return encode_record(RecordType.START, payload)


def encode_finish(seq: int, nodeid: str, outcome: str, duration_ms: int) -> bytes:
    """Encode a FINISH binary record."""
    valid_seq = _validate_seq(seq)
    valid_nodeid = _validate_nodeid(nodeid)
    valid_outcome = _validate_outcome(outcome)
    valid_duration = _validate_duration_ms(duration_ms)
    payload = _serialize_payload(
        {
            "seq": valid_seq,
            "nodeid": valid_nodeid,
            "outcome": valid_outcome,
            "duration_ms": valid_duration,
        }
    )
    return encode_record(RecordType.FINISH, payload)


def encode_end(count: int) -> bytes:
    """Encode an END binary record."""
    valid_count = _validate_count(count)
    payload = _serialize_payload({"count": valid_count})
    return encode_record(RecordType.END, payload)


class StreamEncoder:
    """Stateful deterministic encoder enforcing protocol sequence invariants."""

    def __init__(self) -> None:
        self._seq: int = 0
        self._active_nodeid: str | None = None
        self._seen_nodeids: set[str] = set()
        self._ended: bool = False

    @property
    def seq(self) -> int:
        return self._seq

    def start(self, nodeid: str) -> bytes:
        if self._ended:
            raise RecordError("Cannot emit START after END")
        if self._active_nodeid is not None:
            raise RecordError("Cannot emit START while another test is active")
        if self._seq >= MAX_RECORDS:
            raise RecordError("Stream exceeds MAX_RECORDS")
        valid_nodeid = _validate_nodeid(nodeid)
        if valid_nodeid in self._seen_nodeids:
            raise RecordError("Duplicate nodeid in stream")

        encoded = encode_start(self._seq, valid_nodeid)
        self._seen_nodeids.add(valid_nodeid)
        self._active_nodeid = valid_nodeid
        self._seq += 1
        return encoded

    def finish(self, nodeid: str, outcome: str, duration_ms: int) -> bytes:
        if self._ended:
            raise RecordError("Cannot emit FINISH after END")
        if self._active_nodeid is None:
            raise RecordError("Cannot emit FINISH without matching START")
        if self._seq >= MAX_RECORDS:
            raise RecordError("Stream exceeds MAX_RECORDS")
        valid_nodeid = _validate_nodeid(nodeid)
        if valid_nodeid != self._active_nodeid:
            raise RecordError("FINISH nodeid does not match active START")

        encoded = encode_finish(self._seq, valid_nodeid, outcome, duration_ms)
        self._active_nodeid = None
        self._seq += 1
        return encoded

    def end(self) -> bytes:
        if self._ended:
            raise RecordError("END already emitted")
        if self._active_nodeid is not None:
            raise RecordError("Cannot emit END while a test is still active")
        encoded = encode_end(self._seq)
        self._ended = True
        return encoded


def _strict_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecordError("Duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(constant: str) -> Any:
    raise RecordError("Non-standard JSON constant is forbidden")


def _parse_payload_object(payload_bytes: bytes) -> dict[str, Any]:
    try:
        text = payload_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RecordError("Invalid UTF-8 in record payload") from exc

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs_hook,
            parse_constant=_reject_json_constant,
        )
    except RecordError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise RecordError("Invalid JSON in record payload") from exc

    if not isinstance(parsed, dict):
        raise RecordError("Record payload must be a JSON object")
    return parsed


def _parse_record_payload(record_type: RecordType, payload_bytes: bytes) -> Record:
    obj = _parse_payload_object(payload_bytes)
    keys = frozenset(obj.keys())

    if record_type is RecordType.START:
        if keys != START_KEYS:
            raise RecordError("START payload has missing or extra fields")
        seq = _validate_seq(obj["seq"])
        nodeid = _validate_nodeid(obj["nodeid"])
        return StartRecord(seq=seq, nodeid=nodeid)

    if record_type is RecordType.FINISH:
        if keys != FINISH_KEYS:
            raise RecordError("FINISH payload has missing or extra fields")
        seq = _validate_seq(obj["seq"])
        nodeid = _validate_nodeid(obj["nodeid"])
        outcome = _validate_outcome(obj["outcome"])
        duration_ms = _validate_duration_ms(obj["duration_ms"])
        return FinishRecord(seq=seq, nodeid=nodeid, outcome=outcome, duration_ms=duration_ms)

    if record_type is RecordType.END:
        if keys != END_KEYS:
            raise RecordError("END payload has missing or extra fields")
        count = _validate_count(obj["count"])
        return EndRecord(count=count)

    raise RecordError("Unknown record type")


def _read_exact(
    fileobj: BinaryIO,
    num_bytes: int,
    *,
    allow_clean_eof: bool = False,
) -> bytes:
    """Read exactly num_bytes from fileobj using bounded chunks <= READ_CHUNK_SIZE."""
    if num_bytes < 0 or num_bytes > MAX_RECORD:
        raise RecordError("Requested read length exceeds MAX_RECORD")
    if num_bytes == 0:
        return b""

    chunks: list[bytes] = []
    remaining = num_bytes

    for _ in range(MAX_CHUNK_READS_PER_ITEM):
        if remaining == 0:
            return b"".join(chunks)
        to_read = min(remaining, READ_CHUNK_SIZE)
        try:
            chunk = fileobj.read(to_read)
        except OSError as exc:
            raise RecordError("I/O failure while reading record stream") from exc

        if not isinstance(chunk, (bytes, bytearray)):
            raise RecordError("Stream reader did not return bytes")
        if len(chunk) > to_read:
            raise RecordError("Stream reader returned more bytes than requested")

        if len(chunk) == 0:
            if allow_clean_eof and remaining == num_bytes:
                raise PrematureEOFError("Stream ended at record boundary before END record")
            raise RecordError("Truncated record stream")

        chunks.append(bytes(chunk))
        remaining -= len(chunk)

    raise RecordError("Exceeded maximum chunk read iterations")


def iter_records(fileobj: BinaryIO) -> Iterator[Record]:
    """Stream-decode records from a binary file object in bounded chunks."""
    if fileobj is None or not hasattr(fileobj, "read"):
        raise RecordError("Invalid binary file object")

    magic = _read_exact(fileobj, MAGIC_LEN, allow_clean_eof=False)
    if magic != MAGIC:
        raise RecordError("Bad stream magic")

    expected_seq: int = 0
    active_nodeid: str | None = None
    seen_nodeids: set[str] = set()
    saw_end: bool = False

    for _ in range(MAX_RECORDS + 1):
        if saw_end:
            try:
                trailing = fileobj.read(1)
            except OSError as exc:
                raise RecordError("I/O failure after END record") from exc
            if trailing:
                raise RecordError("Trailing bytes after END record")
            return

        header_bytes = _read_exact(fileobj, HEADER_LEN, allow_clean_eof=True)
        raw_type, payload_len = HEADER_STRUCT.unpack(header_bytes)

        try:
            record_type = RecordType(raw_type)
        except ValueError as exc:
            raise RecordError("Unknown record type") from exc

        if payload_len > MAX_RECORD:
            raise RecordError("Record payload length exceeds MAX_RECORD")

        payload_bytes = _read_exact(fileobj, payload_len, allow_clean_eof=False)
        record = _parse_record_payload(record_type, payload_bytes)

        if isinstance(record, StartRecord):
            if expected_seq >= MAX_RECORDS:
                raise RecordError("Stream exceeds MAX_RECORDS")
            if record.seq != expected_seq:
                raise RecordError("Record sequence out of order")
            if active_nodeid is not None:
                raise RecordError("START received while previous test still active")
            if record.nodeid in seen_nodeids:
                raise RecordError("Duplicate nodeid in stream")

            seen_nodeids.add(record.nodeid)
            active_nodeid = record.nodeid
            expected_seq += 1
            yield record

        elif isinstance(record, FinishRecord):
            if expected_seq >= MAX_RECORDS:
                raise RecordError("Stream exceeds MAX_RECORDS")
            if record.seq != expected_seq:
                raise RecordError("Record sequence out of order")
            if active_nodeid is None:
                raise RecordError("FINISH without matching START")
            if record.nodeid != active_nodeid:
                raise RecordError("FINISH nodeid does not match active START")

            active_nodeid = None
            expected_seq += 1
            yield record

        elif isinstance(record, EndRecord):
            if active_nodeid is not None:
                raise RecordError("END received while test still active")
            if record.count != expected_seq:
                raise RecordError("END record count does not match stream length")
            saw_end = True
            yield record

    raise RecordError("Stream exceeds MAX_RECORDS")


def decode_stream(fileobj: BinaryIO) -> list[Record]:
    """Decode an entire validated record stream into a list of records."""
    return list(iter_records(fileobj))
