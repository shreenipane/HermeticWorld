"""hermetic-execd RPC, matching crates/hermetic-execd/src/rpc.rs."""

from __future__ import annotations

import json
import math
import socket
import struct
import time

from .errors import LimitError, ProtocolError, TransportError, ExecutionTimeout

MAX_FRAME_BYTES = 4 * 1024 * 1024 + 65536
MAX_HANDSHAKE_BYTES = 64
MAX_COMMAND_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RUN_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300
MAX_CALL_SECONDS = MAX_TIMEOUT_SECONDS + 5
MAX_JSON_DEPTH = 64
MAX_JSON_VALUES = MAX_FRAME_BYTES


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Duplicate JSON field")
        result[key] = value
    return result


def parse_json(raw: bytes):
    # Check depth before the JSON decoder allocates nested containers.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if escaped:
            escaped = False
        elif quoted and byte == 92:
            escaped = True
        elif byte == 34:
            quoted = not quoted
        elif not quoted:
            if byte in (123, 91):
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise ProtocolError("JSON depth limit")
            elif byte in (125, 93):
                depth -= 1
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: _invalid_json())
        pending = [result]
        count = 0
        while pending:
            value = pending.pop()
            count += 1
            if count > MAX_JSON_VALUES:
                raise ProtocolError("JSON value limit")
            if isinstance(value, str):
                value.encode("utf-8")
            elif isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid JSON") from None


def _invalid_json():
    raise ProtocolError("Invalid JSON number")


def encode_frame(request: dict) -> bytes:
    raw = json.dumps(request, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise LimitError("Frame limit")
    return struct.pack("<I", len(raw)) + raw


def timeout_seconds(value):
    if (type(value) not in (int, float) or not 0 < value <= MAX_TIMEOUT_SECONDS
            or not math.isfinite(value)):
        raise LimitError("Command timeout limit")
    return value


class ExecdClient:
    """One request per connection, with a single absolute I/O deadline."""

    def __init__(self, vsock_path: str):
        if not isinstance(vsock_path, str) or not vsock_path or "\0" in vsock_path or len(vsock_path.encode()) > 107:
            raise ProtocolError("Invalid vsock endpoint")
        self._vsock_path = vsock_path

    def call(self, request: dict, *, timeout: float = 5) -> dict:
        if type(timeout) not in (float, int) or not 0 < timeout <= MAX_CALL_SECONDS or not math.isfinite(timeout):
            raise LimitError("RPC deadline limit")
        frame = encode_frame(request)
        end = time.monotonic() + timeout

        def remaining():
            value = end - time.monotonic()
            if value <= 0:
                raise ExecutionTimeout()
            return value

        def read_exact(stream, size):
            result = bytearray()
            while len(result) < size:
                stream.settimeout(remaining())
                part = stream.recv(min(65536, size - len(result)))
                if not part:
                    raise ProtocolError("Truncated RPC")
                result.extend(part)
            return bytes(result)

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(remaining())
                stream.connect(self._vsock_path)
                stream.settimeout(remaining())
                stream.sendall(b"CONNECT 5000\n")
                handshake = bytearray()
                for _ in range(MAX_HANDSHAKE_BYTES):
                    byte = read_exact(stream, 1)
                    handshake.extend(byte)
                    if byte == b"\n":
                        break
                prefix, sep, port = bytes(handshake).partition(b" ")
                digits = port.removesuffix(b"\n")
                if (prefix != b"OK" or not sep or not port.endswith(b"\n")
                        or not digits or not digits.isdigit() or int(digits) > 0xffffffff):
                    raise ProtocolError("Invalid vsock handshake")
                stream.settimeout(remaining())
                stream.sendall(frame)
                length, = struct.unpack("<I", read_exact(stream, 4))
                if not 0 < length <= MAX_FRAME_BYTES:
                    raise LimitError("RPC frame limit")
                result = parse_json(read_exact(stream, length))
                if not isinstance(result, dict):
                    raise ProtocolError("Invalid RPC reply")
                if result.get("type") == "error":
                    raise ProtocolError("Execd refused request")
                return result
        except (socket.timeout, TimeoutError):
            raise ExecutionTimeout() from None
        except OSError:
            raise TransportError("Execd transport failed") from None
