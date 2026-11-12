"""TLS leaf certificate validity window, SNI/Host policy, and HTTP method policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import os
import re
import stat
from typing import Any

DEFAULT_HOSTS_CAP_BYTES = 1 * 1024 * 1024
MAX_HOSTS = 4096
MAX_HOST_LEN = 253
MAX_LABEL_LEN = 63
MAX_HEADER_INPUT_LEN = 512
MAX_JSON_DEPTH = 16
MAX_JSON_TOKENS = 50_000
MAX_OBJECT_KEYS = 100
READ_CHUNK_BYTES = 65_536

SECONDS_PER_DAY = 86_400
DAYS_BEFORE = 7
DAYS_AFTER = 365

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
MIN_T_CLOCK = (datetime(1990, 1, 1, tzinfo=timezone.utc) - _EPOCH_UTC) // timedelta(seconds=1)
MAX_T_CLOCK = (datetime(2100, 1, 1, tzinfo=timezone.utc) - _EPOCH_UTC) // timedelta(seconds=1)

ALLOWED_PORTS = frozenset({80, 443})
ALLOWED_METHODS = frozenset({"GET", "HEAD"})

_DNS_LABEL_LOWER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", flags=re.ASCII)
_DNS_LABEL_ANYCASE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", flags=re.ASCII)
_ALL_DIGITS_RE = re.compile(r"^[0-9]+$", flags=re.ASCII)


class HermeticTlsPolicyError(Exception):
    """Base typed error for hermetic_tlspolicy."""

    code: str = "HERMETIC_TLSPOLICY_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CapExceededError(HermeticTlsPolicyError):
    code: str = "CAP_EXCEEDED"


class FileSafetyError(HermeticTlsPolicyError):
    code: str = "FILE_SAFETY_ERROR"


class JsonParseError(HermeticTlsPolicyError):
    code: str = "JSON_PARSE_ERROR"


class ValidationError(HermeticTlsPolicyError):
    code: str = "VALIDATION_ERROR"


class DecisionAction(str, Enum):
    INTERCEPT = "intercept"
    RESET = "reset"


class ResetReason(str, Enum):
    MALFORMED_INPUT = "malformed_input"
    UNSUPPORTED_PORT = "unsupported_port"
    TLS_REQUIRED_ON_443 = "tls_required_on_443"
    TLS_FORBIDDEN_ON_80 = "tls_forbidden_on_80"
    ECH_PRESENT = "ech_present"
    MISSING_SNI = "missing_sni"
    UNEXPECTED_SNI_ON_80 = "unexpected_sni_on_80"
    MALFORMED_SNI = "malformed_sni"
    UNKNOWN_SNI = "unknown_sni"
    MISSING_HOST_HEADER = "missing_host_header"
    MALFORMED_HOST_HEADER = "malformed_host_header"
    UNKNOWN_HOST_HEADER = "unknown_host_header"
    SNI_HOST_MISMATCH = "sni_host_mismatch"


@dataclass(frozen=True)
class Decision:
    decision: str
    reason: ResetReason | None = None

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.decision == other
        if isinstance(other, Decision):
            return self.decision == other.decision and self.reason == other.reason
        return False

    def __str__(self) -> str:
        return self.decision

    def to_dict(self) -> dict[str, str | None]:
        return {
            "decision": self.decision,
            "reason": self.reason.value if self.reason is not None else None,
        }


@dataclass(frozen=True)
class HostTable:
    hosts: frozenset[str]

    def contains(self, host: str) -> bool:
        return host in self.hosts


def format_rfc3339_utc(unix_seconds: int) -> str:
    if isinstance(unix_seconds, bool) or not isinstance(unix_seconds, int):
        raise ValidationError("unix_seconds must be an integer")
    if (
        unix_seconds < MIN_T_CLOCK - DAYS_BEFORE * SECONDS_PER_DAY
        or unix_seconds > MAX_T_CLOCK + DAYS_AFTER * SECONDS_PER_DAY
    ):
        raise ValidationError("unix_seconds outside supported range")
    dt = _EPOCH_UTC + timedelta(seconds=unix_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def leaf_window(t_clock: int) -> tuple[int, int]:
    """Compute (not_before, not_after) in Unix seconds for leaf certificate issuance."""
    if isinstance(t_clock, bool) or not isinstance(t_clock, int):
        raise ValidationError("t_clock must be an integer Unix timestamp")
    if t_clock < MIN_T_CLOCK or t_clock > MAX_T_CLOCK:
        raise ValidationError("t_clock outside allowed range 1990-01-01..2100-01-01")
    not_before = t_clock - DAYS_BEFORE * SECONDS_PER_DAY
    not_after = t_clock + DAYS_AFTER * SECONDS_PER_DAY
    return (not_before, not_after)


def leaf_window_rfc3339(t_clock: int) -> dict[str, Any]:
    not_before, not_after = leaf_window(t_clock)
    return {
        "t_clock": t_clock,
        "not_before": format_rfc3339_utc(not_before),
        "not_after": format_rfc3339_utc(not_after),
        "not_before_unix": not_before,
        "not_after_unix": not_after,
    }


def _precheck_json_structure(text: str, max_depth: int, max_tokens: int) -> None:
    depth = 0
    tokens = 0
    in_string = False
    escape = False
    for i in range(len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            tokens += 1
            if tokens > max_tokens:
                raise CapExceededError("JSON token count exceeds cap")
        elif ch == "{" or ch == "[":
            depth += 1
            tokens += 1
            if depth > max_depth:
                raise CapExceededError("JSON nesting depth exceeds cap")
            if tokens > max_tokens:
                raise CapExceededError("JSON token count exceeds cap")
        elif ch == "}" or ch == "]":
            depth -= 1
            if depth < 0:
                raise JsonParseError("Unbalanced closing bracket in JSON")
        elif ch == "," or ch == ":":
            tokens += 1
            if tokens > max_tokens:
                raise CapExceededError("JSON token count exceeds cap")


def _reject_constant(val: str) -> Any:
    raise JsonParseError(f"Non-standard JSON constant rejected: {val}")


def _strict_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_OBJECT_KEYS:
        raise CapExceededError("JSON object key count exceeds cap")
    out: dict[str, Any] = {}
    for k, v in pairs:
        if "\x00" in k:
            raise ValidationError("NUL byte not allowed in JSON key")
        if k in out:
            raise JsonParseError("Duplicate JSON key rejected")
        out[k] = v
    return out


def read_regular_file_bounded(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FileSafetyError("Refusing to open file (missing, symlink, or OS error)") from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise FileSafetyError("Unable to stat file descriptor") from exc
        if not stat.S_ISREG(st.st_mode):
            raise FileSafetyError("Refusing non-regular file")
        if st.st_size > max_bytes:
            raise CapExceededError("File size exceeds byte cap")
        chunks: list[bytes] = []
        total = 0
        max_reads = (max_bytes // READ_CHUNK_BYTES) + 3
        for _ in range(max_reads):
            to_read = min(READ_CHUNK_BYTES, max_bytes - total + 1)
            try:
                chunk = os.read(fd, to_read)
            except OSError as exc:
                raise FileSafetyError("Error reading file") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise CapExceededError("File read exceeded byte cap")
            chunks.append(chunk)
        else:
            raise CapExceededError("Exceeded maximum read iterations")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _validate_strict_lowercase_dns_name(name: Any) -> str:
    """Validate a strict lower-case DNS name for the host allow-table."""
    if not isinstance(name, str):
        raise ValidationError("Host entry must be a string")
    if len(name) == 0 or len(name) > MAX_HOST_LEN:
        raise ValidationError("Host entry length out of bounds (1..253)")
    if not name.isascii() or "\x00" in name:
        raise ValidationError("Host entry must be pure ASCII without NUL bytes")
    if name.startswith(".") or name.endswith(".") or "*" in name or ":" in name:
        raise ValidationError("Host entry must not have leading/trailing dots, wildcards, or ports")
    labels = name.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > MAX_LABEL_LEN:
            raise ValidationError("DNS label length out of bounds (1..63)")
        if _DNS_LABEL_LOWER_RE.fullmatch(label) is None:
            raise ValidationError("DNS label must be lower-case [a-z0-9-] with no leading/trailing hyphen")
    if _ALL_DIGITS_RE.fullmatch(labels[-1]) is not None:
        raise ValidationError("IP literals and all-numeric TLDs are not allowed")
    return name


def load_host_table(data: Any) -> HostTable:
    """Validate and construct a HostTable from parsed JSON data."""
    if not isinstance(data, dict):
        raise ValidationError("Host table root must be a JSON object")
    if set(data.keys()) != {"hosts"}:
        raise ValidationError("Host table must contain only 'hosts'")
    raw_hosts = data["hosts"]
    if not isinstance(raw_hosts, list):
        raise ValidationError("'hosts' must be a JSON array")
    if len(raw_hosts) > MAX_HOSTS:
        raise CapExceededError("Host table exceeds MAX_HOSTS (4096)")
    seen: set[str] = set()
    for item in raw_hosts:
        validated = _validate_strict_lowercase_dns_name(item)
        if validated in seen:
            raise ValidationError("Duplicate host entry in host table")
        seen.add(validated)
    return HostTable(hosts=frozenset(seen))


def load_host_table_file(
    path: str | os.PathLike[str],
    max_bytes: int = DEFAULT_HOSTS_CAP_BYTES,
) -> HostTable:
    raw = read_regular_file_bounded(path, max_bytes=max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonParseError("Invalid UTF-8 in host table file") from exc
    _precheck_json_structure(text, max_depth=MAX_JSON_DEPTH, max_tokens=MAX_JSON_TOKENS)
    try:
        data = json.loads(
            text,
            object_pairs_hook=_strict_pairs_hook,
            parse_constant=_reject_constant,
        )
    except (CapExceededError, JsonParseError, ValidationError):
        raise
    except RecursionError as exc:
        raise CapExceededError("JSON depth exceeded") from exc
    except ValueError as exc:
        raise JsonParseError("Malformed JSON in host table") from exc
    return load_host_table(data)


def _normalise_wire_dns_name(raw_name: str, allowed_port_suffix: int | None) -> str | None:
    """Normalise an SNI or Host header to lower-case DNS name, or return None if malformed."""
    if not isinstance(raw_name, str) or len(raw_name) == 0 or len(raw_name) > MAX_HEADER_INPUT_LEN:
        return None
    if not raw_name.isascii() or "\x00" in raw_name:
        return None
    host_part = raw_name
    if ":" in raw_name:
        if allowed_port_suffix is None:
            return None
        parts = raw_name.split(":")
        if len(parts) != 2:
            return None
        host_part, port_part = parts
        if port_part != str(allowed_port_suffix):
            return None
    if len(host_part) == 0 or len(host_part) > MAX_HOST_LEN:
        return None
    if host_part.startswith(".") or host_part.endswith(".") or "*" in host_part:
        return None
    labels = host_part.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > MAX_LABEL_LEN:
            return None
        if _DNS_LABEL_ANYCASE_RE.fullmatch(label) is None:
            return None
    if _ALL_DIGITS_RE.fullmatch(labels[-1]) is not None:
        return None
    return host_part.lower()


def decide(
    host_table: HostTable | str | None = None,
    sni: str | None = None,
    host_header: str | int | None = None,
    port: int | bool = 0,
    is_tls: bool = False,
    has_ech: bool = False,
    *,
    table: HostTable | None = None,
) -> Decision:
    """Decide whether to intercept or reset a connection given TLS/HTTP metadata."""
    if isinstance(host_table, HostTable):
        actual_table = host_table
        actual_sni = sni
        actual_host = (
            host_header
            if isinstance(host_header, (str, type(None)))
            else None
        )
        actual_port = (
            port
            if isinstance(port, int) and not isinstance(port, bool)
            else port
        )
        actual_tls = is_tls
        actual_ech = has_ech
    else:
        actual_table = table if table is not None else (host_table if isinstance(host_table, HostTable) else None)
        if isinstance(host_table, (str, type(None))) and isinstance(port, bool):
            # Positional call: decide(sni, host_header, port, is_tls, has_ech)
            actual_sni = host_table
            actual_host = sni if isinstance(sni, (str, type(None))) else None
            actual_port = host_header if isinstance(host_header, (int, bool)) else 0
            actual_tls = port
            actual_ech = is_tls
        else:
            actual_sni = sni
            actual_host = host_header if isinstance(host_header, (str, type(None))) else None
            actual_port = port
            actual_tls = is_tls
            actual_ech = has_ech

    if not isinstance(actual_table, HostTable):
        raise ValidationError("host_table must be a HostTable instance")

    if isinstance(actual_port, bool) or not isinstance(actual_port, int):
        return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_INPUT)
    if not isinstance(actual_tls, bool) or not isinstance(actual_ech, bool):
        return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_INPUT)
    if actual_sni is not None and not isinstance(actual_sni, str):
        return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_INPUT)
    if actual_host is not None and not isinstance(actual_host, str):
        return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_INPUT)

    if actual_port not in ALLOWED_PORTS:
        return Decision(DecisionAction.RESET.value, ResetReason.UNSUPPORTED_PORT)

    if actual_ech:
        return Decision(DecisionAction.RESET.value, ResetReason.ECH_PRESENT)

    if actual_port == 443:
        if not actual_tls:
            return Decision(DecisionAction.RESET.value, ResetReason.TLS_REQUIRED_ON_443)
        if actual_sni is None or actual_sni == "":
            return Decision(DecisionAction.RESET.value, ResetReason.MISSING_SNI)

        norm_sni = _normalise_wire_dns_name(actual_sni, allowed_port_suffix=None)
        if norm_sni is None:
            if actual_sni.endswith(".") and actual_host is not None:
                norm_h = _normalise_wire_dns_name(actual_host, allowed_port_suffix=443)
                if norm_h is not None and actual_sni[:-1].lower() == norm_h:
                    return Decision(DecisionAction.RESET.value, ResetReason.SNI_HOST_MISMATCH)
            return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_SNI)

        if not actual_table.contains(norm_sni):
            return Decision(DecisionAction.RESET.value, ResetReason.UNKNOWN_SNI)

        if actual_host is not None:
            norm_host = _normalise_wire_dns_name(actual_host, allowed_port_suffix=443)
            if norm_host is None:
                stripped_host = (
                    actual_host[:-4] if actual_host.endswith(":443") else actual_host
                )
                if stripped_host.endswith(".") and stripped_host[:-1].lower() == norm_sni:
                    return Decision(DecisionAction.RESET.value, ResetReason.SNI_HOST_MISMATCH)
                return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_HOST_HEADER)
            if norm_host != norm_sni:
                return Decision(DecisionAction.RESET.value, ResetReason.SNI_HOST_MISMATCH)

        return Decision(DecisionAction.INTERCEPT.value, None)

    # actual_port == 80
    if actual_tls:
        return Decision(DecisionAction.RESET.value, ResetReason.TLS_FORBIDDEN_ON_80)
    if actual_sni is not None:
        return Decision(DecisionAction.RESET.value, ResetReason.UNEXPECTED_SNI_ON_80)
    if actual_host is None or actual_host == "":
        return Decision(DecisionAction.RESET.value, ResetReason.MISSING_HOST_HEADER)

    norm_host_80 = _normalise_wire_dns_name(actual_host, allowed_port_suffix=80)
    if norm_host_80 is None:
        return Decision(DecisionAction.RESET.value, ResetReason.MALFORMED_HOST_HEADER)
    if not actual_table.contains(norm_host_80):
        return Decision(DecisionAction.RESET.value, ResetReason.UNKNOWN_HOST_HEADER)

    return Decision(DecisionAction.INTERCEPT.value, None)


def decide_from_file(
    hosts_path: str | os.PathLike[str],
    sni: str | None,
    host_header: str | None,
    port: int,
    is_tls: bool,
    has_ech: bool,
    max_bytes: int = DEFAULT_HOSTS_CAP_BYTES,
) -> Decision:
    table = load_host_table_file(hosts_path, max_bytes=max_bytes)
    return decide(
        host_table=table,
        sni=sni,
        host_header=host_header,
        port=port,
        is_tls=is_tls,
        has_ech=has_ech,
    )


def method_policy(method: str) -> int:
    """Return 200 (forward) for GET and HEAD, and 405 for every other method."""
    if isinstance(method, str) and method in ALLOWED_METHODS:
        return 200
    return 405
