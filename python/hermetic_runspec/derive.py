"""Derive deterministic microVM run specs from OCI image config, passwd/group, and overrides."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
import re
from typing import Any

from hermetic_safe_io import open_regular

DEFAULT_CONFIG_CAP_BYTES = 4 * 1024 * 1024
DEFAULT_PASSWD_CAP_BYTES = 1 * 1024 * 1024
DEFAULT_GROUP_CAP_BYTES = 1 * 1024 * 1024
DEFAULT_OVERRIDES_CAP_BYTES = 256 * 1024

MAX_ENV_COUNT = 512
MAX_ENV_BYTES = 256 * 1024
MAX_ARGV_COUNT = 4096
MAX_ARGV_BYTES = 256 * 1024
MAX_PATH_LEN = 4096
MAX_HOST_LEN = 253
MAX_LABEL_LEN = 63
MAX_PASSWD_GROUP_LINES = 65_536
MAX_LINE_LEN = 4096
MAX_JSON_DEPTH = 16
MAX_JSON_TOKENS = 500_000
MAX_OBJECT_KEYS = 50_000
MAX_UID_GID = 4_294_967_295
MAX_VCPUS = 256
MAX_MEMORY_MIB = 1_048_576
MAX_DISK_MIB = 10_485_760
READ_CHUNK_BYTES = 65_536
# open_regular's own size cap; the caller-supplied cap is checked separately for a typed error.
MAX_OPEN_SIZE_BYTES = 1 << 40
MAX_USER_SPEC_LEN = 256
# Linux HOST_NAME_MAX: sethostname() in PID 1 refuses anything longer.
MAX_HOSTNAME_LEN = 64

# Keys of the OCI image config "config" object (OCI image-spec plus the Docker fields found in
# real images). Any other key is refused rather than silently ignored.
_OCI_CONFIG_ALLOWED_KEYS = frozenset({
    "User", "ExposedPorts", "Env", "Entrypoint", "Cmd", "Volumes", "WorkingDir", "Labels",
    "StopSignal", "ArgsEscaped", "Memory", "MemorySwap", "CpuShares", "Healthcheck",
    "Hostname", "Domainname", "AttachStdin", "AttachStdout", "AttachStderr", "Tty",
    "OpenStdin", "StdinOnce", "Image", "OnBuild", "Shell", "StopTimeout",
})

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$", flags=re.ASCII)
_POSIX_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\$?$", flags=re.ASCII)
_UINT_RE = re.compile(r"^(?:0|[1-9][0-9]*)$", flags=re.ASCII)
_DNS_LABEL_LOWER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", flags=re.ASCII)
_ALL_DIGITS_RE = re.compile(r"^[0-9]+$", flags=re.ASCII)

_OVERRIDES_ALLOWED_KEYS = frozenset(
    {"cmd", "workdir", "user", "vcpus", "memory_mib", "disk_mib", "hostname", "nameserver"}
)
_OVERRIDES_REQUIRED_KEYS = frozenset({"vcpus", "memory_mib", "disk_mib", "hostname", "nameserver"})


class HermeticRunSpecError(Exception):
    """Base typed error for hermetic_runspec."""

    code: str = "HERMETIC_RUNSPEC_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CapExceededError(HermeticRunSpecError):
    code: str = "CAP_EXCEEDED"


class FileSafetyError(HermeticRunSpecError):
    code: str = "FILE_SAFETY_ERROR"


class JsonParseError(HermeticRunSpecError):
    code: str = "JSON_PARSE_ERROR"


class ValidationError(HermeticRunSpecError):
    code: str = "VALIDATION_ERROR"


class UserResolutionError(HermeticRunSpecError):
    code: str = "USER_RESOLUTION_ERROR"


@dataclass(frozen=True)
class PasswdGroupStats:
    valid_passwd_entries: int
    bad_passwd_lines: int
    valid_group_entries: int
    bad_group_lines: int


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


def parse_json_bytes(raw: bytes, max_bytes: int) -> Any:
    if len(raw) > max_bytes:
        raise CapExceededError("JSON payload exceeds byte cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonParseError("Invalid UTF-8 in JSON input") from exc
    _precheck_json_structure(text, max_depth=MAX_JSON_DEPTH, max_tokens=MAX_JSON_TOKENS)
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_pairs_hook,
            parse_constant=_reject_constant,
        )
    except (CapExceededError, JsonParseError, ValidationError):
        raise
    except RecursionError as exc:
        raise CapExceededError("JSON nesting depth exceeded") from exc
    except ValueError as exc:
        raise JsonParseError("Malformed JSON input") from exc


def read_regular_file_bounded(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    """Read a pinned regular file; symlinks, FIFOs and devices are refused without blocking."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValidationError("max_bytes must be a non-negative integer")
    try:
        fd = open_regular(path, MAX_OPEN_SIZE_BYTES)
    except (OSError, ValueError, TypeError) as exc:
        raise FileSafetyError("Refusing to open file (missing, symlink, non-regular, or OS error)") from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise FileSafetyError("Unable to stat file descriptor") from exc
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


def _require_utf8(value: str, what: str) -> str:
    """Refuse strings that cannot be encoded as UTF-8 (lone surrogates from JSON escapes)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{what} must be valid Unicode text") from exc
    return value


def _parse_uint_id(text: str) -> int | None:
    if _UINT_RE.fullmatch(text) is None:
        return None
    val = int(text)
    if val < 0 or val > MAX_UID_GID:
        return None
    return val


def parse_passwd_bytes(
    raw: bytes,
    max_bytes: int = DEFAULT_PASSWD_CAP_BYTES,
) -> tuple[dict[str, tuple[int, int]], dict[int, tuple[str, int]], int]:
    """Strictly parse /etc/passwd bytes; skip and count malformed lines."""
    if not isinstance(raw, bytes):
        raise ValidationError("passwd contents must be bytes")
    if len(raw) > max_bytes:
        raise CapExceededError("passwd contents exceed byte cap")
    if b"\x00" in raw:
        raise ValidationError("passwd contents must not contain NUL bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("passwd contents must be valid UTF-8") from exc

    # Split on "\n" only: str.splitlines() would also split on \v, \f, \x1c-\x1e, \x85 and
    # U+2028/U+2029, letting a field smuggle in an extra entry. A trailing "\r" is not stripped.
    lines = text.split("\n")
    if len(lines) > MAX_PASSWD_GROUP_LINES:
        raise CapExceededError("passwd line count exceeds MAX_PASSWD_GROUP_LINES")

    by_name: dict[str, tuple[int, int]] = {}
    by_uid: dict[int, tuple[str, int]] = {}
    bad_lines = 0

    for line in lines:
        if not line:
            continue
        if len(line) > MAX_LINE_LEN:
            bad_lines += 1
            continue
        fields = line.split(":")
        if len(fields) != 7:
            bad_lines += 1
            continue
        uname, _pw, uid_str, gid_str, _gecos, _home, _shell = fields
        if _POSIX_NAME_RE.fullmatch(uname) is None:
            bad_lines += 1
            continue
        uid = _parse_uint_id(uid_str)
        gid = _parse_uint_id(gid_str)
        if uid is None or gid is None:
            bad_lines += 1
            continue
        if uname not in by_name:
            by_name[uname] = (uid, gid)
        if uid not in by_uid:
            by_uid[uid] = (uname, gid)

    return by_name, by_uid, bad_lines


def parse_group_bytes(
    raw: bytes,
    max_bytes: int = DEFAULT_GROUP_CAP_BYTES,
) -> tuple[dict[str, int], dict[str, set[int]], int]:
    """Strictly parse /etc/group bytes; skip and count malformed lines."""
    if not isinstance(raw, bytes):
        raise ValidationError("group contents must be bytes")
    if len(raw) > max_bytes:
        raise CapExceededError("group contents exceed byte cap")
    if b"\x00" in raw:
        raise ValidationError("group contents must not contain NUL bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("group contents must be valid UTF-8") from exc

    lines = text.split("\n")
    if len(lines) > MAX_PASSWD_GROUP_LINES:
        raise CapExceededError("group line count exceeds MAX_PASSWD_GROUP_LINES")

    by_name: dict[str, int] = {}
    user_groups: dict[str, set[int]] = {}
    bad_lines = 0

    for line in lines:
        if not line:
            continue
        if len(line) > MAX_LINE_LEN:
            bad_lines += 1
            continue
        fields = line.split(":")
        if len(fields) != 4:
            bad_lines += 1
            continue
        gname, _pw, gid_str, members_str = fields
        if _POSIX_NAME_RE.fullmatch(gname) is None:
            bad_lines += 1
            continue
        gid = _parse_uint_id(gid_str)
        if gid is None:
            bad_lines += 1
            continue
        members: list[str] = []
        if members_str != "":
            raw_members = members_str.split(",")
            valid_members = True
            for m in raw_members:
                if _POSIX_NAME_RE.fullmatch(m) is None:
                    valid_members = False
                    break
                members.append(m)
            if not valid_members:
                bad_lines += 1
                continue
        if gname not in by_name:
            by_name[gname] = gid
        for m in members:
            user_groups.setdefault(m, set()).add(gid)

    return by_name, user_groups, bad_lines


def _resolve_user_and_groups(
    user_spec: str,
    passwd_by_name: dict[str, tuple[int, int]],
    passwd_by_uid: dict[int, tuple[str, int]],
    group_by_name: dict[str, int],
    user_groups: dict[str, set[int]],
) -> tuple[int, int, list[int]]:
    if not isinstance(user_spec, str) or "\x00" in user_spec:
        raise UserResolutionError("Invalid user specification")
    if len(user_spec) > MAX_USER_SPEC_LEN:
        raise UserResolutionError("User specification exceeds maximum length")

    if user_spec == "":
        uid = 0
        gid = 0
        resolved_username = passwd_by_uid[0][0] if 0 in passwd_by_uid else None
    else:
        parts = user_spec.split(":")
        if len(parts) > 2:
            raise UserResolutionError("User specification may contain at most one ':'")
        if len(parts) == 1:
            u_part = parts[0]
            if not u_part:
                raise UserResolutionError("Empty user component")
            parsed_uid = _parse_uint_id(u_part)
            if parsed_uid is not None:
                uid = parsed_uid
                if uid in passwd_by_uid:
                    resolved_username, gid = passwd_by_uid[uid]
                else:
                    resolved_username = None
                    gid = 0
            else:
                if u_part not in passwd_by_name:
                    raise UserResolutionError(f"Unresolvable user name: {u_part}")
                uid, gid = passwd_by_name[u_part]
                resolved_username = u_part
        else:
            u_part, g_part = parts
            if not u_part or not g_part:
                raise UserResolutionError("Both user and group must be non-empty when ':' is present")
            parsed_uid = _parse_uint_id(u_part)
            if parsed_uid is not None:
                uid = parsed_uid
                resolved_username = passwd_by_uid[uid][0] if uid in passwd_by_uid else None
            else:
                if u_part not in passwd_by_name:
                    raise UserResolutionError(f"Unresolvable user name: {u_part}")
                uid = passwd_by_name[u_part][0]
                resolved_username = u_part

            parsed_gid = _parse_uint_id(g_part)
            if parsed_gid is not None:
                gid = parsed_gid
            else:
                if g_part not in group_by_name:
                    raise UserResolutionError(f"Unresolvable group name: {g_part}")
                gid = group_by_name[g_part]

    if resolved_username is not None and resolved_username in user_groups:
        supp = sorted(g for g in user_groups[resolved_username] if g != gid)
    else:
        supp = []
    return uid, gid, supp


def _normalise_and_validate_cwd(raw_cwd: str | None) -> str:
    if raw_cwd is None or raw_cwd == "":
        return "/"
    if not isinstance(raw_cwd, str):
        raise ValidationError("Working directory must be a string")
    if "\x00" in raw_cwd:
        raise ValidationError("Working directory must not contain NUL bytes")
    if len(raw_cwd) > MAX_PATH_LEN:
        raise CapExceededError("Working directory exceeds MAX_PATH_LEN")
    if not raw_cwd.startswith("/"):
        raise ValidationError("Working directory must be an absolute path")
    segments = raw_cwd.split("/")
    if ".." in segments:
        raise ValidationError("Working directory must not contain '..' traversal components")
    _require_utf8(raw_cwd, "Working directory")
    # posixpath.normpath keeps a leading "//"; rebuild from segments so the result is canonical.
    normalised = "/" + "/".join(seg for seg in segments if seg not in ("", "."))
    return normalised


def _parse_env_list(raw_env: Any) -> list[list[str]]:
    """Parse OCI config.Env list; names match [A-Za-z_][A-Za-z0-9_]*, duplicate names last-wins."""
    if raw_env is None:
        return []
    if not isinstance(raw_env, list):
        raise ValidationError("config.Env must be a list of strings")
    if len(raw_env) > MAX_ENV_COUNT:
        raise CapExceededError("config.Env entry count exceeds MAX_ENV_COUNT (512)")

    env_map: dict[str, str] = {}
    for item in raw_env:
        if not isinstance(item, str):
            raise ValidationError("Each config.Env entry must be a string")
        if "\x00" in item:
            raise ValidationError("config.Env entries must not contain NUL bytes")
        if "=" not in item:
            raise ValidationError("Each config.Env entry must be formatted as NAME=value")
        _require_utf8(item, "config.Env entry")
        name, value = item.split("=", 1)
        if _ENV_NAME_RE.fullmatch(name) is None:
            raise ValidationError(f"Invalid environment variable name: {name}")
        # Duplicate environment variable names: last entry in config.Env wins.
        env_map[name] = value

    if len(env_map) > MAX_ENV_COUNT:
        raise CapExceededError("Distinct environment variable count exceeds MAX_ENV_COUNT")

    total_bytes = 0
    sorted_pairs: list[list[str]] = []
    for name in sorted(env_map.keys()):
        val = env_map[name]
        total_bytes += len(name.encode("utf-8")) + len(val.encode("utf-8"))
        if total_bytes > MAX_ENV_BYTES:
            raise CapExceededError("Total environment size exceeds MAX_ENV_BYTES (256 KiB)")
        sorted_pairs.append([name, val])
    return sorted_pairs


def _validate_argv_list(raw_list: Any, field_name: str) -> list[str]:
    if raw_list is None:
        return []
    if not isinstance(raw_list, list):
        raise ValidationError(f"{field_name} must be a list of strings")
    if len(raw_list) > MAX_ARGV_COUNT:
        raise CapExceededError(f"{field_name} exceeds MAX_ARGV_COUNT")
    out: list[str] = []
    for item in raw_list:
        if not isinstance(item, str):
            raise ValidationError(f"Every element in {field_name} must be a string")
        if "\x00" in item:
            raise ValidationError(f"Elements in {field_name} must not contain NUL bytes")
        _require_utf8(item, field_name)
        out.append(item)
    return out


def _validate_hostname(hostname: Any) -> str:
    if not isinstance(hostname, str):
        raise ValidationError("hostname must be a string")
    if len(hostname) == 0 or len(hostname) > MAX_HOSTNAME_LEN:
        raise ValidationError("hostname length out of bounds (1..64)")
    if not hostname.isascii() or "\x00" in hostname:
        raise ValidationError("hostname must be pure ASCII")
    if hostname.startswith(".") or hostname.endswith("."):
        raise ValidationError("hostname must not start or end with a dot")
    labels = hostname.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > MAX_LABEL_LEN:
            raise ValidationError("hostname label length out of bounds (1..63)")
        if _DNS_LABEL_LOWER_RE.fullmatch(label) is None:
            raise ValidationError("hostname labels must match lower-case [a-z0-9-] with no leading/trailing '-'")
    if _ALL_DIGITS_RE.fullmatch(labels[-1]) is not None:
        raise ValidationError("hostname must not be an IP literal or have an all-numeric TLD")
    return hostname


def _validate_ipv4(nameserver: Any) -> str:
    if not isinstance(nameserver, str):
        raise ValidationError("nameserver must be a string")
    if "\x00" in nameserver or nameserver.count(".") != 3:
        raise ValidationError("nameserver must be a dotted-quad IPv4 address")
    try:
        addr = ipaddress.ip_address(nameserver)
    except ValueError as exc:
        raise ValidationError("Invalid IPv4 nameserver address") from exc
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValidationError("nameserver must be IPv4, not IPv6")
    return str(addr)


def _validate_positive_int(val: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValidationError(f"{name} must be an integer")
    if val < minimum or val > maximum:
        raise ValidationError(f"{name} out of allowed bounds ({minimum}..{maximum})")
    return val


def derive_runspec(
    image_config_data: Any,
    passwd_bytes: bytes,
    group_bytes: bytes,
    overrides_data: Any,
) -> dict[str, Any]:
    """Derive a deterministic microVM run spec dictionary from OCI config and overrides."""
    if not isinstance(image_config_data, dict):
        raise ValidationError("OCI image config root must be a JSON object")
    cfg_raw = image_config_data.get("config")
    if cfg_raw is None:
        cfg: dict[str, Any] = {}
    elif isinstance(cfg_raw, dict):
        cfg = cfg_raw
    else:
        raise ValidationError("OCI image config 'config' field must be an object or null")
    if set(cfg.keys()) - _OCI_CONFIG_ALLOWED_KEYS:
        raise ValidationError("OCI image config 'config' contains unknown fields")

    if not isinstance(overrides_data, dict):
        raise ValidationError("overrides must be a JSON object")
    unknown_ov = set(overrides_data.keys()) - _OVERRIDES_ALLOWED_KEYS
    if unknown_ov:
        raise ValidationError("overrides contains unknown fields")
    missing_ov = _OVERRIDES_REQUIRED_KEYS - set(overrides_data.keys())
    if missing_ov:
        raise ValidationError("overrides is missing required fields")
    for optional_key in ("cmd", "workdir", "user"):
        if optional_key in overrides_data and overrides_data[optional_key] is None:
            raise ValidationError(f"overrides.{optional_key} must not be null when present")

    vcpus = _validate_positive_int(overrides_data["vcpus"], "vcpus", 1, MAX_VCPUS)
    memory_mib = _validate_positive_int(overrides_data["memory_mib"], "memory_mib", 16, MAX_MEMORY_MIB)
    disk_mib = _validate_positive_int(overrides_data["disk_mib"], "disk_mib", 16, MAX_DISK_MIB)
    hostname = _validate_hostname(overrides_data["hostname"])
    nameserver = _validate_ipv4(overrides_data["nameserver"])

    passwd_by_name, passwd_by_uid, _bad_pw = parse_passwd_bytes(passwd_bytes)
    group_by_name, user_groups, _bad_gr = parse_group_bytes(group_bytes)

    if "user" in overrides_data and overrides_data["user"] is not None:
        user_spec = overrides_data["user"]
        if not isinstance(user_spec, str):
            raise ValidationError("overrides.user must be a string")
        _require_utf8(user_spec, "overrides.user")
    else:
        raw_cfg_user = cfg.get("User")
        if raw_cfg_user is None:
            user_spec = ""
        elif isinstance(raw_cfg_user, str):
            user_spec = _require_utf8(raw_cfg_user, "config.User")
        else:
            raise ValidationError("config.User must be a string or null")

    uid, gid, supplementary_gids = _resolve_user_and_groups(
        user_spec=user_spec,
        passwd_by_name=passwd_by_name,
        passwd_by_uid=passwd_by_uid,
        group_by_name=group_by_name,
        user_groups=user_groups,
    )

    if "workdir" in overrides_data and overrides_data["workdir"] is not None:
        cwd = _normalise_and_validate_cwd(overrides_data["workdir"])
    else:
        cwd = _normalise_and_validate_cwd(cfg.get("WorkingDir"))

    env_list = _parse_env_list(cfg.get("Env"))

    entrypoint = _validate_argv_list(cfg.get("Entrypoint"), "config.Entrypoint")
    if "cmd" in overrides_data and overrides_data["cmd"] is not None:
        cmd = _validate_argv_list(overrides_data["cmd"], "overrides.cmd")
    else:
        cmd = _validate_argv_list(cfg.get("Cmd"), "config.Cmd")

    if len(entrypoint) + len(cmd) > MAX_ARGV_COUNT:
        raise CapExceededError("Combined entrypoint + cmd count exceeds MAX_ARGV_COUNT")
    total_argv_bytes = sum(len(s.encode("utf-8")) for s in entrypoint) + sum(
        len(s.encode("utf-8")) for s in cmd
    )
    if total_argv_bytes > MAX_ARGV_BYTES:
        raise CapExceededError("Combined entrypoint + cmd size exceeds MAX_ARGV_BYTES (256 KiB)")

    resolv_conf = f"nameserver {nameserver}\noptions ndots:0\n"

    return {
        "env": env_list,
        "cwd": cwd,
        "uid": uid,
        "gid": gid,
        "supplementary_gids": supplementary_gids,
        "entrypoint": entrypoint,
        "cmd": cmd,
        "resources": {
            "vcpus": vcpus,
            "memory_mib": memory_mib,
            "disk_mib": disk_mib,
        },
        "hostname": hostname,
        "resolv_conf": resolv_conf,
    }


def derive_runspec_from_files(
    config_path: str | os.PathLike[str],
    passwd_path: str | os.PathLike[str],
    group_path: str | os.PathLike[str],
    overrides_path: str | os.PathLike[str],
    config_cap_bytes: int = DEFAULT_CONFIG_CAP_BYTES,
    passwd_cap_bytes: int = DEFAULT_PASSWD_CAP_BYTES,
    group_cap_bytes: int = DEFAULT_GROUP_CAP_BYTES,
    overrides_cap_bytes: int = DEFAULT_OVERRIDES_CAP_BYTES,
) -> dict[str, Any]:
    cfg_raw = read_regular_file_bounded(config_path, max_bytes=config_cap_bytes)
    cfg_data = parse_json_bytes(cfg_raw, max_bytes=config_cap_bytes)

    passwd_raw = read_regular_file_bounded(passwd_path, max_bytes=passwd_cap_bytes)
    group_raw = read_regular_file_bounded(group_path, max_bytes=group_cap_bytes)

    ov_raw = read_regular_file_bounded(overrides_path, max_bytes=overrides_cap_bytes)
    ov_data = parse_json_bytes(ov_raw, max_bytes=overrides_cap_bytes)

    return derive_runspec(
        image_config_data=cfg_data,
        passwd_bytes=passwd_raw,
        group_bytes=group_raw,
        overrides_data=ov_data,
    )
