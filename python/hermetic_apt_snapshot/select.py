"""Deterministic APT snapshot eligibility check and deb822 sources generation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any

MAX_NAME_LEN = 64
MAX_COMPONENTS = 32
MAX_ARCHITECTURES = 16
MAX_SIGNED_BY_LEN = 4096

ALLOWED_DISTRIBUTIONS = frozenset({"ubuntu", "debian"})
ALLOWED_ARCHITECTURES = frozenset({"amd64", "arm64", "i386", "armhf"})

# Debian security naming convention:
# Debian 10 (buster) and earlier suites use "<suite>/updates" on security archive;
# Debian 11 (bullseye) and later suites use "<suite>-security".
OLD_DEBIAN_SECURITY_SUITES = frozenset(
    {
        "buzz",
        "rex",
        "bo",
        "hamm",
        "slink",
        "potato",
        "woody",
        "sarge",
        "etch",
        "lenny",
        "squeeze",
        "wheezy",
        "jessie",
        "stretch",
        "buster",
    }
)

# Relative Debian aliases name a different release depending on the date, so the security
# suite naming (old "<suite>/updates" vs new "<suite>-security") cannot be decided from the
# name alone. They are refused (fail closed); callers must pass the release codename.
DEBIAN_RELATIVE_SUITE_ALIASES = frozenset(
    {
        "stable",
        "oldstable",
        "oldoldstable",
        "oldoldoldstable",
        "testing",
        "unstable",
        "experimental",
        # Codenames of unstable/experimental: they have no -updates or -security suites.
        "sid",
        "rc-buggy",
    }
)

# Ubuntu publishes amd64/i386 in the "ubuntu" archive and every other architecture in
# "ubuntu-ports".
UBUNTU_PRIMARY_ARCHITECTURES = frozenset({"amd64", "i386"})

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_RFC3339_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$",
    flags=re.ASCII,
)
_SUITE_COMP_RE = re.compile(r"^[a-z0-9-]+$", flags=re.ASCII)
# Signed-By is a whitespace-separated list in deb822, so the single path must not contain
# whitespace, control or non-ASCII characters.
_SIGNED_BY_RE = re.compile(r"^/[A-Za-z0-9._+/-]+$", flags=re.ASCII)


class HermeticAptSnapshotError(Exception):
    """Base typed error for hermetic_apt_snapshot."""

    code: str = "HERMETIC_APT_SNAPSHOT_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ValidationError(HermeticAptSnapshotError):
    code: str = "VALIDATION_ERROR"


class DateParseError(HermeticAptSnapshotError):
    code: str = "DATE_PARSE_ERROR"


def parse_rfc3339_utc_nanos(value: str) -> int:
    """Strictly parse RFC 3339 UTC string with trailing 'Z' to integer nanoseconds since epoch."""
    if not isinstance(value, str) or len(value) > 40:
        raise DateParseError("Invalid RFC 3339 UTC timestamp string")
    match = _RFC3339_RE.fullmatch(value)
    if match is None:
        raise DateParseError("Timestamp must be strict RFC 3339 UTC")
    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))
    frac = match.group(7)
    try:
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as exc:
        raise DateParseError("Calendar date/time out of range") from exc
    epoch_seconds = (dt - _EPOCH_UTC) // timedelta(seconds=1)
    nanos = int(frac.ljust(9, "0")) if frac is not None else 0
    return epoch_seconds * 1_000_000_000 + nanos


UBUNTU_SNAPSHOT_START_NANOS = parse_rfc3339_utc_nanos("2023-03-01T00:00:00Z")
DEBIAN_SNAPSHOT_START_NANOS = parse_rfc3339_utc_nanos("2005-03-12T00:00:00Z")


def _validate_token(val: Any, label: str) -> str:
    if not isinstance(val, str):
        raise ValidationError(f"{label} must be a string")
    if len(val) == 0 or len(val) > MAX_NAME_LEN:
        raise ValidationError(f"{label} length out of bounds (1..{MAX_NAME_LEN})")
    if _SUITE_COMP_RE.fullmatch(val) is None:
        raise ValidationError(f"{label} must match [a-z0-9-]+")
    return val


def _validate_signed_by(signed_by: Any) -> str:
    if not isinstance(signed_by, str):
        raise ValidationError("signed_by must be a string")
    if len(signed_by) == 0 or len(signed_by) > MAX_SIGNED_BY_LEN:
        raise ValidationError("signed_by length out of bounds")
    if "\x00" in signed_by or "\n" in signed_by or "\r" in signed_by:
        raise ValidationError("signed_by must not contain NUL or newline characters")
    if not signed_by.startswith("/"):
        raise ValidationError("signed_by must be an absolute path inside the guest")
    if _SIGNED_BY_RE.fullmatch(signed_by) is None:
        raise ValidationError("signed_by must be a single path of [A-Za-z0-9._+/-] characters")
    return signed_by


def _format_snapshot_id_floor_second(cutoff_nanos: int) -> str:
    # Integer floor division rounds DOWN to the whole second, never later than cutoff.
    floor_seconds = cutoff_nanos // 1_000_000_000
    dt = _EPOCH_UTC + timedelta(seconds=floor_seconds)
    return dt.strftime("%Y%m%dT%H%M%SZ")


def _render_deb822_stanza(
    uri: str,
    suites: list[str],
    components: list[str],
    architectures: list[str],
    signed_by: str,
) -> str:
    lines = [
        "Types: deb",
        f"URIs: {uri}",
        f"Suites: {' '.join(suites)}",
        f"Components: {' '.join(components)}",
        f"Architectures: {' '.join(architectures)}",
        f"Signed-By: {signed_by}",
        "Check-Valid-Until: no",
    ]
    return "\n".join(lines)


def select_apt_snapshot(
    dist: str,
    suite: str,
    components: list[str],
    architectures: list[str],
    cutoff: str,
    signed_by: str,
) -> dict[str, Any]:
    """Validate inputs and produce APT snapshot selection and deb822 sources text."""
    if not isinstance(dist, str) or dist not in ALLOWED_DISTRIBUTIONS:
        raise ValidationError("dist must be 'ubuntu' or 'debian'")

    clean_suite = _validate_token(suite, "suite")
    if dist == "debian" and clean_suite in DEBIAN_RELATIVE_SUITE_ALIASES:
        raise ValidationError("debian suite must be a release codename, not a relative alias")

    if not isinstance(components, list) or len(components) == 0:
        raise ValidationError("components must be a non-empty list")
    if len(components) > MAX_COMPONENTS:
        raise ValidationError(f"components count exceeds MAX_COMPONENTS ({MAX_COMPONENTS})")
    clean_components = sorted({_validate_token(c, "component") for c in components})

    if not isinstance(architectures, list) or len(architectures) == 0:
        raise ValidationError("architectures must be a non-empty list")
    if len(architectures) > MAX_ARCHITECTURES:
        raise ValidationError(f"architectures count exceeds MAX_ARCHITECTURES ({MAX_ARCHITECTURES})")
    clean_archs_set: set[str] = set()
    for arch in architectures:
        if not isinstance(arch, str) or arch not in ALLOWED_ARCHITECTURES:
            raise ValidationError("Unsupported architecture")
        clean_archs_set.add(arch)
    clean_architectures = sorted(clean_archs_set)

    clean_signed_by = _validate_signed_by(signed_by)
    cutoff_nanos = parse_rfc3339_utc_nanos(cutoff)

    if dist == "ubuntu" and cutoff_nanos < UBUNTU_SNAPSHOT_START_NANOS:
        return {
            "available": False,
            "reason": "ubuntu_snapshot_before_2023_03_01",
        }
    if dist == "debian" and cutoff_nanos < DEBIAN_SNAPSHOT_START_NANOS:
        return {
            "available": False,
            "reason": "debian_snapshot_before_2005_03_12",
        }

    snapshot_id = _format_snapshot_id_floor_second(cutoff_nanos)

    if dist == "ubuntu":
        suites = [clean_suite, f"{clean_suite}-updates", f"{clean_suite}-security"]
        primary = [a for a in clean_architectures if a in UBUNTU_PRIMARY_ARCHITECTURES]
        ports = [a for a in clean_architectures if a not in UBUNTU_PRIMARY_ARCHITECTURES]
        stanzas = [
            _render_deb822_stanza(
                uri=f"https://snapshot.ubuntu.com/{archive}/{snapshot_id}",
                suites=suites,
                components=clean_components,
                architectures=archs,
                signed_by=clean_signed_by,
            )
            for archive, archs in (("ubuntu", primary), ("ubuntu-ports", ports))
            if archs
        ]
        sources = "\n\n".join(stanzas) + "\n"
    else:
        main_uri = f"https://snapshot.debian.org/archive/debian/{snapshot_id}"
        sec_uri = f"https://snapshot.debian.org/archive/debian-security/{snapshot_id}"
        if clean_suite in OLD_DEBIAN_SECURITY_SUITES:
            sec_suite = f"{clean_suite}/updates"
        else:
            sec_suite = f"{clean_suite}-security"
        main_stanza = _render_deb822_stanza(
            uri=main_uri,
            suites=[clean_suite, f"{clean_suite}-updates"],
            components=clean_components,
            architectures=clean_architectures,
            signed_by=clean_signed_by,
        )
        sec_stanza = _render_deb822_stanza(
            uri=sec_uri,
            suites=[sec_suite],
            components=clean_components,
            architectures=clean_architectures,
            signed_by=clean_signed_by,
        )
        sources = f"{main_stanza}\n\n{sec_stanza}\n"

    return {
        "available": True,
        "snapshot_id": snapshot_id,
        "sources": sources,
    }
