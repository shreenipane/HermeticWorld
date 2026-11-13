"""Offline pytest suite for Component G7 (hermetic_tlspolicy)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from hermetic_tlspolicy.__main__ import main as cli_main
from hermetic_tlspolicy.policy import (
    MAX_HOSTS,
    MAX_T_CLOCK,
    MIN_T_CLOCK,
    SECONDS_PER_DAY,
    CapExceededError,
    DecisionAction,
    FileSafetyError,
    HostTable,
    JsonParseError,
    ResetReason,
    ValidationError,
    decide,
    leaf_window,
    leaf_window_rfc3339,
    load_host_table,
    load_host_table_file,
    method_policy,
)


def test_rule1_leaf_window_known_answers_and_bounds() -> None:
    """Rule 1: leaf_window(t_clock: int Unix seconds) -> (not_before, not_after)."""
    # 2023-04-01T00:00:00Z == 1680307200
    t_clock = 1680307200
    nb, na = leaf_window(t_clock)
    assert nb == t_clock - 7 * SECONDS_PER_DAY
    assert na == t_clock + 365 * SECONDS_PER_DAY

    rfc = leaf_window_rfc3339(t_clock)
    assert rfc["not_before"] == "2023-03-25T00:00:00Z"
    assert rfc["not_after"] == "2024-03-31T00:00:00Z"  # 2024 is leap year, 365 days after Apr 1 is Mar 31

    # Exact bounds: 1990-01-01 and 2100-01-01 inclusive
    assert leaf_window(MIN_T_CLOCK) == (MIN_T_CLOCK - 7 * 86400, MIN_T_CLOCK + 365 * 86400)
    assert leaf_window(MAX_T_CLOCK) == (MAX_T_CLOCK - 7 * 86400, MAX_T_CLOCK + 365 * 86400)

    # Rejection outside boundaries and non-integer/bool types
    with pytest.raises(ValidationError):
        leaf_window(MIN_T_CLOCK - 1)
    with pytest.raises(ValidationError):
        leaf_window(MAX_T_CLOCK + 1)
    with pytest.raises(ValidationError):
        leaf_window(True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        leaf_window("1680307200")  # type: ignore[arg-type]


def test_rule2_host_table_validation_and_rules() -> None:
    """Rule 2: Host table JSON schema, constraints, caps, and label rules."""
    table = load_host_table({"hosts": ["pypi.org", "files.pythonhosted.org", "xn--bcher-kva.example"]})
    assert table.contains("pypi.org")
    assert not table.contains("unknown.org")

    # Upper-case DNS names rejected in table
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["PyPI.org"]})

    # Non-ASCII IDN rejected
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["b\u00fccher.example"]})

    # Wildcard rejected
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["*.pypi.org"]})

    # IP literals rejected (IPv4 and IPv6)
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["127.0.0.1"]})
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["::1"]})

    # Leading/trailing hyphens, trailing dot, empty labels, and oversized labels rejected
    for bad in ("-pypi.org", "pypi-.org", "pypi..org", "pypi.org.", "a" * 64 + ".org"):
        with pytest.raises(ValidationError):
            load_host_table({"hosts": [bad]})

    # Total length > 253 rejected
    long_host = ("a" * 60 + ".") * 4 + "com"  # 248 chars ok
    load_host_table({"hosts": [long_host]})
    too_long = ("a" * 60 + ".") * 4 + "toolongtld"  # > 253
    with pytest.raises(ValidationError):
        load_host_table({"hosts": [too_long]})

    # Duplicates rejected
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["pypi.org", "pypi.org"]})

    # Extra root keys rejected
    with pytest.raises(ValidationError):
        load_host_table({"hosts": ["pypi.org"], "extra": 1})

    # Non-list hosts rejected
    with pytest.raises(ValidationError):
        load_host_table({"hosts": "pypi.org"})

    # MAX_HOSTS cap 4096 enforced
    with pytest.raises(CapExceededError):
        load_host_table({"hosts": [f"h{i}.example.com" for i in range(MAX_HOSTS + 1)]})


def test_rule3_decide_all_paths_and_reasons() -> None:
    """Rule 3: decide(...) on port 443 and 80, including every reset reason."""
    table = load_host_table({"hosts": ["pypi.org", "files.pythonhosted.org"]})

    # Valid port 443 intercept
    d1 = decide(table, sni="PyPI.ORG", host_header="pypi.org:443", port=443, is_tls=True, has_ech=False)
    assert d1.decision == DecisionAction.INTERCEPT.value
    assert d1 == "intercept"
    assert d1.reason is None

    # Valid port 443 without Host header
    d2 = decide(table, sni="pypi.org", host_header=None, port=443, is_tls=True, has_ech=False)
    assert d2.decision == DecisionAction.INTERCEPT.value
    assert d2 == "intercept"

    # Valid port 80 intercept with optional :80 suffix
    d3 = decide(table, sni=None, host_header="PYPI.ORG:80", port=80, is_tls=False, has_ech=False)
    assert d3.decision == DecisionAction.INTERCEPT.value
    assert d3 == "intercept"

    # Valid port 80 intercept without port suffix
    d4 = decide(table, sni=None, host_header="pypi.org", port=80, is_tls=False, has_ech=False)
    assert d4.decision == DecisionAction.INTERCEPT.value

    # Trailing dot normalisation mismatch on 443: SNI vs Host
    d_mismatch_dot1 = decide(table, sni="pypi.org", host_header="pypi.org.", port=443, is_tls=True, has_ech=False)
    assert d_mismatch_dot1.decision == DecisionAction.RESET.value
    assert d_mismatch_dot1.reason == ResetReason.SNI_HOST_MISMATCH

    d_mismatch_dot2 = decide(table, sni="pypi.org.", host_header="pypi.org", port=443, is_tls=True, has_ech=False)
    assert d_mismatch_dot2.decision == DecisionAction.RESET.value
    assert d_mismatch_dot2.reason == ResetReason.SNI_HOST_MISMATCH

    # Test all distinct ResetReason values
    expected_cases: list[tuple[tuple, ResetReason]] = [
        ((table, "pypi.org", None, True, True, False), ResetReason.MALFORMED_INPUT),
        ((table, "pypi.org", None, 8443, True, False), ResetReason.UNSUPPORTED_PORT),
        ((table, "pypi.org", None, 443, True, True), ResetReason.ECH_PRESENT),
        ((table, "pypi.org", None, 443, False, False), ResetReason.TLS_REQUIRED_ON_443),
        ((table, None, None, 443, True, False), ResetReason.MISSING_SNI),
        ((table, "b\u00fccher.example", None, 443, True, False), ResetReason.MALFORMED_SNI),
        ((table, "evil.example.com", None, 443, True, False), ResetReason.UNKNOWN_SNI),
        ((table, "pypi.org", "pypi.org:8443", 443, True, False), ResetReason.MALFORMED_HOST_HEADER),
        ((table, "pypi.org", "files.pythonhosted.org", 443, True, False), ResetReason.SNI_HOST_MISMATCH),
        ((table, None, "pypi.org", 80, True, False), ResetReason.TLS_FORBIDDEN_ON_80),
        ((table, "pypi.org", "pypi.org", 80, False, False), ResetReason.UNEXPECTED_SNI_ON_80),
        ((table, None, None, 80, False, False), ResetReason.MISSING_HOST_HEADER),
        ((table, None, "pypi.org:443", 80, False, False), ResetReason.MALFORMED_HOST_HEADER),
        ((table, None, "evil.example.com", 80, False, False), ResetReason.UNKNOWN_HOST_HEADER),
    ]

    seen_reasons = {ResetReason.SNI_HOST_MISMATCH}
    for args, exp_reason in expected_cases:
        res = decide(*args)
        assert res.decision == DecisionAction.RESET.value
        assert res == "reset"
        assert res.reason == exp_reason
        seen_reasons.add(exp_reason)

    assert seen_reasons == set(ResetReason)


def test_rule4_method_policy() -> None:
    """Rule 4: method_policy(method: str) -> 200 | 405."""
    assert method_policy("GET") == 200
    assert method_policy("HEAD") == 200

    for rejected in ("get", "head", "POST", "PUT", "DELETE", "CONNECT", "PRI", "OPTIONS", "TRACE", "", "PATCH"):
        assert method_policy(rejected) == 405


def test_rule5_cli_and_file_safety(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 5: CLI commands, determinism, and safety checks."""
    hosts_f = tmp_path / "hosts.json"
    hosts_f.write_text(json.dumps({"hosts": ["pypi.org"]}), encoding="utf-8")

    # CLI window subcommand
    rc_w = cli_main(["window", "--t-clock", "1680307200"])
    out_w = capsys.readouterr().out
    assert rc_w == 0
    parsed_w = json.loads(out_w)
    assert parsed_w["not_before"] == "2023-03-25T00:00:00Z"
    assert parsed_w["not_after"] == "2024-03-31T00:00:00Z"

    # CLI decide subcommand (deterministic output)
    rc_d1 = cli_main(["decide", "--hosts", str(hosts_f), "--port", "443", "--sni", "pypi.org", "--tls"])
    out_d1 = capsys.readouterr().out
    rc_d2 = cli_main(["decide", "--hosts", str(hosts_f), "--port", "443", "--sni", "PYPI.ORG", "--tls"])
    out_d2 = capsys.readouterr().out
    assert rc_d1 == 0 and rc_d2 == 0
    assert out_d1 == out_d2
    assert json.loads(out_d1) == {"decision": "intercept", "reason": None}

    # Duplicate keys in JSON rejected
    dup_f = tmp_path / "dup.json"
    dup_f.write_text('{"hosts": ["pypi.org"], "hosts": ["pypi.org"]}', encoding="utf-8")
    with pytest.raises(JsonParseError):
        load_host_table_file(dup_f)

    # Symlink rejected
    sym_f = tmp_path / "sym_hosts.json"
    os.symlink(hosts_f, sym_f)
    with pytest.raises(FileSafetyError):
        load_host_table_file(sym_f)

    # Byte cap enforced
    with pytest.raises(CapExceededError):
        load_host_table_file(hosts_f, max_bytes=4)


# ---------------------------------------------------------------------------
# Review regressions
# ---------------------------------------------------------------------------

import subprocess
import sys

from hermetic_tlspolicy.policy import DEFAULT_HOSTS_CAP_BYTES

_PKG_ROOT = str(Path(__file__).resolve().parent.parent)


def test_named_caps_match_requirement() -> None:
    """Rule 2: the host table caps are exactly 1 MiB and 4096 entries."""
    assert DEFAULT_HOSTS_CAP_BYTES == 1024 * 1024
    assert MAX_HOSTS == 4096
    load_host_table({"hosts": [f"h{i}.example.com" for i in range(MAX_HOSTS)]})


def test_fifo_host_table_refused_without_blocking(tmp_path: Path) -> None:
    """A FIFO named as the host table is refused immediately instead of blocking on open."""
    fifo = tmp_path / "hosts.fifo"
    os.mkfifo(fifo)
    proc = subprocess.run(
        [sys.executable, "-I", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]);"
         "from hermetic_tlspolicy.__main__ import main; raise SystemExit(main(sys.argv[2:]))",
         _PKG_ROOT, "decide", "--hosts", str(fifo), "--port", "443", "--sni", "pypi.org", "--tls"],
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 1
    assert proc.stdout == b""
    with pytest.raises(FileSafetyError):
        load_host_table_file(fifo)


def test_non_string_host_header_is_malformed_not_ignored() -> None:
    """Rule 3: a malformed (non-string) Host header resets; it is never treated as absent."""
    table = load_host_table({"hosts": ["pypi.org"]})
    for bad_host in (123, b"pypi.org", ["pypi.org"], True):
        res = decide(table, "pypi.org", bad_host, 443, True, False)  # type: ignore[arg-type]
        assert res == "reset"
        assert res.reason == ResetReason.MALFORMED_INPUT
    res80 = decide(table, None, 80, 80, False, False)  # type: ignore[arg-type]
    assert res80.reason == ResetReason.MALFORMED_INPUT
    for bad_sni in (123, b"pypi.org"):
        res = decide(table, bad_sni, None, 443, True, False)  # type: ignore[arg-type]
        assert res.reason == ResetReason.MALFORMED_INPUT
    with pytest.raises(ValidationError):
        decide("pypi.org", None, 443, True, False, table)  # type: ignore[arg-type]


def test_inet_aton_ip_literal_forms_refused() -> None:
    """Rule 2: legacy IPv4 literal spellings are IP literals, not host names."""
    for bad in ("1.2.3.0x4", "0x7f.1", "0x7f000001", "127.1", "0177.0.0.01"):
        with pytest.raises(ValidationError):
            load_host_table({"hosts": [bad]})
    table = load_host_table({"hosts": ["pypi.org", "a1.example", "0x7f.example"]})
    assert table.contains("0x7f.example")
    assert decide(table, "0x7f.1", None, 443, True, False).reason == ResetReason.MALFORMED_SNI
    assert decide(table, None, "0x7f.1", 80, False, False).reason == ResetReason.MALFORMED_HOST_HEADER


def test_cli_integers_parsed_strictly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 5: --port and --t-clock accept plain ASCII decimal only."""
    hosts_f = tmp_path / "hosts.json"
    hosts_f.write_text(json.dumps({"hosts": ["pypi.org"]}), encoding="utf-8")
    for port in ("4_43", " 443", "443 ", "+443", "0443", "\uff14\uff14\uff13", "0x1bb", ""):
        rc = cli_main(["decide", "--hosts", str(hosts_f), "--port", port, "--sni", "pypi.org", "--tls"])
        assert rc == 1, port
        assert capsys.readouterr().out == ""
    for t_clock in ("1_680_307_200", "1680307200.0", " 1680307200", "+1680307200"):
        assert cli_main(["window", "--t-clock", t_clock]) == 1, t_clock
        assert capsys.readouterr().out == ""
    assert cli_main(["window", "--t-clock", "1680307200"]) == 0
    capsys.readouterr()


def test_cli_rejects_abbreviated_options(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 5: only the exact option names are accepted."""
    assert cli_main(["window", "--t-cl", "1680307200"]) == 1
    assert capsys.readouterr().out == ""


def test_cli_output_is_ascii_for_undecodable_argv(capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 5: undecodable argv bytes never crash output; the JSON is pure ASCII."""
    rc = cli_main(["method", "--method", "G\udcffET"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.isascii()
    assert json.loads(out)["status"] == 405


def test_regression_decision_hash_consistent_with_string_equality() -> None:
    from hermetic_tlspolicy.policy import Decision, ResetReason

    d = Decision("reset", ResetReason.UNKNOWN_SNI)
    assert d == "reset"
    assert d in {"reset"}
    assert {"reset": 1}[d] == 1
