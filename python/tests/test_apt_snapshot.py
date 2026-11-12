"""Offline pytest suite for Component G11 (hermetic_apt_snapshot)."""

from __future__ import annotations

import json
import pytest

from hermetic_apt_snapshot.__main__ import main as cli_main
from hermetic_apt_snapshot.select import DateParseError, ValidationError, select_apt_snapshot


def test_rule1_ubuntu_and_debian_boundary() -> None:
    """Test Rule 1 availability cutoffs: Ubuntu 2023-03-01 and Debian 2005-03-12."""
    # 1 nanosecond before 2023-03-01T00:00:00Z -> unavailable
    before_ubuntu = select_apt_snapshot(
        dist="ubuntu",
        suite="jammy",
        components=["main", "universe"],
        architectures=["amd64"],
        cutoff="2023-02-28T23:59:59.999999999Z",
        signed_by="/usr/share/keyrings/ubuntu-archive-keyring.gpg",
    )
    assert before_ubuntu == {"available": False, "reason": "ubuntu_snapshot_before_2023_03_01"}

    # Exactly at 2023-03-01T00:00:00Z -> available
    exact_ubuntu = select_apt_snapshot(
        dist="ubuntu",
        suite="jammy",
        components=["universe", "main"],
        architectures=["amd64"],
        cutoff="2023-03-01T00:00:00Z",
        signed_by="/usr/share/keyrings/ubuntu-archive-keyring.gpg",
    )
    assert exact_ubuntu["available"] is True
    assert exact_ubuntu["snapshot_id"] == "20230301T000000Z"

    # Debian 1 second before 2005-03-12T00:00:00Z -> unavailable
    before_debian = select_apt_snapshot(
        dist="debian",
        suite="sarge",
        components=["main"],
        architectures=["i386"],
        cutoff="2005-03-11T23:59:59Z",
        signed_by="/usr/share/keyrings/debian-archive-keyring.gpg",
    )
    assert before_debian == {"available": False, "reason": "debian_snapshot_before_2005_03_12"}

    # Debian exactly at 2005-03-12T00:00:00Z -> available
    exact_debian = select_apt_snapshot(
        dist="debian",
        suite="sarge",
        components=["main"],
        architectures=["i386"],
        cutoff="2005-03-12T00:00:00Z",
        signed_by="/usr/share/keyrings/debian-archive-keyring.gpg",
    )
    assert exact_debian["available"] is True
    assert exact_debian["snapshot_id"] == "20050312T000000Z"


def test_rule2_rounding_down_to_second() -> None:
    """Test Rule 2 rounding down to integer second (never later than cutoff)."""
    res = select_apt_snapshot(
        dist="ubuntu",
        suite="noble",
        components=["main"],
        architectures=["arm64", "amd64"],
        cutoff="2024-06-15T14:22:59.999999999Z",
        signed_by="/usr/share/keyrings/ubuntu-archive-keyring.gpg",
    )
    assert res["snapshot_id"] == "20240615T142259Z"


def test_rule3_deb822_sources_text_ubuntu_and_debian() -> None:
    """Test Rule 3 sources file formatting for Ubuntu, Debian 11+ and legacy Debian."""
    # Ubuntu known-answer text
    ub = select_apt_snapshot(
        dist="ubuntu",
        suite="jammy",
        components=["universe", "main"],
        architectures=["amd64"],
        cutoff="2023-03-01T00:00:00Z",
        signed_by="/usr/share/keyrings/ubuntu-archive-keyring.gpg",
    )
    expected_ub_sources = (
        "Types: deb\n"
        "URIs: https://snapshot.ubuntu.com/ubuntu/20230301T000000Z\n"
        "Suites: jammy jammy-updates jammy-security\n"
        "Components: main universe\n"
        "Architectures: amd64\n"
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
        "Check-Valid-Until: no\n"
    )
    assert ub["sources"] == expected_ub_sources

    # Modern Debian (bookworm -> bookworm-security)
    modern = select_apt_snapshot(
        dist="debian",
        suite="bookworm",
        components=["main"],
        architectures=["amd64"],
        cutoff="2023-07-01T10:00:00Z",
        signed_by="/usr/share/keyrings/debian-archive-keyring.gpg",
    )
    expected_modern = (
        "Types: deb\n"
        "URIs: https://snapshot.debian.org/archive/debian/20230701T100000Z\n"
        "Suites: bookworm bookworm-updates\n"
        "Components: main\n"
        "Architectures: amd64\n"
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
        "Check-Valid-Until: no\n"
        "\n"
        "Types: deb\n"
        "URIs: https://snapshot.debian.org/archive/debian-security/20230701T100000Z\n"
        "Suites: bookworm-security\n"
        "Components: main\n"
        "Architectures: amd64\n"
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
        "Check-Valid-Until: no\n"
    )
    assert modern["sources"] == expected_modern

    # Older Debian (buster -> buster/updates)
    old = select_apt_snapshot(
        dist="debian",
        suite="buster",
        components=["contrib", "main"],
        architectures=["amd64"],
        cutoff="2020-05-01T00:00:00Z",
        signed_by="/usr/share/keyrings/debian-archive-keyring.gpg",
    )
    assert old["available"] is True
    assert "Suites: buster/updates\n" in old["sources"]


def test_rule4_validation_and_caps() -> None:
    """Test Rule 4 validation of suite, components, architectures allow-list, and signed-by."""
    with pytest.raises(ValidationError):
        select_apt_snapshot("fedora", "jammy", ["main"], ["amd64"], "2023-04-01T00:00:00Z", "/k.gpg")
    with pytest.raises(ValidationError):
        select_apt_snapshot("ubuntu", "Jammy_Bad", ["main"], ["amd64"], "2023-04-01T00:00:00Z", "/k.gpg")
    with pytest.raises(ValidationError):
        select_apt_snapshot("ubuntu", "jammy", ["main\nInjection: yes"], ["amd64"], "2023-04-01T00:00:00Z", "/k.gpg")
    with pytest.raises(ValidationError):
        select_apt_snapshot("ubuntu", "jammy", ["main"], ["riscv64"], "2023-04-01T00:00:00Z", "/k.gpg")
    with pytest.raises(ValidationError):
        select_apt_snapshot("ubuntu", "jammy", ["main"], ["amd64"], "2023-04-01T00:00:00Z", "relative.gpg")
    with pytest.raises(ValidationError):
        select_apt_snapshot("ubuntu", "jammy", ["main"], [], "2023-04-01T00:00:00Z", "/k.gpg")
    with pytest.raises(ValidationError):
        select_apt_snapshot("ubuntu", "jammy", [], ["amd64"], "2023-04-01T00:00:00Z", "/k.gpg")
    with pytest.raises(DateParseError):
        select_apt_snapshot("ubuntu", "jammy", ["main"], ["amd64"], "2023-04-01", "/k.gpg")


def test_rule5_cli_and_determinism(capsys: pytest.CaptureFixture[str]) -> None:
    """Test Rule 5 CLI execution, JSON printing, exit codes, and output determinism."""
    rc1 = cli_main(
        [
            "--dist",
            "ubuntu",
            "--suite",
            "jammy",
            "--components",
            "universe,main",
            "--arch",
            "arm64,amd64",
            "--cutoff",
            "2023-04-01T00:00:00Z",
            "--signed-by",
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        ]
    )
    out1 = capsys.readouterr().out
    rc2 = cli_main(
        [
            "--dist",
            "ubuntu",
            "--suite",
            "jammy",
            "--components",
            "main,universe",
            "--arch",
            "amd64,arm64",
            "--cutoff",
            "2023-04-01T00:00:00Z",
            "--signed-by",
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        ]
    )
    out2 = capsys.readouterr().out
    assert rc1 == 0 and rc2 == 0
    assert out1 == out2
    parsed = json.loads(out1)
    assert parsed["available"] is True
    assert set(parsed.keys()) == {"available", "snapshot_id", "sources"}

    # CLI exit 0 for unavailable snapshot
    rc_unavail = cli_main(
        [
            "--dist",
            "ubuntu",
            "--suite",
            "jammy",
            "--components",
            "main",
            "--arch",
            "amd64",
            "--cutoff",
            "2020-01-01T00:00:00Z",
            "--signed-by",
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        ]
    )
    out_unavail = capsys.readouterr().out
    assert rc_unavail == 0
    parsed_unavail = json.loads(out_unavail)
    assert parsed_unavail["available"] is False
    assert parsed_unavail["reason"] == "ubuntu_snapshot_before_2023_03_01"

    # CLI exit 1 on invalid argument
    rc_bad = cli_main(
        [
            "--dist",
            "unsupported_dist",
            "--suite",
            "jammy",
            "--components",
            "main",
            "--arch",
            "amd64",
            "--cutoff",
            "2023-04-01T00:00:00Z",
            "--signed-by",
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        ]
    )
    assert rc_bad == 1
