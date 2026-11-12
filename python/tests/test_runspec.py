"""Offline pytest suite for Component G8 (hermetic_runspec)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from hermetic_runspec.__main__ import main as cli_main
from hermetic_runspec.derive import (
    MAX_ENV_COUNT,
    CapExceededError,
    FileSafetyError,
    JsonParseError,
    UserResolutionError,
    ValidationError,
    derive_runspec,
    derive_runspec_from_files,
    parse_group_bytes,
    parse_passwd_bytes,
)

PASSWD_FIXTURE = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"malformed_line_only_three:fields:here\n"
    b"baduid:x:-5:100::/home/bad:/bin/sh\n"
    b"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    b"bob:x:1001:1001:Bob:/home/bob:/bin/sh\n"
)

GROUP_FIXTURE = (
    b"root:x:0:\n"
    b"badgroup:x:notanint:alice\n"
    b"alice:x:1000:\n"
    b"bob:x:1001:\n"
    b"docker:x:999:alice,bob\n"
    b"wheel:x:10:alice\n"
)


def _base_overrides() -> dict:
    return {
        "vcpus": 2,
        "memory_mib": 2048,
        "disk_mib": 10240,
        "hostname": "hermetic-vm-01",
        "nameserver": "10.0.2.3",
    }


def test_rule1_output_runspec_structure() -> None:
    """Rule 1: Verify all required keys in the derived run spec JSON."""
    spec = derive_runspec({"config": {}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert set(spec.keys()) == {
        "env",
        "cwd",
        "uid",
        "gid",
        "supplementary_gids",
        "entrypoint",
        "cmd",
        "resources",
        "hostname",
        "resolv_conf",
    }
    assert spec["resources"] == {"vcpus": 2, "memory_mib": 2048, "disk_mib": 10240}
    assert spec["hostname"] == "hermetic-vm-01"
    assert spec["resolv_conf"] == "nameserver 10.0.2.3\noptions ndots:0\n"


def test_rule2_env_validation_last_wins_and_caps() -> None:
    """Rule 2: config.Env parsing, sorting, duplicate last-wins, and security checks."""
    cfg = {
        "config": {
            "Env": [
                "Z_VAR=1",
                "A_VAR=first",
                "A_VAR=second",
                "EMPTY_EQ=a=b=c",
            ]
        }
    }
    spec = derive_runspec(cfg, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    # Sorted by name, last duplicate wins
    assert spec["env"] == [["A_VAR", "second"], ["EMPTY_EQ", "a=b=c"], ["Z_VAR", "1"]]

    # Invalid env name rejected
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"Env": ["1INVALID=val"]}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"Env": ["BAD-NAME=val"]}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())

    # NUL byte rejected
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"Env": ["VAR=val\x00x"]}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())

    # Missing '=' rejected
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"Env": ["NO_EQUALS"]}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())

    # Max count cap 512
    too_many = [f"VAR_{i}=val" for i in range(MAX_ENV_COUNT + 1)]
    with pytest.raises(CapExceededError):
        derive_runspec({"config": {"Env": too_many}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())


def test_rule3_every_user_form_and_group_resolution() -> None:
    """Rule 3: User forms ("", name, uid, name:group, uid:gid, name:gid, uid:group) and passwd/group strict parsing."""
    # Verify strict parser skips and counts bad lines
    _, _, bad_pw = parse_passwd_bytes(PASSWD_FIXTURE)
    _, _, bad_gr = parse_group_bytes(GROUP_FIXTURE)
    assert bad_pw == 2
    assert bad_gr == 1

    # 1. "" -> root 0:0
    spec_empty = derive_runspec({"config": {"User": ""}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_empty["uid"], spec_empty["gid"], spec_empty["supplementary_gids"]) == (0, 0, [])

    # None user -> defaults to root 0:0
    spec_none = derive_runspec({"config": {}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_none["uid"], spec_none["gid"], spec_none["supplementary_gids"]) == (0, 0, [])

    # 2. "name" -> alice 1000:1000 with wheel (10) and docker (999)
    spec_name = derive_runspec({"config": {"User": "alice"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_name["uid"], spec_name["gid"]) == (1000, 1000)
    assert spec_name["supplementary_gids"] == [10, 999]

    # 3. "uid" -> 1000 resolves alice and supplementary groups
    spec_uid = derive_runspec({"config": {"User": "1000"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_uid["uid"], spec_uid["gid"], spec_uid["supplementary_gids"]) == (1000, 1000, [10, 999])

    # Numeric uid not in passwd -> uid=2000, gid=0, no supplementary groups
    spec_unknown_uid = derive_runspec({"config": {"User": "2000"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_unknown_uid["uid"], spec_unknown_uid["gid"], spec_unknown_uid["supplementary_gids"]) == (2000, 0, [])

    # 4. "name:group" -> alice:docker -> 1000:999, supplementary [10] (primary 999 excluded)
    spec_ng = derive_runspec({"config": {"User": "alice:docker"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_ng["uid"], spec_ng["gid"], spec_ng["supplementary_gids"]) == (1000, 999, [10])

    # 5. "uid:gid" -> 1001:2000 -> 1001:2000, bob's supplementary [999]
    spec_ug = derive_runspec({"config": {"User": "1001:2000"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_ug["uid"], spec_ug["gid"], spec_ug["supplementary_gids"]) == (1001, 2000, [999])

    # 6. "name:gid" -> alice:3000 -> 1000:3000, supplementary [10, 999]
    spec_ngid = derive_runspec({"config": {"User": "alice:3000"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_ngid["uid"], spec_ngid["gid"], spec_ngid["supplementary_gids"]) == (1000, 3000, [10, 999])

    # 7. "uid:group" -> 1001:wheel -> 1001:10, bob's supplementary [999]
    spec_ugrp = derive_runspec({"config": {"User": "1001:wheel"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert (spec_ugrp["uid"], spec_ugrp["gid"], spec_ugrp["supplementary_gids"]) == (1001, 10, [999])

    # User in overrides takes precedence over config.User
    ov_user = _base_overrides()
    ov_user["user"] = "bob"
    spec_ov_user = derive_runspec({"config": {"User": "alice"}}, PASSWD_FIXTURE, GROUP_FIXTURE, ov_user)
    assert spec_ov_user["uid"] == 1001

    # Unresolvable name or group fails
    with pytest.raises(UserResolutionError):
        derive_runspec({"config": {"User": "charlie"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    with pytest.raises(UserResolutionError):
        derive_runspec({"config": {"User": "alice:nosuchgroup"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())


def test_rule4_cwd_normalisation() -> None:
    """Rule 4: WorkingDir normalisation, defaults, and traversal prevention."""
    # Default to "/"
    assert derive_runspec({"config": {}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())["cwd"] == "/"
    assert derive_runspec({"config": {"WorkingDir": ""}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())["cwd"] == "/"

    # Normalised path
    spec = derive_runspec({"config": {"WorkingDir": "/var/tmp//dir/"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert spec["cwd"] == "/var/tmp/dir"

    # Override takes precedence
    ov = _base_overrides()
    ov["workdir"] = "/opt/app"
    spec_ov = derive_runspec({"config": {"WorkingDir": "/var/tmp"}}, PASSWD_FIXTURE, GROUP_FIXTURE, ov)
    assert spec_ov["cwd"] == "/opt/app"

    # Relative paths and '..' traversal rejected
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"WorkingDir": "relative/path"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"WorkingDir": "/app/../etc"}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())


def test_rule5_entrypoint_and_cmd_docker_semantics() -> None:
    """Rule 5: Docker semantics for entrypoint and cmd, string validation, and caps."""
    cfg = {
        "config": {
            "Entrypoint": ["/entrypoint.sh"],
            "Cmd": ["server", "run"],
        }
    }
    # Without override, both entrypoint and cmd kept
    spec = derive_runspec(cfg, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())
    assert spec["entrypoint"] == ["/entrypoint.sh"]
    assert spec["cmd"] == ["server", "run"]

    # Override replaces cmd, entrypoint kept
    ov = _base_overrides()
    ov["cmd"] = ["custom", "test"]
    spec_ov = derive_runspec(cfg, PASSWD_FIXTURE, GROUP_FIXTURE, ov)
    assert spec_ov["entrypoint"] == ["/entrypoint.sh"]
    assert spec_ov["cmd"] == ["custom", "test"]

    # NUL byte in argv rejected
    with pytest.raises(ValidationError):
        derive_runspec({"config": {"Cmd": ["bad\x00arg"]}}, PASSWD_FIXTURE, GROUP_FIXTURE, _base_overrides())


def test_rule6_hostname_and_resolv_conf() -> None:
    """Rule 6: Hostname lower-case DNS label validation and IPv4 nameserver in resolv.conf."""
    ov = _base_overrides()
    ov["hostname"] = "valid-node-01.internal"
    ov["nameserver"] = "8.8.8.8"
    spec = derive_runspec({"config": {}}, PASSWD_FIXTURE, GROUP_FIXTURE, ov)
    assert spec["hostname"] == "valid-node-01.internal"
    assert spec["resolv_conf"] == "nameserver 8.8.8.8\noptions ndots:0\n"

    # Uppercase hostname rejected
    bad_host = _base_overrides()
    bad_host["hostname"] = "BadHost"
    with pytest.raises(ValidationError):
        derive_runspec({"config": {}}, PASSWD_FIXTURE, GROUP_FIXTURE, bad_host)

    # IPv6 nameserver rejected
    bad_ns = _base_overrides()
    bad_ns["nameserver"] = "2001:db8::1"
    with pytest.raises(ValidationError):
        derive_runspec({"config": {}}, PASSWD_FIXTURE, GROUP_FIXTURE, bad_ns)


def test_rule7_cli_and_file_safety(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 7: CLI command execution, exit codes, determinism, and hostile file defense."""
    cfg_f = tmp_path / "cfg.json"
    pw_f = tmp_path / "passwd"
    gr_f = tmp_path / "group"
    ov_f = tmp_path / "overrides.json"

    cfg_f.write_text(json.dumps({"config": {"Env": ["B=2", "A=1"], "User": "alice"}}), encoding="utf-8")
    pw_f.write_bytes(PASSWD_FIXTURE)
    gr_f.write_bytes(GROUP_FIXTURE)
    ov_f.write_text(json.dumps(_base_overrides()), encoding="utf-8")

    # CLI successful runs are deterministic
    rc1 = cli_main(["--config", str(cfg_f), "--passwd", str(pw_f), "--group", str(gr_f), "--overrides", str(ov_f)])
    out1 = capsys.readouterr().out
    rc2 = cli_main(["--config", str(cfg_f), "--passwd", str(pw_f), "--group", str(gr_f), "--overrides", str(ov_f)])
    out2 = capsys.readouterr().out
    assert rc1 == 0 and rc2 == 0
    assert out1 == out2
    parsed = json.loads(out1)
    assert parsed["uid"] == 1000
    assert parsed["env"] == [["A", "1"], ["B", "2"]]

    # Duplicate keys in overrides JSON rejected
    bad_ov_f = tmp_path / "bad_ov.json"
    bad_ov_f.write_text('{"vcpus": 1, "vcpus": 2, "memory_mib": 512, "disk_mib": 1024, "hostname": "vm1", "nameserver": "1.1.1.1"}', encoding="utf-8")
    with pytest.raises(JsonParseError):
        derive_runspec_from_files(cfg_f, pw_f, gr_f, bad_ov_f)

    # Symlink input refused
    sym_pw = tmp_path / "sym_pw"
    os.symlink(pw_f, sym_pw)
    with pytest.raises(FileSafetyError):
        derive_runspec_from_files(cfg_f, sym_pw, gr_f, ov_f)

    # CLI exit code 1 on error
    rc_err = cli_main(["--config", str(cfg_f), "--passwd", str(sym_pw), "--group", str(gr_f), "--overrides", str(ov_f)])
    assert rc_err == 1
