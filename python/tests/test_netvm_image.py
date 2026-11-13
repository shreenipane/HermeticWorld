"""NetVM rootfs tree and AgentVM network constants."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hermetic_slice import netvm

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_RS = ROOT / "crates/hermetic-netvm-core/src/runtime.rs"
T = datetime.fromtimestamp(1700000000, timezone.utc)
TABLE = {"records": [{"name": "files.example", "a": ["10.9.0.1"], "aaaa": []}]}


def _inputs(tmp: Path, table: object = TABLE) -> dict:
    (tmp / "netvm").write_bytes(b"\x7fELFnetvm")
    (tmp / "busybox").write_bytes(b"\x7fELFbusybox")
    (tmp / "dns.json").write_text(json.dumps(table))
    return {"netvm_bin": tmp / "netvm", "busybox_bin": tmp / "busybox", "dns_table": tmp / "dns.json", "t_clock": T}


def test_tree_layout_modes_and_config(tmp_path: Path) -> None:
    tree = netvm.build_netvm_tree(tmp_path / "tree", **_inputs(tmp_path))
    files = sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file())
    assert files == [
        "etc/hermetic/dns.json",
        "etc/hermetic/netvm.json",
        "sbin/hermetic-busybox",
        "sbin/hermetic-netvm",
    ]
    assert json.loads((tree / "etc/hermetic/netvm.json").read_text()) == {"t_clock": 1700000000}
    assert oct((tree / "sbin/hermetic-netvm").stat().st_mode & 0o777) == "0o755"
    assert oct((tree / "etc/hermetic/dns.json").stat().st_mode & 0o777) == "0o444"
    assert all(p.lstat().st_mtime == 1700000000 for p in tree.rglob("*"))
    assert not any(p.is_symlink() for p in tree.rglob("*"))


def test_symlinked_input_is_refused(tmp_path: Path) -> None:
    args = _inputs(tmp_path)
    os.symlink(tmp_path / "netvm", tmp_path / "link")
    args["netvm_bin"] = tmp_path / "link"
    with pytest.raises(OSError):
        netvm.build_netvm_tree(tmp_path / "tree", **args)
    assert not (tmp_path / "tree").exists()


@pytest.mark.parametrize("ip", ["10.0.2.15", "10.0.2.3", "192.168.1.1", "8.8.8.8"])
def test_table_address_outside_world_range_is_refused(tmp_path: Path, ip: str) -> None:
    table = {"records": [{"name": "x.example", "a": [ip], "aaaa": []}]}
    with pytest.raises(ValueError):
        netvm.build_netvm_tree(tmp_path / "tree", **_inputs(tmp_path, table))


def test_naive_or_out_of_range_clock_is_refused(tmp_path: Path) -> None:
    args = _inputs(tmp_path)
    args["t_clock"] = datetime(2023, 1, 1)
    with pytest.raises(ValueError):
        netvm.build_netvm_tree(tmp_path / "tree", **args)


def test_constants_match_rust_runtime() -> None:
    src = RUNTIME_RS.read_text()

    def const(name: str) -> str:
        m = re.search(rf'pub const {name}: &str = "([^"]*)";', src)
        assert m, name
        return m.group(1).encode().decode("unicode_escape")

    assert const("NETVM_ADDRESS") == netvm.NETVM_ADDRESS
    assert const("AGENT_CIDR") == netvm.AGENT_CIDR
    assert const("NETVM_PEER_ROUTE") == netvm.NETVM_PEER_ROUTE
    assert const("RESOLV_CONF") == netvm.RESOLV_CONF
    assert const("BUSYBOX") == "/sbin/hermetic-busybox"
    for cmd in netvm.AGENT_NETWORK_COMMANDS:
        literal = ", ".join(f'"{a}"' for a in cmd[1:])
        literal = literal.replace('"10.0.2.15/32"', "AGENT_CIDR").replace('"10.0.2.3"', "NETVM_ADDRESS").replace('"10.0.2.3/32"', "NETVM_PEER_ROUTE")
        assert literal in src, literal


def test_agent_routes_link_neighbours_and_public_addresses_through_filter() -> None:
    import ipaddress
    routes = []
    # Interpret the emitted commands as connected and explicit IPv4 routes.
    # The former /24 assigned a direct route for 10.0.2.2, bypassing NetVM.
    for cmd in netvm.AGENT_NETWORK_COMMANDS:
        if cmd[1:4] == ("ip", "addr", "add"):
            routes.append((ipaddress.ip_interface(cmd[4]).network, None))
        elif cmd[1:4] == ("ip", "route", "add"):
            prefix = "0.0.0.0/0" if cmd[4] == "default" else cmd[4]
            via = cmd[6] if cmd[5] == "via" else None
            if via is not None:
                # The gateway must already have a direct link route.
                assert any(ipaddress.ip_address(via) in net and hop is None for net, hop in routes)
            routes.append((ipaddress.ip_network(prefix), via))
    for addr in ("10.0.2.1", "10.0.2.2", "10.9.0.1", "169.254.169.254", "192.168.0.1", "1.1.1.1"):
        matching = [(net, via) for net, via in routes if ipaddress.ip_address(addr) in net]
        assert max(matching, key=lambda r: r[0].prefixlen)[1] == netvm.NETVM_ADDRESS


@pytest.mark.parametrize("bad", [
    {"records": [{"a": ["10.not-an-ip"]}]},
    {"records": [{"name": "Files.example", "a": ["10.9.0.1"]}]},
    {"records": [{"name": "x.example", "a": ["10.9.0.999"]}]},
    {"records": [{"name": "x.example", "a": ["10.9.0.1"], "aaaa": ["::1"]}]},
    {"records": [{"name": "x.example", "a": ["10.9.0.1"] * 2}]},
    {"records": [{"name": "x.example", "a": ["10.9.0.1"], "extra": 1}]},
    {"records": [{"name": "x.example", "a": []}] * 2},
    {"records": [{"name": "-x.example", "a": []}]},
    {"records": [{"name": "x.example", "a": [f"10.9.0.{i}" for i in range(16)]}]},
    {"records": [{"name": f"x{i}.example", "a": []} for i in range(4097)]},
])
def test_invalid_dns_is_rejected_before_tree_creation(tmp_path: Path, bad: object) -> None:
    with pytest.raises(ValueError):
        netvm.build_netvm_tree(tmp_path / "tree", **_inputs(tmp_path, bad))
    assert not (tmp_path / "tree").exists()


def test_dns_duplicate_fields_and_depth_are_refused() -> None:
    for raw in [b'{"records":[],"records":[]}', b'[' * 2000 + b']' * 2000, b' ' * (netvm.MAX_DNS_TABLE_BYTES + 1)]:
        with pytest.raises(ValueError):
            netvm.validate_dns_table(raw)


def test_dns_addresses_are_unique_and_sorted() -> None:
    table = {"records": [
        {"name": "b.example", "a": ["10.9.0.10", "10.9.0.2"]},
        {"name": "a.example", "a": ["10.9.0.2"]},
    ]}
    assert netvm.validate_dns_table(json.dumps(table).encode()) == ["10.9.0.2", "10.9.0.10"]


def test_fifo_input_is_rejected_without_open_for_io(tmp_path: Path, monkeypatch) -> None:
    args = _inputs(tmp_path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    args["netvm_bin"] = fifo
    real_open = os.open
    def checked_open(path, flags, *a, **kw):
        # Prevent the old blocking open from hanging the regression test.
        if os.fspath(path) == str(fifo) and not flags & os.O_PATH:
            pytest.fail("attempted FIFO I/O open")
        return real_open(path, flags, *a, **kw)
    monkeypatch.setattr(os, "open", checked_open)
    with pytest.raises(OSError):
        netvm.build_netvm_tree(tmp_path / "tree", **args)


def test_ancestor_symlinks_are_refused_for_inputs_and_outputs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    args = _inputs(source)
    link = tmp_path / "link"
    link.symlink_to(source, target_is_directory=True)
    with pytest.raises(OSError):
        netvm.build_netvm_tree(tmp_path / "tree", **{**args, "netvm_bin": link / "netvm"})
    with pytest.raises(OSError):
        netvm.build_netvm_tree(link / "tree", **args)
    assert not (source / "tree").exists()


def test_image_builder_preserves_existing_tree_on_invalid_input(tmp_path: Path) -> None:
    args = _inputs(tmp_path, {"records": [{"a": ["10.invalid"]}]})
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "keep").write_bytes(b"untouched")
    with pytest.raises(ValueError):
        netvm.build_netvm_image(tree, tmp_path / "out.img", world_id="test", **args)
    assert (tree / "keep").read_bytes() == b"untouched"


def test_tree_publication_is_atomic_and_refuses_concurrent_destination(tmp_path: Path, monkeypatch) -> None:
    args = _inputs(tmp_path)
    target = tmp_path / "tree"
    original = netvm._publish_tree
    def race(parent, staged, leaf):
        assert not target.exists()
        target.mkdir()
        original(parent, staged, leaf)
    monkeypatch.setattr(netvm, "_publish_tree", race)
    with pytest.raises(FileExistsError):
        netvm.build_netvm_tree(target, **args)
    assert list(target.iterdir()) == []
    assert not list(tmp_path.glob(".netvm-tree.*"))


def test_tree_build_stays_in_pinned_parent_during_exchange(tmp_path: Path, monkeypatch) -> None:
    args = _inputs(tmp_path)
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    moved = tmp_path / "moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    original = netvm.open_parent
    def exchange(path):
        result = original(path)
        parent.rename(moved)
        parent.symlink_to(outside, target_is_directory=True)
        return result
    monkeypatch.setattr(netvm, "open_parent", exchange)
    netvm.build_netvm_tree(parent / "tree", **args)
    assert (moved / "tree/sbin/hermetic-netvm").read_bytes() == b"\x7fELFnetvm"
    assert list(outside.iterdir()) == []


def test_smoke_boot_probe_fails_before_building_when_kvm_is_missing(tmp_path: Path) -> None:
    import subprocess
    if Path("/dev/kvm").exists():
        pytest.skip("this regression exercises the missing-KVM path")
    target = tmp_path / "unused"
    result = subprocess.run(
        [str(ROOT / "scripts/integration/net-smoke.sh"), str(target)],
        cwd=ROOT, capture_output=True, timeout=10,
    )
    assert result.returncode != 0
    assert b"OPEN: cannot open /dev/kvm or /dev/net/tun" in result.stderr
    assert not target.exists()


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-8-sig"])
def test_dns_encoding_must_match_rust_utf8(tmp_path: Path, encoding: str) -> None:
    args = _inputs(tmp_path)
    args["dns_table"].write_bytes(json.dumps(TABLE).encode(encoding))
    with pytest.raises(ValueError):
        netvm.build_netvm_tree(tmp_path / "tree", **args)
    assert not (tmp_path / "tree").exists()


@pytest.mark.parametrize("exit_code", [0, 17])
def test_smoke_preserves_and_prints_test_diagnostics(tmp_path: Path, exit_code: int) -> None:
    import subprocess
    # Run the script's actual test invocation with an offline cargo stand-in;
    # image building and VM boot are deliberately outside this regression.
    script = (ROOT / "scripts/integration/net-smoke.sh").read_text()
    tail = script[script.index("# 5. Boot both VMs"):]
    setup = '''
set -euo pipefail
WORK=$1
fixture_exit=$2
FC=unused KERNEL=unused
cargo() {
  printf 'AgentVM serial: fixture\\nNetVM serial: netvm_ready\\n' >&2
  printf 'ip addr; ip route; ip neigh; /etc/resolv.conf\\n' >&2
  return "$fixture_exit"
}
'''
    run = subprocess.run(["bash", "-c", setup + tail, "smoke", str(tmp_path), str(exit_code)],
                         capture_output=True, timeout=10)
    assert run.returncode == exit_code
    log = tmp_path / "net-smoke-test.log"
    assert log.is_file()
    assert log.stat().st_mode & 0o777 == 0o600
    saved = log.read_bytes()
    assert b"AgentVM serial" in saved and b"NetVM serial: netvm_ready" in saved
    assert b"ip addr; ip route; ip neigh; /etc/resolv.conf" in saved
    printed = run.stderr if exit_code else run.stdout
    assert saved in printed
