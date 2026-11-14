"""NetVM rootfs tree and image (first cut) plus the AgentVM network constants.

The NetVM image holds the static ``hermetic-netvm`` binary as ``/sbin/hermetic-netvm``
(booted with ``init=/sbin/hermetic-netvm``), a static busybox used only for the fixed
boot commands (``ip``, ``sysctl``, ``mount``, ``poweroff``), the world DNS table and a
tiny runtime config. Every NetVM boot step and every address below must match
``crates/hermetic-netvm-core/src/runtime.rs``; a test checks that.

dm-verity is not applied yet (open in PHASES.md): the image is a D4-checked,
read-only ext4 built by :func:`hermetic_slice.rootfs.build_rootfs`.
"""

from __future__ import annotations

import json
import os
import ctypes
import errno
import ipaddress
import hashlib
import re
import shutil
import stat
from datetime import datetime
from pathlib import Path

from hermetic_safe_io import open_parent, open_regular, UnsafePathError
from hermetic_slice.guest_kernel import DEFAULT_KERNEL_DIR
from hermetic_slice.substrate import substrate_files

NETVM_ADDRESS = "10.0.2.3"
AGENT_ADDRESS = "10.0.2.15"
AGENT_CIDR = "10.0.2.15/32"
NETVM_PEER_ROUTE = "10.0.2.3/32"
LINK_PREFIX = "10.0.2."
RESOLV_CONF = "nameserver 10.0.2.3\noptions ndots:0\n"
NETVM_INIT = "/sbin/hermetic-netvm"
MAX_DNS_TABLE_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
MIN_CLOCK = 315532800
MAX_CLOCK = 4102444799

# Run through execd (as root, before the agent starts), in order.
AGENT_NETWORK_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("/bin/busybox", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"),
    ("/bin/busybox", "ip", "link", "set", "lo", "up"),
    ("/bin/busybox", "ip", "addr", "add", AGENT_CIDR, "dev", "eth0"),
    ("/bin/busybox", "ip", "link", "set", "eth0", "up"),
    ("/bin/busybox", "ip", "route", "add", NETVM_PEER_ROUTE, "dev", "eth0"),
    ("/bin/busybox", "ip", "route", "add", "default", "via", NETVM_ADDRESS, "dev", "eth0"),
)

_TREE_DIRS = ("sbin", "dev", "proc", "etc", "etc/hermetic")


def _read_regular(path: Path, cap: int, what: str) -> bytes:
    """Read a regular, non-symlink file of at most ``cap`` bytes."""
    fd = open_regular(path, cap)
    with os.fdopen(fd, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{what} exceeds byte cap")
    return data


MAX_TABLE_RECORDS = 4096
MAX_A_RECORDS_PER_NAME = 15
MAX_DNS_NAME_BYTES = 253
MAX_DNS_LABELS = 127
MAX_TEMP_ATTEMPTS = 64


def _unique_object(pairs: list[tuple]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate DNS field")
        out[key] = value
    return out


def validate_dns_table(data: bytes) -> list[str]:
    """Match the Rust DNS manifest contract, including NetVM link exclusions."""
    if len(data) > MAX_DNS_TABLE_BYTES:
        raise ValueError("dns table exceeds byte cap")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (RecursionError, UnicodeError, ValueError) as exc:
        raise ValueError("invalid dns table") from exc
    if not isinstance(doc, dict) or set(doc) != {"records"} or not isinstance(doc["records"], list):
        raise ValueError("invalid dns table")
    if len(doc["records"]) > MAX_TABLE_RECORDS:
        raise ValueError("too many dns records")
    names: set[str] = set()
    addresses: set[ipaddress.IPv4Address] = set()
    for rec in doc["records"]:
        if not isinstance(rec, dict) or set(rec) not in ({"name", "a"}, {"name", "a", "aaaa"}):
            raise ValueError("invalid dns record")
        name = rec["name"]
        if not isinstance(name, str) or not 1 <= len(name) <= MAX_DNS_NAME_BYTES:
            raise ValueError("invalid dns name")
        labels = name.split(".")
        if len(labels) > MAX_DNS_LABELS or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
        ) or name in names:
            raise ValueError("invalid or duplicate dns name")
        names.add(name)
        if not isinstance(rec["a"], list) or len(rec["a"]) > MAX_A_RECORDS_PER_NAME or rec.get("aaaa", []) != []:
            raise ValueError("invalid dns addresses")
        seen: set[ipaddress.IPv4Address] = set()
        for value in rec["a"]:
            if not isinstance(value, str):
                raise ValueError("invalid world address")
            try:
                ip = ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                raise ValueError("invalid world address") from None
            if ip not in ipaddress.IPv4Network("10.0.0.0/8") or ip in ipaddress.IPv4Network("10.0.2.0/24") or ip in seen:
                raise ValueError("invalid or duplicate world address")
            seen.add(ip)
            addresses.add(ip)
    return [str(ip) for ip in sorted(addresses)]


def _publish_tree(parent: int, staged: str, leaf: str) -> None:
    # Linux renameat2(RENAME_NOREPLACE) publishes a complete tree atomically and
    # refuses an existing destination, including an empty directory or symlink.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(staged), parent, os.fsencode(leaf), 1) != 0:
        raise OSError(ctypes.get_errno(), "cannot publish netvm tree")
    os.fsync(parent)


def build_netvm_tree(
    tree: Path,
    *,
    netvm_bin: Path,
    busybox_bin: Path,
    dns_table: Path,
    t_clock: datetime,
    tls_identity: dict | None = None,
    kernel_lock: Path = DEFAULT_KERNEL_DIR / "kernel.lock.json",
    kernel_image: Path | None = None,
    clockprobe_bin: Path | None = None,
) -> Path:
    """Create a fresh NetVM rootfs tree at ``tree`` (which must not exist)."""
    if t_clock.tzinfo is None or t_clock.utcoffset() is None:
        raise ValueError("t_clock must be timezone-aware and in range")
    epoch = int(t_clock.timestamp())
    if not MIN_CLOCK <= epoch <= MAX_CLOCK:
        raise ValueError("t_clock must be timezone-aware and in range")
    netvm = _read_regular(netvm_bin, MAX_BINARY_BYTES, "netvm binary")
    busybox = _read_regular(busybox_bin, MAX_BINARY_BYTES, "busybox binary")
    table = _read_regular(dns_table, MAX_DNS_TABLE_BYTES, "dns table")
    validate_dns_table(table)
    config: dict = {"t_clock": epoch}
    if tls_identity is not None:
        if (not isinstance(tls_identity, dict)
            or set(tls_identity) != {"world_id", "dns_sha256", "ca_sha256", "material_sha256"}
            or not isinstance(tls_identity["world_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,256}", tls_identity["world_id"])
            or any(not isinstance(tls_identity[key], str) or not re.fullmatch(r"[a-f0-9]{64}", tls_identity[key])
                   for key in ("dns_sha256", "ca_sha256", "material_sha256"))
            or tls_identity["dns_sha256"] != hashlib.sha256(table).hexdigest()):
            raise ValueError("invalid TLS identity")
        config["tls"] = dict(tls_identity)
    files = {
        "sbin/hermetic-netvm": (netvm, 0o755),
        "sbin/hermetic-busybox": (busybox, 0o755),
        "etc/hermetic/dns.json": (table, 0o444),
        "etc/hermetic/netvm.json": (json.dumps(config, sort_keys=True).encode(), 0o444),
    }
    files.update({name: (data, 0o644) for name, data in substrate_files(
        kernel_lock, kernel_image=kernel_image, clockprobe_bin=clockprobe_bin).items()})
    parent, leaf = open_parent(tree)
    staged = None
    directory = None
    try:
        # Refuse before creating even temporary files. Publication also checks
        # atomically, so a concurrent creator cannot be overwritten.
        try:
            os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("netvm tree already exists")
        if os.fstat(parent).st_mode & 0o022:
            raise UnsafePathError("netvm output parent must not be writable by other users")
        for attempt in range(MAX_TEMP_ATTEMPTS):
            candidate = f".netvm-tree.{attempt}"
            if candidate == leaf:
                continue
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            staged = candidate
            break
        if staged is None:
            raise OSError(errno.EEXIST, "netvm temporary attempts exhausted")
        directory = os.open(staged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        anchor = Path(f"/proc/self/fd/{directory}")
        # Only this fresh private directory is traversed. chmod and timestamps
        # use open descriptors, never a caller-controlled pathname.
        for rel in _TREE_DIRS:
            os.mkdir(anchor / rel, 0o700)
        for rel, (data, mode) in files.items():
            fd = os.open(anchor / rel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fchmod(f.fileno(), mode)
                os.utime(f.fileno(), (epoch, epoch))
                os.fsync(f.fileno())
        for rel in reversed(_TREE_DIRS):
            fd = os.open(anchor / rel, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fchmod(fd, 0o755)
                os.utime(fd, (epoch, epoch))
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fchmod(directory, 0o755)
        os.utime(directory, (epoch, epoch))
        os.fsync(directory)
        _publish_tree(parent, staged, leaf)
        staged = None
    finally:
        if directory is not None:
            os.close(directory)
        if staged is not None:
            shutil.rmtree(Path(f"/proc/self/fd/{parent}") / staged)
        os.close(parent)
    return tree


def build_netvm_image(
    tree: Path,
    out_image: Path,
    *,
    netvm_bin: Path,
    busybox_bin: Path,
    dns_table: Path,
    t_clock: datetime,
    world_id: str,
    sealcheck_bin: Path | None = None,
    work_dir: Path | None = None,
    tls_identity: dict | None = None,
    kernel_lock: Path = DEFAULT_KERNEL_DIR / "kernel.lock.json",
    kernel_image: Path | None = None,
    clockprobe_bin: Path | None = None,
) -> dict:
    """Build the NetVM tree and a D4-checked read-only ext4 image from it."""
    from hermetic_slice.rootfs import build_rootfs

    if tls_identity is None:
        raise ValueError("TLS identity is required for the NetVM image")
    if not isinstance(tls_identity, dict) or tls_identity.get("world_id") != world_id:
        raise ValueError("TLS identity world does not match image world")
    build_netvm_tree(tree, netvm_bin=netvm_bin, busybox_bin=busybox_bin, dns_table=dns_table, t_clock=t_clock, tls_identity=tls_identity,
                     kernel_lock=kernel_lock, kernel_image=kernel_image, clockprobe_bin=clockprobe_bin)
    return build_rootfs(
        tree, out_image, t_clock=t_clock, world_id=world_id, sealcheck_bin=sealcheck_bin, work_dir=work_dir,
        kernel_lock=kernel_lock, kernel_image=kernel_image, clockprobe_bin=clockprobe_bin,
    )
