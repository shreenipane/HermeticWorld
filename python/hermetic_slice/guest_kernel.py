"""Offline guest-kernel policy, pinned container builds and artifact verification."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_LOCK_BYTES = 16384
MAX_PATH_BYTES = 4096
MAX_PATH_DEPTH = 128
MAX_SYMLINK_HOPS = 40
MAX_BOOT_BYTES = 2048
MAX_CLOCK = 253402300799  # Last second of year 9999; shared decimal Unix-seconds contract.
MAX_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_BANNER_BYTES = 1024
MAX_TARBALL_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024**3
MAX_SOURCE_ENTRIES = 150000
MAX_XZ_MEMORY_BYTES = 128 * 1024 * 1024
MAX_TAR_METADATA_BYTES = 16384
MAX_UNPACKED_BYTES = 5 * 1024**3
MAX_BUILD_FILE_BYTES = 2 * 1024**3
CLEANUP_TIMEOUT_S = 30
BUILD_TIMEOUT_S = 7200
CHUNK_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_IMAGE_ID_BYTES = 72
STDERR_LOG = "kernel-build.stderr.log"
PLACEHOLDER = "TO-BE-FILLED-BY-OWNER"
APPROVED_BUILDER_DIGEST = "29ad57ab16edc3ddcb8b44de77061336a4cabc6812243bedac48e815529da238"
APPROVED_BUILDER_IMAGE = "hermetic/kernel-builder:6.6-v1@sha256:" + APPROVED_BUILDER_DIGEST
DEFAULT_KERNEL_DIR = Path(__file__).absolute().parent.parent.parent / "images" / "kernel"


class KernelError(ValueError):
    """Invalid or unsafe input; messages never contain input text or tool output."""


@dataclass(frozen=True)
class Finding:
    option: str
    message: str


@dataclass(frozen=True)
class Rule:
    value: str
    requirement: str


# One policy drives the checker, config fragments and README requirement table.
RULES: dict[str, Rule] = {}
for _purpose, _names in (
    ("Phase 3b: deny guest root access to kernel code and memory", "SECURITY SECURITYFS SECURITY_LOCKDOWN_LSM SECURITY_LOCKDOWN_LSM_EARLY LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY BPF_UNPRIV_DEFAULT_OFF"),
    ("TR-VMM-4: x86 microVM boot", "64BIT X86_64 SMP HYPERVISOR_GUEST PCI BLOCK BLK_DEV NET NETDEVICES INET UNIX PROC_FS SYSFS TMPFS MULTIUSER TTY SERIAL_8250 SERIAL_8250_CONSOLE PRINTK ELF_CORE BINFMT_ELF BINFMT_SCRIPT UNIX98_PTYS DEVTMPFS FHANDLE"),
    ("execd boot contract: the kernel mounts devtmpfs at /dev before PID 1", "DEVTMPFS_MOUNT"),
    ("execd: PID 1 reaps orphans via /proc/<pid>/task/<tid>/children", "PROC_CHILDREN"),
    ("TR-EXD-6: trusted initramfs support (uncompressed or gzip only)", "BLK_DEV_INITRD RD_GZIP"),
    ("TR-VMM-4: cgroup v2 controllers and device BPF", "CGROUPS CGROUP_SCHED FAIR_GROUP_SCHED CFS_BANDWIDTH MEMCG CGROUP_PIDS BLK_CGROUP BLK_DEV_THROTTLING IOSCHED_BFQ BFQ_GROUP_IOSCHED CGROUP_WRITEBACK CPUSETS CGROUP_BPF BPF BPF_SYSCALL"),
    ("TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES)", "NAMESPACES USER_NS PID_NS NET_NS UTS_NS IPC_NS SYSVIPC POSIX_MQUEUE"),
    ("TR-VMM-4: root filesystems", "OVERLAY_FS EXT4_FS FS_POSIX_ACL EXT4_FS_POSIX_ACL"),
    ("TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack", "NETFILTER NETFILTER_ADVANCED NETFILTER_XTABLES NF_CONNTRACK NF_NAT NF_TABLES NF_TABLES_INET NFT_CT NFT_NAT NFT_TPROXY NFT_SOCKET NETFILTER_XT_MATCH_CONNTRACK NETFILTER_XT_MATCH_SOCKET NETFILTER_XT_TARGET_TPROXY NETFILTER_XT_TARGET_REDIRECT NETFILTER_XT_TARGET_MASQUERADE IP_NF_IPTABLES IP_NF_FILTER IP_NF_MANGLE IP_NF_NAT IP6_NF_IPTABLES IP6_NF_FILTER IP6_NF_MANGLE IPV6 NF_TPROXY_IPV4 NF_TPROXY_IPV6 NF_SOCKET_IPV4 NF_SOCKET_IPV6"),
    ("TR-VMM-5: virtio devices, vsock and entropy", "VIRTIO VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES VIRTIO_BLK VIRTIO_NET VIRTIO_CONSOLE HW_RANDOM HW_RANDOM_VIRTIO VSOCKETS VIRTIO_VSOCKETS"),
    ("TR-VMM-4: dm-verity and seccomp", "MD BLK_DEV_DM DM_VERITY CRYPTO CRYPTO_SHA256 SECCOMP SECCOMP_FILTER"),
):
    for _name in _names.split():
        RULES["CONFIG_" + _name] = Rule("y", _purpose)
for _purpose, _names in (
    ("Phase 3b: deny guest root access to kernel code and memory", "MODULES DEVMEM DEVKMEM KEXEC KEXEC_FILE KEXEC_CORE X86_MSR X86_CPUID PROC_KCORE HIBERNATION X86_IOPL_IOPERM BPF_KPROBE_OVERRIDE KPROBES KPROBE_EVENTS UPROBE_EVENTS BPF_EVENTS ACPI_CUSTOM_METHOD ACPI_TABLE_UPGRADE PARAVIRT KVM_GUEST PARAVIRT_CLOCK HERMETIC_CLOCK_CANARY"),
    ("TR-VMM-4: prevent accidental host clock reads", "PTP_1588_CLOCK PTP_1588_CLOCK_KVM PTP_1588_CLOCK_VMW RTC_HCTOSYS"),
    ("TR-VMM-4: fixed build identity; config supplied separately", "LOCALVERSION_AUTO IKCONFIG"),
    ("T3.1: no time namespace needed", "TIME_NS"),
    ("TR-EXD-6: no initramfs decompressor other than gzip", "RD_BZIP2 RD_LZMA RD_XZ RD_LZO RD_LZ4 RD_ZSTD"),
):
    for _name in _names.split():
        RULES["CONFIG_" + _name] = Rule("n", _purpose)
RULES["CONFIG_LOCALVERSION"] = Rule('""', "TR-VMM-4: no local version or host suffix")
RULES["CONFIG_BUILD_SALT"] = Rule('""', "TR-VMM-4: no random build salt")
RULES["CONFIG_DEFAULT_HOSTNAME"] = Rule('"hermetic"', "TR-VMM-4: fixed default guest hostname")
RULES["CONFIG_INITRAMFS_SOURCE"] = Rule('""', "TR-EXD-6: no initramfs built into the kernel image")
RULES["CONFIG_DEBUG_INFO"] = Rule("n", "TR-VMM-4: no compiler paths or debug metadata")
RULES = dict(sorted(RULES.items()))


def documentation_table() -> str:
    lines = ["| Option | Required value | Requirement |", "| --- | --- | --- |"]
    lines.extend(f"| `{name}` | `{rule.value}` | {rule.requirement} |" for name, rule in RULES.items())
    return "\n".join(lines)


def _text(raw: str | bytes, cap: int) -> str:
    try:
        if isinstance(raw, bytes):
            if len(raw) > cap:
                raise KernelError("input exceeds byte cap")
            raw = raw.decode("utf-8", errors="strict")
        if not isinstance(raw, str) or len(raw) > cap or len(raw.encode("utf-8")) > cap:
            raise KernelError("input exceeds byte cap")
    except UnicodeError:
        raise KernelError("input is not UTF-8") from None
    if "\0" in raw:
        raise KernelError("input contains NUL")
    return raw


def parse_config(config_text: str | bytes) -> dict[str, str]:
    text = _text(config_text, MAX_CONFIG_BYTES)
    result: dict[str, str] = {}
    for line in text.split("\n"):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise KernelError("config line exceeds byte cap")
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in line):
            raise KernelError("config must contain printable ASCII lines")
        if not line or line.startswith("#"):
            match = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_]+) is not set", line)
            if match:
                name, value = match.group(1), "n"
            elif line.startswith("# CONFIG_"):
                raise KernelError("invalid config disable line")
            else:
                continue
        else:
            match = re.fullmatch(r'(CONFIG_[A-Za-z0-9_]+)=(y|m|n|-?[0-9]+|0x[0-9a-fA-F]+|"(?:[^"\\\x00-\x1f]|\\["\\])*")', line)
            if not match:
                raise KernelError("invalid config assignment")
            name, value = match.groups()
        if name in result:
            raise KernelError("duplicate config option")
        result[name] = value
    return result


def check_config(config_text: str | bytes) -> list[Finding]:
    values = parse_config(config_text)
    findings = []
    versions = re.findall(r"^# Linux/[^ \n]+ ([0-9]{1,3})\.([0-9]{1,3})(?:\.[0-9]{1,4})? Kernel Configuration$",
                          _text(config_text, MAX_CONFIG_BYTES), re.MULTILINE)
    if len(versions) != 1 or tuple(map(int, versions[0])) < (5, 10):
        findings.append(Finding("kernel.version", "config must identify Linux 5.10 or newer"))
    for name, rule in RULES.items():
        value = values.get(name)
        # Unavailable disabled symbols can be omitted by olddefconfig.
        if rule.value == "n":
            if value in ("y", "m"):
                findings.append(Finding(name, "forbidden option is enabled"))
            elif value not in (None, "n"):
                findings.append(Finding(name, "expected disabled option"))
        elif value != rule.value:
            findings.append(Finding(name, "required option missing" if value is None else "required option has wrong value"))
    return findings


BOOT_FIXED = "console=ttyS0,115200n8 reboot=k panic=-1 pci=off root=/dev/vda rootfstype=ext4 ro init=/sbin/hermetic-init clocksource=tsc tsc=reliable no-kvmclock"


def spec_boot_arguments(t_clock: int) -> str:
    """VmSpec input; lifecycle appends the VMM-owned TSC frequency before boot."""
    if type(t_clock) is not int or not 0 <= t_clock <= MAX_CLOCK:
        raise KernelError("t_clock must be bounded integral Unix seconds")
    return f"{BOOT_FIXED} hermetic.t={t_clock}"


TSC_RESOLVE_TIMEOUT_S = 5
TSC_KHZ_MIN = 100_000
TSC_KHZ_MAX = 10_000_000


def boot_arguments(t_clock: int, *, vmm: Path) -> str:
    """Executable arguments for direct launch, resolved by the same VMM as lifecycle.

    The lock and spec_boot_arguments contain only spec input, never host frequency.
    """
    base = spec_boot_arguments(t_clock)  # Validate before opening the executable.
    try:
        with regular(vmm, MAX_IMAGE_BYTES) as fd:
            if not os.fstat(fd).st_mode & 0o111:
                raise KernelError("VMM resolver must be executable")
            process = subprocess.Popen([f"/proc/self/fd/{fd}", "boot-args", base],
                                       pass_fds=(fd,), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            try:
                try:
                    complete = False
                    output = bytearray()
                    deadline = time.monotonic() + TSC_RESOLVE_TIMEOUT_S
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        while True:
                            left = deadline - time.monotonic()
                            if left <= 0 or not selector.select(left):
                                raise KernelError("VMM resolver timed out")
                            chunk = os.read(process.stdout.fileno(), MAX_BOOT_BYTES + 1 - len(output))
                            if not chunk:
                                break
                            output.extend(chunk)
                            if len(output) > MAX_BOOT_BYTES:
                                raise KernelError("VMM resolver output exceeds cap")
                    if process.wait(timeout=max(0, deadline - time.monotonic())) != 0:
                        raise KernelError("VMM frequency resolution failed")
                    complete = True
                finally:
                    # Kill the whole resolver group on errors, including pipe-holding children.
                    if not complete:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=TSC_RESOLVE_TIMEOUT_S)
            finally:
                # Popen.__exit__ can wait forever after bounded reaping fails.
                if process.stdout is not None:
                    process.stdout.close()
    except (OSError, subprocess.TimeoutExpired):
        raise KernelError("VMM frequency resolution failed") from None
    text = _text(bytes(output), MAX_BOOT_BYTES)
    # The VMM confirms the fixed 2 GHz guest rate and returns the arguments
    # unchanged: the frequency reaches the guest only through CPUID leaf 0x15.
    if text != base + "\n":
        raise KernelError("invalid VMM boot arguments")
    return text[:-1]


def check_boot_arguments(arguments: str) -> list[Finding]:
    text = _text(arguments, MAX_BOOT_BYTES)
    tokens = text.split(" ")
    findings = []
    seen: set[str] = set()
    for token in tokens:
        key = token.partition("=")[0]
        if key in seen:
            findings.append(Finding("boot", "duplicate boot argument"))
        seen.add(key)
        if token.startswith("hermetic.t="):
            value = token.removeprefix("hermetic.t=")
            if not re.fullmatch(r"0|[1-9][0-9]{0,11}", value) or int(value) > MAX_CLOCK:
                findings.append(Finding("hermetic.t", "invalid clock value"))
        elif key.replace("-", "_") == "tsc_early_khz":
            # It would bypass the pinned CPUID leaf 0x15 frequency.
            findings.append(Finding("tsc_early_khz", "TSC frequency must not be a boot argument"))
        elif token not in BOOT_FIXED.split(" "):
            findings.append(Finding("boot", "unapproved boot argument"))
    for required in BOOT_FIXED.split(" "):
        if required not in tokens:
            findings.append(Finding(required.partition("=")[0], "required boot argument missing"))
    if "hermetic.t" not in seen:
        findings.append(Finding("hermetic.t", "required boot argument missing"))
    return sorted(findings, key=lambda f: (f.option, f.message))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise KernelError("duplicate lock field")
        result[key] = value
    return result


def validate_lock(lock: dict, *, for_build: bool = False) -> dict:
    fields = {"version", "source_url", "sha256", "release_date", "build_user", "build_host", "builder_image", "boot_args"}
    if not isinstance(lock, dict) or set(lock) != fields or any(not isinstance(v, str) or len(v) > MAX_BOOT_BYTES for v in lock.values()):
        raise KernelError("invalid lock fields")
    for field in sorted(fields):
        if for_build and PLACEHOLDER in lock[field]:
            raise KernelError(f"lock placeholder: {field}")
    if not re.fullmatch(r"6\.6\.[0-9]{1,4}", lock["version"]):
        raise KernelError("invalid lock field: version (requires 6.6.x)")
    if lock["source_url"] != f'https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-{lock["version"]}.tar.xz':
        raise KernelError("invalid lock field: source_url")
    if lock["sha256"] != PLACEHOLDER and not re.fullmatch(r"[0-9a-f]{64}", lock["sha256"]):
        raise KernelError("invalid lock field: sha256")
    if lock["builder_image"] not in (APPROVED_BUILDER_IMAGE, "sha256:" + APPROVED_BUILDER_DIGEST):
        raise KernelError("invalid lock field: builder_image")
    for field in ("build_user", "build_host"):
        if lock[field] != "hermetic":
            raise KernelError(f"invalid lock field: {field}")
    if lock["release_date"] != PLACEHOLDER:
        release_datetime(lock)
    if lock["boot_args"] != BOOT_FIXED + " hermetic.t={t_clock}":
        raise KernelError("invalid lock field: boot_args")
    return dict(lock)


def release_datetime(lock: dict) -> datetime:
    value = lock.get("release_date", "")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise KernelError("invalid lock field: release_date")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.year < 2022:
            raise ValueError
        return date
    except ValueError:
        raise KernelError("invalid lock field: release_date") from None


@contextmanager
def directory(path: Path, *, create: bool = False, trusted: bool = False):
    """Walk without symlinks, retaining an anchor for subsequent descriptor operations."""
    raw = os.fspath(path)
    if len(os.fsencode(raw)) > MAX_PATH_BYTES or ".." in raw.split("/") or "\0" in raw:
        raise KernelError("invalid path")
    parts = Path(os.path.abspath(raw)).parts[1:]
    if len(parts) > MAX_PATH_DEPTH:
        raise KernelError("path exceeds depth cap")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise KernelError("directory must not contain symlinks")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            opened = os.fstat(child)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(child)
                raise KernelError("directory changed")
            if trusted and (opened.st_uid not in (0, os.geteuid())
                            or (opened.st_mode & 0o022
                                and not (opened.st_uid == 0 and opened.st_mode & stat.S_ISVTX))):
                os.close(child)
                raise KernelError("untrusted output ancestor")
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _regular_at(parent: int, name: str, cap: int):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise KernelError("input must be a regular file")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise KernelError("input changed while opening")
        if opened.st_size > cap:
            raise KernelError("file exceeds byte cap")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def regular(path: Path, cap: int):
    path = Path(path)
    with directory(path.parent) as parent, _regular_at(parent, path.name, cap) as fd:
        yield fd


def _read_bytes(fd: int, cap: int) -> bytes:
    result = bytearray()
    while len(result) <= cap:
        chunk = os.read(fd, min(CHUNK_BYTES, cap + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
    raise KernelError("file exceeds byte cap")


def read_file(path: Path, cap: int) -> bytes:
    with regular(path, cap) as fd:
        return _read_bytes(fd, cap)


def load_lock(path: Path, *, for_build: bool = False) -> dict:
    try:
        value = json.loads(_text(read_file(path, MAX_LOCK_BYTES), MAX_LOCK_BYTES), object_pairs_hook=_pairs)
    except (ValueError, RecursionError):
        raise KernelError("invalid lock JSON") from None
    return validate_lock(value, for_build=for_build)


def hash_file(path: Path, cap: int = MAX_IMAGE_BYTES) -> str:
    with regular(path, cap) as fd:
        digest = hashlib.sha256()
        total = 0
        while total <= cap:
            chunk = os.read(fd, min(CHUNK_BYTES, cap + 1 - total))
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
            total += len(chunk)
        raise KernelError("file exceeds byte cap")


def _banner_date(lock: dict) -> str:
    date = release_datetime(lock)
    # Explicit English names; strftime's weekday and month depend on ambient locale.
    days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return f"{days[date.weekday()]} {months[date.month - 1]} {date.day:02d} {date.hour:02d}:{date.minute:02d}:{date.second:02d} UTC {date.year}"


MAX_BANNER_COPIES = 8


def verify_vmlinux(path: Path, lock: dict) -> list[Finding]:
    validate_lock(lock, for_build=True)
    banners: list[bytes] = []
    with regular(path, MAX_IMAGE_BYTES) as fd:
        tail = b""
        total = 0
        while total <= MAX_IMAGE_BYTES:
            chunk = os.read(fd, min(CHUNK_BYTES, MAX_IMAGE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            data = tail + chunk
            while b"Linux version " in data:
                start = data.find(b"Linux version ")
                end = re.search(b"[\x00\n]", data[start:])
                if end is None:
                    if len(data) - start > MAX_BANNER_BYTES:
                        return [Finding("banner", "banner exceeds byte cap")]
                    data = data[start:]
                    break
                banner = data[start:start + end.start()]
                # A real vmlinux carries identical copies of linux_banner; differing copies are ambiguous.
                if len(banner) > MAX_BANNER_BYTES or (banners and banner != banners[0]):
                    return [Finding("banner", "ambiguous or oversized banner")]
                if len(banners) >= MAX_BANNER_COPIES:
                    return [Finding("banner", "too many banner copies")]
                banners.append(banner)
                data = data[start + end.end():]
            tail = data[-MAX_BANNER_BYTES:]
        if total > MAX_IMAGE_BYTES:
            raise KernelError("image exceeds byte cap")
    if b"Linux version " in tail:
        return [Finding("banner", "Linux version banner is unterminated")]
    if not banners:
        return [Finding("banner", "Linux version banner missing or unterminated")]
    banner = banners[0].decode("ascii", errors="replace")
    expected = f'Linux version {lock["version"]} ({lock["build_user"]}@{lock["build_host"]}) '
    findings = []
    if not banner.startswith(expected):
        findings.append(Finding("banner.identity", "version or build identity differs from lock"))
    if not banner.endswith(" " + _banner_date(lock)):
        findings.append(Finding("banner.date", "build date differs from lock release date"))
    return findings


def docker_arguments(lock: dict, input_dir: Path, output_dir: Path, *, uid: int = 1000, gid: int = 1000, name: str = "hermetic-kernel-build") -> list[str]:
    """Pure argv builder. Mount paths must refer to held, private staging directories."""
    validate_lock(lock, for_build=True)
    for path in (input_dir, output_dir):
        value = str(path)
        if not path.is_absolute() or len(value) > MAX_PATH_BYTES or re.search(r"[,\x00-\x1f]", value) or ".." in path.parts:
            raise KernelError("invalid container mount path")
    if any(type(n) is not int or not 1 <= n <= 2**31 - 1 for n in (uid, gid)):
        raise KernelError("container transport user must be non-root")
    if not re.fullmatch(r"hermetic-kernel-[a-z0-9-]{1,64}", name):
        raise KernelError("invalid container name")
    return [
        "/usr/bin/docker", "--config", str(input_dir / "docker-config"), "run", "--rm", "--name", name, "--pull=never", "--network=none",
        "--hostname=hermetic", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=512", "--memory=4g", "--cpus=2", "--user", f"{uid}:{gid}",
        "--mount", f"type=bind,src={input_dir},dst=/inputs,readonly",
        "--mount", f"type=bind,src={output_dir},dst=/output",
        "--tmpfs", "/build:rw,exec,nosuid,nodev,size=8g,mode=1777",
        "--workdir=/build", "--entrypoint=/bin/bash", "sha256:" + APPROVED_BUILDER_DIGEST, "/inputs/build.sh",
    ]


def _wait_with_tail(process, tail: bytearray) -> int:
    """Drain a pipe without buffering its full contents or waiting past the deadline."""
    deadline = time.monotonic() + BUILD_TIMEOUT_S
    with selectors.DefaultSelector() as poll:
        poll.register(process.stderr, selectors.EVENT_READ)
        while poll.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("kernel build", BUILD_TIMEOUT_S)
            for key, _events in poll.select(remaining):
                chunk = os.read(key.fd, MAX_STDERR_BYTES)
                if not chunk:
                    poll.unregister(key.fileobj)
                else:
                    tail.extend(chunk)
                    del tail[:-MAX_STDERR_BYTES]
        return process.wait(timeout=max(0, deadline - time.monotonic()))


def _run(argv: list[str], *, env: dict[str, str], cwd: Path | None = None,
         stderr_parent: int | None = None) -> None:
    tail = bytearray()
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE if stderr_parent is not None else None,
                              env=env, cwd=cwd, start_new_session=True) as process:
            try:
                status = (_wait_with_tail(process, tail) if stderr_parent is not None
                          else process.wait(timeout=BUILD_TIMEOUT_S))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                raise KernelError("kernel build subprocess timed out") from None
    except OSError:
        raise KernelError("kernel build subprocess unavailable") from None
    finally:
        if stderr_parent is not None:
            _atomic_bytes(stderr_parent, STDERR_LOG, bytes(tail))
    if status:
        raise KernelError("kernel build subprocess failed")


def _atomic_copy(source: Path, parent: int, name: str, cap: int) -> None:
    """Copy from a held regular inode, fsync and rename inside the held destination."""
    temp = ".kernel-" + os.urandom(16).hex()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        with regular(source, cap) as src:
            total = 0
            while total <= cap:
                chunk = os.read(src, min(CHUNK_BYTES, cap + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    raise KernelError("file exceeds byte cap")
                view = memoryview(chunk)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise KernelError("short output write")
                    view = view[written:]
        os.fsync(fd)
        os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(fd)
        try:
            os.unlink(temp, dir_fd=parent)
        except FileNotFoundError:
            pass


def _atomic_bytes(parent: int, name: str, raw: bytes) -> None:
    temp = ".record-" + os.urandom(16).hex()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise KernelError("short record write")
            view = view[written:]
        os.fsync(fd)
        os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(fd)
        try:
            os.unlink(temp, dir_fd=parent)
        except FileNotFoundError:
            pass


def _json_bytes(value: dict) -> bytes:
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")
    if len(raw) > MAX_LOCK_BYTES:
        raise KernelError("record exceeds byte cap")
    return raw


def _write_json(path: Path, value: dict) -> None:
    raw = _json_bytes(value)
    with directory(path.parent) as parent:
        _atomic_bytes(parent, path.name, raw)


ARTIFACTS = {"vmlinux": MAX_IMAGE_BYTES, ".config": MAX_CONFIG_BYTES, "build-record.json": MAX_LOCK_BYTES}


def _build_inputs(kernel_dir: Path) -> dict[str, bytes]:
    inputs = {name: read_file(kernel_dir / name, MAX_CONFIG_BYTES)
              for name in ("base-x86_64.config", "hermetic.config", "build.sh", "Dockerfile")}
    parse_config(inputs["base-x86_64.config"])
    parse_config(inputs["hermetic.config"])
    inputs["guest_kernel.py"] = read_file(Path(__file__).absolute(), MAX_CONFIG_BYTES)
    return inputs


def build_kernel(lock_path: Path, tarball: Path, output: Path, *, kernel_dir: Path = DEFAULT_KERNEL_DIR,
                 verify_reproducible: bool = False, builder=None, work_dir: Path | None = None,
                 output_identity: tuple[int, int] | None = None) -> dict:
    lock = load_lock(lock_path, for_build=True)
    # Validate every small input before creating staging files.
    inputs = _build_inputs(kernel_dir)
    with directory(output) as out_fd:
        out_st = os.fstat(out_fd)
        if output_identity is not None and (out_st.st_dev, out_st.st_ino) != output_identity:
            raise KernelError("integration output directory changed")
        if out_st.st_uid != os.geteuid() or out_st.st_mode & 0o022:
            raise KernelError("output directory must be owned by caller and not shared writable")
        with tempfile.TemporaryDirectory(prefix="hermetic-kernel-", dir=work_dir or "/tmp") as scratch:
            stable = Path(scratch)
            incoming = stable / "inputs"
            incoming.mkdir(mode=0o700)
            (incoming / "docker-config").mkdir(mode=0o700)
            for name, data in inputs.items():
                (incoming / name).write_bytes(data)
            _write_json(incoming / "kernel.lock.json", lock)
            with directory(incoming) as incoming_fd:
                _atomic_copy(tarball, incoming_fd, "source.tar.xz", MAX_TARBALL_BYTES)
            if hash_file(incoming / "source.tar.xz", MAX_TARBALL_BYTES) != lock["sha256"]:
                raise KernelError("source tarball sha256 mismatch")
            hashes = []
            runs = 2 if verify_reproducible else 1
            for index in range(runs):
                run_dir = stable / f"run-{index}"
                run_dir.mkdir(mode=0o700)
                if builder is None:
                    name = "hermetic-kernel-" + os.urandom(16).hex()
                    argv = docker_arguments(lock, incoming, run_dir,
                                            uid=os.geteuid(), gid=os.getegid(), name=name)
                    docker_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "TZ": "UTC"}
                    try:
                        _run(argv, env=docker_env, stderr_parent=out_fd)
                    except KernelError:
                        # A killed Docker client does not kill its daemon-side container.
                        try:
                            cleanup = subprocess.run(["/usr/bin/docker", "--config", str(incoming / "docker-config"),
                                            "rm", "--force", name], env=docker_env, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           timeout=CLEANUP_TIMEOUT_S, check=False)
                            if cleanup.returncode:
                                raise KernelError("build failed; container cleanup failed")
                        except (OSError, subprocess.TimeoutExpired):
                            raise KernelError("build failed; container cleanup failed") from None
                        raise
                else:
                    builder(lock, incoming, run_dir)
                findings = check_config(read_file(run_dir / ".config", MAX_CONFIG_BYTES)) + verify_vmlinux(run_dir / "vmlinux", lock)
                if findings:
                    raise KernelError("built kernel failed verification")
                hashes.append({name: hash_file(run_dir / name, cap) for name, cap in ARTIFACTS.items()})
            if len(hashes) == 2 and hashes[0] != hashes[1]:
                raise KernelError("kernel build is not reproducible")
            for name, cap in ARTIFACTS.items():
                _atomic_copy(stable / "run-0" / name, out_fd, name, cap)
            return {"version": lock["version"], "sha256": hashes[0], "reproducible": verify_reproducible}


def integration_build(tarball: Path, output: Path) -> bytes:
    """Prepare a local builder, then build offline using its immutable image ID."""
    lock = load_lock(DEFAULT_KERNEL_DIR / "kernel.lock.json")
    validate_lock(lock, for_build=True)
    inputs = _build_inputs(DEFAULT_KERNEL_DIR)
    if hash_file(tarball, MAX_TARBALL_BYTES) != lock["sha256"]:
        raise KernelError("source tarball sha256 mismatch")
    output = output.absolute()
    with directory(output, create=True) as out_fd:
        info = os.fstat(out_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise KernelError("integration output directory must be private and owned by caller")
        # Anchor creation to the held inode; expose its actual path only to Docker.
        with tempfile.TemporaryDirectory(prefix=".kernel-integration-", dir=f"/proc/self/fd/{out_fd}") as scratch:
            stable = output / Path(scratch).name
            with directory(stable) as staging:
                _atomic_bytes(staging, "Dockerfile", inputs["Dockerfile"])
                os.mkdir("docker-config", mode=0o700, dir_fd=staging)
            env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "TZ": "UTC"}
            _run(["/usr/bin/docker", "--config", str(stable / "docker-config"), "build",
                  "--build-arg", "BASE_IMAGE=debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc",
                  "-t", "hermetic/kernel-builder:6.6-v1", "--iidfile", str(stable / "image-id"),
                  "-f", str(stable / "Dockerfile"), str(stable)], env=env, stderr_parent=out_fd)
            image = read_file(stable / "image-id", MAX_IMAGE_ID_BYTES).strip()
            if not re.fullmatch(b"sha256:[0-9a-f]{64}", image):
                raise KernelError("invalid local builder image ID")
            lock["builder_image"] = image.decode("ascii")
            validate_lock(lock, for_build=True)
            _write_json(stable / "kernel.lock.json", lock)
            # Keep all integration staging inside the requested output directory.
            build_kernel(stable / "kernel.lock.json", tarball, output, work_dir=stable,
                         output_identity=(info.st_dev, info.st_ino), kernel_dir=DEFAULT_KERNEL_DIR)
            _atomic_bytes(out_fd, "kernel.lock.json", _json_bytes(lock))
            with _regular_at(out_fd, "build-record.json", MAX_LOCK_BYTES) as record:
                return _read_bytes(record, MAX_LOCK_BYTES)


class _BoundedXZ:
    """Streaming decompression with caps on dictionary memory and total output."""

    def __init__(self, raw):
        self.raw = raw
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_XZ_MEMORY_BYTES)
        self.total = 0

    def read(self, size: int) -> bytes:
        if not 0 <= size <= CHUNK_BYTES:
            raise KernelError("archive read exceeds chunk cap")
        out = bytearray()
        while len(out) < size and not self.decoder.eof:
            compressed = self.raw.read(CHUNK_BYTES) if self.decoder.needs_input else b""
            if not compressed and self.decoder.needs_input:
                raise KernelError("truncated XZ source")
            try:
                piece = self.decoder.decompress(compressed, max_length=size - len(out))
            except lzma.LZMAError:
                raise KernelError("invalid XZ source or dictionary exceeds cap") from None
            self.total += len(piece)
            if self.total > MAX_UNPACKED_BYTES:
                raise KernelError("unpacked source exceeds byte cap")
            out.extend(piece)
        return bytes(out)


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_pax(self, tarfile):
        if self.size > MAX_TAR_METADATA_BYTES:
            raise KernelError("archive metadata exceeds cap")
        return super()._proc_pax(tarfile)

    def _proc_gnulong(self, tarfile):
        if self.size > MAX_TAR_METADATA_BYTES:
            raise KernelError("archive metadata exceeds cap")
        return super()._proc_gnulong(tarfile)

    def _proc_sparse(self, tarfile):
        raise KernelError("sparse source archive members are unsupported")

    def _proc_gnusparse_00(self, next, pax_headers, buf):
        raise KernelError("sparse source archive members are unsupported")

    def _proc_gnusparse_01(self, next, pax_headers):
        raise KernelError("sparse source archive members are unsupported")

    def _proc_gnusparse_10(self, next, pax_headers, tarfile):
        raise KernelError("sparse source archive members are unsupported")


@contextmanager
def _source_directory(parent: int, parts: tuple[str, ...]):
    fd = os.dup(parent)
    try:
        for part in parts:
            try:
                os.mkdir(part, mode=0o755, dir_fd=fd)
            except FileExistsError:
                pass
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise KernelError("source directory must not contain symlinks")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            info = os.fstat(child)
            if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                os.close(child)
                raise KernelError("source directory changed")
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _validate_source_links(links: list[tuple[Path, str]], root: Path) -> None:
    targets = {target.relative_to(root).parts: PurePosixPath(link).parts for target, link in links}
    for target, link in links:
        resolved = list(target.relative_to(root).parts[:-1])
        pending = list(reversed(PurePosixPath(link).parts))
        hops = 0
        while pending:
            part = pending.pop()
            if part == "..":
                if not resolved:
                    raise KernelError("source link escapes tree")
                resolved.pop()
            else:
                resolved.append(part)
                expansion = targets.get(tuple(resolved))
                if expansion is not None:
                    hops += 1
                    if hops > MAX_SYMLINK_HOPS:
                        raise KernelError("source link exceeds hop cap")
                    resolved.pop()
                    pending.extend(reversed(expansion))
            if len(resolved) + len(pending) > MAX_PATH_DEPTH:
                raise KernelError("source link exceeds depth cap")


def _extract_source(archive: Path, destination: Path, version: str, expected_sha256: str) -> Path:
    """Extract a hash-verified source with bounded members and no link traversal."""
    root = "linux-" + version
    with directory(destination) as destination_fd, regular(archive, MAX_TARBALL_BYTES) as fd, os.fdopen(os.dup(fd), "rb") as raw:
        digest = hashlib.sha256()
        total_compressed = 0
        while total_compressed <= MAX_TARBALL_BYTES:
            chunk = raw.read(min(CHUNK_BYTES, MAX_TARBALL_BYTES + 1 - total_compressed))
            if not chunk:
                break
            total_compressed += len(chunk)
            digest.update(chunk)
        if total_compressed > MAX_TARBALL_BYTES or digest.hexdigest() != expected_sha256:
            raise KernelError("source tarball sha256 mismatch")
        raw.seek(0)
        with tarfile.open(fileobj=_BoundedXZ(raw), mode="r|", tarinfo=_BoundedTarInfo) as tar:
            total = 0
            count = 0
            links = []
            for member in tar:
                count += 1
                total += member.size
                _text(member.name, MAX_PATH_BYTES)
                parts = PurePosixPath(member.name).parts
                if (count > MAX_SOURCE_ENTRIES or total > MAX_SOURCE_BYTES or member.size < 0
                        or len(member.name) > MAX_PATH_BYTES or len(parts) > MAX_PATH_DEPTH
                        or not parts or parts[0] != root or ".." in parts or member.name.startswith("/")
                        or (len(parts) == 1 and not member.isdir())):
                    raise KernelError("source archive exceeds limits or contains unsafe paths")
                target = destination.joinpath(*parts)
                if member.isdir():
                    with _source_directory(destination_fd, parts):
                        pass
                elif member.isfile():
                    source = tar.extractfile(member)
                    if source is None:
                        raise KernelError("source archive member unavailable")
                    with source, _source_directory(destination_fd, parts[:-1]) as parent:
                        file_fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                          0o600, dir_fd=parent)
                        with os.fdopen(file_fd, "wb") as handle:
                            remaining = member.size
                            while remaining:
                                chunk = source.read(min(CHUNK_BYTES, remaining))
                                if not chunk:
                                    raise KernelError("truncated source archive")
                                handle.write(chunk)
                                remaining -= len(chunk)
                            os.fchmod(handle.fileno(), 0o755 if member.mode & 0o111 else 0o644)
                elif member.issym():
                    # Defer all symlinks until no writes remain; permit internal relative targets only.
                    _text(member.linkname, MAX_PATH_BYTES)
                    link = PurePosixPath(member.linkname)
                    if link.is_absolute() or len(member.linkname) > MAX_PATH_BYTES:
                        raise KernelError("unsafe source link")
                    depth = len(parts) - 1
                    for part in link.parts:
                        depth += -1 if part == ".." else 1
                        if depth < 1:
                            raise KernelError("source link escapes tree")
                    links.append((target, member.linkname))
                else:
                    raise KernelError("source archive contains special file or hard link")
                # Streaming mode otherwise retains every TarInfo in memory.
                tar.members.clear()
            _validate_source_links(links, destination / root)
            for target, _link in links:
                with _source_directory(destination_fd, target.relative_to(destination).parts[:-1]):
                    pass
            for target, link in links:
                with _source_directory(destination_fd, target.relative_to(destination).parts[:-1]) as parent:
                    os.symlink(link, target.name, dir_fd=parent)
    return destination / root


def container_build(*, incoming: Path = Path("/inputs"), output: Path = Path("/output"),
                    work: Path = Path("/build")) -> None:
    """Fixed-path container entrypoint; never invoked by the host CLI directly."""
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BUILD_FILE_BYTES, MAX_BUILD_FILE_BYTES))
    lock = load_lock(incoming / "kernel.lock.json", for_build=True)
    if hash_file(incoming / "source.tar.xz", MAX_TARBALL_BYTES) != lock["sha256"]:
        raise KernelError("source tarball sha256 mismatch")
    source = _extract_source(incoming / "source.tar.xz", work, lock["version"], lock["sha256"])
    build = work / "objects"
    build.mkdir(mode=0o700)
    # The container root (and so /tmp) is read-only; with initramfs support the kernel's
    # usr/gen_initramfs.sh needs mktemp, so give it a private directory on the build tmpfs.
    scratch = work / "tmp"
    scratch.mkdir(mode=0o700)
    env = {
        "PATH": "/usr/bin:/bin", "HOME": "/build", "ARCH": "x86_64", "LC_ALL": "C", "TZ": "UTC",
        "KBUILD_BUILD_TIMESTAMP": _banner_date(lock), "KBUILD_BUILD_USER": lock["build_user"],
        "KBUILD_BUILD_HOST": lock["build_host"], "KBUILD_BUILD_VERSION": "1",
        "SOURCE_DATE_EPOCH": str(int(release_datetime(lock).timestamp())),
        "KCONFIG_NOTIMESTAMP": "1", "KCONFIG_CONFIG": str(build / ".config"),
        "TMPDIR": str(scratch),
    }
    _run(["/bin/bash", str(source / "scripts/kconfig/merge_config.sh"), "-m", "-O", str(build),
          str(incoming / "base-x86_64.config"), str(incoming / "hermetic.config")], env=env, cwd=source)
    make = ["/usr/bin/make", "-C", str(source), "O=" + str(build), "-j2"]
    _run([*make, "olddefconfig"], env=env)
    if check_config(read_file(build / ".config", MAX_CONFIG_BYTES)):
        raise KernelError("final config failed policy")
    _run([*make, "vmlinux"], env=env)
    if verify_vmlinux(build / "vmlinux", lock):
        raise KernelError("built banner failed policy")
    input_hashes = {name: hash_file(incoming / name, MAX_TARBALL_BYTES) for name in (
        "source.tar.xz", "kernel.lock.json", "base-x86_64.config", "hermetic.config", "build.sh", "Dockerfile", "guest_kernel.py")}
    with directory(output) as out_fd:
        for name in ("vmlinux", ".config"):
            _atomic_copy(build / name, out_fd, name, ARTIFACTS[name])
    _write_json(output / "build-record.json", {
        "version": lock["version"], "builder_image": lock["builder_image"],
        "release_date": lock["release_date"], "build_user": "hermetic", "build_host": "hermetic",
        "inputs": input_hashes, "outputs": {name: hash_file(build / name) for name in ("vmlinux", ".config")},
    })


if __name__ == "__main__":
    try:
        container_build()
    except (KernelError, OSError, tarfile.TarError, EOFError, RecursionError):
        raise SystemExit("kernel container build failed") from None
