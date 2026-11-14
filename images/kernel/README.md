# Shared x86_64 guest kernel

This is the T3.2 offline build harness for TR-VMM-4 and the guest side of
TR-VMM-5. The candidate source is Linux **6.6.160** (6.6 long-term series, released
2026-10-21; the newest 6.6.y at least two weeks old when pinned). execd needs
6.6 or later for `utimensat(AT_EMPTY_PATH)`. The 6.6 series is supported by
Firecracker's x86_64 microVM platform. This selects an explicit
substrate, not the newest stable release. Runtime compatibility still needs the
owner's pinned Firecracker integration test.

The guest-root policy also forces early confidentiality lockdown and compiles
out modules, raw memory/MSR/port access, kexec, hibernation, tracing and KVM
paravirtual clock hooks. Required VM drivers and cgroup-device BPF remain built
in. See [guest lockdown](../../docs/guest-lockdown.md) for the source rationale,
probe contract, exact manager build commands and all VM smoke commands.

## Pinned values in `kernel.lock.json`

The lock file `kernel.lock.json` contains verified upstream pin values:
- `version`: `6.6.160`
- `source_url`: `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.160.tar.xz`
- `sha256`: `b24c40a9e2188695803358567edda51c4080176424a57dbefca45e5ac44ec225` (verified against kernel.org `v6.x/sha256sums.asc`, whose signature verified with the kernel.org checksum autosigner key B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1)
- `release_date`: `2026-10-21T00:00:00Z` (the 6.6.160 tarball release date)
- `builder_image`: `hermetic/kernel-builder:6.6-v1@sha256:29ad57ab16edc3ddcb8b44de77061336a4cabc6812243bedac48e815529da238` (owner-approved local image ID; Docker uses `sha256:29ad57ab16edc3ddcb8b44de77061336a4cabc6812243bedac48e815529da238`)
- Builder base image: `debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` (debian:bookworm-slim).

## Running the integration build

Run the integration build script `scripts/integration/kernel-build.sh` from the repository root with two arguments: the path of the downloaded Linux 6.6.160 source tarball and an output directory:

```sh
./scripts/integration/kernel-build.sh /path/to/linux-6.6.160.tar.xz /path/to/kernel-output
```

The script:
1. Validates the source hash and output directory, then makes the **approved** builder image available by its immutable ID, `sha256:29ad57ab16edc3ddcb8b44de77061336a4cabc6812243bedac48e815529da238`, and tags it `hermetic/kernel-builder:6.6-v1`. It never rebuilds the builder: `images/kernel/Dockerfile` installs packages from a live Debian archive and the legacy Docker builder records build times, so a clean rebuild cannot reproduce the approved digest. If the local store lacks the image, it is loaded from a `docker save` archive named by `HERMETIC_KERNEL_BUILDER_ARCHIVE` (absolute path, regular file, no symlinks); tagging by ID then succeeds only if that archive held exactly the approved image.
2. A local image ID is not a registry manifest digest and must not be appended to a repository name with `@`. Producing a new builder from the Dockerfile is an owner re-approval step: it yields a new ID that must replace `APPROVED_BUILDER_DIGEST` (and this README) before any build accepts it. The kernel build runs with `--network=none` and `--pull=never`.
3. Prints the resulting `build-record.json` from the output directory.

The script runs without `sudo` and stages files inside the specified output directory. Missing directories are created with mode 0700; an existing output directory must be caller-owned with mode 0700. Symlinked paths and special files are refused, and existing directories are never chmodded. The resolved `kernel.lock.json` is published atomically with mode 0600 after a successful build. Docker writes to its image store during builder preparation.

Direct CLI invocation from repository root (after builder image is built):

```sh
PYTHONPATH=python python -m hermetic_slice kernel-check-config --config final.config
PYTHONPATH=python python -m hermetic_slice kernel-build \
  --tarball /absolute/path/linux-6.6.160.tar.xz --out /absolute/path/kernel-output \
  --verify-reproducible
```

`kernel-check-config` emits deterministic JSON: exit 0 clean, 2 policy findings,
1 invalid/unsafe input. `kernel-build` exits 1 for unresolved pins, hash mismatch,
build failures, config/banner findings or unequal rebuilds. It never downloads.
It calls `/usr/bin/docker` and requires a **local Linux Docker daemon**.
An empty staged Docker config prevents ambient Docker configuration from entering
the build. No ambient context, host locale, build variables or shell expansion
is used.
The only host environment input is normal OS process/descriptor operation; no
`HERMETIC_*` overrides are accepted. Numeric uid/gid are passed solely to keep
bind-mounted outputs caller-owned, and never enter kernel build identity or the
build record. The pure argv helper defaults these transport IDs to 1000:1000.

The daemon runs an already-cached digest pinned image with `--pull=never`,
`--network=none`, a read-only container root, dropped capabilities, no new
privileges, two CPUs, 4 GiB RAM and 512 processes. Input staging is private and
read-only; compilation uses `/build/linux-6.6.160` and `/build/objects` on a
size-capped 8 GiB tmpfs. `/output` is the only persistent writable mount.
`build.sh` clears its environment. There are no accepted build variables.

The source hash is checked before unpacking. Extraction caps source entries and
bytes, rejects absolute/traversing paths and special files, and writes through
held directory descriptors without following preexisting symlinks. It resolves
composed symlink targets with a 40-hop cap and rejects escapes and cycles before
creating internal relative symlinks after all archive writes. Base plus fragment are merged
with upstream `merge_config.sh -m`, followed by `make olddefconfig`. The checker
must pass the **final** config before `make vmlinux`. The build fixes timestamp,
user, host, build version (`1`), SOURCE_DATE_EPOCH, locale, timezone and paths.
Debug information, build salt and local version suffixes are disabled.

Artifacts are `vmlinux`, `.config`, and `build-record.json`; the record contains
version, pinned builder, fixed identity/release date, sha256 hashes of all staged
inputs (including harness and Dockerfile) and the kernel/config outputs. It has
no host paths or real build time. Each output is published via a same-directory
temporary file, fsync, rename and directory fsync. The record is published last;
a filesystem failure can interrupt the set, so consumers must verify its hashes.
Existing outputs survive validation/build/reproducibility failures. Two-build
verification uses distinct output directories and compares every artifact hash.
Tool stdout is discarded. Container build steps inherit stderr so the host can
retain its last 64 KiB in `kernel-build.stderr.log` in the output directory,
including on build failure or timeout. The log is written atomically through the
held output descriptor with mode 0600 and replaces any existing log symlink
without following it. It is a private diagnostic file containing raw tool output,
separate from the reproducible artifacts and their hashes; do not include it in
sealed worlds. CLI errors remain fixed and never quote tool output. Each run
replaces the preceding log, including the builder preparation log.

The canonical command line uses `clocksource=tsc tsc=reliable no-kvmclock`,
`hermetic.t=<bounded decimal Unix seconds>`, `root=/dev/vda rootfstype=ext4 ro`,
`init=/sbin/hermetic-execd`, serial console `ttyS0,115200n8`, `pci=off`,
`reboot=k panic=-1`. Negative panic timeout reboots immediately on panic so the
VMM can terminate a failed guest; it must never recycle it into a fresh run.
`no-kvmclock` disables the normal paravirtual clock driver as defense in depth;
it does not block malicious ring-0 MSR/hypercall use. The checker permits only
the canonical argument vocabulary and rejects missing/duplicate options,
`clocksource=kvm-clock`, `rw`, any `ip=`, and all other unknown arguments.

All required drivers are built in (`y`), so no module availability is assumed.
Module loading remains available for the later privileged clock-pairing probe;
module signing bypass analysis is outside this task. No signing keys are generated.
`VIRTIO_MMIO_CMDLINE_DEVICES` accepts Firecracker's appended device descriptors;
the boot checker checks the caller's arguments before those VMM additions.
PTP is disabled entirely, including KVM and VMware host clocks; RTC does not
initialize wall time. Mount namespaces are inherent in NAMESPACES; cgroup
namespaces are inherent in CGROUPS, without separate Linux 6.6 switches.
Time namespaces are disabled: execd sets CLOCK_REALTIME before writes, and time
namespaces virtualize monotonic/boottime rather than wall time. Device rules
use cgroup BPF, not the obsolete cgroup-v1 devices controller. BFQ plus block
throttling supplies io weight/max controls. Linux 6.6 x86_64 supplies the
architectural RDRAND implementation when
CPUID advertises it; since Linux 6.2 its entropy contribution is trusted by
default (`random.trust_cpu`), so the removed `RANDOM_TRUST_CPU` switch is not requested.
No obsolete `X86_RDRAND` switch is requested.
`IKCONFIG` is disabled; the exact audited config is a separate artifact.
Devtmpfs is enabled but `DEVTMPFS_MOUNT` is disabled: execd must explicitly
mount it after clock setup, then move `/dev` when switching root. T3.1 must
honor that ordering; the kernel does not automatically provide `/dev`.

Limits are named in `guest_kernel.py`: config 2 MiB, lines 4096 bytes, lock and
record 16 KiB, stderr tail 64 KiB, image ID 72 bytes, command line 2048 bytes,
paths 4096 bytes/128 components, symlink resolution 40 hops, tarball
256 MiB, source 4 GiB/150,000 entries, vmlinux 1 GiB, banner 1024 bytes,
individual compiler output file 2 GiB, XZ dictionary memory 128 MiB,
unpacked stream 5 GiB, extended tar metadata 16 KiB, each build subprocess
7200 seconds and container cleanup 30 seconds. A timeout kills the process
group and requests removal of the daemon-side Docker container.
No image is executed by the verifier. Banner checks require the exact version,
`hermetic@hermetic` and the release date formatted in fixed English UTC.

Offline tests prove policy handling, lock validation, hostile-input rejection,
canonical argv, synthetic banner verification, atomic output, archive handling
and fake-builder reproducibility. They do **not** prove a successful Linux
compile, compatibility after olddefconfig, boot, cgroup/controller behavior,
getrandom readiness or byte reproducibility of a real kernel. The owner must
run the build twice and boot with the pinned Firecracker and T3.1 rootfs.
Virtio-rng attachment, MMDS omission, VMClock review, CPUID enforcement and
host clock-pairing interception belong to the VMM/host tasks. Until those probes
pass, the clock level remains `faked`; this kernel alone cannot certify `hidden`.

The policy table below is generated by `documentation_table()` in
`python/hermetic_slice/guest_kernel.py`; tests require an exact match.
Disabled symbols omitted by olddefconfig are accepted; enabled forbidden
symbols, including modules, fail. Every required enabled/string symbol must be
present with its exact value. The final config must identify Linux >= 5.10.

<!-- BEGIN POLICY -->
| Option | Required value | Requirement |
| --- | --- | --- |
| `CONFIG_64BIT` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_ACPI_CUSTOM_METHOD` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_ACPI_TABLE_UPGRADE` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_BFQ_GROUP_IOSCHED` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_BINFMT_ELF` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_BINFMT_SCRIPT` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_BLK_CGROUP` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_BLK_DEV` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_BLK_DEV_DM` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_BLK_DEV_INITRD` | `y` | TR-EXD-6: trusted initramfs support (uncompressed or gzip only) |
| `CONFIG_BLK_DEV_THROTTLING` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_BLOCK` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_BPF` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_BPF_EVENTS` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_BPF_KPROBE_OVERRIDE` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_BPF_SYSCALL` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_BPF_UNPRIV_DEFAULT_OFF` | `y` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_BUILD_SALT` | `""` | TR-VMM-4: no random build salt |
| `CONFIG_CFS_BANDWIDTH` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CGROUPS` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CGROUP_BPF` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CGROUP_PIDS` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CGROUP_SCHED` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CGROUP_WRITEBACK` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CPUSETS` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_CRYPTO` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_CRYPTO_SHA256` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_DEBUG_INFO` | `n` | TR-VMM-4: no compiler paths or debug metadata |
| `CONFIG_DEFAULT_HOSTNAME` | `"hermetic"` | TR-VMM-4: fixed default guest hostname |
| `CONFIG_DEVKMEM` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_DEVMEM` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_DEVTMPFS` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_DEVTMPFS_MOUNT` | `y` | execd boot contract: the kernel mounts devtmpfs at /dev before PID 1 |
| `CONFIG_DM_VERITY` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_ELF_CORE` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_EXT4_FS` | `y` | TR-VMM-4: root filesystems |
| `CONFIG_EXT4_FS_POSIX_ACL` | `y` | TR-VMM-4: root filesystems |
| `CONFIG_FAIR_GROUP_SCHED` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_FHANDLE` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_FS_POSIX_ACL` | `y` | TR-VMM-4: root filesystems |
| `CONFIG_HERMETIC_CLOCK_CANARY` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_HIBERNATION` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_HW_RANDOM` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_HW_RANDOM_VIRTIO` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_HYPERVISOR_GUEST` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_IKCONFIG` | `n` | TR-VMM-4: fixed build identity; config supplied separately |
| `CONFIG_INET` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_INITRAMFS_SOURCE` | `""` | TR-EXD-6: no initramfs built into the kernel image |
| `CONFIG_IOSCHED_BFQ` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_IP6_NF_FILTER` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IP6_NF_IPTABLES` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IP6_NF_MANGLE` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IPC_NS` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_IPV6` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IP_NF_FILTER` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IP_NF_IPTABLES` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IP_NF_MANGLE` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_IP_NF_NAT` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_KEXEC` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_KEXEC_CORE` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_KEXEC_FILE` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_KPROBES` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_KPROBE_EVENTS` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_KVM_GUEST` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_LOCALVERSION` | `""` | TR-VMM-4: no local version or host suffix |
| `CONFIG_LOCALVERSION_AUTO` | `n` | TR-VMM-4: fixed build identity; config supplied separately |
| `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` | `y` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_MD` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_MEMCG` | `y` | TR-VMM-4: cgroup v2 controllers and device BPF |
| `CONFIG_MODULES` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_MULTIUSER` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_NAMESPACES` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_NET` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_NETDEVICES` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_NETFILTER` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_ADVANCED` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_XTABLES` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_XT_MATCH_CONNTRACK` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_XT_MATCH_SOCKET` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_XT_TARGET_MASQUERADE` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_XT_TARGET_REDIRECT` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NETFILTER_XT_TARGET_TPROXY` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NET_NS` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_NFT_CT` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NFT_NAT` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NFT_SOCKET` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NFT_TPROXY` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_CONNTRACK` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_NAT` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_SOCKET_IPV4` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_SOCKET_IPV6` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_TABLES` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_TABLES_INET` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_TPROXY_IPV4` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_NF_TPROXY_IPV6` | `y` | TR-VMM-4: nftables, legacy iptables, TPROXY and conntrack |
| `CONFIG_OVERLAY_FS` | `y` | TR-VMM-4: root filesystems |
| `CONFIG_PARAVIRT` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_PARAVIRT_CLOCK` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_PCI` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_PID_NS` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_POSIX_MQUEUE` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_PRINTK` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_PROC_CHILDREN` | `y` | execd: PID 1 reaps orphans via /proc/<pid>/task/<tid>/children |
| `CONFIG_PROC_FS` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_PROC_KCORE` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_PTP_1588_CLOCK` | `n` | TR-VMM-4: prevent accidental host clock reads |
| `CONFIG_PTP_1588_CLOCK_KVM` | `n` | TR-VMM-4: prevent accidental host clock reads |
| `CONFIG_PTP_1588_CLOCK_VMW` | `n` | TR-VMM-4: prevent accidental host clock reads |
| `CONFIG_RD_BZIP2` | `n` | TR-EXD-6: no initramfs decompressor other than gzip |
| `CONFIG_RD_GZIP` | `y` | TR-EXD-6: trusted initramfs support (uncompressed or gzip only) |
| `CONFIG_RD_LZ4` | `n` | TR-EXD-6: no initramfs decompressor other than gzip |
| `CONFIG_RD_LZMA` | `n` | TR-EXD-6: no initramfs decompressor other than gzip |
| `CONFIG_RD_LZO` | `n` | TR-EXD-6: no initramfs decompressor other than gzip |
| `CONFIG_RD_XZ` | `n` | TR-EXD-6: no initramfs decompressor other than gzip |
| `CONFIG_RD_ZSTD` | `n` | TR-EXD-6: no initramfs decompressor other than gzip |
| `CONFIG_RTC_HCTOSYS` | `n` | TR-VMM-4: prevent accidental host clock reads |
| `CONFIG_SECCOMP` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_SECCOMP_FILTER` | `y` | TR-VMM-4: dm-verity and seccomp |
| `CONFIG_SECURITY` | `y` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_SECURITYFS` | `y` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_SECURITY_LOCKDOWN_LSM` | `y` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` | `y` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_SERIAL_8250` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_SERIAL_8250_CONSOLE` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_SMP` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_SYSFS` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_SYSVIPC` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_TIME_NS` | `n` | T3.1: no time namespace needed |
| `CONFIG_TMPFS` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_TTY` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_UNIX` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_UNIX98_PTYS` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_UPROBE_EVENTS` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_USER_NS` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_UTS_NS` | `y` | TR-VMM-4: namespaces (mount namespaces are part of NAMESPACES) |
| `CONFIG_VIRTIO` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VIRTIO_BLK` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VIRTIO_CONSOLE` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VIRTIO_MMIO` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VIRTIO_NET` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VIRTIO_VSOCKETS` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_VSOCKETS` | `y` | TR-VMM-5: virtio devices, vsock and entropy |
| `CONFIG_X86_64` | `y` | TR-VMM-4: x86 microVM boot |
| `CONFIG_X86_CPUID` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_X86_IOPL_IOPERM` | `n` | Phase 3b: deny guest root access to kernel code and memory |
| `CONFIG_X86_MSR` | `n` | Phase 3b: deny guest root access to kernel code and memory |
<!-- END POLICY -->

## Executable boot arguments

The lock's boot string is VmSpec input. `spec_boot_arguments(t_clock)` produces
that canonical input; lifecycle adds the VMM-owned `tsc_early_khz` before launch.
Direct Python builders use `boot_arguments(t_clock, vmm=Path(...))`, which executes
the pinned VMM resolver with bounded output and a deadline. It returns the fixed
scaled guest rate `tsc_early_khz=2000000`. Unsupported CPU/scaling hosts fail closed.
`no-kvmclock` remains for compatibility and is inert when KVM_GUEST is disabled.
See [the clock analysis](../../docs/clock-3b-analysis.md) for host filtering and
CPU/TSC enforcement and manager validation required before a hidden-clock claim.
