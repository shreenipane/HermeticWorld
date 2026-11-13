# Boot smoke notes (development, no jailer)

Command, from the worktree root:

```
scripts/integration/boot-smoke.sh /tmp/hermetic-boot-smoke
```

The script runs these steps:

0. Stages the pinned Firecracker.
1. Builds static `hermetic-execd` and `hermetic-init`, a rootfs tree, and a D4-checked
   ext4 image with `hermetic_slice.rootfs.build_rootfs`.
2. Boots that image with kernel `~/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux`
   (Linux 6.6.160) through hermetic-vmm's `dev-unjailed` runner. There is no jailer,
   namespace or cgroup isolation.
3. Runs `tests/guest.rs::boots_guest_and_reads_guest_clock`. The test reads execd's
   status frame and checks its guest clock against `hermetic.t`. It then runs
   `/bin/busybox echo hermetic-ok` and `/bin/busybox date -u +%s` through execd.

## Pinned inputs

- **Firecracker** 1.18.0, `https://github.com/firecracker-microvm/firecracker/releases/download/v1.18.0/firecracker-v1.18.0-x86_64.tgz`.
  - Binary sha256 `b33f46cd6d88834cf6a4f8d184f08f219809c636236bffd286d233a60602a2ba`, equal to `vmm/firecracker.lock.json`.
  - Already on disk; staged as `~/.hermetic/tools/firecracker-1.18.0/firecracker` (mode 0755). Nothing was downloaded.
- **Kernel** 6.6.160 (6.6 LTS, released 2026-10-21; the newest 6.6.y at least 14 days old on 2026-11-13).
  - Source `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.160.tar.xz`, sha256 `b24c40a9e2188695803358567edda51c4080176424a57dbefca45e5ac44ec225`.
  - The tarball matches `v6.x/sha256sums.asc`. That file's signature verified with gpg using the kernel.org checksum autosigner key `B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1`. The key was fetched over HTTPS from kernel.org's `pgpkeys.git`; it is not web-of-trust certified.
  - Tarball cached at `~/.hermetic/cache/kernel-src/linux-6.6.160.tar.xz`.
  - Build: `bash scripts/integration/kernel-build.sh ~/.hermetic/cache/kernel-src/linux-6.6.160.tar.xz ~/.hermetic/cache/kernel-out-20261113-6.6b`.
  - Output vmlinux sha256 `de8afb2fa7c4281311f840d25ed00b5ec0101cf1130d66325b8e4f1eddcc94d1`.
  - Config changes: `DEVTMPFS_MOUNT=y`, `PROC_CHILDREN=y`, `BLK_DEV_INITRD=y`, `RD_GZIP=y`, `INITRAMFS_SOURCE=""`, every other RD_* decompressor off.
  - Clock hiding is unchanged: `no-kvmclock`, PTP KVM off, `PARAVIRT`/`KVM_GUEST` as before.

## Early-boot design (why no initramfs on first boot)

The execd README contract says three things:

- The kernel mounts the sealed base read-only and provides devtmpfs at `/dev`.
- The trusted boot environment provides a read-only early `/proc`.
- execd mounts nothing before setting the clock.

A kernel that boots an initramfs `/init` skips both of its own root and devtmpfs
mounts. A first-boot initramfs would therefore have to mount the base, devtmpfs and
proc and then switch root, or it would have to use `hermetic.initramfs=1`, which
locks execd until `authorize` and is meant for trusted reboots. Neither fits
"only mount proc".

The smallest design that matches the contract exactly is a shim:

- `init=/sbin/hermetic-init` is a static, `forbid(unsafe_code)` binary in the
  hermetic-execd crate (`src/early.rs`, `src/bin/hermetic-init.rs`). It lives on the
  sealed read-only base next to execd.
- As PID 1 it mounts procfs read-only (nosuid, nodev, noexec) at `/proc` and execs
  `/sbin/hermetic-execd` with no arguments and an empty environment. execd runs as
  the same PID 1.
- It reads no clock, writes nothing, logs nothing and parses no input. Any failure
  powers the VM off. It refuses to run unless it is PID 1.
- execd's root switch covers the early proc.

`BLK_DEV_INITRD` is enabled for the TR-EXD-6 trusted-reboot initramfs, which is not
built yet. hermetic-vmm therefore has no initrd wiring yet.

## Verified on the serial console (manual capture, below)

```
VFS: Mounted root (ext4 filesystem) readonly on device 254:0.
devtmpfs: mounted
Run /sbin/hermetic-init as init process
EXT4-fs (vdb): mounted filesystem ... r/w
execd 1700000000 Io
reboot: System halted
```

The failure line is stamped `1700000000`, the faked `hermetic.t` clock. That shows
the clock was set before the overlay mount. A temporary step trace (since removed)
showed every boot step succeeding:

- clock, overlay, `MoveDev`, `SwitchRoot`
- proc, sys, pts, shm
- `StampDev`, spec load, apply, listen

## What broke and how it was fixed

1. **6.1 kernel without early proc or devtmpfs.** Fixed by moving to 6.6.160 with
   `DEVTMPFS_MOUNT` and adding the shim.
   - Tests: `test_execd_boot_contract_kernel_policy`, `test_lock_requires_6_6_series`
     (python), and `early::tests::*` (Rust) for the shim's order, its pid check and
     its failure handling.
2. **`CONFIG_RANDOM_TRUST_CPU` was required by policy but removed upstream in 6.2.**
   Every 6.6 build failed the final config check. The requirement was dropped.
   - Test: `test_policy_has_no_symbols_removed_before_6_6`.
3. **Read-only `/tmp` in the build container.** With initrd support,
   `usr/gen_initramfs.sh` calls `mktemp`. The build now sets `TMPDIR` to a private
   0700 directory on the build tmpfs.
   - Test: an assertion in `test_container_pipeline_checks_before_compile_and_records_inputs`.
4. **execd failed `MountPts`.** The devtmpfs moved over `/dev` hides the base's
   `/dev/pts` and `/dev/shm`. execd now creates those fixed mountpoints after the clock
   (no-follow, must be a directory).
   - Test: `real::tests::devtmpfs_mountpoints_are_created_without_following_links`.
5. **Readiness race in the guest test.** Firecracker closes CONNECT to an unbound
   guest port, and the test treated that as a protocol error.
   - Test: `guest_not_yet_listening_is_retryable`.
6. **Script details.** Under umask 002 the build output is group-writable, so the
   script copies sealcheck privately. `kernel-build.sh` has no execute bit, so it is
   run with `bash`.

## Result: booted

With `CONFIG_PROC_CHILDREN=y` the smoke run passes end to end:

```
{"image": ".../rootfs.img", ..., "d4": "pass"}
guest status: guest_time_unix=1700000000
guest exec: output="hermetic-ok\n" date=1700000000
test result: ok. 1 passed
```

7. **Kernel lacked `CONFIG_PROC_CHILDREN`.** execd's reaper reads
   `/proc/self/task/1/children` before it accepts any connection. Without it, execd
   powered off with `Io` (`execd 1700000000 Io` on serial). Added to the policy and
   `hermetic.config`. Test: `test_policy_requires_proc_children_for_execd_reaper`.

Still open (PHASES.md): the TR-EXD-6 trusted-reboot initramfs and hermetic-vmm initrd wiring.

## Manual serial capture

There is no API socket and no jailer. `cfg.json` lists the kernel, the boot
arguments with `init=/sbin/hermetic-init`, the two drives and vsock:

```
firecracker --no-api --config-file cfg.json > serial.log 2>&1
```

## Network VM

Run from the worktree root on the prepared host:

```sh
scripts/integration/net-smoke.sh "$HOME/hermetic-netvm-smoke"
```

The work directory must be new, with a parent not writable by other users. The
script uses `$HOME` for the pinned Firecracker and kernel locations;
`HERMETIC_KERNEL` can select another policy-checked kernel. It builds static
NetVM/execd/init binaries, copies the offline fixture in `net-fixture`, builds two
D4-checked read-only rootfs images, then runs the ignored
`netvm_serves_world_to_agent_and_drops_everything_else` test with `dev-unjailed`.
Build prerequisites match `boot-smoke.sh`: Cargo, static busybox and the rootfs
builder's pinned e2fsprogs container through Docker. This development runner has
no jailer isolation.

Host prerequisites, configured by the owner beforehand:

- `/dev/kvm` and `/dev/net/tun` accessible to the invoking user.
- Taps `hwtap-agent` and `hwtap-net` owned by uid 1000, up, and attached only to
  bridge `hwbr0`. The bridge is up, has no IPv4 or IPv6 address, IPv6 is disabled
  on it, and the host does not forward traffic outside. No physical NIC belongs
  to the bridge. The script never configures host networking or loads modules.
- A policy-checked 6.6 guest kernel with built-in `NETFILTER_XTABLES`,
  `IP_NF_IPTABLES` and `IP_NF_FILTER`. Linux 6.6 builds `xt_tcpudp.o` with
  `NETFILTER_XTABLES`; no separate TCP/UDP-match option exists. These options are
  already required. No clock, timer, RTC, PTP or paravirtual clock feature is added.

NetVM runs `/sbin/hermetic-netvm` as PID 1. It mounts proc for pinned config reads,
sets the guest clock, installs fixed INPUT/OUTPUT service-port filters and a
drop-only FORWARD chain, disables forwarding and IPv6, then brings up eth0 as
`10.0.2.3/24`. It owns the fixture's `10.9.0.1/32`, serves table DNS on
`10.0.2.3:53` and plain HTTP on port 80, and forwards bounded frames over one
persistent vsock connection to CID 2 port 5001. Firecracker forwards that port to
`<NetVM vsock UDS>_5001`, where the sandboxed host WorldServer listens. Port 5000
is execd; 5002 is reserved for the gateway.

AgentVM boots execd through `hermetic-init`. The run spec installs a regular
`/etc/resolv.conf` pointing at NetVM. Before starting the agent, the trusted
harness runs the fixed busybox setup through execd as root: IPv6 off, eth0
`10.0.2.15/24`, and the sole default route via `10.0.2.3`. The existing run-spec
schema has no network-effect field; automatic eth0 initialization requires an
execd schema/boot change and remains open in PHASES.md.

The test checks allowed DNS, exact GET fixture bytes, POST 405, NXDOMAIN for
unknown DNS, rejection of unknown HTTP hosts, blocked unrelated addresses and
ports, no public DNS answer, ICMP blocked at NetVM itself, and a regular resolver
file. Missing explicit smoke inputs fail. Owning guards kill and reap both VMs
and WorldServer on success or panic.

**Boot status: OPEN here.** The exact command above stops before creating images
or services with `OPEN: cannot open /dev/kvm or /dev/net/tun; run on the prepared host`.
TLS termination, CA-key boot delivery, TPROXY and NetVM dm-verity remain open in
PHASES.md. This cut drops 443 and uses D4-checked read-only ext4. It intercepts
plain HTTP by owning the manifest addresses, without a redirect rule.
