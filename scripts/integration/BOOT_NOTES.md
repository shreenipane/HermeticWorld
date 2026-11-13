# Boot smoke notes (development, no jailer)

Command, from the worktree root:

```
scripts/integration/boot-smoke.sh
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

# Grader smoke (development, offline, VM)

Command, from the worktree root:

```
scripts/integration/grader-smoke.sh
```

Fixture task: `scripts/integration/fixtures/grader-task/`.
- `repo/` is a two-function module with `tests/test_calc.py`.
- `test_double` passes on base (P2P); `test_add` fails on base (F2P).
- `gold.patch` fixes `add`, and `empty.patch` is the empty patch.
- `plan.json` is the grading plan (no mutants, no equivalents).

For each variant the script applies the patch to a fixture work tree, emits a
HEXT v1 stream with `hermetic-extract-agent`, and publishes the validated result
with `hermetic-extract-validate`. It then passes those published trees to
`grader-vm-smoke.sh`, which builds and boots byte-identical images for the three
runs of each variant. This preserves the
full extraction, grading and host verdict checks. A supplied work directory must
be fresh; symlinks are refused before any chmod.

## Grader VM boot and supervisor isolation

The grader VM boots through `hermetic-grader-init` (details below). The supervisor
applies the sandbox plan before executing repository code: new PID, mount, IPC,
UTS and network namespaces, fixed identity and environment, exact capability
sets, no-new-privileges, private mounts and minimal devices. A dedicated fd 3
carries records; stdout and stderr go to `/dev/null`. PID namespace teardown and
pidfds cover descendants that change sessions or close their record descriptor.

The former container smoke used the host realtime clock. Namespaces cannot give
it a private `CLOCK_REALTIME`, and setting it would change the host clock. Both
smoke entry points now use the VM, whose initializer sets the sealed clock.

## What broke and how it was fixed

1. **Result disk header endianness.** The supervisor wrote the HGRD header integers little-endian. The host parser reads them big-endian, so every real result disk was classified as tampered. The supervisor now writes big-endian.
2. **Canonical JSON mismatch.** The supervisor sorted keys. The host re-serializes in schema field order and rejects anything else (`non_canonical_json`). The supervisor now serializes in schema order.
   - Test for 1 and 2: `supervisor_result_disk_is_accepted_by_host_parser` (`crates/hermetic-grader-supervisor/tests/host_format.rs`). It checks that the host accepts the supervisor's image and that the two encoders' images are byte-identical. The supervisor's known-answer image hash was updated.
3. **`build_rootfs` failed on non-ASCII names.** mke2fs ran with `LANG=C`, and libarchive refuses PAX names and link targets that are not ASCII under an ASCII locale. Alpine's CA store has such names. mke2fs now runs with `LANG=C.UTF-8`.
   - Tests: `test_regression_mke2fs_runs_under_utf8_locale` and `test_regression_non_ascii_names_and_link_targets_build`.
4. **Script detail.** Docker's `--tmpfs /tmp` is not world-writable by default, so a non-root test run had no temporary directory. The supervisor then correctly reported `supervisor_crash` and `infra_error`. The script mounts it with `mode=1777`.

## Known gaps (not fixed here)

- **HEXT v1 mismatch (fixed 2026-11-13).** The agent and the validator used to implement two incompatible HEXT v1 formats, so the smoke applied the patch on the host. The validator's format (u32 version, fixed 60-byte header, end record with record count and total bytes) is now canonical and the agent emits it byte for byte (`crates/hermetic-extract-agent/tests/validator_compat.rs`). The smoke now applies the variant patch to a copy of the base repo, runs `hermetic-extract-agent --class patch:` and publishes through `hermetic-extract-validate` with `fixtures/grader-task/extract-config.json`. Both still run on the host, not in an ExtractorVM.
- **Tree root spelling (fixed 2026-11-13).** The root is the empty string on both sides: agent `--class patch:`, validator `repo_dir: ""`. The agent refuses `patch:.` (`InvalidTaskClass`) and the validator refuses `repo_dir: "."` (config error).

# Grader VM (development, dev-unjailed)

Command, from the worktree root:

```
bash scripts/integration/grader-vm-smoke.sh
```

For each variant (empty, gold) and each run (R0, R1, R2), the script:

1. Builds the grader tree from the "Grader smoke" section. The patch is applied on the host. The tree adds static `/sbin/hermetic-grader-init` and has one fixed config, `/etc/hermetic/grader/run.json`, with no run label. Every run gets its own D4-checked image. Before any boot, the script compares all three images byte for byte and records their equal SHA-256 hashes in `<variant>/host/image-sha256.txt`. The kernel command line is also identical.
2. Boots the image with hermetic-vmm's `dev-unjailed` runner through `tests/guest.rs::boots_grader_and_collects_result_drive`.
   - Firecracker 1.18.0, kernel `kernel-out-20261113-6.6b`.
   - Boot arguments: `init=/sbin/hermetic-grader-init`, `hermetic.t=1700000000`, `reboot=k panic=-1`.
   - Drives: root `vda` read-only, then `result` `vdb`, which is writable and exactly 1 MiB. No vsock and no network. The host test reads `HERMETIC_GRADER_RUN` and initializes only the result drive with HGRL v1 boot input: bytes `48 47 52 4c 00 01`, two ASCII run bytes (`R0` through `R3`), then zero padding through byte 1,048,575. It does not forward that host environment variable into the guest.
3. Waits for the VM to exit (`Vmm::wait_exit`) and checks the serial line `grader-init SECONDS clock` against `hermetic.t`. It then copies the jail's result drive out.
4. Runs `hermetic-grader-verdict` over R0/R1/R2.

The supervisor validates the entire fixed-size HGRL image before spawning tests.
Missing, malformed, oversized or nonzero-padded input fails closed. `run` and
`run_name` in the image config are rejected. The label stays in supervisor memory;
it never enters helper input, argv, environment, cmdline or a rootfs file. No
per-run nonce is used. After the process tree exits, the supervisor overwrites
the result drive with the usual HGRD output; the host verdict validates its label.

The sandbox has a fresh proc mount in its own PID namespace and a non-recursive
root bind, minimal `/dev`, no inherited result descriptor, no administrative or
MKNOD capabilities, and block-device denial. Thus tests cannot access `/dev/vdb`
or supervisor memory, file descriptors, argv or environment. The mandatory smoke
plugin `hermetic_run_probe` asserts the label-free config, cmdline, argv and
environment, PID isolation, absent block devices, and exactly the three null
stdio descriptors plus the write-only record pipe. It runs on plugin import,
before pytest capture and repository imports, and a probe failure fails the
host verdict.

Offline regressions: `tests/run_label.rs` in hermetic-grader-supervisor checks
strict transport, safe opens, label-free sandbox input and correct output labels;
`test_all_run_images_hash_equal_and_contain_no_run_label` and
`test_image_difference_fails_before_any_vm_boot` execute the shell harness with
offline builders. Existing test fixtures now place labels on result drives
instead of in configs; their original behavior assertions are retained.

For the real six-boot check on the prepared KVM host, from this worktree root,
let the script allocate a fresh work directory:

```sh
bash scripts/integration/grader-vm-smoke.sh
```

The script requires the three hashes within each variant to match before boot
and removes the images on success. This also executes the sandbox
probe in all six VMs and requires the empty/gold verdicts below. These VM checks
cannot run in the review sandbox because `/dev/kvm` is unavailable.

The interrupted implementation recorded the following result. The current review
environment has no `/dev/kvm`, so these six boots have not been independently
verified here. Run the command above on a KVM-capable host to close that check.

Previously recorded result:

```
grader serial: grader-init clock=1700000000      (all six boots)
empty: verdict rc=2 {"status":"unresolved","reasons":["f2p_failed"], ... passed 1, failed 1 ...}
gold:  verdict rc=0 {"status":"resolved","reasons":[], ... passed 2 ...}
```

Each boot takes about 1.7 s.

## Grader PID 1

`hermetic-grader-init` is a binary in the hermetic-execd crate (`src/grader.rs`). It is static and `forbid(unsafe_code)`. It reuses execd's clock rule (`boot::read_clock`, which was factored out of `Config::parse`) and execd's clock setter (`real::set_realtime`). It runs these steps in order:

1. Checks that it is PID 1.
2. Mounts `/proc` read-only.
3. Reads `hermetic.t`, sets CLOCK_REALTIME and logs the clock line. Nothing writable exists before this step.
4. Mounts tmpfs on `/tmp` (nosuid, nodev, 256 MiB).
5. Mounts a private devpts on `/dev/pts`.
6. Runs the supervisor with `--config /etc/hermetic/grader/run.json --result-disk /dev/vdb`, an empty environment and a 4 h backstop.
7. Logs `done` or `failed`, syncs and ends the VM.

Any failure ends the VM. The clock check uses the serial line because the HGRD result schema has no time field. The guest stamps that line right after `clock_settime`.

## What broke and how it was fixed

1. **Power-off does not end the VM.** `reboot(POWER_OFF)` only halts the sealed kernel (`reboot: System halted`), and Firecracker keeps running, so `wait_exit` timed out. The grader PID 1 now ends with `reboot(RESTART)`. With `reboot=k`, Firecracker exits on the i8042 reset. Order tests: `grader::tests::*`. Boot regression: `boots_grader_and_collects_result_drive`. execd's own power-off has the same property; its harness kills the VM instead.

## Development-only surface

`DevUnjailed::serial()` returns the first 64 KiB of guest serial output. It exists only with the `dev-unjailed` feature. Production runners expose no guest output.

## Still open

- The read-only work or patch drive. The patch is baked into the image for now.

## Network VM

Run from the worktree root on the prepared host:

```sh
scripts/integration/net-smoke.sh
```

An optional work directory must be new, with a parent not writable by other users. The
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


## Running the isolation checks

Offline gates run without root or KVM. Root-only tests print their prerequisite
and return when not root. In a disposable Linux grading environment with root,
mount/namespace privileges and cgroup-device BPF support, run from this worktree:

```sh
export CARGO_TARGET_DIR="$PWD/target"
cargo test --offline -p hermetic-grader-supervisor --no-run
sudo env PATH="$PATH" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" cargo test --offline -p hermetic-grader-supervisor -- --nocapture
```

With `/dev/kvm` available and the pinned kernel, Firecracker, Docker base image
and venv staged as above, run these exact commands from the worktree root (each
script creates a fresh temporary work directory when no argument is supplied):

```sh
bash scripts/integration/grader-vm-smoke.sh
bash scripts/integration/grader-smoke.sh
```

The supervisor mounts cgroup v2 privately and attaches the ordered device BPF
rules before joining the test cgroup. Only `ENODEV` from mounting cgroup2 permits
omitting that layer, for kernels built without cgroup v2. Such kernels still get
the PID/mount boundary, minimal `/dev`, no-new-privileges and capability drop.
All permission, controller, attachment and verifier failures stop setup. The
sealed grader kernel policy requires cgroup v2 and device BPF, so the expected VM
path includes the filter. The privileged test independently opens a planted
block node to verify denial, and tests namespace identity, mount permissions,
capabilities, environment, fd handoff and teardown on both exit and timeout.


## Smoke work storage and cleanup

All four integration smoke scripts (`boot-smoke.sh`, `net-smoke.sh`,
`grader-smoke.sh`, `grader-vm-smoke.sh`) allocate fresh work directories under
`${HERMETIC_SMOKE_DIR:-$HOME/.cache/hermetic-smoke}` by default. Choose a disk-backed
location with enough free space for the images. The host's RAM-backed `/tmp` is
not used for these work directories. Missing cache directories and each work
directory are created with mode 0700, and symlink components are refused.

A single optional `NEW_WORK_DIR` argument selects an exact fresh path instead;
its parent must exist, be owned by the caller and not be writable by other users.
Existing directories, files and symlinks are refused without chmod or deletion.
The shared `smoke_work.py` runner removes only the work directory it created,
using held directory descriptors and bounded cleanup that never follows links.
It refuses cleanup if the directory entry has been replaced.

A successful run removes its work directory, including images and logs. Failure
(including INT, TERM or HUP) retains the work and prints its path on stderr for
inspection. The nested grader VM work follows the same rule; a failed full grader
smoke retains the outer extraction artifacts as well. The network script checks
KVM/TUN access before allocating work. Cleanup failures return a nonzero status.
No script sweeps or deletes artifacts from earlier runs.

Rootfs Python tests place their sealcheck copy, staging files and image outputs
under pytest's per-test `tmp_path`, and discard that tree after assertions, even
on test failure. This avoids retaining large images in pytest's recent-run cache.
Offline regressions in `test_smoke_work.py` exercise cleanup, failure retention,
symlink rejection, directory substitution and signal handling on small fixtures.
The grader shell tests snapshot their fixture artifacts before successful cleanup
so the existing image, extraction and verdict assertions remain in place.
