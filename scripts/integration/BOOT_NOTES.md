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

# Grader smoke (development, offline, VM)

Command, from the worktree root:

```
scripts/integration/grader-smoke.sh /tmp/hermetic-grader-smoke
```

Fixture task: `scripts/integration/fixtures/grader-task/`.
- `repo/` is a two-function module with `tests/test_calc.py`.
- `test_double` passes on base (P2P); `test_add` fails on base (F2P).
- `gold.patch` fixes `add`, and `empty.patch` is the empty patch.
- `plan.json` is the grading plan (no mutants, no equivalents).

For each variant the script applies the patch to a fixture work tree, emits a
HEXT v1 stream with `hermetic-extract-agent`, and publishes the validated result
with `hermetic-extract-validate`. It then passes those published trees to
`grader-vm-smoke.sh`, which builds and boots one image per run. This preserves the
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
scripts/integration/grader-vm-smoke.sh /tmp/hermetic-grader-vm-smoke
```

For each variant (empty, gold) and each run (R0, R1, R2), the script:

1. Builds the grader tree from the "Grader smoke" section. The patch is applied on the host. The tree adds static `/sbin/hermetic-grader-init` and has one fixed config, `/etc/hermetic/grader/run.json`. Every run gets its own D4-checked image, and the kernel command line is the same for all of them.
2. Boots the image with hermetic-vmm's `dev-unjailed` runner through `tests/guest.rs::boots_grader_and_collects_result_drive`.
   - Firecracker 1.18.0, kernel `kernel-out-20261113-6.6b`.
   - Boot arguments: `init=/sbin/hermetic-grader-init`, `hermetic.t=1700000000`, `reboot=k panic=-1`.
   - Drives: root `vda` read-only, then `result` `vdb`, which is writable and exactly 1 MiB. No vsock and no network.
3. Waits for the VM to exit (`Vmm::wait_exit`) and checks the serial line `grader-init SECONDS clock` against `hermetic.t`. It then copies the jail's result drive out.
4. Runs `hermetic-grader-verdict` over R0/R1/R2.

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
  `IP_NF_IPTABLES`, `IP_NF_FILTER`, `IP_NF_NAT`, `NF_NAT`, `NF_CONNTRACK`
  and `NETFILTER_XT_TARGET_REDIRECT`. Linux 6.6 builds `xt_tcpudp.o` with
  `NETFILTER_XTABLES`; no separate TCP/UDP-match option exists. These options are
  already required. No clock, timer, RTC, PTP or paravirtual clock feature is added.

NetVM runs `/sbin/hermetic-netvm` as PID 1. It mounts proc for pinned config reads,
sets the guest clock, installs fixed INPUT/OUTPUT service-port filters and a
drop-only FORWARD chain, disables forwarding and IPv6, then brings up eth0 as
`10.0.2.3/24`. It owns the fixture's `10.9.0.1/32`, serves table DNS on
`10.0.2.3:53` and plain HTTP on port 80. Before eth0 is up it also installs a
fixed NAT table: PREROUTING REDIRECT on eth0 TCP 80/443 preserves the port
while changing every destination address to the local NetVM address. This is
the TPROXY fallback; the deny filter still drops 443 pending TLS. Conntrack
restores the original source address on replies. There is no external route.
Boot caps conntrack at 1024 entries, established idle time at 30 seconds,
SYN-receive/time-wait at 5 seconds, fragment reassembly at 256 KiB and 5 seconds.
It lowers the fragment low watermark to 256 KiB before lowering the high
watermark. Linux 6.6 enforces low <= high on both writes; the former high-only
write failed against the default 3 MiB low watermark, halted NetVM before eth0
came up, and caused the owner-run DNS timeout. The offline regression
`fragment_watermarks_boot_with_linux_defaults` checks these kernel constraints
while replaying the actual boot commands. The two-VM rerun remains required.
Any filter, NAT or sysctl failure prevents networking. NetVM forwards bounded frames over one
persistent vsock connection to CID 2 port 5001. Firecracker forwards that port to
`<NetVM vsock UDS>_5001`, where the sandboxed host WorldServer listens. Port 5000
is execd; 5002 is reserved for the gateway.

AgentVM boots execd through `hermetic-init`. The run spec installs a regular
`/etc/resolv.conf` pointing at NetVM. Before starting the agent, the trusted
harness runs the fixed busybox setup through execd as root: IPv6 off, eth0
`10.0.2.15/32`, a link route to `10.0.2.3/32`, and the sole default route via
`10.0.2.3`. The /32 prevents direct ARP to other addresses on the private link;
those connections also reach NetVM. AgentVM loopback and its own address stay
local. Only packets delivered to NetVM are intercepted. The existing run-spec
schema has no network-effect field; automatic eth0 initialization requires an
execd schema/boot change and remains open in PHASES.md.

The test checks allowed DNS, exact GET fixture bytes, POST 405, NXDOMAIN for
unknown DNS, sealed fixture responses for known Host requests sent to
`1.1.1.1`, `192.168.0.1`, `169.254.169.254` and `10.0.2.2`, rejection of unknown
HTTP hosts at those same destinations, blocked unrelated ports, an actual
HTTPS fetch denied on 443, no public DNS answer, ICMP blocked at NetVM itself, and a regular resolver
file. Missing explicit smoke inputs fail. Owning guards kill and reap both VMs
and WorldServer on success or panic.

**Boot status: OPEN here.** The exact command above stops before creating images
or services with `OPEN: cannot open /dev/kvm or /dev/net/tun; run on the prepared host`.
TLS termination, CA-key boot delivery, successful HTTPS and NetVM dm-verity
remain OPEN in PHASES.md. This cut drops 443 and uses D4-checked read-only ext4.
The REDIRECT rule encoder is checked against the pinned Linux 6.6 UAPI with
offline byte interpretation and known-answer layout tests. Kernel installation
and two-VM packet delivery have not been run here.

### OPEN: TLS and successful HTTPS

The task handoff approves rustls, but the current review instruction prohibits
new dependencies and explicitly leaves dependency-requiring work OPEN. The
workspace has certificate minting and trust injection in `hermetic-trust`, and
rustls already appears transitively through the gateway HTTP client. NetVM has
no direct dependency on either TLS or trust minting; adding those dependencies
is prohibited by the current instruction. Implementing a new TLS stack here
is unsuitable.
The HTTPS fetch in the current smoke asserts denial and does not close TR-NET-3.

To finish with dependency authorization:

1. Pin the TLS library and its crypto provider to exact versions; audit the
   resulting lockfile before adding any other crates. Keep the guest static.
2. Add a host-to-NetVM boot protocol on a separate vsock port, bound to that
   VM's private Firecracker UDS. Deliver only its per-world CA material, never
   the host master secret. Authenticate world ID, clock, DNS-table digest and
   public CA digest against the sealed manifest. Cap the frame (64 KiB), time
   (5 seconds), and connection count (one); reject truncation, extra frames and
   mismatches before eth0 starts. Keep secrets in memory only, redact errors,
   and never copy the private key into either image or AgentVM.
3. Reuse `hermetic-trust` for deterministic leaf minting with validity from
   T_clock - 7 days to T_clock + 365 days. Bound issuance, cache size and concurrent
   handshakes; accept only table SNI, reject missing/unknown SNI and ECH, enforce
   matching Host and SNI, permit only HTTP/1.1 GET/HEAD, and reset malformed TLS.
   Inject only the matching public CA into the AgentVM tree using the existing
   trust installer before building its image. Open 443 only after all setup works.
4. Add offline TLS client/server tests with fixed world certificates: successful
   verified GET/HEAD, deterministic DER/validity, unknown or missing SNI/Host,
   mismatched Host, ECH, plaintext on 443, invalid frames, timeout and resource
   limits; inspect both image trees to prove no private key is present.
5. Stage a certificate-verifying static client in the smoke AgentVM. Require a
   successful HTTPS fixture fetch with the installed world CA and a failure with
   an unrelated CA; no insecure verification flags. Test both manifest and
   non-manifest destinations. Replace the current denial expectation only when
   those tests pass.

### OPEN: NetVM dm-verity

Verified prerequisites: `veritysetup` is absent, the pinned kernel's `.config`
has `CONFIG_DM_INIT` disabled, and `hermetic_slice.guest_kernel` requires
`root=/dev/vda` and rejects unapproved dm arguments. The VMM boot validator
also rejects quotes, so it cannot currently carry a quoted `dm-mod.create`
table. No builder or VMM artifact binds a verity root hash to the sealed world.
`CONFIG_DM_VERITY=y` alone does not enforce integrity on the ext4 root.

A complete path needs coordinated builder/kernel/VMM work:

1. Pin and stage veritysetup in the offline build toolchain, or approve and test
   a bounded SHA-256 verity-tree encoder. Use 4096-byte data/hash blocks, a
   world-derived fixed salt, read-only data and hash images, fixed metadata
   times, descriptor-based no-follow reads, checked sizes and atomic outputs.
   Authenticate root hash, block count and salt in the sealed manifest.
2. Enable built-in `CONFIG_DM_INIT=y` in the pinned kernel and policy. Extend
   both boot validators with an explicit NetVM-only grammar for a read-only
   `dm-mod.create` verity table and `root=/dev/dm-0`. Keep all clock-hiding
   arguments. Bind `/dev/vda` to data and a separate read-only `/dev/vdb` to
   hashes, use verity version 1/SHA-256, and fail boot on corruption. Do not
   provide an unverified fallback root or allow AgentVM-controlled root hashes.
3. Extend VMM sealed-artifact validation to check authenticated metadata and
   both images before boot. Retain current ext4 as explicitly unverified until
   the complete verified boot path passes; do not describe read-only as verity.
4. Add offline known-answer tree/root-hash tests, reproducible-build equality,
   invalid sizes/metadata and symlink/race rejection. On the prepared VM host,
   boot a correct pair, then independently corrupt one data block and one hash
   block in private copies: neither corrupt image may reach `netvm_ready` or
   serve bytes. Check read-only remount/write denial and the live dm table.

The current exact VM check (fresh work directory; no KVM in this sandbox) is:

```sh
cd /home/flingboot/.hermetic/worktrees/netvm-tls
scripts/integration/net-smoke.sh "$HOME/hermetic-netvm-tls-smoke"
```

It checks interception and HTTPS denial, not successful TLS or verity. Run the
same command after the TLS/verity extensions with their positive and corruption
assertions before marking those items complete.


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
