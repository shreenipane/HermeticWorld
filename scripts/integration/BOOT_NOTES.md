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

# Grader smoke (development, offline, VM not booted yet)

Command, from the worktree root:

```
scripts/integration/grader-smoke.sh /tmp/hermetic-grader-smoke
```

Fixture task: `scripts/integration/fixtures/grader-task/`.
- `repo/` is a two-function module with `tests/test_calc.py`.
- `test_double` passes on base (P2P); `test_add` fails on base (F2P).
- `gold.patch` fixes `add`, and `empty.patch` is the empty patch.
- `plan.json` is the grading plan (no mutants, no equivalents).

For each variant, the script:

1. Builds a grader tree.
   - Base userland: the local `python:3.12-alpine` image, exported with `--pull never`.
   - pytest 9.2.0 and its pure-Python dependencies, copied from the project venv.
   - The `hermetic_grader_records` plugin.
   - The repo with the patch applied, under `/work/repo`.
   - Static `/sbin/hermetic-grader-supervisor`.
   - One run config per run in `/etc/hermetic/grader/run-R{0,1,2}.json`.
2. Builds a D4-checked grader image of that tree with `hermetic_slice.rootfs.build_rootfs`. Both variants give 95420416 bytes, and the build is reproducible across runs.
3. Runs the real grading chain from the same tree, in a container with no network, read-only, no capabilities, no-new-privileges and a non-root user. The chain is: supervisor, then `python -s -m pytest -p hermetic_grader_records.plugin` with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, then HGR1 records, then a 1 MiB HGRD result disk. It runs once per run: R0, R1, R2.
4. Validates the disks on the host with `hermetic-grader-verdict`: strict parser, then the differential verdict.

Result:

```
empty: verdict rc=2 {"status":"unresolved","reasons":["f2p_failed"], ... passed 1, failed 1 ...}
gold:  verdict rc=0 {"status":"resolved","reasons":[], ... passed 2 ...}
```

## Why the grader VM is not booted

There is no grader-mode PID 1. Nothing was bypassed to get around that:

- `hermetic-vmm` refuses vsock for `Role::Grader` (TR-GR-1), and it refuses a standalone `--` in boot arguments.
- execd binds vsock 5000 as its last boot step and powers off if that fails. So execd cannot be the grader's PID 1.
- `hermetic-init` only execs execd.
- The supervisor needs `--config` and `--result-disk` flags. It neither sets the clock nor mounts anything, and it does not power off.

Because the VM is not booted, two things are not checked yet:

- that the grader clock equals `T_clock`;
- that the supervisor applies the `hermetic-grader-sandbox` plan. Nothing calls that crate yet, and the supervisor's `RealOs` has no namespaces, capability drop or device cgroup (see its README).

## What broke and how it was fixed

1. **Result disk header endianness.** The supervisor wrote the HGRD header integers little-endian. The host parser reads them big-endian, so every real result disk was classified as tampered. The supervisor now writes big-endian.
2. **Canonical JSON mismatch.** The supervisor sorted keys. The host re-serializes in schema field order and rejects anything else (`non_canonical_json`). The supervisor now serializes in schema order.
   - Test for 1 and 2: `supervisor_result_disk_is_accepted_by_host_parser` (`crates/hermetic-grader-supervisor/tests/host_format.rs`). It checks that the host accepts the supervisor's image and that the two encoders' images are byte-identical. The supervisor's known-answer image hash was updated.
3. **`build_rootfs` failed on non-ASCII names.** mke2fs ran with `LANG=C`, and libarchive refuses PAX names and link targets that are not ASCII under an ASCII locale. Alpine's CA store has such names. mke2fs now runs with `LANG=C.UTF-8`.
   - Tests: `test_regression_mke2fs_runs_under_utf8_locale` and `test_regression_non_ascii_names_and_link_targets_build`.
4. **Script detail.** Docker's `--tmpfs /tmp` is not world-writable by default, so a non-root test run had no temporary directory. The supervisor then correctly reported `supervisor_crash` and `infra_error`. The script mounts it with `mode=1777`.

## Known gaps (not fixed here)

- **Result fd hand-over.** The supervisor's `RealOs` hands the record pipe over on fd 2 and advertises `HERMETIC_RESULT_FD=2`. The plugin requires an fd of 3 or higher. The smoke bridges this with `sh -c 'exec 3>&2 2>/dev/null; exec python ...'` and `HERMETIC_RESULT_FD=3`.
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

- Supervisor isolation (task B).
- The read-only work or patch drive. The patch is baked into the image for now.
- The fd 3 bridge.
