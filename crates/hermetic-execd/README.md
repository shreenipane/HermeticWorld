# hermetic-execd

Linux guest PID 1, library and binary. The `Sys` trait isolates privileged effects;
`Linux` is the guest implementation and `tests/contract.rs` supplies a recording
implementation. The binary refuses to boot unless its PID is 1. Do not invoke
the Linux implementation's boot or shutdown operations on a host.

## Boot contract

The kernel mounts the sealed base read-only. It provides devtmpfs at `/dev` and
the serial console as standard error. The trusted boot environment must make
`/proc/cmdline` and the kernel's `/proc/self/{exe,fd}` interface readable when it
hands PID 1 to execd. This early proc mount is read-only and is hidden by the
root switch; execd mounts the final `/proc` afterwards. Execd never mounts
anything before setting the clock. Provisioning that early proc interface is a
kernel/initramfs integration prerequisite, not something the binary can create
before its first clock effect. Without it, execd powers off silently. T3.3 must
verify this handoff; a stock direct `init=hermetic-execd` boot without early proc
does not satisfy the contract.

On first boot that early proc interface comes from the trusted shim
`/sbin/hermetic-init` (binary `hermetic-init` in this crate, `src/early.rs`), booted
with `init=/sbin/hermetic-init`. It lives on the sealed read-only base next to
execd. As PID 1 it does exactly two things: it mounts procfs read-only (nosuid,
nodev, noexec) at `/proc` and execs `/sbin/hermetic-execd` with no arguments and
an empty environment. execd then runs as the same PID 1. The shim reads no clock,
writes nothing, logs nothing and parses no input. If the mount or the exec fails,
it powers the VM off. It refuses to run unless it is PID 1. The kernel itself
mounts the base read-only and devtmpfs at `/dev` (`CONFIG_DEVTMPFS_MOUNT=y`).
No initramfs is used on first boot, because an initramfs suppresses both of those
kernel mounts. The trusted initramfs remains the TR-EXD-6 reboot path
(`hermetic.initramfs=1`).

The base contains ordinary, symlink-free directories `/mnt/hermetic-overlay`,
`/mnt/hermetic-root`, `/dev`, `/proc`, `/sys`, `/dev/pts`, `/dev/shm`, `/tmp`,
`/run`, `/etc` and the spec's working directory. Network-enabled images also
contain a static, regular, symlink-free `/bin/busybox` with `ip` and `sysctl`
applets. `/tmp` and `/run` are sealed
overlay directories, never tmpfs. `/etc/resolv.conf` is absent or a regular
file, not the symlink used by some distributions. Devices are provided by the
kernel, not taken from a previously touched disk. Standard error must be the
serial console, never a disk file. The sealed kernel must support openat2,
overlayfs, ext4, devtmpfs, procfs, sysfs, devpts, vsock, and
`utimensat(AT_EMPTY_PATH)` (Linux 6.6 or later).

Kernel arguments:

| Argument | Meaning |
| --- | --- |
| `hermetic.t=1700000000` | Required decimal Unix seconds, inclusive range 315532800–4102444799 (1980–2099) |
| `hermetic.overlay=/dev/vdb` | Upper ext4 block device; default `/dev/vdb` |
| `hermetic.spec=/etc/hermetic/run-spec.json` | Guest spec; default shown |
| `hermetic.initramfs=1` | Trusted reboot mode; default `0` |

Duplicate Hermetic options, unknown Hermetic options, malformed flags, and
non-normalized paths fail closed. Unrelated kernel options are ignored.
`/proc/cmdline` is size capped. A missing/malformed clock yields `InvalidClock`,
binary fallback exit code 2, and no log or filesystem write before poweroff.
Other failures have distinct static reason values and fallback exit code 1.
After the clock is set, serial failure lines contain only current guest Unix
seconds and a static reason. No OS error text, command text, paths, environment
values, inherited locale, or host identity is logged. Poweroff itself cannot
deliver an exit status to the VMM; the host must classify an absent readiness
connection separately from a successful frozen shutdown.

The normal effect order is clock, read-write ext4 mount, retain upper descriptor,
create upper/work, assemble overlayfs, move devtmpfs, switch root, mount proc,
sysfs, devpts and `/dev/shm`, stamp `/dev`, validate/apply the spec (including
network setup), optionally
start its initial command, then bind vsock 5000. A failed step runs no later
boot step. The read-only root is checked before mounting the upper disk.
Mount targets and lower/upper/work directories are pinned descriptors. Device
stamping uses O_PATH, no-follow traversal, stable byte ordering and NO_XDEV;
it skips nested mounts, including same-device bind mounts. It stamps symlink
inodes without following their targets, never opens device nodes for I/O, and
never chmods anything.

## GraderVM PID 1

`/sbin/hermetic-grader-init` (binary `hermetic-grader-init`, `src/grader.rs`) is the
GraderVM's PID 1, booted with `init=/sbin/hermetic-grader-init`. It shares execd's
clock rule (`boot::read_clock`) and clock setter (`real::set_realtime`). Order:
refuse unless PID 1; mount procfs read-only; read `hermetic.t=` from
`/proc/cmdline` and set CLOCK_REALTIME (nothing writable exists before this);
write `grader-init SECONDS clock` to the serial console; mount `/tmp` as tmpfs
(nosuid, nodev, 256 MiB) and a private devpts at `/dev/pts`; run
`/sbin/hermetic-grader-supervisor --config /etc/hermetic/grader/run.json
--result-disk /dev/vdb` with an empty environment, bounded by a 4-hour backstop;
write `grader-init SECONDS done|failed`; sync; end the VM. Any failure ends the VM.
The end is `reboot(RESTART)`: with `reboot=k` Firecracker exits on the i8042 reset,
while `reboot(POWER_OFF)` only halts the sealed kernel and leaves Firecracker running.
It opens no vsock and configures no network. Execd-only `hermetic.*` options
are ignored by the grader; the clock option follows the same strict rule.

## Run spec

All fields except `network` are required; unknown fields, including resource and
network fields, and duplicate
environment keys are refused. This guest schema extends the manifest's current
smaller run-spec schema; it reuses `hermetic_common::Resources`, while requiring
explicit numeric `uid` and `gid`. The launcher must produce this guest JSON,
rather than pass a manifest's string-valued `user` through unchanged.

```json
{
  "env": {"PATH": "/usr/bin:/bin", "LANG": "C"},
  "workdir": "/work",
  "uid": 1000,
  "gid": 1000,
  "entrypoint": ["/usr/bin/service"],
  "command": ["--foreground"],
  "hostname": "world",
  "resolv_conf": "nameserver 10.0.0.1\n",
  "network": {"address": "10.0.0.15", "prefix": 24, "gateway": "10.0.0.1", "mtu": 1500},
  "resources": {"vcpus": 2, "memory_mib": 512, "disk_mib": 1024, "wall_time_s": 300}
}
```

Omit `network` (or use `null`) for a networkless image. When present, all four
members are required: canonical IPv4 address strings, a prefix in 1–30 and an
MTU in 576–1500. Address and gateway must be distinct usable RFC1918 hosts in
the same subnet, excluding network/broadcast addresses. The launcher sets
`gateway` to NetVM's link address and points `resolv_conf` at NetVM; execd cannot
authenticate the peer's address. This configures only the fixed `eth0` device.

After clock setup, root assembly and resolver installation, execd disables IPv6
for all/default interfaces, brings up loopback, sets eth0's MTU and address,
brings eth0 up and adds the default route via NetVM. All seven applets must
succeed before the entrypoint or vsock listener starts. A failure/timeout
powers off with a static reason; applet output is drained and discarded.
The implementation uses busybox `ip`/`sysctl` with fixed argument positions
instead of adding unsafe netlink code or a dependency. Validated address and
numeric fields are rendered canonically, with no shell or PATH lookup.
Boot commands run as uid/gid 0 with no supplementary groups, an empty
environment, cwd `/`, a 64 MiB address-space cap and a 5-second deadline per
command (including startup), using the existing supervised child path.
The busybox inode is pinned from the sealed base before switching root; no
overlay replacement can redirect execution. Network setup is boot convenience,
not an AgentVM security boundary; NetVM/host isolation still enforces egress.

The initial argv concatenates entrypoint and command. Empty arrays start no
initial process. The initial child is supervised and its output is drained and
discarded so it cannot block or consume a logging budget. It is not restarted.
RPC exec supplies a complete argv, using the same environment, cwd, credentials
and resource declarations each time. Programs must be absolute regular files.
The `/bin/bash` shell is pinned from the sealed base before overlay assembly on
both first boot and trusted-initramfs reboot. Its image symlinks (including
`/bin -> usr/bin` and absolute targets) resolve inside that held root with
`openat2(IN_ROOT | NO_MAGICLINKS | NO_XDEV)`; mounted runtime filesystems cannot
supply the shell. Kernel `PATH_MAX` (4096 bytes) and
`MAXSYMLINKS` (40 traversals) bound resolution. Only a regular inode on local
guest storage is opened for reading, through its pinned descriptor; absent or
invalid base shells fail closed when requested, without an overlay fallback.
Every other program path and all cwd/upload/download paths remain symlink-free.
No PATH search, shell expansion, passwd/group lookup or inherited environment
is used. Resolve `/bin/sh` or other aliases to their regular image/spec paths.

The same pinned trusted execd executable launches a child helper. Pinned
cwd/executable descriptors and a bounded startup channel cross into it; the
upper freeze descriptor is CLOEXEC. The channel is armed by the helper and
closed on successful program exec; validation, credential and exec failures
are reported before entrypoint startup or reboot authorization succeeds.
Both copies of inherited directory/channel descriptors are CLOEXEC, so they
do not leak into the program. The child creates a session, acquires a controlling terminal for TTY
requests, changes cwd through its descriptor, sets address-space and zero-core
limits, clears supplementary groups, sets all gid values, then all uid values,
clears its inherited signal mask, and executes its pinned program with exactly
the sorted spec environment. The VMM provisions vCPU and ext4 disk size from the
declarations; these declarations do not purport to constrain hostile guest root.
PTY allocation opens the pinned `/dev/pts/ptmx` node in the newly mounted devpts
instance. Ordinary command stdin receives EOF through a pipe, without opening
`/dev/null` through a mutable path. Per-request wall timeout includes helper
startup and is enforced by PID 1 using one monotonic deadline. The
VMM also owns the declared total run wall-time limit.

PID 1 drains both output pipes (or a PTY), handles TERM/INT/HUP through signalfd,
forwards them to the foreground process group (initial child when idle), and
reaps all other direct children, including adopted orphans, while preserving
managed exit statuses. An output cap discards further bytes, sets `truncated`,
and still reaps the process. Final output collection has its own work bound;
exhausting it conservatively marks the reply truncated. Timeout kills the group and direct child and polls
for exit with a bounded deadline. An unkillable child causes a static
`child_stuck` reply and poweroff; a frozen success is never reported in that
case. No worker threads or unbounded output collectors are created.

## Frames and filesystem operations

AF_VSOCK stream port **5000**, guest listener; only host CID **2** is accepted.
One request and one reply per accepted connection. The server handles one
connection and foreground command at a time (plus the optional initial child).
The kernel listen backlog is bounded to 1; queued connections are not active
commands. Both frame input and reply output have absolute deadlines, so a peer
cannot extend a frame indefinitely with occasional bytes.

A frame is `payload_length: u32 little endian`, followed by exactly that many
UTF-8 JSON bytes. The length must be nonzero and at most `MAX_FRAME`, checked
before allocation. Unknown types, unknown fields, invalid JSON, invalid request
values, truncated frames and oversized frames get a static error reply if the
stream still permits one. Malformed input is never echoed. This is a separate
protocol from the common crate's HTTP-oriented HWRQ/HWRS frames, retaining that
module's little-endian and validate-before-allocation conventions.

Requests:

```json
{"type":"exec","argv":["/usr/bin/program","argument"],"tty":false,"timeout_ms":1000}
{"type":"upload","path":"/work/input","data":[65,66,10]}
{"type":"download","path":"/work/result"}
{"type":"status"}
{"type":"authorize"}
{"type":"shutdown"}
```

Replies:

```json
{"type":"exec","code":0,"output":[65,10],"truncated":false,"timed_out":false}
{"type":"download","data":[65,10]}
{"type":"status","locked":false,"output_bytes":2,"guest_time_unix":1700000000}
{"type":"ok"}
{"type":"error","reason":"invalid_input"}
{"type":"frozen"}
```

Byte arrays preserve arbitrary binary output. `code` is null for signal exits.
`truncated:true` is the explicit truncation marker; it is separate from binary
output, including when the run budget is zero. Object fields follow the declared
struct order and environment keys follow byte order, with known-answer tests.

Uploads validate paths/data before mutation, pin each parent beneath the root,
reject symlinks, `..` and special destinations, create an exclusive temporary
regular file in the same directory, write it through its descriptor, assign the
run spec's uid/gid and private mode 0600, stamp it
with the **current guest** clock, fsync, rename and fsync the directory. Frames
have no timestamp field. The resolver configuration uses mode 0644 so non-root
commands can read it. Temporary-name selection skips the destination and retries
collisions at most `MAX_UPLOAD_ATTEMPTS` times. Downloads pin and verify a regular inode before opening
it for reading and read at most the transfer cap plus one byte. FIFOs/devices
are never opened as regular files. The only internal magic-link resolutions are
kernel `/proc/self/exe` and `/proc/self/fd/N` for already pinned descriptors; no
guest-provided symlink is followed. Procfs, the PID 1 process directory and its fd
directory are verified and retained before any guest command runs, including
across the root switch. Descriptor reopens and helper execution use those
retained directories, so covering visible `/proc` cannot redirect them.
Ordinary file reads accept only ext4, tmpfs and overlayfs, refusing regular-looking
pseudo-files such as `/proc/kmsg`; internal proc metadata uses the retained
procfs handle separately. Reads use nonblocking descriptors, a byte cap and
`FILE_IO_TIMEOUT_MS` checks between chunks. Those checks cannot interrupt a
kernel-stalled local filesystem operation; a hard deadline for that case needs
process isolation for filesystem work.

Guest root can alter the guest kernel and tamper with PID 1, its descriptors,
namespaces, or the filesystem, including racing names used by atomic rename.
As required by the project threat model, no security boundary or trusted evidence
depends on this guest daemon surviving a hostile root. Path containment protects
ordinary RPC filesystem operations; the VMM and extraction boundary protect the
host. The host records `unclean_shutdown` unless it receives `frozen`.

Shutdown executes TERM-all, bounded wait, KILL-all, bounded wait, verifies no
other userspace processes remain (kernel threads are identified by the bounded
`/proc/PID/stat` flags field), sync, FIFREEZE on the descriptor retained at boot,
write/flush `frozen`, then poweroff. A freeze/wait failure produces an error,
never `frozen`. A broken reply connection still leads to poweroff. There is no
path lookup to reacquire the upper disk and no thaw operation.

## Trusted reboot from initramfs (TR-EXD-6)

Put this binary and its runtime (prefer a static build) in a **trusted initramfs**,
outside every disk writable by the agent. The trusted handoff executes this
binary as PID 1 from that initramfs, never `/sbin/init` from a touched disk, and
provides the early proc/dev/console interfaces described above. Include ordinary
staging directories `/mnt/hermetic-base`, `/mnt/hermetic-overlay` and
`/mnt/hermetic-root`. For networking, `/bin/busybox` is pinned from the separately
mounted sealed base before overlay assembly, while the trusted child helper
comes from the initramfs. Pass `hermetic.initramfs=1`, `hermetic.t=...`, and the
appropriate overlay/spec options. The sealed base is `/dev/vda`, separate from
the writable upper `/dev/vdb` by default.

Build the archive with `python -m hermetic_slice.initramfs --execd EXECD
--early-init HERMETIC_INIT --t-clock 1700000000 --output trusted.cpio` (set
`PYTHONPATH=python` from the worktree root). Both inputs must be static ELF64
x86-64 binaries, built with `bash scripts/build-trusted-execd.sh`. This offline,
locked build remaps workspace and Cargo source paths to fixed `/src` and `/cargo`
prefixes, so compiler panic locations do not expose host usernames or paths.
The builder checks
the ELF program headers and rejects interpreters and dynamic dependencies.
It emits uncompressed `newc`, sorted names, fixed inode numbers, uid/gid 0,
T_clock mtimes, zero device metadata except the generated 5:1 console, and zero
padding. It reads no host directory contents or metadata into the archive.
`/init` is the early proc shim; `/sbin/hermetic-execd` is the trusted daemon.
Publication is atomic and mode 0600 in a caller-owned, private directory.
The printed SHA-256 must be pinned in the trusted VMM specification, independently
of anything on the touched disk. Identical binary inputs and T_clock produce
identical archives; binary toolchain reproducibility remains a build input.

This mode sets the clock first, mounts fresh devtmpfs (the kernel skips its
devtmpfs automount when running an initramfs), mounts `/dev/vda` read-only as the overlay lower,
and then performs the ordinary assembly. Status reports `locked:true`.
Neither the image's entry point nor any exec request is started until host CID 2
sends `authorize`. Status, upload, download and shutdown work while locked.
Authorization starts the initial command exactly once; only successful startup
unlocks RPC execution. The host must authorize based on its trusted task policy,
not on any value read from a touched disk. A fresh boot never remembers a prior
authorization. The executable used for child helpers is retained from the trusted
initramfs; it is not rediscovered on the overlay.

The builder caps each executable at `MAX_BINARY_BYTES` (24 MiB), the archive at
`MAX_INITRD_BYTES` (64 MiB), ELF program headers at `MAX_PROGRAM_HEADERS` (128),
dynamic entries at `MAX_DYNAMIC_ENTRIES` (4096), and publication attempts at
`MAX_PUBLICATION_ATTEMPTS` (16). Only trusted regular input files are opened,
through pinned descriptors; symlink components, FIFOs and devices are refused.

## Caps

Caps are named constants in `src/lib.rs`, `src/boot.rs`, `src/spec.rs` and
`src/network.rs`.

| Constant | Limit |
| --- | --- |
| `MAX_CMDLINE` | 4 KiB |
| `MIN_CLOCK`, `MAX_CLOCK` | 315532800–4102444799 |
| `MAX_SPEC` | 64 KiB JSON |
| `MIN_NETWORK_PREFIX`, `MAX_NETWORK_PREFIX` | 1–30 |
| `MIN_NETWORK_MTU`, `MAX_NETWORK_MTU` | 576–1500 bytes |
| `NETWORK_COMMAND_TIMEOUT_MS`, `NETWORK_MEMORY_MIB` | 5000 ms per applet; 64 MiB address space; seven sequential commands, zero retained output bytes |
| `MAX_ENV`, `MAX_ENV_NAME`, `MAX_STRING` | 128 entries; 128-byte names; 4096-byte strings |
| `MAX_HOSTNAME` | 63 lowercase ASCII letters/digits/hyphens |
| `MAX_PATH`, `MAX_COMPONENTS`, `MAX_COMPONENT_BYTES` | 4096 bytes; 128 components; 255 bytes/component |
| `MAX_ARGS`, `MAX_ARG_BYTES`, `MAX_CHILD_PAYLOAD` | 128 args; 32 KiB encoded argv; 120 KiB helper payload |
| `MAX_VCPUS`, `MAX_MEMORY_MIB`, `MAX_DISK_MIB`, `MAX_WALL_TIME_S` | 256; 1048576 MiB; 16777216 MiB; 86400 seconds; all positive |
| `MAX_TRANSFER` | 1 MiB per upload/download |
| `MAX_FRAME` | 4 MiB + 64 KiB (fits JSON-encoded binary arrays) |
| `MAX_COMMAND_OUTPUT`, `MAX_RUN_OUTPUT` | 1 MiB/command, 16 MiB/run |
| `MAX_TIMEOUT_MS` | 300000 ms, positive |
| `FRAME_TIMEOUT_MS` | 5000 ms each for request and reply |
| `MAX_CONNECTIONS`, `MAX_COMMANDS` | 1 active connection; 2 direct commands including initial child |
| `MAX_DEV_NODES`, `MAX_DEV_DEPTH` | 16384 nodes; 32 levels |
| `MAX_CHILDREN_BYTES`, `MAX_REAP_BATCH` | 64 KiB child listing; 4096 children/proc entries per sweep |
| `MAX_PROC_STAT` | 4096 bytes per process metadata record |
| `FILE_IO_TIMEOUT_MS` | 5000 ms, checked between file-read chunks |
| `MAX_UPLOAD_ATTEMPTS` | 16 temporary-name attempts per write |
| `SHUTDOWN_WAIT_MS`, `CHILD_KILL_WAIT_MS` | 2000 ms per wait |
| `CHILD_START_TIMEOUT_MS` | 5000 ms; also bounded by the request deadline |
| `IO_BUFFER`, `MAX_DRAIN_READS` | 8192 bytes; 16 reads/stream/tick |
| `MAX_FINAL_DRAIN_READS` | 144 reads/stream after child exit |
| `/dev/shm` | 64 MiB tmpfs |

## Verification and remaining VM work (T3.3)

All fixtures are handwritten and offline. Host tests never mount filesystems,
change the host clock/hostname, signal unrelated processes, freeze filesystems,
power off, or change host settings. The library and binary deny unsafe code;
only `sys.rs` allows it, with individually documented syscall wrappers.

| Requirement | Tests |
| --- | --- |
| Clock parsing, bounds, fatal silence | `cmdline_strict_clock_bounds_defaults_and_initramfs`, `every_boot_failure_stops_later_effects_and_reports_reason` |
| TR-EXD-1, TR-EXD-2 boot order and every failure | `boot_known_answer_no_tmp_or_run_tmpfs`, `every_boot_failure_stops_later_effects_and_reports_reason` |
| Strict spec, all validation before applying, stable env | `spec_strict_fields_caps_names_ids_paths_and_resources`, `frames_known_answer_unknown_malformed_oversize_and_every_truncation` |
| Network validation, boot order, fixed argv, credentials, failure/timeout | `network_spec_strict_schema_subnet_hosts_and_numeric_caps`, `network_boot_order_fixed_argv_root_environment_and_every_failure`, `network_validates_before_commands_and_rejects_failure_signal_and_timeout` |
| Trusted network executable on reboot, symlink/FIFO refusal | `network_executable_is_pinned_before_overlay_and_special_files_fail_closed` |
| Credentials, per-command spec | `credentials_drop_in_groups_gid_uid_order_and_stop_on_failure`, `exec_applies_spec_tty_timeout_and_both_output_caps_and_reaps` |
| TR-EXD-3 entry point, maintenance, orphan handling | `initramfs_exec_is_locked_until_explicit_authorize`, `generic_listener_is_serial_and_services_pid1_maintenance`, `reaper_handles_adopted_children_without_stealing_managed_statuses`, `startup_handshake_requires_armed_channel_and_exec_or_reports_failure_and_timeout`, `helper_reports_validation_failure_and_does_not_drop_credentials` |
| TR-EXD-3 signals, actual PTY | `signal_forwarding_targets_foreground_and_preserves_entrypoint`, `allocated_pty_has_real_terminal_and_output_is_drained` |
| TR-EXD-4 framing, malformed data, caps, timeout | `frames_known_answer_unknown_malformed_oversize_and_every_truncation`, `absolute_stream_deadline_expires_even_after_partial_frame`, `absolute_reply_deadline_bounds_a_peer_that_never_reads`, `supervisor_captures_both_pipes_truncates_and_reaps`, `continuous_output_cannot_starve_timeout_and_zero_budget_still_reaps`, `final_drain_preserves_buffered_tail_and_marks_exhaustion`, `stuck_child_is_terminal_and_never_claims_frozen_shutdown` |
| Uploads/downloads, atomic replacement, guest stamps | `rpc_transfers_validate_before_sys_and_bound_downloads`, `descriptor_transfers_atomic_stamp_and_reject_symlink_fifo_and_escape` |
| `/dev` stamping without symlink traversal | `dev_walk_stamps_nodes_and_symlinks_without_following_targets` |
| TR-EXD-5 shutdown order, retained descriptor, failure | `shutdown_exact_order_retained_handle_and_disconnected_reply` |
| TR-EXD-6 trusted reboot lock | `initramfs_exec_is_locked_until_explicit_authorize`, `authorization_failure_stays_locked_and_empty_initial_command_never_spawns` |
| Serial/static logs, no pre-clock time | `log_errors_are_static_and_preclock_is_silent` |
| Host invocation and malformed helper argv | `binary_refuses_host_boot_and_non_utf8_or_extra_helper_arguments_silently` |
| Kernel-thread shutdown classification | `shutdown_ignores_kernel_threads_but_refuses_userspace_and_bad_metadata` |
| Retained proc access after visible-path denial | `pinned_proc_reopens_work_when_visible_proc_opens_are_denied` |
| Upload ownership and resolver permissions | `uploads_use_command_owner_and_private_mode_resolver_is_readable` |
| Terminal authorization failure | `stuck_authorization_child_is_terminal_and_cannot_launch_again` |
| VMM status clock and complete frame | `status_frame_supplies_vmm_guest_clock_schema` |
| Shared production child effects and failure propagation | `production_child_path_applies_cwd_environment_resources_and_credentials` |
| Temporary-name collision handling | `upload_destination_cannot_collide_with_its_temporary_name`, `upload_temporary_collisions_have_a_work_cap_and_preserve_existing_files` |
| Pseudo-file refusal, file-read byte/time budgets | `transfers_refuse_regular_looking_pseudo_files`, `file_read_caps_deadlines_and_nonblocking_failures` |

T3.3 must run the real binary as PID 1 in Firecracker and verify the trusted
early-proc handoff, read-only kernel root, first writable timestamp, ordinary
`/tmp`/`/run` persistence, overlay mount/move/switch behavior, non-crossing of
actual `/dev` submounts, UID/GID/group changes and controlling-terminal session,
orphan adoption by real PID 1, signalfd delivery, actual AF_VSOCK port/CID
filtering, disk-descriptor retention across root switch and path replacement,
FIFREEZE consistency and reply-before-poweroff, shutdown failure classification,
and a touched-overlay reboot that cannot execute overlay code until authorized.
Those privileged integrations cannot be exercised in the unprivileged host
sandbox. Host policy tests are not evidence of a successful VM boot.
