# hermetic-vmm

Host-side Firecracker orchestration for Linux x86_64. The library never mounts a
guest disk. It forbids unsafe Rust and uses only the workspace's existing Rust
dependencies. `hermetic-vmm plan SPEC.json` (absolute path), or `plan -` for stdin,
prints a deterministic JSON object containing `api_requests` and `jail_plan`.
The planner does not open image paths. Exit codes: 0 planned, 2 invalid/refused,
1 I/O error. Errors contain fixed reasons, never input text, API fault bodies,
host dates, process output or operating-system error strings.

## Specification and roles

`spec::VmSpec` is the JSON schema. Every struct denies unknown fields. Required
fields are `id`, `role`, `index`, `vcpus`, `memory_mib`, `kernel_image`, `boot_args`,
`root_drive`, `drives`, `reserved_drives`, `vsock` (object or null), `networks`,
`cpu_template`, `clock`, `limits`, and `jail`. Drive objects contain `id`, `path`,
`read_only`. Network objects contain `tap`, `guest_mac`, `peer`. Vsock contains
`guest_cid`, `socket_path` (exactly `/vsock`). Limits contain `pids`,
`file_size_bytes`, `open_files`. Jail configuration contains `base`, `uid_start`,
`gid_start`, `count`, `firecracker`, `jailer`, `netns`.

| Role | Rules |
|---|---|
| `agent` | Read-only root; further drive named `overlay` must be writable; at most one interface, declared peer `net`. |
| `net` | All drives read-only; at most one interface, declared peer `agent`. |
| `extractor` | Read-only root; no network. A writable private disk copy can replay the agent overlay journal. |
| `grader` | Read-only root; no network and no vsock (TR-GR-1). The first further drive is `result`, writable and exactly 1 MiB (`GRADER_RESULT_BYTES`, checked at prepare), so the guest sees it as `/dev/vdb`; every other further drive is read-only. |

The harness is trusted to provision the declared tap peers and isolated network
namespaces. No interface is implicitly bridged or attached to a host route.
`project_mac(role, interface_index)` assigns `02:48:57:RR:00:II`, with role codes
1, 2, 3, 4 in the table's order. It contains no host-derived or random bytes.
`validate_run` validates the entire run before preparation, rejecting duplicate
VM ids, vsock CIDs, jail uids and jail gids. CIDs start at 3. The harness must use
this run-wide validation when preparing multiple VMs. Single-spec validation
cannot determine which other VMs the harness is running.

IDs are 1–48 lowercase ASCII letters/digits/hyphens. Drive ids are 1–32 of the
same characters. Paths are absolute, ASCII, normalized, NUL-free, at most 1024
bytes/64 components. Resource ranges and all count limits are named constants
in `spec.rs`. Boot arguments require exactly one each of `clocksource=tsc`,
`tsc=reliable`, `hermetic.t=<decimal seconds>` (0 through 4102444800), and `ro`.
`rw` (including `rw=`), `ip=`, other clocksources, unreliable `tsc=` and duplicate
keys are refused. Quotes and backslashes are refused so command-line quoting
cannot hide a required or forbidden token from the guest's whitespace parser.
The guest contract additionally needs an appropriate root device and
`init=/sbin/hermetic-init` (the early read-only proc shim that execs
`/sbin/hermetic-execd`, see the execd README); the clock rule table does not prohibit alternative
trusted PID 1 binaries for NetVM or GraderVM.

## API order and clock

1. `PUT /machine-config` (SMT disabled).
2. `PUT /cpu-config` with the embedded custom template, always.
3. `PUT /boot-source`.
4. Root drive, then further drives in specification order, then reserved slots.
5. Vsock, when present.
6. Network interfaces in specification order.
7. `PUT /entropy`, always.

There is no MMDS, balloon, metrics or logger request. No host log path is given
to Firecracker. API data uses jail-relative absolute paths, never source image
paths. A reserved slot is a read-only, non-root drive backed by a private 4096
byte zero file. It is an empty block device, not an absent backend (Firecracker
requires a backend when creating a drive). Later work can replace it through
`PATCH /drives/<id>`; snapshot/load/attachment policy is outside this task.

`clock: faked` means execd sets guest realtime from `hermetic.t=`. The custom CPU
template modifies exactly eax bits 0 and 3 of leaf 0x40000001, subleaf zero.
It does not close host MSR or hypercall bypasses. `hidden` always fails with an
error naming TR-VMM-3's enforced-PV-CPUID patch including restore, host-side
KVM_HC_CLOCK_PAIRING block, and passing guest-module probe. `real` is not a
supported VM clock setting. Selecting a CPU model sold before the cutoff remains
best effort: this template only changes the two specified bits, and the harness
must record/provision a suitable host CPU baseline. It must not claim clock
hiding from the template alone.

## Files, jailer, and processes

Sources are opened once, component by component using held directory descriptors.
Each component is lstat-checked, opened with NOFOLLOW/NONBLOCK/CLOEXEC, and its
identity checked after opening. Images must be regular, owned by effective caller
or root, and not writable by group/others. FIFOs, devices and symlinks are refused.
The supplied template is parsed through its held source descriptor and must equal
the embedded template before any artifact is created.

The copy rule is unconditional: **copy every source**, including read-only images.
Never hard-link guest-writable files from a shared original. This spends disk
space to avoid inode sharing, including accidental chmod or mutable-source
interactions. Writes use an exclusive temporary file in the destination directory,
fsync, no-replace rename, then directory fsync. Source originals are not modified.
Writable copies are mode 0600, other images 0400, executable copies 0555. The
executable must remain executable after jailer drops uid even if the copy inside
the chroot stays root-owned; its staging parent is private and it has no write
bits. On a
production root launch copies are chowned to the VM's dedicated identity; the
staged executable remains root-owned. Non-root fake/development preparation keeps
ownership with the caller.

The base must already exist and be caller/root-owned with no group/other writes.
Layout: `BASE/firecracker/ID/firecracker` (staged binary) and `.../root/` containing
`kernel`, `cpu-template.json`, `drive-ID`, `api.socket`, `vsock` and jailer-created
devices. A VM identity is `(uid_start + index, gid_start + index)` from a checked
range starting at 65536 or above; it must differ from caller uid/gid. Jailer gets
cgroup v2 cpu, memory and pids limits (memory includes a fixed 128 MiB
Firecracker overhead allowance), file-size/open-file limits, a preconfigured
namespace name, and `--new-pid-ns`. It stays in the foreground, without daemonize.
The known-answer argument vector is in `tests/spec_plan.rs`. At execution, paths
are rebound to parent-held descriptors, including the namespace opened from
`/run/netns/NAME`, so ancestor replacement does not redirect the launch.

Construct `JailerRunner::new("/absolute/path/to/python3.X")` with a regular,
caller/root-owned Python 3 interpreter, with no symlinked path components.
A default runner refuses execution until its launcher is configured. This is a
runtime requirement for the embedded **stdlib-only** `src/launch.py` trampoline;
no Python package is installed. Rust's safe process API cannot close arbitrary
inherited descriptors before exec. The interpreter is pinned by descriptor and
runs with `-I -S`, a cleared environment, stdin `/dev/null`, and a separate process
group. The trampoline verifies the held executable identity, applies rlimits,
disables core dumps, closes inherited descriptors, then executes that descriptor
with an empty environment. Stdout and stderr are drained continuously in a bounded
worker and retained only up to 64 KiB each, without emitting their contents.
The process group is killed before its exited leader is reaped, so descendants
cannot survive a jailer or launcher exit.

`Vmm` states are `new`, `prepared`, `starting`, `running`, `paused`, `stopped`,
`destroyed`, `failed`. Invalid transitions fail before effects. `wait_exit` (from `running`) waits for
a guest that ends itself, such as the GraderVM after its supervisor, until the
Firecracker process exits; it then moves to `stopped`, so the caller can read the
jail's `drive-result` copy before `destroy`. On its deadline it kills and destroys
like any failed step. Calls accept
0 < timeout <= 300 seconds, and API operations use one overall monotonic deadline
for connect/write/header/body (slow-drip traffic cannot extend it). `wait_ready`
means Firecracker API readiness and successful configuration/InstanceStart;
caller-side execd readiness is a separate outbound vsock request. A failed step
names that step, kills the process, and destroys the jail with an independent
5-second cleanup allowance. `stop` tries SendCtrlAltDel for half its budget, then
kills the process group with the remaining budget. Call execd's graceful shutdown
and record an unclean shutdown in the harness when execd does not answer. Drop
kills running processes and attempts bounded cleanup.

Destruction checks held base/VM/root identities, permits the configured VM uid
on jailer-owned directories after the process has been killed, walks through directory
descriptors without following links or opening disk contents, and unlinks links
as links. It refuses replacement, mount crossings, excessive depth/count, and unsafe directories.
Root/caller remain in the filesystem trust boundary; do not grant another process
those identities or mutate jail names concurrently. Local regular-file I/O is
checked between bounded copy chunks; a kernel-stalled storage syscall itself
cannot be interrupted by a userspace deadline. Provision local storage and enforce
an outer supervisor deadline for storage failures.

| Cap | Value |
|---|---|
| Spec JSON | 64 KiB |
| vCPUs / memory | 32 / 131072 MiB |
| Further + reserved drives | 16 |
| Network interfaces | 2 globally; role rules tighten to 0 or 1 |
| VMs per validated run | 4096 |
| Image / aggregate inputs | 64 GiB / 256 GiB |
| CPU template | 16 KiB |
| Copy chunk | 64 KiB |
| HTTP header / body / request JSON | 8 KiB / 64 KiB / 16 KiB |
| Captured stdout / stderr | 64 KiB each |
| Inherited descriptor upper bound | 1048576 |
| Inherited open descriptor count | 4096 |
| Cleanup entries / depth | 128 / 8 |
| Pids / open files | 4096 / 4096 |

## Release lock and owner verification

`vmm/firecracker.lock.json` pins stock x86_64 Firecracker **v1.18.0**, published
2026-11-09, with the owner-supplied release URL and archive SHA-256
`1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd`.
The verified binary hashes recorded are:
- `firecracker_sha256`: `b33f46cd6d88834cf6a4f8d184f08f219809c636236bffd286d233a60602a2ba`
- `jailer_sha256`: `ddadbaa15b5c942271a83b7040ca7259c8ccf92a9e08d44cce0b86fa407ba460`

Install the verified executables under safe paths, with Firecracker's basename exactly `firecracker`.
Use those paths in the spec. The lock is provenance for installation; the library
does not download or install executables. Recheck VMClock's contents and run the
clock probes on every upgrade. Filling this lock does not satisfy TR-VMM-3.

## Tests

Run checks from the worktree root through the repository gates only:

```
/home/flingboot/.hermetic/bin/rust-gate
```

The gate always lints the workspace. In a sandbox that denies existing gateway
listeners, isolate this crate's tests using the gate's cargo-test arguments:

```
/home/flingboot/.hermetic/bin/rust-gate --exclude hermetic-common --exclude hermetic-gateway --exclude hermetic-sealcheck --exclude hermetic-trust --exclude hermetic-world-server --exclude tiny_http
```

The fake Firecracker is a server on a Unix socketpair, with real HTTP bytes. The
pathname-connect test is ignored because managed sandboxes can deny Unix binds;
run it on a host with that permission through `rust-gate` with the above excludes
and `--test api pathname_client_connects_to_fake_firecracker -- --ignored`.

The client admits only the fixed methods, endpoints and JSON fields used by the
planner and lifecycle (plus reserved-drive PATCH). Fault bodies and child output
are never included in errors. Header/body caps and one deadline cover malformed,
truncated, stalled and slow-drip responses.

`dev-unjailed` is off by default. It exposes `DevUnjailed::new(python_path)` only
at compile time, with no production JSON runner selector. It remaps kernel/disk/
vsock paths to the held jail directory and starts Firecracker directly. It has
no jailer, namespace or cgroup isolation; use only trusted disposable fixtures.

Owner-run guest tests require `/dev/kvm`, the verified Firecracker binary,
the T3.2 kernel, and a sealed T3.1 execd rootfs (including its run specification).
Set `HERMETIC_FC_BIN`, `HERMETIC_KERNEL`, `HERMETIC_ROOTFS` to safe absolute paths.
The test creates its private empty ext4 upper using installed e2fsprogs >=1.47.1,
with fixed UUID/hash seed and timestamps, without mounting anything. It uses a
private copy of the system Python interpreter as its exec launcher. Invoke:

```
/home/flingboot/.hermetic/bin/rust-gate --exclude hermetic-common --exclude hermetic-gateway --exclude hermetic-sealcheck --exclude hermetic-trust --exclude hermetic-world-server --exclude tiny_http --features dev-unjailed --test guest boots_guest_and_reads_guest_clock -- --ignored --nocapture
```

Missing variables print a clear skip message. `boots_grader_and_collects_result_drive` (same flags) boots a
grader image (`HERMETIC_GRADER_ROOTFS`) with `init=/sbin/hermetic-grader-init`,
waits for power-off, checks the serial line `grader-init SECONDS clock` against
`hermetic.t`, and writes the result drive to `HERMETIC_GRADER_RESULT_OUT`. The
development runner's `serial()` returns the first 64 KiB of guest serial output;
production runners expose none. This test connects outbound to
Firecracker's vsock backend, sends `CONNECT 5000\n`, checks bounded `OK PORT\n`,
and sends a u32 **little-endian** length followed by `{"type":"status"}`. It expects
a bounded JSON reply containing `{"type":"status","guest_time_unix":SECONDS}`
(extra reply fields are permitted), within 15 seconds of 1700000000. The T3.1
brief does not fix the JSON field spelling or byte order; this is the explicit
integration contract chosen here and must be coordinated with that implementation.
The fake status test pins these bytes. The kernel arguments, guest boot effects,
clock tolerance and actual Firecracker compatibility require the real guest run.

`jailer_boots_in_isolated_namespace` is separately ignored. It additionally needs
an owner-prepared root test host, cgroup v2 cpu/memory/pids delegation, the configured
network namespace and `HERMETIC_JAILER_BIN`, `HERMETIC_NETNS`. Run that exact test
with `--test guest jailer_boots_in_isolated_namespace -- --ignored --nocapture`.
The library does not provision host namespaces, mount filesystems, or change
host settings. No privileged test is run by the default gate.

## Requirement coverage

| Brief requirement | Regression tests |
|---|---|
| 1. Specification | `validates_roles_devices_identifiers_paths_and_caps`, `every_boot_argument_rule`, `run_rejects_duplicate_cid_uid_gid_and_id`, `project_mac_known_answers_are_independent_of_host_identity` |
| 2. Configuration | `agent_and_extractor_full_known_answers`, `all_roles_attach_entropy_and_template_without_metadata_or_balloon`, `template_changes_exactly_leaf_eax_bits_zero_and_three` |
| 3. Jail plan | `jail_vector_known_answer`, `descriptor_copy_and_reserved_slot_teardown_never_follow_links`; owner-only `jailer_boots_in_isolated_namespace` |
| 4. Lifecycle | `explicit_state_machine_configures_starts_pauses_resumes_stops_and_destroys`, `wait_exit_stops_after_guest_exit_and_destroys_on_deadline`, `grader_result_drive_must_be_exactly_one_mib`, `grader_drive_layout_requires_writable_result_first_and_read_only_others`, `failures_name_the_step_and_destroy_the_jail`, `configuration_failure_names_the_specific_device_step`, `startup_stall_is_destroyed_and_drop_kills_a_running_vm`; runner unit tests cover environment, descriptors, groups, capture and descendants |
| 5. API client | `correct_request_and_response_known_answer`, `fault_body_is_not_exposed`, `oversized_truncated_and_early_close_are_refused`, `stalled_response_hits_overall_deadline`, `slow_drip_does_not_reset_call_deadline`, `malicious_http_grammar_is_bounded_and_strict`, `every_planned_request_passes_the_strict_transport_schema` |
| 6. Host paths | `rejects_unsafe_sources_and_directories_before_creating_artifacts`, `opened_source_remains_pinned_after_path_replacement`, `destroy_refuses_replaced_vm_or_root_identity`, `ancestor_replacement_does_not_redirect_prepared_jail_paths_or_cleanup`; filesystem unit tests cover ownership and atomic publication |
| 7. Development | `default_configuration_cannot_select_development_runner`, feature-only `dev_path_rewriting_uses_only_pinned_directory`, `guest_status_frame_known_answer_and_cap`; owner-only `boots_guest_and_reads_guest_clock` |
| 8. CLI | `plan_json_is_deterministic_and_never_opens_spec_image_paths`, `validation_and_io_have_distinct_exit_codes_and_no_input_echo`, `non_utf8_arguments_are_refused_without_a_panic`, `spec_json_is_strict_and_bounded_without_echoing_input` |
| 9. Documentation and release | This README, owner-run instructions above, and `release_lock_matches_owner_supplied_archive_pin` |
