# `hermetic-grader-supervisor`

Grading supervisor and deterministic 1 MiB HGRD result writer for Hermetic World
benchmark VMs. It never imports the repository. It consumes strict, bounded HGR1
start/finish/end records and writes the result only after the test namespace has
terminated. Missing finish records fail; printed summaries and test exit codes
cannot grant passes.

```sh
hermetic-grader-supervisor --config /etc/hermetic/grader/run.json --result-disk /dev/vdb
```

The supervisor applies `hermetic-grader-sandbox` before executing any repository
code. Configs provide a pytest argv, cwd, a bounded environment allow-list, and
`sandbox: {"t_clock": 1700000000, "required_pytest_plugins": [...]}`. The record
plugin is always required. Fixed environment values may only be repeated with
identical values. Loader and interpreter overrides, arbitrary commands, unsafe
paths and plugin disabling fail closed. `hermetic-grader-init` sets the VM clock;
the launcher verifies it against the sealed time before running tests.

A freshly exec'd helper creates PID, mount, IPC, UTS and network namespaces;
there is no user namespace. Its next child is namespace PID 1. The supervisor
pins that child's pidfd before releasing it. The child applies private mounts,
fixed hostname/domainname, empty supplementary groups, exact bounding/effective/
permitted capabilities, empty inheritable/ambient sets and no-new-privileges.
It supplies the record pipe directly on fd 3, clears inherited descriptors at
exec and directs standard input/output/error to `/dev/null`. The environment is
exactly the planner output, including the explicit `HERMETIC_RESULT_FD=3`
allow-list entry. The parent kills the whole process group on timeout and exit;
PID namespace destruction also kills descendants that created new sessions.
The pidfd must report init's completed exit before the result can be written.

The root is a read-only, nosuid, non-recursive bind of the sealed root. Inherited
proc, sysfs, device, cgroup and unrelated bind mounts are excluded. Fresh proc,
read-only sysfs, bounded device tmpfs, private devpts and shm follow the plan.
The VM initializer's writable `/tmp` is bound into the child. A bounded 256 MiB,
65,536-inode overlay supplies a writable repository even on a read-only base
drive; its backing directory is hidden from the test view. The six device nodes
and five symlinks come directly from the plan. Tests cannot access the result
disk through `/dev`, create device nodes, or retain a supervisor descriptor.

Cgroup v2 is mounted privately and the ordered device rules are compiled to
bounded eBPF and attached before the test joins. Every block device is denied,
including pre-existing nodes outside `/dev`. Only a kernel returning `ENODEV`
for cgroup2 may omit that layer; all other mount, BPF and attachment errors fail
closed. The grader kernel policy requires cgroup v2/BPF. A normal exit removes
the empty cgroup; a forced termination may leave an empty group until VM teardown.
There is one test tree per supervisor/VM.

OS effects pass through `Os`; plan application passes through `SandboxOs`.
The syscall module isolates the minimal unsafe operations unavailable in safe
rustix: namespace creation, close-range CLOEXEC, record-fd duplication and BPF
load/attach. It documents pointer lifetimes, descriptor ownership and the
single-threaded helper precondition. Everything else denies unsafe code; the
binary and integration tests forbid it. Dependencies reuse the existing planner,
rustix and libc in this workspace; no external package is added.

HGR1: magic `HGR1`, then `(type: u8, length: u32 LE, JSON payload)` frames. Frame
payloads cap at 64 KiB. HGRD: magic `HGRD`, version/flags as u16 BE, payload length
as u32 BE, SHA-256, compact canonical JSON in host schema order, then zero padding
to exactly 1 MiB. Regular result files use descriptor-relative, synced atomic
rename with mode 0600. Configs must be regular files; symlinks and FIFOs are
refused. The result block drive is the only intentional special-file write.

Offline tests cover plan values/order and injected failure at every stage,
known-answer eBPF bytes and rule evaluation, descriptor inheritance, process-group
kill, filesystem confinement, canonical result bytes and host-parser compatibility.
The root-only integration test checks kernel state and detached descendants on
exit and timeout; it skips without root. VM and privileged check commands are in
[scripts/integration/BOOT_NOTES.md](../../scripts/integration/BOOT_NOTES.md).
