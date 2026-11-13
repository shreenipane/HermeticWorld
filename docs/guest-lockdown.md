# Guest root lockdown

The trusted Linux 6.6.160 guest must deny root the supported interfaces for
installing kernel code, changing kernel memory, and reading physical memory or
MSRs. Otherwise a module can call KVM_HC_CLOCK_PAIRING at CPL 0, or write the KVM
wall-clock MSRs, irrespective of the CPUID clock mask. This policy does not
replace host-side hypercall/MSR filtering or establish `clock: hidden` under the
architecture's stronger adversary that already controls kernel code. Kernel
vulnerabilities and arbitrary replacement of the trusted boot kernel are outside
this guest policy.

`MODULES=n` removes both module insertion syscalls, including unsigned modules
and root's attempts to undo a runtime modules-disabled setting. `DEVMEM`,
`X86_MSR`, `X86_CPUID`, `PROC_KCORE`, kexec (both APIs and shared core),
hibernation, raw x86 I/O privilege syscalls, ACPI custom methods/table upgrades,
and kprobe/uprobe BPF tracing paths are disabled. `PERF_EVENTS` cannot be disabled on
x86 (the architecture selects it); confidentiality lockdown denies its kernel-reading
uses, and guest PMU exposure is checked by the clock probe as a 3b item. `DEVKMEM` has no symbol in
6.6; its disabled policy entry also rejects enabling it in another source tree.
Disabling the CPUID driver removes a device interface; it does not stop the
userspace CPUID instruction or normalize CPU identity.

Confidentiality lockdown is forced in the kernel config and initialized as an
early LSM. Linux `security/lockdown/lockdown.c` registers `DEFINE_EARLY_LSM` when
`SECURITY_LOCKDOWN_LSM_EARLY=y`, so the mutable normal LSM list cannot omit it.
The forced level cannot be lowered by securityfs or by a weaker boot parameter.
No boot arguments or CPU templates change here.

Confidentiality mode is retained, with no integrity-mode exception. In the
pinned source, `kernel/bpf/syscall.c` does not call `security_locked_down` for
cgroup-device program loading/attachment. `kernel/trace/bpf_trace.c` restricts
`probe_write_user` and kernel-reading helpers, which cgroup-device filters do
not use. `BPF`, `BPF_SYSCALL`, `CGROUP_BPF` and all controllers remain built in;
`BPF_UNPRIV_DEFAULT_OFF=y` defaults the unprivileged BPF sysctl to 2. Root can
change that default, but cannot re-enable the compiled-out tracing paths or
remove lockdown. The verifier remains a trusted kernel boundary. The grader VM
smoke below must exercise device-BPF loading and attachment under this policy.

Virtio blk/net/vsock/console/MMIO/rng, ext4, overlayfs, devtmpfs, dm-verity,
seccomp, namespaces, nftables and legacy iptables/TPROXY/conntrack remain `=y`.
The policy checker rejects `=m` for every required driver; the build checks the
final `olddefconfig`, not just the fragment. See the generated table in
[the kernel README](../images/kernel/README.md).

Both `PARAVIRT` and `KVM_GUEST` (including `PARAVIRT_CLOCK`) are disabled, following
the clock analysis's proposed nested experiment. This removes cooperative
pvclock hooks; it does not filter a malicious CPL-0 hypercall or WRMSR.
Multi-vCPU boot, TSC calibration, timers and performance require measurement.
No guessed TSC frequency or clock fallback is introduced. If the nested boot
stalls on TSC calibration, retain its diagnostics and resolve virtual TSC
frequency enforcement in the VMM separately; do not silently re-enable pvclock.

## Manager build and VM checks

Run these exact commands from the worktree root on the manager's nested-KVM
machine. Every work directory below must be fresh. Builder preparation needs the
cached pinned base image and package inputs as described in the kernel README;
the kernel compilation container itself has `--network=none --pull=never`.
These commands have not been run as part of the offline policy review.

```sh
./scripts/integration/kernel-build.sh \
  /home/flingboot/.hermetic/cache/kernel-src/linux-6.6.160.tar.xz \
  "$PWD/guest-lockdown-kernel"
PYTHONPATH=python python3 -B -m hermetic_slice kernel-check-config \
  --config "$PWD/guest-lockdown-kernel/.config"

export HERMETIC_KERNEL="$PWD/guest-lockdown-kernel/vmlinux"
HERMETIC_LOCKDOWN_CONFIG="$PWD/guest-lockdown-kernel/.config" \
  bash scripts/integration/boot-smoke.sh "$PWD/guest-lockdown-boot-smoke"
bash scripts/integration/net-smoke.sh "$PWD/guest-lockdown-net-smoke"
bash scripts/integration/reboot-smoke.sh "$PWD/guest-lockdown-reboot-smoke"
bash scripts/integration/grader-vm-smoke.sh "$PWD/guest-lockdown-grader-vm-smoke"
bash scripts/integration/grader-smoke.sh "$PWD/guest-lockdown-grader-smoke"
```

The boot smoke additionally builds a static `hermetic-clockprobe`, seals it and
the matching verified `.config` into the agent rootfs, and runs
`boots_guest_and_checks_root_lockdown`. That test mounts securityfs through
execd, runs `/sbin/hermetic-clockprobe --lockdown-only` through execd, and requires
exactly `module_load` and `ring0_paths`, both `blocked`, exit 0, with no timeout or
truncation. It also runs the existing clock/command boot test unchanged. The
normal offline Rust gate tests the response validation without booting a VM.

For an existing pristine AgentVM, stage the static binary and the corresponding
verified final `.config` as `/sbin/hermetic-clockprobe` (0755) and
`/etc/hermetic/guest-kernel.config` (0600), mount securityfs at
`/sys/kernel/security`, then use execd's exec request with argv
`["/sbin/hermetic-clockprobe", "--lockdown-only"]`, `tty: false`,
`timeout_ms: 5000`. Use the `.config` whose digest matches that kernel's verified
build record; the guest diagnostic cannot authenticate an arbitrary supplied
config or an already compromised kernel. No host probe should be executed.

The module probe submits only an empty image to `init_module` and an invalid
file descriptor to `finit_module`, and requires raw `-ENOSYS` from both; permission errors or invalid-image errors do not pass. It never loads
a module. The ring-0 probe requires the supplied config policy, live forced
confidentiality mode, disabled unprivileged BPF and absent proc/sysfs interfaces,
including driver registrations rather than just `/dev` nodes that root could
recreate. Missing evidence or resource-cap failures are errors, not passes.

The unrestricted diagnostic also retains the imported clock/CPU probes. It may
report other clock/CPU leaks and incomplete coverage; its overall exit 0 alone
does not attest hidden time. Review those records separately from these two
lockdown checks. Host-KVM enforcement and CPU identity normalization remain
separate components, as required by TR-VMM-3.
