# Host enforcement for Phase 3b (v1)

The owner decision of 2026-11-14 puts host filtering in v1. Guest lockdown alone
leaves a verified ring-0 bypass: clock-pairing and clock MSR writes do not require
a guest device node or a cooperative guest kernel. The patch in
`vmm/firecracker-patches/0001-host-pv-clock-filter.patch` installs host enforcement
on every x86 KVM VM. Unsupported hosts fail startup; there is no stock fallback.
`clock: hidden` remains refused until the manager validates the whole boundary.

## Source findings

These are source checks against upstream Linux **v7.0**, not an attestation of
the running host. The owner supplied `uname -r = 7.0`; its build configuration
and downstream patches are not independently attested. The manager has verified
the patched build and nested ring-0 canary, including a stock negative control,
as recorded below. Multi-vCPU, pause/resume and restore coverage remain open.
The inspected `arch/x86/kvm/x86.c` SHA256 was
`d5dfe2e58060f8ef4c731cb8433617e8d28115d9e559cee1563ec1b9813746c7`.
Firecracker source is v1.18.0, commit
`eaf83bb718a559d324613d566eaf776b31a62340`; the tarball hash is recorded in the lock.

| Channel | Linux 7.0 behavior and enforcement |
| --- | --- |
| `MSR_KVM_WALL_CLOCK` 0x11, `MSR_KVM_SYSTEM_TIME` 0x12, `MSR_KVM_WALL_CLOCK_NEW` 0x4b564d00, `MSR_KVM_SYSTEM_TIME_NEW` 0x4b564d01 | `kvm_set_msr_common` writes host epoch / PV system-time data into guest GPAs. `kvm_emulate_msr_read/write` check the VM MSR filter **before** the handler. The patch denies both reads and writes of the legacy pair and the entire 0x4b564d00..0x4b564dff PV range. |
| KVM steal time, async-PF and other PV MSRs | Also denied by the entire new PV range. CPUID features remain masked, with enforcement after both cold-boot and restore `set_cpuid2`. |
| `KVM_HC_CLOCK_PAIRING` (9) | `kvm_emulate_hypercall` dispatches to `kvm_pv_clock_pairing` at CPL 0 without a CPUID gate. It copies host realtime into guest memory. `KVM_CAP_EXIT_HYPERCALL` only advertises `1 << KVM_HC_MAP_GPA_RANGE` (12); requesting bit 9 fails EINVAL. It cannot block pairing. |
| Xen interception | `kvm_emulate_hypercall` checks `kvm_xen_hypercall_enabled` **before** the KVM handler. Enable `KVM_XEN_HVM_CONFIG_INTERCEPT_HCALL` using VM ioctl `KVM_XEN_HVM_CONFIG`, with nonzero synthetic MSR 0x40000000 to activate the static key. Hypercall 9 is unhandled by the Xen in-kernel switch, so exits as `KVM_EXIT_XEN_HCALL`. The patch returns fixed `-ENOSYS` through its result field, without touching the guest GPA. Requires `CONFIG_KVM_XEN` and the advertised interception bit; absence fails closed. |
| Xen/Hyper-V PV wall time, reference TSC, frequency MSRs | Deny reads/writes in 0x40000000..0x400001ff, including the selected Xen hypercall-page MSR. No Xen shared-info, runstate or vCPU-info attributes are configured. Hyper-V guest-OS-ID/hypercall activation is denied by the same range. |
| RTC | Firecracker's x86 port device has no CMOS clock. This patch supports only x86_64. ARM PL031 needs its separate offset policy. |
| VMClock | v1.18.0 initializes `clock_status=UNKNOWN`, `counter_id=INVALID`, generation/notification flags, and zero timestamp fields. It supplies disruption/generation notifications, not UTC. Recheck this ABI on upgrade. |
| TSC, CPUID frequency/model, PMU | The patch installs the fixed Nehalem/v2 profile after normalization and enforces a 2 GHz scaled TSC on boot/restore. See [CPU and TSC policy](clock-3b-analysis.md). Host contention remains a substrate timing channel. |

Exact source references:

- Linux [x86.c](https://github.com/torvalds/linux/blob/v7.0/arch/x86/kvm/x86.c):
  `kvm_pv_clock_pairing`, `____kvm_emulate_hypercall`, `kvm_emulate_hypercall`,
  `KVM_EXIT_HYPERCALL_VALID_MASK`, `kvm_vm_ioctl_enable_cap`,
  `kvm_vm_ioctl_set_msr_filter`, `kvm_emulate_msr_read/write`,
  `kvm_msr_reason`, `kvm_msr_user_space`, `kvm_vcpu_ioctl_enable_cap`.
  An MSR filter denial is `KVM_MSR_RET_FILTERED`, separate from unsupported MSRs
  affected by `ignore_msrs`. Setting `KVM_CAP_X86_USER_SPACE_MSR`'s mask to zero
  prevents filtered accesses being serviced in userspace; KVM injects #GP.
- Linux [xen.c](https://github.com/torvalds/linux/blob/v7.0/arch/x86/kvm/xen.c):
  `kvm_xen_hvm_config` and `kvm_xen_hypercall`; and
  [xen.h](https://github.com/torvalds/linux/blob/v7.0/arch/x86/kvm/xen.h),
  `kvm_xen_hypercall_enabled`. A zero Xen MSR is insufficient to activate the
  static key. Enabling a nonzero MSR without denying guest access would allow
  a guest to request a hypercall page; this patch denies it.
- Linux [KVM API](https://github.com/torvalds/linux/blob/v7.0/Documentation/virt/kvm/api.rst):
  `KVM_X86_SET_MSR_FILTER`, `KVM_CAP_X86_USER_SPACE_MSR`,
  `KVM_CAP_ENFORCE_PV_FEATURE_CPUID`, `KVM_CAP_EXIT_HYPERCALL`, `KVM_XEN_HVM_CONFIG`.
- Firecracker [x86 VM](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/arch/x86_64/vm.rs),
  `KvmVm::new`, and [builder](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/builder.rs),
  `build_microvm_for_boot` and `build_microvm_from_snapshot`: both create a new
  VM fd. Filtering is installed there before vCPUs or guest memory registration.
- Firecracker [x86 vCPU](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/arch/x86_64/vcpu.rs),
  `configure_cpuid` / `restore_state`: both now enable PV enforcement immediately
  after `set_cpuid2`; snapshot data cannot remove it.
- Firecracker [run loop](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/vstate/vcpu.rs),
  `run_emulation`: kvm-ioctls 0.25 reports Xen as `Unsupported(KVM_EXIT_XEN)`.
  The patch validates the discriminator and sets only `hcall.result`.
  Other exit types retain fail-closed behavior. The x86 musl seccomp policy adds
  only the three exact KVM ioctl values needed for filter/configuration/capability.
- Firecracker [VMClock](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/devices/acpi/vmclock.rs),
  `VmClock::new`, `activate`, `do_post_restore`.

No host kernel patch is needed **if Xen interception is available**. The
current patch requires the advertised `KVM_XEN_HVM_CONFIG_INTERCEPT_HCALL`
capability and refuses to start without it. The **supported remedy** for a host
that lacks it is rebuilding or upgrading the host kernel with `CONFIG_KVM_XEN=y`.

Two other designs would also close hypercall 9, but neither works with this
patch on its own: a non-TSC host clocksource (global performance and
availability costs), or a host KVM patch rejecting hypercall 9 before
`kvm_pv_clock_pairing` (requires maintained host kernels). Either would also
need a coordinated VMM policy change that replaces the Xen-interception
requirement with a check for that host property. Changing only the host leaves
this patch unable to start. This branch cannot change the owner's host
configuration. VMware backdoor enablement and
any downstream KVM interfaces also require an owner host-policy check.

## Reproducible patched build

Stock release pins in `vmm/firecracker.lock.json` remain historical reference
pins. Its additional `source_url`, `source_sha256`, and `patch_sha256` bind the
patched build inputs; they never masquerade as a measured patched binary hash.

Fetch the source URL in that lock to `source.tar.gz` and verify its SHA256 before
preparing a builder. Source fetch and builder preparation are the online phase.
Build `vmm/firecracker-base.Dockerfile` for the verified base recipe: it starts at
`rust@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073`,
installs `musl-tools cmake patch clang libclang-dev linux-libc-dev libseccomp-dev`,
links the linux/asm/asm-generic headers into the musl include directory, and
installs Rust 1.97.0 with rustfmt and the x86_64-unknown-linux-musl target.
Pass the resulting digest-pinned base to `vmm/firecracker-builder.Dockerfile`.
That Dockerfile fetches only Cargo.lock-pinned dependencies into
`/vendor`; retain the resulting local immutable `sha256:` image ID. The image
must support non-root builds. Package repositories are used only during online
preparation; rebuilding this recipe later may produce a different image ID.
Use the measured immutable image ID for the offline build.

**Verified by the manager (2026-11-14):** the full patched build completed with
this base and toolchain, and the two builds were byte-for-byte reproducible:

| Artifact | Measured SHA256 |
| --- | --- |
| Final vendored builder image | `1c040b0c5ada03792b5696a2c8f837e07c86645018a436c3a57af828505a2caf` |
| Firecracker | `9826f47425bbce514009080adb9f1a60bf776cf942c4c66b2a00d05a1d99c9ad` |
| Jailer | `276e5bc2a17fbb23e5478f6bb245697f99e8c84426cbcf7f2700d8958674518b` |

These measurements document the manager's build. Continue to use its measured
`firecracker.lock.json` with the runners; a different build must measure its own
artifacts and pass the same reproducibility and runtime checks.

Then build without network, using a private parent and fresh output directory:

```sh
mkdir -m 700 "$PWD/.scratch/fc-builds"
scripts/integration/build-firecracker.sh \
  "$PWD/source.tar.gz" sha256:1c040b0c5ada03792b5696a2c8f837e07c86645018a436c3a57af828505a2caf \
  "$PWD/.scratch/fc-builds/patched"
export HERMETIC_FIRECRACKER_LOCK="$PWD/.scratch/fc-builds/patched/firecracker.lock.json"
export HERMETIC_FC_BIN="$PWD/.scratch/fc-builds/patched/firecracker"
```

The script validates hashes and all archive entries before artifacts, applies
with zero fuzz, runs the filter and CPU-profile unit tests without KVM, builds twice in
fresh directories with `--locked --offline`, and compares both binaries byte for
byte. Docker uses `--network=none --pull=never`, a cleared client environment,
fixed locale/timezone/hostname/epoch, an empty Docker client configuration,
a read-only root, and named process, memory,
file, target-storage and time caps. It publishes mode-0500 binaries and a
mode-0600 measured build lock only after reproducibility succeeds. Existing
outputs are refused. The complete output directory is published in one
no-replace rename. Timed-out builds remove the named daemon container before
returning. The immutable builder owns its vendored dependency inputs.

`hermetic-vmm`'s real jailer and development runners require that measured lock,
validate source/patch/toolchain/target provenance, and hash held executable
inodes before execution (including jailer in production). Missing, stock, stale
or substituted artifacts fail closed. The parent keeps each inode pinned through
execution. Fake offline runners retain their test fixtures. Integration smokes
must use the patched binary and lock; a stock smoke cannot certify v1 filtering.

## Manager-only ring-0 canary

`images/kernel/canary/0001-built-in-clock-canary.patch` applies to the pinned
Linux 6.6.160 source. Apply it and merge `canary/hermetic.config` **only in a
separate test build**; keep all production lockdown settings. Build with the
same pinned compiler/identity/epoch as the production guest. Enable the extra
boot argument `hermetic.clock_canary=nested-vm` only in the disposable nested VM.
The normal kernel build checker deliberately refuses this test-only option.
Never use the canary kernel for benchmark workloads or boot it on bare metal.

The late built-in initializer allocates one page, uses its real page-aligned GPA,
attempts RDMSR and WRMSR of all four clock MSRs (enable bit set for system-time),
and calls hypercall 9 even with guest PV support compiled out. Its expected
Xen exit result is Linux `-ENOSYS` (-38), rather than the KVM native ABI
`-KVM_ENOSYS` (-1000). Migration is disabled from registration through removal
so periodic MSRs are disabled on the same vCPU. It checks a
sentinel page without printing its contents, raw epochs, register values or
return codes. Accepted periodic MSRs are disabled before freeing the page; a
page still registered with the VMM is retained rather than freed.

Expected serial payloads (kernel timestamp prefixes are allowed):

```text
hermetic-canary/v1 msr=00000011 rd=gp wr=gp page=unchanged
hermetic-canary/v1 msr=00000012 rd=gp wr=gp page=unchanged
hermetic-canary/v1 msr=4b564d00 rd=gp wr=gp page=unchanged
hermetic-canary/v1 msr=4b564d01 rd=gp wr=gp page=unchanged
hermetic-canary/v1 hypercall=9 ret=enosys page=unchanged
hermetic-canary/v1 result=pass
```

The manager can validate a bounded captured serial transcript without executing
any probe on the host:

```sh
hermetic-clockprobe --kernel-canary-serial < nested-canary.serial
```

It requires every payload exactly once and rejects missing/truncated/duplicate
or changed evidence. Run controls on stock Firecracker: at least accepted MSRs
or a successful pairing/page change must be observed; non-TSC host clocks may
make pairing unsupported in a control, which is not sufficient evidence of an
interceptor. Also test multiple vCPUs, pause/resume and snapshot restore on the
owner's actual host.

**Verified by the manager (2026-11-14):** the nested canary produced all six
expected payloads above: all four MSRs faulted on both RDMSR and WRMSR,
hypercall 9 returned ENOSYS, every sentinel page remained unchanged, and
`result=pass`. The stock Firecracker control accepted all four MSRs on reads
and writes, changed the sentinel page, and reported `result=fail`.
This verifies the tested nested enforcement path and its negative control;
it does not establish coverage of other hosts or restore paths.

## Validation and open items

Verified offline: source SHA256 and archive safety (845 regular files), exact
patch application to v1.18.0, isolated compilation of the filter module against
upstream kvm-ioctls 0.25.0/kvm-bindings 0.14.1, filter and CPU-profile unit tests, wrapper
failure/reproducibility/publication tests, build-lock/descriptor hash tests and
serial validator tests. Regressions apply the complete patch to pinned upstream
file fixtures, validate seccomp rule preservation and unique Rust wiring, and
compile/execute the canary initializer with simulated MSR/hypercall operations
(including accepted writes and failed removal). Production config checks refuse
the canary option. These simulations perform no privileged instructions.
No dependencies were added to the project or upstream
Firecracker manifests. The canary patch is provided for manager builds.

**VERIFIED (manager):** full patched Firecracker and canary compilation, the
measured reproducible artifacts above, nested ring-0 MSR/hypercall enforcement,
and the stock Firecracker negative control. The successful nested run exercised
Xen interception on that tested host configuration.

**Verified full userspace probe (manager, 2026-11-14):** no arguments, exit 0,
every record blocked except `clock_pairing_hc` (unavailable; covered by the
ring-0 canary above). The guest uses pinned CPUID 0x15 and KVM scaling for its
2 GHz rate; no `tsc_early_khz` argument is allowed. KVM's runtime XSAVE size
`0x240`, `cpuid_fault`/`pti`, and tick-based jiffies clocksources are expected.
Kernel-log dates are exempt only when exactly in the sealed `substrate-dates`
list extracted from the image, or within T_clock ±1 day; the release-date
`substrate-bound` metadata is not a general exemption. Repeat with
`HERMETIC_FULL_PROBE=1` and the matching `HERMETIC_LOCKDOWN_CONFIG` in boot-smoke.
The new `LEGACY_PTYS=n` policy requires a manager kernel rebuild before that run.

**OPEN:** independent deployment-host configuration/downstream-interface audit,
multiple vCPUs, pause/resume, snapshot restore and TSC stability. These require
manager host resources. The completed build and nested canary do not establish
the whole runtime security boundary. CPU identity and TSC scaling are implemented
in this patch set; their remaining deployment validation stays a manager check.
AMD hosts fail closed.
See `clock-3b-analysis.md` for the baseline and substrate limits.
