# Phase 3b clock and CPU boundary

The supported level remains **`clock: faked`** until the manager validates the
complete boundary on the deployment host. The owner decision of 2026-11-14
includes host filtering, CPU identity and TSC scaling in v1. No VM was run during
this review. The implementation ships in the pinned Firecracker 1.18.0 patch;
stock Firecracker is refused by the real runners.

## Fixed CPU profile

`vmm/cpu-baseline.rs` defines the single profile. Its exact copy is shipped in the
Firecracker patch, and tests compare them byte for byte. The custom template
`vmm/clock-3b.cpu-template.json` supplies all four registers without host-preserving
bits. The API and staged template must equal the embedded template.

The profile uses the 2009 Intel Xeon E5504 / Nehalem signature `0x106a5`, family 6,
model 26, stepping 5, vendor GenuineIntel, and the fixed brand
`Intel(R) Xeon(R) CPU E5504 @ 2.00GHz`. This predates the benchmark-era substrate
and needs no newer ISA than x86-64-v2: SSE3, SSSE3, CMPXCHG16B, SSE4.1/4.2,
POPCNT and LAHF/SAHF accompany the x86-64 baseline. AVX, XSAVE, AES, RDRAND,
RDSEED, PMU and all structured feature extensions are absent. Virtio entropy
remains available. Very early cutoffs still require the substrate exemption in
the architecture; CPUID cannot suppress instruction or cache timing attacks.

The guest identity check requires these register values exactly:

| Register | Pinned value |
| --- | --- |
| CPUID.1 EAX | `0x000106a5` |
| CPUID.1 ECX | `0x00982201` |
| CPUID.1 EDX (one vCPU) | `0x078bfbff` |

For multiple vCPUs, only EDX bit 28 (HTT) is added to the feature registers;
the topology fields also reflect the bounded guest count and index. Vendor
bytes must spell `GenuineIntel`. Every other register, including extended
feature flags, must match `vmm/cpu-baseline.rs`; an allowlist subset is
insufficient for the `cpuid` result.

Basic/extended maximum leaves, 36-bit physical and 48-bit virtual addresses,
32 KiB L1 instruction/data caches, 256 KiB L2, no L3, and feature flags are fixed.
Topology describes one thread per core in one package; only the bounded vCPU
count/index from the machine specification varies (maximum 32). Unused leaves,
including KVM/PV, PMU, XSAVE, thermal, security-feature and newer extended leaves,
are zero. Leaf 0xb reports only guest topology. The patch constructs a new bounded
CPUID set after upstream normalization on cold boot, so normalization cannot
restore host brand, vendor, cache, flags, maximum leaves or frequency suffixes.
Snapshot restoration requires exactly the same canonical profile and rate;
mutated or older snapshots fail closed before vCPU state is applied.

Before replacing the supported CPUID set, the VM constructor checks the original
KVM vendor, all required instruction bits, invariant TSC and address widths.
Unsupported or AMD hosts fail closed. Nested Intel KVM works only when the
outer hypervisor exposes the required profile and hardware TSC scaling. No
alternative host-dependent profile or stock fallback is selected.

The guest clock probe queries every installed basic/extended/cache/topology/PV
entry and compares every register, including brand and frequency, against this
profile. Missing, duplicate, oversized or altered evidence cannot pass. Its
failure records contain fixed reasons rather than host register values.

## Fixed TSC rate on every launch path

Every launch uses `tsc_early_khz=2000000`. Lifecycle validates it before creating
the jail; CLI `plan`, CLI `boot-args` and Python direct-launch resolution use the
same value. The legacy `HERMETIC_TSC_KHZ` setting is optional and may only equal
`2000000`; any other value, including non-Unicode text, fails closed without
being echoed. Host CPUID calibration helpers remain for offline arithmetic tests
but are no longer called by executable launch paths. Specs cannot supply the
reserved parameter, including bare or hyphenated aliases. Argument caps include
the suffix. Python resolution pins the executable descriptor, bounds output and
has a five-second deadline.

The pinned patch requires `KVM_CAP_TSC_CONTROL` on every VM, calls
`KVM_SET_TSC_KHZ(2000000)` on each vCPU before cold boot and restore, and verifies
`KVM_GET_TSC_KHZ` returns exactly that rate. Upstream frequency-change entrypoints
reject any other requested rate. CPUID.15 is denominator 1, numerator 80, crystal
25 MHz; CPUID.16 is 2000 MHz base/maximum and 100 MHz bus. These values describe
the scaled guest counter, never the physical host counter.

The [KVM API](https://docs.kernel.org/virt/kvm/api.html#kvm-set-tsc-khz)
defines the vCPU frequency ioctl and TSC-control capability. Intel VMX implements
scaling with its hardware TSC multiplier; a host/outer hypervisor that does not
expose this facility cannot satisfy the capability check. Missing capability,
failed ioctl or unequal readback aborts startup with the fixed CPU/TSC/filter
error. A coincidentally matching physical frequency is insufficient. Actual
nested capability, multiple vCPUs, timing, pause/resume and snapshot restore
remain manager runtime checks.

With `PARAVIRT=n` and `KVM_GUEST=n`, `no-kvmclock` is inert and remains only for
lock/spec compatibility. `tsc=reliable` does not supply calibration by itself.
The boot, net, reboot, grader and extraction harnesses all use lifecycle.

## Host enforcement and remaining runtime validation

The [host filtering guide](clock-3b-host-filter.md) describes the MSR filter,
Xen interception of clock-pairing, offline double build, executable measurements
and manager-only ring-0 canary. Filtering is installed on each new VM fd and PV
enforcement follows each boot/restore CPUID installation. Unsupported hosts
abort. Guest lockdown alone cannot close these ring-0 channels.

Linux x86 force-selects `PERF_EVENTS`, so it cannot be forbidden in the kernel
config. Forced confidentiality lockdown restricts kernel reads through perf;
the fixed CPUID profile supplies no architectural PMU. Scheduling, contention,
instruction probing and other microarchitectural timing remain substrate side
channels. This patch does not claim to eliminate them.

Offline tests cover fixed-register known answers, all vCPU positions,
per-register mutations, invalid topology, host feature rejection, snapshot
mutation rejection, immutable builder/source/patch pins and launch paths. The
manager verified the full reproducible pinned-container build, nested ring-0
canary and stock negative control on 2026-11-14; measurements and results are in
the host filtering guide. Multiple vCPUs, pause/resume, snapshot restore and TSC
stability remain required before changing the advertised clock level.
