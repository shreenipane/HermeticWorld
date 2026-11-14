# Phase 3b clock and CPU boundary

The supported level remains **`clock: faked`**. Guest lockdown closes the
supported root interfaces for installing kernel code and reading kernel memory.
It cannot establish the boundary required by TR-VMM-3 against arbitrary guest
kernel execution. No host kernel or VM was booted during this offline review.

Source checks used the cached Linux 6.6.160 source and Firecracker v1.18.0,
commit `eaf83bb718a559d324613d566eaf776b31a62340`. These are source checks;
applicability to the owner's host KVM and runtime CPUID remains unverified.

## Calibration and launch paths

`hermetic-vmm` resolves a bounded frequency before creating the jail. On a
bare-metal Intel host it uses complete CPUID.15 crystal/ratio data. AMD and
nested hosts, and Intel hosts without complete CPUID.15 data, require
`HERMETIC_TSC_KHZ` set to the actual virtual TSC kHz verified by the operator.
An invalid override, including non-Unicode text, always fails. CPUID wins on an
eligible host. Frequencies are restricted to 100,000 through 10,000,000 kHz;
there is no guessed rate or pvclock fallback.

The lifecycle, executable CLI `plan`, and CLI `boot-args` use the same resolver.
The Rust `api_requests` function is a declarative spec plan; it must pass through
`calibrated_api_requests` before execution. Python `spec_boot_arguments` and the
kernel lock likewise contain only VmSpec inputs. Python `boot_arguments(t,
vmm=Path(...))` obtains executable arguments from the pinned VMM descriptor,
with bounded output and a five-second deadline. Specs cannot set the reserved
TSC parameter, including bare or hyphenated spellings. The argument-size cap
includes the VMM suffix.

The launch audit found that boot, net, reboot, grader-VM and extraction/grader
smokes all start through `Vmm::prepare/start/wait_ready`, including the grader
and `tests/support` fixtures. They inherit calibration and the active template.
There is no separate shell or Python Firecracker boot-source request to patch.

With `PARAVIRT=n` and `KVM_GUEST=n`, `no-kvmclock` is inert: the parser is in
`arch/x86/kernel/kvmclock.c`, compiled only with KVM_GUEST by the kernel Makefile.
It remains in the canonical lock/spec string for compatibility and contributes
no isolation guarantee. `tsc=reliable` supplies no calibration frequency.

## CPU profile and stock VMM limits

`vmm/clock-3b.cpu-template.json` is the embedded active profile. It requests an
experimental Broadwell-EP signature and brand, masks the hypervisor vendor/PV
leaves, preserves the existing kvmclock bit-0/bit-3 denial, zeros PMU and
frequency leaves, and restricts structured features to the existing baseline.
The old narrow template remains a reference fixture and is refused as an active
profile. The API and staged input require equality with the embedded profile;
golden requests cover the full object. No MSR values or arbitrary frequency
ratios are invented.

Field names and encoding were verified against Firecracker 1.18's
[CustomCpuTemplate, CpuidLeafModifier and CpuidRegisterModifier](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/cpu_config/x86_64/custom_cpu_template.rs):
`cpuid_modifiers`, `leaf`, `subleaf`, numeric `flags`, `modifiers`, lowercase
`register`, 32-bit `bitmap` with `0/1/x`, and `msr_modifiers`.
**Runtime application is unverified here.**

**OPEN, owner/VMM decision:** stock Firecracker's
[template application](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/cpu_config/x86_64/mod.rs)
rejects unsupported leaf/subleaf keys; the profile may fail closed on older,
AMD or nested KVM CPUID sets. It must never silently fall back to the old mask.
A portable profile needs host capability handling and a complete feature/layout
policy. AMD support is deferred pending that design and owner VM tests.

**OPEN, owner/VMM decision:** subsequent
[common normalization](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/cpu_config/x86_64/cpuid/normalize.rs)
restores the host vendor and hypervisor bit; Intel
[brand normalization](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/cpu_config/x86_64/cpuid/intel/normalize.rs)
overwrites template brand words and can include the host frequency suffix.
These masks therefore do not promise a fixed runtime brand. Cache, topology,
XSAVE and unenumerated leaves also need a complete identity policy. Changing
normalization requires the external Firecracker component. The experimental
2016 baseline itself needs owner acceptance for earlier task cutoffs.

## Kernel-exploit residual risk

**OPEN, owner decision:** a guest kernel exploit can still issue
`KVM_HC_CLOCK_PAIRING` at CPL 0 or write the KVM wall-clock MSRs. Linux 6.6.160
`arch/x86/kvm/x86.c` handles hypercall 9 without a CPUID feature gate, and MSR
feature enforcement is opt-in. Guest config, a custom CPU mask and disappearance
of device nodes do not filter malicious kernel instructions. Stock Firecracker
does not provide the required host-side hypercall/MSR filtering. Closing these
paths needs host KVM/VMM changes and successful hostile ring-0 runtime tests;
those changes are outside this branch. Until then, retain `faked`.

**OPEN, owner/VMM decision:** the actual TSC rate appears in the guest command
line and can be measured with RDTSC. Masking CPUID.15/.16 does not hide it.
A fixed published frequency requires actual per-vCPU TSC scaling first; stock
Firecracker exposes no cold-boot frequency control. Scheduling and contention
remain relative side channels. Never replace the true rate with a baseline
number merely to hide it.

Linux x86 force-selects `PERF_EVENTS` (`arch/x86/Kconfig`), so it cannot be a
forbidden kernel option. Forced confidentiality lockdown restricts kernel
reading through perf; the CPU profile requests an empty architectural PMU.
This does not eliminate timing or microarchitectural side channels. The probe
checks the enumerated PMU/CPU inputs, and unavailable channels remain unproven.
