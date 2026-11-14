# Phase 3b clock and host-identity audit

Status: **proposal and diagnostic only; `clock: faked`**. No kernel, boot argument,
base configuration, or active CPU template is changed. A zero probe exit code
is not evidence for `clock: hidden`: `unavailable` means an untested channel.

## Evidence and scope

`L:` means the extracted Linux **6.6.160** tarball, SHA-256
`b24c40a9e2188695803358567edda51c4080176424a57dbefca45e5ac44ec225`.
`F:` means Firecracker **v1.18.0**, commit
`eaf83bb718a559d324613d566eaf776b31a62340`. Sources are in the ignored
`.scratch/clock-3b/linux-6.6.160/` and `.scratch/clock-3b/firecracker/` directories.
Line references below are to those exact sources. The Firecracker tag was
fetched from its upstream repository; neither source tree is part of the change.

The guest kernel version does **not** establish the host KVM version. All host
KVM answers below are verified for L; the actual running host KVM and today's
in-VM baseline remain **unverified** until the manager runs the command in
[the test plan](clock-3b-config-and-test-plan.md). The active
`images/kernel/base-x86_64.config:26` enables PARAVIRT/KVM_GUEST and `:29` enables
MODULES. The active template clears only KVM clock bits 0 and 3. A trusted guest
kernel is the user/root boundary; root is not automatically CPL 0, but an
unrestricted loadable module gives root CPL 0. Kernel exploitation is not
modeled as an already successful arbitrary-code-execution primitive.

## 1. TSC, frequency, TSC_ADJUST and deadline timer

**Verified, with corrections.** L:`arch/x86/kvm/x86.c:12106` initializes the
vCPU TSC through `kvm_synchronize_tsc(vcpu, 0)`; `:2594` computes an offset from
the scaled host TSC and `:2740` synchronizes it. F:
`src/vmm/src/arch/x86_64/msr.rs:411` also includes a zero IA32_TSC boot MSR.
Cold-boot guest RDTSC therefore starts near the guest creation/boot origin,
not the host boot origin. RDTSC divided by a known rate is a counter age, not
proof of host uptime: host reset semantics, scaling, previous guest writes,
and restore history matter. RDTSCP additionally supplies guest TSC_AUX; the
probe uses RDTSC, not an unconditional RDTSCP on unsupported hardware.

CPUID.15 supplies a TSC/crystal ratio when all three fields are valid; CPUID.16
supplies processor base/max/bus MHz, **not an architectural guarantee of the
TSC frequency**. L:`arch/x86/kernel/tsc.c:658` and `:729` distinguish these.
The draft's CPU-brand/base-MHz fallback was not sound evidence for TSC uptime.
The probe instead uses CPUID.15, or a bounded RDTSC/Instant interval estimate.
Masking frequency leaves cannot conceal the slope of a measurable TSC.

TSC_ADJUST (0x3b) is per-vCPU state, not a direct read of the host register
(L:`arch/x86/kvm/x86.c:3750`, `:4181`). A template setting its initial value is
not a filter on later MSR access. The deadline timer (0x6e0) compares guest TSC
units, not UTC (L:`arch/x86/kvm/lapic.c:1859`). Its timing jitter can reflect
host scheduling. Snapshots preserve guest history and require separate reset
and elapsed-time policy; cold-boot offset evidence does not prove restore safety.

Current cold-boot counter-origin isolation is supported by source; the runtime
probe comparison is still required. Frequency and other hardware signatures
remain exposed. The separate proposal clears .15/.16, **pending** the calibration
solution in section 13; it is not safe to activate it alone.

## 2. pvclock and kvmclock MSRs

**Wrong in draft; fixed.** Constants are verified at
L:`arch/x86/include/uapi/asm/kvm_para.h:47`: legacy wall/system MSRs are
0x11/0x12; new wall/system MSRs are 0x4b564d00/0x4b564d01. L:
`arch/x86/kernel/kvmclock.c:288` checks CPUID bits 3/0, so masking both prevents
cooperative guest initialization.

The host **does have** `guest_pv_has` checks for all four reads and writes
(L:`arch/x86/kvm/x86.c:3823`, `:4204`). However,
L:`arch/x86/kvm/cpuid.h:237` returns true regardless of CPUID when
`vcpu->arch.pv_cpuid.enforce` is false. Enabling the **per-vCPU** capability
KVM_CAP_ENFORCE_PV_FEATURE_CPUID with args[0]=1 activates these checks
(L:`arch/x86/kvm/x86.c:5677`). Merely checking capability support is insufficient.

F:`src/vmm/src/arch/x86_64/vcpu.rs:139` creates/configures the vCPU without this
enable-cap call; a search of F's `src/` finds no ENFORCE_PV or MSR-filter
installation. F:`src/vmm/src/vstate/kvm.rs:29` checks supported capabilities;
`:46` combines the custom template's `kvm_capabilities` into that **checklist**.
That JSON field does not enable capabilities. `msr_modifiers` initialize MSR
values; they do not install KVM_X86_SET_MSR_FILTER.

Thus on inspected host KVM + stock F, a CPL-0 guest can write these MSRs even
with both CPUID bits clear. A system-time write of GPA|1 enables a guest-memory
pvclock page; L:`arch/x86/kvm/x86.c:3246` fills system_time and conversion fields.
`:12474` gives kvmclock its VM-relative origin. Its conversion factors reveal
virtual TSC rate, not necessarily physical host rate when scaling is in use.
A plain RDMSR returns the configured guest address/control value, **not the
page's date**. The diagnostic reads only /dev/cpu/0/msr and never writes guessed
GPAs. Read success/rejection is `unavailable` for the write/page exploit.

Mitigation proposal: remove root's module/MSR/memory/kexec interfaces in the
trusted guest. A stronger VMM boundary needs per-vCPU enforcement and/or a
proper MSR filter. That implementation is **OPEN outside this branch**.

## 3. KVM_HC_CLOCK_PAIRING and other hypercalls

**Several draft claims were wrong; fixed.** Hypercall 9 is defined in
L:`include/uapi/linux/kvm_para.h:29`; wallclock selector 0 and returned struct
are at L:`arch/x86/include/uapi/asm/kvm_para.h:74`. The handler at
L:`arch/x86/kvm/x86.c:9765` writes sec/nsec plus guest TSC into a supplied GPA.
It succeeds only for the supported selector, a writable guest GPA, a suitable
TSC-based **host clocksource**, and no permanent TSC catch-up mode.
`:2922` checks the actual host vclock mode; constant_tsc capability alone is
insufficient. A successful call returns the host's real current wall time.

L:`arch/x86/kvm/x86.c:9935` rejects **every normal KVM hypercall from CPL != 0**
with -KVM_EPERM. UID 0 userspace is still CPL 3. Translating a userspace page
with pagemap and issuing VMCALL therefore does not bypass this check. The
architectural occurrence of a VM exit does not imply successful KVM dispatch.
The probe does not issue VMCALL/VMMCALL or create writable physical mappings.

At `:9957`, CLOCK_PAIRING dispatch has **no guest_pv_has check**. Enabling
KVM_CAP_ENFORCE_PV_FEATURE_CPUID does **not** block this hypercall in L. At
`:118`, KVM_EXIT_HYPERCALL_VALID_MASK contains only MAP_GPA_RANGE (12); enabling
KVM_CAP_EXIT_HYPERCALL for bit 9 is rejected by `:6469`. Both proposed draft
hypercall filters were incorrect for this kernel.

The missing guest PTP driver prevents a cooperative caller, not a malicious
module. With active MODULES=y, root can supply a CPL-0 caller and obtain real
time under the above host conditions. Removing root's ring-0 interfaces is a
guest policy option; a robust hypercall denial in host KVM needs a reviewed host
change (**OPEN**). A non-TSC host clocksource makes this handler unavailable,
but does not stop wall-clock MSR writes. No host settings are changed here.
The other cases in `kvm_emulate_hypercall` (`:9905`) return scheduling/IRQ/mapping
results rather than time. Xen/Hyper-V early dispatch paths are separate modes;
this audit's current KVM CPUID profile does not configure them.

## 4. Wall-clock epoch

**Verified with corrections.** L:`arch/x86/kvm/x86.c:2334` implements
`kvm_write_wall_clock`: it computes `ktime_get_real_ns() - get_kvmclock_ns(kvm)`
and writes version, seconds and nanoseconds to guest RAM. This is a
**VM-clock epoch**, not the host boot timestamp. Combining it with kvmclock
system time reconstructs real current time. The draft's
`kvm_get_wall_clock_epoch` function does not exist in the inspected x86 code.
The enforcement and root-access conclusions in section 2 apply. Guest
clock_settime does not alter host KVM's value. Clearing CPUID alone is not the
current root boundary.

## 5. Steal time and other PV features

**Verified; draft bit numbers corrected.** L:
`arch/x86/include/uapi/asm/kvm_para.h:19` defines clock bits 0/3, async PF 4,
steal 5, EOI 6, unhalt 7, TLB flush **9**, async PF VMEXIT **10**, send IPI **11**,
poll control **12**, sched yield **13**, async PF INT **14**, extended destination
ID **15**, GPA-map hypercall **16**, migration control **17**, stable-clock hint
24. The ABI structs are in the same file at `:63` and `:101`.

L:`arch/x86/kvm/x86.c:3619` accumulates scheduler run-delay deltas for steal
time. It reveals host contention during the guest's run, not UTC or host boot
time. APF tokens and the PV EOI byte carry no wall-clock fields. The stable bit
is a hint, not an independent clock. Clearing 5/24 in the proposal reduces
exposed PV state; it is not a remedy for hypercall 9. Relative contention/jitter
remains a residual channel, pending the owner's acceptance criteria.

## 6. CPU and hypervisor identity

**Wrong in draft; fixed.** F starts from KVM supported CPUID
(`src/vmm/src/arch/x86_64/kvm.rs:57`) and applies custom modifiers
(`src/vmm/src/cpu_config/x86_64/mod.rs:50`). `:71` rejects modifications to
unsupported leaf/subleaf keys, so schema validity does not prove applicability
to every host. The guest can execute CPUID despite CONFIG_X86_CPUID=n.

F subsequently calls normalization before SET_CPUID2
(`src/vmm/src/arch/x86_64/vcpu.rs:211`). Common normalization explicitly restores
**host vendor ID** (`src/vmm/src/cpu_config/x86_64/cpuid/normalize.rs:191`). Intel
normalization overwrites the brand (`intel/normalize.rs:279`), deriving a generic
Xeon name **with the host's parsed frequency suffix** (`:317`); AMD uses its
fixed default (`amd/normalize.rs:87`, `:379`). Therefore the proposal's fixed
brand modifiers do **not survive** stock F's normalization. The previous claim
that all host model strings pass through unchanged was also false. Intel PMU
leaf .A is already zeroed (`intel/normalize.rs:247`).

The proposal uses a Broadwell-EP signature as an **experimental 2016 baseline**;
this is not suitable for every earlier benchmark cutoff. It preserves AVX,
OSXSAVE and AVX2 consistently rather than the draft's accidental AVX disable
with AVX2 left advertised. Post-baseline leaf-7 features are masked, but cache,
XSAVE layout, extended leaves, maximum leaves, topology and remaining flags can
still fingerprint a host. The KVM vendor string identifies the virtualization
substrate. A complete identity profile requires a cutoff-specific, feature-
consistent allowlist and a normalization change, **OPEN for owner/VMM work**.
The diagnostic only reports coverage for its enumerated leaves/model/flags;
`blocked` on that subset cannot attest every CPUID input or every vCPU.

## 7. VMClock

**Verified; draft ABI and IDs corrected.** The device is ACPI, not virtio.
F:`src/vmm/src/devices/acpi/generated/vmclock_abi.rs:135` has time_sec,
time_frac_sec, counter_value, period/error fields, tai_offset_sec, leap fields,
seq_count, disruption_marker and vm_generation_counter. It is wrong to say the
ABI cannot carry dates. But F:`src/vmm/src/devices/acpi/vmclock.rs:96` initializes
clock_status UNKNOWN, counter_id INVALID, flags for notification/generation, and
all other fields to zero. `:121` increments disruption/generation counters and
sequence on restore. It supplies **no valid wall-time or frequency pair** in
this pinned implementation. Device presence alone is not proof of a leak.

F:`vmclock.rs:195` advertises _HID **AMZNC10C**, _CID **VMCLOCK** (not AMZN0001).
These identify a device implementation. No VMClock driver/ABI exists in the
inspected L `drivers/ptp/` tree. The draft's exact upstream introduction version
is not established here and is withdrawn. The pinned device can still be read
through physical memory by a sufficiently privileged caller. The separate
guest proposal disables /dev/mem and PTP. A newer/backported driver or different
VMM needs an ABI validity/content test, not an automatic `leak` from its name.
No supported JSON switch to omit this device was found in F's resource/API code.

## 8. RTC, CMOS, PIT, HPET and PM timer

**Wrong in draft; fixed.** F:`src/vmm/src/arch/x86_64/vm.rs:170` explicitly calls
KVM_CREATE_PIT2 with KVM_PIT_SPEAKER_DUMMY. The emulated PIT is a relative
countdown timer, not a physical host uptime counter. Its existence is not a
wall-time leak and its existence does not guarantee successful calibration in
a nested environment. No x86 CMOS RTC, HPET or PM-timer emulation/ACPI entry was
found in F's x86 setup and device registration. The PL031 RTC code is for the
other architecture and is not evidence for x86 RTC support.

F:`src/vmm/src/arch/x86_64/vcpu.rs:759` initializes unmatched port reads to
**zero**, not 0xff; failed bus lookups leave that value. L:
`arch/x86/kernel/rtc.c:59` uses mc146818_get_time or returns zero on failure.
Do not assume the fallback date is always 1970: CMOS conversion and validity
handling also matter. Neither path supplies the host date in this x86 device
model. Test the observed pre-init boot log separately. Disabling RTC/HPET/PM
drivers reduces interfaces; disabling X86_IOPL_IOPERM closes root raw port I/O.
The probe inspects RTC sysfs/proc time and device presence. Direct RTC_RD_TIME
requires a safe ioctl wrapper, **OPEN under the current std-only/unsafe budget**.

## 9. Virtio, storage and network payloads

**Verified header facts; runtime isolation unverified here.** L:
`include/uapi/linux/virtio_vsock.h:56`, `virtio_net.h:129`, `virtio_blk.h:219`
define headers with CIDs/ports/credits, network offload metadata, and block
sector/type respectively, without UTC fields. F:
`src/vmm/src/devices/virtio/rng/device.rs:130` fills entropy using rand::fill;
the draft's specific direct /dev/urandom-read claim was not established.
Entropy and I/O scheduling have host-dependent timing but no specified encoded
date. Bytes delivered by those protocols can of course contain dates/identity.

L:`fs/ext4/ext4.h:1313`, `:1320`, `:1369` includes write/check/mkfs timestamps,
and inodes have other timestamps. Builders must normalize all of them;
`tune2fs -T` alone does not set every filesystem timestamp. Existing image
seal checks are separate from this diagnostic's coverage.

The draft's claim that TCP TSval directly equals host uptime is too strong:
L:`net/ipv4/tcp_output.c:807` adds tsoffset, and `tcp_ipv4.c:324` installs an
offset. It is still an unnecessary host timing surface. Isolate endpoints in
NetVM; fake CLOCK_REALTIME in a container does not reset its kernel monotonic
clock. A host namespace's tcp_timestamps sysctl is not a per-TAP-interface
setting. No host sysctls are changed here. MMDS must stay unconfigured; host
vsock services must carry only bounded, sealed application payloads. Endpoint,
HTTP Date/NTP/TLS, and backing-disk audits remain separate required tests.

## 10. Serial and kernel logs

**Verified with corrections.** L:`init/version-timestamp.c:28` builds the Linux
banner from compile identity/time. A pinned kernel release build timestamp can
itself be after a task cutoff; the project currently treats this as substrate,
not world evidence. The probe has no trusted build-banner input and therefore
**does not silently exempt every line containing `Linux version`**. It reports
all recognized dates outside T_clock ±1 day for manual substrate triage and
emits only dates, not arbitrary log lines (which may contain secrets).

CONFIG_SECURITY_DMESG_RESTRICT is a CAP_SYSLOG restriction, not denial of a
root adversary. Root lockdown alone is not proof that every log is unreadable.
Serial input, kernel boot arguments and build banners must contain only fixed
approved values. The probe never falls back to an untrusted /var/log/dmesg
file and never prints OS error strings or unsanitized command-line text.

## 11. POSIX clocks, PMU and relative side channels

**Verified scope, unverified runtime.** L:`kernel/time/timekeeping.c:165`
computes TAI from the guest timekeeper's realtime offset and its own tai_offset;
it is not a direct read of the host leap-second table. Guest boot/suspend
accounts also mean BOOTTIME-MONOTONIC is not by itself proof of a host leak.
PID 1 setting realtime establishes the configured fake epoch, not the MSR/
hypercall boundary. The suite checks realtime against hermetic.t + /proc/uptime
with a documented 60-second tolerance. PID 1 sets time after boot starts, so
this is a diagnostic tolerance, not a nanosecond guarantee.

std does not expose raw CLOCK_TAI or absolute CLOCK_MONOTONIC. The unsafe module
is limited to CPUID/RDTSC; adding raw clock syscalls there would exceed the
brief. Full POSIX sampling is therefore **OPEN** pending approval to reuse an
existing safe syscall wrapper or expand the allowed unsafe boundary. No fake
TAI or fabricated monotonic sample is emitted. Tests exercise the pure
four-clock classifier; the real probe labels partial coverage `unavailable`.

Intel F already hides architectural PMU CPUID; the proposal also removes guest
perf access. This does not eliminate hardware timing/microarchitectural side
channels. Elapsed time to sealed world peers is expected by this phase; host
contention, entropy timing and performance fingerprinting require an explicit
residual-risk decision before a hidden-clock claim. No finite probe proves
absence of all side channels.

## 12. PARAVIRT/KVM_GUEST policy

**Verified.** L:`arch/x86/Kconfig:782`, `:819` and
`arch/x86/kernel/Makefile` govern guest hooks; kvmclock initialization checks
were verified in section 2. These options do not grant arbitrary userspace
WRMSR or VMCALL access and disabling them does not filter host KVM operations.
Recommended nested experiment: disable both plus the root ring-0 interfaces
in the separate fragment, retain required virtio/filesystem/cgroup/namespace/
netfilter/BPF features, inspect the final olddefconfig, and measure multi-vCPU
boot/performance before adoption. Keep the current active settings until the
manager's tests and policy choice; no host changes in this branch.

## 13. Boot stall and safest TSC-frequency route

**Verified failure mechanism; observed stall cause remains unproven here.**
The reported `Unable to calibrate against PIT` diagnostic is emitted at
L:`arch/x86/kernel/tsc.c:858`. With no PIT result and no HPET/PM reference it
returns zero. `tsc_init` at `:1574` then marks TSC unstable if it cannot compute
kHz. `tsc=reliable` asserts reliability; it does **not** provide a missing
frequency. `clocksource=tsc` cannot register an uncalibrated source. Zeroing
.15/.16 removes possible early calibration inputs and can worsen this stall.
No matching stall log is present in this checkout's PHASES.md; the task's
reported observation is retained as an observation, not independently replayed.

L:`arch/x86/kernel/tsc.c:66` parses **tsc_early_khz=** as an unsigned kHz value;
`:1508` uses it in early frequency determination. The safest immediate boot
experiment is an accurately measured **guest virtual** KVM_GET_TSC_KHZ value
passed as tsc_early_khz, retaining clocksource=tsc tsc=reliable. It avoids a
PIT dependency without re-enabling pvclock. It reveals the virtual TSC rate in
/proc/cmdline, logs and cpuinfo; on an unscaled guest this fingerprints host
frequency. This experiment can only retain `clock: faked`.

For a hidden profile, choose a fixed rate and actually enforce it on every
vCPU with KVM_SET_TSC_KHZ before boot, verify scaling/support and offset behavior,
then publish the matching fixed tsc_early_khz or normalized .15 ratio. Stock F
exposes set_tsc_khz for restore (`src/vmm/src/arch/x86_64/vcpu.rs:661`, `:678`),
not a cold-boot machine-config frequency field. This requires VMM work outside
this branch. Inventing .15/.16 or tsc_early_khz=2400000 while the counter runs
at another rate corrupts timekeeping and timers. .15's crystal also informs
L's APIC calibration (`tsc.c:720`), so avoid arbitrary fake ratios. Re-enabling
kvmclock supplies accurate conversion but reopens absolute wall time without
host-side filtering. Neither a made-up frequency nor that fallback is accepted.

## Channel matrix

| Channel | Leaks what | Blocked now? | Mitigation / decision | Diagnostic coverage |
| --- | --- | --- | --- | --- |
| RDTSC/RDTSCP | elapsed time, frequency, possibly prior counter origin | cold-boot offset verified in source; runtime unverified | test offsets; normalize actual rate before publishing it | rdtsc heuristic; unavailable without rate/uptime |
| pvclock system MSRs | virtual TSC conversion and VM elapsed time | CPUID alone insufficient | guest root interface removal; VMM enforcement/filter OPEN | kvmclock_msr reads only; writes untested |
| wall MSRs | VM epoch reconstructing real UTC | no with ring-0 access under stock F/L | same plus write/page regression | no safe GPA write test here |
| CLOCK_PAIRING | exact real UTC + guest TSC | CPL3 denied; CPL0 allowed with TSC host clocksource | guest restriction or host patch OPEN | clock_pairing_hc unavailable |
| steal/APF/EOI | contention / flags, no absolute timestamp | partly exposed | reduce PV features; decide residual jitter risk | cpuid advertisement only |
| CPUID / cpuinfo | host generation, frequency and layout | incomplete | full profile + normalization change OPEN | cpuid/cpuinfo subset, not attestation |
| VMClock | ABI can carry UTC; pinned F provides invalid/zero time | no valid timestamp in pinned source | audit ABI on upgrade; disable raw memory access | vmclock presence only |
| RTC / CMOS | date if implemented | no x86 RTC in inspected F | remove drivers/raw ports | rtc_sysfs_dev, proc_driver_rtc; ioctl OPEN |
| PIT / HPET / PM | relative timers; origin implementation dependent | PIT exists | investigate calibration; disable unused interfaces | hpet presence unavailable, not leak proof |
| virtio/network/block | dates/identity in payload/metadata | runtime unverified | seal storage, NetVM/services; MMDS off | separate payload/disk tests required |
| serial / boot logs | build/boot strings and dates | pinned build is substrate; root logs readable | normalize all inputs; manual banner triage | dmesg_dates bounded scan, not arbitrary text audit |
| POSIX clocks / PMU / side channels | fake time expected; timing/fingerprints possible | partial sampling only | fixed guest policy, perf off, residual decision | posix_clocks partial; full clocks OPEN |
