# hermetic-clockprobe

Std-only guest diagnostic for Phase 3b. Run as root in the intended
x86_64 Linux guest, before handing it to an adversary. Never run the real probes
on the host: their purpose is to collect potentially sensitive guest-visible
clock and CPU evidence for the manager. Fixed order and JSON escaping are
deterministic; hardware/time samples themselves are observations, not reproducible
constants. The binary writes only JSON lines to stdout; I/O errors use fixed text.

From the worktree root, test offline with:

```sh
CARGO_NET_OFFLINE=true /home/flingboot/.hermetic/bin/rust-gate
```

Build a static GNU executable using the installed target, without a new musl toolchain:

```sh
RUSTFLAGS='-C target-feature=+crt-static' cargo build --offline --locked --release \
  --target x86_64-unknown-linux-gnu -p hermetic-clockprobe
```

The only unsafe module is `src/arch_x86.rs`, for the RDTSC intrinsic and Linux x86_64
module insertion syscalls with an empty image/invalid fd that cannot install code. CPUID's
intrinsic is safe on the current compiler. The sealed guest must leave CR4.TSD
clear; a kernel actively blocking instructions or falsifying procfs is outside
this diagnostic's trust assumptions. All other modules forbid unsafe code.
MSRs are read only from the checked CPU-0 MSR character device; there are no
WRMSR instructions, port access, device ioctls, guessed GPAs or hypercalls.

`src/read.rs` pins the inspection roots and path components using Linux O_PATH,
lstats before opening, checks descriptor identity/type, and only activates
regular files or the specifically checked kmsg/MSR devices. Relative sysfs
symlinks are expanded within the pinned root; escaping/absolute symlinks fail
closed. It uses its own `/proc/self/fd/N` links to act on pinned descriptors;
procfs must be the trusted kernel procfs. No guest-supplied executable is run. The module syscalls check only an empty
image and invalid fd, and accept raw -ENOSYS from both as evidence of compiled-out support.
Reads reject cap+1 and invalid UTF-8 rather than accepting truncated prefixes.
Caps: small files 4096 bytes, cpuinfo 65536 bytes, log 262144 bytes, directory
512 entries, path 4096 bytes/64 components, symlink expansion 32 links. Kmsg
uses 8192-byte record buffers and at most 512 records. Cap and unexpected I/O failures
become `error`, never `blocked`. Optional absence and log-access denial are distinguished from errors.

| Probe | Classification and limits |
| --- | --- |
| module_load | Empty init_module and invalid-fd finit_module must both return raw -ENOSYS; permission/invalid-image errors do not pass. |
| ring0_paths | Require a matching verified final config, live confidentiality lockdown, disabled unprivileged BPF and absent dangerous proc/sysfs driver interfaces. See the manager contract below. |
| rdtsc | CPUID.15 ratio or a 20 ms RDTSC/Instant rate estimate; counter age exceeding guest uptime by 60 s is `leak` evidence of a prior origin, not proof of physical host boot time. Missing comparison data is `unavailable`. Base MHz/brand MHz is not used as a guaranteed TSC rate. |
| cpuid | Dump all requested queries 0,1,7,7:1,A,15,16,40000000..40000010 and brand. Nonbaseline identity/frequency/PV features in this subset are policy `leak` observations; unknown/unqueried leaves remain outside coverage. Broadwell-EP is an experimental baseline, not an assertion about all task cutoffs. |
| kvmclock_msr | Absence of /dev/cpu/0/msr is `blocked` for this userspace path. Readable/rejected MSRs are `unavailable` for WRMSR/page-content exploits: RDMSR returns a guest address/control word, not UTC. |
| clock_pairing_hc | Inspect PTP names; always `unavailable` without a safe successful clock-pairing read. Device presence is not success. No raw hypercall is issued. |
| rtc_sysfs_dev / proc_driver_rtc | Compare parsed date against hermetic.t + guest uptime (60 s tolerance); absent interfaces are `blocked`; malformed proc dates are `error`. Device-only RTC access is `unavailable` pending a safe RTC_RD_TIME wrapper. |
| hpet | Legacy timer presence is `unavailable`, not proof of wall time/host uptime. No exposed timers is `blocked` for the inspected interfaces. |
| dmesg_dates | Scan bounded kernel records for all recognized calendar dates, including build banners; report `leak` outside T_clock ±1 day. Output dates only, never log text. Missing access is `unavailable`. A pinned substrate banner may require manual triage. This is not a general secret/string detector. |
| clocksource_sysfs | Current source other than tsc or unexpected available sources is a profile `leak`; missing/failed reads are `error`. Source names alone do not prove UTC disclosure. |
| posix_clocks | Read std realtime and proc boottime. Realtime divergence >60 s is `leak`; missing reference is `error`; otherwise `unavailable` because std exposes neither raw CLOCK_TAI nor absolute CLOCK_MONOTONIC. Never invent substitutes. |
| vmclock | Inspect /dev, PTP and ACPI IDs (AMZNC10C/VMCLOCK). A character interface without an ABI/content read is `unavailable`; absence is `blocked` for those inspected paths. |
| cpuinfo | Record model and flags; model differing from the fixed baseline or flags outside the explicit baseline allowlist is a profile `leak`; missing/invalid input is `error`. |

Exit 2 if any record is `leak`, else 1 if any is `error`, else 0.
**Exit 0 with `unavailable` is an incomplete diagnostic, not a hidden-clock pass.**
Pure parsing/classification fixtures and descriptor/cap tests run without guest
hardware. Imported draft assertions about readable MSRs, device presence,
frequency masking and banner exemption were corrected because those assertions
encoded false security conclusions. No pre-existing repository test was changed.

See [guest lockdown policy and manager commands](../../docs/guest-lockdown.md).
`--lockdown-only` emits just the two lockdown records for execd integration.
The manager must supply the verified matching config at
`/etc/hermetic/guest-kernel.config` and mount securityfs first.
Lockdown config reads are capped at 2 MiB, with 4096-byte lines; live state
reads are capped at 4096 bytes. The checks run before adversary handoff;
a substituted config or malicious kernel is outside their trust boundary.
Full POSIX/RTC ioctl coverage needs a safe wrapper already used elsewhere in the
workspace or an expanded unsafe allowance. Neither is silently added here.
