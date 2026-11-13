# Phase 3b proposal and manager test plan

These files are separate proposals. Do not replace `images/kernel/hermetic.config`,
`base-x86_64.config`, canonical boot arguments or `vmm/hide-kvmclock.cpu-template.json`.
Keep `clock: faked`. Source references and limitations are in
[the audit](clock-3b-analysis.md).

## Custom CPU template

`vmm/clock-3b.cpu-template.json` has the x86 shape and bitmap/register types from
Firecracker v1.18.0 `docs/cpu_templates/schema.json` and
`src/vmm/src/cpu_config/x86_64/custom_cpu_template.rs:96`. Offline regression
checks parse it with strict serde structs and exercise bitmap semantics against
known inputs. This validates the artifact format, not a KVM boot. The pinned
schema itself has weak property constraints; the regression also checks widths,
unique leaf/register keys and intended mask values. No new dependencies are used.

| Modifier | Exact intended action | Limitation |
| --- | --- | --- |
| 40000001:0 EAX | clear 0,3,5,24; preserve other bits | not a clock-pairing filter; optional PV enforcement is not enabled by JSON |
| 1:0 EAX | set 000406f1 (Broadwell-EP experiment) | owner must select a baseline no newer than each task cutoff |
| 1:0 ECX | clear 2,3,5,6,7,8,10,14,15,18; preserve other bits | preserve AVX/OSXSAVE/FMA/F16C consistency; no new ISA bits forced on |
| 7:0 EAX | zero maximum structured subleaf | 7:1 is explicitly zeroed too |
| 7:0 EBX | preserve only 0,1,3,5,7,8,9,10,18,19,20; clear others | conservative baseline feature subset, not full identity normalization |
| 7:0 ECX/EDX and 7:1 all registers | zero | unsupported leaf/subleaf modifiers make F reject startup; inspect supported keys in L1 |
| A:0 all registers | zero | stock Intel F already normalizes PMU to zero |
| 15:0 and 16:0 all registers | zero frequency advertisements | do not activate until accurate TSC calibration is supplied |
| 80000002..80000004 all registers | desired padded `Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz` | **overwritten by stock F normalization**, not an effective identity fix |
| msr_modifiers | empty | removed unnecessary initial TSC_ADJUST write; MSR initialization is never an access filter |

No template claims to hide cache/XSAVE/extended-leaf identity. Host vendor and
Intel brand/frequency normalization require a VMM decision/change. Custom templates
are installed before start with **PUT /cpu-config**; a static `machine-config.cpu_template`
name is not a file-path interface and there is no supported `--cpu-template` flag
in the pinned CLI. `kvm_capabilities` only changes support checks. The proposal
cannot activate PV enforcement or an MSR/hypercall filter.

## Kernel and boot experiments

Merge base, current hermetic fragment, then `images/kernel/clock-3b.config` in an
isolated **L1 nested test VM**, using the pinned kernel/build identity and network-
disabled reproducible build process. Every proposed symbol was checked against
Linux 6.6.160 Kconfig; CONFIG_DEVKMEM was removed because it does not exist there.
Run olddefconfig, then compare every requested value to final .config; symbol
existence is not proof that dependencies retained a value. Check the existing
required-driver/kernel policy too. This branch does not claim a built/tested kernel.

The fragment removes root's module/MSR/physical-memory/kexec/hibernation/raw-port
interfaces, guest PTP/RTC/HPET/PM timer and perf inspection, and enables the
confidentiality lockdown framework with SECURITY=y. It preserves required
virtio block/net/vsock/rng/console, filesystems, devtmpfs/proc/sysfs/devpts,
cgroup v2 controllers, namespaces, netfilter and BPF. Lockdown/driver removals
reduce guest attack surface; they do not filter KVM when ring-0 code is obtained.
CAP_SYSLOG root can read restricted logs. Pagemap removal does not turn a CPL3
hypercall into a CPL0 hypercall, or replace host denial.

For the reported PIT stall, first test **tsc_early_khz=<actual guest KVM TSC kHz>**
in L1/L2 while retaining clocksource=tsc tsc=reliable and the normal
hermetic.t/read-only/init settings. Obtain the rate from KVM_GET_TSC_KHZ in the
manager's VMM instrumentation; do not guess from cpu MHz. This exposes virtual
frequency (host rate without scaling), so retain `faked`. A fixed published
frequency needs actual per-vCPU KVM_SET_TSC_KHZ scaling before cold boot,
consistent CPUID/APIC configuration and offset checks. Stock F's restore-only
helper is not a cold-boot setting. These runtime changes require owner/VMM work.

Keep MMDS off and only sealed vsock services; use isolated NetVM endpoints and
full image timestamp validation. Do not change host sysctls or host clocksource
from these instructions. Setting a non-TSC clocksource on a dedicated L1 can be
a negative test of hypercall 9, but wall MSRs still leak without their own block.
No arbitrary tune2fs command is claimed to normalize all filesystem timestamps.

## Today's baseline inside an already running AgentVM

This command uses the existing boot-smoke execd protocol, with **no kernel,
CPU-template or boot-argument change**. The manager supplies the existing
Firecracker vsock backend socket as the first argument; it is the socket ending
in `vsock` under the running AgentVM's prepared jail root. A completed boot-smoke
run has already destroyed its VM; this command requires an existing running VM
with execd unlocked and a uid-0 run spec. The sealed `/bin/busybox` is required,
as in `crates/hermetic-vmm/tests/guest.rs`, with its gzip/sh applets. Do not use a production evaluated VM
with cumulative command-output budget already exhausted.

Build the probe from the worktree root:

```sh
RUSTFLAGS='-C target-feature=+crt-static' cargo build --offline --locked --release \
  --target x86_64-unknown-linux-gnu -p hermetic-clockprobe
```

Then run exactly the following, replacing only `/path/to/running-agent/vsock`
and using the build output under the Cargo target directory used above:

```sh
python3 -I - /path/to/running-agent/vsock \
  target/x86_64-unknown-linux-gnu/release/hermetic-clockprobe <<'PY'
import gzip, json, socket, struct, sys, time
MAX_TRANSFER = 1024 * 1024
MAX_EXECUTABLE = 4 * 1024 * 1024
MAX_FRAME = 4 * 1024 * 1024 + 65536
MAX_HANDSHAKE = 64
MAX_CALLS = 4
CALL_DEADLINE_SECONDS = 15

def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise RuntimeError('execd deadline')
    return left

def exact(sock, n, deadline):
    out = bytearray()
    while len(out) < n:
        sock.settimeout(remaining(deadline))
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError('short execd frame')
        out.extend(chunk)
    return bytes(out)

calls = 0

def call(request):
    global calls
    calls += 1
    if calls > MAX_CALLS:
        raise RuntimeError('execd call cap')
    body = json.dumps(request, separators=(',', ':')).encode('ascii')
    if not 0 < len(body) <= MAX_FRAME:
        raise RuntimeError('execd request cap')
    deadline = time.monotonic() + CALL_DEADLINE_SECONDS
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(remaining(deadline))
        sock.connect(sys.argv[1])
        sock.settimeout(remaining(deadline))
        sock.sendall(b'CONNECT 5000\n')
        hello = bytearray()
        for _ in range(MAX_HANDSHAKE):
            hello.extend(exact(sock, 1, deadline))
            if hello.endswith(b'\n'):
                break
        if hello != b'OK 5000\n':
            raise RuntimeError('execd handshake')
        sock.settimeout(remaining(deadline))
        sock.sendall(struct.pack('<I', len(body)) + body)
        n, = struct.unpack('<I', exact(sock, 4, deadline))
        if not 0 < n <= MAX_FRAME:
            raise RuntimeError('execd reply cap')
        return json.loads(exact(sock, n, deadline))

# Bounded trusted build artifact, compressed to fit the execd transfer cap.
# Run before adversary handoff; the sealed busybox must include gzip and sh.
with open(sys.argv[2], 'rb') as probe:
    executable = probe.read(MAX_EXECUTABLE + 1)
if not executable or len(executable) > MAX_EXECUTABLE:
    raise RuntimeError('probe executable cap')
data = gzip.compress(executable, mtime=0)
if len(data) > MAX_TRANSFER:
    raise RuntimeError('compressed probe exceeds upload cap')
status = call({'type': 'status'})
if status.get('type') != 'status' or status.get('locked') is not False:
    raise RuntimeError('execd must be ready and unlocked')
if call({'type': 'upload', 'path': '/work/hermetic-clockprobe.gz', 'data': list(data)}).get('type') != 'ok':
    raise RuntimeError('probe upload failed')
mode = call({'type': 'exec', 'argv': ['/bin/busybox', 'sh', '-c',
             '/bin/busybox gzip -dc /work/hermetic-clockprobe.gz > /work/hermetic-clockprobe && /bin/busybox chmod 0700 /work/hermetic-clockprobe'],
             'tty': False, 'timeout_ms': 5000})
if mode.get('code') != 0 or mode.get('timed_out') or mode.get('truncated'):
    raise RuntimeError('probe decompression/mode setup failed')
reply = call({'type': 'exec', 'argv': ['/work/hermetic-clockprobe'], 'tty': False, 'timeout_ms': 10000})
if reply.get('type') != 'exec' or reply.get('timed_out') or reply.get('truncated'):
    raise RuntimeError('incomplete probe execution')
output = reply.get('output')
if not isinstance(output, list) or len(output) > MAX_TRANSFER:
    raise RuntimeError('probe output cap')
sys.stdout.buffer.write(bytes(output))
sys.stdout.buffer.flush()
code = reply.get('code')
if code not in (0, 1, 2):
    raise RuntimeError('unexpected probe exit')
raise SystemExit(code)
PY
```

If CARGO_TARGET_DIR is set, substitute that directory for `target` in the second
command. All raw values belong in the manager's private baseline record, never
in evaluated agent logs. This command was checked against execd's frame/transfer/
upload/output contract with an offline fake socket and a >1 MiB executable; it has **not** been run against a guest in this branch.
Do not interpret `unavailable` or an error as a passing hidden-clock check.

## Nested tests and acceptance

Use a disposable L1 KVM VM, set its clock to a known canary distinct from
T_clock, and run Firecracker only inside that VM. Build/install the probe and
kernel there. First capture the unchanged baseline with the command above.
Then repeat with only the proposed kernel fragment, and only after the TSC
calibration experiment succeeds, with the separate CPU proposal. Record all
JSON records, stderr, execd timeout/truncation flags and exit status.

| Change / channel | Expected observation | Required negative/control |
| --- | --- | --- |
| cold-boot TSC offset | rdtsc counter age close to guest uptime | controlled stale guest TSC produces prior-origin finding; repeat all vCPUs and restore cases |
| MSR interface removal | kvmclock_msr blocked for absent userspace device | debug L2 kernel with a reviewed pinned-page kernel test: both old/new wall and system WRMSR plus version-consistent pages; no guessed GPA writes |
| hypercall boundary | userspace unavailable; cannot certify CPL0 denial | debug L2 kernel caller for hypercall 9, host-TSC on/off controls; PV-enforcement on alone must not be claimed to block it |
| CPUID enforcement | checked legacy/new MSR writes denied when clock bits cleared | enable capability on every vCPU and run each write with bit 0/3 on/off independently; requires VMM work |
| CPUID identity proposal | inspect fixed signature and zeroed listed registers | actual .15/.16 and Intel brand after normalization must be checked; brand override is expected to fail on stock F; enumerate other leaves separately |
| RTC / timer interfaces | absent RTC paths blocked; PIT presence may be unavailable | safe RTC ioctl and timer-origin tests required before attestation; mere PIT presence is not a leak |
| VMClock | pinned ABI UNKNOWN/INVALID, all time/rate fields zero | validate content even without a driver using an owner-reviewed kernel test; populate a canary valid ABI as detector control |
| kernel log | no unexpected dates; pinned build banner manually classified as substrate | synthetic postcutoff dates including banner, non-ASCII prefix and second date on line are regression fixtures |
| realtime / full POSIX | realtime matches fake epoch; partial probe unavailable | canary real-date run must report leak; full CLOCK_TAI/MONOTONIC sampling remains OPEN for safe wrapper choice |
| services / storage / timing | sealed payloads/metadata only | separate packet, filesystem timestamp, serial-input and side-channel review; not covered by a clock probe exit code |

Full kernel/VMM boots, canary exploits and the residual-risk decision remain
manager-owned work. Until these pass, keep Phase 3b open and `clock: faked`.
