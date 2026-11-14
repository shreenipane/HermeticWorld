# hermetic-escapeprobe

Escape probe (TR-SEC-6, architecture section 9.6). Run as root inside a
throwaway AgentVM before each batch; prints one JSON line per probe
(`{"probe":..,"result":"blocked|leak|unavailable|error|ok","detail":..}`) with
fixed details that never echo host or network data. Exit 0 clean, 1 error, 2 leak.

Covers: DNS real names and NS delegation via each configured resolver and
public resolvers; raw TCP, ICMP echo, IPv6 TCP/UDP and QUIC-shaped UDP 443;
vsock scans of CID 0 and CID 2 (ports 1-1024 plus fixed high ports, excluding
execd control port 5000); host
device nodes (`/dev/mem`, msr, kvm, vhost, ...); host-share mounts; kernel
module loading (the kvmclock MSR / clock-pairing path); the positive
`getrandom(GRND_NONBLOCK)` check.

Host side: `hermetic-escapeprobe --aggregate < report` prints
`sealed|incomplete|escaped|invalid`; missing, duplicate, unknown or malformed
records are `invalid` (fail closed).

Not yet wired: gateway abuse probes, the real model-call date scan and the
pip/git/curl install checks report `unavailable`, so the verdict is
`incomplete` until they are.

Manager smoke: with the measured Firecracker binary/build lock and kernel inputs
already configured, run from the worktree root:

```sh
HERMETIC_ESCAPE_PROBE=1 scripts/integration/boot-smoke.sh [WORK_DIR]
```

This builds and installs the static probe, boots the guest, executes
`/sbin/hermetic-escapeprobe` with a 290-second execd timeout, and pipes the
captured output to the static host `hermetic-escapeprobe --aggregate`.
Escaped/invalid verdicts and failed, truncated or timed-out exec replies fail
the smoke. Incomplete is printed explicitly and is never a sealed attestation.
The mode can also use `HERMETIC_LOCKDOWN_CONFIG` to install the sealed config.

Records flush as each check completes. Each vsock attempt has a 50 ms cap;
the fixed network/port list fits below the 180-second probe watchdog even when
all connections time out. If the overall scan deadline expires, its result is
an error; a stalled syscall triggers the watchdog and leaves an invalid partial
report. The host accepts execd's bounded full reply size rather than applying
the smaller status-frame limit to the JSON byte-array output.
