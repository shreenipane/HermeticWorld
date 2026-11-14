# hermetic-escapeprobe

Escape probe (TR-SEC-6, architecture section 9.6). Run as root inside a
throwaway AgentVM before each batch; prints one JSON line per probe
(`{"probe":..,"result":"blocked|leak|unavailable|error|ok","detail":..}`) with
fixed details that never echo host or network data. Exit 0 clean, 1 error, 2 leak.

Covers: DNS real names and NS delegation via each configured resolver and
public resolvers; raw TCP, ICMP echo, IPv6 TCP/UDP and QUIC-shaped UDP 443;
vsock scans of CID 0 and CID 2 (ports 1-1024 plus fixed high ports); host
device nodes (`/dev/mem`, msr, kvm, vhost, ...); host-share mounts; kernel
module loading (the kvmclock MSR / clock-pairing path); the positive
`getrandom(GRND_NONBLOCK)` check.

Host side: `hermetic-escapeprobe --aggregate < report` prints
`sealed|incomplete|escaped|invalid`; missing, duplicate, unknown or malformed
records are `invalid` (fail closed).

Not yet wired: gateway abuse probes, the real model-call date scan and the
pip/git/curl install checks report `unavailable`, so the verdict is
`incomplete` until they are.
