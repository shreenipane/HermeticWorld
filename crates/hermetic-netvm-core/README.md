
# `hermetic-netvm-core`

Hermetic World network mediation core library and CLI binary (`hermetic-netvm`).

## Overview

`hermetic-netvm-core` isolates benchmark evaluation environments from post-cutoff world state while enforcing strict resource bounds, deterministic behavior, and an isolated Linux ABI boundary (see below):

1. **Pluggable Architecture**:
   - `DnsResponder`: answers DNS wire packets from an immutable in-memory table (`StaticDnsResponder` provided).
   - `RequestFilter`: inspects only the bounded HTTP request head (`MethodAllowFilter` forwards `GET` and `HEAD` as canonical JSON, returns `NotAllowed` for other valid HTTP methods, and `Reject` for malformed requests).
   - `Upstream`: fetches frozen world content within an explicit `Instant` deadline and streams the response body (`StaticUpstream` provided).
2. **Bounded Non-Forwarding UDP DNS Loop**:
   - Reads datagrams up to `MAX_DNS_PACKET_BYTES` (`512` bytes); oversized datagrams are dropped without parsing.
   - Enforces a fixed per-source IP token bucket (`DNS_BUCKET_CAPACITY`, `DNS_BUCKET_REFILL_PER_SEC`, bounded to `DNS_MAX_TRACKED_SOURCES` entries).
   - Never forwards queries to external resolvers.
3. **One-Request-Per-Connection HTTP/1.1 Loop & Response Hygiene**:
   - Enforces `MAX_CONCURRENT_CONNECTIONS`, immediately closing excess connections.
   - Enforces `head_timeout`, `chunk_write_timeout`, and `overall_timeout` so slow senders or slow readers cannot hold connection slots past their deadlines.
   - Emits `HTTP/1.1 405 Method Not Allowed` (`Content-Length: 0`, `Connection: close`, no `Date` or `Server` header) for disallowed methods and closes silently on `Reject`.
   - Passes only `content-type`, `content-length`, `etag`, `last-modified` (only when `<= T_clock`), `content-encoding`, `accept-ranges`, and `content-range` from upstream responses; strips `Date`, `Server`, `Set-Cookie`, `Age`, `Via`, all `X-*` headers, and any other headers.
4. **Structured Counter Logging**:
   - Emits JSON lines to `stderr` containing only event names and monotonic integer counters (never request bodies, never timestamps, never host names or host wall-clock time).

## Running

cargo run --bin hermetic-netvm -- \
  --dns 127.0.0.1:5353 \
  --http 127.0.0.1:8080 \
  --config config.json


## Testing

cargo test



## Frozen-world runtime

`hermetic-netvm serve --config netvm.json --dns-table dns.json --world-socket world.sock
--dns 127.0.0.1:5353 --http 127.0.0.1:8080` runs the real WorldServer transport
without privileged network effects. `netvm.json` contains only `{"t_clock":1700000000}`.
It accepts strict, capped regular files and refuses symlink path components.
`WorldDns` answers from `hermetic-netvm-dns::DnsTable`; `WorldFilter` applies
`hermetic-netvm-http` policy before encoding the common request wire frame.
Only GET, HEAD, authority, path/query and a single closed byte range cross the wire;
the current common frame has no request-header fields.

As PID 1 (no arguments), the same binary reads `/etc/hermetic/{netvm,dns}.json`,
mounts proc, sets the guest clock, installs a fixed IPv4 filter, disables forwarding
and IPv6, and brings up eth0. Boot applets run at a fixed busybox path with an empty
environment, discarded output and a five-second deadline, and are always reaped.
It powers off on failure before starting listeners. The image builder is
`python/hermetic_slice/netvm.py::build_netvm_image`.

The private link is NetVM `10.0.2.3/24`, AgentVM `10.0.2.15/32`. World A records
must be in `10/8` outside `10.0.2.0/24`; NetVM owns their sorted unique addresses as
`/32`s. A fixed legacy NAT PREROUTING table redirects eth0 TCP ports 80 and
443 at every destination address to the same local port. This is the documented
REDIRECT fallback for TPROXY: policy uses Host (and eventually SNI), never the
original destination IP. Conntrack reverses the translation for replies; no
external route is installed. INPUT and OUTPUT permit only UDP DNS and TCP HTTP
service ports; FORWARD drops everything. Port 443 remains denied pending TLS. This includes ICMP addressed to NetVM itself.
IPv6 is disabled before eth0 comes up. The filter uses the built-in legacy
ip_tables TCP/UDP match, `CONFIG_IP_NF_NAT`, `CONFIG_NF_NAT`,
`CONFIG_NF_CONNTRACK` and `CONFIG_NETFILTER_XT_TARGET_REDIRECT`, all required
built-ins in the existing kernel policy. The filter is installed before NAT;
either failure stops boot before eth0 is up. NAT state is capped by
`MAX_CONNTRACK_ENTRIES=1024` and `CONNTRACK_IDLE_SECONDS=30`; fragment
reassembly by `MAX_FRAGMENT_BYTES=262144` and `FRAGMENT_TIMEOUT_SECONDS=5`.
Boot lowers `ipfrag_low_thresh` before `ipfrag_high_thresh`: Linux 6.6 refuses
a high watermark below the current low watermark (3 MiB by default).
These sysctl settings must succeed before networking starts.

`VsockUpstream` connects only to host CID 2, port **5001** (5000 is execd, 5002 is
reserved for the gateway). It serializes increasing request IDs on a single
connection, including the streamed body, as required by sandboxed WorldServer.
Unix test endpoints are pinned by inode. Request validation precedes connect;
metadata, body length (64 MiB) and all I/O obey existing named caps and a total
request deadline. Abandoned bodies drain within that same deadline; failed
exchanges close the stream. No resolver or Internet socket is used.

Unsafe operations are isolated in `sys.rs`: Linux socket/connect/poll and the
fixed x86-64 filter-table ABI. Every other new runtime module forbids unsafe code.


For AgentVM, install `runtime::RESOLV_CONF` in the run spec's `resolv_conf` field;
execd publishes it as a regular file. Before starting the agent, the trusted
harness runs `runtime::agent_commands()` through execd as root (equivalently
`hermetic_slice.netvm.AGENT_NETWORK_COMMANDS`): static eth0 address, IPv6 off,
an explicit link route to `10.0.2.3/32`, and the sole default route via NetVM.
Using a /32 avoids direct ARP for other link addresses. Interception applies to
IPv4 packets delivered to NetVM; AgentVM loopback and its own local address
remain local, and unsupported protocols are dropped. These root commands belong to trusted
harness setup; the existing run-spec schema has no network-effect field.

TLS termination, CA-key boot delivery and dm-verity remain OPEN in PHASES.md.
The handoff approved rustls, but the current task forbids new dependencies; no TLS
library was added. HTTPS is denied rather than served with unchecked trust. See
`scripts/integration/BOOT_NOTES.md` for the remaining implementation plans and
exact owner-run two-VM commands. The smoke includes an HTTPS denial fetch; a
successful certificate-verified HTTPS fetch remains OPEN with TLS.
