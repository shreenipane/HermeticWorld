//! The probe list (TR-SEC-6, architecture section 9.6). Targets are fixed
//! constants; records carry fixed labels, never addresses read at run time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::classify::{self, Attempt, EscapeRecord, EscapeResult};
use crate::{dns, sys};

pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);
pub const VSOCK_TIMEOUT: Duration = Duration::from_millis(50);
/// Leaves more than a minute for execd framing/cleanup under its 290 s exec cap.
pub const MAX_PROBE_RUNTIME: Duration = Duration::from_secs(180);
pub const EXECD_PORT: u32 = 5000;
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
pub const MOUNTINFO: &str = "/proc/self/mountinfo";
pub const MAX_RESOLV_BYTES: usize = 16 * 1024;
pub const MAX_RESOLVERS: usize = 3;

/// Real names that no sealed world serves.
pub const REAL_NAMES: &[(&str, &str, u16)] = &[
    ("google_a", "www.google.com", dns::QTYPE_A),
    (
        "cloudflare_time_aaaa",
        "time.cloudflare.com",
        dns::QTYPE_AAAA,
    ),
    ("worldtimeapi_a", "worldtimeapi.org", dns::QTYPE_A),
];
/// Delegation queries: NS for the root and a TLD.
pub const DELEGATION: &[(&str, &str, u16)] = &[
    ("root_ns", ".", dns::QTYPE_NS),
    ("com_ns", "com.", dns::QTYPE_NS),
];
pub const PUBLIC_RESOLVERS: &[(&str, Ipv4Addr)] = &[
    ("google", Ipv4Addr::new(8, 8, 8, 8)),
    ("cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
    ("quad9", Ipv4Addr::new(9, 9, 9, 9)),
];
pub const RAW_TCP: &[(&str, Ipv4Addr, u16)] = &[
    ("cloudflare_80", Ipv4Addr::new(1, 1, 1, 1), 80),
    ("google_443", Ipv4Addr::new(8, 8, 8, 8), 443),
    ("google_dns_tcp", Ipv4Addr::new(8, 8, 4, 4), 53),
    ("ntp_like_123", Ipv4Addr::new(162, 159, 200, 1), 123),
];
pub const ICMP: &[(&str, Ipv4Addr)] = &[
    ("google", Ipv4Addr::new(8, 8, 8, 8)),
    ("cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
];
pub const IPV6_TCP: &[(&str, Ipv6Addr, u16)] = &[
    (
        "cloudflare_443",
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        443,
    ),
    (
        "google_443",
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        443,
    ),
];
pub const QUIC: &[(&str, Ipv4Addr)] = &[
    ("cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
    ("google", Ipv4Addr::new(8, 8, 8, 8)),
];
/// vsock CIDs: 0 hypervisor, 2 host. CID 1 (guest-local loopback) is not an
/// exit: it reaches only services inside this guest.
pub const VSOCK_CIDS: &[u32] = &[0, 2];
pub const VSOCK_EXTRA_PORTS: &[u32] = &[
    1025,
    2049,
    3000,
    5000,
    5001,
    5002,
    5003,
    5004,
    5005,
    6000,
    8000,
    8080,
    8443,
    9000,
    9999,
    10000,
    50000,
    52000,
    65535,
    0x7fff_ffff,
    u32::MAX,
];
pub const DEVICES: &[(&str, &str)] = &[
    ("mem", "/dev/mem"),
    ("kmem", "/dev/kmem"),
    ("port", "/dev/port"),
    ("msr", "/dev/cpu/0/msr"),
    ("cpuid", "/dev/cpu/0/cpuid"),
    ("kvm", "/dev/kvm"),
    ("vhost_vsock", "/dev/vhost-vsock"),
    ("vhost_net", "/dev/vhost-net"),
    ("ptp0", "/dev/ptp0"),
    ("rtc0", "/dev/rtc0"),
    ("hpet", "/dev/hpet"),
];

/// Every record name this probe emits, in order. The host aggregator uses this
/// list to reject missing, extra or duplicate records.
pub fn expected_probe_names() -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..MAX_RESOLVERS {
        for (label, _, _) in REAL_NAMES.iter().chain(DELEGATION) {
            out.push(format!("dns.resolver{i}.{label}"));
        }
    }
    for (r, _) in PUBLIC_RESOLVERS {
        out.push(format!("dns.public.{r}"));
    }
    for (l, _, _) in RAW_TCP {
        out.push(format!("ip.tcp.{l}"));
    }
    for (l, _) in ICMP {
        out.push(format!("icmp.echo.{l}"));
    }
    for (l, _, _) in IPV6_TCP {
        out.push(format!("ipv6.tcp.{l}"));
    }
    out.push("ipv6.udp.google_dns".into());
    for (l, _) in QUIC {
        out.push(format!("quic.udp443.{l}"));
    }
    for cid in VSOCK_CIDS {
        out.push(format!("vsock.cid{cid}.scan"));
    }
    for (l, _) in DEVICES {
        out.push(format!("device.{l}"));
    }
    out.push("hostfs.mounts".into());
    out.push("kernel.module_load".into());
    out.extend(GATEWAY_PROBES.iter().map(|s| s.to_string()));
    out.push("positive.getrandom_nonblock".into());
    out.extend(INSTALL_PROBES.iter().map(|s| s.to_string()));
    out
}

/// Gateway abuse and the real model call need a run's gateway config; this
/// build reports them as unavailable, so the host verdict stays incomplete.
pub const GATEWAY_PROBES: &[&str] = &[
    "gateway.remote_source",
    "gateway.provider_tools",
    "gateway.other_endpoint",
    "gateway.other_model",
    "gateway.unlisted_beta",
    "gateway.quota",
    "gateway.model_call_date",
];
pub const INSTALL_PROBES: &[&str] = &[
    "positive.pip_install",
    "positive.git_clone",
    "positive.curl_get",
];

/// Parse up to `MAX_RESOLVERS` IPv4 nameservers from resolv.conf text.
/// Oversized, non-UTF-8 or unparsable input yields `None` (fail closed).
pub fn parse_resolv_conf(text: &[u8]) -> Option<Vec<Ipv4Addr>> {
    if text.len() > MAX_RESOLV_BYTES {
        return None;
    }
    let text = std::str::from_utf8(text).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let addr = words.next()?;
        match addr.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                if out.len() < MAX_RESOLVERS && !out.contains(&v4) {
                    out.push(v4);
                }
            }
            IpAddr::V6(_) => {}
        }
    }
    Some(out)
}

/// Combine a port scan: any reach is a leak, any unexpected errno an error.
pub fn classify_scan(attempts: &[Attempt]) -> (EscapeResult, &'static str) {
    if attempts.is_empty() {
        return (EscapeResult::Error, "empty scan");
    }
    let mut error = false;
    for a in attempts {
        match classify::classify_attempt(*a).0 {
            EscapeResult::Leak => return (EscapeResult::Leak, "vsock port reached"),
            EscapeResult::Error => error = true,
            _ => {}
        }
    }
    if error {
        (EscapeResult::Error, "unexpected errno in scan")
    } else {
        (EscapeResult::Blocked, "all ports refused")
    }
}

/// UDP exchange outcome to a classification for non-DNS datagrams (QUIC).
pub fn classify_datagram(outcome: Result<Option<Vec<u8>>, i32>) -> (EscapeResult, &'static str) {
    match outcome {
        Ok(Some(_)) => classify::classify_attempt(Attempt::Reached),
        Ok(None) => classify::classify_attempt(Attempt::Timeout),
        Err(e) => classify::classify_attempt(Attempt::Errno(e)),
    }
}

/// DNS exchange outcome to a classification.
pub fn classify_dns_exchange(
    id: u16,
    outcome: Result<Option<Vec<u8>>, i32>,
) -> (EscapeResult, &'static str) {
    match outcome {
        Ok(Some(reply)) => dns::classify_response(id, &reply),
        Ok(None) => (EscapeResult::Blocked, "no answer before deadline"),
        Err(e) => classify::classify_attempt(Attempt::Errno(e)),
    }
}

/// A QUIC v1 long-header Initial-shaped datagram, padded to 1200 bytes.
pub fn quic_initial() -> Vec<u8> {
    let mut p = vec![0u8; 1200];
    p[0] = 0xc3;
    p[1..5].copy_from_slice(&1u32.to_be_bytes());
    p[5] = 8;
    p[6..14].copy_from_slice(b"hermetic");
    p
}

fn rec(name: String, (r, d): (EscapeResult, &'static str)) -> EscapeRecord {
    EscapeRecord::new(name, r, d)
}

fn dns_query(server: Ipv4Addr, id: u16, name: &str, qtype: u16) -> (EscapeResult, &'static str) {
    let Some(q) = dns::build_query(id, name, qtype) else {
        return (EscapeResult::Error, "bad query name");
    };
    let out = sys::udp_exchange(
        SocketAddr::new(server.into(), 53),
        &q,
        CONNECT_TIMEOUT,
        dns::MAX_RESPONSE_BYTES,
    );
    classify_dns_exchange(id, out)
}

pub fn run_all() -> Vec<EscapeRecord> {
    run_with(|_| {})
}

/// Deliver each completed record immediately, before starting the next probe.
pub fn run_with(emit: impl FnMut(&EscapeRecord)) -> Vec<EscapeRecord> {
    let cfg = crate::config::load_config(None).ok().flatten();
    let (records, _) = run_with_config(cfg.as_ref(), emit);
    records
}

/// Run all probes with an explicit configuration.
pub fn run_with_config(
    cfg: Option<&crate::config::EscapeConfig>,
    mut emit: impl FnMut(&EscapeRecord),
) -> (
    Vec<EscapeRecord>,
    Option<hermetic_sealcheck::d12_runtime::SentinelSummary>,
) {
    let end = Instant::now() + MAX_PROBE_RUNTIME;
    let mut out = Vec::new();
    let mut push = |record: EscapeRecord| {
        emit(&record);
        out.push(record);
    };
    let mut id: u16 = 0x4857;

    let resolvers = sys::read_bounded(RESOLV_CONF, MAX_RESOLV_BYTES)
        .ok()
        .and_then(|t| parse_resolv_conf(&t));
    for i in 0..MAX_RESOLVERS {
        for (label, name, qtype) in REAL_NAMES.iter().chain(DELEGATION) {
            let probe = format!("dns.resolver{i}.{label}");
            let r = match &resolvers {
                None => (EscapeResult::Error, "resolv.conf unreadable or malformed"),
                Some(list) => match list.get(i) {
                    None => (EscapeResult::Unavailable, "no such resolver configured"),
                    Some(server) => {
                        id = id.wrapping_add(1);
                        dns_query(*server, id, name, *qtype)
                    }
                },
            };
            push(rec(probe, r));
        }
    }
    for (label, server) in PUBLIC_RESOLVERS {
        id = id.wrapping_add(1);
        push(rec(
            format!("dns.public.{label}"),
            dns_query(*server, id, "www.google.com", dns::QTYPE_A),
        ));
    }
    for (label, ip, port) in RAW_TCP {
        let a = sys::tcp_connect(SocketAddr::new((*ip).into(), *port), CONNECT_TIMEOUT);
        push(rec(
            format!("ip.tcp.{label}"),
            classify::classify_attempt(a),
        ));
    }
    for (label, ip) in ICMP {
        let a = sys::icmp_echo(*ip, CONNECT_TIMEOUT);
        push(rec(
            format!("icmp.echo.{label}"),
            classify::classify_attempt(a),
        ));
    }
    for (label, ip, port) in IPV6_TCP {
        let a = sys::tcp_connect(SocketAddr::new((*ip).into(), *port), CONNECT_TIMEOUT);
        push(rec(
            format!("ipv6.tcp.{label}"),
            classify::classify_attempt(a),
        ));
    }
    {
        id = id.wrapping_add(1);
        let q = dns::build_query(id, "www.google.com", dns::QTYPE_A).unwrap_or_default();
        let dst = SocketAddr::new(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).into(),
            53,
        );
        let o = sys::udp_exchange(dst, &q, CONNECT_TIMEOUT, dns::MAX_RESPONSE_BYTES);
        push(rec(
            "ipv6.udp.google_dns".into(),
            classify_dns_exchange(id, o),
        ));
    }
    let quic = quic_initial();
    for (label, ip) in QUIC {
        let o = sys::udp_exchange(
            SocketAddr::new((*ip).into(), 443),
            &quic,
            CONNECT_TIMEOUT,
            2048,
        );
        push(rec(format!("quic.udp443.{label}"), classify_datagram(o)));
    }
    for cid in VSOCK_CIDS {
        push(rec(
            format!("vsock.cid{cid}.scan"),
            scan_vsock(*cid, end, Instant::now, sys::vsock_connect),
        ));
    }
    for (label, path) in DEVICES {
        push(rec(
            format!("device.{label}"),
            classify::classify_device_open(sys::open_device(path)),
        ));
    }
    push(rec(
        "hostfs.mounts".into(),
        match sys::read_bounded(MOUNTINFO, classify::MAX_MOUNTINFO_BYTES) {
            Ok(t) => classify::classify_mountinfo(&t),
            Err(_) => (EscapeResult::Error, "mount table unreadable"),
        },
    ));
    push(rec(
        "kernel.module_load".into(),
        classify::classify_module_load(sys::init_module_empty()),
    ));
    let (gw_records, sentinel_summary) =
        crate::gateway::run_gateway_probes(cfg.and_then(|c| c.gateway.as_ref()), CONNECT_TIMEOUT);
    for r in gw_records {
        push(r);
    }
    let mut buf = [0u8; 32];
    push(rec(
        "positive.getrandom_nonblock".into(),
        classify::classify_getrandom(sys::getrandom_nonblock(&mut buf), buf.len()),
    ));
    let inst_records = crate::install::run_install_probes(cfg.and_then(|c| c.install.as_ref()));
    for r in inst_records {
        push(r);
    }
    (out, sentinel_summary)
}

/// The control listener is outside the escape surface. Probe every other
/// listed port in stable order; an incomplete scan must never claim blocked.
pub fn vsock_ports() -> impl Iterator<Item = u32> {
    (1..=1024u32)
        .chain(VSOCK_EXTRA_PORTS.iter().copied())
        .filter(|port| *port != EXECD_PORT)
}

pub fn scan_vsock(
    cid: u32,
    end: Instant,
    mut now: impl FnMut() -> Instant,
    mut connect: impl FnMut(u32, u32, Duration) -> Attempt,
) -> (EscapeResult, &'static str) {
    let mut attempts = Vec::new();
    for port in vsock_ports() {
        let Some(remaining) = end.checked_duration_since(now()).filter(|d| !d.is_zero()) else {
            return (EscapeResult::Error, "scan runtime cap exceeded");
        };
        let a = connect(cid, port, VSOCK_TIMEOUT.min(remaining));
        attempts.push(a);
        if a == Attempt::Reached || a == Attempt::Errno(libc::EAFNOSUPPORT) {
            break;
        }
    }
    classify_scan(&attempts)
}
