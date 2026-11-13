#![forbid(unsafe_code)]
//! Fixed x86-64 Linux legacy IPv4 filter and NAT tables. No packet bytes enter this encoder.
//! UAPI: linux/netfilter_ipv4/ip_tables.h and linux/netfilter/xt_tcpudp.h.
use std::io;

pub(crate) const MAX_OLD_RULES: usize = 16;
pub(crate) const REPLACE_HEADER_BYTES: usize = 96;
const ENTRY_BYTES: u16 = 112;
const TARGET_BYTES: u16 = 40;
const MATCH_BYTES: u16 = 48;
const DROP: i32 = -1;
const ACCEPT: i32 = -2;
const REDIRECT_TARGET_BYTES: u16 = 56;

pub(crate) struct Table {
    pub entries: Vec<u8>,
    pub hooks: [u32; 5],
    pub underflows: [u32; 5],
    pub count: u32,
}

/// REDIRECT is the interception fallback: ingress TCP keeps its destination
/// port but becomes local regardless of destination address. Conntrack restores
/// the original source address on replies. No external route is installed.
pub(crate) fn nat_table() -> Table {
    let mut t = Table {
        entries: Vec::new(),
        hooks: [0; 5],
        underflows: [0; 5],
        count: 0,
    };
    // The legacy NAT table has PREROUTING, INPUT, OUTPUT and POSTROUTING hooks.
    for hook in [0, 1, 3, 4] {
        t.hooks[hook] = t.entries.len() as u32;
        if hook == 0 {
            for port in [80, 443] {
                let mut e = entry(6, Some((false, port)), ACCEPT);
                let target = ENTRY_BYTES + MATCH_BYTES;
                e.truncate(usize::from(target));
                e.resize(usize::from(target + REDIRECT_TARGET_BYTES), 0);
                e[16..21].copy_from_slice(b"eth0\0");
                e[48..53].fill(255);
                e[90..92].copy_from_slice(&(target + REDIRECT_TARGET_BYTES).to_ne_bytes());
                let start = usize::from(target);
                e[start..start + 2].copy_from_slice(&REDIRECT_TARGET_BYTES.to_ne_bytes());
                e[start + 2..start + 10].copy_from_slice(b"REDIRECT");
                // Revision 0: nf_nat_ipv4_multi_range_compat, one range, flags
                // zero (preserve port); IPs and protocol limits are unused.
                e[start + 32..start + 36].copy_from_slice(&1u32.to_ne_bytes());
                t.entries.extend(e);
                t.count += 1;
            }
        }
        t.underflows[hook] = t.entries.len() as u32;
        t.entries.extend(entry(0, None, ACCEPT));
        t.count += 1;
    }
    t.entries.extend(error_entry());
    t.count += 1;
    t
}
fn entry(protocol: u16, port: Option<(bool, u16)>, verdict: i32) -> Vec<u8> {
    let target = ENTRY_BYTES + if port.is_some() { MATCH_BYTES } else { 0 };
    let mut bytes = vec![0; usize::from(target + TARGET_BYTES)];
    // All offsets and lengths here are compile-time UAPI constants.
    bytes[80..82].copy_from_slice(&protocol.to_ne_bytes());
    bytes[88..90].copy_from_slice(&target.to_ne_bytes());
    bytes[90..92].copy_from_slice(&(target + TARGET_BYTES).to_ne_bytes());
    if let Some((source, port)) = port {
        bytes[112..114].copy_from_slice(&MATCH_BYTES.to_ne_bytes());
        bytes[114..117].copy_from_slice(if protocol == 6 { b"tcp" } else { b"udp" });
        // xt_tcp and xt_udp begin with source and destination port ranges.
        bytes[144..152].copy_from_slice(&[0, 0, 255, 255, 0, 0, 255, 255]);
        let offset = if source { 144 } else { 148 };
        bytes[offset..offset + 2].copy_from_slice(&port.to_ne_bytes());
        bytes[offset + 2..offset + 4].copy_from_slice(&port.to_ne_bytes());
    }
    let start = usize::from(target);
    bytes[start..start + 2].copy_from_slice(&TARGET_BYTES.to_ne_bytes());
    bytes[start + 32..start + 36].copy_from_slice(&verdict.to_ne_bytes());
    bytes
}

pub(crate) fn table(tls: bool) -> Table {
    let mut t = Table {
        entries: Vec::new(),
        hooks: [0; 5],
        underflows: [0; 5],
        count: 0,
    };
    // INPUT, FORWARD, OUTPUT. No routing, ICMP, or other transport is allowed.
    for hook in [1, 2, 3] {
        t.hooks[hook] = t.entries.len() as u32;
        if hook != 2 {
            for (protocol, port) in [(17, 53), (6, 80)]
                .into_iter()
                .chain(tls.then_some((6, 443)))
            {
                t.entries
                    .extend(entry(protocol, Some((hook == 3, port)), ACCEPT));
                t.count += 1;
            }
        }
        t.underflows[hook] = t.entries.len() as u32;
        t.entries.extend(entry(0, None, DROP));
        t.count += 1;
    }
    t.entries.extend(error_entry());
    t.count += 1;
    t
}

fn error_entry() -> Vec<u8> {
    // The terminal ERROR entry required by ip_tables table validation.
    let mut error = vec![0; 176];
    error[88..90].copy_from_slice(&ENTRY_BYTES.to_ne_bytes());
    error[90..92].copy_from_slice(&176u16.to_ne_bytes());
    error[112..114].copy_from_slice(&64u16.to_ne_bytes());
    error[114..119].copy_from_slice(b"ERROR");
    error[144..149].copy_from_slice(b"ERROR");
    error
}

/// Must be called before eth0 is brought up. Failure leaves the VM offline.
pub fn install() -> io::Result<()> {
    install_with(crate::sys::install_table)
}

fn install_with(mut replace: impl FnMut(&[u8], u32, &Table) -> io::Result<()>) -> io::Result<()> {
    // Denial policy first, then interception, always before eth0 comes up.
    replace(b"filter", 14, &table(true))?;
    replace(b"nat", 27, &nat_table())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes(b[at..at + 2].try_into().unwrap())
    }
    fn i32_at(b: &[u8], at: usize) -> i32 {
        i32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn nat_redirect_intercepts_any_destination_only_tcp_service_ports() {
        let t = nat_table();
        // Known-answer layout of the complete NAT table, including underflows.
        assert_eq!(t.hooks, [0, 584, 0, 736, 888]);
        assert_eq!(t.underflows, [432, 584, 0, 736, 888]);
        assert_eq!((t.count, t.entries.len()), (7, 1216));
        // Interpret the actual rule bytes independently of the encoder. Destination
        // IP never affects the decision: both address fields and masks are zero.
        let redirected = |hook: usize, iface: &[u8], proto: u16, port: u16| {
            let mut offset = t.hooks[hook] as usize;
            loop {
                let e = &t.entries[offset..];
                let target = u16_at(e, 88) as usize;
                assert_eq!(&e[..16], &[0; 16], "address-dependent rule");
                if u16_at(e, 80) == 0 {
                    assert_eq!(i32_at(e, target + 32), ACCEPT);
                    return false;
                }
                assert_eq!(u16_at(e, 112), 48);
                assert_eq!(&e[114..118], b"tcp\0");
                assert_eq!(
                    &e[48..64],
                    &[255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                );
                if iface == &e[16..21]
                    && proto == u16_at(e, 80)
                    && (u16_at(e, 148)..=u16_at(e, 150)).contains(&port)
                {
                    assert_eq!(u16_at(e, target), 56);
                    assert_eq!(&e[target + 2..target + 11], b"REDIRECT\0");
                    assert_eq!(e[target + 31], 0, "target revision");
                    assert_eq!(i32_at(e, target + 32), 1, "range count");
                    assert_eq!(
                        &e[target + 36..target + 56],
                        &[0; 20],
                        "port must be preserved"
                    );
                    return true;
                }
                offset += u16_at(e, 90) as usize;
            }
        };
        for hook in [0, 1, 3, 4] {
            for iface in [&b"eth0\0"[..], &b"eth1\0"[..], &b"lo\0\0\0"[..]] {
                for proto in [1, 6, 17, 41, 47, 50, 58, 132] {
                    for port in [0, 22, 53, 80, 123, 443, 853, 5001, 65535] {
                        assert_eq!(
                            redirected(hook, iface, proto, port),
                            hook == 0
                                && iface == b"eth0\0"
                                && proto == 6
                                && [80, 443].contains(&port)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn tls_filter_opens_443_only_in_service_directions() {
        let t = table(true);
        assert_eq!(t.count, 10);
        let mut permits = Vec::new();
        for hook in [1, 2, 3] {
            let mut offset = t.hooks[hook] as usize;
            while offset < t.underflows[hook] as usize {
                let e = &t.entries[offset..];
                let target = u16_at(e, 88) as usize;
                assert_eq!(i32_at(e, target + 32), ACCEPT);
                let port_at = if hook == 3 { 144 } else { 148 };
                permits.push((hook, u16_at(e, 80), u16_at(e, port_at)));
                offset += u16_at(e, 90) as usize;
            }
            let e = &t.entries[offset..];
            assert_eq!(i32_at(e, u16_at(e, 88) as usize + 32), DROP);
        }
        assert_eq!(
            permits,
            [
                (1, 17, 53),
                (1, 6, 80),
                (1, 6, 443),
                (3, 17, 53),
                (3, 6, 80),
                (3, 6, 443)
            ]
        );
    }

    #[test]
    fn interception_installation_is_ordered_and_fails_closed() {
        for failure in [None, Some(0), Some(1)] {
            let mut seen = Vec::new();
            let result = install_with(|name, hooks, rules| {
                let index = seen.len();
                seen.push((name.to_vec(), hooks, rules.count));
                if failure == Some(index) {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.is_err(), failure.is_some());
            assert_eq!(seen[0], (b"filter".to_vec(), 14, 10));
            if failure == Some(0) {
                assert_eq!(seen.len(), 1);
            } else {
                assert_eq!(
                    seen,
                    [(b"filter".to_vec(), 14, 10), (b"nat".to_vec(), 27, 7)]
                );
            }
        }
    }

    #[test]
    fn filter_drops_icmp_forwarding_and_every_non_service_port() {
        let t = table(false);
        assert_eq!(t.hooks, [0, 0, 552, 704, 0]);
        assert_eq!(t.underflows, [0, 400, 552, 1104, 0]);
        assert_eq!((t.count, t.entries.len()), (8, 1432));
        // Independently interpret the generated table for traffic at each hook.
        let verdict = |hook: usize, proto: u16, src: u16, dst: u16| {
            let mut offset = t.hooks[hook] as usize;
            loop {
                let e = &t.entries[offset..];
                let target = u16_at(e, 88) as usize;
                let p = u16_at(e, 80);
                if p == 0
                    || (p == proto
                        && (u16_at(e, 144)..=u16_at(e, 146)).contains(&src)
                        && (u16_at(e, 148)..=u16_at(e, 150)).contains(&dst))
                {
                    break i32_at(e, target + 32);
                }
                offset += u16_at(e, 90) as usize;
            }
        };
        for protocol in [1, 6, 17, 41, 47, 50, 58, 132] {
            for port in [0, 22, 53, 80, 123, 443, 853, 5001, 65535] {
                assert_eq!(verdict(2, protocol, port, port), DROP);
                let allowed = (protocol == 6 && port == 80) || (protocol == 17 && port == 53);
                assert_eq!(
                    verdict(1, protocol, 40000, port),
                    if allowed { ACCEPT } else { DROP }
                );
                assert_eq!(
                    verdict(3, protocol, port, 40000),
                    if allowed { ACCEPT } else { DROP }
                );
            }
        }
    }
}
