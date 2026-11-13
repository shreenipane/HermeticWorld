#![forbid(unsafe_code)]
//! Fixed x86-64 Linux legacy IPv4 filter table. No packet bytes enter this encoder.
//! UAPI: linux/netfilter_ipv4/ip_tables.h and linux/netfilter/xt_tcpudp.h.
use std::io;

pub(crate) const MAX_OLD_RULES: usize = 16;
pub(crate) const REPLACE_HEADER_BYTES: usize = 96;
const ENTRY_BYTES: u16 = 112;
const TARGET_BYTES: u16 = 40;
const MATCH_BYTES: u16 = 48;
const DROP: i32 = -1;
const ACCEPT: i32 = -2;

pub(crate) struct Table {
    pub entries: Vec<u8>,
    pub hooks: [u32; 5],
    pub underflows: [u32; 5],
    pub count: u32,
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

pub(crate) fn table() -> Table {
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
            for (protocol, port) in [(17, 53), (6, 80)] {
                t.entries
                    .extend(entry(protocol, Some((hook == 3, port)), ACCEPT));
                t.count += 1;
            }
        }
        t.underflows[hook] = t.entries.len() as u32;
        t.entries.extend(entry(0, None, DROP));
        t.count += 1;
    }
    // The terminal ERROR entry required by ip_tables table validation.
    let mut error = vec![0; 176];
    error[88..90].copy_from_slice(&ENTRY_BYTES.to_ne_bytes());
    error[90..92].copy_from_slice(&176u16.to_ne_bytes());
    error[112..114].copy_from_slice(&64u16.to_ne_bytes());
    error[114..119].copy_from_slice(b"ERROR");
    error[144..149].copy_from_slice(b"ERROR");
    t.entries.extend(error);
    t.count += 1;
    t
}

/// Must be called before eth0 is brought up. Failure leaves the VM offline.
pub fn install() -> io::Result<()> {
    crate::sys::install_filter(&table())
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
    fn filter_drops_icmp_forwarding_and_every_non_service_port() {
        let t = table();
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
