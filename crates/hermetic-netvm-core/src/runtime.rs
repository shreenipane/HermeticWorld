#![forbid(unsafe_code)]
//! First-cut NetVM boot policy: only static DNS and intercepted plain HTTP.
use crate::{
    dns::DnsResponder,
    http::{FilterDecision, RequestFilter},
    upstream::WireRequest,
};
use hermetic_netvm_dns::DnsTable;
use hermetic_netvm_http::{decide, parse_request_head, Decision, Scheme};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Read, net::Ipv4Addr};

pub const NETVM_ADDRESS: &str = "10.0.2.3";
pub const NETVM_CIDR: &str = "10.0.2.3/24";
pub const AGENT_ADDRESS: &str = "10.0.2.15";
pub const AGENT_CIDR: &str = "10.0.2.15/24";
/// First three octets of the private link between AgentVM and NetVM (10.0.2.0/24).
pub const LINK_PREFIX: [u8; 3] = [10, 0, 2];
pub const BUSYBOX: &str = "/sbin/hermetic-busybox";
pub const RESOLV_CONF: &str = "nameserver 10.0.2.3\noptions ndots:0\n";
pub const MAX_RUNTIME_CONFIG_BYTES: u64 = 4096;
pub const MIN_CLOCK: i64 = 315532800;
pub const MAX_CLOCK: i64 = 4102444799;
pub const BOOT_COMMAND_TIMEOUT_MS: u64 = 5000;
pub const BOOT_POLL_MS: u64 = 5;

/// Emitted only after network configuration and both service loops have started.
/// All fields describe sealed policy; no wall clock or host configuration is read.
pub fn write_ready_status(mut out: impl std::io::Write) -> std::io::Result<()> {
    writeln!(
        out,
        "netvm_ready interface=eth0 address={NETVM_CIDR} dns={NETVM_ADDRESS}:53 http=0.0.0.0:80"
    )
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldConfig {
    pub t_clock: i64,
}
impl WorldConfig {
    pub fn parse(reader: impl Read) -> Result<Self, &'static str> {
        let mut data = Vec::new();
        reader
            .take(MAX_RUNTIME_CONFIG_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| "invalid_config")?;
        if data.len() as u64 > MAX_RUNTIME_CONFIG_BYTES {
            return Err("invalid_config");
        }
        let config: Self = serde_json::from_slice(&data).map_err(|_| "invalid_config")?;
        if !(MIN_CLOCK..=MAX_CLOCK).contains(&config.t_clock) {
            return Err("invalid_config");
        }
        Ok(config)
    }
}
pub struct WorldDns(pub DnsTable);
impl DnsResponder for WorldDns {
    fn respond(&self, packet: &[u8]) -> Option<Vec<u8>> {
        hermetic_netvm_dns::respond(packet, &self.0)
    }
}
pub struct WorldFilter {
    hosts: BTreeSet<String>,
}
impl WorldFilter {
    pub fn new(table: &DnsTable) -> Self {
        Self {
            hosts: table.names().map(str::to_owned).collect(),
        }
    }
}
impl RequestFilter for WorldFilter {
    fn check(&self, head: &[u8], tls: bool, _sni: Option<&str>) -> FilterDecision {
        if tls {
            return FilterDecision::Reject;
        }
        let parsed = match parse_request_head(head) {
            Ok(p) => p,
            Err(_) => return FilterDecision::Reject,
        };
        // Host policy applies to every method, including requests that get 405.
        let method = parsed.method.clone();
        let mut policy_head = parsed;
        policy_head.method = "GET".into();
        match decide(&policy_head, &self.hosts, Scheme::Http) {
            Decision::MethodNotAllowed => FilterDecision::NotAllowed,
            Decision::Reject(_) => FilterDecision::Reject,
            Decision::Forward(mut req) => {
                if method != "GET" && method != "HEAD" {
                    return FilterDecision::NotAllowed;
                }
                req.method = method;
                let path = match req.query {
                    Some(q) => format!("{}?{}", req.path, q),
                    None => req.path,
                };
                let range = req
                    .headers
                    .iter()
                    .find(|h| h.name == "range")
                    .and_then(|h| h.value.strip_prefix("bytes="))
                    .and_then(|v| v.split_once('-'))
                    .and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?)));
                let descriptor = WireRequest {
                    method: req.method,
                    authority: req.host,
                    path,
                    range,
                };
                match serde_json::to_vec(&descriptor) {
                    Ok(v) => FilterDecision::Forward(v),
                    Err(_) => FilterDecision::Reject,
                }
            }
        }
    }
}

/// Fixed boot command; the program is a constant path inside the sealed image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootCommand {
    pub program: &'static str,
    pub args: Vec<String>,
}
fn busy(args: &[&str]) -> BootCommand {
    BootCommand {
        program: BUSYBOX,
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    }
}

/// World addresses NetVM must own, sorted and unique. Addresses inside the
/// AgentVM/NetVM link subnet are refused so a table cannot shadow either VM.
pub fn world_addresses(table: &DnsTable) -> Result<Vec<Ipv4Addr>, &'static str> {
    let mut out = BTreeSet::new();
    for name in table.names() {
        for ip in table.lookup(name).unwrap_or(&[]) {
            if ip.octets()[..3] == LINK_PREFIX {
                return Err("invalid_dns");
            }
            out.insert(*ip);
        }
    }
    Ok(out.into_iter().collect())
}

/// NetVM network bring-up. No forwarding and no IPv6: the only reachable
/// services are the DNS socket on `NETVM_ADDRESS:53` and the HTTP socket on port 80
/// of `NETVM_ADDRESS` and of each world address (assigned as /32 on eth0, so no
/// netfilter redirect is needed). Every other destination is not local and is
/// dropped because forwarding is off.
pub fn boot_commands(table: &DnsTable) -> Result<Vec<BootCommand>, &'static str> {
    let mut out = vec![
        busy(&["sysctl", "-w", "net.ipv4.ip_forward=0"]),
        busy(&["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"]),
        busy(&["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"]),
        busy(&["ip", "link", "set", "lo", "up"]),
        busy(&["ip", "addr", "add", NETVM_CIDR, "dev", "eth0"]),
    ];
    for ip in world_addresses(table)? {
        let cidr = format!("{ip}/32");
        out.push(busy(&["ip", "addr", "add", &cidr, "dev", "eth0"]));
    }
    out.push(busy(&["ip", "link", "set", "eth0", "up"]));
    out.push(busy(&[
        "mount",
        "-o",
        "remount,ro,nosuid,nodev,noexec",
        "/proc",
    ]));
    Ok(out)
}

/// Replayable orchestration, tested without root or host networking effects.
pub fn configure(
    table: &DnsTable,
    mut run: impl FnMut(&BootCommand) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    for command in boot_commands(table)? {
        run(&command)?;
    }
    Ok(())
}

/// AgentVM side, run once through execd before the agent starts (argv lists for
/// the image's static busybox at `/bin/busybox`). `/etc/resolv.conf` comes from
/// the run spec's `resolv_conf` (`RESOLV_CONF`).
pub fn agent_commands() -> Vec<Vec<String>> {
    #[rustfmt::skip]
    let route = ["ip", "route", "add", "default", "via", NETVM_ADDRESS, "dev", "eth0"];
    [
        &["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"][..],
        &["ip", "link", "set", "lo", "up"],
        &["ip", "addr", "add", AGENT_CIDR, "dev", "eth0"],
        &["ip", "link", "set", "eth0", "up"],
        &route,
    ]
    .iter()
    .map(|args| {
        std::iter::once("/bin/busybox")
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect()
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_status_has_only_fixed_network_policy() {
        let mut out = Vec::new();
        write_ready_status(&mut out).unwrap();
        assert_eq!(
            out,
            b"netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80\n"
        );
    }

    /// `(name, [a...])` pairs in the manifest table format.
    fn table(records: &[(&str, &[&str])]) -> DnsTable {
        let records: Vec<_> = records
            .iter()
            .map(|(n, a)| serde_json::json!({"name": n, "a": a, "aaaa": []}))
            .collect();
        DnsTable::from_json_str(&serde_json::json!({ "records": records }).to_string()).unwrap()
    }
    fn get(filter: &WorldFilter, raw: &str) -> FilterDecision {
        filter.check(raw.as_bytes(), false, None)
    }

    #[test]
    fn world_config_is_bounded_and_strict() {
        assert_eq!(
            WorldConfig::parse(&br#"{"t_clock":1700000000}"#[..])
                .unwrap()
                .t_clock,
            1_700_000_000
        );
        for bad in [
            &br#"{"t_clock":1}"#[..],
            br#"{"t_clock":1700000000,"x":1}"#,
            br#"{}"#,
        ] {
            assert!(WorldConfig::parse(bad).is_err());
        }
        let big = vec![b' '; MAX_RUNTIME_CONFIG_BYTES as usize + 1];
        assert!(WorldConfig::parse(&big[..]).is_err());
    }

    #[test]
    fn boot_plan_owns_world_addresses_and_never_forwards() {
        let t = table(&[
            ("b.example", &["10.9.0.2", "10.9.0.1"]),
            ("a.example", &["10.9.0.3"]),
        ]);
        let plan = boot_commands(&t).unwrap();
        assert!(plan.iter().all(|c| c.program == BUSYBOX));
        let flat: Vec<String> = plan.iter().map(|c| c.args.join(" ")).collect();
        assert_eq!(flat[0], "sysctl -w net.ipv4.ip_forward=0");
        assert!(flat.contains(&"ip addr add 10.0.2.3/24 dev eth0".to_owned()));
        let owned: Vec<_> = flat
            .iter()
            .filter(|c| c.ends_with("/32 dev eth0"))
            .collect();
        assert_eq!(
            owned,
            [
                "ip addr add 10.9.0.1/32 dev eth0",
                "ip addr add 10.9.0.2/32 dev eth0",
                "ip addr add 10.9.0.3/32 dev eth0"
            ]
        );
        // eth0 comes up only after every address exists; /proc is read-only last.
        let up = flat
            .iter()
            .position(|c| c == "ip link set eth0 up")
            .unwrap();
        assert!(flat.iter().take(up).any(|c| c.contains("10.9.0.2/32")));
        assert!(flat.last().unwrap().starts_with("mount -o remount,ro"));
        assert!(!flat
            .iter()
            .any(|c| c.contains("ip_forward=1") || c.contains("route")));
    }

    #[test]
    fn table_address_in_link_subnet_is_refused() {
        for ip in ["10.0.2.15", "10.0.2.3", "10.0.2.200"] {
            let t = table(&[("x.example", &[ip])]);
            assert_eq!(boot_commands(&t), Err("invalid_dns"));
        }
    }

    #[test]
    fn configure_stops_at_first_failure() {
        let t = table(&[("a.example", &["10.9.0.1"])]);
        let mut seen = 0;
        let r = configure(&t, |_| {
            seen += 1;
            if seen == 2 {
                Err("boot_failed")
            } else {
                Ok(())
            }
        });
        assert_eq!(r, Err("boot_failed"));
        assert_eq!(seen, 2);
    }

    #[test]
    fn agent_side_routes_only_via_netvm() {
        let cmds = agent_commands();
        assert!(cmds.iter().all(|c| c[0] == "/bin/busybox"));
        let flat: Vec<String> = cmds.iter().map(|c| c[1..].join(" ")).collect();
        assert!(flat.contains(&"ip addr add 10.0.2.15/24 dev eth0".to_owned()));
        assert_eq!(
            flat.iter()
                .filter(|c| c.starts_with("ip route"))
                .collect::<Vec<_>>(),
            ["ip route add default via 10.0.2.3 dev eth0"]
        );
        assert_eq!(RESOLV_CONF, "nameserver 10.0.2.3\noptions ndots:0\n");
    }

    #[test]
    fn filter_forwards_only_get_head_for_table_hosts() {
        let f = WorldFilter::new(&table(&[("files.example", &["10.9.0.1"])]));
        match get(
            &f,
            "GET /a.txt?x=1 HTTP/1.1\r\nHost: files.example\r\nRange: bytes=0-3\r\n\r\n",
        ) {
            FilterDecision::Forward(d) => {
                let w: WireRequest = serde_json::from_slice(&d).unwrap();
                assert_eq!(w.method, "GET");
                assert_eq!(w.authority, "files.example");
                assert_eq!(w.path, "/a.txt?x=1");
                assert_eq!(w.range, Some((0, 3)));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            get(&f, "GET / HTTP/1.1\r\nHost: FILES.example:80\r\n\r\n"),
            FilterDecision::Forward(_)
        ));
        assert!(matches!(
            get(
                &f,
                "POST / HTTP/1.1\r\nHost: files.example\r\nContent-Length: 0\r\n\r\n"
            ),
            FilterDecision::NotAllowed
        ));
        for bad in [
            "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: files.example:8080\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            "garbage",
        ] {
            assert!(matches!(get(&f, bad), FilterDecision::Reject), "{bad}");
        }
        assert!(matches!(
            f.check(b"GET / HTTP/1.1\r\nHost: files.example\r\n\r\n", true, None),
            FilterDecision::Reject
        ));
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn unknown_hosts_are_rejected_even_for_post() {
        let table =
            DnsTable::from_json_str(r#"{"records":[{"name":"files.example","a":["10.9.0.1"]}]}"#)
                .unwrap();
        let filter = WorldFilter::new(&table);
        for head in [
            "POST / HTTP/1.1\r\nHost: unknown.example\r\nContent-Length: 0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: files.example:8080\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert_eq!(
                filter.check(head.as_bytes(), false, None),
                FilterDecision::Reject
            );
        }
    }
}
