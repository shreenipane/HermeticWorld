#![forbid(unsafe_code)]
//! NetVM boot policy: static DNS and sealed HTTP/HTTPS host filtering.
pub use crate::firewall::InterceptionPath;
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
pub const AGENT_CIDR: &str = "10.0.2.15/32";
pub const NETVM_PEER_ROUTE: &str = "10.0.2.3/32";
/// First three octets of the private link between AgentVM and NetVM (10.0.2.0/24).
pub const LINK_PREFIX: [u8; 3] = [10, 0, 2];
pub const BUSYBOX: &str = "/sbin/hermetic-busybox";
pub const RESOLV_CONF: &str = "nameserver 10.0.2.3\noptions ndots:0\n";
pub const MAX_RUNTIME_CONFIG_BYTES: u64 = 4096;
pub const MIN_CLOCK: i64 = 315532800;
pub const MAX_CLOCK: i64 = 4102444799;
pub const BOOT_COMMAND_TIMEOUT_MS: u64 = 5000;
pub const BOOT_POLL_MS: u64 = 5;
/// NAT state and fragment reassembly bounds, installed before eth0 comes up.
pub const MAX_CONNTRACK_ENTRIES: u32 = 1024;
pub const CONNTRACK_IDLE_SECONDS: u32 = 30;
pub const MAX_FRAGMENT_BYTES: u32 = 262144;
pub const FRAGMENT_TIMEOUT_SECONDS: u32 = 5;
pub const TPROXY_ROUTING_TABLE: u32 = 100;
pub const TPROXY_ROUTING_TABLE_STR: &str = "100";

/// Emitted only after network configuration and both service loops have started.
/// All fields describe sealed policy; no wall clock or host configuration is read.
pub fn write_ready_status(
    mut out: impl std::io::Write,
    path: InterceptionPath,
) -> std::io::Result<()> {
    let binding = match path {
        InterceptionPath::Tproxy => "on",
        InterceptionPath::Redirect => "off",
    };
    writeln!(
        out,
        "netvm_ready interface=eth0 address={NETVM_CIDR} dns={NETVM_ADDRESS}:53 http=0.0.0.0:80 path={} destination_binding={binding}",
        path.as_str()
    )
}

/// Emitted during early boot to record interception mode and destination binding status.
pub fn write_boot_log(mut out: impl std::io::Write, path: InterceptionPath) -> std::io::Result<()> {
    match path {
        InterceptionPath::Tproxy => {
            writeln!(out, "netvm_boot: path=tproxy destination_binding=on")
        }
        InterceptionPath::Redirect => {
            writeln!(
                out,
                "netvm_boot: warning: path=redirect destination_binding=off (REDIRECT fallback active)"
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayRouteConfig {
    pub host: String,
    #[serde(default = "default_gateway_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_socket: Option<String>,
}

fn default_gateway_port() -> u16 {
    5002
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldConfig {
    pub t_clock: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<crate::tls::TlsIdentity>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redirect_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayRouteConfig>,
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
        if let Some(tls) = &config.tls {
            tls.validate().map_err(|_| "invalid_config")?;
        }
        if let Some(gw) = &config.gateway {
            if gw.host.is_empty() || gw.host.len() > 255 {
                return Err("invalid_config");
            }
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
#[derive(Clone)]
pub struct WorldFilter {
    hosts: BTreeSet<String>,
    table: DnsTable,
    path: InterceptionPath,
    gateway_host: Option<String>,
}
impl WorldFilter {
    pub fn new(table: &DnsTable) -> Self {
        Self::with_path(table, InterceptionPath::Tproxy)
    }

    pub fn with_path(table: &DnsTable, path: InterceptionPath) -> Self {
        Self::with_gateway(table, path, None)
    }

    pub fn with_gateway(
        table: &DnsTable,
        path: InterceptionPath,
        gateway_host: Option<String>,
    ) -> Self {
        Self {
            hosts: table.names().map(str::to_owned).collect(),
            table: table.clone(),
            path,
            gateway_host,
        }
    }
}
impl RequestFilter for WorldFilter {
    fn check(&self, head: &[u8], tls: bool, sni: Option<&str>) -> FilterDecision {
        self.check_with_dest(head, tls, sni, None)
    }

    fn check_with_dest(
        &self,
        head: &[u8],
        tls: bool,
        sni: Option<&str>,
        destination: Option<std::net::IpAddr>,
    ) -> FilterDecision {
        let parsed = match crate::headers::parse_request_head(head) {
            Ok(p) => p,
            Err(_) => return FilterDecision::Reject,
        };
        let raw_host = match parsed.host.as_deref() {
            Some(h) if !h.is_empty() => h,
            _ => return FilterDecision::Reject,
        };
        let host = raw_host
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(raw_host)
            .trim();
        if host.is_empty() {
            return FilterDecision::Reject;
        }

        if let Some(gw_host) = &self.gateway_host {
            if host.eq_ignore_ascii_case(gw_host) {
                if !self.check_destination(host, destination) {
                    return FilterDecision::Reject;
                }
                if tls && sni.is_none_or(|s| !s.eq_ignore_ascii_case(host)) {
                    return FilterDecision::Reject;
                }
                let path_only = parsed.target.split('?').next().unwrap_or("");
                let is_adapter_endpoint = matches!(
                    path_only,
                    "/v1/messages" | "/v1/messages/count_tokens" | "/v1/chat/completions"
                );
                if !is_adapter_endpoint {
                    return FilterDecision::Reject;
                }
                if parsed.method != "POST" {
                    return FilterDecision::NotAllowed;
                }
                return FilterDecision::ForwardGateway;
            }
        }

        let world_parsed = match parse_request_head(head) {
            Ok(p) => p,
            Err(_) => {
                // If it's a known world host with an unsupported method (e.g. POST), return 405
                if self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    if !self.check_destination(host, destination) {
                        return FilterDecision::Reject;
                    }
                    if tls && sni.is_none_or(|s| !s.eq_ignore_ascii_case(host)) {
                        return FilterDecision::Reject;
                    }
                    if parsed.method != "GET" && parsed.method != "HEAD" {
                        return FilterDecision::NotAllowed;
                    }
                }
                return FilterDecision::Reject;
            }
        };

        // Host policy applies to every method, including requests that get 405.
        let method = world_parsed.method.clone();
        let mut policy_head = world_parsed;
        policy_head.method = "GET".into();
        let scheme = if tls { Scheme::Https } else { Scheme::Http };
        match decide(&policy_head, &self.hosts, scheme) {
            Decision::MethodNotAllowed => FilterDecision::NotAllowed,
            Decision::Reject(_) => FilterDecision::Reject,
            Decision::Forward(mut req) => {
                if !self.check_destination(&req.host, destination) {
                    return FilterDecision::Reject;
                }
                if tls && sni.is_none_or(|sni| !sni.eq_ignore_ascii_case(&req.host)) {
                    return FilterDecision::Reject;
                }
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

    fn check_destination(&self, host: &str, destination: Option<std::net::IpAddr>) -> bool {
        if self.path == InterceptionPath::Redirect {
            return true;
        }
        let Some(dest) = destination else {
            return false;
        };
        let dest_v4 = match dest {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => return false,
        };
        let Some(records) = self.table.lookup(host) else {
            return false;
        };
        records.contains(&dest_v4)
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
/// and HTTPS on port 443 of any destination address (TPROXY with fwmark policy routing,
/// or fallback REDIRECT in PREROUTING). Every other service is dropped.
pub fn boot_commands(
    table: &DnsTable,
    path: InterceptionPath,
) -> Result<Vec<BootCommand>, &'static str> {
    let mut out = vec![
        busy(&["sysctl", "-w", "net.ipv4.ip_forward=0"]),
        busy(&["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"]),
        busy(&["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"]),
    ];
    for (key, value) in [
        ("net.netfilter.nf_conntrack_max", MAX_CONNTRACK_ENTRIES),
        (
            "net.netfilter.nf_conntrack_tcp_timeout_established",
            CONNTRACK_IDLE_SECONDS,
        ),
        (
            "net.netfilter.nf_conntrack_tcp_timeout_syn_recv",
            FRAGMENT_TIMEOUT_SECONDS,
        ),
        (
            "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
            FRAGMENT_TIMEOUT_SECONDS,
        ),
        // Linux requires low <= high even while changing the watermarks.
        // Lower low first: its boot default (3 MiB) exceeds our high cap.
        ("net.ipv4.ipfrag_low_thresh", MAX_FRAGMENT_BYTES),
        ("net.ipv4.ipfrag_high_thresh", MAX_FRAGMENT_BYTES),
        ("net.ipv4.ipfrag_time", FRAGMENT_TIMEOUT_SECONDS),
    ] {
        out.push(busy(&["sysctl", "-w", &format!("{key}={value}")]));
    }
    out.push(busy(&["ip", "link", "set", "lo", "up"]));
    let addresses = world_addresses(table)?;
    match path {
        InterceptionPath::Tproxy => {
            let fwmark_str = crate::firewall::FWMARK.to_string();
            out.push(busy(&[
                "ip",
                "rule",
                "add",
                "fwmark",
                &fwmark_str,
                "table",
                TPROXY_ROUTING_TABLE_STR,
            ]));
            out.push(busy(&[
                "ip",
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                TPROXY_ROUTING_TABLE_STR,
            ]));
            out.push(busy(&["ip", "addr", "add", NETVM_CIDR, "dev", "eth0"]));
        }
        InterceptionPath::Redirect => {
            out.push(busy(&["ip", "addr", "add", NETVM_CIDR, "dev", "eth0"]));
            for ip in addresses {
                let cidr = format!("{ip}/32");
                out.push(busy(&["ip", "addr", "add", &cidr, "dev", "eth0"]));
            }
        }
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
    path: InterceptionPath,
    mut run: impl FnMut(&BootCommand) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    for command in boot_commands(table, path)? {
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
        &["ip", "route", "add", NETVM_PEER_ROUTE, "dev", "eth0"],
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
        write_ready_status(&mut out, InterceptionPath::Tproxy).unwrap();
        assert_eq!(
            out,
            b"netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=tproxy destination_binding=on\n"
        );
        let mut out = Vec::new();
        write_ready_status(&mut out, InterceptionPath::Redirect).unwrap();
        assert_eq!(
            out,
            b"netvm_ready interface=eth0 address=10.0.2.3/24 dns=10.0.2.3:53 http=0.0.0.0:80 path=redirect destination_binding=off\n"
        );
    }

    #[test]
    fn boot_log_states_destination_binding() {
        let mut out = Vec::new();
        write_boot_log(&mut out, InterceptionPath::Tproxy).unwrap();
        assert_eq!(out, b"netvm_boot: path=tproxy destination_binding=on\n");
        let mut out = Vec::new();
        write_boot_log(&mut out, InterceptionPath::Redirect).unwrap();
        assert_eq!(
            out,
            b"netvm_boot: warning: path=redirect destination_binding=off (REDIRECT fallback active)\n"
        );
    }

    /// `(name, [a...])` pairs in the manifest table format.
    fn table(records: &[(&str, &[&str])]) -> DnsTable {
        DnsTable::test_fixture(records.iter().map(|(n, ips)| {
            (
                *n,
                ips.iter()
                    .map(|ip| ip.parse::<std::net::Ipv4Addr>().unwrap())
                    .collect(),
            )
        }))
    }
    fn get(filter: &WorldFilter, raw: &str) -> FilterDecision {
        let dest = "10.9.0.1".parse().ok();
        filter.check_with_dest(raw.as_bytes(), false, None, dest)
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
        let plan = boot_commands(&t, InterceptionPath::Redirect).unwrap();
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
    fn boot_plan_tproxy_configures_policy_routing_and_never_owns_world_addresses() {
        let t = table(&[
            ("b.example", &["10.9.0.2", "10.9.0.1"]),
            ("a.example", &["10.9.0.3"]),
        ]);
        let plan = boot_commands(&t, InterceptionPath::Tproxy).unwrap();
        assert!(plan.iter().all(|c| c.program == BUSYBOX));
        let flat: Vec<String> = plan.iter().map(|c| c.args.join(" ")).collect();
        assert_eq!(flat[0], "sysctl -w net.ipv4.ip_forward=0");
        // Must contain policy rule and local default route
        assert!(flat.contains(&"ip rule add fwmark 1 table 100".to_owned()));
        assert!(flat.contains(&"ip route add local default dev lo table 100".to_owned()));
        assert!(flat.contains(&"ip addr add 10.0.2.3/24 dev eth0".to_owned()));
        // Never owns any world /32 addresses on eth0
        assert!(!flat.iter().any(|c| c.contains("/32")));
        // Ordering: rule, route and addr before eth0 up; /proc remount ro last
        let up = flat
            .iter()
            .position(|c| c == "ip link set eth0 up")
            .unwrap();
        let rule_pos = flat
            .iter()
            .position(|c| c == "ip rule add fwmark 1 table 100")
            .unwrap();
        let route_pos = flat
            .iter()
            .position(|c| c == "ip route add local default dev lo table 100")
            .unwrap();
        let addr_pos = flat
            .iter()
            .position(|c| c == "ip addr add 10.0.2.3/24 dev eth0")
            .unwrap();
        assert!(rule_pos < up);
        assert!(route_pos < up);
        assert!(addr_pos < up);
        assert!(flat.last().unwrap().starts_with("mount -o remount,ro"));
    }

    #[test]
    fn table_address_in_link_subnet_is_refused() {
        for ip in ["10.0.2.15", "10.0.2.3", "10.0.2.200"] {
            let t = table(&[("x.example", &[ip])]);
            assert_eq!(
                boot_commands(&t, InterceptionPath::Tproxy),
                Err("invalid_dns")
            );
            assert_eq!(
                boot_commands(&t, InterceptionPath::Redirect),
                Err("invalid_dns")
            );
        }
    }

    #[test]
    fn configure_stops_at_first_failure() {
        let t = table(&[("a.example", &["10.9.0.1"])]);
        let mut seen = 0;
        let r = configure(&t, InterceptionPath::Tproxy, |_| {
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
    fn interception_state_is_capped_before_network_and_every_failure_stops_boot() {
        let t = table(&[("a.example", &["10.9.0.1"])]);
        for path in [InterceptionPath::Tproxy, InterceptionPath::Redirect] {
            let plan = boot_commands(&t, path).unwrap();
            let up = plan
                .iter()
                .position(|c| c.args == ["ip", "link", "set", "eth0", "up"])
                .unwrap();
            for required in [
                "net.netfilter.nf_conntrack_max=1024",
                "net.netfilter.nf_conntrack_tcp_timeout_established=30",
                "net.netfilter.nf_conntrack_tcp_timeout_syn_recv=5",
                "net.netfilter.nf_conntrack_tcp_timeout_time_wait=5",
                "net.ipv4.ipfrag_high_thresh=262144",
                "net.ipv4.ipfrag_time=5",
            ] {
                assert!(plan
                    .iter()
                    .take(up)
                    .any(|c| c.args == ["sysctl", "-w", required]));
            }
            for fail_at in 0..plan.len() {
                let mut seen = Vec::new();
                assert_eq!(
                    configure(&t, path, |c| {
                        seen.push(c.clone());
                        if seen.len() == fail_at + 1 {
                            Err("boot_failed")
                        } else {
                            Ok(())
                        }
                    }),
                    Err("boot_failed")
                );
                assert_eq!(seen, plan[..=fail_at]);
            }
        }
    }

    #[test]
    fn fragment_watermarks_boot_with_linux_defaults() {
        // Linux 6.6 ip4_frags_ns_ctl_register gives high_thresh a minimum
        // of low_thresh, and low_thresh a maximum of high_thresh.
        let mut low = 3 * 1024 * 1024u32;
        let mut high = 4 * 1024 * 1024u32;
        configure(&table(&[]), InterceptionPath::Tproxy, |command| {
            if command.args.first().map(String::as_str) == Some("sysctl") {
                let (key, value) = command.args[2].split_once('=').unwrap();
                let value: u32 = value.parse().unwrap();
                match key {
                    "net.ipv4.ipfrag_low_thresh" if value <= high => low = value,
                    "net.ipv4.ipfrag_high_thresh" if value >= low => high = value,
                    "net.ipv4.ipfrag_low_thresh" | "net.ipv4.ipfrag_high_thresh" => {
                        return Err("boot_failed");
                    }
                    _ => {}
                }
            }
            if command.args == ["ip", "link", "set", "eth0", "up"] {
                assert_eq!(high, MAX_FRAGMENT_BYTES);
                assert!(low <= high);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(high, MAX_FRAGMENT_BYTES);
    }

    #[test]
    fn agent_side_routes_only_via_netvm() {
        let cmds = agent_commands();
        assert!(cmds.iter().all(|c| c[0] == "/bin/busybox"));
        let flat: Vec<String> = cmds.iter().map(|c| c[1..].join(" ")).collect();
        assert!(flat.contains(&"ip addr add 10.0.2.15/32 dev eth0".to_owned()));
        assert_eq!(
            flat.iter()
                .filter(|c| c.starts_with("ip route"))
                .collect::<Vec<_>>(),
            [
                "ip route add 10.0.2.3/32 dev eth0",
                "ip route add default via 10.0.2.3 dev eth0"
            ]
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

    #[test]
    fn original_destination_mismatch_is_refused() {
        let t = table(&[
            ("files.example", &["10.9.0.1"]),
            ("other.example", &["10.9.0.2"]),
        ]);
        let filter = WorldFilter::new(&t);

        let head = b"GET / HTTP/1.1\r\nHost: files.example\r\n\r\n";
        let post_head = b"POST / HTTP/1.1\r\nHost: files.example\r\nContent-Length: 0\r\n\r\n";

        let ip_matching: std::net::IpAddr = "10.9.0.1".parse().unwrap();
        let ip_mismatch: std::net::IpAddr = "10.9.0.2".parse().unwrap();
        let ip_external: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        let ip_loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // Direct check_destination
        // 1. None rejected
        assert!(!filter.check_destination("files.example", None));
        // 2. Loopback not in the table rejected
        assert!(!filter.check_destination("files.example", Some(ip_loopback)));
        // 3. Mismatch rejected
        assert!(!filter.check_destination("files.example", Some(ip_mismatch)));
        assert!(!filter.check_destination("files.example", Some(ip_external)));
        assert!(!filter.check_destination("unknown.example", Some(ip_matching)));
        // 4. Match accepted
        assert!(filter.check_destination("files.example", Some(ip_matching)));

        // check_with_dest: matching destination forwards
        assert!(matches!(
            filter.check_with_dest(head, false, None, Some(ip_matching)),
            FilterDecision::Forward(_)
        ));

        // check_with_dest: destination None refuses (reset)
        assert_eq!(
            filter.check_with_dest(head, false, None, None),
            FilterDecision::Reject
        );

        // check_with_dest: loopback not in table refuses (reset)
        assert_eq!(
            filter.check_with_dest(head, false, None, Some(ip_loopback)),
            FilterDecision::Reject
        );

        // check_with_dest: mismatched destination refuses (reset)
        assert_eq!(
            filter.check_with_dest(head, false, None, Some(ip_mismatch)),
            FilterDecision::Reject
        );
        assert_eq!(
            filter.check_with_dest(head, false, None, Some(ip_external)),
            FilterDecision::Reject
        );

        // check_with_dest: mismatched destination refuses even for POST (never gives 405)
        assert_eq!(
            filter.check_with_dest(post_head, false, None, Some(ip_mismatch)),
            FilterDecision::Reject
        );

        // check_with_dest: matching destination for POST gives 405
        assert_eq!(
            filter.check_with_dest(post_head, false, None, Some(ip_matching)),
            FilterDecision::NotAllowed
        );

        // Test fixture declaring loopback listener address in table exercises normal match rule:
        let t_loopback = table(&[("files.example", &["127.0.0.1"])]);
        let filter_loopback = WorldFilter::new(&t_loopback);
        assert!(filter_loopback.check_destination("files.example", Some(ip_loopback)));
        assert!(matches!(
            filter_loopback.check_with_dest(head, false, None, Some(ip_loopback)),
            FilterDecision::Forward(_)
        ));

        // Fallback path (Redirect) skips destination check:
        let filter_redirect = WorldFilter::with_path(&t, InterceptionPath::Redirect);
        assert!(filter_redirect.check_destination("files.example", Some(ip_mismatch)));
        assert!(matches!(
            filter_redirect.check_with_dest(head, false, None, Some(ip_mismatch)),
            FilterDecision::Forward(_)
        ));
    }

    #[test]
    fn default_config_never_selects_redirect_fallback() {
        let raw = br#"{"t_clock":1700000000}"#;
        let config = WorldConfig::parse(&raw[..]).unwrap();
        assert!(!config.redirect_fallback);

        let mut touched = Vec::new();
        let res =
            crate::firewall::install_with(config.redirect_fallback, |name, _hooks, _rules| {
                touched.push(name.to_vec());
                if name == b"mangle" {
                    Err(std::io::ErrorKind::Unsupported.into())
                } else {
                    Ok(())
                }
            });
        assert!(res.is_err());
        assert_eq!(touched, [b"filter".to_vec(), b"mangle".to_vec()]);
        assert!(!touched.contains(&b"nat".to_vec()));
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
