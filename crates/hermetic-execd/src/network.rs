#![forbid(unsafe_code)]
//! Fixed busybox applets; no shell, PATH lookup, or inherited environment.
use crate::{rpc::ExecReply, spec::RunSpec, *};

pub const NETWORK_PROGRAM: &str = "/bin/busybox";
pub const NETWORK_COMMAND_TIMEOUT_MS: u64 = 5000;
pub const NETWORK_MEMORY_MIB: u64 = 64;

/// Validate the entire spec before issuing any command. The Linux caller must
/// execute the busybox inode pinned from the sealed base before switching root.
pub fn configure(
    spec: &RunSpec,
    mut run: impl FnMut(&RunSpec, &[String]) -> Result<ExecReply>,
) -> Result<()> {
    spec.validate()?;
    let Some(network) = &spec.network else {
        return Ok(());
    };
    // Network setup is privileged boot work, independent of the task's uid,
    // environment, workdir, entrypoint and resource declarations.
    let mut setup = spec.clone();
    setup.env.clear();
    setup.workdir = "/".into();
    setup.uid = 0;
    setup.gid = 0;
    setup.entrypoint.clear();
    setup.command.clear();
    setup.resources.memory_mib = NETWORK_MEMORY_MIB;
    let cidr = format!("{}/{}", network.address, network.prefix);
    let gateway = network.gateway.to_string();
    let mtu = network.mtu.to_string();
    // /proc is the procfs mounted by PID 1 before this step. sysctl touches
    // only these fixed kernel entries. Disable IPv6 before bringing links up.
    for args in [
        &["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"][..],
        &["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"],
        &["ip", "link", "set", "lo", "up"],
        &["ip", "link", "set", "dev", "eth0", "mtu", &mtu],
        &["ip", "addr", "add", &cidr, "dev", "eth0"],
        &["ip", "link", "set", "dev", "eth0", "up"],
        &[
            "ip", "route", "add", "default", "via", &gateway, "dev", "eth0",
        ],
    ] {
        let argv = std::iter::once(NETWORK_PROGRAM)
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let reply = run(&setup, &argv)?;
        if reply.code != Some(0) || reply.timed_out {
            return Err(Error::Network);
        }
    }
    Ok(())
}
