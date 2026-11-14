use crate::*;
use hermetic_common::world_manifest::Resources;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const MIN_NETWORK_PREFIX: u8 = 1;
pub const MAX_NETWORK_PREFIX: u8 = 30;
pub const MIN_NETWORK_MTU: u16 = 576;
pub const MAX_NETWORK_MTU: u16 = 1500;

/// The gateway is the NetVM's address on the isolated IPv4 link.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub mtu: u16,
}

impl Network {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_NETWORK_PREFIX..=MAX_NETWORK_PREFIX).contains(&self.prefix)
            || !(MIN_NETWORK_MTU..=MAX_NETWORK_MTU).contains(&self.mtu)
        {
            return Err(Error::InvalidInput);
        }
        // The range check precedes the shift. Both ends must be usable private
        // unicast addresses in the same subnet, with distinct host portions.
        let mask = u32::MAX
            .checked_shl(u32::from(
                32_u8.checked_sub(self.prefix).ok_or(Error::InvalidInput)?,
            ))
            .ok_or(Error::InvalidInput)?;
        let address = u32::from(self.address);
        let gateway = u32::from(self.gateway);
        for ip in [self.address, self.gateway] {
            let host = u32::from(ip) & !mask;
            if !ip.is_private() || host == 0 || host == !mask {
                return Err(Error::InvalidInput);
            }
        }
        if address == gateway || address & mask != gateway & mask {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    #[serde(deserialize_with = "environment")]
    pub env: BTreeMap<String, String>,
    pub workdir: String,
    pub uid: u32,
    pub gid: u32,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub hostname: String,
    pub resolv_conf: String,
    /// Omission/null keeps networkless images compatible with the guest schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    pub resources: Resources,
}

pub fn text(s: &str, cap: usize) -> bool {
    s.len() <= cap && !s.contains('\0')
}

pub fn path(s: &str) -> Result<()> {
    if !text(s, MAX_PATH) || !s.starts_with('/') {
        return Err(Error::InvalidInput);
    }
    if s == "/" {
        return Ok(());
    }
    let mut count = 0;
    for part in s.strip_prefix('/').ok_or(Error::InvalidInput)?.split('/') {
        count += 1;
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.len() > MAX_COMPONENT_BYTES
            || count > MAX_COMPONENTS
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

pub fn args(v: &[String], empty: bool) -> Result<()> {
    if (!empty && v.is_empty()) || v.len() > MAX_ARGS || v.iter().any(|s| !text(s, MAX_STRING)) {
        return Err(Error::InvalidInput);
    }
    if let Some(program) = v.first() {
        path(program)?;
    }
    if serde_json::to_vec(v)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > MAX_ARG_BYTES
    {
        return Err(Error::Limit);
    }
    Ok(())
}

impl RunSpec {
    pub fn parse(reader: impl std::io::Read) -> Result<Self> {
        let data = read_capped(reader, MAX_SPEC)?;
        let spec: Self = serde_json::from_slice(&data).map_err(|_| Error::InvalidInput)?;
        spec.validate()?;
        Ok(spec)
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(network) = &self.network {
            network.validate()?;
        }
        path(&self.workdir)?;
        args(&self.entrypoint, true)?;
        // Command is appended to the entry point, so only its first element needs
        // to be an absolute executable when no entry point is present.
        if self.command.len() > MAX_ARGS || self.command.iter().any(|s| !text(s, MAX_STRING)) {
            return Err(Error::InvalidInput);
        }
        if self.entrypoint.is_empty() {
            args(&self.command, true)?;
        }
        if self.entrypoint.len().saturating_add(self.command.len()) > MAX_ARGS {
            return Err(Error::Limit);
        }
        args(&self.initial_argv(), true)?;
        if self.env.len() > MAX_ENV {
            return Err(Error::Limit);
        }
        for (key, value) in &self.env {
            let mut bytes = key.bytes();
            if !text(key, MAX_ENV_NAME)
                || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
                || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || !text(value, MAX_STRING)
            {
                return Err(Error::InvalidInput);
            }
        }
        if self.hostname.is_empty()
            || self.hostname.len() > MAX_HOSTNAME
            || self.hostname.starts_with('-')
            || self.hostname.ends_with('-')
            || !self
                .hostname
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !text(&self.resolv_conf, MAX_STRING)
            || self.uid == u32::MAX
            || self.gid == u32::MAX
        {
            return Err(Error::InvalidInput);
        }
        let r = &self.resources;
        if !(1..=MAX_VCPUS).contains(&r.vcpus)
            || !(1..=MAX_MEMORY_MIB).contains(&r.memory_mib)
            || !(1..=MAX_DISK_MIB).contains(&r.disk_mib)
            || !(1..=MAX_WALL_TIME_S).contains(&r.wall_time_s)
        {
            return Err(Error::InvalidInput);
        }
        if serde_json::to_vec(self)
            .map_err(|_| Error::InvalidInput)?
            .len()
            > MAX_SPEC
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub fn initial_argv(&self) -> Vec<String> {
        self.entrypoint
            .iter()
            .chain(&self.command)
            .cloned()
            .collect()
    }
}

fn environment<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Env;
    impl<'de> serde::de::Visitor<'de> for Env {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded unique environment")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut input: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            use serde::de::Error;
            let mut env = BTreeMap::new();
            while let Some((key, value)) = input.next_entry::<String, String>()? {
                if env.len() >= MAX_ENV || env.insert(key, value).is_some() {
                    return Err(M::Error::custom("invalid environment"));
                }
            }
            Ok(env)
        }
    }
    deserializer.deserialize_map(Env)
}
