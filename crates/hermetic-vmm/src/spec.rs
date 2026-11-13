use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path};

pub const MAX_SPEC_BYTES: u64 = 64 * 1024;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_PATH_COMPONENTS: usize = 64;
pub const MAX_BOOT_ARGS: usize = 4096;
pub const MAX_DRIVES: usize = 16;
pub const MAX_NETWORKS: usize = 2;
pub const MAX_VMS: usize = 4096;
pub const MAX_VCPUS: u8 = 32;
pub const MAX_MEMORY_MIB: u32 = 131072;
pub const MAX_PIDS: u32 = 4096;
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_TOTAL_IMAGE_BYTES: u64 = 256 * 1024 * 1024 * 1024;
pub const MAX_T_CLOCK: u64 = 4_102_444_800;
pub const MAX_INITRD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Initrd {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Agent,
    Net,
    Extractor,
    Grader,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Clock {
    Faked,
    Hidden,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Drive {
    pub id: String,
    pub path: String,
    pub read_only: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vsock {
    pub guest_cid: u32,
    pub socket_path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub tap: String,
    pub guest_mac: String,
    pub peer: Role,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub pids: u32,
    pub file_size_bytes: u64,
    pub open_files: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailConfig {
    pub base: String,
    pub uid_start: u32,
    pub gid_start: u32,
    pub count: u32,
    pub firecracker: String,
    pub jailer: String,
    pub netns: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSpec {
    pub id: String,
    pub role: Role,
    pub index: u32,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub kernel_image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<Initrd>,
    pub boot_args: String,
    pub root_drive: Drive,
    pub drives: Vec<Drive>,
    pub reserved_drives: Vec<String>,
    pub vsock: Option<Vsock>,
    pub networks: Vec<Network>,
    pub cpu_template: String,
    pub clock: Clock,
    pub limits: Limits,
    pub jail: JailConfig,
}
#[derive(Debug, Clone)]
pub struct ValidatedSpec(VmSpec);
impl ValidatedSpec {
    pub fn spec(&self) -> &VmSpec {
        &self.0
    }
}

pub fn identifier(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn absolute_path(s: &str) -> bool {
    s.len() <= MAX_PATH_BYTES
        && !s.as_bytes().contains(&0)
        && s.is_ascii()
        && s.starts_with('/')
        && !s.ends_with('/')
        && !s.contains("//")
        && Path::new(s).components().count() <= MAX_PATH_COMPONENTS
        && s.split('/')
            .skip(1)
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && Path::new(s)
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
pub fn project_mac(role: Role, index: usize) -> String {
    let role = match role {
        Role::Agent => 1,
        Role::Net => 2,
        Role::Extractor => 3,
        Role::Grader => 4,
    };
    format!("02:48:57:{role:02x}:00:{index:02x}")
}
/// Id of the GraderVM's only writable drive (guest `/dev/vdb`).
pub const GRADER_RESULT_DRIVE: &str = "result";
/// Exact size of the GraderVM result drive (HGRD image).
pub const GRADER_RESULT_BYTES: u64 = 1024 * 1024;
pub fn validate_boot_args(args: &str) -> Result<()> {
    if args.len() > MAX_BOOT_ARGS
        || args.is_empty()
        // Keep tokenization identical to the guest's whitespace rule table.
        // Linux command-line quoting must not hide a required/forbidden token.
        || !args.bytes().all(|b| {
            (b == b' ' || b.is_ascii_graphic()) && !matches!(b, b'"' | b'\'' | b'\\')
        })
    {
        return Err(Error::Validation("boot argument encoding/cap"));
    }
    let mut required = [false; 4];
    let mut keys = BTreeSet::new();
    for arg in args.split_ascii_whitespace() {
        if arg == "--" {
            return Err(Error::Validation(
                "standalone -- separator forbidden in boot arguments",
            ));
        }
        let key = arg
            .split('=')
            .next()
            .ok_or(Error::Validation("boot argument"))?;
        if !keys.insert(key) {
            return Err(Error::Validation("duplicate boot argument"));
        }
        match arg {
            "clocksource=tsc" => required[0] = true,
            "tsc=reliable" => required[1] = true,
            "ro" => required[3] = true,
            "rw" => return Err(Error::Validation("writable root forbidden")),
            _ if arg.starts_with("hermetic.t=") => {
                let value = arg
                    .strip_prefix("hermetic.t=")
                    .ok_or(Error::Validation("T_clock"))?;
                if value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                    || value.parse::<u64>().map_or(true, |t| t > MAX_T_CLOCK)
                {
                    return Err(Error::Validation("T_clock range/encoding"));
                }
                required[2] = true;
            }
            _ if arg.starts_with("rw=")
                || arg.starts_with("ip=")
                || arg.starts_with("clocksource=")
                || arg.starts_with("tsc=") =>
            {
                return Err(Error::Validation("forbidden boot argument"))
            }
            _ => (),
        }
    }
    if required.iter().any(|v| !v) {
        return Err(Error::Validation(
            "required boot arguments: clocksource=tsc tsc=reliable hermetic.t= ro",
        ));
    }
    Ok(())
}
impl VmSpec {
    pub fn read(reader: impl Read) -> Result<Self> {
        let mut data = Vec::new();
        reader.take(MAX_SPEC_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_SPEC_BYTES {
            return Err(Error::Validation("spec size cap"));
        }
        serde_json::from_slice(&data).map_err(|_| Error::Validation("invalid spec JSON"))
    }
    pub fn validate(self) -> Result<ValidatedSpec> {
        if self.clock == Clock::Hidden {
            return Err(Error::Validation(concat!(
                "TR-VMM-3 unmet: enforce-pv-cpuid patch (including restore), ",
                "host KVM_HC_CLOCK_PAIRING block, passing guest-module probe"
            )));
        }
        if !identifier(&self.id, 48) || self.index as usize >= MAX_VMS {
            return Err(Error::Validation("VM id/index"));
        }
        if !(1..=MAX_VCPUS).contains(&self.vcpus)
            || !(64..=MAX_MEMORY_MIB).contains(&self.memory_mib)
        {
            return Err(Error::Validation("machine resource caps"));
        }
        if !(1..=MAX_PIDS).contains(&self.limits.pids)
            || !(16..=4096).contains(&self.limits.open_files)
            || self.limits.file_size_bytes == 0
            || self.limits.file_size_bytes > MAX_IMAGE_BYTES
        {
            return Err(Error::Validation("process resource caps"));
        }
        if self.drives.len().saturating_add(self.reserved_drives.len()) > MAX_DRIVES
            || self.networks.len() > MAX_NETWORKS
        {
            return Err(Error::Validation("device count cap"));
        }
        for path in [
            &self.kernel_image,
            &self.cpu_template,
            &self.root_drive.path,
            &self.jail.base,
            &self.jail.firecracker,
            &self.jail.jailer,
        ] {
            if !absolute_path(path) {
                return Err(Error::Validation("absolute normalized path required"));
            }
        }
        if Path::new(&self.jail.firecracker)
            .file_name()
            .and_then(|s| s.to_str())
            != Some("firecracker")
        {
            return Err(Error::Validation(
                "Firecracker executable basename must be firecracker",
            ));
        }
        validate_boot_args(&self.boot_args)?;
        let words: Vec<_> = self.boot_args.split_ascii_whitespace().collect();
        if let Some(initrd) = &self.initrd {
            if self.role != Role::Agent
                || !self.networks.is_empty()
                || !absolute_path(&initrd.path)
                || initrd.sha256.len() != 64
                || !initrd
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || words.iter().any(|w| {
                    matches!(*w, "init" | "rdinit" | "noinitrd" | "skip_initramfs")
                        || w.starts_with("init=")
                        || w.starts_with("rdinit=")
                        || w.starts_with("noinitrd=")
                        || w.starts_with("skip_initramfs=")
                })
                || !words.contains(&"hermetic.initramfs=1")
                || !words.contains(&"root=/dev/vda")
                || self
                    .drives
                    .first()
                    .is_none_or(|d| d.id != "overlay" || d.read_only)
                || words.iter().any(|w| {
                    w.starts_with("hermetic.overlay=") && *w != "hermetic.overlay=/dev/vdb"
                })
            {
                return Err(Error::Validation("trusted reboot initrd contract"));
            }
            let clock = words
                .iter()
                .find_map(|w| w.strip_prefix("hermetic.t="))
                .and_then(|t| t.parse::<u64>().ok());
            if clock.is_none_or(|t| !(315532800..=4102444799).contains(&t)) {
                return Err(Error::Validation("trusted reboot clock range"));
            }
        } else if words.iter().any(|w| {
            (w.starts_with("hermetic.initramfs") && *w != "hermetic.initramfs=0")
                || w.starts_with("rdinit=")
        }) {
            return Err(Error::Validation("initramfs mode requires pinned initrd"));
        }
        let mut ids = BTreeSet::new();
        for drive in std::iter::once(&self.root_drive).chain(self.drives.iter()) {
            if !identifier(&drive.id, 32) || !ids.insert(&drive.id) || !absolute_path(&drive.path) {
                return Err(Error::Validation("drive id/path"));
            }
        }
        for id in &self.reserved_drives {
            if !identifier(id, 32) || !ids.insert(id) {
                return Err(Error::Validation("reserved drive id"));
            }
        }
        if !self.root_drive.read_only {
            return Err(Error::Validation("root must be read-only"));
        }
        if self.role == Role::Agent
            && !self
                .drives
                .iter()
                .any(|d| d.id == "overlay" && !d.read_only)
        {
            return Err(Error::Validation("AgentVM requires writable overlay"));
        }
        // GraderVM layout: sealed read-only root (vda), then exactly one writable
        // drive, `result` (vdb, GRADER_RESULT_BYTES), first among further drives so
        // its guest name is fixed; every other further drive is read-only.
        if self.role == Role::Grader
            && (self
                .drives
                .first()
                .is_none_or(|d| d.id != GRADER_RESULT_DRIVE || d.read_only)
                || self.drives.iter().skip(1).any(|d| !d.read_only))
        {
            return Err(Error::Validation(
                "GraderVM requires writable result drive first and read-only others",
            ));
        }
        if matches!(self.role, Role::Extractor | Role::Grader) && !self.networks.is_empty() {
            return Err(Error::Validation("isolated role cannot have network"));
        }
        if self.role == Role::Net && self.drives.iter().any(|drive| !drive.read_only) {
            return Err(Error::Validation("NetVM drives must be read-only"));
        }
        if self.role == Role::Agent
            && (self.networks.len() > 1 || self.networks.iter().any(|n| n.peer != Role::Net))
        {
            return Err(Error::Validation("AgentVM network must lead only to NetVM"));
        }
        if self.role == Role::Net
            && (self.networks.len() > 1 || self.networks.iter().any(|n| n.peer != Role::Agent))
        {
            return Err(Error::Validation("NetVM network must lead only to AgentVM"));
        }
        let mut taps = BTreeSet::new();
        for (i, net) in self.networks.iter().enumerate() {
            if !identifier(&net.tap, 15)
                || !taps.insert(&net.tap)
                || net.guest_mac != project_mac(self.role, i)
            {
                return Err(Error::Validation("tap or project MAC"));
            }
        }
        if self.role == Role::Grader && self.vsock.is_some() {
            return Err(Error::Validation("TR-GR-1: GraderVM has no vsock"));
        }
        if let Some(v) = &self.vsock {
            if v.guest_cid < 3 || v.socket_path != "/vsock" {
                return Err(Error::Validation("vsock CID/path"));
            }
        }
        let j = &self.jail;
        if j.count == 0
            || j.count as usize > MAX_VMS
            || self.index >= j.count
            || j.uid_start < 65536
            || j.gid_start < 65536
            || !identifier(&j.netns, 48)
        {
            return Err(Error::Validation("jail range/namespace"));
        }
        let uid = j
            .uid_start
            .checked_add(self.index)
            .ok_or(Error::Validation("uid overflow"))?;
        let gid = j
            .gid_start
            .checked_add(self.index)
            .ok_or(Error::Validation("gid overflow"))?;
        if j.uid_start.checked_add(j.count).is_none()
            || j.gid_start.checked_add(j.count).is_none()
            || uid == rustix::process::geteuid().as_raw()
            || gid == rustix::process::getegid().as_raw()
        {
            return Err(Error::Validation("jail identity must be dedicated"));
        }
        Ok(ValidatedSpec(self))
    }
}
/// A run must be validated as a unit before any VM is prepared.
pub fn validate_run(specs: Vec<VmSpec>) -> Result<Vec<ValidatedSpec>> {
    if specs.is_empty() || specs.len() > MAX_VMS {
        return Err(Error::Validation("run count cap"));
    }
    let mut ids = BTreeSet::new();
    let mut cids = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut gids = BTreeSet::new();
    let mut out = Vec::new();
    for spec in specs {
        let valid = spec.validate()?;
        let s = valid.spec();
        if !ids.insert(s.id.clone())
            || !uids.insert(s.jail.uid_start + s.index)
            || !gids.insert(s.jail.gid_start + s.index)
            || s.vsock.as_ref().is_some_and(|v| !cids.insert(v.guest_cid))
        {
            return Err(Error::Validation(
                "run ids, CIDs and jail identities must be unique",
            ));
        }
        out.push(valid);
    }
    Ok(out)
}
