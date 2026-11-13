use crate::spec::ValidatedSpec;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const VMM_OVERHEAD_MIB: u64 = 128;
pub const CPU_TEMPLATE: &str = include_str!("../../../vmm/hide-kvmclock.cpu-template.json");
/// The template is embedded so a plan cannot depend on a mutable host file.
pub fn cpu_template() -> Value {
    json!({
        "cpuid_modifiers": [{
            "leaf": "0x40000001",
            "subleaf": "0x0",
            "flags": 0,
            "modifiers": [{
                "register": "eax",
                "bitmap": "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx0"
            }]
        }]
    })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub body: Value,
}
impl ApiRequest {
    pub(crate) fn new(method: &str, path: &str, body: Value) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            body,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JailFile {
    pub source: Option<String>,
    pub destination: String,
    pub writable: bool,
    pub rule: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JailPlan {
    pub args: Vec<String>,
    pub root: String,
    pub uid: u32,
    pub gid: u32,
    pub files: Vec<JailFile>,
    pub api_socket: String,
}
pub fn api_requests(valid: &ValidatedSpec) -> Vec<ApiRequest> {
    let s = valid.spec();
    let mut boot = json!({"kernel_image_path":"/kernel","boot_args":s.boot_args});
    if s.initrd.is_some() {
        boot["initrd_path"] = json!("/initrd");
    }
    let mut out = vec![
        ApiRequest::new(
            "PUT",
            "/machine-config",
            json!({"vcpu_count":s.vcpus,"mem_size_mib":s.memory_mib,"smt":false}),
        ),
        ApiRequest::new("PUT", "/cpu-config", cpu_template()),
        ApiRequest::new("PUT", "/boot-source", boot),
    ];
    for (root, d) in
        std::iter::once((true, &s.root_drive)).chain(s.drives.iter().map(|d| (false, d)))
    {
        out.push(ApiRequest::new(
            "PUT",
            &format!("/drives/{}", d.id),
            json!({
                "drive_id": d.id,
                "path_on_host": format!("/drive-{}", d.id),
                "is_root_device": root,
                "is_read_only": d.read_only
            }),
        ));
    }
    for id in &s.reserved_drives {
        out.push(ApiRequest::new(
            "PUT",
            &format!("/drives/{id}"),
            json!({
                "drive_id": id,
                "path_on_host": format!("/drive-{id}"),
                "is_root_device": false,
                "is_read_only": true
            }),
        ));
    }
    if let Some(v) = &s.vsock {
        out.push(ApiRequest::new(
            "PUT",
            "/vsock",
            json!({"guest_cid":v.guest_cid,"uds_path":v.socket_path}),
        ));
    }
    for (i, n) in s.networks.iter().enumerate() {
        out.push(ApiRequest::new(
            "PUT",
            &format!("/network-interfaces/eth{i}"),
            json!({"iface_id":format!("eth{i}"),"host_dev_name":n.tap,"guest_mac":n.guest_mac}),
        ));
    }
    out.push(ApiRequest::new("PUT", "/entropy", json!({})));
    out
}
pub fn jail_plan(valid: &ValidatedSpec) -> JailPlan {
    let s = valid.spec();
    let j = &s.jail;
    // These additions and multiplications are bounded by VmSpec::validate.
    let uid = j.uid_start + s.index;
    let gid = j.gid_start + s.index;
    let root = format!("{}/firecracker/{}/root", j.base, s.id);
    let args = [
        "--id".into(),
        s.id.clone(),
        "--exec-file".into(),
        format!("{}/firecracker/{}/firecracker", j.base, s.id),
        "--uid".into(),
        uid.to_string(),
        "--gid".into(),
        gid.to_string(),
        "--chroot-base-dir".into(),
        j.base.clone(),
        "--cgroup-version".into(),
        "2".into(),
        "--cgroup".into(),
        format!("cpu.max={} 100000", u64::from(s.vcpus) * 100000),
        "--cgroup".into(),
        format!(
            "memory.max={}",
            (u64::from(s.memory_mib) + VMM_OVERHEAD_MIB) * 1024 * 1024
        ),
        "--cgroup".into(),
        format!("pids.max={}", s.limits.pids),
        "--netns".into(),
        format!("/var/run/netns/{}", j.netns),
        "--new-pid-ns".into(),
        "--resource-limit".into(),
        format!("fsize={}", s.limits.file_size_bytes),
        "--resource-limit".into(),
        format!("no-file={}", s.limits.open_files),
        "--".into(),
        "--api-sock".into(),
        "/api.socket".into(),
    ]
    .into();
    let mut files = vec![
        JailFile {
            source: Some(s.kernel_image.clone()),
            destination: "kernel".into(),
            writable: false,
            rule: "copy".into(),
        },
        JailFile {
            source: Some(s.cpu_template.clone()),
            destination: "cpu-template.json".into(),
            writable: false,
            rule: "copy".into(),
        },
    ];
    if let Some(initrd) = &s.initrd {
        files.push(JailFile {
            source: Some(initrd.path.clone()),
            destination: "initrd".into(),
            writable: false,
            rule: "copy-sha256-pinned".into(),
        });
    }
    for d in std::iter::once(&s.root_drive).chain(s.drives.iter()) {
        files.push(JailFile {
            source: Some(d.path.clone()),
            destination: format!("drive-{}", d.id),
            writable: !d.read_only,
            rule: "copy".into(),
        });
    }
    for id in &s.reserved_drives {
        files.push(JailFile {
            source: None,
            destination: format!("drive-{id}"),
            writable: false,
            rule: "empty-4096".into(),
        });
    }
    JailPlan {
        args,
        api_socket: format!("{root}/api.socket"),
        root,
        uid,
        gid,
        files,
    }
}
