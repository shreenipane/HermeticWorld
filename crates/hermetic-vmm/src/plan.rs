use crate::spec::ValidatedSpec;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const VMM_OVERHEAD_MIB: u64 = 128;
/// Accepted guest TSC frequency range in kHz (100 MHz to 10 GHz).
pub const TSC_KHZ_RANGE: std::ops::RangeInclusive<u64> = 100_000..=10_000_000;
/// Scaled in the pinned Firecracker build, independent of physical frequency.
pub const GUEST_TSC_KHZ: u64 = 2_000_000;

/// The host TSC frequency from CPUID leaf 0x15 (crystal Hz * EBX / EAX), in kHz.
/// The guest kernel has no kvmclock, PIT, HPET or ACPI PM timer to calibrate
/// against, so the VMM passes this exact value as `tsc_early_khz=`. Returns
/// None when the leaf is absent or incomplete; nothing is guessed.
pub fn host_tsc_khz() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;
        let base = __cpuid(0);
        if base.eax < 0x15 {
            return None;
        }
        let r = __cpuid(0x15);
        tsc_khz_from_host_leaf15(
            [base.ebx, base.edx, base.ecx],
            __cpuid(1).ecx & (1 << 31) != 0,
            r.eax,
            r.ebx,
            r.ecx,
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Bare-metal Intel leaf-0x15 is trusted; other hosts need operator calibration.
pub fn tsc_khz_from_host_leaf15(
    vendor: [u32; 3],
    virtualized: bool,
    eax: u32,
    ebx: u32,
    ecx: u32,
) -> Option<u64> {
    if virtualized || vendor != [0x756e6547, 0x49656e69, 0x6c65746e] {
        return None;
    }
    tsc_khz_from_leaf15(eax, ebx, ecx)
}

/// Pure leaf-0x15 arithmetic, separated for tests.
pub fn tsc_khz_from_leaf15(eax: u32, ebx: u32, ecx: u32) -> Option<u64> {
    if eax == 0 || ebx == 0 || ecx == 0 {
        return None;
    }
    let khz = u64::from(ecx) * u64::from(ebx) / u64::from(eax) / 1000;
    TSC_KHZ_RANGE.contains(&khz).then_some(khz)
}

pub(crate) fn valid_tsc_khz_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8
        && value.bytes().all(|b| b.is_ascii_digit())
        && !value.starts_with('0')
        && value
            .parse::<u64>()
            .is_ok_and(|v| TSC_KHZ_RANGE.contains(&v))
}

/// CPUID leaf 0x15 wins. Hosts without it (AMD, nested QEMU) need the operator
/// to set HERMETIC_TSC_KHZ to the host kernel's own "tsc: Detected" value.
/// An invalid override is an error even when CPUID is available.
pub fn resolve_tsc_khz(cpuid: Option<u64>, operator: Option<&str>) -> crate::Result<u64> {
    let operator = match operator {
        Some(v) if valid_tsc_khz_text(v) => v.parse::<u64>().ok(),
        Some(_) => return Err(crate::Error::Validation("HERMETIC_TSC_KHZ range/encoding")),
        None => None,
    };
    if cpuid.is_some_and(|v| !TSC_KHZ_RANGE.contains(&v)) {
        return Err(crate::Error::Validation("CPUID TSC frequency range"));
    }
    cpuid.or(operator).ok_or(crate::Error::Validation(
        "host TSC frequency unavailable: no CPUID leaf 0x15 and no HERMETIC_TSC_KHZ",
    ))
}

/// The patched VMM scales to this rate. Refuse stale physical-rate overrides,
/// including non-Unicode settings, without querying any host CPU frequency.
pub fn configured_tsc_khz() -> crate::Result<u64> {
    if std::env::var_os("HERMETIC_TSC_KHZ").is_some_and(|value| value != "2000000") {
        return Err(crate::Error::Validation(
            "HERMETIC_TSC_KHZ must match fixed guest rate",
        ));
    }
    Ok(GUEST_TSC_KHZ)
}

pub fn resolve_tsc_khz_os(
    cpuid: Option<u64>,
    operator: Option<&std::ffi::OsStr>,
) -> crate::Result<u64> {
    let operator = operator
        .map(|s| {
            s.to_str()
                .ok_or(crate::Error::Validation("HERMETIC_TSC_KHZ encoding"))
        })
        .transpose()?;
    resolve_tsc_khz(cpuid, operator)
}

/// Resolve the executable boot source before sending any configuration requests.
pub fn with_tsc_khz(mut req: ApiRequest, khz: u64) -> crate::Result<ApiRequest> {
    if khz != GUEST_TSC_KHZ {
        return Err(crate::Error::Validation("TSC frequency range"));
    }
    if req.path == "/boot-source" {
        let args = req
            .body
            .get("boot_args")
            .and_then(Value::as_str)
            .ok_or(crate::Error::Validation("boot argument shape"))?;
        let args = calibrated_boot_args(args, khz)?;
        req.body["boot_args"] = json!(args);
    }
    Ok(req)
}

pub fn calibrated_boot_args(args: &str, khz: u64) -> crate::Result<String> {
    crate::spec::validate_boot_args(args)?;
    if khz != GUEST_TSC_KHZ || has_tsc_arg(args) {
        return Err(crate::Error::Validation("TSC frequency is VMM-owned"));
    }
    let args = format!("{args} tsc_early_khz={khz}");
    crate::spec::validate_boot_args(&args)?;
    Ok(args)
}

pub(crate) fn has_tsc_arg(args: &str) -> bool {
    args.split_ascii_whitespace().any(|a| {
        a.split('=')
            .next()
            .is_some_and(|k| k.replace('-', "_") == "tsc_early_khz")
    })
}

pub(crate) fn valid_calibrated_boot_args(args: &str) -> bool {
    if crate::spec::validate_boot_args(args).is_err() {
        return false;
    }
    let mut reserved = args.split_ascii_whitespace().filter(|a| has_tsc_arg(a));
    reserved
        .next()
        .is_some_and(|a| a == "tsc_early_khz=2000000")
        && reserved.next().is_none()
}

pub fn calibrated_api_requests(valid: &ValidatedSpec, khz: u64) -> crate::Result<Vec<ApiRequest>> {
    api_requests(valid)
        .into_iter()
        .map(|req| with_tsc_khz(req, khz))
        .collect()
}

pub const CPU_TEMPLATE: &str = include_str!("../../../vmm/clock-3b.cpu-template.json");
/// The template is embedded so a plan cannot depend on a mutable host file.
/// A malformed embedded template fails the object check in the API validator.
pub fn cpu_template() -> Value {
    serde_json::from_str(CPU_TEMPLATE).unwrap_or(Value::Null)
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
