use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

/// Maximum number of argv elements accepted in `PlanInput`.
pub const MAX_ARGV_LEN: usize = 256;
/// Maximum byte length of a single argv string.
pub const MAX_ARG_BYTES: usize = 4 * 1024;
/// Maximum byte length of a path (`working_dir`, `home_dir`).
pub const MAX_PATH_BYTES: usize = 4 * 1024;
/// Maximum number of environment allow-list entries accepted in `PlanInput`.
pub const MAX_ENV_ENTRIES: usize = 128;
/// Maximum byte length of an environment variable name.
pub const MAX_ENV_NAME_BYTES: usize = 128;
/// Maximum byte length of an environment variable value.
pub const MAX_ENV_VALUE_BYTES: usize = 4 * 1024;
/// Maximum number of required pytest plugins accepted in `PlanInput`.
pub const MAX_PLUGINS: usize = 64;
/// Maximum byte length of a single pytest plugin name.
pub const MAX_PLUGIN_NAME_BYTES: usize = 128;

/// Docker default capability set before removing MKNOD and administrative capabilities.
const DOCKER_DEFAULT_CAPS: &[&str] = &[
    "CAP_AUDIT_WRITE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_KILL",
    "CAP_MKNOD",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_RAW",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT",
];

/// Capabilities that must never appear in any capability set.
const FORBIDDEN_CAPS: &[&str] = &[
    "CAP_MKNOD",
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_PTRACE",
    "CAP_SYS_TIME",
    "CAP_NET_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_SYSLOG",
    "CAP_BPF",
    "CAP_PERFMON",
    "CAP_CHECKPOINT_RESTORE",
];

/// Fixed environment keys controlled exclusively by the sandbox runner.
const RESERVED_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "TZ",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanInput {
    pub argv: Vec<String>,
    pub working_dir: String,
    pub home_dir: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub env_allowlist: Vec<EnvEntry>,
    pub t_clock: i64,
    pub required_pytest_plugins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    EmptyArgv,
    TooManyArgs,
    ArgTooLong,
    NulByteInInput,
    NotPytestCommand,
    InvalidPath,
    PathTooLong,
    InvalidUidOrGid,
    TooManyEnvEntries,
    InvalidEnvName,
    EnvNameTooLong,
    EnvValueTooLong,
    ReservedEnvOverride,
    DuplicateEnvName,
    InvalidClock,
    TooManyPlugins,
    InvalidPluginName,
    PluginNameTooLong,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PlanError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilitySets {
    pub ambient: Vec<String>,
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub inheritable: Vec<String>,
    pub no_new_privileges: bool,
    pub permitted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamespaceSpec {
    pub ipc: bool,
    pub mount: bool,
    pub net: bool,
    pub pid: bool,
    pub rationale: String,
    pub user: bool,
    pub uts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceNode {
    pub dev_type: String,
    pub major: u32,
    pub minor: u32,
    pub mode: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCgroupRule {
    pub access: String,
    pub allow: bool,
    pub dev_type: String,
    pub major: Option<u32>,
    pub minor: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MountSpec {
    pub destination: String,
    pub fs_type: String,
    pub notes: String,
    pub options: Vec<String>,
    pub read_only: bool,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxPlan {
    pub argv: Vec<String>,
    pub capabilities: CapabilitySets,
    pub device_cgroup_order_note: String,
    pub device_cgroup_rules: Vec<DeviceCgroupRule>,
    pub devices: Vec<DeviceNode>,
    pub env: BTreeMap<String, String>,
    pub gid: u32,
    pub mounts: Vec<MountSpec>,
    pub namespaces: NamespaceSpec,
    pub t_clock: i64,
    pub uid: u32,
    pub working_dir: String,
}

fn validate_abs_clean_path(path: &str) -> Result<(), PlanError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(PlanError::InvalidPath);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PlanError::PathTooLong);
    }
    if path.as_bytes().contains(&0x00) {
        return Err(PlanError::NulByteInInput);
    }
    for seg in path.split('/') {
        if seg == ".." {
            return Err(PlanError::InvalidPath);
        }
    }
    Ok(())
}

fn is_valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !(first.is_ascii_uppercase() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn is_valid_plugin_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn is_python_binary(token: &str) -> bool {
    let base = token.rsplit('/').next().unwrap_or(token);
    if base == "python" || base == "python3" {
        return true;
    }
    if let Some(rest) = base.strip_prefix("python3.") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

fn is_pytest_binary(token: &str) -> bool {
    let base = token.rsplit('/').next().unwrap_or(token);
    base == "pytest" || base == "py.test"
}

/// Extracts the trailing pytest arguments if `argv` is a valid pytest invocation,
/// refusing arbitrary commands or `-c` code execution flags.
fn extract_pytest_args(argv: &[String]) -> Result<&[String], PlanError> {
    if argv.is_empty() {
        return Err(PlanError::EmptyArgv);
    }
    if argv.len() > MAX_ARGV_LEN {
        return Err(PlanError::TooManyArgs);
    }
    for arg in argv {
        if arg.len() > MAX_ARG_BYTES {
            return Err(PlanError::ArgTooLong);
        }
        if arg.as_bytes().contains(&0x00) {
            return Err(PlanError::NulByteInInput);
        }
    }

    let first = argv.first().ok_or(PlanError::EmptyArgv)?;
    if is_pytest_binary(first) {
        return Ok(&argv[1..]);
    }

    if is_python_binary(first) {
        // Scan interpreter flags before `-m pytest`
        let mut idx = 1usize;
        while idx < argv.len() {
            let tok = argv[idx].as_str();
            if tok == "-m" {
                let mod_name = argv.get(idx + 1).ok_or(PlanError::NotPytestCommand)?;
                if mod_name == "pytest" {
                    return Ok(&argv[idx + 2..]);
                }
                return Err(PlanError::NotPytestCommand);
            }
            // Allow harmless isolated/unbuffered flags before `-m`; forbid `-c` or positional scripts
            if matches!(tok, "-s" | "-B" | "-u" | "-E" | "-I" | "-O" | "-OO") {
                idx += 1;
                continue;
            }
            return Err(PlanError::NotPytestCommand);
        }
    }

    Err(PlanError::NotPytestCommand)
}

fn build_capabilities() -> CapabilitySets {
    let forbidden: BTreeSet<&str> = FORBIDDEN_CAPS.iter().copied().collect();
    let allowed: Vec<String> = DOCKER_DEFAULT_CAPS
        .iter()
        .copied()
        .filter(|cap| !forbidden.contains(cap))
        .map(|s| s.to_owned())
        .collect();

    CapabilitySets {
        ambient: Vec::new(),
        bounding: allowed.clone(),
        effective: allowed.clone(),
        inheritable: Vec::new(),
        no_new_privileges: true,
        permitted: allowed,
    }
}

fn build_devices() -> Vec<DeviceNode> {
    vec![
        DeviceNode {
            dev_type: "c".to_owned(),
            major: 1,
            minor: 3,
            mode: "0666".to_owned(),
            path: "/dev/null".to_owned(),
        },
        DeviceNode {
            dev_type: "c".to_owned(),
            major: 1,
            minor: 5,
            mode: "0666".to_owned(),
            path: "/dev/zero".to_owned(),
        },
        DeviceNode {
            dev_type: "c".to_owned(),
            major: 1,
            minor: 7,
            mode: "0666".to_owned(),
            path: "/dev/full".to_owned(),
        },
        DeviceNode {
            dev_type: "c".to_owned(),
            major: 1,
            minor: 8,
            mode: "0666".to_owned(),
            path: "/dev/random".to_owned(),
        },
        DeviceNode {
            dev_type: "c".to_owned(),
            major: 1,
            minor: 9,
            mode: "0666".to_owned(),
            path: "/dev/urandom".to_owned(),
        },
        DeviceNode {
            dev_type: "c".to_owned(),
            major: 5,
            minor: 0,
            mode: "0666".to_owned(),
            path: "/dev/tty".to_owned(),
        },
    ]
}

fn build_device_cgroup_rules() -> Vec<DeviceCgroupRule> {
    // In cgroup v2 device BPF programs, rules are evaluated sequentially from most-specific
    // allow rules down to catch-all deny rules (matching crun/runc BPF device filter compilation,
    // which emits explicit character-device allow branches before falling through to default-deny
    // and explicit block-device `b *:* rwm` denial).
    vec![
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: true,
            dev_type: "c".to_owned(),
            major: Some(1),
            minor: Some(3),
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: true,
            dev_type: "c".to_owned(),
            major: Some(1),
            minor: Some(5),
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: true,
            dev_type: "c".to_owned(),
            major: Some(1),
            minor: Some(7),
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: true,
            dev_type: "c".to_owned(),
            major: Some(1),
            minor: Some(8),
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: true,
            dev_type: "c".to_owned(),
            major: Some(1),
            minor: Some(9),
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: true,
            dev_type: "c".to_owned(),
            major: Some(5),
            minor: Some(0),
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: false,
            dev_type: "b".to_owned(),
            major: None,
            minor: None,
        },
        DeviceCgroupRule {
            access: "rwm".to_owned(),
            allow: false,
            dev_type: "a".to_owned(),
            major: None,
            minor: None,
        },
    ]
}

fn build_mounts(working_dir: &str) -> Vec<MountSpec> {
    vec![
        MountSpec {
            destination: "/".to_owned(),
            fs_type: "overlay".to_owned(),
            notes: "Root filesystem sealed read-only".to_owned(),
            options: vec!["ro".to_owned(), "nosuid".to_owned()],
            read_only: true,
            source: "rootfs".to_owned(),
        },
        MountSpec {
            destination: "/proc".to_owned(),
            fs_type: "proc".to_owned(),
            notes: "hidepid=2 is NOT used because each test run executes in its own dedicated PID namespace and pytest/subprocesses inspect own/child process trees".to_owned(),
            options: vec!["nosuid".to_owned(), "nodev".to_owned(), "noexec".to_owned()],
            read_only: false,
            source: "proc".to_owned(),
        },
        MountSpec {
            destination: "/sys".to_owned(),
            fs_type: "sysfs".to_owned(),
            notes: "Kernel sysfs exposed strictly read-only".to_owned(),
            options: vec![
                "ro".to_owned(),
                "nosuid".to_owned(),
                "nodev".to_owned(),
                "noexec".to_owned(),
            ],
            read_only: true,
            source: "sysfs".to_owned(),
        },
        MountSpec {
            destination: "/dev".to_owned(),
            fs_type: "tmpfs".to_owned(),
            notes: "Minimal device directory populated with null, zero, full, random, urandom, tty".to_owned(),
            options: vec![
                "nosuid".to_owned(),
                "noexec".to_owned(),
                "mode=755".to_owned(),
            ],
            read_only: false,
            source: "tmpfs".to_owned(),
        },
        MountSpec {
            destination: "/dev/pts".to_owned(),
            fs_type: "devpts".to_owned(),
            notes: "Private devpts instance for pseudo-terminals".to_owned(),
            options: vec![
                "nosuid".to_owned(),
                "noexec".to_owned(),
                "newinstance".to_owned(),
                "ptmxmode=0666".to_owned(),
                "mode=0620".to_owned(),
            ],
            read_only: false,
            source: "devpts".to_owned(),
        },
        MountSpec {
            destination: "/dev/shm".to_owned(),
            fs_type: "tmpfs".to_owned(),
            notes: "Private POSIX shared memory mount".to_owned(),
            options: vec![
                "nosuid".to_owned(),
                "nodev".to_owned(),
                "noexec".to_owned(),
                "mode=1777".to_owned(),
            ],
            read_only: false,
            source: "shm".to_owned(),
        },
        MountSpec {
            destination: "/tmp".to_owned(),
            fs_type: "bind".to_owned(),
            notes: "Backed by writable overlay layer (not tmpfs) so test artifacts and logs survive for post-run inspection".to_owned(),
            options: vec!["rbind".to_owned(), "rw".to_owned(), "nosuid".to_owned()],
            read_only: false,
            source: "/tmp".to_owned(),
        },
        MountSpec {
            destination: working_dir.to_owned(),
            fs_type: "bind".to_owned(),
            notes: "Repository working tree mounted read-write for test execution".to_owned(),
            options: vec!["rbind".to_owned(), "rw".to_owned(), "nosuid".to_owned()],
            read_only: false,
            source: working_dir.to_owned(),
        },
    ]
}

/// Computes the deterministic sandbox plan for executing pytest in the grader VM.
pub fn plan(input: &PlanInput) -> Result<SandboxPlan, PlanError> {
    if input.uid == u32::MAX || input.gid == u32::MAX {
        return Err(PlanError::InvalidUidOrGid);
    }
    if input.t_clock < 0 {
        return Err(PlanError::InvalidClock);
    }

    validate_abs_clean_path(&input.working_dir)?;
    let home = match &input.home_dir {
        Some(h) => {
            validate_abs_clean_path(h)?;
            h.clone()
        }
        None => "/root".to_owned(),
    };

    let pytest_tail = extract_pytest_args(&input.argv)?;

    if input.required_pytest_plugins.len() > MAX_PLUGINS {
        return Err(PlanError::TooManyPlugins);
    }
    let mut plugin_set: BTreeSet<String> = BTreeSet::new();
    for p in &input.required_pytest_plugins {
        if p.len() > MAX_PLUGIN_NAME_BYTES {
            return Err(PlanError::PluginNameTooLong);
        }
        if p.as_bytes().contains(&0x00) {
            return Err(PlanError::NulByteInInput);
        }
        if !is_valid_plugin_name(p) {
            return Err(PlanError::InvalidPluginName);
        }
        plugin_set.insert(p.clone());
    }

    // Rewrite command to `python -s -m pytest -p <plugin> ... <original args>`
    let mut rewritten_argv: Vec<String> = vec![
        "python".to_owned(),
        "-s".to_owned(),
        "-m".to_owned(),
        "pytest".to_owned(),
    ];
    for plugin in &plugin_set {
        rewritten_argv.push("-p".to_owned());
        rewritten_argv.push(plugin.clone());
    }
    rewritten_argv.extend(pytest_tail.iter().cloned());

    if input.env_allowlist.len() > MAX_ENV_ENTRIES {
        return Err(PlanError::TooManyEnvEntries);
    }

    let mut env: BTreeMap<String, String> = BTreeMap::new();
    env.insert("HOME".to_owned(), home);
    env.insert("LANG".to_owned(), "C.UTF-8".to_owned());
    env.insert("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned());
    env.insert("PYTEST_DISABLE_PLUGIN_AUTOLOAD".to_owned(), "1".to_owned());
    env.insert("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned());
    env.insert("PYTHONHASHSEED".to_owned(), "0".to_owned());
    env.insert("TZ".to_owned(), "UTC".to_owned());

    let mut seen_custom: BTreeSet<String> = BTreeSet::new();
    for entry in &input.env_allowlist {
        if entry.name.len() > MAX_ENV_NAME_BYTES {
            return Err(PlanError::EnvNameTooLong);
        }
        if entry.value.len() > MAX_ENV_VALUE_BYTES {
            return Err(PlanError::EnvValueTooLong);
        }
        if entry.name.as_bytes().contains(&0x00) || entry.value.as_bytes().contains(&0x00) {
            return Err(PlanError::NulByteInInput);
        }
        if !is_valid_env_name(&entry.name) {
            return Err(PlanError::InvalidEnvName);
        }
        if RESERVED_ENV_KEYS.contains(&entry.name.as_str()) {
            return Err(PlanError::ReservedEnvOverride);
        }
        if !seen_custom.insert(entry.name.clone()) {
            return Err(PlanError::DuplicateEnvName);
        }
        env.insert(entry.name.clone(), entry.value.clone());
    }

    Ok(SandboxPlan {
        argv: rewritten_argv,
        capabilities: build_capabilities(),
        device_cgroup_order_note: "Evaluated top-to-bottom by cgroup v2 device BPF: explicit character device allows (1:3, 1:5, 1:7, 1:8, 1:9, 5:0) precede block device catch-all deny (b *:* rwm) and final default deny (a *:* rwm).".to_owned(),
        device_cgroup_rules: build_device_cgroup_rules(),
        devices: build_devices(),
        env,
        gid: input.gid,
        mounts: build_mounts(&input.working_dir),
        namespaces: NamespaceSpec {
            ipc: true,
            mount: true,
            net: true,
            pid: true,
            rationale: "New PID, mount, IPC, UTS, and empty net namespaces isolate the test process; user namespace is intentionally disabled because the grader VM is already the hardware/hypervisor isolation boundary and enabling unprivileged user namespaces widens the kernel attack surface.".to_owned(),
            user: false,
            uts: true,
        },
        t_clock: input.t_clock,
        uid: input.uid,
        working_dir: input.working_dir.clone(),
    })
}

/// Encodes `SandboxPlan` into canonical deterministic JSON.
pub fn encode_plan(plan: &SandboxPlan) -> Vec<u8> {
    serde_json::to_vec(plan).unwrap_or_else(|_| b"{}".to_vec())
}
