#![forbid(unsafe_code)]
//! Apply the deterministic grader plan before executing any repository code.
use hermetic_grader_sandbox::{plan, EnvEntry, PlanInput, SandboxPlan};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::os::SpawnSpec;

/// Bound on serialized helper input, including JSON escaping.
pub const MAX_LAUNCH_BYTES: usize = 8 * 1024 * 1024;
/// A helper may spend at most this long waiting for its trusted peer.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum difference between the sealed clock and the start of a test run.
pub const MAX_CLOCK_START_SECONDS: i64 = 300;
/// Overlay metadata and artifacts share this bounded private writable layer.
pub const MAX_OVERLAY_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_OVERLAY_INODES: usize = 65_536;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSettings {
    pub t_clock: i64,
    #[serde(default)]
    pub required_pytest_plugins: Vec<String>,
}

pub fn build_plan(spec: &SpawnSpec) -> io::Result<SandboxPlan> {
    if ["/tmp/.hermetic-grader", "/tmp/.hermetic-cgroup"]
        .iter()
        .any(|root| spec.cwd == Path::new(root) || spec.cwd.starts_with(root))
    {
        return Err(invalid());
    }
    let mut plugins = spec.sandbox.required_pytest_plugins.clone();
    plugins.push("hermetic_grader_records.plugin".into());
    // Fixed variables may be supplied by older configs, but only with the exact
    // planned value. No loader or interpreter settings can enter the allow-list.
    let mut base = plan(&PlanInput {
        argv: spec.argv.clone(),
        working_dir: spec.cwd.to_str().ok_or_else(invalid)?.into(),
        home_dir: None,
        uid: 0,
        gid: 0,
        env_allowlist: Vec::new(),
        t_clock: spec.sandbox.t_clock,
        required_pytest_plugins: plugins,
    })
    .map_err(|_| invalid())?;
    base.env.insert("HERMETIC_RESULT_FD".into(), "3".into());
    let mut allowlist = Vec::new();
    for (name, value) in &spec.env {
        if let Some(fixed) = base.env.get(name) {
            if fixed != value {
                return Err(invalid());
            }
        } else {
            allowlist.push(EnvEntry {
                name: name.clone(),
                value: value.clone(),
            });
        }
    }
    allowlist.push(EnvEntry {
        name: "HERMETIC_RESULT_FD".into(),
        value: "3".into(),
    });
    let result = plan(&PlanInput {
        argv: spec.argv.clone(),
        working_dir: base.working_dir.clone(),
        home_dir: None,
        uid: 0,
        gid: 0,
        env_allowlist: allowlist,
        t_clock: base.t_clock,
        required_pytest_plugins: spec
            .sandbox
            .required_pytest_plugins
            .iter()
            .cloned()
            .chain(["hermetic_grader_records.plugin".into()])
            .collect(),
    })
    .map_err(|_| invalid())?;
    Ok(result)
}

pub(crate) fn invalid() -> io::Error {
    io::Error::other("sandbox setup failed")
}

/// Each effect carries the actual plan, so an offline implementation can assert
/// every applied value and inject failures before repository code is reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Namespaces,
    Clock,
    PrivateMounts,
    DeviceCgroup,
    Root,
    Mounts,
    Devices,
    Identity,
    Capabilities,
    RecordFd,
    Exec,
}
pub trait SandboxOs {
    fn apply(&mut self, stage: Stage, plan: &SandboxPlan) -> io::Result<()>;
}
pub fn create_namespaces<O: SandboxOs>(os: &mut O, plan: &SandboxPlan) -> io::Result<()> {
    os.apply(Stage::Namespaces, plan)
}
pub fn apply_plan<O: SandboxOs>(os: &mut O, plan: &SandboxPlan) -> io::Result<()> {
    for stage in [
        Stage::Clock,
        Stage::PrivateMounts,
        Stage::DeviceCgroup,
        Stage::Root,
        Stage::Mounts,
        Stage::Devices,
        Stage::Identity,
        Stage::Capabilities,
        Stage::RecordFd,
        Stage::Exec,
    ] {
        os.apply(stage, plan)?;
    }
    Err(invalid()) // Successful exec never returns.
}

pub(crate) fn write_spec(mut writer: impl Write, spec: &SpawnSpec) -> io::Result<()> {
    let bytes = serde_json::to_vec(spec).map_err(|_| invalid())?;
    if bytes.len() > MAX_LAUNCH_BYTES {
        return Err(invalid());
    }
    writer.write_all(
        &u32::try_from(bytes.len())
            .map_err(|_| invalid())?
            .to_le_bytes(),
    )?;
    writer.write_all(&bytes)
}
fn read_spec(mut reader: impl Read) -> io::Result<SpawnSpec> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len)).map_err(|_| invalid())?;
    if len > MAX_LAUNCH_BYTES {
        return Err(invalid());
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    let spec: SpawnSpec = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    build_plan(&spec)?; // validate all input before any filesystem effects
    Ok(spec)
}

/// Only called at binary entry, before creating threads. NEWPID applies to the
/// next child; std::process owns fork/exec, including its async-signal-safe hook.
pub fn helper(init: bool) -> io::Result<()> {
    crate::sys::close_inherited()?;
    rustix::process::umask(rustix::fs::Mode::empty());
    let spec = read_spec(io::stdin().lock())?;
    if init {
        if rustix::process::getpid().as_raw_pid() != 1 {
            return Err(invalid());
        }
        let plan = build_plan(&spec)?;
        return apply_plan(&mut LinuxSandbox::new()?, &plan);
    }
    create_namespaces(&mut LinuxSandbox::new()?, &build_plan(&spec)?)?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--sandbox-init")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .spawn()?;
    // The init blocks on its input until the supervisor pins a pidfd. Thus its
    // PID cannot be recycled between transmission and pidfd_open.
    let handshake = (|| {
        let mut socket = std::fs::File::from(rustix::io::dup(io::stdin())?);
        socket.write_all(&child.id().to_le_bytes())?;
        let mut ack = [0];
        socket.read_exact(&mut ack)?;
        if ack != [1] {
            return Err(invalid());
        }
        write_spec(child.stdin.take().ok_or_else(invalid)?, &spec)
    })();
    if handshake.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    crate::sys::cleanup_cgroup(child.id())?;
    handshake?;
    if status.code().is_some() {
        Ok(())
    } else {
        Err(invalid())
    }
}

// Resolve every component relative to a pinned directory, lstat before open,
// reject links/special files, and compare the opened inode against the lstat.
pub(crate) fn open_path(
    path: &Path,
    flags: rustix::fs::OFlags,
    kind: rustix::fs::FileType,
) -> io::Result<OwnedFd> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    if path.as_os_str().len() > crate::run::MAX_CWD_BYTES {
        return Err(invalid());
    }
    let components: Vec<_> = path.components().collect();
    if components.len() > crate::run::MAX_CWD_BYTES
        || components.iter().any(|p| {
            !matches!(
                p,
                std::path::Component::Normal(_)
                    | std::path::Component::RootDir
                    | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid());
    }
    let mut dir = fs::open(
        if path.is_absolute() { "/" } else { "." },
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut parts = components.iter().filter(|p| {
        !matches!(
            p,
            std::path::Component::RootDir | std::path::Component::CurDir
        )
    });
    while let Some(component) = parts.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(invalid());
        };
        let last = parts.clone().next().is_none();
        let expected = if last { kind } else { FileType::Directory };
        let next = open_at(
            &dir,
            *name,
            if last {
                flags
            } else {
                OFlags::PATH | OFlags::DIRECTORY
            },
            expected,
        )?;
        dir = next;
    }
    if components.iter().all(|p| {
        matches!(
            p,
            std::path::Component::RootDir | std::path::Component::CurDir
        )
    }) {
        dir = reopen_pin(&dir, flags)?;
    }
    if fs::FileType::from_raw_mode(fs::fstat(&dir)?.st_mode) != kind {
        return Err(invalid());
    }
    Ok(dir)
}
/// Pin and type-check without invoking a device's open method or waiting for
/// a FIFO peer. Reopen only the verified object, never the mutable path again.
pub(crate) fn open_at(
    parent: &OwnedFd,
    name: impl rustix::path::Arg,
    flags: rustix::fs::OFlags,
    kind: rustix::fs::FileType,
) -> io::Result<OwnedFd> {
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    // path::Arg is consumed by rustix, so keep one validated name for both calls.
    let name = name.into_c_str()?;
    let name = name.as_ref();
    {
        let before = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if fs::FileType::from_raw_mode(before.st_mode) != kind {
            return Err(invalid());
        }
        let pinned = fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let after = fs::fstat(&pinned)?;
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            || fs::FileType::from_raw_mode(after.st_mode) != kind
        {
            return Err(invalid());
        }
        reopen_pin(&pinned, flags)
    }
}
pub(crate) fn reopen_pin(pin: &OwnedFd, flags: rustix::fs::OFlags) -> io::Result<OwnedFd> {
    use rustix::fs::{self, Mode, OFlags};
    if flags.contains(OFlags::PATH) {
        return Ok(rustix::io::fcntl_dupfd_cloexec(pin, 3)?);
    }
    let before = fs::fstat(pin)?;
    // This intentional proc magic link resolves the held inode, including after
    // rename/unlink. It contains only a scalar fd generated by this process.
    let reopened = fs::open(
        fd_path(pin),
        flags | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let after = fs::fstat(&reopened)?;
    if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode)
    {
        return Err(invalid());
    }
    Ok(reopened)
}
fn fd_path(fd: &impl AsRawFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}
fn directory(path: impl AsRef<Path>) -> io::Result<OwnedFd> {
    open_path(
        path.as_ref(),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::FileType::Directory,
    )
}
fn mkdir(parent: &OwnedFd, name: &str, mode: u32) -> io::Result<OwnedFd> {
    use rustix::fs::{self, Mode, OFlags};
    fs::mkdirat(parent, name, Mode::from_raw_mode(mode))?;
    open_at(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY,
        fs::FileType::Directory,
    )
}
fn mount_at(
    source: &str,
    target: &OwnedFd,
    typ: &str,
    flags: rustix::mount::MountFlags,
    options: Option<&str>,
) -> io::Result<()> {
    let options = options
        .map(std::ffi::CString::new)
        .transpose()
        .map_err(|_| invalid())?;
    Ok(rustix::mount::mount(
        source,
        fd_path(target),
        typ,
        flags,
        options.as_deref(),
    )?)
}

struct LinuxSandbox {
    root: Option<OwnedFd>,
    scratch: Option<OwnedFd>,
    cgroup: Option<crate::sys::DeviceCgroup>,
}
impl LinuxSandbox {
    fn new() -> io::Result<Self> {
        Ok(Self {
            root: None,
            scratch: None,
            cgroup: None,
        })
    }
    fn target(&self, destination: &str) -> io::Result<OwnedFd> {
        let root = self.root.as_ref().ok_or_else(invalid)?;
        // Paths are validated by the planner; walk from the new root without
        // dereferencing a proc magic link or following repository symlinks.
        let mut fd = rustix::io::dup(root)?;
        for part in destination.split('/').filter(|p| !p.is_empty()) {
            let next = open_at(
                &fd,
                part,
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::FileType::Directory,
            )?;
            fd = next;
        }
        Ok(fd)
    }
}
impl SandboxOs for LinuxSandbox {
    fn apply(&mut self, stage: Stage, plan: &SandboxPlan) -> io::Result<()> {
        use rustix::fs::{self, Mode};
        use rustix::mount::{self, MountFlags as M};
        match stage {
            Stage::Namespaces => {
                crate::sys::unshare(&plan.namespaces)?;
            }
            Stage::Clock => {
                let now = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
                if now < plan.t_clock || now > plan.t_clock.saturating_add(MAX_CLOCK_START_SECONDS)
                {
                    return Err(invalid());
                }
            }
            Stage::PrivateMounts => {
                mount::mount_change(
                    "/",
                    mount::MountPropagationFlags::PRIVATE | mount::MountPropagationFlags::REC,
                )?;
            }
            Stage::DeviceCgroup => {
                self.cgroup = crate::sys::device_cgroup(&plan.device_cgroup_rules)?;
            }
            Stage::Root => {
                let tmp = directory("/tmp")?;
                let scratch = mkdir(&tmp, ".hermetic-grader", 0o700)?;
                // A separate bounded overlay store is hidden from the test's /tmp.
                mount_at(
                    "tmpfs",
                    &scratch,
                    "tmpfs",
                    M::NOSUID | M::NODEV,
                    Some(&format!(
                        "mode=700,size={MAX_OVERLAY_BYTES},nr_inodes={MAX_OVERLAY_INODES}"
                    )),
                )?;
                let scratch = directory("/tmp/.hermetic-grader")?;
                let root = mkdir(&scratch, "root", 0o755)?;
                // Non-recursive root bind excludes every inherited device,
                // proc, sysfs, cgroup and host bind mount.
                mount::mount_bind("/", fd_path(&root))?;
                let root = directory("/tmp/.hermetic-grader/root")?;
                mount::mount_remount(fd_path(&root), M::BIND | M::RDONLY | M::NOSUID, "")?;
                self.root = Some(root);
                self.scratch = Some(scratch);
            }
            Stage::Mounts => {
                for m in plan.mounts.iter().filter(|m| m.destination != "/") {
                    let target = self.target(&m.destination)?;
                    if m.fs_type == "bind" {
                        if m.destination == plan.working_dir {
                            let scratch = self.scratch.as_ref().ok_or_else(invalid)?;
                            let upper = mkdir(scratch, "upper", 0o755)?;
                            let work = mkdir(scratch, "work", 0o700)?;
                            let lower = directory(&plan.working_dir)?;
                            let options = format!(
                                "lowerdir={},upperdir={},workdir={}",
                                fd_path(&lower),
                                fd_path(&upper),
                                fd_path(&work)
                            );
                            mount_at("overlay", &target, "overlay", M::NOSUID, Some(&options))?;
                        } else {
                            let source = directory(&m.source)?;
                            mount::mount_bind(fd_path(&source), fd_path(&target))?;
                            let rebound = self.target(&m.destination)?;
                            mount::mount_remount(fd_path(&rebound), M::BIND | M::NOSUID, "")?;
                        }
                    } else {
                        let mut flags = M::empty();
                        if m.read_only {
                            flags |= M::RDONLY;
                        }
                        for opt in &m.options {
                            match opt.as_str() {
                                "nosuid" => flags |= M::NOSUID,
                                "nodev" => flags |= M::NODEV,
                                "noexec" => flags |= M::NOEXEC,
                                _ => {}
                            }
                        }
                        let data: Vec<_> = m
                            .options
                            .iter()
                            .filter(|o| !matches!(o.as_str(), "ro" | "nosuid" | "nodev" | "noexec"))
                            .cloned()
                            .collect();
                        mount_at(&m.source, &target, &m.fs_type, flags, Some(&data.join(",")))?;
                    }
                    if m.destination == "/dev" {
                        let dev = self.target("/dev")?;
                        mkdir(&dev, "pts", 0o755)?;
                        mkdir(&dev, "shm", 0o1777)?;
                    }
                }
                // Keep overlay internals out of the writable /tmp view.
                let hidden = self.target("/tmp/.hermetic-grader")?;
                mount_at(
                    "tmpfs",
                    &hidden,
                    "tmpfs",
                    M::RDONLY | M::NOSUID | M::NODEV | M::NOEXEC,
                    Some("size=4096,nr_inodes=1,mode=000"),
                )?;
            }
            Stage::Devices => {
                let dev = self.target("/dev")?;
                for node in &plan.devices {
                    let name = node.path.strip_prefix("/dev/").ok_or_else(invalid)?;
                    let mode = u32::from_str_radix(&node.mode, 8).map_err(|_| invalid())?;
                    fs::mknodat(
                        &dev,
                        name,
                        fs::FileType::CharacterDevice,
                        Mode::from_raw_mode(mode),
                        fs::makedev(node.major, node.minor),
                    )?;
                }
                for link in &plan.device_symlinks {
                    fs::symlinkat(
                        &link.target,
                        &dev,
                        link.path.strip_prefix("/dev/").ok_or_else(invalid)?,
                    )?;
                }
            }
            Stage::Identity => {
                rustix::system::sethostname(plan.hostname.as_bytes())?;
                rustix::system::setdomainname(plan.domainname.as_bytes())?;
                let cwd = self.target(&plan.working_dir)?;
                rustix::process::fchdir(self.root.as_ref().ok_or_else(invalid)?)?;
                rustix::process::chroot(".")?;
                rustix::process::fchdir(&cwd)?;
                self.root = None;
                self.scratch = None;
                self.cgroup = None;
                rustix::thread::set_thread_groups(&[])?;
                rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(plan.gid))?;
                rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(plan.uid))?;
            }
            Stage::Capabilities => {
                crate::sys::capabilities(&plan.capabilities)?;
            }
            Stage::RecordFd => {
                let record = rustix::io::fcntl_dupfd_cloexec(io::stdout(), 4)?;
                // All other descriptors are CLOEXEC. Reserve exactly fd 3 so the
                // environment equals the plan, independently of parent fd layout.
                crate::sys::record_fd(&record)?;
                let null = open_path(
                    Path::new("/dev/null"),
                    fs::OFlags::RDWR,
                    fs::FileType::CharacterDevice,
                )?;
                rustix::stdio::dup2_stdin(&null)?;
                rustix::stdio::dup2_stdout(&null)?;
                rustix::stdio::dup2_stderr(&null)?;
            }
            Stage::Exec => {
                let (program, args) = plan.argv.split_first().ok_or_else(invalid)?;
                let error = Command::new(program)
                    .args(args)
                    .env_clear()
                    .envs(&plan.env)
                    .exec();
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_reopen_survives_a_fifo_replacing_the_original_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config");
        std::fs::write(&path, b"original").unwrap();
        let pin = open_path(
            &path,
            rustix::fs::OFlags::PATH,
            rustix::fs::FileType::RegularFile,
        )
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        rustix::fs::mkfifoat(rustix::fs::CWD, &path, rustix::fs::Mode::RUSR).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let fd = reopen_pin(&pin, rustix::fs::OFlags::RDONLY).unwrap();
            let mut bytes = Vec::new();
            std::fs::File::from(fd)
                .take(16)
                .read_to_end(&mut bytes)
                .unwrap();
            let _ = tx.send(bytes);
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("must reopen the pin, not the FIFO"),
            b"original"
        );
    }
}
