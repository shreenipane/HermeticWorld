#![allow(unsafe_code)]
//! Small syscall boundary. All namespace operations run only in a freshly exec'd,
//! single-threaded helper. The supervisor and record parsers contain no unsafe.
use hermetic_grader_sandbox::{CapabilitySets, DeviceCgroupRule, NamespaceSpec};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn checked(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}
pub(crate) fn unshare(ns: &NamespaceSpec) -> io::Result<()> {
    use rustix::thread::UnshareFlags as U;
    if !ns.pid || !ns.mount || !ns.ipc || !ns.uts || !ns.net || ns.user {
        return Err(super::sandbox::invalid());
    }
    // SAFETY: the helper has just been exec'd and has no other threads. FILES
    // is excluded; no descriptor table can diverge from another Rust thread.
    unsafe {
        rustix::thread::unshare_unsafe(U::NEWPID | U::NEWNS | U::NEWIPC | U::NEWUTS | U::NEWNET)?;
    }
    Ok(())
}
pub(crate) fn close_inherited() -> io::Result<()> {
    // SAFETY: CLOEXEC changes no live ownership and closes nothing until exec.
    // The helper deliberately exports only the record descriptor at exec.
    checked(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    })?;
    Ok(())
}
pub(crate) fn record_fd(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fd is live, at least 3, and never equals the target. fd 3 belongs
    // to a CLOEXEC helper handle that is no longer used after RecordFd.
    if fd.as_raw_fd() == 3 {
        return Err(super::sandbox::invalid());
    }
    checked(unsafe { libc::dup3(fd.as_raw_fd(), 3, 0) } as _)?;
    Ok(())
}

pub(crate) fn capabilities(plan: &CapabilitySets) -> io::Result<()> {
    use rustix::thread::{self, CapabilitySet as C};
    let parse = |names: &[String]| -> io::Result<C> {
        names.iter().try_fold(C::empty(), |set, name| {
            let short = name
                .strip_prefix("CAP_")
                .ok_or_else(super::sandbox::invalid)?;
            Ok(set | C::from_name(short).ok_or_else(super::sandbox::invalid)?)
        })
    };
    if !plan.inheritable.is_empty() || !plan.ambient.is_empty() || !plan.no_new_privileges {
        return Err(super::sandbox::invalid());
    }
    let bounding = parse(&plan.bounding)?;
    thread::clear_ambient_capability_set()?;
    // Linux capability ABI is 64 bits. Probe every bit, including capabilities
    // newer than this userspace's names, and fail closed on any other error.
    for bit in 0..u64::BITS {
        let cap = C::from_bits_retain(1u64.checked_shl(bit).ok_or_else(super::sandbox::invalid)?);
        match thread::capability_is_in_bounding_set(cap) {
            Ok(present) => {
                if bounding.contains(cap) {
                    if !present {
                        return Err(super::sandbox::invalid());
                    }
                } else if present {
                    thread::remove_capability_from_bounding_set(cap)?;
                }
            }
            Err(rustix::io::Errno::INVAL) if !bounding.contains(cap) => {}
            Err(e) => return Err(e.into()),
        }
    }
    thread::set_capabilities(
        None,
        thread::CapabilitySets {
            effective: parse(&plan.effective)?,
            permitted: parse(&plan.permitted)?,
            inheritable: C::empty(),
        },
    )?;
    thread::set_no_new_privs(true)?;
    Ok(())
}

/// Maximum generated eBPF instructions and rules (kernel verifier input cap).
pub const MAX_DEVICE_INSTRUCTIONS: usize = 256;
pub const MAX_DEVICE_RULES: usize = 16;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}
fn ins(code: u8, regs: u8, off: i16, imm: i32) -> Instruction {
    Instruction {
        code,
        regs,
        off,
        imm,
    }
}

/// Compile ordered, first-match device rules. Unmatched requests always deny.
pub fn device_program(rules: &[DeviceCgroupRule]) -> io::Result<Vec<Instruction>> {
    if rules.len() > MAX_DEVICE_RULES {
        return Err(super::sandbox::invalid());
    }
    let mut out = Vec::new();
    for rule in rules {
        let mut checks = Vec::new();
        let device_type = match rule.dev_type.as_str() {
            "c" => Some(2),
            "b" => Some(1),
            "a" => None,
            _ => return Err(super::sandbox::invalid()),
        };
        if let Some(typ) = device_type {
            checks.extend([
                ins(0x61, 0x12, 0, 0),
                ins(0x57, 2, 0, 0xffff),
                ins(0x55, 2, 0, typ),
            ]);
        }
        for (offset, value) in [(4, rule.major), (8, rule.minor)] {
            if let Some(value) = value {
                checks.extend([
                    ins(0x61, 0x12, offset, 0),
                    ins(0x55, 2, 0, i32::from_ne_bytes(value.to_ne_bytes())),
                ]);
            }
        }
        let mut access = 0;
        for b in rule.access.bytes() {
            access |= match b {
                b'm' => 1,
                b'r' => 2,
                b'w' => 4,
                _ => return Err(super::sandbox::invalid()),
            };
        }
        // Match only when every requested access bit is allowed by the rule.
        checks.extend([
            ins(0x61, 0x12, 0, 0),
            ins(0x77, 2, 0, 16),
            ins(0x57, 2, 0, !access),
            ins(0x55, 2, 0, 0),
        ]);
        let length = checks.len();
        for (idx, instruction) in checks.iter_mut().enumerate() {
            if instruction.code == 0x55 {
                instruction.off = i16::try_from(length.saturating_sub(idx).saturating_add(1))
                    .map_err(|_| super::sandbox::invalid())?;
            }
        }
        out.extend(checks);
        out.extend([ins(0xb7, 0, 0, i32::from(rule.allow)), ins(0x95, 0, 0, 0)]);
        if out.len() > MAX_DEVICE_INSTRUCTIONS.saturating_sub(2) {
            return Err(super::sandbox::invalid());
        }
    }
    out.extend([ins(0xb7, 0, 0, 0), ins(0x95, 0, 0, 0)]);
    Ok(out)
}
#[repr(C)]
#[derive(Default)]
struct Load {
    typ: u32,
    count: u32,
    instructions: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buffer: u64,
    version: u32,
    flags: u32,
    name: [u8; 16],
    ifindex: u32,
    attach_type: u32,
}
#[repr(C)]
struct Attach {
    target: u32,
    program: u32,
    typ: u32,
    flags: u32,
    replace: u32,
}
fn attach_device_program(cgroup: &OwnedFd, instructions: &[Instruction]) -> io::Result<()> {
    if instructions.len() > MAX_DEVICE_INSTRUCTIONS {
        return Err(super::sandbox::invalid());
    }
    let load = Load {
        typ: 15,
        count: u32::try_from(instructions.len()).map_err(|_| super::sandbox::invalid())?,
        instructions: instructions.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        attach_type: 6,
        ..Load::default()
    };
    // SAFETY: repr(C) matches the Linux bpf_attr prefix; all fields and padding
    // are initialized, pointers remain valid for the synchronous syscall. No
    // verifier log is requested, so no kernel/environment details enter output.
    let raw =
        checked(unsafe { libc::syscall(libc::SYS_bpf, 5, &load, std::mem::size_of::<Load>()) })?;
    let raw = i32::try_from(raw).map_err(|_| super::sandbox::invalid())?;
    // SAFETY: successful BPF_PROG_LOAD returns a fresh owned descriptor.
    let program = unsafe { OwnedFd::from_raw_fd(raw) };
    let attach = Attach {
        target: cgroup.as_raw_fd() as u32,
        program: program.as_raw_fd() as u32,
        typ: 6,
        flags: 0,
        replace: 0,
    };
    // SAFETY: initialized repr(C) scalar-only attribute, with both fds alive.
    checked(unsafe { libc::syscall(libc::SYS_bpf, 8, &attach, std::mem::size_of::<Attach>()) })?;
    Ok(())
}
pub(crate) struct DeviceCgroup {
    _directory: OwnedFd,
}
pub(crate) fn device_cgroup(rules: &[DeviceCgroupRule]) -> io::Result<Option<DeviceCgroup>> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    let instructions = device_program(rules)?;
    let tmp = super::sandbox::open_path(
        std::path::Path::new("/tmp"),
        OFlags::PATH | OFlags::DIRECTORY,
        FileType::Directory,
    )?;
    fs::mkdirat(&tmp, ".hermetic-cgroup", Mode::from_raw_mode(0o700))?;
    let mountpoint = "/tmp/.hermetic-cgroup";
    let target = super::sandbox::open_path(
        std::path::Path::new(mountpoint),
        OFlags::PATH | OFlags::DIRECTORY,
        FileType::Directory,
    )?;
    match rustix::mount::mount(
        "cgroup2",
        format!("/proc/self/fd/{}", target.as_raw_fd()),
        "cgroup2",
        rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOEXEC,
        None::<&std::ffi::CStr>,
    ) {
        Ok(()) => {}
        // Only a kernel with no cgroup v2 support may omit this defense. An
        // unavailable controller, lack of permission, or BPF error fails closed.
        Err(rustix::io::Errno::NODEV) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let root = super::sandbox::open_path(
        std::path::Path::new(mountpoint),
        OFlags::PATH | OFlags::DIRECTORY,
        FileType::Directory,
    )?;
    // The early proc mount belongs to the outer PID namespace. Its self link
    // supplies the same numeric PID used by the trusted launcher for cleanup.
    const MAX_PID_LINK_BYTES: usize = 32;
    let mut pid = [0; MAX_PID_LINK_BYTES];
    let count = fs::readlinkat_raw(fs::CWD, "/proc/self", &mut pid)?;
    let bytes = pid.get(..count).ok_or_else(super::sandbox::invalid)?;
    if bytes.is_empty()
        || bytes.len() >= MAX_PID_LINK_BYTES
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(super::sandbox::invalid());
    }
    let name = format!(
        "grader-{}",
        std::str::from_utf8(bytes).map_err(|_| super::sandbox::invalid())?
    );
    fs::mkdirat(&root, &name, Mode::from_raw_mode(0o700))?;
    let group = super::sandbox::open_at(
        &root,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY,
        FileType::Directory,
    )?;
    attach_device_program(&group, &instructions)?;
    let procs = super::sandbox::open_at(
        &group,
        "cgroup.procs",
        OFlags::WRONLY,
        FileType::RegularFile,
    )?;
    let bytes = b"0\n";
    if rustix::io::write(&procs, bytes)? != bytes.len() {
        return Err(super::sandbox::invalid());
    }
    Ok(Some(DeviceCgroup { _directory: group }))
}

pub(crate) fn cleanup_cgroup(pid: u32) -> io::Result<()> {
    use rustix::fs::{self, AtFlags, FileType, OFlags};
    let root = match super::sandbox::open_path(
        std::path::Path::new("/tmp/.hermetic-cgroup"),
        OFlags::PATH | OFlags::DIRECTORY,
        FileType::Directory,
    ) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    match fs::unlinkat(&root, format!("grader-{pid}"), AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_descriptor_survives_exec_without_stdio_or_extra_fds() {
        if std::env::var_os("HERMETIC_FD_WORKER").is_some() {
            let extra = rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 100).unwrap();
            rustix::io::fcntl_setfd(&extra, rustix::io::FdFlags::empty()).unwrap();
            close_inherited().unwrap();
            let record = rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 4).unwrap();
            record_fd(&record).unwrap();
            let null = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap();
            rustix::stdio::dup2_stdin(&null).unwrap();
            rustix::stdio::dup2_stdout(&null).unwrap();
            rustix::stdio::dup2_stderr(&null).unwrap();
            use std::os::unix::process::CommandExt;
            let error = std::process::Command::new("/bin/sh")
                .args([
                    "-c",
                    "printf HGR1 >&3; printf noise; printf noise >&2; test ! -e /proc/self/fd/100",
                ])
                .env_clear()
                .exec();
            panic!("exec failed: {error}");
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sys::tests::record_descriptor_survives_exec_without_stdio_or_extra_fds",
                "--nocapture",
                "--quiet",
            ])
            .env("HERMETIC_FD_WORKER", "1")
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(result.stdout.ends_with(b"HGR1"));
        assert!(!result.stdout.windows(5).any(|v| v == b"noise"));
        assert!(result.stderr.is_empty());
    }
}
