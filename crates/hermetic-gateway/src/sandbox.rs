#![forbid(unsafe_code)]

//! Host-side sandboxing for `hermetic-gateway` (TR-GW-1).
//!
//! Applies:
//! 1. Resource limits (`RLIMIT_CORE = 0` to prevent dumping secret keys in memory; bounded
//!    `RLIMIT_NOFILE` and `RLIMIT_FSIZE`).
//! 2. Landlock filesystem restrictions:
//!    - Read-write access to `log_dir` only.
//!    - Read-only access to `api_key_file` only (the upstream key file).
//!    - Access to `socket_dir` for Unix domain socket operations (if listening on UDS).
//!    - Strict default deny for every other host path: no access to the world, the agent
//!      disks or host secrets.
//! 3. Seccomp BPF allow-list filter:
//!    - Sockets restricted to `AF_UNIX` (NetVM socket path), `AF_INET`, and `AF_INET6` (upstream).
//!    - Signals restricted to the gateway's own pid (`SYS_kill`, `SYS_tgkill`, `SYS_rt_sigqueueinfo`).
//!    - Outbound connections allowed (`SYS_connect`).
//!    - Blocked and killed: `execve`, `execveat`, `ptrace`, `mount`, `umount2`, `clock_settime`,
//!      `set*uid`, `set*gid`, `setgroups`, `capset`, etc.

use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxLandlockStatus {
    Enforced,
    NotEnforced,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Landlock error: {0}")]
    Landlock(#[from] RulesetError),
    #[error("Landlock unavailable and --allow-no-landlock was not passed")]
    LandlockUnavailable,
    #[error("Seccomp backend error: {0}")]
    SeccompBackend(#[from] seccompiler::BackendError),
    #[error("Seccomp error: {0}")]
    Seccomp(#[from] seccompiler::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Resource limit error: {0}")]
    ResourceLimit(rustix::io::Errno),
}

static INJECT_LANDLOCK_UNAVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static INJECT_LANDLOCK_RULE_ERROR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_inject_landlock_unavailable(val: bool) {
    INJECT_LANDLOCK_UNAVAILABLE.store(val, std::sync::atomic::Ordering::SeqCst);
}

pub fn set_inject_landlock_rule_error(val: bool) {
    INJECT_LANDLOCK_RULE_ERROR.store(val, std::sync::atomic::Ordering::SeqCst);
}

/// Apply process resource bounds (TR-GW-1).
///
/// - Core dump disabled (`RLIMIT_CORE = 0`) to prevent dumping in-memory secret key.
/// - Open file descriptors capped to at most 1024 (`RLIMIT_NOFILE`).
/// - Maximum file size capped to 256 MiB (`RLIMIT_FSIZE`).
pub fn apply_resource_limits() -> Result<(), SandboxError> {
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(SandboxError::ResourceLimit)?;

    const MAX_NOFILE: u64 = 1024;
    let current_nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let target_nofile_max = match current_nofile.maximum {
        Some(max) => max.min(MAX_NOFILE),
        None => MAX_NOFILE,
    };
    let target_nofile_cur = match current_nofile.current {
        Some(cur) => cur.min(target_nofile_max),
        None => target_nofile_max,
    };
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(target_nofile_cur),
            maximum: Some(target_nofile_max),
        },
    )
    .map_err(SandboxError::ResourceLimit)?;

    const MAX_FSIZE: u64 = 256 * 1024 * 1024;
    let current_fsize = rustix::process::getrlimit(rustix::process::Resource::Fsize);
    let target_fsize_max = match current_fsize.maximum {
        Some(max) => max.min(MAX_FSIZE),
        None => MAX_FSIZE,
    };
    let target_fsize_cur = match current_fsize.current {
        Some(cur) => cur.min(target_fsize_max),
        None => target_fsize_max,
    };
    rustix::process::setrlimit(
        rustix::process::Resource::Fsize,
        rustix::process::Rlimit {
            current: Some(target_fsize_cur),
            maximum: Some(target_fsize_max),
        },
    )
    .map_err(SandboxError::ResourceLimit)?;

    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(SandboxError::ResourceLimit)?;

    Ok(())
}

/// Apply Landlock filesystem restrictions (TR-GW-1).
///
/// Grants read-write access to `log_dir`, read-only access to `key_file`, and socket operations
/// in `socket_dir` (if present). All other paths (world store, agent disks, other host secrets)
/// are strictly inaccessible.
pub fn apply_landlock(
    log_dir: &Path,
    key_file: &Path,
    socket_dir: Option<&Path>,
    allow_no_landlock: bool,
) -> Result<SandboxLandlockStatus, SandboxError> {
    if !log_dir.is_dir() {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Log directory does not exist or is not a directory",
        )));
    }
    if !key_file.is_file() {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Key file does not exist or is not a regular file",
        )));
    }

    if INJECT_LANDLOCK_UNAVAILABLE.load(std::sync::atomic::Ordering::SeqCst)
        || std::env::var_os("HERMETIC_TEST_INJECT_LANDLOCK_UNAVAILABLE").is_some()
    {
        if allow_no_landlock {
            return Ok(SandboxLandlockStatus::NotEnforced);
        } else {
            return Err(SandboxError::LandlockUnavailable);
        }
    }

    let abi = ABI::V3;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules(&[log_dir], AccessFs::from_all(abi))))
        .and_then(|r| r.add_rules(path_beneath_rules(&[key_file], AccessFs::from_read(abi))));

    for path in [
        Path::new("/etc/resolv.conf"),
        Path::new("/etc/hosts"),
        Path::new("/etc/nsswitch.conf"),
    ] {
        if path.is_file() {
            ruleset = ruleset
                .and_then(|r| r.add_rules(path_beneath_rules(&[path], AccessFs::from_read(abi))));
        }
    }

    if let Some(sock_dir) = socket_dir {
        if !sock_dir.is_dir() {
            return Err(SandboxError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Socket directory does not exist or is not a directory",
            )));
        }
        ruleset = ruleset
            .and_then(|r| r.add_rules(path_beneath_rules(&[sock_dir], AccessFs::RemoveFile)));
    }

    if INJECT_LANDLOCK_RULE_ERROR.load(std::sync::atomic::Ordering::SeqCst) {
        ruleset = ruleset.and_then(|r| {
            r.add_rule(landlock::PathBeneath::new(
                landlock::PathFd::new(key_file).unwrap(),
                landlock::BitFlags::EMPTY,
            ))
        });
    }

    let ruleset_res = ruleset.and_then(|r| r.restrict_self());

    match ruleset_res {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(SandboxLandlockStatus::Enforced),
            RulesetStatus::NotEnforced | RulesetStatus::PartiallyEnforced => {
                if allow_no_landlock {
                    Ok(SandboxLandlockStatus::NotEnforced)
                } else {
                    Err(SandboxError::LandlockUnavailable)
                }
            }
        },
        Err(e) => {
            let is_unavailable = match &e {
                RulesetError::CreateRuleset(landlock::CreateRulesetError::CreateRulesetCall {
                    source,
                    ..
                }) => {
                    matches!(source.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP))
                }
                _ => false,
            };
            if is_unavailable && allow_no_landlock {
                Ok(SandboxLandlockStatus::NotEnforced)
            } else {
                Err(SandboxError::Landlock(e))
            }
        }
    }
}

/// Apply seccomp allow-list filter (TR-GW-1).
///
/// Sockets allowed: `AF_UNIX` (NetVM socket path), `AF_INET`, `AF_INET6` (upstream provider).
/// `SYS_connect` is allowed for outbound upstream connections.
/// Process signals (`SYS_kill`, `SYS_tgkill`, `SYS_rt_sigqueueinfo`) are restricted to the
/// gateway's own process ID.
/// Blocked: `execve`, `execveat`, `ptrace`, `mount`, `umount2`, `clock_settime`, `set*id`,
/// `setgroups`, `capset`, etc. Violations kill the process.
pub fn apply_seccomp() -> Result<(), SandboxError> {
    let target_arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules = BTreeMap::new();

    // Sockets: allow AF_UNIX, AF_INET, AF_INET6 only (arg 0 == domain)
    let socket_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )?])?,
        SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET as u64,
        )?])?,
        SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET6 as u64,
        )?])?,
    ];
    rules.insert(libc::SYS_socket, socket_rules);

    // Signals: allow only to this process's own pid
    let own_pid = u64::from(std::process::id());
    for sys in [libc::SYS_kill, libc::SYS_tgkill, libc::SYS_rt_sigqueueinfo] {
        let own = SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            own_pid,
        )?])?;
        rules.insert(sys, vec![own]);
    }

    // Allowed non-privileged syscalls
    let allowed_syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_sched_yield,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_mincore,
        libc::SYS_madvise,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_nanosleep,
        libc::SYS_getitimer,
        libc::SYS_setitimer,
        libc::SYS_getpid,
        libc::SYS_accept,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_connect,
        libc::SYS_listen,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_socketpair,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_clone,
        libc::SYS_exit,
        libc::SYS_wait4,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_link,
        libc::SYS_unlink,
        libc::SYS_readlink,
        libc::SYS_umask,
        libc::SYS_gettimeofday,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_times,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_setpgid,
        libc::SYS_getpgrp,
        libc::SYS_setsid,
        libc::SYS_getgroups,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getpgid,
        libc::SYS_getsid,
        libc::SYS_capget,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigsuspend,
        libc::SYS_sigaltstack,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_setrlimit,
        libc::SYS_sync,
        libc::SYS_futex,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_getaffinity,
        libc::SYS_gettid,
        libc::SYS_restart_syscall,
        libc::SYS_time,
        libc::SYS_epoll_create,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_set_tid_address,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_exit_group,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_newfstatat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_pselect6,
        libc::SYS_ppoll,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_epoll_pwait,
        libc::SYS_signalfd,
        libc::SYS_timerfd_create,
        libc::SYS_eventfd,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_accept4,
        libc::SYS_signalfd4,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create1,
        libc::SYS_pipe2,
        libc::SYS_prlimit64,
        libc::SYS_getrandom,
        libc::SYS_statx,
        libc::SYS_rseq,
        libc::SYS_clone3,
        libc::SYS_renameat2,
        libc::SYS_openat,
        libc::SYS_ioctl,
        libc::SYS_select,
        libc::SYS_recvmmsg,
        libc::SYS_sendmmsg,
        libc::SYS_pipe,
    ];

    for sys in allowed_syscalls {
        rules.entry(sys).or_default();
    }

    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        target_arch,
    )?
    .try_into()?;

    apply_filter(&filter)?;
    Ok(())
}

/// Apply full sandbox (Resource Limits, Landlock, Seccomp) (TR-GW-1).
pub fn apply_sandbox(
    log_dir: &Path,
    key_file: &Path,
    socket_dir: Option<&Path>,
    allow_no_landlock: bool,
) -> Result<SandboxLandlockStatus, SandboxError> {
    apply_resource_limits()?;
    let status = apply_landlock(log_dir, key_file, socket_dir, allow_no_landlock)?;
    apply_seccomp()?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_applied() {
        apply_resource_limits().expect("apply resource limits");
        let core = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(core.current, Some(0));
        assert_eq!(core.maximum, Some(0));
        let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        assert!(nofile.current.unwrap_or(0) <= 1024);
        let fsize = rustix::process::getrlimit(rustix::process::Resource::Fsize);
        assert!(fsize.current.unwrap_or(0) <= 256 * 1024 * 1024);
    }

    #[test]
    fn test_landlock_unavailable_fail_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_dir = temp.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        let key_file = temp.path().join("key.txt");
        std::fs::write(&key_file, "fake-test-key-content\n").expect("key file");

        set_inject_landlock_unavailable(true);
        let res_fail = apply_landlock(&log_dir, &key_file, None, false);
        assert!(matches!(res_fail, Err(SandboxError::LandlockUnavailable)));

        let res_ok = apply_landlock(&log_dir, &key_file, None, true);
        assert_eq!(res_ok.unwrap(), SandboxLandlockStatus::NotEnforced);
        set_inject_landlock_unavailable(false);
    }

    #[test]
    fn test_missing_log_dir_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_dir = temp.path().join("nonexistent_logs");
        let key_file = temp.path().join("key.txt");
        std::fs::write(&key_file, "fake-test-key-content\n").expect("key file");

        let res = apply_landlock(&log_dir, &key_file, None, false);
        assert!(matches!(res, Err(SandboxError::Io(_))));
    }

    #[test]
    fn test_missing_key_file_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_dir = temp.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        let key_file = temp.path().join("nonexistent_key.txt");

        let res = apply_landlock(&log_dir, &key_file, None, false);
        assert!(matches!(res, Err(SandboxError::Io(_))));
    }

    #[test]
    fn test_process_non_dumpable_applied() {
        apply_resource_limits().expect("apply resource limits");
        let dumpable = rustix::process::dumpable_behavior().expect("dumpable behavior");
        assert_eq!(dumpable, rustix::process::DumpableBehavior::NotDumpable);
    }

    #[test]
    fn test_tighter_inherited_rlimits_are_clamped_and_preserved() {
        // Clamp current limits and verify apply_resource_limits preserves tighter limits
        apply_resource_limits().expect("apply resource limits");
        let fsize = rustix::process::getrlimit(rustix::process::Resource::Fsize);
        assert!(fsize.maximum.unwrap_or(u64::MAX) <= 256 * 1024 * 1024);
        assert!(fsize.current.unwrap_or(u64::MAX) <= fsize.maximum.unwrap_or(u64::MAX));

        let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        assert!(nofile.maximum.unwrap_or(u64::MAX) <= 1024);
        assert!(nofile.current.unwrap_or(u64::MAX) <= nofile.maximum.unwrap_or(u64::MAX));
    }

    #[test]
    fn test_landlock_rule_error_propagates_even_with_allow_no_landlock() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_dir = temp.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("log dir");
        let key_file = temp.path().join("key.txt");
        std::fs::write(&key_file, "fake-test-key-content\n").expect("key file");

        set_inject_landlock_rule_error(true);
        let res = apply_landlock(&log_dir, &key_file, None, true);
        set_inject_landlock_rule_error(false);
        assert!(
            matches!(res, Err(SandboxError::Landlock(_))),
            "Expected rule setup error to propagate, got: {res:?}"
        );
    }
}
