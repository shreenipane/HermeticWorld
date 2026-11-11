#![forbid(unsafe_code)]

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
}

/// Apply Landlock filesystem restrictions.
///
/// Grants read-only access to `store_dir`, and read-write access to `log_dir`.
/// If Landlock is unavailable and `allow_no_landlock` is false, returns `SandboxError::LandlockUnavailable`.
pub fn apply_landlock(
    store_dir: &Path,
    log_dir: &Path,
    allow_no_landlock: bool,
) -> Result<SandboxLandlockStatus, SandboxError> {
    let abi = ABI::V3;
    let ruleset_res = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules(&[store_dir], AccessFs::from_read(abi))))
        .and_then(|r| r.add_rules(path_beneath_rules(&[log_dir], AccessFs::from_all(abi))))
        .and_then(|r| r.restrict_self());

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
            if allow_no_landlock {
                Ok(SandboxLandlockStatus::NotEnforced)
            } else {
                Err(SandboxError::Landlock(e))
            }
        }
    }
}

/// Apply seccomp allow-list filter.
///
/// Denies `execve`/`execveat`, `ptrace`, `mount`/`umount2`, and `socket` for any family other than `AF_UNIX`.
/// Violations kill the process.
pub fn apply_seccomp() -> Result<(), SandboxError> {
    let target_arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules = BTreeMap::new();

    // Sockets: allow AF_UNIX only (domain arg 0 == AF_UNIX)
    let socket_rule = SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_UNIX as u64,
    )?])?;
    rules.insert(libc::SYS_socket, vec![socket_rule]);

    // System calls allowed unconditionally for server operation
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
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_socketpair,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_clone,
        libc::SYS_exit,
        libc::SYS_wait4,
        libc::SYS_kill,
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
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_setpgid,
        libc::SYS_getpgrp,
        libc::SYS_setsid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_getgroups,
        libc::SYS_setgroups,
        libc::SYS_setresuid,
        libc::SYS_getresuid,
        libc::SYS_setresgid,
        libc::SYS_getresgid,
        libc::SYS_getpgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_getsid,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigqueueinfo,
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
        libc::SYS_tkill,
        libc::SYS_time,
        libc::SYS_epoll_create,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_set_tid_address,
        libc::SYS_clock_settime,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_exit_group,
        libc::SYS_tgkill,
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
    ];

    for sys in allowed_syscalls {
        rules.insert(sys, vec![]);
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

/// Apply full sandbox (Landlock then Seccomp).
pub fn apply_sandbox(
    store_dir: &Path,
    log_dir: &Path,
    allow_no_landlock: bool,
) -> Result<SandboxLandlockStatus, SandboxError> {
    let landlock_status = apply_landlock(store_dir, log_dir, allow_no_landlock)?;
    apply_seccomp()?;
    Ok(landlock_status)
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    #[test]
    fn sandbox_denies_store_and_outside_truncation() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let log = temp.path().join("log");
        fs::create_dir(&store).unwrap();
        fs::create_dir(&log).unwrap();
        let targets = [store.join("body"), temp.path().join("outside")];
        for target in targets {
            for operation in ["open_truncate", "ftruncate"] {
                fs::write(&target, b"unchanged").unwrap();
                let status = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "sandbox::review_tests::truncation_child",
                        "--nocapture",
                    ])
                    .env("HERMETIC_TRUNCATE_TARGET", &target)
                    .env("HERMETIC_TRUNCATE_STORE", &store)
                    .env("HERMETIC_TRUNCATE_LOG", &log)
                    .env("HERMETIC_TRUNCATE_OP", operation)
                    .status()
                    .unwrap();
                assert!(
                    status.success() || status.signal() == Some(libc::SIGSYS),
                    "{status}"
                );
                assert_eq!(fs::read(&target).unwrap(), b"unchanged");
            }
        }
    }
    #[test]
    fn truncation_child() {
        let Some(target) = std::env::var_os("HERMETIC_TRUNCATE_TARGET") else {
            return;
        };
        let store = std::env::var_os("HERMETIC_TRUNCATE_STORE").unwrap();
        let log = std::env::var_os("HERMETIC_TRUNCATE_LOG").unwrap();
        let operation = std::env::var("HERMETIC_TRUNCATE_OP").unwrap();
        let file = fs::OpenOptions::new().write(true).open(&target).unwrap();
        apply_sandbox(Path::new(&store), Path::new(&log), true).unwrap();
        let error = if operation == "ftruncate" {
            file.set_len(0).unwrap_err()
        } else {
            fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(target)
                .unwrap_err()
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        std::process::exit(0);
    }
}
