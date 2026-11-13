//! Trusted early-boot handoff (`/sbin/hermetic-init`, first boot only).
//!
//! The execd boot contract needs `/proc/cmdline` and the kernel's
//! `/proc/self/{exe,fd}` readable when execd starts as PID 1, but execd itself
//! never mounts anything before setting the clock. This shim closes that gap
//! and does nothing else: it mounts procfs read-only at `/proc` of the sealed
//! read-only base, then replaces itself (same PID 1) with
//! `/sbin/hermetic-execd`, passing no arguments and an empty environment.
//! It reads no clock, writes nothing, logs nothing and parses no input.
//! The early proc mount is covered by execd's root switch.
//! Any failure powers the VM off; execd would do the same for a missing proc.

use crate::{Error, Result};

/// Absolute path of the PID 1 program this shim hands over to.
pub const EXECD: &str = "/sbin/hermetic-execd";
/// The only mount target the shim touches.
pub const PROC: &str = "/proc";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyEffect {
    /// procfs at `/proc`, read-only, nosuid, nodev, noexec.
    MountProcReadOnly,
    /// Replace this process image with [`EXECD`]. Returns only on failure.
    ExecExecd,
    PowerOff,
}

/// Privileged operations, isolated so the order can be tested on a host.
pub trait EarlySys {
    fn is_pid1(&self) -> bool;
    fn effect(&mut self, effect: EarlyEffect) -> Result<()>;
}

/// Runs the handoff. On success the exec does not return, so any return is an error.
pub fn run<S: EarlySys>(sys: &mut S) -> Result<()> {
    // Refuse all privileged work when accidentally invoked on the host.
    if !sys.is_pid1() {
        return Err(Error::Boot);
    }
    let result = sys
        .effect(EarlyEffect::MountProcReadOnly)
        .and_then(|()| sys.effect(EarlyEffect::ExecExecd))
        .and(Err(Error::Boot));
    let _ = sys.effect(EarlyEffect::PowerOff);
    result
}

/// Guest implementation.
#[derive(Default)]
pub struct LinuxEarly;

impl EarlySys for LinuxEarly {
    fn is_pid1(&self) -> bool {
        rustix::process::getpid().as_raw_nonzero().get() == 1
    }
    fn effect(&mut self, effect: EarlyEffect) -> Result<()> {
        use rustix::mount::MountFlags;
        match effect {
            EarlyEffect::MountProcReadOnly => rustix::mount::mount(
                "proc",
                PROC,
                "proc",
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None,
            )?,
            EarlyEffect::ExecExecd => {
                use std::os::unix::process::CommandExt;
                // exec only returns on failure.
                let _ = std::process::Command::new(EXECD).env_clear().exec();
                return Err(Error::Boot);
            }
            EarlyEffect::PowerOff => {
                rustix::system::reboot(rustix::system::RebootCommand::PowerOff)?
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        pid1: bool,
        fail: Option<EarlyEffect>,
        exec_returns: bool,
        log: Vec<EarlyEffect>,
    }
    impl Recorder {
        fn new() -> Self {
            Self {
                pid1: true,
                fail: None,
                exec_returns: false,
                log: Vec::new(),
            }
        }
    }
    impl EarlySys for Recorder {
        fn is_pid1(&self) -> bool {
            self.pid1
        }
        fn effect(&mut self, effect: EarlyEffect) -> Result<()> {
            self.log.push(effect);
            if self.fail == Some(effect) {
                return Err(Error::Io);
            }
            if effect == EarlyEffect::ExecExecd && !self.exec_returns {
                // Model a successful exec: the shim never observes a return.
                return Err(Error::Boot);
            }
            Ok(())
        }
    }

    #[test]
    fn mounts_only_read_only_proc_then_execs_execd() {
        let mut sys = Recorder::new();
        assert_eq!(run(&mut sys), Err(Error::Boot));
        assert_eq!(
            sys.log,
            [
                EarlyEffect::MountProcReadOnly,
                EarlyEffect::ExecExecd,
                EarlyEffect::PowerOff
            ]
        );
    }

    #[test]
    fn refuses_without_effects_unless_pid1() {
        let mut sys = Recorder::new();
        sys.pid1 = false;
        assert_eq!(run(&mut sys), Err(Error::Boot));
        assert!(sys.log.is_empty());
    }

    #[test]
    fn mount_failure_powers_off_without_exec() {
        let mut sys = Recorder::new();
        sys.fail = Some(EarlyEffect::MountProcReadOnly);
        assert_eq!(run(&mut sys), Err(Error::Io));
        assert_eq!(
            sys.log,
            [EarlyEffect::MountProcReadOnly, EarlyEffect::PowerOff]
        );
    }

    #[test]
    fn an_exec_that_returns_is_an_error_and_powers_off() {
        let mut sys = Recorder::new();
        sys.exec_returns = true;
        assert_eq!(run(&mut sys), Err(Error::Boot));
        assert_eq!(sys.log.last(), Some(&EarlyEffect::PowerOff));
    }

    #[test]
    fn fixed_paths() {
        assert_eq!(EXECD, "/sbin/hermetic-execd");
        assert_eq!(PROC, "/proc");
    }
}
