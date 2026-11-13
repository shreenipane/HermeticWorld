//! GraderVM PID 1 (`/sbin/hermetic-grader-init`).
//!
//! Order: refuse unless PID 1; mount procfs read-only (nothing writable exists
//! yet); read `hermetic.t=` from `/proc/cmdline` with execd's parser and set
//! CLOCK_REALTIME with execd's clock code; only then mount the writable
//! `/tmp` tmpfs and a private devpts; run the supervisor with fixed arguments;
//! sync; power off. No vsock and no network are touched (TR-GR-1).
//! Every failure, and every success, ends in power-off.
//!
//! After the clock is set it writes two serial lines, each holding only the
//! guest Unix seconds and a static word: `grader-init SECONDS clock` and
//! `grader-init SECONDS done|failed`. The host uses the first line to check
//! the guest clock against `T_clock`.

use crate::{boot, Error, Result};
use std::time::Duration;

pub const PROC: &str = "/proc";
pub const CMDLINE: &str = "/proc/cmdline";
pub const TMP: &str = "/tmp";
pub const DEV_PTS: &str = "/dev/pts";
pub const SUPERVISOR: &str = "/sbin/hermetic-grader-supervisor";
pub const CONFIG: &str = "/etc/hermetic/grader/run.json";
/// Drive order: root `vda`, result `vdb` (hermetic-vmm grader layout).
pub const RESULT_DISK: &str = "/dev/vdb";
/// tmpfs data, fixed.
pub const TMP_OPTIONS: &std::ffi::CStr = c"size=256m,mode=1777,nr_inodes=65536";
pub const PTS_OPTIONS: &std::ffi::CStr = c"newinstance,ptmxmode=0666,mode=0620";
/// Same maximum run deadline as the supervisor; allow startup and kill grace.
pub const MAX_GRADING_SECONDS: u64 = 86_400;
pub const SUPERVISOR_MARGIN: Duration = Duration::from_secs(60);
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(10);
pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
pub const REAP_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const POLL: Duration = Duration::from_millis(50);

pub fn supervisor_args() -> [&'static str; 4] {
    ["--config", CONFIG, "--result-disk", RESULT_DISK]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraderEffect {
    /// procfs at `/proc`, read-only, nosuid, nodev, noexec.
    MountProcReadOnly,
    SetClock(i64),
    /// Serial line `grader-init SECONDS WORD`.
    Log(&'static str),
    MountTmp,
    MountDevPts,
    /// Runs the supervisor to completion (bounded). Its exit status is not
    /// trusted for anything; the host reads only the result drive.
    RunSupervisor,
    Sync,
    PowerOff,
}

pub trait GraderSys {
    fn is_pid1(&self) -> bool;
    /// The kernel command line through the early read-only proc.
    fn cmdline(&mut self) -> Result<Vec<u8>>;
    fn effect(&mut self, effect: GraderEffect) -> Result<()>;
    fn phase(&mut self, _phase: &'static str) {}
    fn recover_result(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Runs the grader boot. Always ends with sync and power-off once PID 1 is
/// confirmed. The result is only for tests: PowerOff does not return on a guest.
pub fn run<S: GraderSys>(sys: &mut S) -> Result<()> {
    if !sys.is_pid1() {
        return Err(Error::Boot);
    }
    let mut clock_set = false;
    let result = (|| {
        sys.effect(GraderEffect::MountProcReadOnly)?;
        let line = sys.cmdline()?;
        let clock = boot::read_clock(line.as_slice())?;
        sys.effect(GraderEffect::SetClock(clock))?;
        clock_set = true;
        sys.effect(GraderEffect::Log("clock"))?;
        sys.effect(GraderEffect::MountTmp)?;
        sys.effect(GraderEffect::MountDevPts)?;
        sys.effect(GraderEffect::RunSupervisor)
    })();
    // No log before the clock is set, as in execd.
    if clock_set {
        let _ = sys.effect(GraderEffect::Log(if result.is_ok() {
            "done"
        } else {
            "failed"
        }));
    }
    if clock_set {
        sys.phase("sync");
    }
    let sync = sys.effect(GraderEffect::Sync);
    if sync.is_err() && clock_set {
        let _ = sys.recover_result();
    }
    if clock_set {
        sys.phase("poweroff");
    }
    let _ = sys.effect(GraderEffect::PowerOff);
    result.and(sync)
}

/// Guest implementation.
#[derive(Default)]
pub struct LinuxGrader;

fn mkdir_nofollow(path: &str) -> Result<()> {
    match rustix::fs::mkdir(path, rustix::fs::Mode::from_raw_mode(0o755)) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    let st = rustix::fs::lstat(path)?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Directory {
        return Err(Error::Boot);
    }
    Ok(())
}

fn supervisor_backstop(bytes: &[u8]) -> Result<Duration> {
    #[derive(serde::Deserialize)]
    struct Deadline {
        #[serde(alias = "deadline_secs")]
        deadline_seconds: u64,
    }
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(Error::Limit);
    }
    let config: Deadline = serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
    if config.deadline_seconds == 0 || config.deadline_seconds > MAX_GRADING_SECONDS {
        return Err(Error::InvalidInput);
    }
    Ok(Duration::from_secs(config.deadline_seconds).saturating_add(SUPERVISOR_MARGIN))
}

fn poll_child(
    limit: Duration,
    mut poll: impl FnMut() -> Result<Option<bool>>,
    mut kill: impl FnMut(),
) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        if let Some(success) = poll()? {
            return if success { Ok(()) } else { Err(Error::Boot) };
        }
        if start.elapsed() >= limit {
            kill();
            // SIGKILL need not complete for an uninterruptible child. PID 1
            // must retain control and reach reboot rather than blocking in wait.
            return Err(Error::Timeout);
        }
        std::thread::sleep(POLL);
    }
}

fn command_supervisor(recovery: bool, limit: Duration) -> Result<()> {
    let mut command = std::process::Command::new(SUPERVISOR);
    if recovery {
        command.arg("--infra-error");
    }
    let child = std::cell::RefCell::new(
        command
            .args(supervisor_args())
            .env_clear()
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .spawn()?,
    );
    poll_child(
        limit,
        || Ok(child.borrow_mut().try_wait()?.map(|s| s.success())),
        || {
            let _ = child.borrow_mut().kill();
        },
    )
}

fn recover_result() -> Result<()> {
    // This operation is legal only in the disposable GraderVM's PID 1.
    if rustix::process::getpid().as_raw_pid() != 1 {
        return Err(Error::Boot);
    }
    eprintln!("grader-init phase recovery");
    let result = recover_quiescent_result();
    if result.is_err() {
        // A collector must reject the drive if recovery could not replace it.
        eprintln!("grader-init phase recovery-failed");
    }
    result
}

fn recover_quiescent_result() -> Result<()> {
    crate::sys::kill_all(libc::SIGKILL)?;
    let start = std::time::Instant::now();
    loop {
        match rustix::process::waitpid(None, rustix::process::WaitOptions::NOHANG) {
            Err(rustix::io::Errno::CHILD) => break,
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
        if start.elapsed() >= REAP_TIMEOUT {
            return Err(Error::ChildStuck);
        }
        std::thread::sleep(POLL);
    }
    command_supervisor(true, RECOVERY_TIMEOUT)
}

fn run_supervisor() -> Result<()> {
    let result = (|| {
        let root = crate::fs::Root::open_root("/")?;
        let bytes = root.read(CONFIG, MAX_CONFIG_BYTES)?;
        command_supervisor(false, supervisor_backstop(&bytes)?)
    })();
    if result.is_err() {
        let _ = recover_result();
    }
    result
}

fn bounded_sync(limit: Duration, sync: impl FnOnce() + Send + 'static) -> Result<()> {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("grader-sync".into())
        .spawn(move || {
            sync();
            let _ = send.send(());
        })?;
    receive.recv_timeout(limit).map_err(|_| Error::Timeout)
}

impl GraderSys for LinuxGrader {
    fn recover_result(&mut self) -> Result<()> {
        recover_result()
    }
    fn phase(&mut self, phase: &'static str) {
        eprintln!("grader-init phase {phase}");
    }
    fn is_pid1(&self) -> bool {
        rustix::process::getpid().as_raw_nonzero().get() == 1
    }
    fn cmdline(&mut self) -> Result<Vec<u8>> {
        let file = std::fs::File::open(CMDLINE)?;
        crate::read_capped(file, crate::MAX_CMDLINE)
    }
    fn effect(&mut self, effect: GraderEffect) -> Result<()> {
        use rustix::mount::{mount, MountFlags};
        match effect {
            GraderEffect::MountProcReadOnly => mount(
                "proc",
                PROC,
                "proc",
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None,
            )?,
            GraderEffect::SetClock(clock) => crate::real::set_realtime(clock)?,
            GraderEffect::Log(word) => {
                use std::io::Write;
                let line = format!("grader-init {} {word}\n", crate::real::now());
                std::io::stderr().write_all(line.as_bytes())?;
            }
            GraderEffect::MountTmp => {
                mount(
                    "tmpfs",
                    TMP,
                    "tmpfs",
                    MountFlags::NOSUID | MountFlags::NODEV,
                    Some(TMP_OPTIONS),
                )?;
            }
            GraderEffect::MountDevPts => {
                // devtmpfs (kernel-mounted) has no /dev/pts; create it, no-follow.
                mkdir_nofollow(DEV_PTS)?;
                mount(
                    "devpts",
                    DEV_PTS,
                    "devpts",
                    MountFlags::NOSUID | MountFlags::NOEXEC,
                    Some(PTS_OPTIONS),
                )?;
            }
            GraderEffect::RunSupervisor => run_supervisor()?,
            GraderEffect::Sync => bounded_sync(SYNC_TIMEOUT, rustix::fs::sync)?,
            // Ends the VM. The sealed kernel has no working power-off path in
            // Firecracker (`reboot(POWER_OFF)` only halts, and Firecracker keeps
            // running). A restart with `reboot=k` resets through the i8042
            // controller, on which Firecracker exits; the host observes that exit.
            GraderEffect::PowerOff => {
                rustix::system::reboot(rustix::system::RebootCommand::Restart)?
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use GraderEffect::*;

    struct Recorder {
        pid1: bool,
        cmdline: Vec<u8>,
        fail: Option<GraderEffect>,
        log: Vec<GraderEffect>,
        recoveries: usize,
    }
    impl Recorder {
        fn new(cmdline: &str) -> Self {
            Self {
                pid1: true,
                cmdline: cmdline.as_bytes().to_vec(),
                fail: None,
                log: Vec::new(),
                recoveries: 0,
            }
        }
    }
    impl GraderSys for Recorder {
        fn recover_result(&mut self) -> Result<()> {
            self.recoveries += 1;
            Ok(())
        }
        fn is_pid1(&self) -> bool {
            self.pid1
        }
        fn cmdline(&mut self) -> Result<Vec<u8>> {
            Ok(self.cmdline.clone())
        }
        fn effect(&mut self, effect: GraderEffect) -> Result<()> {
            self.log.push(effect);
            if self.fail == Some(effect) {
                return Err(Error::Io);
            }
            Ok(())
        }
    }
    const LINE: &str = "console=ttyS0 ro hermetic.t=1700000000 init=/sbin/hermetic-grader-init";

    #[test]
    fn clock_is_set_before_anything_writable_then_supervisor_then_poweroff() {
        let mut sys = Recorder::new(LINE);
        assert_eq!(run(&mut sys), Ok(()));
        assert_eq!(
            sys.log,
            [
                MountProcReadOnly,
                SetClock(1_700_000_000),
                Log("clock"),
                MountTmp,
                MountDevPts,
                RunSupervisor,
                Log("done"),
                Sync,
                PowerOff
            ]
        );
    }

    #[test]
    fn refuses_without_effects_unless_pid1() {
        let mut sys = Recorder::new(LINE);
        sys.pid1 = false;
        assert_eq!(run(&mut sys), Err(Error::Boot));
        assert!(sys.log.is_empty());
    }

    #[test]
    fn invalid_or_missing_clock_powers_off_silently() {
        for line in [
            "ro",
            "hermetic.t=1",
            "hermetic.t=1700000000 hermetic.t=1700000000",
            "hermetic.t=17x",
        ] {
            let mut sys = Recorder::new(line);
            assert_eq!(run(&mut sys), Err(Error::InvalidClock), "{line}");
            assert_eq!(sys.log, [MountProcReadOnly, Sync, PowerOff], "{line}");
        }
        let mut sys = Recorder::new("");
        sys.cmdline = vec![b'a'; crate::MAX_CMDLINE + 1];
        assert_eq!(run(&mut sys), Err(Error::InvalidClock));
    }

    #[test]
    fn grader_ignores_execd_options_but_shares_the_clock_rule() {
        // Execd-only options are not the grader's business; the clock rule is identical.
        let line = "hermetic.t=1700000000 hermetic.overlay=/dev/vdc";
        assert_eq!(boot::read_clock(line.as_bytes()), Ok(1_700_000_000));
        assert!(boot::Config::parse(line.as_bytes()).is_ok());
    }

    #[test]
    fn each_failure_stops_later_steps_and_powers_off() {
        for step in [
            MountProcReadOnly,
            SetClock(1_700_000_000),
            MountTmp,
            MountDevPts,
            RunSupervisor,
        ] {
            let mut sys = Recorder::new(LINE);
            sys.fail = Some(step);
            assert_eq!(run(&mut sys), Err(Error::Io));
            let at = sys.log.iter().position(|e| *e == step).unwrap();
            let tail: Vec<_> = sys.log[at + 1..].to_vec();
            let clock_set = sys.log[..at].contains(&SetClock(1_700_000_000));
            let want: Vec<_> = if clock_set {
                vec![Log("failed"), Sync, PowerOff]
            } else {
                vec![Sync, PowerOff]
            };
            assert_eq!(tail, want, "{step:?}");
        }
    }

    #[test]
    fn fixed_paths_and_arguments() {
        assert_eq!(
            supervisor_args(),
            [
                "--config",
                "/etc/hermetic/grader/run.json",
                "--result-disk",
                "/dev/vdb"
            ]
        );
        assert_eq!(SUPERVISOR, "/sbin/hermetic-grader-supervisor");
        assert_eq!(TMP_OPTIONS, c"size=256m,mode=1777,nr_inodes=65536");
        assert_eq!(PTS_OPTIONS, c"newinstance,ptmxmode=0666,mode=0620");
    }

    #[test]
    fn backstop_tracks_configured_deadline_including_runs_longer_than_four_hours() {
        for seconds in [1, 120, MAX_GRADING_SECONDS] {
            let json = format!(r#"{{"deadline_seconds":{seconds},"argv":["pytest"]}}"#);
            assert_eq!(
                supervisor_backstop(json.as_bytes()),
                Ok(Duration::from_secs(seconds) + SUPERVISOR_MARGIN)
            );
        }
        assert_eq!(
            supervisor_backstop(br#"{"deadline_secs":120}"#),
            Ok(Duration::from_secs(180))
        );
        for json in [
            br#"{}"#.as_slice(),
            br#"{"deadline_seconds":0}"#,
            br#"{"deadline_seconds":86401}"#,
            br#"{"deadline_seconds":-1}"#,
            br#"{"deadline_seconds":1,"deadline_secs":2}"#,
        ] {
            assert!(supervisor_backstop(json).is_err());
        }
        assert_eq!(
            supervisor_backstop(&vec![b' '; MAX_CONFIG_BYTES + 1]),
            Err(Error::Limit)
        );
    }

    #[test]
    fn backstop_kills_but_never_waits_for_an_uninterruptible_child() {
        let killed = std::cell::Cell::new(false);
        assert_eq!(
            poll_child(Duration::ZERO, || Ok(None), || killed.set(true)),
            Err(Error::Timeout)
        );
        assert!(killed.get());
        killed.set(false);
        assert_eq!(
            poll_child(Duration::ZERO, || Ok(Some(true)), || killed.set(true)),
            Ok(())
        );
        assert!(!killed.get());
    }

    #[test]
    fn stalled_sync_is_bounded_and_sync_error_still_powers_off() {
        let (release, wait) = std::sync::mpsc::channel();
        let (finished, done) = std::sync::mpsc::channel();
        assert_eq!(
            bounded_sync(Duration::ZERO, move || {
                wait.recv().unwrap();
                finished.send(()).unwrap();
            }),
            Err(Error::Timeout)
        );
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(1)).unwrap();

        let mut sys = Recorder::new(LINE);
        sys.fail = Some(Sync);
        assert_eq!(run(&mut sys), Err(Error::Io));
        assert_eq!(sys.log.last(), Some(&PowerOff));
        assert_eq!(sys.recoveries, 1);

        let mut sys = Recorder::new("ro");
        sys.fail = Some(Sync);
        assert_eq!(run(&mut sys), Err(Error::InvalidClock));
        assert_eq!(
            sys.recoveries, 0,
            "no result write before setting the sealed clock"
        );
        assert_eq!(sys.log, [MountProcReadOnly, Sync, PowerOff]);
    }
}
