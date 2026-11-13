//! Linux implementation. Constructing this value has no side effects.
use crate::{
    boot::{Effect, Sys},
    fs::Root,
    rpc::{ExecReply, Listener},
    spec::RunSpec,
    sys, *,
};
use rustix::{
    fs::{self, AtFlags, Mode, OFlags, ResolveFlags},
    process::{self, Pid, Signal, WaitOptions},
};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct Linux {
    root: Option<Root>,
    helper: Option<File>,
    signals: Option<OwnedFd>,
    pub listener: Option<VsockListener>,
    entry: Option<Running>,
    foreground: Option<Pid>,
    terminating: bool,
    guest_clock_set: bool,
    base: Option<OwnedFd>,
    upload_owner: Option<(process::Uid, process::Gid)>,
}
pub struct VsockListener(OwnedFd);
impl Listener for VsockListener {
    type Stream = DeadlineStream;
    fn accept(&mut self) -> Result<Option<DeadlineStream>> {
        let Some(fd) = sys::accept(&self.0)? else {
            std::thread::sleep(Duration::from_millis(10));
            return Ok(None);
        };
        Ok(Some(DeadlineStream::new(
            fd.into(),
            Duration::from_millis(FRAME_TIMEOUT_MS),
        )))
    }
}

/// Absolute frame deadlines also bound a peer sending one byte at a time.
pub struct DeadlineStream {
    file: File,
    read_end: Instant,
    write_end: Option<Instant>,
    duration: Duration,
}
impl DeadlineStream {
    pub fn new(file: File, duration: Duration) -> Self {
        Self {
            file,
            read_end: Instant::now() + duration,
            write_end: None,
            duration,
        }
    }
    fn ready(&self, end: Instant, events: rustix::event::PollFlags) -> std::io::Result<()> {
        let remaining = end
            .checked_duration_since(Instant::now())
            .ok_or(std::io::ErrorKind::TimedOut)?;
        let timeout = rustix::time::Timespec::try_from(remaining)
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;
        let mut poll = [rustix::event::PollFd::new(&self.file, events)];
        if rustix::event::poll(&mut poll, Some(&timeout))? == 0 {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.ready(self.read_end, rustix::event::PollFlags::IN)?;
        Ok(rustix::net::recv(&self.file, data, rustix::net::RecvFlags::DONTWAIT)?.0)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let end = *self
            .write_end
            .get_or_insert_with(|| Instant::now() + self.duration);
        self.ready(end, rustix::event::PollFlags::OUT)?;
        Ok(rustix::net::send(
            &self.file,
            data,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        )?)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Running {
    child: Child,
    output: Vec<File>,
}
impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            if let Ok(pid) = pid(&self.child) {
                let _ = process::kill_process_group(pid, Signal::KILL);
            }
            let _ = self.child.kill();
            let _ = killed_status(&mut self.child);
        }
    }
}

fn mount(source: &str, target: &str, kind: &str, data: Option<&str>) -> Result<()> {
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| Error::InvalidInput)?;
    rustix::mount::mount(
        source,
        target,
        kind,
        rustix::mount::MountFlags::NOSUID,
        data.as_deref(),
    )?;
    Ok(())
}
fn fd_path(fd: &impl AsRawFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}
fn now() -> i64 {
    rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec
}
fn nonblock(file: &File) -> Result<()> {
    fs::fcntl_setfl(file, fs::fcntl_getfl(file)? | OFlags::NONBLOCK)?;
    Ok(())
}
fn pid(child: &Child) -> Result<Pid> {
    Pid::from_raw(i32::try_from(child.id()).map_err(|_| Error::Limit)?).ok_or(Error::Io)
}

fn is_kernel_thread(stat: &[u8], expected_pid: &[u8]) -> Result<bool> {
    // /proc/PID/stat field 2 is parenthesized and can itself contain ')' and
    // spaces. Parse the fixed fields after the final ')' rather than comm.
    const PF_KTHREAD: u64 = 0x0020_0000;
    let text = std::str::from_utf8(stat).map_err(|_| Error::Io)?;
    let (pid, rest) = text.split_once(" (").ok_or(Error::Io)?;
    if pid.as_bytes() != expected_pid {
        return Err(Error::Io);
    }
    let (_, fields) = rest.rsplit_once(')').ok_or(Error::Io)?;
    let flags = fields
        .split_ascii_whitespace()
        .nth(6)
        .ok_or(Error::Io)?
        .parse::<u64>()
        .map_err(|_| Error::Io)?;
    Ok(flags & PF_KTHREAD != 0)
}

impl Linux {
    fn mount_guest(&self, source: &str, path: &str, kind: &str, data: Option<&str>) -> Result<()> {
        let target = self.root()?.directory(path)?;
        process::fchdir(&target)?;
        let result = mount(source, ".", kind, data);
        process::fchdir(self.root()?.directory("/")?)?;
        result
    }
    fn supervise(
        &mut self,
        mut running: Running,
        deadline: Instant,
        output_cap: usize,
    ) -> Result<ExecReply> {
        let child_pid = pid(&running.child)?;
        self.foreground = Some(child_pid);
        let mut reply = ExecReply {
            code: None,
            output: Vec::new(),
            truncated: false,
            timed_out: false,
        };
        let mut result = (|| {
            loop {
                self.signals()?;
                drain(
                    &mut running.output,
                    &mut reply.output,
                    output_cap,
                    &mut reply.truncated,
                )?;
                if let Some(status) = running.child.try_wait()? {
                    reply.code = status.code();
                    break;
                }
                if Instant::now() >= deadline {
                    reply.timed_out = true;
                    let _ = process::kill_process_group(child_pid, Signal::KILL);
                    let _ = running.child.kill();
                    reply.code = killed_status(&mut running.child)?.code();
                    break;
                }
                self.maintain()?;
                std::thread::sleep(Duration::from_millis(5));
            }
            // Stop descendants retaining pipes, then drain a bounded final batch.
            let _ = process::kill_process_group(child_pid, Signal::KILL);
            drain_reads(
                &mut running.output,
                &mut reply.output,
                output_cap,
                &mut reply.truncated,
                MAX_FINAL_DRAIN_READS,
                true,
            )?;
            Ok(reply)
        })();
        if result.is_err() {
            let _ = process::kill_process_group(child_pid, Signal::KILL);
            let _ = running.child.kill();
            if killed_status(&mut running.child).is_err() {
                result = Err(Error::ChildStuck);
            }
        }
        self.foreground = None;
        let maintenance = self.maintain();
        result.and_then(|reply| {
            maintenance?;
            Ok(reply)
        })
    }
    fn root(&self) -> Result<&Root> {
        self.root.as_ref().ok_or(Error::Boot)
    }
    fn root_mut(&mut self) -> Result<&mut Root> {
        self.root.as_mut().ok_or(Error::Boot)
    }
    fn install_spec_files(&mut self, spec: &RunSpec) -> Result<()> {
        spec.validate()?;
        self.root_mut()?.atomic_as(
            "/etc/resolv.conf",
            spec.resolv_conf.as_bytes(),
            now(),
            None,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        )?;
        self.upload_owner = Some((
            process::Uid::from_raw(spec.uid),
            process::Gid::from_raw(spec.gid),
        ));
        Ok(())
    }
    fn spawn(
        &mut self,
        spec: &RunSpec,
        argv: &[String],
        tty: bool,
        deadline: Instant,
    ) -> Result<Running> {
        spec.validate()?;
        spec::args(argv, false)?;
        let program = argv.first().ok_or(Error::InvalidInput)?;
        let executable = self.root()?.regular(program)?;
        let cwd = self.root()?.directory(&spec.workdir)?;
        let helper = self.helper.as_ref().ok_or(Error::Boot)?;
        let (startup_read, startup_write) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )?;
        let payload = ChildSpec {
            spec: spec.clone(),
            argv: argv.to_vec(),
            tty,
            executable: executable.as_raw_fd(),
            cwd: cwd.as_raw_fd(),
            startup: startup_write.as_raw_fd(),
        };
        let encoded = serde_json::to_string(&payload).map_err(|_| Error::InvalidInput)?;
        if encoded.len() > MAX_CHILD_PAYLOAD {
            return Err(Error::Limit);
        }
        let mut command = Command::new(format!("./{}", helper.as_raw_fd()));
        command
            .arg("--child")
            .arg(encoded)
            .env_clear()
            .stdin(Stdio::piped());
        let mut output = Vec::new();
        if tty {
            let (master, slave) = allocate_pty(self.root()?)?;
            command
                .stdin(slave.try_clone()?)
                .stdout(slave.try_clone()?)
                .stderr(slave);
            output.push(master);
        } else {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        // Single-threaded PID 1: only these descriptors cross helper exec.
        rustix::io::fcntl_setfd(&executable, rustix::io::FdFlags::empty())?;
        rustix::io::fcntl_setfd(&cwd, rustix::io::FdFlags::empty())?;
        rustix::io::fcntl_setfd(&startup_write, rustix::io::FdFlags::empty())?;
        let spawned = sys::spawn_in(&mut command, &self.root()?.proc.fds);
        let reset_executable = rustix::io::fcntl_setfd(&executable, rustix::io::FdFlags::CLOEXEC);
        let reset_cwd = rustix::io::fcntl_setfd(&cwd, rustix::io::FdFlags::CLOEXEC);
        drop(startup_write);
        let mut running = Running {
            child: spawned?,
            output,
        };
        // EOF on ordinary stdin without opening a mutable /dev/null path.
        drop(running.child.stdin.take());
        reset_executable?;
        reset_cwd?;
        if let Err(error) = await_startup(startup_read.into(), deadline) {
            let _ = process::kill_process_group(pid(&running.child)?, Signal::KILL);
            let _ = running.child.kill();
            killed_status(&mut running.child)?;
            return Err(error);
        }
        if !tty {
            if let Some(stdout) = running.child.stdout.take() {
                running.output.push(File::from(OwnedFd::from(stdout)));
            }
            if let Some(stderr) = running.child.stderr.take() {
                running.output.push(File::from(OwnedFd::from(stderr)));
            }
            for file in &running.output {
                nonblock(file)?;
            }
        }
        Ok(running)
    }
    fn signals(&mut self) -> Result<()> {
        let Some(fd) = &self.signals else {
            return Ok(());
        };
        for _ in 0..MAX_REAP_BATCH {
            let mut record = [0; 128];
            match rustix::io::read(fd, &mut record) {
                Ok(128) => {
                    let number = u32::from_ne_bytes(
                        record
                            .get(..4)
                            .ok_or(Error::Io)?
                            .try_into()
                            .map_err(|_| Error::Io)?,
                    );
                    let signal = match number as i32 {
                        libc::SIGTERM => Some(Signal::TERM),
                        libc::SIGINT => Some(Signal::INT),
                        libc::SIGHUP => Some(Signal::HUP),
                        _ => None,
                    };
                    if let Some(signal) = signal {
                        self.forward_termination(signal)?;
                    }
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(rustix::io::Errno::INTR) => continue,
                _ => return Err(Error::Io),
            }
        }
        Ok(())
    }
    fn forward_termination(&self, signal: Signal) -> Result<()> {
        if let Some(target) = self
            .foreground
            .or_else(|| self.entry.as_ref().and_then(|e| pid(&e.child).ok()))
        {
            if let Err(e) = process::kill_process_group(target, signal) {
                if e != rustix::io::Errno::SRCH {
                    return Err(e.into());
                }
                // The helper may not have reached setsid yet.
                match process::kill_process(target, signal) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }
    fn reap(&mut self) -> Result<()> {
        // Only PID 1 uses this path. Skip managed children so std::Child
        // retains their exit statuses even while orphan zombies are reaped.
        let children = self.root()?.proc.children()?;
        self.reap_children(&children)
    }
    fn reap_children(&mut self, children: &[u8]) -> Result<()> {
        let children = std::str::from_utf8(children).map_err(|_| Error::Io)?;
        for (count, raw) in children.split_ascii_whitespace().enumerate() {
            if count >= MAX_REAP_BATCH {
                return Err(Error::Limit);
            }
            let child = raw
                .parse::<i32>()
                .ok()
                .and_then(Pid::from_raw)
                .ok_or(Error::Io)?;
            if !self.terminating
                && (Some(child) == self.foreground
                    || self.entry.as_ref().and_then(|e| pid(&e.child).ok()) == Some(child))
            {
                continue;
            }
            match process::waitpid(Some(child), WaitOptions::NOHANG) {
                Ok(_) | Err(rustix::io::Errno::CHILD) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn no_other_processes(&mut self) -> Result<bool> {
        self.reap()?;
        self.no_userspace_processes(&self.root()?.proc.dir)
    }
    fn no_userspace_processes(&self, proc: &OwnedFd) -> Result<bool> {
        let entries = fs::Dir::read_from(proc)?;
        for (count, entry) in entries.enumerate() {
            if count >= MAX_REAP_BATCH {
                return Err(Error::Limit);
            }
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name != b"1" && !name.is_empty() && name.iter().all(u8::is_ascii_digit) {
                let directory = match fs::openat2(
                    proc,
                    entry.file_name(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
                ) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::NOENT | rustix::io::Errno::SRCH) => continue,
                    Err(e) => return Err(e.into()),
                };
                let stat = match fs::openat(
                    &directory,
                    "stat",
                    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::NOENT | rustix::io::Errno::SRCH) => continue,
                    Err(e) => return Err(e.into()),
                };
                if fs::FileType::from_raw_mode(fs::fstat(&stat)?.st_mode)
                    != fs::FileType::RegularFile
                {
                    return Err(Error::Io);
                }
                let metadata = read_capped(File::from(stat), MAX_PROC_STAT)?;
                if !is_kernel_thread(&metadata, name)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

fn prepare_overlay(dir: &OwnedFd, lower: &OwnedFd) -> Result<()> {
    let lower_meta = fs::fstat(lower)?;
    for name in ["upper", "work"] {
        let created = match fs::mkdirat(dir, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(e.into()),
        };
        let before = fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if fs::FileType::from_raw_mode(before.st_mode) != fs::FileType::Directory {
            return Err(Error::Boot);
        }
        let directory = fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let after = fs::fstat(&directory)?;
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
            return Err(Error::Boot);
        }
        if name == "upper" && created {
            fs::fchown(
                &directory,
                Some(process::Uid::from_raw(lower_meta.st_uid)),
                Some(process::Gid::from_raw(lower_meta.st_gid)),
            )?;
            fs::fchmod(&directory, Mode::from_raw_mode(lower_meta.st_mode & 0o7777))?;
        } else if name == "work" {
            fs::fchmod(&directory, Mode::from_raw_mode(0o700))?;
        }
    }
    Ok(())
}

impl Sys for Linux {
    type FreezeHandle = OwnedFd;
    fn effect(&mut self, effect: Effect) -> Result<()> {
        match effect {
            Effect::Clock(clock) => {
                rustix::time::clock_settime(
                    rustix::time::ClockId::Realtime,
                    rustix::time::Timespec {
                        tv_sec: clock,
                        tv_nsec: 0,
                    },
                )?;
                self.guest_clock_set = true;
                self.root = Some(Root::open_root("/")?);
            }
            Effect::MountBaseReadOnly => {
                let source = self.root()?.node("/dev/vda", fs::FileType::BlockDevice)?;
                let target = self.root()?.directory("/mnt/hermetic-base")?;
                rustix::mount::mount(
                    fd_path(&source),
                    fd_path(&target),
                    "ext4",
                    rustix::mount::MountFlags::RDONLY | rustix::mount::MountFlags::NOSUID,
                    None,
                )?;
                self.base = Some(self.root()?.directory("/mnt/hermetic-base")?);
            }
            Effect::MountDisk(device) => {
                if self.base.is_none() {
                    let root = self.root()?.directory("/")?;
                    if !fs::fstatvfs(&root)?
                        .f_flag
                        .contains(fs::StatVfsMountFlags::RDONLY)
                    {
                        return Err(Error::Boot);
                    }
                }
                let source = self.root()?.node(&device, fs::FileType::BlockDevice)?;
                let target = self.root()?.directory("/mnt/hermetic-overlay")?;
                mount(&fd_path(&source), &fd_path(&target), "ext4", None)?;
            }
            Effect::PrepareOverlay => {
                let dir = self.root()?.directory("/mnt/hermetic-overlay")?;
                let root = self.root()?.directory("/")?;
                prepare_overlay(&dir, self.base.as_ref().unwrap_or(&root))?;
            }
            Effect::AssembleOverlay => {
                let root = self.root()?.directory("/")?;
                let lower = self.base.as_ref().unwrap_or(&root);
                let upper = self.root()?.directory("/mnt/hermetic-overlay/upper")?;
                let work = self.root()?.directory("/mnt/hermetic-overlay/work")?;
                let target = self.root()?.directory("/mnt/hermetic-root")?;
                let options = format!(
                    "lowerdir={},upperdir={},workdir={}",
                    fd_path(lower),
                    fd_path(&upper),
                    fd_path(&work)
                );
                mount("overlay", &fd_path(&target), "overlay", Some(&options))?;
            }
            Effect::MoveDev => {
                let source = self.root()?.directory("/dev")?;
                let target = self.root()?.directory("/mnt/hermetic-root/dev")?;
                rustix::mount::mount_move(fd_path(&source), fd_path(&target))?;
            }
            Effect::SwitchRoot => {
                let root = self.root()?.directory("/mnt/hermetic-root")?;
                process::fchdir(&root)?;
                rustix::mount::mount_move(".", "/")?;
                process::chroot(".")?;
                process::chdir("/")?;
                self.root = Some(self.root()?.reroot(root)?);
            }
            Effect::MountProc => self.mount_guest("proc", "/proc", "proc", None)?,
            Effect::MountSys => self.mount_guest("sysfs", "/sys", "sysfs", None)?,
            Effect::MountPts => self.mount_guest(
                "devpts",
                "/dev/pts",
                "devpts",
                Some("newinstance,ptmxmode=0666,mode=0620"),
            )?,
            Effect::MountShm => {
                self.mount_guest("tmpfs", "/dev/shm", "tmpfs", Some("size=64m,mode=1777"))?
            }
            Effect::StampDev(clock) => {
                let dev = self.root()?.directory("/dev")?;
                stamp_dev(&dev, clock)?;
            }
            Effect::ApplySpec => {}
            Effect::Listen(port) => {
                let fd = sys::vsock(port)?;
                rustix::net::listen(&fd, MAX_CONNECTIONS as i32)?;
                self.listener = Some(VsockListener(fd));
            }
            Effect::TermAll => {
                self.terminating = true;
                sys::kill_all(libc::SIGTERM)?;
            }
            Effect::KillAll => sys::kill_all(libc::SIGKILL)?,
            Effect::WaitAll(ms) => {
                let deadline = Instant::now() + Duration::from_millis(ms);
                while !self.no_other_processes()? {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Effect::Session => {
                process::setsid()?;
            }
            Effect::ControllingTerminal => process::ioctl_tiocsctty(std::io::stdin())?,
            Effect::MemoryLimit(memory) => process::setrlimit(
                process::Resource::As,
                process::Rlimit {
                    current: Some(memory),
                    maximum: Some(memory),
                },
            )?,
            Effect::CoreLimit => process::setrlimit(
                process::Resource::Core,
                process::Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )?,
            Effect::ClearSignalMask => sys::clear_signal_mask()?,
            Effect::ClearGroups => sys::clear_groups()?,
            Effect::Gid(gid) => sys::set_gid(gid)?,
            Effect::Uid(uid) => sys::set_uid(uid)?,
            Effect::Sync => {
                if !self.no_other_processes()? {
                    return Err(Error::Shutdown);
                }
                fs::sync();
            }
            Effect::PowerOff(reason) => {
                let _ = serial_failure(
                    reason,
                    self.guest_clock_set.then(now),
                    &mut std::io::stderr().lock(),
                );
                rustix::system::reboot(rustix::system::RebootCommand::PowerOff)?;
            }
        }
        Ok(())
    }
    fn keep_upper(&mut self) -> Result<OwnedFd> {
        // The running executable stays pinned across switch_root and hostile
        // overlay changes. /proc/self/exe is a kernel-owned magic link.
        self.helper = Some(self.root()?.proc.executable()?);
        self.root()?.directory("/mnt/hermetic-overlay")
    }
    fn freeze(&mut self, fd: &OwnedFd) -> Result<()> {
        sys::freeze(fd)?;
        Ok(())
    }
    fn load_spec(&mut self, path: &str) -> Result<RunSpec> {
        RunSpec::parse(self.root()?.regular(path)?)
    }
    fn apply(&mut self, spec: &RunSpec) -> Result<()> {
        spec.validate()?;
        self.effect(Effect::ApplySpec)?;
        self.signals = Some(sys::signals()?);
        let _ = self.root()?.directory(&spec.workdir)?;
        rustix::system::sethostname(spec.hostname.as_bytes())?;
        self.install_spec_files(spec)
    }
    fn start_entrypoint(&mut self, spec: &RunSpec) -> Result<()> {
        if self.entry.is_some() {
            return Err(Error::Limit);
        }
        let deadline = Instant::now() + Duration::from_millis(CHILD_START_TIMEOUT_MS);
        self.entry = Some(self.spawn(spec, &spec.initial_argv(), false, deadline)?);
        Ok(())
    }
    fn execute(
        &mut self,
        spec: &RunSpec,
        argv: &[String],
        tty: bool,
        timeout_ms: u64,
        output_cap: usize,
    ) -> Result<ExecReply> {
        if self.foreground.is_some()
            || timeout_ms == 0
            || timeout_ms > MAX_TIMEOUT_MS
            || output_cap > MAX_COMMAND_OUTPUT
        {
            return Err(Error::Limit);
        }
        // Startup consumes the same wall-clock budget as the requested program.
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let running = match self.spawn(spec, argv, tty, deadline) {
            Ok(running) => running,
            Err(Error::Timeout) => {
                return Ok(ExecReply {
                    code: None,
                    output: Vec::new(),
                    truncated: false,
                    timed_out: true,
                })
            }
            Err(error) => return Err(error),
        };
        self.supervise(running, deadline, output_cap)
    }

    fn upload(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let owner = self.upload_owner.ok_or(Error::Boot)?;
        self.root_mut()?
            .atomic_as(path, data, now(), Some(owner), Mode::RUSR | Mode::WUSR)
    }
    fn download(&mut self, path: &str) -> Result<Vec<u8>> {
        self.root()?.read(path, MAX_TRANSFER)
    }
    fn child(
        &mut self,
        spec: &RunSpec,
        argv: &[String],
        cwd: &File,
        executable: &File,
        tty: bool,
    ) -> Result<()> {
        crate::boot::run_child(self, spec, argv, cwd, executable, tty)
    }
    fn child_cwd(&mut self, cwd: &File) -> Result<()> {
        process::fchdir(cwd)?;
        Ok(())
    }
    fn exec_program(&mut self, executable: &File, argv: &[CString], env: &[CString]) -> Result<()> {
        rustix::io::fcntl_setfd(executable, rustix::io::FdFlags::empty())?;
        sys::exec(executable, argv, env)?;
        Err(Error::Io)
    }
    fn guest_time(&mut self) -> Result<i64> {
        if !self.guest_clock_set {
            return Err(Error::Boot);
        }
        Ok(now())
    }
    fn maintain(&mut self) -> Result<()> {
        self.signals()?;
        if let Some(entry) = &mut self.entry {
            let mut discarded = Vec::new();
            let mut truncated = false;
            drain(&mut entry.output, &mut discarded, 0, &mut truncated)?;
            if entry.child.try_wait()?.is_some() {
                self.entry = None;
            }
        }
        // Do not steal the status of an active managed child. Reap orphans by
        // selecting only children not owned by std::process::Child.
        self.reap()?;
        Ok(())
    }
}

fn allocate_pty(root: &Root) -> Result<(File, File)> {
    // Bind allocation to the devpts instance mounted during boot. The kernel's
    // earlier /dev/ptmx node can still refer to a different devpts instance.
    let pinned = root.node("/dev/pts/ptmx", fs::FileType::CharacterDevice)?;
    Ok(open_pty(root, &pinned)?)
}

fn open_pty(root: &Root, pinned: &OwnedFd) -> std::io::Result<(File, File)> {
    let master = root.proc.reopen(pinned, OFlags::RDWR | OFlags::NOCTTY)?;
    rustix::pty::unlockpt(&master)?;
    let slave = File::from(rustix::pty::ioctl_tiocgptpeer(
        &master,
        rustix::pty::OpenptFlags::RDWR
            | rustix::pty::OpenptFlags::CLOEXEC
            | rustix::pty::OpenptFlags::NOCTTY,
    )?);
    fs::fcntl_setfl(&master, fs::fcntl_getfl(&master)? | OFlags::NONBLOCK)?;
    Ok((master, slave))
}

fn killed_status(child: &mut Child) -> Result<std::process::ExitStatus> {
    let end = Instant::now() + Duration::from_millis(CHILD_KILL_WAIT_MS);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            return Err(Error::ChildStuck);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn drain(files: &mut [File], output: &mut Vec<u8>, cap: usize, truncated: &mut bool) -> Result<()> {
    drain_reads(files, output, cap, truncated, MAX_DRAIN_READS, false)
}
fn drain_reads(
    files: &mut [impl Read],
    output: &mut Vec<u8>,
    cap: usize,
    truncated: &mut bool,
    max_reads: usize,
    final_batch: bool,
) -> Result<()> {
    for file in files {
        // A continuously writing child must not prevent timeout/signal checks.
        for read in 0..max_reads {
            let mut buffer = [0; IO_BUFFER];
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let keep = n.min(cap.saturating_sub(output.len()));
                    output.extend_from_slice(buffer.get(..keep).ok_or(Error::Io)?);
                    *truncated |= keep < n;
                    // If final collection exhausts its work budget, conservatively
                    // report truncation rather than silently lose a pending tail.
                    *truncated |= final_batch && read + 1 == max_reads;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    break
                }
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break, // closed PTY
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}

/// Descriptor walk: NO_XDEV rejects even same-device bind mounts; O_PATH avoids
/// opening devices/FIFOs. EMPTY_PATH stamps the pinned inode, including symlinks.
pub fn stamp_dev(dev: &OwnedFd, clock: i64) -> Result<()> {
    fn walk(dir: &OwnedFd, clock: i64, count: &mut usize, depth: usize) -> Result<()> {
        if depth > MAX_DEV_DEPTH {
            return Err(Error::Limit);
        }
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            *count = count.checked_add(1).ok_or(Error::Limit)?;
            if *count > MAX_DEV_NODES {
                return Err(Error::Limit);
            }
            names.push(name.to_owned());
        }
        names.sort();
        for name in names {
            let _ = fs::statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW)?;
            let fd = match fs::openat2(
                dir,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::XDEV) => continue,
                Err(e) => return Err(e.into()),
            };
            let times = fs::Timestamps {
                last_access: rustix::time::Timespec {
                    tv_sec: clock,
                    tv_nsec: 0,
                },
                last_modification: rustix::time::Timespec {
                    tv_sec: clock,
                    tv_nsec: 0,
                },
            };
            fs::utimensat(
                &fd,
                "",
                &times,
                AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if fs::FileType::from_raw_mode(fs::fstat(&fd)?.st_mode) == fs::FileType::Directory {
                let child = fs::openat(
                    &fd,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                walk(&child, clock, count, depth + 1)?;
            }
        }
        crate::fs::stamp(dir, clock)
    }
    walk(dev, clock, &mut 0, 0)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildSpec {
    spec: RunSpec,
    argv: Vec<String>,
    tty: bool,
    executable: i32,
    cwd: i32,
    startup: i32,
}

// The helper announces that its error channel is armed, then CLOEXEC closes it
// only when the requested program starts. Every returning path sends failure.
fn await_startup(file: File, deadline: Instant) -> Result<()> {
    let mut stream = DeadlineStream::new(file, Duration::from_millis(CHILD_START_TIMEOUT_MS));
    stream.read_end = stream.read_end.min(deadline);
    let failure = |error: std::io::Error| {
        if error.kind() == std::io::ErrorKind::TimedOut {
            Error::Timeout
        } else {
            Error::Boot
        }
    };
    let mut byte = [0];
    stream.read_exact(&mut byte).map_err(failure)?;
    if byte != *b"H" {
        return Err(Error::Boot);
    }
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(Error::Boot),
        Err(error) => Err(failure(error)),
    }
}

/// The helper is the same pinned trusted executable, running single-threaded.
pub fn child_main(payload: &str) -> Result<()> {
    if payload.len() > MAX_CHILD_PAYLOAD {
        return Err(Error::Limit);
    }
    let child: ChildSpec = serde_json::from_str(payload).map_err(|_| Error::InvalidInput)?;
    if child.executable < 3
        || child.cwd < 3
        || child.startup < 3
        || child.executable == child.cwd
        || child.executable == child.startup
        || child.cwd == child.startup
    {
        return Err(Error::InvalidInput);
    }
    let mut startup = sys::inherited(child.startup)?;
    startup.write_all(b"H")?;
    let result = (|| {
        child.spec.validate()?;
        spec::args(&child.argv, false)?;
        let executable = sys::inherited(child.executable)?;
        let cwd = sys::inherited(child.cwd)?;
        if !executable.metadata()?.is_file() || !cwd.metadata()?.is_dir() {
            return Err(Error::InvalidInput);
        }
        Linux::default().child(&child.spec, &child.argv, &cwd, &executable, child.tty)
    })();
    let _ = startup.write_all(b"E");
    result
}

/// Static serial diagnostics only; pre-clock failures remain completely silent.
pub fn serial_failure(
    error: Error,
    guest_time: Option<i64>,
    writer: &mut impl Write,
) -> Result<()> {
    if let Some(time) = guest_time {
        writeln!(writer, "execd {time} {error}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::IsTerminal, os::unix::process::CommandExt};

    #[test]
    fn review_overlay_upper_inherits_lower_metadata_only_when_new() {
        let temp = tempfile::tempdir().unwrap();
        let lower_path = temp.path().join("lower");
        let overlay_path = temp.path().join("overlay");
        std::fs::create_dir(&lower_path).unwrap();
        std::fs::create_dir(&overlay_path).unwrap();
        let open = |path: &std::path::Path| {
            fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .unwrap()
        };
        let lower = open(&lower_path);
        let overlay = open(&overlay_path);
        for lower_gid in process::getgroups()
            .unwrap()
            .into_iter()
            .filter(|gid| *gid != process::getegid())
        {
            match fs::fchown(&lower, None, Some(lower_gid)) {
                Ok(()) => break,
                // User namespaces can expose unmapped supplementary groups.
                Err(rustix::io::Errno::INVAL) => continue,
                Err(error) => panic!("cannot prepare lower root group: {error}"),
            }
        }
        fs::fchmod(&lower, Mode::from_raw_mode(0o751)).unwrap();
        prepare_overlay(&overlay, &lower).unwrap();
        let upper = open(&overlay_path.join("upper"));
        let work = open(&overlay_path.join("work"));
        let lower_meta = fs::fstat(&lower).unwrap();
        let upper_meta = fs::fstat(&upper).unwrap();
        assert_eq!(
            (
                upper_meta.st_uid,
                upper_meta.st_gid,
                upper_meta.st_mode & 0o7777
            ),
            (
                lower_meta.st_uid,
                lower_meta.st_gid,
                lower_meta.st_mode & 0o7777
            )
        );
        assert_eq!(fs::fstat(&work).unwrap().st_mode & 0o777, 0o700);
        fs::fchmod(&upper, Mode::from_raw_mode(0o711)).unwrap();
        prepare_overlay(&overlay, &lower).unwrap();
        assert_eq!(fs::fstat(&upper).unwrap().st_mode & 0o777, 0o711);
    }

    fn deadline(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }
    fn run_spec() -> RunSpec {
        RunSpec::parse(br#"{"env":{},"workdir":"/","uid":1000,"gid":1000,"entrypoint":[],"command":[],"hostname":"world","resolv_conf":"nameserver 10.0.0.1\n","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1,"wall_time_s":1}}"#.as_slice()).unwrap()
    }
    #[test]
    fn descriptor_relative_helper_spawn_executes_the_pinned_inode() {
        let root = Root::open_root("/").unwrap();
        let program = std::fs::canonicalize("/bin/sh").unwrap();
        let helper = root.regular(program.to_str().unwrap()).unwrap();
        let mut command = Command::new(format!("./{}", helper.as_raw_fd()));
        command
            .args(["-c", "printf pinned-helper"])
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = sys::spawn_in(&mut command, &root.proc.fds).unwrap();
        assert!(killed_status(&mut child).unwrap().success());
        let output = read_capped(child.stdout.take().unwrap(), MAX_COMMAND_OUTPUT).unwrap();
        assert_eq!(output, b"pinned-helper");
        assert!(
            read_capped(child.stderr.take().unwrap(), MAX_COMMAND_OUTPUT)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn shutdown_ignores_kernel_threads_but_refuses_userspace_and_bad_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let write_stat = |id: u32, contents: &[u8]| {
            let dir = temp.path().join(id.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("stat"), contents).unwrap();
        };
        write_stat(1, b"1 (init) S 0 1 1 0 -1 0");
        write_stat(2, b"2 (kthreadd) S 0 0 0 0 -1 2097152");
        write_stat(3, b"3 (kworker ) 1) I 2 0 0 0 -1 2101312");
        let dir = fs::open(
            temp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let linux = Linux::default();
        assert!(linux.no_userspace_processes(&dir).unwrap());
        write_stat(4, b"4 (surviving task) S 1 4 4 0 -1 4194304");
        assert!(!linux.no_userspace_processes(&dir).unwrap());
        std::fs::remove_dir_all(temp.path().join("4")).unwrap();
        assert!(linux.no_userspace_processes(&dir).unwrap());
        write_stat(2, b"2 (kthreadd) S 0");
        assert_eq!(linux.no_userspace_processes(&dir), Err(Error::Io));
        write_stat(2, &vec![b'x'; MAX_PROC_STAT + 1]);
        assert_eq!(linux.no_userspace_processes(&dir), Err(Error::Limit));
        assert_eq!(
            is_kernel_thread(b"3 (fake) S 0 0 0 0 -1 2097152", b"2"),
            Err(Error::Io)
        );
        assert_eq!(
            is_kernel_thread(b"2 (fake) S 0 0 0 0 -1 18446744073709551616", b"2"),
            Err(Error::Io)
        );
    }
    #[test]
    fn uploads_use_command_owner_and_private_mode_resolver_is_readable() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("etc")).unwrap();
        let mut spec = run_spec();
        // The unprivileged fixture uses its own ids, exercising descriptor
        // ownership assignment without changing any process credentials.
        spec.uid = process::getuid().as_raw();
        spec.gid = process::getgid().as_raw();
        let mut linux = Linux {
            root: Some(Root::open_root(temp.path().to_str().unwrap()).unwrap()),
            ..Linux::default()
        };
        linux.install_spec_files(&spec).unwrap();
        linux.upload("/input", b"private input").unwrap();
        let upload = std::fs::metadata(temp.path().join("input")).unwrap();
        assert_eq!(upload.uid(), spec.uid);
        assert_eq!(upload.gid(), spec.gid);
        assert_eq!(upload.mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read(temp.path().join("input")).unwrap(),
            b"private input"
        );
        let resolver = std::fs::metadata(temp.path().join("etc/resolv.conf")).unwrap();
        assert_eq!(resolver.mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::read(temp.path().join("etc/resolv.conf")).unwrap(),
            spec.resolv_conf.as_bytes()
        );
        assert_eq!(
            linux.upload_owner,
            Some((
                process::Uid::from_raw(spec.uid),
                process::Gid::from_raw(spec.gid)
            ))
        );
        // An unprivileged test cannot give a file to another uid. Requiring
        // this failure proves the production upload actually applies the
        // declared owner, even when the successful fixture shares our ids.
        assert!(!process::geteuid().is_root());
        spec.uid = 0;
        linux.install_spec_files(&spec).unwrap();
        assert_eq!(linux.upload("/refused", b"private"), Err(Error::Io));
        assert!(!temp.path().join("refused").exists());
    }
    fn linux() -> Linux {
        Linux {
            root: Some(Root::open_root("/").unwrap()),
            ..Linux::default()
        }
    }
    fn fixture(script: &str) -> Running {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env_clear()
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let output = vec![
            File::from(OwnedFd::from(child.stdout.take().unwrap())),
            File::from(OwnedFd::from(child.stderr.take().unwrap())),
        ];
        for file in &output {
            nonblock(file).unwrap();
        }
        Running { child, output }
    }
    fn assert_reaped(pid: Pid) {
        assert!(matches!(
            process::waitpid(Some(pid), WaitOptions::NOHANG),
            Err(rustix::io::Errno::CHILD)
        ));
    }
    #[test]
    fn supervisor_captures_both_pipes_truncates_and_reaps() {
        let child = fixture("printf abcdefgh; printf ijklmnop >&2; exit 7");
        let id = pid(&child.child).unwrap();
        let result = linux().supervise(child, deadline(1000), 10).unwrap();
        assert_eq!(result.code, Some(7));
        assert_eq!(result.output.len(), 10);
        assert!(result.truncated);
        assert!(!result.timed_out);
        assert_reaped(id);
    }
    #[test]
    fn final_drain_preserves_buffered_tail_and_marks_exhaustion() {
        use std::io::{Seek, SeekFrom};
        let bytes = vec![b'x'; IO_BUFFER * (MAX_DRAIN_READS * 3)];
        let mut buffered = tempfile::tempfile().unwrap();
        buffered.write_all(&bytes).unwrap();
        buffered.seek(SeekFrom::Start(0)).unwrap();
        let mut child = fixture("exit 0");
        // Model a pipe enlarged by a child, already buffered when it exits.
        // Using a regular fixture avoids changing host-wide pipe settings.
        killed_status(&mut child.child).unwrap();
        child.output = vec![buffered];
        let reply = linux()
            .supervise(child, deadline(1000), MAX_COMMAND_OUTPUT)
            .unwrap();
        assert_eq!(reply.output, bytes);
        assert!(!reply.truncated);

        // Small reads can exhaust the work budget before the byte cap.
        struct SmallReads;
        impl Read for SmallReads {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                if let Some(first) = bytes.first_mut() {
                    *first = b'x';
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
        }
        let mut output = Vec::new();
        let mut truncated = false;
        drain_reads(
            &mut [SmallReads],
            &mut output,
            MAX_COMMAND_OUTPUT,
            &mut truncated,
            MAX_FINAL_DRAIN_READS,
            true,
        )
        .unwrap();
        assert!(truncated);
        assert_eq!(output.len(), MAX_FINAL_DRAIN_READS);
    }
    fn startup_pair() -> (File, File) {
        let (a, b) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        (a.into(), b.into())
    }
    #[test]
    fn startup_handshake_requires_armed_channel_and_exec_or_reports_failure_and_timeout() {
        for (bytes, expected) in [
            (b"H".as_slice(), Ok(())),
            (b"HE".as_slice(), Err(Error::Boot)),
            (b"".as_slice(), Err(Error::Boot)),
            (b"x".as_slice(), Err(Error::Boot)),
        ] {
            let (read, mut write) = startup_pair();
            write.write_all(bytes).unwrap();
            drop(write);
            assert_eq!(await_startup(read, deadline(1000)), expected);
        }
        let (read, mut write) = startup_pair();
        write.write_all(b"H").unwrap();
        assert_eq!(await_startup(read, deadline(10)), Err(Error::Timeout));
    }
    #[test]
    fn helper_reports_validation_failure_and_does_not_drop_credentials() {
        let (mut read, write) = startup_pair();
        let executable = tempfile::tempfile().unwrap();
        let cwd = File::open("/").unwrap();
        let mut spec = crate::spec::RunSpec::parse(
            br#"{"env":{},"workdir":"/","uid":1,"gid":1,"entrypoint":[],"command":[],"hostname":"world","resolv_conf":"","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1,"wall_time_s":1}}"#.as_slice()
        ).unwrap();
        spec.uid = u32::MAX;
        let payload = ChildSpec {
            spec,
            argv: vec!["/program".into()],
            tty: false,
            executable: executable.as_raw_fd(),
            cwd: cwd.as_raw_fd(),
            startup: write.as_raw_fd(),
        };
        assert_eq!(
            child_main(&serde_json::to_string(&payload).unwrap()),
            Err(Error::InvalidInput)
        );
        let mut bytes = [0; 2];
        read.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"HE");
        assert!(rustix::io::fcntl_getfd(&write)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
    }
    #[test]
    fn continuous_output_cannot_starve_timeout_and_zero_budget_still_reaps() {
        let child = fixture("while :; do printf 01234567890123456789; done");
        let id = pid(&child.child).unwrap();
        let start = Instant::now();
        let reply = linux().supervise(child, deadline(30), 0).unwrap();
        assert!(reply.timed_out);
        assert!(reply.truncated);
        assert!(reply.output.is_empty());
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_reaped(id);
    }
    #[test]
    fn signal_forwarding_targets_foreground_and_preserves_entrypoint() {
        let entry = fixture("while :; do :; done");
        let mut foreground = fixture("while :; do :; done");
        let foreground_pid = pid(&foreground.child).unwrap();
        let mut linux = linux();
        linux.entry = Some(entry);
        linux.foreground = Some(foreground_pid);
        linux.forward_termination(Signal::TERM).unwrap();
        let status = killed_status(&mut foreground.child).unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(linux
            .entry
            .as_mut()
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none());
        assert_reaped(foreground_pid);
        linux.foreground = None;
        linux.forward_termination(Signal::TERM).unwrap();
        killed_status(&mut linux.entry.as_mut().unwrap().child).unwrap();
    }
    #[test]
    fn reaper_handles_adopted_children_without_stealing_managed_statuses() {
        let mut orphan = fixture("exit 9");
        let orphan_pid = pid(&orphan.child).unwrap();
        let managed = fixture("exit 6");
        let managed_pid = pid(&managed.child).unwrap();
        // PID 1 receives the same child ids for adopted orphans. A host test
        // supplies a child directly, without modifying process-wide subreaping.
        let children = format!(
            "{} {}",
            orphan_pid.as_raw_nonzero(),
            managed_pid.as_raw_nonzero()
        );
        let mut linux = linux();
        linux.entry = Some(managed);
        for _ in 0..100 {
            linux.reap_children(children.as_bytes()).unwrap();
            if matches!(
                process::waitid(
                    process::WaitId::Pid(orphan_pid),
                    process::WaitIdOptions::EXITED
                        | process::WaitIdOptions::NOHANG
                        | process::WaitIdOptions::NOWAIT,
                ),
                Err(rustix::io::Errno::CHILD)
            ) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_reaped(orphan_pid);
        assert_eq!(
            killed_status(&mut linux.entry.as_mut().unwrap().child)
                .unwrap()
                .code(),
            Some(6)
        );
        // std::Child correctly observes that PID 1's orphan reaper owns this id.
        assert!(orphan.child.try_wait().is_err());
    }
    #[test]
    fn allocated_pty_has_real_terminal_and_output_is_drained() {
        let Some((master, slave)) = host_pty_fixture(|path| {
            // Hosts need not use the guest's ptmxmode=0666 devpts mount.
            // Preserve OS errors for the capability check before policy maps
            // them to the deliberately opaque Error::Io.
            let metadata = fs::statat(fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
            if fs::FileType::from_raw_mode(metadata.st_mode) == fs::FileType::Symlink {
                return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
            }
            let root = Root::open_root("/").map_err(std::io::Error::other)?;
            let pinned = root
                .node(path, fs::FileType::CharacterDevice)
                .map_err(std::io::Error::other)?;
            let available_pty = open_pty(&root, &pinned)?;
            if path == "/dev/pts/ptmx" {
                // Once the guest-style facility is available, failures in the
                // production allocator are defects, never reasons to skip.
                drop(available_pty);
                allocate_pty(&root).map_err(std::io::Error::other)
            } else {
                Ok(available_pty)
            }
        })
        .unwrap() else {
            return;
        };
        assert!(master.is_terminal());
        assert!(slave.is_terminal());
        let child = Command::new("/bin/sh")
            .args(["-c", "test -t 0 && test -t 1 && printf terminal"])
            .env_clear()
            .process_group(0)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave)
            .spawn()
            .unwrap();
        let reply = linux()
            .supervise(
                Running {
                    child,
                    output: vec![master],
                },
                deadline(1000),
                100,
            )
            .unwrap();
        assert_eq!(reply.code, Some(0));
        assert_eq!(reply.output, b"terminal");
    }

    fn host_pty_fixture<T>(
        mut probe: impl FnMut(&str) -> std::io::Result<T>,
    ) -> std::io::Result<Option<T>> {
        const HOST_PTY_DEVICES: [&str; 2] = ["/dev/pts/ptmx", "/dev/ptmx"];
        for path in HOST_PTY_DEVICES {
            match probe(path) {
                Ok(pty) => return Ok(Some(pty)),
                Err(error) => match error.raw_os_error() {
                    Some(
                        libc::EACCES
                        | libc::EPERM
                        | libc::ENOENT
                        | libc::ENODEV
                        | libc::ENXIO
                        | libc::ENOSYS
                        | libc::ENOTTY
                        | libc::EOPNOTSUPP
                        | libc::ELOOP,
                    ) => {}
                    _ => return Err(error),
                },
            }
        }
        eprintln!("SKIP PTY test: neither host PTY device can be verified and opened with the required ioctl support");
        Ok(None)
    }

    #[test]
    fn host_pty_fixture_skips_only_unavailable_facilities() {
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::ENOENT,
            libc::ENODEV,
            libc::ENXIO,
            libc::ENOSYS,
            libc::ENOTTY,
            libc::EOPNOTSUPP,
            libc::ELOOP,
        ] {
            assert_eq!(
                host_pty_fixture::<()>(|_| Err(std::io::Error::from_raw_os_error(errno))).unwrap(),
                None,
            );
        }
        for errno in [libc::EIO, libc::EINVAL, libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                host_pty_fixture::<()>(|_| Err(std::io::Error::from_raw_os_error(errno)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(errno),
            );
        }
        assert!(
            host_pty_fixture::<()>(|_| Err(std::io::Error::other(Error::InvalidInput))).is_err()
        );
        assert_eq!(
            host_pty_fixture(|_| Ok(b"terminal")).unwrap(),
            Some(b"terminal")
        );
    }

    #[test]
    fn host_pty_fixture_uses_available_host_device_without_hiding_allocation_defects() {
        let mut probed = Vec::new();
        let pty = host_pty_fixture(|path| {
            probed.push(path.to_owned());
            if path == "/dev/pts/ptmx" {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            } else {
                Ok(b"terminal")
            }
        })
        .unwrap();
        assert_eq!(pty, Some(b"terminal"));
        assert_eq!(probed, ["/dev/pts/ptmx", "/dev/ptmx"]);

        let mut calls = 0;
        let error = host_pty_fixture::<()>(|_| {
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(calls, 1);
    }
}
