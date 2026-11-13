use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum bytes read from the child result pipe in a single `read_pipe` call.
pub const MAX_PIPE_CHUNK_BYTES: usize = 16 * 1024;

/// Maximum bytes allowed when reading a configuration or regular file via [`Os::read_file`].
pub const MAX_FILE_READ_BYTES: usize = 1024 * 1024;

/// Default polling interval in milliseconds when waiting on child exit without blocking past deadlines.
pub const POLL_INTERVAL_MS: u64 = 5;

/// Capacity of the bounded channel bridging the `RealOs` pipe reader thread and the supervisor loop.
pub const REAL_OS_PIPE_CHANNEL_BOUND: usize = 32;

/// Maximum chunk reads performed by the `RealOs` background pipe reader before closing.
pub const MAX_READ_STEPS: usize = 100_000;

/// Errors returned by [`Os`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsError {
    EmptyArgv,
    FileTooLarge {
        size: usize,
        max: usize,
    },
    Io {
        operation: &'static str,
        detail: String,
    },
    InvalidScript(String),
}

impl fmt::Display for OsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsError::EmptyArgv => write!(f, "spawn argv must not be empty"),
            OsError::FileTooLarge { size, max } => {
                write!(f, "file size {} exceeds cap of {} bytes", size, max)
            }
            OsError::Io { operation, detail } => write!(f, "OS {} failed: {}", operation, detail),
            OsError::InvalidScript(msg) => write!(f, "invalid fake OS script: {}", msg),
        }
    }
}

impl std::error::Error for OsError {}

/// Process launch specification passed to [`Os::spawn`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnSpec {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub sandbox: crate::sandbox::SandboxSettings,
    pub deadline_seconds: u64,
}

/// Result of attempting to read from the child's result pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeRead {
    Data(Vec<u8>),
    WouldBlock,
    Eof,
}

/// How a process tree terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// Process tree exited normally (any exit status code; exit codes are ignored by grading).
    Clean,
    /// Process tree terminated abnormally (e.g. fatal signal).
    Crash,
}

/// Status of the spawned child process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeStatus {
    Running,
    Exited(ExitKind),
}

/// Abstraction over all operating system effects required by the supervisor.
///
/// Every filesystem read/write, child process spawn, result-pipe read, process-group
/// kill, process-tree wait, and monotonic clock query goes through this trait.
pub trait Os {
    /// Opaque handle representing a spawned child process tree and its result pipe.
    type Child;

    /// Returns monotonic elapsed duration since supervisor startup.
    fn now_monotonic(&self) -> Duration;

    /// Reads up to `max_bytes` from `path`. Fails if the file exceeds `max_bytes`.
    fn read_file(&mut self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, OsError>;

    /// Read the fixed-size host boot input. Never forwarded to a sandbox helper.
    fn read_run_label(&mut self, path: &Path) -> Result<crate::RunName, OsError> {
        let image = self.read_file(path, crate::RESULT_DISK_BYTES)?;
        crate::label::decode_run_label(&image).ok_or_else(|| os_error("run_label", "invalid"))
    }

    /// Spawns a child process in a new process group with `argv`, `env`, `cwd`,
    /// and an attached result pipe.
    fn spawn(&mut self, spec: &SpawnSpec) -> Result<Self::Child, OsError>;

    /// Reads up to `max_bytes` from the child's result pipe, waiting at most `timeout`.
    fn read_pipe(
        &mut self,
        child: &mut Self::Child,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<PipeRead, OsError>;

    /// Sends a termination signal to the entire process group of `child`.
    fn kill_process_group(&mut self, child: &mut Self::Child) -> Result<(), OsError>;

    /// Polls or waits up to `timeout` for the entire process tree rooted at `child` to exit.
    fn wait_tree(
        &mut self,
        child: &mut Self::Child,
        timeout: Duration,
    ) -> Result<TreeStatus, OsError>;

    /// Writes `bytes` to `path` atomically (write temp file + fsync + rename, or direct sync
    /// if `path` is a pre-existing block/special device).
    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), OsError>;
}

/// Linux execution with a fresh single-threaded namespace helper.
pub struct RealOs {
    epoch: Instant,
    launcher: Option<PathBuf>,
}
impl RealOs {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            launcher: None,
        }
    }
    /// Select the trusted supervisor executable (also used by integration tests).
    pub fn with_launcher(path: PathBuf) -> Self {
        Self {
            epoch: Instant::now(),
            launcher: Some(path),
        }
    }
}
impl Default for RealOs {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RealChild {
    child: Child,
    pipe: Option<ChildStdout>,
    init: Option<OwnedFd>,
    exited: Option<ExitKind>,
}
fn os_error(operation: &'static str, _: impl std::fmt::Display) -> OsError {
    OsError::Io {
        operation,
        detail: "operation refused".into(),
    }
}
fn group_pid(child: &Child) -> Result<rustix::process::Pid, OsError> {
    rustix::process::Pid::from_raw(i32::try_from(child.id()).map_err(|e| os_error("pid", e))?)
        .ok_or_else(|| os_error("pid", "invalid"))
}
fn kill_group(child: &Child) -> Result<(), OsError> {
    match rustix::process::kill_process_group(group_pid(child)?, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(e) => Err(os_error("kill_group", e)),
    }
}
fn init_done(child: &RealChild) -> Result<bool, OsError> {
    let Some(fd) = &child.init else {
        return Ok(true);
    };
    let mut poll = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
    rustix::event::poll(
        &mut poll,
        Some(&rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map(|n| n != 0)
    .map_err(|e| os_error("pidfd_poll", e))
}
impl Drop for RealChild {
    fn drop(&mut self) {
        if self.exited.is_none() {
            let _ = kill_group(&self.child);
            if let Some(init) = &self.init {
                let _ = rustix::process::pidfd_send_signal(init, rustix::process::Signal::KILL);
            }
            // Cleanup never blocks indefinitely on an uninterruptible process.
            for _ in 0..MAX_DROP_POLLS {
                if self.child.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
        }
    }
}
const MAX_DROP_POLLS: usize = 200;

impl Os for RealOs {
    type Child = RealChild;

    fn now_monotonic(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn read_run_label(&mut self, path: &Path) -> Result<crate::RunName, OsError> {
        // Only the fixed guest result device may be opened as a block device.
        // Offline callers use regular images with the same strict format.
        let kind = if path == Path::new("/dev/vdb") {
            rustix::fs::FileType::BlockDevice
        } else {
            rustix::fs::FileType::RegularFile
        };
        let file = crate::sandbox::open_path(path, rustix::fs::OFlags::RDONLY, kind)
            .map(File::from)
            .map_err(|e| os_error("open_run_label", e))?;
        let mut image = Vec::new();
        file.take((crate::RESULT_DISK_BYTES as u64).saturating_add(1))
            .read_to_end(&mut image)
            .map_err(|e| os_error("read_run_label", e))?;
        crate::label::decode_run_label(&image).ok_or_else(|| os_error("run_label", "invalid"))
    }

    fn read_file(&mut self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, OsError> {
        let cap = max_bytes.min(MAX_FILE_READ_BYTES);
        let file = crate::sandbox::open_path(
            path,
            rustix::fs::OFlags::RDONLY,
            rustix::fs::FileType::RegularFile,
        )
        .map(File::from)
        .map_err(|e| os_error("open_config", e))?;
        let mut buf = Vec::new();
        file.take(
            u64::try_from(cap)
                .map_err(|e| os_error("read_cap", e))?
                .saturating_add(1),
        )
        .read_to_end(&mut buf)
        .map_err(|e| os_error("read_config", e))?;
        if buf.len() > cap {
            return Err(OsError::FileTooLarge {
                size: buf.len(),
                max: cap,
            });
        }
        Ok(buf)
    }

    fn spawn(&mut self, spec: &SpawnSpec) -> Result<Self::Child, OsError> {
        crate::sandbox::build_plan(spec).map_err(|e| os_error("validate_sandbox", e))?;
        let launcher = match &self.launcher {
            Some(p) => p.clone(),
            None => std::env::current_exe().map_err(|e| os_error("launcher", e))?,
        };
        let (mut peer, socket) = UnixStream::pair().map_err(|e| os_error("socket", e))?;
        let timeout =
            crate::sandbox::STARTUP_TIMEOUT.min(Duration::from_secs(spec.deadline_seconds.max(1)));
        peer.set_read_timeout(Some(timeout))
            .map_err(|e| os_error("timeout", e))?;
        peer.set_write_timeout(Some(timeout))
            .map_err(|e| os_error("timeout", e))?;
        let fd: OwnedFd = socket.into();
        let child = Command::new(launcher)
            .arg("--sandbox-launch")
            .env_clear()
            .stdin(Stdio::from(fd))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|e| os_error("spawn", e))?;
        let mut handle = RealChild {
            child,
            pipe: None,
            init: None,
            exited: None,
        };
        handle.pipe = handle.child.stdout.take();
        crate::sandbox::write_spec(&mut peer, spec).map_err(|e| os_error("launch_input", e))?;
        let mut pid = [0; 4];
        peer.read_exact(&mut pid)
            .map_err(|e| os_error("launch_handshake", e))?;
        let pid = rustix::process::Pid::from_raw(
            i32::try_from(u32::from_le_bytes(pid)).map_err(|e| os_error("init_pid", e))?,
        )
        .ok_or_else(|| os_error("init_pid", "invalid"))?;
        handle.init = Some(
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                .map_err(|e| os_error("pin_init", e))?,
        );
        peer.write_all(&[1])
            .map_err(|e| os_error("launch_ack", e))?;
        let pipe = handle
            .pipe
            .as_ref()
            .ok_or_else(|| os_error("record_pipe", "missing"))?;
        rustix::fs::fcntl_setfl(pipe, rustix::fs::OFlags::NONBLOCK)
            .map_err(|e| os_error("nonblock", e))?;
        Ok(handle)
    }

    fn read_pipe(
        &mut self,
        child: &mut Self::Child,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<PipeRead, OsError> {
        let Some(pipe) = &mut child.pipe else {
            return Ok(PipeRead::Eof);
        };
        if max_bytes == 0 {
            return Ok(PipeRead::WouldBlock);
        }
        let timeout =
            rustix::time::Timespec::try_from(timeout.min(Duration::from_millis(POLL_INTERVAL_MS)))
                .map_err(|e| os_error("poll_timeout", e))?;
        let mut poll = [rustix::event::PollFd::new(
            &*pipe,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut poll, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => return Ok(PipeRead::WouldBlock),
            Err(e) => return Err(os_error("poll_pipe", e)),
            Ok(_) => {}
        }
        let mut data = vec![0; max_bytes.min(MAX_PIPE_CHUNK_BYTES)];
        match pipe.read(&mut data) {
            Ok(0) => {
                child.pipe = None;
                Ok(PipeRead::Eof)
            }
            Ok(n) => {
                data.truncate(n);
                Ok(PipeRead::Data(data))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(PipeRead::WouldBlock)
            }
            Err(e) => Err(os_error("read_pipe", e)),
        }
    }

    fn kill_process_group(&mut self, child: &mut Self::Child) -> Result<(), OsError> {
        if child.exited.is_some() {
            return Ok(());
        }
        if let Some(init) = &child.init {
            match rustix::process::pidfd_send_signal(init, rustix::process::Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(e) => return Err(os_error("kill_init", e)),
            }
        }
        kill_group(&child.child)
    }

    fn wait_tree(
        &mut self,
        child: &mut Self::Child,
        timeout: Duration,
    ) -> Result<TreeStatus, OsError> {
        use rustix::process::{self, WaitId, WaitIdOptions as W};
        if let Some(kind) = child.exited {
            return Ok(TreeStatus::Exited(kind));
        }
        // Do not reap before signaling the group: retaining the leader zombie
        // reserves its PID and prevents signals from reaching a recycled PGID.
        let status = process::waitid(
            WaitId::Pid(group_pid(&child.child)?),
            W::EXITED | W::NOHANG | W::NOWAIT,
        )
        .map_err(|e| os_error("waitid", e))?;
        if status.is_some() && init_done(child)? {
            kill_group(&child.child)?;
            let status = child
                .child
                .try_wait()
                .map_err(|e| os_error("reap", e))?
                .ok_or_else(|| os_error("reap", "missing"))?;
            let kind = if status.success() {
                ExitKind::Clean
            } else {
                ExitKind::Crash
            };
            child.exited = Some(kind);
            return Ok(TreeStatus::Exited(kind));
        }
        let delay = timeout.min(Duration::from_millis(POLL_INTERVAL_MS));
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        Ok(TreeStatus::Running)
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), OsError> {
        use rustix::fs::{self as fs, AtFlags, FileType, Mode, OFlags};
        if bytes.len() > crate::disk::RESULT_DISK_BYTES {
            return Err(os_error("write_cap", "too large"));
        }
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = crate::sandbox::open_path(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            FileType::Directory,
        )
        .map_err(|e| os_error("result_parent", e))?;
        let name = path
            .file_name()
            .ok_or_else(|| os_error("result_name", "missing"))?;
        match fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(meta) if FileType::from_raw_mode(meta.st_mode) == FileType::BlockDevice => {
                // The sole intentional special-file write is the result block
                // drive. Compare lstat and fstat on the pinned parent and reject links.
                let pinned =
                    crate::sandbox::open_at(&parent, name, OFlags::PATH, FileType::BlockDevice)
                        .map_err(|e| os_error("pin_result_drive", e))?;
                let after = fs::fstat(&pinned).map_err(|e| os_error("stat_result_drive", e))?;
                if after.st_dev != meta.st_dev
                    || after.st_ino != meta.st_ino
                    || FileType::from_raw_mode(after.st_mode) != FileType::BlockDevice
                {
                    return Err(os_error("result_drive_changed", "invalid"));
                }
                let fd = crate::sandbox::reopen_pin(&pinned, OFlags::WRONLY)
                    .map_err(|e| os_error("open_result_drive", e))?;
                let mut file = File::from(fd);
                file.write_all(bytes)
                    .map_err(|e| os_error("write_result_drive", e))?;
                return file
                    .sync_all()
                    .map_err(|e| os_error("sync_result_drive", e));
            }
            Ok(meta) if FileType::from_raw_mode(meta.st_mode) != FileType::RegularFile => {
                return Err(os_error("result_type", "invalid"))
            }
            Ok(_) | Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(os_error("result_stat", e)),
        }
        let mut temp = std::ffi::OsString::from(".");
        temp.push(name);
        temp.push(".tmp");
        let fd = fs::openat(
            &parent,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| os_error("create_result", e))?;
        let mut file = File::from(fd);
        let result = (|| {
            fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| os_error("mode_result", e))?;
            file.write_all(bytes)
                .map_err(|e| os_error("write_result", e))?;
            file.sync_all().map_err(|e| os_error("sync_result", e))?;
            fs::renameat(&parent, &temp, &parent, name)
                .map_err(|e| os_error("rename_result", e))?;
            fs::fsync(&parent).map_err(|e| os_error("sync_result_parent", e))
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&parent, &temp, AtFlags::empty());
        }
        result
    }
}

/// Chronological log of OS calls recorded by [`FakeOs`] for deterministic test assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsEvent {
    ReadFile(PathBuf),
    Spawn(SpawnSpec),
    ReadPipe(PipeRead),
    KillProcessGroup,
    WaitTree(TreeStatus),
    WriteFileAtomic { path: PathBuf, len: usize },
}

/// A scripted action for [`FakeOs`] child execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeStep {
    /// Emit bytes onto the result pipe.
    EmitBytes(Vec<u8>),
    /// Advance virtual time without emitting pipe data (simulates running/blocking work).
    Sleep(Duration),
    /// Close the result pipe (`PipeRead::Eof`).
    ClosePipe,
    /// Keep the process tree alive for `polls` calls to `wait_tree` before exiting.
    TreeRunningPolls(usize),
    /// Exit the entire process tree with `ExitKind` (also closes pipe if still open).
    ExitTree(ExitKind),
    /// Hang indefinitely until `kill_process_group` is invoked.
    HangForever,
}

/// Complete deterministic execution script for a [`FakeChild`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeChildScript {
    pub steps: VecDeque<FakeStep>,
    /// Number of `wait_tree` polls that still report `Running` after `kill_process_group`.
    pub post_kill_running_polls: usize,
}

impl FakeChildScript {
    /// Creates a script from an ordered list of [`FakeStep`] items.
    pub fn new(steps: Vec<FakeStep>) -> Self {
        Self {
            steps: steps.into(),
            post_kill_running_polls: 0,
        }
    }

    /// Sets how many `wait_tree` polls report `Running` after `kill_process_group`.
    pub fn with_post_kill_running_polls(mut self, polls: usize) -> Self {
        self.post_kill_running_polls = polls;
        self
    }
}

/// Child handle used by [`FakeOs`].
#[derive(Debug, Clone)]
pub struct FakeChild {
    steps: VecDeque<FakeStep>,
    pending_sleep: Duration,
    pending_running_polls: usize,
    post_kill_running_polls: usize,
    pipe_closed: bool,
    killed: bool,
    tree_exited: Option<ExitKind>,
}

/// Deterministic in-memory fake [`Os`] implementation for offline unit and integration tests.
#[derive(Debug, Clone)]
pub struct FakeOs {
    now: Duration,
    files: BTreeMap<PathBuf, Vec<u8>>,
    scripts: VecDeque<FakeChildScript>,
    events: Vec<OsEvent>,
    written_files: BTreeMap<PathBuf, Vec<u8>>,
    kill_count: usize,
}

impl FakeOs {
    /// Creates a new `FakeOs` with virtual clock at `Duration::ZERO`.
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            files: BTreeMap::new(),
            scripts: VecDeque::new(),
            events: Vec::new(),
            written_files: BTreeMap::new(),
            kill_count: 0,
        }
    }

    /// Inserts a virtual file readable by [`Os::read_file`].
    pub fn insert_file(&mut self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) {
        self.files.insert(path.into(), contents.into());
    }

    /// Enqueues a [`FakeChildScript`] to be consumed by the next [`Os::spawn`] call.
    pub fn push_child_script(&mut self, script: FakeChildScript) {
        self.scripts.push_back(script);
    }

    /// Returns all OS events recorded in exact chronological order.
    pub fn events(&self) -> &[OsEvent] {
        &self.events
    }

    /// Returns the bytes atomically written to `path`, if any.
    pub fn written_file(&self, path: &Path) -> Option<&[u8]> {
        self.written_files.get(path).map(Vec::as_slice)
    }

    /// Returns how many times [`Os::kill_process_group`] was called.
    pub fn kill_count(&self) -> usize {
        self.kill_count
    }

    /// Advances the virtual clock manually.
    pub fn advance_time(&mut self, delta: Duration) {
        self.now = self.now.saturating_add(delta);
    }
}

impl Default for FakeOs {
    fn default() -> Self {
        Self::new()
    }
}

impl Os for FakeOs {
    type Child = FakeChild;

    fn now_monotonic(&self) -> Duration {
        self.now
    }

    fn read_file(&mut self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, OsError> {
        self.events.push(OsEvent::ReadFile(path.to_path_buf()));
        let data = self.files.get(path).ok_or_else(|| OsError::Io {
            operation: "read_file",
            detail: format!("file not found: {}", path.display()),
        })?;
        if data.len() > max_bytes {
            return Err(OsError::FileTooLarge {
                size: data.len(),
                max: max_bytes,
            });
        }
        Ok(data.clone())
    }

    fn spawn(&mut self, spec: &SpawnSpec) -> Result<Self::Child, OsError> {
        if spec.argv.is_empty() {
            return Err(OsError::EmptyArgv);
        }
        self.events.push(OsEvent::Spawn(spec.clone()));
        let script = self
            .scripts
            .pop_front()
            .ok_or_else(|| OsError::InvalidScript("no scripted child available".to_string()))?;
        Ok(FakeChild {
            steps: script.steps,
            pending_sleep: Duration::ZERO,
            pending_running_polls: 0,
            post_kill_running_polls: script.post_kill_running_polls,
            pipe_closed: false,
            killed: false,
            tree_exited: None,
        })
    }

    fn read_pipe(
        &mut self,
        child: &mut Self::Child,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<PipeRead, OsError> {
        if child.pipe_closed || child.killed || max_bytes == 0 {
            child.pipe_closed = true;
            self.events.push(OsEvent::ReadPipe(PipeRead::Eof));
            return Ok(PipeRead::Eof);
        }

        if !child.pending_sleep.is_zero() {
            let advance = if timeout.is_zero() {
                Duration::ZERO
            } else {
                child.pending_sleep.min(timeout)
            };
            child.pending_sleep = child.pending_sleep.saturating_sub(advance);
            self.now = self.now.saturating_add(advance);
            self.events.push(OsEvent::ReadPipe(PipeRead::WouldBlock));
            return Ok(PipeRead::WouldBlock);
        }

        while let Some(step) = child.steps.pop_front() {
            match step {
                FakeStep::EmitBytes(mut bytes) => {
                    if bytes.len() > max_bytes {
                        let remainder = bytes.split_off(max_bytes);
                        child.steps.push_front(FakeStep::EmitBytes(remainder));
                    }
                    let res = PipeRead::Data(bytes);
                    self.events.push(OsEvent::ReadPipe(res.clone()));
                    return Ok(res);
                }
                FakeStep::Sleep(dur) => {
                    let advance = if timeout.is_zero() {
                        Duration::ZERO
                    } else {
                        dur.min(timeout)
                    };
                    child.pending_sleep = dur.saturating_sub(advance);
                    self.now = self.now.saturating_add(advance);
                    self.events.push(OsEvent::ReadPipe(PipeRead::WouldBlock));
                    return Ok(PipeRead::WouldBlock);
                }
                FakeStep::ClosePipe => {
                    child.pipe_closed = true;
                    self.events.push(OsEvent::ReadPipe(PipeRead::Eof));
                    return Ok(PipeRead::Eof);
                }
                FakeStep::TreeRunningPolls(polls) => {
                    child.pending_running_polls = child.pending_running_polls.saturating_add(polls);
                }
                FakeStep::ExitTree(kind) => {
                    child.pipe_closed = true;
                    if child.pending_running_polls == 0 {
                        child.tree_exited = Some(kind);
                    } else {
                        child.steps.push_front(FakeStep::ExitTree(kind));
                    }
                    self.events.push(OsEvent::ReadPipe(PipeRead::Eof));
                    return Ok(PipeRead::Eof);
                }
                FakeStep::HangForever => {
                    child.steps.push_front(FakeStep::HangForever);
                    self.now = self.now.saturating_add(timeout);
                    self.events.push(OsEvent::ReadPipe(PipeRead::WouldBlock));
                    return Ok(PipeRead::WouldBlock);
                }
            }
        }

        child.pipe_closed = true;
        if child.pending_running_polls == 0 && child.tree_exited.is_none() {
            child.tree_exited = Some(ExitKind::Clean);
        }
        self.events.push(OsEvent::ReadPipe(PipeRead::Eof));
        Ok(PipeRead::Eof)
    }

    fn kill_process_group(&mut self, child: &mut Self::Child) -> Result<(), OsError> {
        self.kill_count = self.kill_count.saturating_add(1);
        self.events.push(OsEvent::KillProcessGroup);
        child.killed = true;
        child.pipe_closed = true;
        child.steps.clear();
        child.pending_sleep = Duration::ZERO;
        if child.post_kill_running_polls == 0 {
            child.tree_exited = Some(ExitKind::Crash);
        } else {
            child.pending_running_polls = child.post_kill_running_polls;
        }
        Ok(())
    }

    fn wait_tree(
        &mut self,
        child: &mut Self::Child,
        timeout: Duration,
    ) -> Result<TreeStatus, OsError> {
        if let Some(kind) = child.tree_exited {
            let status = TreeStatus::Exited(kind);
            self.events.push(OsEvent::WaitTree(status));
            return Ok(status);
        }

        if child.pending_running_polls > 0 {
            child.pending_running_polls -= 1;
            self.now = self
                .now
                .saturating_add(timeout.min(Duration::from_millis(POLL_INTERVAL_MS)));
            if child.pending_running_polls == 0 {
                if child.killed {
                    child.tree_exited = Some(ExitKind::Crash);
                } else if let Some(&FakeStep::ExitTree(kind)) = child.steps.front() {
                    let _ = child.steps.pop_front();
                    child.tree_exited = Some(kind);
                } else if child.steps.is_empty() {
                    child.tree_exited = Some(ExitKind::Clean);
                }
            }
            let status = TreeStatus::Running;
            self.events.push(OsEvent::WaitTree(status));
            return Ok(status);
        }

        while let Some(step) = child.steps.pop_front() {
            match step {
                FakeStep::TreeRunningPolls(polls) if polls > 0 => {
                    child.pending_running_polls = polls - 1;
                    self.now = self
                        .now
                        .saturating_add(timeout.min(Duration::from_millis(POLL_INTERVAL_MS)));
                    if child.pending_running_polls == 0 && child.steps.is_empty() {
                        child.tree_exited = Some(ExitKind::Clean);
                    }
                    let status = TreeStatus::Running;
                    self.events.push(OsEvent::WaitTree(status));
                    return Ok(status);
                }
                FakeStep::TreeRunningPolls(_) => {}
                FakeStep::ExitTree(kind) => {
                    child.pipe_closed = true;
                    child.tree_exited = Some(kind);
                    let status = TreeStatus::Exited(kind);
                    self.events.push(OsEvent::WaitTree(status));
                    return Ok(status);
                }
                other => {
                    child.steps.push_front(other);
                    self.now = self
                        .now
                        .saturating_add(timeout.min(Duration::from_millis(POLL_INTERVAL_MS)));
                    let status = TreeStatus::Running;
                    self.events.push(OsEvent::WaitTree(status));
                    return Ok(status);
                }
            }
        }

        child.pipe_closed = true;
        child.tree_exited = Some(ExitKind::Clean);
        let status = TreeStatus::Exited(ExitKind::Clean);
        self.events.push(OsEvent::WaitTree(status));
        Ok(status)
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), OsError> {
        self.events.push(OsEvent::WriteFileAtomic {
            path: path.to_path_buf(),
            len: bytes.len(),
        });
        self.written_files
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod real_tests {
    use super::*;
    #[test]
    fn group_kill_stops_background_writers_offline() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("heartbeat");
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "while :; do printf x >> \"$MARKER\"; sleep 0.01; done & wait",
            ])
            .env_clear()
            .env("MARKER", &marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut handle = RealChild {
            child,
            pipe: None,
            init: None,
            exited: None,
        };
        for _ in 0..MAX_DROP_POLLS {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }
        assert!(marker.exists());
        let mut os = RealOs::new();
        os.kill_process_group(&mut handle).unwrap();
        let mut exited = false;
        for _ in 0..MAX_DROP_POLLS {
            if matches!(
                os.wait_tree(&mut handle, Duration::from_millis(POLL_INTERVAL_MS))
                    .unwrap(),
                TreeStatus::Exited(_)
            ) {
                exited = true;
                break;
            }
        }
        assert!(exited);
        let bytes = std::fs::read(&marker).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(std::fs::read(marker).unwrap(), bytes);
    }
}
