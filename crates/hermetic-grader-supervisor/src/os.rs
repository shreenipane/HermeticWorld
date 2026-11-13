use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnSpec {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
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

/// Real operating system implementation built strictly on `std::process` and `std`
/// with `#![forbid(unsafe_code)]`.
///
/// # Limitations & Required Hardening for a Future Privileged Release
/// Because this implementation uses `std::process` only without `unsafe` FFI or external
/// system crates:
/// 1. **Namespaces**: A later version must enter isolated PID, mount, network, IPC, UTS,
///    and cgroup namespaces (`unshare` / `clone3`) before executing untrusted test code.
/// 2. **Capability Drop**: A later version must clear ambient/inheritable/permitted capabilities
///    and drop the capability bounding set (`prctl(PR_CAPBSET_DROP)` + `capset`) plus set
///    `PR_SET_NO_NEW_PRIVS`.
/// 3. **Device Cgroup**: A later version must attach the test process tree to a restrictive
///    cgroup v2 device controller denying raw block/char device access (specifically blocking
///    access to the result disk device until the supervisor writes it).
/// 4. **Dedicated Extra Pipe FD & Process Group Kill**: Safe `std::process::Command` only exposes
///    fds 0, 1, and 2 without `unsafe` `pre_exec`/`dup2`, so `RealOs` passes the result stream over
///    fd 2 (`stderr`, advertising `HERMETIC_RESULT_FD=2`) while discarding stdout. A later version
///    must `dup2` the result pipe onto a dedicated higher fd (such as fd 3) while keeping stderr
///    isolated, and issue `kill(-pgid, SIGKILL)` to terminate all descendants in the process group
///    rather than `Child::kill()` on the leader PID alone.
pub struct RealOs {
    epoch: Instant,
}

impl RealOs {
    /// Creates a new `RealOs` anchored at the current monotonic instant.
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for RealOs {
    fn default() -> Self {
        Self::new()
    }
}

/// Child handle managed by [`RealOs`].
pub struct RealChild {
    child: Child,
    pipe_rx: Receiver<Result<Vec<u8>, OsError>>,
    reader_thread: Option<JoinHandle<()>>,
    pipe_eof: bool,
    exited: Option<ExitKind>,
}

impl Drop for RealChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Os for RealOs {
    type Child = RealChild;

    fn now_monotonic(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn read_file(&mut self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, OsError> {
        let file = File::open(path).map_err(|e| OsError::Io {
            operation: "open",
            detail: format!("{}: {}", path.display(), e),
        })?;
        let mut buf = Vec::new();
        let limit = u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        file.take(limit)
            .read_to_end(&mut buf)
            .map_err(|e| OsError::Io {
                operation: "read",
                detail: format!("{}: {}", path.display(), e),
            })?;
        if buf.len() > max_bytes {
            return Err(OsError::FileTooLarge {
                size: buf.len(),
                max: max_bytes,
            });
        }
        Ok(buf)
    }

    fn spawn(&mut self, spec: &SpawnSpec) -> Result<Self::Child, OsError> {
        let (program, args) = spec.argv.split_first().ok_or(OsError::EmptyArgv)?;
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.current_dir(&spec.cwd);
        cmd.env_clear();
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        if !spec.env.contains_key("HERMETIC_RESULT_FD") {
            cmd.env("HERMETIC_RESULT_FD", "2");
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let mut child = cmd.spawn().map_err(|e| OsError::Io {
            operation: "spawn",
            detail: e.to_string(),
        })?;

        let mut stderr_pipe = child.stderr.take().ok_or_else(|| OsError::Io {
            operation: "take_pipe",
            detail: "child stderr pipe missing".to_string(),
        })?;

        let (tx, rx) = mpsc::sync_channel::<Result<Vec<u8>, OsError>>(REAL_OS_PIPE_CHANNEL_BOUND);
        let reader_thread = thread::spawn(move || {
            let mut buf = vec![0u8; MAX_PIPE_CHUNK_BYTES];
            for _ in 0..MAX_READ_STEPS {
                match stderr_pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = buf.get(..n).unwrap_or(&[]).to_vec();
                        if tx.send(Ok(chunk)).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = tx.send(Err(OsError::Io {
                            operation: "read_pipe",
                            detail: e.to_string(),
                        }));
                        break;
                    }
                }
            }
        });

        Ok(RealChild {
            child,
            pipe_rx: rx,
            reader_thread: Some(reader_thread),
            pipe_eof: false,
            exited: None,
        })
    }

    fn read_pipe(
        &mut self,
        child: &mut Self::Child,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<PipeRead, OsError> {
        if child.pipe_eof || max_bytes == 0 {
            return Ok(PipeRead::Eof);
        }
        let recv_res = if timeout.is_zero() {
            child.pipe_rx.try_recv().map_err(|e| match e {
                std::sync::mpsc::TryRecvError::Empty => RecvTimeoutError::Timeout,
                std::sync::mpsc::TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
            })
        } else {
            child.pipe_rx.recv_timeout(timeout)
        };

        match recv_res {
            Ok(Ok(mut data)) => {
                if data.len() > max_bytes {
                    data.truncate(max_bytes);
                }
                Ok(PipeRead::Data(data))
            }
            Ok(Err(err)) => Err(err),
            Err(RecvTimeoutError::Timeout) => Ok(PipeRead::WouldBlock),
            Err(RecvTimeoutError::Disconnected) => {
                child.pipe_eof = true;
                Ok(PipeRead::Eof)
            }
        }
    }

    fn kill_process_group(&mut self, child: &mut Self::Child) -> Result<(), OsError> {
        match child.child.kill() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
            Err(e) => Err(OsError::Io {
                operation: "kill_process_group",
                detail: e.to_string(),
            }),
        }
    }

    fn wait_tree(
        &mut self,
        child: &mut Self::Child,
        timeout: Duration,
    ) -> Result<TreeStatus, OsError> {
        if let Some(kind) = child.exited {
            return Ok(TreeStatus::Exited(kind));
        }
        match child.child.try_wait() {
            Ok(Some(status)) => {
                let kind = if status.code().is_some() {
                    ExitKind::Clean
                } else {
                    ExitKind::Crash
                };
                child.exited = Some(kind);
                if let Some(handle) = child.reader_thread.take() {
                    let _ = handle.join();
                }
                Ok(TreeStatus::Exited(kind))
            }
            Ok(None) => {
                let sleep_for = timeout.min(Duration::from_millis(POLL_INTERVAL_MS));
                if !sleep_for.is_zero() {
                    thread::sleep(sleep_for);
                }
                Ok(TreeStatus::Running)
            }
            Err(e) => Err(OsError::Io {
                operation: "wait_tree",
                detail: e.to_string(),
            }),
        }
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), OsError> {
        let is_special_device = match fs::metadata(path) {
            Ok(meta) => !meta.file_type().is_file(),
            Err(_) => false,
        };

        if is_special_device {
            let mut file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| OsError::Io {
                    operation: "open_device",
                    detail: format!("{}: {}", path.display(), e),
                })?;
            file.write_all(bytes).map_err(|e| OsError::Io {
                operation: "write_device",
                detail: format!("{}: {}", path.display(), e),
            })?;
            file.sync_all().map_err(|e| OsError::Io {
                operation: "sync_device",
                detail: format!("{}: {}", path.display(), e),
            })?;
            return Ok(());
        }

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("result-disk");
        let tmp_path = parent.join(format!(".{}.tmp", file_name));

        {
            let mut tmp_file = File::create(&tmp_path).map_err(|e| OsError::Io {
                operation: "create_temp",
                detail: format!("{}: {}", tmp_path.display(), e),
            })?;
            tmp_file.write_all(bytes).map_err(|e| OsError::Io {
                operation: "write_temp",
                detail: format!("{}: {}", tmp_path.display(), e),
            })?;
            tmp_file.sync_all().map_err(|e| OsError::Io {
                operation: "sync_temp",
                detail: format!("{}: {}", tmp_path.display(), e),
            })?;
        }

        fs::rename(&tmp_path, path).map_err(|e| OsError::Io {
            operation: "rename_atomic",
            detail: format!("{} -> {}: {}", tmp_path.display(), path.display(), e),
        })?;
        Ok(())
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
