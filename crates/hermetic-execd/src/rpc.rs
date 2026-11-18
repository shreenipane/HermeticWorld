use crate::fs::CommitGate;
use crate::{
    boot::{self, Booted, Effect, Sys},
    *,
};
use serde::de::DeserializeOwned;
use std::io::{Read, Write};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Exec {
        argv: Vec<String>,
        tty: bool,
        timeout_ms: u64,
    },
    Upload {
        path: String,
        data: Vec<u8>,
    },
    Download {
        path: String,
    },
    Status {},
    Shutdown {},
    /// Only the trusted host may release an initramfs boot.
    Authorize {},
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Exec {
                argv, timeout_ms, ..
            } => {
                spec::args(argv, false)?;
                if *timeout_ms == 0 || *timeout_ms > MAX_TIMEOUT_MS {
                    return Err(Error::InvalidInput);
                }
            }
            Self::Upload { path, data } => {
                spec::path(path)?;
                if data.len() > MAX_TRANSFER {
                    return Err(Error::Limit);
                }
            }
            Self::Download { path } => spec::path(path)?,
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecReply {
    pub code: Option<i32>,
    pub output: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Ok,
    Status {
        locked: bool,
        output_bytes: usize,
        guest_time_unix: i64,
    },
    Exec(ExecReply),
    Download {
        data: Vec<u8>,
    },
    Frozen,
    Error {
        reason: Error,
    },
}

/// u32 little endian length then strict JSON; lengths checked before allocation.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)
}
pub fn write_frame(value: &impl Serialize, writer: &mut impl Write) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidInput)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub trait Connection: Read + Write {
    /// After the complete frame is flushed, wait for peer consumption or a
    /// bounded transport linger before the VM can power off.
    fn drain_reply(&mut self) -> std::io::Result<()>;
}

pub trait Listener {
    type Stream: Connection;
    /// Nonblocking accept. Stream must enforce FRAME_TIMEOUT_MS for reads/writes.
    fn accept(&mut self) -> Result<Option<Self::Stream>>;
}

/// Filesystem operations the RPC server runs on its worker thread.
pub trait FsOps: Send {
    /// Must win `gate.begin_commit()` immediately before publishing.
    fn upload(&mut self, path: &str, data: &[u8], gate: &CommitGate) -> Result<()>;
    fn download(&mut self, path: &str) -> Result<Vec<u8>>;
}

enum FsJob {
    Upload { path: String, data: Vec<u8> },
    Download { path: String },
}
impl FsJob {
    fn from_request(request: Request) -> std::result::Result<Self, Request> {
        match request {
            Request::Upload { path, data } => Ok(Self::Upload { path, data }),
            Request::Download { path } => Ok(Self::Download { path }),
            other => Err(other),
        }
    }
}
fn run_job(ops: &mut dyn FsOps, job: FsJob, gate: &CommitGate) -> Result<Reply> {
    match job {
        FsJob::Upload { path, data } => {
            ops.upload(&path, &data, gate)?;
            Ok(Reply::Ok)
        }
        FsJob::Download { path } => {
            let data = ops.download(&path)?;
            if data.len() > MAX_TRANSFER {
                return Err(Error::Limit);
            }
            Ok(Reply::Download { data })
        }
    }
}

/// One filesystem worker: idle with its handle, or busy with one call. A busy
/// call is either still owed a reply (`answered == false`) or was abandoned
/// at its deadline. At most one filesystem call runs at a time.
enum FsSlot {
    Unopened,
    Inline,
    Idle(Box<dyn FsOps>),
    Busy {
        done: mpsc::Receiver<Result<Reply>>,
        worker: JoinHandle<Box<dyn FsOps>>,
        gate: Arc<CommitGate>,
        deadline: Instant,
        answered: bool,
    },
}

/// What `begin` did with a request.
enum Begun {
    Reply(Reply),
    /// A transfer is running on the worker; its reply comes from `poll_fs`.
    Pending,
}

pub struct Server<S: Sys> {
    pub sys: S,
    pub boot: Booted<S::FreezeHandle>,
    output: usize,
    stopped: bool,
    fs: FsSlot,
    fs_deadline: Duration,
}
impl<S: Sys> Server<S> {
    pub fn new(sys: S, boot: Booted<S::FreezeHandle>) -> Self {
        Self {
            sys,
            boot,
            output: 0,
            stopped: false,
            fs: FsSlot::Unopened,
            fs_deadline: Duration::from_millis(FS_OP_DEADLINE_MS),
        }
    }
    /// Shorter filesystem deadline (tests); never above `FS_OP_DEADLINE_MS`.
    pub fn set_fs_deadline(&mut self, deadline: Duration) {
        self.fs_deadline = deadline.min(Duration::from_millis(FS_OP_DEADLINE_MS));
    }
    /// Return an abandoned worker's handle to the slot once its thread ended.
    /// A worker that panicked is dropped; a fresh handle opens on the next call.
    fn reap_fs(&mut self) {
        let finished = matches!(
            &self.fs,
            FsSlot::Busy { worker, answered: true, .. } if worker.is_finished()
        );
        if finished {
            if let FsSlot::Busy { worker, .. } = std::mem::replace(&mut self.fs, FsSlot::Unopened) {
                if let Ok(ops) = worker.join() {
                    self.fs = FsSlot::Idle(ops);
                }
            }
        }
    }
    /// Start a transfer on the worker (or inline when the platform has none).
    fn start_fs(&mut self, job: FsJob) -> Result<Begun> {
        self.reap_fs();
        let mut ops = match std::mem::replace(&mut self.fs, FsSlot::Unopened) {
            busy @ FsSlot::Busy { .. } => {
                self.fs = busy;
                return Err(Error::Busy);
            }
            FsSlot::Idle(ops) => ops,
            FsSlot::Inline => {
                self.fs = FsSlot::Inline;
                return self.inline_job(job).map(Begun::Reply);
            }
            FsSlot::Unopened => match self.sys.fs_ops()? {
                Some(ops) => ops,
                None => {
                    self.fs = FsSlot::Inline;
                    return self.inline_job(job).map(Begun::Reply);
                }
            },
        };
        let deadline = Instant::now() + self.fs_deadline;
        let gate = Arc::new(CommitGate::with_deadline(deadline));
        let worker_gate = gate.clone();
        let (tx, done) = mpsc::sync_channel(1);
        // A download that completes after its deadline is a timeout, whenever
        // the loop gets to poll it (uploads are decided by the commit gate).
        let download = matches!(job, FsJob::Download { .. });
        let worker = std::thread::Builder::new()
            .name("execd-fs".into())
            .spawn(move || {
                let mut result = run_job(&mut *ops, job, &worker_gate);
                if download && Instant::now() >= deadline {
                    result = Err(Error::Timeout);
                }
                let _ = tx.send(result);
                ops
            })
            .map_err(|_| Error::Io)?;
        self.fs = FsSlot::Busy {
            done,
            worker,
            gate,
            deadline,
            answered: false,
        };
        Ok(Begun::Pending)
    }
    /// The pending transfer's reply, waiting at most `wait` (never past its
    /// deadline); `None` while it is still running before the deadline. At the
    /// deadline the call is cancelled (`timeout`) unless it had already begun
    /// publishing (`indeterminate`); it then stays busy until its thread ends.
    fn poll_fs(&mut self, wait: Duration) -> Option<Reply> {
        let FsSlot::Busy {
            done,
            gate,
            deadline,
            answered,
            ..
        } = &mut self.fs
        else {
            return None;
        };
        if *answered {
            return None;
        }
        let wait = wait.min(deadline.saturating_duration_since(Instant::now()));
        let (result, ended) = match done.recv_timeout(wait) {
            Ok(result) => (result, true),
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < *deadline => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => (
                Err(if gate.cancel() {
                    Error::Timeout
                } else {
                    Error::Indeterminate
                }),
                false,
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => (Err(Error::Io), true),
        };
        *answered = true;
        if ended {
            // The worker sent its result (or died) and is returning its handle.
            if let FsSlot::Busy { worker, .. } = std::mem::replace(&mut self.fs, FsSlot::Unopened) {
                if let Ok(ops) = worker.join() {
                    self.fs = FsSlot::Idle(ops);
                }
            }
        }
        Some(result.unwrap_or_else(|reason| Reply::Error { reason }))
    }
    fn inline_job(&mut self, job: FsJob) -> Result<Reply> {
        match job {
            FsJob::Upload { path, data } => {
                self.sys.upload(&path, &data)?;
                Ok(Reply::Ok)
            }
            FsJob::Download { path } => {
                let data = self.sys.download(&path)?;
                if data.len() > MAX_TRANSFER {
                    return Err(Error::Limit);
                }
                Ok(Reply::Download { data })
            }
        }
    }
    /// Before shutdown: true when no filesystem call is running. Never waits:
    /// a running call (owed a reply or abandoned) refuses shutdown at once, and
    /// a later shutdown succeeds after its thread ends.
    fn settle_fs(&mut self) -> bool {
        self.reap_fs();
        !matches!(self.fs, FsSlot::Busy { .. })
    }
    fn begin(&mut self, request: Request) -> Result<Begun> {
        request.validate()?;
        if self.stopped {
            return Err(Error::Shutdown);
        }
        match FsJob::from_request(request) {
            Ok(job) => self.start_fs(job),
            Err(request) => self.dispatch(request).map(Begun::Reply),
        }
    }
    fn dispatch(&mut self, request: Request) -> Result<Reply> {
        request.validate()?;
        if self.stopped {
            return Err(Error::Shutdown);
        }
        match request {
            Request::Status {} => Ok(Reply::Status {
                locked: self.boot.locked,
                output_bytes: self.output,
                guest_time_unix: self.sys.guest_time()?,
            }),
            Request::Authorize {} => {
                if self.boot.locked {
                    if !self.boot.spec.initial_argv().is_empty() {
                        if let Err(error) = self.sys.start_entrypoint(&self.boot.spec) {
                            self.stopped |= error == Error::ChildStuck;
                            return Err(error);
                        }
                    }
                    self.boot.locked = false;
                }
                Ok(Reply::Ok)
            }
            Request::Exec {
                argv,
                tty,
                timeout_ms,
            } => {
                if self.boot.locked {
                    return Err(Error::Locked);
                }
                let cap = MAX_COMMAND_OUTPUT.min(MAX_RUN_OUTPUT.saturating_sub(self.output));
                let result = self
                    .sys
                    .execute(&self.boot.spec, &argv, tty, timeout_ms, cap);
                if matches!(result, Err(Error::ChildStuck)) {
                    self.stopped = true;
                }
                let mut reply = result?;
                if reply.output.len() > cap {
                    reply.output.truncate(cap);
                    reply.truncated = true;
                }
                self.output = self.output.saturating_add(reply.output.len());
                Ok(Reply::Exec(reply))
            }
            // Transfers go through `begin`; reaching here is a server bug.
            Request::Upload { .. } | Request::Download { .. } => Err(Error::InvalidInput),
            Request::Shutdown {} => {
                // Never sync or freeze under a filesystem call that is still
                // running: refuse instead of hanging (the host then tears the VM down).
                if !self.settle_fs() {
                    return Err(Error::Busy);
                }
                self.stopped = true;
                boot::shutdown(&mut self.sys, &self.boot.upper)?;
                Ok(Reply::Frozen)
            }
        }
    }
    /// One request per connection bounds both connection and command concurrency.
    /// A transfer is waited for here (up to its deadline); `run` instead keeps
    /// serving other connections while it is pending.
    /// Always power off after a shutdown attempt, even if the reply disconnects.
    pub fn serve_one(&mut self, stream: &mut impl Connection) -> Result<()> {
        let reply = match read_frame::<Request>(stream).and_then(|r| self.begin(r)) {
            Ok(Begun::Reply(reply)) => reply,
            Ok(Begun::Pending) => loop {
                if let Some(reply) = self.poll_fs(self.fs_deadline) {
                    break reply;
                }
            },
            Err(reason) => Reply::Error { reason },
        };
        self.respond(stream, &reply)
    }
    fn respond(&mut self, stream: &mut impl Connection, reply: &Reply) -> Result<()> {
        if self.stopped {
            self.abandon_pending_fs();
        }
        let mut written = write_frame(reply, stream);
        if self.stopped {
            if written.is_ok() {
                written = stream.drain_reply().map_err(Error::from);
            }
            self.sys.effect(Effect::PowerOff(Error::Shutdown))?;
        }
        written
    }
    /// The connection owed a transfer reply is gone (listener or maintenance
    /// error): cancel the call and mark it abandoned, so its worker is reaped
    /// when its thread ends instead of keeping the slot busy forever.
    fn abandon_pending_fs(&mut self) {
        if let FsSlot::Busy { gate, answered, .. } = &mut self.fs {
            if !*answered {
                gate.cancel();
                *answered = true;
            }
        }
    }
    pub fn run<L: Listener>(&mut self, listener: &mut L) -> Result<()> {
        let result = self.run_loop(listener);
        if result.is_err() {
            self.abandon_pending_fs();
        }
        result
    }
    fn run_loop<L: Listener>(&mut self, listener: &mut L) -> Result<()> {
        // At most one transfer connection waits for its worker reply; other
        // connections are served meanwhile, one request each, in order. The
        // reply is written when the loop next polls: a long Exec delays it (the
        // host's own deadline bounds that wait), but never lets a transfer
        // publish or return data after its deadline.
        let mut pending: Option<L::Stream> = None;
        while !self.stopped {
            self.sys.maintain()?;
            if pending.is_some() {
                if let Some(reply) = self.poll_fs(Duration::from_millis(1)) {
                    if let Some(mut stream) = pending.take() {
                        // A failed reply write only affects that connection.
                        let _ = self.respond(&mut stream, &reply);
                    }
                }
            }
            if let Some(mut stream) = listener.accept()? {
                let begun = read_frame::<Request>(&mut stream).and_then(|r| self.begin(r));
                let result = match begun {
                    Ok(Begun::Pending) => {
                        pending = Some(stream);
                        Ok(())
                    }
                    Ok(Begun::Reply(reply)) => self.respond(&mut stream, &reply),
                    Err(reason) => self.respond(&mut stream, &Reply::Error { reason }),
                };
                if self.stopped {
                    return result;
                }
            }
        }
        Ok(())
    }
}
