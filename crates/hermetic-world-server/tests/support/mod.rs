//! Bounded waiting helpers shared by the integration tests. Every wait on a
//! child process, a server thread or a client socket is bounded, so a
//! regression fails the test instead of hanging it until the run deadline.
#![allow(dead_code)]

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Upper bound for any single wait in a test.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// A child process that is killed and reaped when dropped, with bounded waits.
pub struct BoundedChild(pub Child);

impl Drop for BoundedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl BoundedChild {
    pub fn spawn(command: &mut Command) -> Self {
        BoundedChild(command.spawn().expect("spawn child"))
    }

    /// Wait for exit within `WAIT_TIMEOUT`; on timeout the child is killed and
    /// the test fails.
    pub fn wait_status(&mut self) -> ExitStatus {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        loop {
            if let Some(status) = self.0.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.0.kill();
                let _ = self.0.wait();
                panic!("child did not exit within {WAIT_TIMEOUT:?}");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn wait_code(&mut self) -> i32 {
        self.wait_status().code().expect("child exit code")
    }

    /// Kill the child and reap it (bounded: SIGKILL cannot be ignored).
    pub fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.wait_status();
    }
}

/// Run `command` to completion with bounded wait, capturing its output.
pub fn output_bounded(command: &mut Command) -> Output {
    let mut child = BoundedChild::spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let stdout = drain(child.0.stdout.take());
    let stderr = drain(child.0.stderr.take());
    let status = child.wait_status();
    Output {
        status,
        stdout: stdout
            .recv_timeout(WAIT_TIMEOUT)
            .expect("child stdout timeout"),
        stderr: stderr
            .recv_timeout(WAIT_TIMEOUT)
            .expect("child stderr timeout"),
    }
}

fn drain<R: Read + Send + 'static>(source: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut data = Vec::new();
        if let Some(mut source) = source {
            let _ = source.read_to_end(&mut data);
        }
        let _ = sender.send(data);
    });
    receiver
}

/// A thread whose join is bounded by `WAIT_TIMEOUT`.
pub struct BoundedThread<T> {
    receiver: mpsc::Receiver<T>,
    handle: JoinHandle<()>,
}

pub fn spawn_bounded<T, F>(f: F) -> BoundedThread<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = sender.send(f());
    });
    BoundedThread { receiver, handle }
}

impl<T> BoundedThread<T> {
    /// Join within `WAIT_TIMEOUT`. A panicking thread yields `Err` like
    /// `JoinHandle::join`; a thread that is still running fails the test (it
    /// is abandoned and ends with the test process).
    pub fn join(self) -> thread::Result<T> {
        match self.receiver.recv_timeout(WAIT_TIMEOUT) {
            Ok(value) => {
                let _ = self.handle.join();
                Ok(value)
            }
            Err(RecvTimeoutError::Disconnected) => match self.handle.join() {
                Err(panic) => Err(panic),
                Ok(()) => panic!("bounded thread ended without a result"),
            },
            Err(RecvTimeoutError::Timeout) => {
                panic!("thread did not finish within {WAIT_TIMEOUT:?}")
            }
        }
    }
}

/// Apply read and write timeouts so every blocking socket call is bounded.
pub fn bound_stream(stream: &UnixStream) {
    stream
        .set_read_timeout(Some(WAIT_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(WAIT_TIMEOUT))
        .expect("set write timeout");
}

/// `UnixStream::connect` with read and write timeouts applied.
pub fn connect<P: AsRef<Path>>(path: P) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    bound_stream(&stream);
    Ok(stream)
}

/// Create a private (0700) directory. Publication and endpoint reclaim refuse
/// directories writable by group or others, so test directories must not
/// depend on the umask (0002 leaves them group-writable).
pub fn create_private_dir<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

/// `create_dir_all` with every created directory private (0700).
pub fn create_private_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// `tempfile::tempdir()` honours the umask (0002 gives 0775); publication and
/// endpoint reclaim require a directory not writable by group or others.
pub fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}
