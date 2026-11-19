use crate::fs::{open_image, PreparedJail};
use crate::{api, remaining, ApiRequest, Error, JailPlan, Result, ValidatedSpec};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const MAX_CAPTURE_BYTES: usize = 64 * 1024;
pub const MAX_CAPTURE_READ_PER_TICK: usize = 128 * 1024;
pub const MAX_CAPTURE_CALLS_PER_TICK: usize = 64;
pub const MAX_INHERITED_FDS: u64 = 1_048_576;
/// Privileged/process and transport effects are injectable. Implementations must
/// honour the supplied deadline, and kill on Drop, including failed starts.
pub trait Runner {
    /// Guest frequency policy is injectable for offline failure tests.
    fn tsc_khz(&self) -> Result<u64> {
        crate::plan::configured_tsc_khz()
    }
    fn spawn(
        &mut self,
        spec: &ValidatedSpec,
        plan: &JailPlan,
        jail: &PreparedJail,
        end: Instant,
    ) -> Result<()>;
    fn request(&mut self, socket: &str, request: &ApiRequest, end: Instant) -> Result<()>;
    fn exited(&mut self, end: Instant) -> Result<bool>;
    fn kill(&mut self, end: Instant) -> Result<()>;
    /// Bounded stdout (guest serial console) and stderr captures.
    fn console_output(&self) -> (Vec<u8>, Vec<u8>) {
        (Vec::new(), Vec::new())
    }
}

impl<R: Runner + ?Sized> Runner for Box<R> {
    fn tsc_khz(&self) -> Result<u64> {
        (**self).tsc_khz()
    }
    fn spawn(
        &mut self,
        spec: &ValidatedSpec,
        plan: &JailPlan,
        jail: &PreparedJail,
        end: Instant,
    ) -> Result<()> {
        (**self).spawn(spec, plan, jail, end)
    }
    fn request(&mut self, socket: &str, request: &ApiRequest, end: Instant) -> Result<()> {
        (**self).request(socket, request, end)
    }
    fn exited(&mut self, end: Instant) -> Result<bool> {
        (**self).exited(end)
    }
    fn kill(&mut self, end: Instant) -> Result<()> {
        (**self).kill(end)
    }
    fn console_output(&self) -> (Vec<u8>, Vec<u8>) {
        (**self).console_output()
    }
}
/// A pinned Python 3 interpreter used only for descriptor sanitation and exec.
/// Its path obeys the same no-symlink, ownership and mode rules as images.
pub struct ExecLauncher {
    interpreter: File,
}
impl ExecLauncher {
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self {
            interpreter: open_image(path)?,
        })
    }
}
#[derive(Default)]
pub struct JailerRunner {
    process: Option<OwnedProcess>,
    namespace: Option<File>,
    launcher: Option<ExecLauncher>,
    console: std::sync::Arc<std::sync::Mutex<CaptureData>>,
}
impl JailerRunner {
    pub fn new(python: &str) -> Result<Self> {
        Ok(Self {
            launcher: Some(ExecLauncher::open(python)?),
            ..Self::default()
        })
    }

    /// Diagnostics: bounded stdout (serial) and stderr captures.
    /// Retained after lifecycle failure cleanup kills and drops the process.
    pub fn console_output(&self) -> (Vec<u8>, Vec<u8>) {
        let data = self.console.lock().unwrap_or_else(|e| e.into_inner());
        (data.stdout.clone(), data.stderr.clone())
    }

    /// Diagnostics: serial console output (stdout).
    pub fn serial(&self) -> Vec<u8> {
        let data = self.console.lock().unwrap_or_else(|e| e.into_inner());
        data.stdout.clone()
    }
}
impl Runner for JailerRunner {
    fn spawn(
        &mut self,
        spec: &ValidatedSpec,
        plan: &JailPlan,
        jail: &PreparedJail,
        end: Instant,
    ) -> Result<()> {
        remaining(end, "spawn")?;
        jail.check_identity()?;
        if !rustix::process::geteuid().is_root() {
            return Err(Error::Validation("jailer runner requires root"));
        }
        let binary = open_image(&spec.spec().jail.jailer)?;
        let pin = crate::pin::BuildPin::configured()?;
        pin.verify(&binary, true, end)?;
        pin.verify(&jail.executable()?, false, end)?;
        let namespace = open_image(&format!("/run/netns/{}", spec.spec().jail.netns))?;
        let mut args = jail.pinned_jailer_args(plan);
        let namespace_path = format!("/proc/{}/fd/{}", std::process::id(), namespace.as_raw_fd());
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--" {
                break;
            }
            if args[i] == "--netns" {
                if i + 1 < args.len() {
                    args[i + 1] = namespace_path.clone();
                    i += 2;
                    continue;
                }
            } else if args[i] == "--new-pid-ns" {
                i += 1;
                continue;
            } else {
                i += 2;
                continue;
            }
            i += 1;
        }
        self.namespace = Some(namespace);
        let process = OwnedProcess::spawn(
            binary,
            &args,
            spec,
            self.launcher
                .as_ref()
                .ok_or(Error::Validation("configure pinned exec launcher"))?,
            end,
        )?;
        self.console = process.output._data.clone();
        self.process = Some(process);
        Ok(())
    }
    fn request(&mut self, socket: &str, request: &ApiRequest, end: Instant) -> Result<()> {
        api::call(socket, request, end).map(|_| ())
    }
    fn exited(&mut self, end: Instant) -> Result<bool> {
        match &mut self.process {
            Some(p) => p.exited(end),
            None => Ok(true),
        }
    }
    fn kill(&mut self, end: Instant) -> Result<()> {
        if let Some(p) = &mut self.process {
            p.kill(end)?;
        }
        self.process = None;
        Ok(())
    }
    fn console_output(&self) -> (Vec<u8>, Vec<u8>) {
        let data = self.console.lock().unwrap_or_else(|e| e.into_inner());
        (data.stdout.clone(), data.stderr.clone())
    }
}
/// Production configuration has no selector for this runner.
pub fn refuse_dev_unjailed() -> Result<()> {
    Err(Error::Validation(
        "DevUnjailed requires compile-time dev-unjailed feature and explicit development runner",
    ))
}
#[cfg(feature = "dev-unjailed")]
#[derive(Default)]
pub struct DevUnjailed {
    process: Option<OwnedProcess>,
    root: String,
    launcher: Option<ExecLauncher>,
    console: std::sync::Arc<std::sync::Mutex<CaptureData>>,
}
#[cfg(feature = "dev-unjailed")]
impl DevUnjailed {
    pub fn new(python: &str) -> Result<Self> {
        Ok(Self {
            launcher: Some(ExecLauncher::open(python)?),
            ..Self::default()
        })
    }

    /// Development diagnostics only: bounded stdout (serial) and stderr captures.
    /// Retained after lifecycle failure cleanup kills and drops the process.
    pub fn console_output(&self) -> (Vec<u8>, Vec<u8>) {
        let data = self.console.lock().unwrap_or_else(|e| e.into_inner());
        (data.stdout.clone(), data.stderr.clone())
    }
}
#[cfg(feature = "dev-unjailed")]
impl Runner for DevUnjailed {
    fn spawn(
        &mut self,
        spec: &ValidatedSpec,
        _plan: &JailPlan,
        jail: &PreparedJail,
        end: Instant,
    ) -> Result<()> {
        jail.check_identity()?;
        self.root = jail.root.descriptor_path("");
        // /proc/PID paths remain usable across the child's exec and are pinned
        // by the parent-held directory descriptor for the entire VM lifetime.
        self.root = self
            .root
            .replacen("/proc/self/", &format!("/proc/{}/", std::process::id()), 1);
        let args = vec!["--api-sock".into(), format!("{}api.socket", self.root)];
        let binary = jail.executable()?;
        crate::pin::BuildPin::configured()?.verify(&binary, false, end)?;
        let process = OwnedProcess::spawn(
            binary,
            &args,
            spec,
            self.launcher
                .as_ref()
                .ok_or(Error::Validation("configure pinned exec launcher"))?,
            end,
        )?;
        self.console = process.output._data.clone();
        self.process = Some(process);
        Ok(())
    }
    fn request(&mut self, socket: &str, request: &ApiRequest, end: Instant) -> Result<()> {
        let req = development_request(request, &self.root);
        api::call(socket, &req, end).map(|_| ())
    }
    fn exited(&mut self, end: Instant) -> Result<bool> {
        match &mut self.process {
            Some(p) => p.exited(end),
            None => Ok(true),
        }
    }
    fn kill(&mut self, end: Instant) -> Result<()> {
        if let Some(p) = &mut self.process {
            p.kill(end)?;
        }
        self.process = None;
        Ok(())
    }
    fn console_output(&self) -> (Vec<u8>, Vec<u8>) {
        let data = self.console.lock().unwrap_or_else(|e| e.into_inner());
        (data.stdout.clone(), data.stderr.clone())
    }
}
#[cfg(feature = "dev-unjailed")]
impl DevUnjailed {
    /// Development only: the first bytes (at most MAX_CAPTURE_BYTES) of
    /// Firecracker's stdout, which carries the guest serial console. Trusted
    /// disposable fixtures only; production runners never expose guest output.
    pub fn serial(&self) -> Vec<u8> {
        self.process
            .as_ref()
            .and_then(|p| p.output._data.lock().ok().map(|d| d.stdout.clone()))
            .unwrap_or_default()
    }
}
#[cfg(feature = "dev-unjailed")]
fn development_request(request: &ApiRequest, root: &str) -> ApiRequest {
    let mut req = request.clone();
    for key in [
        "kernel_image_path",
        "initrd_path",
        "path_on_host",
        "uds_path",
    ] {
        if let Some(path) = req
            .body
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
        {
            if let Some(value) = req.body.get_mut(key) {
                *value =
                    serde_json::Value::String(format!("{}{}", root, path.trim_start_matches('/')));
            }
        }
    }
    req
}
struct OwnedProcess {
    child: Child,
    // Pin the executable until the trampoline opens and executes it.
    _binary: File,
    output: OutputCapture,
    reaped: bool,
    pid: rustix::process::Pid,
    launcher_exited: bool,
}
#[derive(Default)]
struct CaptureData {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
struct OutputCapture {
    _data: std::sync::Arc<std::sync::Mutex<CaptureData>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
fn capture(reader: &mut impl Read, data: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0; 4096];
    let mut read = 0;
    for _ in 0..MAX_CAPTURE_CALLS_PER_TICK {
        if read >= MAX_CAPTURE_READ_PER_TICK {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                read += n;
                let keep = n.min(MAX_CAPTURE_BYTES.saturating_sub(data.len()));
                data.extend_from_slice(buffer.get(..keep).ok_or(Error::Io)?);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
impl OutputCapture {
    fn new(child: &mut Child) -> Result<Self> {
        let mut stdout = child.stdout.take().ok_or(Error::Io)?;
        let mut stderr = child.stderr.take().ok_or(Error::Io)?;
        for fd in [
            &stdout as &dyn std::os::fd::AsFd,
            &stderr as &dyn std::os::fd::AsFd,
        ] {
            let flags = rustix::fs::fcntl_getfl(fd)?;
            rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)?;
        }
        let data = std::sync::Arc::new(std::sync::Mutex::new(CaptureData::default()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_data = data.clone();
        let worker_stop = stop.clone();
        let worker = std::thread::Builder::new()
            .name("vmm-capture".into())
            .spawn(move || loop {
                let stopping = worker_stop.load(std::sync::atomic::Ordering::SeqCst);
                if let Ok(mut data) = worker_data.lock() {
                    let _ = capture(&mut stdout, &mut data.stdout);
                    let _ = capture(&mut stderr, &mut data.stderr);
                } else {
                    break;
                }
                if stopping {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            })?;
        Ok(Self {
            _data: data,
            stop,
            worker: Some(worker),
        })
    }
    fn finish(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for OutputCapture {
    fn drop(&mut self) {
        self.finish();
    }
}
impl OwnedProcess {
    fn spawn(
        binary: File,
        args: &[String],
        spec: &ValidatedSpec,
        launcher: &ExecLauncher,
        end: Instant,
    ) -> Result<Self> {
        remaining(end, "spawn")?;
        let meta = binary.metadata()?;
        if meta.mode() & 0o111 == 0 {
            return Err(Error::Validation("executable mode"));
        }
        let s = spec.spec();
        let mut command = Command::new(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            launcher.interpreter.as_raw_fd()
        ));
        command
            .args(["-I", "-S", "-c", include_str!("launch.py")])
            .arg(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                binary.as_raw_fd()
            ))
            .arg(meta.dev().to_string())
            .arg(meta.ino().to_string())
            .arg(s.limits.file_size_bytes.to_string())
            .arg(s.limits.open_files.to_string())
            .arg("firecracker")
            .args(args)
            .env_clear()
            .current_dir("/")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let output = match OutputCapture::new(&mut child) {
            Ok(output) => output,
            Err(error) => {
                let _ = kill_child_group(&mut child, end);
                return Err(error);
            }
        };
        let pid = rustix::process::Pid::from_raw(child.id().try_into().map_err(|_| Error::Io)?)
            .ok_or(Error::Io)?;
        let mut process = Self {
            child,
            _binary: binary,
            output,
            reaped: false,
            pid,
            launcher_exited: false,
        };
        if let Err(e) = remaining(end, "spawn") {
            let _ = process.kill(end);
            return Err(e);
        }
        Ok(process)
    }
    fn exited(&mut self, end: Instant) -> Result<bool> {
        remaining(end, "process-wait")?;
        if self.reaped {
            return Ok(true);
        }
        let pid = self.pid;
        if !self.launcher_exited {
            let options = rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT
                | rustix::process::WaitIdOptions::EXITED;
            if let Some(status) =
                rustix::process::waitid(rustix::process::WaitId::Pid(pid), options)?
            {
                if status.exit_status() == Some(0) {
                    let _ = self.child.try_wait();
                    self.launcher_exited = true;
                } else {
                    self.kill(end)?;
                    return Ok(true);
                }
            }
        }
        if self.launcher_exited {
            match rustix::process::test_kill_process_group(pid) {
                Ok(()) => Ok(false),
                Err(rustix::io::Errno::SRCH) => {
                    self.kill(end)?;
                    Ok(true)
                }
                Err(e) => Err(e.into()),
            }
        } else {
            Ok(false)
        }
    }
    fn kill(&mut self, end: Instant) -> Result<()> {
        if self.reaped {
            self.output.finish();
            return Ok(());
        }
        kill_child_group(&mut self.child, end)?;
        self.reaped = true;
        self.output.finish();
        Ok(())
    }
}
fn kill_child_group(child: &mut Child, end: Instant) -> Result<()> {
    let pid = rustix::process::Pid::from_raw(child.id().try_into().map_err(|_| Error::Io)?)
        .ok_or(Error::Io)?;
    match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => (),
        Err(e) => return Err(e.into()),
    }
    let _ = child.kill();
    loop {
        let child_done = child.try_wait()?.is_some();
        let group_done = match rustix::process::test_kill_process_group(pid) {
            Err(rustix::io::Errno::SRCH) => true,
            Ok(()) => false,
            Err(e) => return Err(e.into()),
        };
        if child_done && group_done {
            return Ok(());
        }
        std::thread::sleep(remaining(end, "hard-kill")?.min(Duration::from_millis(2)));
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if let Ok(end) = crate::deadline(Duration::from_secs(2)) {
            let _ = self.kill(end);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    fn spec() -> ValidatedSpec {
        VmSpec {
            id: "process-test".into(),
            role: Role::Extractor,
            index: 0,
            vcpus: 1,
            memory_mib: 128,
            kernel_image: "/kernel".into(),
            initrd: None,
            boot_args: "clocksource=tsc tsc=reliable hermetic.t=1 ro".into(),
            root_drive: Drive {
                id: "root".into(),
                path: "/rootfs".into(),
                read_only: true,
            },
            drives: vec![],
            reserved_drives: vec![],
            vsock: None,
            networks: vec![],
            cpu_template: "/template".into(),
            clock: Clock::Faked,
            limits: Limits {
                pids: 64,
                file_size_bytes: 1024 * 1024,
                open_files: 128,
            },
            jail: JailConfig {
                base: "/jails".into(),
                uid_start: 200000,
                gid_start: 200000,
                count: 16,
                firecracker: "/bin/firecracker".into(),
                jailer: "/bin/jailer".into(),
                netns: "isolated".into(),
            },
        }
        .validate()
        .unwrap()
    }
    fn binary() -> File {
        // Publish one immutable fixture before any process test can fork. A
        // concurrent fork can briefly inherit another thread's copy writer,
        // even with CLOEXEC, causing ETXTBSY when executing that inode.
        static BINARY: std::sync::OnceLock<(tempfile::TempDir, std::path::PathBuf)> =
            std::sync::OnceLock::new();
        let (_, path) = BINARY.get_or_init(|| {
            let temp = tempfile::tempdir().unwrap();
            let source = std::fs::canonicalize("/usr/bin/python3").unwrap();
            let path = temp.path().join("python");
            std::fs::copy(source, &path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
            (temp, path)
        });
        open_image(path.to_str().unwrap()).unwrap()
    }
    #[test]
    fn real_process_clears_environment_closes_descriptors_and_owns_group() {
        let held = File::open("/dev/null").unwrap();
        // Give the launcher an intentionally inheritable descriptor, without
        // modifying the parent's original descriptor flags.
        let inherited = rustix::io::fcntl_dupfd_cloexec(held.as_fd(), 256).unwrap();
        rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty()).unwrap();
        let raw = inherited.as_raw_fd();
        let code = format!(
            concat!(
                "import os,resource; ",
                "assert open('/proc/self/environ','rb').read(65536)==b''; ",
                "assert os.getpgrp()==os.getpid(); ",
                "assert not os.path.exists('/proc/self/fd/{}'); ",
                "assert resource.getrlimit(resource.RLIMIT_NOFILE)==(128,128); ",
                "assert resource.getrlimit(resource.RLIMIT_FSIZE)==(1048576,1048576); ",
                "assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0); ",
                "os.write(1,b'passed')"
            ),
            raw
        );
        let args = vec!["-I".into(), "-S".into(), "-c".into(), code];
        let end = crate::deadline(Duration::from_secs(3)).unwrap();
        let mut child = OwnedProcess::spawn(
            binary(),
            &args,
            &spec(),
            &ExecLauncher {
                interpreter: binary(),
            },
            end,
        )
        .unwrap();
        while !child.exited(end).unwrap() {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            child.child.try_wait().unwrap().unwrap().success(),
            "{}",
            String::from_utf8_lossy(&child.output._data.lock().unwrap().stderr)
        );
        assert_eq!(child.output._data.lock().unwrap().stdout, b"passed");
        assert!(child.output._data.lock().unwrap().stderr.is_empty());
    }
    #[test]
    fn output_capture_is_capped_and_silent_child_is_killed_on_drop() {
        let end = crate::deadline(Duration::from_secs(3)).unwrap();
        let code = "import os; os.write(1,b'a'*262144); os.write(2,b'b'*262144)";
        let args = vec!["-I".into(), "-S".into(), "-c".into(), code.into()];
        let mut child = OwnedProcess::spawn(
            binary(),
            &args,
            &spec(),
            &ExecLauncher {
                interpreter: binary(),
            },
            end,
        )
        .unwrap();
        while !child.exited(end).unwrap() {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            child.output._data.lock().unwrap().stdout.len(),
            MAX_CAPTURE_BYTES
        );
        assert_eq!(
            child.output._data.lock().unwrap().stderr.len(),
            MAX_CAPTURE_BYTES
        );
        let args = vec![
            "-I".into(),
            "-S".into(),
            "-c".into(),
            "import time; time.sleep(60)".into(),
        ];
        let child = OwnedProcess::spawn(
            binary(),
            &args,
            &spec(),
            &ExecLauncher {
                interpreter: binary(),
            },
            end,
        )
        .unwrap();
        let pid = child.child.id();
        drop(child);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
    #[test]
    fn launcher_exit_keeps_surviving_vm_child_alive_until_stop_or_drop() {
        let end = crate::deadline(Duration::from_secs(3)).unwrap();
        // Model jailer --new-pid-ns: launcher forks a surviving VM child and exits 0.
        let code = "import os, time\npid = os.fork()\nif pid:\n    os.write(1, str(pid).encode())\n    os._exit(0)\nelse:\n    time.sleep(60)\n";
        let args = vec!["-I".into(), "-S".into(), "-c".into(), code.into()];
        let mut child = OwnedProcess::spawn(
            binary(),
            &args,
            &spec(),
            &ExecLauncher {
                interpreter: binary(),
            },
            end,
        )
        .unwrap();
        // Wait for the launcher process to exit 0 and write child pid.
        let mut pid = None;
        while Instant::now() < end {
            let data = child.output._data.lock().unwrap();
            if let Ok(s) = std::str::from_utf8(&data.stdout) {
                if let Ok(parsed) = s.trim().parse::<u32>() {
                    pid = Some(parsed);
                    break;
                }
            }
            drop(data);
            std::thread::sleep(Duration::from_millis(2));
        }
        let pid = pid.expect("launcher must write surviving child pid");
        // Readiness check: exited() must NOT report true and must NOT kill the surviving child!
        for _ in 0..10 {
            assert!(!child.exited(end).unwrap());
            std::thread::sleep(Duration::from_millis(5));
        }
        // Verify child is alive.
        let live = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .is_some_and(|s| {
                s.split_once(") ")
                    .is_some_and(|(_, tail)| !tail.starts_with('Z'))
            });
        assert!(live, "surviving VM child must be running");

        // Stop/drop must terminate the surviving child.
        child.kill(end).unwrap();
        assert!(child.exited(end).unwrap());

        // Verify child was terminated.
        loop {
            let live = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .is_some_and(|s| {
                    s.split_once(") ")
                        .is_some_and(|(_, tail)| !tail.starts_with('Z'))
                });
            if !live {
                break;
            }
            if Instant::now() >= end {
                rustix::process::kill_process(
                    rustix::process::Pid::from_raw(pid as i32).unwrap(),
                    rustix::process::Signal::KILL,
                )
                .unwrap();
                panic!("surviving VM child was not terminated by kill/stop");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    #[cfg(feature = "dev-unjailed")]
    #[test]
    fn trusted_reboot_development_rewrites_both_boot_files() {
        let request = ApiRequest::new(
            "PUT",
            "/boot-source",
            serde_json::json!({"kernel_image_path":"/kernel", "initrd_path":"/initrd", "boot_args":"hermetic.initramfs=1"}),
        );
        let rewritten = development_request(&request, "/proc/123/fd/7/");
        assert_eq!(
            rewritten.body,
            serde_json::json!({
                "kernel_image_path":"/proc/123/fd/7/kernel",
                "initrd_path":"/proc/123/fd/7/initrd",
                "boot_args":"hermetic.initramfs=1"
            })
        );
        assert_eq!(request.body["initrd_path"], "/initrd");
    }

    #[cfg(feature = "dev-unjailed")]
    #[test]
    fn dev_path_rewriting_uses_only_pinned_directory() {
        for (path, key, value) in [
            ("/boot-source", "kernel_image_path", "/kernel"),
            ("/drives/root", "path_on_host", "/drive-root"),
            ("/vsock", "uds_path", "/vsock"),
        ] {
            let request = ApiRequest::new("PUT", path, serde_json::json!({key:value}));
            let rewritten = development_request(&request, "/proc/123/fd/7/");
            assert_eq!(
                rewritten.body,
                serde_json::json!({key:format!("/proc/123/fd/7/{0}",value.trim_start_matches('/'))})
            );
            assert_eq!(request.body, serde_json::json!({key:value}));
        }
        let request = ApiRequest::new("PUT", "/entropy", serde_json::json!({}));
        assert_eq!(development_request(&request, "/proc/123/fd/7/"), request);
        // Malformed public request bodies cannot panic during path rewriting.
        let request = ApiRequest::new("PUT", "/entropy", serde_json::json!(1));
        assert_eq!(development_request(&request, "/proc/123/fd/7/"), request);
    }

    #[test]
    fn jailer_runner_console_output_bounded_and_retained() {
        let mut runner = JailerRunner::default();
        let (out, err) = runner.console_output();
        assert!(out.is_empty());
        assert!(err.is_empty());

        let capture_stdout = vec![b'x'; MAX_CAPTURE_BYTES];
        let capture_stderr = vec![b'y'; MAX_CAPTURE_BYTES];

        {
            let mut data = runner.console.lock().unwrap();
            data.stdout = capture_stdout.clone();
            data.stderr = capture_stderr.clone();
        }

        let (out, err) = runner.console_output();
        assert_eq!(out.len(), MAX_CAPTURE_BYTES);
        assert_eq!(err.len(), MAX_CAPTURE_BYTES);
        assert_eq!(runner.serial().len(), MAX_CAPTURE_BYTES);

        // Retained after kill
        let end = crate::deadline(Duration::from_secs(1)).unwrap();
        runner.kill(end).unwrap();
        let (out_after_kill, err_after_kill) = runner.console_output();
        assert_eq!(out_after_kill.len(), MAX_CAPTURE_BYTES);
        assert_eq!(err_after_kill.len(), MAX_CAPTURE_BYTES);

        // Box<dyn Runner> trait implementation
        let runner_box: Box<dyn Runner> = Box::new(runner);
        let (b_out, b_err) = runner_box.console_output();
        assert_eq!(b_out.len(), MAX_CAPTURE_BYTES);
        assert_eq!(b_err.len(), MAX_CAPTURE_BYTES);
    }
}
