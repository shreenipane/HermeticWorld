use hermetic_execd::{
    boot::{self, Booted, Config, Effect, Sys},
    fs::{self as fs_gate, Root},
    real::{serial_failure, stamp_dev, DeadlineStream},
    rpc::{self, ExecReply, Listener, Reply, Request, Server},
    spec::{self, RunSpec, MAX_NETWORK_MTU, MIN_NETWORK_MTU},
    *,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs,
    io::{self, Cursor, Read, Write},
    os::unix::fs::{symlink, MetadataExt},
    rc::Rc,
    time::{Duration, Instant},
};

const SPEC: &str = r#"{"env":{"Z":"last","A":"first"},"workdir":"/work","uid":1000,"gid":1001,"entrypoint":["/service"],"command":["--serve"],"hostname":"world","resolv_conf":"nameserver 10.0.0.1\n","resources":{"vcpus":2,"memory_mib":512,"disk_mib":1024,"wall_time_s":300}}"#;
fn spec() -> RunSpec {
    RunSpec::parse(SPEC.as_bytes()).unwrap()
}
fn config() -> Config {
    Config::parse(b"ro hermetic.t=1700000000".as_slice()).unwrap()
}

#[derive(Default)]
struct Fake {
    events: Vec<String>,
    fail: Option<usize>,
    steps: usize,
    invalid_spec: bool,
    network: Option<spec::Network>,
    caps: Vec<usize>,
    commands: Vec<(RunSpec, Vec<String>, bool, u64)>,
    reaped: usize,
    output_size: usize,
    execute_error: Option<Error>,
    entry_error: Option<Error>,
    guest_clock: Option<i64>,
    uploaded: Vec<(String, Vec<u8>)>,
    trace: Option<Rc<RefCell<Vec<String>>>>,
    worker_fs: Option<WorkerFake>,
    exec_delay_ms: u64,
    release_after_exec: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    wait_commit_attempt: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    wait_finished_after_exec: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}
impl Fake {
    fn record(&mut self, event: String) -> Result<()> {
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(event.clone());
        }
        self.events.push(event);
        let step = self.steps;
        self.steps += 1;
        if self.fail == Some(step) {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }
}
impl Sys for Fake {
    type FreezeHandle = u32;
    fn child(
        &mut self,
        spec: &RunSpec,
        _: &[String],
        _: &std::fs::File,
        _: &std::fs::File,
        _: bool,
    ) -> Result<()> {
        boot::drop_privileges(self, spec)
    }
    fn effect(&mut self, effect: Effect) -> Result<()> {
        self.record(format!("{effect:?}"))
    }
    fn keep_upper(&mut self) -> Result<u32> {
        self.record("keep:313".into())?;
        Ok(313)
    }
    fn freeze(&mut self, handle: &u32) -> Result<()> {
        self.record(format!("freeze:{handle}"))
    }
    fn load_spec(&mut self, path: &str) -> Result<RunSpec> {
        self.record(format!("load:{path}"))?;
        let mut spec = spec();
        spec.network = self.network.clone();
        if self.invalid_spec {
            spec.workdir = "/work/../escape".into();
        }
        Ok(spec)
    }
    fn apply(&mut self, spec: &RunSpec) -> Result<()> {
        spec.validate()?;
        self.effect(Effect::ApplySpec)
    }
    fn configure_network(&mut self, spec: &RunSpec) -> Result<()> {
        network::configure(spec, |setup, argv| {
            self.execute(setup, argv, false, network::NETWORK_COMMAND_TIMEOUT_MS, 0)
        })
    }
    fn start_entrypoint(&mut self, spec: &RunSpec) -> Result<()> {
        self.record(format!("entry:{:?}", spec.initial_argv()))?;
        self.entry_error.map_or(Ok(()), Err)
    }
    fn execute(
        &mut self,
        spec: &RunSpec,
        argv: &[String],
        tty: bool,
        timeout_ms: u64,
        cap: usize,
    ) -> Result<ExecReply> {
        self.record("exec".into())?;
        if self.exec_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.exec_delay_ms));
        }
        if let Some(release) = &self.release_after_exec {
            release.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(attempted) = &self.wait_commit_attempt {
            WorkerFake::wait_for("the worker to attempt commit", || {
                attempted.load(std::sync::atomic::Ordering::SeqCst)
            });
        }
        if let Some(finished) = &self.wait_finished_after_exec {
            WorkerFake::wait_for("the worker to finish", || {
                finished.load(std::sync::atomic::Ordering::SeqCst) >= 1
            });
        }
        if let Some(error) = self.execute_error {
            return Err(error);
        }
        self.commands
            .push((spec.clone(), argv.to_vec(), tty, timeout_ms));
        self.caps.push(cap);
        // Deliberately return more than the cap: server must enforce its own
        // boundary even if the implementation supplies a larger reply.
        self.reaped += 1;
        Ok(ExecReply {
            code: Some(0),
            output: vec![b'x'; self.output_size],
            truncated: false,
            timed_out: false,
        })
    }
    fn upload(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.record("upload".into())?;
        self.uploaded.push((path.into(), data.to_vec()));
        Ok(())
    }
    fn download(&mut self, _: &str) -> Result<Vec<u8>> {
        self.record("download".into())?;
        Ok(vec![1; self.output_size])
    }
    fn fs_ops(&mut self) -> Result<Option<Box<dyn rpc::FsOps>>> {
        Ok(self
            .worker_fs
            .take()
            .map(|w| Box::new(w) as Box<dyn rpc::FsOps>))
    }
    fn guest_time(&mut self) -> Result<i64> {
        Ok(self.guest_clock.unwrap_or(1700000000))
    }
    fn child_cwd(&mut self, cwd: &std::fs::File) -> Result<()> {
        assert!(cwd.metadata().unwrap().is_dir());
        self.record("cwd".into())
    }
    fn exec_program(
        &mut self,
        executable: &std::fs::File,
        argv: &[std::ffi::CString],
        env: &[std::ffi::CString],
    ) -> Result<()> {
        assert!(executable.metadata().unwrap().is_file());
        self.record(format!("program:{argv:?}:{env:?}"))
    }
    fn maintain(&mut self) -> Result<()> {
        self.record("maintain".into())
    }
}

struct Pipe {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    fail_write: bool,
    trace: Option<Rc<RefCell<Vec<String>>>>,
}
impl Pipe {
    fn request(request: &Request) -> Self {
        let mut bytes = Vec::new();
        rpc::write_frame(request, &mut bytes).unwrap();
        Self::bytes(bytes)
    }
    fn bytes(bytes: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(bytes),
            output: Vec::new(),
            fail_write: false,
            trace: None,
        }
    }
    fn reply(&self) -> Reply {
        rpc::read_frame(&mut self.output.as_slice()).unwrap()
    }
}
impl Read for Pipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}
impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push("write".into());
        }
        if self.fail_write {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            self.output.write(bytes)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push("flush".into());
        }
        Ok(())
    }
}
impl rpc::Connection for Pipe {
    fn drain_reply(&mut self) -> io::Result<()> {
        // The in-memory writer has already delivered every byte.
        Ok(())
    }
}
type Published = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

const RELEASE_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// Send filesystem fake for the RPC worker: the next call can be made to hang
/// until released, before or after it wins the commit gate, and publishes only
/// after winning the gate (as `Root::atomic_cancellable`).
#[derive(Clone, Default)]
struct WorkerFake {
    published: Published,
    hang_next: std::sync::Arc<std::sync::atomic::AtomicBool>,
    hang_in_commit: std::sync::Arc<std::sync::atomic::AtomicBool>,
    release: std::sync::Arc<std::sync::atomic::AtomicBool>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    finished: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    entered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    committing: std::sync::Arc<std::sync::atomic::AtomicBool>,
    attempted_commit: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl WorkerFake {
    fn wait_release(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        self.running.store(true, SeqCst);
        let end = Instant::now() + RELEASE_WAIT_TIMEOUT;
        while !self.release.load(SeqCst) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.running.store(false, SeqCst);
    }
    /// Wait (bounded) until `flag` holds.
    fn wait_for(what: &str, flag: impl Fn() -> bool) {
        let end = Instant::now() + WAIT_DEADLINE;
        while !flag() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    /// Wait (bounded) until `n` calls have fully returned.
    fn wait_finished(&self, n: usize) {
        let end = Instant::now() + WAIT_DEADLINE;
        while self.finished.load(std::sync::atomic::Ordering::SeqCst) < n {
            assert!(Instant::now() < end, "worker call did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl rpc::FsOps for WorkerFake {
    fn upload(&mut self, path: &str, data: &[u8], gate: &fs_gate::CommitGate) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.entered.fetch_add(1, SeqCst);
        let in_commit = self.hang_in_commit.swap(false, SeqCst);
        if self.hang_next.swap(false, SeqCst) && !in_commit {
            self.wait_release();
        }
        self.attempted_commit.store(true, SeqCst);
        let result = if gate.begin_commit() {
            if in_commit {
                self.committing.store(true, SeqCst);
                self.wait_release();
            }
            self.published
                .lock()
                .unwrap()
                .push((path.into(), data.to_vec()));
            Ok(())
        } else {
            Err(Error::Timeout)
        };
        self.finished.fetch_add(1, SeqCst);
        result
    }
    fn download(&mut self, _: &str) -> Result<Vec<u8>> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.hang_next.swap(false, SeqCst) {
            self.wait_release();
        }
        self.finished.fetch_add(1, SeqCst);
        Ok(b"downloaded".to_vec())
    }
}
fn worker_server(deadline_ms: u64) -> (Server<Fake>, WorkerFake) {
    let worker = WorkerFake::default();
    let mut server = server(false);
    server.sys.worker_fs = Some(worker.clone());
    server.set_fs_deadline(Duration::from_millis(deadline_ms));
    (server, worker)
}
fn upload(path: &str, data: &[u8]) -> Request {
    Request::Upload {
        path: path.into(),
        data: data.to_vec(),
    }
}

fn server(locked: bool) -> Server<Fake> {
    Server::new(
        Fake::default(),
        Booted {
            upper: 313,
            spec: spec(),
            locked,
        },
    )
}
fn ask(server: &mut Server<Fake>, request: Request) -> Reply {
    let mut pipe = Pipe::request(&request);
    server.serve_one(&mut pipe).unwrap();
    pipe.reply()
}
fn exec(tty: bool, timeout_ms: u64) -> Request {
    Request::Exec {
        argv: vec!["/bin/program".into(), "arg".into()],
        tty,
        timeout_ms,
    }
}

#[test]
fn cmdline_strict_clock_bounds_defaults_and_initramfs() {
    assert_eq!(
        config(),
        Config {
            clock: 1700000000,
            overlay: "/dev/vdb".into(),
            spec: "/etc/hermetic/run-spec.json".into(),
            initramfs: false,
            agent_volume: None,
        }
    );
    for t in [
        "",
        "+1700000000",
        "-1",
        "1.0",
        "1700000000x",
        "315532799",
        "4102444800",
        "9999999999999999999999999",
    ] {
        assert_eq!(
            Config::parse(format!("hermetic.t={t}").as_bytes()),
            Err(Error::InvalidClock)
        );
    }
    for line in [
        "",
        "hermetic.t=1700000000 hermetic.t=1700000000",
        "hermetic.t",
        "hermetic.t=1700000000 hermetic.initramfs=2",
        "hermetic.t=1700000000 hermetic.spec=/a/../b",
        "hermetic.t=1700000000 hermetic.overlay=/dev/vdb hermetic.overlay=/dev/vdc",
        "hermetic.t=1700000000 hermetic.agent_volume=/dev/vdc hermetic.agent_volume=/dev/vdd",
        "hermetic.t=1700000000 hermetic.agent=/dev/vdc hermetic.agent_volume=/dev/vdd",
        "hermetic.t=1700000000 hermetic.agent_volume=/a/../b",
        "hermetic.t=1700000000 hermetic.unknown=1",
    ] {
        assert!(Config::parse(line.as_bytes()).is_err(), "{line}");
    }
    assert!(Config::parse(vec![b'a'; MAX_CMDLINE + 1].as_slice()).is_err());
    assert!(Config::parse(b"hermetic.t=315532800 hermetic.overlay=/dev/vdc hermetic.spec=/trusted/spec hermetic.initramfs=1".as_slice()).unwrap().initramfs);
    assert_eq!(
        Config::parse(b"hermetic.t=1700000000 hermetic.agent_volume=/dev/vdc".as_slice())
            .unwrap()
            .agent_volume,
        Some("/dev/vdc".into())
    );
    assert_eq!(
        Config::parse(b"hermetic.t=1700000000 hermetic.agent=/dev/vdc".as_slice())
            .unwrap()
            .agent_volume,
        Some("/dev/vdc".into())
    );
    assert!(Config::parse(b"hermetic.t=4102444799".as_slice()).is_ok());
    for line in [
        "hermetic.unknown=1",
        "hermetic.spec=relative hermetic.t=invalid",
        "hermetic.unknown=1 hermetic.t=1700000000 hermetic.t=1700000000",
    ] {
        let mut fake = Fake::default();
        assert!(matches!(
            boot::start(&mut fake, line.as_bytes()),
            Err(Error::InvalidClock)
        ));
        assert_eq!(fake.events, ["PowerOff(InvalidClock)"]);
    }
    for cfg in [
        Config {
            clock: 0,
            ..config()
        },
        Config {
            overlay: "/dev/../vdb".into(),
            ..config()
        },
        Config {
            spec: "relative".into(),
            ..config()
        },
        Config {
            agent_volume: Some("relative".into()),
            ..config()
        },
        Config {
            agent_volume: Some("/dev/../vdc".into()),
            ..config()
        },
    ] {
        let mut fake = Fake::default();
        assert!(boot::boot(&mut fake, &cfg).is_err());
        assert!(fake.events.is_empty());
    }
}

#[test]
fn boot_with_agent_volume_mounts_read_only_tools_disk() {
    let mut fake = Fake::default();
    let cfg = Config {
        agent_volume: Some("/dev/vdc".into()),
        ..config()
    };
    let booted = boot::boot(&mut fake, &cfg).unwrap();
    assert_eq!(booted.upper, 313);
    let mut expected = boot_answer();
    let idx = expected
        .iter()
        .position(|e| e.starts_with("load:"))
        .unwrap();
    expected.insert(idx, "MountAgentVolume(\"/dev/vdc\")".into());
    assert_eq!(fake.events, expected);
}

fn boot_answer() -> Vec<String> {
    [
        "Clock(1700000000)",
        "MountDisk(\"/dev/vdb\")",
        "keep:313",
        "PrepareOverlay",
        "AssembleOverlay",
        "MoveDev",
        "SwitchRoot",
        "MountProc",
        "MountSys",
        "MountPts",
        "MountShm",
        "StampDev(1700000000)",
        "load:/etc/hermetic/run-spec.json",
        "ApplySpec",
        "entry:[\"/service\", \"--serve\"]",
        "Listen(5000)",
    ]
    .map(String::from)
    .to_vec()
}
#[test]
fn boot_known_answer_no_tmp_or_run_tmpfs() {
    let mut fake = Fake::default();
    let boot = boot::boot(&mut fake, &config()).unwrap();
    assert_eq!(fake.events, boot_answer());
    assert_eq!(boot.upper, 313);
    // The exhaustive effect enum has only a /dev/shm tmpfs operation.
    assert!(!fake
        .events
        .iter()
        .any(|e| e.contains("/tmp") || e.contains("/run\"")));
}
#[test]
fn every_boot_failure_stops_later_effects_and_reports_reason() {
    let expected = boot_answer();
    for fail in 0..expected.len() {
        let mut fake = Fake {
            fail: Some(fail),
            ..Fake::default()
        };
        assert!(matches!(
            boot::start(&mut fake, b"hermetic.t=1700000000".as_slice()),
            Err(Error::Io)
        ));
        let mut prefix = expected[..=fail].to_vec();
        prefix.push("PowerOff(Io)".into());
        assert_eq!(fake.events, prefix);
    }
    let mut fake = Fake::default();
    assert!(matches!(
        boot::start(&mut fake, b"no-clock".as_slice()),
        Err(Error::InvalidClock)
    ));
    assert_eq!(fake.events, ["PowerOff(InvalidClock)"]);
    let mut fake = Fake {
        invalid_spec: true,
        ..Fake::default()
    };
    assert!(boot::boot(&mut fake, &config()).is_err());
    assert_eq!(
        fake.events.last().unwrap(),
        "load:/etc/hermetic/run-spec.json"
    );
}

#[test]
fn spec_strict_fields_caps_names_ids_paths_and_resources() {
    let s = spec();
    assert_eq!(s.env.keys().cloned().collect::<Vec<_>>(), ["A", "Z"]);
    let mut unknown: serde_json::Value = serde_json::from_str(SPEC).unwrap();
    unknown["unexpected"] = true.into();
    assert!(RunSpec::parse(unknown.to_string().as_bytes()).is_err());
    unknown.as_object_mut().unwrap().remove("unexpected");
    unknown["resources"]["unexpected"] = true.into();
    assert!(RunSpec::parse(unknown.to_string().as_bytes()).is_err());
    assert_eq!(
        RunSpec::parse(vec![b' '; MAX_SPEC + 1].as_slice()),
        Err(Error::Limit)
    );
    type Mutation = Box<dyn Fn(&mut RunSpec)>;
    let cases: Vec<Mutation> = vec![
        Box::new(|s| {
            s.env.insert("1INVALID".into(), "x".into());
        }),
        Box::new(|s| {
            s.env.insert("GOOD".into(), "secret\0hidden".into());
        }),
        Box::new(|s| {
            s.env.insert("GOOD".into(), "x".repeat(MAX_STRING + 1));
        }),
        Box::new(|s| {
            for n in 0..MAX_ENV + 1 {
                s.env.insert(format!("V{n}"), "x".into());
            }
        }),
        Box::new(|s| s.workdir = "relative".into()),
        Box::new(|s| s.workdir = "/a/./b".into()),
        Box::new(|s| s.workdir = "/a//b".into()),
        Box::new(|s| s.workdir = "/a/../b".into()),
        Box::new(|s| s.workdir = "/a/".into()),
        Box::new(|s| s.workdir = format!("/{}", "x".repeat(256))),
        Box::new(|s| s.uid = u32::MAX),
        Box::new(|s| s.gid = u32::MAX),
        Box::new(|s| s.entrypoint = vec!["relative".into()]),
        Box::new(|s| s.command = vec!["\0".into()]),
        Box::new(|s| s.command = vec!["x".into(); MAX_ARGS]),
        Box::new(|s| s.hostname = "-invalid".into()),
        Box::new(|s| s.hostname = "name\nsecret".into()),
        Box::new(|s| s.resolv_conf = "\0".into()),
        Box::new(|s| s.resources.vcpus = 0),
        Box::new(|s| s.resources.memory_mib = u64::MAX),
        Box::new(|s| s.resources.disk_mib = 0),
        Box::new(|s| s.resources.wall_time_s = 86401),
    ];
    for (n, mutation) in cases.into_iter().enumerate() {
        let mut s = s.clone();
        mutation(&mut s);
        assert!(s.validate().is_err(), "case {n}");
    }
    assert!(spec::args(&vec!["/long".repeat(100); MAX_ARGS], false).is_err());
    for json in [
        SPEC.replace(r#""uid":1000"#, r#""uid":-1"#),
        SPEC.replace(r#""gid":1001"#, r#""gid":"1001""#),
        SPEC.replace(r#""uid":1000"#, r#""uid":1.5"#),
        SPEC.replace(r#""Z":"last","A":"first""#, r#""A":"one","A":"two""#),
    ] {
        assert!(RunSpec::parse(json.as_bytes()).is_err());
    }
}

#[test]
fn credentials_drop_in_groups_gid_uid_order_and_stop_on_failure() {
    let mut fake = Fake::default();
    boot::drop_privileges(&mut fake, &spec()).unwrap();
    assert_eq!(fake.events, ["ClearGroups", "Gid(1001)", "Uid(1000)"]);
    for fail in 0..3 {
        let mut fake = Fake {
            fail: Some(fail),
            ..Fake::default()
        };
        assert!(boot::drop_privileges(&mut fake, &spec()).is_err());
        assert_eq!(fake.events.len(), fail + 1);
    }
    let mut invalid = spec();
    invalid.uid = u32::MAX;
    let mut fake = Fake::default();
    assert!(boot::drop_privileges(&mut fake, &invalid).is_err());
    assert!(fake.events.is_empty());
}

#[test]
fn exec_applies_spec_tty_timeout_and_both_output_caps_and_reaps() {
    let mut server = server(false);
    server.sys.output_size = MAX_COMMAND_OUTPUT + 10;
    for n in 0..18 {
        let Reply::Exec(reply) = ask(&mut server, exec(n % 2 == 0, 3000)) else {
            panic!("exec reply");
        };
        assert!(reply.truncated);
        assert_eq!(
            reply.output.len(),
            if n < 16 { MAX_COMMAND_OUTPUT } else { 0 }
        );
    }
    assert_eq!(server.sys.reaped, 18);
    assert_eq!(
        server.sys.commands.first().unwrap(),
        &(
            spec(),
            vec!["/bin/program".into(), "arg".into()],
            true,
            3000
        )
    );
    assert_eq!(server.sys.caps.last(), Some(&0));
    assert_eq!(
        ask(&mut server, Request::Status {}),
        Reply::Status {
            locked: false,
            output_bytes: MAX_RUN_OUTPUT,
            guest_time_unix: 1700000000
        }
    );
    for timeout in [0, MAX_TIMEOUT_MS + 1, u64::MAX] {
        assert!(matches!(
            ask(&mut server, exec(false, timeout)),
            Reply::Error { .. }
        ));
    }
    assert_eq!(server.sys.reaped, 18);
}

#[test]
fn stuck_child_is_terminal_and_never_claims_frozen_shutdown() {
    let mut server = server(false);
    server.sys.execute_error = Some(Error::ChildStuck);
    assert_eq!(
        ask(&mut server, exec(false, 100)),
        Reply::Error {
            reason: Error::ChildStuck
        }
    );
    assert_eq!(server.sys.events, ["exec", "PowerOff(Shutdown)"]);
    assert_eq!(
        ask(&mut server, Request::Shutdown {}),
        Reply::Error {
            reason: Error::Shutdown
        }
    );
    assert!(!server.sys.events.iter().any(|e| e.starts_with("freeze:")));
}

#[test]
fn stuck_authorization_child_is_terminal_and_cannot_launch_again() {
    let mut server = server(true);
    server.sys.entry_error = Some(Error::ChildStuck);
    assert_eq!(
        ask(&mut server, Request::Authorize {}),
        Reply::Error {
            reason: Error::ChildStuck
        }
    );
    assert_eq!(server.sys.events.last().unwrap(), "PowerOff(Shutdown)");
    assert!(server.boot.locked);
    server.sys.entry_error = None;
    for request in [
        Request::Authorize {},
        exec(false, 100),
        Request::Shutdown {},
    ] {
        assert_eq!(
            ask(&mut server, request),
            Reply::Error {
                reason: Error::Shutdown
            }
        );
    }
    assert_eq!(
        server
            .sys
            .events
            .iter()
            .filter(|e| e.starts_with("entry:"))
            .count(),
        1
    );
    assert!(!server.sys.events.iter().any(|e| e.starts_with("freeze:")));
}

#[test]
fn status_frame_supplies_vmm_guest_clock_schema() {
    // These are the fields required by hermetic-vmm/tests/guest.rs's decoder.
    #[derive(serde::Deserialize)]
    struct GuestStatus {
        #[serde(rename = "type")]
        kind: String,
        guest_time_unix: u64,
    }
    let mut server = server(false);
    let mut pipe = Pipe::request(&Request::Status {});
    server.serve_one(&mut pipe).unwrap();
    let status: GuestStatus = rpc::read_frame(&mut pipe.output.as_slice()).unwrap();
    assert_eq!(status.kind, "status");
    assert_eq!(status.guest_time_unix, 1700000000);
    let body = br#"{"type":"status","locked":false,"output_bytes":0,"guest_time_unix":1700000000}"#;
    let mut expected = (body.len() as u32).to_le_bytes().to_vec();
    expected.extend_from_slice(body);
    assert_eq!(pipe.output, expected);
    server.sys.guest_clock = Some(1700000017);
    let mut pipe = Pipe::request(&Request::Status {});
    server.serve_one(&mut pipe).unwrap();
    let status: GuestStatus = rpc::read_frame(&mut pipe.output.as_slice()).unwrap();
    assert_eq!(status.guest_time_unix, 1700000017);
}

#[test]
fn production_child_path_applies_cwd_environment_resources_and_credentials() {
    let cwd = std::fs::File::open("/").unwrap();
    let executable = tempfile::tempfile().unwrap();
    let s = spec();
    let argv = vec!["/program".into(), "arg".into()];
    let mut fake = Fake::default();
    boot::run_child(&mut fake, &s, &argv, &cwd, &executable, true).unwrap();
    let expected = vec![
        "Session",
        "ControllingTerminal",
        "cwd",
        "MemoryLimit(536870912)",
        "CoreLimit",
        "ClearGroups",
        "Gid(1001)",
        "Uid(1000)",
        "ClearSignalMask",
        "program:[\"/program\", \"arg\"]:[\"A=first\", \"Z=last\"]",
    ];
    assert_eq!(fake.events, expected);
    for fail in 0..expected.len() {
        let mut fake = Fake {
            fail: Some(fail),
            ..Fake::default()
        };
        assert_eq!(
            boot::run_child(&mut fake, &s, &argv, &cwd, &executable, true),
            Err(Error::Io)
        );
        assert_eq!(fake.events, expected[..=fail]);
    }
    let mut fake = Fake::default();
    boot::run_child(&mut fake, &s, &argv, &cwd, &executable, false).unwrap();
    assert!(!fake.events.iter().any(|e| e == "ControllingTerminal"));
    let mut invalid = s;
    invalid.env.insert("BAD".into(), "value\0".into());
    let mut fake = Fake::default();
    assert!(boot::run_child(&mut fake, &invalid, &argv, &cwd, &executable, false).is_err());
    assert!(fake.events.is_empty());
}

#[test]
fn upload_destination_cannot_collide_with_its_temporary_name() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join(".hermetic-upload-1"), b"old").unwrap();
    let mut root = Root::open_root(temp.path().to_str().unwrap()).unwrap();
    root.atomic("/.hermetic-upload-1", b"new", 1700000000)
        .unwrap();
    assert_eq!(
        fs::read(temp.path().join(".hermetic-upload-1")).unwrap(),
        b"new"
    );
}

#[test]
fn upload_temporary_collisions_have_a_work_cap_and_preserve_existing_files() {
    let temp = tempfile::tempdir().unwrap();
    for n in 1..=MAX_UPLOAD_ATTEMPTS {
        fs::write(
            temp.path().join(format!(".hermetic-upload-{n}")),
            b"occupied",
        )
        .unwrap();
    }
    fs::write(temp.path().join("destination"), b"old").unwrap();
    let mut root = Root::open_root(temp.path().to_str().unwrap()).unwrap();
    assert_eq!(
        root.atomic("/destination", b"new", 1700000000),
        Err(Error::Limit)
    );
    assert_eq!(fs::read(temp.path().join("destination")).unwrap(), b"old");
    for n in 1..=MAX_UPLOAD_ATTEMPTS {
        assert_eq!(
            fs::read(temp.path().join(format!(".hermetic-upload-{n}"))).unwrap(),
            b"occupied"
        );
    }
    root.atomic("/destination", b"new", 1700000000).unwrap();
    assert_eq!(fs::read(temp.path().join("destination")).unwrap(), b"new");
}

#[test]
fn upload_publication_mid_race_replacement_is_refused() {
    use std::os::unix::fs::symlink;
    for use_symlink in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"outside secret").unwrap();

        let mut root = Root::open_root(temp.path().to_str().unwrap()).unwrap();
        let temp_dir = temp.path().to_path_buf();
        let outside_target = outside.path().join("secret");

        hermetic_execd::fs::test_hooks::set_before_rename_hook(move || {
            for entry in fs::read_dir(&temp_dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with(".hermetic-upload-") {
                    fs::remove_file(entry.path()).unwrap();
                    if use_symlink {
                        symlink(&outside_target, entry.path()).unwrap();
                    } else {
                        fs::write(entry.path(), b"adversary forged").unwrap();
                    }
                }
            }
        });

        let res = root.atomic("/dest", b"clean payload", 1700000000);
        assert_eq!(res, Err(Error::InvalidInput));

        // Destination must not exist
        assert!(!temp.path().join("dest").exists());
        // Outside file must remain untouched
        assert_eq!(
            fs::read(outside.path().join("secret")).unwrap(),
            b"outside secret"
        );

        // The adversary entry was not deleted by error recovery
        let mut found_replaced = false;
        for entry in fs::read_dir(temp.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(".hermetic-upload-") {
                found_replaced = true;
                if use_symlink {
                    let meta = fs::symlink_metadata(entry.path()).unwrap();
                    assert!(meta.file_type().is_symlink());
                } else {
                    assert_eq!(fs::read(entry.path()).unwrap(), b"adversary forged");
                }
            }
        }
        assert!(
            found_replaced,
            "symlink={use_symlink}: adversary entry deleted"
        );
    }
}

#[test]
fn transfers_refuse_regular_looking_pseudo_files() {
    let root = Root::open_root("/").unwrap();
    assert!(fs::metadata("/proc/version").unwrap().is_file());
    assert!(root.read("/proc/version", MAX_TRANSFER).is_err());
}

#[test]
fn initramfs_exec_is_locked_until_explicit_authorize() {
    let mut fake = Fake::default();
    let mut cfg = config();
    cfg.initramfs = true;
    let boot = boot::boot(&mut fake, &cfg).unwrap();
    assert_eq!(
        &fake.events[..4],
        [
            "Clock(1700000000)",
            "MountDev",
            "MountBaseReadOnly",
            "MountDisk(\"/dev/vdb\")"
        ]
    );
    assert!(!fake.events.iter().any(|e| e.starts_with("entry:")));
    let mut server = Server::new(fake, boot);
    assert_eq!(
        ask(&mut server, exec(false, 1)),
        Reply::Error {
            reason: Error::Locked
        }
    );
    assert_eq!(
        ask(&mut server, Request::Status {}),
        Reply::Status {
            locked: true,
            output_bytes: 0,
            guest_time_unix: 1700000000
        }
    );
    assert_eq!(ask(&mut server, Request::Authorize {}), Reply::Ok);
    assert_eq!(ask(&mut server, Request::Authorize {}), Reply::Ok);
    assert_eq!(
        server
            .sys
            .events
            .iter()
            .filter(|e| e.starts_with("entry:"))
            .count(),
        1
    );
    assert!(matches!(ask(&mut server, exec(false, 1)), Reply::Exec(_)));
}

#[test]
fn trusted_reboot_clock_dev_base_order_and_every_failure_stops_boot() {
    let mut cfg = config();
    cfg.initramfs = true;
    let mut good = Fake::default();
    assert!(boot::boot(&mut good, &cfg).unwrap().locked);
    let mut expected = boot_answer();
    expected.insert(1, "MountDev".into());
    expected.insert(2, "MountBaseReadOnly".into());
    expected.retain(|e| !e.starts_with("entry:"));
    assert_eq!(good.events, expected);
    for failure in 0..expected.len() {
        let mut sys = Fake {
            fail: Some(failure),
            ..Fake::default()
        };
        assert!(boot::start(
            &mut sys,
            b"hermetic.t=1700000000 hermetic.initramfs=1".as_slice()
        )
        .is_err());
        let mut prefix = expected[..=failure].to_vec();
        prefix.push("PowerOff(Io)".into());
        assert_eq!(sys.events, prefix);
    }
    // Authorization is volatile: a second boot always starts locked again.
    let mut first = server(true);
    assert_eq!(ask(&mut first, Request::Authorize {}), Reply::Ok);
    assert!(boot::boot(&mut Fake::default(), &cfg).unwrap().locked);
}

#[test]
fn authorization_failure_stays_locked_and_empty_initial_command_never_spawns() {
    let mut server = server(true);
    server.sys.fail = Some(0);
    assert_eq!(
        ask(&mut server, Request::Authorize {}),
        Reply::Error { reason: Error::Io }
    );
    assert!(server.boot.locked);
    assert_eq!(
        ask(&mut server, exec(false, 1)),
        Reply::Error {
            reason: Error::Locked
        }
    );
    assert!(server.sys.commands.is_empty());
    server.sys.fail = None;
    server.boot.spec.entrypoint.clear();
    server.boot.spec.command.clear();
    let before = server.sys.events.len();
    assert_eq!(ask(&mut server, Request::Authorize {}), Reply::Ok);
    assert!(!server.boot.locked);
    assert_eq!(server.sys.events.len(), before);
}

#[test]
fn frames_known_answer_unknown_malformed_oversize_and_every_truncation() {
    let mut out = Vec::new();
    rpc::write_frame(&Request::Status {}, &mut out).unwrap();
    assert_eq!(out, b"\x11\0\0\0{\"type\":\"status\"}");
    let mut golden = Vec::new();
    rpc::write_frame(&spec(), &mut golden).unwrap();
    let parsed: RunSpec = rpc::read_frame(&mut golden.as_slice()).unwrap();
    assert!(String::from_utf8(golden[4..].to_vec())
        .unwrap()
        .starts_with("{\"env\":{\"A\":\"first\",\"Z\":\"last\"}"));
    assert_eq!(parsed, spec());
    for length in 0..out.len() {
        assert!(rpc::read_frame::<Request>(&mut &out[..length]).is_err());
    }
    for bytes in [
        vec![0; 4],
        u32::MAX.to_le_bytes().to_vec(),
        (MAX_FRAME as u32 + 1).to_le_bytes().to_vec(),
    ] {
        assert!(rpc::read_frame::<Request>(&mut bytes.as_slice()).is_err());
    }
    for value in [
        r#"{"type":"unknown"}"#,
        r#"{"type":"status","secret":"sensitive"}"#,
        "{",
        r#"{"type":"exec","argv":[],"tty":false,"timeout_ms":1}"#,
        r#"{"type":"upload","path":"/work/file","data":[],"timestamp":1700000000}"#,
    ] {
        let mut frame = (value.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(value.as_bytes());
        let mut pipe = Pipe::bytes(frame);
        let mut server = server(false);
        server.serve_one(&mut pipe).unwrap();
        assert!(matches!(pipe.reply(), Reply::Error { .. }));
        assert!(server.sys.events.is_empty());
        assert!(!String::from_utf8(pipe.output)
            .unwrap_or_default()
            .contains("sensitive"));
    }
}

#[test]
fn rpc_transfers_validate_before_sys_and_bound_downloads() {
    let mut server = server(false);
    assert_eq!(
        ask(
            &mut server,
            Request::Upload {
                path: "/work/file".into(),
                data: vec![1, 2]
            }
        ),
        Reply::Ok
    );
    assert_eq!(server.sys.uploaded, [("/work/file".into(), vec![1, 2])]);
    let before = server.sys.steps;
    for request in [
        Request::Upload {
            path: "/../out".into(),
            data: vec![],
        },
        Request::Upload {
            path: "/work/file".into(),
            data: vec![0; MAX_TRANSFER + 1],
        },
        Request::Download {
            path: "/a/../out".into(),
        },
    ] {
        assert!(matches!(ask(&mut server, request), Reply::Error { .. }));
    }
    assert_eq!(server.sys.steps, before);
    server.sys.output_size = MAX_TRANSFER + 1;
    assert_eq!(
        ask(
            &mut server,
            Request::Download {
                path: "/work/file".into()
            }
        ),
        Reply::Error {
            reason: Error::Limit
        }
    );
    server.sys.output_size = 2;
    assert_eq!(
        ask(
            &mut server,
            Request::Download {
                path: "/work/file".into()
            }
        ),
        Reply::Download { data: vec![1, 1] }
    );
}

#[test]
fn shutdown_exact_order_retained_handle_and_disconnected_reply() {
    let mut fake = Fake::default();
    let boot = boot::boot(&mut fake, &config()).unwrap();
    fake.events.clear();
    let mut server = Server::new(fake, boot);
    assert_eq!(ask(&mut server, Request::Shutdown {}), Reply::Frozen);
    assert_eq!(
        server.sys.events,
        [
            "TermAll",
            "WaitAll(2000)",
            "KillAll",
            "WaitAll(2000)",
            "Sync",
            "freeze:313",
            "PowerOff(Shutdown)"
        ]
    );
    let mut server = self::server(false);
    let mut pipe = Pipe::request(&Request::Shutdown {});
    pipe.fail_write = true;
    assert!(server.serve_one(&mut pipe).is_err());
    assert_eq!(server.sys.events.last().unwrap(), "PowerOff(Shutdown)");
    for fail in 0..6 {
        let mut fake = Fake {
            fail: Some(fail),
            ..Fake::default()
        };
        assert!(boot::shutdown(&mut fake, &313).is_err());
        assert_eq!(fake.events.len(), fail + 1);
    }
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut server = self::server(false);
    server.sys.trace = Some(trace.clone());
    let mut pipe = Pipe::request(&Request::Shutdown {});
    pipe.trace = Some(trace.clone());
    server.serve_one(&mut pipe).unwrap();
    assert_eq!(
        trace.borrow().as_slice(),
        [
            "TermAll",
            "WaitAll(2000)",
            "KillAll",
            "WaitAll(2000)",
            "Sync",
            "freeze:313",
            "write",
            "write",
            "flush",
            "PowerOff(Shutdown)"
        ]
    );
    // Each shutdown failure is replied as a static error before poweroff,
    // with no success frame or later filesystem effect.
    for fail in 0..6 {
        let mut server = self::server(false);
        server.sys.fail = Some(fail);
        assert_eq!(
            ask(&mut server, Request::Shutdown {}),
            Reply::Error { reason: Error::Io }
        );
        assert_eq!(server.sys.events.len(), fail + 2);
        assert_eq!(server.sys.events.last().unwrap(), "PowerOff(Shutdown)");
    }
}

#[test]
fn reboot_smoke_shutdown_writes_complete_reply_and_drains_before_poweroff_even_on_drain_failure() {
    struct QueuedSocket {
        input: Cursor<Vec<u8>>,
        queued: Vec<u8>,
        trace: Rc<RefCell<Vec<String>>>,
        fail_drain: bool,
        fail_flush: bool,
    }
    impl Read for QueuedSocket {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.input.read(bytes)
        }
    }
    impl Write for QueuedSocket {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // Short writes split both the header and body.
            let part = bytes.get(..bytes.len().min(2)).unwrap();
            self.queued.extend_from_slice(part);
            Ok(part.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            assert_eq!(self.queued, b"\x11\0\0\0{\"type\":\"frozen\"}");
            self.trace.borrow_mut().push("flush-complete-frame".into());
            if self.fail_flush {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }
    impl rpc::Connection for QueuedSocket {
        fn drain_reply(&mut self) -> io::Result<()> {
            assert_eq!(self.queued, b"\x11\0\0\0{\"type\":\"frozen\"}");
            self.trace.borrow_mut().push("drain-complete-frame".into());
            if self.fail_drain {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }
    for (fail_flush, fail_drain) in [(false, false), (false, true), (true, false)] {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut server = server(false);
        server.sys.trace = Some(trace.clone());
        let mut socket = QueuedSocket {
            input: Pipe::request(&Request::Shutdown {}).input,
            queued: Vec::new(),
            trace: trace.clone(),
            fail_drain,
            fail_flush,
        };
        assert_eq!(
            server.serve_one(&mut socket),
            if fail_flush || fail_drain {
                Err(Error::Io)
            } else {
                Ok(())
            }
        );
        let expected = if fail_flush {
            vec!["flush-complete-frame", "PowerOff(Shutdown)"]
        } else {
            vec![
                "flush-complete-frame",
                "drain-complete-frame",
                "PowerOff(Shutdown)",
            ]
        };
        assert_eq!(trace.borrow().get(6..).unwrap(), expected);
    }
}

struct Queue(VecDeque<Pipe>);
impl Listener for Queue {
    type Stream = Pipe;
    fn accept(&mut self) -> Result<Option<Pipe>> {
        Ok(self.0.pop_front())
    }
}
#[test]
fn generic_listener_is_serial_and_services_pid1_maintenance() {
    assert_eq!(MAX_CONNECTIONS, 1);
    assert_eq!(MAX_COMMANDS, 2);
    let mut queue = Queue(VecDeque::from([
        Pipe::request(&exec(false, 1)),
        Pipe::request(&exec(true, 2)),
        Pipe::request(&Request::Shutdown {}),
    ]));
    let mut server = server(false);
    server.run(&mut queue).unwrap();
    assert_eq!(server.sys.reaped, 2);
    assert_eq!(
        &server.sys.events[..5],
        ["maintain", "exec", "maintain", "exec", "maintain"]
    );
}

#[test]
fn descriptor_transfers_atomic_stamp_and_reject_symlink_fifo_and_escape() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("work")).unwrap();
    let mut root = Root::open_root(temp.path().to_str().unwrap()).unwrap();
    root.atomic("/work/file", b"first", 1700000000).unwrap();
    let held = root.regular("/work/file").unwrap();
    root.atomic("/work/file", b"second", 1700000001).unwrap();
    let meta = fs::metadata(temp.path().join("work/file")).unwrap();
    assert_eq!(meta.mtime(), 1700000001);
    assert_eq!(meta.atime(), 1700000001);
    assert_eq!(root.read("/work/file", 100).unwrap(), b"second");
    assert_eq!(read_capped(held, 100).unwrap(), b"first");
    assert_eq!(fs::read_dir(temp.path().join("work")).unwrap().count(), 1);
    assert_eq!(root.read("/work/file", 1), Err(Error::Limit));
    assert!(root
        .atomic("/work/file", &vec![0; MAX_TRANSFER + 1], 1)
        .is_err());
    fs::write(outside.path().join("secret"), b"unchanged").unwrap();
    symlink(outside.path(), temp.path().join("link")).unwrap();
    symlink(outside.path().join("secret"), temp.path().join("work/link")).unwrap();
    for name in [
        "/link/secret",
        "/work/link",
        "/work/../../secret",
        "/work/file/child",
        "/work",
    ] {
        assert!(root.read(name, 100).is_err(), "{name}");
        assert!(root.atomic(name, b"attack", 1).is_err(), "{name}");
    }
    rustix::fs::mknodat(
        rustix::fs::CWD,
        temp.path().join("work/fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(root.read("/work/fifo", 100).is_err());
    assert!(root.atomic("/work/fifo", b"attack", 1).is_err());
    assert_eq!(
        fs::read(outside.path().join("secret")).unwrap(),
        b"unchanged"
    );
    // The pinned root survives a rename of its original path.
    fs::rename(temp.path().join("work"), temp.path().join("moved")).unwrap();
    assert_eq!(root.read("/moved/file", 100).unwrap(), b"second");
}

#[test]
fn dev_walk_stamps_nodes_and_symlinks_without_following_targets() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("target");
    fs::write(&target, b"outside").unwrap();
    let before = fs::metadata(&target).unwrap().mtime();
    fs::create_dir(temp.path().join("dir")).unwrap();
    fs::write(temp.path().join("dir/file"), b"node").unwrap();
    symlink(&target, temp.path().join("link")).unwrap();
    let dir = rustix::fs::open(
        temp.path(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    stamp_dev(&dir, 1700000000).unwrap();
    for path in [
        temp.path().to_path_buf(),
        temp.path().join("dir"),
        temp.path().join("dir/file"),
        temp.path().join("link"),
    ] {
        assert_eq!(fs::symlink_metadata(path).unwrap().mtime(), 1700000000);
    }
    assert_eq!(fs::metadata(target).unwrap().mtime(), before);
}

#[test]
fn log_errors_are_static_and_preclock_is_silent() {
    let mut log = Vec::new();
    serial_failure(Error::InvalidClock, None, &mut log).unwrap();
    assert!(log.is_empty());
    serial_failure(Error::Io, Some(1700000000), &mut log).unwrap();
    assert_eq!(log, b"execd 1700000000 Io\n");
    let error = RunSpec::parse(b"secret-hostname-and-credentials".as_slice()).unwrap_err();
    assert_eq!(error.to_string(), "InvalidInput");
}

#[test]
fn absolute_stream_deadline_expires_even_after_partial_frame() {
    // socketpair needs no network namespace, listener bind or host address.
    let (a, b) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let mut peer = std::fs::File::from(b);
    peer.write_all(&[1]).unwrap();
    let mut stream = DeadlineStream::new(a.into(), Duration::from_millis(20));
    let start = Instant::now();
    let mut bytes = [0; 4];
    assert!(stream.read_exact(&mut bytes).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    peer.write_all(&[2]).unwrap();
    assert!(stream.read(&mut bytes).is_err());
}

#[test]
fn absolute_reply_deadline_bounds_a_peer_that_never_reads() {
    let (a, _peer) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let mut stream = DeadlineStream::new(a.into(), Duration::from_millis(20));
    let start = Instant::now();
    assert!(stream.write_all(&vec![0; MAX_FRAME]).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(stream.write(&[1]).is_err());
}

#[test]
fn binary_refuses_host_boot_and_non_utf8_or_extra_helper_arguments_silently() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, process::Command};
    for args in [
        vec![],
        vec![OsString::from_vec(vec![0xff])],
        vec!["--child".into(), OsString::from_vec(vec![0xff])],
        vec!["--child".into(), "{}".into(), "extra".into()],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hermetic-execd"))
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

fn network_spec() -> spec::Network {
    spec::Network {
        address: "10.0.2.15".parse().unwrap(),
        prefix: 24,
        gateway: "10.0.2.3".parse().unwrap(),
        mtu: 1500,
    }
}

#[test]
fn network_spec_strict_schema_subnet_hosts_and_numeric_caps() {
    let network = network_spec();
    let mut s = spec();
    s.network = Some(network.clone());
    let json = serde_json::to_vec(&s).unwrap();
    assert_eq!(RunSpec::parse(json.as_slice()).unwrap(), s);
    // Existing networkless specs still round-trip byte-for-byte apart from the
    // established sorted environment order.
    assert_eq!(spec().network, None);
    let mut networkless = serde_json::to_value(spec()).unwrap();
    networkless["network"] = serde_json::Value::Null;
    assert_eq!(
        RunSpec::parse(networkless.to_string().as_bytes()).unwrap(),
        spec()
    );
    for prefix in [0, 31, 33, u8::MAX] {
        let mut bad = network.clone();
        bad.prefix = prefix;
        assert_eq!(bad.validate(), Err(Error::InvalidInput));
    }
    for mtu in [0, MIN_NETWORK_MTU - 1, MAX_NETWORK_MTU + 1, u16::MAX] {
        let mut bad = network.clone();
        bad.mtu = mtu;
        assert_eq!(bad.validate(), Err(Error::InvalidInput));
    }
    for (address, gateway) in [
        ("10.0.2.15", "10.0.3.3"), // off-link NetVM
        ("10.0.2.15", "10.0.2.15"),
        ("10.0.2.0", "10.0.2.3"),
        ("10.0.2.255", "10.0.2.3"),
        ("10.0.2.15", "10.0.2.0"),
        ("10.0.2.15", "10.0.2.255"),
        ("0.0.0.0", "10.0.2.3"),
        ("127.0.0.1", "127.0.0.2"),
        ("169.254.1.1", "169.254.1.2"),
        ("224.0.0.1", "224.0.0.2"),
        ("255.255.255.255", "10.0.2.3"),
        ("8.8.8.8", "8.8.8.9"),
        ("10.0.2.15", "8.8.8.8"),
    ] {
        let bad = spec::Network {
            address: address.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
            ..network.clone()
        };
        assert_eq!(bad.validate(), Err(Error::InvalidInput), "{bad:?}");
    }
    for (prefix, mtu) in [(1, MIN_NETWORK_MTU), (30, MAX_NETWORK_MTU)] {
        let valid = spec::Network {
            address: "10.0.0.1".parse().unwrap(),
            gateway: "10.0.0.2".parse().unwrap(),
            prefix,
            mtu,
        };
        assert_eq!(valid.validate(), Ok(()));
    }
    let mut document = serde_json::to_value(&s).unwrap();
    let good = document["network"].clone();
    for bad in [
        r#"{}"#,
        r#"{"address":"10.0.2.15","prefix":24,"gateway":"10.0.2.3","mtu":1500,"interface":"host0"}"#,
        r#"{"address":"10.0.2.15","address":"10.0.2.16","prefix":24,"gateway":"10.0.2.3","mtu":1500}"#,
        r#"{"address":"10.0.2.15/24","prefix":24,"gateway":"10.0.2.3","mtu":1500}"#,
    ] {
        // Preserve duplicate keys so the actual deserializer sees them.
        let encoded = String::from_utf8(json.clone()).unwrap();
        let original = serde_json::to_string(&good).unwrap();
        let value_order = serde_json::to_string(&document).unwrap();
        assert!(encoded.contains("network"));
        assert!(RunSpec::parse(value_order.replace(&original, bad).as_bytes()).is_err());
    }
    for (key, values) in [
        (
            "address",
            vec![
                serde_json::json!("::1"),
                serde_json::json!("10.0.2.15;reboot"),
                serde_json::json!("010.0.2.15"),
                serde_json::json!("x".repeat(MAX_SPEC)),
            ],
        ),
        (
            "gateway",
            vec![
                serde_json::json!("10.0.2.3\nsecret"),
                serde_json::json!("-1"),
                serde_json::json!(123),
            ],
        ),
        (
            "prefix",
            vec![
                serde_json::json!(-1),
                serde_json::json!(256),
                serde_json::json!(1.5),
                serde_json::json!("24"),
            ],
        ),
        (
            "mtu",
            vec![
                serde_json::json!(-1),
                serde_json::json!(65536),
                serde_json::json!(1.5),
                serde_json::json!("1500"),
            ],
        ),
    ] {
        for value in values {
            document["network"] = good.clone();
            document["network"][key] = value;
            assert!(RunSpec::parse(document.to_string().as_bytes()).is_err());
        }
    }
}

#[test]
fn network_boot_order_fixed_argv_root_environment_and_every_failure() {
    let expected_commands = [
        "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
        "sysctl -w net.ipv6.conf.default.disable_ipv6=1",
        "ip link set lo up",
        "ip link set dev eth0 mtu 1500",
        "ip addr add 10.0.2.15/24 dev eth0",
        "ip link set dev eth0 up",
        "ip route add default via 10.0.2.3 dev eth0",
    ];
    for initramfs in [false, true] {
        let mut fake = Fake {
            network: Some(network_spec()),
            ..Fake::default()
        };
        let booted = boot::boot(
            &mut fake,
            &Config {
                initramfs,
                ..config()
            },
        )
        .unwrap();
        assert_eq!(booted.locked, initramfs);
        let mut expected = boot_answer();
        let apply = expected.iter().position(|e| e == "ApplySpec").unwrap();
        expected.splice(
            apply + 1..apply + 1,
            vec!["exec".to_owned(); expected_commands.len()],
        );
        if initramfs {
            expected.splice(1..1, ["MountDev".into(), "MountBaseReadOnly".into()]);
            expected.retain(|e| !e.starts_with("entry:"));
        }
        assert_eq!(fake.events, expected);
        assert_eq!(fake.commands.len(), expected_commands.len());
        for ((setup, argv, tty, timeout), args) in fake.commands.iter().zip(expected_commands) {
            assert_eq!(
                argv,
                &std::iter::once("/bin/busybox")
                    .chain(args.split(' '))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            );
            assert_eq!((setup.uid, setup.gid), (0, 0));
            assert_eq!(setup.workdir, "/");
            assert!(setup.env.is_empty());
            assert!(setup.initial_argv().is_empty());
            assert_eq!(setup.resources.memory_mib, network::NETWORK_MEMORY_MIB);
            assert!(!tty);
            assert_eq!(*timeout, network::NETWORK_COMMAND_TIMEOUT_MS);
        }
        assert_eq!(fake.caps, vec![0; expected_commands.len()]);
        // Every applet failure powers off, without an entrypoint or listener.
        let first = expected.iter().position(|e| e == "exec").unwrap();
        for offset in 0..expected_commands.len() {
            let mut fake = Fake {
                network: Some(network_spec()),
                fail: Some(first + offset),
                ..Fake::default()
            };
            let cmdline = format!(
                "hermetic.t=1700000000 hermetic.initramfs={}",
                u8::from(initramfs)
            );
            assert!(matches!(
                boot::start(&mut fake, cmdline.as_bytes()),
                Err(Error::Io)
            ));
            let mut prefix = expected[..=first + offset].to_vec();
            prefix.push("PowerOff(Io)".into());
            assert_eq!(fake.events, prefix);
        }
    }
}

#[test]
fn network_validates_before_commands_and_rejects_failure_signal_and_timeout() {
    let mut s = spec();
    s.network = Some(network_spec());
    for bad_reply in [
        ExecReply {
            code: Some(1),
            output: b"secret".to_vec(),
            truncated: false,
            timed_out: false,
        },
        ExecReply {
            code: None,
            output: Vec::new(),
            truncated: false,
            timed_out: false,
        },
        ExecReply {
            code: Some(0),
            output: Vec::new(),
            truncated: false,
            timed_out: true,
        },
    ] {
        for fail in 0..7 {
            let mut calls = 0;
            let result = network::configure(&s, |_, _| {
                let reply = if calls == fail {
                    bad_reply.clone()
                } else {
                    ExecReply {
                        code: Some(0),
                        output: Vec::new(),
                        truncated: false,
                        timed_out: false,
                    }
                };
                calls += 1;
                Ok(reply)
            });
            assert_eq!(result, Err(Error::Network));
            assert_eq!(calls, fail + 1);
            assert_eq!(result.unwrap_err().to_string(), "Network");
        }
    }
    s.network.as_mut().unwrap().prefix = u8::MAX;
    assert_eq!(
        network::configure(&s, |_, _| panic!("invalid network must have no effects")),
        Err(Error::InvalidInput)
    );
    s.network = Some(network_spec());
    s.workdir = "/bad/../path".into();
    assert_eq!(
        network::configure(&s, |_, _| panic!("validate the whole spec first")),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        network::configure(&spec(), |_, _| panic!(
            "networkless boot must not run applets"
        )),
        Ok(())
    );
    let mut fake = Fake {
        network: Some(spec::Network {
            prefix: 255,
            ..network_spec()
        }),
        ..Fake::default()
    };
    assert!(matches!(
        boot::start(&mut fake, b"hermetic.t=1700000000".as_slice()),
        Err(Error::InvalidInput)
    ));
    assert_eq!(fake.events.last().unwrap(), "PowerOff(InvalidInput)");
    assert!(!fake.events.iter().any(|e| e == "ApplySpec"
        || e == "exec"
        || e.starts_with("entry:")
        || e.starts_with("Listen")));
}

#[test]
fn network_argv_uses_declared_address_prefix_gateway_and_mtu() {
    let mut s = spec();
    s.network = Some(spec::Network {
        address: "172.16.1.19".parse().unwrap(),
        prefix: 20,
        gateway: "172.16.0.2".parse().unwrap(),
        mtu: 576,
    });
    let mut calls = Vec::new();
    network::configure(&s, |_, argv| {
        calls.push(argv.join(" "));
        Ok(ExecReply {
            code: Some(0),
            output: Vec::new(),
            truncated: false,
            timed_out: false,
        })
    })
    .unwrap();
    assert_eq!(
        calls,
        [
            "/bin/busybox sysctl -w net.ipv6.conf.all.disable_ipv6=1",
            "/bin/busybox sysctl -w net.ipv6.conf.default.disable_ipv6=1",
            "/bin/busybox ip link set lo up",
            "/bin/busybox ip link set dev eth0 mtu 576",
            "/bin/busybox ip addr add 172.16.1.19/20 dev eth0",
            "/bin/busybox ip link set dev eth0 up",
            "/bin/busybox ip route add default via 172.16.0.2 dev eth0",
        ]
    );
}

#[test]
fn network_point_to_point_routes_neighbours_via_netvm() {
    let mut s = spec();
    s.network = Some(spec::Network {
        prefix: 32,
        ..network_spec()
    });
    assert_eq!(
        RunSpec::parse(serde_json::to_vec(&s).unwrap().as_slice()).unwrap(),
        s
    );
    let mut commands = Vec::new();
    network::configure(&s, |_, argv| {
        commands.push(argv.join(" "));
        Ok(rpc::ExecReply {
            code: Some(0),
            output: Vec::new(),
            truncated: false,
            timed_out: false,
        })
    })
    .unwrap();
    assert!(commands
        .iter()
        .any(|c| c == "/bin/busybox ip addr add 10.0.2.15/32 dev eth0"));
    let routes: Vec<_> = commands.iter().filter(|c| c.contains("ip route")).collect();
    assert_eq!(
        routes,
        [
            "/bin/busybox ip route add 10.0.2.3/32 dev eth0",
            "/bin/busybox ip route add default via 10.0.2.3 dev eth0"
        ]
    );
    for fail in 0..commands.len() {
        let mut seen = 0;
        assert_eq!(
            network::configure(&s, |_, _| {
                let i = seen;
                seen += 1;
                if i == fail {
                    Err(Error::Network)
                } else {
                    Ok(rpc::ExecReply {
                        code: Some(0),
                        output: Vec::new(),
                        truncated: false,
                        timed_out: false,
                    })
                }
            }),
            Err(Error::Network)
        );
        assert_eq!(seen, fail + 1);
    }
}

#[test]
fn hung_filesystem_call_times_out_and_does_not_block_other_rpcs() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut server, worker) = worker_server(200);
    worker.hang_next.store(true, SeqCst);
    let start = Instant::now();
    assert_eq!(
        ask(&mut server, upload("/work/late", b"late")),
        Reply::Error {
            reason: Error::Timeout
        }
    );
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(200) && waited < Duration::from_secs(3));
    WorkerFake::wait_for("the hung call to be running", || {
        worker.running.load(SeqCst)
    });
    assert!(matches!(
        ask(&mut server, Request::Status {}),
        Reply::Status { .. }
    ));
    assert!(matches!(
        ask(&mut server, exec(false, 1000)),
        Reply::Exec(_)
    ));
    // Back-pressure: no second filesystem call starts behind the hung one.
    for request in [
        upload("/work/next", b"next"),
        Request::Download {
            path: "/work/next".into(),
        },
    ] {
        assert_eq!(
            ask(&mut server, request),
            Reply::Error {
                reason: Error::Busy
            }
        );
    }
    worker.release.store(true, SeqCst);
    worker.wait_finished(1);
    // The cancelled upload never published, even after it was released.
    assert!(worker.published.lock().unwrap().is_empty());
    // Busy replies prove a refused call never started, so retrying is safe.
    let end = Instant::now() + Duration::from_secs(5);
    let reply = loop {
        match ask(&mut server, upload("/work/next", b"next")) {
            Reply::Error {
                reason: Error::Busy,
            } if Instant::now() < end => std::thread::sleep(Duration::from_millis(5)),
            other => break other,
        }
    };
    assert_eq!(reply, Reply::Ok);
    assert_eq!(
        *worker.published.lock().unwrap(),
        [("/work/next".to_string(), b"next".to_vec())]
    );
    assert!(
        server.sys.uploaded.is_empty(),
        "no inline fallback was used"
    );
}

type ReplyLog = Rc<RefCell<Vec<(&'static str, Vec<u8>)>>>;

/// Connection whose reply lands in a shared, labelled log, so a test can see
/// the order in which `Server::run` answered its connections.
struct Logged {
    input: Cursor<Vec<u8>>,
    label: &'static str,
    log: ReplyLog,
    entry: RefCell<Option<usize>>,
    drain_hook: Option<Rc<dyn Fn()>>,
}
impl Read for Logged {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}
impl Write for Logged {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut log = self.log.borrow_mut();
        let mut entry = self.entry.borrow_mut();
        let idx = match *entry {
            Some(idx) => idx,
            None => {
                let idx = log.len();
                log.push((self.label, Vec::new()));
                *entry = Some(idx);
                idx
            }
        };
        log[idx].1.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl rpc::Connection for Logged {
    fn drain_reply(&mut self) -> io::Result<()> {
        if let Some(hook) = &self.drain_hook {
            hook();
        }
        Ok(())
    }
}
enum Step {
    Connect(&'static str, Request),
    ConnectWithDrainHook(&'static str, Request, Rc<dyn Fn()>),
    Release,
    /// Keep returning no connection until `label` has been answered.
    AwaitReply(&'static str),
    /// Wait (bounded) until the worker has returned from `n` calls.
    AwaitFinished(usize),
    /// Retry Shutdown (bounded) while it returns Busy, until Frozen.
    RetryShutdown,
    /// Listener accept returns an error.
    FailAccept(Error),
}
struct Script {
    steps: VecDeque<Step>,
    log: ReplyLog,
    worker: WorkerFake,
    waiting_since: Option<Instant>,
}
impl Listener for Script {
    type Stream = Logged;
    fn accept(&mut self) -> Result<Option<Logged>> {
        match self.steps.pop_front() {
            Some(Step::Connect(label, request)) => {
                let mut bytes = Vec::new();
                rpc::write_frame(&request, &mut bytes).unwrap();
                Ok(Some(Logged {
                    input: Cursor::new(bytes),
                    label,
                    log: self.log.clone(),
                    entry: RefCell::new(None),
                    drain_hook: None,
                }))
            }
            Some(Step::ConnectWithDrainHook(label, request, hook)) => {
                let mut bytes = Vec::new();
                rpc::write_frame(&request, &mut bytes).unwrap();
                Ok(Some(Logged {
                    input: Cursor::new(bytes),
                    label,
                    log: self.log.clone(),
                    entry: RefCell::new(None),
                    drain_hook: Some(hook),
                }))
            }
            Some(Step::Release) => {
                self.worker
                    .release
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(None)
            }
            Some(Step::AwaitFinished(n)) => {
                self.worker.wait_finished(n);
                Ok(None)
            }
            Some(Step::AwaitReply(label)) => {
                if !self.log.borrow().iter().any(|(l, _)| *l == label) {
                    let started = *self.waiting_since.get_or_insert_with(Instant::now);
                    assert!(started.elapsed() < WAIT_DEADLINE, "no reply for {label}");
                    self.steps.push_front(Step::AwaitReply(label));
                } else {
                    self.waiting_since = None;
                }
                Ok(None)
            }
            Some(Step::FailAccept(err)) => Err(err),
            Some(Step::RetryShutdown) => {
                let last_busy = self.log.borrow().iter().rev().find_map(|(l, b)| {
                    if *l == "shutdown" {
                        Some(rpc::read_frame::<Reply>(&mut b.as_slice()).ok())
                    } else {
                        None
                    }
                });
                if let Some(Some(Reply::Error {
                    reason: Error::Busy,
                })) = last_busy
                {
                    let started = *self.waiting_since.get_or_insert_with(Instant::now);
                    assert!(
                        started.elapsed() < SHUTDOWN_RETRY_TIMEOUT,
                        "timed out retrying shutdown"
                    );
                    std::thread::sleep(RETRY_INTERVAL);
                } else {
                    self.waiting_since = Some(Instant::now());
                }
                self.steps.push_front(Step::RetryShutdown);
                let mut bytes = Vec::new();
                rpc::write_frame(&Request::Shutdown {}, &mut bytes).unwrap();
                Ok(Some(Logged {
                    input: Cursor::new(bytes),
                    label: "shutdown",
                    log: self.log.clone(),
                    entry: RefCell::new(None),
                    drain_hook: None,
                }))
            }
            None => panic!("server kept running after the script ended"),
        }
    }
}

#[test]
fn run_loop_serves_other_rpcs_while_a_transfer_is_pending() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut server, worker) = worker_server(2000);
    worker.hang_next.store(true, SeqCst);
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut script = Script {
        steps: VecDeque::from([
            Step::Connect("upload", upload("/work/slow", b"slow")),
            Step::Connect("status", Request::Status {}),
            Step::Connect("exec", exec(false, 1000)),
            Step::Connect("second", upload("/work/other", b"other")),
            Step::Connect("early-shutdown", Request::Shutdown {}),
            Step::Release,
            Step::AwaitReply("upload"),
            Step::RetryShutdown,
        ]),
        log: log.clone(),
        worker: worker.clone(),
        waiting_since: None,
    };
    let start = Instant::now();
    server.run(&mut script).unwrap();
    // Everything ran well inside the 2 s transfer deadline.
    assert!(start.elapsed() < Duration::from_secs(2));
    let replies: Vec<(&str, Reply)> = log
        .borrow()
        .iter()
        .map(|(label, bytes)| (*label, rpc::read_frame(&mut bytes.as_slice()).unwrap()))
        .collect();
    let labels: Vec<&str> = replies.iter().map(|(l, _)| *l).collect();
    assert!(labels.len() >= 6);
    assert_eq!(
        &labels[..5],
        &["status", "exec", "second", "early-shutdown", "upload",]
    );
    for label in &labels[5..] {
        assert_eq!(*label, "shutdown");
    }
    assert!(matches!(replies[0].1, Reply::Status { .. }));
    assert!(matches!(replies[1].1, Reply::Exec(_)));
    for (_, reply) in &replies[2..4] {
        assert_eq!(
            *reply,
            Reply::Error {
                reason: Error::Busy
            }
        );
    }
    assert_eq!(replies[4].1, Reply::Ok);
    for (_, reply) in &replies[5..replies.len() - 1] {
        assert_eq!(
            *reply,
            Reply::Error {
                reason: Error::Busy
            }
        );
    }
    assert_eq!(replies.last().unwrap().1, Reply::Frozen);
    assert_eq!(
        *worker.published.lock().unwrap(),
        [("/work/slow".to_string(), b"slow".to_vec())]
    );
}

#[test]
fn deadline_after_commit_began_is_indeterminate_not_cancelled() {
    use std::sync::atomic::Ordering::SeqCst;
    // The worker enters the commit phase at once and then stalls there; the
    // deadline is long enough that it is reached only after the gate was won.
    let (mut server, worker) = worker_server(1000);
    worker.hang_in_commit.store(true, SeqCst);
    assert_eq!(
        ask(&mut server, upload("/work/racing", b"racing")),
        Reply::Error {
            reason: Error::Indeterminate
        }
    );
    assert!(
        worker.committing.load(SeqCst),
        "the deadline expired only after publication began"
    );
    worker.release.store(true, SeqCst);
    worker.wait_finished(1);
    // It did publish: the server must not have claimed it was cancelled.
    assert_eq!(
        *worker.published.lock().unwrap(),
        [("/work/racing".to_string(), b"racing".to_vec())]
    );
}

#[test]
fn filesystem_worker_keeps_request_order() {
    let (mut server, worker) = worker_server(2000);
    for n in 0..20u8 {
        assert_eq!(ask(&mut server, upload("/work/file", &[n])), Reply::Ok);
    }
    assert_eq!(
        ask(
            &mut server,
            Request::Download {
                path: "/work/file".into()
            }
        ),
        Reply::Download {
            data: b"downloaded".to_vec()
        }
    );
    let published = worker.published.lock().unwrap();
    let order: Vec<u8> = published.iter().map(|(_, d)| d[0]).collect();
    assert_eq!(order, (0..20).collect::<Vec<u8>>());
}

#[test]
fn shutdown_refuses_instead_of_freezing_under_a_running_filesystem_call() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut server, worker) = worker_server(100);
    worker.hang_next.store(true, SeqCst);
    assert_eq!(
        ask(&mut server, upload("/work/late", b"late")),
        Reply::Error {
            reason: Error::Timeout
        }
    );
    let start = Instant::now();
    assert_eq!(
        ask(&mut server, Request::Shutdown {}),
        Reply::Error {
            reason: Error::Busy
        }
    );
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "shutdown is bounded"
    );
    assert!(!server.sys.events.iter().any(|e| e.starts_with("freeze")));
    worker.release.store(true, SeqCst);
    worker.wait_finished(1);
    assert!(worker.published.lock().unwrap().is_empty());
    let end = Instant::now() + SHUTDOWN_RETRY_TIMEOUT;
    let reply = loop {
        match ask(&mut server, Request::Shutdown {}) {
            Reply::Error {
                reason: Error::Busy,
            } if Instant::now() < end => std::thread::sleep(RETRY_INTERVAL),
            other => break other,
        }
    };
    assert_eq!(reply, Reply::Frozen);
    assert!(server.sys.events.iter().any(|e| e == "freeze:313"));
}

#[test]
fn cancelled_upload_is_never_published_and_leaves_no_temporary() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"old").unwrap();
    let root = Root::new(fs::File::open(temp.path()).unwrap().into()).unwrap();
    let mut worker = root.worker_clone().unwrap();
    let mode = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
    let cancelled = fs_gate::CommitGate::new();
    assert!(cancelled.cancel());
    assert_eq!(
        worker.atomic_cancellable("/file", b"new", 1700000000, None, mode, Some(&cancelled)),
        Err(Error::Timeout)
    );
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"old");
    let names: Vec<_> = fs::read_dir(temp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["file"]);
    // An open gate is won by the commit, after which cancellation fails.
    let open = fs_gate::CommitGate::new();
    worker
        .atomic_cancellable("/file", b"new", 1700000000, None, mode, Some(&open))
        .unwrap();
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"new");
    assert!(
        !open.cancel(),
        "a committed call can no longer be cancelled"
    );
}

#[test]
fn transfer_deadline_holds_while_the_loop_is_blocked_in_another_request() {
    use std::sync::atomic::Ordering::SeqCst;
    // The upload hangs; an Exec then blocks the RPC loop past the upload's
    // deadline and only afterwards releases the worker. The worker must not
    // publish after its deadline even though the loop had not cancelled it yet.
    let (mut server, worker) = worker_server(200);
    worker.hang_next.store(true, SeqCst);
    server.sys.exec_delay_ms = 400;
    server.sys.release_after_exec = Some(worker.release.clone());
    server.sys.wait_finished_after_exec = Some(worker.finished.clone());
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut script = Script {
        steps: VecDeque::from([
            Step::Connect("upload", upload("/work/late", b"late")),
            Step::Connect("exec", exec(false, 1000)),
            Step::AwaitReply("upload"),
            Step::AwaitFinished(1),
            Step::RetryShutdown,
        ]),
        log: log.clone(),
        worker: worker.clone(),
        waiting_since: None,
    };
    server.run(&mut script).unwrap();
    let replies: Vec<(&str, Reply)> = log
        .borrow()
        .iter()
        .map(|(label, bytes)| (*label, rpc::read_frame(&mut bytes.as_slice()).unwrap()))
        .collect();
    assert_eq!(replies[0].0, "exec");
    assert_eq!(
        replies[1],
        (
            "upload",
            Reply::Error {
                reason: Error::Timeout
            }
        )
    );
    worker.wait_finished(1);
    assert!(
        worker.published.lock().unwrap().is_empty(),
        "nothing publishes after its deadline"
    );
}

#[test]
fn download_finishing_after_deadline_while_exec_blocks_loop_replies_timeout() {
    use std::sync::atomic::Ordering::SeqCst;
    // The download hangs; an Exec then blocks the RPC loop past the download's
    // deadline and releases the worker. The worker must convert the late
    // download to Timeout.
    let (mut server, worker) = worker_server(200);
    worker.hang_next.store(true, SeqCst);
    server.sys.exec_delay_ms = 400;
    server.sys.release_after_exec = Some(worker.release.clone());
    server.sys.wait_finished_after_exec = Some(worker.finished.clone());
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut script = Script {
        steps: VecDeque::from([
            Step::Connect(
                "download",
                Request::Download {
                    path: "/work/late".into(),
                },
            ),
            Step::Connect("exec", exec(false, 1000)),
            Step::AwaitReply("download"),
            Step::AwaitFinished(1),
            Step::RetryShutdown,
        ]),
        log: log.clone(),
        worker: worker.clone(),
        waiting_since: None,
    };
    server.run(&mut script).unwrap();
    let replies: Vec<(&str, Reply)> = log
        .borrow()
        .iter()
        .map(|(label, bytes)| (*label, rpc::read_frame(&mut bytes.as_slice()).unwrap()))
        .collect();
    assert_eq!(replies[0].0, "exec");
    assert_eq!(
        replies[1],
        (
            "download",
            Reply::Error {
                reason: Error::Timeout
            }
        )
    );
    worker.wait_finished(1);
}

#[test]
fn listener_accept_error_while_transfer_pending_abandons_worker_so_later_fs_call_succeeds() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut server, worker) = worker_server(5000);
    worker.hang_next.store(true, SeqCst);
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut script = Script {
        steps: VecDeque::from([
            Step::Connect("upload", upload("/work/pending", b"pending")),
            Step::FailAccept(Error::Io),
        ]),
        log: log.clone(),
        worker: worker.clone(),
        waiting_since: None,
    };
    assert_eq!(server.run(&mut script), Err(Error::Io));
    // The worker is still running the cancelled upload; a filesystem call
    // refuses with Busy while the worker thread is still active.
    assert_eq!(
        ask(&mut server, upload("/work/next", b"next")),
        Reply::Error {
            reason: Error::Busy
        }
    );
    worker.release.store(true, SeqCst);
    worker.wait_finished(1);
    // Because abandon_pending_fs marked the abandoned transfer answered,
    // the slot is reaped once the thread ends instead of staying busy forever.
    let end = Instant::now() + SHUTDOWN_RETRY_TIMEOUT;
    let reply = loop {
        match ask(&mut server, upload("/work/next", b"next")) {
            Reply::Error {
                reason: Error::Busy,
            } if Instant::now() < end => std::thread::sleep(RETRY_INTERVAL),
            other => break other,
        }
    };
    assert_eq!(reply, Reply::Ok);
    assert_eq!(
        *worker.published.lock().unwrap(),
        [("/work/next".to_string(), b"next".to_vec())]
    );
}

#[test]
fn commit_gate_refuses_after_its_deadline() {
    let gate = fs_gate::CommitGate::with_deadline(Instant::now());
    assert!(!gate.begin_commit());
    assert!(gate.cancel(), "an expired gate reads as cancelled");
    let gate = fs_gate::CommitGate::with_deadline(Instant::now() + Duration::from_secs(60));
    assert!(gate.begin_commit());
    assert!(!gate.cancel());
}

#[test]
fn logged_connections_with_same_label_record_separate_entries() {
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut conn1 = Logged {
        input: Cursor::new(Vec::new()),
        label: "shutdown",
        log: log.clone(),
        entry: RefCell::new(None),
        drain_hook: None,
    };
    let mut conn2 = Logged {
        input: Cursor::new(Vec::new()),
        label: "shutdown",
        log: log.clone(),
        entry: RefCell::new(None),
        drain_hook: None,
    };
    conn1.write_all(b"first").unwrap();
    conn2.write_all(b"second").unwrap();
    let entries = log.borrow().clone();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], ("shutdown", b"first".to_vec()));
    assert_eq!(entries[1], ("shutdown", b"second".to_vec()));
}

#[test]
fn commit_gate_refuses_when_deadline_expires_during_provisional_claim() {
    let gate = fs_gate::CommitGate::with_deadline(Instant::now() + Duration::from_millis(50));
    hermetic_execd::fs::test_hooks::set_provisional_claim_hook(|| {
        std::thread::sleep(Duration::from_millis(100));
    });
    assert!(!gate.begin_commit());
    assert!(gate.cancel(), "an expired gate reads as cancelled");
}

#[test]
fn child_stuck_terminal_reply_cancels_pending_upload_before_drain() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut server, worker) = worker_server(5000);
    worker.hang_next.store(true, SeqCst);
    server.sys.execute_error = Some(Error::ChildStuck);

    let worker_for_hook = worker.clone();
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut script = Script {
        steps: VecDeque::from([
            Step::Connect("upload", upload("/work/pending", b"data")),
            Step::ConnectWithDrainHook(
                "exec",
                exec(false, 1000),
                Rc::new(move || {
                    worker_for_hook.release.store(true, SeqCst);
                    worker_for_hook.wait_finished(1);
                }),
            ),
        ]),
        log: log.clone(),
        worker: worker.clone(),
        waiting_since: None,
    };

    let _ = server.run(&mut script);
    assert!(
        worker.published.lock().unwrap().is_empty(),
        "unanswered upload must be cancelled before terminal reply drain"
    );
}
