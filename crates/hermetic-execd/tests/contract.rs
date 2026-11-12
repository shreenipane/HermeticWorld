use hermetic_execd::{
    boot::{self, Booted, Config, Effect, Sys},
    fs::Root,
    real::{serial_failure, stamp_dev, DeadlineStream},
    rpc::{self, ExecReply, Listener, Reply, Request, Server},
    spec::{self, RunSpec},
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
    caps: Vec<usize>,
    commands: Vec<(RunSpec, Vec<String>, bool, u64)>,
    reaped: usize,
    output_size: usize,
    execute_error: Option<Error>,
    uploaded: Vec<(String, Vec<u8>)>,
    trace: Option<Rc<RefCell<Vec<String>>>>,
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
        if self.invalid_spec {
            spec.workdir = "/work/../escape".into();
        }
        Ok(spec)
    }
    fn apply(&mut self, spec: &RunSpec) -> Result<()> {
        spec.validate()?;
        self.effect(Effect::ApplySpec)
    }
    fn start_entrypoint(&mut self, spec: &RunSpec) -> Result<()> {
        self.record(format!("entry:{:?}", spec.initial_argv()))
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
            initramfs: false
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
        "hermetic.t=1700000000 hermetic.unknown=1",
    ] {
        assert!(Config::parse(line.as_bytes()).is_err(), "{line}");
    }
    assert!(Config::parse(vec![b'a'; MAX_CMDLINE + 1].as_slice()).is_err());
    assert!(Config::parse(b"hermetic.t=315532800 hermetic.overlay=/dev/vdc hermetic.spec=/trusted/spec hermetic.initramfs=1".as_slice()).unwrap().initramfs);
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
    ] {
        let mut fake = Fake::default();
        assert!(boot::boot(&mut fake, &cfg).is_err());
        assert!(fake.events.is_empty());
    }
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
            output_bytes: MAX_RUN_OUTPUT
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
fn initramfs_exec_is_locked_until_explicit_authorize() {
    let mut fake = Fake::default();
    let mut cfg = config();
    cfg.initramfs = true;
    let boot = boot::boot(&mut fake, &cfg).unwrap();
    assert_eq!(
        &fake.events[..3],
        [
            "Clock(1700000000)",
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
            output_bytes: 0
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
