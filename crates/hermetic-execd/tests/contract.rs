use hermetic_execd::{
    boot::{self, Booted, Config, Effect, Sys},
    fs::Root,
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
