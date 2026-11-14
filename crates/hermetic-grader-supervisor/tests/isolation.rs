#![forbid(unsafe_code)]
use hermetic_grader_sandbox::SandboxPlan;
use hermetic_grader_supervisor::{
    sandbox::{self, SandboxOs, SandboxSettings, Stage},
    *,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

fn spec() -> SpawnSpec {
    SpawnSpec {
        argv: vec!["pytest".into(), "-q".into()],
        env: BTreeMap::new(),
        cwd: "/work/repo".into(),
        sandbox: SandboxSettings {
            t_clock: 1700000000,
            required_pytest_plugins: vec!["z_plugin".into(), "a_plugin".into()],
        },
        deadline_seconds: 10,
    }
}
#[derive(Default)]
struct Applied {
    stages: Vec<Stage>,
    plans: Vec<SandboxPlan>,
    fail: Option<Stage>,
}
impl SandboxOs for Applied {
    fn apply(&mut self, stage: Stage, plan: &SandboxPlan) -> std::io::Result<()> {
        self.stages.push(stage);
        self.plans.push(plan.clone());
        if self.fail == Some(stage) {
            Err(std::io::Error::other("injected"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn applied_plan_covers_every_isolation_property_and_fails_closed() {
    let spec = spec();
    let plan = sandbox::build_plan(&spec).unwrap();
    let stages = [
        Stage::Namespaces,
        Stage::Clock,
        Stage::PrivateMounts,
        Stage::DeviceCgroup,
        Stage::Root,
        Stage::Mounts,
        Stage::Devices,
        Stage::Identity,
        Stage::Capabilities,
        Stage::RecordFd,
        Stage::Exec,
    ];
    let mut os = Applied::default();
    sandbox::create_namespaces(&mut os, &plan).unwrap();
    assert!(sandbox::apply_plan(&mut os, &plan).is_err());
    assert_eq!(os.stages, stages);
    assert!(os.plans.iter().all(|p| p == &plan));
    assert!(
        plan.namespaces.pid
            && plan.namespaces.mount
            && plan.namespaces.ipc
            && plan.namespaces.uts
            && plan.namespaces.net
    );
    assert!(!plan.namespaces.user);
    assert_eq!(plan.mount_propagation, "rprivate");
    let caps = vec![
        "CAP_AUDIT_WRITE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT",
    ];
    assert_eq!(plan.capabilities.bounding, caps);
    assert_eq!(plan.capabilities.effective, caps);
    assert_eq!(plan.capabilities.permitted, caps);
    assert!(plan.capabilities.inheritable.is_empty() && plan.capabilities.ambient.is_empty());
    assert!(plan.capabilities.no_new_privileges);
    assert_eq!(
        plan.devices
            .iter()
            .map(|d| (d.path.as_str(), d.major, d.minor, d.mode.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("/dev/null", 1, 3, "0666"),
            ("/dev/zero", 1, 5, "0666"),
            ("/dev/full", 1, 7, "0666"),
            ("/dev/random", 1, 8, "0666"),
            ("/dev/urandom", 1, 9, "0666"),
            ("/dev/tty", 5, 0, "0666")
        ]
    );
    assert_eq!(
        plan.mounts
            .iter()
            .map(|m| (m.destination.as_str(), m.read_only))
            .collect::<Vec<_>>(),
        vec![
            ("/", true),
            ("/proc", false),
            ("/sys", true),
            ("/dev", false),
            ("/dev/pts", false),
            ("/dev/shm", false),
            ("/tmp", false),
            ("/work/repo", false)
        ]
    );
    assert_eq!(plan.hostname, "hermetic");
    assert_eq!(plan.domainname, "hermetic");
    assert!(plan.supplementary_groups.is_empty());
    assert_eq!((plan.uid, plan.gid), (0, 0));
    assert_eq!(
        plan.env,
        BTreeMap::from([
            ("HOME".into(), "/root".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("PYTEST_DISABLE_PLUGIN_AUTOLOAD".into(), "1".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
            ("PYTHONHASHSEED".into(), "0".into()),
            ("TZ".into(), "UTC".into()),
            ("HERMETIC_RESULT_FD".into(), "3".into())
        ])
    );
    assert_eq!(
        plan.argv,
        [
            "python",
            "-s",
            "-m",
            "pytest",
            "-p",
            "a_plugin",
            "-p",
            "hermetic_grader_records.plugin",
            "-p",
            "z_plugin",
            "-q"
        ]
    );
    for (idx, stage) in stages.iter().enumerate() {
        let mut os = Applied {
            fail: Some(*stage),
            ..Applied::default()
        };
        assert!(sandbox::create_namespaces(&mut os, &plan)
            .and_then(|()| sandbox::apply_plan(&mut os, &plan))
            .is_err());
        assert_eq!(os.stages, stages[..=idx]);
    }
}
#[test]
fn hostile_configuration_is_refused_before_spawn_or_result_write() {
    let base = spec();
    for (key, value) in [
        ("LD_PRELOAD", "secret"),
        ("PYTHONPATH", "secret"),
        ("TZ", "local"),
        ("HERMETIC_RESULT_FD", "2"),
        ("HOME", "/tmp"),
        ("PATH", "/tmp"),
    ] {
        let mut s = base.clone();
        s.env.insert(key.into(), value.into());
        assert!(sandbox::build_plan(&s).is_err(), "{key}");
    }
    for cwd in [
        "/",
        "/dev/repo",
        "/sys/x",
        "/proc/x",
        "/work/../repo",
        "relative",
        "/tmp/.hermetic-grader/root",
    ] {
        let mut s = base.clone();
        s.cwd = cwd.into();
        assert!(sandbox::build_plan(&s).is_err(), "{cwd}");
    }
    let mut os = FakeOs::new();
    let config = serde_json::json!({"argv":["sh","-c","touch /victim"],"cwd":"/work/repo","deadline_seconds":1,"expected_test_ids":[],"variant_set":"00".repeat(32)});
    os.insert_file(Path::new("/config"), serde_json::to_vec(&config).unwrap());
    assert!(run_supervisor(&mut os, Path::new("/config"), Path::new("/result")).is_err());
    assert_eq!(os.events(), &[OsEvent::ReadFile("/config".into())]);
}
#[test]
fn deterministic_plan_and_device_program_known_answer() {
    let p = sandbox::build_plan(&spec()).unwrap();
    assert_eq!(p, sandbox::build_plan(&spec()).unwrap());
    let program = hermetic_grader_supervisor::sys::device_program(&p.device_cgroup_rules).unwrap();
    let mut bytes = Vec::new();
    for i in &program {
        bytes.extend([i.code, i.regs]);
        bytes.extend(i.off.to_le_bytes());
        bytes.extend(i.imm.to_le_bytes());
    }
    use sha2::{Digest, Sha256};
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "38b81a2fd7454d915f8244457d10401811b2b62145b80069a2fa8c46f4deb51a"
    );
    // Execute the generated instructions against synthetic bpf_cgroup_dev_ctx
    // values. This checks jump offsets, rule ordering and every access bit.
    let evaluate = |typ: u32, major: u32, minor: u32, access: u32| {
        let ctx = [(access << 16) | typ, major, minor];
        let mut r2 = 0u32;
        let mut r0 = 0;
        let mut pc = 0usize;
        for _ in 0..hermetic_grader_supervisor::sys::MAX_DEVICE_INSTRUCTIONS {
            let i = program.get(pc).unwrap();
            pc += 1;
            match i.code {
                0x61 => r2 = *ctx.get(usize::try_from(i.off).unwrap() / 4).unwrap(),
                0x57 => r2 &= i.imm as u32,
                0x77 => r2 >>= i.imm,
                0x55 => {
                    if r2 != i.imm as u32 {
                        pc += usize::try_from(i.off).unwrap();
                    }
                }
                0xb7 => r0 = i.imm,
                0x95 => return r0,
                _ => panic!("unexpected opcode"),
            }
        }
        panic!("unbounded program")
    };
    for access in 1..=7 {
        for minor in [3, 5, 7, 8, 9] {
            assert_eq!(evaluate(2, 1, minor, access), 1);
        }
        assert_eq!(evaluate(2, 5, 0, access), 1);
        for (major, minor) in [(5, 2), (136, 0), (136, 255)] {
            assert_eq!(
                evaluate(2, major, minor, access),
                i32::from(access & 1 == 0)
            );
        }
        for (major, minor) in [(0, 0), (1, 3), (8, 0), (254, 16), (u32::MAX, u32::MAX)] {
            assert_eq!(evaluate(1, major, minor, access), 0);
        }
        for (major, minor) in [(1, 1), (5, 1), (137, 0)] {
            assert_eq!(evaluate(2, major, minor, access), 0);
        }
    }
}
#[test]
fn configuration_and_results_reject_links_fifos_devices_and_bound_reads() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let mut os = RealOs::new();
    let regular = tmp.path().join("regular");
    std::fs::write(&regular, b"abcdef").unwrap();
    assert!(os.read_file(&regular, 5).is_err());
    assert_eq!(os.read_file(&regular, 6).unwrap(), b"abcdef");
    let fifo = tmp.path().join("fifo");
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::RUSR).unwrap();
    let link = tmp.path().join("link");
    symlink(&regular, &link).unwrap();
    let parent_link = tmp.path().join("parent");
    symlink(tmp.path(), &parent_link).unwrap();
    for path in [
        fifo.clone(),
        link,
        parent_link.join("regular"),
        "/dev/zero".into(),
        "/dev/null".into(),
    ] {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut os = RealOs::new();
            let refused = os.read_file(&path, MAX_FILE_READ_BYTES).is_err()
                && os.write_file_atomic(&path, b"no").is_err();
            let _ = tx.send(refused);
        });
        const FILE_OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
        assert!(rx
            .recv_timeout(FILE_OPERATION_TIMEOUT)
            .expect("special files must not block"));
    }
    assert_eq!(std::fs::read(&regular).unwrap(), b"abcdef");
    let oversized = tmp.path().join("oversized");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len((MAX_FILE_READ_BYTES as u64) + 1)
        .unwrap();
    assert!(os.read_file(&oversized, usize::MAX).is_err());
    let output = tmp.path().join("result");
    os.write_file_atomic(&output, b"secret").unwrap();
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    os.write_file_atomic(&output, b"replace").unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), b"replace");
    assert!(!tmp.path().join(".result.tmp").exists());
}

#[test]
fn unprivileged_launch_fails_closed_without_running_repository() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    std::fs::write(
        tmp.path().join("pytest.py"),
        format!("open({:?},'w').write('bad')", marker.to_str().unwrap()),
    )
    .unwrap();
    let mut s = spec();
    s.cwd = tmp.path().into();
    s.sandbox.required_pytest_plugins.clear();
    let mut os = RealOs::with_launcher(env!("CARGO_BIN_EXE_hermetic-grader-supervisor").into());
    assert!(os.spawn(&s).is_err());
    assert!(!marker.exists());
}

/// Privileged checks run in disposable mount namespaces and never change the
/// host realtime clock. The runner below is a tiny offline Python fixture; all
/// assertions inspect kernel state after the production launcher has exec'd it.
#[test]
fn privileged_kernel_isolation_and_tree_teardown() {
    if !rustix::process::geteuid().is_root() {
        eprintln!("requires root (run in the disposable grader test environment)");
        return;
    }
    for case in ["properties", "exit", "timeout"] {
        let status = std::process::Command::new("timeout")
            .args([
                "45",
                "unshare",
                "--mount",
                "--propagation",
                "private",
                "--fork",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "privileged_kernel_worker", "--nocapture"])
            .env("HERMETIC_ISOLATION_CASE", case)
            .status()
            .unwrap();
        assert!(status.success(), "privileged case {case}");
    }
}
#[test]
fn privileged_kernel_worker() {
    let Ok(case) = std::env::var("HERMETIC_ISOLATION_CASE") else {
        return;
    };
    assert!(rustix::process::geteuid().is_root());
    rustix::mount::mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        rustix::mount::MountFlags::NOSUID | rustix::mount::MountFlags::NODEV,
        Some(c"mode=1777,size=268435456,nr_inodes=65536"),
    )
    .unwrap();
    rustix::mount::mount_change("/tmp", rustix::mount::MountPropagationFlags::SHARED).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let mut original = BTreeMap::new();
    for name in ["pid", "mnt", "ipc", "uts", "net", "user"] {
        original.insert(
            name,
            std::fs::read_link(format!("/proc/self/ns/{name}"))
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
    }
    // A deliberately planted block node exercises the cgroup rule independently
    // of the minimal /dev and CAP_MKNOD defenses.
    rustix::fs::mknodat(
        rustix::fs::CWD,
        repo.join("block"),
        rustix::fs::FileType::BlockDevice,
        rustix::fs::Mode::from_raw_mode(0o666),
        rustix::fs::makedev(8, 0),
    )
    .unwrap();
    let before = serde_json::to_string(&original).unwrap();
    let properties = format!(
        r#"
import os, sys, json, stat, socket, errno
old=json.loads({before:?})
for name in ('pid','mnt','ipc','uts','net'):
    assert os.readlink('/proc/self/ns/'+name)!=old[name],name
assert os.readlink('/proc/self/ns/user')==old['user']
assert os.getpid()==1 and os.getppid()==0
assert socket.gethostname()=='hermetic'
assert not any(' shared:' in line for line in open('/proc/self/mountinfo'))
assert os.getgroups()==[]
assert os.getuid()==0 and os.getgid()==0
status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
expected=sum(1<<bit for bit in (0,1,3,4,5,6,7,8,10,13,18,29,31))
for name in ('CapBnd','CapEff','CapPrm'): assert int(status[name],16)==expected,(name,status[name])
for name in ('CapInh','CapAmb'): assert int(status[name],16)==0
assert int(status['NoNewPrivs'])==1
assert dict(os.environ)=={{'HOME':'/root','LANG':'C.UTF-8','PATH':'/usr/local/bin:/usr/bin:/bin','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','TZ':'UTC','HERMETIC_RESULT_FD':'3'}}
assert '-s' in sys.orig_argv
assert sys.argv[1:]==['-p','hermetic_grader_records.plugin']
assert stat.S_ISFIFO(os.fstat(3).st_mode)
for fd in (0,1,2): assert os.stat('/dev/null').st_rdev==os.fstat(fd).st_rdev
assert set(os.listdir('/dev'))==set(('null','zero','full','random','urandom','tty','pts','shm','fd','ptmx','stderr','stdin','stdout'))
for name,major,minor in [('null',1,3),('zero',1,5),('full',1,7),('random',1,8),('urandom',1,9),('tty',5,0)]:
    s=os.lstat('/dev/'+name);assert stat.S_ISCHR(s.st_mode) and os.major(s.st_rdev)==major and os.minor(s.st_rdev)==minor
    assert s.st_mode&0o777==0o666
try: os.mknod('/tmp/forbidden',stat.S_IFCHR|0o666,os.makedev(1,3));raise AssertionError('mknod allowed')
except PermissionError: pass
# A cgroup2-capable kernel must deny opening an existing block node.
if 'cgroup2' in open('/proc/filesystems').read():
    try: os.open('block',os.O_RDONLY|os.O_NONBLOCK);raise AssertionError('block open allowed')
    except OSError as error: assert error.errno==errno.EPERM,error
try: open('/etc/hermetic-isolation-must-stay-readonly','w');raise AssertionError('root writable')
except OSError as error: assert error.errno==errno.EROFS,error
open('artifact','w').write('overlay')
open('/tmp/artifact','w').write('tmp')
assert not os.listdir('/tmp/.hermetic-grader')
assert len([n for n in os.listdir('/proc') if n.isdigit()])==1
assert [line.split(':')[0].strip() for line in open('/proc/net/dev').read().splitlines()[2:]]==['lo']
assert os.statvfs('/sys').f_flag&os.ST_RDONLY
for path in ('/proc','/sys','/dev','/dev/pts','/dev/shm','/tmp'):
    assert os.path.ismount(path),path
"#
    );
    let records = r#"
def emit(kind,payload):
    body=json.dumps(payload,separators=(',',':')).encode()
    os.write(3,bytes([kind])+len(body).to_bytes(4,'little')+body)
os.write(3,b'HGR1')
emit(1,{'seq':1,'nodeid':'probe'})
"#;
    let body=match case.as_str() {
        "properties"=> format!("{properties}\n{records}\nemit(2,{{'seq':2,'nodeid':'probe','outcome':'passed','duration_ms':0}})\nemit(3,{{'count':1}})\n"),
        "exit"|"timeout"=>format!(r#"
import os, json, time
{records}
pid=os.fork()
if pid==0:
    os.setsid()
    os.close(0);os.close(1);os.close(2);os.close(3)
    while True:
        open('/tmp/heartbeat','w').write('live')
        time.sleep(0.01)
while not os.path.exists('/tmp/heartbeat'): time.sleep(0.01)
{}
"#,if case=="exit" { "os._exit(0)" } else { "time.sleep(60)" }),
        _=>panic!("unknown case"),
    };
    std::fs::write(repo.join("pytest.py"), body).unwrap();
    let mut spec = spec();
    spec.cwd = repo.clone();
    spec.argv = vec!["pytest".into()];
    spec.sandbox.required_pytest_plugins.clear();
    spec.sandbox.t_clock = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    let cfg = RunConfig {
        argv: spec.argv,
        env: spec.env,
        cwd: repo.to_string_lossy().into_owned(),
        sandbox: spec.sandbox,
        deadline_seconds: if case == "timeout" { 1 } else { 10 },
        expected_test_ids: vec!["probe".into()],
        variant_set: "00".repeat(32),
    };
    let config = tmp.path().join("config");
    let disk = tmp.path().join("disk");
    std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let mut os = RealOs::with_launcher(env!("CARGO_BIN_EXE_hermetic-grader-supervisor").into());
    std::fs::write(
        &disk,
        hermetic_grader_supervisor::label::encode_run_label(RunName::R0),
    )
    .unwrap();
    let report = run_supervisor(&mut os, &config, &disk).unwrap();
    assert_eq!(
        report.payload.supervisor.exit,
        match case.as_str() {
            "properties" => SupervisorExit::Clean,
            "exit" => SupervisorExit::Crash,
            _ => SupervisorExit::Timeout,
        }
    );
    if case == "properties" {
        assert_eq!(
            report.payload.tests.get("probe"),
            Some(&FinalTestOutcome::Passed)
        );
        assert!(!repo.join("artifact").exists());
    } else {
        let heartbeat = Path::new("/tmp/heartbeat");
        let modified = std::fs::metadata(heartbeat).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            modified,
            std::fs::metadata(heartbeat).unwrap().modified().unwrap()
        );
    }
    assert_eq!(
        decode_result_disk(&std::fs::read(disk).unwrap()).unwrap(),
        report.payload
    );
}

#[test]
fn invalid_config_and_cli_never_echo_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config");
    let secret = "SENSITIVE_CANARY_VALUE";
    let invalid = format!("{{\"{secret}\":true}}");
    let error = RunConfig::from_json_bytes(invalid.as_bytes()).unwrap_err();
    assert!(!format!("{error:?}").contains(secret));
    std::fs::write(&config, invalid).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-grader-supervisor"))
        .arg("--config")
        .arg(&config)
        .arg("--result-disk")
        .arg(tmp.path().join("result"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-grader-supervisor"))
        .arg(secret)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
}

#[test]
fn config_parser_enforces_its_cap_before_deserialization() {
    let mut bytes=serde_json::to_vec(&serde_json::json!({"argv":["pytest"],"cwd":"/work/repo","deadline_seconds":1,"expected_test_ids":[],"variant_set":"00".repeat(32)})).unwrap();
    bytes.resize(MAX_CONFIG_BYTES + 1, b' ');
    assert!(RunConfig::from_json_bytes(&bytes).is_err());
}
