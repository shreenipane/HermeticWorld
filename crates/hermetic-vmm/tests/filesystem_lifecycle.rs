mod support;
use hermetic_vmm::{deadline, fs::*, runner::Runner, spec::*, *};
use std::{
    fs,
    io::Read,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    process::Command,
    time::{Duration, Instant},
};
use support::Fixture;
const TIMEOUT: Duration = Duration::from_secs(2);
#[derive(Default)]
struct Fake {
    events: Vec<String>,
    fail: Option<String>,
    alive: bool,
    stalled: bool,
    killed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Runner for Fake {
    fn spawn(
        &mut self,
        _: &ValidatedSpec,
        _: &JailPlan,
        _: &PreparedJail,
        _: Instant,
    ) -> Result<()> {
        self.events.push("spawn".into());
        if self.fail.as_deref() == Some("spawn") {
            return Err(Error::Io);
        }
        self.alive = true;
        Ok(())
    }
    fn request(&mut self, _: &str, r: &ApiRequest, end: Instant) -> Result<()> {
        self.events.push(format!("{} {}", r.method, r.path));
        if self.stalled {
            while Instant::now() < end {
                std::thread::sleep(Duration::from_millis(1));
            }
            return Err(Error::Deadline("fake"));
        }
        if self.fail.as_deref() == Some(&r.path) {
            return Err(Error::Api(400));
        }
        Ok(())
    }
    fn exited(&mut self, _: Instant) -> Result<bool> {
        Ok(!self.alive)
    }
    fn kill(&mut self, _: Instant) -> Result<()> {
        self.events.push("kill".into());
        self.alive = false;
        self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn descriptor_copy_and_reserved_slot_teardown_never_follow_links() {
    let f = Fixture::new();
    let source = fs::metadata(&f.spec.drives[0].path).unwrap();
    let jail = PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap(),
    )
    .unwrap();
    let dest = fs::metadata(f.root().join("drive-overlay")).unwrap();
    assert_ne!((source.dev(), source.ino()), (dest.dev(), dest.ino()));
    assert_eq!(dest.mode() & 0o777, 0o600);
    let binary = jail.executable().unwrap().metadata().unwrap();
    assert_eq!(binary.mode() & 0o777, 0o555);
    assert_eq!(binary.mode() & 0o022, 0);
    assert_eq!(
        fs::metadata(f.root().join("drive-rootfs")).unwrap().mode() & 0o777,
        0o400
    );
    assert_eq!(
        fs::read(f.root().join("drive-tests")).unwrap(),
        vec![0; 4096]
    );
    fs::write(f.root().join("drive-overlay"), b"changed").unwrap();
    assert_eq!(fs::read(&f.spec.drives[0].path).unwrap(), b"overlay");
    let outside = f.temp.path().join("outside");
    fs::write(&outside, b"protected").unwrap();
    symlink(&outside, f.root().join("link")).unwrap();
    jail.destroy(deadline(TIMEOUT).unwrap()).unwrap();
    assert!(!f.root().exists());
    assert_eq!(fs::read(outside).unwrap(), b"protected");
}
#[test]
fn rejects_unsafe_sources_and_directories_before_creating_artifacts() {
    for kind in [
        "file-symlink",
        "ancestor-symlink",
        "fifo",
        "directory",
        "writable",
        "template",
    ] {
        let mut f = Fixture::new();
        let kernel = f.spec.kernel_image.clone();
        match kind {
            "file-symlink" => {
                fs::remove_file(&kernel).unwrap();
                symlink(&f.spec.root_drive.path, &kernel).unwrap();
            }
            "ancestor-symlink" => {
                symlink(f.temp.path(), f.temp.path().join("alias")).unwrap();
                f.spec.kernel_image = f.temp.path().join("alias/kernel").to_str().unwrap().into();
            }
            "fifo" => {
                fs::remove_file(&kernel).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &kernel,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            "directory" => {
                f.spec.kernel_image = f.temp.path().to_str().unwrap().into();
            }
            "writable" => fs::set_permissions(&kernel, fs::Permissions::from_mode(0o622)).unwrap(),
            "template" => fs::write(&f.spec.cpu_template, b"{}").unwrap(),
            _ => unreachable!(),
        }
        assert!(
            PreparedJail::prepare(
                &f.spec.clone().validate().unwrap(),
                deadline(TIMEOUT).unwrap()
            )
            .is_err(),
            "{kind}"
        );
        assert!(!f.temp.path().join("firecracker").exists());
    }
    let f = Fixture::new();
    fs::set_permissions(f.temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap()
    )
    .is_err());
    assert!(!f.temp.path().join("firecracker").exists());
}
#[test]
fn opened_source_remains_pinned_after_path_replacement() {
    let f = Fixture::new();
    let mut file = open_image(&f.spec.kernel_image).unwrap();
    fs::rename(&f.spec.kernel_image, f.temp.path().join("old-kernel")).unwrap();
    symlink(&f.spec.root_drive.path, &f.spec.kernel_image).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"kernel");
    assert!(open_image(&f.spec.kernel_image).is_err());
}
#[test]
fn image_and_template_and_cleanup_caps_are_enforced() {
    let f = Fixture::new();
    let image = fs::OpenOptions::new()
        .write(true)
        .open(&f.spec.kernel_image)
        .unwrap();
    image.set_len(MAX_IMAGE_BYTES + 1).unwrap();
    assert!(open_image(&f.spec.kernel_image).is_err());
    let f = Fixture::new();
    fs::write(
        &f.spec.cpu_template,
        vec![b' '; MAX_TEMPLATE_BYTES as usize + 1],
    )
    .unwrap();
    assert!(PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap()
    )
    .is_err());
    let f = Fixture::new();
    let jail = PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap(),
    )
    .unwrap();
    for i in 0..MAX_CLEANUP_ENTRIES {
        fs::write(f.root().join(format!("extra-{i}")), b"").unwrap();
    }
    assert!(jail.destroy(deadline(TIMEOUT).unwrap()).is_err());
}
#[test]
fn destroy_refuses_replaced_vm_or_root_identity() {
    for replace_root in [true, false] {
        let f = Fixture::new();
        let jail = PreparedJail::prepare(
            &f.spec.clone().validate().unwrap(),
            deadline(TIMEOUT).unwrap(),
        )
        .unwrap();
        let path = if replace_root {
            f.root()
        } else {
            f.root().parent().unwrap().to_path_buf()
        };
        let old = path.with_extension("saved");
        fs::rename(&path, &old).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("protected"), b"keep").unwrap();
        assert!(jail.destroy(deadline(TIMEOUT).unwrap()).is_err());
        assert_eq!(fs::read(path.join("protected")).unwrap(), b"keep");
        assert!(old.exists());
    }
}
#[test]
fn explicit_state_machine_configures_starts_pauses_resumes_stops_and_destroys() {
    let f = Fixture::new();
    let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), Fake::default());
    assert_eq!(vm.state(), State::New);
    assert_eq!(vm.start(TIMEOUT), Err(Error::State));
    assert_eq!(vm.wait_ready(TIMEOUT), Err(Error::State));
    assert_eq!(vm.destroy(TIMEOUT), Err(Error::State));
    vm.prepare(TIMEOUT).unwrap();
    assert_eq!(vm.state(), State::Prepared);
    assert_eq!(vm.prepare(TIMEOUT), Err(Error::State));
    assert_eq!(vm.pause(TIMEOUT), Err(Error::State));
    vm.start(TIMEOUT).unwrap();
    assert_eq!(vm.state(), State::Starting);
    assert_eq!(vm.start(TIMEOUT), Err(Error::State));
    vm.wait_ready(TIMEOUT).unwrap();
    assert_eq!(vm.state(), State::Running);
    assert_eq!(vm.resume(TIMEOUT), Err(Error::State));
    assert_eq!(vm.destroy(TIMEOUT), Err(Error::State));
    vm.pause(TIMEOUT).unwrap();
    assert_eq!(vm.state(), State::Paused);
    assert_eq!(vm.pause(TIMEOUT), Err(Error::State));
    vm.resume(TIMEOUT).unwrap();
    vm.stop(Duration::from_millis(10)).unwrap();
    assert_eq!(vm.state(), State::Stopped);
    vm.destroy(TIMEOUT).unwrap();
    assert_eq!(vm.state(), State::Destroyed);
    assert!(!f.root().exists());
    assert_eq!(
        vm.runner().events,
        vec![
            "spawn",
            "GET /",
            "PUT /machine-config",
            "PUT /cpu-config",
            "PUT /boot-source",
            "PUT /drives/rootfs",
            "PUT /drives/overlay",
            "PUT /drives/tests",
            "PUT /vsock",
            "PUT /network-interfaces/eth0",
            "PUT /entropy",
            "PUT /actions",
            "GET /",
            "PATCH /vm",
            "PATCH /vm",
            "PUT /actions",
            "kill",
            "kill"
        ]
    );
}
#[test]
fn failures_name_the_step_and_destroy_the_jail() {
    for fail in [
        "spawn",
        "/machine-config",
        "/cpu-config",
        "/boot-source",
        "/drives/rootfs",
        "/drives/overlay",
        "/drives/tests",
        "/vsock",
        "/network-interfaces/eth0",
        "/entropy",
        "/actions",
        "/vm",
    ] {
        let f = Fixture::new();
        let fake = Fake {
            fail: Some(fail.into()),
            ..Fake::default()
        };
        let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), fake);
        vm.prepare(TIMEOUT).unwrap();
        let error = if fail == "spawn" {
            vm.start(TIMEOUT).unwrap_err()
        } else {
            vm.start(TIMEOUT).unwrap();
            if fail == "/vm" {
                vm.wait_ready(TIMEOUT).unwrap();
                vm.pause(TIMEOUT).unwrap_err()
            } else {
                vm.wait_ready(TIMEOUT).unwrap_err()
            }
        };
        assert!(matches!(error, Error::Step(_)));
        assert_eq!(vm.state(), State::Failed);
        assert!(!f.root().exists(), "{fail}");
        assert!(!vm.runner().alive);
        vm.destroy(TIMEOUT).unwrap();
    }
}
#[test]
fn startup_stall_is_destroyed_and_drop_kills_a_running_vm() {
    let f = Fixture::new();
    let fake = Fake {
        stalled: true,
        ..Fake::default()
    };
    let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), fake);
    vm.prepare(TIMEOUT).unwrap();
    vm.start(TIMEOUT).unwrap();
    let start = Instant::now();
    assert_eq!(
        vm.wait_ready(Duration::from_millis(20)),
        Err(Error::Step("wait_ready"))
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!f.root().exists());
    let f = Fixture::new();
    let fake = Fake::default();
    let killed = fake.killed.clone();
    let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), fake);
    vm.prepare(TIMEOUT).unwrap();
    vm.start(TIMEOUT).unwrap();
    vm.wait_ready(TIMEOUT).unwrap();
    drop(vm);
    assert!(killed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!f.root().exists());
}
#[test]
fn deadlines_refuse_zero_and_oversized_and_expired_prepare_leaves_no_jail() {
    assert!(deadline(Duration::ZERO).is_err());
    assert!(deadline(Duration::from_secs(301)).is_err());
    let f = Fixture::new();
    assert!(PreparedJail::prepare(&f.spec.clone().validate().unwrap(), Instant::now()).is_err());
    assert!(!f.root().exists());
    let jail = PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        jail.destroy(Instant::now()),
        Err(Error::Deadline("destroy"))
    ));
    assert!(f.root().exists());
    jail.destroy(deadline(TIMEOUT).unwrap()).unwrap();
}

#[test]
fn configuration_failure_names_the_specific_device_step() {
    for (path, step) in [
        ("/cpu-config", "configure CPU template"),
        ("/boot-source", "configure boot source"),
        ("/drives/tests", "configure drives"),
        ("/entropy", "configure entropy"),
        ("/actions", "InstanceStart"),
    ] {
        let f = Fixture::new();
        let fake = Fake {
            fail: Some(path.into()),
            ..Fake::default()
        };
        let mut vm = Vmm::new(f.spec.clone().validate().unwrap(), fake);
        vm.prepare(TIMEOUT).unwrap();
        vm.start(TIMEOUT).unwrap();
        assert_eq!(vm.wait_ready(TIMEOUT), Err(Error::Step(step)));
        assert!(!f.root().exists());
    }
}

#[test]
fn aggregate_input_budget_refuses_sparse_images_before_writing() {
    let f = Fixture::new();
    for path in [
        &f.spec.jail.firecracker,
        &f.spec.kernel_image,
        &f.spec.root_drive.path,
        &f.spec.drives[0].path,
    ] {
        // Source binary normally has mode 0500; this is a private test fixture.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES)
            .unwrap();
    }
    let error = PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap(),
    )
    .err()
    .unwrap();
    assert_eq!(error, Error::Validation("total image size cap"));
    assert!(!f.temp.path().join("firecracker").exists());
}
#[test]
fn ancestor_replacement_does_not_redirect_prepared_jail_paths_or_cleanup() {
    let f = Fixture::new();
    let jail = PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap(),
    )
    .unwrap();
    let plan = jail_plan(&f.spec.clone().validate().unwrap());
    let args = jail.pinned_jailer_args(&plan);
    let base = f.temp.path();
    let relocated = base.with_extension("relocated");
    fs::rename(base, &relocated).unwrap();
    fs::create_dir(base).unwrap();
    fs::write(base.join("protected"), b"keep").unwrap();
    let executable = args.windows(2).find(|w| w[0] == "--exec-file").unwrap()[1].clone();
    assert_eq!(fs::read(executable).unwrap(), b"fake-firecracker");
    jail.destroy(deadline(TIMEOUT).unwrap()).unwrap();
    assert!(!relocated.join("firecracker/vm-0").exists());
    assert_eq!(fs::read(base.join("protected")).unwrap(), b"keep");
    fs::remove_dir_all(relocated).unwrap();
}
#[test]
fn prepare_refuses_existing_vm_and_depth_cleanup_is_bounded() {
    let f = Fixture::new();
    let valid = f.spec.clone().validate().unwrap();
    let jail = PreparedJail::prepare(&valid, deadline(TIMEOUT).unwrap()).unwrap();
    assert!(PreparedJail::prepare(&valid, deadline(TIMEOUT).unwrap()).is_err());
    assert_eq!(fs::read(f.root().join("drive-rootfs")).unwrap(), b"rootfs");
    let mut path = f.root();
    for _ in 0..MAX_CLEANUP_DEPTH + 1 {
        path = path.join("nested");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(
        jail.destroy(deadline(TIMEOUT).unwrap()),
        Err(Error::Validation("cleanup depth cap"))
    );
}

#[test]
fn ancestor_ownership_validation_rejects_untrusted_parents() {
    let f = Fixture::new();
    let untrusted = f.temp.path().join("untrusted");
    fs::create_dir(&untrusted).unwrap();
    let target = untrusted.join("jail");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();

    // World-writable ancestor without sticky bit is rejected
    fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Directory::open(target.to_str().unwrap()).is_err());

    // Non-root world-writable ancestor with sticky bit is also rejected
    fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(Directory::open(target.to_str().unwrap()).is_err());

    // When restored to private permissions, open succeeds
    fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Directory::open(target.to_str().unwrap()).is_ok());

    // Preparing a jail where base has an untrusted ancestor is rejected before any artifacts are created
    let mut spec = f.spec.clone();
    spec.jail.base = target.to_str().unwrap().into();
    fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(PreparedJail::prepare(
        &spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap()
    )
    .is_err());
    assert!(!target.join("firecracker").exists());

    // When restored to trusted permissions, prepare succeeds
    fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o700)).unwrap();
    let jail =
        PreparedJail::prepare(&spec.validate().unwrap(), deadline(TIMEOUT).unwrap()).unwrap();
    jail.destroy(deadline(TIMEOUT).unwrap()).unwrap();
}

const BIND_MOUNT_CHILD: &str = "HERMETIC_BIND_MOUNT_CHILD";

#[test]
fn bind_mount_child() {
    if std::env::var_os(BIND_MOUNT_CHILD).is_none() {
        return;
    }
    let f = Fixture::new();
    let jail = PreparedJail::prepare(
        &f.spec.clone().validate().unwrap(),
        deadline(TIMEOUT).unwrap(),
    )
    .unwrap();
    let outside = f.temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let sentinel = outside.join("sentinel.txt");
    fs::write(&sentinel, b"preserve-me").unwrap();

    let mountpoint = f.root().join("bindmount");
    fs::create_dir(&mountpoint).unwrap();

    // In an isolated user and mount namespace, bind-mount outside to mountpoint
    let unshared = unsafe {
        rustix::thread::unshare_unsafe(
            rustix::thread::UnshareFlags::NEWUSER | rustix::thread::UnshareFlags::NEWNS,
        )
    };
    if let Err(e) = unshared {
        eprintln!("unshare not supported in environment: {e}");
        std::process::exit(0);
    }
    let _ = fs::write("/proc/self/setgroups", b"deny");
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let _ = fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"));
    let _ = fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"));

    if let Err(e) = rustix::mount::mount_bind(&outside, &mountpoint) {
        eprintln!("mount_bind failed: {e}");
        std::process::exit(0);
    }

    // Destruction must refuse traversal over same-filesystem mount boundary
    let res = jail.destroy(deadline(TIMEOUT).unwrap());
    assert_eq!(
        res,
        Err(Error::Validation("cleanup mount boundary")),
        "destroy must refuse mount crossing"
    );
    // Sentinel file must be preserved
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"preserve-me",
        "sentinel file must be preserved"
    );
    std::process::exit(0);
}

#[test]
fn destruction_refuses_same_filesystem_bind_mount_and_preserves_sentinel() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "bind_mount_child", "--nocapture"])
        .env(BIND_MOUNT_CHILD, "1")
        .output()
        .expect("spawn bind mount child");
    assert!(
        output.status.success(),
        "child failed: stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejected_specifications_create_no_artifacts() {
    for bad_id in ["--exec-file", "--netns", "--id", "--chroot-base-dir", "-vm"] {
        let f = Fixture::new();
        let mut spec = f.spec.clone();
        spec.id = bad_id.into();
        assert!(spec.validate().is_err());

        // If an unvalidated spec is somehow used or before preparation, no artifacts exist
        assert!(!f.temp.path().join(format!("firecracker/{bad_id}")).exists());
        assert!(!f.temp.path().join("firecracker").exists());
    }
}
