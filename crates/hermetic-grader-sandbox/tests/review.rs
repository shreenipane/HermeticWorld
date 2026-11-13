use hermetic_grader_sandbox::{encode_plan, plan, EnvEntry, PlanInput};

fn input() -> PlanInput {
    PlanInput {
        argv: vec!["pytest".into()],
        working_dir: "/workspace/repo".into(),
        home_dir: None,
        uid: 0,
        gid: 0,
        env_allowlist: vec![],
        t_clock: 1_700_000_000,
        required_pytest_plugins: vec![],
    }
}

#[test]
fn review_mount_destinations_cannot_replace_isolation() {
    for path in [
        "/",
        "/proc",
        "/dev",
        "/sys",
        "/proc/child",
        "/dev/shm/x",
        "/tmp",
        "/workspace//repo",
        "/workspace/./repo",
        "/workspace/repo/",
        "/workspace/line\nbreak",
    ] {
        let mut i = input();
        i.working_dir = path.into();
        assert!(plan(&i).is_err(), "{path}");
    }
    assert!(plan(&input()).is_ok());
}

#[test]
fn review_environment_cannot_override_runtime_controls() {
    for name in [
        "LC_ALL",
        "LC_TIME",
        "LANGUAGE",
        "TZDIR",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ] {
        let mut i = input();
        i.env_allowlist = vec![EnvEntry {
            name: name.into(),
            value: "host-canary".into(),
        }];
        assert!(plan(&i).is_err(), "{name}");
    }
}

#[test]
fn review_interpreter_flags_preserved() {
    let mut i = input();
    i.argv = ["python3", "-B", "-OO", "-u", "-m", "pytest", "-q"]
        .map(String::from)
        .to_vec();
    let p = plan(&i).unwrap();
    for flag in ["-B", "-OO", "-u"] {
        assert!(p.argv.iter().any(|a| a == flag));
    }
}

#[test]
fn review_plan_sets_hostname_and_clears_supplementary_groups() {
    let p = plan(&input()).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&encode_plan(&p)).unwrap();
    assert_eq!(json["hostname"], "hermetic");
    assert_eq!(json["domainname"], "hermetic");
    assert_eq!(json["supplementary_groups"], serde_json::json!([]));
}

#[test]
fn review_mount_tree_is_private_before_mounting() {
    let value: serde_json::Value =
        serde_json::from_slice(&encode_plan(&plan(&input()).unwrap())).unwrap();
    assert_eq!(value["mount_propagation"], "rprivate");
}

#[test]
fn review_private_ptys_work_and_block_devices_remain_denied() {
    let p = plan(&input()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&encode_plan(&p)).unwrap();
    assert!(value["device_symlinks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["path"] == "/dev/ptmx" && s["target"] == "pts/ptmx"));
    let allowed = |kind: &str, major, minor| {
        p.device_cgroup_rules
            .iter()
            .find(|r| {
                (r.dev_type == "a" || r.dev_type == kind)
                    && r.major.is_none_or(|m| m == major)
                    && r.minor.is_none_or(|m| m == minor)
            })
            .is_some_and(|r| r.allow)
    };
    assert!(allowed("c", 5, 2));
    assert!(allowed("c", 136, 0));
    assert!(allowed("c", 136, 255));
    for major in [1, 8, 252] {
        for minor in [0, 1, 255] {
            assert!(!allowed("b", major, minor));
        }
    }
    assert!(!allowed("c", 10, 200));
}

#[test]
fn review_required_plugins_cannot_be_disabled_by_tail() {
    for (required, tail) in [
        ("cov", vec!["-p", "no:cov"]),
        ("cov", vec!["-pno:cov"]),
        ("pytest_cov", vec!["-p", "no:cov"]),
        ("cov", vec!["--", "-p", "no:cov"]),
        ("cov", vec!["-p", " no:cov "]),
        ("cov", vec!["-p\u{1c}no:cov\u{1f}"]),
        ("stepwise", vec!["-p", "no:cacheprovider"]),
    ] {
        let mut i = input();
        i.required_pytest_plugins = vec![required.into()];
        i.argv.extend(tail.into_iter().map(String::from));
        assert!(plan(&i).is_err());
    }
}

#[test]
fn review_python_flags_cannot_ignore_deterministic_environment() {
    for flag in ["-E", "-I"] {
        let mut i = input();
        i.argv = ["python", flag, "-m", "pytest"].map(String::from).to_vec();
        assert!(plan(&i).is_err(), "{flag} ignores PYTHONHASHSEED=0");
    }
}

#[test]
fn review_memory_filesystems_and_ptys_have_explicit_caps() {
    let p = plan(&input()).unwrap();
    for destination in ["/dev", "/dev/shm"] {
        let mount = p
            .mounts
            .iter()
            .find(|m| m.destination == destination)
            .unwrap();
        assert!(
            mount.options.iter().any(|o| o.starts_with("size=")),
            "{destination}"
        );
        assert!(
            mount.options.iter().any(|o| o.starts_with("nr_inodes=")),
            "{destination}"
        );
    }
    let pts = p
        .mounts
        .iter()
        .find(|m| m.destination == "/dev/pts")
        .unwrap();
    assert!(pts.options.iter().any(|o| o.starts_with("max=")));
    assert!(pts.options.contains(&"max=256".to_owned()));
    for (destination, size, inodes) in [
        ("/dev", "size=1048576", "nr_inodes=1024"),
        ("/dev/shm", "size=67108864", "nr_inodes=4096"),
    ] {
        let mount = p
            .mounts
            .iter()
            .find(|m| m.destination == destination)
            .unwrap();
        assert!(mount.options.iter().any(|o| o == size));
        assert!(mount.options.iter().any(|o| o == inodes));
    }
}

#[test]
fn review_private_plugin_names_are_supported() {
    let mut i = input();
    i.required_pytest_plugins = vec!["_capture".into()];
    let p = plan(&i).expect("valid private plugin name");
    assert!(p.argv.windows(2).any(|args| args == ["-p", "_capture"]));
}
