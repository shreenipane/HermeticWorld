use hermetic_grader_sandbox::{encode_plan, plan, EnvEntry, PlanError, PlanInput};

fn base_input() -> PlanInput {
    PlanInput {
        argv: vec![
            "pytest".to_owned(),
            "-q".to_owned(),
            "tests/test_core.py".to_owned(),
        ],
        working_dir: "/workspace/repo".to_owned(),
        home_dir: None,
        uid: 1000,
        gid: 1000,
        env_allowlist: vec![EnvEntry {
            name: "CUSTOM_FLAG".to_owned(),
            value: "enabled".to_owned(),
        }],
        t_clock: 1_700_000_000,
        required_pytest_plugins: vec!["asyncio".to_owned(), "cov".to_owned()],
    }
}

#[test]
fn test_capability_set_exactness() {
    let p = plan(&base_input()).expect("valid plan");
    let expected = vec![
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
    assert_eq!(p.capabilities.bounding, expected);
    assert_eq!(p.capabilities.effective, expected);
    assert_eq!(p.capabilities.permitted, expected);
    assert!(p.capabilities.inheritable.is_empty());
    assert!(p.capabilities.ambient.is_empty());
    assert!(p.capabilities.no_new_privileges);

    let forbidden = [
        "CAP_MKNOD",
        "CAP_SYS_ADMIN",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_PTRACE",
        "CAP_SYS_TIME",
        "CAP_NET_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_MAC_ADMIN",
        "CAP_MAC_OVERRIDE",
        "CAP_SYSLOG",
        "CAP_BPF",
        "CAP_PERFMON",
        "CAP_CHECKPOINT_RESTORE",
    ];
    for f in forbidden {
        assert!(!p.capabilities.bounding.iter().any(|c| c == f));
        assert!(!p.capabilities.effective.iter().any(|c| c == f));
        assert!(!p.capabilities.permitted.iter().any(|c| c == f));
    }
}

#[test]
fn test_device_list_and_cgroup_rule_order() {
    let p = plan(&base_input()).expect("valid plan");
    let majors_minors: Vec<(&str, u32, u32, &str)> = p
        .devices
        .iter()
        .map(|d| (d.path.as_str(), d.major, d.minor, d.mode.as_str()))
        .collect();
    assert_eq!(
        majors_minors,
        vec![
            ("/dev/null", 1, 3, "0666"),
            ("/dev/zero", 1, 5, "0666"),
            ("/dev/full", 1, 7, "0666"),
            ("/dev/random", 1, 8, "0666"),
            ("/dev/urandom", 1, 9, "0666"),
            ("/dev/tty", 5, 0, "0666"),
        ]
    );

    assert_eq!(p.device_cgroup_rules.len(), 10);
    // First 8 allow the character devices and private PTYs, followed by block/default denies.
    for rule in &p.device_cgroup_rules[..8] {
        assert!(rule.allow);
        assert_eq!(rule.dev_type, "c");
    }
    assert!(!p.device_cgroup_rules[8].allow);
    assert_eq!(p.device_cgroup_rules[8].dev_type, "b");
    assert_eq!(p.device_cgroup_rules[8].major, None);
    assert_eq!(p.device_cgroup_rules[8].minor, None);

    assert!(!p.device_cgroup_rules[9].allow);
    assert_eq!(p.device_cgroup_rules[9].dev_type, "a");
}

#[test]
fn test_environment_exactness_and_no_host_leak() {
    std::env::set_var("HERMETIC_HOST_SECRET_CANARY", "must_not_leak");
    let p = plan(&base_input()).expect("valid plan");
    assert!(!p.env.contains_key("HERMETIC_HOST_SECRET_CANARY"));
    assert_eq!(p.env.len(), 8);
    assert_eq!(p.env.get("HOME").map(String::as_str), Some("/root"));
    assert_eq!(p.env.get("LANG").map(String::as_str), Some("C.UTF-8"));
    assert_eq!(
        p.env.get("PATH").map(String::as_str),
        Some("/usr/local/bin:/usr/bin:/bin")
    );
    assert_eq!(
        p.env
            .get("PYTEST_DISABLE_PLUGIN_AUTOLOAD")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        p.env.get("PYTHONDONTWRITEBYTECODE").map(String::as_str),
        Some("1")
    );
    assert_eq!(p.env.get("PYTHONHASHSEED").map(String::as_str), Some("0"));
    assert_eq!(p.env.get("TZ").map(String::as_str), Some("UTC"));
    assert_eq!(
        p.env.get("CUSTOM_FLAG").map(String::as_str),
        Some("enabled")
    );
}

#[test]
fn test_command_rewriting_and_refusals() {
    let mut inp = base_input();
    inp.argv = vec![
        "/usr/bin/python3.11".to_owned(),
        "-m".to_owned(),
        "pytest".to_owned(),
        "-k".to_owned(),
        "smoke".to_owned(),
    ];
    inp.required_pytest_plugins = vec!["xdist".to_owned(), "asyncio".to_owned()];
    let p = plan(&inp).expect("valid python -m pytest");
    assert_eq!(
        p.argv,
        vec!["python", "-s", "-m", "pytest", "-p", "asyncio", "-p", "xdist", "-k", "smoke",]
    );

    // Refusal: non-pytest command
    let mut bad_cmd = base_input();
    bad_cmd.argv = vec!["bash".to_owned(), "-c".to_owned(), "id".to_owned()];
    assert_eq!(plan(&bad_cmd), Err(PlanError::NotPytestCommand));

    // Refusal: python -c
    let mut py_c = base_input();
    py_c.argv = vec!["python".to_owned(), "-c".to_owned(), "import os".to_owned()];
    assert_eq!(plan(&py_c), Err(PlanError::NotPytestCommand));

    // Refusal: reserved env override
    let mut bad_env = base_input();
    bad_env.env_allowlist = vec![EnvEntry {
        name: "PATH".to_owned(),
        value: "/evil".to_owned(),
    }];
    assert_eq!(plan(&bad_env), Err(PlanError::ReservedEnvOverride));

    // Refusal: invalid env name
    let mut bad_env_name = base_input();
    bad_env_name.env_allowlist = vec![EnvEntry {
        name: "lower_case".to_owned(),
        value: "1".to_owned(),
    }];
    assert_eq!(plan(&bad_env_name), Err(PlanError::InvalidEnvName));

    // Refusal: traversal in working_dir
    let mut bad_dir = base_input();
    bad_dir.working_dir = "/workspace/../etc".to_owned();
    assert_eq!(plan(&bad_dir), Err(PlanError::InvalidPath));
}

#[test]
fn test_known_answer_and_determinism() {
    let inp1 = base_input();
    let mut inp2 = base_input();
    inp2.required_pytest_plugins.reverse();

    let json1 = encode_plan(&plan(&inp1).expect("plan 1"));
    let json2 = encode_plan(&plan(&inp2).expect("plan 2"));
    assert_eq!(json1, json2);

    let text = std::str::from_utf8(&json1).expect("utf8");
    assert!(text.contains(r#""argv":["python","-s","-m","pytest","-p","asyncio","-p","cov","-q","tests/test_core.py"]"#));
    assert!(text.contains(r#""user":false"#));
    assert!(text.contains(r#""t_clock":1700000000"#));
    assert!(text.contains(r#""destination":"/tmp","fs_type":"bind""#));
}
