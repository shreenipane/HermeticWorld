mod support;
use hermetic_vmm::{spec::*, *};
use serde_json::{json, Value};
use support::spec;

#[test]
fn agent_and_extractor_full_known_answers() {
    for (role, fixture) in [
        (Role::Agent, include_str!("fixtures/agent-requests.json")),
        (
            Role::Extractor,
            include_str!("fixtures/extractor-requests.json"),
        ),
    ] {
        let actual = serde_json::to_value(api_requests(&spec(role).validate().unwrap())).unwrap();
        assert_eq!(actual, serde_json::from_str::<Value>(fixture).unwrap());
    }
}
#[test]
fn jail_vector_known_answer() {
    let p = jail_plan(&spec(Role::Agent).validate().unwrap());
    assert_eq!(
        p.args,
        vec![
            "--id",
            "vm-0",
            "--exec-file",
            "/jails/firecracker/vm-0/firecracker",
            "--uid",
            "200000",
            "--gid",
            "200000",
            "--chroot-base-dir",
            "/jails",
            "--cgroup-version",
            "2",
            "--cgroup",
            "cpu.max=200000 100000",
            "--cgroup",
            "memory.max=402653184",
            "--cgroup",
            "pids.max=128",
            "--netns",
            "/var/run/netns/isolated-0",
            "--new-pid-ns",
            "--resource-limit",
            "fsize=67108864",
            "--resource-limit",
            "no-file=128",
            "--",
            "--api-sock",
            "/api.socket"
        ]
    );
    assert_eq!(p.root, "/jails/firecracker/vm-0/root");
    assert_eq!((p.uid, p.gid), (200000, 200000));
    assert!(p
        .files
        .iter()
        .all(|f| f.rule == "copy" || f.rule == "empty-4096"));
    assert!(p
        .files
        .iter()
        .any(|f| f.destination == "drive-overlay" && f.writable && f.rule == "copy"));
}
#[test]
fn all_roles_attach_entropy_and_template_without_metadata_or_balloon() {
    for role in [Role::Agent, Role::Net, Role::Extractor, Role::Grader] {
        let requests = api_requests(&spec(role).validate().unwrap());
        assert!(requests.iter().all(|r| !r.path.starts_with("/mmds")
            && !r.path.starts_with("/balloon")
            && !r.path.starts_with("/logger")
            && !r.path.starts_with("/metrics")));
        assert_eq!(requests.last().unwrap().path, "/entropy");
        assert_eq!(requests[1].path, "/cpu-config");
        assert_eq!(requests[1].body, plan::cpu_template());
        assert!(requests.iter().any(|r| r.path == "/drives/tests"
            && r.body["path_on_host"] == "/drive-tests"
            && r.body["is_read_only"] == true));
    }
}
#[test]
fn template_changes_exactly_leaf_eax_bits_zero_and_three() {
    let file: Value = serde_json::from_str(plan::CPU_TEMPLATE).unwrap();
    assert_eq!(
        file,
        json!({
            "cpuid_modifiers": [{
                "leaf": "0x40000001",
                "subleaf": "0x0",
                "flags": 0,
                "modifiers": [{
                    "register": "eax",
                    "bitmap": "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx0"
                }]
            }]
        })
    );
    let bitmap = file["cpuid_modifiers"][0]["modifiers"][0]["bitmap"]
        .as_str()
        .unwrap()
        .strip_prefix("0b")
        .unwrap();
    assert_eq!(bitmap.len(), 32);
    assert_eq!(
        bitmap
            .chars()
            .rev()
            .enumerate()
            .filter_map(|(i, c)| if c != 'x' { Some((i, c)) } else { None })
            .collect::<Vec<_>>(),
        vec![(0, '0'), (3, '0')]
    );
}
#[test]
fn every_boot_argument_rule() {
    let good = "clocksource=tsc tsc=reliable hermetic.t=1700000000 ro";
    validate_boot_args(good).unwrap();
    for bad in [
        "",
        "tsc=reliable hermetic.t=1 ro",
        "clocksource=tsc hermetic.t=1 ro",
        "clocksource=tsc tsc=reliable ro",
        "clocksource=tsc tsc=reliable hermetic.t=1",
        "clocksource=kvm-clock tsc=reliable hermetic.t=1 ro",
        "-- clocksource=tsc tsc=reliable hermetic.t=1 ro",
        "clocksource=tsc -- tsc=reliable hermetic.t=1 ro",
        "clocksource=tsc tsc=reliable -- hermetic.t=1 ro",
        "clocksource=tsc tsc=reliable hermetic.t=1 -- ro",
        "clocksource=tsc tsc=reliable hermetic.t=1 ro --",
        "root=/dev/vda init=/sbin/hermetic-execd -- clocksource=tsc tsc=reliable hermetic.t=1 ro",
    ] {
        assert!(validate_boot_args(bad).is_err(), "{bad}");
    }
    for suffix in [
        " rw",
        " rw=1",
        " ip=dhcp",
        " clocksource=kvm-clock",
        " clocksource=tsc",
        " hermetic.t=2",
        " tsc=unstable",
        "\n",
        "\0",
        " quoted=\"value\"",
        " quoted='value'",
        " escaped=\\value",
    ] {
        assert!(validate_boot_args(&format!("{good}{suffix}")).is_err());
    }
    for t in [
        "-1",
        "+1",
        "",
        "999999999999999999999999999",
        "4102444801",
        "1x",
    ] {
        assert!(
            validate_boot_args(&format!("clocksource=tsc tsc=reliable hermetic.t={t} ro")).is_err()
        );
    }
    assert!(validate_boot_args(&"a".repeat(MAX_BOOT_ARGS + 1)).is_err());
}
#[test]
fn release_lock_matches_owner_supplied_archive_pin() {
    let lock: Value =
        serde_json::from_str(include_str!("../../../vmm/firecracker.lock.json")).unwrap();
    assert_eq!(lock["version"], "1.18.0");
    assert_eq!(lock["release_date"], "2026-11-09");
    assert_eq!(lock["release_url"], "https://github.com/firecracker-microvm/firecracker/releases/download/v1.18.0/firecracker-v1.18.0-x86_64.tgz");
    assert_eq!(
        lock["archive_sha256"],
        "1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd"
    );
    // Verified binary hashes
    assert_eq!(
        lock["firecracker_sha256"],
        "b33f46cd6d88834cf6a4f8d184f08f219809c636236bffd286d233a60602a2ba"
    );
    assert_eq!(
        lock["jailer_sha256"],
        "ddadbaa15b5c942271a83b7040ca7259c8ccf92a9e08d44cce0b86fa407ba460"
    );
    assert_ne!(lock["firecracker_sha256"], "TO-BE-FILLED-BY-OWNER");
    assert_ne!(lock["jailer_sha256"], "TO-BE-FILLED-BY-OWNER");
}
#[test]
fn phase3_task_briefs_integrity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let briefs = [
        "agy-tasks/T3.1-execd.md",
        "agy-tasks/T3.2-guest-kernel.md",
        "agy-tasks/T3.3-vmm.md",
        "agy-tasks/T3.4-attest.md",
        "agy-tasks/T3.5-extract-validator.md",
        "agy-tasks/T3.6-classifier.md",
        "agy-tasks/T3.7-mutants-variants.md",
    ];
    for brief in briefs {
        let p = root.join(brief);
        assert!(p.is_file(), "missing Phase 3 brief: {brief}");
        let meta = std::fs::metadata(&p).unwrap();
        assert!(meta.len() > 100, "empty or truncated brief: {brief}");
    }
}
#[test]
fn project_mac_known_answers_are_independent_of_host_identity() {
    for (role, expected) in [
        (Role::Agent, "02:48:57:01:00:00"),
        (Role::Net, "02:48:57:02:00:00"),
        (Role::Extractor, "02:48:57:03:00:00"),
        (Role::Grader, "02:48:57:04:00:00"),
    ] {
        assert_eq!(project_mac(role, 0), expected);
    }
    assert_eq!(project_mac(Role::Agent, 1), "02:48:57:01:00:01");
}
#[test]
fn validates_roles_devices_identifiers_paths_and_caps() {
    type Mutation = Box<dyn Fn(&mut VmSpec)>;
    let cases: Vec<Mutation> = vec![
        Box::new(|s| s.id = "../escape".into()),
        Box::new(|s| s.id = "A".into()),
        Box::new(|s| s.id = "x".repeat(49)),
        Box::new(|s| s.id = "--exec-file".into()),
        Box::new(|s| s.id = "--netns".into()),
        Box::new(|s| s.id = "-bad".into()),
        Box::new(|s| s.jail.netns = "--netns".into()),
        Box::new(|s| s.jail.netns = "-ns".into()),
        Box::new(|s| s.index = 4096),
        Box::new(|s| s.vcpus = 0),
        Box::new(|s| s.vcpus = 33),
        Box::new(|s| s.memory_mib = 63),
        Box::new(|s| s.memory_mib = MAX_MEMORY_MIB + 1),
        Box::new(|s| s.kernel_image = "/images/../kernel".into()),
        Box::new(|s| s.kernel_image = "relative".into()),
        Box::new(|s| s.kernel_image = "/images//kernel".into()),
        Box::new(|s| s.root_drive.read_only = false),
        Box::new(|s| s.drives.clear()),
        Box::new(|s| s.drives[0].read_only = true),
        Box::new(|s| s.drives[0].id = "rootfs".into()),
        Box::new(|s| s.reserved_drives = vec!["rootfs".into()]),
        Box::new(|s| s.reserved_drives = vec!["x".into(); MAX_DRIVES + 1]),
        Box::new(|s| s.vsock.as_mut().unwrap().guest_cid = 2),
        Box::new(|s| s.vsock.as_mut().unwrap().socket_path = "/host/socket".into()),
        Box::new(|s| s.networks[0].guest_mac = "02:00:00:00:00:00".into()),
        Box::new(|s| s.networks[0].peer = Role::Grader),
        Box::new(|s| s.networks[0].tap = "bad/tap".into()),
        Box::new(|s| s.networks.push(s.networks[0].clone())),
        Box::new(|s| s.limits.pids = 0),
        Box::new(|s| s.limits.open_files = 4097),
        Box::new(|s| s.limits.file_size_bytes = MAX_IMAGE_BYTES + 1),
        Box::new(|s| s.jail.uid_start = u32::MAX),
        Box::new(|s| s.jail.gid_start = 0),
        Box::new(|s| s.jail.count = 0),
        Box::new(|s| s.jail.netns = "../host".into()),
        Box::new(|s| s.jail.firecracker = "/bin/other".into()),
    ];
    for (i, case) in cases.into_iter().enumerate() {
        let mut s = spec(Role::Agent);
        case(&mut s);
        assert!(s.validate().is_err(), "case {i}");
    }
    for role in [Role::Extractor, Role::Grader] {
        let mut s = spec(Role::Agent);
        s.role = role;
        assert!(s.validate().is_err());
    }
    let mut grader = spec(Role::Grader);
    grader.vsock = spec(Role::Agent).vsock;
    assert!(grader.validate().is_err());
    let mut net = spec(Role::Net);
    net.drives = spec(Role::Agent).drives;
    assert!(net.clone().validate().is_err());
    net.drives.clear();
    net.networks = spec(Role::Agent).networks;
    assert!(net.validate().is_err());
    let mut hidden = spec(Role::Agent);
    hidden.clock = Clock::Hidden;
    let message = hidden.validate().unwrap_err().to_string();
    for requirement in [
        "TR-VMM-3",
        "enforce-pv-cpuid",
        "restore",
        "KVM_HC_CLOCK_PAIRING",
        "guest-module probe",
    ] {
        assert!(message.contains(requirement));
    }
}
#[test]
fn run_rejects_duplicate_cid_uid_gid_and_id() {
    assert!(validate_run(vec![]).is_err());
    let a = spec(Role::Agent);
    let mut b = spec(Role::Net);
    b.id = "vm-1".into();
    b.index = 1;
    assert!(validate_run(vec![a.clone(), b.clone()]).is_err());
    b.vsock.as_mut().unwrap().guest_cid = 4;
    assert!(validate_run(vec![a.clone(), b.clone()]).is_ok());
    b.id = a.id.clone();
    assert!(validate_run(vec![a.clone(), b.clone()]).is_err());
    b.id = "vm-1".into();
    b.index = 0;
    assert!(validate_run(vec![a.clone(), b.clone()]).is_err());
    b.jail.uid_start += 1;
    assert!(validate_run(vec![a, b]).is_err());
}
#[test]
fn spec_json_is_strict_and_bounded_without_echoing_input() {
    let value = serde_json::to_value(spec(Role::Agent)).unwrap();
    let mut unknown = value.clone();
    unknown["secret-host-path"] = json!("sensitive");
    assert_eq!(
        VmSpec::read(serde_json::to_vec(&unknown).unwrap().as_slice())
            .unwrap_err()
            .to_string(),
        "refused: invalid spec JSON"
    );
    let mut nested = value.clone();
    nested["limits"]["extra"] = json!(true);
    assert!(VmSpec::read(serde_json::to_vec(&nested).unwrap().as_slice()).is_err());
    for bad in [
        vec![b' '; MAX_SPEC_BYTES as usize + 1],
        vec![0],
        vec![255],
        b"{".to_vec(),
    ] {
        assert!(VmSpec::read(bad.as_slice()).is_err());
    }
    assert!(VmSpec::read(serde_json::to_vec(&value).unwrap().as_slice())
        .unwrap()
        .validate()
        .is_ok());
}
#[test]
fn default_configuration_cannot_select_development_runner() {
    assert!(runner::refuse_dev_unjailed().is_err());
    let mut value = serde_json::to_value(spec(Role::Agent)).unwrap();
    value["runner"] = json!("dev_unjailed");
    assert!(VmSpec::read(serde_json::to_vec(&value).unwrap().as_slice()).is_err());
}
