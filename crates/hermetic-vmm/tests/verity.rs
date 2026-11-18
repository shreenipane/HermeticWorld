mod support;
use hermetic_vmm::api_requests;
use hermetic_vmm::fs::PreparedJail;
use hermetic_vmm::spec::{
    split_boot_args, validate_boot_args, validate_boot_args_for_role, Drive, Network, Role,
};
use hermetic_vmm::verity::{
    calculate_tree_layout, compute_verity_tree, format_dm_create, parse_dm_create,
    verify_root_block, BLOCK_BYTES,
};
use hermetic_vmm::{Error, State, Vmm};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

#[test]
fn verity_table_parse_and_tamper() {
    let root_hash = "a".repeat(64);
    let salt = "b".repeat(64);
    let formatted = format_dm_create("netvm", 2048, &root_hash, &salt).unwrap();
    assert!(formatted.starts_with(
        "dm-mod.create=\"netvm,,,ro,0 16384 verity 1 /dev/vda /dev/vdb 4096 4096 2048 0 sha256 "
    ));

    let table = parse_dm_create(&formatted).unwrap();
    assert_eq!(table.device_name, "netvm");
    assert_eq!(table.num_sectors, 16384);
    assert_eq!(table.data_device, "/dev/vda");
    assert_eq!(table.hash_device, "/dev/vdb");
    assert_eq!(table.data_block_size, 4096);
    assert_eq!(table.hash_block_size, 4096);
    assert_eq!(table.num_data_blocks, 2048);
    assert_eq!(table.hash_start_block, 0);
    assert_eq!(table.algorithm, "sha256");
    assert_eq!(table.root_hash, root_hash);
    assert_eq!(table.salt, salt);

    // Hostile mutations
    // Wrong device name
    assert!(parse_dm_create(&formatted.replace("netvm,,,ro", "agent,,,ro")).is_err());
    // Writable device
    assert!(parse_dm_create(&formatted.replace(",,,ro,", ",,,rw,")).is_err());
    // Sector mismatch
    assert!(parse_dm_create(&formatted.replace("0 16384 verity", "0 16385 verity")).is_err());
    // Non-zero start sector
    assert!(parse_dm_create(&formatted.replace("0 16384 verity", "1 16384 verity")).is_err());
    // Wrong target type
    assert!(parse_dm_create(&formatted.replace("verity 1", "linear 1")).is_err());
    // Wrong verity version
    assert!(parse_dm_create(&formatted.replace("verity 1", "verity 0")).is_err());
    // Wrong data device
    assert!(parse_dm_create(&formatted.replace("/dev/vda", "/dev/vdc")).is_err());
    // Wrong hash device
    assert!(parse_dm_create(&formatted.replace("/dev/vdb", "/dev/vdd")).is_err());
    // Wrong block size
    assert!(parse_dm_create(&formatted.replace("4096 4096", "512 512")).is_err());
    // Hash start block != 0
    assert!(parse_dm_create(&formatted.replace("2048 0 sha256", "2048 1 sha256")).is_err());
    // Non-sha256 algorithm
    assert!(parse_dm_create(&formatted.replace("sha256", "sha512")).is_err());
    // Corrupted hex in root hash
    assert!(parse_dm_create(&formatted.replace(&root_hash, &"g".repeat(64))).is_err());
    // Truncated root hash
    assert!(parse_dm_create(&formatted.replace(&root_hash, &"a".repeat(63))).is_err());
    // Corrupted hex in salt
    assert!(parse_dm_create(&formatted.replace(&salt, &"z".repeat(64))).is_err());
    // Bad optional params
    assert!(
        parse_dm_create(&formatted.replace("1 restart_on_corruption", "1 ignore_corruption"))
            .is_err()
    );
    // Missing quotes
    let unquoted = formatted
        .strip_prefix("dm-mod.create=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    assert_eq!(parse_dm_create(unquoted).unwrap(), table);
}

#[test]
fn verity_boot_args_role_separation() {
    let root_hash = "c".repeat(64);
    let salt = "d".repeat(64);
    let dm_create = format_dm_create("netvm", 1024, &root_hash, &salt).unwrap();
    let netvm_boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
    );

    // Valid NetVM boot args pass for NetVM role
    assert!(validate_boot_args_for_role(&netvm_boot_args, Role::Net).is_ok());
    assert!(validate_boot_args(&netvm_boot_args).is_ok());

    // Non-NetVM roles must strictly refuse dm-mod.create and root=/dev/dm-0
    for role in [Role::Agent, Role::Grader, Role::Extractor] {
        assert_eq!(
            validate_boot_args_for_role(&netvm_boot_args, role),
            Err(Error::Validation(
                "dm-mod.create only permitted for NetVM role"
            ))
        );
        let dm_root_only = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-execd clocksource=tsc tsc=reliable hermetic.t=1700000000 ro";
        assert_eq!(
            validate_boot_args_for_role(dm_root_only, role),
            Err(Error::Validation(
                "root=/dev/dm-0 only permitted for NetVM role"
            ))
        );
    }

    // NetVM with dm-mod.create requires root=/dev/dm-0
    let bad_netvm_root = netvm_boot_args.replace("root=/dev/dm-0", "root=/dev/vda");
    assert_eq!(
        validate_boot_args_for_role(&bad_netvm_root, Role::Net),
        Err(Error::Validation(
            "NetVM with dm-verity requires root=/dev/dm-0"
        ))
    );

    // NetVM with root=/dev/dm-0 requires dm-mod.create
    let missing_dm = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro";
    assert_eq!(
        validate_boot_args_for_role(missing_dm, Role::Net),
        Err(Error::Validation(
            "root=/dev/dm-0 requires dm-mod.create verity table"
        ))
    );

    // Tokens outside dm-mod.create cannot contain quotes
    let quote_injection =
        netvm_boot_args.replace("init=/sbin/hermetic-netvm", "init=\"/sbin/hermetic-netvm\"");
    assert!(split_boot_args(&quote_injection).is_err());
}

#[test]
fn verity_tree_known_answer_and_tamper() {
    // 1 block: no hash blocks; root is direct hash
    assert_eq!(calculate_tree_layout(1).unwrap(), (0, vec![]));
    // 128 blocks: fits in 1 hash block (level 0)
    assert_eq!(calculate_tree_layout(128).unwrap(), (1, vec![1]));
    // 129 blocks: 2 hash blocks at level 0, 1 at level 1 -> 3 total
    assert_eq!(calculate_tree_layout(129).unwrap(), (3, vec![2, 1]));
    // 16384 blocks: 128 blocks at level 0, 1 at level 1 -> 129 total
    assert_eq!(calculate_tree_layout(16384).unwrap(), (129, vec![128, 1]));
    // 16385 blocks: 129 blocks at level 0, 2 at level 1, 1 at level 2 -> 132 total
    assert_eq!(
        calculate_tree_layout(16385).unwrap(),
        (132, vec![129, 2, 1])
    );

    let salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let data = vec![0x42u8; BLOCK_BYTES * 2]; // 2 data blocks
    let (root_hash, hash_image) = compute_verity_tree(&data, salt).unwrap();
    assert_eq!(hash_image.len(), BLOCK_BYTES); // 1 hash block

    // Root block verification succeeds with matching root block and salt
    assert!(verify_root_block(&hash_image[..BLOCK_BYTES], salt, &root_hash).is_ok());

    // Tampering root block fails verification
    let mut bad_root_block = hash_image[..BLOCK_BYTES].to_vec();
    bad_root_block[0] ^= 0xff;
    assert_eq!(
        verify_root_block(&bad_root_block, salt, &root_hash),
        Err(Error::Validation("verity root hash mismatch"))
    );

    // Tampering salt fails verification
    let mut bad_salt = salt.to_string();
    bad_salt.replace_range(0..2, "ff");
    assert_eq!(
        verify_root_block(&hash_image[..BLOCK_BYTES], &bad_salt, &root_hash),
        Err(Error::Validation("verity root hash mismatch"))
    );

    // Tampering data block produces different root hash
    let mut tampered_data = data.clone();
    tampered_data[10] ^= 0x01;
    let (tampered_root_hash, _) = compute_verity_tree(&tampered_data, salt).unwrap();
    assert_ne!(root_hash, tampered_root_hash);
}

#[test]
fn verity_prepared_jail_validates_artifacts() {
    let mut f = support::Fixture::new();
    let base = f.temp.path().to_path_buf();
    f.spec.id = "net-0".into();
    f.spec.role = Role::Net;
    f.spec.networks = vec![Network {
        tap: "net-tap".into(),
        guest_mac: hermetic_vmm::spec::project_mac(Role::Net, 0),
        peer: Role::Agent,
    }];

    // Build 2 data blocks
    let data_bytes = vec![0x37u8; BLOCK_BYTES * 2];
    let salt = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let (root_hash, hash_bytes) = compute_verity_tree(&data_bytes, salt).unwrap();

    let data_path = base.join("netvm-data.img");
    fs::write(&data_path, &data_bytes).unwrap();
    fs::set_permissions(&data_path, fs::Permissions::from_mode(0o400)).unwrap();

    let hash_path = base.join("netvm-hash.img");
    fs::write(&hash_path, &hash_bytes).unwrap();
    fs::set_permissions(&hash_path, fs::Permissions::from_mode(0o400)).unwrap();

    f.spec.root_drive = Drive {
        id: "rootfs".into(),
        path: data_path.to_str().unwrap().into(),
        read_only: true,
    };
    f.spec.drives = vec![Drive {
        id: "verity_hash".into(),
        path: hash_path.to_str().unwrap().into(),
        read_only: true,
    }];

    let dm_create = format_dm_create("netvm", 2, &root_hash, salt).unwrap();
    f.spec.boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
    );

    // Verity hash drive id must refuse verity-hash
    let mut bad_hash_id = f.spec.clone();
    bad_hash_id.drives[0].id = "verity-hash".into();
    assert!(bad_hash_id.validate().is_err());

    // Validation passes for correct spec
    let valid = f.spec.clone().validate().unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    let jail = PreparedJail::prepare(&valid, end).unwrap();
    assert!(jail.root.identity().is_ok());

    // Corrupted data size fails closed
    let mut bad_data_f = f.spec.clone();
    let bad_data_path = base.join("bad-data.img");
    let mut bad_data = data_bytes.clone();
    bad_data.push(0); // not a multiple of 4096
    fs::write(&bad_data_path, &bad_data).unwrap();
    fs::set_permissions(&bad_data_path, fs::Permissions::from_mode(0o400)).unwrap();
    bad_data_f.root_drive.path = bad_data_path.to_str().unwrap().into();
    let bad_valid = bad_data_f.validate().unwrap();
    assert_eq!(
        PreparedJail::prepare(&bad_valid, end).err(),
        Some(Error::Validation("NetVM verity data drive size mismatch"))
    );

    // Corrupted hash size fails closed
    let mut bad_hash_f = f.spec.clone();
    let bad_hash_path = base.join("bad-hash.img");
    let mut bad_hash = hash_bytes.clone();
    bad_hash.extend_from_slice(&[0u8; 4096]); // extra block
    fs::write(&bad_hash_path, &bad_hash).unwrap();
    fs::set_permissions(&bad_hash_path, fs::Permissions::from_mode(0o400)).unwrap();
    bad_hash_f.drives[0].path = bad_hash_path.to_str().unwrap().into();
    let bad_valid = bad_hash_f.validate().unwrap();
    assert_eq!(
        PreparedJail::prepare(&bad_valid, end).err(),
        Some(Error::Validation("NetVM verity hash drive size mismatch"))
    );

    // Corrupted root block in hash image fails closed with root hash mismatch
    let mut corrupt_hash_f = f.spec.clone();
    let corrupt_hash_path = base.join("corrupt-hash.img");
    let mut corrupt_hash = hash_bytes.clone();
    corrupt_hash[42] ^= 0x5a;
    fs::write(&corrupt_hash_path, &corrupt_hash).unwrap();
    fs::set_permissions(&corrupt_hash_path, fs::Permissions::from_mode(0o400)).unwrap();
    corrupt_hash_f.drives[0].path = corrupt_hash_path.to_str().unwrap().into();
    let corrupt_valid = corrupt_hash_f.validate().unwrap();
    assert_eq!(
        PreparedJail::prepare(&corrupt_valid, end).err(),
        Some(Error::Validation("verity root hash mismatch"))
    );
    let mut corrupt_vm = Vmm::new(corrupt_valid, DummyRunner);
    assert_eq!(
        corrupt_vm.prepare(Duration::from_secs(30)).err(),
        Some(Error::Validation("verity root hash mismatch"))
    );
    assert_eq!(corrupt_vm.state(), State::Failed);
}

#[test]
fn verity_dm_create_minor_validation() {
    let root_hash = "a".repeat(64);
    let salt = "b".repeat(64);
    let formatted = format_dm_create("netvm", 2048, &root_hash, &salt).unwrap();
    // Default formatter produces empty minor, which is valid
    assert!(parse_dm_create(&formatted).is_ok());
    // Minor 0 is valid
    let minor_0 = formatted.replace("netvm,,,ro", "netvm,,0,ro");
    assert!(parse_dm_create(&minor_0).is_ok());
    // Minor 1 must be rejected
    let minor_1 = formatted.replace("netvm,,,ro", "netvm,,1,ro");
    assert_eq!(
        parse_dm_create(&minor_1),
        Err(Error::Validation("verity device minor must be 0 or empty"))
    );
    // Non-zero minor like 42 must be rejected
    let minor_42 = formatted.replace("netvm,,,ro", "netvm,,42,ro");
    assert_eq!(
        parse_dm_create(&minor_42),
        Err(Error::Validation("verity device minor must be 0 or empty"))
    );
}

#[test]
fn corruption_copy_permissions_regression() {
    let temp = tempfile::tempdir().unwrap();
    let src = temp.path().join("src.img");
    fs::write(&src, b"original content for verity").unwrap();
    fs::set_permissions(&src, fs::Permissions::from_mode(0o400)).unwrap();
    let dst = temp.path().join("dst.img");
    fs::copy(&src, &dst).unwrap();
    // Destination copied from 0400 file retains 0400 mode
    assert_eq!(
        fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
        0o400
    );
    // Setting 0600 allows write-enabled opening
    fs::set_permissions(&dst, fs::Permissions::from_mode(0o600)).unwrap();
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dst)
        .unwrap();
    use std::io::Write;
    f.write_all(b"modified").unwrap();
}

#[test]
fn verity_request_plan_has_no_root_device_and_single_dm_root() {
    let root_hash = "a".repeat(64);
    let salt = "b".repeat(64);
    let dm_create = format_dm_create("netvm", 2048, &root_hash, &salt).unwrap();

    let mut net = support::spec(Role::Net);
    net.drives = vec![Drive {
        id: "verity_hash".into(),
        path: "/images/verity_hash".into(),
        read_only: true,
    }];
    net.boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
    );

    let valid = net.validate().unwrap();
    let requests = api_requests(&valid);

    // 1. Verity request plan has no root device (all drives have is_root_device=false)
    let drive_reqs: Vec<_> = requests
        .iter()
        .filter(|r| r.path.starts_with("/drives/"))
        .collect();
    assert!(!drive_reqs.is_empty());
    for req in &drive_reqs {
        assert_eq!(
            req.body["is_root_device"], false,
            "drive {} must have is_root_device=false in verity VM",
            req.path
        );
    }
    assert!(
        !requests
            .iter()
            .any(|r| r.body.get("is_root_device") == Some(&serde_json::json!(true))),
        "verity plan must have no root device"
    );

    // 2. Data drive is first (/dev/vda) and hash drive is second (/dev/vdb)
    assert_eq!(drive_reqs[0].path, "/drives/rootfs");
    assert_eq!(drive_reqs[0].body["drive_id"], "rootfs");
    assert_eq!(drive_reqs[1].path, "/drives/verity_hash");
    assert_eq!(drive_reqs[1].body["drive_id"], "verity_hash");

    // 3. Boot args contain exactly one root= (root=/dev/dm-0)
    let boot = requests
        .iter()
        .find(|r| r.path == "/boot-source")
        .expect("missing /boot-source request");
    let boot_args = boot.body["boot_args"]
        .as_str()
        .expect("boot_args must be string");
    let root_args: Vec<_> = boot_args
        .split_ascii_whitespace()
        .filter(|token| token.starts_with("root="))
        .collect();
    assert_eq!(
        root_args,
        vec!["root=/dev/dm-0"],
        "boot args must contain exactly one root= (root=/dev/dm-0)"
    );
    assert!(
        boot_args.contains(&dm_create),
        "boot args must contain the dm-mod.create table"
    );

    // Calibrated api requests also preserve single root=/dev/dm-0
    let cal_requests = hermetic_vmm::plan::calibrated_api_requests(&valid, 2_000_000).unwrap();
    let cal_boot = cal_requests
        .iter()
        .find(|r| r.path == "/boot-source")
        .expect("missing calibrated /boot-source request");
    let cal_boot_args = cal_boot.body["boot_args"]
        .as_str()
        .expect("calibrated boot_args must be string");
    let cal_root_args: Vec<_> = cal_boot_args
        .split_ascii_whitespace()
        .filter(|token| token.starts_with("root="))
        .collect();
    assert_eq!(
        cal_root_args,
        vec!["root=/dev/dm-0"],
        "calibrated boot args must contain exactly one root= (root=/dev/dm-0)"
    );

    // 4. Non-verity VMs unchanged (they still use is_root_device=true on their root drive)
    for role in [Role::Agent, Role::Net, Role::Extractor, Role::Grader] {
        let non_verity = support::spec(role).validate().unwrap();
        let non_verity_reqs = api_requests(&non_verity);
        let root_drive = non_verity_reqs
            .iter()
            .find(|r| r.path == "/drives/rootfs")
            .unwrap_or_else(|| panic!("missing rootfs drive for role {role:?}"));
        assert_eq!(
            root_drive.body["is_root_device"], true,
            "non-verity role {role:?} must retain is_root_device=true on root drive"
        );
        let root_count = non_verity_reqs
            .iter()
            .filter(|r| r.body.get("is_root_device") == Some(&serde_json::json!(true)))
            .count();
        assert_eq!(
            root_count, 1,
            "non-verity role {role:?} must have exactly one root device"
        );
    }
}

#[test]
fn runtime_path_never_computes_root_hash_from_data_image() {
    let mut f = support::Fixture::new();
    let base = f.temp.path().to_path_buf();
    f.spec.id = "net-verity-runtime".into();
    f.spec.role = Role::Net;
    f.spec.networks = vec![Network {
        tap: "net-tap".into(),
        guest_mac: hermetic_vmm::spec::project_mac(Role::Net, 0),
        peer: Role::Agent,
    }];

    // 1. Build authentic 2-block data image and authentic verity hash tree
    let authentic_data = vec![0x24u8; BLOCK_BYTES * 2];
    let salt = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    let (pinned_root_hash, hash_bytes) = compute_verity_tree(&authentic_data, salt).unwrap();

    let hash_path = base.join("pinned-hash.img");
    fs::write(&hash_path, &hash_bytes).unwrap();
    fs::set_permissions(&hash_path, fs::Permissions::from_mode(0o400)).unwrap();

    // 2. Build tampered data image with altered byte at offset 1024
    let mut tampered_data = authentic_data.clone();
    tampered_data[1024] ^= 0x55;
    let (tampered_root_hash, _) = compute_verity_tree(&tampered_data, salt).unwrap();
    assert_ne!(
        pinned_root_hash, tampered_root_hash,
        "tampered data image must produce a distinct root hash"
    );

    let tampered_data_path = base.join("tampered-data.img");
    fs::write(&tampered_data_path, &tampered_data).unwrap();
    fs::set_permissions(&tampered_data_path, fs::Permissions::from_mode(0o400)).unwrap();

    // 3. Spec points at tampered data image, but carries the pinned root hash in dm-mod.create
    f.spec.root_drive = Drive {
        id: "rootfs".into(),
        path: tampered_data_path.to_str().unwrap().into(),
        read_only: true,
    };
    f.spec.drives = vec![Drive {
        id: "verity_hash".into(),
        path: hash_path.to_str().unwrap().into(),
        read_only: true,
    }];
    let dm_create = format_dm_create("netvm", 2, &pinned_root_hash, salt).unwrap();
    f.spec.boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
    );

    let valid = f.spec.clone().validate().unwrap();

    // 4. Prove api_requests never derives root hash from data image
    let requests = api_requests(&valid);
    let boot_req = requests
        .iter()
        .find(|r| r.path == "/boot-source")
        .expect("missing /boot-source request");
    let boot_args_str = boot_req.body["boot_args"]
        .as_str()
        .expect("boot_args must be string");
    assert!(
        boot_args_str.contains(&pinned_root_hash),
        "api_requests must keep pinned root hash in boot args"
    );
    assert!(
        !boot_args_str.contains(&tampered_root_hash),
        "api_requests must not compute or use root hash from data image"
    );
    let tokens = split_boot_args(boot_args_str).unwrap();
    let dm_token = tokens
        .iter()
        .find(|t| t.starts_with("dm-mod.create="))
        .unwrap();
    let parsed_dm = parse_dm_create(dm_token).unwrap();
    assert_eq!(parsed_dm.root_hash, pinned_root_hash);
    assert_ne!(parsed_dm.root_hash, tampered_root_hash);

    // 5. Prove calibrated_api_requests never derives root hash from data image
    let cal_requests = hermetic_vmm::plan::calibrated_api_requests(&valid, 2_000_000).unwrap();
    let cal_boot_req = cal_requests
        .iter()
        .find(|r| r.path == "/boot-source")
        .expect("missing calibrated /boot-source request");
    let cal_boot_args_str = cal_boot_req.body["boot_args"]
        .as_str()
        .expect("calibrated boot_args must be string");
    assert!(
        cal_boot_args_str.contains(&pinned_root_hash),
        "calibrated_api_requests must keep pinned root hash in boot args"
    );
    assert!(
        !cal_boot_args_str.contains(&tampered_root_hash),
        "calibrated_api_requests must not compute or use root hash from data image"
    );
    let cal_tokens = split_boot_args(cal_boot_args_str).unwrap();
    let cal_dm_token = cal_tokens
        .iter()
        .find(|t| t.starts_with("dm-mod.create="))
        .unwrap();
    let cal_parsed_dm = parse_dm_create(cal_dm_token).unwrap();
    assert_eq!(cal_parsed_dm.root_hash, pinned_root_hash);
    assert_ne!(cal_parsed_dm.root_hash, tampered_root_hash);

    // 6. Prove jail_plan keeps the pinned hash drive path
    let plan = hermetic_vmm::jail_plan(&valid);
    let hash_entry = plan
        .files
        .iter()
        .find(|f| f.destination == "drive-verity_hash")
        .expect("missing drive-verity_hash in jail plan");
    assert_eq!(hash_entry.source.as_deref(), hash_path.to_str());

    // 7. Prove PreparedJail::prepare stages the pinned hash device untouched,
    // and never recomputes the hash tree from the tampered data image
    let end = Instant::now() + Duration::from_secs(30);
    let jail = PreparedJail::prepare(&valid, end).unwrap();
    assert!(jail.root.identity().is_ok());

    let staged_hash_path = format!(
        "{}/firecracker/{}/root/drive-verity_hash",
        f.spec.jail.base, f.spec.id
    );
    let staged_hash_bytes = fs::read(&staged_hash_path).unwrap();
    assert_eq!(
        staged_hash_bytes, hash_bytes,
        "prepare must stage pinned hash device untouched without recomputing from data image"
    );
    assert_ne!(
        verify_root_block(&staged_hash_bytes[..BLOCK_BYTES], salt, &tampered_root_hash),
        Ok(()),
        "staged hash device must not verify against tampered data root hash"
    );
    assert_eq!(
        verify_root_block(&staged_hash_bytes[..BLOCK_BYTES], salt, &pinned_root_hash),
        Ok(()),
        "staged hash device must verify against pinned root hash"
    );

    let staged_data_path = format!(
        "{}/firecracker/{}/root/drive-rootfs",
        f.spec.jail.base, f.spec.id
    );
    let staged_data_bytes = fs::read(&staged_data_path).unwrap();
    assert_eq!(
        staged_data_bytes, tampered_data,
        "prepare must stage data image verbatim"
    );
}

#[test]
fn single_block_tampered_data_image_refused_at_prepare() {
    let mut f = support::Fixture::new();
    let base = f.temp.path().to_path_buf();
    f.spec.id = "net-verity-single".into();
    f.spec.role = Role::Net;
    f.spec.networks = vec![Network {
        tap: "net-tap".into(),
        guest_mac: hermetic_vmm::spec::project_mac(Role::Net, 0),
        peer: Role::Agent,
    }];

    // 1 data block: calculate_tree_layout(1) has 0 hash blocks
    let original_data = vec![0x55u8; BLOCK_BYTES];
    let salt = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let (pinned_root_hash, hash_bytes) = compute_verity_tree(&original_data, salt).unwrap();
    assert!(hash_bytes.is_empty());

    let hash_path = base.join("empty-hash.img");
    fs::write(&hash_path, &hash_bytes).unwrap();
    fs::set_permissions(&hash_path, fs::Permissions::from_mode(0o400)).unwrap();

    let mut tampered_data = original_data.clone();
    tampered_data[1024] ^= 0xaa;
    let tampered_data_path = base.join("tampered-single-data.img");
    fs::write(&tampered_data_path, &tampered_data).unwrap();
    fs::set_permissions(&tampered_data_path, fs::Permissions::from_mode(0o400)).unwrap();

    f.spec.root_drive = Drive {
        id: "rootfs".into(),
        path: tampered_data_path.to_str().unwrap().into(),
        read_only: true,
    };
    f.spec.drives = vec![Drive {
        id: "verity_hash".into(),
        path: hash_path.to_str().unwrap().into(),
        read_only: true,
    }];
    let dm_create = format_dm_create("netvm", 1, &pinned_root_hash, salt).unwrap();
    f.spec.boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
    );

    let valid = f.spec.validate().unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    // For single-block verity images, prepare() checks SHA256(salt || data) against pinned root hash
    // and refuses tampered data image immediately:
    assert_eq!(
        PreparedJail::prepare(&valid, end).err(),
        Some(Error::Validation("NetVM verity root hash mismatch"))
    );
}

struct DummyRunner;

impl hermetic_vmm::runner::Runner for DummyRunner {
    fn spawn(
        &mut self,
        _: &hermetic_vmm::ValidatedSpec,
        _: &hermetic_vmm::JailPlan,
        _: &PreparedJail,
        _: Instant,
    ) -> hermetic_vmm::Result<()> {
        Err(Error::State)
    }
    fn request(
        &mut self,
        _: &str,
        _: &hermetic_vmm::ApiRequest,
        _: Instant,
    ) -> hermetic_vmm::Result<()> {
        Err(Error::State)
    }
    fn exited(&mut self, _: Instant) -> hermetic_vmm::Result<bool> {
        Ok(true)
    }
    fn kill(&mut self, _: Instant) -> hermetic_vmm::Result<()> {
        Ok(())
    }
}

#[test]
fn verity_hash_device_root_hash_mismatch_fails_vm_prepare() {
    let mut f = support::Fixture::new();
    let base = f.temp.path().to_path_buf();
    f.spec.id = "net-verity-corrupt-vm".into();
    f.spec.role = Role::Net;
    f.spec.networks = vec![Network {
        tap: "net-tap".into(),
        guest_mac: hermetic_vmm::spec::project_mac(Role::Net, 0),
        peer: Role::Agent,
    }];

    let data_bytes = vec![0x37u8; BLOCK_BYTES * 2];
    let salt = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let (root_hash, mut hash_bytes) = compute_verity_tree(&data_bytes, salt).unwrap();

    let data_path = base.join("netvm-data.img");
    fs::write(&data_path, &data_bytes).unwrap();
    fs::set_permissions(&data_path, fs::Permissions::from_mode(0o400)).unwrap();

    // Corrupt root block in hash image (corrupted hash-device / root-hash mismatch)
    hash_bytes[42] ^= 0x5a;
    let hash_path = base.join("netvm-corrupt-hash.img");
    fs::write(&hash_path, &hash_bytes).unwrap();
    fs::set_permissions(&hash_path, fs::Permissions::from_mode(0o400)).unwrap();

    f.spec.root_drive = Drive {
        id: "rootfs".into(),
        path: data_path.to_str().unwrap().into(),
        read_only: true,
    };
    f.spec.drives = vec![Drive {
        id: "verity_hash".into(),
        path: hash_path.to_str().unwrap().into(),
        read_only: true,
    }];

    let dm_create = format_dm_create("netvm", 2, &root_hash, salt).unwrap();
    f.spec.boot_args = format!(
        "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/dm-0 init=/sbin/hermetic-netvm clocksource=tsc tsc=reliable hermetic.t=1700000000 ro {dm_create}"
    );

    let valid = f.spec.validate().unwrap();
    let mut vm = Vmm::new(valid, DummyRunner);
    let prep = vm.prepare(Duration::from_secs(30));
    assert_eq!(
        prep.err(),
        Some(Error::Validation("verity root hash mismatch"))
    );
    assert_eq!(vm.state(), State::Failed);
    assert!(vm.jail().is_none());
}
