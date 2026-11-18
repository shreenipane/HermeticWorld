#![forbid(unsafe_code)]

mod support;
use hermetic_vmm::{
    api,
    fs::PreparedJail,
    plan::{api_requests, jail_plan, JailPlan},
    runner::Runner,
    spec::MAX_VCPUS,
    ApiRequest, Error, Result, State, ValidatedSpec, Vmm,
};
use serde_json::json;
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[path = "../../../vmm/cpu-baseline.rs"]
mod baseline;

#[derive(Default)]
struct FakeRunner {
    requests: Vec<ApiRequest>,
    alive: bool,
}

impl Runner for FakeRunner {
    fn tsc_khz(&self) -> Result<u64> {
        Ok(2_000_000)
    }
    fn spawn(
        &mut self,
        _: &ValidatedSpec,
        _: &JailPlan,
        _: &PreparedJail,
        _: Instant,
    ) -> Result<()> {
        self.alive = true;
        Ok(())
    }
    fn request(&mut self, _: &str, r: &ApiRequest, _: Instant) -> Result<()> {
        self.requests.push(r.clone());
        Ok(())
    }
    fn exited(&mut self, _: Instant) -> Result<bool> {
        Ok(!self.alive)
    }
    fn kill(&mut self, _: Instant) -> Result<()> {
        self.alive = false;
        Ok(())
    }
}

#[test]
fn test_spec_vcpus_validation_1_to_32() {
    let mut fixture = support::Fixture::new();
    for valid_count in [1, 2, 4, 8, 16, 32] {
        fixture.spec.vcpus = valid_count;
        assert!(
            fixture.spec.clone().validate().is_ok(),
            "valid vcpu count {valid_count} was rejected"
        );
    }

    // 0 is invalid
    fixture.spec.vcpus = 0;
    assert!(fixture.spec.clone().validate().is_err());

    // MAX_VCPUS + 1 is invalid (> MAX_VCPUS)
    fixture.spec.vcpus = MAX_VCPUS + 1;
    assert!(fixture.spec.clone().validate().is_err());
}

#[test]
fn test_plan_machine_config_and_cgroups_multi_vcpu() {
    for valid_count in [1, 2, 4, 8, 16, 32] {
        let mut fixture = support::Fixture::new();
        fixture.spec.vcpus = valid_count;
        let validated = fixture.spec.validate().unwrap();
        let requests = api_requests(&validated);
        let jail = jail_plan(&validated);

        // Check machine-config request
        let machine_cfg = requests
            .iter()
            .find(|r| r.path == "/machine-config")
            .expect("machine-config request missing");
        let body: serde_json::Value = machine_cfg.body.clone();
        assert_eq!(body["vcpu_count"], valid_count);

        // Check cgroup cpu.max configuration in jail args
        let expected_quota = u64::from(valid_count) * 100_000;
        let expected_cgroup = format!("cpu.max={expected_quota} 100000");
        assert!(
            jail.args
                .windows(2)
                .any(|w| w[0] == "--cgroup" && w[1] == expected_cgroup),
            "expected cgroup {expected_cgroup} not found in jail args"
        );
    }
}

#[test]
fn test_multivcpu_cpu_baseline_identity_all_cpus() {
    for count in [1, 2, 4, 8, 16, 32] {
        for index in 0..count {
            let regs = baseline::registers(1, 0, index, count)
                .expect("leaf 1 subleaf 0 expected for all vcpus");
            let [_eax, ebx, _ecx, edx] = regs;

            // HTT bit in EDX (bit 28) must be set if and only if count > 1
            let htt_bit = (edx >> 28) & 1;
            if count > 1 {
                assert_eq!(
                    htt_bit, 1,
                    "HTT bit should be 1 for multi-vcpu ({count} vcpus)"
                );
            } else {
                assert_eq!(htt_bit, 0, "HTT bit should be 0 for single-vcpu");
            }

            // APIC ID in EBX (bits 24-31) must match index
            let apic_id = (ebx >> 24) as u8;
            assert_eq!(apic_id, index, "APIC ID must match vCPU index");

            // Max addressable IDs in EBX (bits 16-23) must match count
            let max_ids = ((ebx >> 16) & 0xff) as u8;
            assert_eq!(max_ids, count, "max addressable IDs must match vCPU count");

            // Fixed 2.0 GHz in leaf 0x15: 25 MHz * 80 / 1 = 2.0 GHz
            let freq = baseline::registers(0x15, 0, index, count).expect("leaf 0x15 expected");
            assert_eq!(freq[0], 1); // EAX denominator
            assert_eq!(freq[1], 80); // EBX numerator
            assert_eq!(freq[2], 25_000_000); // ECX crystal Hz
            assert_eq!(
                u64::from(freq[2]) * u64::from(freq[1]) / u64::from(freq[0]),
                2_000_000_000
            );
        }
    }
}

#[test]
fn test_snapshot_create_request_validation() {
    // Valid Full snapshot
    let valid_full = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/create".into(),
        body: json!({
            "snapshot_type": "Full",
            "snapshot_path": "/srv/jail/snap.state",
            "mem_file_path": "/srv/jail/snap.mem"
        }),
    };
    assert!(api::validate_request(&valid_full).is_ok());

    // Valid Diff snapshot
    let valid_diff = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/create".into(),
        body: json!({
            "snapshot_type": "Diff",
            "snapshot_path": "/srv/jail/snap.state",
            "mem_file_path": "/srv/jail/snap.mem"
        }),
    };
    assert!(api::validate_request(&valid_diff).is_ok());

    // Relative path rejected (fail closed, no relative host paths)
    let rel_snap = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/create".into(),
        body: json!({
            "snapshot_type": "Full",
            "snapshot_path": "relative/snap.state",
            "mem_file_path": "/srv/jail/snap.mem"
        }),
    };
    assert!(api::validate_request(&rel_snap).is_err());

    let rel_mem = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/create".into(),
        body: json!({
            "snapshot_type": "Full",
            "snapshot_path": "/srv/jail/snap.state",
            "mem_file_path": "relative/snap.mem"
        }),
    };
    assert!(api::validate_request(&rel_mem).is_err());

    // Unknown snapshot type rejected
    let bad_type = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/create".into(),
        body: json!({
            "snapshot_type": "Incremental",
            "snapshot_path": "/srv/jail/snap.state",
            "mem_file_path": "/srv/jail/snap.mem"
        }),
    };
    assert!(api::validate_request(&bad_type).is_err());

    // Missing field rejected
    let missing_field = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/create".into(),
        body: json!({
            "snapshot_type": "Full",
            "snapshot_path": "/srv/jail/snap.state"
        }),
    };
    assert!(api::validate_request(&missing_field).is_err());
}

#[test]
fn test_snapshot_load_request_validation() {
    // Valid load request
    let valid_load = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/load".into(),
        body: json!({
            "snapshot_path": "/srv/jail/snap.state",
            "mem_file_path": "/srv/jail/snap.mem",
            "enable_diff_snapshots": false,
            "resume_vm": true
        }),
    };
    assert!(api::validate_request(&valid_load).is_ok());

    // Valid load with diff enabled and resume false
    let valid_diff_load = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/load".into(),
        body: json!({
            "snapshot_path": "/srv/jail/snap.state",
            "mem_file_path": "/srv/jail/snap.mem",
            "enable_diff_snapshots": true,
            "resume_vm": false
        }),
    };
    assert!(api::validate_request(&valid_diff_load).is_ok());

    // Relative path rejected
    let rel_load = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/load".into(),
        body: json!({
            "snapshot_path": "snap.state",
            "mem_file_path": "/srv/jail/snap.mem",
            "resume_vm": true
        }),
    };
    assert!(api::validate_request(&rel_load).is_err());

    // Missing snapshot_path rejected
    let missing = ApiRequest {
        method: "PUT".into(),
        path: "/snapshot/load".into(),
        body: json!({
            "mem_file_path": "/srv/jail/snap.mem",
            "resume_vm": true
        }),
    };
    assert!(api::validate_request(&missing).is_err());
}

#[test]
fn test_snapshot_lifecycle_state_machine_with_fake_runner() {
    let mut fixture = support::Fixture::new();
    fixture.spec.limits.file_size_bytes = 256 * 1024 * 1024;
    let validated = fixture.spec.validate().unwrap();
    let runner = FakeRunner::default();
    let mut vmm = Vmm::new(validated, runner);

    assert_eq!(vmm.state(), State::New);

    // snapshot_create must fail in State::New
    let err = vmm
        .snapshot_create(
            "/srv/jail/snap.state",
            "/srv/jail/snap.mem",
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert_eq!(err, Error::State);

    // Prepare VM
    vmm.prepare(Duration::from_secs(30)).unwrap();
    assert_eq!(vmm.state(), State::Prepared);

    // Start VM
    vmm.start(Duration::from_secs(10)).unwrap();
    assert_eq!(vmm.state(), State::Starting);

    // Load snapshot in State::Starting
    vmm.snapshot_load(
        "/srv/jail/snap.state",
        "/srv/jail/snap.mem",
        false,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(vmm.state(), State::Paused);
    assert_eq!(vmm.boot_record().unwrap().boot_path, "snapshot_restore");

    // snapshot_create succeeds in State::Paused
    vmm.snapshot_create(
        "/srv/jail/snap.state",
        "/srv/jail/snap.mem",
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(vmm.state(), State::Paused);

    // Resume VM to State::Running
    vmm.resume(Duration::from_secs(5)).unwrap();
    assert_eq!(vmm.state(), State::Running);

    // Now in Running, snapshot_create must fail
    assert_eq!(
        vmm.snapshot_create(
            "/srv/jail/snap.state",
            "/srv/jail/snap.mem",
            Duration::from_secs(1)
        )
        .unwrap_err(),
        Error::State
    );

    // Pause VM back to State::Paused
    vmm.pause(Duration::from_secs(5)).unwrap();
    assert_eq!(vmm.state(), State::Paused);

    // Now snapshot_create succeeds again
    vmm.snapshot_create(
        "/srv/jail/snap.state",
        "/srv/jail/snap.mem",
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(vmm.state(), State::Paused);
}

#[test]
fn test_snapshot_create_oversized_guest_memory_rejected() {
    let fixture = support::Fixture::new();
    // Default fixture: memory_mib = 256, file_size_bytes = 64 MiB (67108864)
    assert_eq!(fixture.spec.memory_mib, 256);
    assert_eq!(fixture.spec.limits.file_size_bytes, 67108864);
    let validated = fixture.spec.validate().unwrap();
    let runner = FakeRunner::default();
    let mut vmm = Vmm::new(validated, runner);

    vmm.prepare(Duration::from_secs(30)).unwrap();
    vmm.start(Duration::from_secs(10)).unwrap();
    // Move to State::Paused with a fake snapshot load or pause
    // In Starting, let's load a snapshot with fake runner to reach Paused
    vmm.snapshot_load(
        "/srv/jail/snap.state",
        "/srv/jail/snap.mem",
        false,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(vmm.state(), State::Paused);

    // Full snapshot creation must fail validation before sending request to runner
    let err = vmm
        .snapshot_create(
            "/srv/jail/snap.state",
            "/srv/jail/snap.mem",
            Duration::from_secs(5),
        )
        .unwrap_err();
    assert_eq!(
        err,
        Error::Validation("snapshot memory file exceeds file size limit")
    );
    // VM must remain Paused, NOT Failed
    assert_eq!(vmm.state(), State::Paused);
}

#[test]
fn test_snapshot_load_waits_for_readiness() {
    let mut fixture = support::Fixture::new();
    fixture.spec.limits.file_size_bytes = 256 * 1024 * 1024;
    let validated = fixture.spec.validate().unwrap();
    let runner = FakeRunner::default();
    let mut vmm = Vmm::new(validated, runner);

    vmm.prepare(Duration::from_secs(30)).unwrap();
    vmm.start(Duration::from_secs(10)).unwrap();
    assert_eq!(vmm.state(), State::Starting);

    vmm.snapshot_load(
        "/srv/jail/snap.state",
        "/srv/jail/snap.mem",
        false,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(vmm.state(), State::Paused);

    // Verify runner received GET / readiness probe BEFORE PUT /snapshot/load
    let requests = &vmm.runner().requests;
    assert!(requests.len() >= 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/");
    assert_eq!(requests[1].method, "PUT");
    assert_eq!(requests[1].path, "/snapshot/load");
}

#[test]
fn test_smoke_scripts_exist_and_are_executable() {
    use std::os::unix::fs::PermissionsExt;
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let scripts = [
        "scripts/integration/multivcpu-smoke.sh",
        "scripts/integration/snapshot-smoke.sh",
        "scripts/integration/tsc-drift-smoke.sh",
    ];
    for rel in scripts {
        let path = root.join(rel);
        assert!(path.exists(), "smoke script must exist: {:?}", path);
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(
            meta.is_file(),
            "smoke script must be regular file: {:?}",
            path
        );
        assert!(
            !meta.is_symlink(),
            "smoke script must not be symlink: {:?}",
            path
        );
        let mode = meta.permissions().mode();
        assert!(mode & 0o100 != 0, "{rel} must be executable by owner");
        assert!(mode & 0o002 == 0, "{rel} must not be writable by others");
    }
}
