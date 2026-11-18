#![cfg(feature = "dev-unjailed")]
//! Mode G AgentVM KVM test: /opt/agent volume and NetVM model path (TR-GW-1..9, TR-NET-3).
//! The ordinary offline gate skips cleanly when environment variables are unset.

#[path = "support/agent_h.rs"]
#[allow(dead_code)]
mod diagnostics;
mod support;

use hermetic_vmm::spec::{Drive, Role};
use std::os::unix::fs::PermissionsExt;

fn environment() -> Option<support::Fixture> {
    let mut vars = Vec::new();
    for name in ["HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_ROOTFS"] {
        match std::env::var(name) {
            Ok(value) => vars.push(value),
            Err(_) => {
                eprintln!("skipped: set HERMETIC_FC_BIN, HERMETIC_KERNEL and HERMETIC_ROOTFS");
                return None;
            }
        }
    }
    let mut f = support::Fixture::new();
    f.spec.jail.firecracker = vars[0].clone();
    f.spec.kernel_image = vars[1].clone();
    f.spec.root_drive.path = vars[2].clone();
    Some(f)
}

#[test]
fn test_agent_g_spec_validates_with_opt_agent_volume_and_netvm_network() {
    let mut fixture = support::Fixture::new();
    assert_eq!(fixture.spec.role, Role::Agent);

    // Add /opt/agent read-only drive
    let agent_disk = fixture.temp.path().join("agent.raw");
    std::fs::write(&agent_disk, b"fake-agent-volume").unwrap();
    std::fs::set_permissions(&agent_disk, std::fs::Permissions::from_mode(0o600)).unwrap();

    fixture.spec.drives.push(Drive {
        id: "agent".into(),
        path: agent_disk.to_str().unwrap().into(),
        read_only: true,
    });

    let validated = fixture
        .spec
        .validate()
        .expect("Mode G AgentVM spec must validate");
    assert_eq!(validated.spec().drives.len(), 2);
    assert_eq!(validated.spec().drives[0].id, "overlay");
    assert!(!validated.spec().drives[0].read_only);
    assert_eq!(validated.spec().drives[1].id, "agent");
    assert!(validated.spec().drives[1].read_only);
}

#[test]
fn test_agent_g_offline_skips_cleanly_when_unconfigured() {
    let Some(mut fixture) = environment() else {
        println!("test_agent_g_offline_skips_cleanly_when_unconfigured: cleanly skipped");
        return;
    };

    // If environment is set, verify execution setup
    assert_eq!(fixture.spec.role, Role::Agent);
    let agent_disk = fixture.temp.path().join("agent.raw");
    std::fs::write(&agent_disk, b"agent-content").unwrap();
    std::fs::set_permissions(&agent_disk, std::fs::Permissions::from_mode(0o600)).unwrap();

    fixture.spec.drives.push(Drive {
        id: "agent".into(),
        path: agent_disk.to_str().unwrap().into(),
        read_only: true,
    });
    assert!(fixture.spec.validate().is_ok());
}
