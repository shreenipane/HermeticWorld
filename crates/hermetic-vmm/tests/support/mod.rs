#![allow(dead_code)]
use hermetic_vmm::spec::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

pub fn spec(role: Role) -> VmSpec {
    VmSpec {
        id: "vm-0".into(),
        role,
        index: 0,
        vcpus: 2,
        memory_mib: 256,
        kernel_image: "/images/kernel".into(),
        boot_args: concat!(
            "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda ",
            "init=/sbin/hermetic-execd clocksource=tsc tsc=reliable ",
            "hermetic.t=1700000000 ro"
        )
        .into(),
        root_drive: Drive {
            id: "rootfs".into(),
            path: "/images/rootfs".into(),
            read_only: true,
        },
        drives: if role == Role::Agent {
            vec![Drive {
                id: "overlay".into(),
                path: "/images/overlay".into(),
                read_only: false,
            }]
        } else {
            vec![]
        },
        reserved_drives: vec!["tests".into()],
        vsock: if role == Role::Grader {
            None
        } else {
            Some(Vsock {
                guest_cid: 3,
                socket_path: "/vsock".into(),
            })
        },
        networks: if role == Role::Agent {
            vec![Network {
                tap: "agent-tap".into(),
                guest_mac: project_mac(role, 0),
                peer: Role::Net,
            }]
        } else {
            vec![]
        },
        cpu_template: "/images/cpu-template.json".into(),
        clock: Clock::Faked,
        limits: Limits {
            pids: 128,
            file_size_bytes: 67108864,
            open_files: 128,
        },
        jail: JailConfig {
            base: "/jails".into(),
            uid_start: 200000,
            gid_start: 200000,
            count: 64,
            firecracker: "/bin/firecracker".into(),
            jailer: "/bin/jailer".into(),
            netns: "isolated-0".into(),
        },
    }
}

pub struct Fixture {
    pub temp: TempDir,
    pub spec: VmSpec,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        fs::set_permissions(base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(base.join("bin")).unwrap();
        let mut s = spec(Role::Agent);
        for (field, name, bytes) in [
            (&mut s.kernel_image, "kernel", b"kernel".as_slice()),
            (&mut s.root_drive.path, "rootfs", b"rootfs".as_slice()),
            (
                &mut s.cpu_template,
                "template",
                hermetic_vmm::plan::CPU_TEMPLATE.as_bytes(),
            ),
            (
                &mut s.jail.firecracker,
                "bin/firecracker",
                b"fake-firecracker".as_slice(),
            ),
            (&mut s.jail.jailer, "jailer", b"fake-jailer".as_slice()),
        ] {
            let path = base.join(name);
            fs::write(&path, bytes).unwrap();
            *field = path.to_str().unwrap().into();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::set_permissions(&s.jail.firecracker, fs::Permissions::from_mode(0o500)).unwrap();
        let overlay = base.join("overlay");
        fs::write(&overlay, b"overlay").unwrap();
        fs::set_permissions(&overlay, fs::Permissions::from_mode(0o600)).unwrap();
        s.drives[0].path = overlay.to_str().unwrap().into();
        s.jail.base = base.to_str().unwrap().into();
        Self { temp, spec: s }
    }
    pub fn root(&self) -> std::path::PathBuf {
        self.temp.path().join("firecracker/vm-0/root")
    }
}
