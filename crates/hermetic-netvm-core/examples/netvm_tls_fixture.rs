//! Offline smoke fixture only. The fixed seed is public test data, never a production secret.
use hermetic_netvm_core::{files, tls::BootMaterial};
use hermetic_trust::{install_ca_with_options, mint_ca, GuestOwner, InstallOptions};
use std::{
    fs::{File, OpenOptions, Permissions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

fn anchor(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/.", directory.as_raw_fd()))
}
// Fixed names in a held private directory; create-new and link publication
// refuse pre-existing files, symlinks, devices and concurrent creators.
fn publish(directory: &File, name: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let staged = anchor(directory).join(format!(".tls-{name}"));
    let target = anchor(directory).join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.set_permissions(Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::hard_link(&staged, &target)?;
        directory.sync_all()
    })();
    let cleanup = std::fs::remove_file(staged);
    result?;
    cleanup
}
fn prepare(work: &Path, tree: &Path, dns_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let work = files::private_directory(work)?;
    let tree = files::private_directory(tree)?;
    if anchor(&work)
        .canonicalize()?
        .starts_with(anchor(&tree).canonicalize()?)
    {
        return Err("private material destination is inside the image tree".into());
    }
    for name in ["unrelated.der", "ca.boot", "ca.der", "tls-identity.json"] {
        for candidate in [name.to_owned(), format!(".tls-{name}")] {
            match std::fs::symlink_metadata(anchor(&work).join(candidate)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("fixture output already exists or is inaccessible".into()),
            }
        }
    }
    const MAX_DNS_BYTES: u64 = hermetic_netvm_dns::MAX_TABLE_JSON_BYTES as u64;
    let mut dns = Vec::new();
    files::regular(dns_path, MAX_DNS_BYTES)?
        .take(MAX_DNS_BYTES + 1)
        .read_to_end(&mut dns)?;
    if dns.len() as u64 > MAX_DNS_BYTES {
        return Err("invalid_dns".into());
    }
    hermetic_netvm_dns::DnsTable::from_json_str(std::str::from_utf8(&dns)?)?;
    let clock = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let ca = mint_ca("net-smoke-netvm", clock, &[7; 32])?;
    let unrelated = mint_ca("unrelated-world", clock, &[8; 32])?;
    let material = BootMaterial::from_ca(&ca, 1_700_000_000, &dns);
    let identity = material.identity(&ca)?;
    let owner = tree.metadata()?;
    // No CA key or seed goes into either image tree.
    install_ca_with_options(
        &anchor(&tree),
        &ca.cert_pem,
        &InstallOptions {
            owner: GuestOwner {
                uid: owner.uid(),
                gid: owner.gid(),
            },
            report_path: None,
        },
    )?;
    publish(&work, "unrelated.der", &unrelated.cert_der, 0o444)?;
    publish(&work, "ca.boot", &material.encode()?, 0o600)?;
    publish(&work, "ca.der", &ca.cert_der, 0o444)?;
    publish(
        &work,
        "tls-identity.json",
        &serde_json::to_vec(&identity)?,
        0o444,
    )?;
    Ok(())
}
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_ARGUMENTS: usize = 5;
fn arguments(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Vec<String>, &'static str> {
    args.into_iter()
        .take(MAX_ARGUMENTS)
        .map(|arg| {
            if arg.len() > MAX_ARGUMENT_BYTES {
                return Err("invalid_arguments");
            }
            arg.into_string().map_err(|_| "invalid_arguments")
        })
        .collect()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = arguments(std::env::args_os())?;
    if args.len() != 4 || args.iter().any(|s| s.len() > 4096) {
        return Err("expected WORK AGENT_TREE DNS_TABLE".into());
    }
    prepare(
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    )
}
fn main() {
    if run().is_err() {
        eprintln!("tls_fixture_failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    #[test]
    fn hostile_arguments_are_rejected_without_panicking() {
        use std::os::unix::ffi::OsStringExt;
        assert!(arguments([std::ffi::OsString::from_vec(vec![255])]).is_err());
        assert!(arguments([std::ffi::OsString::from("x".repeat(MAX_ARGUMENT_BYTES + 1))]).is_err());
    }
    #[test]
    fn fixture_pins_publication_and_injects_only_public_trust() {
        let temp = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let tree = temp.path().join("agent-tree");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&tree)
            .unwrap();
        let dns = temp.path().join("dns.json");
        std::fs::write(&dns, b"{\"records\":[]}").unwrap();
        files::private_directory(temp.path()).expect("private work directory");
        files::private_directory(&tree).expect("private image tree");
        files::regular(&dns, 1024).expect("regular DNS file");
        prepare(temp.path(), &tree, &dns).unwrap();
        assert!(prepare(&tree, &tree, &dns).is_err());
        assert!(!tree.join("ca.boot").exists());
        let boot_path = temp.path().join("ca.boot");
        assert_eq!(std::fs::metadata(&boot_path).unwrap().mode() & 0o777, 0o600);
        let boot = std::fs::read(&boot_path).unwrap();
        let material: BootMaterial = serde_json::from_slice(&boot[4..]).unwrap();
        let bundle = std::fs::read(tree.join("etc/ssl/certs/ca-certificates.crt")).unwrap();
        assert!(bundle.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(!bundle
            .windows(material.ca_key_pem.len())
            .any(|b| b == material.ca_key_pem.as_bytes()));
        assert!(!bundle.windows(32).any(|b| b == material.ca_seed));
        let work = files::private_directory(temp.path()).unwrap();
        assert!(publish(&work, "ca.boot", b"overwrite", 0o600).is_err());
        assert_eq!(std::fs::read(&boot_path).unwrap(), boot);
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&tree, &link).unwrap();
        assert!(prepare(temp.path(), &link, &dns).is_err());
        let device = temp.path().join("device.der");
        std::os::unix::fs::symlink("/dev/null", &device).unwrap();
        assert!(publish(&work, "device.der", b"bytes", 0o444).is_err());
        assert!(std::fs::symlink_metadata(device).unwrap().is_symlink());
    }
}
