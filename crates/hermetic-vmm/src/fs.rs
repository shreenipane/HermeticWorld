//! Linux descriptor-relative access. Names may be mutated only in directories
//! owned by the caller/root and not writable by other identities. Root and the
//! caller are trusted. Jailer-owned descendants are permitted during cleanup
//! after the process group has been killed; the base and VM parent stay trusted.
use crate::spec::{absolute_path, MAX_IMAGE_BYTES, MAX_TOTAL_IMAGE_BYTES};
use crate::{remaining, Error, Result};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::path::{Component, Path};
use std::time::Instant;

pub const MAX_CLEANUP_ENTRIES: usize = 128;
pub const MAX_CLEANUP_DEPTH: usize = 8;
pub const MAX_TEMPLATE_BYTES: u64 = 16 * 1024;
pub const COPY_BUFFER_BYTES: usize = 64 * 1024;
fn flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}
fn regular(stat: &fs::Stat) -> Result<()> {
    let owner = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || (stat.st_uid != owner && stat.st_uid != 0)
        || stat.st_mode & 0o022 != 0
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_IMAGE_BYTES
    {
        return Err(Error::Validation("unsafe image ownership/type/mode/size"));
    }
    Ok(())
}
fn validate_ancestor(dir: &Directory) -> Result<()> {
    validate_ancestor_stat(&fs::fstat(&dir.0)?)
}
fn validate_ancestor_stat(s: &fs::Stat) -> Result<()> {
    let owner = rustix::process::geteuid().as_raw();
    let caller_gid = rustix::process::getegid().as_raw();
    if s.st_uid != 0 && s.st_uid != owner {
        return Err(Error::Validation("unsafe ancestor ownership"));
    }
    if s.st_mode & 0o002 != 0 && !(s.st_uid == 0 && s.st_mode & 0o1000 != 0) {
        return Err(Error::Validation("unsafe ancestor mode: world writable"));
    }
    // Group write is trusted only for the caller's own (user-private) group; root's group
    // and every other group stay refused unless the directory is sticky.
    if s.st_mode & 0o020 != 0 && s.st_mode & 0o1000 == 0 && s.st_gid != caller_gid {
        return Err(Error::Validation("unsafe ancestor mode: group writable"));
    }
    Ok(())
}
pub struct Directory(pub(crate) File);
impl Directory {
    pub fn open(path: &str) -> Result<Self> {
        if !absolute_path(path) {
            return Err(Error::Validation("directory path"));
        }
        let root = Self(File::from(fs::open(
            "/",
            flags() | OFlags::DIRECTORY,
            Mode::empty(),
        )?));
        validate_ancestor(&root)?;
        let mut dir = root;
        for part in Path::new(path).components() {
            if let Component::Normal(name) = part {
                dir = dir.child(name)?;
                validate_ancestor(&dir)?;
            }
        }
        Ok(dir)
    }
    fn child(&self, name: &std::ffi::OsStr) -> Result<Self> {
        let before = fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::Directory {
            return Err(Error::Validation("symlink or non-directory component"));
        }
        let dir = Self(File::from(fs::openat(
            &self.0,
            name,
            flags() | OFlags::DIRECTORY,
            Mode::empty(),
        )?));
        let after = fs::fstat(&dir.0)?;
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
            return Err(Error::Validation("directory changed"));
        }
        Ok(dir)
    }
    pub fn exclusive(&self) -> Result<()> {
        self.exclusive_owner(None)
    }
    fn exclusive_owner(&self, additional: Option<u32>) -> Result<()> {
        let s = fs::fstat(&self.0)?;
        if (s.st_uid != 0
            && s.st_uid != rustix::process::geteuid().as_raw()
            && Some(s.st_uid) != additional)
            || s.st_mode & 0o022 != 0
        {
            return Err(Error::Validation("unsafe directory owner/mode"));
        }
        Ok(())
    }
    pub fn create(&self, name: &str) -> Result<Self> {
        self.exclusive()?;
        if !crate::spec::identifier(name, 64) {
            return Err(Error::Validation("directory name"));
        }
        fs::mkdirat(&self.0, name, Mode::from_raw_mode(0o700))?;
        self.child(std::ffi::OsStr::new(name))
    }
    pub fn descriptor_path(&self, name: &str) -> String {
        format!("/proc/self/fd/{}/{name}", self.0.as_raw_fd())
    }
    pub fn identity(&self) -> Result<(u64, u64)> {
        let s = fs::fstat(&self.0)?;
        Ok((s.st_dev, s.st_ino))
    }
    fn image(&self, name: &std::ffi::OsStr) -> Result<File> {
        let before = fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
        regular(&before)?;
        let file = File::from(fs::openat(&self.0, name, flags(), Mode::empty())?);
        let after = fs::fstat(&file)?;
        regular(&after)?;
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
            return Err(Error::Validation("image changed"));
        }
        Ok(file)
    }
    fn publish(
        &self,
        name: &str,
        mut source: Option<&mut File>,
        writable: bool,
        owner: (u32, u32),
        budget: &mut u64,
        end: Instant,
    ) -> Result<()> {
        self.exclusive()?;
        let temp = format!(".{name}.tmp");
        let mut file = File::from(fs::openat(
            &self.0,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )?);
        let result = (|| {
            let mut total = 0u64;
            let mut buffer = [0u8; COPY_BUFFER_BYTES];
            if let Some(input) = source.as_mut() {
                loop {
                    remaining(end, "prepare-copy")?;
                    let n = input.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    total = total
                        .checked_add(n as u64)
                        .ok_or(Error::Validation("image size cap"))?;
                    if total > MAX_IMAGE_BYTES {
                        return Err(Error::Validation("image size cap"));
                    }
                    *budget = budget
                        .checked_sub(n as u64)
                        .ok_or(Error::Validation("total image size cap"))?;
                    file.write_all(buffer.get(..n).ok_or(Error::Io)?)?;
                }
            } else {
                *budget = budget
                    .checked_sub(4096)
                    .ok_or(Error::Validation("total image size cap"))?;
                file.write_all(&[0; 4096])?;
            }
            let mode = if writable { 0o600 } else { 0o400 };
            if rustix::process::geteuid().is_root() {
                fs::fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(owner.0)),
                    Some(rustix::process::Gid::from_raw(owner.1)),
                )?;
            }
            fs::fchmod(&file, Mode::from_raw_mode(mode))?;
            file.sync_all()?;
            fs::renameat_with(&self.0, &temp, &self.0, name, fs::RenameFlags::NOREPLACE)?;
            self.0.sync_all()?;
            remaining(end, "prepare-copy")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.0, &temp, AtFlags::empty());
        }
        result
    }
}
pub fn open_image(path: &str) -> Result<File> {
    if !absolute_path(path) {
        return Err(Error::Validation("image path"));
    }
    let p = Path::new(path);
    let parent = p.parent().and_then(|p| p.to_str()).ok_or(Error::Io)?;
    let dir = if parent == "/" {
        let d = Directory(File::from(fs::open(
            "/",
            flags() | OFlags::DIRECTORY,
            Mode::empty(),
        )?));
        validate_ancestor(&d)?;
        d
    } else {
        Directory::open(parent)?
    };
    let name = p.file_name().ok_or(Error::Io)?;
    dir.image(name)
}
/// Owns parent, VM and root descriptors until teardown; replacement is refused.
pub struct PreparedJail {
    base: Directory,
    parent: Directory,
    vm: Directory,
    pub root: Directory,
    id: String,
    uid: u32,
}
impl PreparedJail {
    pub fn prepare(valid: &crate::ValidatedSpec, end: Instant) -> Result<Self> {
        remaining(end, "prepare")?;
        let plan = crate::jail_plan(valid);
        // All sources are opened and checked before creating a single artifact.
        let mut executable = open_image(&valid.spec().jail.firecracker)?;
        let mut sources = Vec::new();
        let mut total = executable.metadata()?.len();
        for entry in &plan.files {
            remaining(end, "prepare-open")?;
            let file = entry.source.as_ref().map(|p| open_image(p)).transpose()?;
            let size = match &file {
                Some(f) => f.metadata()?.len(),
                None => 4096,
            };
            if valid.spec().role == crate::spec::Role::Grader
                && entry.destination == format!("drive-{}", crate::spec::GRADER_RESULT_DRIVE)
                && size != crate::spec::GRADER_RESULT_BYTES
            {
                return Err(Error::Validation("GraderVM result drive must be 1 MiB"));
            }
            total = total.checked_add(size).ok_or(Error::Io)?;
            if total > MAX_TOTAL_IMAGE_BYTES {
                return Err(Error::Validation("total image size cap"));
            }
            sources.push(file);
        }
        let template = sources
            .get_mut(1)
            .and_then(Option::as_mut)
            .ok_or(Error::Io)?;
        let mut data = Vec::new();
        Read::by_ref(template)
            .take(MAX_TEMPLATE_BYTES + 1)
            .read_to_end(&mut data)?;
        if data.len() as u64 > MAX_TEMPLATE_BYTES
            || serde_json::from_slice::<serde_json::Value>(&data)
                .map_err(|_| Error::Validation("CPU template JSON"))?
                != crate::plan::cpu_template()
        {
            return Err(Error::Validation(
                "CPU template must clear only kvmclock bits",
            ));
        }
        template.rewind()?;
        remaining(end, "prepare")?;
        let base = Directory::open(&valid.spec().jail.base)?;
        base.exclusive()?;
        let parent = match base.child(std::ffi::OsStr::new("firecracker")) {
            Ok(d) => d,
            Err(Error::Io) => base.create("firecracker")?,
            Err(e) => return Err(e),
        };
        parent.exclusive()?;
        let vm = parent.create(&valid.spec().id)?;
        let root = match vm.create("root") {
            Ok(d) => d,
            Err(e) => {
                let _ = fs::unlinkat(&parent.0, &valid.spec().id, AtFlags::REMOVEDIR);
                return Err(e);
            }
        };
        let jail = Self {
            base,
            parent,
            vm,
            root,
            id: valid.spec().id.clone(),
            uid: plan.uid,
        };
        let result = (|| {
            let mut budget = MAX_TOTAL_IMAGE_BYTES;
            fs::fchmod(&jail.root.0, Mode::from_raw_mode(0o711))?;
            jail.vm.publish(
                "firecracker",
                Some(&mut executable),
                false,
                (0, 0),
                &mut budget,
                end,
            )?;
            let binary = jail.executable()?;
            // Jailer copies this mode into its chroot before dropping uid.
            // Execution must work even when the new copy remains root-owned.
            fs::fchmod(&binary, Mode::from_raw_mode(0o555))?;
            binary.sync_all()?;
            for (entry, source) in plan.files.iter().zip(sources.iter_mut()) {
                jail.root.publish(
                    &entry.destination,
                    source.as_mut(),
                    entry.writable,
                    (plan.uid, plan.gid),
                    &mut budget,
                    end,
                )?;
            }
            remaining(end, "prepare")?;
            Ok(())
        })();
        if let Err(e) = result {
            if let Ok(cleanup_end) = crate::deadline(crate::lifecycle::CLEANUP_TIMEOUT) {
                let _ = jail.destroy(cleanup_end);
            }
            return Err(e);
        }
        Ok(jail)
    }
    pub fn pinned_jailer_args(&self, plan: &crate::JailPlan) -> Vec<String> {
        let parent_path = |path: String| {
            path.replacen("/proc/self/", &format!("/proc/{}/", std::process::id()), 1)
        };
        let mut args = plan.args.clone();
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--" {
                break;
            }
            if args[i] == "--exec-file" {
                if i + 1 < args.len() {
                    args[i + 1] = parent_path(self.vm.descriptor_path("firecracker"));
                    i += 2;
                    continue;
                }
            } else if args[i] == "--chroot-base-dir" {
                if i + 1 < args.len() {
                    args[i + 1] = parent_path(self.base.descriptor_path(""));
                    i += 2;
                    continue;
                }
            } else if args[i] == "--new-pid-ns" {
                i += 1;
                continue;
            } else {
                i += 2;
                continue;
            }
            i += 1;
        }
        args
    }
    pub fn executable(&self) -> Result<File> {
        self.vm.image(std::ffi::OsStr::new("firecracker"))
    }
    pub fn api_socket(&self) -> String {
        self.root.descriptor_path("api.socket")
    }
    pub fn check_identity(&self) -> Result<()> {
        self.base.exclusive()?;
        self.parent.exclusive()?;
        self.vm.exclusive()?;
        self.root.exclusive_owner(Some(self.uid))?;
        if self
            .base
            .child(std::ffi::OsStr::new("firecracker"))?
            .identity()?
            != self.parent.identity()?
        {
            return Err(Error::Validation("jail directory identity changed"));
        }
        let current = self.parent.child(std::ffi::OsStr::new(&self.id))?;
        if current.identity()? != self.vm.identity()?
            || self.vm.child(std::ffi::OsStr::new("root"))?.identity()? != self.root.identity()?
        {
            return Err(Error::Validation("jail directory identity changed"));
        }
        Ok(())
    }
    pub fn destroy(&self, end: Instant) -> Result<()> {
        remaining(end, "destroy")?;
        self.check_identity()?;
        let mut count = 0;
        remove_contents(&self.vm, 0, &mut count, Some(self.uid), end)?;
        self.check_vm_identity()?;
        fs::unlinkat(&self.parent.0, &self.id, AtFlags::REMOVEDIR)?;
        self.parent.0.sync_all()?;
        remaining(end, "destroy")?;
        Ok(())
    }
    fn check_vm_identity(&self) -> Result<()> {
        if self
            .parent
            .child(std::ffi::OsStr::new(&self.id))?
            .identity()?
            != self.vm.identity()?
        {
            return Err(Error::Validation("jail directory identity changed"));
        }
        Ok(())
    }
}
fn remove_contents(
    dir: &Directory,
    depth: usize,
    count: &mut usize,
    uid: Option<u32>,
    end: Instant,
) -> Result<()> {
    dir.exclusive_owner(uid)?;
    if depth > MAX_CLEANUP_DEPTH {
        return Err(Error::Validation("cleanup depth cap"));
    }
    let mut entries = fs::Dir::read_from(&dir.0)?;
    for item in &mut entries {
        remaining(end, "destroy")?;
        let item = item?;
        let name = item.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *count = count.checked_add(1).ok_or(Error::Io)?;
        if *count > MAX_CLEANUP_ENTRIES {
            return Err(Error::Validation("cleanup entry cap"));
        }
        let s = fs::statat(&dir.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(s.st_mode) == FileType::Directory {
            if let (Ok(p_sx), Ok(c_sx)) = (
                fs::statx(&dir.0, "", AtFlags::EMPTY_PATH, fs::StatxFlags::MNT_ID),
                fs::statx(
                    &dir.0,
                    name,
                    AtFlags::SYMLINK_NOFOLLOW,
                    fs::StatxFlags::MNT_ID,
                ),
            ) {
                let mask = fs::StatxFlags::MNT_ID.bits();
                if (p_sx.stx_mask & mask != 0)
                    && (c_sx.stx_mask & mask != 0)
                    && p_sx.stx_mnt_id != c_sx.stx_mnt_id
                {
                    return Err(Error::Validation("cleanup mount boundary"));
                }
            }
            let child = match fs::openat2(
                &dir.0,
                name,
                flags() | OFlags::DIRECTORY,
                Mode::empty(),
                fs::ResolveFlags::NO_XDEV,
            ) {
                Ok(fd) => Directory(File::from(fd)),
                Err(rustix::io::Errno::XDEV) => {
                    return Err(Error::Validation("cleanup mount boundary"));
                }
                Err(e) => return Err(e.into()),
            };
            if child.identity()?.0 != dir.identity()?.0 {
                return Err(Error::Validation("cleanup mount boundary"));
            }
            remove_contents(&child, depth + 1, count, uid, end)?;
            let now = fs::statat(&dir.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if (now.st_dev, now.st_ino) != child.identity()? {
                return Err(Error::Validation("cleanup directory changed"));
            }
            fs::unlinkat(&dir.0, name, AtFlags::REMOVEDIR)?;
        } else {
            fs::unlinkat(&dir.0, name, AtFlags::empty())?;
        }
    }
    dir.0.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_ancestor_rejects_group_write_for_every_gid() {
        let temp = tempfile::tempdir().unwrap();
        let dir = File::open(temp.path()).unwrap();
        let mut stat = fs::fstat(&dir).unwrap();
        stat.st_uid = 0;
        stat.st_mode = 0o040770;
        let caller_gid = rustix::process::getegid().as_raw();
        for gid in [0, 123456] {
            if gid == caller_gid {
                continue;
            }
            stat.st_gid = gid;
            assert!(validate_ancestor_stat(&stat).is_err(), "accepted gid {gid}");
        }
        stat.st_gid = caller_gid;
        validate_ancestor_stat(&stat).unwrap();
        stat.st_gid = 123456;
        stat.st_mode = 0o041777;
        validate_ancestor_stat(&stat).unwrap();
        stat.st_mode = 0o040755;
        validate_ancestor_stat(&stat).unwrap();
        stat.st_uid = rustix::process::geteuid().as_raw();
        stat.st_mode = 0o041770;
        validate_ancestor_stat(&stat).unwrap();
    }
    #[test]
    fn ownership_check_refuses_foreign_ids_special_files_and_write_bits() {
        let temporary = tempfile::tempfile().unwrap();
        fs::fchmod(&temporary, Mode::from_raw_mode(0o600)).unwrap();
        let valid = fs::fstat(&temporary).unwrap();
        regular(&valid).unwrap();
        let mut foreign = valid;
        foreign.st_uid = if rustix::process::geteuid().as_raw() == 123456 {
            123457
        } else {
            123456
        };
        assert!(regular(&foreign).is_err());
        for mode in [0o100620, 0o100602, 0o020600, 0o010600, 0o060600, 0o040700] {
            let mut bad = valid;
            bad.st_mode = mode;
            assert!(regular(&bad).is_err());
        }
        let mut root = valid;
        root.st_uid = 0;
        assert!(regular(&root).is_ok());
    }
    #[test]
    fn publication_is_atomic_no_replace_and_enforces_remaining_copy_budget() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Directory::open(temp.path().to_str().unwrap()).unwrap();
        fs::fchmod(&dir.0, Mode::from_raw_mode(0o700)).unwrap();
        let end = crate::deadline(std::time::Duration::from_secs(2)).unwrap();
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(b"payload").unwrap();
        source.rewind().unwrap();
        let mut budget = 6;
        assert_eq!(
            dir.publish("image", Some(&mut source), false, (0, 0), &mut budget, end),
            Err(Error::Validation("total image size cap"))
        );
        assert!(!temp.path().join("image").exists());
        assert!(!temp.path().join(".image.tmp").exists());
        source.rewind().unwrap();
        budget = 7;
        dir.publish("image", Some(&mut source), false, (0, 0), &mut budget, end)
            .unwrap();
        assert_eq!(budget, 0);
        assert_eq!(
            std::fs::read(temp.path().join("image")).unwrap(),
            b"payload"
        );
        budget = 4096;
        assert!(dir
            .publish("image", None, false, (0, 0), &mut budget, end)
            .is_err());
        assert_eq!(
            std::fs::read(temp.path().join("image")).unwrap(),
            b"payload"
        );
        assert!(!temp.path().join(".image.tmp").exists());
    }
}
