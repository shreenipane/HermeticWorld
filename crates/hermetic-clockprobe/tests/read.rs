#![forbid(unsafe_code)]
use hermetic_clockprobe::read::{Root, MAX_DIR_ENTRIES, MAX_SYMLINKS};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "clockprobe-read-{}",
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("fixture directory: {e}"),
            }
        }
        panic!("fixture directory cap");
    }
    fn root(&self) -> Root {
        Root::new(&self.0).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bounded_reads_reject_truncation_and_invalid_utf8() {
    let f = Fixture::new();
    let root = f.root();
    fs::write(f.0.join("file"), b"abcd").unwrap();
    assert_eq!(root.text("file", 4).unwrap(), "abcd");
    assert!(root.text("file", 3).is_err());
    fs::write(f.0.join("file"), [0xff]).unwrap();
    assert!(root.text("file", 4).is_err());
    assert!(root.text("file", u64::MAX).is_err());
}

#[test]
fn symlinks_stay_in_root_and_cycles_are_capped() {
    let f = Fixture::new();
    let outside = Fixture::new();
    fs::write(outside.0.join("secret"), b"outside").unwrap();
    fs::create_dir(f.0.join("dir")).unwrap();
    fs::write(f.0.join("file"), b"inside").unwrap();
    symlink("../file", f.0.join("dir/link")).unwrap();
    symlink(outside.0.join("secret"), f.0.join("escape")).unwrap();
    symlink("../outside", f.0.join("relative-escape")).unwrap();
    symlink("loop", f.0.join("loop")).unwrap();
    let root = f.root();
    assert_eq!(root.text("dir/link", 10).unwrap(), "inside");
    for path in ["escape", "relative-escape", "loop", "../file"] {
        assert!(root.text(path, 10).is_err());
    }
    for i in 0..=MAX_SYMLINKS {
        symlink(format!("link{}", i + 1), f.0.join(format!("link{i}"))).unwrap();
    }
    fs::write(f.0.join(format!("link{}", MAX_SYMLINKS + 1)), b"end").unwrap();
    assert!(root.text("link0", 10).is_err());
    assert_eq!(fs::read(outside.0.join("secret")).unwrap(), b"outside");
}

#[test]
fn enumeration_overflow_is_an_error_and_order_is_stable() {
    let f = Fixture::new();
    let root = f.root();
    for name in ["z", "a", "b"] {
        fs::write(f.0.join(name), b"").unwrap();
    }
    assert_eq!(root.list(".").unwrap(), vec!["a", "b", "z"]);
    for n in 0..MAX_DIR_ENTRIES {
        fs::write(f.0.join(format!("entry{n}")), b"").unwrap();
    }
    assert!(root.list(".").is_err());
}

#[test]
fn pinned_root_survives_path_replacement_and_refuses_special_files() {
    let f = Fixture::new();
    fs::create_dir(f.0.join("root")).unwrap();
    fs::write(f.0.join("root/value"), b"old").unwrap();
    let root = Root::new(&f.0.join("root")).unwrap();
    fs::rename(f.0.join("root"), f.0.join("saved")).unwrap();
    fs::create_dir(f.0.join("root")).unwrap();
    fs::write(f.0.join("root/value"), b"new").unwrap();
    assert_eq!(root.text("value", 10).unwrap(), "old");
    symlink("saved", f.0.join("linked-root")).unwrap();
    assert!(Root::new(&f.0.join("linked-root")).is_err());
    assert!(root.device("value", 202 << 8).is_err());
    let dev = Root::new(std::path::Path::new("/dev")).unwrap();
    assert!(dev.text("null", 10).is_err());
    assert!(dev.device("null", 202 << 8).is_err());
    // mkfifo is fixture creation only; production code never invokes commands.
    assert!(std::process::Command::new("/usr/bin/mkfifo")
        .arg(f.0.join("saved/fifo"))
        .status()
        .unwrap()
        .success());
    assert!(root.text("fifo", 10).is_err());
}

#[test]
fn every_registered_rtc_is_checked_and_partial_dates_fail_closed() {
    use hermetic_clockprobe::{classify::ProbeResult, probes::inspect_rtc};
    let sys = Fixture::new();
    let dev = Fixture::new();
    for name in ["rtc0", "rtc1"] {
        fs::create_dir_all(sys.0.join(format!("class/rtc/{name}"))).unwrap();
        fs::write(
            sys.0.join(format!("class/rtc/{name}/since_epoch")),
            "1704067200\n",
        )
        .unwrap();
    }
    assert_eq!(
        inspect_rtc(&sys.root(), &dev.root(), Some(1704067200), 0.0)
            .unwrap()
            .result,
        ProbeResult::Blocked
    );
    fs::write(dev.0.join("rtc0"), "").unwrap();
    assert_eq!(
        inspect_rtc(&sys.root(), &dev.root(), Some(1704067200), 0.0)
            .unwrap()
            .result,
        ProbeResult::Blocked
    );
    fs::write(sys.0.join("class/rtc/rtc1/since_epoch"), "1794600000\n").unwrap();
    assert_eq!(
        inspect_rtc(&sys.root(), &dev.root(), Some(1704067200), 0.0)
            .unwrap()
            .result,
        ProbeResult::Leak
    );
    fs::write(sys.0.join("class/rtc/rtc0/date"), "2024-01-01\n").unwrap();
    assert!(inspect_rtc(&sys.root(), &dev.root(), Some(1704067200), 0.0).is_err());
}
