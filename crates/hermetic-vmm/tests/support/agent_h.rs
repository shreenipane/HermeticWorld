//! Bounded development-only failure reports for the owner-run harnesses.
use hermetic_vmm::{runner::DevUnjailed, Vmm};
use std::io::Write;
use std::time::Duration;

pub fn report(console: (Vec<u8>, Vec<u8>), output: &mut impl Write) {
    for (name, bytes) in [("serial", console.0), ("stderr", console.1)] {
        let capped = bytes
            .get(..bytes.len().min(hermetic_vmm::runner::MAX_CAPTURE_BYTES))
            .unwrap_or_default();
        // Write bytes directly: lossy UTF-8 expansion cannot enlarge the capture.
        let _ = writeln!(output, "agent VM failure: {name}:");
        let _ = output.write_all(capped);
        let _ = writeln!(output);
    }
}

pub fn run<T, E>(
    vm: &mut Vmm<DevUnjailed>,
    operation: impl FnOnce(&mut Vmm<DevUnjailed>) -> Result<T, E>,
) -> Result<T, E> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(vm)));
    if !matches!(&result, Ok(Ok(_))) {
        // Reap first, so the capture includes the final boot/power-off messages.
        // console_output survives lifecycle failure cleanup.
        let _ = vm.stop(Duration::from_secs(2));
        report(vm.runner().console_output(), &mut std::io::stderr());
    }
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

pub fn status(reply: &serde_json::Value, clock: i64) -> hermetic_vmm::Result<()> {
    if reply.get("type").and_then(serde_json::Value::as_str) != Some("status")
        || !reply
            .get("guest_time_unix")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|time| time.abs_diff(clock) < 20)
    {
        return Err(hermetic_vmm::Error::Protocol);
    }
    Ok(())
}

pub fn overlay_command(clock: i64) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/sbin/mke2fs");
    command
        .args([
            "-q",
            "-t",
            "ext4",
            "-F",
            "-U",
            "00000000-0000-0000-0000-000000000001",
            "-E",
            "hash_seed=00000000-0000-0000-0000-000000000002,lazy_itable_init=0,lazy_journal_init=0",
        ])
        .env_clear()
        .env(
            "MKE2FS_CONFIG",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../python/hermetic_slice/data/mke2fs-hermetic.conf"
            ),
        )
        .env("SOURCE_DATE_EPOCH", clock.to_string())
        .env("E2FSPROGS_FAKE_TIME", clock.to_string())
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}
