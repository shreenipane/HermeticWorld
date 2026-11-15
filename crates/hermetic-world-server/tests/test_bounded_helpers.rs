//! The bounded test helpers really time out: a stalled child, thread or socket
//! fails the test within the bound instead of hanging the run.

mod support;

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, Instant};

const BOUND: Duration = Duration::from_millis(300);
const SLACK: Duration = Duration::from_secs(5);

fn panics_within<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> Duration {
    let start = Instant::now();
    assert!(std::panic::catch_unwind(f).is_err(), "helper did not fail");
    start.elapsed()
}

#[test]
fn stalled_child_fails_within_its_bound_and_is_killed() {
    let mut child = support::BoundedChild::spawn(Command::new("sleep").arg("60"));
    let pid = child.0.id();
    let elapsed = panics_within(std::panic::AssertUnwindSafe(|| {
        child.wait_status_within(BOUND);
    }));
    assert!(elapsed < SLACK, "{elapsed:?}");
    // The stalled child was killed and reaped, not left running.
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn stalled_thread_fails_within_its_bound() {
    let (_hold, release) = std::sync::mpsc::channel::<()>();
    let thread = support::spawn_bounded(move || {
        let _ = release.recv();
    });
    let elapsed = panics_within(std::panic::AssertUnwindSafe(|| {
        let _ = thread.join_within(BOUND);
    }));
    assert!(elapsed < SLACK, "{elapsed:?}");
}

#[test]
fn stalled_socket_read_times_out_within_its_bound() {
    let (a, _silent_peer) = UnixStream::pair().unwrap();
    support::bound_stream_for(&a, BOUND);
    let start = Instant::now();
    let mut buf = [0u8; 1];
    let err = (&a).read(&mut buf).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{err:?}"
    );
    assert!(start.elapsed() >= BOUND && start.elapsed() < SLACK);
}
