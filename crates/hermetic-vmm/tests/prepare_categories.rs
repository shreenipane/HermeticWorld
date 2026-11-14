mod support;

use hermetic_vmm::{fs::PreparedJail, runner::Runner, ApiRequest, Error, Result, State, Vmm};
use std::time::{Duration, Instant};

struct FailingPrepare(rustix::io::Errno);

impl Runner for FailingPrepare {
    fn tsc_khz(&self) -> Result<u64> {
        Err(self.0.into())
    }
    fn spawn(
        &mut self,
        _: &hermetic_vmm::ValidatedSpec,
        _: &hermetic_vmm::JailPlan,
        _: &PreparedJail,
        _: Instant,
    ) -> Result<()> {
        Err(Error::State)
    }
    fn request(&mut self, _: &str, _: &ApiRequest, _: Instant) -> Result<()> {
        Err(Error::State)
    }
    fn exited(&mut self, _: Instant) -> Result<bool> {
        Ok(true)
    }
    fn kill(&mut self, _: Instant) -> Result<()> {
        Ok(())
    }
}

#[test]
fn prepare_reports_safe_io_categories_and_fails_closed() {
    for (errno, category) in [
        (rustix::io::Errno::NOSPC, "prepare-io-no-space"),
        (rustix::io::Errno::DQUOT, "prepare-io-no-space"),
        (rustix::io::Errno::ACCESS, "prepare-io"),
    ] {
        let spec = support::spec(hermetic_vmm::spec::Role::Agent)
            .validate()
            .unwrap();
        let mut vm = Vmm::new(spec, FailingPrepare(errno));
        assert_eq!(
            vm.prepare(Duration::from_secs(1)),
            Err(Error::Step(category))
        );
        assert_eq!(vm.state(), State::Failed);
        assert!(vm.jail().is_none());
    }
}

#[test]
fn no_space_survives_both_io_conversions_without_private_details() {
    let errno = rustix::io::Errno::NOSPC;
    let direct = Error::from(errno);
    let io = Error::from(std::io::Error::from_raw_os_error(errno.raw_os_error()));
    assert_eq!(direct, io);
    assert_eq!(direct.to_string(), "I/O operation failed: no-space");
    assert_eq!(
        Error::from(std::io::Error::other("private host path and secret")).to_string(),
        "I/O operation failed"
    );
}
