use crate::fs::PreparedJail;
use crate::runner::Runner;
use crate::{deadline, remaining, ApiRequest, Error, Result, ValidatedSpec};
use serde::Serialize;
use serde_json::json;
use std::time::{Duration, Instant};

pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
pub const READY_RETRY: Duration = Duration::from_millis(5);
pub const EXIT_POLL: Duration = Duration::from_millis(50);

fn wait_for_exit(runner: &mut impl Runner, end: Instant) -> Result<()> {
    loop {
        remaining(end, "wait-exit")?;
        if runner.exited(end)? {
            remaining(end, "wait-exit")?;
            return Ok(());
        }
        std::thread::sleep(remaining(end, "wait-exit")?.min(EXIT_POLL));
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    New,
    Prepared,
    Starting,
    Running,
    Paused,
    Stopped,
    Destroyed,
    Failed,
}
/// Host-side evidence of the boot actually started; no host paths or clocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootRecord {
    pub vm_id: String,
    pub boot_path: &'static str,
    pub initrd_sha256: Option<String>,
}
pub struct Vmm<R: Runner> {
    spec: ValidatedSpec,
    runner: R,
    jail: Option<PreparedJail>,
    state: State,
    boot_record: Option<BootRecord>,
}
impl<R: Runner> Vmm<R> {
    pub fn new(spec: ValidatedSpec, runner: R) -> Self {
        Self {
            spec,
            runner,
            jail: None,
            state: State::New,
            boot_record: None,
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Include this record in the enclosing run record, including after teardown.
    pub fn boot_record(&self) -> Option<&BootRecord> {
        self.boot_record.as_ref()
    }
    pub fn runner(&self) -> &R {
        &self.runner
    }
    pub fn jail(&self) -> Option<&PreparedJail> {
        self.jail.as_ref()
    }
    fn require(&self, allowed: &[State]) -> Result<()> {
        if allowed.contains(&self.state) {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
    fn failure(&mut self, step: &'static str) -> Error {
        self.state = State::Failed;
        if let Ok(end) = deadline(CLEANUP_TIMEOUT) {
            let killed = self.runner.kill(end).is_ok();
            if killed {
                if let Some(jail) = &self.jail {
                    if jail.destroy(end).is_ok() {
                        self.jail = None;
                    }
                }
            }
        }
        Error::Step(step)
    }
    pub fn prepare(&mut self, timeout: Duration) -> Result<()> {
        self.require(&[State::New])?;
        let end = deadline(timeout)?;
        match PreparedJail::prepare(&self.spec, end) {
            Ok(j) => {
                self.jail = Some(j);
                self.state = State::Prepared;
                Ok(())
            }
            Err(_) => Err(self.failure("prepare")),
        }
    }
    pub fn start(&mut self, timeout: Duration) -> Result<()> {
        self.require(&[State::Prepared])?;
        let end = deadline(timeout)?;
        let plan = crate::jail_plan(&self.spec);
        let result = self.jail.as_ref().ok_or(Error::State).and_then(|j| {
            j.check_identity()
                .and_then(|()| self.runner.spawn(&self.spec, &plan, j, end))
                .and_then(|()| remaining(end, "start").map(|_| ()))
        });
        match result {
            Ok(()) => {
                self.state = State::Starting;
                Ok(())
            }
            Err(_) => Err(self.failure("start")),
        }
    }
    /// Wait for the API, configure devices, start vCPUs, then confirm Running.
    /// Guest execd readiness is checked by the caller through its outbound vsock
    /// connection; this crate never listens for guest-initiated connections.
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<()> {
        self.require(&[State::Starting])?;
        let end = deadline(timeout)?;
        let socket = self.jail.as_ref().ok_or(Error::State)?.api_socket();
        let result: Result<()> = (|| {
            loop {
                remaining(end, "wait-ready")?;
                if self.runner.exited(end)? {
                    return Err(Error::Step("wait-ready"));
                }
                let call_end = Instant::now()
                    .checked_add(Duration::from_millis(100))
                    .ok_or(Error::Io)?
                    .min(end);
                match self.runner.request(
                    &socket,
                    &ApiRequest::new("GET", "/", json!({})),
                    call_end,
                ) {
                    Ok(()) => break,
                    Err(Error::Io | Error::Deadline(_)) => {
                        std::thread::sleep(remaining(end, "wait-ready")?.min(READY_RETRY))
                    }
                    Err(e) => return Err(e),
                }
            }
            for req in crate::api_requests(&self.spec) {
                let step = match req.path.as_str() {
                    "/machine-config" => "configure machine",
                    "/cpu-config" => "configure CPU template",
                    "/boot-source" => "configure boot source",
                    "/vsock" => "configure vsock",
                    "/entropy" => "configure entropy",
                    path if path.starts_with("/drives/") => "configure drives",
                    _ => "configure network",
                };
                self.runner
                    .request(&socket, &req, end)
                    .map_err(|_| Error::Step(step))?;
            }
            self.runner
                .request(
                    &socket,
                    &ApiRequest::new("PUT", "/actions", json!({"action_type":"InstanceStart"})),
                    end,
                )
                .map_err(|_| Error::Step("InstanceStart"))?;
            let s = self.spec.spec();
            self.boot_record = Some(BootRecord {
                vm_id: s.id.clone(),
                boot_path: if s.initrd.is_some() {
                    "trusted_initramfs"
                } else {
                    "sealed_disk"
                },
                initrd_sha256: s.initrd.as_ref().map(|i| i.sha256.clone()),
            });
            self.runner
                .request(&socket, &ApiRequest::new("GET", "/", json!({})), end)?;
            remaining(end, "wait-ready")?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.state = State::Running;
                Ok(())
            }
            Err(Error::Step(step)) => Err(self.failure(step)),
            Err(_) => Err(self.failure("wait_ready")),
        }
    }
    fn transition(
        &mut self,
        from: State,
        to: State,
        body: serde_json::Value,
        timeout: Duration,
        step: &'static str,
    ) -> Result<()> {
        self.require(&[from])?;
        let end = deadline(timeout)?;
        let socket = self.jail.as_ref().ok_or(Error::State)?.api_socket();
        match self
            .runner
            .request(&socket, &ApiRequest::new("PATCH", "/vm", body), end)
            .and_then(|()| remaining(end, step).map(|_| ()))
        {
            Ok(()) => {
                self.state = to;
                Ok(())
            }
            Err(_) => Err(self.failure(step)),
        }
    }
    pub fn pause(&mut self, timeout: Duration) -> Result<()> {
        self.transition(
            State::Running,
            State::Paused,
            json!({"state":"Paused"}),
            timeout,
            "pause",
        )
    }
    pub fn resume(&mut self, timeout: Duration) -> Result<()> {
        self.transition(
            State::Paused,
            State::Running,
            json!({"state":"Resumed"}),
            timeout,
            "resume",
        )
    }
    pub fn stop(&mut self, timeout: Duration) -> Result<()> {
        self.require(&[State::Starting, State::Running, State::Paused])?;
        let end = deadline(timeout)?;
        let socket = self.jail.as_ref().ok_or(Error::State)?.api_socket();
        // CtrlAltDel is best effort. The caller shuts down execd before this.
        let action_end = Instant::now()
            .checked_add(timeout / 2)
            .ok_or(Error::Io)?
            .min(end);
        let _ = self.runner.request(
            &socket,
            &ApiRequest::new("PUT", "/actions", json!({"action_type":"SendCtrlAltDel"})),
            action_end,
        );
        let result: Result<()> = (|| {
            while Instant::now() < action_end {
                if self.runner.exited(end)? {
                    break;
                }
                if let Some(left) = action_end.checked_duration_since(Instant::now()) {
                    std::thread::sleep(left.min(READY_RETRY));
                }
            }
            self.runner.kill(end)?;
            remaining(end, "stop")?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(())
            }
            Err(_) => Err(self.failure("stop")),
        }
    }
    /// Waits for a running VM whose guest ends itself (GraderVM resets after
    /// the supervisor). That exit moves the
    /// VM to `Stopped`; call `destroy` next. On deadline the VM is killed and the jail destroyed.
    pub fn wait_exit(&mut self, timeout: Duration) -> Result<()> {
        self.require(&[State::Running])?;
        let end = deadline(timeout)?;
        let result = wait_for_exit(&mut self.runner, end);
        match result {
            // `destroy` kills the remaining process group and reaps it.
            Ok(()) => {
                self.state = State::Stopped;
                Ok(())
            }
            Err(_) => Err(self.failure("wait-exit")),
        }
    }
    pub fn destroy(&mut self, timeout: Duration) -> Result<()> {
        self.require(&[State::Prepared, State::Stopped, State::Failed])?;
        let end = deadline(timeout)?;
        self.runner.kill(end)?;
        if let Some(j) = &self.jail {
            j.destroy(end)?;
        }
        self.jail = None;
        self.state = State::Destroyed;
        Ok(())
    }
}
impl<R: Runner> Drop for Vmm<R> {
    fn drop(&mut self) {
        if let Ok(end) = deadline(CLEANUP_TIMEOUT) {
            if self.runner.kill(end).is_ok() {
                if let Some(j) = &self.jail {
                    let _ = j.destroy(end);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LateExit;
    impl Runner for LateExit {
        fn spawn(
            &mut self,
            _: &ValidatedSpec,
            _: &crate::JailPlan,
            _: &PreparedJail,
            _: Instant,
        ) -> Result<()> {
            Err(Error::State)
        }
        fn request(&mut self, _: &str, _: &ApiRequest, _: Instant) -> Result<()> {
            Err(Error::State)
        }
        fn exited(&mut self, _: Instant) -> Result<bool> {
            std::thread::sleep(Duration::from_millis(80));
            Ok(true)
        }
        fn kill(&mut self, _: Instant) -> Result<()> {
            Err(Error::State)
        }
    }

    #[test]
    fn late_exit_does_not_extend_the_wait_deadline() {
        let end = deadline(Duration::from_millis(10)).unwrap();
        assert_eq!(
            wait_for_exit(&mut LateExit, end),
            Err(Error::Deadline("wait-exit"))
        );
    }
}
