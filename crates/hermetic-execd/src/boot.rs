use crate::{
    rpc::ExecReply,
    spec::{self, RunSpec},
    *,
};

pub const MIN_CLOCK: i64 = 315532800; // 1980-01-01, ZIP's lower bound
pub const MAX_CLOCK: i64 = 4102444799; // 2099-12-31

/// Reads the capped kernel command line and returns its `hermetic.t=` clock.
/// Shared by execd and the grader PID 1 (`crate::grader`).
pub fn read_clock(reader: impl std::io::Read) -> Result<i64> {
    let data = read_capped(reader, MAX_CMDLINE).map_err(|_| Error::InvalidClock)?;
    let line = std::str::from_utf8(&data).map_err(|_| Error::InvalidClock)?;
    parse_clock(line)
}

/// Exactly one `hermetic.t=<decimal seconds>` in [MIN_CLOCK, MAX_CLOCK].
/// Classifies missing/invalid clocks independently of other option order:
/// no other malformed option may hide the distinct fatal clock reason.
pub fn parse_clock(line: &str) -> Result<i64> {
    let mut clock = None;
    for word in line.split_ascii_whitespace() {
        if word == "hermetic.t" {
            return Err(Error::InvalidClock);
        }
        if let Some(t) = word.strip_prefix("hermetic.t=") {
            if clock.is_some() || t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidClock);
            }
            let t = t.parse::<i64>().map_err(|_| Error::InvalidClock)?;
            if !(MIN_CLOCK..=MAX_CLOCK).contains(&t) {
                return Err(Error::InvalidClock);
            }
            clock = Some(t);
        }
    }
    clock.ok_or(Error::InvalidClock)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub clock: i64,
    pub overlay: String,
    pub spec: String,
    pub initramfs: bool,
}
impl Config {
    pub fn parse(reader: impl std::io::Read) -> Result<Self> {
        let data = read_capped(reader, MAX_CMDLINE).map_err(|_| Error::InvalidClock)?;
        let line = std::str::from_utf8(&data).map_err(|_| Error::InvalidClock)?;
        let clock = parse_clock(line)?;
        let mut overlay = None;
        let mut spec = None;
        let mut initramfs = None;
        for word in line.split_ascii_whitespace() {
            if word.starts_with("hermetic.t=") {
                continue;
            } else if let Some(v) = word.strip_prefix("hermetic.overlay=") {
                if overlay.replace(v.to_owned()).is_some() {
                    return Err(Error::InvalidInput);
                }
            } else if let Some(v) = word.strip_prefix("hermetic.spec=") {
                if spec.replace(v.to_owned()).is_some() {
                    return Err(Error::InvalidInput);
                }
            } else if let Some(v) = word.strip_prefix("hermetic.initramfs=") {
                if initramfs.is_some() || !matches!(v, "0" | "1") {
                    return Err(Error::InvalidInput);
                }
                initramfs = Some(v == "1");
            } else if word.starts_with("hermetic.") {
                return Err(Error::InvalidInput);
            }
        }
        let config = Self {
            clock,
            overlay: overlay.unwrap_or_else(|| "/dev/vdb".into()),
            spec: spec.unwrap_or_else(|| "/etc/hermetic/run-spec.json".into()),
            initramfs: initramfs.unwrap_or(false),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if !(MIN_CLOCK..=MAX_CLOCK).contains(&self.clock) {
            return Err(Error::InvalidClock);
        }
        spec::path(&self.overlay)?;
        spec::path(&self.spec)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Clock(i64),
    MountBaseReadOnly,
    MountDisk(String),
    PrepareOverlay,
    AssembleOverlay,
    MoveDev,
    SwitchRoot,
    MountProc,
    MountSys,
    MountPts,
    MountShm,
    StampDev(i64),
    ApplySpec,
    Listen(u32),
    TermAll,
    WaitAll(u64),
    KillAll,
    Sync,
    ClearGroups,
    Gid(u32),
    Uid(u32),
    Session,
    ControllingTerminal,
    MemoryLimit(u64),
    CoreLimit,
    ClearSignalMask,
    PowerOff(Error),
}

/// All privileged effects, including child processes and filesystem mutations.
/// Implementations must drain output with the supplied cap and always reap.
pub trait Sys {
    type FreezeHandle;
    fn effect(&mut self, effect: Effect) -> Result<()>;
    fn keep_upper(&mut self) -> Result<Self::FreezeHandle>;
    fn freeze(&mut self, handle: &Self::FreezeHandle) -> Result<()>;
    fn load_spec(&mut self, path: &str) -> Result<RunSpec>;
    fn apply(&mut self, spec: &RunSpec) -> Result<()>;
    fn start_entrypoint(&mut self, spec: &RunSpec) -> Result<()>;
    fn execute(
        &mut self,
        spec: &RunSpec,
        argv: &[String],
        tty: bool,
        timeout_ms: u64,
        output_cap: usize,
    ) -> Result<ExecReply>;
    fn upload(&mut self, path: &str, data: &[u8]) -> Result<()>;
    fn download(&mut self, path: &str) -> Result<Vec<u8>>;
    fn maintain(&mut self) -> Result<()>;
    fn guest_time(&mut self) -> Result<i64>;
    fn child_cwd(&mut self, cwd: &std::fs::File) -> Result<()>;
    fn exec_program(
        &mut self,
        executable: &std::fs::File,
        argv: &[std::ffi::CString],
        env: &[std::ffi::CString],
    ) -> Result<()>;
    fn child(
        &mut self,
        spec: &RunSpec,
        argv: &[String],
        cwd: &std::fs::File,
        executable: &std::fs::File,
        tty: bool,
    ) -> Result<()>;
}

pub struct Booted<H> {
    pub upper: H,
    pub spec: RunSpec,
    pub locked: bool,
}

pub fn boot<S: Sys>(sys: &mut S, config: &Config) -> Result<Booted<S::FreezeHandle>> {
    config.validate()?;
    // Clock is the first effect. Even the freeze handle is opened afterwards.
    sys.effect(Effect::Clock(config.clock))?;
    if config.initramfs {
        sys.effect(Effect::MountBaseReadOnly)?;
    }
    sys.effect(Effect::MountDisk(config.overlay.clone()))?;
    let upper = sys.keep_upper()?;
    for effect in [
        Effect::PrepareOverlay,
        Effect::AssembleOverlay,
        Effect::MoveDev,
        Effect::SwitchRoot,
        Effect::MountProc,
        Effect::MountSys,
        Effect::MountPts,
        Effect::MountShm,
        Effect::StampDev(config.clock),
    ] {
        sys.effect(effect)?;
    }
    let spec = sys.load_spec(&config.spec)?;
    spec.validate()?;
    sys.apply(&spec)?;
    if !config.initramfs && !spec.initial_argv().is_empty() {
        sys.start_entrypoint(&spec)?;
    }
    sys.effect(Effect::Listen(VSOCK_PORT))?;
    Ok(Booted {
        upper,
        spec,
        locked: config.initramfs,
    })
}

pub fn shutdown<S: Sys>(sys: &mut S, handle: &S::FreezeHandle) -> Result<()> {
    sys.effect(Effect::TermAll)?;
    sys.effect(Effect::WaitAll(SHUTDOWN_WAIT_MS))?;
    sys.effect(Effect::KillAll)?;
    sys.effect(Effect::WaitAll(SHUTDOWN_WAIT_MS))?;
    sys.effect(Effect::Sync)?;
    sys.freeze(handle)
}

pub fn drop_privileges(sys: &mut impl Sys, spec: &RunSpec) -> Result<()> {
    spec.validate()?;
    sys.effect(Effect::ClearGroups)?;
    sys.effect(Effect::Gid(spec.gid))?;
    sys.effect(Effect::Uid(spec.uid))
}

/// Shared production child path, including validation before the first effect.
pub fn run_child(
    sys: &mut impl Sys,
    spec: &RunSpec,
    argv: &[String],
    cwd: &std::fs::File,
    executable: &std::fs::File,
    tty: bool,
) -> Result<()> {
    use std::ffi::CString;
    spec.validate()?;
    spec::args(argv, false)?;
    let argv = argv
        .iter()
        .map(|s| CString::new(s.as_str()).map_err(|_| Error::InvalidInput))
        .collect::<Result<Vec<_>>>()?;
    let env = spec
        .env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).map_err(|_| Error::InvalidInput))
        .collect::<Result<Vec<_>>>()?;
    let memory = spec
        .resources
        .memory_mib
        .checked_mul(1024 * 1024)
        .ok_or(Error::Limit)?;
    sys.effect(Effect::Session)?;
    if tty {
        sys.effect(Effect::ControllingTerminal)?;
    }
    sys.child_cwd(cwd)?;
    sys.effect(Effect::MemoryLimit(memory))?;
    sys.effect(Effect::CoreLimit)?;
    drop_privileges(sys, spec)?;
    sys.effect(Effect::ClearSignalMask)?;
    sys.exec_program(executable, &argv, &env)
}

/// Parsing failures produce no log or filesystem write. Poweroff reason is
/// fixed and distinguishes an invalid/missing clock from later boot failures.
pub fn start<S: Sys>(sys: &mut S, cmdline: impl std::io::Read) -> Result<Booted<S::FreezeHandle>> {
    let result = Config::parse(cmdline).and_then(|config| boot(sys, &config));
    if let Err(reason) = &result {
        let _ = sys.effect(Effect::PowerOff(*reason));
    }
    result
}
