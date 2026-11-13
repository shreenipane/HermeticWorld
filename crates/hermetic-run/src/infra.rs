use std::cell::RefCell;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::verdict::{R0Result, R1Result, R2Result, R3Result};

/// Injected monotonic clock used exclusively for enforcing step deadlines.
/// Implementations must never leak host wall-clock values into run outputs.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// Logical grader identifier (R0..R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraderRun {
    R0,
    R1,
    R2,
    R3,
}

impl GraderRun {
    pub fn as_str(&self) -> &'static str {
        match self {
            GraderRun::R0 => "R0",
            GraderRun::R1 => "R1",
            GraderRun::R2 => "R2",
            GraderRun::R3 => "R3",
        }
    }
}

impl fmt::Display for GraderRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every step in the evaluation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    PrepareWorld,
    StartNetVm,
    StartAgentVm,
    WaitAgentReady,
    RunAgent,
    ShutdownAgent,
    DestroyAgentVm,
    DestroyNetVm,
    RunExtractor,
    RunGrader(GraderRun),
}

impl Step {
    pub fn as_str(&self) -> &'static str {
        match self {
            Step::PrepareWorld => "prepare_world",
            Step::StartNetVm => "start_netvm",
            Step::StartAgentVm => "start_agentvm",
            Step::WaitAgentReady => "wait_agent_ready",
            Step::RunAgent => "run_agent",
            Step::ShutdownAgent => "shutdown_agent",
            Step::DestroyAgentVm => "destroy_agentvm",
            Step::DestroyNetVm => "destroy_netvm",
            Step::RunExtractor => "run_extractor",
            Step::RunGrader(GraderRun::R0) => "run_grader_r0",
            Step::RunGrader(GraderRun::R1) => "run_grader_r1",
            Step::RunGrader(GraderRun::R2) => "run_grader_r2",
            Step::RunGrader(GraderRun::R3) => "run_grader_r3",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Named deadline passed to each step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedDeadline {
    pub name: String,
    pub deadline_ms: u64,
}

impl NamedDeadline {
    pub fn new(name: impl Into<String>, deadline_ms: u64) -> Self {
        Self {
            name: name.into(),
            deadline_ms,
        }
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.deadline_ms
    }
}

/// Named deadline budgets (relative to the injected `Clock` when each step begins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlineSchedule {
    pub prepare_world: (String, u64),
    pub start_netvm: (String, u64),
    pub start_agentvm: (String, u64),
    pub wait_agent_ready: (String, u64),
    pub run_agent: (String, u64),
    pub shutdown_agent: (String, u64),
    pub destroy_agentvm: (String, u64),
    pub destroy_netvm: (String, u64),
    pub run_extractor: (String, u64),
    pub run_grader_r0: (String, u64),
    pub run_grader_r1: (String, u64),
    pub run_grader_r2: (String, u64),
    pub run_grader_r3: (String, u64),
}

impl Default for DeadlineSchedule {
    fn default() -> Self {
        Self {
            prepare_world: ("prepare_world_deadline".to_string(), 10_000),
            start_netvm: ("start_netvm_deadline".to_string(), 10_000),
            start_agentvm: ("start_agentvm_deadline".to_string(), 10_000),
            wait_agent_ready: ("wait_agent_ready_deadline".to_string(), 15_000),
            run_agent: ("run_agent_deadline".to_string(), 300_000),
            shutdown_agent: ("shutdown_agent_deadline".to_string(), 10_000),
            destroy_agentvm: ("destroy_agentvm_deadline".to_string(), 5_000),
            destroy_netvm: ("destroy_netvm_deadline".to_string(), 5_000),
            run_extractor: ("run_extractor_deadline".to_string(), 30_000),
            run_grader_r0: ("run_grader_r0_deadline".to_string(), 60_000),
            run_grader_r1: ("run_grader_r1_deadline".to_string(), 60_000),
            run_grader_r2: ("run_grader_r2_deadline".to_string(), 60_000),
            run_grader_r3: ("run_grader_r3_deadline".to_string(), 60_000),
        }
    }
}

impl DeadlineSchedule {
    pub fn deadline_for(&self, step: Step, now_ms: u64) -> NamedDeadline {
        let (name, budget) = match step {
            Step::PrepareWorld => &self.prepare_world,
            Step::StartNetVm => &self.start_netvm,
            Step::StartAgentVm => &self.start_agentvm,
            Step::WaitAgentReady => &self.wait_agent_ready,
            Step::RunAgent => &self.run_agent,
            Step::ShutdownAgent => &self.shutdown_agent,
            Step::DestroyAgentVm => &self.destroy_agentvm,
            Step::DestroyNetVm => &self.destroy_netvm,
            Step::RunExtractor => &self.run_extractor,
            Step::RunGrader(GraderRun::R0) => &self.run_grader_r0,
            Step::RunGrader(GraderRun::R1) => &self.run_grader_r1,
            Step::RunGrader(GraderRun::R2) => &self.run_grader_r2,
            Step::RunGrader(GraderRun::R3) => &self.run_grader_r3,
        };
        NamedDeadline::new(name.clone(), now_ms.saturating_add(*budget))
    }

    pub fn set_step(&mut self, step: Step, name: impl Into<String>, budget_ms: u64) {
        let entry = (name.into(), budget_ms);
        match step {
            Step::PrepareWorld => self.prepare_world = entry,
            Step::StartNetVm => self.start_netvm = entry,
            Step::StartAgentVm => self.start_agentvm = entry,
            Step::WaitAgentReady => self.wait_agent_ready = entry,
            Step::RunAgent => self.run_agent = entry,
            Step::ShutdownAgent => self.shutdown_agent = entry,
            Step::DestroyAgentVm => self.destroy_agentvm = entry,
            Step::DestroyNetVm => self.destroy_netvm = entry,
            Step::RunExtractor => self.run_extractor = entry,
            Step::RunGrader(GraderRun::R0) => self.run_grader_r0 = entry,
            Step::RunGrader(GraderRun::R1) => self.run_grader_r1 = entry,
            Step::RunGrader(GraderRun::R2) => self.run_grader_r2 = entry,
            Step::RunGrader(GraderRun::R3) => self.run_grader_r3 = entry,
        }
    }
}

/// Kind of managed VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmKind {
    Net,
    Agent,
    Extractor,
    Grader,
}

impl fmt::Display for VmKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            VmKind::Net => "net",
            VmKind::Agent => "agent",
            VmKind::Extractor => "extractor",
            VmKind::Grader => "grader",
        };
        f.write_str(label)
    }
}

/// Deterministic VM identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VmId(pub String);

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Handle representing a started VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmHandle {
    pub id: VmId,
    pub kind: VmKind,
}

impl VmHandle {
    pub fn new(id: impl Into<String>, kind: VmKind) -> Self {
        Self {
            id: VmId(id.into()),
            kind,
        }
    }
}

/// Input specification for preparing a sealed Hermetic World.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldSpec {
    pub world_id: String,
    pub cutoff_seal: String,
}

/// Prepared sealed world ready to boot VMs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedWorld {
    pub world_id: String,
    pub image_digest: String,
}

/// Agent execution mode inside the sealed environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    /// Mode H: the evaluation harness sends commands to the agent VM.
    HarnessDriven { commands: Vec<String> },
    /// Mode G: the agent runs autonomously inside the agent VM.
    GuestAutonomous { entrypoint: String },
}

/// Resource limit exceeded by the agent run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    Quota,
    VolumeCap,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitKind::Quota => f.write_str("quota"),
            LimitKind::VolumeCap => f.write_str("volume_cap"),
        }
    }
}

/// Result returned by `run_agent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOutcome {
    Completed { exit_code: i32 },
    LimitExceeded { kind: LimitKind, detail: String },
}

/// Shutdown status reported by `shutdown_agent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownKind {
    Clean,
    Unclean,
}

/// Output from `run_extractor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractorOutcome {
    pub patch_digest: String,
    pub tamper_evidence: Option<String>,
}

/// Handle representing an in-flight grader VM run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraderHandle {
    pub run: GraderRun,
    pub vm: VmHandle,
}

/// Typed payload produced by a grader run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraderPayload {
    R0(R0Result),
    R1(R1Result),
    R2(R2Result),
    R3(R3Result),
}

/// Output from `run_grader` / `finish_grader`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraderOutcome {
    pub run: GraderRun,
    pub payload: GraderPayload,
    pub tamper_evidence: Option<String>,
}

/// Typed infrastructure errors for all operations in `Infra`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfraError {
    DeadlineExceeded {
        step: Step,
        deadline_name: String,
    },
    BackendFailure {
        step: Step,
        detail: String,
    },
    TamperDetected {
        step: Step,
        detail: String,
    },
    VmNotFound {
        vm_id: VmId,
    },
    InvalidVmKind {
        expected: VmKind,
        actual: VmKind,
    },
    GraderPayloadMismatch {
        expected: GraderRun,
        actual: GraderRun,
    },
}

impl fmt::Display for InfraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InfraError::DeadlineExceeded {
                step,
                deadline_name,
            } => write!(f, "step '{}' exceeded deadline '{}'", step, deadline_name),
            InfraError::BackendFailure { step, detail } => {
                write!(f, "step '{}' failed: {}", step, detail)
            }
            InfraError::TamperDetected { step, detail } => {
                write!(f, "tamper detected at step '{}': {}", step, detail)
            }
            InfraError::VmNotFound { vm_id } => {
                write!(f, "VM '{}' does not exist", vm_id)
            }
            InfraError::InvalidVmKind { expected, actual } => {
                write!(f, "expected VM kind '{}', got '{}'", expected, actual)
            }
            InfraError::GraderPayloadMismatch { expected, actual } => {
                write!(f, "grader '{}' returned payload for '{}'", expected, actual)
            }
        }
    }
}

impl std::error::Error for InfraError {}

/// Deterministic log recording VM cleanup actions performed explicitly or via `VmGuard::drop`.
#[derive(Debug, Default)]
pub struct CleanupLog {
    cleaned: RefCell<Vec<VmId>>,
}

impl CleanupLog {
    pub fn new() -> Self {
        Self {
            cleaned: RefCell::new(Vec::new()),
        }
    }

    pub fn record(&self, vm_id: VmId) {
        self.cleaned.borrow_mut().push(vm_id);
    }

    pub fn entries(&self) -> Vec<VmId> {
        self.cleaned.borrow().clone()
    }
}

/// RAII guard for a started VM.
///
/// Guarantees that every started VM is destroyed on all execution paths—including early errors
/// and panics inside fake implementations—and records cleanup in `CleanupLog` upon `Drop`.
pub struct VmGuard<'a, I: Infra> {
    infra: &'a RefCell<&'a mut I>,
    cleanup_log: &'a CleanupLog,
    handle: VmHandle,
    cleanup_deadline: NamedDeadline,
    destroyed: bool,
}

impl<'a, I: Infra> VmGuard<'a, I> {
    pub fn new(
        infra: &'a RefCell<&'a mut I>,
        cleanup_log: &'a CleanupLog,
        handle: VmHandle,
        cleanup_deadline: NamedDeadline,
    ) -> Self {
        Self {
            infra,
            cleanup_log,
            handle,
            cleanup_deadline,
            destroyed: false,
        }
    }

    pub fn handle(&self) -> &VmHandle {
        &self.handle
    }

    /// Explicitly destroys the guarded VM before scope exit and disarms `Drop` destruction.
    pub fn destroy_now(&mut self, deadline: &NamedDeadline) -> Result<(), InfraError> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        self.cleanup_log.record(self.handle.id.clone());
        let mut infra = self
            .infra
            .try_borrow_mut()
            .map_err(|_| InfraError::BackendFailure {
                step: match self.handle.kind {
                    VmKind::Agent => Step::DestroyAgentVm,
                    VmKind::Net => Step::DestroyNetVm,
                    _ => Step::DestroyNetVm,
                },
                detail: "infrastructure backend is mutably borrowed".to_string(),
            })?;
        infra.destroy_vm(&self.handle, deadline)
    }
}

impl<I: Infra> Drop for VmGuard<'_, I> {
    fn drop(&mut self) {
        if !self.destroyed {
            self.destroyed = true;
            self.cleanup_log.record(self.handle.id.clone());
            if let Ok(mut infra) = self.infra.try_borrow_mut() {
                let _ = infra.destroy_vm(&self.handle, &self.cleanup_deadline);
            }
        }
    }
}

/// Infrastructure operations for executing a sealed Hermetic World evaluation run.
pub trait Infra {
    fn prepare_world(
        &mut self,
        world: &WorldSpec,
        deadline: &NamedDeadline,
    ) -> Result<PreparedWorld, InfraError>;

    fn start_netvm(
        &mut self,
        world: &PreparedWorld,
        deadline: &NamedDeadline,
    ) -> Result<VmHandle, InfraError>;

    fn start_agentvm(
        &mut self,
        world: &PreparedWorld,
        net_vm: &VmHandle,
        deadline: &NamedDeadline,
    ) -> Result<VmHandle, InfraError>;

    fn wait_agent_ready(
        &mut self,
        agent_vm: &VmHandle,
        deadline: &NamedDeadline,
    ) -> Result<(), InfraError>;

    fn run_agent(
        &mut self,
        agent_vm: &VmHandle,
        mode: &AgentMode,
        deadline: &NamedDeadline,
    ) -> Result<AgentOutcome, InfraError>;

    fn shutdown_agent(
        &mut self,
        agent_vm: &VmHandle,
        deadline: &NamedDeadline,
    ) -> Result<ShutdownKind, InfraError>;

    fn destroy_vm(&mut self, vm: &VmHandle, deadline: &NamedDeadline) -> Result<(), InfraError>;

    fn run_extractor(
        &mut self,
        world: &PreparedWorld,
        deadline: &NamedDeadline,
    ) -> Result<ExtractorOutcome, InfraError>;

    /// Starts an isolated grader VM for `run_name`, enabling R0..R2 to run concurrently.
    fn start_grader(
        &mut self,
        run_name: GraderRun,
        world: &PreparedWorld,
        extracted: &ExtractorOutcome,
        deadline: &NamedDeadline,
    ) -> Result<GraderHandle, InfraError>;

    /// Waits for an in-flight grader VM to finish and destroys it.
    fn finish_grader(
        &mut self,
        handle: GraderHandle,
        deadline: &NamedDeadline,
    ) -> Result<GraderOutcome, InfraError>;

    /// Best-effort cleanup of an in-flight grader if a sibling grader fails to start.
    fn abort_grader(
        &mut self,
        handle: GraderHandle,
        deadline: &NamedDeadline,
    ) -> Result<(), InfraError> {
        let _ = self.finish_grader(handle, deadline);
        Ok(())
    }

    /// Runs a single grader end-to-end (`start_grader` followed by `finish_grader`).
    fn run_grader(
        &mut self,
        run_name: GraderRun,
        world: &PreparedWorld,
        extracted: &ExtractorOutcome,
        deadline: &NamedDeadline,
    ) -> Result<GraderOutcome, InfraError> {
        let handle = self.start_grader(run_name, world, extracted, deadline)?;
        self.finish_grader(handle, deadline)
    }
}
