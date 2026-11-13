use std::fmt;

use serde::{Deserialize, Serialize};

use crate::infra::Step;

/// Structured reason when a run transitions to `RunState::Failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureReason {
    pub message: String,
}

impl FailureReason {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Explicit states of an evaluation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunState {
    Initial,
    Prepared,
    NetUp,
    AgentUp,
    AgentDone,
    Extracted,
    Graded,
    Finished,
    Failed { step: Step, reason: FailureReason },
}

impl RunState {
    pub fn label(&self) -> &'static str {
        match self {
            RunState::Initial => "Initial",
            RunState::Prepared => "Prepared",
            RunState::NetUp => "NetUp",
            RunState::AgentUp => "AgentUp",
            RunState::AgentDone => "AgentDone",
            RunState::Extracted => "Extracted",
            RunState::Graded => "Graded",
            RunState::Finished => "Finished",
            RunState::Failed { .. } => "Failed",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, RunState::Finished | RunState::Failed { .. })
    }
}

impl fmt::Display for RunState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunState::Failed { step, reason } => write!(f, "Failed({}, {})", step, reason),
            other => f.write_str(other.label()),
        }
    }
}

/// Typed error returned when an invalid state transition or lifecycle invariant violation occurs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionError {
    InvalidTransition { from: String, to: String },
    InvariantViolation { detail: String },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::InvalidTransition { from, to } => {
                write!(f, "invalid state transition from {} to {}", from, to)
            }
            TransitionError::InvariantViolation { detail } => {
                write!(f, "lifecycle invariant violated: {}", detail)
            }
        }
    }
}

impl std::error::Error for TransitionError {}

/// Deterministic state machine enforcing valid evaluation lifecycle transitions
/// and VM existence invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachine {
    state: RunState,
    net_vm_alive: bool,
    agent_vm_alive: bool,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine {
    pub fn new() -> Self {
        Self {
            state: RunState::Initial,
            net_vm_alive: false,
            agent_vm_alive: false,
        }
    }

    pub fn state(&self) -> &RunState {
        &self.state
    }

    pub fn net_vm_alive(&self) -> bool {
        self.net_vm_alive
    }

    pub fn agent_vm_alive(&self) -> bool {
        self.agent_vm_alive
    }

    /// Validates and executes a transition to `next`.
    ///
    /// Valid transitions:
    /// - `Initial -> Prepared`
    /// - `Prepared -> NetUp`
    /// - `NetUp -> AgentUp`
    /// - `AgentUp -> AgentDone`
    /// - `AgentDone -> Extracted`
    /// - `Extracted -> Graded`
    /// - `Graded -> Finished`
    /// - Any non-terminal state `-> Failed { .. }`
    pub fn transition(&mut self, next: RunState) -> Result<(), TransitionError> {
        if self.state.is_terminal() {
            return Err(TransitionError::InvalidTransition {
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }

        let valid = matches!(
            (&self.state, &next),
            (RunState::Initial, RunState::Prepared)
                | (RunState::Prepared, RunState::NetUp)
                | (RunState::NetUp, RunState::AgentUp)
                | (RunState::AgentUp, RunState::AgentDone)
                | (RunState::AgentDone, RunState::Extracted)
                | (RunState::Extracted, RunState::Graded)
                | (RunState::Graded, RunState::Finished)
                | (_, RunState::Failed { .. })
        );

        if !valid {
            return Err(TransitionError::InvalidTransition {
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }

        if matches!(next, RunState::AgentUp) && !self.net_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "NetVM must be up before AgentVM starts".to_string(),
            });
        }

        if matches!(next, RunState::Extracted) && (self.agent_vm_alive || self.net_vm_alive) {
            return Err(TransitionError::InvariantViolation {
                detail: "AgentVM and NetVM must be destroyed before extraction".to_string(),
            });
        }

        self.state = next;
        Ok(())
    }

    pub fn to_prepared(&mut self) -> Result<(), TransitionError> {
        self.transition(RunState::Prepared)
    }

    pub fn to_net_up(&mut self) -> Result<(), TransitionError> {
        if self.net_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "NetVM is already running".to_string(),
            });
        }
        self.transition(RunState::NetUp)?;
        self.net_vm_alive = true;
        Ok(())
    }

    pub fn to_agent_up(&mut self) -> Result<(), TransitionError> {
        if !self.net_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "NetVM must be up before AgentVM starts".to_string(),
            });
        }
        if self.agent_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "AgentVM is already running".to_string(),
            });
        }
        self.transition(RunState::AgentUp)?;
        self.agent_vm_alive = true;
        Ok(())
    }

    pub fn to_agent_done(&mut self) -> Result<(), TransitionError> {
        self.transition(RunState::AgentDone)
    }

    pub fn mark_agent_vm_destroyed(&mut self) -> Result<(), TransitionError> {
        if !self.agent_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "AgentVM is not running".to_string(),
            });
        }
        self.agent_vm_alive = false;
        Ok(())
    }

    pub fn mark_net_vm_destroyed(&mut self) -> Result<(), TransitionError> {
        if !self.net_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "NetVM is not running".to_string(),
            });
        }
        self.net_vm_alive = false;
        Ok(())
    }

    /// Verifies that no agent or network VM exists before starting extraction.
    pub fn ensure_ready_for_extraction(&self) -> Result<(), TransitionError> {
        if self.state != RunState::AgentDone {
            return Err(TransitionError::InvalidTransition {
                from: self.state.to_string(),
                to: RunState::Extracted.to_string(),
            });
        }
        if self.agent_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "extractor cannot run while AgentVM exists".to_string(),
            });
        }
        if self.net_vm_alive {
            return Err(TransitionError::InvariantViolation {
                detail: "extractor cannot run while NetVM exists".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_extracted(&mut self) -> Result<(), TransitionError> {
        self.ensure_ready_for_extraction()?;
        self.transition(RunState::Extracted)
    }

    pub fn to_graded(&mut self) -> Result<(), TransitionError> {
        self.transition(RunState::Graded)
    }

    pub fn to_finished(&mut self) -> Result<(), TransitionError> {
        self.transition(RunState::Finished)
    }

    pub fn fail(&mut self, step: Step, reason: impl Into<String>) -> Result<(), TransitionError> {
        self.transition(RunState::Failed {
            step,
            reason: FailureReason::new(reason),
        })
    }
}
