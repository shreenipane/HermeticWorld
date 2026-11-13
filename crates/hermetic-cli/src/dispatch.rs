use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::args::{
    ClockMode, ProbeRequest, RunRequest, SealRequest, ValidatedCommand, VerifyBundleRequest,
    VerifyRequest,
};

/// Fixed exit codes for the `hermetic` CLI.
pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_PROBLEM_FOUND: u8 = 2;
pub const EXIT_USAGE_ERROR: u8 = 64;
pub const EXIT_DATA_ERROR: u8 = 65;
pub const EXIT_INTERNAL_OR_NOT_IMPLEMENTED: u8 = 70;
pub const EXIT_IO_ERROR: u8 = 74;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub ok: bool,
    pub summary: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl Outcome {
    pub fn success(summary: impl Into<String>) -> Self {
        Self {
            ok: true,
            summary: summary.into(),
            details: BTreeMap::new(),
        }
    }

    pub fn problem(summary: impl Into<String>) -> Self {
        Self {
            ok: false,
            summary: summary.into(),
            details: BTreeMap::new(),
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    NotWired { operation: &'static str },
    ProblemFound(String),
    Io(String),
    Internal(String),
}

impl BackendError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::ProblemFound(_) => EXIT_PROBLEM_FOUND,
            Self::NotWired { .. } | Self::Internal(_) => EXIT_INTERNAL_OR_NOT_IMPLEMENTED,
            Self::Io(_) => EXIT_IO_ERROR,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWired { operation } => {
                write!(f, "backend operation '{operation}' is not yet wired")
            }
            Self::ProblemFound(msg) => f.write_str(msg),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for BackendError {}

pub trait Backend {
    fn seal(&self, req: SealRequest) -> Result<Outcome, BackendError>;
    fn verify_bundle(&self, req: VerifyBundleRequest) -> Result<Outcome, BackendError>;
    fn probe(&self, req: ProbeRequest) -> Result<Outcome, BackendError>;
    fn run(&self, req: RunRequest) -> Result<Outcome, BackendError>;
    fn verify(&self, req: VerifyRequest) -> Result<Outcome, BackendError>;
}

/// Default production placeholder backend until the core Hermetic World crates are wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotImplementedBackend;

impl Backend for NotImplementedBackend {
    fn seal(&self, _req: SealRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::NotWired { operation: "seal" })
    }

    fn verify_bundle(&self, _req: VerifyBundleRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::NotWired {
            operation: "verify-bundle",
        })
    }

    fn probe(&self, _req: ProbeRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::NotWired { operation: "probe" })
    }

    fn run(&self, _req: RunRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::NotWired { operation: "run" })
    }

    fn verify(&self, _req: VerifyRequest) -> Result<Outcome, BackendError> {
        Err(BackendError::NotWired {
            operation: "verify",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    HiddenClockUnavailable,
    Backend(BackendError),
}

impl DispatchError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::HiddenClockUnavailable => EXIT_INTERNAL_OR_NOT_IMPLEMENTED,
            Self::Backend(err) => err.exit_code(),
        }
    }
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HiddenClockUnavailable => {
                f.write_str("the hidden clock level is not available yet")
            }
            Self::Backend(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for DispatchError {}

impl From<BackendError> for DispatchError {
    fn from(err: BackendError) -> Self {
        Self::Backend(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchedOutput {
    pub exit_code: u8,
    pub stdout_line: String,
}

pub fn dispatch(
    command: ValidatedCommand,
    backend: &dyn Backend,
) -> Result<DispatchedOutput, DispatchError> {
    match command {
        ValidatedCommand::Version => Ok(DispatchedOutput {
            exit_code: EXIT_SUCCESS,
            stdout_line: format!("hermetic {}", env!("CARGO_PKG_VERSION")),
        }),
        ValidatedCommand::Help(_) => Err(DispatchError::Backend(BackendError::Internal(
            "help command must be rendered prior to backend dispatch".to_string(),
        ))),
        ValidatedCommand::Seal(req) => {
            let outcome = backend.seal(req)?;
            format_outcome("seal", outcome, false)
        }
        ValidatedCommand::VerifyBundle(req) => {
            let outcome = backend.verify_bundle(req)?;
            format_outcome("verify-bundle", outcome, false)
        }
        ValidatedCommand::Probe(req) => {
            let json = req.json;
            let outcome = backend.probe(req)?;
            format_outcome("probe", outcome, json)
        }
        ValidatedCommand::Run(req) => {
            if req.clock == ClockMode::Hidden {
                return Err(DispatchError::HiddenClockUnavailable);
            }
            let json = req.json;
            let outcome = backend.run(req)?;
            format_outcome("run", outcome, json)
        }
        ValidatedCommand::Verify(req) => {
            let outcome = backend.verify(req)?;
            format_outcome("verify", outcome, false)
        }
    }
}

fn format_outcome(
    command: &'static str,
    outcome: Outcome,
    json: bool,
) -> Result<DispatchedOutput, DispatchError> {
    let exit_code = if outcome.ok {
        EXIT_SUCCESS
    } else {
        EXIT_PROBLEM_FOUND
    };

    if json {
        let mut root: BTreeMap<String, Value> = BTreeMap::new();
        root.insert("command".to_string(), Value::String(command.to_string()));
        root.insert("ok".to_string(), Value::Bool(outcome.ok));
        root.insert("summary".to_string(), Value::String(outcome.summary));
        if !outcome.details.is_empty() {
            let canonical_details: BTreeMap<String, Value> = outcome
                .details
                .into_iter()
                .map(|(k, v)| (k, canonicalize_json_value(v)))
                .collect();
            let details_obj = canonical_details.into_iter().collect();
            root.insert("details".to_string(), Value::Object(details_obj));
        }
        let serialized = serde_json::to_string(&root).map_err(|e| {
            DispatchError::Backend(BackendError::Internal(format!(
                "failed to serialize JSON output: {e}"
            )))
        })?;
        Ok(DispatchedOutput {
            exit_code,
            stdout_line: serialized,
        })
    } else {
        let single_line_summary = outcome.summary.replace(['\r', '\n'], " ");
        Ok(DispatchedOutput {
            exit_code,
            stdout_line: format!("{command}: {single_line_summary}"),
        })
    }
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize_json_value).collect())
        }
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, canonicalize_json_value(v)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        other => other,
    }
}
