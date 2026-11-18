#![forbid(unsafe_code)]

pub mod args;
pub mod backend;
pub mod dispatch;
pub mod fsutil;
pub mod run_flow;
pub mod vmm_infra;

use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::process::ExitCode as StdExitCode;

pub use args::{
    parse_args, validate_command, AgentMode, ClockMode, ParseError, ParseErrorKind, ProbeRequest,
    RawCommand, RawProbeArgs, RawRunArgs, RawSealArgs, RawVerifyArgs, RawVerifyBundleArgs,
    RunRequest, SealLevel, SealRequest, SubcommandKind, ValidatedCommand, ValidationError,
    VerifyBundleRequest, VerifyRequest, MAX_ARGS, MAX_ARG_BYTES,
};
pub use backend::RealBackend;
pub use dispatch::{
    dispatch, Backend, BackendError, DispatchError, DispatchedOutput, NotImplementedBackend,
    Outcome, EXIT_DATA_ERROR, EXIT_INTERNAL_OR_NOT_IMPLEMENTED, EXIT_IO_ERROR, EXIT_PROBLEM_FOUND,
    EXIT_SUCCESS, EXIT_USAGE_ERROR,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitCode(pub u8);

impl ExitCode {
    pub const SUCCESS: Self = Self(EXIT_SUCCESS);
    pub const PROBLEM_FOUND: Self = Self(EXIT_PROBLEM_FOUND);
    pub const USAGE_ERROR: Self = Self(EXIT_USAGE_ERROR);
    pub const DATA_ERROR: Self = Self(EXIT_DATA_ERROR);
    pub const INTERNAL_OR_NOT_IMPLEMENTED: Self = Self(EXIT_INTERNAL_OR_NOT_IMPLEMENTED);
    pub const IO_ERROR: Self = Self(EXIT_IO_ERROR);
}

impl From<ExitCode> for StdExitCode {
    fn from(code: ExitCode) -> Self {
        StdExitCode::from(code.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    Parse(ParseError),
    Validation(ValidationError),
    Dispatch(DispatchError),
}

impl CliError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Parse(_) => ExitCode::USAGE_ERROR,
            Self::Validation(_) => ExitCode::DATA_ERROR,
            Self::Dispatch(err) => ExitCode(err.exit_code()),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => err.fmt(f),
            Self::Validation(err) => err.fmt(f),
            Self::Dispatch(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for CliError {}

pub const TOP_LEVEL_HELP: &str = "\
hermetic - Seal and evaluate Hermetic World software-engineering benchmarks

USAGE:
  hermetic seal --src DIR --out DIR --t-clock RFC3339 --world-id ID [--seal-level strict|repo_only]
  hermetic verify-bundle DIR [--root sha256:HEX]
  hermetic probe --world DIR [--clockprobe-output FILE] [--kernel-canary-serial FILE] [--json]
  hermetic run --world DIR --task ID --agent-mode H|G [--clock faked|hidden] [--json]
  hermetic verify --record FILE --key FILE [--bundle DIR] [--classification FILE]
  hermetic --version
  hermetic help [SUBCOMMAND]

SUBCOMMANDS:
  seal           Seal a source repository into a deterministic Hermetic World
  verify-bundle  Verify integrity and root digest of a sealed world bundle
  probe          Classify captured clock probe output (never probes the host)
  run            Execute a benchmark task inside a sealed world
  verify         Verify a recorded evaluation run against a bundle
  help           Show general or subcommand help

OPTIONS:
  Both --flag=value and --flag value forms are accepted.
  Use -- to terminate option parsing; short flags are not supported.

EXIT CODES:
  0   Success
  2   Operation completed and found a problem (for example, verification failed)
  64  Command-line usage error
  65  Invalid input data
  70  Internal error or feature not implemented
  74  I/O error";

pub const SEAL_HELP: &str = "\
USAGE:
  hermetic seal --src DIR --out DIR --t-clock RFC3339 --world-id ID [--seal-level strict|repo_only]

OPTIONS:
  --src DIR                      Source directory path (non-empty, no NUL bytes)
  --out DIR                      Output bundle directory path (non-empty, no NUL bytes)
  --t-clock RFC3339              Cutoff timestamp in UTC RFC 3339 format with 'Z' suffix
  --world-id ID                  World identifier matching [a-z0-9-]{1,64}
  --seal-level strict|repo_only  Sealing strictness level (default: strict)";

pub const VERIFY_BUNDLE_HELP: &str = "\
USAGE:
  hermetic verify-bundle DIR [--root sha256:HEX]

ARGS:
  DIR                 Sealed bundle directory path (non-empty, no NUL bytes)

OPTIONS:
  --root sha256:HEX   Expected root digest ('sha256:' followed by 64 lowercase hex chars)";

pub const PROBE_HELP: &str = "\
USAGE:
  hermetic probe --world DIR [--clockprobe-output FILE] [--kernel-canary-serial FILE] [--json]

OPTIONS:
  --world DIR                   Sealed world directory path (non-empty, no NUL bytes)
  --clockprobe-output FILE      Captured hermetic-clockprobe JSON lines to classify
  --kernel-canary-serial FILE   Captured kernel canary serial transcript to classify
  --json                        Emit a single canonical JSON object on stdout

Probes never run on the host; without an input file probe fails closed (exit 70).";

pub const RUN_HELP: &str = "\
USAGE:
  hermetic run --world DIR --task ID --agent-mode H|G [--clock faked|hidden] [--json]

OPTIONS:
  --world DIR            Sealed world directory path (non-empty, no NUL bytes)
  --task ID              Task identifier matching [A-Za-z0-9._-]{1,128}
  --agent-mode H|G       Agent evaluation mode ('H' or 'G')
  --clock faked|hidden   Clock isolation mode (default: faked)
  --json                 Emit a single canonical JSON object on stdout";

pub const VERIFY_HELP: &str = "\
USAGE:
  hermetic verify --record FILE --key FILE [--bundle DIR] [--classification FILE]

OPTIONS:
  --record FILE          Signed run attestation (DSSE envelope JSON)
  --key FILE             Trusted raw 32-byte Ed25519 public key
  --bundle DIR           Optional sealed bundle; its root must equal the record's world_root
  --classification FILE  Optional hermetic-run-classification/v1 to cross-check";

pub const HELP_COMMAND_HELP: &str = "\
USAGE:
  hermetic help [SUBCOMMAND]

ARGS:
  SUBCOMMAND   Optional subcommand name (seal, verify-bundle, probe, run, verify, help)";

pub fn help_text(subcommand: Option<SubcommandKind>) -> &'static str {
    match subcommand {
        None => TOP_LEVEL_HELP,
        Some(SubcommandKind::Seal) => SEAL_HELP,
        Some(SubcommandKind::VerifyBundle) => VERIFY_BUNDLE_HELP,
        Some(SubcommandKind::Probe) => PROBE_HELP,
        Some(SubcommandKind::Run) => RUN_HELP,
        Some(SubcommandKind::Verify) => VERIFY_HELP,
        Some(SubcommandKind::Help) => HELP_COMMAND_HELP,
    }
}

/// Runs the CLI using a full process `argv` iterator (including `argv[0]`).
pub fn run_from_env_args<I>(
    args: I,
    backend: &dyn Backend,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    run_with_args(args.into_iter().skip(1), backend, stdout, stderr)
}

/// Runs the CLI using argument tokens after `argv[0]`.
pub fn run_with_args<I>(
    args: I,
    backend: &dyn Backend,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    let raw = match parse_args(args) {
        Ok(cmd) => cmd,
        Err(err) => {
            let usage = help_text(err.subcommand);
            let _ = writeln!(stderr, "error: {err}\n\n{usage}");
            return ExitCode::USAGE_ERROR;
        }
    };

    if let RawCommand::Help(subcommand) = raw {
        if writeln!(stdout, "{}", help_text(subcommand)).is_err() {
            return ExitCode::IO_ERROR;
        }
        return ExitCode::SUCCESS;
    }

    let validated = match validate_command(raw) {
        Ok(cmd) => cmd,
        Err(err) => {
            let _ = writeln!(stderr, "error: {err}");
            return ExitCode::DATA_ERROR;
        }
    };

    match dispatch(validated, backend) {
        Ok(output) => {
            if writeln!(stdout, "{}", output.stdout_line).is_err() {
                return ExitCode::IO_ERROR;
            }
            ExitCode(output.exit_code)
        }
        Err(err) => {
            let _ = writeln!(stderr, "error: {err}");
            ExitCode(err.exit_code())
        }
    }
}
