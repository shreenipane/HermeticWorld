#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;

use hermetic_grader_supervisor::{run_supervisor, Os, RealOs, SupervisorError};

const MAX_CLI_ARGS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    config: PathBuf,
    result_disk: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliError {
    HelpRequested,
    TooManyArgs,
    MissingValue(&'static str),
    DuplicateFlag(&'static str),
    UnknownArgument(String),
    MissingRequiredFlag(&'static str),
    Supervisor(SupervisorError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::HelpRequested => write!(
                f,
                "Usage: hermetic-grader-supervisor --config FILE --result-disk FILE"
            ),
            CliError::TooManyArgs => write!(f, "too many command-line arguments"),
            CliError::MissingValue(flag) => write!(f, "flag {} requires a file path value", flag),
            CliError::DuplicateFlag(flag) => write!(f, "flag {} specified more than once", flag),
            CliError::UnknownArgument(_) => write!(f, "unknown argument"),
            CliError::MissingRequiredFlag(flag) => write!(f, "missing required flag: {}", flag),
            CliError::Supervisor(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for CliError {}

fn parse_cli_args<I>(args: I) -> Result<CliArgs, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iter = args.into_iter().take(MAX_CLI_ARGS.saturating_add(1));
    let _program = iter.next();

    let mut config: Option<PathBuf> = None;
    let mut result_disk: Option<PathBuf> = None;
    let mut count = 0usize;

    while let Some(arg) = iter.next() {
        count = count.saturating_add(1);
        if count > MAX_CLI_ARGS {
            return Err(CliError::TooManyArgs);
        }

        let lossy = arg.to_string_lossy();
        match lossy.as_ref() {
            "-h" | "--help" => return Err(CliError::HelpRequested),
            "--config" => {
                if config.is_some() {
                    return Err(CliError::DuplicateFlag("--config"));
                }
                let val = iter.next().ok_or(CliError::MissingValue("--config"))?;
                count = count.saturating_add(1);
                if count > MAX_CLI_ARGS || val.is_empty() {
                    return Err(CliError::MissingValue("--config"));
                }
                config = Some(PathBuf::from(val));
            }
            "--result-disk" => {
                if result_disk.is_some() {
                    return Err(CliError::DuplicateFlag("--result-disk"));
                }
                let val = iter.next().ok_or(CliError::MissingValue("--result-disk"))?;
                count = count.saturating_add(1);
                if count > MAX_CLI_ARGS || val.is_empty() {
                    return Err(CliError::MissingValue("--result-disk"));
                }
                result_disk = Some(PathBuf::from(val));
            }
            other => {
                if let Some(val) = other.strip_prefix("--config=") {
                    if config.is_some() {
                        return Err(CliError::DuplicateFlag("--config"));
                    }
                    if val.is_empty() {
                        return Err(CliError::MissingValue("--config"));
                    }
                    config = Some(PathBuf::from(val));
                } else if let Some(val) = other.strip_prefix("--result-disk=") {
                    if result_disk.is_some() {
                        return Err(CliError::DuplicateFlag("--result-disk"));
                    }
                    if val.is_empty() {
                        return Err(CliError::MissingValue("--result-disk"));
                    }
                    result_disk = Some(PathBuf::from(val));
                } else {
                    return Err(CliError::UnknownArgument(other.to_string()));
                }
            }
        }
    }

    let config = config.ok_or(CliError::MissingRequiredFlag("--config"))?;
    let result_disk = result_disk.ok_or(CliError::MissingRequiredFlag("--result-disk"))?;

    Ok(CliArgs {
        config,
        result_disk,
    })
}

fn run_with_os<I, O>(args: I, os: &mut O) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
    O: Os,
{
    let parsed = parse_cli_args(args)?;
    run_supervisor(os, &parsed.config, &parsed.result_disk).map_err(CliError::Supervisor)?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().take(3).collect();
    if args.len() == 2 {
        if let Some(mode) = args.get(1).and_then(|s| s.to_str()) {
            if matches!(mode, "--sandbox-launch" | "--sandbox-init") {
                return if hermetic_grader_supervisor::sandbox::helper(mode == "--sandbox-init")
                    .is_ok()
                {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
            }
        }
    }
    let mut os = RealOs::new();
    match run_with_os(std::env::args_os(), &mut os) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::HelpRequested) => {
            println!("{}", CliError::HelpRequested);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {}", err);
            ExitCode::from(1)
        }
    }
}
