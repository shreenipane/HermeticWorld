#![forbid(unsafe_code)]

use hermetic_grader_result::{
    read_bounded_regular_file, read_disk, verdict, DiskError, GradingPlan, RunResult,
    VerdictStatus, MAX_PLAN_BYTES,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_CLI_ARGS: usize = 32;

#[derive(Debug)]
enum CliError {
    Usage,
    Io,
}

struct CliPaths {
    r0: PathBuf,
    r1: PathBuf,
    r2: PathBuf,
    r3: Option<PathBuf>,
    plan: PathBuf,
}

fn parse_cli_args() -> Result<CliPaths, CliError> {
    let mut args_iter = std::env::args_os();
    let _prog = args_iter.next();

    let mut r0: Option<PathBuf> = None;
    let mut r1: Option<PathBuf> = None;
    let mut r2: Option<PathBuf> = None;
    let mut r3: Option<PathBuf> = None;
    let mut plan: Option<PathBuf> = None;

    let mut steps: usize = 0;
    while let Some(flag_os) = args_iter.next() {
        steps = steps.checked_add(1).ok_or(CliError::Usage)?;
        if steps > MAX_CLI_ARGS {
            return Err(CliError::Usage);
        }

        let flag = flag_os.to_str().ok_or(CliError::Usage)?;
        let val_os = args_iter.next().ok_or(CliError::Usage)?;
        if val_os.is_empty() {
            return Err(CliError::Usage);
        }
        let path = PathBuf::from(val_os);

        match flag {
            "--r0" => {
                if r0.is_some() {
                    return Err(CliError::Usage);
                }
                r0 = Some(path);
            }
            "--r1" => {
                if r1.is_some() {
                    return Err(CliError::Usage);
                }
                r1 = Some(path);
            }
            "--r2" => {
                if r2.is_some() {
                    return Err(CliError::Usage);
                }
                r2 = Some(path);
            }
            "--r3" => {
                if r3.is_some() {
                    return Err(CliError::Usage);
                }
                r3 = Some(path);
            }
            "--plan" => {
                if plan.is_some() {
                    return Err(CliError::Usage);
                }
                plan = Some(path);
            }
            _ => return Err(CliError::Usage),
        }
    }

    Ok(CliPaths {
        r0: r0.ok_or(CliError::Usage)?,
        r1: r1.ok_or(CliError::Usage)?,
        r2: r2.ok_or(CliError::Usage)?,
        r3,
        plan: plan.ok_or(CliError::Usage)?,
    })
}

fn load_plan(path: &Path) -> Result<GradingPlan, CliError> {
    let bytes = read_bounded_regular_file(path, MAX_PLAN_BYTES).map_err(|_| CliError::Io)?;
    let plan: GradingPlan = serde_json::from_slice(&bytes).map_err(|_| CliError::Io)?;
    if !plan.is_valid() {
        return Err(CliError::Io);
    }
    Ok(plan)
}

fn load_run_disk(path: &Path) -> Result<Result<RunResult, DiskError>, CliError> {
    match read_disk(path) {
        Ok(run) => Ok(Ok(run)),
        Err(DiskError::Tamper(reason)) => Ok(Err(DiskError::Tamper(reason))),
        Err(DiskError::NotRegularFile(_)) | Err(DiskError::Io(_)) => Err(CliError::Io),
    }
}

fn run_cli() -> Result<ExitCode, CliError> {
    let paths = parse_cli_args()?;
    let plan = load_plan(&paths.plan)?;

    let r0 = load_run_disk(&paths.r0)?;
    let r1 = load_run_disk(&paths.r1)?;
    let r2 = load_run_disk(&paths.r2)?;
    let r3 = match paths.r3 {
        Some(ref p) => Some(load_run_disk(p)?),
        None => None,
    };

    let out = verdict(r0, r1, r2, r3, &plan);
    let json = serde_json::to_string(&out).map_err(|_| CliError::Io)?;
    println!("{}", json);

    if out.status == VerdictStatus::Resolved {
        Ok(ExitCode::from(0))
    } else {
        Ok(ExitCode::from(2))
    }
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(code) => code,
        Err(CliError::Usage) => {
            eprintln!("usage: hermetic-grader-verdict --r0 F --r1 F --r2 F [--r3 F] --plan F");
            ExitCode::from(1)
        }
        Err(CliError::Io) => {
            eprintln!("error: failed to read grading inputs");
            ExitCode::from(1)
        }
    }
}
