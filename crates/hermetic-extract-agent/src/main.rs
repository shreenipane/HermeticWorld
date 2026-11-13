#![forbid(unsafe_code)]

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use hermetic_extract_agent::{extract, parse_task_class, Caps, ExtractError, TaskClass};

const MAX_CLI_ARGS: usize = 64;
const MAX_CLI_ARG_BYTES: usize = 16 * 1024;

const USAGE: &str = "Usage: hermetic-extract-agent --base DIR --work DIR --class patch:REPO|artifact:P1,P2|state --out FILE --report FILE";

#[derive(Debug)]
struct CliArgs {
    base: PathBuf,
    work: PathBuf,
    task_class: TaskClass,
    out: PathBuf,
    report: PathBuf,
}

#[derive(Debug)]
enum CliError {
    HelpRequested,
    TooManyArgs,
    ArgTooLong,
    InvalidUtf8Arg,
    UnexpectedPositional(String),
    UnknownFlag(String),
    MissingValue(&'static str),
    DuplicateFlag(&'static str),
    MissingRequiredFlag(&'static str),
    Extract(ExtractError),
    OutputIo(&'static str, io::ErrorKind),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::HelpRequested => write!(f, "{}", USAGE),
            CliError::TooManyArgs => write!(f, "too many CLI arguments (max {})", MAX_CLI_ARGS),
            CliError::ArgTooLong => {
                write!(
                    f,
                    "CLI argument exceeds maximum length ({} bytes)",
                    MAX_CLI_ARG_BYTES
                )
            }
            CliError::InvalidUtf8Arg => write!(f, "CLI argument is not valid UTF-8"),
            CliError::UnexpectedPositional(arg) => {
                write!(f, "unexpected positional argument: '{}'", arg)
            }
            CliError::UnknownFlag(flag) => write!(f, "unknown flag: '{}'", flag),
            CliError::MissingValue(flag) => write!(f, "missing value for flag '{}'", flag),
            CliError::DuplicateFlag(flag) => write!(f, "duplicate flag '{}'", flag),
            CliError::MissingRequiredFlag(flag) => {
                write!(f, "missing required flag '{}'\n{}", flag, USAGE)
            }
            CliError::Extract(err) => write!(f, "{}", err),
            CliError::OutputIo(what, kind) => write!(f, "failed writing {}: {:?}", what, kind),
        }
    }
}

fn parse_cli<I>(args_iter: I) -> Result<CliArgs, CliError>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut raw_args: Vec<String> = Vec::new();
    for (idx, os_arg) in args_iter.into_iter().enumerate() {
        if idx >= MAX_CLI_ARGS {
            return Err(CliError::TooManyArgs);
        }
        let s = os_arg.into_string().map_err(|_| CliError::InvalidUtf8Arg)?;
        if s.len() > MAX_CLI_ARG_BYTES {
            return Err(CliError::ArgTooLong);
        }
        raw_args.push(s);
    }

    let mut base: Option<PathBuf> = None;
    let mut work: Option<PathBuf> = None;
    let mut class_spec: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;

    let mut i: usize = 1; // Skip argv[0]
    for _ in 0..MAX_CLI_ARGS {
        let Some(arg) = raw_args.get(i) else {
            break;
        };
        if arg == "-h" || arg == "--help" {
            return Err(CliError::HelpRequested);
        }

        let (flag, inline_val) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (arg.as_str(), None),
        };

        let (canonical_flag, needs_val) = match flag {
            "--base" => ("--base", true),
            "--work" => ("--work", true),
            "--class" => ("--class", true),
            "--out" => ("--out", true),
            "--report" => ("--report", true),
            _ if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_string())),
            _ => return Err(CliError::UnexpectedPositional(arg.clone())),
        };

        let val = if needs_val {
            if let Some(v) = inline_val {
                i = i.saturating_add(1);
                v
            } else {
                let next_idx = i.saturating_add(1);
                let next = raw_args
                    .get(next_idx)
                    .ok_or(CliError::MissingValue(canonical_flag))?;
                i = next_idx.saturating_add(1);
                next.clone()
            }
        } else {
            i = i.saturating_add(1);
            String::new()
        };

        if val.is_empty() {
            return Err(CliError::MissingValue(canonical_flag));
        }

        match canonical_flag {
            "--base" => {
                if base.is_some() {
                    return Err(CliError::DuplicateFlag("--base"));
                }
                base = Some(PathBuf::from(val));
            }
            "--work" => {
                if work.is_some() {
                    return Err(CliError::DuplicateFlag("--work"));
                }
                work = Some(PathBuf::from(val));
            }
            "--class" => {
                if class_spec.is_some() {
                    return Err(CliError::DuplicateFlag("--class"));
                }
                class_spec = Some(val);
            }
            "--out" => {
                if out.is_some() {
                    return Err(CliError::DuplicateFlag("--out"));
                }
                out = Some(PathBuf::from(val));
            }
            "--report" => {
                if report.is_some() {
                    return Err(CliError::DuplicateFlag("--report"));
                }
                report = Some(PathBuf::from(val));
            }
            _ => return Err(CliError::UnknownFlag(flag.to_string())),
        }
    }

    let base = base.ok_or(CliError::MissingRequiredFlag("--base"))?;
    let work = work.ok_or(CliError::MissingRequiredFlag("--work"))?;
    let class_str = class_spec.ok_or(CliError::MissingRequiredFlag("--class"))?;
    let out = out.ok_or(CliError::MissingRequiredFlag("--out"))?;
    let report = report.ok_or(CliError::MissingRequiredFlag("--report"))?;

    let task_class = parse_task_class(&class_str).map_err(CliError::Extract)?;

    Ok(CliArgs {
        base,
        work,
        task_class,
        out,
        report,
    })
}

fn run() -> Result<(), CliError> {
    let args = parse_cli(env::args_os())?;
    let caps = Caps::default();

    let out_file =
        File::create(&args.out).map_err(|e| CliError::OutputIo("output stream file", e.kind()))?;
    let out_writer = BufWriter::new(out_file);

    let report_data = extract(&args.base, &args.work, &args.task_class, &caps, out_writer)
        .map_err(CliError::Extract)?;

    let mut json = serde_json::to_string_pretty(&report_data)
        .map_err(|_| CliError::OutputIo("report json", io::ErrorKind::InvalidData))?;
    json.push('\n');

    let mut report_file =
        File::create(&args.report).map_err(|e| CliError::OutputIo("report file", e.kind()))?;
    report_file
        .write_all(json.as_bytes())
        .map_err(|e| CliError::OutputIo("report file", e.kind()))?;
    report_file
        .flush()
        .map_err(|e| CliError::OutputIo("report file", e.kind()))?;

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::HelpRequested) => {
            println!("{}", USAGE);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {}", err);
            ExitCode::FAILURE
        }
    }
}
