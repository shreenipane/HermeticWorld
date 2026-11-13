#![forbid(unsafe_code)]

use hermetic_extract_walk::{diff_trees, Caps, TaskClass};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// Hard upper bound on command-line arguments accepted by the CLI binary.
const MAX_CLI_ARGS: usize = 256;

enum CliAction {
    Run {
        base: PathBuf,
        work: PathBuf,
        class: TaskClass,
        caps: Caps,
    },
    Help,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            let _ = writeln!(io::stderr(), "error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<OsString> = std::env::args_os().skip(1).take(MAX_CLI_ARGS + 1).collect();
    if args.len() > MAX_CLI_ARGS {
        return Err(format!("too many CLI arguments (max {MAX_CLI_ARGS})"));
    }

    let action = parse_args(&args)?;
    let (base, work, class, caps) = match action {
        CliAction::Help => {
            print_usage()?;
            return Ok(ExitCode::from(0));
        }
        CliAction::Run {
            base,
            work,
            class,
            caps,
        } => (base, work, class, caps),
    };

    let change_set = diff_trees(&base, &work, class, &caps).map_err(|e| e.to_string())?;
    let json = change_set.to_canonical_json().map_err(|e| e.to_string())?;

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(json.as_bytes())
        .map_err(|e| format!("failed to write output: {}", e.kind()))?;
    stdout
        .write_all(b"\n")
        .map_err(|e| format!("failed to write newline: {}", e.kind()))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush stdout: {}", e.kind()))?;

    if change_set.refused.is_empty() {
        Ok(ExitCode::from(0))
    } else {
        Ok(ExitCode::from(2))
    }
}

fn parse_args(args: &[OsString]) -> Result<CliAction, String> {
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut patch_dir: Option<PathBuf> = None;
    let mut artifact_paths: Vec<PathBuf> = Vec::new();
    let mut is_state = false;
    let mut caps = Caps::default();

    let mut idx: usize = 0;
    while idx < args.len() && idx < MAX_CLI_ARGS {
        let Some(arg) = args.get(idx) else {
            break;
        };

        match arg.to_str() {
            Some("-h") | Some("--help") => return Ok(CliAction::Help),
            Some("--state") => {
                is_state = true;
            }
            Some("--patch") | Some("--repo-dir") => {
                idx = idx.saturating_add(1);
                let val = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --patch".to_string())?;
                patch_dir = Some(PathBuf::from(val));
            }
            Some("--artifact") => {
                idx = idx.saturating_add(1);
                let val = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --artifact".to_string())?;
                artifact_paths.push(PathBuf::from(val));
            }
            Some("--max-entries") => {
                idx = idx.saturating_add(1);
                caps.max_entries_walked = parse_usize_flag(args.get(idx), "--max-entries")?;
            }
            Some("--max-depth") => {
                idx = idx.saturating_add(1);
                caps.max_depth = parse_usize_flag(args.get(idx), "--max-depth")?;
            }
            Some("--max-file-size") => {
                idx = idx.saturating_add(1);
                caps.max_file_size = parse_u64_flag(args.get(idx), "--max-file-size")?;
            }
            Some("--max-total-bytes") => {
                idx = idx.saturating_add(1);
                caps.max_total_bytes_hashed = parse_u64_flag(args.get(idx), "--max-total-bytes")?;
            }
            Some("--max-path-length") => {
                idx = idx.saturating_add(1);
                caps.max_path_length = parse_usize_flag(args.get(idx), "--max-path-length")?;
            }
            Some(flag) if flag.starts_with('-') => {
                return Err(format!("unknown option '{flag}'"));
            }
            _ => {
                positional.push(PathBuf::from(arg));
            }
        }

        idx = idx.saturating_add(1);
    }

    let mode_count = usize::from(is_state)
        .saturating_add(usize::from(patch_dir.is_some()))
        .saturating_add(usize::from(!artifact_paths.is_empty()));
    if mode_count > 1 {
        return Err("specify at most one of --patch, --artifact, or --state".to_string());
    }

    if positional.len() != 2 {
        return Err(
            "expected exactly two positional paths: <BASE_DIR> <WORK_DIR> (see --help)".to_string(),
        );
    }

    let base = positional
        .first()
        .cloned()
        .ok_or_else(|| "missing <BASE_DIR>".to_string())?;
    let work = positional
        .get(1)
        .cloned()
        .ok_or_else(|| "missing <WORK_DIR>".to_string())?;

    let class = if is_state {
        TaskClass::State
    } else if let Some(repo_dir) = patch_dir {
        TaskClass::Patch { repo_dir }
    } else if !artifact_paths.is_empty() {
        TaskClass::Artifact {
            paths: artifact_paths,
        }
    } else {
        TaskClass::Patch {
            repo_dir: PathBuf::from("."),
        }
    };

    Ok(CliAction::Run {
        base,
        work,
        class,
        caps,
    })
}

fn parse_usize_flag(val: Option<&OsString>, flag: &str) -> Result<usize, String> {
    let raw = val
        .ok_or_else(|| format!("missing value for {flag}"))?
        .to_str()
        .ok_or_else(|| format!("invalid UTF-8 value for {flag}"))?;
    raw.parse::<usize>()
        .map_err(|_| format!("invalid integer for {flag}: '{raw}'"))
}

fn parse_u64_flag(val: Option<&OsString>, flag: &str) -> Result<u64, String> {
    let raw = val
        .ok_or_else(|| format!("missing value for {flag}"))?
        .to_str()
        .ok_or_else(|| format!("invalid UTF-8 value for {flag}"))?;
    raw.parse::<u64>()
        .map_err(|_| format!("invalid integer for {flag}: '{raw}'"))
}

fn print_usage() -> Result<(), String> {
    let usage = "\
Usage: hermetic-extract-walk [OPTIONS] <BASE_DIR> <WORK_DIR>

Options:
  --patch <REPO_DIR>         Extract changes only inside relative <REPO_DIR> (default: .)
  --artifact <REL_PATH>      Extract changes only for declared <REL_PATH> (repeatable)
  --state                    Extract nothing and emit an empty ChangeSet
  --max-entries <N>          Cap maximum entries walked
  --max-depth <N>            Cap maximum directory depth
  --max-file-size <N>        Cap maximum single file size in bytes
  --max-total-bytes <N>      Cap maximum total bytes hashed
  --max-path-length <N>      Cap maximum relative path length in bytes
  -h, --help                 Show this help message

Exit codes:
  0  Success, no refused entries
  1  Error (invalid arguments, I/O error, or resource cap exceeded)
  2  Success, one or more refused entries present in output
";
    io::stdout()
        .write_all(usage.as_bytes())
        .map_err(|e| format!("failed to write help: {}", e.kind()))
}
