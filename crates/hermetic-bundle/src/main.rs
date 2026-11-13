#![forbid(unsafe_code)]

use hermetic_bundle::{seal, verify, Verdict};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const MAX_CLI_ARGS: usize = 8;
const MAX_CLI_ARG_BYTES: usize = 8_192;

enum Command {
    Seal {
        dir: OsString,
    },
    Verify {
        dir: OsString,
        expected_root: Option<String>,
    },
}

fn parse_args() -> Result<Command, &'static str> {
    let mut raw_args: Vec<OsString> = Vec::new();
    for arg in std::env::args_os().skip(1) {
        if raw_args.len() >= MAX_CLI_ARGS {
            return Err("too many CLI arguments");
        }
        if arg.len() > MAX_CLI_ARG_BYTES {
            return Err("CLI argument exceeds maximum length");
        }
        raw_args.push(arg);
    }

    let subcommand = raw_args
        .first()
        .and_then(|s| s.to_str())
        .ok_or("usage: hermetic-bundle <seal|verify> ...")?;

    match subcommand {
        "seal" => {
            if raw_args.len() != 2 {
                return Err("usage: hermetic-bundle seal DIR");
            }
            let dir = raw_args
                .get(1)
                .cloned()
                .ok_or("usage: hermetic-bundle seal DIR")?;
            Ok(Command::Seal { dir })
        }
        "verify" | "verify-bundle" => {
            let mut dir: Option<OsString> = None;
            let mut expected_root: Option<String> = None;
            let mut idx: usize = 1;

            while idx < raw_args.len() {
                let current = raw_args.get(idx).ok_or("invalid arguments for verify")?;
                if let Some(s) = current.to_str() {
                    if s == "--root" {
                        if expected_root.is_some() {
                            return Err("duplicate --root option");
                        }
                        idx = idx.saturating_add(1);
                        let val = raw_args
                            .get(idx)
                            .and_then(|v| v.to_str())
                            .ok_or("--root requires a UTF-8 sha256:HEX argument")?;
                        expected_root = Some(val.to_string());
                        idx = idx.saturating_add(1);
                        continue;
                    }
                    if let Some(val) = s.strip_prefix("--root=") {
                        if expected_root.is_some() {
                            return Err("duplicate --root option");
                        }
                        expected_root = Some(val.to_string());
                        idx = idx.saturating_add(1);
                        continue;
                    }
                    if s.starts_with('-') {
                        return Err("unknown option for verify");
                    }
                }

                if dir.is_some() {
                    return Err("usage: hermetic-bundle verify DIR [--root sha256:HEX]");
                }
                dir = Some(current.clone());
                idx = idx.saturating_add(1);
            }

            let target_dir = dir.ok_or("usage: hermetic-bundle verify DIR [--root sha256:HEX]")?;
            Ok(Command::Verify {
                dir: target_dir,
                expected_root,
            })
        }
        _ => Err("usage: hermetic-bundle <seal|verify> ..."),
    }
}

fn main() -> ExitCode {
    let cmd = match parse_args() {
        Ok(c) => c,
        Err(msg) => {
            let _ = writeln!(io::stderr().lock(), "error: {msg}");
            return ExitCode::from(1);
        }
    };

    match cmd {
        Command::Seal { dir } => match seal(Path::new(&dir)) {
            Ok(manifest) => match write_root(&mut io::stdout().lock(), &manifest.root) {
                Ok(()) => ExitCode::from(0),
                Err(_) => ExitCode::from(1),
            },
            Err(err) => {
                let _ = writeln!(io::stderr().lock(), "error: {err}");
                ExitCode::from(1)
            }
        },
        Command::Verify { dir, expected_root } => {
            match verify(Path::new(&dir), expected_root.as_deref()) {
                Ok(report) => {
                    let mut stdout = io::stdout().lock();
                    if serde_json::to_writer_pretty(&mut stdout, &report).is_err()
                        || stdout.write_all(b"\n").is_err()
                    {
                        return ExitCode::from(1);
                    }
                    match report.verdict {
                        Verdict::Ok => ExitCode::from(0),
                        Verdict::Mismatch => ExitCode::from(2),
                    }
                }
                Err(err) => {
                    let _ = writeln!(io::stderr().lock(), "error: {err}");
                    ExitCode::from(1)
                }
            }
        }
    }
}

fn write_root(output: &mut impl Write, root: &str) -> io::Result<()> {
    writeln!(output, "{root}")
}
