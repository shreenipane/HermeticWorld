#![forbid(unsafe_code)]

use std::fs::File;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::validator::validate_stream;

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!(
        "Usage: hermetic-extract-validate --stream FILE --base DIR --out DIR --class patch|artifact|state --config FILE"
    );
    process::exit(code);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut stream_path: Option<PathBuf> = None;
    let mut base_path: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut class_opt: Option<TaskClass> = None;
    let mut config_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--stream" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing value for --stream");
                    process::exit(1);
                }
                stream_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--base" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing value for --base");
                    process::exit(1);
                }
                base_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--out" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing value for --out");
                    process::exit(1);
                }
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--class" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing value for --class");
                    process::exit(1);
                }
                match TaskClass::from_str(&args[i + 1]) {
                    Ok(c) => class_opt = Some(c),
                    Err(e) => {
                        eprintln!("{e}");
                        process::exit(1);
                    }
                }
                i += 2;
            }
            "--config" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing value for --config");
                    process::exit(1);
                }
                config_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                print_usage_and_exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                process::exit(1);
            }
        }
    }

    let stream_file = match stream_path {
        Some(p) => p,
        None => {
            eprintln!("--stream is required");
            process::exit(1);
        }
    };
    let base_dir = match base_path {
        Some(p) => p,
        None => {
            eprintln!("--base is required");
            process::exit(1);
        }
    };
    let out_dir = match out_path {
        Some(p) => p,
        None => {
            eprintln!("--out is required");
            process::exit(1);
        }
    };
    let class = match class_opt {
        Some(c) => c,
        None => {
            eprintln!("--class is required (patch, artifact, or state)");
            process::exit(1);
        }
    };
    let config_file = match config_path {
        Some(p) => p,
        None => {
            eprintln!("--config is required");
            process::exit(1);
        }
    };

    let config = match ExtractConfig::load_from_file(&config_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            process::exit(1);
        }
    };

    // Verify stream file is a regular file
    let meta = match std::fs::symlink_metadata(&stream_file) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Cannot stat stream file '{}': {e}", stream_file.display());
            process::exit(1);
        }
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        eprintln!(
            "Stream file '{}' must be a regular file",
            stream_file.display()
        );
        process::exit(1);
    }

    let mut stream = match File::open(&stream_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open stream file '{}': {e}", stream_file.display());
            process::exit(1);
        }
    };

    match validate_stream(&mut stream, &base_dir, &out_dir, class, &config) {
        Ok(report) => {
            let json = match serde_json::to_string_pretty(&report) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Failed to serialize report JSON: {e}");
                    process::exit(1);
                }
            };
            println!("{json}");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Validation failed: {e}");
            if e.is_rejection() {
                process::exit(2);
            } else {
                process::exit(1);
            }
        }
    }
}
