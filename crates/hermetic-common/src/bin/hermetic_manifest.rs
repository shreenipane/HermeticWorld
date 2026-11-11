use hermetic_common::world_manifest::{
    digest_file, digest_tree, verify_inclusion, InclusionProof, ProofStep, WorldManifest,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn print_usage() {
    eprintln!(
        r#"Usage:
  hermetic-manifest root --manifest <FILE>
  hermetic-manifest verify --manifest <FILE> --expect <ROOT>
  hermetic-manifest prove --manifest <FILE> --path <PATH>
  hermetic-manifest check-proof --root <ROOT> --path <P> --value <V> --proof <FILE>
  hermetic-manifest digest-tree --dir <DIR>
  hermetic-manifest digest-file --file <FILE>
"#
    );
}

fn parse_args() -> (String, HashMap<String, String>) {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        process::exit(1);
    }

    let subcommand = args[0].clone();
    if subcommand == "--help" || subcommand == "-h" || subcommand == "help" {
        print_usage();
        process::exit(0);
    }

    let mut options = HashMap::new();
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if let Some(stripped) = arg.strip_prefix("--") {
            if let Some((key, val)) = stripped.split_once('=') {
                options.insert(key.to_string(), val.to_string());
                i += 1;
            } else if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                options.insert(stripped.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                options.insert(stripped.to_string(), String::new());
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    (subcommand, options)
}

fn get_required_opt<'a>(options: &'a HashMap<String, String>, key: &str) -> &'a str {
    match options.get(key) {
        Some(val) if !val.is_empty() => val.as_str(),
        _ => {
            eprintln!("Missing required option: --{key}");
            print_usage();
            process::exit(1);
        }
    }
}

fn main() {
    let (subcommand, options) = parse_args();

    match subcommand.as_str() {
        "root" => {
            let manifest_path = get_required_opt(&options, "manifest");
            let manifest = match WorldManifest::load(Path::new(manifest_path)) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error loading manifest: {e}");
                    process::exit(1);
                }
            };
            match manifest.world_root() {
                Ok(root) => {
                    println!("{root}");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Error computing world root: {e}");
                    process::exit(1);
                }
            }
        }
        "verify" => {
            let manifest_path = get_required_opt(&options, "manifest");
            let expect_root = get_required_opt(&options, "expect");
            let manifest = match WorldManifest::load(Path::new(manifest_path)) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error loading manifest: {e}");
                    process::exit(1);
                }
            };
            match manifest.world_root() {
                Ok(computed_root) => {
                    if computed_root.eq_ignore_ascii_case(expect_root) {
                        process::exit(0);
                    } else {
                        println!("{computed_root}");
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error computing world root: {e}");
                    process::exit(1);
                }
            }
        }
        "prove" => {
            let manifest_path = get_required_opt(&options, "manifest");
            let path_val = get_required_opt(&options, "path");
            let manifest = match WorldManifest::load(Path::new(manifest_path)) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error loading manifest: {e}");
                    process::exit(1);
                }
            };
            match manifest.inclusion_proof(path_val) {
                Ok((value, proof)) => {
                    let out = InclusionProof {
                        path: path_val.to_string(),
                        value,
                        proof,
                    };
                    match serde_json::to_string_pretty(&out) {
                        Ok(json_str) => {
                            println!("{json_str}");
                            process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("Error formatting JSON proof: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error generating inclusion proof: {e}");
                    process::exit(1);
                }
            }
        }
        "check-proof" => {
            let root = get_required_opt(&options, "root");
            let path_val = get_required_opt(&options, "path");
            let value = get_required_opt(&options, "value");
            let proof_file = get_required_opt(&options, "proof");

            let proof_str = match fs::read_to_string(proof_file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error reading proof file '{proof_file}': {e}");
                    process::exit(1);
                }
            };

            let proof_steps = match serde_json::from_str::<InclusionProof>(&proof_str) {
                Ok(ip) => ip.proof,
                Err(_) => match serde_json::from_str::<Vec<ProofStep>>(&proof_str) {
                    Ok(steps) => steps,
                    Err(e) => {
                        eprintln!("Error parsing proof JSON: {e}");
                        process::exit(1);
                    }
                },
            };

            match verify_inclusion(root, path_val, value, &proof_steps) {
                Ok(true) => {
                    process::exit(0);
                }
                Ok(false) => {
                    eprintln!("Inclusion verification failed: root mismatch");
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!("Inclusion verification error: {e}");
                    process::exit(1);
                }
            }
        }
        "digest-tree" => {
            let dir = get_required_opt(&options, "dir");
            match digest_tree(Path::new(dir)) {
                Ok(digest) => {
                    println!("{digest}");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Error digesting tree '{dir}': {e}");
                    process::exit(1);
                }
            }
        }
        "digest-file" => {
            let file = get_required_opt(&options, "file");
            match digest_file(Path::new(file)) {
                Ok(digest) => {
                    println!("{digest}");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Error digesting file '{file}': {e}");
                    process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown subcommand: '{other}'");
            print_usage();
            process::exit(1);
        }
    }
}
