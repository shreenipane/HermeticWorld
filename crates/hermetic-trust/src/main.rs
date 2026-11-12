#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use hermetic_trust::{
    atomic_write_file, check_not_alias, install_ca, mint_ca, read_cert_file_bounded,
    read_seed_file, validate_output_path, write_private_key_file, TrustError,
};

#[derive(Parser, Debug)]
#[command(
    name = "hermetic-trust",
    about = "Deterministic CA minting and rootfs trust injection"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Mint per-world deterministic CA certificate and private key
    MintCa {
        #[arg(long)]
        world_id: String,

        #[arg(long)]
        t_clock: String,

        #[arg(long)]
        ca_seed_file: PathBuf,

        #[arg(long)]
        cert_out: PathBuf,

        #[arg(long)]
        key_out: PathBuf,
    },

    /// Install CA certificate into every trust store in a rootfs
    Install {
        #[arg(long)]
        rootfs: PathBuf,

        #[arg(long)]
        ca_cert: PathBuf,

        #[arg(long)]
        report: Option<PathBuf>,
    },
}

fn run() -> Result<(), TrustError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::MintCa {
            world_id,
            t_clock,
            ca_seed_file,
            cert_out,
            key_out,
        } => {
            // Validate output paths and alias collisions before mutation
            check_not_alias(&cert_out, &key_out, "cert_out", "key_out")?;
            check_not_alias(&cert_out, &ca_seed_file, "cert_out", "ca_seed_file")?;
            check_not_alias(&key_out, &ca_seed_file, "key_out", "ca_seed_file")?;

            validate_output_path(&cert_out)?;
            validate_output_path(&key_out)?;

            let parsed_time = OffsetDateTime::parse(&t_clock, &Rfc3339).map_err(|e| {
                TrustError::Time(format!("invalid RFC3339 date '{}': {}", t_clock, e))
            })?;

            let seed = read_seed_file(&ca_seed_file)?;
            let ca = mint_ca(&world_id, parsed_time, &seed)?;

            atomic_write_file(&cert_out, ca.cert_pem.as_bytes(), Some(0o644))?;
            write_private_key_file(&key_out, &ca.key_pem)?;
        }

        Commands::Install {
            rootfs,
            ca_cert,
            report,
        } => {
            if let Some(ref report_path) = report {
                check_not_alias(report_path, &ca_cert, "report", "ca_cert")?;
                validate_output_path(report_path)?;
            }

            let ca_pem = read_cert_file_bounded(&ca_cert)?;
            let install_report = install_ca(&rootfs, &ca_pem)?;

            let report_json = serde_json::to_string_pretty(&install_report)?;
            if let Some(ref report_path) = report {
                atomic_write_file(report_path, report_json.as_bytes(), Some(0o644))?;
            } else {
                println!("{}", report_json);
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
