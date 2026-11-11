#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use hermetic_common::TaskInput;
use hermetic_sealcheck::{
    generate_sarif, scan_problem_statement, scan_tree, BenchmarkSignatures, FingerprintSet,
    FingerprintSummary, ScanOptions, SealcheckReport, Severity, Visibility,
};

#[derive(Parser, Debug)]
#[command(
    name = "hermetic-sealcheck",
    version,
    about = "Hermetic World sealcheck: verify that nothing post-cutoff is reachable"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan directories and problem statement for post-cutoff leaks
    Scan(ScanArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
enum OutputFormat {
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
enum CliVisibility {
    AgentVisible,
    ImageOnly,
}

impl From<CliVisibility> for Visibility {
    fn from(v: CliVisibility) -> Self {
        match v {
            CliVisibility::AgentVisible => Visibility::AgentVisible,
            CliVisibility::ImageOnly => Visibility::ImageOnly,
        }
    }
}

#[derive(Parser, Debug)]
struct ScanArgs {
    /// Path to task directory containing task.json, staging/, agent/ (paths under --task are never scanned)
    #[arg(long)]
    task: PathBuf,

    /// Path to base tree root
    #[arg(long)]
    base_tree: PathBuf,

    /// Root directory to scan (repeatable)
    #[arg(long = "root", required = true)]
    roots: Vec<PathBuf>,

    /// Visibility for root (repeatable)
    #[arg(long = "root-visibility")]
    root_visibilities: Vec<CliVisibility>,

    /// Path to optional external signatures JSON file
    #[arg(long)]
    signatures: Option<PathBuf>,

    /// Output format: json or sarif
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,

    /// Path to docker inspect JSON array file
    #[arg(long)]
    oci_inspect: Option<PathBuf>,

    /// Path to docker history JSON lines file
    #[arg(long)]
    oci_history: Option<PathBuf>,
}

fn run_scan(args: ScanArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // Either no --root-visibility (every root is agent-visible) or exactly one per --root.
    if !args.root_visibilities.is_empty() && args.root_visibilities.len() != args.roots.len() {
        return Err(format!(
            "got {} --root-visibility values for {} --root values; give one per root or none",
            args.root_visibilities.len(),
            args.roots.len()
        )
        .into());
    }

    let task = TaskInput::load(&args.task)?;
    let fp = FingerprintSet::from_task(&task.gold_patch, &task.test_patch, &args.base_tree)?;

    let signatures = if let Some(ref sig_file) = args.signatures {
        BenchmarkSignatures::load_from_file(Some(task.instance_id.clone()), sig_file)?
    } else {
        BenchmarkSignatures::new(Some(task.instance_id.clone()))
    };

    let d0_opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        signatures: signatures.clone(),
        ..Default::default()
    };
    let mut all_findings = scan_problem_statement(&task.problem_statement, &fp, &d0_opts);

    let canonical_task_dir = args.task.canonicalize().ok();

    for (idx, root) in args.roots.iter().enumerate() {
        let vis = args
            .root_visibilities
            .get(idx)
            .copied()
            .unwrap_or(CliVisibility::AgentVisible);

        // Paths under the sealcheck's own --task dir are never scanned, wherever the root is
        let opts = ScanOptions {
            visibility: vis.into(),
            signatures: signatures.clone(),
            exclude_dirs: canonical_task_dir.iter().cloned().collect(),
            base_commit: Some(task.base_commit.clone()),
            t_clock: Some(task.cutoffs.t_clock),
            ..Default::default()
        };
        let tree_findings = scan_tree(root, &fp, &opts);
        all_findings.extend(tree_findings);
    }

    if args.oci_inspect.is_some() || args.oci_history.is_some() {
        let oci_opts = ScanOptions {
            visibility: Visibility::ImageOnly,
            signatures: signatures.clone(),
            t_clock: Some(task.cutoffs.t_clock),
            ..Default::default()
        };
        let oci_findings = hermetic_sealcheck::scan_oci(
            args.oci_inspect.as_deref(),
            args.oci_history.as_deref(),
            Some(task.cutoffs.t_clock),
            &fp,
            &signatures,
            &oci_opts,
        )?;
        all_findings.extend(oci_findings);
    }

    let gate = all_findings
        .iter()
        .any(|f| f.severity == Severity::Gate && f.visibility == Visibility::AgentVisible);

    let output_str = match args.format {
        OutputFormat::Sarif => {
            let sarif = generate_sarif(&all_findings);
            serde_json::to_string_pretty(&sarif)?
        }
        OutputFormat::Json => {
            let summary = FingerprintSummary {
                lines: fp.lines_count,
                windows: fp.windows_count,
                removed_markers: fp.removed_markers_count,
                diff_shapes: fp.diff_shapes_count,
                subtracted: fp.subtracted_count,
                winnow: fp.winnow_count,
                winnow_subtracted: fp.winnow_subtracted_count,
            };
            let report = SealcheckReport {
                schema: "hermetic-sealcheck/v0".to_string(),
                instance_id: task.instance_id,
                fingerprints: summary,
                findings: all_findings,
                gate,
            };
            serde_json::to_string_pretty(&report)?
        }
    };

    if let Some(out_path) = args.out {
        fs::write(out_path, format!("{}\n", output_str))?;
    } else {
        println!("{}", output_str);
    }

    if gate {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn main() -> ExitCode {
    // Exit code 2 means "agent-visible gate finding", so usage errors (clap's default
    // exit code 2) must exit 1 instead. --help and --version still exit 0.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { 1 } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    match cli.command {
        Commands::Scan(args) => match run_scan(args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("hermetic-sealcheck error: {}", e);
                ExitCode::from(1)
            }
        },
    }
}
