#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use hermetic_common::TaskInput;
use hermetic_sealcheck::{
    generate_sarif, generate_sarif_with_properties, load_undated_task, query_index,
    scan_problem_statement, scan_tree, write_index, BenchmarkSignatures, Finding, FingerprintSet,
    FingerprintSummary, SarifRunProperties, ScanOptions, SealcheckReport, Severity, Visibility,
    NOT_COVERED, UNDATED_NOT_COVERED,
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
    /// Index a tree once: record each unit's task-independent facts (TR-SC-10)
    Index(IndexArgs),
    /// Match one task against layer indexes instead of scanning the trees again
    Query(QueryArgs),
    /// Check coherence tells (D8) under a rootfs
    D8(D8Args),
}

#[derive(Parser, Debug)]
struct IndexArgs {
    /// Root directory to index
    #[arg(long)]
    root: PathBuf,

    /// Index file to write
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser, Debug)]
struct QueryArgs {
    /// Undated task mode (no gold patch; fingerprints from solution/ and tests/)
    #[arg(long)]
    undated: bool,

    /// Path to task directory containing task.json, staging/, agent/
    #[arg(long)]
    task: PathBuf,

    /// Path to base tree root
    #[arg(long)]
    base_tree: PathBuf,

    /// Index file to query (repeatable)
    #[arg(long = "index", required = true)]
    indexes: Vec<PathBuf>,

    /// Visibility for each index's root (repeatable, one per --index)
    #[arg(long = "root-visibility")]
    root_visibilities: Vec<CliVisibility>,

    /// Output format: json or sarif
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,

    /// Target package names for D5a target version check (repeatable)
    #[arg(long = "target-package")]
    target_package: Vec<String>,
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
    /// Undated task mode (no gold patch; fingerprints from solution/ and tests/)
    #[arg(long)]
    undated: bool,

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

    /// Target package names for D5a target version check (repeatable)
    #[arg(long = "target-package")]
    target_package: Vec<String>,
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

    if args.undated {
        let undated_task = load_undated_task(&args.task)?;
        let fp = FingerprintSet::from_files(&undated_task.files, &args.base_tree)?;

        let signatures = if let Some(ref sig_file) = args.signatures {
            BenchmarkSignatures::load_from_file(Some(undated_task.instance_id.clone()), sig_file)?
        } else {
            BenchmarkSignatures::new(Some(undated_task.instance_id.clone()))
        };

        let d0_opts = ScanOptions {
            visibility: Visibility::AgentVisible,
            signatures: signatures.clone(),
            undated: true,
            ..Default::default()
        };
        let mut all_findings = scan_problem_statement(&undated_task.instruction, &fp, &d0_opts);

        if fp.skipped_files_count > 0 {
            all_findings.push(Finding {
                detector: "D2".into(),
                channel: "task_file_skipped".into(),
                path: args.task.display().to_string(),
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!(
                    "skipped {} task files exceeding size limit",
                    fp.skipped_files_count
                )],
            });
        }

        let canonical_task_dir = args.task.canonicalize().ok();

        for (idx, root) in args.roots.iter().enumerate() {
            let vis = args
                .root_visibilities
                .get(idx)
                .copied()
                .unwrap_or(CliVisibility::AgentVisible);

            let opts = ScanOptions {
                visibility: vis.into(),
                signatures: signatures.clone(),
                exclude_dirs: canonical_task_dir.iter().cloned().collect(),
                undated: true,
                ..Default::default()
            };
            let tree_findings = scan_tree(root, &fp, &opts);
            all_findings.extend(tree_findings);
        }

        if args.oci_inspect.is_some() || args.oci_history.is_some() {
            let oci_opts = ScanOptions {
                visibility: Visibility::ImageOnly,
                signatures: signatures.clone(),
                undated: true,
                ..Default::default()
            };
            let oci_findings = hermetic_sealcheck::scan_oci(
                args.oci_inspect.as_deref(),
                args.oci_history.as_deref(),
                None,
                &fp,
                &signatures,
                &oci_opts,
            )?;
            all_findings.extend(oci_findings);
        }

        all_findings.retain(|f| !matches!(f.detector.as_str(), "D1" | "D3" | "D4" | "D5a"));

        write_report(
            all_findings,
            &fp,
            undated_task.instance_id,
            args.format,
            args.out,
            Some("undated".to_string()),
            UNDATED_NOT_COVERED.iter().map(|s| s.to_string()).collect(),
        )
    } else {
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

        let repo_pkg = task.repo.rsplit('/').next().unwrap_or(&task.repo);
        let mut target_packages = vec![repo_pkg.to_string()];
        target_packages.extend(args.target_package);

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
                target_packages: target_packages.clone(),
                task_version: task.version.clone(),
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

        write_report(
            all_findings,
            &fp,
            task.instance_id,
            args.format,
            args.out,
            None,
            Vec::new(),
        )
    }
}

fn write_report(
    all_findings: Vec<Finding>,
    fp: &FingerprintSet,
    instance_id: String,
    format: OutputFormat,
    out: Option<PathBuf>,
    mode: Option<String>,
    not_covered: Vec<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let gate = all_findings
        .iter()
        .any(|f| f.severity == Severity::Gate && f.visibility == Visibility::AgentVisible);

    let output_str = match format {
        OutputFormat::Sarif => {
            let sarif = match mode.as_ref() {
                Some(m) => generate_sarif_with_properties(
                    &all_findings,
                    Some(SarifRunProperties {
                        mode: m.clone(),
                        not_covered: not_covered.clone(),
                    }),
                ),
                None => generate_sarif(&all_findings),
            };
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
                binary_items: fp.binary_items_count,
                binary_subtracted: fp.binary_subtracted_count,
            };
            let report = SealcheckReport {
                schema: "hermetic-sealcheck/v0".to_string(),
                instance_id,
                fingerprints: summary,
                findings: all_findings,
                gate,
                mode,
                not_covered,
            };
            serde_json::to_string_pretty(&report)?
        }
    };

    if let Some(out_path) = out {
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

fn run_index(args: IndexArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let stats = write_index(&args.root, &args.out)?;
    eprintln!(
        "indexed {} files into {} records: {}",
        stats.files,
        stats.records,
        args.out.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn run_query(args: QueryArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !args.root_visibilities.is_empty() && args.root_visibilities.len() != args.indexes.len() {
        return Err(format!(
            "got {} --root-visibility values for {} --index values; give one per index or none",
            args.root_visibilities.len(),
            args.indexes.len()
        )
        .into());
    }

    if args.undated {
        let undated_task = load_undated_task(&args.task)?;
        let fp = FingerprintSet::from_files(&undated_task.files, &args.base_tree)?;

        let signatures = BenchmarkSignatures::new(Some(undated_task.instance_id.clone()));
        let d0_opts = ScanOptions {
            visibility: Visibility::AgentVisible,
            signatures,
            undated: true,
            ..Default::default()
        };
        let mut all_findings = scan_problem_statement(&undated_task.instruction, &fp, &d0_opts);

        if fp.skipped_files_count > 0 {
            all_findings.push(Finding {
                detector: "D2".into(),
                channel: "task_file_skipped".into(),
                path: args.task.display().to_string(),
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!(
                    "skipped {} task files exceeding size limit",
                    fp.skipped_files_count
                )],
            });
        }

        let canonical_task_dir = args.task.canonicalize().ok();

        for (idx, index) in args.indexes.iter().enumerate() {
            let vis = args
                .root_visibilities
                .get(idx)
                .copied()
                .unwrap_or(CliVisibility::AgentVisible);
            let opts = ScanOptions {
                visibility: vis.into(),
                exclude_dirs: canonical_task_dir.iter().cloned().collect(),
                undated: true,
                ..Default::default()
            };
            all_findings.extend(query_index(index, &fp, &opts)?);
        }

        all_findings.retain(|f| !matches!(f.detector.as_str(), "D1" | "D3" | "D4" | "D5a"));

        let mut not_covered = Vec::new();
        for d in NOT_COVERED {
            not_covered.push(d.to_string());
        }
        for d in UNDATED_NOT_COVERED {
            if !not_covered.iter().any(|c| c == d) {
                not_covered.push(d.to_string());
            }
        }

        write_report(
            all_findings,
            &fp,
            undated_task.instance_id,
            args.format,
            args.out,
            Some("undated".to_string()),
            not_covered,
        )
    } else {
        let task = TaskInput::load(&args.task)?;
        let fp = FingerprintSet::from_task(&task.gold_patch, &task.test_patch, &args.base_tree)?;

        // The instance id is not matched in the trees (D9:instance_id is not covered),
        // but D0 on the problem statement runs exactly as in `scan`.
        let signatures = BenchmarkSignatures::new(Some(task.instance_id.clone()));
        let d0_opts = ScanOptions {
            visibility: Visibility::AgentVisible,
            signatures,
            ..Default::default()
        };
        let mut all_findings = scan_problem_statement(&task.problem_statement, &fp, &d0_opts);

        let canonical_task_dir = args.task.canonicalize().ok();
        let repo_pkg = task.repo.rsplit('/').next().unwrap_or(&task.repo);
        let mut target_packages = vec![repo_pkg.to_string()];
        target_packages.extend(args.target_package);

        for (idx, index) in args.indexes.iter().enumerate() {
            let vis = args
                .root_visibilities
                .get(idx)
                .copied()
                .unwrap_or(CliVisibility::AgentVisible);
            let opts = ScanOptions {
                visibility: vis.into(),
                exclude_dirs: canonical_task_dir.iter().cloned().collect(),
                base_commit: Some(task.base_commit.clone()),
                t_clock: Some(task.cutoffs.t_clock),
                target_packages: target_packages.clone(),
                task_version: task.version.clone(),
                ..Default::default()
            };
            all_findings.extend(query_index(index, &fp, &opts)?);
        }

        write_report(
            all_findings,
            &fp,
            task.instance_id,
            args.format,
            args.out,
            Some("query".to_string()),
            NOT_COVERED.iter().map(|s| s.to_string()).collect(),
        )
    }
}

#[derive(Parser, Debug)]
struct D8Args {
    /// Root directory to inspect
    #[arg(long)]
    root: PathBuf,

    /// Clock cutoff in RFC 3339 format
    #[arg(long = "t-clock")]
    t_clock: String,

    /// Visibility for root
    #[arg(long = "root-visibility", default_value = "agent_visible")]
    root_visibility: CliVisibility,

    /// Output format: json or sarif
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

fn run_d8(args: D8Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !args.root.is_dir() {
        return Err(format!(
            "--root '{}' does not exist or is not a directory",
            args.root.display()
        )
        .into());
    }

    let t_clock = match time::OffsetDateTime::parse(
        &args.t_clock,
        &time::format_description::well_known::Rfc3339,
    ) {
        Ok(t) => t,
        Err(e) => {
            return Err(format!(
                "invalid --t-clock RFC3339 timestamp '{}': {}",
                args.t_clock, e
            )
            .into());
        }
    };

    let findings = hermetic_sealcheck::check_d8(&args.root, t_clock, args.root_visibility.into());

    let output_str = match args.format {
        OutputFormat::Sarif => {
            let sarif = generate_sarif_with_properties(
                &findings,
                Some(SarifRunProperties {
                    mode: "d8".to_string(),
                    not_covered: Vec::new(),
                }),
            );
            serde_json::to_string_pretty(&sarif)?
        }
        OutputFormat::Json => {
            let summary = FingerprintSummary {
                lines: 0,
                windows: 0,
                removed_markers: 0,
                diff_shapes: 0,
                subtracted: 0,
                winnow: 0,
                winnow_subtracted: 0,
                binary_items: 0,
                binary_subtracted: 0,
            };
            let report = SealcheckReport {
                schema: "hermetic-sealcheck/v0".to_string(),
                instance_id: String::new(),
                fingerprints: summary,
                findings,
                gate: false,
                mode: Some("d8".to_string()),
                not_covered: Vec::new(),
            };
            serde_json::to_string_pretty(&report)?
        }
    };

    if let Some(out_path) = args.out {
        fs::write(out_path, format!("{}\n", output_str))?;
    } else {
        println!("{}", output_str);
    }

    Ok(ExitCode::SUCCESS)
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
    let result = match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Index(args) => run_index(args),
        Commands::Query(args) => run_query(args),
        Commands::D8(args) => run_d8(args),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hermetic-sealcheck error: {}", e);
            ExitCode::from(1)
        }
    }
}
