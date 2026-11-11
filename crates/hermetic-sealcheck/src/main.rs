#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use hermetic_common::TaskInput;
use hermetic_sealcheck::{
    check_d11, check_d12, generate_sarif, generate_sarif_with_options,
    generate_sarif_with_properties, query_index, scan_problem_statement, scan_tree, write_index,
    BenchmarkSignatures, D11Options, D12Options, Finding, FingerprintSet, FingerprintSummary,
    SarifRunProperties, ScanOptions, SealcheckReport, Severity, Visibility, NOT_COVERED,
};
use walkdir::WalkDir;

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
    /// Check unified diff for test-infrastructure changes (D11 advisory)
    #[command(name = "d11")]
    D11(D11Args),
    /// Scan files for real-date, host-name, and host-path sentinels (D12 advisory)
    #[command(name = "d12")]
    D12(D12Args),
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
    )
}

fn write_report(
    all_findings: Vec<Finding>,
    fp: &FingerprintSet,
    instance_id: String,
    format: OutputFormat,
    out: Option<PathBuf>,
    query_mode: Option<&[&str]>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let gate = all_findings
        .iter()
        .any(|f| f.severity == Severity::Gate && f.visibility == Visibility::AgentVisible);

    let output_str = match format {
        OutputFormat::Sarif => {
            let sarif = match query_mode {
                Some(not_covered) => generate_sarif_with_properties(
                    &all_findings,
                    Some(SarifRunProperties {
                        mode: "query".to_string(),
                        not_covered: not_covered.iter().map(|s| s.to_string()).collect(),
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
                mode: query_mode.map(|_| "query".to_string()),
                not_covered: query_mode
                    .unwrap_or(&[])
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
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
        Some(NOT_COVERED),
    )
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

#[derive(Parser, Debug)]
struct D11Args {
    /// Path to patch file
    #[arg(long)]
    patch: PathBuf,

    /// Benchmark test file (repeatable)
    #[arg(long = "benchmark-test-file")]
    benchmark_test_file: Vec<String>,

    /// Installed package name (repeatable)
    #[arg(long = "installed-package")]
    installed_package: Vec<String>,

    /// Output format: json or sarif
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct D12Args {
    /// File or directory to scan (repeatable)
    #[arg(long = "path", required = true, num_args = 1..)]
    path: Vec<PathBuf>,

    /// Real date (YYYY-MM-DD) against which to compare
    #[arg(long = "real-date")]
    real_date: Option<String>,

    /// Tolerance window in days (default 1)
    #[arg(long = "tolerance-days", default_value_t = 1)]
    tolerance_days: u32,

    /// Host name to search for (repeatable)
    #[arg(long = "host-name")]
    host_name: Vec<String>,

    /// Host path to search for (repeatable)
    #[arg(long = "host-path")]
    host_path: Vec<String>,

    /// Output format: json or sarif
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

fn parse_iso_date(s: &str) -> Result<time::Date, String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(format!("expected YYYY-MM-DD, got {s}"));
    }
    let year = parts[0].parse::<i32>().map_err(|e| e.to_string())?;
    let month = parts[1].parse::<u8>().map_err(|e| e.to_string())?;
    let day = parts[2].parse::<u8>().map_err(|e| e.to_string())?;
    let m = time::Month::try_from(month).map_err(|_| format!("invalid month {month}"))?;
    time::Date::from_calendar_date(year, m, day).map_err(|_| format!("invalid calendar date {s}"))
}

fn run_d11(args: D11Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let patch_text = fs::read_to_string(&args.patch)?;
    let opts = D11Options {
        benchmark_test_files: args.benchmark_test_file,
        installed_packages: args.installed_package,
    };
    let findings = check_d11(&patch_text, &opts);
    write_advisory_report(findings, "d11", args.format, args.out)?;
    Ok(ExitCode::SUCCESS)
}

fn run_d12(args: D12Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let real_date = match args.real_date {
        Some(ref s) => parse_iso_date(s).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?,
        None => time::OffsetDateTime::now_utc().date(),
    };

    let opts = D12Options {
        real_date,
        tolerance_days: args.tolerance_days,
        host_names: args.host_name,
        host_paths: args.host_path,
    };

    let mut findings = Vec::new();
    const MAX_SIZE: u64 = 64 * 1024 * 1024;

    for target in &args.path {
        let sym_meta = match fs::symlink_metadata(target) {
            Ok(m) => m,
            Err(_) => {
                return Err(format!("path does not exist: {}", target.display()).into());
            }
        };

        if sym_meta.file_type().is_symlink() {
            findings.push(Finding {
                detector: "D12".to_string(),
                channel: "skipped_symlink".to_string(),
                path: target.display().to_string(),
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 1.0,
                hunk: None,
                evidence: vec!["symlink not followed".to_string()],
            });
            continue;
        }

        if target.is_file() {
            let meta = fs::metadata(target)?;
            if meta.len() > MAX_SIZE {
                findings.push(Finding {
                    detector: "D12".to_string(),
                    channel: "oversize_file".to_string(),
                    path: target.display().to_string(),
                    visibility: Visibility::AgentVisible,
                    severity: Severity::Info,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![format!("file over 64 MiB skipped: {} bytes", meta.len())],
                });
            } else {
                let bytes = fs::read(target)?;
                let text = String::from_utf8_lossy(&bytes);
                let f = check_d12(&target.display().to_string(), &text, &opts);
                findings.extend(f);
            }
        } else if target.is_dir() {
            for entry in WalkDir::new(target) {
                let entry = entry?;
                if entry.file_type().is_symlink() {
                    findings.push(Finding {
                        detector: "D12".to_string(),
                        channel: "skipped_symlink".to_string(),
                        path: entry.path().display().to_string(),
                        visibility: Visibility::AgentVisible,
                        severity: Severity::Info,
                        confidence: 1.0,
                        hunk: None,
                        evidence: vec!["symlink not followed".to_string()],
                    });
                } else if entry.file_type().is_file() {
                    let p = entry.path();
                    let meta = entry.metadata()?;
                    if meta.len() > MAX_SIZE {
                        findings.push(Finding {
                            detector: "D12".to_string(),
                            channel: "oversize_file".to_string(),
                            path: p.display().to_string(),
                            visibility: Visibility::AgentVisible,
                            severity: Severity::Info,
                            confidence: 1.0,
                            hunk: None,
                            evidence: vec![format!(
                                "file over 64 MiB skipped: {} bytes",
                                meta.len()
                            )],
                        });
                    } else {
                        let bytes = fs::read(p)?;
                        let text = String::from_utf8_lossy(&bytes);
                        let f = check_d12(&p.display().to_string(), &text, &opts);
                        findings.extend(f);
                    }
                }
            }
        }
    }

    write_advisory_report(findings, "d12", args.format, args.out)?;
    Ok(ExitCode::SUCCESS)
}

fn write_advisory_report(
    all_findings: Vec<Finding>,
    mode: &str,
    format: OutputFormat,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_str = match format {
        OutputFormat::Sarif => {
            let sarif = generate_sarif_with_options(
                &all_findings,
                Some(SarifRunProperties {
                    mode: mode.to_string(),
                    not_covered: Vec::new(),
                }),
                true,
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
                findings: all_findings,
                gate: false,
                mode: Some(mode.to_string()),
                not_covered: Vec::new(),
            };
            serde_json::to_string_pretty(&report)?
        }
    };

    if let Some(out_path) = out {
        fs::write(out_path, format!("{}\n", output_str))?;
    } else {
        println!("{}", output_str);
    }

    Ok(())
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
        Commands::D11(args) => run_d11(args),
        Commands::D12(args) => run_d12(args),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hermetic-sealcheck error: {}", e);
            ExitCode::from(1)
        }
    }
}
