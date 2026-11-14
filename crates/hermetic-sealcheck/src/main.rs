#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

use hermetic_common::TaskInput;
use hermetic_sealcheck::{
    check_d11, check_d12, coverage_gaps, generate_sarif, generate_sarif_with_options,
    generate_sarif_with_properties, load_undated_task, query_index, scan_problem_statement,
    scan_tree, write_index, BenchmarkSignatures, D11Options, D12Options, Finding, FingerprintSet,
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
    /// Check unified diff for test-infrastructure changes (D11 advisory)
    #[command(name = "d11")]
    D11(D11Args),
    /// Scan files for real-date, host-name, and host-path sentinels (D12 advisory)
    #[command(name = "d12")]
    D12(D12Args),
    /// Check an ext4 filesystem image for times later than T_clock (D4)
    #[command(name = "d4-image")]
    D4Image(D4ImageArgs),
}

#[derive(Parser, Debug)]
struct D4ImageArgs {
    /// Path to ext4 filesystem image
    #[arg(long)]
    image: PathBuf,

    /// Target clock time (RFC 3339 format)
    #[arg(long = "t-clock")]
    t_clock: String,

    /// Output format: json or sarif
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
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

    /// Baseline byte budget for subtraction
    #[arg(long)]
    baseline_budget: Option<usize>,
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

    /// Baseline byte budget for subtraction
    #[arg(long)]
    baseline_budget: Option<usize>,
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
        let mut fp = FingerprintSet::from_files_with_budget(
            &undated_task.files,
            &args.base_tree,
            args.baseline_budget,
        )?;
        fp.skipped_files_count += undated_task.skipped_files_count;

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

        all_findings.extend(fp.coverage_gap_findings(&args.task.display().to_string()));

        if fp.baseline_incomplete {
            all_findings.push(Finding {
                detector: "D2".into(),
                channel: "baseline_incomplete".into(),
                path: args.base_tree.display().to_string(),
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!(
                    "baseline incomplete: {} bytes not subtracted",
                    fp.baseline_skipped_bytes
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
            Some(&fp),
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

        let not_covered = coverage_gaps(&all_findings);

        write_report(
            all_findings,
            Some(&fp),
            task.instance_id,
            args.format,
            args.out,
            None,
            not_covered,
        )
    }
}

fn write_report(
    all_findings: Vec<Finding>,
    fp: Option<&FingerprintSet>,
    instance_id: String,
    format: OutputFormat,
    out: Option<PathBuf>,
    mode: Option<String>,
    not_covered: Vec<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let gate = all_findings
        .iter()
        .any(|f| f.severity == Severity::Gate && f.visibility == Visibility::AgentVisible);
    let incomplete = all_findings
        .iter()
        .any(|f| f.detector == "D4" && f.channel == "tree_incomplete");

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
            let summary = match fp {
                Some(fp) => FingerprintSummary {
                    lines: fp.lines_count,
                    windows: fp.windows_count,
                    removed_markers: fp.removed_markers_count,
                    diff_shapes: fp.diff_shapes_count,
                    subtracted: fp.subtracted_count,
                    winnow: fp.winnow_count,
                    winnow_subtracted: fp.winnow_subtracted_count,
                    binary_items: fp.binary_items_count,
                    binary_subtracted: fp.binary_subtracted_count,
                },
                None => FingerprintSummary {
                    lines: 0,
                    windows: 0,
                    removed_markers: 0,
                    diff_shapes: 0,
                    subtracted: 0,
                    winnow: 0,
                    winnow_subtracted: 0,
                    binary_items: 0,
                    binary_subtracted: 0,
                },
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
        hermetic_sealcheck::safe_fs::atomic_write(
            &out_path,
            format!("{}\n", output_str).as_bytes(),
        )?;
    } else {
        println!("{}", output_str);
    }

    if gate {
        Ok(ExitCode::from(2))
    } else if incomplete {
        Ok(ExitCode::FAILURE)
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
        let mut fp = FingerprintSet::from_files_with_budget(
            &undated_task.files,
            &args.base_tree,
            args.baseline_budget,
        )?;
        fp.skipped_files_count += undated_task.skipped_files_count;

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

        all_findings.extend(fp.coverage_gap_findings(&args.task.display().to_string()));

        if fp.baseline_incomplete {
            all_findings.push(Finding {
                detector: "D2".into(),
                channel: "baseline_incomplete".into(),
                path: args.base_tree.display().to_string(),
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!(
                    "baseline incomplete: {} bytes not subtracted",
                    fp.baseline_skipped_bytes
                )],
            });
        }

        let canonical_task_dir = args.task.canonicalize().ok();

        let mut not_covered_set: Vec<String> = NOT_COVERED.iter().map(|s| s.to_string()).collect();
        for d in UNDATED_NOT_COVERED {
            let s = d.to_string();
            if !not_covered_set.contains(&s) {
                not_covered_set.push(s);
            }
        }
        for (idx, index) in args.indexes.iter().enumerate() {
            let reader = hermetic_sealcheck::IndexReader::open(index)?;
            let v = reader.version();
            for item in hermetic_sealcheck::index::not_covered_for_version(v) {
                let s = item.to_string();
                if !not_covered_set.contains(&s) {
                    not_covered_set.push(s);
                }
            }

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

        write_report(
            all_findings,
            Some(&fp),
            undated_task.instance_id,
            args.format,
            args.out,
            Some("undated".to_string()),
            not_covered_set,
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

        let mut not_covered_set: Vec<String> = NOT_COVERED.iter().map(|s| s.to_string()).collect();
        for (idx, index) in args.indexes.iter().enumerate() {
            let reader = hermetic_sealcheck::IndexReader::open(index)?;
            let v = reader.version();
            for item in hermetic_sealcheck::index::not_covered_for_version(v) {
                let s = item.to_string();
                if !not_covered_set.contains(&s) {
                    not_covered_set.push(s);
                }
            }
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
            Some(&fp),
            task.instance_id,
            args.format,
            args.out,
            Some("query".to_string()),
            not_covered_set,
        )
    }
}

fn run_d4_image(args: D4ImageArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let t_clock = hermetic_common::cutoff::parse_utc_datetime(&args.t_clock)
        .map_err(|e| format!("invalid --t-clock: {e}"))?;
    let image_name = hermetic_sealcheck::ext4::image_display(&args.image);
    let findings = match hermetic_sealcheck::scan_ext4_image(&args.image, t_clock) {
        Ok(findings) => findings,
        Err(error) => {
            let finding = Finding {
                detector: "D4".into(),
                channel: "image_malformed".into(),
                path: image_name.clone(),
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![error.to_string()],
            };
            write_report(
                vec![finding],
                None,
                image_name,
                args.format,
                args.out,
                None,
                Vec::new(),
            )?;
            return Err(error.into());
        }
    };
    write_report(
        findings,
        None,
        image_name,
        args.format,
        args.out,
        None,
        Vec::new(),
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
    if !hermetic_sealcheck::safe_fs::is_dir(&args.root) {
        return Err("--root does not exist or is not a directory".into());
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
        hermetic_sealcheck::safe_fs::atomic_write(
            &out_path,
            format!("{}\n", output_str).as_bytes(),
        )?;
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
    let opts = D11Options {
        benchmark_test_files: args.benchmark_test_file,
        installed_packages: args.installed_package,
    };
    opts.validate()?;
    let patch_bytes = hermetic_sealcheck::safe_fs::read(
        &args.patch,
        hermetic_sealcheck::d11::MAX_PATCH_BYTES as u64,
    )?;
    let patch_text = String::from_utf8(patch_bytes).map_err(|_| "patch is not UTF-8")?;
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
    opts.validate()?;

    let mut findings = Vec::new();
    let mut total_bytes = 0u64;
    let mut entries = 0usize;
    let mut incomplete = false;
    for target in &args.path {
        for entry in hermetic_sealcheck::safe_fs::walk(target, |_| true) {
            entries = entries.saturating_add(1);
            if entries > hermetic_sealcheck::safe_fs::MAX_TREE_ENTRIES {
                return Err("D12 tree entry cap exceeded".into());
            }
            let path = entry.map_err(|_| "D12 directory unreadable or traversal cap exceeded")?;
            let meta = hermetic_sealcheck::safe_fs::metadata(&path)?;
            let display = if meta.is_dir() || path != *target {
                path.strip_prefix(target)
                    .unwrap_or(&path)
                    .display()
                    .to_string()
            } else {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            };
            if meta.file_type().is_symlink() {
                findings.push(Finding {
                    detector: "D12".into(),
                    channel: "skipped_symlink".into(),
                    path: display,
                    visibility: Visibility::AgentVisible,
                    severity: Severity::Info,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec!["symlink not followed".into()],
                });
            } else if meta.is_file() {
                let cap = hermetic_sealcheck::d12::MAX_TEXT_BYTES as u64;
                let remaining =
                    hermetic_sealcheck::safe_fs::MAX_TREE_BYTES.saturating_sub(total_bytes);
                match hermetic_sealcheck::safe_fs::read_counted(
                    &path,
                    cap.min(remaining),
                    &mut total_bytes,
                ) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        findings.extend(check_d12(&display, &text, &opts));
                    }
                    Err(_) => {
                        incomplete = true;
                        findings.push(Finding {
                            detector: "D12".into(),
                            channel: "read_error".into(),
                            path: display,
                            visibility: Visibility::AgentVisible,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec!["file refused or byte cap exceeded".into()],
                        });
                    }
                }
            } else if !meta.is_dir() {
                incomplete = true;
            }
        }
    }
    write_advisory_report(findings, "d12", args.format, args.out)?;
    Ok(if incomplete {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
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
        hermetic_sealcheck::safe_fs::atomic_write(
            &out_path,
            format!("{}\n", output_str).as_bytes(),
        )?;
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
        Commands::D4Image(args) => run_d4_image(args),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hermetic-sealcheck error: {}", e);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod detector_coverage_tests {
    use super::*;
    #[test]
    fn incomplete_d4_coverage_exits_one() {
        let directory = tempfile::tempdir().unwrap();
        let finding = Finding {
            detector: "D4".into(),
            channel: "tree_incomplete".into(),
            path: ".".into(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Info,
            confidence: 0.0,
            hunk: None,
            evidence: vec!["tree cap exceeded".into()],
        };
        let exit = write_report(
            vec![finding],
            None,
            String::new(),
            OutputFormat::Json,
            Some(directory.path().join("report.json")),
            None,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(exit, ExitCode::FAILURE);
    }
}
