use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::disk::{
    encode_result_disk, DiskError, FinalTestOutcome, ResultPayload, RunName, SupervisorExit,
    SupervisorSummary,
};
use crate::os::{ExitKind, Os, OsError, PipeRead, SpawnSpec, TreeStatus, MAX_PIPE_CHUNK_BYTES};
use crate::records::{
    DecodedRecord, RecordDecoder, RecordError, RecordOutcome, MAX_NODEID_BYTES,
    MAX_RECORDS_PER_STREAM,
};

/// Maximum run configuration JSON file size (1 MiB).
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Maximum number of arguments in `RunConfig::argv`.
pub const MAX_ARGV_ITEMS: usize = 256;

/// Maximum UTF-8 byte length of any single argument in `RunConfig::argv`.
pub const MAX_ARG_BYTES: usize = 32 * 1024;

/// Maximum number of environment variables in `RunConfig::env`.
pub const MAX_ENV_VARS: usize = 256;

/// Maximum UTF-8 byte length of any environment variable key or value.
pub const MAX_ENV_ENTRY_BYTES: usize = 32 * 1024;

/// Maximum UTF-8 byte length of `RunConfig::cwd`.
pub const MAX_CWD_BYTES: usize = 4096;

/// Maximum allowed grading deadline in seconds (24 hours).
pub const MAX_DEADLINE_SECONDS: u64 = 86_400;

/// Maximum number of expected test IDs in a single run configuration.
pub const MAX_EXPECTED_TESTS: usize = 10_000;

/// Hard upper bound on main supervisor loop iterations to guarantee bounded execution.
pub const MAX_SUPERVISOR_ITERATIONS: usize = 20_000_000;

/// Maximum drain iterations after child exit when flushing remaining pipe bytes.
pub const MAX_POST_EXIT_DRAIN_STEPS: usize = 1024;

/// Polling slice duration in milliseconds for deadline enforcement and tree-exit checks.
pub const POLL_SLICE_MS: u64 = 10;

/// Grace wait duration in seconds after sending SIGKILL to the process group.
pub const KILL_GRACE_SECONDS: u64 = 30;

/// Run configuration JSON loaded by the supervisor before launching tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    #[serde(alias = "test_argv")]
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    #[serde(default)]
    pub sandbox: crate::sandbox::SandboxSettings,
    #[serde(alias = "deadline_secs")]
    pub deadline_seconds: u64,
    #[serde(alias = "expected_tests")]
    pub expected_test_ids: Vec<String>,
    #[serde(alias = "run_name")]
    pub run: RunName,
    #[serde(alias = "variant_set_sha256")]
    pub variant_set: String,
}

/// Errors encountered while parsing or validating [`RunConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidJson(String),
    EmptyArgv,
    TooManyArgs {
        count: usize,
        max: usize,
    },
    ArgTooLong {
        index: usize,
        len: usize,
        max: usize,
    },
    TooManyEnvVars {
        count: usize,
        max: usize,
    },
    EnvEntryTooLong {
        key: String,
        len: usize,
        max: usize,
    },
    InvalidCwd(String),
    InvalidDeadline {
        seconds: u64,
        max: u64,
    },
    TooManyExpectedTests {
        count: usize,
        max: usize,
    },
    InvalidTestId(String),
    DuplicateTestId(String),
    InvalidVariantSetHash(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidJson(_) => write!(f, "invalid run config JSON"),
            ConfigError::EmptyArgv => write!(f, "config argv must not be empty"),
            ConfigError::TooManyArgs { count, max } => {
                write!(f, "config argv has {} items (max {})", count, max)
            }
            ConfigError::ArgTooLong { index, len, max } => {
                write!(
                    f,
                    "argv[{}] length {} exceeds max {} bytes",
                    index, len, max
                )
            }
            ConfigError::TooManyEnvVars { count, max } => {
                write!(f, "config env has {} entries (max {})", count, max)
            }
            ConfigError::EnvEntryTooLong { len, max, .. } => {
                write!(f, "env entry length {} exceeds max {} bytes", len, max)
            }
            ConfigError::InvalidCwd(msg) => write!(f, "invalid config cwd: {}", msg),
            ConfigError::InvalidDeadline { seconds, max } => {
                write!(
                    f,
                    "invalid deadline_seconds {} (must be 1..={})",
                    seconds, max
                )
            }
            ConfigError::TooManyExpectedTests { count, max } => {
                write!(f, "expected_test_ids count {} exceeds max {}", count, max)
            }
            ConfigError::InvalidTestId(msg) => write!(f, "invalid expected test id: {}", msg),
            ConfigError::DuplicateTestId(_) => write!(f, "duplicate expected test id in config"),
            ConfigError::InvalidVariantSetHash(msg) => {
                write!(f, "invalid variant_set sha256: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl RunConfig {
    /// Parses and strictly validates a JSON run configuration.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::InvalidJson(
                "configuration exceeds size cap".into(),
            ));
        }
        let mut cfg: RunConfig = serde_json::from_slice(bytes).map_err(|e| {
            ConfigError::InvalidJson(format!("schema error at {}:{}", e.line(), e.column()))
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates all bounds and invariants on `self`, normalizing `variant_set` to lowercase hex.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        if self.argv.is_empty() {
            return Err(ConfigError::EmptyArgv);
        }
        if self.argv.len() > MAX_ARGV_ITEMS {
            return Err(ConfigError::TooManyArgs {
                count: self.argv.len(),
                max: MAX_ARGV_ITEMS,
            });
        }
        for (idx, arg) in self.argv.iter().enumerate() {
            if idx == 0 && arg.is_empty() {
                return Err(ConfigError::ArgTooLong {
                    index: 0,
                    len: 0,
                    max: MAX_ARG_BYTES,
                });
            }
            if arg.len() > MAX_ARG_BYTES || arg.contains('\0') {
                return Err(ConfigError::ArgTooLong {
                    index: idx,
                    len: arg.len(),
                    max: MAX_ARG_BYTES,
                });
            }
        }

        if self.env.len() > MAX_ENV_VARS {
            return Err(ConfigError::TooManyEnvVars {
                count: self.env.len(),
                max: MAX_ENV_VARS,
            });
        }
        for (k, v) in &self.env {
            if k.is_empty() || k.contains('=') || k.contains('\0') {
                return Err(ConfigError::EnvEntryTooLong {
                    key: "redacted".into(),
                    len: k.len(),
                    max: MAX_ENV_ENTRY_BYTES,
                });
            }
            if k.len() > MAX_ENV_ENTRY_BYTES {
                return Err(ConfigError::EnvEntryTooLong {
                    key: "redacted".into(),
                    len: k.len(),
                    max: MAX_ENV_ENTRY_BYTES,
                });
            }
            if v.len() > MAX_ENV_ENTRY_BYTES || v.contains('\0') {
                return Err(ConfigError::EnvEntryTooLong {
                    key: "redacted".into(),
                    len: v.len(),
                    max: MAX_ENV_ENTRY_BYTES,
                });
            }
        }

        if self.cwd.is_empty() || self.cwd.len() > MAX_CWD_BYTES {
            return Err(ConfigError::InvalidCwd(format!(
                "cwd length {} must be 1..={}",
                self.cwd.len(),
                MAX_CWD_BYTES
            )));
        }

        if self.deadline_seconds == 0 || self.deadline_seconds > MAX_DEADLINE_SECONDS {
            return Err(ConfigError::InvalidDeadline {
                seconds: self.deadline_seconds,
                max: MAX_DEADLINE_SECONDS,
            });
        }

        if self.expected_test_ids.len() > MAX_EXPECTED_TESTS {
            return Err(ConfigError::TooManyExpectedTests {
                count: self.expected_test_ids.len(),
                max: MAX_EXPECTED_TESTS,
            });
        }
        let mut seen = BTreeSet::new();
        for id in &self.expected_test_ids {
            if id.is_empty() || id.len() > MAX_NODEID_BYTES {
                return Err(ConfigError::InvalidTestId(format!(
                    "test id length {} must be 1..={}",
                    id.len(),
                    MAX_NODEID_BYTES
                )));
            }
            if !seen.insert(id.clone()) {
                return Err(ConfigError::DuplicateTestId("redacted".into()));
            }
        }

        if self.variant_set.len() != 64 || !self.variant_set.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ConfigError::InvalidVariantSetHash(
                "variant_set must be exactly 64 ASCII hex digits".to_string(),
            ));
        }
        self.variant_set = self.variant_set.to_ascii_lowercase();

        Ok(())
    }
}

/// Top-level supervisor execution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    Os(OsError),
    Config(ConfigError),
    Disk(DiskError),
    TreeDidNotExitAfterKill,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupervisorError::Os(e) => write!(f, "OS error: {}", e),
            SupervisorError::Config(e) => write!(f, "config error: {}", e),
            SupervisorError::Disk(e) => write!(f, "result disk error: {}", e),
            SupervisorError::TreeDidNotExitAfterKill => {
                write!(
                    f,
                    "process tree did not terminate within post-kill grace period"
                )
            }
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<OsError> for SupervisorError {
    fn from(err: OsError) -> Self {
        SupervisorError::Os(err)
    }
}

impl From<ConfigError> for SupervisorError {
    fn from(err: ConfigError) -> Self {
        SupervisorError::Config(err)
    }
}

impl From<DiskError> for SupervisorError {
    fn from(err: DiskError) -> Self {
        SupervisorError::Disk(err)
    }
}

/// Structured report returned by [`run_supervisor`] in addition to writing the result disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub payload: ResultPayload,
    pub unexpected_ids: u64,
    pub stream_error: Option<RecordError>,
}

struct StreamTracker {
    expected_ids: BTreeSet<String>,
    completed_expected: BTreeMap<String, FinalTestOutcome>,
    in_flight_expected: BTreeSet<String>,
    in_flight_unexpected: BTreeSet<String>,
    completed_unexpected: BTreeSet<String>,
    unexpected_ids_count: u64,
    tests_started: u64,
    tests_finished: u64,
    records_emitted: u64,
    last_seq: Option<u64>,
    saw_end: bool,
    stream_error: Option<RecordError>,
}

impl StreamTracker {
    fn new(expected_test_ids: &[String]) -> Self {
        Self {
            expected_ids: expected_test_ids.iter().cloned().collect(),
            completed_expected: BTreeMap::new(),
            in_flight_expected: BTreeSet::new(),
            in_flight_unexpected: BTreeSet::new(),
            completed_unexpected: BTreeSet::new(),
            unexpected_ids_count: 0,
            tests_started: 0,
            tests_finished: 0,
            records_emitted: 0,
            last_seq: None,
            saw_end: false,
            stream_error: None,
        }
    }

    fn record_stream_error(&mut self, err: RecordError) {
        if self.stream_error.is_none() {
            self.stream_error = Some(err);
        }
    }

    fn apply_record(&mut self, rec: DecodedRecord) {
        if self.stream_error.is_some() {
            return;
        }
        if self.saw_end {
            self.record_stream_error(RecordError::TrailingDataAfterEnd);
            return;
        }

        match rec {
            DecodedRecord::Start(start) => {
                if let Some(prev) = self.last_seq {
                    if start.seq < prev {
                        self.record_stream_error(RecordError::NonMonotonicSeq {
                            prev,
                            current: start.seq,
                        });
                        return;
                    }
                }
                self.last_seq = Some(start.seq);

                let is_expected = self.expected_ids.contains(&start.nodeid);
                if is_expected {
                    if self.in_flight_expected.contains(&start.nodeid) {
                        self.record_stream_error(RecordError::DuplicateStart(start.nodeid));
                        return;
                    }
                    if self.completed_expected.contains_key(&start.nodeid) {
                        self.record_stream_error(RecordError::DuplicateTest(start.nodeid));
                        return;
                    }
                    self.in_flight_expected.insert(start.nodeid);
                } else {
                    if self.in_flight_unexpected.contains(&start.nodeid) {
                        self.record_stream_error(RecordError::DuplicateStart(start.nodeid));
                        return;
                    }
                    if self.completed_unexpected.contains(&start.nodeid) {
                        self.record_stream_error(RecordError::DuplicateTest(start.nodeid));
                        return;
                    }
                    self.in_flight_unexpected.insert(start.nodeid);
                    self.unexpected_ids_count = self.unexpected_ids_count.saturating_add(1);
                }

                self.tests_started = self.tests_started.saturating_add(1);
                self.records_emitted = self.records_emitted.saturating_add(1);
            }
            DecodedRecord::Finish(finish) => {
                if let Some(prev) = self.last_seq {
                    if finish.seq < prev {
                        self.record_stream_error(RecordError::NonMonotonicSeq {
                            prev,
                            current: finish.seq,
                        });
                        return;
                    }
                }
                self.last_seq = Some(finish.seq);

                let is_expected = self.expected_ids.contains(&finish.nodeid);
                if is_expected {
                    if !self.in_flight_expected.remove(&finish.nodeid) {
                        self.record_stream_error(RecordError::FinishWithoutStart(finish.nodeid));
                        return;
                    }
                    let final_outcome = match finish.outcome {
                        RecordOutcome::Passed => FinalTestOutcome::Passed,
                        RecordOutcome::Failed => FinalTestOutcome::Failed,
                        RecordOutcome::Skipped => FinalTestOutcome::Skipped,
                        RecordOutcome::Error => FinalTestOutcome::Error,
                    };
                    self.completed_expected.insert(finish.nodeid, final_outcome);
                } else {
                    if !self.in_flight_unexpected.remove(&finish.nodeid) {
                        self.record_stream_error(RecordError::FinishWithoutStart(finish.nodeid));
                        return;
                    }
                    self.completed_unexpected.insert(finish.nodeid);
                }

                self.tests_finished = self.tests_finished.saturating_add(1);
                self.records_emitted = self.records_emitted.saturating_add(1);
            }
            DecodedRecord::End(end) => {
                if end.count != self.tests_finished && end.count != self.records_emitted {
                    self.record_stream_error(RecordError::EndCountMismatch {
                        reported: end.count,
                        tests_finished: self.tests_finished,
                        records_emitted: self.records_emitted,
                    });
                    return;
                }
                self.saw_end = true;
            }
        }
    }
}

/// Executes a complete grading run through `os`:
/// 1. Reads and validates the run configuration JSON.
/// 2. Spawns the test process with `argv`, `env`, `cwd`, and the result pipe.
/// 3. Streams and strictly decodes per-test records while enforcing the overall deadline.
/// 4. On deadline expiry, kills the entire process group and marks exit `"timeout"`.
/// 5. Waits until the entire test process tree has exited.
/// 6. Atomically writes the 1 MiB `HGRD` result disk.
pub fn run_supervisor<O: Os>(
    os: &mut O,
    config_path: &Path,
    result_disk_path: &Path,
) -> Result<RunReport, SupervisorError> {
    let config_bytes = os.read_file(config_path, MAX_CONFIG_BYTES)?;
    let config = RunConfig::from_json_bytes(&config_bytes)?;

    let spawn_spec = SpawnSpec {
        argv: config.argv.clone(),
        env: config.env.clone(),
        cwd: PathBuf::from(&config.cwd),
        sandbox: config.sandbox.clone(),
        deadline_seconds: config.deadline_seconds,
    };

    crate::sandbox::build_plan(&spawn_spec).map_err(|_| OsError::Io {
        operation: "validate_sandbox",
        detail: "invalid sandbox configuration".into(),
    })?;

    let start_time = os.now_monotonic();
    let deadline_at = start_time.saturating_add(Duration::from_secs(config.deadline_seconds));
    let poll_slice = Duration::from_millis(POLL_SLICE_MS);

    let mut child = os.spawn(&spawn_spec)?;

    let mut decoder = RecordDecoder::new();
    let mut tracker = StreamTracker::new(&config.expected_test_ids);
    let mut pipe_eof = false;
    let mut timed_out = false;
    let mut tree_exit: Option<ExitKind> = None;
    let mut post_kill_deadline: Option<Duration> = None;

    for _ in 0..MAX_SUPERVISOR_ITERATIONS {
        let now = os.now_monotonic();

        if !timed_out && now >= deadline_at {
            timed_out = true;
            os.kill_process_group(&mut child)?;
            pipe_eof = true;
            post_kill_deadline = Some(now.saturating_add(Duration::from_secs(KILL_GRACE_SECONDS)));
        }

        if let Some(kill_limit) = post_kill_deadline {
            if now >= kill_limit && tree_exit.is_none() {
                return Err(SupervisorError::TreeDidNotExitAfterKill);
            }
        }

        // The pipe keeps being drained after a stream error (the decoder discards the bytes)
        // so a writer blocked on a full pipe can still finish and the tree can end.
        if !pipe_eof && !timed_out {
            let remaining = deadline_at.saturating_sub(now);
            let read_timeout = remaining.min(poll_slice);
            match os.read_pipe(&mut child, MAX_PIPE_CHUNK_BYTES, read_timeout)? {
                PipeRead::Data(chunk) if tracker.stream_error.is_some() => {
                    drop(chunk);
                }
                PipeRead::Data(chunk) => {
                    let (records, err) = decoder.push(&chunk);
                    for rec in records.into_iter().take(MAX_RECORDS_PER_STREAM) {
                        tracker.apply_record(rec);
                    }
                    if let Some(decode_err) = err {
                        tracker.record_stream_error(decode_err);
                    } else {
                        continue;
                    }
                }
                PipeRead::WouldBlock => {}
                PipeRead::Eof => {
                    pipe_eof = true;
                    if let Err(eof_err) = decoder.finish_eof() {
                        tracker.record_stream_error(eof_err);
                    }
                }
            }
        }

        let wait_timeout = if pipe_eof || tracker.stream_error.is_some() || timed_out {
            let active_limit = post_kill_deadline.unwrap_or(deadline_at);
            active_limit
                .saturating_sub(os.now_monotonic())
                .min(poll_slice)
        } else {
            Duration::ZERO
        };

        match os.wait_tree(&mut child, wait_timeout)? {
            TreeStatus::Running => {}
            TreeStatus::Exited(kind) => {
                tree_exit = Some(kind);

                // Drain any final bytes that arrived right as the process tree exited.
                if !pipe_eof && tracker.stream_error.is_none() && !timed_out {
                    for _ in 0..MAX_POST_EXIT_DRAIN_STEPS {
                        match os.read_pipe(&mut child, MAX_PIPE_CHUNK_BYTES, Duration::ZERO)? {
                            PipeRead::Data(chunk) => {
                                let (records, err) = decoder.push(&chunk);
                                for rec in records.into_iter().take(MAX_RECORDS_PER_STREAM) {
                                    tracker.apply_record(rec);
                                }
                                if let Some(decode_err) = err {
                                    tracker.record_stream_error(decode_err);
                                    break;
                                }
                            }
                            PipeRead::WouldBlock | PipeRead::Eof => {
                                break;
                            }
                        }
                    }
                    if let Err(eof_err) = decoder.finish_eof() {
                        tracker.record_stream_error(eof_err);
                    }
                }

                break;
            }
        }
    }

    if tree_exit.is_none() {
        if !timed_out {
            os.kill_process_group(&mut child)?;
        }
        return Err(SupervisorError::TreeDidNotExitAfterKill);
    }

    let has_stream_error = tracker.stream_error.is_some();
    let mut tests_map = BTreeMap::new();
    for expected_id in &config.expected_test_ids {
        let outcome = if let Some(&valid_outcome) = tracker.completed_expected.get(expected_id) {
            valid_outcome
        } else if has_stream_error || tracker.in_flight_expected.contains(expected_id) {
            FinalTestOutcome::Failed
        } else {
            FinalTestOutcome::Missing
        };
        tests_map.insert(expected_id.clone(), outcome);
    }

    let supervisor_exit = if timed_out {
        SupervisorExit::Timeout
    } else if has_stream_error
        || !tracker.saw_end
        || matches!(tree_exit, Some(ExitKind::Crash) | None)
    {
        SupervisorExit::Crash
    } else {
        SupervisorExit::Clean
    };

    let payload = ResultPayload {
        run: config.run,
        variant_set: config.variant_set,
        tests: tests_map,
        supervisor: SupervisorSummary {
            exit: supervisor_exit,
            tests_started: tracker.tests_started,
            tests_finished: tracker.tests_finished,
        },
    };

    let disk_bytes = encode_result_disk(&payload)?;
    os.write_file_atomic(result_disk_path, &disk_bytes)?;

    Ok(RunReport {
        payload,
        unexpected_ids: tracker.unexpected_ids_count,
        stream_error: tracker.stream_error,
    })
}
